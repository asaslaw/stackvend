"""FEATURE-REQUEST-CLOSE-OWN-ONLY: a deploy closes only the feature request its run built, never one filed while it ran.

With an id recorded on the run (`pipeline_executions/{trace}.request_id`) it is exactly that one. With none (Express,
initial builds until they record theirs, other channels, older runs): a request in a build status that no other run
started. Hermetic: in-memory Firestore, no network, no ADC.
"""
import hermetic_guard  # noqa: F401  (first import)

import copy
from unittest.mock import MagicMock

import pytest

from test_fd4aq_w1_no_host_secret import tf  # noqa: E402,F401  (tf is a fixture)
from test_fd4dt_access_fastpath import _Pub, _RDB  # noqa: E402
from test_l19_11_access_intake import ADMIN_H, _client, cc  # noqa: E402,F401  (cc is a fixture)

PID = "shop"
URL = "https://shop-abc.a.run.app"
TRACE = "intake-shop-1"


def _service(tf, tmp_path, db):  # noqa: F811
    return tf.TerraformService(project_id="mock-stackvend-project", state_bucket="",
                               workspace_base_dir=str(tmp_path / "b"), firestore_client=db)


def _store(requests, run=None, trace=TRACE):
    db = _RDB()
    for fr_id, fr in requests.items():
        db.store[("feature_requests", fr_id)] = dict({"product_id": PID, "request_id": fr_id}, **fr)
    if run is not None:
        db.store[("pipeline_executions", trace)] = dict({"product_id": PID, "trace_id": trace}, **run)
    return db


def _sync(tf, tmp_path, db, trace=TRACE, success=True, error=None):  # noqa: F811
    _service(tf, tmp_path, db)._sync_feature_requests(
        product_id=PID, trace_id=trace, is_successful_deploy=success, error_msg=error,
        service_url=URL if success else None)


def _closed(db, fr_id, trace=TRACE):
    fr = db.store[("feature_requests", fr_id)]
    return fr["status"] == "COMPLETED" and fr["service_url"] == URL and fr["trace_id"] == trace and fr["completed_at"]


def test_a_recorded_run_closes_only_its_own_request(tf, tmp_path):  # noqa: F811
    db = _store({"fr-1": {"status": "IN_DEVELOPMENT", "trace_id": TRACE},
                 "fr-2": {"status": "PENDING_TRIAGE"},
                 "fr-3": {"status": "IN_DEVELOPMENT", "trace_id": "retry-shop-other"},
                 "fr-4": {"status": "IN_PROGRESS"}}, run={"request_id": "fr-1"})
    before = copy.deepcopy(db.store)
    _sync(tf, tmp_path, db)
    assert _closed(db, "fr-1")
    for other in ("fr-2", "fr-3", "fr-4"):
        assert db.store[("feature_requests", other)] == before[("feature_requests", other)]


def test_a_recorded_id_is_exact_whatever_the_status(tf, tmp_path):  # noqa: F811
    db = _store({"fr-1": {"status": "PENDING_TRIAGE"}}, run={"request_id": "fr-1"})
    _sync(tf, tmp_path, db)
    assert _closed(db, "fr-1")


def test_a_request_filed_during_an_unrecorded_first_build_stays_open(tf, tmp_path):  # noqa: F811
    """The defect: FR-2 filed while the first build ran showed COMPLETED with the first build's URL."""
    db = _store({"spec-shop-1": {"status": "IN_PROGRESS"}, "fr-2": {"status": "PENDING_TRIAGE"}}, run={})
    before = copy.deepcopy(db.store[("feature_requests", "fr-2")])
    _sync(tf, tmp_path, db)
    assert _closed(db, "spec-shop-1")
    assert db.store[("feature_requests", "fr-2")] == before


def test_no_run_record_is_the_same_as_no_recorded_id(tf, tmp_path):  # noqa: F811
    db = _store({"spec-shop-1": {"status": "IN_PROGRESS"}, "fr-2": {"status": "PENDING_TRIAGE"}})
    _sync(tf, tmp_path, db)
    assert _closed(db, "spec-shop-1")
    assert db.store[("feature_requests", "fr-2")]["status"] == "PENDING_TRIAGE"


def test_an_unrecorded_run_closes_a_request_it_started_but_not_another_runs(tf, tmp_path):  # noqa: F811
    db = _store({"fr-own": {"status": "IN_DEVELOPMENT", "trace_id": TRACE},
                 "fr-other": {"status": "IN_DEVELOPMENT", "trace_id": "retry-shop-other"}}, run={})
    before = copy.deepcopy(db.store[("feature_requests", "fr-other")])
    _sync(tf, tmp_path, db)
    assert _closed(db, "fr-own")
    assert db.store[("feature_requests", "fr-other")] == before


@pytest.mark.parametrize("status", ["PENDING_TRIAGE", "FAILED", "REJECTED", "CANCELLED", "RESOLVED", None])
def test_an_unrecorded_run_leaves_every_other_status_alone(tf, tmp_path, status):  # noqa: F811
    db = _store({"fr-1": {} if status is None else {"status": status}}, run={})
    before = copy.deepcopy(db.store[("feature_requests", "fr-1")])
    _sync(tf, tmp_path, db)
    assert db.store[("feature_requests", "fr-1")] == before


@pytest.mark.parametrize("recorded", [None, "", 42, {"id": "fr-1"}])
def test_only_a_non_empty_string_counts_as_a_recorded_id(tf, tmp_path, recorded):  # noqa: F811
    db = _store({"spec-shop-1": {"status": "IN_PROGRESS"}, "fr-2": {"status": "PENDING_TRIAGE"}},
                run={"request_id": recorded})
    _sync(tf, tmp_path, db)
    assert _closed(db, "spec-shop-1")
    assert db.store[("feature_requests", "fr-2")]["status"] == "PENDING_TRIAGE"


def test_an_id_of_another_workload_closes_nothing(tf, tmp_path):  # noqa: F811
    db = _store({"fr-1": {"status": "IN_PROGRESS"}}, run={"request_id": "fr-foreign"})
    db.store[("feature_requests", "fr-foreign")] = {"product_id": "other", "status": "IN_DEVELOPMENT"}
    before = copy.deepcopy(db.store)
    _sync(tf, tmp_path, db)
    assert db.store == before


def test_an_already_completed_request_keeps_its_own_record(tf, tmp_path):  # noqa: F811
    done = {"status": "COMPLETED", "completed_at": "2026-11-01T00:00:00+00:00", "service_url": "https://old",
            "trace_id": "retry-shop-old"}
    db = _store({"fr-1": done}, run={"request_id": "fr-1"})
    _sync(tf, tmp_path, db)
    assert db.store[("feature_requests", "fr-1")] == dict(done, product_id=PID, request_id="fr-1")


def test_an_unreadable_run_record_changes_nothing(tf, tmp_path):  # noqa: F811
    """Not known which request the run built: never read as "no recorded id", which would close the in-build ones."""
    db = MagicMock()
    db.collection.return_value.document.return_value.get.side_effect = RuntimeError("firestore down")
    _sync(tf, tmp_path, db)
    db.collection.return_value.document.return_value.set.assert_not_called()


# The failure branches use the same selection: a run's failure is not written on requests it did not build.
@pytest.mark.parametrize("trace, field, value", [
    ("retry-shop-1", "last_iac_error", "apply failed"),     # orchestrated: provenance only, the gateway owns FAILED
    ("standalone-1", "status", "FAILED"),                   # standalone: FAILED directly
])
def test_a_failed_deploy_writes_only_on_the_runs_own_request(tf, tmp_path, trace, field, value):  # noqa: F811
    db = _store({"fr-1": {"status": "IN_DEVELOPMENT", "trace_id": trace}, "fr-2": {"status": "PENDING_TRIAGE"}},
                run={"request_id": "fr-1"}, trace=trace)
    before = copy.deepcopy(db.store[("feature_requests", "fr-2")])
    _sync(tf, tmp_path, db, trace=trace, success=False, error="apply failed")
    assert db.store[("feature_requests", "fr-1")][field] == value
    assert db.store[("feature_requests", "fr-2")] == before


@pytest.mark.parametrize("trace, field, value", [
    ("intake-shop-1", "last_iac_error", "apply failed"),
    ("standalone-1", "status", "FAILED"),
])
def test_a_failed_unrecorded_deploy_leaves_a_filed_request_alone(tf, tmp_path, trace, field, value):  # noqa: F811
    db = _store({"spec-shop-1": {"status": "IN_PROGRESS"}, "fr-2": {"status": "PENDING_TRIAGE"}}, run={}, trace=trace)
    before = copy.deepcopy(db.store[("feature_requests", "fr-2")])
    _sync(tf, tmp_path, db, trace=trace, success=False, error="apply failed")
    assert db.store[("feature_requests", "spec-shop-1")][field] == value
    assert db.store[("feature_requests", "fr-2")] == before


# ---- AUTO-DEPLOY-ONLY-OTHER-REQUEST: through the real retrigger route ------------------------------------------------
FAILED_AT_TF = {"status": "FAILED", "current_stage": "TERRAFORM", "started_at": "2026-11-09T01:00:00+00:00",
                "error": "quota exceeded", "stages": {"terraform": {"status": "FAILED", "error": "quota exceeded"}}}


def _relaunch(cc, monkeypatch, run, body, fr_id="fr-2"):  # noqa: F811
    _, wl = cc
    db = _store({"fr-1": {"status": "FAILED", "title": "First", "description": "spec one"},
                 "fr-2": {"status": "PENDING_TRIAGE", "title": "Second", "description": "spec two"}},
                run=run, trace="intake-shop-1")
    db.store[("workloads", PID)] = {"product_id": PID, "project_id": "sv-shop-1a2b", "github_repo": "example-org/shop",
                                    "default_branch": "main"}
    pub = _Pub()
    main_mod = MagicMock(project_id="mock-stackvend-project", get_pubsub_publisher=lambda: pub)
    client = _client(wl, monkeypatch, db)
    import authz
    monkeypatch.setattr(authz, "_db", lambda: db)      # the route's real authorization reads the same store
    monkeypatch.setattr(wl, "get_caller_main_module", lambda: main_mod)
    monkeypatch.setattr(wl, "_refuse_new_run_in_maintenance", lambda *a, **k: None)
    from build_admission_support import admit_every_build
    admit_every_build(monkeypatch, wl)   # BUILD-ADMISSION-QUEUE: this store holds no build slots
    res = client.post(f"/api/workloads/{PID}/feature-requests/{fr_id}/retrigger", json=body, headers=ADMIN_H)
    assert res.status_code == 200, res.text[:400]
    return res.json(), db, pub


@pytest.mark.parametrize("body", [{"execution_mode": "AUTO"}, {}, {"execution_mode": "DEFAULT"}])
def test_auto_builds_a_request_the_last_run_did_not_build(cc, monkeypatch, body):  # noqa: F811
    res, db, pub = _relaunch(cc, monkeypatch, dict(FAILED_AT_TF, request_id="fr-1"), body)
    assert res["execution_mode"] == "FULL" and res["trace_id"].startswith(f"retry-{PID}-")
    assert res["auto_fallback_reason"] == "OTHER_FEATURE_REQUEST" and "Fast-Path" in res["auto_fallback_message"]
    assert pub.messages[0][1]["execution_mode"] == "FULL"
    run = db.store[("pipeline_executions", res["trace_id"])]
    assert run["execution_mode"] == "FULL" and run["request_id"] == "fr-2"
    assert run["auto_fallback_reason"] == "OTHER_FEATURE_REQUEST"
    assert run["stages"]["developer"]["status"] == "QUEUED"    # really a build, not a skipped developer


def test_auto_keeps_fast_path_for_the_request_the_last_run_built(cc, monkeypatch):  # noqa: F811
    res, _, _ = _relaunch(cc, monkeypatch, dict(FAILED_AT_TF, request_id="fr-2"), {"execution_mode": "AUTO"})
    assert res["execution_mode"] == "DEPLOY_ONLY" and "auto_fallback_reason" not in res


def test_auto_keeps_fast_path_when_the_last_run_recorded_no_request(cc, monkeypatch):  # noqa: F811
    res, _, _ = _relaunch(cc, monkeypatch, FAILED_AT_TF, {"execution_mode": "AUTO"})
    assert res["execution_mode"] == "DEPLOY_ONLY" and "auto_fallback_reason" not in res


def test_an_explicit_fast_path_of_another_request_is_kept(cc, monkeypatch):  # noqa: F811
    res, db, pub = _relaunch(cc, monkeypatch, dict(FAILED_AT_TF, request_id="fr-1"), {"execution_mode": "DEPLOY_ONLY"})
    assert res["execution_mode"] == "DEPLOY_ONLY" and "auto_fallback_reason" not in res
    assert pub.messages[0][1]["execution_mode"] == "DEPLOY_ONLY"
    assert "auto_fallback_reason" not in db.store[("pipeline_executions", res["trace_id"])]


def test_the_guard_acts_only_on_fast_path(cc, monkeypatch):  # noqa: F811
    """A code defect does not route to Fast-Path; a Resume keeps its own rules, whichever request the last run built."""
    run = dict(FAILED_AT_TF, request_id="fr-1", error="syntax error in main.tf",
               stages={"terraform": {"status": "FAILED", "error": "syntax error in main.tf"}})
    res, _, _ = _relaunch(cc, monkeypatch, run, {"execution_mode": "AUTO"})
    assert res["execution_mode"] != "DEPLOY_ONLY" and res.get("auto_fallback_reason") != "OTHER_FEATURE_REQUEST"


def test_the_relaunch_record_is_what_the_deploy_closes(cc, tf, tmp_path, monkeypatch):  # noqa: F811
    """The Control Center's record and the terraform server's read agree: the relaunched request closes, the other stays."""
    res, db, _ = _relaunch(cc, monkeypatch, dict(FAILED_AT_TF, request_id="fr-1"), {"execution_mode": "AUTO"})
    db.store[("feature_requests", "fr-3")] = {"product_id": PID, "status": "PENDING_TRIAGE"}
    before = copy.deepcopy(db.store[("feature_requests", "fr-3")])
    fr_1_before = copy.deepcopy(db.store[("feature_requests", "fr-1")])
    _sync(tf, tmp_path, db, trace=res["trace_id"])
    assert _closed(db, "fr-2", trace=res["trace_id"])
    assert db.store[("feature_requests", "fr-3")] == before
    assert db.store[("feature_requests", "fr-1")] == fr_1_before
