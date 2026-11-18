"""FD deploy-dispatch (EXP-8 Opus RT finding 5): the Fast-Path re-apply (CC POST /api/workloads/{pid}/deploy-infra).

- The build event (spec-intake-events) is the only thing that starts the re-apply. When it cannot be sent the request
  fails visibly with a typed error_class, chosen by which step failed / the exception type (never by message text):
    no Pub/Sub publisher or no platform project -> 503 DEPLOY_DISPATCH_UNAVAILABLE (nothing published)
    publish error                               -> 502 DEPLOY_DISPATCH_FAILED
    publish wait timed out                      -> 504 DEPLOY_DISPATCH_OUTCOME_UNKNOWN (message may still go out)
  The execution record is FAILED with that class; the deployment lock is released at once (FAILED / UNAVAILABLE),
  or kept for the outcome-unknown case (the workflow's terminal status or the 15-minute expiry releases it).
- The gateway's /events/workflow-status releases workloads/{pid}.deployment_lock when the trace that holds it reports
  SUCCEEDED or FAILED. Only that trace's lock, only on a terminal status, with a version precondition.
Negative tests: the success path is unchanged; a lock held by another trace, a heartbeat, or a missing lock is left
alone.

Hermetic: in-memory FakeDB, MagicMock publisher; no cloud client, no network.
"""
import hermetic_guard  # noqa: F401  (first import)

import concurrent.futures
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from fd4f_support import FakeDB, gw  # noqa: F401  (gw is a fixture)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
PID = "shop-app"
WL = f"workloads/{PID}"


# ------------------------------------------------------------------------------------------------ CC route
def _publisher(msg_id="msg-1", publish_exc=None, result_exc=None):
    pub = MagicMock()
    if publish_exc is not None:
        pub.publish.side_effect = publish_exc
    else:
        fut = MagicMock()
        if result_exc is not None:
            fut.result.side_effect = result_exc
        else:
            fut.result.return_value = msg_id
        pub.publish.return_value = fut
    return pub


def _cc(monkeypatch, publisher, *, project="mock-stackvend-project", lock=None):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl

    monkeypatch.setattr(cc_db, "_db_client", False)
    store = FakeDB()
    store.docs[WL] = {"project_id": "shop-app-1", "github_repo": "org/shop-app", "default_branch": "main"}
    if lock is not None:
        store.docs[WL]["deployment_lock"] = lock
    monkeypatch.setattr(wl, "db", store)
    monkeypatch.setattr(wl, "verify_workload_access", lambda *a, **k: None)
    monkeypatch.setattr(wl, "get_caller_main_module", lambda: None)
    monkeypatch.setattr(wl, "get_pubsub_publisher", lambda: publisher)
    monkeypatch.setattr(wl, "project_id", project)
    _settings_maintenance_off(monkeypatch, wl)
    if project:
        monkeypatch.setenv("PROJECT_ID", project)
    else:
        monkeypatch.delenv("PROJECT_ID", raising=False)
    return wl, store


def _settings_maintenance_off(monkeypatch, module):
    """settings-toggles ST-1: the route reads platform settings strictly (maintenance mode) before any side effect.
    Serve the compile-time defaults (maintenance off) so these tests exercise the dispatch / redeploy paths."""
    from routes.settings import PlatformSettings

    defaults = PlatformSettings()
    assert defaults.governance.maintenance_mode is False
    monkeypatch.setattr(module, "get_platform_settings", lambda *a, **k: defaults)


def _deploy(wl, force=False):
    from schemas import DeployInfraRequest

    request = MagicMock()
    request.state.user_email = "admin@example.com"
    try:
        return wl.deploy_workload_infra(PID, request, DeployInfraRequest(force=force))
    except HTTPException as he:
        return he


def _execution(store):
    docs = [p for p in store.docs if p.startswith("pipeline_executions/")]
    assert len(docs) == 1, docs
    return store.docs[docs[0]]


def test_negative_dispatch_success_is_unchanged(monkeypatch):
    pub = _publisher("msg-42")
    wl, store = _cc(monkeypatch, pub)
    out = _deploy(wl)
    assert not isinstance(out, HTTPException)
    assert out.status == "DISPATCHED" and out.pubsub_message_id == "msg-42" and out.execution_mode == "DEPLOY_ONLY"
    topic = pub.publish.call_args[0][0]
    assert topic == "projects/mock-stackvend-project/topics/spec-intake-events"
    ex = _execution(store)
    assert ex["status"] == "ACTIVE" and ex["stages"]["terraform"]["status"] == "QUEUED"
    assert "error_class" not in ex
    lock = store.docs[WL]["deployment_lock"]
    assert lock["is_locked"] is True and lock["trace_id"] == out.trace_id  # released later by the workflow status


def _assert_failed(store, out, status_code, error_class, *, lock_released):
    assert isinstance(out, HTTPException) and out.status_code == status_code
    assert out.detail["error_class"] == error_class
    ex = _execution(store)
    assert out.detail["trace_id"] == ex["trace_id"]
    assert ex["status"] == "FAILED" and ex["current_stage"] == "FAILED" and ex["error_class"] == error_class
    assert ex["stages"]["terraform"]["status"] == "FAILED"
    assert ex["stages"]["terraform"]["error_class"] == error_class
    lock = store.docs[WL]["deployment_lock"]
    assert lock["trace_id"] == ex["trace_id"]
    if lock_released:
        assert lock["is_locked"] is False and lock["release_reason"] == error_class
        assert lock["locked_by"] == "admin@example.com"  # the rest of the lock record is kept
    else:
        assert lock["is_locked"] is True and "release_reason" not in lock


def test_no_publisher_is_unavailable_not_queued(monkeypatch):
    wl, store = _cc(monkeypatch, None)
    out = _deploy(wl)
    _assert_failed(store, out, 503, "DEPLOY_DISPATCH_UNAVAILABLE", lock_released=True)


def test_no_platform_project_is_unavailable_and_nothing_published(monkeypatch):
    pub = _publisher()
    wl, store = _cc(monkeypatch, pub, project="")
    out = _deploy(wl)
    _assert_failed(store, out, 503, "DEPLOY_DISPATCH_UNAVAILABLE", lock_released=True)
    pub.publish.assert_not_called()


def test_publish_error_is_dispatch_failed(monkeypatch):
    wl, store = _cc(monkeypatch, _publisher(publish_exc=RuntimeError("permission denied on topic")))
    out = _deploy(wl)
    _assert_failed(store, out, 502, "DEPLOY_DISPATCH_FAILED", lock_released=True)


def test_publish_result_error_is_dispatch_failed(monkeypatch):
    wl, store = _cc(monkeypatch, _publisher(result_exc=ValueError("bad message")))
    out = _deploy(wl)
    _assert_failed(store, out, 502, "DEPLOY_DISPATCH_FAILED", lock_released=True)


@pytest.mark.parametrize("exc", [concurrent.futures.TimeoutError(), TimeoutError("t")])
def test_publish_timeout_is_outcome_unknown_and_keeps_the_lock(monkeypatch, exc):
    wl, store = _cc(monkeypatch, _publisher(result_exc=exc))
    out = _deploy(wl)
    _assert_failed(store, out, 504, "DEPLOY_DISPATCH_OUTCOME_UNKNOWN", lock_released=False)


def test_class_comes_from_the_exception_type_not_its_message(monkeypatch):
    """A publish error whose text names another class (or says 'timeout') is still DEPLOY_DISPATCH_FAILED."""
    wl, store = _cc(monkeypatch, _publisher(publish_exc=RuntimeError("DEPLOY_DISPATCH_OUTCOME_UNKNOWN timeout")))
    out = _deploy(wl)
    _assert_failed(store, out, 502, "DEPLOY_DISPATCH_FAILED", lock_released=True)


def test_failed_dispatch_does_not_release_a_lock_another_reapply_took(monkeypatch):
    def _publish(topic, data):
        store.docs[WL]["deployment_lock"] = {"is_locked": True, "trace_id": "fastpath-other", "locked_by": "b"}
        raise RuntimeError("publish failed")

    pub = MagicMock()
    pub.publish.side_effect = _publish
    wl, store = _cc(monkeypatch, pub)
    out = _deploy(wl)
    assert isinstance(out, HTTPException) and out.detail["error_class"] == "DEPLOY_DISPATCH_FAILED"
    assert store.docs[WL]["deployment_lock"] == {"is_locked": True, "trace_id": "fastpath-other", "locked_by": "b"}


def test_negative_a_held_lock_still_refuses_without_writes(monkeypatch):
    now = datetime.now(timezone.utc).isoformat()
    lock = {"is_locked": True, "locked_at": now, "locked_by": "other@example.com", "trace_id": "fastpath-x"}
    pub = _publisher()
    wl, store = _cc(monkeypatch, pub, lock=dict(lock))
    out = _deploy(wl)
    assert isinstance(out, HTTPException) and out.status_code == 409
    assert store.writes == [] and store.docs[WL]["deployment_lock"] == lock
    pub.publish.assert_not_called()


def test_negative_an_expired_lock_is_still_taken_over(monkeypatch):
    old = (datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat()
    wl, store = _cc(monkeypatch, _publisher(), lock={"is_locked": True, "locked_at": old, "trace_id": "fastpath-x"})
    out = _deploy(wl)
    assert out.status == "DISPATCHED" and store.docs[WL]["deployment_lock"]["trace_id"] == out.trace_id


# ------------------------------------------------------------------------------------------------ gateway release
TRACE = "fastpath-shop-app-abc123"
LOCK = {"is_locked": True, "locked_at": "2026-10-19T10:00:00+00:00", "locked_by": "admin@example.com",
        "trace_id": TRACE, "branch": "main"}


def _gw_post(gw, monkeypatch, db, body):
    import google.cloud.firestore as fs_mod

    monkeypatch.setattr(fs_mod, "Client", lambda *a, **k: db)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    r = TestClient(gw.app).post("/events/workflow-status", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "UPDATED", r.text
    return r


@pytest.mark.parametrize("status", ["SUCCEEDED", "FAILED"])
def test_terminal_status_releases_the_lock_of_its_trace(gw, monkeypatch, status):
    db = FakeDB()
    db.docs[WL] = {"status": "ACTIVE", "deployment_lock": dict(LOCK)}
    _gw_post(gw, monkeypatch, db, {"trace_id": TRACE, "product_id": PID, "status": status})
    lock = db.docs[WL]["deployment_lock"]
    assert lock["is_locked"] is False and lock["release_reason"] == f"WORKFLOW_{status}" and lock["released_at"]
    assert {k: lock[k] for k in ("locked_at", "locked_by", "trace_id", "branch")} == \
        {k: LOCK[k] for k in ("locked_at", "locked_by", "trace_id", "branch")}
    assert db.docs[WL]["status"] == "ACTIVE"
    assert db.docs[f"pipeline_executions/{TRACE}"]["status"] == status


def test_product_id_comes_from_the_execution_record_when_the_event_omits_it(gw, monkeypatch):
    db = FakeDB()
    db.docs[WL] = {"deployment_lock": dict(LOCK)}
    db.docs[f"pipeline_executions/{TRACE}"] = {"product_id": PID, "started_at": "2026-10-19T10:00:00+00:00"}
    _gw_post(gw, monkeypatch, db, {"trace_id": TRACE, "status": "SUCCEEDED"})
    assert db.docs[WL]["deployment_lock"]["is_locked"] is False


@pytest.mark.parametrize("seed, body", [
    ({"deployment_lock": dict(LOCK)}, {"trace_id": TRACE, "product_id": PID, "current_stage": "TERRAFORM_CALLBACK",
                                      "stage_name": "terraform", "stage_status": "IN_FLIGHT"}),
    ({"deployment_lock": dict(LOCK, trace_id="fastpath-shop-app-other")},
     {"trace_id": TRACE, "product_id": PID, "status": "SUCCEEDED"}),
    ({"deployment_lock": dict(LOCK, is_locked=False)}, {"trace_id": TRACE, "product_id": PID, "status": "FAILED"}),
    ({"status": "ACTIVE"}, {"trace_id": TRACE, "product_id": PID, "status": "SUCCEEDED"}),
])
def test_negative_other_locks_heartbeats_and_unlocked_workloads_are_untouched(gw, monkeypatch, seed, body):
    db = FakeDB()
    db.docs[WL] = dict(seed)
    _gw_post(gw, monkeypatch, db, body)
    assert db.docs[WL] == seed
    assert not [w for w in db.writes if w[0] == WL]


def test_negative_no_workload_doc_is_not_created(gw, monkeypatch):
    db = FakeDB()
    _gw_post(gw, monkeypatch, db, {"trace_id": TRACE, "product_id": PID, "status": "SUCCEEDED"})
    assert WL not in db.docs


def test_a_concurrent_relock_wins_and_the_status_update_still_succeeds(gw, monkeypatch):
    class _StaleDB(FakeDB):
        def write_option(self, **kw):
            return {"last_update_time": "stale-version"}

    db = _StaleDB()
    db.docs[WL] = {"deployment_lock": dict(LOCK)}
    _gw_post(gw, monkeypatch, db, {"trace_id": TRACE, "product_id": PID, "status": "SUCCEEDED"})
    assert db.docs[WL]["deployment_lock"] == LOCK
    assert db.docs[f"pipeline_executions/{TRACE}"]["status"] == "SUCCEEDED"


def test_a_store_error_on_release_never_fails_the_status_update(gw, monkeypatch):
    db = FakeDB()
    db.docs[WL] = {"deployment_lock": dict(LOCK)}
    real_collection = db.collection

    def _collection(name):
        if name == "workloads":
            raise RuntimeError("workloads unreadable")
        return real_collection(name)

    db.collection = _collection
    _gw_post(gw, monkeypatch, db, {"trace_id": TRACE, "product_id": PID, "status": "FAILED"})
    assert db.docs[WL]["deployment_lock"] == LOCK
    assert db.docs[f"pipeline_executions/{TRACE}"]["status"] == "FAILED"


def test_failed_dispatch_release_is_version_checked(monkeypatch):
    """RT S2: the CC release uses the same version-checked write as the gateway: a concurrent re-lock wins."""
    class _StaleDB(FakeDB):
        def write_option(self, **kw):
            return {"last_update_time": "stale-version"}

    wl, store = _cc(monkeypatch, None)
    stale = _StaleDB()
    stale.docs = store.docs
    monkeypatch.setattr(wl, "db", stale)
    out = _deploy(wl)
    assert isinstance(out, HTTPException) and out.detail["error_class"] == "DEPLOY_DISPATCH_UNAVAILABLE"
    lock = stale.docs[WL]["deployment_lock"]
    assert lock["is_locked"] is True and "release_reason" not in lock  # the precondition failed: left to expiry
    assert _execution(stale)["status"] == "FAILED"


# ------------------------------------------------------------------------------------------------ gateway intake (S1)
def _intake(gw, monkeypatch, db, trace):
    import base64
    import json
    import types

    import google.cloud.firestore as fs_mod

    monkeypatch.setattr(fs_mod, "Client", lambda *a, **k: db)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    monkeypatch.setenv("REGION", "us-central1")   # FALLBACK-URLS: dispatch needs REGION (no default)
    # settings-toggles ST-1: the gateway intake reads maintenance mode strictly (shared.settings); maintenance off.
    import importlib

    shared_settings = importlib.import_module("shared.settings")
    defaults = shared_settings.PlatformSettings()
    assert defaults.governance.maintenance_mode is False
    monkeypatch.setattr(shared_settings, "get_platform_settings", lambda *a, **k: defaults)

    class _Exec:
        def __init__(self, argument=None):
            self.argument = argument

    class _Client:
        def workflow_path(self, *a):
            return "projects/p/locations/r/workflows/w"

        def create_execution(self, parent=None, execution=None):
            return types.SimpleNamespace(name=parent + "/executions/e-7")

    fake_exec_mod = types.SimpleNamespace(ExecutionsClient=_Client, Execution=_Exec)
    monkeypatch.setitem(sys.modules, "google.cloud.workflows", types.SimpleNamespace(executions_v1=fake_exec_mod))
    monkeypatch.setitem(sys.modules, "google.cloud.workflows.executions_v1", fake_exec_mod)
    monkeypatch.setitem(sys.modules, "google.cloud.workflows_v1", types.SimpleNamespace())
    monkeypatch.setattr(gw, "resolve_service_url", lambda name, *a, **k: f"https://{name}.example.run.app")
    payload = {"product_id": PID, "trace_id": trace, "execution_mode": "DEPLOY_ONLY",
               "source_channel": "control_center_deploy_infra", "target_branch": "main"}
    env = {"message": {"data": base64.b64encode(json.dumps(payload).encode()).decode(), "messageId": "m1"}}
    r = TestClient(gw.app).post("/events/pubsub-intake", json=env)
    assert r.status_code == 200, r.text
    return r


def _seeded(error_class=None):
    doc = {"trace_id": TRACE, "product_id": PID, "status": "ACTIVE", "current_stage": "TERRAFORM",
           "execution_mode": "DEPLOY_ONLY", "workflow_execution_id": None,
           "stages": {"terraform": {"status": "QUEUED"}, "sre": {"status": "QUEUED"}}}
    if error_class:
        doc.update({"status": "FAILED", "current_stage": "FAILED", "error_class": error_class, "error": "timed out",
                    "failed_stage": "terraform", "completed_at": "2026-10-19T10:00:10+00:00",
                    "stages": {"terraform": {"status": "FAILED", "error_class": error_class},
                               "sre": {"status": "SKIPPED", "summary": "Skipped"}}})
    return doc


def test_delivered_outcome_unknown_reapply_is_running_again(gw, monkeypatch):
    from google.cloud import firestore

    db = FakeDB()
    db.docs[f"pipeline_executions/{TRACE}"] = _seeded("DEPLOY_DISPATCH_OUTCOME_UNKNOWN")
    r = _intake(gw, monkeypatch, db, TRACE)
    assert r.json()["status"] == "DISPATCHED", r.text
    writes = [w for w in db.writes if w[0] == f"pipeline_executions/{TRACE}"]
    assert len(writes) == 1
    _, data, merge = writes[0]
    assert merge is True
    assert data["status"] == "ACTIVE" and data["current_stage"] == "TERRAFORM"
    assert data["workflow_execution_id"] == "e-7"
    assert data["workflow_execution_name"] == "projects/p/locations/r/workflows/w/executions/e-7"  # SAT-43
    for field in ("error_class", "error", "failed_stage", "completed_at"):
        assert data[field] is firestore.DELETE_FIELD
    assert data["stages"]["terraform"]["status"] == "QUEUED"
    assert data["stages"]["terraform"]["error_class"] is firestore.DELETE_FIELD
    assert data["stages"]["sre"]["status"] == "QUEUED"


@pytest.mark.parametrize("error_class", [None])
def test_negative_other_preseeded_records_only_get_the_execution_id(gw, monkeypatch, error_class):
    db = FakeDB()
    seeded = _seeded(error_class)
    db.docs[f"pipeline_executions/{TRACE}"] = dict(seeded)
    r = _intake(gw, monkeypatch, db, TRACE)
    assert r.json()["status"] == "DISPATCHED", r.text
    assert db.docs[f"pipeline_executions/{TRACE}"] == dict(
        seeded, workflow_execution_id="e-7",
        workflow_execution_name="projects/p/locations/r/workflows/w/executions/e-7")  # SAT-43: the full name too


@pytest.mark.parametrize("error_class", ["DEPLOY_DISPATCH_FAILED", "DEPLOY_DISPATCH_UNAVAILABLE"])
def test_rt14_14_a_late_event_of_a_failed_dispatch_is_refused(gw, monkeypatch, error_class):
    """RT14-14 (owner 11-14): the Control Center failed this re-apply (its publish raised, or nothing could publish)
    and released the deployment lock, so an event that still arrives is refused typed and acked; the record stays as
    the Control Center wrote it. Before, it started a workflow on a FAILED record (only OUTCOME_UNKNOWN is revived)."""
    db = FakeDB()
    seeded = _seeded(error_class)
    db.docs[f"pipeline_executions/{TRACE}"] = dict(seeded)
    r = _intake(gw, monkeypatch, db, TRACE)
    assert r.status_code == 200 and r.json()["status"] == "SUPPRESSED:RUN_ALREADY_ENDED", r.text
    assert db.docs[f"pipeline_executions/{TRACE}"] == seeded
