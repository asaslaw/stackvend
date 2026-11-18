"""C10: the shared sandbox sweep (shared/sandbox_sweep.py) and sandbox-workload-sweeper-job (apps/sandbox-sweeper).

Pre-review F12: every Control Center guard holds in the job (platform-id refusal before any vending call, in-flight /
pending-review deferral, BATCH_LIMIT, "system-sandbox-sweeper" on every audit record, the statuses the dashboard reads,
the Workflows cascade cancel); the job calls vending with its own ID token for VENDING_SERVICE_URL, never mints an
approval; and the human route (ADMIN) runs the same code with the Control Center's vending call (negative: unchanged).
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
SWEEPER_DIR = os.path.join(REPO, "apps", "sandbox-sweeper")
CC_DIR = os.path.join(REPO, "apps", "control-center")
for p in (HERE, REPO):
    if p not in sys.path:
        sys.path.insert(0, p)

import c10_fakes as F  # noqa: E402
from shared import sandbox_sweep as SW  # noqa: E402


def _load(name, directory, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(directory, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.path.append(directory)
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(directory)
    return mod


sweeper = _load("c10_sweeper_main", SWEEPER_DIR, "main.py")
HOST = "mock-stackvend-project"
VENDING = "https://project-repo-vending-service-123.us-central1.run.app"
ENV = {"PROJECT_ID": HOST, "VENDING_SERVICE_URL": VENDING, "REGION": "us-central1", "CLOUD_RUN_EXECUTION": "sw-1"}


def _expired(days=-1.0):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _sandbox(db, pid, days=-1.0, **extra):
    db.put("workloads", pid, dict({"product_id": pid, "is_sandbox": True, "status": "ACTIVE", "project_id": f"{pid}-p",
                                   "sandbox_expires_at": _expired(days),
                                   "sandbox_designation_source": "OPERATOR_CHECKBOX"}, **extra))


class Vending:
    def __init__(self, status=200, body=None):
        self.calls, self.status, self.body = [], status, body or {"deleted_project_id": "x", "deleted_project_number": "9"}

    def post(self, url, json, headers, timeout):
        self.calls.append((url, json, headers, timeout))
        return F.Resp(self.status, self.body if self.status == 200 else {"detail": {"code": "GUARD_TAG_MISSING",
                                                                                   "detail": "no tag"}})


class Workflows:
    FAILED = "FAILED"

    def __init__(self, outcome="CANCELLED"):
        self.outcome, self.calls, self.region_provider = outcome, [], None

    def cancel_bound_execution(self, record, project):
        self.calls.append((record.get("trace_id"), project))
        return {"name": "projects/p/locations/r/workflows/w/executions/e", "outcome": self.outcome,
                "reason": "WORKFLOW_CANCEL_FAILED" if self.outcome == "FAILED" else "OK", "detail": "", "state": ""}


def _job(db, vending=None, workflows=None, env=None):
    vending = vending or Vending()
    workflows = workflows or Workflows()
    code, summary = sweeper.run(dict(ENV, **(env or {})), database=db, id_token=lambda aud: f"tok-for-{aud}",
                                http_post=vending.post, workflows=workflows)
    return code, summary, vending, workflows


def _audits(db, pid):
    return list(db.coll("workloads", pid, "audit_logs").values())


def test_expired_sandbox_is_decommissioned_through_vending_with_the_jobs_own_token():
    db = F.FakeDB()
    _sandbox(db, "sbx-1")
    db.put("pipeline_executions", "t-1", {"product_id": "sbx-1", "status": "RUNNING", "trace_id": "t-1"})
    code, summary, vending, wf = _job(db)
    assert code == 0 and summary["outcome"] == "COMPLETED" and summary["decommissioned_workloads"] == ["sbx-1"]
    [(url, body, headers, timeout)] = vending.calls
    assert url == f"{VENDING}/projects/sbx-1/decommission" and body == {"action_class": "SANDBOX_TTL"}
    assert headers["Authorization"] == f"Bearer tok-for-{VENDING}" and timeout == SW.DECOMMISSION_TIMEOUT_SECONDS
    assert "approval_id" not in body
    w = db.doc("workloads", "sbx-1")
    assert (w["sandbox_decommission_status"], w["decommission_reason"]) == ("DECOMMISSIONED", "AUTO_SANDBOX_EXPIRATION")
    assert wf.calls == [("t-1", HOST)] and db.doc("pipeline_executions", "t-1")["status"] == "ABORTED"
    assert all(a["operator_email"] == "system-sandbox-sweeper" for a in _audits(db, "sbx-1"))
    assert wf.region_provider() == "us-central1"


def test_expired_sandbox_failed_before_deploy_goes_to_vending_and_provisioning_stays_deferred():
    """WORKLOAD-STATUS-PRE-DEPLOY-FAILURE: FAILED is a finished run (PROVISIONING is the sweeper's in-flight word)."""
    db = F.FakeDB()
    _sandbox(db, "sbx-failed", status="FAILED")
    _sandbox(db, "sbx-running", status="PROVISIONING")
    code, summary, vending, _ = _job(db)
    assert code == 0 and summary["decommissioned_workloads"] == ["sbx-failed"] and len(vending.calls) == 1
    assert db.doc("workloads", "sbx-running")["sandbox_decommission_status"] == "DEFERRED_ACTIVE_PIPELINE"


def test_platform_ids_are_refused_before_any_vending_call():
    db = F.FakeDB()
    _sandbox(db, "sbx-host", project_id=HOST)
    _sandbox(db, "sbx-cp", project_id="castor-platform-1")
    code, summary, vending, _ = _job(db)
    assert vending.calls == [] and code == 1 and summary["outcome"] == "COMPLETED_WITH_ERRORS"
    assert summary["error_count"] == 2 and all("Platform protection" in e for e in summary["errors"])


@pytest.mark.parametrize("fr_status, deferred_status", [("IN_PROGRESS", "DEFERRED_ACTIVE_PIPELINE"),
                                                        ("DEPLOYING", "DEFERRED_ACTIVE_PIPELINE"),
                                                        ("PENDING_APPROVAL", "DEFERRED_PENDING_REVIEW")])
def test_in_flight_or_pending_review_feature_request_defers(fr_status, deferred_status):
    db = F.FakeDB()
    _sandbox(db, "sbx-1")
    db.put("feature_requests", "fr-1", {"product_id": "sbx-1", "status": fr_status})
    code, summary, vending, _ = _job(db)
    assert vending.calls == [] and code == 0 and summary["deferred_workloads"]
    w = db.doc("workloads", "sbx-1")
    assert w["sandbox_decommission_status"] == deferred_status
    assert datetime.fromisoformat(w["sandbox_expires_at"]) > datetime.now(timezone.utc) + timedelta(hours=23)
    assert [a["operator_email"] for a in _audits(db, "sbx-1")] == ["system-sandbox-sweeper"]


def test_in_flight_ledger_status_defers():
    db = F.FakeDB()
    _sandbox(db, "sbx-1", status="DEPLOYING")
    assert _job(db)[2].calls == []


def test_batch_limit_is_ten_per_run():
    db = F.FakeDB()
    for i in range(13):
        _sandbox(db, f"sbx-{i:02d}")
    code, summary, vending, _ = _job(db)
    assert len(vending.calls) == SW.BATCH_LIMIT == 10 and summary["expired_count"] == 13


@pytest.mark.parametrize("status", [403, 409])
def test_vending_refusal_is_recorded_for_the_dashboard_and_is_not_a_failure(status):
    """RT finding 4: vending's typed guard answer is listed (refused), GUARD_REFUSED is recorded, the run is OK."""
    db = F.FakeDB()
    _sandbox(db, "sbx-1")
    code, summary, _, _ = _job(db, vending=Vending(status=status))
    assert code == 0 and summary["outcome"] == "COMPLETED" and summary["error_count"] == 0
    assert summary["refused_workloads"] == ["sbx-1 (GUARD_TAG_MISSING)"]
    w = db.doc("workloads", "sbx-1")
    assert (w["sandbox_decommission_status"], w["sandbox_guard_refusal"]) == ("GUARD_REFUSED", "GUARD_TAG_MISSING")


@pytest.mark.parametrize("status", [500, 502, 503])
def test_vending_failure_fails_the_run(status):
    db = F.FakeDB()
    _sandbox(db, "sbx-1")
    code, summary, _, _ = _job(db, vending=Vending(status=status))
    assert code == 1 and summary["outcome"] == "COMPLETED_WITH_ERRORS" and summary["refused_workloads"] == []
    want = "DECOMMISSION_FAILED" if status == 502 else "GUARD_REFUSED"
    assert db.doc("workloads", "sbx-1")["sandbox_decommission_status"] == want


def test_vending_unreachable_fails_the_run():
    def boom(*a, **k):
        raise ConnectionError("down")
    db = F.FakeDB()
    _sandbox(db, "sbx-1")
    code, summary = sweeper.run(ENV, database=db, id_token=lambda a: "t", http_post=boom, workflows=Workflows())
    assert code == 1 and "VENDING_UNREACHABLE" in summary["errors"][0]


@pytest.mark.parametrize("extra", [{"sandbox_designation_source": "KEYWORD_DETECTED"},
                                   {"sandbox_designation_source": None},
                                   {"ttl_authority": "LEDGER_DISPLAY_ONLY"}])
def test_sandboxes_vending_never_ttl_deletes_are_not_sent(extra):
    """RT finding 4: awaiting confirmation or a display-only TTL: listed as not eligible, nothing sent or written,
    and they do not use up the 10-per-run batch."""
    db = F.FakeDB()
    for i in range(11):
        _sandbox(db, f"sbx-n{i:02d}", **extra)
    _sandbox(db, "sbx-ok")
    code, summary, vending, _ = _job(db)
    assert code == 0 and summary["decommissioned_workloads"] == ["sbx-ok"] and len(vending.calls) == 1
    assert len(summary["not_eligible_workloads"]) == 11
    assert "sandbox_decommission_status" not in db.doc("workloads", "sbx-n00")


def test_workflow_cancel_failure_is_reported():
    db = F.FakeDB()
    _sandbox(db, "sbx-1")
    db.put("pipeline_executions", "t-1", {"product_id": "sbx-1", "status": "RUNNING"})
    code, summary, _, _ = _job(db, workflows=Workflows(outcome="FAILED"))
    assert code == 1 and "NOT aborted" in summary["errors"][0]
    assert db.doc("pipeline_executions", "t-1")["status"] == "RUNNING"   # fail closed: not marked ABORTED


def test_t7_and_t2_notices_are_idempotent():
    db = F.FakeDB()
    _sandbox(db, "sbx-7", days=5.0)
    _sandbox(db, "sbx-2", days=1.0)
    code, summary, vending, _ = _job(db)
    assert code == 0 and summary["notifications_count"] == 2 and vending.calls == []
    assert db.doc("workloads", "sbx-7")["warn_t7_sent"] and db.doc("workloads", "sbx-2")["warn_t2_sent"]
    assert _job(db, env={"CLOUD_RUN_EXECUTION": "sw-2"})[1]["notifications_count"] == 0


def test_query_failure_is_failed():
    db = F.FakeDB()
    db.fail.add(("stream", "workloads"))
    code, summary, _, _ = _job(db)
    assert code == 1 and summary["outcome"] == "FAILED"


@pytest.mark.parametrize("key", sweeper.REQUIRED_ENV)
def test_not_configured(key):
    code, summary = sweeper.run({k: v for k, v in ENV.items() if k != key}, database=F.FakeDB(),
                                id_token=lambda a: "t", http_post=Vending().post, workflows=Workflows())
    assert code == 3 and key in summary["missing"]


def test_vending_unreachable_is_typed():
    def boom(*a, **k):
        raise ConnectionError("down")
    client = SW.SandboxVendingClient(VENDING, lambda a: "t", boom)
    out = client.decommission("sbx-1")
    assert (out.ok, out.http_status, out.code) == (False, 0, "VENDING_UNREACHABLE")


# ------------------------------------------------------------------------------------------------ the human route
@pytest.fixture
def cc(monkeypatch):
    monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl
    monkeypatch.setattr(cc_db, "_db_client", False)
    return wl


def test_route_runs_the_shared_sweep_with_the_cc_vending_call(cc, monkeypatch):
    """Negative (behaviour for humans unchanged): same result shape, the CC's call_vending, the same audit fields."""
    db = F.FakeDB()
    _sandbox(db, "sbx-1")
    monkeypatch.setattr(cc, "db", db)
    seen = []

    def fake_vending(method, path, json_body=None, timeout=60.0, request=None):
        seen.append((method, path, json_body, timeout))
        return F.Resp(200, {"deleted_project_id": "sbx-1-p"})

    monkeypatch.setattr(cc, "make_vending_request", fake_vending)
    res = cc.sweep_expired_sandboxes_endpoint(MagicMock())
    assert res.decommissioned_workloads == ["sbx-1"] and res.errors == []
    assert seen == [("POST", "/projects/sbx-1/decommission", {"action_class": "SANDBOX_TTL"}, 180.0)]
    assert db.doc("workloads", "sbx-1")["sandbox_decommission_status"] == "DECOMMISSIONED"
    monkeypatch.setattr(cc, "db", None)
    with pytest.raises(Exception) as err:
        cc.sweep_expired_sandboxes_endpoint(MagicMock())
    assert getattr(err.value, "status_code", None) == 503


def test_route_policy_is_admin_and_cc_helpers_are_the_shared_ones(cc):
    import destructive_actions as da
    src = open(os.path.join(CC_DIR, "routes", "workloads.py")).read()
    assert 'dependencies=[require(ADMIN)])\ndef sweep_expired_sandboxes_endpoint' in src
    assert "require(ADMIN_OR_JOB)" not in src
    assert da.sandbox_notice_suffix is SW.sandbox_notice_suffix or da.sandbox_notice_suffix.__code__ is \
        SW.sandbox_notice_suffix.__code__
    assert da.EXPLICIT_DESIGNATION_SOURCES == SW.EXPLICIT_DESIGNATION_SOURCES
