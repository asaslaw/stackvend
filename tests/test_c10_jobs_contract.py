"""C10: the day-2 job contract (shared/day2_job.py: run record, lease, exit codes) and finops-spend-sync-job, plus the
negative test that POST /api/finops/sync-spend behaves for a human exactly as before (first failure -> 500)."""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
SYNC_DIR = os.path.join(REPO, "apps", "finops-spend-sync")
CC_DIR = os.path.join(REPO, "apps", "control-center")
for p in (HERE, REPO):
    if p not in sys.path:
        sys.path.insert(0, p)

import c10_fakes as F  # noqa: E402
from shared import day2_job as J  # noqa: E402
from shared import spend_sync as SS  # noqa: E402


def _load(name, directory, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(directory, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.path.append(directory)
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(directory)
    return mod


sync_job = _load("c10_spend_sync_main", SYNC_DIR, "main.py")
ENV = {"PROJECT_ID": "mock-stackvend-project", "CLOUD_RUN_EXECUTION": "exec-1"}


# ------------------------------------------------------------------------------------------------ contract
def test_run_record_create_then_outcome_and_lease_released():
    db = F.FakeDB()
    code, summary = J.run_job("x-job", lambda run_id: (J.COMPLETED, {"n": 1}), db, ENV)
    assert code == 0 and db.doc("x-job_runs", "exec-1")["outcome"] == "COMPLETED"
    assert ("create", ("x-job_runs", "exec-1")) in db.ops and db.doc("x-job_leases", "current") is None


def test_rerun_of_the_same_execution_never_works_twice():
    db = F.FakeDB()
    work = MagicMock(return_value=(J.COMPLETED, {}))
    J.run_job("x-job", work, db, ENV)
    assert J.run_job("x-job", work, db, ENV)[0] == 0 and work.call_count == 1
    db.docs[("x-job_runs", "exec-1")]["outcome"] = "RUNNING"
    code, summary = J.run_job("x-job", work, db, ENV)
    assert code == 1 and summary["outcome"] == "INTERRUPTED" and work.call_count == 1


def test_concurrent_execution_is_skipped_not_failed():
    db = F.FakeDB()
    future = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    db.put("x-job_leases", "current", {"holder": "other", "expires_at": future})
    work = MagicMock()
    code, summary = J.run_job("x-job", work, db, ENV)
    assert code == 0 and summary["outcome"] == "SKIPPED_CONCURRENT" and not work.called
    assert db.doc("x-job_leases", "current")["holder"] == "other"


def test_expired_lease_is_taken_over():
    db = F.FakeDB()
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    db.put("x-job_leases", "current", {"holder": "dead", "expires_at": past})
    code, _ = J.run_job("x-job", lambda r: (J.COMPLETED, {}), db, ENV)
    assert code == 0 and ("update", ("x-job_leases", "current")) in db.ops


@pytest.mark.parametrize("outcome, code", [(J.COMPLETED, 0), (J.COMPLETED_WITH_ERRORS, 1), (J.FAILED, 1),
                                           ("SUCCESS", 1)])
def test_exit_codes(outcome, code):
    assert J.run_job("x-job", lambda r: (outcome, {}), F.FakeDB(), ENV)[0] == code


def test_exception_is_failed_with_its_class_and_not_configured_is_3():
    def boom(run_id):
        raise KeyError("nope")
    code, summary = J.run_job("x-job", boom, F.FakeDB(), ENV)
    assert code == 1 and summary["outcome"] == "FAILED" and summary["error_class"] == "KeyError"
    db = F.FakeDB()
    code, summary = J.run_job("x-job", boom, db, {"CLOUD_RUN_EXECUTION": "e"}, required_env=("PROJECT_ID",))
    assert code == 3 and summary["missing"] == ["PROJECT_ID"]
    assert J.run_job("x-job", boom, None, ENV)[0] == 1


# ------------------------------------------------------------------------------------------------ spend sync job
def _workloads(db):
    db.put("workloads", "a", {"budget_ceiling_monthly_usd": 50.0})
    db.put("workloads", "b", {"budget_ceiling_monthly_usd": 50.0})
    db.put("workloads", "gone", {"status": "DECOMMISSIONED"})


def _reconcile(fail=()):
    def reconcile(pid, data, host, db=None):
        if pid in fail:
            raise RuntimeError(f"state of {pid} unreadable")
        return {"current_spend_usd": 10.0, "projected_monthly_spend_usd": 60.0, "is_overrun_projected": True,
                "spend_source": "ESTIMATED_ACTIVE_ACCRUAL", "spend_last_updated_at": "now"}
    return reconcile


def test_spend_sync_job_writes_every_workload_and_skips_decommissioned():
    db = F.FakeDB()
    _workloads(db)
    code, summary = sync_job.run(ENV, database=db, reconcile=_reconcile())
    assert code == 0 and summary["synced_count"] == 2 and summary["overrun_projected"] == ["a", "b"]
    assert db.doc("workloads", "a")["projected_monthly_spend_usd"] == 60.0
    assert "current_spend_usd" not in db.doc("workloads", "gone")


def test_spend_sync_job_continues_past_a_failing_workload():
    db = F.FakeDB()
    _workloads(db)
    code, summary = sync_job.run(ENV, database=db, reconcile=_reconcile(fail=("a",)))
    assert code == 1 and summary["outcome"] == "COMPLETED_WITH_ERRORS"
    assert summary["failed"][0]["product_id"] == "a" and db.doc("workloads", "b")["current_spend_usd"] == 10.0


@pytest.fixture
def finops(monkeypatch):
    monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import finops as fr
    monkeypatch.setattr(cc_db, "_db_client", False)
    monkeypatch.setattr(fr, "verify_admin_access", lambda request: True)
    return fr


def test_route_behaviour_for_humans_is_unchanged(finops, monkeypatch):
    db = F.FakeDB()
    _workloads(db)
    monkeypatch.setattr(finops, "db", db)
    monkeypatch.setattr(finops, "reconcile_workload_spend", _reconcile())
    res = finops.sync_all_spend(MagicMock())
    assert set(res) == {"status", "synced_at", "count", "workloads"} and res["count"] == 2
    monkeypatch.setattr(finops, "reconcile_workload_spend", _reconcile(fail=("a",)))
    with pytest.raises(Exception) as err:          # the route still stops at the first failure: 500
        finops.sync_all_spend(MagicMock())
    assert err.value.status_code == 500
    monkeypatch.setattr(finops, "db", None)
    with pytest.raises(Exception) as err:
        finops.sync_all_spend(MagicMock())
    assert err.value.status_code == 503


def test_route_policy_is_admin():
    src = open(os.path.join(CC_DIR, "routes", "finops.py")).read()
    assert '@router.post("/api/finops/sync-spend", dependencies=[require(ADMIN)])' in src
    assert '@router.post("/api/alerts/billing", dependencies=[require(PUBSUB_PUSH("/api/alerts/billing"))])' in src
    assert SS.sync_all_workloads.__module__.endswith("spend_sync")
