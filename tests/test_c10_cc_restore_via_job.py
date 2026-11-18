"""C10 (RT residual R3, FD26-07): the Control Center's budget-breach approvals restore a quarantined workload by running
finops-budget-enforcer-job with FINOPS_ACTION=RESTORE (shared/enforcer_job.py) and reading its run record; typed
EXECUTION_FAILED on any failure (never a fabricated restore); the engine's restore clears the breach latch.
Hermetic: in-memory Firestore and REST fakes; the real enforcer engine with mocked Google clients.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
CC_DIR = os.path.join(REPO, "apps", "control-center")
FINOPS_DIR = os.path.join(REPO, "apps", "finops-enforcer")
for p in (HERE, REPO):
    if p not in sys.path:
        sys.path.insert(0, p)

import c10_fakes as F  # noqa: E402
from shared import enforcer_job as EJ  # noqa: E402


def _load(name, directory, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(directory, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.path.append(directory)
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(directory)
    return mod


with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/c10-adc.json"}):
    enf = _load("c10r_enforcer", FINOPS_DIR, "enforcer.py")
    # Only the `enforcer` alias is set and removed (patch.dict(sys.modules) would drop first-time imports on exit).
    _prior = sys.modules.get("enforcer")
    sys.modules["enforcer"] = enf
    try:
        enf_main = _load("c10r_enforcer_main", FINOPS_DIR, "main.py")
    finally:
        if _prior is None:
            sys.modules.pop("enforcer", None)
        else:
            sys.modules["enforcer"] = _prior

HOST = "mock-stackvend-project"
ROOT = "111111111111"
JOB = f"projects/{HOST}/locations/us-central1/jobs/finops-budget-enforcer-job"
ACCT_NAME = "billingAccounts/01ABCD-234567-89EF01"
LATCH = {"period": "2026-11", "threshold": 100.0, "outcome": "QUARANTINED", "at": "2026-11-10T00:00:00+00:00"}


def _relinkable_billing(account=None):
    """RT14-05: a billing client whose read-back shows the relinked account (the restore checks it)."""
    billing = MagicMock(name="billing")
    billing.projects.return_value.getBillingInfo.return_value.execute.return_value = {
        "billingAccountName": account or ACCT_NAME}
    return billing


def _crm():
    crm = MagicMock(name="crm")
    projects = crm.projects.return_value

    def get_ancestry(projectId, body):
        call = MagicMock()
        call.execute.return_value = {"ancestor": [{"resourceId": {"type": "project", "id": projectId}},
                                                  {"resourceId": {"type": "folder", "id": ROOT}}]}
        return call

    def get(projectId):
        call = MagicMock()
        call.execute.return_value = {"projectNumber": "222" if projectId == "shop-app-1" else "999"}
        return call

    projects.getAncestry.side_effect = get_ancestry
    projects.get.side_effect = get
    return crm


def _db(**workload):
    db = F.FakeDB()
    db.put("workloads", "shop-app", dict({"product_id": "shop-app", "project_id": "shop-app-1", "status": "QUARANTINED",
                                          "budget_ceiling_monthly_usd": 100.0, "budget_breach_latch": LATCH},
                                         **workload))
    return db


def _job_running(db, outcome=None, engine=None):
    """A FakeRest whose jobs:run writes the execution's run record (a fixed outcome, or the real job's run_batch)."""
    rest = F.FakeRest()

    def on_run(body):
        execution_id = f"finops-budget-enforcer-job-r{len(rest.calls)}"
        rest.execution = f"{JOB}/executions/{execution_id}"
        env = {e["name"]: e["value"] for e in body["overrides"]["containerOverrides"][0]["env"]}
        rest.last_env = env
        if engine is not None:
            enf_main.run_batch(dict(env, PROJECT_ID=HOST, CLOUD_RUN_EXECUTION=execution_id), engine)
        else:
            db.put("finops-budget-enforcer-job_runs", execution_id, {"outcome": outcome})

    rest.on_run = on_run
    return rest


def _client(db, rest, wait_s=60):
    clock = SimpleNamespace(t=0.0)
    return EJ.EnforcerJob(rest, db, HOST, "us-central1", clock=lambda: clock.t,
                          sleep=lambda s: setattr(clock, "t", clock.t + s), wait_s=wait_s)


# ------------------------------------------------------------------------------------------------ enforcer job: RESTORE
def test_restore_mode_runs_the_engine_restore_and_records_it(monkeypatch):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    db = _db(status="BILLING_UNLINKED", root_billing_account=ACCT_NAME)   # recorded at unlink (RT D1)
    engine = enf.FinopsBudgetEnforcer(project_id=HOST, firestore_client=db, run_service=MagicMock(),
                                      compute_service=MagicMock(), sql_service=MagicMock(),
                                      container_service=MagicMock(), billing_service=_relinkable_billing(),
                                      crm_service=_crm(),
                                      advisor=SimpleNamespace(available=False))
    code, summary = enf_main.run_batch({"PROJECT_ID": HOST, "FINOPS_ACTION": "RESTORE", "CLOUD_RUN_EXECUTION": "e1",
                                        "FINOPS_ENFORCE_PRODUCT_ID": "shop-app",
                                        "FINOPS_ENFORCE_TARGET_PROJECT_ID": "shop-app-1"}, engine)
    assert code == 0 and summary["outcome"] == "BILLING_RESTORED" and summary["action"] == "RESTORE"
    assert db.doc("finops-budget-enforcer-job_runs", "e1")["outcome"] == "BILLING_RESTORED"
    assert db.doc("workloads", "shop-app")["budget_breach_latch"] is None


@pytest.mark.parametrize("env, code, outcome", [
    ({"FINOPS_ACTION": "DELETE"}, 2, "INVALID_REQUEST"),
    ({"FINOPS_ACTION": "RESTORE", "FINOPS_RESTORE_MAX_INSTANCES": "zero"}, 2, "INVALID_REQUEST"),
    ({"FINOPS_ACTION": "RESTORE", "FINOPS_RESTORE_MAX_INSTANCES": "101"}, 2, "INVALID_REQUEST"),     # RT D3 cap
    ({"FINOPS_ACTION": "RESTORE", "FINOPS_RESTORE_BILLING_ACCOUNT": ACCT_NAME}, 2, "INVALID_REQUEST"),   # RT D5
    ({"FINOPS_ACTION": "RESTORE", "FINOPS_ENFORCE_TARGET_PROJECT_ID": ""}, 3, "NOT_CONFIGURED"),
    ({"FINOPS_ACTION": "RESTORE", "FINOPS_ENFORCE_TARGET_PROJECT_ID": HOST}, 1, "REFUSED"),   # FD-4O guard
])
def test_restore_mode_typed_failures(monkeypatch, env, code, outcome):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    db = _db()
    engine = enf.FinopsBudgetEnforcer(project_id=HOST, firestore_client=db, run_service=MagicMock(),
                                      compute_service=MagicMock(), sql_service=MagicMock(),
                                      container_service=MagicMock(), billing_service=MagicMock(), crm_service=_crm(),
                                      advisor=SimpleNamespace(available=False))
    base = {"PROJECT_ID": HOST, "CLOUD_RUN_EXECUTION": "e2", "FINOPS_ENFORCE_PRODUCT_ID": "shop-app",
            "FINOPS_ENFORCE_TARGET_PROJECT_ID": "shop-app-1"}
    got_code, summary = enf_main.run_batch(dict(base, **env), engine)
    assert (got_code, summary["outcome"]) == (code, outcome)
    assert db.doc("workloads", "shop-app")["budget_breach_latch"] == LATCH   # nothing restored


def test_quarantine_contract_is_unchanged_without_an_action():
    e = MagicMock()
    e.db = F.FakeDB()
    e.quarantine_workload.return_value = {"status": "QUARANTINED"}
    code, summary = enf_main.run_batch({"PROJECT_ID": HOST, "FINOPS_ENFORCE_PRODUCT_ID": "p",
                                        "FINOPS_ENFORCE_TARGET_PROJECT_ID": "t", "CLOUD_RUN_EXECUTION": "q1"}, e)
    assert code == 0 and summary["outcome"] == "QUARANTINED" and not e.restore_workload.called


def test_status_sets_match_the_enforcer():
    assert EJ.ENFORCED_STATUSES == enf_main.ENFORCED_STATUSES and EJ.RESTORE_STATUSES == enf_main.RESTORE_STATUSES


# ------------------------------------------------------------------------------------------------ client
def test_client_restore_runs_the_job_with_the_restore_overrides():
    db = _db()
    rest = _job_running(db, outcome="RESTORED")
    out = _client(db, rest).restore_workload("shop-app", "shop-app-1")
    assert out["status"] == "RESTORED" and out["execution"].startswith(f"{JOB}/executions/")
    assert rest.last_env == {"FINOPS_ACTION": "RESTORE", "FINOPS_ENFORCE_PRODUCT_ID": "shop-app",
                             "FINOPS_ENFORCE_TARGET_PROJECT_ID": "shop-app-1"}


@pytest.mark.parametrize("outcome", ["FAILED", "INVALID_REQUEST", "NOT_CONFIGURED"])
def test_client_job_failure_is_typed(outcome):
    db = _db()
    with pytest.raises(EJ.EnforcerRunError) as err:
        _client(db, _job_running(db, outcome=outcome)).restore_workload("shop-app", "shop-app-1")
    assert err.value.code == f"ENFORCER_{outcome}" and err.value.execution


def test_client_run_refused_and_timeout_are_typed():
    db = _db()
    with pytest.raises(EJ.EnforcerRunError) as err:
        _client(db, F.FakeRest(run_status=403)).restore_workload("shop-app", "shop-app-1")
    assert err.value.code == "ENFORCER_RUN_REFUSED"
    rest = F.FakeRest(execution=f"{JOB}/executions/finops-budget-enforcer-job-zz", exec_complete=False)
    with pytest.raises(EJ.EnforcerRunError) as err:
        _client(db, rest, wait_s=30).restore_workload("shop-app", "shop-app-1")
    assert err.value.code == "ENFORCER_TIMEOUT"


# ------------------------------------------------------------------------------------------------ the CC approval
@pytest.fixture
def approvals(monkeypatch):
    monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import approvals as ar
    monkeypatch.setattr(cc_db, "_db_client", False)
    return ar


def _decide(ar, monkeypatch, db, client, action="RESTORE_BUFFER"):
    from schemas import ApprovalDecisionRequest, ApprovalStatus
    monkeypatch.setattr(ar, "db", db)
    monkeypatch.setattr(ar, "get_finops_enforcer", lambda: client)
    record = {"approval_id": "appr-1", "approval_type": "BUDGET_BREACH", "product_id": "shop-app",
              "current_spend_usd": 120.0, "budget_ceiling_usd": 100.0}
    req = ApprovalDecisionRequest(decision=ApprovalStatus.APPROVED, action=action, new_budget_usd=200.0)
    return ar._decide_budget(record, req, "admin@example.com", "2026-11-07T00:00:00+00:00", {"approval_id": "appr-1"})


@pytest.mark.parametrize("action", ["RESTORE_BUFFER", "INCREASE_BUDGET"])
def test_cc_restore_runs_the_job_end_to_end_and_clears_the_latch(approvals, monkeypatch, action):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    db = _db(status="BILLING_UNLINKED", root_billing_account=ACCT_NAME)   # recorded at unlink (RT D1)
    engine = enf.FinopsBudgetEnforcer(project_id=HOST, firestore_client=db, run_service=MagicMock(),
                                      compute_service=MagicMock(), sql_service=MagicMock(),
                                      container_service=MagicMock(), billing_service=_relinkable_billing(),
                                      crm_service=_crm(),
                                      advisor=SimpleNamespace(available=False))
    rest = _job_running(db, engine=engine)
    out = _decide(approvals, monkeypatch, db, _client(db, rest), action)
    assert out["status"] == "APPROVED", out
    assert rest.last_env["FINOPS_ACTION"] == "RESTORE" and rest.last_env["FINOPS_ENFORCE_TARGET_PROJECT_ID"] == "shop-app-1"
    w = db.doc("workloads", "shop-app")
    assert w["status"] == "ACTIVE" and w["budget_breach_latch"] is None
    if action == "RESTORE_BUFFER":
        assert w["buffer_ceiling_usd"] == 138.0
    else:
        assert w["budget_ceiling_monthly_usd"] == 200.0


def test_cc_restore_failure_is_execution_failed_and_writes_nothing(approvals, monkeypatch):
    db = _db()
    out = _decide(approvals, monkeypatch, db, _client(db, _job_running(db, outcome="FAILED")))
    assert out["status"] == "EXECUTION_FAILED" and out["failure_reason"].startswith("ENFORCER_FAILED")
    assert out["pending_decision"] == "APPROVED"
    w = db.doc("workloads", "shop-app")
    assert w["status"] == "QUARANTINED" and "buffer_ceiling_usd" not in w and w["budget_breach_latch"] == LATCH


def test_cc_restore_refused_is_execution_failed(approvals, monkeypatch):
    db = _db()
    out = _decide(approvals, monkeypatch, db, _client(db, _job_running(db, outcome="REFUSED")))
    assert out["status"] == "EXECUTION_FAILED" and out["failure_reason"].startswith("REFUSED")
    assert db.doc("workloads", "shop-app")["status"] == "QUARANTINED"


def test_cc_without_an_enforcer_client_never_claims_a_restore(approvals, monkeypatch):
    db = _db()
    out = _decide(approvals, monkeypatch, db, None)
    assert out["status"] == "EXECUTION_FAILED" and out["failure_reason"].startswith("ENFORCER_UNAVAILABLE")
    assert db.doc("workloads", "shop-app")["status"] == "QUARANTINED"


def test_cc_get_finops_enforcer_is_the_job_client(approvals, monkeypatch):
    """The in-process engine import is gone (it worked only in a source checkout): the client is the job client, and
    without a region it is None (typed ENFORCER_UNAVAILABLE upstream)."""
    from routes import platform_release
    monkeypatch.setattr(platform_release, "_region", lambda: "")
    assert approvals.get_finops_enforcer() is None
    src = open(os.path.join(CC_DIR, "routes", "approvals.py")).read()
    assert "FinopsBudgetEnforcer" not in src and "finops-enforcer" not in src.split("def get_finops_enforcer")[1][:2000]



# ------------------------------------------------------------------------------------------------ never scaled down
def _engine(db, run_service):
    return enf.FinopsBudgetEnforcer(project_id=HOST, firestore_client=db, run_service=run_service,
                                    compute_service=MagicMock(), sql_service=MagicMock(),
                                    container_service=MagicMock(), billing_service=MagicMock(), crm_service=_crm(),
                                    advisor=SimpleNamespace(available=False))


def _run_service_with_api_at_max_20():
    run_service = MagicMock(name="run")
    services = run_service.projects.return_value.locations.return_value.services.return_value
    services.list.return_value.execute.return_value = {"services": [
        {"name": "projects/shop-app-1/locations/us-central1/services/api",
         "template": {"scaling": {"maxInstanceCount": 20, "minInstanceCount": 1}}}]}
    return run_service, services


@pytest.mark.parametrize("action", ["RESTORE_BUFFER", "INCREASE_BUDGET"])
def test_negative_a_workload_that_was_never_scaled_down_is_unchanged(approvals, monkeypatch, action):
    """Owner-directed (11-07): approving a HITL budget card for a workload the quarantine never touched (services at
    max 20) must not set its services to max_instances=5. The restore answers NOTHING_TO_RESTORE, changes no service,
    clears the latch, and the decision writes the new ceiling and ACTIVE."""
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    db = _db(status="ACTIVE", budget_breach_policy="HITL_CONFIRMATION_REQUIRED")
    run_service, services = _run_service_with_api_at_max_20()
    rest = _job_running(db, engine=_engine(db, run_service))
    out = _decide(approvals, monkeypatch, db, _client(db, rest), action)
    assert out["status"] == "APPROVED", out
    run = db.coll("finops-budget-enforcer-job_runs")
    assert [r["outcome"] for r in run.values()] == ["NOTHING_TO_RESTORE"]
    assert not services.patch.called and not services.list.called      # no service read, no service changed
    w = db.doc("workloads", "shop-app")
    assert w["status"] == "ACTIVE" and w["budget_breach_latch"] is None


def test_a_quarantined_workload_without_its_snapshot_is_not_guessed(approvals, monkeypatch):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    db = _db()                                            # status QUARANTINED, no quarantine_snapshots/shop-app
    run_service, services = _run_service_with_api_at_max_20()
    out = _decide(approvals, monkeypatch, db, _client(db, _job_running(db, engine=_engine(db, run_service))))
    assert out["status"] == "EXECUTION_FAILED" and out["failure_reason"].startswith("ENFORCER_SNAPSHOT_MISSING")
    assert not services.patch.called
    assert db.doc("workloads", "shop-app")["status"] == "QUARANTINED"


def test_engine_restore_without_markers_is_nothing_to_restore(monkeypatch):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    db = _db(status="ACTIVE")
    run_service, services = _run_service_with_api_at_max_20()
    out = _engine(db, run_service).restore_workload("shop-app", "shop-app-1")
    assert out["status"] == "NOTHING_TO_RESTORE" and out["restored_services"] == []
    assert not services.patch.called and db.doc("workloads", "shop-app")["budget_breach_latch"] is None
    # a quarantine record without a snapshot is SNAPSHOT_MISSING (nothing touched)
    db.put("quarantined_workloads", "shop-app", {"status": "QUARANTINED"})
    assert _engine(db, run_service).restore_workload("shop-app", "shop-app-1")["status"] == "SNAPSHOT_MISSING"
    assert not services.patch.called



# ------------------------------------------------------------------------------------------------ RT D1-D3
def _unlinked_engine(db, billing):
    return enf.FinopsBudgetEnforcer(project_id=HOST, firestore_client=db, run_service=MagicMock(),
                                    compute_service=MagicMock(), sql_service=MagicMock(),
                                    container_service=MagicMock(), billing_service=billing, crm_service=_crm(),
                                    advisor=SimpleNamespace(available=False))


def test_unlink_records_the_account_and_restore_relinks_exactly_that_one(monkeypatch):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    monkeypatch.delenv("BILLING_ACCOUNT_ID", raising=False)
    db = _db(status="ACTIVE", budget_breach_latch=None)
    billing = MagicMock(name="billing")
    billing.projects.return_value.getBillingInfo.return_value.execute.return_value = {"billingAccountName": ACCT_NAME}
    eng = _unlinked_engine(db, billing)
    out = eng.quarantine_workload("shop-app", "shop-app-1", spend_amount=150.0, budget_amount=100.0,
                                  policy="NUCLEAR_UNLINK_BILLING")
    assert out["status"] == "BILLING_UNLINKED"
    assert db.doc("workloads", "shop-app")["root_billing_account"] == ACCT_NAME
    out = eng.restore_workload("shop-app", "shop-app-1")
    assert out["status"] == "BILLING_RESTORED" and out["billing_account"] == ACCT_NAME
    relink = billing.projects.return_value.updateBillingInfo.call_args_list[-1].kwargs
    assert relink == {"name": "projects/shop-app-1", "body": {"billingAccountName": ACCT_NAME}}
    assert db.doc("workloads", "shop-app")["status"] == "ACTIVE"


def test_a_failed_unlink_is_not_billing_unlinked(monkeypatch):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    db = _db(status="ACTIVE")
    billing = MagicMock(name="billing")
    billing.projects.return_value.getBillingInfo.return_value.execute.return_value = {"billingAccountName": ACCT_NAME}
    billing.projects.return_value.updateBillingInfo.return_value.execute.side_effect = RuntimeError("403")
    out = _unlinked_engine(db, billing).quarantine_workload("shop-app", "shop-app-1", spend_amount=150.0,
                                                            budget_amount=100.0, policy="NUCLEAR_UNLINK_BILLING")
    assert out["status"] == "BILLING_UNLINK_FAILED" and db.doc("workloads", "shop-app")["status"] == "ACTIVE"


@pytest.mark.parametrize("case, status", [("no-account", "BILLING_ACCOUNT_UNKNOWN"),
                                          ("relink-fails", "BILLING_RELINK_FAILED"),
                                          ("no-client", "BILLING_CLIENT_UNAVAILABLE"),
                                          ("other-account", "BILLING_ACCOUNT_MISMATCH")])
def test_billing_restore_failures_are_typed_and_write_nothing(monkeypatch, case, status):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    monkeypatch.delenv("BILLING_ACCOUNT_ID", raising=False)
    recorded = None if case == "no-account" else ACCT_NAME
    db = _db(status="BILLING_UNLINKED", root_billing_account=recorded)
    billing = MagicMock(name="billing")
    if case == "relink-fails":
        billing.projects.return_value.updateBillingInfo.return_value.execute.side_effect = RuntimeError("403")
    if case == "no-client":
        billing = None
        monkeypatch.setenv("TEST_MODE", "false")      # the mock relink is for TEST_MODE only
    kwargs = {"root_billing_account": "billingAccounts/OTHER-0000"} if case == "other-account" else {}
    out = _unlinked_engine(db, billing).restore_workload("shop-app", "shop-app-1", **kwargs)
    assert out["status"] == status and status not in enf_main.RESTORE_STATUSES
    w = db.doc("workloads", "shop-app")
    assert w["status"] == "BILLING_UNLINKED" and w["budget_breach_latch"] == LATCH   # nothing written


def test_the_install_account_is_the_fallback(monkeypatch):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    monkeypatch.setenv("BILLING_ACCOUNT_ID", "01ABCD-234567-89EF01")
    db = _db(status="BILLING_UNLINKED")
    out = _unlinked_engine(db, _relinkable_billing()).restore_workload("shop-app", "shop-app-1")
    assert out["status"] == "BILLING_RESTORED" and out["billing_account"] == ACCT_NAME


def _snapshot_engine(db, failing=(), live=None):
    """`live`: the Cloud Run services as the API shows them ({name: {max_instances, min_instances}}); a scaling call
    that succeeds updates it (RT14-05: the restore reads it back before reporting RESTORED)."""
    eng = _unlinked_engine(db, MagicMock(name="billing"))
    calls = []
    live = {} if live is None else live
    for svc in (db.doc("quarantine_snapshots", "shop-app") or {}).get("cloud_run_services", []):
        live.setdefault(svc["name"], {"name": svc["name"], "max_instances": None, "min_instances": 0})

    def scale(proj, name, max_instances, min_instances=0, region=None):
        calls.append((name, max_instances, min_instances))
        if name in failing:
            return False
        cur = live.setdefault(name, {"name": name, "max_instances": None, "min_instances": 0})
        cur["min_instances"] = min_instances
        if max_instances is not None:
            cur["max_instances"] = max_instances
        return True

    eng.set_service_scaling = scale
    eng.list_workload_services = lambda proj, region=None, strict=False: [dict(v) for v in live.values()]
    eng.resolve_workload_region = lambda pid: "us-central1"
    eng.restore_verify_wait_s = 0
    return eng, calls


def test_a_partial_restore_is_not_restored_and_keeps_the_snapshot(monkeypatch):
    """RT D2: one failed service -> RESTORE_PARTIAL, snapshot and quarantine record kept, no ACTIVE."""
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    db = _db()
    snap = {"cloud_run_services": [{"name": "api", "max_instances": 7, "min_instances": 1},
                                   {"name": "worker", "max_instances": 3, "min_instances": 0}]}
    db.put("quarantine_snapshots", "shop-app", snap)
    db.put("quarantined_workloads", "shop-app", {"status": "QUARANTINED"})
    eng, calls = _snapshot_engine(db, failing=("worker",))
    out = eng.restore_workload("shop-app", "shop-app-1")
    assert out["status"] == "RESTORE_PARTIAL" and out["failed"] == ["run/worker"] and out["restored_services"] == ["api"]
    assert "RESTORE_PARTIAL" not in enf_main.RESTORE_STATUSES
    assert db.doc("quarantine_snapshots", "shop-app") == snap and db.doc("quarantined_workloads", "shop-app")
    assert db.doc("workloads", "shop-app")["status"] == "QUARANTINED"
    # the retry, with the service fixed, restores everything from the kept snapshot
    eng, calls = _snapshot_engine(db)
    assert eng.restore_workload("shop-app", "shop-app-1")["status"] == "RESTORED"
    assert calls == [("api", 7, 1), ("worker", 3, 0)] and db.doc("quarantine_snapshots", "shop-app") is None


def test_a_snapshot_entry_without_a_max_keeps_its_max(monkeypatch):
    """RT D3: never a guessed max=5; only the recorded min is restored (or the capped override when given)."""
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    db = _db()
    db.put("quarantine_snapshots", "shop-app", {"cloud_run_services": [{"name": "api", "min_instances": 2}]})
    eng, calls = _snapshot_engine(db)
    assert eng.restore_workload("shop-app", "shop-app-1")["status"] == "RESTORED"
    assert calls == [("api", None, 2)]


def test_set_service_scaling_without_a_max_patches_only_the_min():
    run = MagicMock(name="run")
    eng = _unlinked_engine(F.FakeDB(), MagicMock())
    eng.run = run
    assert eng.set_service_scaling("p", "api", max_instances=None, min_instances=2, region="us-central1")
    kw = run.projects.return_value.locations.return_value.services.return_value.patch.call_args.kwargs
    assert kw["updateMask"] == "template.scaling.minInstanceCount"
    assert kw["body"] == {"template": {"scaling": {"minInstanceCount": 2}}}
