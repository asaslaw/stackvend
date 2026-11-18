"""Lane 17 (FD-4AJ / FD-4R / FD-4AG) gateway gates: every route the PR-2 workflow calls fails closed.

Covers workflow_gates.py (pure decisions) and the routes in apps/orchestrator-gateway/main.py:
/health.workflow_contract, /governance/kill-switch, /events/pre-build-gate (+ /decision), /events/approval-request,
/agent/resume/outcome, /governance/deploy-only-gate, /events/approval-callback (AJ-7), /events/plan-approval-request
(503), /events/workflow-status (F5), the F6 developer re-dispatch guard and Pub/Sub intake (AJ-11/AJ-12).
Negative tests: the valid path passes with its input unchanged.

Hermetic: in-memory FakeDB injected via dependency_overrides / module attributes; no cloud client, no network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import base64
import json
import sys
import types

import pytest
from fastapi.testclient import TestClient

from fd4f_support import FakeDB, gw  # noqa: F401  (gw is a fixture)

TRACE = "tr-l17-1"
PID = "app"
CB = "https://workflowexecutions.googleapis.com/v1/projects/p/locations/r/workflows/w/executions/e/callbacks/c1"


def _client(gw, db):
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: db
    return TestClient(gw.app)


def _compliance(**kw):
    base = {"requires_human_approval": False, "has_policy_conflicts": False, "allow_unauthenticated": True}
    base.update(kw)
    return base


def _finops(**kw):
    base = {"requires_human_approval": False, "monthly_cost_delta_usd": 12.5, "risk_assessment": "LOW"}
    base.update(kw)
    return base


# ================================================================================ workflow_gates (pure)
def test_pre_build_gate_negative_clean_inputs_pass():
    import workflow_gates as g

    comp, fin = _compliance(), _finops()
    snapshot = (json.dumps(comp, sort_keys=True), json.dumps(fin, sort_keys=True))
    assert g.evaluate_pre_build_gate(compliance=comp, finops=fin) == ("PASS", [])
    assert (json.dumps(comp, sort_keys=True), json.dumps(fin, sort_keys=True)) == snapshot  # inputs unchanged


@pytest.mark.parametrize("kw, reason", [
    ({"compliance": _compliance(requires_human_approval=True)}, "COMPLIANCE_REQUIRES_APPROVAL"),
    ({"compliance": _compliance(has_policy_conflicts=True)}, "COMPLIANCE_POLICY_CONFLICT"),
    ({"operator_requested": True}, "OPERATOR_REQUESTED"),
    ({"finops": None}, "FINOPS_UNAVAILABLE"),
    ({"finops_error": "HTTP 503"}, "FINOPS_UNAVAILABLE"),
    ({"finops": {"monthly_cost_delta_usd": 1.0}}, "FINOPS_INCOMPLETE"),
    ({"finops": _finops(requires_human_approval="yes")}, "FINOPS_INCOMPLETE"),
    ({"finops": _finops(requires_human_approval=True)}, "FINOPS_THRESHOLD"),
    ({"policy_harvest_status": "FAILED"}, "POLICY_HARVEST_FAILED"),
])
def test_pre_build_gate_every_reason_awaits_approval(kw, reason):
    import workflow_gates as g

    args = {"compliance": _compliance(), "finops": _finops()}
    args.update(kw)
    decision, reasons = g.evaluate_pre_build_gate(**args)
    assert decision == "AWAIT_APPROVAL" and reason in reasons


def test_pre_build_gate_missing_compliance_is_an_error_not_a_pass():
    import workflow_gates as g

    with pytest.raises(ValueError):
        g.evaluate_pre_build_gate(compliance=None, finops=_finops())


@pytest.mark.parametrize("branch, workload, ledger, allowed", [
    ("main", {}, None, True),
    ("release", {"default_branch": "release"}, None, True),
    ("main", {"default_branch": "release"}, None, False),
    ("feature/x", {}, None, False),
    ("feature/x", {}, [{"branch": "feature/x", "state": "MERGED"}], True),
    ("feature/x", {}, [{"branch": "feature/x", "state": "PR_OPEN"}], False),
    ("feature/x", {}, [{"branch": "feature/x", "state": "MERGED"}, {"branch": "feature/x", "state": "MERGED"}], False),
    ("Main", {}, None, False),  # exact equality only
    ("", {}, None, False),
])
def test_deploy_only_truth_table(branch, workload, ledger, allowed):
    import workflow_gates as g

    assert g.deploy_only_allowed(branch=branch, workload=workload, ledger_entries=ledger)[0] is allowed


def test_resume_outcome_requires_same_trace_and_passed_gate():
    import workflow_gates as g

    gate = {"status": "PASS", "trace_id": "t-old", "product_id": PID}
    rec = {"trace_id": "t-old", "product_id": PID, "allow_unauthenticated": False}
    assert g.resume_outcome_problems(product_id=PID, compliance_record=rec, prebuild_gate=gate) == []
    assert "TRACE_MISMATCH" in g.resume_outcome_problems(
        product_id=PID, compliance_record=dict(rec, trace_id="t-other"), prebuild_gate=gate)
    assert "PREBUILD_GATE_NOT_PASSED" in g.resume_outcome_problems(
        product_id=PID, compliance_record=rec, prebuild_gate=dict(gate, status="REJECTED"))
    assert g.resume_outcome_problems(product_id=PID, compliance_record=None, prebuild_gate=gate) == ["NO_COMPLIANCE_RECORD"]
    assert g.resume_outcome_problems(product_id=PID, compliance_record=rec, prebuild_gate=None) == ["NO_PREBUILD_GATE"]


def test_compliance_ingress_view_missing_flag_is_private_never_public():
    import workflow_gates as g

    assert g.compliance_ingress_view({})["allow_unauthenticated"] is False
    assert g.compliance_ingress_view({"allow_unauthenticated": True})["allow_unauthenticated"] is True


def test_error_class_vocabulary_is_pinned():
    from gate_errors import ErrorClass

    assert {e.value for e in ErrorClass} == {
        "CODE_DEFECT", "GATE_UNAVAILABLE", "PLATFORM_DEFECT", "POLICY_REJECTED", "GATE_TIMEOUT",
        "KILL_SWITCH_ACTIVE", "CONTRACT_VIOLATION", "RELEASE_FAILED", "MAIN_MOVED", "OPERATOR_ACTION_REQUIRED",
        "STATE_LOCKED", "DEPLOY_TIMEOUT", "IAC_DEFECT", "DEPLOY_FAILED", "DEPENDENCY_FAILED", "UNHANDLED",
        "ARCHITECT_DEFECT",  # lane 10 (FD-51): architect topology still invalid after its one repair (422)
        "COMPLIANCE.PRIVATE_INGRESS_UNSUPPORTED",  # PRIVATE-INGRESS-EARLY-STOP (409, stage compliance)
        "STAGE_DEADLINE_EXCEEDED", "STAGE_ABANDONED",  # STAGE-DEADLINE (owner 11-13)
        "STAGE_INTERRUPTED", "STAGE_TIMEOUT"}  # LONG-STAGE-CALLBACK (owner 11-13)


def test_gate_error_body_carries_stage_only_when_given():
    from gate_errors import GateUnavailableError

    assert "stage" not in GateUnavailableError("x").to_body()  # lane 13 bodies unchanged
    assert GateUnavailableError("x", stage="resume").to_body()["stage"] == "resume"


# ================================================================================ /health + kill switch
def test_health_reports_workflow_contract(gw):
    # LONG-STAGE-CALLBACK (owner 11-13): 3 = the stage-job routes exist (the workflow requires >= 3)
    assert TestClient(gw.app).get("/health").json()["workflow_contract"] == 3


def test_kill_switch_states(gw):
    db = FakeDB()
    c = _client(gw, db)
    assert c.get("/governance/kill-switch").json()["active"] is False  # no record = not active
    db.docs["governance/platform_kill_switch"] = {"emergency_stop_active": True, "reason": "incident",
                                                  "activated_by": "ops@example.com"}
    body = c.get("/governance/kill-switch").json()
    assert body == {"active": True, "reason": "incident", "set_by": "ops@example.com"}


@pytest.mark.parametrize("setup", ["no_db", "read_fails", "malformed"])
def test_kill_switch_unreadable_is_503(gw, setup):
    db = None if setup == "no_db" else FakeDB()
    if setup == "read_fails":
        db.fail_reads = True
    if setup == "malformed":
        db.docs["governance/platform_kill_switch"] = {"emergency_stop_active": "yes"}
    r = _client(gw, db).get("/governance/kill-switch")
    assert r.status_code == 503 and r.json()["error_class"] == "GATE_UNAVAILABLE"
    assert r.json()["reason"] == "KILL_SWITCH_UNREADABLE"


# ================================================================================ pre-build gate
def _gate_body(**kw):
    body = {"trace_id": TRACE, "product_id": PID, "callback_url": CB, "rework_cycle": 0,
            "compliance": _compliance(), "finops": _finops(), "finops_error": "", "policy_harvest_status": "SUCCESS",
            "operator_requested": False, "spec_doc_id": "", "task_dag": []}
    body.update(kw)
    return body


def test_pre_build_gate_pass_persists_decision_and_writes_no_approval(gw):
    db = FakeDB()
    r = _client(gw, db).post("/events/pre-build-gate", json=_gate_body())
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "SUCCESS", "decision": "PASS", "gate_reasons": [], "approval_id": ""}
    assert not [p for p in db.docs if p.startswith("approval_requests/")]
    assert db.docs[f"workloads/{PID}"]["last_prebuild_gate"]["status"] == "PASS"
    assert db.docs[f"pipeline_executions/{TRACE}"]["prebuild_gate"]["trace_id"] == TRACE


def test_pre_build_gate_await_writes_one_record_and_is_idempotent(gw):
    db = FakeDB()
    c = _client(gw, db)
    body = _gate_body(finops=_finops(requires_human_approval=True, monthly_cost_delta_usd=4200.0,
                                     monthly_cost_estimate="+$4200.00/mo"))
    r1 = c.post("/events/pre-build-gate", json=body)
    r2 = c.post("/events/pre-build-gate", json=body)  # retried POST (RT F7)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["decision"] == "AWAIT_APPROVAL" and r1.json()["gate_reasons"] == ["FINOPS_THRESHOLD"]
    assert r1.json()["approval_id"] == r2.json()["approval_id"] == f"appr-plan-{TRACE}-0"
    records = [p for p in db.docs if p.startswith("approval_requests/")]
    assert records == [f"approval_requests/appr-plan-{TRACE}-0"]
    rec = db.docs[records[0]]
    assert rec["approval_type"] == "ARCHITECTURAL_PLAN" and rec["status"] == "PENDING" and rec["callback_url"] == CB
    assert rec["cost_delta_monthly"] == "+$4200.00/mo" and rec["cost_delta_monthly_usd"] == 4200.0  # RT F5
    assert rec["gate_reasons"] == ["FINOPS_THRESHOLD"]


def test_pre_build_gate_retry_with_new_callback_refreshes_pending_record(gw):
    db = FakeDB()
    c = _client(gw, db)
    c.post("/events/pre-build-gate", json=_gate_body(operator_requested=True))
    c.post("/events/pre-build-gate", json=_gate_body(operator_requested=True, callback_url=CB + "-2"))
    assert db.docs[f"approval_requests/appr-plan-{TRACE}-0"]["callback_url"] == CB + "-2"


def test_pre_build_gate_finops_outage_requires_approval(gw):
    db = FakeDB()
    r = _client(gw, db).post("/events/pre-build-gate", json=_gate_body(finops=None, finops_error="HTTP 503"))
    assert r.json()["decision"] == "AWAIT_APPROVAL" and "FINOPS_UNAVAILABLE" in r.json()["gate_reasons"]
    rec = db.docs[f"approval_requests/appr-plan-{TRACE}-0"]
    assert rec["cost_delta_monthly"] == "not evaluated" and rec["cost_delta_monthly_usd"] == 0.0  # RT F5


@pytest.mark.parametrize("finops,shown", [
    (None, "not evaluated"), ({}, "not evaluated"), ({"monthly_cost_estimate": ""}, "not evaluated"),
    ({"monthly_cost_estimate": 5.0}, "not evaluated"), ({"monthly_cost_estimate": "+$5.00/mo"}, "+$5.00/mo")])
def test_cost_display_is_the_finops_string_or_not_evaluated(gw, finops, shown):
    """Bundle RT F5: the card shows the FinOps display string, never a bare float like `5.0`."""
    import workflow_gates
    assert workflow_gates.cost_display(finops) == shown


def test_plan_card_renders_the_display_string_in_the_control_center(gw):
    """Bundle RT F5: what the CC does with the stored value (str(...)) now yields the FinOps wording."""
    db = FakeDB()
    _client(gw, db).post("/events/pre-build-gate", json=_gate_body(
        finops=_finops(requires_human_approval=True, monthly_cost_delta_usd=5.0, monthly_cost_estimate="+$5.00/mo")))
    rec = db.docs[f"approval_requests/appr-plan-{TRACE}-0"]
    assert str(rec.get("cost_delta_monthly", "$0.00/mo")) == "+$5.00/mo"  # approvals.py:147/319 coercion


def test_pre_build_gate_missing_compliance_is_422(gw):
    r = _client(gw, FakeDB()).post("/events/pre-build-gate", json=_gate_body(compliance=None))
    assert r.status_code == 422


@pytest.mark.parametrize("setup", ["no_db", "write_fails"])
def test_pre_build_gate_store_failure_is_503_never_a_pass(gw, setup):
    db = None if setup == "no_db" else FakeDB()
    if db is not None:
        db.fail_writes = True
    r = _client(gw, db).post("/events/pre-build-gate", json=_gate_body())
    assert r.status_code == 503 and r.json()["error_class"] == "GATE_UNAVAILABLE"


def _seed_plan_record(db, status):
    db.docs[f"approval_requests/appr-plan-{TRACE}-0"] = {"approval_id": f"appr-plan-{TRACE}-0", "trace_id": TRACE,
                                                         "product_id": PID, "status": status,
                                                         "gate_reasons": ["OPERATOR_REQUESTED"]}


def _decision(c, decision="APPROVED", **kw):
    body = {"trace_id": TRACE, "product_id": PID, "approval_id": f"appr-plan-{TRACE}-0", "decision": decision}
    body.update(kw)
    return c.post("/events/pre-build-gate/decision", json=body)


def test_decision_persisted_only_when_it_equals_the_record(gw):
    db = FakeDB()
    _seed_plan_record(db, "APPROVED")
    r = _decision(_client(gw, db))
    assert r.status_code == 200 and r.json()["decision"] == "APPROVED"
    assert db.docs[f"workloads/{PID}"]["last_prebuild_gate"]["status"] == "APPROVED"


@pytest.mark.parametrize("status, decision, code, reason", [
    ("REJECTED", "APPROVED", 409, "DECISION_MISMATCH"),
    ("PENDING", "APPROVED", 503, "DECISION_PENDING"),
    ("DECIDING", "APPROVED", 503, "DECISION_PENDING"),
    ("APPROVED", "MAYBE", 409, "UNKNOWN_DECISION"),
])
def test_decision_mismatch_or_pending_never_persists(gw, status, decision, code, reason):
    db = FakeDB()
    _seed_plan_record(db, status)
    r = _decision(_client(gw, db), decision)
    assert r.status_code == code and r.json()["reason"] == reason
    assert f"workloads/{PID}" not in db.docs


def test_decision_for_another_trace_is_409(gw):
    db = FakeDB()
    _seed_plan_record(db, "APPROVED")
    db.docs[f"approval_requests/appr-plan-{TRACE}-0"]["trace_id"] = "someone-else"
    assert _decision(_client(gw, db)).status_code == 409


# ================================================================================ quota gate approval record
def _quota_body(**kw):
    body = {"trace_id": TRACE, "product_id": PID, "approval_type": "QUOTA_GATE", "callback_url": CB,
            "recheck_n": 0, "reason": "QUOTA_INSUFFICIENT", "violations": [{"metric": "cpus"}], "quota_source": "API"}
    body.update(kw)
    return body


def test_quota_gate_record_is_created_once(gw):
    db = FakeDB()
    c = _client(gw, db)
    r1, r2 = c.post("/events/approval-request", json=_quota_body()), c.post("/events/approval-request", json=_quota_body())
    assert r1.status_code == r2.status_code == 200 and r1.json()["approval_id"] == f"appr-quota-{TRACE}-0"
    assert [p for p in db.docs if p.startswith("approval_requests/")] == [f"approval_requests/appr-quota-{TRACE}-0"]
    rec = db.docs[f"approval_requests/appr-quota-{TRACE}-0"]
    assert rec["approval_type"] == "QUOTA_GATE" and rec["callback_url"] == CB and rec["status"] == "PENDING"


def test_quota_gate_rejects_other_types_and_store_outage(gw):
    assert _client(gw, FakeDB()).post("/events/approval-request",
                                      json=_quota_body(approval_type="PULL_REQUEST")).status_code == 409
    assert _client(gw, None).post("/events/approval-request", json=_quota_body()).status_code == 503


# ================================================================================ resume outcome
def _seed_resume(db, gate_status="PASS", comp_trace="t-old"):
    db.docs[f"workloads/{PID}"] = {"last_prebuild_gate": {"status": gate_status, "trace_id": "t-old",
                                                          "product_id": PID, "approval_id": "", "rework_cycle": 0}}
    db.docs[f"workloads/{PID}/prebuild_task_dags/t-old"] = {
        "product_id": PID, "trace_id": "t-old", "rework_cycle": 0, "status": "STORED", "task_count": 1,
        "task_dag_json": json.dumps([{"step_id": "S1"}])}
    db.docs[f"workloads/{PID}/compliance_audits/t-old"] = {"trace_id": comp_trace, "product_id": PID,
                                                          "allow_unauthenticated": False, "enable_direct_iap": True,
                                                          "compliance_profile": "HIPAA"}


def _resume(c):
    return c.post("/agent/resume/outcome", json={"trace_id": TRACE, "product_id": PID})


def test_resume_outcome_returns_the_prior_decision(gw):
    db = FakeDB()
    _seed_resume(db)
    r = _resume(_client(gw, db))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["source_trace_id"] == "t-old" and body["prebuild_gate"]["status"] == "PASS"
    assert body["compliance"]["allow_unauthenticated"] is False and body["compliance"]["enable_direct_iap"] is True


@pytest.mark.parametrize("gate_status, comp_trace", [("REJECTED", "t-old"), ("AWAIT_APPROVAL", "t-old"),
                                                     ("PASS", "t-other")])
def test_resume_outcome_refuses_unreusable_decisions(gw, gate_status, comp_trace):
    db = FakeDB()
    _seed_resume(db, gate_status, comp_trace)
    r = _resume(_client(gw, db))
    assert r.status_code == 503 and r.json()["reason"] == "RESUME_GATE_UNAVAILABLE"


def test_resume_outcome_without_any_prior_build_is_503(gw):
    assert _resume(_client(gw, FakeDB())).status_code == 503


# ================================================================================ DEPLOY_ONLY gate
def test_deploy_only_gate_allows_default_branch_and_refuses_others(gw):
    db = FakeDB()
    db.docs[f"workloads/{PID}"] = {"default_branch": "main"}
    c = _client(gw, db)
    ok = c.post("/governance/deploy-only-gate", json={"trace_id": TRACE, "product_id": PID, "branch": "main"})
    assert ok.status_code == 200 and ok.json()["status"] == "ALLOW"
    no = c.post("/governance/deploy-only-gate", json={"trace_id": TRACE, "product_id": PID, "branch": "feature/x"})
    assert no.status_code == 403 and no.json()["error_class"] == "POLICY_REJECTED"
    assert no.json()["stage"] == "deploy_only_gate"


def test_deploy_only_gate_unknown_workload_and_outage(gw):
    body = {"trace_id": TRACE, "product_id": PID, "branch": "main"}
    assert _client(gw, FakeDB()).post("/governance/deploy-only-gate", json=body).status_code == 409
    assert _client(gw, None).post("/governance/deploy-only-gate", json=body).status_code == 503


# ================================================================================ AJ-7 approval callback registration
def _seed_pr_record(db, **kw):
    rec = {"product_id": PID, "trace_id": TRACE, "status": "PENDING"}
    rec.update(kw)
    db.docs["approval_requests/appr-app-abc123"] = rec
    db.docs["approval_requests/plan-app-stale"] = {"product_id": PID, "trace_id": "old", "status": "PENDING"}


def _register(c, **kw):
    body = {"trace_id": TRACE, "product_id": PID, "approval_id": "appr-app-abc123", "callback_url": CB}
    body.update(kw)
    return c.post("/events/approval-callback", json=body)


def test_approval_callback_writes_exactly_one_record(gw):
    db = FakeDB()
    _seed_pr_record(db)
    r = _register(_client(gw, db))
    assert r.status_code == 200 and r.json()["status"] == "SUCCESS"
    assert db.docs["approval_requests/appr-app-abc123"]["callback_url"] == CB
    assert "callback_url" not in db.docs["approval_requests/plan-app-stale"]  # no fan-out


def test_approval_callback_empty_id_is_422_and_touches_nothing(gw):
    db = FakeDB()
    _seed_pr_record(db)
    assert _register(_client(gw, db), approval_id="").status_code == 422
    assert all("callback_url" not in v for k, v in db.docs.items() if k.startswith("approval_requests/"))


@pytest.mark.parametrize("kw, code", [({"product_id": "other"}, 409), ({"trace_id": "other"}, 409),
                                      ({"status": "APPROVED"}, 409)])
def test_approval_callback_mismatch_is_409(gw, kw, code):
    db = FakeDB()
    _seed_pr_record(db, **kw)
    assert _register(_client(gw, db)).status_code == code


def test_approval_callback_missing_record_404_and_store_outage_503(gw):
    assert _register(_client(gw, FakeDB())).status_code == 404
    assert _register(_client(gw, None)).status_code == 503


# ================================================================================ plan-approval-request 503
def test_plan_approval_request_store_failure_is_503(gw, monkeypatch):
    class _Boom:
        def collection(self, name):
            raise RuntimeError("firestore down")

    monkeypatch.setattr(gw, "db", _Boom())
    r = TestClient(gw.app).post("/events/plan-approval-request", json={"product_id": PID, "trace_id": TRACE,
                                                                       "callback_url": CB})
    assert r.status_code == 503 and r.json()["reason"] == "APPROVAL_NOT_RECORDED"


# ================================================================================ F5 workflow-status persistence
def test_workflow_status_persists_error_class(gw, monkeypatch):
    db = FakeDB()
    import google.cloud.firestore as fs_mod

    monkeypatch.setattr(fs_mod, "Client", lambda *a, **k: db)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    r = TestClient(gw.app).post("/events/workflow-status", json={
        "trace_id": TRACE, "product_id": PID, "status": "FAILED", "current_stage": "FAILED",
        "error_class": "STATE_LOCKED", "failed_stage": "terraform", "reason": "STATE_LOCKED",
        "error_detail": "Terraform deployment failed: STATE_LOCKED"})
    assert r.status_code == 200, r.text
    doc = db.docs[f"pipeline_executions/{TRACE}"]
    assert doc["error_class"] == "STATE_LOCKED" and doc["failed_stage"] == "terraform"
    assert doc["error"] == "Terraform deployment failed: STATE_LOCKED"


# ================================================================================ F6 developer re-dispatch guard
def _dev_req(gw, ctx="Error: state locked"):
    return gw.DeveloperExecuteRequest(trace_id=TRACE, product_id=PID, tf_remediation_context=ctx)


def test_f6_state_locked_refuses_developer_remediation(gw):
    db = FakeDB()
    db.docs[f"pipeline_executions/{TRACE}"] = {"stages": {"terraform": {"error_class": "STATE_LOCKED",
                                                                         "lock_holder": "tf-applier-x"}}}
    from gate_errors import OperatorActionRequiredError

    with pytest.raises(OperatorActionRequiredError) as ei:
        gw._assert_tf_remediation_allowed(_dev_req(gw), db)
    assert ei.value.to_body()["error_class"] == "OPERATOR_ACTION_REQUIRED"
    assert ei.value.details["lock_holder"] == "tf-applier-x"


@pytest.mark.parametrize("cls", ["IAC_DEFECT", "", None])
def test_f6_negative_remediable_or_unclassified_is_allowed(gw, cls):
    db = FakeDB()
    db.docs[f"pipeline_executions/{TRACE}"] = {"stages": {"terraform": {"error_class": cls}}}
    gw._assert_tf_remediation_allowed(_dev_req(gw), db)  # no raise


def test_f6_negative_first_dispatch_never_reads_the_store(gw):
    gw._assert_tf_remediation_allowed(_dev_req(gw, ctx=""), None)  # no remediation context: no store needed


def test_f6_store_unreadable_refuses_remediation(gw):
    from gate_errors import GateUnavailableError

    with pytest.raises(GateUnavailableError):
        gw._assert_tf_remediation_allowed(_dev_req(gw), None)


# ================================================================================ Pub/Sub intake (AJ-11 / AJ-12)
def _envelope(payload):
    return {"message": {"data": base64.b64encode(json.dumps(payload).encode()).decode(), "messageId": "m1"}}


def _intake(gw, monkeypatch, db, *, create_fails=False, project="mock-stackvend-project"):
    import google.cloud.firestore as fs_mod

    monkeypatch.setattr(fs_mod, "Client", lambda *a, **k: db)
    monkeypatch.setenv("REGION", "us-central1")   # FALLBACK-URLS: dispatch needs REGION (no default)
    if project:
        monkeypatch.setenv("PROJECT_ID", project)
    else:
        monkeypatch.delenv("PROJECT_ID", raising=False)
    created = []

    class _Exec:
        def __init__(self, argument=None):
            self.argument = argument

    class _Client:
        def workflow_path(self, *a):
            return "projects/p/locations/r/workflows/w"

        def create_execution(self, parent=None, execution=None):
            if create_fails:
                raise RuntimeError("workflows API down")
            created.append(execution)
            return types.SimpleNamespace(name=parent + "/executions/e-1")

    fake_exec_mod = types.SimpleNamespace(ExecutionsClient=_Client, Execution=_Exec)
    monkeypatch.setitem(sys.modules, "google.cloud.workflows", types.SimpleNamespace(executions_v1=fake_exec_mod))
    monkeypatch.setitem(sys.modules, "google.cloud.workflows.executions_v1", fake_exec_mod)
    monkeypatch.setitem(sys.modules, "google.cloud.workflows_v1", types.SimpleNamespace())
    monkeypatch.setattr(gw, "resolve_service_url", lambda name, *a, **k: f"https://{name}.example.run.app")
    r = TestClient(gw.app).post("/events/pubsub-intake", json=_envelope({"product_id": PID, "trace_id": TRACE}))
    return r, created


def test_intake_negative_dispatches_once(gw, monkeypatch):
    db = FakeDB()
    r, created = _intake(gw, monkeypatch, db)
    assert r.status_code == 200 and r.json()["status"] == "DISPATCHED" and len(created) == 1


def test_intake_redelivery_is_deduplicated(gw, monkeypatch):
    db = FakeDB()
    db.docs[f"pipeline_executions/{TRACE}"] = {"workflow_execution_id": "e-0"}
    r, created = _intake(gw, monkeypatch, db)
    assert r.status_code == 200 and r.json()["status"] == "DUPLICATE" and created == []


def test_intake_dispatch_failure_is_503_for_pubsub_retry(gw, monkeypatch):
    r, _ = _intake(gw, monkeypatch, FakeDB(), create_fails=True)
    assert r.status_code == 503


def test_intake_kill_switch_unreadable_is_503(gw, monkeypatch):
    db = FakeDB()
    db.fail_reads = True
    r, created = _intake(gw, monkeypatch, db)
    assert r.status_code == 503 and created == []


def test_intake_kill_switch_active_suppresses(gw, monkeypatch):
    db = FakeDB()
    db.docs["governance/platform_kill_switch"] = {"emergency_stop_active": True}
    r, created = _intake(gw, monkeypatch, db)
    assert r.json()["status"] == "SUPPRESSED_BY_EMERGENCY_STOP" and created == []


def test_intake_without_project_is_503(gw, monkeypatch):
    r, created = _intake(gw, monkeypatch, FakeDB(), project="")
    assert r.status_code == 503 and created == []


# ================================================================================ bundle RT F7: AJ-7 as a transaction
def _transactional_approval_store(decide_between_read_and_write):
    """A real firestore_v1 DocumentReference subclass over an in-memory store, driven by the REAL
    firestore_v1.transactional retry loop: a commit whose read set changed since it was read raises Aborted and the
    library re-runs the function (same technique as tests/test_cc_approval_concurrency.py)."""
    import copy

    from google.api_core import exceptions as gexc
    from google.cloud.firestore_v1.document import DocumentReference

    store = {"docs": {}, "versions": {}, "log": [], "plain_sets": 0}

    def write(key, data, merge):
        cur = store["docs"].get(key) if merge else None
        store["docs"][key] = {**(cur or {}), **data}
        store["versions"][key] = store["versions"].get(key, 0) + 1

    class Txn:
        _read_only = False
        _max_attempts = 5

        def __init__(self):
            self._id, self.attempts, self.reads, self.writes = None, 0, {}, []

        def _clean_up(self):
            self.reads, self.writes, self._id = {}, [], None

        def _begin(self, retry_id=None):
            self.attempts += 1
            self._id = f"txn-{self.attempts}".encode()

        def _rollback(self):
            store["log"].append("rolled_back")
            self._clean_up()

        def update(self, ref, fields):
            self.writes.append((ref._path, dict(fields)))

        def _commit(self):
            stale = any(store["versions"].get(k, 0) != v for k, v in self.reads.items())
            if not stale:
                for key, fields in self.writes:
                    write(key, fields, True)
            store["log"].append("aborted" if stale else "committed")
            self._clean_up()
            if stale:
                raise gexc.Aborted("concurrent modification")
            return []

    class Client:
        def transaction(self):
            return Txn()

    client = Client()
    reads = {"n": 0}

    class Snap:
        def __init__(self, data):
            self._d, self.exists = data, data is not None

        def to_dict(self):
            return copy.deepcopy(self._d) if self._d is not None else None

    class Ref(DocumentReference):
        def get(self, field_paths=None, transaction=None, **kw):
            data, ver = copy.deepcopy(store["docs"].get(self._path)), store["versions"].get(self._path, 0)
            if transaction is not None:
                transaction.reads[self._path] = ver
            reads["n"] += 1
            if reads["n"] == 1 and decide_between_read_and_write:
                write(self._path, {"status": "APPROVED"}, True)  # the CC's decision lands right after our read
            return Snap(data)

        def set(self, data, merge=False):
            store["plain_sets"] += 1
            write(self._path, data, merge)

    class Coll:
        def __init__(self, name):
            self.name = name

        def document(self, doc_id):
            return Ref(self.name, doc_id, client=client)

    class DB:
        def collection(self, name):
            return Coll(name)

    write(("approval_requests", "appr-app-abc123"), {"product_id": PID, "trace_id": TRACE, "status": "PENDING"}, False)
    return store, DB()


def test_approval_callback_decision_between_read_and_write_is_409_and_writes_nothing(gw):
    """Bundle RT F7: under read-then-merge this answered 200 and left a callback_url on a decided record."""
    store, db = _transactional_approval_store(decide_between_read_and_write=True)
    r = _register(_client(gw, db))
    assert r.status_code == 409, r.text
    assert r.json()["reason"] == "NOT_PENDING"
    rec = store["docs"][("approval_requests", "appr-app-abc123")]
    assert rec["status"] == "APPROVED" and "callback_url" not in rec
    assert store["log"][0] == "aborted" and store["plain_sets"] == 0


def test_approval_callback_transaction_commits_when_uncontended(gw):
    store, db = _transactional_approval_store(decide_between_read_and_write=False)
    r = _register(_client(gw, db))
    assert r.status_code == 200, r.text
    assert store["docs"][("approval_requests", "appr-app-abc123")]["callback_url"] == CB
    assert store["log"] == ["committed"] and store["plain_sets"] == 0
