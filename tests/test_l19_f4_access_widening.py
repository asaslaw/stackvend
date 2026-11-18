"""Owner decision L19-F4 (10-19): widening a workload's access through the admin PATCH needs confirmation, is audited
as a widening, and forces plan approval on the workload's next run.

* `shared.access_policy.widening_changes` (typed, no text matching): ACCESS_MODE_BREADTH order PRIVATE_IAM <
  PRIVATE_IAP < PUBLIC_APP; a member that was not in the previous private record; no valid previous record.
* `PATCH /api/workloads/{pid}/access`: widening without `confirm_widening: true` -> 422 ACCESS_WIDENING_UNCONFIRMED,
  nothing written; narrowing / no-op needs no confirmation; a confirmed widening writes the record, the audit entry
  (`widening: true`, previous + new record) and the one-shot `access_widening_approval` flag in ONE batch.
* gateway pre-build gate: a pending flag adds ACCESS_WIDENED (AWAIT_APPROVAL); only an APPROVED decision on exactly
  the reviewed flag clears it, so the next run is forced exactly once; unreadable -> 503; a resume is refused; the
  developer refuses to build a still-pending widening (ACCESS_WIDENING_UNAPPROVED) before any LLM call.

Hermetic: the CC router on an in-memory Firestore fake (tests/test_l19_11_access_intake.py), the gateway with
tests/fd4f_support.FakeDB. No network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy
import os
import sys
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")
for _p in (GW_DIR, os.path.dirname(__file__)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fd4f_support import FakeDB as GwFakeDB, gw  # noqa: F401,E402  (gw is a fixture)
from shared.access_policy import (  # noqa: E402
    ACCESS_MODE_BREADTH, ACCESS_WIDENING_APPROVAL_FIELD, AccessMode, AccessPolicy, AccessWideningApproval,
    WideningChange, is_widening, widening_changes)
from test_l19_11_access_intake import ADMIN_H, FakeDB, _client, cc  # noqa: F401,E402  (cc is a fixture)

PID = "shop-app"
A, B, C = "user:a@example.com", "user:b@example.com", "group:c@example.com"


def _policy(mode, members=(), a8=None):
    google = "DISABLED" if mode != "PUBLIC_APP" else ("BYO" if a8 else "SHARED_PLATFORM_CLIENT")
    return AccessPolicy(mode=mode, invoker_principals=list(members), sign_in={"google": google},
                        tenant_isolation_required=a8 if mode == "PUBLIC_APP" else None, source="operator_hitl")


def _record(mode, members=(), a8=None):
    p = _policy(mode, members, a8)
    rec = p.model_dump(mode="json")
    rec["invoker_principals"] = p.invoker_members()
    return rec


def _body(mode, members=(), a8=None, **kw):
    b = {"mode": mode, "invoker_principals": list(members)}
    if mode == "PUBLIC_APP":
        b["tenant_isolation_required"] = bool(a8)
    b.update(kw)
    return b


# ============================================================================ 1. the definition (pure)
def test_mode_order_is_explicit_and_total():
    assert set(ACCESS_MODE_BREADTH) == set(AccessMode)
    assert ACCESS_MODE_BREADTH[AccessMode.PRIVATE_IAM] < ACCESS_MODE_BREADTH[AccessMode.PRIVATE_IAP] \
        < ACCESS_MODE_BREADTH[AccessMode.PUBLIC_APP]
    assert len(set(ACCESS_MODE_BREADTH.values())) == len(AccessMode)


MM = "MODE_WIDENED"
MA = "MEMBERS_ADDED"
MATRIX = [
    # (old mode, old members, new mode, new members, expected changes)
    ("PRIVATE_IAP", [A], "PUBLIC_APP", [], [MM]),            # private -> public
    ("PRIVATE_IAM", [A], "PUBLIC_APP", [], [MM]),
    ("PRIVATE_IAM", [A], "PRIVATE_IAP", [A], [MM]),           # IAM-only -> IAP (browser path for the same members)
    ("PRIVATE_IAM", [A], "PRIVATE_IAP", [A, B], [MM, MA]),
    ("PUBLIC_APP", [], "PRIVATE_IAP", [A, B], []),            # public -> private: narrowing whatever the members
    ("PUBLIC_APP", [], "PRIVATE_IAM", [A], []),
    ("PRIVATE_IAP", [A], "PRIVATE_IAM", [A], []),             # IAP -> IAM-only: narrowing
    ("PRIVATE_IAP", [A, B], "PRIVATE_IAM", [A], []),
    ("PRIVATE_IAP", [A], "PRIVATE_IAM", [B], [MA]),           # mode down but a new member
    ("PRIVATE_IAP", [A], "PRIVATE_IAP", [A, B], [MA]),        # member added
    ("PRIVATE_IAP", [A], "PRIVATE_IAP", [B], [MA]),           # member swapped
    ("PRIVATE_IAP", [A, B], "PRIVATE_IAP", [A], []),          # member removed
    ("PRIVATE_IAP", [A, B], "PRIVATE_IAP", [B, A], []),       # same set, other order
    ("PRIVATE_IAP", [A], "PRIVATE_IAP", [A], []),             # no-op
    ("PRIVATE_IAP", ["domain:example.com"], "PRIVATE_IAP", [A], [MA]),  # membership never resolved (conservative)
    ("PUBLIC_APP", [], "PUBLIC_APP", [], []),
]


@pytest.mark.parametrize("old_mode, old_m, new_mode, new_m, expected", MATRIX)
def test_widening_matrix(old_mode, old_m, new_mode, new_m, expected):
    old, new = _policy(old_mode, old_m, False), _policy(new_mode, new_m, False)
    assert [c.value for c in widening_changes(old, new)] == expected
    assert is_widening(old, new) is bool(expected)


def test_no_previous_record_is_always_a_widening():
    for new in (_policy("PRIVATE_IAM", [A]), _policy("PRIVATE_IAP", [A]), _policy("PUBLIC_APP", a8=True)):
        assert widening_changes(None, new) == [WideningChange.NO_PREVIOUS_RECORD]


def test_a8_answer_alone_is_not_counted():
    """Documented limit: only mode and members are compared (owner text); the A8 answer is not."""
    assert widening_changes(_policy("PUBLIC_APP", a8=True), _policy("PUBLIC_APP", a8=False)) == []


def test_flag_field_name_is_one_constant_everywhere(gw):
    import workflow_gates
    from developer_agent import handler

    assert workflow_gates.ACCESS_WIDENING_APPROVAL_FIELD == ACCESS_WIDENING_APPROVAL_FIELD == \
        handler.ACCESS_WIDENING_APPROVAL_FIELD == "access_widening_approval"
    assert workflow_gates.REASON_ACCESS_WIDENED in workflow_gates.PRE_BUILD_REASONS


def test_widening_flag_model_is_strict():
    ok = {"audit_log_id": "a1", "set_at": "t", "set_by": "admin@example.com", "previous_mode": "PRIVATE_IAP",
          "new_mode": "PUBLIC_APP", "changes": ["MODE_WIDENED"]}
    assert AccessWideningApproval(**ok).required is True
    for bad in ({**ok, "changes": []}, {**ok, "required": False}, {**ok, "extra": 1}, {**ok, "new_mode": "public"}):
        with pytest.raises(ValueError):
            AccessWideningApproval(**bad)


# ============================================================================ 2. PATCH: confirm / audit / atomic
def _patch(wl, monkeypatch, body, initial):
    fake_db = FakeDB(initial)
    client = _client(wl, monkeypatch, fake_db)
    return client.patch(f"/api/workloads/{PID}/access", json=body, headers=ADMIN_H), fake_db


def _wl(access=None, **extra):
    doc = {"product_id": PID, "status": "DEPLOYED", **extra}
    if access is not None:
        doc["access"] = access
    return {f"workloads/{PID}": doc}


def _audits(fake_db):
    return [fake_db[k] for k in sorted(fake_db) if k.startswith(f"workloads/{PID}/audit_logs/")]


@pytest.mark.parametrize("old_mode, old_m, new_mode, new_m, expected", MATRIX)
@pytest.mark.parametrize("confirm", [None, False, True])
def test_patch_widening_matrix(cc, monkeypatch, old_mode, old_m, new_mode, new_m, expected, confirm):
    _, wl = cc
    initial = _wl(_record(old_mode, old_m, False))
    body = _body(new_mode, new_m, False)
    if confirm is not None:
        body["confirm_widening"] = confirm
    r, fake_db = _patch(wl, monkeypatch, body, initial)
    if expected and confirm is not True:
        assert r.status_code == 422, r.text
        detail = r.json()["detail"]
        assert detail["error_class"] == "ACCESS_WIDENING_UNCONFIRMED" and detail["changes"] == expected
        assert detail["previous_mode"] == old_mode and detail["new_mode"] == new_mode
        assert dict(fake_db) == initial and fake_db.writes == [] and fake_db.commits == 0
        return
    assert r.status_code == 200, r.text
    doc = fake_db[f"workloads/{PID}"]
    (audit,) = _audits(fake_db)
    assert audit["widening"] is bool(expected) and audit["widening_changes"] == expected
    assert audit["previous_access"] == initial[f"workloads/{PID}"]["access"] and audit["new_access"] == doc["access"]
    assert r.json()["plan_approval_forced"] is bool(expected) and fake_db.commits == 1
    if expected:
        flag = AccessWideningApproval.model_validate(doc[ACCESS_WIDENING_APPROVAL_FIELD])
        audit_id = [k for k in fake_db if k.startswith(f"workloads/{PID}/audit_logs/")][0].rsplit("/", 1)[-1]
        assert flag.audit_log_id == audit_id and flag.set_by == "admin@example.com"
        assert flag.previous_mode.value == old_mode and flag.new_mode.value == new_mode
        assert [c.value for c in flag.changes] == expected
    else:
        assert ACCESS_WIDENING_APPROVAL_FIELD not in doc


@pytest.mark.parametrize("previous", [None, "PRIVATE_IAP", {"mode": "PRIVATE_IAP"}, {"mode": "BOGUS"}])
def test_patch_without_a_valid_previous_record_needs_confirmation(cc, monkeypatch, previous):
    _, wl = cc
    initial = _wl() if previous is None else _wl(previous)
    r, fake_db = _patch(wl, monkeypatch, _body("PRIVATE_IAP", [A]), initial)
    assert r.status_code == 422 and r.json()["detail"]["changes"] == ["NO_PREVIOUS_RECORD"]
    assert dict(fake_db) == initial and fake_db.writes == []
    r, fake_db = _patch(wl, monkeypatch, _body("PRIVATE_IAP", [A], confirm_widening=True), initial)
    assert r.status_code == 200
    flag = fake_db[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD]
    assert flag["previous_mode"] is None and flag["changes"] == ["NO_PREVIOUS_RECORD"]


@pytest.mark.parametrize("confirm", ["true", 1, "yes"])
def test_confirm_is_a_strict_boolean(cc, monkeypatch, confirm):
    _, wl = cc
    initial = _wl(_record("PRIVATE_IAP", [A]))
    r, fake_db = _patch(wl, monkeypatch, _body("PUBLIC_APP", a8=False, confirm_widening=confirm), initial)
    assert r.status_code == 422 and dict(fake_db) == initial and fake_db.writes == []


def test_failed_audit_write_changes_nothing(cc, monkeypatch):
    """Atomicity: the record, the audit entry and the flag are one batch; a failed commit leaves the doc as it was."""
    _, wl = cc
    initial = _wl(_record("PRIVATE_IAP", [A]))
    fake_db = FakeDB(initial, fail_commit=True)
    client = _client(wl, monkeypatch, fake_db)
    r = client.patch(f"/api/workloads/{PID}/access", headers=ADMIN_H,
                     json=_body("PUBLIC_APP", a8=False, confirm_widening=True))
    assert r.status_code == 500
    assert dict(fake_db) == initial and _audits(fake_db) == [] and fake_db.commits == 0


def test_narrowing_keeps_a_pending_flag(cc, monkeypatch):
    """An unapproved widening stays unapproved when a later PATCH narrows (the flag is only cleared by approval)."""
    _, wl = cc
    pending = {"required": True, "audit_log_id": "auto0", "set_at": "t0", "set_by": "admin@example.com",
               "previous_mode": "PRIVATE_IAP", "new_mode": "PRIVATE_IAP", "changes": ["MEMBERS_ADDED"]}
    initial = _wl(_record("PRIVATE_IAP", [A, B]), **{ACCESS_WIDENING_APPROVAL_FIELD: pending})
    r, fake_db = _patch(wl, monkeypatch, _body("PRIVATE_IAP", [A]), initial)
    assert r.status_code == 200 and r.json()["widening"] is False
    assert fake_db[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] == pending


def test_a_second_widening_replaces_the_flag(cc, monkeypatch):
    _, wl = cc
    old_flag = {"required": True, "audit_log_id": "auto0", "set_at": "t0", "set_by": "admin@example.com",
                "previous_mode": "PRIVATE_IAP", "new_mode": "PRIVATE_IAP", "changes": ["MEMBERS_ADDED"]}
    initial = _wl(_record("PRIVATE_IAP", [A, B]), **{ACCESS_WIDENING_APPROVAL_FIELD: old_flag})
    r, fake_db = _patch(wl, monkeypatch, _body("PUBLIC_APP", a8=False, confirm_widening=True), initial)
    assert r.status_code == 200
    flag = fake_db[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD]
    # RT R2: a new flag (new audit id), still described from the pending flag's baseline with the changes accumulated
    assert flag != old_flag and flag["audit_log_id"] != old_flag["audit_log_id"] and flag["new_mode"] == "PUBLIC_APP"
    assert flag["changes"] == ["MEMBERS_ADDED", "MODE_WIDENED"] and flag["previous_mode"] == "PRIVATE_IAP"


# ============================================================================ 3. gateway: forced exactly once
TRACE, TRACE2 = "tr-f4-1", "tr-f4-2"
CB = "https://workflowexecutions.googleapis.com/v1/projects/p/locations/r/workflows/w/executions/e/callbacks/c1"
FLAG = AccessWideningApproval(audit_log_id="auto1", set_at="2026-10-19T00:00:00+00:00", set_by="admin@example.com",
                              previous_mode="PRIVATE_IAP", new_mode="PUBLIC_APP",
                              changes=["MODE_WIDENED"]).model_dump(mode="json")


def _gw(gw, db):
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: db
    return TestClient(gw.app)


def _gate(c, trace=TRACE, cycle=0):
    body = {"trace_id": trace, "product_id": PID, "callback_url": CB, "rework_cycle": cycle,
            "compliance": {"requires_human_approval": False, "has_policy_conflicts": False,
                           "allow_unauthenticated": True},
            "finops": {"requires_human_approval": False, "monthly_cost_delta_usd": 1.0},
            "finops_error": "", "policy_harvest_status": "SUCCESS", "operator_requested": False,
            "spec_doc_id": "", "task_dag": []}
    return c.post("/events/pre-build-gate", json=body)


def _decide(db, c, decision, trace=TRACE, cycle=0):
    aid = f"appr-plan-{trace}-{cycle}"
    db.docs[f"approval_requests/{aid}"]["status"] = decision  # what the CC approvals route writes
    return c.post("/events/pre-build-gate/decision",
                  json={"trace_id": trace, "product_id": PID, "approval_id": aid, "decision": decision})


def _gw_db(flag=FLAG):
    db = GwFakeDB()
    db.docs[f"workloads/{PID}"] = {"product_id": PID, "access": _record("PUBLIC_APP", a8=False)}
    if flag is not None:
        db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] = copy.deepcopy(flag)
    return db


def test_no_flag_passes_unchanged(gw):
    """Negative: without a pending widening the gate decides exactly as before."""
    db = _gw_db(flag=None)
    r = _gate(_gw(gw, db))
    assert r.json() == {"status": "SUCCESS", "decision": "PASS", "gate_reasons": [], "approval_id": ""}


def test_explicit_null_flag_is_nothing_pending(gw):
    db = _gw_db(flag=None)
    db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] = None  # what an APPROVED decision leaves
    assert _gate(_gw(gw, db)).json()["decision"] == "PASS"


def test_next_run_is_forced_exactly_once(gw):
    db = _gw_db()
    c = _gw(gw, db)
    r = _gate(c)
    assert r.json()["decision"] == "AWAIT_APPROVAL" and r.json()["gate_reasons"] == ["ACCESS_WIDENED"]
    rec = db.docs[f"approval_requests/appr-plan-{TRACE}-0"]
    assert rec["access_widening_reviewed"] == FLAG and "ACCESS_WIDENED" in rec["risk_assessment"]
    assert db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] == FLAG  # requesting does not consume
    assert _decide(db, c, "APPROVED").status_code == 200
    wdoc = db.docs[f"workloads/{PID}"]
    assert wdoc[ACCESS_WIDENING_APPROVAL_FIELD] is None
    assert wdoc["access_widening_last_approval"]["approval_id"] == f"appr-plan-{TRACE}-0"
    assert wdoc["access_widening_last_approval"]["approved_flag"] == FLAG
    assert wdoc["last_prebuild_gate"]["status"] == "APPROVED"
    # the run after that is not forced again
    assert _gate(c, trace=TRACE2).json()["decision"] == "PASS"


def test_widening_and_strict_compliance_advisory_both_hold_the_run(gw, monkeypatch):
    """l19-on-main merge: L19-F4 ACCESS_WIDENED and settings-toggles COMPLIANCE_PROFILE_ADVISORY are independent
    reasons of one gate; both are listed, the card carries both, and approving still consumes the flag."""
    monkeypatch.setattr(gw, "_compliance_advisories_block", lambda: True)  # governance.strict_compliance_gates on
    db = _gw_db()
    c = _gw(gw, db)
    advisory = {"profile": "HIPAA", "matched_terms": ["patient"], "advisory": "Set compliance_profile=HIPAA."}
    body = {"trace_id": TRACE, "product_id": PID, "callback_url": CB, "rework_cycle": 0,
            "compliance": {"requires_human_approval": False, "has_policy_conflicts": False,
                           "allow_unauthenticated": True, "profile_advisories": [advisory]},
            "finops": {"requires_human_approval": False, "monthly_cost_delta_usd": 1.0},
            "finops_error": "", "policy_harvest_status": "SUCCESS", "operator_requested": False,
            "spec_doc_id": "", "task_dag": []}
    r = c.post("/events/pre-build-gate", json=body)
    assert r.status_code == 200 and r.json()["decision"] == "AWAIT_APPROVAL"
    assert r.json()["gate_reasons"] == ["ACCESS_WIDENED", "COMPLIANCE_PROFILE_ADVISORY"]
    rec = db.docs[f"approval_requests/appr-plan-{TRACE}-0"]
    assert rec["access_widening_reviewed"] == FLAG and advisory["advisory"] in rec["risk_assessment"]
    assert "ACCESS_WIDENED" in rec["risk_assessment"]
    assert _decide(db, c, "APPROVED").status_code == 200
    assert db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] is None


def test_retried_approved_decision_is_idempotent(gw):
    db = _gw_db()
    c = _gw(gw, db)
    _gate(c)
    assert _decide(db, c, "APPROVED").status_code == 200
    writes_before = len(db.writes)
    assert _decide(db, c, "APPROVED").status_code == 200
    assert not [w for w in db.writes[writes_before:] if ACCESS_WIDENING_APPROVAL_FIELD in w[1]]


@pytest.mark.parametrize("decision", ["REJECTED", "REWORK"])
def test_rejection_or_rework_keeps_the_flag_and_asks_again(gw, decision):
    db = _gw_db()
    c = _gw(gw, db)
    _gate(c)
    assert _decide(db, c, decision).status_code == 200
    assert db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] == FLAG
    nxt = _gate(c, cycle=1) if decision == "REWORK" else _gate(c, trace=TRACE2)
    assert nxt.json()["decision"] == "AWAIT_APPROVAL" and "ACCESS_WIDENED" in nxt.json()["gate_reasons"]


def test_flag_replaced_after_review_is_409_and_kept(gw):
    db = _gw_db()
    c = _gw(gw, db)
    _gate(c)
    newer = {**FLAG, "audit_log_id": "auto2"}
    db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] = newer
    r = _decide(db, c, "APPROVED")
    assert r.status_code == 409 and r.json()["reason"] == "ACCESS_WIDENED_AFTER_REVIEW"
    assert db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] == newer
    assert "last_prebuild_gate" not in db.docs[f"workloads/{PID}"] or \
        db.docs[f"workloads/{PID}"]["last_prebuild_gate"]["status"] != "APPROVED"


def test_flag_set_after_an_approval_for_another_reason_is_409(gw):
    db = _gw_db(flag=None)
    c = _gw(gw, db)
    body_reason = _gate(c)
    assert body_reason.json()["decision"] == "PASS"
    # an approval requested for another reason (no widening reviewed), then a widening PATCH lands
    db.docs[f"approval_requests/appr-plan-{TRACE2}-0"] = {
        "approval_id": f"appr-plan-{TRACE2}-0", "trace_id": TRACE2, "product_id": PID, "status": "PENDING",
        "gate_reasons": ["OPERATOR_REQUESTED"], "access_widening_reviewed": None}
    db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] = FLAG
    r = _decide(db, c, "APPROVED", trace=TRACE2)
    assert r.status_code == 409 and r.json()["reason"] == "ACCESS_WIDENED_AFTER_REVIEW"
    assert db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] == FLAG


def test_malformed_flag_is_pending(gw):
    """Fail closed: any non-null value forces approval (the gate never parses it into 'nothing pending')."""
    db = _gw_db(flag="yes")
    c = _gw(gw, db)
    assert _gate(c).json()["gate_reasons"] == ["ACCESS_WIDENED"]
    assert _decide(db, c, "APPROVED").status_code == 200
    assert db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] is None


def test_unreadable_workload_doc_is_503_never_a_pass(gw):
    db = _gw_db()
    db.fail_reads = True
    r = _gate(_gw(gw, db))
    assert r.status_code == 503 and r.json()["error_class"] == "GATE_UNAVAILABLE"
    assert not [p for p in db.docs if p.startswith("approval_requests/")]


def test_unreadable_at_decision_is_503_and_nothing_cleared(gw):
    db = _gw_db()
    c = _gw(gw, db)
    _gate(c)
    db.docs[f"approval_requests/appr-plan-{TRACE}-0"]["status"] = "APPROVED"
    calls = {"n": 0}
    real_collection = db.collection

    def flaky(name):  # the approval record reads fine; the workload document does not
        col = real_collection(name)
        if name == "workloads":
            calls["n"] += 1
            return SimpleNamespace(document=lambda _id: SimpleNamespace(
                get=lambda: (_ for _ in ()).throw(RuntimeError("read failed"))))
        return col

    db.collection = flaky
    r = c.post("/events/pre-build-gate/decision", json={"trace_id": TRACE, "product_id": PID,
                                                        "approval_id": f"appr-plan-{TRACE}-0",
                                                        "decision": "APPROVED"})
    db.collection = real_collection
    assert r.status_code == 503 and calls["n"] >= 1
    assert db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] == FLAG


def test_clear_is_a_precondition_write_and_rereads_on_contention(gw):
    db = _gw_db()
    c = _gw(gw, db)
    _gate(c)
    tokens = iter([{"last_update_time": "stale"}])  # first attempt: the document changed since it was read
    real = db.write_option
    issued = []

    def write_option(**kw):
        issued.append(kw)
        return next(tokens, None) or real(**kw)

    db.write_option = write_option
    assert _decide(db, c, "APPROVED").status_code == 200
    assert len(issued) == 2 and all("last_update_time" in kw for kw in issued)  # precondition on every attempt
    assert db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] is None


def test_resume_is_refused_while_a_widening_is_pending(gw):
    db = _gw_db()
    db.docs[f"workloads/{PID}"]["last_prebuild_gate"] = {"status": "PASS", "trace_id": TRACE, "product_id": PID,
                                                         "rework_cycle": 0}
    db.docs[f"workloads/{PID}/compliance_audits/{TRACE}"] = {"trace_id": TRACE, "product_id": PID}
    db.docs[f"workloads/{PID}/prebuild_task_dags/{TRACE}"] = {
        "trace_id": TRACE, "product_id": PID, "rework_cycle": 0, "status": "STORED", "task_count": 1,
        "task_dag_json": '[{"step_id": "S1"}]'}
    c = _gw(gw, db)
    r = c.post("/agent/resume/outcome", json={"trace_id": TRACE2, "product_id": PID})
    assert r.status_code == 503 and "ACCESS_WIDENING_PENDING" in r.json()["details"]["problems"]
    db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] = None  # negative: nothing pending -> reusable
    assert c.post("/agent/resume/outcome", json={"trace_id": TRACE2, "product_id": PID}).status_code == 200


# ============================================================================ 4. developer: never builds it unapproved
class _ExplodingModels:
    def __init__(self):
        self.calls = []

    def generate_content(self, *a, **k):
        self.calls.append(1)
        raise AssertionError("no LLM call may happen before the access policy is resolved")


@pytest.fixture
def agent(monkeypatch):
    monkeypatch.setenv("ENABLE_DEVELOPER_SWARM", "false")
    for k in ("K_SERVICE", "PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GEMINI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    from google.cloud import firestore

    def _no_firestore(*a, **k):
        raise RuntimeError("no Firestore in this test")
    monkeypatch.setattr(firestore, "Client", _no_firestore)
    from developer_agent.handler import DeveloperAgent

    return DeveloperAgent()


def _resolve(agent):
    return agent._resolve_run_access(PID, "tr-dev", [], None, None, None, None, None)


def test_developer_refuses_a_pending_widening_before_any_llm_call(agent):
    from unittest.mock import patch

    from developer_agent.errors import ACCESS_WIDENING_UNAPPROVED, DeveloperStageError

    agent.db = _gw_db()
    models = _ExplodingModels()
    agent.genai_client = SimpleNamespace(models=models)
    with pytest.raises(DeveloperStageError) as ei:
        _resolve(agent)
    assert ei.value.error_class == ACCESS_WIDENING_UNAPPROVED
    with patch.object(agent, "fetch_existing_repo_files", return_value={}), pytest.raises(DeveloperStageError) as ei2:
        # main FD-4R R-6: the developer needs the typed compliance decision first (public decision = the record's mode)
        agent.generate_code_files(product_id=PID, spec_text="a shop", task_dag=[], allow_unauthenticated=True,
                                  enable_direct_iap=False, domain_restricted_sharing=False)
    assert ei2.value.error_class == ACCESS_WIDENING_UNAPPROVED and models.calls == []


def test_developer_negative_cleared_flag_resolves_the_record(agent):
    db = _gw_db()
    db.docs[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD] = None
    agent.db = db
    resolved, _, _ = _resolve(agent)
    assert resolved.mode == "PUBLIC_APP" and resolved.source == "workload_record"


def test_r3_developer_reads_the_flag_also_with_a_request_access(agent):
    """RT R3: a direct caller passing `access` does not skip the pending-widening refusal."""
    from unittest.mock import patch

    from developer_agent.errors import ACCESS_WIDENING_UNAPPROVED, DeveloperStageError

    agent.db = _gw_db()
    models = _ExplodingModels()
    agent.genai_client = SimpleNamespace(models=models)
    with pytest.raises(DeveloperStageError) as ei:
        agent._resolve_run_access(PID, "tr-dev", [], _record("PUBLIC_APP", a8=False), None, None, None, None)
    assert ei.value.error_class == ACCESS_WIDENING_UNAPPROVED
    with patch.object(agent, "fetch_existing_repo_files", return_value={}), pytest.raises(DeveloperStageError) as ei2:
        agent.generate_code_files(product_id=PID, spec_text="a shop", task_dag=[],
                                  access=_record("PUBLIC_APP", a8=False), allow_unauthenticated=True,
                                  enable_direct_iap=False, domain_restricted_sharing=False)
    assert ei2.value.error_class == ACCESS_WIDENING_UNAPPROVED and models.calls == []


def test_r3_negative_request_access_wins_as_the_source(agent):
    db = _gw_db(flag=None)
    # re-check N5: the stored record is NARROWER (IAM) with another member, so "stricter wins" would also fail here
    db.docs[f"workloads/{PID}"]["access"] = _record("PRIVATE_IAM", ["user:z@example.com"])
    agent.db = db
    resolved, _, _ = agent._resolve_run_access(PID, "tr-dev", [], _record("PRIVATE_IAP", [A]), None, None, None, None)
    assert resolved.mode == "PRIVATE_IAP" and resolved.source == "request"  # the stored record is not used
    assert resolved.invoker_members == (A,)
    agent.db = None  # eval harness: no client -> request access resolves as before
    resolved, _, _ = agent._resolve_run_access(PID, "tr-dev", [], _record("PRIVATE_IAP", [A]), None, None, None, None)
    assert resolved.invoker_members == (A,)


# ============================================================================ 5. RT R1: no first record via re-create
def test_r1_recreate_cannot_give_an_existing_workload_its_first_record(cc, monkeypatch):
    from test_l19_11_access_intake import _create

    _, wl = cc
    initial = {f"workloads/{PID}": {"product_id": PID, "status": "FAILED"}}
    r, fake_db, payload = _create(wl, monkeypatch, {"access": _body("PUBLIC_APP", a8=False)}, initial=initial)
    assert r.status_code == 409, r.text
    assert "PATCH /api/workloads/shop-app/access" in r.json()["detail"]
    assert dict(fake_db) == initial and fake_db.writes == [] and payload is None


def test_r1_negative_new_workload_with_access_is_created(cc, monkeypatch):
    from test_l19_11_access_intake import _create

    _, wl = cc
    r, fake_db, payload = _create(wl, monkeypatch, {"access": _body("PRIVATE_IAP", [A])})
    assert r.status_code == 200, r.text
    assert fake_db[f"workloads/{PID}"]["access"]["invoker_principals"] == [A] and payload is not None


# ============================================================================ 6. RT R2: the approver sees the widening
def test_r2_flag_carries_the_exact_added_members(cc, monkeypatch):
    _, wl = cc
    initial = _wl(_record("PRIVATE_IAM", [A, B]))
    r, fake_db = _patch(wl, monkeypatch, _body("PRIVATE_IAP", [B, C, A], confirm_widening=True), initial)
    assert r.status_code == 200, r.text
    flag = fake_db[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD]
    assert flag["previous_mode"] == "PRIVATE_IAM" and flag["previous_members"] == sorted([A, B])
    assert flag["new_mode"] == "PRIVATE_IAP" and flag["added_members"] == [C]
    assert flag["changes"] == ["MODE_WIDENED", "MEMBERS_ADDED"]
    (audit,) = _audits(fake_db)
    assert audit["widening_approval"] == flag


def test_r2_chained_widenings_keep_the_earliest_baseline(cc, monkeypatch):
    _, wl = cc
    initial = _wl(_record("PRIVATE_IAP", [A]))
    r1, db1 = _patch(wl, monkeypatch, _body("PRIVATE_IAP", [A, B], confirm_widening=True), initial)  # W1
    assert r1.status_code == 200
    after_w1 = {k: v for k, v in db1.items() if k == f"workloads/{PID}"}
    r2, db2 = _patch(wl, monkeypatch, _body("PUBLIC_APP", a8=False, confirm_widening=True), after_w1)  # W2
    assert r2.status_code == 200
    flag = db2[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD]
    assert flag["previous_mode"] == "PRIVATE_IAP" and flag["previous_members"] == [A]  # W1's baseline
    assert flag["new_mode"] == "PUBLIC_APP" and flag["changes"] == ["MEMBERS_ADDED", "MODE_WIDENED"]
    assert flag["added_members"] == []  # a public record lists no members; the mode change is what is shown


def test_r2_malformed_pending_flag_gives_an_unknown_baseline(cc, monkeypatch):
    _, wl = cc
    initial = _wl(_record("PRIVATE_IAP", [A]), **{ACCESS_WIDENING_APPROVAL_FIELD: "yes"})
    r, fake_db = _patch(wl, monkeypatch, _body("PRIVATE_IAP", [A, B], confirm_widening=True), initial)
    assert r.status_code == 200, r.text
    flag = fake_db[f"workloads/{PID}"][ACCESS_WIDENING_APPROVAL_FIELD]
    assert flag["previous_mode"] is None and flag["previous_members"] == [] and flag["added_members"] == sorted([A, B])
    assert flag["changes"] == ["NO_PREVIOUS_RECORD", "MEMBERS_ADDED"]


def test_r2_gate_copies_the_flag_and_the_current_record(gw):
    db = _gw_db()
    _gate(_gw(gw, db))
    rec = db.docs[f"approval_requests/appr-plan-{TRACE}-0"]
    assert rec["access_under_review"] == {"flag": FLAG, "current_access": db.docs[f"workloads/{PID}"]["access"]}


def test_r2_negative_no_flag_copies_nothing(gw):
    db = _gw_db(flag=None)
    body = _gate(_gw(gw, db)).json()
    assert body["decision"] == "PASS" and not [p for p in db.docs if p.startswith("approval_requests/")]


def test_r2_card_view_shows_mode_before_after_and_added_members(cc):
    from routes import approvals

    flag = {**FLAG, "previous_mode": "PRIVATE_IAP", "previous_members": [A], "added_members": [B]}
    data = {"gate_reasons": ["FINOPS_THRESHOLD", "ACCESS_WIDENED"],
            "access_under_review": {"flag": flag, "current_access": _record("PRIVATE_IAP", [A, B, C])}}
    view = approvals._access_review(data)
    assert view["access_widened"] is True
    assert (view["access_mode_before"], view["access_mode_after"]) == ("PRIVATE_IAP", "PRIVATE_IAP")
    assert view["access_added_members"] == sorted([B, C])  # against the record the build will use
    first = {"gate_reasons": ["ACCESS_WIDENED"],
             "access_under_review": {"flag": {**FLAG, "previous_mode": None, "previous_members": []},
                                     "current_access": _record("PUBLIC_APP", a8=False)}}
    assert approvals._access_review(first)["access_mode_before"] == "none recorded"
    broken = approvals._access_review({"gate_reasons": ["ACCESS_WIDENED"], "access_under_review": "x"})
    assert broken["access_widened"] is True and broken["access_mode_before"] == "unknown"
    assert broken["access_added_members"] is None  # re-check N2: unknown, never "no members added"
    no_baseline = {"gate_reasons": ["ACCESS_WIDENED"],
                   "access_under_review": {"flag": {k: v for k, v in flag.items() if k != "previous_members"},
                                           "current_access": _record("PRIVATE_IAP", [A, B])}}
    assert approvals._access_review(no_baseline)["access_added_members"] is None
    assert approvals.ApprovalRequestRecord(approval_id="a", product_id=PID, trace_id="t", cost_delta_monthly="x",
                                           risk_assessment="r", requested_at="now",
                                           **broken).access_added_members is None
    # negative: any other approval shows nothing extra
    assert approvals._access_review({"gate_reasons": ["OPERATOR_REQUESTED"]}) == {
        "gate_reasons": ["OPERATOR_REQUESTED"], "access_widened": False}
    rec = approvals.ApprovalRequestRecord(approval_id="a", product_id=PID, trace_id="t", cost_delta_monthly="x",
                                          risk_assessment="r", requested_at="now", **view)
    assert rec.access_added_members == sorted([B, C]) and rec.access_widened is True


def test_r2_card_template_binds_the_widening_fields():
    html = open(os.path.join(REPO, "apps", "control-center", "templates", "dashboard.html"), encoding="utf-8").read()
    start = html.index('data-testid="approval-access-widening"')
    block = html[html.rindex("<template", 0, start):html.index("</template>", html.index("approval-access-added", start))]
    assert 'x-if="item.access_widened"' in block
    assert "item.access_mode_before" in block and "item.access_mode_after" in block
    assert 'x-for="m in (item.access_added_members || [])"' in block
    assert "item.access_added_members == null ? 'Members added: unknown'" in block  # re-check N2


# ============================================================================ 7. RT R4: no lost update
def test_r4_concurrent_patch_is_409_and_writes_nothing(cc, monkeypatch):
    _, wl = cc
    initial = _wl(_record("PRIVATE_IAP", [A, B]))
    fake_db = FakeDB(initial)
    fake_db.write_option = lambda **kw: {"last_update_time": "older-version"}  # another PATCH committed meanwhile
    client = _client(wl, monkeypatch, fake_db)
    r = client.patch(f"/api/workloads/{PID}/access", json=_body("PRIVATE_IAP", [A, B]), headers=ADMIN_H)
    assert r.status_code == 409 and "send the PATCH again" in r.json()["detail"]
    assert dict(fake_db) == initial and fake_db.writes == [] and fake_db.commits == 0


def test_r4_negative_the_commit_carries_the_read_version(cc, monkeypatch):
    _, wl = cc
    initial = _wl(_record("PRIVATE_IAP", [A, B]))
    fake_db = FakeDB(initial)
    issued = []
    real = fake_db.write_option
    fake_db.write_option = lambda **kw: issued.append(kw) or real(**kw)
    client = _client(wl, monkeypatch, fake_db)
    r = client.patch(f"/api/workloads/{PID}/access", json=_body("PRIVATE_IAP", [A]), headers=ADMIN_H)
    assert r.status_code == 200 and issued == [{"last_update_time": 0}] and fake_db.commits == 1
