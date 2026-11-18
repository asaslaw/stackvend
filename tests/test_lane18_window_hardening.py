"""
Lane 18 single window: red-team hardening H1-H5, H7 (docs/planning/wave2-lane18-window-red-team-fable.md). Hermetic.

H1  keyword-detected / docs-poller sandboxes are never TTL-deleted until an ADMIN confirms them: the dashboard gets a
    "Confirm sandbox" button, and the card, list badge, banner and T-7/T-2 notices say "deleted only after you
    confirm" until then; a display-only countdown says so.
H2  an approval vending refused (answered, never consumed) is set to VOID instead of staying live for 15 minutes.
H3  `ttl_authority` is persisted on the workload doc (extend / promote / confirm) and exposed to the dashboard.
H4  the CC waits DECOMMISSION_TIMEOUT_SECONDS for vending's decommission; on no answer it re-reads the ledger and says
    when vending already finished.
H5  (vending) lives in tests/test_lane18_window_vending_fixes.py.
H7  vend_all keys vend_gcp_project and its ledger write by the normalized product id.
H6  (apps/control-center/sandbox_guard.py, no longer called) is kept on purpose: owner rule, never delete.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from test_lane18_window_cc import (  # noqa: F401  (fixtures + fakes)
    BASE_DIR, PID, FakeVending, _decommission, _json, _sandbox, appr_routes, da, human, refusal, seed, world, wl,
    ConfirmSandboxRequest, ExtendSandboxRequest, _budget_approval, _decide,
)

DASHBOARD = os.path.join(BASE_DIR, "apps", "control-center", "templates", "dashboard.html")


class TimedVending(FakeVending):
    """FakeVending that also records the timeout the CC passed."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.timeouts = []

    def __call__(self, method, path, json_body=None, timeout=60.0, request=None):
        self.timeouts.append(timeout)
        return super().__call__(method, path, json_body=json_body, timeout=timeout, request=request)


# ---------------------------------------------------------------------------------------------- H2 void
@pytest.mark.parametrize("vending", [refusal("LIEN_PRESENT", 409), refusal("NOT_STACKVEND_OWNED", 403),
                                     FakeVending(500, {"detail": "boom"})])
def test_refused_decommission_voids_the_unconsumed_approval(world, vending):
    seed(world.db)
    res = _decommission(vending)
    assert res.status_code == 502
    [(aid, appr)] = world.db.approvals().items()
    assert appr["status"] == "VOID" and appr["void_reason"] == _json(res)["code"] and appr["voided_at"]
    assert world.db.ledger_writes() == []


def test_no_answer_from_vending_does_not_void_the_approval(world):
    """Vending may still be working with the approval when the CC stops waiting: never touch it then."""
    seed(world.db)

    def timeout(**kw):
        raise TimeoutError("read timeout")

    with patch.object(wl, "make_vending_request", timeout):
        res = wl.decommission_workload_endpoint(PID, da_req(), human())
    assert _json(res)["code"] == "VENDING_UNREACHABLE"
    [(aid, appr)] = world.db.approvals().items()
    assert appr["status"] == "APPROVED"


@pytest.mark.parametrize("status", ["CONSUMED", "EXECUTION_FAILED", "EXECUTED"])
def test_void_never_overwrites_a_status_vending_wrote(world, status):
    world.db.docs["destructive_approvals/a1"] = {"status": status, "consumed_at": "2026-10-12T12:00:00+00:00"}
    outcome = da.VendingOutcome(False, 502, "DECOMMISSION_FAILED", "x")
    assert da.void_approval("a1", outcome) is False
    assert world.db.docs["destructive_approvals/a1"]["status"] == status


def test_void_is_best_effort_when_the_guard_db_fails(world, monkeypatch):
    monkeypatch.setattr(da, "get_guard_db", lambda: (_ for _ in ()).throw(RuntimeError("down")))
    assert da.void_approval("a1", da.VendingOutcome(False, 409, "LIEN_PRESENT", "x")) is False


def test_successful_decommission_leaves_the_approval_to_vending(world):
    seed(world.db)
    _decommission(FakeVending(200, {"status": "DECOMMISSIONED"}))
    [(aid, appr)] = world.db.approvals().items()
    assert appr["status"] == "APPROVED"  # vending's own CONSUMED/EXECUTED writes are not faked here; CC never voids


def test_refused_confirm_voids_the_approval(world):
    _sandbox(world.db, sandbox_designation_source="KEYWORD_DETECTED")
    with patch.object(wl, "make_vending_request", refusal("SANDBOX_NOT_ELIGIBLE", 409)):
        res = wl.confirm_sandbox_endpoint(PID, human(), ConfirmSandboxRequest(ttl_days=14))
    assert res.status_code == 502
    [(aid, appr)] = world.db.approvals().items()
    assert (appr["action"], appr["status"], appr["void_reason"]) == ("CONFIRM_SANDBOX", "VOID", "SANDBOX_NOT_ELIGIBLE")


def test_refused_budget_breach_decommission_voids_the_approval(world):
    seed(world.db, status="QUARANTINED")
    appr_id = _budget_approval(world.db)
    with pytest.raises(Exception):
        _decide(appr_id, human(), refusal("LIEN_PRESENT", 409))
    [(aid, appr)] = world.db.approvals().items()
    assert appr["status"] == "VOID"


# ---------------------------------------------------------------------------------------------- H4 timeout
def test_decommission_waits_long_enough_for_vending(world):
    seed(world.db)
    vending = TimedVending(200, {"status": "DECOMMISSIONED"})
    _decommission(vending)
    assert vending.timeouts == [da.DECOMMISSION_TIMEOUT_SECONDS] and da.DECOMMISSION_TIMEOUT_SECONDS >= 120


def test_budget_breach_and_sweeper_use_the_same_timeout():
    import inspect
    assert "timeout=destructive_actions.DECOMMISSION_TIMEOUT_SECONDS" in inspect.getsource(
        appr_routes._decommission_via_vending)
    assert "timeout=destructive_actions.DECOMMISSION_TIMEOUT_SECONDS" in inspect.getsource(
        wl.sweep_expired_sandboxes_endpoint)


def test_timeout_after_vending_finished_says_so(world):
    seed(world.db)

    def slow_success(**kw):
        world.db.docs[f"workloads/{PID}"]["status"] = "DECOMMISSIONED"  # vending wrote the ledger, then the CC gave up
        raise TimeoutError("read timeout")

    with patch.object(wl, "make_vending_request", slow_success):
        res = wl.decommission_workload_endpoint(PID, da_req(), human())
    body = _json(res)
    assert res.status_code == 502 and body["code"] == "VENDING_UNREACHABLE"
    assert "the ledger now shows DECOMMISSIONED" in body["detail"]


def test_timeout_with_the_project_still_active_has_no_hint(world):
    seed(world.db)

    def timeout(**kw):
        raise TimeoutError("read timeout")

    with patch.object(wl, "make_vending_request", timeout):
        res = wl.decommission_workload_endpoint(PID, da_req(), human())
    assert "ledger now shows" not in _json(res)["detail"]


# ---------------------------------------------------------------------------------------------- H3 ttl_authority
@pytest.mark.parametrize("code", ["LEDGER_UNPROVENANCED", "SANDBOX_NOT_ELIGIBLE"])
def test_display_only_extend_is_persisted_on_the_workload(world, code):
    _sandbox(world.db)
    with patch.object(wl, "make_vending_request", refusal(code, 409)):
        wl.extend_sandbox_endpoint(PID, human(), ExtendSandboxRequest(extend_days=10))
    assert world.db.docs[f"workloads/{PID}"]["ttl_authority"] == "LEDGER_DISPLAY_ONLY"


def test_vending_extend_marks_vending_as_the_authority(world):
    _sandbox(world.db, ttl_authority="LEDGER_DISPLAY_ONLY")
    vending = FakeVending(200, {"status": "OK", "sandbox_expires_at": "2026-12-01T00:00:00+00:00"})
    with patch.object(wl, "make_vending_request", vending):
        wl.extend_sandbox_endpoint(PID, human(), ExtendSandboxRequest(extend_days=10))
    assert world.db.docs[f"workloads/{PID}"]["ttl_authority"] == "VENDING_PROVENANCE"


def test_promote_and_confirm_record_the_authority(world):
    _sandbox(world.db, sandbox_designation_source="KEYWORD_DETECTED")
    with patch.object(wl, "make_vending_request", FakeVending(200, {"status": "OK", "sandbox_expires_at": "x"})):
        wl.confirm_sandbox_endpoint(PID, human(), ConfirmSandboxRequest(ttl_days=7))
    assert world.db.docs[f"workloads/{PID}"]["ttl_authority"] == "VENDING_PROVENANCE"
    with patch.object(wl, "make_vending_request", refusal("LEDGER_UNPROVENANCED", 403)):
        wl.promote_sandbox_endpoint(PID, human())
    assert world.db.docs[f"workloads/{PID}"]["ttl_authority"] == "LEDGER_DISPLAY_ONLY"


# ---------------------------------------------------------------------------------------------- H1 honesty
@pytest.mark.parametrize("fields,awaiting", [
    ({"is_sandbox": True, "sandbox_designation_source": "KEYWORD_DETECTED"}, True),
    ({"is_sandbox": True, "sandbox_designation_source": None}, True),   # docs poller / pre-lane-4 record
    ({"is_sandbox": True}, True),
    ({"is_sandbox": True, "sandbox_designation_source": "API_FIELD"}, False),
    ({"is_sandbox": True, "sandbox_designation_source": "OPERATOR_CHECKBOX"}, False),
    ({"is_sandbox": True, "sandbox_designation_source": "OPERATOR_CONFIRMED"}, False),
    ({"is_sandbox": False, "sandbox_designation_source": "KEYWORD_DETECTED"}, False),
    ({}, False),
])
def test_awaiting_confirmation_is_exact_set_membership(fields, awaiting):
    assert da.sandbox_awaiting_confirmation(fields) is awaiting
    assert da.sandbox_display_fields(fields)["sandbox_awaiting_confirmation"] is awaiting


def _notices(world, **fields):
    exp = (datetime.now(timezone.utc) + timedelta(days=fields.pop("days"))).isoformat()
    _sandbox(world.db, sandbox_expires_at=exp, warn_t7_sent=False, warn_t2_sent=False, **fields)
    with patch.object(wl, "make_vending_request", FakeVending(200, {})) as vending:
        res = wl.sweep_expired_sandboxes_endpoint(human())
    assert vending.calls == []  # nothing expired: notices only
    return res.notifications_sent


@pytest.mark.parametrize("days,tag", [(5, "[T-7 Notice]"), (1, "[T-2 Notice]")])
def test_notices_for_an_unconfirmed_sandbox_say_it_is_deleted_only_after_confirm(world, days, tag):
    [msg] = _notices(world, days=days, sandbox_designation_source="KEYWORD_DETECTED")
    assert msg.startswith(tag) and "deleted only after you confirm" in msg and "will auto-decommission" not in msg
    audit = [d for p, d in world.db.docs.items() if p.startswith(f"workloads/{PID}/audit_logs/")][0]
    assert audit["awaiting_confirmation"] is True and audit["message"] == msg


def test_notices_for_a_display_only_sandbox_say_it_is_never_auto_deleted(world):
    [msg] = _notices(world, days=1, sandbox_designation_source="API_FIELD", ttl_authority="LEDGER_DISPLAY_ONLY")
    assert msg.startswith("[T-2 Notice]") and "never auto-deleted" in msg


@pytest.mark.parametrize("days,tag,text", [
    (5, "[T-7 Notice]", "auto-decommissioned at expiry"),
    (1, "[T-2 URGENT]", "will auto-decommission in"),
])
def test_notices_for_an_explicit_sandbox_keep_the_auto_delete_warning(world, days, tag, text):
    [msg] = _notices(world, days=days, sandbox_designation_source="OPERATOR_CHECKBOX")
    assert msg.startswith(tag) and text in msg and "confirm" not in msg


def test_details_and_list_expose_the_honesty_fields():
    import schemas
    for cls in (schemas.WorkloadSummary, schemas.WorkloadDetailsResponse):
        assert {"sandbox_designation_source", "sandbox_awaiting_confirmation", "ttl_authority"} <= \
            set(cls.model_fields)
    import inspect
    src = inspect.getsource(wl)
    assert src.count("**destructive_actions.sandbox_display_fields(") == 3


def test_dashboard_has_the_confirm_button_and_the_honest_texts():
    html = open(DASHBOARD, encoding="utf-8").read()
    assert '@click="confirmSandboxWorkload(selectedWorkloadId)"' in html
    assert 'x-show="workloadDetails?.sandbox_awaiting_confirmation"' in html
    assert "async confirmSandboxWorkload(productId)" in html and "/sandbox/confirm`" in html
    assert "ttl_days: ttlDays" in html and "Math.min(30, Math.max(1," in html  # vending/CC accept 1-30
    assert 'data-testid="sandbox-awaiting-confirmation-note"' in html and "deleted only after you confirm" in html
    assert 'data-testid="sandbox-display-only-note"' in html
    assert "Awaiting confirmation (not auto-deleted)" in html and "Display only (never auto-deleted)" in html
    # the imminent-expiry banner ("scheduled for autonomous decommission") lists only sandboxes that will be deleted
    assert "!w.sandbox_awaiting_confirmation && w.ttl_authority !== 'LEDGER_DISPLAY_ONLY'" in html


# ---------------------------------------------------------------------------------------------- H6 kept
def test_interim_sandbox_guard_module_is_kept():
    """Owner rule: never delete a component. The lane 4 interim guard stays in the tree (no longer called)."""
    assert os.path.isfile(os.path.join(BASE_DIR, "apps", "control-center", "sandbox_guard.py"))


def da_req():
    from schemas import DecommissionRequest
    return DecommissionRequest(confirm_product_id=PID)
