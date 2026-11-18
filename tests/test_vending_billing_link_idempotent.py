"""VENDING-BILLING-LINK-IDEMPOTENT: a vend never re-links a project that is already billed to the target account.

Cloud Billing answers updateBillingInfo with HTTP 400 "Precondition check failed" (a quota failure) when the billing
account is at its project limit, even for a project already linked to that account, so a relaunch used to fail with
BILLING_NOT_LINKED. The vend now reads getBillingInfo first:
- linked to exactly the target account with billing enabled -> no update, the vend succeeds;
- any other state (no billing, another account, billing disabled, an unexpected answer) -> the update path as before;
- a quota failure on a genuinely new link -> still BILLING_NOT_LINKED;
- a read that fails -> the update is attempted, so "could not check" is never "linked".
Hermetic: fakes only (tests/destructive_guard_fakes.py).
"""
import hermetic_guard  # noqa: F401  (must stay the first import)

import json
import logging
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from googleapiclient.errors import HttpError

sys.path.insert(0, os.path.dirname(__file__))

import destructive_guard_fakes as f  # noqa: E402

# Imported at collection time: the root conftest snapshots each test module's sys.modules view at import (FD-05A).
VENDING_MAIN = f.load_vending_main()
V = sys.modules[VENDING_MAIN.ProjectRepoVendingEngine.__module__]
BILLING = "billingAccounts/000000-AAAAAA-BBBBBB"   # synthetic
OTHER_BILLING = "billingAccounts/111111-CCCCCC-DDDDDD"   # synthetic
PID = "relaunch-svc"
PROJECT = "relaunch-svc-123abc"
UPDATE_BODY = {"billingAccountName": BILLING, "billingEnabled": True}

LINKED_SAME = {"name": f"projects/{PROJECT}/billingInfo", "projectId": PROJECT,
               "billingAccountName": BILLING, "billingEnabled": True}
NOT_THE_TARGET_STATES = {
    "not_linked_empty_account": {"projectId": PROJECT, "billingAccountName": "", "billingEnabled": False},
    "not_linked_fields_absent": {"projectId": PROJECT},
    "linked_to_another_account": {"projectId": PROJECT, "billingAccountName": OTHER_BILLING, "billingEnabled": True},
    "same_account_billing_disabled": {"projectId": PROJECT, "billingAccountName": BILLING, "billingEnabled": False},
    "same_account_enabled_absent": {"projectId": PROJECT, "billingAccountName": BILLING},
    "same_id_without_prefix": {"projectId": PROJECT, "billingAccountName": BILLING.split("/", 1)[1],
                               "billingEnabled": True},
    "enabled_is_not_a_boolean": {"projectId": PROJECT, "billingAccountName": BILLING, "billingEnabled": "true"},
}
UNEXPECTED_ANSWERS = {"none": None, "empty": {}, "list": [LINKED_SAME]}


def _http_error(status, reason, payload):
    return HttpError(MagicMock(status=status, reason=reason), json.dumps({"error": payload}).encode())


def _quota_400():
    """The answer seen live: a 400 whose details carry a QuotaFailure."""
    return _http_error(400, "Precondition check failed.", {
        "code": 400, "message": "Precondition check failed.", "status": "FAILED_PRECONDITION",
        "details": [{"@type": "type.googleapis.com/google.rpc.QuotaFailure",
                     "violations": [{"subject": BILLING, "description": "Cloud billing quota exceeded"}]}]})


READ_FAILURES = {
    "http_403": lambda: _http_error(403, "Forbidden", {"code": 403, "message": "denied", "status": "PERMISSION_DENIED"}),
    "http_503": lambda: _http_error(503, "Unavailable", {"code": 503, "message": "down", "status": "UNAVAILABLE"}),
    "not_http": lambda: RuntimeError("connection reset"),
}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    import importlib
    live = importlib.import_module("shared.settings")
    live.invalidate_settings_cache()
    monkeypatch.setattr(live, "get_platform_settings", lambda *a, **k: live.PlatformSettings())
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", f.TAG)
    monkeypatch.delenv("STACKVEND_GUARD_FIRESTORE_DATABASE", raising=False)
    monkeypatch.delenv("STACKVEND_CHILD_PROJECT_OWNER_MEMBERS", raising=False)
    monkeypatch.setattr(V, "time", SimpleNamespace(time=lambda: 0.0, sleep=lambda s: None))
    # API enablement and the org-policy check use their own clients; not under test here.
    monkeypatch.setattr(V.ProjectRepoVendingEngine, "enable_child_apis", lambda self, pid: {"status": "ENABLED"})
    monkeypatch.setattr(V.ProjectRepoVendingEngine, "check_child_org_policies", lambda self, pid: [])
    yield
    live.invalidate_settings_cache()


def _crm():
    crm = MagicMock()
    projects = crm.projects.return_value
    projects.get.return_value.execute.return_value = {"name": f"projects/{f.NUMBER}", "projectId": PROJECT,
                                                      "state": "ACTIVE"}
    projects.getIamPolicy.return_value.execute.return_value = {"bindings": []}
    return crm


def _billing(read, update=None):
    """`read` is the getBillingInfo answer or an exception it raises; `update` an exception updateBillingInfo raises."""
    billing = MagicMock()
    projects = billing.projects.return_value
    if isinstance(read, Exception):
        projects.getBillingInfo.return_value.execute.side_effect = read
    else:
        projects.getBillingInfo.return_value.execute.return_value = read
    if update is not None:
        projects.updateBillingInfo.return_value.execute.side_effect = update
    else:
        projects.updateBillingInfo.return_value.execute.return_value = UPDATE_BODY
    return billing


def _relaunch(billing, status="ACTIVE", account=BILLING):
    """Vends a workload whose record already names its project (an `already_created` re-vend, as a Full rebuild does)."""
    db = f.FakeDB()
    db.docs[f"workloads/{PID}"] = {"status": status, "project_id": PROJECT}
    eng = VENDING_MAIN.ProjectRepoVendingEngine(iam_client=f.FakeChildIAM(), platform_project_id=f.HOST, firestore_client=db, crm_service=_crm(),
                                                billing_service=billing, storage_client=MagicMock())
    eng.billing_account_id = account
    eng.devops_sa_email = ""
    return db, eng.vend_gcp_project(PID, "tr-1", folder_id=f.ROOT)


def _relaunch_fails(billing):
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _relaunch(billing)
    return exc.value


def _read(billing):
    return billing.projects.return_value.getBillingInfo


def _update(billing):
    return billing.projects.return_value.updateBillingInfo


def _assert_update_as_before(billing):
    assert _update(billing).call_args.kwargs == {"name": f"projects/{PROJECT}", "body": UPDATE_BODY}


# ------------------------------------------------------------------------------- already linked: no update
@pytest.mark.parametrize("status", ["ACTIVE", "PROVISIONED"])
def test_already_linked_same_account_skips_the_update(status):
    billing = _billing(LINKED_SAME)
    db, res = _relaunch(billing, status=status)
    assert res["status"] == "PROJECT_VENDED"
    _read(billing).assert_called_once_with(name=f"projects/{PROJECT}")
    _update(billing).assert_not_called()
    assert "vending_error_class" not in db.doc(f"workloads/{PID}")


def test_already_linked_vend_succeeds_on_a_full_account():
    """The live defect: the update would answer the 400 quota error, and it is no longer called."""
    billing = _billing(LINKED_SAME, update=_quota_400())
    _, res = _relaunch(billing)
    assert res["status"] == "PROJECT_VENDED"
    _update(billing).assert_not_called()


def test_a_bare_configured_account_id_compares_in_its_prefixed_form():
    billing = _billing(LINKED_SAME, update=_quota_400())
    _, res = _relaunch(billing, account=BILLING.split("/", 1)[1])
    assert res["status"] == "PROJECT_VENDED"
    _update(billing).assert_not_called()


def test_the_skip_is_logged(caplog):
    with caplog.at_level(logging.INFO):
        _relaunch(_billing(LINKED_SAME))
    assert any("skipping updateBillingInfo" in r.getMessage() and PROJECT in r.getMessage() for r in caplog.records)


# ------------------------------------------------------------------------------- any other state: update as before
@pytest.mark.parametrize("state", NOT_THE_TARGET_STATES.values(), ids=NOT_THE_TARGET_STATES.keys())
def test_any_other_billing_state_updates_as_before(state):
    billing = _billing(state)
    _, res = _relaunch(billing)
    assert res["status"] == "PROJECT_VENDED"
    _read(billing).assert_called_once_with(name=f"projects/{PROJECT}")
    _assert_update_as_before(billing)


@pytest.mark.parametrize("answer", UNEXPECTED_ANSWERS.values(), ids=UNEXPECTED_ANSWERS.keys())
def test_an_unexpected_read_answer_is_not_linked(answer):
    billing = _billing(answer)
    assert _relaunch(billing)[1]["status"] == "PROJECT_VENDED"
    _assert_update_as_before(billing)


@pytest.mark.parametrize("state", NOT_THE_TARGET_STATES.values(), ids=NOT_THE_TARGET_STATES.keys())
def test_quota_400_on_a_new_link_is_still_billing_not_linked(state):
    error = _quota_400()
    billing = _billing(state, update=error)
    failure = _relaunch_fails(billing)
    assert failure.error_class == "BILLING_NOT_LINKED" and "Quota" in failure.detail and failure.__cause__ is error
    _assert_update_as_before(billing)


# ------------------------------------------------------------------------------- the read fails: fall back to update
@pytest.mark.parametrize("make_error", READ_FAILURES.values(), ids=READ_FAILURES.keys())
def test_read_failure_falls_back_to_the_update(make_error):
    billing = _billing(make_error())
    assert _relaunch(billing)[1]["status"] == "PROJECT_VENDED"
    _read(billing).assert_called_once_with(name=f"projects/{PROJECT}")
    _assert_update_as_before(billing)


@pytest.mark.parametrize("make_error", READ_FAILURES.values(), ids=READ_FAILURES.keys())
def test_read_failure_never_invents_success(make_error):
    """Today's behaviour when the read cannot answer: a full account still stops the vend."""
    error = _quota_400()
    billing = _billing(make_error(), update=error)
    failure = _relaunch_fails(billing)
    assert failure.error_class == "BILLING_NOT_LINKED" and failure.__cause__ is error
    _assert_update_as_before(billing)


def test_a_client_without_the_read_method_falls_back_to_the_update():
    billing = _billing(LINKED_SAME)
    billing.projects.return_value.getBillingInfo.side_effect = AttributeError("getBillingInfo")
    assert _relaunch(billing)[1]["status"] == "PROJECT_VENDED"
    _assert_update_as_before(billing)
