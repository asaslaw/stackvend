"""FD-4AI (owner 10-26, D9): vending never reports success when billing could not be linked.

With a billing account configured, a failed Cloud Billing link (updateBillingInfo raising after its retries, the
billing-quota case, or no Cloud Billing client) fails the vend with the typed class BILLING_NOT_LINKED:
- vend_gcp_project raises VendingFailure (never PROJECT_VENDED) after keeping a project it just created recoverable
  (provenance at birth, the project id on the workload record so a re-run reuses it);
- the async route delivers a FAILED callback with error_class BILLING_NOT_LINKED (the workflow's
  handle_vending_failure lifts it unchanged); the sync routes answer 502 with a typed detail;
- the Control Center Express route marks the vending stage, the pipeline and the workload FAILED with that class and
  synthesizes / deploys nothing.
Negative (Do No Harm): billing linked -> the vend and the Express route are unchanged.
Hermetic: fakes only (tests/destructive_guard_fakes.py, the EXP-7 Express harness).
"""
import hermetic_guard  # noqa: F401  (must stay the first import)

import copy
import json
import os
import sys
from unittest.mock import MagicMock

import pytest
import yaml
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))

import destructive_guard_fakes as f  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VENDING_MAIN = f.load_vending_main()
BILLING = "billingAccounts/000000-AAAAAA-BBBBBB"   # synthetic


@pytest.fixture(autouse=True)
def _settings_without_firestore(monkeypatch):
    import importlib
    live = importlib.import_module("shared.settings")
    live.invalidate_settings_cache()
    monkeypatch.setattr(live, "get_platform_settings", lambda *a, **k: live.PlatformSettings())
    yield
    live.invalidate_settings_cache()


def _crm(number=f.NUMBER, project_id="fresh-svc-123abc"):
    crm = MagicMock()
    projects = crm.projects.return_value
    projects.create.return_value.execute.return_value = {"name": "operations/cp.42"}
    projects.get.return_value.execute.return_value = {"name": f"projects/{number}", "projectId": project_id,
                                                      "state": "ACTIVE"}
    projects.getIamPolicy.return_value.execute.return_value = {"bindings": []}
    crm.operations.return_value.get.return_value.execute.return_value = {"done": True}
    return crm


def _billing(side_effect=None):
    billing = MagicMock()
    call = billing.projects.return_value.updateBillingInfo.return_value.execute
    if side_effect is not None:
        call.side_effect = side_effect
    else:
        call.return_value = {"billingEnabled": True}
    return billing


def _engine(db, crm, billing):
    eng = VENDING_MAIN.ProjectRepoVendingEngine(iam_client=f.FakeChildIAM(), platform_project_id=f.HOST, firestore_client=db, crm_service=crm,
                                                billing_service=billing, storage_client=MagicMock())
    eng.billing_account_id = BILLING
    eng.devops_sa_email = ""
    return eng


def _http_403():
    from googleapiclient.errors import HttpError
    return HttpError(MagicMock(status=403, reason="Forbidden"), b'{"error": {"status": "PERMISSION_DENIED"}}')


def _vend(eng, pid="fresh-svc"):
    return eng.vend_gcp_project(pid, "tr-1", folder_id=f.ROOT, force_new_project_id="fresh-svc-123abc")


# ------------------------------------------------------------------------------------------- engine
def test_negative_billing_linked_vend_is_unchanged(monkeypatch):
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", f.TAG)
    db, crm, billing = f.FakeDB(), _crm(), _billing()
    res = _vend(_engine(db, crm, billing))
    assert res["status"] == "PROJECT_VENDED" and res["provenance_status"] == "RECORDED"
    kwargs = billing.projects.return_value.updateBillingInfo.call_args.kwargs
    assert kwargs == {"name": "projects/fresh-svc-123abc",
                      "body": {"billingAccountName": BILLING, "billingEnabled": True}}
    wdoc = db.doc("workloads/fresh-svc")
    assert wdoc["status"] == "PROVISIONED" and "vending_error_class" not in wdoc


def test_negative_no_billing_account_configured_is_unchanged():
    db, crm, billing = f.FakeDB(), _crm(), _billing()
    eng = _engine(db, crm, billing)
    eng.billing_account_id = ""
    assert _vend(eng)["status"] == "PROJECT_VENDED"
    billing.projects.assert_not_called()


@pytest.mark.parametrize("error", [_http_403(), RuntimeError("caller lacks billing.resourceAssociations.create")])
def test_billing_link_failure_is_typed_never_vended(monkeypatch, error):
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", f.TAG)
    db, crm, billing = f.FakeDB(), _crm(), _billing(side_effect=error)
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend(_engine(db, crm, billing))
    assert exc.value.error_class == "BILLING_NOT_LINKED" and exc.value.__cause__ is error
    assert "fresh-svc-123abc" in exc.value.detail and BILLING in exc.value.detail
    # the project created in this call stays recoverable: provenance at birth + its id on the workload record
    assert db.doc("workload_provenance/fresh-svc")["project_number"] == f.NUMBER
    wdoc = db.doc("workloads/fresh-svc")
    assert wdoc["project_id"] == "fresh-svc-123abc" and wdoc["vending_error_class"] == "BILLING_NOT_LINKED"
    assert wdoc.get("status") != "PROVISIONED"
    # nothing after billing ran (no admin / DevOps IAM writes on an unbilled project)
    crm.projects.return_value.setIamPolicy.assert_not_called()


def test_billing_quota_failure_is_typed_too():
    db, crm = f.FakeDB(), _crm()
    billing = _billing(side_effect=RuntimeError("QuotaFailure: billing quota exceeded"))
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend(_engine(db, crm, billing))
    assert exc.value.error_class == "BILLING_NOT_LINKED" and "Quota" in exc.value.detail
    assert isinstance(exc.value, RuntimeError)   # callers that caught the old RuntimeError still do


def test_no_billing_client_with_an_account_configured_is_typed(monkeypatch):
    db, crm = f.FakeDB(), _crm()
    eng = _engine(db, crm, None)
    monkeypatch.setattr(type(eng), "billing", property(lambda self: None))
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend(eng)
    assert exc.value.error_class == "BILLING_NOT_LINKED"


def test_a_reused_project_records_no_new_provenance(monkeypatch):
    """A project that already existed (not created in this call) gets no provenance from the failure path."""
    from googleapiclient.errors import HttpError
    db, crm = f.FakeDB(), _crm()
    crm.projects.return_value.create.return_value.execute.side_effect = HttpError(
        MagicMock(status=409, reason="Conflict"), b"already exists")
    with pytest.raises(VENDING_MAIN.VendingFailure):
        _vend(_engine(db, crm, _billing(side_effect=_http_403())))
    assert db.doc("workload_provenance/fresh-svc") is None
    assert db.doc("workloads/fresh-svc")["project_id"] == "fresh-svc-123abc"


# ------------------------------------------------------------------------------------------- routes
def _failing_vend_all(**_kw):
    raise VENDING_MAIN.VendingFailure("BILLING_NOT_LINKED", "Billing account 'x' could not be linked.")


def _capture_callbacks(monkeypatch):
    cbmod = sys.modules[VENDING_MAIN.guaranteed_callback_scope.__module__]
    sent = []

    def _send(callback_url, payload, timeout=15, max_attempts=5):
        json.dumps(payload)
        sent.append(copy.deepcopy(payload))
        return {}

    monkeypatch.setattr(cbmod.CallbackDeliveryClient, "send_callback", staticmethod(_send))
    return sent


def _async_req(**kw):
    return VENDING_MAIN.AsyncVendingRequest(product_id="fresh-svc", trace_id="tr-async",
                                            callback_url="http://127.0.0.1:9/cb", **kw)


def test_async_route_delivers_a_typed_failed_callback(monkeypatch):
    sent = _capture_callbacks(monkeypatch)
    eng = _engine(f.FakeDB(), _crm(), _billing())
    monkeypatch.setattr(eng, "vend_all", _failing_vend_all)
    monkeypatch.setattr(VENDING_MAIN, "vending_engine", eng)
    VENDING_MAIN.run_vending_in_background(_async_req())
    assert len(sent) == 1
    payload = sent[0]
    assert payload["status"] == "FAILED" and payload["error_class"] == "BILLING_NOT_LINKED"
    assert payload["error"].startswith("BILLING_NOT_LINKED: ") and "reported_status" not in payload


def test_negative_async_route_success_is_unchanged(monkeypatch):
    sent = _capture_callbacks(monkeypatch)
    eng = _engine(f.FakeDB(), _crm(), _billing())
    monkeypatch.setattr(eng, "vend_all", lambda **kw: {"status": "WORKLOAD_VENDED", "project_id": "fresh-svc-1"})
    monkeypatch.setattr(VENDING_MAIN, "vending_engine", eng)
    VENDING_MAIN.run_vending_in_background(_async_req())
    assert sent[0]["status"] == "SUCCESS" and sent[0]["project_id"] == "fresh-svc-1"
    assert "error_class" not in sent[0]


@pytest.mark.parametrize("path", ["/vend-all", "/vend-project"])
def test_sync_routes_answer_a_typed_502(monkeypatch, path):
    eng = _engine(f.FakeDB(), _crm(), _billing())
    monkeypatch.setattr(eng, "vend_all", _failing_vend_all)
    monkeypatch.setattr(eng, "vend_gcp_project", _failing_vend_all)
    monkeypatch.setattr(VENDING_MAIN, "vending_engine", eng)
    r = TestClient(VENDING_MAIN.app).post(path, json={"product_id": "fresh-svc"})
    assert r.status_code == 502
    assert r.json()["detail"] == {"error_class": "BILLING_NOT_LINKED", "stage": "vending",
                                  "detail": "Billing account 'x' could not be linked."}


def test_workflow_lifts_the_vending_error_class_unchanged():
    """No workflow change needed: handle_vending_failure takes error_class from the callback body."""
    wf = yaml.safe_load(open(os.path.join(REPO, "workflows", "main_orchestrator.yaml")))
    steps = {}

    def _walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, dict) and k not in steps:
                    steps[k] = v
                _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(wf)
    check = steps["check_vending_status"]["switch"][0]["condition"]
    assert check == '${vending_status == "SUCCESS" or vending_status == "WORKLOAD_VENDED"}'
    assigns = {k: v for a in steps["handle_vending_failure"]["assign"] for k, v in a.items()}
    assert assigns["error_class"] == '${default(map.get(vending_output, "error_class"), "DEPENDENCY_FAILED")}'


# ------------------------------------------------------------------------------------------- Control Center Express
def _express(monkeypatch, v_status, v_json):
    from test_exp7_express_destroy_approval import _route
    wl, store, tfm = _route(monkeypatch)
    wl.make_vending_request.return_value.status_code = v_status
    wl.make_vending_request.return_value.json.return_value = v_json
    return wl, store, tfm


def test_express_typed_vending_failure_stops_the_run(monkeypatch):
    from test_exp7_express_destroy_approval import _run
    detail = {"error_class": "BILLING_NOT_LINKED", "stage": "vending", "detail": "Billing account 'x' not linked."}
    wl, store, tfm = _express(monkeypatch, 502, {"detail": detail})
    _run(wl)
    pe, wdoc = store.docs["pipeline_executions/tr-exp7"], store.docs["workloads/exp-app"]
    assert pe["status"] == "FAILED" and pe["error_class"] == "BILLING_NOT_LINKED"
    assert pe["stages"]["vending"]["status"] == "FAILED"
    assert pe["stages"]["vending"]["error_class"] == "BILLING_NOT_LINKED"
    assert all(pe["stages"][s]["status"] == "SKIPPED" for s in ("hcl_synthesis", "vcs_seed", "terraform"))
    assert wdoc["status"] == "FAILED" and wdoc["failure_reason"] == "BILLING_NOT_LINKED: Billing account 'x' not linked."
    tfm.assert_not_called()


@pytest.mark.parametrize("v_status,v_json", [
    (200, {"project_id": "castor-exp-1", "github_repo": "org/exp-repo"}),   # vended
    (500, {"detail": "some untyped vending error"}),                         # untyped: today's behaviour kept
    (502, {"detail": {"error_class": "not an identifier"}}),
])
def test_negative_express_without_a_typed_vending_failure_is_unchanged(monkeypatch, v_status, v_json):
    from test_exp7_express_destroy_approval import _run
    wl, store, tfm = _express(monkeypatch, v_status, v_json)
    _run(wl)
    vending_writes = [d["stages"]["vending"] for path, d, _m in store.writes
                      if path == "pipeline_executions/tr-exp7" and "vending" in d.get("stages", {})]
    assert vending_writes[-1]["status"] == "SUCCESS"
    assert store.docs["workloads/exp-app"]["status"] == "ACTIVE"
    assert tfm.call_args.kwargs["path"] == "/deploy"
