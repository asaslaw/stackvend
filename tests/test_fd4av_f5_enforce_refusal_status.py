"""FD-4AV-a F5 (owner row, 10-20): POST /enforce answers a refusal with a non-200 status.

The FinOps enforcer's FD-4O target guard returns ``{"status": "REFUSED", ...}``. /enforce now answers that with HTTP
409 and the engine's typed body byte-for-byte unchanged (no ``{"detail": ...}`` wrapper), so an HTTP caller can never
read a refusal as a 200 success. 409, not 5xx: a retry cannot change the guard's answer, and 5xx invites retries.

Kept (negative tests): every enforced status still answers 200 with the engine's body unchanged; an engine exception is
still 500; caller verification still runs first (an unverified caller never reaches the engine); the batch job's
exit codes are unchanged (it shares ``perform_enforce``, not the HTTP mapping).

Hermetic: the engine is a MagicMock or the real engine with MagicMock Google clients; no network, no ADC.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

HERE = os.path.dirname(os.path.abspath(__file__))
FINOPS_DIR = os.path.join(HERE, "..", "apps", "finops-enforcer")
_NO_ADC = {"PROJECT_ID": "", "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/fd4av-f5-adc.json"}


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(FINOPS_DIR, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


with patch.dict(os.environ, _NO_ADC):
    enf = _load("fd4av_f5_enforcer", "enforcer.py")
    with patch.dict(sys.modules, {"enforcer": enf}):
        enf_main = _load("fd4av_f5_enforcer_main", "main.py")

BODY = {"product_id": "pay-api", "target_project_id": "child-proj-1", "spend_amount": 120.0, "budget_amount": 100.0}


@pytest.fixture()
def client():
    enf_main.app.dependency_overrides[enf_main.require_platform_caller] = lambda: "sa-castor-cc@p.iam.gserviceaccount.com"
    try:
        yield TestClient(enf_main.app)
    finally:
        enf_main.app.dependency_overrides.clear()


def _engine(result=None, error=None):
    e = MagicMock(name="enforcer")
    if error is not None:
        e.quarantine_workload.side_effect = error
    else:
        e.quarantine_workload.return_value = result
    return e


def test_refusal_is_409_with_the_engine_body_unchanged(client):
    refused = {"status": "REFUSED", "product_id": "pay-api", "project_id": "child-proj-1", "action": "QUARANTINE",
               "reason": "'child-proj-1' is not a descendant of folders/123"}
    with patch.object(enf_main, "enforcer", _engine(refused)):
        r = client.post("/enforce", json=BODY)
    assert r.status_code == enf_main.REFUSED_HTTP_STATUS == 409
    assert r.json() == refused  # typed body unchanged, not wrapped in {"detail": ...}


def test_host_project_refused_by_the_real_fd4o_guard_is_409_and_touches_nothing(client):
    clients = {k: MagicMock(name=k) for k in ("run_service", "compute_service", "sql_service", "container_service",
                                              "billing_service", "crm_service")}
    real = enf.FinopsBudgetEnforcer(project_id="mock-stackvend-project", firestore_client=MagicMock(), **clients)
    with patch.object(enf_main, "enforcer", real):
        r = client.post("/enforce", json=dict(BODY, target_project_id="mock-stackvend-project"))
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "REFUSED" and body["action"] == "QUARANTINE" and body["product_id"] == "pay-api"
    assert "host platform project" in body["reason"]
    for name in ("run_service", "compute_service", "sql_service", "container_service", "billing_service"):
        assert clients[name].method_calls == [], name


def test_missing_target_is_refused_409_not_200(client):
    real = enf.FinopsBudgetEnforcer(project_id="mock-stackvend-project", firestore_client=MagicMock(),
                                    **{k: MagicMock() for k in ("run_service", "compute_service", "sql_service",
                                                                "container_service", "billing_service",
                                                                "crm_service")})
    with patch.object(enf_main, "enforcer", real):
        r = client.post("/enforce", json={"product_id": "pay-api"})
    assert r.status_code == 409 and r.json()["status"] == "REFUSED"


# ------------------------------------------------------------------------------ Do No Harm (behavior kept)
@pytest.mark.parametrize("status", sorted(enf_main.ENFORCED_STATUSES))
def test_enforced_statuses_still_answer_200_with_the_body_unchanged(client, status):
    result = {"status": status, "product_id": "pay-api", "project_id": "child-proj-1", "policy": "ALERT_ONLY"}
    e = _engine(result)
    with patch.object(enf_main, "enforcer", e):
        r = client.post("/enforce", json=BODY)
    assert r.status_code == 200 and r.json() == result
    e.quarantine_workload.assert_called_once_with(product_id="pay-api", target_project_id="child-proj-1",
                                                  trace_id=None, spend_amount=120.0, budget_amount=100.0,
                                                  policy="AUTONOMOUS_SCALE_TO_ZERO")


def test_engine_exception_is_still_500(client):
    with patch.object(enf_main, "enforcer", _engine(error=RuntimeError("compute API down"))):
        r = client.post("/enforce", json=BODY)
    assert r.status_code == 500 and r.json() == {"detail": "compute API down"}


def test_caller_verification_still_runs_before_the_engine():
    e = _engine({"status": "REFUSED", "reason": "x"})
    with patch.dict(os.environ, {"FINOPS_SERVICE_URL": "", "FINOPS_ALLOWED_CALLERS": ""}), \
            patch.object(enf_main, "enforcer", e):
        r = TestClient(enf_main.app).post("/enforce", json=BODY)
    assert r.status_code == 503
    e.quarantine_workload.assert_not_called()


_AUTH_ENV = {"FINOPS_SERVICE_URL": "https://finops.example.run.app",
             "FINOPS_ALLOWED_CALLERS": "sa-castor-cc@p.iam.gserviceaccount.com"}
_WOULD_REFUSE = {"status": "REFUSED", "product_id": "pay-api", "project_id": "child-proj-1", "action": "QUARANTINE",
                 "reason": "'child-proj-1' is not a descendant of folders/123"}


def _post_with_auth(headers, verify, engine):
    import google.oauth2.id_token as gid

    with patch.dict(os.environ, _AUTH_ENV), patch.object(gid, "verify_oauth2_token", verify), \
            patch.object(enf_main, "enforcer", engine):
        return TestClient(enf_main.app).post("/enforce", json=BODY, headers=headers)


@pytest.mark.parametrize("headers,verify_result,expected", [
    ({}, None, 401),                                                        # no token
    ({"Authorization": "Bearer bad"}, ValueError("bad signature"), 401),    # invalid token
    ({"Authorization": "Bearer t"}, {"email": "pwn@attacker.iam.gserviceaccount.com", "email_verified": True}, 403),
    ({"Authorization": "Bearer t"}, {"email": "sa-castor-cc@p.iam.gserviceaccount.com", "email_verified": False}, 403),
])
def test_unauthenticated_or_unauthorized_caller_never_sees_the_refused_body(headers, verify_result, expected):
    # Opus RT low fix: the engine WOULD refuse, but caller verification answers first; the REFUSED body (reason,
    # project id) never reaches an unverified caller and the engine is never called.
    e = _engine(_WOULD_REFUSE)
    verify = MagicMock(side_effect=verify_result) if isinstance(verify_result, Exception) \
        else MagicMock(return_value=verify_result)
    r = _post_with_auth(headers, verify, e)
    assert r.status_code == expected
    assert "REFUSED" not in r.text and "descendant" not in r.text and "child-proj-1" not in r.text
    e.quarantine_workload.assert_not_called()


def test_verified_caller_gets_the_409_refusal():
    # Control for the case above: the same request from a verified, allow-listed caller reaches the engine -> 409.
    e = _engine(_WOULD_REFUSE)
    verify = MagicMock(return_value={"email": "sa-castor-cc@p.iam.gserviceaccount.com", "email_verified": True})
    r = _post_with_auth({"Authorization": "Bearer t"}, verify, e)
    assert r.status_code == 409 and r.json() == _WOULD_REFUSE
    assert verify.call_args.kwargs.get("audience") == "https://finops.example.run.app"


def test_direct_call_returns_the_engine_dict_for_a_success():
    # The FD-4AV-a shared-call test calls the route function directly; a success is still the plain dict.
    with patch.object(enf_main, "enforcer", _engine({"status": "ALERTED_ONLY"})):
        assert enf_main.enforce_quarantine(enf_main.QuarantineRequest(product_id="pay-api",
                                                                      target_project_id="child-proj-1")) \
            == {"status": "ALERTED_ONLY"}


def test_batch_job_exit_code_for_a_refusal_is_unchanged():
    db = MagicMock(name="firestore")
    e = _engine({"status": "REFUSED", "reason": "host"})
    e.db = db
    env = {"PROJECT_ID": "mock-stackvend-project", "FINOPS_ENFORCE_PRODUCT_ID": "pay-api",
           "FINOPS_ENFORCE_TARGET_PROJECT_ID": "child-proj-1", "CLOUD_RUN_EXECUTION": "f5-exec-1"}
    code, summary = enf_main.run_batch(env, e)
    assert code == enf_main.EXIT_ERROR == 1 and summary["outcome"] == "REFUSED"


# ------------------------------------------------------------------------------ FD-4AV-a F5-c: unknown policy -> 422
@pytest.mark.parametrize("policy", ["ALERT-ONLY", "alert_only!", "SCALE", "none", "SCALE_TO_ZERO", " ALERT_ONLY"])
def test_unknown_policy_is_422_and_never_reaches_the_engine(client, policy):
    e = _engine({"status": "QUARANTINED"})
    with patch.object(enf_main, "enforcer", e):
        r = client.post("/enforce", json=dict(BODY, policy=policy))
    assert r.status_code == 422
    assert "unknown policy" in r.text
    e.quarantine_workload.assert_not_called()


@pytest.mark.parametrize("policy,sent", [
    ("ALERT_ONLY", "ALERT_ONLY"), ("alert_only", "alert_only"), ("Nuclear_Unlink_Billing", "Nuclear_Unlink_Billing"),
    ("HITL_CONFIRMATION_REQUIRED", "HITL_CONFIRMATION_REQUIRED"),
    ("AUTONOMOUS_SCALE_TO_ZERO", "AUTONOMOUS_SCALE_TO_ZERO"),
    ("", "AUTONOMOUS_SCALE_TO_ZERO"), (None, "AUTONOMOUS_SCALE_TO_ZERO"),
])
def test_known_policy_spellings_the_engine_accepts_are_unchanged(client, policy, sent):
    # Do No Harm: every value the engine accepts today (it upper()s) still passes through unchanged; None / "" keep
    # the default policy.
    e = _engine({"status": "ALERTED_ONLY"})
    with patch.object(enf_main, "enforcer", e):
        r = client.post("/enforce", json=dict(BODY, policy=policy))
    assert r.status_code == 200
    assert e.quarantine_workload.call_args.kwargs["policy"] == sent


def test_omitted_policy_is_the_default():
    req = enf_main.QuarantineRequest(product_id="pay-api", target_project_id="child-proj-1")
    assert req.policy == "AUTONOMOUS_SCALE_TO_ZERO"


def test_unauthenticated_unknown_policy_is_still_auth_first():
    # Caller verification (a dependency) answers before body validation would matter: no 422 detail leaks either.
    e = _engine({"status": "QUARANTINED"})
    with patch.dict(os.environ, {"FINOPS_SERVICE_URL": "", "FINOPS_ALLOWED_CALLERS": ""}), \
            patch.object(enf_main, "enforcer", e):
        r = TestClient(enf_main.app).post("/enforce", json=dict(BODY, policy="SCALE"))
    assert r.status_code == 503, r.text
    e.quarantine_workload.assert_not_called()


@pytest.mark.parametrize("policy", ["ALERT-ONLY", "SCALE"])
def test_batch_job_unknown_policy_is_still_exit_2_with_the_same_summary(policy):
    db = MagicMock(name="firestore")
    e = _engine({"status": "QUARANTINED"})
    e.db = db
    env = {"PROJECT_ID": "mock-stackvend-project", "FINOPS_ENFORCE_PRODUCT_ID": "pay-api",
           "FINOPS_ENFORCE_TARGET_PROJECT_ID": "child-proj-1", "CLOUD_RUN_EXECUTION": "f5c-exec-1",
           "FINOPS_ENFORCE_POLICY": policy}
    code, summary = enf_main.run_batch(env, e)
    assert code == enf_main.EXIT_USAGE == 2
    assert summary == {"job": enf_main.JOB_NAME, "outcome": "INVALID_REQUEST",
                       "error": f"unknown FINOPS_ENFORCE_POLICY {policy!r}"}
    e.quarantine_workload.assert_not_called()


def _restore_engine(result=None, error=None):
    e = MagicMock(name="enforcer")
    if error is not None:
        e.restore_workload.side_effect = error
    else:
        e.restore_workload.return_value = result
    return e


def test_restore_refusal_is_409_with_the_engine_body_unchanged(client):
    # FD-4AV-a F5-b (owner 10-24): /restore answers REFUSED like /enforce.
    refused = {"status": "REFUSED", "product_id": "pay-api", "project_id": None, "action": "RESTORE", "reason": "x"}
    with patch.object(enf_main, "enforcer", _restore_engine(refused)):
        r = client.post("/restore", json={"product_id": "pay-api"})
    assert r.status_code == 409 and r.json() == refused


def test_restore_host_project_refused_by_the_real_fd4o_guard_is_409_and_touches_nothing(client):
    clients = {k: MagicMock(name=k) for k in ("run_service", "compute_service", "sql_service", "container_service",
                                              "billing_service", "crm_service")}
    real = enf.FinopsBudgetEnforcer(project_id="mock-stackvend-project", firestore_client=MagicMock(), **clients)
    with patch.object(enf_main, "enforcer", real):
        r = client.post("/restore", json={"product_id": "pay-api", "target_project_id": "mock-stackvend-project"})
    assert r.status_code == 409
    assert r.json()["status"] == "REFUSED" and r.json()["action"] == "RESTORE"
    for name in ("run_service", "compute_service", "sql_service", "container_service", "billing_service"):
        assert clients[name].method_calls == [], name


@pytest.mark.parametrize("status", ["RESTORED", "BILLING_RESTORED"])
def test_restore_success_still_200_with_the_body_unchanged(client, status):
    result = {"status": status, "product_id": "pay-api", "restored_services": []}
    e = _restore_engine(result)
    with patch.object(enf_main, "enforcer", e):
        r = client.post("/restore", json={"product_id": "pay-api", "target_project_id": "child-proj-1"})
    assert r.status_code == 200 and r.json() == result
    e.restore_workload.assert_called_once_with(product_id="pay-api", target_project_id="child-proj-1",
                                               max_instances=None, root_billing_account=None)  # C10 RT D3: no 5 guess


def test_restore_engine_exception_is_still_500(client):
    with patch.object(enf_main, "enforcer", _restore_engine(error=RuntimeError("run API down"))):
        r = client.post("/restore", json={"product_id": "pay-api"})
    assert r.status_code == 500 and r.json() == {"detail": "run API down"}


def test_restore_unverified_caller_never_reaches_the_engine():
    e = _restore_engine({"status": "REFUSED", "reason": "x"})
    with patch.dict(os.environ, {"FINOPS_SERVICE_URL": "", "FINOPS_ALLOWED_CALLERS": ""}), \
            patch.object(enf_main, "enforcer", e):
        r = TestClient(enf_main.app).post("/restore", json={"product_id": "pay-api"})
    assert r.status_code == 503 and "REFUSED" not in r.text
    e.restore_workload.assert_not_called()
