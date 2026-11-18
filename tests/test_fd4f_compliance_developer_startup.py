"""FD-4F red-team F4 (compliance fails closed), F5 (typed developer gate errors), D12 (startup), F10 (/health)."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from fd4f_support import gw  # noqa: F401


def _compliance(gw, monkeypatch, behaviour):
    import compliance_agent.handler as ch

    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://127.0.0.1:9")
    monkeypatch.setattr(ch.ComplianceAgentHandler, "audit_and_enrich", behaviour)
    return TestClient(gw.app).post("/agent/compliance/audit", json={
        "product_id": "hipaa-claims", "trace_id": "t1", "spec_text": "HIPAA PHI; internal users only",
        "task_dag": [{"id": "x"}]})


def test_f4_compliance_outage_is_503_not_public_passed(gw, monkeypatch):
    def boom(self, req):
        raise ConnectionError("compliance MCP unreachable")

    r = _compliance(gw, monkeypatch, boom)
    assert r.status_code == 503
    body = r.json()
    assert body["error_class"] == "GATE_UNAVAILABLE" and body["reason"] == "COMPLIANCE_UNAVAILABLE"
    assert "allow_unauthenticated" not in body and body["passed"] is False


def test_f4_negative_compliance_success_path_unchanged(gw, monkeypatch):
    res = SimpleNamespace(
        status="PASSED", product_id="hipaa-claims", compliance_profile="HIPAA", is_regulated=True, requires_cmek=True,
        requires_audit_logging=True, domain_restricted_sharing=True, allowed_domains=["example.com"],
        allow_unauthenticated=False, enable_direct_iap=False, enforce_private_ingress=True, enriched_dag=[{"id": "x"}],
        injected_tasks=["cmek"], compliance_summary="ok", plan_markdown=None, plan_file_path=None, policy_matrix=None,
        has_policy_conflicts=False, policy_conflicts=[], requires_human_approval=True,
    )
    r = _compliance(gw, monkeypatch, lambda self, req: res)
    assert r.status_code == 200
    body = r.json()
    assert body["compliance_profile"] == "HIPAA" and body["allow_unauthenticated"] is False
    assert body["requires_human_approval"] is True


def test_f5_developer_gate_error_keeps_error_class(gw, monkeypatch):
    from gate_errors import GateUnavailableError

    def raise_gate(req):
        raise GateUnavailableError("pre-commit verifier crashed: ValueError", reason="VERIFIER_ERROR")

    monkeypatch.setattr(gw, "_execute_developer_logic", raise_gate)
    r = TestClient(gw.app).post("/agent/developer/execute", json={"trace_id": "t1", "product_id": "app"})
    assert r.status_code == 503 and r.json()["error_class"] == "GATE_UNAVAILABLE"


def test_f5_negative_untyped_developer_error_still_500(gw, monkeypatch):
    monkeypatch.setattr(gw, "_execute_developer_logic", lambda req: (_ for _ in ()).throw(RuntimeError("x")))
    r = TestClient(gw.app).post("/agent/developer/execute", json={"trace_id": "t1", "product_id": "app"})
    assert r.status_code == 500


def test_f5_async_developer_callback_carries_error_class(gw, monkeypatch):
    from gate_errors import GateFailedError

    delivered = {}
    import shared.callbacks as cb

    monkeypatch.setattr(cb.CallbackDeliveryClient, "send_callback",
                        staticmethod(lambda callback_url, payload, timeout=15, **kw: delivered.update(payload) or True))
    monkeypatch.setattr(gw, "_execute_developer_logic",
                        lambda req: (_ for _ in ()).throw(GateFailedError("verifier failed", diagnostics=[{"code": "X"}])))
    req = gw.DeveloperExecuteRequest(trace_id="t1", product_id="app", callback_url="http://127.0.0.1:9/cb")
    gw.run_developer_execute_in_background(req)
    assert delivered["status"] == "FAILED" and delivered["error_class"] == "CODE_DEFECT"
    assert delivered["diagnostics"] == [{"code": "X"}]


def test_d12_startup_refuses_test_mode_on_cloud_run(gw, monkeypatch):
    monkeypatch.setenv("K_SERVICE", "orchestrator-gateway-service")
    monkeypatch.setenv("TEST_MODE", "false")  # strict presence check: "false" also refuses
    with pytest.raises(RuntimeError, match="TEST_MODE"):
        gw.assert_pipeline_gates_ready()


def test_d12_startup_passes_without_qa_config(gw, monkeypatch):
    monkeypatch.setenv("K_SERVICE", "orchestrator-gateway-service")
    monkeypatch.delenv("TEST_MODE", raising=False)
    gw.assert_pipeline_gates_ready()  # QA config absence is a per-request GATE_UNAVAILABLE, not a boot refusal


def test_d12_startup_refuses_missing_gate(gw, monkeypatch):
    monkeypatch.setenv("K_SERVICE", "orchestrator-gateway-service")
    monkeypatch.delenv("TEST_MODE", raising=False)
    monkeypatch.setattr(gw, "evaluate_release_decision", None)
    with pytest.raises(RuntimeError, match="evaluate_release_decision"):
        gw.assert_pipeline_gates_ready()


def test_f10_health_reports_qa_configured(gw, monkeypatch):
    c = TestClient(gw.app)
    assert c.get("/health").json()["qa_configured"] is False
    for k, v in {"PROJECT_ID": "p", "REGION": "r", "QA_JOB_NAME": "j", "QA_STAGING_BUCKET": "b", "QA_SANDBOX_SA": "s"}.items():
        monkeypatch.setenv(k, v)
    assert c.get("/health").json()["qa_configured"] is True
