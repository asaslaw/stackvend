"""Step 1 code RT F4: typed developer failures leave the gateway process. The async developer runner puts
error_class + bounded diagnostics into the callback outcome (status/error unchanged), and the hallucination stack
writes the final ValidationReport + RepairEvents to pipeline_executions/{trace}.stages.developer (merge). Fake
callback client and fake Firestore; no network."""
import hermetic_guard  # noqa: F401  (first import)

import importlib.util
import os
import sys
from unittest.mock import patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from shared.diagnostics import (Diagnostic, ErrorClass, RepairBudgetExhausted, StageError,  # noqa: E402
                                ValidationReport)

sys.path.insert(0, os.path.dirname(__file__))
from test_step1_s1b_generation import W, Client, _agent, _generate, _runtime  # noqa: E402
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402


_GW = None


def _gateway_main():
    """Gateway main.py loaded once with no project, no API key and the cloud client classes stubbed out."""
    global _GW
    if _GW is None:
        spec = importlib.util.spec_from_file_location("orchestrator_gateway_main_f4", os.path.join(GATEWAY, "main.py"))
        mod = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": "",
                                     "GEMINI_API_KEY": ""}), \
                patch("google.genai.Client", side_effect=RuntimeError("no genai in tests")), \
                patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
            spec.loader.exec_module(mod)
        _GW = mod
    return _GW


def _report():
    d = Diagnostic(tool="policy", code="POLICY.PUBLIC_MEMBER", severity="error", file=W + "iam.tf",
                   block_address="google_cloud_run_v2_service_iam_member.pub", message="allUsers", source="precommit")
    return ValidationReport(status="FAIL", error_class=ErrorClass.CODE_DEFECT, source="precommit", artifact_hash="h",
                            diagnostics=[d])


def test_async_callback_carries_error_class_and_diagnostics():
    """Mutation checked: removing `outcome.update(_typed_failure_fields(...))` in run_developer_execute_in_background
    fails this test (no error_class / diagnostics in the payload)."""
    gw = _gateway_main()
    sent = []
    req = gw.DeveloperExecuteRequest(product_id="shop", trace_id="trace-f4",
                                     callback_url="https://workflowexecutions.googleapis.com/v1/x/callbacks/c")
    exc = RepairBudgetExhausted(_report(), "ITERATIONS")
    with patch.object(gw, "_execute_developer_logic", side_effect=exc), patch.object(gw, "db", None), \
            patch.object(gw.CallbackDeliveryClient, "send_callback", side_effect=lambda **kw: sent.append(kw["payload"])):
        with pytest.raises(RepairBudgetExhausted):
            gw.run_developer_execute_in_background(req)
    assert len(sent) == 1
    out = sent[0]
    # unchanged contract: status FAILED and the "<Type>: <message>" error string
    assert out["status"] == "FAILED" and out["error"] == f"RepairBudgetExhausted: {exc}"
    # new, additive fields
    assert out["error_class"] == "CODE_DEFECT" and out["exhausted_reason"] == "ITERATIONS"
    assert out["validation_status"] == "FAIL" and out["diagnostics_total"] == 1
    assert out["diagnostics"][0]["code"] == "POLICY.PUBLIC_MEMBER"


def test_async_callback_untyped_failure_is_unchanged():
    gw = _gateway_main()
    sent = []
    req = gw.DeveloperExecuteRequest(product_id="shop", trace_id="trace-f4b",
                                     callback_url="https://workflowexecutions.googleapis.com/v1/x/callbacks/c")
    with patch.object(gw, "_execute_developer_logic", side_effect=RuntimeError("boom")), patch.object(gw, "db", None), \
            patch.object(gw.CallbackDeliveryClient, "send_callback", side_effect=lambda **kw: sent.append(kw["payload"])):
        with pytest.raises(RuntimeError):
            gw.run_developer_execute_in_background(req)
    assert sent[0]["status"] == "FAILED" and sent[0]["error"] == "RuntimeError: boom"
    assert "error_class" not in sent[0] and "diagnostics" not in sent[0]


class _Missing:
    exists = False

    def to_dict(self):
        return {}


class FakeDB:
    def __init__(self):
        self.writes = []

    def collection(self, name):
        db = self

        class Col:
            def document(self, doc_id):
                class Doc:
                    def set(self, data, merge=False):
                        db.writes.append((name, doc_id, data, merge))

                    def get(self):  # lane 19 L19-2: the developer reads workloads/{pid}.access (none here)
                        return _Missing()

                    def collection(self, sub):  # ... and workloads/{pid}/compliance_audits/{trace} (none here)
                        return db.collection(f"{name}/{doc_id}/{sub}")
                return Doc()
        return Col()


def _stage_writes(writes):
    """The stack-outcome writes; the faithful RT fix 2 compute-intent write (developer_compute_intent, merge) is
    checked here and set aside."""
    ci = [w for w in writes if "developer_compute_intent" in w[2]]
    assert len(ci) == 1 and ci[0][0] == "pipeline_executions" and ci[0][3] is True
    return [w for w in writes if "developer_compute_intent" not in w[2]]


def test_stack_report_and_events_are_persisted_on_failure_and_on_pass():
    """Mutation checked: removing the _persist_stack_outcome call on the StageError path fails the first half."""
    diag = {"severity": "error", "summary": "Reference to undeclared resource",
            "range": {"filename": W + "custom.tf", "start": {"line": 3, "byte": 0}, "end": {"line": 3, "byte": 1}}}
    agent = _agent(_runtime(Client(status="FAIL", diags=[diag]),
                            settings=HallucinationStackSettings(repair_max_iterations_precommit=0)))
    agent.db = FakeDB()
    with pytest.raises(RepairBudgetExhausted):
        _generate(agent, trace="trace-f4-fail")
    (col, doc, data, merge), = _stage_writes(agent.db.writes)
    assert (col, doc, merge) == ("pipeline_executions", "trace-f4-fail", True)
    dev = data["stages"]["developer"]
    assert dev["error_class"] == "CODE_DEFECT" and dev["exhausted_reason"] == "ITERATIONS"
    assert dev["validation_report"]["status"] == "FAIL" and dev["validation_report"]["diagnostics_total"] >= 1
    assert isinstance(dev["repair_events"], list)

    agent = _agent(_runtime(Client()))
    agent.db = FakeDB()
    _generate(agent, trace="trace-f4-pass")
    (col, doc, data, merge), = _stage_writes(agent.db.writes)
    assert doc == "trace-f4-pass" and data["stages"]["developer"]["validation_report"]["status"] == "PASS"
    assert "error_class" not in data["stages"]["developer"]


def test_persist_failure_never_changes_the_outcome():
    class BrokenDB:  # every write fails; reads find nothing (an unreadable store would stop the run before the LLM:
        # ACCESS_POLICY_UNAVAILABLE, lane 19 L19-2, pinned in tests/test_lane19_tenant_authz.py)
        def collection(self, name):
            class Col:
                def document(self, doc_id):
                    class Doc:
                        def get(self):
                            return _Missing()

                        def collection(self, sub):
                            return Col()

                        def set(self, *a, **k):
                            raise RuntimeError("firestore down")
                    return Doc()
            return Col()
    agent = _agent(_runtime(Client()))
    agent.db = BrokenDB()
    files = _generate(agent, trace="trace-f4-broken")
    assert files and agent.last_validation_report.status == "PASS"
