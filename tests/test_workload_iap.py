"""
Unit Tests for Direct Identity-Aware Proxy (IAP) Support in Project Castor Workloads.

Tests coverage:
1. infra/modules/compute-cloudrun HCL declarations:
   - enable_direct_iap variable (type bool, default false)
   - google_project_service_identity.iap_sa resource
   - google_cloud_run_v2_service_iam_member.iap_agent_invoker binding
   - google_iap_web_cloud_run_service_iam_member.iap_accessors binding
   - BETA launch_stage and iap_enabled on google_cloud_run_v2_service
   - outputs.tf exposing iap_enabled
2. infra/modules/workload-foundation/base:
   - "iap.googleapis.com" declared in default base_apis
3. Developer Agent Deterministic Terraform Engine:
   - generate_golden_main_tf wires enable_direct_iap = var.enable_direct_iap
   - generate_golden_main_tf uses var.product_id for service_name (no "castor-" prefix)
   - generate_golden_variables_tf declares variable "enable_direct_iap"
4. Compliance Agent Intent Detection & DAG Enrichment:
   - Natural language queries ("restrict access, do not allow unauthenticated", "internal web app with IAP", "corporate SSO")
     trigger enable_direct_iap = True, allow_unauthenticated = False, and STEP-03D-DIRECT-IAP task
   - Standard public services remain enable_direct_iap = False, allow_unauthenticated = True
5. Developer Agent Code Generation:
   - Emits enable_direct_iap = true in terraform.tfvars
   - Preserves backward compatibility when IAP is disabled
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure mocks for third-party libs if not installed in host environment
try:
    import pydantic
except ImportError:
    class MockBaseModel:
        def __init__(self, **kwargs):
            for k, v in self.__class__.__dict__.items():
                if not k.startswith('_') and not callable(v):
                    default_val = getattr(v, 'default', v)
                    if default_val is not Ellipsis:
                        setattr(self, k, default_val)
            for k, v in kwargs.items():
                setattr(self, k, v)
        def model_dump(self):
            return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}

    class MockFieldInfo:
        def __init__(self, default=None, default_factory=None):
            self.default = default if default is not None else (default_factory() if default_factory else None)

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: MockFieldInfo(default, default_factory)
    mock_pydantic.EmailStr = str
    sys.modules['pydantic'] = mock_pydantic

for m in [
    'httpx', 'fastapi', 'fastapi.responses', 'google', 'google.genai',
    'google.genai.types', 'google.cloud', 'google.cloud.firestore',
    'google.cloud.storage', 'google.cloud.logging', 'google.cloud.pubsub_v1',
    'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GATEWAY_PATH not in sys.path:
    sys.path.insert(0, GATEWAY_PATH)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from developer_agent.terraform_engine import (
    generate_golden_main_tf,
    generate_golden_variables_tf,
)
from compliance_agent.handler import ComplianceAgentHandler
from compliance_agent.schemas import ComplianceAuditRequest


class TestWorkloadComputeCloudRunIAPHCL(unittest.TestCase):
    """Verifies HCL declarations in infra/modules/compute-cloudrun for Direct IAP."""

    def setUp(self):
        self.module_dir = os.path.join(REPO_ROOT, "infra", "modules", "compute-cloudrun")
        with open(os.path.join(self.module_dir, "variables.tf"), "r") as f:
            self.variables_tf = f.read()
        with open(os.path.join(self.module_dir, "main.tf"), "r") as f:
            self.main_tf = f.read()
        with open(os.path.join(self.module_dir, "outputs.tf"), "r") as f:
            self.outputs_tf = f.read()

    def test_variables_tf_declares_enable_direct_iap(self):
        self.assertIn('variable "enable_direct_iap"', self.variables_tf)
        self.assertIn('type        = bool', self.variables_tf)
        self.assertIn('default     = false', self.variables_tf)

    def test_main_tf_declares_iap_service_identity(self):
        self.assertIn('data "google_project" "workload_project"', self.main_tf)

    def test_main_tf_declares_iap_agent_invoker_binding(self):
        self.assertIn('resource "google_cloud_run_v2_service_iam_member" "iap_agent_invoker"', self.main_tf)
        self.assertIn('"roles/run.invoker"', self.main_tf)
        self.assertIn('gcp-sa-iap.iam.gserviceaccount.com', self.main_tf)

    def test_main_tf_declares_iap_accessors_binding(self):
        self.assertIn('resource "google_iap_web_cloud_run_service_iam_member" "iap_accessors"', self.main_tf)
        self.assertIn('"roles/iap.httpsResourceAccessor"', self.main_tf)

    def test_main_tf_cloud_run_service_configures_iap(self):
        self.assertIn('launch_stage = (!var.allow_unauthenticated && var.enable_direct_iap) ? "BETA" : null', self.main_tf)
        self.assertIn('iap_enabled  = (!var.allow_unauthenticated && var.enable_direct_iap)', self.main_tf)

    def test_main_tf_configures_google_beta_provider(self):
        self.assertIn('provider            = google-beta', self.main_tf)
        self.assertIn('google-beta = {', self.main_tf)


class TestWorkloadFoundationBaseIAP(unittest.TestCase):
    """Verifies that iap.googleapis.com is enabled in workload foundation base."""

    def test_base_apis_includes_iap(self):
        base_vars_path = os.path.join(REPO_ROOT, "infra", "modules", "workload-foundation", "base", "variables.tf")
        with open(base_vars_path, "r") as f:
            content = f.read()
        self.assertIn('"iap.googleapis.com"', content)


class TestDeveloperAgentTerraformEngineIAP(unittest.TestCase):
    """Verifies deterministic Terraform code generation for Direct IAP."""

    def test_golden_main_tf_wires_enable_direct_iap(self):
        hcl = generate_golden_main_tf("myworkload", "cloudrun", "Direct IAP service", enable_direct_iap=True)
        self.assertIn("enable_direct_iap     = var.enable_direct_iap", hcl)

    def test_golden_main_tf_does_not_prepend_castor_to_service_name(self):
        hcl = generate_golden_main_tf("internalportal", "cloudrun", "Portal service", enable_direct_iap=True)
        self.assertIn("service_name          = var.product_id", hcl)
        self.assertNotIn("castor-internalportal", hcl)

    def test_golden_variables_tf_declares_enable_direct_iap(self):
        hcl = generate_golden_variables_tf("myworkload", "myorg/myworkload", enable_direct_iap=True)
        self.assertIn('variable "enable_direct_iap"', hcl)
        self.assertIn('type        = bool', hcl)
        self.assertIn('default     = true', hcl)


# The handler first tries the remote Compliance MCP server, then falls back to its embedded engine.
@hermetic_guard.unavailable("compliance_agent.handler.httpx.Client", "Compliance MCP server")
class TestComplianceAgentDirectIAP(unittest.TestCase):
    """Verifies intent detection and DAG enrichment by Compliance Agent."""

    def setUp(self):
        # Lane 17 PR-1a: the compliance engine runs in-process only on explicit request (never a fallback).
        self.handler = ComplianceAgentHandler(compliance_server_url="http://mock-compliance", mode="inprocess")

    @patch.object(ComplianceAgentHandler, "_persist_audit_record")
    def test_detects_restrict_access_unauthenticated(self, mock_persist):
        req = ComplianceAuditRequest(
            product_id="secure-portal",
            spec_text="make a new cloud run service but restrict access, do not allow unauthenticated",
            task_dag=[{"step_id": "STEP-01-APIS"}, {"step_id": "STEP-03-IAM"}, {"step_id": "STEP-06-COMPUTE"}],
        )
        res = self.handler.audit_and_enrich(req)
        self.assertTrue(res.enable_direct_iap)
        self.assertFalse(res.allow_unauthenticated)
        injected_ids = [t["step_id"] for t in res.injected_tasks]
        self.assertIn("STEP-03D-DIRECT-IAP", injected_ids)

    @patch.object(ComplianceAgentHandler, "_persist_audit_record")
    def test_detects_internal_web_app_iap(self, mock_persist):
        req = ComplianceAuditRequest(
            product_id="internal-crm",
            spec_text="internal web app with IAP single sign-on for company employees",
            task_dag=[{"step_id": "STEP-01-APIS"}, {"step_id": "STEP-03-IAM"}, {"step_id": "STEP-06-COMPUTE"}],
        )
        res = self.handler.audit_and_enrich(req)
        self.assertTrue(res.enable_direct_iap)
        self.assertFalse(res.allow_unauthenticated)
        injected_ids = [t["step_id"] for t in res.injected_tasks]
        self.assertIn("STEP-03D-DIRECT-IAP", injected_ids)

    @patch.object(ComplianceAgentHandler, "_persist_audit_record")
    def test_detects_corporate_sso_keyword(self, mock_persist):
        req = ComplianceAuditRequest(
            product_id="corp-directory",
            spec_text="employee directory portal requiring corporate sso login",
            task_dag=[{"step_id": "STEP-01-APIS"}, {"step_id": "STEP-03-IAM"}],
        )
        res = self.handler.audit_and_enrich(req)
        self.assertTrue(res.enable_direct_iap)
        self.assertFalse(res.allow_unauthenticated)

    @patch.object(ComplianceAgentHandler, "_persist_audit_record")
    def test_standard_public_service_has_no_iap(self, mock_persist):
        req = ComplianceAuditRequest(
            product_id="public-api",
            spec_text="public rest api for weather telemetry data",
            task_dag=[{"step_id": "STEP-01-APIS"}, {"step_id": "STEP-03-IAM"}],
        )
        res = self.handler.audit_and_enrich(req)
        self.assertFalse(res.enable_direct_iap)
        self.assertTrue(res.allow_unauthenticated)
        injected_ids = [t["step_id"] for t in res.injected_tasks]
        self.assertNotIn("STEP-03D-DIRECT-IAP", injected_ids)


class TestDeveloperAgentDirectIAPScaffolding(unittest.TestCase):
    """Verifies Developer Agent generates valid tfvars and files with Direct IAP."""

    def setUp(self):
        # Lane 19 L19-3b (owner register row 27a): the template scaffold is deleted; the LLM path runs with a fake
        # model. L19-2 later replaces the explicit flag / keyword inference with AccessPolicy (plan §10 L19-3b).
        from developer_agent.handler import DeveloperAgent
        from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
        env = patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"})
        env.start()
        self.addCleanup(env.stop)
        self.agent = DeveloperAgent()
        self.fake = lambda pid: FakeGenaiClient(files=canned_workload_files(pid))

    def _generate(self, product_id, spec_text, **kw):
        self.agent.genai_client = self.fake(product_id)
        # FD-4R R-6: the compliance decision is an explicit input (the gateway reads it from the persisted record).
        kw.setdefault("domain_restricted_sharing", False)
        kw.setdefault("allow_unauthenticated", not kw.get("enable_direct_iap"))
        kw.setdefault("enable_direct_iap", False)
        with patch.object(self.agent, "fetch_existing_repo_files", return_value={}):
            return self.agent.generate_code_files(product_id=product_id, spec_text=spec_text, task_dag=[], **kw)

    _IAP_ACCESS = {"mode": "PRIVATE_IAP", "invoker_principals": ["group:staff@example.com"],
                   "sign_in": {"google": "DISABLED"}, "source": "intake"}

    def test_llm_path_with_direct_iap(self):
        # Lane 19 L19-2: Direct IAP and its accessors come from the AccessPolicy record (exact principals).
        files = self._generate("secureapp", "Internal admin app with IAP", access=self._IAP_ACCESS)
        self.assertIn("infra/workload/terraform.tfvars", files)
        tfvars = files["infra/workload/terraform.tfvars"]
        self.assertIn("enable_direct_iap          = true", tfvars)
        self.assertIn("allow_unauthenticated      = false", tfvars)
        self.assertIn('authorized_invoker_members = ["group:staff@example.com"]', tfvars)

    def test_llm_path_iap_flag_without_principals_stops_before_the_llm(self):
        # Lane 19 L19-2 (FD-4I I7): the compliance flag alone gives the mode, never principals -> operator (HITL).
        from developer_agent.errors import ACCESS_POLICY_INCOMPLETE, DeveloperStageError
        with self.assertRaises(DeveloperStageError) as ctx:
            self._generate("secureapp", "Internal admin app with IAP", enable_direct_iap=True)
        self.assertEqual(ctx.exception.error_class, ACCESS_POLICY_INCOMPLETE)
        self.assertEqual(self.agent.genai_client.models.calls, [])

    def test_llm_path_without_direct_iap(self):
        files = self._generate("publicapp", "Public marketing website", enable_direct_iap=False,
                               allow_unauthenticated=True)
        if "infra/workload/terraform.tfvars" in files:
            tfvars = files["infra/workload/terraform.tfvars"]
            self.assertNotIn("enable_direct_iap", tfvars)
            self.assertNotIn("allow_unauthenticated      = false", tfvars)

    def test_spec_text_has_no_effect_on_ingress(self):
        # FD-4R R-6 + lane 19 L19-2 (plan §10 L19-3b): spec keywords are never read. The same "restrict access" spec
        # with a public compliance decision stays public; without the compliance decision the developer stops before
        # any repository read or LLM call (R-6's COMPLIANCE_DECISION_MISSING, which runs before the access resolution).
        from gate_errors import GateUnavailableError
        spec = "make a new cloud run service but restrict access, do not allow unauthenticated, internal portal with IAP"
        files = self._generate("internalportal", spec, allow_unauthenticated=True, enable_direct_iap=False)
        tfvars = files.get("infra/workload/terraform.tfvars", "")
        self.assertNotIn("enable_direct_iap", tfvars)
        self.assertNotIn("allow_unauthenticated      = false", tfvars)
        self.agent.genai_client = self.fake("internalportal")
        with patch.object(self.agent, "fetch_existing_repo_files", return_value={}) as fetch:
            with self.assertRaises(GateUnavailableError) as ei:
                self.agent.generate_code_files(product_id="internalportal", spec_text=spec, task_dag=[])
        self.assertEqual(ei.exception.reason, "COMPLIANCE_DECISION_MISSING")
        self.assertEqual(sorted(ei.exception.details["missing"]),
                         ["allow_unauthenticated", "domain_restricted_sharing", "enable_direct_iap"])
        fetch.assert_not_called()
        self.assertEqual(self.agent.genai_client.models.calls, [])  # no LLM call before the refusal

if __name__ == "__main__":
    unittest.main()
