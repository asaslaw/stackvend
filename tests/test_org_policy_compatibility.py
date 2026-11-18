"""
Unit Tests for Implementation Plan 7: Enterprise GCP Organization Policy Compatibility & Authenticated Ingress Guardrails.
Verifies detection of constraints/iam.allowedPolicyMemberDomains and constraints/run.allowedIngress,
parameterization of compute-cloudrun modules, and emission of policy-compliant CI/CD workflows and Terraform HCL.
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
    vendor_terraform_modules,
)
from developer_agent.handler import (
    DeveloperAgent,
    generate_service_workflow,
)
# FD-55 W1 (FD55-W1): the gateway's sanitize_github_workflow (no production caller) is deleted with its case; the
# rendered workflow's --no-allow-unauthenticated is covered by the generate_service_workflow cases below.


class TestOrgPolicyCompatibility(unittest.TestCase):
    def test_golden_main_tf_with_domain_restrictions(self):
        """Verifies compute module call parameterization in infra/workload/main.tf."""
        hcl = generate_golden_main_tf(
            product_id="billing-svc",
            archetype="cloudrun",
            spec_text="Enterprise billing service",
            allow_unauthenticated=False,
            authorized_invoker_members=["domain:mycompany.com"],
        )
        self.assertIn('source                = "../modules/compute-cloudrun"', hcl)
        self.assertIn("allow_unauthenticated = var.allow_unauthenticated", hcl)
        self.assertIn("authorized_invoker_members = var.authorized_invoker_members", hcl)

    def test_golden_variables_tf_with_domain_restrictions(self):
        """Verifies variables declaration in infra/workload/variables.tf."""
        vars_hcl = generate_golden_variables_tf(
            product_id="billing-svc",
            default_repo="myorg/billing-svc",
            allow_unauthenticated=False,
            authorized_invoker_members=["domain:mycompany.com"],
        )
        self.assertIn('variable "allow_unauthenticated"', vars_hcl)
        self.assertIn("default     = false", vars_hcl)
        self.assertIn('variable "authorized_invoker_members"', vars_hcl)
        self.assertIn('default     = ["domain:mycompany.com"]', vars_hcl)

    def test_workflow_generation_unauthenticated_false(self):
        """Verifies GitHub Actions workflow contains --no-allow-unauthenticated."""
        wf = generate_service_workflow(
            service_name="billing-svc",
            product_id="billing-svc",
            project_id="castor-billing-svc",
            archetype="cloudrun",
            allow_unauthenticated=False,
        )
        self.assertIn("--no-allow-unauthenticated", wf)
        self.assertNotIn("--allow-unauthenticated \\", wf)

    def test_workflow_generation_unauthenticated_true(self):
        """Verifies GitHub Actions workflow contains --allow-unauthenticated in standard orgs."""
        wf = generate_service_workflow(
            service_name="billing-svc",
            product_id="billing-svc",
            project_id="castor-billing-svc",
            archetype="cloudrun",
            allow_unauthenticated=True,
        )
        self.assertIn("--allow-unauthenticated", wf)
        self.assertNotIn("--no-allow-unauthenticated", wf)

    def test_developer_agent_generate_code_files_domain_restricted(self):
        """Verifies DeveloperAgent outputs compliant Terraform and workflows under domain restriction."""
        # Lane 19 L19-3b (owner register row 27a): the template scaffold is deleted; a fake model supplies the app
        # through the single-turn LLM seam and the compliant golden IaC / workflow assertions are unchanged.
        from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
        agent = DeveloperAgent()
        agent.genai_client = FakeGenaiClient(files=canned_workload_files("fintech-portal"))

        with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}), \
                patch.object(agent, "fetch_existing_repo_files", return_value={}):
            files = agent.generate_code_files(
                product_id="fintech-portal",
                spec_text="Enterprise payment portal with domain-restricted sharing",
                task_dag=[{"step_id": "STEP-06-COMPUTE", "title": "Deploy Cloud Run", "depends_on": []}],
                domain_restricted_sharing=True,
                allowed_domains=["fintech.corp"], allow_unauthenticated=False, enable_direct_iap=False,
                # Lane 19 L19-2 (FD-4I I9): invokers come only from the access record; allowed_domains (org-policy
                # values) is never turned into `domain:` members.
                access={"mode": "PRIVATE_IAM", "invoker_principals": ["domain:fintech.corp"],
                        "sign_in": {"google": "DISABLED"}, "source": "intake"},
            )

        # 1. Main HCL passes variables to module
        main_tf = files.get("infra/workload/main.tf", "")
        self.assertIn("allow_unauthenticated = var.allow_unauthenticated", main_tf)
        self.assertIn("authorized_invoker_members = var.authorized_invoker_members", main_tf)

        # 2. Variables define false and authorized members
        vars_tf = files.get("infra/workload/variables.tf", "")
        self.assertIn('variable "allow_unauthenticated"', vars_tf)
        self.assertIn("default     = false", vars_tf)
        self.assertIn('default     = ["domain:fintech.corp"]', vars_tf)

        # 3. terraform.tfvars is emitted with policy values
        tfvars = files.get("infra/workload/terraform.tfvars", "")
        self.assertIn("allow_unauthenticated      = false", tfvars)
        self.assertIn('authorized_invoker_members = ["domain:fintech.corp"]', tfvars)

        # 4. Canonical compute-cloudrun module has domain_access resource
        mod_main = files.get("infra/modules/compute-cloudrun/main.tf", "")
        self.assertIn('resource "google_cloud_run_v2_service_iam_member" "domain_access"', mod_main)
        self.assertIn('for_each = var.allow_unauthenticated ? toset([]) : toset(var.authorized_invoker_members)', mod_main)

        # 5. Workflow has --no-allow-unauthenticated
        wf_content = files.get(".github/workflows/deploy-fintech-portal.yml", "")
        self.assertIn("--no-allow-unauthenticated", wf_content)
        self.assertNotIn("--allow-unauthenticated \\", wf_content)

    def test_canonical_module_disk_files(self):
        """Verifies infra/modules/compute-cloudrun files on disk contain domain_access IAM and variables."""
        mod_main_path = os.path.join(REPO_ROOT, "infra", "modules", "compute-cloudrun", "main.tf")
        mod_vars_path = os.path.join(REPO_ROOT, "infra", "modules", "compute-cloudrun", "variables.tf")

        with open(mod_main_path, "r", encoding="utf-8") as f:
            mod_main = f.read()
        with open(mod_vars_path, "r", encoding="utf-8") as f:
            mod_vars = f.read()

        self.assertIn('resource "google_cloud_run_v2_service_iam_member" "domain_access"', mod_main)
        self.assertIn('variable "authorized_invoker_members"', mod_vars)


if __name__ == "__main__":
    unittest.main()
