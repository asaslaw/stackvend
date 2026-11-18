"""
Unit Tests for Implementation Plan 9: Dynamic Cloud Run Container Sizing & Out-Of-Memory (OOM) Guardrails.
Verifies dependency-aware static analysis, multi-service aggregation, spec intent fallback,
modular Terraform parameterization, and CI/CD workflow flag generation.
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

from shared.resource_sizing import (
    calculate_container_sizing,
    resolve_workload_sizing,
    extract_package_names,
)
from developer_agent.terraform_engine import (
    generate_golden_main_tf,
    generate_golden_variables_tf,
)
from developer_agent.handler import (
    DeveloperAgent,
    generate_service_workflow,
)


class TestResourceSizing(unittest.TestCase):
    def test_extract_package_names(self):
        reqs = """
        # Core API dependencies
        fastapi>=0.110.0
        uvicorn[standard] == 0.28.0
        pydantic~=2.6.0; python_version >= "3.10"
        pandas >= 2.0.0 # Data processing
        openpyxl<=3.1.2
        """
        pkgs = extract_package_names(reqs)
        self.assertIn("fastapi", pkgs)
        self.assertIn("uvicorn", pkgs)
        self.assertIn("pydantic", pkgs)
        self.assertIn("pandas", pkgs)
        self.assertIn("openpyxl", pkgs)
        self.assertNotIn("core", pkgs)

    def test_tier1_standard_sizing(self):
        reqs = """
        fastapi==0.110.0
        uvicorn==0.28.0
        pydantic==2.6.0
        httpx==0.27.0
        """
        profile = calculate_container_sizing(requirements_text=reqs)
        self.assertEqual(profile.tier, 1)
        self.assertEqual(profile.memory_limit, "512Mi")
        self.assertEqual(profile.cpu_limit, "1000m")
        self.assertEqual(profile.gcloud_cpu, "1")
        self.assertEqual(profile.initial_delay_secs, 2)
        self.assertEqual(profile.failure_threshold, 20)

    def test_tier2_data_media_sizing(self):
        reqs = """
        fastapi==0.110.0
        pandas>=2.0.0
        openpyxl>=3.1.0
        pillow>=10.0.0
        """
        profile = calculate_container_sizing(requirements_text=reqs)
        self.assertEqual(profile.tier, 2)
        self.assertEqual(profile.memory_limit, "1Gi")
        self.assertEqual(profile.cpu_limit, "1000m")
        self.assertEqual(profile.gcloud_cpu, "1")
        self.assertEqual(profile.initial_delay_secs, 4)
        self.assertEqual(profile.failure_threshold, 25)
        self.assertIn("pandas", profile.matched_packages)
        self.assertIn("openpyxl", profile.matched_packages)
        self.assertIn("pillow", profile.matched_packages)

    def test_tier3_heavy_compute_sizing(self):
        reqs = """
        fastapi==0.110.0
        torch>=2.2.0
        transformers>=4.38.0
        playwright>=1.42.0
        """
        profile = calculate_container_sizing(requirements_text=reqs)
        self.assertEqual(profile.tier, 3)
        self.assertEqual(profile.memory_limit, "2Gi")
        self.assertEqual(profile.cpu_limit, "2000m")
        self.assertEqual(profile.gcloud_cpu, "2")
        self.assertEqual(profile.initial_delay_secs, 6)
        self.assertEqual(profile.failure_threshold, 30)
        self.assertIn("torch", profile.matched_packages)
        self.assertIn("transformers", profile.matched_packages)
        self.assertIn("playwright", profile.matched_packages)

    def test_spec_intent_keyword_fallback(self):
        spec_tier2 = "I need an automated system to parse CSV spreadsheets using pandas and generate excel reports."
        profile2 = calculate_container_sizing(requirements_text="", spec_text=spec_tier2)
        self.assertEqual(profile2.tier, 2)
        self.assertEqual(profile2.memory_limit, "1Gi")
        self.assertTrue(any("pandas" in kw or "spreadsheet" in kw for kw in profile2.matched_intents))

        spec_tier3 = "Deploy a machine learning inference microservice with deep learning models."
        profile3 = calculate_container_sizing(requirements_text="", spec_text=spec_tier3)
        self.assertEqual(profile3.tier, 3)
        self.assertEqual(profile3.memory_limit, "2Gi")
        self.assertTrue(any("machine learning" in kw or "deep learning" in kw for kw in profile3.matched_intents))

    def test_multi_service_aggregation(self):
        files = {
            "apps/web/requirements.txt": "fastapi\nuvicorn\npydantic",
            "apps/worker/requirements.txt": "openpyxl\npandas",
        }
        profile = resolve_workload_sizing(files=files)
        self.assertEqual(profile.tier, 2)
        self.assertEqual(profile.memory_limit, "1Gi")

        # Adding heavy ML to one service bumps entire workload
        files["apps/ml/requirements.txt"] = "torch\ntransformers"
        profile_heavy = resolve_workload_sizing(files=files)
        self.assertEqual(profile_heavy.tier, 3)
        self.assertEqual(profile_heavy.memory_limit, "2Gi")
        self.assertEqual(profile_heavy.cpu_limit, "2000m")

    def test_terraform_golden_main_and_variables(self):
        main_hcl = generate_golden_main_tf(
            product_id="data-pipeline",
            archetype="cloudrun",
            spec_text="Data processing service",
        )
        self.assertIn("cpu_limit             = var.cpu_limit", main_hcl)
        self.assertIn("memory_limit          = var.memory_limit", main_hcl)

        vars_hcl = generate_golden_variables_tf(
            product_id="data-pipeline",
            default_repo="org/data-pipeline",
        )
        self.assertIn('variable "cpu_limit"', vars_hcl)
        self.assertIn('default     = "1000m"', vars_hcl)
        self.assertIn('variable "memory_limit"', vars_hcl)
        self.assertIn('default     = "512Mi"', vars_hcl)

    def test_workflow_generation_resource_flags(self):
        wf_hcl = generate_service_workflow(
            service_name="data-svc",
            product_id="data-svc",
            archetype="cloudrun",
            memory_limit="1Gi",
            cpu_limit="1",
        )
        self.assertIn("MEMORY_LIMIT: 1Gi", wf_hcl)
        self.assertIn("CPU_LIMIT: 1", wf_hcl)
        self.assertIn('--memory "${MEMORY_LIMIT}"', wf_hcl)
        self.assertIn('--cpu "${CPU_LIMIT}"', wf_hcl)

    def test_developer_agent_tfvars_injection_tier2(self):
        # Lane 19 L19-3b (owner row 27a): the old mock answered markdown, which never parsed, so this test silently
        # ran on the deleted template fallback. The fake model now answers the same two files as the JSON envelope a
        # real model returns, so the tier-2 sizing is derived from the LLM's pandas requirement.
        sys.path.insert(0, os.path.dirname(__file__))
        from _lane19_fake_genai import FakeGenaiClient
        agent = DeveloperAgent(project_id="test-proj")
        agent.genai_client = FakeGenaiClient(files={
            "apps/data-svc/main.py": "from fastapi import FastAPI\nimport pandas as pd\napp = FastAPI()\n",
            "apps/data-svc/requirements.txt": "fastapi>=0.110.0\npandas>=2.0.0\nopenpyxl>=3.1.0\n",
        })

        with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}), \
                patch.object(agent, "fetch_existing_repo_files", return_value={}):
            files = agent.generate_code_files(
                product_id="data-svc",
                spec_text="Build a pandas data parser",
                task_dag=[{"step_id": "STEP-06-COMPUTE", "title": "Deploy Cloud Run", "depends_on": []}], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False
            )

        self.assertIn("infra/workload/terraform.tfvars", files)
        tfvars = files["infra/workload/terraform.tfvars"]
        self.assertIn('memory_limit               = "1Gi"', tfvars)
        self.assertIn('cpu_limit                  = "1000m"', tfvars)

        # Check deploy workflow has 1Gi
        wf = files[".github/workflows/deploy-data-svc.yml"]
        self.assertIn("MEMORY_LIMIT: 1Gi", wf)
        self.assertIn('--memory "${MEMORY_LIMIT}"', wf)


if __name__ == "__main__":
    unittest.main()
