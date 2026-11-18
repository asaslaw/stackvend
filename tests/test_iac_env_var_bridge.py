"""
Unit Tests for Project Castor: 3-Layer Deterministic Bridge for IaC & Application Parity.
Tests custom resource env var extraction, cyclic dependency protection, multi-service propagation,
additional APIs inference, and Gatekeeper auto-curing idempotency.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock

# Setup mock modules if needed in environment
for m in [
    'pydantic', 'httpx', 'fastapi', 'fastapi.responses', 'google', 'google.genai',
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
    extract_custom_resource_env_vars,
    infer_additional_apis_from_custom_tf,
    format_hcl_env_vars,
    generate_golden_main_tf,
    reconcile_multi_service_declarations,
)
from gatekeeper_agent.verifier import SynthesisVerifierAgent


class TestIaCEnvironmentVariableBridge(unittest.TestCase):

    def setUp(self):
        self.sample_custom_tf = """
resource "google_storage_bucket" "audit_archive" {
  name          = "testplan01-a-testplan01-a-audit-archive"
  location      = var.region
  force_destroy = false
  lifecycle_rule {
    condition {
      age = 7
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_pubsub_topic" "inbound_events" {
  name = "testplan01-a-inbound-events"
}

resource "google_pubsub_subscription" "event_push" {
  name  = "testplan01-a-event-push-sub"
  topic = google_pubsub_topic.inbound_events.name
  push_config {
    push_endpoint = "${module.compute.service_uri}/api/v1/tasks/process"
  }
}

resource "google_secret_manager_secret" "api_key" {
  secret_id = "external-api-key"
  replication {
    auto {}
  }
}
"""
        self.sample_py_files = {
            "apps/testplan/main.py": """
import os
from fastapi import FastAPI
app = FastAPI()
BUCKET = os.getenv("GCS_BUCKET_NAME")
TOPIC = os.getenv("PUBSUB_TOPIC_ID")
FALLBACK = os.getenv("RAW_EVENTS_BUCKET")
""",
        }

    def test_extract_custom_resource_env_vars_and_cycle_prevention(self):
        env = extract_custom_resource_env_vars(self.sample_custom_tf, self.sample_py_files)
        # Verify safe upstream bindings
        self.assertEqual(env["GCS_BUCKET_NAME"], "google_storage_bucket.audit_archive.name")
        self.assertEqual(env["RAW_EVENTS_BUCKET"], "google_storage_bucket.audit_archive.name")
        self.assertEqual(env["PUBSUB_TOPIC_ID"], "google_pubsub_topic.inbound_events.name")
        self.assertEqual(env["SECRET_API_KEY"], "google_secret_manager_secret.api_key.secret_id")
        self.assertEqual(env["PROJECT_ID"], "var.project_id")

        # RED TEAM CHECK: Verify downstream push subscription was NOT extracted (cycle prevention)
        self.assertNotIn("PUBSUB_SUBSCRIPTION", env)
        self.assertNotIn("EVENT_PUSH", env)

    def test_infer_additional_apis_from_custom_tf(self):
        # S2-C (HS-63): exact type table; storage and pubsub are already in the foundation's base_apis, so only the
        # APIs the foundation does not enable are listed (tests/test_step2c_api_requirements.py has the rule tests).
        apis = infer_additional_apis_from_custom_tf(self.sample_custom_tf)
        self.assertIn("secretmanager.googleapis.com", apis)
        self.assertNotIn("storage.googleapis.com", apis)
        self.assertNotIn("pubsub.googleapis.com", apis)

    def test_generate_golden_main_tf_with_custom_resources(self):
        main_tf = generate_golden_main_tf(
            product_id="testplan01-a",
            archetype="cloudrun",
            custom_tf_content=self.sample_custom_tf,
            app_files=self.sample_py_files,
        )
        self.assertIn("merge(var.env_vars, {", main_tf)
        self.assertIn('"GCS_BUCKET_NAME" = google_storage_bucket.audit_archive.name', main_tf)
        self.assertIn('"PUBSUB_TOPIC_ID" = google_pubsub_topic.inbound_events.name', main_tf)

    def test_generate_golden_main_tf_without_custom_resources(self):
        main_tf = generate_golden_main_tf(
            product_id="plain-app",
            archetype="cloudrun",
            custom_tf_content="",
            app_files={},
        )
        # Should remain clean and standard
        self.assertIn("env_vars              = var.env_vars", main_tf)
        self.assertNotIn("merge(var.env_vars", main_tf)

    def test_reconcile_multi_service_declarations_injects_env_vars(self):
        files = {
            "infra/workload/custom.tf": self.sample_custom_tf,
            "apps/worker/main.py": "import os\nb = os.getenv('GCS_BUCKET_NAME')\n",
            "apps/api/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        }
        reconcile_multi_service_declarations(
            files=files,
            product_id="multi-test",
            spec_text="Two cloud run services: api and worker",
            archetype="cloudrun",
        )
        c_tf = files["infra/workload/custom.tf"]
        self.assertIn('module "compute_worker"', c_tf)
        self.assertIn("merge(var.env_vars, {", c_tf)
        self.assertIn('"GCS_BUCKET_NAME" = google_storage_bucket.audit_archive.name', c_tf)

    def test_gatekeeper_reconcile_iac_contracts_idempotent(self):
        verifier = SynthesisVerifierAgent(product_id="testplan01-a")
        initial_main_tf = generate_golden_main_tf(
            product_id="testplan01-a",
            archetype="cloudrun",
            # Generate un-wired main.tf to test gatekeeper cure
            custom_tf_content=None,
        )
        self.assertIn("env_vars              = var.env_vars", initial_main_tf)

        files = {
            "infra/workload/main.tf": initial_main_tf,
            "infra/workload/custom.tf": self.sample_custom_tf,
            "apps/testplan/main.py": self.sample_py_files["apps/testplan/main.py"],
        }

        # First pass: Gatekeeper cures missing bindings
        cured_1 = verifier.reconcile_iac_environment_contracts(files)
        main_1 = cured_1["infra/workload/main.tf"]
        self.assertIn("merge(var.env_vars, {", main_1)
        self.assertIn('"GCS_BUCKET_NAME" = google_storage_bucket.audit_archive.name', main_1)

        # Second pass: Gatekeeper is idempotent and does not corrupt or duplicate
        cured_2 = verifier.reconcile_iac_environment_contracts(cured_1)
        main_2 = cured_2["infra/workload/main.tf"]
        self.assertEqual(main_1, main_2)
        # Ensure only 1 occurrence of merge(var.env_vars, {
        self.assertEqual(main_2.count("merge(var.env_vars, {"), 1)

    def test_extract_compute_module_env_vars_and_inter_service_wiring(self):
        custom_tf = """
module "compute_core_processor" {
  source       = "../modules/compute-cloudrun"
  service_name = "core-processor"
}
module "compute_service_b" {
  source       = "../modules/compute-cloudrun"
  service_name = "service-b"
}
"""
        app_files = {
            "apps/api-gateway/main.py": """
import os
url = os.getenv("CORE_PROCESSOR_URL", "http://localhost:8081").rstrip("/")
aud = os.getenv("CORE_PROCESSOR_AUDIENCE", url)
core_svc = os.getenv("CORE_SERVICE_URL")
b_url = os.environ.get("SERVICE_B_URL")
""",
            "apps/core-processor/main.py": """
import os
my_url = os.getenv("CORE_PROCESSOR_URL")
aud = os.getenv("OIDC_AUDIENCE")
""",
        }

        # 1. Caller is api-gateway (or default primary service)
        env_gw = extract_custom_resource_env_vars(custom_tf, app_files, caller_service="api-gateway")
        self.assertEqual(env_gw["CORE_PROCESSOR_URL"], "module.compute_core_processor.service_uri")
        self.assertEqual(env_gw["CORE_PROCESSOR_AUDIENCE"], "module.compute_core_processor.service_uri")
        # S2-D (HS-65): CORE_SERVICE_URL names no sibling (TOKEN CORE_PROCESSOR), so the deleted generic-alias rule no
        # longer binds it; it is reported, not bound (code RT ruling Q1). Read exactly + names a sibling -> bound.
        self.assertNotIn("CORE_SERVICE_URL", env_gw)
        self.assertEqual(env_gw["SERVICE_B_URL"], "module.compute_service_b.service_uri")

        # 2. RED TEAM CHECK: Caller is core-processor -> must NOT contain CORE_PROCESSOR_URL (cycle prevention)
        env_core = extract_custom_resource_env_vars(custom_tf, app_files, caller_service="core-processor")
        self.assertNotIn("CORE_PROCESSOR_URL", env_core)
        self.assertNotIn("CORE_PROCESSOR_AUDIENCE", env_core)

    def test_gatekeeper_cures_missing_compute_module_bindings(self):
        verifier = SynthesisVerifierAgent(product_id="testplan02-b")
        custom_tf = """
module "compute_core_processor" {
  source       = "../modules/compute-cloudrun"
  service_name = "core-processor"
}
"""
        initial_main_tf = """
module "compute" {
  source       = "../modules/compute-cloudrun"
  service_name = "api-gateway"
  env_vars = merge(var.env_vars, {
    "PROJECT_ID" = var.project_id
  })
}
"""
        files = {
            "infra/workload/main.tf": initial_main_tf,
            "infra/workload/custom.tf": custom_tf,
            "apps/api-gateway/main.py": """
import os
url = os.getenv("CORE_PROCESSOR_URL", "http://localhost:8081")
aud = os.getenv("CORE_PROCESSOR_AUDIENCE", url)
""",
        }

        cured = verifier.reconcile_iac_environment_contracts(files)
        main_cured = cured["infra/workload/main.tf"]
        self.assertIn('"CORE_PROCESSOR_URL" = module.compute_core_processor.service_uri', main_cured)
        self.assertIn('"CORE_PROCESSOR_AUDIENCE" = module.compute_core_processor.service_uri', main_cured)


if __name__ == "__main__":
    unittest.main()
