"""
Unit tests for Multi-Service Archetype Reconciliation, Phantom Service Prevention,
and IDP/IAP 403 Safety Guardrails in Developer Agent and Compliance Agent.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GATEWAY_PATH not in sys.path:
    sys.path.insert(0, GATEWAY_PATH)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

for m in [
    'httpx', 'fastapi', 'google', 'google.genai', 'google.genai.types',
    'google.cloud', 'google.cloud.firestore', 'google.cloud.storage',
    'google.cloud.secretmanager', 'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

from developer_agent.compute_intent import resolve_compute_intent
from developer_agent.terraform_engine import (
    extract_hcl_blocks,
    generate_golden_main_tf,
    reconcile_multi_service_declarations,
)
from developer_agent.handler import (
    DeveloperAgent,
    detect_workload_services,
    generate_service_workflow,
)
from compliance_agent.handler import ComplianceAgentHandler
from compliance_agent.schemas import ComplianceAuditRequest


class TestMultiServiceReconciliation(unittest.TestCase):
    """Verifies that multi-service prompts deploy exactly N services, preventing phantom services."""

    def test_reconcile_phantom_service_deduplication(self):
        """
        When LLM generates 2 services in custom.tf, but main.tf already defines module.compute,
        reconciliation must drop the duplicate service from custom.tf so total is 2, not 3.
        """
        product_id = "testingcr123"
        spec_text = "Please create two cloud run services. PLease make both of the cloud run services protected with IDP. Jsut two services."

        custom_tf_with_two_services = """
resource "google_cloud_run_v2_service" "service_one" {
  name     = "testingcr123-service-one"
  location = var.region
}

resource "google_cloud_run_v2_service" "service_two" {
  name     = "testingcr123-service-two"
  location = var.region
}
"""
        files = {
            "infra/workload/main.tf": 'module "compute" { source = "../modules/compute-cloudrun" service_name = var.product_id }',
            "infra/workload/custom.tf": custom_tf_with_two_services,
            "apps/service-one/main.py": "print('one')",
            "apps/service-two/main.py": "print('two')",
        }

        reconcile_multi_service_declarations(
            files=files,
            product_id=product_id,
            spec_text=spec_text,
            archetype="cloudrun",
            allow_unauthenticated=False,
            enable_direct_iap=True,
            authorized_invoker_members=["user:admin@example.com"],
        )

        custom_tf_result = files.get("infra/workload/custom.tf", "")
        # custom.tf must now contain exactly ONE secondary module (module.compute in main.tf is Service 1)
        self.assertIn("module \"compute_service_two\"", custom_tf_result)
        self.assertNotIn("google_cloud_run_v2_service\" \"service_one\"", custom_tf_result)
        self.assertIn("enable_direct_iap     = var.enable_direct_iap", custom_tf_result)
        self.assertIn("authorized_invoker_members = var.authorized_invoker_members", custom_tf_result)

    def test_single_service_purges_duplicate_from_custom_tf(self):
        """
        When a single service is requested, any duplicate Cloud Run declaration in custom.tf is purged.
        """
        product_id = "singleapp"
        spec_text = "Build a single public REST API"

        files = {
            "infra/workload/main.tf": 'module "compute" { source = "../modules/compute-cloudrun" service_name = var.product_id }',
            "infra/workload/custom.tf": 'resource "google_cloud_run_v2_service" "app" { name = var.product_id }',
            f"apps/{product_id}/main.py": "print('app')",
        }

        reconcile_multi_service_declarations(
            files=files,
            product_id=product_id,
            spec_text=spec_text,
            archetype="cloudrun",
        )

        # Step 1 S1-A (HS-01/HS-08): the LLM Cloud Run service is replaced by the primary module (exact-range
        # removal); the file itself is never deleted by the platform.
        self.assertIn("infra/workload/custom.tf", files)
        self.assertNotIn("google_cloud_run_v2_service", files["infra/workload/custom.tf"])

    def test_reconcile_ignores_shared_packages(self):
        """The HB-04 app-directory census ignores apps/common, apps/shared, apps/__init__.py (it used to be checked
        through the deleted detect_requested_service_count)."""
        files = {
            "infra/workload/main.tf": 'module "compute" { source = "../modules/compute-cloudrun" service_name = var.product_id }',
            "apps/service_a/main.py": "print('a')",
            "apps/service_b/main.py": "print('b')",
            "apps/common/models.py": "class Model: pass",
            "apps/shared/utils.py": "def helper(): pass",
            "apps/__init__.py": "# init",
        }
        reconcile_multi_service_declarations(files=files, product_id="pkgs", spec_text="", archetype="cloudrun")
        custom_tf = files.get("infra/workload/custom.tf", "")
        self.assertIn('module "compute_service_b"', custom_tf)
        self.assertNotIn("compute_common", custom_tf)
        self.assertNotIn("compute_shared", custom_tf)

    def test_reconcile_does_not_duplicate_snake_case_services(self):
        """
        Verify reconcile_multi_service_declarations detects apps/service_a/main.py
        and does NOT create dummy fallback files in apps/service-a/main.py.
        """
        files = {
            "infra/workload/main.tf": 'module "compute" { source = "../modules/compute-cloudrun" service_name = "testplan02-a" }',
            "apps/service_a/main.py": "# real implementation a",
            "apps/service_b/main.py": "# real implementation b",
        }
        reconcile_multi_service_declarations(
            files=files,
            product_id="testplan02-a",
            spec_text="Deploy two cloud run services: Service A and Service B",
            archetype="cloudrun",
        )
        self.assertNotIn("apps/service-a/main.py", files)
        self.assertNotIn("apps/service-b/main.py", files)
        self.assertIn("apps/service_a/main.py", files)
        self.assertIn("apps/service_b/main.py", files)
        # FD-55 W5 (G15, register FD55-W5): no Procfile / .python-version / requirements.txt is written into an app
        # directory any more (the build writes the default Procfile only when missing; V3c judges the service)
        self.assertNotIn("apps/service_a/Procfile", files)
        self.assertNotIn("apps/service_b/Procfile", files)
        custom_tf = files.get("infra/workload/custom.tf", "")
        self.assertIn('module "compute_service_b"', custom_tf)
        self.assertNotIn("service-3", custom_tf)

    def test_primary_service_container_image_rewriting(self):
        """
        Verify generate_golden_main_tf sets container_image = replace(var.container_image, "/app:", "/storefront:")
        when service_name is explicitly specified and distinct from product_id.
        """
        hcl = generate_golden_main_tf(
            product_id="testplan06-a",
            archetype="cloudrun",
            service_name="storefront",
        )
        self.assertIn('container_image       = replace(var.container_image, "/app:", "/storefront:")', hcl)

    def test_pubsub_push_subscription_is_not_rewired_by_name(self):
        """
        FD-55 W5: the deleted HB-01 re-pointed a Pub/Sub push endpoint and audience from module.compute to
        module.compute_warehouse because "warehouse" appears in the subscription. Now nothing is rewired.
        """
        custom_hcl = '''
module "compute_warehouse" {
  source = "../modules/compute-cloudrun"
  service_name = "warehouse"
}

resource "google_pubsub_subscription" "warehouse_fulfillment" {
  name  = "warehouse-order-fulfillment-sub"
  topic = "order-events"
  push_config {
    push_endpoint = "${module.compute.service_uri}/api/v1/fulfillment/push"
    oidc_token {
      service_account_email = "sa@example.com"
      audience = module.compute.service_uri
    }
  }
  depends_on = [
    module.compute_warehouse,
    google_cloud_run_v2_service_iam_member.warehouse_pubsub_invoker
  ]
}
'''
        files = {
            "infra/workload/main.tf": 'module "compute" { source = "../modules/compute-cloudrun" service_name = "storefront" }',
            "infra/workload/custom.tf": custom_hcl,
        }
        reconcile_multi_service_declarations(files, product_id="testplan06-a", spec_text="")
        res_custom = files["infra/workload/custom.tf"]
        # FD-55 W5 (G16, register FD55-W5): HB-01 is deleted. The push endpoint / audience are no longer re-pointed
        # by name matching ("warehouse" in the subscription label); the AI's file is byte-identical and a wrong
        # reference is reported and repaired. No run.invoker member is synthesized either (S2-B B1, HS-02).
        self.assertEqual(res_custom, custom_hcl)
        self.assertIn("${module.compute.service_uri}/api/v1/fulfillment/push", res_custom)
        self.assertNotIn('resource "google_cloud_run_v2_service_iam_member"', res_custom)

    def test_reconcile_heterogeneous_gke_and_cloudrun_gateway(self):
        """
        When primary archetype is gke-autopilot, but the spec/repo contains a Cloud Run gateway,
        reconciliation must declare module.compute_gateway in custom.tf rather than skipping it.
        """
        product_id = "testplan05-a"
        spec_text = (
            "Please deploy a multi-tier distributed fleet architecture incorporating Cloud Run, "
            "GKE Autopilot, and an ephemeral Compute Engine worker. Tier 1 must consist of a Cloud "
            "Run Edge Gateway exposing POST /api/v1/dispatch."
        )
        files = {
            "infra/workload/main.tf": 'module "compute" { source = "../modules/compute-gke-autopilot" }',
            "infra/workload/custom.tf": 'resource "google_pubsub_topic" "stream" { name = "stream" }\n',
            "apps/gateway/main.py": "from fastapi import FastAPI\napp = FastAPI()",
            "apps/workers/main.py": "print('worker')",
        }
        reconcile_multi_service_declarations(
            files=files,
            product_id=product_id,
            spec_text=spec_text,
            archetype="gke-autopilot",
            allow_unauthenticated=True,
            enable_direct_iap=False,
            authorized_invoker_members=[],
        )
        custom_tf = files.get("infra/workload/custom.tf", "")
        self.assertIn('module "compute_gateway"', custom_tf)
        self.assertIn('source                = "../modules/compute-cloudrun"', custom_tf)
        self.assertIn('resource "google_pubsub_topic" "stream"', custom_tf)

    def test_service_kind_heterogeneous_fleet_comes_from_the_typed_intent(self):
        """
        FD-55 W8 (FD55-W8): in a heterogeneous fleet without a topology (primary gke-autopilot), a workflow's kind
        comes from the typed compute intent (planned secondaries are Cloud Run), never from the AI's HCL or a name
        substring (the deleted HD-03 resolve_service_archetype).
        """
        intent = resolve_compute_intent("testplan05-a", {"compute_archetype": "gke-autopilot",
                                                          "target_compute_services": ["worker", "gateway"]})
        kind = DeveloperAgent._service_kind
        self.assertEqual(kind("gateway", "gke-autopilot", intent), "cloudrun")      # planned secondary
        self.assertEqual(kind("worker", "gke-autopilot", intent), "gke-autopilot")  # primary
        # an unplanned directory gets the primary archetype, whatever its name (no `api` / `edge` substring guess)
        self.assertEqual(kind("api", "gke-autopilot", intent), "gke-autopilot")
        self.assertEqual(kind("ephemeral-worker", "gke-autopilot", intent), "gke-autopilot")

    def test_generate_service_workflow_gke_autopilot_hardening(self):
        """
        Verify that GKE Autopilot workflows include:
        1. install_components: 'gke-gcloud-auth-plugin' in setup-gcloud step
        2. Cluster readiness pre-check to prevent 404 race conditions during initial provisioning
        """
        wf = generate_service_workflow(
            service_name="worker",
            product_id="testplan05-a",
            archetype="gke-autopilot",
        )
        self.assertIn("install_components: 'gke-gcloud-auth-plugin'", wf)
        self.assertIn("if ! gcloud container clusters describe gke-testplan05-a", wf)
        self.assertIn("gcloud container clusters get-credentials gke-testplan05-a", wf)
        self.assertIn("Deploy worker to GKE Autopilot", wf)

    def test_generate_service_workflow_heterogeneous_cloudrun_gateway(self):
        """
        Verify that in a heterogeneous GKE fleet, the edge gateway workflow is generated
        as a Cloud Run deployment rather than a GKE deployment.
        """
        intent = resolve_compute_intent("testplan05-a", {"compute_archetype": "gke-autopilot",
                                                          "target_compute_services": ["worker", "gateway"]})
        resolved = DeveloperAgent._service_kind("gateway", "gke-autopilot", intent)   # FD-55 W8: typed intent
        self.assertEqual(resolved, "cloudrun")

        wf = generate_service_workflow(
            service_name="gateway",
            product_id="testplan05-a",
            archetype=resolved,
            allow_unauthenticated=True,
        )
        self.assertIn("Deploy gateway to Cloud Run", wf)
        self.assertIn("gcloud run deploy ${SERVICE_NAME}", wf)
        self.assertNotIn("gke-gcloud-auth-plugin", wf)
        self.assertNotIn("gcloud container clusters get-credentials", wf)

    def test_multi_service_preserves_both_storefront_and_warehouse(self):
        """
        Verifies that when both apps/storefront and apps/warehouse-service exist,
        reconcile_multi_service_declarations treats storefront as the primary (rendered into main.tf by
        generate_golden_main_tf) and declares warehouse-service as secondary compute in custom.tf.
        """
        files = {
            "infra/workload/main.tf": 'module "compute" { source = "../modules/compute-cloudrun" service_name = "testplan06-a" }',
            "apps/storefront/main.py": "# Storefront UI",
            "apps/warehouse-service/main.py": "# Warehouse fulfillment worker",
        }
        reconcile_multi_service_declarations(
            files=files,
            product_id="testplan06-a",
            spec_text="Deploy an e-commerce platform with a customer-facing storefront and warehouse fulfillment worker.",
            archetype="cloudrun",
        )
        # FD-55 W5 (G14): main.tf is no longer regex-rewritten here (the golden main.tf render, written after this
        # call, names the primary); the input main.tf is byte-identical
        self.assertEqual(files["infra/workload/main.tf"],
                         'module "compute" { source = "../modules/compute-cloudrun" service_name = "testplan06-a" }')
        # custom.tf must have module compute_warehouse_service
        custom_tf = files.get("infra/workload/custom.tf", "")
        self.assertIn('module "compute_warehouse_service"', custom_tf)
        self.assertIn('service_name          = "warehouse-service"', custom_tf)
        self.assertNotIn('compute_storefront', custom_tf)

    def test_subtask_target_services_does_not_clobber_existing_storefront(self):
        """
        Verifies the Sticky Primary Service Invariant: Passing target_compute_services = ["warehouse-service"]
        during a sub-task does NOT overwrite main.tf's storefront or drop storefront from topology.
        """
        files = {
            "infra/workload/main.tf": 'module "compute" { source = "../modules/compute-cloudrun" service_name = "storefront" }',
            "infra/workload/custom.tf": 'module "compute_warehouse_service" { source = "../modules/compute-cloudrun" service_name = "warehouse-service" }',
            "apps/storefront/main.py": "# Storefront UI",
            "apps/warehouse-service/main.py": "# Warehouse fulfillment worker",
        }
        # Step 1: the typed compute intent pins the repository's existing compute (HD-02 replacement)
        intent = resolve_compute_intent("testplan06-a", {"target_compute_services": ["warehouse-service"]},
                                        existing_files=files)
        # Pinned primary keeps storefront at index 0, warehouse-service index 1
        self.assertEqual(intent.service_names[0], "storefront")
        self.assertIn("warehouse-service", intent.service_names)

        # Step 2: Reconcile multi-service declarations with the intent's service set (what the developer passes)
        reconcile_multi_service_declarations(
            files=files,
            product_id="testplan06-a",
            spec_text="Task: implement warehouse stock deduction logic",
            archetype="cloudrun",
            target_services=list(intent.service_names),
        )
        self.assertIn('service_name = "storefront"', files["infra/workload/main.tf"])
        custom_tf = files.get("infra/workload/custom.tf", "")
        self.assertIn('module "compute_warehouse_service"', custom_tf)
        self.assertNotIn('compute_storefront', custom_tf)

    def test_detect_workload_services_prioritizes_authentic_entrypoints(self):
        """
        When LLM generates code in apps/agent-service/main.py and apps/testplan07-a/ only contains
        skeleton requirements/Procfile, detect_workload_services must return ['agent-service'].
        """
        files = {
            "apps/agent-service/main.py": "from fastapi import FastAPI\napp = FastAPI()",
            "apps/agent-service/agent.py": "class Agent: pass",
            "apps/testplan07-a/requirements.txt": "fastapi>=0.115.0\n",
            "apps/testplan07-a/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}\n",
            "apps/testplan07-a/.python-version": "3.13\n",
        }
        svcs = detect_workload_services(files, "testplan07-a")
        self.assertEqual(svcs, ["agent-service"])


    """Verifies that 'protected with IDP' triggers Direct IAP and auto-populates invokers."""

    def setUp(self):
        # Lane 17 PR-1a: the compliance engine runs in-process only on explicit request (never a fallback).
        self.compliance = ComplianceAgentHandler(mode="inprocess")
        self.developer = DeveloperAgent()

    def test_compliance_agent_detects_protected_with_idp(self):
        req = ComplianceAuditRequest(
            product_id="testingcr123",
            spec_text="Please create two cloud run services. PLease make both of the cloud run services protected with IDP. Jsut two services.",
            task_dag=[],
        )
        res = self.compliance.audit_and_enrich(req)
        self.assertTrue(res.enable_direct_iap)
        self.assertFalse(res.allow_unauthenticated)
        injected = [t["step_id"] for t in res.injected_tasks]
        self.assertIn("STEP-03D-DIRECT-IAP", injected)
        # Lane 19 L19-8 (FD-4I): compliance never invents invokers (no guessed admins, no allAuthenticatedUsers);
        # the developer stops a private workload without an access record (ACCESS_POLICY_INCOMPLETE).
        self.assertNotIn("allAuthenticatedUsers", res.allowed_domains)
        self.assertEqual(res.allowed_domains, [])

    def test_developer_agent_takes_invokers_from_the_access_policy(self):
        # Lane 19 L19-2 (plan §10 L19-3b): retargeted from the deleted, guessed get_admin_and_creator_members to
        # AccessPolicy.invoker_principals. The spec text ("protected with IDP") has no effect; the record decides.
        from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
        self.developer.genai_client = FakeGenaiClient(files=canned_workload_files("testingcr123"))
        access = {"mode": "PRIVATE_IAP", "invoker_principals": ["user:admin1@example.com", "group:ops@example.com"],
                  "sign_in": {"google": "DISABLED"}, "source": "intake"}
        with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}), \
             patch.object(self.developer, "fetch_existing_repo_files", return_value={}):
            files = self.developer.generate_code_files(
                product_id="testingcr123",
                spec_text="Please create two cloud run services. PLease make both of the cloud run services protected with IDP. Jsut two services.",
                # FD-4R R-6: the IAP decision comes from the compliance decision (here: the one the compliance server
                # derives for "protected with IDP"), never from the developer's own spec scan; lane 19 L19-2: the
                # invokers come only from the access record.
                task_dag=[], allow_unauthenticated=False, enable_direct_iap=True, domain_restricted_sharing=False,
                access=access,
            )
            tfvars = files.get("infra/workload/terraform.tfvars", "")
            self.assertIn("enable_direct_iap          = true", tfvars)
            self.assertIn("allow_unauthenticated      = false", tfvars)
            self.assertIn('authorized_invoker_members = ["user:admin1@example.com", "group:ops@example.com"]', tfvars)
            # Golden modules (infra/modules/, platform-owned) name the forbidden members in their validation rule.
            workload_text = "\n".join(v for p, v in files.items() if isinstance(v, str) and not p.startswith("infra/modules/"))
            self.assertNotIn("allAuthenticatedUsers", workload_text)

if __name__ == "__main__":
    unittest.main()
