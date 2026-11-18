"""
Unit tests for Express Golden / Registered Modules Workload Creation.
Covers ExpressHCLSynthesizer and Control Center Express Workload routes.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Mock third-party libraries if missing from test environment
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
    'httpx', 'fastapi', 'fastapi.responses', 'fastapi.templating', 'fastapi.staticfiles',
    'starlette', 'starlette.middleware', 'starlette.middleware.base', 'starlette.requests',
    'google', 'google.genai', 'google.genai.types', 'google.cloud', 'google.cloud.firestore',
    'google.cloud.storage', 'google.cloud.logging', 'google.cloud.logging_v2',
    'google.cloud.pubsub_v1', 'google.cloud.secretmanager', 'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONTROL_CENTER_PATH = os.path.join(REPO_ROOT, "apps", "control-center")
if CONTROL_CENTER_PATH not in sys.path:
    sys.path.insert(0, CONTROL_CENTER_PATH)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from shared.express_synthesizer import ExpressHCLSynthesizer


class TestExpressHCLSynthesizer(unittest.TestCase):
    """Tests for deterministic HCL synthesis and vendoring in Express mode."""

    def setUp(self):
        self.synth = ExpressHCLSynthesizer()

    def test_default_express_workload_synthesis(self):
        """Test basic Express synthesis with default single Cloud Run gateway."""
        files = self.synth.synthesize_workload(
            product_id="express-demo",
            project_id="castor-express-demo-1234",
            region="us-central1",
            module_instances=[
                {"module_id": "compute-cloudrun", "instance_name": "gateway", "parameters": {}}
            ],
            include_vpc=False,
            state_bucket="castor-tfstate-1234"
        )

        # 1. Zero dummy app code verification
        for path in files.keys():
            self.assertFalse(path.startswith("apps/"), f"Unexpected app file in IaC repo: {path}")

        # 2. OpenTofu 1.9.0 compliance
        self.assertIn("infra/workload/versions.tf", files)
        versions_tf = files["infra/workload/versions.tf"]
        self.assertIn('required_version = ">= 1.9.0"', versions_tf)
        self.assertIn('source  = "hashicorp/google"', versions_tf)

        # 3. State backend
        self.assertIn("infra/workload/backend.tf", files)
        backend_tf = files["infra/workload/backend.tf"]
        self.assertIn('bucket = "castor-tfstate-1234"', backend_tf)
        self.assertIn('prefix = "workloads/express-demo"', backend_tf)

        # 4. Foundation module present
        self.assertIn("infra/workload/main.tf", files)
        main_tf = files["infra/workload/main.tf"]
        self.assertIn('module "foundation"', main_tf)
        self.assertIn('"../modules/workload-foundation/base"', main_tf)

        # 5. Single Cloud Run module instance
        self.assertIn('module "compute_gateway"', main_tf)
        self.assertIn('"../modules/compute-cloudrun"', main_tf)
        self.assertIn('container_image       = "us-docker.pkg.dev/cloudrun/container/hello"', main_tf)

        # 6. Outputs verify
        self.assertIn("infra/workload/outputs.tf", files)
        outputs_tf = files["infra/workload/outputs.tf"]
        self.assertIn("compute_gateway_uri", outputs_tf)

        # 7. Vendored files
        self.assertTrue(any(k.startswith("infra/modules/workload-foundation/base/") for k in files))
        self.assertTrue(any(k.startswith("infra/modules/compute-cloudrun/") for k in files))

        # 8. Gitignore & README
        self.assertIn(".gitignore", files)
        self.assertIn("README.md", files)
        self.assertIn("express-demo", files["README.md"])

    def test_multi_instance_synthesis(self):
        """Test synthesizing multiple compute and storage instances with unique identifiers."""
        module_instances = [
            {"module_id": "compute-cloudrun", "instance_name": "gateway", "parameters": {"container_port": 8080}},
            {"module_id": "compute-cloudrun", "instance_name": "orders_api", "parameters": {"container_port": 8081}},
            {"module_id": "database-cloudsql", "instance_name": "main_pg", "parameters": {"database_version": "POSTGRES_15"}},
            {"module_id": "storage-bucket", "instance_name": "invoices", "parameters": {"versioning": True}},
            {"module_id": "messaging-pubsub", "instance_name": "order_events", "parameters": {}},
        ]

        files = self.synth.synthesize_workload(
            product_id="multi-inst-demo",
            project_id="castor-multi-inst-1234",
            region="us-central1",
            module_instances=module_instances,
            include_vpc=True,
            state_bucket="castor-tfstate-1234"
        )

        main_tf = files["infra/workload/main.tf"]

        # VPC Module included
        self.assertIn('module "network"', main_tf)
        # FD-CSQL: with a Cloud SQL instance the network block carries the IPAM subnet fact (realigned)
        self.assertIn('source = "../modules/networking-vpc"', main_tf)
        self.assertIn('primary_subnet_cidr = var.subnet_cidr', main_tf)

        # Multi Cloud Run instances
        self.assertIn('module "compute_gateway"', main_tf)
        self.assertIn('module "compute_orders_api"', main_tf)

        # Multi Database / Storage instances
        self.assertIn('module "database_main_pg"', main_tf)
        self.assertIn('module "storage_invoices"', main_tf)
        self.assertIn('module "messaging_order_events"', main_tf)

        # Vendored modules present
        self.assertTrue(any(k.startswith("infra/modules/networking-vpc/") for k in files))
        self.assertTrue(any(k.startswith("infra/modules/database-cloudsql/") for k in files))
        self.assertTrue(any(k.startswith("infra/modules/storage-bucket/") for k in files))
        self.assertTrue(any(k.startswith("infra/modules/messaging-pubsub/") for k in files))

        # Outputs contains service urls and db connections
        outputs_tf = files["infra/workload/outputs.tf"]
        self.assertIn("compute_gateway_uri", outputs_tf)
        self.assertIn("compute_orders_api_uri", outputs_tf)
        self.assertIn("database_main_pg_connection_name", outputs_tf)
        self.assertIn("storage_invoices_bucket_name", outputs_tf)
        self.assertIn("messaging_order_events_topic_id", outputs_tf)

    def test_custom_module_synthesis(self):
        """Test synthesizing a custom module instance."""
        module_instances = [
            {
                "module_id": "custom-my-queue",
                "instance_name": "billing",
                "parameters": {"queue_name": "billing-jobs"}
            }
        ]

        files = self.synth.synthesize_workload(
            product_id="custom-mod-demo",
            project_id="castor-custom-1234",
            region="us-central1",
            module_instances=module_instances,
            include_vpc=False,
            state_bucket="castor-tfstate-1234"
        )

        main_tf = files["infra/workload/main.tf"]
        self.assertIn('module "mod_billing"', main_tf)
        self.assertIn('source = "../modules/custom-my-queue"', main_tf)
        self.assertIn('queue_name = "billing-jobs"', main_tf)


class TestControlCenterSchemas(unittest.TestCase):
    """Tests for Control Center Pydantic schema extensions."""

    def test_create_workload_request_express_defaults(self):
        from schemas import CreateWorkloadRequest, ModuleInstanceConfig

        # Test Express creation request without spec_content
        req = CreateWorkloadRequest(
            product_id="express-test",
            creation_mode="EXPRESS",
            module_instances=[
                ModuleInstanceConfig(module_id="compute-cloudrun", instance_name="gateway")
            ],
            include_vpc=True
        )
        self.assertEqual(req.creation_mode, "EXPRESS")
        self.assertEqual(req.spec_content, "")
        self.assertTrue(req.include_vpc)
        self.assertEqual(len(req.module_instances), 1)
        self.assertEqual(req.module_instances[0].instance_name, "gateway")

    def test_create_workload_request_agent_defaults(self):
        from schemas import CreateWorkloadRequest

        # Test Agent creation request
        req = CreateWorkloadRequest(
            product_id="agent-test",
            spec_content="Build a microservice"
        )
        self.assertEqual(req.creation_mode, "AGENT")
        self.assertEqual(req.spec_content, "Build a microservice")
        self.assertFalse(req.include_vpc)


class TestExpressProvisioningRoute(unittest.TestCase):
    """Tests for Express provisioning workflow in workloads route."""

    @patch("routes.workloads.make_vending_request")
    @patch("routes.workloads.VCSProviderFactory.get_provider")
    @patch("routes.workloads.make_terraform_request")
    @patch("routes.workloads.db")
    # Entered first (innermost decorator): patch() reads the original routes.workloads.db, a lazy Firestore proxy; when
    # an earlier test file imported the real google.cloud.firestore, that read would construct a real client.
    @patch("db._db_client", False)
    def test_execute_express_provisioning(self, mock_db, mock_tf, mock_vcs, mock_vending):
        from routes.workloads import execute_express_provisioning

        # Setup mocks
        mock_vending_resp = MagicMock()
        mock_vending_resp.status_code = 200
        mock_vending_resp.json.return_value = {
            "project_id": "castor-express-1234",
            "github_repo": "https://github.com/org/express-repo",
            "state_bucket": "castor-tfstate-1234"
        }
        mock_vending.return_value = mock_vending_resp

        mock_provider_instance = MagicMock()
        mock_vcs.return_value = mock_provider_instance

        mock_tf_resp = MagicMock()
        mock_tf_resp.status_code = 200
        mock_tf_resp.json.return_value = {
            "status": "SUCCESS",
            "service_url": "https://gateway-express-uc.a.run.app"
        }
        mock_tf.return_value = mock_tf_resp

        # Execute
        execute_express_provisioning(
            product_id="express-pipeline-test",
            target_project_id="castor-express-1234",
            clean_vcs_provider="GITHUB",
            full_github_repo="org/express-repo",
            target_branch="main",
            target_folder=None,
            budget=50.0,
            clean_engine="OPENTOFU",
            is_sandbox=False,
            admin_email="admin@example.com",
            module_instances=[
                {"module_id": "compute-cloudrun", "instance_name": "gateway", "parameters": {}}
            ],
            include_vpc=False,
            trace_id="trace-exp-123",
            vending_url="http://vending-service",
            terraform_url="http://terraform-service",
            region="us-central1",   # FD-7M-a: the create route passes the region it recorded
        )

        # Assert vending called
        mock_vending.assert_called_once()
        vending_payload = mock_vending.call_args[1]["json_body"]
        self.assertEqual(vending_payload["product_id"], "express-pipeline-test")

        # Assert VCS commit files called
        mock_provider_instance.commit_files.assert_called_once()
        commit_files = mock_provider_instance.commit_files.call_args[1]["files"]
        self.assertIn("infra/workload/main.tf", commit_files)
        self.assertIn("infra/workload/versions.tf", commit_files)
        self.assertIn(".gitignore", commit_files)
        # Ensure zero app code committed
        for k in commit_files.keys():
            self.assertFalse(k.startswith("apps/"))

        # Assert OpenTofu deploy dispatched
        mock_tf.assert_called_once()
        tf_payload = mock_tf.call_args[1]["json_body"]
        self.assertEqual(tf_payload["product_id"], "express-pipeline-test")
        self.assertEqual(tf_payload["target_project_id"], "castor-express-1234")
        self.assertEqual(tf_payload["iac_engine"], "OPENTOFU")

        # Assert Firestore updated
        mock_db.collection.assert_called()


if __name__ == "__main__":
    unittest.main()
