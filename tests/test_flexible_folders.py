"""
Project Castor: Unit Tests for Multi-Folder Support, Target Folder Selection, and Branch-Backed Folder Deployment
Verifies:
1. Schemas: ManagedFolder, CreateFolderRequest, DeployToFolderRequest, RedeployRequestWithFolder, WorkloadSummary.
2. Project Vending Engine: create_folder, vend_gcp_project with folder_id, redeploy_workload with target_folder_id.
3. Control Center Settings Endpoints: GET /api/settings/folders, POST /api/settings/folders, set-default, DELETE.
4. RBAC Authorization: ADMIN enforcement on folder creation, mutation, and deletion; WORKLOAD_MANAGER on deploy-to-folder.
5. Workload Creation & Redeploy: folder_id persistence in Firestore and Pub/Sub payload.
6. Branch-Backed Promotion: POST /api/workloads/{product_id}/deploy-to-folder creates Git branch and registers new workload.
7. Google Drive Ingestion Waterfall: resolve_target_folder 4-tier resolution.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
cc_dir = os.path.join(repo_root, "apps", "control-center")
vending_dir = os.path.join(repo_root, "apps", "project-vending")
spec_dir = os.path.join(repo_root, "apps", "spec-ingestion")
sys.path.insert(0, repo_root)
sys.path.insert(0, cc_dir)
sys.path.insert(0, vending_dir)
sys.path.insert(0, spec_dir)

# Mock external cloud clients and frameworks before imports
for mod in [
    "google", "google.auth", "google.auth.transport", "google.auth.transport.requests",
    "google.oauth2", "google.oauth2.id_token", "googleapiclient", "googleapiclient.discovery",
    "googleapiclient.errors", "google.cloud", "google.cloud.firestore", "google.cloud.storage",
    "google.cloud.logging", "google.cloud.logging_v2", "google.cloud.pubsub_v1",
    "google.cloud.secretmanager", "starlette", "starlette.middleware", "starlette.middleware.base",
    "jwt", "github", "httpx"
]:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()


class MockHttpError(Exception):
    def __init__(self, resp=None, content=b""):
        self.resp = resp or MagicMock(status=404)
        self.content = content
        super().__init__(f"HttpError {getattr(self.resp, 'status', 404)}: {content}")


sys.modules["googleapiclient.errors"].HttpError = MockHttpError


class MockHTTPException(Exception):
    def __init__(self, status_code: int, detail: str = ""):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"{status_code}: {detail}")


def mock_decorator(*args, **kwargs):
    def inner(fn):
        return fn
    return inner


mock_app = MagicMock()
mock_app.get = mock_decorator
mock_app.post = mock_decorator
mock_app.put = mock_decorator
mock_app.delete = mock_decorator
mock_app.patch = mock_decorator
mock_app.middleware = mock_decorator

mock_fastapi = MagicMock()
mock_fastapi.HTTPException = MockHTTPException
mock_fastapi.FastAPI = lambda *args, **kwargs: mock_app
mock_fastapi.Request = MagicMock
mock_fastapi.Response = MagicMock
sys.modules["fastapi"] = mock_fastapi

mock_responses = MagicMock()
mock_responses.HTMLResponse = MagicMock
mock_responses.JSONResponse = MagicMock
mock_responses.RedirectResponse = MagicMock
sys.modules["fastapi.responses"] = mock_responses

# Mock Pydantic
try:
    import pydantic
except ImportError:
    class MockFieldInfo:
        def __init__(self, default=None, default_factory=None, **kwargs):
            self.default = default
            self.default_factory = default_factory
        def get_value(self):
            if self.default_factory is not None:
                return self.default_factory()
            return self.default

    class MockBaseModel:
        def __init__(self, **kwargs):
            for cls in reversed(self.__class__.__mro__):
                for k, v in cls.__dict__.items():
                    if not k.startswith('_') and not callable(v):
                        default_val = v.get_value() if isinstance(v, MockFieldInfo) else v
                        if default_val is not Ellipsis:
                            setattr(self, k, default_val)
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self):
            res = {}
            for k, v in self.__dict__.items():
                if not k.startswith('_'):
                    if hasattr(v, 'model_dump'):
                        res[k] = v.model_dump()
                    elif isinstance(v, list):
                        res[k] = [item.model_dump() if hasattr(item, 'model_dump') else item for item in v]
                    elif isinstance(v, dict):
                        res[k] = {ik: (iv.model_dump() if hasattr(iv, 'model_dump') else iv) for ik, iv in v.items()}
                    else:
                        res[k] = v
            return res

        def dict(self):
            return self.model_dump()

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: MockFieldInfo(default=default, default_factory=default_factory)
    mock_pydantic.EmailStr = str
    sys.modules['pydantic'] = mock_pydantic

# Load Schemas
_cc_schemas_spec = importlib.util.spec_from_file_location("cc_schemas", os.path.join(cc_dir, "schemas.py"))
cc_schemas = importlib.util.module_from_spec(_cc_schemas_spec)
sys.modules["schemas"] = cc_schemas
_cc_schemas_spec.loader.exec_module(cc_schemas)

# Load Settings
_settings_spec = importlib.util.spec_from_file_location("shared_settings", os.path.join(repo_root, "shared", "settings.py"))
shared_settings = importlib.util.module_from_spec(_settings_spec)
sys.modules["shared.settings"] = shared_settings
_settings_spec.loader.exec_module(shared_settings)

# Load Vending Engine
_vending_spec = importlib.util.spec_from_file_location("project_vending", os.path.join(vending_dir, "vending.py"))
project_vending = importlib.util.module_from_spec(_vending_spec)
sys.modules["vending"] = project_vending
_vending_spec.loader.exec_module(project_vending)

# Load Control Center main
_cc_main_spec = importlib.util.spec_from_file_location("cc_main", os.path.join(cc_dir, "main.py"))
cc_main = importlib.util.module_from_spec(_cc_main_spec)
sys.modules["main"] = cc_main
_cc_main_spec.loader.exec_module(cc_main)

# Load Spec Ingestion Poller
_poller_spec = importlib.util.spec_from_file_location("spec_poller", os.path.join(spec_dir, "poller.py"))
spec_poller = importlib.util.module_from_spec(_poller_spec)
sys.modules["poller"] = spec_poller
_poller_spec.loader.exec_module(spec_poller)


class TestFlexibleFolderSchemas(unittest.TestCase):
    """Tests schema validation for multi-folder and promotion models."""

    def test_managed_folder_schema(self):
        folder = cc_schemas.ManagedFolder(
            folder_id="folders/1234567890",
            folder_number="1234567890",  # FD-05 B-4: required since 372e991
            display_name="Finance Dev",
            parent_folder_id="folders/9876543210",
            is_default=True,
            status="ACTIVE",
            description="Financial systems development sandbox",
        )
        self.assertEqual(folder.folder_id, "folders/1234567890")
        self.assertEqual(folder.display_name, "Finance Dev")
        self.assertTrue(folder.is_default)
        self.assertEqual(folder.status, "ACTIVE")

    def test_create_folder_request_schema(self):
        req = cc_schemas.CreateFolderRequest(
            display_name="Production Core",
            parent_folder_id="folders/111222333",
            description="Tier 1 production services",
        )
        self.assertEqual(req.display_name, "Production Core")
        self.assertEqual(req.parent_folder_id, "folders/111222333")

    def test_deploy_to_folder_request_schema(self):
        req = cc_schemas.DeployToFolderRequest(
            destination_folder_id="folders/999888777",
            new_product_id="payment-service-prod",
            target_branch="production",
            copy_feature_requests=True,
        )
        self.assertEqual(req.destination_folder_id, "folders/999888777")
        self.assertEqual(req.new_product_id, "payment-service-prod")
        self.assertEqual(req.target_branch, "production")
        self.assertTrue(req.copy_feature_requests)

    def test_redeploy_request_with_folder_schema(self):
        req = cc_schemas.RedeployRequestWithFolder(
            target_folder_id="folders/555444333"
        )
        self.assertEqual(req.target_folder_id, "folders/555444333")

    def test_workload_summary_folder_fields(self):
        ws = cc_schemas.WorkloadSummary(
            product_id="billing-api",
            project_id="castor-billing-api-1a2b",
            folder_id="folders/1234567890",
            folder_name="Finance Dev",
            status="ACTIVE",
            budget_ceiling_monthly_usd=50.0,
        )
        self.assertEqual(ws.folder_id, "folders/1234567890")
        self.assertEqual(ws.folder_name, "Finance Dev")


# A finished projects.create operation: its response is the v3 Project, whose name carries the project number
# (VENDING-READ-TRANSIENT, OQ-28: a project created in a vend must have a known number).
CREATED_OP = {"name": "operations/proj-create", "done": True, "response": {"name": "projects/123456789012"}}


class FakeChildIAM:
    """Child IAM policies for the vend-time grants (RT14-31 Control Center log reader); grants succeed."""

    def __init__(self):
        self.policies = {}

    def get_iam_policy(self, project_id):
        return dict(self.policies.get(project_id, {"bindings": []}))

    def set_iam_policy(self, project_id, policy):
        self.policies[project_id] = policy
        return policy


class TestProjectVendingFolderManagement(unittest.TestCase):
    """Tests GCP Resource Manager folder creation and folder-aware project provisioning."""

    def setUp(self):
        self.mock_crm = MagicMock()
        self.mock_db = MagicMock()
        self.vending_engine = project_vending.ProjectRepoVendingEngine(
            platform_project_id="test-castor-platform",
            firestore_client=self.mock_db,
            crm_service=self.mock_crm,
            iam_client=FakeChildIAM(),   # RT14-31: the vend-time Control Center log-reader grant
        )
        self.vending_engine.folder_id = "folders/1000000001"

    def test_create_folder_success(self):
        mock_op = {"name": "operations/folder-create-123", "done": True, "response": {"name": "folders/2000000002"}}
        folders_mock = MagicMock()
        folders_mock.create().execute.return_value = mock_op
        self.mock_crm.folders.return_value = folders_mock
        self.mock_crm.operations().get().execute.return_value = mock_op
        folders_mock.create.reset_mock()

        result = self.vending_engine.create_folder(
            display_name="Marketing QA",
            parent_folder_id="folders/1000000001",
        )

        folders_mock.create.assert_called_once_with(
            body={"displayName": "Marketing QA", "parent": "folders/1000000001"},
        )
        self.assertEqual(result["folder_id"], "folders/2000000002")
        self.assertEqual(result["display_name"], "Marketing QA")
        self.assertEqual(result["status"], "SUCCESS")

    def test_create_folder_empty_display_name_raises(self):
        with self.assertRaises(ValueError):
            self.vending_engine.create_folder(display_name="   ")

    def test_vend_gcp_project_uses_override_folder(self):
        """vend_gcp_project must prioritize folder_id argument over doc data or default folder."""
        projects_mock = MagicMock()
        projects_mock.create().execute.return_value = {"name": "operations/proj-create-123", "done": True}
        self.mock_crm.projects.return_value = projects_mock

        # Mock Firestore doc
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "product_id": "test-service",
            "folder_id": "folders/from-doc-333",
        }
        self.mock_db.collection().document().get.return_value = mock_doc
        projects_mock.create.reset_mock()

        with patch.object(self.vending_engine, "_wait_for_crm_operation", return_value=CREATED_OP), \
             patch.object(self.vending_engine, "_retry_api_call"), \
             patch("googleapiclient.discovery.build"):

            res_dict = self.vending_engine.vend_gcp_project(
                product_id="test-service",
                trace_id="test-trace-123",
                folder_id="folders/explicit-override-999",
            )

            # Verify CRM projects().create was invoked with the explicit override folder
            create_call_args = projects_mock.create.call_args[1]
            self.assertEqual(create_call_args["body"]["parent"], "folders/explicit-override-999")
            self.assertTrue(res_dict["project_id"].startswith("test-service"))

    def test_vend_gcp_project_creates_project_when_status_is_provisioning(self):
        """vend_gcp_project must NOT skip creation when Firestore status is PROVISIONING."""
        projects_mock = MagicMock()
        projects_mock.create().execute.return_value = {"name": "operations/proj-create-456", "done": True}
        self.mock_crm.projects.return_value = projects_mock

        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "product_id": "test-provisioning-app",
            "project_id": "castor-preassign-123",
            "status": "PROVISIONING",
            "folder_id": "folders/111222",
        }
        self.mock_db.collection().document().get.return_value = mock_doc
        projects_mock.create.reset_mock()

        with patch.object(self.vending_engine, "_wait_for_crm_operation", return_value=CREATED_OP), \
             patch.object(self.vending_engine, "_retry_api_call"), \
             patch("googleapiclient.discovery.build"):

            res_dict = self.vending_engine.vend_gcp_project(
                product_id="test-provisioning-app",
                trace_id="test-trace-prov",
            )

            # projects().create MUST be called even though project_id was present in Firestore
            projects_mock.create.assert_called_once()
            self.assertEqual(res_dict["status"], "PROJECT_VENDED")

    def test_vend_gcp_project_handles_invalid_or_overlong_project_id(self):
        """vend_gcp_project must regenerate project ID if preassigned ID exceeds 30 characters."""
        projects_mock = MagicMock()
        projects_mock.create().execute.return_value = {"name": "operations/proj-create-789", "done": True}
        self.mock_crm.projects.return_value = projects_mock

        # 34 character project_id
        overlong_id = "castor-castorcloudruntest-s-5a6ba1"
        self.assertGreater(len(overlong_id), 30)

        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "product_id": "castorcloudruntest-stage",
            "project_id": overlong_id,
            "status": "PROVISIONING",
            "folder_id": "folders/123456789012",
        }
        self.mock_db.collection().document().get.return_value = mock_doc
        projects_mock.create.reset_mock()

        with patch.object(self.vending_engine, "_wait_for_crm_operation", return_value=CREATED_OP), \
             patch.object(self.vending_engine, "_retry_api_call"), \
             patch("googleapiclient.discovery.build"):

            res_dict = self.vending_engine.vend_gcp_project(
                product_id="castorcloudruntest-stage",
                trace_id="test-trace-overlong",
            )

            # projects().create MUST be called and projectId MUST be <= 30 chars
            projects_mock.create.assert_called_once()
            called_proj_id = projects_mock.create.call_args[1]["body"]["projectId"]
            self.assertLessEqual(len(called_proj_id), 30)
            self.assertLessEqual(len(res_dict["project_id"]), 30)

    def _ghost_vend(self, status):
        from googleapiclient.errors import HttpError

        projects_mock = MagicMock()
        fake_resp = MagicMock()
        fake_resp.status = 404
        projects_mock.get.return_value.execute.side_effect = HttpError(resp=fake_resp, content=b"Project not found")
        projects_mock.create.return_value.execute.return_value = {"name": "operations/proj-recreate-123", "done": True}
        self.mock_crm.projects.return_value = projects_mock

        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "product_id": "ghost-service",
            "project_id": "castor-ghost-serv-112233",
            "status": status,
            "folder_id": "folders/111222",
        }
        self.mock_db.collection().document().get.return_value = mock_doc
        projects_mock.create.reset_mock()

        with patch.object(self.vending_engine, "_wait_for_crm_operation", return_value=CREATED_OP), \
             patch.object(self.vending_engine, "_retry_api_call"), \
             patch("googleapiclient.discovery.build"):
            return projects_mock, self.vending_engine.vend_gcp_project(
                product_id="ghost-service",
                trace_id="test-trace-ghost",
            )

    def test_vend_gcp_project_stops_typed_when_recorded_active_project_answers_404(self):
        """SAT-38 (RT SAT-25 M1): a project an ACTIVE record names that CRM answers 404 for is never created again
        (its id is not reusable, so that could only 409 into a second, fallback project): typed stop, no create."""
        VendingFailure = project_vending.VendingFailure
        with self.assertRaises(VendingFailure) as ctx:
            self._ghost_vend("ACTIVE")
        self.assertEqual(ctx.exception.error_class, "VENDING.RECORDED_PROJECT_UNREADABLE")
        self.assertIn("castor-ghost-serv-112233", ctx.exception.detail)
        self.mock_crm.projects.return_value.create.assert_not_called()

    def test_vend_gcp_project_creates_pre_assigned_id_when_crm_returns_404(self):
        """Negative (SAT-38): a pre-assigned id (PROVISIONING record) is still created exactly as before."""
        projects_mock, res_dict = self._ghost_vend("PROVISIONING")
        projects_mock.create.assert_called_once()
        self.assertEqual(res_dict["status"], "PROJECT_VENDED")

    def test_redeploy_workload_updates_target_folder(self):
        """redeploy_workload must store target_folder_id in Firestore and pass to vend_gcp_project."""
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "product_id": "dormant-api",
            "status": "DECOMMISSIONED",
            "folder_id": "folders/old-folder",
            "project_id": "castor-dormant-api-old",
        }
        self.mock_db.collection().document().get.return_value = mock_doc

        # FD vending-redeploy: ACTIVE needs a terraform /deploy that answers HTTP 200 (no terraform URL -> FAILED).
        # SAT-38: redeploy records the project vending returns, so the fake returns the id it was asked to create.
        with patch.object(self.vending_engine, "vend_gcp_project",
                          side_effect=lambda **kw: {"project_id": kw["force_new_project_id"]}) as mock_vend, \
             patch("httpx.Client") as mock_httpx, patch.object(project_vending, "_fetch_id_token", return_value=None), \
             patch.dict(os.environ, {"TERRAFORM_SERVICE_URL": "http://terraform-svc"}):
            mock_httpx.return_value.__enter__.return_value.post.return_value = MagicMock(
                status_code=200, json=lambda: {"outputs": {"service_url": "https://dormant.run.app"}})
            res = self.vending_engine.redeploy_workload(
                product_id="dormant-api",
                operator_email="admin@castor.internal",
                target_folder_id="folders/new-target-444",
            )

            call_kwargs = mock_vend.call_args[1]
            self.assertEqual(call_kwargs["product_id"], "dormant-api")
            self.assertEqual(call_kwargs["folder_id"], "folders/new-target-444")

            # Verify Firestore status update includes folder_id
            set_call = self.mock_db.collection().document().set.call_args[0][0]
            self.assertEqual(set_call["status"], "ACTIVE")
            self.assertEqual(set_call["folder_id"], "folders/new-target-444")
            self.assertTrue(res["project_id"].startswith("dormant-api-"))

    def test_vend_all_reuses_existing_github_repo_in_firestore(self):
        """vend_all must reuse existing github_repo from Firestore rather than creating a duplicate repository."""
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "product_id": "castorcloudruntest-stage",
            "project_id": "castor-castorcloudrunte-83f06c",
            "github_repo": "example-org/castor-castorcloudruntest",
            "default_branch": "stage",
            "status": "PROVISIONING",
            "folder_id": "folders/123456789012",
        }
        self.mock_db.collection().document().get.return_value = mock_doc

        with patch.object(self.vending_engine, "vend_gcp_project", return_value={"project_id": "castor-castorcloudrunte-83f06c"}), \
             patch.object(self.vending_engine, "vend_github_repo") as mock_vend_repo:

            res = self.vending_engine.vend_all(
                product_id="castorcloudruntest-stage",
                trace_id="test-trace-reuse",
                folder_id="folders/123456789012",
            )

            mock_vend_repo.assert_not_called()
            self.assertEqual(res["github_repo"]["full_name"], "example-org/castor-castorcloudruntest")
            self.assertTrue(res["github_repo"]["reused_existing"])
            self.assertEqual(res["product_id"], "castorcloudruntest-stage")

    def test_redeploy_workload_passes_branch_and_preserves_secrets_for_non_main(self):
        """redeploy_workload must preserve default_branch and pass branch in deployment request.
        FD-4CI-b-R1-WIF: the repository is shared with the main workload `castorcloudruntest` (its record names the same
        repository), so the plain secrets stay that workload's and this one keeps the branch-suffixed names."""
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "product_id": "castorcloudruntest-stage",
            "status": "DECOMMISSIONED",
            "folder_id": "folders/123456789012",
            "project_id": "castor-castorcloudrunte-old",
            "github_repo": "example-org/castor-castorcloudruntest",
            "default_branch": "stage",
        }
        self.mock_db.collection().document().get.return_value = mock_doc
        sibling = MagicMock()
        sibling.id = "castorcloudruntest"
        sibling.to_dict.return_value = {"github_repo": "example-org/castor-castorcloudruntest", "default_branch": "main"}
        self.mock_db.collection().stream.return_value = [sibling]

        with patch.object(self.vending_engine, "vend_gcp_project", return_value={"project_id": "castor-castorcloudrunte-new"}), \
             patch.object(self.vending_engine, "_update_github_secrets") as mock_update_secrets, \
             patch("httpx.Client") as mock_httpx, patch.object(project_vending, "_fetch_id_token", return_value=None):

            mock_client_instance = MagicMock()
            mock_client_instance.post.return_value = MagicMock(status_code=200, json=lambda: {"outputs": {"service_url": "https://stage.run.app"}})
            mock_httpx.return_value.__enter__.return_value = mock_client_instance

            with patch.dict(os.environ, {"TERRAFORM_SERVICE_URL": "http://terraform-svc"}):
                res = self.vending_engine.redeploy_workload(
                    product_id="castorcloudruntest-stage",
                    operator_email="admin@castor.internal",
                )

            # GCP_PROJECT_ID secret must NOT be overwritten when branch != main
            mock_update_secrets.assert_called_once()
            called_secrets = mock_update_secrets.call_args[0][1]
            self.assertNotIn("GCP_PROJECT_ID", called_secrets)
            self.assertIn("GCP_PROJECT_ID_STAGE", called_secrets)

            # HTTP post to terraform service must include branch="stage"
            mock_client_instance.post.assert_called_once()
            post_args = mock_client_instance.post.call_args
            payload = post_args[1]["json"]
            self.assertEqual(payload["branch"], "stage")
            self.assertEqual(payload["product_id"], "castorcloudruntest-stage")

    # FD-4CI-b-R1-WIF: the secret names a redeploy writes are the ones the generated deploy workflows read
    # (secrets.GCP_PROJECT_ID / WIF_PROVIDER / WIF_SERVICE_ACCOUNT), unless the repository is another workload's too.
    _PLAIN = {"GCP_PROJECT_ID", "WIF_PROVIDER", "WIF_SERVICE_ACCOUNT"}

    def _r1wif_redeploy(self, record, others=None, stream_error=None):
        doc = MagicMock()
        doc.exists = True
        doc.to_dict.return_value = dict(record, status="DECOMMISSIONED", folder_id="folders/123456789012")
        self.mock_db.collection().document().get.return_value = doc
        stream = self.mock_db.collection().stream
        stream.reset_mock()
        if stream_error is not None:
            stream.side_effect = stream_error
        else:
            stream.side_effect = None
            docs = []
            for pid, data in [(record["product_id"], record)] + list(others or []):
                d = MagicMock()
                d.id = pid
                d.to_dict.return_value = dict(data)
                docs.append(d)
            stream.return_value = docs
        spy = MagicMock(wraps=self.vending_engine._repository_shared_with_other_workload)
        with patch.object(self.vending_engine, "vend_gcp_project", return_value={"project_id": "r1wif-new"}), \
             patch.object(self.vending_engine, "_repository_shared_with_other_workload", spy), \
             patch.object(self.vending_engine, "_update_github_secrets", return_value=True) as upd, \
             patch("httpx.Client") as mock_httpx, patch.object(project_vending, "_fetch_id_token", return_value=None), \
             patch.dict(os.environ, {"TERRAFORM_SERVICE_URL": "http://terraform-svc"}):
            mock_httpx.return_value.__enter__.return_value.post.return_value = MagicMock(
                status_code=200, json=lambda: {"outputs": {"service_url": "https://r1wif.run.app"}})
            res = self.vending_engine.redeploy_workload(product_id=record["product_id"],
                                                        operator_email="admin@castor.internal")
        upd.assert_called_once()
        return upd.call_args[0][1], res, spy

    def test_r1wif_own_repository_on_a_non_main_branch_gets_the_names_the_workflow_reads(self):
        secrets, res, stream = self._r1wif_redeploy(
            {"product_id": "r1wif-app", "github_repo": "example-org/r1wif-app", "default_branch": "develop"},
            others=[("other-app", {"github_repo": "example-org/other-app"}),
                    ("legacy-dict", {"github_repo": {"full_name": "example-org/legacy-dict"}})])
        self.assertEqual(set(secrets), self._PLAIN)
        self.assertEqual(secrets["GCP_PROJECT_ID"], res["project_id"])
        self.assertEqual(secrets["WIF_PROVIDER"], f"projects/{res['project_id']}/locations/global/"
                                                  "workloadIdentityPools/castor-gh-pool/providers/github-provider")
        self.assertEqual(secrets["WIF_SERVICE_ACCOUNT"], f"sa-gh-deployer@{res['project_id']}.iam.gserviceaccount.com")
        stream.assert_called_once_with("r1wif-app", "example-org/r1wif-app")

    def test_r1wif_repository_named_by_another_workload_keeps_the_suffixed_names(self):
        """Do No Harm: GitHub names compare case-insensitively; a dict-shaped record counts too."""
        for other in ({"github_repo": "Example-Org/R1WIF-App"}, {"github_repo": {"full_name": "example-org/r1wif-app"}}):
            secrets, _res, _ = self._r1wif_redeploy(
                {"product_id": "r1wif-app-stage", "github_repo": "example-org/r1wif-app", "default_branch": "stage"},
                others=[("r1wif-app", other)])
            self.assertEqual(set(secrets), {"GCP_PROJECT_ID_STAGE", "WIF_PROVIDER_STAGE", "WIF_SERVICE_ACCOUNT_STAGE"})

    def _r1wif_default_repo(self, pid):
        return project_vending.resolve_repo_identity(None, default_owner=self.vending_engine.github_owner,
                                                     product_id=pid)[2]

    def test_r1wif_sibling_without_github_repo_is_its_default_repository(self):
        """RT F1: a sibling record with no github_repo (None / "" / missing) is resolved to its default repository
        <owner>/<pid>, like the redeploying record; when that is this workload's repository the names stay suffixed."""
        repo = self._r1wif_default_repo("other-app")
        for sibling in ({}, {"github_repo": None}, {"github_repo": ""}):
            secrets, _res, spy = self._r1wif_redeploy(
                {"product_id": "r1wif-app", "github_repo": repo, "default_branch": "develop"},
                others=[("other-app", sibling)])
            self.assertEqual(set(secrets), {"GCP_PROJECT_ID_DEVELOP", "WIF_PROVIDER_DEVELOP",
                                            "WIF_SERVICE_ACCOUNT_DEVELOP"}, sibling)
            spy.assert_called_once_with("r1wif-app", repo)

    def test_r1wif_sibling_without_github_repo_elsewhere_leaves_the_plain_names(self):
        """RT F1 Do No Harm: a sibling without the field whose default repository is another one does not make this
        workload's own repository shared."""
        own = self._r1wif_default_repo("r1wif-app")
        secrets, _res, _spy = self._r1wif_redeploy(
            {"product_id": "r1wif-app", "github_repo": own, "default_branch": "develop"},
            others=[("other-app", {}), ("third-app", {"github_repo": None})])
        self.assertEqual(set(secrets), self._PLAIN)

    def test_r1wif_unreadable_records_keep_the_suffixed_names(self):
        secrets, _res, _ = self._r1wif_redeploy(
            {"product_id": "r1wif-app", "github_repo": "example-org/r1wif-app", "default_branch": "develop"},
            stream_error=RuntimeError("firestore down"))
        self.assertEqual(set(secrets), {"GCP_PROJECT_ID_DEVELOP", "WIF_PROVIDER_DEVELOP", "WIF_SERVICE_ACCOUNT_DEVELOP"})

    def test_r1wif_promoted_workload_keeps_the_suffixed_names(self):
        secrets, _res, stream = self._r1wif_redeploy(
            {"product_id": "r1wif-app-prod", "github_repo": "example-org/r1wif-app", "default_branch": "prod",
             "promoted_from_product_id": "r1wif-app"})
        self.assertEqual(set(secrets), {"GCP_PROJECT_ID_PROD", "WIF_PROVIDER_PROD", "WIF_SERVICE_ACCOUNT_PROD"})
        stream.assert_not_called()   # promoted: shared by definition, nothing else is read

    def test_gha_switch_off_redeploy_writes_no_deploy_secrets(self):
        """GHA-DEPLOY-SWITCH: a workload whose GitHub Actions deploy switch is off (or holds an invalid value) has no
        WIF pool / provider / sa-gh-deployer, so its redeploy writes no deploy secrets; the deploy still runs."""
        for value in (False, "false"):
            doc = MagicMock()
            doc.exists = True
            doc.to_dict.return_value = {"product_id": "r1wif-app", "github_repo": "example-org/r1wif-app",
                                        "default_branch": "main", "status": "DECOMMISSIONED",
                                        "folder_id": "folders/123456789012", "github_actions_deploy": value}
            self.mock_db.collection().document().get.return_value = doc
            with patch.object(self.vending_engine, "vend_gcp_project", return_value={"project_id": "r1wif-new"}), \
                 patch.object(self.vending_engine, "_update_github_secrets", return_value=True) as upd, \
                 patch("httpx.Client") as mock_httpx, \
                 patch.object(project_vending, "_fetch_id_token", return_value=None), \
                 patch.dict(os.environ, {"TERRAFORM_SERVICE_URL": "http://terraform-svc"}):
                mock_httpx.return_value.__enter__.return_value.post.return_value = MagicMock(
                    status_code=200, json=lambda: {"service_url": "https://r1wif.run.app"})
                res = self.vending_engine.redeploy_workload(product_id="r1wif-app",
                                                            operator_email="admin@castor.internal")
            upd.assert_not_called()
            mock_httpx.return_value.__enter__.return_value.post.assert_called_once()
            self.assertEqual(res["status"], "ACTIVE")

    def _oq15_vend(self, record):
        doc = MagicMock()
        doc.exists = True
        doc.to_dict.return_value = dict(record)
        self.mock_db.collection().document().get.return_value = doc
        self.mock_db.collection().document().set.reset_mock()
        with patch.object(self.vending_engine, "vend_gcp_project", return_value={"project_id": "shop-prod-1a2b3c"}), \
             patch.object(self.vending_engine, "vend_github_repo", return_value={"full_name": "example-org/shop"}), \
             patch.object(self.vending_engine, "_next_repo_identity", return_value=None), \
             patch.object(self.vending_engine, "_update_github_secrets", return_value=True) as upd:
            res = self.vending_engine.vend_all(product_id="shop-prod", trace_id="t-oq15")
        writes = [c[0][0] for c in self.mock_db.collection().document().set.call_args_list]
        return res, upd, writes

    def test_oq15_first_vend_of_a_promoted_workload_writes_its_branch_named_secrets(self):
        """OQ-15 (owner 10-31): vending writes a promoted workload's branch-named deploy secrets at its first vend,
        through redeploy's code path, and records the project they were written for."""
        promoted = {"product_id": "shop-prod", "github_repo": "example-org/shop", "default_branch": "prod",
                    "promoted_from_product_id": "shop"}
        res, upd, writes = self._oq15_vend(promoted)
        self.assertEqual(res["status"], "WORKLOAD_VENDED")
        upd.assert_called_once()
        repo, secrets = upd.call_args[0]
        self.assertEqual(repo, "example-org/shop")
        self.assertEqual(secrets, {
            "GCP_PROJECT_ID_PROD": "shop-prod-1a2b3c",
            "WIF_PROVIDER_PROD": "projects/shop-prod-1a2b3c/locations/global/workloadIdentityPools/castor-gh-pool/"
                                 "providers/github-provider",
            "WIF_SERVICE_ACCOUNT_PROD": "sa-gh-deployer@shop-prod-1a2b3c.iam.gserviceaccount.com"})
        self.assertTrue(any(w.get(project_vending.PROMOTION_DEPLOY_SECRETS_FIELD) == "shop-prod-1a2b3c"
                            for w in writes))
        # RT14-LIFECYCLE-ASYNC RT item 2: the write that records the secrets also clears an earlier typed error
        self.assertTrue(any(w.get(project_vending.PROMOTION_DEPLOY_SECRETS_FIELD) == "shop-prod-1a2b3c"
                            and w.get(project_vending.DEPLOY_SECRETS_ERROR_FIELD)
                            is project_vending.firestore.DELETE_FIELD for w in writes))

    def test_oq15_later_vends_and_other_workloads_write_no_secrets(self):
        """Do No Harm: a later vend of the same promoted project, a workload that is not promoted, and a promoted
        workload whose GitHub Actions deploy switch is off write no secrets (as before)."""
        base = {"product_id": "shop-prod", "github_repo": "example-org/shop", "default_branch": "prod",
                "promoted_from_product_id": "shop"}
        for record in (dict(base, **{project_vending.PROMOTION_DEPLOY_SECRETS_FIELD: "shop-prod-1a2b3c"}),
                       {"product_id": "shop-prod", "github_repo": "example-org/shop-prod", "default_branch": "main"},
                       dict(base, github_actions_deploy=False)):
            res, upd, writes = self._oq15_vend(record)
            self.assertEqual(res["status"], "WORKLOAD_VENDED")
            upd.assert_not_called()
            self.assertFalse(any(project_vending.PROMOTION_DEPLOY_SECRETS_FIELD in w for w in writes), record)

    def test_oq15_a_failed_write_is_not_recorded(self):
        promoted = {"product_id": "shop-prod", "github_repo": "example-org/shop", "default_branch": "prod",
                    "promoted_from_product_id": "shop"}
        doc = MagicMock()
        doc.exists = True
        doc.to_dict.return_value = dict(promoted)
        self.mock_db.collection().document().get.return_value = doc
        self.mock_db.collection().document().set.reset_mock()
        with patch.object(self.vending_engine, "vend_gcp_project", return_value={"project_id": "shop-prod-1a2b3c"}), \
             patch.object(self.vending_engine, "_next_repo_identity", return_value=None), \
             patch.object(self.vending_engine, "_update_github_secrets", return_value=False):
            res = self.vending_engine.vend_all(product_id="shop-prod", trace_id="t-oq15")
        self.assertEqual(res["status"], "WORKLOAD_VENDED")
        writes = [c[0][0] for c in self.mock_db.collection().document().set.call_args_list]
        self.assertFalse(any(project_vending.PROMOTION_DEPLOY_SECRETS_FIELD in w for w in writes))

    def test_r1wif_shared_branch_names_use_the_shared_suffix_rule(self):
        """FD-4CI-b-R1-WIF-SHARED: `-` / `/` / `.` map to `_` (shared.github_identity.branch_secret_suffix, the rule
        the generated workflow reads with)."""
        secrets, _res, _ = self._r1wif_redeploy(
            {"product_id": "r1wif-app-rc", "github_repo": "example-org/r1wif-app", "default_branch": "release/v1.2-rc",
             "promoted_from_product_id": "r1wif-app"})
        self.assertEqual(set(secrets), {"GCP_PROJECT_ID_RELEASE_V1_2_RC", "WIF_PROVIDER_RELEASE_V1_2_RC",
                                        "WIF_SERVICE_ACCOUNT_RELEASE_V1_2_RC"})

    def test_r1wif_main_branch_names_unchanged_and_no_extra_read(self):
        """Do No Harm: main (recorded, or no record) writes the plain names exactly as before, with no records scan."""
        for record in ({"product_id": "r1wif-app", "github_repo": "example-org/r1wif-app", "default_branch": "main"},
                       {"product_id": "r1wif-app", "github_repo": "example-org/r1wif-app"}):
            secrets, _res, stream = self._r1wif_redeploy(record, others=[("r1wif-x", {"github_repo": "example-org/r1wif-app"})])
            self.assertEqual(set(secrets), self._PLAIN)
            stream.assert_not_called()


MANAGED_ROOT = "111111111111"  # lane 4 FD-4AY / H9: the managed root comes only from MANAGED_WORKLOADS_FOLDER_ID


def _managed_folder_env(test):
    """Lane 4 (register L4-g/L4-n/L4-o): root folder and vending URL are configuration; containment is checked with a
    CRM v3 parent walk, faked here so every numeric folder below is a direct child of the managed root."""
    env = patch.dict(os.environ, {"MANAGED_WORKLOADS_FOLDER_ID": MANAGED_ROOT,
                                  "VENDING_SERVICE_URL": "https://vending-svc.a.run.app"})
    env.start()
    test.addCleanup(env.stop)
    walk = patch.object(sys.modules["folders"], "_default_get_folder",
                        lambda name: {"name": name, "parent": f"folders/{MANAGED_ROOT}"})
    walk.start()
    test.addCleanup(walk.stop)


def _maintenance_off(test):
    """settings-toggles: deploy-to-folder reads maintenance mode strictly before any side effect; these tests run with
    valid settings and maintenance off (the mocked Firestore module cannot serve a settings document)."""
    wl = sys.modules["routes.workloads"]
    off = patch.object(wl, "get_platform_settings", return_value=shared_settings.PlatformSettings())
    off.start()
    test.addCleanup(off.stop)


class TestControlCenterFolderEndpoints(unittest.TestCase):
    """Tests Control Center backend endpoints for folder hierarchy management and RBAC."""

    def setUp(self):
        self.mock_db = MagicMock()
        cc_main.db = self.mock_db
        _managed_folder_env(self)

    def test_list_folders_endpoint(self):
        doc1 = MagicMock()
        doc1.to_dict.return_value = {
            "folder_id": "folders/111",
            "folder_number": "111",  # FD-05 B-5
            "display_name": "Dev",
            "is_default": True,
            "status": "ACTIVE",
        }
        doc2 = MagicMock()
        doc2.to_dict.return_value = {
            "folder_id": "folders/222",
            "folder_number": "222",  # FD-05 B-5
            "display_name": "Prod",
            "is_default": False,
            "status": "ACTIVE",
        }
        self.mock_db.collection("managed_folders").stream.return_value = [doc1, doc2]

        mock_request = MagicMock()
        folders = cc_main.list_managed_folders_api(mock_request)
        self.assertEqual(len(folders), 2)
        self.assertEqual(folders[0].display_name, "Dev")
        self.assertTrue(folders[0].is_default)
        self.assertEqual(folders[1].display_name, "Prod")

    def test_create_folder_endpoint_admin_allowed(self):
        req_obj = cc_schemas.CreateFolderRequest(
            display_name="Engineering Dev",
            parent_folder_id=f"folders/{MANAGED_ROOT}",
            description="Main dev sandbox",
        )
        mock_request = MagicMock()
        mock_request.state.user_role = cc_schemas.UserRole.ADMIN
        mock_request.state.user_email = "admin@castor.internal"

        # Mock document doesn't exist yet
        mock_doc_ref = MagicMock()
        self.mock_db.collection("managed_folders").document.return_value = mock_doc_ref

        # Lane 4 (L4-o): the folder comes from the vending service; no fake folder record is ever written.
        vending_resp = MagicMock(status_code=200)
        vending_resp.json.return_value = {"folder_id": "folders/555444333", "folder_number": "555444333"}
        with patch.object(cc_main, "make_vending_request", return_value=vending_resp):
            created = cc_main.create_managed_folder_api(req_obj, mock_request)
        self.assertTrue(created.folder_id.startswith("folders/"))
        self.assertEqual(created.display_name, "Engineering Dev")
        mock_doc_ref.set.assert_called_once()

    def test_vending_url_auto_discovery_from_request_host(self):
        """Lane 4 / lane-5 rule (register L4-o): the vending URL is NEVER derived from Host / X-Forwarded-Host; with
        VENDING_SERVICE_URL unset the lookup fails closed (None)."""
        cc_main._CACHED_VENDING_SERVICE_URL = None
        mock_req = MagicMock()
        mock_req.headers = {"host": "product-control-center-ui-test-uc.a.run.app"}
        mock_req.url.hostname = "product-control-center-ui-test-uc.a.run.app"
        with patch.dict(os.environ, {}, clear=False):
            if "VENDING_SERVICE_URL" in os.environ:
                del os.environ["VENDING_SERVICE_URL"]
            url = cc_main.get_vending_service_url(mock_req)
            self.assertIsNone(url)

    def test_make_vending_request_injects_bearer_auth(self):
        """make_vending_request should inject Google OIDC ID token in Authorization header."""
        mock_httpx = MagicMock()
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client.request.return_value = mock_resp
        mock_httpx.Client.return_value.__enter__.return_value = mock_client
        with patch.object(cc_main, "get_vending_service_url", return_value="https://vending-svc.a.run.app"), \
             patch.object(cc_main, "get_google_id_token", return_value="test-oidc-id-token-xyz"), \
             patch.dict(sys.modules, {"httpx": mock_httpx}):

            resp = cc_main.make_vending_request("POST", "/folders", {"display_name": "Test"})
            self.assertEqual(resp, mock_resp)
            mock_client.request.assert_called_once()
            called_args = mock_client.request.call_args
            self.assertEqual(called_args[1]["headers"]["Authorization"], "Bearer test-oidc-id-token-xyz")
            self.assertEqual(called_args[1]["url"], "https://vending-svc.a.run.app/folders")

    def test_create_folder_endpoint_invokes_vending_and_saves_gcp_id(self):
        """create_managed_folder_api should call Vending Service and record real GCP folder in Firestore."""
        req_obj = cc_schemas.CreateFolderRequest(
            display_name="Marketing Production",
            parent_folder_id=f"folders/{MANAGED_ROOT}",
            description="Live marketing workloads",
        )
        mock_request = MagicMock()
        mock_request.state.user_role = cc_schemas.UserRole.ADMIN
        mock_request.state.user_email = "admin@castor.internal"
        mock_request.headers = {"host": "product-control-center-ui-test-uc.a.run.app"}

        mock_doc_ref = MagicMock()
        self.mock_db.collection("managed_folders").document.return_value = mock_doc_ref

        mock_vending_resp = MagicMock()
        mock_vending_resp.status_code = 200
        mock_vending_resp.json.return_value = {
            "status": "SUCCESS",
            "folder_id": "folders/999888777",
            "folder_number": "999888777",
            "display_name": "Marketing Production",
        }

        with patch.object(cc_main, "make_vending_request", return_value=mock_vending_resp) as mock_vend_req:
            created = cc_main.create_managed_folder_api(req_obj, mock_request)
            self.assertEqual(created.folder_id, "folders/999888777")
            self.assertEqual(created.folder_number, "999888777")
            self.assertEqual(created.display_name, "Marketing Production")

            # Verify Firestore saved the real GCP folder ID
            self.mock_db.collection("managed_folders").document.assert_called_with("folders_999888777")
            mock_doc_ref.set.assert_called_once()

    @patch.dict(os.environ)
    def test_create_folder_endpoint_forbidden_for_non_admin(self):
        # verify_admin_access is a no-op under TEST_MODE; exercise the production RBAC path.
        os.environ.pop("TEST_MODE", None)
        req_obj = cc_schemas.CreateFolderRequest(display_name="Unauthorized Folder")
        mock_request = MagicMock()
        mock_request.state.user_role = cc_schemas.UserRole.WORKLOAD_MANAGER
        mock_request.state.user_email = "manager@castor.internal"

        with self.assertRaises(MockHTTPException) as ctx:
            cc_main.create_managed_folder_api(req_obj, mock_request)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_set_default_folder_endpoint_admin(self):
        mock_request = MagicMock()
        mock_request.state.user_role = cc_schemas.UserRole.ADMIN
        mock_request.state.user_email = "admin@castor.internal"

        # Mock existing folders stream to find target and clear old default
        target_doc = MagicMock()
        target_doc.id = "folders_target123"
        target_doc.to_dict.return_value = {"folder_id": "folders/target123", "display_name": "Target"}

        existing_default = MagicMock()
        existing_default.id = "folders_old"
        existing_default.to_dict.return_value = {"folder_id": "folders/old-default", "is_default": True}
        self.mock_db.collection("managed_folders").stream.return_value = [existing_default, target_doc]

        res = cc_main.set_default_managed_folder_api("folders/target123", mock_request)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["default_folder_id"], "folders/target123")

    def test_disable_folder_endpoint_admin(self):
        mock_request = MagicMock()
        mock_request.state.user_role = cc_schemas.UserRole.ADMIN
        mock_request.state.user_email = "admin@castor.internal"

        # No active workloads in folder
        self.mock_db.collection("workloads").where().stream.return_value = []

        target_doc_ref = MagicMock()
        target_doc = MagicMock()
        target_doc.exists = True
        target_doc_ref.get.return_value = target_doc
        self.mock_db.collection("managed_folders").document.return_value = target_doc_ref

        res = cc_main.delete_managed_folder_api("folders/target123", mock_request)
        self.assertEqual(res["status"], "SUCCESS")
        target_doc_ref.set.assert_called_once()


class TestBranchBackedFolderPromotion(unittest.TestCase):
    """Tests POST /api/workloads/{product_id}/deploy-to-folder."""

    def setUp(self):
        self.mock_db = MagicMock()
        cc_main.db = self.mock_db
        _managed_folder_env(self)
        _maintenance_off(self)

    def test_deploy_to_folder_success(self):
        mock_request = MagicMock()
        mock_request.state.user_role = cc_schemas.UserRole.ADMIN
        mock_request.state.user_email = "admin@castor.internal"

        # Mock source workload doc in Firestore
        source_doc = MagicMock()
        source_doc.exists = True
        source_doc.to_dict.return_value = {
            "product_id": "inventory-api",
            "project_id": "castor-inventory-api-dev",
            "status": "ACTIVE",
            "github_repo": "example-org/inventory-api",
            "default_branch": "main",
            "budget_ceiling_monthly_usd": 50.0,
        }

        # Mock target workload does not exist
        target_doc = MagicMock()
        target_doc.exists = False

        def doc_side_effect(doc_id):
            mock_ref = MagicMock()
            if doc_id == "inventory-api":
                mock_ref.get.return_value = source_doc
            elif doc_id == "inventory-api-prod":
                mock_ref.get.return_value = target_doc
            elif doc_id == "folders_222222222222":
                f_doc = MagicMock()
                f_doc.exists = True
                f_doc.to_dict.return_value = {"display_name": "Production"}
                mock_ref.get.return_value = f_doc
            else:
                generic = MagicMock()
                generic.get.return_value = MagicMock(exists=False)
                return generic
            return mock_ref

        self.mock_db.collection("workloads").document.side_effect = doc_side_effect
        self.mock_db.collection("managed_folders").document.side_effect = doc_side_effect

        req = cc_schemas.DeployToFolderRequest(
            destination_folder_id="folders/222222222222",
            new_product_id="inventory-api-prod",
            target_branch="production",
            copy_feature_requests=False,
        )

        with patch.object(cc_main, "create_or_verify_branch") as mock_branch, \
             patch.object(cc_main, "get_pubsub_publisher", return_value=MagicMock()):

            summary = cc_main.deploy_workload_to_folder_endpoint("inventory-api", req, mock_request)

            mock_branch.assert_called_once_with(
                repo_full_name="example-org/inventory-api",
                branch_name="production",
                source_branch="main",
            )
            self.assertEqual(summary.product_id, "inventory-api-prod")
            self.assertEqual(summary.folder_id, "folders/222222222222")
            self.assertEqual(summary.folder_name, "Production")
            self.assertEqual(summary.default_branch, "production")
            self.assertLessEqual(len(summary.project_id), 30)

    def test_deploy_to_folder_long_product_id_within_30_chars(self):
        """deploy_workload_to_folder_endpoint must generate target_project_id <= 30 chars for long names."""
        mock_request = MagicMock()
        mock_request.state.user_role = cc_schemas.UserRole.ADMIN
        mock_request.state.user_email = "admin@castor.internal"

        source_doc = MagicMock(exists=True)
        source_doc.to_dict.return_value = {
            "product_id": "castorcloudruntest",
            "project_id": "castor-castorcloudrunte-5c73b3",
            "status": "ACTIVE",
            "github_repo": "example-org/castor-castorcloudruntest",
            "default_branch": "main",
        }
        target_doc = MagicMock(exists=False)

        def doc_side_effect(doc_id):
            mock_ref = MagicMock()
            if doc_id == "castorcloudruntest":
                mock_ref.get.return_value = source_doc
            elif doc_id == "castorcloudruntest-stage":
                mock_ref.get.return_value = target_doc
            else:
                mock_ref.get.return_value = MagicMock(exists=False)
            return mock_ref

        self.mock_db.collection("workloads").document.side_effect = doc_side_effect
        self.mock_db.collection("managed_folders").document.side_effect = doc_side_effect

        req = cc_schemas.DeployToFolderRequest(
            destination_folder_id="folders/123456789012",
            new_product_id="castorcloudruntest-stage",
            target_branch="stage",
        )

        with patch.object(cc_main, "create_or_verify_branch"), \
             patch.object(cc_main, "get_pubsub_publisher", return_value=MagicMock()):

            summary = cc_main.deploy_workload_to_folder_endpoint("castorcloudruntest", req, mock_request)
            self.assertLessEqual(len(summary.project_id), 30)
            self.assertTrue(summary.project_id.startswith("castorcloudruntest-stage"))

    def test_deploy_to_folder_conflict_if_target_exists(self):
        mock_request = MagicMock()
        mock_request.state.user_role = cc_schemas.UserRole.ADMIN
        mock_request.state.user_email = "admin@castor.internal"

        source_doc = MagicMock(exists=True)
        source_doc.to_dict.return_value = {"status": "ACTIVE", "github_repo": "test/repo"}
        target_doc = MagicMock(exists=True)

        def doc_side_effect(doc_id):
            mock_ref = MagicMock()
            if doc_id == "src":
                mock_ref.get.return_value = source_doc
            elif doc_id == "existing-target":
                mock_ref.get.return_value = target_doc
            return mock_ref

        self.mock_db.collection("workloads").document.side_effect = doc_side_effect

        req = cc_schemas.DeployToFolderRequest(
            destination_folder_id="folders/123",
            new_product_id="existing-target",
            target_branch="prod",
        )

        with self.assertRaises(MockHTTPException) as ctx:
            cc_main.deploy_workload_to_folder_endpoint("src", req, mock_request)
        self.assertEqual(ctx.exception.status_code, 409)


class TestDriveSpecTargetFolderWaterfall(unittest.TestCase):
    """Tests 4-tier target GCP folder resolution in spec-ingestion poller.
    FD-4AS (owner 10-20): every tier must resolve to an active managed_folders document (exact folder_id; names by
    whole-name casefold, unique); a tag / property / assignment that is not managed is rejected (no fallthrough)."""

    def setUp(self):
        self.mock_db = MagicMock()
        self.mock_drive = MagicMock()
        self.poller = spec_poller.SpecIngestionPoller(
            drive_service=self.mock_drive,
            firestore_client=self.mock_db,
            publisher_client=MagicMock(),
        )

    def _managed(self, *records):
        docs = []
        for r in records:
            d = MagicMock()
            d.to_dict.return_value = r
            docs.append(d)
        self.mock_db.collection("managed_folders").stream.return_value = docs

    def test_tier_1_explicit_tag_in_title(self):
        doc = {
            "name": "[folder: folders/998877] Customer Portal API Spec",
            "description": "Tech spec",
        }
        self._managed({"display_name": "Portal", "folder_id": "folders/998877"})
        res = self.poller.resolve_target_folder(doc)
        self.assertEqual(res, "folders/998877")

    def test_tier_1_unmanaged_tag_is_rejected_not_routed(self):
        doc = {"name": "[folder: folders/998877] Customer Portal API Spec", "description": "Tech spec"}
        self._managed({"display_name": "Default", "folder_id": "folders/1", "is_default": True})
        with self.assertRaises(spec_poller.IntakeRejected) as ctx:
            self.poller.resolve_target_folder(doc)
        self.assertEqual(ctx.exception.code, "TARGET_FOLDER_NOT_MANAGED")

    def test_tier_1_display_name_tag_resolved_in_firestore(self):
        doc = {
            "name": "Customer Portal Spec [target_folder: Finance]",
            "description": "",
        }
        self._managed({"display_name": "Finance", "folder_id": "folders/444555"})

        res = self.poller.resolve_target_folder(doc)
        self.assertEqual(res, "folders/444555")

    def test_tier_2_author_assigned_folder(self):
        doc = {
            "name": "Billing Service Spec",
            "owners": [{"emailAddress": "lead@company.com"}],
        }
        user_doc = MagicMock()
        user_doc.exists = True
        user_doc.to_dict.return_value = {"assigned_folder_id": "folders/111"}
        self.mock_db.collection("users").document("lead@company.com").get.return_value = user_doc
        self._managed({"display_name": "Billing", "folder_id": "folders/111"})

        res = self.poller.resolve_target_folder(doc)
        self.assertEqual(res, "folders/111")

    def test_tier_3_drive_parent_folder_name_match(self):
        doc = {
            "name": "General Analytics Engine Spec",
            "owners": [],
        }
        self.mock_drive.files().get().execute.return_value = {"name": "Data Engineering"}
        self._managed({"display_name": "Data Engineering", "folder_id": "folders/222"})

        res = self.poller.resolve_target_folder(doc, parent_drive_folder_id="drive-folder-abc")
        self.assertEqual(res, "folders/222")

    def test_tier_4_platform_default_fallback(self):
        doc = {
            "name": "Uncategorized Workload Spec",
            "owners": [],
        }
        self._managed({"folder_id": "folders/999", "is_default": True})

        res = self.poller.resolve_target_folder(doc, parent_drive_folder_id=None)
        self.assertEqual(res, "folders/999")


if __name__ == "__main__":
    unittest.main()
