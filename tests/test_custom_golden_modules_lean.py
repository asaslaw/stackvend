"""
Project Castor: Unit & Integration Tests for Enterprise Custom Golden Modules Catalog (Lean Phase 1)
Tests:
- In-memory HCL AST/regex contract inspector (shared/module_inspector.py)
- GitHub REST Contents API inspector (shared/module_inspector.py)
- Control Center Admin RBAC and CRUD endpoints (apps/control-center/routes/settings.py)
- Developer Agent contract inspector & module vendoring (contract_inspector.py & terraform_engine.py)
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
cc_dir = os.path.join(repo_root, "apps", "control-center")
og_dir = os.path.join(repo_root, "apps", "orchestrator-gateway")

if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
if cc_dir not in sys.path:
    sys.path.append(cc_dir)
if og_dir not in sys.path:
    sys.path.append(og_dir)

# Mock external cloud clients and frameworks before imports if needed
for mod in [
    "google", "google.auth", "google.auth.transport", "google.auth.transport.requests",
    "google.oauth2", "google.oauth2.id_token", "googleapiclient", "google.cloud",
    "google.cloud.firestore", "google.cloud.storage", "google.cloud.logging",
    "google.cloud.logging_v2", "google.cloud.pubsub_v1", "starlette", "starlette.middleware",
    "starlette.middleware.base"
]:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

# Mock FastAPI
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
mock_fastapi.APIRouter = lambda *args, **kwargs: mock_app
mock_fastapi.Request = MagicMock
mock_fastapi.Response = MagicMock
sys.modules["fastapi"] = mock_fastapi

mock_responses = MagicMock()
mock_responses.HTMLResponse = MagicMock
mock_responses.JSONResponse = MagicMock
mock_responses.RedirectResponse = MagicMock
sys.modules["fastapi.responses"] = mock_responses

# Mock Pydantic if not present
try:
    import pydantic
except ImportError:
    class MockFieldInfo:
        def __init__(self, default=None, default_factory=None):
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
                curr = getattr(self, k, None)
                if isinstance(curr, MockBaseModel) and isinstance(v, dict):
                    setattr(self, k, curr.__class__(**v))
                else:
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

# Load cc_schemas
_cc_schemas_spec = importlib.util.spec_from_file_location("cc_schemas", os.path.join(cc_dir, "schemas.py"))
cc_schemas = importlib.util.module_from_spec(_cc_schemas_spec)
sys.modules["schemas"] = cc_schemas
_cc_schemas_spec.loader.exec_module(cc_schemas)

# Now import shared and routes
from shared.module_inspector import (
    parse_hcl_variables_and_outputs,
    fetch_and_inspect_github_module,
)

# Load routes.settings
_cc_settings_spec = importlib.util.spec_from_file_location("routes_settings", os.path.join(cc_dir, "routes", "settings.py"))
routes_settings = importlib.util.module_from_spec(_cc_settings_spec)
sys.modules["routes.settings"] = routes_settings
_cc_settings_spec.loader.exec_module(routes_settings)

CustomGoldenModuleRecord = cc_schemas.CustomGoldenModuleRecord
CustomModuleSourceType = cc_schemas.CustomModuleSourceType
CustomModuleCategory = cc_schemas.CustomModuleCategory
RegisterCustomModuleRequest = cc_schemas.RegisterCustomModuleRequest
UpdateCustomModuleRequest = cc_schemas.UpdateCustomModuleRequest
UserRole = cc_schemas.UserRole


class TestHclModuleInspector(unittest.TestCase):
    def test_parse_hcl_variables_and_outputs(self):
        sample_variables_hcl = """
        variable "project_id" {
          description = "The target GCP project ID"
          type        = string
        }

        variable "network_name" {
          description = "The name of the VPC network to create"
          type        = string
          default     = "custom-prod-vpc"
        }

        variable "subnets" {
          description = "List of subnets"
          type        = list(object({
            name = string
            ip_cidr_range = string
            region = string
          }))
          default     = []
        }

        variable "enable_flow_logs" {
          type    = bool
          default = true
        }
        """

        sample_outputs_hcl = """
        output "network_id" {
          description = "The ID of the created VPC network"
          value       = google_compute_network.custom_vpc.id
        }

        output "subnets" {
          description = "Map of created subnetworks"
          value       = { for k, v in google_compute_subnetwork.subnets : k => v.id }
        }
        """

        hcl_files = {
            "variables.tf": sample_variables_hcl,
            "outputs.tf": sample_outputs_hcl,
        }

        variables, outputs = parse_hcl_variables_and_outputs(hcl_files)

        # Verify variables
        var_names = [v["name"] for v in variables]
        self.assertIn("project_id", var_names)
        self.assertIn("network_name", var_names)
        self.assertIn("subnets", var_names)
        self.assertIn("enable_flow_logs", var_names)

        # Verify variable details
        proj_var = next(v for v in variables if v["name"] == "project_id")
        self.assertEqual(proj_var["type"], "string")
        self.assertTrue(proj_var["required"])
        self.assertIsNone(proj_var["default"])
        self.assertEqual(proj_var["description"], "The target GCP project ID")

        net_var = next(v for v in variables if v["name"] == "network_name")
        self.assertEqual(net_var["type"], "string")
        self.assertFalse(net_var["required"])
        self.assertEqual(net_var["default"], "custom-prod-vpc")

        flow_var = next(v for v in variables if v["name"] == "enable_flow_logs")
        self.assertEqual(flow_var["type"], "bool")
        self.assertFalse(flow_var["required"])
        self.assertTrue(flow_var["default"])

        # Verify outputs
        out_names = [o["name"] for o in outputs]
        self.assertIn("network_id", out_names)
        self.assertIn("subnets", out_names)

        net_out = next(o for o in outputs if o["name"] == "network_id")
        self.assertEqual(net_out["description"], "The ID of the created VPC network")

    def test_parse_hcl_fallback_to_main_tf(self):
        sample_main_hcl = """
        variable "cluster_name" {
          description = "GKE cluster name"
          type        = string
        }

        output "endpoint" {
          description = "GKE master endpoint"
          value       = google_container_cluster.primary.endpoint
        }
        """
        hcl_files = {"main.tf": sample_main_hcl}
        variables, outputs = parse_hcl_variables_and_outputs(hcl_files)
        self.assertEqual(len(variables), 1)
        self.assertEqual(variables[0]["name"], "cluster_name")
        self.assertEqual(len(outputs), 1)
        self.assertEqual(outputs[0]["name"], "endpoint")

    @patch("shared.providers.github_provider.GitHubProvider")
    def test_fetch_and_inspect_github_module(self, mock_provider_cls):
        mock_provider = MagicMock()
        mock_provider_cls.return_value = mock_provider
        mock_provider.fetch_file_content.side_effect = lambda repo, path, branch: (
            'variable "bucket_name" {\n  description = "Target GCS bucket"\n  type = string\n}\n'
            if "variables.tf" in path else ""
        )

        variables, outputs = fetch_and_inspect_github_module(
            source_url="https://github.com/my-org/terraform-modules",
            repo_path="modules/storage-bucket",
            version_tag="v2.1.0",
        )

        self.assertEqual(len(variables), 1)
        self.assertEqual(variables[0]["name"], "bucket_name")
        self.assertEqual(variables[0]["type"], "string")


class TestCustomModulesEndpoints(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.mock_collection = MagicMock()
        self.mock_db.collection.return_value = self.mock_collection
        routes_settings.db = self.mock_db

    @patch.dict(os.environ)
    def test_admin_rbac_enforcement(self):
        # verify_admin_access is a no-op under TEST_MODE; exercise the production RBAC path.
        os.environ.pop("TEST_MODE", None)
        # Non-admin request (e.g. VIEWER or OPERATOR)
        non_admin_req = MagicMock()
        non_admin_req.state.user_role = UserRole.VIEWER
        non_admin_req.state.user_email = "viewer@enterprise.com"

        # 1. GET /api/settings/modules -> 403
        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.list_custom_modules_endpoint(non_admin_req)
        self.assertEqual(ctx.exception.status_code, 403)

        # 2. POST /api/settings/modules -> 403
        payload = RegisterCustomModuleRequest(
            module_id="test-mod",
            name="Test Module",
            source_type=CustomModuleSourceType.DIRECT_CODE,
            category=CustomModuleCategory.CUSTOM,
        )
        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.register_custom_module_endpoint(non_admin_req, payload)
        self.assertEqual(ctx.exception.status_code, 403)

        # 3. POST /api/settings/modules/{id}/sync -> 403
        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.sync_custom_module_endpoint(non_admin_req, "test-mod")
        self.assertEqual(ctx.exception.status_code, 403)

        # 4. DELETE /api/settings/modules/{id} -> 403
        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.delete_custom_module_endpoint(non_admin_req, "test-mod")
        self.assertEqual(ctx.exception.status_code, 403)

    def test_register_and_list_direct_code_module(self):
        mock_doc_ref = MagicMock()
        mock_doc_ref.get.return_value.exists = False
        self.mock_collection.document.return_value = mock_doc_ref

        admin_req = MagicMock()
        admin_req.state.user_role = UserRole.ADMIN
        admin_req.state.user_email = "architect@enterprise.com"

        reg_payload = RegisterCustomModuleRequest(
            module_id="hardened-vpc",
            name="Hardened Enterprise VPC",
            source_type=CustomModuleSourceType.DIRECT_CODE,
            category=CustomModuleCategory.NETWORKING,
            description="Custom PCI-DSS compliant VPC",
            override_builtin="vpc",
            is_heavy_stateful=False,
            hcl_files={
                "main.tf": 'resource "google_compute_network" "vpc" { name = var.network_name }',
                "variables.tf": 'variable "network_name" { type = string\n description = "VPC Name" }',
                "outputs.tf": 'output "network_id" { value = google_compute_network.vpc.id }',
            },
        )

        record = routes_settings.register_custom_module_endpoint(admin_req, reg_payload)
        self.assertEqual(record.module_id, "hardened-vpc")
        self.assertEqual(record.source_type, CustomModuleSourceType.DIRECT_CODE)
        self.assertEqual(record.override_builtin, "vpc")
        self.assertEqual(len(record.variables), 1)
        var_name = record.variables[0].name if hasattr(record.variables[0], "name") else record.variables[0]["name"]
        self.assertEqual(var_name, "network_name")
        self.assertEqual(len(record.outputs), 1)
        out_name = record.outputs[0].name if hasattr(record.outputs[0], "name") else record.outputs[0]["name"]
        self.assertEqual(out_name, "network_id")
        self.assertTrue(mock_doc_ref.set.called)

        # Test listing
        mock_doc_snap = MagicMock()
        mock_doc_snap.to_dict.return_value = record.model_dump()
        self.mock_collection.stream.return_value = [mock_doc_snap]

        resp = routes_settings.list_custom_modules_endpoint(admin_req)
        modules = resp.custom_modules if hasattr(resp, "custom_modules") else resp.modules
        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0].module_id, "hardened-vpc")

    # cc-module-inspector-parser: HCL python-hcl2 cannot read is never stored as an (empty or partial) contract.
    _BROKEN_HCL = {
        "main.tf": 'resource "google_compute_network" "vpc" { name = var.network_name }',
        "variables.tf": 'variable "network_name" {\n  type = string\n}\n\nvariable "broken" {\n  default = \n}\n',
    }

    def _admin(self):
        admin_req = MagicMock()
        admin_req.state.user_role = UserRole.ADMIN
        admin_req.state.user_email = "architect@enterprise.com"
        return admin_req

    def test_register_unparseable_hcl_is_rejected_and_not_stored(self):
        mock_doc_ref = MagicMock()
        mock_doc_ref.get.return_value.exists = False
        self.mock_collection.document.return_value = mock_doc_ref
        reg_payload = RegisterCustomModuleRequest(
            module_id="broken-vpc", name="Broken VPC", source_type=CustomModuleSourceType.DIRECT_CODE,
            category=CustomModuleCategory.NETWORKING, hcl_files=dict(self._BROKEN_HCL),
        )
        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.register_custom_module_endpoint(self._admin(), reg_payload)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("could not be parsed", ctx.exception.detail)
        mock_doc_ref.set.assert_not_called()

    def test_update_with_unparseable_hcl_is_rejected_and_not_stored(self):
        mock_doc_ref = MagicMock()
        mock_doc_ref.get.return_value.exists = True
        mock_doc_ref.get.return_value.to_dict.return_value = {
            "module_id": "corp-vpc", "name": "Corp VPC", "source_type": "DIRECT_CODE", "category": "NETWORKING",
            "hcl_files": {"variables.tf": 'variable "network_name" {\n  type = string\n}\n'},
            "inputs": [{"name": "network_name", "type": "string", "required": True}],
            "variables": [{"name": "network_name", "type": "string", "required": True}],
        }
        self.mock_collection.document.return_value = mock_doc_ref
        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.update_custom_module_endpoint(
                "corp-vpc", UpdateCustomModuleRequest(name="Renamed", hcl_files=dict(self._BROKEN_HCL)), self._admin())
        self.assertEqual(ctx.exception.status_code, 400)
        mock_doc_ref.set.assert_not_called()  # neither the new code nor the rename is written

    def test_sync_unparseable_hcl_marks_error_and_keeps_the_stored_contract(self):
        mock_doc_ref = MagicMock()
        mock_doc_ref.get.return_value.exists = True
        mock_doc_ref.get.return_value.to_dict.return_value = {
            "module_id": "corp-vpc", "name": "Corp VPC", "source_type": "DIRECT_CODE", "category": "NETWORKING",
            "hcl_files": dict(self._BROKEN_HCL),
            "inputs": [{"name": "network_name", "type": "string", "required": True}],
        }
        self.mock_collection.document.return_value = mock_doc_ref
        record = routes_settings.sync_custom_module_endpoint(self._admin(), "corp-vpc")
        self.assertEqual(record.sync_status, "ERROR")
        written = mock_doc_ref.set.call_args[0][0]
        self.assertEqual(written["sync_status"], "ERROR")
        self.assertNotIn("inputs", written)  # the last good contract is not overwritten with an empty one

    # Row CC-MI-2: if the built-in catalog itself cannot be built, PATCH / DELETE of a custom module are refused with a
    # clear 503 (it cannot be shown the id is not a built-in) and nothing is written; sync says why instead of 404.
    def test_update_and_delete_refused_cleanly_when_builtin_catalog_fails(self):
        mock_doc_ref = MagicMock()
        mock_doc_ref.get.return_value.exists = True
        self.mock_collection.document.return_value = mock_doc_ref
        with patch.object(routes_settings, "get_builtin_modules", side_effect=RuntimeError("catalog boom")):
            with self.assertRaises(MockHTTPException) as ctx:
                routes_settings.update_custom_module_endpoint(
                    "corp-vpc", UpdateCustomModuleRequest(name="Renamed"), self._admin())
            self.assertEqual(ctx.exception.status_code, 503)
            self.assertIn("catalog boom", ctx.exception.detail)
            with self.assertRaises(MockHTTPException) as ctx:
                routes_settings.delete_custom_module_endpoint(self._admin(), "corp-vpc")
            self.assertEqual(ctx.exception.status_code, 503)
        mock_doc_ref.set.assert_not_called()
        mock_doc_ref.delete.assert_not_called()

    def test_sync_reports_catalog_failure_instead_of_not_found(self):
        mock_doc_ref = MagicMock()
        mock_doc_ref.get.return_value.exists = False
        self.mock_collection.document.return_value = mock_doc_ref
        with patch.object(routes_settings, "get_builtin_modules", side_effect=RuntimeError("catalog boom")):
            with self.assertRaises(MockHTTPException) as ctx:
                routes_settings.sync_custom_module_endpoint(self._admin(), "storage-bucket")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertIn("catalog boom", ctx.exception.detail)
        # Do No Harm: with a healthy catalog an unknown id is still a plain 404
        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.sync_custom_module_endpoint(self._admin(), "no-such-module")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_sync_of_unreadable_builtin_returns_its_error_record(self):
        broken = {
            "module_id": "storage-bucket", "name": "Cloud Storage Bucket", "source_type": "BUILT_IN",
            "category": "STORAGE", "description": "", "is_builtin": True, "is_active": True,
            "sync_status": "ERROR", "error_message": "ModuleContractUnparseable: x", "created_by": "system",
            "inputs": [], "variables": [], "outputs": [], "hcl_files": {}, "overridden_by": None,
        }
        with patch.object(routes_settings, "get_builtin_modules", return_value=[broken]):
            record = routes_settings.sync_custom_module_endpoint(self._admin(), "storage-bucket")
        self.assertEqual(record.sync_status, "ERROR")
        self.assertIn("ModuleContractUnparseable", record.error_message)

    def test_delete_custom_module(self):
        mock_doc_ref = MagicMock()
        mock_doc_ref.get.return_value.exists = True
        self.mock_collection.document.return_value = mock_doc_ref

        admin_req = MagicMock()
        admin_req.state.user_role = UserRole.ADMIN
        admin_req.state.user_email = "architect@enterprise.com"

        res = routes_settings.delete_custom_module_endpoint(admin_req, "hardened-vpc")
        self.assertTrue(res.get("deleted"))
        self.assertTrue(mock_doc_ref.delete.called)

    def test_register_override_conflict_rejected(self):
        mock_doc_ref = MagicMock()
        mock_doc_ref.get.return_value.exists = False
        self.mock_collection.document.return_value = mock_doc_ref

        # Mock existing active module overriding storage-bucket
        mock_existing = MagicMock()
        mock_existing.id = "corp-bucket-1"
        mock_existing.to_dict.return_value = {"name": "Corp Bucket Primary", "override_builtin": "storage-bucket", "is_active": True}
        self.mock_collection.where.return_value.where.return_value.stream.return_value = [mock_existing]

        admin_req = MagicMock()
        admin_req.state.user_role = UserRole.ADMIN
        admin_req.state.user_email = "architect@enterprise.com"

        reg_payload = RegisterCustomModuleRequest(
            module_id="corp-bucket-2",
            name="Corp Bucket Secondary",
            source_type=CustomModuleSourceType.DIRECT_CODE,
            category=CustomModuleCategory.STORAGE,
            override_builtin="storage-bucket",
            hcl_files={"main.tf": 'resource "google_storage_bucket" "b" {}'},
        )

        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.register_custom_module_endpoint(admin_req, reg_payload)
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertIn("already actively overridden", ctx.exception.detail)


class TestRegisteredModulePublicExposure(unittest.TestCase):
    """FD-4CX: a registered module that grants public access by itself is refused at registration and on a code or
    ref update (nothing written), and marked ERROR (with the reason) on sync. Private modules are unchanged."""

    PUBLIC_HCL = {
        "main.tf": ('resource "google_cloud_run_v2_service_iam_member" "public" {\n  name   = var.name\n'
                    '  role   = "roles/run.invoker"\n  member = "allUsers"\n}\n'),
        "variables.tf": 'variable "name" {\n  type = string\n}\n',
    }
    PRIVATE_HCL = {
        "main.tf": 'resource "google_compute_network" "vpc" {\n  name = var.name\n}\n',
        "variables.tf": 'variable "name" {\n  type = string\n}\n',
    }

    def setUp(self):
        self.mock_db = MagicMock()
        self.mock_collection = MagicMock()
        self.mock_db.collection.return_value = self.mock_collection
        routes_settings.db = self.mock_db
        self.doc_ref = MagicMock()
        self.mock_collection.document.return_value = self.doc_ref

    def _admin(self):
        req = MagicMock()
        req.state.user_role = UserRole.ADMIN
        req.state.user_email = "architect@enterprise.com"
        return req

    def _register(self, **kw):
        self.doc_ref.get.return_value.exists = False
        payload = RegisterCustomModuleRequest(module_id="acme-run", name="Acme Run", category=CustomModuleCategory.COMPUTE,
                                              **kw)
        return routes_settings.register_custom_module_endpoint(self._admin(), payload)

    def _stored(self, **kw):
        self.doc_ref.get.return_value.exists = True
        self.doc_ref.get.return_value.to_dict.return_value = {
            "module_id": "acme-run", "name": "Acme Run", "category": "COMPUTE",
            "inputs": [{"name": "name", "type": "string", "required": True}], **kw}

    def test_direct_code_public_module_is_refused_and_not_stored(self):
        with self.assertRaises(MockHTTPException) as ctx:
            self._register(source_type=CustomModuleSourceType.DIRECT_CODE, hcl_files=dict(self.PUBLIC_HCL))
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("REGISTERED_MODULE_PUBLIC_EXPOSURE", ctx.exception.detail)
        self.assertIn('google_cloud_run_v2_service_iam_member.public member = "allUsers"', ctx.exception.detail)
        self.doc_ref.set.assert_not_called()

    def test_negative_direct_code_private_module_registers_as_before(self):
        record = self._register(source_type=CustomModuleSourceType.DIRECT_CODE, hcl_files=dict(self.PRIVATE_HCL))
        self.assertEqual(record.sync_status, "VERIFIED")
        self.assertTrue(self.doc_ref.set.called)

    def test_remote_git_module_is_checked_at_the_contract_ref(self):
        with patch.object(routes_settings, "fetch_and_inspect_github_module",
                          return_value=([{"name": "name", "type": "string", "required": True}], [])), \
                patch.object(routes_settings, "fetch_remote_module_files",
                             return_value={"modules/run/main.tf": self.PUBLIC_HCL["main.tf"]}) as fetch:
            with self.assertRaises(MockHTTPException) as ctx:
                self._register(source_type=CustomModuleSourceType.REMOTE_GIT, source_url="https://github.com/acme/m",
                               repo_path="modules/run", version_tag="v2.0.0")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("REGISTERED_MODULE_PUBLIC_EXPOSURE", ctx.exception.detail)
        fetch.assert_called_once_with("https://github.com/acme/m", "modules/run", "v2.0.0")
        self.doc_ref.set.assert_not_called()

    def test_remote_git_module_that_cannot_be_read_is_refused(self):
        with patch.object(routes_settings, "fetch_and_inspect_github_module", return_value=([], [])), \
                patch.object(routes_settings, "fetch_remote_module_files", side_effect=ValueError("tree truncated")):
            with self.assertRaises(MockHTTPException) as ctx:
                self._register(source_type=CustomModuleSourceType.REMOTE_GIT, source_url="https://github.com/acme/m")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("cannot be checked for public access", ctx.exception.detail)
        self.doc_ref.set.assert_not_called()

    def test_negative_remote_git_private_module_registers(self):
        with patch.object(routes_settings, "fetch_and_inspect_github_module", return_value=([], [])), \
                patch.object(routes_settings, "fetch_remote_module_files",
                             return_value={"main.tf": self.PRIVATE_HCL["main.tf"]}):
            record = self._register(source_type=CustomModuleSourceType.REMOTE_GIT, source_url="https://github.com/acme/m")
        self.assertEqual(record.module_id, "acme-run")
        self.assertTrue(self.doc_ref.set.called)

    def test_update_with_public_code_is_refused_and_nothing_written(self):
        self._stored(source_type="DIRECT_CODE", hcl_files=dict(self.PRIVATE_HCL))
        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.update_custom_module_endpoint(
                "acme-run", UpdateCustomModuleRequest(name="Renamed", hcl_files=dict(self.PUBLIC_HCL)), self._admin())
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("REGISTERED_MODULE_PUBLIC_EXPOSURE", ctx.exception.detail)
        self.doc_ref.set.assert_not_called()

    def test_update_of_a_remote_ref_checks_the_new_ref(self):
        self._stored(source_type="REMOTE_GIT", source_url="https://github.com/acme/m", repo_path="", version_tag="v1")
        with patch.object(routes_settings, "fetch_remote_module_files",
                          return_value={"main.tf": self.PUBLIC_HCL["main.tf"]}) as fetch:
            with self.assertRaises(MockHTTPException):
                routes_settings.update_custom_module_endpoint(
                    "acme-run", UpdateCustomModuleRequest(version_tag="v2"), self._admin())
        fetch.assert_called_once_with("https://github.com/acme/m", "", "v2")
        self.doc_ref.set.assert_not_called()

    def test_negative_metadata_update_of_an_existing_module_is_not_rechecked(self):
        """Do No Harm: a rename / activation of a module registered before FD-4CX writes as before (the build-time
        check stops a private workload from using it; sync reports it)."""
        self._stored(source_type="DIRECT_CODE", hcl_files=dict(self.PUBLIC_HCL))
        record = routes_settings.update_custom_module_endpoint(
            "acme-run", UpdateCustomModuleRequest(name="Renamed", is_active=True), self._admin())
        self.assertEqual(record.name, "Renamed")
        self.assertEqual(self.doc_ref.set.call_args[0][0], {"name": "Renamed", "is_active": True})

    def test_sync_of_a_public_module_marks_error_with_the_reason(self):
        self._stored(source_type="DIRECT_CODE", hcl_files=dict(self.PUBLIC_HCL))
        record = routes_settings.sync_custom_module_endpoint(self._admin(), "acme-run")
        self.assertEqual(record.sync_status, "ERROR")
        self.assertIn("REGISTERED_MODULE_PUBLIC_EXPOSURE", record.error_message)
        written = self.doc_ref.set.call_args[0][0]
        self.assertEqual(written["sync_status"], "ERROR")
        self.assertNotIn("inputs", written)

    def test_remote_git_read_refusal_is_typed_by_cause(self):
        """RT F4: a failed repository read is a retryable 503; a repository too large to read whole is a 400."""
        from shared.module_exposure import RemoteModuleReadError
        for transient, status in ((True, 503), (False, 400)):
            self.doc_ref.reset_mock()
            with patch.object(routes_settings, "fetch_and_inspect_github_module", return_value=([], [])), \
                    patch.object(routes_settings, "fetch_remote_module_files",
                                 side_effect=RemoteModuleReadError("cannot read", transient=transient)):
                with self.assertRaises(MockHTTPException) as ctx:
                    self._register(source_type=CustomModuleSourceType.REMOTE_GIT,
                                   source_url="https://github.com/acme/m")
            self.assertEqual(ctx.exception.status_code, status)
            self.doc_ref.set.assert_not_called()

    def test_sync_platform_defect_or_failed_read_is_503_and_nothing_written(self):
        """RT F6 / F4: a missing HCL parser or a failed repository read never marks the module ERROR."""
        from shared.module_exposure import ModuleExposureUnavailable, RemoteModuleReadError
        for err in (ModuleExposureUnavailable("python-hcl2 is not installed"),
                    RemoteModuleReadError("rate limited", transient=True)):
            self.doc_ref.reset_mock()
            self._stored(source_type="DIRECT_CODE", hcl_files=dict(self.PRIVATE_HCL))
            with patch.object(routes_settings, "check_registered_module", side_effect=err):
                with self.assertRaises(MockHTTPException) as ctx:
                    routes_settings.sync_custom_module_endpoint(self._admin(), "acme-run")
            self.assertEqual(ctx.exception.status_code, 503)
            self.doc_ref.set.assert_not_called()

    def test_sync_of_a_too_large_remote_repository_is_marked_error(self):
        from shared.module_exposure import RemoteModuleReadError
        self._stored(source_type="REMOTE_GIT", source_url="https://github.com/acme/m", repo_path="", version_tag="v1")
        with patch.object(routes_settings, "fetch_and_inspect_github_module", return_value=([], [])), \
                patch.object(routes_settings, "fetch_remote_module_files",
                             side_effect=RemoteModuleReadError("more files than 2,500", transient=False)):
            record = routes_settings.sync_custom_module_endpoint(self._admin(), "acme-run")
        self.assertEqual(record.sync_status, "ERROR")
        self.assertIn("2,500", record.error_message)

    def test_negative_sync_of_a_private_module_is_verified(self):
        self._stored(source_type="DIRECT_CODE", hcl_files=dict(self.PRIVATE_HCL))
        record = routes_settings.sync_custom_module_endpoint(self._admin(), "acme-run")
        self.assertEqual(record.sync_status, "VERIFIED")
        self.assertEqual(self.doc_ref.set.call_args[0][0]["sync_status"], "VERIFIED")


class TestDeveloperAgentIntegration(unittest.TestCase):
    def test_contract_inspector_includes_custom_modules(self):
        from developer_agent.contract_inspector import (
            get_all_active_module_contracts,
        )

        mock_firestore = sys.modules["google.cloud.firestore"]
        mock_client = MagicMock()
        mock_firestore.Client.return_value = mock_client
        mock_doc = MagicMock()
        mock_doc.id = "org-vault"
        mock_doc.to_dict.return_value = {
            "module_id": "org-vault",
            "name": "Enterprise HashiCorp Vault",
            "source_type": "DIRECT_CODE",
            "category": "SECURITY",
            "override_builtin": None,
            "description": "Custom HashiCorp Vault cluster",
            "inputs": [{"name": "vault_version", "type": "string", "required": False, "default": "1.15.0"}],
            "outputs": [{"name": "vault_addr", "description": "Vault internal URL"}],
        }
        mock_client.collection.return_value.where.return_value.stream.return_value = [mock_doc]

        mock_gc = MagicMock()
        mock_gc.firestore = mock_firestore
        sys.modules["google.cloud"] = mock_gc

        contracts_text = get_all_active_module_contracts()

        # Check that built-ins exist
        self.assertIn("workload-foundation/base", contracts_text)

        # Check custom module is present
        self.assertIn("Custom Enterprise Module Contract: `org-vault`", contracts_text)
        self.assertIn("vault_version", contracts_text)
        self.assertIn("vault_addr", contracts_text)

    def test_vendor_terraform_modules_custom_direct_code(self):
        from developer_agent.terraform_engine import (
            vendor_terraform_modules,
        )

        mock_firestore = sys.modules["google.cloud.firestore"]
        mock_client = MagicMock()
        mock_firestore.Client.return_value = mock_client
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "module_id": "custom-vpc",
            "source_type": "DIRECT_CODE",
            "hcl_files": {
                "main.tf": '# custom vpc hcl\nresource "google_compute_network" "custom" {}',
                "variables.tf": 'variable "foo" {}',
                "outputs.tf": 'output "bar" {}',
            },
        }
        mock_client.collection.return_value.document.return_value.get.return_value = mock_doc

        mock_gc = MagicMock()
        mock_gc.firestore = mock_firestore
        sys.modules["google.cloud"] = mock_gc

        files = {
            "infra/main.tf": 'module "vpc" {\n  source = "../modules/custom-vpc"\n}\n'
        }

        vendor_terraform_modules(files, "cloudrun")

        self.assertIn("infra/modules/custom-vpc/main.tf", files)
        self.assertIn("custom vpc hcl", files["infra/modules/custom-vpc/main.tf"])
        self.assertIn("infra/modules/custom-vpc/variables.tf", files)

    def test_builtin_modules_provider(self):
        from shared.builtin_modules_provider import get_builtin_modules
        modules = get_builtin_modules()
        self.assertGreaterEqual(len(modules), 19)
        
        # Verify storage-bucket
        bucket = next((m for m in modules if m["module_id"] == "storage-bucket"), None)
        self.assertIsNotNone(bucket)
        self.assertEqual(bucket["category"], "STORAGE")
        self.assertEqual(bucket["source_type"], "BUILT_IN")
        self.assertTrue(bucket["is_builtin"])
        self.assertFalse(bucket["is_heavy_stateful"])
        self.assertGreater(len(bucket["inputs"]), 0)

        # Verify database-cloudsql (heavy stateful)
        sql = next((m for m in modules if m["module_id"] == "database-cloudsql"), None)
        self.assertIsNotNone(sql)
        self.assertEqual(sql["category"], "DATABASE")
        self.assertTrue(sql["is_heavy_stateful"])
        self.assertEqual(sql["timeout_minutes"], 1440)

        # Verify networking-vpc
        vpc = next((m for m in modules if m["module_id"] == "networking-vpc"), None)
        self.assertIsNotNone(vpc)
        self.assertEqual(vpc["name"], "Enterprise VPC Network")
        self.assertEqual(vpc["category"], "NETWORKING")
        self.assertEqual(vpc["source_type"], "BUILT_IN")
        self.assertTrue(vpc["is_builtin"])
        self.assertFalse(vpc["is_heavy_stateful"])
        self.assertEqual(vpc["timeout_minutes"], 15)
        self.assertGreater(len(vpc["inputs"]), 0)
        self.assertGreater(len(vpc["outputs"]), 0)
        input_names = [inp["name"] for inp in vpc["inputs"]]
        self.assertIn("project_id", input_names)
        self.assertIn("network_name", input_names)
        self.assertIn("region", input_names)
        self.assertIn("additional_regions", input_names)
        self.assertIn("enable_nat", input_names)
        self.assertIn("enable_private_service_access", input_names)
        output_names = [out["name"] for out in vpc["outputs"]]
        self.assertIn("network_id", output_names)
        self.assertIn("primary_subnetwork_id", output_names)

        # Verify Glass Pane source code inspection files
        self.assertIn("hcl_files", vpc)
        self.assertIn("main.tf", vpc["hcl_files"])
        self.assertIn("variables.tf", vpc["hcl_files"])
        self.assertIn("outputs.tf", vpc["hcl_files"])
        self.assertIn("google_compute_network", vpc["hcl_files"]["main.tf"])
        self.assertIn("variable \"project_id\"", vpc["hcl_files"]["variables.tf"])
        self.assertIn("output \"network_id\"", vpc["hcl_files"]["outputs.tf"])

    def test_list_modules_includes_builtins_and_override_detection(self):
        admin_req = MagicMock()
        admin_req.state.user_role = UserRole.ADMIN
        admin_req.state.user_email = "architect@enterprise.com"

        # Mock custom module in Firestore overriding storage-bucket
        mock_custom = MagicMock()
        mock_custom.to_dict.return_value = {
            "module_id": "corp-secure-bucket",
            "name": "Corp Compliant Bucket",
            "source_type": "DIRECT_CODE",
            "category": "STORAGE",
            "description": "PCI-DSS compliant bucket",
            "override_builtin": "storage-bucket",
            "is_active": True,
            "inputs": [{"name": "bucket_name", "type": "string", "required": True}],
            "variables": [{"name": "bucket_name", "type": "string", "required": True}],
            "outputs": [{"name": "bucket_url"}],
        }
        routes_settings.db.collection.return_value.stream.return_value = [mock_custom]

        # List all modules
        resp = routes_settings.list_custom_modules_endpoint(admin_req)
        self.assertGreaterEqual(resp.builtin_modules_count, 19)
        self.assertEqual(resp.total_custom, 1)
        self.assertEqual(len(resp.custom_modules), 1)
        self.assertGreaterEqual(len(resp.modules), 20)

        # Verify storage-bucket is marked as overridden
        storage_mod = next(m for m in resp.modules if m.module_id == "storage-bucket")
        self.assertEqual(storage_mod.overridden_by, "Corp Compliant Bucket")

        # Verify built-in immutability (cannot delete or update native module)
        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.delete_custom_module_endpoint(admin_req, "storage-bucket")
        self.assertEqual(ctx.exception.status_code, 400)

        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.update_custom_module_endpoint("storage-bucket", UpdateCustomModuleRequest(name="Hacked"), admin_req)
        self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
