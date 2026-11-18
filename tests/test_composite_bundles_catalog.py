"""
Project Castor: Unit & Integration Tests for Composite Bundles Catalog & Guardrails (Milestone 37)
Tests:
- Built-in Enterprise Bundles Catalog (all 5 canonical bundles with manifests and files)
- Guardrail 3: Single-call recursive Git Trees API monorepo scanner (scan_repository_git_bundles)
- Guardrail 4: Atomic cascade re-vendoring (extract_vendored_bundles_from_files & _re_vendor_bundles_hook)
- Guardrail 5: Quota preflight resource footprint merging with spec overrides (estimate_bom_demand)
- Guardrail 6: Missing dependency fast-fail validation gate (fetch_and_inspect_git_bundle)
- Control Center REST API Endpoints: list, register, sync, toggle, scan, and built-in immutability
- Swarm Developer Agent: vendor_composite_bundle unpacking
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import json
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

# Mock external cloud clients and frameworks before imports
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

# Load routes.settings
_cc_settings_spec = importlib.util.spec_from_file_location("routes_settings", os.path.join(cc_dir, "routes", "settings.py"))
routes_settings = importlib.util.module_from_spec(_cc_settings_spec)
sys.modules["routes.settings"] = routes_settings
_cc_settings_spec.loader.exec_module(routes_settings)

from shared.bundle_schema import (
    CompositeBundleRecord,
    RegisterBundleRequest,
    ScanRepositoryBundlesRequest,
    DiscoveredBundleSummary,
    BundleDriftStatusResponse,
    UpdateBundleRequest,
)
from shared.builtin_bundles_payload import list_builtin_bundles, get_builtin_bundle
from shared.module_inspector import (
    parse_bundle_source_url,
    fetch_and_inspect_git_bundle,
    scan_repository_git_bundles,
)
from shared.iac_upgrade_engine import (
    extract_vendored_bundles_from_files,
    _re_vendor_bundles_hook,
)
from shared.quota_inspector import CloudQuotaInspector


class TestBuiltinCompositeBundles(unittest.TestCase):
    """Test suite for the 5 Canonical Enterprise Bundles."""

    def setUp(self):
        self.bundles = list_builtin_bundles()

    def test_all_five_bundles_present(self):
        expected_ids = {
            "secure-three-tier-web",
            "event-driven-microservice",
            "vertex-ai-rag-stack",
            "private-gke-microservices",
            "serverless-analytics-lakehouse",
        }
        actual_ids = {b.bundle_id for b in self.bundles}
        self.assertEqual(expected_ids, actual_ids)

    def test_bundle_structure_and_hcl_files(self):
        for record in self.bundles:
            self.assertTrue(record.is_builtin)
            self.assertTrue(record.is_active)
            self.assertIn("tofu", record.supported_engines)
            self.assertIn("terraform", record.supported_engines)
            
            # File validation
            files = record.hcl_files
            self.assertIn("main.tf", files)
            self.assertIn("variables.tf", files)
            self.assertIn("outputs.tf", files)

            # Modules included check
            self.assertGreaterEqual(len(record.modules_included), 1)

            # Resource footprint check
            self.assertGreater(len(record.resource_footprint), 0)
            self.assertIn("cpus", record.resource_footprint)
            self.assertIn("memory_gb", record.resource_footprint)


class TestGuardrailsAndInspector(unittest.TestCase):
    """Tests for Guardrails G3, G4, G5, and G6."""

    def test_guardrail_3_monorepo_git_trees_scanner(self):
        """G3: Single-call recursive Git Trees API monorepo scanner."""
        mock_provider = MagicMock()
        mock_provider.fetch_existing_repo_files.return_value = {
            "bundles/rag-pipeline/main.tf": 'module "endpoint" { source = "../modules/vertex-ai-endpoint" }',
            "bundles/rag-pipeline/variables.tf": 'variable "project_id" { type = string }',
            "bundles/rag-pipeline/outputs.tf": 'output "id" { value = "ok" }',
            "bundles/rag-pipeline/bundle.yaml": 'name: "Discovered RAG Pipeline"\ncategory: "AI_ML"',
            "docs/readme.md": '# Readme',
        }

        with patch("shared.vcs_provider.VCSProviderFactory.get_provider", return_value=mock_provider):
            discovered = scan_repository_git_bundles(
                source_url="https://github.com/acme/infra-monorepo",
                parent_path="bundles",
                version_tag="main",
            )

            self.assertEqual(len(discovered), 1)
            disc = discovered[0]
            self.assertEqual(disc["bundle_id"], "rag-pipeline")
            self.assertEqual(disc["repo_path"], "bundles/rag-pipeline")
            self.assertTrue(disc["has_manifest"])
            self.assertIn("endpoint", disc["modules_detected"])

    def test_guardrail_4_atomic_cascade_revendoring(self):
        """G4: Atomic cascade re-vendoring (bundle + underlying Golden Modules)."""
        existing_files = {
            "infra/main.tf": 'module "web" { source = "./infra/bundles/secure-three-tier-web" }',
            "infra/bundles/secure-three-tier-web/.castor-bundle.json": json.dumps({
                "bundle_id": "secure-three-tier-web",
                "version": "1.0.0",
                "modules_included": ["networking-vpc", "database-cloudsql"]
            }),
            "infra/bundles/secure-three-tier-web/main.tf": '# old bundle main.tf',
        }

        # 1. Test extraction
        vendored_bundles = extract_vendored_bundles_from_files(existing_files)
        self.assertIn("secure-three-tier-web", vendored_bundles)
        self.assertIn("main.tf", vendored_bundles["secure-three-tier-web"])

        # 2. Test re-vendoring hook
        re_vendored_details = _re_vendor_bundles_hook(existing_files, ["secure-three-tier-web"])
        
        # Check bundle files updated
        self.assertIn("infra/bundles/secure-three-tier-web/main.tf", existing_files)
        self.assertIn("infra/bundles/secure-three-tier-web/.castor-bundle.json", existing_files)
        # Check underlying golden module cascaded into infra/modules/
        self.assertIn("infra/modules/networking-vpc/main.tf", existing_files)
        self.assertIn("infra/modules/networking-vpc/.castor-module.json", existing_files)

    def test_guardrail_5_quota_footprint_preflight_with_overrides(self):
        """G5: Resource footprint extraction and merging with spec parameter overrides."""
        spec_overrides = {
            "bundle_id": "secure-three-tier-web",
            "parameters": {
                "min_instances": 4,  # Overrides default 1 instance -> 4 * 2 = 8 cpus
            }
        }

        inspector = CloudQuotaInspector()
        demand = inspector.estimate_bom_demand(spec_overrides)
        
        self.assertGreaterEqual(demand.get("compute.googleapis.com/cpus", 0), 8)
        self.assertGreaterEqual(demand.get("compute.googleapis.com/regional_external_ip_addresses", 0), 1)
        self.assertGreaterEqual(demand.get("sqladmin.googleapis.com/instances", 0), 1)

    def test_guardrail_6_missing_dependency_fast_fail_validation(self):
        """G6: Missing required golden module rejected during registration / inspection."""
        mock_provider = MagicMock()
        mock_provider.fetch_file_content.side_effect = lambda repo_id, path, branch: (
            'module "unknown" { source = "../modules/exotic-unapproved-module" }' if path.endswith("main.tf")
            else 'variable "project_id" {}' if path.endswith("variables.tf")
            else ""
        )

        with patch("shared.vcs_provider.VCSProviderFactory.get_provider", return_value=mock_provider):
            with self.assertRaises(ValueError) as ctx:
                fetch_and_inspect_git_bundle(
                    source_url="https://github.com/acme/infra",
                    repo_path="bundles/broken-bundle",
                    version_tag="main",
                    known_golden_modules=["networking-vpc", "storage-bucket"],
                )
            self.assertIn("Validation Error: Bundle references module 'exotic-unapproved-module'", str(ctx.exception))
            self.assertIn("does not exist in StackVend's Golden Modules catalog", str(ctx.exception))


class TestDeveloperAgentBundleVendoring(unittest.TestCase):
    """Tests Developer Agent unpacking bundles into infra/bundles/<bundle-id>/."""

    def test_vendor_composite_bundle_unpacking(self):
        from developer_agent.terraform_engine import vendor_composite_bundle

        files = {
            "infra/main.tf": 'module "web" { source = "./infra/bundles/secure-three-tier-web" }'
        }

        success = vendor_composite_bundle(files, "secure-three-tier-web")
        self.assertTrue(success)

        self.assertIn("infra/bundles/secure-three-tier-web/main.tf", files)
        self.assertIn("infra/bundles/secure-three-tier-web/variables.tf", files)
        self.assertIn("infra/bundles/secure-three-tier-web/outputs.tf", files)
        self.assertIn("infra/bundles/secure-three-tier-web/.castor-bundle.json", files)

        # Ensure child modules are cascaded
        self.assertIn("infra/modules/networking-vpc/main.tf", files)
        self.assertIn("infra/modules/database-cloudsql/main.tf", files)
        self.assertIn("infra/modules/compute-cloudrun/main.tf", files)


class TestControlCenterBundleEndpoints(unittest.TestCase):
    """Tests Control Center settings API routes for bundles."""

    def setUp(self):
        self.routes = routes_settings
        self.mock_db = MagicMock()
        self.routes.db = self.mock_db

    def test_list_custom_bundles_includes_builtins(self):
        admin_req = MagicMock()
        admin_req.state.user_role = cc_schemas.UserRole.ADMIN
        admin_req.state.user_email = "admin@enterprise.com"

        # Mock Firestore returning no custom bundles
        self.mock_db.collection.return_value.stream.return_value = []

        resp = self.routes.list_custom_bundles_endpoint(admin_req)
        self.assertEqual(resp.builtin_count, 5)
        self.assertEqual(resp.custom_count, 0)
        self.assertEqual(len(resp.bundles), 5)
        self.assertTrue(all(b.is_builtin for b in resp.bundles))

    def test_builtin_bundle_immutability(self):
        admin_req = MagicMock()
        admin_req.state.user_role = cc_schemas.UserRole.ADMIN
        admin_req.state.user_email = "admin@enterprise.com"

        # Attempt to delete built-in bundle
        with self.assertRaises(MockHTTPException) as ctx:
            self.routes.delete_custom_bundle_endpoint(admin_req, "secure-three-tier-web")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Built-in bundles are immutable", ctx.exception.detail)

        # Attempt to update built-in bundle
        with self.assertRaises(MockHTTPException) as ctx:
            self.routes.update_custom_bundle_endpoint(
                "secure-three-tier-web",
                UpdateBundleRequest(name="Hacked Name"),
                admin_req
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Built-in bundles are immutable", ctx.exception.detail)


_GIT_BUNDLE_FILES = {
    "bundles/web/main.tf": 'module "svc" {\n  source = "../../infra/modules/compute-cloudrun"\n}\n',
    "bundles/web/variables.tf": 'variable "project_id" {\n  type = string\n}\nvariable "region" {\n  type    = string\n  default = "us-central1"\n}\n',
    "bundles/web/outputs.tf": 'output "url" {\n  value = module.svc.service_uri\n}\n',
    "bundles/web/bundle.yaml": 'name: "Web Bundle"\ncategory: "COMPUTE_DATA"\n',
}


class TestControlCenterGitBundleEndpoints(unittest.TestCase):
    """cc-git-bundle-fix: register / re-sync / scan reach the real inspector (only the Git fetch is faked).

    Before the fix all three endpoints passed keyword arguments the inspector does not accept
    (bundle_dir=, repo_url=, ref=), so every call raised TypeError and returned 400.
    """

    def setUp(self):
        self.routes = routes_settings
        self.mock_db = MagicMock()
        self.routes.db = self.mock_db
        self.doc_ref = MagicMock()
        self.mock_db.collection.return_value.document.return_value = self.doc_ref
        self.req = MagicMock()
        self.req.state.user_role = cc_schemas.UserRole.ADMIN
        self.req.state.user_email = "admin@enterprise.com"
        self.provider = MagicMock()
        self.provider.fetch_file_content.side_effect = self._fetch
        self.provider.fetch_existing_repo_files.return_value = dict(_GIT_BUNDLE_FILES)
        self.files = dict(_GIT_BUNDLE_FILES)
        self.fetched = []
        patcher = patch("shared.vcs_provider.VCSProviderFactory.get_provider", return_value=self.provider)
        self.get_provider = patcher.start()
        self.addCleanup(patcher.stop)
        pid = patch.object(self.routes, "PROJECT_ID", "host-proj-x")
        pid.start()
        self.addCleanup(pid.stop)

    def _fetch(self, repo_id, path, branch):
        self.fetched.append((repo_id, path, branch))
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def _existing(self, **over):
        rec = {
            "bundle_id": "web", "name": "Web Bundle", "source_type": "REMOTE_GIT",
            "source_url": "https://github.com/acme/infra", "repo_path": "bundles/web",
            "version_tag": "v1.2.0", "variables": [{"name": "old"}], "hcl_files": {"main.tf": "old"},
        }
        rec.update(over)
        self.doc_ref.get.return_value.exists = True
        self.doc_ref.get.return_value.to_dict.return_value = rec

    def test_register_happy_path_stores_inspected_bundle(self):
        self.doc_ref.get.return_value.exists = False
        payload = RegisterBundleRequest(source_url="https://github.com/acme/infra", repo_path="bundles/web", version_tag="v1.2.0")
        rec = self.routes.register_custom_bundle_endpoint(payload, self.req)
        # the subdirectory and ref reach the Git fetch; the host project reaches the provider (token lookup)
        self.assertIn(("acme/infra", "bundles/web/main.tf", "v1.2.0"), self.fetched)
        self.assertIn(("acme/infra", "bundles/web/variables.tf", "v1.2.0"), self.fetched)
        self.get_provider.assert_called_with("GITHUB", project_id="host-proj-x")
        self.assertEqual(rec.bundle_id, "web")
        self.assertEqual(rec.name, "Web Bundle")
        self.assertEqual(rec.repo_path, "bundles/web")
        self.assertEqual([v["name"] for v in rec.variables], ["project_id", "region"])
        self.assertEqual([o["name"] for o in rec.outputs], ["url"])
        self.assertEqual(set(rec.hcl_files), {"main.tf", "variables.tf", "outputs.tf"})
        self.assertIn("compute-cloudrun", rec.modules_included)
        self.doc_ref.set.assert_called_once()
        self.assertEqual(self.doc_ref.set.call_args[0][0]["bundle_id"], "web")

    def test_register_bad_bundle_is_400_and_stores_nothing(self):
        self.doc_ref.get.return_value.exists = False
        del self.files["bundles/web/main.tf"]
        payload = RegisterBundleRequest(source_url="https://github.com/acme/infra", repo_path="bundles/web", version_tag="v1.2.0")
        with self.assertRaises(MockHTTPException) as ctx:
            self.routes.register_custom_bundle_endpoint(payload, self.req)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Failed to inspect Git bundle", ctx.exception.detail)
        self.assertIn("bundles/web/main.tf", ctx.exception.detail)
        self.assertNotIn("unexpected keyword", ctx.exception.detail)
        self.doc_ref.set.assert_not_called()

    def test_resync_happy_path_updates_contract(self):
        self._existing()
        rec = self.routes.sync_custom_bundle_endpoint("web", self.req)
        self.assertIn(("acme/infra", "bundles/web/main.tf", "v1.2.0"), self.fetched)
        self.get_provider.assert_called_with("GITHUB", project_id="host-proj-x")
        self.doc_ref.set.assert_called_once()
        updates, kwargs = self.doc_ref.set.call_args
        self.assertEqual(kwargs, {"merge": True})
        self.assertEqual([v["name"] for v in updates[0]["variables"]], ["project_id", "region"])
        self.assertEqual(updates[0]["hcl_files"]["main.tf"], _GIT_BUNDLE_FILES["bundles/web/main.tf"])
        self.assertEqual([v["name"] for v in rec.variables], ["project_id", "region"])

    def test_resync_bad_bundle_is_400_and_stores_nothing(self):
        self._existing()
        del self.files["bundles/web/variables.tf"]
        with self.assertRaises(MockHTTPException) as ctx:
            self.routes.sync_custom_bundle_endpoint("web", self.req)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Failed to re-sync bundle", ctx.exception.detail)
        self.assertIn("bundles/web/variables.tf", ctx.exception.detail)
        self.doc_ref.set.assert_not_called()

    def test_scan_repository_happy_path_and_failure(self):
        payload = ScanRepositoryBundlesRequest(source_url="https://github.com/acme/infra", parent_path="bundles", version_tag="v1.2.0")
        found = self.routes.scan_repository_bundles_endpoint(payload, self.req)
        self.assertEqual([d.repo_path for d in found], ["bundles/web"])
        self.provider.fetch_existing_repo_files.assert_called_with("acme/infra", branch="v1.2.0", max_files=2000)
        self.get_provider.assert_called_with("GITHUB", project_id="host-proj-x")
        self.provider.fetch_existing_repo_files.side_effect = RuntimeError("rate limited")
        with self.assertRaises(MockHTTPException) as ctx:
            self.routes.scan_repository_bundles_endpoint(payload, self.req)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("rate limited", ctx.exception.detail)

    def test_parse_bundle_source_url_https_forms(self):
        """The '//' of 'https://' is not the Terraform subdirectory separator (the register form suggests https URLs)."""
        self.assertEqual(parse_bundle_source_url("https://github.com/acme/infra"), ("acme/infra", "", "main"))
        self.assertEqual(parse_bundle_source_url("https://github.com/org/repo.git//bundles/my-bundle"), ("org/repo", "bundles/my-bundle", "main"))
        self.assertEqual(parse_bundle_source_url("git::https://github.com/org/repo.git//bundles/b?ref=v2"), ("org/repo", "bundles/b", "v2"))

    def test_parse_bundle_source_url_schemeless_unchanged(self):
        """Negative (Do No Harm): inputs without '://' parse exactly as before the fix."""
        def old_parse(source_url):
            raw = (source_url or "").strip()
            ref = "main"
            if "?ref=" in raw:
                raw, ref = raw.split("?ref=", 1)
            elif "?version=" in raw:
                raw, ref = raw.split("?version=", 1)
            subpath = ""
            if "//" in raw:
                repo_part, subpath = raw.split("//", 1)
                subpath = subpath.strip("/")
            else:
                repo_part = raw
            return routes_settings.parse_bundle_source_url.__globals__["parse_github_repo_identifier"](repo_part), subpath, ref

        for src in ["acme/infra", "github.com/org/repo//bundles/secure-three-tier-web?ref=v1.2.0", "org/repo//a/b/",
                    "git@github.com:org/repo.git//bundles/x?version=1.0", "  org/repo  ", "", "org/repo?ref=dev"]:
            self.assertEqual(parse_bundle_source_url(src), old_parse(src), src)

    # --- G1 (Opus RT): a ?ref= in the URL is honoured, never silently replaced by the "main" default ---

    def test_register_url_ref_wins_over_schema_default(self):
        self.doc_ref.get.return_value.exists = False
        payload = RegisterBundleRequest(source_url="https://github.com/acme/infra.git//bundles/web?ref=v1.2.0", bundle_id="web")
        rec = self.routes.register_custom_bundle_endpoint(payload, self.req)
        self.assertEqual({b for _, _, b in self.fetched}, {"v1.2.0"})
        self.assertEqual(rec.version_tag, "v1.2.0")
        self.assertEqual(self.doc_ref.set.call_args[0][0]["version_tag"], "v1.2.0")

    def test_register_explicit_version_tag_without_url_ref(self):
        self.doc_ref.get.return_value.exists = False
        payload = RegisterBundleRequest(source_url="acme/infra", repo_path="bundles/web", version_tag="release-7")
        rec = self.routes.register_custom_bundle_endpoint(payload, self.req)
        self.assertEqual({b for _, _, b in self.fetched}, {"release-7"})
        self.assertEqual(rec.version_tag, "release-7")

    def test_register_no_ref_anywhere_reads_main(self):
        self.doc_ref.get.return_value.exists = False
        payload = RegisterBundleRequest(source_url="acme/infra", repo_path="bundles/web")
        rec = self.routes.register_custom_bundle_endpoint(payload, self.req)
        self.assertEqual({b for _, _, b in self.fetched}, {"main"})
        self.assertEqual(rec.version_tag, "main")

    def test_register_ref_conflict_is_400_and_stores_nothing(self):
        self.doc_ref.get.return_value.exists = False
        payload = RegisterBundleRequest(source_url="https://github.com/acme/infra//bundles/web?ref=v1.2.0", bundle_id="web", version_tag="main")
        with self.assertRaises(MockHTTPException) as ctx:
            self.routes.register_custom_bundle_endpoint(payload, self.req)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Git ref conflict", ctx.exception.detail)
        self.assertEqual(self.fetched, [])
        self.doc_ref.set.assert_not_called()
        # same ref in both places is not a conflict
        payload = RegisterBundleRequest(source_url="https://github.com/acme/infra//bundles/web?ref=v1.2.0", bundle_id="web", version_tag="v1.2.0")
        self.assertEqual(self.routes.register_custom_bundle_endpoint(payload, self.req).version_tag, "v1.2.0")

    def test_resync_reads_the_stored_ref_of_a_url_ref_bundle(self):
        self._existing(source_url="https://github.com/acme/infra//bundles/web?ref=v1.2.0", repo_path="", version_tag="v1.2.0")
        self.routes.sync_custom_bundle_endpoint("web", self.req)
        self.assertEqual({b for _, _, b in self.fetched}, {"v1.2.0"})
        self.doc_ref.set.assert_called_once()

    def test_scan_url_ref_wins_over_schema_default_and_conflict_is_400(self):
        payload = ScanRepositoryBundlesRequest(source_url="https://github.com/acme/infra?ref=v1.2.0")
        self.routes.scan_repository_bundles_endpoint(payload, self.req)
        self.provider.fetch_existing_repo_files.assert_called_with("acme/infra", branch="v1.2.0", max_files=2000)
        payload = ScanRepositoryBundlesRequest(source_url="https://github.com/acme/infra?ref=v1.2.0", version_tag="dev")
        with self.assertRaises(MockHTTPException) as ctx:
            self.routes.scan_repository_bundles_endpoint(payload, self.req)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Git ref conflict", ctx.exception.detail)

    # --- G2 (Opus RT): a scheme URL must be on github.com, naming exactly <owner>/<repo> ---

    def test_non_github_hosts_are_refused_before_any_fetch(self):
        for src in [
            "https://gitlab.com/acme/infra",
            "https://gitlab.com/acme/infra//bundles/web",
            "https://github.com.evil.example/acme/infra",
            "https://evil.example/x/github.com/acme/infra",
            "https://evil.example/github.com/acme/infra",
            "git::https://bitbucket.org/acme/infra.git",
            "ftp://github.com/acme/infra",
            "https://github.com/acme",
            "https://github.com/acme/infra/tree/main",
        ]:
            with self.assertRaises(ValueError, msg=src):
                parse_bundle_source_url(src)
            self.doc_ref.reset_mock()
            self.doc_ref.get.return_value.exists = False
            with self.assertRaises(MockHTTPException, msg=src) as ctx:
                self.routes.register_custom_bundle_endpoint(RegisterBundleRequest(source_url=src, bundle_id="web"), self.req)
            self.assertEqual(ctx.exception.status_code, 400, src)
            self.doc_ref.set.assert_not_called()
            with self.assertRaises(MockHTTPException, msg=src):
                self.routes.scan_repository_bundles_endpoint(ScanRepositoryBundlesRequest(source_url=src), self.req)
        self.assertEqual(self.fetched, [])
        self.get_provider.assert_not_called()
        self.provider.fetch_existing_repo_files.assert_not_called()

    def test_github_scheme_forms_accepted(self):
        for src, want in [
            ("https://github.com/acme/infra", ("acme/infra", "", "main")),
            ("https://GitHub.com/acme/infra.git/", ("acme/infra", "", "main")),
            ("ssh://git@github.com/acme/infra.git//bundles/web", ("acme/infra", "bundles/web", "main")),
            ("https://github.com/acme/infra?version=1.0", ("acme/infra", "", "1.0")),
            ("git::https://github.com/acme/infra.git//bundles/web?ref=v2", ("acme/infra", "bundles/web", "v2")),
        ]:
            self.assertEqual(parse_bundle_source_url(src), want, src)

    def test_inspector_ref_resolution_direct(self):
        res = fetch_and_inspect_git_bundle(source_url="https://github.com/acme/infra//bundles/web?ref=v9")
        self.assertEqual(res["version_tag"], "v9")
        self.assertEqual(res["repo_path"], "bundles/web")
        with self.assertRaises(ValueError):
            fetch_and_inspect_git_bundle(source_url="https://github.com/acme/infra//bundles/web?ref=v9", version_tag="v8")

    def test_inspector_without_project_id_keeps_provider_default(self):
        """Negative: callers that pass no project_id get the unchanged get_provider("GITHUB") call."""
        fetch_and_inspect_git_bundle(source_url="https://github.com/acme/infra", repo_path="bundles/web", version_tag="v1.2.0")
        scan_repository_git_bundles(source_url="https://github.com/acme/infra", parent_path="bundles", version_tag="v1.2.0")
        for call in self.get_provider.call_args_list:
            self.assertEqual(call, (("GITHUB",), {}))


if __name__ == "__main__":
    unittest.main()
