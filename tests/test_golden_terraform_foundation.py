"""
Unit Tests for Implementation Plan 1: Deterministic Golden Terraform Foundation Module,
Pluggable Compute Archetypes, Module Vendoring (Option A), and State Migration (moved.tf).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import tempfile
import unittest

import pytest
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
    detect_cloudrun_scaling_parameters,
    generate_golden_main_tf,
    generate_golden_moved_tf,
    generate_golden_outputs_tf,
    generate_golden_variables_tf,
    get_canonical_module_files,
    vendor_terraform_modules,
)
from developer_agent.handler import DeveloperAgent, generate_service_workflow
from developer_agent.compute_intent import resolve_compute_intent


class TestGoldenTerraformFoundation(unittest.TestCase):
    """Verifies all architectural components of Golden Foundation Plan 1."""

    def test_compute_archetype_resolution_is_typed(self):
        """HD-01 (FD-4X) replacement: every archetype the deleted keyword detector could return is reachable from
        the typed compute intent; the spec text is not an input (full matrix: tests/test_faithful_hd01_hd02.py)."""
        cases = [
            ({"target_compute_services": ["portal"]}, "cloudrun"),
            (None, "cloudrun"),
            ({"target_compute_services": ["jump"], "compute_archetype": "gce-bastion"}, "gce-bastion"),
            ({"target_compute_services": ["mesh"], "bundle_id": "private-gke-microservices"}, "gke-autopilot"),
            ({"target_compute_services": ["mesh"], "compute_archetype": "gke-autopilot"}, "gke-autopilot"),
            ({"target_compute_services": ["consumer"], "compute_archetype": "event-worker"}, "event-worker"),
            ({"target_compute_services": [], "compute_archetype": "foundation-only"}, "foundation-only"),
        ]
        for record, expected in cases:
            self.assertEqual(resolve_compute_intent("p", record).archetype, expected, record)

    def test_canonical_modules_loading(self):
        """Verifies that all canonical base and compute archetype files are loaded."""
        mods = get_canonical_module_files()
        self.assertGreaterEqual(len(mods), 15)

        # Base module files
        expected_base = [
            "infra/modules/workload-foundation/base/apis.tf",
            "infra/modules/workload-foundation/base/wif.tf",
            "infra/modules/workload-foundation/base/iam.tf",
            "infra/modules/workload-foundation/base/database.tf",
            "infra/modules/workload-foundation/base/registry.tf",
            "infra/modules/workload-foundation/base/variables.tf",
            "infra/modules/workload-foundation/base/outputs.tf",
        ]
        for bpath in expected_base:
            self.assertIn(bpath, mods, f"Missing base module file: {bpath}")

        # Compute archetypes
        self.assertIn("infra/modules/compute-cloudrun/main.tf", mods)
        self.assertIn("infra/modules/compute-gce-bastion/main.tf", mods)
        self.assertIn("infra/modules/compute-gke-autopilot/main.tf", mods)
        self.assertIn("infra/modules/compute-event-worker/main.tf", mods)

    def test_option_a_module_vendoring(self):
        """Verifies that vendor_terraform_modules populates child repo files dictionary."""
        files = {}
        vendor_terraform_modules(files, "cloudrun")
        self.assertTrue(any(k.startswith("infra/modules/workload-foundation/base/") for k in files))
        self.assertTrue(any(k.startswith("infra/modules/compute-cloudrun/") for k in files))

        # Check that apis.tf contains additional_apis support
        apis_tf = files["infra/modules/workload-foundation/base/apis.tf"]
        self.assertIn("var.additional_apis", apis_tf)

        # FD-4AZ (owner scope A, D5 10-16): Firestore delete protection defaults ON; database.tf still maps an
        # explicit `firestore_delete_protection = false` opt-out to DELETE_PROTECTION_DISABLED.
        db_tf = files["infra/modules/workload-foundation/base/database.tf"]
        self.assertIn(
            'var.firestore_delete_protection ? "DELETE_PROTECTION_ENABLED" : "DELETE_PROTECTION_DISABLED"', db_tf)
        vars_tf = files["infra/modules/workload-foundation/base/variables.tf"]
        fdp = vars_tf[vars_tf.index('variable "firestore_delete_protection"'):]
        self.assertIn("default     = true", fdp[:fdp.index("}")])

        # FD-4AT (owner 10-20): the CI deployer never holds roles/editor (custom.tf is applied by tf-applier,
        # not by CI); its exact least-privilege role set is pinned in tests/test_fd4at_ci_least_privilege.py.
        iam_tf = files["infra/modules/workload-foundation/base/iam.tf"]
        self.assertNotIn("roles/editor", iam_tf)
        self.assertIn('resource "google_service_account_iam_member" "deployer_runtime_sa_user"', iam_tf)

    def test_golden_main_tf_structure(self):
        """Verifies deterministic main.tf instantiates foundation and compute modules."""
        # Cloud Run default
        main_tf = generate_golden_main_tf("myworkload", "cloudrun")
        self.assertIn('module "foundation"', main_tf)
        self.assertIn('module "compute"', main_tf)
        self.assertIn('source                = "../modules/workload-foundation/base"', main_tf)
        self.assertIn('source                = "../modules/compute-cloudrun"', main_tf)
        self.assertIn('service_name          = var.product_id', main_tf)
        self.assertIn('min_instances         = 0', main_tf)
        self.assertIn('max_instances         = 10', main_tf)
        self.assertIn('cpu_idle              = true', main_tf)

        # Cloud Run with custom hot scaling in spec text
        hot_main = generate_golden_main_tf(
            "myworkload",
            "cloudrun",
            "I want this cloud run to be minimum instances 2 and always allocated CPU"
        )
        self.assertIn('min_instances         = 2', hot_main)
        self.assertIn('cpu_idle              = false', hot_main)

        # GCE Bastion
        bastion_main = generate_golden_main_tf("myworkload", "gce-bastion")
        self.assertIn('source     = "../modules/compute-gce-bastion"', bastion_main)

        # GKE Autopilot
        gke_main = generate_golden_main_tf("myworkload", "gke-autopilot")
        self.assertIn('source     = "../modules/compute-gke-autopilot"', gke_main)

        # Event Worker
        worker_main = generate_golden_main_tf("myworkload", "event-worker")
        self.assertIn('source                = "../modules/compute-event-worker"', worker_main)

    def test_detect_cloudrun_scaling_parameters(self):
        """Verifies natural language extraction of scaling and CPU allocation across intake channels."""
        # Defaults
        res = detect_cloudrun_scaling_parameters("")
        self.assertEqual(res["min_instances"], 0)
        self.assertEqual(res["max_instances"], 10)
        self.assertTrue(res["cpu_idle"])

        # Explicit min instances and unthrottled CPU
        res = detect_cloudrun_scaling_parameters("i want this cloud run to be minimum instances 3 and always allocated cpu")
        self.assertEqual(res["min_instances"], 3)
        self.assertFalse(res["cpu_idle"])

        # Warm instance phrase
        res = detect_cloudrun_scaling_parameters("keep 2 warm instances alive to avoid cold starts")
        self.assertEqual(res["min_instances"], 2)
        self.assertTrue(res["cpu_idle"])

        # Generic "always live" phrase defaults to min 1
        res = detect_cloudrun_scaling_parameters("runtime must remain hot and always live")
        self.assertEqual(res["min_instances"], 1)
        self.assertTrue(res["cpu_idle"])

        # Explicit scale to zero override
        res = detect_cloudrun_scaling_parameters("please scale to zero when idle with max instances 15")
        self.assertEqual(res["min_instances"], 0)
        self.assertEqual(res["max_instances"], 15)
        self.assertTrue(res["cpu_idle"])

    def test_golden_moved_tf_state_migration(self):
        """Verifies moved.tf contains complete migration blocks for live resource addresses."""
        moved_tf = generate_golden_moved_tf("myworkload", "cloudrun")
        self.assertIn("moved {", moved_tf)
        self.assertIn("from = google_cloud_run_v2_service.app", moved_tf)
        self.assertIn("to   = module.compute.google_cloud_run_v2_service.app", moved_tf)
        self.assertIn("from = google_firestore_database.database", moved_tf)
        self.assertIn("to   = module.foundation.google_firestore_database.database", moved_tf)
        self.assertIn("from = google_artifact_registry_repository.docker_repo", moved_tf)
        self.assertIn("to   = module.foundation.google_artifact_registry_repository.docker_repo", moved_tf)
        self.assertIn("from = google_service_account.workload_sa", moved_tf)
        self.assertIn("to   = module.foundation.google_service_account.workload_sa", moved_tf)
        self.assertIn("from = google_iam_workload_identity_pool.github_pool", moved_tf)
        self.assertIn("to   = module.foundation.google_iam_workload_identity_pool.github_pool", moved_tf)
        self.assertIn("from = google_service_account.github_deployer", moved_tf)
        self.assertIn("to   = module.foundation.google_service_account.github_deployer", moved_tf)

    def test_service_workflow_generation_across_archetypes(self):
        """Verifies CI/CD workflow aligns with selected archetype."""
        cr_wf = generate_service_workflow("portal", "portal", "test-proj", archetype="cloudrun")
        self.assertIn("gcloud run deploy", cr_wf)

        bastion_wf = generate_service_workflow("bastion", "bastion", "test-proj", archetype="gce-bastion")
        # FD-4AT-b (owner 10-20): CI never applies Terraform (tf-applier owns the state); the step is a logged no-op.
        self.assertNotIn("terraform apply", bastion_wf)
        self.assertIn("tf-applier", bastion_wf)

        worker_wf = generate_service_workflow("worker", "worker", "test-proj", archetype="event-worker")
        self.assertIn("gcloud run jobs deploy", worker_wf)

        gke_wf = generate_service_workflow("k8s", "k8s", "test-proj", archetype="gke-autopilot")
        self.assertIn("gcloud container clusters get-credentials", gke_wf)

    def test_developer_agent_full_scaffolding(self):
        """Verifies DeveloperAgent outputs vendored modules and golden terraform."""
        # Lane 19 L19-3b (owner row 27a): the template scaffold is deleted; the LLM path (fake model) must still
        # emit the golden root module and the vendored modules.
        from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
        dev = DeveloperAgent(project_id="test-proj")
        dev.genai_client = FakeGenaiClient(files=canned_workload_files("testportal"))
        with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}), \
                patch.object(dev, "fetch_existing_repo_files", return_value={}):
            files = dev.generate_code_files(product_id="testportal", spec_text="FastAPI web portal", task_dag=[], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)

        self.assertIn("infra/workload/main.tf", files)
        self.assertIn("infra/workload/variables.tf", files)
        self.assertIn("infra/workload/outputs.tf", files)
        self.assertIn("infra/workload/moved.tf", files)
        self.assertTrue(any(k.startswith("infra/modules/workload-foundation/base/") for k in files))
        self.assertTrue(any(k.startswith("infra/modules/compute-cloudrun/") for k in files))

    # FD-05 B-6 (red-team F4): with VCSProviderFactory unavailable (the import-shim fallback) commit_and_open_pr
    # falls through to a legacy git-CLI clone and then to the PyGithub REST create_git_tree/create_git_commit path,
    # the same REST path GitHubProvider.commit_files deleted on purpose (285d275). That fallback is also broken for
    # a NEW branch: target_branch is unbound -> UnboundLocalError -> FAILED (FD21-18; executed in the lane 2 plan).
    # The old assertion (SUCCESS via REST) blessed that path, so this asserts the fail-closed contract instead.
    # When FD21-18 deletes the fallback this XPASSes: delete the marker (strict) and this comment.
    # raises=AssertionError (code-RT finding 4): a crash is re-raised and FAILS the test; it never XPASSes.
    @pytest.mark.xfail(strict=True, raises=AssertionError,
                       reason="FD-4AH/FD21-18 + FD-4F: no VCS provider falls back to the PyGithub REST commit path "
                              "instead of failing closed")
    @patch("developer_agent.handler.VCSProviderFactory", None)
    @patch("developer_agent.handler.Github")
    def test_commit_and_open_pr_without_vcs_provider_fails_closed(self, mock_github_cls):
        mock_gh = MagicMock()
        mock_repo = MagicMock()
        mock_github_cls.return_value = mock_gh
        mock_gh.get_repo.return_value = mock_repo
        mock_main = MagicMock()
        mock_main.commit.sha = "main-sha-123456"
        mock_main.commit.commit.tree.sha = "main-tree-sha"
        mock_repo.get_branch.return_value = mock_main
        mock_repo.get_git_tree.return_value = MagicMock(tree=[])
        mock_repo.create_git_commit.return_value = MagicMock(sha="new-commit-sha-789012")
        mock_repo.create_pull.return_value = MagicMock(html_url="https://github.com/org/repo/pull/42")

        dev = DeveloperAgent(project_id="test-proj")
        # shutil.which is looked up through the handler module, but patching it there patches the global
        # shutil.which for the duration (acceptable: it only hides the git binary from the code under test).
        with patch.object(dev, "fetch_github_token", return_value="fake-token"), \
                patch("developer_agent.handler.shutil.which", return_value=None):
            try:
                res = dev.commit_and_open_pr(
                    product_id="testportal",
                    files={"README.md": "Hello"},
                    branch_name="feature/testportal-abc",
                )
            except (AttributeError, TypeError, NameError, LookupError, ImportError):
                raise  # a crash is not fail-closed
            except Exception:
                res = {"status": "RAISED"}

        self.assertNotEqual(res.get("status"), "SUCCESS")
        mock_repo.create_git_tree.assert_not_called()
        mock_repo.create_git_commit.assert_not_called()
        mock_repo.get_git_ref.return_value.edit.assert_not_called()

    def test_terraform_service_module_path_resolution(self):
        """Verifies prepare_workspace sets up module symlinks. FD-55 W6a (register FD55-W6a, A20): root main.tf is written
        as committed (no substring source rewrite; deploy re-anchors flattened sources with the parser before this
        method, FD-4BW), and the parent `modules` symlink resolves `../modules/...`."""
        import tempfile
        tf_dir = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
        if tf_dir not in sys.path:
            sys.path.insert(0, tf_dir)
        sys.modules.pop("service", None)
        from service import TerraformService

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = TerraformService(project_id="test-proj", workspace_base_dir=tmpdir)
            files = {
                "infra/modules/workload-foundation/base/apis.tf": 'resource "google_project_service" "apis" {}',
                "infra/modules/compute-cloudrun/main.tf": 'resource "google_cloud_run_v2_service" "app" {}',
                "main.tf": 'module "compute" {\n  source = "../modules/compute-cloudrun"\n}',
            }
            ws = svc.prepare_workspace("test-product", "trace-symlink-test", files)

            with open(os.path.join(ws, "main.tf"), "r") as f:
                content = f.read()
            self.assertEqual(content, files["main.tf"])

            # Verify symlinks were created
            self.assertTrue(os.path.exists(os.path.join(ws, "modules")))
            self.assertTrue(os.path.exists(os.path.join(os.path.dirname(ws), "modules")))
            self.assertTrue(os.path.exists(os.path.join(ws, "..", "modules", "compute-cloudrun", "main.tf")))

    def test_terraform_service_provider_mirror_and_status_hardening(self):
        """Verifies _ensure_provider_mirror writes terraform.rc with filesystem_mirror."""
        import tempfile
        tf_dir = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
        if tf_dir not in sys.path:
            sys.path.insert(0, tf_dir)
        sys.modules.pop("service", None)
        from service import TerraformService

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = TerraformService(project_id="test-proj", workspace_base_dir=tmpdir)
            with patch("binary_checksums.fetch_to", side_effect=OSError("offline test")):  # FD-4BQ fetch primitive
                rc_path = svc._ensure_provider_mirror()
                self.assertTrue(os.path.exists(rc_path))
                with open(rc_path, "r") as f:
                    content = f.read()
                self.assertIn("provider_installation", content)
                self.assertIn("filesystem_mirror", content)
                self.assertIn(os.path.join(tmpdir, ".castor-tooling", "plugin_mirror"), content)
                self.assertIn("direct {\n    include = [", content)   # FD-4AQ W1b: limited to the allow-list
                self.assertNotIn("direct {}", content)

    def test_terraform_service_tarball_contract_and_parallel_buildpacks(self):
        """Verifies _build_and_push_container packages contract files into tarball and emits parallel steps."""
        import io
        import tarfile
        import tempfile
        tf_dir = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
        if tf_dir not in sys.path:
            sys.path.insert(0, tf_dir)
        sys.modules.pop("service", None)
        from service import TerraformService

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = TerraformService(project_id="test-proj", workspace_base_dir=tmpdir)
            ws = os.path.join(tmpdir, "workspace")
            os.makedirs(os.path.join(ws, "apps", "frontend"), exist_ok=True)
            os.makedirs(os.path.join(ws, "apps", "backend-api"), exist_ok=True)

            with open(os.path.join(ws, "apps", "frontend", "main.py"), "w") as f:
                f.write("# frontend\n")
            with open(os.path.join(ws, "apps", "backend-api", "main.py"), "w") as f:
                f.write("# backend\n")

            uploaded_tar_bytes = None
            submitted_payload = None

            mock_blob = MagicMock()
            def fake_upload(data, content_type=None):
                nonlocal uploaded_tar_bytes
                uploaded_tar_bytes = data
            mock_blob.upload_from_string.side_effect = fake_upload

            mock_bucket = MagicMock()
            mock_bucket.exists.return_value = True
            mock_bucket.blob.return_value = mock_blob
            mock_bucket.get_iam_policy.return_value = MagicMock(bindings=[])

            mock_storage_client = MagicMock()
            mock_storage_client.bucket.return_value = mock_bucket

            mock_session = MagicMock()
            def fake_post(url, json=None, timeout=None):
                nonlocal submitted_payload
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                if "builds" in url:
                    submitted_payload = json
                    mock_resp.json.return_value = {"id": "b-12345"}
                else:
                    mock_resp.json.return_value = {}
                return mock_resp

            def fake_get(url, timeout=None):
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                if "builds/b-12345" in url:
                    mock_resp.json.return_value = {"status": "SUCCESS"}
                elif "defaultServiceAccount" in url:
                    # FD-4BA: the source bucket grant goes to the resolved Cloud Build default service account.
                    mock_resp.json.return_value = {"serviceAccountEmail": "projects/target-proj/serviceAccounts/123456789-compute@developer.gserviceaccount.com"}
                elif "repositories" in url:
                    mock_resp.status_code = 404
                elif "projects/target-proj" in url:
                    mock_resp.json.return_value = {"projectNumber": "123456789"}
                return mock_resp

            mock_session.post.side_effect = fake_post
            mock_session.get.side_effect = fake_get

            # Configure sys.modules mocks for google auth and storage
            google_mock = sys.modules.get("google", MagicMock())
            google_auth_mock = MagicMock()
            google_auth_mock.default.return_value = (MagicMock(), "proj")
            google_auth_mock.transport.requests.AuthorizedSession.return_value = mock_session
            google_mock.auth = google_auth_mock
            sys.modules["google"] = google_mock
            sys.modules["google.auth"] = google_auth_mock
            sys.modules["google.auth.transport"] = google_auth_mock.transport
            sys.modules["google.auth.transport.requests"] = google_auth_mock.transport.requests

            google_cloud_mock = sys.modules.get("google.cloud", MagicMock())
            google_cloud_storage_mock = MagicMock()
            google_cloud_storage_mock.Client.return_value = mock_storage_client
            google_cloud_mock.storage = google_cloud_storage_mock
            sys.modules["google.cloud"] = google_cloud_mock
            sys.modules["google.cloud.storage"] = google_cloud_storage_mock

            success = svc._build_and_push_container(
                product_id="multi-app",
                target_project_id="target-proj",
                workspace_dir=ws,
                image_tag="us-central1-docker.pkg.dev/target-proj/castor-multi-app/app:latest"
            )
            self.assertTrue(success)

            # 1. Verify container contract files exist on disk in every service directory
            self.assertTrue(os.path.exists(os.path.join(ws, "Procfile")))
            self.assertTrue(os.path.exists(os.path.join(ws, ".python-version")))
            self.assertTrue(os.path.exists(os.path.join(ws, "apps", "frontend", "Procfile")))
            self.assertTrue(os.path.exists(os.path.join(ws, "apps", "frontend", ".python-version")))
            self.assertTrue(os.path.exists(os.path.join(ws, "apps", "backend-api", "Procfile")))
            self.assertTrue(os.path.exists(os.path.join(ws, "apps", "backend-api", ".python-version")))

            # 2. Verify tarball was packed with these files included
            self.assertIsNotNone(uploaded_tar_bytes)
            with tarfile.open(fileobj=io.BytesIO(uploaded_tar_bytes), mode="r:gz") as tar:
                names = tar.getnames()
                self.assertIn("Procfile", names)
                self.assertIn(".python-version", names)
                self.assertIn("apps/frontend/Procfile", names)
                self.assertIn("apps/frontend/.python-version", names)
                self.assertIn("apps/backend-api/Procfile", names)
                self.assertIn("apps/backend-api/.python-version", names)

            # 3. Verify Cloud Build payload executed all steps in parallel with waitFor: ['-']
            self.assertIsNotNone(submitted_payload)
            steps = submitted_payload.get("steps", [])
            self.assertEqual(len(steps), 2)
            for step in steps:
                self.assertEqual(step["waitFor"], ["-"])
                self.assertIn("gcr.io/k8s-skaffold/pack", step["name"])

    def test_terraform_service_writes_root_main_tf_as_committed_with_iap(self):
        """FD-55 W6a (register FD55-W6a, A21): prepare_workspace no longer injects the google-beta provider into the
        root main.tf (or into a Cloud Run resource) when Direct IAP is in use; the platform render declares what it
        needs. The root main.tf is byte-identical (a missing provider would be a validate / apply error)."""
        import tempfile
        tf_dir = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
        if tf_dir not in sys.path:
            sys.path.insert(0, tf_dir)
        sys.modules.pop("service", None)
        from service import TerraformService

        root_main = '''terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0.0, < 7.0.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_cloud_run_v2_service" "app" {
  name        = "app"
  location    = var.region
  iap_enabled = true
}
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = TerraformService(project_id="test-proj", workspace_base_dir=tmpdir)
            ws = svc.prepare_workspace("test-product", "trace-iap-heal", {"main.tf": root_main})
            with open(os.path.join(ws, "main.tf"), "r") as f:
                self.assertEqual(f.read(), root_main)

    def test_foundation_only_golden_terraform(self):
        """Verifies foundation-only archetype produces zero compute resources, zero workflows, and clean base IaC."""
        # 1. Main.tf verification
        main_tf = generate_golden_main_tf(product_id="emptyone", archetype="foundation-only")
        self.assertIn('module "foundation"', main_tf)
        self.assertNotIn('module "compute"', main_tf)
        self.assertNotIn("google_cloud_run_v2_service", main_tf)

        # 2. Outputs.tf verification
        outputs_tf = generate_golden_outputs_tf(product_id="emptyone", archetype="foundation-only")
        self.assertIn("workload_sa_email", outputs_tf)
        self.assertIn("deployer_sa_email", outputs_tf)
        self.assertNotIn("service_uri", outputs_tf)
        self.assertNotIn("service_name", outputs_tf)

        # 3. Moved.tf verification
        moved_tf = generate_golden_moved_tf(product_id="emptyone", archetype="foundation-only")
        self.assertIn("module.foundation.google_firestore_database.database", moved_tf)
        self.assertNotIn("module.compute.google_cloud_run_v2_service.app", moved_tf)

        # 4. Module vendoring verification
        files = {}
        vendor_terraform_modules(files, "foundation-only")
        self.assertTrue(any(k.startswith("infra/modules/workload-foundation/base/") for k in files))
        self.assertFalse(any(k.startswith("infra/modules/compute-cloudrun/") for k in files))
        self.assertFalse(any(k.startswith("infra/modules/compute-gce-bastion/") for k in files))

        # 5. Developer agent foundation-only output (lane 19 L19-3b, owner row 27a: the template scaffold is
        # deleted; the LLM path with a fake model must strip apps/ and workflows for a foundation-only spec).
        from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
        dev_agent = DeveloperAgent()
        dev_agent.genai_client = FakeGenaiClient(files={
            "infra/workload/custom.tf": "# foundation only\n",
            "apps/emptyone/main.py": "print('stray app code the foundation-only path must strip')\n",
        })
        with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}), \
                patch.object(dev_agent, "fetch_existing_repo_files", return_value={}):
            # HD-01: foundation-only comes from the architect's typed record, not from the spec wording.
            scaffold = dev_agent.generate_code_files(
                product_id="emptyone",
                spec_text="Create an empty project with APIs enabled, no services",
                task_dag=[],
                architect_compute_intent={"target_compute_services": [], "compute_archetype": "foundation-only"}, allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False
            )
        # Should have infra/workload files and README, but NO apps/ and NO .github/workflows/
        self.assertIn("infra/workload/main.tf", scaffold)
        self.assertIn("infra/workload/variables.tf", scaffold)
        self.assertIn("infra/workload/outputs.tf", scaffold)
        self.assertIn("infra/workload/README.md", scaffold)
        self.assertNotIn('module "compute"', scaffold["infra/workload/main.tf"])
        # No app code and no workflows. (Known LLM-path wrinkle, reported by lane 19 for the gatekeeper owner: the
        # gatekeeper's requirements reconciliation re-adds apps/<pid>/requirements.txt after the foundation-only
        # strip; the deleted template path skipped the gatekeeper, so the old `no apps/ at all` check never saw it.)
        self.assertFalse(any(k.startswith("apps/") and k.endswith(".py") for k in scaffold))
        self.assertFalse(any(k.startswith(".github/workflows/") for k in scaffold))

        # 6. TerraformService deployment verification
        import tempfile
        tf_dir = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
        if tf_dir not in sys.path:
            sys.path.insert(0, tf_dir)
        from service import TerraformService
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = TerraformService(
                project_id="test-project",
                state_bucket="castor-tfstate-test-project",
                workspace_base_dir=tmpdir,
                firestore_client=MagicMock(),
            )
            with patch.object(svc, "_build_and_push_container") as mock_build, \
                 patch.object(svc, "_ensure_binary", return_value="tofu"), \
                 patch.object(svc, "_compliance_gate_check", return_value={"passed": True, "evidence": {}}), \
                 patch.object(svc, "_run_subprocess") as mock_subproc:
                mock_subproc.return_value = {
                    "success": True,
                    "stdout": "Apply complete! Resources: 5 added, 0 changed, 0 destroyed.",
                    "stderr": "",
                }
                res = svc.deploy_workload(
                    product_id="emptyone",
                    trace_id="trace-emptyone-test",
                    hcl_files={
                        "main.tf": main_tf,
                        "variables.tf": scaffold["infra/workload/variables.tf"],
                        "outputs.tf": outputs_tf,
                    },
                    target_project_id="emptyone-proj",
                )
                mock_build.assert_not_called()
                self.assertEqual(res["status"], "SUCCESS")
                self.assertEqual(res.get("service_url"), "")


    def test_auxiliary_tf_stays_in_place_and_is_not_purged(self):
        """Step 1 S1-A (register HS-01/HS-08): auxiliary .tf files stay where the draft put them (no Tier-3
        consolidation, no stem purge); only exact platform root declarations (its `terraform` block) are removed."""
        dev = DeveloperAgent(project_id="test-project")
        raw_files = {
            "apps/testplan/main.py": "print('hello')",
            "infra/workload/pubsub_gcs_firestore.tf": """
terraform {
  required_providers {
    google = { source = "hashicorp/google" }
  }
}
resource "google_pubsub_topic" "events_inbound" {
  project = var.project_id
  name    = "test-topic"
}
resource "google_storage_bucket" "event_payloads" {
  project = var.project_id
  name    = "test-bucket"
}
output "pubsub_topic_id" {
  value = google_pubsub_topic.events_inbound.id
}
""",
            "infra/workload/custom.tf": """
resource "google_pubsub_topic" "events_inbound" {
  project = var.project_id
  name    = "test-topic"
}
resource "google_storage_bucket" "event_payloads" {
  project = var.project_id
  name    = "test-bucket"
}
output "pubsub_topic_id" {
  value = google_pubsub_topic.events_inbound.id
}
""",
        }

        # Lane 19 L19-3b (owner row 27a): the same raw files now arrive through the LLM seam (fake model), not the
        # deleted template scaffold.
        from _lane19_fake_genai import FakeGenaiClient
        with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}):
            with patch.object(dev, "fetch_existing_repo_files", return_value={}):
                with patch.object(dev, "genai_client", FakeGenaiClient(files=dict(raw_files))):
                    processed = dev.generate_code_files(
                        product_id="testplan",
                        spec_text="Deploy webhook service with test-topic and test-bucket",
                        task_dag=[],
                        target_compute_services=["testplan"], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False
                    )

        # 1. The auxiliary file is never purged (the template scaffold is platform output: kept, not spliced)
        self.assertIn("infra/workload/pubsub_gcs_firestore.tf", processed)

        # 2. No declaration is lost from the root module (no Tier-3 consolidation copies, no stem purge)
        root = "\n".join(v for k, v in processed.items()
                         if k.startswith("infra/workload/") and k.endswith(".tf") and "/" not in k[len("infra/workload/"):])
        self.assertIn('resource "google_pubsub_topic" "events_inbound"', root)
        self.assertIn('resource "google_storage_bucket" "event_payloads"', root)
        self.assertIn('output "pubsub_topic_id"', root)

    def test_prepare_workspace_preserves_moved_tf(self):
        """Verify that prepare_workspace does not alter moved.tf declarations."""
        import tempfile
        import shutil
        tf_dir = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
        if tf_dir not in sys.path:
            sys.path.insert(0, tf_dir)
        sys.modules.pop("service", None)
        from service import TerraformService

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = TerraformService(project_id="test-proj", workspace_base_dir=tmpdir)
            orig_moved_content = (
                'moved {\n'
                '  from = google_firestore_database.database\n'
                '  to   = module.foundation.google_firestore_database.database\n'
                '}\n'
            )
            files = {
                "moved.tf": orig_moved_content,
                "custom.tf": 'output "fs" { value = google_firestore_database.database.name }\n',
            }

            ws = svc.prepare_workspace("test-prod", "trace-moved", files)
            moved_path = os.path.join(ws, "moved.tf")

            with open(moved_path, "r", encoding="utf-8") as f:
                new_moved_content = f.read()

            # Verify moved.tf was untouched and preserves the exact 'from = google_firestore_database.database'
            self.assertEqual(new_moved_content, orig_moved_content)
            self.assertIn("from = google_firestore_database.database", new_moved_content)
            self.assertNotIn("from = module.foundation\n", new_moved_content)

    def test_prepare_workspace_keeps_undeclared_locals_as_committed(self):
        """FD-55 W6b (register FD55-W6b+W6d, A28 / HA-17): prepare_workspace no longer synthesizes a `locals` block for
        an undeclared `local.x` (it invented the value from the name). The file reaches the workspace byte-identical;
        the undeclared local is a `tofu validate` error that is reported back."""
        tf_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "terraform"))
        if tf_dir not in sys.path:
            sys.path.insert(0, tf_dir)
        sys.modules.pop("service", None)
        from service import TerraformService

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = TerraformService(project_id="test-proj", workspace_base_dir=tmpdir)
            files = {
                "variables.tf": 'variable "project_id" { type = string }\nvariable "region" { type = string }\n',
                "custom.tf": (
                    'resource "google_storage_bucket" "raw_events" {\n'
                    '  name     = local.raw_bucket_name\n'
                    '  location = var.region\n'
                    '}\n'
                ),
            }

            ws = svc.prepare_workspace("test-prod", "trace-locals", files)
            custom_path = os.path.join(ws, "custom.tf")

            with open(custom_path, "r", encoding="utf-8", newline="") as f:
                applied_custom = f.read()

            self.assertEqual(applied_custom, files["custom.tf"])
            self.assertNotIn("locals {", applied_custom)

    def test_prepare_workspace_keeps_enforce_bucket_policy_only_as_committed(self):
        """FD-55 W6a (register FD55-W6a, A21): the `enforce_bucket_policy_only` -> `uniform_bucket_level_access` swap
        is deleted. The argument does not exist in google provider >= 6, so such a file fails `tofu validate` before
        commit (V1b) or at deploy (reported back); prepare_workspace writes it byte-identical."""
        tf_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "terraform"))
        if tf_dir not in sys.path:
            sys.path.insert(0, tf_dir)
        sys.modules.pop("service", None)
        from service import TerraformService

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = TerraformService(project_id="test-proj", workspace_base_dir=tmpdir)
            files = {
                "variables.tf": 'variable "project_id" { type = string }\nvariable "region" { type = string }\n',
                "custom.tf": (
                    'resource "google_storage_bucket" "events_bucket" {\n'
                    '  name                       = "my-bucket"\n'
                    '  location                   = var.region\n'
                    '  enforce_bucket_policy_only = true\n'
                    '}\n'
                ),
            }

            ws = svc.prepare_workspace("test-prod", "trace-enforce-bucket", files)
            with open(os.path.join(ws, "custom.tf"), "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), files["custom.tf"])

if __name__ == "__main__":
    unittest.main()




