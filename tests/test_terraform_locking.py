"""
Tests for Implementation Plan 10:
Terraform State Lock Queueing, Concurrency Resilience & Self-Healing Auto-Unlock.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

# Self-contained: the tests below patch "google.auth.default" / "google.auth.transport.requests.AuthorizedSession",
# and the service imports both inside its functions. Import the real modules (google-auth is a terraform MCP
# requirement) before the stub loop, so the patch target and the module the service reads are the same object
# whether or not another test file imported google.auth first. With a stubbed google.auth, mock.patch resolves
# sys.modules["google.auth"] while `import google.auth` reads the parent's attribute: a different object (or an
# AttributeError on the real `google` namespace), and the patch silently missed (hermetic_guard still blocks ADC).
import google.auth  # noqa: E402,F401
import google.auth.transport.requests  # noqa: E402,F401

for mod in ["httpx", "google", "google.auth", "google.auth.transport", "google.auth.transport.requests", "google.cloud", "google.cloud.storage", "google.cloud.secretmanager"]:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

# Ensure mcp-servers/terraform is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../mcp-servers/terraform")))

from service import TerraformService


class TestTerraformLockingAndResilience(unittest.TestCase):
    def setUp(self):
        # Hermetic (FD-4BO follow-up): a private workspace root under TMPDIR instead of a shared, hard-coded
        # path in the system temp dir, so no state carries over between runs or machines.
        self.workspace_base = tempfile.mkdtemp(prefix="tf_locking_")
        self.addCleanup(shutil.rmtree, self.workspace_base, ignore_errors=True)
        self.service = TerraformService(
            project_id="test-project-123",
            state_bucket="castor-tfstate-test",
            workspace_base_dir=self.workspace_base,
            firestore_client=MagicMock(),
        )
        self.service.lock_timeout = "180s"
        self.service.stale_lock_max_age_min = 20
        # _run_subprocess pre-caches the provider mirror (OpenTofu registry) when the hard-coded /tmp tooling dir
        # has none: these tests are about argv/env only, so the mirror is mocked (hermetic in any environment).
        rc_dir = tempfile.mkdtemp(prefix="tf-locking-rc-")
        rc = os.path.join(rc_dir, "terraform.rc")
        with open(rc, "w") as fh:
            fh.write("provider_installation {}\n")
        self.addCleanup(shutil.rmtree, rc_dir, True)
        mirror = patch.object(TerraformService, "_ensure_provider_mirror", return_value=rc)
        mirror.start()
        self.addCleanup(mirror.stop)
        # Lane 14 PR-0: these tests are about locks, not compliance; the plan gate answers PASS without planning
        # (its own behaviour: tests/test_lane14_compliance_gate.py).
        gate = patch.object(TerraformService, "_compliance_gate_check", return_value={"passed": True, "evidence": {}})
        gate.start()
        self.addCleanup(gate.stop)
        # Self-contained: the service reads platform settings at call time (tool versions, IaC engine). Answer
        # with the documented defaults (what an install with no stored settings document gets) instead of letting
        # the read reach a real Firestore client when google.cloud.firestore is importable.
        import shared.settings as platform_settings
        settings = patch.object(platform_settings, "get_platform_settings",
                                return_value=platform_settings.PlatformSettings())
        settings.start()
        self.addCleanup(settings.stop)

    def _mock_provider_mirror(self):
        """Mock the provider-mirror seam for tests that call the real _run_subprocess.

        The real _ensure_provider_mirror downloads linux provider zips through the OpenTofu registry whenever a mirror
        platform dir holds no verified binary (a provider it cannot verify leaves no platform dir behind, and the next
        run tries again). These tests only check the argv that reaches subprocess.Popen.
        """
        rc_path = os.path.join(self.workspace_base, "terraform.rc")
        with open(rc_path, "w") as f:
            f.write("provider_installation {\n  direct {}\n}\n")
        patcher = patch.object(self.service, "_ensure_provider_mirror", return_value=rc_path)
        mirror = patcher.start()
        self.addCleanup(patcher.stop)
        return mirror

    @patch("service.TerraformService._ensure_binary", return_value="/usr/local/bin/terraform")  # RT14-22: never PATH
    @patch("subprocess.Popen")
    def test_run_subprocess_injects_lock_timeout_for_plan_apply_destroy(self, mock_run, mock_which):
        """Verify centralized -lock-timeout injection for locking subcommands."""
        self._mock_provider_mirror()
        mock_run.return_value = MagicMock(returncode=0, communicate=MagicMock(return_value=("success", "")))

        # 1. Apply
        self.service._run_subprocess(["terraform", "apply", "-input=false", "-auto-approve"], cwd=self.workspace_base)
        called_cmd = mock_run.call_args[0][0]
        self.assertIn("-lock-timeout=180s", called_cmd)
        self.assertEqual(called_cmd[0], "/usr/local/bin/terraform")
        self.assertEqual(called_cmd[1], "apply")
        self.assertEqual(called_cmd[2], "-lock-timeout=180s")

        # 2. Plan
        self.service._run_subprocess(["terraform", "plan", "-out=tfplan"], cwd=self.workspace_base)
        called_cmd = mock_run.call_args[0][0]
        self.assertIn("-lock-timeout=180s", called_cmd)
        self.assertEqual(called_cmd[1], "plan")
        self.assertEqual(called_cmd[2], "-lock-timeout=180s")

        # 3. Destroy
        self.service._run_subprocess(["terraform", "destroy", "-auto-approve"], cwd=self.workspace_base)
        called_cmd = mock_run.call_args[0][0]
        self.assertIn("-lock-timeout=180s", called_cmd)
        self.assertEqual(called_cmd[1], "destroy")
        self.assertEqual(called_cmd[2], "-lock-timeout=180s")

    @patch("service.TerraformService._ensure_binary", return_value="/usr/local/bin/terraform")  # RT14-22: never PATH
    @patch("subprocess.Popen")
    def test_run_subprocess_preserves_explicit_lock_timeout(self, mock_run, mock_which):
        """Verify explicit caller-provided -lock-timeout is not duplicated."""
        self._mock_provider_mirror()
        mock_run.return_value = MagicMock(returncode=0, communicate=MagicMock(return_value=("success", "")))

        self.service._run_subprocess(["terraform", "apply", "-lock-timeout=45s", "-auto-approve"], cwd=self.workspace_base)
        called_cmd = mock_run.call_args[0][0]
        self.assertIn("-lock-timeout=45s", called_cmd)
        # Should NOT contain -lock-timeout=180s
        self.assertNotIn("-lock-timeout=180s", called_cmd)

    @patch("service.TerraformService._ensure_binary", return_value="/usr/local/bin/terraform")  # RT14-22: never PATH
    @patch("subprocess.Popen")
    def test_run_subprocess_does_not_inject_lock_timeout_for_non_locking_commands(self, mock_run, mock_which):
        """Verify subcommands that do not support -lock-timeout are strictly untouched."""
        self._mock_provider_mirror()
        mock_run.return_value = MagicMock(returncode=0, communicate=MagicMock(return_value=("success", "")))

        non_locking = [
            ["terraform", "init", "-input=false", "-no-color"],
            ["terraform", "validate", "-json"],
            ["terraform", "show", "-json", "tfplan"],
            ["terraform", "output", "-json"],
            ["terraform", "force-unlock", "-force", "12345"],
        ]

        for cmd in non_locking:
            self.service._run_subprocess(cmd, cwd=self.workspace_base)
            called_cmd = mock_run.call_args[0][0]
            for arg in called_cmd:
                self.assertFalse(arg.startswith("-lock-timeout"), f"Unexpected -lock-timeout in {called_cmd}")

    def test_parse_state_lock_info_valid(self):
        """Verify extraction of structured lock info from real Terraform stderr."""
        stderr = """
Error: Error acquiring the state lock
Error message: writing "gs://castor-tfstate-123/workloads/myapp/default.tflock" failed: googleapi: Error 412: Precondition Failed, conditionNotMet
Lock Info:
  ID:        1725822600123456
  Path:      gs://castor-tfstate-123/workloads/myapp/default.tflock
  Operation: OperationTypeApply
  Who:       terraform-mcp@test-platform-project.iam.gserviceaccount.com
  Version:   1.7.5
  Created:   2026-09-08 14:00:00.000000000 UTC
  Info:      
"""
        info = self.service.parse_state_lock_info(stderr, max_age_minutes=20)
        self.assertIsNotNone(info)
        self.assertEqual(info["lock_id"], "1725822600123456")
        self.assertEqual(info["who"], "terraform-mcp@test-platform-project.iam.gserviceaccount.com")
        self.assertEqual(info["path"], "gs://castor-tfstate-123/workloads/myapp/default.tflock")
        self.assertEqual(info["operation"], "OperationTypeApply")
        self.assertTrue(info["age_seconds"] > 0)
        # Should be stale because 14:00 is many minutes ago
        self.assertTrue(info["is_stale"])

    def test_parse_state_lock_info_fresh(self):
        """Verify lock created within threshold is flagged as fresh (not stale)."""
        recent_dt = datetime.now(timezone.utc) - timedelta(minutes=2)
        created_str = recent_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        stderr = f"""
Error: Error acquiring the state lock
Lock Info:
  ID:        999888777
  Path:      gs://bucket/workloads/test/default.tflock
  Operation: OperationTypeApply
  Who:       runner@castor
  Created:   {created_str}
"""
        info = self.service.parse_state_lock_info(stderr, max_age_minutes=20)
        self.assertIsNotNone(info)
        self.assertEqual(info["lock_id"], "999888777")
        self.assertFalse(info["is_stale"])

    def test_parse_state_lock_info_non_lock_error(self):
        """Verify returns None when stderr does not contain lock error."""
        stderr = "Error: Invalid reference 'var.missing_var' at main.tf:12"
        self.assertIsNone(self.service.parse_state_lock_info(stderr))
        self.assertIsNone(self.service.parse_state_lock_info(""))

    @patch.object(TerraformService, "_read_state_lock_object",
                  return_value=({"lock_id": "1725822600", "who": "cnb@localhost", "operation": "OperationTypeApply"},
                                {"ID": "x", "Operation": "OperationTypeApply", "Who": "cnb@localhost"}))
    @patch.object(TerraformService, "_run_subprocess")
    def test_force_unlock_execution(self, mock_subprocess, _mock_lock_read):
        """Verify force_unlock creates backend workspace, runs init, and runs force-unlock -force.
        FD-7L Phase 2b (P1): the lock object is read first (an ordinary OpenTofu lock here)."""
        mock_subprocess.side_effect = [
            {"success": True, "exit_code": 0, "stdout": "init ok", "stderr": ""},
            {"success": True, "exit_code": 0, "stdout": "Lock 1725822600 cleared", "stderr": ""},
        ]

        res = self.service.force_unlock(product_id="myapp", lock_id="1725822600")
        self.assertEqual(res["status"], "UNLOCKED")
        self.assertEqual(res["lock_id"], "1725822600")
        self.assertEqual(res["product_id"], "myapp")

        # Verify subprocess calls
        calls = mock_subprocess.call_args_list
        self.assertEqual(len(calls), 2)
        # Call 1: init
        self.assertIn("init", calls[0][0][0])
        # Call 2: force-unlock
        self.assertEqual(calls[1][0][0], ["terraform", "force-unlock", "-force", "1725822600"])

    @patch("os.path.exists", return_value=True)
    @patch.object(TerraformService, "force_unlock")
    @patch.object(TerraformService, "_run_subprocess")
    def test_apply_plan_old_lock_is_never_force_unlocked(self, mock_subprocess, mock_force_unlock, mock_exists):
        """FD-4H (inverted from the old auto-heal test): even a weeks-old lock is reported, never broken."""
        stale_stderr = """
Error: Error acquiring the state lock
Lock Info:
  ID:        1725822600123456
  Path:      gs://bucket/workloads/test/default.tflock
  Operation: OperationTypeApply
  Who:       dead-runner@castor
  Created:   2026-09-08 10:00:00 UTC
"""
        safe_plan = ('{"configuration": {"root_module": {}}, '   # FD-4AW-b: a real show -json always carries it
                     '"resource_changes": [{"type": "google_storage_bucket", "name": "b", "change": {"actions": ["create"]}}]}')

        def fake_run(cmd, *args, **kwargs):
            if cmd[1] == "show":
                return {"success": True, "exit_code": 0, "stdout": safe_plan, "stderr": ""}
            if cmd[1] == "apply":
                return {"success": False, "exit_code": 1, "stdout": "", "stderr": stale_stderr}
            raise AssertionError(f"unexpected subprocess after a lock error: {cmd}")

        mock_subprocess.side_effect = fake_run

        res = self.service.apply_plan(product_id="testapp", trace_id="trace-123")

        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(res["error_class"], "STATE_LOCKED")
        self.assertTrue(res["error"].startswith("STATE_LOCKED: "))
        self.assertIn('"lock_id": "1725822600123456"', res["error"])
        self.assertEqual(res["lock_info"]["lock_id"], "1725822600123456")
        mock_force_unlock.assert_not_called()
        apply_calls = [c for c in mock_subprocess.call_args_list if c[0][0][1] == "apply"]
        self.assertEqual(len(apply_calls), 1)
        self.assertFalse(any(c[0][0][1] == "force-unlock" for c in mock_subprocess.call_args_list))

    def test_fetch_repo_files_fetches_from_specified_branch(self):
        """_fetch_repo_files must fetch tree and raw content from the specified branch."""
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_mocktoken"}), \
             patch("service.VCSProviderFactory", None), \
             patch("httpx.Client") as mock_httpx:

            mock_client = MagicMock()
            tree_resp = MagicMock(status_code=200)
            tree_resp.json.return_value = {
                "tree": [
                    {"path": "main.py", "type": "blob"},
                ]
            }
            blob_resp = MagicMock(status_code=200, text="print('stage version')", content=b"print('stage version')")

            def client_get(url, headers=None):
                if "/git/trees/" in url:
                    self.assertIn("/git/trees/stage?recursive=1", url)
                    return tree_resp
                elif "raw.githubusercontent.com" in url:
                    self.assertIn("/stage/main.py", url)
                    return blob_resp
                return MagicMock(status_code=404)

            mock_client.get.side_effect = client_get
            mock_httpx.return_value.__enter__.return_value = mock_client

            files = self.service._fetch_repo_files(
                product_id="castorcloudruntest-stage",
                github_repo="example-org/castor-castorcloudruntest",
                branch="stage",
            )

            self.assertIn("main.py", files)
            self.assertEqual(files["main.py"], "print('stage version')")

    def test_fetch_repo_files_resolves_default_branch_from_firestore(self):
        """_fetch_repo_files must query Firestore default_branch if branch parameter is omitted."""
        mock_doc = MagicMock(exists=True)
        mock_doc.to_dict.return_value = {
            "github_repo": "example-org/castor-castorcloudruntest",
            "default_branch": "dev",
        }
        self.service.db.collection().document().get.return_value = mock_doc

        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_mocktoken"}), \
             patch("service.VCSProviderFactory", None), \
             patch("httpx.Client") as mock_httpx:

            mock_client = MagicMock()
            tree_resp = MagicMock(status_code=200)
            tree_resp.json.return_value = {"tree": [{"path": "app.py", "type": "blob"}]}
            blob_resp = MagicMock(status_code=200, text="print('dev version')", content=b"print('dev version')")

            def client_get(url, headers=None):
                if "/git/trees/" in url:
                    self.assertIn("/git/trees/dev?recursive=1", url)
                    return tree_resp
                elif "raw.githubusercontent.com" in url:
                    self.assertIn("/dev/app.py", url)
                    return blob_resp
                return MagicMock(status_code=404)

            mock_client.get.side_effect = client_get
            mock_httpx.return_value.__enter__.return_value = mock_client

            files = self.service._fetch_repo_files(
                product_id="castorcloudruntest-dev",
                github_repo="example-org/castor-castorcloudruntest",
            )

            self.assertIn("app.py", files)
            self.assertEqual(files["app.py"], "print('dev version')")

    @patch("service.TerraformService._ensure_binary", return_value="/usr/local/bin/terraform")  # RT14-22: never PATH
    @patch.object(TerraformService, "_fetch_repo_files", return_value={})
    @patch.object(TerraformService, "prepare_workspace")
    @patch.object(TerraformService, "_build_and_push_container")
    @patch.object(TerraformService, "_ensure_provider_mirror")
    @patch.object(TerraformService, "_run_subprocess")
    def test_state_lock_during_the_gated_plan_is_labelled_plan(
        self, mock_subprocess, mock_mirror, mock_build, mock_prepare, mock_fetch, mock_which,
    ):
        """PR-0 tip RT N2: a lock held when the gated helper plans is STATE_LOCKED with phase "plan" (was "apply");
        nothing is applied and the lock is never broken."""
        ws_dir = os.path.join(self.workspace_base, "trace-lock", "lockapp")
        os.makedirs(ws_dir, exist_ok=True)
        with open(os.path.join(ws_dir, "main.tf"), "w") as f:
            f.write("# main")
        mock_prepare.return_value = ws_dir
        mock_build.return_value = "us-central1-docker.pkg.dev/test-proj/lockapp/app:latest"
        fresh = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lock_stderr = (
            "\nError: Error acquiring the state lock\nLock Info:\n  ID:        42\n"
            "  Path:      gs://bucket/workloads/lockapp/default.tflock\n  Operation: OperationTypeApply\n"
            f"  Who:       other-runner@castor\n  Created:   {fresh}\n"
        )

        def fake_run(cmd, *args, **kwargs):
            if cmd[1] == "plan":
                return {"success": False, "exit_code": 1, "stdout": "", "stderr": lock_stderr}
            if cmd[1] in ("apply", "force-unlock"):
                raise AssertionError(f"must not run after a lock error: {cmd}")
            return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

        mock_subprocess.side_effect = fake_run
        with patch("google.auth.default", return_value=(MagicMock(), "test-proj")), \
                patch("google.auth.transport.requests.AuthorizedSession"), patch("httpx.Client"):
            res = self.service.deploy_workload(product_id="lockapp", trace_id="trace-lock",
                                               hcl_files={"main.tf": "# tf"}, target_project_id="target-project-123")
        self.assertEqual(res["error_class"], "STATE_LOCKED")
        self.assertIn("detected at plan)", res["error"])

    @patch("service.TerraformService._ensure_binary", return_value="/usr/local/bin/terraform")  # RT14-22: never PATH
    @patch.object(TerraformService, "_fetch_repo_files", return_value={})
    @patch.object(TerraformService, "prepare_workspace")
    @patch.object(TerraformService, "_build_and_push_container")
    @patch.object(TerraformService, "_ensure_provider_mirror")
    @patch.object(TerraformService, "_run_subprocess")
    def test_compliance_refusal_inside_the_idp_retry_is_typed_and_main_tf_untouched(
        self, mock_subprocess, mock_mirror, mock_build, mock_prepare, mock_fetch, mock_which,
    ):
        """Lane 14 PR-0 RT F2: a gate refusal raised by the gated apply inside the IdP initializeAuth retry is not
        swallowed by that block's `except Exception`: deploy_workload returns the typed refusal and the IdP-block
        HCL rewrite never runs."""
        import service as tf_service

        ws_dir = os.path.join(self.workspace_base, "trace-idp", "idpapp")
        os.makedirs(ws_dir, exist_ok=True)
        main_tf = (
            'resource "google_identity_platform_default_supported_idp_config" "google_idp" {\n'
            '  enabled = true\n  idp_id = "google.com"\n  client_id = "x"\n  client_secret = "y"\n}\n}\n'
        )
        with open(os.path.join(ws_dir, "main.tf"), "w") as f:
            f.write(main_tf)
        mock_prepare.return_value = ws_dir
        mock_build.return_value = "us-central1-docker.pkg.dev/test-proj/idpapp/app:latest"
        mock_subprocess.return_value = {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}
        refusal = {"status": "FAILED", "error_class": "COMPLIANCE_VIOLATION", "error": "COMPLIANCE_VIOLATION: x",
                   "product_id": "idpapp", "trace_id": "trace-idp", "compliance_gate": {}}
        idp_err = {"success": False, "exit_code": 1, "stdout": "",
                   "stderr": "Error: CONFIGURATION_NOT_FOUND on google_identity_platform_default_supported_idp_config"}
        gated = MagicMock(side_effect=[idp_err, tf_service.compliance_gate.ComplianceGateRefused(refusal)])
        with patch.object(self.service, "_compliance_gated_apply", gated), \
                patch("google.auth.default", return_value=(MagicMock(), "test-proj")), \
                patch("google.auth.transport.requests.AuthorizedSession"), patch("httpx.Client"):
            res = self.service.deploy_workload(
                product_id="idpapp", trace_id="trace-idp", hcl_files={"main.tf": main_tf},
                target_project_id="target-project-123",
            )
        self.assertEqual(gated.call_count, 2)
        self.assertEqual(res["error_class"], "COMPLIANCE_VIOLATION")
        self.assertEqual(res["status"], "FAILED")
        with open(os.path.join(ws_dir, "main.tf")) as f:
            self.assertEqual(f.read(), main_tf)  # the IdP-block regex rewrite never ran

    @patch("service.TerraformService._ensure_binary", return_value="/usr/local/bin/terraform")  # RT14-22: never PATH
    @patch.object(TerraformService, "_fetch_repo_files", return_value={})
    @patch.object(TerraformService, "prepare_workspace")
    @patch.object(TerraformService, "_build_and_push_container")
    @patch.object(TerraformService, "_ensure_provider_mirror")
    @patch.object(TerraformService, "_run_subprocess")
    def test_auto_import_cloud_run_service_on_409(
        self,
        mock_subprocess,
        mock_mirror,
        mock_build,
        mock_prepare,
        mock_fetch,
        mock_which,
    ):
        """Verify that a 409 Error creating Service triggers auto-import into Terraform state and retries apply."""
        ws_dir = os.path.join(self.workspace_base, "trace-123", "testapp")
        os.makedirs(ws_dir, exist_ok=True)
        with open(os.path.join(ws_dir, "main.tf"), "w") as f:
            f.write("# main")
        mock_prepare.return_value = ws_dir
        mock_build.return_value = "us-central1-docker.pkg.dev/test-proj/testapp/app:latest"

        crun_409_err = (
            "Error: Error creating Service: googleapi: Error 409: Resource 'testapp' already exists.\n\n"
            "  with module.compute.google_cloud_run_v2_service.app,\n"
            "  on main.tf line 5, in resource \"google_cloud_run_v2_service\" \"app\":\n"
            "   5: resource \"google_cloud_run_v2_service\" \"app\" {\n"
        )

        # 1. init: success
        # 2. validate: success
        # (FD-4CY W7: no `state list` any more; Pass 0 adopts from the gated plan: its GET is not a 200 here)
        # 3-5. gated apply (lane 14 PR-0 RT F4): plan -out, show -json, apply <plan file>: fails with 409
        # 6. import at the plan's address, id from the planned attributes: succeeds
        # 7-9. gated retry: plan, show, apply <plan file>: succeeds
        # 10. output: succeeds
        planned = {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}
        # FD-4AW-b: with `configuration`, like real tofu. FD-4CY W7: the planned create the 409 names.
        create = {"address": "module.compute.google_cloud_run_v2_service.app", "mode": "managed",
                  "type": "google_cloud_run_v2_service",
                  "change": {"actions": ["create"], "after_unknown": {"uri": True},
                             "after": {"name": "testapp", "location": "us-central1", "project": "target-project-123"}}}
        shown = {"success": True, "exit_code": 0, "stderr": "",
                 "stdout": json.dumps({"format_version": "1.2", "configuration": {"root_module": {}},
                                       "resource_changes": [create]})}
        shown_after = {"success": True, "exit_code": 0, "stderr": "",
                       "stdout": '{"format_version": "1.2", "configuration": {"root_module": {}}, "resource_changes": []}'}
        mock_subprocess.side_effect = [
            {"success": True, "exit_code": 0, "stdout": "Initialized", "stderr": ""},
            {"success": True, "exit_code": 0, "stdout": "Success", "stderr": ""},
            planned, shown,
            {"success": False, "exit_code": 1, "stdout": "", "stderr": crun_409_err},
            {"success": True, "exit_code": 0, "stdout": "Import successful", "stderr": ""},
            planned, shown_after,
            {"success": True, "exit_code": 0, "stdout": "Apply complete!", "stderr": ""},
            {"success": True, "exit_code": 0, "stdout": '{"service_url": {"value": "https://test.run.app"}}', "stderr": ""},
        ]

        with patch("google.auth.default", return_value=(MagicMock(), "test-proj")):
            with patch("google.auth.transport.requests.AuthorizedSession"), patch("httpx.Client"):
                res = self.service.deploy_workload(
                    product_id="testapp",
                    trace_id="trace-123",
                    hcl_files={"main.tf": "# tf"},
                    target_project_id="target-project-123",
                )

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(mock_subprocess.call_count, 10)
        # FD-4B (D-1): exactly one import -- the Universal 409 engine must not re-import the address.
        import_calls = [c for c in mock_subprocess.call_args_list if c[0][0][1] == "import"]
        self.assertEqual(len(import_calls), 1)
        # RT F4: both applies apply the gated plan file.
        apply_cmds = [c[0][0] for c in mock_subprocess.call_args_list if c[0][0][1] == "apply"]
        self.assertEqual(len(apply_cmds), 2)
        self.assertTrue(all(cmd[-1] == "stackvend-compliance.tfplan" for cmd in apply_cmds))

        # Inspect the subprocess call that imports
        import_call_cmd = mock_subprocess.call_args_list[5][0][0]
        self.assertEqual(import_call_cmd[0], "terraform")
        self.assertEqual(import_call_cmd[1], "import")
        self.assertEqual(import_call_cmd[3], "module.compute.google_cloud_run_v2_service.app")
        self.assertEqual(
            import_call_cmd[4],
            "projects/target-project-123/locations/us-central1/services/testapp",
        )


if __name__ == "__main__":
    unittest.main()


