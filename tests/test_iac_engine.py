"""
Unit Tests for Dual IaC Engine Support (OpenTofu and Terraform)
Validates schema validation, settings persistence, binary resolution,
unified CLI provider mirroring, preflight validator, and vending propagation.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
cc_dir = os.path.join(repo_root, "apps", "control-center")
mcp_tf_dir = os.path.join(repo_root, "mcp-servers", "terraform")
gw_dir = os.path.join(repo_root, "apps", "orchestrator-gateway")

for p in [repo_root, cc_dir, mcp_tf_dir, gw_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Mock GCP cloud libraries before imports if not installed locally
for mod in [
    "google", "google.auth", "google.oauth2", "google.cloud",
    "google.cloud.firestore", "google.cloud.storage", "google.cloud.pubsub_v1"
]:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

from shared.settings import (
    IaCEngineType,
    OrchestrationSettings,
    PlatformSettings,
)
import schemas as cc_schemas
import service as tf_service_mod


class TestDualIaCEngineSupport(unittest.TestCase):
    def test_iac_engine_enum_and_settings_defaults(self):
        """Validates IaCEngineType enum values and OrchestrationSettings defaults."""
        self.assertEqual(IaCEngineType.TERRAFORM.value, "TERRAFORM")
        self.assertEqual(IaCEngineType.OPENTOFU.value, "OPENTOFU")

        orch = OrchestrationSettings()
        self.assertEqual(orch.default_iac_engine, "OPENTOFU")
        self.assertEqual(orch.terraform_version, "1.5.7")
        self.assertEqual(orch.tofu_version, "1.9.0")
        self.assertIn("1.5.7", orch.supported_terraform_versions)
        self.assertIn("1.9.0", orch.supported_tofu_versions)

    def test_dynamic_custom_versions_persistence(self):
        """Admins can append custom versions to supported lists without code changes."""
        orch = OrchestrationSettings()
        custom_tofu = "1.9.5"
        orch.supported_tofu_versions.append(custom_tofu)
        orch.tofu_version = custom_tofu

        settings = PlatformSettings(orchestration=orch)
        serialized = settings.model_dump()

        self.assertIn(custom_tofu, serialized["orchestration"]["supported_tofu_versions"])
        self.assertEqual(serialized["orchestration"]["tofu_version"], custom_tofu)

    def test_workload_request_and_summary_schemas(self):
        """Validates workload request parsing and summary serialization with iac_engine."""
        req_tofu = cc_schemas.CreateWorkloadRequest(
            product_id="order-service",
            title="Order Processing",
            spec_content="Order service spec",
            iac_engine="OPENTOFU",
        )
        self.assertEqual(req_tofu.iac_engine, "OPENTOFU")

        req_default = cc_schemas.CreateWorkloadRequest(
            product_id="default-service",
            title="Default Engine Service",
            spec_content="Default spec",
        )
        self.assertIsNone(req_default.iac_engine)

        summary = cc_schemas.WorkloadSummary(
            product_id="order-service",
            project_id="order-service-proj",
            status="ACTIVE",
            budget_ceiling_monthly_usd=50.0,
            iac_engine="OPENTOFU",
        )
        self.assertEqual(summary.iac_engine, "OPENTOFU")

        details = cc_schemas.WorkloadDetailsResponse(
            product_id="order-service",
            project_id="order-service-proj",
            status="ACTIVE",
            budget_ceiling_monthly_usd=50.0,
            iac_engine="OPENTOFU",
            terraform_version="1.9.0",
        )
        self.assertEqual(details.iac_engine, "OPENTOFU")

    @patch("service.shutil.which")
    def test_binary_resolution_for_terraform_and_tofu(self, mock_which):
        """Tests that _ensure_binary finds tofu or terraform and honors cache fallback."""
        svc = tf_service_mod.TerraformService(project_id="test-p", state_bucket="test-b")

        mock_which.side_effect = lambda cmd: "/usr/local/bin/" + cmd if cmd in ("terraform", "tofu") else None

        # RT14-22: a PATH binary is never used. Terraform 1.5.7 has a pinned row since RT14 RT D1; offline, its
        # download fails -> typed refusal (never the PATH binary).
        with patch("binary_checksums.fetch_to", side_effect=OSError("offline test")), \
                self.assertRaises(tf_service_mod.EngineUnverifiable):
            svc._ensure_binary(engine="TERRAFORM", version="1.5.7")

        # FD-05 B-7: Terraform >= 1.6.0 (BSL) is refused by policy (6677523), even when present on PATH.
        with self.assertRaises(ValueError):
            svc._ensure_binary(engine="TERRAFORM", version="1.7.5")

        # RT14-22: OpenTofu 1.9.0 is downloaded and verified; a zip that does not match the pinned sha256 is refused
        def _wrong_zip(url, fobj, max_bytes, timeout=None):
            fobj.write(b"not the release zip")
        with patch("binary_checksums.fetch_to", side_effect=_wrong_zip):  # RT14 RT F2: the bounded fetch primitive
            with self.assertRaises(tf_service_mod.EngineUnverifiable) as ctx:
                svc._ensure_binary(engine="OPENTOFU", version="1.9.0")
        self.assertIn("!= owner-verified", str(ctx.exception))

    @patch("binary_checksums.fetch_to", side_effect=OSError("offline test"))  # FD-4BQ fetch primitive
    def test_provider_mirror_generates_dual_registries(self, mock_fetch):
        """Validates that _ensure_provider_mirror writes mirror blocks for both HashiCorp and OpenTofu registries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = tf_service_mod.TerraformService(
                project_id="test-p", state_bucket="test-b", workspace_base_dir=tmpdir
            )
            rc_path = svc._ensure_provider_mirror()

            self.assertTrue(os.path.exists(rc_path))
            with open(rc_path, "r") as f:
                content = f.read()

            # FD-05 B-8: exact provider addresses for BOTH registries (5a02919 / a162b1c), not wildcards.
            for addr in ("registry.terraform.io/hashicorp/google", "registry.terraform.io/hashicorp/google-beta",
                         "registry.opentofu.org/hashicorp/google", "registry.opentofu.org/hashicorp/google-beta"):
                self.assertIn(f'"{addr}"', content)
            self.assertNotIn("/*/*", content)
            self.assertIn("filesystem_mirror", content)
            self.assertIn("direct {\n    include = [", content)   # FD-4AQ W1b: limited to the allow-list
            self.assertNotIn("direct {}", content)

    @patch("service.subprocess.Popen")
    def test_run_subprocess_engine_swapping(self, mock_run):
        """Tests that _run_subprocess swaps the command binary based on iac_engine."""
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.communicate.return_value = ("OK", "")
        mock_run.return_value = mock_res

        # Hermetic (FD-4BO follow-up): a private workspace root under TMPDIR, and the provider-mirror seam mocked.
        # The real _ensure_provider_mirror downloads linux provider zips into <root>/.castor-tooling/plugin_mirror
        # whenever a version dir holds no binary, so this test used to pass or fail depending on what an earlier
        # run had left in the hard-coded /tmp/castor_tf_workspaces (an empty skeleton -> 16 blocked downloads).
        # The mirror itself is covered by test_provider_mirror_generates_dual_registries.
        tmpdir_ctx = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir_ctx.cleanup)
        tmpdir = tmpdir_ctx.name
        svc = tf_service_mod.TerraformService(project_id="test-p", state_bucket="test-b", workspace_base_dir=tmpdir)
        rc_path = os.path.join(tmpdir, "terraform.rc")
        with open(rc_path, "w") as f:
            f.write("provider_installation {\n  direct {}\n}\n")

        with patch.object(svc, "_ensure_binary", side_effect=lambda engine, version=None: f"/opt/bin/{engine.lower()}"), \
             patch.object(svc, "_ensure_provider_mirror", return_value=rc_path) as mirror:
            result = svc._run_subprocess(["terraform", "version"], cwd=tmpdir, iac_engine="OPENTOFU")
            mirror.assert_called_once_with()
            self.assertTrue(result["success"])

            called_cmd = mock_run.call_args[0][0]
            self.assertEqual(called_cmd[0], "/opt/bin/opentofu")

            called_env = mock_run.call_args[1].get("env", {})
            self.assertEqual(called_env.get("TF_CLI_CONFIG_FILE"), rc_path)
            self.assertEqual(called_env.get("TF_PLUGIN_CACHE_DIR"), os.path.join(svc.tooling_dir, "plugin_cache"))


if __name__ == "__main__":
    unittest.main()
