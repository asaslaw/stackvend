"""
Project Castor: Unit Tests for OpenTofu & Terraform Dual-Engine Runtime & Guardrails
Covers:
- Guardrail 1: One-way state gate (OpenTofu -> Terraform downgrade strictly blocked)
- Engine ceiling: Terraform max version constraint (strictly <= 1.5.7)
- Guardrail 2: Ephemeral workspace path rewriting (../bundles/ -> ./infra/bundles/)
- REST / MCP engine parameter propagation and persistence
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add BASE_DIR to sys.path first
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import importlib.util
TERRAFORM_MCP_DIR = os.path.join(BASE_DIR, "mcp-servers", "terraform")
_tf_service_spec = importlib.util.spec_from_file_location(
    "tf_service", os.path.join(TERRAFORM_MCP_DIR, "service.py")
)
tf_service_mod = importlib.util.module_from_spec(_tf_service_spec)
_tf_service_spec.loader.exec_module(tf_service_mod)

TerraformService = tf_service_mod.TerraformService
IaCEngineDowngradeBlockedError = tf_service_mod.IaCEngineDowngradeBlockedError


class TestOpenTofuDualEngine(unittest.TestCase):
    """Test suite for OpenTofu v1.9.0 and Terraform v1.5.7 dual-engine runtime."""

    def setUp(self):
        self.mock_db = MagicMock()
        self.service = TerraformService(db=self.mock_db)

    def test_terraform_binary_version_ceiling_enforced(self):
        """Terraform binary must be strictly <= 1.5.7; >= 1.6.0 is forbidden to eliminate BSL code."""
        with patch.dict(os.environ, {"TERRAFORM_VERSION": "1.6.0"}):
            with self.assertRaises(ValueError) as ctx:
                self.service._ensure_binary(engine="terraform")
            self.assertIn("Terraform >= 1.6.0 is strictly forbidden", str(ctx.exception))

    def test_opentofu_binary_resolution(self):
        """OpenTofu engine resolves to the verified `tofu_<version>` binary (RT14-22: never a PATH or a cached
        unverified file; a failed download is the typed EngineUnverifiable, never the bare name)."""
        with patch.dict(os.environ, {"OPENTOFU_VERSION": "1.9.0"}), \
                patch.object(tf_service_mod.shutil, "which", return_value="/usr/local/bin/tofu"), \
                patch.object(tf_service_mod._binary_checksums_module(), "fetch_to", side_effect=OSError("offline")):
            with self.assertRaises(tf_service_mod.EngineUnverifiable) as ctx:
                self.service._ensure_binary(engine="tofu")
        self.assertEqual(ctx.exception.error_class, "ENGINE_UNVERIFIABLE")

    def test_guardrail_1_downgrade_blocked_when_prior_state_is_tofu(self):
        """G1: Blocking OpenTofu -> Terraform downgrade with IaCEngineDowngradeBlockedError."""
        # Setup mock Firestore returning applied_iac_engine = 'tofu'
        doc_mock = MagicMock()
        doc_mock.exists = True
        doc_mock.to_dict.return_value = {
            "applied_iac_engine": "tofu",
            "status": "APPLIED",
        }
        self.mock_db.collection.return_value.document.return_value.get.return_value = doc_mock

        with self.assertRaises(IaCEngineDowngradeBlockedError) as ctx:
            self.service._validate_no_engine_downgrade("prod-web-stack", "terraform")

        self.assertIn("Guardrail 1 Violation", str(ctx.exception))
        self.assertIn("cannot be downgraded to Terraform", str(ctx.exception))

    def test_guardrail_1_upgrade_from_terraform_to_tofu_allowed(self):
        """G1: Terraform -> OpenTofu transition is fully permissible."""
        doc_mock = MagicMock()
        doc_mock.exists = True
        doc_mock.to_dict.return_value = {
            "applied_iac_engine": "terraform",
            "status": "APPLIED",
        }
        self.mock_db.collection.return_value.document.return_value.get.return_value = doc_mock

        # Should not raise exception
        self.service._validate_no_engine_downgrade("prod-web-stack", "tofu")

    def test_guardrail_1_same_engine_allowed(self):
        """Running OpenTofu on an OpenTofu state is normal operation."""
        doc_mock = MagicMock()
        doc_mock.exists = True
        doc_mock.to_dict.return_value = {
            "applied_iac_engine": "tofu",
            "status": "APPLIED",
        }
        self.mock_db.collection.return_value.document.return_value.get.return_value = doc_mock

        self.service._validate_no_engine_downgrade("prod-web-stack", "tofu")

    def test_guardrail_2_exact_text_rewriter_is_deleted(self):
        """G2 (SAT-01 / FD4BD-Q2): the exact-text `_rewrite_bundle_and_module_paths` had no production caller and is
        deleted. The flattened root's module sources are re-anchored from the parse tree only
        (rewrite_flattened_module_sources); bundles and vendored modules reach the workspace byte-identical
        (tests/test_sat01_deploy_tfvars.py pins both)."""
        self.assertFalse(hasattr(self.service, "_rewrite_bundle_and_module_paths"))
        self.assertFalse(hasattr(type(self.service), "_rewrite_bundle_and_module_paths"))

    def test_engine_parameter_normalization(self):
        """Engine defaults to tofu when unspecified or empty."""
        self.assertEqual(self.service._normalize_engine(None), "tofu")
        self.assertEqual(self.service._normalize_engine(""), "tofu")
        self.assertEqual(self.service._normalize_engine("OPENTOFU"), "tofu")
        self.assertEqual(self.service._normalize_engine("terraform"), "terraform")
        self.assertEqual(self.service._normalize_engine("TF"), "terraform")


if __name__ == "__main__":
    unittest.main()
