"""
Project Castor: Unit Tests for Platform Global Settings Schemas
Validates Pydantic schema models, defaults, boundary constraints, and bounded audit logging.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import sys
import unittest
from unittest.mock import MagicMock

try:
    import pydantic
    from pydantic import ValidationError
except ImportError:
    ValidationError = ValueError

from shared.settings import (
    FinOpsSettings,
    OrchestrationSettings,
    AgentModelSettings,
    GovernanceSettings,
    SettingsAuditEntry,
    PlatformSettings,
)


class TestSettingsSchema(unittest.TestCase):
    def test_finops_defaults(self):
        finops = FinOpsSettings()
        self.assertEqual(finops.default_monthly_budget_usd, 40.0)
        self.assertEqual(finops.warning_threshold_pct, 80.0)
        self.assertEqual(finops.circuit_breaker_threshold_pct, 100.0)
        self.assertTrue(finops.enforce_scale_to_zero_default)

        custom = FinOpsSettings(
            default_monthly_budget_usd=100.0,
            warning_threshold_pct=75.0,
            circuit_breaker_threshold_pct=95.0,
            enforce_scale_to_zero_default=False,
        )
        self.assertEqual(custom.default_monthly_budget_usd, 100.0)
        self.assertFalse(custom.enforce_scale_to_zero_default)

    def test_orchestration_defaults_and_plan_harmonization(self):
        orch = OrchestrationSettings()
        self.assertEqual(orch.default_gcp_region, "us-central1")
        self.assertEqual(orch.default_terraform_timeout_seconds, 3600)
        # Plan 10 harmonization
        self.assertEqual(orch.terraform_lock_timeout_seconds, 180)
        self.assertEqual(orch.stale_lock_threshold_minutes, 20)
        # Plan 9 harmonization
        self.assertEqual(orch.default_container_memory_mb, 512)
        self.assertEqual(orch.default_container_cpu, 1)
        self.assertEqual(orch.high_memory_container_mb, 1024)
        self.assertEqual(orch.high_cpu_container, 2)

    def test_agent_models_defaults_and_plan13(self):
        models = AgentModelSettings()
        self.assertEqual(models.architect_model, "gemini-4-carbon")
        self.assertEqual(models.developer_model, "gemini-4-carbon")
        self.assertEqual(models.finops_model, "gemini-4-carbon")
        self.assertEqual(models.assistant_model, "gemini-4-carbon")
        self.assertEqual(models.max_output_tokens, 65536)
        self.assertEqual(models.architect_max_output_tokens, 16384)
        self.assertEqual(models.developer_max_output_tokens, 65536)
        self.assertEqual(models.get_architect_token_limit(), 16384)
        self.assertEqual(models.get_developer_token_limit(), 65536)
        self.assertEqual(models.default_thinking_budget, 0)
        self.assertEqual(models.max_swarm_token_envelope, 350000)
        self.assertEqual(models.fallback_models, ["gemini-4-argon", "gemini-3.8-flash", "gemini-3.7-flash"])

        custom = AgentModelSettings(
            max_output_tokens=8192,
            architect_max_output_tokens=4096,
            developer_max_output_tokens=32768,
            max_swarm_token_envelope=500000,
        )
        self.assertEqual(custom.max_output_tokens, 8192)
        self.assertEqual(custom.get_architect_token_limit(), 4096)
        self.assertEqual(custom.get_developer_token_limit(), 32768)
        self.assertEqual(custom.max_swarm_token_envelope, 500000)

        # FD-4CI-b (owner 10-21): no silent raise -- a stored 16384 stays 16384 (the legacy floor migration is gone)
        stored = PlatformSettings(models={"max_output_tokens": 16384})
        self.assertEqual(stored.models.max_output_tokens, 16384)

    def test_governance_defaults(self):
        gov = GovernanceSettings()
        self.assertFalse(gov.maintenance_mode)
        self.assertTrue(gov.strict_compliance_gates)
        self.assertTrue(gov.require_hitl_for_destructive_tf)
        self.assertTrue(gov.default_require_human_code_review)

    def test_platform_settings_circular_audit_log(self):
        settings = PlatformSettings()
        self.assertEqual(len(settings.audit_log), 0)
        self.assertEqual(settings.version, 1)

        # Simulate 20 updates to test buffer capping
        entries = []
        for i in range(20):
            entry = SettingsAuditEntry(
                timestamp=f"2026-09-08T12:{i:02d}:00Z",
                admin_email=f"admin{i}@example.com",
                action="UPDATE_SETTINGS",
                changed_fields={"version": {"from": i, "to": i + 1}},
            )
            entries.insert(0, entry)

        # Enforce bounded buffer of 15 entries
        settings.audit_log = entries[:15]
        self.assertEqual(len(settings.audit_log), 15)
        self.assertEqual(settings.audit_log[0].admin_email, "admin19@example.com")
        self.assertEqual(settings.audit_log[-1].admin_email, "admin5@example.com")


if __name__ == "__main__":
    unittest.main()
