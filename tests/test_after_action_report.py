"""
Unit tests for Autonomous Mission Debrief & Self-Healing Ledger (AAR).
Validates marker harvesting, dual-mode synthesis (Success with Healing vs Failure),
and Pydantic contract serialization.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import sys
import os

# Add apps/control-center to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "control-center")))

import unittest
from schemas import (
    AAROutcomeType,
    AARResponse,
    AfterActionReport,
    BlastRadius,
    RemediationPlan,
    RootCauseAnalysis,
    SelfHealingIntervention,
)
from routes.telemetry import (
    harvest_self_healing_markers,
    synthesize_after_action_report,
)


class TestAfterActionReport(unittest.TestCase):

    def setUp(self):
        # These tests assert the deterministic-rules synthesis. Without this patch
        # synthesize_after_action_report makes a live Gemini call whenever ADC is
        # available (it used to be masked only by stubs leaked from other files).
        # AAR-SETTINGS-MODEL: the model step is aar_model_report; here every model "failed" (typed)
        from unittest.mock import patch
        from routes.telemetry import AARModelFailure
        patcher = patch("routes.telemetry.aar_model_report",
                        side_effect=AARModelFailure("AAR_MODEL_CALL_FAILED", [{"model": "m", "error": "down"}]))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_harvest_self_healing_markers_comprehensive(self):
        """Tests deterministic extraction of all self-healing categories from logs and stages."""
        sample_logs = [
            {"message": "INFO:mcp-terraform-server:🛡️ Physical package sanitization: generated missing '__init__.py' in 'apps/service-b/schemas'", "severity": "INFO"},
            {"message": "INFO:mcp-terraform-server:Dynamic API enablement completed on 'testplan02-a-63d952' for batch: ['compute.googleapis.com', 'vpcaccess.googleapis.com']", "severity": "INFO"},
            {"message": "INFO:mcp-terraform-server:Self-healed invalid CIDR declaration: var.vpc_connector_cidr normalized to 10.8.0.0/28", "severity": "INFO"},
            {"message": "INFO:mcp-terraform-server:Pre-apply reconciler populated missing/empty variable 'vpc_connector_name' = \"castor-vpc-conn\" in terraform.tfvars", "severity": "INFO"},
            {"message": "INFO:mcp-terraform-server:Universal 409 Resource Adoption Engine intercepted existing GCP entity in OpenTofu diagnostics...", "severity": "INFO"},
            {"message": "INFO:mcp-terraform-server:Auto-cured self-referential block in main.tf", "severity": "INFO"},
        ]

        sample_stages = {
            "architect": {
                "details": {
                    "architect_consensus": {
                        "remediation_performed": True,
                        "remediation_diff_summary": "Auto-Patched Invariant Violations in subnets"
                    }
                }
            }
        }

        interventions = harvest_self_healing_markers(sample_logs, sample_stages)

        categories = [i.category for i in interventions]
        self.assertIn("PACKAGING", categories)
        self.assertIn("GCP_APIS", categories)
        self.assertIn("NETWORKING_CIDR", categories)
        # FD-55 W6c: the reconciler / self-reference markers no longer count (their apply-side healers are deleted)
        self.assertNotIn("SYNTAX_HEALING", categories)
        self.assertIn("RESOURCE_ADOPTION", categories)
        self.assertIn("CONSENSUS_AUDIT", categories)

        # Check packaging intervention details
        self.assertEqual(len(interventions), 5)   # PACKAGING, GCP_APIS, NETWORKING_CIDR, RESOURCE_ADOPTION, CONSENSUS

        pkg_item = next(i for i in interventions if i.category == "PACKAGING")
        self.assertEqual(pkg_item.component, "apps/service-b/schemas")
        self.assertIn("__init__.py", pkg_item.autonomous_cure)

    def test_deleted_apply_heal_markers_are_no_longer_counted(self):
        """FD-55 W6c (register FD55-W6c): the reconciler (A42) and self-reference (A47) markers are not harvested any
        more (their healers are deleted); a kept marker beside them still counts (negative)."""
        logs = [
            {"message": "INFO:mcp-terraform-server:Pre-apply reconciler populated missing/empty variable 'x' = \"y\" "
                        "in terraform.tfvars"},
            {"message": "INFO:mcp-terraform-server:Auto-cured self-referential block in /ws/custom.tf"},
        ]
        self.assertEqual(harvest_self_healing_markers(logs, {}), [])
        kept = harvest_self_healing_markers(
            logs + [{"message": "Universal 409 Resource Adoption Engine intercepted x"}], {})
        self.assertEqual([i.category for i in kept], ["RESOURCE_ADOPTION"])

    def test_synthesize_success_with_healing(self):
        """Tests debrief synthesis on a successful run that had self-healing interventions."""
        harvested = [
            SelfHealingIntervention(
                category="PACKAGING",
                component="apps/service-b/schemas",
                issue_detected="Missing __init__.py",
                autonomous_cure="Synthesized valid __init__.py descriptor"
            )
        ]
        outputs = {
            "service_url": "https://api-gateway-123.run.app",
            "service_b_url": "https://service-b-123.run.app"
        }

        aar = synthesize_after_action_report(
            trace_id="test-trace-success",
            product_id="testplan02-a",
            status="SUCCEEDED",
            harvested_interventions=harvested,
            error_message=None,
            stages_dict={"terraform": {"status": "SUCCESS"}},
            outputs_dict=outputs,
            cloud_logs=[],
        )

        self.assertEqual(aar.status, "SUCCEEDED")
        self.assertEqual(aar.outcome_type, AAROutcomeType.SUCCESS_WITH_HEALING)
        self.assertEqual(len(aar.self_healing_interventions), 1)
        self.assertIn("https://api-gateway-123.run.app", aar.live_service_urls)
        self.assertIsNone(aar.root_cause)

    def test_deploy_health_wording_success_says_deployed_not_serving(self):
        """DEPLOY-HEALTH-WORDING (owner 10-27): no health probe runs, so a success AAR never says "serving"."""
        from unittest.mock import patch
        from routes.telemetry import AARModelFailure
        for harvested in ([], [SelfHealingIntervention(category="IAC", component="main.tf", issue_detected="x",
                                                         autonomous_cure="y")]):
            with patch("routes.telemetry.aar_model_report",
                       side_effect=AARModelFailure("AAR_MODEL_CALL_FAILED", [])) as llm:
                aar = synthesize_after_action_report(
                    trace_id="t", product_id="p", status="SUCCEEDED", harvested_interventions=harvested,
                    error_message=None, stages_dict={"terraform": {"status": "SUCCESS"}},
                    outputs_dict={"service_url": "https://p.run.app"}, cloud_logs=[])
            self.assertIn("deployed (no health probe ran)", aar.executive_summary)
            self.assertNotIn("serving", aar.executive_summary)
            self.assertNotIn("healthy", aar.executive_summary)
            prompt = llm.call_args.args[0]
            self.assertIn("Deployed Service URLs (no health probe ran; do not claim they are healthy or serving)", prompt)
            self.assertNotIn("Live Service URLs", prompt)

    def test_synthesize_failure_naming_regex(self):
        """Tests post-mortem synthesis on a failure with regexp mismatch on variable."""
        error_msg = 'Error: "name" ("10.10.0.0/24") doesn\'t match regexp "^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$"'

        aar = synthesize_after_action_report(
            trace_id="test-trace-fail",
            product_id="testplan02-c",
            status="FAILED",
            harvested_interventions=[],
            error_message=error_msg,
            stages_dict={"terraform": {"status": "FAILED", "error": error_msg}},
            outputs_dict={},
            cloud_logs=[],
        )

        self.assertEqual(aar.status, "FAILED")
        self.assertEqual(aar.outcome_type, AAROutcomeType.FAILURE_RECOVERABLE)
        self.assertIsNotNone(aar.root_cause)
        self.assertEqual(aar.root_cause.failure_class, "TYPE_SEMANTIC_MISMATCH")
        self.assertIsNotNone(aar.remediation)
        self.assertEqual(aar.remediation.recommended_mode, "FULL")

    def test_pydantic_aar_response_serialization(self):
        """Tests that AARResponse and AfterActionReport serialize and deserialize cleanly."""
        report = AfterActionReport(
            trace_id="trace-abc",
            product_id="test-prod",
            status="SUCCEEDED",
            outcome_type=AAROutcomeType.SUCCESS_CLEAN,
            executive_summary="Clean build without interventions",
            self_healing_interventions=[],
            generated_at="2026-10-11T16:00:00Z",
            model_used="deterministic-rules"
        )
        resp = AARResponse(has_aar=True, aar=report, latest_trace_id="trace-abc", latest_status="SUCCEEDED")

        json_bytes = resp.model_dump_json()
        self.assertIn("trace-abc", json_bytes)
        self.assertIn("SUCCESS_CLEAN", json_bytes)

        # Deserialize
        reloaded = AARResponse.model_validate_json(json_bytes)
        self.assertTrue(reloaded.has_aar)
        self.assertEqual(reloaded.aar.trace_id, "trace-abc")
        self.assertEqual(reloaded.latest_trace_id, "trace-abc")
        self.assertEqual(reloaded.latest_status, "SUCCEEDED")

    def test_workload_execution_run_serialization(self):
        """Tests that WorkloadExecutionRun model contracts serialize and deserialize properly."""
        from schemas import WorkloadExecutionRun

        run = WorkloadExecutionRun(
            trace_id="trace-xyz-123",
            started_at="2026-10-11T12:00:00Z",
            completed_at="2026-10-11T12:05:00Z",
            status="SUCCEEDED",
            feature_title="Test Feature",
            has_aar=True,
            outcome_type="SUCCESS_WITH_HEALING",
            healing_count=3,
        )

        run_json = run.model_dump_json()
        self.assertIn("trace-xyz-123", run_json)
        self.assertIn("SUCCESS_WITH_HEALING", run_json)

        deserialized = WorkloadExecutionRun.model_validate_json(run_json)
        self.assertEqual(deserialized.trace_id, "trace-xyz-123")
        self.assertEqual(deserialized.healing_count, 3)
        self.assertTrue(deserialized.has_aar)


if __name__ == "__main__":
    unittest.main()

