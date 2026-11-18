"""
Project Castor: Test Suite for Developer Swarm Flight Deck & Multi-Agent UI Observability
Tests telemetry models, wave metrics, scoped junior stage evals, prompt registry resolution,
workload file attribution serialization, and persona attribution in constraint violations.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure apps/orchestrator-gateway, apps/control-center, and root are in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "apps/orchestrator-gateway"))
sys.path.insert(0, os.path.join(BASE_DIR, "apps/control-center"))
sys.path.insert(0, BASE_DIR)

from developer_agent.swarm_schemas import (
    DeveloperSwarmStageTelemetry,
    JuniorExecutionResult,
    JuniorExecutionTelemetry,
    JuniorPersona,
    WaveExecutionTelemetry,
)
from shared.agent_evaluator import (
    evaluate_agent_execution,
)
from shared.builtin_prompts import (
    AGENT_DISPLAY_METADATA,
    BUILTIN_PROMPTS,
    DEVELOPER_JUNIOR_BACKEND_PROMPT,
    DEVELOPER_JUNIOR_IAC_PROMPT,
)
from schemas import AgentEvalMetric, AttributedConstraintViolation, WorkloadDetailsResponse


@hermetic_guard.unavailable("google.genai.Client", "Gemini")
class TestDeveloperSwarmUITelemetry(unittest.TestCase):

    def test_junior_and_wave_telemetry_schema(self):
        """Verify JuniorExecutionTelemetry, WaveExecutionTelemetry, and DeveloperSwarmStageTelemetry serialization."""
        jr_telemetry = JuniorExecutionTelemetry(
            task_id="task-be-1",
            persona="BACKEND_ENGINEER",
            wave=1,
            status="SUCCEEDED",
            elapsed_seconds=4.2,
            output_tokens=1250,
            assigned_files=["apps/order_api/main.py"],
            retry_count=0,
            error_message=None,
        )

        wave_telemetry = WaveExecutionTelemetry(
            wave_index=1,
            wave_name="Wave 1 - Foundation & Core",
            status="SUCCEEDED",
            elapsed_seconds=5.0,
            tasks=[jr_telemetry],
        )

        swarm_telemetry = DeveloperSwarmStageTelemetry(
            execution_mode="STANDARD_SWARM",
            current_wave=1,
            total_waves=3,
            total_tokens_consumed=1250,
            max_tokens_budget=150000,
            circuit_breaker_tripped=False,
            waves=[wave_telemetry],
            file_attribution={"apps/order_api/main.py": "BACKEND_ENGINEER"},
        )

        dumped = swarm_telemetry.model_dump()
        self.assertEqual(dumped["execution_mode"], "STANDARD_SWARM")
        self.assertEqual(dumped["total_tokens_consumed"], 1250)
        self.assertEqual(dumped["waves"][0]["tasks"][0]["persona"], "BACKEND_ENGINEER")
        self.assertEqual(dumped["file_attribution"]["apps/order_api/main.py"], "BACKEND_ENGINEER")
        self.assertFalse(dumped["circuit_breaker_tripped"])

    def test_junior_execution_result_rendered_prompt(self):
        """Verify that JuniorExecutionResult correctly carries rendered_prompt for Glass Pane inspection."""
        result = JuniorExecutionResult(
            task_id="task-iac-1",
            persona=JuniorPersona.IAC_ENGINEER,
            wave=1,
            files={"infra/workload/main.tf": 'resource "google_cloud_run_v2_service" "app" {}'},
            duration_seconds=2.8,
            consumed_tokens=650,
            rendered_prompt="System Prompt: You are a Junior IaC Engineer specializing in OpenTofu...",
        )
        self.assertEqual(result.rendered_prompt, "System Prompt: You are a Junior IaC Engineer specializing in OpenTofu...")

    def test_attributed_constraint_violation_in_agent_evaluator(self):
        """Verify AttributedConstraintViolation model and persona/file extraction in evaluator."""
        violation = AttributedConstraintViolation(
            rule_id="RULE-001",
            rule_or_directive="Zero-Dockerfile Mandate",
            persona="BACKEND_ENGINEER",
            file_path="apps/service/Dockerfile",
            violation_message="Forbidden Dockerfile created: apps/service/Dockerfile",
        )
        metric = AgentEvalMetric(
            instruction_adherence_score=0.7,
            grounding_score=1.0,
            tool_efficiency_score=1.0,
            constraint_violations=["Forbidden Dockerfile created: apps/service/Dockerfile"],
            attributed_violations=[violation],
            eval_summary="1 constraint violation detected",
        )
        dumped = metric.model_dump()
        self.assertEqual(len(dumped["attributed_violations"]), 1)
        self.assertEqual(dumped["attributed_violations"][0]["persona"], "BACKEND_ENGINEER")
        self.assertEqual(dumped["attributed_violations"][0]["file_path"], "apps/service/Dockerfile")

    def test_evaluator_persona_attribution_parsing(self):
        """Verify evaluate_agent_execution correctly tags persona and file_path in attributed_violations."""
        raw_output = """
        Generated files:
        apps/api/main.py
        apps/api/Dockerfile
        """
        # Test evaluation with Dockerfile violation
        metric = evaluate_agent_execution(
            stage_name="developer",
            agent_output=raw_output,
            rendered_prompt="Do not create Dockerfiles. Use Cloud Native Buildpacks.",
        )
        self.assertTrue(len(metric.get("constraint_violations", [])) > 0)
        self.assertTrue(len(metric.get("attributed_violations", [])) > 0)
        found_docker = any(
            "Dockerfile" in av.get("violation_message", "") or av.get("file_path") == "Dockerfile"
            for av in metric.get("attributed_violations", [])
        )
        self.assertTrue(found_docker)

    def test_builtin_prompts_and_roster_registry(self):
        """Verify junior persona prompts and display metadata are properly registered."""
        self.assertIn("DEVELOPER_JUNIOR_BACKEND_ENGINEER", BUILTIN_PROMPTS)
        self.assertIn("DEVELOPER_JUNIOR_IAC_ENGINEER", BUILTIN_PROMPTS)
        self.assertIn("DEVELOPER_JUNIOR_FRONTEND_ENGINEER", BUILTIN_PROMPTS)
        self.assertIn("DEVELOPER_JUNIOR_TEST_ENGINEER", BUILTIN_PROMPTS)
        self.assertIn("DEVELOPER_JUNIOR_DEVOPS_ENGINEER", BUILTIN_PROMPTS)
        self.assertIn("DEVELOPER_JUNIOR_DATABASE_ENGINEER", BUILTIN_PROMPTS)

        self.assertIn("DEVELOPER_JUNIOR_BACKEND_ENGINEER", AGENT_DISPLAY_METADATA)
        self.assertEqual(AGENT_DISPLAY_METADATA["DEVELOPER_JUNIOR_BACKEND_ENGINEER"]["name"], "Junior Backend Engineer")

        # Verify prompt content includes Zero-Dockerfile Mandate
        self.assertIn("Zero-Dockerfiles Mandate", DEVELOPER_JUNIOR_BACKEND_PROMPT)
        self.assertIn("Zero-Dockerfiles Mandate", DEVELOPER_JUNIOR_IAC_PROMPT)

    def test_workload_details_file_attribution_schema(self):
        """Verify WorkloadDetailsResponse serializes file_attribution properly."""
        response = WorkloadDetailsResponse(
            product_id="test-product",
            project_id="castor-prod",
            status="ACTIVE",
            budget_ceiling_monthly_usd=100.0,
            current_spend_usd=12.5,
            file_attribution={
                "apps/order_api/main.py": "BACKEND_ENGINEER",
                "infra/workload/main.tf": "IAC_ENGINEER",
                "tests/test_order_api.py": "TEST_ENGINEER",
            },
        )
        dumped = response.model_dump()
        self.assertIn("file_attribution", dumped)
        self.assertEqual(dumped["file_attribution"]["apps/order_api/main.py"], "BACKEND_ENGINEER")
        self.assertEqual(dumped["file_attribution"]["infra/workload/main.tf"], "IAC_ENGINEER")
        self.assertEqual(dumped["file_attribution"]["tests/test_order_api.py"], "TEST_ENGINEER")


if __name__ == "__main__":
    unittest.main()
