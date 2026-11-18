"""
Project Castor: Comprehensive Test Suite for Developer Swarm
Tests the Lead Developer WBS engine, phased wave dispatcher, disjoint partition invariants,
surgical dependency injection, self-healing escalation, FinOps circuit breakers, and zero-dockerfile mandate.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import asyncio
import json
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# Ensure apps/orchestrator-gateway is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../apps/orchestrator-gateway")))

from developer_agent.swarm_schemas import (
    ConflictingFileAssignmentError,
    FinOpsCircuitBreakerError,
    JuniorPersona,
    JuniorTaskAssignment,
    LeadDeveloperDecompositionPlan,
    PoisonedContractEscalationError,
    SwarmExecutionMode,
    UnauthorizedFileCreationError,
)
from developer_agent.lead_orchestrator import LeadDeveloperOrchestrator
from developer_agent.swarm_dispatcher import SwarmDispatcher, stage_junior_files
from developer_agent.handler import is_prohibited_container_file
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; row SWARM-TOK-1)


def validate_zero_dockerfiles(files):
    """FD-55 W5 (G24): the preflight check is deleted; handler.is_prohibited_container_file is the one rule."""
    violations = [f"Dockerfile-class file {p}" for p in files if is_prohibited_container_file(p)]
    return not violations, violations


class TestDeveloperSwarm(unittest.TestCase):

    def test_disjoint_file_partition_invariant_rejection(self):
        """Verify that WBS rejects plans where two tasks touch the same file."""
        with self.assertRaises(ValueError) as ctx:
            LeadDeveloperDecompositionPlan(
                execution_mode=SwarmExecutionMode.STANDARD_SWARM,
                iac_engine="OPENTOFU",
                vcs_provider="GITHUB",
                tasks=[
                    JuniorTaskAssignment(
                        task_id="task-1",
                        persona=JuniorPersona.BACKEND_ENGINEER,
                        wave=1,
                        assigned_files=["apps/workload/main.py", "apps/workload/models.py"],
                        task_objective="Implement backend",
                    ),
                    JuniorTaskAssignment(
                        task_id="task-2",
                        persona=JuniorPersona.FRONTEND_ENGINEER,
                        wave=2,
                        assigned_files=["apps/workload/main.py", "apps/workload/views.html"],  # OVERLAP on main.py!
                        task_objective="Implement frontend",
                    ),
                ],
            )
        self.assertIn("WBS Invariant Violation", str(ctx.exception))
        self.assertIn("apps/workload/main.py", str(ctx.exception))

    def test_unauthorized_file_creation_protection(self):
        """Verify that a junior staging a file outside assigned_files is rejected."""
        staged_tree = {}
        task = JuniorTaskAssignment(
            task_id="task-iac",
            persona=JuniorPersona.IAC_ENGINEER,
            wave=2,
            assigned_files=["infra/workload/main.tf"],
            task_objective="Write infra",
        )
        malicious_files = {
            "infra/workload/main.tf": "terraform {}",
            "apps/order_api/backdoor.py": "import os",  # NOT IN ASSIGNED_FILES!
        }
        with self.assertRaises(UnauthorizedFileCreationError) as ctx:
            stage_junior_files(staged_tree, task, malicious_files)
        self.assertIn("attempted to stage undeclared file", str(ctx.exception))

    def test_conflicting_file_assignment_detection(self):
        """Verify that staging an already-existing file raises ConflictingFileAssignmentError."""
        staged_tree = {"apps/order_api/main.py": "# original"}
        task = JuniorTaskAssignment(
            task_id="task-backend-2",
            persona=JuniorPersona.BACKEND_ENGINEER,
            wave=2,
            assigned_files=["apps/order_api/main.py"],
            task_objective="Overwrite",
        )
        with self.assertRaises(ConflictingFileAssignmentError) as ctx:
            stage_junior_files(staged_tree, task, {"apps/order_api/main.py": "# overwrite"})
        self.assertIn("File collision detected", str(ctx.exception))

    def test_zero_dockerfile_mandate_in_task_assignment(self):
        """Verify that Pydantic schema immediately rejects any task assigned a Dockerfile."""
        with self.assertRaises(ValueError) as ctx:
            JuniorTaskAssignment(
                task_id="task-devops",
                persona=JuniorPersona.DEVOPS_ENGINEER,
                wave=3,
                assigned_files=["Dockerfile", "Procfile"],
                task_objective="Build containers",
            )
        self.assertIn("Platform Mandate Violation", str(ctx.exception))
        self.assertIn("Zero Dockerfiles", str(ctx.exception))

    def test_zero_dockerfile_preflight_validator(self):
        """Verify preflight validator detects and reports Dockerfiles."""
        clean_files = {
            "Procfile": "web: uvicorn main:app",
            "requirements.txt": "fastapi",
        }
        passed, violations = validate_zero_dockerfiles(clean_files)
        self.assertTrue(passed)
        self.assertEqual(len(violations), 0)

        dirty_files = {
            "Procfile": "web: uvicorn main:app",
            "apps/worker/Dockerfile": "FROM python:3.11",
            ".dockerignore": "*.pyc",
        }
        passed, violations = validate_zero_dockerfiles(dirty_files)
        self.assertFalse(passed)
        self.assertEqual(len(violations), 2)
        self.assertTrue(any("Dockerfile" in v for v in violations))

    def test_deterministic_fallback_wbs_plan_generation(self):
        """Verify fallback plan satisfies disjoint partitions and zero dockerfile invariants."""
        lead = LeadDeveloperOrchestrator(genai_client=None)
        plan = lead._build_deterministic_fallback_plan(
            product_id="orders-api",
            iac_engine="OPENTOFU",
            vcs_provider="GITHUB",
        )
        self.assertEqual(plan.execution_mode, SwarmExecutionMode.STANDARD_SWARM)
        self.assertEqual(len(plan.tasks), 5)
        # Verify 3 waves
        waves = set(t.wave for t in plan.tasks)
        self.assertEqual(waves, {1, 2, 3})
        # Verify zero dockerfiles in any task
        for t in plan.tasks:
            for f in t.assigned_files:
                self.assertNotIn("dockerfile", f.lower())

    def test_finops_token_circuit_breaker(self):
        """Verify that exceeding 110% of the token envelope trips the FinOps circuit breaker."""
        plan = LeadDeveloperDecompositionPlan(
            execution_mode=SwarmExecutionMode.STANDARD_SWARM,
            iac_engine="OPENTOFU",
            vcs_provider="GITHUB",
            max_swarm_token_envelope=10_000,  # Small envelope
            tasks=[
                JuniorTaskAssignment(
                    task_id="task-1",
                    persona=JuniorPersona.BACKEND_ENGINEER,
                    wave=1,
                    assigned_files=["apps/api/main.py"],
                    task_objective="Big task",
                ),
            ],
        )

        dispatcher = SwarmDispatcher(genai_client=None)
        # Mock worker to return consumed_tokens exceeding envelope
        async def mock_worker(*args, **kwargs):
            from developer_agent.swarm_schemas import JuniorExecutionResult
            return JuniorExecutionResult(
                task_id="task-1",
                persona=JuniorPersona.BACKEND_ENGINEER,
                wave=1,
                files={"apps/api/main.py": "print('hello')"},
                consumed_tokens=15_000,  # > 10,000 * 1.10 = 11,000!
            )

        dispatcher.invoke_junior_worker = mock_worker

        with self.assertRaises(FinOpsCircuitBreakerError) as ctx:
            asyncio.run(dispatcher.execute_phased_junior_swarm(plan, "trace-123", "orders-api"))
        self.assertIn("FinOps Circuit Breaker Tripped", str(ctx.exception))

    def test_self_healing_retry_ceiling_and_escalation(self):
        """Verify that failing twice escalates to Staff Lead with PoisonedContractEscalationError."""
        task = JuniorTaskAssignment(
            task_id="task-iac",
            persona=JuniorPersona.IAC_ENGINEER,
            wave=2,
            assigned_files=["infra/workload/main.tf"],
            task_objective="Compile impossible HCL",
        )
        plan = LeadDeveloperDecompositionPlan(
            execution_mode=SwarmExecutionMode.STANDARD_SWARM,
            tasks=[task],
        )

        dispatcher = SwarmDispatcher(genai_client=MagicMock())
        # Make the LLM call fail every time
        async def mock_call_gemini(*args, **kwargs):
            raise RuntimeError("HCL Compiler Error: Invalid module contract signature var.vpc_id")

        dispatcher._call_gemini_with_backoff = mock_call_gemini

        with self.assertRaises(PoisonedContractEscalationError) as ctx:
            asyncio.run(dispatcher.invoke_junior_worker(task, plan, {}, "gemini-3.7-flash"))
        self.assertIn("Escalated to Staff Lead Developer", str(ctx.exception))

    def test_surgical_dependency_injection(self):
        """Verify that worker only receives files declared in read_dependencies."""
        plan = LeadDeveloperDecompositionPlan(
            execution_mode=SwarmExecutionMode.STANDARD_SWARM,
            tasks=[
                JuniorTaskAssignment(
                    task_id="task-w1",
                    persona=JuniorPersona.DATABASE_ENGINEER,
                    wave=1,
                    assigned_files=["apps/api/models.py", "apps/api/secret.py"],
                    task_objective="Wave 1",
                ),
                JuniorTaskAssignment(
                    task_id="task-w2",
                    persona=JuniorPersona.TEST_ENGINEER,
                    wave=2,
                    assigned_files=["tests/test_api.py"],
                    read_dependencies=["apps/api/models.py"],  # ONLY MODELS, NOT SECRET!
                    task_objective="Wave 2",
                ),
            ],
        )

        dispatcher = SwarmDispatcher(genai_client=None)

        injected_deps_captured = {}

        async def capture_worker(task, plan_arg, deps, model, *args, **kwargs):
            from developer_agent.swarm_schemas import JuniorExecutionResult
            if task.wave == 1:
                return JuniorExecutionResult(
                    task_id=task.task_id,
                    persona=task.persona,
                    wave=1,
                    files={"apps/api/models.py": "class User: pass", "apps/api/secret.py": "KEY=123"},
                    consumed_tokens=500,
                )
            else:
                injected_deps_captured.update(deps)
                return JuniorExecutionResult(
                    task_id=task.task_id,
                    persona=task.persona,
                    wave=2,
                    files={"tests/test_api.py": "def test_user(): pass"},
                    consumed_tokens=500,
                )

        dispatcher.invoke_junior_worker = capture_worker
        files = asyncio.run(dispatcher.execute_phased_junior_swarm(plan, "trace-test", "product-x"))

        # Verify Wave 2 only received models.py, NOT secret.py
        self.assertIn("apps/api/models.py", injected_deps_captured)
        self.assertNotIn("apps/api/secret.py", injected_deps_captured)
        self.assertEqual(len(files), 3)

    def test_lead_orchestrator_429_cascade(self):
        """Verify that LeadDeveloperOrchestrator cascades models on 429 ResourceExhausted."""
        mock_client = MagicMock()
        
        call_models = []
        def mock_generate_content(model, contents, config):
            call_models.append(model)
            if model == "gemini-3.8-flash":
                raise Exception("429 RESOURCE_EXHAUSTED: Rate limit exceeded")
            # Secondary candidate succeeds
            res = MagicMock()
            res.text = json.dumps({
                "execution_mode": "STANDARD_SWARM",
                "max_swarm_token_envelope": 300000,
                "shared_contracts": {},
                "tasks": [
                    {
                        "task_id": "test-task-1",
                        "persona": "DATABASE_ENGINEER",
                        "wave": 1,
                        "assigned_files": ["apps/test/models.py"],
                        "task_objective": "Build models",
                    }
                ]
            })
            res.candidates = []
            return res

        mock_client.models.generate_content.side_effect = mock_generate_content
        
        with patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent", return_value=["gemini-3.8-flash", "gemini-2.5-flash"]):
            lead = LeadDeveloperOrchestrator(genai_client=mock_client, model_name="gemini-3.8-flash")
            plan = lead.decompose_specification(
                product_id="test-prod",
                spec_text="Spec test",
                task_dag=[{"task_id": "step-1"}],
            )
            
            # Verify that primary model hit 429 and cascaded to secondary model
            self.assertEqual(call_models, ["gemini-3.8-flash", "gemini-2.5-flash"])
            self.assertEqual(len(plan.tasks), 1)
            self.assertEqual(plan.tasks[0].task_id, "test-task-1")

    def test_junior_worker_429_resilience_cascade(self):
        """Verify that junior worker cascades models across retry attempts on 429."""
        dispatcher = SwarmDispatcher(genai_client=MagicMock())
        task = JuniorTaskAssignment(
            task_id="task-test",
            persona=JuniorPersona.BACKEND_ENGINEER,
            wave=1,
            assigned_files=["apps/test/main.py"],
            task_objective="Test task",
        )
        plan = LeadDeveloperDecompositionPlan(
            execution_mode=SwarmExecutionMode.STANDARD_SWARM,
            tasks=[task],
        )

        call_models = []
        async def mock_call_backoff(prompt, sys_inst, model_name, trace_id=None):
            call_models.append(model_name)
            if model_name == "gemini-3.8-flash":
                raise Exception("429 RESOURCE_EXHAUSTED")
            return {"apps/test/main.py": "print('ok')"}, 100

        dispatcher._call_gemini_with_backoff = mock_call_backoff

        with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=["gemini-3.8-flash", "gemini-2.5-flash"]):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                res = asyncio.run(dispatcher.invoke_junior_worker(task, plan, {}, "gemini-3.8-flash"))
                self.assertEqual(res.status, "SUCCEEDED")
                self.assertIn("gemini-3.8-flash", call_models)
                self.assertIn("gemini-2.5-flash", call_models)

    def test_is_transient_vertex_error_classification(self):
        """Verify discriminator correctly identifies transient infrastructure errors vs permanent client errors."""
        from shared.cooldown_manager import is_transient_vertex_error

        # Transient errors that MUST retry
        transient_cases = [
            Exception("500 Internal error: failed to communicate with Harpoon"),
            Exception("503 Service Unavailable: backend overloaded"),
            Exception("502 Bad Gateway"),
            Exception("504 Gateway Timeout"),
            Exception("429 Quota exceeded for metric GenerateContent"),
            Exception("ResourceExhausted: rate limit reached"),
            Exception("ConnectionResetError: RemoteDisconnected"),
            Exception("INTERNAL: failed to allocate Borg job"),
            Exception("UNAVAILABLE: Temporary failure in name resolution"),
        ]
        for err in transient_cases:
            self.assertTrue(is_transient_vertex_error(err), f"Expected True for transient error: {err}")

        # Permanent errors that MUST NOT retry
        permanent_cases = [
            Exception("400 Bad Request: Invalid argument supplied"),
            Exception("404 Not Found: Model gemini-invalid does not exist"),
            ValueError("Invalid schema field type"),
            TypeError("Missing required argument"),
        ]
        for err in permanent_cases:
            self.assertFalse(is_transient_vertex_error(err), f"Expected False for permanent error: {err}")

    def test_swarm_inner_backoff_recovery_harpoon(self):
        """Verify Level 1 inner backoff retries and recovers from transient Harpoon 500 errors."""
        mock_client = MagicMock()
        attempts = 0

        def mock_generate(model, contents, config):
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise Exception("500 Internal error: failed to communicate with Harpoon")
            res = MagicMock()
            res.text = json.dumps({"files": {"apps/workload/main.py": "# recovered successfully"}})
            res.candidates = []
            res.usage_metadata = MagicMock(total_token_count=1500)
            return res

        mock_client.models.generate_content.side_effect = mock_generate
        dispatcher = SwarmDispatcher(genai_client=mock_client)

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            files, tokens = asyncio.run(dispatcher._call_gemini_with_backoff(
                prompt="Generate code",
                system_instruction="System prompt",
                model_name="gemini-3.8-flash",
            ))

            self.assertEqual(attempts, 3)
            self.assertIn("apps/workload/main.py", files)
            self.assertEqual(files["apps/workload/main.py"], "# recovered successfully")
            self.assertEqual(mock_sleep.call_count, 2)

    def test_junior_worker_harpoon_cascade(self):
        """Verify Level 2 model cascading when transient Harpoon 500 persists across inner retries."""
        dispatcher = SwarmDispatcher(genai_client=MagicMock())
        task = JuniorTaskAssignment(
            task_id="task-harpoon",
            persona=JuniorPersona.BACKEND_ENGINEER,
            wave=1,
            assigned_files=["apps/test/api.py"],
            task_objective="Test harpoon resilience",
        )
        plan = LeadDeveloperDecompositionPlan(
            execution_mode=SwarmExecutionMode.STANDARD_SWARM,
            tasks=[task],
        )

        call_models = []
        async def mock_call_backoff(prompt, sys_inst, model_name, trace_id=None):
            call_models.append(model_name)
            if model_name == "gemini-3.8-flash":
                raise Exception("500 Internal error: failed to communicate with Harpoon")
            return {"apps/test/api.py": "# fallback succeeded"}, 200

        dispatcher._call_gemini_with_backoff = mock_call_backoff

        with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=["gemini-3.8-flash", "gemini-2.5-pro"]):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                res = asyncio.run(dispatcher.invoke_junior_worker(task, plan, {}, "gemini-3.8-flash"))
                self.assertEqual(res.status, "SUCCEEDED")
                self.assertIn("gemini-3.8-flash", call_models)
                self.assertIn("gemini-2.5-pro", call_models)
                self.assertEqual(res.files["apps/test/api.py"], "# fallback succeeded")


if __name__ == "__main__":
    unittest.main()

