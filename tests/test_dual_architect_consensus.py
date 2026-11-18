"""
Project Castor: Dual-Architect Consensus & Red-Team DAG Auditing Tests
Tests:
- Deterministic Kahn's algorithm cycle detection (macro & micro DAGs)
- Orphan dependency detection and stage ordering violations
- Fast-pass verification when 0 critical faults exist (<2s)
- Red-Team Critic adversarial audit & 5-point gauntlet
- Bounded N=1 remediation turn and diff summarization
- Circuit breaker fault-tolerance on remediation errors
- ENABLE_DUAL_ARCHITECT_CONSENSUS feature flag bypass
- Downstream Compliance Agent contract stability
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")

if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if GATEWAY_DIR not in sys.path:
    sys.path.append(GATEWAY_DIR)
if CC_DIR not in sys.path:
    sys.path.append(CC_DIR)

from shared.critic_schemas import (
    ArchitecturalCritique,
    ArchitectSubagentTelemetry,
    CritiqueCategory,
    CritiqueFinding,
    CritiqueSeverity,
    DualArchitectConsensusTelemetry,
    GauntletCheckResult,
)
from architect_agent.schemas import (
    ArchitectDecompositionResult,
    ArchitecturePlan,
    ArchitecturePlanDAG,
    BuildPlanStep,
    BuildStepCategory,
    SequencedBuildPlan,
    TaskCategory,
    TaskItem,
)
from architect_agent.cycle_detector import (
    validate_build_plan_steps,
    validate_dual_layer_dag,
    validate_task_dag_items,
)
from architect_agent.red_team_critic import (
    CANONICAL_GOLDEN_MODULES,
    RedTeamCritic,
)
from architect_agent.consensus_engine import (
    DualArchitectConsensusEngine,
)
from architect_agent.handler import ArchitectAgent
from compliance_agent.handler import ComplianceAgentHandler
from compliance_agent.schemas import (
    ComplianceAuditRequest,
    ComplianceAuditResponse,
)


class TestDualArchitectCycleDetection(unittest.TestCase):
    """Tests Kahn's algorithm and topological invariant checks."""

    def test_macro_steps_sound_dag(self):
        steps = [
            BuildPlanStep(step_id="STEP-01-APIS", step_index=1, category=BuildStepCategory.FOUNDATION_API, depends_on=[]),
            BuildPlanStep(step_id="STEP-02-DB", step_index=2, category=BuildStepCategory.DATABASE, depends_on=["STEP-01-APIS"]),
            BuildPlanStep(step_id="STEP-03-IAM", step_index=3, category=BuildStepCategory.IAM, depends_on=["STEP-01-APIS"]),
            BuildPlanStep(step_id="STEP-06-COMPUTE", step_index=4, category=BuildStepCategory.COMPUTE, depends_on=["STEP-02-DB", "STEP-03-IAM"]),
        ]
        res = validate_build_plan_steps(steps)
        self.assertTrue(res.is_valid)
        self.assertFalse(res.cycle_detected)
        self.assertEqual(len(res.orphan_dependencies), 0)
        self.assertEqual(len(res.ordering_violations), 0)

    def test_macro_steps_cycle_detection(self):
        # Circular: STEP-02 depends on STEP-03, STEP-03 depends on STEP-02
        steps = [
            BuildPlanStep(step_id="STEP-01-APIS", step_index=1, category=BuildStepCategory.FOUNDATION_API, depends_on=[]),
            BuildPlanStep(step_id="STEP-02-DB", step_index=2, category=BuildStepCategory.DATABASE, depends_on=["STEP-03-IAM"]),
            BuildPlanStep(step_id="STEP-03-IAM", step_index=3, category=BuildStepCategory.IAM, depends_on=["STEP-02-DB"]),
        ]
        res = validate_build_plan_steps(steps)
        self.assertFalse(res.is_valid)
        self.assertTrue(res.cycle_detected)
        self.assertTrue(any("cycle detected" in err.lower() for err in res.errors))

    def test_orphan_dependency_detection(self):
        # STEP-02 references non-existent STEP-99-GHOST
        steps = [
            BuildPlanStep(step_id="STEP-01-APIS", step_index=1, category=BuildStepCategory.FOUNDATION_API, depends_on=[]),
            BuildPlanStep(step_id="STEP-02-DB", step_index=2, category=BuildStepCategory.DATABASE, depends_on=["STEP-99-GHOST"]),
        ]
        res = validate_build_plan_steps(steps)
        self.assertFalse(res.is_valid)
        self.assertEqual(len(res.orphan_dependencies), 1)
        self.assertIn("STEP-99-GHOST", res.orphan_dependencies[0])

    def test_stage_ordering_inversion(self):
        # Inversion: Foundation API depending on downstream Compute
        steps = [
            BuildPlanStep(step_id="STEP-01-APIS", step_index=1, category=BuildStepCategory.FOUNDATION_API, depends_on=["STEP-06-COMPUTE"]),
            BuildPlanStep(step_id="STEP-06-COMPUTE", step_index=2, category=BuildStepCategory.COMPUTE, depends_on=[]),
        ]
        res = validate_build_plan_steps(steps)
        self.assertFalse(res.is_valid)
        self.assertTrue(len(res.ordering_violations) > 0)
        self.assertIn("Stage ordering inverted", res.ordering_violations[0])

    def test_micro_task_items_cycle_detection(self):
        tasks = [
            TaskItem(task_id="INFRA-01", depends_on=["CODE-01"], category=TaskCategory.INFRA),
            TaskItem(task_id="CODE-01", depends_on=["INFRA-01"], category=TaskCategory.CODE),
        ]
        res = validate_task_dag_items(tasks)
        self.assertFalse(res.is_valid)
        self.assertTrue(res.cycle_detected)

    def test_dual_layer_validation(self):
        steps = [
            BuildPlanStep(step_id="STEP-01-APIS", step_index=1, category=BuildStepCategory.FOUNDATION_API, depends_on=[]),
        ]
        tasks = [
            TaskItem(task_id="CODE-01", depends_on=["CODE-02"], category=TaskCategory.CODE),
            TaskItem(task_id="CODE-02", depends_on=["CODE-01"], category=TaskCategory.CODE),
        ]
        res = validate_dual_layer_dag(steps=steps, infra_tasks=[], code_tasks=tasks)
        self.assertFalse(res.is_valid)
        self.assertTrue(res.cycle_detected)


class TestRedTeamCriticAudit(unittest.TestCase):
    """Tests the Principal Red-Team Reviewer audit behavior."""

    def setUp(self):
        self.critic = RedTeamCritic(genai_client=None, model_name="gemini-3.7-flash")

    def test_critic_flags_topological_cycle(self):
        steps = [
            BuildPlanStep(step_id="STEP-01", depends_on=["STEP-02"], category=BuildStepCategory.FOUNDATION_API),
            BuildPlanStep(step_id="STEP-02", depends_on=["STEP-01"], category=BuildStepCategory.COMPUTE),
        ]
        build_plan = SequencedBuildPlan(steps=steps)
        plan = ArchitecturePlan(product_id="test-prod", sequenced_build_plan=build_plan)

        critique = self.critic.audit_plan(plan, "Build user portal")
        self.assertTrue(critique.has_critical_findings)
        self.assertLessEqual(critique.soundness_score, 0.5)
        self.assertTrue(any(f.category == CritiqueCategory.TOPOLOGY_AND_ORDERING for f in critique.findings))

    def test_critic_passes_sound_plan_in_offline_mode(self):
        steps = [
            BuildPlanStep(step_id="STEP-01-APIS", depends_on=[], category=BuildStepCategory.FOUNDATION_API),
            BuildPlanStep(step_id="STEP-02-DB", depends_on=["STEP-01-APIS"], category=BuildStepCategory.DATABASE),
        ]
        build_plan = SequencedBuildPlan(steps=steps)
        plan = ArchitecturePlan(product_id="sound-prod", sequenced_build_plan=build_plan)

        critique = self.critic.audit_plan(plan, "Build simple API")
        self.assertFalse(critique.has_critical_findings)
        self.assertEqual(critique.soundness_score, 1.0)
        self.assertEqual(len(critique.gauntlet_checks), 5)
        self.assertEqual(critique.gauntlet_checks[0].status, "PASSED")


@hermetic_guard.unavailable("google.genai.Client", "Gemini")
class TestConsensusEngine(unittest.TestCase):
    """Tests fast pass, N=1 remediation turn, circuit breaker, and feature flag bypass."""

    def test_fast_pass_branch(self):
        engine = DualArchitectConsensusEngine(genai_client=None)
        steps = [
            BuildPlanStep(step_id="STEP-01-APIS", depends_on=[], category=BuildStepCategory.FOUNDATION_API),
            BuildPlanStep(step_id="STEP-02-COMPUTE", depends_on=["STEP-01-APIS"], category=BuildStepCategory.COMPUTE),
        ]
        plan = ArchitecturePlan(
            product_id="fast-prod",
            sequenced_build_plan=SequencedBuildPlan(steps=steps),
            infra_tasks=[],
            code_tasks=[TaskItem(task_id="CODE-01", depends_on=[], category=TaskCategory.CODE)],
        )

        mock_architect = MagicMock()
        reconciled_plan, telemetry = engine.evaluate_and_reconcile(
            plan=plan,
            spec_text="Deploy simple service",
            architect_agent=mock_architect,
            product_id="fast-prod",
            trace_id="tr-fast-01",
        )

        self.assertEqual(telemetry.consensus_status, "CONSENSUS_VERIFIED")
        self.assertFalse(telemetry.remediation_performed)
        self.assertFalse(telemetry.has_critical_findings)
        mock_architect.decompose.assert_not_called()

    def test_bounded_n1_remediation_success(self):
        # 1. Draft with cycle
        flawed_steps = [
            BuildPlanStep(step_id="STEP-01", depends_on=["STEP-02"], category=BuildStepCategory.FOUNDATION_API),
            BuildPlanStep(step_id="STEP-02", depends_on=["STEP-01"], category=BuildStepCategory.COMPUTE),
        ]
        flawed_plan = ArchitecturePlan(
            product_id="remedy-prod",
            sequenced_build_plan=SequencedBuildPlan(steps=flawed_steps),
        )

        # 2. Mock patched plan
        fixed_steps = [
            BuildPlanStep(step_id="STEP-01", depends_on=[], category=BuildStepCategory.FOUNDATION_API),
            BuildPlanStep(step_id="STEP-02", depends_on=["STEP-01"], category=BuildStepCategory.COMPUTE),
        ]
        fixed_plan = ArchitecturePlan(
            product_id="remedy-prod",
            sequenced_build_plan=SequencedBuildPlan(steps=fixed_steps),
        )

        mock_architect = MagicMock()
        mock_result = MagicMock()
        mock_result.architecture_plan = fixed_plan
        mock_architect.decompose.return_value = mock_result

        engine = DualArchitectConsensusEngine(genai_client=None)
        reconciled_plan, telemetry = engine.evaluate_and_reconcile(
            plan=flawed_plan,
            spec_text="Deploy fixed service",
            architect_agent=mock_architect,
            product_id="remedy-prod",
            trace_id="tr-remedy-01",
        )

        # Verify Architect 1 was called exactly ONCE (N=1)
        mock_architect.decompose.assert_called_once()
        call_kwargs = mock_architect.decompose.call_args[1]
        self.assertTrue(call_kwargs.get("bypass_consensus"))
        # RT14-16: the critique is the remediation brief, never passed off as the operator's REWORK feedback
        self.assertIn("ADVERSARIAL RED-TEAM ARCHITECTURAL AUDIT", call_kwargs.get("remediation_brief"))
        self.assertIsNone(call_kwargs.get("human_feedback"))

        self.assertEqual(telemetry.consensus_status, "AUTO_REMEDIATED")
        self.assertTrue(telemetry.remediation_performed)
        self.assertFalse(telemetry.has_critical_findings)
        self.assertEqual(reconciled_plan, fixed_plan)

    def test_circuit_breaker_on_remediation_error(self):
        # Flawed plan triggers remediation, but Architect 1 throws RuntimeError
        flawed_steps = [
            BuildPlanStep(step_id="STEP-01", depends_on=["STEP-02"], category=BuildStepCategory.FOUNDATION_API),
            BuildPlanStep(step_id="STEP-02", depends_on=["STEP-01"], category=BuildStepCategory.COMPUTE),
        ]
        flawed_plan = ArchitecturePlan(
            product_id="broken-prod",
            sequenced_build_plan=SequencedBuildPlan(steps=flawed_steps),
        )

        mock_architect = MagicMock()
        mock_architect.decompose.side_effect = RuntimeError("API Rate Limit 429 during remediation turn")

        engine = DualArchitectConsensusEngine(genai_client=None)
        reconciled_plan, telemetry = engine.evaluate_and_reconcile(
            plan=flawed_plan,
            spec_text="Deploy broken service",
            architect_agent=mock_architect,
            product_id="broken-prod",
            trace_id="tr-broken-01",
        )

        # Circuit breaker gracefully recovers without crashing
        self.assertEqual(telemetry.consensus_status, "CRITIQUE_FAILED")
        self.assertFalse(telemetry.remediation_performed)
        self.assertIn("Remediation turn failed", telemetry.remediation_diff_summary)
        self.assertEqual(reconciled_plan, flawed_plan)

    def test_feature_flag_bypass(self):
        with patch.dict(os.environ, {"ENABLE_DUAL_ARCHITECT_CONSENSUS": "false"}):
            agent = ArchitectAgent(project_id="")
            agent.genai_client = None
            agent.model = None

            # consensus-bypass telemetry only: the topology gate (lane 10) is covered by test_architect_topology_gate.py
            result = agent.decompose(
                spec_text="Test bypass",
                product_id="bypass-prod",
                topology_gate=False,
            )
            self.assertIsNotNone(result.consensus_telemetry)
            self.assertEqual(result.consensus_telemetry.consensus_status, "BYPASSED")


@hermetic_guard.unavailable("google.genai.Client", "Gemini")
class TestDownstreamComplianceCompatibility(unittest.TestCase):
    """Verifies that the consensus-hardened DAG seamlessly processes into Stage 3 Compliance Agent."""

    def test_consensus_plan_compliance_enrichment(self):
        # Step 1: Create a verified, topologically sound DAG
        steps = [
            BuildPlanStep(step_id="STEP-01-APIS", step_index=1, category=BuildStepCategory.FOUNDATION_API, depends_on=[]),
            BuildPlanStep(step_id="STEP-02-STORAGE", step_index=2, category=BuildStepCategory.DATABASE, depends_on=["STEP-01-APIS"]),
            BuildPlanStep(step_id="STEP-03-IAM", step_index=3, category=BuildStepCategory.IAM, depends_on=["STEP-01-APIS"]),
            BuildPlanStep(step_id="STEP-06-COMPUTE", step_index=4, category=BuildStepCategory.COMPUTE, depends_on=["STEP-02-STORAGE", "STEP-03-IAM"]),
        ]
        tasks = [
            TaskItem(task_id="INFRA-01", title="Provision Storage & IAM", category=TaskCategory.INFRA, depends_on=[]),
            TaskItem(task_id="CODE-01", title="Implement FastAPI app", category=TaskCategory.CODE, depends_on=["INFRA-01"]),
        ]
        plan = ArchitecturePlan(
            product_id="compliance-workload",
            sequenced_build_plan=SequencedBuildPlan(steps=steps),
            infra_tasks=[tasks[0]],
            code_tasks=[tasks[1]],
            plan_markdown="# Compliance Workload Plan\nDetails here...",
            plan_file_path="docs/planning/2026-09-23-feat-compliance-workload.md",
        )

        # Step 2: Feed directly into ComplianceAgentHandler
        # Lane 17 PR-1a: the compliance engine runs in-process only on explicit request (never a fallback).
        compliance_handler = ComplianceAgentHandler(mode="inprocess")
        compliance_handler.genai_client = None
        compliance_handler.model = None

        req = ComplianceAuditRequest(
            product_id=plan.product_id,
            spec_text="Standard medical healthcare portal requiring HIPAA compliant audit logging",
            task_dag=[t.model_dump() for t in (plan.infra_tasks + plan.code_tasks)],
            plan_markdown=plan.plan_markdown,
            plan_file_path=plan.plan_file_path,
        )

        resp = compliance_handler.audit_and_enrich(req)
        self.assertIsInstance(resp, ComplianceAuditResponse)
        self.assertEqual(resp.product_id, "compliance-workload")
        self.assertTrue(len(resp.enriched_dag) >= len(req.task_dag))
        self.assertIn(resp.status, ["PASSED", "ENRICHED"])


if __name__ == "__main__":
    unittest.main()
