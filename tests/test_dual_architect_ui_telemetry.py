"""
Project Castor: Test Suite for Dual-Architect Flight Deck & UI Observability
Tests consensus telemetry serialization into StageExecutionDetail,
Architecture Council roster resolution in /api/platform/agents/{agent_id}/details,
Glass Pane dynamic subagent resolution (?subagent=critic),
and graceful fallback handling.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure apps/orchestrator-gateway, apps/control-center, and root are in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_DIR = os.path.join(BASE_DIR, "apps", "orchestrator-gateway")
CONTROL_CENTER_DIR = os.path.join(BASE_DIR, "apps", "control-center")

for p in (GATEWAY_DIR, CONTROL_CENTER_DIR, BASE_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared.critic_schemas import (
    ArchitectSubagentTelemetry,
    CritiqueFinding,
    CritiqueSeverity,
    DualArchitectConsensusTelemetry,
    GauntletCheckResult,
)
from shared.builtin_prompts import (
    AGENT_DISPLAY_METADATA,
    ARCHITECT_RED_TEAM_CRITIC_PROMPT,
    BUILTIN_PROMPTS,
)
from schemas import (
    AgentDetailsResponse,
    StageExecutionDetail,
    StageExecutionTraceRecord,
)


class TestDualArchitectUIObservability(unittest.TestCase):
    """Verifies UI observability contracts and backend endpoints for Dual-Architect Council."""

    def test_consensus_telemetry_serialization_into_stage_detail(self):
        """Test DualArchitectConsensusTelemetry serialization into StageExecutionDetail.details."""
        subagents = [
            ArchitectSubagentTelemetry(
                persona="LEAD_ARCHITECT",
                status="SUCCEEDED",
                elapsed_seconds=3.5,
                output_tokens=2200,
            ),
            ArchitectSubagentTelemetry(
                persona="RED_TEAM_CRITIC",
                status="SUCCEEDED",
                elapsed_seconds=1.8,
                output_tokens=950,
            ),
        ]
        checks = [
            GauntletCheckResult(
                invariant_name="DAG Topology & Cycles",
                status="PASSED",
                details="Topologically sorted with 0 cycles via Kahn's algorithm",
            ),
            GauntletCheckResult(
                invariant_name="GCP Service Overlap",
                status="PASSED",
                details="Single primary compute engine selected",
            ),
        ]
        telemetry = DualArchitectConsensusTelemetry(
            consensus_status="CONSENSUS_VERIFIED",
            soundness_score=1.0,
            has_critical_findings=False,
            remediation_performed=False,
            remediation_diff_summary=None,
            subagents=subagents,
            gauntlet_checks=checks,
            findings=[],
            bypassed=False,
        )

        detail = StageExecutionDetail(
            status="SUCCESS",
            summary="Stage 2 Architect decomposition verified by Dual-Architect consensus",
            duration_seconds=5.3,
            details={"architect_consensus": telemetry.model_dump()},
        )

        self.assertEqual(detail.status, "SUCCESS")
        self.assertIn("architect_consensus", detail.details)
        cons_data = detail.details["architect_consensus"]
        self.assertEqual(cons_data["consensus_status"], "CONSENSUS_VERIFIED")
        self.assertEqual(cons_data["soundness_score"], 1.0)
        self.assertEqual(len(cons_data["subagents"]), 2)
        self.assertEqual(len(cons_data["gauntlet_checks"]), 2)
        self.assertEqual(cons_data["gauntlet_checks"][0]["status"], "PASSED")
        self.assertEqual(cons_data["gauntlet_checks"][0]["invariant_name"], "DAG Topology & Cycles")

    def test_architect_critic_roster_resolution(self):
        """Test that get_agent_details resolves architect_critic with correct prompt & metadata."""
        from routes.agent_evals import AGENT_ROSTER_REGISTRY, get_agent_details

        self.assertIn("architect_critic", AGENT_ROSTER_REGISTRY)
        meta = AGENT_ROSTER_REGISTRY["architect_critic"]
        self.assertEqual(meta["agent_role"], "ARCHITECT_RED_TEAM_CRITIC")
        self.assertEqual(meta["name"], "Principal Red-Team Reviewer")
        self.assertEqual(meta["avatar_icon"], "🧐")

        with patch("routes.agent_evals.db", None):
            resp = get_agent_details("architect_critic")
            self.assertIsInstance(resp, AgentDetailsResponse)
            self.assertEqual(resp.name, "Principal Red-Team Reviewer")
            self.assertEqual(resp.agent_role, "ARCHITECT_RED_TEAM_CRITIC")
            self.assertEqual(resp.avatar_icon, "🧐")
            self.assertIn("Principal Red-Team Reviewer", resp.base_prompt)

    def test_lead_architect_roster_resolution(self):
        """Test that get_agent_details resolves primary architect."""
        from routes.agent_evals import get_agent_details

        with patch("routes.agent_evals.db", None):
            resp = get_agent_details("architect")
            self.assertIsInstance(resp, AgentDetailsResponse)
            self.assertEqual(resp.name, "The Architect")
            self.assertEqual(resp.agent_role, "ARCHITECT_AGENT")
            self.assertEqual(resp.avatar_icon, "🧠")
            self.assertIn("Lead Cloud Architect", resp.base_prompt)

    def test_glass_pane_critic_subagent_dynamic_resolution(self):
        """Test GET /api/pipeline/executions/{trace_id}/stages/architect/eval?subagent=critic."""
        from routes.agent_evals import get_stage_execution_eval

        trace_id = "test-trace-ui-obs-001"
        consensus_dict = {
            "consensus_status": "CONSENSUS_VERIFIED",
            "soundness_score": 0.98,
            "has_critical_findings": False,
            "remediation_performed": False,
            "remediation_diff_summary": None,
            "gauntlet_checks": [
                {"invariant_name": "DAG Topology & Cycles", "status": "PASSED", "details": "0 cycles"},
                {"invariant_name": "Golden Modules Catalog Grounding", "status": "PASSED", "details": "All modules valid"},
            ],
            "findings": [
                {
                    "category": "SPEC_COVERAGE",
                    "severity": "WARNING",
                    "description": "Verify streaming buffer size on Cloud Run",
                    "recommended_remediation": "Use chunked streaming",
                }
            ],
            "subagents": [],
        }

        # Mock Firestore returning execution with architect consensus details
        mock_db = MagicMock()

        mock_parent_trace_doc = MagicMock()
        mock_parent_trace_doc.exists = True
        mock_parent_trace_doc.to_dict.return_value = {
            "trace_id": trace_id,
            "stage_name": "architect",
            "architect_consensus": consensus_dict,
            "created_at": "2026-09-23T20:00:00Z",
        }

        mock_parent_exec_doc = MagicMock()
        mock_parent_exec_doc.exists = True
        mock_parent_exec_doc.to_dict.return_value = {
            "trace_id": trace_id,
            "started_at": "2026-09-23T20:00:00Z",
            "stages": {
                "architect": {
                    "details": {
                        "architect_consensus": consensus_dict
                    }
                }
            }
        }

        def mock_doc_ref(doc_id):
            ref = MagicMock()
            if doc_id == "architect":
                ref.get.return_value = mock_parent_trace_doc
            elif doc_id == trace_id:
                ref.get.return_value = mock_parent_exec_doc
            else:
                snap = MagicMock()
                snap.exists = False
                snap.to_dict.return_value = {}
                ref.get.return_value = snap
            return ref

        # mock_db.collection("pipeline_executions").document(trace_id)...
        mock_pipeline_exec_ref = MagicMock()
        mock_pipeline_exec_ref.get.return_value = mock_parent_exec_doc
        mock_pipeline_exec_ref.collection.return_value.document.side_effect = mock_doc_ref

        mock_db.collection.return_value.document.return_value = mock_pipeline_exec_ref

        with patch("routes.agent_evals.db", mock_db):
            record = get_stage_execution_eval(trace_id=trace_id, stage_name="architect", subagent="critic")

            self.assertIsInstance(record, StageExecutionTraceRecord)
            self.assertEqual(record.stage_name, "architect_critic")
            self.assertIn("Principal Red-Team Reviewer", record.rendered_prompt)
            output_obj = json.loads(record.agent_output)
            self.assertEqual(output_obj["consensus_status"], "CONSENSUS_VERIFIED")
            self.assertEqual(len(output_obj["gauntlet_checks"]), 2)
            self.assertIsNotNone(record.eval_metric)
            self.assertEqual(record.eval_metric.instruction_adherence_score, 0.98)
            self.assertEqual(len(record.eval_metric.constraint_violations), 1)

    def test_glass_pane_architect_fallback_when_empty(self):
        """Test graceful degradation when trace has no consensus recorded."""
        from routes.agent_evals import get_stage_execution_eval

        trace_id = "test-trace-fallback-002"
        mock_db = MagicMock()
        mock_doc = MagicMock()
        mock_doc.exists = False
        mock_parent = MagicMock()
        mock_parent.exists = True
        mock_parent.to_dict.return_value = {
            "trace_id": trace_id,
            "started_at": "2026-09-23T20:00:00Z",
            "stages": {
                "architect": {"status": "SUCCESS", "summary": "Decomposed 5 steps"}
            }
        }
        mock_db.collection.return_value.document.return_value.collection.return_value.document.return_value.get.return_value = mock_doc
        mock_db.collection.return_value.document.return_value.get.return_value = mock_parent

        with patch("routes.agent_evals.db", mock_db):
            record = get_stage_execution_eval(trace_id=trace_id, stage_name="architect", subagent="critic")
            self.assertIsInstance(record, StageExecutionTraceRecord)
            self.assertEqual(record.stage_name, "architect_critic")
            output_obj = json.loads(record.agent_output)
            self.assertIn("message", output_obj)


if __name__ == "__main__":
    unittest.main()
