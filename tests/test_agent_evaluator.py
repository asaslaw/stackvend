"""
Project Castor: Unit Tests for Agent Glass Pane & Continuous Evaluation Feedback Cockpit
Verifies:
1. Dynamic model resolution from Firestore platform_settings (default: gemini-4-carbon, DEFAULT-MODEL-GEMINI-4-CARBON)
2. Gemini 3.7 Flash LLM-as-a-judge evaluation scoring and schema parsing
3. Heuristic deterministic fallback evaluation when Gemini is unavailable
4. Strict enforcement of 5-directive ceiling per agent role
5. Prompt streamlining and directive consolidation
6. API routes for inspection, evaluation, feedback, promotion, and directives
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure project root and control-center directory are in sys.path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
cc_dir = os.path.join(repo_root, "apps", "control-center")
sys.path.insert(0, repo_root)
sys.path.insert(0, cc_dir)

# Mock external cloud clients and frameworks before imports
for mod in [
    "google", "google.auth", "google.auth.transport", "google.auth.transport.requests",
    "google.oauth2", "google.oauth2.id_token", "googleapiclient", "google.cloud",
    "google.cloud.firestore", "google.cloud.storage", "google.cloud.logging",
    "google.cloud.logging_v2", "google.cloud.pubsub_v1", "starlette", "starlette.middleware",
    "starlette.middleware.base"
]:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

# FastAPI mock
class MockHTTPException(Exception):
    def __init__(self, status_code: int, detail: str = ""):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"{status_code}: {detail}")

def mock_decorator(*args, **kwargs):
    def inner(fn):
        return fn
    return inner

mock_router = MagicMock()
mock_router.get = mock_decorator
mock_router.post = mock_decorator
mock_router.put = mock_decorator
mock_router.delete = mock_decorator

mock_fastapi = MagicMock()
mock_fastapi.HTTPException = MockHTTPException
mock_fastapi.APIRouter = lambda *args, **kwargs: mock_router
mock_fastapi.Request = MagicMock
mock_fastapi.Response = MagicMock
mock_fastapi.__path__ = []
sys.modules["fastapi"] = mock_fastapi

mock_responses = MagicMock()
mock_responses.HTMLResponse = MagicMock
mock_responses.JSONResponse = MagicMock
mock_responses.RedirectResponse = MagicMock
sys.modules["fastapi.responses"] = mock_responses

# Mock pydantic if needed
try:
    import pydantic
    from pydantic import BaseModel, Field
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

        def dict(self):
            res = {}
            for k, v in self.__dict__.items():
                if not k.startswith('_'):
                    if hasattr(v, 'dict'):
                        res[k] = v.dict()
                    elif isinstance(v, dict):
                        res[k] = {ik: iv.dict() if hasattr(iv, 'dict') else iv for ik, iv in v.items()}
                    else:
                        res[k] = v
            return res

        def model_dump(self):
            return self.dict()

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: default if default is not None else (default_factory() if default_factory else None)
    mock_pydantic.EmailStr = str
    sys.modules['pydantic'] = mock_pydantic
    BaseModel = MockBaseModel
    Field = mock_pydantic.Field

from shared.agent_evaluator import (
    evaluate_agent_execution,
    get_evaluation_model,
    streamline_agent_prompt,
)
from shared.settings import AgentModelSettings, PlatformSettings

# Import schemas and routes via importlib
import importlib.util
_spec = importlib.util.spec_from_file_location('cc_schemas', os.path.join(cc_dir, 'schemas.py'))
cc_schemas = importlib.util.module_from_spec(_spec)
sys.modules['schemas'] = cc_schemas
_spec.loader.exec_module(cc_schemas)

_eval_spec = importlib.util.spec_from_file_location('agent_evals', os.path.join(cc_dir, 'routes', 'agent_evals.py'))
evals_module = importlib.util.module_from_spec(_eval_spec)
_eval_spec.loader.exec_module(evals_module)


class TestAgentEvaluator(unittest.TestCase):
    """Unit tests for evaluator logic and prompt management."""

    def test_dynamic_model_resolution_defaults(self):
        """When platform settings has default or missing architect_model, resolve the default primary model."""
        mock_db = MagicMock()
        mock_doc = MagicMock()
        mock_doc.exists = False
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        model_name = get_evaluation_model(mock_db)
        self.assertEqual(model_name, "gemini-4-carbon")

    def test_dynamic_model_resolution_custom(self):
        """Resolves customized model from platform settings in Firestore."""
        mock_db = MagicMock()
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "models": {
                "architect_model": "gemini-3.7-flash"
            }
        }
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        model_name = get_evaluation_model(mock_db)
        self.assertEqual(model_name, "gemini-3.7-flash")

    @patch("shared.agent_evaluator._call_gemini_inference", return_value=None)
    def test_heuristic_fallback_eval_success(self, mock_gemini):
        """When Gemini client is not initialized, fallback heuristics evaluate output."""
        prompt = "System prompt for architect: private only VPC network."
        output = "resource \"google_compute_subnetwork\" \"private\" { ip_cidr_range = \"10.0.0.0/24\" }"
        eval_result = evaluate_agent_execution("architect", prompt, output, db_client=None)
        self.assertGreaterEqual(eval_result["instruction_adherence_score"], 0.8)
        self.assertEqual(eval_result["grounding_score"], 1.0)
        self.assertIn("heuristic-fallback", eval_result["eval_judge_model"])

    @patch("shared.agent_evaluator._call_gemini_inference", return_value=None)
    def test_heuristic_fallback_eval_violations(self, mock_gemini):
        """When output violates constraints (e.g. 0.0.0.0/0 on private only), fallback deducts adherence."""
        prompt = "System prompt: private only, no public ip allowed."
        output = "resource \"google_compute_firewall\" \"allow_all\" { source_ranges = [\"0.0.0.0/0\"] }"
        eval_result = evaluate_agent_execution("architect", prompt, output, db_client=None)
        self.assertLess(eval_result["instruction_adherence_score"], 0.8)
        self.assertIn("Exposed public ingress", eval_result["constraint_violations"][0])

    @patch("shared.agent_evaluator._call_gemini_inference")
    def test_evaluate_agent_execution_with_gemini(self, mock_gemini):
        """Test LLM-as-a-Judge execution when Gemini API responds with structured JSON."""
        mock_gemini.return_value = json.dumps({
            "instruction_adherence_score": 0.98,
            "grounding_score": 1.0,
            "tool_efficiency_score": 0.95,
            "constraint_violations": [],
            "hallucinations_detected": [],
            "strengths": ["Clean modular HCL", "Correct resource naming"],
            "improvement_directives": ["Add cloud monitoring alert"],
            "eval_summary": "Exemplary architectural synthesis conforming to all enterprise guidelines."
        })

        res = evaluate_agent_execution(
            stage_name="architect",
            rendered_prompt="Follow GCP foundation best practices.",
            agent_output="resource \"google_project_service\" \"run\" {}",
            db_client=None,
        )

        self.assertEqual(res["instruction_adherence_score"], 0.98)
        self.assertEqual(res["grounding_score"], 1.0)
        self.assertEqual(res["eval_judge_model"], "gemini-4-carbon")
        self.assertIn("Exemplary", res["eval_summary"])

    def test_directive_ceiling_enforcement_in_settings(self):
        """Verify AgentModelSettings has custom_directives dict structure."""
        settings = AgentModelSettings()
        self.assertIsInstance(settings.custom_directives, dict)
        settings.custom_directives["ARCHITECT_AGENT"] = ["directive 1"]
        self.assertEqual(settings.custom_directives["ARCHITECT_AGENT"], ["directive 1"])

    @patch("shared.agent_evaluator._call_gemini_inference")
    def test_streamline_agent_prompt_with_gemini(self, mock_gemini):
        """Tests that streamline_agent_prompt merges ad-hoc directives and produces streamlined prompt."""
        mock_gemini.return_value = json.dumps({
            "streamlined_prompt": "# Consolidated Architect Prompt\n- Enforce Scale-to-zero.\n- Validate IAM least privilege.",
            "diff_summary": "Consolidated 2 ad-hoc directives into the core system instructions."
        })

        streamlined_prompt, diff_summary = streamline_agent_prompt(
            agent_role="ARCHITECT_AGENT",
            base_prompt="System instructions for architect agent.",
            directives=[
                "Always add min_instance_count=0 to Cloud Run templates",
                "Ensure IAM bindings use least privilege"
            ],
            db_client=None
        )

        self.assertIn("Consolidated", streamlined_prompt)
        self.assertIn("Consolidated 2 ad-hoc directives", diff_summary)


class TestAgentEvalsAPIRoutes(unittest.TestCase):
    """Tests FastAPI router endpoints in apps/control-center/routes/agent_evals.py."""

    def setUp(self):
        self.evals_mod = evals_module
        self.mock_db = MagicMock()
        evals_module.db = self.mock_db

    def test_get_stage_eval_fallback_when_trace_exists_in_parent(self):
        """When subcollection document is absent, synthesizes from parent execution."""
        mock_subdoc = MagicMock()
        mock_subdoc.exists = False

        mock_parentdoc = MagicMock()
        mock_parentdoc.exists = True
        mock_parentdoc.to_dict.return_value = {
            "trace_id": "trace-100",
            "started_at": "2026-09-16T12:00:00Z",
            "stages": {
                "architect": {"status": "SUCCESS", "module_count": 2}
            }
        }

        self.mock_db.collection.return_value.document.return_value.collection.return_value.document.return_value.get.return_value = mock_subdoc
        self.mock_db.collection.return_value.document.return_value.get.return_value = mock_parentdoc

        trace_record = self.evals_mod.get_stage_execution_eval("trace-100", "architect")
        self.assertEqual(trace_record.trace_id, "trace-100")
        self.assertEqual(trace_record.stage_name, "architect")
        self.assertIn("unrecorded historical execution", trace_record.rendered_prompt)

    def test_submit_stage_feedback(self):
        """Submitting feedback updates the stage trace document and global feedback collection."""
        mock_subdoc_ref = MagicMock()
        self.mock_db.collection.return_value.document.return_value.collection.return_value.document.return_value = mock_subdoc_ref

        req_payload = self.evals_mod.SubmitFeedbackRequest(
            rating=self.evals_mod.FeedbackRating.THUMBS_UP,
            feedback_text="Exceptional compliance with corporate VPC policies",
            tags=["exemplary", "vpc"]
        )

        record = self.evals_mod.submit_stage_feedback(
            trace_id="trace-101",
            stage_name="architect",
            payload=req_payload,
            request=None
        )

        self.assertEqual(record.rating, self.evals_mod.FeedbackRating.THUMBS_UP)
        self.assertEqual(record.trace_id, "trace-101")
        mock_subdoc_ref.set.assert_called()

    def test_add_directive_enforces_5_ceiling(self):
        """Enforces maximum of 5 active directives per agent role."""
        mock_settings_doc = MagicMock()
        mock_settings_doc.exists = True
        mock_settings_doc.to_dict.return_value = {
            "models": {
                "custom_directives": {
                    "ARCHITECT_AGENT": ["dir1", "dir2", "dir3", "dir4", "dir5"]
                }
            }
        }
        self.mock_db.collection.return_value.document.return_value.get.return_value = mock_settings_doc

        req_payload = self.evals_mod.ApplyDirectiveRequest(directive="dir6_should_fail")

        with self.assertRaises(Exception) as ctx:
            self.evals_mod.apply_prompt_directive("ARCHITECT_AGENT", req_payload, None)
        
        self.assertIn("already has 5 active directives", str(ctx.exception))

    def test_get_agent_details_success(self):
        """Retrieves comprehensive agent details for a valid agent role."""
        mock_settings_doc = MagicMock()
        mock_settings_doc.exists = True
        mock_settings_doc.to_dict.return_value = {
            "models": {
                "custom_directives": {
                    "ARCHITECT_AGENT": ["Enforce VPC-SC on all storage buckets"]
                }
            }
        }
        self.mock_db.collection.return_value.document.return_value.get.return_value = mock_settings_doc

        # Mock builds query for evaluations
        mock_build_doc = MagicMock()
        mock_build_doc.to_dict.return_value = {
            "evaluations": {
                "architect": {
                    "adherence_score": 92.0,
                    "grounding_score": 88.0,
                    "approval_rate": 95.0
                }
            }
        }
        self.mock_db.collection.return_value.order_by.return_value.limit.return_value.stream.return_value = [mock_build_doc]

        details = self.evals_mod.get_agent_details("architect", None)

        self.assertEqual(details.agent_id, "architect")
        self.assertEqual(details.name, "The Architect")
        self.assertIn("Lead Cloud Architect Agent", details.base_prompt)
        self.assertTrue(len(details.attached_skills) > 0)
        self.assertIn("Enforce VPC-SC on all storage buckets", details.directives)
        self.assertGreaterEqual(details.total_builds_evaluated, 1)
        self.assertGreaterEqual(details.average_adherence, 0.0)

    def test_get_agent_details_not_found(self):
        """Returns 404 for unknown agent role."""
        with self.assertRaises(Exception) as ctx:
            self.evals_mod.get_agent_details("non-existent-agent", None)
        self.assertIn("404", str(ctx.exception))

    def test_get_agent_audit_exceptions_developer(self):
        """Returns exceptions for Developer Agent with adherence and grounding scores < 1.0."""
        audit_data = self.evals_mod.get_agent_audit_exceptions("developer", None)

        self.assertEqual(audit_data.agent_id, "developer")
        self.assertEqual(audit_data.agent_role, "DEVELOPER_AGENT")
        self.assertLess(audit_data.average_adherence, 1.0)
        self.assertLess(audit_data.average_grounding, 1.0)
        self.assertGreaterEqual(len(audit_data.adherence_exceptions), 1)
        self.assertGreaterEqual(len(audit_data.grounding_exceptions), 1)
        self.assertGreaterEqual(audit_data.hallucinations_detected_count, 1)

        exc = audit_data.adherence_exceptions[0]
        self.assertEqual(exc.category, "INSTRUCTION_OMISSION")
        self.assertIn("probe", (exc.rule_or_directive or "").lower())
        self.assertIn("probe", exc.deduction_reason.lower())

        grd_exc = audit_data.grounding_exceptions[0]
        self.assertEqual(grd_exc.category, "TERRAFORM_SCHEMA_HALLUCINATION")
        self.assertIn("auto_heal_policy", grd_exc.deduction_reason)

    def test_get_agent_audit_exceptions_clean_compliance(self):
        """Returns zero exceptions for Compliance Agent with 100% adherence and grounding."""
        audit_data = self.evals_mod.get_agent_audit_exceptions("compliance", 10, None)

        self.assertEqual(audit_data.agent_id, "compliance")
        self.assertEqual(audit_data.agent_role, "COMPLIANCE_AGENT")
        self.assertEqual(audit_data.average_adherence, 1.0)
        self.assertEqual(audit_data.average_grounding, 1.0)
        self.assertEqual(len(audit_data.adherence_exceptions), 0)
        self.assertEqual(len(audit_data.grounding_exceptions), 0)
        self.assertEqual(audit_data.hallucinations_detected_count, 0)

    def test_get_agent_details_window_and_trends(self):
        """Validates that rolling window adjustments update evaluated counts and trends."""
        # Test window = 5 for Developer (shows recent improvement)
        details_5 = self.evals_mod.get_agent_details("developer", window=5, request=None)
        self.assertEqual(details_5.selected_window, 5)
        self.assertEqual(details_5.total_builds_evaluated, 5)
        self.assertEqual(details_5.average_adherence, 1.0)
        self.assertEqual(details_5.approval_rate, 100.0)
        self.assertIn("+7%", details_5.adherence_trend)

        # Test window = 0 (Lifetime)
        details_all = self.evals_mod.get_agent_details("developer", window=0, request=None)
        self.assertEqual(details_all.selected_window, 0)
        self.assertEqual(details_all.average_adherence, 0.93)
        self.assertEqual(details_all.approval_rate, 92.0)
        self.assertIn("Baseline", details_all.adherence_trend)


    def test_get_glass_pane_overview_window_filtering(self):
        """Validates that get_glass_pane_overview responds to window parameter."""
        # Window = 5 (recent clean builds, 100% adherence, 100% grounding, 100% HITL approval)
        overview_5 = self.evals_mod.get_glass_pane_overview(window=5, request=None)
        self.assertEqual(overview_5.platform_adherence_avg, 1.0)
        self.assertEqual(overview_5.platform_grounding_avg, 1.0)
        self.assertEqual(overview_5.approval_rate_pct, 100.0)
        for ag in overview_5.agents:
            self.assertEqual(ag.total_evals, 5)
            self.assertEqual(ag.average_adherence, 1.0)
            self.assertEqual(ag.approval_rate, 100.0)
            self.assertIsNone(ag.flakiest_directive)

        # Window = 10 (default 10 builds)
        overview_10 = self.evals_mod.get_glass_pane_overview(window=10, request=None)
        self.assertEqual(overview_10.platform_adherence_avg, 0.97)
        self.assertEqual(overview_10.approval_rate_pct, 98.0)
        dev_10 = next(ag for ag in overview_10.agents if ag.agent_role == "DEVELOPER_AGENT")
        self.assertEqual(dev_10.total_evals, 10)
        self.assertEqual(dev_10.average_adherence, 0.95)
        self.assertEqual(dev_10.approval_rate, 95.0)
        self.assertEqual(dev_10.flakiest_directive, "Cloud Run probe definition")

        # Window = 0 (Lifetime)
        overview_all = self.evals_mod.get_glass_pane_overview(window=0, request=None)
        self.assertEqual(overview_all.platform_adherence_avg, 0.96)
        self.assertEqual(overview_all.approval_rate_pct, 95.0)
        dev_all = next(ag for ag in overview_all.agents if ag.agent_role == "DEVELOPER_AGENT")
        self.assertEqual(dev_all.total_evals, 14)
        self.assertEqual(dev_all.average_adherence, 0.93)
        self.assertEqual(dev_all.approval_rate, 92.0)


if __name__ == "__main__":
    unittest.main()


