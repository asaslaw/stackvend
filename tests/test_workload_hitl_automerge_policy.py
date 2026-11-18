import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import os
import sys
import unittest
import importlib.util
from unittest.mock import MagicMock

# Ensure mocks for third-party libs if not installed in host environment
for m in [
    'httpx', 'fastapi', 'fastapi.responses', 'fastapi.staticfiles', 'google', 'google.genai',
    'google.genai.types', 'google.cloud', 'google.cloud.firestore',
    'google.cloud.storage', 'google.cloud.logging', 'google.cloud.pubsub_v1',
    'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

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

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: default if default is not None else (default_factory() if default_factory else None)
    mock_pydantic.EmailStr = str
    sys.modules['pydantic'] = mock_pydantic
    BaseModel = MockBaseModel

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from shared.settings import GovernanceSettings

if GATEWAY_PATH not in sys.path:
    sys.path.insert(0, GATEWAY_PATH)

from developer_agent.handler import DeveloperAgent

# Load Control Center schemas
_spec = importlib.util.spec_from_file_location(
    'cc_schemas',
    os.path.join(REPO_ROOT, 'apps', 'control-center', 'schemas.py')
)
cc_schemas = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc_schemas)


class TestWorkloadHitlAutomergePolicy(unittest.TestCase):
    def test_schemas_default_require_human_code_review_true(self):
        """Verify that all workload schemas enforce require_human_code_review = True (Auto-Merge False) by default."""
        summary = cc_schemas.WorkloadSummary(
            product_id="test-svc",
            project_id="castor-test-svc",  # FD-05 B-15/16: required fields (since 30d5d22)
            status="ACTIVE",
            budget_ceiling_monthly_usd=50.0,
            spend_last_updated_at="2026-09-10T12:00:00Z",
        )
        self.assertTrue(summary.require_human_code_review, "WorkloadSummary must default require_human_code_review to True")

        detail = cc_schemas.WorkloadDetailsResponse(
            product_id="test-svc",
            project_id="castor-test-svc",
            status="ACTIVE",
            budget_ceiling_monthly_usd=50.0,
        )
        self.assertTrue(detail.require_human_code_review, "WorkloadDetailsResponse must default require_human_code_review to True")

        create_req = cc_schemas.CreateWorkloadRequest(
            product_id="test-svc",
            spec_content="Build a simple service",
        )
        self.assertTrue(create_req.require_human_code_review, "CreateWorkloadRequest must default require_human_code_review to True")

    def test_governance_settings_default(self):
        """Verify governance settings defaults to require_human_code_review = True."""
        gov = GovernanceSettings()
        self.assertTrue(gov.default_require_human_code_review)

    def test_developer_agent_automerge_default_false(self):
        """FD-4P (P4): the developer agent can no longer merge right after PR creation (before QA): the
        `auto_merge_pr` switch and its two merge calls are gone; merges happen only at release via the PR ledger."""
        agent = DeveloperAgent(project_id="test-proj")
        self.assertFalse(hasattr(agent, "auto_merge_pr"), "DeveloperAgent must not carry a merge-before-QA switch")
        self.assertFalse(hasattr(agent, "merge_pull_request"), "DeveloperAgent must not merge PRs (ledger only)")

    def test_create_workload_request_explicit_false(self):
        """Verify that CreateWorkloadRequest honors explicit require_human_code_review = False."""
        create_req = cc_schemas.CreateWorkloadRequest(
            product_id="test-svc",
            spec_content="Build a simple service",
            require_human_code_review=False,
            auto_merge=True,
        )
        self.assertFalse(create_req.require_human_code_review)
        self.assertTrue(create_req.auto_merge)

    def test_plan_approval_schemas_and_governance(self):
        """Verify require_plan_approval schema defaults and explicit configuration."""
        summary = cc_schemas.WorkloadSummary(
            product_id="test-svc",
            project_id="castor-test-svc",  # FD-05 B-15/16: required fields (since 30d5d22)
            status="ACTIVE",
            budget_ceiling_monthly_usd=50.0,
            spend_last_updated_at="2026-09-10T12:00:00Z",
        )
        self.assertFalse(summary.require_plan_approval)

        detail = cc_schemas.WorkloadDetailsResponse(
            product_id="test-svc",
            project_id="castor-test-svc",
            status="ACTIVE",
            budget_ceiling_monthly_usd=50.0,
        )
        self.assertFalse(detail.require_plan_approval)

        create_req_default = cc_schemas.CreateWorkloadRequest(
            product_id="test-svc",
            spec_content="Build service",
        )
        self.assertIsNone(create_req_default.require_plan_approval)

        create_req_explicit = cc_schemas.CreateWorkloadRequest(
            product_id="test-svc",
            spec_content="Build service",
            require_plan_approval=True,
        )
        self.assertTrue(create_req_explicit.require_plan_approval)

        update_req = cc_schemas.UpdateWorkloadPoliciesRequest(
            require_plan_approval=True,
        )
        self.assertTrue(update_req.require_plan_approval)

        gov = GovernanceSettings()
        self.assertFalse(gov.require_plan_approval)
        self.assertEqual(gov.plan_approval_policy, "ON_COMPLIANCE_CONFLICT")


if __name__ == "__main__":
    unittest.main()
