"""
Project Castor: Unit & Integration Tests for Agentic Skills Catalog & Dynamic Context Injection Engine (Lean Phase 1)
Tests:
- Zero-database code-backed Built-In Skills Provider (shared/builtin_skills_provider.py)
- Sub-5ms deterministic Skills Resolver & Context Matching (shared/skills_resolver.py)
- Admin RBAC and CRUD Endpoints for Agent Skills (apps/control-center/routes/settings.py)
- Built-in skill immutability guards (cannot edit/delete built-ins via API)
- Agent prompt enrichment for Developer and Architect agents
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
cc_dir = os.path.join(repo_root, "apps", "control-center")
og_dir = os.path.join(repo_root, "apps", "orchestrator-gateway")

if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
if cc_dir not in sys.path:
    sys.path.append(cc_dir)
if og_dir not in sys.path:
    sys.path.append(og_dir)

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

# Mock FastAPI
class MockHTTPException(Exception):
    def __init__(self, status_code: int, detail: str = ""):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"{status_code}: {detail}")


def mock_decorator(*args, **kwargs):
    def inner(fn):
        return fn
    return inner


mock_app = MagicMock()
mock_app.get = mock_decorator
mock_app.post = mock_decorator
mock_app.put = mock_decorator
mock_app.delete = mock_decorator
mock_app.patch = mock_decorator
mock_app.middleware = mock_decorator

mock_fastapi = MagicMock()
mock_fastapi.HTTPException = MockHTTPException
mock_fastapi.FastAPI = lambda *args, **kwargs: mock_app
mock_fastapi.APIRouter = lambda *args, **kwargs: mock_app
mock_fastapi.Request = MagicMock
mock_fastapi.Response = MagicMock
sys.modules["fastapi"] = mock_fastapi

mock_responses = MagicMock()
mock_responses.HTMLResponse = MagicMock
mock_responses.JSONResponse = MagicMock
mock_responses.RedirectResponse = MagicMock
sys.modules["fastapi.responses"] = mock_responses

# Mock Pydantic if needed
try:
    import pydantic
except ImportError:
    class MockFieldInfo:
        def __init__(self, default=None, default_factory=None):
            self.default = default
            self.default_factory = default_factory
        def get_value(self):
            if self.default_factory is not None:
                return self.default_factory()
            return self.default

    class MockBaseModel:
        def __init__(self, **kwargs):
            for cls in reversed(self.__class__.__mro__):
                for k, v in cls.__dict__.items():
                    if not k.startswith('_') and not callable(v):
                        default_val = v.get_value() if isinstance(v, MockFieldInfo) else v
                        if default_val is not Ellipsis:
                            setattr(self, k, default_val)
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self):
            res = {}
            for k, v in self.__dict__.items():
                if not k.startswith('_'):
                    if hasattr(v, 'model_dump'):
                        res[k] = v.model_dump()
                    elif isinstance(v, list):
                        res[k] = [item.model_dump() if hasattr(item, 'model_dump') else item for item in v]
                    elif isinstance(v, dict):
                        res[k] = {ik: (iv.model_dump() if hasattr(iv, 'model_dump') else iv) for ik, iv in v.items()}
                    else:
                        res[k] = v
            return res

        def dict(self):
            return self.model_dump()

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: MockFieldInfo(default=default, default_factory=default_factory)
    mock_pydantic.EmailStr = str
    sys.modules['pydantic'] = mock_pydantic

# Load cc_schemas
_cc_schemas_spec = importlib.util.spec_from_file_location("cc_schemas", os.path.join(cc_dir, "schemas.py"))
cc_schemas = importlib.util.module_from_spec(_cc_schemas_spec)
sys.modules["schemas"] = cc_schemas
_cc_schemas_spec.loader.exec_module(cc_schemas)

# Import Built-in skills and skills resolver
from shared.builtin_skills_provider import get_builtin_skills, get_builtin_skill_by_id
from shared.skills_resolver import resolve_active_skills, format_skills_for_prompt

# Load routes.settings
_cc_settings_spec = importlib.util.spec_from_file_location("routes_settings", os.path.join(cc_dir, "routes", "settings.py"))
routes_settings = importlib.util.module_from_spec(_cc_settings_spec)
sys.modules["routes.settings"] = routes_settings
_cc_settings_spec.loader.exec_module(routes_settings)

# Import agent prompt builders
from developer_agent.prompt import build_developer_system_prompt
from architect_agent.prompt import build_architect_system_prompt


class TestBuiltinSkillsProvider(unittest.TestCase):
    """Test the Zero-Database Code-Backed Built-In Skills Provider."""

    def test_canonical_builtin_skills_count_and_keys(self):
        skills = get_builtin_skills()
        self.assertGreaterEqual(len(skills), 6)
        
        skill_ids = [s["skill_id"] for s in skills]
        expected_skills = [
            "gcp-direct-iap",
            "golden-terraform-patterns",
            "heavy-stateful-applier",
            "zero-trust-org-policies",
            "qa-security-and-coverage-standards",
            "sre-incident-rca-standards"
        ]
        for exp in expected_skills:
            self.assertIn(exp, skill_ids, f"Expected canonical skill {exp} not found in provider")

    def test_builtin_skills_attributes(self):
        skills = get_builtin_skills()
        for s in skills:
            self.assertTrue(s["skill_id"])
            self.assertTrue(s["name"])
            self.assertTrue(s["description"])
            self.assertTrue(s["target_agent"])
            self.assertEqual(s["source_type"], "BUILT_IN")
            self.assertTrue(s["instructions_markdown"])
            self.assertIn("##", s["instructions_markdown"])

    def test_get_builtin_skill_by_id(self):
        skill = get_builtin_skill_by_id("gcp-direct-iap")
        self.assertIsNotNone(skill)
        self.assertEqual(skill["skill_id"], "gcp-direct-iap")
        self.assertEqual(skill["target_agent"], "DEVELOPER_AGENT")
        self.assertIn("iap", skill["trigger_keywords"])

        none_skill = get_builtin_skill_by_id("non-existent-skill")
        self.assertIsNone(none_skill)


class TestSkillsResolver(unittest.TestCase):
    """Test deterministic sub-5ms skills resolution and prompt formatting."""

    def test_always_active_resolution(self):
        # golden-terraform-patterns has always_active=True and target_agent=DEVELOPER_AGENT
        skills = resolve_active_skills(target_agent="DEVELOPER_AGENT", context_text="Empty task", db_client=None)
        skill_ids = [s["skill_id"] for s in skills]
        self.assertIn("golden-terraform-patterns", skill_ids)

    def test_keyword_triggered_resolution(self):
        # gcp-direct-iap has always_active=False, trigger_keywords=["iap", "identity-aware proxy", ...]
        skills_without_kw = resolve_active_skills(target_agent="DEVELOPER_AGENT", context_text="Create a compute engine vm", db_client=None)
        ids_without = [s["skill_id"] for s in skills_without_kw]
        self.assertNotIn("gcp-direct-iap", ids_without)

        skills_with_kw = resolve_active_skills(target_agent="DEVELOPER_AGENT", context_text="Configure access using IAP and tunnel", db_client=None)
        ids_with = [s["skill_id"] for s in skills_with_kw]
        self.assertIn("gcp-direct-iap", ids_with)

    def test_agent_role_scoping(self):
        # QA skill (qa-security-and-coverage-standards) should not be injected into DEVELOPER_AGENT
        dev_skills = resolve_active_skills(target_agent="DEVELOPER_AGENT", context_text="test coverage pytest", db_client=None)
        dev_ids = [s["skill_id"] for s in dev_skills]
        self.assertNotIn("qa-security-and-coverage-standards", dev_ids)

        # QA skill should be injected for QA_AGENT
        qa_skills = resolve_active_skills(target_agent="QA_AGENT", context_text="run tests", db_client=None)
        qa_ids = [s["skill_id"] for s in qa_skills]
        self.assertIn("qa-security-and-coverage-standards", qa_ids)

    def test_global_all_agents_scoping(self):
        # zero-trust-org-policies is target_agent=ALL_AGENTS
        # Trigger it with "org policy"
        arch_skills = resolve_active_skills(target_agent="ARCHITECT_AGENT", context_text="enforce org policy constraints", db_client=None)
        arch_ids = [s["skill_id"] for s in arch_skills]
        self.assertIn("zero-trust-org-policies", arch_ids)

        comp_skills = resolve_active_skills(target_agent="COMPLIANCE_AGENT", context_text="check org policy violations", db_client=None)
        comp_ids = [s["skill_id"] for s in comp_skills]
        self.assertIn("zero-trust-org-policies", comp_ids)

    def test_format_skills_for_prompt(self):
        skills = get_builtin_skills()[:2]
        formatted = format_skills_for_prompt(skills)
        self.assertIn("DYNAMIC AGENTIC SKILLS & DOMAIN GUIDELINES", formatted)
        self.assertIn(f"--- [ACTIVE SKILL: {skills[0]['name']}", formatted)
        self.assertIn(skills[0]["instructions_markdown"], formatted)

    def test_format_empty_skills_returns_empty_string(self):
        self.assertEqual(format_skills_for_prompt([]), "")


class TestAgentSkillsAdminEndpoints(unittest.TestCase):
    """Test Control Center Admin REST API routes for Skills Catalog."""

    def setUp(self):
        self.mock_request_admin = MagicMock()
        self.mock_request_admin.state.user_role = "ADMIN"
        self.mock_request_admin.state.user_email = "admin@castor.internal"
        self.mock_request_admin.state.user = {"role": "ADMIN", "email": "admin@castor.internal"}
        
        self.mock_request_viewer = MagicMock()
        self.mock_request_viewer.state.user_role = "VIEWER"
        self.mock_request_viewer.state.user_email = "viewer@castor.internal"
        self.mock_request_viewer.state.user = {"role": "VIEWER", "email": "viewer@castor.internal"}

    def test_list_skills_admin_success(self):
        with patch.object(routes_settings, "db", None):
            resp = routes_settings.list_skills_endpoint(self.mock_request_admin)
            # Response can be a SkillsListResponse model or dict
            skills_list = resp.skills if hasattr(resp, "skills") else resp["skills"]
            builtin_count = resp.builtin_skills_count if hasattr(resp, "builtin_skills_count") else resp["builtin_skills_count"]
            total_custom = resp.total_custom if hasattr(resp, "total_custom") else resp["total_custom"]

            self.assertGreaterEqual(len(skills_list), 6)
            self.assertGreaterEqual(builtin_count, 6)
            self.assertEqual(total_custom, 0)

    def test_list_skills_viewer_forbidden(self):
        # verify_admin_access is a no-op under TEST_MODE; exercise the production RBAC path.
        with patch.dict(os.environ), patch.object(routes_settings, "db", None):
            os.environ.pop("TEST_MODE", None)
            with self.assertRaises(MockHTTPException) as ctx:
                routes_settings.list_skills_endpoint(self.mock_request_viewer)
            self.assertEqual(ctx.exception.status_code, 403)

    def test_get_builtin_skill_detail(self):
        with patch.object(routes_settings, "db", None):
            skill = routes_settings.get_skill_endpoint("gcp-direct-iap", self.mock_request_admin)
            skill_id = skill.skill_id if hasattr(skill, "skill_id") else skill["skill_id"]
            source_type = skill.source_type if hasattr(skill, "source_type") else skill["source_type"]
            self.assertEqual(skill_id, "gcp-direct-iap")
            val = source_type.value if hasattr(source_type, "value") else str(source_type)
            self.assertEqual(val, "BUILT_IN")

    def test_get_nonexistent_skill_raises_404(self):
        mock_db = MagicMock()
        mock_db.collection.return_value.document.return_value.get.return_value.exists = False
        with patch.object(routes_settings, "db", mock_db):
            with self.assertRaises(MockHTTPException) as ctx:
                routes_settings.get_skill_endpoint("unknown-skill", self.mock_request_admin)
            self.assertEqual(ctx.exception.status_code, 404)

    def test_create_custom_skill(self):
        mock_db = MagicMock()
        mock_doc = MagicMock()
        mock_doc.get.return_value.exists = False
        mock_db.collection.return_value.document.return_value = mock_doc

        req = cc_schemas.CreateSkillRequest(
            skill_id="corp-dlp-rules",
            name="Corporate DLP Rules",
            description="Enforce DLP policies on BigQuery datasets",
            target_agent="COMPLIANCE_AGENT",
            always_active=True,
            trigger_keywords=["dlp", "pii"],
            instructions_markdown="# Corp DLP Guidelines\n- Never export PII without masking."
        )

        with patch.object(routes_settings, "db", mock_db):
            created = routes_settings.create_skill_endpoint(req, self.mock_request_admin)
            skill_id = created.skill_id if hasattr(created, "skill_id") else created["skill_id"]
            source_type = created.source_type if hasattr(created, "source_type") else created["source_type"]
            self.assertEqual(skill_id, "corp-dlp-rules")
            source_val = source_type.value if hasattr(source_type, "value") else str(source_type)
            self.assertIn(source_val, ["CUSTOM", "SkillSourceType.CUSTOM"])
            self.assertTrue(mock_doc.set.called)

    def test_create_skill_collision_with_builtin_fails(self):
        req = cc_schemas.CreateSkillRequest(
            skill_id="gcp-direct-iap",
            name="Conflicting IAP Skill",
            description="Attempt to overwrite built-in",
            instructions_markdown="# Conflict"
        )
        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.create_skill_endpoint(req, self.mock_request_admin)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("collides with a native built-in platform skill", ctx.exception.detail)

    def test_immutability_guards_patch_builtin_fails(self):
        req = cc_schemas.UpdateSkillRequest(name="New Name")
        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.update_skill_endpoint("gcp-direct-iap", req, self.mock_request_admin)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Built-in skills are immutable", ctx.exception.detail)

    def test_immutability_guards_delete_builtin_fails(self):
        with self.assertRaises(MockHTTPException) as ctx:
            routes_settings.delete_skill_endpoint("gcp-direct-iap", self.mock_request_admin)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Built-in skills are immutable", ctx.exception.detail)


class TestAgentPromptEnrichment(unittest.TestCase):
    """Test dynamic skills injection into Developer and Architect agent system prompts."""

    def test_developer_prompt_enrichment(self):
        # Developer prompt without IAP context should have golden-terraform-patterns (always_active)
        prompt = build_developer_system_prompt("Provision standard VPC")
        self.assertIn("DYNAMIC AGENTIC SKILLS & DOMAIN GUIDELINES", prompt)
        self.assertIn("golden-terraform-patterns", prompt)
        self.assertNotIn("gcp-direct-iap", prompt)

        # Developer prompt with IAP context should inject gcp-direct-iap
        prompt_iap = build_developer_system_prompt("Configure private compute instance behind IAP tunnel")
        self.assertIn("gcp-direct-iap", prompt_iap)

    def test_architect_prompt_enrichment(self):
        # Architect prompt with Org Policy context should inject zero-trust-org-policies
        prompt = build_architect_system_prompt("Review enterprise network design with org policy constraints")
        self.assertIn("DYNAMIC AGENTIC SKILLS & DOMAIN GUIDELINES", prompt)
        self.assertIn("zero-trust-org-policies", prompt)


if __name__ == "__main__":
    unittest.main()
