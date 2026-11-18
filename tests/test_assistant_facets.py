"""
Project Castor: Unit Tests for Castor Assistant Multi-Facet Intelligence
Tests:
- Golden Modules & Custom Modules catalog awareness
- Pipeline Flight Deck execution context
- Pending HITL approvals context
- Platform governance & settings context
- Intent routing & implementation plan assistance
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
cc_dir = os.path.join(repo_root, "apps", "control-center")
sys.path.insert(0, repo_root)
sys.path.insert(0, cc_dir)

# Mock external cloud clients and frameworks before imports if needed
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
mock_fastapi.Request = MagicMock
mock_fastapi.Response = MagicMock
sys.modules["fastapi"] = mock_fastapi

# Mock Pydantic
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

_cc_schemas_spec = importlib.util.spec_from_file_location("cc_schemas", os.path.join(cc_dir, "schemas.py"))
cc_schemas = importlib.util.module_from_spec(_cc_schemas_spec)
sys.modules["schemas"] = cc_schemas
_cc_schemas_spec.loader.exec_module(cc_schemas)

_cc_assistant_spec = importlib.util.spec_from_file_location("cc_assistant", os.path.join(cc_dir, "assistant.py"))
cc_assistant = importlib.util.module_from_spec(_cc_assistant_spec)
sys.modules["assistant"] = cc_assistant
_cc_assistant_spec.loader.exec_module(cc_assistant)

UserRole = cc_schemas.UserRole
CastorAssistantEngine = cc_assistant.CastorAssistantEngine


@hermetic_guard.unavailable("google.genai.Client", "Gemini")
class TestAssistantFacets(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.engine = CastorAssistantEngine(firestore_client=self.mock_db)

    def test_catalog_modules_summary_includes_builtins_and_custom(self):
        """Verifies assistant retrieves all 24 built-ins plus custom modules from Firestore."""
        # Mock a custom module in Firestore
        mock_custom = MagicMock()
        mock_custom.id = "custom-vpc-module"
        mock_custom.to_dict.return_value = {
            "module_id": "custom-vpc-module",
            "name": "Enterprise Custom VPC",
            "category": "NETWORKING",
            "source_type": "DIRECT_CODE",
            "override_builtin": None,
            "is_active": True,
            "inputs": [{"name": "vpc_name", "type": "string", "required": True}],
            "outputs": [{"name": "vpc_id"}],
            "description": "Custom hardened VPC module",
        }
        self.mock_db.collection.return_value.stream.return_value = [mock_custom]

        catalog = self.engine.get_catalog_modules_summary()
        self.assertGreaterEqual(len(catalog), 25)

        # Check native built-in networking-vpc
        native_vpc = next((m for m in catalog if m["module_id"] == "networking-vpc"), None)
        self.assertIsNotNone(native_vpc)
        self.assertEqual(native_vpc["source_type"], "BUILT_IN")
        self.assertEqual(native_vpc["category"], "NETWORKING")

        # Check custom-vpc-module
        custom_vpc = next((m for m in catalog if m["module_id"] == "custom-vpc-module"), None)
        self.assertIsNotNone(custom_vpc)
        self.assertEqual(custom_vpc["source_type"], "DIRECT_CODE")
        self.assertIn("vpc_name: string (required)", custom_vpc["inputs"])

    def test_assistant_answers_custom_vpc_module_query(self):
        """Verifies assistant answers questions about custom modules."""
        mock_custom = MagicMock()
        mock_custom.id = "custom-vpc-module"
        mock_custom.to_dict.return_value = {
            "module_id": "custom-vpc-module",
            "name": "Enterprise Custom VPC",
            "category": "NETWORKING",
            "source_type": "DIRECT_CODE",
            "override_builtin": None,
            "is_active": True,
            "inputs": [{"name": "vpc_name", "type": "string", "required": True}],
            "outputs": [{"name": "vpc_id"}],
            "description": "Custom hardened VPC module",
        }
        self.mock_db.collection.return_value.stream.return_value = [mock_custom]

        # Query asking for custom module name
        res = self.engine.handle_chat_message(
            message="Hey Castor, what is the custom vpc module name?",
            user_role=UserRole.ADMIN,
            user_email="admin@castor.io",
        )
        self.assertIn("custom-vpc-module", res.response_text)
        self.assertIn("Custom Enterprise Golden Modules", res.response_text)

    def test_assistant_implementation_plan_assistance(self):
        """Verifies assistant provides implementation planning guidance."""
        res = self.engine.handle_chat_message(
            message="Help me build an implementation plan before actually building it",
            user_role=UserRole.ADMIN,
            user_email="admin@castor.io",
        )
        self.assertIn("Implementation Plan", res.response_text)

    def test_assistant_approvals_query(self):
        """Verifies assistant reports pending approvals."""
        mock_appr = MagicMock()
        mock_appr.id = "appr-001"
        mock_appr.to_dict.return_value = {
            "approval_id": "appr-001",
            "product_id": "payment-service",
            "status": "PENDING",
            "summary": "Deploying Postgres Cloud SQL cluster",
        }
        self.mock_db.collection.return_value.where.return_value.stream.return_value = [mock_appr]

        res = self.engine.handle_chat_message(
            message="Do we have any pending approvals?",
            user_role=UserRole.ADMIN,
            user_email="admin@castor.io",
        )
        self.assertIn("Pending Tier 3 HITL Approvals", res.response_text)
        self.assertIn("appr-001", res.response_text)
        self.assertIn("payment-service", res.response_text)


if __name__ == "__main__":
    unittest.main()
