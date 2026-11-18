"""
Project Castor: Unit Tests for Workload-Scoped RBAC, Role Simplification, and Assistant AI Guardrails
Verifies:
1. Legacy APPROVER role backward-compatible migration to WORKLOAD_MANAGER.
2. Endpoint security gates: verify_admin_access and verify_workload_access.
3. Workload scoping for non-admin users (0-read fast path and db.get_all batching).
4. PUT /api/users/{email}/workloads endpoint functionality.
5. Assistant pre-LLM context sandboxing, token pruning, and role-based action gating.
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

mock_responses = MagicMock()
mock_responses.HTMLResponse = MagicMock
mock_responses.JSONResponse = MagicMock
mock_responses.RedirectResponse = MagicMock
sys.modules["fastapi.responses"] = mock_responses

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

_cc_main_spec = importlib.util.spec_from_file_location("cc_main", os.path.join(cc_dir, "main.py"))
cc_main = importlib.util.module_from_spec(_cc_main_spec)
sys.modules["main"] = cc_main
_cc_main_spec.loader.exec_module(cc_main)

UserRole = cc_schemas.UserRole
UserAccessRecord = cc_schemas.UserAccessRecord
AddUserRequest = cc_schemas.AddUserRequest
UpdateUserWorkloadsRequest = cc_schemas.UpdateUserWorkloadsRequest
WorkloadSummary = cc_schemas.WorkloadSummary
CastorAssistantEngine = cc_assistant.CastorAssistantEngine
prune_workloads_for_context = cc_assistant.prune_workloads_for_context


class TestRBACSchemasAndRoleSimplification(unittest.TestCase):
    """Tests schema level role simplification and backward compatibility."""

    def test_legacy_approver_role_normalized_to_workload_manager(self):
        """Legacy 'APPROVER' records from Firestore must be transparently translated to WORKLOAD_MANAGER."""
        record = UserAccessRecord(
            email="lead-eng@castor.internal",
            role="APPROVER",
            assigned_workloads=["castor-app", "billing-svc"],
            added_at="2026-01-01T00:00:00Z",  # FD-05 B-9: required field
        )
        self.assertEqual(record.role, UserRole.WORKLOAD_MANAGER)
        self.assertEqual(record.assigned_workloads, ["castor-app", "billing-svc"])

    def test_admin_and_viewer_roles(self):
        admin_rec = UserAccessRecord(email="admin@castor.internal", role=UserRole.ADMIN,
                                     added_at="2026-01-01T00:00:00Z")  # FD-05 B-10
        self.assertEqual(admin_rec.role, UserRole.ADMIN)
        self.assertEqual(admin_rec.assigned_workloads, [])

        viewer_rec = UserAccessRecord(
            email="analyst@castor.internal",
            role=UserRole.VIEWER,
            assigned_workloads=["castor-app"],
            added_at="2026-01-01T00:00:00Z",  # FD-05 B-10
        )
        self.assertEqual(viewer_rec.role, UserRole.VIEWER)
        self.assertEqual(viewer_rec.assigned_workloads, ["castor-app"])

    def test_update_user_workloads_request_schema(self):
        req = UpdateUserWorkloadsRequest(
            assigned_workloads=["analytics-engine", "data-pipeline"],
            role=UserRole.WORKLOAD_MANAGER,
        )
        self.assertEqual(len(req.assigned_workloads), 2)
        self.assertEqual(req.role, UserRole.WORKLOAD_MANAGER)


class TestAccessControlGuards(unittest.TestCase):
    """Tests verify_admin_access and verify_workload_access helper functions."""

    def setUp(self):
        self.orig_test_mode = os.environ.get("TEST_MODE")
        if "TEST_MODE" in os.environ:
            del os.environ["TEST_MODE"]

    def tearDown(self):
        if self.orig_test_mode is not None:
            os.environ["TEST_MODE"] = self.orig_test_mode
        elif "TEST_MODE" in os.environ:
            del os.environ["TEST_MODE"]

    def test_verify_admin_access_allows_admin(self):
        mock_req = MagicMock()
        mock_req.state.user_role = UserRole.ADMIN
        self.assertTrue(cc_main.verify_admin_access(mock_req))

    def test_verify_admin_access_rejects_non_admin(self):
        for role in [UserRole.WORKLOAD_MANAGER, UserRole.VIEWER]:
            mock_req = MagicMock()
            mock_req.state.user_role = role
            with self.assertRaises(MockHTTPException) as ctx:
                cc_main.verify_admin_access(mock_req)
            self.assertEqual(ctx.exception.status_code, 403)

    def test_verify_workload_access_admin_bypasses_check(self):
        mock_req = MagicMock()
        mock_req.state.user_role = UserRole.ADMIN
        mock_req.state.assigned_workloads = []
        self.assertTrue(cc_main.verify_workload_access("any-product", mock_req))

    def test_verify_workload_access_manager_assigned(self):
        mock_req = MagicMock()
        mock_req.state.user_role = UserRole.WORKLOAD_MANAGER
        mock_req.state.assigned_workloads = ["castor-app", "finance-service"]
        self.assertTrue(cc_main.verify_workload_access("castor-app", mock_req))
        self.assertTrue(cc_main.verify_workload_access("FINANCE-SERVICE", mock_req))

    def test_verify_workload_access_manager_unassigned(self):
        mock_req = MagicMock()
        mock_req.state.user_role = UserRole.WORKLOAD_MANAGER
        mock_req.state.assigned_workloads = ["castor-app"]
        with self.assertRaises(MockHTTPException) as ctx:
            cc_main.verify_workload_access("unauthorized-workload", mock_req)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_verify_workload_access_viewer_read_only(self):
        mock_req = MagicMock()
        mock_req.state.user_role = UserRole.VIEWER
        mock_req.state.assigned_workloads = ["castor-app"]

        # Read operation succeeds
        self.assertTrue(cc_main.verify_workload_access("castor-app", mock_req, require_manager=False))

        # Write operation fails with 403
        with self.assertRaises(MockHTTPException) as ctx:
            cc_main.verify_workload_access("castor-app", mock_req, require_manager=True)
        self.assertEqual(ctx.exception.status_code, 403)


class TestWorkloadScopingEndpoints(unittest.TestCase):
    """Tests scoping in list_workloads and user workload assignment updates."""

    def setUp(self):
        self.orig_test_mode = os.environ.get("TEST_MODE")
        if "TEST_MODE" in os.environ:
            del os.environ["TEST_MODE"]

    def tearDown(self):
        if self.orig_test_mode is not None:
            os.environ["TEST_MODE"] = self.orig_test_mode
        elif "TEST_MODE" in os.environ:
            del os.environ["TEST_MODE"]

    def test_list_workloads_empty_assignment_returns_empty_zero_reads(self):
        mock_req = MagicMock()
        mock_req.state.user_role = UserRole.WORKLOAD_MANAGER
        mock_req.state.assigned_workloads = []

        with patch.object(cc_main, "db") as mock_db:
            res = cc_main.list_workloads(request=mock_req)
            self.assertEqual(res, [])
            mock_db.collection.assert_not_called()
            mock_db.get_all.assert_not_called()

    def test_list_workloads_manager_uses_batched_get_all(self):
        mock_req = MagicMock()
        mock_req.state.user_role = UserRole.WORKLOAD_MANAGER
        mock_req.state.assigned_workloads = ["prod-a", "prod-b"]

        snap_a = MagicMock()
        snap_a.exists = True
        snap_a.id = "prod-a"
        snap_a.to_dict.return_value = {
            "product_id": "prod-a",
            "project_id": "castor-prod-a",
            "status": "ACTIVE",
            "current_spend_usd": 15.0,
            "budget_ceiling_monthly_usd": 50.0,
        }

        snap_b = MagicMock()
        snap_b.exists = True
        snap_b.id = "prod-b"
        snap_b.to_dict.return_value = {
            "product_id": "prod-b",
            "project_id": "castor-prod-b",
            "status": "ACTIVE",
            "current_spend_usd": 25.0,
            "budget_ceiling_monthly_usd": 50.0,
        }

        with patch.object(cc_main, "db") as mock_db:
            mock_db.get_all.return_value = [snap_a, snap_b]
            res = cc_main.list_workloads(request=mock_req)
            self.assertEqual(len(res), 2)
            self.assertEqual(res[0].product_id, "prod-a")
            self.assertEqual(res[1].product_id, "prod-b")
            mock_db.get_all.assert_called_once()

    def test_update_user_workloads_endpoint(self):
        mock_req = MagicMock()
        mock_req.state.user_role = UserRole.ADMIN

        update_payload = UpdateUserWorkloadsRequest(
            assigned_workloads=["workload-1", "workload-2"],
            role=UserRole.WORKLOAD_MANAGER,
        )

        with patch.object(cc_main, "db") as mock_db:
            mock_doc_ref = MagicMock()
            mock_doc = MagicMock()
            mock_doc.exists = True
            mock_doc.to_dict.return_value = {
                "email": "engineer@castor.internal",
                "role": "VIEWER",
                "assigned_workloads": [],
                "added_at": "2026-01-01T00:00:00Z",  # FD-05 B-11: every real writer stores it
            }
            mock_doc_ref.get.return_value = mock_doc
            mock_db.collection.return_value.document.return_value = mock_doc_ref

            updated_record = cc_main.update_user_workloads(
                email="engineer@castor.internal",
                req=update_payload,
                request=mock_req,
            )

            self.assertEqual(updated_record.email, "engineer@castor.internal")
            self.assertEqual(updated_record.role, UserRole.WORKLOAD_MANAGER)
            self.assertEqual(updated_record.assigned_workloads, ["workload-1", "workload-2"])
            # FD-4CI-b: the change is written in one batch with its user_access_audit entry
            batch = mock_db.batch.return_value
            (ref, data), kw = batch.set.call_args_list[0]
            self.assertIs(ref, mock_doc_ref)
            self.assertEqual(kw, {"merge": True})
            self.assertEqual((data["role"], data["assigned_workloads"]), ("WORKLOAD_MANAGER", ["workload-1", "workload-2"]))
            batch.commit.assert_called_once()


class TestAssistantGuardrailsAndSandboxing(unittest.TestCase):
    """Tests pre-LLM context sandboxing and role gating in CastorAssistantEngine."""

    def test_prune_workloads_for_context(self):
        raw_workloads = [
            {
                "product_id": "heavy-workload",
                "status": "ACTIVE",
                "budget_ceiling_monthly_usd": 100.0,
                "current_spend_usd": 45.0,
                "service_url": "https://heavy.run.app",
                "code_freeze": False,
                "heavy_terraform_manifest": {"large": "data"},
                "task_dag": ["task1", "task2", "task3"],
            }
        ]
        pruned = prune_workloads_for_context(raw_workloads)
        self.assertEqual(len(pruned), 1)
        self.assertIn("product_id", pruned[0])
        self.assertIn("status", pruned[0])
        self.assertIn("budget_ceiling_monthly_usd", pruned[0])
        self.assertIn("service_url", pruned[0])
        self.assertIn("code_freeze", pruned[0])
        self.assertNotIn("heavy_terraform_manifest", pruned[0])
        self.assertNotIn("task_dag", pruned[0])

    def test_assistant_viewer_read_only_mode(self):
        engine = CastorAssistantEngine()
        res = engine.handle_chat_message(
            message="Please build and deploy feature XYZ immediately",
            conversation_history=[],
            user_role=UserRole.VIEWER,
            assigned_workloads=["castor-app"],
            user_email="viewer@castor.internal",
        )
        self.assertIn("Read-Only Mode", res.response_text)
        self.assertTrue(any("Topology" in chip or "Assets" in chip for chip in res.actions_suggested))

    def test_assistant_manager_unassigned_workload_rejected(self):
        engine = CastorAssistantEngine()
        res = engine.handle_chat_message(
            message="Please deploy new feature for unauthorized-project",
            conversation_history=[],
            user_role=UserRole.WORKLOAD_MANAGER,
            assigned_workloads=["authorized-project"],
            user_email="manager@castor.internal",
        )
        self.assertIn("Scope Boundary", res.response_text)
        self.assertIn("authorized-project", res.response_text)


if __name__ == "__main__":
    unittest.main()
