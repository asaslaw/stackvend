"""
Unit and Property Tests for:
1. Shift-Left Generic AST IaC Reference Graph Reconciliation (Anti-Band-Aid Curing)
2. Swarm Dispatcher True Concurrency & Thread-Safe State Locking
3. Async Developer Execution Endpoint with Guaranteed Callback Scope
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GATEWAY_PATH in sys.path:
    sys.path.remove(GATEWAY_PATH)
sys.path.insert(0, GATEWAY_PATH)
if REPO_ROOT not in sys.path:
    sys.path.insert(1, REPO_ROOT)
if 'main' in sys.modules:
    mod_file = getattr(sys.modules['main'], '__file__', '') or ''
    if 'orchestrator-gateway' not in mod_file:
        del sys.modules['main']

# Mock third-party libraries if not installed
try:
    import pydantic
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
        def model_dump(self):
            return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}

    class MockFieldInfo:
        def __init__(self, default=None, default_factory=None):
            self.default = default if default is not None else (default_factory() if default_factory else None)

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: MockFieldInfo(default, default_factory)
    mock_pydantic.EmailStr = str
    mock_pydantic.model_validator = lambda **kwargs: (lambda f: f)
    sys.modules['pydantic'] = mock_pydantic

try:
    import fastapi
except ImportError:
    class MockHTTPException(Exception):
        def __init__(self, status_code: int = 500, detail: str = ""):
            self.status_code = status_code
            self.detail = detail
            super().__init__(f"{status_code}: {detail}")

    mock_fastapi = MagicMock()
    mock_fastapi.HTTPException = MockHTTPException
    mock_fastapi.FastAPI.return_value.post = lambda *args, **kwargs: (lambda f: f)
    mock_fastapi.FastAPI.return_value.get = lambda *args, **kwargs: (lambda f: f)
    mock_fastapi.status.HTTP_202_ACCEPTED = 202
    sys.modules['fastapi'] = mock_fastapi

for m in [
    'httpx', 'google', 'google.genai', 'google.genai.types',
    'google.cloud', 'google.cloud.firestore', 'google.cloud.storage',
    'google.cloud.secretmanager', 'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

from developer_agent.terraform_engine import (
    extract_hcl_blocks,
    reconcile_multi_service_declarations,
)


def _reconcile_without_hb01(files, product_id, allow_unauthenticated=True):
    # FD-55 W5 (G16): HB-01 reconcile_iac_reference_graph is deleted. Its former caller (HB-04) is what runs at
    # generation now; these single-service trees must come out of it byte-identical.
    reconcile_multi_service_declarations(files, product_id, "", allow_unauthenticated=allow_unauthenticated)
from developer_agent.swarm_dispatcher import SwarmDispatcher
from developer_agent.swarm_schemas import (
    JuniorExecutionResult,
    JuniorPersona,
    JuniorTaskAssignment,
    LeadDeveloperDecompositionPlan,
    SwarmExecutionMode,
)


class TestIaCReferenceGraphReconciliation(unittest.TestCase):
    """Verifies shift-left generic AST reconciliation for undeclared IaC dependencies."""

    def test_undeclared_invoker_in_depends_on_is_not_synthesized(self):
        """
        When custom.tf declares a Cloud Scheduler job with depends_on = [google_cloud_run_v2_service_iam_member.scheduler_gateway_invoker],
        no run.invoker member is synthesized (S2-B B1; HB-01 itself is deleted, FD-55 W5).
        """
        files = {
            "infra/workload/main.tf": """
module "foundation" {
  source = "../modules/foundation"
  project_id = var.project_id
}

module "compute" {
  source = "../modules/compute-cloudrun"
  project_id = var.project_id
  service_name = "gateway"
}
""",
            "infra/workload/custom.tf": """
resource "google_service_account" "scheduler_sa" {
  account_id   = "scheduler-sa"
  display_name = "Scheduler SA"
}

resource "google_cloud_scheduler_job" "reconcile" {
  name        = "order-reconciliation-job"
  region      = var.region
  schedule    = "0 2 * * *"
  depends_on  = [
    google_cloud_run_v2_service_iam_member.scheduler_gateway_invoker
  ]
}
"""
        }

        before = files["infra/workload/custom.tf"]
        _reconcile_without_hb01(files, product_id="testplan02-a", allow_unauthenticated=False)

        # S2-B B1 (register HS-02): the run.invoker synthesis is deleted. The AI's block is kept byte-identical and
        # V1b reports the undeclared depends_on entry (TF.REFERENCE_TO_UNDECLARED_RESOURCE) for the repair loop.
        custom_tf = files["infra/workload/custom.tf"]
        self.assertEqual(custom_tf, before)
        self.assertNotIn('roles/run.invoker', custom_tf)

    def test_undeclared_depends_on_entry_is_kept(self):
        """
        When custom.tf contains an orphaned dependency to an undeclared resource that is not
        a canonical IAM binding, it must prune the invalid reference from depends_on so OpenTofu passes.
        """
        files = {
            "infra/workload/main.tf": """
module "foundation" {
  source = "../modules/foundation"
}
module "compute" {
  source = "../modules/compute-cloudrun"
}
""",
            "infra/workload/custom.tf": """
resource "google_cloud_scheduler_job" "sync_job" {
  name       = "sync-job"
  schedule   = "0 * * * *"
  depends_on = [
    module.compute,
    google_nonexistent_table.phantom_ref
  ]
}
"""
        }

        before = files["infra/workload/custom.tf"]
        _reconcile_without_hb01(files, product_id="testplan02-a")

        # S2-B B1 (HS-02): no prune; the undeclared entry is reported by V1b instead.
        self.assertEqual(files["infra/workload/custom.tf"], before)

    def test_all_undeclared_depends_on_is_kept(self):
        """If all items in depends_on are undeclared/orphaned, depends_on should be cleanly removed."""
        files = {
            "infra/workload/main.tf": "module \"foundation\" {}\nmodule \"compute\" {}",
            "infra/workload/custom.tf": """
resource "google_pubsub_topic" "events" {
  name       = "events-topic"
  depends_on = [
    google_nonexistent_resource.orphan
  ]
}
"""
        }

        before = files["infra/workload/custom.tf"]
        _reconcile_without_hb01(files, product_id="testplan02-a")

        # S2-B B1 (HS-02): the depends_on list is never removed by the platform.
        self.assertEqual(files["infra/workload/custom.tf"], before)


class TestSwarmDispatcherConcurrencyAndLocking(unittest.TestCase):
    """Verifies that SwarmDispatcher uses thread-safe state locks and runs inference off the event loop."""

    def test_swarm_dispatcher_has_state_lock(self):
        dispatcher = SwarmDispatcher(genai_client=None, max_concurrency=3)
        self.assertTrue(hasattr(dispatcher, "_state_lock"))
        self.assertIsInstance(dispatcher._state_lock, asyncio.Lock)

    def test_mock_swarm_execution_concurrency(self):
        """Verifies that multiple tasks can be executed under the semaphore and state lock without clobbering."""
        dispatcher = SwarmDispatcher(genai_client=None, max_concurrency=4)

        t1 = JuniorTaskAssignment(
            task_id="task-1",
            persona=JuniorPersona.BACKEND_ENGINEER,
            wave=1,
            task_objective="API 1",
            assigned_files=["apps/gateway/api.py"],
            iac_engine="opentofu",
        )
        t2 = JuniorTaskAssignment(
            task_id="task-2",
            persona=JuniorPersona.DATABASE_ENGINEER,
            wave=1,
            task_objective="DB 1",
            assigned_files=["apps/gateway/db.py"],
            iac_engine="opentofu",
        )
        plan = LeadDeveloperDecompositionPlan(
            execution_mode=SwarmExecutionMode.STANDARD_SWARM,
            lead_notes="Test",
            max_swarm_token_envelope=100000,
            tasks=[t1, t2],
        )

        # Lane 19 (27a): no junior stub files without an LLM; the model seam is faked (real invoke_junior_worker).
        from _lane19_fake_genai import async_assigned_files_fake
        dispatcher._call_gemini_with_backoff = async_assigned_files_fake(["apps/gateway/api.py", "apps/gateway/db.py"])
        staged_files = asyncio.run(dispatcher.execute_phased_junior_swarm(
            plan=plan,
            trace_id="test-trace-123",
            product_id="test-product",
        ))

        self.assertIn("apps/gateway/api.py", staged_files)
        self.assertIn("apps/gateway/db.py", staged_files)


class TestAsyncDeveloperExecution(unittest.TestCase):
    """Verifies async developer execution endpoint schema and dispatch logic."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("orchestrator_gateway_main", os.path.join(GATEWAY_PATH, "main.py"))
        cls.gw_main = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.gw_main)

    def test_developer_execute_request_has_callback_url(self):
        req = self.gw_main.DeveloperExecuteRequest(
            product_id="testplan02-a",
            callback_url="https://workflowexecutions.googleapis.com/v1/callbacks/abc123",
        )
        self.assertEqual(req.callback_url, "https://workflowexecutions.googleapis.com/v1/callbacks/abc123")
        self.assertEqual(req.product_id, "testplan02-a")

    def test_developer_execute_async_endpoint_returns_202(self):
        with patch.object(self.gw_main, "run_developer_execute_in_background") as mock_bg_worker:
            class FakeBackgroundTasks:
                def __init__(self):
                    self.tasks = []
                def add_task(self, func, *args, **kwargs):
                    self.tasks.append((func, args, kwargs))

            bg = FakeBackgroundTasks()
            req = self.gw_main.DeveloperExecuteRequest(
                product_id="testplan02-a",
                trace_id="trace-test-202",
                callback_url="https://callbacks.example.com/test",
            )
            resp = self.gw_main.developer_execute_async(req, bg)
            self.assertEqual(resp["status"], "ACCEPTED")
            self.assertEqual(resp["product_id"], "testplan02-a")
            self.assertEqual(len(bg.tasks), 1)


if __name__ == "__main__":
    unittest.main()
