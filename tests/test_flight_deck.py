"""
Project Castor: Unit Tests for Live Flight Deck & In-Flight Pipeline Tracker
Tests schemas, active execution queries, telemetry endpoints, and retrigger initial tracking.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from types import SimpleNamespace

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

# Ensure FastAPI mock uses passthrough decorators
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
mock_app.middleware = mock_decorator

mock_fastapi = MagicMock()
mock_fastapi.HTTPException = MockHTTPException
mock_fastapi.FastAPI = lambda *args, **kwargs: mock_app
mock_fastapi.Request = MagicMock
mock_fastapi.Response = MagicMock
mock_fastapi.status.HTTP_202_ACCEPTED = 202
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

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: default if default is not None else (default_factory() if default_factory else None)
    mock_pydantic.EmailStr = str
    sys.modules['pydantic'] = mock_pydantic
    BaseModel = MockBaseModel
    Field = mock_pydantic.Field

# Import schemas from apps/control-center/schemas.py
import importlib.util
_spec = importlib.util.spec_from_file_location('cc_schemas', os.path.join(cc_dir, 'schemas.py'))
cc_schemas = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc_schemas)

StageExecutionDetail = cc_schemas.StageExecutionDetail
PipelineExecutionItem = cc_schemas.PipelineExecutionItem
ActiveExecutionsResponse = cc_schemas.ActiveExecutionsResponse
FlightDeckResponse = cc_schemas.FlightDeckResponse

_cc_main_spec = importlib.util.spec_from_file_location('cc_main', os.path.join(cc_dir, 'main.py'))
cc_main = importlib.util.module_from_spec(_cc_main_spec)
_cc_main_spec.loader.exec_module(cc_main)
import workflow_executions as cc_wfx  # noqa: E402  (the module the CC routes use; SAT-43 REST cancel)


class _CancellingWorkflows:
    """SAT-43: a Workflows REST stand-in whose cancel succeeds (the old client-library call was a silent no-op here)."""

    def __init__(self):
        self.cancelled = []

    def post(self, url, json=None, timeout=None):
        self.cancelled.append(url)
        return SimpleNamespace(status_code=200, json=lambda: {"state": "CANCELLED"})


def _workflows_session():
    fake = _CancellingWorkflows()
    return fake, patch.multiple(cc_wfx, session_provider=lambda: fake, region_provider=lambda: "us-central1")


# --- STALE-RUN-AUTOFAIL-BOUND helpers: one active-runs poll over given records, with a Workflows state stand-in -------
_WF_NAME = "projects/p/locations/us-central1/workflows/castor-main-orchestrator/executions/e-bound"


class _StateWorkflows:
    """Workflows REST stand-in for get_execution_state: answers `state`, or HTTP `http_status`, or raises `exc`."""

    def __init__(self, state="ACTIVE", http_status=200, exc=None):
        self.state, self.http_status, self.exc = state, http_status, exc
        self.reads = 0
        self.timeouts = []
        self.sessions_built = 0  # incremented by _poll's session provider

    def get(self, url, timeout=None):
        self.reads += 1
        self.timeouts.append(timeout)
        if self.exc is not None:
            raise self.exc
        if self.http_status != 200:
            return SimpleNamespace(status_code=self.http_status,
                                   json=lambda: {"error": {"status": "INTERNAL", "message": "backend error"}})
        return SimpleNamespace(status_code=200, json=lambda: {"state": self.state})


def _iso_ago(seconds):
    from datetime import timedelta
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()


def _active_doc(trace_id, fields):
    doc = MagicMock()
    doc.id = trace_id
    record = {"trace_id": trace_id, "product_id": "active-app", "status": "ACTIVE"}
    record.update(fields)
    doc.to_dict.return_value = record
    return doc


def _terminal_write(doc):
    """The payload of the reconcile's version-checked write (RT F3: reference.update with a last_update_time option)."""
    doc.reference.set.assert_not_called()
    return doc.reference.update.call_args[0][0]


def _poll(docs, fake_wf=None, fresh_cache=True, mock_db=None):
    """Runs get_active_pipeline_executions once over `docs` (parent workload ACTIVE), by default with a fresh
    rate-limit cache."""
    telemetry_globals = cc_main.get_active_pipeline_executions.__globals__
    if fresh_cache:
        telemetry_globals["_wf_check_cache"].clear()
        telemetry_globals["_ts_parse_warned"].clear()
    active_query = MagicMock()
    active_query.stream.return_value = docs
    workload_doc = MagicMock()
    workload_doc.exists = True
    workload_doc.to_dict.return_value = {"status": "ACTIVE"}

    def col_side_effect(col_name):
        col_m = MagicMock()
        if col_name == "pipeline_executions":
            col_m.where.return_value = active_query
            col_m.order_by.return_value.limit.return_value.stream.return_value = []
        elif col_name == "workloads":
            col_m.document.return_value.get.return_value = workload_doc
        return col_m

    mock_db = mock_db if mock_db is not None else MagicMock()
    mock_db.collection.side_effect = col_side_effect

    def no_session():
        raise AssertionError("the Workflows API must not be called")

    def fake_session():
        fake_wf.sessions_built += 1
        return fake_wf

    provider = fake_session if fake_wf is not None else no_session
    with patch.object(cc_main, "db", mock_db), \
            patch.multiple(cc_wfx, session_provider=provider, region_provider=lambda: "us-central1"):
        return cc_main.get_active_pipeline_executions()


class TestFlightDeckSchemas(unittest.TestCase):
    """Verifies that Flight Deck and Pipeline observability schemas serialize accurately."""

    def test_stage_execution_detail_defaults(self):
        stage = StageExecutionDetail()
        self.assertEqual(stage.status, "QUEUED")
        self.assertIsNone(stage.state)
        self.assertIsNone(stage.duration_seconds)
        self.assertIsNone(stage.summary)

    def test_stage_execution_detail_callback_state(self):
        stage = StageExecutionDetail(
            status="IN_FLIGHT",
            state="AWAITING_CALLBACK",
            duration_seconds=84.2,
            summary="Waiting for signed callback from Cloud Workflows",
            details={"callback_url_created": True, "timeout": 1800}
        )
        self.assertEqual(stage.status, "IN_FLIGHT")
        self.assertEqual(stage.state, "AWAITING_CALLBACK")
        self.assertEqual(stage.duration_seconds, 84.2)
        self.assertIn("callback_url_created", stage.details)

    def test_pipeline_execution_item(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        item = PipelineExecutionItem(
            trace_id="retry-test-123456",
            product_id="testapp",
            request_id="spec-test-01",
            feature_title="Add User Authentication",
            status="ACTIVE",
            current_stage="TERRAFORM",
            started_at=now_iso,
            elapsed_seconds=124.5,
            stages={
                "vending": StageExecutionDetail(status="SKIPPED"),
                "architect": StageExecutionDetail(status="SUCCESS", duration_seconds=0.06),
                "terraform": StageExecutionDetail(status="IN_FLIGHT", state="AWAITING_CALLBACK"),
            },
            outputs={"service_url": "https://testapp-uc.a.run.app"}
        )
        self.assertEqual(item.trace_id, "retry-test-123456")
        self.assertEqual(item.product_id, "testapp")
        self.assertEqual(item.status, "ACTIVE")
        self.assertEqual(item.current_stage, "TERRAFORM")
        self.assertEqual(item.stages["terraform"].state, "AWAITING_CALLBACK")
        self.assertEqual(item.outputs["service_url"], "https://testapp-uc.a.run.app")

    def test_active_executions_response(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        exec1 = PipelineExecutionItem(
            trace_id="trace-active-01",
            product_id="workload-a",
            started_at=now_iso,
            status="ACTIVE",
        )
        resp = ActiveExecutionsResponse(
            active_executions=[exec1],
            total_active=1,
            latest_completed=None,
        )
        self.assertEqual(resp.total_active, 1)
        self.assertEqual(len(resp.active_executions), 1)
        self.assertEqual(resp.active_executions[0].product_id, "workload-a")

    def test_flight_deck_response(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        item = PipelineExecutionItem(
            trace_id="trace-telemetry-01",
            product_id="telemetry-app",
            started_at=now_iso,
            status="ACTIVE",
        )
        logs = [
            {"timestamp": now_iso, "severity": "INFO", "service_name": "developer-agent", "message": "Synthesized main.py"}
        ]
        deck = FlightDeckResponse(execution=item, live_logs=logs)
        self.assertEqual(deck.execution.trace_id, "trace-telemetry-01")
        self.assertEqual(len(deck.live_logs), 1)
        self.assertEqual(deck.live_logs[0]["service_name"], "developer-agent")


class TestFlightDeckEndpoints(unittest.TestCase):
    """Tests the business logic of the Flight Deck REST endpoints with mock Firestore and Cloud Logging."""

    def setUp(self):
        # settings-toggles: retrigger reads maintenance mode strictly before any side effect; these tests run with
        # maintenance off (the mocked Firestore module cannot serve a settings document).
        wl = sys.modules["routes.workloads"]
        off = patch.object(wl, "get_platform_settings",
                           return_value=SimpleNamespace(governance=SimpleNamespace(maintenance_mode=False)))
        off.start()
        self.addCleanup(off.stop)

    def test_active_executions_endpoint_with_active_runs(self):
        """When an ACTIVE execution exists, it should be returned with calculated elapsed_seconds."""
        mock_db = MagicMock()
        started_at = datetime.now(timezone.utc).isoformat()
        doc_mock = MagicMock()
        doc_mock.id = "trace-001"
        doc_mock.to_dict.return_value = {
            "trace_id": "trace-001",
            "product_id": "demo-workload",
            "status": "ACTIVE",
            "current_stage": "DEVELOPER",
            "started_at": started_at,
            "stages": {
                "architect": {"status": "SUCCESS", "duration_seconds": 0.05},
                "developer": {"status": "IN_FLIGHT", "summary": "Generating application code"},
            }
        }

        query_mock = MagicMock()
        query_mock.stream.return_value = [doc_mock]
        mock_db.collection.return_value.where.return_value = query_mock

        with patch.object(cc_main, "db", mock_db):
            result = cc_main.get_active_pipeline_executions()
            self.assertEqual(result.total_active, 1)
            self.assertEqual(len(result.active_executions), 1)
            self.assertEqual(result.active_executions[0].trace_id, "trace-001")
            self.assertIsNotNone(result.active_executions[0].elapsed_seconds)

    def test_active_executions_fallback_to_latest_completed(self):
        """When no ACTIVE execution exists, falls back to latest completed run."""
        mock_db = MagicMock()
        active_query = MagicMock()
        active_query.stream.return_value = []  # No active

        comp_doc = MagicMock()
        comp_doc.id = "trace-completed-002"
        comp_doc.to_dict.return_value = {
            "trace_id": "trace-completed-002",
            "product_id": "demo-workload",
            "status": "SUCCEEDED",
            "current_stage": "SRE",
            "started_at": "2026-09-06T16:00:00.000Z",
            "completed_at": "2026-09-06T16:03:20.000Z",
            "elapsed_seconds": 200.0,
        }

        comp_query = MagicMock()
        comp_query.stream.return_value = [comp_doc]

        def col_side_effect(col_name):
            col_mock = MagicMock()
            col_mock.where.return_value = active_query
            col_mock.order_by.return_value.limit.return_value = comp_query
            return col_mock

        mock_db.collection.side_effect = col_side_effect

        with patch.object(cc_main, "db", mock_db):
            result = cc_main.get_active_pipeline_executions()
            self.assertEqual(result.total_active, 0)
            self.assertEqual(len(result.active_executions), 0)
            self.assertIsNotNone(result.latest_completed)
            self.assertEqual(result.latest_completed.trace_id, "trace-completed-002")
            self.assertEqual(result.latest_completed.status, "SUCCEEDED")
            self.assertEqual(len(result.recent_completed), 1)
            self.assertEqual(result.recent_completed[0].trace_id, "trace-completed-002")
            # Discovery stage should be auto-reconciled to SUCCESS on succeeded executions
            self.assertIn("discovery", result.latest_completed.stages)
            self.assertEqual(result.latest_completed.stages["discovery"].status, "SUCCESS")

    def test_succeeded_execution_reconciles_inflight_discovery_stage(self):
        """When an execution has SUCCEEDED but discovery stage was stored as IN_FLIGHT, it must be reconciled to SUCCESS."""
        mock_db = MagicMock()
        active_query = MagicMock()
        active_query.stream.return_value = []

        comp_doc = MagicMock()
        comp_doc.id = "trace-succeeded-003"
        comp_doc.to_dict.return_value = {
            "trace_id": "trace-succeeded-003",
            "product_id": "demo-workload",
            "status": "SUCCEEDED",
            "current_stage": "COMPLETE",
            "started_at": "2026-09-06T16:00:00.000Z",
            "stages": {
                "discovery": {"status": "IN_FLIGHT", "summary": "Harvesting GCP folder organization policies (0 LLM)..."},
                "terraform": {"status": "SUCCESS", "summary": "Infrastructure provisioned"},
            }
        }

        comp_query = MagicMock()
        comp_query.stream.return_value = [comp_doc]

        def col_side_effect(col_name):
            col_mock = MagicMock()
            col_mock.where.return_value = active_query
            col_mock.order_by.return_value.limit.return_value = comp_query
            return col_mock

        mock_db.collection.side_effect = col_side_effect

        with patch.object(cc_main, "db", mock_db):
            result = cc_main.get_active_pipeline_executions()
            self.assertIsNotNone(result.latest_completed)
            self.assertEqual(result.latest_completed.stages["discovery"].status, "SUCCESS")
            self.assertEqual(result.latest_completed.stages["discovery"].summary, "GCP Org Policies harvested & verified")

    def test_get_pipeline_execution_by_trace_id(self):
        """Retrieves a single execution document by trace ID."""
        mock_db = MagicMock()
        doc_mock = MagicMock()
        doc_mock.exists = True
        doc_mock.to_dict.return_value = {
            "trace_id": "trace-xyz",
            "product_id": "castorcloudruntest",
            "status": "ACTIVE",
            "current_stage": "TERRAFORM",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "stages": {
                "terraform": {
                    "status": "IN_FLIGHT",
                    "state": "AWAITING_CALLBACK",
                    "summary": "Building container image via Cloud Buildpacks"
                }
            }
        }
        mock_db.collection.return_value.document.return_value.get.return_value = doc_mock

        with patch.object(cc_main, "db", mock_db):
            item = cc_main.get_pipeline_execution("trace-xyz")
            self.assertEqual(item.trace_id, "trace-xyz")
            self.assertEqual(item.product_id, "castorcloudruntest")
            self.assertEqual(item.stages["terraform"].state, "AWAITING_CALLBACK")

    def test_retrigger_initializes_pipeline_execution_doc(self):
        """Retriggering a build should initialize pipeline_executions/{trace_id} with status ACTIVE."""
        mock_db = MagicMock()
        feat_doc = MagicMock()
        feat_doc.exists = True
        # Lane 4 (B1, register L4-h): the feature request must belong to the path's workload; this doc mock also
        # serves workloads/demo, the only source of the retrigger targets (project_id / github_repo).
        feat_doc.to_dict.return_value = {
            "product_id": "demo",
            "project_id": "castor-demo",
            "github_repo": "example-org/demo",
            "title": "Add OAuth Login",
            "description": "Implement Google Sign-In button",
            "budget_ceiling_monthly_usd": 50.0,
        }
        mock_db.collection.return_value.document.return_value.get.return_value = feat_doc

        mock_pub_client = MagicMock()
        mock_future = MagicMock()
        mock_future.result.return_value = "msg-12345"
        mock_pub_client.publish.return_value = mock_future

        mock_req = MagicMock()
        mock_req.state.user_email = "tester@example.com"
        mock_req.state.user_role = cc_main.UserRole.ADMIN

        with patch.object(cc_main, "db", mock_db), \
             patch.object(cc_main, "get_pubsub_publisher", return_value=mock_pub_client), \
             patch.object(cc_main, "project_id", "test-platform-project"):
            res = cc_main.retrigger_feature_request_build("demo", "spec-001", mock_req)
            self.assertEqual(res["status"], "DISPATCHED")
            self.assertEqual(res["request_id"], "spec-001")
            self.assertIn("trace_id", res)
            self.assertIn("execution", res)
            self.assertEqual(res["execution"]["status"], "ACTIVE")
            self.assertEqual(res["execution"]["current_stage"], "DISCOVERY")
            self.assertIn("discovery", res["execution"]["stages"])
            self.assertIn("architect", res["execution"]["stages"])

    def test_retrigger_explicit_deploy_only(self):
        """Passing execution_mode='DEPLOY_ONLY' must generate fastpath trace and skip LLM discovery stages."""
        mock_db = MagicMock()
        feat_doc = MagicMock()
        feat_doc.exists = True
        # Lane 4 (B1, register L4-h): the feature request must belong to the path's workload; this doc mock also
        # serves workloads/demo, the only source of the retrigger targets (project_id / github_repo).
        feat_doc.to_dict.return_value = {
            "product_id": "demo",
            "project_id": "castor-demo",
            "github_repo": "example-org/demo",
            "title": "Add OAuth Login",
            "description": "Implement Google Sign-In button",
            "budget_ceiling_monthly_usd": 50.0,
        }
        mock_db.collection.return_value.document.return_value.get.return_value = feat_doc

        mock_pub_client = MagicMock()
        mock_future = MagicMock()
        mock_future.result.return_value = "msg-9999"
        mock_pub_client.publish.return_value = mock_future

        mock_req = MagicMock()
        mock_req.state.user_email = "tester@example.com"
        mock_req.state.user_role = cc_main.UserRole.ADMIN

        with patch.object(cc_main, "db", mock_db), \
             patch.object(cc_main.workloads, "db", mock_db), \
             patch.object(cc_main, "get_pubsub_publisher", return_value=mock_pub_client), \
             patch.object(cc_main, "project_id", "test-platform-project"):
            res = cc_main.retrigger_feature_request_build("demo", "spec-001", mock_req, body={"execution_mode": "DEPLOY_ONLY"})
            self.assertEqual(res["status"], "DISPATCHED")
            self.assertTrue(res["trace_id"].startswith("fastpath-demo-"))
            self.assertEqual(res["execution_mode"], "DEPLOY_ONLY")
            self.assertEqual(res["execution"]["current_stage"], "TERRAFORM")
            self.assertEqual(res["execution"]["stages"]["discovery"]["status"], "SKIPPED")
            self.assertEqual(res["execution"]["stages"]["architect"]["status"], "SKIPPED")
            self.assertEqual(res["execution"]["stages"]["developer"]["status"], "SKIPPED")

    def test_retrigger_explicit_full(self):
        """Passing execution_mode='FULL' must generate retry trace and begin with DISCOVERY stage."""
        mock_db = MagicMock()
        feat_doc = MagicMock()
        feat_doc.exists = True
        # Lane 4 (B1, register L4-h): the feature request must belong to the path's workload; this doc mock also
        # serves workloads/demo, the only source of the retrigger targets (project_id / github_repo).
        feat_doc.to_dict.return_value = {
            "product_id": "demo",
            "project_id": "castor-demo",
            "github_repo": "example-org/demo",
            "title": "Add OAuth Login",
            "description": "Implement Google Sign-In button",
            "budget_ceiling_monthly_usd": 50.0,
        }
        mock_db.collection.return_value.document.return_value.get.return_value = feat_doc

        mock_pub_client = MagicMock()
        mock_future = MagicMock()
        mock_future.result.return_value = "msg-8888"
        mock_pub_client.publish.return_value = mock_future

        mock_req = MagicMock()
        mock_req.state.user_email = "tester@example.com"
        mock_req.state.user_role = cc_main.UserRole.ADMIN

        with patch.object(cc_main, "db", mock_db), \
             patch.object(cc_main.workloads, "db", mock_db), \
             patch.object(cc_main, "get_pubsub_publisher", return_value=mock_pub_client), \
             patch.object(cc_main, "project_id", "test-platform-project"):
            res = cc_main.retrigger_feature_request_build("demo", "spec-001", mock_req, body={"execution_mode": "FULL"})
            self.assertEqual(res["status"], "DISPATCHED")
            self.assertTrue(res["trace_id"].startswith("retry-demo-"))
            self.assertEqual(res["execution_mode"], "FULL")
            self.assertEqual(res["execution"]["current_stage"], "DISCOVERY")
            self.assertEqual(res["execution"]["stages"]["discovery"]["status"], "IN_FLIGHT")
            self.assertEqual(res["execution"]["stages"]["architect"]["status"], "QUEUED")

    def test_retrigger_explicit_auto(self):
        """Passing execution_mode='AUTO' must invoke failure-aware heuristics."""
        mock_db = MagicMock()
        feat_doc = MagicMock()
        feat_doc.exists = True
        # Lane 4 (B1, register L4-h): the feature request must belong to the path's workload; this doc mock also
        # serves workloads/demo, the only source of the retrigger targets (project_id / github_repo).
        feat_doc.to_dict.return_value = {
            "product_id": "demo",
            "project_id": "castor-demo",
            "github_repo": "example-org/demo",
            "title": "Add OAuth Login",
            "description": "Implement Google Sign-In button",
            "budget_ceiling_monthly_usd": 50.0,
        }
        mock_db.collection.return_value.document.return_value.get.return_value = feat_doc

        # Mock recent pipeline executions with a failed TERRAFORM stage to test auto-routing to DEPLOY_ONLY
        prev_run_doc = MagicMock()
        prev_run_doc.to_dict.return_value = {
            "status": "FAILED",
            "current_stage": "TERRAFORM",
            "started_at": "2026-10-11T12:00:00Z",
            "stages": {
                "terraform": {"status": "FAILED", "state": "FAILED", "error": "connection timeout"}
            }
        }
        mock_query = MagicMock()
        mock_query.stream.return_value = [prev_run_doc]
        mock_db.collection.return_value.where.return_value.limit.return_value = mock_query

        mock_pub_client = MagicMock()
        mock_future = MagicMock()
        mock_future.result.return_value = "msg-auto"
        mock_pub_client.publish.return_value = mock_future

        mock_req = MagicMock()
        mock_req.state.user_email = "tester@example.com"
        mock_req.state.user_role = cc_main.UserRole.ADMIN

        with patch.object(cc_main, "db", mock_db), \
             patch.object(cc_main.workloads, "db", mock_db), \
             patch.object(cc_main, "get_pubsub_publisher", return_value=mock_pub_client), \
             patch.object(cc_main, "project_id", "test-platform-project"):
            res = cc_main.retrigger_feature_request_build("demo", "spec-001", mock_req, body={"execution_mode": "AUTO"})
            self.assertEqual(res["status"], "DISPATCHED")
            # Auto-routing should detect late-stage IaC failure and route to DEPLOY_ONLY!
            self.assertEqual(res["execution_mode"], "DEPLOY_ONLY")
            self.assertTrue(res["trace_id"].startswith("fastpath-demo-"))
            self.assertIn("trace_id", res)

    def test_fetch_trace_logs_filters_ui_logs(self):
        """Trace log querying must exclude product-control-center-ui polling and access entries."""
        mock_entry_ui = MagicMock()
        mock_entry_ui.timestamp = datetime(2026, 9, 6, 16, 0, 0, tzinfo=timezone.utc)
        mock_entry_ui.severity = "INFO"
        mock_entry_ui.resource.labels = {"service_name": "product-control-center-ui"}
        mock_entry_ui.payload = 'INFO: 169.254.169.126:59252 - "GET /api/pipeline/executions/trace-xyz/telemetry HTTP/1.1" 200 OK'
        mock_entry_ui.text_payload = None
        mock_entry_ui.json_payload = None

        mock_entry_agent = MagicMock()
        mock_entry_agent.timestamp = datetime(2026, 9, 6, 16, 0, 1, tzinfo=timezone.utc)
        mock_entry_agent.severity = "INFO"
        mock_entry_agent.resource.labels = {"service_name": "developer-agent"}
        mock_entry_agent.payload = "Synthesizing main.py"
        mock_entry_agent.text_payload = None
        mock_entry_agent.json_payload = None

        mock_logging_client = MagicMock()
        mock_logging_client.list_entries.return_value = [mock_entry_ui, mock_entry_agent]

        with patch.object(cc_main.cloud_logging, "Client", return_value=mock_logging_client), \
             patch.object(cc_main, "project_id", "test-project"):
            logs = cc_main.fetch_trace_logs_from_cloud_logging("trace-xyz")
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0]["service_name"], "developer-agent")
            self.assertEqual(logs[0]["message"], "Synthesizing main.py")

    def test_decommission_cascade_aborts_active_executions(self):
        """Decommissioning a workload must abort active pipeline executions in Firestore and cancel Cloud Workflows."""
        mock_db = MagicMock()
        doc_mock = MagicMock()
        doc_mock.id = "trace-active-001"
        doc_mock.to_dict.return_value = {
            "trace_id": "trace-active-001",
            "product_id": "target-workload",
            "status": "ACTIVE",
            "workflow_execution_id": "projects/p/locations/l/workflows/w/executions/e1",
        }
        col_mock = MagicMock()
        col_mock.where.return_value.where.return_value.stream.return_value = [doc_mock]
        mock_db.collection.return_value = col_mock

        fake_wf, wf_patch = _workflows_session()
        with patch.object(cc_main, "db", mock_db), wf_patch:
            aborted = cc_main.cancel_workload_active_executions(
                target_product_id="target-workload",
                operator_email="admin@example.com",
                reason="Workload decommissioned",
            )
            self.assertEqual(aborted, 1)
            self.assertEqual(fake_wf.cancelled, ["https://workflowexecutions.googleapis.com/v1/projects/p/locations/l/"
                                                 "workflows/w/executions/e1:cancel"])
            doc_mock.reference.set.assert_called_once()
            set_args = doc_mock.reference.set.call_args[0][0]
            self.assertEqual(set_args["status"], "ABORTED")
            self.assertIn("Workload decommissioned", set_args["error_message"])

    def test_auto_reconcile_phantom_workload_on_active_poll(self):
        """Active executions polling must auto-abort executions whose parent workload is DECOMMISSIONED."""
        mock_db = MagicMock()

        active_doc = MagicMock()
        active_doc.id = "trace-phantom-001"
        active_doc.to_dict.return_value = {
            "trace_id": "trace-phantom-001",
            "product_id": "decommissioned-app",
            "status": "ACTIVE",
            "started_at": "2026-09-29T00:00:00.000Z",
        }

        active_query = MagicMock()
        active_query.stream.return_value = [active_doc]

        # Workload doc returns status: DECOMMISSIONED
        workload_doc = MagicMock()
        workload_doc.exists = True
        workload_doc.to_dict.return_value = {
            "product_id": "decommissioned-app",
            "status": "DECOMMISSIONED",
        }

        def col_side_effect(col_name):
            col_m = MagicMock()
            if col_name == "pipeline_executions":
                col_m.where.return_value = active_query
                col_m.order_by.return_value.limit.return_value.stream.return_value = []
            elif col_name == "workloads":
                col_m.document.return_value.get.return_value = workload_doc
            return col_m

        mock_db.collection.side_effect = col_side_effect

        with patch.object(cc_main, "db", mock_db):
            res = cc_main.get_active_pipeline_executions()
            self.assertEqual(res.total_active, 0)
            self.assertEqual(len(res.active_executions), 0)
            active_doc.reference.set.assert_called_once()
            set_args = active_doc.reference.set.call_args[0][0]
            self.assertEqual(set_args["status"], "ABORTED")
            self.assertIn("DECOMMISSIONED", set_args["error_message"])

    def test_auto_fail_stale_silent_execution(self):
        """STALE-RUN-AUTOFAIL-BOUND: a run bound to a workflow execution that the Workflows API reports ACTIVE is never
        failed for silence, however long it has been quiet (developer and QA may each run 30 min without an event)."""
        fake_wf = _StateWorkflows("ACTIVE")
        doc = _active_doc("trace-stale-001", {
            "current_stage": "QA",
            "started_at": "2026-09-29T00:00:00.000Z",
            "last_heartbeat_at": "2026-09-29T00:05:00.000Z",  # hours silent
            "workflow_execution_id": _WF_NAME,
        })
        res = _poll([doc], fake_wf)
        self.assertEqual(res.total_active, 1)
        self.assertEqual(fake_wf.reads, 1)
        doc.reference.set.assert_not_called()

    def test_abort_pipeline_execution_endpoint(self):
        """POST /api/pipeline/executions/{trace_id}/abort must cancel Cloud Workflows and mark Firestore document ABORTED."""
        mock_db = MagicMock()
        doc_mock = MagicMock()
        doc_mock.exists = True
        doc_mock.to_dict.return_value = {
            "trace_id": "trace-abort-test",
            "product_id": "demo-workload",
            "status": "ACTIVE",
            "workflow_execution_id": "projects/p/locations/l/workflows/w/executions/e99",
        }
        doc_mock.get.return_value = doc_mock  # abort reads doc_ref.get()
        mock_db.collection.return_value.document.return_value = doc_mock

        mock_req = MagicMock()
        mock_req.state.user_email = "admin@example.com"
        mock_req.state.user_role = cc_main.UserRole.ADMIN

        fake_wf, wf_patch = _workflows_session()
        with patch.object(cc_main, "db", mock_db), wf_patch:
            res = cc_main.abort_pipeline_execution("trace-abort-test", mock_req)
            self.assertEqual(len(fake_wf.cancelled), 1)
            self.assertEqual(res["status"], "ABORTED")
            self.assertEqual(res["trace_id"], "trace-abort-test")
            self.assertEqual(res["aborted_by"], "admin@example.com")
            doc_mock.set.assert_called_once()
            set_args = doc_mock.set.call_args[0][0]
            self.assertEqual(set_args["status"], "ABORTED")


class TestStaleRunDetector(unittest.TestCase):
    """STALE-RUN-AUTOFAIL-BOUND: the active-runs poll ends a bound run only on a terminal Workflows state, and fails an
    unbound run only after the silence limit outside the exact exempt stages."""

    # --- bound runs: the Workflows API decides --------------------------------------------------------------------

    def test_bound_terminal_failed_is_reconciled(self):
        fake_wf = _StateWorkflows("FAILED")
        doc = _active_doc("trace-bound-failed", {"current_stage": "TERRAFORM_CALLBACK", "started_at": _iso_ago(7200),
                                                 "workflow_execution_name": _WF_NAME})
        res = _poll([doc], fake_wf)
        self.assertEqual(res.total_active, 0)
        written = _terminal_write(doc)
        self.assertEqual(written["status"], "FAILED")
        self.assertEqual(written["current_stage"], "FAILED")
        self.assertEqual(written["workflow_state_check"]["outcome"], "RECONCILED")
        self.assertEqual(written["workflow_state_check"]["state"], "FAILED")
        # RT F2: the reason is written where the UI and API show it
        self.assertEqual(written["error_class"], "WORKFLOW_EXECUTION_FAILED")
        self.assertIn("final status notification was not received", written["error"])
        self.assertEqual(written["error_message"], written["error"])

    def test_bound_terminal_cancelled_and_succeeded_are_reconciled(self):
        for wf_state, expected in (("CANCELLED", "ABORTED"), ("SUCCEEDED", "SUCCEEDED")):
            doc = _active_doc(f"trace-bound-{wf_state}", {"current_stage": "QA", "started_at": _iso_ago(7200),
                                                          "workflow_execution_id": _WF_NAME})
            res = _poll([doc], _StateWorkflows(wf_state))
            self.assertEqual(res.total_active, 0)
            written = _terminal_write(doc)
            self.assertEqual(written["status"], expected)
            if wf_state == "SUCCEEDED":  # Do No Harm: a success carries no error
                self.assertFalse({"error", "error_class", "error_message"} & set(written))
            else:
                self.assertEqual(written["error_class"], "WORKFLOW_EXECUTION_CANCELLED")

    def test_bound_api_read_error_leaves_run_untouched(self):
        for fake_wf in (_StateWorkflows(http_status=500), _StateWorkflows(exc=ConnectionError("network down"))):
            doc = _active_doc("trace-bound-readerr", {"current_stage": "QA", "started_at": _iso_ago(7200),
                                                      "workflow_execution_id": _WF_NAME})
            with self.assertLogs("control-center-telemetry", level="WARNING") as logs:
                res = _poll([doc], fake_wf)
            self.assertEqual(res.total_active, 1)
            self.assertTrue(any("WORKFLOW_STATE_READ_FAILED" in line for line in logs.output))
            doc.reference.set.assert_called_once()
            written = doc.reference.set.call_args[0][0]
            self.assertEqual(set(written), {"workflow_state_check"})  # never status / current_stage / ended_at
            self.assertEqual(written["workflow_state_check"]["outcome"], "READ_FAILED")
            self.assertEqual(written["workflow_state_check"]["reason"], "WORKFLOW_STATE_READ_FAILED")

    def test_bound_unusable_execution_name_leaves_run_untouched(self):
        doc = _active_doc("trace-bound-badname", {"current_stage": "QA", "started_at": _iso_ago(7200),
                                                  "workflow_execution_id": "a/b"})
        res = _poll([doc], _StateWorkflows("FAILED"))
        self.assertEqual(res.total_active, 1)
        written = doc.reference.set.call_args[0][0]
        self.assertEqual(set(written), {"workflow_state_check"})
        self.assertEqual(written["workflow_state_check"]["reason"], "WORKFLOW_EXECUTION_NAME_INVALID")

    def test_bound_api_read_error_already_recorded_is_not_rewritten(self):
        doc = _active_doc("trace-bound-readerr2", {
            "current_stage": "QA", "started_at": _iso_ago(7200), "workflow_execution_id": _WF_NAME,
            "workflow_state_check": {"outcome": "READ_FAILED", "reason": "WORKFLOW_STATE_READ_FAILED"}})
        res = _poll([doc], _StateWorkflows(http_status=500))
        self.assertEqual(res.total_active, 1)
        doc.reference.set.assert_not_called()

    def test_bound_active_after_read_error_clears_the_recorded_failure(self):
        doc = _active_doc("trace-bound-recovered", {
            "current_stage": "QA", "started_at": _iso_ago(7200), "workflow_execution_id": _WF_NAME,
            "workflow_state_check": {"outcome": "READ_FAILED", "reason": "WORKFLOW_STATE_READ_FAILED"}})
        res = _poll([doc], _StateWorkflows("ACTIVE"))
        self.assertEqual(res.total_active, 1)
        written = doc.reference.set.call_args[0][0]
        self.assertEqual(set(written), {"workflow_state_check"})
        self.assertEqual(written["workflow_state_check"]["outcome"], "OK")

    def test_bound_api_check_is_rate_limited(self):
        fake_wf = _StateWorkflows("ACTIVE")
        doc = _active_doc("trace-bound-rate", {"current_stage": "QA", "started_at": _iso_ago(7200),
                                               "workflow_execution_id": _WF_NAME})
        _poll([doc], fake_wf)
        _poll([doc], fake_wf, fresh_cache=False)
        self.assertEqual(fake_wf.reads, 1)

    def test_bound_exempt_stage_with_terminal_workflow_is_still_reconciled(self):
        # The exact exempt stages apply to unbound runs only: a bound run waiting at an approval whose workflow ended
        # is reconciled from the Workflows state instead of staying ACTIVE forever.
        doc = _active_doc("trace-bound-approval", {"current_stage": "AWAITING_PR_APPROVAL",
                                                   "started_at": _iso_ago(7200), "workflow_execution_id": _WF_NAME})
        res = _poll([doc], _StateWorkflows("CANCELLED"))
        self.assertEqual(res.total_active, 0)
        self.assertEqual(_terminal_write(doc)["status"], "ABORTED")

    # --- red-team fixes (docs/planning/stale-run-autofail-rt.md) ----------------------------------------------------

    def test_f1_404_on_stored_name_reconciles_not_found(self):
        for field in ("workflow_execution_name", "workflow_execution_id"):  # a full name stored in either field
            doc = _active_doc(f"trace-404-{field}", {"current_stage": "QA", "started_at": _iso_ago(7200),
                                                     field: _WF_NAME})
            res = _poll([doc], _StateWorkflows(http_status=404))
            self.assertEqual(res.total_active, 0, field)
            written = _terminal_write(doc)
            self.assertEqual(written["status"], "FAILED")
            self.assertEqual(written["current_stage"], "FAILED")
            self.assertEqual(written["error_class"], "WORKFLOW_EXECUTION_NOT_FOUND")
            self.assertIn("not found", written["error"])
            self.assertEqual(written["workflow_state_check"]["outcome"], "RECONCILED_NOT_FOUND")

    def test_f1_404_on_name_built_from_bare_id_stays_running(self):
        # A legacy record with only the bare id: the name is built from this CC's project / region, which may be wrong.
        doc = _active_doc("trace-404-built", {"current_stage": "QA", "started_at": _iso_ago(7200),
                                              "workflow_execution_id": "e-bare-id"})
        res = _poll([doc], _StateWorkflows(http_status=404))
        self.assertEqual(res.total_active, 1)
        doc.reference.update.assert_not_called()
        written = doc.reference.set.call_args[0][0]
        self.assertEqual(set(written), {"workflow_state_check"})
        self.assertEqual(written["workflow_state_check"]["outcome"], "READ_FAILED")
        self.assertEqual(written["workflow_state_check"]["reason"], "WORKFLOW_STATE_READ_FAILED")

    def test_f1_404_stored_name_but_stale_id_mismatch_stays_running(self):
        # execution_name_of ignores a stored name whose last segment is not the stored id and builds one from the id.
        doc = _active_doc("trace-404-mismatch", {"current_stage": "QA", "started_at": _iso_ago(7200),
                                                 "workflow_execution_name": _WF_NAME,
                                                 "workflow_execution_id": "e-other"})
        res = _poll([doc], _StateWorkflows(http_status=404))
        self.assertEqual(res.total_active, 1)
        doc.reference.update.assert_not_called()

    def test_f2_existing_error_is_kept_and_schema_returns_error_class(self):
        doc = _active_doc("trace-keep-error", {"current_stage": "TERRAFORM_CALLBACK", "started_at": _iso_ago(7200),
                                               "workflow_execution_id": _WF_NAME, "error": "tofu apply failed"})
        _poll([doc], _StateWorkflows("FAILED"))
        written = _terminal_write(doc)
        self.assertNotIn("error", written)  # the stage's own error stays the shown reason
        self.assertEqual(written["error_class"], "WORKFLOW_EXECUTION_FAILED")
        item = PipelineExecutionItem(trace_id="t", error_class="RUN_SILENT_NO_WORKFLOW", error_message="m",
                                     workflow_state_check={"outcome": "READ_FAILED"})
        self.assertEqual(item.error_class, "RUN_SILENT_NO_WORKFLOW")
        self.assertEqual(item.error_message, "m")
        self.assertEqual(item.workflow_state_check["outcome"], "READ_FAILED")

    def test_f3_reconcile_is_conditional_on_the_read_version(self):
        mock_db = MagicMock()
        doc = _active_doc("trace-precondition", {"current_stage": "QA", "started_at": _iso_ago(7200),
                                                 "workflow_execution_id": _WF_NAME})
        doc.update_time = "read-version-1"
        _poll([doc], _StateWorkflows("FAILED"), mock_db=mock_db)
        mock_db.write_option.assert_called_once_with(last_update_time="read-version-1")
        self.assertIs(doc.reference.update.call_args[1]["option"], mock_db.write_option.return_value)

    def test_f3_record_changed_since_read_is_not_overwritten(self):
        doc = _active_doc("trace-conflict", {"current_stage": "QA", "started_at": _iso_ago(7200),
                                             "workflow_execution_id": _WF_NAME})
        doc.reference.update.side_effect = RuntimeError("FailedPrecondition: the stored version does not match")
        with self.assertLogs("control-center-telemetry", level="WARNING") as logs:
            res = _poll([doc], _StateWorkflows("SUCCEEDED"))
        self.assertTrue(any("changed since it was read" in line for line in logs.output))
        self.assertEqual(res.total_active, 1)  # left for the next poll; the newer write stands
        doc.reference.set.assert_not_called()

    def test_f4_reads_per_poll_are_capped_with_one_session_and_short_timeout(self):
        fake_wf = _StateWorkflows("ACTIVE")
        docs = [_active_doc(f"trace-cap-{i}", {"current_stage": "QA", "started_at": _iso_ago(7200),
                                               "workflow_execution_id": _WF_NAME}) for i in range(8)]
        res = _poll(docs, fake_wf)
        self.assertEqual(res.total_active, 8)
        self.assertEqual(fake_wf.reads, 5)
        self.assertEqual(fake_wf.sessions_built, 1)
        self.assertEqual(set(fake_wf.timeouts), {5.0})
        # The runs left over were not marked checked: the next poll reads them (and not the 5 already read).
        _poll(docs, fake_wf, fresh_cache=False)
        self.assertEqual(fake_wf.reads, 8)

    def test_f8_403_on_read_has_a_read_specific_reason(self):
        doc = _active_doc("trace-403", {"current_stage": "QA", "started_at": _iso_ago(7200),
                                        "workflow_execution_id": _WF_NAME})
        res = _poll([doc], _StateWorkflows(http_status=403))
        self.assertEqual(res.total_active, 1)
        written = doc.reference.set.call_args[0][0]
        self.assertEqual(written["workflow_state_check"]["reason"], "WORKFLOW_STATE_READ_NOT_PERMITTED")

    # --- unbound runs: the silence rule ---------------------------------------------------------------------------

    def test_unbound_silent_beyond_threshold_is_auto_failed(self):
        doc = _active_doc("trace-unbound-stale", {"current_stage": "DEVELOPER", "started_at": _iso_ago(7200),
                                                  "workflow_execution_id": None})
        res = _poll([doc])
        self.assertEqual(res.total_active, 0)
        written = doc.reference.set.call_args[0][0]
        self.assertEqual(written["status"], "FAILED")
        self.assertEqual(written["current_stage"], "FAILED")
        self.assertEqual(written["error_class"], "RUN_SILENT_NO_WORKFLOW")
        self.assertIn("timed out", written["error_message"])
        self.assertEqual(written["error"], written["error_message"])  # RT F2: the field the Flight Deck shows

    def test_unbound_exact_exempt_stages_are_untouched(self):
        for stage in ("AWAITING_PLAN_APPROVAL", "AWAITING_PR_APPROVAL", "QUOTA_PAUSED", "VENDING_CALLBACK",
                      "TERRAFORM_CALLBACK"):
            doc = _active_doc(f"trace-unbound-{stage}", {"current_stage": stage, "started_at": _iso_ago(7200)})
            res = _poll([doc])
            self.assertEqual(res.total_active, 1, stage)
            doc.reference.set.assert_not_called()

    def test_unbound_stage_merely_containing_an_exempt_word_is_not_exempt(self):
        # Invariant 2: exact stage values, no substring matching.
        for stage in ("SOME_CALLBACK_STAGE", "approval", "QUOTA_PAUSED_X"):
            doc = _active_doc(f"trace-unbound-sub-{stage}", {"current_stage": stage, "started_at": _iso_ago(7200)})
            res = _poll([doc])
            self.assertEqual(res.total_active, 0, stage)
            self.assertEqual(doc.reference.set.call_args[0][0]["status"], "FAILED")

    def test_unbound_rate_limit_cooldown_is_untouched(self):
        for fields in ({"status": "PAUSED_RATE_LIMIT_COOLDOWN"}, {"cooldown_state": {"is_paused": True}}):
            record = {"current_stage": "DEVELOPER", "started_at": _iso_ago(7200)}
            record.update(fields)
            doc = _active_doc("trace-unbound-cooldown", record)
            res = _poll([doc])
            self.assertEqual(res.total_active, 1)
            doc.reference.set.assert_not_called()

    # --- updated_at as an epoch float (plan / quota approval writes) -------------------------------------------------

    def test_unbound_float_updated_at_recent_keeps_the_run(self):
        import time as _time
        doc = _active_doc("trace-float-recent", {"current_stage": "DEVELOPER", "started_at": _iso_ago(7200),
                                                 "updated_at": _time.time() - 60})
        res = _poll([doc])
        self.assertEqual(res.total_active, 1)
        doc.reference.set.assert_not_called()

    def test_unbound_float_updated_at_old_is_read_not_swallowed(self):
        import time as _time
        doc = _active_doc("trace-float-old", {"current_stage": "DEVELOPER", "started_at": _iso_ago(9000),
                                              "updated_at": _time.time() - 7200})
        res = _poll([doc])
        self.assertEqual(res.total_active, 0)
        self.assertEqual(doc.reference.set.call_args[0][0]["status"], "FAILED")

    def test_bound_float_updated_at_still_reaches_the_workflow_check(self):
        import time as _time
        fake_wf = _StateWorkflows("FAILED")
        doc = _active_doc("trace-float-bound", {"current_stage": "AWAITING_PLAN_APPROVAL", "started_at": _iso_ago(9000),
                                                "updated_at": _time.time() - 3600, "workflow_execution_id": _WF_NAME})
        res = _poll([doc], fake_wf)
        self.assertEqual(fake_wf.reads, 1)
        self.assertEqual(res.total_active, 0)

    def test_unreadable_timestamp_is_logged_not_swallowed(self):
        doc = _active_doc("trace-bad-ts", {"current_stage": "DEVELOPER", "started_at": _iso_ago(60),
                                           "updated_at": "not-a-time"})
        with self.assertLogs("control-center-telemetry", level="WARNING") as logs:
            res = _poll([doc])
        self.assertTrue(any("updated_at" in line and "not-a-time" in line for line in logs.output))
        self.assertEqual(res.total_active, 1)  # the readable started_at is recent
        doc.reference.set.assert_not_called()

    def test_parse_record_time_forms(self):
        parse = cc_main.get_active_pipeline_executions.__globals__["_parse_record_time"]
        expected = datetime(2026, 11, 12, 20, 55, 1, tzinfo=timezone.utc)
        self.assertEqual(parse("2026-11-12T20:55:01Z", "t", "f"), expected)
        self.assertEqual(parse("2026-11-12T20:55:01+00:00", "t", "f"), expected)
        self.assertEqual(parse(expected.timestamp(), "t", "f"), expected)
        self.assertEqual(parse(int(expected.timestamp()), "t", "f"), expected)
        self.assertEqual(parse(expected.replace(tzinfo=None), "t", "f"), expected)  # naive Firestore-like datetime
        self.assertEqual(parse(expected, "t", "f"), expected)
        self.assertIsNone(parse(None, "t", "f"))
        self.assertIsNone(parse(True, "t", "f"))

    # --- Do No Harm: healthy recent runs are unchanged and cost no API call -----------------------------------------

    def test_recent_runs_are_untouched(self):
        bound = _active_doc("trace-recent-bound", {"current_stage": "DEVELOPER", "started_at": _iso_ago(60),
                                                   "workflow_execution_id": _WF_NAME})
        unbound = _active_doc("trace-recent-unbound", {"current_stage": "ARCHITECT", "started_at": _iso_ago(60)})
        res = _poll([bound, unbound])  # no Workflows session: a read would raise
        self.assertEqual(res.total_active, 2)
        bound.reference.set.assert_not_called()
        unbound.reference.set.assert_not_called()

    def test_unbound_just_under_threshold_is_untouched(self):
        doc = _active_doc("trace-unbound-edge", {"current_stage": "QA", "started_at": _iso_ago(1700)})
        res = _poll([doc])
        self.assertEqual(res.total_active, 1)
        doc.reference.set.assert_not_called()


class TestRetriggerPreSeedOrder(unittest.TestCase):
    """STALE-RUN-AUTOFAIL-BOUND (RT F5): the retrigger writes its run record before it publishes the build event, so
    the gateway's attach (workflow_execution_id/_name) can never be wiped by a later full write."""

    setUp = TestFlightDeckEndpoints.setUp  # maintenance mode off (the mocked Firestore serves no settings document)

    def _retrigger(self, result_side_effect=None):
        events = []
        mock_db = MagicMock()
        feat_doc = MagicMock()
        feat_doc.exists = True
        feat_doc.to_dict.return_value = {"product_id": "demo", "project_id": "castor-demo",
                                         "github_repo": "example-org/demo", "title": "Add OAuth Login",
                                         "description": "Implement Google Sign-In button",
                                         "budget_ceiling_monthly_usd": 50.0}
        doc = mock_db.collection.return_value.document.return_value
        doc.get.return_value = feat_doc
        doc.set.side_effect = lambda payload, *a, **k: events.append(("set", payload, k.get("merge", False)))
        mock_future = MagicMock()
        if result_side_effect is not None:
            mock_future.result.side_effect = result_side_effect
        else:
            mock_future.result.return_value = "msg-1"
        mock_pub = MagicMock()

        def publish(topic, data):
            events.append(("publish", topic))
            return mock_future

        mock_pub.publish.side_effect = publish
        mock_req = MagicMock()
        mock_req.state.user_email = "tester@example.com"
        mock_req.state.user_role = cc_main.UserRole.ADMIN
        error = None
        with patch.object(cc_main, "db", mock_db), \
                patch.object(cc_main, "get_pubsub_publisher", return_value=mock_pub), \
                patch.object(cc_main, "project_id", "test-platform-project"):
            try:
                cc_main.retrigger_feature_request_build("demo", "spec-001", mock_req)
            except Exception as e:  # noqa: BLE001 - the route's HTTP error
                error = e
        return events, error

    @staticmethod
    def _index(events, pred):
        return next(i for i, ev in enumerate(events) if pred(ev))

    def test_preseed_is_written_before_publish_without_a_binding_key(self):
        events, error = self._retrigger()
        self.assertIsNone(error)
        seed_i = self._index(events, lambda ev: ev[0] == "set" and ev[1].get("status") == "ACTIVE"
                             and "stages" in ev[1])
        pub_i = self._index(events, lambda ev: ev[0] == "publish")
        self.assertLess(seed_i, pub_i)
        self.assertNotIn("workflow_execution_id", events[seed_i][1])
        self.assertNotIn("workflow_execution_name", events[seed_i][1])

    def test_definite_publish_failure_closes_the_preseed_typed(self):
        events, error = self._retrigger(result_side_effect=RuntimeError("pubsub refused"))
        self.assertIsNotNone(error)
        self.assertEqual(error.status_code, 500)  # unchanged answer for a definite failure
        self.assertIn("Failed to publish build event", str(error.detail))
        pub_i = self._index(events, lambda ev: ev[0] == "publish")
        fail_i = self._index(events, lambda ev: ev[0] == "set" and ev[1].get("status") == "FAILED")
        self.assertGreater(fail_i, pub_i)
        self.assertEqual(events[fail_i][1]["error_class"], "RETRIGGER_DISPATCH_FAILED")
        self.assertTrue(events[fail_i][2])  # merge: the pre-seed's stages are kept

    def test_publish_timeout_leaves_the_preseed_running(self):
        # The event may still be delivered: the record stays ACTIVE for the gateway to attach, else the silence rule.
        events, error = self._retrigger(result_side_effect=TimeoutError())
        self.assertIsNotNone(error)
        self.assertFalse(any(ev[0] == "set" and ev[1].get("status") == "FAILED" for ev in events))
        # Red-team delta D1: answered like /deploy-infra, typed 504 with the trace id and a check-before-retry message
        # ({code, message}: the dashboard's apiErrorText shows it as the toast).
        self.assertEqual(error.status_code, 504)
        seed = next(ev[1] for ev in events if ev[0] == "set" and ev[1].get("status") == "ACTIVE" and "stages" in ev[1])
        self.assertEqual(error.detail["code"], "RETRIGGER_DISPATCH_OUTCOME_UNKNOWN")
        self.assertEqual(error.detail["error_class"], "RETRIGGER_DISPATCH_OUTCOME_UNKNOWN")
        self.assertEqual(error.detail["trace_id"], seed["trace_id"])
        self.assertIn("may already be running", error.detail["message"])
        self.assertIn(seed["trace_id"], error.detail["message"])

    def test_concurrent_futures_timeout_is_the_same_outcome_unknown(self):
        import concurrent.futures
        _, error = self._retrigger(result_side_effect=concurrent.futures.TimeoutError())
        self.assertEqual(error.status_code, 504)
        self.assertEqual(error.detail["error_class"], "RETRIGGER_DISPATCH_OUTCOME_UNKNOWN")


class TestUndeliveredCallbackRedelivery(unittest.TestCase):
    """RT14-25 (owner 11-14): a bound run whose workflow is still ACTIVE and one of whose stage outcomes never reached
    it (stage state CALLBACK_FAILED) gets that outcome sent again; no other run is touched."""

    def _poll_with_spy(self, stages):
        doc = _active_doc("trace-undelivered", {"current_stage": "TERRAFORM_CALLBACK", "started_at": _iso_ago(7200),
                                                "workflow_execution_name": _WF_NAME, "stages": stages})
        calls = []
        callbacks_mod = cc_main.get_active_pipeline_executions.__globals__["_callbacks"]
        with patch.object(callbacks_mod, "redeliver_undelivered_callbacks",
                          lambda db, trace_id: calls.append(trace_id) or []):
            res = _poll([doc], _StateWorkflows("ACTIVE"))
        return res, doc, calls

    def test_an_undelivered_outcome_of_a_waiting_workflow_is_redelivered(self):
        res, doc, calls = self._poll_with_spy({"terraform": {"status": "SUCCESS", "state": "CALLBACK_FAILED"}})
        self.assertEqual(calls, ["trace-undelivered"])
        self.assertEqual(res.total_active, 1)            # the run itself is left to its workflow
        doc.reference.update.assert_not_called()

    def test_negative_a_delivered_outcome_sends_nothing(self):
        _, _, calls = self._poll_with_spy({"terraform": {"status": "SUCCESS", "state": "CALLBACK_DELIVERED"}})
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
