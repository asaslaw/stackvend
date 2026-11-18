"""
Project Castor: Unit & Contract Tests for Cloud Workflows Callbacks and Agent Lifecycle Logging
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import http.server
import json
import logging
import os
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock

# Mock pydantic if not installed
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

    class MockFieldInfo:
        def __init__(self, default=None, default_factory=None):
            self.default = default if default is not None else (default_factory() if default_factory else None)

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: MockFieldInfo(default, default_factory)
    mock_pydantic.EmailStr = str
    sys.modules['pydantic'] = mock_pydantic


# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.callbacks import CallbackDeliveryClient, guaranteed_callback_scope
from shared.logging_utils import AgentLifecycle
import importlib.util
_spec = importlib.util.spec_from_file_location('cc_schemas', os.path.abspath(os.path.join(os.path.dirname(__file__), '../apps/control-center/schemas.py')))
_cc_schemas = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cc_schemas)

AsyncCallbackPayload = _cc_schemas.AsyncCallbackPayload
AsyncDeployRequest = _cc_schemas.AsyncDeployRequest
AsyncJobAck = _cc_schemas.AsyncJobAck
AsyncQAVerifyRequest = _cc_schemas.AsyncQAVerifyRequest
AsyncVendingRequest = _cc_schemas.AsyncVendingRequest


class MockCallbackReceiver(http.server.BaseHTTPRequestHandler):
    """Mock HTTP receiver simulating Google Cloud Workflows signed callback endpoints."""
    received_callbacks = []
    fail_attempts = 0
    current_attempt = 0

    def do_POST(self):
        MockCallbackReceiver.current_attempt += 1
        if MockCallbackReceiver.current_attempt <= MockCallbackReceiver.fail_attempts:
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Transient Server Error"}')
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        payload = json.loads(post_data.decode("utf-8"))
        MockCallbackReceiver.received_callbacks.append(payload)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "CALLBACK_PROCESSED"}')

    def log_message(self, format, *args):
        pass  # Suppress default server log spam


class TestAgentLifecycle(unittest.TestCase):
    def test_lifecycle_success_banner_and_timing(self):
        with AgentLifecycle("Architect", "test-workload", "trace-001", mode="SYNC") as agent:
            time.sleep(0.05)
            agent.set_summary("Decomposed 5 tasks successfully", status="SUCCESS")

        self.assertEqual(agent.status, "SUCCESS")
        self.assertEqual(agent.summary, "Decomposed 5 tasks successfully")
        self.assertGreaterEqual(agent.elapsed, 0.05)

    def test_lifecycle_failure_records_exception(self):
        with self.assertRaises(ValueError):
            with AgentLifecycle("Developer", "test-workload", "trace-002", mode="SYNC") as agent:
                raise ValueError("Syntax error in generated HCL")

        self.assertEqual(agent.status, "FAILED")
        self.assertIn("Syntax error in generated HCL", agent.summary)
        self.assertGreaterEqual(agent.elapsed, 0.0)


class TestCallbackDeliveryClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        MockCallbackReceiver.received_callbacks = []
        MockCallbackReceiver.fail_attempts = 0
        MockCallbackReceiver.current_attempt = 0
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockCallbackReceiver)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        MockCallbackReceiver.received_callbacks.clear()
        MockCallbackReceiver.fail_attempts = 0
        MockCallbackReceiver.current_attempt = 0

    def test_successful_callback_delivery(self):
        callback_url = f"http://127.0.0.1:{self.port}/v1/callbacks/cb-test-1"
        payload = {
            "status": "SUCCESS",
            "product_id": "test-workload",
            "outputs": {"service_url": "https://test.a.run.app"},
        }
        res = CallbackDeliveryClient.send_callback(callback_url, payload, timeout=5)
        self.assertEqual(res.get("status"), "CALLBACK_PROCESSED")
        self.assertEqual(len(MockCallbackReceiver.received_callbacks), 1)
        self.assertEqual(MockCallbackReceiver.received_callbacks[0]["status"], "SUCCESS")
        self.assertEqual(MockCallbackReceiver.received_callbacks[0]["product_id"], "test-workload")

    def test_retry_on_transient_failure(self):
        MockCallbackReceiver.fail_attempts = 2  # Fail first 2 attempts with 503, succeed on 3rd
        callback_url = f"http://127.0.0.1:{self.port}/v1/callbacks/cb-retry-test"
        payload = {"status": "SUCCESS", "retried": True}

        res = CallbackDeliveryClient.send_callback(callback_url, payload, timeout=5, max_attempts=4)
        self.assertEqual(res.get("status"), "CALLBACK_PROCESSED")
        self.assertEqual(MockCallbackReceiver.current_attempt, 3)
        self.assertEqual(len(MockCallbackReceiver.received_callbacks), 1)


class TestAsyncSchemas(unittest.TestCase):
    def test_async_schemas_validation(self):
        ack = AsyncJobAck(product_id="test-prod", trace_id="tr-1")
        self.assertEqual(ack.status, "ACCEPTED")

        cb_payload = AsyncCallbackPayload(
            status="SUCCESS",
            execution_duration_seconds=12.4,
            product_id="test-prod",
            outputs={"service_url": "https://service.run.app"},
        )
        self.assertEqual(cb_payload.status, "SUCCESS")
        self.assertEqual(cb_payload.outputs["service_url"], "https://service.run.app")

        vending_req = AsyncVendingRequest(
            product_id="test-prod",
            callback_url="https://workflowexecutions.googleapis.com/.../callback",
        )
        self.assertEqual(vending_req.initial_budget, 40.0)

        deploy_req = AsyncDeployRequest(
            product_id="test-prod",
            callback_url="https://workflowexecutions.googleapis.com/.../callback",
        )
        self.assertEqual(deploy_req.product_id, "test-prod")

        qa_req = AsyncQAVerifyRequest(
            product_id="test-prod",
            branch_name="feature/test",
            callback_url="https://workflowexecutions.googleapis.com/.../callback",
        )
        self.assertEqual(qa_req.branch_name, "feature/test")


def _import_terraform_service_class():
    """Import mcp-servers/terraform/service.py regardless of sys.path order.

    Several apps ship a top-level ``service.py``; other test files may have put
    their directory ahead of the terraform one, or cached a different
    ``service`` module, which made ``from service import TerraformService``
    depend on run order.
    """
    tf_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "terraform"))
    if tf_dir in sys.path:
        sys.path.remove(tf_dir)
    sys.path.insert(0, tf_dir)
    cached = sys.modules.get("service")
    if os.path.dirname(os.path.abspath(getattr(cached, "__file__", None) or "")) != tf_dir:
        sys.modules.pop("service", None)
    import service
    return service.TerraformService


class TestGuaranteedCallbackScope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        MockCallbackReceiver.received_callbacks = []
        MockCallbackReceiver.fail_attempts = 0
        MockCallbackReceiver.current_attempt = 0
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockCallbackReceiver)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        MockCallbackReceiver.received_callbacks.clear()
        MockCallbackReceiver.fail_attempts = 0
        MockCallbackReceiver.current_attempt = 0

    def test_guaranteed_callback_success(self):
        callback_url = f"http://127.0.0.1:{self.port}/v1/callbacks/cb-scope-success"
        trace_id = "trace-success-123"
        product_id = "prod-test-abc"
        stage_name = "vending"

        with guaranteed_callback_scope(
            callback_url=callback_url,
            trace_id=trace_id,
            stage_name=stage_name,
            product_id=product_id,
        ) as outcome:
            # FD27-07 / FD-4AI-c: success must be reported explicitly; an untouched status is now FAILED
            # (WORKER_NO_OUTCOME, pinned in tests/test_fd4ai_callback_outcome.py).
            outcome["status"] = "SUCCESS"
            outcome["outputs"] = {"project_id": "castor-prod-test-abc", "service_url": "https://service.run.app"}

        self.assertEqual(len(MockCallbackReceiver.received_callbacks), 1)
        delivered = MockCallbackReceiver.received_callbacks[0]
        self.assertEqual(delivered["status"], "SUCCESS")
        self.assertIsNone(delivered["error"])
        self.assertEqual(delivered["stage"], "vending")
        self.assertEqual(delivered["trace_id"], trace_id)
        self.assertEqual(delivered["product_id"], product_id)
        self.assertGreaterEqual(delivered["execution_duration_seconds"], 0.0)
        self.assertEqual(delivered["outputs"]["project_id"], "castor-prod-test-abc")

    def test_guaranteed_callback_workload_vended(self):
        callback_url = f"http://127.0.0.1:{self.port}/v1/callbacks/cb-scope-vended"
        trace_id = "trace-vended-123"
        product_id = "prod-test-vended"
        stage_name = "vending"

        with guaranteed_callback_scope(
            callback_url=callback_url,
            trace_id=trace_id,
            stage_name=stage_name,
            product_id=product_id,
        ) as outcome:
            outcome["status"] = "WORKLOAD_VENDED"
            outcome["outputs"] = {"project_id": "testplan01-a"}

        # FD27-07 / FD-4AI-c: WORKLOAD_VENDED is not in SUCCESS_STATUSES (no audited caller delivers it: the
        # vending worker sets SUCCESS explicitly after copying vend_all's result). It is FAILED, word kept.
        self.assertEqual(len(MockCallbackReceiver.received_callbacks), 1)
        delivered = MockCallbackReceiver.received_callbacks[0]
        self.assertEqual(delivered["status"], "FAILED")
        self.assertEqual(delivered["reported_status"], "WORKLOAD_VENDED")
        self.assertEqual(delivered["outputs"]["project_id"], "testplan01-a")

    def test_guaranteed_callback_validation_failed_stays_failed(self):
        callback_url = f"http://127.0.0.1:{self.port}/v1/callbacks/cb-scope-val-fail"
        trace_id = "trace-val-fail-123"
        product_id = "prod-test-val-fail"
        stage_name = "terraform"

        with guaranteed_callback_scope(
            callback_url=callback_url,
            trace_id=trace_id,
            stage_name=stage_name,
            product_id=product_id,
        ) as outcome:
            outcome["status"] = "VALIDATION_FAILED"
            outcome["error"] = "Reference to undeclared resource"

        self.assertEqual(len(MockCallbackReceiver.received_callbacks), 1)
        delivered = MockCallbackReceiver.received_callbacks[0]
        self.assertEqual(delivered["status"], "FAILED")
        self.assertEqual(delivered["error"], "Reference to undeclared resource")

    def test_guaranteed_callback_crash_captured(self):
        callback_url = f"http://127.0.0.1:{self.port}/v1/callbacks/cb-scope-crash"
        trace_id = "trace-crash-456"
        product_id = "prod-crash-xyz"
        stage_name = "terraform"

        with self.assertRaises(RuntimeError) as cm:
            with guaranteed_callback_scope(
                callback_url=callback_url,
                trace_id=trace_id,
                stage_name=stage_name,
                product_id=product_id,
            ) as outcome:
                raise RuntimeError("Simulated worker unhandled crash")

        self.assertIn("Simulated worker unhandled crash", str(cm.exception))
        self.assertEqual(len(MockCallbackReceiver.received_callbacks), 1)
        delivered = MockCallbackReceiver.received_callbacks[0]
        self.assertEqual(delivered["status"], "FAILED")
        self.assertEqual(delivered["error"], "RuntimeError: Simulated worker unhandled crash")
        self.assertIsNotNone(delivered["traceback"])
        self.assertIn("Simulated worker unhandled crash", delivered["traceback"])
        self.assertEqual(delivered["stage"], "terraform")
        self.assertEqual(delivered["trace_id"], trace_id)
        self.assertGreaterEqual(delivered["execution_duration_seconds"], 0.0)

    def test_guaranteed_callback_fallback_to_firestore(self):
        bad_callback_url = "http://127.0.0.1:9/unreachable"
        trace_id = "trace-fs-fallback-789"
        product_id = "prod-fs-fallback"
        stage_name = "qa"

        mock_doc = MagicMock()
        mock_collection = MagicMock()
        mock_collection.document.return_value = mock_doc
        mock_firestore = MagicMock()
        mock_firestore.collection.return_value = mock_collection

        with unittest.mock.patch("shared.callbacks.CallbackDeliveryClient.send_callback", side_effect=ConnectionRefusedError("Connection refused")):
            with self.assertRaises(ValueError):
                with guaranteed_callback_scope(
                    callback_url=bad_callback_url,
                    trace_id=trace_id,
                    stage_name=stage_name,
                    product_id=product_id,
                    firestore_db=mock_firestore,
                ) as outcome:
                    raise ValueError("QA test suite execution failed")

        mock_firestore.collection.assert_called_with("pipeline_executions")
        mock_collection.document.assert_called_with(trace_id)
        mock_doc.set.assert_called_once()
        call_args, call_kwargs = mock_doc.set.call_args
        doc_payload = call_args[0]
        self.assertEqual(call_kwargs.get("merge"), True)
        self.assertEqual(doc_payload["status"], "FAILED")
        self.assertEqual(doc_payload["stages"]["qa"]["status"], "FAILED")
        self.assertEqual(doc_payload["stages"]["qa"]["state"], "CALLBACK_FAILED")
        self.assertIn("QA test suite execution failed", doc_payload["stages"]["qa"]["error"])
        self.assertIn("traceback", doc_payload["stages"]["qa"])

    def test_deploy_workload_startup_probe_failure_stays_failed(self):
        """FD-4DE: the startup-probe override is gone. An apply that fails on a startup probe is FAILED even when
        the Cloud Run API would list the service with a URL (it is not consulted on a failed apply)."""
        import tempfile
        TerraformService = _import_terraform_service_class()

        service = TerraformService(project_id="castor-parent")
        self.assertFalse(hasattr(service, "_reconcile_cloud_run_service"))
        listed = []

        def _listing(*a, **k):
            listed.append(a)
            return [{"name": "projects/p/locations/r/services/mytest", "uri": "https://mytest-xyz.a.run.app"}], None

        with tempfile.TemporaryDirectory() as tmp_ws:
            with unittest.mock.patch.object(service, "_fetch_repo_files", return_value={}), \
                 unittest.mock.patch.object(service, "prepare_workspace", return_value=tmp_ws), \
                 unittest.mock.patch.object(service, "_build_and_push_container", return_value=True), \
                 unittest.mock.patch.object(service, "_ensure_provider_mirror", return_value="/tmp/terraform.rc"), \
                 unittest.mock.patch.object(service, "_compliance_gate_check", return_value={"passed": True, "evidence": {}}), \
                 unittest.mock.patch.object(service, "_list_cloud_run_services", side_effect=_listing):

                def mock_subp(cmd, **kwargs):
                    if "init" in cmd:
                        return {"success": True, "returncode": 0, "stdout": "", "stderr": ""}
                    elif "apply" in cmd:
                        return {
                            "success": False,
                            "returncode": 1,
                            "stderr": "Error: The user-provided container failed the configured startup probe checks",
                            "stdout": "",
                        }
                    elif "output" in cmd:
                        return {"success": True, "returncode": 0, "stdout": "{}"}
                    return {"success": True, "returncode": 0, "stdout": ""}

                with unittest.mock.patch.object(service, "_run_subprocess", side_effect=mock_subp):
                    res = service.deploy_workload(
                        product_id="mytest",
                        trace_id="trace-rec-test",
                        hcl_files={"main.tf": 'resource "google_cloud_run_v2_service" "app" {}'},
                        target_project_id="child-proj-123",
                    )

            self.assertEqual(res.get("status"), "FAILED")
            self.assertIn("failed the configured startup probe checks", res.get("error", ""))
            self.assertFalse(res.get("service_url"))
            self.assertEqual(listed, [])


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    unittest.main()
