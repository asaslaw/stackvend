"""
Project Castor: End-to-End Async Callback Harness Test
Tests async endpoints across Project Vending, Terraform MCP, and Gateway services.
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

import pytest
from unittest.mock import MagicMock, patch

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Mock external cloud clients before imports
for mod in [
    "google", "google.auth", "googleapiclient", "googleapiclient.discovery",
    "googleapiclient.errors", "google.cloud", "google.cloud.firestore",
    "google.cloud.secretmanager", "google.cloud.storage", "jwt", "github", "httpx"
]:
    sys.modules[mod] = MagicMock()

# Mock pydantic & fastapi
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
    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: default if default is not None else (default_factory() if default_factory else None)
    mock_pydantic.EmailStr = str
    sys.modules['pydantic'] = mock_pydantic

try:
    import fastapi
except ImportError:
    mock_fastapi = MagicMock()
    mock_fastapi.status.HTTP_202_ACCEPTED = 202
    sys.modules['fastapi'] = mock_fastapi


class MockCallbackServer(http.server.BaseHTTPRequestHandler):
    received_payloads = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        payload = json.loads(body.decode("utf-8"))
        MockCallbackServer.received_payloads.append(payload)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ACK"}')

    def log_message(self, format, *args):
        pass


class TestAsyncEndpointsHarness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        MockCallbackServer.received_payloads.clear()
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockCallbackServer)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        MockCallbackServer.received_payloads.clear()


    # ---------------------------------------------------------------- QA async worker (FD-05 B-2)
    # The old test ran the REAL QASandboxRunner: a failed clone left an empty sandbox, and it "passed" only when no
    # `pytest` binary was on PATH (the runner maps FileNotFoundError to success: FD-4F). With an activated venv
    # (and in CI) it failed. These tests pin the gateway worker's contract with BOTH QA stages mocked; never with the
    # Stage-2 auditor set to None (red-team F3). The runner's own fail-opens are the FD-4F strict xfails below.
    def _gateway(self):
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../apps/orchestrator-gateway")))
        import importlib.util
        spec = importlib.util.spec_from_file_location("gw_main", os.path.abspath(os.path.join(os.path.dirname(__file__), "../apps/orchestrator-gateway/main.py")))
        gw = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gw)
        return gw

    def _qa_request(self, gw):
        return gw.AsyncQAVerifyRequest(
            product_id="test-portal",
            branch_name="feature/test-branch",
            trace_id="tr-qa-999",
            callback_url=f"http://127.0.0.1:{self.port}/workflow/qa-callback",
        )

    # FD-4F (lane 13): the gateway no longer runs QA in-process (no `qa_runner`, no QASandboxRunner). The async worker
    # wraps the one `run_qa` core (isolated QA job + Stage 2 dual-lens, tested in tests/test_fd4f_qa_*.py) and must
    # always deliver exactly one callback carrying run_qa's typed verdict. Lane 2's strict xfails X-3b / X-3c (QA
    # without a runner / a Stage 2 crash reported SUCCESS) are fixed by lane 13 and are now ordinary tests.
    _PASS = {"status": "SUCCESS", "passed": True, "error_class": None, "product_id": "test-portal",
             "summary": "QA passed: 3/3 tests", "outputs": {"exit_code": 0}, "execution_duration_seconds": 1.0}
    _STAGE_ONE_FAIL = {"status": "FAILED", "passed": False, "error_class": "CODE_DEFECT", "retryable": True,
                       "product_id": "test-portal", "summary": "QA failed: 1 blocking defect", "outputs": {}}
    _STAGE_TWO_REJECT = {"status": "FAILED", "passed": False, "error_class": "CODE_DEFECT", "retryable": True,
                         "product_id": "test-portal", "summary": "Composite audit rejected", "outputs": {}}

    def _run_worker(self, gw, qa_body=None, raises=None, client=object()):
        seen = []

        def fake_run_qa(req, *, client, source_backend_factory, evidence_db):
            seen.append({"req": req, "client": client})
            if raises is not None:
                raise raises
            if client is None:  # mirrors run_qa: no QA job client -> typed GATE_UNAVAILABLE, never a pass
                raise gw.GateUnavailableError("QA job not configured", reason="QA_NOT_CONFIGURED")
            return dict(qa_body)

        with patch.object(gw, "run_qa", side_effect=fake_run_qa):
            gw.run_qa_verify_in_background(self._qa_request(gw), client, lambda pid: None, None)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["req"].trace_id, "tr-qa-999")
        self.assertEqual(len(MockCallbackServer.received_payloads), 1)
        return MockCallbackServer.received_payloads[0]

    def test_direct_gateway_qa_async_worker(self):
        """run_qa passes -> SUCCESS callback with the verdict fields."""
        res = self._run_worker(self._gateway(), self._PASS)
        self.assertEqual(res.get("status"), "SUCCESS")
        self.assertEqual(res.get("product_id"), "test-portal")
        self.assertTrue(res.get("passed"))

    def test_direct_gateway_qa_async_worker_stage_one_failure(self):
        """The isolated QA job finds a code defect -> FAILED callback, typed CODE_DEFECT."""
        res = self._run_worker(self._gateway(), self._STAGE_ONE_FAIL)
        self.assertEqual(res.get("status"), "FAILED")
        self.assertFalse(res.get("passed"))
        self.assertEqual(res.get("error_class"), "CODE_DEFECT")

    def test_direct_gateway_qa_async_worker_stage_two_rejection(self):
        """Stage 1 passes but the dual-lens audit rejects -> FAILED callback."""
        res = self._run_worker(self._gateway(), self._STAGE_TWO_REJECT)
        self.assertEqual(res.get("status"), "FAILED")
        self.assertFalse(res.get("passed"))

    def test_qa_worker_without_runner_fails_closed(self):
        """X-3b fixed: no QA job client -> FAILED GATE_UNAVAILABLE callback, never SUCCESS."""
        res = self._run_worker(self._gateway(), client=None)
        self.assertEqual(res.get("status"), "FAILED")
        self.assertFalse(res.get("passed"))
        self.assertEqual(res.get("error_class"), "GATE_UNAVAILABLE")

    def test_qa_worker_stage_two_crash_fails_closed(self):
        """X-3c fixed: a Stage 2 audit outage is a typed GATE_UNAVAILABLE -> FAILED callback, never SUCCESS."""
        gw = self._gateway()
        res = self._run_worker(gw, raises=gw.GateUnavailableError("security lens: judge unavailable",
                                                                  reason="STAGE2_UNAVAILABLE"))
        self.assertEqual(res.get("status"), "FAILED")
        self.assertFalse(res.get("passed"))
        self.assertEqual(res.get("error_class"), "GATE_UNAVAILABLE")

    # Exercise the in-process worker: with PROJECT_ID set (as in every test env),
    # trigger_tf_applier_job would otherwise dispatch the real tf-applier Cloud Run
    # Job (or "succeed" against a stubbed run_v2) and never post the callback.
    @patch.dict(os.environ, {"ENABLE_TF_APPLIER_JOB": "false"})
    def test_terraform_deploy_async_worker(self):
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../mcp-servers/terraform")))
        import importlib.util
        spec = importlib.util.spec_from_file_location("tf_main", os.path.abspath(os.path.join(os.path.dirname(__file__), "../mcp-servers/terraform/main.py")))
        tf = importlib.util.module_from_spec(spec)

        spec.loader.exec_module(tf)
        tf.service.deploy_workload = MagicMock(return_value={
            "status": "SUCCESS",
            "product_id": "test-portal",
            "service_url": "https://test-portal.a.run.app",
        })

        callback_url = f"http://127.0.0.1:{self.port}/workflow/deploy-callback"
        req = tf.AsyncDeployRequest(
            product_id="test-portal",
            trace_id="tr-tf-888",
            callback_url=callback_url,
        )

        tf.run_deploy_in_background(req)

        self.assertEqual(len(MockCallbackServer.received_payloads), 1)
        res = MockCallbackServer.received_payloads[0]
        self.assertEqual(res.get("status"), "SUCCESS")
        self.assertEqual(res.get("product_id"), "test-portal")
        self.assertEqual(res.get("service_url"), "https://test-portal.a.run.app")

    def test_vending_async_worker(self):
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../apps/project-vending")))
        import importlib.util
        spec = importlib.util.spec_from_file_location("vending_main", os.path.abspath(os.path.join(os.path.dirname(__file__), "../apps/project-vending/main.py")))
        vending_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vending_mod)

        vending_mod.vending_engine.vend_all = MagicMock(return_value={
            "status": "SUCCESS",
            "project_id": "castor-test-portal-507121",
            "assigned_cidr": "10.100.1.0/28",
            "github_repo_url": "https://github.com/projectcastor/test-portal",
        })

        callback_url = f"http://127.0.0.1:{self.port}/workflow/vending-callback"
        req = vending_mod.AsyncVendingRequest(
            product_id="test-portal",
            trace_id="tr-vend-777",
            callback_url=callback_url,
        )

        vending_mod.run_vending_in_background(req)

        self.assertEqual(len(MockCallbackServer.received_payloads), 1)
        res = MockCallbackServer.received_payloads[0]
        self.assertEqual(res.get("status"), "SUCCESS")
        self.assertEqual(res.get("project_id"), "castor-test-portal-507121")
        self.assertEqual(res.get("assigned_cidr"), "10.100.1.0/28")


# ---------------------------------------------------------------- QA sandbox runner fail-opens (FD-4F)
# The X-3 xfails exercised the old in-process qa-runner module, deleted by register row L3-PRB-d (nothing ran it). The isolated QA
# job's fail-closed equivalents are covered in tests/test_qa_sandbox_job.py: a missing pytest/bandit toolchain exits 11
# (GATE_UNAVAILABLE, never a pass) and the job has no checkout step (a bad/short source archive also exits 11).


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    unittest.main()
