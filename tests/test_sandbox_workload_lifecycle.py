"""
Project Castor: Autonomous Sandbox Workload Lifecycle & Decommissioning Test Suite
Comprehensive verification of:
1. Intent detection & third-party API disambiguation
2. Control Center Workload registration with dynamic countdowns
3. Operator controls: Lifespan Extension (+30d, 90d ceiling, max 3) & Production Promotion
4. Decommissioning Safeguards & Platform Self-Preservation Guards
5. Sweeper batching, in-flight pipeline deferral, pending review deferral, and T-7 / T-2 notifications
6. 2-Hour Cleaner Isolation from 30-Day Managed Sandboxes
7. Spec Ingestion Google Doc sandbox tagging
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

# Ensure paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONTROL_CENTER_DIR = os.path.join(BASE_DIR, "apps", "control-center")
SANDBOX_CLEANER_DIR = os.path.join(BASE_DIR, "apps", "sandbox-cleaner")
SPEC_INGESTION_DIR = os.path.join(BASE_DIR, "apps", "spec-ingestion")

for p in (BASE_DIR, CONTROL_CENTER_DIR, SANDBOX_CLEANER_DIR, SPEC_INGESTION_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

os.environ["TEST_MODE"] = "true"
os.environ["PROJECT_ID"] = "test-platform-project"
os.environ["PLATFORM_PROJECT_ID"] = "test-platform-project"

from shared.sandbox_detection import (
    detect_sandbox_intent,
    compute_sandbox_expiry,
    compute_days_remaining,
    validate_extension,
    MAX_SANDBOX_CUMULATIVE_DAYS,
    MAX_SANDBOX_EXTENSIONS,
)
try:
    from cleaner import SandboxGarbageCollector
except ImportError:
    from apps.sandbox_cleaner.cleaner import SandboxGarbageCollector  # type: ignore

try:
    from poller import SpecIngestionPoller
except ImportError:
    from apps.spec_ingestion.poller import SpecIngestionPoller  # type: ignore

from fastapi import HTTPException
from fastapi.testclient import TestClient


class TestSandboxIntentDetection(unittest.TestCase):
    """Verifies regex and NLP heuristics for detecting sandbox intent and avoiding false positives."""

    def test_direct_sandbox_intent(self):
        text = "Please make this a sandbox workload for testing the payment webhook."
        is_sb, ttl = detect_sandbox_intent(text)
        self.assertTrue(is_sb)
        self.assertEqual(ttl, 30)

    def test_temporary_test_environment(self):
        text = "Deploy a temporary test environment for sprint 4 validation."
        is_sb, ttl = detect_sandbox_intent(text)
        self.assertTrue(is_sb)
        self.assertEqual(ttl, 30)

    def test_throwaway_sandbox(self):
        text = "We need a throwaway sandbox environment for load testing."
        is_sb, ttl = detect_sandbox_intent(text)
        self.assertTrue(is_sb)
        self.assertEqual(ttl, 30)

    def test_explicit_ttl_parsing(self):
        text = "Create a sandbox environment with 60 days duration for customer beta."
        is_sb, ttl = detect_sandbox_intent(text)
        self.assertTrue(is_sb)
        self.assertEqual(ttl, 60)

        text_14 = "Disposable eval environment (14d ttl) for security audit."
        is_sb_14, ttl_14 = detect_sandbox_intent(text_14)
        self.assertTrue(is_sb_14)
        self.assertEqual(ttl_14, 14)

    def test_third_party_api_exclusion(self):
        text = "Connect customer billing service to Stripe Sandbox API with secret keys."
        is_sb, _ = detect_sandbox_intent(text)
        self.assertFalse(is_sb)

        paypal_text = "Verify payments using PayPal Sandbox environment credentials."
        is_sb_pp, _ = detect_sandbox_intent(paypal_text)
        self.assertFalse(is_sb_pp)

    def test_permanent_production_intent(self):
        text = "Build mission-critical core banking ledger service on high availability Cloud SQL."
        is_sb, _ = detect_sandbox_intent(text)
        self.assertFalse(is_sb)

    def test_extension_validation(self):
        # Initial 30d -> extend 30d (Cumulative 60d, Ext #1) -> ALLOWED
        allowed, msg = validate_extension(30, 0, 30)
        self.assertTrue(allowed)

        # Cumulative 60d -> extend 30d (Cumulative 90d, Ext #2) -> ALLOWED
        allowed, msg = validate_extension(60, 1, 30)
        self.assertTrue(allowed)

        # Cumulative 90d -> extend 30d (Would be 120d > 90d) -> REJECTED
        allowed, msg = validate_extension(90, 2, 30)
        self.assertFalse(allowed)
        self.assertIn("Cumulative maximum lifespan", msg)

        # Extension count maxed at 3
        allowed, msg = validate_extension(60, 3, 10)
        self.assertFalse(allowed)
        self.assertIn("Maximum extension limit (3) reached", msg)


class _VendingResp:
    def __init__(self, status_code, body):
        self.status_code, self._body, self.text = status_code, body, str(body)

    def json(self):
        return self._body


class FakeVending:
    """Lane 18 S2: the CC routes sandbox lifecycle and decommission through project-vending (make_vending_request)."""

    def __init__(self, status_code=200, body=None):
        self.status_code, self.body, self.calls = status_code, body or {}, []

    def __call__(self, method, path, json_body=None, timeout=60.0, request=None):
        self.calls.append((method, path, json_body))
        return _VendingResp(self.status_code, self.body)


class TestControlCenterWorkloadRoutes(unittest.TestCase):
    """Tests Control Center Workload endpoints for sandbox lifecycle, extensions, promotions, and sweeps."""

    def setUp(self):
        from routes import workloads as wl_routes
        self.wl_routes = wl_routes
        self.mock_db = MagicMock()
        self.wl_routes.db = self.mock_db

    def test_create_workload_with_sandbox(self):
        from schemas import CreateWorkloadRequest
        req = CreateWorkloadRequest(
            product_id="billing-sandbox",
            title="Billing Sandbox Test",
            spec_content="A temporary test sandbox environment for billing testing.",
            is_sandbox=True,
            sandbox_ttl_days=30,
        )
        mock_http_request = MagicMock()
        mock_http_request.state.user_email = "test-admin@company.com"
        mock_http_request.state.user_role = "ADMIN"

        doc_mock = MagicMock()
        self.mock_db.collection().document.return_value = doc_mock

        # FD-4AY (lane 4): no owner/folder defaults; the install's GITHUB_OWNER and managed root come from config.
        # RT14-19: a create with no publisher is now 503 INTAKE_DISPATCH_UNAVAILABLE (it used to answer 200 with no
        # build); this test is about the sandbox fields, so the build event is published to a mock.
        with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
             patch("routes.workloads.get_pubsub_publisher", return_value=MagicMock()), \
             patch("routes.workloads._admit_new_build", return_value=None), \
             patch("routes.workloads.get_platform_settings",  # FD-4AK: unreadable settings refuse intake (503)
                   return_value=__import__("routes.settings", fromlist=["x"]).PlatformSettings()):
            resp = self.wl_routes.create_workload(req, mock_http_request)

        self.assertEqual(resp.product_id, "billing-sandbox")
        # Verify stored doc received sandbox fields
        set_calls = doc_mock.set.call_args_list
        self.assertTrue(len(set_calls) > 0)
        workload_payload = set_calls[0][0][0]
        self.assertTrue(workload_payload.get("is_sandbox"))
        self.assertEqual(workload_payload.get("sandbox_ttl_days"), 30)
        self.assertIsNotNone(workload_payload.get("sandbox_expires_at"))
        self.assertEqual(workload_payload.get("sandbox_decommission_status"), "SCHEDULED")

    def test_extend_sandbox_endpoint_success(self):
        from schemas import ExtendSandboxRequest

        mock_doc = MagicMock()
        mock_doc.exists = True
        future_iso = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        mock_doc.to_dict.return_value = {
            "product_id": "test-sb",
            "is_sandbox": True,
            "status": "ACTIVE",
            "sandbox_expires_at": future_iso,
            "sandbox_ttl_days": 30,
            "cumulative_lifespan_days": 30,
            "extension_count": 0,
        }
        doc_ref_mock = MagicMock()
        doc_ref_mock.get.return_value = mock_doc
        self.mock_db.collection().document.return_value = doc_ref_mock

        mock_http_request = MagicMock()
        mock_http_request.state.user_email = "admin@company.com"
        mock_http_request.state.user_role = "ADMIN"

        vending_expiry = (datetime.now(timezone.utc) + timedelta(days=40)).isoformat()
        vending = FakeVending(200, {"status": "OK", "action": "EXTEND", "sandbox_expires_at": vending_expiry})
        with patch.object(self.wl_routes, "make_vending_request", vending):
            resp = self.wl_routes.extend_sandbox_endpoint(
                "test-sb",
                mock_http_request,
                ExtendSandboxRequest(extend_days=30, reason="Sprint testing continuation"),
            )

        self.assertEqual(resp.product_id, "test-sb")
        self.assertEqual(resp.extension_count, 1)
        self.assertEqual(resp.cumulative_lifespan_days, 60)
        self.assertTrue(resp.sandbox_days_remaining > 35)
        # Lane 18 S2: vending applies the extension to the vend-time expiry it enforces; the ledger mirrors it
        self.assertEqual(vending.calls, [("POST", "/projects/test-sb/lifecycle", {"action": "EXTEND", "ttl_days": 30})])
        self.assertEqual(resp.new_expires_at, vending_expiry)
        self.assertEqual(doc_ref_mock.set.call_args_list[0][0][0]["sandbox_expires_at"], vending_expiry)

    def test_extend_sandbox_endpoint_limit_enforced(self):
        from schemas import ExtendSandboxRequest

        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "product_id": "test-sb",
            "is_sandbox": True,
            "status": "ACTIVE",
            "sandbox_expires_at": datetime.now(timezone.utc).isoformat(),
            "cumulative_lifespan_days": 90,
            "extension_count": 2,
        }
        doc_ref_mock = MagicMock()
        doc_ref_mock.get.return_value = mock_doc
        self.mock_db.collection().document.return_value = doc_ref_mock

        mock_http_request = MagicMock()
        mock_http_request.state.user_email = "admin@company.com"
        mock_http_request.state.user_role = "ADMIN"

        with self.assertRaises(HTTPException) as ctx:
            self.wl_routes.extend_sandbox_endpoint(
                "test-sb",
                mock_http_request,
                ExtendSandboxRequest(extend_days=30),
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Cumulative maximum lifespan", ctx.exception.detail)

    def test_promote_sandbox_endpoint(self):
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "product_id": "test-sb",
            "is_sandbox": True,
            "status": "ACTIVE",
            "sandbox_expires_at": datetime.now(timezone.utc).isoformat(),
        }
        doc_ref_mock = MagicMock()
        doc_ref_mock.get.return_value = mock_doc
        self.mock_db.collection().document.return_value = doc_ref_mock

        mock_http_request = MagicMock()
        mock_http_request.state.user_email = "admin@company.com"
        mock_http_request.state.user_role = "ADMIN"

        vending = FakeVending(200, {"status": "OK", "action": "PROMOTE", "warnings": []})
        with patch.object(self.wl_routes, "make_vending_request", vending):
            resp = self.wl_routes.promote_sandbox_endpoint("test-sb", mock_http_request)
        self.assertEqual(resp.product_id, "test-sb")
        self.assertFalse(resp.is_sandbox)
        self.assertEqual(vending.calls, [("POST", "/projects/test-sb/lifecycle", {"action": "PROMOTE"})])

        # Verify Firestore update cleared sandbox flags
        set_call = doc_ref_mock.set.call_args[0][0]
        self.assertFalse(set_call["is_sandbox"])
        self.assertFalse(set_call["sandbox_auto_decommission"])
        self.assertIsNone(set_call["sandbox_expires_at"])
        self.assertEqual(set_call["sandbox_decommission_status"], "PROMOTED")

    def test_sweep_outcome_status_not_masked_by_imminent_expiry(self):
        """Lane 4 (re-review G6): GUARD_REFUSED / DECOMMISSION_FAILED written by the guarded sweep are shown as-is;
        any other expired sandbox still reports the derived EXPIRATION_IMMINENT (Do-No-Harm control)."""
        past_iso = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        mock_http_request = MagicMock()
        mock_http_request.state.user_email = "admin@company.com"
        mock_http_request.state.user_role = "ADMIN"
        for stored, shown in (("GUARD_REFUSED", "GUARD_REFUSED"), ("DECOMMISSION_FAILED", "DECOMMISSION_FAILED"),
                              ("SCHEDULED", "EXPIRATION_IMMINENT")):
            mock_doc = MagicMock()
            mock_doc.exists = True
            mock_doc.to_dict.return_value = {
                "product_id": "test-sb", "project_id": "castor-test-sb", "is_sandbox": True, "status": "ACTIVE",
                "sandbox_expires_at": past_iso, "sandbox_decommission_status": stored,
            }
            self.mock_db.collection().document().get.return_value = mock_doc
            with patch.object(self.wl_routes, "fetch_workload_state_from_gcs", return_value=None):
                details = self.wl_routes.get_workload_details("test-sb", mock_http_request)
            self.assertEqual(details.sandbox_decommission_status, shown, stored)

    def test_platform_self_preservation_guardrail(self):
        from schemas import DecommissionRequest
        mock_http_request = MagicMock()
        mock_http_request.state.user_email = "admin@company.com"
        mock_http_request.state.user_role = "ADMIN"

        # Attempting to decommission project-castor must raise HTTP 400
        with self.assertRaises(HTTPException) as ctx:
            self.wl_routes.decommission_workload_endpoint(
                "project-castor",
                DecommissionRequest(confirm_product_id="project-castor", approval_id="app-123"),
                mock_http_request,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("cannot be decommissioned", ctx.exception.detail.lower())

        # Attempting to decommission host platform project must raise HTTP 400
        with self.assertRaises(HTTPException) as ctx2:
            self.wl_routes.decommission_workload_endpoint(
                "test-platform-project",
                DecommissionRequest(confirm_product_id="test-platform-project", approval_id="app-123"),
                mock_http_request,
            )
        self.assertEqual(ctx2.exception.status_code, 400)


@hermetic_guard.unavailable("google.cloud.storage.Client", "GCS")
class TestSweeperSafeguards(unittest.TestCase):
    """Tests the automated sweeper logic for batching, pipeline deferrals, advance warnings, and zero-cost decommissioning."""

    def setUp(self):
        from routes import workloads as wl_routes
        self.wl_routes = wl_routes
        self.mock_db = MagicMock()
        self.wl_routes.db = self.mock_db

    def test_sweeper_advance_warnings(self):
        # Mock active sandboxes: one at T-5 (warn_t7), one at T-1 (warn_t2)
        doc_t5 = MagicMock()
        doc_t5.id = "sb-warning-t5"
        exp_t5 = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        doc_t5.to_dict.return_value = {
            "product_id": "sb-warning-t5",
            "is_sandbox": True,
            "status": "ACTIVE",
            "sandbox_expires_at": exp_t5,
            "warn_t7_sent": False,
            "warn_t2_sent": False,
        }

        doc_t1 = MagicMock()
        doc_t1.id = "sb-warning-t1"
        exp_t1 = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        doc_t1.to_dict.return_value = {
            "product_id": "sb-warning-t1",
            "is_sandbox": True,
            "status": "ACTIVE",
            "sandbox_expires_at": exp_t1,
            "warn_t7_sent": True,
            "warn_t2_sent": False,
        }

        self.mock_db.collection().where().stream.return_value = [doc_t5, doc_t1]

        mock_http_request = MagicMock()
        mock_http_request.headers = {"X-CloudScheduler": "true"}

        result = self.wl_routes.sweep_expired_sandboxes_endpoint(mock_http_request)

        self.assertEqual(result.scanned_count, 2)
        self.assertEqual(len(result.notifications_sent), 2)
        self.assertEqual(result.expired_count, 0)
        self.assertEqual(len(result.decommissioned_workloads), 0)

    def test_sweeper_in_flight_pipeline_deferral(self):
        # Workload expired (days <= 0) but status is IN_PROGRESS
        doc_expired = MagicMock()
        doc_expired.id = "sb-active-pipeline"
        past_iso = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        doc_expired.to_dict.return_value = {
            "product_id": "sb-active-pipeline",
            "is_sandbox": True,
            "status": "IN_PROGRESS",
            "sandbox_expires_at": past_iso,
            "sandbox_designation_source": "API_FIELD",   # C10: only a TTL-eligible sandbox reaches the deferrals
        }

        self.mock_db.collection().where().stream.return_value = [doc_expired]

        mock_http_request = MagicMock()
        mock_http_request.headers = {"X-CloudScheduler": "true"}

        result = self.wl_routes.sweep_expired_sandboxes_endpoint(mock_http_request)

        self.assertEqual(result.expired_count, 1)
        self.assertEqual(len(result.deferred_workloads), 1)
        self.assertIn("sb-active-pipeline", result.deferred_workloads[0])
        self.assertEqual(len(result.decommissioned_workloads), 0)

    def test_sweeper_pending_review_deferral(self):
        # Workload expired (days <= 0), status ACTIVE, but feature request PENDING_APPROVAL
        doc_expired = MagicMock()
        doc_expired.id = "sb-pending-review"
        past_iso = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        doc_expired.to_dict.return_value = {
            "product_id": "sb-pending-review",
            "is_sandbox": True,
            "sandbox_designation_source": "API_FIELD",
            "status": "ACTIVE",
            "sandbox_expires_at": past_iso,
        }

        self.mock_db.collection().where().stream.return_value = [doc_expired]

        # Feature request stream has 1 pending review
        mock_feat_doc = MagicMock()
        mock_feat_stream = [mock_feat_doc]
        self.mock_db.collection().where().where().limit().stream.return_value = mock_feat_stream

        mock_http_request = MagicMock()
        mock_http_request.headers = {"X-CloudScheduler": "true"}

        result = self.wl_routes.sweep_expired_sandboxes_endpoint(mock_http_request)

        self.assertEqual(result.expired_count, 1)
        self.assertEqual(len(result.deferred_workloads), 1)
        self.assertIn("sb-pending-review", result.deferred_workloads[0])
        self.assertEqual(len(result.decommissioned_workloads), 0)

    def test_sweeper_autonomous_decommission_execution(self):
        # Workload expired, no active pipeline or review -> lane 18 S2: the sweep asks project-vending to decommission it
        # (SANDBOX_TTL, automatic). Vending's guard decides and deletes by number; the CC itself makes no CRM call.
        doc_expired = MagicMock()
        doc_expired.id = "sb-expired-ready"
        past_iso = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
        ledger = {
            "product_id": "sb-expired-ready", "project_id": "castor-sb-expired-child-123",
            "project_number": "123456789", "is_sandbox": True, "sandbox_auto_decommission": True,
            "sandbox_designation_source": "API_FIELD", "status": "ACTIVE", "sandbox_expires_at": past_iso,
            "sandbox_ttl_days": 30, "cumulative_lifespan_days": 30,
        }
        doc_expired.to_dict.return_value = ledger
        workloads_coll = self.mock_db.collection.return_value
        workloads_coll.where().stream.return_value = [doc_expired]          # sweep scan
        workloads_coll.where().where().limit().stream.return_value = []     # no pending review

        vending = FakeVending(200, {"status": "DECOMMISSIONED", "deleted_project_id": "castor-sb-expired-child-123",
                                    "deleted_project_number": "123456789", "crm_operation": "operations/op-1",
                                    "action_class": "SANDBOX_TTL", "warnings": []})
        mock_http_request = MagicMock()
        mock_http_request.headers = {"X-CloudScheduler": "true"}
        with patch.object(self.wl_routes, "make_vending_request", vending), \
             patch.object(self.wl_routes, "cancel_workload_active_executions", return_value=0):
            result = self.wl_routes.sweep_expired_sandboxes_endpoint(mock_http_request)
        self.assertEqual(result.expired_count, 1)
        self.assertEqual(len(result.decommissioned_workloads), 1)
        self.assertIn("sb-expired-ready", result.decommissioned_workloads)
        self.assertEqual(vending.calls, [("POST", "/projects/sb-expired-ready/decommission",
                                          {"action_class": "SANDBOX_TTL"})])

    def test_sweeper_reports_vending_refusal(self):
        doc_expired = MagicMock()
        doc_expired.id = "sb-keyword"
        doc_expired.to_dict.return_value = {
            "product_id": "sb-keyword", "project_id": "castor-sb-keyword", "is_sandbox": True, "status": "ACTIVE",
            "sandbox_expires_at": (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(),
            "sandbox_designation_source": "KEYWORD_DETECTED"}
        workloads_coll = self.mock_db.collection.return_value
        workloads_coll.where().stream.return_value = [doc_expired]
        workloads_coll.where().where().limit().stream.return_value = []
        vending = FakeVending(409, {"detail": {"code": "SANDBOX_NOT_ELIGIBLE", "detail": "designation not explicit"}})
        with patch.object(self.wl_routes, "make_vending_request", vending):
            result = self.wl_routes.sweep_expired_sandboxes_endpoint(MagicMock())
        # C10 (RT finding 4): a keyword-detected sandbox awaits confirmation: not sent to vending, listed not eligible
        self.assertEqual(result.decommissioned_workloads, [])
        self.assertEqual(result.not_eligible_workloads, ["sb-keyword"])
        self.assertEqual(len(vending.calls), 0)
        # an explicit sandbox that vending refuses (409): listed as refused, not an error
        doc_expired.to_dict.return_value = dict(doc_expired.to_dict.return_value, sandbox_designation_source="API_FIELD")
        with patch.object(self.wl_routes, "make_vending_request", vending):
            result = self.wl_routes.sweep_expired_sandboxes_endpoint(MagicMock())
        self.assertEqual(result.refused_workloads, ["sb-keyword (SANDBOX_NOT_ELIGIBLE)"])
        self.assertEqual(result.errors, [])
        self.assertEqual(len(vending.calls), 1)


@hermetic_guard.unavailable("google.cloud.storage.Client", "GCS")
class TestCleanerIsolation(unittest.TestCase):
    """The 2-hour ephemeral garbage collector never touches 30-day sandboxes (lane 14 PR-6, plan 2.2): it acts only on
    vending-registered ``ephemeral_resources`` ledger records, so a sandbox (or any service) with no ledger record is
    never requested for deletion, whatever its name or labels."""

    def test_cleaner_ignores_30d_sandbox_services(self):
        mock_db = MagicMock()
        # The ledger holds no record for the 30-day sandbox (or for the services the old name sweep matched).
        mock_db.collection.return_value.where.return_value.stream.return_value = []
        posts = []
        collector = SandboxGarbageCollector(
            project_id="test-platform-proj",
            env={"PROJECT_ID": "test-platform-proj", "REGION": "us-central1", "CLOUD_RUN_EXECUTION": "exec-30d"},
            firestore_client=mock_db,
            service_url_resolver=lambda *a: self.fail("no vending lookup without a due ledger record"),
            id_token_fetcher=lambda aud: self.fail("no token without a due ledger record"),
            http_post=lambda *a, **k: posts.append(a) or (500, None),
        )

        res = collector.execute_cleanup()

        self.assertEqual(res["exit_code"], 0)
        self.assertEqual(res["requests"], [])
        self.assertEqual(posts, [])
        self.assertFalse(hasattr(collector, "clean_ephemeral_cloud_run_services"))  # no name-based sweep exists


class TestSpecIngestionSandbox(unittest.TestCase):
    """Verifies that Google Doc intake poller tags sandbox specifications correctly."""

    def test_poller_tags_sandbox_spec(self):
        mock_drive = MagicMock()
        mock_publisher = MagicMock()
        mock_db = MagicMock()

        mock_drive.files().list().execute.return_value = {
            "files": [
                {
                    "id": "doc-sb-101",
                    "name": "NEW_PRODUCT_SPEC: Test Sandbox Analytics Environment",
                    "description": "Please deploy a sandbox workload for evaluating analytics.",
                    "mimeType": "application/vnd.google-apps.document",
                    "owners": [{"emailAddress": "lead@example.com", "me": False}],
                }
            ]
        }
        # FD-4AS: the owner is an active Control Center user; no managed folders yet (fresh install).
        user_snap = MagicMock()
        user_snap.exists = True
        user_snap.to_dict.return_value = {"role": "WORKLOAD_MANAGER", "is_active": True}
        # RT14-02: the title names a NEW workload (no ledger record), so a Workload Manager may submit it. MagicMock
        # chains ignore arguments, so the two collections the decision reads get their own documents.
        absent = MagicMock()
        absent.exists = False
        users_col, workloads_col, folders_col = MagicMock(), MagicMock(), MagicMock()
        users_col.document.return_value.get.return_value = user_snap
        workloads_col.document.return_value.get.return_value = absent
        folders_col.stream.return_value = []
        cols = {"authorized_users": users_col, "workloads": workloads_col, "managed_folders": folders_col}
        mock_db.collection.side_effect = lambda name: cols.get(name, MagicMock())
        mock_drive.files().update().execute.return_value = {
            "id": "doc-sb-101",
            "parents": ["folder-progress"],
        }
        mock_future = MagicMock()
        mock_future.result.return_value = "msg-101"
        mock_publisher.publish.return_value = mock_future

        poller = SpecIngestionPoller(
            project_id="test-proj",
            drive_service=mock_drive,
            publisher_client=mock_publisher,
            firestore_client=mock_db,
        )
        # Mock read_doc_text to return empty string
        poller.read_doc_text = MagicMock(return_value="")

        ingested = poller.poll_and_ingest("folder-inbox", "folder-progress")
        self.assertEqual(len(ingested), 1)
        item = ingested[0]
        self.assertTrue(item.get("is_sandbox"))
        self.assertEqual(item.get("sandbox_ttl_days"), 30)
        self.assertIsNotNone(item.get("sandbox_expires_at"))


if __name__ == "__main__":
    unittest.main()
