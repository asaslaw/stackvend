"""
Unit Tests for FinOps Budget Enforcement & Multi-Resource Kill-Switch
Validates breach policy schemas, multi-resource quarantine (Cloud Run, GCE, Cloud SQL, GKE, Billing Unlink),
pre-quarantine state snapshotting, 1-click restoration, CI/CD drift lockout (HTTP 423),
and Human-in-the-Loop budget remediation approval workflows.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import base64
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
FINOPS_DIR = os.path.join(REPO_ROOT, "apps", "finops-enforcer")

sys.path.insert(0, REPO_ROOT)
sys.path.insert(1, CC_DIR)
sys.path.insert(2, FINOPS_DIR)

# Set test environment flags
os.environ["TEST_MODE"] = "true"
os.environ["ENVIRONMENT"] = "test"

# ------------------------------------------------------------------------------
# Mock Third-Party Libraries (pydantic, fastapi, google-cloud) if unavailable
# ------------------------------------------------------------------------------
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
        def __init__(self, default=None, default_factory=None, **kwargs):
            self.default = default if default is not None else (default_factory() if default_factory else None)

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: MockFieldInfo(default, default_factory, **kwargs)
    mock_pydantic.EmailStr = str
    sys.modules['pydantic'] = mock_pydantic

try:
    import fastapi
except ImportError:
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

    mock_fastapi = MagicMock()
    mock_fastapi.__path__ = []
    mock_fastapi.HTTPException = MockHTTPException
    mock_fastapi.FastAPI = lambda *args, **kwargs: mock_app
    mock_fastapi.APIRouter = lambda *args, **kwargs: mock_app
    mock_fastapi.Request = MagicMock
    mock_fastapi.Response = MagicMock
    mock_fastapi.Header = lambda default=None: default
    sys.modules["fastapi"] = mock_fastapi
    sys.modules["fastapi.responses"] = MagicMock()
    sys.modules["fastapi.staticfiles"] = MagicMock()
    sys.modules["starlette"] = MagicMock()
    sys.modules["starlette.middleware"] = MagicMock()
    sys.modules["starlette.middleware.base"] = MagicMock()

for mod in [
    "google", "google.auth", "google.oauth2", "google.cloud",
    "google.cloud.firestore", "google.cloud.storage", "google.cloud.pubsub_v1",
    "googleapiclient", "googleapiclient.discovery", "googleapiclient.errors",
    "fastapi.responses", "fastapi.staticfiles", "starlette", "starlette.middleware", "starlette.middleware.base",
]:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

from shared.settings import (
    BudgetBreachPolicy,
    FinOpsSettings,
    PlatformSettings,
)
import schemas as cc_schemas
from enforcer import FinopsBudgetEnforcer


class AlreadyExists(Exception):
    code = 409


class InMemoryFirestore:
    """Mock Firestore client for simulating document reads and writes."""
    def __init__(self):
        self.data = {}

    def collection(self, col_name):
        return InMemoryCollection(self.data, col_name)

    def batch(self):
        """RT14-05 / RT14-20: the enforcer writes its markers in one batch (applied in order on commit)."""
        writes = []

        class _Batch:
            def set(self, ref, data, merge=False):
                writes.append(lambda: ref.set(data, merge=merge))

            def delete(self, ref):
                writes.append(ref.delete)

            def commit(self):
                for w in writes:
                    w()
        return _Batch()


class InMemoryCollection:
    def __init__(self, storage, col_name):
        self.storage = storage
        self.col_name = col_name
        if col_name not in self.storage:
            self.storage[col_name] = {}

    def document(self, doc_id):
        return InMemoryDocument(self.storage[self.col_name], doc_id)

    def add(self, data):
        doc_id = f"auto-{len(self.storage[self.col_name]) + 1}"
        self.storage[self.col_name][doc_id] = dict(data)
        return None, InMemoryDocument(self.storage[self.col_name], doc_id)

    def stream(self):
        for doc_id, doc_data in list(self.storage[self.col_name].items()):
            yield InMemoryDocSnapshot(doc_id, doc_data)


class InMemoryDocument:
    def __init__(self, col_storage, doc_id):
        self.col_storage = col_storage
        self.doc_id = doc_id

    def set(self, data, merge=False):
        if merge and self.doc_id in self.col_storage:
            self.col_storage[self.doc_id].update(data)
        else:
            self.col_storage[self.doc_id] = dict(data)

    def create(self, data):
        if self.doc_id in self.col_storage:
            raise AlreadyExists(self.doc_id)
        self.col_storage[self.doc_id] = dict(data)

    def get(self):
        doc_data = self.col_storage.get(self.doc_id)
        return InMemoryDocSnapshot(self.doc_id, doc_data)

    def delete(self):
        if self.doc_id in self.col_storage:
            del self.col_storage[self.doc_id]


class InMemoryDocSnapshot:
    def __init__(self, doc_id, doc_data):
        self.id = doc_id
        self._data = doc_data

    @property
    def exists(self):
        return self._data is not None

    def to_dict(self):
        return dict(self._data) if self._data else {}


MANAGED_ROOT = "111111111111"
HOST_PROJECT = "castor-platform-test"


def _managed_crm(root=MANAGED_ROOT):
    """FD-4O (lane 4, register L4-m): the enforcer acts only on projects under the managed root folder that are not
    the host. This Resource Manager fake places every project under ``root`` and gives each id its own number."""
    crm = MagicMock(name="crm")
    projects = crm.projects.return_value
    numbers = {}

    def get_ancestry(projectId, body):
        call = MagicMock()
        call.execute.return_value = {"ancestor": [{"resourceId": {"type": "project", "id": projectId}},
                                                  {"resourceId": {"type": "folder", "id": root}},
                                                  {"resourceId": {"type": "organization", "id": "999"}}]}
        return call

    def get(projectId):
        call = MagicMock()
        call.execute.return_value = {"projectNumber": numbers.setdefault(projectId, str(100000 + len(numbers)))}
        return call

    projects.getAncestry.side_effect = get_ancestry
    projects.get.side_effect = get
    return crm


class TestFinOpsBudgetEnforcement(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"MANAGED_WORKLOADS_FOLDER_ID": MANAGED_ROOT, "PROJECT_ID": HOST_PROJECT,
                                      "GOOGLE_CLOUD_PROJECT": HOST_PROJECT})
        env.start()
        self.addCleanup(env.stop)
        self.db = InMemoryFirestore()
        self.mock_run = MagicMock()
        self.mock_compute = MagicMock()
        self.mock_sql = MagicMock()
        self.mock_container = MagicMock()
        self.mock_billing = MagicMock()

        self.enforcer = FinopsBudgetEnforcer(
            project_id=HOST_PROJECT,
            firestore_client=self.db,
            run_service=self.mock_run,
            compute_service=self.mock_compute,
            sql_service=self.mock_sql,
            container_service=self.mock_container,
            billing_service=self.mock_billing,
            crm_service=_managed_crm(),
        )

    def test_budget_breach_policy_enums_and_schemas(self):
        """Validates that BudgetBreachPolicy enum values exist across shared settings and schemas."""
        self.assertEqual(BudgetBreachPolicy.AUTONOMOUS_SCALE_TO_ZERO.value, "AUTONOMOUS_SCALE_TO_ZERO")
        self.assertEqual(BudgetBreachPolicy.ALERT_ONLY.value, "ALERT_ONLY")
        self.assertEqual(BudgetBreachPolicy.HITL_CONFIRMATION_REQUIRED.value, "HITL_CONFIRMATION_REQUIRED")
        self.assertEqual(BudgetBreachPolicy.NUCLEAR_UNLINK_BILLING.value, "NUCLEAR_UNLINK_BILLING")

        finops = FinOpsSettings()
        self.assertEqual(finops.default_breach_policy, BudgetBreachPolicy.AUTONOMOUS_SCALE_TO_ZERO)

        # Control Center Schemas
        self.assertEqual(cc_schemas.BudgetBreachPolicy.AUTONOMOUS_SCALE_TO_ZERO.value, "AUTONOMOUS_SCALE_TO_ZERO")
        self.assertEqual(cc_schemas.ApprovalType.BUDGET_BREACH.value, "BUDGET_BREACH")
        self.assertEqual(cc_schemas.ApprovalType.BUDGET_BREACH_REMEDIATION.value, "BUDGET_BREACH_REMEDIATION")

        summary = cc_schemas.WorkloadSummary(
            product_id="test-wl",
            project_id="test-proj",
            status="ACTIVE",
            budget_ceiling_monthly_usd=50.0,
            budget_breach_policy="AUTONOMOUS_SCALE_TO_ZERO",
            buffer_ceiling_usd=57.50,
        )
        self.assertEqual(summary.budget_breach_policy, "AUTONOMOUS_SCALE_TO_ZERO")
        self.assertEqual(summary.buffer_ceiling_usd, 57.50)

    def test_quarantine_alert_only(self):
        """Verifies ALERT_ONLY logs/writes an alert without stopping compute."""
        res = self.enforcer.quarantine_workload(
            product_id="critical-prod-svc",
            target_project_id="proj-critical-prod",
            spend_amount=105.00,
            budget_amount=100.00,
            policy="ALERT_ONLY",
        )
        self.assertEqual(res["status"], "ALERTED_ONLY")
        self.assertEqual(res["scaled_services"], [])

        # Confirm compute APIs were NOT invoked
        self.mock_run.projects().locations().services().patch.assert_not_called()
        self.mock_compute.instances().stop.assert_not_called()

        # Confirm alert was recorded in Firestore
        alerts = list(self.db.collection("billing_alerts").stream())
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].to_dict()["product_id"], "critical-prod-svc")

    def test_quarantine_nuclear_unlink_billing(self):
        """Verifies NUCLEAR_UNLINK_BILLING detaches Google Cloud billing and sets BILLING_UNLINKED."""
        # RT14 F2: the account is read (and recorded) before the unlink
        self.mock_billing.projects.return_value.getBillingInfo.return_value.execute.return_value = {
            "billingAccountName": "billingAccounts/01ABCD-234567-89EF01"}
        res = self.enforcer.quarantine_workload(
            product_id="sandbox-runaway",
            target_project_id="proj-sandbox-runaway",
            spend_amount=250.00,
            budget_amount=50.00,
            policy="NUCLEAR_UNLINK_BILLING",
        )
        self.assertEqual(res["status"], "BILLING_UNLINKED")
        self.mock_billing.projects().updateBillingInfo.assert_called_with(
            name="projects/proj-sandbox-runaway",
            body={"billingAccountName": ""}
        )

        # Confirm workload status updated to BILLING_UNLINKED in Firestore
        wl = self.db.collection("workloads").document("sandbox-runaway").get().to_dict()
        self.assertEqual(wl["status"], "BILLING_UNLINKED")

        # Confirm approval request created
        appr = self.db.collection("approval_requests").document(res["approval_id"]).get().to_dict()
        self.assertEqual(appr["approval_type"], "BUDGET_BREACH")
        self.assertEqual(appr["status"], "PENDING")

    def test_quarantine_hitl_confirmation_required(self):
        """Verifies HITL_CONFIRMATION_REQUIRED pauses without halting compute."""
        res = self.enforcer.quarantine_workload(
            product_id="hitl-svc",
            target_project_id="proj-hitl",
            spend_amount=55.00,
            budget_amount=50.00,
            policy="HITL_CONFIRMATION_REQUIRED",
        )
        self.assertEqual(res["status"], "HITL_CONFIRMATION_PENDING")
        self.mock_run.projects().locations().services().patch.assert_not_called()

        appr = self.db.collection("approval_requests").document(res["approval_id"]).get().to_dict()
        self.assertEqual(appr["approval_type"], "BUDGET_BREACH")
        self.assertEqual(appr["status"], "PENDING")

    def test_quarantine_autonomous_scale_to_zero_and_snapshot(self):
        """Verifies AUTONOMOUS_SCALE_TO_ZERO takes snapshot and shuts off multi-resource compute."""
        # Setup mock active resources
        self.enforcer.list_workload_services = MagicMock(return_value=[
            {"name": "order-api", "max_instances": 5, "min_instances": 0}
        ])
        self.enforcer.list_running_vms = MagicMock(return_value=[
            {"name": "worker-vm-1", "zone": "us-central1-a", "status": "RUNNING"},
            {"name": "standby-vm-2", "zone": "us-central1-a", "status": "TERMINATED"},
        ])
        self.enforcer.list_cloud_sql_instances = MagicMock(return_value=[
            {"name": "order-db", "activation_policy": "ALWAYS"}
        ])
        self.enforcer.list_gke_pools = MagicMock(return_value=[
            {"cluster_name": "main-cluster", "location": "us-central1", "pool_name": "stream-pool", "node_count": 3}
        ])

        res = self.enforcer.quarantine_workload(
            product_id="order-service",
            target_project_id="proj-order-svc",
            spend_amount=52.40,
            budget_amount=50.00,
            policy="AUTONOMOUS_SCALE_TO_ZERO",
        )

        self.assertEqual(res["status"], "QUARANTINED")
        self.assertIn("run/order-api", res["quarantined_resources"])
        self.assertIn("sql/order-db", res["quarantined_resources"])

        # Check pre-quarantine snapshot was captured
        snapshot = self.db.collection("quarantine_snapshots").document("order-service").get().to_dict()
        self.assertIsNotNone(snapshot)
        self.assertEqual(len(snapshot["cloud_run_services"]), 1)
        self.assertEqual(snapshot["cloud_run_services"][0]["max_instances"], 5)
        # Verify standby VM was tracked as TERMINATED
        vm_statuses = {v["name"]: v["status"] for v in snapshot["compute_vms"]}
        self.assertEqual(vm_statuses["worker-vm-1"], "RUNNING")
        self.assertEqual(vm_statuses["standby-vm-2"], "TERMINATED")

        # Verify workload status is QUARANTINED
        wl = self.db.collection("workloads").document("order-service").get().to_dict()
        self.assertEqual(wl["status"], "QUARANTINED")

    def test_restore_from_snapshot(self):
        """Verifies 1-click restore brings back only previously running resources with original limits."""
        # Seed snapshot
        snapshot_data = {
            "product_id": "order-service",
            "project_id": "proj-order-svc",
            "cloud_run_services": [{"name": "order-api", "max_instances": 8, "min_instances": 1}],
            "compute_vms": [
                {"name": "worker-vm-1", "zone": "us-central1-a", "status": "RUNNING"},
                {"name": "standby-vm-2", "zone": "us-central1-a", "status": "TERMINATED"},
            ],
            "cloud_sql": [{"name": "order-db", "activation_policy": "ALWAYS"}],
            "gke_pools": [{"cluster_name": "main-cluster", "location": "us-central1", "pool_name": "stream-pool", "node_count": 3}],
        }
        self.db.collection("quarantine_snapshots").document("order-service").set(snapshot_data)
        self.db.collection("workloads").document("order-service").set({"status": "QUARANTINED"})

        # Mock restoration methods
        self.enforcer.set_service_scaling = MagicMock(return_value=True)
        self.enforcer.start_vms = MagicMock(return_value=["us-central1-a/worker-vm-1"])
        self.enforcer.set_cloud_sql_activation = MagicMock(return_value=True)
        self.enforcer.scale_gke_pool = MagicMock(return_value=True)
        # RT14-05: the live state read back after the restore shows the snapshot's values
        self.enforcer.list_workload_services = MagicMock(return_value=[
            {"name": "order-api", "max_instances": 8, "min_instances": 1}])
        self.enforcer.list_running_vms = MagicMock(return_value=[
            {"name": "worker-vm-1", "zone": "us-central1-a", "status": "STAGING"},
            {"name": "standby-vm-2", "zone": "us-central1-a", "status": "TERMINATED"}])
        self.enforcer.list_cloud_sql_instances = MagicMock(return_value=[
            {"name": "order-db", "activation_policy": "ALWAYS"}])

        res = self.enforcer.restore_workload("order-service", "proj-order-svc")
        self.assertEqual(res["status"], "RESTORED")

        # Verify Cloud Run was restored to 8 instances (from snapshot, not default 5)
        # FD-7M-a: in the workload's region (no recorded region -> Settings default_gcp_region, schema default here)
        self.enforcer.set_service_scaling.assert_called_with("proj-order-svc", "order-api", max_instances=8,
                                                             min_instances=1, region="us-central1")

        # Verify start_vms called ONLY for worker-vm-1 (not standby-vm-2)
        called_vms = self.enforcer.start_vms.call_args[0][1]
        self.assertEqual(len(called_vms), 1)
        self.assertEqual(called_vms[0]["name"], "worker-vm-1")

        # Verify Cloud SQL and GKE restored
        self.enforcer.set_cloud_sql_activation.assert_called_with("proj-order-svc", "order-db", "ALWAYS")
        self.enforcer.scale_gke_pool.assert_called_with("proj-order-svc", "us-central1", "main-cluster", "stream-pool", 3)

        # Verify Firestore snapshot deleted and status set to ACTIVE
        self.assertFalse(self.db.collection("quarantine_snapshots").document("order-service").get().exists)
        wl = self.db.collection("workloads").document("order-service").get().to_dict()
        self.assertEqual(wl["status"], "ACTIVE")

    def test_restore_billing_unlinked(self):
        """Verifies restoring a BILLING_UNLINKED workload re-links billing and sets status to ACTIVE."""
        self.db.collection("workloads").document("unlinked-svc").set({
            "status": "BILLING_UNLINKED",
            "root_billing_account": "billingAccounts/012345-6789AB-CDEF01",
        })
        # RT14-05: the restore reads the billing account back before reporting BILLING_RESTORED
        self.mock_billing.projects.return_value.getBillingInfo.return_value.execute.return_value = {
            "billingAccountName": "billingAccounts/012345-6789AB-CDEF01"}

        res = self.enforcer.restore_workload("unlinked-svc", "proj-unlinked-svc")
        self.assertEqual(res["status"], "BILLING_RESTORED")
        self.mock_billing.projects().updateBillingInfo.assert_called_with(
            name="projects/proj-unlinked-svc",
            body={"billingAccountName": "billingAccounts/012345-6789AB-CDEF01"}
        )
        wl = self.db.collection("workloads").document("unlinked-svc").get().to_dict()
        self.assertEqual(wl["status"], "ACTIVE")

    def test_cicd_drift_lockout_on_quarantined_workloads(self):
        """Verifies that CI/CD and feature request submissions are blocked with HTTP 423 Locked when QUARANTINED."""
        import routes.workloads as wl_routes
        from fastapi import HTTPException

        self.db.collection("workloads").document("locked-svc").set({
            "status": "QUARANTINED",
            "project_id": "proj-locked",
        })

        mock_req = MagicMock()
        mock_req.state.user_email = "operator@example.com"
        mock_req.state.user_role = "ADMIN"

        feat_req = cc_schemas.CreateFeatureRequest(
            title="Add Payment Gateway",
            description="Integration with external payment provider"
        )

        with patch("routes.workloads.db", self.db), \
             patch("routes.workloads.verify_workload_access", return_value=True):
            with self.assertRaises(HTTPException) as ctx:
                wl_routes.submit_feature_request("locked-svc", feat_req, mock_req)
            self.assertEqual(ctx.exception.status_code, 423)
            self.assertIn("locked in QUARANTINED", ctx.exception.detail)

    def test_hitl_budget_remediation_actions(self):
        """Verifies HITL decision handler executes the 4 explicit actions: Increase Budget, Restore Buffer, Maintain, Decommission."""
        import routes.approvals as appr_routes
        from schemas import ApprovalDecisionRequest, ApprovalStatus

        # Lane 4 (H6, register L4-c): an approval is decided once (re-deciding -> 409), so each action gets its own
        # approval doc. H1: the restore target comes from the workload doc's project_id, never the approval record.
        def seed_approval(appr_id):
            self.db.collection("approval_requests").document(appr_id).set({
                "approval_id": appr_id,
                "approval_type": "BUDGET_BREACH",
                "product_id": "overrun-svc",
                "target_project_id": "proj-overrun",
                "current_spend_usd": 52.40,
                "budget_ceiling_usd": 50.00,
                "projected_monthly_spend_usd": 95.00,
                "status": "PENDING",
            })
            return appr_id

        appr_id = seed_approval("appr-budget-test-123")
        self.db.collection("workloads").document("overrun-svc").set({
            "project_id": "proj-overrun",
            "status": "QUARANTINED",
            "budget_ceiling_monthly_usd": 50.00,
        })

        mock_req = MagicMock()
        mock_req.state.user_email = "finops-admin@example.com"
        mock_req.state.user_role = "ADMIN"

        mock_enforcer = MagicMock()
        # C10: the restore must report a restore (the enforcer job's verified outcome); anything else is EXECUTION_FAILED
        mock_enforcer.restore_workload.return_value = {"status": "RESTORED", "execution": "exec-1"}

        # Action 1: Increase Budget & Restore
        with patch("routes.approvals.db", self.db), \
             patch("routes.approvals.verify_workload_access", return_value=True), \
             patch("routes.approvals.get_finops_enforcer", return_value=mock_enforcer):
            dec_req = ApprovalDecisionRequest(
                decision=ApprovalStatus.APPROVED,
                action="INCREASE_BUDGET",
                new_budget_usd=100.00,
            )
            res = appr_routes.decide_approval_request(appr_id, dec_req, mock_req)
            self.assertEqual(res.status, ApprovalStatus.APPROVED)

            wl = self.db.collection("workloads").document("overrun-svc").get().to_dict()
            self.assertEqual(wl["budget_ceiling_monthly_usd"], 100.00)
            self.assertEqual(wl["status"], "ACTIVE")
            mock_enforcer.restore_workload.assert_called_with("overrun-svc", "proj-overrun")

        # Action 2: Restore with Buffer (+15%)
        appr_id = seed_approval("appr-budget-test-124")
        self.db.collection("workloads").document("overrun-svc").set({
            "project_id": "proj-overrun",
            "status": "QUARANTINED",
            "budget_ceiling_monthly_usd": 50.00,
        })
        with patch("routes.approvals.db", self.db), \
             patch("routes.approvals.verify_workload_access", return_value=True), \
             patch("routes.approvals.get_finops_enforcer", return_value=mock_enforcer):
            dec_req_buf = ApprovalDecisionRequest(
                decision=ApprovalStatus.APPROVED,
                action="RESTORE_BUFFER",
            )
            res_buf = appr_routes.decide_approval_request(appr_id, dec_req_buf, mock_req)
            self.assertEqual(res_buf.status, ApprovalStatus.APPROVED)

            wl_buf = self.db.collection("workloads").document("overrun-svc").get().to_dict()
            self.assertEqual(wl_buf["buffer_ceiling_usd"], 60.26)  # 52.40 * 1.15 = 60.26
            self.assertEqual(wl_buf["status"], "ACTIVE")

        # Action 3: Maintain Quarantine
        appr_id = seed_approval("appr-budget-test-125")
        with patch("routes.approvals.db", self.db), \
             patch("routes.approvals.verify_workload_access", return_value=True):
            dec_req_maint = ApprovalDecisionRequest(
                decision=ApprovalStatus.REJECTED,
                action="MAINTAIN_QUARANTINE",
            )
            res_maint = appr_routes.decide_approval_request(appr_id, dec_req_maint, mock_req)
            self.assertEqual(res_maint.status, ApprovalStatus.REJECTED)

        # Action 4: Decommission Workload. Lane 18 S2 (probe P11): no longer a fabricated status flip -- a human ADMIN
        # approval is minted for exactly this workload's project and project-vending executes behind its guard.
        appr_id = seed_approval("appr-budget-test-126")
        self.db.collection("workloads").document("overrun-svc").set({"project_number": "123456789"}, merge=True)
        mock_req.state.auth_method = "session"
        guard_db = MagicMock(name="guard_db")

        class _Resp:
            status_code = 200
            text = ""

            def json(self):
                return {"status": "DECOMMISSIONED", "crm_operation": "operations/delete-123456789"}

        vending_calls = []

        def fake_vending(method, path, json_body=None, timeout=60.0, request=None):
            vending_calls.append((path, json_body))
            return _Resp()

        import destructive_actions
        with patch("routes.approvals.db", self.db), \
             patch("routes.approvals.verify_workload_access", return_value=True), \
             patch("routes.approvals.make_vending_request", fake_vending), \
             patch.object(destructive_actions, "get_guard_db", return_value=guard_db):
            dec_req_decom = ApprovalDecisionRequest(
                decision=ApprovalStatus.APPROVED,
                action="DECOMMISSION",
            )
            res_decom = appr_routes.decide_approval_request(appr_id, dec_req_decom, mock_req)
            self.assertEqual(res_decom.status, ApprovalStatus.APPROVED)
        record = guard_db.collection.return_value.document.return_value.create.call_args[0][0]
        self.assertEqual((record["action"], record["product_id"], record["project_id"], record["project_number"],
                          record["principal_type"], record["approved_by_role"]),
                         ("PROJECT_DECOMMISSION", "overrun-svc", "proj-overrun", "123456789", "USER", "ADMIN"))
        [(path, body)] = vending_calls
        self.assertEqual(path, "/projects/overrun-svc/decommission")
        self.assertEqual(body["action_class"], "PROJECT_DECOMMISSION")
        self.assertEqual(guard_db.collection.return_value.document.call_args[0][0], body["approval_id"])
        # the ledger status is vending's write; the CC no longer fabricates DECOMMISSIONED
        wl_decom = self.db.collection("workloads").document("overrun-svc").get().to_dict()
        self.assertNotEqual(wl_decom.get("status"), "DECOMMISSIONED")

    def test_pubsub_billing_alert_webhook(self):
        """Verifies Pub/Sub webhook decodes Base64 message and triggers quarantine on budget breach."""
        import routes.finops as finops_routes
        from routes.finops import PubSubAlertEnvelope, PubSubAlertMessage

        # Workload with $50 budget
        self.db.collection("workloads").document("cart-service").set({
            "status": "ACTIVE",
            "budget_ceiling_monthly_usd": 50.00,
            "budget_breach_policy": "AUTONOMOUS_SCALE_TO_ZERO",
            "project_id": "proj-cart-service",
        })

        # Pub/Sub notification for $55 spend
        billing_payload = {
            "budgetDisplayName": "budget-cart-service",
            "costAmount": 55.00,
            "budgetAmount": 50.00,
            "currencyCode": "USD",
        }
        b64_data = base64.b64encode(json.dumps(billing_payload).encode("utf-8")).decode("utf-8")

        envelope = PubSubAlertEnvelope(
            message=PubSubAlertMessage(
                data=b64_data,
                messageId="msg-12345",
                attributes={"billingAccountId": "01ABCD-234567-89EF01"},   # C10: install billing account check
            )
        )

        mock_enforcer = MagicMock()
        mock_enforcer.quarantine_workload.return_value = {"status": "QUARANTINED"}

        with patch("routes.finops.db", self.db), \
             patch.dict(os.environ, {"BILLING_ACCOUNT_ID": "billingAccounts/01ABCD-234567-89EF01"}), \
             patch("routes.approvals.get_finops_enforcer", return_value=mock_enforcer):
            res = finops_routes.billing_alert_webhook(envelope, MagicMock())
            self.assertEqual(res["status"], "QUARANTINE_EXECUTED")
            self.assertEqual(res["product_id"], "cart-service")
            mock_enforcer.quarantine_workload.assert_called_once()


if __name__ == "__main__":
    unittest.main()
