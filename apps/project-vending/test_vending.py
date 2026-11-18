"""
Unit Tests for project-repo-vending-service
Tests GCP project ID generation, Resource Manager creation, Billing attachment, and GitHub repo vending.
"""

from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import pytest

from main import app
from vending import ProjectRepoVendingEngine


@pytest.fixture
def mock_vending_engine():
    mock_db = MagicMock()
    mock_crm = MagicMock()
    mock_billing = MagicMock()
    mock_secret = MagicMock()
    mock_storage = MagicMock()

    # Mock Resource Manager create and delete
    mock_crm.projects().create().execute.return_value = {"name": "operations/create-123"}
    mock_crm.projects().delete().execute.return_value = {"name": "operations/delete-123"}
    mock_crm.operations().get().execute.return_value = {"name": "operations/create-123", "done": True}
    mock_crm.projects().getIamPolicy().execute.return_value = {"bindings": []}
    mock_crm.projects().setIamPolicy().execute.return_value = {"bindings": []}

    # Mock Billing update
    mock_billing.projects().updateBillingInfo().execute.return_value = {"billingEnabled": True}

    # Mock Storage state blob
    mock_blob = MagicMock()
    mock_blob.exists.return_value = True
    mock_storage.bucket().blob.return_value = mock_blob

    return ProjectRepoVendingEngine(
        platform_project_id="test-platform-proj",
        firestore_client=mock_db,
        secret_client=mock_secret,
        crm_service=mock_crm,
        billing_service=mock_billing,
        storage_client=mock_storage,
    )


def test_health_check():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_generate_project_id(mock_vending_engine):
    pid1 = mock_vending_engine.generate_project_id("Customer-Portal-API")
    assert pid1.startswith("castor-customer-portal-")
    assert len(pid1) <= 30
    assert pid1.islower()

    pid2 = mock_vending_engine.generate_project_id("Very_Long_Product_Name_That_Exceeds_Character_Limits")
    assert len(pid2) <= 30


def test_vend_gcp_project(mock_vending_engine):
    res = mock_vending_engine.vend_gcp_project(
        product_id="auth-service",
        trace_id="tr-vend-101",
        folder_id="1234567890",
        billing_account_id="00AA11-22BB33",
        initial_budget=50.0,
    )
    assert res["status"] == "PROJECT_VENDED"
    assert res["product_id"] == "auth-service"
    assert res["budget_ceiling_monthly_usd"] == 50.0
    assert res["project_id"].startswith("castor-auth-service-")
    assert res["auth_config"]["identity_platform_enabled"] is True
    assert res["auth_config"]["idp_provider"] == "google.com"


def test_fetch_oauth_credentials(mock_vending_engine):
    # Mock secret manager response
    mock_payload = MagicMock()
    mock_payload.payload.data.decode.return_value = "test-secret-value"
    mock_vending_engine.secret_client.access_secret_version.return_value = mock_payload

    creds = mock_vending_engine.fetch_oauth_credentials()
    assert creds["client_id"] == "test-secret-value"
    assert creds["client_secret"] == "test-secret-value"


def test_fetch_oauth_credentials_fails_closed(mock_vending_engine, monkeypatch):
    # Lane 19 L19-12: a Secret Manager error raises even when the old env fallback variables are set.
    monkeypatch.setenv("OAUTH_CLIENT_ID", "env-id")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "env-secret")
    mock_vending_engine.secret_client.access_secret_version.side_effect = RuntimeError("denied")
    with pytest.raises(RuntimeError):
        mock_vending_engine.fetch_oauth_credentials()


def test_vend_all_pipeline(mock_vending_engine):
    res = mock_vending_engine.vend_all(
        product_id="billing-service",
        trace_id="tr-vend-all-202",
        initial_budget=75.0,
    )
    assert res["status"] == "WORKLOAD_VENDED"
    assert res["product_id"] == "billing-service"
    assert res["budget_ceiling_monthly_usd"] == 75.0
    assert "gcp_project" in res
    assert "github_repo" in res


def test_rest_vend_all_endpoint():
    client = TestClient(app)
    payload = {
        "product_id": "analytics-dashboard",
        "initial_budget": 100.0,
    }
    response = client.post("/vend-all", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "WORKLOAD_VENDED"
    assert data["product_id"] == "analytics-dashboard"


def _configure_guard_env(monkeypatch):
    """Lane 18 S1 code RT Fix 4: configure the guard so the refusal under test is the one the test names (without
    these the guard refuses GUARD_UNCONFIGURED at check 1, before the check the test is about)."""
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", "4242")
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", "tagValues/1")
    monkeypatch.setenv("PROJECT_ID", "test-platform-proj")
    monkeypatch.delenv("PLATFORM_PROJECT_ID", raising=False)
    monkeypatch.delenv("STACKVEND_GUARD_FIRESTORE_DATABASE", raising=False)


def test_decommission_workload_requires_guard(mock_vending_engine, monkeypatch):
    """Lane 18 S1: an unprovenanced workload is refused (LEDGER_UNPROVENANCED) before any delete (was: deleted by
    id). Guarded behaviour is covered hermetically by tests/test_destructive_guard_*.py."""
    import destructive_guard as dg

    _configure_guard_env(monkeypatch)

    mock_doc = MagicMock()
    mock_doc.exists = True
    mock_doc.to_dict.return_value = {
        "product_id": "auth-service",
        "project_id": "castor-auth-service-507121",
        "status": "ACTIVE",
        "is_castor": False,
    }
    mock_vending_engine.db.collection().document().get.return_value = mock_doc
    deletes_before = mock_vending_engine.crm.projects().delete.call_count

    with pytest.raises(dg.DeletionRefused) as ei:
        mock_vending_engine.decommission_workload(
            product_id="auth-service",
            operator_email="admin@google.com",
        )
    assert ei.value.code == "LEDGER_UNPROVENANCED"
    assert mock_vending_engine.crm.projects().delete.call_count == deletes_before


def test_decommission_platform_guard_blocked(mock_vending_engine, monkeypatch):
    import destructive_guard as dg

    _configure_guard_env(monkeypatch)
    with pytest.raises(dg.DeletionRefused) as ei:
        mock_vending_engine.decommission_workload(
            product_id="project-castor",
            operator_email="admin@google.com",
        )
    assert ei.value.code == "PLATFORM_WORKLOAD"


def test_redeploy_workload_success(mock_vending_engine):
    # Mock Firestore doc in DECOMMISSIONED state
    mock_doc = MagicMock()
    mock_doc.exists = True
    mock_doc.to_dict.return_value = {
        "product_id": "payment-api",
        "project_id": "castor-payment-api-old",
        "status": "DECOMMISSIONED",
        "github_repo": "example-org/castor-payment-api",
        "budget_ceiling_monthly_usd": 60.0,
    }
    mock_vending_engine.db.collection().document().get.return_value = mock_doc

    res = mock_vending_engine.redeploy_workload(
        product_id="payment-api",
        operator_email="admin@google.com",
    )
    assert res["status"] == "ACTIVE"
    assert res["product_id"] == "payment-api"
    assert res["project_id"].startswith("castor-payment-api-")
    assert res["project_id"] != "castor-payment-api-old"
    assert res["service_url"].startswith("https://payment-api-castor-payment-api-")


def test_redeploy_non_decommissioned_blocked(mock_vending_engine):
    mock_doc = MagicMock()
    mock_doc.exists = True
    mock_doc.to_dict.return_value = {
        "product_id": "payment-api",
        "status": "ACTIVE",
    }
    mock_vending_engine.db.collection().document().get.return_value = mock_doc

    with pytest.raises(ValueError, match="Only DECOMMISSIONED workloads can be redeployed"):
        mock_vending_engine.redeploy_workload(
            product_id="payment-api",
            operator_email="admin@google.com",
        )


def test_rest_decommission_and_redeploy_endpoints(monkeypatch):
    client = TestClient(app)
    # 1. Decommission endpoint: lane 18 S1 requires an allow-listed Google ID token; with DESTRUCTIVE_CALLERS unset
    #    every call is 503 CALLERS_UNCONFIGURED before any read (S1 code RT Fix 4: pin the exact code).
    monkeypatch.delenv("DESTRUCTIVE_CALLERS", raising=False)
    dec_res = client.post("/projects/demo-service/decommission", json={"operator_email": "admin@castor.org"})
    assert dec_res.status_code == 503
    assert dec_res.json()["detail"]["code"] == "CALLERS_UNCONFIGURED"

    # 2. Platform workload via API: refused the same way, before any read
    castor_res = client.post("/projects/project-castor/decommission", json={"operator_email": "admin@castor.org"})
    assert castor_res.status_code == 503
    assert castor_res.json()["detail"]["code"] == "CALLERS_UNCONFIGURED"

    # 3. Redeploy endpoint
    red_res = client.post("/projects/demo-service/redeploy", json={"operator_email": "admin@castor.org"})
    assert red_res.status_code == 200
    assert red_res.json()["status"] == "ACTIVE"


def test_wait_for_crm_operation_success(mock_vending_engine):
    mock_crm = mock_vending_engine.crm
    mock_crm.operations().get().execute.side_effect = [
        {"name": "operations/test-op", "done": False},
        {"name": "operations/test-op", "done": True, "response": {"projectId": "test-proj"}},
    ]
    res = mock_vending_engine._wait_for_crm_operation("operations/test-op", max_wait_seconds=5)
    assert res["done"] is True
    assert res["response"]["projectId"] == "test-proj"


def test_wait_for_crm_operation_failure(mock_vending_engine):
    mock_crm = mock_vending_engine.crm
    mock_crm.operations().get().execute.return_value = {
        "name": "operations/test-op",
        "done": True,
        "error": {"code": 7, "message": "Permission denied on parent folder"},
    }
    with pytest.raises(RuntimeError, match="GCP Project creation operation failed"):
        mock_vending_engine._wait_for_crm_operation("operations/test-op", max_wait_seconds=5)


def test_wait_for_crm_operation_timeout(mock_vending_engine):
    mock_crm = mock_vending_engine.crm
    mock_crm.operations().get().execute.return_value = {
        "name": "operations/test-op",
        "done": False,
    }
    with pytest.raises(TimeoutError, match="timed out"):
        mock_vending_engine._wait_for_crm_operation("operations/test-op", max_wait_seconds=0.05)


def test_retry_api_call_eventual_consistency_recovery(mock_vending_engine):
    call_count = 0

    def flaky_api():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("404 Not Found: Project is currently initializing")
        return {"status": "SUCCESS"}

    res = mock_vending_engine._retry_api_call(flaky_api, max_attempts=3, delay=0.01, description="test API")
    assert res["status"] == "SUCCESS"
    assert call_count == 2


def test_vend_gcp_project_403_is_raised_as_googles_error(mock_vending_engine):
    """VENDING-PROJECT-QUOTA-TYPED: a 403 on create is no longer guessed to be a quota from its text (the typed quota
    stop is VENDING.PROJECT_QUOTA_EXCEEDED from the create operation; tests/test_vending_project_quota_typed.py)."""
    mock_resp = MagicMock()
    mock_resp.status = 403
    from googleapiclient.errors import HttpError
    error = HttpError(resp=mock_resp, content=b"The project creation quota has been reached for this account.")
    mock_vending_engine.crm.projects().create.return_value.execute.side_effect = error

    with pytest.raises(HttpError):
        mock_vending_engine.vend_gcp_project(
            product_id="quota-test",
            trace_id="tr-quota-123",
            folder_id="123456",
            billing_account_id="00AA11-22BB33",
        )


def test_get_platform_admin_members(mock_vending_engine, monkeypatch):
    # Lane 19 L19-12 (FD-4I I10/I11): exact ADMIN role only; env admins and creator fields grant nothing.
    monkeypatch.setenv("ADMIN_USER_EMAIL", "env-admin@example.com,secondary-admin@example.com")
    mock_doc1 = MagicMock()
    mock_doc1.id = "db-admin@example.com"
    mock_doc1.to_dict.return_value = {"email": "db-admin@example.com", "role": "ADMIN", "is_active": True}

    mock_doc2 = MagicMock()
    mock_doc2.id = "viewer@example.com"
    mock_doc2.to_dict.return_value = {"email": "viewer@example.com", "role": "NON_ADMIN", "is_active": True}

    mock_vending_engine.db.collection.return_value.stream.return_value = [mock_doc1, mock_doc2]

    members = mock_vending_engine.get_platform_admin_members()

    assert members == ["user:db-admin@example.com"]


def test_vend_gcp_project_binds_roles_viewer(mock_vending_engine, monkeypatch):
    # Lane 19 L19-12: the admin comes from authorized_users (exact ADMIN role), never from env.
    admin = MagicMock()
    admin.id = "lead-admin@example.com"
    admin.to_dict.return_value = {"email": "lead-admin@example.com", "role": "ADMIN", "is_active": True}
    mock_vending_engine.db.collection.return_value.stream.return_value = [admin]

    # Track setIamPolicy body
    saved_policies = []
    def record_set_iam(resource, body):
        saved_policies.append(body.get("policy", {}))
        m = MagicMock()
        m.execute.return_value = body.get("policy", {})
        return m

    mock_vending_engine.crm.projects().setIamPolicy = record_set_iam

    mock_vending_engine.vend_gcp_project(
        product_id="multi-admin-app",
        trace_id="tr-admin-456",
        folder_id="folders/123",
        billing_account_id="00AA11-22BB33",
    )

    assert len(saved_policies) > 0
    viewer_bindings = [b for b in saved_policies[0].get("bindings", []) if b.get("role") == "roles/viewer"]
    assert len(viewer_bindings) == 1
    assert "user:lead-admin@example.com" in viewer_bindings[0]["members"]




