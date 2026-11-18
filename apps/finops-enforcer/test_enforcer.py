"""
Unit Tests for finops-budget-enforcer-job
Tests auto-kill scale-to-zero enforcement, workload restoration, and API endpoints.
"""

from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import pytest

from enforcer import FinopsBudgetEnforcer
from main import app


@pytest.fixture
def mock_enforcer():
    mock_db = MagicMock()
    mock_run = MagicMock()

    # Mock list services
    mock_run.projects().locations().services().list().execute.return_value = {
        "services": [
            {"name": "projects/test-proj/locations/us-central1/services/customer-api"},
            {"name": "projects/test-proj/locations/us-central1/services/customer-worker"},
        ]
    }
    # Mock patch
    mock_run.projects().locations().services().patch().execute.return_value = {}

    return FinopsBudgetEnforcer(
        project_id="test-platform-proj",
        region="us-central1",
        firestore_client=mock_db,
        run_service=mock_run,
    )


def test_health_check():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_quarantine_workload(mock_enforcer):
    res = mock_enforcer.quarantine_workload(
        product_id="auth-service",
        target_project_id="castor-auth-123",
        trace_id="tr-kill-101",
        spend_amount=45.0,
        budget_amount=40.0,
    )
    assert res["status"] == "QUARANTINED"
    assert res["product_id"] == "auth-service"
    assert res["action"] == "AUTO_KILL_SCALE_TO_ZERO"
    assert res["scaled_services_count"] == 2


def test_restore_workload(mock_enforcer):
    res = mock_enforcer.restore_workload(
        product_id="auth-service",
        target_project_id="castor-auth-123",
        max_instances=5,
    )
    assert res["status"] == "RESTORED"
    assert res["product_id"] == "auth-service"
    assert len(res["restored_services"]) == 2


def test_rest_enforce_endpoint():
    client = TestClient(app)
    payload = {
        "product_id": "billing-api",
        "spend_amount": 55.0,
        "budget_amount": 50.0,
    }
    response = client.post("/enforce", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "QUARANTINED"
    assert data["product_id"] == "billing-api"
