"""
Unit Tests for infra-rollback-job
Tests GCS state version discovery, snapshot reversion, Firestore audit logging, and API endpoints.
"""

from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import pytest

from main import app
from rollback import InfraRollbackEngine


@pytest.fixture
def mock_rollback_engine():
    mock_db = MagicMock()
    mock_storage = MagicMock()
    mock_bucket = MagicMock()

    # Mock GCS versioned blobs
    mock_blob_v1 = MagicMock()
    mock_blob_v1.name = "workloads/auth-service/default.tfstate"
    mock_blob_v1.generation = 100001
    mock_blob_v1.updated.isoformat.return_value = "2026-08-30T10:00:00Z"
    mock_blob_v1.size = 2048
    mock_blob_v1.etag = "etag-v1"
    mock_blob_v1.time_deleted = "2026-08-31T10:00:00Z"  # noncurrent version

    mock_blob_v2 = MagicMock()
    mock_blob_v2.name = "workloads/auth-service/default.tfstate"
    mock_blob_v2.generation = 100002
    mock_blob_v2.updated.isoformat.return_value = "2026-08-31T10:00:00Z"
    mock_blob_v2.size = 2100
    mock_blob_v2.etag = "etag-v2"
    mock_blob_v2.time_deleted = None  # live object

    mock_bucket.list_blobs.return_value = [mock_blob_v1, mock_blob_v2]
    # FD-4AV-b: the copy creates a new live generation, which the post-copy re-check reads back.
    mock_blob_v3 = MagicMock()
    mock_blob_v3.name = "workloads/auth-service/default.tfstate"
    mock_blob_v3.generation = 100003
    mock_bucket.copy_blob.return_value = mock_blob_v3
    # FD-4AV-a: the state lock object (default.tflock) is absent; a lookup by generation returns the old generation,
    # a lookup without one returns the live object (the copy).
    mock_bucket.get_blob.side_effect = lambda name, generation=None: (
        None if name.endswith(".tflock") else (mock_blob_v1 if generation is not None else mock_blob_v3))
    mock_bucket.versioning_enabled = True  # FD-4AV-a RT F1: restores need a versioned state bucket
    mock_storage.bucket.return_value = mock_bucket

    return InfraRollbackEngine(
        project_id="test-platform-proj",
        state_bucket_name="castor-tfstate-test",
        firestore_client=mock_db,
        storage_client=mock_storage,
    )


def test_health_check():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_get_state_history(mock_rollback_engine):
    versions = mock_rollback_engine.get_state_history("auth-service")
    assert len(versions) == 2
    # Latest generation first
    assert versions[0]["generation"] == "100002"
    assert versions[1]["generation"] == "100001"


def test_revert_state_to_generation(mock_rollback_engine):
    res = mock_rollback_engine.revert_state_to_generation("auth-service", "100001")
    assert res["status"] == "REVERTED"
    assert res["restored_generation"] == "100001"
    assert res["product_id"] == "auth-service"


def test_execute_rollback(mock_rollback_engine):
    res = mock_rollback_engine.execute_rollback(
        product_id="auth-service",
        trace_id="tr-rb-999",
        reason="Midway failure during apply",
    )
    assert res["status"] == "REVERTED"
    assert res["product_id"] == "auth-service"
    assert res["target_generation"] == "100001"


def test_rest_rollback_endpoint():
    # FD-4AV-a: the module engine has no GCS client in tests, so the honest answer is 503 ROLLBACK_UNAVAILABLE
    # (formerly a fabricated 200 ROLLBACK_SUCCESS).
    client = TestClient(app)
    payload = {
        "product_id": "payment-api",
        "reason": "Container startup timeout",
    }
    response = client.post("/rollback", json=payload)
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "ROLLBACK_UNAVAILABLE"
    assert data["product_id"] == "payment-api"
