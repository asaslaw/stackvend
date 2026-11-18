"""
Unit Tests for spec-ingestion-service
Tests poller logic, product ID extraction, Pub/Sub publishing, and FastAPI endpoints.
"""

from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import pytest

from main import app
from poller import SpecIngestionPoller


@pytest.fixture
def mock_poller():
    mock_drive = MagicMock()
    mock_publisher = MagicMock()
    mock_db = MagicMock()

    # Mock list inbox specs
    mock_drive.files().list().execute.return_value = {
        "files": [
            {
                "id": "doc-999",
                "name": "NEW_PRODUCT_SPEC: Billing Service (v2)",
                "mimeType": "application/vnd.google-apps.document",
                "webViewLink": "https://docs.google.com/document/d/doc-999/edit",
                # FD-4AS: only documents owned by an authorized submitter are ingested.
                "owners": [{"emailAddress": "lead@example.com", "me": False}],
            }
        ]
    }

    # Mock move file
    mock_drive.files().update().execute.return_value = {
        "id": "doc-999",
        "parents": ["folder-progress"],
    }

    # Mock pubsub publish future
    mock_future = MagicMock()
    mock_future.result.return_value = "msg-12345"
    mock_publisher.publish.return_value = mock_future
    mock_publisher.topic_path.return_value = "projects/test-project/topics/spec-intake-events"

    # Mock firestore
    mock_doc_ref = MagicMock()
    mock_db.collection().document.return_value = mock_doc_ref
    # FD-4AS: authorized_users/{owner} is an active Workload Manager; no managed folders yet (fresh install).
    user_snap = MagicMock()
    user_snap.exists = True
    user_snap.to_dict.return_value = {"role": "WORKLOAD_MANAGER", "is_active": True}
    mock_doc_ref.get.return_value = user_snap
    mock_db.collection().stream.return_value = []

    return SpecIngestionPoller(
        project_id="test-project",
        drive_service=mock_drive,
        publisher_client=mock_publisher,
        firestore_client=mock_db,
    )


def test_extract_product_id(mock_poller):
    assert mock_poller.extract_product_id("NEW_PRODUCT_SPEC: Customer Portal (v1)") == "customer-portal-v1"
    assert mock_poller.extract_product_id("FEATURE_ENHANCEMENT - Auth Service") == "auth-service"
    assert mock_poller.extract_product_id("INCIDENT_FIX: billing-db crash") == "billing-db-crash"
    assert mock_poller.extract_product_id("Simple Project") == "simple-project"


def test_poll_and_ingest(mock_poller):
    ingested = mock_poller.poll_and_ingest("folder-inbox", "folder-progress")
    assert len(ingested) == 1
    item = ingested[0]
    assert item["spec_doc_id"] == "doc-999"
    assert item["product_id"] == "billing-service-v2"
    assert item["source_channel"] == "google_docs"
    assert item["pubsub_message_id"] == "msg-12345"


def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_poll_endpoint_skipped_when_no_folders():
    client = TestClient(app)
    response = client.post("/poll", json={})
    assert response.status_code == 200
    assert response.json()["status"] in ["IDLE", "SKIPPED"]
