"""
Unit Tests for orchestrator-gateway-service
Tests agent dispatch endpoints, Pub/Sub message handling, and health routes.
"""

import base64
import json
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
import pytest

from main import app


def test_health_check():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_architect_decompose_endpoint():
    client = TestClient(app)
    payload = {
        "trace_id": "test-trace-123",
        "product_id": "test-product",
        "spec_text": "Build a simple microservice on Cloud Run.",
        "source_channel": "google_docs",
    }
    response = client.post("/agent/architect/decompose", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["product_id"] == "test-product"
    assert len(data["task_dag"]) >= 1


def test_developer_execute_endpoint():
    client = TestClient(app)
    payload = {
        "trace_id": "trace-dev-456",
        "product_id": "auth-service",
        "task_dag": [{"task_id": "CODE-01", "title": "Create login"}],
        "retry_count": 0,
    }
    response = client.post("/agent/developer/execute", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert "feature/auth-service" in data["branch_name"]


def test_qa_verify_endpoint():
    client = TestClient(app)
    payload = {
        "trace_id": "trace-qa-789",
        "product_id": "auth-service",
        "branch_name": "feature/auth-service-123",
    }
    with patch("main.qa_runner") as mock_runner:
        mock_runner.execute_full_qa_pipeline.return_value = {
            "passed": True,
            "summary": "QA Verification Succeeded: 5 passed, 0 failed.",
            "tests_passed": 5,
            "tests_failed": 0,
        }
        response = client.post("/agent/qa/verify", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["passed"] is True
        assert data["status"] == "SUCCESS"


def test_qa_verify_endpoint_failure():
    client = TestClient(app)
    payload = {
        "trace_id": "trace-qa-fail",
        "product_id": "auth-service",
        "branch_name": "feature/auth-service-fail",
    }
    with patch("main.qa_runner") as mock_runner:
        mock_runner.execute_full_qa_pipeline.return_value = {
            "passed": False,
            "summary": "QA Verification Failed: 2 tests failed.",
            "tests_passed": 3,
            "tests_failed": 2,
        }
        response = client.post("/agent/qa/verify", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["passed"] is False
        assert data["status"] == "FAILED"


def test_qa_verify_async_endpoint():
    client = TestClient(app)
    payload = {
        "trace_id": "trace-qa-async-1",
        "product_id": "auth-service",
        "branch_name": "feature/auth-service-123",
        "callback_url": "https://workflowexecutions.googleapis.com/v1/callbacks/123",
    }
    response = client.post("/agent/qa/verify-async", json=payload)
    assert response.status_code == 202
    assert response.json()["status"] == "ACCEPTED"


def test_release_promote_endpoint():
    client = TestClient(app)
    payload = {
        "trace_id": "trace-rel-101",
        "spec_doc_id": "doc-555",
        "product_id": "auth-service",
        "branch_name": "feature/auth-service-123",
        "test_summary": "All tests passed",
    }
    response = client.post("/agent/release/promote", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert "pull_request_url" in data


def test_pubsub_intake_push():
    client = TestClient(app)
    intake_data = {"spec_doc_id": "doc-999", "product_id": "billing-app"}
    encoded = base64.b64encode(json.dumps(intake_data).encode("utf-8")).decode("utf-8")

    envelope = {
        "message": {
            "data": encoded,
            "messageId": "msg-001",
        }
    }
    response = client.post("/events/pubsub-intake", json=envelope)
    assert response.status_code == 200
    assert response.json()["status"] in ["RECEIVED", "DISPATCHED"]
