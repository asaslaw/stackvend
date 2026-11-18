"""
Unit Tests for log-sre-sentinel-service
Tests stack trace normalization, fingerprinting, deduplication, RCA parsing, and API endpoints.
"""

import base64
import json
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import pytest

from main import app
from sentinel import LogSRESentinel


@pytest.fixture
def mock_sentinel():
    mock_db = MagicMock()
    mock_doc = MagicMock()
    mock_doc.exists = False
    mock_db.collection().document().get.return_value = mock_doc
    return LogSRESentinel(project_id="test-project", firestore_client=mock_db)


def test_health_check():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    # Without Firestore / REGION / host project number the sentinel reports itself degraded (lane 14 PR-2).
    assert response.json()["status"] in ("healthy", "degraded")


def test_compute_stack_fingerprint_normalization(mock_sentinel):
    trace1 = 'File "service.py", line 45, in foo at 0x7fff5fbff840\nKeyError: "doc_id"'
    trace2 = 'File "service.py", line 99, in foo at 0x7fff5fbff999\nKeyError: "doc_id"'

    fp1 = mock_sentinel.compute_stack_fingerprint(trace1, "workspace-service")
    fp2 = mock_sentinel.compute_stack_fingerprint(trace2, "workspace-service")

    # Both traces should normalize to the same deterministic hash
    assert fp1 == fp2


def test_perform_rca_mapping(mock_sentinel):
    stack = 'Traceback (most recent call last):\n  File "mcp-servers/workspace/service.py", line 84, in read_doc\nValueError: Invalid document ID'
    rca = mock_sentinel.perform_rca(stack, "Invalid document ID", "mcp-workspace-connector")

    assert rca["service_name"] == "mcp-workspace-connector"
    assert rca["affected_repository"] == "mcp-servers/workspace/"
    assert rca["exception_type"] == "ValueError"
    assert "Unhandled ValueError" in rca["root_cause_summary"]


def test_triage_endpoint():
    client = TestClient(app)
    payload = {
        "trace_id": "tr-sre-123",
        "incident_data": {
            "service_name": "mcp-workspace-connector",
            "stack_trace": 'File "service.py", line 12, in read_doc\nKeyError: "id"',
            "error_message": "Missing key id",
        },
    }
    response = client.post("/triage", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "TRIAGED"
    assert data["service_name"] == "mcp-workspace-connector"
    assert data["affected_repository"] == "mcp-servers/workspace/"


def test_log_sink_event_push_without_firestore_is_not_recorded():
    # Lane 14 PR-2: an incident that cannot be recorded answers 503 so Pub/Sub redelivers it. The full classification /
    # recording / dispatch contract is tested hermetically in tests/test_lane14_sentinel.py.
    import main as main_module

    main_module._sentinel = LogSRESentinel(project_id="test-project", firestore_client=None, env={})
    main_module._sentinel.db = None
    client = TestClient(app)
    raw_log = {
        "logName": "projects/test-project/logs/run.googleapis.com%2Fstderr",
        "resource": {"type": "cloud_run_revision", "labels": {"service_name": "auth-service", "project_id": "test-project"}},
        "jsonPayload": {"stack_trace": "ZeroDivisionError: division by zero"},
    }
    encoded = base64.b64encode(json.dumps(raw_log).encode("utf-8")).decode("utf-8")
    envelope = {"message": {"data": encoded}}

    response = client.post("/events/log-sink", json=envelope)
    main_module._sentinel = None
    assert response.status_code == 503
    assert response.json()["status"] == "NOT_RECORDED"
