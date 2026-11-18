"""
Unit tests for sre-telemetry-digest-job (lane 14 PR-3: real telemetry only).
The full contract is tested hermetically in tests/test_lane14_sre_digest.py; these are local smoke tests with injected
readers. Per AGENTS.md (incident FD-08) this file is not run by the agents' test commands.
"""

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

import main as main_module
from digest import SRETelemetryDigest, latency_verdict


def _engine():
    db = MagicMock()
    db.collection.return_value.where.return_value.stream.return_value = []  # no ACTIVE workloads
    return SRETelemetryDigest(
        project_id="test-project", firestore_client=db, env={"PROJECT_ID": "test-project", "REGION": "us-central1"},
        log_reader=lambda *a: ([], False), latency_reader=lambda *a: {})


def test_health_check():
    main_module._engine = _engine()
    try:
        response = TestClient(main_module.app).get("/health")
    finally:
        main_module._engine = None
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_cluster_warning_logs():
    sample = [
        {"service_name": "auth-api", "message": "Failed auth for user 12345: timeout"},
        {"service_name": "auth-api", "message": "Failed auth for user 67890: timeout"},
        {"service_name": "payment-api", "message": "Stripe slow response 450ms"},
    ]
    clusters = _engine().cluster_warning_logs(sample)
    assert len(clusters) == 2
    auth_cluster = [c for c in clusters if c["service_name"] == "auth-api"][0]
    assert auth_cluster["count"] == 2
    assert "<NUM>" in auth_cluster["pattern"]


def test_latency_verdict():
    v = latency_verdict({"p95_ms": 160.0, "samples": 100}, {"p95_ms": 100.0, "samples": 100}, 50, 1.2, 1.5)
    assert v["status"] == "REGRESSION" and v["severity"] == "HIGH"
    assert latency_verdict({"p95_ms": 160.0, "samples": 3}, {"p95_ms": 100.0, "samples": 3}, 50, 1.2, 1.5)["status"] \
        == "NO_BASELINE"


def test_generate_digest_report_without_data_is_no_data():
    report = _engine().generate_digest_report()
    assert report["system_status"] == "NO_DATA"
    assert report["overall_health_score"] is None
    assert report["exit_code"] == 0
