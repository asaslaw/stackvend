"""
Unit tests for sandbox-garbage-collector-job (lane 14 PR-6 ledger contract).
The full contract is tested hermetically in tests/test_lane14_sandbox_cleaner.py; these are local smoke tests.
Per AGENTS.md (incident FD-08) this file is not run by the agents' test commands.
"""

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

import main as main_module
from cleaner import SandboxGarbageCollector


def _collector(env):
    db = MagicMock()
    db.collection.return_value.where.return_value.stream.return_value = []  # empty ledger
    return SandboxGarbageCollector(
        env=env, firestore_client=db,
        service_url_resolver=lambda *a: None, id_token_fetcher=lambda aud: "", http_post=lambda *a, **k: (500, None))


def test_health_check():
    main_module._collector = _collector({"PROJECT_ID": "test-platform-proj", "REGION": "us-central1"})
    try:
        response = TestClient(main_module.app).get("/health")
    finally:
        main_module._collector = None
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["batch_cap"] == 10


def test_empty_ledger_run_exits_zero():
    report = _collector({"PROJECT_ID": "test-platform-proj", "REGION": "us-central1"}).execute_cleanup()
    assert report["status"] == "COMPLETED"
    assert report["exit_code"] == 0
    assert report["requests"] == []


def test_rest_clean_endpoint():
    main_module._collector = _collector({"PROJECT_ID": "test-platform-proj", "REGION": "us-central1"})
    try:
        response = TestClient(main_module.app).post("/clean", json={"dry_run": True})
    finally:
        main_module._collector = None
    assert response.status_code == 200
    assert response.json()["dry_run"] is True
