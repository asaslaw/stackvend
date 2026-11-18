"""
Unit Tests for github-refactor-scanner-job
Tests AST code smell parsing, missing test detection, and scan report aggregation.
"""

from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import pytest

from main import app
from scanner import RefactorScanner


@pytest.fixture
def mock_scanner():
    mock_db = MagicMock()
    mock_pub = MagicMock()
    mock_future = MagicMock()
    mock_future.result.return_value = "msg-refactor-123"
    mock_pub.publish.return_value = mock_future
    mock_pub.topic_path.return_value = "projects/test-project/topics/autonomous-refactor-events"

    return RefactorScanner(
        project_id="test-project",
        firestore_client=mock_db,
        publisher_client=mock_pub,
    )


def test_health_check():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_scan_python_ast_bare_except(mock_scanner, tmp_path):
    code_file = tmp_path / "bad_code.py"
    code_file.write_text("""
def divide_numbers(a, b):
    try:
        return a / b
    except:
        return 0
""")
    findings = mock_scanner.scan_python_ast(str(code_file))
    assert len(findings) == 1
    assert findings[0]["rule"] == "no-bare-except"
    assert findings[0]["category"] == "CODE_SMELL"
    assert findings[0]["severity"] == "MEDIUM"


def test_scan_test_gaps(mock_scanner, tmp_path):
    apps_dir = tmp_path / "apps"
    service_a = apps_dir / "service_a"
    service_a.mkdir(parents=True)
    (service_a / "main.py").write_text("print('hello')")
    # Service A is missing test_main.py

    findings = mock_scanner.scan_test_gaps(str(tmp_path))
    assert len(findings) == 1
    assert findings[0]["category"] == "TEST_GAP"
    assert findings[0]["service"] == "service_a"
    assert findings[0]["severity"] == "HIGH"


def test_scan_tree_clean(tmp_path):
    # Lane 14 PR-4: scan_tree runs the three passes over an extracted repo; Bandit is injected here.
    scanner = RefactorScanner(project_id="test-project", firestore_client=MagicMock(), publisher_client=MagicMock(),
                              env={}, bandit_runner=lambda argv: MagicMock(stdout='{"results": []}', returncode=0))
    apps_dir = tmp_path / "apps" / "clean_service"
    apps_dir.mkdir(parents=True)
    (apps_dir / "main.py").write_text("def hello(): return 'world'")
    (apps_dir / "test_main.py").write_text("def test_hello(): pass")

    assert scanner.scan_tree(str(tmp_path)) == []
