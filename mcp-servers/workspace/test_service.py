"""
Unit Tests for mcp-workspace-connector
Tests Google Docs/Drive service methods and MCP API endpoints using mocks.
"""

from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import pytest

from main import app
from service import WorkspaceService


@pytest.fixture
def mock_workspace_service():
    mock_drive = MagicMock()
    mock_docs = MagicMock()

    # Mock list files
    mock_drive.files().list().execute.return_value = {
        "files": [
            {
                "id": "doc-123",
                "name": "NEW_PRODUCT_SPEC_Frontend",
                "mimeType": "application/vnd.google-apps.document",
            }
        ]
    }

    # Mock get doc content
    mock_docs.documents().get().execute.return_value = {
        "title": "Castor Frontend Spec",
        "revisionId": "rev-1",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [{"textRun": {"content": "Build specification for Castor Web Portal."}}]
                    }
                }
            ]
        },
    }

    # Mock move file
    mock_drive.files().update().execute.return_value = {
        "id": "doc-123",
        "name": "NEW_PRODUCT_SPEC_Frontend",
        "parents": ["folder-progress"],
    }

    # Mock batchUpdate
    mock_docs.documents().batchUpdate().execute.return_value = {"replies": []}

    # Mock copy template
    mock_drive.files().copy().execute.return_value = {
        "id": "cloned-doc-456",
        "name": "INCIDENT-FIX: auth-service",
        "webViewLink": "https://docs.google.com/document/d/cloned-doc-456/edit",
    }

    return WorkspaceService(drive_service=mock_drive, docs_service=mock_docs)


def test_health_check():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_list_folder_files(mock_workspace_service):
    files = mock_workspace_service.list_folder_files("folder-inbox")
    assert len(files) == 1
    assert files[0]["id"] == "doc-123"
    assert files[0]["name"] == "NEW_PRODUCT_SPEC_Frontend"


def test_read_doc_content(mock_workspace_service):
    result = mock_workspace_service.read_doc_content("doc-123")
    assert result["document_id"] == "doc-123"
    assert result["title"] == "Castor Frontend Spec"
    assert "Build specification for Castor Web Portal." in result["full_text"]


def test_move_file_folder(mock_workspace_service):
    result = mock_workspace_service.move_file_folder("doc-123", "folder-inbox", "folder-progress")
    assert result["status"] == "MOVED"
    assert result["new_parents"] == ["folder-progress"]


def test_append_text_to_doc(mock_workspace_service):
    result = mock_workspace_service.append_text_to_doc("doc-123", "### Task Checklist\n- [x] Provision Cloud Run")
    assert result["status"] == "APPENDED"


def test_insert_approval_callout(mock_workspace_service):
    result = mock_workspace_service.insert_approval_callout("doc-123", "+$45.00/mo", "Destructive Cloud SQL change")
    assert result["status"] == "APPROVAL_REQUESTED"


def test_mcp_tools_list():
    client = TestClient(app)
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 200
    tools = response.json()["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "read_specification_doc" in tool_names
    assert "move_document_folder" in tool_names
    assert "request_human_approval" in tool_names
