"""
Project Castor: Workspace MCP Service Connector
Handles Google Docs and Google Drive API interactions for multi-agent lifecycle operations.
"""

import io
import logging
import string
from typing import Any, Dict, List, Optional
import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload

logger = logging.getLogger("mcp-workspace-connector")
logging.basicConfig(level=logging.INFO)

SCOPES = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/documents",
]

# FD-4AG-b (AG-7, FD27-16): a Drive file / folder ID is letters, digits, '-' and '_'. Exact allow-list: anything else
# is refused BEFORE it is placed in a Drive `q` string, so input can never rewrite the query.
DRIVE_ID_CHARS = frozenset(string.ascii_letters + string.digits + "-_")
DRIVE_ID_MAX_LEN = 128


class InvalidDriveIdError(ValueError):
    """A Drive ID that is empty, too long or contains a character outside DRIVE_ID_CHARS (HTTP 422)."""


def validate_drive_id(value: Any, field: str = "folder_id") -> str:
    """Returns `value` unchanged when it is a valid Drive ID, else raises InvalidDriveIdError."""
    if not isinstance(value, str) or not value:
        raise InvalidDriveIdError(f"{field} must be a non-empty Drive ID")
    if len(value) > DRIVE_ID_MAX_LEN:
        raise InvalidDriveIdError(f"{field} is longer than {DRIVE_ID_MAX_LEN} characters")
    if not set(value) <= DRIVE_ID_CHARS:
        raise InvalidDriveIdError(f"{field} may contain only letters, digits, '-' and '_'")
    return value


# SAT-51 (owner 11-03 live, project-vending: two concurrent requests both died with "OSError: [Errno 9] Bad file
# descriptor"). The module-global service (main.py) is shared by every request thread, and a discovery client built with
# credentials= holds ONE httplib2.Http, which is not thread-safe. Per the google-api-python-client thread-safety
# guidance the client stays shared but every request gets its own authorized httplib2 connection.
def _build_thread_safe(service: str, version: str, credentials):
    import google_auth_httplib2
    from googleapiclient.http import HttpRequest, build_http

    def request_builder(_http, *args, **kwargs):
        return HttpRequest(google_auth_httplib2.AuthorizedHttp(credentials, http=build_http()), *args, **kwargs)

    return build(service, version, http=google_auth_httplib2.AuthorizedHttp(credentials, http=build_http()),
                 requestBuilder=request_builder, cache_discovery=False)


class WorkspaceService:
    def __init__(self, drive_service: Optional[Any] = None, docs_service: Optional[Any] = None):
        if drive_service and docs_service:
            self.drive_service = drive_service
            self.docs_service = docs_service
        else:
            try:
                credentials, _ = google.auth.default(scopes=SCOPES)
                self.drive_service = _build_thread_safe("drive", "v3", credentials)   # SAT-51
                self.docs_service = _build_thread_safe("docs", "v1", credentials)   # SAT-51
            except Exception as e:
                logger.warning(f"Could not load default GCP credentials: {e}. Running in unauthenticated mode.")
                self.drive_service = None
                self.docs_service = None

    def list_folder_files(self, folder_id: str) -> List[Dict[str, Any]]:
        """Lists active files in a specific Google Drive folder."""
        folder_id = validate_drive_id(folder_id, "folder_id")
        if not self.drive_service:
            raise RuntimeError("Google Drive client is not initialized")

        query = f"'{folder_id}' in parents and trashed = false"
        try:
            results = (
                self.drive_service.files()
                .list(
                    q=query,
                    fields="files(id, name, mimeType, modifiedTime, createdTime, webViewLink)",
                    pageSize=100,
                )
                .execute()
            )
            return results.get("files", [])
        except HttpError as e:
            logger.error(f"Failed to list files in folder {folder_id}: {e}")
            raise

    def read_doc_content(self, doc_id: str) -> Dict[str, Any]:
        """Fetches and extracts structured text content from a Google Doc."""
        if not self.docs_service:
            raise RuntimeError("Google Docs client is not initialized")

        try:
            doc = self.docs_service.documents().get(documentId=doc_id).execute()
            title = doc.get("title", "")
            body = doc.get("body", {}).get("content", [])

            extracted_text = []
            for element in body:
                if "paragraph" in element:
                    elements = element.get("paragraph", {}).get("elements", [])
                    for elem in elements:
                        text_run = elem.get("textRun", {})
                        if "content" in text_run:
                            extracted_text.append(text_run.get("content", ""))
                elif "table" in element:
                    table = element.get("table", {})
                    for row in table.get("tableRows", []):
                        row_text = []
                        for cell in row.get("tableCells", []):
                            cell_content = []
                            for c_elem in cell.get("content", []):
                                if "paragraph" in c_elem:
                                    for elem in c_elem.get("paragraph", {}).get("elements", []):
                                        cell_content.append(elem.get("textRun", {}).get("content", "").strip())
                            row_text.append(" ".join(cell_content))
                        extracted_text.append(" | ".join(row_text) + "\n")

            full_text = "".join(extracted_text)
            return {
                "document_id": doc_id,
                "title": title,
                "full_text": full_text,
                "revision_id": doc.get("revisionId", ""),
            }
        except HttpError as e:
            logger.error(f"Failed to read document {doc_id}: {e}")
            raise

    def move_file_folder(self, file_id: str, source_folder_id: str, target_folder_id: str) -> Dict[str, Any]:
        """Moves a file from a source folder to a target folder in Google Drive."""
        if not self.drive_service:
            raise RuntimeError("Google Drive client is not initialized")

        try:
            file_meta = (
                self.drive_service.files()
                .update(
                    fileId=file_id,
                    addParents=target_folder_id,
                    removeParents=source_folder_id,
                    fields="id, name, parents",
                )
                .execute()
            )
            return {
                "file_id": file_meta.get("id"),
                "name": file_meta.get("name"),
                "new_parents": file_meta.get("parents"),
                "status": "MOVED",
            }
        except HttpError as e:
            logger.error(f"Failed to move file {file_id}: {e}")
            raise

    def append_text_to_doc(self, doc_id: str, text_to_append: str) -> Dict[str, Any]:
        """Appends status text or task checklists to the end of a Google Doc."""
        if not self.docs_service:
            raise RuntimeError("Google Docs client is not initialized")

        try:
            doc = self.docs_service.documents().get(documentId=doc_id).execute()
            content = doc.get("body", {}).get("content", [])
            end_index = 1
            if content:
                end_index = content[-1].get("endIndex", 1)

            insert_index = max(1, end_index - 1)
            requests = [
                {
                    "insertText": {
                        "location": {"index": insert_index},
                        "text": f"\n\n{text_to_append}\n",
                    }
                }
            ]

            self.docs_service.documents().batchUpdate(
                documentId=doc_id, body={"requests": requests}
            ).execute()

            return {
                "document_id": doc_id,
                "status": "APPENDED",
                "insert_index": insert_index,
            }
        except HttpError as e:
            logger.error(f"Failed to append text to document {doc_id}: {e}")
            raise

    def insert_approval_callout(self, doc_id: str, cost_delta: str, risk_assessment: str) -> Dict[str, Any]:
        """Inserts a structured Tier 3 Approval Callout Box at the top of the Google Doc."""
        if not self.docs_service:
            raise RuntimeError("Google Docs client is not initialized")

        callout_text = (
            "================================================================================\n"
            "⚠️ TIER 3 HUMAN-IN-THE-LOOP APPROVAL REQUIRED\n"
            "--------------------------------------------------------------------------------\n"
            f"• Estimated Cost Impact: {cost_delta}\n"
            f"• Risk Assessment: {risk_assessment}\n"
            "• Action: Please resolve this approval box or comment 'APPROVED' to resume execution.\n"
            "================================================================================\n\n"
        )

        try:
            requests = [
                {
                    "insertText": {
                        "location": {"index": 1},
                        "text": callout_text,
                    }
                }
            ]

            self.docs_service.documents().batchUpdate(
                documentId=doc_id, body={"requests": requests}
            ).execute()

            return {
                "document_id": doc_id,
                "status": "APPROVAL_REQUESTED",
            }
        except HttpError as e:
            logger.error(f"Failed to insert approval callout in document {doc_id}: {e}")
            raise

    def clone_template_doc(
        self, template_id: str, target_folder_id: str, new_title: str, replacements: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Clones a template from 00_Templates into a target folder and populates fields."""
        if not self.drive_service or not self.docs_service:
            raise RuntimeError("Google API clients are not initialized")

        try:
            copied_file = (
                self.drive_service.files()
                .copy(
                    fileId=template_id,
                    body={"name": new_title, "parents": [target_folder_id]},
                    fields="id, name, webViewLink",
                    supportsAllDrives=True,  # FD-4BM: the template / folder may live in a shared drive
                )
                .execute()
            )
            cloned_id = copied_file.get("id")
            if not isinstance(cloned_id, str) or not cloned_id:
                raise RuntimeError("Drive files.copy returned no document id")

            if replacements:
                requests = []
                for key, val in replacements.items():
                    requests.append(
                        {
                            "replaceAllText": {
                                "containsText": {"text": f"{{{{{key}}}}}", "matchCase": True},
                                "replaceText": str(val),
                            }
                        }
                    )
                if requests:
                    self.docs_service.documents().batchUpdate(
                        documentId=cloned_id, body={"requests": requests}
                    ).execute()

            return {
                "document_id": cloned_id,
                "title": copied_file.get("name"),
                "web_view_link": copied_file.get("webViewLink"),
                "status": "CREATED",
            }
        except HttpError as e:
            logger.error(f"Failed to clone template {template_id}: {e}")
            raise

    def create_doc_from_html(self, folder_id: str, title: str, html_text: str) -> Dict[str, Any]:
        """FD-4BM: creates a Google Doc named ``title`` inside ``folder_id`` from an HTML body, in ONE Drive call
        (``files.create`` with a text/html upload converted to a Google Doc). The document either exists with
        its full content or was not created. It is created in the folder, so it is shared as the folder is; no
        permission is added. Works in shared drives (``supportsAllDrives``). Raises on any failure, including a
        response without a document id (never returns an id Drive did not give)."""
        folder_id = validate_drive_id(folder_id, "folder_id")
        if not self.drive_service:
            raise RuntimeError("Google Drive client is not initialized")
        media = MediaIoBaseUpload(io.BytesIO(html_text.encode("utf-8")), mimetype="text/html", resumable=False)
        created = (
            self.drive_service.files()
            .create(
                body={"name": title, "parents": [folder_id], "mimeType": "application/vnd.google-apps.document"},
                media_body=media,
                fields="id, name, webViewLink",
                supportsAllDrives=True,
            )
            .execute()
        )
        doc_id = (created or {}).get("id")
        if not isinstance(doc_id, str) or not doc_id:
            raise RuntimeError("Drive files.create returned no document id")
        return {
            "document_id": doc_id,
            "title": created.get("name") or title,
            "web_view_link": created.get("webViewLink"),
            "status": "CREATED",
        }
