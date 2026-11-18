"""
Project Castor: Workspace MCP Tool Server
Exposes JSON-RPC 2.0 MCP tools and REST endpoints for Google Docs & Drive management.
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import logging
import os
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import incident_doc
from service import InvalidDriveIdError, WorkspaceService

# Same logger name as service.py (`logging.getLogger("mcp-workspace-connector")`); service.py configures the level.
logger = logging.getLogger("mcp-workspace-connector")

app = FastAPI(
    title="StackVend Workspace MCP Server",
    description="Model Context Protocol server for Google Docs & Drive lifecycle operations",
    version="1.0.0",
)

service = WorkspaceService()


# ------------------------------------------------------------------------------
# Pydantic Request Models
# ------------------------------------------------------------------------------
class ReadDocRequest(BaseModel):
    document_id: str


class ListFolderRequest(BaseModel):
    folder_id: str


class MoveDocRequest(BaseModel):
    file_id: str
    source_folder_id: str
    target_folder_id: str


class AppendStatusRequest(BaseModel):
    document_id: str
    status_text: str


class RequestApprovalRequest(BaseModel):
    trace_id: Optional[str] = None
    spec_doc_id: str
    cost_delta_monthly: str
    risk_assessment: str
    # AG-7 (bundle RT F4): the id of the approval record the workflow's pre-build gate already wrote. When set, the
    # gateway owns the approval and this route only notifies (Doc callout, no Firestore write: one approval card).
    approval_id: Optional[str] = None


class CreateIncidentSpecRequest(BaseModel):
    # Body sent by workflows/sre_remediation.yaml create_incident_ticket (product_id included since lane 14 PR-2).
    trace_id: Optional[str] = None
    incident_id: str
    product_id: Optional[str] = None
    severity: Optional[str] = ""
    service_name: Optional[str] = ""
    stack_trace: Optional[str] = ""
    root_cause_summary: Optional[str] = ""
    affected_repository: Optional[str] = ""
    # Optional target folder named by the caller; else IN_PROGRESS_FOLDER_ID (FD-4BM, incident_doc.resolve_target).
    inbox_folder_id: Optional[str] = None


class TemplateCloneRequest(BaseModel):
    template_id: str
    target_folder_id: str
    title: str
    replacements: Optional[Dict[str, Any]] = None


# MCP JSON-RPC Models
class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    method: str
    params: Optional[Dict[str, Any]] = Field(default_factory=dict)


# ------------------------------------------------------------------------------
# Health & Status
# ------------------------------------------------------------------------------
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "mcp-workspace-connector",
        "environment": os.getenv("ENVIRONMENT", "prod"),
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


# ------------------------------------------------------------------------------
# MCP Protocol Endpoint (JSON-RPC 2.0)
# ------------------------------------------------------------------------------
@app.post("/mcp")
def handle_mcp_rpc(request: JsonRpcRequest):
    method = request.method
    params = request.params or {}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request.id,
            "result": {
                "tools": [
                    {
                        "name": "read_specification_doc",
                        "description": "Reads and extracts structured requirements from a Google Doc specification.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"document_id": {"type": "string"}},
                            "required": ["document_id"],
                        },
                    },
                    {
                        "name": "list_folder_files",
                        "description": "Lists all active files within a Google Drive Kanban folder.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"folder_id": {"type": "string"}},
                            "required": ["folder_id"],
                        },
                    },
                    {
                        "name": "move_document_folder",
                        "description": "Moves a specification document between Drive status folders (e.g. Inbox -> In_Progress -> Completed).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "file_id": {"type": "string"},
                                "source_folder_id": {"type": "string"},
                                "target_folder_id": {"type": "string"},
                            },
                            "required": ["file_id", "source_folder_id", "target_folder_id"],
                        },
                    },
                    {
                        "name": "append_execution_status",
                        "description": "Appends task checklist, test outputs, or live URLs to the end of a Google Doc.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "document_id": {"type": "string"},
                                "status_text": {"type": "string"},
                            },
                            "required": ["document_id", "status_text"],
                        },
                    },
                    {
                        "name": "request_human_approval",
                        "description": "Pre-pends a Tier 3 HITL Approval Callout Box to the top of a Google Doc.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "spec_doc_id": {"type": "string"},
                                "cost_delta_monthly": {"type": "string"},
                                "risk_assessment": {"type": "string"},
                            },
                            "required": ["spec_doc_id", "cost_delta_monthly", "risk_assessment"],
                        },
                    },
                ]
            },
        }

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        try:
            if tool_name == "read_specification_doc":
                result = service.read_doc_content(arguments["document_id"])
            elif tool_name == "list_folder_files":
                result = service.list_folder_files(arguments["folder_id"])
            elif tool_name == "move_document_folder":
                result = service.move_file_folder(
                    arguments["file_id"], arguments["source_folder_id"], arguments["target_folder_id"]
                )
            elif tool_name == "append_execution_status":
                result = service.append_text_to_doc(arguments["document_id"], arguments["status_text"])
            elif tool_name == "request_human_approval":
                result = service.insert_approval_callout(
                    arguments["spec_doc_id"], arguments["cost_delta_monthly"], arguments["risk_assessment"]
                )
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request.id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                }

            return {"jsonrpc": "2.0", "id": request.id, "result": {"content": [{"type": "text", "text": str(result)}]}}
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": request.id,
                "error": {"code": -32000, "message": str(e)},
            }

    return {
        "jsonrpc": "2.0",
        "id": request.id,
        "error": {"code": -32601, "message": f"Method '{method}' not supported."},
    }


# ------------------------------------------------------------------------------
# REST Endpoints (Invoked directly by Cloud Workflows & Services)
# ------------------------------------------------------------------------------
@app.post("/read-doc")
def read_doc(req: ReadDocRequest):
    try:
        return service.read_doc_content(req.document_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/list-folder")
def list_folder(req: ListFolderRequest):
    try:
        return {"files": service.list_folder_files(req.folder_id)}
    except InvalidDriveIdError as e:
        # FD-4AG-b: an invalid Drive ID -> 422, typed; nothing was sent to Drive (F6: only this error class).
        return _typed_error(422, INVALID_DRIVE_ID, str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/move-doc")
def move_doc(req: MoveDocRequest):
    try:
        return service.move_file_folder(req.file_id, req.source_folder_id, req.target_folder_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Typed failures (workspace logger fix, 2026-10-12). A route never reports success for an action that failed: the
# response is a non-2xx with a TOP-LEVEL ``error_class`` (same shape as lane 14's /create-incident-spec). Logged at
# WARNING, not ERROR, so a Docs/Firestore outage does not become a platform incident in the SRE error sink.
DOC_APPEND_FAILED = "DOC_APPEND_FAILED"
APPROVAL_PERSIST_FAILED = "APPROVAL_PERSIST_FAILED"
APPROVAL_CALLOUT_FAILED = "APPROVAL_CALLOUT_FAILED"
APPROVAL_NOT_RECORDED = "APPROVAL_NOT_RECORDED"
INVALID_DRIVE_ID = "INVALID_DRIVE_ID"


def _typed_error(status_code: int, error_class: str, detail: str, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={
        "status": "FAILED", "error_class": error_class, "detail": detail, **extra})


def _firestore_client(project_id: str):
    """Firestore client for the approval record (a seam so tests never build a real client)."""
    from google.cloud import firestore
    return firestore.Client(project=project_id)


@app.post("/append-status")
def append_status(req: AppendStatusRequest):
    if not req.document_id or req.document_id.strip() == "":
        # Nothing was attempted and the response says so (not a success claim).
        return {"status": "SKIPPED", "message": "No Google Doc ID provided; skipping append."}
    try:
        return service.append_text_to_doc(req.document_id, req.status_text)
    except Exception as e:
        logger.warning(f"Append status failed for document {req.document_id}: {type(e).__name__}: {e}")
        return _typed_error(502, DOC_APPEND_FAILED, f"{type(e).__name__}: {e}", document_id=req.document_id)


def _notify_gate_owned_approval(req: RequestApprovalRequest, approval_id: str, has_doc: bool):
    """AG-7 notify-only path (bundle RT F4): the workflow's pre-build gate already wrote
    ``approval_requests/{approval_id}`` (lane 17 PR-2), so this writes NOTHING to Firestore and only posts the Doc
    callout. WS-1 typed errors are kept: a callout failure is 502 ``APPROVAL_CALLOUT_FAILED`` naming the gate's id."""
    if not has_doc:
        return {
            "status": "SKIPPED",
            "message": (f"No spec Doc to annotate; the workflow gate's approval request {approval_id} is PENDING in "
                        "Control Center -> Approvals. This is not an approval."),
            "approval_id": approval_id,
            "approval_status": "PENDING",
        }
    try:
        result = service.insert_approval_callout(req.spec_doc_id, req.cost_delta_monthly, req.risk_assessment)
    except Exception as e:
        logger.warning(f"Request approval callout failed for document {req.spec_doc_id}: {type(e).__name__}: {e}")
        return _typed_error(502, APPROVAL_CALLOUT_FAILED, f"{type(e).__name__}: {e}",
                            document_id=req.spec_doc_id, approval_id=approval_id, trace_id=req.trace_id)
    return {**result, "approval_id": approval_id}


@app.post("/request-approval")
def request_approval(req: RequestApprovalRequest):
    """Records a Tier-3 FinOps approval request and/or posts the callout in the spec Doc.

    Notify only: this route never grants or records an approval DECISION. The caller (main_orchestrator.yaml
    ``await_human_approval``) must suspend on its own approval gate after a 200.

    AG-7 (bundle RT F4): when the body carries ``approval_id`` (the record the workflow's pre-build gate already
    wrote), nothing is written to Firestore; the route only posts the Doc callout (200 ``APPROVAL_REQUESTED`` with
    that ``approval_id``; no Doc -> 200 ``SKIPPED``; callout failure -> 502 ``APPROVAL_CALLOUT_FAILED``). Without
    ``approval_id`` (older workflow revisions, the MCP tool) the WS-1 behaviour below is unchanged.

    200 -> ``{document_id, status: "APPROVAL_REQUESTED", approval_id?}`` (callout posted; record persisted when
           PROJECT_ID is set) or ``{status: "APPROVAL_RECORDED_CONTROL_CENTER", approval_id, approval_status: "PENDING"}``
           (no spec Doc; the PENDING record was persisted).
    502 -> ``error_class: APPROVAL_PERSIST_FAILED`` (record write failed; no callout is posted) or
           ``APPROVAL_CALLOUT_FAILED`` (Doc callout failed; ``approval_id`` names the PENDING record if one was written).
    503 -> ``error_class: APPROVAL_NOT_RECORDED``: no spec Doc and no PROJECT_ID, so nothing could be recorded.
    """
    has_doc = bool(req.spec_doc_id and req.spec_doc_id.strip())
    gate_approval_id = (req.approval_id or "").strip()
    if gate_approval_id:
        return _notify_gate_owned_approval(req, gate_approval_id, has_doc)
    approval_id: Optional[str] = None

    # 1. Persist the PENDING request to Firestore approval_requests
    project_id = os.getenv("PROJECT_ID")
    if project_id:
        import uuid
        from datetime import datetime, timezone
        approval_id = f"appr-{req.trace_id or uuid.uuid4().hex[:6]}"
        try:
            db = _firestore_client(project_id)
            db.collection("approval_requests").document(approval_id).set({
                "approval_id": approval_id,
                "trace_id": req.trace_id,
                "spec_doc_id": req.spec_doc_id,
                "cost_delta_monthly": req.cost_delta_monthly,
                "risk_assessment": req.risk_assessment,
                "status": "PENDING",
                "requested_at": datetime.now(timezone.utc).isoformat(),
            }, merge=True)
            logger.info(f"Persisted approval request '{approval_id}' to Firestore")
        except Exception as fs_err:
            logger.warning(f"Could not persist approval '{approval_id}' to Firestore: {type(fs_err).__name__}: {fs_err}")
            return _typed_error(502, APPROVAL_PERSIST_FAILED, f"{type(fs_err).__name__}: {fs_err}",
                                approval_id=approval_id, trace_id=req.trace_id)

    # 2. No spec Doc: the persisted PENDING record is the only artifact
    if not has_doc:
        if approval_id is None:
            logger.warning("Request approval with empty spec_doc_id and no PROJECT_ID: nothing recorded.")
            return _typed_error(503, APPROVAL_NOT_RECORDED,
                                "No spec_doc_id and no PROJECT_ID: the approval request was not recorded anywhere.",
                                trace_id=req.trace_id)
        logger.info(f"Request approval with empty spec_doc_id: PENDING record '{approval_id}' only.")
        return {
            "status": "APPROVAL_RECORDED_CONTROL_CENTER",
            "message": "Approval request recorded as PENDING (no spec Doc to annotate). This is not an approval.",
            "approval_id": approval_id,
            "approval_status": "PENDING",
            "cost_delta_monthly": req.cost_delta_monthly,
            "risk_assessment": req.risk_assessment,
        }

    # 3. Post the callout into the spec Doc
    try:
        result = service.insert_approval_callout(req.spec_doc_id, req.cost_delta_monthly, req.risk_assessment)
    except Exception as e:
        logger.warning(f"Request approval callout failed for document {req.spec_doc_id}: {type(e).__name__}: {e}")
        return _typed_error(502, APPROVAL_CALLOUT_FAILED, f"{type(e).__name__}: {e}",
                            document_id=req.spec_doc_id, approval_id=approval_id, trace_id=req.trace_id)
    if approval_id is not None:
        result = {**result, "approval_id": approval_id}
    return result


# FD-4BM (with lane 14 L14-u): the incident document. Contract with workflows/sre_remediation.yaml
# create_incident_ticket: 200 + a real ``document_id`` -> the remediation request carries it as ``spec_doc_id``;
# 503 INCIDENT_TEMPLATE_NOT_CONFIGURED -> the run continues with ``spec_text`` only; any other non-2xx -> the run is
# reported REMEDIATION_FAILED. No path returns an id Drive did not give (the fabricated id of the past is gone).
INCIDENT_TEMPLATE_NOT_CONFIGURED = "INCIDENT_TEMPLATE_NOT_CONFIGURED"
INCIDENT_DOC_CREATE_FAILED = "INCIDENT_DOC_CREATE_FAILED"


def _pipeline_reader():
    """Read-only Firestore reader for the incident's records (a seam so tests never build a real client);
    None when PROJECT_ID is unset (the document then says the records were not read)."""
    project_id = os.getenv("PROJECT_ID", "").strip()
    return incident_doc.FirestoreRestReader(project_id) if project_id else None


@app.post("/create-incident-spec")
def create_incident_spec(req: CreateIncidentSpecRequest):
    """Creates the incident document for an SRE remediation run in the configured Drive folder.

    The document is the built-in template ``incident_doc_template.html`` (incident, workload, trace, timeline,
    failure summary, stack trace, recommended next steps, record sources), filled from the request and the
    incident's Firestore records (read-only), and created in ONE Drive call in the target folder, so it is shared
    as that folder is. With ``INCIDENT_TEMPLATE_ID`` set, that Google Doc is copied and its ``{{KEY}}``
    placeholders are replaced instead.

    200 -> ``{document_id, title, web_view_link, status: "CREATED", folder_id, template}``.
    503 -> ``error_class: INCIDENT_TEMPLATE_NOT_CONFIGURED`` with ``reason`` (no folder, several folders, an
           invalid configured id, or no Drive client): nothing was created.
    422 -> ``error_class: INVALID_DRIVE_ID``: the request named a folder that is not a Drive id.
    502 -> ``error_class: INCIDENT_DOC_CREATE_FAILED``: Drive / Docs refused or failed; the cause is in ``detail``.
    Failures are logged at WARNING (a Docs outage must not become a platform incident in the SRE error sink).
    """
    try:
        folder_id, template_id = incident_doc.resolve_target(req.inbox_folder_id)
    except incident_doc.InvalidRequestFolder as e:
        return _typed_error(422, INVALID_DRIVE_ID, str(e), incident_id=req.incident_id)
    except incident_doc.NotConfigured as nc:
        logger.warning(f"Incident document for {req.incident_id} not created: {nc.reason}: {nc.detail}")
        return _typed_error(503, INCIDENT_TEMPLATE_NOT_CONFIGURED, nc.detail, reason=nc.reason,
                            incident_id=req.incident_id, trace_id=req.trace_id)
    if not service.drive_service or (template_id and not service.docs_service):
        detail = "The Google Drive / Docs client is not initialized (no credentials); no document was created."
        logger.warning(f"Incident document for {req.incident_id} not created: {detail}")
        return _typed_error(503, INCIDENT_TEMPLATE_NOT_CONFIGURED, detail, reason="WORKSPACE_CLIENT_UNAVAILABLE",
                            incident_id=req.incident_id, trace_id=req.trace_id)

    fields = req.model_dump()
    records, notes = incident_doc.read_pipeline_records(_pipeline_reader(), req.incident_id, req.product_id or "")
    ctx = incident_doc.build_context(fields, records, notes)
    try:
        if template_id:
            result = service.clone_template_doc(template_id, folder_id, ctx["TITLE"],
                                                incident_doc.plain_replacements(ctx))
            template_name = f"drive:{template_id}"
        else:
            result = service.create_doc_from_html(folder_id, ctx["TITLE"], incident_doc.render_html(ctx))
            template_name = incident_doc.BUILTIN_TEMPLATE_NAME
    except Exception as e:
        logger.warning(f"Incident document for {req.incident_id} failed: {type(e).__name__}: {e}")
        return _typed_error(502, INCIDENT_DOC_CREATE_FAILED, f"{type(e).__name__}: {e}",
                            incident_id=req.incident_id, trace_id=req.trace_id, folder_id=folder_id)
    doc_id = result.get("document_id") if isinstance(result, dict) else None
    if not isinstance(doc_id, str) or not doc_id.strip():
        logger.warning(f"Incident document for {req.incident_id}: Drive returned no document id")
        return _typed_error(502, INCIDENT_DOC_CREATE_FAILED, "Drive returned no document id",
                            incident_id=req.incident_id, trace_id=req.trace_id, folder_id=folder_id)
    logger.info(f"Created incident document {doc_id} for {req.incident_id} in folder {folder_id}")
    return {**result, "status": "CREATED", "folder_id": folder_id, "template": template_name,
            "incident_id": req.incident_id}


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
