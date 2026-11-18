"""
StackVend gcloud MCP Tool Server.

Typed Google Cloud tools only (FD-4L / FD27-05; executor.py): inspection of, and audited Cloud Run ops on, a managed
workload's own project (from the workload ledger; never the host project). `/exec` takes `{tool, args}`; a
free-form command string is refused with 422 FREE_FORM_COMMAND_REFUSED. `/logs` and `/status` take typed fields.
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import logging
import os
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from executor import INSPECTION_TOOLS, OPS_TOOLS, GcloudExecutor, GcloudRefused

logger = logging.getLogger("mcp-gcloud-server")

app = FastAPI(
    title="StackVend gcloud MCP Tool Server",
    description="Typed, ledger-scoped Google Cloud inspection and audited Cloud Run operations for managed workloads.",
    version="2.0.0",
)

executor = GcloudExecutor()

FREE_FORM_COMMAND_REFUSED = "FREE_FORM_COMMAND_REFUSED"


# ------------------------------------------------------------------------------
# Request Models
# ------------------------------------------------------------------------------
class ExecToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: Optional[str] = Field(default=None, description=f"One of {list(INSPECTION_TOOLS + OPS_TOOLS)}")
    args: Dict[str, Any] = Field(default_factory=dict)
    command: Optional[str] = Field(default=None, description="Refused: free-form commands no longer run")


class QueryLogsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_id: str
    severity: Optional[str] = None
    resource_type: Optional[str] = None
    service_name: Optional[str] = None
    since: Optional[str] = None
    limit: int = 50
    project_id: Optional[str] = None


class ServiceStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_id: str
    region: str
    service: str
    project_id: Optional[str] = None


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    method: str
    params: Optional[Dict[str, Any]] = Field(default_factory=dict)


# ------------------------------------------------------------------------------
# Health Check
# ------------------------------------------------------------------------------
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "mcp-gcloud-server",
        "environment": os.getenv("ENVIRONMENT", "prod"),
        "credentials": executor.credentials_status(),
        "tools": list(INSPECTION_TOOLS + OPS_TOOLS),
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


# ------------------------------------------------------------------------------
# REST Endpoints
# ------------------------------------------------------------------------------
def _refusal(e: GcloudRefused) -> HTTPException:
    return HTTPException(status_code=e.http_status, detail={"status": e.code, "detail": e.detail})


@app.post("/exec")
def exec_tool(req: ExecToolRequest, request: Request):
    if req.command is not None:
        raise HTTPException(status_code=422, detail={
            "status": FREE_FORM_COMMAND_REFUSED,
            "detail": "free-form gcloud commands are not run; send {tool, args} for a typed tool"})
    try:
        return executor.run_tool(req.tool, req.args, authorization=request.headers.get("authorization"))
    except GcloudRefused as e:
        raise _refusal(e)


@app.post("/logs")
def query_logs(req: QueryLogsRequest):
    try:
        return executor.query_logs(**req.model_dump())
    except GcloudRefused as e:
        raise _refusal(e)


@app.post("/status")
def service_status(req: ServiceStatusRequest):
    try:
        return executor.get_cloud_run_service(**req.model_dump())
    except GcloudRefused as e:
        raise _refusal(e)


# ------------------------------------------------------------------------------
# MCP Protocol Endpoint (JSON-RPC 2.0)
# ------------------------------------------------------------------------------
_S = {"type": "string"}
_TARGET = {"product_id": _S, "project_id": _S}
_SERVICE = {**_TARGET, "region": _S, "service": _S}

TOOL_SCHEMAS = [
    {"name": "get_cloud_run_service", "description": "Reads a Cloud Run service in the workload's project.",
     "inputSchema": {"type": "object", "properties": _SERVICE, "required": ["product_id", "region", "service"]}},
    {"name": "list_cloud_run_services", "description": "Lists Cloud Run services in the workload's project.",
     "inputSchema": {"type": "object", "properties": {**_TARGET, "region": _S}, "required": ["product_id", "region"]}},
    {"name": "get_project_iam_policy", "description": "Reads the workload project's IAM policy.",
     "inputSchema": {"type": "object", "properties": _TARGET, "required": ["product_id"]}},
    {"name": "list_service_accounts", "description": "Lists the workload project's service accounts.",
     "inputSchema": {"type": "object", "properties": _TARGET, "required": ["product_id"]}},
    {"name": "query_logs",
     "description": "Cloud Logging entries of the workload's project; the filter is built from typed fields only.",
     "inputSchema": {"type": "object", "required": ["product_id"], "properties": {
         **_TARGET, "severity": {"type": "string", "enum": ["DEFAULT", "DEBUG", "INFO", "NOTICE", "WARNING", "ERROR",
                                                             "CRITICAL", "ALERT", "EMERGENCY"]},
         "resource_type": _S, "service_name": _S, "since": _S, "limit": {"type": "integer", "default": 50}}}},
    {"name": "update_cloud_run_scaling",
     "description": "Sets a service's template min/max instances (audited first; max 0 is the enforcer's quarantine and "
                    "is refused).",
     "inputSchema": {"type": "object", "required": ["product_id", "region", "service", "min_instance_count",
                                                    "max_instance_count"],
                     "properties": {**_SERVICE, "min_instance_count": {"type": "integer"},
                                    "max_instance_count": {"type": "integer"}}}},
    {"name": "update_cloud_run_traffic",
     "description": "Splits traffic across existing revisions (integer percents summing to 100; audited first).",
     "inputSchema": {"type": "object", "required": ["product_id", "region", "service", "traffic"],
                     "properties": {**_SERVICE, "traffic": {"type": "object"}}}},
    {"name": "restart_cloud_run_service", "description": "Rolls a new revision with the same spec (audited first).",
     "inputSchema": {"type": "object", "properties": _SERVICE, "required": ["product_id", "region", "service"]}},
]


def _rpc_error(request_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


@app.post("/mcp")
def handle_mcp_rpc(rpc: JsonRpcRequest, request: Request):
    params = rpc.params or {}
    if rpc.method == "tools/list":
        return {"jsonrpc": "2.0", "id": rpc.id, "result": {"tools": TOOL_SCHEMAS}}
    if rpc.method == "tools/call":
        tool_name = params.get("name")
        if tool_name == "exec_gcloud_command":
            return _rpc_error(rpc.id, -32002, FREE_FORM_COMMAND_REFUSED, {"status": FREE_FORM_COMMAND_REFUSED})
        try:
            result = executor.run_tool(tool_name, params.get("arguments") or {}, authorization=request.headers.get("authorization"))
        except GcloudRefused as e:
            return _rpc_error(rpc.id, -32002, f"{e.code}: {e.detail}", {"status": e.code, "detail": e.detail})
        return {"jsonrpc": "2.0", "id": rpc.id, "result": {"content": [{"type": "text", "text": str(result)}]}}
    return _rpc_error(rpc.id, -32601, f"Method '{rpc.method}' not supported.")


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
