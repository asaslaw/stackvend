"""
StackVend GitHub MCP Tool Server.

JSON-RPC 2.0 MCP tools and REST endpoints for branches, file reads, commits, diffs and pull requests in the
workload's own repository only (FD-4L / FD27-17; service.py): every call takes `product_id`; the repository comes
from the workload ledger; an optional `repo_name` must equal it exactly. Refusals are typed.
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import logging
import os
from typing import Any, Callable, Dict, Optional

from fastapi import FastAPI, HTTPException
from github import GithubException
from pydantic import BaseModel, Field

from service import GithubRefused, GithubService

logger = logging.getLogger("mcp-github-toolserver")

app = FastAPI(
    title="StackVend GitHub MCP Tool Server",
    description="Model Context Protocol server for Git operations in a managed workload's own GitHub repository.",
    version="2.0.0",
)

service = GithubService()


# ------------------------------------------------------------------------------
# Request Models
# ------------------------------------------------------------------------------
class RepoRequest(BaseModel):
    product_id: str = Field(description="Workload id; the repository comes from its ledger record")
    repo_name: Optional[str] = Field(default=None, description="Optional; must equal the workload's repository")


class CreateBranchRequest(RepoRequest):
    new_branch: str
    source_branch: str = "main"


class ReadFileRequest(RepoRequest):
    file_path: str
    branch: str = "main"


class CommitFilesRequest(RepoRequest):
    branch: str
    commit_message: str
    files: Dict[str, str] = Field(description="Map of file_path to file_content")


class GetDiffRequest(RepoRequest):
    base_branch: str = "main"
    head_branch: str


class CreatePRRequest(RepoRequest):
    title: str
    body: str
    head_branch: str
    base_branch: str = "main"


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    method: str
    params: Optional[Dict[str, Any]] = Field(default_factory=dict)


# ------------------------------------------------------------------------------
# Tools (one table for MCP and REST)
# ------------------------------------------------------------------------------
def _opt(a: Dict[str, Any], name: str, default: Any) -> Any:
    return a[name] if a.get(name) is not None else default


TOOLS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "create_branch": lambda a: service.create_branch(
        a.get("product_id"), a.get("new_branch"), _opt(a, "source_branch", "main"), repo_name=a.get("repo_name")),
    "read_file": lambda a: service.read_file_content(
        a.get("product_id"), a.get("file_path"), _opt(a, "branch", "main"), repo_name=a.get("repo_name")),
    "commit_files": lambda a: service.commit_files(
        a.get("product_id"), a.get("branch"), a.get("commit_message"), a.get("files"), repo_name=a.get("repo_name")),
    "get_diff": lambda a: service.get_diff(
        a.get("product_id"), _opt(a, "base_branch", "main"), a.get("head_branch"), repo_name=a.get("repo_name")),
    "create_pull_request": lambda a: service.create_pull_request(
        a.get("product_id"), a.get("title"), a.get("body"), a.get("head_branch"), _opt(a, "base_branch", "main"),
        repo_name=a.get("repo_name")),
}

_S = {"type": "string"}
_REPO = {"product_id": _S, "repo_name": _S}


def _schema(props: Dict[str, Any], required: list) -> Dict[str, Any]:
    return {"type": "object", "properties": {**_REPO, **props}, "required": ["product_id"] + required}


TOOL_SCHEMAS = [
    {"name": "create_branch", "description": "Creates a branch in the workload's repository (refused if it exists).",
     "inputSchema": _schema({"new_branch": _S, "source_branch": {"type": "string", "default": "main"}}, ["new_branch"])},
    {"name": "read_file", "description": "Reads a file from the workload's repository on a branch.",
     "inputSchema": _schema({"file_path": _S, "branch": {"type": "string", "default": "main"}}, ["file_path"])},
    {"name": "commit_files", "description": "Commits files atomically to a branch of the workload's repository.",
     "inputSchema": _schema({"branch": _S, "commit_message": _S, "files": {"type": "object"}},
                            ["branch", "commit_message", "files"])},
    {"name": "get_diff", "description": "Diff between two branches of the workload's repository.",
     "inputSchema": _schema({"base_branch": {"type": "string", "default": "main"}, "head_branch": _S},
                            ["head_branch"])},
    {"name": "create_pull_request",
     "description": "Opens a PR in the workload's repository (an open PR for the same head is returned).",
     "inputSchema": _schema({"title": _S, "body": _S, "head_branch": _S,
                             "base_branch": {"type": "string", "default": "main"}}, ["title", "body", "head_branch"])},
]
# FD-4P / FD-4BB (owner row 23, rows L16-k): this server never merges. The REST `/merge` route, MergePRRequest and
# GithubService.merge_pull_request are deleted; StackVend merges only ledger-recorded PRs (gateway release step,
# Control Center approval).
MCP_TOOLS = frozenset(t["name"] for t in TOOL_SCHEMAS)


def _run(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Returns the result or raises GithubRefused (GitHub API errors become typed GITHUB_ERROR refusals)."""
    try:
        return TOOLS[tool](args)
    except GithubException as e:
        status = getattr(e, "status", None)
        status = status if isinstance(status, int) else 502
        raise GithubRefused("GITHUB_ERROR", f"{tool}: HTTP {status}", status if status in (404, 409, 422) else 502) from e


# ------------------------------------------------------------------------------
# Health Check
# ------------------------------------------------------------------------------
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "mcp-github-toolserver",
        "environment": os.getenv("ENVIRONMENT", "prod"),
        "github_org": os.getenv("GITHUB_ORG") or None,
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


# ------------------------------------------------------------------------------
# REST Endpoints
# ------------------------------------------------------------------------------
def _rest(tool: str, req: BaseModel) -> Dict[str, Any]:
    try:
        return _run(tool, req.model_dump())
    except GithubRefused as e:
        raise HTTPException(status_code=e.http_status, detail={"status": e.code, "detail": e.detail})


@app.post("/branch")
def create_branch(req: CreateBranchRequest):
    return _rest("create_branch", req)


@app.post("/read-file")
def read_file(req: ReadFileRequest):
    return _rest("read_file", req)


@app.post("/commit")
def commit_files(req: CommitFilesRequest):
    return _rest("commit_files", req)


@app.post("/diff")
def get_diff(req: GetDiffRequest):
    return _rest("get_diff", req)


@app.post("/pull-request")
def create_pull_request(req: CreatePRRequest):
    return _rest("create_pull_request", req)


# ------------------------------------------------------------------------------
# MCP Protocol Endpoint (JSON-RPC 2.0)
# ------------------------------------------------------------------------------
def _rpc_error(request_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


@app.post("/mcp")
def handle_mcp_rpc(request: JsonRpcRequest):
    params = request.params or {}
    if request.method == "tools/list":
        return {"jsonrpc": "2.0", "id": request.id, "result": {"tools": TOOL_SCHEMAS}}
    if request.method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments") or {}
        if tool_name not in MCP_TOOLS:
            return _rpc_error(request.id, -32601, f"Unknown tool: {tool_name}")
        if not isinstance(args, dict):
            return _rpc_error(request.id, -32602, "arguments must be an object")
        try:
            result = _run(tool_name, dict(args))
        except GithubRefused as e:
            return _rpc_error(request.id, -32002, f"{e.code}: {e.detail}", {"status": e.code, "detail": e.detail})
        except Exception as e:
            logger.error(f"{tool_name} failed: {type(e).__name__}")
            return _rpc_error(request.id, -32000, f"{type(e).__name__}: {e}")
        return {"jsonrpc": "2.0", "id": request.id, "result": {"content": [{"type": "text", "text": str(result)}]}}
    return _rpc_error(request.id, -32601, f"Method '{request.method}' not supported.")


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
