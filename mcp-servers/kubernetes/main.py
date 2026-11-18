"""
StackVend Kubernetes MCP Tool Server.

JSON-RPC 2.0 Model Context Protocol tools and REST endpoints for manifest apply, container logs, events, day-2
deployment operations and the Helm lifecycle in a managed workload's GKE cluster.

FD-4L / FD27-10: every tool takes `product_id`; the target project comes only from the workload ledger (an optional
`project_id` must equal it exactly). Refusals are typed (`status` code + HTTP status), never a mock success.
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import os
import logging
from typing import Any, Callable, Dict, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from helm import HelmRefused
from service import KubernetesService

logger = logging.getLogger("mcp-kubernetes-server")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="StackVend Kubernetes MCP Tool Server",
    description="Model Context Protocol server for a managed workload's GKE cluster: policy-checked server-side "
                "apply, pod logs, events, rolling restart / scale and the Helm lifecycle.",
    version="1.1.0",
)

service = KubernetesService()


# ------------------------------------------------------------------------------
# Request Schemas
# ------------------------------------------------------------------------------
class TargetRequest(BaseModel):
    product_id: str = Field(description="Workload id; the project comes from its ledger record")
    cluster_name: str
    location: str = Field(description="GKE cluster location (region or zone)")
    project_id: Optional[str] = Field(default=None, description="Optional; must equal the workload's project")


class NamespacedRequest(TargetRequest):
    namespace: str


class ApplyManifestRequest(NamespacedRequest):
    yaml_content: str = Field(description="Multi-document YAML manifest content")
    dry_run: bool = False


class ClusterStatusRequest(TargetRequest):
    pass


class ListResourcesRequest(NamespacedRequest):
    pass


class PodLogsRequest(NamespacedRequest):
    pod_name: str
    container: Optional[str] = None
    previous: bool = False
    tail_lines: int = 100


class ClusterEventsRequest(NamespacedRequest):
    pass


class RestartDeploymentRequest(NamespacedRequest):
    deployment_name: str


class ScaleDeploymentRequest(NamespacedRequest):
    deployment_name: str
    replicas: int


# Lane 14 PR-8: Helm lifecycle. The target project comes from the workload ledger (product_id).
class HelmTargetRequest(NamespacedRequest):
    pass


class HelmInstallRequest(HelmTargetRequest):
    release: str
    chart_ref: str = Field(description="oci://<region>-docker.pkg.dev/<project>/<repo>/<chart> or a chart name")
    version: str = Field(description="Exact semver or sha256:<digest>")
    repo_url: Optional[str] = Field(default=None, description="Chart repository URL (exact allow-list only)")
    values: Dict[str, Any] = Field(default_factory=dict)


class HelmReleaseRequest(HelmTargetRequest):
    release: str


class HelmRollbackRequest(HelmReleaseRequest):
    revision: int


class HelmUninstallRequest(HelmReleaseRequest):
    approval_id: Optional[str] = None


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
        "service": "mcp-kubernetes-server",
        **service.helm.health(),
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


# ------------------------------------------------------------------------------
# Tools (one table for MCP and REST)
# ------------------------------------------------------------------------------
_S = {"type": "string"}
_TARGET_PROPS = {"product_id": _S, "cluster_name": _S, "location": _S, "project_id": _S}
_TARGET_REQ = ["product_id", "cluster_name", "location"]


def _schema(extra: Dict[str, Any], required: list) -> Dict[str, Any]:
    return {"type": "object", "properties": {**_TARGET_PROPS, **extra}, "required": _TARGET_REQ + required}


TOOL_SCHEMAS = [
    {"name": "k8s_apply_manifest",
     "description": "Server-side applies a multi-document manifest after a per-document policy (each document's own "
                    "namespace; kinds resolved through the cluster's API discovery: cluster-scoped and unknown kinds and "
                    "protected namespaces are refused) and a server dry run of every document.",
     "inputSchema": _schema({"namespace": _S, "yaml_content": _S, "dry_run": {"type": "boolean", "default": False}},
                            ["namespace", "yaml_content"])},
    {"name": "k8s_get_cluster_status",
     "description": "GKE cluster health, master version, nodes and namespaces.",
     "inputSchema": _schema({}, [])},
    {"name": "k8s_list_resources",
     "description": "Deployments, Pods, Services and Ingresses in a namespace.",
     "inputSchema": _schema({"namespace": _S}, ["namespace"])},
    {"name": "k8s_fetch_pod_logs",
     "description": "Container logs (previous=True: the crashed instance).",
     "inputSchema": _schema({"namespace": _S, "pod_name": _S, "container": _S,
                             "previous": {"type": "boolean", "default": False},
                             "tail_lines": {"type": "integer", "default": 100}}, ["namespace", "pod_name"])},
    {"name": "k8s_get_events",
     "description": "Recent events in a namespace (e.g. CrashLoopBackOff, OOMKilled).",
     "inputSchema": _schema({"namespace": _S}, ["namespace"])},
    {"name": "k8s_restart_deployment",
     "description": "Zero-downtime rolling restart of a deployment (protected namespaces refused).",
     "inputSchema": _schema({"namespace": _S, "deployment_name": _S}, ["namespace", "deployment_name"])},
    {"name": "k8s_scale_deployment",
     "description": "Sets a deployment's replica count (protected namespaces refused; bounded).",
     "inputSchema": _schema({"namespace": _S, "deployment_name": _S, "replicas": {"type": "integer"}},
                            ["namespace", "deployment_name", "replicas"])},
    {"name": "helm_install_or_upgrade",
     "description": "Installs or upgrades a Helm release in a workload's GKE cluster. Policy runs on the server-side dry "
                    "run (manifest + hooks); cluster-scoped kinds and protected namespaces are refused; post-install "
                    "digest must match.",
     "inputSchema": _schema({"namespace": _S, "release": _S, "chart_ref": _S, "version": _S, "repo_url": _S,
                             "values": {"type": "object"}}, ["namespace", "release", "chart_ref", "version"])},
    {"name": "helm_rollback", "description": "Rolls a Helm release back to a revision.",
     "inputSchema": _schema({"namespace": _S, "release": _S, "revision": {"type": "integer"}},
                            ["namespace", "release", "revision"])},
    {"name": "helm_uninstall",
     "description": ("Uninstalls a Helm release (approved HELM_UNINSTALL operator record required). Without "
                     "approval_id it records an approval card in the Control Center and answers "
                     "REFUSED:APPROVAL_REQUIRED with approval_request_id."),
     "inputSchema": _schema({"namespace": _S, "release": _S, "approval_id": _S},
                            ["namespace", "release"])},
    {"name": "helm_list", "description": "Lists Helm releases in a namespace.",
     "inputSchema": _schema({"namespace": _S}, ["namespace"])},
    {"name": "helm_status", "description": "Shows a Helm release's status.",
     "inputSchema": _schema({"namespace": _S, "release": _S}, ["namespace", "release"])},
    {"name": "helm_history", "description": "Shows a Helm release's revision history.",
     "inputSchema": _schema({"namespace": _S, "release": _S}, ["namespace", "release"])},
]


def _kw(args: Dict[str, Any], *names: str, namespaced: bool = True) -> Dict[str, Any]:
    base = {k: args.get(k) for k in ("product_id", "cluster_name", "location", "project_id")}
    if namespaced:
        base["namespace"] = args.get("namespace")
    base.update({k: args.get(k) for k in names})
    return base


def _opt(args: Dict[str, Any], name: str, default: Any) -> Dict[str, Any]:
    return {name: args[name]} if args.get(name) is not None else {name: default}


K8S_TOOLS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "k8s_apply_manifest": lambda a: service.apply_manifest(
        **_kw(a, "yaml_content"), **_opt(a, "dry_run", False)),
    "k8s_get_cluster_status": lambda a: service.get_cluster_status(**_kw(a, namespaced=False)),
    "k8s_list_resources": lambda a: service.list_workload_resources(**_kw(a)),
    "k8s_fetch_pod_logs": lambda a: service.fetch_pod_logs(
        **_kw(a, "pod_name", "container"), **_opt(a, "previous", False), **_opt(a, "tail_lines", 100)),
    "k8s_get_events": lambda a: service.get_cluster_events(**_kw(a)),
    "k8s_restart_deployment": lambda a: service.restart_deployment(**_kw(a, "deployment_name")),
    "k8s_scale_deployment": lambda a: service.scale_deployment(**_kw(a, "deployment_name", "replicas")),
}

HELM_TOOLS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "helm_install_or_upgrade": lambda a: service.helm.install_or_upgrade(
        **_kw(a, "release", "chart_ref", "version", "repo_url"), values=a.get("values") or {}),
    "helm_rollback": lambda a: service.helm.rollback(**_kw(a, "release", "revision")),
    "helm_uninstall": lambda a: service.helm.uninstall(**_kw(a, "release", "approval_id")),
    "helm_list": lambda a: service.helm.list_releases(**_kw(a)),
    "helm_status": lambda a: service.helm.release_status(**_kw(a, "release")),
    "helm_history": lambda a: service.helm.history(**_kw(a, "release")),
}

TOOLS = {**K8S_TOOLS, **HELM_TOOLS}


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
    method = request.method
    params = request.params or {}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request.id, "result": {"tools": TOOL_SCHEMAS}}

    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments") or {}
        if tool_name not in TOOLS:
            return _rpc_error(request.id, -32601, f"Unknown tool: {tool_name}")
        if not isinstance(args, dict):
            return _rpc_error(request.id, -32602, "arguments must be an object")
        try:
            result = TOOLS[tool_name](dict(args))
        except HelmRefused as refused:
            return _rpc_error(request.id, -32002, f"{refused.code}: {refused.detail}",
                              {"status": refused.code, "detail": refused.detail, **refused.extra})
        except Exception as e:
            logger.error(f"{tool_name} failed: {type(e).__name__}")
            return _rpc_error(request.id, -32000, f"{type(e).__name__}: {e}")
        if isinstance(result, dict) and result.get("http_status", 200) != 200:
            return _rpc_error(request.id, -32002, str(result.get("status")), result)
        return {"jsonrpc": "2.0", "id": request.id, "result": {"content": [{"type": "text", "text": str(result)}]}}

    return _rpc_error(request.id, -32601, f"Method '{method}' not supported.")


# ------------------------------------------------------------------------------
# REST Endpoints
# ------------------------------------------------------------------------------
def _rest(tool: str, req: BaseModel):
    try:
        result = TOOLS[tool](req.model_dump())
    except HelmRefused as refused:
        raise HTTPException(status_code=refused.http_status,
                            detail={"status": refused.code, "detail": refused.detail, **refused.extra})
    except Exception as e:
        logger.error(f"{tool} failed: {type(e).__name__}")
        raise HTTPException(status_code=500, detail={"status": "ERROR", "detail": f"{type(e).__name__}: {e}"})
    body = dict(result)
    code = int(body.pop("http_status", 200))
    if code != 200:
        raise HTTPException(status_code=code, detail=body)
    return body


@app.post("/apply")
def apply_manifest_endpoint(req: ApplyManifestRequest):
    return _rest("k8s_apply_manifest", req)


@app.post("/status")
def cluster_status_endpoint(req: ClusterStatusRequest):
    return _rest("k8s_get_cluster_status", req)


@app.post("/resources")
def list_resources_endpoint(req: ListResourcesRequest):
    return _rest("k8s_list_resources", req)


@app.post("/logs")
def fetch_pod_logs_endpoint(req: PodLogsRequest):
    return _rest("k8s_fetch_pod_logs", req)


@app.post("/events")
def get_cluster_events_endpoint(req: ClusterEventsRequest):
    return _rest("k8s_get_events", req)


@app.post("/restart")
def restart_deployment_endpoint(req: RestartDeploymentRequest):
    return _rest("k8s_restart_deployment", req)


@app.post("/scale")
def scale_deployment_endpoint(req: ScaleDeploymentRequest):
    return _rest("k8s_scale_deployment", req)


# Lane 14 PR-8: Helm lifecycle (REST + the MCP tools above)
@app.post("/helm/install")
def helm_install_endpoint(req: HelmInstallRequest):
    return _rest("helm_install_or_upgrade", req)


@app.post("/helm/rollback")
def helm_rollback_endpoint(req: HelmRollbackRequest):
    return _rest("helm_rollback", req)


@app.post("/helm/uninstall")
def helm_uninstall_endpoint(req: HelmUninstallRequest):
    return _rest("helm_uninstall", req)


@app.post("/helm/list")
def helm_list_endpoint(req: HelmTargetRequest):
    return _rest("helm_list", req)


@app.post("/helm/status")
def helm_status_endpoint(req: HelmReleaseRequest):
    return _rest("helm_status", req)


@app.post("/helm/history")
def helm_history_endpoint(req: HelmReleaseRequest):
    return _rest("helm_history", req)


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
