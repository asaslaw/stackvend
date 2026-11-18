"""
StackVend: Google ADK & Agent Engine MCP Server (mcp-agent-builder-server, C44)
Exposes JSON-RPC 2.0 MCP tools and REST endpoints for synthesizing, evaluating, and deploying code-first Google ADK
agents to Agent Engine in a workload's own (managed child) project.

Lane 14 PR-9: deploy / datastore / eval are real calls in the child project (see service.py); every mutating call
needs an approved operator record (lane 18 approval shape). Typed outcomes map to HTTP status codes; nothing is
simulated.
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import os
import sys
import logging
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Ensure local directory and repo root are available in python path
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from service import AgentBuilderService

logger = logging.getLogger("mcp-agent-builder-server")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="StackVend Agent Builder & Agent Engine MCP Server",
    description="Model Context Protocol server for Google ADK scaffolding, Discovery Engine datastores, and Agent Engine deployment in managed workload projects.",
    version="2.0.0",
)

service = AgentBuilderService()


def _respond(result: Dict[str, Any], ok_statuses=(200, 202)) -> Any:
    """Typed result -> HTTP: 2xx returns the body; anything else raises with the typed body as detail."""
    body = dict(result)
    code = int(body.pop("http_status", 200))
    if code not in ok_statuses:
        raise HTTPException(status_code=code, detail=body)
    return JSONResponse(status_code=code, content=body)


# ------------------------------------------------------------------------------
# Request Schemas
# ------------------------------------------------------------------------------
class ScaffoldAdkRequest(BaseModel):
    agent_name: str
    system_instruction: str
    tools_definition: List[Dict[str, Any]] = Field(default_factory=list)
    model_name: str = "gemini-3.8-flash"
    grounding_datastore_id: Optional[str] = None
    max_turns: int = 8
    per_request_timeout_seconds: int = 30


class ProvisionDatastoreRequest(BaseModel):
    product_id: str
    approval_id: Optional[str] = None
    datastore_name: str
    source_uri: str
    location: Optional[str] = Field(default=None, description="Discovery Engine location: global, us or eu")
    content_type: str = "UNSTRUCTURED_DOCUMENT"
    project_id: Optional[str] = Field(default=None, description="Optional; must equal the workload's project")


class RunEvalRequest(BaseModel):
    product_id: str
    agent_resource_name: str
    test_cases: List[Dict[str, Any]] = Field(default_factory=list)
    metric: str = "safety"
    system_instruction: Optional[str] = ""


class DeployAgentEngineRequest(ScaffoldAdkRequest):
    product_id: str
    approval_id: Optional[str] = None
    requirements: List[str] = Field(default_factory=list)
    region: Optional[str] = Field(default=None, description="Optional; must equal the workload's agent_engine.region")
    display_name: Optional[str] = None
    project_id: Optional[str] = Field(default=None, description="Optional; must equal the workload's project")


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
        "service": "mcp-agent-builder-server",
        "runtime_target": "Agent Engine",
        "default_region": os.getenv("REGION") or None,
        "gemini_enterprise_licenses": 0,
        "environment": os.getenv("ENVIRONMENT", "prod"),
        # Approvals are consumed through project-vending (URL from VENDING_SERVICE_URL, else this Cloud Run
        # runtime's metadata: docs/planning/mcp-action-approval-plan.md).
        "approval_consume_service": "project-repo-vending-service",
        "approval_consume_url_configured": bool(os.getenv("VENDING_SERVICE_URL")),
        "guard_database": os.getenv("STACKVEND_GUARD_FIRESTORE_DATABASE") or "(default)",
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


# ------------------------------------------------------------------------------
# REST Endpoints
# ------------------------------------------------------------------------------
@app.post("/api/v1/adk/scaffold")
def api_scaffold_adk(req: ScaffoldAdkRequest):
    result = service.scaffold_adk_project(
        agent_name=req.agent_name,
        system_instruction=req.system_instruction,
        tools_definition=req.tools_definition,
        model_name=req.model_name,
        grounding_datastore_id=req.grounding_datastore_id,
        max_turns=req.max_turns,
        per_request_timeout_seconds=req.per_request_timeout_seconds,
    )
    if result.get("status") in ["VALIDATION_FAILED", "SECURITY_CHECK_FAILED"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result)
    return result


def _datastore(args: Dict[str, Any]) -> Dict[str, Any]:
    return service.provision_discovery_datastore(
        product_id=args.get("product_id", ""),
        approval_id=args.get("approval_id"),
        datastore_name=args.get("datastore_name", ""),
        source_uri=args.get("source_uri", ""),
        location=args.get("location"),
        content_type=args.get("content_type", "UNSTRUCTURED_DOCUMENT"),
        project_id=args.get("project_id"),
    )


def _eval(args: Dict[str, Any]) -> Dict[str, Any]:
    return service.run_eval_suite(
        product_id=args.get("product_id", ""),
        agent_resource_name=args.get("agent_resource_name", ""),
        test_cases=args.get("test_cases", []),
        metric=args.get("metric", "safety"),
        system_instruction=args.get("system_instruction") or "",
    )


def _deploy(args: Dict[str, Any]) -> Dict[str, Any]:
    return service.deploy_to_agent_engine(
        product_id=args.get("product_id", ""),
        approval_id=args.get("approval_id"),
        agent_name=args.get("agent_name", ""),
        system_instruction=args.get("system_instruction", ""),
        tools_definition=args.get("tools_definition", []),
        requirements=args.get("requirements", []),
        model_name=args.get("model_name", "gemini-3.8-flash"),
        grounding_datastore_id=args.get("grounding_datastore_id"),
        max_turns=args.get("max_turns", 8),
        per_request_timeout_seconds=args.get("per_request_timeout_seconds", 30),
        region=args.get("region"),
        display_name=args.get("display_name"),
        project_id=args.get("project_id"),
    )


@app.post("/api/v1/datastore/provision")
def api_provision_datastore(req: ProvisionDatastoreRequest):
    return _respond(_datastore(req.model_dump()))


@app.post("/api/v1/eval/run")
def api_run_eval(req: RunEvalRequest):
    return _respond(_eval(req.model_dump()))


@app.post("/api/v1/agent-engine/deploy")
def api_deploy_agent_engine(req: DeployAgentEngineRequest):
    return _respond(_deploy(req.model_dump()))


@app.get("/api/v1/agent-engine/deployments/{deployment_id}")
def api_deployment_status(deployment_id: str, product_id: str):
    """RT F4: `?product_id=` is required (422 without it); another product's deployment is 404."""
    return _respond(service.get_deployment(deployment_id, product_id))


# ------------------------------------------------------------------------------
# MCP JSON-RPC 2.0 Protocol Handler
# ------------------------------------------------------------------------------
_APPROVAL_PROP = {"type": "string", "description": ("Approved operator record id (Control Center approval card). "
                                                    "Omit it to request an approval: the answer is "
                                                    "REFUSED:APPROVAL_REQUIRED with approval_request_id.")}
_PRODUCT_PROP = {"type": "string", "description": "StackVend workload product_id; the target project comes from its ledger"}
_SCAFFOLD_PROPS = {
    "agent_name": {"type": "string", "description": "Normalized identifier (e.g. hr-benefits-assistant)"},
    "model_name": {"type": "string", "default": "gemini-3.8-flash", "description": "Target Gemini model on Vertex AI"},
    "system_instruction": {"type": "string", "description": "Core persona, constraints, and instructions"},
    "grounding_datastore_id": {"type": "string", "description": "Optional search datastore ID for RAG"},
    "max_turns": {"type": "integer", "default": 8, "description": "Hard limit on autonomous reasoning turns per request"},
    "per_request_timeout_seconds": {"type": "integer", "default": 30, "description": "Execution timeout"},
    "tools_definition": {
        "type": "array",
        "items": {
            "type": "object",
            "required": ["name", "description", "safety_level", "parameters_schema"],
            "properties": {
                "name": {"type": "string", "description": "Python identifier"},
                "description": {"type": "string"},
                "safety_level": {"type": "string", "enum": ["READ_ONLY", "STATE_MUTATING"]},
                "parameters_schema": {"type": "object"},
            },
        },
    },
}

MCP_TOOLS_MANIFEST = [
    {
        "name": "adk_scaffold_project",
        "description": "Generates a complete Google Agent Development Kit (ADK) repository with safety delimiters and tool contracts.",
        "inputSchema": {"type": "object", "required": ["agent_name", "system_instruction", "tools_definition"],
                        "properties": dict(_SCAFFOLD_PROPS)},
    },
    {
        "name": "discovery_datastore_provision",
        "description": "Creates a Discovery Engine search datastore in the workload's project (approval required).",
        "inputSchema": {
            "type": "object",
            "required": ["product_id", "datastore_name", "source_uri", "location"],
            "properties": {
                "product_id": _PRODUCT_PROP,
                "approval_id": _APPROVAL_PROP,
                "datastore_name": {"type": "string"},
                "source_uri": {"type": "string", "description": "GCS URI (gs://...), drive:// or https:// source"},
                "location": {"type": "string", "enum": ["global", "us", "eu"]},
                "content_type": {"type": "string", "enum": ["UNSTRUCTURED_DOCUMENT", "STRUCTURED_DATA", "WEBSITE"], "default": "UNSTRUCTURED_DOCUMENT"},
            },
        },
    },
    {
        "name": "adk_eval_suite",
        "description": "Queries a deployed Agent Engine with the test cases plus standard jailbreak probes and scores each response with the Gen AI evaluation service.",
        "inputSchema": {
            "type": "object",
            "required": ["product_id", "agent_resource_name", "test_cases"],
            "properties": {
                "product_id": _PRODUCT_PROP,
                "agent_resource_name": {"type": "string", "description": "reasoningEngines resource this server deployed for the workload"},
                "metric": {"type": "string", "enum": ["safety", "fluency", "coherence"], "default": "safety"},
                "test_cases": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["user_prompt"],
                        "properties": {
                            "user_prompt": {"type": "string"},
                            "expected_tool_call": {"type": "string"},
                            "prohibited_content": {"type": "array", "items": {"type": "string"}},
                            "must_ground_in_docs": {"type": "boolean"},
                            "is_jailbreak_probe": {"type": "boolean", "default": False},
                        },
                    },
                },
            },
        },
    },
    {
        "name": "agent_engine_deploy",
        "description": "Renders and validates the ADK scaffold, then packages and deploys it to Agent Engine by a Cloud Build in the workload's own project (approval required). Returns a deployment id to poll.",
        "inputSchema": {
            "type": "object",
            "required": ["product_id", "agent_name", "system_instruction", "tools_definition", "requirements"],
            "properties": dict(_SCAFFOLD_PROPS, **{
                "product_id": _PRODUCT_PROP,
                "approval_id": _APPROVAL_PROP,
                "requirements": {"type": "array", "items": {"type": "string"}},
                "region": {"type": "string", "description": "Optional; must equal the workload's agent_engine.region"},
                "display_name": {"type": "string"},
            }),
        },
    },
    {
        "name": "agent_engine_deployment_status",
        "description": "One poll of an Agent Engine deployment: build state, then the real reasoningEngines resource.",
        "inputSchema": {"type": "object", "required": ["product_id", "deployment_id"],
                        "properties": {"product_id": _PRODUCT_PROP, "deployment_id": {"type": "string"}}},
    },
]


@app.post("/mcp")
def handle_mcp_rpc(request: JsonRpcRequest):
    method = request.method
    params = request.params or {}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request.id,
            "result": {"tools": MCP_TOOLS_MANIFEST},
        }

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {}) or {}

        try:
            if tool_name == "adk_scaffold_project":
                res = service.scaffold_adk_project(
                    agent_name=arguments.get("agent_name", "enterprise-agent"),
                    system_instruction=arguments.get("system_instruction", ""),
                    tools_definition=arguments.get("tools_definition", []),
                    model_name=arguments.get("model_name", "gemini-3.8-flash"),
                    grounding_datastore_id=arguments.get("grounding_datastore_id"),
                    max_turns=arguments.get("max_turns", 8),
                    per_request_timeout_seconds=arguments.get("per_request_timeout_seconds", 30),
                )
            elif tool_name in ["discovery_datastore_provision", "vertex_datastore_provision"]:
                res = _datastore(arguments)
            elif tool_name == "adk_eval_suite":
                res = _eval(arguments)
            elif tool_name == "agent_engine_deploy":
                res = _deploy(arguments)
            elif tool_name == "agent_engine_deployment_status":
                res = service.get_deployment(arguments.get("deployment_id", ""), arguments.get("product_id", ""))
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request.id,
                    "error": {"code": -32601, "message": f"Tool '{tool_name}' not found."},
                }

            http_status = res.get("http_status", 200) if isinstance(res, dict) else 200
            if isinstance(res, dict) and http_status not in (200, 202):
                return {
                    "jsonrpc": "2.0",
                    "id": request.id,
                    "error": {"code": -32002, "message": res.get("error") or res.get("status"), "data": res},
                }
            return {
                "jsonrpc": "2.0",
                "id": request.id,
                "result": {"content": [{"type": "text", "text": str(res)}], "data": res},
            }

        except Exception as e:
            logger.error(f"Error handling MCP tool call '{tool_name}': {e}", exc_info=True)
            return {
                "jsonrpc": "2.0",
                "id": request.id,
                "error": {"code": -32000, "message": str(e)},
            }

    return {
        "jsonrpc": "2.0",
        "id": request.id,
        "error": {"code": -32601, "message": f"Method '{method}' not found."},
    }
