"""
Project Castor: Infracost MCP Tool Server
Exposes JSON-RPC 2.0 MCP tools and REST endpoints for pre-flight Terraform cost estimation and FinOps policy checks.
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import os
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from calculator import InfracostCalculator

app = FastAPI(
    title="StackVend Infracost MCP Tool Server",
    description="Model Context Protocol server for pre-flight Terraform cost estimation and FinOps budget circuit breaker enforcement.",
    version="1.0.0",
)

calculator = InfracostCalculator()


# ------------------------------------------------------------------------------
# Request Models
# ------------------------------------------------------------------------------
class EvaluatePlanRequest(BaseModel):
    trace_id: Optional[str] = None
    product_id: str
    proposed_infra_plan: Optional[Dict[str, Any]] = None
    budget_ceiling: Optional[float] = None
    # FD-4AG-b: the architect's typed compute record (architect response `architect_compute_intent`). Optional and
    # subordinate (FD-4AG-b-r F5): the gated record persisted at pipeline_executions/{trace_id} always wins; this is
    # used only when there is no DB or no persisted record (harness / no-PROJECT_ID path).
    architect_compute_intent: Optional[Dict[str, Any]] = None


class EvaluatePlanJsonRequest(BaseModel):
    plan_json: Dict[str, Any]
    product_id: Optional[str] = None
    budget_ceiling: Optional[float] = None


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
        "service": "mcp-infracost-server",
        "budget_ceiling": float(os.getenv("BUDGET_CEILING_MONTHLY", "40.0")),
        "environment": os.getenv("ENVIRONMENT", "prod"),
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


# ------------------------------------------------------------------------------
# REST Endpoints (Invoked directly by Cloud Workflows & Gateway)
# ------------------------------------------------------------------------------
@app.post("/evaluate")
def evaluate_infra(req: EvaluatePlanRequest):
    """
    Invoked by Step 2 of castor_main_orchestrator workflow.
    Evaluates proposed infrastructure plan against the $40/mo budget ceiling.
    """
    try:
        trace_id = req.trace_id or "auto-trace"
        return calculator.evaluate_infra_plan(
            product_id=req.product_id,
            trace_id=trace_id,
            proposed_infra_plan=req.proposed_infra_plan,
            budget_ceiling=req.budget_ceiling,
            compute_intent=req.architect_compute_intent,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/evaluate-plan-json")
def evaluate_plan_json(req: EvaluatePlanJsonRequest):
    """Evaluates raw terraform show -json output for precise resource cost deltas."""
    try:
        # FD-4AG-b (AG-6): by keyword. Positionally the ceiling landed in `product_id` and the budget was ignored.
        return calculator.evaluate_terraform_plan_json(
            plan_json=req.plan_json, product_id=req.product_id, budget_ceiling=req.budget_ceiling)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
                        "name": "evaluate_terraform_cost",
                        "description": "Calculates monthly delta cost in USD for a proposed infrastructure plan or Terraform plan and checks budget ceilings.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "product_id": {"type": "string"},
                                "trace_id": {"type": "string"},
                                "proposed_infra_plan": {"type": "object"},
                                "budget_ceiling": {"type": "number"},
                                "architect_compute_intent": {"type": "object"},
                            },
                            "required": ["product_id"],
                        },
                    }
                ]
            },
        }

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        try:
            if tool_name == "evaluate_terraform_cost":
                result = calculator.evaluate_infra_plan(
                    product_id=arguments["product_id"],
                    trace_id=arguments.get("trace_id", "auto-trace"),
                    proposed_infra_plan=arguments.get("proposed_infra_plan"),
                    budget_ceiling=arguments.get("budget_ceiling"),
                    compute_intent=arguments.get("architect_compute_intent"),
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


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
