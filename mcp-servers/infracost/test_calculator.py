"""
Unit Tests for mcp-infracost-server
Tests pricing estimates, budget ceiling evaluations, destructive change detection, and API endpoints.
"""

from fastapi.testclient import TestClient
import pytest

from calculator import InfracostCalculator
from main import app


@pytest.fixture
def calculator():
    return InfracostCalculator(default_budget_ceiling=40.0)


def test_health_check():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_evaluate_infra_plan_under_budget(calculator):
    plan = {
        "tasks": [
            {"title": "Provision Cloud Run", "description": "Deploy stateless Cloud Run service"}
        ]
    }
    # FD-4AG-b: priced from the typed compute kind (no typed record would require approval, F2)
    intent = {"compute_archetype": "cloudrun", "target_compute_services": ["demo-app"]}
    res = calculator.evaluate_infra_plan("demo-app", "trace-1", plan, compute_intent=intent)
    assert res["monthly_cost_estimate"] == "+$0.00/mo"
    assert res["is_under_budget"] is True
    assert res["requires_human_approval"] is False


def test_evaluate_infra_plan_over_budget(calculator):
    plan = {
        "tasks": [
            {"title": "Provision GKE Cluster", "description": "Create high-performance Kubernetes cluster"}
        ]
    }
    # FD-4AG-b: priced from the typed compute kind, not the description text
    intent = {"compute_archetype": "gke-autopilot", "target_compute_services": ["heavy-app"]}
    res = calculator.evaluate_infra_plan("heavy-app", "trace-2", plan, compute_intent=intent)
    assert res["monthly_cost_delta_usd"] >= 70.0
    assert res["is_under_budget"] is False
    assert res["requires_human_approval"] is True
    assert "Tier 3 Human-in-the-Loop approval required" in res["risk_assessment"]


def test_evaluate_terraform_plan_json_destructive(calculator):
    plan_json = {
        "resource_changes": [
            {
                "type": "google_sql_database_instance",
                "name": "primary_db",
                "change": {"actions": ["delete"]},
            }
        ]
    }
    res = calculator.evaluate_terraform_plan_json(plan_json)
    assert res["has_destructive_change"] is True
    assert res["requires_human_approval"] is True


def test_rest_evaluate_endpoint():
    client = TestClient(app)
    payload = {
        "trace_id": "test-tr",
        "product_id": "auth-service",
        "proposed_infra_plan": {
            "tasks": [{"title": "Cloud Run", "description": "serverless service"}]
        },
        "architect_compute_intent": {"compute_archetype": "cloudrun", "target_compute_services": ["auth-service"]},
    }
    response = client.post("/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["monthly_cost_estimate"].startswith("+$0.00/mo")
    assert data["requires_human_approval"] is False


def test_mcp_tools_list():
    client = TestClient(app)
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 200
    tools = response.json()["result"]["tools"]
    assert len(tools) >= 1
    assert tools[0]["name"] == "evaluate_terraform_cost"
