"""
Unit Tests for Architect Agent
Tests Task DAG schemas, decomposition logic, fallback generation, and Markdown summary formatting.
"""

from unittest.mock import MagicMock, patch
import pytest

from handler import ArchitectAgent
from schemas import (
    ArchitectDecompositionResult,
    ArchitecturePlan,
    TaskCategory,
    TaskItem,
    TaskPriority,
)


@pytest.fixture
def sample_plan():
    return ArchitecturePlan(
        product_id="auth-service",
        project_tier=1,
        summary="Build OAuth2 Authentication Service",
        architecture_overview="FastAPI microservice with Firestore token store.",
        infra_tasks=[
            TaskItem(
                task_id="INFRA-01",
                title="Provision Cloud Run Service",
                category=TaskCategory.INFRA,
                target_files=["infra/workloads/auth-service/main.tf"],
                description="Create Cloud Run service resource in Terraform.",
                acceptance_criteria=["Valid Terraform syntax"],
                depends_on=[],
                assigned_agent="gcp-devops",
                priority=TaskPriority.HIGH,
            )
        ],
        code_tasks=[
            TaskItem(
                task_id="CODE-01",
                title="Implement Auth Endpoints",
                category=TaskCategory.CODE,
                target_files=["apps/auth-service/main.py"],
                description="Implement /login and /token endpoints.",
                acceptance_criteria=["Returns JWT token on valid credentials"],
                depends_on=["INFRA-01"],
                assigned_agent="developer",
                priority=TaskPriority.HIGH,
            )
        ],
        estimated_complexity="MEDIUM",
        requires_human_approval=False,
        risk_assessment="Low risk standard microservice.",
    )


def test_schema_serialization(sample_plan):
    data = sample_plan.model_dump()
    assert data["product_id"] == "auth-service"
    assert len(data["infra_tasks"]) == 1
    assert len(data["code_tasks"]) == 1
    assert data["requires_human_approval"] is False


def test_markdown_summary_generation(sample_plan):
    agent = ArchitectAgent(project_id="test-proj")
    summary = agent.generate_markdown_summary(sample_plan)
    assert "## 📋 StackVend Multi-Agent Execution Plan" in summary
    assert "**Product ID**: `auth-service`" in summary
    assert "INFRA-01" in summary
    assert "CODE-01" in summary
    assert "gcp-devops" in str(sample_plan.infra_tasks[0].assigned_agent)


def test_fallback_decomposition():
    agent = ArchitectAgent(project_id="test-proj")
    agent.genai_client = None
    agent.model = None
    result = agent.decompose(
        spec_text="Please build an analytics dashboard API",
        product_id="analytics-dashboard",
    )
    assert isinstance(result, ArchitectDecompositionResult)
    assert result.product_id == "analytics-dashboard"
    assert len(result.task_dag) >= 2
    assert result.architecture_plan.requires_human_approval is False


def test_decomposition_with_mock_model():
    agent = ArchitectAgent(project_id="test-proj")
    agent.genai_client = None
    mock_model = MagicMock()
    mock_response = MagicMock()
    mock_response.text = """{
        "product_id": "payment-api",
        "project_tier": 2,
        "summary": "Implement Stripe checkout endpoint",
        "architecture_overview": "Cloud Run webhook listener with PubSub dispatch.",
        "infra_tasks": [],
        "code_tasks": [
            {
                "task_id": "CODE-01",
                "title": "Add payment endpoint",
                "category": "CODE",
                "target_files": ["apps/payment/main.py"],
                "description": "Add /checkout route.",
                "acceptance_criteria": ["200 OK on valid payload"],
                "depends_on": [],
                "assigned_agent": "developer",
                "priority": "HIGH"
            }
        ],
        "estimated_complexity": "LOW",
        "requires_human_approval": false,
        "risk_assessment": "Standard low-risk feature addition."
    }"""
    mock_model.generate_content.return_value = mock_response
    agent.model = mock_model

    result = agent.decompose(
        spec_text="Specification text for payment API",
        product_id="payment-api",
    )
    assert result.product_id == "payment-api"
    assert len(result.task_dag) == 1
    assert result.task_dag[0].task_id == "CODE-01"
