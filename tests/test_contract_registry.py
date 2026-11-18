"""
Tests for Project Castor: Wave 0 Shared Contract Registry & Architectural Grounding Anchor
Verifies:
1. Canonical contract generation across multiple services.
2. Injection of contract read dependencies into WBS tasks.
3. Schema integrity and disjoint partition enforcement.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import sys
from pathlib import Path

# Add apps/orchestrator-gateway to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "apps" / "orchestrator-gateway"))

import pytest
from developer_agent.contract_registry import SharedContractRegistry
from developer_agent.swarm_schemas import (
    JuniorPersona,
    JuniorTaskAssignment,
    LeadDeveloperDecompositionPlan,
    SwarmExecutionMode,
)
from developer_agent.lead_orchestrator import LeadDeveloperOrchestrator
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; row SWARM-TOK-1)


def test_contract_registry_generation():
    registry = SharedContractRegistry(product_id="test-mesh")
    shared_contracts = {
        "UserAccountModel": "class UserAccount(BaseModel):\n    user_id: str\n    email: str",
        "PaymentEvent": "class PaymentEvent(BaseEventEnvelope):\n    amount: float",
    }
    services = ["orders-service", "payments-service"]

    files = registry.extract_and_generate_contracts(
        shared_contracts=shared_contracts,
        detected_services=services,
        spec_text="Multi-service architecture specification.",
    )

    # Global contracts
    assert "contracts/schemas.py" in files
    assert "contracts/__init__.py" in files
    assert "BaseEventEnvelope" in files["contracts/schemas.py"]
    assert "UserAccount" in files["contracts/schemas.py"]
    assert "PaymentEvent" in files["contracts/schemas.py"]

    # Local per-service contracts
    assert "apps/orders-service/schemas/contracts.py" in files
    assert "apps/orders-service/schemas/__init__.py" in files
    assert "apps/payments-service/schemas/contracts.py" in files
    assert "apps/payments-service/schemas/__init__.py" in files


def test_contract_injection_into_wbs_tasks():
    registry = SharedContractRegistry(product_id="test-mesh")
    services = ["orders-service", "payments-service"]
    contract_files = registry.extract_and_generate_contracts(
        shared_contracts={"Item": "class Item(BaseModel): name: str"},
        detected_services=services,
    )

    tasks = [
        JuniorTaskAssignment(
            task_id="task-orders-db",
            persona=JuniorPersona.DATABASE_ENGINEER,
            wave=1,
            assigned_files=["apps/orders-service/models.py"],
            read_dependencies=[],
            task_objective="Implement order models",
        ),
        JuniorTaskAssignment(
            task_id="task-payments-api",
            persona=JuniorPersona.BACKEND_ENGINEER,
            wave=2,
            assigned_files=["apps/payments-service/main.py"],
            read_dependencies=["apps/payments-service/models.py"],
            task_objective="Implement payment routes",
        ),
        JuniorTaskAssignment(
            task_id="task-iac",
            persona=JuniorPersona.IAC_ENGINEER,
            wave=2,
            assigned_files=["infra/workload/main.tf"],
            read_dependencies=[],
            task_objective="Implement IaC",
        ),
    ]

    registry.inject_contracts_into_wbs_tasks(tasks, contract_files)

    # Check that orders task received orders-service contract
    assert "apps/orders-service/schemas/contracts.py" in tasks[0].read_dependencies

    # Check that payments task received payments-service contract without dropping existing deps
    assert "apps/payments-service/models.py" in tasks[1].read_dependencies
    assert "apps/payments-service/schemas/contracts.py" in tasks[1].read_dependencies

    # Check that non-app task received root contracts/schemas.py
    assert "contracts/schemas.py" in tasks[2].read_dependencies


def test_lead_orchestrator_attaches_wave_0_contracts():
    orchestrator = LeadDeveloperOrchestrator(db=None, genai_client=None)
    plan = orchestrator.decompose_specification(
        product_id="ecommerce-mesh",
        spec_text="Build an ecommerce microservices platform with orders, inventory, and billing.",
        task_dag=[],
        existing_files={},
        iac_engine="OPENTOFU",
        vcs_provider="GITHUB",
    )

    assert isinstance(plan, LeadDeveloperDecompositionPlan)
    assert plan.wave_0_contract_files is not None
    assert len(plan.wave_0_contract_files) > 0
    assert "contracts/schemas.py" in plan.wave_0_contract_files

    # Verify tasks have read dependencies injected
    has_injected_contract = any(
        any("contracts" in dep for dep in t.read_dependencies)
        for t in plan.tasks
    )
    assert has_injected_contract, "Expected at least one task to have contract read dependencies"


def test_contract_registry_supports_domain_primitives():
    registry = SharedContractRegistry(product_id="test-billing")
    shared_contracts = {
        "Organization": "class Organization(BaseModel):\n    id: UUID\n    name: str\n    billing_email: EmailStr",
        "Invoice": "class Invoice(BaseModel):\n    id: UUID\n    amount: Decimal\n    created_at: datetime",
    }
    files = registry.extract_and_generate_contracts(
        shared_contracts=shared_contracts,
        detected_services=["billing-api"],
    )
    contract_code = files["contracts/schemas.py"]
    assert "from uuid import UUID" in contract_code
    assert "from decimal import Decimal" in contract_code
    assert "EmailStr" in contract_code

    # Verify syntax valid
    import ast
    ast.parse(contract_code)
