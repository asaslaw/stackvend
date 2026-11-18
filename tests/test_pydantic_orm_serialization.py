"""
Unit & Regression Tests for Universal Pydantic ORM Serialization Compatibility.
Validates that shared contract models automatically inherit from_attributes=True,
allowing SQLAlchemy ORM objects to be validated by Pydantic models without ValidationError.

FD-4AE: the post-QA rewrite `ensure_pydantic_orm_compatibility` (terraform MCP build path) was DELETED together with
its three tests. `from_attributes=True` is owned by the generation contract (SharedContractRegistry's base contract,
tested below), which runs before QA.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import ast
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../mcp-servers/terraform")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../apps/orchestrator-gateway")))

from developer_agent.contract_registry import SharedContractRegistry


class MockORMOrganization:
    """Simulates a SQLAlchemy ORM model instance with attributes."""
    def __init__(self, id="org-123", name="Acme Corp", slug="acme-corp", created_at=None):
        self.id = id
        self.name = name
        self.slug = slug
        self.created_at = created_at or datetime.now(timezone.utc)


def test_contract_registry_default_base_contract():
    """Verify that SharedContractRegistry.DEFAULT_BASE_CONTRACT generates BaseModel with from_attributes=True."""
    registry = SharedContractRegistry(product_id="test-product")
    contracts = registry.extract_and_generate_contracts(
        shared_contracts=None,
        detected_services=["billing-api"],
    )

    base_code = contracts["contracts/schemas.py"]
    assert "class BaseModel(_PydanticBaseModel):" in base_code
    assert "from_attributes=True" in base_code

    # Verify that the generated code parses cleanly
    ast.parse(base_code)

    # Execute and verify runtime behavior
    exec_globals = {}
    exec(base_code, exec_globals)
    BaseModel = exec_globals["BaseModel"]

    class TestReadModel(BaseModel):
        id: str
        name: str

    mock_obj = MockORMOrganization()
    model = TestReadModel.model_validate(mock_obj)
    assert model.id == "org-123"
    assert model.name == "Acme Corp"
