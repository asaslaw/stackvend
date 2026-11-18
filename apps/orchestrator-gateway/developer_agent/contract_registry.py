"""
Project Castor: Wave 0 Shared Contract Registry
Generates and distributes immutable shared Pydantic data models, OpenAPI contracts,
and Pub/Sub event schemas across all microservices before junior developer workers write code.
Eliminates Vector 6 (Microservice Contract Drift) and Vector 9 (Architectural Amnesia).
"""

import ast
import logging
import os
import re
from pathlib import PurePosixPath
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger("castor-contract-registry")

# AC-6: the statement kinds a lead contract may consist of to be inlined as code. Text that merely parses (a route
# list `GET /api/v1/items` is a division, an env list `A, B` a tuple) is not a definition and is commented instead.
DEFINITION_NODES = (ast.Import, ast.ImportFrom, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Assign,
                    ast.AnnAssign, ast.Pass) + ((ast.TypeAlias,) if hasattr(ast, "TypeAlias") else ())


def _is_definition(node: ast.stmt) -> bool:
    """One statement is a definition: an exact DEFINITION_NODES type (a `from __future__` import excluded: it is only
    valid at the top of a file, and the contract lands mid-file), a docstring, or an `if` / `try` (e.g.
    `if TYPE_CHECKING:`, `try: ... except ImportError:`) whose every branch is definitions only."""
    if isinstance(node, ast.ImportFrom) and node.module == "__future__":
        return False
    if isinstance(node, DEFINITION_NODES):
        return True
    if isinstance(node, ast.Expr):
        return isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
    if isinstance(node, ast.If):
        return _all_definitions(node.body) and _all_definitions(node.orelse)
    if isinstance(node, ast.Try):
        return (_all_definitions(node.body) and all(_all_definitions(h.body) for h in node.handlers)
                and _all_definitions(node.orelse) and _all_definitions(node.finalbody))
    return False


def _all_definitions(stmts) -> bool:
    return all(_is_definition(n) for n in stmts)


def is_definitions_only(tree: ast.Module) -> bool:
    """True when every top-level statement is a definition (`_is_definition`: exact `ast` node types; no text
    matching)."""
    return _all_definitions(tree.body)


# SCHEMAS-COLLISION (owner 10-28): the files the registry writes, as exact paths. `apps/<svc>/schemas/` is a regular
# package (its __init__.py is platform-owned), so a module `apps/<svc>/schemas.py` beside it is never imported (CPython
# imports a regular package before a same-named module). The lead plan may assign neither (`reserved_assignments`).
GLOBAL_CONTRACT_MODULE = "contracts/schemas.py"
GLOBAL_CONTRACT_INIT = "contracts/__init__.py"
SCHEMAS_PACKAGE = "schemas"
CONTRACTS_MODULE = "contracts"


def service_contract_path(svc: str) -> str:
    return f"apps/{svc}/{SCHEMAS_PACKAGE}/{CONTRACTS_MODULE}.py"


def service_init_path(svc: str) -> str:
    return f"apps/{svc}/{SCHEMAS_PACKAGE}/__init__.py"


def plan_services(tasks: Iterable[Any], product_id: str) -> List[str]:
    """The services the registry distributes into: the second component of every assigned `apps/...` path (sorted);
    with none, the product id's service name. Exactly the set lead_orchestrator built inline before (refactor)."""
    detected: Set[str] = set()
    for t in tasks:
        for f in getattr(t, "assigned_files", None) or ():
            if f.startswith("apps/"):
                parts = f.split("/")
                if len(parts) >= 2 and parts[1]:
                    detected.add(parts[1])
    if not detected:
        detected.add(product_id.lower().replace("_", "-"))
    return sorted(detected)


def registry_paths(services: Iterable[str]) -> FrozenSet[str]:
    """Every path `extract_and_generate_contracts` writes for these services (pinned equal by a test)."""
    out = {GLOBAL_CONTRACT_MODULE, GLOBAL_CONTRACT_INIT}
    for svc in services:
        clean = svc.strip()
        if clean:
            out |= {service_contract_path(clean), service_init_path(clean)}
    return frozenset(out)


def reserved_paths(services: Iterable[str]) -> FrozenSet[str]:
    """The registry's own files plus, for each package it writes, the same-named module that package would shadow
    (`apps/<svc>/schemas.py`, `contracts.py`). Derived from the paths with PurePosixPath, no text rule."""
    owned = registry_paths(services)
    shadowed = {PurePosixPath(p).parent.as_posix() + ".py" for p in owned if PurePosixPath(p).name == "__init__.py"}
    return frozenset(owned | shadowed)


def _norm(path: str) -> str:
    return PurePosixPath(path).as_posix() if isinstance(path, str) and path else ""


def reserved_assignments(tasks: Iterable[Any], product_id: str) -> List[Tuple[str, str]]:
    """(task_id, path) of every assigned file the plan may not own: a registry file or a module a registry package
    shadows (SCHEMAS-COLLISION). Paths are compared normalized (`./apps/x/schemas.py` is `apps/x/schemas.py`)."""
    tasks = list(tasks)
    reserved = reserved_paths(plan_services(tasks, product_id))
    out: List[Tuple[str, str]] = []
    for t in tasks:
        for f in getattr(t, "assigned_files", None) or ():
            if _norm(f) in reserved:
                out.append((str(getattr(t, "task_id", "")), f))
    return out


def schema_submodules(svc: str, assigned_files: Iterable[str]) -> List[str]:
    """The module names of the plan-assigned `apps/<svc>/schemas/<name>.py` files (direct children only, sorted):
    importable names (`str.isidentifier`, not a keyword), never a dunder stem (`__init__`, `__main__`, ...) nor the
    registry's own `contracts`."""
    import keyword
    names: Set[str] = set()
    pkg = PurePosixPath("apps", svc, SCHEMAS_PACKAGE)
    for f in assigned_files or ():
        p = PurePosixPath(_norm(f))
        if p.parent == pkg and p.suffix == ".py":
            stem = p.stem
            dunder = stem.startswith("__") and stem.endswith("__")   # __init__, __main__, ... (review N2)
            if stem.isidentifier() and not keyword.iskeyword(stem) and not dunder and stem != CONTRACTS_MODULE:
                names.add(stem)
    return sorted(names)


def render_service_init(submodules: Iterable[str] = ()) -> str:
    """`apps/<svc>/schemas/__init__.py`. Without plan-assigned schema modules: `from .contracts import *` (as before).
    With them (SCHEMAS-COLLISION): the contracts first (a module that imports a contract name from `schemas` while the
    package initializes finds it bound), each module's names, then the contracts again, so every name that resolved
    before resolves to the same object and the modules' own names now resolve too (`from schemas import Name`)."""
    subs = list(submodules)
    if not subs:
        return "from .contracts import *\n"
    lines = ["from .contracts import *",
             "# Platform re-export of the plan's schemas/<name>.py modules; the contracts last, so each contract name",
             "# keeps its contract binding."]
    lines += [f"from .{m} import *" for m in subs]
    lines.append("from .contracts import *")
    return "\n".join(lines) + "\n"


def init_services(paths: Iterable[str]) -> List[str]:
    """The services whose `apps/<svc>/schemas/__init__.py` is among these paths (exact path components, sorted)."""
    out: Set[str] = set()
    for p in paths:
        parts = PurePosixPath(_norm(p)).parts
        if len(parts) == 4 and parts[0] == "apps" and parts[2:] == (SCHEMAS_PACKAGE, "__init__.py"):
            out.add(parts[1])
    return sorted(out)


def rerender_service_inits(tree: Dict[str, str], wave0_files: Iterable[str], assigned_files: Iterable[str]) -> None:
    """SCHEMAS-COLLISION review F1: after the swarm, each Wave 0 `schemas/__init__.py` in `tree` is rendered again from
    the assigned schema modules the juniors actually produced (a junior may omit an assigned file on its last attempt),
    so the init never imports an absent module. Every module produced -> the same text as the Wave 0 render."""
    produced = [f for f in assigned_files if f in tree]
    for svc in init_services(wave0_files):
        path = service_init_path(svc)
        if path in tree:
            tree[path] = render_service_init(schema_submodules(svc, produced))


class SharedContractRegistry:
    """
    Manages the lifecycle of shared data schemas and event contracts:
    1. Extracts contract definitions from Lead Orchestrator WBS / Architect DAG.
    2. Synthesizes canonical, typed Pydantic models for shared event envelopes.
    3. Distributes contract files into each microservice (`apps/<svc>/schemas/contracts.py`).
    4. Automatically binds contract files to junior tasks as surgical read_dependencies.
    """

    DEFAULT_BASE_CONTRACT = '''"""
Shared Domain & Event Contracts
Auto-generated by StackVend Wave 0 Contract Registry.
All microservices compile against this shared schema to guarantee type parity.
"""
from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Set, Union
from uuid import UUID
from pydantic import BaseModel as _PydanticBaseModel, ConfigDict, Field

try:
    from pydantic import EmailStr
except Exception:
    EmailStr = str


class BaseModel(_PydanticBaseModel):
    """Canonical base model with universal ORM attribute serialization."""
    model_config = ConfigDict(from_attributes=True)


class BaseEventEnvelope(BaseModel):
    """Canonical CloudEvents-compliant event envelope."""
    event_id: str = Field(..., description="Unique event identifier (UUID v4)")
    event_type: str = Field(..., description="Fully qualified event type, e.g. domain.entity.action")
    source: str = Field(default="castor.workload", description="Originating producer service")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC creation timestamp"
    )
    payload: Dict[str, Any] = Field(default_factory=dict, description="Event payload body")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Tracing and audit headers")


class StandardApiResponse(BaseModel):
    """Standardized REST API response wrapper."""
    success: bool = Field(default=True)
    status_code: int = Field(default=200)
    data: Optional[Any] = Field(default=None)
    error_message: Optional[str] = Field(default=None)
'''

    def __init__(self, product_id: str):
        self.product_id = product_id

    def extract_and_generate_contracts(
        self,
        shared_contracts: Optional[Dict[str, Any]],
        detected_services: List[str],
        spec_text: str = "",
        assigned_files: Iterable[str] = (),
    ) -> Dict[str, str]:
        """
        Synthesizes the shared contract code and returns a file map:
        { "contracts/schemas.py": <content>, "apps/<svc>/schemas/contracts.py": <content>, ... }
        ``assigned_files`` (SCHEMAS-COLLISION): the plan's assigned paths; each `apps/<svc>/schemas/<name>.py` among
        them is re-exported from that service's `schemas/__init__.py` (`render_service_init`). Empty: as before.
        """
        assigned_files = list(assigned_files or ())
        contract_code_parts = [self.DEFAULT_BASE_CONTRACT]

        # Ingest custom shared contracts if emitted by Lead Developer
        if shared_contracts and isinstance(shared_contracts, dict):
            contract_code_parts.append("\n# Custom Workload Contracts from Lead Architect")
            for name, definition in shared_contracts.items():
                if isinstance(definition, str) and definition.strip():
                    clean_def = definition.strip()
                    # Strip markdown code fences if present
                    unfenced = re.sub(r'^```(?:python)?\s*\n', '', clean_def, flags=re.MULTILINE)
                    unfenced = re.sub(r'\n```\s*$', '', unfenced, flags=re.MULTILINE).strip()

                    is_valid_code = False
                    try:
                        is_valid_code = is_definitions_only(ast.parse(unfenced))  # AC-6: definitions only
                    except SyntaxError:
                        is_valid_code = False
                    if is_valid_code:
                        clean_def = unfenced

                    if not is_valid_code:
                        commented_lines = "\n".join(
                            f"# {line}" if line.strip() and not line.strip().startswith("#") else line
                            for line in clean_def.splitlines()
                        )
                        clean_def = f"# Contract: {name}\n{commented_lines}\n"
                    contract_code_parts.append(clean_def)

        final_contract_code = "\n\n".join(contract_code_parts) + "\n"

        contract_files: Dict[str, str] = {
            GLOBAL_CONTRACT_MODULE: final_contract_code,
            GLOBAL_CONTRACT_INIT: "from .schemas import *\n",
        }

        # Distribute into each service's local schemas directory
        for svc in detected_services:
            clean_svc = svc.strip()
            if clean_svc:
                svc_path = service_contract_path(clean_svc)
                contract_files[svc_path] = final_contract_code
                init_path = service_init_path(clean_svc)
                contract_files[init_path] = render_service_init(schema_submodules(clean_svc, assigned_files))

        logger.info(
            f"Wave 0 Shared Contract Registry generated {len(contract_files)} files across "
            f"{len(detected_services)} microservices."
        )
        return contract_files

    def inject_contracts_into_wbs_tasks(
        self,
        tasks: List[Any],
        contract_files: Dict[str, str],
    ) -> None:
        """
        Mutates WBS tasks in-place:
        Adds local contract paths into `read_dependencies` for Wave 1, Wave 2, and Wave 3 tasks.
        """
        for task in tasks:
            assigned = getattr(task, "assigned_files", []) or []
            read_deps = getattr(task, "read_dependencies", []) or []
            
            # Determine which service this task targets
            task_service = None
            for f in assigned:
                if f.startswith("apps/"):
                    parts = f.split("/")
                    if len(parts) >= 2:
                        task_service = parts[1]
                        break

            # If task belongs to a service, ensure it reads its local contract schema
            if task_service:
                svc_contract = service_contract_path(task_service)
                if svc_contract in contract_files and svc_contract not in read_deps:
                    read_deps.append(svc_contract)
            else:
                # Top-level task: inject global contracts/schemas.py
                if "contracts/schemas.py" in contract_files and "contracts/schemas.py" not in read_deps:
                    read_deps.append("contracts/schemas.py")

            setattr(task, "read_dependencies", read_deps)
