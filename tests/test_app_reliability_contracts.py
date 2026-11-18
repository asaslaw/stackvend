"""App-code reliability AC-2 / AC-3 / AC-6 (docs/planning/app-code-reliability-plan.md; register rows AC-2, AC-3, AC-6).

AC-2: the lead prompt and the topology contract state the platform's Cloud Run startup probe path (GET /health, the
      compute-cloudrun module's `health_check_path` default; one source: validators/container.HEALTH_PATH).
AC-3: the TEST_ENGINEER persona prompt says how to write several context managers in one `with` (Python 3.13).
AC-6: the contract registry inlines only real Python definitions (exact `ast` node types) and imports Enum/Literal.

Negatives: prompts without a Cloud Run service, every other persona prompt and the lead system prompt are
byte-identical to before (snapshots taken from origin/main 30270c8); the registry's custom section is byte-identical
for the 23 recorded 10-14 lead answers that were already definitions-only. Hermetic, $0.
"""
import hermetic_guard  # noqa: F401  (first import)

import ast
import hashlib
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

import hcl2  # noqa: E402
from pyflakes import checker  # noqa: E402

from developer_agent import topology_wiring as tw  # noqa: E402
from developer_agent.compute_intent import ComputeIntent  # noqa: E402
from developer_agent.contract_registry import SharedContractRegistry, is_definitions_only  # noqa: E402
from developer_agent.juniors import prompt_registry  # noqa: E402
from developer_agent.lead_orchestrator import LEAD_ORCHESTRATOR_SYSTEM_PROMPT, LeadDeveloperOrchestrator  # noqa: E402
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; row SWARM-TOK-1)
from developer_agent.validators import container  # noqa: E402
from visible_rename_render import pre_visible_rename  # noqa: E402  (VISIBLE-RENAME pin normalization)
from shared.service_topology import validate_service_topology  # noqa: E402


def _sha(text):
    # VISIBLE-RENAME (owner 10-26): pins predate the StackVend persona wording (tests/visible_rename_render.py).
    return hashlib.sha256(pre_visible_rename(text).encode()).hexdigest()


def _topo(services, primary, edges=()):
    raw = {"services": [{"name": n, "kind": k} for n, k in services], "primary_service": primary,
           "edges": [{"caller": a, "callee": b, "protocol": p} for a, b, p in edges], "resources": []}
    vt, diags = validate_service_topology(raw, product_id="shop")
    assert vt is not None, [d.code for d in diags]
    return vt


TOPOLOGIES = {
    "two_cloudrun": lambda: _topo([("api", "cloudrun"), ("core", "cloudrun")], "api", [("api", "core", "http")]),
    "gke_plus_event_worker": lambda: _topo([("cluster", "gke-autopilot"), ("jobs", "event-worker")], "cluster"),
    "cloudrun_launches_gce_worker": lambda: _topo([("api", "cloudrun"), ("render", "gce-worker")], "api",
                                                  [("api", "render", "launch")]),
}
with open(os.path.join(FIXTURES, "ac2_topology_contract_pre.json")) as _f:
    PRE_AC2_CONTRACT = json.load(_f)   # topology_contract_rule output on origin/main 30270c8
PROBE_CLAUSE = "; it must serve `GET /health` returning 200 (the platform's startup probe)"


# ------------------------------------------------------------------------------------------------------------ AC-2
def test_ac2_probe_path_has_one_source_equal_to_the_module_default():
    with open(os.path.join(REPO_ROOT, "infra", "modules", "compute-cloudrun", "variables.tf")) as f:
        variables = {k: v for block in hcl2.load(f)["variable"] for k, v in block.items()}
    assert tw.health_path() == container.HEALTH_PATH == variables["health_check_path"]["default"] == "/health"


def test_ac2_probe_rule_text_and_empty_when_no_cloud_run_service():
    assert tw.health_probe_rule([]) == "" and tw.health_probe_rule(None) == ""
    assert tw.health_probe_rule(["api", "core"]) == (
        "PLATFORM PROBE: the platform's Cloud Run startup probe calls `GET /health` on `api`, `core`; each of these "
        "services must serve `GET /health` returning 200 (other health routes may be added, never instead). Copy "
        "this line into every task that writes these services' routes.")


def test_ac2_cloud_run_services_come_from_typed_facts_only():
    intent = lambda **kw: SimpleNamespace(**{"topology": None, "archetype": "cloudrun", "service_names": (), **kw})
    assert tw.cloudrun_probe_services(intent(topology=TOPOLOGIES["two_cloudrun"]())) == ["api", "core"]
    assert tw.cloudrun_probe_services(intent(topology=TOPOLOGIES["gke_plus_event_worker"](),
                                             archetype="gke-autopilot")) == []
    assert tw.cloudrun_probe_services(intent(topology=TOPOLOGIES["cloudrun_launches_gce_worker"]())) == ["api"]
    # legacy single-archetype path (no topology), on the real ComputeIntent: service_names[1:] are Cloud Run
    # secondaries for every archetype (compute_intent.py service-list contract); the primary only when cloudrun
    legacy = lambda archetype, names: ComputeIntent(archetype=archetype, service_names=names, source="architect",
                                                    archetype_source="test")
    assert tw.cloudrun_probe_services(legacy("cloudrun", ("shop", "admin"))) == ["shop", "admin"]
    for archetype in ("gke-autopilot", "event-worker", "gce-bastion", "foundation-only"):
        assert tw.cloudrun_probe_services(legacy(archetype, ("shop",))) == []
    for archetype in ("gke-autopilot", "event-worker", "gce-bastion"):   # review F1: Cloud Run edge secondaries
        assert tw.cloudrun_probe_services(legacy(archetype, ("cluster", "edge"))) == ["edge"]
    assert tw.cloudrun_probe_services(legacy("foundation-only", ("shop", "edge"))) == []


def test_ac2_topology_contract_adds_the_probe_only_on_cloud_run_lines():
    for name, make in TOPOLOGIES.items():
        text = tw.topology_contract_rule(make())
        vt = make()
        cloudrun = [n for n in vt.names if vt.kind(n) == "cloudrun"]
        assert text.count(PROBE_CLAUSE) == len(cloudrun), name
        for line in text.splitlines():
            served = PROBE_CLAUSE in line
            assert served == any(line.startswith(f"- `{n}` (cloudrun,") for n in cloudrun), (name, line)
        # Do No Harm: everything except the new clauses (AC-2 probe; PWB-4 GKE manifest) is byte-identical to before
        assert _strip_gke_clauses(text.replace(PROBE_CLAUSE, ""), vt) == PRE_AC2_CONTRACT[name], name


def _strip_gke_clauses(text, vt):
    for n in vt.names:
        if vt.kind(n) == "gke-autopilot":
            assert text.count(tw.gke_manifest_clause(n)) == 1, n
            text = text.replace(tw.gke_manifest_clause(n), "")
    return text


def test_ac2_topology_without_cloud_run_is_byte_identical():
    """Without a Cloud Run service no probe clause is added; the only change since AC-2 is the PWB-4 GKE clause."""
    vt = TOPOLOGIES["gke_plus_event_worker"]()
    assert _strip_gke_clauses(tw.topology_contract_rule(vt), vt) == PRE_AC2_CONTRACT["gke_plus_event_worker"]
    assert tw.topology_contract_rule(None) == ""
    assert tw.topology_contract_rule(_topo([("shop", "cloudrun")], "shop")) == ""   # single service: lead line only


def _lead_prompt(service_names=(), **kw):
    seen = []

    def gen(model, contents, config):
        seen.append(contents)
        raise ValueError("captured")
    client = MagicMock()
    client.models.generate_content.side_effect = gen
    with patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent", return_value=["m"]):
        LeadDeveloperOrchestrator(genai_client=client, model_name="m").decompose_specification(
            product_id="shop", spec_text="Spec", task_dag=[{"task_id": "s"}], service_names=service_names, **kw)
    return seen[0]


def test_ac2_lead_prompt_gains_the_probe_line_only_when_given():
    base = _lead_prompt(("shop",))
    assert _lead_prompt(("shop",), probe_rule="") == base and _lead_prompt(("shop",), probe_rule=None) == base
    rule = tw.health_probe_rule(["shop"])
    assert _lead_prompt(("shop",), probe_rule=rule) == base + "\n\n" + rule
    # multi-service: test layout, then the probe line, then the topology contract
    vt = TOPOLOGIES["two_cloudrun"]()
    contract = tw.topology_contract_rule(vt)
    multi_base = _lead_prompt(("api", "core"), wiring_contract=contract)
    multi = _lead_prompt(("api", "core"), wiring_contract=contract, probe_rule=tw.health_probe_rule(["api", "core"]))
    head, _, tail = multi_base.partition("\n\n" + contract)
    assert multi == head + "\n\n" + tw.health_probe_rule(["api", "core"]) + "\n\n" + contract + tail


# SCHEMAS-COLLISION (owner 10-28): the one block added to the lead system prompt (invariant 5); without it the prompt
# is byte-identical to the AC-2 pin.
SCHEMAS_LEAD_RULE = (
    "5. **PLATFORM-OWNED SHARED SCHEMAS PACKAGE**:\n"
    "   - The platform writes the Wave 0 shared contracts itself: `contracts/__init__.py`, `contracts/schemas.py` and, "
    "in every service, the package `apps/<service>/schemas/` (`schemas/__init__.py`, `schemas/contracts.py`). NEVER "
    "assign those files, and NEVER assign a module `apps/<service>/schemas.py` (Python imports the package, so that "
    "module would never load).\n"
    "   - Put further shared models in `apps/<service>/schemas/<name>.py`: the platform re-exports each of them from "
    "`schemas/__init__.py`, so `from schemas import Name` works in every file of the service.\n")
# ... and the one sentence edit of the backend persona's import standard (also the DATABASE_ENGINEER prompt).
SCHEMAS_BACKEND_OLD = ("(e.g. `routers.py`, `schemas.py`, `services.py`), use direct local imports: "
                       "`from routers import router`, `from schemas import EventAuditRecord`. ")
SCHEMAS_BACKEND_NEW = ("(e.g. `routers.py`, `services.py`, the shared `schemas/` package), use direct local imports: "
                       "`from routers import router`, `from schemas import EventAuditRecord`. Shared models live in "
                       "the platform's `schemas/` package (`schemas/contracts.py` and the plan's `schemas/<name>.py` "
                       "modules, all re-exported by `schemas/__init__.py`); never write a `schemas.py` module. ")


def test_ac2_lead_system_prompt_is_unchanged():
    assert LEAD_ORCHESTRATOR_SYSTEM_PROMPT.count(SCHEMAS_LEAD_RULE) == 1
    assert (_sha(LEAD_ORCHESTRATOR_SYSTEM_PROMPT.replace(SCHEMAS_LEAD_RULE, ""))
            == "24d9eca33d949061a950f963ba9f445554ee7aa2f2cf0475d3285972d6406a86")


# ------------------------------------------------------------------------------------------------------------ AC-3
OVERBROAD_IAC_OLD = ("required access if non-standard (e.g. `roles/secretmanager.secretAccessor`).")
OVERBROAD_IAC_NEW = ("required access if non-standard, on the one resource it uses (e.g. "
                     "`roles/secretmanager.secretAccessor` through a `google_secret_manager_secret_iam_member` on that "
                     "secret). Never grant a Secret Manager or IAM-admin role at project level "
                     "(`google_project_iam_member`).")
PRE_AC3_PERSONA_SHA = {   # origin/main 30270c8
    "BACKEND_ENGINEER": "c10366f111492575c589ab0392d024df06145655fcfabf2fc14b6ac93cb1e3a7",
    "DATABASE_ENGINEER": "c10366f111492575c589ab0392d024df06145655fcfabf2fc14b6ac93cb1e3a7",
    "DEVOPS_ENGINEER": "ddea2bb0860b5afa58b674910ede060a7fe4be7f1f8d57b0da7aa1cb6ef5189a",
    "FRONTEND_ENGINEER": "2e78cb269dffd933b80eefa599b67c537ae306681bfc22661f2907177d56d8ab",
    "IAC_ENGINEER": "9e1f9c976b9a29cfface57737798408c803dae9fb95e31208e462aa6bf16c1ef",
}
AC3_RULE = ("   - Python 3.13: write several context managers in one `with` inside parentheses, e.g. "
            "`with (patch(a) as x, patch(b) as y):`, or as nested `with` blocks; a `with` line never ends with a "
            "comma.\n")


def test_ac3_test_persona_states_the_with_rule_once():
    prompt = prompt_registry.LOCAL_PROMPTS_MAP["TEST_ENGINEER"]
    assert prompt.count(AC3_RULE) == 1
    assert _sha(prompt) == "fb71b419bfe324092c8dbacae4c5d8b40c53aaf3c914283a123823b7d69ed25f"
    assert _sha(prompt.replace(AC3_RULE, "")) == "abeeb8e07afaca5fa00f0bb14786bb34dd3adb1e468b7c6fbf9e765684f07dd9"


def test_ac3_the_example_is_valid_and_the_banned_form_is_not():
    ast.parse("with (patch(a) as x, patch(b) as y):\n    pass\n")
    with pytest.raises(SyntaxError):   # the form TEST_ENGINEER wrote in 16 of 19 broken files (10-13 + 10-14)
        ast.parse("with patch(a) as x,\n     patch(b) as y:\n    pass\n")


def test_ac3_other_persona_prompts_are_byte_identical():
    # SCHEMAS-COLLISION: the backend / database persona differs from the pin only by its one import-standard edit
    assert prompt_registry.LOCAL_PROMPTS_MAP["BACKEND_ENGINEER"].count(SCHEMAS_BACKEND_NEW) == 1
    # OVERBROAD-SECRET-GRANT (owner 11-14): the IaC persona differs from the pin only by its one scoped-grant edit
    assert prompt_registry.LOCAL_PROMPTS_MAP["IAC_ENGINEER"].count(OVERBROAD_IAC_NEW) == 1
    got = {k: _sha(v.replace(SCHEMAS_BACKEND_NEW, SCHEMAS_BACKEND_OLD).replace(OVERBROAD_IAC_NEW, OVERBROAD_IAC_OLD))
           for k, v in prompt_registry.LOCAL_PROMPTS_MAP.items() if k != "TEST_ENGINEER"}
    assert got == PRE_AC3_PERSONA_SHA


# ------------------------------------------------------------------------------------------------------------ AC-6
def _custom(shared_contracts):
    text = SharedContractRegistry("p").extract_and_generate_contracts(shared_contracts, ["svc"])["contracts/schemas.py"]
    assert text.startswith(SharedContractRegistry.DEFAULT_BASE_CONTRACT)
    return text, text[len(SharedContractRegistry.DEFAULT_BASE_CONTRACT):]


def _undefined(src):
    w = checker.Checker(ast.parse(src), "contracts/schemas.py")
    return sorted({m.message_args[0] for m in w.messages if type(m).__name__ in ("UndefinedName", "UndefinedLocal")})


@pytest.mark.parametrize("value", [
    "GET /healthz",                                   # parses as a division
    "GET /api/v1/items, POST /api/v1/items",          # parses as a tuple of divisions
    "FIRESTORE_DATABASE, PUBSUB_TOPIC",               # parses as a tuple
    "configure()",                                    # a call is not a definition
    "class A(BaseModel):\n    x: int\n\nGET /health",  # one non-definition statement comments the whole value
    "if x:\n    GET / y",                                # review F2 negative: a branch that is not a definition
    "try:\n    from enum import StrEnum\nexcept ImportError:\n    configure()",   # one handler is not
    "from __future__ import annotations\nclass A(BaseModel):\n    x: int",         # F3: only valid at file top
])
def test_ac6_parse_accidental_text_is_commented(value):
    _, custom = _custom({"c": value})
    assert custom == "\n\n\n# Custom Workload Contracts from Lead Architect\n\n# Contract: c\n" + "\n".join(
        f"# {line}" if line.strip() else line for line in value.splitlines()) + "\n\n"
    assert not is_definitions_only(ast.parse(value))


@pytest.mark.parametrize("value", [
    "class Item(BaseModel):\n    name: str",
    '"""Models."""\nfrom typing import Tuple\nclass Status(str, Enum):\n    OK = "ok"\nLIMIT: int = 5\nX = 1\n'
    "def f():\n    return 1\nasync def g():\n    return 2",
    "# only a comment",
    # review F2: guarded definitions and PEP 695 aliases are definitions
    "if TYPE_CHECKING:\n    from typing import Tuple\nelse:\n    pass\nclass A(BaseModel):\n    x: int",
    "try:\n    from enum import StrEnum\nexcept ImportError:\n    class StrEnum(str, Enum):\n        pass\n"
    "finally:\n    pass",
    "type Ids = list[str]",
])
def test_ac6_definitions_are_inlined_unchanged(value):
    _, custom = _custom({"c": value})
    assert custom == "\n\n\n# Custom Workload Contracts from Lead Architect\n\n" + value.strip() + "\n"
    assert is_definitions_only(ast.parse(value))


def test_ac6_preamble_imports_enum_and_literal():
    text, _ = _custom({"m": 'class Status(str, Enum):\n    OK = "ok"\n\nclass R(BaseModel):\n    k: Literal["a"]'})
    assert "from enum import Enum\n" in SharedContractRegistry.DEFAULT_BASE_CONTRACT
    assert _undefined(text) == []


def test_ac6_recorded_lead_answers_exact_gate():
    """$0 gate: the 26 lead answers of the 10-14 fresh record (06-r1 never reached the lead)."""
    with open(os.path.join(FIXTURES, "ac6_lead_shared_contracts_1014.json")) as f:
        runs = json.load(f)["runs"]
    assert len(runs) == 26
    changed = set()
    for run, rec in runs.items():
        text, custom = _custom(rec["shared_contracts"])
        if _sha(custom) != rec["old_custom_sha256"]:
            changed.add(run)
        assert _undefined(text) == [], run   # before: 01-r1, 03-r1, 05-r2, 08-r1, 09-r2 had undefined names
    assert changed == {"01-r1", "08-r1", "09-r2"}   # prose that parsed (env list, route lists) is now commented
