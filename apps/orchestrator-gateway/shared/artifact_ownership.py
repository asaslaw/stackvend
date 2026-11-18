"""Who owns each artifact of a developer run (Wave 2 C0a; integration plan §1.2, lane 8B plan §5.1).

Ownership decides routing: platform-owned files are validated but never sent to the LLM (a finding there is a
PLATFORM_DEFECT), user-owned files are never repaired, healed or deleted (a finding there is a BROWNFIELD_CONFLICT),
LLM-authored files go back to the persona that wrote them. Classification is exact set membership over per-run sets
(no path patterns beyond Terraform's own override-file naming rule); nothing is guessed.

Rule (Step 1 RT F4): no file under infra/workload/ is ever deleted by the platform.

PLATFORM-RENDERED-FINDING + QA-FINDING-ON-UNOWNED-FILE (owner 11-13; review docs/planning/anti-whack-a-mole-review-1113.md
item 1): `classify_repository_file` is the one ownership predicate for a file of a committed / tested tree seen after the
developer's run (QA finding routing), across the whole tree (apps, tests, root files, infra, CI). It adds two classes:
PRIOR_BUILD (the platform wrote exactly these bytes in an earlier build: developer_agent.app_provenance history) and
UNKNOWN (no record says who wrote it). Neither is ever routed to the developer as a repair; who can change the file
decides the route (the caller: developer_agent.qa_repair).

QA-STOP-RENDER-SOURCES (owner 11-14; plan docs/planning/render-sources-routing-plan.md; diagnosis
docs/handoff/ex08-1114-qa-routing-diagnosis.md section 3): `RENDER_SOURCES` is the typed relation from each file the
platform renders to the typed sources it is computed from (who owns each source, and the code that reads it).
`REPAIR_THROUGH` is the explicit, exact map of the renders a QA finding is repaired through a developer document
(today only custom.tf.json -> iac_intent.json); every other render stays a typed stop whose message names the
sources and says whether the finding is a platform capability gap or an architect/topology issue
(`render_stop_kind`). Exact keys and typed fields only; nothing is read from a finding's text.
"""
from __future__ import annotations

import hashlib
import posixpath
from dataclasses import dataclass
from enum import Enum
from typing import AbstractSet, Callable, Iterable, Mapping, Optional, Tuple

from shared.diagnostics import PRECEDENCE, ErrorClass, ValidationReport
from shared.path_safety import validate_relpath

__all__ = ["Ownership", "PLATFORM_RENDERED_FLOOR", "LLM_DOCUMENT_PATHS", "USER_OWNED_BASENAMES", "WORKLOAD_ROOT",
           "CUSTOM_TF", "UnattributablePath", "classify_path", "classify_address", "classify_report",
           "classify_repository_file", "SourceOwner", "RenderSource", "RENDER_SOURCES", "DEPLOY_WORKFLOW_RENDER",
           "RUNTIME_PIN_RENDER", "STOP_PLATFORM_CAPABILITY_GAP", "STOP_TOPOLOGY_OR_PLATFORM_GAP",
           "REPAIR_THROUGH", "render_stop_kind"]


class Ownership(str, Enum):
    PLATFORM_VENDORED = "PLATFORM_VENDORED"   # golden modules / bundles written by vendoring THIS run
    PLATFORM_RENDERED = "PLATFORM_RENDERED"   # files the platform renders deterministically this run
    LLM_DOCUMENT = "LLM_DOCUMENT"             # rendered from an LLM-authored typed document (lane 15)
    LLM_AUTHORED = "LLM_AUTHORED"             # written by this run's LLM (or by an earlier run, recorded exactly)
    USER_OWNED = "USER_OWNED"                 # human files, pre-existing unrecorded infra files, legacy custom.tf
    # classify_repository_file only (never returned by classify_path):
    PRIOR_BUILD = "PRIOR_BUILD"               # byte-identical to a version an earlier build's developer committed
    UNKNOWN = "UNKNOWN"                       # no record says who wrote it (never routed to the developer)


WORKLOAD_ROOT = "infra/workload/"
CUSTOM_TF = "infra/workload/custom.tf"
# network.tf and terraform.tfvars are NOT in the floor (RT F4): they are rendered per run only when facts say so.
PLATFORM_RENDERED_FLOOR = frozenset({"infra/workload/main.tf", "infra/workload/variables.tf",
                                     "infra/workload/outputs.tf", "infra/workload/moved.tf",
                                     "infra/workload/services.tf", "infra/workload/topology.json"})
# TI-3: the typed IaC intent (shared/iac_intent.INTENT_PATH) is the AI's document; on the intent path custom.tf.json is
# rendered from it by the platform (in the per-run `rendered` set, which classify_path checks first).
LLM_DOCUMENT_PATHS = frozenset({"infra/workload/custom.tf.json", "infra/workload/iac_intent.json"})
USER_OWNED_BASENAMES = frozenset({"human.tf", "human_override.tf"})


# ------------------------------------------------------------------------------------------------ render -> sources
class SourceOwner(str, Enum):
    ARCHITECT = "ARCHITECT"   # the architect's validated plan (the service topology record)
    PLATFORM = "PLATFORM"     # platform code, tables, templates, the compliance decision, network facts
    DEVELOPER = "DEVELOPER"   # the developer's (AI's) own documents and files


@dataclass(frozen=True)
class RenderSource:
    """One typed source a platform render is computed from. `ref` = (repository file, symbol) of the code that reads
    or holds it (tests/test_render_sources_routing.py checks each one exists). `path` = the committed document that
    holds the source, when it is one (a developer repair can change only such a document)."""
    source: str
    owner: SourceOwner
    ref: Tuple[str, str]
    path: Optional[str] = None


_INTENT_DOC = "infra/workload/iac_intent.json"   # shared.iac_intent.INTENT_PATH (parity-tested)
_INTENT_RENDER = "infra/workload/custom.tf.json"  # shared.iac_intent.RENDER_PATH (parity-tested)
_GW = "apps/orchestrator-gateway/developer_agent/"
_ARCHITECT_TOPOLOGY = RenderSource("architect service topology record (workloads.service_topology.record)",
                                   SourceOwner.ARCHITECT, ("shared/service_topology.py", "topology_from_record"))
_TOPOLOGY_CATALOG = RenderSource("topology catalog (the attributes a topology can bind)", SourceOwner.PLATFORM,
                                 ("shared/service_topology.py", "BOOTSTRAP_CATALOG"))
_REALIZATION_TABLES = RenderSource("realization tables (topology attribute -> module output)", SourceOwner.PLATFORM,
                                   ("shared/iac_intent.py", "REALIZATION_EXPORTS"))
_INTENT_REALIZATIONS = RenderSource("developer intent realizations and push identities (checked before commit)",
                                    SourceOwner.DEVELOPER, (_GW + "iac_intent_contract.py", "assemble_intent"),
                                    _INTENT_DOC)
_COMPLIANCE = RenderSource("compliance decision (ingress, IAP, invokers)", SourceOwner.PLATFORM,
                           (_GW + "handler.py", "_assemble_tree"))
_NETWORK_FACTS = RenderSource("network facts (IPAM, connectors)", SourceOwner.PLATFORM,
                              (_GW + "platform_facts.py", "render_fact_variables"))
_CONNECTOR = RenderSource("network facts (the VPC connector of a consumed private resource)", SourceOwner.PLATFORM,
                          (_GW + "topology_wiring.py", "topology_vpc_connector"))

DEPLOY_WORKFLOW_RENDER = ".github/workflows/deploy-<service>.yml"   # judge_input.is_platform_deploy_workflow
RUNTIME_PIN_RENDER = "<apps/service/>.python-version"               # developer_agent.runtime_pin (exact content)
RENDER_SOURCES: Mapping[str, Tuple[RenderSource, ...]] = {
    "infra/workload/topology.json": (_ARCHITECT_TOPOLOGY, _TOPOLOGY_CATALOG),
    # the intent render: the developer's typed intent plus what the platform's renderer adds to it (repaired through
    # the intent: REPAIR_THROUGH)
    _INTENT_RENDER: (
        RenderSource("developer typed IaC intent", SourceOwner.DEVELOPER, ("shared/iac_intent.py", "render_intent"),
                     _INTENT_DOC),
        RenderSource("platform fact expressions", SourceOwner.PLATFORM, ("shared/iac_intent.py", "FACTS")),
        RenderSource("realization-required arguments (topology attributes x table)", SourceOwner.PLATFORM,
                     ("shared/iac_intent.py", "REALIZATION_REQUIRED_ARGS")),
        RenderSource("allow-listed type forced arguments and generated secret versions", SourceOwner.PLATFORM,
                     ("shared/iac_intent.py", "GENERATED_SECRET_ARG"))),
    "infra/workload/intent_facts.tf.json": (
        RenderSource("developer intent's platform fact uses", SourceOwner.DEVELOPER,
                     ("shared/iac_intent.py", "render_intent"), _INTENT_DOC),
        RenderSource("platform facts table", SourceOwner.PLATFORM, ("shared/iac_intent.py", "FACTS")),
        _NETWORK_FACTS),
    "infra/workload/main.tf": (
        _ARCHITECT_TOPOLOGY, _TOPOLOGY_CATALOG, _REALIZATION_TABLES, _INTENT_REALIZATIONS,
        RenderSource("developer root HCL env bindings (classic path, no typed intent)", SourceOwner.DEVELOPER,
                     (_GW + "terraform_engine.py", "extract_custom_resource_env_vars")),
        _COMPLIANCE, _CONNECTOR,
        RenderSource("golden main template", SourceOwner.PLATFORM, (_GW + "terraform_engine.py",
                                                                    "generate_golden_main_tf"))),
    "infra/workload/services.tf": (
        _ARCHITECT_TOPOLOGY, _TOPOLOGY_CATALOG, _REALIZATION_TABLES, _INTENT_REALIZATIONS, _COMPLIANCE, _CONNECTOR,
        RenderSource("secondary services template", SourceOwner.PLATFORM,
                     (_GW + "terraform_engine.py", "reconcile_multi_service_declarations"))),
    "infra/workload/variables.tf": (
        RenderSource("golden variables template", SourceOwner.PLATFORM,
                     (_GW + "terraform_engine.py", "generate_golden_variables_tf")), _COMPLIANCE, _NETWORK_FACTS),
    "infra/workload/outputs.tf": (
        RenderSource("golden outputs template", SourceOwner.PLATFORM,
                     (_GW + "terraform_engine.py", "generate_golden_outputs_tf")),),
    "infra/workload/moved.tf": (
        RenderSource("golden moved template", SourceOwner.PLATFORM,
                     (_GW + "terraform_engine.py", "generate_golden_moved_tf")),),
    "infra/workload/terraform.tfvars": (
        _COMPLIANCE, RenderSource("container sizing and inferred APIs", SourceOwner.PLATFORM,
                                  (_GW + "terraform_engine.py", "infer_additional_apis_from_custom_tf")),
        RenderSource("network fact values", SourceOwner.PLATFORM, (_GW + "platform_facts.py", "render_fact_tfvars"))),
    DEPLOY_WORKFLOW_RENDER: (
        RenderSource("architect service topology (the services CI deploys)", SourceOwner.ARCHITECT,
                     (_GW + "topology_wiring.py", "workflow_services")),
        RenderSource("deploy workflow template", SourceOwner.PLATFORM, (_GW + "handler.py", "generate_service_workflow")),
        _COMPLIANCE),
    "cloudbuild.yaml": (
        RenderSource("architect service topology (the services CI deploys)", SourceOwner.ARCHITECT,
                     (_GW + "topology_wiring.py", "workflow_services")),
        RenderSource("Serverless Git pipeline contract", SourceOwner.PLATFORM,
                     ("shared/providers/serverless_git_provider.py", "get_pipeline_contract"))),
    RUNTIME_PIN_RENDER: (
        RenderSource("platform runtime pin", SourceOwner.PLATFORM,
                     (_GW + "runtime_pin.py", "PLATFORM_PYTHON_VERSION_CONTENT")),),
}
STOP_PLATFORM_CAPABILITY_GAP = "PLATFORM_CAPABILITY_GAP"
STOP_TOPOLOGY_OR_PLATFORM_GAP = "ARCHITECT_TOPOLOGY_OR_PLATFORM_GAP"


# The renders a QA finding is repaired through a developer document: render -> that document (exact keys; an explicit
# typed decision, not a consequence of how many sources a row lists). The intent is the only developer-changeable input
# of custom.tf.json (the render's own header says "change the intent instead"); what the platform adds to it (fact
# expressions, realization-required arguments, forced arguments, generated secret versions) comes from gate-checked
# platform tables. Every other render is a typed stop.
REPAIR_THROUGH: Mapping[str, str] = {_INTENT_RENDER: _INTENT_DOC}


def render_stop_kind(sources: Iterable[RenderSource]) -> str:
    """What a QA finding on a render that is not repaired through a developer document is: an architect/topology
    issue or a platform capability gap when the architect's topology is among its sources, otherwise a platform
    capability gap (only platform code, tables and facts decide it). Decided by the sources' owners only."""
    if any(s.owner is SourceOwner.ARCHITECT for s in (sources or ())):
        return STOP_TOPOLOGY_OR_PLATFORM_GAP
    return STOP_PLATFORM_CAPABILITY_GAP


class UnattributablePath(ValueError):
    """A path in the tree that no per-run set explains (PLATFORM.UNATTRIBUTABLE for the caller)."""


def _is_override_file(path: str) -> bool:
    # Terraform's override-file rule: a file named override.tf or ending in _override.tf (exact basename rule).
    base = posixpath.basename(path)
    return base in ("override.tf", "override.tf.json") or base.endswith(("_override.tf", "_override.tf.json"))


def classify_path(path: str, *, vendored: Iterable[str], rendered: Iterable[str], authored: Iterable[str],
                  preexisting: Iterable[str], legacy_custom_tf: bool = False,
                  prior_llm: Optional[Mapping[str, str]] = None) -> Ownership:
    """Exact set membership, in this order (integration plan §1.2):
    vendored -> PLATFORM_VENDORED; rendered -> PLATFORM_RENDERED; LLM_DOCUMENT_PATHS -> LLM_DOCUMENT;
    human.tf / human_override.tf / Terraform override files, or the legacy custom.tf (from 15b) -> USER_OWNED;
    authored (this run's file_attribution keys) -> LLM_AUTHORED; prior_llm (recorded by an earlier commit, sha256
    verified by the caller) -> LLM_AUTHORED; pre-existing under infra/workload/ -> USER_OWNED; otherwise raise."""
    validate_relpath(path)
    if path in frozenset(vendored):
        return Ownership.PLATFORM_VENDORED
    if path in frozenset(rendered):
        return Ownership.PLATFORM_RENDERED
    if path in LLM_DOCUMENT_PATHS:
        return Ownership.LLM_DOCUMENT
    if posixpath.basename(path) in USER_OWNED_BASENAMES or _is_override_file(path) or (
            legacy_custom_tf and path == CUSTOM_TF):
        return Ownership.USER_OWNED
    if path in frozenset(authored):
        return Ownership.LLM_AUTHORED
    if prior_llm and path in prior_llm:
        return Ownership.LLM_AUTHORED
    if path in frozenset(preexisting) and path.startswith(WORKLOAD_ROOT):
        return Ownership.USER_OWNED
    raise UnattributablePath(f"{path}: not vendored, rendered, authored, recorded or pre-existing in this run")


def classify_address(path: str, address: str, *, platform_addresses: Iterable[tuple]) -> Optional[Ownership]:
    """Step 1 only (until lane 10 moves compute into services.tf): a block the platform synthesized inside an LLM file
    (custom.tf) is PLATFORM_RENDERED. `platform_addresses` = exact (path, address) pairs; None = not platform's."""
    return Ownership.PLATFORM_RENDERED if (path, address) in frozenset(platform_addresses) else None


def classify_report(report: ValidationReport, ownership_of: Callable[[str], Optional[Ownership]]) -> Optional[ErrorClass]:
    """The class a FAIL report routes as, ownership first (lane 13 RT F3): any error on a platform-owned or
    unattributable file forces PLATFORM_DEFECT even when mixed with workload findings; user-owned -> BROWNFIELD_CONFLICT;
    otherwise each diagnostic's own class. UNAVAILABLE -> GATE_UNAVAILABLE; PASS -> None."""
    if report.status == "UNAVAILABLE":
        return ErrorClass.GATE_UNAVAILABLE
    if report.status == "PASS":
        return None
    present = set()
    for d in report.diagnostics:
        if d.severity != "error":
            continue
        own = ownership_of(d.file)
        if own is None or own in (Ownership.PLATFORM_VENDORED, Ownership.PLATFORM_RENDERED):
            present.add(ErrorClass.PLATFORM_DEFECT)
        elif own is Ownership.USER_OWNED:
            present.add(ErrorClass.BROWNFIELD_CONFLICT)
        else:
            present.add(d.error_class)
    for c in PRECEDENCE:
        if c in present:
            return c
    return None


def classify_repository_file(path: str, content: Optional[str], *, draft: AbstractSet[str], platform_rendered: bool,
                             recorded_versions: Optional[AbstractSet[str]]) -> Ownership:
    """The owner of `path` (with `content`) in a committed tree, exact rules in this order:
    1. human.tf / human_override.tf / a Terraform override file -> USER_OWNED;
    2. LLM_DOCUMENT_PATHS (the typed IaC intent and its render) -> LLM_DOCUMENT (changed through the AI's document);
    3. `platform_rendered` (the caller's exact registries of what the platform renders: the floor, the CI rule, the IaC
       renders, the runtime pin with its exact content) -> PLATFORM_RENDERED;
    4. in `draft` (the build's own LLM draft paths, exact) -> LLM_AUTHORED;
    5. no recorded versions -> UNKNOWN; sha256(content) one of `recorded_versions` -> PRIOR_BUILD; any other content
       (a person changed a platform-written file) -> USER_OWNED."""
    if posixpath.basename(path) in USER_OWNED_BASENAMES or _is_override_file(path):
        return Ownership.USER_OWNED
    if path in LLM_DOCUMENT_PATHS:
        return Ownership.LLM_DOCUMENT
    if platform_rendered:
        return Ownership.PLATFORM_RENDERED
    if path in draft:
        return Ownership.LLM_AUTHORED
    if not recorded_versions:
        return Ownership.UNKNOWN
    if isinstance(content, str) and hashlib.sha256(content.encode("utf-8")).hexdigest() in recorded_versions:
        return Ownership.PRIOR_BUILD
    return Ownership.USER_OWNED
