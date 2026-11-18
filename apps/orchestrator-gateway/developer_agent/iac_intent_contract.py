"""TI-3 (typed IaC plan §4 TI-3; register rows TI-3a..TI-3e): the developer stage's typed-intent generation contract.

What lives here (pure functions; no LLM; the only I/O is one read of the golden foundation module's iam.tf,
`foundation_iam_tf_text`, TI5-FOUNDATION-GRANTS):
- the mode decision (`resolve_iac_intent_mode`): HallucinationStackSettings.iac_intent_mode for NEW workloads, sticky
  "generate" for a repository that already holds infra/workload/iac_intent.json (TI-3e, plan RT F13);
- the per-dispatch run object (`IntentRun`): artifacts, the IaC persona's system instruction and this workload's
  context block, built once before any LLM call;
- the prompt texts that exist ONLY in mode "generate" (lead rule, single-turn rule, topology slots); with mode "off"
  none of them is ever rendered, so every prompt is byte-identical to before TI-3;
- the assembly step (`assemble_intent`): gate the intent (shared/iac_intent.validate_intent), bind the topology's
  consumers to the realizing intent entries (shared/service_topology.ValidatedTopology.with_realizations) and render
  infra/workload/custom.tf.json; the gate's findings are kept for the blocking validator V-IAC
  (validators/iac_intent.py), which the repair loop routes to the intent's author;
- the junior / repair envelope (and single-turn files map) normalization of an intent given as a JSON object.

Every check is a schema walk, an exact table or a closed grammar (AGENTS.md invariant 2). Nothing here reads HCL text.
"""
from __future__ import annotations

import json
import logging
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

try:
    from shared import iac_intent as II
    from shared.artifact_ownership import (PLATFORM_RENDERED_FLOOR, USER_OWNED_BASENAMES, WORKLOAD_ROOT,
                                           _is_override_file)
    from shared.diagnostics import Diagnostic, ErrorClass
    from shared.service_topology import FOUNDATION_PROVIDED, GENERATED_SECRET_LENGTH, MODULE_DIR, MODULE_ONLY_ATTRIBUTES
except ImportError:  # pragma: no cover - vendored layout
    from ..shared import iac_intent as II  # type: ignore
    from ..shared.artifact_ownership import (PLATFORM_RENDERED_FLOOR, USER_OWNED_BASENAMES,  # type: ignore
                                             WORKLOAD_ROOT, _is_override_file)
    from ..shared.diagnostics import Diagnostic, ErrorClass  # type: ignore
    from ..shared.service_topology import (FOUNDATION_PROVIDED, GENERATED_SECRET_LENGTH, MODULE_DIR,  # type: ignore
                                           MODULE_ONLY_ATTRIBUTES)

__all__ = ["MODE_OFF", "MODE_GENERATE", "INTENT_PATH", "RENDER_PATH", "FACTS_RENDER_PATH", "IAC_PERSONA",
           "INTENT_MISSING_CODE", "IAC_HCL_NOT_ALLOWED_CODE", "INTENT_REMOVAL_CODES", "IntentRun", "IntentAssembly",
           "resolve_iac_intent_mode", "build_intent_run", "intent_context", "assemble_intent",
           "topology_slot_lines", "lead_intent_rule", "developer_intent_rule", "normalize_intent_envelope",
           "normalize_intent_files", "intent_entry_addresses", "intent_document_addresses", "is_ai_iac_hcl_path", "iac_hcl_assignments", "LEAD_INTENT_REASK",
           "intent_response_json_schema", "SINGLE_TURN_IAC_LINE", "repair_system_instruction", "intent_path_facts",
           "intent_network_purposes", "psa_range_wanted", "context_facts", "not_wired_types", "not_wired_slots",
           "NOT_WIRED_YET", "secret_generation", "SECRET_EXISTING_NOT_GENERATED", "secret_note_lines"]

logger = logging.getLogger("castor-iac-intent-contract")

MODE_OFF, MODE_GENERATE = "off", "generate"
INTENT_PATH = II.INTENT_PATH
RENDER_PATH = II.RENDER_PATH
FACTS_RENDER_PATH = II.FACTS_RENDER_PATH
PLATFORM_INTENT_RENDERS = (RENDER_PATH, FACTS_RENDER_PATH)
IAC_PERSONA = "IAC_ENGINEER"          # swarm_schemas.JuniorPersona.IAC_ENGINEER.value
INTENT_MISSING_CODE = "IAC.INTENT_MISSING"
API_ONLY_ENTRY_PREFIX = II.API_ONLY_ENTRY_PREFIX   # TI-3j: "api_only.<service>" (diagnostic / repair address)
IAC_HCL_NOT_ALLOWED_CODE = "PATH.IAC_HCL_NOT_ALLOWED"
# An intent entry flagged with one of these may be deleted by a repair (repair_loop.removal_justifications): the
# type / module / grant cannot be expressed, the address is a duplicate, or the grant is not allowed (narrows access).
# RT F6: REALIZATION_EXPORT_MISSING / REALIZATION_TYPE_MISMATCH name the entry whose only fix is to replace it (their
# hint says so); RT F3: MODULE_FACT_UNAVAILABLE's only fix is to remove the module.
INTENT_REMOVAL_CODES = frozenset({"IAC.TYPE_NOT_ALLOWED", "IAC.MODULE_UNKNOWN", "IAC.DUPLICATE_ADDRESS",
                                  "IAC.DUPLICATE_REALIZATION", "IAC.ROLE_NOT_ALLOWED", "IAC.UNKNOWN_REALIZATION",
                                  "IAC.REALIZATION_EXPORT_MISSING", "IAC.REALIZATION_TYPE_MISMATCH",
                                  "IAC.MODULE_FACT_UNAVAILABLE", IAC_HCL_NOT_ALLOWED_CODE,
                                  "IAC.API_NOT_ALLOWED",   # TI-3j: an API-only entry off the allow-list
                                  II.API_ONLY_DUPLICATE_GRANT,   # TI-3j-d: an AI grant an api_only entry renders
                                  II.PROJECT_WIDE_GRANT_CODE,   # OVERBROAD-SECRET-GRANT: the scoped grant replaces it
                                  # SECRET-INITIAL-VERSION: a version the platform / an operator owns (remove it), and
                                  # a generated secret realized by a resource (replace it with the golden module)
                                  "IAC.SECRET_VERSION_PLATFORM_OWNED", "IAC.SECRET_REALIZATION_MODULE_REQUIRED"})
_ENTRY_LISTS = ("modules", "resources", "outputs", "api_only")


# ------------------------------------------------------------------------------------------------ mode
STICKY = "STICKY"
INTENT_WITHOUT_RENDER = "IAC.INTENT_WITHOUT_RENDER"
LEGACY_WORKLOAD_STAYS_HCL = "IAC.LEGACY_WORKLOAD_STAYS_HCL"
NETWORK_FACT_UNAVAILABLE = "IAC.NETWORK_FACT_UNAVAILABLE"
NOT_WIRED_YET = "IAC.TYPE_NOT_WIRED_YET"   # owner 10-21: a type only a NOT_YET_WIRED_MODULES module declares (R2)


def legacy_workload_hcl(existing_files: Optional[Mapping[str, Any]]) -> List[str]:
    """RT F2: the repository's legacy workload Terraform: every `infra/workload/**.tf` that is not a platform render of
    the floor (PLATFORM_RENDERED_FLOOR), not a human file (USER_OWNED_BASENAMES) and not a Terraform override file.
    Exact set / basename rules of shared/artifact_ownership; conservative (an unknown .tf keeps the legacy path)."""
    return sorted(p for p in (existing_files or {}) if isinstance(p, str) and p.startswith(WORKLOAD_ROOT)
                  and p.endswith(".tf") and p not in PLATFORM_RENDERED_FLOOR
                  and posixpath.basename(p) not in USER_OWNED_BASENAMES and not _is_override_file(p))


def iac_intent_mode_decision(setting: Any, existing_files: Optional[Mapping[str, Any]],
                             topology: Any) -> Tuple[str, str]:
    """(mode, reason) of the developer dispatch (before any LLM call; no artifact is read):
    - sticky (TI-3e, RT F7): the repository holds the intent AND the platform's render of it -> "generate";
    - an intent without the render (not a platform commit) -> "off" (IAC.INTENT_WITHOUT_RENDER, logged);
    - otherwise the setting decides for a NEW typed-topology workload; a repository with legacy workload Terraform
      stays on the legacy path until the owner-run conversion (TI-6; RT F2: never two declarations of one resource)."""
    ex = existing_files or {}
    if INTENT_PATH in ex and RENDER_PATH in ex:
        return MODE_GENERATE, STICKY
    if INTENT_PATH in ex:
        return MODE_OFF, INTENT_WITHOUT_RENDER
    if setting != MODE_GENERATE or topology is None:
        return MODE_OFF, ""
    if legacy_workload_hcl(ex):
        return MODE_OFF, LEGACY_WORKLOAD_STAYS_HCL
    return MODE_GENERATE, "SETTING"


def is_intent_tree(files: Optional[Mapping[str, Any]]) -> bool:
    """FD-55 W5 (W2/W4 review F4): the sticky rule of iac_intent_mode_decision over a tree: it holds the typed intent
    AND the platform's render of it (exact paths). The gatekeeper callers that have the tree but not the dispatch's
    intent run (pre-commit cure, GK-5 re-cure) pass this as `verify_and_cure(typed_iac=...)`, so all three callers
    skip the same IaC cure on a typed-intent tree."""
    ex = files or {}
    return INTENT_PATH in ex and RENDER_PATH in ex


def resolve_iac_intent_mode(setting: Any, existing_files: Optional[Mapping[str, Any]], topology: Any) -> str:
    """The mode of `iac_intent_mode_decision`."""
    return iac_intent_mode_decision(setting, existing_files, topology)[0]


def network_bound_types(art: Any, facts: Optional[Mapping[str, str]] = None) -> FrozenSet[str]:
    """RT F3(3): resource types that only golden modules needing an unavailable platform fact (network / zone without
    an expression yet) declare, derived from the catalog's declares_types (never hand-written): such a topology
    resource cannot be realized on the intent path today."""
    facts = II.default_facts() if facts is None else facts
    bound: Set[str] = set()
    free: Set[str] = set(art.allowed_types)
    for mid in art.ai_modules:
        cat = art.module(mid) or {}
        needs_missing = any(v.get("class") == "FACT" and v.get("fact") not in facts
                            for v in (cat.get("variables") or {}).values())
        (bound if needs_missing else free).update(cat.get("declares_types") or ())
    return frozenset(bound - free)


def network_bound_slots(vt: Any, art: Any, facts: Optional[Mapping[str, str]] = None) -> List[str]:
    """The topology resources (logical names) whose type is network-bound (network_bound_types under `facts`)."""
    if vt is None:
        return []
    bound = network_bound_types(art, facts)
    return sorted(logical for logical, (rtype, _a) in vt.realization_needs().items() if rtype in bound)


def not_wired_types(art: Any) -> FrozenSet[str]:
    """Resource types that only not-yet-wired catalog modules (shared/iac_intent.NOT_YET_WIRED_MODULES; empty since
    TI-5-R2) declare, from the catalog's declares_types (never hand-written); a type another available module or the
    allow-list provides is free."""
    bound: Set[str] = set()
    free: Set[str] = set(art.allowed_types)
    for mid in art.ai_modules:
        types = (art.module(mid) or {}).get("declares_types") or ()
        (bound if mid in II.NOT_YET_WIRED_MODULES else free).update(types)
    return frozenset(bound - free)


def not_wired_slots(vt: Any, art: Any) -> List[str]:
    """The topology resources (logical names) only a not-yet-wired module could realize: the dispatch stays on the
    legacy path (NOT_WIRED_YET, logged); a sticky workload stops typed (handler._resolve_intent_run)."""
    if vt is None:
        return []
    bound = not_wired_types(art)
    return sorted(logical for logical, (rtype, _a) in vt.realization_needs().items() if rtype in bound)


def intent_path_facts() -> Dict[str, str]:
    """TI-5c (register TI-5c, replaces TI-3f): every fact the platform can supply on the intent path: the static
    facts, the zone (a data source on var.region) and the lane-11 network facts (rendered from the workload's IPAM
    facts, which the developer stage allocates for the intent's network modules; an IPAM failure stops the stage
    with GATE_UNAVAILABLE, never a fallback). network_bound_types under these facts is the set of types that still
    cannot be realized (none in today's catalog; a future fact without an expression puts its types back)."""
    facts = dict(II.default_facts())
    facts.update(II.platform_zone_facts())
    facts.update(II.platform_network_facts())
    return facts


def _network_fact_modules(art: Any) -> FrozenSet[str]:
    """Catalog module ids with a FACT input whose fact is a platform-network fact (exact catalog + FACTS table); a
    not-yet-wired module (owner 10-21) is refused by the gate, so it never asks IPAM for a range."""
    out: Set[str] = set()
    for mid in art.ai_modules:
        if mid in II.NOT_YET_WIRED_MODULES:
            continue
        for v in ((art.module(mid) or {}).get("variables") or {}).values():
            if v.get("class") == "FACT" and (II.FACTS.get(v.get("fact")) or {}).get("platform") == "network":
                out.add(mid)
    return frozenset(out)


def intent_network_purposes(files: Mapping[str, Any], art: Any, vt: Any = None,
                            existing_files: Optional[Mapping[str, Any]] = None) -> FrozenSet[str]:
    """TI-5c: the IPAM purposes (developer_agent.platform_facts) the intent path needs for this draft, before the
    assembly renders it: WORKLOAD_SUBNET when the intent document (this draft's, else the committed one; json.loads,
    exact module ids) instantiates a catalog module with a platform-network FACT input; also
    SERVERLESS_VPC_CONNECTOR when, in addition, a Cloud Run service of the topology consumes a private-network
    resource (topology_wiring.private_network_consumers); TI-5-F4: PRIVATE_SERVICES_ACCESS with the subnet unless the
    workload's network was committed before TI-5-F4 (psa_range_wanted). Unparseable / absent intent -> nothing (the
    gate reports it). Pure apart from parsing the committed tfvars."""
    try:
        from .platform_facts import PURPOSE_CONNECTOR, PURPOSE_PSA, PURPOSE_SUBNET
        from .topology_wiring import private_network_consumers
    except ImportError:  # pragma: no cover
        from developer_agent.platform_facts import PURPOSE_CONNECTOR, PURPOSE_PSA, PURPOSE_SUBNET
        from developer_agent.topology_wiring import private_network_consumers
    # TI-5-F4: the platform network always has Private Services Access, so it also needs the PSA range, except for a
    # workload whose network was rendered before TI-5-F4 (psa_range_wanted: its live PSA range stays Google's)
    text = (files or {}).get(INTENT_PATH)
    if not isinstance(text, str):
        text = (existing_files or {}).get(INTENT_PATH)
    try:
        doc = json.loads(text) if isinstance(text, str) else None
    except ValueError:
        doc = None
    mods = doc.get("modules") if isinstance(doc, dict) else None
    used = {m.get("module") for m in mods if isinstance(m, dict)} if isinstance(mods, list) else set()
    if not used & _network_fact_modules(art):
        return frozenset()
    out = {PURPOSE_SUBNET}
    if vt is not None and private_network_consumers(vt):
        out.add(PURPOSE_CONNECTOR)
    if psa_range_wanted(existing_files):
        out.add(PURPOSE_PSA)
    return frozenset(out)


def psa_range_wanted(existing_files: Optional[Mapping[str, Any]]) -> bool:
    """TI-5-F4 (owner 10-21): whether the platform network of this workload takes its Private Services Access range
    from IPAM. Yes for a new network (the committed platform tfvars hold no subnet fact) and for a network that was
    rendered with an IPAM PSA range (they hold psa_cidr). No for a network committed before TI-5-F4 (subnet fact, no
    psa_cidr): its live PSA range was allocated by Google, and an address on it would replace the range and the
    peering (IPAM.LEDGER_MISMATCH spirit of TI-5: a committed network never moves). Committed tfvars that cannot be
    read -> False here; the stage stops on them anyway (platform_facts.committed_fact_values, GATE_UNAVAILABLE)."""
    try:
        from .platform_facts import FactsUnavailable, committed_fact_values
    except ImportError:  # pragma: no cover
        from developer_agent.platform_facts import FactsUnavailable, committed_fact_values
    try:
        committed = committed_fact_values(existing_files)
    except FactsUnavailable:
        return False
    return "psa_cidr" in committed or "subnet_cidr" not in committed


def is_ai_iac_hcl_path(path: str) -> bool:
    """An AI-authored Terraform file under infra/ (exact suffix rule: Terraform's own file extensions)."""
    return isinstance(path, str) and path.startswith("infra/") and path.endswith((".tf", ".tf.json"))


def iac_hcl_assignments(tasks: Iterable[Any]) -> List[Tuple[str, str]]:
    """(task_id, path) of every Terraform file under infra/ a lead plan assigns to a junior (intent mode: refused)."""
    out: List[Tuple[str, str]] = []
    for t in tasks:
        for f in getattr(t, "assigned_files", None) or ():
            if is_ai_iac_hcl_path(f):
                out.append((str(getattr(t, "task_id", "")), f))
    return out


# ------------------------------------------------------------------------------------------------ context
def moved_from_addresses(moved_tf: Optional[str]) -> FrozenSet[str]:
    """TI-3 merge gate (10-20): the `from` addresses of the platform's moved.tf (legacy root addresses moved into
    module.foundation / module.compute), read with the HCL parser (assembly.index_blocks + the exact reference
    grammar of topology_wiring.exact_reference). An intent entry at one of them passes validate but fails plan."""
    try:
        from .assembly import index_blocks
        from .topology_wiring import exact_reference
    except ImportError:  # pragma: no cover
        from developer_agent.assembly import index_blocks
        from developer_agent.topology_wiring import exact_reference
    out: Set[str] = set()
    for b in index_blocks(moved_tf or "") or []:
        if b.kind == "moved":
            t = exact_reference((b.body or {}).get("from"))
            if t:
                out.add(".".join(t))
    return frozenset(out)


def context_facts(network_facts: Any = None) -> Dict[str, str]:
    """TI-5c: the facts of this dispatch's IntentContext: the static facts, the zone, and the lane-11 network facts
    when the workload holds the IPAM WORKLOAD_SUBNET fact (platform_facts.NetworkFacts.subnet_cidr)."""
    facts = dict(II.default_facts())
    facts.update(II.platform_zone_facts())
    if network_facts is not None and getattr(network_facts, "subnet_cidr", None):
        facts.update(II.platform_network_facts())
    return facts


# ---------------------------------------------------------------------------------------- SECRET-INITIAL-VERSION
# Register SECRET-INITIAL-VERSION (owner 11-10). A topology secret the architect marks initial_value = "random" gets the
# platform's random first version (golden security-secret generate_initial_version), but only when this run's apply
# creates the secret, so a value an operator added to an existing secret is never shadowed by a newer version. Read
# from the repository's committed, platform-written files (typed parses only, never HCL text or names):
#   (a) stated "random" and the committed iac_intent.json realizes no entry for that topology resource (new secret);
#   (b) the committed custom.tf.json already renders generate_initial_version = true on the security-secret module
#       instance that realizes it (sticky: never abandoned and re-created with a new value, whatever a later plan says).
# Stated "random" on a secret the repository already realizes otherwise -> no version + the typed workload warning
# SECRET.EXISTING_NOT_GENERATED. A committed intent or render that cannot be parsed counts as "already realized, not
# generated" (never guessed into a new version).
SECRET_EXISTING_NOT_GENERATED = "SECRET.EXISTING_NOT_GENERATED"


def _committed_realizations(existing_files: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Tuple[str, str]]]:
    """{logical: (entry kind "module" / resource type, entry name)} of the repository's committed intent; {} without
    one; None when it cannot be parsed."""
    text = (existing_files or {}).get(INTENT_PATH)
    if not isinstance(text, str):
        return {}
    try:
        doc = II.IacIntent.model_validate(json.loads(text))
    except Exception:  # noqa: BLE001 - json / pydantic: unreadable -> None (the caller never guesses)
        return None
    out: Dict[str, Tuple[str, str]] = {}
    for m in doc.modules:
        if m.realizes:
            out.setdefault(m.realizes, ("module:" + m.module, m.name))
    for r in doc.resources:
        if r.realizes:
            out.setdefault(r.realizes, (r.type, r.name))
    return out


def _committed_generated_modules(existing_files: Optional[Mapping[str, Any]]) -> FrozenSet[str]:
    """Names of the module blocks of the committed platform render (custom.tf.json) that set
    generate_initial_version to exactly true; empty when there is none or it cannot be parsed."""
    text = (existing_files or {}).get(RENDER_PATH)
    if not isinstance(text, str):
        return frozenset()
    try:
        doc = json.loads(text)
    except ValueError:
        return frozenset()
    mods = doc.get("module") if isinstance(doc, dict) else None
    if not isinstance(mods, dict):
        return frozenset()
    return frozenset(n for n, body in mods.items()
                     if isinstance(body, dict) and body.get(II.GENERATED_SECRET_ARG) is True
                     and body.get("source") == II.MODULE_SOURCE_PREFIX + II.GENERATED_SECRET_MODULE)


def secret_generation(vt: Any, existing_files: Optional[Mapping[str, Any]] = None
                      ) -> Tuple[FrozenSet[str], Tuple[Dict[str, Any], ...]]:
    """(the topology secrets that get the platform's random first version in this run, the SECRET.EXISTING_NOT_GENERATED
    workload warnings) for the validated topology `vt` and the repository's committed files (rules above). Pure."""
    if vt is None:
        return frozenset(), ()
    values = vt.secret_initial_values()
    if not values:
        return frozenset(), ()
    realized = _committed_realizations(existing_files)
    generated_before = _committed_generated_modules(existing_files)
    out: Set[str] = set()
    warnings: List[Dict[str, Any]] = []
    for logical, value in values.items():
        entry = (realized or {}).get(logical)
        sticky = (entry is not None and entry[0] == "module:" + II.GENERATED_SECRET_MODULE
                  and entry[1] in generated_before)
        if sticky or (value == "random" and realized is not None and entry is None):
            out.add(logical)
        elif value == "random":
            address = f"module.{entry[1]}" if entry and entry[0].startswith("module:") else (
                f"{entry[0]}.{entry[1]}" if entry else logical)
            warnings.append({
                "code": SECRET_EXISTING_NOT_GENERATED, "address": address, "realizes": logical,
                "kind": "secret", "stops_build": False,
                "message": (f"{address} (topology secret {logical}) already exists in this workload, so the platform "
                            "adds no random first version to it (a value an operator added would otherwise be "
                            "replaced as the newest). If it has no version yet, the app cannot read it until one "
                            "is added in Secret Manager.")})
    return frozenset(out), tuple(warnings)


def secret_note_lines(vt: Any) -> List[str]:
    """SECRET-INITIAL-VERSION (typed-intent developer contract only): one line per service env key bound to a topology
    secret whose plan states initial_value, saying what the secret will hold. [] without one (contract unchanged)."""
    if vt is None:
        return []
    values = {k: v for k, v in vt.secret_initial_values().items() if v}
    lines: List[str] = []
    for r in vt.intent.resources:
        value = values.get(r.logical_name)
        if value is None:
            continue
        for c in r.consumers:
            if value == "random":
                note = (f"the Secret Manager secret id of `{r.logical_name}`, whose first version the platform "
                        f"creates at deploy: {GENERATED_SECRET_LENGTH} random letters and digits. Read its `latest` "
                        "version as UTF-8 text and use it as the key material (derive a fixed-length key from it, "
                        "e.g. with SHA-256, when an algorithm needs one); never generate or store a key yourself")
            else:
                note = (f"the Secret Manager secret id of `{r.logical_name}`, whose value an operator adds after the "
                        "deploy. Until then reading its `latest` version fails: answer HTTP 503 with a clear message "
                        "at that point, never fail at start-up")
            lines.append(f"- `{c.env_key}` on `{c.service}` is {note}.")
    return lines


def intent_context(vt: Any, root_keys: Iterable[str] = (),
                   reserved_addresses: Iterable[str] = (), network_facts: Any = None,
                   existing_files: Optional[Mapping[str, Any]] = None) -> II.IntentContext:
    """The platform facts the gate checks this workload's intent against (never LLM text): the topology's services
    (ServiceRef targets: module address + golden compute module id), the topology resources the IaC declares (slots),
    the consumer reads (service -> resource edges for the cycle check), and the platform's own root addresses.
    TI-5c: `network_facts` (platform_facts.NetworkFacts of this iteration) adds the network facts (context_facts);
    with the IPAM connector fact too and a Cloud Run consumer of a private-network resource, the platform network
    render carries the VPC connector (`vpc_connector`)."""
    keys = set(root_keys or ())
    reserved = {"foundation", "compute"} | {k[len("module."):] for k in keys if k.startswith("module.")}
    outputs = {k[len("output."):] for k in keys if k.startswith("output.")}
    addresses = frozenset(reserved_addresses or ())
    facts = context_facts(network_facts)
    # TI-5-F4: the platform network's PSA range is the IPAM fact when this iteration holds it
    psa = bool("network" in facts and getattr(network_facts, "psa_cidr", None))
    if vt is None:
        return II.IntentContext(facts=facts, reserved_module_names=frozenset(reserved),
                                platform_output_names=frozenset(outputs), reserved_addresses=addresses,
                                psa_range=psa)
    try:
        from .topology_wiring import private_network_consumers
    except ImportError:  # pragma: no cover
        from developer_agent.topology_wiring import private_network_consumers
    connector = bool("network" in facts and getattr(network_facts, "connector_cidr", None)
                     and private_network_consumers(vt))
    services = {n: (f"module.{vt.label(n)}", MODULE_DIR[vt.kind(n)]) for n in vt.names}
    needs = vt.realization_needs()
    slots = {logical: rtype for logical, (rtype, _a) in needs.items()}
    reads = sorted({(c.service, r.logical_name) for r in vt.intent.resources if r.type not in FOUNDATION_PROVIDED
                    for c in r.consumers})
    reserved |= {vt.label(n) for n in vt.names}
    generated, _warnings = secret_generation(vt, existing_files)   # SECRET-INITIAL-VERSION
    stated = {k: v for k, v in vt.secret_initial_values().items() if v is not None}
    return II.IntentContext(facts=facts, services=services, topology_resources=slots, service_reads=tuple(reads),
                            reserved_module_names=frozenset(reserved), platform_output_names=frozenset(outputs),
                            reserved_addresses=addresses, vpc_connector=connector, psa_range=psa,
                            topology_attributes={logical: tuple(a) for logical, (_t, a) in needs.items()},
                            secret_initial_values=stated, generated_secrets=generated)


# ------------------------------------------------------------------------------------------------ prompts
def _secret_slot_note(logical: str, vt: Any, generated: FrozenSet[str]) -> str:
    """SECRET-INITIAL-VERSION: the slot line's note for a topology secret whose plan states initial_value ("" for any
    other resource, so a topology without the field renders exactly as before)."""
    value = vt.secret_initial_values().get(logical) if vt is not None else None
    if logical in generated:
        return (f"; the platform creates its first version ({GENERATED_SECRET_LENGTH} random letters and digits): "
                f"never declare a {II.GENERATED_SECRET_VERSION_TYPE} or random_password for it")
    if value == "random":
        return (f"; it already exists in this workload: never declare a {II.GENERATED_SECRET_VERSION_TYPE} for it")
    if value == "operator":
        return f"; an operator adds its value: never declare a {II.GENERATED_SECRET_VERSION_TYPE} for it"
    return ""


def topology_slot_lines(vt: Any, art: Any = None, generated_secrets: Optional[FrozenSet[str]] = None) -> List[str]:
    """Contract lines (intent path) for the topology's resources: one intent entry per resource the IaC declares, with
    the module ids that can realize its type and the attributes the services read; the foundation's resources are
    named so they are never declared. [] without resources.
    TI-5-R2 P2 (owner 10-25, FOLLOWUPS-1025): the "or a `<type>` resource" option is offered only for a type on the
    allow-list (`art.allowed_types`, the gate's own set; `art` defaults to shared.iac_intent.load_artifacts()), so the
    AI is never told to write a resource the gate refuses (IAC.TYPE_NOT_ALLOWED). A resource with neither a realizing
    golden module nor an allow-listed type raises IntentGateUnavailable (GATE.IAC_INTENT_ARTIFACT_INCONSISTENT): the
    artifacts cannot realize the topology, so no line is offered on a guess.
    SECRET-INITIAL-VERSION: a secret in `generated_secrets` (None = secret_generation without a repository: every
    secret stated "random") is offered only its golden module, which renders the platform's first version; a secret
    whose plan states initial_value says who owns its version (_secret_slot_note)."""
    if vt is None:
        return []
    lines: List[str] = []
    needs = vt.realization_needs()
    if needs:
        allowed = frozenset((art if art is not None else II.load_artifacts()).allowed_types)
        generated = secret_generation(vt)[0] if generated_secrets is None else frozenset(generated_secrets)
        parts = []
        for logical, (rtype, attrs) in sorted(needs.items()):
            via = sorted(mid for (mid, t), row in II.REALIZATION_EXPORTS.items()
                         if t == rtype and set(attrs) <= set(row))
            if logical in generated:   # SECRET-INITIAL-VERSION: only the golden module renders the first version
                via = [mid for mid in via if mid == II.GENERATED_SECRET_MODULE]
            # TI-5-R2 P3: the arguments a realizing module must set for these attributes (exact table), and no
            # resource option when an attribute only the module exports is read (MODULE_ONLY_ATTRIBUTES)
            mods = []
            for mid in via:
                req = II.realization_required_args(mid, rtype, attrs)
                mods.append(mid + (" with " + ", ".join(f"{k}: {json.dumps(v)}" for k, v in req.items())
                                   if req else ""))
            module_only = set(attrs) & set(MODULE_ONLY_ATTRIBUTES.get(rtype, ())) or logical in generated
            options = (([f"golden module {', '.join(mods)}"] if mods else [])
                       + ([] if module_only or rtype not in allowed else [f"a {rtype} resource"]))
            if not options:
                raise II.IntentGateUnavailable(
                    "GATE.IAC_INTENT_ARTIFACT_INCONSISTENT",
                    f"topology resource {logical!r} ({rtype}) has no realizing golden module and its type is not on "
                    f"the allow-list")
            how = " or ".join(options)
            reads = f"; services read {', '.join(attrs)}" if attrs else ""
            note = _secret_slot_note(logical, vt, generated)   # SECRET-INITIAL-VERSION ("" without the field)
            parts.append(f"`{logical}` ({rtype}{reads}; realize it with {how}{note})")
        lines.append("- In infra/workload/iac_intent.json add exactly one entry with \"realizes\": \"<name>\" for each "
                     "of these topology resources: " + "; ".join(parts) + ". The platform binds the services' "
                     "environment variables to that entry; never declare them twice.")
    if vt.foundation_resources():
        types_ = sorted({t for t, _ in vt.foundation_resources()})
        lines.append(f"- Do not declare {', '.join(types_)}: the workload foundation (module.foundation) already "
                     f"declares it; reference it in the intent with the fact database_name.")
    for e in getattr(vt, "pushes", ()):   # PUSH-PLAN-CHECK: only a topology with push edges adds lines
        lines.append(push_plan_line(e.topic, e.service, e.path))
    return lines


# PUSH-PLAN-CHECK (owner 10-28): the exact intent form that satisfies one topology push edge (topic T pushes to the
# cloudrun service S at path P), shared by the contract line above and the pre-commit check (validators/push_plan.py).
PUSH_PLAN_IDENTITY = {"$ref": {"kind": "fact", "fact": "workload_sa_email"}}
__all__ += ["push_plan_form", "push_plan_line", "PUSH_PLAN_IDENTITY"]


def push_plan_form(service: str, path: str) -> Dict[str, Any]:
    """The closed `push` value (shared.iac_intent PUSH_ARG_KEYS) for a push to `service` at `path`, signed by the
    workload service account (the fact workload_sa_email)."""
    return {"service": {"$ref": {"kind": "service", "service": service, "output": "service_uri"}}, "path": path,
            "service_account_email": PUSH_PLAN_IDENTITY}


def push_plan_line(topic: str, service: str, path: str) -> str:
    """The intent-path contract line of one topology push edge (validated identifiers and path only)."""
    return (f"- The plan's topic `{topic}` pushes to the service `{service}` at `{path}`: set \"push\" on the "
            f"messaging-pubsub instance with \"realizes\": \"{topic}\" to "
            f"{json.dumps(push_plan_form(service, path), sort_keys=True)} (or another push identity of the push "
            "grammar). The pre-commit check refuses the infrastructure without that push.")


# TI5-FOUNDATION-GRANTS (owner 10-25): the workload service account's project grants that module.foundation declares,
# read from the golden module's own iam.tf with the HCL parser, so the intent context states them as facts.
FOUNDATION_IAM_TF = ("workload-foundation", "base", "iam.tf")       # under infra/modules/
WORKLOAD_SA_EMAIL_REF = ("google_service_account", "workload_sa", "email")


def foundation_iam_tf_text() -> Optional[str]:
    """The golden workload-foundation module's iam.tf: the module tree on disk, else the built-in payload (byte-identical
    and parity-tested, tests/test_lane8_payload_parity.py), the same sources as express_synthesizer's vendoring.
    None when neither holds it. The only file read in this module."""
    import os
    try:
        from shared.builtin_modules_provider import get_platform_modules_path
        from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
    except ImportError:  # pragma: no cover - vendored layout
        from ..shared.builtin_modules_provider import get_platform_modules_path  # type: ignore
        from ..shared.builtin_modules_payload import BUILTIN_MODULE_FILES  # type: ignore
    root = get_platform_modules_path()
    if root:
        path = os.path.join(root, *FOUNDATION_IAM_TF)
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
    text = (BUILTIN_MODULE_FILES.get("/".join(FOUNDATION_IAM_TF[:2])) or {}).get(FOUNDATION_IAM_TF[2])
    return text if isinstance(text, str) else None


def _template_references(value: Any) -> Optional[List[Tuple[str, ...]]]:
    """Every interpolated traversal of a python-hcl2 string value (`"serviceAccount:${a.b.c}"` -> [("a", "b", "c")]),
    read with the HCL parser's own grammar (the value re-parsed as one quoted template). None when it does not parse
    as one, or an interpolation is not a plain traversal."""
    if not isinstance(value, str):
        return None
    try:
        from .topology_wiring import _parser_helpers
    except ImportError:  # pragma: no cover
        from developer_agent.topology_wiring import _parser_helpers
    _unavailable, _data, _kids, _traversal = _parser_helpers()
    try:
        import hcl2  # python-hcl2==7.3.1 (requirements.txt)
        tree = hcl2.parses("x = " + json.dumps(value) + "\n")
    except Exception:  # noqa: BLE001 - not one template: no references
        return None
    refs: List[Tuple[str, ...]] = []
    stack = [tree]
    while stack:
        node = stack.pop()
        if _data(node) == "interpolation":
            inner = [k for k in _kids(node) if _data(k) is not None]
            t = _traversal(inner[0]) if len(inner) == 1 else None
            if t is None:
                return None
            refs.append(t)
            continue
        stack.extend(_kids(node))
    return refs


def foundation_workload_grants(iam_tf: Optional[str]) -> Optional[Tuple[str, ...]]:
    """The roles module.foundation grants the workload service account: each `google_project_iam_member` block of the
    foundation's iam.tf whose literal `role` is granted to exactly `${google_service_account.workload_sa.email}`
    (python-hcl2 block index + the template's parsed interpolation; no text matching), sorted. None when the file is
    missing, does not parse, or holds no such grant (the caller omits the facts)."""
    try:
        from .assembly import index_blocks
        from .sibling_wiring import literal_string
    except ImportError:  # pragma: no cover
        from developer_agent.assembly import index_blocks
        from developer_agent.sibling_wiring import literal_string
    if not iam_tf:
        return None
    try:
        blocks = index_blocks(iam_tf)
    except Exception:  # noqa: BLE001 - HclUnavailable: no facts, never a crash
        return None
    roles: Set[str] = set()
    for b in blocks or []:
        if b.kind != "resource" or b.labels[:1] != ("google_project_iam_member",):
            continue
        role = literal_string((b.body or {}).get("role"))
        if role and _template_references((b.body or {}).get("member")) == [WORKLOAD_SA_EMAIL_REF]:
            roles.add(role)
    return tuple(sorted(roles)) or None


def _run_context(vt: Any, ctx: II.IntentContext, existing_intent: Optional[str],
                 foundation_grants: Optional[Sequence[str]] = None, art: Any = None) -> str:
    lines = ["IAC INTENT CONTEXT FOR THIS WORKLOAD (platform facts):"]
    lines += topology_slot_lines(vt, art, ctx.generated_secrets) or [
        "- The topology declares no resources: add only what the specification needs (an empty intent "
        "{\"schema\": \"iac_intent/v1\"} is valid)."]
    if ctx.services:
        svc = []
        for name, (_addr, mid) in sorted(ctx.services.items()):
            outs = sorted(II._COMPUTE_OUTPUTS.get(mid, ()))
            svc.append(f"`{name}` ({mid}{': ' + ', '.join(outs) if outs else ': no outputs'})")
        lines.append("- Services you may reference with {\"$ref\": {\"kind\": \"service\", ...}}: " + "; ".join(svc)
                     + ". The platform renders their compute; never declare it.")
    if II.gke_compute_modules(ctx):
        # GKE-WI-INTENT (ex04-1115b): the one Workload Identity entry the intent expresses (only for a GKE workload,
        # so every other workload's context is byte-identical)
        lines.append("- GKE Workload Identity (the one exception to \"Workload Identity\" under NOT EXPRESSIBLE): a "
                     "Kubernetes service account whose k8s/*.yaml ServiceAccount carries the annotation "
                     "iam.gke.io/gcp-service-account acts as that Google service account only when this intent grants "
                     "it. Declare the google_service_account the pods run as, grant it the roles the code needs, and "
                     "add one entry per Kubernetes service account. " + II.GKE_WI_HINT + " The platform renders the "
                     "member as serviceAccount:<project>.svc.id.goog[<namespace>/<name>] and waits for the cluster.")
    lines.append("- Module names already used by the platform: " + ", ".join(sorted(ctx.reserved_module_names)) + ".")
    if ctx.reserved_addresses:
        # TI5-FOUNDATION-GRANTS: with the grants stated as facts (next line) the prose names no grant the list omits
        held = ("" if foundation_grants else ", including the workload service account's Firestore, Logging, "
                "Pub/Sub publisher and Storage object grants")
        lines.append(f"- Addresses the platform reserves (module.foundation already declares them{held}): "
                     + ", ".join(sorted(ctx.reserved_addresses)) + ". Never declare an entry at one of them.")
    if foundation_grants:
        lines.append("- Project roles module.foundation already grants the workload service account (fact "
                     "workload_sa_email), so its services hold them: " + ", ".join(foundation_grants) + ". Never "
                     "declare an entry that grants one of these roles to the workload service account; grant it only "
                     "the other roles the specification needs.")
    if ctx.platform_output_names:
        lines.append("- Output names already used by the platform: " + ", ".join(sorted(ctx.platform_output_names))
                     + ".")
    if existing_intent is not None:
        lines += ["- The repository's current infra/workload/iac_intent.json (keep every entry that is still needed; "
                  "change it only where the specification asks):", existing_intent]
    return "\n".join(lines)


def lead_intent_rule() -> str:
    """Lead decomposition rule on the intent path (appended to the decomposition prompt; mode "generate" only)."""
    return ("TYPED IAC INTENT CONTRACT (this rule replaces every .tf assignment in the system prompt's example): "
            "assign exactly ONE IAC_ENGINEER task whose only assigned file is \"infra/workload/iac_intent.json\" "
            "(the typed IaC intent; the platform renders all Terraform from it). No task may be assigned a .tf or "
            ".tf.json file. Give that task the specification's infrastructure needs (buckets, topics, secrets, "
            "databases, schedules, grants) and the topology resources it must realize.")


LEAD_INTENT_REASK = ("\n\nERROR IAC.HCL_ASSIGNED: the previous plan assigned Terraform files {paths}. With the typed "
                     "IaC intent no task may be assigned a .tf or .tf.json file: assign the IAC_ENGINEER task exactly "
                     "[\"infra/workload/iac_intent.json\"].")

# The single-turn developer request's last line on the intent path (the "off" line stays verbatim in handler.py).
SINGLE_TURN_IAC_LINE = ("Generate all necessary application files, Procfile, requirements.txt, .python-version, "
                        "cloudbuild.yaml, the typed IaC intent infra/workload/iac_intent.json (no Terraform files), "
                        "and pytest unit tests.")


def developer_intent_rule(run: "IntentRun") -> str:
    """Single-turn developer system-prompt block on the intent path: items 6, 8 and 9 (custom.tf / variables.tf /
    outputs.tf) are replaced by the intent document; the IaC persona's full instruction follows."""
    return ("TYPED IAC INTENT (overrides items 6, 8 and 9 above and every infra/workload/*.tf in the response format): "
            "do not write any .tf or .tf.json file. Write the workload's infrastructure as the single file "
            "\"infra/workload/iac_intent.json\" in the \"files\" object, following this contract:\n\n"
            + run.system_prompt + "\n" + run.run_context)


REPAIR_EMPTY_TF_NOTE = ("A Terraform (.tf / .tf.json) file listed under FILES TO FIX is returned under its own key with "
                        "empty content; this is the only Terraform you return.")


def repair_task_needs_intent_prompt(files_to_fix: Iterable[str]) -> bool:
    """An intent-mode repair task that holds the intent or an AI Terraform file (to be emptied) gets the intent
    instruction (never the HCL prompt, which would ask for Terraform)."""
    return any(p == INTENT_PATH or is_ai_iac_hcl_path(p) for p in files_to_fix)


def repair_system_instruction(run: "IntentRun", persona: str, base: str,
                              files_to_fix: Iterable[str] = ()) -> str:
    """A repair task that holds the intent: the IaC persona gets its intent instruction and this workload's context
    (never the HCL prompt); any other author (single-turn developer) keeps its prompt plus the intent rule.
    RT F8: when the task also holds an AI Terraform file (PATH.IAC_HCL_NOT_ALLOWED: "return it empty"), one sentence
    says so, so the instruction "never return a .tf file" does not contradict the task."""
    note = ("\n" + REPAIR_EMPTY_TF_NOTE) if any(is_ai_iac_hcl_path(p) for p in files_to_fix) else ""
    if persona == IAC_PERSONA:
        return run.system_prompt + "\n" + run.run_context + note
    return base + "\n\n" + developer_intent_rule(run) + note


# ------------------------------------------------------------------------------------------------ run
@dataclass(frozen=True)
class IntentRun:
    """One developer dispatch on the intent path (resolved before any LLM call)."""
    artifacts: Any                    # shared.iac_intent.Artifacts
    system_prompt: str                # the IaC persona's system instruction (juniors/iac_worker)
    run_context: str                  # this workload's slots / services / reserved names
    sticky: bool = False              # the repository already holds an intent
    structured_output: bool = False   # HallucinationStackSettings.iac_intent_structured_output
    thinking_budget: int = 4096       # HallucinationStackSettings.iac_intent_thinking_budget (IaC junior call)
    max_output_tokens: int = 16_384   # HallucinationStackSettings.iac_intent_max_output_tokens (IaC junior call)
    reserved_addresses: FrozenSet[str] = frozenset()   # moved.tf `from` addresses (merge-gate finding, 10-20)
    generated_secrets: FrozenSet[str] = frozenset()    # SECRET-INITIAL-VERSION: secret_generation of this dispatch


def platform_moved_from(vt: Any) -> FrozenSet[str]:
    """The `from` addresses of the moved.tf the platform renders for this workload (the same generator and
    arguments as handler._assemble_tree: product id and archetype of the validated topology)."""
    try:
        from .terraform_engine import generate_golden_moved_tf
    except ImportError:  # pragma: no cover
        from developer_agent.terraform_engine import generate_golden_moved_tf
    if vt is None:
        return frozenset()
    return moved_from_addresses(generate_golden_moved_tf(vt.product_id, vt.archetype))


def build_intent_run(vt: Any, existing_files: Optional[Mapping[str, Any]], *, structured_output: bool = False,
                     artifacts: Any = None, thinking_budget: int = 4096,
                     max_output_tokens: int = 16_384) -> IntentRun:
    """Raises shared.iac_intent.IntentGateUnavailable (GATE_UNAVAILABLE) when an artifact is unusable."""
    try:
        from .juniors.iac_worker import build_iac_intent_worker_prompt
    except ImportError:  # pragma: no cover
        from developer_agent.juniors.iac_worker import build_iac_intent_worker_prompt
    art = artifacts or II.load_artifacts()
    existing = (existing_files or {}).get(INTENT_PATH)
    existing = existing if isinstance(existing, str) else None
    reserved = platform_moved_from(vt)
    ctx = intent_context(vt, reserved_addresses=reserved, existing_files=existing_files)
    try:   # TI5-FOUNDATION-GRANTS: missing / unparseable iam.tf -> the facts are omitted (warning), never a crash
        grants = foundation_workload_grants(foundation_iam_tf_text())
    except Exception as e:  # noqa: BLE001
        logger.warning(f"TI5-FOUNDATION-GRANTS: could not read the foundation iam.tf ({type(e).__name__}: {e})")
        grants = None
    if grants is None:
        logger.warning("TI5-FOUNDATION-GRANTS: the workload service account's foundation grants are unavailable "
                       "(workload-foundation/base/iam.tf missing, unparseable or without grants); the intent context "
                       "omits them")
    return IntentRun(artifacts=art, system_prompt=build_iac_intent_worker_prompt(art),
                     run_context=_run_context(vt, ctx, existing, grants, art), sticky=existing is not None,
                     structured_output=bool(structured_output), thinking_budget=int(thinking_budget),
                     max_output_tokens=int(max_output_tokens), reserved_addresses=reserved,
                     generated_secrets=ctx.generated_secrets)


def intent_response_json_schema(art: Any) -> Dict[str, Any]:
    """Gemini `response_json_schema` for the IaC persona's junior envelope: {"files": {INTENT_PATH: <IacIntent>}}
    (the intent schema's $defs lifted to the root, so its #/$defs references resolve)."""
    schema = dict(II.response_json_schema(art))
    defs = schema.pop("$defs", {})
    return {"$defs": defs, "type": "object", "required": ["files"],
            "properties": {"files": {"type": "object", "required": [INTENT_PATH],
                                     "properties": {INTENT_PATH: schema}}}}


def normalize_intent_envelope(clean_json: str) -> str:
    """A junior / repair answer may carry the intent as a JSON object instead of a JSON string: re-dump exactly that
    value as canonical text (indent 2, sorted keys) so the envelope is {"files": {path: text}} again. Anything else
    (not JSON, no files object, a string value) is returned unchanged."""
    try:
        doc = json.loads(clean_json)
    except (TypeError, ValueError):
        return clean_json
    files = doc.get("files") if isinstance(doc, dict) else None
    if not isinstance(files, dict) or not isinstance(files.get(INTENT_PATH), (dict, list)):
        return clean_json
    doc["files"] = normalize_intent_files(files)
    return json.dumps(doc, ensure_ascii=False)


def normalize_intent_files(files: Dict[str, Any]) -> Dict[str, Any]:
    """The same normalization on an already-parsed files map (the single-turn developer answer, TI-5 gate 08-r2/r3:
    the model wrote the intent as a JSON object and the draft carried a dict as file content). Only the intent
    path's value is touched, and only when it is a JSON object or array: it becomes its canonical text (indent 2,
    sorted keys). Every other case returns `files` itself, unchanged (a string intent is never rewritten)."""
    if not isinstance(files.get(INTENT_PATH), (dict, list)):
        return files
    out = dict(files)
    out[INTENT_PATH] = json.dumps(files[INTENT_PATH], indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return out


# ------------------------------------------------------------------------------------------------ assembly
@dataclass(frozen=True)
class IntentAssembly:
    """What the assembly did with the intent this iteration (kept on repair_loop.Assembled.iac_intent)."""
    diagnostics: Tuple[Diagnostic, ...] = ()
    rendered: Tuple[str, ...] = ()                                   # platform paths rendered from the intent
    provenance: Mapping[str, str] = field(default_factory=dict)     # rendered JSON pointer -> intent JSON pointer
    modules: Tuple[str, ...] = ()                                   # golden modules the intent instantiates (vendor)
    intent_sha256: Optional[str] = None
    realizations: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    present: bool = False                                            # the tree holds an intent document
    # PUSH-TO-PRIVATE (owner 10-27): {compute-cloudrun module address: {identity key: HCL email expression}} of the
    # intent's push subscriptions (shared.iac_intent.push_identities); the platform's compute module renders take it
    push_identities: Mapping[str, Mapping[str, str]] = field(default_factory=dict)


def intent_entry_addresses(intent: Any) -> Dict[str, str]:
    """{"/modules/<n>": "module.<name>", "/resources/<n>": "<type>.<name>", "/outputs/<n>": "output.<name>",
    "/api_only/<n>": "api_only.<service>"} of a parsed intent (shared.iac_intent.IacIntent)."""
    out: Dict[str, str] = {}
    for n, m in enumerate(getattr(intent, "modules", ()) or ()):
        out[f"/modules/{n}"] = f"module.{m.name}"
    for n, r in enumerate(getattr(intent, "resources", ()) or ()):
        out[f"/resources/{n}"] = f"{r.type}.{r.name}"
    for n, o in enumerate(getattr(intent, "outputs", ()) or ()):
        out[f"/outputs/{n}"] = f"output.{o.name}"
    for n, a in enumerate(getattr(intent, "api_only", ()) or ()):   # TI-3j
        out[f"/api_only/{n}"] = II.API_ONLY_ENTRY_PREFIX + a.service
    return out


def intent_document_addresses(text: Any, *, api_only: bool = True) -> Set[str]:
    """The entry addresses of an intent DOCUMENT (json.loads only, no model validation): "module.<name>" per
    `modules` entry, "<type>.<name>" per `resources` entry and, with `api_only`, "api_only.<service>" per `api_only`
    entry (TI-3j). Not JSON / not a string -> set(). The repair loop's preserved intent addresses
    (repair_loop._intent_addresses) and JUDGE-NAMED-INTENT-REMOVAL's nameable entries (api_only=False) are both this
    set, so a judge can name exactly the entries the preservation rule counts."""
    if not isinstance(text, str):
        return set()
    try:
        doc = json.loads(text)
    except ValueError:
        return set()
    out: Set[str] = set()
    for m in (doc.get("modules") if isinstance(doc, dict) else None) or []:
        if isinstance(m, dict) and isinstance(m.get("name"), str):
            out.add("module." + m["name"])
    for r in (doc.get("resources") if isinstance(doc, dict) else None) or []:
        if isinstance(r, dict) and isinstance(r.get("type"), str) and isinstance(r.get("name"), str):
            out.add(f"{r['type']}.{r['name']}")
    if api_only:
        for e in (doc.get("api_only") if isinstance(doc, dict) else None) or []:   # TI-3j: dropped only when justified
            if isinstance(e, dict) and isinstance(e.get("service"), str):
                out.add(API_ONLY_ENTRY_PREFIX + e["service"])
    return out


def _anchor(d: Diagnostic, entries: Mapping[str, str]) -> Diagnostic:
    """Give a gate finding the address of its intent entry (block_address) and a path relative to that entry, so its
    fingerprint does not change when a repair deletes an earlier entry (the JSON pointer is the gate's own grammar:
    /<list>/<index>/...)."""
    path = d.attribute_path or "/"
    parts = path.split("/")
    if len(parts) >= 3 and parts[0] == "" and parts[1] in _ENTRY_LISTS and parts[2].isdigit():
        key = f"/{parts[1]}/{parts[2]}"
        if key in entries and d.block_address is None:
            rest = "/" + "/".join(parts[3:]) if len(parts) > 3 else "/"
            return d.model_copy(update={"block_address": entries[key], "attribute_path": rest})
    return d


def _missing_intent(needs: Mapping[str, Any]) -> Diagnostic:
    return Diagnostic(tool="schema", code=INTENT_MISSING_CODE, severity="error", error_class=ErrorClass.CODE_DEFECT,
                      file=INTENT_PATH, attribute_path="/", source="precommit",
                      message="no infra/workload/iac_intent.json was written, and the topology has resources to "
                              "realize: " + ", ".join(sorted(needs)),
                      hint="Write infra/workload/iac_intent.json with one entry per topology resource "
                           "(\"realizes\": \"<name>\").")


def assemble_intent(files: Dict[str, str], run: IntentRun, vt: Any, root_keys: Iterable[str] = (), *,
                    existing_files: Optional[Mapping[str, Any]] = None, record: Any = None,
                    network_facts: Any = None) -> Tuple[IntentAssembly, Any]:
    """The intent step of `_assemble_tree` (mutates `files`). Returns (IntentAssembly, the topology bound to the
    intent's realizations; None without a topology).
    1. The platform's render paths are reserved: an AI file there is removed and recorded (PLATFORM_PATH_RESERVED,
       the terraform.tfvars precedent); V-IAC-PATH reports the AI's file as PATH.IAC_HCL_NOT_ALLOWED.
    2. A sticky workload's committed intent stays the source when this draft wrote none.
    3. Gate -> realizations -> render (only a gate-clean intent renders; ValidatedIntent is token-guarded).
       A failed gate renders nothing and binds no topology resource, so no platform file references an address the
       AI has not declared (TF.REFERENCE_TO_UNDECLARED_RESOURCE in a platform file stays a renderer bug)."""
    for p in PLATFORM_INTENT_RENDERS:
        if files.pop(p, None) is not None and record is not None:
            record.drop(p, "PLATFORM_PATH_RESERVED")
    if INTENT_PATH not in files and isinstance((existing_files or {}).get(INTENT_PATH), str):
        files[INTENT_PATH] = existing_files[INTENT_PATH]
    needs = vt.realization_needs() if vt is not None else {}
    unbound = vt.with_realizations({}) if vt is not None else None
    text = files.get(INTENT_PATH)
    if not isinstance(text, str):
        diags = (_missing_intent(needs),) if needs else ()
        return IntentAssembly(diagnostics=diags), unbound
    ctx = intent_context(vt, root_keys, reserved_addresses=run.reserved_addresses, network_facts=network_facts,
                         existing_files=existing_files)   # SECRET-INITIAL-VERSION
    res = II.validate_intent(text, run.artifacts, ctx)
    entries = intent_entry_addresses(res.intent) if res.intent is not None else {}
    diags: List[Diagnostic] = list(res.diagnostics)
    if not res.ok:
        return IntentAssembly(diagnostics=tuple(_anchor(d, entries) for d in diags), present=True), unbound
    realizations, rdiags = II.intent_realizations(res.intent, needs)
    diags += list(rdiags)
    rr = II.render_intent(res.validated)
    files.update(rr.files)
    bound = vt.with_realizations(realizations) if vt is not None else None
    return IntentAssembly(diagnostics=tuple(_anchor(d, entries) for d in diags), rendered=tuple(sorted(rr.files)),
                          provenance=dict(rr.provenance),
                          modules=tuple(sorted({m.module for m in res.intent.modules} | set(rr.platform_modules))),
                          intent_sha256=rr.intent_sha256, realizations=realizations, present=True,
                          push_identities=II.push_identities(res.validated)), bound


# ------------------------------------------------------------------------------------------------ TI-3i
# Register TI-3i (owner 10-21): an intent entry a repair removed as IAC.TYPE_NOT_ALLOWED / IAC.MODULE_UNKNOWN is a
# visible workload warning; when the architect's TYPED plan names that service, the build stops with a typed error
# instead of shipping without it. "Names" is decided only from typed plan fields, never from spec prose (AGENTS.md
# invariant 2): the service topology's resources (exact logical name / exact resource type) and the plan's
# `required_cloud_apis` (exact API ids, carried on the architect's compute record only when the model wrote the build
# plan, never the keyword fallback). An entry's APIs are the exact shared/api_requirements row of its type / module id.
# TI-3i-b (owner 10-25, FOLLOWUPS-1025): an api_only entry removed as IAC.API_NOT_ALLOWED is a workload warning too
# (address "api_only.<service>"; its API is that exact service), judged by the same rule as every dropped entry.
DROPPED_REASONS: Mapping[str, str] = {"REMOVAL_CODE:IAC.TYPE_NOT_ALLOWED": "IAC.TYPE_NOT_ALLOWED",
                                      "REMOVAL_CODE:IAC.MODULE_UNKNOWN": "IAC.MODULE_UNKNOWN",
                                      "REMOVAL_CODE:IAC.API_NOT_ALLOWED": "IAC.API_NOT_ALLOWED"}
ENTRY_DROPPED_WARNING = "IAC.ENTRY_DROPPED"
REQUESTED_SERVICE_DROPPED = "IAC.REQUESTED_SERVICE_DROPPED"
PLAN_APIS_RECORD_KEY = "required_cloud_apis"   # architect_agent.schemas.compute_intent_record(plan_apis=...)
_WARNINGS_MAX = 20
WARNINGS_MAX = _WARNINGS_MAX   # the workload warnings list bound (SECRET-INITIAL-VERSION appends its own, handler.py)
_MODULE_ID_RE = re.compile(r"[a-z][a-z0-9_-]{1,62}")                  # shared.iac_intent ModuleId
_TYPE_RE = re.compile(II.PROVIDER_TYPE_PATTERN.strip("^$"))
_LOGICAL_RE = re.compile(II.HCL_IDENT_PATTERN.strip("^$"))
_API_RE = re.compile(II.API_SERVICE_PATTERN.strip("^$"))
__all__ += ["DROPPED_REASONS", "ENTRY_DROPPED_WARNING", "REQUESTED_SERVICE_DROPPED", "PLAN_APIS_RECORD_KEY",
            "API_ONLY_ENTRY_PREFIX", "plan_required_apis", "dropped_intent_entries", "dropped_entry_outcome"]


def _grammar(value: Any, pattern: "re.Pattern[str]") -> Optional[str]:
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def plan_required_apis(record: Any) -> Tuple[str, ...]:
    """The plan's typed API list from the architect's compute record (exact API grammar; anything else dropped)."""
    raw = record.get(PLAN_APIS_RECORD_KEY) if isinstance(record, Mapping) else None
    if not isinstance(raw, (list, tuple)):
        return ()
    return tuple(sorted({a for a in raw if _grammar(a, _API_RE)}))


def dropped_intent_entries(before_text: Any, reasons: Mapping[str, str]) -> Tuple[Dict[str, Any], ...]:
    """The entries an accepted repair removed with a TYPE_NOT_ALLOWED / MODULE_UNKNOWN justification
    (repair_loop.removal_justifications), identified in the intent document they were removed from (json.loads, exact
    addresses). Identity fields pass their closed grammar or are None (they are shown in the Control Center)."""
    wanted = {a: DROPPED_REASONS[r] for a, r in (reasons or {}).items() if r in DROPPED_REASONS}
    if not wanted:
        return ()
    try:
        doc = json.loads(before_text) if isinstance(before_text, str) else None
    except ValueError:
        doc = None
    doc = doc if isinstance(doc, dict) else {}
    found: Dict[str, Dict[str, Any]] = {}
    for m in doc.get("modules") if isinstance(doc.get("modules"), list) else []:
        if isinstance(m, dict) and isinstance(m.get("name"), str) and "module." + m["name"] in wanted:
            found["module." + m["name"]] = {"kind": "module", "type": None,
                                            "module": _grammar(m.get("module"), _MODULE_ID_RE),
                                            "realizes": _grammar(m.get("realizes"), _LOGICAL_RE)}
    for r in doc.get("resources") if isinstance(doc.get("resources"), list) else []:
        if isinstance(r, dict) and isinstance(r.get("type"), str) and isinstance(r.get("name"), str):
            addr = f"{r['type']}.{r['name']}"
            if addr in wanted:
                args = r.get("arguments") if isinstance(r.get("arguments"), dict) else {}
                found[addr] = {"kind": "resource", "module": None, "type": _grammar(r.get("type"), _TYPE_RE),
                               "realizes": _grammar(r.get("realizes"), _LOGICAL_RE),
                               # Fable F1: the API a dropped google_project_service named (exact grammar or None)
                               "service": _grammar(args.get("service"), _API_RE)}
    for a in doc.get("api_only") if isinstance(doc.get("api_only"), list) else []:   # TI-3i-b
        if isinstance(a, dict) and isinstance(a.get("service"), str):
            addr = API_ONLY_ENTRY_PREFIX + a["service"]
            if addr in wanted:
                found[addr] = {"kind": "api_only", "module": None, "type": None, "realizes": None,
                               "service": _grammar(a.get("service"), _API_RE)}
    out = []
    for addr in sorted(wanted):
        entry = found.get(addr) or {"kind": None, "type": None, "module": None, "realizes": None}
        entry = {"service": None, **entry}
        out.append({"address": addr, "removed_as": wanted[addr], **entry})
    return tuple(out)


def _platform_module_ids() -> FrozenSet[str]:
    """Golden module ids the platform itself renders (compute kinds, the platform network, the foundation)."""
    return frozenset(MODULE_DIR.values()) | {II.PLATFORM_NETWORK_MODULE_ID, "base"}


def _final_coverage(final_text: Any, art: Any) -> Tuple[Set[str], Set[str], Tuple[str, ...]]:
    """(resource types the shipped intent declares, topology logicals it realizes, its API-only services)."""
    try:
        intent = II.IacIntent.model_validate(json.loads(final_text)) if isinstance(final_text, str) else None
    except (ValueError, TypeError):
        intent = None
    if intent is None:
        return set(), set(), ()
    types = {r.type for r in intent.resources}
    for m in intent.modules:
        types |= set(((art.module(m.module) if art is not None else None) or {}).get("declares_types") or ())
    realized = {e.realizes for e in list(intent.modules) + list(intent.resources) if e.realizes}
    return types, realized, II.api_only_services(intent)


def _api_table() -> Mapping[str, Any]:
    try:
        from shared.api_requirements import load_table
    except ImportError:  # pragma: no cover - vendored layout
        from ..shared.api_requirements import load_table  # type: ignore
    return load_table()


def _shipped_coverage(tree: Mapping[str, Any], art: Any
                      ) -> Tuple[Mapping[str, Any], Set[str], Set[str], Set[str], Set[str]]:
    """(api table, vending + foundation APIs, every API the shipped tree provides, intent resource types, realized
    topology logicals). Provided = the exact shared/api_requirements rows of the shipped root Terraform (modules,
    resources, the render) + the vending / foundation APIs + the intent's api_only services."""
    try:
        from shared.api_requirements import required_apis
    except ImportError:  # pragma: no cover - vendored layout
        from ..shared.api_requirements import required_apis  # type: ignore
    table = _api_table()
    base = set(table["base_apis"]) | set(table["foundation_base_apis"])
    root = {p: t for p, t in (tree or {}).items() if isinstance(t, str) and p.startswith(WORKLOAD_ROOT)
            and "/" not in p[len(WORKLOAD_ROOT):] and p.endswith((".tf", ".tf.json"))}
    final_types, final_realized, final_api_only = _final_coverage((tree or {}).get(INTENT_PATH), art)
    provided = set(required_apis(root).apis) | base | set(final_api_only)
    return table, base, provided, final_types, final_realized


# ------------------------------------------------------------------------------------------------ TI-3i-e
# Register TI-3i-e (owner 10-25): generate mode - an API the architect's typed plan needs (`required_cloud_apis`, the
# vending / foundation APIs excluded) that nothing in the shipped build provides stops the build typed, even when no
# entry was dropped. "Provides" is the exact table rule of TI-3i (_shipped_coverage). An API a dropped-entry stop
# already names is not stopped twice.
PLAN_API_NOT_PROVIDED = "IAC.PLAN_API_NOT_PROVIDED"
PLAN_API_WARNING = "IAC.PLAN_API_MISSING"
__all__ += ["PLAN_API_NOT_PROVIDED", "PLAN_API_WARNING", "plan_api_outcome", "api_providers"]


def api_providers(api: str, art: Any) -> Dict[str, List[str]]:
    """The typed ways the intent can provide `api` (exact table lookups, no name matching): the API-only table, the
    golden modules the intent may instantiate whose shared/api_requirements row holds it (platform-rendered modules
    excluded), and the allow-listed resource types whose row holds it."""
    table = _api_table()
    modules = sorted(m for m, apis in (table.get("modules") or {}).items()
                     if api in (apis or ()) and m not in _platform_module_ids()
                     and (art is not None and art.module(m) is not None))
    allowed = set(art.allowed_types) if art is not None else set()
    types = sorted(t for t, apis in (table.get("resource_types") or {}).items()
                   if api in (apis or ()) and t in allowed and art.not_expressible_owner(t) is None)
    return {"api_only": [api] if api in II.API_ONLY_SERVICES else [], "modules": modules, "resource_types": types}


def plan_api_outcome(tree: Mapping[str, Any], plan_apis: Iterable[str], art: Any,
                     already: Iterable[str] = ()) -> Tuple[List[Dict[str, Any]], List[Diagnostic]]:
    """(workload warnings, stop diagnostics) for the plan's APIs the shipped tree `tree` does not provide. `already`:
    APIs a dropped-entry stop (dropped_entry_outcome) already names. One warning + one stop per API, sorted."""
    _table, base, provided, _t, _r = _shipped_coverage(tree, art)
    skip = set(already or ())
    warnings: List[Dict[str, Any]] = []
    stops: List[Diagnostic] = []
    for api in sorted(set(plan_apis or ()) - base - provided - skip):
        ways = api_providers(api, art)
        detail = f"the architect's plan needs {api} and nothing in the build provides it"
        warnings.append({"code": PLAN_API_WARNING, "removed_as": None, "address": api,
                         "kind": "plan_api", "type": None, "module": None, "realizes": None, "service": api,
                         "plan_named": [f"plan API {api}"], "missing": [f"API {api}"], "missing_apis": [api],
                         "owner": None,
                         "stops_build": True, "providers": ways, "message": detail})
        stops.append(Diagnostic(
            tool="schema", code=PLAN_API_NOT_PROVIDED, severity="error", error_class=ErrorClass.PLATFORM_DEFECT,
            file=INTENT_PATH, attribute_path="/", block_address=None, symbol=api, source="precommit",
            message=detail + ": the workload is not shipped without it",
            hint=_plan_api_hint(api, ways)))
    return warnings[:_WARNINGS_MAX], stops


def _plan_api_hint(api: str, ways: Mapping[str, List[str]]) -> str:
    parts = []
    if ways.get("api_only"):
        parts.append('an api_only entry {"service": "%s"}' % api)
    if ways.get("modules"):
        parts.append("a golden module that needs it (" + ", ".join(ways["modules"]) + ")")
    if ways.get("resource_types"):
        parts.append("an allow-listed resource that needs it (" + ", ".join(ways["resource_types"]) + ")")
    if not parts:
        return (f"The typed IaC intent cannot provide {api} yet. Add it to the platform (a golden module or an "
                "allow-list row, by PR) or change the specification.")
    return f"The typed IaC intent provides {api} through " + " or ".join(parts) + "."


# ------------------------------------------------------------------------------------------------ TI-3i-c
# Register FOLLOWUPS-1025 TI-3i-c (owner 10-25): before a plan-named stop (IAC.REQUESTED_SERVICE_DROPPED, TI-3i-e's
# IAC.PLAN_API_NOT_PROVIDED (held for 0.9.1)) the IaC persona gets ONE repair turn with the stop as a finding on the intent, naming
# the typed ways to provide what is missing (exact tables only). A stop with no typed way gets no turn (no LLM spend
# that cannot help); the stop is then raised as before.
__all__ += ["repair_turn_seeds", "types_providers", "intent_outcome"]


def intent_outcome(drops: Iterable[Mapping[str, Any]], tree: Mapping[str, Any], topology: Any,
                   plan_apis: Iterable[str], art: Any) -> Tuple[List[Dict[str, Any]], List[Diagnostic]]:
    """(workload warnings, stops) of a passing intent-path tree: TI-3i dropped entries. TI-3i-e (plan APIs nothing
    provides, plan_api_outcome) is held for 0.9.1, owner decision pending: it is not wired here until then."""
    plan_apis = tuple(plan_apis or ())
    warnings, stops = dropped_entry_outcome(drops, tree, topology, plan_apis, art)
    return warnings[:_WARNINGS_MAX], stops


def types_providers(rtype: str, art: Any) -> List[str]:
    """AI-instantiable golden modules whose catalog `declares_types` holds `rtype` (exact), sorted."""
    if art is None or not rtype:
        return []
    return sorted(m for m in art.ai_modules if rtype in ((art.module(m) or {}).get("declares_types") or ()))


def repair_turn_seeds(warnings: Iterable[Mapping[str, Any]], art: Any, topology: Any = None) -> List[Diagnostic]:
    """The repair turn's findings: one CODE_DEFECT diagnostic on the intent per stopping warning that has a typed way
    to provide what is missing. Identity (fingerprint) = code + the warning's address (the dropped entry, or the plan
    API as symbol), so a finding is the same on every candidate while it holds."""
    topo = {r.logical_name: r.type for r in (getattr(getattr(topology, "intent", None), "resources", None) or ())}
    out: List[Diagnostic] = []
    for w in warnings or ():
        if not w.get("stops_build"):
            continue
        ways: List[str] = []
        for api in w.get("missing_apis") or ():
            # review F2: a missing API is offered only as pure enablement (an api_only row); a module or resource that
            # merely needs the same API would add unrequested infrastructure (the operator hint keeps the full list)
            if api_providers(api, art)["api_only"]:
                ways.append('for %s an api_only entry {"service": "%s"}' % (api, api))
        types = {t for t in (w.get("type"), topo.get(w.get("realizes"))) if t}
        for t in sorted(types):
            mods = types_providers(t, art)
            if mods:
                realizes = f' with "realizes": "{w["realizes"]}"' if w.get("realizes") in topo else ""
                ways.append(f"for {t} a golden module that declares it ({', '.join(mods)}){realizes}")
        if not ways:
            continue
        plan_api = w.get("kind") == "plan_api"
        code = PLAN_API_NOT_PROVIDED if plan_api else REQUESTED_SERVICE_DROPPED
        out.append(Diagnostic(
            tool="schema", code=code, severity="error", error_class=ErrorClass.CODE_DEFECT, file=INTENT_PATH,
            attribute_path="/", block_address=None if plan_api else w.get("address"),
            symbol=w.get("service") if plan_api else None, source="precommit",
            message=str(w.get("message") or "") + ": the build stops unless the intent provides it",
            hint=("The architect's plan needs this and the intent does not provide it. Add the typed entry that "
                  "provides it: " + "; ".join(ways) + ". Keep every other entry as it is. If none of these "
                  "fits the specification, return the intent unchanged (the build then stops for an operator).")))
    return out


def dropped_entry_outcome(dropped: Iterable[Mapping[str, Any]], tree: Mapping[str, Any], topology: Any,
                          plan_apis: Iterable[str], art: Any) -> Tuple[List[Dict[str, Any]], List[Diagnostic]]:
    """(workload warnings, stop diagnostics) for the entries the repairs dropped (dropped_intent_entries), judged on
    the shipped tree `tree` (its intent and root Terraform). The plan names an entry when it realized a topology
    resource, has a topology resource's type, or its exact API row meets the plan's `required_cloud_apis` (the
    foundation's own APIs excluded). It stops the build only when the plan names it, nothing shipped provides that
    (no realizing entry / no entry of that type / no shipped module, resource or api_only entry needing that API), and
    it is not something the platform owns or policy forbids (allowed_types not_expressible, platform module ids):
    those are provided elsewhere or refused by design. Every dropped entry is a warning."""
    table, base, provided, final_types, final_realized = _shipped_coverage(tree, art)
    topo_res = list(getattr(getattr(topology, "intent", None), "resources", None) or ())
    topo_types = {r.type for r in topo_res}
    topo_logicals = {r.logical_name for r in topo_res}
    plan = set(plan_apis or ()) - base
    warnings: List[Dict[str, Any]] = []
    stops: List[Diagnostic] = []
    seen: Set[Tuple[Any, ...]] = set()
    for e in dropped:
        key = (e.get("address"), e.get("kind"), e.get("type"), e.get("module"), e.get("realizes"))
        if key in seen:
            continue
        seen.add(key)
        rtype, mid, logical = e.get("type"), e.get("module"), e.get("realizes")
        api_veto_exempt = False
        if e.get("kind") == "resource" and rtype == II.API_ONLY_SERVICE_TYPE and e.get("service"):
            # Fable F1: a dropped google_project_service names its API exactly; the API (not the platform-owned
            # type) is what the plan may have asked for, so "platform_owned" does not veto the stop for it
            owner = art.not_expressible_owner(rtype) if art is not None else None
            apis = {e["service"]}
            api_veto_exempt = owner == "platform_owned"
        elif e.get("kind") == "resource" and rtype:
            owner = art.not_expressible_owner(rtype) if art is not None else None
            apis = table["resource_types"].get(rtype)
        elif e.get("kind") == "module" and mid:
            owner = "platform_module" if mid in _platform_module_ids() else None
            apis = table["modules"].get(mid)
        elif e.get("kind") == "api_only":   # TI-3i-b: the entry's API is its exact service (grammar-checked or None)
            owner = None
            apis = {e["service"]} if e.get("service") else None
        else:
            owner, apis = None, None
        named: List[str] = []
        missing: List[str] = []
        missing_apis: List[str] = []   # TI-3i-e: the exact API ids of `missing` (plan_api_outcome's `already`)
        if logical and logical in topo_logicals:
            named.append(f"topology resource {logical}")
            if logical not in final_realized:
                missing.append(f"topology resource {logical}")
        if rtype and rtype in topo_types:
            named.append(f"topology resource type {rtype}")
            if rtype not in final_types:
                missing.append(f"resource type {rtype}")
        for api in sorted(set(apis or ()) & plan):
            named.append(f"plan API {api}")
            if api not in provided:
                missing.append(f"API {api}")
                missing_apis.append(api)
        # TI-3i-b: an api_only removal stays a workload warning; its plan-named stop is the TI-3i-e false-stop class,
        # held for 0.9.1 with TI-3i-e (owner decision pending; review F1)
        stop = bool(missing) and (owner is None or api_veto_exempt) and e.get("kind") != "api_only"
        what = rtype or (f"golden module {mid}" if mid else
                         "API-only entry" if e.get("kind") == "api_only" else "unknown entry")
        detail = (f"{e.get('address')} ({what}) was removed by a repair as {e.get('removed_as')}"
                  + (f" ({owner.replace('_', ' ')})" if owner else "")
                  + (f"; the architect's plan names it ({', '.join(named)})" if named else "")
                  + (f" and the build does not provide {', '.join(missing)}" if missing else ""))
        warnings.append({"code": ENTRY_DROPPED_WARNING, "removed_as": e.get("removed_as"), "address": e.get("address"),
                         "kind": e.get("kind"), "type": rtype, "module": mid, "realizes": logical,
                         "service": e.get("service"),
                         "plan_named": named, "missing": missing, "missing_apis": missing_apis, "owner": owner,
                         "stops_build": stop, "message": detail})
        if stop:
            stops.append(Diagnostic(
                tool="schema", code=REQUESTED_SERVICE_DROPPED, severity="error",
                error_class=ErrorClass.PLATFORM_DEFECT, file=INTENT_PATH, attribute_path="/",
                block_address=e.get("address"), symbol=logical, source="precommit",
                message=detail + ": the workload is not shipped without it",
                hint="The typed IaC intent cannot express this service yet. Add it to the platform (a golden module "
                     "or an allow-list row, by PR) or change the specification. An API the code only calls can be an "
                     "api_only entry when it is on the API-only allow-list."))
    return warnings[:_WARNINGS_MAX], stops
