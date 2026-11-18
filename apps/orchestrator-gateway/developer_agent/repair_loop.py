"""Step 1 S1-B: the bounded repair loop (lane 8B plan §4.3, §5, §6, §7; integration plan §1.1, §S.5).

    draft D --assemble--> tree T --ValidatorStack--> report R
      PASS                  -> commit T (artifact_hash(T) == R.artifact_hash)
      UNAVAILABLE           -> StageError(GATE_UNAVAILABLE), zero LLM spend
      non-CODE_DEFECT error -> StageError(PLATFORM_DEFECT | BROWNFIELD_CONFLICT), zero LLM spend
      same fingerprints as before / budget gone -> RepairBudgetExhausted(R)
      else: CODE_DEFECT diagnostics grouped by the persona that wrote the DRAFT file -> one RepairTask per persona
            (concurrent); D' = D | repaired draft files; re-assemble; accept iff (F4) something was fixed, every new
            finding sits in a file whose visibility improved (or, R3c, is a dangling reference to a block this
            candidate removed with a justification, with net progress), and nothing was lost without a diagnosed
            justification (removal_justifications, recorded in RepairEvent.removal_reasons).

Routing (8B §4.3) is a pure function of ownership (exact per-run sets), the AssemblyRecord (replaced vs dropped) and
the diagnostic itself. The loop repairs the draft, never the assembled tree, so the platform's own assembly is
re-applied exactly on every iteration. The per-trace budget (iterations, tokens incl. thoughts, wall clock) lives in
a LedgerStore and is saved after every attempt (store failure -> GATE_UNAVAILABLE).
"""
from __future__ import annotations

import ast
import io
import json
import logging
import posixpath
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Set, Tuple

import stage_deadline   # STAGE-DEADLINE (gateway root module)
from .llm_transport import LlmStageBudgetExhausted   # SLOW-CALL-FALLBACK: the walk's own out-of-time stop
from .llm_transport import REPAIR_WALL_CLOCK   # REPAIR-WALL-CLOCK-ROOM: the walk's typed "no room" result

try:
    from shared.artifact_ownership import Ownership, UnattributablePath, classify_path
    from shared.diagnostics import (PRECEDENCE, AssemblyRecord, Diagnostic, ErrorClass, RepairBudgetExhausted,
                                    RepairEvent, RepairLedger, StageError, StoreUnavailable, ValidationReport,
                                    fingerprint)
    from shared.hallucination_stack import (HallucinationStackSettings, effective_dispatch_token_budget,
                                            effective_repair_token_budget, repair_call_max_output_tokens,
                                            repair_call_thinking_budget)
    from shared.path_safety import GIT_RESERVED, UnsafePathError, validate_relpath
except ImportError:  # pragma: no cover
    from ..shared.artifact_ownership import Ownership, UnattributablePath, classify_path  # type: ignore
    from ..shared.diagnostics import (PRECEDENCE, AssemblyRecord, Diagnostic, ErrorClass,  # type: ignore
                                      RepairBudgetExhausted, RepairEvent, RepairLedger, StageError, StoreUnavailable,
                                      ValidationReport, fingerprint)
    from ..shared.hallucination_stack import (HallucinationStackSettings,  # type: ignore
                                              effective_dispatch_token_budget, effective_repair_token_budget,
                                              repair_call_max_output_tokens, repair_call_thinking_budget)
    from ..shared.path_safety import GIT_RESERVED, UnsafePathError, validate_relpath  # type: ignore

from .assembly import CUSTOM_TF, WORKLOAD, file_keys, index_blocks
from .deploy_repair import live_seeds, with_seeds
from . import qa_repair   # QA-FEEDBACK: QA's findings as seeds (file-content liveness, untrusted output block)
from . import qa_requirements_guard   # QA-REPAIR-ON-IMPORT-FAILURE: the add-only rule of a QA repair's requirements edit
from .iac_intent_contract import (IAC_HCL_NOT_ALLOWED_CODE, IAC_PERSONA, INTENT_MISSING_CODE, INTENT_PATH,
                                  INTENT_REMOVAL_CODES)
from .iac_intent_contract import RENDER_PATH as INTENT_RENDER_PATH
from .iac_intent_contract import API_ONLY_ENTRY_PREFIX, dropped_intent_entries   # TI-3j / TI-3i  # noqa: F401
from .iac_intent_contract import intent_document_addresses   # JUDGE-NAMED-INTENT-REMOVAL: the one intent parse
from .validators.base import ValidationContext, ValidatorStack
from .validators.container import (ENTRYPOINT_CODE, ENTRYPOINT_MASKED_CODES, K8S_APPLY_DIR,
                                  K8S_WORKLOAD_MISSING_CODE, HINT_PLANNED_CREATE, HINT_PLANNED_FACTS,
                                  PLANNED_SERVICE_CREATE_FILES, PLANNED_SERVICE_DETAIL, WEB_PROCESS,
                                  planned_push_route_findings, planned_push_route_unverified, planned_service_facts)
from .validators.local_imports import CODE as LOCAL_IMPORT_CODE
from .validators.local_imports import unjudged_imports
from .validators.push_plan import CODE as PUSH_PLAN_CODE
from .validators.plan_targets import CODE as PLAN_TARGET_MISSING_CODE   # PLAN-TARGET-FILES
from .validators.push_plan import push_plan_judged
from .validators.policy_tables import FOUNDATION_DECLARED_TYPES, HINT_PLATFORM_OWNED_REFERENCE
from .validators.policy_tables import HINT_UNSAFE_KEY as UNSAFE_KEY_HINT
from .validators.policy_tables import PLATFORM_OWNED_TYPES
from .validators.policy_tables import HINT_SENSITIVE_OUTPUT, SENSITIVE_OUTPUT_CODE   # SAT-02
from .validators.python_units import top_level_units, unit_at

logger = logging.getLogger("castor-repair-loop")

REPAIR_PROMPT_VERSION = "step1-repair-v2"   # changing the template invalidates the repair cassettes (§11.3)
# v2 (R3c, 10-13): deterministic diagnostic order, removal rules spelled out, replaced/platform-owned reference
# actions in the hints, specific feedback on a rejected attempt.
PLATFORM_OWNED_REFERENCE_ACTION = ("This address is a foundation-owned resource type: the workload foundation declares it and the platform enables APIs itself. Delete the reference (a depends_on entry or an output that only re-exports it); if the value is really needed, use the module.foundation outputs (e.g. module.foundation.database_name, module.foundation.docker_repo_id).")
REMOVAL_CODES = frozenset({"TF.DUPLICATE_RESOURCE_CONFIGURATION", "POLICY.FORBIDDEN_RESOURCE_TYPE",
                           "POLICY.PLATFORM_OWNED_TYPE", "POLICY.PUBLIC_MEMBER",
                           "POLICY.PLATFORM_OWNED_BINDING",   # S2-B B4: the IAP service-agent grant
                           "POLICY.PROJECT_WIDE_GRANT",   # OVERBROAD-SECRET-GRANT: replaced by the scoped grant
                           SENSITIVE_OUTPUT_CODE}   # SAT-02: deleting an output that exposes a sensitive value
                          | INTENT_REMOVAL_CODES)   # TI-3: intent entries that cannot be expressed / AI .tf blocks
# Unsafe file keys (V7 / V8). On a key the LLM wrote, the repair is a rename (Step 1 code RT F12).
UNSAFE_KEY_CODES = frozenset({"PATH.UNSAFE_KEY", "GATE.UNSAFE_PATH_KEY"})
# FD-4AW-a F1/F2: a safe LLM draft key the platform cannot check (a root *.tf.json) or reserved for the human architect
# (human.tf, *_override.tf): repaired by the same rename to a new key, by the persona that wrote it. The RENAME prompt
# section is reused unchanged (no prompt text change); the diagnostic's hint states the real reason.
# AI-TOFU-REFUSED (owner 10-29): an AI-written .tofu / .tofu.json file (V2n) comes back under a new .tf key the same way.
RENAME_ONLY_CODES = frozenset({"POLICY.JSON_IAC_NOT_CHECKABLE", "PATH.USER_OWNED_NAME_WRITTEN_BY_LLM",
                               "POLICY.TOFU_FILE_NOT_ALLOWED"})
RENAME_CODES = UNSAFE_KEY_CODES | RENAME_ONLY_CODES
REPLACED_REASONS_WITH_HINT = frozenset({"CLOUD_RUN_REPLACED_BY_MODULE", "GKE_CLUSTER_REPLACED_BY_MODULE"})
# A required file that does not exist yet (S2-A, V3c): the repair is to WRITE that exact path. The diagnostic's file is
# the missing path `apps/<svc>/<name>`; it is routed to the persona that wrote the service's code and is the only new
# key that task may return (an exception to "do not add files", stated in its prompt).
# + lane 10 RT F7; + HS-40: CONTAINER.MIGRATION_NOT_INVOKED names apps/<svc>/Procfile, which may not exist yet (then it
# rides on the same create as ENTRYPOINT_MISSING; an existing Procfile is an ordinary file repair)
# PWB-4: CONTAINER.K8S_WORKLOAD_MISSING's missing file is `k8s/<svc>.yaml` (repo root); see _route_k8s_create.
# TI-3: IAC.INTENT_MISSING names infra/workload/iac_intent.json, created by the IaC persona (_route_create).
# PLAN-TARGET-FILES: PLAN.TARGET_FILE_MISSING names a DAG target file the developer must write (any developer path);
# see _route_plan_target_create.
CREATE_FILE_CODES = frozenset({"CONTAINER.ENTRYPOINT_MISSING", "TOPOLOGY.WORKER_SCRIPT_MISSING",
                               "CONTAINER.MIGRATION_NOT_INVOKED", K8S_WORKLOAD_MISSING_CODE, INTENT_MISSING_CODE,
                               PLAN_TARGET_MISSING_CODE})
PY_SYNTAX_CODE = "PY.SYNTAX"   # V3a-syntax: one finding per broken top-level unit (AC-1, validators/python_units.py)
PLATFORM_OWNERSHIP = (Ownership.PLATFORM_RENDERED, Ownership.PLATFORM_VENDORED)
SYNTAX_CODES_PATH = posixpath.join(posixpath.dirname(__file__).replace("\\", "/"), "validators", "syntax_codes.json")


def _load_syntax_codes() -> Dict[str, Set[str]]:
    try:
        with open(SYNTAX_CODES_PATH) as fh:
            data = json.load(fh)
        return {eng: {c for codes in fixtures.values() for c in codes} for eng, fixtures in data["engines"].items()}
    except Exception:  # noqa: BLE001 - no table: only the engine-independent visibility signals are used
        return {}


SYNTAX_CODES = _load_syntax_codes()


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _is_root_tf(path: str) -> bool:
    return path.startswith(WORKLOAD) and path.endswith(".tf") and "/" not in path[len(WORKLOAD):]


# ------------------------------------------------------------------------------------------------ assembly view
@dataclass
class Assembled:
    """One assembly of a draft: the tree plus what the validators and the router need to know about it."""

    tree: Dict[str, str]
    record: AssemblyRecord
    platform_files: Dict[str, str] = field(default_factory=dict)        # vendored snapshot
    vendored_before_restore: Dict[str, str] = field(default_factory=dict)
    assembled_root: Optional[Dict[str, str]] = None                     # final root module, after every healer (RT F1)
    iac_intent: Optional[Any] = None    # TI-3: iac_intent_contract.IntentAssembly on the intent path; None = mode off


@dataclass
class LoopContext:
    trace_id: str
    product_id: str
    assemble: Callable[[Dict[str, str]], Assembled]
    stack: ValidatorStack
    ledger_store: Any
    settings: HallucinationStackSettings
    attribution: Dict[str, str]
    llm_draft_paths: Set[str]
    preexisting: Set[str]
    prior_llm: Dict[str, str] = field(default_factory=dict)
    preexisting_files: Dict[str, str] = field(default_factory=dict)   # repository files (prior custom.tf head, ...)
    repair_fn: Optional[Callable[["RepairTask"], Dict[str, Any]]] = None
    model: str = ""
    available_providers: Optional[List[str]] = None
    engine_label: str = "opentofu 1.9.0"
    swarm_envelope: Optional[int] = None
    clock: Callable[[], float] = time.monotonic
    events: List[RepairEvent] = field(default_factory=list)
    # TI-3i: the typed-intent entries accepted repairs removed as TYPE_NOT_ALLOWED / MODULE_UNKNOWN (in order)
    intent_drops: List[Dict[str, Any]] = field(default_factory=list)
    # TI-5-R3 (deploy_repair.py): the deploy's CODE_DEFECT findings on intent entries, re-added to every report while
    # their entry is unchanged, and the only paths a repair may edit. Defaults: nothing changes.
    seed_diagnostics: Tuple[Diagnostic, ...] = ()
    seed_entries: Mapping[str, str] = field(default_factory=dict)
    repairable_paths: Optional[FrozenSet[str]] = None
    # QA-FEEDBACK (qa_repair.py): the seeds are QA's findings, live while their file is the tested content (seed_files
    # non-empty); `untrusted_output` = the framed QA block shown to the tasks that repair them. Defaults: unchanged.
    seed_files: Mapping[str, str] = field(default_factory=dict)
    untrusted_output: str = ""
    # QA-REPAIR-ON-IMPORT-FAILURE: requirements file -> the names a candidate may add. Default {}: no check, unchanged.
    requirements_guard: Mapping[str, FrozenSet[str]] = field(default_factory=dict)
    # QA-REPAIR-CRASH-REQUIREMENTS-GUARD: requirements file a crash repair may replace -> names it may hold. Default {}.
    requirements_crash_guard: Mapping[str, FrozenSet[str]] = field(default_factory=dict)
    # TI-3i-c (developer handler): findings computed from each candidate's assembled tree and added to its report while
    # they hold (the plan-named stop's one repair turn). Default None: nothing changes.
    seed_check: Optional[Callable[[Mapping[str, str]], List[Diagnostic]]] = None
    # FD55-W5c: the `apps/<svc>/` of every planned service already offered its one whole-service CREATE round in this
    # loop (filled after the round is dispatched); a service in it stops as before (PLANNED_SERVICE_STOP_REASON)
    planned_service_rounds: Set[str] = field(default_factory=set)
    # FD55-W5c-PLAN-FACTS: the run's ValidatedTopology (None: no typed plan): the facts of that round's hint, and the
    # planned-push check on the services it wrote (validators/container.py planned_push_route_findings)
    topology: Any = None
    # REPAIR-WALL-CLOCK-ROOM (RT F2): True while the dispatch's repair wall clock still has room for one repair call,
    # by the call walk's own rule (llm_transport.call_timeout_s on the same deadline; set by the developer handler).
    # None (tests, eval harness): only the loop's own wall-clock check, as before.
    repair_call_room: Optional[Callable[[], bool]] = None
    # PLAN-TARGET-FILES: each required DAG target path -> the other target paths of the DAG task naming it (exact, DAG
    # order; developer_agent.plan_targets.required_plan_targets). Default {}: no plan target is ever routed.
    plan_targets: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    # MANIFEST-PATH-DEFERS-TO-DAG: each applied manifest path the DAG names for a gke service -> that service
    # (plan_targets.dag_manifest_paths, inverted). Default {}: a missing manifest's service is its file stem, as before.
    manifest_services: Mapping[str, str] = field(default_factory=dict)


@dataclass
class RepairTask:
    persona: str
    files_to_fix: Dict[str, str]
    diagnostics: List[Dict[str, Any]]
    read_only_context: Dict[str, str]
    iteration: int
    remaining_iterations: int
    feedback: str
    max_output_tokens: int                              # bound on candidates + thoughts (sent as max_output_tokens)
    renames: List[str] = field(default_factory=list)   # unsafe LLM keys in files_to_fix: return them under a new key
    creates: List[str] = field(default_factory=list)   # missing required files in files_to_fix (empty): write them
    thinking_budget: Optional[int] = None               # ThinkingConfig(thinking_budget); < max_output_tokens
    untrusted_output: str = ""                          # QA-FEEDBACK: the framed QA block (QA repair tasks only)
    # SLOW-CALL-FALLBACK: the size the bound was computed from, so a fallback model's bound is re-sized for its family
    files_to_fix_tokens: Optional[int] = None

    def prompt(self) -> str:
        return render_repair_prompt(self)


def _diag_sort_key(x: Mapping[str, Any]) -> Tuple[str, int, str, str, str, str]:
    """R3c: the validators' finding order is not deterministic across runs (concurrent tools), so the same repair
    task rendered different prompts; the prompt lists the findings in this fixed order."""
    return (str(x.get("file") or ""), int(x.get("line") or 0), str(x.get("code") or ""), str(x.get("block") or ""),
            str(x.get("message") or ""), json.dumps(x, sort_keys=True, default=str))


def render_repair_prompt(task: "RepairTask") -> str:
    parts = [
        f"REPAIR TASK ({REPAIR_PROMPT_VERSION}) for persona {task.persona}, iteration {task.iteration} "
        f"({task.remaining_iterations} remaining).",
        "A deterministic validation of the assembled repository (OpenTofu validate, Python compiler, platform policy) "
        "found the errors below in files you generated. Fix them.",
        "Rules: return ONLY the files listed under FILES TO FIX, each complete, as JSON {\"files\": {\"<path>\": "
        "\"<content>\"}}. Keep every declaration unless a diagnostic on that block says it is forbidden, "
        "platform-owned, public, privileged or duplicated, or its hint says to delete it. Do not add, rename or delete "
        "files. Use each hint: it is a platform fact.",
        "DIAGNOSTICS:", json.dumps(sorted(task.diagnostics, key=_diag_sort_key), indent=1, sort_keys=True),
        "FILES TO FIX:", json.dumps(task.files_to_fix, indent=1, sort_keys=True),
    ]
    if task.renames:   # only when present, so every other repair prompt (and its cassette key) is unchanged
        parts += ["RENAME (exception to the rules above): each key listed here is not a safe relative path. Return "
                  "that file's content under ONE new safe relative key (no leading '/', no drive letter, no "
                  "backslash, no empty, '.' or '..' components, no '.git' component) that is not already in the "
                  "repository, and do not return the old key:", json.dumps(sorted(task.renames), indent=1)]
    if task.creates:   # only when present (S2-A): every other repair prompt (and its cassette key) is unchanged
        parts += ["CREATE (exception to the rules above): each key listed here is a required file that does not exist "
                  "yet; it appears under FILES TO FIX with empty content. Return it, complete, under exactly that "
                  "key:", json.dumps(sorted(task.creates), indent=1)]
    if task.untrusted_output:   # QA-FEEDBACK: only on a QA repair, so every other repair prompt is unchanged
        parts += [qa_repair.QA_OUTPUT_HEADER, task.untrusted_output]
    if task.read_only_context:
        parts += ["READ-ONLY CONTEXT (do not return these):", json.dumps(task.read_only_context, indent=1,
                                                                         sort_keys=True)]
    if task.feedback:
        parts += ["FEEDBACK ON YOUR PREVIOUS ATTEMPT:", task.feedback]
    return "\n\n".join(parts)


def _one_creator_per_file(by_persona: Dict[str, Dict[str, Any]]) -> None:
    """PLAN-TARGET-FILES: a path to create that two routes give to two personas (PLAN.TARGET_FILE_MISSING beside the
    create of another validator on the same path, e.g. CONTAINER.K8S_WORKLOAD_MISSING on a DAG-named manifest) is
    offered to ONE persona: the one another create code routed it to (its route is specific), else the first in
    persona order; that persona's task also gets the other findings on the path. Before PLAN.TARGET_FILE_MISSING every
    create route of one path gave one persona, so this changes nothing there (in place; exact path equality)."""
    owner: Dict[str, str] = {}
    for persona in sorted(by_persona):
        slot = by_persona[persona]
        for x in slot["diags"]:
            if x.get("file") in slot["creates"] and x.get("code") != PLAN_TARGET_MISSING_CODE:
                owner.setdefault(x["file"], persona)
    for persona in sorted(by_persona):
        for c in sorted(by_persona[persona]["creates"]):
            owner.setdefault(c, persona)
    for persona in sorted(by_persona):
        slot = by_persona[persona]
        for c in sorted(slot["creates"]):
            if owner[c] == persona:
                continue
            moved = [x for x in slot["diags"] if x.get("file") == c]
            slot["diags"] = [x for x in slot["diags"] if x.get("file") != c]
            slot["files"].pop(c, None)
            slot["creates"].discard(c)
            target = by_persona[owner[c]]
            target["diags"].extend(x for x in moved if x not in target["diags"])


# ------------------------------------------------------------------------------------------------ routing
@dataclass
class Routing:
    error_class: ErrorClass
    persona: Optional[str] = None
    draft_path: Optional[str] = None
    draft_line: Optional[int] = None
    hint: Optional[str] = None
    reason: Optional[str] = None   # FD-55 W5 RT F3: a named stop reason (the stage error message carries it)
    creates: Tuple[str, ...] = ()   # FD55-W5c: more missing files of the same create task (the whole service)


# FD-55 W5 RT F3: a planned Cloud Run service with no code at all (V3c-planned) stops the stage with this named reason
# instead of a generic platform defect. FD55-W5c (register FD55-W5c, owner 10-25): before that stop, the developer is
# asked ONCE to write the whole service (one CREATE round, PLANNED_SERVICE_CREATE_FILES, inside the loop's ordinary
# iteration / token / time limits); the stop applies when the service is still missing after that round, and right
# away in a repair that may only edit given files (QA / deploy repair: `repairable_paths`).
PLANNED_SERVICE_STOP_REASON = "planned service has no code (CONTAINER.ENTRYPOINT_MISSING)"
PLANNED_SERVICE_PERSONA = "developer"


class Router:
    """8B §4.3: per error diagnostic -> class + owner (persona and draft location) + platform hint."""

    def __init__(self, ctx: LoopContext, draft: Mapping[str, str], asm: Assembled):
        self.ctx, self.draft, self.asm = ctx, draft, asm
        tree = asm.tree
        self.vendored = frozenset(asm.platform_files)
        self.authored = frozenset(p for p in ctx.llm_draft_paths if p in tree) | (
            {CUSTOM_TF} if CUSTOM_TF in tree and (CUSTOM_TF in ctx.llm_draft_paths or asm.record.segments) else set())
        self.preexisting = frozenset(ctx.preexisting)
        # TI-3 RT F1: what the platform rendered from the intent THIS assembly is platform-rendered even when the path
        # is pre-existing (a sticky workload's committed render) or was also drafted by the AI (its copy was replaced)
        intent_rendered = frozenset(asm.iac_intent.rendered or ()) if asm.iac_intent is not None else frozenset()
        self.authored = self.authored - intent_rendered
        self.rendered = frozenset(p for p in tree if p not in self.authored and p not in self.vendored
                                  and p not in self.preexisting) | intent_rendered
        draft_keys: Set[str] = set()
        for p, t in draft.items():
            if _is_root_tf(p):
                draft_keys |= file_keys(t) or set()
        prior_keys: Set[str] = set()
        for p, t in (ctx.preexisting_files or {}).items():
            if _is_root_tf(p) and isinstance(t, str):
                prior_keys |= file_keys(t) or set()
        custom_keys = file_keys(tree.get(CUSTOM_TF, "")) or set()
        # blocks the platform synthesized inside custom.tf: neither the LLM's draft nor the repository declares them
        self.platform_addresses = {(CUSTOM_TF, k) for k in custom_keys - draft_keys - prior_keys} | {
            (asm.record.replaced_from.get(k, CUSTOM_TF), k) for k, why in asm.record.replaced_reason.items()
            if why == "PLATFORM_RESYNTHESIZED"}
        self.dropped = self._dropped(draft_keys)

    def _dropped(self, draft_keys: Set[str]) -> Set[str]:
        root = self.asm.assembled_root
        if root is None:
            return set()
        tree_keys: Set[str] = set()
        for p, t in root.items():
            if _is_root_tf(p):
                tree_keys |= file_keys(t) or set()
        return draft_keys - tree_keys - set(self.asm.record.replaced)

    def ownership(self, path: str) -> Optional[Ownership]:
        try:
            return classify_path(path, vendored=self.vendored, rendered=self.rendered, authored=self.authored,
                                 preexisting=self.preexisting, prior_llm=self.ctx.prior_llm or None)
        except (UnattributablePath, ValueError):
            return None

    def unsafe_llm_key(self, key: str) -> bool:
        """A draft key the LLM wrote that is not a safe relative path (its repair is a rename, code RT F12)."""
        if key not in self.draft or key not in self.ctx.llm_draft_paths:
            return False
        try:
            validate_relpath(key, reserved=GIT_RESERVED)
        except UnsafePathError:
            return True
        return False

    def route(self, d: Diagnostic) -> Routing:
        if d.error_class is not ErrorClass.CODE_DEFECT:                     # V2c / VD set it themselves
            return Routing(d.error_class)
        if self.unsafe_llm_key(d.file):
            # every finding on an unsafe LLM key goes to the persona that wrote it: the repair renames the file
            persona = self.ctx.attribution.get(d.file) or "developer"
            hint = UNSAFE_KEY_HINT if d.code in UNSAFE_KEY_CODES else self._hint(d)
            return Routing(ErrorClass.CODE_DEFECT, persona, d.file, d.line, hint)
        if d.code in UNSAFE_KEY_CODES:
            return Routing(ErrorClass.PLATFORM_DEFECT)                       # not a key the LLM wrote
        if d.code in RENAME_ONLY_CODES:   # FD-4AW-a: only a key the LLM wrote this run is renamed by its author
            if d.file in self.draft and d.file in self.ctx.llm_draft_paths:
                persona = self.ctx.attribution.get(d.file) or "developer"
                return Routing(ErrorClass.CODE_DEFECT, persona, d.file, d.line, d.hint)
            return Routing(ErrorClass.PLATFORM_DEFECT)
        if d.code in CREATE_FILE_CODES and d.file not in self.asm.tree:
            if d.code == PLAN_TARGET_MISSING_CODE:   # PLAN-TARGET-FILES
                return self._route_plan_target_create(d)
            return self._route_k8s_create(d) if d.code == K8S_WORKLOAD_MISSING_CODE else self._route_create(d)
        if (self.asm.iac_intent is not None and d.code == IAC_HCL_NOT_ALLOWED_CODE and d.file in self.draft
                and d.file in self.ctx.llm_draft_paths):
            # TI-3: the AI's own Terraform draft (also one at a platform render path, whose tree copy the platform
            # replaced): its author empties it
            persona = self.ctx.attribution.get(d.file) or "developer"
            return Routing(ErrorClass.CODE_DEFECT, persona, d.file, d.line, d.hint)
        if self.asm.iac_intent is not None and d.file == INTENT_RENDER_PATH:
            return self._route_rendered_intent(d)
        own = self.ownership(d.file)
        if own is None or own in PLATFORM_OWNERSHIP:
            return Routing(ErrorClass.PLATFORM_DEFECT)
        if own is Ownership.USER_OWNED:
            return Routing(ErrorClass.BROWNFIELD_CONFLICT)
        if d.block_address and (d.file, d.block_address) in self.platform_addresses:
            return Routing(ErrorClass.PLATFORM_DEFECT)
        # its symbol is a process name / TF key; a PY.SYNTAX symbol is a def/class name (AC-1 Fable RT F5)
        if d.symbol and d.code not in (ENTRYPOINT_CODE, PY_SYNTAX_CODE) and d.symbol in self.dropped:
            return Routing(ErrorClass.PLATFORM_DEFECT)
        draft_path, draft_line = self._draft_location(d)
        if draft_path is None:
            return Routing(ErrorClass.PLATFORM_DEFECT)
        persona = (self.ctx.prior_llm or {}).get(draft_path) or self.ctx.attribution.get(draft_path) or (
            IAC_PERSONA if draft_path == INTENT_PATH else "developer")   # TI-3: a committed intent's author
        return Routing(ErrorClass.CODE_DEFECT, persona, draft_path, draft_line, self._hint(d))

    def _intent_persona(self) -> str:
        return self.ctx.attribution.get(INTENT_PATH) or IAC_PERSONA

    def _route_rendered_intent(self, d: Diagnostic) -> Routing:
        """TI-3 (plan §2.7 V1b): a finding in the platform's render of the intent (custom.tf.json) whose block is an
        entry of the intent (the renderer's provenance map, exact pointer) goes to the intent's author, on the intent
        file; anything else there (no block, a block the intent does not hold) is a renderer defect."""
        if d.error_class is not ErrorClass.CODE_DEFECT or not d.block_address:
            return Routing(ErrorClass.PLATFORM_DEFECT)
        if d.block_address.startswith("module."):
            pointer = "/module/" + d.block_address[len("module."):]
        elif d.block_address.startswith("output."):
            pointer = "/output/" + d.block_address[len("output."):]
        else:
            pointer = "/resource/" + d.block_address.replace(".", "/", 1)
        entry = (self.asm.iac_intent.provenance or {}).get(pointer)
        if entry is None or (INTENT_PATH not in self.draft and INTENT_PATH not in self.preexisting):
            return Routing(ErrorClass.PLATFORM_DEFECT)
        hint = json.dumps({"rendered_from": entry, "action": "OpenTofu rejected the platform's render of this intent "
                           "entry: fix the entry in infra/workload/iac_intent.json (the render is never edited)."})
        return Routing(ErrorClass.CODE_DEFECT, self._intent_persona(), INTENT_PATH, None, hint)

    def _route_create(self, d: Diagnostic) -> Routing:
        """A missing required file `apps/<svc>/<name>`: owned by the persona of the service's first LLM-authored draft
        file (exact path prefix); no LLM file in that service -> the platform created the service -> PLATFORM_DEFECT.
        An unsafe path (`..`, absolute, reserved; code RT F5) is never offered as a create -> PLATFORM_DEFECT."""
        try:
            validate_relpath(d.file, reserved=GIT_RESERVED)
        except UnsafePathError:
            return Routing(ErrorClass.PLATFORM_DEFECT)
        if d.code == INTENT_MISSING_CODE:   # TI-3: the typed IaC intent is the IaC persona's file to write
            if d.file != INTENT_PATH or self.asm.iac_intent is None:
                return Routing(ErrorClass.PLATFORM_DEFECT)
            return Routing(ErrorClass.CODE_DEFECT, self._intent_persona(), d.file, None, d.hint)
        parts = d.file.split("/")
        if len(parts) != 3 or parts[0] != "apps" or not parts[1]:
            return Routing(ErrorClass.PLATFORM_DEFECT)
        prefix = f"apps/{parts[1]}/"
        owned = sorted(p for p in self.draft if p.startswith(prefix) and p in self.authored)
        if not owned:
            if d.code == ENTRYPOINT_CODE and d.detail == PLANNED_SERVICE_DETAIL:   # FD-55 W5 RT F3
                if (prefix not in self.ctx.planned_service_rounds and self.ctx.repairable_paths is None
                        and parts[2] in PLANNED_SERVICE_CREATE_FILES):
                    # FD55-W5c: the one whole-service CREATE round (files the tree does not hold yet, exact paths)
                    extra = tuple(prefix + name for name in PLANNED_SERVICE_CREATE_FILES
                                  if prefix + name != d.file and prefix + name not in self.asm.tree)
                    hint = HINT_PLANNED_CREATE.format(svc=parts[1], files=", ".join(sorted((d.file,) + extra)))
                    facts = planned_service_facts(self.ctx.topology, parts[1], self.asm.tree,
                                                  typed_intent=self.asm.iac_intent is not None)
                    if facts:   # FD55-W5c-PLAN-FACTS: no plan facts (no typed plan): the hint is as before
                        hint += HINT_PLANNED_FACTS.format(facts=json.dumps(facts, sort_keys=True))
                    return Routing(ErrorClass.CODE_DEFECT, PLANNED_SERVICE_PERSONA, d.file, None, hint,
                                   creates=extra)
                return Routing(ErrorClass.PLATFORM_DEFECT, reason=f"{PLANNED_SERVICE_STOP_REASON}: {prefix}")
            return Routing(ErrorClass.PLATFORM_DEFECT)
        persona = (self.ctx.prior_llm or {}).get(owned[0]) or self.ctx.attribution.get(owned[0]) or "developer"
        return Routing(ErrorClass.CODE_DEFECT, persona, d.file, None, d.hint)

    def _route_plan_target_create(self, d: Diagnostic) -> Routing:
        """PLAN-TARGET-FILES: a missing DAG target file goes to the persona that wrote another target of the same DAG
        task (the first one, DAG order, that is an LLM-authored draft file: its prior-run or this run's author), else
        to the author of the first LLM-authored draft file in the same directory (exact dirname), else "developer".
        A path the loop was not given as a required target, or an unsafe one, is never offered -> PLATFORM_DEFECT."""
        try:
            validate_relpath(d.file, reserved=GIT_RESERVED)
        except UnsafePathError:
            return Routing(ErrorClass.PLATFORM_DEFECT)
        if d.file not in self.ctx.plan_targets or d.file in (self.ctx.preexisting_files or {}):
            return Routing(ErrorClass.PLATFORM_DEFECT)   # RT F5: never a "create" of a file the repository holds

        def author(p: str) -> Optional[str]:
            return (self.ctx.prior_llm or {}).get(p) or self.ctx.attribution.get(p)

        same_task = [p for p in self.ctx.plan_targets[d.file] if p in self.draft and p in self.authored]
        folder = posixpath.dirname(d.file)
        same_dir = sorted(p for p in self.draft if p in self.authored and posixpath.dirname(p) == folder)
        persona = next((a for a in (author(p) for p in same_task + same_dir) if a), None) or "developer"
        return Routing(ErrorClass.CODE_DEFECT, persona, d.file, None, d.hint)

    def _route_k8s_create(self, d: Diagnostic) -> Routing:
        """PWB-4: a missing applied manifest `k8s/<svc>.yaml` goes to the persona that writes Kubernetes manifests: the
        author of this run's first LLM-authored draft manifest (a `.yaml`/`.yml` under a `k8s` path segment; the
        applied `k8s/*` ones first), else the author of the service's first LLM-authored draft file under
        `apps/<svc>/` (exact path prefix; MANIFEST-PATH-DEFERS-TO-DAG: for a manifest path the DAG names, the
        service it names it for). Nobody wrote either -> PLATFORM_DEFECT. Any other path shape, or an unsafe
        one, is never offered as a create -> PLATFORM_DEFECT."""
        try:
            validate_relpath(d.file, reserved=GIT_RESERVED)
        except UnsafePathError:
            return Routing(ErrorClass.PLATFORM_DEFECT)
        parts = d.file.split("/")
        stem, ext = posixpath.splitext(parts[-1])
        planned_yml = ext == ".yml" and d.file in self.ctx.manifest_services   # a `.yml` path the DAG names
        if len(parts) != 2 or parts[0] != K8S_APPLY_DIR or (ext != ".yaml" and not planned_yml) or not stem:
            return Routing(ErrorClass.PLATFORM_DEFECT)

        def manifest_rank(p: str) -> Tuple[int, str]:
            segs = p.split("/")
            return (0 if len(segs) == 2 and segs[0] == K8S_APPLY_DIR else 1, p)

        manifests = sorted((p for p in self.draft if p in self.authored and p.endswith((".yaml", ".yml"))
                            and K8S_APPLY_DIR in p.split("/")[:-1]), key=manifest_rank)
        svc = self.ctx.manifest_services.get(d.file, stem)   # MANIFEST-PATH-DEFERS-TO-DAG: the plan's manifest
        owned = manifests or sorted(p for p in self.draft if p.startswith(f"apps/{svc}/") and p in self.authored)
        if not owned:
            return Routing(ErrorClass.PLATFORM_DEFECT)
        persona = (self.ctx.prior_llm or {}).get(owned[0]) or self.ctx.attribution.get(owned[0]) or "developer"
        return Routing(ErrorClass.CODE_DEFECT, persona, d.file, None, d.hint)

    def _draft_location(self, d: Diagnostic) -> Tuple[Optional[str], Optional[int]]:
        if d.file == CUSTOM_TF or any(s.assembled_path == d.file for s in self.asm.record.segments):
            if d.line:
                loc = self.asm.record.draft_location(d.file, d.line)
                if loc:
                    return loc
            if d.file != CUSTOM_TF:
                return d.file, None
            if CUSTOM_TF in self.draft:
                return CUSTOM_TF, None
            return None, None
        if d.file in self.draft:
            return d.file, d.line
        if d.file in (self.ctx.prior_llm or {}):
            return d.file, d.line
        if d.file == INTENT_PATH and self.asm.iac_intent is not None and d.file in self.preexisting:
            return d.file, None   # TI-3: a sticky workload's committed intent (no draft this run) is repaired in place
        return None, None

    def _hint(self, d: Diagnostic) -> Optional[str]:
        if d.code == SENSITIVE_OUTPUT_CODE:   # SAT-02 (FD4BD-Q4): OpenTofu's own finding, by its exact code
            return HINT_SENSITIVE_OUTPUT
        rec = self.asm.record
        if d.symbol and d.code != ENTRYPOINT_CODE and rec.replaced_reason.get(d.symbol) in REPLACED_REASONS_WITH_HINT:
            new = rec.replaced[d.symbol]
            outputs = self._module_outputs(new)
            hint: Dict[str, Any] = {"old": d.symbol, "new": new, "outputs": outputs}
            if d.code == UNDECLARED_REFERENCE_CODE:   # R3c: say what to do, from parsed platform facts only
                old_type = d.symbol.split(".", 1)[0]
                managed = _module_resource_types(self.asm.tree, new)
                keep = (f"Leave the {d.symbol} block itself as it is (the platform replaces it with {new} on every "
                        f"assembly); do not re-declare it under another name.")
                if managed is not None and old_type not in managed:
                    hint["action"] = (f"{new} manages no {old_type}, so nothing equivalent to {d.symbol} exists. "
                                      f"Delete this block (it only serves {d.symbol}: e.g. an IAM member, an output "
                                      f"or a push subscription) unless one of {new}'s outputs {outputs} is exactly "
                                      f"what it needs. " + keep)
                else:
                    hint["action"] = (f"Replace the reference with {new}.<output> using one of {new}'s outputs "
                                      f"{outputs}; if none of them is equivalent, delete this block. " + keep)
            return json.dumps(hint)
        if d.code == UNDECLARED_REFERENCE_CODE and d.symbol and d.symbol.split(".", 1)[0] in PLATFORM_OWNED_TYPES:
            return json.dumps({"reference": d.symbol, "action": PLATFORM_OWNED_REFERENCE_ACTION})
        if d.symbol and d.symbol.startswith("module.") and d.code.startswith("TF."):
            outs = self._module_outputs(d.symbol)
            if outs:
                return json.dumps({"module": d.symbol, "outputs": outs})
        # S2-B B4 (HS-19b): an undeclared address of a type the workload foundation declares (exact type table)
        # -> the module.foundation hint; replaces HC-05's rewrite of such references to "(default)"/module.foundation.
        if (d.code == "TF.REFERENCE_TO_UNDECLARED_RESOURCE" and d.symbol
                and d.symbol.split(".", 1)[0] in FOUNDATION_DECLARED_TYPES):
            return HINT_PLATFORM_OWNED_REFERENCE
        return d.hint

    def _module_outputs(self, module_address: str) -> List[str]:
        """Names declared in the vendored module's outputs.tf (platform fact, read with python-hcl2)."""
        name = module_address.split(".", 1)[1] if "." in module_address else ""
        for path, text in sorted(self.asm.tree.items()):
            if not _is_root_tf(path):
                continue
            for b in index_blocks(text) or []:
                if b.kind == "module" and b.labels and b.labels[0] == name:
                    src = (b.body or {}).get("source")
                    if isinstance(src, str):
                        mod_dir = posixpath.normpath(posixpath.join(WORKLOAD, src))
                        keys = set()
                        for p, t in self.asm.tree.items():
                            if posixpath.dirname(p) == mod_dir and p.endswith(".tf"):
                                keys |= {k[len("output."):] for k in (file_keys(t) or set()) if k.startswith("output.")}
                        return sorted(keys)
        return []


def classify(report: ValidationReport, router: Router) -> Tuple[ValidationReport, Dict[str, Routing]]:
    """Re-class every error diagnostic by routing; the report's error_class is the first of PRECEDENCE present."""
    routes: Dict[str, Routing] = {}
    diags: List[Diagnostic] = []
    for d in report.diagnostics:
        if d.severity != "error":
            diags.append(d)
            continue
        r = router.route(d)
        if r.hint and r.hint != d.hint:
            d = d.model_copy(update={"hint": r.hint})
        if r.error_class is not d.error_class:
            d = d.model_copy(update={"error_class": r.error_class})
        routes[fingerprint(d)] = r
        diags.append(d)
    present = {d.error_class for d in diags if d.severity == "error"}
    error_class = next((c for c in PRECEDENCE if c in present), None)
    out = report.model_copy(update={"diagnostics": diags, "error_class": error_class if report.status == "FAIL"
                                    else report.error_class})
    return out, routes


# ------------------------------------------------------------------------------------------------ the loop
@dataclass
class Attempt:
    """One judged repair candidate (all personas' answers together, or one persona's answer alone)."""

    accepted: bool
    why: Optional[str]
    d2: Optional[Dict[str, str]]
    asm2: Optional[Assembled]
    report2: Optional[ValidationReport]
    routes2: Optional[Dict[str, Routing]]
    removed: Set[str]
    reasons: Dict[str, str]
    feedback: str
    prev: Optional[ValidationReport] = None   # the report this candidate was judged against (removal_followups)
    intent_drops: Tuple[Dict[str, Any], ...] = ()   # TI-3i: entries removed as TYPE_NOT_ALLOWED / MODULE_UNKNOWN


class RepairLoop:
    def __init__(self, ctx: LoopContext):
        self.ctx = ctx
        self.started = ctx.clock()
        self.final_draft: Optional[Dict[str, str]] = None   # set when run() returns a PASS

    # -------------------------------------------------------------------------------------------- ledger
    def _load_ledger(self) -> RepairLedger:
        if self.ctx.ledger_store is None:
            raise StageError(_unavailable("repair_ledger_store"), "repair ledger store not configured")
        try:
            return self.ctx.ledger_store.load(self.ctx.trace_id) or RepairLedger(trace_id=self.ctx.trace_id)
        except StoreUnavailable as e:
            raise StageError(_unavailable("repair_ledger_store"), str(e)) from e

    def _save(self, ledger: RepairLedger) -> None:
        try:
            self.ctx.ledger_store.save(ledger)
        except StoreUnavailable as e:
            raise StageError(_unavailable("repair_ledger_store"), str(e)) from e

    def _budget(self) -> int:
        return effective_repair_token_budget(self.ctx.settings, self.ctx.swarm_envelope)

    def _dispatch_budget(self) -> int:
        return effective_dispatch_token_budget(self.ctx.settings, self.ctx.swarm_envelope)

    # -------------------------------------------------------------------------------------------- validation
    def validate(self, draft: Mapping[str, str], asm: Assembled, iteration: int
                 ) -> Tuple[ValidationReport, Dict[str, Routing]]:
        router = Router(self.ctx, draft, asm)
        vctx = ValidationContext.build(
            asm.tree, ownership=router.ownership, vendored=frozenset(asm.platform_files),
            rendered=router.rendered, draft=dict(draft), assembly=asm.record, iteration=iteration,
            product_id=self.ctx.product_id, trace_id=self.ctx.trace_id,
            extras={"platform_files": asm.platform_files, "vendored_before_restore": asm.vendored_before_restore,
                    "assembled_root": asm.assembled_root, "platform_addresses": router.platform_addresses,
                    "available_providers": self.ctx.available_providers,
                    # AI-TFVARS/TOFU RT F1: the committed repository files (V2n judges only changed / new bytes)
                    "preexisting_files": self.ctx.preexisting_files,
                    "iac_intent": asm.iac_intent})   # TI-3: None on mode "off" (no intent validator registered)
        report = self.ctx.stack.run(vctx)
        if self.ctx.seed_diagnostics and self.ctx.seed_files:   # QA-FEEDBACK: while their file is the tested one
            report = with_seeds(report, qa_repair.live_seeds(self.ctx.seed_diagnostics, self.ctx.seed_files, draft))
        elif self.ctx.seed_diagnostics:   # TI-5-R3: the deploy's findings while their intent entry is unchanged
            report = with_seeds(report, live_seeds(self.ctx.seed_diagnostics, self.ctx.seed_entries,
                                                   asm.tree.get(INTENT_PATH)))
        if self.ctx.seed_check is not None:   # TI-3i-c: the stop's findings while the candidate still has them
            report = with_seeds(report, list(self.ctx.seed_check(asm.tree)))
        if self.ctx.planned_service_rounds and self.ctx.topology is not None:   # FD55-W5c-PLAN-FACTS (narrow scope)
            created = {prefix.split("/")[1] for prefix in self.ctx.planned_service_rounds}
            report = with_seeds(report, planned_push_route_findings(vctx, self.ctx.topology, created))
            unverified = planned_push_route_unverified(vctx, self.ctx.topology, created)
            if unverified:   # measured only: the status and the blocking diagnostics stay as they are
                report = report.model_copy(update={"report_only": list(report.report_only) + unverified})
        if report.status != "FAIL":
            return report, {}
        return classify(report, router)

    # -------------------------------------------------------------------------------------------- run
    def run(self, draft: Dict[str, str]) -> Tuple[Dict[str, str], ValidationReport]:
        ctx, s = self.ctx, self.ctx.settings
        ledger = self._load_ledger()
        ledger.dispatches += 1
        d = dict(draft)
        asm = ctx.assemble(d)
        report, routes = self.validate(d, asm, ledger.iteration)
        dispatch_iterations = 0
        dispatch_wall_ms = 0   # QA-REPAIR-BUDGET: repair_wall_clock_s is per dispatch (the ledger keeps the trace total)
        dispatch_tokens_from = ledger.tokens_spent   # QA-REPAIR-BUDGET: this dispatch's own token budget
        feedback: Dict[str, str] = {}   # persona -> feedback on its own rejected answer
        followups: List[Tuple[Diagnostic, Routing, str]] = []   # references a rejected removal left (fresh 10-14)
        prev_fps: Optional[List[str]] = None
        wall_clock_spent = False   # REPAIR-WALL-CLOCK-ROOM: a walk of this dispatch reported REPAIR_WALL_CLOCK
        while True:
            fps = report.error_fingerprints()
            elapsed_ms = int((ctx.clock() - self.started) * 1000)
            ledger.wall_clock_ms += elapsed_ms
            dispatch_wall_ms += elapsed_ms
            self.started = ctx.clock()
            if report.status == "PASS":
                ledger.last_fingerprints = []
                self._save(ledger)
                self.final_draft = dict(d)   # TI-3i-c: the passing draft (the repair turn starts from it)
                return asm.tree, report
            if report.status == "UNAVAILABLE":
                self._save(ledger)
                raise StageError(report, f"validation unavailable: {report.tools_unavailable}")
            if report.error_class is not ErrorClass.CODE_DEFECT:
                self._save(ledger)
                named = sorted({r.reason for r in routes.values() if r.reason})   # FD-55 W5 RT F3
                raise StageError(report, f"{report.error_class.value}: not repairable by the developer"
                                         + (f" ({'; '.join(named)})" if named else ""))
            unowned = [fp for fp, r in routes.items() if r.error_class is ErrorClass.CODE_DEFECT and (
                not r.persona or (ctx.repairable_paths is not None and r.draft_path not in ctx.repairable_paths))]
            if unowned:
                self._save(ledger)
                raise StageError(report, "CODE_DEFECT diagnostics without a repairable owner")
            reason = None
            if wall_clock_spent:   # REPAIR-WALL-CLOCK-ROOM: a walk of the last dispatch had no room left (the cause)
                reason = "WALL_CLOCK"
            elif prev_fps is not None and fps == prev_fps or (dispatch_iterations == 0 and ledger.last_fingerprints
                                                               and fps == ledger.last_fingerprints):
                reason = "NO_PROGRESS"
            elif dispatch_iterations >= s.repair_max_iterations_precommit or \
                    ledger.iteration >= s.repair_max_iterations_total:
                reason = "ITERATIONS"
            elif dispatch_wall_ms >= s.repair_wall_clock_s * 1000 or (
                    ctx.repair_call_room is not None and not ctx.repair_call_room()):
                # REPAIR-WALL-CLOCK-ROOM (RT F2): the walk would refuse the call (less room than its minimum call
                # plus the answer margin), so no iteration is dispatched to be refused
                reason = "WALL_CLOCK"
            if reason is None and ctx.repair_fn is None:
                reason = "ITERATIONS"
            tasks = [] if reason else self._tasks(d, report, routes, ledger, s, feedback, dispatch_iterations,
                                                  followups)
            if not reason and not tasks:
                self._save(ledger)
                raise StageError(report, "CODE_DEFECT diagnostics without a repairable draft file")
            if not reason:
                reserve = sum(_estimate_tokens(t.prompt()) + t.max_output_tokens for t in tasks)
                if ledger.tokens_spent + reserve > self._budget() or \
                        ledger.tokens_spent - dispatch_tokens_from + reserve > self._dispatch_budget():
                    reason = "TOKENS"
            if reason:
                ledger.exhausted_reason = reason
                ledger.last_fingerprints = fps
                self._save(ledger)
                raise RepairBudgetExhausted(report, reason)
            # STAGE-DEADLINE: no repair iteration starts after the stage deadline; a stop during the dispatch leaves
            # no reservation behind (11-13 ex08: the ledger kept reserved_tokens after the orphaned call)
            stage_deadline.checkpoint("developer.repair_iteration")
            stage_deadline.mark("developer.repair_iteration", iteration=ledger.iteration + 1, tasks=len(tasks))
            ledger.reserved_tokens = reserve
            self._save(ledger)
            try:
                results = self._dispatch(tasks)
            except (*stage_deadline.STOP_ERRORS, LlmStageBudgetExhausted):   # SLOW-CALL-FALLBACK RT F3: a walk
                ledger.reserved_tokens = 0                                     # budget stop releases it too
                self._save(ledger)
                raise
            ledger.reserved_tokens = 0
            planned_now = {posixpath.dirname(x["file"]) + "/" for t in tasks for x in t.diagnostics
                           if x.get("detail") == PLANNED_SERVICE_DETAIL and x.get("code") == ENTRYPOINT_CODE
                           and isinstance(x.get("file"), str)}
            ctx.planned_service_rounds |= planned_now   # FD55-W5c: each planned service gets this one round only
            for res in results:
                ledger.tokens_in += int(res.get("tokens_in") or 0)
                ledger.tokens_out += int(res.get("tokens_out") or 0) + int(res.get("tokens_thoughts") or 0)
                # SLOW-CALL-FALLBACK: a late answer that was not used was still billed
                ledger.tokens_in += int(res.get("tokens_abandoned_in") or 0)
                ledger.tokens_out += int(res.get("tokens_abandoned_out") or 0)
            # REPAIR-WALL-CLOCK-ROOM (ex04-1114, 11-15): the call walk refuses a call with less room than the call
            # minimum plus the answer margin left on the dispatch's repair wall clock (typed error_code
            # REPAIR_WALL_CLOCK). Before, each such dispatch counted as a repair iteration ("ENVELOPE_INVALID",
            # nothing asked) until ITERATIONS stopped the loop. The pre-check above now applies the walk's own room
            # rule; this is the backstop (parallel tasks, a walk that ran out after a fallback). Decided by the typed
            # result fields only: when no walk of this dispatch started a call (`calls_started` 0; an absent count is
            # unknown and the iteration counts), it is not an iteration and the loop stops on WALL_CLOCK now; when
            # some did, the iteration is judged as usual and the next check stops on WALL_CLOCK (unless the answers
            # made the tree pass).
            if any(res.get("error_code") == REPAIR_WALL_CLOCK for res in results):
                wall_clock_spent = True
                if all(res.get("error_code") == REPAIR_WALL_CLOCK and res.get("calls_started") == 0
                       for res in results):
                    ledger.wall_clock_ms += int((ctx.clock() - self.started) * 1000)
                    self.started = ctx.clock()
                    ledger.exhausted_reason = "WALL_CLOCK"
                    ledger.last_fingerprints = fps
                    self._save(ledger)
                    raise RepairBudgetExhausted(report, "WALL_CLOCK")
            iteration = ledger.iteration + 1
            ledger.iteration = iteration
            dispatch_iterations += 1
            joint = self._attempt(d, asm, report, tasks, results, iteration)
            outcomes = [(task, res, joint) for task, res in zip(tasks, results)]
            final = joint if joint.accepted else None
            if not joint.accepted and len(tasks) > 1:
                # entrypoint-repair-hint (10-14): one persona's regression no longer discards the other personas'
                # fixes. Each persona's answer is applied alone, in task order, on top of the answers accepted
                # before it; each step must pass the same accept() rule against the state it starts from.
                outcomes, final = [], None
                base_d, base_asm, base_report = d, asm, report
                for task, res in zip(tasks, results):
                    one = self._attempt(base_d, base_asm, base_report, [task], [res], iteration)
                    outcomes.append((task, res, one))
                    if one.accepted:
                        final = one
                        base_d, base_asm, base_report = one.d2, one.asm2, one.report2
            for task, res, a in outcomes:
                ctx.events.append(RepairEvent(
                    trace_id=ctx.trace_id, product_id=ctx.product_id, iteration=iteration, source="precommit",
                    persona=task.persona, files=sorted(task.files_to_fix), codes=sorted({x["code"] for x in task.diagnostics}),
                    fingerprints_before=fps, fingerprints_after=a.report2.error_fingerprints() if a.report2 else [],
                    accepted=a.accepted, reject_reason=None if a.accepted else a.why,
                    removed_addresses=sorted(a.removed), removal_reasons=a.reasons,
                    model=res.get("model") or ctx.model, model_fallback=res.get("model_fallback_reason"),
                    # REPAIR-WALL-CLOCK-ROOM: the call's typed error code (e.g. REPAIR_WALL_CLOCK,
                    # LLM_FALLBACK_EXHAUSTED) on the run record; None when the result has none (unchanged)
                    detail=res.get("error_code") if isinstance(res.get("error_code"), str) else None,
                    tokens_in=int(res.get("tokens_in") or 0),
                    tokens_out=int(res.get("tokens_out") or 0), tokens_thoughts=int(res.get("tokens_thoughts") or 0)))
            self._save(ledger)
            for a in {id(a): a for _t, _r, a in outcomes}.values():   # TI-3i: once per accepted candidate
                if a.accepted and a.intent_drops:
                    ctx.intent_drops.extend(dict(x) for x in a.intent_drops)
            for task, res, a in outcomes:   # a renamed file stays the persona's own file (code RT F12)
                if a.accepted and task.renames:
                    for k in set(res.get("files") or {}) - set(task.files_to_fix):
                        ctx.llm_draft_paths.add(k)
                        ctx.attribution[k] = task.persona
            # feedback goes to the persona whose own answer was rejected, about that answer only
            feedback = {task.persona: a.feedback for task, res, a in outcomes if not a.accepted and a.feedback}
            # fresh 10-14: a removal the diagnostics require, rejected only because references to the removed block
            # remain in files that task was not given -> the next task also offers those files (exact tofu findings)
            followups = [f for task, res, a in outcomes if not a.accepted for f in removal_followups(a)
                         if ctx.repairable_paths is None or f[1].draft_path in ctx.repairable_paths]   # TI-5-R3
            if final is not None:
                d, asm, report, routes = final.d2, final.asm2, final.report2, final.routes2
                prev_fps = fps
            else:
                prev_fps = None
                if planned_now:
                    # FD55-W5c: the round was rejected, so the service is still missing: re-route the same findings
                    # (no validator run) so the next check stops with the named reason instead of asking again
                    report, routes = classify(report, Router(ctx, d, asm))

    # -------------------------------------------------------------------------------------------- one candidate
    def _attempt(self, d: Dict[str, str], asm: Assembled, report: ValidationReport, tasks: List["RepairTask"],
                 results: List[Dict[str, Any]], iteration: int) -> "Attempt":
        """Merge `results` of `tasks` into draft `d`, re-assemble, re-validate and judge with accept() against
        (d, asm, report). Never mutates `d`."""
        ctx = self.ctx
        d2, merge_why, removed = self._merge(d, tasks, results, report)
        if d2 is None:   # envelope / scope failure: nothing to assemble, the attempt counts
            fb = _rejection_feedback(merge_why, d, None, asm, None, report, None, removed, results)
            return Attempt(False, merge_why, None, None, None, None, removed, {}, fb, report)
        refusals = (qa_requirements_guard.refusals_of(ctx.requirements_guard, ctx.seed_files, d2)
                    + qa_requirements_guard.refusals_of(ctx.requirements_crash_guard, ctx.seed_files, d2, add_only=False))
        if refusals:   # QA-REPAIR-ON-IMPORT-FAILURE: the whole candidate is rejected (typed), never partly applied
            logger.warning(f"QA repair candidate refused ({qa_requirements_guard.REQUIREMENTS_REFUSED}) for "
                           f"{ctx.trace_id}: {[(r.path, r.line, r.reason) for r in refusals[:20]]}")
            return Attempt(False, qa_requirements_guard.REQUIREMENTS_REFUSED, None, None, None, None, removed, {},
                           qa_requirements_guard.render_refusals(refusals), report)
        if asm.iac_intent is not None:   # TI-3: the intent's entries are preserved like root-module blocks (rule 5)
            # RT F5: on a sticky run the draft holds no intent; the assembled tree always holds the one checked
            before = d if INTENT_PATH in d else {INTENT_PATH: asm.tree.get(INTENT_PATH)}
            removed = removed | (_intent_addresses(before) - _intent_addresses(d2))
        for task in tasks:   # a required file the persona just wrote is its own file from now on (S2-A)
            for k in task.creates:
                if k in d2:
                    ctx.llm_draft_paths.add(k)
                    ctx.attribution[k] = task.persona
        asm2 = ctx.assemble(d2)
        report2, routes2 = self.validate(d2, asm2, iteration)
        renamed = ({k for t in tasks for k in t.renames}, set(d2) - set(d))
        ok, why = accept(d, d2, asm, asm2, report, report2, removed, ctx.engine_label, renamed)
        reasons = removal_justifications(d, d2, asm, asm2, report, removed) if removed else {}
        fb = "" if ok else _rejection_feedback(why, d, d2, asm, asm2, report, report2, removed, results)
        drops = (dropped_intent_entries((d if INTENT_PATH in d else asm.tree).get(INTENT_PATH), reasons)
                 if asm.iac_intent is not None and reasons else ())   # TI-3i: what this candidate dropped
        return Attempt(ok, why, d2, asm2, report2, routes2, removed, reasons, fb, report, drops)

    # -------------------------------------------------------------------------------------------- tasks
    def _tasks(self, d: Mapping[str, str], report: ValidationReport, routes: Dict[str, Routing],
               ledger: RepairLedger, s: HallucinationStackSettings, feedback: Mapping[str, str],
               dispatch_iterations: int = 0,
               followups: Optional[List[Tuple[Diagnostic, Routing, str]]] = None) -> List[RepairTask]:
        by_persona: Dict[str, Dict[str, Any]] = {}
        for diag in report.diagnostics:
            if diag.severity != "error":
                continue
            r = routes.get(fingerprint(diag))
            if r is None or r.error_class is not ErrorClass.CODE_DEFECT:
                continue
            slot = by_persona.setdefault(r.persona, {"files": {}, "diags": [], "renames": set(), "creates": set(),
                                                     "seen": set()})
            slot["seen"].add((diag.code, r.draft_path, diag.block_address, diag.symbol))
            if diag.code == ENTRYPOINT_CODE and diag.detail == PLANNED_SERVICE_DETAIL:   # FD55-W5c-PLAN-FACTS (F2)
                slot["whole_service"] = True
            if diag.source == qa_repair.SEED_SOURCE and self.ctx.untrusted_output:   # QA-FEEDBACK: a QA finding
                slot["qa"] = True
            content = d.get(r.draft_path)
            if content is None:   # a prior-run LLM file (prior custom.tf head, prior_llm aux file): repairable too
                content = (self.ctx.preexisting_files or {}).get(r.draft_path)
            if content is None and diag.code in CREATE_FILE_CODES and r.draft_path:
                content = ""      # a required file to write (S2-A): offered empty, returned under exactly this key
                slot["creates"].add(r.draft_path)
            if isinstance(content, str):
                slot["files"][r.draft_path] = content
                if r.draft_path in d and diag.code in RENAME_CODES:
                    slot["renames"].add(r.draft_path)
            for extra in r.creates:   # FD55-W5c: the rest of the whole service, offered empty like the finding's file
                if extra not in d:
                    slot["files"][extra] = ""
                    slot["creates"].add(extra)
            slot["diags"].append({"code": diag.code, "file": r.draft_path, "line": r.draft_line,
                                  "block": diag.block_address, "message": diag.message, "detail": diag.detail,
                                  "snippet": diag.snippet, "hint": r.hint})
        # fresh 10-14: the references a rejected, justified removal left behind (removal_followups), offered to the
        # persona that owns each referencing draft file; only files the current draft has (never a new key). Added
        # only when present, so every other repair prompt (and its cassette key) is unchanged.
        def deleter_personas(addr: str) -> Set[str]:
            # PO-1b (Fable RT F1): who deleted `addr` = the persona the Router gives each root .tf draft file that
            # declares it (python-hcl2 index). A task is offered only files routed to its persona and _merge rejects
            # any other write, so the rejected removal came from exactly these personas' task(s).
            out: Set[str] = set()
            for p, t in d.items():
                if _is_root_tf(p) and isinstance(t, str) and addr in (file_keys(t) or set()):
                    out.add((self.ctx.prior_llm or {}).get(p) or self.ctx.attribution.get(p) or "developer")
            return out

        for diag, r, removed_addr in followups or []:
            content = d.get(r.draft_path)
            if not isinstance(content, str):
                continue
            slot = by_persona.setdefault(r.persona, {"files": {}, "diags": [], "renames": set(), "creates": set(),
                                                     "seen": set()})
            # PO-1b (Fable RT F2): a finding's identity includes its symbol, so a block that references two removed
            # addresses (or two references outside any block, block None) keeps one entry per removed address
            key = (diag.code, r.draft_path, diag.block_address, diag.symbol)
            if key in slot["seen"]:
                continue
            slot["seen"].add(key)
            slot["files"][r.draft_path] = content
            slot["diags"].append({"code": diag.code, "file": r.draft_path, "line": None, "block": diag.block_address,
                                  "message": diag.message, "detail": diag.detail, "snippet": diag.snippet,
                                  "hint": followup_hint(diag, removed_addr,
                                                        own=deleter_personas(removed_addr) == {r.persona})})
        _one_creator_per_file(by_persona)   # PLAN-TARGET-FILES: two routes never both create one path
        # iterations left after this one (the prompt said "2 remaining" on every iteration before 10-14)
        remaining = min(s.repair_max_iterations_precommit - dispatch_iterations,
                        s.repair_max_iterations_total - ledger.iteration)
        tasks = []
        for persona, slot in sorted(by_persona.items()):
            if not slot["files"]:
                continue
            size = sum(_estimate_tokens(t) for t in slot["files"].values())
            if slot.get("whole_service"):   # FD55-W5c-PLAN-FACTS (F2): its files are empty, so their size says nothing
                size = max(size, s.repair_max_output_tokens)   # so the cap binds: the settings' per-call maximum
            qa = bool(slot.get("qa"))   # QA-FEEDBACK: the untrusted QA block and read-only context, QA tasks only
            # PLAN-TARGET-FILES: a task that creates a DAG target file sees the draft's other files (the same
            # selection as a QA repair), so the new module fits the code that is already there; every other task: {}
            plan_create = any(c in self.ctx.plan_targets for c in slot["creates"])
            tasks.append(RepairTask(persona=persona, files_to_fix=dict(sorted(slot["files"].items())),
                                    diagnostics=slot["diags"],
                                    read_only_context=(qa_repair.context_files(d, slot["files"])
                                                       if qa or plan_create else {}),
                                    untrusted_output=self.ctx.untrusted_output if qa else "",
                                    iteration=ledger.iteration + 1, remaining_iterations=max(0, remaining - 1),
                                    feedback=feedback.get(persona, ""),
                                    max_output_tokens=repair_call_max_output_tokens(s, size,
                                                                                    model=self.ctx.model or None),
                                    renames=sorted(slot["renames"]),
                                    thinking_budget=repair_call_thinking_budget(s, model=self.ctx.model or None),
                                    creates=sorted(slot["creates"]), files_to_fix_tokens=int(size)))
        return tasks

    def _dispatch(self, tasks: List[RepairTask]) -> List[Dict[str, Any]]:
        if len(tasks) == 1:
            return [self.ctx.repair_fn(tasks[0])]
        with ThreadPoolExecutor(max_workers=max(1, len(tasks))) as pool:
            # STAGE-DEADLINE: each pool thread runs in the caller's context (the stage deadline)
            return list(pool.map(stage_deadline.bind_context(self.ctx.repair_fn), tasks))

    @staticmethod
    def _merge(d: Dict[str, str], tasks: List[RepairTask], results: List[Dict[str, Any]],
               report: ValidationReport) -> Tuple[Optional[Dict[str, str]], Optional[str], Set[str]]:
        d2 = dict(d)
        claimed: Set[str] = set()
        for task, res in zip(tasks, results):
            # a response the model did not finish (MAX_TOKENS, MALFORMED_FUNCTION_CALL, SAFETY, ...) is never merged,
            # even if its text happens to parse: the attempt fails as a truncated envelope (8B §7) and still counts
            if not res.get("envelope_ok") or res.get("finish_reason") not in (None, "STOP"):
                return None, "ENVELOPE_INVALID", set()
            files = res.get("files") or {}
            renames = set(getattr(task, "renames", ()) or ())
            new_keys = set(files) - set(task.files_to_fix)
            # a rename task (code RT F12) returns each unsafe key under exactly one new, safe key that no other file
            # uses; anything else outside files_to_fix is an out-of-scope write, as before
            if set(files) & renames or len(new_keys) != len(renames) or new_keys & (set(d) | claimed):
                return None, "OUT_OF_SCOPE_WRITE", set()
            for k in new_keys:
                try:
                    validate_relpath(k, reserved=GIT_RESERVED)
                except UnsafePathError:
                    return None, "OUT_OF_SCOPE_WRITE", set()
            claimed |= new_keys
            for old in renames:
                d2.pop(old, None)
            d2.update(files)
        return d2, None, _preserved_addresses(d) - _preserved_addresses(d2)


FEEDBACK_MAX_ITEMS = 8


def _rejection_feedback(why: Optional[str], d: Mapping[str, str], d2: Optional[Mapping[str, str]],
                        asm: Assembled, asm2: Optional[Assembled], prev: ValidationReport,
                        new: Optional[ValidationReport], removed: Set[str], results: List[Dict[str, Any]]) -> str:
    """R3c: the feedback names what the rejected attempt did wrong (platform facts only), not a generic sentence."""
    if why == "ENVELOPE_INVALID" and all(r.get("error") and r.get("finish_reason") is None and
                                         not r.get("tokens_out") for r in results if not r.get("envelope_ok")):
        return ""   # transport failure: the model produced nothing, there is nothing to correct
    head = f"Your previous attempt was rejected ({why})."
    if why == "PRESERVATION_VIOLATION" and asm2 is not None and d2 is not None:
        lost = sorted(removed - set(removal_justifications(d, d2, asm, asm2, prev, removed)))[:FEEDBACK_MAX_ITEMS]
        return (f"{head} It deleted declarations that no diagnostic allows deleting: {json.dumps(lost)}. Keep them; "
                "fix only the listed diagnostics.")
    if why == "NEW_FINGERPRINT" and new is not None:
        P = {fingerprint(x) for x in prev.diagnostics if x.severity == "error"}
        added = [x for x in new.diagnostics if x.severity == "error" and fingerprint(x) not in P]
        items = [f"{x.code} in {x.file}" + (f" at {x.block_address}" if x.block_address else "") + f": {x.message}"
                 for x in sorted(added, key=lambda x: (x.file, x.line or 0, x.code))[:FEEDBACK_MAX_ITEMS]]
        return (f"{head} It introduced new errors: {json.dumps(items)}. Fix the listed diagnostics without "
                "introducing these.")
    if why == "ENVELOPE_INVALID":
        return (f"{head} The answer was not one complete JSON object {{\"files\": {{\"<path>\": \"<content>\"}}}}; "
                "return exactly that, with every listed file complete.")
    return (f"{head} Keep every declaration, fix the listed diagnostics, do not introduce new errors in other files.")


# ------------------------------------------------------------------------------------------------ acceptance (F4)
PRESERVED_KINDS = frozenset({"resource", "data", "module"})


def _preserved_addresses(files: Mapping[str, str]) -> Set[str]:
    """Lane 8B §6.2 rule 5: the draft's declared resource/data/module addresses (root-module files). Outputs,
    variables, locals, providers and terraform blocks are not preserved by acceptance (Step 1 code RT F5): a repair
    may delete e.g. a dangling output; a reference it breaks shows up as a new fingerprint (rule 4)."""
    out: Set[str] = set()
    for p, t in files.items():
        if _is_root_tf(p):
            out |= {k for b in (index_blocks(t) or []) if b.kind in PRESERVED_KINDS for k in b.keys}
    return out


def _intent_addresses(files: Mapping[str, str]) -> Set[str]:
    """TI-3: the module / resource addresses of the draft's typed IaC intent (an unparseable or invalid document has
    none; its finding is JSON.OUTPUT_INVALID). Outputs are not preserved, as in `_preserved_addresses`. TI-3j: api_only
    entries too (dropped only when justified). JUDGE-NAMED-INTENT-REMOVAL: the one parse lives in iac_intent_contract."""
    return intent_document_addresses(files.get(INTENT_PATH))


# R3c (10-13): explicit, diagnosed removals beyond the 8B §6.2 rule-5 codes. Each removed address must carry exactly one
# of these justifications (recorded in RepairEvent.removal_reasons); an address without one is still a violation.
UNDECLARED_REFERENCE_CODE = "TF.REFERENCE_TO_UNDECLARED_RESOURCE"
PRIVILEGED_ROLE_CODE = "POLICY.PRIVILEGED_ROLE"


def _root_keys(tree: Mapping[str, str]) -> Set[str]:
    out: Set[str] = set()
    for p, t in tree.items():
        if _is_root_tf(p):
            out |= file_keys(t) or set()
    return out


def _module_resource_types(tree: Mapping[str, str], module_address: str) -> Optional[Set[str]]:
    """Resource types declared inside the module a root `module.<name>` block calls (its directory and the local
    sub-modules it calls, parsed with python-hcl2). None ("unknown") when the module block or its local source is not
    found, or when python-hcl2 cannot parse one of its .tf files: an unknown module never justifies a removal."""
    name = module_address.split(".", 1)[1] if module_address.startswith("module.") else ""
    if not name:
        return None
    start: Optional[str] = None
    for path, text in sorted(tree.items()):
        if not _is_root_tf(path):
            continue
        for b in index_blocks(text) or []:
            if b.kind == "module" and b.labels and b.labels[0] == name:
                src = (b.body or {}).get("source")
                if isinstance(src, str) and src.startswith(("./", "../")):
                    start = posixpath.normpath(posixpath.join(WORKLOAD, src))
    if start is None:
        return None
    types_: Set[str] = set()
    seen: Set[str] = set()
    todo = [start]
    found = False
    while todo:
        mod_dir = todo.pop()
        if mod_dir in seen:
            continue
        seen.add(mod_dir)
        for p, t in sorted(tree.items()):
            if posixpath.dirname(p) != mod_dir or not p.endswith(".tf"):
                continue
            blocks = index_blocks(t)
            if blocks is None:   # python-hcl2 rejects the file: the module's contents are unknown (RT fix 1)
                return None
            found = True
            for b in blocks:
                if b.kind == "resource" and b.labels:
                    types_.add(b.labels[0])
                elif b.kind == "module":
                    src = (b.body or {}).get("source")
                    if isinstance(src, str) and src.startswith(("./", "../")):
                        todo.append(posixpath.normpath(posixpath.join(mod_dir, src)))
    return types_ if found else None


def removal_justifications(d: Mapping[str, str], d2: Mapping[str, str], asm: Assembled, asm2: Assembled,
                           prev: ValidationReport, removed: Set[str]) -> Dict[str, str]:
    """{removed address: why the removal is allowed} for the addresses a candidate may remove (lane 8B §6.2 rule 5 as
    amended after R3c). Exact signals only (AssemblyRecord, diagnostic code/block/symbol, parsed module contents):
      - REMOVAL_CODE:<code>   the previous report names the block with a blocking rule-5 code (forbidden, platform-owned,
                              public, duplicate) or, R3c, with a blocking POLICY.PRIVILEGED_ROLE (dropping a privileged
                              grant can only narrow access); a warning (report-only) finding never justifies a removal;
      - REPLACED:<target>     the draft block was already REPLACED by the platform in the previous assembly
                              (AssemblyRecord.replaced) and the replacement is still in the new assembled root: removing
                              the draft copy does not change what is deployed;
      - DEAD_REFERENCE:<old>  every blocking diagnostic on the block is an undeclared reference to a REPLACED address
                              whose replacing module manages no resource of the replaced type (no equivalent exists:
                              e.g. an IAM member on a Cloud Run service replaced by an event-worker job module);
      - QA_JUDGE_REMOVAL:<code> JUDGE-NAMED-INTENT-REMOVAL: an entry removed from the intent that a live QA seed of a
                              judge finding names exactly for deletion (qa_repair.JUDGE_REMOVAL_CODES, block_address =
                              the address; only plan_qa_repair writes it, from the gateway-stamped finding's typed
                              field checked against the tested intent). The judge's next round re-reviews the result.
    An address with no blocking diagnostic and no replacement record gets no justification (still a violation)."""
    rec = asm.record
    errors = [x for x in prev.diagnostics if x.severity == "error"]
    by_block: Dict[str, List[Diagnostic]] = {}
    for x in errors:
        if x.block_address:
            by_block.setdefault(x.block_address, []).append(x)
    legacy = {x.block_address for x in errors if x.code in REMOVAL_CODES and x.block_address}   # blocking only
    new_root = _root_keys(asm2.assembled_root if asm2.assembled_root is not None else asm2.tree)
    types_cache: Dict[str, Optional[Set[str]]] = {}
    # JUDGE-NAMED-INTENT-REMOVAL: a live QA seed of a judge finding that names exactly that entry for deletion
    def judge_named(x: Diagnostic) -> bool:
        return (x.source == qa_repair.SEED_SOURCE and x.code in qa_repair.JUDGE_REMOVAL_CODES and x.file == INTENT_PATH
                and bool(x.block_address))

    intent_removed: Set[str] = set()
    if any(judge_named(x) for x in errors):   # RT F3: parsed only when such a seed exists (else exactly as before)
        # RT F4: the entries the candidate removed from the INTENT (not a root .tf block of the same address)
        intent_removed = (_intent_addresses(d if INTENT_PATH in d else asm.tree)
                          - _intent_addresses(d2 if INTENT_PATH in d2 else asm2.tree))

    def no_equivalent(old: str) -> bool:
        if rec.replaced_reason.get(old) not in REPLACED_REASONS_WITH_HINT or "." not in old or old.startswith(
                ("data.", "module.")):
            return False
        target = rec.replaced[old]
        if target not in types_cache:
            types_cache[target] = _module_resource_types(asm.tree, target)
        managed = types_cache[target]
        return managed is not None and old.split(".", 1)[0] not in managed

    out: Dict[str, str] = {}
    for addr in sorted(removed):
        diags = by_block.get(addr, [])
        if addr in legacy:
            out[addr] = "REMOVAL_CODE:" + sorted({x.code for x in errors
                                                  if x.block_address == addr and x.code in REMOVAL_CODES})[0]
        elif any(x.code == PRIVILEGED_ROLE_CODE for x in diags):
            out[addr] = "REMOVAL_CODE:" + PRIVILEGED_ROLE_CODE
        elif addr in rec.replaced and rec.replaced[addr] in new_root:
            out[addr] = "REPLACED:" + rec.replaced[addr]
        elif diags and all(x.code == UNDECLARED_REFERENCE_CODE and x.symbol and x.symbol in rec.replaced
                           and no_equivalent(x.symbol) for x in diags):
            out[addr] = "DEAD_REFERENCE:" + sorted({x.symbol for x in diags})[0]
        elif addr in intent_removed and any(judge_named(x) for x in diags):
            out[addr] = JUDGE_REMOVAL_REASON_PREFIX + sorted({x.code for x in diags if judge_named(x)})[0]
    return out


# JUDGE-NAMED-INTENT-REMOVAL (ex02-1115): the justification of deleting an intent entry the QA judge named
JUDGE_REMOVAL_REASON_PREFIX = "QA_JUDGE_REMOVAL:"


def removal_followups(a: "Attempt") -> List[Tuple[Diagnostic, Routing, str]]:
    """fresh 10-14 regression: a candidate that deleted blocks the diagnostics require deleting (removal_justifications)
    is rejected as NEW_FINGERPRINT when the references to them sit in other draft files the task was not given (e.g.
    outputs.tf): the count rose, and the next identical prompt got the identical answer. When EVERY new blocking finding
    of the rejected candidate is OpenTofu's undeclared-reference error naming exactly an address it removed with a
    justification, return those findings with their routes (computed on the candidate) and the removed address, so the
    next task offers the referencing files. Exact signals only (OpenTofu's finding, its symbol, the removal record); a
    finding routed to no repairable draft file (platform-rendered, user-owned) is not offered. Anything else (a real
    regression, no removal) -> []."""
    if (a.accepted or a.why != "NEW_FINGERPRINT" or a.report2 is None or not a.reasons or a.routes2 is None
            or a.prev is None):
        return []
    P = {fingerprint(x) for x in a.prev.diagnostics if x.severity == "error"}
    added = [x for x in a.report2.diagnostics if x.severity == "error" and fingerprint(x) not in P]
    if not added or not all(x.code == UNDECLARED_REFERENCE_CODE and x.symbol in a.reasons for x in added):
        return []
    out: List[Tuple[Diagnostic, Routing, str]] = []
    for x in sorted(added, key=lambda x: (x.file, x.line or 0, x.block_address or "", x.symbol or "")):
        r = a.routes2.get(fingerprint(x))
        if r is not None and r.error_class is ErrorClass.CODE_DEFECT and r.persona and r.draft_path:
            out.append((x, r, str(x.symbol)))
    return out


def followup_hint(x: Diagnostic, removed_addr: str, own: bool = True) -> str:
    """The hint on a removal follow-up (removal_followups): which deleted block this reference names and what to do
    with it, from exact facts (the removed address, the referencing block, the foundation type table).
    PO-1b (Fable RT F1/F2): `own` = the persona receiving the hint is exactly the one whose answer deleted the block
    (otherwise, another persona or not provable, a neutral sentence that is true either way); a reference outside any
    block (block_address None) is "this file", never "None".
    The own-persona, in-block text is unchanged (recorded prompts keep their cassette keys)."""
    where = x.block_address or "this file"
    if own:
        action = (f"Your previous answer deleted {removed_addr}, as its diagnostic requires, but {where} "
                  f"still references it. Keep {removed_addr} deleted and, in the same answer, delete this reference "
                  "(a depends_on entry, or an output that only re-exports it) or point it at an address that exists.")
    else:
        action = (f"A previous repair answer deleted {removed_addr}, as its diagnostic requires, but {where} still "
                  f"references it. {removed_addr} stays deleted: delete this reference (a depends_on entry, or an "
                  "output that only re-exports it) or point it at an address that exists.")
    hint: Dict[str, Any] = {"removed": removed_addr, "reference": x.block_address, "action": action}
    if removed_addr.split(".", 1)[0] in FOUNDATION_DECLARED_TYPES:
        hint["platform"] = PLATFORM_OWNED_REFERENCE_ACTION
    return json.dumps(hint, sort_keys=True)


def _parses(text: Optional[str], path: str) -> Optional[bool]:
    if text is None:
        return None
    if path.endswith(".py"):
        try:
            compile(text, path, "exec", dont_inherit=True)
            return True
        except (SyntaxError, ValueError):
            return False
    if path.endswith(".tf"):
        return file_keys(text) is not None
    return None


def _top_level_symbols(text: str) -> Set[str]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return set()
    return {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}


def accept(d: Mapping[str, str], d2: Mapping[str, str], asm: Assembled, asm2: Assembled, prev: ValidationReport,
           new: ValidationReport, removed: Set[str], engine_label: str,
           renamed: Optional[Tuple[Set[str], Set[str]]] = None) -> Tuple[bool, Optional[str]]:
    """Set-based, visibility-aware, preserving acceptance (lane 8B §6.2, Step 1 RT F4; R3c amendments: removals need a
    removal_justifications() entry, and a new finding is also allowed when it is an undeclared reference to an address
    this candidate removed with a justification while the blocking count drops). `renamed` = (unsafe keys a
    rename task dropped, the new keys it returned) (code RT F12): a renamed `.py` file is preserved when the new keys
    carry at least as many `.py` files and every top-level symbol of the old files."""
    P = {fingerprint(x): x for x in prev.diagnostics if x.severity == "error"}
    N = {fingerprint(x): x for x in new.diagnostics if x.severity == "error"} if new.status == "FAIL" else {}
    if new.status == "UNAVAILABLE":
        return False, "NO_IMPROVEMENT"
    if not (set(P) - set(N)):
        return False, "NO_IMPROVEMENT"
    syntax_codes = SYNTAX_CODES.get(engine_label, set())

    def visibility_improved(path: str) -> bool:
        before, after = _parses(asm.tree.get(path), path), _parses(asm2.tree.get(path), path)
        if before is False and after is True:
            return True
        had = any(x.file == path and x.code in syntax_codes for x in P.values())
        has = any(x.file == path and x.code in syntax_codes for x in N.values())
        return had and not has

    justified = removal_justifications(d, d2, asm, asm2, prev, removed) if removed else {}

    def consequential(x: Diagnostic) -> bool:
        # R3c: deleting a justified block (platform-owned, forbidden, public, ...) leaves the references to it
        # dangling (depends_on, outputs). Such a finding names exactly an address this candidate removed with a
        # justification; it is accepted only while the candidate makes net progress (fewer blocking findings).
        return x.code == UNDECLARED_REFERENCE_CODE and bool(x.symbol) and x.symbol in justified and len(N) < len(P)

    def unmasked_by_entrypoint(x: Diagnostic) -> bool:
        # entrypoint-repair-hint (10-14): V3c checks a service's PORT binding and health route only once its Procfile
        # entrypoint resolves (validators/container.py ENTRYPOINT_MASKED_CODES). A finding of those codes in
        # apps/<svc>/ is revealed, not caused, when apps/<svc>/Procfile had a blocking ENTRYPOINT_MISSING before and
        # has none now (R3 fresh 10-13: 03/06/09 rejected the correct Procfile fix because main.py lacked /health).
        parts = (x.file or "").split("/")
        if x.code not in ENTRYPOINT_MASKED_CODES or len(parts) < 3 or parts[0] != "apps" or not parts[1]:
            return False
        procfile = f"apps/{parts[1]}/Procfile"

        def masks_web(y: Diagnostic) -> bool:   # Fable RT F1: masking is per process; only `web` is checked
            return y.code == ENTRYPOINT_CODE and y.file == procfile and y.symbol in (None, WEB_PROCESS)
        return any(masks_web(p) for p in P.values()) and not any(masks_web(n) for n in N.values())

    unjudged_before: List[Set[Tuple[str, Optional[int]]]] = []

    def unmasked_local_import(x: Diagnostic) -> bool:
        # IMPORT-RESOLVE-GATE: V3e-local-imports does not judge an import whose target it cannot read (e.g. a target
        # with a syntax error). A finding on such an import is revealed, not caused, when the repair fixed the target
        # and left the importing file byte-unchanged: the import was not judgeable on the previous tree.
        if x.code != LOCAL_IMPORT_CODE or not x.file:
            return False
        before, after = asm.tree.get(x.file), asm2.tree.get(x.file)
        if not isinstance(before, str) or before != after:
            return False
        if not unjudged_before:   # computed once, only when such a fingerprint appears
            unjudged_before.append(unjudged_imports(asm.tree))
        return (x.file, x.line) in unjudged_before[0]

    def unmasked_push_plan(x: Diagnostic) -> bool:
        # PUSH-PLAN-CHECK: V-IAC-PUSH does not judge a tree whose intent is absent or does not parse (V-IAC reports
        # that). A missing-push finding is revealed, not caused, when the previous tree was not judged: the repair
        # made the intent parse. When the previous intent parsed, it was judged, and a new finding there is caused.
        return x.code == PUSH_PLAN_CODE and not push_plan_judged(asm.tree)

    def split_by_unit(x: Diagnostic) -> bool:
        # AC-1: a per-unit PY.SYNTAX finding (symbol set) is revealed, not caused, when its file's previous syntax
        # finding was the whole-file one (symbol None: the token stream could not be split, or the first error
        # spanned units) and that whole-file finding is gone, i.e. the fix made the file splittable, AND the broken
        # unit's source existed verbatim in the previous version of the file (Fable RT F1: a unit the repair
        # rewrote, or a stub it replaced the file with, was not revealed). Exact containment, no pattern.
        def whole_file(y: Diagnostic) -> bool:
            return y.code == PY_SYNTAX_CODE and y.file == x.file and y.symbol is None
        if not (x.code == PY_SYNTAX_CODE and x.symbol is not None and any(whole_file(p) for p in P.values())
                and not any(whole_file(n) for n in N.values())):
            return False
        before, after = asm.tree.get(x.file), asm2.tree.get(x.file)
        if not isinstance(before, str) or not isinstance(after, str):
            return False
        u = unit_at(top_level_units(after) or [], x.line)
        if u is None:
            return False
        text = "".join(io.StringIO(after, newline=None).readlines()[u.start - 1:u.end]).strip()
        return bool(text) and text in io.StringIO(before, newline=None).read()

    for fp in set(N) - set(P):
        if (not visibility_improved(N[fp].file) and not consequential(N[fp]) and not unmasked_by_entrypoint(N[fp])
                and not split_by_unit(N[fp]) and not unmasked_local_import(N[fp])
                and not unmasked_push_plan(N[fp])):
            return False, "NEW_FINGERPRINT"
    if removed - set(justified):
        return False, "PRESERVATION_VIOLATION"
    old_keys, new_keys = renamed or (set(), set())
    # AC-1: a PY.SYNTAX symbol names a broken unit to FIX, never a symbol a repair may delete (before AC-1 PY.SYNTAX
    # carried no symbol, so this set is unchanged)
    named = {x.symbol for x in prev.diagnostics if x.code.startswith("PY.") and x.code != PY_SYNTAX_CODE and x.symbol}
    old_py = sorted(p for p in old_keys if p.endswith(".py") and p in d)
    if old_py:
        new_py = sorted(p for p in new_keys if p.endswith(".py") and p in d2)
        if len(new_py) < len(old_py):
            return False, "PRESERVATION_VIOLATION"
        before = set().union(*(_top_level_symbols(d[p]) for p in old_py))
        after = set().union(*(_top_level_symbols(d2[p]) for p in new_py))
        if (before - after) - named:
            return False, "PRESERVATION_VIOLATION"
    for path, text in d.items():
        if path in old_keys:
            continue
        if path.endswith(".py") and path not in d2:
            return False, "PRESERVATION_VIOLATION"
        if path.startswith("apps/") and path.endswith(".py") and d2.get(path) != text:
            if (_top_level_symbols(text) - _top_level_symbols(d2[path])) - named:
                return False, "PRESERVATION_VIOLATION"
    return True, None


def _unavailable(tool: str) -> ValidationReport:
    return ValidationReport(status="UNAVAILABLE", source="precommit", artifact_hash="", tools_unavailable=[tool])


__all__ = ["REPAIR_PROMPT_VERSION", "Assembled", "LoopContext", "RepairLoop", "RepairTask", "Router", "accept",
           "classify", "followup_hint", "removal_followups", "removal_justifications", "render_repair_prompt"]
