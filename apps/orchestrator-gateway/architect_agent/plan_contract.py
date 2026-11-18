"""PLAN-CONTRACT-CHECK (owner 11-17; plan docs/planning/plan-contract-check-plan.md §2-§4, §8.1): refuse architect
plans the platform cannot honour, before any code is written.

The check reads the plan's TYPED `target_files` only (every infra task, code task and build step); descriptions,
acceptance criteria, titles and risk text are never read (AGENTS invariant 2). A planned file is refused when the
platform deletes it before commit and never writes it back, by the platform's own exact predicates, imported, never
copied:
- PLAN.PLATFORM_CI_FILE: `qa_auditor.judge_input.is_platform_ci_path` and not `is_platform_deploy_workflow`; the root
  `cloudbuild.yaml` (`SERVERLESS_GIT_PIPELINE_FILE`) only when the workload's VCS kind is exactly GITHUB. With an
  unknown VCS kind that one clause is not evaluated and is recorded in `not_checked` (fail-loudly policy §2).
- PLAN.CONTAINER_FILE: `developer_agent.handler.is_prohibited_container_file` (Buildpacks only, AGENTS invariant 4).

`gate_plan_contract` holds the whole loop: a violating plan is sent back to the architect through the caller's
`replan_fn` (the existing consensus remediation-turn call) at most MAX_PLAN_CONTRACT_REPLANS times; turn 2 only when
turn 1 fixed every path it was told about and reported new ones (fingerprint `(code, symbol)`, the exact path). A
re-plan is accepted only when it is a real plan with no violation, no DAG error it introduced (`dag_regression`,
counts against the draft's own baseline) and the draft's typed compute decision unchanged (`compute_scope_changes`:
the critic audited the draft, not the re-plan). Every other ending is typed: an outage (rate limit, no model answer)
raises GATE_UNAVAILABLE, typed gate errors and stage stops propagate, an unusable answer (off-enum archetype,
unparseable plan) and everything else exhausts. Exhaustion follows PLAN_CONTRACT_ON_EXHAUSTION: STRIP removes the
flagged entries from the DRAFT (the consensus-audited plan) and records it, except a CI-file entry the QA judge's
per-task facts rest on (kept and recorded, `strip_violations`); FAIL raises PlanContractViolationError
(ARCHITECT_DEFECT, 422). A plan with no violation is returned as the same object, unchanged, with no model call (Do No
Harm). An unexpected exception inside the gate is a typed PlatformDefectError (PLAN_CONTRACT_GATE_DEFECT).

Every exception that leaves `gate_plan_contract` carries the stage-trace record as `exc.plan_contract_record`, so the
caller writes the architect stage trace before re-raising. Heavy imports (judge_input, the developer handler, the cycle
detector) are lazy: judge_input already imports developer_agent lazily, and this avoids an import cycle.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Tuple

import stage_deadline   # STAGE-DEADLINE (gateway root module)
from gate_errors import ErrorClass, GateError, GateUnavailableError, PlatformDefectError

try:
    from shared.artifact_ownership import RENDER_SOURCES
    from shared.diagnostics import Diagnostic
    from shared.diagnostics import ErrorClass as DiagnosticClass
except ImportError:  # pragma: no cover - package-relative fallback
    from ..shared.artifact_ownership import RENDER_SOURCES  # type: ignore
    from ..shared.diagnostics import Diagnostic  # type: ignore
    from ..shared.diagnostics import ErrorClass as DiagnosticClass  # type: ignore

logger = logging.getLogger("castor-architect-agent")

CODE_PLATFORM_CI_FILE = "PLAN.PLATFORM_CI_FILE"
CODE_CONTAINER_FILE = "PLAN.CONTAINER_FILE"
CODE_DAG_INVALID = "PLAN.DAG_INVALID"
# Q4 (owner 11-17): at most 2 re-plan turns, as the topology gate (AC-4).
MAX_PLAN_CONTRACT_REPLANS = 2
# Stage budget a re-plan turn needs (plan §3.3): 180 s for one re-plan call (the upper end of the observed 1-3 min)
# + 120 s for the topology gate's up to two repair calls after it + 60 s for persistence and trace writes. No measured
# live-model p95 exists yet (Q6 refines it). `stage_deadline.remaining_s() is None` (no stage deadline) means allowed.
PLAN_CONTRACT_REPLAN_MIN_S = 360.0
# Q5 (owner): what an exhausted re-plan does. "STRIP" (recommended, the default) or "FAIL". One constant.
EXHAUSTION_STRIP, EXHAUSTION_FAIL = "STRIP", "FAIL"
PLAN_CONTRACT_ON_EXHAUSTION = EXHAUSTION_STRIP
PLAN_FILE = "architect:plan"
REASON = "ARCHITECT_PLAN_CONTRACT_VIOLATION"
CHECKPOINT_LABEL = "architect.plan_contract"

# outcomes (stage trace `plan_contract.outcome`)
OUTCOME_PASSED = "PASSED"
OUTCOME_REPLANNED = "REPLANNED"
OUTCOME_STRIPPED = "STRIPPED"
OUTCOME_REFUSED = "REFUSED"
OUTCOME_INTERRUPTED = "INTERRUPTED"   # an outage (FAIL mode), a typed gate error or a stage stop left the gate
OUTCOME_SKIPPED = "SKIPPED"           # the deterministic fallback plan: never checked here (the topology gate refuses it)

# exhaustion reasons (stage trace `plan_contract.stopped`)
STOP_NO_PROGRESS = "NO_PROGRESS"
STOP_MAX_TURNS = "MAX_TURNS"
STOP_NO_STAGE_BUDGET = "NO_STAGE_BUDGET"
STOP_NO_MODEL = "NO_MODEL"
STOP_MAP_REDUCE = "MAP_REDUCE"
STOP_REPLAN_UNUSABLE = "REPLAN_UNUSABLE"
STOP_REPLAN_DAG_INVALID = "REPLAN_DAG_INVALID"
STOP_REPLAN_FAILED = "REPLAN_FAILED"
STOP_REPLAN_CHANGED_COMPUTE = "REPLAN_CHANGED_COMPUTE"
# Under STRIP, a model outage during a re-plan turn (a GATE_UNAVAILABLE-class error raised by the re-plan call, e.g.
# ArchitectRateLimitedError, or a re-plan with no model answer) is a failed turn, never a failed stage: the audited
# draft was usable before the re-plan was asked for (orchestrator decision on code review finding 3; owner policy: the
# check never fails a run that passes today). Under FAIL the outage still surfaces as GATE_UNAVAILABLE.
STOP_REPLAN_MODEL_UNAVAILABLE = "REPLAN_MODEL_UNAVAILABLE"

# An unexpected exception inside the gate (code review finding 4): typed, never an untyped HTTP 500.
REASON_GATE_DEFECT = "PLAN_CONTRACT_GATE_DEFECT"
# Why a strip kept a flagged entry (code review finding 1, stage trace `plan_contract.stripped[*].kept[*].reason`).
KEPT_FOR_JUDGE_TASK_FACTS = "JUDGE_TASK_FACTS"

VCS_UNKNOWN_NOT_CHECKED = f"{CODE_PLATFORM_CI_FILE}:cloudbuild.yaml (vcs unknown)"
MAX_RECORDED_STRINGS = 10

# Fixed text per code (pinned by tests/test_plan_contract_check.py). `{path}` is the exact planned path.
_MESSAGES = {
    CODE_PLATFORM_CI_FILE: ("StackVend builds every image with Buildpacks and writes the CI itself "
                            "(`.github/workflows/deploy-<service>.yml` on GitHub); a repository `{path}` is deleted."),
    CODE_CONTAINER_FILE: "images are built with Buildpacks; every Dockerfile / .dockerignore is deleted.",
}
_HINTS = {
    CODE_PLATFORM_CI_FILE: ("Remove `{path}` from this task's or step's target_files, and the instructions and "
                            "acceptance criteria that ask for it: the platform deletes the file before commit and "
                            "writes the CI itself."),
    CODE_CONTAINER_FILE: ("Remove `{path}` from this task's or step's target_files, and the instructions and "
                          "acceptance criteria that ask for it: the platform deletes it before commit and builds "
                          "the image with Buildpacks."),
}

BRIEF_HEADER = (
    "--- PLATFORM PLAN CONTRACT (the platform refused the draft plan) ---\n"
    "Each line is one planned file the platform deletes before commit and never writes, so the task can never be "
    "met.\n"
    "For each line:\n"
    "- remove the file from the target_files of the task or step that names it;\n"
    "- in that same task or step, remove every instruction in its description and every acceptance criterion that "
    "asks for that file, because the platform provides what the file was for.\n"
    "If a task or step is then left with no target files and no other work, remove it and drop its id from every "
    "depends_on. Change nothing else.\n"
)
BRIEF_FOOTER = "--- END PLAN CONTRACT ---\n"

# Turn results (stage trace `plan_contract.turns[*].result`)
TURN_ACCEPTED = "ACCEPTED"
TURN_VIOLATING = "VIOLATING"
TURN_DAG_REGRESSION = "DAG_REGRESSION"
TURN_UNUSABLE = "UNUSABLE"
TURN_NO_MODEL_RESPONSE = "NO_MODEL_RESPONSE"
TURN_FAILED = "FAILED"
TURN_RAISED = "RAISED"
TURN_CHANGED_COMPUTE = "CHANGED_COMPUTE"
TURN_MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"   # STRIP only: an outage in the re-plan turn (`turns[*].unavailable`)


class PlanContractViolationError(GateError):
    """The architect's plan names files the platform deletes and never writes, and the bounded re-plan did not remove
    them (exhaustion mode FAIL), or a strip left a violation (a platform defect, never passed). Typed outcome
    ARCHITECT_DEFECT, HTTP 422, reason ARCHITECT_PLAN_CONTRACT_VIOLATION, stage `architect`; the violations are the
    body's diagnostics. Same shape as topology_gate.TopologyInvalidError."""

    error_class = ErrorClass.ARCHITECT_DEFECT
    http_status = 422


@dataclass
class PlanContractResult:
    """`plan` is the plan the architect stage continues with: the draft itself (PASSED / SKIPPED / STRIPPED, the same
    object) or the accepted re-plan (REPLANNED). `replanned_model_build_plan` is the value `read_model_build_plan()`
    returned right after the accepted re-plan call (None unless REPLANNED). `record` is the stage-trace
    `plan_contract` record (JSON-serialisable, no nested arrays)."""

    plan: Any
    outcome: str
    record: Dict[str, Any]
    replanned_model_build_plan: Optional[bool] = None


ReplanFn = Callable[[Any, List[Diagnostic]], Any]   # (plan to fix, its violations) -> inner ArchitectDecompositionResult


class ReplanAnswerUnusableError(Exception):
    """Raised by a `replan_fn` when every model answered but no answer is a usable plan (the caller maps its own
    typed "bad answer" error, e.g. the architect's off-enum compute archetype, to this). Not a GateError: the gate
    treats it as a failed turn (REPLAN_UNUSABLE) and exhaustion keeps the audited draft (code review finding 3).
    `reason` is the original error's typed reason (recorded in the turn)."""

    def __init__(self, message: str, *, reason: Optional[str] = None):
        super().__init__(message)
        self.reason = reason


# ------------------------------------------------------------------------------------------------- the check
def _judge_input():
    from qa_auditor import judge_input   # lazy: judge_input imports developer_agent lazily (import cycle)
    return judge_input


def _is_prohibited_container_file(path: str) -> bool:
    from developer_agent.handler import is_prohibited_container_file   # lazy (heavy module, import cycle)
    return is_prohibited_container_file(path)


def _items(plan: Any) -> List[Tuple[str, str, str, Any]]:
    """(kind, address prefix, id, item) for every task and build step, in plan order: infra tasks, code tasks, then
    build steps. Attribute reads only."""
    out: List[Tuple[str, str, str, Any]] = []
    for kind, field in (("infra_task", "infra_tasks"), ("code_task", "code_tasks")):
        for t in list(getattr(plan, field, None) or []):
            tid = str(getattr(t, "task_id", "") or "")
            out.append((kind, f"{field}[{tid}]", tid, t))
    build_plan = getattr(plan, "sequenced_build_plan", None)
    for s in list(getattr(build_plan, "steps", None) or []) if build_plan is not None else []:
        sid = str(getattr(s, "step_id", "") or "")
        out.append(("build_step", f"sequenced_build_plan.steps[{sid}]", sid, s))
    return out


def _block_address(prefix: str, index: int) -> str:
    return f"{prefix}.target_files[{index}]"


def _diagnostic(code: str, path: str, block_address: str) -> Diagnostic:
    hint = _HINTS[code].format(path=path)
    sources = RENDER_SOURCES.get(path)
    if sources:
        hint += " Platform render sources of this path: " + "; ".join(
            f"{s.source} ({s.owner.value})" for s in sources) + "."
    return Diagnostic(tool="platform", code=code, severity="error", error_class=DiagnosticClass.ARCHITECT_DEFECT,
                      file=PLAN_FILE, block_address=block_address, symbol=path,
                      message=_MESSAGES[code].format(path=path), hint=hint, source="architect")


def _path_codes(path: Any, vcs_kind: Optional[str]) -> List[str]:
    """The v1 codes one planned path breaks (exact predicates; a non-string target is never flagged)."""
    if not isinstance(path, str):
        return []
    ji = _judge_input()
    codes: List[str] = []
    if ji.is_platform_ci_path(path) and not ji.is_platform_deploy_workflow(path):
        if path != ji.SERVERLESS_GIT_PIPELINE_FILE or vcs_kind == ji.VCS_GITHUB:
            codes.append(CODE_PLATFORM_CI_FILE)
    if _is_prohibited_container_file(path):
        codes.append(CODE_CONTAINER_FILE)
    return codes


def check_plan_contract(plan: Any, vcs_kind: Optional[str]) -> Tuple[List[Diagnostic], List[str]]:
    """(violations, not_checked) of the plan's typed target files. Pure and read-only: attribute reads only, no copy,
    no assignment. Deterministic order: infra tasks, code tasks, build steps, each in plan order, then file index.

    The root `cloudbuild.yaml` clause runs only with a known VCS kind (GITHUB or SERVERLESS_GIT) and flags only on
    GITHUB; with any other value (None: unreadable workload record, eval harness) it is not evaluated and
    `not_checked` says so (fail-loudly policy §2). Every other clause always runs."""
    ji = _judge_input()
    not_checked: List[str] = []
    if vcs_kind not in (ji.VCS_GITHUB, ji.VCS_SERVERLESS_GIT):
        not_checked.append(VCS_UNKNOWN_NOT_CHECKED)
    violations: List[Diagnostic] = []
    for _kind, prefix, _id, item in _items(plan):
        for i, path in enumerate(list(getattr(item, "target_files", None) or [])):
            for code in _path_codes(path, vcs_kind):
                violations.append(_diagnostic(code, path, _block_address(prefix, i)))
    return violations, not_checked


def violation_key(d: Diagnostic) -> Tuple[str, str]:
    """Progress fingerprint (RT 6): (code, exact path). `block_address` carries the list index and the task id, which
    a full re-plan renumbers, so it is never part of the key."""
    return (d.code, d.symbol or "")


def _key_json(d: Diagnostic) -> Dict[str, str]:
    code, symbol = violation_key(d)
    return {"code": code, "symbol": symbol}


def _dumps(diags: List[Diagnostic]) -> List[Dict[str, Any]]:
    return [d.model_dump(mode="json") for d in diags]


# ------------------------------------------------------------------------------------------------- DAG regression
def _validate_dag(plan: Any) -> Any:
    try:
        from .cycle_detector import validate_dual_layer_dag
    except ImportError:  # pragma: no cover - flat layout
        from cycle_detector import validate_dual_layer_dag  # type: ignore
    build_plan = getattr(plan, "sequenced_build_plan", None)
    return validate_dual_layer_dag(steps=list(getattr(build_plan, "steps", None) or []) if build_plan else [],
                                   infra_tasks=list(getattr(plan, "infra_tasks", None) or []),
                                   code_tasks=list(getattr(plan, "code_tasks", None) or []))


def _dag_diag(kind: str, message: str, errors: List[str]) -> Diagnostic:
    shown = list(errors)[:MAX_RECORDED_STRINGS]
    return Diagnostic(tool="platform", code=CODE_DAG_INVALID, severity="error",
                      error_class=DiagnosticClass.ARCHITECT_DEFECT, file=PLAN_FILE, block_address=f"dag.{kind}",
                      symbol=kind, message=message, detail="\n".join(shown) or None,
                      hint="Keep the draft plan's task and step dependencies; change only what the platform plan "
                           "contract asks for.",
                      source="architect")


def dag_regression(before: Any, after: Any) -> List[Diagnostic]:
    """PLAN.DAG_INVALID for each DAG error kind the re-plan INTRODUCED compared with the draft's baseline (RT 3):
    a cycle appears, or the number of orphan dependencies grows, or the number of stage-ordering violations grows.
    Counts, not error strings: a full re-plan renumbers the ids inside the strings. [] = no regression (errors the
    draft already had are never refused)."""
    out: List[Diagnostic] = []
    if bool(getattr(after, "cycle_detected", False)) and not bool(getattr(before, "cycle_detected", False)):
        out.append(_dag_diag("cycle", "the re-plan introduced a dependency cycle",
                             list(getattr(after, "errors", None) or [])))
    b_orph = list(getattr(before, "orphan_dependencies", None) or [])
    a_orph = list(getattr(after, "orphan_dependencies", None) or [])
    if len(a_orph) > len(b_orph):
        out.append(_dag_diag("orphan_dependencies",
                             f"the re-plan has {len(a_orph)} dependencies on ids that do not exist "
                             f"(the draft had {len(b_orph)})", a_orph))
    b_ord = list(getattr(before, "ordering_violations", None) or [])
    a_ord = list(getattr(after, "ordering_violations", None) or [])
    if len(a_ord) > len(b_ord):
        out.append(_dag_diag("ordering_violations",
                             f"the re-plan has {len(a_ord)} stage-ordering violations (the draft had {len(b_ord)})",
                             a_ord))
    return out


def _dag_summary(res: Any) -> Dict[str, Any]:
    errors = list(getattr(res, "errors", None) or [])
    return {"count": len(errors), "errors": errors[:MAX_RECORDED_STRINGS],
            "cycle_detected": bool(getattr(res, "cycle_detected", False)),
            "orphan_dependencies": len(list(getattr(res, "orphan_dependencies", None) or [])),
            "ordering_violations": len(list(getattr(res, "ordering_violations", None) or []))}


# ------------------------------------------------------------------------------------------------- compute scope
def _topology_services(topo: Any) -> List[Tuple[str, str]]:
    return sorted((str(getattr(s, "name", "")), str(getattr(getattr(s, "kind", None), "value", getattr(s, "kind", ""))))
                  for s in list(getattr(topo, "services", None) or []))


def compute_scope_changes(draft: Any, replan: Any) -> List[str]:
    """The typed compute fields an (otherwise clean) re-plan changed compared with the draft, by exact equality (code
    review finding 2: the critic audited the draft, and the brief says "change nothing else"). [] = unchanged.
    - `compute_archetype`;
    - `target_compute_services`, in order ([0] is the workload the primary archetype runs, schemas.py);
    - the typed `service_topology` (parsed, not raw), when the draft has one: present in the re-plan, the sorted
      (name, kind) of its services and its `primary_service`. A draft without a parsed topology (absent or malformed:
      the topology gate repairs it) has nothing typed to compare."""
    changed: List[str] = []
    if getattr(draft, "compute_archetype", None) != getattr(replan, "compute_archetype", None):
        changed.append("compute_archetype")
    if list(getattr(draft, "target_compute_services", None) or []) != \
            list(getattr(replan, "target_compute_services", None) or []):
        changed.append("target_compute_services")
    d_topo = getattr(draft, "service_topology", None)
    if d_topo is not None:
        r_topo = getattr(replan, "service_topology", None)
        if r_topo is None:
            changed.append("service_topology")
        else:
            if _topology_services(d_topo) != _topology_services(r_topo):
                changed.append("service_topology.services")
            if getattr(d_topo, "primary_service", None) != getattr(r_topo, "primary_service", None):
                changed.append("service_topology.primary_service")
    return changed


# ------------------------------------------------------------------------------------------------- renderers
def render_contract_brief(violations: List[Diagnostic]) -> str:
    """The exact block the architect is told (plan §3.3), one line per violation, values verbatim. The caller appends
    the two draft renderers (`_draft_plan_json(plan, subject=...)`, `_draft_compute_decision(plan)`)."""
    lines = [f"- {d.code} {d.block_address} `{d.symbol}`: {d.message}" for d in violations]
    return BRIEF_HEADER + "".join(line + "\n" for line in lines) + BRIEF_FOOTER


_KIND_LABEL = {"infra_task": "Task", "code_task": "Task", "build_step": "Build step"}


def render_contract_note(record: Dict[str, Any]) -> str:
    """The plan markdown's `## Platform plan contract` section for a STRIPPED or REPLANNED outcome ("" otherwise),
    appended like the test-layout note."""
    outcome = (record or {}).get("outcome")
    turns = len((record or {}).get("turns") or [])
    if outcome == OUTCOME_STRIPPED and record.get("stripped"):
        lines = ["## Platform plan contract", "",
                 "The architect's plan named files the platform deletes before commit and never writes, and no "
                 f"re-plan removed them ({turns} re-plan turn(s), stopped: {record.get('stopped')}). The platform "
                 "removed exactly these entries from the plan's target files; task descriptions and acceptance "
                 "criteria were not changed and the platform provides what the files were for:"]
        for s in record["stripped"]:
            label = f"- {_KIND_LABEL.get(s.get('kind'), 'Item')} `{s.get('id')}`: "
            removed = [f"`{r['path']}` ({r['code']}: {r['message']})" for r in s.get("removed") or []]
            kept = [f"`{k['path']}` ({k['code']})" for k in s.get("kept") or []]
            said: List[str] = []
            if removed:
                said.append("removed " + "; ".join(removed))
            if kept:
                said.append("kept in the target files, because the QA judge's facts for this task rest on it (the "
                            "platform still deletes it before commit and writes the CI itself): " + "; ".join(kept))
            lines.append(label + "; ".join(said))
        return "\n".join(lines) + "\n"
    if outcome == OUTCOME_REPLANNED and record.get("violations"):
        lines = ["## Platform plan contract", "",
                 "The architect's first plan named files the platform deletes before commit and never writes; the "
                 f"architect re-planned it ({turns} re-plan turn(s)) and this plan names none of them. The re-plan "
                 "was not re-audited by the critic. Refused entries of the first plan:"]
        for v in record["violations"]:
            lines.append(f"- {v.get('code')} `{v.get('symbol')}` ({v.get('block_address')})")
        return "\n".join(lines) + "\n"
    return ""


# ------------------------------------------------------------------------------------------------- strip
def _judge_kinds(item: Any, targets: List[Any]) -> List[str]:
    """`judge_input.task_fact_kinds` of a plan task as the QA DAG carries it (its exact category value, these target
    files): the judge's own typed rule, never re-implemented here."""
    category = getattr(item, "category", None)
    return _judge_input().task_fact_kinds({"category": getattr(category, "value", category),
                                           "target_files": list(targets)})


def _strip(plan: Any, violations: List[Diagnostic]) -> Tuple[List[Dict[str, Any]], set]:
    """`strip_violations`, plus the exact (block address after the strip, path) of every entry it kept."""
    if not violations:
        return [], set()
    flagged: Dict[Tuple[str, str], List[Diagnostic]] = {}
    for d in violations:
        flagged.setdefault((d.block_address or "", d.symbol or ""), []).append(d)
    records: List[Dict[str, Any]] = []
    kept_addresses: set = set()
    for kind, prefix, item_id, item in _items(plan):
        targets = list(getattr(item, "target_files", None) or [])
        hits_at: Dict[int, List[Diagnostic]] = {}
        for i, path in enumerate(targets):
            hits = flagged.get((_block_address(prefix, i), path)) if isinstance(path, str) else None
            if hits:
                hits_at[i] = hits
        if not hits_at:
            continue
        keep: set = set()
        if kind in ("infra_task", "code_task"):   # judged tasks (build steps are not in the QA task DAG)
            before = _judge_kinds(item, targets)
            if _judge_kinds(item, [p for i, p in enumerate(targets) if i not in hits_at]) != before:
                # keep exactly the flagged entries that on their own give the task a judge fact kind; removing the
                # rest then leaves the kinds unchanged (task_fact_kinds is category OR any target)
                keep = {i for i in hits_at if _judge_kinds(SimpleNamespace(category=None), [targets[i]])}
        kept_list: List[Any] = []
        removed: List[Dict[str, Any]] = []
        kept: List[Dict[str, Any]] = []
        for i, path in enumerate(targets):
            if i in hits_at and i not in keep:
                removed.extend({"index": i, "path": path, "code": d.code, "message": d.message} for d in hits_at[i])
                continue
            if i in keep:
                kept.extend({"index": i, "path": path, "code": d.code, "reason": KEPT_FOR_JUDGE_TASK_FACTS}
                            for d in hits_at[i])
                kept_addresses.add((_block_address(prefix, len(kept_list)), path))
            kept_list.append(path)
        if removed:
            item.target_files = kept_list
        rec: Dict[str, Any] = {"kind": kind, "id": item_id, "removed": removed}
        if kept:
            rec["kept"] = kept
        records.append(rec)
    return records, kept_addresses


def strip_violations(plan: Any, violations: List[Diagnostic]) -> List[Dict[str, Any]]:
    """Exhaustion mode STRIP (plan §4, the `_apply_test_layout` precedent): remove the flagged entries from the items'
    `target_files` (a new list per changed item). Never touches descriptions, acceptance criteria, depends_on or the
    task set; an item left with no targets stays. An entry is removed only when its (block address, path) is exactly
    one `check_plan_contract` reported, so with no violations nothing is touched.

    One exception (code review finding 1): in an infra or code task (the QA task DAG), a flagged entry is KEPT when
    removing the task's flagged entries would change `judge_input.task_fact_kinds` for it and that entry on its own
    gives a fact kind (e.g. `cloudbuild.yaml` in a RELEASE task: the only typed "CI/CD facts apply" signal the judge
    has, while the task's prose still asks for the file). The developer never writes it (plan_targets excludes CI
    paths) and the platform still deletes it, exactly as today. Build steps are never judged: always stripped.

    Returns one record per item with a flagged entry: {kind, id, removed: [{index, path, code, message}]}, plus
    `kept: [{index, path, code, reason}]` when an entry was kept."""
    return _strip(plan, violations)[0]


# ------------------------------------------------------------------------------------------------- the gate
def _attach_record(exc: BaseException, record: Dict[str, Any]) -> None:
    try:
        exc.plan_contract_record = record   # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - best effort (plan §8.1: a stop error may not take attributes)
        pass


def _interrupted(record: Dict[str, Any], exc: BaseException) -> None:
    record["outcome"] = OUTCOME_INTERRUPTED
    record["interrupted_by"] = {"type": type(exc).__name__,
                                "error_class": getattr(getattr(exc, "error_class", None), "value", None),
                                "reason": getattr(exc, "reason", None)}
    _attach_record(exc, record)


def _unavailable_turn(entry: Dict[str, Any], exc: BaseException) -> None:
    """STRIP only: record a model outage of the re-plan turn as the failed turn MODEL_UNAVAILABLE (its typed class
    and reason in `turns[*].unavailable`); the caller stops the loop with REPLAN_MODEL_UNAVAILABLE."""
    error_class = getattr(getattr(exc, "error_class", None), "value", None)
    reason = getattr(exc, "reason", None)
    entry.update(result=TURN_MODEL_UNAVAILABLE,
                 unavailable={"type": type(exc).__name__, "error_class": error_class, "reason": reason},
                 error=f"{reason or type(exc).__name__}: {exc}"[:500])


def _refuse(record: Dict[str, Any], diagnostics: List[Diagnostic], *, trace_id: str, product_id: str,
            vcs_kind: Optional[str], why: Optional[str] = None) -> PlanContractViolationError:
    turns = record.get("turns") or []
    errors = [d for d in diagnostics if d.severity == "error"]
    summary = "; ".join(f"{d.code} {d.symbol}" for d in errors[:MAX_RECORDED_STRINGS])
    msg = f"architect plan violates the platform contract after {len(turns)} re-plan turn(s): {summary}"
    if why:
        msg = f"{msg} ({why})"
    record["outcome"] = OUTCOME_REFUSED
    err = PlanContractViolationError(
        msg, diagnostics=_dumps(errors), reason=REASON, stage="architect",
        details={"trace_id": trace_id, "product_id": product_id, "vcs_kind": vcs_kind,
                 "not_checked": list(record.get("not_checked") or []), "turns": list(turns),
                 "stopped": record.get("stopped")})
    _attach_record(err, record)
    return err


def gate_defect_error(exc: BaseException, *, trace_id: str, product_id: str,
                      record: Optional[Dict[str, Any]] = None) -> PlatformDefectError:
    """Code review finding 4: an unexpected exception inside the plan-contract gate (a defect of this check, which runs
    on every plan) as a typed PlatformDefectError, reason PLAN_CONTRACT_GATE_DEFECT, stage `architect` (invariant 8),
    with the stage-trace record (outcome INTERRUPTED) attached as `plan_contract_record`. The caller raises it `from`
    the original exception."""
    defect = f"{type(exc).__name__}: {exc}"[:500]
    err = PlatformDefectError(f"the platform plan-contract check failed: {defect}", reason=REASON_GATE_DEFECT,
                              stage="architect",
                              details={"trace_id": trace_id, "product_id": product_id, "defect": defect})
    rec = record if record is not None else {"outcome": None, "turns": [], "stripped": []}
    rec["defect"] = defect
    _interrupted(rec, err)
    return err


def gate_plan_contract(plan: Any, *, vcs_kind: Optional[str], replan_fn: Optional[ReplanFn], is_map_reduce: bool,
                       trace_id: str, product_id: str,
                       read_model_build_plan: Callable[[], Optional[bool]]) -> PlanContractResult:
    """Check the final (post-consensus) plan; re-plan a violating one (bounded); on exhaustion STRIP or FAIL.

    - 0 violations: PASSED with the same plan object, no model call, nothing changed.
    - A deterministic fallback plan (`_is_fallback`): SKIPPED (the topology gate refuses it right after).
    - Each turn: `stage_deadline.checkpoint`, then the room check (`remaining_s() < PLAN_CONTRACT_REPLAN_MIN_S` stops
      with NO_STAGE_BUDGET; None = allowed), then `replan_fn(plan_to_fix, its_violations)`.
    - Inner outcomes (plan §3.3): a clean real plan with no DAG regression is accepted (REPLANNED); a violating one
      gets turn 2 only after full progress by path, else NO_PROGRESS / MAX_TURNS; a DAG regression ->
      REPLAN_DAG_INVALID; a changed typed compute decision -> REPLAN_CHANGED_COMPUTE; `_is_fallback`, no plan or
      ReplanAnswerUnusableError -> REPLAN_UNUSABLE; a model outage of the re-plan call (a GATE_UNAVAILABLE-class
      GateError, e.g. ArchitectRateLimitedError, or `_no_model_response`) -> under STRIP the failed turn
      MODEL_UNAVAILABLE, REPLAN_MODEL_UNAVAILABLE; under FAIL it propagates (`_no_model_response` as
      GateUnavailableError ARCHITECT_NO_MODEL_RESPONSE); stage STOP_ERRORS and every other typed GateError propagate;
      any other exception -> REPLAN_FAILED.
    - Exhaustion (NO_PROGRESS, MAX_TURNS, NO_STAGE_BUDGET, NO_MODEL, MAP_REDUCE, REPLAN_*) works from the DRAFT.
    - Only the re-plan call is covered: the outer architect call and everything outside the turn are never caught.
    - Any other exception raised by the gate itself -> `gate_defect_error` (PlatformDefectError)."""
    record: Dict[str, Any] = {
        "outcome": None, "vcs_kind": vcs_kind, "not_checked": [], "violations": [], "turns": [], "stopped": None,
        "stripped": [], "dag_preexisting": None, "exhaustion_mode": PLAN_CONTRACT_ON_EXHAUSTION,
    }
    try:
        return _gate(plan, record, vcs_kind=vcs_kind, replan_fn=replan_fn, is_map_reduce=is_map_reduce,
                     trace_id=trace_id, product_id=product_id, read_model_build_plan=read_model_build_plan)
    except stage_deadline.STOP_ERRORS:
        raise
    except GateError:
        raise
    except Exception as e:  # noqa: BLE001 - finding 4: a defect of the check is typed, never an untyped 500
        logger.error(f"Plan-contract gate defect for '{product_id}' ({trace_id}): {type(e).__name__}: {e}")
        raise gate_defect_error(e, trace_id=trace_id, product_id=product_id, record=record) from e


def _gate(plan: Any, record: Dict[str, Any], *, vcs_kind: Optional[str], replan_fn: Optional[ReplanFn],
          is_map_reduce: bool, trace_id: str, product_id: str,
          read_model_build_plan: Callable[[], Optional[bool]]) -> PlanContractResult:
    if getattr(plan, "_is_fallback", False):
        record["outcome"] = OUTCOME_SKIPPED
        return PlanContractResult(plan=plan, outcome=OUTCOME_SKIPPED, record=record)

    violations, not_checked = check_plan_contract(plan, vcs_kind)
    record["not_checked"] = list(not_checked)
    if not violations:
        record["outcome"] = OUTCOME_PASSED
        return PlanContractResult(plan=plan, outcome=OUTCOME_PASSED, record=record)

    mode = PLAN_CONTRACT_ON_EXHAUSTION
    if mode not in (EXHAUSTION_STRIP, EXHAUSTION_FAIL):
        err = PlatformDefectError(f"PLAN_CONTRACT_ON_EXHAUSTION is {mode!r}; it must be 'STRIP' or 'FAIL'",
                                  reason="PLAN_CONTRACT_MODE_INVALID", stage="architect",
                                  details={"trace_id": trace_id, "product_id": product_id})
        _interrupted(record, err)
        raise err

    record["violations"] = _dumps(violations)
    baseline = _validate_dag(plan)
    record["dag_preexisting"] = _dag_summary(baseline)
    logger.warning(f"Plan contract: the architect plan for '{product_id}' ({trace_id}) names "
                   f"{len(violations)} file(s) the platform deletes and never writes: "
                   + "; ".join(f"{d.code} {d.symbol}" for d in violations[:MAX_RECORDED_STRINGS]))

    to_fix, told = plan, violations
    stopped: Optional[str] = None
    last_dag: List[Diagnostic] = []
    for turn in range(1, MAX_PLAN_CONTRACT_REPLANS + 1):
        if is_map_reduce:
            stopped = STOP_MAP_REDUCE   # a remediation brief forces single-turn: never re-plan a huge spec at once
            break
        if replan_fn is None:
            stopped = STOP_NO_MODEL
            break
        try:
            stage_deadline.checkpoint(CHECKPOINT_LABEL)
        except stage_deadline.STOP_ERRORS as stop:   # a stopped stage propagates unchanged, with the record
            _interrupted(record, stop)
            raise
        left = stage_deadline.remaining_s()
        if left is not None and left < PLAN_CONTRACT_REPLAN_MIN_S:
            stopped = STOP_NO_STAGE_BUDGET
            record["stage_budget_left_s"] = round(float(left), 1)
            break

        entry: Dict[str, Any] = {"turn": turn, "told": [_key_json(d) for d in told], "after": [],
                                 "dag_regression": [], "result": None, "duration_ms": 0}
        record["turns"].append(entry)
        t0 = time.time()
        try:
            inner = replan_fn(to_fix, told)
        except stage_deadline.STOP_ERRORS as stop:
            entry.update(result=TURN_RAISED, duration_ms=int((time.time() - t0) * 1000))
            _interrupted(record, stop)
            raise
        except ReplanAnswerUnusableError as bad:   # finding 3: a bad answer, not an outage; the draft stays usable
            entry.update(result=TURN_UNUSABLE, error=f"{bad.reason or type(bad).__name__}: {bad}"[:500],
                         duration_ms=int((time.time() - t0) * 1000))
            logger.warning(f"Plan-contract re-plan turn {turn} for '{product_id}' ({trace_id}) answered no usable "
                           f"plan: {bad.reason}")
            stopped = STOP_REPLAN_UNUSABLE
            break
        except GateError as gate_err:   # incl. ArchitectRateLimitedError (an outage)
            if mode == EXHAUSTION_STRIP and getattr(gate_err, "error_class", None) == ErrorClass.GATE_UNAVAILABLE:
                # an outage of the re-plan turn only (STOP_ERRORS were re-raised above): the draft stays usable
                _unavailable_turn(entry, gate_err)
                entry["duration_ms"] = int((time.time() - t0) * 1000)
                logger.warning(f"Plan-contract re-plan turn {turn} for '{product_id}' ({trace_id}): model "
                               f"unavailable ({type(gate_err).__name__} {getattr(gate_err, 'reason', None)}); "
                               f"the audited draft is stripped")
                stopped = STOP_REPLAN_MODEL_UNAVAILABLE
                break
            entry.update(result=TURN_RAISED, duration_ms=int((time.time() - t0) * 1000))
            _interrupted(record, gate_err)
            raise
        except Exception as e:  # noqa: BLE001 - one bounded call; a failed turn exhausts (topology-repair precedent)
            entry.update(result=TURN_FAILED, error=f"{type(e).__name__}: {e}"[:500],
                         duration_ms=int((time.time() - t0) * 1000))
            logger.error(f"Plan-contract re-plan turn {turn} failed for '{product_id}' ({trace_id}): {e}")
            stopped = STOP_REPLAN_FAILED
            break
        entry["duration_ms"] = int((time.time() - t0) * 1000)
        model_build_plan = read_model_build_plan()
        new_plan = getattr(inner, "architecture_plan", None)

        if new_plan is not None and getattr(new_plan, "_no_model_response", False):
            outage = GateUnavailableError(
                f"no architect model returned an answer for '{product_id}'; the deterministic fallback plan is never "
                f"used", reason="ARCHITECT_NO_MODEL_RESPONSE",
                details={"trace_id": trace_id, "product_id": product_id})
            if mode == EXHAUSTION_STRIP:   # the re-plan's fallback is never used; the audited draft is
                _unavailable_turn(entry, outage)
                logger.warning(f"Plan-contract re-plan turn {turn} for '{product_id}' ({trace_id}): no model "
                               f"answer; the audited draft is stripped")
                stopped = STOP_REPLAN_MODEL_UNAVAILABLE
                break
            entry["result"] = TURN_NO_MODEL_RESPONSE
            _interrupted(record, outage)
            raise outage
        if new_plan is None or getattr(new_plan, "_is_fallback", False):
            entry["result"] = TURN_UNUSABLE
            stopped = STOP_REPLAN_UNUSABLE
            break

        after, _ = check_plan_contract(new_plan, vcs_kind)
        entry["after"] = [_key_json(d) for d in after]
        regression = dag_regression(baseline, _validate_dag(new_plan))
        if regression:
            entry["dag_regression"] = _dumps(regression)
            entry["result"] = TURN_DAG_REGRESSION
            last_dag = regression
            stopped = STOP_REPLAN_DAG_INVALID
            break
        changed = compute_scope_changes(plan, new_plan)   # always against the audited draft
        if changed:
            entry["compute_changed"] = changed
            entry["result"] = TURN_CHANGED_COMPUTE
            stopped = STOP_REPLAN_CHANGED_COMPUTE
            break
        if not after:
            entry["result"] = TURN_ACCEPTED
            record["outcome"] = OUTCOME_REPLANNED
            logger.info(f"Plan contract: re-plan turn {turn} for '{product_id}' ({trace_id}) accepted")
            return PlanContractResult(plan=new_plan, outcome=OUTCOME_REPLANNED, record=record,
                                      replanned_model_build_plan=model_build_plan)
        entry["result"] = TURN_VIOLATING
        told_keys = {violation_key(d) for d in told}
        after_keys = {violation_key(d) for d in after}
        if turn >= MAX_PLAN_CONTRACT_REPLANS:
            stopped = STOP_MAX_TURNS
            break
        if told_keys & after_keys:
            stopped = STOP_NO_PROGRESS   # a path it was told about is still planned (whatever its index or task id)
            break
        to_fix, told = new_plan, after   # full progress, new findings: one more turn on the re-plan

    record["stopped"] = stopped
    logger.warning(f"Plan contract exhausted for '{product_id}' ({trace_id}): stopped {stopped}, mode {mode}")
    if mode == EXHAUSTION_FAIL:
        raise _refuse(record, violations + last_dag, trace_id=trace_id, product_id=product_id, vcs_kind=vcs_kind)

    # STRIP: the draft's flagged entries, from the draft (the consensus-audited plan); judge-fact entries are kept
    record["stripped"], kept_addresses = _strip(plan, violations)
    remaining = [d for d in check_plan_contract(plan, vcs_kind)[0]
                 if (d.block_address or "", d.symbol or "") not in kept_addresses]
    if remaining:   # a platform defect: the strip must remove every flagged entry; never passed
        record["stripped_remaining"] = _dumps(remaining)
        raise _refuse(record, remaining, trace_id=trace_id, product_id=product_id, vcs_kind=vcs_kind,
                      why="the platform strip left a violation")
    record["outcome"] = OUTCOME_STRIPPED
    return PlanContractResult(plan=plan, outcome=OUTCOME_STRIPPED, record=record)
