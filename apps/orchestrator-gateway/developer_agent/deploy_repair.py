"""TI-5-R3 (register row TI-5-R3, owner 10-21): the deploy's typed `validation_report` drives the developer stage's
terraform remediation on a typed-intent workload.

The workflow forwards the tf-applier callback's `validation_report` (mcp-servers/terraform/service.py
`apply_validation_report`, source "apply") with the remediation dispatch (`tf_validation_report`). This module decides,
before any LLM call, what that dispatch does (pure functions; json.loads and the shared models only, no I/O):

- REGENERATE (today's path, full regeneration from the error text): no report (older tf-applier / older workflow /
  a first build); a legacy workload (no typed-intent run), whatever the report says; a report that does not parse,
  is not source "apply", or is UNAVAILABLE (GATE_UNAVAILABLE: no engine result, e.g. a failed init); a CODE_DEFECT
  that is not on an entry of the committed intent.
- STOP, zero LLM spend: a FAIL with PLATFORM_DEFECT (a platform-written file, TI-3c) -> typed PLATFORM_DEFECT (503);
  a FAIL with BROWNFIELD_CONFLICT (a user-owned file, also beside intent findings; TI-5-R3-b, owner 10-25) -> typed
  OPERATOR_ACTION_REQUIRED, reason BROWNFIELD_CONFLICT (409).
- INTENT_REPAIR: a FAIL with CODE_DEFECT whose every error names an entry of the committed
  infra/workload/iac_intent.json: the existing repair loop on that intent, the findings as seeds.

INTENT_REPAIR: the draft is the repository's own files (the committed bytes; nothing is regenerated): every file
outside `infra/` and `.github/` (the platform renders those; on the intent path the AI's only file under `infra/` is
the intent, which joins the draft) plus the committed intent. QA-REPAIR-OWNERSHIP-PARITY (SAT-49): of those files,
only the ones the developer wrote in the released build (`draft_paths`, the gateway's record matched to the trace's
merged commit by exact sha); without them an INTENT_REPAIR is today's regeneration, reason DRAFT_PATHS_UNAVAILABLE.
The deploy's findings are seeds: the repair loop adds each one to its report for as long as the intent entry it
names is unchanged (exact JSON value), so a repair must change that entry; the loop's own rules decide the rest
(accept, preservation, removal justification, budget).
Repairs may edit only the intent (`REPAIRABLE_PATHS`); a finding routed to any other file stops the loop.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

try:
    from shared.diagnostics import Diagnostic, ErrorClass, ValidationReport, fingerprint
except ImportError:  # pragma: no cover
    from ..shared.diagnostics import Diagnostic, ErrorClass, ValidationReport, fingerprint  # type: ignore

from .iac_intent_contract import INTENT_PATH

REGENERATE, STOP, INTENT_REPAIR = "REGENERATE", "STOP", "INTENT_REPAIR"
REPORT_SOURCE = "apply"
# Exact path prefixes the platform owns in a typed-intent repository (rendered workload IaC, vendored modules, CI
# workflows); the committed files under them stay in the repository (the commit is a tree on top of the base tree).
PLATFORM_TREE_PREFIXES = ("infra/", ".github/")
REPAIRABLE_PATHS: FrozenSet[str] = frozenset({INTENT_PATH})
_ENTRY_LISTS = (("modules", "module.{name}"), ("resources", "{type}.{name}"), ("outputs", "output.{name}"))
# QA-REPAIR-OWNERSHIP-PARITY (SAT-49): a recorded draft path set (pipeline_executions/{trace}.stages.developer.
# committed_draft.llm_draft_paths) is used only when it is a non-empty list of strings of at most this many paths; the
# gateway refuses to record a larger one (the 1 MiB document limit), so a larger one is never a record.
DRAFT_PATHS_MAX = 2000
DRAFT_PATHS_UNAVAILABLE = "DRAFT_PATHS_UNAVAILABLE"
# the generate_code_files keyword the gateway sets on a terraform remediation dispatch whose record it matched
DRAFT_PATHS_KWARG = "deploy_draft_paths"


def draft_paths_of(value: Any) -> Optional[FrozenSet[str]]:
    """The exact path set of a forwarded draft record, or None (absent, not a list, empty, a non-string entry, or
    more than DRAFT_PATHS_MAX paths). Type checks only; the paths are compared by exact equality."""
    if not isinstance(value, (list, tuple)) or not value or len(value) > DRAFT_PATHS_MAX:
        return None
    if not all(isinstance(p, str) for p in value):
        return None
    return frozenset(value)


@dataclass(frozen=True)
class DeployRepairPlan:
    mode: str
    reason: str
    report: Optional[ValidationReport] = None
    seeds: Tuple[Diagnostic, ...] = ()
    seed_entries: Mapping[str, str] = field(default_factory=dict)   # entry address -> canonical JSON (committed)
    draft: Mapping[str, str] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        """What the run record keeps (DeveloperAgent._record_stack)."""
        return {"mode": self.mode, "reason": self.reason,
                "report_class": (self.report.error_class.value if self.report is not None
                                 and self.report.error_class is not None else None),
                "seeds": [{"code": d.code, "block": d.block_address} for d in self.seeds]}


def intent_entries(text: Any) -> Optional[Dict[str, str]]:
    """{entry address: canonical JSON of the entry} of an intent document ("module.<name>", "<type>.<name>",
    "output.<name>": the addresses the renderer and the apply report use). None when the text is not a JSON object.
    json.loads only; an entry without the naming fields has no address (and so is never a seed's entry)."""
    if not isinstance(text, str):
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    out: Dict[str, str] = {}
    for key, fmt in _ENTRY_LISTS:
        items = doc.get(key)
        for e in items if isinstance(items, list) else ():
            if isinstance(e, dict) and isinstance(e.get("name"), str) and (key != "resources"
                                                                            or isinstance(e.get("type"), str)):
                out.setdefault(fmt.format(name=e["name"], type=e.get("type")),
                               json.dumps(e, sort_keys=True, ensure_ascii=False))
    return out


def repair_draft(existing_files: Mapping[str, Any], draft_paths: Optional[FrozenSet[str]] = None) -> Dict[str, str]:
    """The INTENT_REPAIR draft: the repository's files outside the platform prefixes, plus the committed intent.
    QA-REPAIR-OWNERSHIP-PARITY (SAT-49): with `draft_paths` (the released build's own LLM draft, exact paths) only
    those files; every other file stays the repository's. None = every file outside the prefixes (before SAT-49;
    plan_deploy_repair always passes a set)."""
    draft = {p: c for p, c in (existing_files or {}).items()
             if isinstance(p, str) and isinstance(c, str) and not p.startswith(PLATFORM_TREE_PREFIXES)
             and (draft_paths is None or p in draft_paths)}
    draft[INTENT_PATH] = existing_files[INTENT_PATH]
    return draft


def plan_deploy_repair(raw_report: Any, *, intent_run: Any, existing_files: Optional[Mapping[str, Any]],
                       draft_paths: Any = None) -> DeployRepairPlan:
    """The dispatch's plan (module docstring table). Never raises. `draft_paths`: the gateway's matched record of the
    released build's own files (SAT-49); without a usable one an INTENT_REPAIR becomes today's regeneration
    (DRAFT_PATHS_UNAVAILABLE). Every other row of the table is unchanged (the STOPs need no draft)."""
    if raw_report is None:
        return DeployRepairPlan(REGENERATE, "NO_REPORT")
    if intent_run is None:
        return DeployRepairPlan(REGENERATE, "NOT_AN_INTENT_WORKLOAD")
    try:
        report = ValidationReport.model_validate(raw_report)
    except Exception:  # noqa: BLE001 - pydantic ValidationError / TypeError: an unusable report is no report
        return DeployRepairPlan(REGENERATE, "REPORT_INVALID")
    if report.source != REPORT_SOURCE:
        return DeployRepairPlan(REGENERATE, "REPORT_NOT_FROM_APPLY", report)
    if report.status != "FAIL":
        return DeployRepairPlan(REGENERATE, "REPORT_" + report.status, report)
    # TI-3c: a platform-written file -> PLATFORM_DEFECT; TI-5-R3-b: a user-owned file (also beside intent findings:
    # the report's class outranks CODE_DEFECT) -> the operator. Both stop, never regenerate.
    if report.error_class in (ErrorClass.PLATFORM_DEFECT, ErrorClass.BROWNFIELD_CONFLICT):
        return DeployRepairPlan(STOP, report.error_class.value, report)
    if report.error_class is not ErrorClass.CODE_DEFECT:
        return DeployRepairPlan(REGENERATE, "REPORT_CLASS_" + str(getattr(report.error_class, "value", None)),
                                report)
    committed = (existing_files or {}).get(INTENT_PATH)
    entries = intent_entries(committed)
    if entries is None:
        return DeployRepairPlan(REGENERATE, "NO_COMMITTED_INTENT", report)
    seeds: List[Diagnostic] = []
    seen = set()
    for d in report.diagnostics:
        if d.severity != "error":
            continue
        if d.error_class is not ErrorClass.CODE_DEFECT or d.file != INTENT_PATH or d.block_address not in entries:
            return DeployRepairPlan(REGENERATE, "FINDING_NOT_ON_A_COMMITTED_INTENT_ENTRY", report)
        # the engine's line / column are positions in the render (custom.tf.json), not in the intent
        seed = d.model_copy(update={"line": None, "column": None, "end_line": None})
        if fingerprint(seed) not in seen:
            seen.add(fingerprint(seed))
            seeds.append(seed)
    paths = draft_paths_of(draft_paths)   # SAT-49: the released build's own files (exact paths), else regenerate
    if paths is None:
        return DeployRepairPlan(REGENERATE, DRAFT_PATHS_UNAVAILABLE, report)
    return DeployRepairPlan(INTENT_REPAIR, "CODE_DEFECT_ON_INTENT", report, tuple(seeds),
                            {d.block_address: entries[d.block_address] for d in seeds},
                            repair_draft(existing_files or {}, paths))


def live_seeds(seeds: Tuple[Diagnostic, ...], seed_entries: Mapping[str, str], intent_text: Any) -> List[Diagnostic]:
    """The seeds whose intent entry is still exactly the committed one (canonical JSON equality)."""
    if not seeds:
        return []
    now = intent_entries(intent_text) or {}
    return [d for d in seeds if d.block_address in now and now[d.block_address] == seed_entries.get(d.block_address)]


def with_seeds(report: ValidationReport, seeds: List[Diagnostic]) -> ValidationReport:
    """`report` plus the live seeds (a PASS becomes a FAIL carrying them; UNAVAILABLE is kept as it is)."""
    if not seeds or report.status == "UNAVAILABLE":
        return report
    have = {fingerprint(d) for d in report.diagnostics}
    extra = [d for d in seeds if fingerprint(d) not in have]
    if not extra:
        return report
    data = report.model_dump(mode="json")
    data.update(status="FAIL", error_class=None, diagnostics=data["diagnostics"] + [d.model_dump(mode="json")
                                                                                  for d in extra])
    return ValidationReport.model_validate(data)


def stop_error(plan: DeployRepairPlan, product_id: str) -> Exception:
    """The typed refusal of a STOP plan (gateway gate_errors; the workflow's failure handler keeps the class)."""
    from gate_errors import OperatorActionRequiredError, PlatformDefectError
    report = plan.report
    diags = [d.model_dump(mode="json") for d in (report.diagnostics if report is not None else [])][:50]
    details = {"product_id": product_id, "source": REPORT_SOURCE, "report_class": plan.reason}
    if plan.reason == ErrorClass.BROWNFIELD_CONFLICT.value:   # TI-5-R3-b (owner 10-25): HTTP 409, the operator
        return OperatorActionRequiredError(
            "the deploy failed on a user-owned file (human.tf, human_override.tf or an override file): operator "
            "action required; the developer never edits user-owned files", reason="BROWNFIELD_CONFLICT",
            stage="developer", diagnostics=diags, details=details)
    return PlatformDefectError(
        "the deploy failed on a platform-written file (PLATFORM_DEFECT): a regeneration of the workload cannot fix "
        "it", reason="APPLY_PLATFORM_DEFECT", stage="developer", diagnostics=diags, details=details)


__all__ = ["REGENERATE", "STOP", "INTENT_REPAIR", "REPAIRABLE_PATHS", "PLATFORM_TREE_PREFIXES", "DeployRepairPlan",
           "DRAFT_PATHS_MAX", "DRAFT_PATHS_UNAVAILABLE", "DRAFT_PATHS_KWARG", "draft_paths_of", "intent_entries",
           "repair_draft", "plan_deploy_repair", "live_seeds", "with_seeds", "stop_error"]
