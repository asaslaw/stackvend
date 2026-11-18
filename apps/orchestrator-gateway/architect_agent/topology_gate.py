"""Architect topology gate (lane 10, FD-51; plan §5.3-§5.4, RT F5).

After consensus, the plan's `service_topology` is validated by the one deterministic validator
(`shared.service_topology.validate_service_topology`). An invalid topology gets ONE patch-style repair: a single
`generate_content` call with `response_schema=ServiceTopologyIntent`, whose prompt is the previous topology JSON + the
diagnostics + the plan's own typed summary fields. AC-4: a SECOND (last) patch turn is allowed only when the first
answer is a well-formed topology in which none of the findings it was told about remains (it fixed them all, and the
validator now reports new ones); its prompt is the same builder over that answer and its diagnostics. It never
re-decomposes the specification, never runs map-reduce and never enters the consensus remediation turn. Still
invalid -> `TopologyInvalidError` (ARCHITECT_DEFECT, HTTP 422, diagnostics in the body). A deterministic fallback plan
never passes the gate.

Ceiling per workflow run: architect invocations <= 1 + plan-approval reworks (rework_counter < 2) = 3, so topology
repair calls <= 3 x MAX_REPAIR_TURNS = 6. Each repair turn emits one `RepairEvent(source="architect",
persona="architect")`.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import stage_deadline   # STAGE-DEADLINE (gateway root module)
from gate_errors import ErrorClass, GateError

try:
    from shared.diagnostics import Diagnostic, RepairEvent, fingerprint
    from shared.service_topology import (
        ServiceTopologyIntent,
        ValidatedTopology,
        render_topology_contract,
        validate_service_topology,
    )
except ImportError:  # pragma: no cover - package-relative fallback
    from ..shared.diagnostics import Diagnostic, RepairEvent, fingerprint  # type: ignore
    from ..shared.service_topology import (  # type: ignore
        ServiceTopologyIntent,
        ValidatedTopology,
        render_topology_contract,
        validate_service_topology,
    )

logger = logging.getLogger("castor-architect-agent")

TOPOLOGY_FILE = "architect:service_topology"
MAX_CONTEXT_CHARS = 2000
MAX_REPAIR_TURNS = 2   # AC-4: turn 2 only after turn 1 fixed every finding it was told about


class TopologyInvalidError(GateError):
    """The architect's service topology is still invalid after its one bounded repair (or the plan is the
    deterministic fallback, which carries none). Typed outcome ARCHITECT_DEFECT, HTTP 422, with the diagnostics in the
    body and in `details` (RT F14) so the workflow's DLQ record and the Flight Deck carry them."""

    error_class = ErrorClass.ARCHITECT_DEFECT
    http_status = 422


@dataclass
class TopologyGateResult:
    topology: ValidatedTopology
    warnings: List[Diagnostic] = field(default_factory=list)
    draft_sha256: Optional[str] = None
    repaired: bool = False
    repair_event: Optional[RepairEvent] = None          # the last repair turn's event
    # Every turn, in order (AC-4: at most 2). A NON-final event with accepted=True means "progress: its answer became
    # the next turn's input", not "valid topology"; only the final event says how the gate ended (accepted=True on a
    # pass; accepted=False + NO_PROGRESS when it still failed, with TopologyInvalidError raised). Opus RT F2.
    repair_events: List[RepairEvent] = field(default_factory=list)

    def provenance(self) -> Dict[str, Any]:
        return {"final_sha256": self.topology.sha256, "draft_sha256": self.draft_sha256, "repaired": self.repaired,
                "warnings": [d.model_dump(mode="json") for d in self.warnings]}


def _diag_json(diags: List[Diagnostic]) -> List[Dict[str, Any]]:
    return [{"code": d.code, "path": d.block_address, "message": d.message, "hint": d.hint, "detail": d.detail}
            for d in diags]


def _raise_invalid(diags: List[Diagnostic], *, trace_id: str, product_id: str, why: str) -> None:
    errors = [d for d in diags if d.severity == "error"]
    body = [d.model_dump(mode="json") for d in errors]
    raise TopologyInvalidError(
        f"service_topology invalid ({why}): " + "; ".join(f"{d.code} {d.message}" for d in errors[:10]),
        diagnostics=body, reason="ARCHITECT_TOPOLOGY_INVALID",
        details={"trace_id": trace_id, "product_id": product_id, "diagnostics": body}, stage="architect")


def raw_topology_of(plan: Any) -> Any:
    """The topology exactly as the model returned it (kept beside the parsed plan so a malformed topology becomes
    diagnostics instead of a plan-wide parse failure), else the typed field."""
    raw = getattr(plan, "_raw_service_topology", None)
    if raw is not None:
        return raw
    typed = getattr(plan, "service_topology", None)
    return typed.model_dump(mode="json") if hasattr(typed, "model_dump") else typed


def plan_context(plan: Any) -> Dict[str, Any]:
    """The plan's own typed summary fields given to the repair (never the specification text)."""
    return {
        "product_id": getattr(plan, "product_id", None),
        "compute_archetype": getattr(plan, "compute_archetype", None),
        "target_compute_services": list(getattr(plan, "target_compute_services", None) or []),
        "bundle_id": getattr(plan, "bundle_id", None),
        "summary": str(getattr(plan, "summary", "") or "")[:MAX_CONTEXT_CHARS],
        "architecture_overview": str(getattr(plan, "architecture_overview", "") or "")[:MAX_CONTEXT_CHARS],
    }


def build_repair_prompt(previous: Any, diags: List[Diagnostic], context: Dict[str, Any],
                        current_topology: Optional[Dict[str, Any]] = None) -> str:
    """`current_topology` (RT14-06, lane-10 RT F9): the workload's last committed topology, so a repair of a
    brownfield plan keeps the deployed services' names and kinds. None (new workload) = the prompt is unchanged."""
    deployed = "" if not current_topology else (
        "--- CURRENT DEPLOYED SERVICE TOPOLOGY (last committed build of this product) ---\n"
        f"{json.dumps(current_topology, sort_keys=True, indent=1)}\n"
        "Keep every deployed service with the same name and kind unless a diagnostic is about it.\n")
    return (
        "Your previous architecture plan's `service_topology` failed deterministic validation. Return ONLY a "
        "corrected `service_topology` JSON object. Change only what the diagnostics require; keep every valid "
        "service, kind, edge and resource as it was. `primary_service`'s kind must equal the plan's "
        "`compute_archetype`.\n\n"
        f"--- PLAN SUMMARY (typed fields of your plan) ---\n{json.dumps(context, sort_keys=True, indent=1)}\n"
        f"{deployed}"
        f"--- PREVIOUS service_topology ---\n{json.dumps(previous, sort_keys=True, indent=1, default=str)}\n"
        f"--- DIAGNOSTICS ---\n{json.dumps(_diag_json(diags), sort_keys=True, indent=1)}\n--- END ---"
    )


def _attach(plan: Any, vt: ValidatedTopology) -> None:
    """The validated intent replaces whatever the plan carried (the returned architecture_plan shows it)."""
    try:
        plan.service_topology = vt.intent
    except Exception:  # noqa: BLE001 - plain objects in tests
        pass


RepairFn = Callable[[str, str], Tuple[Optional[str], str, int, int]]   # (system, prompt) -> (text, model, in, out)


def fixed_every_finding(repaired_raw: Any, before: List[str], after: List[str]) -> bool:
    """AC-4 strict progress: the repair answer is a well-formed `ServiceTopologyIntent` (so the validator ran every
    check, not only the schema) and none of the error fingerprints it was told about is still reported. Only then
    may the still-invalid answer get one more repair turn; anything else stops with the diagnostics."""
    if repaired_raw is None:
        return False
    try:
        ServiceTopologyIntent.model_validate(repaired_raw)
    except Exception:  # noqa: BLE001 - pydantic ValidationError / wrong JSON type: not progress
        return False
    return not (set(before) & set(after))


def gate_service_topology(plan: Any, *, product_id: str, trace_id: str, repair_fn: Optional[RepairFn],
                          is_fallback: bool = False,
                          current_topology: Optional[Dict[str, Any]] = None) -> TopologyGateResult:
    """Validate the plan's topology; a patch repair on failure, a second one only when the first fixed every finding
    it was told about (AC-4, `fixed_every_finding`); raise TopologyInvalidError when still invalid."""
    expected = getattr(plan, "compute_archetype", None)
    raw = raw_topology_of(plan)
    vt, diags = validate_service_topology(raw, product_id=product_id, expected_archetype=expected,
                                          file=TOPOLOGY_FILE, source="architect")
    if vt is not None:
        _attach(plan, vt)
        return TopologyGateResult(topology=vt, warnings=[d for d in diags if d.severity == "warning"],
                                  draft_sha256=vt.sha256)
    if is_fallback:
        _raise_invalid(diags, trace_id=trace_id, product_id=product_id,
                       why="the deterministic fallback plan carries no model topology")
    if repair_fn is None:
        _raise_invalid(diags, trace_id=trace_id, product_id=product_id, why="no LLM client for the repair")

    events: List[RepairEvent] = []
    cur_raw, cur_diags = raw, diags
    vt2: Optional[ValidatedTopology] = None
    diags2 = diags
    for turn in range(1, MAX_REPAIR_TURNS + 1):
        t0 = time.time()
        before = [fingerprint(d) for d in cur_diags if d.severity == "error"]
        model, tin, tout = "", 0, 0
        try:
            text, model, tin, tout = repair_fn(render_topology_contract(),
                                               build_repair_prompt(cur_raw, cur_diags, plan_context(plan),
                                                                   current_topology=current_topology))
            repaired_raw = json.loads(text) if text else None
        except stage_deadline.STOP_ERRORS:
            raise  # RT14-24: a stopped stage is never "repair failed" (which would answer ARCHITECT_DEFECT)
        except Exception as e:  # noqa: BLE001 - one bounded call; any failure keeps the previous diagnostics
            logger.error(f"Topology repair call {turn} failed for '{product_id}' ({trace_id}): {e}")
            repaired_raw = None
        vt2, diags2 = (None, cur_diags) if repaired_raw is None else validate_service_topology(
            repaired_raw, product_id=product_id, expected_archetype=expected, file=TOPOLOGY_FILE, source="architect")
        after = [fingerprint(d) for d in diags2 if d.severity == "error"]
        again = vt2 is None and turn < MAX_REPAIR_TURNS and fixed_every_finding(repaired_raw, before, after)
        events.append(RepairEvent(
            trace_id=trace_id, product_id=product_id, iteration=turn, source="architect", persona="architect",
            files=[TOPOLOGY_FILE], codes=sorted({d.code for d in cur_diags if d.severity == "error"}),
            fingerprints_before=before, fingerprints_after=after, accepted=vt2 is not None or again,
            reject_reason=None if (vt2 is not None or again) else "NO_PROGRESS", model=model or "unknown",
            tokens_in=tin, tokens_out=tout, duration_ms=int((time.time() - t0) * 1000)))
        if not again:
            break
        cur_raw, cur_diags = repaired_raw, diags2
    if vt2 is None:
        why = "still invalid after one repair" if len(events) == 1 else \
            f"still invalid after {len(events)} repairs (the first fixed every finding it was told about)"
        try:
            _raise_invalid(diags2, trace_id=trace_id, product_id=product_id, why=why)
        except TopologyInvalidError as e:
            e.details["repair_event"] = events[-1].model_dump(mode="json")
            if len(events) > 1:
                e.details["repair_events"] = [ev.model_dump(mode="json") for ev in events]
            raise
    _attach(plan, vt2)
    return TopologyGateResult(topology=vt2, warnings=[d for d in diags2 if d.severity == "warning"],
                              draft_sha256=None, repaired=True, repair_event=events[-1], repair_events=events)
