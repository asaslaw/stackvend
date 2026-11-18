"""
Project Castor: Dual-Lens QA Auditor Coordinator
Dispatches Lens A (Security & Ingress) and Lens B (Task DAG Adherence) in parallel under ONE shared
deadline and composes the Stage 2 verdict.

FD-4F (DL-1..DL-3):
- The deadline is real: the executor is shut down with wait=False/cancel_futures, so a slow lens no longer
  blocks past the timeout (the old `with ThreadPoolExecutor` waited in __exit__).
- A lens that errors or times out raises LensUnavailableError (-> GATE_UNAVAILABLE). No heuristic substitute.
- A missing deterministic report raises; a passing report is never fabricated.
"""

import concurrent.futures
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import stage_deadline  # STAGE-DEADLINE (RT F1): the lens threads carry the QA stage's deadline and probe

from shared.qa_audit_schemas import (
    AdherenceLensResult,
    CompositeAuditReport,
    DeterministicGateReport,
    SecurityLensResult,
)

from .adherence_lens import ADHERENCE_THRESHOLD, evaluate_adherence_lens
from .lens_common import LensUnavailableError
from .platform_facts import PlatformFacts
from .platform_satisfied import summary_note
from .security_lens import evaluate_security_lens

logger = logging.getLogger("castor-qa-coordinator")

# QA-JUDGE-RETRY (owner 10-27): 60 s -> 300 s, so one slow judge call (JUDGE_TIMEOUT_S = 120 s) plus a typed retry fit.
# JUDGE-FALLBACK-FLASH-ROOM (owner 11-16): each judge call is time-boxed within this limit (judge.attempt_timeout_s); at
# 300 s, with every failure at its whole box: evaluation model 120 s, first fallback 87 s, second fallback 88 s.
# run_qa passes min(STAGE_TWO_DEADLINE_S, remaining request budget - margin).
STAGE_TWO_DEADLINE_S = 300.0


def score_advisory(adh_result: Any) -> str:
    """JUDGE-GATE-ENUMERATED-FINDINGS: the adherence lens's scores below the reporting threshold, as one informational
    sentence for the QA summary (never a blocking reason); "" when both are at or above it."""
    adh, gnd = adh_result.instruction_adherence_score, adh_result.grounding_score
    if adh >= ADHERENCE_THRESHOLD and gnd >= ADHERENCE_THRESHOLD:
        return ""
    return (f"Adherence score {adh:.2f}, grounding score {gnd:.2f} (below {ADHERENCE_THRESHOLD:.2f}): informational, "
            f"not a blocking reason; only listed findings block.")


def _with_fallback_note(summary: str, sec_result: Any, adh_result: Any) -> str:
    """QA-JUDGE-FALLBACK RT F2: a verdict a fallback model gave is named in the composite summary (the text the QA
    summary, the plan sign-off, the callback outputs and the Control Center carry; the composite dump keeps only the
    base lens fields). The release certificate names it from the stored lens records
    (release_gatekeeper._fallback_judge_note, RT D1). Typed fields only (`eval_judge_fallback` exactly True). No
    fallback: the summary is returned unchanged."""
    fb = [f"{name} by {r.eval_judge_model} ({r.eval_judge_primary_model} unavailable: "
          f"{', '.join(r.eval_judge_fallback_outcomes)})"
          for name, r in (("security lens", sec_result), ("adherence lens", adh_result))
          if getattr(r, "eval_judge_fallback", False) is True]
    return f"{summary} Reviewed by a fallback model: {'; '.join(fb)}." if fb else summary


class DualLensAuditorCoordinator:
    """Coordinates concurrent execution of the Dual-Lens QA Audit panel."""

    def __init__(self, timeout_seconds: float = STAGE_TWO_DEADLINE_S):
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _coerce_determ(determ_report: Any) -> DeterministicGateReport:
        if isinstance(determ_report, DeterministicGateReport):
            return determ_report
        if isinstance(determ_report, dict):
            return DeterministicGateReport(**determ_report)
        raise LensUnavailableError("Stage 2 requires the deterministic gate report; none was supplied")

    def evaluate_stage_two(
        self,
        git_diff: str,
        determ_report: Any = None,
        task_dag: Optional[List[Dict[str, Any]]] = None,
        pytest_logs: Optional[str] = None,
        ingress_policy: Optional[Dict[str, Any]] = None,
        compliance_frameworks: Optional[List[str]] = None,
        compliance_summary: Optional[str] = None,
        model_name: Optional[str] = None,
        db_client: Any = None,
        file_inventory: Optional[str] = None,
        *,
        platform_facts: PlatformFacts,
        base_branch: str = "main",
    ) -> Tuple[SecurityLensResult, AdherenceLensResult, CompositeAuditReport]:
        """Returns (security_result, adherence_result, composite_report). Raises LensUnavailableError.
        `platform_facts` (SECURITY-LENS-PLATFORM-FACTS, required): the run's one facts object; the SAME object goes to
        every lens (each renders it with PlatformFacts.section and decides its advisories from its typed `handled`).
        Anything else is refused before a judge runs (no lens is ever judged without the platform's facts)."""
        if not isinstance(platform_facts, PlatformFacts):
            raise LensUnavailableError(
                f"Stage 2 refused: no platform facts object (got {type(platform_facts).__name__}); every lens needs it")
        determ_gate = self._coerce_determ(determ_report)
        policy = ingress_policy or {}
        tasks = task_dag or []

        deadline = time.monotonic() + self.timeout_seconds
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="qa-lens")
        try:
            # RT F1: a plain pool does not carry context variables; bind_context gives each lens the stage deadline,
            # so the judge's checkpoint sees an ended run / emergency stop / supersede / deadline (no-op without one).
            sec_future = executor.submit(
                stage_deadline.bind_context(evaluate_security_lens),
                git_diff=git_diff,
                ingress_policy=policy,
                compliance_frameworks=compliance_frameworks,
                model_name=model_name,
                db_client=db_client,
                deadline=deadline,
                file_inventory=file_inventory,
                platform_facts=platform_facts,
                base_branch=base_branch,   # RT14-28: the FILES rules name the workload's base branch
            )
            adh_future = executor.submit(
                stage_deadline.bind_context(evaluate_adherence_lens),
                git_diff=git_diff,
                task_dag=tasks,
                pytest_logs=pytest_logs,
                compliance_summary=compliance_summary,
                model_name=model_name,
                db_client=db_client,
                deadline=deadline,
                file_inventory=file_inventory,
                platform_facts=platform_facts,
                base_branch=base_branch,
            )
            sec_result = self._result(sec_future, deadline, "security lens")
            adh_result = self._result(adh_future, deadline, "adherence lens")
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        # JUDGE-GATE-ENUMERATED-FINDINGS (owner 11-13): a judge blocks only through enumerated findings (one per
        # critical vulnerability, one per missed directive). A failed lens verdict that lists none is no verdict
        # (LensUnavailableError -> GATE_UNAVAILABLE): never a pass and never a block without an actionable finding.
        if not sec_result.passed and not sec_result.critical_vulnerabilities:
            raise LensUnavailableError("security lens: failed verdict with no enumerated critical vulnerability")
        if not adh_result.passed and not adh_result.missed_directives:
            raise LensUnavailableError("adherence lens: failed verdict with no enumerated missed directive")

        blocking_reasons: List[str] = []
        if not determ_gate.passed:
            blocking_reasons.extend(determ_gate.bandit_issues)
            blocking_reasons.extend(determ_gate.hcl_errors)
            blocking_reasons.extend(determ_gate.zero_dockerfile_violations)
            blocking_reasons.extend(determ_gate.ast_syntax_errors)
            if not blocking_reasons:
                blocking_reasons.append(f"Deterministic gate failed: {determ_gate.summary}")
        blocking_reasons.extend(f"Security: {v}" for v in sec_result.critical_vulnerabilities)
        blocking_reasons.extend(f"Missed Directive: {m}" for m in adh_result.missed_directives)

        composite_passed = determ_gate.passed and sec_result.passed and adh_result.passed and not blocking_reasons

        overall_soundness = round(
            min(1.0, (1.0 if sec_result.passed else 0.5) * adh_result.instruction_adherence_score),
            2,
        )
        if composite_passed:
            summary = (
                f"Unified QA Verification Succeeded: Deterministic barrier passed, "
                f"Security clean (0 critical), Task DAG Adherence at {adh_result.instruction_adherence_score * 100:.1f}%."
            )
        else:
            summary = (
                f"Unified QA Verification Failed: {len(blocking_reasons)} blocking defects. "
                f"Issues: {'; '.join(blocking_reasons[:3])}"
            )

        note = score_advisory(adh_result)
        if note:
            summary = f"{summary} {note}"

        # ADHERENCE-PLATFORM-SATISFIED / SECURITY-LENS-PLATFORM-FACTS: findings the platform handles, from every lens,
        # stay visible in the summary (invariant 8).
        handled_entries = [e.model_dump() for res in (adh_result, sec_result)
                           for key in ("platform_satisfied_directives", "platform_limitation_advisories")
                           for e in (getattr(res, key, None) or [])]
        note = summary_note(dict(platform_facts.handled), handled_entries)
        if note:
            summary = f"{summary} {note}"
        summary = _with_fallback_note(summary, sec_result, adh_result)

        composite_report = CompositeAuditReport(
            passed=composite_passed,
            deterministic_gate=determ_gate,
            security_lens=sec_result,
            adherence_lens=adh_result,
            overall_soundness_score=overall_soundness,
            blocking_reasons=blocking_reasons,
            summary=summary,
            executed_at=datetime.now(timezone.utc).isoformat(),
        )
        return sec_result, adh_result, composite_report

    @staticmethod
    def _result(future: "concurrent.futures.Future", deadline: float, name: str) -> Any:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            return future.result(timeout=remaining)
        except concurrent.futures.TimeoutError as e:
            future.cancel()
            raise LensUnavailableError(f"{name} exceeded the Stage 2 deadline") from e
        except (LensUnavailableError, *stage_deadline.STOP_ERRORS):
            raise   # RT F1: a stage stop stays a stop (never a lens outage)
        except Exception as e:
            raise LensUnavailableError(f"{name} failed: {type(e).__name__}: {e}") from e
