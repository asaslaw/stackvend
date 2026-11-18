"""Dry-run verdict for one harness run (FD-4BN Phase 0, plan `test-workload-dry-run-plan.md` §12.2). Pure: no I/O.

`verdict(row, result)` where `row` is `metrics.run_row(rec)` (the scoreboard's own per-run fields, never re-derived
here) and `result` is the run's result.json. Rules, first match wins:

1. pipeline_outcome == canary_only                 -> INCONCLUSIVE:canary_only
2. not row["valid"]                                -> INCONCLUSIVE:<first invalid reason> (isolation_guard_ineffective
                                                      -> isolation, fallback_tripwire -> llm_fallback, others verbatim)
3. any call served by replay_fallback, or         -> INCONCLUSIVE:replay_diverged (the run measured another request's
   spec_match is False                                recorded output; fallback sites in the reason; RT fix 3)
4. developer_failed_typed                          -> WOULD_FAIL_AT:developer (error class + diagnostic codes)
5. generation_error                                -> WOULD_FAIL_AT:<first of architect|compliance|developer not ok>
6. precommit_rejected / gatekeeper_rejected        -> WOULD_FAIL_AT:precommit / WOULD_FAIL_AT:gatekeeper
7. committed_passed and C3 tofu validate True      -> WOULD_SUCCEED ("through validation", never "will deploy")
                      C3 tofu validate False       -> WOULD_FAIL_AT:deploy, gate_false_pass=True
                      C3 tofu validate None        -> INCONCLUSIVE:validator_unavailable
8. anything else                                   -> INCONCLUSIVE:unknown_outcome:<outcome>

Invariant violations and expected (blocked and swallowed) isolation attempts are returned as `warnings`; they never
change the verdict. Replay divergence is also listed as a warning, and it does change the verdict (rule 3).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

WOULD_SUCCEED = "WOULD_SUCCEED"
WOULD_FAIL_AT = "WOULD_FAIL_AT:"
INCONCLUSIVE = "INCONCLUSIVE:"

# Invalid-run reasons shown under a shorter, operator-facing name; every other reason passes through verbatim.
REASON_ALIASES = {"isolation_guard_ineffective": "isolation", "fallback_tripwire": "llm_fallback"}
GENERATION_STAGES = ("architect", "compliance", "developer")
REASON_MAX = 300


def _trunc(text: Any, limit: int = REASON_MAX) -> str:
    s = "" if text is None else str(text)
    return s if len(s) <= limit else s[:limit] + "..."


def _warnings(row: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    if row.get("invariant_violations"):
        out.append(f"invariant violations: {row['invariant_violations']} "
                   f"(I6 cycles {row.get('I6_cycles', 0)}, I3 literals {row.get('I3_literals', 0)})")
    if row.get("golden_module_mutations"):
        out.append(f"golden module mutations in the committed tree: {row['golden_module_mutations']}")
    if row.get("isolation_attempts"):
        out.append(f"isolation attempts blocked (expected product paths, swallowed): {row['isolation_attempts']}")
    if row.get("c3_column_agreement") is False:
        out.append("tofu validate columns disagree (production vs oracle)")
    served = row.get("served") or {}
    if served.get("replay_fallback"):
        out.append(f"replay served {served['replay_fallback']} call(s) by site/ordinal fallback (request diverged)")
    if row.get("spec_match") is False:
        out.append("spec differs from the recorded spec")
    return out


def _typed_reason(row: Dict[str, Any], result: Dict[str, Any]) -> str:
    typed = (result.get("hallucination_stack") or {}).get("developer_failed_typed") or {}
    ec = typed.get("error_class") or row.get("developer_failed_typed") or "UNTYPED"
    codes = typed.get("codes") if typed.get("codes") is not None else (row.get("typed_failure_codes") or [])
    return _trunc(f"{ec}: {', '.join(str(c) for c in codes if c) or 'no codes'}")


def _first_failed_stage(result: Dict[str, Any]) -> Optional[str]:
    stages = result.get("stages") or {}
    for name in GENERATION_STAGES:
        if (stages.get(name) or {}).get("ok") is not True:
            return name
    return None


def verdict(row: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    """{"verdict", "stage", "reason", "warnings", "gate_false_pass"} for one run."""
    warnings = _warnings(row)

    def out(v: str, stage: Optional[str], reason: str, gate_false_pass: bool = False) -> Dict[str, Any]:
        return {"verdict": v, "stage": stage, "reason": reason, "warnings": warnings,
                "gate_false_pass": gate_false_pass}

    outcome = row.get("outcome")
    if result.get("pipeline_outcome") == "canary_only":
        return out(INCONCLUSIVE + "canary_only", None, "canary only: the pipeline was not run")
    if not row.get("valid"):
        reasons = list(row.get("invalid_reasons") or [])
        first = reasons[0] if reasons else "invalid_run"
        return out(INCONCLUSIVE + REASON_ALIASES.get(first, first), None,
                   _trunc("invalid run: " + (", ".join(reasons) or "no reason recorded")))
    fallback = int((row.get("served") or {}).get("replay_fallback") or 0)
    if fallback or row.get("spec_match") is False:
        why = []
        if fallback:
            sites = row.get("served_not_exact_sites") or {}
            listed = ", ".join(str(k) + " x" + str(n) for k, n in sorted(sites.items()))
            why.append(str(fallback) + " call(s) served by site/ordinal fallback"
                       + ("; sites not served exactly: " + listed if listed else ""))
        if row.get("spec_match") is False:
            why.append("spec differs from the recorded spec")
        return out(INCONCLUSIVE + "replay_diverged", None, _trunc("replay diverged: " + "; ".join(why)))
    if outcome == "developer_failed_typed":
        return out(WOULD_FAIL_AT + "developer", "developer", _typed_reason(row, result))
    if outcome == "generation_error":
        stage = _first_failed_stage(result)
        if stage is None:  # all three generation stages ok: the failure came from the pre-commit call itself
            pre = (result.get("stages") or {}).get("precommit") or {}
            return out(WOULD_FAIL_AT + "precommit", "precommit",
                       _trunc(pre.get("error") or pre.get("note") or "generation error after the developer stage"))
        err = ((result.get("stages") or {}).get(stage) or {}).get("error") or "stage did not complete"
        return out(WOULD_FAIL_AT + stage, stage, _trunc(err))
    if outcome == "precommit_rejected":
        pre = (result.get("stages") or {}).get("precommit") or {}
        return out(WOULD_FAIL_AT + "precommit", "precommit", _trunc(pre.get("error") or "pre-commit gate rejected"))
    if outcome == "gatekeeper_rejected":
        gk = (result.get("stages") or {}).get("gatekeeper_4_5") or {}
        errs = gk.get("errors") or []
        return out(WOULD_FAIL_AT + "gatekeeper", "gatekeeper",
                   _trunc(errs[0] if errs else (gk.get("error") or "gatekeeper rejected")))
    if outcome == "committed_passed":
        ok = row.get("c3_validate_ok")
        if ok is True:
            return out(WOULD_SUCCEED, None, "through validation")
        if ok is False:
            diags = row.get("c3_diag_summaries") or []
            first = next((d for d in diags if d), "tofu validate failed")
            return out(WOULD_FAIL_AT + "deploy", "deploy",
                       _trunc("gate false-pass: committed tree fails tofu validate: " + first), gate_false_pass=True)
        return out(INCONCLUSIVE + "validator_unavailable", None,
                   _trunc("committed, but tofu validate did not run (status: "
                          + str(row.get("c3_tofu_status") or "not scored") + ")"))
    return out(INCONCLUSIVE + "unknown_outcome:" + str(outcome), None, _trunc("unrecognised outcome " + str(outcome)))


def tally(verdicts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """"k/N would succeed" plus counts per verdict (for the N-run matrix)."""
    counts: Dict[str, int] = {}
    for v in verdicts:
        counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
    k = counts.get(WOULD_SUCCEED, 0)
    return {"would_succeed": k, "runs": len(verdicts), "counts": dict(sorted(counts.items()))}
