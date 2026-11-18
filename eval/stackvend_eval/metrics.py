"""Aggregate per-run results + scores into summary.json (plan §5.2; red-team H3, L2).

Validity metrics are always named by checkpoint:
  C0 raw LLM files (parse rates only) | C1 healers-off (first-pass, replay) | C2 generate_code_files return |
  C3 committed tree (what production would push).
`validate_rate_unconditional`: denominator = valid runs; a run passes only if pipeline_outcome == committed_passed
AND C3 passes tofu validate (pre-commit/gatekeeper rejection = fail). `validate_rate_conditional`: among valid runs
that produced a C3 tree.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .llm_proxy import SERVED_KINDS
from .stats import rate

GATEWAY = "apps/orchestrator-gateway/"


def _ck(score: Optional[Dict[str, Any]], name: str) -> Dict[str, Any]:
    return ((score or {}).get("checkpoints") or {}).get(name) or {}


def served_counts(result: Dict[str, Any]) -> Dict[str, int]:
    """F9: per-run served counts (exact replay / site-ordinal fallback / miss / backend), from result.json's llm."""
    llm = result.get("llm") or {}
    served = llm.get("served") or {}
    out = {k: int(served.get(k) or 0) for k in SERVED_KINDS}
    if "replay_miss" not in served:  # results written before F9: a miss is a call with served unset
        out["replay_miss"] = sum(1 for c in (llm.get("per_call") or []) if c.get("served") is None)
    return out


def _site_label(site: str) -> str:
    return site.rsplit(":", 1)[-1]


def fallback_sites(result: Dict[str, Any]) -> Dict[str, int]:
    """Sites (qualname) whose calls were not exact replays, with counts: where a replay diverged."""
    out: Dict[str, int] = defaultdict(int)
    for c in ((result.get("llm") or {}).get("per_call") or []):
        if c.get("served") in ("replay_fallback", None):
            out[_site_label(str(c.get("site")))] += 1
    return dict(sorted(out.items()))


# ------------------------------------------------------------------------------------ TI-0 typed-IaC measurements
# Author of a repair persona's draft (exact table). IAC_ENGINEER writes the IaC; "developer" is the single-turn
# generator, which writes both; every other swarm persona writes application code / config.
IAC_PERSONAS = frozenset({"IAC_ENGINEER"})
MIXED_PERSONAS = frozenset({"developer"})


def persona_author(persona: Any) -> str:
    p = str(persona)
    return "iac" if p in IAC_PERSONAS else ("mixed" if p in MIXED_PERSONAS else "app")


def _repair_events(r: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [e for e in ((r.get("hallucination_stack") or {}).get("repair_events") or [])
            if isinstance(e, dict) and e.get("kind", "repair") == "repair"]


def first_draft_codes(r: Dict[str, Any]) -> Dict[str, List[str]]:
    """Codes of the first-draft diagnostics the product sent in its iteration-1 repair prompts, by author of the
    draft (persona_author). Platform-owned diagnostics are never sent to a persona: they show only as end codes."""
    out: Dict[str, set] = {"iac": set(), "app": set(), "mixed": set()}
    for e in _repair_events(r):
        if e.get("iteration") == 1:
            out[persona_author(e.get("persona"))] |= {str(c) for c in (e.get("codes") or [])}
    return {k: sorted(v) for k, v in out.items()}


def repair_calls_by_persona(r: Dict[str, Any]) -> Tuple[Dict[str, int], str]:
    """{persona: repair calls}. Source "observer": every SwarmDispatcher.invoke_repair call (run_child observer);
    "repair_events" (results written before TI-0): one per recorded repair event, which misses calls whose event the
    product did not record (10-14: 74 events for 81 invoke_repair LLM calls)."""
    obs = (r.get("repair_calls") or {}).get("by_persona")
    if isinstance(obs, dict):
        return {str(k): int((v or {}).get("calls") or 0) for k, v in sorted(obs.items())}, "observer"
    out: Dict[str, int] = defaultdict(int)
    for e in _repair_events(r):
        out[str(e.get("persona"))] += 1
    return dict(sorted(out.items())), "repair_events"


def platform_blocks_in_ai_files(r: Dict[str, Any]) -> Optional[List[str]]:
    """Platform blocks placed inside the AI's IaC files (the two-author collision TI-1 removes), from records only:
    the last AssemblyRecord's PLATFORM_RESYNTHESIZED entries (HB-04 replaced an AI block in place, "<draft path>:<key>")
    plus every HB-04 `append_text` of a synthesized module into the AI's custom.tf (run_child observer,
    "<path>:module.<label>", deduplicated over repair iterations). None when the run has no AssemblyRecord or was
    recorded before the observer existed (then the appended half is unknown)."""
    hs = r.get("hallucination_stack") or {}
    rec = hs.get("assembly_record")
    appends = (r.get("hb04_appends") or {}).get("appends")
    if not isinstance(rec, dict) or appends is None:
        return None
    out = {f"{(rec.get('replaced_from') or {}).get(k, '?')}:{k}"
           for k, why in (rec.get("replaced_reason") or {}).items() if why == "PLATFORM_RESYNTHESIZED"}
    out |= {f"{a.get('path')}:{a.get('address') or '<unparsed append>'}" for a in appends if isinstance(a, dict)}
    return sorted(out)


def consensus_changed_topology(r: Dict[str, Any]) -> Optional[bool]:
    """True when the dual-architect consensus returned a plan whose topology sha differs from the draft's; None when
    consensus did not run (off, or a result written before TI-0)."""
    calls = ((r.get("architect_consensus") or {}).get("invocations"))
    if not calls:
        return None
    vals = [c.get("changed") for c in calls]
    if any(v is True for v in vals):
        return True
    return None if all(v is None for v in vals) else False


def typed_outcome(row: Dict[str, Any]) -> Optional[str]:
    """committed_passed, or the ErrorClass of a typed failure (developer or architect stage), else None."""
    if row.get("outcome") == "committed_passed":
        return "committed_passed"
    return row.get("developer_failed_typed") or row.get("architect_failed_typed")


def synthetic_expectation(row: Dict[str, Any], expected: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """TI-0 synthetic specs (integration §6.2): a valid run meets its expectation when its typed outcome is one of
    `expected.accept`; a typed failure's codes lie within `expected.codes_within` (when given); every row field in
    `expected.zero` is 0 / empty (e.g. I6_cycles); and, for a brownfield rerun (`no_compute_dropped`), no compute
    service of the base run was dropped."""
    if not expected:
        return None
    got = typed_outcome(row)
    met = bool(row.get("valid")) and got in (expected.get("accept") or [])
    why = [] if met else [f"outcome {got} not in {list(expected.get('accept') or [])}"]
    within = expected.get("codes_within")
    if met and got != "committed_passed" and within is not None:
        extra = sorted(set(row.get("typed_failure_codes") or []) - set(within))
        if extra:
            met, why = False, why + [f"codes outside the expected set: {extra}"]
    for f in expected.get("zero") or []:
        if row.get(f):
            met, why = False, why + [f"{f} = {row.get(f)}"]
    if got == "committed_passed":
        # S6 (RT F4): a committed tree is scored independently of the product's own gate (exact tables, C3)
        bad_types = sorted(set(row.get("resource_types") or []) & set(expected.get("forbid_types") or []))
        if bad_types:
            met, why = False, why + [f"forbidden resource types committed: {bad_types}"]
        if expected.get("require_c3_policy_scan") and row.get("c3_policy_unparsed") is None:
            met, why = False, why + ["committed tree not policy-scanned"]
    if expected.get("no_compute_dropped") and got == "committed_passed":
        dropped = row.get("compute_dropped_on_rerun")
        if dropped is None:   # RT F5: never vacuous
            met, why = False, why + ["compute set unknown (base or rerun compute intent not recorded)"]
        elif dropped:
            met, why = False, why + [f"compute dropped on rerun: {dropped}"]
    return {"accept": list(expected.get("accept") or []), "got": got, "met": met, "why_not": why}


def compute_service_names(r: Dict[str, Any]) -> Optional[List[str]]:
    """The run's compute service names from its recorded compute intent: `service_kinds` keys when the typed topology
    wrote them, else `service_names` (always written by ComputeIntent.as_record); None when neither is recorded."""
    ci = (r.get("hallucination_stack") or {}).get("compute_intent") or {}
    if isinstance(ci.get("service_kinds"), dict):
        return sorted(ci["service_kinds"])
    if isinstance(ci.get("service_names"), list):
        return sorted(str(x) for x in ci["service_names"])
    return None


def compute_dropped_on_rerun(r: Dict[str, Any]) -> Optional[List[str]]:
    """S7: compute services of the base run absent from a committed rerun's compute intent (must be []). None when
    the run is not a committed rerun, or when either compute set is unknown (synthetic_expectation then fails closed)."""
    bf = r.get("brownfield") or {}
    if "base_compute" not in bf or r.get("pipeline_outcome") != "committed_passed":
        return None
    base, now = bf.get("base_compute"), compute_service_names(r)
    if base is None or now is None:
        return None
    return sorted(set(base) - set(now))


def run_row(rec: Dict[str, Any]) -> Dict[str, Any]:
    row = _run_row(rec)
    r, s = rec["result"], rec.get("score") or {}
    ti = s.get("typed_iac") or {}
    by_persona, source = repair_calls_by_persona(r)
    split = ti.get("healer_fvv_split")
    if split is None and s.get("healer_classification") is not None:   # score.json written before TI-0
        from .scoring import healer_fvv_split
        split = healer_fvv_split((r.get("healers") or {}).get("events") or [], s.get("healer_classification") or {})
    fd = ti.get("first_draft") if isinstance(ti.get("first_draft"), dict) else {}
    cp = ti.get("c3_policy") if isinstance(ti.get("c3_policy"), dict) and "unparsed" in ti["c3_policy"] else None
    row.update({
        # independent policy scan of the committed root module (scoring.c3_policy_scan); None = not scanned
        "c3_public_members": (cp or {}).get("public_members"), "c3_owner_grants": (cp or {}).get("owner_grants"),
        "c3_policy_unparsed": (cp or {}).get("unparsed"),
        "first_draft_codes": first_draft_codes(r),
        "repair_calls_by_persona": by_persona, "repair_calls_source": source,
        "platform_blocks_in_ai_files": platform_blocks_in_ai_files(r),
        "ai_iac_paths": ti.get("ai_iac_paths"),
        # TI-2 expressibility inputs from the IaC persona's own first draft (scoring.iac_first_draft)
        "first_draft_types": fd.get("types"), "data_sources_used": fd.get("data_sources"),
        "functions_used": fd.get("functions"), "first_draft_source": fd.get("source"),
        "healer_fvv_split": split,
        "consensus_changed_topology": consensus_changed_topology(r),
        "consensus_status": ((r.get("stages") or {}).get("architect") or {}).get("consensus_status"),
        "architect_failed_typed": (r.get("architect_failed_typed") or {}).get("error_class"),
        "compute_dropped_on_rerun": compute_dropped_on_rerun(r),
    })
    row["synthetic_expectation"] = synthetic_expectation(row, rec.get("expected_outcome"))
    return row


def _run_row(rec: Dict[str, Any]) -> Dict[str, Any]:
    r, s = rec["result"], rec.get("score")
    c3 = _ck(s, "C3_committed")
    c2 = _ck(s, "C2_generated")
    c1 = _ck(s, "C1_healers_off")
    t3 = c3.get("tofu") or {}
    llm = r.get("llm") or {}
    inv = c3.get("invariants") or {}
    hcl = c3.get("hcl") or {}
    py = c3.get("python") or {}
    fires = (s or {}).get("healer_fires") or {}
    return {
        "key": rec["key"], "example": r.get("example"), "run": r.get("run"), "valid": bool(r.get("valid_run")),
        "invalid_reasons": r.get("invalid_reasons") or [], "outcome": r.get("pipeline_outcome"),
        "developer_path": ((r.get("stages") or {}).get("developer") or {}).get("path"),
        "c3_present": bool(c3), "c3_tree": ((r.get("checkpoints") or {}).get("C3_committed") or {}).get("tree"),
        "c3_validate_ok": t3.get("validate_ok"), "c3_tofu_status": t3.get("status"),
        "c3_plan_ok": (t3.get("plan") or {}).get("plan_ok"),
        "c3_diag_count": len(t3.get("diagnostics") or []),
        "c2_validate_ok": (c2.get("tofu") or {}).get("validate_ok"),
        "c3_oracle_validate_ok": (c3.get("tofu_oracle") or {}).get("validate_ok"),
        # S1-0 (R1/R1b/R2): assembly preservation, golden-module mutations, typed developer failures
        "assembly_dropped_unreplaced": ((s or {}).get("assembly") or {}).get("dropped_unreplaced"),
        "assembly_repair_removals_justified": ((s or {}).get("assembly") or {}).get("repair_removals_justified") or {},
        "assembly_dropped_non_preserved": ((s or {}).get("assembly") or {}).get("dropped_non_preserved") or [],
        "assembly_replaced_by_reason": ((s or {}).get("assembly") or {}).get("replaced_by_reason"),
        "assembly_blocks_not_verbatim": len(((s or {}).get("assembly") or {}).get("blocks_not_verbatim") or []),
        "golden_module_mutations": ((s or {}).get("assembly") or {}).get("golden_module_mutations_c3"),
        "developer_failed_typed": ((r.get("hallucination_stack") or {}).get("developer_failed_typed") or {}).get(
            "error_class"),
        "typed_failure_codes": ((r.get("hallucination_stack") or {}).get("developer_failed_typed") or {}).get("codes"),
        "report_only_codes": sorted({d.get("code") for d in (((r.get("hallucination_stack") or {}).get(
            "validation_report") or {}).get("report_only") or [])}),
        "repair_events": sum(1 for e in ((r.get("hallucination_stack") or {}).get("repair_events") or [])
                             if (e or {}).get("kind", "repair") != "junior_reask"),
        # code RT F4: swarm junior typed JSON re-asks (HS-61), recorded beside the repair events, never in the budget
        "junior_reasks": sum(1 for e in ((r.get("hallucination_stack") or {}).get("repair_events") or [])
                             if (e or {}).get("kind") == "junior_reask"),
        "envelope_checks": len((r.get("hallucination_stack") or {}).get("envelope_checks") or []),
        "envelope_ok": sum(1 for c in ((r.get("hallucination_stack") or {}).get("envelope_checks") or [])
                           if c.get("ok")),
        "validation_status": ((r.get("hallucination_stack") or {}).get("validation_report") or {}).get("status"),
        "validation_error_codes": sorted({d.get("code") for d in (((r.get("hallucination_stack") or {}).get(
            "validation_report") or {}).get("diagnostics") or []) if d.get("severity") == "error"}),
        "c3_column_agreement": c3.get("column_agreement"),
        "c3_diag_summaries": sorted({d.get("summary") or "" for d in (t3.get("diagnostics") or [])}),
        "c1_validate_ok": (c1.get("tofu") or {}).get("validate_ok"),
        "tf_files": hcl.get("tf_files", 0), "hcl_parse_ok": hcl.get("hcl_parse_ok", 0),
        "py_files": py.get("py_files", 0), "py_ast_ok": py.get("ast_ok", 0),
        "py_files_undefined_names": py.get("files_with_undefined_names", 0),
        "invariant_violations": inv.get("violations"), "I6_cycles": len(inv.get("I6_service_uri_cycles") or []),
        "I3_literals": len(inv.get("I3_literals") or []), "resource_types": inv.get("workload_resource_types"),
        "fires": sum(v["fires"] for v in fires.values()),
        "fires_on_validate_valid": sum(v["fires_on_validate_valid"] for v in fires.values()),
        "fires_on_syntax_valid": sum(v["fires_on_syntax_valid"] for v in fires.values()),
        "fires_validate_unknown": sum(v["fires_validate_unknown"] for v in fires.values()),
        "llm_calls": llm.get("calls", 0), "usd": llm.get("usd", 0.0), "tokens": llm.get("tokens"),
        "truncations": llm.get("max_tokens_truncations", 0),
        "replay_diverged": bool(((r.get("state") or {}).get("flags") or {}).get("replay_diverged")),
        "served": served_counts(r) if r.get("llm") else None,
        "served_not_exact_sites": fallback_sites(r),
        "spec_source": (r.get("spec_provenance") or {}).get("source"),
        "spec_sha256": (r.get("spec_provenance") or {}).get("spec_sha256"),
        "spec_match": (r.get("spec_provenance") or {}).get("match"),
        "wall_s": round((r.get("finished") or 0) - (r.get("started") or 0), 1),
        # S2-0 (Step 2 plan §2.1, §4 G0/M1): per-branch self_correct_hcl fires, single-turn calls, harness stops
        "self_correct_calls": (r.get("self_correct_branches") or {}).get("calls", 0),
        "self_correct_branch_fires": {f"{b['id']}|{b['marker']}": b.get("calls_fired", 0)
                                      for b in ((r.get("self_correct_branches") or {}).get("branches") or [])
                                      if b.get("index", -1) >= 0},
        "single_turn_calls": sum(1 for c in (llm.get("per_call") or [])
                                 if str(c.get("site") or "").endswith("DeveloperAgent.generate_code_files")),
        "harness_budget_stop": sorted(set(r.get("invalid_reasons") or []) & HARNESS_BUDGET_STOPS),
        "isolation_attempts": sum(1 for e in ((r.get("state") or {}).get("events") or [])
                                  if e.get("stage") not in ("canary", "guard")
                                  and e.get("kind") in ("egress_blocked", "grpc_blocked", "client_blocked",
                                                        "process_blocked")),
    }


def _count_codes(rows: List[Dict[str, Any]], field: str) -> Dict[str, int]:
    out: Dict[str, int] = defaultdict(int)
    for r in rows:
        for c in r.get(field) or []:
            out[c] += 1
    return dict(out)


HARNESS_BUDGET_STOPS = frozenset({"not_run_budget", "budget_exceeded"})


def _sum_branch_fires(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    """Calls in which each self_correct_hcl branch changed the tree, summed over runs (S2-0 branch probe)."""
    out: Dict[str, int] = defaultdict(int)
    for r in rows:
        for k, v in (r.get("self_correct_branch_fires") or {}).items():
            out[k] += v
    return dict(sorted(out.items()))


def _branch_fire_runs(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = defaultdict(int)
    for r in rows:
        for k, v in (r.get("self_correct_branch_fires") or {}).items():
            out[k] += 1 if v else 0
    return dict(sorted(out.items()))


def _sum_reasons(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = defaultdict(int)
    for r in rows:
        for why, keys in (r.get("assembly_replaced_by_reason") or {}).items():
            out[why] += len(keys)
    return dict(sorted(out.items()))


def coverage(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Probe coverage over generation-path inventory rows (H2)."""
    targets: Dict[str, Dict[str, Any]] = {}
    for rec in results:
        for t in ((rec["result"].get("healers") or {}).get("targets") or []):
            targets.setdefault(t["key"], dict(t))
    gen = [t for t in targets.values() if (t.get("file") or "").startswith(GATEWAY)
           and t.get("kind") in ("function", "inline", "unresolved")]
    measured = [t for t in gen if (t["kind"] == "function" and (t.get("bindings") or 0) > 0)
                or (t["kind"] == "inline" and t.get("status") == "anchored")]
    # FD-55 W0 / FD-4CR: the denominator is the LIVE fragments. A retired fragment is one listed in the reviewed
    # eval/config/healer_deletions.json (with the commit that deleted it) whose code is actually gone from the
    # measured product root (targets.anchor_to sets `deleted_by`): it cannot be probed and is not a gap. Everything
    # else stays in the denominator: an absent or anchor_lost fragment that is NOT listed counts as unmeasured (an
    # unrecorded deletion lowers coverage and fails the exact pins in tests/test_eval_e2e.py; before W0 an unlisted
    # absent fragment silently left the denominator).
    absent_status = ("absent", "absent_file", "absent_module")
    retired = [t for t in gen if t.get("deleted_by") and t.get("status") in absent_status]
    retired_keys = {t["key"] for t in retired}
    live = [t for t in gen if t["key"] not in retired_keys]
    measured_keys = {t["key"] for t in measured}
    rows = {t["id"] for t in gen}
    rows_measured = {t["id"] for t in measured}
    # S2-A: coverage_pct_incl_absent keeps the deleted fragments in the denominator (for trend comparison)
    return {"generation_path_fragments": len(gen), "fragments_measured": len(measured),
            "fragments_retired": len(retired), "live_fragments": len(live),
            "fragments_absent": sum(1 for t in gen if t.get("status") in absent_status),
            "coverage_pct": round(100.0 * len(measured) / len(live), 1) if live else None,
            "coverage_pct_incl_absent": round(100.0 * len(measured) / len(gen), 1) if gen else None,
            "generation_path_rows": len(rows), "rows_measured": len(rows_measured),
            "retired": sorted(retired_keys),
            "absent": sorted(t["key"] for t in gen if t.get("status") in absent_status),
            "absent_unrecorded": sorted(t["key"] for t in gen
                                        if t.get("status") in absent_status and t["key"] not in retired_keys),
            "anchor_lost": sorted(t["key"] for t in gen if t.get("status") == "anchor_lost"),
            "unmeasured": sorted(t["key"] for t in live if t["key"] not in measured_keys)}


def healer_table(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    agg: Dict[str, Dict[str, Any]] = {}
    for rec in results:
        if not rec["result"].get("valid_run"):
            continue
        for t in ((rec["result"].get("healers") or {}).get("targets") or []):
            if t.get("kind") not in ("function", "inline"):
                continue
            a = agg.setdefault(t["key"], {"key": t["key"], "id": t["id"], "tier": t["tier"], "kind": t["kind"],
                                          "role": t.get("role"), "calls": 0, "reached": 0, "fires": 0,
                                          "fires_on_validate_valid": 0, "fires_on_syntax_valid": 0,
                                          "fires_validate_unknown": 0})
            a["calls"] += t.get("calls") or 0
            a["reached"] += t.get("reached") or 0
        for k, v in (((rec.get("score") or {}).get("healer_fires")) or {}).items():
            a = agg.get(k)
            if a is None:
                continue
            for f in ("fires", "fires_on_validate_valid", "fires_on_syntax_valid", "fires_validate_unknown"):
                a[f] += v.get(f, 0)
    return sorted(agg.values(), key=lambda a: (-a["fires_on_validate_valid"], -a["fires"], a["key"]))


def aggregate(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows = [run_row(r) for r in results]
    by_ex: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_ex[row["example"]].append(row)

    def block(rs: List[Dict[str, Any]]) -> Dict[str, Any]:
        valid = [r for r in rs if r["valid"]]
        committed = [r for r in valid if r["c3_present"]]
        healers_off = [r for r in valid if r["c1_validate_ok"] is not None]
        tf = sum(r["tf_files"] for r in valid)
        py = sum(r["py_files"] for r in valid)
        return {
            "runs": len(rs), "valid_runs": len(valid),
            "invalid_reasons": sorted({x for r in rs for x in r["invalid_reasons"]}),
            "outcomes": {o: sum(1 for r in rs if r["outcome"] == o) for o in sorted({r["outcome"] for r in rs if r["outcome"]})},
            # unscored committed runs (tofu could not run, e.g. cold offline mirror) are excluded, never counted as fail
            "validate_rate_unconditional": rate(sum(1 for r in valid if r["outcome"] == "committed_passed"
                                                    and r["c3_validate_ok"] is True),
                                                sum(1 for r in valid if not (r["c3_present"] and r["c3_validate_ok"] is None))),
            "validate_rate_conditional": rate(sum(1 for r in committed if r["c3_validate_ok"] is True),
                                              sum(1 for r in committed if r["c3_validate_ok"] is not None)),
            "c3_validate_unscored": sum(1 for r in committed if r["c3_validate_ok"] is None),
            "plan_rate": rate(sum(1 for r in committed if r["c3_plan_ok"] is True),
                              sum(1 for r in committed if r["c3_validate_ok"] is True)),
            "c2_validate_rate": rate(sum(1 for r in valid if r["c2_validate_ok"] is True),
                                     sum(1 for r in valid if r["c2_validate_ok"] is not None)),
            "c1_first_pass_validate_rate": rate(sum(1 for r in healers_off if r["c1_validate_ok"]), len(healers_off)),
            "hcl_parse_rate": rate(sum(r["hcl_parse_ok"] for r in valid), tf),
            "py_ast_rate": rate(sum(r["py_ast_ok"] for r in valid), py),
            "py_files_with_undefined_names": sum(r["py_files_undefined_names"] for r in valid),
            "invariant_violations": sum(r["invariant_violations"] or 0 for r in valid),
            "I6_cycles": sum(r["I6_cycles"] for r in valid), "I3_literals": sum(r["I3_literals"] for r in valid),
            "fires": sum(r["fires"] for r in valid),
            "fires_on_validate_valid": sum(r["fires_on_validate_valid"] for r in valid),
            "fires_on_syntax_valid": sum(r["fires_on_syntax_valid"] for r in valid),
            "fires_validate_unknown": sum(r["fires_validate_unknown"] for r in valid),
            "gate_false_pass": sum(1 for r in valid if r["outcome"] == "committed_passed" and r["c3_validate_ok"] is False),
            # S1-0 (F5): second scoring column; a disagreement lists the run, never changes the primary verdict
            "c3_oracle_validate_rate": rate(sum(1 for r in committed if r["c3_oracle_validate_ok"] is True),
                                            sum(1 for r in committed if r["c3_oracle_validate_ok"] is not None)),
            "column_disagreements": sorted(r["key"] for r in valid if r["c3_column_agreement"] is False),
            "assembly_dropped_unreplaced": sum(len(r["assembly_dropped_unreplaced"] or []) for r in valid),
            "assembly_runs_with_drops": sorted(r["key"] for r in valid if r["assembly_dropped_unreplaced"]),
            "assembly_repair_removals_justified": sum(len(r["assembly_repair_removals_justified"]) for r in valid),
            "assembly_dropped_non_preserved": sum(len(r["assembly_dropped_non_preserved"]) for r in valid),
            "assembly_blocks_not_verbatim": sum(r["assembly_blocks_not_verbatim"] for r in valid),
            "replaced_by_reason": _sum_reasons(valid),
            "golden_module_mutation_runs": sorted(r["key"] for r in valid if r["golden_module_mutations"]),
            "v6_envelope": f"{sum(r['envelope_ok'] for r in valid)}/{sum(r['envelope_checks'] for r in valid)}",
            "report_only_codes": dict(sorted(_count_codes(valid, "report_only_codes").items())),
            "blocking_error_codes": dict(sorted(_count_codes(valid, "validation_error_codes").items())),
            "developer_failed_typed": {c: sum(1 for r in valid if r["developer_failed_typed"] == c)
                                       for c in sorted({r["developer_failed_typed"] for r in valid
                                                        if r["developer_failed_typed"]})},
            "distinct_committed_trees": len({r["c3_tree"] for r in valid if r["c3_tree"]}),
            "distinct_resource_type_sets": len({tuple(r["resource_types"] or []) for r in valid if r["c3_present"]}),
            "replay_diverged_runs": sum(1 for r in rs if r["replay_diverged"]),
            "served": {k: sum((r["served"] or {}).get(k, 0) for r in rs) for k in SERVED_KINDS},
            "spec_sources": {src: sum(1 for r in rs if r["spec_source"] == src)
                             for src in sorted({str(r["spec_source"]) for r in rs})},
            "spec_mismatch_runs": sorted(r["key"] for r in rs if r["spec_match"] is False),
            "isolation_attempts": sum(r["isolation_attempts"] for r in rs),
            "self_correct_calls": sum(r["self_correct_calls"] for r in valid),
            "self_correct_branch_fires": _sum_branch_fires(valid),
            "self_correct_branch_fire_runs": _branch_fire_runs(valid),
            "single_turn_calls": sum(r["single_turn_calls"] for r in valid),
            "junior_reasks": sum(r["junior_reasks"] for r in valid),
            # RT F4: a run the harness stopped (admission / budget cap) is neither a pass nor a product failure
            "harness_budget_stop_runs": sorted(r["key"] for r in rs if r["harness_budget_stop"]),
            "product_outcomes": {o: sum(1 for r in rs if r["outcome"] == o and not r["harness_budget_stop"])
                                 for o in sorted({r["outcome"] for r in rs if r["outcome"]})},
            **typed_iac_block(rs, valid),
            "usd": round(sum(r["usd"] or 0 for r in rs), 4), "llm_calls": sum(r["llm_calls"] for r in rs),
            "truncations": sum(r["truncations"] for r in rs),
            "wall_s_mean": round(sum(r["wall_s"] for r in rs) / len(rs), 1) if rs else None,
        }

    return {"overall": block(rows), "by_example": {ex: block(rs) for ex, rs in sorted(by_ex.items())},
            "runs": rows, "healers": healer_table(results), "coverage": coverage(results),
            "paired_exclusions": paired_exclusions(rows)}


def _code_runs(rows: List[Dict[str, Any]], codes_of: Any) -> Dict[str, int]:
    out: Dict[str, int] = defaultdict(int)
    for r in rows:
        for c in set(codes_of(r)):
            out[c] += 1
    return dict(sorted(out.items()))


def typed_iac_block(rs: List[Dict[str, Any]], valid: List[Dict[str, Any]]) -> Dict[str, Any]:
    """TI-0 aggregates (typed-IaC plan §4 TI-0 / §1.2): code incidence in RUNS (a run counts once per code)."""
    fdc = lambda r: [c for v in (r.get("first_draft_codes") or {}).values() for c in v]  # noqa: E731
    persona: Dict[str, int] = defaultdict(int)
    for r in valid:
        for p, n in (r.get("repair_calls_by_persona") or {}).items():
            persona[p] += n
    split: Dict[str, int] = defaultdict(int)
    for r in valid:
        for k, n in (r.get("healer_fvv_split") or {}).items():
            split[k] += n
    pb = [r for r in valid if r.get("platform_blocks_in_ai_files") is not None]
    cct = [r for r in valid if r.get("consensus_changed_topology") is not None]
    syn = [r for r in rs if r.get("synthetic_expectation") is not None]
    rerun = [r for r in valid if r.get("compute_dropped_on_rerun") is not None]
    return {
        "first_draft_code_runs": _code_runs(valid, fdc),
        "first_draft_code_runs_by_author": {a: _code_runs(valid, lambda r, a=a: (r.get("first_draft_codes") or {})
                                                          .get(a) or []) for a in ("iac", "app", "mixed")},
        "typed_failure_code_runs": _code_runs(valid, lambda r: r.get("typed_failure_codes") or []),
        "repair_calls_by_persona": dict(sorted(persona.items())),
        "repair_calls_total": sum(persona.values()),
        "repair_calls_iac": sum(n for p, n in persona.items() if persona_author(p) == "iac"),
        "repair_calls_source": sorted({r.get("repair_calls_source") for r in valid if r.get("repair_calls_source")}),
        "platform_blocks_in_ai_files": sum(len(r["platform_blocks_in_ai_files"]) for r in pb),
        "platform_blocks_in_ai_files_runs": f"{sum(1 for r in pb if r['platform_blocks_in_ai_files'])}/{len(pb)}",
        "ai_iac_path_runs": _code_runs(valid, lambda r: r.get("ai_iac_paths") or []),
        "first_draft_type_runs": _code_runs(valid, lambda r: r.get("first_draft_types") or []),
        "data_source_runs": _code_runs(valid, lambda r: r.get("data_sources_used") or []),
        "function_runs": _code_runs(valid, lambda r: r.get("functions_used") or []),
        "first_draft_sources": _code_runs(valid, lambda r: [r["first_draft_source"]] if r.get("first_draft_source")
                                          else []),
        "healer_fvv_split": dict(sorted(split.items())),
        "consensus_changed_topology": f"{sum(1 for r in cct if r['consensus_changed_topology'])}/{len(cct)}",
        "consensus_status": {s: sum(1 for r in valid if r.get("consensus_status") == s)
                             for s in sorted({str(r.get("consensus_status")) for r in valid
                                              if r.get("consensus_status")})},
        "architect_failed_typed": {c: sum(1 for r in valid if r.get("architect_failed_typed") == c)
                                   for c in sorted({r["architect_failed_typed"] for r in valid
                                                    if r.get("architect_failed_typed")})},
        "compute_dropped_on_rerun": sum(len(r["compute_dropped_on_rerun"]) for r in rerun),
        # all runs (a harness-invalid run never meets its expectation) and valid runs only (the gate bar, RT F8)
        "synthetic_expected_met": f"{sum(1 for r in syn if r['synthetic_expectation']['met'])}/{len(syn)}",
        "synthetic_expected_met_valid": (f"{sum(1 for r in syn if r['valid'] and r['synthetic_expectation']['met'])}"
                                         f"/{sum(1 for r in syn if r['valid'])}"),
    }


def paired_exclusions(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Code RT F7 (plan RT F10): runs whose LLM calls were not all served by exact replay, with the not-exact sites.
    Their outcome is not faithful to the recording at those sites; `compare.py` drops a run from the paired deltas
    when its not-exact sites differ between the two sides (identical sites = the same recorded answers on both)."""
    return [{"run": r["key"], "reason": "replay_not_exact", "sites": dict(sorted(r["served_not_exact_sites"].items()))}
            for r in rows if r.get("served_not_exact_sites")]


def excluded_from_pairing(base: List[Dict[str, Any]], cand: List[Dict[str, Any]]) -> Dict[str, str]:
    """{run: reason} of the runs removed from a paired comparison: not-exact served sites differ between the sides."""
    b = {e["run"]: e.get("sites") or {} for e in base or []}
    c = {e["run"]: e.get("sites") or {} for e in cand or []}
    return {k: f"replay_not_exact sites {b.get(k, {})} -> {c.get(k, {})}" for k in sorted(set(b) | set(c))
            if b.get(k, {}) != c.get(k, {})}
