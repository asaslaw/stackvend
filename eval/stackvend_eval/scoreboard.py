"""Render summary.json as SCOREBOARD.md."""
from __future__ import annotations

from typing import Any, Dict, Optional


def _pct(r: Optional[Dict[str, Any]]) -> str:
    if not r or not r.get("n"):
        return "n/a"
    lo, hi = r["ci95"]
    return f"{r['k']}/{r['n']} ({100 * r['rate']:.0f}%, CI {100 * lo:.0f}-{100 * hi:.0f})"


def _fired(d: Optional[Dict[str, int]]) -> str:
    items = {k.split("|", 1)[0] + " " + k.split("|", 1)[-1][:40]: v for k, v in (d or {}).items() if v}
    return str(items) if items else "none"


def render(summary: Dict[str, Any]) -> str:
    m = summary.get("manifest", {})
    o = summary["overall"]
    cov = summary.get("coverage", {})
    lines = [
        "# StackVend eval scoreboard (FD-30)", "",
        f"- **Product SHA**: `{m.get('product_sha')}` (dirty={m.get('product_dirty')})  "
        f"**Harness SHA**: `{m.get('harness_sha')}`",
        f"- **Mode**: `{m.get('llm_mode')}`  **Model**: `{m.get('model')}` (fallbacks: {m.get('fallback_models')})  "
        f"**Location**: `{m.get('vertex_location')}`  **Runs/example**: {m.get('runs_per_example')}",
        f"- **Healers off (C1)**: {m.get('healers_off')}  **Seeds injected**: {m.get('inject_seed')}  "
        f"**Temperature override**: {m.get('temperature_override')}",
        f"- **Spend**: ${o['usd']:.4f} across {o['llm_calls']} LLM calls (invocation cap ${m.get('budget_usd')}; "
        f"ledger {m.get('ledger')})",
        f"- **Probe coverage**: {cov.get('fragments_measured')}/{cov.get('live_fragments')} live generation-path "
        f"fragments ({cov.get('coverage_pct')}%; {cov.get('fragments_retired')} retired of "
        f"{cov.get('generation_path_fragments')}), {cov.get('rows_measured')}/{cov.get('generation_path_rows')} HEALERS.md rows",
        "",
        "> Rates are descriptive at N<=5 (Wilson 95% CI shown). Decisions use paired replay (`compare.py`).", "",
        "## Overall", "",
        f"- valid runs: {o['valid_runs']}/{o['runs']}  outcomes: {o['outcomes']}  invalid reasons: {o['invalid_reasons'] or 'none'}",
        f"- **C3 validate (unconditional)**: {_pct(o['validate_rate_unconditional'])}  "
        f"conditional: {_pct(o['validate_rate_conditional'])}  unscored: {o['c3_validate_unscored']}",
        f"- C3 mock plan: {_pct(o['plan_rate'])}  C2 validate: {_pct(o['c2_validate_rate'])}  "
        f"C1 first-pass (healers off): {_pct(o['c1_first_pass_validate_rate'])}",
        f"- HCL parse: {_pct(o['hcl_parse_rate'])}  Python ast: {_pct(o['py_ast_rate'])}  "
        f".py files with undefined names: {o['py_files_with_undefined_names']}",
        f"- invariant violations: {o['invariant_violations']} (I6 cycles {o['I6_cycles']}, I3 literals {o['I3_literals']})  "
        f"gate false-pass: {o['gate_false_pass']}",
        f"- **healer fires on validate-valid input (DNH gate, must be 0)**: {o['fires_on_validate_valid']}  "
        f"(syntax-valid {o['fires_on_syntax_valid']}, unknown {o['fires_validate_unknown']}, total fires {o['fires']})",
        f"- isolation attempts blocked (product paths, expected and swallowed): {o['isolation_attempts']}  "
        f"replay-diverged runs: {o['replay_diverged_runs']}",
        f"- **LLM calls served** (F9): exact replay {o.get('served', {}).get('replay')}, site/ordinal fallback "
        f"{o.get('served', {}).get('replay_fallback')}, miss {o.get('served', {}).get('replay_miss')}, backend "
        f"{o.get('served', {}).get('backend')}; spec sources {o.get('spec_sources') or {}}; spec mismatch runs "
        f"{o.get('spec_mismatch_runs') or 'none'}",
        f"- **Step 1 (S1-0)**: columns `{m.get('provider_set') or 'default'}` (tofu {m.get('tofu')}) vs "
        f"`{m.get('oracle_provider_set') or 'oracle'}` (tofu {m.get('oracle_tofu')}): oracle C3 validate "
        f"{_pct(o.get('c3_oracle_validate_rate'))}, disagreements {o.get('column_disagreements') or 'none'}",
        f"- assembly: dropped LLM declarations without a recorded replacement **{o.get('assembly_dropped_unreplaced')}** "
        f"(runs {o.get('assembly_runs_with_drops') or 'none'}); repair removals (justified) "
        f"{o.get('assembly_repair_removals_justified')}; outputs/locals/other non-preserved kinds absent "
        f"{o.get('assembly_dropped_non_preserved')}; replaced by reason {o.get('replaced_by_reason') or {}}, "
        f"LLM blocks not verbatim {o.get('assembly_blocks_not_verbatim')}; golden-module mutation runs "
        f"{o.get('golden_module_mutation_runs') or 'none'}; typed developer failures {o.get('developer_failed_typed') or {}}",
        f"- validators: blocking error codes (runs) {o.get('blocking_error_codes') or {}}; report-only codes (runs) "
        f"{o.get('report_only_codes') or {}}; V6 envelopes ok {o.get('v6_envelope')}",
        f"- **S2-0**: self_correct_hcl calls {o.get('self_correct_calls')}; branches that changed the tree "
        f"(runs) {_fired(o.get('self_correct_branch_fire_runs'))}; single-turn developer calls "
        f"{o.get('single_turn_calls')}; harness budget stops (not product outcomes) "
        f"{o.get('harness_budget_stop_runs') or 'none'}; product outcomes {o.get('product_outcomes')}; junior JSON "
        f"re-asks {o.get('junior_reasks', 0)}",
        f"- **paired exclusions** (not-exact replay; dropped from paired deltas when the sites differ between the "
        f"sides): {', '.join(e['run'] + ' ' + str(e['sites']) for e in summary.get('paired_exclusions') or []) or 'none'}",
        f"- probe coverage denominator: live healers only (`coverage_pct`: inventory minus the retired list "
        f"eval/config/healer_deletions.json); incl. deleted healers `coverage_pct_incl_absent` = "
        f"{cov.get('coverage_pct_incl_absent')}%",
        "", "## By example", "",
        "| Example | valid | C3 validate (uncond.) | cond. | plan | HCL parse | py ast | undef .py | inv. viol | fires | fires on valid | distinct trees | $ |",
        "| :-- | :-- | :-- | :-- | :-- | :-- | :-- | --: | --: | --: | --: | --: | --: |",
    ]
    for ex, b in summary["by_example"].items():
        lines.append(f"| {ex} | {b['valid_runs']}/{b['runs']} | {_pct(b['validate_rate_unconditional'])} | "
                     f"{_pct(b['validate_rate_conditional'])} | {_pct(b['plan_rate'])} | {_pct(b['hcl_parse_rate'])} | "
                     f"{_pct(b['py_ast_rate'])} | {b['py_files_with_undefined_names']} | {b['invariant_violations']} | "
                     f"{b['fires']} | {b['fires_on_validate_valid']} | {b['distinct_committed_trees']} | {b['usd']:.4f} |")
    lines += ["", "## Healers (valid runs; top 25 by fires on validate-valid input)", "",
              "| HEALERS.md | tier | kind | role | calls / reached | fires | on validate-valid | on syntax-valid | unknown |",
              "| :-- | :-- | :-- | :-- | --: | --: | --: | --: | --: |"]
    for h in summary["healers"][:25]:
        cr = h["calls"] if h["kind"] == "function" else h["reached"]
        lines.append(f"| {h['id']} `{h['key'].split('@', 1)[1][:70]}` | {h['tier']} | {h['kind']} | {h.get('role') or ''} | "
                     f"{cr} | {h['fires']} | {h['fires_on_validate_valid']} | {h['fires_on_syntax_valid']} | "
                     f"{h['fires_validate_unknown']} |")
    lines += ["", "## Replay provenance (served per run)", "",
              "| Run | exact replay | fallback | miss | backend | not-exact sites | spec source | spec sha256 | spec = recorded |",
              "| :-- | --: | --: | --: | --: | :-- | :-- | :-- | :-- |"]
    for r in summary["runs"]:
        sv = r.get("served") or {}
        sites = ", ".join(f"{k} x{v}" for k, v in (r.get("served_not_exact_sites") or {}).items()) or "-"
        lines.append(f"| {r['key']} | {sv.get('replay', '-')} | {sv.get('replay_fallback', '-')} | "
                     f"{sv.get('replay_miss', '-')} | {sv.get('backend', '-')} | {sites} | {r.get('spec_source')} | "
                     f"`{(r.get('spec_sha256') or '')[:12]}` | {r.get('spec_match')} |")
    bad = [r for r in summary["runs"] if not r["valid"]]
    lines += ["", "## Invalid runs", ""]
    lines += [f"- {r['key']}: {', '.join(r['invalid_reasons'])}" for r in bad] or ["- none"]
    if cov.get("absent") or cov.get("anchor_lost"):
        lines += ["", "## Probe gaps", "", f"- absent at this product root: {len(cov.get('absent', []))} "
                  f"(retired on purpose: {len(cov.get('retired', []))}; NOT in the retired list: "
                  f"{len(cov.get('absent_unrecorded', []))})",
                  f"- inline ranges whose anchor was lost: {len(cov.get('anchor_lost', []))}"]
    return "\n".join(lines) + "\n"
