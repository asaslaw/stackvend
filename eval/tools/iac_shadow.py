#!/usr/bin/env python3
"""TI-2 typed-IaC intent shadow gate over recorded cassettes ($0, offline, read-only on the cassettes).

    python eval/tools/iac_shadow.py --out <dir> --tofu <tofu-1.9.0> --mirror <.tofu-mirror-prod> \
        <cassette_dir> [<cassette_dir> ...] [--product-root <checkout>] [--keys 01-r1,02-r3] [--no-precision]

Each cassette dir holds `<example>-r<run>.jsonl` files (copy them out of your cassette backup directory after
checking the `.sha256` first). Writes `<out>/iac_shadow.json` (per-run records + summary) and `<out>/iac_shadow.md`.
See eval/stackvend_eval/iac_shadow.py for the metrics (a)-(d).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

EVAL = Path(__file__).resolve().parent.parent
if str(EVAL) not in sys.path:
    sys.path.insert(0, str(EVAL))

from stackvend_eval import iac_shadow as sh  # noqa: E402


def _product_ids(root: Path) -> dict:
    ex = json.loads((root / "eval" / "config" / "examples.json").read_text())["examples"]
    return {e["id"]: e["product_id"] for e in ex}


def _md(summary: dict, records: list) -> str:
    a, b, d = summary["a_expressibility"], summary["b_render_validate"], summary["d_gate_precision"]
    lines = ["# TI-2 intent shadow gate", "",
             f"- runs: {summary['runs_total']} total, {summary['runs_scored']} scored; "
             f"no IaC draft: {', '.join(summary['runs_without_iac_draft']) or 'none'}",
             f"- (a) expressibility per run: min {a['min_per_run']}, mean {a['mean_per_run']}; "
             f"below 90 %: {len(a['runs_below_90'])} ({', '.join(a['runs_below_90'])}); "
             f"below 80 %: {len(a['runs_below_80'])}",
             f"  - excluding draft defects: min {a['excl_draft_defects']['min_per_run']}; below 90 %: "
             f"{len(a['excl_draft_defects']['runs_below_90'])} ({', '.join(a['excl_draft_defects']['runs_below_90'])}); "
             f"below 80 %: {len(a['excl_draft_defects']['runs_below_80'])}",
             f"  - per set: {a['per_set']}",
             f"  - blocks: {a['blocks']}; excluded by owner: {a['excluded_by_owner']}",
             f"  - convert reasons: {a['convert_reasons']}",
             f"  - failed types: {a['failed_types']}",
             f"- (b) gate-clean render + platform root, production tofu validate: {b['pass']}/{b['runs']} "
             f"(failing: {', '.join(b['failing']) or 'none'})",
             f"- (c) TF.* on gate-clean renders: {summary['c_tf_codes_on_gate_clean'] or 'none'}",
             f"- (d) gate precision: {len(d['false_positives'])} false positives of {d['checked']} leave-one-in checks",
             f"- mutants (gate vs compiler): {summary['mutations']['checked']} checked {summary['mutations']['by_kind']};"
             f" gate missed {len(summary['mutations']['gate_missed'])}; gate flagged but tofu accepted (false positive) "
             f"{len(summary['mutations']['tofu_accepted_gate_flagged'])}",
             f"- gate codes on converted intents: {summary['gate_codes']}",
             f"- render deterministic: {summary['render_deterministic']}",
             f"- functions seen in drafts: {summary['functions_seen']}; rendered: {summary['functions_rendered']}",
             f"- lifecycle seen: {summary['lifecycle_seen']}; rendered: {summary['lifecycle_rendered']}",
             f"- data sources seen: {summary['data_sources_seen']}; meta-arguments seen: {summary['meta_seen']}",
             f"- facts rendered: {summary['facts_rendered']}", "", "| run | conv | fail | excl | expr | gate-clean |"
             " validate | gate codes |", "| :-- | --: | --: | --: | --: | --: | :-- | :-- |"]
    for r in records:
        if r.get("status") != "scored":
            lines.append(f"| {r['key']} | | | | | | {r.get('status')} | |")
            continue
        ex = "" if r["expressibility"] is None else f"{r['expressibility']:.2f}"
        lines.append(f"| {r['key']} | {r['converted']} | {r['failed']} | {r['excluded']} | {ex} | "
                     f"{r['gate_clean_entries']} | {'PASS' if r['validate']['ok'] else 'FAIL'} | "
                     f"{', '.join(f'{k}×{v}' for k, v in sorted(r['gate_codes'].items()))} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("cassette_dirs", nargs="+")
    ap.add_argument("--out", required=True)
    ap.add_argument("--tofu", required=True)
    ap.add_argument("--mirror", required=True)
    ap.add_argument("--product-root", default=str(EVAL.parent))
    ap.add_argument("--keys", default="")
    ap.add_argument("--no-precision", action="store_true")
    ap.add_argument("--mutations", action="store_true", help="schema-derived mutants per run (gate vs compiler)")
    a = ap.parse_args(argv)
    root = Path(a.product_root).resolve()
    prod = sh.load_product(root)
    art = prod["ii"].load_artifacts()
    pids = _product_ids(root)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    validator = sh.ShadowValidator(a.tofu, a.mirror, out / "work")
    want = {k for k in a.keys.split(",") if k}
    records = []
    t0 = time.time()
    for cdir in a.cassette_dirs:
        cdir = Path(cdir)
        for cas in sorted(cdir.glob("*.jsonl")):
            run = cas.stem
            if want and run not in want:
                continue
            key = f"{cdir.name}/{run}"
            rec = sh.shadow_run(prod, art, validator, key, cas, pids[run.split("-")[0]],
                                precision=not a.no_precision, mutations=a.mutations)
            records.append(rec)
            print(f"[{time.time() - t0:6.0f}s] {key}: {rec.get('status')} expr={rec.get('expressibility')} "
                  f"validate={(rec.get('validate') or {}).get('ok')}", flush=True)
    summary = sh.summarize(records)
    summary["catalog_module_smoke"] = sh.module_smoke(prod, art, validator, "test-01-event-router")
    summary["escape_roundtrip"] = sh.escape_roundtrip(prod, validator)
    print("escape round-trip:", json.dumps(summary["escape_roundtrip"]))
    print("catalog module smoke:", json.dumps(summary["catalog_module_smoke"], indent=1))
    (out / "iac_shadow.json").write_text(json.dumps({"summary": summary, "runs": records}, indent=1, default=str))
    (out / "iac_shadow.md").write_text(_md(summary, records))
    print(_md(summary, records))
    return 0


if __name__ == "__main__":
    sys.exit(main())
