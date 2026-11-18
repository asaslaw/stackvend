#!/usr/bin/env python3
"""TI-3 smoke scoring (typed IaC plan §4 TI-3 paid gate 1): read a results directory of a `--iac-intent-mode generate
--repair-iterations 0` run and report the three pass criteria per run and in total.

    python -m eval.tools.ti3_smoke_score <results_dir> [--json]

Per valid run, from result.json (`hallucination_stack`: the final ValidationReport, which with 0 repair iterations
is the first draft's report, or the typed failure's report):
  intent_parsed     the draft holds infra/workload/iac_intent.json and it parses as an IacIntent (no JSON.OUTPUT_INVALID /
                    IAC.INTENT_MISSING on it, and no junior JSON.OUTPUT_INVALID from the IaC persona)
  gate_clean        intent_parsed and no error finding on the intent file (V-IAC: IAC.*, TOPOLOGY.CYCLE, FACT.MISSING)
  render_validates  gate_clean and no TF.* / PLATFORM.INTENT_GATE_GAP finding on a root-module file (the render, the
                    platform's main.tf / services.tf / variables.tf / outputs.tf / intent_facts.tf.json)
Pass (plan): intents parse >= 8/9; gate first-pass clean >= 6/9; render-validate 100 % of gate-clean runs.
Exact field reads only; no scoring of app code (CONTAINER.* / PY.* are reported, not judged).
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

INTENT_PATH = "infra/workload/iac_intent.json"
WORKLOAD = "infra/workload/"
NOT_PARSED = frozenset({"JSON.OUTPUT_INVALID", "IAC.INTENT_MISSING"})


def _report(result: Dict[str, Any]) -> Dict[str, Any]:
    hs = result.get("hallucination_stack") or {}
    return hs.get("developer_failed_typed") or hs.get("validation_report") or {}


def _errors(rep: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [d for d in rep.get("diagnostics") or [] if d.get("severity") == "error"]


def _root_file(path: str) -> bool:
    return path.startswith(WORKLOAD) and "/" not in path[len(WORKLOAD):] and path.endswith((".tf", ".tf.json"))


def on_intent_path(run_dir: Optional[Path], result: Dict[str, Any]) -> Optional[bool]:
    """RT F2/F3: a dispatch may stay on the legacy path under generate (legacy workload HCL, a network-bound topology
    resource). True when the run's first assembled tree (--dump-trees) holds the intent or its render, False when
    it holds neither, None when no tree was dumped."""
    entries = ((result.get("tree_dumps") or {}).get("assemble") or []) if isinstance(result.get("tree_dumps"),
                                                                                       dict) else []
    if run_dir is None or not entries or not isinstance(entries[0], dict):
        return None
    p = run_dir / "trees" / f"{entries[0].get('assembled')}.json"
    if not p.exists():
        return None
    tree = json.loads(p.read_text())
    return INTENT_PATH in tree or "infra/workload/custom.tf.json" in tree


def score_run(result: Dict[str, Any], run_dir: Optional[Path] = None) -> Dict[str, Any]:
    rep = _report(result)
    errs = _errors(rep)
    on_intent = [d for d in errs if d.get("file") == INTENT_PATH]
    junior_iac_json = [d for d in errs if d.get("code") == "JSON.OUTPUT_INVALID"
                       and str(d.get("file", "")).startswith("<junior:") and d.get("symbol") == "IAC_ENGINEER"]
    reached = bool(rep)   # the developer stage produced a validated (or typed-failed) tree
    parsed = reached and not junior_iac_json and not any(d.get("code") in NOT_PARSED for d in on_intent)
    gate_clean = parsed and not on_intent
    tf = [d for d in errs if (str(d.get("code", "")).startswith("TF.") and _root_file(str(d.get("file", ""))))
          or d.get("code") == "PLATFORM.INTENT_GATE_GAP"]
    return {"valid": bool(result.get("valid_run")), "outcome": result.get("pipeline_outcome"),
            "on_intent_path": on_intent_path(run_dir, result),
            "intent_parsed": parsed, "gate_clean": gate_clean, "render_validates": gate_clean and not tf,
            "intent_codes": sorted({d.get("code") for d in on_intent}),
            "iac_tf_codes": sorted({(d.get("code"), d.get("file")) for d in tf}),
            "hcl_not_allowed": sum(1 for d in errs if d.get("code") == "PATH.IAC_HCL_NOT_ALLOWED"),
            "other_codes": sorted({d.get("code") for d in errs if d not in on_intent and d not in tf})}


def score_dir(results: Path) -> Dict[str, Any]:
    runs: Dict[str, Dict[str, Any]] = {}
    for rj in sorted(results.glob("runs/*/result.json")):
        runs[rj.parent.name] = score_run(json.loads(rj.read_text()), rj.parent)
    # a run that stayed on the legacy path (on_intent_path False) is reported, never counted for the intent bars
    valid = {k: v for k, v in runs.items() if v["valid"] and v["on_intent_path"] is not False}
    n = len(valid)
    need_parse, need_clean = max(n - 1, 0), -(-6 * n // 9)   # plan bars 8/9 and 6/9, scaled to the runs scored
    parsed = sum(v["intent_parsed"] for v in valid.values())
    clean = sum(v["gate_clean"] for v in valid.values())
    rv = sum(v["render_validates"] for v in valid.values())
    codes = collections.Counter(c for v in valid.values() for c in v["intent_codes"])
    manifest = results / "manifest.json"
    mode = json.loads(manifest.read_text()).get("iac_intent_mode") if manifest.exists() else None
    return {"runs": runs, "valid": n, "intent_parsed": parsed, "gate_clean": clean, "render_validates": rv,
            "intent_code_runs": dict(codes.most_common()), "iac_intent_mode": mode,
            "legacy_path_runs": sorted(k for k, v in runs.items() if v["on_intent_path"] is False),
            "bars": {"intents_parse": need_parse, "gate_clean": need_clean},
            "pass": {"run_in_generate_mode": mode == "generate", "at_least_8_runs_scored": n >= 8,
                     "intents_parse": parsed >= need_parse, "gate_clean": clean >= need_clean,
                     "render_validate_all_gate_clean": rv == clean}}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("results")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    s = score_dir(Path(a.results))
    if a.json:
        print(json.dumps(s, indent=1, sort_keys=True))
        return 0
    for k, v in s["runs"].items():
        print(f"{k}: valid={v['valid']} outcome={v['outcome']} parsed={v['intent_parsed']} clean={v['gate_clean']} "
              f"render_ok={v['render_validates']} intent={v['intent_codes']} tf={v['iac_tf_codes']} "
              f"hcl_not_allowed={v['hcl_not_allowed']} other={v['other_codes']}")
    print(f"scored {s['valid']} (legacy-path runs not scored: {s['legacy_path_runs']}); intents parse "
          f"{s['intent_parsed']}/{s['valid']} (>= {s['bars']['intents_parse']}); gate first-pass clean "
          f"{s['gate_clean']}/{s['valid']} (>= {s['bars']['gate_clean']}); render-validate {s['render_validates']}/"
          f"{s['gate_clean']} of gate-clean (100 %)")
    print("intent codes (runs):", s["intent_code_runs"])
    print("PASS" if all(s["pass"].values()) else "MISS", s["pass"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
