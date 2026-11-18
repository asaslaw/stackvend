#!/usr/bin/env python3
"""Compare two harness invocations (red-team L2).

    python -m eval.compare <baseline summary.json | results dir> <candidate summary.json | results dir>

Replay comparisons (same cassettes, two product roots) are PAIRED by run key (minus `paired_excluded`: runs whose
not-exact replay sites differ between the two sides) and are the decision lever: any
pass->fail flip, any new fires on validate-valid input, any new invariant violation or invalid-run reason is a
regression (exit 1). Live comparisons additionally get an exact McNemar p-value on the pooled pairs; per-example
N=3 rates are descriptive only.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

EVAL_DIR = Path(__file__).resolve().parent
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

from stackvend_eval.metrics import excluded_from_pairing, paired_exclusions  # noqa: E402
from stackvend_eval.stats import paired  # noqa: E402


def load(p: str) -> Dict[str, Any]:
    path = Path(p)
    if path.is_dir():
        path = path / "summary.json"
    return json.loads(path.read_text())


def _pass(r: Dict[str, Any]) -> bool:
    return bool(r.get("valid")) and r.get("outcome") == "committed_passed" and r.get("c3_validate_ok") is True


def compare(base: Dict[str, Any], cand: Dict[str, Any]) -> Dict[str, Any]:
    b_runs = {r["key"]: r for r in base.get("runs", [])}
    c_runs = {r["key"]: r for r in cand.get("runs", [])}
    # code RT F7: runs whose not-exact replay sites differ between the sides are not paired (summaries written
    # before F7 carry no list: it is recomputed from the per-run served sites)
    excluded = excluded_from_pairing(base.get("paired_exclusions", paired_exclusions(base.get("runs", []))),
                                     cand.get("paired_exclusions", paired_exclusions(cand.get("runs", []))))
    scored = [k for k in set(b_runs) & set(c_runs) if k not in excluded
              and b_runs[k].get("c3_validate_ok") is not None and c_runs[k].get("c3_validate_ok") is not None]
    pv = paired({k: _pass(b_runs[k]) for k in scored}, {k: _pass(c_runs[k]) for k in scored})
    bo, co = base["overall"], cand["overall"]
    regressions: List[str] = []
    if pv["pass_to_fail"]:
        regressions.append(f"validate pass->fail on {pv['regressed']}")
    if co["fires_on_validate_valid"] > bo["fires_on_validate_valid"]:
        regressions.append(f"fires on validate-valid input {bo['fires_on_validate_valid']} -> {co['fires_on_validate_valid']}")
    if co["invariant_violations"] > bo["invariant_violations"]:
        regressions.append(f"invariant violations {bo['invariant_violations']} -> {co['invariant_violations']}")
    new_reasons = sorted(set(co["invalid_reasons"]) - set(bo["invalid_reasons"]))
    if new_reasons:
        regressions.append(f"new invalid-run reasons {new_reasons}")
    diverged = co.get("replay_diverged_runs", 0)
    return {"paired": pv, "paired_excluded": excluded, "regressions": regressions,
            "deltas": {k: (bo.get(k), co.get(k)) for k in ("fires", "fires_on_validate_valid", "fires_on_syntax_valid",
                                                            "invariant_violations", "usd", "llm_calls")},
            "rates": {k: ((bo.get(k) or {}).get("rate"), (co.get(k) or {}).get("rate"))
                      for k in ("validate_rate_unconditional", "validate_rate_conditional", "plan_rate",
                                "hcl_parse_rate", "py_ast_rate")},
            "note": ("candidate has replay-diverged runs: not a deterministic comparison" if diverged else None)}


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    out = compare(load(argv[0]), load(argv[1]))
    print(json.dumps(out, indent=1, default=str))
    return 1 if out["regressions"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
