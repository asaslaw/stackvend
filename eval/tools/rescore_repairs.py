#!/usr/bin/env python3
"""$0 re-scoring of recorded repair candidates under the product's CURRENT acceptance rules (Step 1 R3c, 10-13).

    python -m eval.tools.rescore_repairs <recorded results/<id>> <shadow replay results/<id>> [--json out.json]

The shadow replay is a `replay-strict` run of the merged cassettes (eval.tools.merge_cassettes) with
`--shadow-accept-from <recorded results/<id>>`: the repair loop is handed the recorded verdicts, so every repair prompt
equals the recorded one and the cassette keeps serving the recorded responses, while `accept_trace` keeps the
product's own verdict on each recorded candidate. This tool compares the two per candidate and per run:

- per candidate (repair iteration): recorded verdict -> product verdict, with the diagnostics fixed / introduced;
- per run: the FIRST candidate the new rules accept that the recorded run rejected. If its tree validates (PASS),
  the run is known to converge there (the loop would return that tree). If it is accepted but still FAILs, every later
  prompt differs from the recording and the outcome is unknowable until a live run (reported as such).

Envelope / transport failures never reach acceptance: they are listed from the recorded events. Reads only.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List


def _events(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    return (result.get("hallucination_stack") or {}).get("repair_events") or []


def rescore(recorded: Path, shadow: Path) -> Dict[str, Any]:
    runs: Dict[str, Any] = {}
    cand_rows: List[Dict[str, Any]] = []
    for rp in sorted((recorded / "runs").glob("*/result.json")):
        key = rp.parent.name
        rec = json.loads(rp.read_text())
        sp = shadow / "runs" / key / "result.json"
        sh = json.loads(sp.read_text()) if sp.is_file() else {}
        ev = _events(rec)
        by_it: Dict[int, Dict[str, Any]] = {}
        for e in ev:
            slot = by_it.setdefault(e["iteration"], {"accepted": e["accepted"], "reject_reason": e.get("reject_reason"),
                                                     "personas": [], "calls": 0})
            slot["personas"].append(e["persona"])
            slot["calls"] += 1
        trace = {t["iteration"]: t for t in sh.get("accept_trace") or []}
        # the shadow replay followed the recorded path iff its events (verdicts forced to the recorded ones) equal the
        # recorded events; a site/ordinal replay fallback between concurrent personas can swap responses (then not)
        def sig(evs: List[Dict[str, Any]]) -> List[Any]:
            return sorted((e["iteration"], e["persona"], e["accepted"], e.get("reject_reason")) for e in evs)
        same_path = bool(sh) and sig(_events(sh)) == sig(ev)
        first_new = None
        for it in sorted(by_it):
            r = by_it[it]
            t = trace.get(it)
            row = {"run": key, "iteration": it, "calls": r["calls"], "recorded": [r["accepted"], r["reject_reason"]],
                   "product": t["product_verdict"] if t else None,
                   "status_after": t["status_after"] if t else None,
                   "n_before": t["n_before"] if t else None, "n_after": t["n_after"] if t else None,
                   "removal_justifications": (t or {}).get("removal_justifications"),
                   "new": [f'{x["code"]}@{x["block"]}' for x in (t or {}).get("new", [])]}
            cand_rows.append(row)
            if first_new is None and t and t["product_verdict"][0] and not r["accepted"]:
                first_new = row
            if first_new is None and r["accepted"] and t and not t["product_verdict"][0]:
                first_new = dict(row, flipped_to_reject=True)
        recorded_outcome = rec.get("pipeline_outcome")
        if not same_path and (first_new is None or not sh.get("valid_run")):
            projected = "unscored"
            basis = "the shadow replay did not follow the recorded path (replay fallback served another call)"
        elif first_new is None:
            projected = recorded_outcome
            basis = "unchanged (no candidate verdict flips)"
        elif first_new.get("flipped_to_reject"):
            projected = "unknown"
            basis = f"a recorded ACCEPTED candidate is now rejected at iteration {first_new['iteration']}"
        elif first_new["status_after"] == "PASS":
            projected = "committed_passed"
            basis = f"newly accepted candidate at iteration {first_new['iteration']} validates PASS"
        else:
            projected = "unknown"
            basis = (f"newly accepted at iteration {first_new['iteration']} with {first_new['n_after']} findings left; "
                     "later prompts differ from the recording (needs a live run)")
        runs[key] = {"recorded_outcome": recorded_outcome, "projected_outcome": projected, "basis": basis,
                     "shadow_valid": bool(sh.get("valid_run")), "shadow_path_matches_recording": same_path,
                     "shadow_outcome": sh.get("pipeline_outcome")}
    calls = sum(r["calls"] for r in cand_rows)
    rec_reasons = Counter(r["recorded"][1] or "ACCEPTED" for r in cand_rows for _ in range(r["calls"]))
    prod_reasons = Counter((r["product"][1] or "ACCEPTED") if r["product"] else "NOT_REACHED_ACCEPT(" +
                           (r["recorded"][1] or "?") + ")" for r in cand_rows for _ in range(r["calls"]))
    transitions = Counter(f'{r["recorded"][1] or "ACCEPTED"} -> '
                          f'{(r["product"][1] or "ACCEPTED") if r["product"] else "(no candidate)"}'
                          for r in cand_rows for _ in range(r["calls"]))
    outcomes = Counter(v["projected_outcome"] for v in runs.values())
    return {"repair_calls": calls, "recorded_verdicts_by_call": dict(rec_reasons),
            "product_verdicts_by_call": dict(prod_reasons), "transitions_by_call": dict(transitions),
            "recorded_outcomes": dict(Counter(v["recorded_outcome"] for v in runs.values())),
            "projected_outcomes": dict(outcomes), "runs": runs, "candidates": cand_rows}


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("recorded")
    ap.add_argument("shadow")
    ap.add_argument("--json", default=None)
    a = ap.parse_args(argv)
    out = rescore(Path(a.recorded), Path(a.shadow))
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=1, sort_keys=True))
    summary = {k: v for k, v in out.items() if k not in ("runs", "candidates")}
    print(json.dumps(summary, indent=1, sort_keys=True))
    for key, v in out["runs"].items():
        print(f"{key}: {v['recorded_outcome']} -> {v['projected_outcome']} ({v['basis']})"
              f"{'' if v['shadow_path_matches_recording'] and v['shadow_valid'] else '  [SHADOW PATH MISMATCH]'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
