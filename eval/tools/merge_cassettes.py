#!/usr/bin/env python3
"""Merge base cassettes with the per-run cassettes a replay-then-live invocation recorded (S1-0, Step 1 R4).

    python -m eval.tools.merge_cassettes <base_cassette_dir> <results/<id>> --out <dir>

For every run key <NN>-r<n>: out/<key>.jsonl = base/<key>.jsonl  ∪  results/<id>/runs/<key>/cassette.jsonl, keyed by
(request_hash, occurrence). The same key in both with a different recorded response is a collision and fails the merge
(nothing is written). The base meta line is kept; the per-run meta is recorded as `merged_from`. The base directory
and the results are only read. Cassettes hold prompts and model output: the output directory must be gitignored
(eval/cassettes/ is).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

RESPONSE_FIELDS = ("response", "error", "finish_reason", "model_version")


class MergeCollision(Exception):
    pass


def _read(path: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    meta: Dict[str, Any] = {}
    calls: List[Dict[str, Any]] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("type") == "meta":
            meta = rec
        elif rec.get("type") == "call":
            calls.append(rec)
    return meta, calls


def merge_one(base: Path, extra: Optional[Path]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int]:
    meta, calls = _read(base)
    by_key = {(c["request_hash"], int(c["occurrence"])): c for c in calls}
    added = 0
    if extra is not None and extra.is_file():
        emeta, ecalls = _read(extra)
        for c in ecalls:
            k = (c["request_hash"], int(c["occurrence"]))
            if k in by_key:
                if any(by_key[k].get(f) != c.get(f) for f in RESPONSE_FIELDS):
                    raise MergeCollision(f"{base.name}: {k[0][:12]}#{k[1]} recorded twice with different responses")
                continue
            by_key[k] = c
            calls.append(c)
            added += 1
        meta = dict(meta, merged_from={k: v for k, v in emeta.items() if k != "type"})
    return meta, calls, added


def merge(base_dir: Path, results_dir: Path, out_dir: Path) -> Dict[str, int]:
    base_dir, results_dir, out_dir = Path(base_dir), Path(results_dir), Path(out_dir)
    if out_dir.resolve() in (base_dir.resolve(), results_dir.resolve()):
        raise SystemExit("--out must differ from the inputs (inputs are read-only)")
    staged: Dict[str, Tuple[Dict[str, Any], List[Dict[str, Any]], int]] = {}
    for base in sorted(base_dir.glob("*.jsonl")):
        key = base.stem
        staged[key] = merge_one(base, results_dir / "runs" / key / "cassette.jsonl")
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {}
    for key, (meta, calls, added) in staged.items():
        lines = [json.dumps(meta, sort_keys=True)] + [json.dumps(c, sort_keys=True) for c in calls]
        (out_dir / f"{key}.jsonl").write_text("\n".join(lines) + "\n")
        report[key] = added
    return report


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base")
    ap.add_argument("results")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        report = merge(Path(a.base), Path(a.results), Path(a.out))
    except MergeCollision as e:
        print(f"merge refused: {e}", file=sys.stderr)
        return 2
    print(json.dumps({"runs": len(report), "added_calls": sum(report.values()), "per_run": report}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
