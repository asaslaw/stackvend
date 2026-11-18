#!/usr/bin/env python3
"""Copy cassettes without the repair calls of iteration >= 2 (entrypoint-repair-hint, 10-14).

    python -m eval.tools.strip_repair_calls <cassette_dir> --out <dir> [--keys 03-r1,06-r2] [--max-iteration 1]
        [--drop-architect-repairs] [--force]

--out must lie outside the source directory (refused otherwise); existing output files are never overwritten
without --force.

Why: a replay looks a request up by exact hash and, on a miss, falls back to the recorded call at the same
(site, site_ordinal) (llm_proxy, `replay_fallback`). When the repair loop changes, the prompts of repair iteration 2+
change, so `replay-then-live` on the full cassettes would serve the OLD answers to the NEW prompts instead of going
live. Dropping those records makes them real misses (live, budgeted), while generation calls and iteration-1 repair
prompts (unchanged) still replay exactly. The iteration is read from the repair prompt's own first line
(`REPAIR TASK (<version>) for persona <P>, iteration <N> (...)`, repair_loop.render_repair_prompt). The source
directory is only read; the output holds prompts and model output and must be gitignored (eval/cassettes/ is).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

REPAIR_SITE = "developer_agent/swarm_dispatcher.py:SwarmDispatcher.invoke_repair"
# AC-4: the architect's service-topology patch calls (topology_gate). --drop-architect-repairs drops all of them, so a
# changed topology repair prompt goes live instead of being answered by the recorded call at the same ordinal.
ARCHITECT_REPAIR_SITE = "architect_agent/handler.py:ArchitectAgent._topology_repair_fn.<locals>.repair"


def repair_iteration(rec: Dict[str, Any]) -> Optional[int]:
    """The repair iteration of a recorded invoke_repair call, or None when the header is not the loop's own."""
    contents = (rec.get("request") or {}).get("contents")
    if not isinstance(contents, str):
        return None
    words = contents.split("\n", 1)[0].replace(",", " ").split()
    if len(words) < 2 or words[:2] != ["REPAIR", "TASK"] or "iteration" not in words:
        return None
    i = words.index("iteration")
    return int(words[i + 1]) if i + 1 < len(words) and words[i + 1].isdigit() else None


def valid_key(key: str) -> bool:
    """A run key is exactly <two digits>-r<digits> (the cassette file stem), so `<out>/<key>.jsonl` stays in --out."""
    ex, sep, run = key.partition("-r")
    return bool(sep) and len(ex) == 2 and ex.isascii() and ex.isdigit() and run.isascii() and run.isdigit()


ARCHITECT_STAGE_PREFIX = "architect_agent/"   # TI-3: architect + red-team critic + topology repair call sites


def strip(lines: List[str], max_iteration: int, drop_architect_repairs: bool = False,
          architect_only: bool = False) -> List[str]:
    """`architect_only` (TI-3 smoke): keep the meta line and the architect stage's calls only (exact site prefix
    `architect_agent/`), so every developer-stage call (lead, juniors, single-turn, repair) goes live in
    `replay-then-live` instead of being answered by the recorded call at the same (site, ordinal)."""
    out = []
    for line in lines:
        if not line.strip():
            continue
        rec = json.loads(line)
        if architect_only and rec.get("type") == "call" and not str(rec.get("site") or "").startswith(
                ARCHITECT_STAGE_PREFIX):
            continue
        if drop_architect_repairs and rec.get("type") == "call" and rec.get("site") == ARCHITECT_REPAIR_SITE:
            continue
        if rec.get("type") == "call" and rec.get("site") == REPAIR_SITE:
            it = repair_iteration(rec)
            if it is None:
                raise ValueError(f"repair call without a parseable iteration header (site_ordinal "
                                 f"{rec.get('site_ordinal')})")
            if it > max_iteration:
                continue
        out.append(line)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cassettes")
    ap.add_argument("--out", required=True)
    ap.add_argument("--keys", default=None, help="comma-separated run keys (default: every <NN>-r<n>.jsonl)")
    ap.add_argument("--max-iteration", type=int, default=1)
    ap.add_argument("--force", action="store_true", help="overwrite existing output files")
    ap.add_argument("--drop-architect-repairs", action="store_true",
                    help="also drop every architect topology repair call (AC-4)")
    ap.add_argument("--architect-only", action="store_true",
                    help="TI-3: keep only the architect stage's calls (every developer call goes live)")
    a = ap.parse_args(argv)
    src, dst = Path(a.cassettes), Path(a.out)
    src_r, dst_r = src.resolve(), dst.resolve()
    if dst_r == src_r or src_r in dst_r.parents:   # Fable RT F2: the source cassettes are read-only evidence
        raise SystemExit(f"--out {dst} is the source directory or inside it; choose a directory outside {src}")
    keys = a.keys.split(",") if a.keys else sorted(p.stem for p in src.glob("*-r*.jsonl"))
    bad = [k for k in keys if not valid_key(k)]
    if bad:   # Opus RT F5 (AC-4): a key is a file stem; never a path that could leave --out
        raise SystemExit(f"invalid run key(s) {bad}: expected <NN>-r<n>, e.g. 06-r1")
    dst.mkdir(parents=True, exist_ok=True)
    for key in keys:
        lines = (src / f"{key}.jsonl").read_text().splitlines()
        kept = strip(lines, a.max_iteration, a.drop_architect_repairs, a.architect_only)
        out = dst / f"{key}.jsonl"
        if out.exists() and not a.force:
            raise SystemExit(f"{out} exists; pass --force to overwrite")
        with out.open("w" if a.force else "x") as fh:
            fh.write("\n".join(kept) + "\n")
        print(f"{key}: kept {len(kept)} of {len([x for x in lines if x.strip()])} records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
