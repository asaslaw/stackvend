#!/usr/bin/env python3
"""Regenerate eval/config/healer_targets.json from docs/planning/review/HEALERS.md (red-team H2).

Resolution happens against the inventory commit (targets.INVENTORY_SHA), where HEALERS.md line numbers are valid.
Anchoring onto the product root being measured happens at run time in the parent (run_examples.py), against
eval/config/inventory_line_digests.json (also written here), so the run time never needs the inventory commit.

This maintainer tool needs the private repository: HEALERS.md lives in the internal docs/ tree and the inventory
commit in the full history. A public export (fresh single-commit history, no docs/) uses the two committed files.

    python eval/tools/build_targets.py            # writes healer_targets.json + inventory_line_digests.json
    python eval/tools/build_targets.py --check    # exit 1 if either committed file is stale
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from stackvend_eval import gitutil  # noqa: E402
from stackvend_eval.paths import CONFIG_DIR, REPO_ROOT  # noqa: E402
from stackvend_eval.targets import INVENTORY_SHA, build_inventory_digests, parse_rows, resolve  # noqa: E402

SCAN_PREFIXES = ("apps/", "mcp-servers/", "shared/")
HEALERS_MD = REPO_ROOT / "docs" / "planning" / "review" / "HEALERS.md"
TARGETS_JSON = "healer_targets.json"
DIGESTS_JSON = "inventory_line_digests.json"


def build() -> tuple:
    if not HEALERS_MD.is_file():
        raise SystemExit(f"{HEALERS_MD.relative_to(REPO_ROOT)} not found: this tool runs in the private repository "
                         "only (docs/ is internal); the committed healer_targets.json is used as is")
    md = HEALERS_MD.read_text()
    rows = parse_rows(md)
    files = [p for p in gitutil.ls_tree(REPO_ROOT, INVENTORY_SHA) if p.startswith(SCAN_PREFIXES)]
    if not files:
        raise SystemExit(f"cannot list files at inventory commit {INVENTORY_SHA}: it is not in this clone (shallow "
                         "checkout or fresh public history); run in a full clone of the private repository")
    read_old = lambda p: gitutil.show(str(REPO_ROOT), INVENTORY_SHA, p)  # noqa: E731
    frags = resolve(rows, read_old, lambda: files)
    from dataclasses import asdict
    kinds: dict = {}
    for f in frags:
        kinds[f.kind] = kinds.get(f.kind, 0) + 1
    targets = {"inventory_sha": INVENTORY_SHA, "source": "docs/planning/review/HEALERS.md",
               "healer_rows": len(rows), "fragments": [dict(asdict(f), key=f.key()) for f in frags],
               "counts_by_kind": dict(sorted(kinds.items()))}
    return targets, build_inventory_digests(frags, read_old)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    data, digests = build()
    outputs = [(CONFIG_DIR / TARGETS_JSON, json.dumps(data, indent=1, sort_keys=True) + "\n"),
               (CONFIG_DIR / DIGESTS_JSON, json.dumps(digests, indent=1, sort_keys=True) + "\n")]
    if a.check:
        stale = [out.name for out, text in outputs if not (out.exists() and out.read_text() == text)]
        for out, _ in outputs:
            print(out.name, "is", "STALE" if out.name in stale else "current")
        return 1 if stale else 0
    for out, text in outputs:
        out.write_text(text)
    print(f"wrote {outputs[0][0]} ({len(data['fragments'])} fragments from {data['healer_rows']} rows): "
          f"{data['counts_by_kind']}")
    print(f"wrote {outputs[1][0]} ({len(digests['files'])} inventory files as line digests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
