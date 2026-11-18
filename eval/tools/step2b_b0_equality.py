#!/usr/bin/env python3
"""S2-B B0 equality check (Step 2 plan §3.2 B0, RT F6; gate G-B).

    python eval/tools/step2b_b0_equality.py <results_dir> --old-source <old preflight_validator.py> \
        [--product-root <checkout>] [--out <json>]

Claim under test: after the S2-B branch deletions, the product's `self_correct_hcl` equals the OLD `self_correct_hcl`
with exactly the to-be-deleted branches disabled, on every `self_correct_hcl` input the harness exported with
`--dump-trees` (the C2 corpus), i.e. the lane-owned sweeps (HA-13, naming, HA-06, coverage, HC-03, GKE WI) did not
move.

How the "old with branches disabled" function is built (no text guessing): the old source is parsed with `ast`; the
branch of every statement of `_self_correct_workload_hcl` (top level and inside its `for err in errors:` loop) is the
last branch marker comment (eval/config/self_correct_branches.json, the S2-0 probe's anchors) at or before the
statement's first line. Statements of the disabled branches are removed from the AST (a `return` is never removed; an
emptied loop body becomes `pass`), and the module is compiled and executed as a sibling module of the product's
`developer_agent` package, so its imports resolve to the same checkout. Disabled by default: every branch whose
`kind` is `error` or `tail` (the S2-B rows); kept: `sweep` (lanes 10/11b).

A sanity column replays the OLD function unmodified on each input and compares it with the output the harness
recorded, so a reconstruction or environment difference is visible instead of hiding inside the equality.

Read-only: nothing in the product is edited. Runs under the WAVE1 mock env (the caller's environment).
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
import types
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

EVAL_DIR = Path(__file__).resolve().parents[1]
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

from stackvend_eval.blobs import BlobStore  # noqa: E402
from stackvend_eval.paths import CONFIG_DIR, REPO_ROOT, add_deps_to_path, gateway_dir  # noqa: E402

FUNCTION = "_self_correct_workload_hcl"
DISABLED_KINDS = frozenset({"error", "tail"})


def load_branches(config: Path = CONFIG_DIR / "self_correct_branches.json") -> List[Dict[str, Any]]:
    return json.loads(Path(config).read_text())["branches"]


def _marker_lines(src_lines: Sequence[str], start: int, end: int, branches: List[Dict[str, Any]]) -> List[tuple]:
    """[(line, branch_index)] for every marker comment inside [start, end] (1-based), sorted."""
    out = []
    for bi, b in enumerate(branches):
        for ln in range(start, end + 1):
            if src_lines[ln - 1].strip().startswith(b["marker"]):
                out.append((ln, bi))
                break
    return sorted(out)


def _branch_of(lineno: int, markers: List[tuple]) -> int:
    owner = -1
    for ln, bi in markers:
        if ln <= lineno:
            owner = bi
        else:
            break
    return owner


def disable_branches(source: str, branches: List[Dict[str, Any]], disabled: Set[int]) -> tuple:
    """-> (module AST with the disabled branches' statements removed, {branch index: removed statement count})."""
    tree = ast.parse(source)
    lines = source.splitlines()
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == FUNCTION)
    markers = _marker_lines(lines, fn.lineno, fn.end_lineno, branches)
    removed: Dict[int, int] = {}

    def prune(body: List[ast.stmt]) -> List[ast.stmt]:
        kept = []
        for st in body:
            bi = _branch_of(st.lineno, markers)
            if bi in disabled and not isinstance(st, ast.Return):
                removed[bi] = removed.get(bi, 0) + 1
                continue
            if isinstance(st, ast.For) and isinstance(st.target, ast.Name) and st.target.id == "err":
                st.body = prune(st.body) or [ast.copy_location(ast.Pass(), st)]
            kept.append(st)
        return kept

    fn.body = prune(fn.body)
    ast.fix_missing_locations(tree)
    return tree, removed


def load_variant(name: str, tree: ast.Module, filename: str) -> types.ModuleType:
    """Execute a (possibly pruned) copy of preflight_validator as `developer_agent.<name>`."""
    mod = types.ModuleType(f"developer_agent.{name}")
    mod.__package__ = "developer_agent"
    mod.__file__ = filename
    sys.modules[mod.__name__] = mod
    exec(compile(tree, filename, "exec"), mod.__dict__)  # noqa: S102 - product text, harness trust level
    return mod


def _platform(files: Dict[str, str], keys: Optional[List[str]]) -> Optional[Dict[str, str]]:
    if keys is None:
        return None
    return {k: files[k] for k in keys if k in files}


def _diff(a: Dict[str, str], b: Dict[str, str]) -> List[str]:
    return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))


def run(results_dir: Path, old_source: Path, product_root: Path, branches: List[Dict[str, Any]],
        disabled_kinds: Set[str] = DISABLED_KINDS) -> Dict[str, Any]:
    add_deps_to_path()
    gw = str(gateway_dir(product_root))
    if gw not in sys.path:
        sys.path.insert(0, gw)
    import developer_agent.preflight_validator as new_pv  # noqa: E402 - the product under test

    src = old_source.read_text()
    disabled = {i for i, b in enumerate(branches) if b.get("kind") in disabled_kinds}
    old_full = load_variant("_b0_old_full", ast.parse(src), str(old_source))
    pruned_tree, removed = disable_branches(src, branches, disabled)
    old_disabled = load_variant("_b0_old_disabled", pruned_tree, str(old_source))

    calls: List[Dict[str, Any]] = []
    for rd in sorted((results_dir / "runs").iterdir()):
        rj = rd / "result.json"
        if not rj.is_file():
            continue
        result = json.loads(rj.read_text())
        recs = ((result.get("tree_dumps") or {}).get("self_correct") or [])
        if not recs:
            continue
        bs = BlobStore(rd)
        for rec in recs:
            if "files" not in rec:
                calls.append({"run": rd.name, "call": rec.get("call"), "error": rec.get("error")})
                continue
            files = bs.get_tree(rec["files"])
            recorded = bs.get_tree(rec["result"])
            errors = list(rec.get("errors") or [])
            pid = rec.get("product_id") or "workload"
            pkeys = rec.get("platform_files")
            out_full = old_full.self_correct_hcl(dict(files), list(errors), pid, platform_files=_platform(files, pkeys))
            out_dis = old_disabled.self_correct_hcl(dict(files), list(errors), pid,
                                                    platform_files=_platform(files, pkeys))
            out_new = new_pv.self_correct_hcl(dict(files), list(errors), pid, platform_files=_platform(files, pkeys))
            calls.append({
                "run": rd.name, "call": rec.get("call"),
                "replay_old_equals_recorded": out_full == recorded,
                "replay_old_diff_files": _diff(out_full, recorded),
                "new_equals_old_disabled": out_new == out_dis,
                "new_vs_old_disabled_diff_files": _diff(out_new, out_dis),
                "deleted_branches_changed_files": _diff(out_full, out_dis),
                "platform_files_unchanged_new": all(out_new.get(k) == files.get(k) for k in (pkeys or [])),
            })
    ok = [c for c in calls if "error" not in c]
    return {
        "results_dir": str(results_dir), "old_source": str(old_source), "product_root": str(product_root),
        "disabled_branches": sorted({branches[i]["id"] for i in disabled}),
        "removed_statements": {f'{branches[i]["id"]} {branches[i]["marker"]}': n for i, n in sorted(removed.items())},
        "calls": calls,
        "totals": {
            "calls": len(ok), "runs": len({c["run"] for c in ok}),
            "new_equals_old_disabled": sum(c["new_equals_old_disabled"] for c in ok),
            "replay_old_equals_recorded": sum(c["replay_old_equals_recorded"] for c in ok),
            "calls_where_deleted_branches_changed_the_tree": sum(bool(c["deleted_branches_changed_files"])
                                                                 for c in ok),
            "platform_files_unchanged_new": sum(c["platform_files_unchanged_new"] for c in ok),
            "errors": [c for c in calls if "error" in c],
        },
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("results_dir", type=Path)
    ap.add_argument("--old-source", type=Path, required=True)
    ap.add_argument("--product-root", type=Path, default=REPO_ROOT)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)
    rep = run(args.results_dir, args.old_source, args.product_root, load_branches())
    out = args.out or (args.results_dir / "step2b_b0_equality.json")
    out.write_text(json.dumps(rep, indent=1, sort_keys=True))
    t = rep["totals"]
    print(json.dumps({"removed_statements": rep["removed_statements"], "totals": t}, indent=1, sort_keys=True))
    bad = [c for c in rep["calls"] if "error" not in c and not c["new_equals_old_disabled"]]
    for c in bad:
        print(f"DIFF {c['run']} call {c['call']}: {c['new_vs_old_disabled_diff_files']}")
    return 0 if not bad and not t["errors"] and t["platform_files_unchanged_new"] == t["calls"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
