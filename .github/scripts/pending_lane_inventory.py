#!/usr/bin/env python3
"""
Inventory for tests/hermetic_known_leaks.py PENDING_LANE_FILES (code red-team finding 3). Read-only (git show/diff).

For each unmerged lane branch, lists the top-level tests/test_*.py files it ADDS relative to its merge-base with the base
ref, and which hermetic meta-tests each would fail (no ``import hermetic_guard`` first; a ``[sys.executable, ...]``
spawn without ``env=hermetic_guard.child_env(...)``). Prints ready-to-paste PENDING_LANE_FILES entries.

Run it right before lane 2 merges: the registry can only be filled by that merge (allowlist_guard.py refuses new
entries once the file exists on the base branch), so files a lane adds later must comply when they are added.

  python .github/scripts/pending_lane_inventory.py --base main 3=worktree-agent-ae72f121dfe2a2ae4 4=...
"""
import argparse
import ast
import subprocess

ROOT = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip()


def git(*args):
    return subprocess.run(["git", "-C", ROOT, *args], capture_output=True, text=True, check=True).stdout


def first_import_is_guard(tree):
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant):
            continue
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            continue
        return isinstance(node, ast.Import) and [a.name for a in node.names] == ["hermetic_guard"]
    return False


def bare_python_spawns(tree):
    """Same rule as tests/test_hermetic_guard.py::test_python_children_use_child_env."""
    bad = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        uses = any(isinstance(n, ast.Attribute) and n.attr in ("child_env", "run_python_child")
                   and isinstance(n.value, ast.Name) and n.value.id == "hermetic_guard" for n in ast.walk(fn))
        for call in ast.walk(fn):
            if not isinstance(call, ast.Call) or not call.args:
                continue
            first = call.args[0]
            if isinstance(first, (ast.List, ast.Tuple)) and any(
                    isinstance(e, ast.Attribute) and e.attr == "executable" and isinstance(e.value, ast.Name)
                    and e.value.id == "sys" for e in first.elts):
                if not (any(k.arg == "env" for k in call.keywords) and uses):
                    bad.append(f"{fn.name}:{call.lineno}")
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="main")
    ap.add_argument("--expires", default="2026-11-15")
    ap.add_argument("lanes", nargs="+", help="LANE=BRANCH, e.g. 4=worktree-agent-a35e10e8c0d93ef50")
    args = ap.parse_args()
    for spec in args.lanes:
        lane, branch = spec.split("=", 1)
        tip = git("rev-parse", "--short", branch).strip()
        mb = git("merge-base", args.base, branch).strip()
        print(f"    # --- lane {lane} ({branch} @ {tip})")
        for line in git("diff", "--name-status", "--diff-filter=A", mb, branch, "--", "tests/").splitlines():
            path = line.split("\t", 1)[1]
            name = path[len("tests/"):]
            if "/" in name or not (name.startswith("test_") and name.endswith(".py")):
                continue
            tree = ast.parse(git("show", f"{branch}:{path}"))
            checks = []
            if not first_import_is_guard(tree):
                checks.append("preamble")
            if bare_python_spawns(tree):
                checks.append("child_env")
            if checks:
                print(f'    "{path}": {{"lane": {int(lane)}, "checks": {tuple(checks)!r}, '
                      f'"expires": "{args.expires}"}},'.replace("'", '"'))


if __name__ == "__main__":
    main()
