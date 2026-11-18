#!/usr/bin/env python3
"""
CI: the test-suite allow-lists may only SHRINK relative to the base branch (red-team F9/F10).

Checked against ``git show <base>:<path>``:
  * .github/lint-baseline.json      no fingerprint count may grow, no new fingerprint
  * tests/hermetic_known_leaks.py   KNOWN_LEAKS: no new nodeid, no later expiry
                                    FIRESTORE_ALLOWANCE: no new file, no higher count
                                    PREAMBLE_EXEMPT: no new file
                                    PENDING_LANE_FILES: no new path, no new check, no later expiry
The data module is read with ``ast`` (literal values only), never imported or executed.

  python .github/scripts/allowlist_guard.py --base origin/main
"""
import argparse
import ast
import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
LINT = ".github/lint-baseline.json"
LEAKS = "tests/hermetic_known_leaks.py"


def git_show(base, path):
    res = subprocess.run(["git", "show", f"{base}:{path}"], cwd=ROOT, capture_output=True, text=True)
    return res.stdout if res.returncode == 0 else None


def read_head(path):
    p = os.path.join(ROOT, path)
    return open(p, encoding="utf-8").read() if os.path.exists(p) else None


def _literal(node):
    # frozenset({...}) / set() are the only non-literal shapes the data module uses
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("frozenset", "set"):
        return set(ast.literal_eval(node.args[0])) if node.args else set()
    return ast.literal_eval(node)


def leaks_data(src):
    out = {"KNOWN_LEAKS": {}, "FIRESTORE_ALLOWANCE": {}, "PREAMBLE_EXEMPT": set(), "PENDING_LANE_FILES": {}}
    if src is None:
        return out
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in out:
                out[name] = _literal(node.value)
    return out


def lint_data(src):
    return json.loads(src).get("fingerprints", {}) if src else {}


def leaks_problems(base_src, head_src):
    """Shrink-only problems of tests/hermetic_known_leaks.py (head vs base sources). Unit-tested in
    tests/test_hermetic_guard.py."""
    problems = []
    if base_src is None:  # first introduction of the file is allowed
        return problems
    base, head = leaks_data(base_src), leaks_data(head_src)
    for nodeid, meta in head["KNOWN_LEAKS"].items():
        old = base["KNOWN_LEAKS"].get(nodeid)
        if old is None:
            problems.append(f"{LEAKS}: new KNOWN_LEAKS entry {nodeid} (fix the test instead)")
        elif str(meta.get("expires", "")) > str(old.get("expires", "")):
            problems.append(f"{LEAKS}: KNOWN_LEAKS expiry extended for {nodeid}")
    for path, n in head["FIRESTORE_ALLOWANCE"].items():
        if n > base["FIRESTORE_ALLOWANCE"].get(path, 0):
            problems.append(f"{LEAKS}: FIRESTORE_ALLOWANCE[{path}] grew {base['FIRESTORE_ALLOWANCE'].get(path, 0)}"
                            f" -> {n} (inject a fake db instead)")
    for path in sorted(head["PREAMBLE_EXEMPT"] - base["PREAMBLE_EXEMPT"]):
        problems.append(f"{LEAKS}: new PREAMBLE_EXEMPT entry {path} (start the file with `import hermetic_guard`)")
    # Registered once, by lane 2, for other lanes' not-yet-merged files (code-RT finding 3). Never grows.
    for path, meta in head["PENDING_LANE_FILES"].items():
        old = base["PENDING_LANE_FILES"].get(path)
        if old is None:
            problems.append(f"{LEAKS}: new PENDING_LANE_FILES entry {path} (add the preamble / child_env instead)")
            continue
        if set(meta.get("checks", ())) - set(old.get("checks", ())):
            problems.append(f"{LEAKS}: PENDING_LANE_FILES[{path}] exempts more checks than on the base branch")
        if str(meta.get("expires", "")) > str(old.get("expires", "")):
            problems.append(f"{LEAKS}: PENDING_LANE_FILES expiry extended for {path}")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="base ref, e.g. origin/main")
    args = ap.parse_args()
    problems = []

    base_lint, head_lint = lint_data(git_show(args.base, LINT)), lint_data(read_head(LINT))
    if git_show(args.base, LINT) is not None:  # first introduction of the file is allowed
        for fp, n in head_lint.items():
            if n > base_lint.get(fp, 0):
                problems.append(f"{LINT}: '{fp}' grew {base_lint.get(fp, 0)} -> {n}")

    problems.extend(leaks_problems(git_show(args.base, LEAKS), read_head(LEAKS)))

    if problems:
        print("Allow-lists may only shrink:")
        for p in problems:
            print("  - " + p)
        return 1
    print(f"allow-lists OK against {args.base}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
