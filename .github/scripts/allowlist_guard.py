#!/usr/bin/env python3
"""
CI: the test-suite allow-lists may only SHRINK relative to the base branch (red-team F9/F10).

Checked against ``git show <base>:<path>``:
  * .github/lint-baseline.json      no fingerprint count may grow, no new fingerprint, except a code the head newly
                                    selects (seeded once); select keeps every base code; max_complexity
                                    present and never raised (lint_problems)
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
LEGACY_SELECT = "F821,F811"  # what a baseline written before it recorded `select` held (FD-60)


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
    return json.loads(src) if src else {}


def _codes(select):
    return {c.strip() for c in select.split(",") if c.strip()} if isinstance(select, str) else set()


def _is_int(value):
    return type(value) is int


def lint_problems(base_src, head_src):
    """Shrink-only problems of .github/lint-baseline.json (head vs base sources). Unit-tested in
    tests/test_ruff_ratchet.py.

    * every code in the base's ``select`` stays selected (head ``select`` is a superset of base ``select``);
    * a fingerprint of a code in base ``select`` may not be added or grow;
    * a fingerprint of a code the head newly selects (in head ``select``, not in base ``select``) may be added: a newly
      selected code seeds its list once, after which the base selects it and it is shrink-only (FD-85 seeding rule);
    * head ``max_complexity`` must be an integer, and no higher than base's when the base records one.
    A base that predates the ``select`` key is read as LEGACY_SELECT, the only codes such a baseline ever held."""
    problems = []
    if base_src is None:  # first introduction of the file is allowed
        return problems
    base, head = lint_data(base_src), lint_data(head_src)
    base_select = _codes(base.get("select", LEGACY_SELECT))
    head_select = _codes(head.get("select"))
    seeding = head_select - base_select
    for code in sorted(base_select - head_select):
        problems.append(f"{LINT}: select no longer includes {code} (head select must include every base code)")
    base_fp, head_fp = base.get("fingerprints", {}), head.get("fingerprints", {})
    for fp, n in sorted(head_fp.items()):
        old = base_fp.get(fp, 0)
        if n <= old:
            continue
        parts = fp.split("|")
        if len(parts) == 3 and parts[1] in seeding:  # exactly path|code|symbol: a '|' in a path never seeds
            continue  # seeds the list of a code the head newly selects
        problems.append(f"{LINT}: '{fp}' grew {old} -> {n}")
    head_mc, base_mc = head.get("max_complexity"), base.get("max_complexity")
    if not _is_int(head_mc):
        problems.append(f"{LINT}: max_complexity is {head_mc!r} (missing or not an integer)")
    elif _is_int(base_mc) and head_mc > base_mc:
        problems.append(f"{LINT}: max_complexity raised {base_mc} -> {head_mc} (the threshold may only go down)")
    return problems


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
    # Fail closed: a base that is not a commit would make every file read as "first introduction" (all checks skipped).
    if subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{args.base}^{{commit}}"], cwd=ROOT,
                      capture_output=True).returncode != 0:
        print(f"ERROR: base {args.base!r} is not a commit in this checkout (BASE_NOT_FOUND); nothing was checked")
        return 2
    problems = []

    problems.extend(lint_problems(git_show(args.base, LINT), read_head(LINT)))
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
