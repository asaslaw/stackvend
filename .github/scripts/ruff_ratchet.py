#!/usr/bin/env python3
"""
F821 (undefined name) / F811 (redefined unused name) ratchet for CI (FD-60, FD-4AH; red-team F10).

The baseline is a multiset of fingerprints ``path|code|symbol`` (no line numbers, so unrelated edits do not churn it).
CI fails on any fingerprint whose count exceeds the baseline: one lane fixing an F821 cannot hide another lane adding
one. The baseline may only shrink (.github/scripts/allowlist_guard.py compares it with the base branch).

  python .github/scripts/ruff_ratchet.py                 # check (exit 1 on new findings)
  python .github/scripts/ruff_ratchet.py --update        # rewrite the baseline (only ever to remove entries)

ruff runs with --isolated (no repo/user config can exclude files or disable rules), --no-cache and --ignore-noqa
(code red-team finding 5: a `# noqa: F821` comment must not hide a new undefined name from the ratchet; the two test
harnesses that used such comments now bind their exec()-defined names explicitly).

One F811 shape is not counted: a function parameter, or an assignment local to a function, that shadows a module-level
import (the pytest pattern ``from support import gw`` then ``def test_x(gw)``). It rebinds nothing outside the function.
That is decided from ruff's location and the file's AST, one finding at a time. Everything else stays reported:
duplicate ``def test_x`` (the first one silently never runs), re-imports, module-level and class-level rebinding,
``global`` assignments. A file Python cannot parse keeps all its findings and is named on stderr.
"""
import argparse
import ast
import collections
import io
import json
import os
import re
import subprocess
import sys
import tokenize

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BASELINE = os.path.join(ROOT, ".github", "lint-baseline.json")
SELECT = "F821,F811"
_SYMBOL = re.compile(r"`([^`]+)`")
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_SCOPES = _FUNCTIONS + (ast.ClassDef, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def fingerprint(item):
    path = os.path.relpath(item["filename"], ROOT).replace(os.sep, "/")
    m = _SYMBOL.search(item.get("message", ""))
    return f"{path}|{item['code']}|{m.group(1) if m else item.get('message', '')}"


def _in_scope(nodes):
    """Yield ``nodes`` and their descendants, without entering a nested scope (the scope's own node is yielded)."""
    stack = list(nodes)
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _SCOPES):
            stack.extend(ast.iter_child_nodes(node))


def _module_imports(tree):
    names = set()
    for node in _in_scope(tree.body):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
    return names


def _target_names(target):
    if isinstance(target, ast.Name):
        yield target
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _target_names(element)
    elif isinstance(target, ast.Starred):
        yield from _target_names(target.value)


def _parameters(func):
    args = func.args
    return [*args.posonlyargs, *args.args, *args.kwonlyargs, *filter(None, (args.vararg, args.kwarg))]


def _local_assignments(func):
    body = func.body if isinstance(func.body, list) else [func.body]
    nodes = list(_in_scope(body))
    outer = {name for n in nodes if isinstance(n, (ast.Global, ast.Nonlocal)) for name in n.names}
    for node in nodes:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            targets = [node.target]
        else:
            continue
        for target in targets:
            for name in _target_names(target):
                if name.id not in outer:  # a `global x` assignment does rebind the module-level name
                    yield name


def import_shadow_sites(source):
    """(row, column) of each parameter / function-local assignment named after a module-level import.

    ``source`` is the file's bytes. Rows and columns are 1-based and count characters, as ruff's JSON does; ``ast``
    counts UTF-8 bytes. Raises what the parse raises: the caller decides what an unparseable file means.
    """
    encoding, _ = tokenize.detect_encoding(io.BytesIO(source).readline)
    text = source.decode(encoding)
    tree = ast.parse(text)
    lines = text.encode("utf-8").splitlines()
    imports = _module_imports(tree)
    sites = set()
    for func in ast.walk(tree):
        if isinstance(func, _FUNCTIONS):
            for node in _parameters(func):
                if node.arg in imports:
                    sites.add((node.lineno, node.col_offset))
            for node in _local_assignments(func):
                if node.id in imports:
                    sites.add((node.lineno, node.col_offset))
    return {(row, len(lines[row - 1][:col].decode("utf-8")) + 1) for row, col in sites}


def drop_import_shadows(items):
    """Split ruff's JSON findings into (kept, number skipped, unparseable paths). Only F811 is ever skipped."""
    kept, skipped, unparseable, sites_by_file = [], 0, [], {}
    for item in items:
        if item.get("code") == "F811":
            path = item["filename"]
            if path not in sites_by_file:
                try:
                    with open(path, "rb") as fh:
                        sites_by_file[path] = import_shadow_sites(fh.read())
                except (OSError, SyntaxError, ValueError, RecursionError) as exc:
                    sites_by_file[path] = frozenset()
                    unparseable.append((path, exc))
            location = item["location"]
            if (location["row"], location["column"]) in sites_by_file[path]:
                skipped += 1
                continue
        kept.append(item)
    return kept, skipped, unparseable


def run_ruff(ruff):
    files = subprocess.run(["git", "ls-files", "-z", "*.py"], cwd=ROOT, check=True, capture_output=True,
                           text=True).stdout.split("\0")
    files = [f for f in files if f]
    out = subprocess.run([ruff, "check", "--isolated", "--no-cache", "--ignore-noqa", "--select", SELECT,
                          "--output-format", "json", "--exit-zero", *files],
                         cwd=ROOT, check=True, capture_output=True, text=True).stdout
    kept, skipped, unparseable = drop_import_shadows(json.loads(out or "[]"))
    for path, exc in unparseable:
        print(f"WARNING: cannot parse {os.path.relpath(path, ROOT)} ({type(exc).__name__}: {exc}); "
              "all its F811 findings stay reported", file=sys.stderr)
    return collections.Counter(fingerprint(i) for i in kept), skipped


def load(path):
    if not os.path.exists(path):
        return collections.Counter()
    with open(path, encoding="utf-8") as fh:
        return collections.Counter(json.load(fh).get("fingerprints", {}))


def save(path, counter):
    data = {
        "_comment": "F821/F811 fingerprints (path|code|symbol: count) accepted on main. May only shrink. "
                    "Regenerate with: python .github/scripts/ruff_ratchet.py --update",
        "select": SELECT,
        "total": sum(counter.values()),
        "fingerprints": dict(sorted(counter.items())),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ruff", default="ruff")
    ap.add_argument("--baseline", default=BASELINE)
    ap.add_argument("--update", action="store_true")
    args = ap.parse_args()
    current, skipped = run_ruff(args.ruff)
    baseline = load(args.baseline)
    new = current - baseline
    fixed = baseline - current
    by_code = collections.Counter(k.split("|")[1] for k in current.elements())
    print(f"ruff {SELECT}: {sum(current.values())} finding(s) {dict(by_code)}; baseline {sum(baseline.values())}; "
          f"new {sum(new.values())}; fixed {sum(fixed.values())}; "
          f"not counted (F811 parameter/local shadowing a module-level import) {skipped}")
    if args.update:
        save(args.baseline, current)
        print(f"wrote {os.path.relpath(args.baseline, ROOT)}")
        return 0
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(f"- ruff {SELECT}: {sum(current.values())} accepted-baseline findings, "
                     f"{sum(new.values())} new, {sum(fixed.values())} fixed\n")
    if fixed:
        print("Fixed since the baseline (shrink it with --update):")
        for k in sorted(fixed):
            print(f"  - {k}")
    if new:
        print("NEW F821/F811 findings (undefined / shadowed names crash at runtime; fix them):")
        for k in sorted(new):
            print(f"  + {k}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
