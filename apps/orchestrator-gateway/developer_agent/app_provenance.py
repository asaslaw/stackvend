"""SAT-49 F4 (follow-up of QA-REPAIR-OWNERSHIP-PARITY): app-code provenance and the removal of unchanged orphan files.

Problem: the developer commit is additive. A relaunch whose new build no longer writes a file of an earlier build
(for example a stale `tests/test_routes.py` importing a dead `routes.py`) leaves it in the repository, outside the
tree the platform validated; QA then fails inside it and no repair can own it.

Record (after a commit of the tree the hallucination stack validated): `workloads/{product_id}.app_provenance` =
{path: {"sha256", "trace_id", "history"}} for every application file the developer's LLM wrote (not `infra/**`,
which `iac_provenance` covers, not `.github/**`). PROVENANCE-HISTORY (owner 11-13, plan
docs/planning/provenance-cleanup-robustness-plan.md): `history` is every version (sha256) the platform committed at that
path, on any branch of the workload, merged or not, oldest first; `sha256` / `trace_id` are the newest. The record is
append-only: a commit adds the versions it wrote and never drops another path or version, also when the commit
deletes the path (the deletion may be on a branch that is never merged). Bounds (fail-safe: a version that is not
recorded makes its file "not platform-written", i.e. kept): APP_PROVENANCE_HISTORY_MAX versions per path (the oldest is
evicted, never the version the dispatch's start tree holds nor the newest); a record over APP_PROVENANCE_MAX paths or
APP_PROVENANCE_SHAS_MAX versions is not written (the stored one stays). A record from before this change
({"sha256", "trace_id"}) reads as a one-version history.

Removal (the next stack-validated developer run of the workload, only when that run read the whole repository;
otherwise SKIPPED_TREE_INCOMPLETE): an orphan is a recorded path that
  * is a Python file (`.py`), not a pytest `conftest.py` (loaded without an import) and not under an Alembic script
    location (`alembic.ini` `script_location`, or a folder holding `env.py` + `script.py.mako`: migrations are
    loaded by directory scan),
  * is in the repository the run started from with bytes whose sha256 is one of the recorded versions (byte-identical
    to a version the platform wrote: any other content is a person's and is never removed),
  * is not in the tree this run validated and commits,
  * is not imported by any Python file that stays in the repository (real `ast` parse; an absolute import is matched
    against every directory of the repository as an import root, the QA runner's rule, so `src/` layouts, pytest
    `pythonpath` and root `tests/` folders are covered and the check keeps a file when in doubt), is not a package
    `__init__.py` with any other file left under its directory, and
  * is not named, by exact equality with one of its dotted module names or path suffixes, in a string constant (or
    one of its tokens, `mod:attr` included) of a remaining Python file, or in a token of ANY remaining non-Python
    file (a Procfile `python -m apps.shop.worker`, `uvicorn.run("worker:app")`, `pytest_plugins`, entry points, an
    `infra/*.tf` container command or startup script, a Makefile, `.env`, Dockerfile, notes); a token that is a path
    matches by component-exact suffix (`/workspace/apps/shop/worker.py`), and a package's `__main__.py` is also
    named by the package (`python -m apps.shop`, `python apps/shop`). These rules can only KEEP a file; a module
    name built at run time (an f-string) is not seen.
A Python file that stays and does not parse, or calls a dynamic import (`__import__`, `import_module`, `exec`,
`eval`, `run_module`, `run_path`, `spec_from_file_location`, `iter_modules`, `walk_packages`, `find_spec`,
`import_string`, `load_module`, `resolve_name`, `module_from_spec`), removes nothing in this run (typed reason).
PROVENANCE-CONSTANT-DYNAMIC-IMPORT (owner 11-13): `__import__("x")` / `import_module("x")` with one positional argument
that is a constant str holding an absolute dotted name (an `ast.Constant`, no keyword such as `package=`) is an
ordinary import of `x`; with an f-string or `+` chain whose constant head starts a dotted name (`f"plugins.{n}"`) every
module whose dotted name could start with that head is kept as imported, and the run goes on. Any other argument still
removes nothing (SKIPPED_DYNAMIC_IMPORT).
Anything not recorded (older runs, a person's files, the platform's own files) is never a candidate. Orphans are
deleted in the same commit as the new build (`commit_and_open_pr(files_to_delete=...)`), so the pull request shows
them.

Every decision is exact path / sha256 / token equality, configparser or an `ast` walk.
"""
from __future__ import annotations

import ast
import configparser
import hashlib
import posixpath
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Set, Tuple

APP_PROVENANCE_FIELD = "app_provenance"
APP_PROVENANCE_MAX = 2000          # paths; a larger record is not written (the Firestore document stays small)
APP_PROVENANCE_HISTORY_MAX = 16    # PROVENANCE-HISTORY: versions kept per path (oldest evicted, never the pinned one)
APP_PROVENANCE_SHAS_MAX = 4000     # versions in the whole record; a larger record is not written
HISTORY_FIELD = "history"
# RT R3: the version the path had in the last start tree that was the default branch (a regeneration's start tree);
# the per-path bound never evicts it, so a run of unmerged commits can never push the default branch's version out
BASE_FIELD = "base"
SUMMARY_LIST_MAX = 200             # paths listed per kind in the persisted summary

# summary status values
STATUS_OFF = "OFF"                                  # no store, or the hallucination stack did not run
STATUS_UNAVAILABLE = "APP_PROVENANCE_UNAVAILABLE"   # the record could not be read: nothing is removed
STATUS_NO_RECORD = "NO_RECORD"                      # no record yet (first run since this feature): nothing removed
STATUS_CHECKED = "CHECKED"
STATUS_SKIPPED_UNPARSEABLE = "SKIPPED_UNPARSEABLE_FILE"
STATUS_SKIPPED_DYNAMIC_IMPORT = "SKIPPED_DYNAMIC_IMPORT"
STATUS_SKIPPED_TREE_INCOMPLETE = "SKIPPED_TREE_INCOMPLETE"   # the repository was not read completely
STATUS_SKIPPED_INCREMENTAL = "SKIPPED_INCREMENTAL_CHANGE"     # INCREMENTAL-CHANGE-NO-ORPHAN-DELETE: not a full build

# reasons a recorded, unchanged file outside the tree is kept
KEPT_IMPORTED = "IMPORTED_BY_A_REMAINING_FILE"
KEPT_PACKAGE = "PACKAGE_STILL_HAS_FILES"
KEPT_CONFTEST = "PYTEST_CONFTEST"
KEPT_NOT_PYTHON = "NOT_A_PYTHON_FILE"
KEPT_NAMED_IN_STRING = "NAMED_IN_A_STRING"          # a remaining file names it (Procfile, `mod:app`, plugins)
KEPT_MIGRATION = "ALEMBIC_MIGRATION"               # under an Alembic script location
KEPT_RUN_SKIPPED = "RUN_SKIPPED"                    # this run removes nothing (the status says why)

# exact call names of Python's dynamic import machinery (an `ast.Call` whose function is this Name or Attribute)
# PROVENANCE-CONSTANT-DYNAMIC-IMPORT: the two of them whose one constant argument names the module exactly
CONSTANT_IMPORT_CALLS: FrozenSet[str] = frozenset({"__import__", "import_module"})
DYNAMIC_IMPORT_CALLS: FrozenSet[str] = frozenset({"__import__", "import_module", "exec", "eval", "run_module",
                                                  "run_path", "spec_from_file_location", "iter_modules",
                                                  "walk_packages", "find_spec", "import_string", "load_module",
                                                  "resolve_name", "module_from_spec"})


class AppProvenanceUnavailable(RuntimeError):
    pass


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_app_path(path: Any) -> bool:
    """An application path the record may hold: a relative POSIX path outside `infra/` and `.github/`, with no
    empty, `.` or `..` segment and no backslash (a forged entry never reaches the provider's path check)."""
    if not isinstance(path, str) or not path or "\\" in path:
        return False
    parts = path.split("/")
    return all(parts) and not any(p in (".", "..") for p in parts) and parts[0] not in ("infra", ".github")


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64


def _valid_entry(entry: Any) -> bool:
    if not (isinstance(entry, dict) and _is_sha(entry.get("sha256")) and isinstance(entry.get("trace_id"), str)):
        return False
    history = entry.get(HISTORY_FIELD)   # absent = a record from before PROVENANCE-HISTORY (one version)
    base = entry.get(BASE_FIELD)         # absent = no default-branch version recorded (RT R3)
    return ((history is None or (isinstance(history, list) and all(_is_sha(h) for h in history)))
            and (base is None or _is_sha(base)))


def _entry(sha: str, trace_id: str, history: Iterable[str], base: Optional[str] = None) -> Dict[str, Any]:
    """The canonical entry: `history` without duplicates, oldest first, ending with `sha` (the newest), bounded
    (`_evict`); `base` (RT R3: the default branch's version) only when it is one of the recorded versions."""
    hist = [h for h in dict.fromkeys(history) if h != sha] + [sha]
    base = base if _is_sha(base) and base in hist else None
    out: Dict[str, Any] = {"sha256": sha, "trace_id": trace_id, HISTORY_FIELD: _evict(hist, None, base)}
    if base is not None:
        out[BASE_FIELD] = base
    return out


def parse_record(raw: Any) -> Dict[str, Dict[str, Any]]:
    """The usable entries of a stored record, canonical (exact shape only; an entry of any other shape is ignored,
    never repaired: its file is then not platform-written, i.e. kept). Migration: no `history` = [sha256]."""
    if not isinstance(raw, dict):
        return {}
    return {p: _entry(e["sha256"], e["trace_id"], e.get(HISTORY_FIELD) or [], e.get(BASE_FIELD)) for p, e in raw.items()
            if is_app_path(p) and _valid_entry(e)}


def shas_of(entry: Mapping[str, Any]) -> FrozenSet[str]:
    """I-OWN: every version the platform committed at the entry's path (the history, plus the newest sha256)."""
    history = entry.get(HISTORY_FIELD)
    return frozenset([h for h in (history if isinstance(history, list) else []) if _is_sha(h)]
                     + ([entry["sha256"]] if _is_sha(entry.get("sha256")) else []))


def platform_written(entry: Optional[Mapping[str, Any]], content: Any) -> bool:
    """I-OWN: `content` is byte-identical to a version the platform committed at this entry's path."""
    return entry is not None and isinstance(content, str) and sha256(content) in shas_of(entry)


class FirestoreAppProvenanceStore:
    """workloads/{product_id}.app_provenance (the same document as `iac_provenance`)."""

    def __init__(self, db: Any):
        self.db = db

    def load(self, product_id: str) -> Dict[str, Dict[str, Any]]:
        try:
            snap = self.db.collection("workloads").document(product_id).get()
            data = (snap.to_dict() or {}) if snap.exists else {}
        except Exception as e:  # noqa: BLE001 - typed for the caller
            raise AppProvenanceUnavailable(f"app provenance read failed for {product_id}: {type(e).__name__}") from e
        return parse_record(data.get(APP_PROVENANCE_FIELD))

    def save(self, product_id: str, entries: Mapping[str, Mapping[str, Any]]) -> None:
        try:
            self.db.collection("workloads").document(product_id).set(
                {APP_PROVENANCE_FIELD: {p: _copy(e) for p, e in entries.items()}}, merge=[APP_PROVENANCE_FIELD])
        except Exception as e:  # noqa: BLE001 - typed for the caller
            raise AppProvenanceUnavailable(f"app provenance write failed for {product_id}: {type(e).__name__}") from e


    def load_iac_history(self, product_id: str) -> Dict[str, List[str]]:
        try:
            snap = self.db.collection("workloads").document(product_id).get()
            data = (snap.to_dict() or {}) if snap.exists else {}
        except Exception as e:  # noqa: BLE001 - typed for the caller
            raise AppProvenanceUnavailable(f"IaC provenance history read failed for {product_id}: "
                                           f"{type(e).__name__}") from e
        return parse_iac_history(data.get(IAC_HISTORY_FIELD))

    def save_iac_history(self, product_id: str, history: Mapping[str, List[str]]) -> None:
        try:
            self.db.collection("workloads").document(product_id).set(
                {IAC_HISTORY_FIELD: {p: list(h) for p, h in history.items()}}, merge=[IAC_HISTORY_FIELD])
        except Exception as e:  # noqa: BLE001 - typed for the caller
            raise AppProvenanceUnavailable(f"IaC provenance history write failed for {product_id}: "
                                           f"{type(e).__name__}") from e


def _copy(entry: Mapping[str, Any]) -> Dict[str, Any]:
    return {k: (list(v) if isinstance(v, list) else v) for k, v in entry.items()}


class MemoryAppProvenanceStore:
    """Same contract as the Firestore store (load = parse_record of what was saved)."""

    def __init__(self) -> None:
        self.data: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self.iac_history: Dict[str, Dict[str, List[str]]] = {}

    def load(self, product_id: str) -> Dict[str, Dict[str, Any]]:
        return parse_record({p: _copy(e) for p, e in self.data.get(product_id, {}).items()})

    def save(self, product_id: str, entries: Mapping[str, Mapping[str, Any]]) -> None:
        self.data[product_id] = {p: _copy(e) for p, e in entries.items()}

    def load_iac_history(self, product_id: str) -> Dict[str, List[str]]:
        return parse_iac_history({p: list(h) for p, h in self.iac_history.get(product_id, {}).items()})

    def save_iac_history(self, product_id: str, history: Mapping[str, List[str]]) -> None:
        self.iac_history[product_id] = {p: list(h) for p, h in history.items()}


# ------------------------------------------------------------------------------------------- IaC provenance history
# PROVENANCE-HISTORY, IaC part (review 11-13 item 2): `workloads/{id}.iac_provenance` (shared.diagnostics
# ProvenanceEntry, one sha per path, rewritten by every commit) keeps its shape, so an older gateway still reads it.
# Beside it, `iac_provenance_history` = {path: [sha256, ...]} is every version of an LLM-authored IaC file the platform
# committed (any branch, append-only, the same per-path bound). The developer's prior-LLM check accepts a start-tree file
# whose sha256 is the entry's or any recorded version; without the history it is exactly the single-sha check.
IAC_HISTORY_FIELD = "iac_provenance_history"


def _is_iac_history_path(path: Any) -> bool:
    """An IaC history path: a relative POSIX path under `infra/` with no empty, `.` or `..` segment."""
    if not isinstance(path, str) or "\\" in path:
        return False
    parts = path.split("/")
    return len(parts) > 1 and parts[0] == "infra" and all(parts) and not any(p in (".", "..") for p in parts)


def parse_iac_history(raw: Any) -> Dict[str, List[str]]:
    """The usable entries of a stored IaC history (a list of sha256 strings per infra/ path; anything else ignored)."""
    if not isinstance(raw, dict):
        return {}
    return {p: list(dict.fromkeys(h))[-APP_PROVENANCE_HISTORY_MAX:] for p, h in raw.items()
            if _is_iac_history_path(p) and isinstance(h, list) and h and all(_is_sha(x) for x in h)}


def iac_history_after_commit(stored: Mapping[str, List[str]], written: Mapping[str, str]) -> Dict[str, List[str]]:
    """`stored` (every path and version kept) plus each `written` {path: committed sha256} appended (newest last;
    the per-path bound evicts the oldest)."""
    out = {p: list(h) for p, h in stored.items()}
    for p, sha in written.items():
        if _is_iac_history_path(p) and _is_sha(sha):
            out[p] = _evict([h for h in out.get(p, []) if h != sha] + [sha], None)
    return out


# ----------------------------------------------------------------------------------------------- import references
def _call_name(node: ast.AST) -> Optional[str]:
    func = getattr(node, "func", None)
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _prefixes(dotted: str) -> Set[str]:
    """`a.b.c` -> {a, a.b, a.b.c}: importing a module also runs every package above it."""
    parts = dotted.split(".")
    if not all(parts):
        return set()
    return {".".join(parts[:i]) for i in range(1, len(parts) + 1)}


_TOKEN_SEPARATORS = str.maketrans({ch: " " for ch in ":=\"'`,;()[]{}"})


def tokens(text: str) -> Set[str]:
    """`text` split at whitespace and at `: = " ' , ; ( ) [ ] { }` (a Procfile command, a TOML / INI / YAML value,
    `mod:attr`), with a leading `./` dropped. Used only to KEEP a file named exactly by one token."""
    out = set()
    for tok in text.translate(_TOKEN_SEPARATORS).split():
        out.add(tok[2:] if tok.startswith("./") else tok)
    return out


def _is_dotted_name(value: Any) -> bool:
    """An absolute dotted module name (ASCII-or-not identifiers joined by dots; no leading dot, no empty part)."""
    return isinstance(value, str) and bool(value) and all(part.isidentifier() for part in value.split("."))


def _single_argument(node: ast.Call) -> Optional[ast.AST]:
    """The only argument of a call with exactly one positional argument and no keywords / starred, else None."""
    if len(node.args) != 1 or node.keywords or isinstance(node.args[0], ast.Starred):
        return None
    return node.args[0]


def constant_import_name(node: ast.AST) -> Optional[str]:
    """PROVENANCE-CONSTANT-DYNAMIC-IMPORT: `__import__("x.y")` / `import_module("x.y")` (one positional argument that
    is an `ast.Constant` str holding an absolute dotted name, no keyword such as `package=`) imports exactly `x.y`.
    Anything else -> None (the call stays a dynamic import)."""
    if not isinstance(node, ast.Call) or _call_name(node) not in CONSTANT_IMPORT_CALLS:
        return None
    arg = _single_argument(node)
    if isinstance(arg, ast.Constant) and type(arg.value) is str and _is_dotted_name(arg.value):
        return arg.value
    return None


def _constant_head(node: Optional[ast.AST]) -> Optional[str]:
    """The constant text every value of `node` starts with: an f-string whose first part is a constant
    (`f"plugins.{x}"`), or a `+` chain whose leftmost operand is a constant (`"plugins." + x`). Else None."""
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        if isinstance(first, ast.Constant) and type(first.value) is str:
            return first.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = node.left
        while isinstance(left, ast.BinOp) and isinstance(left.op, ast.Add):
            left = left.left
        if isinstance(left, ast.Constant) and type(left.value) is str:
            return left.value
    return None


def import_name_prefix(node: ast.AST) -> Optional[str]:
    """Review 11-13 item 3 (bounding a computed import, typed): `__import__(f"pkg.{x}")` / `import_module("pkg." + x)`
    (the same one-argument shape) can only import a module whose dotted name starts with the constant head `pkg.`;
    every module that could match is then KEPT as imported (sound: it can only keep). A head that is empty or is not
    the start of a dotted name (`f"{x}"`, `f".{x}"`, `f"a b{x}"`) -> None (the call stays a dynamic import)."""
    if not isinstance(node, ast.Call) or _call_name(node) not in CONSTANT_IMPORT_CALLS:
        return None
    head = _constant_head(_single_argument(node))
    if not head:
        return None
    stem = head[:-1] if head.endswith(".") else head
    return head if _is_dotted_name(stem) else None


def reachable_by_prefix(candidate: str, prefixes: Iterable[str]) -> bool:
    """A module name of `candidate` is one an import starting with a prefix can load: the name starts with the prefix
    (`pkg.x`), or is a package the import passes through (`pkg` for the prefix `pkg.` or `pkg.x`)."""
    return any(n.startswith(pre) or pre.startswith(n + ".") for n in module_names(candidate) for pre in prefixes)


def references(importer: str, tree: ast.Module) -> Tuple[Set[str], Set[str], Set[str], bool, Set[str]]:
    """(absolute dotted module names `importer` imports, with every package prefix; repository paths its relative
    imports load; the string constants it holds and their tokens; uses a dynamic import that nothing bounds; the
    constant heads of bounded computed imports). Over-approximates on purpose: an absolute name is matched against
    every directory of the repository as an import root."""
    names: Set[str] = set()
    paths: Set[str] = set()
    strings: Set[str] = set()
    prefixes: Set[str] = set()
    dynamic = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names |= _prefixes(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            subs = [a.name for a in node.names if a.name != "*"]
            if node.level:
                base = posixpath.dirname(importer)
                for _ in range(node.level - 1):
                    base = posixpath.dirname(base)
                pkg = "/".join(([base] if base else []) + (mod.split(".") if mod else []))
                if mod:
                    paths |= {pkg + ".py", pkg + "/__init__.py"}
                elif pkg:
                    paths.add(pkg + "/__init__.py")
                for sub in subs:
                    stem = f"{pkg}/{sub}" if pkg else sub
                    paths |= {stem + ".py", stem + "/__init__.py"}
            elif mod:
                names |= _prefixes(mod)
                for sub in subs:
                    names |= _prefixes(f"{mod}.{sub}")
        elif isinstance(node, ast.Call) and _call_name(node) in DYNAMIC_IMPORT_CALLS:
            constant = constant_import_name(node)
            prefix = import_name_prefix(node) if constant is None else None
            if constant is not None:          # PROVENANCE-CONSTANT-DYNAMIC-IMPORT: an ordinary import
                names |= _prefixes(constant)
            elif prefix is not None:          # bounded computed import: keeps every module it could load
                prefixes.add(prefix)
            else:
                dynamic = True
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.add(node.value)
            strings |= tokens(node.value)
    return names, paths, strings, dynamic, prefixes


def _dotted(comps: List[str]) -> Set[str]:
    return {".".join(comps[i:]) for i in range(len(comps))}


def module_names(path: str) -> Set[str]:
    """Every dotted name the .py file `path` is importable or runnable as, one per directory of the repository used
    as the import root: apps/shop/worker.py -> apps.shop.worker, shop.worker, worker. A package's __init__.py -> the
    package; a package's __main__.py -> its own names and the package's (`python -m apps.shop` runs it, RT F8)."""
    comps = path[:-3].split("/")
    if comps[-1] == "__init__":
        return _dotted(comps[:-1])
    if comps[-1] == "__main__":
        return _dotted(comps) | _dotted(comps[:-1])
    return _dotted(comps)


def path_suffixes(path: str) -> Set[str]:
    """Every component-exact suffix of `path` (`/workspace/apps/shop/worker.py` -> ..., `apps/shop/worker.py`,
    `shop/worker.py`, `worker.py`)."""
    comps = path.split("/")
    return {"/".join(comps[i:]) for i in range(len(comps))}


def candidate_paths(path: str) -> Set[str]:
    """The path suffixes that name the file `path`; a package's __main__.py is also named by its folder
    (`python apps/shop`, RT F8)."""
    out = path_suffixes(path)
    if posixpath.basename(path) == "__main__.py" and posixpath.dirname(path):
        out |= path_suffixes(posixpath.dirname(path))
    return out


def _named(candidate: str, words: Set[str]) -> bool:
    """`words` = every string / token of the remaining files and every component-exact path suffix of each (RT F9:
    an absolute `/workspace/apps/shop/worker.py` names apps/shop/worker.py). Exact equality with one of the
    candidate's module names or paths."""
    return bool((module_names(candidate) | candidate_paths(candidate)) & words)


def migration_dirs(contents: Mapping[str, str]) -> Set[str]:
    """Alembic script directories of the repository: the `script_location` of every `alembic.ini` (configparser;
    `%(here)s` = the file's folder; a `package:dir` value, an absolute one or one outside the repository is not
    resolved here) and every folder holding both `env.py` and `script.py.mako`."""
    out: Set[str] = set()
    for p, text in contents.items():
        base, folder = posixpath.basename(p), posixpath.dirname(p)
        if base == "alembic.ini":
            parser = configparser.ConfigParser(defaults={"here": folder or "."})
            try:
                parser.read_string(text)
                raw = parser.get("alembic", "script_location", raw=True)
                value = parser.get("alembic", "script_location").strip()
            except (configparser.Error, ValueError):
                continue
            if not value or ":" in value or value.startswith("/"):
                continue
            # `%(here)s` already put the ini's folder in front; a plain relative value is relative to that folder
            loc = posixpath.normpath(value if "%(here)s" in raw or not folder else posixpath.join(folder, value))
            if loc != ".." and not loc.startswith("../") and not loc.startswith("/"):
                out.add("" if loc == "." else loc)
        elif base == "env.py" and posixpath.join(folder, "script.py.mako") in contents:
            out.add(folder)
    return out


# ------------------------------------------------------------------------------------------------------- orphans
def find_orphans(record: Mapping[str, Mapping[str, Any]], existing_files: Mapping[str, Any],
                 tree: Mapping[str, Any], *, tree_complete: bool) -> Dict[str, Any]:
    """The removal decision of one run: {"status", "deleted", "kept", "carry", "blocked_by"}.

    `existing_files` = the repository the run started from (`tree_complete`: it was read completely); `tree` = the
    tree it validated and commits. `carry` = the recorded entries of platform-written files that stay outside the
    tree (kept; informational since PROVENANCE-HISTORY, which keeps every entry anyway).
    """
    unchanged = {p: e for p, e in record.items() if p not in tree and platform_written(e, existing_files.get(p))}
    if tree_complete is not True:
        return _decision(STATUS_SKIPPED_TREE_INCOMPLETE, [], {p: KEPT_RUN_SKIPPED for p in unchanged}, unchanged)
    contents: Dict[str, str] = {p: c for p, c in existing_files.items() if isinstance(c, str)}
    contents.update({p: c for p, c in tree.items() if isinstance(c, str)})
    migrations = migration_dirs(contents)
    kept: Dict[str, str] = {}
    candidates: Set[str] = set()
    for p in unchanged:
        if not p.endswith(".py"):
            kept[p] = KEPT_NOT_PYTHON
        elif posixpath.basename(p) == "conftest.py":
            kept[p] = KEPT_CONFTEST
        elif any(d == "" or p.startswith(d + "/") for d in migrations):
            kept[p] = KEPT_MIGRATION
        else:
            candidates.add(p)

    # every remaining non-Python file is the same in every round (never a candidate) and is tokenised (RT F7:
    # infra/*.tf container args and startup scripts, .tfvars, Makefile, .env, .conf, Dockerfile, notes, ...)
    config_tokens: Set[str] = set()
    for p, text in contents.items():
        if not p.endswith(".py"):
            config_tokens |= tokens(text)
    parsed: Dict[str, Tuple[Set[str], Set[str], Set[str], bool, Set[str]]] = {}

    def _refs(path: str) -> Optional[Tuple[Set[str], Set[str], Set[str], bool, Set[str]]]:
        if path not in parsed:
            try:
                parsed[path] = references(path, ast.parse(contents[path]))
            except (SyntaxError, ValueError):
                return None
        return parsed[path]

    def _skipped(status: str, blocker: str) -> Dict[str, Any]:
        return _decision(status, [], dict(kept, **{c: KEPT_RUN_SKIPPED for c in candidates}), unchanged,
                         blocked_by=blocker)

    while True:
        remaining = [p for p in contents if p not in candidates]
        names: Set[str] = set()
        paths: Set[str] = set()
        strings: Set[str] = set(config_tokens)
        prefixes: Set[str] = set()
        for p in remaining:
            if not p.endswith(".py"):
                continue
            got = _refs(p)
            if got is None:
                return _skipped(STATUS_SKIPPED_UNPARSEABLE, p)
            if got[3]:
                return _skipped(STATUS_SKIPPED_DYNAMIC_IMPORT, p)
            names |= got[0]
            paths |= got[1]
            strings |= got[2]
            prefixes |= got[4]
        words: Set[str] = set()
        for w in strings:
            words |= path_suffixes(w)
        newly: Dict[str, str] = {}
        for c in candidates:
            if c in paths or module_names(c) & names or (prefixes and reachable_by_prefix(c, prefixes)):
                newly[c] = KEPT_IMPORTED
            elif _named(c, words):
                newly[c] = KEPT_NAMED_IN_STRING
            elif posixpath.basename(c) == "__init__.py":
                pkg = posixpath.dirname(c)
                prefix = pkg + "/" if pkg else ""
                if any(r != c and r.startswith(prefix) for r in remaining):
                    newly[c] = KEPT_PACKAGE
        if not newly:
            break
        kept.update(newly)
        candidates -= set(newly)
    return _decision(STATUS_CHECKED, sorted(candidates), kept, unchanged)


REMOVABLE = "REMOVABLE"


def removal_outlook(record: Mapping[str, Mapping[str, Any]], base_files: Mapping[str, Any],
                    path: str, replaced: Iterable[str] = ()) -> Tuple[bool, str, Optional[str]]:
    """QA-FINDING-ON-UNOWNED-FILE: whether ANY regeneration starting from `base_files` (the default branch, read
    completely) could have this cleanup delete `path`: the most favourable regeneration writes nothing at all, so
    `find_orphans(record, base_files, {})` (more written files only keep more). (True, REMOVABLE, None) or (False,
    the kept reason or the skip status, the blocking file). The same rules as the cleanup itself: no second
    ownership definition. `replaced`: the paths the tested commit wrote (committed_draft.committed_paths): every
    regeneration writes them again (the platform re-renders its own files, such as the plan document that lists the
    build's files), so their default-branch copies never keep `path` here."""
    gone = set(replaced or ()) - {path}
    base_files = {p: c for p, c in base_files.items() if p not in gone}
    d = find_orphans(record, base_files, {}, tree_complete=True)
    if path in d["deleted"]:
        return True, REMOVABLE, None
    if d["status"] != STATUS_CHECKED:
        return False, d["status"], d["blocked_by"]
    return False, d["kept"].get(path, "NOT_A_CANDIDATE"), None


def _decision(status: str, deleted: List[str], kept: Dict[str, str], unchanged: Mapping[str, Mapping[str, str]],
              blocked_by: Optional[str] = None) -> Dict[str, Any]:
    gone = set(deleted)
    return {"status": status, "deleted": list(deleted), "kept": dict(sorted(kept.items())),
            "carry": {p: dict(e) for p, e in unchanged.items() if p not in gone}, "blocked_by": blocked_by}


def incremental_decision(decision: Mapping[str, Any]) -> Dict[str, Any]:
    """INCREMENTAL-CHANGE-NO-ORPHAN-DELETE (owner 11-14): a dispatch that did not generate the whole application (a
    SOLO_FAST_PATH change, a QA or deploy repair of given files) deletes nothing it derived: every file the full-build
    rule would have removed is kept (RUN_SKIPPED), status SKIPPED_INCREMENTAL_CHANGE. Decided by the caller from typed
    data (the repair plan, the lead's execution mode), never from text."""
    kept = dict(decision.get("kept") or {})
    kept.update({p: KEPT_RUN_SKIPPED for p in (decision.get("deleted") or [])})
    return dict(decision, status=STATUS_SKIPPED_INCREMENTAL, deleted=[], kept=dict(sorted(kept.items())))


def summary(decision: Mapping[str, Any]) -> Dict[str, Any]:
    """The persisted, bounded form (every key always present)."""
    kept = list((decision.get("kept") or {}).items())
    deleted = list(decision.get("deleted") or [])
    return {"status": decision.get("status"), "deleted": deleted[:SUMMARY_LIST_MAX], "deleted_count": len(deleted),
            "kept": dict(kept[:SUMMARY_LIST_MAX]), "kept_count": len(kept),
            "blocked_by": decision.get("blocked_by"), "error": decision.get("error")}


def _evict(history: List[str], pin: Optional[str], base: Optional[str] = None) -> List[str]:
    """APP_PROVENANCE_HISTORY_MAX: drop the oldest versions, never `pin` (the start tree's version), `base` (RT R3: the
    default branch's version) nor the newest."""
    hist = list(history)
    while len(hist) > APP_PROVENANCE_HISTORY_MAX:
        drop = next((i for i, h in enumerate(hist[:-1]) if h != pin and h != base), None)
        if drop is None:
            break
        del hist[drop]
    return hist


def record_for_commit(llm_paths: Iterable[str], files: Mapping[str, Any], trace_id: str,
                      stored: Mapping[str, Mapping[str, Any]],
                      pins: Optional[Mapping[str, str]] = None,
                      base_pins: Optional[Mapping[str, str]] = None) -> Dict[str, Dict[str, Any]]:
    """PROVENANCE-HISTORY: the record after a commit of `files` = the STORED record (every entry and version kept,
    whatever this commit wrote or deleted, on whatever branch) plus, for each of this run's LLM application files,
    the committed version appended to its history (newest last; sha256 / trace_id = this commit). `pins` = {path:
    sha256 of the path in the dispatch's start tree}: that version is never evicted by the per-path bound.
    RT R3: `base_pins` = the same map, given only by a dispatch whose start tree is the default branch: each recorded
    version in it becomes the entry's `base`, which no later commit evicts (a QA-repair dispatch starts from a tested
    branch and passes none, so `base` stays the default branch's version through any run of unmerged commits)."""
    entries: Dict[str, Dict[str, Any]] = {p: _copy(e) for p, e in stored.items()}
    for p, sha in (base_pins or {}).items():
        e = entries.get(p)
        if e is not None and sha in shas_of(e):
            e[BASE_FIELD] = sha
        elif e is not None:
            e.pop(BASE_FIELD, None)      # the default branch holds no platform version of it any more
    for p in dict.fromkeys(llm_paths):
        if not (is_app_path(p) and isinstance(files.get(p), str)):
            continue
        sha = sha256(files[p])
        old = entries.get(p)
        older = (old.get(HISTORY_FIELD) or [old["sha256"]]) if old else []
        base = old.get(BASE_FIELD) if old else None
        entry = {"sha256": sha, "trace_id": trace_id,
                 HISTORY_FIELD: _evict([h for h in older if h != sha] + [sha], (pins or {}).get(p), base)}
        if base is not None and base in entry[HISTORY_FIELD]:
            entry[BASE_FIELD] = base
        entries[p] = entry
    return entries


def record_too_large(entries: Mapping[str, Mapping[str, Any]]) -> Optional[str]:
    """Why a record must not be written (the stored one then stays as it is: every entry in it is still true), or
    None."""
    if len(entries) > APP_PROVENANCE_MAX:
        return f"{len(entries)} paths, more than {APP_PROVENANCE_MAX}"
    versions = sum(len(shas_of(e)) for e in entries.values())
    if versions > APP_PROVENANCE_SHAS_MAX:
        return f"{versions} versions, more than {APP_PROVENANCE_SHAS_MAX}"
    return None


def start_tree_pins(record: Mapping[str, Mapping[str, Any]], existing_files: Mapping[str, Any]) -> Dict[str, str]:
    """{recorded path: sha256 of its bytes in the dispatch's start tree} (the versions the per-path bound keeps)."""
    return {p: sha256(c) for p in record for c in [existing_files.get(p)] if isinstance(c, str)}
