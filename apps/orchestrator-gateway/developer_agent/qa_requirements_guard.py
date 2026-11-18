"""QA-REPAIR-ON-IMPORT-FAILURE (register row): what a QA repair may do to `apps/<service>/requirements.txt` on the
import-failure path (`qa_repair.is_import_failure`). Pure functions: no I/O, no LLM.

Why a guard is needed. The failure text the repair reads is produced by the code under repair, so it is untrusted, and
nothing after a repair relates a package NAME to the code: the gatekeeper's `reconcile_service_requirements` only
appends catalog needs and never removes a line; V4 (`validators/step1.py`) only parses lines and skips pip options; the
QA job's `check_requirements` refuses URLs, paths and options one QA round later but accepts any PEP 508 name, which
pip then installs. Without this guard, a sentence in QA's output could add any package to the deployed app.

The rule, applied to every candidate before it is assembled (repair_loop `RepairLoop._attempt`):
- pip reads the candidate as the UTF-8 text checked here. pip decodes the file with the codec a comment in its first two
  lines names (`pip._internal.req.req_file`, PEP 263), so every other check here would otherwise read text pip does not
  read. The rule is the QA job's (`apps/qa-runner` `pip_reads_other_text`; parity tests on it and on the installed pip),
  on both views of the first two lines: the file as committed (pip splits on the newline byte for this) and after the
  deploy's harmonizer has rejoined `splitlines()` with newlines (a comment behind a form feed moves up to line 2 there).
  A byte-order mark at the very start wins over any comment and reads as UTF-8; U+FEFF anywhere else is refused. A
  comment is refused when decoding the file with its codec gives other text than UTF-8 does, or fails. So a declaration
  the tested file carries no longer blocks the repair (`# -*- coding: utf-8 -*-`, a BOM, `# coding: latin-1` over ASCII).
  What the repair itself introduces is held to more: a BOM the tested file lacks is refused, and so is a declaration of
  any codec but UTF-8 that pip did not use on the tested file, even over text it reads the same today, because the next
  byte added could then read differently. An added UTF-8 declaration is accepted: it cannot change pip's reading.
- Add-only: the tested file's lines stay, exact and in order. Blank lines and comments may be added.
- An added requirement is one PEP 508 name requirement (`packaging`, the parser pip and the QA job use) with optional
  extras and plain version specifiers (no local version `+x`, no arbitrary equality `===`). Refused: URLs and VCS references (`name @ url`, a bare URL), paths, archive file names
  (pip reads `x.whl` as a file), every pip option (`-r`, `-e`, `-c`, `--index-url`, `--extra-index-url`, `--hash`),
  environment markers (they can make QA and the deployed app install different things) and backslash continuations
  (pip joins the next line, so the line this guard read would not be the line pip reads; a comment line neither
  continues nor joins the next line in pip, so its trailing backslash is not one).
- The name is not already declared, so an addition cannot re-pin or downgrade an existing dependency.
- The name is related to what the TESTED code imports (`imported_names`, AST facts only). The tested tree is used, never
  the candidate: the repair may also edit the service's entry file, so it could otherwise add `import x` and `x` together.

The crash path (QA-REPAIR-CRASH-REQUIREMENTS-GUARD, `add_only=False`) may need to re-pin a pytest plugin, so lines may
change or go there. The encoding rule and the per-line rules hold for every line the repair wrote, and every resulting
name must be already declared, imported by the tested code, or the QA runner's own test toolchain or pinned plugins.

A candidate that breaks any of this is rejected whole with the typed reason REQUIREMENTS_ADDITION_REFUSED (invariant 8):
no line is dropped silently and nothing of it is committed. The attempt counts against the loop's limits.

What "related" covers, and its limit. Related = the contract's own proven needs (`service_needs`), plus each non-local,
non-stdlib import's root, plus the exact table `IMPORT_PATH_DISTRIBUTIONS` (`google.auth.transport.requests` needs the
distribution `requests`, which neither its root nor the catalog's answer names). Only for an import the catalog
(`resolve_import_to_pypi`) has no answer for, the last component of its dotted module path and a lower-case name imported
from a dotted module also count, because that is the only hint of its distribution. A path the catalog answers adds
nothing else: `fastapi.responses` does not relate to `responses`, nor `from google.cloud import storage` to `storage` or
`cloud`. So a repair cannot introduce a name the tested code does not already use in an import. It is not a malware
check: a name that appears in an uncatalogued import path is accepted if it is on the index, and a real need the code
never names (a driver chosen only by a database URL) is refused, unless QA-REPAIR-MISSING-MODULE allows it: the QA
runner's typed missing module, mapped through the closed catalog (qa_repair.missing_module_of), adds exactly that one
distribution to the allowed names (the only one, for a requirements file the gatekeeper's contract wrote).
"""
from __future__ import annotations

import ast
import codecs
import logging
import re
from dataclasses import dataclass, replace
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Set, Tuple

from packaging.requirements import InvalidRequirement, Requirement

from gatekeeper_agent.pypi_catalog import STDLIB_MODULES, resolve_import_to_pypi
from gatekeeper_agent.requirements_contract import (QA_RUNNER_TEST_TOOLCHAIN, canonical_name, declared_names,
                                                    requirement_name, root_test_files, root_test_local_modules,
                                                    root_tests_service, service_needs, service_top_level_modules)

logger = logging.getLogger("castor-qa-requirements-guard")

REQUIREMENTS_REFUSED = "REQUIREMENTS_ADDITION_REFUSED"   # the repair loop's typed reject reason (RepairEvent)

EXISTING_LINE_CHANGED = "EXISTING_LINE_CHANGED"
LINE_CONTINUATION = "LINE_CONTINUATION"
PIP_OPTION = "PIP_OPTION"
NOT_A_NAME_REQUIREMENT = "NOT_A_NAME_REQUIREMENT"
URL_REQUIREMENT = "URL_REQUIREMENT"
ENVIRONMENT_MARKER = "ENVIRONMENT_MARKER"
ARCHIVE_FILE_NAME = "ARCHIVE_FILE_NAME"
ALREADY_DECLARED = "ALREADY_DECLARED"
NOT_IMPORTED_BY_SERVICE = "NOT_IMPORTED_BY_SERVICE"
NOT_TEXT = "NOT_TEXT"
ENCODING_DECLARATION = "ENCODING_DECLARATION"
VERSION_NOT_PLAIN = "VERSION_NOT_PLAIN"
TESTED_CONTENT_MISSING = "TESTED_CONTENT_MISSING"

# pip's own PEP 263 pattern, a bytes pattern (`pip._internal.req.req_file.PEP263_ENCODING_RE`; parity test on the
# installed pip). Bytes on purpose: on `str`, its classes would also match non-ASCII characters, which pip's does not.
PIP_PEP263_ENCODING_RE = re.compile(rb"coding[:=]\s*([-\w.]+)")
BYTE_ORDER_MARK = "\ufeff"
# A whole line that is a comment to pip's `join_lines` (its COMMENT_RE, matched at the start of the line).
COMMENT_LINE_RE = re.compile(r"^\s*#")
# An import path whose distribution neither its root nor the catalog names. Exact paths only; google-auth declares
# `requests` only as an extra of its own, so the service has to declare it (test: every form of this import).
IMPORT_PATH_DISTRIBUTIONS = {"google.auth.transport.requests": "requests"}
# QA-REPAIR-CRASH-REQUIREMENTS-GUARD: the pytest plugins pinned in apps/qa-runner/qa_toolchain_constraints.txt that the
# job does not install itself (parity test against the file and Toolchain.test_packages).
QA_PINNED_TEST_PLUGINS = frozenset({"pytest-asyncio"})
QA_TEST_TOOL_NAMES = QA_RUNNER_TEST_TOOLCHAIN | QA_PINNED_TEST_PLUGINS

# pip's own archive extensions (pip._internal.utils.filetypes.ARCHIVE_EXTENSIONS): such a "name" is a file to pip.
ARCHIVE_SUFFIXES = (".zip", ".whl", ".tar.bz2", ".tbz", ".tar.gz", ".tgz", ".tar", ".tar.xz", ".txz", ".tlz", ".tar.lz",
                    ".tar.lzma")


@dataclass(frozen=True)
class Refusal:
    path: str
    line: int                     # 1-based line of the candidate (of the tested file for EXISTING_LINE_CHANGED)
    reason: str
    name: Optional[str] = None    # the canonical name, only after the parser accepted it (never raw candidate text)
    add_only: bool = True         # False: found on the crash path, where lines may change (the feedback says so)


def _strip_comment(line: str) -> str:
    """pip's requirements-file comment rule (as V4 and the QA job): `#` at the start or after whitespace."""
    for i, ch in enumerate(line):
        if ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


def _path_names(path: str, answered: bool = False) -> Set[str]:
    """Names one dotted import path relates to: its root, its exact entry in IMPORT_PATH_DISTRIBUTIONS, and its last
    component when nothing else can name the distribution: the catalog has no answer for it (`answered`: nor for
    another part of the same import statement), and that component is dotted and lower-case."""
    parts = path.split(".")
    last = parts[-1]
    out = {canonical_name(parts[0])}
    if path in IMPORT_PATH_DISTRIBUTIONS:
        out.add(canonical_name(IMPORT_PATH_DISTRIBUTIONS[path]))
    elif (not answered and len(parts) > 1 and last == last.lower() and last not in STDLIB_MODULES
          and resolve_import_to_pypi(path) is None):
        out.add(canonical_name(last))
    return out


def _import_path_names(tree: ast.AST, local: Set[str]) -> Set[str]:
    """Canonical names the import statements of one file relate to (module docstring). A local or stdlib root is not a
    distribution; a relative import is local."""
    out: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root not in local and root not in STDLIB_MODULES:
                    out |= _path_names(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            parts = node.module.split(".")
            if parts[0] in local or parts[0] in STDLIB_MODULES:
                continue
            # `from a.b import c`: c may be a submodule; from a bare package it is an attribute. A dotted name the
            # catalog answers for one imported name is an answer for the statement (`from google.cloud import storage`)
            imported = [f"{node.module}.{alias.name}" for alias in node.names if alias.name != "*"]
            out |= _path_names(node.module, answered=any(resolve_import_to_pypi(p) for p in imported))
            if len(parts) > 1:
                for path in imported:
                    out |= _path_names(path)
    return out


def imported_names(tree: Mapping[str, Any], service: str) -> FrozenSet[str]:
    """The canonical distribution names the tested code of `apps/<service>/` relates to (and, for the single service
    of a repository-root `tests/`, those test files: the QA job runs them with this service's venv). Never raises; a
    file that cannot be read adds nothing, and an unreadable tree relates to nothing, so additions are refused."""
    files: Dict[str, str] = {p: c for p, c in (tree or {}).items() if isinstance(p, str) and isinstance(c, str)}
    prefix = f"apps/{service}/"
    try:
        names = {n for n in (requirement_name(spec) for spec in service_needs(files, service)) if n}
        groups = [([p for p in sorted(files) if p.startswith(prefix) and p.endswith(".py")],
                   service_top_level_modules(files, service))]
        if root_tests_service(files) == service:
            groups.append((root_test_files(files), root_test_local_modules(files, service)))
        for paths, local in groups:
            for path in paths:
                try:
                    names |= _import_path_names(ast.parse(files[path]), local)
                except (SyntaxError, ValueError):
                    continue
    except Exception as e:  # noqa: BLE001 - e.g. RecursionError on a hostile file: fail closed, additions are refused
        logger.warning(f"QA requirements guard: imports of {prefix} could not be read ({type(e).__name__})")
        return frozenset()
    return frozenset(names - QA_RUNNER_TEST_TOOLCHAIN)


def _declarations(text: str) -> List[Tuple[int, str, bytes]]:
    """(line, codec name, the bytes pip would decode) of the declaration pip obeys in each view of `text` (module
    docstring). Mirrors the QA job's `pip_reads_other_text`: a BOM wins, and pip stops at the first declaration."""
    if text[:1] == BYTE_ORDER_MARK:
        return []
    found: List[Tuple[int, str, bytes]] = []
    views = (text.encode("utf-8", "surrogatepass"), "\n".join(text.splitlines()).encode("utf-8", "surrogatepass"))
    for view in views:
        for lineno, line in enumerate(view.split(b"\n")[:2], 1):
            match = PIP_PEP263_ENCODING_RE.search(line) if line[0:1] == b"#" else None
            if match is not None:
                found.append((lineno, match.group(1).decode("ascii"), view))
                break
    return found


def _reads_other_text(view: bytes, codec: str) -> bool:
    """True when pip, told to use `codec`, would read something else than the UTF-8 text checked here, or fail."""
    try:
        return view.decode(codec) != view.decode("utf-8")
    except (LookupError, UnicodeError):
        return True


def _codec_name(codec: str) -> str:
    """The codec's canonical name, so `UTF8` and `utf-8` are one codec; an unknown name stands for itself."""
    try:
        return codecs.lookup(codec).name
    except LookupError:
        return codec.lower()


def _encoding_refusal(path: str, text: str, tested: str) -> Optional[Refusal]:
    """The refusal when pip would (or the deploy's harmonizer would let pip) decode the candidate `text` into anything but
    the UTF-8 text checked here, or when the repair introduced a BOM or a non-UTF-8 declaration the `tested` file did not
    have (module docstring). Text that cannot be encoded is not a file pip could read at all."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return Refusal(path, 0, NOT_TEXT)
    if BYTE_ORDER_MARK in text[1:] or (text[:1] == BYTE_ORDER_MARK and tested[:1] != BYTE_ORDER_MARK):
        return Refusal(path, 1, ENCODING_DECLARATION)
    used = {"utf-8"} | {_codec_name(codec) for _line, codec, _view in _declarations(tested)}
    for lineno, codec, view in _declarations(text):
        if _reads_other_text(view, codec) or _codec_name(codec) not in used:
            return Refusal(path, lineno, ENCODING_DECLARATION)
    return None


def check_requirements_edit(path: str, before: str, after: Any, allowed: Iterable[str],
                            add_only: bool = True) -> List[Refusal]:
    """Every reason the candidate `after` of the tested file `before` is refused ([] = accepted; module docstring).
    `add_only=False` is the crash path's mode: `allowed` plus what the file declared are the names it may hold.
    Lines are split as pip splits them (`splitlines`, so a form feed or U+2028 cannot hide a line from this check)."""
    if not isinstance(after, str):
        return [Refusal(path, 0, NOT_TEXT)]
    if after == before:
        return []
    encoding = _encoding_refusal(path, after, before)
    if encoding is not None:
        return [encoding]
    # pip drops a leading BOM before it reads any line, so the rules below read what pip reads.
    before, after = before.removeprefix(BYTE_ORDER_MARK), after.removeprefix(BYTE_ORDER_MARK)
    allowed_names = frozenset(allowed)
    old, new = before.splitlines(), after.splitlines()
    if not add_only:
        return _replaced_file_refusals(path, before, old, new, allowed_names)
    refusals: List[Refusal] = []
    added: List[int] = []
    matched = 0
    for i, line in enumerate(new):
        if matched < len(old) and line == old[matched]:
            matched += 1
        else:
            added.append(i)
    if matched < len(old):
        return [Refusal(path, matched + 1, EXISTING_LINE_CHANGED)]
    declared = set(declared_names(before))
    for i in added:
        refusal, name = _line_refusal(path, new, i)
        if refusal is not None:
            refusals.append(refusal)
        elif name is None:
            continue
        elif name in declared:
            refusals.append(Refusal(path, i + 1, ALREADY_DECLARED, name))
        elif name not in allowed_names:
            refusals.append(Refusal(path, i + 1, NOT_IMPORTED_BY_SERVICE, name))
        else:
            declared.add(name)   # the same name twice in one candidate is a re-declaration
    return refusals


def _line_refusal(path: str, lines: List[str], i: int) -> Tuple[Optional[Refusal], Optional[str]]:
    """(the per-line refusal of `lines[i]`, or None; its canonical name when it is a requirement line)."""
    raw = lines[i]
    lineno = i + 1
    if _continues(lines, i):
        return Refusal(path, lineno, LINE_CONTINUATION), None
    text = _strip_comment(raw).strip()
    if not text:
        return None, None
    if text.startswith("-"):
        return Refusal(path, lineno, PIP_OPTION), None
    try:
        req = Requirement(text)
    except InvalidRequirement:
        return Refusal(path, lineno, NOT_A_NAME_REQUIREMENT), None
    name = canonical_name(req.name)
    if req.url is not None:
        return Refusal(path, lineno, URL_REQUIREMENT, name), name
    if req.marker is not None:
        return Refusal(path, lineno, ENVIRONMENT_MARKER, name), name
    if req.name.lower().endswith(ARCHIVE_SUFFIXES):
        return Refusal(path, lineno, ARCHIVE_FILE_NAME, name), name
    if any(spec.operator == "===" or "+" in spec.version for spec in req.specifier):
        return Refusal(path, lineno, VERSION_NOT_PLAIN, name), name
    return None, name


def _continues(lines: List[str], i: int) -> bool:
    """pip joins a line ending in a backslash with the next one, so this line is not the line pip reads. A comment line
    ending in one joins nothing (pip's `join_lines`). `rstrip` is stricter than pip on purpose."""
    own = not _is_comment_line(lines[i]) and lines[i].rstrip().endswith("\\")
    prev = i > 0 and not _is_comment_line(lines[i - 1]) and lines[i - 1].rstrip().endswith("\\")
    return own or prev


def _is_comment_line(line: str) -> bool:
    return COMMENT_LINE_RE.match(line) is not None


def _replaced_file_refusals(path: str, before: str, old: List[str], new: List[str],
                            allowed: FrozenSet[str]) -> List[Refusal]:
    """QA-REPAIR-CRASH-REQUIREMENTS-GUARD: the file a crash repair may replace. Lines may change or go, so re-pins work;
    every line this repair wrote passes the per-line rules and names a package already declared or in `allowed`. A line
    that is exactly a tested line is not re-judged by form (QA installed it as it stands, and the repair did not write
    it), but it still cannot sit where pip would join it to another line."""
    carried = set(old)
    names = allowed | declared_names(before)
    refusals: List[Refusal] = []
    for i, raw in enumerate(new):
        if raw in carried and not _continues(new, i):
            continue
        refusal, name = _line_refusal(path, new, i)
        if refusal is not None:
            refusals.append(refusal)
        elif name is not None and name not in names:
            refusals.append(Refusal(path, i + 1, NOT_IMPORTED_BY_SERVICE, name))
    return refusals


def refusals_of(guard: Mapping[str, FrozenSet[str]], tested: Mapping[str, str],
                candidate: Mapping[str, Any], add_only: bool = True) -> List[Refusal]:
    """The refusals of a whole candidate: every guarded file against its tested content. {} guard: none. A guarded file
    the candidate writes without tested content to compare it to is refused, never waved through (invariant 8)."""
    out: List[Refusal] = []
    for path in sorted(guard):
        if path not in candidate:
            continue
        if not isinstance(tested.get(path), str):
            out.append(Refusal(path, 0, TESTED_CONTENT_MISSING, add_only=add_only))
            continue
        found = check_requirements_edit(path, tested[path], candidate[path], guard[path], add_only=add_only)
        out.extend(replace(r, add_only=add_only) for r in found)
    return out


def render_refusals(refusals: List[Refusal]) -> str:
    """The feedback of a refused attempt. Typed facts only: a raw refused line is never echoed."""
    items = [f"{r.path} line {r.line}: {r.reason}" + (f" ({r.name})" if r.name else "") for r in refusals[:8]]
    if not any(r.add_only for r in refusals):
        return (f"Your previous attempt was rejected ({REQUIREMENTS_REFUSED}): {items}. In requirements.txt every line "
                "you write must be a package name with an optional plain version (no URLs, paths, pip options, markers "
                "or encoding declarations), for a package the file already lists, this service's code already imports, "
                "or a QA test tool (pytest, pytest-timeout, pytest-asyncio). If no such change helps, fix the test setup "
                "in another file instead.")
    return (f"Your previous attempt was rejected ({REQUIREMENTS_REFUSED}): {items}. In requirements.txt keep every "
            "existing line exactly as it is and only add new lines, each a package name with an optional version "
            "(no URLs, paths, pip options, markers or encoding declarations), for a package this service's code already imports. If no such "
            "package is missing, fix the code in the other file instead.")


__all__ = ["REQUIREMENTS_REFUSED", "Refusal", "check_requirements_edit", "imported_names", "refusals_of",
           "render_refusals"]
