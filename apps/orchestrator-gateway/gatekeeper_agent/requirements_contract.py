"""FD-4AD: the add-only requirements contract of an AI-written Python service (replaces HB-28 and HB-33).

`apps/<svc>/requirements.txt` is the AI's file. The platform only APPENDS a distribution that an exact fact proves the
service needs and that no line already names. It never deletes, reorders, re-pins or rewrites a line, and a file that
already covers every need is returned byte-identical (Invariant 1).

Facts (no regex, no substring tests on code; Invariant 2):
1. Imports: every `import X` / `from X import ...` (level 0) the AST of a service `.py` file holds whose top-level name
   is not stdlib and not a top-level module of the service itself (`apps/<svc>/<name>.py` or `apps/<svc>/<name>/`), and
   that the closed-world catalog maps to a distribution (`pypi_catalog.resolve_import_to_pypi`, HE-03).
2. Imported names that need an optional distribution at import or route-definition time (`IMPLIED_BY_IMPORTED_NAME`,
   an exact (module, name) table; e.g. `from fastapi import Form` needs python-multipart), and imported modules that do
   (`IMPLIED_BY_IMPORTED_MODULE`, exact dotted names; e.g. `google.auth.transport.requests` needs `requests`, which
   google-auth declares only as an extra).
3. The server a Procfile process launches, read with the SAME parser V3c uses (gatekeeper_agent/procfile.py: the Procfile line
   rule, `shlex`, the exact wrappers `exec` / `env NAME=value` / `NAME=value` / `sh -c "..."`, the executable's
   basename or `python -m <server>`), on every simple command split at the exact shell tokens `&&`, `||`, `;`; plus a
   gunicorn `-k/--worker-class` whose module root is a launcher (`uvicorn.workers.UvicornWorker`).

4. QA-REQ-TESTS (owner 10-27): the test files the QA sandbox job runs with a service's venv. A single-service
   workload keeps its tests in the repository-root `tests/` directory (developer_agent/workload_test_layout.py), and
   the QA job runs them, plus a root `conftest.py` (pytest loads it: `--confcutdir` is the source root), with that
   service's venv (apps/qa-runner/sandbox_job.discover_layout). Their imports count for that service, read as in (1)
   and (2), with the repository-root names and every module or package name under `tests/` treated as local (pytest
   puts those directories on sys.path), and without the QA runner's own test toolchain (`pytest`, `pytest-timeout`:
   installed by the job, pinned). The single-service rule is the QA job's, mirrored exactly (`root_tests_service`;
   parity: tests/test_qa_req_tests.py): with more than one service the QA job rejects a root `tests/`
   (PY.TEST_LAYOUT), so nothing is read there.

5. REQUIREMENTS-ASYNC-TEST-PLUGIN: a test module the QA job runs with the service's venv (`test_*.py` / `*_test.py`
   under `apps/<svc>/`, plus the root `tests/` ones of a single service) that defines an `async def` test (an
   AsyncFunctionDef named `test*` at module level or in a `Test*` class: AST only) needs an async test plugin:
   `ASYNC_TEST_PLUGIN` (pytest-asyncio at the QA toolchain's pin), unless the file already names pytest-asyncio or
   anyio (`ASYNC_TEST_PLUGIN_COVERED_BY`). The QA job loads pytest-asyncio only when it is installed and then runs it
   in auto mode, so unmarked async tests run.

Known benign edges (FD-4AD RT): a Node service holding a stray `.py` file counts as a Python service; a `-r other.txt`
line is not followed, so a need it already covers is appended once more (harmless to pip).

Existing lines are matched by PEP 503 canonical name (`packaging`), plus the distributions an extra is known to install
(`INSTALLED_BY_EXTRA`: `google-auth[requests]` names `requests`); pip option lines (`-r`, `-e`, `--index-url`) and lines
`packaging` cannot parse are kept as written and name nothing (V4 REQ.UNPARSEABLE reports the latter). A Python service
(at least one `.py` file under `apps/<svc>/`) without a requirements.txt gets one holding only the proven needs; a
service without `.py` files (e.g. Node) is never given one.
"""
from __future__ import annotations

import ast
import shlex
from typing import Dict, List, Mapping, Optional, Set, Tuple

try:
    from .procfile import command_segments, parse_command, parse_procfile, unwrap
    from .pypi_catalog import STDLIB_MODULES, resolve_import_to_pypi
except ImportError:  # pragma: no cover - module loaded outside its package
    from procfile import command_segments, parse_command, parse_procfile, unwrap  # type: ignore
    from pypi_catalog import STDLIB_MODULES, resolve_import_to_pypi  # type: ignore

# (module, imported name) -> distribution requirement. The version floors are the ones HB-33 / the old base manifest
# used, so a need the old code met is met with the same floor.
_MULTIPART = "python-multipart>=0.0.20"
_EMAIL = "email-validator>=2.0.0"
_JINJA = "jinja2>=3.1.5"
_HTTPX = "httpx>=0.27.0"
_REQUESTS = "requests>=2.31.0"   # the catalog's row for `requests` (pypi_catalog.CANONICAL_PYPI_CATALOG)
IMPLIED_BY_IMPORTED_NAME: Dict[Tuple[str, str], str] = {
    ("fastapi", "Form"): _MULTIPART,
    ("fastapi", "File"): _MULTIPART,
    ("fastapi", "UploadFile"): _MULTIPART,
    ("fastapi.param_functions", "Form"): _MULTIPART,
    ("fastapi.param_functions", "File"): _MULTIPART,
    ("pydantic", "EmailStr"): _EMAIL,
    ("pydantic", "NameEmail"): _EMAIL,
    ("pydantic.networks", "EmailStr"): _EMAIL,
    ("pydantic.networks", "NameEmail"): _EMAIL,
    ("fastapi.templating", "Jinja2Templates"): _JINJA,
    ("starlette.templating", "Jinja2Templates"): _JINJA,
    ("fastapi.testclient", "TestClient"): _HTTPX,
    ("starlette.testclient", "TestClient"): _HTTPX,
    # `from <package> import <submodule>` of a module listed in IMPLIED_BY_IMPORTED_MODULE
    ("google.auth.transport", "requests"): _REQUESTS,
    ("google.auth", "compute_engine"): _REQUESTS,
    ("google.auth.compute_engine", "credentials"): _REQUESTS,
}
# Exact dotted module -> distribution the module itself imports when it loads, so `import M` and `from M import ...` both
# need it. Each row was proven on google-auth 2.61.0 by importing the module with `requests` absent; that package
# declares `requests` only through extras, so a service naming just google-auth fails at `import main`.
IMPLIED_BY_IMPORTED_MODULE: Dict[str, str] = {
    "google.auth.transport.requests": _REQUESTS,
    "google.auth.compute_engine": _REQUESTS,
    "google.auth.compute_engine.credentials": _REQUESTS,
    "google.auth.compute_engine._metadata": _REQUESTS,
}
# (distribution, extra) -> distribution that extra installs, from google-auth's Requires-Dist. A line naming one of
# these already covers the need, so nothing is appended (Invariant 1).
INSTALLED_BY_EXTRA: Dict[Tuple[str, str], str] = {
    ("google-auth", "requests"): "requests",
    ("google-auth", "aiohttp"): "requests",
}
# Procfile executable (or gunicorn worker-class module root) -> distribution.
LAUNCHER_DISTRIBUTIONS: Dict[str, str] = {
    "uvicorn": "uvicorn[standard]>=0.28.0",
    "gunicorn": "gunicorn>=22.0.0",
    "hypercorn": "hypercorn>=0.16.0",
}
EXCLUDED_SERVICE_DIRS = frozenset({"shared", "common", "contracts", "schemas", "__pycache__"})
# QA-REQ-TESTS: the distributions the QA sandbox job installs itself into every service venv, pinned
# (apps/qa-runner/sandbox_job.Toolchain.test_packages; parity: tests/test_qa_req_tests.py). A test-file import of
# them is never appended to the service's production requirements.
QA_RUNNER_TEST_TOOLCHAIN = frozenset({"pytest", "pytest-timeout"})
ROOT_TESTS_DIR = "tests"
ROOT_CONFTEST = "conftest.py"
# REQUIREMENTS-ASYNC-TEST-PLUGIN: an `async def` test needs an async test plugin; the QA job loads pytest-asyncio only
# when the service venv has it (sandbox_job.OPTIONAL_PYTEST_PLUGIN_DISTS) and then runs it in auto mode. The pin is the
# QA toolchain's (apps/qa-runner/qa_toolchain_constraints.txt; parity: tests/test_requirements_async_test_plugin.py).
ASYNC_TEST_PLUGIN = "pytest-asyncio==1.4.0"
# A file naming one of these already provides an async test runner: nothing is appended (anyio has its own plugin).
ASYNC_TEST_PLUGIN_COVERED_BY = frozenset({"pytest-asyncio", "anyio"})
# pytest's collection rules as the QA job applies them: its own ini's `python_files` (apps/qa-runner/qa_pytest.ini:
# `test_*.py *_test.py`) and pytest's default `python_functions` / `python_classes` prefixes (that ini sets neither).
TEST_FILE_PREFIX, TEST_FILE_SUFFIX = "test_", "_test.py"
TEST_FUNCTION_PREFIX, TEST_CLASS_PREFIX = "test", "Test"


def canonical_name(name: str) -> str:
    from packaging.utils import canonicalize_name
    return str(canonicalize_name(name))


def requirement_name(spec: str) -> Optional[str]:
    """Canonical distribution name of one requirement specifier, or None when `packaging` cannot parse it."""
    from packaging.requirements import InvalidRequirement, Requirement
    try:
        return canonical_name(Requirement(spec).name)
    except InvalidRequirement:
        return None


def _requirement_specs(text: str) -> List[str]:
    """The requirement lines of a requirements.txt (pip comment rule as in V4: `#` at line start or after whitespace;
    option lines starting with `-` are not requirements). Lines split as pip splits them (`splitlines`, as the guard and
    the QA job do), so a form feed or U+2028 cannot hide a requirement from this."""
    out: List[str] = []
    for line in text.splitlines():
        cut = line
        for i, ch in enumerate(line):
            if ch == "#" and (i == 0 or line[i - 1] in " \t"):
                cut = line[:i]
                break
        cut = cut.strip()
        if not cut or cut.startswith("-"):
            continue
        out.append(cut)
    return out


def declared_names(text: str) -> Set[str]:
    """Canonical names of the requirement lines in a requirements.txt."""
    return {name for name in map(requirement_name, _requirement_specs(text)) if name}


def installed_by_declared_extras(text: str) -> Set[str]:
    """Distributions the extras named on the requirement lines install (`INSTALLED_BY_EXTRA`, exact parsed facts)."""
    from packaging.requirements import InvalidRequirement, Requirement
    out: Set[str] = set()
    for spec in _requirement_specs(text):
        try:
            req = Requirement(spec)
        except InvalidRequirement:
            continue
        name = canonical_name(req.name)
        out |= {INSTALLED_BY_EXTRA[(name, canonical_name(e))] for e in req.extras
                if (name, canonical_name(e)) in INSTALLED_BY_EXTRA}
    return out


def python_services(files: Mapping[str, str]) -> List[str]:
    """`apps/<svc>/` directories holding at least one `.py` file (library dirs excluded, as detect_services does)."""
    out: Set[str] = set()
    for p in files:
        parts = p.split("/")
        if len(parts) >= 3 and parts[0] == "apps" and parts[1] and parts[1] not in EXCLUDED_SERVICE_DIRS \
                and "." not in parts[1] and p.endswith(".py"):
            out.add(parts[1])
    return sorted(out)


def service_top_level_modules(files: Mapping[str, str], svc: str) -> Set[str]:
    """Names importable from the service root (Buildpacks run it as the container root): `<name>.py` files and
    directories directly under `apps/<svc>/`."""
    pre = f"apps/{svc}/"
    out: Set[str] = set()
    for p in files:
        if not p.startswith(pre):
            continue
        rest = p[len(pre):]
        head, sep, _ = rest.partition("/")
        if sep:
            out.add(head)
        elif head.endswith(".py"):
            out.add(head[:-3])
    return out


def _import_needs(tree: ast.AST, local: Set[str]) -> Set[str]:
    needs: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in local or root in STDLIB_MODULES:
                    continue
                dist = resolve_import_to_pypi(alias.name)
                if dist:
                    needs.add(dist)
                implied = IMPLIED_BY_IMPORTED_MODULE.get(alias.name)
                if implied:
                    needs.add(implied)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            module = node.module
            root = module.split(".")[0]
            if root in local or root in STDLIB_MODULES:
                continue
            found = False
            for alias in node.names:
                dist = resolve_import_to_pypi(f"{module}.{alias.name}")
                if dist:
                    needs.add(dist)
                    found = True
            if not found:
                dist = resolve_import_to_pypi(module)
                if dist:
                    needs.add(dist)
            for alias in node.names:
                implied = IMPLIED_BY_IMPORTED_NAME.get((module, alias.name))
                if implied:
                    needs.add(implied)
            implied = IMPLIED_BY_IMPORTED_MODULE.get(module)
            if implied:
                needs.add(implied)
    return needs


def procfile_needs(text: str) -> Set[str]:
    """Distributions the Procfile's processes launch: the V3c parser (gatekeeper_agent/procfile.py, one source for both) on every
    simple command of every process line; an unsplittable command names nothing."""
    needs: Set[str] = set()
    procs, _ = parse_procfile(text)
    for cmd in procs.values():
        try:
            argv = shlex.split(cmd)
        except ValueError:
            continue
        for seg in command_segments(argv):
            launch = parse_command(seg)
            if launch.kind != "server" or launch.server not in LAUNCHER_DISTRIBUTIONS:
                continue
            needs.add(LAUNCHER_DISTRIBUTIONS[launch.server])
            if launch.server == "gunicorn":
                seg = unwrap(seg)
                for k, tok in enumerate(seg):
                    opt, eq, val = tok.partition("=")
                    if opt in ("-k", "--worker-class"):
                        val = val if eq else (seg[k + 1] if k + 1 < len(seg) else "")
                        root = val.split(".")[0]
                        if root in LAUNCHER_DISTRIBUTIONS:
                            needs.add(LAUNCHER_DISTRIBUTIONS[root])
    return needs


def _file_needs(files: Mapping[str, str], paths: List[str], local: Set[str]) -> Set[str]:
    needs: Set[str] = set()
    for p in paths:
        try:
            tree = ast.parse(files[p])
        except (SyntaxError, ValueError):
            continue   # PY.SYNTAX (V3a) reports it; its imports are read after the repair
        needs |= _import_needs(tree, local)
    return needs


def qa_services(files: Mapping[str, str]) -> List[str]:
    """The services the QA sandbox job will find in the tree this contract returns: its rule (`discover_layout`: a
    service is `apps/<svc>/` with a `requirements.txt`, the same path test) on the existing requirements files plus
    the ones `append_missing_requirements` creates (one per Python service)."""
    names = {p.split("/")[1] for p in files if p.startswith("apps/") and p.count("/") == 2
             and p.endswith("/requirements.txt")}
    return sorted(names | set(python_services(files)))


def root_tests_service(files: Mapping[str, str]) -> Optional[str]:
    """The service the QA job runs the root `tests/` with (`discover_layout`: a root `tests/` file exists and there
    is exactly one service), when that service is a Python service this contract covers; else None."""
    if not any(p.startswith(f"{ROOT_TESTS_DIR}/") for p in files):
        return None
    services = qa_services(files)
    if len(services) != 1 or services[0] not in python_services(files):
        return None
    return services[0]


def root_test_files(files: Mapping[str, str]) -> List[str]:
    """The root test `.py` files the QA job's pytest loads for the single service: `tests/**/*.py` and the root
    `conftest.py`."""
    return sorted(p for p in files if p.endswith(".py")
                  and (p.startswith(f"{ROOT_TESTS_DIR}/") or p == ROOT_CONFTEST))


def root_test_local_modules(files: Mapping[str, str], svc: str) -> Set[str]:
    """Names a root test file imports locally: the service's top-level modules (the QA job's PYTHONPATH is the
    service directory), every repository-root directory and `<name>.py` (pytest's rootdir-based sys.path entry), and
    every directory and `<name>.py` under `tests/` (pytest prepends each test file's directory). Over-counting a
    local name only ever means one append fewer (Do No Harm)."""
    local = set(service_top_level_modules(files, svc))
    for p in files:
        parts = p.split("/")
        if len(parts) > 1:
            local.add(parts[0])
        elif p.endswith(".py"):
            local.add(p[:-3])
        if parts[0] == ROOT_TESTS_DIR:
            local.update(parts[1:-1])
            if parts[-1].endswith(".py"):
                local.add(parts[-1][:-3])
    return local


def is_test_module_path(path: str) -> bool:
    """REQUIREMENTS-ASYNC-TEST-PLUGIN: a file pytest collects as a test module under the QA job's `python_files`
    (`test_*.py`, `*_test.py`; the basename only)."""
    base = path.rsplit("/", 1)[-1]
    return (base.startswith(TEST_FILE_PREFIX) and base.endswith(".py")) or base.endswith(TEST_FILE_SUFFIX)


def has_async_test(tree: ast.AST) -> bool:
    """REQUIREMENTS-ASYNC-TEST-PLUGIN: the module defines an `async def` test pytest collects: a module-level
    AsyncFunctionDef whose name starts with `test`, or one in a module-level class whose name starts with `Test`
    (pytest's default python_functions / python_classes). AST nodes only."""
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.AsyncFunctionDef) and node.name.startswith(TEST_FUNCTION_PREFIX):
            return True
        if isinstance(node, ast.ClassDef) and node.name.startswith(TEST_CLASS_PREFIX) and any(
                isinstance(item, ast.AsyncFunctionDef) and item.name.startswith(TEST_FUNCTION_PREFIX)
                for item in node.body):
            return True
    return False


def service_test_modules(files: Mapping[str, str], svc: str) -> List[str]:
    """REQUIREMENTS-ASYNC-TEST-PLUGIN: the test modules the QA job runs with this service's venv: those under
    `apps/<svc>/`, plus the repository-root `tests/` ones when this is their single service (QA-REQ-TESTS)."""
    pre = f"apps/{svc}/"
    out = [p for p in sorted(files) if p.startswith(pre) and p.endswith(".py") and is_test_module_path(p)]
    if root_tests_service(files) == svc:
        out += [p for p in root_test_files(files) if is_test_module_path(p)]
    return out


def async_test_needs(files: Mapping[str, str], svc: str) -> Set[str]:
    """REQUIREMENTS-ASYNC-TEST-PLUGIN: {ASYNC_TEST_PLUGIN} when a test module of the service has an async test."""
    for p in service_test_modules(files, svc):
        try:
            if has_async_test(ast.parse(files[p])):
                return {ASYNC_TEST_PLUGIN}
        except (SyntaxError, ValueError):
            continue   # PY.SYNTAX (V3a) reports it; read again after the repair
    return set()


def service_needs(files: Mapping[str, str], svc: str) -> Set[str]:
    """Every distribution the exact facts prove `apps/<svc>/` needs (requirement specifier strings)."""
    pre = f"apps/{svc}/"
    needs = _file_needs(files, [p for p in sorted(files) if p.startswith(pre) and p.endswith(".py")],
                        service_top_level_modules(files, svc))
    procfile = files.get(f"{pre}Procfile")
    if isinstance(procfile, str):
        needs |= procfile_needs(procfile)
    if root_tests_service(files) == svc:   # QA-REQ-TESTS
        needs |= {spec for spec in _file_needs(files, root_test_files(files), root_test_local_modules(files, svc))
                  if requirement_name(spec) not in QA_RUNNER_TEST_TOOLCHAIN}
    needs |= async_test_needs(files, svc)   # REQUIREMENTS-ASYNC-TEST-PLUGIN
    return needs


def missing_requirements(files: Mapping[str, str], svc: str) -> List[str]:
    """The proven needs of `apps/<svc>/` that its requirements.txt does not name, sorted by canonical name."""
    text = files.get(f"apps/{svc}/requirements.txt", "") or ""
    declared = declared_names(text) | installed_by_declared_extras(text)
    if declared & ASYNC_TEST_PLUGIN_COVERED_BY:   # REQUIREMENTS-ASYNC-TEST-PLUGIN: an async test runner is named
        declared = declared | {requirement_name(ASYNC_TEST_PLUGIN)}
    by_name: Dict[str, str] = {}
    for spec in service_needs(files, svc):
        name = requirement_name(spec)
        if name and name not in declared:
            by_name.setdefault(name, spec)
    return [by_name[n] for n in sorted(by_name)]


def append_missing_requirements(files: Mapping[str, str]) -> Tuple[Dict[str, str], List[str]]:
    """Add-only: (files with the missing lines appended, one action string per change). Every other file, and every
    requirements.txt that already names every proven need, is returned byte-identical."""
    out = dict(files)
    actions: List[str] = []
    for svc in python_services(files):
        req = f"apps/{svc}/requirements.txt"
        missing = missing_requirements(files, svc)
        if req in files and not missing:
            continue
        current = files.get(req)
        if current is None:
            out[req] = "".join(f"{m}\n" for m in missing)
            actions.append(f"created {req} with {len(missing)} proven requirement(s): {missing}")
            continue
        prefix = current if (not current or current.endswith("\n")) else current + "\n"
        out[req] = prefix + "".join(f"{m}\n" for m in missing)
        actions.append(f"appended {missing} to {req}")
    return out, actions


__all__ = ["ASYNC_TEST_PLUGIN", "ASYNC_TEST_PLUGIN_COVERED_BY", "async_test_needs", "has_async_test",
           "is_test_module_path", "service_test_modules", "IMPLIED_BY_IMPORTED_MODULE", "IMPLIED_BY_IMPORTED_NAME", "INSTALLED_BY_EXTRA", "LAUNCHER_DISTRIBUTIONS",
           "QA_RUNNER_TEST_TOOLCHAIN", "append_missing_requirements", "canonical_name", "declared_names",
           "installed_by_declared_extras", "missing_requirements", "procfile_needs",
           "python_services", "qa_services", "requirement_name", "root_test_files", "root_test_local_modules",
           "root_tests_service", "service_needs", "service_top_level_modules"]
