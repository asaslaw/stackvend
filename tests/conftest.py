"""
StackVend Platform Test Suite: Root Conftest Harness
Ensures canonical module resolution and protects global interpreter state
during monorepo test collection.
"""

import os
import sys

# Ensure repository root is at the head of sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# FD-4AY: the platform has no built-in GitHub owner (shared/github_identity.py raises when VCS_PROVIDER=GITHUB and
# none is configured). The suite runs as an install whose workloads org is "example-org" unless a test sets its own.
os.environ.setdefault("GITHUB_ORG", "example-org")

# Pin the canonical root shared package to prevent shadowing from app-local directories
import shared  # noqa: E402

# Pre-import fastapi if installed in current environment to prevent mock clobbering
try:
    import fastapi  # noqa: F401
    import fastapi.testclient  # noqa: F401
except ImportError:
    pass


# ---------------------------------------------------------------------------
# FD-05A: per-test-module sys.modules sandbox
#
# Many test files stub third-party/first-party modules at import time
# (``sys.modules["fastapi"] = MagicMock()``, ``sys.modules["google"] = ...``)
# and then import product modules (``routes.settings``, ``schemas``, ``main``)
# that bind those stubs. Pytest imports every test file during collection,
# before any test runs, so without isolation each file's stubs leak into
# every later file and the outcome depends on run order.
#
# Mechanism:
#   * Collection: snapshot sys.modules before a test module is imported,
#     record what the import changed (its "view"), then roll sys.modules
#     back so the next file is collected against a clean interpreter.
#   * Run: re-apply a module's view before its first test and roll back
#     after its last test, so each file runs against exactly the
#     sys.modules state it was written against (the same as running it alone).
#
# Rollback restores every replaced/removed key and drops every added key except
# stdlib modules, C extensions (pydantic_core, grpc, upb cannot be initialised
# twice) and _SINGLETON_FILES. Pure-Python third-party modules are dropped too:
# files guard stubs with ``if m not in sys.modules``, so a real ``google.genai``
# left behind by an earlier file silently replaces a later file's stub.
# ---------------------------------------------------------------------------
import importlib.machinery  # noqa: E402
import sysconfig  # noqa: E402
import types  # noqa: E402

import pytest  # noqa: E402

_MISSING = object()
_STDLIB = os.path.abspath(sysconfig.get_paths()["stdlib"])
_SITE_MARKERS = ("site-packages", "dist-packages")
_MODULE_VIEWS = {}  # Module nodeid -> (changed: dict, removed: list)
_ENV_VIEWS = {}  # Module nodeid -> (set: dict, unset: list): os.environ changes made at import (FD-05 B-12)
# First-party modules that must stay process-wide singletons. control-center's
# db.LazyDbProxy resolves the live client by scanning gc for every loaded
# control-center main module and checking isinstance(main.db, LazyDbProxy);
# two copies of db.py make that check fail and the proxies recurse forever.
_SINGLETON_FILES = {
    os.path.join(REPO_ROOT, "apps", "control-center", "db.py"),
    # The hermetic guard keeps its state on ``sys`` and installs process-wide hooks: one copy only.
    os.path.join(REPO_ROOT, "tests", "hermetic_guard.py"),
    os.path.join(REPO_ROOT, "tests", "hermetic_known_leaks.py"),
}
# Pure-Python halves of C-backed libraries: their extension keeps references to
# the first copy of these classes/registries (e.g. upb rejects a re-imported
# google.protobuf.message.Message), so they are never dropped.
_C_BACKED = {"grpc", "pydantic", "pydantic_core", "proto"}
_C_BACKED_PREFIXES = ("google.protobuf", "google._upb", "google.rpc", "google.type", "google.api.", "google.longrunning")


def _ext_roots(mods):
    """Top-level regular packages that have a loaded C extension (cryptography, nacl, yaml...)."""
    roots = set(_C_BACKED)
    for n, v in mods.items():
        loader = getattr(getattr(v, "__spec__", None), "loader", None)
        if isinstance(v, types.ModuleType) and isinstance(loader, importlib.machinery.ExtensionFileLoader):
            root = n.split(".")[0]
            if getattr(mods.get(root), "__file__", None):  # skip namespace roots like ``google``
                roots.add(root)
    return roots


def _keep_added(name, value, keep_names, ext_roots) -> bool:
    if name in keep_names:
        return True
    if not isinstance(value, types.ModuleType):
        return False  # MagicMock / SimpleNamespace / custom stub
    if name.split(".")[0] in ext_roots:
        return True  # incl. spec-less PyO3/cffi submodules such as cryptography's _openssl
    if getattr(value, "__spec__", None) is None:
        return False  # types.ModuleType("x") stub
    path = getattr(value, "__file__", None)
    if path and os.path.abspath(path) in _SINGLETON_FILES:
        return True
    if isinstance(getattr(value.__spec__, "loader", None), importlib.machinery.ExtensionFileLoader):
        return True  # C extensions (pydantic_core, grpc, upb) cannot be re-initialised
    if name.startswith(_C_BACKED_PREFIXES):
        return True
    if "DESCRIPTOR" in vars(value) or "__protobuf__" in vars(value):
        return True  # pb2 / proto-plus modules: re-import = duplicate descriptor-pool file
    if path is None:
        # builtin/frozen modules are stdlib; namespace packages live under a search path
        try:
            locs = list(value.__spec__.submodule_search_locations or [])
        except Exception:  # _NamespacePath whose parent is already gone
            return False
        if not locs:
            return True
        path = locs[0]
    path = os.path.abspath(path)
    return path.startswith(_STDLIB) and not any(m in path for m in _SITE_MARKERS)


def _snapshot():
    """sys.modules plus the namespace of every package (to restore ``pkg.child``)."""
    mods = dict(sys.modules)
    pkg_dicts = {
        n: dict(m.__dict__)
        for n, m in mods.items()
        if isinstance(m, types.ModuleType) and hasattr(m, "__path__")
    }
    return mods, pkg_dicts


def _restore_parent_attrs(names, pkg_dicts, before):
    """Restore ``parent.child`` for each touched ``parent.child`` module name.

    ``from google import genai`` reads the attribute on the parent package
    before sys.modules, and tests often set ``real_google.auth = MagicMock()``
    next to the sys.modules stub, so attributes leak just like entries do.
    """
    for name in names:
        parent_name, _, child = name.rpartition(".")
        parent = sys.modules.get(parent_name) if parent_name else None
        if not isinstance(parent, types.ModuleType):
            continue
        current = parent.__dict__.get(child, _MISSING)
        saved = pkg_dicts.get(parent_name)
        if name not in before and name in sys.modules:
            # real module added in this window and kept (C-backed / stdlib)
            want = sys.modules[name]
        elif saved is not None and saved.get("__name__") == parent.__dict__.get("__name__"):
            want = saved.get(child, _MISSING)
        else:
            # parent first appeared during this window: mirror sys.modules
            target = sys.modules.get(name)
            if not isinstance(current, types.ModuleType):
                continue
            want = target if isinstance(target, types.ModuleType) and target.__spec__ is not None else _MISSING
        if current is want:
            continue
        if want is _MISSING:
            parent.__dict__.pop(child, None)
        else:
            setattr(parent, child, want)


def _rollback(snapshot, keep_names=()):
    before, pkg_dicts = snapshot
    current = dict(sys.modules)
    roots = _ext_roots(current)
    drop = [n for n, v in current.items() if n not in before and not _keep_added(n, v, keep_names, roots)]
    for name in drop:
        sys.modules.pop(name, None)
    restored = [n for n, v in before.items() if sys.modules.get(n, _MISSING) is not v]
    for name in restored:
        sys.modules[name] = before[name]
    touched = set(drop) | set(restored) | {n for n in current if n not in before}
    _restore_parent_attrs(sorted(touched), pkg_dicts, before)


def _parent_attr(name):
    parent_name, _, child = name.rpartition(".")
    parent = sys.modules.get(parent_name) if parent_name else None
    if not isinstance(parent, types.ModuleType):
        return None, child, _MISSING
    return parent, child, parent.__dict__.get(child, _MISSING)


def _diff(before):
    after = dict(sys.modules)
    changed = {k: v for k, v in after.items() if before.get(k, _MISSING) is not v}
    removed = [k for k in before if k not in after]
    # ``parent.child`` attributes as the file left them (tests often also do
    # ``real_google.auth = MagicMock()`` next to the sys.modules stub).
    attrs = {}
    for name in list(changed) + removed:
        parent, child, value = _parent_attr(name)
        if parent is not None:
            attrs[name] = (parent, child, value)
    return changed, removed, attrs


def _module_nodeid(item):
    mod = item.getparent(pytest.Module)
    return mod.nodeid if mod is not None else None


def _env_diff(before):
    after = dict(os.environ)
    return ({k: v for k, v in after.items() if before.get(k) != v}, [k for k in before if k not in after])


def _env_restore(before):
    for k in [k for k in os.environ if k not in before]:
        del os.environ[k]
    for k, v in before.items():
        if os.environ.get(k) != v:
            os.environ[k] = v


@pytest.hookimpl(hookwrapper=True)
def pytest_make_collect_report(collector):
    if not isinstance(collector, pytest.Module):
        yield
        return
    snapshot = _snapshot()
    env_before = dict(os.environ)
    yield
    # Test files that set os.environ at import (e.g. os.environ["PROJECT_ID"] = ...) used to leak into every file
    # collected after them. Record the change as the module's env "view" and roll it back, like sys.modules.
    _ENV_VIEWS[collector.nodeid] = _env_diff(env_before)
    _env_restore(env_before)
    _MODULE_VIEWS[collector.nodeid] = _diff(snapshot[0])
    # FD-4BT: the test module itself is rolled back too (its view re-adds it while its own tests run). Keeping it
    # in sys.modules let a later file's ``from test_x import helper`` reuse test_x's copy, bound to the product
    # modules of test_x's view, next to the later file's fresh copies of the same product modules: two
    # ``shared.diagnostics`` instances, two ``ErrorClass`` enums, and ``is`` comparisons that silently misroute.
    # Rolled back, a cross-import re-executes test_x inside the importing file's view (one instance per view).
    _rollback(snapshot)


_active = {"nodeid": None, "before": None, "env": None}


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    nodeid = _module_nodeid(item)
    if nodeid != _active["nodeid"]:
        _active["nodeid"] = nodeid
        _active["before"] = _snapshot()
        _active["env"] = dict(os.environ)
        env_set, env_unset = _ENV_VIEWS.get(nodeid, ({}, []))
        os.environ.update(env_set)
        for k in env_unset:
            os.environ.pop(k, None)
        changed, removed, attrs = _MODULE_VIEWS.get(nodeid, ({}, [], {}))
        sys.modules.update(changed)
        for name in removed:
            sys.modules.pop(name, None)
        for parent, child, value in attrs.values():
            if value is _MISSING:
                parent.__dict__.pop(child, None)
            else:
                setattr(parent, child, value)
    yield
    if nextitem is None or _module_nodeid(nextitem) != nodeid:
        _rollback(_active["before"])
        _env_restore(_active["env"])
        _active["nodeid"] = _active["before"] = _active["env"] = None
