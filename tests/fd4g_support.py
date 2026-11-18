"""FD-4G test support: isolate FD-4G tests from sys.modules pollution left by other root tests.

Several root test modules replace third-party packages (fastapi, pydantic, httpx, google.*) with MagicMock in
sys.modules at import time and never restore them. The FD-4G tests load real service apps, so they temporarily
restore real modules (monkeypatch puts the previous entries back afterwards) and load each service module by
file path under its import name, restoring the previous sys.modules entry when done.
"""

import importlib
import importlib.util
import os
import sys
import types

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")

_STACK_PREFIXES = ("fastapi", "starlette", "pydantic", "pydantic_core", "httpx", "anyio", "dulwich",
                   "multipart", "python_multipart", "shared", "yaml", "jwt", "github", "google")


def _is_stack(name):
    return any(name == p or name.startswith(p + ".") for p in _STACK_PREFIXES)


# google.* (protobuf / proto-plus) registers into process-global C descriptor pools; re-importing a popped module
# segfaults, so those stay registered.
_NEVER_POP = ("google",)


class _PopNewStackModules:
    """Monkeypatch-registered finalizer: undo() deletes the ``armed`` attribute, which pops stack modules first
    imported during the test (monkeypatch only restores entries it replaced or deleted itself)."""

    def __init__(self, before):
        object.__setattr__(self, "_before", before)

    def __delattr__(self, name):
        for key in list(sys.modules):
            if key not in self._before and _is_stack(key) and not any(
                    key == p or key.startswith(p + ".") for p in _NEVER_POP):
                sys.modules.pop(key, None)
        if name in self.__dict__:
            object.__delattr__(self, name)


def real_modules(monkeypatch):
    """Drop mocked (non-module) sys.modules entries for the web/test stack so real packages re-import."""
    monkeypatch.setattr(_PopNewStackModules(set(sys.modules)), "armed", True, raising=False)
    for name, mod in list(sys.modules.items()):
        if _is_stack(name) and not isinstance(mod, types.ModuleType):
            monkeypatch.delitem(sys.modules, name)
    import fastapi  # noqa: F401
    import fastapi.responses  # noqa: F401
    import fastapi.testclient  # noqa: F401
    import pydantic  # noqa: F401


def load_module(monkeypatch, import_name, path):
    """Exec ``path`` as ``import_name``; the module stays registered only for the test (monkeypatch)."""
    spec = importlib.util.spec_from_file_location(import_name, path)
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, import_name, mod)
    spec.loader.exec_module(mod)
    return mod


def load_tf_service(monkeypatch):
    """The REAL mcp-servers/terraform/service.py (other dirs on sys.path also ship a 'service' module)."""
    real_modules(monkeypatch)
    return load_module(monkeypatch, "service", os.path.join(TF_DIR, "service.py"))
