"""
Hermetic test guard for Python CHILD processes (Wave 1 lane 2, code red-team fixes).

tests/hermetic_guard.py puts this directory first on PYTHONPATH in the Layer-0 env of every child process a guarded
process starts, so Python runs this file at interpreter start-up, before the child's own code. It installs the guard
(loaded by path, without adding tests/ to sys.path) and then runs the next ``sitecustomize`` on sys.path, if any, so a
pre-existing one (e.g. a virtualenv's, or an interim guard) keeps working. Violations in the child are blocked and
forwarded to the parent pytest through STACKVEND_HERMETIC_CHILD_LOG.

Not a sandbox: ``python -I``/``-E``/``-S`` ignore PYTHONPATH (see the threat model in hermetic_guard.py).
"""
import importlib.util as _ilu
import os as _os
import sys as _sys

_HERE = _os.path.dirname(_os.path.abspath(__file__))


def _load(name, path):
    spec = _ilu.spec_from_file_location(name, path)
    mod = _ilu.module_from_spec(spec)
    _sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        _sys.modules.pop(name, None)
        raise
    return mod


if "hermetic_guard" not in _sys.modules:
    _sys._stackvend_hermetic_child = True  # hermetic_guard.install(): keep the env the parent test chose
    try:
        _load("hermetic_guard", _os.path.join(_os.path.dirname(_HERE), "hermetic_guard.py"))
    except Exception as _e:  # never stop the child from starting; Layer 0 (already in its env) still applies
        _sys.stderr.write(f"hermetic guard: could not install in child process: {_e!r}\n")

for _p in list(_sys.path):
    try:
        if not _p or _os.path.realpath(_p) == _os.path.realpath(_HERE):
            continue
    except (OSError, ValueError):
        continue
    _next = _os.path.join(_p, "sitecustomize.py")
    if _os.path.isfile(_next):
        _load("_hermetic_chained_sitecustomize", _next)
        break
