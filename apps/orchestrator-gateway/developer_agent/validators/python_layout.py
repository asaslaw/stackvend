"""V3d (report-only, FD-4AD): the module-layout facts the deleted Python healers used to "fix" by rewriting the tree.

HB-26 (stdlib-shadow rename), HB-27 (flat-module / `__init__` purge), HB-28 (local-stem requirement prune) and HB-31 /
HE-02 (import rewrites) mutated valid trees and are deleted. The genuine hazards they guessed at are reported here as
typed diagnostics instead; nothing here writes. Exact rules only (paths, `ast`, `packaging`; no regex, no substring
tests on code; Invariant 2). A service is `apps/<svc>/` with at least one `.py` file (the same inventory as the
add-only requirements contract); Buildpacks run it with `apps/<svc>/` as the container root, so its top-level modules
are `apps/<svc>/<name>.py` and `apps/<svc>/<name>/__init__.py`.

Codes (severity warning, registered report_only; promotion to blocking needs its own register row):
* PY.STDLIB_SHADOWED          a top-level module of the service is named like a stdlib module (`sys.stdlib_module_names`),
                              so `import <name>` anywhere in the container loads the service's file instead.
* PY.MODULE_PACKAGE_CONFLICT  `<dir>/<x>.py` and a `<dir>/<x>/` directory holding `.py` files both exist: one of them is
                              unreachable (a regular package wins over the module; a namespace dir loses to it).
* REQ.LOCAL_MODULE_NAME       a requirements.txt line names (PEP 503, `-` == `_`) a top-level module of the same service,
                              a monorepo library dir (`apps/shared|common|contracts|schemas`) or one of its top-level
                              modules (the old HB-28 prune deleted such lines; a local name is not a PyPI distribution).

Imports that cannot resolve under the container's import root (absolute `apps.<...>`, a relative import above the
service root) are reported once, by V3c-imports `CONTAINER.IMPORT_OUTSIDE_SERVICE` (validators/container.py,
FD-4AE-c); FD-4AD's duplicate `PY.IMPORT_OUTSIDE_SERVICE_ROOT` was dropped at the integration merge (FD-4AE-c RT F2).
"""
from __future__ import annotations

import posixpath
from typing import Any, List, Set

try:
    from shared.diagnostics import Diagnostic
except ImportError:  # pragma: no cover
    from ...shared.diagnostics import Diagnostic  # type: ignore

try:
    from gatekeeper_agent.pypi_catalog import STDLIB_MODULES
    from gatekeeper_agent.requirements_contract import EXCLUDED_SERVICE_DIRS, declared_names, python_services
except ImportError:  # pragma: no cover - loaded as a sub-package of the gateway root
    from ...gatekeeper_agent.pypi_catalog import STDLIB_MODULES  # type: ignore
    from ...gatekeeper_agent.requirements_contract import (  # type: ignore
        EXCLUDED_SERVICE_DIRS, declared_names, python_services)

TOOL = "ast"


def _d(**kw: Any) -> Diagnostic:
    kw.setdefault("source", "precommit")
    kw.setdefault("severity", "warning")
    kw.setdefault("tool", TOOL)
    return Diagnostic(**kw)


def top_level_modules(files: Any, svc: str) -> dict:
    """{name: path} of the service's importable top-level modules: `<name>.py` and regular packages
    `<name>/__init__.py` directly under `apps/<svc>/`."""
    pre = f"apps/{svc}/"
    out = {}
    for p in sorted(files):
        if not p.startswith(pre):
            continue
        parts = p[len(pre):].split("/")
        if len(parts) == 1 and parts[0].endswith(".py") and parts[0] != "__init__.py":
            out.setdefault(parts[0][:-3], p)
        elif len(parts) == 2 and parts[1] == "__init__.py":
            out.setdefault(parts[0], p)
    return out


def repo_library_names(files: Any) -> Set[str]:
    """Lower-cased names local to the monorepo that are never PyPI distributions: the library dirs under `apps/`
    (EXCLUDED_SERVICE_DIRS: shared, common, contracts, schemas) and their top-level modules / packages."""
    out: Set[str] = set()
    for p in files:
        parts = p.split("/")
        if len(parts) >= 3 and parts[0] == "apps" and parts[1] in EXCLUDED_SERVICE_DIRS and parts[1] != "__pycache__":
            out.add(parts[1].lower())
            head = parts[2]
            if len(parts) > 3:
                out.add(head.lower())
            elif head.endswith(".py") and head != "__init__.py":
                out.add(head[:-3].lower())
    return out


class PythonLayoutValidator:
    id, tool = "V3d", TOOL

    def validate(self, ctx: Any) -> List[Diagnostic]:
        files = ctx.files
        it = ctx.iteration
        out: List[Diagnostic] = []
        for svc in python_services(files):
            pre = f"apps/{svc}/"
            tops = top_level_modules(files, svc)
            for name in sorted(tops):
                if name in STDLIB_MODULES:
                    out.append(_d(code="PY.STDLIB_SHADOWED", file=tops[name], iteration=it,
                                  message=f"top-level module '{name}' of service '{svc}' has the name of a Python "
                                          f"standard library module; inside the container `import {name}` loads "
                                          f"{tops[name]} instead of the standard library",
                                  hint=f"Rename it (e.g. {name}_utils) and update its imports."))
            out.extend(self._module_package_conflicts(files, pre, it))
            req = f"{pre}requirements.txt"
            if isinstance(files.get(req), str):
                local = {n.lower() for n in tops} | repo_library_names(files)
                for name in sorted(declared_names(files[req])):   # canonical: lower case, `-` separators
                    if name.replace("-", "_") in local:
                        out.append(_d(code="REQ.LOCAL_MODULE_NAME", file=req, iteration=it, tool="pip",
                                      message=f"requirement '{name}' names a module local to the repository "
                                              f"(service '{svc}' or apps/ library dirs): a local module is not a PyPI "
                                              f"distribution, and a real one of that name would be shadowed by it"))
        return out

    @staticmethod
    def _module_package_conflicts(files: Any, pre: str, it: int) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        py_dirs: Set[str] = set()
        for p in files:
            if p.startswith(pre) and p.endswith(".py"):
                py_dirs.add(posixpath.dirname(p))
        for p in sorted(files):
            if not (p.startswith(pre) and p.endswith(".py")) or posixpath.basename(p) == "__init__.py":
                continue
            stem_dir = p[:-3]
            if stem_dir in py_dirs or any(d.startswith(stem_dir + "/") for d in py_dirs):
                kind = "regular package" if f"{stem_dir}/__init__.py" in files else "namespace directory"
                winner = f"{stem_dir}/ (package)" if kind == "regular package" else p
                out.append(_d(code="PY.MODULE_PACKAGE_CONFLICT", file=p, iteration=it,
                              message=f"{p} and the {kind} {stem_dir}/ have the same import name; only {winner} is "
                                      f"importable",
                              hint=f"Keep one: move the module's code into {stem_dir}/ or rename one of them."))
        return out


__all__ = ["PythonLayoutValidator", "repo_library_names", "top_level_modules"]
