"""Filesystem layout helpers (no product imports)."""
from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

EVAL_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = EVAL_DIR.parent
CONFIG_DIR = EVAL_DIR / "config"
RESULTS_DIR = EVAL_DIR / "results"
CASSETTES_DIR = EVAL_DIR / "cassettes"
BASELINE_DIR = EVAL_DIR / "baseline"
EXAMPLES_DIR = REPO_ROOT / "documentation" / "examples"

GATEWAY_REL = Path("apps") / "orchestrator-gateway"


def gateway_dir(product_root: Path | str) -> Path:
    return Path(product_root).resolve() / GATEWAY_REL


def deps_dir() -> Path:
    """Optional pinned copies of python-hcl2/lark/regex/pyflakes installed with `pip install --target`.

    Since Step 1 they are also gateway requirements, so an interpreter with the AGENTS.md "Setup" requirements
    installed already has them in its own site-packages (which `python -I` keeps). This directory is only an
    override; when it is absent the child imports them from its interpreter's site-packages."""
    env = os.environ.get("STACKVEND_EVAL_DEPS")
    return Path(env).resolve() if env else EVAL_DIR / ".deps"


def add_deps_to_path() -> bool:
    d = deps_dir()
    if d.is_dir():
        if str(d) not in sys.path:
            sys.path.append(str(d))
        return True
    return False


# Gateway requirements the generation child imports in-process (distribution -> top-level import name). Only the
# ones the product root's own requirements.txt lists are required, so older --product-root SHAs (before Step 1 added
# them) still run without them.
PRODUCT_IMPORTS = {"python-hcl2": "hcl2", "lark": "lark", "regex": "regex", "pyflakes": "pyflakes"}
_PEP508_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")  # PEP 508 distribution-name grammar


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()  # PEP 503 normalization


def required_product_imports(product_root: Path | str) -> Dict[str, str]:
    """{distribution: import name} for the PRODUCT_IMPORTS entries the product's gateway requirements.txt names."""
    req = gateway_dir(product_root) / "requirements.txt"
    if not req.is_file():
        return {}
    names = set()
    for raw in req.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _PEP508_NAME.match(line)
        if m:
            names.add(_canonical(m.group(0)))
    return {dist: mod for dist, mod in PRODUCT_IMPORTS.items() if dist in names}


def resolve_product_dep_dirs(product_root: Optional[Path | str]) -> List[str]:
    """The sys.path entries THIS process imports each required product dependency from (after add_deps_to_path);
    product_root=None: every PRODUCT_IMPORTS entry (the scoring child's own python-hcl2/pyflakes use).

    The parent passes them to its `python -I` children, which drop PYTHONPATH and user site-packages: a parent that
    has python-hcl2 through PYTHONPATH or `pip install --user` would otherwise start a child that cannot import it.
    Allow-list: only the directories that hold one of PRODUCT_IMPORTS, appended after the child's own sys.path (so
    they never shadow the stdlib or the interpreter's site-packages); nothing is imported here."""
    add_deps_to_path()
    dirs: List[str] = []
    mods = PRODUCT_IMPORTS if product_root is None else required_product_imports(product_root)
    for mod in mods.values():
        spec = importlib.util.find_spec(mod)
        if spec is None:
            continue
        if spec.submodule_search_locations:
            entry = Path(list(spec.submodule_search_locations)[0]).parent
        elif spec.origin:
            entry = Path(spec.origin).parent
        else:
            continue
        if entry.is_dir() and str(entry) not in dirs:
            dirs.append(str(entry))
    return dirs


def add_dep_dirs(dirs: List[str]) -> List[str]:
    """Append the parent's resolved dependency directories (resolve_product_dep_dirs); returns the ones added."""
    added = []
    for d in dirs or []:
        if Path(d).is_dir() and d not in sys.path:
            sys.path.append(d)
            added.append(d)
    return added


def product_deps_report(product_root: Path | str, dep_dirs: List[str] = ()) -> Dict[str, object]:  # type: ignore[assignment]
    """Where this interpreter (after add_deps_to_path and the parent's dep_dirs) resolves each required product
    dependency; nothing is imported. `missing` lists the ones it cannot find."""
    from_deps = add_deps_to_path()
    added = add_dep_dirs(list(dep_dirs))
    found: Dict[str, Dict[str, str]] = {}
    missing: List[Dict[str, str]] = []
    for dist, mod in required_product_imports(product_root).items():
        spec = importlib.util.find_spec(mod)
        if spec is None:
            missing.append({"distribution": dist, "import": mod})
            continue
        try:
            version = importlib.metadata.version(dist)
        except importlib.metadata.PackageNotFoundError:
            version = "unknown"
        found[dist] = {"import": mod, "origin": str(spec.origin), "version": version}
    return {"python": sys.executable, "deps_dir": str(deps_dir()), "deps_dir_on_path": from_deps,
            "dep_dirs_from_parent": list(dep_dirs), "dep_dirs_added": added, "found": found, "missing": missing}


def probe_child_deps(product_root: Path | str, env: Dict[str, str]) -> Dict[str, object]:
    """product_deps_report as a generation child started from THIS process sees it: same interpreter, same `-I -B`
    flags, same script, same parent-resolved dependency directories."""
    import json
    import subprocess
    cmd = [sys.executable, "-I", "-B", str(EVAL_DIR / "run_child.py"), "--check-deps", str(product_root)]
    for d in resolve_product_dep_dirs(product_root):
        cmd += ["--dep-dir", d]
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
    if r.returncode not in (0, 5):
        raise RuntimeError(f"run_child.py --check-deps exited {r.returncode}: {r.stderr[-2000:]}")
    return json.loads(r.stdout)


def missing_deps_message(report: Dict[str, object], product_root: Path | str) -> str:
    names = ", ".join(f"{m['distribution']} (import {m['import']})" for m in report["missing"])  # type: ignore[union-attr]
    verb = "is" if len(report["missing"]) == 1 else "are"  # type: ignore[arg-type]
    return (f"product dependency missing: {names} {verb} listed in "
            f"{gateway_dir(product_root) / 'requirements.txt'} but the harness child ({report['python']} -I) cannot "
            f"import {'it' if verb == 'is' else 'them'} (nor could its parent). Install the AGENTS.md Setup "
            f"requirements into this interpreter (pip install -r apps/orchestrator-gateway/requirements.txt), or "
            f"pip install --target eval/.deps -r eval/requirements.txt.")


def have_hcl2() -> bool:
    add_deps_to_path()
    try:
        import hcl2  # noqa: F401
        return True
    except Exception:
        return False


def have_pyflakes() -> bool:
    add_deps_to_path()
    try:
        import pyflakes  # noqa: F401
        return True
    except Exception:
        return False
