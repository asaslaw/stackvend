"""
FD-4AH rescan: apps/control-center/routes/workloads.py::submit_feature_request read ``plan_fn`` / ``plan_fp``
without assigning them (the two lines were lost when ``target_repo`` moved to ``resolve_repo_identity``), so every
feature-request submission raised NameError -> HTTP 500 before anything was saved.

Static gate: pyflakes (pinned in apps/orchestrator-gateway/requirements.txt) must report no undefined name
(F821 class) in any Control Center product module (test_*.py excluded). Hermetic: pyflakes only parses the
source; nothing is imported or executed.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import os

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_ROOT = os.path.join(REPO_ROOT, "apps", "control-center")


def _undefined_names(path):
    from pyflakes import checker, messages

    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    tree = ast.parse(source, filename=path)
    found = checker.Checker(tree, filename=path)
    return sorted(
        f"{m.lineno}: {m.message_args[0]}"
        for m in found.messages
        if isinstance(m, messages.UndefinedName)
    )


def _cc_product_files():
    out = []
    for root, dirs, files in os.walk(CC_ROOT):
        dirs[:] = sorted(d for d in dirs if d not in ("__pycache__", "tests", "test"))
        for name in sorted(files):
            if name.endswith(".py") and not name.startswith("test_"):
                out.append(os.path.join(root, name))
    return out


def test_control_center_has_no_undefined_names():
    files = _cc_product_files()
    assert os.path.join(CC_ROOT, "routes", "workloads.py") in files
    problems = {
        os.path.relpath(p, REPO_ROOT): names for p in files if (names := _undefined_names(p))
    }
    assert problems == {}


def test_pyflakes_gate_detects_undefined_name(tmp_path):
    """The gate itself must fire: a name read before any assignment is reported."""
    bad = tmp_path / "bad.py"
    bad.write_text('def f(d):\n    url = f"/plans/{plan_fn}/raw"\n    return url\n', encoding="utf-8")
    assert _undefined_names(str(bad)) == ["2: plan_fn"]
