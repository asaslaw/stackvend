"""The harness generation child (`python -I -B eval/run_child.py`) must be able to import the gateway requirements the
product imports in-process (python-hcl2, lark, regex, pyflakes since Step 1). Without them every harness e2e test
fails with an unrelated-looking `generation_error`; this file is the ONE test that fails, by name, and the e2e tests
in tests/test_eval_e2e.py and tests/test_eval_spec_file.py skip with a pointer here.

Fix: install the AGENTS.md "Setup" requirements (they include apps/orchestrator-gateway/requirements.txt) into the
interpreter that runs pytest, or `pip install --target eval/.deps -r eval/requirements.txt`."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "eval"
sys.path.insert(0, str(EVAL))

from stackvend_eval import paths  # noqa: E402


def test_harness_child_can_import_the_product_requirements():
    report = paths.probe_child_deps(ROOT, env=hermetic_guard.child_env())
    if report["missing"]:
        pytest.fail(paths.missing_deps_message(report, ROOT), pytrace=False)
    assert set(report["found"]) == set(paths.required_product_imports(ROOT))


def test_required_imports_follow_the_product_root_requirements(tmp_path):
    """Only what the product root's gateway requirements.txt lists is required (older --product-root SHAs ran
    before Step 1 added python-hcl2), and names are PEP 503-normalized."""
    gw = tmp_path / "apps" / "orchestrator-gateway"
    gw.mkdir(parents=True)
    assert paths.required_product_imports(tmp_path) == {}
    (gw / "requirements.txt").write_text("fastapi>=0.110.0\n# python-hcl2==7.3.1 (commented out)\n", encoding="utf-8")
    assert paths.required_product_imports(tmp_path) == {}
    (gw / "requirements.txt").write_text(
        "-c constraints.txt\nPython_HCL2==7.3.1  # pin\nlark[regex]==1.2.2\npyflakes ; python_version>'3'\n",
        encoding="utf-8")
    assert paths.required_product_imports(tmp_path) == {"python-hcl2": "hcl2", "lark": "lark", "pyflakes": "pyflakes"}


FAKE = "stackvend_fake_product_dep"


def _product_root(tmp_path):
    gw = tmp_path / "root" / "apps" / "orchestrator-gateway"
    gw.mkdir(parents=True)
    (gw / "requirements.txt").write_text("python-hcl2==7.3.1\n", encoding="utf-8")
    pkg = tmp_path / "parent-only" / FAKE
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    return tmp_path / "root", pkg.parent


def _child_report(tmp_path, root, dep_dirs):
    """product_deps_report in a `python -I -B` child (as run_child.py runs it), python-hcl2 mapped to FAKE."""
    env = hermetic_guard.child_env(extra={"STACKVEND_EVAL_DEPS": str(tmp_path / "no-such-deps")})
    r = subprocess.run([sys.executable, "-I", "-B", "-c",
                        "import json, sys; sys.path.insert(0, sys.argv[1]); from stackvend_eval import paths; "
                        f"paths.PRODUCT_IMPORTS = {{'python-hcl2': '{FAKE}'}}; "
                        "rep = paths.product_deps_report(sys.argv[2], json.loads(sys.argv[3])); "
                        "print(json.dumps({'rep': rep, 'msg': paths.missing_deps_message(rep, sys.argv[2])}))",
                        str(EVAL), str(root), json.dumps(dep_dirs)], capture_output=True, text=True, env=env,
                       timeout=120)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_parent_resolved_dep_dirs_reach_the_isolated_child(tmp_path, monkeypatch):
    """A parent that imports the dependency from a directory `-I` drops (PYTHONPATH, user site) resolves that
    directory and hands it to the child, which appends exactly it (the clean-checkout failure, lane 18)."""
    root, parent_only = _product_root(tmp_path)
    monkeypatch.setattr(paths, "PRODUCT_IMPORTS", {"python-hcl2": FAKE})
    monkeypatch.setenv("STACKVEND_EVAL_DEPS", str(tmp_path / "no-such-deps"))
    assert paths.resolve_product_dep_dirs(root) == []  # not importable here yet: nothing to hand over
    monkeypatch.syspath_prepend(str(parent_only))
    dirs = paths.resolve_product_dep_dirs(root)
    assert dirs == [str(parent_only)]
    assert paths.resolve_product_dep_dirs(tmp_path / "no-root") == []  # not required by that product root
    out = _child_report(tmp_path, root, dirs)
    assert out["rep"]["missing"] == [] and out["rep"]["dep_dirs_added"] == dirs
    assert out["rep"]["found"]["python-hcl2"]["origin"].startswith(str(parent_only))


def test_missing_dependency_is_named_in_one_actionable_message(tmp_path):
    root, _ = _product_root(tmp_path)
    out = _child_report(tmp_path, root, [])  # the -I child alone cannot see the parent-only directory
    assert out["rep"]["missing"] == [{"distribution": "python-hcl2", "import": FAKE}]
    assert out["rep"]["deps_dir_on_path"] is False
    assert f"python-hcl2 (import {FAKE})" in out["msg"]
    assert "pip install -r apps/orchestrator-gateway/requirements.txt" in out["msg"]


def test_check_deps_cli_exits_5_exactly_when_something_is_missing(tmp_path):
    """The entry point the e2e gate uses (probe_child_deps): JSON report, exit 5 iff `missing`."""
    root, _ = _product_root(tmp_path)
    env = hermetic_guard.child_env()
    r = subprocess.run([sys.executable, "-I", "-B", str(EVAL / "run_child.py"), "--check-deps", str(root)],
                       capture_output=True, text=True, env=env, timeout=120)
    assert r.returncode in (0, 5), r.stderr
    rep = json.loads(r.stdout)
    assert (r.returncode == 5) == bool(rep["missing"])
    assert set(rep["found"]) | {m["distribution"] for m in rep["missing"]} == {"python-hcl2"}
