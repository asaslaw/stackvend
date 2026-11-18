"""CONFTEST-TOP-LEVEL-IMPORT (live ex09-1115 on stackvend12, 11-15; diagnosis
docs/handoff/ex09-1115-dag-target-file-diagnosis.md section 1).

QA attempts 1 and 3 of ex09-1115 failed collection: `tests/test_main.py` did `from conftest import (...)` next to its
own `tests/conftest.py` (valid: pytest's default `prepend` import mode puts a non-package test directory on sys.path),
and the gatekeeper's add-only package scaffolding then wrote `tests/__init__.py` ("# Auto-generated package init by
StackVend"), which makes pytest import that conftest as `tests.conftest`: ModuleNotFoundError: No module named
'conftest' (QA: PY.TEST_SETUP_ERROR, developer log "module 'conftest' -> MISSING_MODULE_NOT_IN_CATALOG").
The scaffolding now leaves exactly that directory without an `__init__.py`; every other tree is byte-identical to
before (Invariant 1: Do No Harm). Real pytest collections run in a temporary directory (no network)."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../apps/orchestrator-gateway")))

from gatekeeper_agent.verifier import SynthesisVerifierAgent, imports_sibling_conftest_top_level  # noqa: E402

INIT = "tests/__init__.py"
CONFTEST = "import pytest\n\nTOKEN = 'abc'\n\n\n@pytest.fixture\ndef token():\n    return TOKEN\n"
ABSOLUTE = "from conftest import TOKEN\n\n\ndef test_token(token):\n    assert token == TOKEN\n"
RELATIVE = "from .conftest import TOKEN\n\n\ndef test_token(token):\n    assert token == TOKEN\n"
FIXTURE_ONLY = "def test_token(token):\n    assert token == 'abc'\n"
APP = {"apps/svc/main.py": "from fastapi import FastAPI\n\napp = FastAPI()\n", "apps/svc/requirements.txt": "fastapi\n"}


def _scaffold(files):
    cured, _ = SynthesisVerifierAgent("svc").purge_shadowed_package_files(dict(files))
    return cured


def test_ex09_attempt_1_shape_gets_no_tests_init():
    files = dict(APP, **{"tests/conftest.py": CONFTEST, "tests/test_main.py": ABSOLUTE})
    cured = _scaffold(files)
    assert INIT not in cured
    assert cured == dict(files, **{"apps/__init__.py": cured["apps/__init__.py"],
                                   "apps/svc/__init__.py": cured["apps/svc/__init__.py"]})   # the service: as before


def test_import_conftest_module_form_also_counts():
    files = {"tests/conftest.py": CONFTEST, "tests/test_a.py": "import conftest\n\n\ndef test_a():\n    pass\n"}
    assert INIT not in _scaffold(files)


@pytest.mark.parametrize("test_text", [RELATIVE, FIXTURE_ONLY])
def test_negative_relative_or_no_conftest_import_keeps_todays_init(test_text):
    files = dict(APP, **{"tests/conftest.py": CONFTEST, "tests/test_main.py": test_text})
    assert _scaffold(files)[INIT] == "# Auto-generated package init by StackVend\n"


def test_negative_mixed_relative_and_absolute_keeps_todays_init():
    files = {"tests/conftest.py": CONFTEST, "tests/test_a.py": ABSOLUTE, "tests/test_b.py": RELATIVE}
    assert INIT in _scaffold(files)


def test_negative_no_sibling_conftest_keeps_todays_init():
    files = {"tests/test_a.py": ABSOLUTE, "conftest.py": CONFTEST}
    assert INIT in _scaffold(files)


def test_negative_the_tree_imports_the_directory_as_a_package():
    files = {"tests/conftest.py": CONFTEST, "tests/test_a.py": ABSOLUTE, "tests/helpers.py": "X = 1\n",
             "tests/test_b.py": "from tests.helpers import X\n\n\ndef test_b():\n    assert X\n"}
    assert INIT in _scaffold(files)


def test_negative_an_unparseable_file_in_the_directory_keeps_todays_init():
    files = {"tests/conftest.py": CONFTEST, "tests/test_a.py": ABSOLUTE, "tests/test_b.py": "def broken(:\n"}
    assert INIT in _scaffold(files)


def test_negative_an_existing_init_is_never_touched():
    files = {"tests/conftest.py": CONFTEST, "tests/test_a.py": ABSOLUTE, INIT: "# mine\n"}
    assert _scaffold(files)[INIT] == "# mine\n"


def test_nested_service_tests_directory():
    files = dict(APP, **{"apps/svc/tests/conftest.py": CONFTEST, "apps/svc/tests/test_a.py": ABSOLUTE})
    cured = _scaffold(files)
    assert "apps/svc/tests/__init__.py" not in cured and "apps/svc/__init__.py" in cured


def test_helper_is_pure():
    files = {"tests/conftest.py": CONFTEST, "tests/test_a.py": ABSOLUTE}
    before = dict(files)
    assert imports_sibling_conftest_top_level("tests", files) is True
    assert files == before
    assert imports_sibling_conftest_top_level("other", files) is False


def _collect(tmp_path, files):
    for path, text in files.items():
        full = tmp_path / path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(text)
    ini = tmp_path / "qa_pytest.ini"
    ini.write_text("[pytest]\npython_files = test_*.py *_test.py\n")
    env = hermetic_guard.child_env(drop=("PYTEST_ADDOPTS", "PYTHONPATH"))   # the guard shim only on the path
    return subprocess.run([sys.executable, "-m", "pytest", "-c", str(ini), "--rootdir", str(tmp_path),
                           "--confcutdir", str(tmp_path), "-q", "-p", "no:cacheprovider", "tests"],
                          cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=120)


@pytest.mark.parametrize("test_text", [ABSOLUTE, RELATIVE, FIXTURE_ONLY])
def test_real_pytest_collects_the_scaffolded_tree(tmp_path, test_text):
    """The tree as the gatekeeper leaves it collects and passes under pytest's default import mode, for each style
    (before: the absolute style failed with `No module named 'conftest'`)."""
    files = {"tests/conftest.py": CONFTEST, "tests/test_main.py": test_text}
    r = _collect(tmp_path, _scaffold(files))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "1 passed" in r.stdout


def _collect_like_qa(tmp_path, files, svc_dir, test_root):
    """The QA runner's invocation (apps/qa-runner/sandbox_job.py run_service): cwd and PYTHONPATH = the service dir,
    `-c` runner ini, --rootdir / --confcutdir = the repository root, absolute test roots."""
    for path, text in files.items():
        full = tmp_path / path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(text)
    ini = tmp_path / "qa_pytest.ini"
    ini.write_text("[pytest]\npython_files = test_*.py *_test.py\n")
    env = hermetic_guard.child_env(drop=("PYTEST_ADDOPTS", "PYTHONPATH"))
    env["PYTHONPATH"] = os.pathsep.join([str(tmp_path / svc_dir), env["PYTHONPATH"]])   # service dir first, then the guard shim
    return subprocess.run([sys.executable, "-m", "pytest", "-c", str(ini), "--rootdir", str(tmp_path),
                           "--confcutdir", str(tmp_path), "-q", "-p", "no:cacheprovider", str(tmp_path / test_root)],
                          cwd=str(tmp_path / svc_dir), env=env, capture_output=True, text=True, timeout=120)


SVC_CONFTEST = {"apps/svc/conftest.py": "BASE_URL = 'http://x'\n",
                "apps/svc/tests/conftest.py": CONFTEST,
                "apps/svc/tests/test_main.py": "from conftest import BASE_URL\n\n\ndef test_a(token):\n    assert BASE_URL\n"}


@pytest.mark.parametrize("files", [
    SVC_CONFTEST,                                                                 # RT F2 S1: the service's conftest
    dict(SVC_CONFTEST, **{"apps/svc/tests/helpers.py": "H = 1\n",                 # RT F2 S2: a sub-package climbs
                          "apps/svc/tests/unit/test_u.py": "from ..helpers import H\n\n\ndef test_u():\n    assert H\n"}),
    {"conftest.py": "BASE_URL = 'x'\n", "tests/conftest.py": CONFTEST, "tests/test_main.py": ABSOLUTE},   # root one
])
def test_rt_f2_negative_another_importable_conftest_keeps_todays_init(files):
    cured = _scaffold(dict(APP, **files))
    test_dir = "tests" if "tests/conftest.py" in files else "apps/svc/tests"
    assert f"{test_dir}/__init__.py" in cured


def test_rt_f2_qa_invocation_still_passes_where_it_passed_before(tmp_path):
    files = dict(SVC_CONFTEST, **{"apps/svc/tests/helpers.py": "H = 1\n",
                                  "apps/svc/tests/unit/test_u.py": "from ..helpers import H\n\n\ndef test_u():\n"
                                                                   "    assert H\n"})
    r = _collect_like_qa(tmp_path, _scaffold(dict(APP, **files)), "apps/svc", "apps/svc/tests")
    assert r.returncode == 0 and "2 passed" in r.stdout, r.stdout + r.stderr


def test_qa_invocation_collects_the_ex09_shape_after_the_fix(tmp_path):
    files = dict(APP, **{"apps/svc/tests/conftest.py": CONFTEST, "apps/svc/tests/test_main.py": ABSOLUTE})
    r = _collect_like_qa(tmp_path, _scaffold(files), "apps/svc", "apps/svc/tests")
    assert r.returncode == 0 and "1 passed" in r.stdout, r.stdout + r.stderr


def test_real_pytest_before_the_fix_reproduces_the_live_error(tmp_path):
    files = {"tests/conftest.py": CONFTEST, "tests/test_main.py": ABSOLUTE,
             INIT: "# Auto-generated package init by StackVend\n"}
    r = _collect(tmp_path, files)
    assert r.returncode != 0 and "No module named 'conftest'" in r.stdout + r.stderr
