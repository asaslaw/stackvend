"""REQUIREMENTS-ASYNC-TEST-PLUGIN (register row, awaiting owner): a service whose QA tests include an `async def` test
gets pytest-asyncio (the QA toolchain's pin) from the gatekeeper's add-only requirements contract, and the QA runner
runs pytest-asyncio in auto mode whenever it loads it.

Seen live 2026-11-10 (examples 04 and 05): QA failed `async def` tests with "async def functions are not natively
supported": requirements.txt had no pytest-asyncio, so the runner never loaded it, and the repair could not add it.
pytest-asyncio's default strict mode would still fail an unmarked async test, and the runner's own `-c` ini ignores the
workload's pytest config, so the runner selects auto mode itself when the plugin is installed.

Covered: the AST rule (module-level and Test-class async tests; not helpers, fixtures, sync tests, non-test files,
nested defs, other classes); the contract creates and completes the file (its existing semantics) and leaves every
file without an async test, and every file naming pytest-asyncio or anyio, byte-identical; the pin parity with the
toolchain constraints and the runner's collection config; the runner's arguments (auto mode only with the plugin);
and a real pytest-asyncio run of unmarked async tests through the job.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import configparser
import os

import pytest

import qa_sandbox_support as sup
import fd4f_support  # noqa: F401,E402  (puts the gateway on sys.path)
from gatekeeper_agent import requirements_contract as RC  # noqa: E402
from qa_job_client import classify  # noqa: E402,F401
from test_qa_sandbox_job import artifacts, single_service  # noqa: E402

sj = sup.load_sandbox_job("sandbox_job_async_test_plugin")
REQS = "apps/svc/requirements.txt"
MAIN = "apps/svc/main.py"
MAIN_TEXT = "from fastapi import FastAPI\n\napp = FastAPI()\n"
ASYNC_TEST = "import asyncio\n\n\nasync def test_stream():\n    await asyncio.sleep(0)\n"
CLASS_TEST = "import asyncio\n\n\nclass TestWorker:\n    async def test_tick(self):\n        await asyncio.sleep(0)\n"
SYNC_TEST = "def test_health():\n    assert True\n"


def _tree(**extra):
    files = {MAIN: MAIN_TEXT, "apps/svc/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"}
    files.update(extra)
    return {k: v for k, v in files.items() if v is not None}


# ------------------------------------------------------------------------------------------------ the AST rule
@pytest.mark.parametrize("source,expected", [
    (ASYNC_TEST, True),
    (CLASS_TEST, True),
    ("async def testfoo():\n    pass\n", True),                                    # pytest's prefix is `test`
    (SYNC_TEST, False),
    ("async def helper():\n    pass\n", False),
    ("import pytest\n\n\n@pytest.fixture\nasync def test_data():\n    return 1\n", True),  # still collected: pytest's rule
    ("def test_outer():\n    async def test_inner():\n        pass\n", False),         # nested: not collected
    ("class Helper:\n    async def test_x(self):\n        pass\n", False),           # not a Test* class
    ("class TestX:\n    def test_x(self):\n        pass\n", False),
    ("x = 'async def test_x(): pass'\n", False),                                       # text is never read
    ("# async def test_x():\n", False),
], ids=["module", "class", "prefix", "sync", "helper", "decorated", "nested", "other_class", "sync_class", "string",
        "comment"])
def test_the_async_test_rule_reads_the_ast_only(source, expected):
    assert RC.has_async_test(ast.parse(source)) is expected


@pytest.mark.parametrize("path,expected", [
    ("tests/test_api.py", True), ("apps/svc/tests/test_x.py", True), ("apps/svc/worker_test.py", True),
    ("tests/conftest.py", False), ("apps/svc/main.py", False), ("tests/helpers.py", False), ("tests/test_x.txt", False),
])
def test_test_modules_are_the_qa_jobs_python_files(path, expected):
    assert RC.is_test_module_path(path) is expected


def test_the_collection_rules_are_the_qa_runners():
    cp = configparser.ConfigParser()
    cp.read(os.path.join(sup.QA_DIR, "qa_pytest.ini"))
    assert cp.get("pytest", "python_files").split() == [f"{RC.TEST_FILE_PREFIX}*.py", f"*{RC.TEST_FILE_SUFFIX}"]
    assert not cp.has_option("pytest", "python_functions") and not cp.has_option("pytest", "python_classes")
    assert not cp.has_option("pytest", "asyncio_mode")          # the runner selects the mode itself (below)


def test_the_pin_is_the_qa_toolchains():
    pins = sj.toolchain_pins(os.path.join(sup.QA_DIR, "qa_toolchain_constraints.txt"))
    assert pins["pytest-asyncio"] == [RC.ASYNC_TEST_PLUGIN]
    assert "pytest-asyncio" in sj.OPTIONAL_PYTEST_PLUGIN_DISTS and sj.ASYNCIO_PLUGIN_DIST == "pytest-asyncio"


# ------------------------------------------------------------------------------------------------ the contract
def test_a_created_file_gets_the_plugin():
    out, actions = RC.append_missing_requirements(_tree(**{"tests/test_stream_worker.py": ASYNC_TEST}))
    assert RC.ASYNC_TEST_PLUGIN in out[REQS].splitlines()
    assert actions[0].startswith(f"created {REQS}")


def test_a_developer_file_is_completed_add_only():
    """The contract's existing semantics: it appends a proven need to the AI's file and keeps every line."""
    before = "fastapi>=0.110.0\nuvicorn[standard]>=0.28.0\n"
    out, actions = RC.append_missing_requirements(_tree(**{REQS: before, "apps/svc/tests/test_w.py": CLASS_TEST}))
    assert out[REQS] == before + RC.ASYNC_TEST_PLUGIN + "\n"
    assert actions == [f"appended ['{RC.ASYNC_TEST_PLUGIN}'] to {REQS}"]


@pytest.mark.parametrize("extra", [
    {"tests/test_api.py": SYNC_TEST},
    {"tests/test_api.py": "async def helper():\n    pass\n\n\ndef test_x():\n    pass\n"},
    {"tests/conftest.py": "import pytest\n\n\nasync def test_like_name_in_conftest():\n    pass\n"},
    {"apps/svc/worker.py": "async def test_connection():\n    pass\n"},                # not a test module
    {"tests/test_api.py": "async def test_(:\n"},                                     # does not parse: read later
    {},
], ids=["sync_tests", "async_helper", "conftest", "not_a_test_module", "syntax_error", "no_tests"])
def test_n_without_an_async_test_the_file_is_unchanged(extra):
    before = "fastapi>=0.110.0\nuvicorn[standard]>=0.28.0\n"
    tree = _tree(**{REQS: before}, **extra)
    out, actions = RC.append_missing_requirements(tree)
    assert out[REQS] == before and actions == []


@pytest.mark.parametrize("line", ["pytest-asyncio>=0.23\n", "pytest_asyncio\n", "anyio>=4\n", "AnyIO\n",
                                  "pytest-asyncio==0.21.0  # pinned\n"])
def test_n_a_file_naming_an_async_test_runner_is_unchanged(line):
    before = "fastapi>=0.110.0\nuvicorn[standard]>=0.28.0\n" + line
    out, actions = RC.append_missing_requirements(_tree(**{REQS: before, "tests/test_a.py": ASYNC_TEST}))
    assert out[REQS] == before and actions == []


def test_root_tests_count_only_for_a_single_service():
    tree = _tree(**{REQS: "fastapi\nuvicorn[standard]\n", "tests/test_a.py": ASYNC_TEST})
    assert RC.ASYNC_TEST_PLUGIN in RC.append_missing_requirements(tree)[0][REQS]
    two = dict(tree, **{"apps/api/main.py": "x = 1\n", "apps/api/requirements.txt": ""})
    out, _ = RC.append_missing_requirements(two)                    # QA rejects a root tests/ with two services
    assert "pytest-asyncio" not in out[REQS] and "pytest-asyncio" not in out["apps/api/requirements.txt"]


def test_only_the_service_with_the_async_test_gets_it():
    tree = _tree(**{REQS: "fastapi\nuvicorn[standard]\n", "apps/api/main.py": "x = 1\n",
                    "apps/api/requirements.txt": "", "apps/api/tests/test_a.py": ASYNC_TEST})
    out, _ = RC.append_missing_requirements(tree)
    assert out[REQS] == tree[REQS] and out["apps/api/requirements.txt"] == RC.ASYNC_TEST_PLUGIN + "\n"


def test_the_appended_line_passes_the_qa_jobs_requirement_check_and_the_toolchain_pin_wins():
    pins = sj.toolchain_pins(os.path.join(sup.QA_DIR, "qa_toolchain_constraints.txt"))
    kept, dropped = sj.split_toolchain_pinned([RC.ASYNC_TEST_PLUGIN], pins)
    assert kept == [] and dropped == [(RC.ASYNC_TEST_PLUGIN, RC.ASYNC_TEST_PLUGIN)]
    assert sj.toolchain_replacements([RC.ASYNC_TEST_PLUGIN], pins, ("pytest", "pytest-timeout")) == [RC.ASYNC_TEST_PLUGIN]


# ------------------------------------------------------------------------------------------------ the runner's mode
def _venv_with(tmp_path, dists):
    sp = tmp_path / "venv" / "lib" / "python3.13" / "site-packages"
    sp.mkdir(parents=True)
    for dist, module in dists:
        info = sp / f"{dist.replace('-', '_')}-1.0.dist-info"
        info.mkdir()
        (info / "entry_points.txt").write_text(f"[pytest11]\n{module.split('.')[0]} = {module}\n")
    return str(tmp_path / "venv")


def _tc():
    return sj.Toolchain(**sup.HERMETIC_TOOLCHAIN)


def test_auto_mode_only_with_the_pytest_asyncio_plugin(tmp_path):
    venv = _venv_with(tmp_path, [("pytest-asyncio", "pytest_asyncio.plugin"), ("anyio", "anyio.pytest_plugin")])
    args = sj.pytest_plugin_args(venv, _tc())
    assert args == ["-p", "anyio.pytest_plugin", "-p", "pytest_asyncio.plugin", "-o", "asyncio_mode=auto"]


@pytest.mark.parametrize("dists", [[], [("anyio", "anyio.pytest_plugin")], [("pytest-mock", "pytest_mock")]],
                         ids=["none", "anyio", "mock"])
def test_n_without_pytest_asyncio_the_arguments_are_as_before(tmp_path, dists):
    args = sj.pytest_plugin_args(_venv_with(tmp_path, dists), _tc())
    assert args == [a for dist, module in sorted(dists) for a in ("-p", module)]
    assert "asyncio_mode=auto" not in args


# ------------------------------------------------------------------------------------------------ end to end
@pytest.fixture(scope="module")
def wheelhouse(tmp_path_factory):
    """The offline wheelhouse plus the installed pytest-asyncio repacked (no download)."""
    d = str(tmp_path_factory.mktemp("wheelhouse-async"))
    index = sup.build_wheelhouse(d)
    try:
        index["pytest-asyncio"] = [sup._wheel_from_installed("pytest-asyncio", d)]
        index["typing-extensions"] = [sup._wheel_from_installed("typing_extensions", d)]   # its dependency below 3.13
    except Exception as e:  # noqa: BLE001 - the test venv must hold pytest-asyncio 1.4.0 (the platform's own CI pin)
        pytest.skip(f"pytest-asyncio cannot be repacked here ({type(e).__name__})")
    return d, index


@pytest.fixture()
def cloud(wheelhouse):
    c = sup.FakeCloud(*wheelhouse)
    yield c
    c.close()


@pytest.fixture()
def toolchain(cloud, tmp_path):
    return sup.make_toolchain(sj, cloud, str(tmp_path))


def _job(cloud, toolchain, files):
    from test_qa_sandbox_job import run
    return run(cloud, toolchain, files)


def test_unmarked_async_tests_pass_with_the_contracts_requirements(cloud, toolchain):
    """Example 04's shape: unmarked `async def test_*` (module level and in a Test class), the requirements the
    contract writes for them, a real pytest-asyncio in the QA venv."""
    files = single_service(**{"tests/test_stream_worker.py": ASYNC_TEST + "\n\n" + CLASS_TEST.split("\n", 1)[1],
                              "apps/svc/requirements.txt": ""})
    out, _ = RC.append_missing_requirements({k: v for k, v in files.items() if isinstance(v, str)})
    assert RC.ASYNC_TEST_PLUGIN in out["apps/svc/requirements.txt"].splitlines()
    # the offline index holds no web stack: QA installs exactly the line this row adds (the other needs are older rows')
    needs = RC.async_test_needs(files, "svc")
    assert needs == {RC.ASYNC_TEST_PLUGIN}
    code, _ = _job(cloud, toolchain, dict(files, **{"apps/svc/requirements.txt": "".join(f"{n}\n" for n in needs)}))
    static, report = artifacts(cloud)
    assert code == 0, (static, report)
    assert report["tests_failed"] == 0 and report["tests_total"] >= 3


def test_the_plugin_in_strict_mode_alone_would_not_fix_unmarked_tests(cloud, toolchain, monkeypatch):
    """Why the runner selects auto mode: with pytest-asyncio loaded in its default strict mode the same unmarked
    tests still fail."""
    import test_qa_sandbox_job as job_tests   # its `run` drives its own loaded copy of the job module
    monkeypatch.setattr(job_tests.sj, "ASYNCIO_AUTO_MODE_ARGS", ())
    files = single_service(**{"tests/test_stream_worker.py": ASYNC_TEST,
                              "apps/svc/requirements.txt": RC.ASYNC_TEST_PLUGIN + "\n"})
    code, _ = _job(cloud, toolchain, files)
    _static, report = artifacts(cloud)
    assert code == 10 and "PY.TEST_FAILED" in [d["code"] for d in report["diagnostics"]]


def test_n_without_the_plugin_the_same_tests_still_fail_as_today(cloud, toolchain):
    files = single_service(**{"tests/test_stream_worker.py": ASYNC_TEST})
    code, _ = _job(cloud, toolchain, files)
    _static, report = artifacts(cloud)
    assert code == 10 and "PY.TEST_FAILED" in [d["code"] for d in report["diagnostics"]]
