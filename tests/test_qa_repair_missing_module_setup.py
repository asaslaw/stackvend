"""QA-REPAIR-MISSING-MODULE-SETUP (register row, awaiting owner): the QA runner reports the module a test's setup or
collection could not import as the same typed `missing_module` fact, and the QA repair may add exactly the one
distribution the closed catalog maps it to.

Seen live 2026-11-10 (example 08, run ex08-1110): 14 tests errored in setup with
`ModuleNotFoundError: No module named 'aiosqlite'` (the fixtures build a `sqlite+aiosqlite://` engine, so no import line
names the driver). QA-REPAIR-SETUP-ERROR offered requirements.txt, but the guard had no fact allowing the driver: the
typed fact came only from the import smoke, so each of three attempts was refused (REQUIREMENTS_ADDITION_REFUSED).

Covered: the runner's own pytest plugin (apps/qa-runner/qa_missing_module_plugin.py) records the exception's own `name`
for collection and setup errors (never the traceback text), loaded through the environment only (argv, the
environment the tests see and the junit report are unchanged; it is not loaded when the service directory could shadow
it); the job reads the fact as untrusted and adds it only to PY.TEST_SETUP_ERROR diagnostics; the gateway maps it
through the catalog for a draft requirements file (crash guard) and a gatekeeper-written one (add-only, exactly one
name); every other status, a forged or oversized fact and an unscoped finding widen nothing; and the developer stage
end to end. `aiosqlite` itself joined the catalog later (AIOSQLITE-CATALOG, owner 11-11); a module outside the catalog
(here `aiomysql`) is reported as MISSING_MODULE_NOT_IN_CATALOG, never guessed.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

import qa_sandbox_support as sup
import fd4f_support  # noqa: F401,E402  (puts the gateway on sys.path)
from test_qa_feedback import _develop, _feedback, _first_build, _qa_diag  # noqa: E402
from test_qa_sandbox_job import artifacts, cloud, gateway_verdict, run, single_service, toolchain, wheelhouse  # noqa: F401,E402
from test_qa_repair_setup_error import CONFTEST, SETUP_TREE, TEST_API, TEST_OTHER, TESTS_INIT  # noqa: E402
from developer_agent import qa_repair as QR  # noqa: E402
from developer_agent import qa_requirements_guard as G  # noqa: E402
from gatekeeper_agent.pypi_catalog import CANONICAL_PYPI_CATALOG, resolve_import_to_pypi  # noqa: E402
from gatekeeper_agent.requirements_contract import append_missing_requirements  # noqa: E402
from shared.diagnostics import RepairBudgetExhausted  # noqa: E402

sj = sup.load_sandbox_job("sandbox_job_qa_repair_missing_module_setup")
PLUGIN_FILE = os.path.join(sup.QA_DIR, "qa_missing_module_plugin.py")
_spec = importlib.util.spec_from_file_location("qa_missing_module_plugin_under_test", PLUGIN_FILE)
plugin = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plugin)

REQS = "apps/shop/requirements.txt"
ASYNCPG = CANONICAL_PYPI_CATALOG["asyncpg"]
AIOSQLITE = CANONICAL_PYPI_CATALOG["aiosqlite"]
SETUP_TEXT = "ModuleNotFoundError: No module named 'asyncpg'"


def _setup_error(missing="asyncpg", file=TEST_API, **kw):
    base = dict(file=file, code="PY.TEST_SETUP_ERROR", message='tests.test_api.test_a: failed on setup with "E"',
                detail=SETUP_TEXT)
    base.update(kw)
    d = _qa_diag(**base)
    d["tool"] = "pytest"
    if missing is not None:
        d["missing_module"] = missing
    return d


# ------------------------------------------------------------------------------------------------ catalog fact
def test_aiosqlite_and_asyncpg_are_in_the_catalog_and_aiomysql_is_not():
    """The live module of run ex08-1110 is in the closed catalog since AIOSQLITE-CATALOG (owner 11-11); a module
    the catalog does not know is still reported by name and adds nothing."""
    assert resolve_import_to_pypi("aiosqlite") == AIOSQLITE
    assert resolve_import_to_pypi("asyncpg") == ASYNCPG
    assert resolve_import_to_pypi("aiomysql") is None


def test_the_runner_and_the_plugin_agree():
    assert plugin.FACT_SUFFIX == sj.MISSING_MODULE_FACT_SUFFIX
    assert plugin.PLUGINS_ENV == sj.PYTEST_PLUGINS_ENV
    assert os.path.basename(sj.Toolchain().missing_module_plugin) == f"{sj.MISSING_MODULE_PLUGIN}.py"
    assert os.path.isfile(sj.Toolchain().missing_module_plugin)
    assert plugin.MAX_CHAIN_LINKS == 32 and "n < 32" in sj.IMPORT_SMOKE_BY_ARGV   # the import smoke's own walk


def _raise(make):
    try:
        make()
    except BaseException as e:  # noqa: BLE001
        return e
    raise AssertionError("did not raise")


def _cause():
    try:
        import definitely_missing_cause_xyz  # noqa: F401
    except ImportError as e:
        raise RuntimeError("wrapped") from e


def _context():
    try:
        import definitely_missing_context_xyz  # noqa: F401
    except ImportError:
        raise RuntimeError("during")


def _suppressed():
    try:
        import definitely_missing_suppressed_xyz  # noqa: F401
    except ImportError:
        raise RuntimeError("no context") from None


@pytest.mark.parametrize("make,name", [
    (lambda: __import__("definitely_missing_plain_xyz"), "definitely_missing_plain_xyz"),
    (lambda: __import__("json.definitely_missing_sub"), "json.definitely_missing_sub"),
    (_cause, "definitely_missing_cause_xyz"),
    (_context, "definitely_missing_context_xyz"),
    (_suppressed, None),
    (lambda: (_ for _ in ()).throw(ImportError("not a ModuleNotFoundError")), None),
    (lambda: (_ for _ in ()).throw(ModuleNotFoundError("no name")), None),
    (lambda: 1 / 0, None),
], ids=["plain", "submodule", "cause", "context", "suppressed", "import_error", "no_name", "other"])
def test_the_plugin_takes_the_exceptions_own_name(make, name):
    assert plugin.missing_module_name(_raise(make)) == name


# ------------------------------------------------------------------------------------------------ real pytest, plugin only
FIXTURE_MISSING = ("import importlib\nimport pytest\n\n\n@pytest.fixture\ndef engine():\n"
                   "    # a driver chosen by name from a URL: no import line names it\n"
                   "    return importlib.import_module('definitely_missing_' + 'driver_xyz')\n")
FIXTURE_RAISES = "import pytest\n\n\n@pytest.fixture\ndef engine():\n    raise RuntimeError('no engine')\n"
FIXTURE_OK = "import pytest\n\n\n@pytest.fixture\ndef engine():\n    return 'engine'\n"
FIXTURE_TEARDOWN = ("import importlib\nimport pytest\n\n\n@pytest.fixture\ndef engine():\n    yield object()\n"
                    "    importlib.import_module('definitely_missing_teardown_xyz')\n")
USES_ENGINE = "def test_a(engine):\n    assert engine\n\n\ndef test_b(engine):\n    assert engine\n"
FAILS = "def test_a(engine):\n    assert 1 == 2\n"
COLLECT_MISSING = "import definitely_missing_collect_xyz  # noqa\n\n\ndef test_a():\n    pass\n"


def _pytest(tmp_path, conftest, test, *, plugin_on):
    """The job's pytest shape (own ini, autoload off), with the plugin loaded exactly as the job loads it or not."""
    work = tmp_path / "work"   # one directory for both runs: the tracebacks in the junit name the same paths
    (work / "tests").mkdir(parents=True, exist_ok=True)
    (work / "tests" / "conftest.py").write_text(conftest)
    (work / "tests" / "test_api.py").write_text(test)
    site = tmp_path / "site"
    site.mkdir(exist_ok=True)
    shutil.copyfile(PLUGIN_FILE, site / f"{sj.MISSING_MODULE_PLUGIN}.py")
    out = tmp_path / ("on" if plugin_on else "off")
    out.mkdir()
    junit = out / "junit.xml"
    env = dict(hermetic_guard.child_env(), PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTEST_ADDOPTS="-p no:cacheprovider",
               PYTHONPATH=str(site))
    if plugin_on:
        env.update(sj.missing_module_plugin_env(str(work)))
    r = subprocess.run([sys.executable, "-m", "pytest", "-c", os.path.join(sup.QA_DIR, "qa_pytest.ini"), "--rootdir",
                        str(work), "--junitxml", str(junit), "-q", "tests"], cwd=str(work), env=env,
                       capture_output=True, text=True, timeout=120)
    fact = sj.missing_module_fact(str(junit) + sj.MISSING_MODULE_FACT_SUFFIX)
    return r, junit, fact


def _junit_shape(path):
    """The junit without the attributes that differ on every run (time, timestamp, hostname)."""
    root = ET.parse(str(path)).getroot()
    for el in root.iter():
        for key in ("time", "timestamp", "hostname"):
            el.attrib.pop(key, None)
    return ET.tostring(root)


CASES = [
    ("setup_missing", FIXTURE_MISSING, USES_ENGINE, "definitely_missing_driver_xyz"),
    ("collect_missing", FIXTURE_OK, COLLECT_MISSING, "definitely_missing_collect_xyz"),
    ("setup_other_error", FIXTURE_RAISES, USES_ENGINE, None),
    ("teardown_missing", FIXTURE_TEARDOWN, USES_ENGINE, None),      # setup and collection only
    ("passing", FIXTURE_OK, USES_ENGINE, None),
    ("failing", FIXTURE_OK, FAILS, None),
]


@pytest.mark.parametrize("label,conftest,test,fact", CASES, ids=[c[0] for c in CASES])
def test_the_plugin_writes_the_fact_and_changes_nothing_else(tmp_path, label, conftest, test, fact):
    """Do No Harm: the same exit status, output summary and junit with and without the plugin; the fact only for a
    ModuleNotFoundError in collection or setup."""
    off, junit_off, fact_off = _pytest(tmp_path, conftest, test, plugin_on=False)
    on, junit_on, fact_on = _pytest(tmp_path, conftest, test, plugin_on=True)
    assert fact_on == fact and fact_off is None
    assert on.returncode == off.returncode
    summary = lambda out: re.sub(r" in [0-9.]+s", "", out.strip().splitlines()[-1])  # noqa: E731
    assert summary(on.stdout) == summary(off.stdout)
    assert _junit_shape(junit_on) == _junit_shape(junit_off)


def test_the_first_module_wins_and_the_fact_file_is_create_only(tmp_path):
    two = FIXTURE_MISSING + ("\n\n@pytest.fixture\ndef other():\n    import definitely_missing_second_xyz  # noqa\n")
    test = "def test_a(engine):\n    pass\n\n\ndef test_b(other):\n    pass\n"
    _r, _junit, fact = _pytest(tmp_path, two, test, plugin_on=True)
    assert fact == "definitely_missing_driver_xyz"


# ------------------------------------------------------------------------------------------------ the job, end to end
SETUP_CONFTEST = FIXTURE_MISSING.replace("def engine", "def client")
CLIENT_TESTS = "def test_a(client):\n    assert client\n\n\ndef test_b(client):\n    assert client\n"
PROBE = ("import os\nimport sys\n\n\ndef test_probe():\n"
         "    assert False, 'PROBE=' + repr((sys.argv, 'PYTEST_PLUGINS' in os.environ, "
         "'qa_missing_module_plugin' in sys.modules))\n")


def _probe(report):
    (d,) = [d for d in report["diagnostics"] if d["code"] == "PY.TEST_FAILED"]
    return eval(d["message"].split("PROBE=", 1)[1].split("\n")[0])  # noqa: S307 - the test's own repr


def test_a_fixture_that_loads_a_missing_module_is_a_setup_error_with_the_fact(cloud, toolchain):
    code, _ = run(cloud, toolchain, single_service(**{"tests/conftest.py": SETUP_CONFTEST,
                                                      "tests/test_main.py": CLIENT_TESTS}))
    _static, report = artifacts(cloud)
    assert code == 10, report
    errors = [d for d in report["diagnostics"] if d["severity"] == "error"]
    assert [(d["code"], d["file"], d.get("missing_module")) for d in errors] == [
        ("PY.TEST_SETUP_ERROR", "tests/test_main.py", "definitely_missing_driver_xyz")] * 2
    outcome = gateway_verdict(cloud, code)
    assert [x.get("missing_module") for x in outcome.diagnostics if x["severity"] == "error"] == [
        "definitely_missing_driver_xyz"] * 2


def test_a_test_module_that_imports_a_missing_module_is_a_collection_error_with_the_fact(cloud, toolchain):
    code, _ = run(cloud, toolchain, single_service(**{"tests/test_main.py": COLLECT_MISSING}))
    _static, report = artifacts(cloud)
    assert code == 10, report
    errors = [d for d in report["diagnostics"] if d["severity"] == "error"]
    assert [(d["code"], d.get("missing_module")) for d in errors] == [
        ("PY.TEST_SETUP_ERROR", "definitely_missing_collect_xyz")]


def test_without_a_missing_module_the_report_is_exactly_as_without_the_plugin(cloud, toolchain):
    """Do No Harm through the job: the same diagnostics (keys and values, the per-run temp paths aside) with the plugin
    switched off; no diagnostic gains a field."""
    import dataclasses
    files = single_service(**{"tests/conftest.py": FIXTURE_RAISES.replace("def engine", "def client"),
                              "tests/test_main.py": CLIENT_TESTS, "tests/test_fail.py": "def test_f():\n    assert 1 == 2\n"})
    run(cloud, toolchain, files)
    _s, with_plugin = artifacts(cloud)
    cloud.objects.clear()
    run(cloud, dataclasses.replace(toolchain, missing_module_plugin=None), files)
    _s, without = artifacts(cloud)
    shape = lambda r: [(sorted(d), d["code"], d["file"], d["line"], d["message"]) for d in r["diagnostics"]]  # noqa: E731
    assert shape(with_plugin) == shape(without)
    assert not any("missing_module" in d for d in with_plugin["diagnostics"])
    assert (with_plugin["tests_total"], with_plugin["tests_failed"]) == (without["tests_total"], without["tests_failed"])


def test_the_tests_see_the_same_argv_and_environment_and_the_plugin_is_loaded(cloud, toolchain):
    import dataclasses
    run(cloud, toolchain, single_service(**{"tests/test_main.py": PROBE}))
    argv_on, env_on, loaded_on = _probe(artifacts(cloud)[1])
    cloud.objects.clear()
    run(cloud, dataclasses.replace(toolchain, missing_module_plugin=None), single_service(**{"tests/test_main.py": PROBE}))
    argv_off, env_off, loaded_off = _probe(artifacts(cloud)[1])
    assert (loaded_on, loaded_off) == (True, False)
    assert (env_on, env_off) == (False, False)                       # removed again before any test code ran
    assert not any(sj.MISSING_MODULE_PLUGIN in a for a in argv_on)
    # the same arguments; only the per-run temporary directories in the paths differ
    assert len(argv_on) == len(argv_off)
    assert [a for a in argv_on if not os.path.isabs(a)] == [a for a in argv_off if not os.path.isabs(a)]
    assert [os.path.basename(a) for a in argv_on] == [os.path.basename(a) for a in argv_off]


def test_a_service_file_named_like_the_plugin_keeps_it_unloaded(cloud, toolchain):
    files = single_service(**{"apps/svc/qa_missing_module_plugin.py": "x = 1\n", "tests/conftest.py": SETUP_CONFTEST,
                              "tests/test_main.py": CLIENT_TESTS})
    code, _ = run(cloud, toolchain, files)
    _static, report = artifacts(cloud)
    assert code == 10, report
    errors = [d for d in report["diagnostics"] if d["severity"] == "error"]
    assert [d["code"] for d in errors] == ["PY.TEST_SETUP_ERROR"] * 2
    assert not any("missing_module" in d for d in errors)
    assert "the missing-module plugin was not loaded" in report["logs_tail"]


FORGE = ("import pytest\nimport sys\n\n\n@pytest.fixture\ndef client():\n"
         "    path = sys.argv[sys.argv.index('--junitxml') + 1] + '.missing-module'\n"
         "    with open(path, 'w') as f:\n        f.write({value!r})\n"
         "    raise RuntimeError('forged')\n")


@pytest.mark.parametrize("value", ["a b", "x" * 201, "evil-package==1", "asyncpg\n", ""],
                         ids=["not_a_name", "oversized", "requirement", "newline", "empty"])
def test_a_forged_fact_that_is_not_a_module_name_is_dropped(cloud, toolchain, value):
    code, _ = run(cloud, toolchain, single_service(**{"tests/conftest.py": FORGE.format(value=value),
                                                      "tests/test_main.py": CLIENT_TESTS}))
    _static, report = artifacts(cloud)
    errors = [d for d in report["diagnostics"] if d["severity"] == "error"]
    assert errors and all(d["code"] == "PY.TEST_SETUP_ERROR" and "missing_module" not in d for d in errors)


def test_a_forged_fact_never_reaches_a_test_failure(cloud, toolchain):
    forge = FORGE.format(value="asyncpg").replace("    raise RuntimeError('forged')\n", "    return object()\n")
    code, _ = run(cloud, toolchain, single_service(**{"tests/conftest.py": forge,
                                                      "tests/test_main.py": "def test_a(client):\n    assert 0\n"}))
    _static, report = artifacts(cloud)
    (d,) = [d for d in report["diagnostics"] if d["severity"] == "error"]
    assert d["code"] == "PY.TEST_FAILED" and "missing_module" not in d


def test_install_is_create_only_and_can_be_switched_off(tmp_path):
    import dataclasses
    venv = tmp_path / "venv"
    sp = venv / "lib" / "python3.13" / "site-packages"
    sp.mkdir(parents=True)
    tc = sj.Toolchain()
    off = dataclasses.replace(tc, missing_module_plugin=None)
    assert sj.install_missing_module_plugin(str(venv), off) == sj.PLUGIN_OFF
    assert sj.install_missing_module_plugin(str(venv), tc) == sj.PLUGIN_INSTALLED
    assert (sp / "qa_missing_module_plugin.py").read_bytes() == open(PLUGIN_FILE, "rb").read()
    # already there: never overwritten
    assert sj.install_missing_module_plugin(str(venv), tc) == sj.PLUGIN_SHADOWED_BY_REQUIREMENT
    for entry in ("qa_missing_module_plugin", "qa_missing_module_plugin.cpython-313-x86_64-linux-gnu.so"):
        other = tmp_path / entry.replace(".", "_")
        osp = other / "lib" / "python3.13" / "site-packages"
        osp.mkdir(parents=True)
        (osp / entry).mkdir() if "." not in entry else (osp / entry).write_text("")
        # a requirement shipped that name
        assert sj.install_missing_module_plugin(str(other), tc) == sj.PLUGIN_SHADOWED_BY_REQUIREMENT
    with pytest.raises(sj.RunnerError):
        sj.install_missing_module_plugin(str(tmp_path / "no-venv"), tc)


def test_rt_f2_a_requirement_that_ships_the_plugins_name_is_logged_and_the_plugin_stays_unloaded(cloud, toolchain,
                                                                                                  wheelhouse):
    fn = sup.build_plugin_wheel(wheelhouse[0], "qa-missing-module-plugin", "1.0", "qa_missing_module_plugin",
                                "VALUE = 1\n")
    cloud.wheel_index["qa-missing-module-plugin"] = [fn]
    files = single_service(**{"apps/svc/requirements.txt": "qa-missing-module-plugin==1.0\n",
                              "tests/conftest.py": SETUP_CONFTEST, "tests/test_main.py": CLIENT_TESTS})
    code, _ = run(cloud, toolchain, files)
    _static, report = artifacts(cloud)
    assert code == 10, report
    errors = [d for d in report["diagnostics"] if d["severity"] == "error"]
    assert [d["code"] for d in errors] == ["PY.TEST_SETUP_ERROR"] * 2
    assert not any("missing_module" in d for d in errors)
    assert ("the missing-module plugin was not loaded (an installed requirement ships an entry named "
            "qa_missing_module_plugin)") in report["logs_tail"]


def test_rt_f2_switched_off_is_silent(cloud, toolchain):
    import dataclasses
    run(cloud, dataclasses.replace(toolchain, missing_module_plugin=None),
        single_service(**{"tests/conftest.py": SETUP_CONFTEST, "tests/test_main.py": CLIENT_TESTS}))
    assert "missing-module plugin" not in artifacts(cloud)[1]["logs_tail"]


@pytest.mark.parametrize("make,reason", [
    (lambda p, t: p.write_bytes(b"a" * 201), "FACT_TOO_LARGE"),
    (lambda p, t: p.write_bytes(b"a b"), "FACT_NOT_MODULE_NAME"),
    (lambda p, t: p.write_bytes(b"\xff\xfe"), "FACT_NOT_UTF8"),
    (lambda p, t: (t.write_text("asyncpg"), os.symlink(str(t), str(p))), "FACT_NOT_REGULAR"),
    (lambda p, t: p.mkdir(), "FACT_NOT_REGULAR"),
    (lambda p, t: os.mkfifo(str(p)) if hasattr(os, "mkfifo") else pytest.skip("no mkfifo"), "FACT_NOT_REGULAR"),
], ids=["too_large", "not_a_name", "not_utf8", "symlink", "directory", "fifo"])
def test_rt_f3_a_dropped_fact_has_a_typed_reason_and_one_log_line(tmp_path, make, reason):
    path, target = tmp_path / "fact", tmp_path / "target"
    make(path, target)
    assert sj.read_missing_module_fact(str(path)) == (None, getattr(sj, reason))
    res = sj.DynamicResult()
    assert sj.missing_module_fact_logged(str(path), "apps/svc", "pytest", res) is None
    assert res.logs == [f"== apps/svc: note: the pytest missing-module fact was dropped ({getattr(sj, reason)})"]
    assert "asyncpg" not in res.logs[0] and "a b" not in res.logs[0]          # never the content


def test_rt_f3_no_file_and_a_valid_fact_log_nothing(tmp_path):
    res = sj.DynamicResult()
    assert sj.read_missing_module_fact(str(tmp_path / "absent")) == (None, None)
    assert sj.missing_module_fact_logged(str(tmp_path / "absent"), "apps/svc", "pytest", res) is None
    (tmp_path / "ok").write_text("asyncpg")
    assert sj.missing_module_fact_logged(str(tmp_path / "ok"), "apps/svc", "import smoke", res) == "asyncpg"
    assert res.logs == []


def test_rt_f3_a_forged_fact_is_logged_by_the_job(cloud, toolchain):
    code, _ = run(cloud, toolchain, single_service(**{"tests/conftest.py": FORGE.format(value="a b"),
                                                      "tests/test_main.py": CLIENT_TESTS}))
    logs = artifacts(cloud)[1]["logs_tail"]
    assert f"note: the pytest missing-module fact was dropped ({sj.FACT_NOT_MODULE_NAME})" in logs


def test_rt_f3_the_import_smoke_path_logs_a_dropped_fact_too(cloud, toolchain):
    """The code under test writes a malformed fact where the smoke would (the service work dir is its venv's parent,
    on PATH), then fails the import with another error: dropped and logged, never in the diagnostic."""
    files = single_service(**{"apps/svc/main.py": (
        "import os\n"
        "for p in os.environ.get('PATH', '').split(':'):\n"
        "    if p.endswith('/venv/bin'):\n"
        "        with open(os.path.join(os.path.dirname(os.path.dirname(p)), 'import-fact-main'), 'w') as f:\n"
        "            f.write('not a module')\n"
        "raise RuntimeError('boom')\n")})
    code, _ = run(cloud, toolchain, files)
    _static, report = artifacts(cloud)
    (d,) = [d for d in report["diagnostics"] if d["code"] == "PY.IMPORT_FAILED"]
    assert "missing_module" not in d
    assert (f"note: the import smoke missing-module fact was dropped ({sj.FACT_NOT_MODULE_NAME})"
            in report["logs_tail"])


@pytest.mark.parametrize("entry,loaded", [
    (None, True), ("qa_missing_module_plugin.py", False), ("qa_missing_module_plugin", False),
    ("qa_missing_module_plugin.pyc", False), ("qa_missing_module_plugin_extra.py", True), ("main.py", True),
])
def test_the_plugin_env_is_withheld_when_the_service_could_shadow_it(tmp_path, entry, loaded):
    if entry is not None:
        (tmp_path / entry).write_text("")
    assert sj.missing_module_plugin_env(str(tmp_path)) == (
        {"PYTEST_PLUGINS": "qa_missing_module_plugin"} if loaded else {})


def test_parse_junit_adds_the_fact_only_to_setup_errors(tmp_path):
    p = tmp_path / "junit.xml"
    p.write_text('<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">'
                 '<testcase classname="tests.test_api" name="test_a" file="tests/test_api.py" line="0">'
                 '<error message="failed on setup">t</error></testcase>'
                 '<testcase classname="tests.test_api" name="test_b" file="tests/test_api.py" line="3">'
                 '<failure message="assert False">t</failure></testcase></testsuite></testsuites>')
    _t, _f, before, _i = sj.parse_junit(str(p))
    _t, _f, after, _i = sj.parse_junit(str(p), "asyncpg")
    assert [d.get("missing_module") for d in after] == ["asyncpg", None]
    assert after[1] == before[1] and dict(after[0], missing_module=None) != before[0]
    assert {k: v for k, v in after[0].items() if k != "missing_module"} == before[0]


# ------------------------------------------------------------------------------------------------ the plan
def test_a_draft_requirements_file_gains_exactly_the_catalog_distribution_under_the_crash_guard():
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _setup_error()), stack_configured=True)
    today = QR.plan_qa_repair(_feedback(SETUP_TREE, _setup_error(missing=None)), stack_configured=True)
    assert plan.reason == today.reason == "PYTEST_SETUP_ERROR_ON_TEST_SETUP"
    assert plan.repairable_paths == today.repairable_paths == {REQS, CONFTEST, TESTS_INIT, TEST_API}
    assert plan.requirements_crash_guard[REQS] == today.requirements_crash_guard[REQS] | {"asyncpg"}
    assert "asyncpg" not in today.requirements_crash_guard[REQS] and not plan.requirements_guard
    for s in plan.seeds:
        assert s.hint == QR.MISSING_MODULE_SETUP_SEED_HINT and f"`{ASYNCPG}`" in s.message
        assert SETUP_TEXT not in s.model_dump_json()
    assert all(s.hint == QR.SETUP_ERROR_SEED_HINT for s in today.seeds)
    assert plan.summary()["missing_modules"] == [{"file": TEST_API, "module": "asyncpg", "status": QR.MODULE_IN_CATALOG,
                                                  "requirement": ASYNCPG, "requirements": REQS}]


def test_fourteen_errored_tests_are_one_record_and_one_group():
    errors = [_setup_error(), _setup_error(file=TEST_OTHER)] + [_setup_error() for _ in range(12)]
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, *errors), stack_configured=True)
    assert {s.symbol for s in plan.seeds} == {"qa_setup_error_1"} and plan.findings == 14
    assert len(plan.summary()["missing_modules"]) == 1


@pytest.mark.parametrize("first,second", [("asyncpg", "psycopg"), ("psycopg", "asyncpg")])
@pytest.mark.parametrize("gatekeeper", [False, True], ids=["draft_requirements", "gatekeeper_requirements"])
def test_rt_f1_two_values_in_one_service_widen_only_the_first_and_record_the_conflict(first, second, gatekeeper):
    """RT F1: the runner sends one fact per pytest run; another sender's second value for the same service adds
    nothing and is recorded as MISSING_MODULE_CONFLICT."""
    tree, draft_paths = _gatekeeper_tree() if gatekeeper else (SETUP_TREE, sorted(SETUP_TREE))
    errors = [_setup_error(missing=first), _setup_error(missing=second, file=TEST_OTHER), _setup_error(missing=first)]
    plan = QR.plan_qa_repair(_feedback(tree, *errors, draft_paths=draft_paths), stack_configured=True)
    only_first = QR.plan_qa_repair(_feedback(tree, *[_setup_error(missing=first, file=d["file"]) for d in errors],
                                             draft_paths=draft_paths), stack_configured=True)
    assert dict(plan.requirements_guard) == dict(only_first.requirements_guard)
    assert dict(plan.requirements_crash_guard) == dict(only_first.requirements_crash_guard)
    guard = (plan.requirements_guard if gatekeeper else plan.requirements_crash_guard)[REQS]
    assert first in guard and second not in guard
    assert [(m["module"], m["status"], m["requirements"]) for m in plan.summary()["missing_modules"]] == [
        (first, QR.MODULE_IN_CATALOG, REQS), (second, QR.MODULE_CONFLICT, None)]
    assert plan.summary()["missing_modules"][1]["file"] == TEST_OTHER


def test_rt_f1_two_services_each_keep_their_own_first_value():
    from test_qa_repair_setup_error import API_TEST, API_REQS, SHOP_TEST, TWO
    plan = QR.plan_qa_repair(_feedback(TWO, _setup_error(missing="asyncpg", file=API_TEST),
                                       _setup_error(missing="psycopg", file=SHOP_TEST)), stack_configured=True)
    assert "asyncpg" in plan.requirements_crash_guard[API_REQS] and "psycopg" not in plan.requirements_crash_guard[API_REQS]
    assert "psycopg" in plan.requirements_crash_guard[REQS] and "asyncpg" not in plan.requirements_crash_guard[REQS]
    assert [m["status"] for m in plan.summary()["missing_modules"]] == [QR.MODULE_IN_CATALOG] * 2


def _gatekeeper_tree():
    """The developer wrote the service, its conftest and tests, no requirements.txt; the gatekeeper's contract
    created it (append_missing_requirements, as reconcile_service_requirements runs it)."""
    draft = {p: c for p, c in SETUP_TREE.items() if p != REQS and not p.startswith(("infra/", ".github/"))}
    tree, actions = append_missing_requirements(draft)
    assert actions and REQS in tree and "asyncpg" not in tree[REQS]
    tree = dict(tree, **{p: c for p, c in SETUP_TREE.items() if p.startswith(("infra/", ".github/"))})
    return tree, sorted(draft)


def test_a_gatekeeper_written_requirements_file_joins_the_group_add_only_for_exactly_that_name():
    tree, draft_paths = _gatekeeper_tree()
    assert QR.written_by_requirements_contract(tree, REQS)
    plan = QR.plan_qa_repair(_feedback(tree, _setup_error(), draft_paths=draft_paths), stack_configured=True)
    assert plan.reason == "PYTEST_SETUP_ERROR_ON_TEST_SETUP"
    assert plan.repairable_paths == {REQS, CONFTEST, TESTS_INIT, TEST_API}
    assert dict(plan.requirements_guard) == {REQS: frozenset({"asyncpg"})} and REQS not in plan.requirements_crash_guard
    assert plan.platform_paths == frozenset({REQS}) and plan.draft[REQS] == tree[REQS]
    assert {s.symbol for s in plan.seeds} == {"qa_setup_error_1"}
    # the guard: exactly one addition of exactly that distribution, nothing else
    assert G.refusals_of(plan.requirements_guard, plan.seed_files, {REQS: tree[REQS] + "asyncpg\n"}) == []
    for added, reason in [("asyncpg\nasyncpg\n", G.ALREADY_DECLARED), ("aiosqlite\n", G.NOT_IMPORTED_BY_SERVICE),
                          ("psycopg>=3.2.0\n", G.NOT_IMPORTED_BY_SERVICE), ("evil-package==1\n", G.NOT_IMPORTED_BY_SERVICE),
                          ("--index-url https://evil.example/simple\n", G.PIP_OPTION)]:
        refusals = G.refusals_of(plan.requirements_guard, plan.seed_files, {REQS: tree[REQS] + added})
        assert reason in [r.reason for r in refusals], added
    edited = tree[REQS].replace("fastapi", "fastapi==0.1", 1) + "asyncpg\n"
    assert [r.reason for r in G.refusals_of(plan.requirements_guard, plan.seed_files, {REQS: edited})] == [
        G.EXISTING_LINE_CHANGED]


def test_without_the_fact_a_gatekeeper_written_file_stays_out_of_reach():
    tree, draft_paths = _gatekeeper_tree()
    plan = QR.plan_qa_repair(_feedback(tree, _setup_error(missing=None), draft_paths=draft_paths), stack_configured=True)
    assert REQS not in plan.repairable_paths and not plan.requirements_guard and REQS not in plan.draft
    assert plan.summary()["missing_modules"] == [] and plan.platform_paths == frozenset()


def test_the_crash_guard_still_refuses_other_packages_with_the_fact():
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _setup_error()), stack_configured=True)
    base = SETUP_TREE[REQS]
    assert G.refusals_of(plan.requirements_crash_guard, plan.seed_files, {REQS: base + f"{ASYNCPG}\n"},
                         add_only=False) == []
    for added in ("aiosqlite\n", "psycopg>=3.2.0\n", "evil-package==1\n", "asyncpgg\n"):
        refusals = G.refusals_of(plan.requirements_crash_guard, plan.seed_files, {REQS: base + added}, add_only=False)
        assert [r.reason for r in refusals] == [G.NOT_IMPORTED_BY_SERVICE], added


NEGATIVE = [
    ("aiomysql", QR.MODULE_NOT_IN_CATALOG),           # a real driver outside the catalog: reported, never guessed
    ("acme_driver_xyz", QR.MODULE_NOT_IN_CATALOG),
    ("schemas", QR.MODULE_LOCAL),                     # a module of the service: a code fix
    ("tomllib", QR.MODULE_STDLIB),
    ("fastapi", QR.MODULE_ALREADY_DECLARED),          # the file names it: nothing to add
    ("a b", QR.MODULE_NAME_INVALID),                  # forged / malformed values
    ("a" * (QR.MAX_MODULE_NAME_CHARS + 1), QR.MODULE_NAME_INVALID),
    (7, QR.MODULE_NAME_INVALID),
]


@pytest.mark.parametrize("missing,status", NEGATIVE,
                         ids=["aiomysql", "not_in_catalog", "local", "stdlib", "already_declared", "invalid",
                              "oversized", "not_a_string"])
@pytest.mark.parametrize("gatekeeper", [False, True], ids=["draft_requirements", "gatekeeper_requirements"])
def test_any_other_fact_widens_nothing_and_is_recorded(missing, status, gatekeeper):
    tree, draft_paths = _gatekeeper_tree() if gatekeeper else (SETUP_TREE, sorted(SETUP_TREE))
    if status == QR.MODULE_ALREADY_DECLARED:
        assert "fastapi" in tree[REQS]
    plan = QR.plan_qa_repair(_feedback(tree, _setup_error(missing=missing), draft_paths=draft_paths),
                             stack_configured=True)
    today = QR.plan_qa_repair(_feedback(tree, _setup_error(missing=None), draft_paths=draft_paths),
                              stack_configured=True)
    assert (plan.reason, plan.repairable_paths) == (today.reason, today.repairable_paths)
    assert dict(plan.requirements_guard) == dict(today.requirements_guard)
    assert dict(plan.requirements_crash_guard) == dict(today.requirements_crash_guard)
    assert [s.model_dump() for s in plan.seeds] == [s.model_dump() for s in today.seeds]
    assert dict(plan.draft) == dict(today.draft) and plan.platform_paths == today.platform_paths
    (fact,) = plan.summary()["missing_modules"]
    assert fact["status"] == status and fact["requirements"] is None


def test_a_requirements_file_nobody_can_claim_stays_the_repositorys():
    """Neither a draft file nor byte for byte the gatekeeper's: SAT-49 holds, the fact allows nothing there."""
    tree, draft_paths = _gatekeeper_tree()
    tree = dict(tree, **{REQS: tree[REQS] + "pinned-thing==1.0\n"})
    plan = QR.plan_qa_repair(_feedback(tree, _setup_error(), draft_paths=draft_paths), stack_configured=True)
    assert REQS not in plan.repairable_paths and not plan.requirements_guard and REQS not in plan.draft
    (fact,) = plan.summary()["missing_modules"]
    assert (fact["status"], fact["requirements"]) == (QR.MODULE_IN_CATALOG, None)
    assert all(s.hint == QR.SETUP_ERROR_SEED_HINT for s in plan.seeds)


@pytest.mark.parametrize("finding_file", [None, "tests/test_root.py"], ids=["no_file", "root_path_two_services"])
def test_an_unscoped_setup_error_never_uses_the_fact(finding_file):
    from test_qa_repair_setup_error import TWO
    tree = dict(TWO, **{"conftest.py": "import pytest\n", "tests/test_root.py": "def test_r():\n    pass\n"})
    plan = QR.plan_qa_repair(_feedback(tree, _setup_error(file=finding_file)), stack_configured=True)
    today = QR.plan_qa_repair(_feedback(tree, _setup_error(missing=None, file=finding_file)), stack_configured=True)
    assert (plan.mode, plan.reason) == (today.mode, today.reason)
    assert plan.summary()["missing_modules"] == [] and not plan.requirements_guard
    assert dict(plan.requirements_crash_guard) == dict(today.requirements_crash_guard)


def test_the_fact_on_another_code_is_never_read():
    for d in (dict(_qa_diag(file=TEST_API, code="PY.TEST_FAILED"), missing_module="asyncpg"),
              dict(_setup_error(), stage2_judge=True)):
        plan = QR.plan_qa_repair(_feedback(SETUP_TREE, d), stack_configured=True)
        assert plan.summary()["missing_modules"] == [] and not plan.requirements_guard
        assert all("asyncpg" not in names for names in plan.requirements_crash_guard.values())


def test_the_setup_requirements_path_is_the_services():
    assert QR.setup_error_requirements_path({"file": "apps/api/tests/test_a.py"}, {}) == "apps/api/requirements.txt"
    assert QR.setup_error_requirements_path({"file": TEST_API}, SETUP_TREE) == REQS        # root tests, one service
    from test_qa_repair_setup_error import TWO
    assert QR.setup_error_requirements_path({"file": "tests/test_root.py"}, TWO) is None


# ------------------------------------------------------------------------------------------------ developer stage
def _setup_tree():
    tree = _first_build("off")
    return dict(tree, **{CONFTEST: SETUP_TREE[CONFTEST], TEST_API: SETUP_TREE[TEST_API]})


def test_end_to_end_the_driver_is_added_to_requirements_and_committed():
    tree = _setup_tree()
    fixed = tree[REQS] + f"{ASYNCPG}\n"
    files, agent, _client, seen = _develop("off", feedback=_feedback(tree, _setup_error()), repairs=[{REQS: fixed}])
    assert seen["swarm"] == 0 and not seen["lead_calls"]
    assert agent.last_validation_report.status == "PASS" and files[REQS] == fixed
    rec = agent.stack_run("t-qa")["qa_repair"]
    assert (rec["mode"], rec["reason"]) == (QR.QA_REPAIR, "PYTEST_SETUP_ERROR_ON_TEST_SETUP")
    assert rec["missing_modules"][0]["status"] == QR.MODULE_IN_CATALOG


def test_end_to_end_without_the_fact_the_driver_is_refused_and_the_loop_stays_bounded():
    """Today's behaviour (the live ex08-1110 shape): no fact, so the driver no import names is refused."""
    tree = _setup_tree()
    with pytest.raises(RepairBudgetExhausted):
        _develop("off", feedback=_feedback(tree, _setup_error(missing=None)), repairs=[{REQS: tree[REQS] + "asyncpg\n"}],
                 repair_max_iterations_precommit=1)


def test_end_to_end_a_module_outside_the_catalog_is_never_added():
    tree = _setup_tree()
    with pytest.raises(RepairBudgetExhausted):
        _develop("off", feedback=_feedback(tree, _setup_error(missing="aiomysql")),
                 repairs=[{REQS: tree[REQS] + "aiomysql\n"}], repair_max_iterations_precommit=1)


def test_end_to_end_the_live_aiosqlite_fact_adds_the_catalog_distribution():
    """AIOSQLITE-CATALOG: the ex08-1110 shape (setup error, missing `aiosqlite`) now repairs with the catalog's
    requirement string, and nothing else."""
    tree = _setup_tree()
    fixed = tree[REQS] + f"{AIOSQLITE}\n"
    files, agent, _client, _seen = _develop("off", feedback=_feedback(tree, _setup_error(missing="aiosqlite")),
                                            repairs=[{REQS: fixed}])
    assert agent.last_validation_report.status == "PASS" and files[REQS] == fixed
    rec = agent.stack_run("t-qa")["qa_repair"]
    assert rec["missing_modules"][0]["status"] == QR.MODULE_IN_CATALOG
    with pytest.raises(RepairBudgetExhausted):
        _develop("off", feedback=_feedback(tree, _setup_error(missing="aiosqlite")),
                 repairs=[{REQS: tree[REQS] + f"{AIOSQLITE}\nasyncpg\n"}], repair_max_iterations_precommit=1)


def test_the_new_hint_is_its_own_and_fits():
    assert QR.MISSING_MODULE_SETUP_SEED_HINT not in (QR.SETUP_ERROR_SEED_HINT, QR.MISSING_MODULE_SEED_HINT)
    assert len(QR.MISSING_MODULE_SETUP_SEED_HINT.encode()) < 4096          # shared.diagnostics.HINT_CAP
