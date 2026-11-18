"""QA-REPAIR-SETUP-ERROR (register row, awaiting owner): a test that errors outside its own call (a fixture's setup or
teardown, or the test module's collection) is a QA repair of the service's test setup plus the test file.

Seen live 2026-11-09 (example 07): a generated `tests/conftest.py` fixture raised in setup, so every test errored.
The runner reported each as `PY.TEST_FAILED` on the test file, so the repair could edit only the test files; a fixed
conftest.py was rejected as an out-of-scope write and the loop ran out of iterations.

Covered: the runner types the junit `<error>` element as `PY.TEST_SETUP_ERROR` (by the XML tag only; `<failure>` stays
`PY.TEST_FAILED`), on hand-written junit and on a real pytest run of a raising conftest fixture through the job and the
gateway; the code parity; the plan (one group per service over the test setup plus the test files, the crash guard on
requirements.txt, today's single seed without a test-setup file, judge findings riding along); group liveness; and the
developer stage end to end (a fixed conftest.py is accepted and committed, no out-of-scope rejection).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
from unittest.mock import MagicMock, patch

import pytest

import qa_sandbox_support as sup
from test_qa_feedback import (MAIN, TREE, W, _block_parts, _develop, _feedback, _first_build, _qa_diag,  # noqa: E402
                              _section)
from test_qa_sandbox_job import artifacts, cloud, gateway_verdict, run, single_service, toolchain, wheelhouse  # noqa: F401,E402
from test_qa_stage2_on_test_fail import SEC_NOFILE  # noqa: E402
from developer_agent import qa_repair as QR  # noqa: E402
from developer_agent import qa_requirements_guard as G  # noqa: E402
from shared.diagnostics import RepairBudgetExhausted  # noqa: E402

sj = sup.load_sandbox_job("sandbox_job_qa_repair_setup_error")
REQS = "apps/shop/requirements.txt"
CONFTEST = "tests/conftest.py"
TESTS_INIT = "tests/__init__.py"
TEST_API = "tests/test_api.py"
TEST_OTHER = "tests/test_other.py"
SETUP_TEXT = "AttributeError: 'NoneType' object has no attribute 'get'"
SETUP_DETAIL = "tests/conftest.py:36: in client\n    return app.state.get('x')\nE   " + SETUP_TEXT
SETUP_TREE = dict(TREE, **{CONFTEST: "import pytest\n\n\n@pytest.fixture\ndef client():\n    return None.get\n",
                           TESTS_INIT: "", TEST_API: "def test_a(client):\n    assert client\n",
                           TEST_OTHER: "def test_b(client):\n    assert client\n"})


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


def _setup_error(file=TEST_API, **kw):
    base = dict(file=file, code="PY.TEST_SETUP_ERROR", message=f'tests.test_api.test_a: failed on setup with "{SETUP_TEXT}"',
                detail=SETUP_DETAIL)
    base.update(kw)
    d = _qa_diag(**base)
    d["tool"] = "pytest"
    return d


# ------------------------------------------------------------------------------------------------ runner: the junit tag
def _junit(tmp_path, cases):
    p = tmp_path / "junit.xml"
    p.write_text('<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">' + cases
                 + "</testsuite></testsuites>")
    return str(p)


ERROR_CASE = ('<testcase classname="tests.test_api" name="test_a" file="tests/test_api.py" line="0">'
              '<error message="failed on setup with &quot;AttributeError&quot;">trace</error></testcase>')
FAILURE_CASE = ('<testcase classname="tests.test_api" name="test_b" file="tests/test_api.py" line="3">'
                '<failure message="assert False">trace</failure></testcase>')
# RT F3: pytest 9 (xunit1) writes a failing test whose fixture then errors in teardown as TWO testcases with the same
# name: the failure, then the teardown error (reproduced below with the real pytest).
FAILURE_THEN_TEARDOWN = ('<testcase classname="tests.test_api" name="test_c" file="tests/test_api.py" line="5">'
                         '<failure message="assert False">t</failure></testcase>'
                         '<testcase classname="tests.test_api" name="test_c" file="tests/test_api.py" line="5">'
                         '<error message="failed on teardown with &quot;RuntimeError&quot;">t</error></testcase>')
PASSED_CASE = '<testcase classname="tests.test_api" name="test_d" file="tests/test_api.py" line="7"/>'


def test_an_error_element_is_a_setup_error_and_a_failure_stays_a_test_failure(tmp_path):
    total, failed, diags, internal = sj.parse_junit(_junit(tmp_path, ERROR_CASE + FAILURE_CASE + FAILURE_THEN_TEARDOWN
                                                           + PASSED_CASE))
    assert (total, failed, internal) == (5, 4, [])     # the teardown case counts again (pre-existing double count)
    assert [(d["code"], d["file"], d["line"]) for d in diags] == [
        ("PY.TEST_SETUP_ERROR", TEST_API, 1), ("PY.TEST_FAILED", TEST_API, 4), ("PY.TEST_FAILED", TEST_API, 6),
        ("PY.TEST_SETUP_ERROR", TEST_API, 6)]
    assert diags[0]["detail"] == "trace" and diags[0]["message"].startswith("tests.test_api.test_a: failed on setup")


TEARDOWN_CONFTEST = ("import pytest\n\n\n@pytest.fixture\ndef res():\n    yield 1\n"
                     "    raise RuntimeError('teardown broke')\n")


def test_rt_f3_real_pytest_writes_a_failure_plus_teardown_error_as_two_cases(tmp_path):
    """The shape above, from the real pytest: one failing test whose fixture errors in teardown."""
    import subprocess
    import sys
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "conftest.py").write_text(TEARDOWN_CONFTEST)
    (tmp_path / "tests" / "test_api.py").write_text("def test_c(res):\n    assert res == 2\n")
    (tmp_path / "ini.ini").write_text("[pytest]\njunit_family = xunit1\n")
    junit = tmp_path / "junit.xml"
    env = dict(hermetic_guard.child_env(), PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    subprocess.run([sys.executable, "-m", "pytest", "-c", str(tmp_path / "ini.ini"), "--rootdir", str(tmp_path),
                    "-p", "no:cacheprovider", "--junitxml", str(junit), "-q", "tests"], cwd=str(tmp_path), env=env,
                   capture_output=True, timeout=120)
    _total, _failed, diags, _internal = sj.parse_junit(str(junit))
    assert [(d["code"], d["file"]) for d in diags] == [("PY.TEST_FAILED", TEST_API), ("PY.TEST_SETUP_ERROR", TEST_API)]


def test_rt_f3_a_failure_plus_teardown_error_routes_the_setup_group_and_the_test_file():
    """Decided behaviour: both findings are kept; the teardown error routes the service's setup group (which holds the
    test file), the failure its plain seed on the test file."""
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _qa_diag(file=TEST_API), _setup_error()), stack_configured=True)
    assert plan.reason == "PYTEST_SETUP_ERROR_ON_TEST_SETUP"
    assert sorted((s.code, s.file, s.symbol) for s in plan.seeds) == sorted(
        [("PY.TEST_FAILED", TEST_API, None)] + [("PY.TEST_SETUP_ERROR", f, "qa_setup_error_2")
                                                for f in (REQS, CONFTEST, TESTS_INIT, TEST_API)])


def test_n_a_failure_only_report_is_exactly_as_before(tmp_path):
    """Do No Harm: the diagnostics of a junit without <error> are what the code before this row produced."""
    _t, _f, diags, _i = sj.parse_junit(_junit(tmp_path, FAILURE_CASE + PASSED_CASE))
    assert diags == [sj.diag("pytest", "PY.TEST_FAILED", "tests.test_api.test_b: assert False", file=TEST_API, line=4,
                             detail="trace")]


def test_the_tag_decides_never_the_message(tmp_path):
    case = ('<testcase classname="t" name="x" file="tests/test_api.py" line="0">'
            '<failure message="failed on setup with &quot;E&quot;">t</failure></testcase>')
    assert [d["code"] for d in sj.parse_junit(_junit(tmp_path, case))[2]] == ["PY.TEST_FAILED"]
    case = ('<testcase classname="t" name="x" file="tests/test_api.py" line="0">'
            '<error message="assert False">t</error></testcase>')
    assert [d["code"] for d in sj.parse_junit(_junit(tmp_path, case))[2]] == ["PY.TEST_SETUP_ERROR"]


def test_the_codes_are_the_gateways():
    assert QR.SETUP_ERROR_CODES == sj.PYTEST_SETUP_ERROR_CODES == {sj.PYTEST_SETUP_ERROR_CODE}
    assert not (QR.SETUP_ERROR_CODES & QR.CRASH_CODES) and "PY.TEST_FAILED" not in QR.SETUP_ERROR_CODES


RAISING_CONFTEST = "import pytest\n\n\n@pytest.fixture\ndef client():\n    raise AttributeError('no client')\n"
CLIENT_TEST = "def test_health(client):\n    assert client\n"
FAILING_TEST = "def test_health():\n    assert 1 == 2\n"


def test_a_real_raising_conftest_fixture_is_a_setup_error_end_to_end(cloud, toolchain):
    code, _ = run(cloud, toolchain, single_service(**{"tests/conftest.py": RAISING_CONFTEST,
                                                      "tests/test_main.py": CLIENT_TEST}))
    _static, report = artifacts(cloud)
    assert code == 10, report
    (d,) = [d for d in report["diagnostics"] if d["severity"] == "error"]
    assert (d["code"], d["file"]) == ("PY.TEST_SETUP_ERROR", "tests/test_main.py")
    outcome = gateway_verdict(cloud, code)
    assert [x["code"] for x in outcome.diagnostics if x["severity"] == "error"] == ["PY.TEST_SETUP_ERROR"]


def test_n_a_real_assertion_failure_stays_a_test_failure_end_to_end(cloud, toolchain):
    code, _ = run(cloud, toolchain, single_service(**{"tests/test_main.py": FAILING_TEST}))
    _static, report = artifacts(cloud)
    assert code == 10, report
    assert [(d["code"], d["file"]) for d in report["diagnostics"] if d["severity"] == "error"] == [
        ("PY.TEST_FAILED", "tests/test_main.py")]


# ------------------------------------------------------------------------------------------------ the plan
def test_a_setup_error_is_a_repair_of_the_test_setup_and_the_test_file():
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _setup_error()), stack_configured=True)
    assert (plan.mode, plan.reason, plan.findings) == (QR.QA_REPAIR, "PYTEST_SETUP_ERROR_ON_TEST_SETUP", 1)
    assert plan.repairable_paths == {REQS, CONFTEST, TESTS_INIT, TEST_API}
    assert plan.seed_files == {p: SETUP_TREE[p] for p in (REQS, CONFTEST, TESTS_INIT, TEST_API)}
    for s in plan.seeds:
        assert (s.code, s.symbol, s.hint) == ("PY.TEST_SETUP_ERROR", "qa_setup_error_1", QR.SETUP_ERROR_SEED_HINT)
        assert SETUP_TEXT not in s.model_dump_json()                 # pytest's text lives only in the QA block
    assert SETUP_TEXT in _block_parts(plan.untrusted_output)[1]
    assert dict(plan.requirements_crash_guard).keys() == {REQS} and not plan.requirements_guard
    assert G.QA_TEST_TOOL_NAMES <= plan.requirements_crash_guard[REQS]


def test_the_setup_errors_of_one_service_are_one_group():
    """Example 07 had 16 errored tests: one group over the setup plus every errored test file, not 16 groups."""
    errors = [_setup_error(), _setup_error(file=TEST_OTHER)] + [_setup_error() for _ in range(5)]
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, *errors), stack_configured=True)
    assert plan.reason == "PYTEST_SETUP_ERROR_ON_TEST_SETUP" and plan.findings == 7
    assert {s.symbol for s in plan.seeds} == {"qa_setup_error_1"}
    assert sorted(s.file for s in plan.seeds) == sorted({REQS, CONFTEST, TESTS_INIT, TEST_API, TEST_OTHER})


API_REQS, API_CONF, API_TEST = "apps/api/requirements.txt", "apps/api/tests/conftest.py", "apps/api/tests/test_a.py"
SHOP_CONF, SHOP_TEST = "apps/shop/tests/conftest.py", "apps/shop/tests/test_s.py"
TWO = dict(TREE, **{API_REQS: "fastapi\n", "apps/api/main.py": "x = 1\n", API_CONF: "", API_TEST: "def test_a():\n    pass\n",
                    SHOP_CONF: "", SHOP_TEST: "def test_s():\n    pass\n"})


def test_two_services_are_two_groups_each_over_its_own_setup():
    plan = QR.plan_qa_repair(_feedback(TWO, _setup_error(file=API_TEST), _setup_error(file=SHOP_TEST)),
                             stack_configured=True)
    groups = {}
    for s in plan.seeds:
        groups.setdefault(s.symbol, set()).add(s.file)
    assert groups == {"qa_setup_error_1": {API_REQS, API_CONF, API_TEST},
                      "qa_setup_error_2": {REQS, SHOP_CONF, SHOP_TEST}}
    draft = dict(plan.draft)
    fixed = dict(draft, **{API_CONF: "import pytest\n"})
    assert {s.symbol for s in QR.live_seeds(plan.seeds, plan.seed_files, fixed)} == {"qa_setup_error_2"}


def test_changing_the_conftest_alone_ends_the_group_and_nothing_changed_keeps_it():
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _setup_error(), _setup_error(file=TEST_OTHER)), stack_configured=True)
    draft = dict(plan.draft)
    assert QR.live_seeds(plan.seeds, plan.seed_files, draft) == list(plan.seeds)
    assert QR.live_seeds(plan.seeds, plan.seed_files, dict(draft, **{CONFTEST: "import pytest\n"})) == []


@pytest.mark.parametrize("finding_file", [None, "tests/test_root.py"], ids=["no_file", "root_path"])
def test_rt_f2_an_unscoped_setup_error_beside_two_services_reaches_no_service_setup(finding_file):
    """RT F2: without a service in `file` (none, or a root tests/ path QA would not run beside two services) the
    finding never seeds several services' test setup: today's rule (no seed for a file that is not a draft file)."""
    tree = dict(TWO, **{"conftest.py": "import pytest\n", "tests/test_root.py": "def test_r():\n    pass\n"})
    d = _setup_error(file=finding_file)
    assert QR.setup_error_targets(d, tree, tree) == []
    plan = QR.plan_qa_repair(_feedback(tree, d), stack_configured=True)
    today = QR.plan_qa_repair(_feedback(tree, dict(d, code="PY.TEST_FAILED")), stack_configured=True)
    assert (plan.mode, plan.reason) == (today.mode, today.reason)
    assert [(s.file, s.symbol) for s in plan.seeds] == [(s.file, s.symbol) for s in today.seeds]
    assert not plan.requirements_crash_guard


def test_rt_f2_a_root_test_path_of_a_single_service_still_reaches_its_setup():
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _setup_error(file=TEST_API)), stack_configured=True)
    assert plan.reason == "PYTEST_SETUP_ERROR_ON_TEST_SETUP" and REQS in plan.repairable_paths


def test_without_a_test_setup_draft_file_it_is_todays_single_seed_on_the_test_file():
    tree = {MAIN: TREE[MAIN], TEST_API: SETUP_TREE[TEST_API], W + "main.tf": "# platform\n"}
    plan = QR.plan_qa_repair(_feedback(tree, _setup_error()), stack_configured=True)
    assert (plan.mode, plan.reason) == (QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES")
    (seed,) = plan.seeds
    assert (seed.file, seed.hint, seed.symbol) == (TEST_API, QR.SEED_HINT, None)
    assert QR.setup_error_targets(_setup_error(), tree) == []


def test_a_setup_error_on_a_file_that_is_not_a_draft_file_still_reaches_the_setup():
    paths = [p for p in SETUP_TREE if p != TEST_API]
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _setup_error(), draft_paths=paths), stack_configured=True)
    assert plan.reason == "PYTEST_SETUP_ERROR_ON_TEST_SETUP" and plan.repairable_paths == {REQS, CONFTEST, TESTS_INIT}


def test_a_judge_finding_rides_along_as_text_and_a_judge_stamped_code_is_not_a_setup_error():
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _setup_error(), SEC_NOFILE), stack_configured=True)
    assert plan.mode == QR.QA_REPAIR and {s.code for s in plan.seeds} == {"PY.TEST_SETUP_ERROR"}
    judge = dict(SEC_NOFILE, code="PY.TEST_SETUP_ERROR", file=TEST_API)
    assert not QR.is_setup_error(judge) and QR.is_setup_error(_setup_error())


def test_a_setup_error_with_an_unrepairable_sandbox_finding_is_todays_regeneration():
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _setup_error(), _qa_diag(file=W + "main.tf")), stack_configured=True)
    # PLATFORM-RENDERED-FINDING (owner 11-13): main.tf is platform-rendered: a typed stop (was REGENERATE)
    assert (plan.mode, plan.reason) == (QR.STOP, QR.PLATFORM_RENDERED_REASON)


@pytest.mark.parametrize("diags", [
    [_qa_diag(file=TEST_API)], [_qa_diag(file=TEST_API), _qa_diag(file=TEST_OTHER)], [_qa_diag()],
], ids=["one", "two_files", "main"])
def test_n_a_test_failure_routes_exactly_as_today(diags):
    """Do No Harm: PY.TEST_FAILED (a <failure>) keeps one plain seed per named file, even with a conftest.py."""
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, *diags), stack_configured=True)
    assert (plan.mode, plan.reason) == (QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES")
    assert [(s.code, s.file, s.hint, s.symbol) for s in plan.seeds] == [
        ("PY.TEST_FAILED", d["file"], QR.SEED_HINT, None) for d in diags]
    assert not plan.requirements_crash_guard and not plan.requirements_guard


# ------------------------------------------------------------------------------------------------ developer stage
FIXED_CONFTEST = "import pytest\n\n\n@pytest.fixture\ndef client():\n    return object()\n"


def _setup_tree():
    tree = _first_build("off")
    return dict(tree, **{CONFTEST: SETUP_TREE[CONFTEST], TEST_API: SETUP_TREE[TEST_API]})


def test_a_fixed_conftest_is_accepted_and_committed():
    tree = _setup_tree()
    files, agent, _client, seen = _develop("off", feedback=_feedback(tree, _setup_error()),
                                           repairs=[{CONFTEST: FIXED_CONFTEST}])
    assert seen["swarm"] == 0 and not seen["lead_calls"]
    (task,) = seen["repair_tasks"]
    offered = json.loads(_section(task["prompt"], "FILES TO FIX:", QR.QA_OUTPUT_HEADER))
    assert set(offered) == {CONFTEST, TEST_API, REQS}
    assert agent.last_validation_report.status == "PASS" and files[CONFTEST] == FIXED_CONFTEST
    assert files[TEST_API] == tree[TEST_API]
    rec = agent.stack_run("t-qa")["qa_repair"]
    assert (rec["mode"], rec["reason"]) == (QR.QA_REPAIR, "PYTEST_SETUP_ERROR_ON_TEST_SETUP")
    events = agent.stack_run("t-qa")["repair_events"]
    assert all((e if isinstance(e, dict) else e.model_dump()).get("reject_reason") != "OUT_OF_SCOPE_WRITE"
               for e in events)


def test_a_requirements_change_in_the_group_is_under_the_crash_guard():
    tree = _setup_tree()
    bad = tree[REQS] + "evil-package==1.0\n"
    good = tree[REQS] + "pytest-asyncio==1.4.0\n"
    files, agent, _client, seen = _develop("off", feedback=_feedback(tree, _setup_error()),
                                           repairs=[{REQS: bad}, {REQS: good}])
    assert files[REQS] == good and G.REQUIREMENTS_REFUSED in seen["repair_tasks"][1]["prompt"]


def test_an_unchanged_setup_never_passes_and_the_loop_stays_bounded():
    tree = _setup_tree()
    with pytest.raises(RepairBudgetExhausted):
        _develop("off", feedback=_feedback(tree, _setup_error()), repairs=[{CONFTEST: tree[CONFTEST]}],
                 repair_max_iterations_precommit=1)


def test_a_write_outside_the_group_is_still_rejected():
    tree = _setup_tree()
    with pytest.raises(RepairBudgetExhausted):
        _develop("off", feedback=_feedback(tree, _setup_error()), repairs=[{MAIN: tree[MAIN] + "\n# x\n"}],
                 repair_max_iterations_precommit=1)
