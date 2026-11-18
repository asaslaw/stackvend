"""RT14-17 (full-scope red-team 11-14): QA counted skipped and xfail tests as passes ("N/N tests").

Now the QA job counts <skipped> testcases separately (`tests_skipped`, xfail included: pytest's junit reports it as
<skipped type="pytest.xfail">), a pass needs at least one test that RAN, a service whose every test skipped is a typed
CODE_DEFECT `PY.ALL_TESTS_SKIPPED` listing the skip reasons, and the gateway (the trust boundary) refuses an exit-0
report whose tests all skipped. Summaries and the release certificate never count a skipped test as passed. With no
skipped test every text and verdict is exactly as before (negative tests). Plan: docs/planning/rt14-developer-qa-context-plan.md.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import json

import pytest

import qa_sandbox_support as sup
import fd4f_support  # noqa: F401  (puts the gateway on sys.path)
from gate_errors import ErrorClass
from qa_job_client import ReportV1, classify, pass_count_text
from qa_source import deterministic_tar_gz
from release_gatekeeper import _pytest_counts

sj = sup.load_sandbox_job("sandbox_job_rt14_skips")

NONCE = "0123456789abcdef0123456789abcdef"
MAIN = "def health():\n    return {'status': 'healthy'}\n"
TEST = "from main import health\n\ndef test_health():\n    assert health() == {'status': 'healthy'}\n"
ALL_SKIP = ("import os\nimport pytest\n\n"
            "@pytest.mark.skipif(not os.getenv('FIRESTORE_EMULATOR_HOST'), reason='needs the emulator')\n"
            "def test_a():\n    assert False\n\n"
            "@pytest.mark.xfail(reason='known bug')\ndef test_b():\n    assert False\n")
SOME_SKIP = TEST + "\nimport pytest\n\n@pytest.mark.skip(reason='later')\ndef test_later():\n    assert False\n"


def _junit(tmp_path, text):
    p = tmp_path / "junit.xml"
    p.write_text(text)
    return str(p)


# ============================================================================================ unit: junit structure
def test_skipped_and_xfail_cases_are_listed_with_their_reason(tmp_path):
    text = ('<testsuite>'
            '<testcase classname="t" name="a" file="tests/t.py"><skipped type="pytest.skip" message="needs db"/>'
            '</testcase>'
            '<testcase classname="t" name="b" file="tests/t.py"><skipped type="pytest.xfail" message="known"/>'
            '</testcase>'
            '<testcase classname="t" name="c" file="tests/t.py"/>'
            '<testcase classname="t" name="d" file="tests/t.py"><failure message="x">x</failure></testcase>'
            '</testsuite>')
    path = _junit(tmp_path, text)
    assert sj.junit_skips(path) == ["t.a: needs db", "t.b: known"]
    total, failed, _cases, _internal = sj.parse_junit(path)
    assert (total, failed) == (4, 1)            # parse_junit's contract is unchanged


def test_n_no_skipped_case_lists_nothing(tmp_path):
    text = ('<testsuite><testcase classname="t" name="c" file="tests/t.py"/>'
            '<testcase classname="t" name="d" file="tests/t.py"><error message="x">x</error></testcase></testsuite>')
    assert sj.junit_skips(_junit(tmp_path, text)) == []


# ============================================================================================ gateway trust boundary
def _report(**kw):
    return ReportV1(schema_version=1, nonce=NONCE, passed=True, **kw)


def test_pass_count_text_never_counts_a_skip_as_passed():
    assert pass_count_text(_report(tests_total=5, tests_failed=0, tests_skipped=2)) == "3/3 tests (2 skipped)"
    # negative: no skipped test -> exactly the earlier text
    assert pass_count_text(_report(tests_total=5, tests_failed=0)) == "5/5 tests"


def test_report_from_an_older_job_reads_zero_skipped():
    assert _report(tests_total=1).tests_skipped == 0


def _static_ok():
    return json.dumps({"schema_version": 1, "nonce": NONCE, "passed": True, "index_reachable": True}).encode()


def _classify_exit0(report):
    execution = {"completionTime": "t", "succeededCount": 1}
    tasks = [{"lastAttemptResult": {"exitCode": 0}}]
    return classify(execution, tasks, _static_ok(), json.dumps(report).encode(), NONCE)


def test_gateway_refuses_an_exit0_report_whose_tests_all_skipped():
    out = _classify_exit0({"schema_version": 1, "nonce": NONCE, "passed": True, "tests_total": 3,
                           "tests_failed": 0, "tests_skipped": 3})
    assert out.passed is False and out.error_class == ErrorClass.GATE_UNAVAILABLE and out.reason == "VERDICT_MISMATCH"


def test_n_gateway_passes_a_report_with_a_test_that_ran():
    out = _classify_exit0({"schema_version": 1, "nonce": NONCE, "passed": True, "tests_total": 3,
                           "tests_failed": 0, "tests_skipped": 1})
    assert out.passed is True and out.summary == "QA passed: 2/2 tests (1 skipped), static checks clean"
    old = _classify_exit0({"schema_version": 1, "nonce": NONCE, "passed": True, "tests_total": 3, "tests_failed": 0})
    assert old.passed is True and old.summary == "QA passed: 3/3 tests, static checks clean"


def test_certificate_counts_from_the_evidence_report():
    assert _pytest_counts({"report": {"tests_total": 5, "tests_failed": 0, "tests_skipped": 2}}) == (3, 3,
                                                                                                    " (2 skipped)")
    assert _pytest_counts({"report": {"tests_total": 5, "tests_failed": 1}}) == (4, 5, "")
    assert _pytest_counts({"tests_passed": 5, "tests_total": 5}) == (5, 5, "")    # top-level (as before)
    assert _pytest_counts({}) == (0, 0, "")


# ============================================================================================ end to end (real job)
@pytest.fixture(scope="module")
def wheelhouse(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("wheelhouse-rt14-skips"))
    return d, sup.build_wheelhouse(d)


@pytest.fixture()
def cloud(wheelhouse):
    c = sup.FakeCloud(*wheelhouse)
    yield c
    c.close()


@pytest.fixture()
def toolchain(cloud, tmp_path):
    return sup.make_toolchain(sj, cloud, str(tmp_path))


def _run(cloud, toolchain, test_src):
    files = {"apps/svc/main.py": MAIN, "apps/svc/requirements.txt": "", "apps/svc/Procfile": "web: python main.py\n",
             "apps/svc/.python-version": "3.13\n", "tests/test_main.py": test_src}
    archive = deterministic_tar_gz({k: v.encode() for k, v in files.items()})
    cloud.source = archive
    env = {
        "QA_SOURCE_URL": cloud.url("source.tar.gz"), "QA_SOURCE_SHA256": hashlib.sha256(archive).hexdigest(),
        "QA_STATIC_PUT_URL": cloud.url("static.json"), "QA_REPORT_PUT_URL": cloud.url("report.json"),
        "QA_NONCE": NONCE, "QA_TRACE_ID": "trace-rt14", "QA_COMMIT_SHA": "c" * 40, "QA_PRODUCT_ID": "demo-app",
        "QA_DEADLINE_SECONDS": "300",
    }
    code = sj.run_job(env, toolchain=toolchain, transport=sj.HttpTransport(sleep=lambda s: None))
    r = cloud.objects.get("report.json")
    return code, (json.loads(r) if r else None)


def _verdict(cloud, code):
    if code == 0:
        execution, tasks = {"completionTime": "t", "succeededCount": 1}, [{"lastAttemptResult": {"exitCode": 0}}]
    else:
        execution, tasks = {"completionTime": "t", "failedCount": 1}, [{"lastAttemptResult": {"exitCode": code}}]
    return classify(execution, tasks, cloud.objects.get("static.json"), cloud.objects.get("report.json"), NONCE)


def test_all_skipped_suite_is_a_typed_code_defect(cloud, toolchain):
    code, report = _run(cloud, toolchain, ALL_SKIP)
    assert code == 10, report
    assert (report["tests_total"], report["tests_failed"], report["tests_skipped"]) == (2, 0, 2)
    assert report["passed"] is False
    [d] = [d for d in report["diagnostics"] if d["severity"] == "error"]
    assert (d["code"], d["file"]) == ("PY.ALL_TESTS_SKIPPED", "tests")
    assert "needs the emulator" in d["detail"] and "known bug" in d["detail"]
    verdict = _verdict(cloud, code)
    assert verdict.error_class == ErrorClass.CODE_DEFECT and verdict.diagnostics[0]["code"] == "PY.ALL_TESTS_SKIPPED"


def test_n_suite_with_a_test_that_ran_still_passes(cloud, toolchain):
    code, report = _run(cloud, toolchain, SOME_SKIP)
    assert code == 0, report
    assert (report["tests_total"], report["tests_failed"], report["tests_skipped"]) == (2, 0, 1)
    verdict = _verdict(cloud, code)
    assert verdict.passed is True and verdict.summary == "QA passed: 1/1 tests (1 skipped), static checks clean"


def test_n_suite_without_skips_is_unchanged(cloud, toolchain):
    code, report = _run(cloud, toolchain, TEST)
    assert code == 0, report
    assert (report["tests_total"], report["tests_failed"], report["tests_skipped"]) == (1, 0, 0)
    assert _verdict(cloud, code).summary == "QA passed: 1/1 tests, static checks clean"
