"""Row QA-PYTEST-CRASH (owner 10-29), QA runner only.

(a) When pytest itself crashes (exit 3 / the junit's synthetic `pytest.internal` testcase; exit 2 / 4 with a junit that
lists no failing test), the diagnostic carries pytest's own crash output: the message leads with pytest's first output
block (QA-START-MSG's helpers, redacted, bounded) and the detail is the END of pytest's crash report (where the
exception is). Typed by exit code and junit structure, never by text. The synthetic case is not a test: it is neither
counted nor reported as PY.TEST_FAILED.

(b) The toolchain pins the allow-listed pytest plugin that caps pytest below 9 in older releases (pytest-asyncio, at the
release the platform's own CI runs with pytest 9.1.1); a workload requirement for it is replaced by the pin (installed
in step 2b, with the QA-TOOLCHAIN-PINS note), never left out.

Seen live 10-29 (second install, run newplan1-a2): `tests=1 failed=1`, `PY.TEST_FAILED pytest.internal: internal error`, and
the detail held only the first frames of pytest's traceback, so the crash itself was recorded nowhere. End-to-end cases
run the real job and real pytest against the loopback index of tests/qa_sandbox_support.py (nothing is downloaded).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import json
import os

import pytest

import qa_sandbox_support as sup
import fd4f_support  # noqa: F401  (puts the gateway on sys.path)
from gate_errors import ErrorClass
from qa_job_client import classify
from qa_source import deterministic_tar_gz

sj = sup.load_sandbox_job("sandbox_job_pytest_crash")

NONCE = "0123456789abcdef0123456789abcdef"
MAIN = "def health():\n    return {'status': 'healthy'}\n"
TEST = "from main import health\n\ndef test_health():\n    assert health() == {'status': 'healthy'}\n"
CRASH = "the plugin wants pytest<9"
# A conftest hook that is allowed by the H4 lint (not an outcome hook) and raises after pytest's junit plugin is set
# up: pytest reports INTERNALERROR, exits 3 and writes the synthetic internal-error testcase (the 10-29 shape).
CRASHING_CONFTEST = f"def pytest_collection_finish(session):\n    raise RuntimeError({CRASH!r})\n"

INTERNAL_JUNIT = (
    '<?xml version="1.0" encoding="utf-8"?><testsuites name="pytest tests"><testsuite name="pytest" errors="1" '
    'failures="0" skipped="0" tests="1"><testcase classname="pytest" name="internal" time="0.000">'
    '<error message="internal error">Traceback (most recent call last):\n  File "_pytest/main.py", line 330\n'
    '{frames}RuntimeError: {crash}</error></testcase></testsuite></testsuites>')


def _junit(tmp_path, text):
    p = tmp_path / "junit.xml"
    p.write_text(text)
    return str(p)


# ============================================================================================ unit: junit structure
def test_synthetic_internal_error_case_is_not_a_test(tmp_path):
    path = _junit(tmp_path, INTERNAL_JUNIT.format(frames="", crash="boom"))
    total, failed, cases, internal = sj.parse_junit(path)
    assert (total, failed, cases) == (0, 0, [])
    assert len(internal) == 1 and internal[0].endswith("RuntimeError: boom")


def test_n_a_real_test_named_internal_is_an_ordinary_test(tmp_path):
    """Do No Harm: the marker is the structure pytest writes (no `file`); a real xunit1 testcase always has `file`."""
    text = ('<testsuite><testcase classname="pytest" name="internal" file="tests/test_x.py" line="3">'
            '<failure message="assert 0">E assert 0</failure></testcase>'
            '<testcase classname="t" name="ok" file="tests/test_x.py" line="9"/></testsuite>')
    total, failed, cases, internal = sj.parse_junit(_junit(tmp_path, text))
    assert (total, failed, internal) == (2, 1, [])
    assert [(d["code"], d["file"], d["line"]) for d in cases] == [("PY.TEST_FAILED", "tests/test_x.py", 4)]


@pytest.mark.parametrize("attrs", ['classname="pytest" name="internal"><failure message="x">x</failure>',
                                   'classname="pytest" name="other"><error message="x">x</error>',
                                   'classname="tests" name="internal"><error message="x">x</error>'])
def test_n_near_misses_of_the_marker_are_ordinary_cases(tmp_path, attrs):
    total, failed, cases, internal = sj.parse_junit(_junit(tmp_path, f"<testsuite><testcase {attrs}</testcase>"
                                                                     "</testsuite>"))
    # QA-REPAIR-SETUP-ERROR: an ordinary case whose bad child is <error> is a setup error, <failure> a test failure
    expected = "PY.TEST_SETUP_ERROR" if "<error" in attrs else "PY.TEST_FAILED"
    assert (total, failed, internal) == (1, 1, []) and [d["code"] for d in cases] == [expected]


def test_crash_diag_message_leads_with_the_first_block_and_detail_keeps_the_end(tmp_path):
    secret = "https://storage.example.invalid/runs/x?X-Goog-Signature=abc"
    redact = sj.Redactor()
    redact.add(secret)
    log = tmp_path / "pytest.log"
    log.write_text("INTERNALERROR> Traceback (most recent call last):\n"
                   + "".join(f"INTERNALERROR>   frame {i} {secret}\n" for i in range(200))
                   + f"INTERNALERROR> RuntimeError: {CRASH}\n\nno tests ran in 0.01s\n")
    frames = "".join(f'  File "x{i}.py", line {i}, in f {secret}\n' for i in range(300))
    report = INTERNAL_JUNIT.format(frames=frames, crash=CRASH)
    d = sj.pytest_crash_diag(sj.PYTEST_INTERNAL_ERROR_CODE, "apps/api", 3, str(log), redact, report, "out")
    assert (d["tool"], d["code"], d["file"], d["severity"]) == ("pytest", "PYTEST.INTERNAL_ERROR",
                                                                "apps/api/requirements.txt", "error")   # the scope
    assert d["message"].startswith("INTERNALERROR> Traceback (most recent call last):")
    assert f"INTERNALERROR> RuntimeError: {CRASH}" in d["message"]          # the last line of the block is kept
    assert "no tests ran" not in d["message"]                               # the first block only
    assert d["message"].endswith("(pytest crashed with an internal error for apps/api: exit 3; pytest's crash "
                                 "report in detail)")
    assert d["detail"].endswith(f"RuntimeError: {CRASH}</error></testcase></testsuite></testsuites>")
    assert len(d["message"]) <= sj.MAX_FIELD_CHARS and len(d["detail"]) <= sj.MAX_FIELD_CHARS
    assert "X-Goog-Signature" not in d["message"] + d["detail"] and "[REDACTED]" in d["detail"]


def test_crash_diag_without_a_crash_report_uses_the_output_tail(tmp_path):
    d = sj.pytest_crash_diag(sj.PYTEST_SESSION_ERROR_CODE, "apps/api", 2, str(tmp_path / "missing.log"),
                             sj.Redactor(), None, "x" * 5000 + "END")
    assert d["message"] == "pytest stopped with a session error for apps/api: exit 2; pytest's crash report in detail"
    assert d["detail"].endswith("END") and len(d["detail"]) == sj.MAX_FIELD_CHARS


# ============================================================================================ end to end (real job)
@pytest.fixture(scope="module")
def wheelhouse(tmp_path_factory):
    """The standard offline wheelhouse plus stub pytest-asyncio releases (no pytest11 entry point: never loaded)."""
    d = str(tmp_path_factory.mktemp("wheelhouse-crash"))
    index = sup.build_wheelhouse(d)
    index["pytest-asyncio"] = [sup.build_wheel(d, "pytest-asyncio", v, {"pytest_asyncio_stub.py": f"V = {v!r}\n"})
                               for v in ("0.23.8", "1.4.0")]
    return d, index


@pytest.fixture()
def cloud(wheelhouse):
    c = sup.FakeCloud(*wheelhouse)
    yield c
    c.close()


@pytest.fixture()
def toolchain(cloud, tmp_path):
    return sup.make_toolchain(sj, cloud, str(tmp_path))


@pytest.fixture()
def pip_calls(monkeypatch):
    calls = []
    real = sj.Runner.run

    def recording(self, argv, *a, **k):
        if k.get("what") == "pip install":
            calls.append(list(argv[argv.index("-c") + 2:]))
        return real(self, argv, *a, **k)

    monkeypatch.setattr(sj.Runner, "run", recording)
    return calls


def _run(cloud, toolchain, requirements="", **extra):
    files = {"apps/svc/main.py": MAIN, "apps/svc/requirements.txt": requirements,
             "apps/svc/Procfile": "web: python main.py\n", "apps/svc/.python-version": "3.13\n",
             "tests/test_main.py": TEST}
    files.update(extra)
    archive = deterministic_tar_gz({k: v.encode() for k, v in files.items()})
    cloud.source = archive
    env = {
        "QA_SOURCE_URL": cloud.url("source.tar.gz"), "QA_SOURCE_SHA256": hashlib.sha256(archive).hexdigest(),
        "QA_STATIC_PUT_URL": cloud.url("static.json"), "QA_REPORT_PUT_URL": cloud.url("report.json"),
        "QA_NONCE": NONCE, "QA_TRACE_ID": "trace-crash", "QA_COMMIT_SHA": "c" * 40, "QA_PRODUCT_ID": "demo-app",
        "QA_DEADLINE_SECONDS": "300",
    }
    code = sj.run_job(env, toolchain=toolchain, transport=sj.HttpTransport(sleep=lambda s: None))
    r = cloud.objects.get("report.json")
    return code, (json.loads(r) if r else None)


def _verdict(cloud, code):
    execution, tasks = {"completionTime": "t", "failedCount": 1}, [{"lastAttemptResult": {"exitCode": code}}]
    return classify(execution, tasks, cloud.objects.get("static.json"), cloud.objects.get("report.json"), NONCE)


def test_live_shape_internal_error_carries_pytest_crash_output(cloud, toolchain):
    """10-29 newplan1-a2 shape: pytest exits 3 and writes the synthetic case. The report no longer says
    `tests=1 failed=1 pytest.internal: internal error` without the crash: it names the exception."""
    code, report = _run(cloud, toolchain, **{"tests/conftest.py": CRASHING_CONFTEST})
    assert code == 10, report
    assert (report["tests_total"], report["tests_failed"]) == (0, 0)
    [d] = [d for d in report["diagnostics"] if d["severity"] == "error"]
    assert (d["code"], d["file"]) == ("PYTEST.INTERNAL_ERROR", "apps/svc/requirements.txt")
    assert d["message"].startswith("INTERNALERROR> Traceback (most recent call last):")
    assert f"RuntimeError: {CRASH}" in d["message"]
    assert "(pytest crashed with an internal error for apps/svc: exit 3; pytest's crash report in detail)" in \
        d["message"]
    assert d["detail"].rstrip().endswith(f"RuntimeError: {CRASH}")         # the junit's crash report, its end
    assert not [x for x in report["diagnostics"] if x["code"] == "PY.TEST_FAILED"]
    verdict = _verdict(cloud, code)
    assert verdict.error_class == ErrorClass.CODE_DEFECT and verdict.diagnostics[0]["code"] == "PYTEST.INTERNAL_ERROR"


def test_session_error_with_a_readable_junit_leads_with_pytest_first_block(cloud, toolchain):
    """Exit 2 (pytest.exit in a test) with a junit that lists no failing test: typed PYTEST.SESSION_ERROR, pytest's
    own first block in the message (before: `pytest exited 2` with the output tail only)."""
    stopper = "import pytest\n\ndef test_stop():\n    pytest.exit('environment not ready', returncode=2)\n"
    code, report = _run(cloud, toolchain, **{"tests/test_main.py": stopper})
    assert code == 10, report
    [d] = [d for d in report["diagnostics"] if d["severity"] == "error"]
    assert (d["code"], d["file"]) == ("PYTEST.SESSION_ERROR", "apps/svc/requirements.txt")
    assert "environment not ready" in d["message"]
    assert d["message"].endswith("(pytest stopped with a session error for apps/svc: exit 2; pytest's crash report "
                                 "in detail)")


def test_n_ordinary_test_failures_are_unchanged(cloud, toolchain):
    failing = "def test_bad():\n    assert 1 == 2\n"
    code, report = _run(cloud, toolchain, **{"tests/test_main.py": failing})
    assert code == 10
    assert (report["tests_total"], report["tests_failed"]) == (1, 1)
    [d] = [d for d in report["diagnostics"] if d["severity"] == "error"]
    assert (d["code"], d["file"], d["line"]) == ("PY.TEST_FAILED", "tests/test_main.py", 1)
    assert d["message"].startswith("tests.test_main.test_bad: assert 1 == 2")


def test_conftest_import_error_is_a_startup_error_with_the_start_message(cloud, toolchain):
    """Exit 4 before any junit (Opus RT F2): typed PYTEST.STARTUP_ERROR, scoped to the service; QA-START-MSG's message
    (pytest's first block first) is unchanged."""
    code, report = _run(cloud, toolchain, **{"tests/conftest.py": "import not_installed_anywhere\n"})
    assert code == 10
    [d] = [d for d in report["diagnostics"] if d["severity"] == "error"]
    assert (d["code"], d["file"]) == ("PYTEST.STARTUP_ERROR", "apps/svc/requirements.txt")
    assert d["message"].startswith("ImportError while loading conftest ")
    assert "(pytest stopped before writing a junit report for apps/svc: exit 4; full output in detail)" in d["message"]


@pytest.mark.parametrize("test_src, message", [
    # (b) a junit that does not parse, after os._exit(1): the app's / a test's doing, not a pytest crash
    ("import os\n\ndef test_forge(request):\n    open(request.config.option.xmlpath, 'w').write('<not xml')\n"
     "    os._exit(1)\n", "pytest exited 1 without a readable junit report (ParseError)"),
    # (b) no junit at all after os._exit(1) (not a pytest exit code 2/3/4)
    ("import os\n\ndef test_quit():\n    os._exit(1)\n", None),
])
def test_n_unreadable_report_on_other_exits_stays_report_invalid(cloud, toolchain, test_src, message):
    code, report = _run(cloud, toolchain, **{"tests/test_main.py": test_src})
    assert code == 10
    [d] = [d for d in report["diagnostics"] if d["severity"] == "error"]
    assert (d["code"], d["file"]) == ("PYTEST.REPORT_INVALID", None)
    if message is not None:
        assert d["message"] == message


def test_n_a_passing_run_is_unchanged(cloud, toolchain):
    code, report = _run(cloud, toolchain)
    assert code == 0 and report["passed"] is True and report["tests_total"] == 1 and report["diagnostics"] == []


# ============================================================================================ (b) plugin pins
def test_real_constraints_pin_pytest_asyncio_at_the_ci_release():
    pins = sj.toolchain_pins(os.path.join(sup.QA_DIR, "qa_toolchain_constraints.txt"))
    assert pins == {"pytest": ["pytest==9.1.1"], "pytest-timeout": ["pytest-timeout==2.4.0"],
                    "pytest-asyncio": ["pytest-asyncio==1.4.0"]}
    ci = open(os.path.join(sup.REPO_ROOT, ".github", "ci-constraints.txt")).read().splitlines()
    assert "pytest==9.1.1" in ci and "pytest-asyncio==1.4.0" in ci   # the pair the platform's own CI runs
    assert "pytest-asyncio" in sj.OPTIONAL_PYTEST_PLUGIN_DISTS        # a plugin QA loads when installed


PINS = {"pytest": ["pytest==9.1.1"], "pytest-timeout": ["pytest-timeout==2.4.0"],
        "pytest-asyncio": ["pytest-asyncio==1.4.0"]}


@pytest.mark.parametrize("reqs, out", [
    (["pytest-asyncio==0.23.8"], ["pytest-asyncio==1.4.0"]),
    (["fastapi", "Pytest_Asyncio>=0.21", "pytest-asyncio<1"], ["pytest-asyncio==1.4.0"]),   # once, canonical name
    (["pytest==8.1.1", "pytest-timeout==2.0"], []),          # installed by step 2a: nothing added (unchanged)
    (["fastapi", "pytest-mock", "anyio"], []),               # not pinned: unchanged
])
def test_toolchain_replacements(reqs, out):
    reqs = [str(sj.Requirement(r)) for r in reqs]
    assert sj.toolchain_replacements(reqs, PINS, ("pytest", "pytest-timeout")) == out


def test_workload_pytest_asyncio_below_9_is_replaced_by_the_pin_with_a_note(cloud, toolchain, pip_calls):
    code, report = _run(cloud, toolchain, "pytest<9.0.0,>=8.0.0\npytest-asyncio==0.23.8\npluggy\n")
    assert code == 0, report
    assert pip_calls == [["pluggy", "pytest-asyncio==1.4.0"]]   # replaced, never left out
    assert ("note: QA used the toolchain's pytest-asyncio==1.4.0 instead of the workload's pytest-asyncio==0.23.8"
            in report["logs_tail"])
    assert "QA used the toolchain's pytest==9.1.1 instead of the workload's pytest<9.0.0,>=8.0.0" in \
        report["logs_tail"]


def test_n_workload_without_the_plugin_installs_nothing_extra(cloud, toolchain, pip_calls):
    code, report = _run(cloud, toolchain, "pluggy\n")
    assert code == 0, report
    assert pip_calls == [["pluggy"]] and "note: QA used the toolchain's" not in report["logs_tail"]
