"""Row QA-TOOLCHAIN-PINS (owner 10-27, "toolchain wins"): in the QA sandbox only, a workload requirement for a package
the QA test toolchain pins (`apps/qa-runner/qa_toolchain_constraints.txt`, today pytest and pytest-timeout) is left out
of step 2b's `pip install`, matched by canonical PEP 503 name (never by text); the toolchain's pin is used and a note is
logged. Every other requirement reaches pip unchanged and in order; any other unresolvable requirement is still
REQ.UNRESOLVABLE; a malformed constraints file is the platform's fault (exit 11).

Seen live 10-27: a generated requirements.txt pinned pytest==8.1.1 against the toolchain's 9.1.1 and QA stopped
NO_PROGRESS on REQ.UNRESOLVABLE. End-to-end cases run the real job against the loopback index of
tests/qa_sandbox_support.py (nothing is downloaded).
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

sj = sup.load_sandbox_job("sandbox_job_toolchain_pins")

NONCE = "0123456789abcdef0123456789abcdef"
REAL_CONSTRAINTS = os.path.join(sup.QA_DIR, "qa_toolchain_constraints.txt")
PINS = {"pytest": ["pytest==9.1.1"], "pytest-timeout": ["pytest-timeout==2.4.0"]}
# Row QA-PYTEST-CRASH added the pytest-asyncio pin (installed only when a workload names it; tests/test_qa_pytest_crash.py)
REAL_PINS = dict(PINS, **{"pytest-asyncio": ["pytest-asyncio==1.4.0"]})

MAIN = "def health():\n    return {'status': 'healthy'}\n"
TEST = "from main import health\n\ndef test_health():\n    assert health() == {'status': 'healthy'}\n"


# ============================================================================================ unit: the constraints parse
def test_real_constraints_file_pins_pytest_and_pytest_timeout():
    assert sj.toolchain_pins(REAL_CONSTRAINTS) == REAL_PINS


def _write(tmp_path, text, name="constraints.txt"):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


@pytest.mark.parametrize("line", [
    "-e .",                                  # a pip option
    "-r other.txt",
    "pytest @ https://example.invalid/p.whl",  # a URL
    "pytest[testing]==9.1.1",                # extras (pip refuses them in constraints)
    "pytest==9.1.1; python_version < '3'",   # a marker
    "==9.1.1",                               # unparsable (no name)
    "not a requirement!!",
])
def test_malformed_constraints_line_is_a_runner_error(tmp_path, line):
    with pytest.raises(sj.RunnerError):
        sj.toolchain_pins(_write(tmp_path, f"# header\npytest-timeout==2.4.0\n{line}\n"))


def test_unreadable_constraints_file_is_a_runner_error(tmp_path):
    with pytest.raises(sj.RunnerError):
        sj.toolchain_pins(str(tmp_path / "missing.txt"))
    p = tmp_path / "latin1.txt"
    p.write_bytes(b"pytest==9.1.1  # \xe9\n")
    with pytest.raises(sj.RunnerError):
        sj.toolchain_pins(str(p))


def test_constraints_comments_and_blank_lines_are_ignored(tmp_path):
    text = "# c\n\n  pytest==9.1.1  # inline\nPytest_Timeout==2.4.0\n"
    assert sj.toolchain_pins(_write(tmp_path, text)) == {"pytest": ["pytest==9.1.1"],
                                                         "pytest-timeout": ["Pytest_Timeout==2.4.0"]}


# ============================================================================================ unit: the split
@pytest.mark.parametrize("workload, pin", [
    ("pytest==8.1.1", "pytest==9.1.1"),
    ("PyTest>=7", "pytest==9.1.1"),
    ("pytest_timeout==2.0", "pytest-timeout==2.4.0"),
    ("pytest.timeout<3", "pytest-timeout==2.4.0"),
])
def test_toolchain_package_is_dropped_by_canonical_name(workload, pin):
    req = str(sj.Requirement(workload))  # check_requirements' stored form
    kept, dropped = sj.split_toolchain_pinned(["fastapi>=0.110", req, "uvicorn"], PINS)
    assert kept == ["fastapi>=0.110", "uvicorn"]
    assert dropped == [(req, pin)]


def test_n_requirements_without_a_toolchain_package_are_unchanged_and_in_order():
    reqs = ["uvicorn[standard]>=0.29", "fastapi>=0.110", 'httpx; python_version >= "3.8"', "pytest-cov==5.0",
            "pytest-asyncio>=0.23", "pytest-mock", "pytesting==1.0", "requests"]
    reqs = [str(sj.Requirement(r)) for r in reqs]
    kept, dropped = sj.split_toolchain_pinned(reqs, PINS)
    assert kept == reqs and dropped == []


def test_n_no_pins_drops_nothing():
    reqs = ["pytest==8.1.1", "fastapi"]
    assert sj.split_toolchain_pinned(reqs, {}) == (reqs, [])


# ============================================================================================ end to end (real job)
@pytest.fixture(scope="module")
def wheelhouse(tmp_path_factory):
    """The standard offline wheelhouse plus a stub pytest-asyncio and a stub pytest-timeout at the toolchain's pin (no
    pytest11 entry point, so never loaded)."""
    d = str(tmp_path_factory.mktemp("wheelhouse-pins"))
    index = sup.build_wheelhouse(d)
    index["pytest-asyncio"] = [sup.build_wheel(d, "pytest-asyncio", "0.0.1", {"pytest_asyncio_stub.py": "X = 1\n"})]
    index["pytest-timeout"] = [sup.build_wheel(d, "pytest-timeout", "2.4.0", {"pytest_timeout_stub.py": "X = 1\n"})]
    # a near-miss name of a pinned package (canonical-name match, never a prefix): reaches pip unchanged
    index["pytest-timeout-extra"] = [sup.build_wheel(d, "pytest-timeout-extra", "0.0.1", {"ptx_stub.py": "X = 1\n"})]
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
    """argv of every workload `pip install` (step 2b), recorded around the real Runner.run."""
    calls = []
    real = sj.Runner.run

    def recording(self, argv, *a, **k):
        if k.get("what") == "pip install":
            calls.append(list(argv))
        return real(self, argv, *a, **k)

    monkeypatch.setattr(sj.Runner, "run", recording)
    return calls


def _files(requirements):
    return {
        "apps/svc/main.py": MAIN,
        "apps/svc/requirements.txt": requirements,
        "apps/svc/Procfile": "web: python main.py\n",
        "apps/svc/.python-version": "3.13\n",
        "tests/test_main.py": TEST,
    }


def _run(cloud, toolchain, requirements):
    archive = deterministic_tar_gz({k: v.encode() for k, v in _files(requirements).items()})
    cloud.source = archive
    env = {
        "QA_SOURCE_URL": cloud.url("source.tar.gz"), "QA_SOURCE_SHA256": hashlib.sha256(archive).hexdigest(),
        "QA_STATIC_PUT_URL": cloud.url("static.json"), "QA_REPORT_PUT_URL": cloud.url("report.json"),
        "QA_NONCE": NONCE, "QA_TRACE_ID": "trace-pins", "QA_COMMIT_SHA": "c" * 40, "QA_PRODUCT_ID": "demo-app",
        "QA_DEADLINE_SECONDS": "300",
    }
    code = sj.run_job(env, toolchain=toolchain, transport=sj.HttpTransport(sleep=lambda s: None))
    r = cloud.objects.get("report.json")
    return code, (json.loads(r) if r else None)


def _verdict(cloud, code):
    if code == 0:
        execution, tasks = {"completionTime": "t", "succeededCount": 1}, [{"lastAttemptResult": {}}]
    else:
        execution, tasks = {"completionTime": "t", "failedCount": 1}, [{"lastAttemptResult": {"exitCode": code}}]
    return classify(execution, tasks, cloud.objects.get("static.json"), cloud.objects.get("report.json"), NONCE)


def _pip_tail(call):
    """The requirement arguments of a step-2b pip argv (everything after `-c <constraints>`)."""
    return call[call.index("-c") + 2:]


def test_live_case_pytest_pin_is_replaced_by_the_toolchain_pin(cloud, toolchain, pip_calls):
    """10-27 live finding: `pytest==8.1.1` vs the toolchain's 9.1.1 no longer stops QA."""
    code, report = _run(cloud, toolchain, "pytest==8.1.1\npluggy\n")
    assert code == 0, report
    assert report["passed"] is True and report["tests_total"] == 1
    assert [d["code"] for d in report["diagnostics"]] == []  # a log note only, no new diagnostic
    assert ("note: QA used the toolchain's pytest==9.1.1 instead of the workload's pytest==8.1.1"
            in report["logs_tail"])
    assert [_pip_tail(c) for c in pip_calls] == [["pluggy"]]  # install proceeds with the remaining list
    assert _verdict(cloud, code).passed is True


def test_only_toolchain_packages_means_no_workload_pip_install(cloud, toolchain, pip_calls):
    """`PyTest>=7` and `pytest_timeout==2.0` are both dropped (canonical names). With the production test_packages
    (step 2a installs pytest and pytest-timeout), nothing is left for step 2b: no workload pip install at all."""
    toolchain.test_packages = ("pytest", "pytest-timeout")
    code, report = _run(cloud, toolchain, "PyTest>=7\npytest_timeout==2.0\n")
    assert code == 0, report
    assert pip_calls == []
    assert "the workload's PyTest>=7" in report["logs_tail"]
    assert "pytest-timeout==2.4.0 instead of the workload's pytest_timeout==2.0" in report["logs_tail"]


def test_n_requirements_without_toolchain_packages_reach_pip_byte_identical(cloud, toolchain, pip_calls):
    code, report = _run(cloud, toolchain, "iniconfig>=1.0\npytest-timeout-extra==0.0.1\npluggy\n")
    assert code == 0, report
    assert [_pip_tail(c) for c in pip_calls] == [["iniconfig>=1.0", "pytest-timeout-extra==0.0.1", "pluggy"]]
    assert "note: QA used the toolchain's" not in report["logs_tail"]


def test_n_unrelated_unresolvable_requirement_is_still_req_unresolvable(cloud, toolchain, pip_calls):
    """A dropped pytest pin does not hide another conflict: `pluggy<1.0` cannot coexist with the toolchain's pytest."""
    code, report = _run(cloud, toolchain, "pytest==8.1.1\npluggy<1.0\n")
    assert code == 10
    assert [d["code"] for d in report["diagnostics"]] == ["REQ.UNRESOLVABLE"]
    assert [_pip_tail(c) for c in pip_calls] == [["pluggy<1.0"]]
    assert "instead of the workload's pytest==8.1.1" in report["logs_tail"]
    assert _verdict(cloud, code).error_class == ErrorClass.CODE_DEFECT


def test_n_pytest_cov_is_kept_and_fails_as_before_when_it_cannot_install(cloud, toolchain, pip_calls):
    """pytest-cov is not pinned by the toolchain: it reaches pip (no wheel on the local index -> REQ.UNRESOLVABLE)."""
    code, report = _run(cloud, toolchain, "pytest-cov==5.0\n")
    assert code == 10
    assert [d["code"] for d in report["diagnostics"]] == ["REQ.UNRESOLVABLE"]
    assert [_pip_tail(c) for c in pip_calls] == [["pytest-cov==5.0"]]


def test_malformed_constraints_file_is_exit_11_before_any_input_is_read(cloud, toolchain, tmp_path):
    bad = tmp_path / "bad-constraints.txt"
    bad.write_text("pytest==9.1.1\n-e .\n")
    toolchain.constraints = str(bad)
    code, report = _run(cloud, toolchain, "pytest==8.1.1\n")
    assert code == 11 and report is None
    assert "static.json" not in cloud.objects and cloud.requests == []  # nothing downloaded, nothing charged
