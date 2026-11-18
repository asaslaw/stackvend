"""Lane 3 PR-B: the QA sandbox job (`apps/qa-runner/sandbox_job.py`), end to end against in-process fakes.

Real subprocesses (venv, pip from a local PEP 503 index, the import smoke, pytest) run in tmp dirs; the three signed
URLs and the package index are a loopback HTTP server (qa_sandbox_support.FakeCloud). bandit is not installed in the
test venv and nothing may be downloaded, so a stub with the real CLI shape stands in (the real-bandit case is skipped
unless bandit is importable). Each verdict is also fed to the gateway's `qa_job_client.classify` so both sides of the
contract are exercised together (more contract pins: tests/test_lane3_prb_qa_contract.py).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import time

import pytest

import qa_sandbox_support as sup
import fd4f_support  # noqa: F401  (puts the gateway on sys.path)
from gate_errors import ErrorClass
from qa_job_client import JOB_INTERNAL_DEADLINE_S, ReportV1, StaticV1, classify
from qa_source import deterministic_tar_gz

sj = sup.load_sandbox_job()

NONCE = "0123456789abcdef0123456789abcdef"
COMMIT = "c" * 40
TRACE = "trace-prb-1"

PASSING_MAIN = (
    "import os\n"
    "def health():\n"
    "    return {'status': 'healthy'}\n"
    "if __name__ == '__main__':\n"
    "    import uvicorn\n"
    "    uvicorn.run('main:app', host='0.0.0.0', port=int(os.getenv('PORT', '8080')))\n"  # E1: platform B104
)
PASSING_TEST = "from main import health\n\ndef test_health():\n    assert health() == {'status': 'healthy'}\n"
FIXTURE_CONFTEST = "import pytest\n\n@pytest.fixture\ndef client():\n    return object()\n"


def single_service(**extra):
    files = {
        "apps/svc/main.py": PASSING_MAIN,
        "apps/svc/requirements.txt": "",
        "apps/svc/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}\n",
        "apps/svc/.python-version": "3.13\n",
        "tests/conftest.py": FIXTURE_CONFTEST,
        "tests/test_main.py": PASSING_TEST,
        "README.md": "# demo\n",
    }
    files.update(extra)
    return {k: v for k, v in files.items() if v is not None}


def tgz(files):
    return deterministic_tar_gz({k: (v.encode() if isinstance(v, str) else v) for k, v in files.items()})


@pytest.fixture(scope="session")
def wheelhouse(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("wheelhouse"))
    return d, sup.build_wheelhouse(d)


@pytest.fixture()
def cloud(wheelhouse):
    c = sup.FakeCloud(*wheelhouse)
    yield c
    c.close()


@pytest.fixture()
def toolchain(cloud, tmp_path):
    return sj.Toolchain(
        bandit_argv=sup.write_fake_bandit(str(tmp_path / "bandit")),
        test_packages=("pytest",),  # pytest-timeout is not installed here (nothing may be downloaded)
        pytest_extra_args=(),
        index_url=cloud.index_url,
        apply_rlimits=False,
        **sup.HERMETIC_TOOLCHAIN,
    )


def job_env(cloud, archive, **over):
    env = {
        "QA_SOURCE_URL": cloud.url("source.tar.gz"),
        "QA_SOURCE_SHA256": hashlib.sha256(archive).hexdigest(),
        "QA_STATIC_PUT_URL": cloud.url("static.json"),
        "QA_REPORT_PUT_URL": cloud.url("report.json"),
        "QA_NONCE": NONCE,
        "QA_TRACE_ID": TRACE,
        "QA_COMMIT_SHA": COMMIT,
        "QA_PRODUCT_ID": "demo-app",
        "QA_DEADLINE_SECONDS": "300",
    }
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


def run(cloud, toolchain, files=None, archive=None, **env_over):
    archive = tgz(files if files is not None else single_service()) if archive is None else archive
    cloud.source = archive
    env = job_env(cloud, archive, **env_over)
    code = sj.run_job(env, toolchain=toolchain, transport=sj.HttpTransport(sleep=lambda s: None))
    return code, env


def artifacts(cloud):
    s = cloud.objects.get("static.json")
    r = cloud.objects.get("report.json")
    return (json.loads(s) if s else None), (json.loads(r) if r else None)


def gateway_verdict(cloud, code):
    """What the gateway concludes from this run (execution counts as Cloud Run reports them for that exit code)."""
    if code == 0:
        execution, tasks = {"completionTime": "t", "succeededCount": 1}, [{"lastAttemptResult": {}}]
    else:
        execution, tasks = {"completionTime": "t", "failedCount": 1}, [{"lastAttemptResult": {"exitCode": code}}]
    return classify(execution, tasks, cloud.objects.get("static.json"), cloud.objects.get("report.json"), NONCE)


def codes(diags):
    return [d["code"] for d in diags]


# ------------------------------------------------------------------------------------------------------------------
# Negative (Do No Harm): valid workloads pass, unchanged
# ------------------------------------------------------------------------------------------------------------------
def test_n_valid_single_service_passes_static_before_report(cloud, toolchain):
    code, _ = run(cloud, toolchain)
    static, report = artifacts(cloud)
    assert code == 0, (static, report)
    assert cloud.put_order == ["static.json", "report.json"]  # static is written BEFORE any untrusted code
    assert static["passed"] is True and static["index_reachable"] is True and static["nonce"] == NONCE
    assert static["toolchain"]["job_contract"] == sj.JOB_CONTRACT_VERSION
    # E1: the platform-injected uvicorn host='0.0.0.0' (B104) and a fixtures-only conftest.py do not fail QA.
    assert "BANDIT.B104" not in codes(static["diagnostics"])
    assert report["passed"] is True and report["tests_total"] == 1 and report["tests_failed"] == 0
    StaticV1.model_validate(static)
    ReportV1.model_validate(report)
    out = gateway_verdict(cloud, code)
    assert out.passed is True and out.error_class is None


def test_n_two_services_with_service_local_tests(cloud, toolchain):
    files = {
        "apps/api/main.py": PASSING_MAIN,
        "apps/api/requirements.txt": "",
        "apps/api/tests/test_api.py": PASSING_TEST,
        "apps/worker/main.py": "def work():\n    return 2\n",
        "apps/worker/requirements.txt": "",
        "apps/worker/tests/test_worker.py": "from main import work\n\ndef test_w():\n    assert work() == 2\n"
                                            "\ndef test_w2():\n    assert work() + 1 == 3\n",
        "apps/frontend/package.json": "{}\n",  # not a Python service: ignored
    }
    code, _ = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 0, (static, report)
    assert report["tests_total"] == 3


def test_n_extracted_bytes_equal_the_source(tmp_path):
    files = {"apps/svc/main.py": b"print(1)\n", "apps/svc/data.bin": bytes(range(256)) * 3, "a/b/c.txt": b"x"}
    archive = deterministic_tar_gz(files)
    dest = tmp_path / "out"
    dest.mkdir()
    sizes = sj.extract_source(archive, hashlib.sha256(archive).hexdigest(), str(dest))
    assert sizes == {k: len(v) for k, v in files.items()}
    for k, v in files.items():
        assert (dest / k).read_bytes() == v


def test_n_python_version_mismatch_recorded_not_blocking(tmp_path):
    (tmp_path / "apps" / "a").mkdir(parents=True)
    (tmp_path / "apps" / "a" / ".python-version").write_text("2.7\n")
    svc = sj.Service("a", "apps/a", [])
    assert sj._python_version_mismatches(str(tmp_path), [svc]) == "apps/a:2.7"
    job = f"{sys.version_info[0]}.{sys.version_info[1]}"
    (tmp_path / "apps" / "a" / ".python-version").write_text(job + "\n")
    assert sj._python_version_mismatches(str(tmp_path), [svc]) == ""


# ------------------------------------------------------------------------------------------------------------------
# CODE_DEFECT (exit 10 / 12): the code failed checks that ran
# ------------------------------------------------------------------------------------------------------------------
def test_failing_test_is_code_defect_with_location(cloud, toolchain):
    files = single_service(**{"tests/test_main.py": "def test_bad():\n    assert 1 + 1 == 3\n"})
    code, _ = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 10
    assert report["passed"] is False and report["tests_failed"] == 1
    d = [d for d in report["diagnostics"] if d["code"] == "PY.TEST_FAILED"][0]
    assert d["file"] == "tests/test_main.py" and d["line"] == 1 and d["tool"] == "pytest"
    out = gateway_verdict(cloud, code)
    assert out.error_class == ErrorClass.CODE_DEFECT


def test_e4_outcome_rewriting_conftest_hook_fails_static_phase(cloud, toolchain):
    conftest = (
        "import pytest\n\n@pytest.hookimpl(hookwrapper=True)\ndef pytest_runtest_makereport(item, call):\n"
        "    outcome = yield\n    rep = outcome.get_result()\n    rep.outcome = 'passed'\n"
    )
    files = single_service(**{"tests/conftest.py": conftest, "tests/test_main.py": "def test_x():\n    assert 0\n"})
    code, _ = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 10
    assert static["passed"] is False and report is None  # no untrusted code ran
    assert "PYTEST.OUTCOME_HOOK" in codes(static["diagnostics"])
    assert gateway_verdict(cloud, code).error_class == ErrorClass.CODE_DEFECT


def test_intree_pytest_ini_addopts_cannot_deselect_failures(cloud, toolchain):
    files = single_service(**{
        "pytest.ini": "[pytest]\naddopts = --deselect tests/test_main.py::test_bad -p no:junitxml\n",
        "tests/test_main.py": "def test_bad():\n    assert False\n\ndef test_ok():\n    assert True\n",
    })
    code, _ = run(cloud, toolchain, files)
    _, report = artifacts(cloud)
    assert code == 10 and report["tests_total"] == 2 and report["tests_failed"] == 1


def test_syntax_error_is_static_code_defect(cloud, toolchain):
    code, _ = run(cloud, toolchain, single_service(**{"apps/svc/broken.py": "def broken(:\n"}))
    static, report = artifacts(cloud)
    assert code == 10 and report is None
    d = [d for d in static["diagnostics"] if d["code"] == "PY.SYNTAX"][0]
    assert d["file"] == "apps/svc/broken.py" and d["line"] == 1


def test_dockerfile_is_static_code_defect(cloud, toolchain):
    code, _ = run(cloud, toolchain, single_service(**{"apps/svc/Dockerfile": "FROM python\n"}))
    static, _ = artifacts(cloud)
    assert code == 10 and "POLICY.DOCKERFILE" in codes(static["diagnostics"])


def test_high_severity_bandit_finding_blocks_and_runner_owns_bandit_config(cloud, toolchain, tmp_path):
    bad = "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)  # nosec\n"
    files = single_service(**{
        "apps/svc/tools.py": bad,
        "apps/svc/.bandit": "[bandit]\nskips = B602\n",  # E3: workload-owned config must have no effect
        "apps/svc/calc.py": "def calc(x):\n    return eval(x)\n",  # MEDIUM severity: reported, not blocking
    })
    code, _ = run(cloud, toolchain, files)
    static, _ = artifacts(cloud)
    assert code == 10
    by_code = {d["code"]: d for d in static["diagnostics"]}
    assert by_code["BANDIT.B602"]["severity"] == "error" and by_code["BANDIT.B602"]["file"] == "apps/svc/tools.py"
    assert by_code["BANDIT.B307"]["severity"] == "warning"
    argv = json.loads((tmp_path / "bandit" / "argv.json").read_text())
    assert "--ignore-nosec" in argv and argv[argv.index("--ini") + 1] == toolchain.bandit_ini
    assert argv[argv.index("-f") + 1] == "json"


def test_medium_bandit_findings_alone_do_not_block(cloud, toolchain):
    code, _ = run(cloud, toolchain, single_service(**{"apps/svc/calc.py": "def calc(x):\n    return eval(x)\n"}))
    static, _ = artifacts(cloud)
    assert code == 0 and static["passed"] is True
    assert [d["severity"] for d in static["diagnostics"]] == ["warning"]


def test_import_smoke_failure_is_code_defect(cloud, toolchain):
    files = single_service(**{"apps/svc/main.py": "import definitely_not_installed_module_xyz\n"})
    code, _ = run(cloud, toolchain, files)
    _, report = artifacts(cloud)
    assert code == 10
    d = [d for d in report["diagnostics"] if d["code"] == "PY.IMPORT_FAILED"][0]
    assert d["file"] == "apps/svc/main.py" and "definitely_not_installed_module_xyz" in d["detail"]


def test_unresolvable_requirement_with_reachable_index_is_code_defect(cloud, toolchain):
    files = single_service(**{"apps/svc/requirements.txt": "definitely-not-a-real-package-xyz==1.0\n"})
    code, _ = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 10 and static["index_reachable"] is True
    assert "REQ.UNRESOLVABLE" in codes(report["diagnostics"])
    assert gateway_verdict(cloud, code).error_class == ErrorClass.CODE_DEFECT


def test_untrusted_timeout_is_exit_12_with_report(cloud, toolchain):
    files = single_service(**{"tests/test_main.py": "import time\n\ndef test_hang():\n    time.sleep(120)\n"})
    t0 = time.monotonic()
    code, _ = run(cloud, toolchain, files, QA_DEADLINE_SECONDS="12")
    elapsed = time.monotonic() - t0
    static, report = artifacts(cloud)
    assert code == 12, (static, report)
    assert elapsed < 12 + 15
    assert report["passed"] is False and "PY.TEST_TIMEOUT" in codes(report["diagnostics"])
    assert gateway_verdict(cloud, code).error_class == ErrorClass.CODE_DEFECT


def test_no_tests_is_code_defect(cloud, toolchain):
    files = single_service(**{"tests/test_main.py": None, "tests/conftest.py": None})
    code, _ = run(cloud, toolchain, files)
    static, _ = artifacts(cloud)
    assert code == 10 and "PY.NO_TESTS" in codes(static["diagnostics"])


def test_untrusted_code_sees_only_the_allow_listed_env(cloud, toolchain):
    dump = "import os\n\ndef test_env():\n    assert False, 'ENV=' + ','.join(sorted(os.environ))\n"
    files = single_service(**{"tests/test_main.py": dump})
    code, env = run(cloud, toolchain, files)
    _, report = artifacts(cloud)
    assert code == 10
    msg = [d for d in report["diagnostics"] if d["code"] == "PY.TEST_FAILED"][0]["message"]
    keys = set(msg.split("ENV=", 1)[1].split()[0].split(","))
    allowed = set(sj.SANDBOX_ENV_FIXED) | {"PATH", "HOME", "TMPDIR", "PYTHONPATH", "LD_LIBRARY_PATH"}
    # The hermetic guard forces its own (offline) settings into every child of the test process.
    guard = (set(hermetic_guard.FORCED_ENV) | set(hermetic_guard.GIT_IDENTITY_ENV)
             | {"GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_CONFIG", hermetic_guard.CHILD_LOG_ENV}
             | {k for k in keys if k.startswith("GIT_CONFIG_")})
    # pytest itself adds PYTEST_CURRENT_TEST / PYTEST_VERSION; macOS CoreFoundation sets __CF_USER_TEXT_ENCODING in
    # every process it starts (not inherited from the job).
    runtime = {"PYTEST_CURRENT_TEST", "PYTEST_VERSION"} | ({"__CF_USER_TEXT_ENCODING"} if sys.platform == "darwin" else set())
    assert keys - allowed - guard - runtime == set()
    assert not any(k.startswith(("QA_", "K_", "CLOUD_RUN_")) or k in ("PROJECT_ID", "GOOGLE_CLOUD_PROJECT")
                   for k in keys)
    assert not any(k.startswith("QA_") for k in env)  # inputs were read once and removed


# ------------------------------------------------------------------------------------------------------------------
# RUNNER_ERROR (exit 11): never a pass, never a code defect
# ------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("missing", sj.REQUIRED_INPUTS)
def test_missing_input_is_runner_error_and_writes_nothing(cloud, toolchain, missing):
    code, _ = run(cloud, toolchain, **{missing: None})
    assert code == 11 and cloud.objects == {}
    assert not any(r.startswith("GET /runs/") for r in cloud.requests)


@pytest.mark.parametrize("key,value", [
    ("QA_SOURCE_SHA256", "A" * 64), ("QA_NONCE", "short"), ("QA_COMMIT_SHA", "main"),
    ("QA_TRACE_ID", "../x"), ("QA_DEADLINE_SECONDS", "0"), ("QA_DEADLINE_SECONDS", "9999"),
    ("QA_DEADLINE_SECONDS", "ten"), ("QA_STATIC_PUT_URL", "file:///etc/passwd"),
])
def test_invalid_input_is_runner_error(cloud, toolchain, key, value):
    code, _ = run(cloud, toolchain, **{key: value})
    assert code == 11 and cloud.objects == {}


def test_same_url_for_static_and_report_is_refused(cloud, toolchain):
    code, _ = run(cloud, toolchain, QA_REPORT_PUT_URL=cloud.url("static.json"))
    assert code == 11 and cloud.objects == {}


def test_sha_mismatch_is_runner_error(cloud, toolchain):
    code, _ = run(cloud, toolchain, QA_SOURCE_SHA256="0" * 64)
    assert code == 11 and cloud.objects == {}


@pytest.mark.parametrize("status", [403, 404, 500])
def test_source_get_failure_is_runner_error(cloud, toolchain, status):
    cloud.source_status = status
    archive = tgz(single_service())
    env = job_env(cloud, archive)
    assert sj.run_job(env, toolchain=toolchain, transport=sj.HttpTransport(sleep=lambda s: None)) == 11
    assert cloud.objects == {}


def _tar_with(members):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for ti, data in members:
            tf.addfile(ti, io.BytesIO(data) if data is not None else None)
    return gzip.compress(raw.getvalue(), mtime=0)


def _reg(name, data=b"x"):
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    return ti, data


def _link(name, target, kind):
    ti = tarfile.TarInfo(name)
    ti.type, ti.linkname = kind, target
    return ti, None


def _special(name, kind):
    ti = tarfile.TarInfo(name)
    ti.type = kind
    return ti, None


MALFORMED = {
    "symlink_in_tree": [_reg("a.py"), _link("b.py", "a.py", tarfile.SYMTYPE)],
    "symlink_absolute": [_link("b.py", "/etc/passwd", tarfile.SYMTYPE)],
    "hardlink": [_reg("a.py"), _link("b.py", "a.py", tarfile.LNKTYPE)],
    "dotdot": [_reg("../escape.py")],
    "absolute": [_reg("/etc/x.py")],
    "dot_git": [_reg(".git/config")],
    "directory_member": [_special("apps", tarfile.DIRTYPE), _reg("apps/a.py")],
    "duplicate": [_reg("a.py"), _reg("a.py", b"y")],
    "file_and_dir": [_reg("a"), _reg("a/b.py")],
    "fifo": [_special("p", tarfile.FIFOTYPE)],
}


@pytest.mark.parametrize("case", sorted(MALFORMED))
def test_malformed_tree_is_runner_error(cloud, toolchain, case, tmp_path):
    archive = _tar_with(MALFORMED[case])
    with pytest.raises(sj.RunnerError):
        sj.extract_source(archive, hashlib.sha256(archive).hexdigest(), str(tmp_path))
    assert not (tmp_path.parent / "escape.py").exists()
    code, _ = run(cloud, toolchain, archive=archive)
    assert code == 11 and cloud.objects == {}


@pytest.mark.parametrize("blob", [b"not a gzip", gzip.compress(b"not a tar"), b"\x1f\x8b\x08\x00truncated",
                                  gzip.compress(b"", mtime=0)])
def test_corrupt_or_empty_archive_is_runner_error(tmp_path, blob):
    with pytest.raises(sj.RunnerError):
        sj.extract_source(blob, hashlib.sha256(blob).hexdigest(), str(tmp_path))


def test_truncated_gzip_is_runner_error(tmp_path):
    good = tgz(single_service())
    blob = good[: len(good) - 6]
    with pytest.raises(sj.RunnerError):
        sj.extract_source(blob, hashlib.sha256(blob).hexdigest(), str(tmp_path))


def test_index_unreachable_is_runner_error_never_a_req_defect(cloud, toolchain):
    cloud.index_up = False
    files = single_service(**{"apps/svc/requirements.txt": "anything==1.0\n"})
    code, _ = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 11 and static["index_reachable"] is False and report is None
    assert gateway_verdict(cloud, code).error_class == ErrorClass.GATE_UNAVAILABLE


def test_static_put_conflict_412_is_runner_error(cloud, toolchain):
    cloud.objects["static.json"] = b'{"forged": true}'
    code, _ = run(cloud, toolchain)
    assert code == 11 and "report.json" not in cloud.objects


def test_report_put_conflict_412_is_runner_error(cloud, toolchain):
    cloud.objects["report.json"] = b'{"forged": true}'  # e.g. test code pre-wrote a forged report
    code, _ = run(cloud, toolchain)
    assert code == 11
    assert gateway_verdict(cloud, code).error_class == ErrorClass.GATE_UNAVAILABLE


@pytest.mark.parametrize("status", [403, 500])
def test_put_failure_is_runner_error(cloud, toolchain, status):
    cloud.put_status["static.json"] = status
    code, _ = run(cloud, toolchain)
    assert code == 11 and cloud.objects == {}


def test_create_only_headers_are_sent_exactly(cloud, toolchain):
    run(cloud, toolchain)
    for name in ("static.json", "report.json"):
        h = cloud.put_headers[name]
        assert h["x-goog-if-generation-match"] == "0" and h["content-type"] == "application/json"


def test_missing_bandit_is_runner_error_before_inputs_are_read(cloud, toolchain):
    toolchain.bandit_argv = (sys.executable, "-m", "definitely_not_bandit_module")
    archive = tgz(single_service())
    cloud.source = archive
    env = job_env(cloud, archive)
    assert sj.run_job(env, toolchain=toolchain, transport=sj.HttpTransport(sleep=lambda s: None)) == 11
    assert cloud.requests == [] and cloud.objects == {}


def test_missing_runner_config_is_runner_error(cloud, toolchain, tmp_path):
    toolchain.pytest_ini = str(tmp_path / "nope.ini")
    code, _ = run(cloud, toolchain)
    assert code == 11 and cloud.objects == {}


def test_deadline_in_trusted_step_is_exit_11_not_12(cloud, toolchain):
    """Red-team F2a: the deadline expiring while no untrusted code runs (here: bandit) is not a code defect."""
    t0 = time.monotonic()
    code, _ = run(cloud, toolchain, single_service(SLOW_BANDIT="1"), QA_DEADLINE_SECONDS="3")
    assert code == 11 and time.monotonic() - t0 < 30
    assert cloud.objects == {}


def test_internal_exception_is_exit_11(monkeypatch):
    def boom(*a, **k):
        raise KeyError("internal bug")

    monkeypatch.setattr(sj, "run_job", boom)
    assert sj.main([]) == 11
    monkeypatch.setattr(sj, "run_job", lambda *a, **k: (_ for _ in ()).throw(SystemExit(0)))
    assert sj.main([]) == 11
    monkeypatch.setattr(sj, "run_job", lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert sj.main([]) == 11


def test_entrypoint_without_inputs_exits_11(tmp_path):
    """`python3 -m sandbox_job` (the job's launcher args) with no QA_* env: exit 11, never 0 or 1."""
    env = hermetic_guard.child_env(extra={"TMPDIR": str(tmp_path)})
    for k in list(env):
        if k.startswith("QA_"):
            env.pop(k)
    r = subprocess.run([sys.executable, "-m", "sandbox_job"], cwd=sup.QA_DIR, env=env, capture_output=True,
                       timeout=180)
    assert r.returncode == 11, r.stdout[-2000:] + r.stderr[-2000:]


# ------------------------------------------------------------------------------------------------------------------
# Units: hook policy, layout, redaction, artifact caps, rlimits
# ------------------------------------------------------------------------------------------------------------------
def _hooks(files):
    import ast

    trees = {k: ast.parse(v) for k, v in files.items()}
    return sj.check_pytest_hooks(trees, [sj.Service("svc", "apps/svc", ["tests"])])


def test_hook_policy_negative_fixtures_and_other_hooks_allowed():
    assert _hooks({"tests/conftest.py": FIXTURE_CONFTEST + "\ndef pytest_configure(config):\n    pass\n"}) == []
    # A test module (not a plugin) may name a helper like a hook; pytest never loads hooks from it.
    assert _hooks({"tests/test_x.py": "def pytest_runtest_call():\n    pass\n"}) == []


@pytest.mark.parametrize("src", [
    "async def pytest_pyfunc_call(pyfuncitem):\n    return True\n",
    "from somewhere import pytest_runtest_makereport\n",
    "pytest_report_teststatus = lambda report, config: ('passed', '.', 'PASSED')\n",
    "import pytest\n\n@pytest.hookimpl(specname='pytest_runtest_makereport')\ndef anything(item, call):\n    pass\n",
    "class P:\n    def pytest_runtest_logreport(self, report):\n        report.outcome = 'passed'\n",
])
def test_hook_policy_flags_outcome_hooks_in_conftest(src):
    assert codes(_hooks({"tests/conftest.py": src})) == ["PYTEST.OUTCOME_HOOK"]


def test_hook_policy_follows_pytest_plugins_into_tree():
    files = {
        "tests/conftest.py": "pytest_plugins = ['helpers.plug']\n",
        "helpers/plug.py": "def pytest_sessionfinish(session, exitstatus):\n    session.exitstatus = 0\n",
    }
    found = _hooks(files)
    assert [d["file"] for d in found] == ["helpers/plug.py"]
    assert _hooks({"tests/conftest.py": "pytest_plugins = ['pytest_asyncio']\n"}) == []  # third-party: not in tree
    assert codes(_hooks({"tests/conftest.py": "import os\npytest_plugins = os.environ['X'].split()\n"})) == [
        "PYTEST.OUTCOME_HOOK"]


def test_layout_rules():
    lay = sj.discover_layout(["apps/a/requirements.txt", "apps/b/requirements.txt", "tests/test_x.py"])
    assert codes(lay.diagnostics) == ["PY.TEST_LAYOUT"]
    assert codes(sj.discover_layout(["README.md"]).diagnostics) == ["PY.NO_TESTS"]
    assert codes(sj.discover_layout(["apps/a/requirements.txt", "apps/a/main.py"]).diagnostics) == ["PY.NO_TESTS"]
    lay = sj.discover_layout(["apps/a/requirements.txt", "tests/test_x.py", "apps/a/x/requirements.txt"])
    assert lay.diagnostics == [] and [(s.rel, s.test_roots) for s in lay.services] == [("apps/a", ["tests"])]


def test_redactor_hides_exact_values_longest_first():
    r = sj.Redactor()
    r.add("https://h/x?sig=1")
    r.add("https://h/x?sig=12")
    assert r("a https://h/x?sig=12 b https://h/x?sig=1") == "a [REDACTED] b [REDACTED]"
    assert r("unrelated") == "unrelated"


def test_fit_artifact_stays_under_the_gateway_cap_and_validates():
    big = "\u2603\x01" * 5000
    diags = [sj.diag("pytest", "PY.TEST_FAILED", big, detail=big, file="tests/t.py", line=1) for _ in range(500)]
    art = {"schema_version": 1, "nonce": NONCE, "passed": False, "diagnostics": diags, "diagnostics_truncated": False,
           "tests_total": 500, "tests_failed": 500, "logs_tail": big}
    data = sj.fit_artifact(art)
    assert len(data) <= sj.MAX_ARTIFACT_BYTES
    rep = ReportV1.model_validate(json.loads(data))
    assert rep.diagnostics_truncated is True and 1 <= len(rep.diagnostics) <= 200


def test_artifacts_redact_the_signed_urls_everywhere():
    url = "https://storage.googleapis.com/b/runs/t/n/report.json?X-Goog-Signature=deadbeef"
    r = sj.Redactor()
    r.add(url)
    art = {"schema_version": 1, "nonce": NONCE, "passed": False, "diagnostics_truncated": False, "tests_total": 1,
           "tests_failed": 1, "logs_tail": f"env dump {url}",
           "diagnostics": [sj.diag("pytest", "PY.TEST_FAILED", f"saw {url}", detail=f"d {url}", file="tests/t.py")]}
    data = sj.fit_artifact(art, r).decode()
    assert "deadbeef" not in data and data.count("[REDACTED]") == 3


def test_diag_shape_matches_gateway_schema():
    from qa_job_client import DiagnosticIn

    d = sj.diag("bandit", "BANDIT.B602", "m" * 5000, file="x" * 600, line=True, detail="d" * 5000)
    m = DiagnosticIn.model_validate(d)
    assert m.file is None and m.line is None and len(m.message) == sj.MAX_FIELD_CHARS


def test_rlimit_preexec_values(monkeypatch):
    resource = pytest.importorskip("resource")
    calls = []
    monkeypatch.setattr(resource, "setrlimit", lambda what, lim: calls.append((what, lim)))
    sj._rlimit_preexec()
    assert calls == [(resource.RLIMIT_AS, (3 * 1024 ** 3,) * 2), (resource.RLIMIT_NPROC, (512, 512))]


def test_default_toolchain_is_the_runner_owned_files():
    tc = sj.Toolchain()
    for p in (tc.bandit_ini, tc.pytest_ini, tc.constraints):
        assert os.path.dirname(p) == sup.QA_DIR and os.path.isfile(p)
    assert tc.index_url == "https://pypi.org/simple" and tc.apply_rlimits is True
    assert list(tc.bandit_argv) == [sys.executable, "-m", "bandit"]
    assert "--timeout=60" in tc.pytest_extra_args and "pytest-timeout" in tc.test_packages
    with open(tc.constraints) as f:
        pins = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    assert pins and all("==" in p for p in pins)


def test_job_internal_deadline_fits_the_job_contract():
    assert JOB_INTERNAL_DEADLINE_S <= sj.MAX_DEADLINE_S


def test_real_bandit_profile_if_installed(tmp_path):
    pytest.importorskip("bandit")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text(
        "import subprocess\nsubprocess.call(input(), shell=True)  # nosec\nHOST = '0.0.0.0'\nassert HOST\n")
    (tmp_path / "src" / ".bandit").write_text("[bandit]\nskips = B602\n")
    out = tmp_path / "b.json"
    subprocess.run([sys.executable, "-m", "bandit", "-r", str(tmp_path / "src"), "-f", "json", "-o", str(out), "-q",
                    "--ignore-nosec", "--ini", sj.Toolchain().bandit_ini], env=hermetic_guard.child_env(),
                   timeout=120)
    ids = {r["test_id"] for r in json.loads(out.read_text())["results"]}
    assert "B602" in ids and "B104" not in ids and "B101" not in ids


def test_deadline_already_spent_before_an_untrusted_step_is_not_a_timeout_defect(tmp_path):
    """F2a: when the budget ran out between steps, nothing untrusted was running -> exit 11, not 12."""
    runner = sj.Runner(deadline=time.monotonic() - 1, redact=sj.Redactor())
    with pytest.raises(sj.DeadlineExpired) as ei:
        runner.run([sys.executable, "-c", "pass"], env=hermetic_guard.child_env(), cwd=str(tmp_path), untrusted=True,
                   what="pytest x",
                   log_path=str(tmp_path / "l.log"))
    assert ei.value.untrusted is False


def test_background_process_left_by_a_step_is_killed(tmp_path):
    marker = tmp_path / "alive"
    late = tmp_path / "late.py"
    late.write_text(f"import time\ntime.sleep(3)\nopen({str(marker)!r}, 'w').write('x')\n")
    step = tmp_path / "step.py"
    step.write_text(f"import subprocess, sys\nsubprocess.Popen([sys.executable, {str(late)!r}])\n")
    runner = sj.Runner(deadline=time.monotonic() + 60, redact=sj.Redactor())
    res = runner.run([sys.executable, str(step)], env=hermetic_guard.child_env(), cwd=str(tmp_path), untrusted=True,
                     what="t", log_path=str(tmp_path / "l.log"))
    assert res.returncode == 0
    time.sleep(4)
    assert not marker.exists()


def test_uninstallable_platform_toolchain_is_runner_error_not_code_defect(cloud, toolchain):
    """A bad pin in qa_toolchain_constraints.txt (or a toolchain wheel missing from the index) is the platform's
    fault: exit 11 (GATE_UNAVAILABLE), never REQ.UNRESOLVABLE against the workload."""
    toolchain.test_packages = ("pytest", "pytest-timeout")  # no pytest-timeout wheel on the local index
    code, _ = run(cloud, toolchain)
    static, report = artifacts(cloud)
    assert code == 11 and static["passed"] is True and report is None
    assert gateway_verdict(cloud, code).error_class == ErrorClass.GATE_UNAVAILABLE


def test_workload_pin_conflicting_with_the_toolchain_is_code_defect(cloud, toolchain):
    """A pin that cannot coexist with the toolchain (pytest 9 needs pluggy>=1.5) is the workload's defect. A pin of a
    toolchain package itself (e.g. pytest==7.0.0) is replaced by the toolchain's pin instead: row QA-TOOLCHAIN-PINS,
    tests/test_qa_toolchain_pins.py."""
    files = single_service(**{"apps/svc/requirements.txt": "pluggy<1.0\n"})
    code, _ = run(cloud, toolchain, files)
    _, report = artifacts(cloud)
    assert code == 10 and "REQ.UNRESOLVABLE" in codes(report["diagnostics"])
