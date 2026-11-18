"""FD-4F review H2/H3/H10 + red-team F2/F3: QA job verdict classification and the job identity check."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json

import pytest

import fd4f_support  # noqa: F401
from gate_errors import ErrorClass, GateUnavailableError
from qa_job_client import QAJobClient, QAJobConfig, classify

NONCE = "f" * 32
OK_EXEC = {"completionTime": "t", "succeededCount": 1}
FAIL_EXEC = {"completionTime": "t", "failedCount": 1}


def _art(passed=True, nonce=NONCE, diags=None, **extra):
    d = {"schema_version": 1, "nonce": nonce, "passed": passed, "diagnostics": diags or []}
    d.update(extra)
    return json.dumps(d).encode()


def _diag(code="PY.TEST_FAILED", file="tests/test_a.py"):
    return {"tool": "pytest", "code": code, "severity": "error", "file": file, "line": 1, "message": "failed"}


def _task(exit_code=None, signal=None):
    r = {}
    if exit_code:
        r["exitCode"] = exit_code
    if signal:
        r["termSignal"] = signal
    return [{"lastAttemptResult": r}]


STATIC_OK = _art(index_reachable=True)
REPORT_OK = _art(tests_total=3, tests_failed=0)


def test_negative_exit0_proto3_omitted_exitcode_passes():
    o = classify(OK_EXEC, _task(), STATIC_OK, REPORT_OK, NONCE)
    assert o.passed is True and o.error_class is None


@pytest.mark.parametrize("execution,tasks,static,report,reason", [
    ({}, _task(), STATIC_OK, REPORT_OK, "NOT_COMPLETE"),
    ({**OK_EXEC, "retriedCount": 1}, _task(), STATIC_OK, REPORT_OK, "CANCELLED_OR_RETRIED"),
    ({**OK_EXEC, "cancelledCount": 1}, _task(), STATIC_OK, REPORT_OK, "CANCELLED_OR_RETRIED"),
    (OK_EXEC, _task(), None, REPORT_OK, "STATIC_INVALID"),
    (OK_EXEC, _task(), _art(nonce="x" * 32), REPORT_OK, "STATIC_INVALID"),
    (OK_EXEC, _task(), b"{" * 10, REPORT_OK, "STATIC_INVALID"),
    (OK_EXEC, _task(), b" " * (2 * 1024 * 1024 + 1), REPORT_OK, "STATIC_INVALID"),
    (OK_EXEC, _task(), _art(unexpected_field=1), REPORT_OK, "STATIC_INVALID"),
    (FAIL_EXEC, _task(signal=9), STATIC_OK, REPORT_OK, "SIGNAL"),
    (FAIL_EXEC, [{}], STATIC_OK, REPORT_OK, "NO_ATTEMPT_RESULT"),
    (FAIL_EXEC, _task(), STATIC_OK, REPORT_OK, "COUNTS_MISMATCH"),          # exit unset on a failed task
    (OK_EXEC, _task(exit_code=10), STATIC_OK, REPORT_OK, "COUNTS_MISMATCH"),
    (FAIL_EXEC, _task(exit_code=1), STATIC_OK, REPORT_OK, "RUNNER_ERROR"),   # interpreter crash != code defect
    (FAIL_EXEC, _task(exit_code=11), STATIC_OK, REPORT_OK, "RUNNER_ERROR"),
    (FAIL_EXEC, _task(exit_code=137), STATIC_OK, REPORT_OK, "RUNNER_ERROR"),
    (OK_EXEC, _task(), STATIC_OK, None, "VERDICT_MISMATCH"),
    (OK_EXEC, _task(), STATIC_OK, _art(passed=False), "VERDICT_MISMATCH"),
    (OK_EXEC, _task(), _art(passed=False), REPORT_OK, "VERDICT_MISMATCH"),
    (FAIL_EXEC, _task(exit_code=10), STATIC_OK, None, "REPORT_INVALID"),
    (FAIL_EXEC, _task(exit_code=10), STATIC_OK, _art(passed=False), "NO_DIAGNOSTICS"),
])
def test_everything_but_a_clean_verdict_is_gate_unavailable(execution, tasks, static, report, reason):
    o = classify(execution, tasks, static, report, NONCE)
    assert o.passed is False and o.error_class == ErrorClass.GATE_UNAVAILABLE and o.reason == reason


def test_exit10_with_diagnostics_is_code_defect():
    o = classify(FAIL_EXEC, _task(exit_code=10), STATIC_OK, _art(passed=False, diags=[_diag()]), NONCE)
    assert o.error_class == ErrorClass.CODE_DEFECT and o.diagnostics[0]["code"] == "PY.TEST_FAILED"


def test_exit10_static_failure_without_report_is_code_defect():
    o = classify(FAIL_EXEC, _task(exit_code=10), _art(passed=False, diags=[_diag("PY.SYNTAX", "apps/a/main.py")]), None, NONCE)
    assert o.error_class == ErrorClass.CODE_DEFECT


def test_f2_dependency_diagnostics_need_a_reachable_index():
    report = _art(passed=False, diags=[_diag("REQ.UNRESOLVABLE", "apps/a/requirements.txt")])
    unknown = classify(FAIL_EXEC, _task(exit_code=10), _art(), report, NONCE)  # index_reachable not recorded
    down = classify(FAIL_EXEC, _task(exit_code=10), _art(index_reachable=False), report, NONCE)
    up = classify(FAIL_EXEC, _task(exit_code=10), STATIC_OK, report, NONCE)
    assert unknown.reason == down.reason == "INDEX_UNREACHABLE"
    assert unknown.error_class == down.error_class == ErrorClass.GATE_UNAVAILABLE
    assert up.error_class == ErrorClass.CODE_DEFECT


def test_f3_platform_owned_path_diagnostic_is_platform_defect():
    report = _art(passed=False, diags=[_diag(file="apps/a/main.py"), _diag(file="infra/modules/x/main.tf")])
    o = classify(FAIL_EXEC, _task(exit_code=10), STATIC_OK, report, NONCE,
                 platform_owned=lambda p: p.startswith("infra/modules/"))
    assert o.error_class == ErrorClass.PLATFORM_DEFECT


def test_exit12_timeout_with_diagnostics_is_code_defect():
    o = classify(FAIL_EXEC, _task(exit_code=12), STATIC_OK, _art(passed=False, diags=[_diag("PY.TEST_TIMEOUT")]), NONCE)
    assert o.error_class == ErrorClass.CODE_DEFECT


def test_untrusted_fields_are_capped():
    big = [dict(_diag(), message="m" * 5000) for _ in range(250)]
    o = classify(FAIL_EXEC, _task(exit_code=10), STATIC_OK, _art(passed=False, diags=big), NONCE)
    assert len(o.diagnostics) == 200 and len(o.diagnostics[0]["message"]) < 2100
    assert o.report["diagnostics_truncated"] is True


# ------------------------------------------------------------------ run() with fakes
CFG = QAJobConfig("p", "r", "qa-sandbox-test-runner", "bkt", "sa-castor-qa-sandbox@p.iam.gserviceaccount.com")
# Row L3-PRB-g (FD-4BR): dispatch also requires the egress contract (args + vpcAccess; tests/test_fd4br_qa_readiness.py).
JOB = {"template": {"template": {
    "serviceAccount": CFG.sandbox_sa, "timeout": "900s",
    "containers": [{"image": "i", "args": ["python3", "-m", "sandbox_job", "--index-url",
                                           "https://r-python.pkg.dev/p/castor-pypi-remote/simple/"]}],
    "vpcAccess": {"egress": "ALL_TRAFFIC", "networkInterfaces": [
        {"network": "projects/p/global/networks/castor-qa-sandbox",
         "subnetwork": "projects/p/regions/r/subnetworks/castor-qa-sandbox-r"}]},
}}}
EXEC_NAME = f"{CFG.job_path}/executions/e1"


class _Res:
    def __init__(self, status=200, payload=None):
        self.status_code, self._p = status, payload

    def json(self):
        return self._p


class FakeSession:
    def __init__(self, job=JOB, run_status=200, exec_doc=None, tasks=None, exec_name=EXEC_NAME):
        self.job, self.run_status, self.exec_doc, self.tasks, self.exec_name = job, run_status, exec_doc, tasks, exec_name
        self.posts, self.gets = [], []

    def get(self, url, **kw):
        self.gets.append(url)
        if url.endswith("/tasks"):
            return _Res(payload={"tasks": self.tasks})
        if "/executions/" in url:
            return _Res(payload=self.exec_doc)
        return _Res(payload=self.job)

    def post(self, url, json=None, **kw):
        self.posts.append((url, json))
        if url.endswith(":run"):
            return _Res(self.run_status, {"metadata": {"name": self.exec_name}})
        return _Res(payload={})


class FakeStore:
    def __init__(self):
        self.objs, self.signed = {}, []

    def upload(self, name, data, content_type):
        self.objs[name] = data

    def sign(self, name, method, ttl_s, headers=None):
        self.signed.append((name, method, ttl_s, headers))
        return f"https://signed/{name}?X-Goog-Signature=s"

    def download(self, name, max_bytes):
        return self.objs.get(name)


def _client(session, store, **kw):
    clock = {"t": 0.0}

    def tick(s):
        clock["t"] += s

    return QAJobClient(CFG, session, store, sleep=tick, clock=lambda: clock["t"], poll_interval_s=10, **kw)


def test_negative_run_stages_signs_and_passes():
    session = FakeSession(exec_doc=OK_EXEC, tasks=_task())
    store = FakeStore()
    client = _client(session, store)

    def post(url, json=None, **kw):
        session.posts.append((url, json))
        if url.endswith(":run"):
            env = {e["name"]: e["value"] for e in json["overrides"]["containerOverrides"][0]["env"]}
            prefix = env["QA_STATIC_PUT_URL"].split("https://signed/")[1].split("?")[0].rsplit("/", 1)[0]
            store.objs[f"{prefix}/static.json"] = _art(nonce=env["QA_NONCE"], index_reachable=True)
            store.objs[f"{prefix}/report.json"] = _art(nonce=env["QA_NONCE"], tests_total=1)
            assert env["QA_COMMIT_SHA"] == "a" * 40 and len(env["QA_SOURCE_SHA256"]) == 64
            assert json["overrides"]["taskCount"] == 1 and json["overrides"]["timeout"] == "900s"
            return _Res(200, {"metadata": {"name": EXEC_NAME}})
        return _Res(payload={})

    session.post = post
    o = client.run(tar_bytes=b"tgz", commit_sha="a" * 40, trace_id="tr-1", product_id="app", deadline=10_000)
    assert o.passed is True, o
    # create-only PUT URLs for both artifacts, GET for the source
    methods = sorted((m, bool(h and h.get("x-goog-if-generation-match") == "0")) for _, m, _, h in store.signed)
    assert methods == [("GET", False), ("PUT", True), ("PUT", True)]


@pytest.mark.parametrize("field,value", [
    ("serviceAccount", "sa-castor-developer@p.iam.gserviceaccount.com"),
    ("maxRetries", 3),
    ("timeout", "3600s"),
    ("containers", [{"image": "i", "env": [{"name": "PROJECT_ID", "value": "p"}]}]),
])
def test_h3_job_identity_drift_refuses_before_staging(field, value):
    job = json.loads(json.dumps(JOB))
    job["template"]["template"][field] = value
    store = FakeStore()
    with pytest.raises(GateUnavailableError) as e:
        _client(FakeSession(job=job), store).run(tar_bytes=b"x", commit_sha="a" * 40, trace_id="tr-1",
                                                product_id="app", deadline=10_000)
    assert e.value.reason == "QA_JOB_DRIFT"
    assert store.objs == {}  # no code staged for a drifted job


def test_run_api_error_is_unavailable():
    o = _client(FakeSession(run_status=403), FakeStore()).run(
        tar_bytes=b"x", commit_sha="a" * 40, trace_id="tr-1", product_id="app", deadline=10_000)
    assert o.error_class == ErrorClass.GATE_UNAVAILABLE and o.reason == "RUN_API"


def test_unexpected_execution_name_is_unavailable():
    o = _client(FakeSession(exec_name="projects/other/locations/r/jobs/j/executions/e"), FakeStore()).run(
        tar_bytes=b"x", commit_sha="a" * 40, trace_id="tr-1", product_id="app", deadline=10_000)
    assert o.reason == "RUN_API"


def test_deadline_cancels_execution():
    session = FakeSession(exec_doc={"runningCount": 1}, tasks=[])
    o = _client(session, FakeStore()).run(tar_bytes=b"x", commit_sha="a" * 40, trace_id="tr-1",
                                         product_id="app", deadline=100)
    assert o.reason == "DEADLINE"
    assert any(url.endswith(":cancel") for url, _ in session.posts)


def test_config_from_env_requires_every_setting():
    full = {"PROJECT_ID": "p", "REGION": "r", "QA_JOB_NAME": "j", "QA_STAGING_BUCKET": "b", "QA_SANDBOX_SA": "s"}
    assert QAJobConfig.from_env(full) is not None
    for k in full:
        assert QAJobConfig.from_env({**full, k: ""}) is None


def test_invalid_trace_id_rejected():
    from shared.path_safety import UnsafePathError

    with pytest.raises(UnsafePathError):
        _client(FakeSession(), FakeStore()).run(tar_bytes=b"x", commit_sha="a" * 40, trace_id="../x",
                                               product_id="app", deadline=10_000)


# REQUIREMENTS-GOOGLE-AUTH-REQUESTS: a non-blocking warning is never named as the cause of a failed QA run.
def _sev(code, severity):
    return {"tool": "t", "code": code, "severity": severity, "file": "apps/a/main.py", "line": 1, "message": f"{code} text"}


def test_headline_names_the_first_error_not_an_earlier_warning():
    static = _art(index_reachable=True, diags=[_sev("BANDIT.B113", "warning")])
    report = _art(passed=False, diags=[_sev("PY.IMPORT_FAILED", "error"), _sev("PY.TEST_FAILED", "error")])
    o = classify(FAIL_EXEC, _task(exit_code=10), static, report, NONCE)
    assert o.summary == "QA failed: 3 diagnostic(s); first: PY.IMPORT_FAILED PY.IMPORT_FAILED text"
    assert [d["code"] for d in o.diagnostics] == ["BANDIT.B113", "PY.IMPORT_FAILED", "PY.TEST_FAILED"]   # order kept


def test_headline_with_an_error_first_is_unchanged():
    report = _art(passed=False, diags=[_sev("PY.TEST_FAILED", "error"), _sev("BANDIT.B113", "warning")])
    o = classify(FAIL_EXEC, _task(exit_code=10), STATIC_OK, report, NONCE)
    assert o.summary == "QA failed: 2 diagnostic(s); first: PY.TEST_FAILED PY.TEST_FAILED text"


def test_negative_headline_falls_back_to_the_first_diagnostic_when_none_is_an_error():
    report = _art(passed=False, diags=[_sev("BANDIT.B113", "warning"), _sev("BANDIT.B310", "warning")])
    o = classify(FAIL_EXEC, _task(exit_code=10), STATIC_OK, report, NONCE)
    assert o.error_class == ErrorClass.CODE_DEFECT
    assert o.summary == "QA failed: 2 diagnostic(s); first: BANDIT.B113 BANDIT.B113 text"
