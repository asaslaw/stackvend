"""LONG-STAGE-CALLBACK (G6) + STAGE-JOB-RUNNER (G7, owner 11-13): architect / developer / QA run as one stage-runner
Cloud Run Job execution each and answer by a Workflows callback.

Plans: docs/planning/stage-deadline-and-callback-plan.md §4-5, docs/planning/stage-job-runner-plan.md. The gateway
validates and stores the request by reference, claims the job atomically (RT F2) and starts one execution; the job
(stage_runner.run) answers exactly what the synchronous route answers (status + JSON body), once, through
shared.callbacks.CallbackDeliveryClient; a duplicate submission starts nothing; a superseded, ended or interrupted
job writes nothing.

Hermetic: the Cloud Run Admin API is a fake starter that runs stage_runner.run in a thread (the "execution");
callback delivery is captured (no network); in-memory Firestore stand-in; loopback callback URLs.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import logging
import os
import sys
import threading
import time

import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from fd4f_support import FakeDB, gw  # noqa: F401  (gw is a fixture)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)

import stage_deadline as sdm  # noqa: E402
import stage_jobs  # noqa: E402
import stage_runner  # noqa: E402
from gate_errors import GateUnavailableError, StageAbandonedError  # noqa: E402
from stage_deadline import StageMode  # noqa: E402

CB = "http://127.0.0.1:9/cb-1"
CB2 = "http://127.0.0.1:9/cb-2"
WF_CB = ("https://workflowexecutions.googleapis.com/v1/projects/123/locations/us-central1/workflows/w/executions/"
         "exec-9/callbacks/cb-1")
EXEC = "projects/p/locations/us-central1/jobs/stage-runner/executions/stage-runner-x"


def _delete(self):
    self._db.docs.pop(self._path, None)


@pytest.fixture(autouse=True)
def _fake_delete(monkeypatch):
    """Firestore DocumentReference.delete() on the shared FakeDB document stand-in."""
    import fd4f_support
    monkeypatch.setattr(fd4f_support._DocRef, "delete", _delete, raising=False)


class Delivery:
    """Captures CallbackDeliveryClient.send_callback (the existing authenticated delivery)."""

    def __init__(self, monkeypatch, fail=False):
        self.sent, self.fail = [], fail
        monkeypatch.setattr(stage_jobs.CallbackDeliveryClient, "send_callback", staticmethod(self.send))

    def send(self, callback_url, payload, timeout=15, max_attempts=5):
        self.sent.append({"url": callback_url, "payload": payload, "timeout": timeout, "max_attempts": max_attempts})
        if self.fail:
            raise RuntimeError("callback endpoint unreachable")
        return {}

    def wait(self, n=1, timeout=5.0):
        end = time.monotonic() + timeout
        while len(self.sent) < n and time.monotonic() < end:
            time.sleep(0.02)
        assert len(self.sent) >= n, self.sent
        return self.sent


class Runner:
    """The fake Cloud Run Admin API: `start(job)` records the env overrides and runs stage_runner.run (the job's
    entry point) in a thread, as one execution would; `fail` makes jobs.run refuse."""

    def __init__(self, gw, monkeypatch, *, fail=None, run=True, release=""):
        self.gw, self.fail, self.run, self.release = gw, fail, run, release
        self.started, self.exits, self.threads = [], [], []
        gw.app.dependency_overrides[gw.get_stage_job_starter] = lambda: self.start

    def start(self, job):
        if self.fail is not None:
            raise stage_jobs.StageJobStartError(f"jobs.run answered HTTP {self.fail}", http_status=self.fail)
        env = {stage_jobs.ENV_TRACE: job.trace_id, stage_jobs.ENV_STAGE: job.stage, stage_jobs.ENV_JOB_ID: job.job_id}
        if self.release:
            env[stage_jobs.ENV_RELEASE] = self.release
        self.started.append(env)
        if self.run:
            # the execution starts after the dispatch answered (jobs.run returns before the container runs)
            t = threading.Thread(target=lambda: (time.sleep(0.05), self.exits.append(
                stage_runner.run(env, gateway=self.gw, exit_fn=lambda code: None))), daemon=True)
            t.start()
            self.threads.append(t)
        return f"{EXEC}-{len(self.started)}"

    def join(self, timeout=5.0):
        for t in self.threads:
            t.join(timeout)


def _wire(gw, db=None):
    db = db if db is not None else FakeDB()
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: db
    return TestClient(gw.app), db


def _dev(c, cb=CB, **extra):
    body = {"trace_id": "tr-1", "product_id": "app", "callback_url": cb}
    body.update(extra)
    return c.post("/agent/developer/execute-job", json=body)


# ===================================================================================== byte compatibility
@pytest.mark.parametrize("outcome", ["dict", "gate_error", "http_exception", "json_response"])
def test_negative_job_answer_equals_the_synchronous_answer(gw, monkeypatch, outcome):
    """The callback carries exactly the status and body the synchronous route returns for the same outcome."""
    def body(req):
        if outcome == "dict":
            return {"status": "SUCCESS", "branch_name": "castor/app-1", "files_committed": ["a.py"],
                    "commit_sha": "c" * 40, "files_count": 1}
        if outcome == "gate_error":
            raise GateUnavailableError("no VCS credential", reason="VCS_CREDENTIAL_UNAVAILABLE", stage="developer")
        if outcome == "http_exception":
            raise HTTPException(status_code=500, detail="Developer execution failed: boom")
        return JSONResponse(status_code=422, content={"status": "FAILED", "error_class": "CODE_DEFECT",
                                                      "stage": "developer", "diagnostics": [{"code": "X"}]})
    monkeypatch.setattr(gw, "_developer_execute_body", body)
    d = Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch)
    c, _ = _wire(gw)
    sync = c.post("/agent/developer/execute", json={"trace_id": "tr-1", "product_id": "app"})
    r = _dev(c)
    assert r.status_code == 202 and r.json()["status"] == "ACCEPTED" and r.json()["duplicate"] is False
    assert r.json()["run_execution"] == f"{EXEC}-1"
    [sent] = d.wait()
    runner.join()
    assert sent["url"] == CB
    payload = sent["payload"]
    assert payload["http_status"] == sync.status_code and payload["body"] == sync.json()
    assert payload["stage"] == "developer" and payload["trace_id"] == "tr-1" and payload["job_id"] == r.json()["job_id"]
    assert runner.exits == [stage_runner.EXIT_OK]


def test_architect_and_qa_jobs_answer_by_callback(gw, monkeypatch):
    monkeypatch.setattr(gw, "_architect_decompose_body", lambda req: {"status": "SUCCESS", "task_dag": []})
    monkeypatch.setattr(gw, "_qa_verify_body", lambda req, *a, **k: {"status": "SUCCESS", "passed": True,
                                                                       "mode": k.get("mode")})
    d = Delivery(monkeypatch)
    Runner(gw, monkeypatch)
    c, _ = _wire(gw)
    a = c.post("/agent/architect/decompose-job", json={"trace_id": "tr-1", "product_id": "app", "callback_url": CB})
    q = c.post("/agent/qa/verify-job", json={"trace_id": "tr-1", "product_id": "app", "branch_name": "castor/app-1",
                                             "callback_url": CB2})
    assert a.status_code == 202 and q.status_code == 202
    sent = {s["url"]: s["payload"] for s in d.wait(2)}
    assert sent[CB]["stage"] == "architect" and sent[CB]["body"]["task_dag"] == []
    assert sent[CB2]["stage"] == "qa" and sent[CB2]["body"]["passed"] is True
    assert sent[CB2]["body"]["mode"] == "CALLBACK JOB"


def test_request_goes_by_reference_and_the_job_runs_under_the_callback_budget(gw, monkeypatch):
    seen = {}

    def body(req):
        sd = sdm.current()
        seen["mode"], seen["budget"], seen["spec"] = sd.budget.mode, sd.budget.budget_s, req.spec_text
        return {"status": "SUCCESS"}
    monkeypatch.setattr(gw, "_developer_execute_body", body)
    d = Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch)
    c, db = _wire(gw)
    spec = "x" * 300_000                                   # far over any env override limit
    _dev(c, spec_text=spec)
    d.wait()
    runner.join()
    env = runner.started[0]
    assert set(env) == {stage_jobs.ENV_TRACE, stage_jobs.ENV_STAGE, stage_jobs.ENV_JOB_ID}   # references only
    assert sum(len(v) for v in env.values()) < 200
    assert seen == {"mode": StageMode.CALLBACK, "budget": 3600, "spec": spec}             # never truncated
    rec = db.docs["pipeline_executions/tr-1/stage_jobs/developer"]
    assert rec["status"] == "DELIVERED" and rec["http_status"] == 200 and rec["job_id"] == stage_jobs.job_id_for(CB)
    req = db.docs[f"pipeline_executions/tr-1/stage_job_requests/{stage_jobs.job_id_for(CB)}"]
    assert req["answer"] == "DELIVERED" and req["request_json"] is None and req["callback_url"] is None


def test_deadline_counts_from_accepted_at_not_from_the_job_start(gw, monkeypatch):
    """RT §6.4: a job that starts late does not get a fresh budget."""
    seen = {}
    monkeypatch.setattr(gw, "_developer_execute_body",
                        lambda req: seen.setdefault("elapsed", sdm.current().elapsed_s()) and {"status": "SUCCESS"})
    d = Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch, run=False)
    c, db = _wire(gw)
    _dev(c)
    ref = f"pipeline_executions/tr-1/stage_job_requests/{stage_jobs.job_id_for(CB)}"
    db.docs[ref]["accepted_epoch"] -= 120                  # accepted two minutes before the job started
    assert stage_runner.run(runner.started[0], gateway=gw, exit_fn=lambda c: None) == stage_runner.EXIT_OK
    assert d.sent and seen["elapsed"] >= 119


def test_request_over_the_store_limit_is_refused_typed_never_truncated(gw, monkeypatch):
    runner = Runner(gw, monkeypatch)
    c, db = _wire(gw)
    r = _dev(c, spec_text="x" * (stage_jobs.MAX_REQUEST_BYTES + 10))
    assert r.status_code == 409 and r.json()["reason"] == "STAGE_REQUEST_TOO_LARGE"
    assert runner.started == [] and not [k for k in db.docs if "stage_job" in k]


# ===================================================================================== refusals at dispatch
def test_callback_url_outside_the_platform_is_refused_typed(gw, monkeypatch):
    runner = Runner(gw, monkeypatch)
    c, _ = _wire(gw)
    r = _dev(c, cb="https://evil.example.com/cb")
    assert r.status_code == 409 and r.json()["error_class"] == "CONTRACT_VIOLATION"
    assert r.json()["reason"] == "CALLBACK_URL_REJECTED" and runner.started == []


def test_loopback_callback_is_refused_on_cloud_run(gw, monkeypatch):
    """RT S5."""
    runner = Runner(gw, monkeypatch)
    c, _ = _wire(gw)
    monkeypatch.setenv("K_SERVICE", "orchestrator-gateway-service")
    r = _dev(c)
    assert r.status_code == 409 and r.json()["reason"] == "CALLBACK_URL_REJECTED" and runner.started == []


def test_no_job_store_is_gate_unavailable(gw, monkeypatch):
    runner = Runner(gw, monkeypatch)
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: None
    r = _dev(TestClient(gw.app))
    assert r.status_code == 503 and r.json()["reason"] == "STAGE_JOB_STORE" and runner.started == []


def test_job_request_needs_a_valid_trace_and_callback(gw, monkeypatch):
    Runner(gw, monkeypatch)
    c, _ = _wire(gw)
    assert c.post("/agent/developer/execute-job", json={"product_id": "app", "callback_url": CB}).status_code == 422
    assert c.post("/agent/developer/execute-job", json={"trace_id": "tr-1", "product_id": "app"}).status_code == 422
    assert c.post("/agent/developer/execute-job", json={"trace_id": "../x", "product_id": "app",
                                                        "callback_url": CB}).status_code == 422


@pytest.mark.parametrize("http_status", [403, 429, 0])
def test_failed_start_is_typed_and_releases_the_claim_so_a_retry_starts_it(gw, monkeypatch, http_status):
    """RT §6.2: 202 only when the execution exists; a refused start (permission, quota, no answer) is a typed 503
    at dispatch and the dispatch retry (http.default_retry) can start it."""
    monkeypatch.setattr(gw, "_developer_execute_body", lambda req: {"status": "SUCCESS"})
    d = Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch, fail=http_status)
    c, db = _wire(gw)
    r = _dev(c)
    assert r.status_code == 503, r.text
    assert r.json()["error_class"] == "GATE_UNAVAILABLE" and r.json()["reason"] == "STAGE_JOB_START_FAILED"
    assert r.json()["stage"] == "developer"
    assert db.docs["pipeline_executions/tr-1/stage_jobs/developer"]["status"] == "START_FAILED"
    runner.fail = None
    again = _dev(c)
    assert again.status_code == 202 and again.json()["duplicate"] is False
    d.wait()
    assert len(runner.started) == 1


# ===================================================================================== idempotency, supersede
def test_duplicate_submission_runs_once(gw, monkeypatch):
    runs, gate = [], threading.Event()

    def body(req):
        runs.append(1)
        gate.wait(5)
        return {"status": "SUCCESS"}
    monkeypatch.setattr(gw, "_developer_execute_body", body)
    d = Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch)
    c, _ = _wire(gw)
    first, again = _dev(c), _dev(c)
    assert first.json()["duplicate"] is False and again.json()["duplicate"] is True
    gate.set()
    d.wait()
    runner.join()
    third = _dev(c)   # after the job answered: the claim stays, nothing new starts
    assert third.json()["duplicate"] is True
    assert runs == [1] and len(d.sent) == 1 and len(runner.started) == 1


def test_claim_is_atomic_two_concurrent_dispatches_start_one_execution(gw, monkeypatch):
    """RT F2: two dispatch attempts of one callback URL that read 'no job' at the same moment: create() lets one
    through; the other waits for STARTED and answers duplicate."""
    monkeypatch.setattr(gw, "_developer_execute_body", lambda req: {"status": "SUCCESS"})
    Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch, run=False)
    slow = threading.Event()
    real_start = runner.start

    def slow_start(job):
        slow.wait(2)
        return real_start(job)
    gw.app.dependency_overrides[gw.get_stage_job_starter] = lambda: slow_start
    c, _ = _wire(gw)
    out = []
    ts = [threading.Thread(target=lambda: out.append(_dev(c).json())) for _ in range(2)]
    for t in ts:
        t.start()
    time.sleep(0.3)
    slow.set()
    for t in ts:
        t.join(10)
    assert sorted(o["duplicate"] for o in out) == [False, True]
    assert len(runner.started) == 1


def test_duplicate_while_the_first_attempt_is_still_starting_is_typed_pending(gw, monkeypatch):
    runner = Runner(gw, monkeypatch, run=False)
    c, db = _wire(gw)
    ref = f"pipeline_executions/tr-1/stage_job_requests/{stage_jobs.job_id_for(CB)}"
    db.docs[ref] = {"job_id": stage_jobs.job_id_for(CB), "dispatch": "DISPATCHING"}
    with pytest.raises(GateUnavailableError) as e:
        stage_jobs.submit("developer", trace_id="tr-1", product_id="app", callback_url=CB, request={}, db=db,
                          start=runner.start, wait_s=0.2, sleep=lambda s: time.sleep(0.05))
    assert e.value.reason == "STAGE_JOB_DISPATCH_PENDING" and runner.started == []
    assert c is not None


def test_a_newer_job_supersedes_the_older_one_before_its_commit(gw, monkeypatch):
    gate, outcomes = threading.Event(), {}

    def body(req):
        if req.callback_url == CB:
            gate.wait(5)
            try:
                sdm.guard_side_effect("developer.commit", reserve_s=0)
                outcomes["old"] = "COMMITTED"
            except StageAbandonedError as e:
                outcomes["old"] = e.reason
                raise
        return {"status": "SUCCESS"}
    monkeypatch.setattr(gw, "_developer_execute_body", body)
    d = Delivery(monkeypatch)
    Runner(gw, monkeypatch)
    c, db = _wire(gw)
    _dev(c, cb=CB)
    time.sleep(0.3)
    _dev(c, cb=CB2)                     # QA retry / relaunch path: a newer job owns (trace, developer)
    gate.set()
    sent = {s["url"]: s["payload"] for s in d.wait(2)}
    assert outcomes["old"] == "SUPERSEDED"
    assert sent[CB]["http_status"] == 409 and sent[CB]["body"]["error_class"] == "STAGE_ABANDONED"
    assert sent[CB2]["http_status"] == 200
    assert db.docs["pipeline_executions/tr-1/stage_jobs/developer"]["job_id"] == stage_jobs.job_id_for(CB2)


def test_ended_run_stops_the_job_before_its_commit(gw, monkeypatch):
    gate, outcome = threading.Event(), []

    def body(req):
        gate.wait(5)
        sdm.guard_side_effect("developer.commit", reserve_s=0)
        outcome.append("COMMITTED")
        return {"status": "SUCCESS"}
    monkeypatch.setattr(gw, "_developer_execute_body", body)
    d = Delivery(monkeypatch)
    Runner(gw, monkeypatch)
    c, db = _wire(gw)
    _dev(c)
    db.docs["pipeline_executions/tr-1"] = {"status": "ABORTED"}   # the operator aborted / the cascade cancelled
    gate.set()
    [sent] = d.wait()
    assert not outcome and sent["payload"]["body"]["reason"] == "RUN_ENDED"


# ===================================================================================== failures
def test_late_job_answers_typed_by_callback(gw, monkeypatch):
    monkeypatch.setattr(sdm, "ANSWER_GRACE_S", 0.3)
    monkeypatch.setitem(sdm.STAGE_BUDGETS, ("developer", StageMode.CALLBACK),
                        sdm.StageBudget("developer", StageMode.CALLBACK, 3, 2))
    monkeypatch.setattr(gw, "_developer_execute_body", lambda req: time.sleep(3) or {"status": "SUCCESS"})
    d = Delivery(monkeypatch)
    Runner(gw, monkeypatch)
    c, _ = _wire(gw)
    _dev(c)
    [sent] = d.wait(timeout=4)
    assert sent["payload"]["http_status"] == 504
    assert sent["payload"]["body"]["error_class"] == "STAGE_DEADLINE_EXCEEDED"
    assert sent["payload"]["body"]["stage"] == "developer"


def test_crash_outside_the_mapping_is_a_typed_callback(gw, monkeypatch):
    def boom(job, request):
        raise RuntimeError("mapper bug")
    monkeypatch.setattr(gw, "run_stage_job_here", boom)
    d = Delivery(monkeypatch)
    Runner(gw, monkeypatch)
    c, _ = _wire(gw)
    _dev(c)
    [sent] = d.wait()
    assert sent["payload"]["http_status"] == 500 and sent["payload"]["body"]["error_class"] == "UNHANDLED"
    assert sent["payload"]["body"]["reason"] == "STAGE_JOB_CRASHED"


def test_delivery_failure_is_logged_and_recorded_never_raised(gw, monkeypatch, caplog):
    monkeypatch.setattr(gw, "_developer_execute_body", lambda req: {"status": "SUCCESS"})
    d = Delivery(monkeypatch, fail=True)
    runner = Runner(gw, monkeypatch)
    c, db = _wire(gw)
    with caplog.at_level(logging.CRITICAL, logger="castor.stage_jobs"):
        _dev(c)
        d.wait()
        runner.join()
    assert db.docs["pipeline_executions/tr-1/stage_jobs/developer"]["status"] == "CALLBACK_FAILED"
    assert "STAGE_CALLBACK_UNDELIVERED" in caplog.text
    assert d.sent[0]["max_attempts"] == stage_jobs.CALLBACK_MAX_ATTEMPTS
    assert runner.exits == [stage_runner.EXIT_UNDELIVERED]
    state = stage_jobs.job_state(db, "tr-1", "developer", stage_jobs.job_id_for(CB), lambda n: {})
    assert state["state"] == "DEAD" and state["reason"] == "CALLBACK_UNDELIVERED"


def test_sigterm_in_the_job_delivers_interrupted_synchronously_before_exit(gw, monkeypatch):
    """RT R2: the handler itself delivers (no thread, no shutdown race), abandons the stage, then exits."""
    gate, outcome, exits = threading.Event(), [], []
    import signal

    def body(req):
        gate.wait(5)
        try:
            sdm.guard_side_effect("developer.commit", reserve_s=0)
            outcome.append("COMMITTED")
        except StageAbandonedError as e:
            outcome.append(e.reason)
        return {"status": "SUCCESS"}
    monkeypatch.setattr(gw, "_developer_execute_body", body)
    d = Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch, run=False)
    installed = {}
    monkeypatch.setattr(signal, "signal", lambda s, h: installed.setdefault(s, h))
    c, db = _wire(gw)
    _dev(c)
    monkeypatch.setattr(stage_runner.threading, "main_thread", lambda: threading.current_thread())
    t = threading.Thread(target=lambda: stage_runner.run(runner.started[0], gateway=gw, exit_fn=exits.append),
                         daemon=True)
    t.start()
    end = time.monotonic() + 3
    while signal.SIGTERM not in installed and time.monotonic() < end:
        time.sleep(0.02)
    time.sleep(0.1)
    installed[signal.SIGTERM](signal.SIGTERM, None)        # what Cloud Run sends at task timeout / cancel
    assert exits == [stage_runner.EXIT_INTERRUPTED]
    assert len(d.sent) == 1                                 # delivered inside the handler, before the exit
    p = d.sent[0]["payload"]
    assert p["http_status"] == 503 and p["body"]["error_class"] == "STAGE_INTERRUPTED"
    assert d.sent[0]["max_attempts"] == 1
    gate.set()
    t.join(5)
    assert outcome == ["SHUTDOWN"] and len(d.sent) == 1     # nothing written, no second answer


def test_image_skew_is_refused_typed_before_any_work(gw, monkeypatch):
    ran = []
    monkeypatch.setattr(gw, "_developer_execute_body", lambda req: ran.append(1))
    monkeypatch.setattr(stage_runner.release_info, "log_release",
                        lambda c: {"release": "0.9.3", "commit": "b" * 40, "built_at": "2026-11-13T10:00:00Z"})
    d = Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch, release="0.9.3|" + "a" * 40 + "|2026-11-13T09:00:00Z")
    c, _ = _wire(gw)
    _dev(c)
    [sent] = d.wait()
    runner.join()
    assert sent["payload"]["http_status"] == 503
    assert sent["payload"]["body"]["reason"] == "STAGE_RUNNER_IMAGE_SKEW" and not ran


def test_corrupt_request_is_a_typed_contract_violation(gw, monkeypatch):
    d = Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch, run=False)
    c, db = _wire(gw)
    _dev(c)
    db.docs[f"pipeline_executions/tr-1/stage_job_requests/{stage_jobs.job_id_for(CB)}"]["request_json"] = "{}"
    assert stage_runner.run(runner.started[0], gateway=gw, exit_fn=lambda c: None) == stage_runner.EXIT_LOAD_FAILED
    [sent] = d.sent
    assert sent["payload"]["http_status"] == 409 and sent["payload"]["body"]["reason"] == "STAGE_REQUEST_CORRUPT"


def test_missing_request_exits_nonzero_and_the_probe_reports_it_dead(gw, monkeypatch):
    d = Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch, run=False)
    c, db = _wire(gw)
    _dev(c)
    job_id = stage_jobs.job_id_for(CB)
    db.docs.pop(f"pipeline_executions/tr-1/stage_job_requests/{job_id}")
    assert stage_runner.run(runner.started[0], gateway=gw, exit_fn=lambda c: None) == stage_runner.EXIT_LOAD_FAILED
    assert d.sent == []
    assert stage_jobs.job_state(db, "tr-1", "developer", job_id, lambda n: {})["state"] == "DEAD"


# ===================================================================================== the workflow's probe
def test_state_route_reports_running_answered_and_dead(gw, monkeypatch):
    monkeypatch.setattr(gw, "_developer_execute_body", lambda req: {"status": "SUCCESS"})
    Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch, run=False)
    c, db = _wire(gw)
    execution = {"name": "x"}
    gw.app.dependency_overrides[gw.get_stage_execution_reader] = lambda: (lambda name: dict(execution))
    job_id = _dev(c).json()["job_id"]
    q = {"trace_id": "tr-1", "stage": "developer", "job_id": job_id}
    assert c.get("/agent/stage-job/state", params=q).json()["state"] == "RUNNING"
    execution["completionTime"] = "2026-11-13T10:00:00Z"   # killed (OOM / SIGKILL): ended, no answer
    dead = c.get("/agent/stage-job/state", params=q).json()
    assert dead["state"] == "DEAD" and dead["reason"] == "EXECUTION_ENDED_WITHOUT_ANSWER"
    stage_runner.run(runner.started[0], gateway=gw, exit_fn=lambda c: None)
    assert c.get("/agent/stage-job/state", params=q).json()["state"] == "ANSWERED"
    assert c.get("/agent/stage-job/state", params={**q, "job_id": "zz"}).status_code == 400


def test_state_read_error_is_unknown_never_dead(gw, monkeypatch):
    runner = Runner(gw, monkeypatch, run=False)
    c, db = _wire(gw)

    def unreadable(name):
        raise RuntimeError("503 from run.googleapis.com")
    gw.app.dependency_overrides[gw.get_stage_execution_reader] = lambda: unreadable
    job_id = _dev(c).json()["job_id"]
    s = c.get("/agent/stage-job/state", params={"trace_id": "tr-1", "stage": "developer", "job_id": job_id}).json()
    assert s["state"] == "UNKNOWN" and runner.started


# ===================================================================================== misc
def test_execution_id_from_a_workflows_callback_url():
    assert stage_jobs.execution_id_of(WF_CB) == "exec-9"
    assert stage_jobs.execution_id_of(CB) is None
    assert stage_jobs.job_id_for(CB) != stage_jobs.job_id_for(CB2) and len(stage_jobs.job_id_for(CB)) == 32


def test_health_announces_workflow_contract_3_and_the_stage_job_switch(gw, monkeypatch):
    h = TestClient(gw.app).get("/health").json()
    assert h["workflow_contract"] == 3 and h["stage_jobs_enabled"] is stage_jobs.STAGE_JOBS_DEFAULT_ENABLED is True
    monkeypatch.setenv("STAGE_JOBS_ENABLED", "false")
    assert TestClient(gw.app).get("/health").json()["stage_jobs_enabled"] is False


def test_run_api_starter_sends_references_only_and_checks_the_execution_name():
    class Res:
        def __init__(self, code, body):
            self.status_code, self._body, self.text = code, body, json.dumps(body)

        def json(self):
            return self._body

    class Sess:
        def __init__(self, res):
            self.res, self.calls = res, []

        def post(self, url, json=None, timeout=None):
            self.calls.append((url, json, timeout))
            return self.res
    job = stage_jobs.StageJob(job_id="a" * 32, stage="qa", trace_id="tr-1", product_id="app", callback_url=CB,
                              execution_id=None)
    ok = Sess(Res(200, {"metadata": {"name": "projects/p/locations/r/jobs/stage-runner/executions/e1"}}))
    start = stage_jobs.run_api_starter("p", "r", session_factory=lambda: ok, expected_release="0.9.3|c|t")
    assert start(job) == "projects/p/locations/r/jobs/stage-runner/executions/e1"
    url, body, _ = ok.calls[0]
    assert url == "https://run.googleapis.com/v2/projects/p/locations/r/jobs/stage-runner:run"
    env = {e["name"]: e["value"] for e in body["overrides"]["containerOverrides"][0]["env"]}
    assert env == {"STAGE_JOB_TRACE_ID": "tr-1", "STAGE_JOB_STAGE": "qa", "STAGE_JOB_ID": "a" * 32,
                   "STAGE_JOB_EXPECTED_RELEASE": "0.9.3|c|t"}
    for res in (Res(403, {"error": "denied"}), Res(200, {"metadata": {"name": "projects/p/elsewhere"}})):
        with pytest.raises(stage_jobs.StageJobStartError):
            stage_jobs.run_api_starter("p", "r", session_factory=lambda res=res: Sess(res))(job)


def test_gateway_service_no_longer_runs_stage_work_or_hooks_sigterm():
    """STAGE-JOB-RUNNER: the gateway only dispatches; no stage thread and no SIGTERM hook in the service."""
    src = open(os.path.join(GW_DIR, "main.py"), encoding="utf-8").read()
    assert "install_sigterm_hook" not in src and "interrupt_all" not in src
    assert not hasattr(stage_jobs, "running_jobs")


# ===================================================================================== typed QA stops (provenance)
@pytest.mark.parametrize("kind", ["platform_rendered", "unowned"])
def test_the_qa_routing_stops_keep_class_reason_and_stage_through_the_job(gw, monkeypatch, kind):
    """PLATFORM-RENDERED-FINDING (PLATFORM_DEFECT) and QA-FINDING-ON-UNOWNED-FILE (OPERATOR_ACTION_REQUIRED) are raised
    by the developer dispatch: the job's callback carries exactly the synchronous typed body (class, reason, stage)."""
    from developer_agent import qa_repair as QR
    if kind == "platform_rendered":
        plan = QR.QARepairPlan(QR.STOP, QR.PLATFORM_RENDERED_REASON, 0, "a" * 40,
                               stop_files=("infra/workload/services.tf",))
        outcome, want = None, ("PLATFORM_DEFECT", QR.PLATFORM_RENDERED_REASON)
    else:
        plan = QR.QARepairPlan(QR.REGENERATE, QR.NOT_ON_A_DRAFT_FILE, 1, "a" * 40, off_draft_files=("tests/t.py",))
        outcome = {"verdict": QR.STOP, "reason": QR.UNOWNED_FILE_REASON, "files": [
            {"file": "tests/t.py", "owner": "UNKNOWN", "cleanup": "NOT_PLATFORM_WRITTEN", "stop": QR.STOP_RECURRED,
             "blocked_by": None, "sha256": "0" * 64, "unchanged_on_default_branch": True, "first_failure": False}]}
        want = ("OPERATOR_ACTION_REQUIRED", QR.UNOWNED_FILE_REASON)

    def body(req):
        raise QR.stop_error(plan, "app", {"diagnostics": []}, outcome)
    monkeypatch.setattr(gw, "_developer_execute_body", body)
    d = Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch)
    c, _ = _wire(gw)
    sync = c.post("/agent/developer/execute", json={"trace_id": "tr-1", "product_id": "app"})
    _dev(c)
    [sent] = d.wait()
    runner.join()
    payload = sent["payload"]
    assert payload["http_status"] == sync.status_code and payload["body"] == sync.json()
    assert (payload["body"]["error_class"], payload["body"]["reason"], payload["body"]["stage"]) == want + ("qa",)
