"""STAGE-JOB-RUNNER red team re-check (docs/planning/stage-job-runner-rt.md) G1 + G2.

G1: the fail-closed gates that are strict "on Cloud Run" stay closed inside the stage-runner Cloud Run Job, which has
CLOUD_RUN_JOB but no K_SERVICE: one helper (runtime_env.on_cloud_run), a pin that nothing else in the gateway reads
K_SERVICE, and the gateway's startup checks run by every execution before its stage.
G2: a jobs.run whose outcome was unknown may have created an execution and been re-dispatched: exactly one execution
of a job (the first to bind its request record) runs the stage and answers; any other exits without answering, and
the workflow's probe follows the bound execution.

Hermetic: fake Cloud Run starter (runs stage_runner.run in a thread), captured callback delivery, in-memory Firestore.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import re
import sys
import threading
import time

import pytest

from fd4f_support import FakeDB, gw  # noqa: F401  (gw is a fixture)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)

import runtime_env  # noqa: E402
import stage_jobs  # noqa: E402
import stage_runner  # noqa: E402
from test_stage_jobs import CB, Delivery, Runner, _dev, _fake_delete, _wire  # noqa: E402,F401

EXEC_PREFIX = "projects/p/locations/us-central1/jobs/stage-runner/executions/"


def _env(job_env, name):
    return dict(job_env, PROJECT_ID="p", REGION="us-central1", CLOUD_RUN_JOB="stage-runner",
                CLOUD_RUN_EXECUTION=name)


# ===================================================================================== G1
_READS = re.compile(r"""(getenv\(\s*["']K_SERVICE["']|environ\.get\(\s*["']K_SERVICE["']|environ\[\s*["']K_SERVICE["'])""")


def test_nothing_in_the_gateway_reads_k_service_outside_the_helper():
    """Pin: a new "on Cloud Run" gate must ask runtime_env.on_cloud_run() (service AND job). shared/ holds replicated
    copies (callbacks.py already checks both variables) and text about generated workloads."""
    offenders = []
    for root, dirs, files in os.walk(GW_DIR):
        dirs[:] = [d for d in dirs if d not in ("shared", "__pycache__", "tests")]
        for f in files:
            if f.endswith(".py") and not f.startswith("test_"):
                path = os.path.join(root, f)
                if _READS.search(open(path, encoding="utf-8").read()):
                    offenders.append(os.path.relpath(path, GW_DIR))
    assert offenders == ["runtime_env.py"], offenders


def test_helper_is_true_in_a_job_and_on_a_service_only(monkeypatch):
    for k in ("K_SERVICE", "CLOUD_RUN_JOB"):
        monkeypatch.delenv(k, raising=False)
    assert runtime_env.on_cloud_run() is False and stage_jobs.on_cloud_run() is False
    monkeypatch.setenv("CLOUD_RUN_JOB", "stage-runner")
    assert runtime_env.on_cloud_run() is True and stage_jobs.on_cloud_run() is True
    monkeypatch.delenv("CLOUD_RUN_JOB")
    monkeypatch.setenv("K_SERVICE", "orchestrator-gateway-service")
    assert runtime_env.on_cloud_run() is True


@pytest.fixture
def in_job(monkeypatch):
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.setenv("CLOUD_RUN_JOB", "stage-runner")


def test_startup_gate_refuses_test_mode_inside_the_job(gw, in_job, monkeypatch):
    monkeypatch.setenv("TEST_MODE", "true")
    with pytest.raises(RuntimeError, match="TEST_MODE"):
        gw.assert_pipeline_gates_ready()


def test_terraform_server_client_refuses_a_tokenless_call_inside_the_job(in_job):
    from developer_agent.stack_clients import HttpValidateClient
    with pytest.raises(RuntimeError, match="not an https Cloud Run URL"):
        HttpValidateClient(lambda: "http://10.0.0.1:8080")._headers("http://10.0.0.1:8080")


def test_negative_terraform_server_client_off_cloud_run_is_unchanged(monkeypatch):
    for k in ("K_SERVICE", "CLOUD_RUN_JOB"):
        monkeypatch.delenv(k, raising=False)
    from developer_agent.stack_clients import HttpValidateClient
    assert HttpValidateClient(lambda: "http://10.0.0.1:8080")._headers("http://10.0.0.1:8080") == {}


def test_job_runs_the_startup_checks_and_answers_a_failure_typed(gw, monkeypatch):
    """G1: TEST_MODE inside the job (CLOUD_RUN_JOB set) stops the stage before any work: 503 GATE_UNAVAILABLE
    STAGE_RUNNER_STARTUP_CHECK by callback."""
    ran = []
    monkeypatch.setattr(gw, "_developer_execute_body", lambda req: ran.append(1) or {"status": "SUCCESS"})
    d = Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch, run=False)
    c, _ = _wire(gw)
    _dev(c)
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.setenv("CLOUD_RUN_JOB", "stage-runner")
    monkeypatch.setenv("TEST_MODE", "true")
    monkeypatch.setattr(stage_jobs, "on_cloud_run", lambda: False)   # keep the loopback test callback deliverable
    rc = stage_runner.run(_env(runner.started[0], "e1"), gateway=gw, exit_fn=lambda c: None)
    assert rc == stage_runner.EXIT_LOAD_FAILED and not ran
    [sent] = d.sent
    assert sent["payload"]["http_status"] == 503
    assert sent["payload"]["body"]["reason"] == "STAGE_RUNNER_STARTUP_CHECK"


def test_negative_startup_checks_pass_off_cloud_run(gw, monkeypatch):
    for k in ("K_SERVICE", "CLOUD_RUN_JOB"):
        monkeypatch.delenv(k, raising=False)
    gw.assert_pipeline_gates_ready()   # local / tests: unchanged (returns)


def test_an_unnamed_execution_on_cloud_run_never_runs(gw, monkeypatch):
    ran = []
    monkeypatch.setattr(gw, "_developer_execute_body", lambda req: ran.append(1) or {"status": "SUCCESS"})
    d = Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch, run=False)
    c, _ = _wire(gw)
    _dev(c)
    monkeypatch.setenv("CLOUD_RUN_JOB", "stage-runner")
    assert stage_runner.run(runner.started[0], gateway=gw, exit_fn=lambda c: None) == stage_runner.EXIT_LOAD_FAILED
    assert not ran and d.sent == []


# ===================================================================================== G2
def _blocking_body(gw, monkeypatch, gate, runs):
    def body(req):
        runs.append(threading.current_thread().name)
        gate.wait(5)
        return {"status": "SUCCESS"}
    monkeypatch.setattr(gw, "_developer_execute_body", body)


@pytest.mark.parametrize("winner,loser", [("e1", "e2"), ("e2", "e1")])
def test_two_executions_of_one_job_exactly_one_runs_and_answers(gw, monkeypatch, winner, loser):
    gate, runs = threading.Event(), []
    _blocking_body(gw, monkeypatch, gate, runs)
    d = Delivery(monkeypatch)
    runner = Runner(gw, monkeypatch, run=False)
    c, db = _wire(gw)
    job_id = _dev(c).json()["job_id"]
    job_env = runner.started[0]
    exits = {}
    t = threading.Thread(target=lambda: exits.setdefault(winner, stage_runner.run(
        _env(job_env, winner), gateway=gw, exit_fn=lambda c: None)), daemon=True)
    t.start()
    end = time.monotonic() + 3
    while not runs and time.monotonic() < end:
        time.sleep(0.02)
    exits[loser] = stage_runner.run(_env(job_env, loser), gateway=gw, exit_fn=lambda c: None)
    assert exits[loser] == stage_runner.EXIT_NOT_OWNER and len(runs) == 1 and d.sent == []
    # the probe follows the bound execution: the loser's ended execution never reads as DEAD
    ended = {EXEC_PREFIX + loser: {"completionTime": "2026-11-14T00:00:00Z"}}
    state = stage_jobs.job_state(db, "tr-1", "developer", job_id, lambda n: ended.get(n, {}))
    assert state["state"] == "RUNNING" and state["run_execution"] == EXEC_PREFIX + winner
    gate.set()
    t.join(5)
    assert exits[winner] == stage_runner.EXIT_OK and len(d.sent) == 1 and len(runs) == 1
    rec = db.docs[f"pipeline_executions/tr-1/stage_job_requests/{job_id}"]
    assert rec["bound_execution"] == EXEC_PREFIX + winner


def test_unknown_start_outcome_then_retry_runs_the_stage_once(gw, monkeypatch):
    """jobs.run times out AFTER creating an execution that starts late (it has not bound the job when the retry
    comes); the workflow's dispatch retry starts a second one on the same record (never deleted); exactly one runs
    the stage and answers once. (Bound before the retry: N9, no spare is started; next test.)"""
    runs, d = [], Delivery(monkeypatch)
    monkeypatch.setattr(gw, "_developer_execute_body", lambda req: runs.append(1) or {"status": "SUCCESS"})
    c, db = _wire(gw)
    started, threads = [], []
    late = threading.Event()

    def start(job):
        n = len(started) + 1
        env = _env({stage_jobs.ENV_TRACE: job.trace_id, stage_jobs.ENV_STAGE: job.stage,
                    stage_jobs.ENV_JOB_ID: job.job_id}, f"e{n}")
        started.append(env)

        def execution():
            if n == 1:
                late.wait(5)   # the first execution starts only after the retry
            stage_runner.run(env, gateway=gw, exit_fn=lambda c: None)
        th = threading.Thread(target=execution, daemon=True)
        th.start()
        threads.append(th)
        if n == 1:
            raise stage_jobs.StageJobStartError("jobs.run request failed: ReadTimeout", http_status=0)
        return EXEC_PREFIX + f"e{n}"
    gw.app.dependency_overrides[gw.get_stage_job_starter] = lambda: start
    first = _dev(c)
    assert first.status_code == 503 and first.json()["reason"] == "STAGE_JOB_START_FAILED"
    ref = f"pipeline_executions/tr-1/stage_job_requests/{stage_jobs.job_id_for(CB)}"
    assert ref in db.docs                                 # the claim is kept, never deleted
    again = _dev(c)
    assert again.status_code == 202 and again.json()["duplicate"] is False
    late.set()
    for th in threads:
        th.join(5)
    assert len(started) == 2 and runs == [1] and len(d.sent) == 1
    assert db.docs[ref]["dispatch"] == "STARTED" and db.docs[ref]["redispatches"] == 1


def test_a_lost_started_record_does_not_hide_a_dead_job(gw, monkeypatch):
    """N5: the probe reads the bound execution even when the STARTED update was never written."""
    Delivery(monkeypatch)
    Runner(gw, monkeypatch, run=False)
    c, db = _wire(gw)
    job_id = _dev(c).json()["job_id"]
    ref = f"pipeline_executions/tr-1/stage_job_requests/{job_id}"
    db.docs[ref]["run_execution"] = None
    db.docs[ref]["bound_execution"] = EXEC_PREFIX + "e9"
    dead = stage_jobs.job_state(db, "tr-1", "developer", job_id,
                                lambda n: {"completionTime": "x"} if n == EXEC_PREFIX + "e9" else {})
    assert dead["state"] == "DEAD" and dead["run_execution"] == EXEC_PREFIX + "e9"


def test_answer_lock_is_reentrant_for_the_signal_handler():
    """N4: the SIGTERM handler runs on the main thread, possibly inside claim_answer."""
    job = stage_jobs.StageJob(job_id="a" * 32, stage="developer", trace_id="tr-1", product_id="app", callback_url=CB,
                              execution_id=None)
    with job._answer_lock:
        assert job.claim_answer() is True     # would deadlock with a plain Lock
    assert job.claim_answer() is False



def test_redispatch_starts_no_spare_when_the_unknown_start_already_bound(gw, monkeypatch):
    """N9: jobs.run timed out, but its execution started and bound the job before the retry: the retry starts
    nothing, answers 202 with the bound execution, and the stage runs once."""
    runs, d = [], Delivery(monkeypatch)
    gate = threading.Event()

    def body(req):
        runs.append(1)
        gate.wait(5)
        return {"status": "SUCCESS"}
    monkeypatch.setattr(gw, "_developer_execute_body", body)
    c, db = _wire(gw)
    started, threads = [], []

    def start(job):
        n = len(started) + 1
        env = _env({stage_jobs.ENV_TRACE: job.trace_id, stage_jobs.ENV_STAGE: job.stage,
                    stage_jobs.ENV_JOB_ID: job.job_id}, f"e{n}")
        started.append(env)
        th = threading.Thread(target=lambda: stage_runner.run(env, gateway=gw, exit_fn=lambda c: None), daemon=True)
        th.start()
        threads.append(th)
        end = time.monotonic() + 3
        while not runs and time.monotonic() < end:   # the execution binds and starts before the timeout answers
            time.sleep(0.02)
        raise stage_jobs.StageJobStartError("jobs.run request failed: ReadTimeout", http_status=0)
    gw.app.dependency_overrides[gw.get_stage_job_starter] = lambda: start
    assert _dev(c).status_code == 503
    again = _dev(c)
    assert again.status_code == 202 and again.json()["duplicate"] is True
    assert again.json()["run_execution"] == EXEC_PREFIX + "e1"
    assert len(started) == 1                                   # no spare execution
    ref = f"pipeline_executions/tr-1/stage_job_requests/{stage_jobs.job_id_for(CB)}"
    assert db.docs[ref]["dispatch"] == "STARTED" and db.docs[ref]["run_execution"] == EXEC_PREFIX + "e1"
    gate.set()
    for th in threads:
        th.join(5)
    assert runs == [1] and len(d.sent) == 1
