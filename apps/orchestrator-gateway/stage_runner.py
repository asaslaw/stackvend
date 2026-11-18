"""STAGE-JOB-RUNNER (G7, owner 11-13): the entry point of the `stage-runner` Cloud Run Job (`python3 -m stage_runner`).

One execution runs ONE stage request (architect, developer or QA) that the gateway accepted (stage_jobs.submit) and
answers the workflow by callback. The job runs the gateway's own image (scripts/deploy-services.sh and the upgrader
keep the two identical; the release check below refuses a skewed pair), so the stage code, the deadline (G5), the
orphan guard and the typed answers are exactly the gateway's.

Inputs (env overrides of this execution, set by the gateway): STAGE_JOB_TRACE_ID, STAGE_JOB_STAGE, STAGE_JOB_ID and
STAGE_JOB_EXPECTED_RELEASE. The request itself is read by reference from
`pipeline_executions/{trace}/stage_job_requests/{job_id}` (never passed through env: size limits).

Order of one execution:
1. Load the request (a missing / corrupt record is a typed CONTRACT_VIOLATION by callback when the callback URL is
   readable, else a non-zero exit that the workflow's probe reports as STAGE_INTERRUPTED within one await slice).
2. Release check: the gateway's release != this image's release -> 503 GATE_UNAVAILABLE STAGE_RUNNER_IMAGE_SKEW by
   callback, nothing run.
3. SIGTERM handler (task timeout, execution cancel): the stage is abandoned and STAGE_INTERRUPTED is delivered
   synchronously before the process exits (red team R2).
4. Heartbeat: `last_heartbeat_at` on the run record every HEARTBEAT_S while the stage runs (red team S7).
5. The stage body under its CALLBACK deadline counted from the job's accepted_at, mapped to exactly the synchronous
   (status, body), delivered once. Exit 0 when delivered, 3 when the answer could not be delivered (recorded
   CALLBACK_FAILED), 4 when the job could not load, 143 after SIGTERM. The job has max_retries = 0: a retry would
   repeat LLM spend and could commit twice; the workflow owns retries.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

import release_info
import runtime_env
import stage_jobs
from gate_errors import ContractViolationError, GateUnavailableError

logger = logging.getLogger("castor.stage_runner")

COMPONENT = "stage-runner"
EXIT_OK = 0
EXIT_UNDELIVERED = 3
EXIT_LOAD_FAILED = 4
EXIT_INTERRUPTED = 143
EXIT_NOT_OWNER = 0      # another execution runs this job (red team G2): nothing to do, not a failure
HEARTBEAT_S = 300.0


def execution_name(env: Mapping[str, str]) -> str:
    """This execution's full Cloud Run name (the form jobs.run returns). Off Cloud Run (tests, local runs) without the
    Cloud Run variables: a local name unique to this process. "" on Cloud Run when a part is missing."""
    parts = [env.get(k, "") for k in ("PROJECT_ID", "REGION", "CLOUD_RUN_JOB", "CLOUD_RUN_EXECUTION")]
    if all(parts):
        return "projects/{}/locations/{}/jobs/{}/executions/{}".format(*parts)
    if runtime_env.on_cloud_run():
        return ""
    return f"local/{os.getpid()}/{threading.get_ident()}/{id(env)}"


def _crash_answer(job: stage_jobs.StageJob, e: BaseException) -> stage_jobs.Answer:
    return 500, {"status": "FAILED", "passed": False, "error_class": "UNHANDLED", "stage": job.stage,
                 "reason": "STAGE_JOB_CRASHED", "summary": f"{job.stage} job crashed: {type(e).__name__}: {e}",
                 "errors": [f"{type(e).__name__}: {e}"], "diagnostics": []}


def _heartbeat(db: Any, job: stage_jobs.StageJob, stop: threading.Event, interval_s: float) -> None:
    """S7: the run record stays 'active' for the Control Center's silence rule while the stage runs. update() only:
    a deleted run record is never re-created."""
    while not stop.wait(interval_s):
        try:
            db.collection("pipeline_executions").document(job.trace_id).update(
                {"last_heartbeat_at": datetime.now(timezone.utc).isoformat()})
        except Exception as e:  # noqa: BLE001 - a heartbeat never stops a stage
            logger.warning(f"stage-runner heartbeat for {job.trace_id} not written: {type(e).__name__}: {e}")


def install_sigterm(job: stage_jobs.StageJob, db: Any, exit_fn: Any = os._exit) -> None:
    """Main thread only. On SIGTERM: when the job has not answered yet, abandon the stage and deliver
    STAGE_INTERRUPTED now (synchronously, about 5 s), then exit. When the main thread is already delivering the
    stage's own answer, return and let it finish inside the grace."""
    def handler(signum: int, frame: Any) -> None:
        if job.answered:
            logger.warning("stage-runner: SIGTERM while the answer is being delivered; finishing the delivery")
            return
        delivered = stage_jobs.interrupt(job, db=db)
        logger.warning(f"STAGE_INTERRUPTED: {job.stage} job {job.job_id} (trace {job.trace_id}) stopped on SIGTERM; "
                       f"answer {'delivered' if delivered else 'NOT delivered'}")
        logging.shutdown()
        exit_fn(EXIT_INTERRUPTED)

    signal.signal(signal.SIGTERM, handler)


def run(env: Mapping[str, str], gateway: Any = None, *, heartbeat_s: float = HEARTBEAT_S,
        exit_fn: Any = os._exit) -> int:
    """One stage-runner execution. `gateway` is the gateway module (tests pass the fixture's)."""
    release = release_info.log_release("stage-runner")   # COMPONENT (literal: tests/test_sat11_release_record.py)
    trace_id, stage, job_id = (env.get(stage_jobs.ENV_TRACE, ""), env.get(stage_jobs.ENV_STAGE, ""),
                               env.get(stage_jobs.ENV_JOB_ID, ""))
    if not (trace_id and stage and job_id):
        logger.critical(f"stage-runner: missing {stage_jobs.ENV_TRACE} / {stage_jobs.ENV_STAGE} / "
                        f"{stage_jobs.ENV_JOB_ID}; nothing to run (the workflow's probe ends the stage)")
        return EXIT_LOAD_FAILED
    if gateway is None:
        import main as gateway  # noqa: PLC0415 - the gateway module: the same stage bodies and dependencies
    db = gateway._resolved_dependency(gateway.get_governance_db)

    try:
        job, request = stage_jobs.load_job(db, trace_id, stage, job_id)
    except stage_jobs.StageJobLoadError as e:
        logger.critical(f"stage-runner: {stage} job {job_id} (trace {trace_id}) cannot load its request: "
                        f"{e.reason}: {e}")
        if e.callback_url:
            job = stage_jobs.StageJob(job_id=job_id, stage=stage, trace_id=trace_id, product_id="",
                                      callback_url=e.callback_url, execution_id=None)
            err = ContractViolationError(f"{stage} job could not read its request: {e}", reason=e.reason,
                                         stage=stage)
            stage_jobs.deliver(job, err.http_status, err.to_body(), db=db)
        return EXIT_LOAD_FAILED

    # Red team G2: exactly one execution of a job runs its stage. A jobs.run whose outcome was unknown (timeout, 5xx)
    # may have created an execution AND been re-dispatched; the first execution to bind the request record wins and
    # every other one exits here, before any answer or work.
    me = execution_name(env)
    if not me:
        logger.critical("stage-runner: CLOUD_RUN_JOB / CLOUD_RUN_EXECUTION / PROJECT_ID / REGION unset on Cloud Run; "
                        "the execution cannot claim its job (the workflow's probe ends the stage)")
        return EXIT_LOAD_FAILED
    try:
        owner = stage_jobs.bind_execution(db, job, me)
    except stage_jobs.StageJobLoadError as e:
        logger.critical(f"stage-runner: {stage} job {job_id} could not claim its execution: {e.reason}: {e}")
        return EXIT_LOAD_FAILED
    if owner is not None:
        logger.warning(f"stage-runner: {stage} job {job_id} (trace {trace_id}) is already run by execution {owner}; "
                       f"this execution ({me}) exits without answering")
        return EXIT_NOT_OWNER

    expected, own = env.get(stage_jobs.ENV_RELEASE, ""), stage_jobs.release_token(release)
    if expected and own and expected != own:
        err = GateUnavailableError(
            f"{stage} job refused: the stage-runner image ({own}) is not the gateway's ({expected}); the deploy "
            f"did not synchronise the job (scripts/deploy-services.sh orchestrator-gateway-service syncs it). "
            f"Nothing was run.", reason="STAGE_RUNNER_IMAGE_SKEW", stage=stage)
        logger.critical(f"STAGE_RUNNER_IMAGE_SKEW: {err.message}")
        stage_jobs.deliver(job, err.http_status, err.to_body(product_id=job.product_id), db=db)
        return EXIT_LOAD_FAILED
    if not (expected and own):
        logger.warning(f"stage-runner: release check not decidable (gateway {expected or 'unknown'}, job "
                       f"{own or 'unknown'}): a build without release.json; running the stage")

    # Red team G1: the gateway service's startup gates (TEST_MODE refused, QA / release / gatekeeper gates present,
    # model SDK support) run here too: a job never serves a request, so its startup hooks never fire.
    try:
        gateway.assert_pipeline_gates_ready()
        gateway._argon_compat_startup_check()
    except Exception as e:  # noqa: BLE001 - typed answer by callback, nothing run
        err = GateUnavailableError(f"{stage} job refused: a startup check failed in the stage-runner job "
                                   f"({type(e).__name__}: {e}); nothing was run", reason="STAGE_RUNNER_STARTUP_CHECK",
                                   stage=stage)
        logger.critical(f"STAGE_RUNNER_STARTUP_CHECK: {err.message}")
        stage_jobs.deliver(job, err.http_status, err.to_body(product_id=job.product_id), db=db)
        return EXIT_LOAD_FAILED

    stage_jobs.mark_running(db, job, me)
    if threading.current_thread() is threading.main_thread():
        install_sigterm(job, db, exit_fn)
    stop = threading.Event()
    beat = threading.Thread(target=_heartbeat, args=(db, job, stop, heartbeat_s), name="stage-runner-heartbeat",
                            daemon=True)
    beat.start()
    try:
        try:
            status, body = gateway.run_stage_job_here(job, request)
        except BaseException as e:  # noqa: BLE001 - never silent: a typed failure callback
            logger.exception(f"Stage job {stage} {job_id} crashed: {type(e).__name__}: {e}")
            status, body = _crash_answer(job, e)
    finally:
        stop.set()
    delivered = stage_jobs.deliver(job, status, body, db=db)
    return EXIT_OK if delivered else EXIT_UNDELIVERED


def main() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(levelname)s %(name)s: %(message)s")
    code = run(os.environ)
    logging.shutdown()
    sys.exit(code)


if __name__ == "__main__":
    main()
