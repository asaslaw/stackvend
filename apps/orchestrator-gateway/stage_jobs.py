"""LONG-STAGE-CALLBACK (G6) + STAGE-JOB-RUNNER (G7, owner 11-13): the long LLM stages (architect, developer, QA) run as
one Cloud Run Job execution each (`stage-runner`, the gateway's own image) and answer the workflow by callback.

Why a job (G7; red team R1-R3, docs/planning/stage-deadline-and-callback-rt.md): work that continues after a 202 on
the gateway Cloud Run *service* has no request keeping its instance alive, and Cloud Run stops an idle instance
within about 15 minutes (CPU always allocated does not change that; minimum instances do not choose which instance
survives). A job execution needs no request to stay alive, runs one stage in isolation from the gateway API, and is
not touched by a gateway deploy. Plan: docs/planning/stage-job-runner-plan.md.

Gateway side (the `-job` routes call `submit`):
1. The callback URL is validated (shared.callbacks.classify_callback_url; on Cloud Run a loopback URL is refused).
2. The request is stored BY REFERENCE: `pipeline_executions/{trace}/stage_job_requests/{job_id}` holds the validated
   request as exact JSON text (never truncated; over MAX_REQUEST_BYTES it is refused typed) and the callback URL.
   Its `create()` is the atomic single-run claim (RT F2): one document per job id = sha256(callback URL), so two
   dispatch attempts of one callback URL can never both start an execution. A duplicate waits (bounded) for the
   first attempt to reach STARTED and answers 202 `duplicate: true`. A start that failed, or whose outcome is
   unknown (a `jobs.run` timeout or 5xx may still have created an execution), marks the claim START_FAILED and is
   never deleted: a retry re-dispatches on the SAME record, and the execution-level claim (`bind_execution`, red team
   G2) lets exactly one execution of the job run the stage; any other one exits without answering.
3. `pipeline_executions/{trace}/stage_jobs/{stage}` names the job that owns the stage (a newer job supersedes an
   older one; the older one's liveness probe stops it before any commit).
4. One execution of the stage-runner job is started through the Cloud Run Admin API (`jobs.run` with env
   overrides: only the trace id, stage and job id, plus this gateway's release for the skew check). The route
   answers 202 only after the execution exists; a refused start is a typed 503 GATE_UNAVAILABLE
   STAGE_JOB_START_FAILED (the workflow's dispatch retry may start it again; see 2.).

Job side (stage_runner.py calls `load_job` / `deliver` / `interrupt`): the job reads its request, runs the SAME stage
body as the synchronous route under the stage's CALLBACK deadline counted from `accepted_at` (not from the job's
start), maps the outcome to exactly the synchronous (status, body) and POSTs `{"stage", "job_id", "trace_id",
"product_id", "http_status", "body"}` to the callback URL with its identity (shared.callbacks.CallbackDeliveryClient:
the platform-project Workflows callback endpoint only, OAuth token, bounded retries). Exactly one answer per job: the
first delivery wins (the outcome, or STAGE_INTERRUPTED from the SIGTERM handler, delivered synchronously before the
process exits). A failure to deliver is logged CRITICAL and recorded CALLBACK_FAILED, never silenced.

The workflow also probes the job between await slices (`job_state`): an execution that ended without an answer
(a hard kill, out of memory) ends the stage STAGE_INTERRUPTED within one slice instead of at the await bound.

Rollback (RT F4): `stage_jobs_enabled()` is reported on /health; with it false the workflow calls the synchronous
routes exactly as before LONG-STAGE-CALLBACK.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple

import runtime_env
import stage_deadline
from gate_errors import ContractViolationError, GateUnavailableError, StageInterruptedError
from stage_deadline import StageMode

try:
    from shared.callbacks import (KIND_LOOPBACK, KIND_WORKFLOWS, CallbackDeliveryClient, CallbackURLRejected,
                                  classify_callback_url)
except ImportError:  # pragma: no cover
    from .shared.callbacks import (KIND_LOOPBACK, KIND_WORKFLOWS, CallbackDeliveryClient,  # type: ignore
                                   CallbackURLRejected, classify_callback_url)

logger = logging.getLogger("castor.stage_jobs")

# The stages that run as callback jobs (each has a CALLBACK row in stage_deadline.STAGE_BUDGETS).
JOB_STAGES = frozenset({"architect", "developer", "qa"})
CALLBACK_TIMEOUT_S = 15
CALLBACK_MAX_ATTEMPTS = 5          # backoff 1.5, 3, 6, 12 s: under a minute, inside the CALLBACK margin
SHUTDOWN_DELIVERY_TIMEOUT_S = 5    # Cloud Run gives 10 s after SIGTERM
JOB_RECORD = "stage_jobs"          # pipeline_executions/{trace}/stage_jobs/{stage}: which job owns the stage
REQUEST_RECORD = "stage_job_requests"  # pipeline_executions/{trace}/stage_job_requests/{job_id}: claim + request
# The Cloud Run Job that runs one stage per execution (infra/platform/stage_runner.tf; same image as the gateway).
STAGE_RUNNER_JOB = "stage-runner"
RUN_API = "https://run.googleapis.com/v2"
RUN_API_TIMEOUT_S = 30
# A Firestore document holds at most 1 MiB. The request comes from the workflow, whose variables are capped at
# 512 KB in total, so every real request fits; a larger one is refused typed, never truncated.
MAX_REQUEST_BYTES = 1_000_000
# A duplicate dispatch waits this long for the first attempt to start its execution (the workflow's dispatch
# timeout is 60 s).
DISPATCH_WAIT_S = 40.0
DISPATCH_POLL_S = 1.0
# Override env of one execution (stage_runner.py reads them).
ENV_TRACE, ENV_STAGE, ENV_JOB_ID, ENV_RELEASE = ("STAGE_JOB_TRACE_ID", "STAGE_JOB_STAGE", "STAGE_JOB_ID",
                                                 "STAGE_JOB_EXPECTED_RELEASE")

# RT F4 rollback switch, a runtime setting (red team N1: no code edit, no deploy, no apply):
#   1. env STAGE_JOBS_ENABLED=true|false on the gateway (wins when set; Terraform does not set it),
#   2. Firestore governance/stage_jobs.enabled (bool), written by `scripts/stage-jobs-switch.sh off|on`,
#   3. the release default below.
# The gateway reports the result on /health; the workflow reads it before every stage (run_stage_job).
STAGE_JOBS_DEFAULT_ENABLED = True
SWITCH_COLLECTION, SWITCH_DOCUMENT = "governance", "stage_jobs"
SWITCH_CACHE_S = 15.0
# N8 (G7 follow-up): /health reads the setting; a slow Firestore must not make /health slow or fail. The read is
# bounded; a timeout is a read error (N7: last good value, source CACHED, else the default, source ERROR).
SWITCH_READ_TIMEOUT_S = 2.0
_switch_cache: Dict[str, Any] = {}

# A (status, body) pair: exactly what the synchronous route would have answered.
Answer = Tuple[int, Dict[str, Any]]


def stage_jobs_switch(db: Any = None, *, clock: Callable[[], float] = time.monotonic) -> Dict[str, Any]:
    """{"enabled": bool, "source": ENV | SETTING | DEFAULT | CACHED | ERROR}. N7 (G7 follow-up): a setting read error
    keeps the LAST GOOD value (source CACHED; an operator's "off" is never undone by a read error); with no good read
    yet it is the release default (source ERROR). Logged; retried after SWITCH_CACHE_S."""
    raw = os.getenv("STAGE_JOBS_ENABLED", "").strip().lower()
    if raw in ("true", "false"):
        return {"enabled": raw == "true", "source": "ENV"}
    if db is None:
        return {"enabled": STAGE_JOBS_DEFAULT_ENABLED, "source": "DEFAULT"}
    now = clock()
    hit = _switch_cache.get("value")
    if hit is not None and now - _switch_cache.get("at", 0.0) < SWITCH_CACHE_S:
        return dict(hit)
    try:
        data = _snap_dict(db.collection(SWITCH_COLLECTION).document(SWITCH_DOCUMENT).get(
            timeout=SWITCH_READ_TIMEOUT_S)) or {}
        flag = data.get("enabled")
        value = ({"enabled": flag, "source": "SETTING"} if isinstance(flag, bool)
                 else {"enabled": STAGE_JOBS_DEFAULT_ENABLED, "source": "DEFAULT"})
    except Exception as e:  # noqa: BLE001
        good = _switch_cache.get("good")
        if good is not None:
            value = {"enabled": good["enabled"], "source": "CACHED"}
        else:
            value = {"enabled": STAGE_JOBS_DEFAULT_ENABLED, "source": "ERROR"}
        logger.warning(f"stage-jobs switch unreadable ({type(e).__name__}: {e}); using "
                       f"{'the last good value' if good is not None else 'the release default'} "
                       f"({'on' if value['enabled'] else 'off'})")
        _switch_cache.update(value=dict(value), at=now)
        return value
    _switch_cache.update(value=dict(value), good=dict(value), at=now)
    return value


def stage_jobs_enabled(db: Any = None) -> bool:
    return bool(stage_jobs_switch(db)["enabled"])


def job_id_for(callback_url: str) -> str:
    """The job id: sha256 of the callback URL (Workflows makes one URL per create_callback_endpoint)."""
    return hashlib.sha256(callback_url.encode("utf-8")).hexdigest()[:32]


def execution_id_of(callback_url: str) -> Optional[str]:
    """The workflow execution id of a validated Workflows callback URL (path segment `executions/<id>`), else None
    (a loopback test URL). Only called after classify_callback_url accepted the URL's exact path shape."""
    segments = urllib.parse.urlsplit(callback_url).path.split("/")
    return segments[9] if len(segments) == 12 and segments[8] == "executions" else None


def release_token(release: Dict[str, Any]) -> str:
    """The identity of one build for the gateway / job skew check: release, commit and build time of release.json
    (one image = one file). "" when the build has no valid release.json (the check cannot decide)."""
    if not isinstance(release, dict) or release.get("release") in (None, "unknown"):
        return ""
    return "|".join(str(release.get(k, "")) for k in ("release", "commit", "built_at"))


def on_cloud_run() -> bool:
    """The one runtime check (runtime_env.on_cloud_run): a Cloud Run service revision or a Cloud Run Job execution."""
    return runtime_env.on_cloud_run()


@dataclass
class StageJob:
    job_id: str
    stage: str
    trace_id: str
    product_id: str
    callback_url: str
    execution_id: Optional[str]
    accepted_at: float = field(default_factory=time.time)   # epoch seconds: the deadline counts from here
    deadline: Optional[stage_deadline.StageDeadline] = None
    # RLock (red team N4): the SIGTERM handler runs on the main thread and may interrupt it inside claim_answer
    _answer_lock: threading.RLock = field(default_factory=threading.RLock)
    answered: bool = False

    def claim_answer(self) -> bool:
        """True exactly once: the caller owns this job's one callback."""
        with self._answer_lock:
            if self.answered:
                return False
            self.answered = True
            return True


class StageJobStartError(Exception):
    """The Cloud Run Admin API did not create the execution (`http_status` 0 = no answer)."""

    def __init__(self, message: str, http_status: int = 0):
        super().__init__(message)
        self.http_status = http_status


class StageJobLoadError(Exception):
    """The job cannot read its own request. `callback_url` is set when the failure can still be answered."""

    def __init__(self, message: str, reason: str, callback_url: Optional[str] = None):
        super().__init__(message)
        self.reason = reason
        self.callback_url = callback_url


def owner_ref(db: Any, trace_id: str, stage: str) -> Any:
    return db.collection("pipeline_executions").document(trace_id).collection(JOB_RECORD).document(stage)


def request_ref(db: Any, trace_id: str, job_id: str) -> Any:
    return db.collection("pipeline_executions").document(trace_id).collection(REQUEST_RECORD).document(job_id)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _snap_dict(snap: Any) -> Optional[Dict[str, Any]]:
    return (snap.to_dict() or {}) if getattr(snap, "exists", False) else None


def _already_exists(e: BaseException) -> bool:
    try:
        from google.api_core import exceptions as gexc
    except ImportError:  # pragma: no cover
        return False
    return isinstance(e, (gexc.AlreadyExists, gexc.Conflict))


# ================================================================================================ gateway: start
def run_api_starter(project: str, region: str, *, job_name: str = STAGE_RUNNER_JOB,
                    session_factory: Optional[Callable[[], Any]] = None,
                    expected_release: str = "") -> Callable[["StageJob"], str]:
    """`start(job) -> execution name`: one execution of the stage-runner job with the job's references as env
    overrides (Cloud Run Admin API v2 `jobs.run`; the gateway's identity holds run.jobs.runWithOverrides on that one
    job, infra/platform/stage_runner.tf). Raises StageJobStartError."""
    def session() -> Any:
        if session_factory is not None:
            return session_factory()
        import google.auth
        from google.auth.transport.requests import AuthorizedSession
        creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        return AuthorizedSession(creds)

    def start(job: "StageJob") -> str:
        if not project or not region:
            raise StageJobStartError("PROJECT_ID / REGION unset: the stage-runner job cannot be addressed")
        env = {ENV_TRACE: job.trace_id, ENV_STAGE: job.stage, ENV_JOB_ID: job.job_id}
        if expected_release:
            env[ENV_RELEASE] = expected_release
        body = {"overrides": {"containerOverrides": [{"env": [{"name": k, "value": v}
                                                               for k, v in sorted(env.items())]}],
                              "taskCount": 1}}
        url = f"{RUN_API}/projects/{project}/locations/{region}/jobs/{job_name}:run"
        try:
            res = session().post(url, json=body, timeout=RUN_API_TIMEOUT_S)
        except Exception as e:  # noqa: BLE001 - typed by the caller
            raise StageJobStartError(f"jobs.run request failed: {type(e).__name__}: {e}") from e
        if res.status_code not in (200, 201):
            raise StageJobStartError(f"jobs.run answered HTTP {res.status_code}: {str(getattr(res, 'text', ''))[:300]}",
                                     http_status=res.status_code)
        try:
            name = res.json()["metadata"]["name"]
        except Exception as e:  # noqa: BLE001
            raise StageJobStartError("jobs.run answer has no execution name", http_status=res.status_code) from e
        prefix = f"projects/{project}/locations/{region}/jobs/{job_name}/executions/"
        if not isinstance(name, str) or not name.startswith(prefix):
            raise StageJobStartError(f"jobs.run returned an unexpected execution name {name!r}",
                                     http_status=res.status_code)
        return name
    return start


def submit(stage: str, *, trace_id: str, product_id: str, callback_url: Any, request: Dict[str, Any], db: Any,
           start: Callable[[StageJob], str], wait_s: float = DISPATCH_WAIT_S,
           sleep: Callable[[float], None] = time.sleep) -> Dict[str, Any]:
    """Accepts one stage job (the 202 body, after its execution was created) or raises a typed refusal:
    409 CONTRACT_VIOLATION CALLBACK_URL_REJECTED / STAGE_REQUEST_TOO_LARGE, 503 GATE_UNAVAILABLE STAGE_JOB_STORE /
    STAGE_JOB_START_FAILED / STAGE_JOB_DISPATCH_PENDING. Never starts two executions for one callback URL."""
    if stage not in JOB_STAGES:
        raise ValueError(f"{stage!r} is not a callback stage")
    try:
        kind = classify_callback_url(callback_url)
    except CallbackURLRejected as e:
        raise ContractViolationError(f"{stage} job refused: {e}", reason="CALLBACK_URL_REJECTED", stage=stage) from e
    if kind == KIND_LOOPBACK and on_cloud_run():
        # RT S5: a loopback answer URL is for tests and local runs only; on Cloud Run it would be the job's own port.
        raise ContractViolationError(f"{stage} job refused: a loopback callback URL is not accepted on Cloud Run",
                                     reason="CALLBACK_URL_REJECTED", stage=stage)
    if db is None:
        raise GateUnavailableError(f"{stage} job refused: no job store (Firestore) to make the job single-run",
                                   reason="STAGE_JOB_STORE", stage=stage)
    request_json = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    size = len(request_json.encode("utf-8"))
    if size > MAX_REQUEST_BYTES:
        raise ContractViolationError(f"{stage} job refused: the request is {size} bytes (limit {MAX_REQUEST_BYTES})",
                                     reason="STAGE_REQUEST_TOO_LARGE", stage=stage, details={"bytes": size})
    job = StageJob(job_id=job_id_for(callback_url), stage=stage, trace_id=trace_id, product_id=product_id,
                   callback_url=callback_url,
                   execution_id=execution_id_of(callback_url) if kind == KIND_WORKFLOWS else None)
    budget = stage_deadline.budget_for(stage, StageMode.CALLBACK)
    accepted = {"status": "ACCEPTED", "stage": stage, "trace_id": trace_id, "product_id": product_id,
                "job_id": job.job_id, "budget_s": budget.budget_s, "await_timeout_s": budget.workflow_timeout_s}
    req_ref = request_ref(db, trace_id, job.job_id)
    claim = {"job_id": job.job_id, "stage": stage, "trace_id": trace_id, "product_id": product_id,
             "callback_url": callback_url, "execution_id": job.execution_id, "request_json": request_json,
             "request_sha256": hashlib.sha256(request_json.encode("utf-8")).hexdigest(), "request_bytes": size,
             "accepted_at": _now_iso(), "accepted_epoch": job.accepted_at, "dispatch": "DISPATCHING",
             "run_execution": None}
    try:
        req_ref.create(claim)     # RT F2: the atomic claim (one document per callback URL)
    except Exception as e:  # noqa: BLE001
        if not _already_exists(e):
            raise GateUnavailableError(f"{stage} job refused: job store unwritable ({type(e).__name__})",
                                       reason="STAGE_JOB_STORE", stage=stage) from e
        state = _await_dispatch(req_ref, wait_s, sleep, stage)
        bound = _bound_after_failed_start(req_ref, stage) if state == "START_FAILED" else None
        if bound:
            # N9 (G7 follow-up): the start whose outcome was unknown DID create an execution and it has bound the job:
            # it runs the stage; no spare execution is started.
            logger.info(f"Stage job {stage} {job.job_id} for {trace_id}: the earlier start did run ({bound}); "
                        f"nothing new is started")
            return dict(accepted, duplicate=True, run_execution=bound)
        if state != "START_FAILED" or not _retake(db, req_ref):
            logger.info(f"Stage job {stage} {job.job_id} for {trace_id}: duplicate submission ({state})")
            return {**accepted, "duplicate": True}
        # an earlier start failed (or its outcome is unknown): re-dispatch on the same record (bind_execution makes
        # sure that only one execution of this job ever runs the stage)
        logger.warning(f"Stage job {stage} {job.job_id} for {trace_id}: re-dispatching after an earlier failed start")
    own = owner_ref(db, trace_id, stage)
    try:
        prev = _snap_dict(own.get()) or {}
        own.set({"job_id": job.job_id, "stage": stage, "status": "DISPATCHING", "execution_id": job.execution_id,
                 "accepted_at": claim["accepted_at"], "accepted_epoch": job.accepted_at, "budget_s": budget.budget_s,
                 "superseded_job_id": prev.get("job_id") if prev.get("job_id") != job.job_id else None,
                 "run_execution": None})
    except Exception as e:  # noqa: BLE001
        _mark_start_failed(req_ref, job, f"owner record unwritable: {type(e).__name__}")
        raise GateUnavailableError(f"{stage} job refused: job store unwritable ({type(e).__name__})",
                                   reason="STAGE_JOB_STORE", stage=stage) from e
    try:
        execution = start(job)
    except StageJobStartError as e:
        # Never deleted (red team G2): a timeout / 5xx may have created an execution; it binds this record or loses.
        _mark_start_failed(req_ref, job, str(e))
        _update_owner(db, job, {"status": "START_FAILED", "finished_at": _now_iso(), "error": str(e)[:500]})
        logger.error(f"STAGE_JOB_START_FAILED: {stage} job {job.job_id} for '{product_id}' (trace {trace_id}): {e}")
        raise GateUnavailableError(f"{stage} job could not start: {e}", reason="STAGE_JOB_START_FAILED", stage=stage,
                                   details={"http_status": e.http_status, "job": STAGE_RUNNER_JOB}) from e
    try:
        req_ref.update({"dispatch": "STARTED", "run_execution": execution})
    except Exception as e:  # noqa: BLE001 - the execution exists; a duplicate then waits and answers pending
        logger.warning(f"Stage job {stage} {job.job_id}: STARTED not recorded ({type(e).__name__}: {e})")
    _update_owner(db, job, {"status": "DISPATCHED", "run_execution": execution})
    logger.info(f"Stage job {stage} {job.job_id} accepted for '{product_id}' (trace {trace_id}); execution "
                f"{execution}; budget {budget.budget_s} s, answer by callback")
    return {**accepted, "duplicate": False, "run_execution": execution}


def _await_dispatch(req_ref: Any, wait_s: float, sleep: Callable[[float], None], stage: str) -> Optional[str]:
    """A duplicate submission: the first attempt's dispatch state once it is no longer DISPATCHING ("STARTED", or
    "START_FAILED": that start failed or its outcome is unknown). Still DISPATCHING after `wait_s`: typed 503
    (retryable)."""
    end = time.monotonic() + wait_s
    while True:
        try:
            data = _snap_dict(req_ref.get())
        except Exception as e:  # noqa: BLE001
            raise GateUnavailableError(f"{stage} job refused: job store unreadable ({type(e).__name__})",
                                       reason="STAGE_JOB_STORE", stage=stage) from e
        if data is None:
            raise GateUnavailableError(f"{stage} job: the job claim disappeared", reason="STAGE_JOB_STORE",
                                       stage=stage)
        if data.get("dispatch") != "DISPATCHING":
            return str(data.get("dispatch"))
        if time.monotonic() >= end:
            raise GateUnavailableError(f"{stage} job: an earlier dispatch of this callback is still starting",
                                       reason="STAGE_JOB_DISPATCH_PENDING", stage=stage)
        sleep(DISPATCH_POLL_S)


def _mark_start_failed(req_ref: Any, job: StageJob, error: str) -> None:
    try:
        req_ref.update({"dispatch": "START_FAILED", "start_error": error[:500], "start_failed_at": _now_iso()})
    except Exception as e:  # noqa: BLE001 - a retry then answers DISPATCH_PENDING (typed), never a silent pass
        logger.critical(f"Stage job {job.stage} {job.job_id}: START_FAILED not recorded ({type(e).__name__}: {e}); "
                        f"a dispatch retry of this callback answers STAGE_JOB_DISPATCH_PENDING")


def _precondition_failed(e: BaseException) -> bool:
    try:
        from google.api_core import exceptions as gexc
    except ImportError:  # pragma: no cover
        return False
    return isinstance(e, (gexc.FailedPrecondition, gexc.Aborted))


def _cas_update(db: Any, ref: Any, snap: Any, fields: Dict[str, Any]) -> bool:
    """Compare-and-set: update only if the document did not change since `snap` (Firestore last_update_time
    precondition, atomic on the server). False when another writer got there first."""
    try:
        ref.update(fields, option=db.write_option(last_update_time=snap.update_time))
        return True
    except Exception as e:  # noqa: BLE001
        if _precondition_failed(e):
            return False
        raise


def _bound_after_failed_start(req_ref: Any, stage: str) -> Optional[str]:
    """N9: the execution that bound a START_FAILED record (an earlier jobs.run whose outcome was unknown did create
    it); recorded as STARTED so the probe and later duplicates see it. None when nothing is bound."""
    try:
        data = _snap_dict(req_ref.get()) or dict()
    except Exception as e:  # noqa: BLE001
        raise GateUnavailableError(f"{stage} job refused: job store unreadable ({type(e).__name__})",
                                   reason="STAGE_JOB_STORE", stage=stage) from e
    bound = data.get("bound_execution")
    if not (isinstance(bound, str) and bound):
        return None
    try:
        req_ref.update(dict(dispatch="STARTED", run_execution=bound))
    except Exception as e:  # noqa: BLE001 - the probe reads bound_execution first anyway
        logger.warning(f"Stage job {stage}: STARTED not recorded for the bound execution ({type(e).__name__}: {e})")
    return bound


def _retake(db: Any, req_ref: Any) -> bool:
    """Takes a START_FAILED claim back to DISPATCHING for this dispatch (one dispatcher wins)."""
    try:
        snap = req_ref.get()
        data = _snap_dict(snap) or {}
        if data.get("dispatch") != "START_FAILED":
            return False
        return _cas_update(db, req_ref, snap, {"dispatch": "DISPATCHING",
                                               "redispatches": int(data.get("redispatches") or 0) + 1})
    except Exception as e:  # noqa: BLE001
        raise GateUnavailableError(f"job store unwritable ({type(e).__name__})", reason="STAGE_JOB_STORE") from e


def bind_execution(db: Any, job: StageJob, execution_name: str, attempts: int = 3) -> Optional[str]:
    """Red team G2: the execution-level claim. Binds the job's request record to exactly one stage-runner execution
    (compare-and-set). None when `execution_name` owns the job (bound now or before), else the name of the execution
    that does (this one must exit without answering). Raises StageJobLoadError when the store fails."""
    ref = request_ref(db, job.trace_id, job.job_id)
    for _ in range(attempts):
        try:
            snap = ref.get()
            data = _snap_dict(snap)
            if data is None:
                raise StageJobLoadError(f"no request record for job {job.job_id}", "STAGE_REQUEST_MISSING")
            bound = data.get("bound_execution")
            if bound == execution_name:
                return None
            if isinstance(bound, str) and bound:
                return bound
            if _cas_update(db, ref, snap, {"bound_execution": execution_name, "bound_at": _now_iso()}):
                return None
        except StageJobLoadError:
            raise
        except Exception as e:  # noqa: BLE001
            raise StageJobLoadError(f"execution claim failed ({type(e).__name__}: {e})", "STAGE_JOB_STORE") from e
    raise StageJobLoadError("execution claim contended", "STAGE_JOB_STORE")


def _update_owner(db: Any, job: StageJob, fields: Dict[str, Any]) -> None:
    """Best-effort owner-record update while this job still owns the stage; a failure is logged."""
    try:
        ref = owner_ref(db, job.trace_id, job.stage)
        data = _snap_dict(ref.get()) or {}
        if data.get("job_id") != job.job_id:
            return
        ref.set(fields, merge=True)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Stage job record of {job.stage} for {job.trace_id} not updated ({fields.get('status')}): "
                       f"{type(e).__name__}: {e}")


# ================================================================================================ gateway: state
def run_api_execution_reader(session_factory: Optional[Callable[[], Any]] = None) -> Callable[[str], Dict[str, Any]]:
    def read(name: str) -> Dict[str, Any]:
        if session_factory is not None:
            sess = session_factory()
        else:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession
            creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            sess = AuthorizedSession(creds)
        res = sess.get(f"{RUN_API}/{name}", timeout=RUN_API_TIMEOUT_S)
        if res.status_code != 200:
            raise RuntimeError(f"executions.get answered HTTP {res.status_code}")
        return res.json()
    return read


def job_state(db: Any, trace_id: str, stage: str, job_id: str,
              read_execution: Callable[[str], Dict[str, Any]]) -> Dict[str, Any]:
    """What the workflow's await loop needs between slices: {"state": RUNNING | ANSWERED | DEAD | UNKNOWN, ...}.
    DEAD = the job can no longer answer: its execution ended without an answer, its start failed, or its answer
    could not be delivered. Never DEAD on a read error (UNKNOWN: the workflow keeps waiting, the await bound holds)."""
    try:
        req = _snap_dict(request_ref(db, trace_id, job_id).get())
        own = _snap_dict(owner_ref(db, trace_id, stage).get()) or {}
    except Exception as e:  # noqa: BLE001
        return {"state": "UNKNOWN", "reason": "STORE_UNREADABLE", "detail": type(e).__name__}
    if req is None:
        return {"state": "DEAD", "reason": "NO_JOB_RECORD", "detail": "no dispatch record for this job"}
    answer = req.get("answer")
    if answer == "DELIVERED":
        return {"state": "ANSWERED", "reason": "DELIVERED"}
    if answer == "CALLBACK_FAILED":
        return {"state": "DEAD", "reason": "CALLBACK_UNDELIVERED",
                "detail": "the job's answer could not be delivered to the workflow callback"}
    # Red team G2 / N5: the execution that bound the job is the one that answers; a losing execution's exit (or a
    # missing STARTED record) never reads as DEAD.
    execution = req.get("bound_execution") or req.get("run_execution")
    if not execution:
        if req.get("dispatch") == "START_FAILED":
            return {"state": "DEAD", "reason": "START_FAILED", "detail": str(req.get("start_error") or "")[:300]}
        return {"state": "RUNNING", "reason": "DISPATCHING"}
    try:
        ex = read_execution(execution)
    except Exception as e:  # noqa: BLE001
        return {"state": "UNKNOWN", "reason": "EXECUTION_UNREADABLE", "detail": f"{type(e).__name__}: {e}"[:300]}
    if not ex.get("completionTime"):
        return {"state": "RUNNING", "reason": "EXECUTION_RUNNING", "run_execution": execution,
                "owner": own.get("job_id") == job_id}
    counts = {k: ex.get(k, 0) for k in ("succeededCount", "failedCount", "cancelledCount")}
    return {"state": "DEAD", "reason": "EXECUTION_ENDED_WITHOUT_ANSWER", "run_execution": execution,
            "detail": f"the stage-runner execution ended ({counts}) and no answer was recorded"}


# ================================================================================================ job: load / answer
def load_job(db: Any, trace_id: str, stage: str, job_id: str) -> Tuple[StageJob, Dict[str, Any]]:
    """The job and its request, read by reference. Raises StageJobLoadError (with the callback URL when known)."""
    if stage not in JOB_STAGES:
        raise StageJobLoadError(f"{stage!r} is not a callback stage", "STAGE_UNKNOWN")
    if db is None:
        raise StageJobLoadError("no job store (Firestore)", "STAGE_JOB_STORE")
    try:
        data = _snap_dict(request_ref(db, trace_id, job_id).get())
    except Exception as e:  # noqa: BLE001
        raise StageJobLoadError(f"job store unreadable ({type(e).__name__}: {e})", "STAGE_JOB_STORE") from e
    if data is None:
        raise StageJobLoadError(f"no request record for job {job_id}", "STAGE_REQUEST_MISSING")
    cb = data.get("callback_url")
    if not isinstance(cb, str) or not cb:
        raise StageJobLoadError(f"request record of job {job_id} has no callback URL (already answered?)",
                                "STAGE_REQUEST_MISSING")
    try:
        kind = classify_callback_url(cb)
    except CallbackURLRejected as e:
        raise StageJobLoadError(f"stored callback URL refused: {e}", "CALLBACK_URL_REJECTED") from e
    if kind == KIND_LOOPBACK and on_cloud_run():
        raise StageJobLoadError("stored callback URL is a loopback URL", "CALLBACK_URL_REJECTED")
    if job_id_for(cb) != job_id or data.get("stage") != stage or data.get("trace_id") != trace_id:
        raise StageJobLoadError("request record does not belong to this job", "STAGE_REQUEST_CORRUPT", cb)
    text = data.get("request_json")
    if not isinstance(text, str) or hashlib.sha256(text.encode("utf-8")).hexdigest() != data.get("request_sha256"):
        raise StageJobLoadError("stored request is missing or does not match its sha256", "STAGE_REQUEST_CORRUPT", cb)
    try:
        request = json.loads(text)
    except ValueError as e:
        raise StageJobLoadError("stored request is not JSON", "STAGE_REQUEST_CORRUPT", cb) from e
    accepted = data.get("accepted_epoch")
    job = StageJob(job_id=job_id, stage=stage, trace_id=trace_id, product_id=str(data.get("product_id") or ""),
                   callback_url=cb, execution_id=data.get("execution_id"),
                   accepted_at=float(accepted) if isinstance(accepted, (int, float)) else time.time())
    return job, request


def mark_running(db: Any, job: StageJob, run_execution: str) -> None:
    _update_owner(db, job, {"status": "RUNNING", "started_at": _now_iso(), "run_execution": run_execution or None})


def payload_of(job: StageJob, status: int, body: Dict[str, Any]) -> Dict[str, Any]:
    return {"stage": job.stage, "job_id": job.job_id, "trace_id": job.trace_id, "product_id": job.product_id,
            "http_status": int(status), "body": body}


def _record_answer(db: Any, job: StageJob, state: str, http_status: Optional[int]) -> None:
    """The answer on both records. DELIVERED also drops the request text and the callback URL (not needed any
    more); the claim itself stays, so a late duplicate of this callback can never start a second execution."""
    _update_owner(db, job, {"status": state, "http_status": http_status, "finished_at": _now_iso()})
    if db is None:
        return
    fields: Dict[str, Any] = {"answer": state, "answered_at": _now_iso(), "http_status": http_status}
    if state == "DELIVERED":
        fields.update({"request_json": None, "callback_url": None})
    try:
        request_ref(db, job.trace_id, job.job_id).update(fields)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Stage job {job.stage} {job.job_id}: answer {state} not recorded on the request record "
                       f"({type(e).__name__}: {e})")


def deliver(job: StageJob, status: int, body: Dict[str, Any], *, db: Any,
            max_attempts: int = CALLBACK_MAX_ATTEMPTS, timeout: int = CALLBACK_TIMEOUT_S) -> bool:
    """POSTs the job's one answer to its callback URL. False when another answer was already sent (or this one
    could not be delivered: logged CRITICAL, recorded CALLBACK_FAILED; the workflow's probe then ends the stage)."""
    if not job.claim_answer():
        logger.info(f"Stage job {job.stage} {job.job_id}: already answered; outcome HTTP {status} not sent")
        return False
    payload = payload_of(job, status, body)
    size = len(json.dumps(payload, default=str).encode("utf-8"))
    if size > 256_000:
        # Workflows keeps the answer in a variable (512 KB for all variables of the execution), as it kept the
        # synchronous response before; a large answer is logged so the limit is visible before it bites.
        logger.warning(f"Stage job {job.stage} {job.job_id}: answer is {size} bytes (Workflows variable memory is "
                       f"512 KB per execution)")
    try:
        CallbackDeliveryClient.send_callback(callback_url=job.callback_url, payload=payload, timeout=timeout,
                                             max_attempts=max_attempts)
    except Exception as e:  # noqa: BLE001
        logger.critical(f"STAGE_CALLBACK_UNDELIVERED: {job.stage} job {job.job_id} for '{job.product_id}' (trace "
                        f"{job.trace_id}), outcome HTTP {status}: {type(e).__name__}: {e}. The workflow ends the "
                        f"stage STAGE_INTERRUPTED at its next probe.")
        _record_answer(db, job, "CALLBACK_FAILED", status)
        return False
    _record_answer(db, job, "DELIVERED", status)
    logger.info(f"Stage job {job.stage} {job.job_id} answered HTTP {status} by callback ({size} bytes)")
    return True


def interrupted_answer(job: StageJob, reason: str, why: str) -> Answer:
    err = StageInterruptedError(
        f"{job.stage} job stopped: {why}; nothing was committed after this point. Re-run the workload.",
        reason=reason, stage=job.stage,
        details={"progress": job.deadline.progress() if job.deadline is not None else None})
    return err.http_status, err.to_body(product_id=job.product_id)


def interrupt(job: StageJob, *, db: Any, reason: str = "INSTANCE_SHUTDOWN",
              why: str = "the stage-runner execution received SIGTERM (task timeout or cancel)") -> bool:
    """SIGTERM inside the job (RT R2): abandon the stage (no side effect after this) and deliver STAGE_INTERRUPTED
    synchronously, once, inside the shutdown grace. True when this call delivered the job's answer."""
    if job.deadline is not None:
        job.deadline.abandon("SHUTDOWN", why)
    status, body = interrupted_answer(job, reason, why)
    return deliver(job, status, body, db=db, max_attempts=1, timeout=SHUTDOWN_DELIVERY_TIMEOUT_S)
