"""
StackVend: the day-2 Cloud Run job contract for the C10 jobs (finops-spend-sync-job, sandbox-workload-sweeper-job,
billing-alert-drain-job). The same contract as sandbox-garbage-collector-job / sre-telemetry-digest-job /
finops-budget-enforcer-job (plan 2.0; pre-review F16-F18):

- Run record `<job>_runs/{CLOUD_RUN_EXECUTION}` (default Firestore database) created with create() BEFORE any work: a
  re-run of the same execution never does the work twice ("an earlier attempt of this execution was interrupted: no
  second mutation"). The log-sre-sentinel reads its `outcome` (sre_classifier.run_record_collection).
- Mutual exclusion (F18): a lease `<job>_leases/current` {holder, expires_at}. A run that cannot take it (another
  execution holds an unexpired lease) records SKIPPED_CONCURRENT and exits 0: nothing was done, nothing is wrong. An
  expired lease is taken over with a last-update-time precondition (two takers cannot both win).
- Outcomes and exit codes: COMPLETED 0, SKIPPED_CONCURRENT 0, COMPLETED_WITH_ERRORS 1 (some workloads / messages
  failed; listed in the record), FAILED 1, INTERRUPTED 1, RUN_RECORD_UNAVAILABLE 1, NOT_CONFIGURED 3 (WARNING: a
  required env var is missing; the record names it). Terraform runs these jobs with max_retries = 0.
- Fail loudly: an exception in the work is FAILED with its class, never a success.

Replicated (byte-identical, tests/test_c10_platform_tf.py::test_c10_copies_are_byte_identical): shared/, apps/finops-spend-sync/shared/,
apps/sandbox-sweeper/shared/, apps/billing-alert-drain/shared/. Standard library only.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger("stackvend-day2-job")

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_NOT_CONFIGURED = 0, 1, 2, 3
COMPLETED = "COMPLETED"
COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"
FAILED = "FAILED"
NOT_CONFIGURED = "NOT_CONFIGURED"
RUNNING = "RUNNING"
SKIPPED_CONCURRENT = "SKIPPED_CONCURRENT"
INTERRUPTED = "INTERRUPTED"
WORK_OUTCOMES = (COMPLETED, COMPLETED_WITH_ERRORS, FAILED)
OUTCOME_EXIT_CODES: Dict[str, int] = {COMPLETED: EXIT_OK, SKIPPED_CONCURRENT: EXIT_OK,
                                      COMPLETED_WITH_ERRORS: EXIT_ERROR, FAILED: EXIT_ERROR,
                                      NOT_CONFIGURED: EXIT_NOT_CONFIGURED}

Work = Callable[[str], Tuple[str, Dict[str, Any]]]   # work(run_id) -> (outcome, detail)


def run_collection(job_name: str) -> str:
    return f"{job_name}_runs"


def lease_collection(job_name: str) -> str:
    return f"{job_name}_leases"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_already_exists(exc: BaseException) -> bool:
    return type(exc).__name__ == "AlreadyExists" or getattr(exc, "code", None) == 409


def _is_precondition_failed(exc: BaseException) -> bool:
    return type(exc).__name__ in ("FailedPrecondition", "Aborted") or getattr(exc, "code", None) in (409, 412)


def _log(level: int, event: str, **fields: Any) -> None:
    logger.log(level, json.dumps({"event": event, **fields}, sort_keys=True, default=str))


def acquire_lease(database: Any, job_name: str, run_id: str, lease_seconds: int,
                  now: Optional[datetime] = None) -> bool:
    """True when this run holds `<job>_leases/current` (created, or an expired one taken over)."""
    now = now or _now()
    ref = database.collection(lease_collection(job_name)).document("current")
    lease = {"holder": run_id, "acquired_at": now.isoformat(),
             "expires_at": (now + timedelta(seconds=lease_seconds)).isoformat()}
    try:
        ref.create(lease)
        return True
    except Exception as e:  # noqa: BLE001 - classified
        if not _is_already_exists(e):
            raise
    snap = ref.get()
    current = (snap.to_dict() or {}) if getattr(snap, "exists", False) else {}
    try:
        expired = datetime.fromisoformat(str(current.get("expires_at"))) <= now
    except ValueError:
        expired = True   # an unreadable lease never blocks forever
    if not expired:
        return False
    try:
        ref.update(lease, option=database.write_option(last_update_time=snap.update_time))
        return True
    except Exception as e:  # noqa: BLE001
        if _is_precondition_failed(e):
            return False   # another run took it over first
        raise


def release_lease(database: Any, job_name: str, run_id: str) -> None:
    ref = database.collection(lease_collection(job_name)).document("current")
    try:
        snap = ref.get()
        if getattr(snap, "exists", False) and (snap.to_dict() or {}).get("holder") == run_id:
            ref.delete()
    except Exception as e:  # noqa: BLE001 - the lease expires on its own
        logger.warning(f"{job_name}: could not release the lease ({type(e).__name__}); it expires by itself")


def run_job(job_name: str, work: Work, database: Any, env: Optional[Mapping[str, str]] = None,
            required_env: Sequence[str] = ("PROJECT_ID",), lease_seconds: int = 3600) -> Tuple[int, Dict[str, Any]]:
    """Run `work` once under the contract. Returns (exit code, the run record as written)."""
    env = os.environ if env is None else env
    run_id = (env.get("CLOUD_RUN_EXECUTION") or "").strip() or f"manual-{uuid.uuid4().hex[:12]}"
    missing = [k for k in required_env if not (env.get(k) or "").strip()]
    if missing:
        _log(logging.WARNING, NOT_CONFIGURED, error_class=NOT_CONFIGURED, job=job_name, missing=missing)
        summary = {"job": job_name, "run_id": run_id, "outcome": NOT_CONFIGURED, "missing": missing,
                   "finished_at": _now().isoformat()}
        if "PROJECT_ID" not in missing and database:
            try:
                database.collection(run_collection(job_name)).document(run_id).set(summary)
            except Exception as e:  # noqa: BLE001 - the exit code still says NOT_CONFIGURED
                logger.warning(f"Could not record the NOT_CONFIGURED run {run_id}: {type(e).__name__}")
        return EXIT_NOT_CONFIGURED, summary

    if not database:
        _log(logging.ERROR, "RUN_RECORD_UNAVAILABLE", error_class="RUN_RECORD_UNAVAILABLE", job=job_name,
             detail="no Firestore client; refusing to run without a run record")
        return EXIT_ERROR, {"job": job_name, "run_id": run_id, "outcome": FAILED, "error": "RUN_RECORD_UNAVAILABLE"}

    ref = database.collection(run_collection(job_name)).document(run_id)
    started = _now().isoformat()
    try:
        ref.create({"job": job_name, "run_id": run_id, "outcome": RUNNING, "started_at": started})
    except Exception as e:  # noqa: BLE001 - classified below
        if not _is_already_exists(e):
            _log(logging.ERROR, "RUN_RECORD_UNAVAILABLE", error_class="RUN_RECORD_UNAVAILABLE", job=job_name,
                 detail=type(e).__name__)
            return EXIT_ERROR, {"job": job_name, "run_id": run_id, "outcome": FAILED, "error": "RUN_RECORD_UNAVAILABLE"}
        prior = ref.get().to_dict() or {}
        logger.info(f"{job_name}: run {run_id} already recorded ({prior.get('outcome')}); no second mutation.")
        if prior.get("outcome") == RUNNING:
            return EXIT_ERROR, dict(prior, outcome=INTERRUPTED)
        return OUTCOME_EXIT_CODES.get(prior.get("outcome"), EXIT_ERROR), prior

    try:
        held = acquire_lease(database, job_name, run_id, lease_seconds)
    except Exception as e:  # noqa: BLE001 - fail loudly: no lease, no work
        held = None
        lease_error = f"{type(e).__name__}: {e}"[:300]
    if not held:
        outcome = SKIPPED_CONCURRENT if held is False else FAILED
        detail = ({"reason": "another execution holds the lease"} if held is False
                  else {"error_class": "LEASE_UNAVAILABLE", "error": lease_error})
        summary = {"job": job_name, "run_id": run_id, "outcome": outcome, "started_at": started,
                   "finished_at": _now().isoformat(), **detail}
        _log(logging.WARNING if held is False else logging.ERROR, outcome, job=job_name, run_id=run_id)
        try:
            ref.set(summary)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Could not finish run record {run_id}: {type(e).__name__}")
        return OUTCOME_EXIT_CODES[outcome], summary

    try:
        try:
            outcome, detail = work(run_id)
        except Exception as e:  # noqa: BLE001 - fail loudly: typed FAILED, never a success
            _log(logging.ERROR, FAILED, error_class=type(e).__name__, job=job_name, detail=str(e)[:500])
            outcome, detail = FAILED, {"error_class": type(e).__name__, "error": str(e)[:500]}
        if outcome not in WORK_OUTCOMES:
            detail = dict(detail or {}, invalid_outcome=str(outcome))
            outcome = FAILED
        summary = {"job": job_name, "run_id": run_id, "outcome": outcome, "started_at": started,
                   "finished_at": _now().isoformat(), **(detail or {})}
        try:
            ref.set(summary)
        except Exception as e:  # noqa: BLE001 - the exit code still carries the outcome
            logger.warning(f"Could not finish run record {run_id}: {type(e).__name__}")
        return OUTCOME_EXIT_CODES[outcome], summary
    finally:
        release_lease(database, job_name, run_id)
