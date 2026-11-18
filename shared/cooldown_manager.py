# ==============================================================================
# PROJECT CASTOR: GEMINI 429 RATE-LIMIT COOLDOWN & RESUME MANAGER
# ==============================================================================
"""
Provides resilient 429 ResourceExhausted detection, interruptible 60s cooldowns,
dynamic model cascade resolution, and operator force-resume / abort listeners.
"""

import logging
import os
import random
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

__all__ = [
    "is_rate_limit_error",
    "is_model_deprecated_error",
    "is_transient_vertex_error",
    "wait_for_rate_limit_cooldown",
    "RunEndedDuringCooldown",
    "RUN_ENDED_STATUSES",
]

logger = logging.getLogger("castor-cooldown-manager")

# RT14-15 (owner 11-14): the run-record statuses that mean the run is over (the same set as the gateway's
# stage_deadline.RUN_ENDED_STATUSES). A cooldown never writes over one of them.
RUN_ENDED_STATUSES = frozenset({"FAILED", "SUCCEEDED", "ABORTED", "CANCELLED", "REJECTED"})
COOLDOWN_STATUS = "PAUSED_RATE_LIMIT_COOLDOWN"
_CAS_ATTEMPTS = 5


class RunEndedDuringCooldown(RuntimeError):
    """RT14-15: the run ended (an operator abort, a failure) before or during a rate-limit cooldown. Nothing is written
    over its status and the caller stops (STAGE_ABANDONED, reason RUN_ENDED). A RuntimeError, so every caller that
    stopped on the former abort RuntimeError stops on this too."""

    error_class = "STAGE_ABANDONED"
    reason = "RUN_ENDED"

    def __init__(self, trace_id: str, status: str, stage: str):
        super().__init__(f"Build {trace_id} was aborted or ended ({status}) during rate-limit cooldown; stage "
                         f"{stage} stops (RUN_ENDED)")
        self.trace_id = trace_id
        self.status = status
        self.stage = stage


def _is_write_conflict(err: BaseException) -> bool:
    """A compare-and-set lost to a concurrent writer (create() on an existing document, a stale precondition)."""
    try:
        from google.api_core import exceptions as gexc
    except ImportError:  # pragma: no cover - google-api-core ships with every Firestore client
        return False
    return isinstance(err, (gexc.AlreadyExists, gexc.FailedPrecondition, gexc.Aborted, gexc.Conflict))


def _cas_run_write(db: Any, trace_id: str, stage: str, build: Any) -> str:
    """RT14-15: one compare-and-set write on pipeline_executions/{trace_id}. `build(data)` returns the fields to write
    for the record as read, or None to write nothing. A record whose status is in RUN_ENDED_STATUSES is never written:
    RunEndedDuringCooldown is raised. Returns the status read ("" when none). A write that lost to a concurrent writer
    re-reads and decides again; any other error propagates (the caller logs it)."""
    ref = db.collection("pipeline_executions").document(trace_id)
    for _attempt in range(_CAS_ATTEMPTS):
        snap = ref.get()
        exists = bool(getattr(snap, "exists", False))
        data = (snap.to_dict() or {}) if exists else {}
        status = str(data.get("status") or "").upper()
        if status in RUN_ENDED_STATUSES:
            raise RunEndedDuringCooldown(trace_id, status, stage)
        fields = build(data)
        if fields is None:
            return status
        try:
            update_time = getattr(snap, "update_time", None)
            if not exists:
                ref.create(fields)
            elif update_time is not None:
                ref.update(fields, option=db.write_option(last_update_time=update_time))
            else:
                ref.set(fields, merge=True)
            return status
        except Exception as err:  # noqa: BLE001 - typed below
            if _is_write_conflict(err):
                continue
            raise
    raise RuntimeError(f"pipeline_executions/{trace_id} kept changing during {_CAS_ATTEMPTS} cooldown write attempts")


def is_transient_vertex_error(error: Exception) -> bool:
    """
    Discriminates transient Google Cloud Vertex AI infrastructure errors
    (500 Harpoon, 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout,
    429 Quota/Rate Limit, network resets) from permanent client errors (400, 404, validation).
    """
    if error is None:
        return False
    err_str = str(error).lower()

    # Check status code attributes if present
    code = getattr(error, "code", None) or getattr(error, "status_code", None)
    if code in (429, 500, 502, 503, 504, "429", "500", "502", "503", "504", "RESOURCE_EXHAUSTED", "UNAVAILABLE", "INTERNAL"):
        return True

    # Check error message keywords
    patterns = [
        r"\b429\b",
        r"\b500\b",
        r"\b502\b",
        r"\b503\b",
        r"\b504\b",
        r"harpoon",
        r"\binternal\b",
        r"internal error",
        r"server error",
        r"resource[_\s]exhausted",
        r"quota[_\s]exceeded",
        r"rate[_\s]limit",
        r"too many requests",
        r"\bunavailable\b",
        r"service unavailable",
        r"deadline exceeded",
        r"timeout",
        r"connection reset",
        r"remotedisconnected",
        r"connection refused",
        r"temporary failure",
        r"borg",
    ]
    return any(re.search(pat, err_str) for pat in patterns)


def is_rate_limit_error(error: Exception) -> bool:
    """
    Discriminates 429 / ResourceExhausted errors from standard validation,
    syntax, or 400 Bad Request errors.
    """
    if error is None:
        return False
    err_str = str(error).lower()
    
    # Check status code attributes if present
    code = getattr(error, "code", None) or getattr(error, "status_code", None)
    if code in (429, "429", "RESOURCE_EXHAUSTED"):
        return True

    # Check error message keywords
    patterns = [
        r"\b429\b",
        r"resource[_\s]exhausted",
        r"quota[_\s]exceeded",
        r"rate[_\s]limit",
        r"too many requests",
        r"requests per minute",
        r"tokens per minute",
    ]
    for pat in patterns:
        if re.search(pat, err_str):
            return True
    return False


def is_model_deprecated_error(error: Exception) -> bool:
    """
    Detects if a model failed because it was deprecated or not found (HTTP 404).
    """
    if error is None:
        return False
    err_str = str(error).lower()
    code = getattr(error, "code", None) or getattr(error, "status_code", None)
    if code in (404, "404", "NOT_FOUND"):
        return True
    return "not found" in err_str or "publisher model" in err_str or "deprecated" in err_str


def wait_for_rate_limit_cooldown(
    trace_id: str,
    product_id: str,
    stage: str,
    model_name: str,
    attempt: int = 1,
    max_attempts: int = 3,
    project_id: Optional[str] = None,
) -> bool:
    """
    Suspends execution in an interruptible 60-second cooldown loop (+ jitter).
    Surfaces real-time countdown to Firestore for the Control Center UI.
    Listens every 2 seconds for operator [Resume Immediately] or [Abort] actions.
    
    Returns True if execution should retry, False if max attempts exceeded.
    """
    if attempt > max_attempts:
        logger.error(
            f"Trace {trace_id}: Max rate-limit cooldown attempts ({max_attempts}) reached for {stage}. Escalating to failure."
        )
        return False

    # Jittered duration: 60s base + 3-10s random jitter to eliminate thundering herds
    jitter_sec = round(random.uniform(3.0, 10.0), 2)
    cooldown_seconds = 60.0 + jitter_sec
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=cooldown_seconds)
    expires_at_iso = expires_at.isoformat()

    logger.warning(
        f"Trace {trace_id}: Gemini 429 Rate Limit encountered on '{model_name}' ({stage}). "
        f"Entering {int(cooldown_seconds)}s cooldown (attempt {attempt}/{max_attempts})..."
    )

    db = None
    try:
        from google.cloud import firestore
        pid = project_id or os.getenv("PROJECT_ID")
        db = firestore.Client(project=pid) if pid else firestore.Client()
    except Exception as e:
        logger.warning(f"Could not connect to Firestore for cooldown tracking ({e}); using local sleep.")

    # 1. Update Firestore execution record with PAUSED_RATE_LIMIT_COOLDOWN.
    # RT14-15: a compare-and-set write that never touches an ended run (an abort that landed just before the 429
    # cascade): the cooldown raises RunEndedDuringCooldown instead and the stage stops. The status in force before the
    # cooldown is kept in cooldown_state.status_before and put back at the end (never a hardcoded RUNNING).
    status_before = "RUNNING"
    if db and trace_id:
        def _enter(data: Dict[str, Any]) -> Dict[str, Any]:
            nonlocal status_before
            current = str(data.get("status") or "").upper()
            previous_state = data.get("cooldown_state") if isinstance(data.get("cooldown_state"), dict) else {}
            if current and current != COOLDOWN_STATUS:
                status_before = str(data.get("status"))
            elif current == COOLDOWN_STATUS and previous_state.get("status_before"):
                status_before = str(previous_state["status_before"])   # a second cooldown while one is running
            return {
                "status": COOLDOWN_STATUS,
                "cooldown_state": {
                    **previous_state,
                    "is_paused": True,
                    "model_name": model_name,
                    "stage": stage,
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "cooldown_seconds": int(cooldown_seconds),
                    "started_at": now.isoformat(),
                    "expires_at": expires_at_iso,
                    "status_before": status_before,
                    "message": f"Gemini API rate limit hit (429). Cooling down for {int(cooldown_seconds)}s while Vertex AI quota replenishes.",
                },
                "force_resume": False,
                "updated_at": now.isoformat(),
            }
        try:
            _cas_run_write(db, trace_id, stage, _enter)
            logger.info(f"Trace {trace_id}: Updated Firestore state to PAUSED_RATE_LIMIT_COOLDOWN (expires at {expires_at_iso})")
        except RunEndedDuringCooldown as ended:
            logger.warning(f"Trace {trace_id}: run is {ended.status}; no cooldown, stage {stage} stops (RUN_ENDED)")
            raise
        except Exception as e:
            logger.warning(f"Could not update Firestore cooldown state: {e}")

    # 2. Interruptible Sleep Loop (polls every 2 seconds for force_resume or abort)
    poll_interval = 2.0
    elapsed = 0.0
    resumed_early = False

    while elapsed < cooldown_seconds:
        time.sleep(poll_interval)
        elapsed += poll_interval

        if db and trace_id:
            try:
                snap = db.collection("pipeline_executions").document(trace_id).get()
                if snap.exists:
                    data = snap.to_dict() or {}
                    # Check for mid-cooldown abort. RT14-15: every ended status, not only CANCELLED / ABORTED.
                    ended_status = str(data.get("status", "")).upper()
                    if ended_status in RUN_ENDED_STATUSES:
                        logger.warning(f"Trace {trace_id}: Operator aborted build during rate-limit cooldown.")
                        raise RunEndedDuringCooldown(trace_id, ended_status, stage)

                    # Check for operator [Resume Immediately] click
                    if data.get("force_resume") is True:
                        logger.info(f"Trace {trace_id}: Operator clicked [Resume Immediately] after {int(elapsed)}s!")
                        resumed_early = True
                        break
            except RuntimeError:
                raise
            except Exception as poll_err:
                logger.debug(f"Cooldown polling notice: {poll_err}")

    # 3. Restore the status in force before the cooldown. RT14-15: compare-and-set; an ended run is never written (the
    # stage stops), and a status someone else wrote meanwhile (the Resume button, a workflow notify) is kept.
    if db and trace_id:
        restored = {"to": None}

        def _leave(data: Dict[str, Any]) -> Dict[str, Any]:
            previous_state = data.get("cooldown_state") if isinstance(data.get("cooldown_state"), dict) else {}
            fields: Dict[str, Any] = {
                "cooldown_state": {
                    **previous_state,
                    "is_paused": False,
                    "resumed_at": datetime.now(timezone.utc).isoformat(),
                    "resumed_early": resumed_early,
                },
                "force_resume": False,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            if str(data.get("status") or "").upper() == COOLDOWN_STATUS:
                target = str(previous_state.get("status_before") or status_before)
                if target.upper() == COOLDOWN_STATUS:
                    target = "RUNNING"
                fields["status"] = target
                restored["to"] = target
            return fields
        try:
            _cas_run_write(db, trace_id, stage, _leave)
            if restored["to"]:
                logger.info(f"Trace {trace_id}: Cooldown complete. Restored status to {restored['to']}.")
            else:
                logger.info(f"Trace {trace_id}: Cooldown complete; the run status was changed meanwhile and is kept.")
        except RunEndedDuringCooldown as ended:
            logger.warning(f"Trace {trace_id}: run is {ended.status} after the cooldown; stage {stage} stops (RUN_ENDED)")
            raise
        except Exception as e:
            logger.warning(f"Could not restore Firestore state after cooldown: {e}")

    return True
