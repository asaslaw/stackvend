"""BUILD-ADMISSION-QUEUE (G4, owner 11-13): the Control Center side of the build queue.

The decision is shared/build_admission.py (one function, also called by the gateway's intake). Here:
- `admit_run`: the CC's own LLM-heavy dispatches (new Agent-mode workload, Full / Resume Developer relaunch, promotion)
  ask for a slot BEFORE publishing, so the API can answer 202 QUEUED. When the slots look full it first reads the
  holders' workflow executions from the Workflows API (the STALE-RUN-AUTOFAIL-BOUND reconcile in routes/telemetry.py),
  so a run that ended without telling anyone never blocks a submission.
- `reconcile_and_pump`: the reconcile safety net, run on every Flight Deck poll (after the poll's own Workflows-state
  reconcile): releases the slots of ended runs and dispatches queued runs by publishing their stored event to
  spec-intake-events, exactly as the original submission would have.
- `cancel_queued`, `cancel_product_queue`, `queued_runs`, `queue_position`: the queue in the UI.
Plan: docs/planning/build-admission-queue-plan.md.
"""

import concurrent.futures
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException

from shared import build_admission as ba

logger = logging.getLogger("control-center-build-queue")

INTAKE_TOPIC_NAME = "spec-intake-events"
PUBLISH_TIMEOUT_SECONDS = 10.0
_HTTP_STATUS = {ba.BUILD_ALREADY_QUEUED: 409, ba.BUILD_QUEUE_ALREADY_DISPATCHING: 409,
                ba.BUILD_QUEUE_NOT_QUEUED: 409}


def http_error(err: ba.BuildAdmissionError) -> HTTPException:
    return HTTPException(status_code=_HTTP_STATUS.get(err.error_class, 503), detail=err.body())


def _unavailable(message: str) -> HTTPException:
    return http_error(ba.BuildAdmissionError(ba.BUILD_ADMISSION_UNAVAILABLE, message))


def reconcile_holders_with_workflows(db: Any, state: Dict[str, Any]) -> int:
    """Reads the Workflows API state of every slot holder whose run record is still running and bound to an execution
    (routes/telemetry.py `_reconcile_bound_run`, capped reads). A run whose workflow ended is closed on its record, so
    the admission that follows frees its slot. Returns the number of runs closed. Never raises (each failure is
    logged and recorded on the run by the reconcile itself)."""
    from routes import telemetry   # lazy: telemetry imports the workloads stack

    closed = 0
    reader = telemetry._WorkflowStateReader()
    now_dt = datetime.now(timezone.utc)
    for trace_id in list(state.get("holders") or {}):
        try:
            snap = db.collection(ba.RUNS_COLLECTION).document(trace_id).get()
            if getattr(snap, "exists", None) is not True:
                continue
            data = snap.to_dict() or {}
            if str(data.get("status") or "").upper() not in ("ACTIVE", "RUNNING", "PAUSED_RATE_LIMIT_COOLDOWN"):
                continue
            if not (data.get("workflow_execution_name") or data.get("workflow_execution_id")):
                continue
            if not reader.take():
                break
            if telemetry._reconcile_bound_run(snap, data, trace_id, now_dt, reader):
                closed += 1
        except Exception as err:  # noqa: BLE001 - the next poll checks again
            logger.warning(f"Build slot holder {trace_id}: workflow state not reconciled ({type(err).__name__}: {err})")
    return closed


def admit_run(db: Any, *, trace_id: str, product_id: str, payload: Dict[str, Any], source: str,
              one_per_product: bool = False, request_status_on_dispatch: Optional[str] = None,
              queued_record: Optional[Dict[str, Any]] = None, overwrite_record: bool = False) -> ba.Admission:
    """The CC's admission call. `queued_record`: the run record written (before the run joins the queue) when it has to
    wait: created only if absent, or set as given with `overwrite_record` (a relaunch pre-seed). Raises HTTPException:
    503 BUILD_ADMISSION_UNAVAILABLE (store down: nothing is published), 409 BUILD_ALREADY_QUEUED (a relaunch of a
    workload that already has a queued run; nothing is written)."""
    if db is None:
        raise _unavailable("Firestore is unavailable: the build cannot be admitted")
    try:
        limit = ba.read_limit(db)
        state = ba.read_state(db)
        if len(state["holders"]) >= limit:
            reconcile_holders_with_workflows(db, state)

        def write_record():
            if queued_record is None:
                return
            if overwrite_record:
                db.collection(ba.RUNS_COLLECTION).document(trace_id).set(queued_record)
            else:
                ba.create_queued_run_record(db, queued_record)

        admission = ba.admit(db, trace_id, product_id=product_id, payload=payload, source=source, limit=limit,
                             one_per_product=one_per_product, request_status_on_dispatch=request_status_on_dispatch,
                             before_queue=write_record)
    except ba.BuildAdmissionError as err:
        logger.error(f"{err.error_class}: build {trace_id} of '{product_id}' not admitted: {err.message}")
        raise http_error(err)
    if admission.state == ba.ALREADY_QUEUED:
        raise HTTPException(status_code=409, detail={
            "code": ba.BUILD_ALREADY_QUEUED, "error_class": ba.BUILD_ALREADY_QUEUED, "stage": "build_admission",
            "queued_trace_id": admission.queued_trace_id, "position": admission.position,
            "message": (f"Workload '{product_id}' already has a build waiting in the queue (trace "
                        f"{admission.queued_trace_id}, #{admission.position} in line). Cancel it first, or wait for "
                        f"it to start.")})
    return admission


def resume_after_approval(db: Any, record: Dict[str, Any], approval_id: str, callback_url: str,
                          callback_payload: Dict[str, Any], decision: str) -> Optional[ba.Admission]:
    """F2 option A (owner 11-14): before an approved (or reworked) run's callback is delivered, the run takes a build
    slot again through the same admission accounting. None or RESUME_NOW / RESUME_NOT_HELD: deliver now. QUEUED: the
    run waits at the head of the queue and the pump delivers the callback when a slot frees. Store unavailable -> 503
    (the decision is released and can be retried; nothing is delivered without accounting)."""
    trace_id = record.get("trace_id")
    if db is None or not isinstance(trace_id, str) or not trace_id:
        return None
    stage = ba.APPROVAL_TYPE_WAIT_STAGE.get(str(record.get("approval_type") or ""))
    try:
        admission = ba.resume(db, trace_id, stage=stage, callback_url=callback_url, callback_payload=callback_payload,
                              approval_id=approval_id, decision=decision)
    except ba.BuildAdmissionError as err:
        logger.error(f"{err.error_class}: approved run {trace_id} not resumed: {err.message}")
        raise http_error(err)
    if admission.state == ba.QUEUED and admission.pump_needed:
        reconcile_and_pump(db)
    return admission


def slot_annotations(db: Any) -> Tuple[Dict[str, Any], int]:
    """(state, limit) for annotating running runs (waiting for a person / approved and waiting for a slot); ({}, 1)
    when unreadable (logged)."""
    try:
        return ba.read_state(db), ba.read_limit(db)
    except Exception as err:  # noqa: BLE001
        logger.warning(f"Build queue unreadable for annotations ({type(err).__name__})")
        return {}, 1


def release_after_abort(db: Any, trace_id: str) -> None:
    """An aborted run frees its slot (or leaves the waiting list / the queue) at once and the next build starts. Never
    raises: the release rule frees it from the ABORTED record on the next admission or poll."""
    if db is None:
        return
    try:
        ba.release(db, trace_id, reason="ABORTED")
        reconcile_and_pump(db)
    except Exception as err:  # noqa: BLE001
        logger.error(f"{ba.BUILD_ADMISSION_UNAVAILABLE}: slot of aborted run {trace_id} not released now "
                     f"({type(err).__name__}: {err})")


def mark_request_queued(db: Any, request_id: Optional[str], fields: Dict[str, Any]) -> None:
    """The feature request of a queued run shows QUEUED (dispatch moves it on). Logged on failure."""
    if not request_id or db is None:
        return
    try:
        db.collection(ba.REQUESTS_COLLECTION).document(request_id).set(dict(fields, status=ba.RUN_STATUS_QUEUED),
                                                                         merge=True)
    except Exception as err:  # noqa: BLE001
        logger.error(f"feature_requests/{request_id} not marked QUEUED ({type(err).__name__}: {err})")


def _project() -> str:
    from config import PROJECT_ID
    return PROJECT_ID or os.getenv("PROJECT_ID", "")


def _gate(db: Any) -> Optional[str]:
    """Why queued builds must not be dispatched now, else None: the emergency stop (unreadable = stop) or maintenance
    mode / unreadable settings (shared.settings.new_run_refusal)."""
    try:
        snap = db.collection("governance").document("platform_kill_switch").get()
        data = (snap.to_dict() or {}) if getattr(snap, "exists", None) is True else {}
        if not isinstance(data, dict):
            return "kill switch record is malformed"
        if data.get("emergency_stop_active") is True:
            return "platform emergency stop is active"
    except Exception as err:  # noqa: BLE001
        return f"kill switch unreadable ({type(err).__name__})"
    try:
        from routes.settings import get_platform_settings, new_run_refusal
        refusal = new_run_refusal("dispatch of a queued build", read=get_platform_settings)
    except Exception as err:  # noqa: BLE001
        return f"settings unreadable ({type(err).__name__})"
    return str(refusal.get("code") or "maintenance") if refusal is not None else None


def pump(db: Any, *, publisher: Any = None, project: Optional[str] = None) -> List[Dict[str, Any]]:
    """Dispatches queued builds into free slots by publishing their stored intake event (the gateway's intake finds the
    run already holding its slot). A publish that raises fails the run (BUILD_DISPATCH_FAILED); one that times out
    keeps the slot (the event may still arrive). Raises BuildAdmissionError when the store is unavailable."""
    state = ba.read_state(db)
    if not state["queue"]:
        if state["holders"]:
            ba.promote(db)   # nothing waits: only release the slots of runs that have ended
        return []
    if publisher is None:
        from db import get_pubsub_publisher
        publisher = get_pubsub_publisher()
    project = project or _project()
    if not publisher or not project:
        logger.warning("Queued builds not dispatched: no Pub/Sub publisher or PROJECT_ID on this Control Center")
        return []
    topic = f"projects/{project}/topics/{INTAKE_TOPIC_NAME}"

    def dispatch(entry: Dict[str, Any]) -> str:
        data = json.dumps(entry["payload"]).encode("utf-8")
        try:
            future = publisher.publish(topic, data)
            future.result(timeout=PUBLISH_TIMEOUT_SECONDS)
        except (TimeoutError, concurrent.futures.TimeoutError):
            return ba.OUTCOME_UNKNOWN
        except Exception as err:  # noqa: BLE001 - RT F1: a publish error is transient: requeued at the head
            raise ba.BuildDispatchRetryable(f"publish failed ({type(err).__name__}: {err})")
        return ba.DISPATCHED

    return ba.pump(db, dispatch, gate=lambda: _gate(db))


def reconcile_and_pump(db: Any) -> List[Dict[str, Any]]:
    """The Flight Deck poll's safety net. Never raises (logged)."""
    if db is None:
        return []
    try:
        return pump(db)
    except Exception as err:  # noqa: BLE001
        logger.error(f"{ba.BUILD_ADMISSION_UNAVAILABLE}: build queue not reconciled on this poll "
                     f"({type(err).__name__}: {err})")
        return []


def queued_runs(db: Any, product_id: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """(run records of the queued builds in queue order, each with `build_queue` {state, position, ahead, limit,
    running}; summary {limit, running, queued}). ([], None) when the queue cannot be read (logged)."""
    if db is None:
        return [], None
    try:
        view = ba.queue_view(db)
    except Exception as err:  # noqa: BLE001
        logger.error(f"Build queue unreadable ({type(err).__name__}: {err})")
        return [], None
    runs = []
    for item in view["queue"]:
        if product_id and item.get("product_id") != product_id:
            continue
        if item.get("kind") == ba.KIND_RESUME:
            continue   # F2: an approved run waiting for a slot is a running run (annotated in the active list)
        try:
            snap = db.collection(ba.RUNS_COLLECTION).document(item["trace_id"]).get()
            record = (snap.to_dict() or {}) if getattr(snap, "exists", None) is True else {}
        except Exception as err:  # noqa: BLE001
            logger.warning(f"Queued run record {item['trace_id']} unreadable ({type(err).__name__})")
            record = {}
        record = dict(record) if isinstance(record, dict) else {}
        record.setdefault("trace_id", item["trace_id"])
        record.setdefault("product_id", item.get("product_id") or "")
        record.setdefault("started_at", item.get("submitted_at") or "")
        record["status"] = ba.RUN_STATUS_QUEUED
        record["current_stage"] = ba.RUN_STATUS_QUEUED
        record["build_queue"] = {"state": ba.QUEUED, "position": item["position"], "ahead": item["ahead"],
                                 "limit": view["limit"], "running": view["running"]}
        runs.append(record)
    return runs, {"limit": view["limit"], "running": view["running"], "queued": len(view["queue"])}


def queue_position(db: Any, trace_id: str) -> Optional[Dict[str, Any]]:
    """The `build_queue` object of a queued run, None when it is not in the queue or the queue is unreadable."""
    try:
        view = ba.queue_view(db)
    except Exception as err:  # noqa: BLE001
        logger.warning(f"Build queue unreadable ({type(err).__name__})")
        return None
    for item in view["queue"]:
        if item["trace_id"] == trace_id:
            return {"state": ba.QUEUED, "position": item["position"], "ahead": item["ahead"],
                    "limit": view["limit"], "running": view["running"]}
    return None


def cancel_queued(db: Any, trace_id: str, by: str) -> Dict[str, Any]:
    """Cancels a queued run. Raises BuildAdmissionError (BUILD_QUEUE_ALREADY_DISPATCHING / BUILD_QUEUE_NOT_QUEUED /
    BUILD_ADMISSION_UNAVAILABLE) for the caller to map."""
    return ba.cancel(db, trace_id, by=by)


def cancel_product_queue(db: Any, product_id: str, by: str) -> List[str]:
    """Decommission / archive cascade: cancels the workload's queued runs. Never raises: a failure is logged at ERROR
    (the pump still refuses to dispatch into a DECOMMISSIONED / ARCHIVED workload: BUILD_QUEUE_WORKLOAD_GONE)."""
    if db is None:
        return []
    try:
        cancelled = ba.cancel_product(db, product_id, by=by)
    except Exception as err:  # noqa: BLE001
        logger.error(f"{ba.BUILD_ADMISSION_UNAVAILABLE}: queued builds of '{product_id}' not cancelled "
                     f"({type(err).__name__}: {err}); they fail with {ba.BUILD_QUEUE_WORKLOAD_GONE} at dispatch")
        return []
    if cancelled:
        logger.info(f"Cancelled {len(cancelled)} queued build(s) of '{product_id}': {cancelled}")
    return cancelled
