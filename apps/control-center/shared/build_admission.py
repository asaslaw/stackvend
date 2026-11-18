"""BUILD-ADMISSION-QUEUE (G4, owner 11-13): one admission function for every LLM-heavy pipeline run.

Plan: docs/planning/build-admission-queue-plan.md. Byte-identical copies: shared/, apps/control-center/shared/,
apps/orchestrator-gateway/shared/ (tests/test_build_admission_queue.py::test_copies_are_byte_identical).

A run asks for a slot at intake, never inside a running stage. `orchestration.max_concurrent_builds` (default 1) runs
hold a slot at a time; the others wait in a FIFO queue and are dispatched when a slot frees.

Accounting lives in ONE Firestore document, `system_config/build_admission`:
    holders: {trace_id: {product_id, acquired_at, source, via}}
    queue:   [{trace_id, product_id, submitted_at, source}, ...]     (index + 1 = position)
Every change is a compare-and-set on that document (create() when absent, else update() with a last_update_time
precondition; a conflict re-reads and decides again), so any number of Control Center / gateway instances agree and
nothing is counted in memory. The payload of a queued run is kept in `build_queue/{trace_id}`.

A slot is released when the run's `pipeline_executions/{trace_id}` record is terminal (any status other than the ones
in RUN_STATUSES_HOLDING_A_SLOT), or, when no workflow execution was ever bound to it, DISPATCH_GRACE_SECONDS after the
slot was taken (BUILD_DISPATCH_LOST; the run record is failed with that class, never freed silently).

Fail loudly: a store that cannot be read or written raises BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE); a limit
that cannot be read is 1 with a WARNING, never unlimited.
"""

from __future__ import annotations

import logging
import random
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

STATE_COLLECTION = "system_config"
STATE_DOCUMENT = "build_admission"
SETTINGS_DOCUMENT = "platform_settings"
QUEUE_COLLECTION = "build_queue"
RUNS_COLLECTION = "pipeline_executions"
REQUESTS_COLLECTION = "feature_requests"
WORKLOADS_COLLECTION = "workloads"

DEFAULT_MAX_CONCURRENT_BUILDS = 1
MAX_CONCURRENT_BUILDS_CEILING = 20
DISPATCH_GRACE_SECONDS = 1200   # beyond Pub/Sub's retry-to-DLQ window (~2.5 min) and any publish wait
CAS_ATTEMPTS = 8
CAS_BACKOFF_BASE_SECONDS = 0.05   # RT F6: jittered backoff between attempts, uniform(0, min(1, base * 2**attempt))
CAS_BACKOFF_CAP_SECONDS = 1.0
_sleep = time.sleep               # test seam
PUMP_MAX_ROUNDS = 10
MAX_DISPATCH_ATTEMPTS = 3   # RT F1: a queued run whose start fails transiently is requeued at the head; FAILED on the 3rd

# Admission outcomes
ADMITTED = "ADMITTED"
QUEUED = "QUEUED"
ALREADY_QUEUED = "ALREADY_QUEUED"

# The run-record status of a queued run (pipeline_executions/{trace}.status).
RUN_STATUS_QUEUED = "QUEUED"
# Run statuses that keep a slot held. Anything else (SUCCEEDED, FAILED, ABORTED, CANCELLED, REJECTED, ...) frees it.
RUN_STATUSES_HOLDING_A_SLOT = frozenset({"ACTIVE", "RUNNING", "PAUSED_RATE_LIMIT_COOLDOWN", RUN_STATUS_QUEUED})
# Execution modes that run no LLM stage (Fast-Path: terraform only) and never wait for a slot.
BYPASS_EXECUTION_MODES = frozenset({"DEPLOY_ONLY"})
# BUILD-ADMISSION-QUEUE F2 option A (owner 11-14): the exact `current_stage` values the workflow posts while it waits
# for a person (workflows/main_orchestrator.yaml notify_plan_approval_pending, the quota gate, the release pull request
# approval). A run entering one gives its slot up ("parked"); when the approval is granted it takes one again through
# resume(), at the head of the queue when none is free.
APPROVAL_WAIT_STAGES = frozenset({"AWAITING_PLAN_APPROVAL", "QUOTA_PAUSED", "AWAITING_PR_APPROVAL"})
# The wait each approval type ends (the Control Center's approval records).
APPROVAL_TYPE_WAIT_STAGE = {"ARCHITECTURAL_PLAN": "AWAITING_PLAN_APPROVAL", "QUOTA_GATE": "QUOTA_PAUSED",
                            "PR_MERGE": "AWAITING_PR_APPROVAL", "PULL_REQUEST": "AWAITING_PR_APPROVAL"}
KIND_RESUME = "resume"   # a queue item that resumes an approved run (delivers its approval callback)
PARKED = "PARKED"
RESUME_NOW = "RESUME_NOW"
RESUME_NOT_HELD = "RESUME_NOT_HELD"   # the run never held a slot (admitted before the queue existed, Fast-Path)

# Workload statuses a queued run is never dispatched into.
WORKLOAD_GONE_STATUSES = frozenset({"DECOMMISSIONED", "ARCHIVED"})

# build_queue/{trace}.status
ENTRY_QUEUED = "QUEUED"
ENTRY_DISPATCHING = "DISPATCHING"
ENTRY_DISPATCHED = "DISPATCHED"
ENTRY_OUTCOME_UNKNOWN = "DISPATCH_OUTCOME_UNKNOWN"
ENTRY_FAILED = "FAILED"
ENTRY_CANCELLED = "CANCELLED"

# Dispatcher answers
DISPATCHED = "DISPATCHED"
OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"

# Typed error classes
BUILD_ADMISSION_UNAVAILABLE = "BUILD_ADMISSION_UNAVAILABLE"
BUILD_ALREADY_QUEUED = "BUILD_ALREADY_QUEUED"
BUILD_QUEUE_ALREADY_DISPATCHING = "BUILD_QUEUE_ALREADY_DISPATCHING"
BUILD_QUEUE_NOT_QUEUED = "BUILD_QUEUE_NOT_QUEUED"
BUILD_QUEUE_CANCELLED = "BUILD_QUEUE_CANCELLED"
BUILD_QUEUE_WORKLOAD_GONE = "BUILD_QUEUE_WORKLOAD_GONE"
BUILD_DISPATCH_FAILED = "BUILD_DISPATCH_FAILED"
BUILD_DISPATCH_REFUSED = "BUILD_DISPATCH_REFUSED"
BUILD_DISPATCH_LOST = "BUILD_DISPATCH_LOST"


class BuildAdmissionError(RuntimeError):
    """A typed admission failure (error_class + stage). Never a silent pass."""

    def __init__(self, error_class: str, message: str, *, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"{error_class}: {message}")
        self.error_class = error_class
        self.stage = "build_admission"
        self.message = message
        self.details = dict(details or {})

    def body(self) -> Dict[str, Any]:
        return {"code": self.error_class, "error_class": self.error_class, "stage": self.stage,
                "message": self.message, **self.details}


class BuildDispatchRefused(RuntimeError):
    """Raised by a dispatcher when the run was refused (not a transport failure): the run is failed with this class."""

    def __init__(self, error_class: str, detail: str):
        super().__init__(f"{error_class}: {detail}")
        self.error_class = error_class
        self.detail = detail


class BuildDispatchRetryable(RuntimeError):
    """Raised by a dispatcher for a transient failure (a 5xx while starting the run, a publish error): the run goes
    back to the head of the queue and is retried on the next trigger; the MAX_DISPATCH_ATTEMPTS-th failure fails it
    (BUILD_DISPATCH_FAILED). The queued run keeps the retries Pub/Sub gives an admitted one (RT F1)."""

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class Admission:
    """The answer of admit(): state ADMITTED / QUEUED / ALREADY_QUEUED, with the queue position when queued."""

    def __init__(self, state: str, trace_id: str, *, limit: int, running: int, position: Optional[int] = None,
                 queued_trace_id: Optional[str] = None, already: bool = False, pump_needed: bool = False,
                 released: Optional[List[Tuple[str, str]]] = None):
        self.state = state
        self.trace_id = trace_id
        self.limit = limit
        self.running = running
        self.position = position
        self.queued_trace_id = queued_trace_id
        self.already = already
        self.pump_needed = pump_needed
        self.released = list(released or [])

    def view(self) -> Dict[str, Any]:
        """The `build_queue` object of an API answer."""
        out: Dict[str, Any] = {"state": self.state, "trace_id": self.trace_id, "limit": self.limit,
                               "running": self.running}
        if self.position is not None:
            out["position"] = self.position
            out["ahead"] = self.position - 1
        if self.queued_trace_id:
            out["queued_trace_id"] = self.queued_trace_id
        return out


# ------------------------------------------------------------------------------------------------ small helpers
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_time(value: Any) -> Optional[datetime]:
    try:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str) and value:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    return None


def _snapshot_data(snap: Any, what: str) -> Optional[Dict[str, Any]]:
    """A Firestore snapshot's mapping, None when the document does not exist. Anything that is not a readable snapshot
    raises BuildAdmissionError (fail closed: no accounting decision on data that cannot be read)."""
    exists = getattr(snap, "exists", None)
    if exists is False:
        return None
    if exists is not True:
        raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, f"{what} is not a readable Firestore document")
    data = snap.to_dict()
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, f"{what} is not a mapping ({type(data).__name__})")
    return data


def _is_conflict(err: BaseException) -> bool:
    """A compare-and-set lost to a concurrent writer (create() on an existing document, a stale precondition)."""
    try:
        from google.api_core import exceptions as gexc
    except ImportError:  # pragma: no cover - google-api-core ships with every Firestore client
        return False
    return isinstance(err, (gexc.AlreadyExists, gexc.FailedPrecondition, gexc.Aborted, gexc.Conflict))


def requires_admission(payload: Any) -> bool:
    """True for a run that needs a slot: every execution mode except the 0-LLM Fast-Path (DEPLOY_ONLY)."""
    mode = str((payload or {}).get("execution_mode") or "FULL").strip().upper() if isinstance(payload, dict) else "FULL"
    return mode not in BYPASS_EXECUTION_MODES


def valid_limit(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)
            and DEFAULT_MAX_CONCURRENT_BUILDS <= value <= MAX_CONCURRENT_BUILDS_CEILING)


def read_limit(db: Any) -> int:
    """`orchestration.max_concurrent_builds` from system_config/platform_settings. No document or no value: the
    default (1). Unreadable or invalid: 1 with a WARNING, never unlimited."""
    try:
        snap = db.collection(STATE_COLLECTION).document(SETTINGS_DOCUMENT).get()
        data = _snapshot_data(snap, "system_config/platform_settings")
        if data is None:
            return DEFAULT_MAX_CONCURRENT_BUILDS
        orch = data.get("orchestration")
        if orch is None:
            return DEFAULT_MAX_CONCURRENT_BUILDS
        if not isinstance(orch, dict):
            raise TypeError(f"orchestration is {type(orch).__name__}, not a mapping")
        value = orch.get("max_concurrent_builds")
        if value is None:
            return DEFAULT_MAX_CONCURRENT_BUILDS
        if valid_limit(value):
            return value
        logger.warning(f"orchestration.max_concurrent_builds={value!r} is not an integer from "
                       f"{DEFAULT_MAX_CONCURRENT_BUILDS} to {MAX_CONCURRENT_BUILDS_CEILING}; using "
                       f"{DEFAULT_MAX_CONCURRENT_BUILDS}")
        return DEFAULT_MAX_CONCURRENT_BUILDS
    except Exception as err:  # noqa: BLE001 - unreadable: the safe default, logged
        logger.warning(f"orchestration.max_concurrent_builds could not be read ({type(err).__name__}: {err}); "
                       f"using {DEFAULT_MAX_CONCURRENT_BUILDS}")
        return DEFAULT_MAX_CONCURRENT_BUILDS


# ------------------------------------------------------------------------------------------------ state document
def _state_ref(db: Any) -> Any:
    return db.collection(STATE_COLLECTION).document(STATE_DOCUMENT)


def _entry_ref(db: Any, trace_id: str) -> Any:
    return db.collection(QUEUE_COLLECTION).document(trace_id)


def _parse_state(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if data is None:
        return {"holders": {}, "queue": [], "waiting": {}}
    holders = data.get("holders") or {}
    queue = data.get("queue") or []
    waiting = data.get("waiting") or {}
    if not isinstance(waiting, dict) or not all(isinstance(k, str) and isinstance(v, dict) for k, v in waiting.items()):
        raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, "system_config/build_admission.waiting is malformed")
    if not isinstance(holders, dict) or not all(isinstance(k, str) and isinstance(v, dict) for k, v in holders.items()):
        raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, "system_config/build_admission.holders is malformed")
    if not isinstance(queue, list) or not all(isinstance(q, dict) and isinstance(q.get("trace_id"), str)
                                              for q in queue):
        raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, "system_config/build_admission.queue is malformed")
    return {"holders": {k: dict(v) for k, v in holders.items()}, "queue": [dict(q) for q in queue],
            "waiting": {k: dict(v) for k, v in waiting.items()}}


def read_state(db: Any) -> Dict[str, Any]:
    """{holders, queue} as stored (empty when there is no document). Raises BuildAdmissionError when unreadable."""
    try:
        snap = _state_ref(db).get()
    except Exception as err:  # noqa: BLE001
        raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE,
                                  f"system_config/build_admission unreadable ({type(err).__name__}: {err})") from err
    return _parse_state(_snapshot_data(snap, "system_config/build_admission"))


def _own_write_landed(ref: Any, token: str) -> bool:
    """RT F4: after a conflict, True when the stored document carries this write's `cas_token`: the client's commit
    retry (on UNAVAILABLE) failed against our own write, which had already committed."""
    try:
        data = _snapshot_data(ref.get(), "system_config/build_admission")
    except BuildAdmissionError:
        raise
    except Exception as err:  # noqa: BLE001
        raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, f"system_config/build_admission unreadable after a "
                                                               f"conflict ({type(err).__name__}: {err})") from err
    return bool(data) and data.get("cas_token") == token


def _cas(db: Any, decide: Callable[[Dict[str, Any]], Tuple[Any, bool]]) -> Any:
    """Read the state document, let `decide(state)` change it in place and return (result, changed), then write it
    only if nobody wrote in between; a conflict re-reads and decides again. Returns decide's result. Every write
    carries its own `cas_token`, so a write that committed but was reported as a conflict (a retried commit) is
    recognised as ours and its decision is returned (RT F4)."""
    ref = _state_ref(db)
    for _attempt in range(CAS_ATTEMPTS):
        try:
            snap = ref.get()
        except Exception as err:  # noqa: BLE001
            raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, f"system_config/build_admission unreadable "
                                                                   f"({type(err).__name__}: {err})") from err
        data = _snapshot_data(snap, "system_config/build_admission")
        state = _parse_state(data)
        result, changed = decide(state)
        if not changed:
            return result
        token = uuid.uuid4().hex
        body = {"holders": state["holders"], "queue": state["queue"], "waiting": state.get("waiting") or {},
                "updated_at": _iso(_now()), "cas_token": token}
        try:
            if data is None:
                ref.create(body)
            else:
                ref.update(body, option=db.write_option(last_update_time=snap.update_time))
            return result
        except Exception as err:  # noqa: BLE001
            if _is_conflict(err):
                if _own_write_landed(ref, token):
                    return result
                _sleep(random.uniform(0, min(CAS_BACKOFF_CAP_SECONDS, CAS_BACKOFF_BASE_SECONDS * 2 ** _attempt)))
                continue
            raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, f"system_config/build_admission not written "
                                                                   f"({type(err).__name__}: {err})") from err
    raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE,
                              f"system_config/build_admission kept changing during {CAS_ATTEMPTS} attempts")


def _release_reason(db: Any, trace_id: str, holder: Dict[str, Any], now: datetime) -> Optional[str]:
    """Why a holder's slot is free, else None: RUN_ENDED:<status> when its run record is terminal; BUILD_DISPATCH_LOST
    when no workflow execution was bound to it within DISPATCH_GRACE_SECONDS of taking the slot."""
    try:
        snap = db.collection(RUNS_COLLECTION).document(trace_id).get()
    except Exception as err:  # noqa: BLE001
        raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, f"run record {trace_id} unreadable "
                                                               f"({type(err).__name__}: {err})") from err
    record = _snapshot_data(snap, f"pipeline_executions/{trace_id}")
    if record is not None:
        status = str(record.get("status") or "").upper()
        if status and status not in RUN_STATUSES_HOLDING_A_SLOT:
            return f"RUN_ENDED:{status}"
        if record.get("workflow_execution_name") or record.get("workflow_execution_id"):
            return None
    acquired = _parse_time(holder.get("acquired_at"))
    if acquired is None or (now - acquired).total_seconds() > DISPATCH_GRACE_SECONDS:
        return BUILD_DISPATCH_LOST
    return None


def _run_ended(db: Any, trace_id: str) -> bool:
    """True when the run record is terminal (a status that holds no slot). Unreadable raises (fail closed)."""
    try:
        snap = db.collection(RUNS_COLLECTION).document(trace_id).get()
    except Exception as err:  # noqa: BLE001
        raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, f"run record {trace_id} unreadable "
                                                               f"({type(err).__name__}: {err})") from err
    record = _snapshot_data(snap, f"pipeline_executions/{trace_id}")
    status = str((record or {}).get("status") or "").upper()
    return bool(status) and status not in RUN_STATUSES_HOLDING_A_SLOT


def _release_ended(db: Any, state: Dict[str, Any], now: datetime) -> List[Tuple[str, str]]:
    released = []
    for trace_id, holder in list(state["holders"].items()):
        reason = _release_reason(db, trace_id, holder, now)
        if reason:
            state["holders"].pop(trace_id, None)
            released.append((trace_id, reason))
    # F2: a run that waited for a person, or for a slot after its approval, and ended meanwhile (rejected, the approval
    # timed out, aborted) leaves the waiting list and the queue; it never takes a slot again.
    for trace_id in list(state.get("waiting") or {}):
        if _run_ended(db, trace_id):
            state["waiting"].pop(trace_id, None)
            released.append((trace_id, "WAIT_ENDED"))
    for item in list(state["queue"]):
        if item.get("kind") == KIND_RESUME and _run_ended(db, item["trace_id"]):
            state["queue"].remove(item)
            released.append((item["trace_id"], "WAIT_ENDED"))
    return released


def _after_release(db: Any, released: List[Tuple[str, str]]) -> None:
    """Log every release; a lost dispatch also fails its run record (typed), never a silent free."""
    for trace_id, reason in released:
        if reason != BUILD_DISPATCH_LOST:
            logger.info(f"Build slot of {trace_id} released ({reason})")
            continue
        detail = (f"No workflow execution started for this run within {DISPATCH_GRACE_SECONDS // 60} minutes of its "
                  f"build slot being granted; the slot was released.")
        logger.error(f"{BUILD_DISPATCH_LOST}: {trace_id}: {detail}")
        _fail_records(db, trace_id, BUILD_DISPATCH_LOST, detail, only_if_unbound=True)


def _position(state: Dict[str, Any], trace_id: str) -> Optional[int]:
    for idx, item in enumerate(state["queue"]):
        if item.get("trace_id") == trace_id:
            return idx + 1
    return None


# ------------------------------------------------------------------------------------------------ admission
def admit(db: Any, trace_id: str, *, product_id: str, payload: Dict[str, Any], source: str,
          limit: Optional[int] = None, one_per_product: bool = False,
          request_status_on_dispatch: Optional[str] = None, before_queue: Optional[Callable[[], Any]] = None,
          now: Optional[datetime] = None) -> Admission:
    """The one admission decision. Idempotent per trace_id (a holder stays ADMITTED, a queued run stays QUEUED).
    Releases the slots of runs that have ended first. A free slot is granted only when nobody is waiting (FIFO:
    a newcomer never jumps the queue; `pump_needed` tells the caller to dispatch the head). Over the limit the run is
    queued with its payload. `one_per_product`: a queued run of the same workload -> ALREADY_QUEUED.
    `before_queue()` runs after the payload is stored and before the run joins the queue (the caller writes its QUEUED
    run record there, so a pump on another instance never dispatches a run whose record is not written yet); it may
    run for a run that is then admitted after all (a slot freed in between), so it must leave the record in a state
    the dispatch accepts (the gateway takes a QUEUED record over at dispatch)."""
    if not isinstance(trace_id, str) or not trace_id.strip():
        raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, "a run needs a trace_id to be admitted")
    limit = read_limit(db) if limit is None else limit
    now = now or _now()
    entry_written = {"done": False}

    def decide(state):
        if trace_id in state["holders"]:
            return Admission(ADMITTED, trace_id, limit=limit, running=len(state["holders"]), already=True), False
        pos = _position(state, trace_id)
        if pos is not None:
            return Admission(QUEUED, trace_id, limit=limit, running=len(state["holders"]), position=pos,
                             already=True), False
        if one_per_product:
            for item in state["queue"]:
                if item.get("product_id") == product_id:
                    return Admission(ALREADY_QUEUED, trace_id, limit=limit, running=len(state["holders"]),
                                     queued_trace_id=item.get("trace_id"),
                                     position=_position(state, item.get("trace_id"))), False
        released = _release_ended(db, state, now)
        if len(state["holders"]) < limit and not state["queue"]:
            state["holders"][trace_id] = {"product_id": product_id, "acquired_at": _iso(now), "source": source,
                                          "via": "intake"}
            return Admission(ADMITTED, trace_id, limit=limit, running=len(state["holders"]),
                             released=released), True
        if not entry_written["done"]:
            return None, False   # the payload must be stored before the run joins the queue
        state["queue"].append({"trace_id": trace_id, "product_id": product_id, "submitted_at": _iso(now),
                               "source": source})
        return Admission(QUEUED, trace_id, limit=limit, running=len(state["holders"]),
                         position=len(state["queue"]), pump_needed=len(state["holders"]) < limit,
                         released=released), True

    queue_writes_started = False
    try:
        for _round in range(2):
            result = _cas(db, decide)
            if result is not None:
                break
            queue_writes_started = True
            _write_entry(db, trace_id, product_id=product_id, payload=payload, source=source, now=now,
                         request_status_on_dispatch=request_status_on_dispatch)
            if before_queue is not None:
                try:
                    before_queue()
                except BuildAdmissionError:
                    raise
                except Exception as err:  # noqa: BLE001
                    raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, f"the queued run record of {trace_id} was "
                                                                           f"not written ({type(err).__name__}: {err})"
                                              ) from err
            entry_written["done"] = True
        else:  # pragma: no cover - the second round always decides
            raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, f"admission of {trace_id} did not decide")
    except BuildAdmissionError:
        if queue_writes_started:
            # RT F5: the run never joined the queue (the caller answers 503 / Pub/Sub retries): what it wrote for the
            # queue is removed. Both documents belong to this trace; the record goes only while QUEUED and unbound.
            _drop_entry(db, trace_id)
            _drop_unstarted_record(db, trace_id)
        raise
    if entry_written["done"] and result.state == ADMITTED and not result.already:
        _drop_entry(db, trace_id)   # a slot freed between the two rounds: the run is dispatched directly
    if entry_written["done"] and result.state == ALREADY_QUEUED:
        # another run of the workload joined the queue between the two rounds: this one is refused, so what it
        # wrote for the queue is removed (its trace id is its own: nothing else wrote these documents)
        _drop_entry(db, trace_id)
        _drop_unstarted_record(db, trace_id)
    _after_release(db, result.released)
    if result.state == QUEUED and not result.already:
        logger.warning(f"Build {trace_id} of '{product_id}' QUEUED at position {result.position} "
                       f"({result.running}/{limit} build slots in use)")
    return result


def _write_entry(db: Any, trace_id: str, *, product_id: str, payload: Dict[str, Any], source: str, now: datetime,
                 request_status_on_dispatch: Optional[str]) -> None:
    entry = {"trace_id": trace_id, "product_id": product_id, "payload": dict(payload or {}), "source": source,
             "submitted_at": _iso(now), "status": ENTRY_QUEUED,
             "request_id": (payload or {}).get("request_id") if isinstance(payload, dict) else None,
             "request_status_on_dispatch": request_status_on_dispatch}
    try:
        _entry_ref(db, trace_id).set(entry)
    except Exception as err:  # noqa: BLE001
        raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, f"build_queue/{trace_id} not written "
                                                               f"({type(err).__name__}: {err})") from err


def _drop_entry(db: Any, trace_id: str) -> None:
    try:
        _entry_ref(db, trace_id).delete()
    except Exception as err:  # noqa: BLE001 - an unused entry is never read (not in the queue)
        logger.warning(f"Unused build_queue/{trace_id} not deleted ({type(err).__name__}: {err})")


def _drop_unstarted_record(db: Any, trace_id: str) -> None:
    ref = db.collection(RUNS_COLLECTION).document(trace_id)
    try:
        record = _snapshot_data(ref.get(), f"pipeline_executions/{trace_id}")
        if record is not None and record.get("status") == RUN_STATUS_QUEUED and not (
                record.get("workflow_execution_name") or record.get("workflow_execution_id")):
            ref.delete()
    except Exception as err:  # noqa: BLE001
        logger.warning(f"Unused queued run record {trace_id} not deleted ({type(err).__name__}: {err})")


def _set_entry(db: Any, trace_id: str, fields: Dict[str, Any]) -> None:
    try:
        _entry_ref(db, trace_id).set(dict(fields, updated_at=_iso(_now())), merge=True)
    except Exception as err:  # noqa: BLE001 - the state document is the authority; logged
        logger.error(f"build_queue/{trace_id} not updated to {fields.get('status')} ({type(err).__name__}: {err})")


# ------------------------------------------------------------------------------------------------ records
def queued_run_record(*, trace_id: str, product_id: str, title: str, execution_mode: str, source: str,
                      now_iso: str, request_id: Optional[str] = None, position: Optional[int] = None) -> Dict[str, Any]:
    """The pipeline_executions record of a run that waits for a build slot (no stages: the dispatch writes them)."""
    record: Dict[str, Any] = {
        "trace_id": trace_id, "product_id": product_id, "feature_title": title,
        "status": RUN_STATUS_QUEUED, "current_stage": RUN_STATUS_QUEUED,
        "queued_at": now_iso, "started_at": now_iso, "completed_at": None, "elapsed_seconds": 0.0,
        "execution_mode": execution_mode, "source_channel": source,
    }
    if request_id:
        record["request_id"] = request_id
    if position is not None:
        record["queue_position_at_submit"] = position
    return record


def create_queued_run_record(db: Any, record: Dict[str, Any]) -> bool:
    """Writes the QUEUED run record only if the run has none yet (a dispatch may already have written the real one).
    True when written. Store errors raise BuildAdmissionError."""
    try:
        db.collection(RUNS_COLLECTION).document(record["trace_id"]).create(record)
        return True
    except Exception as err:  # noqa: BLE001
        if _is_conflict(err):
            return False
        raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, f"queued run record {record['trace_id']} not written "
                                                               f"({type(err).__name__}: {err})") from err


def _fail_records(db: Any, trace_id: str, error_class: str, detail: str, *, only_if_unbound: bool = False,
                  status: str = "FAILED", entry_status: str = ENTRY_FAILED,
                  request_status: str = "FAILED", extra: Optional[Dict[str, Any]] = None,
                  run_record_only: bool = False) -> None:
    """Typed end of a run that never started: run record, queue entry and feature request. Each write is logged on
    failure (the slot accounting is already done). `run_record_only` (RT14-14): the queue entry and the feature
    request are left as they are (a run that holds no slot: its entry, if any, already has its own end)."""
    now_iso = _iso(_now())
    run_ref = db.collection(RUNS_COLLECTION).document(trace_id)
    request_id = None
    try:
        snap = run_ref.get()
        record = _snapshot_data(snap, f"pipeline_executions/{trace_id}")
        if record is not None:
            request_id = record.get("request_id")
        bound = bool(record and (record.get("workflow_execution_name") or record.get("workflow_execution_id")))
        terminal = bool(record and str(record.get("status") or "").upper() not in RUN_STATUSES_HOLDING_A_SLOT
                        and record.get("status"))
        if record is not None and not terminal and not (only_if_unbound and bound):
            update = {"status": status, "current_stage": status, "ended_at": now_iso, "completed_at": now_iso,
                      "error_class": error_class, "error": detail, "error_message": detail, **(extra or {})}
            if getattr(snap, "update_time", None) is not None:
                run_ref.update(update, option=db.write_option(last_update_time=snap.update_time))
            else:
                run_ref.set(update, merge=True)
    except Exception as err:  # noqa: BLE001
        logger.error(f"{error_class}: run record {trace_id} not marked {status} ({type(err).__name__}: {err})")
    if run_record_only:
        return
    entry = _read_entry(db, trace_id)
    request_id = request_id or (entry or {}).get("request_id")
    if entry is not None:
        _set_entry(db, trace_id, {"status": entry_status, "error_class": error_class, "error": detail})
    if request_id:
        _set_request_status(db, request_id, request_status, only_from=RUN_STATUS_QUEUED,
                            extra={"error": detail, "error_class": error_class})


def _read_entry(db: Any, trace_id: str) -> Optional[Dict[str, Any]]:
    try:
        return _snapshot_data(_entry_ref(db, trace_id).get(), f"build_queue/{trace_id}")
    except Exception as err:  # noqa: BLE001
        logger.error(f"build_queue/{trace_id} unreadable ({type(err).__name__}: {err})")
        return None


def _set_request_status(db: Any, request_id: str, status: str, *, only_from: Optional[str] = None,
                        extra: Optional[Dict[str, Any]] = None) -> None:
    """Moves a feature request out of QUEUED (only from `only_from`, so a request that already moved on is kept)."""
    ref = db.collection(REQUESTS_COLLECTION).document(request_id)
    try:
        snap = ref.get()
        current = _snapshot_data(snap, f"feature_requests/{request_id}")
        if current is None or (only_from is not None and current.get("status") != only_from):
            return
        ref.set(dict(extra or {}, status=status, updated_at=_iso(_now())), merge=True)
    except Exception as err:  # noqa: BLE001
        logger.error(f"feature_requests/{request_id} not set to {status} ({type(err).__name__}: {err})")


# ------------------------------------------------------------------------------------------------ release / pump
def release(db: Any, trace_id: str, *, reason: str) -> bool:
    """Frees the slot of `trace_id` (a run that ended). True when it held one."""
    def decide(state):
        held = state["holders"].pop(trace_id, None) is not None
        waited = state.get("waiting", {}).pop(trace_id, None) is not None
        resume_items = [q for q in state["queue"] if q.get("trace_id") == trace_id and q.get("kind") == KIND_RESUME]
        for q in resume_items:
            state["queue"].remove(q)
        return held, bool(held or waited or resume_items)

    held = _cas(db, decide)
    if held:
        logger.info(f"Build slot of {trace_id} released ({reason})")
    return held


def fail_dispatch(db: Any, trace_id: str, error_class: str, detail: str) -> bool:
    """A run that holds a slot (or waits) but could not be dispatched: slot freed, run / entry / feature request FAILED
    with the typed class and the error. False (and nothing written) when the trace neither holds a slot nor waits."""
    def decide(state):
        held = trace_id in state["holders"]
        pos = _position(state, trace_id)
        if not held and pos is None:
            return False, False
        state["holders"].pop(trace_id, None)
        if pos is not None:
            state["queue"].pop(pos - 1)
        return True, True

    if not _cas(db, decide):
        return False
    logger.error(f"{error_class}: build {trace_id} not dispatched: {detail}")
    _fail_records(db, trace_id, error_class, detail)
    return True


def refuse_run(db: Any, trace_id: str, error_class: str, detail: str, *, fail_unbound_record: bool) -> bool:
    """RT14-14: an intake event refused for good when it arrives (its workload is DECOMMISSIONED / ARCHIVED, or its run
    already ended). A run that holds a slot or waits in the queue frees it and is failed with the class
    (fail_dispatch). One that holds neither has, when `fail_unbound_record`, only its run record failed, and only while
    no workflow execution is bound to it and it has not ended. True when a slot or queue place was freed."""
    if fail_dispatch(db, trace_id, error_class, detail):
        return True
    if fail_unbound_record:
        logger.error(f"{error_class}: run {trace_id} refused at intake: {detail}")
        _fail_records(db, trace_id, error_class, detail, only_if_unbound=True, run_record_only=True)
    return False


def requeue(db: Any, trace_id: str, detail: str) -> bool:
    """RT F1: a promoted run whose start failed transiently goes back to the HEAD of the queue (its slot is freed) and
    its attempt count grows; on the MAX_DISPATCH_ATTEMPTS-th failure it is failed instead (BUILD_DISPATCH_FAILED, with
    the error). True when requeued."""
    entry = _read_entry(db, trace_id) or {}
    attempts = int(entry.get("dispatch_attempts") or 0) + 1
    if attempts >= MAX_DISPATCH_ATTEMPTS:
        message = f"{detail} (start attempt {attempts} of {MAX_DISPATCH_ATTEMPTS} failed)"
        if entry.get("kind") == KIND_RESUME:
            fail_resume(db, trace_id, message, entry)
        else:
            fail_dispatch(db, trace_id, BUILD_DISPATCH_FAILED, message)
        return False

    def decide(state):
        if trace_id not in state["holders"]:
            return False, False
        state["holders"].pop(trace_id)
        state["queue"].insert(0, {"trace_id": trace_id, "product_id": entry.get("product_id"),
                                  "submitted_at": entry.get("submitted_at") or _iso(_now()),
                                  "source": entry.get("source"), **({"kind": entry["kind"]} if entry.get("kind")
                                                                     else {})})
        return True, True

    if not _cas(db, decide):
        return False
    _set_entry(db, trace_id, {"status": ENTRY_QUEUED, "dispatch_attempts": attempts, "last_dispatch_error": detail})
    logger.warning(f"Queued build {trace_id}: start attempt {attempts} of {MAX_DISPATCH_ATTEMPTS} failed ({detail}); "
                   f"it is back at the head of the queue and is retried on the next trigger")
    return True


def mark_dispatched(db: Any, trace_id: str, entry: Optional[Dict[str, Any]] = None) -> None:
    entry = entry if entry is not None else (_read_entry(db, trace_id) or {})
    _set_entry(db, trace_id, {"status": ENTRY_DISPATCHED, "dispatched_at": _iso(_now())})
    request_id = entry.get("request_id")
    if request_id:
        _set_request_status(db, request_id, entry.get("request_status_on_dispatch") or "IN_DEVELOPMENT",
                            only_from=RUN_STATUS_QUEUED)


def mark_outcome_unknown(db: Any, trace_id: str, detail: str) -> None:
    """The dispatch may or may not have arrived: the slot is kept; the grace rule fails the run if nothing binds."""
    logger.error(f"Build {trace_id}: dispatch outcome unknown ({detail}); its slot is kept until a workflow binds or "
                 f"{DISPATCH_GRACE_SECONDS // 60} minutes pass ({BUILD_DISPATCH_LOST})")
    _set_entry(db, trace_id, {"status": ENTRY_OUTCOME_UNKNOWN, "error": detail})


def promote(db: Any, *, limit: Optional[int] = None, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Releases the slots of ended runs, then moves the queue head(s) into the free slots. Only the caller whose
    compare-and-set moved an entry receives it, so a queued run is dispatched once. Returns the promoted entries
    (each with its stored payload); an entry whose payload is missing is failed here."""
    limit = read_limit(db) if limit is None else limit
    now = now or _now()

    def decide(state):
        released = _release_ended(db, state, now)
        promoted = []
        while state["queue"] and len(state["holders"]) < limit:
            item = state["queue"].pop(0)
            state["holders"][item["trace_id"]] = {"product_id": item.get("product_id"), "acquired_at": _iso(now),
                                                  "source": item.get("source"), "via": "queue"}
            promoted.append(item)
        return (released, promoted), bool(released or promoted)

    released, promoted = _cas(db, decide)
    _after_release(db, released)
    out = []
    for item in promoted:
        trace_id = item["trace_id"]
        entry = _read_entry(db, trace_id)
        if not entry or (entry.get("kind") != KIND_RESUME and not isinstance(entry.get("payload"), dict)):
            fail_dispatch(db, trace_id, BUILD_DISPATCH_FAILED, "the queued run's stored request (build_queue entry) "
                                                               "is missing or unreadable")
            continue
        _set_entry(db, trace_id, {"status": ENTRY_DISPATCHING, "dispatch_started_at": _iso(now)})
        out.append(entry)
    return out


def _workload_gone(db: Any, product_id: Optional[str]) -> Optional[str]:
    if not product_id:
        return None
    try:
        data = _snapshot_data(db.collection(WORKLOADS_COLLECTION).document(product_id).get(), f"workloads/{product_id}")
    except Exception as err:  # noqa: BLE001 - unknown: dispatch decides (the gateway re-checks its own gates)
        logger.warning(f"workloads/{product_id} unreadable before a queued dispatch ({type(err).__name__})")
        return None
    status = str((data or {}).get("status") or "").upper()
    return status if status in WORKLOAD_GONE_STATUSES else None


def pump(db: Any, dispatch: Callable[[Dict[str, Any]], str], *, gate: Optional[Callable[[], Optional[str]]] = None,
         limit: Optional[int] = None,
         resume_dispatch: Optional[Callable[[Dict[str, Any]], str]] = None) -> List[Dict[str, Any]]:
    """Dispatches queued runs into free slots, oldest first. `dispatch(entry)` returns DISPATCHED or OUTCOME_UNKNOWN,
    raises BuildDispatchRefused (run failed with its class) or anything else (run failed BUILD_DISPATCH_FAILED).
    `gate()` returns a reason to dispatch nothing now (emergency stop, maintenance): queued runs then stay queued.
    Returns [{trace_id, outcome, error_class?}]. Store errors raise BuildAdmissionError."""
    state = read_state(db)
    if not state["queue"] and not state["holders"]:
        return []
    if state["queue"] and gate is not None:
        reason = gate()
        if reason:
            logger.warning(f"{len(state['queue'])} queued build(s) not dispatched now: {reason}")
            return []
    results: List[Dict[str, Any]] = []
    for _round in range(PUMP_MAX_ROUNDS):
        batch = promote(db, limit=limit)
        if not batch:
            break
        freed = False
        requeued = False
        untried_at = 0
        for entry in batch:
            if requeued:   # RT F1: one transient failure ends this pump; the rest go back to the head, in order
                untried_at += 1
                requeue_untried(db, entry, untried_at)
                continue
            trace_id = entry["trace_id"]
            if entry.get("kind") == KIND_RESUME:
                outcome = _pump_resume(db, entry, resume_dispatch or deliver_resume_callback)
                results.append({"trace_id": trace_id, "outcome": outcome, "kind": KIND_RESUME})
                if outcome == ENTRY_QUEUED:
                    requeued = True
                elif outcome != ENTRY_DISPATCHED:
                    freed = True
                continue
            gone = _workload_gone(db, entry.get("product_id"))
            if gone:
                fail_dispatch(db, trace_id, BUILD_QUEUE_WORKLOAD_GONE,
                              f"workload '{entry.get('product_id')}' is {gone}; the queued build was not started")
                results.append({"trace_id": trace_id, "outcome": ENTRY_FAILED, "error_class": BUILD_QUEUE_WORKLOAD_GONE})
                freed = True
                continue
            try:
                outcome = dispatch(entry)
            except BuildDispatchRetryable as transient:
                if requeue(db, trace_id, transient.detail):
                    results.append({"trace_id": trace_id, "outcome": ENTRY_QUEUED, "error": transient.detail})
                    requeued = True
                else:
                    results.append({"trace_id": trace_id, "outcome": ENTRY_FAILED,
                                    "error_class": BUILD_DISPATCH_FAILED})
                    freed = True
                continue
            except BuildDispatchRefused as refused:
                fail_dispatch(db, trace_id, refused.error_class, refused.detail)
                results.append({"trace_id": trace_id, "outcome": ENTRY_FAILED, "error_class": refused.error_class})
                freed = True
                continue
            except Exception as err:  # noqa: BLE001 - typed below
                fail_dispatch(db, trace_id, BUILD_DISPATCH_FAILED, f"{type(err).__name__}: {err}")
                results.append({"trace_id": trace_id, "outcome": ENTRY_FAILED, "error_class": BUILD_DISPATCH_FAILED})
                freed = True
                continue
            if outcome == OUTCOME_UNKNOWN:
                mark_outcome_unknown(db, trace_id, "the dispatch did not confirm")
                results.append({"trace_id": trace_id, "outcome": ENTRY_OUTCOME_UNKNOWN})
            else:
                mark_dispatched(db, trace_id, entry)
                logger.info(f"Queued build {trace_id} of '{entry.get('product_id')}' dispatched")
                results.append({"trace_id": trace_id, "outcome": ENTRY_DISPATCHED})
        if requeued or not freed:
            break
    return results


def _pump_resume(db: Any, entry: Dict[str, Any], deliver: Callable[[Dict[str, Any]], str]) -> str:
    """F2: delivers the approval callback of a run that waited for a slot after its approval. A run that ended
    meanwhile (aborted, the workflow's 24 h wait expired) or whose workload is gone frees the slot, nothing is sent."""
    trace_id = entry["trace_id"]
    if _run_ended(db, trace_id) or _workload_gone(db, entry.get("product_id")):
        release(db, trace_id, reason="WAIT_ENDED")
        _set_entry(db, trace_id, {"status": ENTRY_CANCELLED})
        return ENTRY_CANCELLED
    try:
        deliver(entry)
    except BuildDispatchRetryable as transient:
        return ENTRY_QUEUED if requeue(db, trace_id, transient.detail) else ENTRY_FAILED
    except Exception as err:  # noqa: BLE001 - BuildDispatchRefused or anything else: typed below
        fail_resume(db, trace_id, getattr(err, "detail", None) or f"{type(err).__name__}: {err}", entry)
        return ENTRY_FAILED
    _set_entry(db, trace_id, {"status": ENTRY_DISPATCHED, "dispatched_at": _iso(_now())})
    logger.info(f"Approved run {trace_id} of '{entry.get('product_id')}' resumed with its build slot")
    return ENTRY_DISPATCHED


def requeue_untried(db: Any, entry: Dict[str, Any], at: int) -> None:
    """Puts a promoted run that was not tried (the pump stopped on a transient failure) back at the head, behind the
    run that failed, without counting an attempt."""
    trace_id = entry["trace_id"]

    def decide(state):
        if trace_id not in state["holders"]:
            return False, False
        state["holders"].pop(trace_id)
        state["queue"].insert(min(at, len(state["queue"])), {"trace_id": trace_id, "product_id": entry.get("product_id"),
                                   "submitted_at": entry.get("submitted_at") or _iso(_now()),
                                   "source": entry.get("source"),
                                   **({"kind": entry["kind"]} if entry.get("kind") else {})})
        return True, True

    if _cas(db, decide):
        _set_entry(db, trace_id, {"status": ENTRY_QUEUED})


# ------------------------------------------------------------------------------------------------ approval waits (F2)
def park(db: Any, trace_id: str, *, stage: str, now: Optional[datetime] = None) -> str:
    """F2 option A (owner 11-14): a run that starts waiting for a person (`stage` in APPROVAL_WAIT_STAGES) gives its
    slot up; the caller then dispatches the next queued run. Idempotent. PARKED, or: KEPT (its approval was already
    decided while it held the slot: the late notice of a wait that is over), ALREADY (parked before) or NOT_HELD."""
    if stage not in APPROVAL_WAIT_STAGES:
        return RESUME_NOT_HELD
    now = now or _now()

    def decide(state):
        if trace_id in state.get("waiting", {}):
            return "ALREADY", False
        holder = state["holders"].get(trace_id)
        if holder is None:
            return "NOT_HELD", False
        if holder.get("resumed_from") == stage:
            holder.pop("resumed_from", None)
            return "KEPT", True
        state["holders"].pop(trace_id)
        state["waiting"][trace_id] = {"product_id": holder.get("product_id"), "since": _iso(now), "stage": stage,
                                      "source": holder.get("source")}
        return PARKED, True

    outcome = _cas(db, decide)
    if outcome == PARKED:
        logger.info(f"Run {trace_id} waits for a person ({stage}): its build slot is released")
    return outcome


def resume(db: Any, trace_id: str, *, stage: Optional[str], callback_url: str, callback_payload: Dict[str, Any],
           approval_id: Optional[str], decision: str, limit: Optional[int] = None,
           now: Optional[datetime] = None) -> Admission:
    """F2 option A: an approved (or reworked) run takes a build slot again before its approval callback is delivered,
    through the same accounting as every admission. RESUME_NOW: deliver now (a slot was free, or it never gave its slot
    up). QUEUED: it waits at the HEAD of the queue (behind runs resumed earlier, ahead of new submissions); the pump
    delivers the callback when a slot frees. RESUME_NOT_HELD: the run never held a slot (deliver now, as before).
    Idempotent: a second grant of the same run finds it queued or holding."""
    limit = read_limit(db) if limit is None else limit
    now = now or _now()
    entry_written = {"done": False}

    def decide(state):
        running = len(state["holders"])
        holder = state["holders"].get(trace_id)
        if holder is not None:
            if stage and holder.get("resumed_from") != stage:
                holder["resumed_from"] = stage   # its wait notice may still arrive: park() keeps the slot then
                return Admission(RESUME_NOW, trace_id, limit=limit, running=running, already=True), True
            return Admission(RESUME_NOW, trace_id, limit=limit, running=running, already=True), False
        pos = _position(state, trace_id)
        if pos is not None:
            return Admission(QUEUED, trace_id, limit=limit, running=running, position=pos, already=True), False
        if trace_id not in state.get("waiting", {}):
            return Admission(RESUME_NOT_HELD, trace_id, limit=limit, running=running), False
        released = _release_ended(db, state, now)
        waited = state["waiting"].get(trace_id)
        if waited is None:   # the run ended meanwhile: nothing to resume into a slot
            return Admission(RESUME_NOT_HELD, trace_id, limit=limit, running=len(state["holders"]),
                             released=released), bool(released)
        ahead = 0
        while ahead < len(state["queue"]) and state["queue"][ahead].get("kind") == KIND_RESUME:
            ahead += 1
        if len(state["holders"]) < limit and ahead == 0:
            state["waiting"].pop(trace_id)
            state["holders"][trace_id] = {"product_id": waited.get("product_id"), "acquired_at": _iso(now),
                                          "source": waited.get("source"), "via": KIND_RESUME}
            return Admission(RESUME_NOW, trace_id, limit=limit, running=len(state["holders"]), released=released), True
        if not entry_written["done"]:
            return None, False
        state["waiting"].pop(trace_id)
        state["queue"].insert(ahead, {"trace_id": trace_id, "product_id": waited.get("product_id"),
                                      "submitted_at": _iso(now), "source": waited.get("source"), "kind": KIND_RESUME})
        return Admission(QUEUED, trace_id, limit=limit, running=len(state["holders"]), position=ahead + 1,
                         pump_needed=len(state["holders"]) < limit, released=released), True

    result = None
    for _round in range(2):
        result = _cas(db, decide)
        if result is not None:
            break
        state = read_state(db)
        waited = (state.get("waiting") or {}).get(trace_id) or {}
        try:
            _entry_ref(db, trace_id).set({
                "trace_id": trace_id, "product_id": waited.get("product_id"), "kind": KIND_RESUME,
                "source": waited.get("source"), "stage": stage, "submitted_at": _iso(now), "status": ENTRY_QUEUED,
                "payload": {}, "callback_url": callback_url, "callback_payload": dict(callback_payload or {}),
                "approval_id": approval_id, "decision": decision})
        except Exception as err:  # noqa: BLE001
            raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, f"build_queue/{trace_id} not written "
                                                                   f"({type(err).__name__}: {err})") from err
        entry_written["done"] = True
    if result is None:  # pragma: no cover - the second round always decides
        raise BuildAdmissionError(BUILD_ADMISSION_UNAVAILABLE, f"resume of {trace_id} did not decide")
    _after_release(db, result.released)
    if result.state == QUEUED and not result.already:
        logger.warning(f"Approved run {trace_id} waits for a build slot at position {result.position} "
                       f"({result.running}/{limit} in use)")
    return result


def fail_resume(db: Any, trace_id: str, detail: str, entry: Optional[Dict[str, Any]] = None) -> None:
    """F2: the approval callback of a resumed run could not be delivered: its slot is freed, it waits for a decision
    again (waiting list), and its approval card shows CALLBACK_FAILED with the pending decision, so an operator
    re-decides (the existing re-decidable state). The workflow itself still waits for its callback."""
    entry = entry if entry is not None else (_read_entry(db, trace_id) or {})
    now_iso = _iso(_now())

    def decide(state):
        holder = state["holders"].pop(trace_id, None)
        pos = _position(state, trace_id)
        if pos is not None:
            state["queue"].pop(pos - 1)
        if holder is None and pos is None:
            return False, False
        state["waiting"][trace_id] = {"product_id": entry.get("product_id"), "since": now_iso,
                                      "stage": entry.get("stage"), "source": entry.get("source")}
        return True, True

    _cas(db, decide)
    logger.error(f"{BUILD_DISPATCH_FAILED}: approval callback of run {trace_id} not delivered: {detail}")
    _set_entry(db, trace_id, {"status": ENTRY_FAILED, "error_class": BUILD_DISPATCH_FAILED, "error": detail})
    approval_id = entry.get("approval_id")
    if approval_id:
        try:
            db.collection("approval_requests").document(approval_id).set({
                "status": "CALLBACK_FAILED", "failure_reason": f"{BUILD_DISPATCH_FAILED}: {detail}",
                "pending_decision": entry.get("decision") or "APPROVED", "updated_at": now_iso}, merge=True)
        except Exception as err:  # noqa: BLE001
            logger.error(f"approval_requests/{approval_id} not marked CALLBACK_FAILED ({type(err).__name__}: {err})")


def deliver_resume_callback(entry: Dict[str, Any]) -> str:
    """Delivers a resumed run's approval callback (shared/callbacks.py: the platform's own Workflows callback endpoint
    only, no redirects). A refused URL -> BuildDispatchRefused; a delivery failure -> BuildDispatchRetryable."""
    from shared.callbacks import CallbackDeliveryClient, CallbackURLRejected, classify_callback_url

    url = entry.get("callback_url")
    try:
        classify_callback_url(url)
    except CallbackURLRejected as rej:
        raise BuildDispatchRefused(BUILD_DISPATCH_REFUSED, f"callback URL refused: {rej}")
    try:
        CallbackDeliveryClient.send_callback(callback_url=url, payload=dict(entry.get("callback_payload") or {}),
                                             timeout=10, max_attempts=3)
    except Exception as err:  # noqa: BLE001
        raise BuildDispatchRetryable(f"callback delivery failed ({type(err).__name__}: {err})")
    return DISPATCHED


def slot_view(state: Dict[str, Any], trace_id: str, limit: int) -> Optional[Dict[str, Any]]:
    """The `build_queue` object the Control Center shows on a running run: waiting for a person without a slot, or
    approved and waiting for a slot (with its place). None otherwise."""
    if trace_id in (state.get("waiting") or {}):
        return {"state": "WAITING_FOR_APPROVAL", "holds_slot": False, "limit": limit,
                "running": len(state["holders"]), "stage": state["waiting"][trace_id].get("stage")}
    for i, item in enumerate(state["queue"]):
        if item.get("trace_id") == trace_id and item.get("kind") == KIND_RESUME:
            return {"state": QUEUED, "kind": KIND_RESUME, "position": i + 1, "ahead": i, "limit": limit,
                    "running": len(state["holders"])}
    return None


# ------------------------------------------------------------------------------------------------ cancel / view
def cancel(db: Any, trace_id: str, *, by: str) -> Dict[str, Any]:
    """Cancels a queued run (it never starts). A run already granted a slot -> BuildAdmissionError
    BUILD_QUEUE_ALREADY_DISPATCHING (abort it once it runs); a run that is neither -> BUILD_QUEUE_NOT_QUEUED."""
    def decide(state):
        pos = _position(state, trace_id)
        if pos is not None:
            state["queue"].pop(pos - 1)
            return "CANCELLED", True
        return ("HOLDER" if trace_id in state["holders"] else "UNKNOWN"), False

    outcome = _cas(db, decide)
    if outcome == "HOLDER":
        raise BuildAdmissionError(BUILD_QUEUE_ALREADY_DISPATCHING,
                                  f"run {trace_id} has left the queue and is being started; abort it once it runs",
                                  details={"trace_id": trace_id})
    if outcome == "UNKNOWN":
        raise BuildAdmissionError(BUILD_QUEUE_NOT_QUEUED, f"run {trace_id} is not waiting in the build queue",
                                  details={"trace_id": trace_id})
    detail = f"Queued build cancelled by {by} before it started"
    _fail_records(db, trace_id, BUILD_QUEUE_CANCELLED, detail, status="ABORTED", entry_status=ENTRY_CANCELLED,
                  request_status="CANCELLED", extra={"cancelled_by": by})
    logger.info(f"Queued build {trace_id} cancelled by {by}")
    return {"trace_id": trace_id, "state": ENTRY_CANCELLED, "cancelled_by": by}


def _run_bound(db: Any, trace_id: str) -> bool:
    """RT14-14: True when a workflow execution is bound to the run record, or the record cannot be read (a holder whose
    state is unknown is left to the release rule and the gateway's arrival check, never taken)."""
    try:
        record = _snapshot_data(db.collection(RUNS_COLLECTION).document(trace_id).get(),
                                f"pipeline_executions/{trace_id}")
    except Exception as err:  # noqa: BLE001
        logger.warning(f"run record {trace_id} unreadable during a workload cancel ({type(err).__name__})")
        return True
    return bool(record and (record.get("workflow_execution_name") or record.get("workflow_execution_id")))


def cancel_product(db: Any, product_id: str, *, by: str) -> List[str]:
    """Cancels every queued run of a workload (decommission / archive cascade), and (RT14-14) every slot holder of the
    workload that no workflow execution is bound to yet: a promoted run whose intake event is still in flight, which
    the cascade's run cancel (bound executions only) cannot see. Returns the cancelled traces."""
    def decide(state):
        # F2: an approved run waiting for a slot is a running workflow: the decommission cascade aborts it (and the
        # pump never resumes a run that ended), so only builds that never started are cancelled here.
        mine = [q for q in state["queue"] if q.get("product_id") == product_id and q.get("kind") != KIND_RESUME]
        unbound = [t for t, h in state["holders"].items()
                   if isinstance(h, dict) and h.get("product_id") == product_id and not _run_bound(db, t)]
        if not mine and not unbound:
            return ([], []), False
        state["queue"] = [q for q in state["queue"] if q not in mine]
        for trace_id in unbound:
            state["holders"].pop(trace_id, None)
        return ([q["trace_id"] for q in mine], unbound), True

    cancelled, unbound = _cas(db, decide)
    for trace_id in cancelled:
        _fail_records(db, trace_id, BUILD_QUEUE_CANCELLED, f"Queued build cancelled: {by}", status="ABORTED",
                      entry_status=ENTRY_CANCELLED, request_status="CANCELLED", extra={"cancelled_by": by})
    for trace_id in unbound:
        # only_if_unbound: a workflow that bound in between keeps its record (the cascade's run cancel ends it)
        _fail_records(db, trace_id, BUILD_QUEUE_CANCELLED, f"Build cancelled before its workflow started: {by}",
                      only_if_unbound=True, status="ABORTED", entry_status=ENTRY_CANCELLED,
                      request_status="CANCELLED", extra={"cancelled_by": by})
    return cancelled + unbound


def queue_view(db: Any, limit: Optional[int] = None) -> Dict[str, Any]:
    """{limit, running, queue: [{trace_id, product_id, position, ahead, submitted_at}]} for the Control Center."""
    state = read_state(db)
    limit = read_limit(db) if limit is None else limit
    return {"limit": limit, "running": len(state["holders"]),
            "queue": [{"trace_id": q["trace_id"], "product_id": q.get("product_id"), "position": i + 1, "ahead": i,
                       "submitted_at": q.get("submitted_at"), "kind": q.get("kind")}
                      for i, q in enumerate(state["queue"])],
            "waiting": sorted(state.get("waiting") or {})}
