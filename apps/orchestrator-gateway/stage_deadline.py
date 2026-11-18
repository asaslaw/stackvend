"""STAGE-DEADLINE (G5, owner 11-13): one stage-deadline mechanism for every gateway agent stage the workflow calls.

Why: 11-13 ex08 (plan docs/planning/stage-deadline-and-callback-plan.md). The developer request ran into the
workflow's 1800 s http.post cap; Workflows recorded UNHANDLED, and the gateway kept working on a request nobody was
waiting for (an orphan that could still have committed and opened a PR for a FAILED run).

The mechanism, in one place:
- STAGE_BUDGETS is the single typed source of truth: per (stage, mode) the workflow's own bound (the YAML http.post
  `timeout` for a synchronous stage, the `await_callback` timeout for a callback stage) and a margin. The cooperative
  deadline is `budget_s = workflow_timeout_s - margin_s`; the hard answer comes at `budget_s + ANSWER_GRACE_S`, still
  inside the workflow's bound (tests/test_stage_deadline.py pins the table against the YAML).
- `run_with_deadline(sd, fn)` runs the stage body in a worker thread with the deadline in a context variable and waits
  for it until the hard answer time. In time: the body's own result or exception, unchanged (today's behaviour). Late:
  a typed StageDeadlineExceededError (HTTP 504, error_class STAGE_DEADLINE_EXCEEDED, stage, progress summary), which
  the workflow's build_failure keeps as typed (never CODE_DEFECT, never a developer retry).
- Cooperative bound: `checkpoint(label)` before every LLM call, wave and repair iteration raises once the deadline has
  passed or the stage was abandoned, so no new work starts; `llm_call_timeout_ms()` bounds a call started in the last
  STAGE_CALL_HEADER_CEILING_S (120 s, RT F3) by the remaining budget through the transport seam
  `developer_agent.llm_transport.call_timeout_ms(remaining_s)`; earlier calls are sent exactly as before.
- Orphan guard: once the stage has answered (or was abandoned), `guard_side_effect(label)` refuses every commit, PR,
  merge and provenance write, so nothing reaches the child repository after the workflow has its answer. A side
  effect also needs SIDE_EFFECT_RESERVE_S of budget left, so it finishes before the answer.
- Run liveness (optional probe): a run that ended (terminal status), was superseded (another workflow execution owns
  the trace, or a newer job owns the stage) or hit the emergency stop abandons the stage at the next checkpoint.

No deadline in the context (a direct call from a test or a script) = today's behaviour: every function here is a
no-op and `llm_call_timeout_ms()` is None.
"""

from __future__ import annotations

import contextvars
import logging
import threading
import time
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

from gate_errors import GateError, StageAbandonedError, StageDeadlineExceededError

# RT14-15: the rate-limit cooldown's typed stop (the run ended before or during a cooldown). No fallback: the gateway
# image ships shared/, and a missing stop class must crash at import, never let a stop pass as a generic error.
from shared.cooldown_manager import RunEndedDuringCooldown

logger = logging.getLogger("castor.stage_deadline")

T = TypeVar("T")


class StageMode(str, Enum):
    SYNC = "SYNC"          # the workflow waits on the HTTP response (http.post, capped at 1800 s by Workflows)
    CALLBACK = "CALLBACK"  # the workflow awaits a callback (stage_jobs.py); the request answers 202 at once


# Seconds between the cooperative deadline and the hard answer: a body that observes the deadline at a checkpoint
# gets this long to finish its own typed answer before the runner answers for it.
ANSWER_GRACE_S = 20
# A commit / PR / merge starts only with at least this much budget left, so it ends before the answer.
SIDE_EFFECT_RESERVE_S = 60
# The run-liveness probe is read at most this often from checkpoints (a side-effect guard always reads it).
PROBE_INTERVAL_S = 30.0
# pipeline_executions/{trace}.status values that mean the run is over (gateway notify + Control Center reconcile).
RUN_ENDED_STATUSES = frozenset({"FAILED", "SUCCEEDED", "ABORTED", "CANCELLED", "REJECTED"})
_MAX_MILESTONES = 200
# The two stop outcomes. A cascade / retry / fallback loop re-raises these before its generic `except Exception`.
# RT14-15: plus the cooldown's RunEndedDuringCooldown (the run ended during a rate-limit cooldown), which
# run_with_deadline answers as STAGE_ABANDONED (reason RUN_ENDED).
STOP_ERRORS = (StageDeadlineExceededError, StageAbandonedError, RunEndedDuringCooldown)


@dataclass(frozen=True)
class StageBudget:
    stage: str
    mode: StageMode
    workflow_timeout_s: int   # SYNC: the YAML http.post `timeout`; CALLBACK: the YAML await timeout
    margin_s: int             # answer grace + (CALLBACK) callback delivery reserve

    @property
    def budget_s(self) -> int:
        """The cooperative deadline: no new work starts after it."""
        return self.workflow_timeout_s - self.margin_s

    @property
    def answer_at_s(self) -> int:
        """The hard answer: the runner answers (typed) at this point whatever the body is doing."""
        return self.budget_s + ANSWER_GRACE_S


def _b(stage: str, mode: StageMode, workflow_timeout_s: int, margin_s: int) -> Tuple[Tuple[str, StageMode], StageBudget]:
    return (stage, mode), StageBudget(stage, mode, workflow_timeout_s, margin_s)


# The single source of truth (plan §3). SYNC rows: the YAML step timeout of each synchronous gateway agent call
# (compliance: the Workflows default 300 s, now written in the YAML). CALLBACK rows: the YAML await timeout of the
# converted long LLM stages (LONG-STAGE-CALLBACK). The SYNC rows of converted stages keep serving older workflows and
# direct callers of the synchronous routes.
STAGE_BUDGETS: Dict[Tuple[str, StageMode], StageBudget] = dict([
    _b("architect", StageMode.SYNC, 600, 60),       # 540 s (11-13: 365 s on Carbon)
    _b("compliance", StageMode.SYNC, 300, 30),      # 270 s
    _b("developer", StageMode.SYNC, 1800, 150),     # 1650 s (11-13: 561-1209 s on Carbon, one > 1800 s)
    _b("gatekeeper", StageMode.SYNC, 300, 30),      # 270 s (no LLM)
    _b("qa", StageMode.SYNC, 1800, 300),            # 1500 s = the former QA_REQUEST_DEADLINE_S (behaviour kept)
    _b("release", StageMode.SYNC, 600, 60),         # 540 s (no LLM)
    _b("architect", StageMode.CALLBACK, 2100, 300),   # 1800 s: about 5x the 11-13 Carbon architect (365 s)
    _b("developer", StageMode.CALLBACK, 3900, 300),   # 3600 s: about 4x the Carbon median (840 s), 2x the old cap
    _b("qa", StageMode.CALLBACK, 3000, 300),          # 2700 s: QA job + Stage 2 judges with room for judge retries
])


def budget_for(stage: str, mode: StageMode) -> StageBudget:
    try:
        return STAGE_BUDGETS[(stage, mode)]
    except KeyError:
        raise KeyError(f"no stage budget for ({stage!r}, {mode.value})") from None


class StageDeadline:
    """One stage's deadline, progress notes and abandon flag. Thread-safe; shared by the body's threads."""

    def __init__(self, budget: StageBudget, *, trace_id: Optional[str] = None, product_id: Optional[str] = None,
                 probe: Optional[Callable[[], Optional[Tuple[str, str]]]] = None,
                 clock: Callable[[], float] = time.monotonic, elapsed_s: float = 0.0):
        """`elapsed_s` (STAGE-JOB-RUNNER, RT §6.4): budget already spent when this object is made. A stage-runner job
        counts its deadline from the job's `accepted_at`, not from its own start, so a slow job start never moves the
        answer past the workflow's await bound."""
        self.budget = budget
        self.stage = budget.stage
        self.trace_id = trace_id
        self.product_id = product_id
        self._clock = clock
        self.started = clock() - max(0.0, float(elapsed_s))
        self.deadline = self.started + budget.budget_s
        self.answer_at = self.started + budget.answer_at_s
        self._lock = threading.Lock()
        self._abandoned: Optional[Tuple[str, str]] = None   # (reason, message)
        self.tripped = False                                 # a checkpoint observed the deadline
        # RT14-24: a checkpoint / side-effect guard raised StageAbandonedError. Sticky like `tripped`: a body that
        # swallowed that stop still answers typed (run_with_deadline), never with its own result.
        self.abandon_observed = False
        self._milestones: List[Dict[str, Any]] = []
        self._tasks_completed: List[str] = []
        self._probe = probe
        self._probe_at: Optional[float] = None

    # ---------------------------------------------------------------------------------------------- time
    def elapsed_s(self) -> float:
        return self._clock() - self.started

    def remaining_s(self) -> float:
        return self.deadline - self._clock()

    def expired(self) -> bool:
        return self.remaining_s() <= 0

    # ---------------------------------------------------------------------------------------------- state
    @property
    def abandoned(self) -> Optional[Tuple[str, str]]:
        with self._lock:
            return self._abandoned

    def abandon(self, reason: str, message: str = "", *, quiet: bool = False) -> None:
        """Marks the stage abandoned (first reason wins). Every later checkpoint / side-effect guard refuses."""
        with self._lock:
            if self._abandoned is None:
                self._abandoned = (reason, message or reason)
                if not quiet:
                    logger.warning(f"STAGE_ABANDONED: {self.stage} for '{self.product_id}' (trace {self.trace_id}): "
                                   f"{reason}: {message}")

    def mark(self, label: str, **info: Any) -> None:
        """A progress note (bounded); `task_completed=<id>` also lists the task as finished."""
        note = {"label": label, "elapsed_s": round(self.elapsed_s(), 1)}
        note.update({k: v for k, v in info.items() if k != "task_completed"})
        with self._lock:
            if len(self._milestones) < _MAX_MILESTONES:
                self._milestones.append(note)
            done = info.get("task_completed")
            if isinstance(done, str) and done not in self._tasks_completed:
                self._tasks_completed.append(done)

    def progress(self) -> Dict[str, Any]:
        with self._lock:
            milestones = list(self._milestones)
            done = list(self._tasks_completed)
        return {"stage": self.stage, "mode": self.budget.mode.value, "budget_s": self.budget.budget_s,
                "elapsed_s": round(self.elapsed_s(), 1), "phase": milestones[-1]["label"] if milestones else None,
                "tasks_completed": done, "milestones": milestones[-50:]}

    # ---------------------------------------------------------------------------------------------- probes
    def _check_probe(self, force: bool) -> None:
        if self._probe is None or self._abandoned is not None:
            return
        now = self._clock()
        if not force and self._probe_at is not None and now - self._probe_at < PROBE_INTERVAL_S:
            return
        self._probe_at = now
        try:
            verdict = self._probe()
        except Exception as e:  # noqa: BLE001 - a probe read failure never stops a stage (the deadline still does)
            logger.warning(f"Stage liveness probe for {self.stage} (trace {self.trace_id}) unreadable: "
                           f"{type(e).__name__}: {e}")
            return
        if verdict is not None:
            self.abandon(*verdict)

    # ---------------------------------------------------------------------------------------------- guards
    def checkpoint(self, label: str) -> None:
        """Before new work (an LLM call, a wave, a repair iteration): raise when the stage must stop."""
        self._check_probe(force=False)
        gone = self.abandoned
        if gone is not None:
            self.abandon_observed = True
            raise StageAbandonedError(f"{self.stage} stopped before '{label}': {gone[1]}", reason=gone[0],
                                      stage=self.stage, details={"progress": self.progress()})
        if self.expired():
            self.tripped = True
            raise self.exceeded(f"before '{label}'")

    def guard_side_effect(self, label: str, reserve_s: float = SIDE_EFFECT_RESERVE_S) -> None:
        """Before a commit / PR / merge / provenance write: refuse after the answer, on an ended run, or when the
        side effect could not finish before the deadline."""
        self._check_probe(force=True)
        gone = self.abandoned
        if gone is not None:
            logger.warning(f"ORPHAN_ABANDONED: {self.stage} for '{self.product_id}' (trace {self.trace_id}) refused "
                           f"'{label}' ({gone[0]}): nothing is written after the stage answered")
            self.abandon_observed = True
            raise StageAbandonedError(f"{self.stage} refused '{label}': {gone[1]}", reason=gone[0], stage=self.stage,
                                      details={"progress": self.progress()})
        if self.remaining_s() < reserve_s:
            self.tripped = True
            raise self.exceeded(f"before '{label}' (needs {int(reserve_s)} s of budget, "
                                f"{max(0, int(self.remaining_s()))} s left)")

    def abandoned_error(self, where: str) -> StageAbandonedError:
        """RT14-24: the typed answer of a stage whose body swallowed an observed abandonment."""
        gone = self.abandoned or ("ABANDONED", "the stage was abandoned")
        return StageAbandonedError(f"{self.stage} was abandoned {where}: {gone[1]}", reason=gone[0], stage=self.stage,
                                   details={"progress": self.progress()})

    def exceeded(self, where: str) -> StageDeadlineExceededError:
        return StageDeadlineExceededError(
            f"{self.stage} stage deadline exceeded ({self.budget.budget_s} s budget, {self.budget.mode.value}) "
            f"{where}; nothing further was started or committed",
            reason="STAGE_DEADLINE", stage=self.stage, details={"progress": self.progress()})


# ---------------------------------------------------------------------------------------------- context
_CURRENT: contextvars.ContextVar[Optional[StageDeadline]] = contextvars.ContextVar("stage_deadline", default=None)


def current() -> Optional[StageDeadline]:
    return _CURRENT.get()


def remaining_s() -> Optional[float]:
    sd = _CURRENT.get()
    return None if sd is None else sd.remaining_s()


def checkpoint(label: str) -> None:
    sd = _CURRENT.get()
    if sd is not None:
        sd.checkpoint(label)


def mark(label: str, **info: Any) -> None:
    sd = _CURRENT.get()
    if sd is not None:
        sd.mark(label, **info)


def guard_side_effect(label: str, reserve_s: float = SIDE_EFFECT_RESERVE_S) -> None:
    sd = _CURRENT.get()
    if sd is not None:
        sd.guard_side_effect(label, reserve_s)


def answered() -> Optional[Tuple[str, str]]:
    """STOP-KEEPS-EVIDENCE RT F2: (reason, message) once the current stage answered or was abandoned, else None (also
    None without a stage deadline). Never raises and never probes: for an optional write after a landed side effect,
    which is skipped (not failed) once the stage answered."""
    sd = _CURRENT.get()
    return None if sd is None else sd.abandoned


def llm_call_timeout_ms() -> Optional[int]:
    """The HTTP timeout for an LLM call started now: the transport seam applied to the remaining stage budget.
    None (no stage deadline, or more budget left than the seam's header ceiling, RT F3) = no timeout, today's
    behaviour."""
    rem = remaining_s()
    if rem is None:
        return None
    from developer_agent.llm_transport import call_timeout_ms   # lazy: developer_agent imports this module
    return call_timeout_ms(rem)


def bound_llm_config(config: Any, label: str, *, types: Any) -> Any:
    """checkpoint(label), then the call's GenerateContentConfig with the transport timeout for the remaining budget
    (the same object, unchanged, when no stage deadline is active)."""
    checkpoint(label)
    ms = llm_call_timeout_ms()
    if ms is None or config is None:
        return config
    http_options = types.HttpOptions(timeout=ms)
    if isinstance(config, dict):   # a config given as GenerateContentConfig keyword arguments
        return {**config, "http_options": http_options}
    return config.model_copy(update={"http_options": http_options})


def bind_context(fn: Callable[..., T]) -> Callable[..., T]:
    """`fn` wrapped to run in a copy of the caller's context (stage deadline included), for a thread pool, which,
    unlike asyncio.to_thread, does not carry context variables across. Each call runs in its own copy."""
    parent = contextvars.copy_context()

    def run(*a: Any, **kw: Any) -> T:
        return parent.copy().run(fn, *a, **kw)
    return run


# ---------------------------------------------------------------------------------------------- runner
def _carry_evidence(replacement: GateError, body_error: BaseException) -> GateError:
    """STOP-KEEPS-EVIDENCE RT F3: the typed deadline / abandon answer that replaces the body's own error keeps what
    that error said was kept: a copy of its `details["evidence"]` and that evidence's `summary` sentence on the
    message. Without evidence on a GateError body error the replacement is returned unchanged. Never raises."""
    try:
        details = getattr(body_error, "details", None) if isinstance(body_error, GateError) else None
        evidence = details.get("evidence") if isinstance(details, dict) else None
        if not isinstance(evidence, dict) or "evidence" in replacement.details:
            return replacement
        replacement.details["evidence"] = dict(evidence)
        summary = evidence.get("summary")
        if isinstance(summary, str) and summary:
            replacement.message = f"{replacement.message} {summary}"
            replacement.args = (replacement.message,)
    except Exception as err:  # noqa: BLE001 - the typed replacement is the answer either way
        logger.warning(f"Stop evidence not carried onto the {type(replacement).__name__} ({type(err).__name__})")
    return replacement


def run_with_deadline(sd: StageDeadline, fn: Callable[[], T]) -> T:
    """Runs `fn` with `sd` as the current deadline in a worker thread and waits until `sd.answer_at`.

    In time: `fn`'s result, or its exception re-raised unchanged (byte-for-byte today's answer), unless a checkpoint
    observed the deadline (then the typed deadline error, whatever `fn` turned it into) or raised an abandonment
    (RT14-24: then the typed StageAbandonedError, whatever `fn` turned it into; a body that swallowed the stop and
    answered SUCCESS never reaches the caller). Late: the typed deadline
    error at once; the worker is abandoned (its next checkpoint or side effect refuses) and never answers.
    Either way the stage is marked answered when this returns, so nothing writes after the answer."""
    fut: "Future[T]" = Future()
    ctx = contextvars.copy_context()

    def target() -> None:
        _CURRENT.set(sd)
        try:
            fut.set_result(fn())
        except BaseException as e:  # noqa: BLE001 - handed to the waiting thread unchanged
            fut.set_exception(e)

    worker = threading.Thread(target=ctx.run, args=(target,), name=f"stage-{sd.stage}-{sd.trace_id or ''}",
                              daemon=True)
    worker.start()
    try:
        wait_s = max(0.0, sd.answer_at - sd._clock())
        try:
            result = fut.result(timeout=wait_s)
        except FutureTimeout:
            sd.tripped = True
            sd.abandon("ANSWERED", "the stage deadline answered while the stage was still running")
            err = sd.exceeded("while the stage was still running")
            logger.error(f"STAGE_DEADLINE_EXCEEDED: {sd.stage} for '{sd.product_id}' (trace {sd.trace_id}) after "
                         f"{round(sd.elapsed_s(), 1)} s; progress {sd.progress()}")
            raise err from None
        except (StageDeadlineExceededError, StageAbandonedError):
            raise
        except RunEndedDuringCooldown as ended:   # RT14-15: typed like the probe's own RUN_ENDED stop
            raise StageAbandonedError(f"{sd.stage} stopped: {ended}", reason=ended.reason, stage=sd.stage,
                                      details={"run_status": ended.status}) from ended
        except BaseException as e:
            if sd.tripped:
                raise _carry_evidence(sd.exceeded("(the stage failed after its deadline)"), e) from e
            if sd.abandon_observed:
                raise _carry_evidence(sd.abandoned_error("(the stage failed after the stop was observed)"), e) from e
            raise
        if sd.tripped:
            raise sd.exceeded("(the stage returned after its deadline)")
        if sd.abandon_observed:
            raise sd.abandoned_error("(the stage returned after the stop was observed)")
        return result
    finally:
        sd.abandon("ANSWERED", "the stage has answered", quiet=True)


def run_probe(db: Any, trace_id: Optional[str], *, execution_id: Optional[str] = None,
              stage_job: Optional[Tuple[str, str]] = None,
              kill_switch: Optional[Callable[[], bool]] = None) -> Callable[[], Optional[Tuple[str, str]]]:
    """The run-liveness probe: (reason, message) when the stage must stop, else None.

    - RUN_ENDED: pipeline_executions/{trace}.status is terminal.
    - SUPERSEDED: the run record names another workflow execution than `execution_id` (exact comparison of the
      execution id segment), or the stage job record `pipeline_executions/{trace}/stage_jobs/{stage}` names another
      job than `stage_job = (stage, job_id)`.
    - KILL_SWITCH_ACTIVE: the platform emergency stop is on.
    A read error raises (the caller logs it and carries on: the deadline still bounds the stage)."""
    def probe() -> Optional[Tuple[str, str]]:
        if kill_switch is not None and kill_switch():
            return ("KILL_SWITCH_ACTIVE", "the platform emergency stop is active")
        if db is None or not trace_id:
            return None
        ref = db.collection("pipeline_executions").document(trace_id)
        snap = ref.get()
        data = (snap.to_dict() or {}) if getattr(snap, "exists", False) else {}
        status = data.get("status")
        if isinstance(status, str) and status in RUN_ENDED_STATUSES:
            return ("RUN_ENDED", f"run {trace_id} is {status}")
        if execution_id:
            for field in ("workflow_execution_id", "workflow_execution_name"):
                stored = data.get(field)
                if isinstance(stored, str) and stored and stored.rsplit("/", 1)[-1] != execution_id:
                    return ("SUPERSEDED", f"run {trace_id} now belongs to workflow execution {stored}")
        if stage_job is not None:
            stage, job_id = stage_job
            jsnap = ref.collection("stage_jobs").document(stage).get()
            jdata = (jsnap.to_dict() or {}) if getattr(jsnap, "exists", False) else {}
            owner = jdata.get("job_id")
            if isinstance(owner, str) and owner and owner != job_id:
                return ("SUPERSEDED", f"a newer {stage} job ({owner}) owns this stage")
        return None
    return probe
