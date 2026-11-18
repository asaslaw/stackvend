"""The platform's typed LLM transport rules (R3c, 10-13; QA-JUDGE-RETRY; SLOW-CALL-FALLBACK, owner 11-13).

1. `transient_status`: the one typed rule for a transient Vertex AI (google-genai) transport error. A call is
   transient only when the SDK error carries an integer status code (`google.genai.errors.APIError.code`) in
   TRANSIENT_PROVIDER_STATUS. The error MESSAGE is never read (AGENTS.md invariant 2: no string matching on error
   text). Shared by the developer path and the QA Stage 2 judge (`qa_auditor/judge.call`).

2. `CallWalk` (SLOW-CALL-FALLBACK, owner 11-13 option (b): "a too-slow AI call walks down the fallback list"): the
   per-call timeout and fallback walk of every developer-path model call (lead WBS, swarm juniors incl. the IaC
   intent task, repair, single turn). Plan: docs/planning/slow-call-fallback-plan.md.
   - Each attempt gets `timeout = min(CallTimeouts cap of its purpose, deadline - now - margin)`, sent as
     `GenerateContentConfig.http_options = HttpOptions(timeout=ms)` (the SDK bounds the request and Vertex stops at
     the `X-Server-Timeout` it sends). `deadline` is an absolute `time.monotonic()` value; None = no stage bound.
   - TIMEOUT (a typed timeout exception, a 504 at the bound, or an answer that arrived after the timeout) and
     TRANSIENT_<code> move to the next model of the chain without retrying the same model; only a transient on the
     last model is retried on it after RETRY_BACKOFF_S (walk mode). Any other error is not the walk's: the caller
     re-raises it and keeps its own handling.
   - A late answer is never used (`answered()` returns False); its billed tokens, or "usage unknown" for a timeout
     without a response, go to the `abandoned` sink so the token ledger never silently drops them.
   - Chain exhausted -> LlmFallbackExhausted; no room left in the stage budget -> LlmStageBudgetExhausted. Both are
     typed DeveloperStageErrors carrying the stage, the purpose and every attempt (invariant 8).
   - The `generate_content` call itself stays in the caller's frame (the eval harness keys its cassettes on it).

Imports: stdlib + developer_agent.errors; google.genai / httpx / Firestore / token_accounting are imported lazily.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence

from .errors import LLM_STAGE_BUDGET_EXHAUSTED, LLM_UNAVAILABLE, DeveloperStageError

logger = logging.getLogger("castor-llm-transport")

# Provider statuses that are transient: rate limit, internal error, unavailable, deadline exceeded.
TRANSIENT_PROVIDER_STATUS = frozenset({429, 500, 503, 504})
# Backoff (seconds) before retry 1 and retry 2; its length is the retry cap.
RETRY_BACKOFF_S = (4.0, 16.0)


def transient_status(exc: BaseException) -> Optional[int]:
    """The exception's integer status code when it is a transient provider status, else None.

    Exact type rule: `exc.code` must be an int (bool excluded) and a member of TRANSIENT_PROVIDER_STATUS."""
    code: Any = getattr(exc, "code", None)
    if isinstance(code, int) and not isinstance(code, bool) and code in TRANSIENT_PROVIDER_STATUS:
        return code
    return None


# STAGE-DEADLINE seam (owner 11-13; stage_deadline.py). The one place where the remaining stage budget reaches an LLM
# call's transport: every bounded call site asks `stage_deadline.llm_call_timeout_ms()`, which calls this with the
# seconds of stage budget left. The per-call slow-call policy (owner 11-13 choice (b): a per-call cap that walks the
# fallback chain) plugs in here and in the call sites' fallback loops, not in stage_deadline.py.
#
# RT F3 (11-13): a timeout makes the SDK send `X-Server-Timeout: <seconds>` with the request. Before the seam, the
# developer, architect and compliance calls sent no such header, and the only value proven live on Vertex is the QA
# judge's 120 s (JUDGE_TIMEOUT_MS, every judge call since 10-27, Carbon included). So the seam sends a timeout only
# when the stage has at most STAGE_CALL_HEADER_CEILING_S left, and then never more than that: a call that starts with
# more budget left is byte-identical to today's request (Do No Harm; live single calls take up to 715 s, ex08 11-13),
# and a call in the last 120 s is cut at the budget with a value already proven live. The stage's hard answer and
# the orphan guards bound the rest (in the stage-runner job the process ends with its answer). Raise the ceiling only
# after a live call per configured model family accepts the larger value.
#
# SLOW-CALL-FALLBACK (RT F2/F3, 11-14): this ceiling rule applies to the architect, compliance, red-team critic and
# decomposer calls. The developer path (lead WBS, swarm juniors, repair, single turn) does NOT use it: there the
# CallWalk below is the only writer of `http_options`, with timeout = min(CallTimeouts cap, stage time left - 15 s).
# Live check 11-14 (RT F2): carbon, argon, gemini-3.8-flash and gemini-3.7-flash on `global` each answered 200 with
# HttpOptions timeouts of 900 s, 240 s and 120 s (docs/planning/slow-call-fallback-rt.md).
STAGE_CALL_MIN_TIMEOUT_MS = 1000
STAGE_CALL_HEADER_CEILING_S = 120
# RT F6: the typed `error_code` of a repair call result whose walk ended because the dispatch's repair wall clock left
# no room for (another) call (SwarmDispatcher.invoke_repair). REPAIR-WALL-CLOCK-ROOM: the repair loop stops on it
# (WALL_CLOCK), and a dispatch whose every walk started no call (`calls_started` 0) is not a repair iteration.
REPAIR_WALL_CLOCK = "REPAIR_WALL_CLOCK"


def call_timeout_ms(remaining_s: float) -> Optional[int]:
    """HTTP timeout (milliseconds) for an LLM call started with `remaining_s` seconds of stage budget left; None (no
    timeout, no header: today's request) while more than STAGE_CALL_HEADER_CEILING_S is left."""
    if remaining_s > STAGE_CALL_HEADER_CEILING_S:
        return None
    return max(STAGE_CALL_MIN_TIMEOUT_MS, int(remaining_s * 1000))
# ------------------------------------------------------------------------------------------ SLOW-CALL-FALLBACK
class CallPurpose(str, Enum):
    WBS = "WBS"                  # lead orchestrator work breakdown
    JUNIOR = "JUNIOR"            # swarm junior code task
    IAC = "IAC"                  # swarm junior IaC intent task (typed-intent IaC synthesis)
    REPAIR = "REPAIR"            # hallucination-stack repair call
    SINGLE_TURN = "SINGLE_TURN"  # whole draft in one call (swarm off or failed, repair plans)


@dataclass(frozen=True)
class CallTimeouts:
    """Per-attempt caps (seconds) by purpose, from the 11-13 Carbon measurements (plan §3.1). A cap is a hung-call
    guard set above the slowest healthy-but-slow call (>= 1.2 x the slowest measured call, >= 2.5 x a healthy one;
    RT F1), never a latency target: a non-streaming call cannot tell "stalled" from "still generating"."""
    wbs_s: float = 240.0
    junior_s: float = 900.0   # 1.26 x the 715 s DB task of 11-13
    iac_s: float = 420.0      # 2-5K-token answers took 126 s and 372 s on 11-13
    repair_s: float = 180.0
    single_turn_s: float = 900.0
    deadline_margin_s: float = 15.0   # left after the last call to answer typed
    min_call_s: float = 20.0          # a call with less room than this is not started

    def __post_init__(self) -> None:
        caps = (self.wbs_s, self.junior_s, self.iac_s, self.repair_s, self.single_turn_s)
        for v in caps + (self.deadline_margin_s, self.min_call_s):
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
                raise ValueError(f"CallTimeouts values must be positive numbers, got {v!r}")
        if self.min_call_s > min(caps):
            raise ValueError(f"min_call_s {self.min_call_s} exceeds the smallest per-call cap {min(caps)}")

    def cap(self, purpose: CallPurpose) -> float:
        return float({CallPurpose.WBS: self.wbs_s, CallPurpose.JUNIOR: self.junior_s, CallPurpose.IAC: self.iac_s,
                      CallPurpose.REPAIR: self.repair_s,
                      CallPurpose.SINGLE_TURN: self.single_turn_s}[CallPurpose(purpose)])


DEFAULT_CALL_TIMEOUTS = CallTimeouts()


def call_timeout_s(purpose: CallPurpose, *, deadline: Optional[float] = None, now: Optional[float] = None,
                   timeouts: CallTimeouts = DEFAULT_CALL_TIMEOUTS) -> Optional[float]:
    """The timeout of one attempt: the purpose's cap, never more than the stage budget left (`deadline - now -
    deadline_margin_s`). None: the room left is below `min_call_s`, so no call may start."""
    cap = timeouts.cap(purpose)
    if deadline is None:
        return cap
    room = float(deadline) - float(time.monotonic() if now is None else now) - timeouts.deadline_margin_s
    if room < timeouts.min_call_s:
        return None
    return min(cap, room)


OK = "OK"
TIMEOUT = "TIMEOUT"
ERROR = "ERROR"
NO_STAGE_BUDGET = "NO_STAGE_BUDGET"
OUTPUT_REJECTED = "OUTPUT_REJECTED"   # manual mode: the model answered in time, the caller rejected the content
USAGE_NONE = "NONE"          # the provider answered nothing billable (transient status, error)
USAGE_REPORTED = "REPORTED"  # the response's usage_metadata was recorded
USAGE_UNKNOWN = "UNKNOWN"    # abandoned with no response: billing unknown
FALLBACK_EXHAUSTED_REASON = "LLM_FALLBACK_EXHAUSTED"
# RT F4: the walk's clock starts before the SDK refreshes the credential and connects and stops after parsing, so an
# answer the SDK accepted within its own timeout can land just after the cap on this clock. It is used, not redone;
# only an answer later than cap + LATE_GRACE_S is late (the SDK's own bound stays authoritative).
LATE_GRACE_S = 5.0
# RT F10 (owner 11-14 approved): one same-model retry after RETRY_BACKOFF_S[0] (4 s) on a 429 / 503 before the walk
# moves down the chain (a Dynamic Shared Quota blip usually clears in seconds; R3c: 9 of 67 repair calls hit 429).
# A 500, a 504 below the bound and a TIMEOUT walk at once. The last model keeps the R3c retries (4 s, 16 s) instead.
# The single switch: False = a transient walks at once.
SAME_MODEL_TRANSIENT_RETRY = True
SAME_MODEL_RETRY_STATUSES = frozenset({429, 503})


def transient_outcome(code: int) -> str:
    return f"TRANSIENT_{int(code)}"


def is_timeout_exception(exc: BaseException) -> bool:
    """Exact type check: the HTTP client's own timeout (httpx.TimeoutException) or a TimeoutError."""
    if isinstance(exc, TimeoutError):
        return True
    try:
        import httpx  # google-genai's HTTP client
    except ImportError:  # pragma: no cover
        return False
    return isinstance(exc, httpx.TimeoutException)


@dataclass
class CallAttempt:
    model: str
    outcome: str                     # OK | TIMEOUT | TRANSIENT_<code> | ERROR | NO_STAGE_BUDGET
    timeout_s: Optional[float]
    elapsed_s: float = 0.0
    usage: str = USAGE_NONE          # NONE | REPORTED | UNKNOWN
    billed_tokens: Optional[int] = None
    late: bool = False               # an answer that arrived after the timeout (never used)
    # RT F9: the billed split of a reported usage: prompt tokens, and output = candidates + thoughts (at least
    # total - prompt), so a ledger counts each where it belongs
    prompt_tokens: Optional[int] = None
    output_tokens: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"model": self.model, "outcome": self.outcome,
                "timeout_s": None if self.timeout_s is None else round(self.timeout_s, 1),
                "elapsed_s": round(self.elapsed_s, 2), "usage": self.usage, "billed_tokens": self.billed_tokens,
                "prompt_tokens": self.prompt_tokens, "output_tokens": self.output_tokens, "late": self.late}


@dataclass
class CallPlan:
    model: str
    index: int                        # position in the walk's chain
    timeout_s: float
    backoff_s: float = 0.0            # wait before this attempt (a transient on the last model)
    started: float = 0.0


def _attempts_text(attempts: Sequence[CallAttempt]) -> str:
    return "; ".join(f"{a.model}: {a.outcome}" + (f" after {a.elapsed_s:.1f}s" if a.outcome != NO_STAGE_BUDGET else "")
                     + (f" (timeout {a.timeout_s:.0f}s)" if a.timeout_s else "") for a in attempts) or "no attempt"


class LlmFallbackExhausted(DeveloperStageError):
    """Every model of the chain timed out or answered a transient status: no answer (class LLM_UNAVAILABLE)."""
    reason = FALLBACK_EXHAUSTED_REASON

    def __init__(self, stage: str, purpose: CallPurpose, attempts: Sequence[CallAttempt]):
        self.stage, self.purpose, self.attempts = stage, CallPurpose(purpose), list(attempts)
        super().__init__(LLM_UNAVAILABLE, f"{FALLBACK_EXHAUSTED_REASON}: stage {stage}, {self.purpose.value} call, "
                                          f"no model answered in time: {_attempts_text(self.attempts)}")

    def to_body(self) -> Dict[str, Any]:
        return {"error_class": self.error_class, "reason": self.reason, "stage": self.stage,
                "purpose": self.purpose.value, "attempts": [a.to_dict() for a in self.attempts]}


class LlmStageBudgetExhausted(DeveloperStageError):
    """The stage's remaining budget leaves no room for another model call (class LLM_STAGE_BUDGET_EXHAUSTED)."""
    reason = LLM_STAGE_BUDGET_EXHAUSTED

    def __init__(self, stage: str, purpose: CallPurpose, attempts: Sequence[CallAttempt]):
        self.stage, self.purpose, self.attempts = stage, CallPurpose(purpose), list(attempts)
        super().__init__(LLM_STAGE_BUDGET_EXHAUSTED, f"stage {stage}, {self.purpose.value} call: the stage budget "
                                                     f"left no room for a model call: {_attempts_text(self.attempts)}")

    def to_body(self) -> Dict[str, Any]:
        return {"error_class": self.error_class, "reason": self.reason, "stage": self.stage,
                "purpose": self.purpose.value, "attempts": [a.to_dict() for a in self.attempts]}


def _int_field(obj: Any, name: str) -> int:
    v = getattr(obj, name, None) if obj is not None else None
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


def usage_split(response: Any) -> "tuple[Optional[int], Optional[int]]":
    """(prompt tokens, output tokens) of a response's usage_metadata; output = max(candidates + thoughts, total -
    prompt) (the repair call's billed-output rule). (None, None) without a reported total."""
    if _usage_total(response) is None:
        return None, None
    um = getattr(response, "usage_metadata", None)
    prompt, total = _int_field(um, "prompt_token_count"), _int_field(um, "total_token_count")
    out = max(_int_field(um, "candidates_token_count") + _int_field(um, "thoughts_token_count"), total - prompt, 0)
    return prompt, out


def _usage_total(response: Any) -> Optional[int]:
    um = getattr(response, "usage_metadata", None) if response is not None else None
    total = getattr(um, "total_token_count", None) if um is not None else None
    return total if isinstance(total, int) and not isinstance(total, bool) else None


def with_http_timeout(config: Any, timeout_s: float) -> Any:
    """A copy of the request config carrying `http_options.timeout` (ms); the request content is unchanged."""
    ms = max(1, int(round(float(timeout_s) * 1000)))
    if isinstance(config, dict):
        return {**config, "http_options": {"timeout": ms}}
    from google.genai import types
    if config is None:
        return types.GenerateContentConfig(http_options=types.HttpOptions(timeout=ms))
    return config.model_copy(update={"http_options": types.HttpOptions(timeout=ms)})


AbandonedSink = Callable[[CallAttempt, Any], None]


def active_stage_bound(deadline: Optional[float], stage_stop: Optional[Callable[[str], BaseException]],
                       clock: Callable[[], float]) -> "tuple[Optional[float], Optional[Callable[[str], BaseException]]]":
    """RT F3: (deadline, stage_stop) of a developer call, filled from the active STAGE-DEADLINE
    (`stage_deadline.current()`) where the caller passed none: the deadline on the walk's own clock
    (`clock() + remaining`, so a test clock and the stage's clock never mix) and the stage's typed stop (RT F5)."""
    try:
        import stage_deadline   # gateway root module (absent in a bare import of this package)
    except ImportError:  # pragma: no cover
        return deadline, stage_stop
    sd = stage_deadline.current()
    if sd is None:
        return deadline, stage_stop
    if deadline is None:
        deadline = clock() + sd.remaining_s()
    if stage_stop is None:
        stage_stop = sd.exceeded
    return deadline, stage_stop
# RT F5: the stage's own stop for "no stage time left" (G7: `stage_deadline.current().exceeded`, class
# STAGE_DEADLINE_EXCEEDED): called with a label ("before developer.JUNIOR call"), returns the exception to raise. One
# class per condition: with a stage stop, the walk never raises LlmStageBudgetExhausted for the same condition.
StageStop = Callable[[str], BaseException]


class CallWalk:
    """One model call walked down a fallback chain (plan §3). Walk mode: `for plan in walk:`. Manual mode (callers
    with their own model loop): `plan(model)`, `config`, then `failed` or `answered`, for each model they try."""

    def __init__(self, models: Sequence[str], *, purpose: CallPurpose, stage: str = "developer",
                 deadline: Optional[float] = None, timeouts: Optional[CallTimeouts] = None,
                 clock: Optional[Callable[[], float]] = None, abandoned: Optional[AbandonedSink] = None,
                 retry_last_on_transient: bool = True, stage_stop: Optional[StageStop] = None):
        chain: List[str] = []
        for m in models:
            if m and m not in chain:
                chain.append(m)
        if not chain:
            raise ValueError("CallWalk needs at least one model")
        self.models = chain
        self.purpose = CallPurpose(purpose)
        self.stage = stage
        self.deadline = deadline
        self.timeouts = timeouts or DEFAULT_CALL_TIMEOUTS
        self.clock = clock or time.monotonic
        self.abandoned = abandoned
        self.retry_last_on_transient = retry_last_on_transient
        self.stage_stop = stage_stop
        self.attempts: List[CallAttempt] = []
        self.answered_model: Optional[str] = None
        self._same_model_retried: set = set()

    # ------------------------------------------------------------------------------------------- per attempt
    def _timeout_now(self, model: str) -> float:
        t = call_timeout_s(self.purpose, deadline=self.deadline, now=self.clock(), timeouts=self.timeouts)
        if t is None:
            self.attempts.append(CallAttempt(model=model, outcome=NO_STAGE_BUDGET, timeout_s=None))
            if self.stage_stop is not None:   # RT F5: an active stage deadline answers with its own class
                raise self.stage_stop(f"before {self.stage}.{self.purpose.value} call ({model})")
            raise LlmStageBudgetExhausted(self.stage, self.purpose, self.attempts)
        return t

    def plan(self, model: str, backoff_s: float = 0.0) -> CallPlan:
        """The next attempt on `model`; raises LlmStageBudgetExhausted when the stage budget has no room for it."""
        index = self.models.index(model) if model in self.models else len(self.models)
        if model not in self.models:
            self.models.append(model)
        return CallPlan(model=model, index=index, timeout_s=self._timeout_now(model), backoff_s=float(backoff_s),
                        started=self.clock())

    def config(self, plan: CallPlan, config: Any) -> Any:
        """The attempt's config with its timeout; call right before the request (after any backoff wait)."""
        plan.timeout_s = min(plan.timeout_s, self._timeout_now(plan.model))
        plan.started = self.clock()
        return with_http_timeout(config, plan.timeout_s)

    def failed(self, plan: CallPlan, exc: BaseException) -> Optional[str]:
        """Classify an exception of the attempt: TIMEOUT / TRANSIENT_<code> (the walk moves on), or None when the
        error is not the walk's (recorded as ERROR; the caller re-raises it and keeps its own handling)."""
        elapsed = max(0.0, self.clock() - plan.started)
        code = transient_status(exc)
        if is_timeout_exception(exc) or (code == 504 and elapsed >= plan.timeout_s):
            att = CallAttempt(plan.model, TIMEOUT, plan.timeout_s, elapsed, usage=USAGE_UNKNOWN)
            self.attempts.append(att)
            self._abandon(att, None)
            return TIMEOUT
        if code is not None:
            self.attempts.append(CallAttempt(plan.model, transient_outcome(code), plan.timeout_s, elapsed))
            return transient_outcome(code)
        self.attempts.append(CallAttempt(plan.model, ERROR, plan.timeout_s, elapsed))
        return None

    def answered(self, plan: CallPlan, response: Any) -> bool:
        """True: the answer arrived within the timeout and may be used. False: it is late, recorded as TIMEOUT
        (its billed tokens go to the abandoned sink) and must never be used. Late = after cap + LATE_GRACE_S."""
        elapsed = max(0.0, self.clock() - plan.started)
        if elapsed > plan.timeout_s + LATE_GRACE_S:
            billed = _usage_total(response)
            prompt_n, out_n = usage_split(response)
            att = CallAttempt(plan.model, TIMEOUT, plan.timeout_s, elapsed,
                              usage=USAGE_REPORTED if billed is not None else USAGE_UNKNOWN, billed_tokens=billed,
                              late=True, prompt_tokens=prompt_n, output_tokens=out_n)
            self.attempts.append(att)
            self._abandon(att, response)
            return False
        self.attempts.append(CallAttempt(plan.model, OK, plan.timeout_s, elapsed, usage=USAGE_REPORTED
                                         if _usage_total(response) is not None else USAGE_NONE,
                                         billed_tokens=_usage_total(response)))
        self.answered_model = plan.model
        return True

    def _abandon(self, attempt: CallAttempt, response: Any) -> None:
        logger.warning(f"{self.stage} {self.purpose.value} call to '{attempt.model}' abandoned: {attempt.outcome} "
                       f"after {attempt.elapsed_s:.1f}s (timeout {attempt.timeout_s:.0f}s, usage {attempt.usage})")
        if self.abandoned is None:
            return
        try:
            self.abandoned(attempt, response)
        except Exception as e:  # noqa: BLE001 - accounting must not change the walk; logged, never swallowed silently
            logger.warning(f"abandoned-call accounting failed for '{attempt.model}': {type(e).__name__}: {e}")

    def same_model_retry_s(self, plan: CallPlan, outcome: Optional[str]) -> Optional[float]:
        """RT F10: the wait before the one same-model retry of `plan.model` after a TRANSIENT_429 / TRANSIENT_503,
        or None (already retried, another outcome, or the switch is off). Manual-mode callers retry the same model
        after this wait; walk mode does it itself."""
        if not SAME_MODEL_TRANSIENT_RETRY or outcome not in {transient_outcome(c) for c in SAME_MODEL_RETRY_STATUSES}:
            return None
        if plan.model in self._same_model_retried:
            return None
        self._same_model_retried.add(plan.model)
        return RETRY_BACKOFF_S[0]

    # ------------------------------------------------------------------------------------------- walk mode
    def __iter__(self) -> Iterator[CallPlan]:
        i, same_retries = 0, 0
        backoff = 0.0
        while i < len(self.models):
            if self.answered_model is not None:
                return
            p = self.plan(self.models[i], backoff_s=backoff)
            yield p
            if self.answered_model is not None:
                return
            last = self.attempts[-1] if self.attempts else None
            if last is None or last.outcome in (OK, ERROR):
                return   # the caller did not report the attempt, or re-raised a non-walk error
            backoff = 0.0
            is_last = i == len(self.models) - 1
            if (last.outcome.startswith("TRANSIENT_") and is_last and self.retry_last_on_transient
                    and same_retries < len(RETRY_BACKOFF_S)):
                backoff = RETRY_BACKOFF_S[same_retries]   # R3c: the last model's retries (4 s, 16 s)
                same_retries += 1
                continue
            if not is_last:
                retry_s = self.same_model_retry_s(p, last.outcome)   # RT F10: one 4 s retry on 429 / 503
                if retry_s is not None:
                    backoff = retry_s
                    continue
            i += 1
        raise self.exhausted()

    # ------------------------------------------------------------------------------------------- results
    @property
    def timed_out(self) -> bool:
        return any(a.outcome == TIMEOUT for a in self.attempts)

    @property
    def any_answer(self) -> bool:
        return self.answered_model is not None or any(a.outcome == OK for a in self.attempts)

    @property
    def primary(self) -> str:
        return self.models[0]

    def left_primary_reason(self) -> Optional[str]:
        """Why the primary's work was not used: the outcome of its last attempt (TIMEOUT / TRANSIENT_<code> / ERROR),
        or OUTPUT_REJECTED when it answered and the caller rejected the content (manual mode: invalid JSON, ...)."""
        prim = [a for a in self.attempts if a.model == self.primary]
        if not prim:
            return None
        return OUTPUT_REJECTED if prim[-1].outcome == OK else prim[-1].outcome

    @property
    def fallback_reason(self) -> Optional[str]:
        """Why the answer came from a fallback model (None: the primary answered, or nothing did)."""
        if self.answered_model is None or self.answered_model == self.primary:
            return None
        return self.left_primary_reason()

    def exhausted(self) -> LlmFallbackExhausted:
        return LlmFallbackExhausted(self.stage, self.purpose, self.attempts)

    def provenance(self) -> Dict[str, Any]:
        model = self.answered_model
        return {"model": model, "primary_model": self.primary,
                "fallback": model is not None and model != self.primary, "fallback_reason": self.fallback_reason,
                "purpose": self.purpose.value, "attempts": [a.to_dict() for a in self.attempts]}


def ledger_abandoned_sink(db: Any, trace_id: Optional[str], agent: str) -> Optional[AbandonedSink]:
    """The token-ledger sink of abandoned attempts for `pipeline_executions/{trace_id}` (None without db/trace):
    a late answer's billed tokens are recorded under `agent` like any used answer, and every abandoned attempt
    increments `token_usage.abandoned_calls_usage_reported` or `..._usage_unknown` (never dropped silently)."""
    if not db or not trace_id:
        return None

    def sink(attempt: CallAttempt, response: Any) -> None:
        if response is not None and attempt.usage == USAGE_REPORTED:
            try:
                from shared.token_accounting import extract_token_usage, record_agent_tokens
            except ImportError:  # pragma: no cover
                from ..shared.token_accounting import extract_token_usage, record_agent_tokens  # type: ignore
            record_agent_tokens(db, trace_id, agent, extract_token_usage(response, attempt.model))
        from google.cloud import firestore
        key = ("abandoned_calls_usage_reported" if attempt.usage == USAGE_REPORTED
               else "abandoned_calls_usage_unknown")
        clean = agent.lower().replace("-", "_")
        db.collection("pipeline_executions").document(trace_id).set(
            {"token_usage": {key: firestore.Increment(1), "by_agent": {clean: {key: firestore.Increment(1)}}}},
            merge=True)

    return sink


# ------------------------------------------------------------------------------------------- provenance text
def _reason_text(reason: Optional[str]) -> str:
    if not reason:
        return ""
    if reason == TIMEOUT:
        return "timeout"
    if reason.startswith("TRANSIENT_"):
        return "transient " + reason[len("TRANSIENT_"):]
    return reason.lower().replace("_", " ")


def model_provenance_record(outputs: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """The run record of who wrote what: {summary, mixed, outputs}. `outputs` entries: {output, model,
    primary_model, fallback, fallback_reason}. Summary: "written by <model>" when every output came from one
    model without a fallback; otherwise the main model plus each fallback output, e.g. "written by gemini-4-carbon;
    task-db by gemini-4-argon (fallback: timeout)"."""
    outs = [dict(o) for o in outputs if o.get("model")]
    models = [o["model"] for o in outs]
    if not outs:
        return {"summary": "", "mixed": False, "outputs": []}
    main = max(dict.fromkeys(models), key=models.count)
    main_outs = [o for o in outs if o["model"] == main]
    main_reasons = {o.get("fallback_reason") for o in main_outs}
    # every output of the main model came from the same fallback: "written by <model> (fallback: <why>)"
    main_all_fallback = all(o.get("fallback") for o in main_outs) and len(main_reasons) == 1
    head = f"written by {main}"
    if main_all_fallback and _reason_text(next(iter(main_reasons))):
        head += f" (fallback: {_reason_text(next(iter(main_reasons)))})"
    parts = [head]
    for o in outs:
        if o["model"] != main or (o.get("fallback") and not main_all_fallback):
            why = _reason_text(o.get("fallback_reason"))
            parts.append(f"{o.get('output')} by {o['model']}" + (f" (fallback: {why})" if why else ""))
    return {"summary": "; ".join(parts), "mixed": len(set(models)) > 1, "outputs": outs}
