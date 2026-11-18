"""Sticky per-run state (red-team H7).

Guards, tripwires and the budget record events here *and* raise. Product code swallows most exceptions, so the
stage runner consults this state at every stage boundary (`check_boundary`) and stops the run when a fatal
reason is set. Thread-safe: junior LLM calls run on executor threads.
"""
from __future__ import annotations

import threading
import time
import traceback
from typing import Any, Dict, List, Optional

from .errors import EvalAbort

# Reasons that invalidate a run (excluded from quality metrics).
INVALID_REASONS = {
    "fallback_tripwire",        # a deterministic stub/fallback path ran (FD-4C)
    "budget_exceeded",          # budget/token/call cap refused a call
    "unpriced_model",           # a call targeted a model with no price row
    "token_bound_violation",    # candidates+thoughts exceeded max_output_tokens (B6 calibration assertion)
    "isolation_guard_ineffective",
    "replay_miss",
    "timeout",
    "harness_error",
    "unmetered_llm_client",     # product tried to build its own genai client
}
# Reasons that also stop the run at the next stage boundary (no point spending more).
FATAL_REASONS = {"budget_exceeded", "unpriced_model", "isolation_guard_ineffective", "timeout", "harness_error",
                 "replay_miss", "unmetered_llm_client", "fallback_tripwire", "token_bound_violation"}


class RunState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.invalid_reasons: List[str] = []
        self.events: List[Dict[str, Any]] = []
        self.flags: Dict[str, Any] = {}
        self.stage: Optional[str] = None

    # -- recording ---------------------------------------------------------------------------------------
    def record(self, kind: str, detail: Any = None, *, stack: bool = False, invalid: Optional[str] = None) -> None:
        evt = {"kind": kind, "detail": detail, "stage": self.stage, "t": time.time(),
               "thread": threading.current_thread().name}
        if stack:
            evt["stack"] = "".join(traceback.format_stack(limit=14)[:-2])
        with self._lock:
            self.events.append(evt)
            if invalid and invalid not in self.invalid_reasons:
                self.invalid_reasons.append(invalid)

    def invalidate(self, reason: str, detail: Any = None) -> None:
        self.record("invalid", {"reason": reason, "detail": detail}, invalid=reason)

    def set_flag(self, name: str, value: Any = True) -> None:
        with self._lock:
            self.flags[name] = value

    # -- queries ------------------------------------------------------------------------------------------
    def events_of(self, kind: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [e for e in self.events if e["kind"] == kind]

    @property
    def valid(self) -> bool:
        with self._lock:
            return not self.invalid_reasons

    @property
    def fatal(self) -> Optional[str]:
        with self._lock:
            for r in self.invalid_reasons:
                if r in FATAL_REASONS:
                    return r
        return None

    def check_boundary(self, next_stage: str) -> None:
        reason = self.fatal
        if reason:
            raise EvalAbort(f"run stopped before stage '{next_stage}': {reason}")
        self.stage = next_stage

    def to_json(self) -> Dict[str, Any]:
        with self._lock:
            return {"invalid_reasons": list(self.invalid_reasons), "flags": dict(self.flags),
                    "events": list(self.events)}


_STATE: Optional[RunState] = None


def get_state() -> RunState:
    global _STATE
    if _STATE is None:
        _STATE = RunState()
    return _STATE


def reset_state() -> RunState:
    global _STATE
    _STATE = RunState()
    return _STATE
