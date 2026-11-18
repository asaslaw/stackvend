"""Hard LLM budget (red-team B5/B6): atomic reservations, settle-to-actual, sticky exceeded flag, per-model
fail-closed pricing and a price-independent token cap.

Per call:  worst = est_input_tokens * in_price + max_output_tokens * out_price   (ceiling prices = 2x list;
           est_input_tokens = request UTF-8 bytes + 64, a strict upper bound on input tokens)
           reserve(worst) under a lock BEFORE the call; settle to actual usage after; a call that fails without
           usage is charged the full reservation (a timed-out request can still be billed).
Invariant: settled + outstanding <= cap at all times (both USD and tokens), provided actual <= reserved, which
           holds because Vertex counts thinking tokens inside max_output_tokens. If a response ever violates that
           (candidates + thoughts > max_output_tokens) the run is invalidated (token_bound_violation) and the
           budget goes sticky-exceeded.
Concurrency: if settled + worst fits but outstanding reservations of other in-flight calls do not, the caller
           WAITS (bounded) for them to settle instead of failing, so the swarm's 5 concurrent juniors do not cause
           spurious refusals at a small cap. If settled + worst alone does not fit -> refuse immediately, sticky.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from .errors import EvalBudgetExceeded, EvalUnpricedModel
from .state import RunState

DEFAULT_MAX_OUTPUT_TOKENS = 65536  # what Vertex applies when a request sets no max_output_tokens (Flash class)


@dataclass(frozen=True)
class Price:
    model: str
    in_per_m: float          # ceiling USD per 1M input tokens
    out_per_m: float         # ceiling USD per 1M output tokens (candidates + thoughts)
    list_in_per_m: float
    list_out_per_m: float
    verified: bool
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS


class PriceTable:
    def __init__(self, prices: Dict[str, Price], source: str = "<memory>"):
        self.prices = prices
        self.source = source

    @classmethod
    def load(cls, path: Path) -> "PriceTable":
        data = json.loads(Path(path).read_text())
        mult = float(data.get("ceiling_multiplier", 2.0))
        prices = {}
        for model, row in data["models"].items():
            prices[model] = Price(
                model=model,
                in_per_m=round(float(row["list_in_per_m"]) * mult, 6),
                out_per_m=round(float(row["list_out_per_m"]) * mult, 6),
                list_in_per_m=float(row["list_in_per_m"]),
                list_out_per_m=float(row["list_out_per_m"]),
                verified=bool(row.get("verified", False)),
                max_output_tokens=int(row.get("max_output_tokens", DEFAULT_MAX_OUTPUT_TOKENS)),
            )
        return cls(prices, str(path))

    def get(self, model: str) -> Price:
        key = (model or "").split("/")[-1]  # tolerate publishers/google/models/<id>
        if key not in self.prices:
            raise EvalUnpricedModel(f"model '{model}' has no row in {self.source}; refusing (fail closed)")
        return self.prices[key]


INPUT_OVERHEAD_TOKENS = 64  # role/turn markers the API adds around the payload


def estimate_input_tokens(payload_bytes: int) -> int:
    """Strict upper bound: a token never covers less than one UTF-8 byte, so tokens <= bytes.

    (The red-team suggested bytes / 2. That is usually pessimistic but is not a bound; input is a small share of
    cost, so the harness takes the strict bound to keep the cap hard.)"""
    return int(payload_bytes) + INPUT_OVERHEAD_TOKENS


@dataclass
class Reservation:
    rid: int
    model: str
    usd: float
    tokens: int
    max_output_tokens: int
    price: Price
    t0: float = field(default_factory=time.time)
    settled: bool = False


class Budget:
    def __init__(self, cap_usd: float, token_cap: int, prices: PriceTable, *, max_calls: int = 60,
                 state: Optional[RunState] = None, wait_timeout_s: float = 900.0):
        if cap_usd < 0 or token_cap < 0:
            raise ValueError("caps must be >= 0")
        self.cap_usd = float(cap_usd)
        self.token_cap = int(token_cap)
        self.prices = prices
        self.max_calls = int(max_calls)
        self.state = state
        self.wait_timeout_s = wait_timeout_s
        self._cond = threading.Condition()
        self.settled_usd = 0.0
        self.outstanding_usd = 0.0
        self.settled_tokens = 0
        self.outstanding_tokens = 0
        self.calls_reserved = 0
        self.calls_refused = 0
        # AC-5: time reserve() spent blocked on in-flight reservations (a budget stall, not model latency)
        self.wait_s = 0.0
        self.waits = 0
        self.exceeded: Optional[str] = None
        self._next_id = 0
        self.ledger: list = []

    # ---------------------------------------------------------------------------------------- internals
    def _trip(self, reason: str, detail: str) -> None:
        # caller holds the lock
        if self.exceeded is None:
            self.exceeded = detail
        self.calls_refused += 1
        if self.state is not None:
            self.state.invalidate(reason, detail)
        self._cond.notify_all()

    def worst_case(self, model: str, input_bytes: int, max_output_tokens: Optional[int]) -> tuple:
        price = self.prices.get(model)
        est_in = estimate_input_tokens(input_bytes)
        max_out = int(max_output_tokens or price.max_output_tokens)
        usd = est_in * price.in_per_m / 1e6 + max_out * price.out_per_m / 1e6
        return price, est_in, max_out, usd, est_in + max_out

    # ------------------------------------------------------------------------------------------- public
    def reserve(self, model: str, input_bytes: int, max_output_tokens: Optional[int]) -> Reservation:
        with self._cond:
            if self.exceeded is not None:
                self.calls_refused += 1
                raise EvalBudgetExceeded(f"budget already exceeded (sticky): {self.exceeded}")
            try:
                price, est_in, max_out, usd, tokens = self.worst_case(model, input_bytes, max_output_tokens)
            except EvalUnpricedModel as e:
                self._trip("unpriced_model", str(e))
                raise
            if self.calls_reserved >= self.max_calls:
                self._trip("budget_exceeded", f"call cap {self.max_calls} reached")
                raise EvalBudgetExceeded(self.exceeded)
            if self.settled_usd + usd > self.cap_usd + 1e-12:
                self._trip("budget_exceeded", f"USD cap ${self.cap_usd:.4f}: settled ${self.settled_usd:.4f} + "
                                               f"worst ${usd:.4f} for {model}")
                raise EvalBudgetExceeded(self.exceeded)
            if self.settled_tokens + tokens > self.token_cap:
                self._trip("budget_exceeded", f"token cap {self.token_cap}: settled {self.settled_tokens} + "
                                               f"worst {tokens}")
                raise EvalBudgetExceeded(self.exceeded)
            t_wait = time.monotonic()
            deadline = t_wait + self.wait_timeout_s
            blocked = self._no_room(usd, tokens)
            try:
                while self._no_room(usd, tokens):
                    if self.exceeded is not None:
                        self.calls_refused += 1
                        raise EvalBudgetExceeded(f"budget exceeded while waiting: {self.exceeded}")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._trip("budget_exceeded", "timed out waiting for in-flight reservations to settle")
                        raise EvalBudgetExceeded(self.exceeded)
                    self._cond.wait(timeout=min(remaining, 5.0))
                    # re-check the immediate-refusal condition: others may have settled high
                    if self.settled_usd + usd > self.cap_usd + 1e-12:
                        self._trip("budget_exceeded", f"USD cap ${self.cap_usd:.4f} after wait")
                        raise EvalBudgetExceeded(self.exceeded)
                    if self.settled_tokens + tokens > self.token_cap:
                        self._trip("budget_exceeded", f"token cap {self.token_cap} after wait")
                        raise EvalBudgetExceeded(self.exceeded)
            finally:
                if blocked:  # AC-5: a budget stall is recorded apart from model latency
                    self.wait_s += time.monotonic() - t_wait
                    self.waits += 1
            self._next_id += 1
            self.calls_reserved += 1
            self.outstanding_usd += usd
            self.outstanding_tokens += tokens
            return Reservation(self._next_id, model, usd, tokens, max_out, price)

    def _no_room(self, usd: float, tokens: int) -> bool:
        # caller holds the lock: the in-flight reservations leave no room for this one yet
        return (self.settled_usd + self.outstanding_usd + usd > self.cap_usd + 1e-12
                or self.settled_tokens + self.outstanding_tokens + tokens > self.token_cap)

    def settle(self, res: Reservation, usage: Optional[Dict[str, int]]) -> Dict[str, Any]:
        """usage: {'prompt': n, 'candidates': n, 'thoughts': n, 'cached': n, 'total': n} or None (charge full
        reservation). Output is billed as max(candidates + thoughts, total - prompt): a response that reports
        total_token_count but omits candidates_token_count (safety-blocked / empty candidate) is not under-charged
        (RT finding 2)."""
        with self._cond:
            if res.settled:
                raise RuntimeError("reservation settled twice")
            res.settled = True
            self.outstanding_usd -= res.usd
            self.outstanding_tokens -= res.tokens
            if usage is None:
                actual_usd, actual_tokens, basis = res.usd, res.tokens, "full_reservation"
            else:
                p = int(usage.get("prompt") or 0)
                out = max(int(usage.get("candidates") or 0) + int(usage.get("thoughts") or 0),
                          int(usage.get("total") or 0) - p, 0)
                actual_usd = p * res.price.in_per_m / 1e6 + out * res.price.out_per_m / 1e6
                actual_tokens = p + out
                basis = "usage"
                if out > res.max_output_tokens:
                    self.settled_usd += actual_usd
                    self.settled_tokens += actual_tokens
                    self._trip("token_bound_violation",
                               f"{res.model}: candidates+thoughts={out} > max_output_tokens={res.max_output_tokens}")
                    self.ledger.append({"rid": res.rid, "model": res.model, "usd": actual_usd, "basis": basis})
                    return {"usd": actual_usd, "tokens": actual_tokens, "basis": basis, "bound_violation": True}
            self.settled_usd += actual_usd
            self.settled_tokens += actual_tokens
            if self.settled_usd > self.cap_usd + 1e-9 or self.settled_tokens > self.token_cap:
                self._trip("budget_exceeded", "settled spend above cap (input estimate exceeded)")
            self.ledger.append({"rid": res.rid, "model": res.model, "usd": actual_usd, "basis": basis})
            self._cond.notify_all()
            return {"usd": actual_usd, "tokens": actual_tokens, "basis": basis, "bound_violation": False}

    def settle_rejected(self, res: Reservation, status: int) -> Dict[str, Any]:
        """TI-3 smoke diagnosis (10-20): a call the provider REJECTED with HTTP 429 (RESOURCE_EXHAUSTED: quota; the
        request is refused before any model work and is not billed) carries no usage. It used to be charged the full
        ceiling reservation (about $0.53 per Flash call at 65 536 max output tokens); in the two TI-3 smokes that
        booked 81 % of the charged spend on calls that cost nothing. Only the exact status 429 settles at $0 (basis
        `provider_rejected_429`); every other usage-less failure (timeout, 5xx, transport) keeps the full charge."""
        if status != 429:
            raise ValueError("only HTTP 429 is a provider rejection that is never billed")
        with self._cond:
            if res.settled:
                raise RuntimeError("reservation settled twice")
            res.settled = True
            self.outstanding_usd -= res.usd
            self.outstanding_tokens -= res.tokens
            basis = f"provider_rejected_{status}"
            self.ledger.append({"rid": res.rid, "model": res.model, "usd": 0.0, "basis": basis})
            self._cond.notify_all()
            return {"usd": 0.0, "tokens": 0, "basis": basis, "bound_violation": False}

    def snapshot(self) -> Dict[str, Any]:
        with self._cond:
            return {"cap_usd": self.cap_usd, "token_cap": self.token_cap, "max_calls": self.max_calls,
                    "settled_usd": round(self.settled_usd, 6), "outstanding_usd": round(self.outstanding_usd, 6),
                    "settled_tokens": self.settled_tokens, "outstanding_tokens": self.outstanding_tokens,
                    "calls_reserved": self.calls_reserved, "calls_refused": self.calls_refused,
                    "wait_s": round(self.wait_s, 3), "waits": self.waits,
                    "exceeded": self.exceeded, "price_source": self.prices.source}


class InvocationLedger:
    """Parent-side cap across children (B5.2). A child is admitted with an allocation only if
    cap - settled - sum(outstanding allocations) >= allocation. A child that dies without reporting is charged its
    full allocation."""

    def __init__(self, cap_usd: float, ledger_path: Optional[Path] = None):
        self.cap_usd = float(cap_usd)
        self.settled_usd = 0.0
        self.outstanding: Dict[str, float] = {}
        self._lock = threading.Lock()
        self.ledger_path = ledger_path

    def admit(self, run_key: str, want_usd: float, min_usd: float) -> Optional[float]:
        with self._lock:
            free = self.cap_usd - self.settled_usd - sum(self.outstanding.values())
            alloc = min(want_usd, free)
            if alloc + 1e-12 < min_usd or alloc <= 0:
                return None
            self.outstanding[run_key] = alloc
            return alloc

    def close(self, run_key: str, reported_usd: Optional[float]) -> float:
        with self._lock:
            alloc = self.outstanding.pop(run_key)
            charged = alloc if reported_usd is None else min(max(float(reported_usd), 0.0), alloc)
            if reported_usd is not None and float(reported_usd) > alloc + 1e-9:
                charged = float(reported_usd)  # never under-report what was actually spent
            self.settled_usd += charged
            if self.ledger_path is not None:
                self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
                with self.ledger_path.open("a") as fh:
                    fh.write(json.dumps({"t": time.time(), "run": run_key, "allocated_usd": alloc,
                                         "reported_usd": reported_usd, "charged_usd": charged}) + "\n")
            return charged

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {"cap_usd": self.cap_usd, "settled_usd": round(self.settled_usd, 6),
                    "outstanding_usd": round(sum(self.outstanding.values()), 6)}
