"""FD-30 harness budget (red-team B5/B6): exact magnitudes, sticky refusal, concurrency never overshoots."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import random
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "eval"))

from stackvend_eval.budget import (Budget, InvocationLedger, Price, PriceTable,  # noqa: E402
                                   estimate_input_tokens)
from stackvend_eval.errors import EvalBudgetExceeded, EvalUnpricedModel  # noqa: E402
from stackvend_eval.state import RunState  # noqa: E402

# ceiling $1.00 / 1M input tokens, $10.00 / 1M output tokens
PRICES = PriceTable({"m": Price("m", 1.0, 10.0, 0.5, 5.0, True, 65536)})
IN_BYTES = 936          # -> 936 + 64 = 1000 input tokens
MAX_OUT = 9000
WORST = 1000 * 1e-6 + 9000 * 10e-6          # 0.091
USAGE = {"prompt": 500, "candidates": 1000, "thoughts": 500}
ACTUAL = 500 * 1e-6 + 1500 * 10e-6          # 0.0155


def test_input_estimate_is_a_strict_upper_bound():
    assert estimate_input_tokens(936) == 1000
    assert estimate_input_tokens(0) == 64


def test_reserve_settle_exact_magnitudes():
    b = Budget(1.0, 10 ** 9, PRICES, max_calls=1000)
    r = b.reserve("m", IN_BYTES, MAX_OUT)
    assert r.usd == pytest.approx(WORST, abs=1e-12)
    assert b.snapshot()["outstanding_usd"] == pytest.approx(0.091, abs=1e-9)
    s = b.settle(r, USAGE)
    assert s["usd"] == pytest.approx(ACTUAL, abs=1e-12)
    snap = b.snapshot()
    assert snap["settled_usd"] == pytest.approx(0.0155, abs=1e-9)
    assert snap["outstanding_usd"] == pytest.approx(0.0, abs=1e-12)
    assert snap["settled_tokens"] == 2000


def test_refuses_exactly_at_call_60_and_is_sticky():
    state = RunState()
    b = Budget(1.0, 10 ** 9, PRICES, max_calls=1000, state=state)
    refused_at = None
    for i in range(1, 100):
        try:
            r = b.reserve("m", IN_BYTES, MAX_OUT)
        except EvalBudgetExceeded:
            refused_at = i
            break
        b.settle(r, USAGE)
    # 59 calls settle 59 * 0.0155 = 0.9145; call 60 would need 0.9145 + 0.091 = 1.0055 > 1.00
    assert refused_at == 60
    assert b.snapshot()["settled_usd"] == pytest.approx(0.9145, abs=1e-9)
    assert "budget_exceeded" in state.invalid_reasons and state.fatal == "budget_exceeded"
    with pytest.raises(EvalBudgetExceeded):  # sticky: even a tiny call is refused now
        b.reserve("m", 0, 1)


def test_usage_less_failure_charges_full_reservation():
    b = Budget(1.0, 10 ** 9, PRICES)
    r = b.reserve("m", IN_BYTES, MAX_OUT)
    out = b.settle(r, None)
    assert out["basis"] == "full_reservation"
    assert b.snapshot()["settled_usd"] == pytest.approx(0.091, abs=1e-12)


def test_settle_bills_total_minus_prompt_when_candidates_are_missing():
    """RT finding 2: usage with total_token_count but no candidates_token_count (safety-blocked / empty candidate,
    thoughts billed only under total) must charge total - prompt as output, not $0."""
    b = Budget(1.0, 10 ** 9, PRICES)
    r = b.reserve("m", IN_BYTES, MAX_OUT)
    out = b.settle(r, {"prompt": 100, "total": 5000})
    assert out["tokens"] == 5000 and out["bound_violation"] is False
    assert out["usd"] == pytest.approx(100 * 1e-6 + 4900 * 10e-6, abs=1e-12)  # 4,900 output tokens charged
    assert b.snapshot()["settled_usd"] == pytest.approx(0.0491, abs=1e-12)


def test_settle_with_full_usage_shape_is_unchanged_and_bound_uses_the_same_out():
    b = Budget(1.0, 10 ** 9, PRICES)
    r = b.reserve("m", IN_BYTES, MAX_OUT)
    full = dict(USAGE, total=USAGE["prompt"] + USAGE["candidates"] + USAGE["thoughts"])  # consistent total
    assert b.settle(r, full)["usd"] == pytest.approx(ACTUAL, abs=1e-12)
    r2 = b.reserve("m", IN_BYTES, MAX_OUT)
    low_total = dict(USAGE, total=600)                   # total smaller than parts: parts win, never a credit
    assert b.settle(r2, low_total)["usd"] == pytest.approx(ACTUAL, abs=1e-12)
    state = RunState()
    b2 = Budget(10.0, 10 ** 9, PRICES, state=state)
    r3 = b2.reserve("m", IN_BYTES, 1000)                 # total-only usage above the cap trips the bound too
    assert b2.settle(r3, {"prompt": 10, "total": 1500})["bound_violation"] is True
    assert "token_bound_violation" in state.invalid_reasons


def test_unknown_model_is_refused_fail_closed():
    state = RunState()
    b = Budget(1.0, 10 ** 9, PRICES, state=state)
    with pytest.raises(EvalUnpricedModel):
        b.reserve("gemini-unknown", 10, 10)
    assert "unpriced_model" in state.invalid_reasons


def test_token_cap_is_price_independent():
    b = Budget(1000.0, 25_000, PRICES, max_calls=1000)
    r1 = b.reserve("m", IN_BYTES, MAX_OUT)   # 10,000 reserved tokens
    b.settle(r1, USAGE)                        # 2,000 settled
    r2 = b.reserve("m", IN_BYTES, MAX_OUT)
    b.settle(r2, {"prompt": 1000, "candidates": 9000, "thoughts": 0})  # 10,000 settled -> 12,000
    with pytest.raises(EvalBudgetExceeded):    # 12,000 + 10,000 fits; then 22,000 + 10,000 > 25,000
        r3 = b.reserve("m", IN_BYTES, MAX_OUT)
        b.settle(r3, {"prompt": 1000, "candidates": 9000, "thoughts": 0})
        b.reserve("m", IN_BYTES, MAX_OUT)
    assert b.snapshot()["settled_tokens"] == 22_000


def test_thinking_tokens_outside_max_output_invalidate_the_run():
    state = RunState()
    b = Budget(10.0, 10 ** 9, PRICES, state=state)
    r = b.reserve("m", IN_BYTES, 1000)
    out = b.settle(r, {"prompt": 10, "candidates": 900, "thoughts": 200})
    assert out["bound_violation"] is True
    assert "token_bound_violation" in state.invalid_reasons
    with pytest.raises(EvalBudgetExceeded):
        b.reserve("m", 1, 1)


def test_five_concurrent_callers_never_exceed_cap():
    cap = 0.5
    b = Budget(cap, 10 ** 9, PRICES, max_calls=10_000, wait_timeout_s=30)
    peaks = []
    lock = threading.Lock()
    rng = random.Random(7)

    def worker():
        while True:
            try:
                r = b.reserve("m", IN_BYTES, MAX_OUT)
            except EvalBudgetExceeded:
                return
            snap = b.snapshot()
            with lock:
                peaks.append(snap["settled_usd"] + snap["outstanding_usd"])
            time.sleep(0.002)
            with lock:
                c = rng.randint(0, MAX_OUT)
            b.settle(r, {"prompt": 1000, "candidates": c, "thoughts": 0})

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert peaks, "no call was admitted"
    assert max(peaks) <= cap + 1e-9
    assert b.snapshot()["settled_usd"] <= cap + 1e-9
    assert b.snapshot()["outstanding_usd"] == pytest.approx(0.0, abs=1e-9)
    assert b.exceeded is not None


def test_invocation_ledger_counts_outstanding_allocations_and_dead_children():
    led = InvocationLedger(10.0)
    assert led.admit("a", 3.0, 0.7) == 3.0
    assert led.admit("b", 3.0, 0.7) == 3.0
    assert led.admit("c", 3.0, 0.7) == 3.0
    assert led.admit("d", 3.0, 0.7) == pytest.approx(1.0)  # only $1 unallocated
    assert led.admit("e", 3.0, 0.7) is None
    assert led.close("a", 0.25) == pytest.approx(0.25)     # finished child: charged what it reported
    assert led.close("b", None) == pytest.approx(3.0)      # dead child: charged its whole allocation
    snap = led.snapshot()
    assert snap["settled_usd"] == pytest.approx(3.25)
    assert snap["outstanding_usd"] == pytest.approx(4.0)
    assert led.admit("f", 3.0, 0.7) == pytest.approx(2.75)


def test_committed_price_table_loads_with_ceiling_and_flags():
    t = PriceTable.load(Path(__file__).resolve().parent.parent / "eval" / "config" / "pricing.json")
    p = t.get("gemini-3.8-flash")
    assert p.in_per_m == pytest.approx(2 * p.list_in_per_m)
    assert p.out_per_m == pytest.approx(2 * p.list_out_per_m)
    assert t.get("gemini-3.7-flash")
    with pytest.raises(EvalUnpricedModel):
        t.get("gemini-9.9-ultra")


# ------------------------------------------------------------------------- AC-5: budget stall measured apart
def test_unblocked_reserves_record_no_wait():
    b = Budget(1.0, 10 ** 9, PRICES, max_calls=1000)
    b.settle(b.reserve("m", IN_BYTES, MAX_OUT), USAGE)
    snap = b.snapshot()
    assert snap["wait_s"] == 0.0 and snap["waits"] == 0


def test_blocked_reserve_records_its_wait_seconds():
    b = Budget(0.15, 10 ** 9, PRICES, max_calls=1000)  # room for one worst-case reservation in flight
    r1 = b.reserve("m", IN_BYTES, MAX_OUT)
    t = threading.Timer(0.3, lambda: b.settle(r1, USAGE))
    t.start()
    r2 = b.reserve("m", IN_BYTES, MAX_OUT)              # blocks until r1 settles
    t.join()
    b.settle(r2, USAGE)
    snap = b.snapshot()
    assert snap["waits"] == 1 and 0.2 <= snap["wait_s"] < 5.0


def test_wait_is_recorded_when_the_wait_times_out():
    b = Budget(0.1, 10 ** 9, PRICES, max_calls=1000, wait_timeout_s=0.2)
    b.reserve("m", IN_BYTES, MAX_OUT)
    with pytest.raises(EvalBudgetExceeded):
        b.reserve("m", IN_BYTES, MAX_OUT)
    snap = b.snapshot()
    assert snap["waits"] == 1 and snap["wait_s"] >= 0.15
