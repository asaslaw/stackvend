"""QA-REPAIR-BUDGET (owner 10-29): the repair budgets for QA-RETRIES' 3 QA repair rounds.

- `repair_wall_clock_s` (900 s since REPAIR-WALL-CLOCK-900, owner 11-15; 360 s before) is a per-developer-dispatch budget, as its description always said: the loop counts
  only this dispatch's time (RepairLedger.wall_clock_ms still keeps the trace total), and the QA-repair pre-check no
  longer refuses a dispatch because earlier dispatches of the trace used their wall clock.
- Per trace: 10 repair iterations (was 5) and 2x the token budget for every swarm envelope (500_000 x 1.4: 490_000 at
  the default envelope; was 250_000 x 0.7 = 245_000).
- Per dispatch: the old per-trace token budget (250_000 x 0.7) and the precommit cap (3), so a single-round run (one
  dispatch on a fresh trace) stops exactly where it stopped before.
Every stop keeps its typed kind (RepairBudgetExhausted ITERATIONS / WALL_CLOCK / TOKENS).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import pytest

from test_step1_s1b_loop import BUCKETS, MAIN, REFS, Persona, _ctx  # noqa: E402
from developer_agent import qa_repair as QR  # noqa: E402
from developer_agent.repair_loop import RepairLoop  # noqa: E402
from shared.diagnostics import MemoryLedgerStore, RepairBudgetExhausted, RepairLedger  # noqa: E402
from shared.hallucination_stack import (HallucinationStackSettings, effective_dispatch_token_budget,  # noqa: E402
                                        effective_repair_token_budget)
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

BROKEN = {MAIN: BUCKETS + REFS}
FIXED = BUCKETS + 'resource "google_storage_bucket" "b" {\n  name = "b"\n}\n' + REFS
# Today's (pre-row) per-trace values: with them, trace budget == dispatch budget, i.e. the old behaviour.
OLD = dict(repair_max_iterations_total=5, repair_token_budget=250_000, repair_budget_envelope_fraction=0.7)


class Clock:
    def __init__(self, step=0.0):
        self.t, self.step = 1000.0, step

    def __call__(self):
        self.t += self.step
        return self.t


def _run(persona, *, ledger=None, settings=None, clock=None):
    store = MemoryLedgerStore()
    if ledger is not None:
        store.save(ledger)
    ctx = _ctx(persona, ledger=store, settings=settings)
    if clock is not None:
        ctx.clock = clock
    try:
        tree, report = RepairLoop(ctx).run(dict(BROKEN))
        out = ("PASS", report.status)
    except RepairBudgetExhausted as e:
        out = ("EXHAUSTED", e.exhausted_reason)
    return out, persona, store.load("t1")


def test_settings_sized_for_three_qa_rounds():
    s = HallucinationStackSettings()
    assert s.repair_max_iterations_total == 10 and s.repair_max_iterations_precommit == 3
    assert effective_repair_token_budget(s) == 490_000 and effective_dispatch_token_budget(s) == 245_000
    old = HallucinationStackSettings(**OLD)
    assert effective_repair_token_budget(old) == effective_dispatch_token_budget(old) == 245_000
    assert s.repair_wall_clock_s == 900   # REPAIR-WALL-CLOCK-900 (owner 11-15; was 360)


# ------------------------------------------------------------------------------------------------ single round: as before
@pytest.mark.parametrize("tokens", [(100, 200, 50), (200_000, 50_000, 0)])
def test_n_one_dispatch_on_a_fresh_trace_stops_where_it_did_before(tokens):
    """No improvement, then the budget: the same stop (TOKENS after a 250k call, else the precommit cap), the same
    number of repair calls and the same prompts ('N remaining') as with today's values."""
    runs = []
    for settings in (None, HallucinationStackSettings(**OLD)):
        out, persona, ledger = _run(Persona({}, {}, {}, {}, tokens=tokens), settings=settings)
        runs.append((out, [t.prompt() for t in persona.tasks], ledger.iteration, ledger.tokens_spent))
    assert runs[0] == runs[1]
    assert runs[0][0] == ("EXHAUSTED", "TOKENS" if tokens[0] == 200_000 else "ITERATIONS")


def test_n_one_dispatch_that_converges_is_unchanged():
    runs = [_run(Persona({MAIN: FIXED}), settings=s) for s in (None, HallucinationStackSettings(**OLD))]
    assert [(o, len(p.tasks), lg.iteration) for o, p, lg in runs] == [(("PASS", "PASS"), 1, 1)] * 2


def test_n_wall_clock_of_one_dispatch_on_a_fresh_trace_stops_as_before():
    for settings in (None, HallucinationStackSettings(**OLD)):
        out, persona, ledger = _run(Persona({MAIN: FIXED}), settings=settings, clock=Clock(step=1000.0))   # past both the old 360 s and the 900 s default
        assert out == ("EXHAUSTED", "WALL_CLOCK") and persona.tasks == []
        assert ledger.exhausted_reason == "WALL_CLOCK"


# ------------------------------------------------------------------------------------------------ later rounds: more room
def test_wall_clock_is_per_dispatch_not_summed_across_the_trace():
    earlier = RepairLedger(trace_id="t1", iteration=2, wall_clock_ms=10 ** 9)   # earlier dispatches' time
    out, persona, ledger = _run(Persona({MAIN: FIXED}), ledger=earlier, clock=Clock(step=1.0))
    assert out == ("PASS", "PASS") and len(persona.tasks) == 1
    assert ledger.wall_clock_ms > 10 ** 9                                          # the trace total is still kept
    assert QR.budget_spent(earlier, HallucinationStackSettings(), 490_000) is None


def test_a_later_dispatch_gets_its_own_token_budget_within_the_trace_budget():
    """Before: 244k spent by earlier dispatches left no room (TOKENS). Now the dispatch has its own 245k."""
    earlier = RepairLedger(trace_id="t1", iteration=3, tokens_in=244_000)
    out_old, p_old, _ = _run(Persona({MAIN: FIXED}), ledger=earlier, settings=HallucinationStackSettings(**OLD))
    assert out_old == ("EXHAUSTED", "TOKENS") and p_old.tasks == []
    out, persona, ledger = _run(Persona({MAIN: FIXED}), ledger=earlier)
    assert out == ("PASS", "PASS") and len(persona.tasks) == 1 and ledger.iteration == 4


def test_the_dispatch_token_budget_still_binds_inside_a_later_dispatch():
    earlier = RepairLedger(trace_id="t1", iteration=3, tokens_in=100_000)
    out, persona, ledger = _run(Persona({}, {}, tokens=(200_000, 50_000, 0)), ledger=earlier)
    assert out == ("EXHAUSTED", "TOKENS") and len(persona.tasks) == 1            # 250k in this dispatch > 245k
    assert ledger.tokens_spent == 350_000 < 490_000 and ledger.exhausted_reason == "TOKENS"


def test_the_trace_token_budget_binds():
    out, persona, _ = _run(Persona({MAIN: FIXED}), ledger=RepairLedger(trace_id="t1", tokens_in=489_990))
    assert out == ("EXHAUSTED", "TOKENS") and persona.tasks == []
    assert QR.budget_spent(RepairLedger(trace_id="t", tokens_in=490_000), HallucinationStackSettings(),
                           490_000) == "TOKENS"


@pytest.mark.parametrize("before,expected", [(5, ("PASS", "PASS")), (9, ("PASS", "PASS")),
                                             (10, ("EXHAUSTED", "ITERATIONS"))])
def test_trace_iterations_allow_ten(before, expected):
    out, persona, _ = _run(Persona({MAIN: FIXED}), ledger=RepairLedger(trace_id="t1", iteration=before))
    assert out == expected and len(persona.tasks) == (0 if before == 10 else 1)


def test_the_precommit_cap_per_dispatch_is_unchanged():
    out, persona, ledger = _run(Persona({}, {}, {}, {}, {}), ledger=RepairLedger(trace_id="t1", iteration=4))
    assert out == ("EXHAUSTED", "ITERATIONS") and len(persona.tasks) == 3 and ledger.iteration == 7
