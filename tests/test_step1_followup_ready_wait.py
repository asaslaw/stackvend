"""Step 1 follow-up (owner decision 10-13): bounded readiness wait before the developer stage.

The gateway polls the terraform server's /validate/ready with backoff for up to `validate_ready_wait_s` (default
180 s). Still not ready -> the existing GATE_UNAVAILABLE typed failure, before any LLM call ($0). Never proceeds
without a ready gate; a probe that raises or answers garbage counts as not ready. Virtual clock, no network."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys
from unittest.mock import patch

import pytest
from pydantic import ValidationError

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent import hallucination_runtime as hr  # noqa: E402
from developer_agent.stack_clients import (READY_HTTP_TIMEOUT_S, VALIDATE_HTTP_TIMEOUT_S,  # noqa: E402
                                           HttpValidateClient)
from shared.diagnostics import (ErrorClass, MemoryLedgerStore, RepairBudgetExhausted, RepairLedger,  # noqa: E402
                                StageError)
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402
from test_step1_s1b_generation import Client, _agent, _generate, _runtime  # noqa: E402

READY = {"ready": True, "providers": ["google", "google-beta", "kubernetes", "random"], "engine": "OPENTOFU",
         "engine_version": "1.9.0", "reason": ""}


@pytest.fixture()
def clock():
    """Virtual clock: hr._sleep advances it; every sleep is recorded."""
    state = {"now": 0.0, "sleeps": []}

    def sleep(s):
        assert s > 0
        state["sleeps"].append(s)
        state["now"] += s
    with patch.object(hr, "_sleep", sleep), patch.object(hr, "_clock", lambda: state["now"]):
        yield state


class Scripted(Client):
    """ready() answers from a script (dict, Exception instance, or any other object); the last entry repeats."""

    def __init__(self, script, **kw):
        super().__init__(**kw)
        self.script, self.probes = list(script), 0

    def ready(self, iac_engine="OPENTOFU"):
        self.probes += 1
        item = self.script[min(self.probes - 1, len(self.script) - 1)]
        if isinstance(item, BaseException):
            raise item
        return item


NOT_READY = {"ready": False, "reason": "provider mirror not populated (google missing)"}


# ------------------------------------------------------------------------------------------------ settings
def test_setting_default_is_180_s_and_bounded():
    assert HallucinationStackSettings().validate_ready_wait_s == 180
    assert HallucinationStackSettings(validate_ready_wait_s=0).validate_ready_wait_s == 0
    for bad in (-1, 901):
        with pytest.raises(ValidationError):
            HallucinationStackSettings(validate_ready_wait_s=bad)


def test_both_settings_copies_are_identical():
    a = open(os.path.join(REPO_ROOT, "shared", "hallucination_stack.py")).read()
    b = open(os.path.join(GATEWAY, "shared", "hallucination_stack.py")).read()
    assert a == b


# ------------------------------------------------------------------------------------------------ helper
def test_never_ready_stops_at_the_deadline_without_a_probe_after_it(clock):
    c = Scripted([NOT_READY])
    answer, probes, waited = hr.wait_for_validate_ready(c, "OPENTOFU", 180)
    assert answer["ready"] is False and answer["reason"] == NOT_READY["reason"]
    assert clock["sleeps"] == [2, 4, 8, 16, 30, 30, 30, 30, 30]       # backoff 2 s doubling, 30 s cap
    assert waited == 180 == sum(clock["sleeps"]) and probes == c.probes == 10   # last probe at t=180, none after


def test_ready_on_the_third_probe(clock):
    c = Scripted([NOT_READY, NOT_READY, READY])
    answer, probes, waited = hr.wait_for_validate_ready(c, "OPENTOFU", 180)
    assert answer is READY and probes == 3 and clock["sleeps"] == [2, 4] and waited == 6


def test_probe_errors_and_garbage_count_as_not_ready(clock):
    # a raising probe, a non-dict body, a truthy non-True "ready" -- none is ready; the real answer then wins
    c = Scripted([RuntimeError("connect timeout"), ["ready"], {"ready": "true"}, {"ready": 1}, READY])
    answer, probes, _ = hr.wait_for_validate_ready(c, "OPENTOFU", 180)
    assert answer is READY and probes == 5
    always_raises = Scripted([TimeoutError("read timeout")])
    answer, probes, waited = hr.wait_for_validate_ready(always_raises, "OPENTOFU", 180)
    assert answer["ready"] is False and "TimeoutError" in answer["reason"] and waited == 180 and probes == 10


def test_zero_wait_is_a_single_probe_and_no_client_is_not_ready(clock):
    c = Scripted([NOT_READY, READY])
    answer, probes, waited = hr.wait_for_validate_ready(c, "OPENTOFU", 0)
    assert answer["ready"] is False and probes == 1 and clock["sleeps"] == [] and waited == 0
    answer, probes, _ = hr.wait_for_validate_ready(None, "OPENTOFU", 180)
    assert answer["ready"] is False and probes == 0 and clock["sleeps"] == []


def test_short_limit_clamps_the_last_pause(clock):
    c = Scripted([NOT_READY])
    _, probes, waited = hr.wait_for_validate_ready(c, "OPENTOFU", 5)
    assert clock["sleeps"] == [2, 3] and waited == 5 and probes == 3


# ------------------------------------------------------------------------------------------------ developer gate
def test_never_ready_is_gate_unavailable_before_any_llm_call(clock):
    c = Scripted([NOT_READY])
    calls = []
    with pytest.raises(StageError) as ei:
        _generate(_agent(_runtime(c)), lead_calls=calls)
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE and calls == [0]   # lead never ran: $0
    assert ei.value.report.tools_unavailable == ["V1b"]
    assert "after 10 probe(s) in 180s (limit 180s)" in str(ei.value) and "google missing" in str(ei.value)
    assert c.validated == []


def test_ready_on_third_poll_proceeds_to_generation(clock):
    c = Scripted([NOT_READY, RuntimeError("503"), READY])
    calls = []
    agent = _agent(_runtime(c))
    files = _generate(agent, lead_calls=calls)
    assert c.probes == 3 and calls == [1] and files
    assert agent.last_validation_report.status == "PASS" and c.validated


def test_configured_limit_is_honoured(clock):
    c = Scripted([NOT_READY])
    with pytest.raises(StageError) as ei:
        _generate(_agent(_runtime(c, settings=HallucinationStackSettings(validate_ready_wait_s=30))))
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE and sum(clock["sleeps"]) == 30 and c.probes == 5


def test_exhausted_budget_is_refused_before_any_ready_probe(clock):
    ledger = MemoryLedgerStore()
    ledger.save(RepairLedger(trace_id="trace-s1b", iteration=5, exhausted_reason="ITERATIONS"))
    c = Scripted([NOT_READY])
    with pytest.raises(RepairBudgetExhausted):
        _generate(_agent(_runtime(c, ledger=ledger)))
    assert c.probes == 0 and clock["sleeps"] == []


def test_already_ready_gate_is_one_probe_and_no_sleep(clock):
    """Do No Harm: a warm server costs exactly what it did before the wait existed (one probe, no pause)."""
    c = Scripted([READY])
    _generate(_agent(_runtime(c)))
    assert c.probes == 1 and clock["sleeps"] == []


# ------------------------------------------------------------------------------------------------ HTTP client
def test_http_ready_probe_uses_the_short_timeout_and_validate_keeps_75_s():
    seen = []

    class Res:
        status_code = 200

        @staticmethod
        def json():
            return {"ready": True}

    class FakeHttp:
        def __init__(self, timeout, follow_redirects):
            seen.append(timeout)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, *a, **k):
            return Res()

        def post(self, *a, **k):
            return Res()

    with patch.dict(os.environ, {"K_SERVICE": ""}):
        client = HttpValidateClient(lambda: "http://127.0.0.1:9", http_factory=FakeHttp)
        assert client.ready()["ready"] is True
        client.validate({"infra/workload/main.tf": ""})
    assert seen == [READY_HTTP_TIMEOUT_S, VALIDATE_HTTP_TIMEOUT_S] and READY_HTTP_TIMEOUT_S <= 30
