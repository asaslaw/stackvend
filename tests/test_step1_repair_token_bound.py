"""Step 1 repair-call token bound (R3 10-13 finding, plan 8B §7 / integration §S F7).

R3 (paid, 200b8df): every repair call was sent with max_output_tokens = 1.5 x tokens(files) + 2048 and no thinking
config. Vertex counts thinking inside max_output_tokens, so the model thought until the bound (thoughts ~96 % of it),
the JSON answer was cut off (FinishReason.MAX_TOKENS / MALFORMED_FUNCTION_CALL) and 6/26 truncated responses reported
~2x the bound (harness `token_bound_violation`). The fix: an explicit ThinkingConfig(thinking_budget) on every repair
call, the call bound = answer room (1.5 x tokens(files) + 2048, unchanged) + thinking budget, and an unfinished
response is a typed failed iteration (never merged) whose tokens, thoughts included, are charged to the ledger.
Fake genai client only: no network, no LLM."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import json
import os
import sys

import pytest
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
from google.genai import types  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from developer_agent.repair_loop import RepairLoop  # noqa: E402
from developer_agent.swarm_dispatcher import SwarmDispatcher  # noqa: E402
from shared.diagnostics import RepairBudgetExhausted  # noqa: E402
from shared.hallucination_stack import (HallucinationStackSettings, repair_call_max_output_tokens,  # noqa: E402
                                        repair_call_thinking_budget)

from test_step1_s1b_loop import BUCKETS, MAIN, REFS, _ctx  # noqa: E402

FIXED = BUCKETS + 'resource "google_storage_bucket" "b" {\n  name = "b"\n}\n' + REFS


# ------------------------------------------------------------------------------------------------ fakes
def _response(text, finish="STOP", prompt=400, cand=300, thoughts=700, total=None):
    usage = {"prompt_token_count": prompt, "candidates_token_count": cand, "thoughts_token_count": thoughts,
             "total_token_count": prompt + cand + thoughts if total is None else total}
    return types.GenerateContentResponse.model_validate({
        "candidates": [{"content": {"role": "model", "parts": [{"text": text}]}, "finish_reason": finish}],
        "usage_metadata": usage})


class FakeGenai:
    """genai_client stand-in: records every config, answers with scripted responses."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.configs = []
        self.models = self

    def generate_content(self, *, model, contents, config):
        self.configs.append(config)
        return self.responses.pop(0)


def _repair_fn(dispatcher):
    # the handler's wiring (developer_agent/handler.py repair()): pinned by test_handler_passes_the_thinking_budget
    return lambda t: dispatcher.invoke_repair(t.persona, "sys", t.prompt(), "gemini-test", t.max_output_tokens,
                                              thinking_budget=t.thinking_budget)


def _envelope(files):
    return json.dumps({"files": files})


# ------------------------------------------------------------------------------------------------ the bound
def test_bound_is_answer_room_plus_thinking_budget():
    s = HallucinationStackSettings()
    assert s.repair_thinking_budget == 2048 == repair_call_thinking_budget(s)
    # R3 01-r1: files_to_fix ~1790 tokens -> was 4733 (answer room only), now 4733 + 2048
    assert repair_call_max_output_tokens(s, 1790) == 6781
    assert repair_call_max_output_tokens(s, 1000) == 3548 + 2048
    for f in (0, 1, 500, 1790, 5316, 9000, 100_000):
        bound = repair_call_max_output_tokens(s, f)
        assert bound <= s.repair_max_output_tokens
        assert repair_call_thinking_budget(s) < bound
        # the answer keeps the F7 room (one full rewrite + headroom) unless the per-call cap binds
        assert bound - repair_call_thinking_budget(s) == min(int(1.5 * f + 2048),
                                                            s.repair_max_output_tokens - s.repair_thinking_budget)
    assert repair_call_max_output_tokens(s, 100_000) == 16_384


def test_thinking_budget_must_leave_room_for_the_answer():
    HallucinationStackSettings(repair_thinking_budget=15_360)                     # 15360 + 1024 == 16384: ok
    with pytest.raises(ValidationError):
        HallucinationStackSettings(repair_thinking_budget=15_361)
    with pytest.raises(ValidationError):
        HallucinationStackSettings(repair_max_output_tokens=2048)                 # 2048 thinking + 1024 > 2048
    with pytest.raises(ValidationError):
        HallucinationStackSettings(repair_thinking_budget=0)                      # thinking is always bounded


def test_request_config_carries_thinking_budget_and_bound():
    genai = FakeGenai(_response(_envelope({MAIN: FIXED})))
    ctx = _ctx(_repair_fn(SwarmDispatcher(genai_client=genai)))
    tree, report = RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    assert report.status == "PASS" and tree[MAIN] == FIXED
    (config,) = genai.configs
    size = max(1, len(BUCKETS + REFS) // 4)
    assert config.max_output_tokens == int(1.5 * size + 2048) + 2048
    assert config.thinking_config is not None and config.thinking_config.thinking_budget == 2048
    assert config.thinking_config.thinking_budget < config.max_output_tokens


def test_invoke_repair_rejects_a_thinking_budget_outside_the_bound():
    genai = FakeGenai(_response(_envelope({MAIN: FIXED})))
    d = SwarmDispatcher(genai_client=genai)
    res = d.invoke_repair("iac_worker", "sys", "p", "m", 4000, thinking_budget=4000)
    assert res["envelope_ok"] is False and "thinking_budget" in res["error"] and genai.configs == []
    res = d.invoke_repair("iac_worker", "sys", "p", "m", 4000)                  # no budget: config unchanged
    assert res["envelope_ok"] and genai.configs[0].thinking_config is None


def test_handler_passes_the_thinking_budget():
    """The production repair closure forwards task.thinking_budget (AST of developer_agent/handler.py)."""
    with open(os.path.join(GATEWAY, "developer_agent", "handler.py")) as fh:
        tree = ast.parse(fh.read())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "invoke_repair"]
    assert len(calls) == 1
    kw = {k.arg: k.value for k in calls[0].keywords}
    assert "thinking_budget" in kw and ast.unparse(kw["thinking_budget"]) == "task.thinking_budget"


# ------------------------------------------------------------------------------------------------ truncation
@pytest.mark.parametrize("finish", ["MAX_TOKENS", "MALFORMED_FUNCTION_CALL"])
def test_unfinished_response_is_a_failed_iteration_never_merged(finish):
    # the text is a VALID envelope with the right fix: only the finish reason says the answer is not complete
    genai = FakeGenai(_response(_envelope({MAIN: FIXED}), finish=finish, prompt=400, cand=187, thoughts=9087))
    ctx = _ctx(_repair_fn(SwarmDispatcher(genai_client=genai)),
               settings=HallucinationStackSettings(repair_max_iterations_precommit=1))
    broken = {MAIN: BUCKETS + REFS}
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run(broken)
    assert ei.value.exhausted_reason == "ITERATIONS"
    ev = ctx.events[0]
    assert ev.accepted is False and ev.reject_reason == "ENVELOPE_INVALID" and ev.fingerprints_after == []
    led = ctx.ledger_store.load("t1")
    assert led.iteration == 1                                                    # counted against the budget
    assert led.tokens_in == 400 and led.tokens_out == 187 + 9087                 # thoughts charged
    assert ev.tokens_thoughts == 9087


def test_invoke_repair_reports_the_finish_reason():
    d = SwarmDispatcher(genai_client=FakeGenai(_response(_envelope({MAIN: FIXED}), finish="MAX_TOKENS")))
    res = d.invoke_repair("iac_worker", "sys", "p", "m", 6781, thinking_budget=2048)
    assert res["finish_reason"] == "MAX_TOKENS" and res["files"] == {} and res["envelope_ok"] is False
    assert res["error"].startswith("FINISH_REASON_MAX_TOKENS")
    d = SwarmDispatcher(genai_client=FakeGenai(_response(_envelope({MAIN: FIXED}))))
    res = d.invoke_repair("iac_worker", "sys", "p", "m", 6781, thinking_budget=2048)
    assert res["finish_reason"] == "STOP" and res["envelope_ok"] and res["files"] == {MAIN: FIXED}


def test_merge_refuses_an_unfinished_result_from_any_repair_fn():
    """Defense in depth: a repair_fn other than invoke_repair that reports envelope_ok with MAX_TOKENS."""
    def repair(task):
        return {"files": {MAIN: FIXED}, "envelope_ok": True, "finish_reason": "MAX_TOKENS", "model": "m",
                "tokens_in": 10, "tokens_out": 5, "tokens_thoughts": 7}
    ctx = _ctx(repair, settings=HallucinationStackSettings(repair_max_iterations_precommit=1))
    with pytest.raises(RepairBudgetExhausted):
        RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    assert ctx.events[0].reject_reason == "ENVELOPE_INVALID"
    assert ctx.ledger_store.load("t1").tokens_out == 12


# ------------------------------------------------------------------------------------------------ accounting
def test_accounting_counts_thoughts_and_never_undercounts():
    d = SwarmDispatcher(genai_client=FakeGenai(_response(_envelope({MAIN: FIXED}), prompt=400, cand=300,
                                                         thoughts=700)))
    res = d.invoke_repair("iac_worker", "sys", "p", "m", 6781, thinking_budget=2048)
    assert (res["tokens_in"], res["tokens_out"], res["tokens_thoughts"]) == (400, 300, 700)
    # total_token_count above prompt + candidates + thoughts (e.g. candidates omitted): billed as total - prompt
    d = SwarmDispatcher(genai_client=FakeGenai(_response(_envelope({MAIN: FIXED}), prompt=400, cand=0,
                                                         thoughts=700, total=1600)))
    res = d.invoke_repair("iac_worker", "sys", "p", "m", 6781, thinking_budget=2048)
    assert res["tokens_out"] + res["tokens_thoughts"] == 1600 - 400


def test_converged_repair_settles_thoughts_in_the_ledger():
    genai = FakeGenai(_response(_envelope({MAIN: FIXED}), prompt=400, cand=300, thoughts=700))
    ctx = _ctx(_repair_fn(SwarmDispatcher(genai_client=genai)))
    RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    led = ctx.ledger_store.load("t1")
    assert led.tokens_out == 1000 and led.tokens_spent == 1400 and ctx.events[0].accepted
