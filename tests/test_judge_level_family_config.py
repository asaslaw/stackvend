"""JUDGE-LEVEL-FAMILY-CONFIG (11-11; register row awaiting owner): the Stage 2 judge and the agent evaluator under
Gemini 4 Carbon.

Live defect (the test install, run ex08-c1, trace intake-ex08-c1-65a011, 11-11 01:32Z): QA Stage 2 failed closed with
"adherence lens: judge reply is not JSON (Expecting value: line 1 column 1 (char 0))" -- a non-empty answer that did
not start with JSON. The judge read `response.text` without the finish reason and logged nothing about the answer.

Here: the judge request follows the model family (Carbon: thinking level, no budget / sampling / penalty params, a
cap with room for thinking); the answer is read from typed parts (thought parts skipped) and the finish reason; a
TRUNCATED / EMPTY / UNPARSEABLE answer is asked again once (deadline permitting); anything still unusable is a typed
JudgeReplyError -> LensUnavailableError -> STAGE2_UNAVAILABLE, never a pass. Gemini 3.x requests are byte-identical.
Fake clients only (real google.genai response types): no network, no LLM, no Firestore."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import filecmp
import json
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import REPO_ROOT, sdk_response
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse)

pytest.importorskip("google.genai")
from google.genai import types  # noqa: E402

import qa_auditor.judge as judge_mod  # noqa: E402
import shared.gemini_model_config as gmc  # noqa: E402
from qa_auditor import DualLensAuditorCoordinator, LensUnavailableError, build_platform_facts  # noqa: E402
from qa_auditor.adherence_lens import ADHERENCE_RESPONSE_SCHEMA, evaluate_adherence_lens  # noqa: E402
from qa_auditor.lens_common import parse_judge_json  # noqa: E402
from qa_auditor.security_lens import SECURITY_RESPONSE_SCHEMA  # noqa: E402

CARBON = "gemini-4-carbon"
FLASH_IDS = ("gemini-3.8-flash", "gemini-3.7-flash")
ADH_OK = json.dumps({"instruction_adherence_score": 1.0, "grounding_score": 1.0, "missed_directives": [],
                     "hallucinated_features": [], "summary": "ok"})
SEC_OK = json.dumps({"passed": True, "critical_vulnerabilities": [], "summary": "ok"})

needs_level_sdk = pytest.mark.skipif(not gmc.sdk_supports_thinking_level(types),
                                     reason="installed google-genai lacks ThinkingConfig.thinking_level")


class _Client:
    """Returns the queued responses in order; records every request config."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.configs = []
        self.models = self

    @property
    def calls(self):
        return len(self.configs)

    def generate_content(self, model, contents, config):
        self.configs.append(config)
        return self.responses.pop(0)


def _call(client, model=CARBON, **kw):
    kw.setdefault("validate", lambda raw: parse_judge_json(raw, "adherence lens"))
    return judge_mod.call("prompt", model, client=client, response_schema=ADHERENCE_RESPONSE_SCHEMA,
                          sleep=lambda s: None, **kw)


def _levels(monkeypatch, level):
    monkeypatch.setattr(gmc, "_stored_models_section",
                        lambda: SimpleNamespace(thinking_levels={"auxiliary": level}, custom_families={}))


# ------------------------------------------------------------------------------------------------ request config
@needs_level_sdk
def test_carbon_judge_config_level_thinking_no_budget_no_penalties_cap_has_thinking_room():
    cfg = judge_mod.judge_config(CARBON, judge_mod.JUDGE_MAX_OUTPUT_TOKENS, ADHERENCE_RESPONSE_SCHEMA)
    assert cfg.thinking_config.thinking_level == types.ThinkingLevel.LOW      # settings default for "auxiliary"
    assert cfg.thinking_config.thinking_budget is None
    for p in ("temperature", "top_p", "top_k", "presence_penalty", "frequency_penalty", "candidate_count",
              "cached_content"):
        assert getattr(cfg, p) is None, p
    assert cfg.response_mime_type == "application/json" and cfg.response_schema == ADHERENCE_RESPONSE_SCHEMA
    # the answer room (8,192) plus the LOW thinking reserve (4,096): thinking cannot starve the answer
    assert cfg.max_output_tokens == judge_mod.JUDGE_MAX_OUTPUT_TOKENS + gmc.THINKING_RESERVE_TOKENS["LOW"] == 12288


@needs_level_sdk
@pytest.mark.parametrize("level, cap", [("MEDIUM", 8192 + 8192), ("HIGH", 8192 + 16384)])
def test_carbon_judge_config_follows_the_configured_auxiliary_level(monkeypatch, level, cap):
    _levels(monkeypatch, level)
    cfg = judge_mod.judge_config(CARBON, judge_mod.JUDGE_MAX_OUTPUT_TOKENS, SECURITY_RESPONSE_SCHEMA)
    assert cfg.thinking_config.thinking_level == getattr(types.ThinkingLevel, level)
    assert cfg.thinking_config.thinking_budget is None and cfg.max_output_tokens == cap


@needs_level_sdk
def test_carbon_judge_call_sends_the_family_config():
    c = _Client(sdk_response(ADH_OK))
    assert _call(c) == ADH_OK and c.calls == 1
    cfg = c.configs[0]
    assert cfg.thinking_config.thinking_level == types.ThinkingLevel.LOW and cfg.thinking_config.thinking_budget is None
    assert cfg.temperature is None and cfg.max_output_tokens == 12288


@pytest.mark.parametrize("model", FLASH_IDS)
def test_do_no_harm_flash_judge_request_byte_identical(model):
    """The pre-11-11 judge request for a budget-family model, written out literally."""
    before = types.GenerateContentConfig(response_mime_type="application/json", temperature=0.0,
                                         max_output_tokens=8192, response_schema=ADHERENCE_RESPONSE_SCHEMA)
    c = _Client(sdk_response(ADH_OK))
    assert _call(c, model=model) == ADH_OK and c.calls == 1
    # JUDGE-FALLBACK-FLASH-ROOM: the request also carries its own time box, here the full 120 s the client sent as its
    # default before (same X-Server-Timeout); the request content is unchanged
    sent = c.configs[0]
    assert sent.http_options.timeout == judge_mod.JUDGE_TIMEOUT_MS
    assert sent.model_copy(update={"http_options": None}).model_dump_json(exclude_none=True) == \
        before.model_dump_json(exclude_none=True)
    assert judge_mod.judge_config(model, 8192, ADHERENCE_RESPONSE_SCHEMA).model_dump_json() == before.model_dump_json()


# ------------------------------------------------------------------------------------------------ answer reading
def test_thought_part_first_is_skipped():
    c = _Client(sdk_response(ADH_OK, thought="Looking at the diff, INFRA-01 is..."))
    assert _call(c) == ADH_OK and c.calls == 1
    ans = judge_mod.read_answer(sdk_response(ADH_OK, thought="thinking"))
    assert ans.text == ADH_OK and ans.finish_reason == "STOP" and "1 thought part(s)" in ans.shape


def test_read_answer_never_uses_response_text():
    class R:
        text = ADH_OK     # a response object without candidates: no reply, whatever `.text` says
        candidates = None
        usage_metadata = None
        prompt_feedback = None

    ans = judge_mod.read_answer(R())
    assert ans.text == "" and ans.finish_reason == "NO_CANDIDATE"


def test_do_no_harm_valid_answer_is_returned_unchanged_in_one_call():
    for text in (ADH_OK, "```json\n" + ADH_OK + "\n```", "\n  " + ADH_OK + "\n"):
        c = _Client(sdk_response(text))
        assert _call(c) == text and c.calls == 1


# ------------------------------------------------------------------------------------------------ typed failures
def test_empty_answer_twice_is_a_typed_failure():
    c = _Client(sdk_response(""), sdk_response("  "))
    with pytest.raises(judge_mod.JudgeReplyError) as ei:
        _call(c)
    e = ei.value
    assert (e.reason, e.finish_reason, e.answers, c.calls) == ("EMPTY", "STOP", 2, 2)
    assert "finish reason STOP" in str(e) and "after 2 answers" in str(e)


def test_no_answer_part_is_empty_not_a_pass():
    c = _Client(sdk_response(None, usage={"prompt_token_count": 9, "thoughts_token_count": 7}), sdk_response(ADH_OK))
    assert _call(c) == ADH_OK and c.calls == 2


@needs_level_sdk
def test_max_tokens_is_asked_again_once_with_a_larger_cap():
    c = _Client(sdk_response('{"instruction_adherence_score": 1.0, "missed', finish="MAX_TOKENS"), sdk_response(ADH_OK))
    assert _call(c) == ADH_OK and c.calls == 2
    assert [cfg.max_output_tokens for cfg in c.configs] == [12288, 2 * 8192 + 4096]
    assert all(cfg.thinking_config.thinking_budget is None for cfg in c.configs)


def test_max_tokens_retry_for_flash_only_raises_the_cap():
    c = _Client(sdk_response("{", finish="MAX_TOKENS"), sdk_response(ADH_OK))
    assert _call(c, model="gemini-3.8-flash") == ADH_OK
    first, second = (json.loads(cfg.model_dump_json(exclude_none=True)) for cfg in c.configs)
    assert first.pop("max_output_tokens") == 8192 and second.pop("max_output_tokens") == 16384
    assert first == second


def test_max_tokens_twice_is_a_typed_failure():
    c = _Client(sdk_response("{", finish="MAX_TOKENS"), sdk_response('{"a', finish="MAX_TOKENS"))
    with pytest.raises(judge_mod.JudgeReplyError) as ei:
        _call(c)
    assert (ei.value.reason, ei.value.finish_reason, c.calls) == ("TRUNCATED", "MAX_TOKENS", 2)
    assert "finish reason MAX_TOKENS" in str(ei.value)


@pytest.mark.parametrize("finish", ["SAFETY", "RECITATION", "PROHIBITED_CONTENT", "OTHER"])
def test_other_finish_reasons_fail_typed_without_a_retry(finish):
    c = _Client(sdk_response(ADH_OK, finish=finish))
    with pytest.raises(judge_mod.JudgeReplyError) as ei:
        _call(c)
    assert (ei.value.reason, ei.value.finish_reason, c.calls) == ("BLOCKED", finish, 1)


def test_missing_finish_reason_or_candidate_is_not_a_reply():
    c = _Client(sdk_response(ADH_OK, finish=None))
    with pytest.raises(judge_mod.JudgeReplyError) as ei:
        _call(c)
    assert ei.value.finish_reason == "FINISH_REASON_MISSING" and c.calls == 1
    c = _Client(sdk_response(None, candidates=False))
    with pytest.raises(judge_mod.JudgeReplyError) as ei:
        _call(c)
    assert ei.value.finish_reason == "NO_CANDIDATE" and c.calls == 1


def test_non_json_stop_answer_is_asked_again_once():
    """The ex08-c1 shape: STOP, text that does not start with JSON."""
    c = _Client(sdk_response("Here is my audit:\n" + ADH_OK), sdk_response(ADH_OK))
    assert _call(c) == ADH_OK and c.calls == 2


def test_non_json_twice_is_a_typed_failure_with_the_shape(caplog):
    c = _Client(sdk_response("Here is my audit:"), sdk_response("Here is my audit, again:"))
    with caplog.at_level("WARNING", logger="castor-qa-judge"), pytest.raises(judge_mod.JudgeReplyError) as ei:
        _call(c)
    msg = str(ei.value)
    assert ei.value.reason == "UNPARSEABLE" and c.calls == 2
    assert "not JSON" in msg and "finish reason STOP" in msg and "answer chars" in msg
    # RT low #2: the answer text is in the WARNING log only, never in the (persisted) error detail
    assert "Here is my audit" not in msg
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert any("'Here is my audit, again:'" in w and "UNPARSEABLE" in w for w in warnings)


SECRET = "AKIAABCDEFGHIJKLMNOP sk_live_0123456789abcdef"


@pytest.mark.parametrize("responses", [
    (sdk_response("I found " + SECRET),) * 2,                                  # UNPARSEABLE
    (sdk_response('{"summary": "' + SECRET, finish="MAX_TOKENS"),) * 2,        # TRUNCATED
    (sdk_response("quoting " + SECRET, finish="SAFETY"),),                     # BLOCKED
    (sdk_response('{"summary": "' + SECRET + '"}'),) * 2,                      # schema-incomplete
])
def test_persisted_detail_never_carries_answer_text(monkeypatch, caplog, responses):
    """RT low #2: the STAGE2_UNAVAILABLE detail is stored (qa_test_runs, workload record, CC): typed shape only."""
    monkeypatch.setattr(judge_mod, "_client", _Client(*responses))
    with caplog.at_level("WARNING", logger="castor-qa-judge"), pytest.raises(LensUnavailableError) as ei:
        evaluate_adherence_lens("+x", task_dag=[{"task_id": "t"}], model_name=CARBON)
    assert "AKIA" not in str(ei.value) and "sk_live" not in str(ei.value)
    assert "finish reason" in str(ei.value) and "answer chars" in str(ei.value)
    assert any("AKIA" in r.getMessage() for r in caplog.records if r.levelname == "WARNING")


@pytest.mark.parametrize("lens", ["adherence", "security"])
def test_schema_incomplete_json_is_unparseable_and_asked_again_once(monkeypatch, lens):
    """RT low #1: a STOP answer that is JSON but misses the lens's required fields gets the one re-ask."""
    from qa_auditor.security_lens import evaluate_security_lens
    good = ADH_OK if lens == "adherence" else SEC_OK
    run = (lambda: evaluate_adherence_lens("+x", task_dag=[{"task_id": "t"}], model_name=CARBON)) \
        if lens == "adherence" else (lambda: evaluate_security_lens("+x", model_name=CARBON))
    c = _Client(sdk_response('{"summary": "fine"}'), sdk_response(good))
    monkeypatch.setattr(judge_mod, "_client", c)
    assert run().passed and c.calls == 2
    c = _Client(sdk_response('{"summary": "fine"}'), sdk_response('{"summary": "still fine"}'), sdk_response(good))
    monkeypatch.setattr(judge_mod, "_client", c)
    with pytest.raises(LensUnavailableError) as ei:
        run()
    assert c.calls == 2 and "judge answer UNPARSEABLE" in str(ei.value) and "after 2 answers" in str(ei.value)


def test_reask_needs_a_time_box_before_the_deadline():
    """JUDGE-FALLBACK-FLASH-ROOM: the re-ask starts only when its time box (>= JUDGE_MIN_CALL_S, the deadline margin
    kept free) fits; it is time-boxed to the room left (was: one full 120 s call)."""
    floor = judge_mod.JUDGE_MIN_CALL_S + judge_mod.JUDGE_DEADLINE_MARGIN_S   # 60 s

    def run(deadline):
        t = {"now": 0.0}

        class Timed(_Client):
            def generate_content(self, model, contents, config):
                t["now"] += 10.0                       # each answer takes 10 s
                return super().generate_content(model, contents, config)

        c = Timed(sdk_response("not json"), sdk_response(ADH_OK))
        return c, (lambda: _call(c, deadline=deadline, clock=lambda: t["now"]))

    c, go = run(10.0 + floor - 1)
    with pytest.raises(judge_mod.JudgeReplyError):
        go()
    assert c.calls == 1
    c, go = run(10.0 + floor)
    assert go() == ADH_OK and c.calls == 2
    assert c.configs[1].http_options.timeout == judge_mod.JUDGE_MIN_CALL_S * 1000


def test_without_validate_a_stop_answer_is_returned_as_before():
    c = _Client(sdk_response("not json"))
    assert judge_mod.call("p", CARBON, client=c) == "not json" and c.calls == 1


# ------------------------------------------------------------------------------------------------ lens / Stage 2
def test_lens_unusable_answer_is_lens_unavailable_with_the_finish_reason(monkeypatch):
    c = _Client(sdk_response("{", finish="MAX_TOKENS"), sdk_response("{", finish="MAX_TOKENS"))
    monkeypatch.setattr(judge_mod, "_client", c)
    with pytest.raises(LensUnavailableError) as ei:
        evaluate_adherence_lens("+x", task_dag=[{"task_id": "t"}], model_name=CARBON)
    assert str(ei.value).startswith("adherence lens: judge answer TRUNCATED (finish reason MAX_TOKENS")


def test_stage_two_with_a_non_json_answer_then_a_good_one_passes(monkeypatch):
    replies = {"sec": [sdk_response(SEC_OK)], "adh": [sdk_response("I reviewed the diff."), sdk_response(ADH_OK)]}

    class C:
        def __init__(self):
            self.models = self

        def generate_content(self, model, contents, config):
            return replies["sec" if "Security Engineer" in contents else "adh"].pop(0)

    monkeypatch.setattr(judge_mod, "_client", C())
    sec, adh, report = DualLensAuditorCoordinator(timeout_seconds=300.0).evaluate_stage_two(
        git_diff="+x", determ_report={"passed": True, "summary": "ok"}, task_dag=[{"task_id": "t"}],
        ingress_policy={}, model_name=CARBON, platform_facts=build_platform_facts(None, "off", []))
    assert sec.passed and adh.passed and replies == {"sec": [], "adh": []}


def test_stage_two_with_unusable_answers_is_unavailable_never_a_pass(monkeypatch):
    class C:
        def __init__(self):
            self.models = self

        def generate_content(self, model, contents, config):
            return sdk_response("")

    monkeypatch.setattr(judge_mod, "_client", C())
    with pytest.raises(LensUnavailableError) as ei:
        DualLensAuditorCoordinator(timeout_seconds=300.0).evaluate_stage_two(
            git_diff="+x", determ_report={"passed": True, "summary": "ok"}, task_dag=[{"task_id": "t"}],
            ingress_policy={}, model_name=CARBON, platform_facts=build_platform_facts(None, "off", []))
    assert "EMPTY" in str(ei.value) and "finish reason STOP" in str(ei.value)


# ------------------------------------------------------------------------------------------------ agent evaluator
class _EvalClient:
    calls = []

    def __init__(self, *a, **kw):
        self.models = self

    def generate_content(self, **kw):
        _EvalClient.calls.append(kw)
        return sdk_response(json.dumps({"instruction_adherence_score": 0.9, "grounding_score": 1.0,
                                        "tool_efficiency_score": 1.0}))


@pytest.mark.parametrize("model", FLASH_IDS + ("gemini-2.5-flash", "gemini-2.0-flash"))
def test_do_no_harm_evaluator_flash_request_has_no_config(model):
    from shared import agent_evaluator as ae
    _EvalClient.calls = []
    with patch("google.genai.Client", _EvalClient):
        assert ae._call_gemini_inference("prompt", model) is not None
    assert _EvalClient.calls == [{"model": model, "contents": "prompt"}]


@needs_level_sdk
def test_evaluator_carbon_request_has_level_thinking_and_no_budget():
    from shared import agent_evaluator as ae
    _EvalClient.calls = []
    with patch("google.genai.Client", _EvalClient):
        assert ae._call_gemini_inference("prompt", CARBON) is not None
    (kw,) = _EvalClient.calls
    cfg = kw["config"]
    assert cfg.thinking_config.thinking_level == types.ThinkingLevel.LOW and cfg.thinking_config.thinking_budget is None
    assert cfg.temperature is None and cfg.presence_penalty is None and cfg.frequency_penalty is None


def test_agent_evaluator_copies_are_byte_identical():
    src = os.path.join(REPO_ROOT, "shared", "agent_evaluator.py")
    for d in ("apps/control-center/shared", "apps/orchestrator-gateway/shared", "mcp-servers/terraform/shared"):
        assert filecmp.cmp(src, os.path.join(REPO_ROOT, d, "agent_evaluator.py"), shallow=False), d
