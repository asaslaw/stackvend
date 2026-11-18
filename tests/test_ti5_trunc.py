"""TI5-TRUNC (owner 10-25, register row TI5-TRUNC): an IaC-intent junior answer cut off at the output token cap (the
API's finish reason MAX_TOKENS) is a typed JSON.OUTPUT_TRUNCATED, detected before any JSON parse, and is re-asked ONCE
with a note naming the truncation and the cap raised to min(developer limit, 2 x intent cap); a second truncation is
a typed stop. The TOKEN_LIMIT_EXCEEDED log prints the cap actually sent. Other juniors, mode off and an intent answer
that is not cut off send byte-identical requests (snapshot captured on main ef0018b3 by tests/ti5_trunc_capture.py).
Fake client only: no network, no LLM, no Firestore."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import json
import logging
import os
import sys

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

import ti5_trunc_capture as cap  # noqa: E402
from developer_agent import swarm_dispatcher as sd  # noqa: E402
from shared.diagnostics import ErrorClass  # noqa: E402

SNAPSHOT = os.path.join(TESTS, "fixtures", "ti5_trunc_unchanged_requests.json")
R = cap.response


def _cfg(req):
    return json.loads(req["config"])


def _intent(answers):
    return cap.run_junior(answers, persona="IAC_ENGINEER", intent=True)


# ------------------------------------------------------------------------------------------------ byte identity
def test_other_juniors_mode_off_and_uncut_intent_answers_send_byte_identical_requests():
    """Every scenario of the pre-change snapshot (main ef0018b3) re-captured on this code: same requests (model,
    contents, config) and the same outcome. Covers the other juniors (also on a MAX_TOKENS answer), the IaC persona
    with mode off, and the IaC-intent junior when its answer is not cut off (incl. the HS-61 JSON re-ask path)."""
    with open(SNAPSHOT) as fh:
        before = json.load(fh)
    now = cap.capture()
    assert sorted(now) == sorted(before) == sorted(cap.scenarios())
    for name in before:
        assert now[name] == before[name], name


# ------------------------------------------------------------------------------------------------ the fix
def test_truncated_intent_answer_is_re_asked_once_with_the_raised_cap_and_the_truncation_note():
    reqs, outcome, d = _intent([R(cap.CUT, "MAX_TOKENS", 15728, 649), R(cap.VALID_INTENT)])
    assert outcome["status"] == "SUCCEEDED" and len(reqs) == 2
    first, second = reqs
    assert _cfg(first)["max_output_tokens"] == 16_384               # the first attempt keeps the TI-3 cost cap
    assert _cfg(second)["max_output_tokens"] == 32_768              # min(65 536, 2 x 16 384)
    assert _cfg(first)["thinking_config"] == _cfg(second)["thinking_config"] == {"thinking_budget": 4096}
    assert {k: v for k, v in _cfg(second).items() if k != "max_output_tokens"} == \
        {k: v for k, v in _cfg(first).items() if k != "max_output_tokens"}
    assert second["contents"] == first["contents"] + sd.TRUNCATION_REASK
    assert "JSON.OUTPUT_INVALID" not in second["contents"] and "escape" not in sd.TRUNCATION_REASK
    assert first["model"] == second["model"]                        # same model: not a model fault
    [r] = d.junior_reasks
    assert r["code"] == "JSON.OUTPUT_TRUNCATED" and r["max_output_tokens"] == 32_768 and r["attempt"] == 1
    # measured like every junior response, without parsing the cut-off text
    assert [c["ok"] for c in d.envelope_checks] == [False, True]
    assert d.envelope_checks[0]["error"].startswith("JSON.OUTPUT_TRUNCATED")


def test_truncated_twice_is_a_typed_json_output_truncated_stop():
    reqs, outcome, d = _intent([R(cap.CUT, "MAX_TOKENS", 15728, 649), R(cap.CUT, "MAX_TOKENS", 32000, 700),
                                R(cap.VALID_INTENT), R(cap.VALID_INTENT)])
    assert outcome == {"error": "StageError", "codes": ["JSON.OUTPUT_TRUNCATED"]}
    assert len(reqs) == 2                                           # re-asked once only, never a third time
    assert [_cfg(x)["max_output_tokens"] for x in reqs] == [16_384, 32_768]


def test_typed_stop_report_carries_the_cap_and_token_counts():
    from developer_agent.swarm_schemas import JuniorPersona
    err = sd.JuniorOutputTruncated(32_768, 65_536, thoughts=32_000, answer=700)
    stop = sd.json_output_truncated_error("task-x", JuniorPersona.IAC_ENGINEER.value, err, 2, reasked=True)
    assert stop.error_class is ErrorClass.CODE_DEFECT
    [diag] = stop.report.diagnostics
    assert diag.code == "JSON.OUTPUT_TRUNCATED" and diag.file == "<junior:task-x>"
    assert "cap sent 32768" in diag.message and "thinking tokens 32000" in diag.message
    assert "answer tokens 700" in diag.message and "after the one truncation re-ask" in diag.message


def test_truncation_on_the_last_attempt_is_a_typed_stop_without_a_re_ask():
    reqs, outcome, d = _intent([R(cap.INVALID)] * 3 + [R(cap.CUT, "MAX_TOKENS")])
    assert outcome == {"error": "StageError", "codes": ["JSON.OUTPUT_TRUNCATED"]} and len(reqs) == 4
    assert all(_cfg(x)["max_output_tokens"] == 16_384 for x in reqs)


def test_after_the_truncation_re_ask_an_invalid_json_answer_takes_the_json_re_ask_at_the_raised_cap():
    reqs, outcome, d = _intent([R(cap.CUT, "MAX_TOKENS"), R(cap.INVALID), R(cap.VALID_INTENT)])
    assert outcome["status"] == "SUCCEEDED" and len(reqs) == 3
    assert [_cfg(x)["max_output_tokens"] for x in reqs] == [16_384, 32_768, 32_768]   # stays raised for the task
    third = reqs[2]["contents"]
    assert third.startswith(reqs[0]["contents"]) and third.count("ERROR JSON.OUTPUT_INVALID") == 1
    assert "JSON.OUTPUT_TRUNCATED" not in third                    # notes are replaced, never stacked


def test_one_truncation_then_invalid_json_on_every_other_attempt_stays_the_typed_json_output_invalid_stop():
    """Before TI5-TRUNC a cut-off answer counted as invalid JSON, so four unusable answers were the typed HS-61 stop;
    one truncation among them must not turn that into an escalation to the single-call path."""
    reqs, outcome, d = _intent([R(cap.CUT, "MAX_TOKENS")] + [R(cap.INVALID)] * 3)
    assert outcome == {"error": "StageError", "codes": ["JSON.OUTPUT_INVALID"]} and len(reqs) == 4


def test_an_empty_answer_after_thinking_is_a_truncation_not_an_omitted_file():
    """e2f11615: a MAX_TOKENS answer with no visible text used to parse as {} and be retried as 'omitted files'."""
    reqs, outcome, d = _intent([R("", "MAX_TOKENS", 16_000, 0), R(cap.VALID_INTENT)])
    assert outcome["status"] == "SUCCEEDED" and len(reqs) == 2
    assert reqs[1]["contents"] == reqs[0]["contents"] + sd.TRUNCATION_REASK
    assert "omitted" not in reqs[1]["contents"]


def test_raised_cap_never_exceeds_the_developer_limit():
    from unittest.mock import patch
    import asyncio
    from developer_agent.swarm_dispatcher import SwarmDispatcher

    class S:
        class models:
            @staticmethod
            def get_developer_token_limit():
                return 20_000
    fake = cap.FakeGenai([R(cap.CUT, "MAX_TOKENS")])
    d = SwarmDispatcher(genai_client=fake, model_name=cap.MODEL)
    d.iac_intent = cap.intent_run()
    with patch("shared.settings.get_platform_settings", return_value=S()), \
            patch("shared.settings.thinking_budget_of", return_value=0):
        with pytest.raises(sd.JuniorOutputTruncated) as ei:
            asyncio.run(d._call_gemini_with_backoff("P", "SYS", cap.MODEL, intent_task=True,
                                                    intent_max_output_tokens=32_768))
    assert fake.calls[0]["config"].max_output_tokens == 20_000 and ei.value.cap == 20_000
    assert ei.value.developer_limit == 20_000      # the loop's next cap would be min(20 000, 32 768)


# ------------------------------------------------------------------------------------------------ negatives (DNH)
def test_stop_answer_with_invalid_json_keeps_the_hs61_json_re_ask_unchanged():
    reqs, outcome, d = _intent([R(cap.INVALID), R(cap.VALID_INTENT)])
    assert outcome["status"] == "SUCCEEDED" and len(reqs) == 2
    assert [_cfg(x)["max_output_tokens"] for x in reqs] == [16_384, 16_384]
    second = reqs[1]["contents"]
    assert second.count("ERROR JSON.OUTPUT_INVALID") == 1 and "JSON.OUTPUT_TRUNCATED" not in second
    assert [r.get("code") for r in d.junior_reasks] == [None]      # the HS-61 record keeps its old shape


def test_stop_answer_with_valid_json_makes_no_extra_call():
    reqs, outcome, d = _intent([R(cap.VALID_INTENT), R(cap.VALID_INTENT)])
    assert outcome["status"] == "SUCCEEDED" and len(reqs) == 1 and d.junior_reasks == []


@pytest.mark.parametrize("persona,intent", [("BACKEND_ENGINEER", True), ("BACKEND_ENGINEER", False),
                                            ("IAC_ENGINEER", False)])
def test_max_tokens_on_other_juniors_and_mode_off_is_parsed_as_before(persona, intent):
    reqs, outcome, d = cap.run_junior([R(cap.VALID_INTENT if persona == "IAC_ENGINEER" else cap.VALID_APP,
                                         "MAX_TOKENS")], persona=persona, intent=intent)
    assert outcome["status"] == "SUCCEEDED" and len(reqs) == 1 and d.junior_reasks == []


# ------------------------------------------------------------------------------------------------ detection + log
def test_detection_is_the_typed_finish_reason_not_text():
    """The enum, its recorded string form, and nothing else: a non-string finish reason (a mock) or STOP is never a
    truncation; the answer's text is never inspected for it."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch
    import asyncio
    from google.genai import types
    from developer_agent.swarm_dispatcher import SwarmDispatcher

    def call(finish, text=cap.VALID_INTENT):
        class M:
            def generate_content(self, *, model, contents, config):
                return SimpleNamespace(text=text, candidates=[SimpleNamespace(finish_reason=finish)],
                                       usage_metadata=None)
        d = SwarmDispatcher(genai_client=SimpleNamespace(models=M()), model_name=cap.MODEL)
        d.iac_intent = cap.intent_run()
        with patch("shared.settings.get_platform_settings", side_effect=RuntimeError("no settings")):
            return asyncio.run(d._call_gemini_with_backoff("P", "SYS", cap.MODEL, intent_task=True))
    for finish in (types.FinishReason.MAX_TOKENS, "MAX_TOKENS"):
        with pytest.raises(sd.JuniorOutputTruncated):
            call(finish)
    for finish in (types.FinishReason.STOP, "STOP", None, MagicMock(), "FinishReason.MAX_TOKENS_X"):
        assert call(finish)[0] == json.loads(cap.VALID_INTENT)["files"]
    with pytest.raises(sd.JuniorEnvelopeInvalid):                   # text is never read for the finish reason
        call("STOP", text="MAX_TOKENS")
    src = open(sd.__file__).read()
    bad = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Compare) and any(isinstance(o, ast.In)
           for o in n.ops) and isinstance(n.left, ast.Constant) and n.left.value == "MAX_TOKENS"]
    assert not bad, "substring test on the finish reason is back"


def test_token_limit_log_prints_the_cap_actually_sent_and_the_token_counts(caplog):
    with caplog.at_level(logging.CRITICAL, logger="castor-swarm-dispatcher"):
        _intent([R(cap.CUT, "MAX_TOKENS", 15728, 649), R(cap.VALID_INTENT)])
    [line] = [r.getMessage() for r in caplog.records if "TOKEN_LIMIT_EXCEEDED" in r.getMessage()]
    assert "(16384; thinking tokens 15728, answer tokens 649)" in line and "65536" not in line
    caplog.clear()
    with caplog.at_level(logging.CRITICAL, logger="castor-swarm-dispatcher"):
        cap.run_junior([R(cap.VALID_APP, "MAX_TOKENS")])            # another junior: its cap (65 536), no counts
    [line] = [r.getMessage() for r in caplog.records if "TOKEN_LIMIT_EXCEEDED" in r.getMessage()]
    assert "(65536; thinking tokens None, answer tokens None)" in line


def test_handler_records_a_truncation_re_ask_with_its_own_code():
    from developer_agent.handler import DeveloperAgent
    agent = DeveloperAgent.__new__(DeveloperAgent)
    agent._last_junior_reasks = [
        {"kind": "junior_reask", "task_id": "t", "persona": "IAC_ENGINEER", "attempt": 1, "model": "m",
         "files": ["infra/workload/iac_intent.json"], "error": "E", "code": "JSON.OUTPUT_TRUNCATED",
         "max_output_tokens": 32768},
        {"kind": "junior_reask", "task_id": "t", "persona": "IAC_ENGINEER", "attempt": 2, "model": "m",
         "files": ["infra/workload/iac_intent.json"], "error": "E2"}]
    trunc, invalid = agent._junior_reask_events("trace", "shop")
    assert trunc.codes == ["JSON.OUTPUT_TRUNCATED"] and invalid.codes == ["JSON.OUTPUT_INVALID"]
    assert trunc.kind == invalid.kind == "junior_reask"
