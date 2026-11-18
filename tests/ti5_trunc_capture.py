"""Swarm junior request capture for the TI5-TRUNC byte-identity snapshot (tests/test_ti5_trunc.py).

Drives SwarmDispatcher.invoke_junior_worker with a fake genai client over scripted answers (finish reason + text) and
returns every request it sent (model, contents, canonical config JSON) plus the outcome. The snapshot
`tests/fixtures/ti5_trunc_unchanged_requests.json` was produced by this module on the code BEFORE TI5-TRUNC (main
ef0018b3); the test re-captures on the current code and requires every scenario in it to be byte-identical: the other
juniors, mode off, and an IaC-intent answer that is NOT cut off (the eval cassettes key on these requests).
Fake client only: no network, no LLM, no Firestore."""
import asyncio
import json
import os
import sys
from unittest.mock import AsyncMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for _p in (GATEWAY, REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from google.genai import types  # noqa: E402

MODEL = "gemini-3.8-flash"
INTENT_PATH = "infra/workload/iac_intent.json"
APP_PATH = "apps/api/main.py"
VALID_APP = json.dumps({"files": {APP_PATH: "x = 1\n"}})
VALID_INTENT = json.dumps({"files": {INTENT_PATH: "{\"schema\": \"iac_intent/v1\"}"}})
CUT = '{"files": {"' + INTENT_PATH + '": "{\\"schema\\": \\"iac_intent/v1\\", \\"resources\\": [{\\"type'
INVALID = '{"files": {"' + APP_PATH + '": "P = re.compile(r\'\\d+\')"}}'   # \d is not a JSON escape


def response(text, finish="STOP", thoughts=None, answer=None):
    usage = {"prompt_token_count": 10, "total_token_count": 20}
    if thoughts is not None:
        usage["thoughts_token_count"] = thoughts
    if answer is not None:
        usage["candidates_token_count"] = answer
    return types.GenerateContentResponse.model_validate({
        "candidates": [{"content": {"role": "model", "parts": [{"text": text}]}, "finish_reason": finish}],
        "usage_metadata": usage})


class FakeGenai:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []
        self.models = self

    def generate_content(self, *, model, contents, config):
        self.calls.append({"model": model, "contents": contents, "config": config})
        return self.answers.pop(0)


def dump_config(config):
    # SLOW-CALL-FALLBACK: http_options (the per-call timeout) is transport, not request content (cassette key too)
    return json.dumps(config.model_dump(mode="json", exclude_none=True, exclude={"http_options"}), sort_keys=True,
                      default=str)


def intent_run():
    """A fixed IntentRun (the run context is a constant, so the request does not depend on the prompt texts)."""
    from developer_agent.iac_intent_contract import IntentRun
    return IntentRun(artifacts=None, system_prompt="INTENT SYSTEM PROMPT", run_context="INTENT RUN CONTEXT")


def run_junior(answers, *, persona="BACKEND_ENGINEER", intent=False):
    """(requests, outcome) of one junior task over the scripted answers."""
    from developer_agent.swarm_dispatcher import SwarmDispatcher
    from developer_agent.swarm_schemas import (JuniorPersona, JuniorTaskAssignment, LeadDeveloperDecompositionPlan,
                                               SwarmExecutionMode)
    fake = FakeGenai(answers)
    d = SwarmDispatcher(genai_client=fake, model_name=MODEL)
    if intent:
        d.iac_intent = intent_run()
    p = JuniorPersona(persona)
    f = INTENT_PATH if p == JuniorPersona.IAC_ENGINEER else APP_PATH
    task = JuniorTaskAssignment(task_id="task-x", persona=p, wave=1, assigned_files=[f], task_objective="objective")
    plan = LeadDeveloperDecompositionPlan(execution_mode=SwarmExecutionMode.STANDARD_SWARM, tasks=[task])
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=[MODEL]), \
            patch("shared.settings.get_platform_settings", side_effect=RuntimeError("no settings in tests")), \
            patch("developer_agent.swarm_dispatcher.resolve_junior_prompt", return_value="JUNIOR SYSTEM PROMPT"), \
            patch("asyncio.sleep", new_callable=AsyncMock):
        try:
            res = asyncio.run(d.invoke_junior_worker(task, plan, {}, MODEL))
            outcome = {"status": res.status, "files": res.files}
        except Exception as e:  # noqa: BLE001 - the typed stop is part of the outcome
            report = getattr(e, "report", None)
            outcome = {"error": type(e).__name__,
                       "codes": [x.code for x in report.diagnostics] if report is not None else []}
    reqs = [{"model": c["model"], "contents": c["contents"], "config": dump_config(c["config"])} for c in fake.calls]
    return reqs, outcome, d


def scenarios():
    """The requests that TI5-TRUNC must leave byte-identical."""
    return {
        # other juniors (mode off)
        "backend_off_stop_valid": dict(answers=[("STOP", VALID_APP)]),
        "backend_off_max_tokens_valid": dict(answers=[("MAX_TOKENS", VALID_APP)]),
        "backend_off_invalid_then_valid": dict(answers=[("STOP", INVALID), ("STOP", VALID_APP)]),
        # the IaC persona with mode off (HCL path): a MAX_TOKENS answer is parsed as before
        "iac_off_max_tokens_cut": dict(persona="IAC_ENGINEER", answers=[("MAX_TOKENS", CUT)] * 4),
        # other juniors with mode generate (an intent run on the dispatcher)
        "backend_gen_max_tokens_valid": dict(intent=True, answers=[("MAX_TOKENS", VALID_APP)]),
        "backend_gen_invalid_then_valid": dict(intent=True, answers=[("STOP", INVALID), ("STOP", VALID_APP)]),
        # the IaC-intent junior when the answer is NOT cut off
        "intent_stop_valid": dict(persona="IAC_ENGINEER", intent=True, answers=[("STOP", VALID_INTENT)]),
        "intent_stop_invalid_then_valid": dict(persona="IAC_ENGINEER", intent=True,
                                               answers=[("STOP", INVALID), ("STOP", VALID_INTENT)]),
        "intent_stop_invalid_x4": dict(persona="IAC_ENGINEER", intent=True, answers=[("STOP", INVALID)] * 4),
    }


def capture():
    out = {}
    for name, sc in sorted(scenarios().items()):
        answers = [response(text, finish) for finish, text in sc["answers"]]
        reqs, outcome, _ = run_junior(answers, persona=sc.get("persona", "BACKEND_ENGINEER"),
                                      intent=sc.get("intent", False))
        out[name] = {"requests": reqs, "outcome": outcome}
    return out


if __name__ == "__main__":   # python tests/ti5_trunc_capture.py <out.json>  (run on the pre-change code)
    with open(sys.argv[1], "w") as fh:
        json.dump(capture(), fh, indent=1, sort_keys=True)
