"""Gemini request-config capture for the Argon-compat byte-identity snapshot (tests/test_argon_compat.py).

Drives the real call sites (swarm repair call, swarm generation call, red-team critic) with a fake genai client and
returns each request config as canonical JSON. The snapshot `tests/fixtures/argon_flash_request_configs.json` was
produced by this module on the code BEFORE the Argon change (origin/main 769600e); the test re-captures on the
current code and requires the Flash configs to be byte-identical (the eval cassettes key on them).
Fake client only: no network, no LLM, no Firestore."""
import asyncio
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for _p in (GATEWAY, REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from google.genai import types  # noqa: E402

FLASH_MODELS = ("gemini-3.8-flash", "gemini-3.7-flash")


def _response(text):
    return types.GenerateContentResponse.model_validate({
        "candidates": [{"content": {"role": "model", "parts": [{"text": text}]}, "finish_reason": "STOP"}],
        "usage_metadata": {"prompt_token_count": 10, "candidates_token_count": 10, "total_token_count": 20}})


class FakeGenai:
    def __init__(self, text='{"files": {}}'):
        self.text = text
        self.calls = []
        self.models = self

    def generate_content(self, *, model, contents, config):
        self.calls.append({"model": model, "config": config})
        return _response(self.text)


def dump_config(config):
    """Canonical JSON of a request config (GenerateContentConfig or the dict form the critic sends)."""
    if isinstance(config, dict):
        d = {k: (v.__name__ if isinstance(v, type)
                 else v.model_dump(mode="json", exclude_none=True) if hasattr(v, "model_dump") else v)
             for k, v in config.items()}
        return json.dumps({"__dict__": True, **d}, sort_keys=True, default=str)
    # SLOW-CALL-FALLBACK: http_options (the per-call timeout) is transport, not request content (cassette key too)
    d = config.model_dump(mode="json", exclude_none=True, exclude={"http_options"})
    if getattr(config, "response_schema", None) is not None and isinstance(config.response_schema, type):
        d["response_schema"] = config.response_schema.__name__
    return json.dumps(d, sort_keys=True, default=str)


def capture(model):
    """{call_site: canonical config JSON} for one model id."""
    from developer_agent.swarm_dispatcher import SwarmDispatcher
    out = {}

    fake = FakeGenai()
    SwarmDispatcher(genai_client=fake, model_name=model).invoke_repair(
        "developer", "SYS", "PROMPT", model, 9000, thinking_budget=2048)
    out["swarm.invoke_repair"] = dump_config(fake.calls[-1]["config"])

    fake = FakeGenai()
    asyncio.run(SwarmDispatcher(genai_client=fake, model_name=model)._call_gemini_with_backoff("PROMPT", "SYS", model))
    out["swarm._call_gemini_with_backoff"] = dump_config(fake.calls[-1]["config"])

    from architect_agent import red_team_critic
    from shared.settings import PlatformSettings
    fake = FakeGenai('{"is_approved": true}')
    topo = SimpleNamespace(is_valid=True, cycle_detected=False, orphan_dependencies=[], ordering_violations=[])
    with patch.object(red_team_critic, "get_model_cascade_for_agent", return_value=[model]), \
            patch("shared.settings.get_platform_settings", return_value=PlatformSettings()):
        red_team_critic.RedTeamCritic(genai_client=fake, model_name=model)._invoke_llm_critic(
            {"steps": []}, "spec", topo, None)
    out["red_team_critic._invoke_llm_critic"] = dump_config(fake.calls[0]["config"])
    return out


if __name__ == "__main__":
    print(json.dumps({m: capture(m) for m in FLASH_MODELS}, indent=2, sort_keys=True))
