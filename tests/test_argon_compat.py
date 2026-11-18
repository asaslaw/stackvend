"""Gemini 4 Argon compatibility (owner-approved 10-14). Fake genai clients only: no network, no LLM, no Firestore.

The helper tests use a fake google.genai.types (they do not depend on the installed SDK version); the call-site
Argon test needs an SDK with ThinkingConfig.thinking_level and is skipped without one."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
from datetime import date
from types import SimpleNamespace
from unittest.mock import patch

import pytest

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
import argon_flash_capture as cap  # noqa: E402
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; row SWARM-TOK-1)
from pydantic import ValidationError  # noqa: E402

import shared.gemini_model_config as gmc  # noqa: E402
from shared.gemini_model_config import (ARGON_FAMILY, BUDGET_FAMILY, MODEL_FAMILIES,  # noqa: E402
                                        UNSUPPORTED_MODEL_CONFIG, Purpose, UnsupportedModelConfig,
                                        adapt_generate_config_kwargs, max_output_tokens_for, resolve_model_family,
                                        thinking_config_for, validate_model_id)

SNAPSHOT = os.path.join(os.path.dirname(__file__), "fixtures", "argon_flash_request_configs.json")
ARGON = "gemini-4-argon"
BUDGET_IDS = sorted(m for m, f in MODEL_FAMILIES.items() if f is BUDGET_FAMILY)


# ------------------------------------------------------------------------------------------------ Flash byte identity
def test_flash_request_configs_byte_identical_to_pre_argon_snapshot():
    """The snapshot was captured on origin/main 769600e (before this change) by tests/argon_flash_capture.py.
    Since then the only edit is FD-4AM-d (owner 10-20): the critic system prompt no longer names the invented module
    `cicd-github-actions-wif` (both Flash entries, same one-substring change as shared/builtin_prompts.py)."""
    now = {m: cap.capture(m) for m in cap.FLASH_MODELS}
    with open(SNAPSHOT) as f:
        before = json.load(f)
    assert now == before


# ------------------------------------------------------------------------------------------------ helper unit tests
class _FakeThinkingConfig:
    def __init__(self, **kw):
        self.kw = kw


_FakeThinkingConfig.model_fields = {"thinking_budget": None, "thinking_level": None}


class _FakeTypes:
    """google.genai.types stand-in: the helper's behaviour must not depend on the installed SDK version."""
    ThinkingConfig = _FakeThinkingConfig
    ThinkingLevel = SimpleNamespace(LOW="LOW", MEDIUM="MEDIUM", HIGH="HIGH", MINIMAL="MINIMAL")


class _OldTypes:
    """An SDK without ThinkingConfig.thinking_level."""
    class ThinkingConfig(_FakeThinkingConfig):
        model_fields = {"thinking_budget": None}


T = _FakeTypes


def test_family_table_is_explicit():
    assert resolve_model_family(ARGON) is ARGON_FAMILY
    assert resolve_model_family("publishers/google/models/gemini-4-argon") is ARGON_FAMILY
    assert resolve_model_family("gemini-4-argon-preview-10-2026") is ARGON_FAMILY
    assert resolve_model_family("gemini-3.8-flash") is BUDGET_FAMILY
    assert resolve_model_family("gemini-2.0-flash-lite-001") is BUDGET_FAMILY
    for unknown in ("gemini-4", "gemini-4-flash", "gemini-9.9-ultra", "argon", "my-gemini-4-argon", ""):
        assert resolve_model_family(unknown) is None, unknown


@pytest.mark.parametrize("model", BUDGET_IDS)
def test_budget_family_is_identity(model):
    """Do No Harm: a Gemini <= 3.x request is returned as the same object, untouched."""
    kwargs = {"system_instruction": "S", "temperature": 0.2, "top_p": 0.9, "max_output_tokens": 65536,
              "candidate_count": 1, "thinking_config": object()}
    snapshot = dict(kwargs)
    assert adapt_generate_config_kwargs(model, Purpose.DEVELOPER, kwargs, types=T) is kwargs
    assert kwargs == snapshot
    assert max_output_tokens_for(model, 65536, Purpose.DEVELOPER, reserved_thinking_tokens=2048) == 65536
    assert thinking_config_for(model, 0, Purpose.REPAIR, types=T) is None
    assert thinking_config_for(model, None, Purpose.REPAIR, types=T) is None
    assert thinking_config_for(model, 2048, Purpose.REPAIR, types=T).kw == {"thinking_budget": 2048}


@pytest.mark.parametrize("purpose,level", [(Purpose.ARCHITECT, "LOW"), (Purpose.REPAIR, "LOW"),
                                           (Purpose.DEVELOPER, "MEDIUM"), (Purpose.AUXILIARY, "LOW")])
def test_argon_thinking_level_never_budget(purpose, level):
    tc = thinking_config_for(ARGON, 2048, purpose, types=T)
    assert tc.kw == {"thinking_level": level}
    assert "thinking_budget" not in tc.kw and tc.kw["thinking_level"] != "MINIMAL"


def test_argon_adapter_drops_rejected_and_sampling_params():
    kwargs = {"system_instruction": "S", "response_mime_type": "application/json", "response_schema": dict,
              "temperature": 0.1, "top_p": 0.9, "top_k": 40, "candidate_count": 1, "frequency_penalty": 0.1,
              "presence_penalty": 0.1, "cached_content": "c", "max_output_tokens": 65536,
              "thinking_config": _FakeThinkingConfig(thinking_budget=2048)}
    out = adapt_generate_config_kwargs(ARGON, Purpose.ARCHITECT, kwargs, types=T)
    assert set(out) == {"system_instruction", "response_mime_type", "response_schema", "max_output_tokens",
                        "thinking_config"}
    assert out["thinking_config"].kw == {"thinking_level": "LOW"}
    assert out["max_output_tokens"] == 32768            # non-streaming cap; long decode is not enabled
    assert kwargs["temperature"] == 0.1                  # the caller's dict is not mutated


def test_argon_output_caps():
    # architect: its 16384 answer room + the LOW reserve; developer 65536 -> the 32768 non-streaming cap
    assert max_output_tokens_for(ARGON, 16384, Purpose.ARCHITECT) == 16384 + 4096
    assert max_output_tokens_for(ARGON, 65536, Purpose.DEVELOPER) == 32768
    assert max_output_tokens_for(ARGON, 9000, Purpose.REPAIR, reserved_thinking_tokens=2048) == 9000 - 2048 + 4096
    assert max_output_tokens_for(ARGON, None, Purpose.AUXILIARY) is None


def test_repair_call_bound_flash_unchanged_argon_reserve():
    from shared.hallucination_stack import HallucinationStackSettings, repair_call_max_output_tokens
    s = HallucinationStackSettings()
    for size in (0, 1000, 5000, 50_000):
        flash = repair_call_max_output_tokens(s, size)
        assert repair_call_max_output_tokens(s, size, model="gemini-3.8-flash") == flash
        argon = repair_call_max_output_tokens(s, size, model=ARGON)
        assert argon == min(32768, flash - s.repair_thinking_budget + 4096)
        assert argon > s.repair_thinking_budget  # invoke_repair's (0, max_output_tokens) check still holds
    big = HallucinationStackSettings(repair_max_output_tokens=65536)
    assert repair_call_max_output_tokens(big, 100_000, model=ARGON) == 32768


def test_unknown_model_typed_error_at_settings_never_at_call():
    from shared.hallucination_stack import HallucinationStackSettings
    from shared.settings import AgentModelSettings
    with pytest.raises(UnsupportedModelConfig) as ei:
        validate_model_id("gemini-9.9-ultra", "architect_model")
    assert ei.value.code == UNSUPPORTED_MODEL_CONFIG and UNSUPPORTED_MODEL_CONFIG in str(ei.value)
    for kw in ({"architect_model": "gemini-9.9-ultra"}, {"repair_model": "gpt-x"},
               {"fallback_models": ["gemini-3.7-flash", "nope"]}):
        with pytest.raises(ValidationError, match=UNSUPPORTED_MODEL_CONFIG):
            AgentModelSettings(**kw)
    with pytest.raises(ValidationError, match=UNSUPPORTED_MODEL_CONFIG):
        HallucinationStackSettings(repair_model="gemini-9.9-ultra")
    assert validate_model_id("") == ""
    # a live call with an unknown id (e.g. the GEMINI_MODEL env fallback) is sent exactly as before
    kwargs = {"temperature": 0.2, "max_output_tokens": 65536}
    assert adapt_generate_config_kwargs("gemini-9.9-ultra", Purpose.DEVELOPER, kwargs, types=T) is kwargs
    assert max_output_tokens_for("gemini-9.9-ultra", 65536, Purpose.DEVELOPER) == 65536
    assert thinking_config_for("gemini-9.9-ultra", 2048, Purpose.REPAIR, types=T).kw == {"thinking_budget": 2048}


def test_startup_sdk_gate():
    from shared.gemini_model_config import assert_sdk_supports_families
    assert_sdk_supports_families(["gemini-3.8-flash", "", ARGON], types=T)
    assert_sdk_supports_families(["gemini-3.8-flash", ""], types=_OldTypes)     # budget family: no SDK need
    with pytest.raises(UnsupportedModelConfig, match="2.30.1"):
        assert_sdk_supports_families([ARGON], types=_OldTypes)
    assert thinking_config_for(ARGON, None, Purpose.REPAIR, types=_OldTypes) is None   # live call: no raise
    with pytest.raises(UnsupportedModelConfig):
        assert_sdk_supports_families(["gemini-9.9-ultra"], types=T)


def test_helper_never_imports_the_sdk():
    """shared/ is vendored into services without google-genai (tests/test_shared_packaging.py): the SDK types are
    injected by the caller."""
    import ast
    tree = ast.parse(open(gmc.__file__).read())
    names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    names += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [n for n in names if n.startswith("google")]


# ------------------------------------------------------------------------------------------------ settings
def test_settings_allow_argon_per_agent_while_developer_stays_flash():
    from shared import settings as st
    ps = st.PlatformSettings(models={"architect_model": ARGON, "repair_model": ARGON,
                                     "developer_model": "gemini-3.8-flash", "fallback_models": ["gemini-3.7-flash"]})
    assert ps.models.architect_model == ARGON and ps.models.repair_model == ARGON
    assert st.AgentModelSettings().repair_model == ""        # default: unset -> the developer model repairs
    with patch.object(st, "get_platform_settings", return_value=ps):
        assert st.get_model_cascade_for_agent("architect")[0] == ARGON
        assert st.get_model_cascade_for_agent("developer") == ["gemini-3.8-flash", "gemini-3.7-flash"]
    from developer_agent.handler import DeveloperAgent
    with patch("shared.settings.get_platform_settings", return_value=ps):
        assert DeveloperAgent._platform_repair_model(SimpleNamespace(project_id="p")) == ARGON
    with patch("shared.settings.get_platform_settings", return_value=st.PlatformSettings()):
        assert DeveloperAgent._platform_repair_model(SimpleNamespace(project_id="p")) == ""
    with patch("shared.settings.get_platform_settings", side_effect=RuntimeError("down")):
        assert DeveloperAgent._platform_repair_model(SimpleNamespace(project_id="p")) == ""


# ------------------------------------------------------------------------------------------------ call sites (Argon)
@pytest.mark.skipif(not gmc.sdk_supports_thinking_level(__import__("google.genai.types", fromlist=["x"])), reason="installed google-genai lacks thinking_level")
def test_argon_call_site_configs():
    got = {k: json.loads(v) for k, v in cap.capture(ARGON).items()}
    for site, cfg in got.items():
        assert "temperature" not in cfg and "top_p" not in cfg and "top_k" not in cfg, site
        assert "thinking_budget" not in cfg["thinking_config"], site
        for p in ("candidate_count", "frequency_penalty", "presence_penalty", "cached_content"):
            assert p not in cfg, (site, p)
    assert got["swarm.invoke_repair"]["thinking_config"] == {"thinking_level": "LOW"}
    assert got["swarm.invoke_repair"]["max_output_tokens"] == 9000      # sized upstream (repair_call_max_output_tokens)
    assert got["swarm._call_gemini_with_backoff"]["thinking_config"] == {"thinking_level": "MEDIUM"}
    assert got["swarm._call_gemini_with_backoff"]["max_output_tokens"] == 32768
    critic = got["red_team_critic._invoke_llm_critic"]
    assert critic["thinking_config"] == {"thinking_level": "LOW"}
    assert critic["max_output_tokens"] == 16384 + 4096


# ------------------------------------------------------------------------------------------------ prices
def test_argon_price_switch_on_2026_12_01():
    from shared.token_accounting import calculate_token_cost, model_pricing
    assert model_pricing(ARGON, date(2026, 11, 30)) == {"prompt_per_m": 2.00, "candidates_per_m": 10.00,
                                                        "cached_prompt_per_m": 0.10}
    assert model_pricing(ARGON, date(2026, 12, 1)) == {"prompt_per_m": 4.00, "candidates_per_m": 20.00,
                                                       "cached_prompt_per_m": 0.20}
    assert calculate_token_cost(ARGON, 1_000_000, 1_000_000, on=date(2026, 11, 30)) == pytest.approx(12.0)
    assert calculate_token_cost(ARGON, 1_000_000, 1_000_000, on=date(2026, 12, 1)) == pytest.approx(24.0)
    for d in (date(2026, 11, 30), date(2026, 12, 1)):   # Flash rows untouched by the dated table
        assert calculate_token_cost("gemini-3.8-flash", 1_000_000, 1_000_000, on=d) == pytest.approx(0.375)


def test_eval_pricing_row_unverified():
    with open(os.path.join(cap.REPO_ROOT, "eval", "config", "pricing.json")) as f:
        row = json.load(f)["models"][ARGON]
    assert row["verified"] is False and row["max_output_tokens"] == 32768
    assert (row["list_in_per_m"], row["list_out_per_m"]) == (4.00, 20.00)   # the higher (12-01) row: an upper bound


# ------------------------------------------------------------------------------------------------ replicas / pins
_COPIES = ["apps/control-center/shared", "apps/orchestrator-gateway/shared", "apps/project-vending/shared",
           "mcp-servers/terraform/shared"]


@pytest.mark.parametrize("name,dirs", [("gemini_model_config.py", _COPIES), ("settings.py", _COPIES),
                                       ("token_accounting.py", _COPIES),
                                       ("hallucination_stack.py", ["apps/orchestrator-gateway/shared"])])
def test_replicas_identical(name, dirs):
    with open(os.path.join(cap.REPO_ROOT, "shared", name), "rb") as f:
        canonical = f.read()
    for d in dirs:
        with open(os.path.join(cap.REPO_ROOT, d, name), "rb") as f:
            assert f.read() == canonical, f"{d}/{name} drifted from shared/{name}"


def test_genai_pins():
    for req in ("apps/orchestrator-gateway/requirements.txt", "apps/control-center/requirements.txt"):
        with open(os.path.join(cap.REPO_ROOT, req)) as f:
            lines = [ln.split("#")[0].strip() for ln in f]
        assert "google-genai>=2.29.0,<3" in lines, req   # RT F3: 2.29.0 already has thinking_level


# ------------------------------------------------------------------------------------------------ Fable RT fixes
_STORED = {"finops": {"default_monthly_budget_usd": 123.0}, "governance": {"maintenance_mode": True},
           "models": {"architect_model": ARGON, "developer_model": "gemini-3.8-flash",
                      "assistant_model": "gemini-3.7-flash", "fallback_models": ["gemini-3.7-flash"]}}


def test_f1_stored_doc_with_known_ids_parses_exactly_as_before():
    from shared import settings as st
    assert st.platform_settings_from_stored(json.loads(json.dumps(_STORED))).model_dump() == \
        st.PlatformSettings(**json.loads(json.dumps(_STORED))).model_dump()


def test_f1_one_unknown_stored_id_resets_only_that_field(caplog):
    from shared import settings as st
    doc = json.loads(json.dumps(_STORED))
    doc["models"]["assistant_model"] = "gemini-flash-latest"
    doc["models"]["fallback_models"] = ["gemini-3.7-flash", "nope"]
    with pytest.raises(ValidationError):                                  # strict where it is saved (PUT -> 422)
        st.PlatformSettings(**json.loads(json.dumps(doc)))
    with caplog.at_level("ERROR"):
        ps = st.platform_settings_from_stored(doc)
    defaults = st.AgentModelSettings()
    assert ps.models.assistant_model == defaults.assistant_model
    assert ps.models.fallback_models == defaults.fallback_models
    assert ps.models.architect_model == ARGON and ps.models.developer_model == "gemini-3.8-flash"
    assert ps.finops.default_monthly_budget_usd == 123.0 and ps.governance.maintenance_mode is True
    assert UNSUPPORTED_MODEL_CONFIG in caplog.text


def test_f1_other_validation_errors_still_raise():
    from shared import settings as st
    doc = json.loads(json.dumps(_STORED))
    doc["models"]["assistant_model"] = "nope"
    doc["models"]["max_output_tokens"] = 10**9                          # not a model-id error
    with pytest.raises(ValidationError):
        st.platform_settings_from_stored(doc)


def test_f1_get_platform_settings_applies_lenient_doc_and_advances_cache_time():
    from shared import settings as st
    doc = json.loads(json.dumps(_STORED))
    doc["models"]["finops_model"] = "gemini-9.9-ultra"

    class _Doc:
        exists = True

        def to_dict(self):
            return json.loads(json.dumps(doc))

    class _Client:
        def __init__(self, *a, **k):
            pass

        def collection(self, *_a):
            return SimpleNamespace(document=lambda *_b: SimpleNamespace(get=lambda: _Doc()))

    st.invalidate_settings_cache()
    try:
        with patch("google.cloud.firestore.Client", _Client):
            ps = st.get_platform_settings(force_refresh=True, project_id="p")
        assert ps.models.finops_model == st.AgentModelSettings().finops_model
        assert ps.finops.default_monthly_budget_usd == 123.0 and ps.governance.maintenance_mode is True
        assert st._LAST_FETCH_TIME > 0 and st._SETTINGS_CACHE is ps
    finally:
        st.invalidate_settings_cache()


def test_f2_argon_repair_task_carries_no_flash_budget():
    from developer_agent.swarm_dispatcher import SwarmDispatcher
    from shared.hallucination_stack import (HallucinationStackSettings, repair_call_max_output_tokens,
                                            repair_call_thinking_budget)
    s = HallucinationStackSettings()
    assert repair_call_thinking_budget(s) == 2048                            # negative: Flash unchanged
    assert repair_call_thinking_budget(s, model="gemini-3.8-flash") == 2048
    assert repair_call_thinking_budget(s, model="gemini-9.9-ultra") == 2048  # unknown id: as before
    big = HallucinationStackSettings(repair_thinking_budget=8192)
    assert repair_call_thinking_budget(big, model=ARGON) is None
    if not gmc.sdk_supports_thinking_level(__import__("google.genai.types", fromlist=["x"])):
        pytest.skip("installed google-genai lacks thinking_level")
    fake = cap.FakeGenai()
    res = SwarmDispatcher(genai_client=fake, model_name=ARGON).invoke_repair(
        "developer", "SYS", "PROMPT", ARGON, repair_call_max_output_tokens(big, 0, model=ARGON),
        thinking_budget=repair_call_thinking_budget(big, model=ARGON))
    assert len(fake.calls) == 1 and res["error"] is None                    # sent, not refused before send
    cfg = json.loads(cap.dump_config(fake.calls[0]["config"]))
    assert cfg["thinking_config"] == {"thinking_level": "LOW"}
    assert cfg["max_output_tokens"] == 2048 + 4096


def test_f4_price_lookup_uses_the_family_id_rule():
    from shared.token_accounting import model_pricing
    d = date(2026, 11, 30)
    for mid in ("publishers/google/models/gemini-4-argon", "gemini-4-argon-preview-11-2026", "GEMINI-4-ARGON"):
        assert model_pricing(mid, d)["prompt_per_m"] == 2.00, mid
        assert model_pricing(mid, date(2026, 12, 1))["prompt_per_m"] == 4.00, mid
    assert model_pricing("gemini-3.8-flash", d) == {"prompt_per_m": 0.075, "candidates_per_m": 0.30}
    # OPEN-MODEL-SETTINGS (owner 11-10): an id with no built-in rules and no price row has a typed unknown price
    from shared.token_accounting import UnknownModelPrice
    with pytest.raises(UnknownModelPrice):
        model_pricing("unknown-model-xyz", d)
