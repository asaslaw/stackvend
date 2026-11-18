"""Gemini 4 Carbon as a selectable model (owner 11-10, register row GEMINI-4-CARBON).

Carbon takes Argon's request rules under its own family entry. Fake genai types / clients only: no network, no LLM,
no Firestore. Do No Harm: every model known before this change keeps its family and its price."""
import hermetic_guard  # noqa: F401  (first import)

import glob
import json
import os
import sys
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
import argon_flash_capture as cap  # noqa: E402
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; row SWARM-TOK-1)

import shared.gemini_model_config as gmc  # noqa: E402
from shared.gemini_model_config import (ARGON_FAMILY, BUDGET_FAMILY, CARBON_FAMILY, MODEL_FAMILIES,  # noqa: E402
                                        Purpose, ThinkingControl, adapt_generate_config_kwargs, known_model_id,
                                        max_output_tokens_for, resolve_model_family, thinking_config_for,
                                        validate_model_id)

CARBON = "gemini-4-carbon"
ARGON = "gemini-4-argon"

# The family table and the price table as they were before GEMINI-4-CARBON (main d7ce554e).
_FAMILIES_BEFORE = {
    "gemini-1.5-flash": BUDGET_FAMILY, "gemini-1.5-pro": BUDGET_FAMILY, "gemini-2.0-flash": BUDGET_FAMILY,
    "gemini-2.0-flash-lite": BUDGET_FAMILY, "gemini-2.5-flash": BUDGET_FAMILY, "gemini-2.5-flash-lite": BUDGET_FAMILY,
    "gemini-2.5-pro": BUDGET_FAMILY, "gemini-3.0-flash": BUDGET_FAMILY, "gemini-3.7-flash": BUDGET_FAMILY,
    "gemini-3.8-flash": BUDGET_FAMILY, "gemini-3.8-pro": BUDGET_FAMILY, ARGON: ARGON_FAMILY,
}
_PRICES_BEFORE = {
    "gemini-3.8-flash": {"prompt_per_m": 0.075, "candidates_per_m": 0.30},
    "gemini-3.7-flash": {"prompt_per_m": 0.075, "candidates_per_m": 0.30},
    "gemini-2.0-flash": {"prompt_per_m": 0.10, "candidates_per_m": 0.40},
    "gemini-2.0-flash-lite": {"prompt_per_m": 0.075, "candidates_per_m": 0.30},
    "gemini-1.5-flash": {"prompt_per_m": 0.075, "candidates_per_m": 0.30},
    "gemini-1.5-pro": {"prompt_per_m": 1.25, "candidates_per_m": 5.00},
    ARGON: {"prompt_per_m": 2.00, "candidates_per_m": 10.00, "cached_prompt_per_m": 0.10},
    "default": {"prompt_per_m": 0.075, "candidates_per_m": 0.30},
}
_EVAL_ROWS_BEFORE = {  # (list in, list out, verified, max_output_tokens)
    "gemini-3.8-flash": (0.50, 4.00, False, 65536), "gemini-3.7-flash": (0.50, 4.00, False, 65536),
    "gemini-2.5-flash": (0.30, 2.50, False, 65536), "gemini-2.0-flash": (0.15, 0.60, False, 8192),
    ARGON: (4.00, 20.00, False, 32768),
}


class _FakeThinkingConfig:
    def __init__(self, **kw):
        self.kw = kw


_FakeThinkingConfig.model_fields = {"thinking_budget": None, "thinking_level": None}


class _FakeTypes:
    ThinkingConfig = _FakeThinkingConfig
    ThinkingLevel = SimpleNamespace(LOW="LOW", MEDIUM="MEDIUM", HIGH="HIGH", MINIMAL="MINIMAL")


class _OldTypes:
    """An SDK without ThinkingConfig.thinking_level."""
    class ThinkingConfig(_FakeThinkingConfig):
        model_fields = {"thinking_budget": None}


T = _FakeTypes


# ------------------------------------------------------------------------------------------------ family
def test_carbon_family_has_argons_rules_under_its_own_name():
    assert MODEL_FAMILIES[CARBON] is CARBON_FAMILY
    assert CARBON_FAMILY.name == CARBON
    assert CARBON_FAMILY.thinking is ThinkingControl.LEVEL
    assert CARBON_FAMILY.non_streaming_max_output_tokens == 32768
    assert CARBON_FAMILY.sampling_params_honoured is False
    assert CARBON_FAMILY.rejected_params == ARGON_FAMILY.rejected_params
    assert {"frequency_penalty", "presence_penalty"} <= CARBON_FAMILY.rejected_params


def test_carbon_id_rule_is_the_exact_table():
    assert resolve_model_family(CARBON) is CARBON_FAMILY
    assert resolve_model_family("publishers/google/models/gemini-4-carbon") is CARBON_FAMILY
    assert resolve_model_family("GEMINI-4-CARBON") is CARBON_FAMILY
    assert resolve_model_family("gemini-4-carbon-preview-12-2026") is CARBON_FAMILY
    assert known_model_id("gemini-4-carbon-001") == CARBON
    for unknown in ("carbon", "gemini-4-carb", "my-gemini-4-carbon", "gemini-4-carbonx"):
        assert resolve_model_family(unknown) is None, unknown


def test_do_no_harm_existing_families_unchanged():
    assert {m: f for m, f in MODEL_FAMILIES.items() if m != CARBON} == _FAMILIES_BEFORE
    assert ARGON_FAMILY == gmc.ModelFamily(name=ARGON, thinking=ThinkingControl.LEVEL,
                                           non_streaming_max_output_tokens=32_768, sampling_params_honoured=False,
                                           rejected_params=frozenset({"candidate_count", "frequency_penalty",
                                                                      "presence_penalty", "cached_content"}))
    assert BUDGET_FAMILY.thinking is ThinkingControl.BUDGET and BUDGET_FAMILY.rejected_params == frozenset()


# ------------------------------------------------------------------------------------------------ request config
@pytest.mark.parametrize("purpose,level", [(Purpose.ARCHITECT, "LOW"), (Purpose.REPAIR, "LOW"),
                                           (Purpose.DEVELOPER, "MEDIUM"), (Purpose.AUXILIARY, "LOW")])
def test_carbon_thinking_level_never_budget_never_minimal(purpose, level):
    tc = thinking_config_for(CARBON, 2048, purpose, types=T)
    assert tc.kw == {"thinking_level": level}
    assert "thinking_budget" not in tc.kw and tc.kw["thinking_level"] != "MINIMAL"


def test_carbon_adapter_drops_budget_penalties_and_sampling():
    kwargs = {"system_instruction": "S", "response_mime_type": "application/json", "response_schema": dict,
              "temperature": 0.1, "top_p": 0.9, "top_k": 40, "candidate_count": 1, "frequency_penalty": 0.1,
              "presence_penalty": 0.1, "cached_content": "c", "max_output_tokens": 65536,
              "thinking_config": _FakeThinkingConfig(thinking_budget=2048)}
    snapshot = dict(kwargs)
    out = adapt_generate_config_kwargs(CARBON, Purpose.DEVELOPER, kwargs, types=T)
    assert set(out) == {"system_instruction", "response_mime_type", "response_schema", "max_output_tokens",
                        "thinking_config"}
    assert out["thinking_config"].kw == {"thinking_level": "MEDIUM"}
    assert out["max_output_tokens"] == 32768
    assert kwargs == snapshot                                     # the caller's dict is not mutated


def test_carbon_cc_assistant_request():
    """The CC assistant's base config (system instruction, temperature 0.4) -> thinking_level LOW, no temperature."""
    out = adapt_generate_config_kwargs(CARBON, Purpose.AUXILIARY, {"system_instruction": "S", "temperature": 0.4},
                                       types=T)
    assert set(out) == {"system_instruction", "thinking_config"}
    assert out["thinking_config"].kw == {"thinking_level": "LOW"}


def test_carbon_output_caps_match_argon():
    for requested, purpose, reserved in ((16384, Purpose.ARCHITECT, 0), (65536, Purpose.DEVELOPER, 0),
                                         (9000, Purpose.REPAIR, 2048), (None, Purpose.AUXILIARY, 0)):
        assert max_output_tokens_for(CARBON, requested, purpose, reserved) == \
            max_output_tokens_for(ARGON, requested, purpose, reserved)


def test_carbon_repair_budget_is_not_sent():
    from shared.hallucination_stack import (HallucinationStackSettings, repair_call_max_output_tokens,
                                            repair_call_thinking_budget)
    s = HallucinationStackSettings(repair_thinking_budget=8192)
    assert repair_call_thinking_budget(s, model=CARBON) is None
    assert repair_call_max_output_tokens(s, 0, model=CARBON) == repair_call_max_output_tokens(s, 0, model=ARGON)


def test_carbon_startup_sdk_gate():
    from shared.gemini_model_config import assert_sdk_supports_families
    assert_sdk_supports_families([CARBON], types=T)
    with pytest.raises(gmc.UnsupportedModelConfig):
        assert_sdk_supports_families([CARBON], types=_OldTypes)
    assert thinking_config_for(CARBON, None, Purpose.REPAIR, types=_OldTypes) is None   # live call: no raise


def test_gateway_startup_check_covers_every_level_family(caplog):
    # DEFAULT-MODEL-GEMINI-4-CARBON RT F4: the default models (Carbon, fallback Argon) fail the boot loudly on an SDK
    # without thinking_level (they used to be only logged, with every other level family)
    from test_fd4dc_archive_and_partial_readers import _gateway_main
    gw = _gateway_main()
    with patch.dict(os.environ, {"GEMINI_MODEL": ""}), patch("google.genai.types", _OldTypes), \
            pytest.raises(gmc.UnsupportedModelConfig) as ei:
        gw._argon_compat_startup_check()
    assert CARBON in str(ei.value)
    with patch.dict(os.environ, {"GEMINI_MODEL": ""}), patch("google.genai.types", T):
        gw._argon_compat_startup_check()                      # an SDK with thinking_level boots


@pytest.mark.skipif(not gmc.sdk_supports_thinking_level(__import__("google.genai.types", fromlist=["x"])),
                    reason="installed google-genai lacks thinking_level")
def test_carbon_call_site_configs():
    got = {k: json.loads(v) for k, v in cap.capture(CARBON).items()}
    for site, cfg in got.items():
        assert "temperature" not in cfg and "top_p" not in cfg and "top_k" not in cfg, site
        assert "thinking_budget" not in cfg["thinking_config"], site
        assert cfg["thinking_config"]["thinking_level"] != "MINIMAL", site
        for p in ("candidate_count", "frequency_penalty", "presence_penalty", "cached_content"):
            assert p not in cfg, (site, p)
    assert got["swarm.invoke_repair"]["thinking_config"] == {"thinking_level": "LOW"}
    assert got["swarm._call_gemini_with_backoff"]["thinking_config"] == {"thinking_level": "MEDIUM"}
    assert got["swarm._call_gemini_with_backoff"]["max_output_tokens"] == 32768
    assert got["red_team_critic._invoke_llm_critic"]["thinking_config"] == {"thinking_level": "LOW"}
    # same request shape as Argon at every call site
    argon = {k: json.loads(v) for k, v in cap.capture(ARGON).items()}
    assert got == argon


# ------------------------------------------------------------------------------------------------ settings
_MODEL_ROLES = ("architect_model", "developer_model", "finops_model", "assistant_model", "repair_model")


@pytest.mark.parametrize("role", _MODEL_ROLES)
def test_settings_accept_carbon_for_every_model_role(role):
    from shared import settings as st
    assert validate_model_id(CARBON, role) == CARBON
    ps = st.PlatformSettings(models={role: CARBON})           # the CC PUT /api/settings body type
    assert getattr(ps.models, role) == CARBON
    # and it survives the lenient load path unchanged (no reset to the default)
    stored = st.platform_settings_from_stored(json.loads(json.dumps(ps.model_dump(mode="json"))))
    assert getattr(stored.models, role) == CARBON


def test_settings_accept_carbon_as_fallback_and_hallucination_repair_model():
    from shared import settings as st
    from shared.hallucination_stack import HallucinationStackSettings
    assert st.AgentModelSettings(fallback_models=[CARBON, "gemini-3.7-flash"]).fallback_models[0] == CARBON
    assert HallucinationStackSettings(repair_model=CARBON).repair_model == CARBON


def test_settings_defaults_are_carbon_with_argon_fallback():
    # DEFAULT-MODEL-GEMINI-4-CARBON (owner 11-11): was gemini-3.8-flash x4 / ["gemini-3.7-flash"] (GEMINI-4-CARBON)
    from shared import settings as st
    m = st.AgentModelSettings()
    assert (m.architect_model, m.developer_model, m.finops_model, m.assistant_model) == (CARBON,) * 4
    assert m.repair_model == "" and m.fallback_models == [ARGON, "gemini-3.8-flash", "gemini-3.7-flash"]


def test_assistant_cascade_uses_carbon_when_selected():
    from shared import settings as st
    ps = st.PlatformSettings(models={"assistant_model": CARBON})
    with patch.object(st, "get_platform_settings", return_value=ps):
        assert st.get_model_cascade_for_agent("assistant") == [CARBON, ARGON, "gemini-3.8-flash", "gemini-3.7-flash"]
        assert st.get_model_cascade_for_agent("developer") == [CARBON, ARGON, "gemini-3.8-flash", "gemini-3.7-flash"]
    ps = st.PlatformSettings(models={"assistant_model": CARBON, "developer_model": "gemini-3.8-flash",
                                     "fallback_models": ["gemini-3.7-flash"]})
    with patch.object(st, "get_platform_settings", return_value=ps):     # stored values are used as they are
        assert st.get_model_cascade_for_agent("assistant") == [CARBON, "gemini-3.7-flash"]
        assert st.get_model_cascade_for_agent("developer") == ["gemini-3.8-flash", "gemini-3.7-flash"]


# ------------------------------------------------------------------------------------------------ prices
def test_carbon_price_row():
    from shared.token_accounting import calculate_token_cost, model_pricing
    row = {"prompt_per_m": 4.00, "candidates_per_m": 20.00, "cached_prompt_per_m": 0.20}
    for d in (date(2026, 11, 10), date(2026, 12, 1), date(2027, 6, 1)):      # no dated change
        assert model_pricing(CARBON, d) == row
    for mid in ("publishers/google/models/gemini-4-carbon", "gemini-4-carbon-001", "GEMINI-4-CARBON"):
        assert model_pricing(mid, date(2026, 11, 10)) == row, mid
    assert calculate_token_cost(CARBON, 1_000_000, 1_000_000, on=date(2026, 11, 10)) == pytest.approx(24.0)


def test_do_no_harm_existing_prices_unchanged():
    from shared.token_accounting import MODEL_PRICE_CHANGES, MODEL_PRICING, model_pricing
    assert {m: r for m, r in MODEL_PRICING.items() if m != CARBON} == _PRICES_BEFORE
    assert set(MODEL_PRICE_CHANGES) == {ARGON}
    assert model_pricing(ARGON, date(2026, 12, 1)) == {"prompt_per_m": 4.00, "candidates_per_m": 20.00,
                                                       "cached_prompt_per_m": 0.20}
    assert model_pricing("default", date(2026, 11, 10)) == _PRICES_BEFORE["default"]


def test_eval_pricing_carbon_row_and_others_unchanged():
    with open(os.path.join(cap.REPO_ROOT, "eval", "config", "pricing.json")) as f:
        models = json.load(f)["models"]
    row = models[CARBON]
    assert (row["list_in_per_m"], row["list_out_per_m"], row["max_output_tokens"]) == (4.00, 20.00, 32768)
    assert row["verified"] is True        # Cloud Billing Catalog list price, fetched 2026-11-10
    assert {m: (r["list_in_per_m"], r["list_out_per_m"], r["verified"], r["max_output_tokens"])
            for m, r in models.items() if m != CARBON} == _EVAL_ROWS_BEFORE
    harness = os.path.join(cap.REPO_ROOT, "eval")
    with patch("sys.path", [harness] + sys.path):            # the harness loader accepts the row
        from stackvend_eval.budget import PriceTable
    price = PriceTable.load(Path(harness) / "config" / "pricing.json").get(CARBON)
    assert price.verified is True and (price.in_per_m, price.out_per_m) == (8.0, 40.0)   # ceiling = 2x list


# ------------------------------------------------------------------------------------------------ copy parity
def _copies(name):
    root = cap.REPO_ROOT
    return sorted(glob.glob(os.path.join(root, "apps", "*", "shared", name))
                  + glob.glob(os.path.join(root, "mcp-servers", "*", "shared", name)))


@pytest.mark.parametrize("name,count", [("gemini_model_config.py", 7), ("token_accounting.py", 5)])
def test_every_copy_is_byte_identical(name, count):
    with open(os.path.join(cap.REPO_ROOT, "shared", name), "rb") as f:
        canonical = f.read()
    copies = _copies(name)
    assert len(copies) == count, copies
    for path in copies:
        with open(path, "rb") as f:
            assert f.read() == canonical, f"{os.path.relpath(path, cap.REPO_ROOT)} drifted from shared/{name}"
