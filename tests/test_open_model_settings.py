"""OPEN-MODEL-SETTINGS + THINKING-LEVEL-SETTINGS (owner 11-10).

Admins may enter any Gemini model id in Settings: each changed model gets one small live call when the settings are
saved (Control Center PUT /api/settings), and a model without built-in rules gets its request style (LEVEL / BUDGET)
from typed API outcomes, stored in `models.custom_families`. Thinking levels per role (`models.thinking_levels`) drive
every level-family call. FD-7Z: the save toast reads every error shape and reverts refused fields.

Stubbed genai clients only: no network, no LLM, no real Firestore. Do No Harm: built-in models' requests and prices
are unchanged; with the default settings every call is byte-identical to before."""
import hermetic_guard  # noqa: F401  (first import)

import copy
import json
import os
import sys
import threading
from datetime import date
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
import argon_flash_capture as cap  # noqa: E402
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; row SWARM-TOK-1)
from pydantic import ValidationError  # noqa: E402

import shared.gemini_model_config as gmc  # noqa: E402
from shared import settings as S  # noqa: E402
from shared.gemini_model_config import (ARGON_FAMILY, ARGON_THINKING_LEVEL, BUDGET_FAMILY,  # noqa: E402
                                        DEFAULT_THINKING_LEVELS, LEVEL_STYLE_FAMILY, MODEL_FAMILIES,
                                        UNSUPPORTED_MODEL_CONFIG, Purpose, ThinkingControl, UnsupportedModelConfig,
                                        adapt_generate_config_kwargs, max_output_tokens_for, resolve_model_family,
                                        thinking_config_for, thinking_level_for, validate_model_id)

REPO_ROOT = cap.REPO_ROOT
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
ARGON, CARBON = "gemini-4-argon", "gemini-4-carbon"
LEVEL_ID, BUDGET_ID = "acme-thinker-2", "acme-classic-1"


class _FakeThinkingConfig:
    def __init__(self, **kw):
        self.kw = kw


_FakeThinkingConfig.model_fields = {"thinking_budget": None, "thinking_level": None}


class T:
    ThinkingConfig = _FakeThinkingConfig
    ThinkingLevel = SimpleNamespace(LOW="LOW", MEDIUM="MEDIUM", HIGH="HIGH", MINIMAL="MINIMAL")


def _settings(**models):
    return S.PlatformSettings(models=models)


def _with_settings(ps):
    return patch.object(S, "get_platform_settings", lambda *a, **k: ps)


# ================================================================================================ family resolution
def test_table_wins_over_a_custom_entry():
    fams = {"gemini-3.8-flash": "LEVEL", ARGON: "BUDGET", LEVEL_ID: "LEVEL", BUDGET_ID: "BUDGET"}
    assert resolve_model_family("gemini-3.8-flash", fams) is BUDGET_FAMILY
    assert resolve_model_family(ARGON, fams) is ARGON_FAMILY
    assert resolve_model_family(LEVEL_ID, fams) is LEVEL_STYLE_FAMILY
    assert resolve_model_family(BUDGET_ID, fams) is BUDGET_FAMILY
    assert resolve_model_family("acme-other", fams) is None
    assert LEVEL_STYLE_FAMILY.thinking is ThinkingControl.LEVEL
    assert LEVEL_STYLE_FAMILY.rejected_params == ARGON_FAMILY.rejected_params


def test_stored_custom_family_drives_the_agents_kwargs():
    ps = _settings(custom_families={LEVEL_ID: "LEVEL", BUDGET_ID: "BUDGET"}, architect_model=LEVEL_ID,
                   developer_model=BUDGET_ID)
    kwargs = {"system_instruction": "S", "temperature": 0.2, "max_output_tokens": 65536, "frequency_penalty": 0.1,
              "thinking_config": _FakeThinkingConfig(thinking_budget=2048)}
    with _with_settings(ps):
        out = adapt_generate_config_kwargs(LEVEL_ID, Purpose.ARCHITECT, kwargs, types=T)
        assert set(out) == {"system_instruction", "max_output_tokens", "thinking_config"}
        assert out["thinking_config"].kw == {"thinking_level": "LOW"} and out["max_output_tokens"] == 32768
        assert adapt_generate_config_kwargs(BUDGET_ID, Purpose.DEVELOPER, kwargs, types=T) is kwargs
        assert thinking_config_for(BUDGET_ID, 2048, Purpose.REPAIR, types=T).kw == {"thinking_budget": 2048}
        assert max_output_tokens_for(LEVEL_ID, 16384, Purpose.ARCHITECT) == 16384 + 4096


@pytest.mark.skipif(not gmc.sdk_supports_thinking_level(__import__("google.genai.types", fromlist=["x"])),
                    reason="installed google-genai lacks thinking_level")
def test_stored_custom_level_model_at_every_call_site():
    ps = _settings(custom_families={LEVEL_ID: "LEVEL"})
    critic = "red_team_critic._invoke_llm_critic"   # the capture pins PlatformSettings() for the critic itself
    with _with_settings(ps):
        got = {k: json.loads(v) for k, v in cap.capture(LEVEL_ID).items() if k != critic}
        argon = {k: json.loads(v) for k, v in cap.capture(ARGON).items() if k != critic}
        assert max_output_tokens_for(LEVEL_ID, 16384, Purpose.ARCHITECT) == \
            max_output_tokens_for(ARGON, 16384, Purpose.ARCHITECT)
    assert got == argon and got      # a LEVEL-style custom model gets Argon's request rules at the swarm sites


def test_model_in_neither_is_refused_at_settings_and_sent_unchanged_at_a_call():
    with pytest.raises(UnsupportedModelConfig):
        validate_model_id(LEVEL_ID, "architect_model")
    with pytest.raises(ValidationError, match=UNSUPPORTED_MODEL_CONFIG):
        S.AgentModelSettings(architect_model=LEVEL_ID)
    kwargs = {"temperature": 0.2}
    with _with_settings(S.PlatformSettings()):
        assert adapt_generate_config_kwargs(LEVEL_ID, Purpose.DEVELOPER, kwargs, types=T) is kwargs


# ================================================================================================ settings schema
def test_custom_id_accepted_only_with_a_style_in_the_same_document():
    m = S.AgentModelSettings(custom_families={LEVEL_ID: "LEVEL"}, architect_model=LEVEL_ID,
                             fallback_models=[LEVEL_ID, "gemini-3.7-flash"])
    assert m.architect_model == LEVEL_ID and m.fallback_models[0] == LEVEL_ID
    for bad_families in ({LEVEL_ID: "MEDIUM"}, {"Acme-Thinker-2": "LEVEL"}, {"bad id": "LEVEL"}, ["x"]):
        with pytest.raises(ValidationError):
            S.AgentModelSettings(custom_families=bad_families)


@pytest.mark.parametrize("mid", ["acme thinker", "a/b", "-lead", "x" * 81, "acme_1", "acme!"])
def test_entered_id_syntax_is_still_checked(mid):
    assert not gmc.is_model_id_syntax(mid)
    with pytest.raises(UnsupportedModelConfig):
        validate_model_id(mid, "architect_model", {mid.lower(): "LEVEL"})


def test_thinking_levels_schema():
    assert S.AgentModelSettings().thinking_levels == DEFAULT_THINKING_LEVELS
    assert DEFAULT_THINKING_LEVELS == {p.value: lvl for p, lvl in ARGON_THINKING_LEVEL.items()}
    assert DEFAULT_THINKING_LEVELS == {"architect": "LOW", "developer": "MEDIUM", "repair": "LOW", "auxiliary": "LOW"}
    assert S.AgentModelSettings(thinking_levels={"developer": "HIGH"}).thinking_levels == \
        {**DEFAULT_THINKING_LEVELS, "developer": "HIGH"}                       # partial: the rest default
    assert S.AgentModelSettings(thinking_levels=None).thinking_levels == DEFAULT_THINKING_LEVELS
    for bad in ({"architect": "MINIMAL"}, {"architect": "low"}, {"critic": "LOW"}, {"developer": None}, "HIGH"):
        with pytest.raises(ValidationError):
            S.AgentModelSettings(thinking_levels=bad)


def test_stored_documents_without_the_new_fields_load_as_before():
    doc = {"models": {"architect_model": ARGON, "assistant_model": "gemini-3.7-flash"}}
    ps = S.platform_settings_from_stored(copy.deepcopy(doc))
    assert ps.models.custom_families == {} and ps.models.thinking_levels == DEFAULT_THINKING_LEVELS
    assert ps.models.architect_model == ARGON


def test_stored_custom_id_without_its_style_resets_only_that_field(caplog):
    doc = {"models": {"architect_model": LEVEL_ID, "developer_model": BUDGET_ID,
                      "custom_families": {BUDGET_ID: "BUDGET"}}}
    with caplog.at_level("ERROR"):
        ps = S.platform_settings_from_stored(copy.deepcopy(doc))
    assert ps.models.architect_model == S.AgentModelSettings().architect_model
    assert ps.models.developer_model == BUDGET_ID and UNSUPPORTED_MODEL_CONFIG in caplog.text


# ================================================================================================ thinking levels
@pytest.mark.parametrize("purpose", list(Purpose))
@pytest.mark.parametrize("level", ["LOW", "MEDIUM", "HIGH"])
def test_each_role_honours_its_level(purpose, level):
    levels = {purpose.value: level}
    for model in (ARGON, CARBON):
        assert thinking_config_for(model, 2048, purpose, types=T, thinking_levels=levels).kw == \
            {"thinking_level": level}
        assert thinking_level_for(purpose, levels) == level
    with _with_settings(_settings(thinking_levels=levels)):         # the stored setting, no explicit mapping
        assert thinking_config_for(ARGON, None, purpose, types=T).kw == {"thinking_level": level}
        others = [p for p in Purpose if p is not purpose]
        for p in others:
            assert thinking_level_for(p) == ARGON_THINKING_LEVEL[p]


def test_high_gets_its_reserve_and_the_cap_holds():
    high = {"architect": "HIGH", "repair": "HIGH"}
    assert max_output_tokens_for(ARGON, 9000, Purpose.ARCHITECT, thinking_levels=high) == 9000 + 16384
    assert max_output_tokens_for(ARGON, 16384, Purpose.ARCHITECT, thinking_levels=high) == 32768
    assert max_output_tokens_for(ARGON, 9000, Purpose.REPAIR, 2048, thinking_levels=high) == 9000 - 2048 + 16384
    from shared.hallucination_stack import HallucinationStackSettings, repair_call_max_output_tokens
    with _with_settings(_settings(thinking_levels=high)):
        s = HallucinationStackSettings()
        assert repair_call_max_output_tokens(s, 1000, model=CARBON) == \
            min(32768, repair_call_max_output_tokens(s, 1000) - s.repair_thinking_budget + 16384)


def test_budget_family_never_reads_the_levels():
    weird = {"architect": "HIGH", "developer": "HIGH", "repair": "HIGH", "auxiliary": "HIGH"}
    for model in sorted(m for m, f in MODEL_FAMILIES.items() if f is BUDGET_FAMILY):
        kwargs = {"temperature": 0.2, "max_output_tokens": 65536}
        assert adapt_generate_config_kwargs(model, Purpose.DEVELOPER, kwargs, types=T, thinking_levels=weird) is kwargs
        assert max_output_tokens_for(model, 65536, Purpose.DEVELOPER, thinking_levels=weird) == 65536
        assert thinking_config_for(model, 2048, Purpose.REPAIR, types=T, thinking_levels=weird).kw == \
            {"thinking_budget": 2048}


# ================================================================================================ Do No Harm
def _all_calls(model):
    out = {}
    for p in Purpose:
        kwargs = {"system_instruction": "S", "temperature": 0.2, "max_output_tokens": 65536,
                  "thinking_config": _FakeThinkingConfig(thinking_budget=2048)}
        a = adapt_generate_config_kwargs(model, p, kwargs, types=T)
        tc = thinking_config_for(model, 2048, p, types=T)
        out[p.value] = (a is kwargs, {k: (v.kw if isinstance(v, _FakeThinkingConfig) else v) for k, v in a.items()},
                        tc.kw if tc is not None else None, max_output_tokens_for(model, 16384, p, 2048))
    return out


@pytest.mark.parametrize("model", sorted(MODEL_FAMILIES))
def test_default_settings_give_the_same_request_as_no_settings(model):
    """With the default settings (what a fresh install and the eval harness pin) every built-in model's request is the
    one the built-in rules alone give; non-default custom families never change a built-in model's family."""
    with patch.object(gmc, "_stored_models_section", lambda: None):
        before = _all_calls(model)
    with _with_settings(S.PlatformSettings()):
        assert _all_calls(model) == before
    with _with_settings(_settings(custom_families={model: "LEVEL" if MODEL_FAMILIES[model] is BUDGET_FAMILY
                                                    else "BUDGET"})):
        assert _all_calls(model) == before


def test_level_table_models_default_to_argon_levels_without_settings():
    with patch.object(gmc, "_stored_models_section", lambda: None):
        for p, level in ARGON_THINKING_LEVEL.items():
            assert thinking_config_for(CARBON, None, p, types=T).kw == {"thinking_level": level}


@pytest.mark.skipif(not gmc.sdk_supports_thinking_level(__import__("google.genai.types", fromlist=["x"])),
                    reason="installed google-genai lacks thinking_level")
def test_eval_path_pinned_defaults_keep_the_argon_call_site_configs():
    """The eval harness pins PlatformSettings() (eval/stackvend_eval/stages.py pin_settings): the request configs (the
    cassette request hash inputs) equal those of the built-in rules alone, so replay keys do not move."""
    with _with_settings(S.PlatformSettings()):
        pinned = cap.capture(ARGON)
    with patch.object(gmc, "_stored_models_section", lambda: None):
        builtin = cap.capture(ARGON)
    assert pinned == builtin
    assert json.loads(pinned["swarm._call_gemini_with_backoff"])["thinking_config"] == {"thinking_level": "MEDIUM"}


def test_eval_harness_pins_the_settings_defaults():
    src = open(os.path.join(REPO_ROOT, "eval", "stackvend_eval", "stages.py"), encoding="utf-8").read()
    assert "base = S.PlatformSettings()" in src and "rebind(S.get_platform_settings, get_platform_settings)" in src


# ================================================================================================ prices
def test_unknown_price_is_typed_never_zero():
    from shared import token_accounting as ta
    with pytest.raises(ta.UnknownModelPrice) as ei:
        ta.model_pricing(LEVEL_ID, date(2026, 11, 10))
    assert ei.value.code == "UNKNOWN_MODEL_PRICE"
    assert ta.calculate_token_cost(LEVEL_ID, 1000, 1000) is None
    resp = SimpleNamespace(usage_metadata=SimpleNamespace(prompt_token_count=10, candidates_token_count=5,
                                                          total_token_count=15))
    rec = ta.extract_token_usage(resp, model_name=LEVEL_ID)
    assert rec.cost_usd is None and rec.cost_status == "UNKNOWN_MODEL_PRICE" and rec.total_tokens == 15
    priced = ta.extract_token_usage(resp, model_name="gemini-3.8-flash")
    assert priced.cost_status == "PRICED" and priced.cost_usd == ta.calculate_token_cost("gemini-3.8-flash", 10, 5)


def test_built_in_models_keep_their_prices():
    from shared import token_accounting as ta
    d = date(2026, 11, 10)
    for model in MODEL_FAMILIES:   # a built-in model without its own row keeps the default row, as before
        assert ta.model_pricing(model, d) == ta.MODEL_PRICING.get(model, ta.MODEL_PRICING["default"]), model
    assert ta.model_pricing("default", d) == ta.MODEL_PRICING["default"]


def test_record_agent_tokens_records_an_unknown_price_as_unknown():
    from google.cloud import firestore

    from shared import token_accounting as ta
    db = MagicMock()
    rec = ta.AgentTokenRecord(prompt_tokens=10, candidates_tokens=5, total_tokens=15, cost_usd=None,
                              cost_status="UNKNOWN_MODEL_PRICE", model=LEVEL_ID)
    assert ta.record_agent_tokens(db, "tr-1", "architect", rec) is True
    (payload,), _ = db.collection.return_value.document.return_value.update.call_args
    assert "token_usage.total_cost_usd" not in payload and "token_usage.by_agent.architect.cost_usd" not in payload
    assert isinstance(payload["token_usage.unpriced_models"], type(firestore.ArrayUnion([LEVEL_ID])))
    assert payload["token_usage.by_agent.architect.cost_status"] == "UNKNOWN_MODEL_PRICE"
    db2 = MagicMock()
    ta.record_agent_tokens(db2, "tr-1", "architect", ta.AgentTokenRecord(total_tokens=15, cost_usd=0.5))
    (payload2,), _ = db2.collection.return_value.document.return_value.update.call_args
    assert "token_usage.unpriced_models" not in payload2 and "token_usage.total_cost_usd" in payload2


# ================================================================================================ the save check
class _FakeModels:
    def __init__(self, behaviour):
        self.behaviour, self.calls, self.lock = behaviour, [], threading.Lock()

    def generate_content(self, *, model, contents, config):
        with self.lock:
            self.calls.append({"model": model, "config": config})
        return self.behaviour(model, config)


class _FakeClient:
    def __init__(self, behaviour=lambda m, c: SimpleNamespace(text="OK")):
        self.models = _FakeModels(behaviour)


def _api_error(message, code=400, status="INVALID_ARGUMENT"):
    from google.genai import errors
    return errors.ClientError(code, {"error": {"code": code, "message": message, "status": status}})


def _level_only(model, config):
    if config.thinking_config is not None and config.thinking_config.thinking_budget is not None:
        raise _api_error("Thinking budget is not supported for this model. Use thinking level instead.")
    return SimpleNamespace(text="OK")


def _budget_only(model, config):
    if config.thinking_config is not None and config.thinking_config.thinking_level is not None:
        raise _api_error("Thinking level is not supported for this model.")
    return SimpleNamespace(text="OK")


@pytest.fixture
def cc(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    monkeypatch.setattr(cc_db, "_db_client", False)
    from routes import settings as rs
    from settings_write_fake import wire_settings_writes
    from test_fd4ak_settings_fail_closed import _store
    cc_store, doc_ref = MagicMock(), MagicMock()
    cc_store.collection.return_value.document.return_value = doc_ref
    monkeypatch.setattr(rs, "db", cc_store)
    wire_settings_writes(cc_store, doc_ref)
    request = MagicMock()
    request.state.user_role = rs.UserRole.ADMIN
    request.state.user_email = "admin@example.com"
    S.invalidate_settings_cache()
    client = _FakeClient()
    monkeypatch.setattr(rs, "model_check_client_factory", lambda timeout: client)
    ns = SimpleNamespace(rs=rs, doc_ref=doc_ref, request=request, client=client,
                         store=lambda data: _store(monkeypatch, data))
    yield ns
    S.invalidate_settings_cache()


def _body(stored, **models):
    doc = S.PlatformSettings(**copy.deepcopy(stored)).model_dump(mode="json")
    doc["models"].update(models)
    return doc


def _stored_doc(cc):
    (stored,), kwargs = cc.doc_ref.set.call_args
    return stored


# The stored models are explicit (Flash): the save tests below change one field away from them, whatever the code
# defaults are (DEFAULT-MODEL-GEMINI-4-CARBON made every default gemini-4-carbon / gemini-4-argon).
_FLASH = "gemini-3.8-flash"
STORED = {"version": 3, "models": {"architect_model": _FLASH, "developer_model": _FLASH, "finops_model": _FLASH,
                                   "assistant_model": _FLASH, "fallback_models": ["gemini-3.7-flash"]}}


def test_save_accepted_after_one_call_with_the_roles_request(cc):
    cc.store(copy.deepcopy(STORED))
    out = cc.rs.update_settings_api(_body(STORED, assistant_model=CARBON), cc.request)
    assert out.models.assistant_model == CARBON and _stored_doc(cc)["models"]["assistant_model"] == CARBON
    (call,) = cc.client.models.calls
    cfg = call["config"]
    assert call["model"] == CARBON and cfg.thinking_config.thinking_level.value == "LOW"
    assert cfg.thinking_config.thinking_budget is None and cfg.temperature is None
    assert cfg.max_output_tokens <= 256


def test_save_refused_with_googles_message_and_nothing_stored(cc, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSECRET-KEY-VALUE-123")
    cc.store(copy.deepcopy(STORED))
    cc.client.models.behaviour = lambda m, c: (_ for _ in ()).throw(
        _api_error("Publisher model was not found (key AIzaSECRET-KEY-VALUE-123)", 404, "NOT_FOUND"))
    with pytest.raises(Exception) as ei:
        cc.rs.update_settings_api(_body(STORED, architect_model=ARGON), cc.request)
    assert ei.value.status_code == 422
    d = ei.value.detail
    assert d["code"] == "MODEL_CHECK_FAILED" and "Publisher model was not found" in d["message"]
    assert "AIzaSECRET" not in json.dumps(d) and d["errors"][0]["loc"] == ["models", "architect_model"]
    cc.doc_ref.set.assert_not_called()


def test_save_timeout_is_a_typed_failure_not_a_pass(cc, monkeypatch):
    from services import model_check as mc
    monkeypatch.setattr(mc, "CHECK_TIMEOUT_SECONDS", 0.2)
    release = threading.Event()
    cc.client.models.behaviour = lambda m, c: (release.wait(5), SimpleNamespace(text="OK"))[1]
    cc.store(copy.deepcopy(STORED))
    try:
        with pytest.raises(Exception) as ei:
            cc.rs.update_settings_api(_body(STORED, developer_model=CARBON), cc.request)
    finally:
        release.set()
    assert ei.value.status_code == 422 and ei.value.detail["code"] == "MODEL_CHECK_TIMEOUT"
    cc.doc_ref.set.assert_not_called()


def test_level_only_custom_model_is_stored_with_the_level_style(cc):
    cc.store(copy.deepcopy(STORED))
    cc.client.models.behaviour = _level_only
    out = cc.rs.update_settings_api(_body(STORED, architect_model=LEVEL_ID), cc.request)
    assert out.models.custom_families == {LEVEL_ID: "LEVEL"}
    stored = _stored_doc(cc)
    assert stored["models"]["architect_model"] == LEVEL_ID and stored["models"]["custom_families"] == {LEVEL_ID: "LEVEL"}
    budget_call, level_call = cc.client.models.calls
    assert budget_call["config"].thinking_config.thinking_budget == 128 and budget_call["config"].temperature == 0.2
    assert level_call["config"].thinking_config.thinking_level.value == "MEDIUM"   # RT F6: the developer probe
    assert level_call["config"].temperature is None


def test_budget_only_custom_model_is_stored_with_the_budget_style(cc):
    cc.store(copy.deepcopy(STORED))
    cc.client.models.behaviour = _budget_only
    out = cc.rs.update_settings_api(_body(STORED, developer_model=BUDGET_ID), cc.request)
    assert out.models.custom_families == {BUDGET_ID: "BUDGET"} and len(cc.client.models.calls) == 1


def test_custom_model_refused_in_both_styles_reports_both(cc):
    cc.store(copy.deepcopy(STORED))
    cc.client.models.behaviour = lambda m, c: (_ for _ in ()).throw(_api_error("Model not found", 404, "NOT_FOUND"))
    with pytest.raises(Exception) as ei:
        cc.rs.update_settings_api(_body(STORED, developer_model=BUDGET_ID), cc.request)
    msg = ei.value.detail["errors"][0]["msg"]
    assert "budget style" in msg and "level style" in msg and len(cc.client.models.calls) == 2
    cc.doc_ref.set.assert_not_called()


def test_unchanged_fields_are_not_checked(cc):
    stored = {"version": 5, "models": {"architect_model": LEVEL_ID, "custom_families": {LEVEL_ID: "LEVEL"},
                                       "fallback_models": ["gemini-3.7-flash"]}}
    cc.store(copy.deepcopy(stored))
    body = _body(stored)
    body["finops"]["default_monthly_budget_usd"] = 77.0
    body["models"]["custom_families"] = {}                     # a client's value is not trusted, nor needed
    out = cc.rs.update_settings_api(body, cc.request)
    assert cc.client.models.calls == []
    assert out.models.custom_families == {LEVEL_ID: "LEVEL"} and out.finops.default_monthly_budget_usd == 77.0


def test_client_cannot_set_a_style_without_the_check(cc):
    stored = {"version": 5, "models": {"architect_model": LEVEL_ID, "custom_families": {LEVEL_ID: "LEVEL"}}}
    cc.store(copy.deepcopy(stored))
    body = _body(stored)
    body["models"]["custom_families"] = {LEVEL_ID: "BUDGET", "acme-unused": "LEVEL"}
    out = cc.rs.update_settings_api(body, cc.request)
    assert out.models.custom_families == {LEVEL_ID: "LEVEL"} and cc.client.models.calls == []


def test_a_changed_level_rechecks_that_roles_level_models_only(cc):
    stored = {"version": 5, "models": {"architect_model": ARGON, "developer_model": "gemini-3.8-flash",
                                       "repair_model": CARBON, "fallback_models": ["gemini-3.7-flash"]}}
    cc.store(copy.deepcopy(stored))
    body = _body(stored)
    body["models"]["thinking_levels"] = {**DEFAULT_THINKING_LEVELS, "architect": "HIGH", "developer": "HIGH"}
    out = cc.rs.update_settings_api(body, cc.request)
    assert out.models.thinking_levels["architect"] == "HIGH"
    (call,) = cc.client.models.calls                  # Argon (architect); Flash developer and Carbon repair: no call
    assert call["model"] == ARGON and call["config"].thinking_config.thinking_level.value == "HIGH"


def test_invalid_thinking_level_is_refused_at_save(cc):
    from fastapi.exceptions import RequestValidationError
    cc.store(copy.deepcopy(STORED))
    body = _body(STORED)
    body["models"]["thinking_levels"] = {"architect": "MINIMAL"}
    with pytest.raises(RequestValidationError) as ei:
        cc.rs.update_settings_api(body, cc.request)
    assert ei.value.errors()[0]["loc"][0] == "body"
    assert cc.client.models.calls == [] and not cc.doc_ref.set.called


def test_new_fallback_entries_are_checked_old_ones_not(cc):
    stored = {"version": 5, "models": {"fallback_models": ["gemini-3.7-flash"]}}
    cc.store(copy.deepcopy(stored))
    cc.rs.update_settings_api(_body(stored, fallback_models=["gemini-3.7-flash", CARBON]), cc.request)
    assert [c["model"] for c in cc.client.models.calls] == [CARBON]


def test_no_client_is_a_typed_refusal(cc, monkeypatch):
    def broken(timeout):
        raise RuntimeError("no credentials")
    monkeypatch.setattr(cc.rs, "model_check_client_factory", broken)
    cc.store(copy.deepcopy(STORED))
    with pytest.raises(Exception) as ei:
        cc.rs.update_settings_api(_body(STORED, architect_model=CARBON), cc.request)
    assert ei.value.status_code == 422 and ei.value.detail["code"] == "MODEL_CHECK_UNAVAILABLE"


def test_default_client_is_the_agents_client(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    from services import model_check as mc
    made = []
    monkeypatch.setattr("google.genai.Client", lambda **kw: made.append(kw) or SimpleNamespace())
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("PROJECT_ID", "p-1")
    monkeypatch.setenv("GEMINI_LOCATION", "global")
    mc.default_client_factory(20.0)
    assert made[-1]["vertexai"] is True and made[-1]["project"] == "p-1" and made[-1]["location"] == "global"
    assert made[-1]["http_options"].timeout == 20000
    monkeypatch.setenv("GEMINI_API_KEY", "k" * 20)
    mc.default_client_factory(20.0)
    assert made[-1]["api_key"] == "k" * 20


# ================================================================================================ FD-7Z page
def _html():
    return open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()


def test_save_toast_reads_every_error_shape_and_reverts_refused_fields():
    html = _html()
    fn = html.split("async savePlatformSettings() {", 1)[1].split("async resetPlatformSettings()", 1)[0]
    assert "this.apiErrorText(d," in fn and "this.revertRefusedSettingsFields(d)" in fn
    assert "this.rememberSavedSettings();" in fn
    assert "${d.code}: ${d.message}` : (d ||" not in fn      # the old toast showed a list detail as [object Object]
    helper = html.split("revertRefusedSettingsFields(d) {", 1)[1].split("apiErrorText(d, fallback) {", 1)[0]
    assert "loc[0] === 'body'" in helper and "d.errors" in helper and "platformSettingsSaved" in helper
    load = html.split("async fetchPlatformSettings(force = false) {", 1)[1].split("async savePlatformSettings()", 1)[0]
    assert "this.rememberSavedSettings();" in load


def test_settings_page_has_the_four_thinking_level_selects():
    html = _html()
    assert 'x-model="platformSettings.models.thinking_levels[role[0]]"' in html
    block = html.split('x-model="platformSettings.models.thinking_levels[role[0]]"', 1)[1][:3000]
    for role in ("'architect'", "'developer'", "'repair'", "'auxiliary'"):
        assert role in html.split('x-model="platformSettings.models.thinking_levels[role[0]]"', 1)[0][-1500:]
    assert '<option value="HIGH">' in block and "MINIMAL" not in block
    assert "Gemini 3.x models use the Thinking Budget field" in block and "$20 per 1M" in block


def test_unknown_cost_is_shown_as_unknown():
    html = _html()
    assert "(cost unknown)" in html and "unpriced_models" in html


# ================================================================================================ copies
@pytest.mark.parametrize("name,count", [("settings.py", 7), ("gemini_model_config.py", 7), ("token_accounting.py", 5)])
def test_every_copy_is_byte_identical(name, count):
    import glob
    canonical = open(os.path.join(REPO_ROOT, "shared", name), "rb").read()
    copies = sorted(glob.glob(os.path.join(REPO_ROOT, "apps", "*", "shared", name))
                    + glob.glob(os.path.join(REPO_ROOT, "mcp-servers", "*", "shared", name)))
    assert len(copies) == count, copies
    for path in copies:
        assert open(path, "rb").read() == canonical, path


# ================================================================================================ review hardening
# docs/implemented/open-model-settings-rt.md findings F1-F7.

def test_rt_f1_custom_fallback_ids_with_legacy_substrings_survive_save_and_load(cc):
    """F1: the fallback purge compares exact retired ids; `acme-2.5-turbo` / `acme-3.8-pro-x` are legal custom ids."""
    stored = {"version": 5, "models": {"fallback_models": ["gemini-3.7-flash"]}}
    cc.store(copy.deepcopy(stored))
    cc.client.models.behaviour = _level_only
    ids = ["acme-2.5-turbo", "acme-3.8-pro-x"]
    out = cc.rs.update_settings_api(_body(stored, fallback_models=["gemini-3.7-flash"] + ids), cc.request)
    assert out.models.fallback_models == ["gemini-3.7-flash"] + ids
    assert out.models.custom_families == {i: "LEVEL" for i in ids}
    doc = _stored_doc(cc)
    assert S.platform_settings_from_stored(copy.deepcopy(doc)).models.fallback_models == ["gemini-3.7-flash"] + ids
    assert S.PlatformSettings(**copy.deepcopy(doc)).models.fallback_models == ["gemini-3.7-flash"] + ids


def test_rt_f1_retired_fallback_ids_are_still_purged_exactly():
    for legacy in ("gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.5-pro", "gemini-3.8-pro",
                   "gemini-2.5-flash-001", "publishers/google/models/gemini-2.5-pro"):
        ps = S.PlatformSettings(models={"fallback_models": [legacy, "gemini-3.7-flash"]})
        assert ps.models.fallback_models == ["gemini-3.7-flash"], legacy
    # nothing left: the default fallback list (DEFAULT-MODEL-GEMINI-4-CARBON: DEFAULT-FALLBACK-CHAIN: argon, 3.8-flash, 3.7-flash)
    assert S.PlatformSettings(models={"fallback_models": ["gemini-2.5-pro"]}).models.fallback_models == \
        ["gemini-4-argon", "gemini-3.8-flash", "gemini-3.7-flash"]
    src = open(S.__file__, encoding="utf-8").read()
    assert '"2.5" not in m' not in src and '"3.8-pro" not in m' not in src


def test_rt_f2_too_many_fallbacks_is_refused_before_any_call(cc):
    from services import model_check as mc
    cc.store(copy.deepcopy(STORED))
    five = ["gemini-3.7-flash", ARGON, CARBON, "gemini-2.0-flash", "gemini-1.5-pro"]
    assert len(five) == mc.MAX_FALLBACK_MODELS + 1
    with pytest.raises(Exception) as ei:
        cc.rs.update_settings_api(_body(STORED, fallback_models=five), cc.request)
    assert ei.value.status_code == 422 and ei.value.detail["code"] == "FALLBACK_MODELS_TOO_MANY"
    assert cc.client.models.calls == [] and not cc.doc_ref.set.called


def test_rt_f2_check_count_and_worker_caps(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    from services import model_check as mc
    many = [mc._Check(model=f"acme-{i}", purpose=Purpose.DEVELOPER, fields=["fallback_models"])
            for i in range(mc.MAX_CHECKS_PER_SAVE + 1)]
    made = []
    with pytest.raises(mc.ModelCheckError) as ei:
        mc.run_checks(many, thinking_levels={}, client_factory=lambda t: made.append(t) or _FakeClient())
    assert ei.value.code == "MODEL_CHECK_TOO_MANY" and made == []          # refused before a client is built
    seen = []
    real_pool = mc.ThreadPoolExecutor

    def pool(max_workers, **kw):
        seen.append(max_workers)
        return real_pool(max_workers=max_workers, **kw)
    monkeypatch.setattr(mc, "ThreadPoolExecutor", pool)
    ok = [mc._Check(model=CARBON, purpose=p, style="LEVEL", fields=["architect_model"]) for p in Purpose]
    ok += [mc._Check(model=f"gemini-3.{i}-flash", purpose=Purpose.DEVELOPER, style="BUDGET",
                     fields=["fallback_models"]) for i in range(6)]
    assert len(ok) == 10
    mc.run_checks(ok, thinking_levels={}, client_factory=lambda t: _FakeClient())
    assert seen == [mc.MAX_WORKERS] and mc.MAX_WORKERS == 8


def test_rt_f3_custom_id_is_reprobed_when_a_field_naming_it_changes(cc, caplog):
    stored = {"version": 5, "models": {"architect_model": BUDGET_ID, "custom_families": {BUDGET_ID: "BUDGET"}}}
    cc.store(copy.deepcopy(stored))
    cc.client.models.behaviour = _level_only                 # the model now refuses a budget
    out = cc.rs.update_settings_api(_body(stored, developer_model=BUDGET_ID), cc.request)
    assert out.models.custom_families == {BUDGET_ID: "LEVEL"}  # re-probed, style refreshed for every field
    assert len(cc.client.models.calls) == 2


def test_rt_f3_budget_style_is_logged_and_shown(cc, caplog):
    cc.store(copy.deepcopy(STORED))
    cc.client.models.behaviour = _budget_only
    with caplog.at_level("WARNING"):
        cc.rs.update_settings_api(_body(STORED, developer_model=BUDGET_ID), cc.request)
    assert "request style BUDGET" in caplog.text and "thinking levels do not apply" in caplog.text
    html = _html()
    assert "Detected request styles (read-only)" in html
    assert 'x-for="(style, mid) in (platformSettings.models.custom_families || {})"' in html


def test_rt_f5_cap_binding_is_logged_once_with_the_numbers(caplog):
    gmc._warned_capped.clear()
    high = {"architect": "HIGH"}
    with caplog.at_level("WARNING"):
        assert max_output_tokens_for(ARGON, 32768, Purpose.ARCHITECT, thinking_levels=high) == 32768
        assert max_output_tokens_for(ARGON, 32768, Purpose.ARCHITECT, thinking_levels=high) == 32768
    lines = [r.getMessage() for r in caplog.records if "capped at 32768" in r.getMessage()]
    assert len(lines) == 1 and "16384" in lines[0] and "HIGH" in lines[0] and "32768 asked" in lines[0]
    caplog.clear()
    with caplog.at_level("WARNING"):
        assert max_output_tokens_for(ARGON, 9000, Purpose.ARCHITECT, thinking_levels=high) == 9000 + 16384
    assert "capped" not in caplog.text                       # no log when the cap does not bind


def test_rt_f6_new_custom_id_is_probed_with_the_purpose_it_is_keyed_under(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    from services import model_check as mc
    old = S.AgentModelSettings()
    new = S.AgentModelSettings(custom_families={LEVEL_ID: "LEVEL"}, architect_model=LEVEL_ID, repair_model=LEVEL_ID)
    (chk,) = mc.plan_checks(old, new, {})
    assert chk.purpose is mc.PROBE_PURPOSE is Purpose.DEVELOPER and chk.style is None
    assert chk.fields == ["architect_model", "repair_model"]


def test_rt_f7_finops_model_and_its_rules_come_from_one_strict_read(monkeypatch, caplog):
    finops_dir = os.path.join(REPO_ROOT, "apps", "finops-enforcer")
    if finops_dir not in sys.path:
        monkeypatch.syspath_prepend(finops_dir)
    import finops_advisor as adv
    ps = _settings(finops_model=LEVEL_ID, custom_families={LEVEL_ID: "LEVEL"}, thinking_levels={"auxiliary": "HIGH"})
    reads = []

    def read(**kw):
        reads.append(kw)
        return ps
    rules = adv.finops_model_rules("p", read)
    assert rules["model"] == LEVEL_ID and rules["custom_families"] == {LEVEL_ID: "LEVEL"} and len(reads) == 1
    assert reads[0]["strict"] is True
    cfg = adv.generation_config(rules["model"], rules["custom_families"], rules["thinking_levels"])
    assert cfg["thinkingConfig"] == {"thinkingLevel": "HIGH"} and "temperature" not in cfg

    def broken(**kw):
        raise RuntimeError("firestore blip")
    monkeypatch.delenv("GEMINI_MODEL", raising=False)   # RT D2: with GEMINI_MODEL set, that model would be used
    with caplog.at_level("ERROR"):
        rules = adv.finops_model_rules("p", broken)
    assert rules["model"] == S.AgentModelSettings().finops_model
    assert "firestore blip" in caplog.text and "default model" in caplog.text
