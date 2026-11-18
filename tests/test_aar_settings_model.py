"""AAR-SETTINGS-MODEL (owner 11-11 "yes to all three"; register row DEFAULT-MODEL-GEMINI-4-CARBON).

The After-Action Report used to call the retired gemini-2.5-flash / gemini-2.0-flash. It is now written by the
Control Center Assistant Model's cascade (models.assistant_model + models.fallback_models), each request built by its
own model family's rules, through the Settings live check's client. No model answering is a typed AARModelFailure,
stored with the deterministic report. Fake clients only: no network, no LLM, no Firestore."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "control-center")))

from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; row SWARM-TOK-1)

CARBON = "gemini-4-carbon"
ARGON = "gemini-4-argon"
FLASH = "gemini-3.8-flash"
# DEFAULT-FALLBACK-CHAIN (owner 11-13): the new-install fallback list (was [ARGON])
DEFAULT_FALLBACKS = [ARGON, FLASH, "gemini-3.7-flash"]
TELEMETRY = os.path.join(os.path.dirname(__file__), "..", "apps", "control-center", "routes", "telemetry.py")
REPORT = {"executive_summary": "Deployed.", "root_cause": None, "blast_radius": None, "remediation": None}


@pytest.fixture(autouse=True)
def cc_env(monkeypatch):
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    monkeypatch.setattr(cc_db, "_db_client", False)   # importing the routes must not build a real client


@pytest.fixture
def tel():
    from routes import telemetry
    return telemetry


class _Client:
    """generate_content records each call; `answers` maps a model id to its text, or to an exception to raise."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []
        self.models = self

    def generate_content(self, *, model, contents, config):
        self.calls.append({"model": model, "contents": contents, "config": config})
        a = self.answers.get(model, RuntimeError("404 NOT_FOUND"))
        if isinstance(a, BaseException):
            raise a
        return SimpleNamespace(text=a)


def _factory(client, seen=None):
    def make(timeout_seconds):
        if seen is not None:
            seen.append(timeout_seconds)
        return client
    return make


_needs_level = pytest.mark.skipif(
    not importlib.import_module("shared.gemini_model_config").sdk_supports_thinking_level(
        __import__("google.genai.types", fromlist=["x"])), reason="installed google-genai lacks thinking_level")


def test_role_is_the_control_center_assistant(tel):
    assert tel.AAR_MODEL_ROLE == "assistant"
    assert tel._aar_model_cascade() == [CARBON, *DEFAULT_FALLBACKS]          # settings defaults
    S = importlib.import_module("shared.settings")
    ps = S.PlatformSettings(models={"assistant_model": FLASH, "architect_model": ARGON,
                                    "fallback_models": ["gemini-3.7-flash"]})
    with patch.object(S, "get_platform_settings", return_value=ps):
        assert tel._aar_model_cascade() == [FLASH, "gemini-3.7-flash"]


@_needs_level
def test_carbon_fails_argon_writes_the_report_each_with_its_own_rules(tel):
    client = _Client({CARBON: RuntimeError("429 RESOURCE_EXHAUSTED"), ARGON: "```json\n" + json.dumps(REPORT) + "\n```"})
    seen = []
    data, model = tel.aar_model_report("PROMPT", client_factory=_factory(client, seen))
    assert model == ARGON and data == {"executive_summary": "Deployed.", "root_cause": None, "blast_radius": None,
                                       "remediation": None}
    assert seen == [tel.AAR_MODEL_TIMEOUT_SECONDS]
    assert [c["model"] for c in client.calls] == [CARBON, ARGON]
    for c in client.calls:
        cfg = c["config"]
        assert cfg.thinking_config.thinking_level.value == "LOW" and cfg.thinking_config.thinking_budget is None
        assert cfg.temperature is None and cfg.response_mime_type == "application/json"
        assert c["contents"] == "PROMPT"


def test_a_gemini_3_model_keeps_its_request_unchanged(tel):
    client = _Client({FLASH: json.dumps(REPORT)})
    data, model = tel.aar_model_report("PROMPT", client_factory=_factory(client), cascade=[FLASH])
    cfg = client.calls[0]["config"]
    assert model == FLASH and cfg.temperature == 0.2 and cfg.thinking_config is None


def test_invalid_json_counts_as_a_failed_model(tel):
    client = _Client({CARBON: "not json", ARGON: json.dumps(["a", "list"])})
    with pytest.raises(tel.AARModelFailure) as ei:
        tel.aar_model_report("PROMPT", client_factory=_factory(client))
    assert ei.value.code == tel.AAR_MODEL_CALL_FAILED
    assert [f["model"] for f in ei.value.failures] == [CARBON, *DEFAULT_FALLBACKS]
    assert "JSONDecodeError" in ei.value.failures[0]["error"] and "not an object" in ei.value.failures[1]["error"]


def test_no_client_is_a_typed_unavailable_without_a_call(tel):
    def no_client(timeout_seconds):
        raise RuntimeError("no PROJECT_ID and no GEMINI_API_KEY")
    with pytest.raises(tel.AARModelFailure) as ei:
        tel.aar_model_report("PROMPT", client_factory=no_client)
    assert ei.value.code == tel.AAR_MODEL_UNAVAILABLE and "no PROJECT_ID" in ei.value.failures[0]["error"]


def test_api_key_never_appears_in_the_failure(tel, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSECRET-KEY-VALUE-123")
    client = _Client({CARBON: RuntimeError("denied for key AIzaSECRET-KEY-VALUE-123"), ARGON: RuntimeError("x")})
    with pytest.raises(tel.AARModelFailure) as ei:
        tel.aar_model_report("PROMPT", client_factory=_factory(client))
    assert "AIzaSECRET" not in json.dumps(ei.value.as_record())


def _synth(tel, status="SUCCEEDED"):
    return tel.synthesize_after_action_report(
        trace_id="t1", product_id="shop", status=status, harvested_interventions=[], error_message=None,
        stages_dict={"terraform": {"status": "SUCCESS"}}, outputs_dict={"service_url": "https://shop.run.app"},
        cloud_logs=[])


def test_report_names_the_model_that_wrote_it(tel):
    from services import model_check
    client = _Client({CARBON: json.dumps(REPORT)})
    with patch.object(model_check, "default_client_factory", _factory(client)):
        aar = _synth(tel)
    assert aar.model_used == CARBON and aar.model_failure is None and aar.executive_summary == "Deployed."


def test_all_models_failed_is_typed_on_the_deterministic_report(tel, caplog):
    from services import model_check
    client = _Client({CARBON: RuntimeError("500 INTERNAL"), ARGON: RuntimeError("503 UNAVAILABLE")})
    with patch.object(model_check, "default_client_factory", _factory(client)), caplog.at_level("ERROR"):
        aar = _synth(tel)
    assert aar.model_used == tel.AAR_DETERMINISTIC_ENGINE
    assert aar.model_failure["code"] == tel.AAR_MODEL_CALL_FAILED
    assert [m["model"] for m in aar.model_failure["models"]] == [CARBON, *DEFAULT_FALLBACKS]
    assert "deployed (no health probe ran)" in aar.executive_summary    # recorded facts only
    assert tel.AAR_MODEL_CALL_FAILED in caplog.text
    assert json.loads(aar.model_dump_json())["model_failure"]["code"] == tel.AAR_MODEL_CALL_FAILED


def test_a_cached_report_without_the_new_field_still_loads():
    from schemas import AfterActionReport
    old = {"trace_id": "t", "product_id": "p", "status": "SUCCEEDED", "outcome_type": "SUCCESS_CLEAN",
           "executive_summary": "x", "generated_at": "2026-11-01T00:00:00+00:00", "model_used": "gemini-flash"}
    assert AfterActionReport(**old).model_failure is None


def test_no_retired_model_id_is_called():
    tree = ast.parse(open(TELEMETRY, encoding="utf-8").read())
    literals = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert not {"gemini-2.5-flash", "gemini-2.0-flash", "gemini-flash"} & literals
    assert "_call_gemini_inference" not in open(TELEMETRY, encoding="utf-8").read()


# ------------------------------------------------------------------------------------------------ RT D1: schema check
BAD_ANSWERS = [
    ({"root_cause": "disk full"}, "root_cause is a str"),
    ({"executive_summary": ["a"]}, "executive_summary is a list"),
    ({}, "no report content"),
    ({"executive_summary": "  ", "root_cause": None}, "no report content"),
    ({"executive_summary": "x", "blast_radius": {"provisioned_resources": "not-a-list"}}, "provisioned_resources"),
]


@pytest.mark.parametrize("answer,why", BAD_ANSWERS,
                         ids=["str-root-cause", "list-summary", "empty", "blank", "bad-field"])
def test_a_malformed_answer_fails_that_model_and_the_next_is_tried(tel, answer, why):
    good = {"executive_summary": "Stopped at terraform.", "root_cause": {"failing_component": "main.tf"},
            "remediation": {"recommended_mode": "ARCHITECT_AND_DEV"}}
    client = _Client({CARBON: json.dumps(answer), ARGON: json.dumps(good)})
    data, model = tel.aar_model_report("PROMPT", client_factory=_factory(client))
    assert model == ARGON and [c["model"] for c in client.calls] == [CARBON, ARGON]
    assert data["root_cause"].failing_component == "main.tf" and data["remediation"].recommended_mode == "FULL"
    client = _Client({CARBON: json.dumps(answer), ARGON: json.dumps(answer)})
    with pytest.raises(tel.AARModelFailure) as ei:
        tel.aar_model_report("PROMPT", client_factory=_factory(client))
    assert ei.value.code == tel.AAR_MODEL_CALL_FAILED and why in ei.value.failures[0]["error"]


@pytest.mark.parametrize("answer", [a for a, _ in BAD_ANSWERS])
def test_all_malformed_answers_give_the_labelled_deterministic_report(tel, answer):
    from services import model_check
    client = _Client({CARBON: json.dumps(answer), ARGON: json.dumps(answer)})
    with patch.object(model_check, "default_client_factory", _factory(client)):
        aar = tel.synthesize_after_action_report(
            trace_id="t1", product_id="shop", status="FAILED", harvested_interventions=[], error_message="boom",
            stages_dict={"terraform": {"status": "FAILED"}}, outputs_dict={}, cloud_logs=[], failed_stage="terraform")
    assert aar.model_used == tel.AAR_DETERMINISTIC_ENGINE
    assert aar.model_failure["code"] == tel.AAR_MODEL_CALL_FAILED
    assert [m["model"] for m in aar.model_failure["models"]] == [CARBON, *DEFAULT_FALLBACKS]


def test_a_valid_failure_answer_builds_the_report_sections(tel):
    from services import model_check
    good = {"executive_summary": "Apply failed.", "root_cause": {"failing_component": "main.tf",
                                                                 "failure_class": "IAM_PERMISSION_DENIED"},
            "blast_radius": {"provisioned_resources": ["bucket"], "failed_resource": "run"},
            "remediation": {"recommended_mode": "DEPLOY_ONLY", "immediate_action": "grant the role"}}
    client = _Client({CARBON: json.dumps(good)})
    with patch.object(model_check, "default_client_factory", _factory(client)):
        aar = tel.synthesize_after_action_report(
            trace_id="t1", product_id="shop", status="FAILED", harvested_interventions=[], error_message="boom",
            stages_dict={}, outputs_dict={}, cloud_logs=[])
    assert aar.model_used == CARBON and aar.model_failure is None
    assert aar.root_cause.failure_class == "IAM_PERMISSION_DENIED"
    assert aar.blast_radius.provisioned_resources == ["bucket"]
    assert aar.remediation.recommended_mode == "DEPLOY_ONLY"
