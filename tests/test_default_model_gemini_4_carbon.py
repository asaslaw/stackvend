"""DEFAULT-MODEL-GEMINI-4-CARBON (owner 11-11: "i want to default stackvend to ... gemini-4-carbon. It is just
superior."; "gemini-4-argon should be the fall back").

Every model role defaults to gemini-4-carbon and the fallback list to ["gemini-4-argon", "gemini-3.8-flash", "gemini-3.7-flash"] (DEFAULT-FALLBACK-CHAIN 11-13) (new installs; stored settings
are used as they are). Covers: the defaults and their single source, the copies, the env fallback path, the settings
model outranking GEMINI_MODEL in the architect/developer agents, the Carbon -> Argon fallback request configs, the
Vertex location rule, pricing, the thinking budget being ignored, and the eval harness keeping its pinned fallback.
Fake clients only: no network, no LLM, no Firestore."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import glob
import importlib
import json
import os
import sys
from datetime import date
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import pytest

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
import argon_flash_capture as cap  # noqa: E402  (puts the gateway on sys.path)
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; row SWARM-TOK-1)

import shared.gemini_model_config as gmc  # noqa: E402
from shared.gemini_model_config import Purpose, ThinkingControl  # noqa: E402

REPO = cap.REPO_ROOT
CARBON = "gemini-4-carbon"
ARGON = "gemini-4-argon"
# DEFAULT-FALLBACK-CHAIN (owner 11-13): the new-install fallback list (was ("gemini-4-argon",))
FALLBACKS = (ARGON, "gemini-3.8-flash", "gemini-3.7-flash")
ROLE_FIELDS = ("architect_model", "developer_model", "finops_model", "assistant_model")


def _chain(primary):
    """The cascade get_model_cascade_for_agent builds on the default fallback list: primary first, deduped."""
    return list(dict.fromkeys([primary, *FALLBACKS]))


def _settings():
    return importlib.import_module("shared.settings")   # the module the product's `from shared.settings` gets


class _FakeThinkingConfig:
    model_fields = {"thinking_budget": None, "thinking_level": None}

    def __init__(self, **kw):
        self.kw = kw


class _FakeTypes:
    ThinkingConfig = _FakeThinkingConfig
    ThinkingLevel = SimpleNamespace(LOW="LOW", MEDIUM="MEDIUM", HIGH="HIGH", MINIMAL="MINIMAL")


# ------------------------------------------------------------------------------------------------ defaults
def test_single_source_of_the_defaults():
    assert gmc.DEFAULT_PRIMARY_MODEL == CARBON
    assert gmc.DEFAULT_FALLBACK_MODELS == FALLBACKS


@pytest.mark.parametrize("field", ROLE_FIELDS)
def test_every_role_defaults_to_carbon(field):
    S = _settings()
    assert getattr(S.AgentModelSettings(), field) == CARBON
    assert getattr(S.PlatformSettings().models, field) == CARBON
    # a stored document without a models section (a new install's first read) takes the defaults
    assert getattr(S.platform_settings_from_stored({"version": 1}).models, field) == CARBON


def test_repair_model_default_is_the_developer_model_and_fallback_is_argon():
    S = _settings()
    m = S.AgentModelSettings()
    assert m.repair_model == "" and m.fallback_models == list(FALLBACKS)
    assert m.thinking_levels == {"architect": "LOW", "developer": "MEDIUM", "repair": "LOW", "auxiliary": "LOW"}


def test_stored_settings_are_used_as_they_are():
    """Existing installs keep their models: nothing is migrated to the new defaults."""
    S = _settings()
    stored = {"version": 7, "models": {f: "gemini-3.8-flash" for f in ROLE_FIELDS}}
    stored["models"]["fallback_models"] = ["gemini-3.7-flash"]
    ps = S.platform_settings_from_stored(json.loads(json.dumps(stored)))
    assert {getattr(ps.models, f) for f in ROLE_FIELDS} == {"gemini-3.8-flash"}
    assert ps.models.fallback_models == ["gemini-3.7-flash"]


def test_default_fallback_chain_new_installs_only():
    """DEFAULT-FALLBACK-CHAIN (owner 11-13): a settings document that never stored fallback_models gets the 3-model
    chain; a stored list (including the 11-11 default ["gemini-4-argon"]) is used exactly as stored."""
    S = _settings()
    assert FALLBACKS == (ARGON, "gemini-3.8-flash", "gemini-3.7-flash")
    for doc in ({"version": 3}, {"version": 3, "models": {"architect_model": CARBON}}):
        assert S.platform_settings_from_stored(json.loads(json.dumps(doc))).models.fallback_models == list(FALLBACKS)
    for stored in ([ARGON], ["gemini-3.7-flash"], [ARGON, "gemini-3.8-flash"], ["gemini-3.8-flash", ARGON]):
        doc = {"version": 3, "models": {"fallback_models": list(stored)}}
        assert S.platform_settings_from_stored(doc).models.fallback_models == stored
    # both Flash ids are built-in budget-family models and are never purged as retired
    for mid in ("gemini-3.8-flash", "gemini-3.7-flash"):
        assert gmc.resolve_model_family(mid, {}) is gmc.BUDGET_FAMILY
        assert gmc.known_model_id(mid) not in S.PURGED_LEGACY_FALLBACK_IDS
    assert S.PlatformSettings(models={"fallback_models": list(FALLBACKS)}).models.fallback_models == list(FALLBACKS)


def test_retired_fallback_purge_is_exact_and_defaults_to_argon():
    S = _settings()
    assert S.PlatformSettings(models={"fallback_models": ["gemini-2.5-pro", "gemini-3.7-flash"]}
                              ).models.fallback_models == ["gemini-3.7-flash"]
    assert S.PlatformSettings(models={"fallback_models": ["gemini-2.5-flash", "gemini-3.8-pro"]}
                              ).models.fallback_models == list(FALLBACKS)


def test_defaults_are_level_family_models_with_their_own_prices():
    from shared.token_accounting import MODEL_PRICING, calculate_token_cost, extract_token_usage, model_pricing
    for mid in (CARBON, ARGON):
        assert gmc.resolve_model_family(mid, {}).thinking is ThinkingControl.LEVEL
        assert mid in MODEL_PRICING                       # its own row, never the "default" row or unknown
    assert model_pricing(CARBON, date(2026, 11, 11)) == {"prompt_per_m": 4.00, "candidates_per_m": 20.00,
                                                         "cached_prompt_per_m": 0.20}
    assert calculate_token_cost(ARGON, 1_000_000, 1_000_000, on=date(2026, 11, 11)) == pytest.approx(12.0)
    assert calculate_token_cost(ARGON, 1_000_000, 1_000_000, on=date(2026, 12, 1)) == pytest.approx(24.0)
    resp = SimpleNamespace(usage_metadata=SimpleNamespace(prompt_token_count=10, candidates_token_count=5,
                                                          total_token_count=15))
    for mid in (CARBON, ARGON):
        rec = extract_token_usage(resp, model_name=mid)
        assert rec.cost_status == "PRICED" and rec.cost_usd is not None and rec.cost_usd > 0


def test_eval_pricing_has_rows_for_the_defaults():
    with open(os.path.join(REPO, "eval", "config", "pricing.json")) as f:
        models = json.load(f)["models"]
    assert CARBON in models and ARGON in models


# ------------------------------------------------------------------------------------------------ copies
def _copies(name):
    return sorted(glob.glob(os.path.join(REPO, "apps", "*", "shared", name))
                  + glob.glob(os.path.join(REPO, "mcp-servers", "*", "shared", name)))


@pytest.mark.parametrize("name,count", [("settings.py", 7), ("gemini_model_config.py", 7),
                                        ("agent_evaluator.py", 3)])
def test_copies_are_byte_identical(name, count):
    with open(os.path.join(REPO, "shared", name), "rb") as f:
        canonical = f.read()
    copies = _copies(name)
    assert len(copies) == count, copies
    for path in copies:
        with open(path, "rb") as f:
            assert f.read() == canonical, f"{os.path.relpath(path, REPO)} drifted from shared/{name}"


# ------------------------------------------------------------------------------------------------ cascades
def test_cascade_defaults(monkeypatch):
    S = _settings()
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    for role in ("architect", "developer", "assistant", "finops"):
        assert S.get_model_cascade_for_agent(role) == _chain(CARBON), role
    # a name with no settings field: GEMINI_MODEL, else the default primary model (the compliance agent no longer
    # asks for this name: it uses the architect role, COMPLIANCE-FOLLOWS-ARCHITECT-MODEL)
    assert S.get_model_cascade_for_agent("compliance") == _chain(CARBON)
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.7-flash")
    assert S.get_model_cascade_for_agent("compliance") == _chain("gemini-3.7-flash")
    assert S.get_model_cascade_for_agent("developer") == _chain(CARBON)     # a role's setting outranks the env


def test_env_fallback_when_the_settings_cannot_be_read(monkeypatch):
    S = _settings()

    def boom(*a, **k):
        raise RuntimeError("settings unavailable")
    monkeypatch.setattr(S, "get_platform_settings", boom)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    assert S.get_model_cascade_for_agent("developer") == _chain(CARBON)
    monkeypatch.setenv("GEMINI_MODEL", "")
    assert S.get_model_cascade_for_agent("developer") == _chain(CARBON)
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
    assert S.get_model_cascade_for_agent("developer") == _chain("gemini-3.8-flash")
    monkeypatch.setenv("GEMINI_MODEL", ARGON)
    assert S.get_model_cascade_for_agent("developer") == _chain(ARGON)


def _no_client_env():
    return {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": "", "GEMINI_MODEL": "gemini-3.7-flash"}


@pytest.mark.parametrize("module,cls,role", [("developer_agent.handler", "DeveloperAgent", "developer"),
                                             ("architect_agent.handler", "ArchitectAgent", "architect")])
def test_agent_leads_with_the_settings_model_not_the_env(module, cls, role):
    """A default install's platform Terraform sets GEMINI_MODEL=gemini-3.7-flash; it used to be put first in every
    cascade it was not part of. The settings model leads now; an explicit model still wins."""
    S = _settings()
    agent_cls = getattr(importlib.import_module(module), cls)
    with patch.dict(os.environ, _no_client_env()):
        agent = agent_cls(project_id="")
        assert agent.model_name == CARBON
        cascade = S.get_model_cascade_for_agent(role)
        assert cascade[0] == agent.model_name                       # nothing is inserted ahead of the settings
        explicit = agent_cls(project_id="", model_name="gemini-3.8-flash")
        assert explicit.model_name == "gemini-3.8-flash"
        agent.model_name = "gemini-3.8-flash"
        assert agent.model_name == "gemini-3.8-flash"
        agent.model_name = None
        assert agent.model_name == CARBON
        ps = S.PlatformSettings(models={f"{role}_model": "gemini-3.8-flash"})
        with patch.object(S, "get_platform_settings", return_value=ps):    # a Settings change applies at once
            assert agent.model_name == "gemini-3.8-flash"


def _compliance(monkeypatch):
    from compliance_agent import handler as ch
    for k, v in _no_client_env().items():
        monkeypatch.setenv(k, v)
    return ch, ch.ComplianceAgentHandler()


def test_compliance_agent_follows_the_architect_model_not_the_env(monkeypatch):
    """COMPLIANCE-FOLLOWS-ARCHITECT-MODEL (owner 11-11 "yes to all three"): no compliance setting; the architect
    role's settings model and cascade, never GEMINI_MODEL (gemini-3.7-flash on a default install)."""
    S = _settings()
    ch, agent = _compliance(monkeypatch)
    assert ch.COMPLIANCE_MODEL_ROLE == "architect"
    assert agent.model_name == CARBON
    ps = S.PlatformSettings(models={"architect_model": "gemini-3.8-flash", "developer_model": ARGON})
    with patch.object(S, "get_platform_settings", return_value=ps):
        assert agent.model_name == "gemini-3.8-flash"
    agent.model_name = ARGON                                   # an assigned model still wins
    assert agent.model_name == ARGON
    agent.model_name = None
    assert agent.model_name == CARBON


@pytest.mark.skipif(not gmc.sdk_supports_thinking_level(__import__("google.genai.types", fromlist=["x"])),
                    reason="installed google-genai lacks thinking_level")
def test_compliance_rewriter_uses_the_architect_cascade_with_each_models_rules(monkeypatch):
    _ch, agent = _compliance(monkeypatch)
    calls = []

    class Client:
        class models:  # noqa: N801
            @staticmethod
            def generate_content(*, model, contents, config):
                calls.append({"model": model, "config": config})
                if model == CARBON:
                    raise RuntimeError("503 UNAVAILABLE")
                return SimpleNamespace(text="# Remediated plan\n" + "Private VMs with Cloud NAT. " * 5)

    agent.genai_client = Client()
    plan, _dag = agent.remediate_conflicts(["Folder enforces constraints/compute.vmExternalIpAccess."],
                                           "# Plan\nA VM with a public IP.", [], {})
    assert [c["model"] for c in calls] == [CARBON, ARGON]
    for c in calls:
        cfg = c["config"]
        assert cfg.thinking_config.thinking_level.value == "LOW" and cfg.thinking_config.thinking_budget is None
        assert cfg.temperature is None
    assert plan.startswith("# Remediated plan")


@pytest.mark.skipif(not gmc.sdk_supports_thinking_level(__import__("google.genai.types", fromlist=["x"])),
                    reason="installed google-genai lacks thinking_level")
def test_carbon_to_argon_fallback_uses_argons_own_request_rules():
    """The red-team critic's real cascade (settings defaults): Carbon fails, Argon answers. Each request is built by
    its own model's family rules: thinking level, no thinking_budget, no temperature."""
    from architect_agent import red_team_critic
    calls = []

    class Client:
        class models:  # noqa: N801
            @staticmethod
            def generate_content(*, model, contents, config):
                calls.append({"model": model, "config": config})
                if model == CARBON:
                    raise RuntimeError("429 RESOURCE_EXHAUSTED")
                return cap._response('{"is_approved": true}')

    topo = SimpleNamespace(is_valid=True, cycle_detected=False, orphan_dependencies=[], ordering_violations=[])
    critic = red_team_critic.RedTeamCritic(genai_client=Client(), model_name=CARBON)
    critic._invoke_llm_critic({"steps": []}, "spec", topo, None)
    assert [c["model"] for c in calls] == [CARBON, ARGON]
    for c in calls:
        cfg = json.loads(cap.dump_config(c["config"]))
        assert cfg["thinking_config"] == {"thinking_level": "LOW"}, c["model"]
        assert "temperature" not in cfg and cfg["max_output_tokens"] <= 32768, c["model"]


@pytest.mark.parametrize("purpose", list(Purpose))
@pytest.mark.parametrize("model", [CARBON, ARGON])
def test_thinking_budget_setting_is_ignored_for_the_default_models(purpose, model):
    for budget in (0, 1024, 2048):
        tc = gmc.thinking_config_for(model, budget, purpose, types=_FakeTypes, thinking_levels={})
        assert "thinking_budget" not in tc.kw and tc.kw["thinking_level"] == gmc.ARGON_THINKING_LEVEL[purpose]
    kwargs = {"temperature": 0.2, "max_output_tokens": 65536,
              "thinking_config": _FakeThinkingConfig(thinking_budget=1024)}
    out = gmc.adapt_generate_config_kwargs(model, purpose, kwargs, types=_FakeTypes, thinking_levels={})
    assert set(out) == {"max_output_tokens", "thinking_config"} and "thinking_budget" not in out["thinking_config"].kw


# ------------------------------------------------------------------------------------------------ Vertex location
def test_vertex_location_rule():
    f = gmc.vertex_location_for
    # RT F5: only proven locations are listed (global, live-probed 11-11): us / eu / regions go to global
    assert gmc.VERTEX_LOCATIONS == {"gemini-4-argon": frozenset({"global"}), "gemini-4-carbon": frozenset({"global"})}
    for model in (CARBON, ARGON, "publishers/google/models/gemini-4-carbon"):
        assert f(model, "global") == "global" and f(model, " GLOBAL ") == "global"
        for loc in ("us", "eu", "us-central1", "europe-west1", "asia-northeast1", "", None):
            assert f(model, loc) == "global", (model, loc)
    # Gemini 3.x and ids without built-in rules keep the configured location (lower case; Do No Harm)
    assert f("gemini-3.8-flash", "us-central1") == "us-central1"
    assert f("gemini-3.8-flash", "US-CENTRAL1") == "us-central1"
    assert f("acme-model-1", "europe-west1") == "europe-west1"
    # an empty configured location is global for every model (RT F6)
    for model in ("gemini-3.8-flash", "acme-model-1", CARBON):
        assert f(model, "") == "global" and f(model, None) == "global"


def test_every_level_family_has_served_locations_including_global():
    level = {fam.name for fam in gmc.MODEL_FAMILIES.values() if fam.thinking is ThinkingControl.LEVEL}
    assert level == set(gmc.VERTEX_LOCATIONS)
    assert all(gmc.VERTEX_GLOBAL_LOCATION in locs for locs in gmc.VERTEX_LOCATIONS.values())


def _regions():
    with open(os.path.join(REPO, "eval", "config", "gcp_regions.txt")) as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


@pytest.mark.parametrize("model", [CARBON, ARGON])
def test_a_platform_in_any_region_calls_the_defaults_where_they_are_served(model):
    regions = _regions()
    assert len(regions) > 30
    for region in regions:
        assert gmc.vertex_location_for(model, region) in gmc.VERTEX_LOCATIONS[gmc.MODEL_FAMILIES[model].name]


def _env_blocks(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "env":
                for e in (v if isinstance(v, list) else [v]):
                    yield e
            yield from _env_blocks(v)
    elif isinstance(node, list):
        for x in node:
            yield from _env_blocks(x)


def test_platform_terraform_sets_global_gemini_location_wherever_it_sets_the_model():
    """The agents' clients use GEMINI_LOCATION (code default "global"); the platform Terraform sets it to "global"
    on every service and job that gets GEMINI_MODEL, whatever the install region."""
    import hcl2
    with open(os.path.join(REPO, "infra", "platform", "main.tf")) as f:
        doc = hcl2.load(f)
    envs = [e for e in _env_blocks(doc) if isinstance(e, dict)]
    names = [str(e.get("name", "")).strip('"') for e in envs]
    locs = [str(e.get("value", "")).strip('"') for e in envs if str(e.get("name", "")).strip('"') == "GEMINI_LOCATION"]
    assert names.count("GEMINI_MODEL") >= 1 and names.count("GEMINI_LOCATION") == names.count("GEMINI_MODEL")
    # STAGE-JOB-RUNNER: the services read the value from infra/platform/stage_runner.tf local.platform_service_env
    # (also the stage-runner job's env); follow that one reference.
    with open(os.path.join(REPO, "infra", "platform", "stage_runner.tf")) as f:
        common = hcl2.load(f)["locals"][0]["platform_service_env"]
    locs = [common["GEMINI_LOCATION"] if loc == '${local.platform_service_env["GEMINI_LOCATION"]}' else loc for loc in locs]
    assert set(locs) == {"global"}


def test_agent_clients_default_to_the_global_location(monkeypatch):
    monkeypatch.delenv("GEMINI_LOCATION", raising=False)
    monkeypatch.delenv("VERTEX_LOCATION", raising=False)
    from architect_agent.handler import ArchitectAgent
    from developer_agent.handler import DeveloperAgent
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        assert ArchitectAgent(project_id="").location == "global"
        assert DeveloperAgent(project_id="").location == "global"


@pytest.mark.parametrize("model,expected", [(CARBON, "global"), (ARGON, "global"),
                                            ("gemini-3.8-flash", "europe-west1")])
def test_agent_evaluator_backup_client_uses_a_served_location(model, expected, monkeypatch):
    """The agent-quality evaluator's backup client (legacy Vertex SDK) used the platform region; a Gemini 4 model is
    sent to the global endpoint, a Gemini 3.x model keeps the region."""
    ae = importlib.import_module("shared.agent_evaluator")
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    monkeypatch.setenv("DEFAULT_GCP_REGION", "europe-west1")
    seen = {}

    def init(project, location):
        seen["location"] = location

    class Model:
        def __init__(self, name):
            seen["model"] = name

        def generate_content(self, prompt):
            return SimpleNamespace(text="OK")

    # stand-in vertexai modules: importing the real SDK here can hit its circular import in a full-suite run
    fake_vertexai = ModuleType("vertexai")
    fake_vertexai.init = init
    fake_gm = ModuleType("vertexai.generative_models")
    fake_gm.GenerativeModel = Model
    fake_vertexai.generative_models = fake_gm
    with patch("google.genai.Client", side_effect=ValueError("no key")), \
            patch.dict(sys.modules, {"vertexai": fake_vertexai, "vertexai.generative_models": fake_gm}):
        assert ae._call_gemini_inference("prompt", model) == "OK"
    assert seen == {"location": expected, "model": model}


def test_agent_evaluator_default_model_is_the_settings_default():
    ae = importlib.import_module("shared.agent_evaluator")
    assert ae.DEFAULT_EVALUATION_MODEL == gmc.DEFAULT_PRIMARY_MODEL == CARBON


# ------------------------------------------------------------------------------------------------ eval harness pin
def _harness():
    path = os.path.join(REPO, "eval")
    if path not in sys.path:
        sys.path.insert(0, path)
    from stackvend_eval import cassettes, stages
    return cassettes, stages


def test_harness_default_fallback_is_pinned_not_the_product_default(monkeypatch):
    """The replay cassettes were recorded with fallback gemini-3.7-flash (their fallback calls name it). The harness
    keeps that list for `--fallback-models default`, so a product default change never moves a replay's requests."""
    cassettes, stages = _harness()
    assert cassettes.HARNESS_DEFAULT_FALLBACK_MODELS == ("gemini-3.7-flash",)
    assert list(cassettes.HARNESS_DEFAULT_FALLBACK_MODELS) != list(gmc.DEFAULT_FALLBACK_MODELS)
    S = _settings()
    fake = ModuleType("fake_settings_for_default_pin")
    fake.PlatformSettings = S.PlatformSettings

    def get_platform_settings(force_refresh: bool = False, project_id=None):
        raise AssertionError("stand-in must not call through")
    fake.get_platform_settings = get_platform_settings
    fake._SETTINGS_CACHE, fake._LAST_FETCH_TIME = None, 0.0
    monkeypatch.setitem(sys.modules, fake.__name__, fake)
    dump = stages.pin_settings({"shared.settings": fake}, "gemini-3.8-flash", None)
    assert dump["models"]["fallback_models"] == ["gemini-3.7-flash"]
    assert {dump["models"][f] for f in stages.AGENT_MODEL_FIELDS} == {"gemini-3.8-flash"}
    pinned = fake._SETTINGS_CACHE
    with patch.object(S, "get_platform_settings", return_value=pinned):   # the recorded cascade, unchanged
        assert S.get_model_cascade_for_agent("developer") == ["gemini-3.8-flash", "gemini-3.7-flash"]
        assert S.get_model_cascade_for_agent("architect") == ["gemini-3.8-flash", "gemini-3.7-flash"]
    # an explicit list still wins
    dump = stages.pin_settings({"shared.settings": fake}, "gemini-3.8-flash", [ARGON])
    assert dump["models"]["fallback_models"] == [ARGON]


def test_harness_manifest_records_the_pinned_list():
    src = open(os.path.join(REPO, "eval", "run_examples.py"), encoding="utf-8").read()
    assert "settings-default" not in src
    assert src.count("HARNESS_DEFAULT_FALLBACK_MODELS") >= 2


# ------------------------------------------------------------------------------------------------ RT F2: no silent jump
def _unreadable(monkeypatch, S):
    def boom(project_id=None):
        raise S.PlatformSettingsReadError("could not read system_config/platform_settings: down")
    monkeypatch.setattr(S, "_read_stored_document", boom)
    monkeypatch.setattr(S, "_SETTINGS_CACHE", None)
    monkeypatch.setattr(S, "_LAST_FETCH_TIME", 0.0)
    monkeypatch.setattr(S, "_LAST_FAILURE", None)
    monkeypatch.setattr(S, "_LAST_FAILURE_TIME", 0.0)
    monkeypatch.setattr(S, "_WARNED_MODEL_DEFAULTS", set())


def test_unreadable_settings_keep_the_env_model_first(monkeypatch, caplog):
    """RT F2: settings that could not be read (no last good copy) are defaults no one chose: the env model (what the
    services ran before) leads, logged at WARNING with the typed reason; never a silent jump to Carbon."""
    S = _settings()
    _unreadable(monkeypatch, S)
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.7-flash")
    ps = S.get_platform_settings()
    for field in S.ROLE_MODEL_FIELDS:
        assert S.model_default_reason(ps.models, field) is S.ModelDefaultReason.SETTINGS_UNAVAILABLE
    with caplog.at_level("WARNING"):
        assert S.get_model_cascade_for_agent("developer") == _chain("gemini-3.7-flash")
        assert S.get_model_cascade_for_agent("architect") == _chain("gemini-3.7-flash")
    assert "PLATFORM_SETTINGS_UNAVAILABLE" in caplog.text and "models.developer_model" in caplog.text
    with patch.dict(os.environ, _no_client_env()):            # the agents follow the same rule
        from developer_agent.handler import DeveloperAgent
        assert DeveloperAgent(project_id="").model_name == "gemini-3.7-flash"
    monkeypatch.delenv("GEMINI_MODEL")
    assert S.get_model_cascade_for_agent("developer") == _chain(CARBON)   # no env: the code default, logged


def test_stored_unknown_model_reset_keeps_the_env_model_first(monkeypatch):
    S = _settings()
    monkeypatch.setattr(S, "_WARNED_MODEL_DEFAULTS", set())
    ps = S.platform_settings_from_stored({"version": 3, "models": {"developer_model": "acme-unknown-model",
                                                                   "architect_model": "gemini-3.8-flash"}})
    assert ps.models.developer_model == CARBON                                   # reset to the default ...
    assert S.model_default_reason(ps.models, "developer_model") is S.ModelDefaultReason.UNSUPPORTED_STORED_MODEL
    assert S.model_default_reason(ps.models, "architect_model") is None          # ... only that field
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.7-flash")
    with patch.object(S, "get_platform_settings", return_value=ps):
        assert S.get_model_cascade_for_agent("developer") == _chain("gemini-3.7-flash")
        assert S.get_model_cascade_for_agent("architect") == _chain("gemini-3.8-flash")
        assert S.get_model_cascade_for_agent("assistant") == _chain(CARBON)    # untouched default: Carbon


def test_an_install_without_a_settings_document_gets_carbon(monkeypatch):
    """No document is a fresh install: the defaults ARE its settings (not a read failure), so Carbon leads."""
    S = _settings()
    _unreadable(monkeypatch, S)
    monkeypatch.setattr(S, "_read_stored_document", lambda project_id=None: None)
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.7-flash")
    ps = S.get_platform_settings()
    assert all(S.model_default_reason(ps.models, f) is None for f in S.ROLE_MODEL_FIELDS)
    assert S.get_model_cascade_for_agent("developer") == _chain(CARBON)


def test_the_reason_is_never_stored_or_dumped():
    S = _settings()
    ps = S.PlatformSettings()
    S._mark_model_defaults(ps.models, S.ROLE_MODEL_FIELDS, S.ModelDefaultReason.SETTINGS_UNAVAILABLE)
    dumped = json.dumps(ps.model_dump(mode="json"))
    assert "_model_default_reasons" not in dumped and "PLATFORM_SETTINGS_UNAVAILABLE" not in dumped


# ------------------------------------------------------------------------------------------------ RT F3: one read per build
def _method(tree, cls, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == cls:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"{cls}.{name} not found")


def _model_name_loads(fn):
    return [n for n in ast.walk(fn) if isinstance(n, ast.Attribute) and n.attr == "model_name"
            and isinstance(n.value, ast.Name) and n.value.id == "self" and isinstance(n.ctx, ast.Load)]


def test_developer_reads_its_model_once_per_build_and_never_at_construction():
    path = os.path.join(REPO, "apps", "orchestrator-gateway", "developer_agent", "handler.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    assert len(_model_name_loads(_method(tree, "DeveloperAgent", "generate_code_files"))) == 1
    assert _model_name_loads(_method(tree, "DeveloperAgent", "__init__")) == []
    stack = _method(tree, "DeveloperAgent", "_run_hallucination_stack")
    assert "developer_model" in [a.arg for a in stack.args.args + stack.args.kwonlyargs]


def test_compliance_agent_reads_no_settings_at_construction():
    path = os.path.join(REPO, "apps", "orchestrator-gateway", "compliance_agent", "handler.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    assert _model_name_loads(_method(tree, "ComplianceAgentHandler", "__init__")) == []


def test_compliance_legacy_model_is_built_per_call_with_the_current_model(monkeypatch):
    _ch, agent = _compliance(monkeypatch)
    built = []

    class Model:
        def __init__(self, name):
            built.append(name)

        def generate_content(self, prompt):
            return SimpleNamespace(text="ok")

    legacy = _ch._PerCallLegacyModel(agent, Model)
    assert built == []                                     # nothing resolved until a call
    legacy.generate_content("p")
    agent.model_name = ARGON
    legacy.generate_content("p")
    assert built == [CARBON, ARGON]


def test_compliance_legacy_call_uses_one_model_read_for_the_call_and_its_tokens(monkeypatch):
    """RT D3: the legacy path reads the model once and uses it for the call and the token accounting."""
    ch, agent = _compliance(monkeypatch)
    built, reads = [], []

    class Model:
        def __init__(self, name):
            built.append(name)

        def generate_content(self, prompt):
            return SimpleNamespace(text="# Remediated plan\n" + "Private VMs with Cloud NAT. " * 5)

    agent.genai_client = None
    agent.model = ch._PerCallLegacyModel(agent, Model)
    agent._db = object()
    real = type(agent).model_name

    def counting(self):
        reads.append(1)
        return real.fget(self)
    monkeypatch.setattr(type(agent), "model_name", property(counting, real.fset))
    recorded = []
    import shared.token_accounting as ta
    monkeypatch.setattr(ta, "extract_token_usage", lambda response, model: recorded.append(model) or None)
    monkeypatch.setattr(ta, "record_agent_tokens", lambda *a, **k: None)
    agent.remediate_conflicts(["Folder enforces constraints/compute.vmExternalIpAccess."], "# Plan", [], {},
                              trace_id="t1")
    assert len(reads) == 1 and built == [CARBON] and recorded == [CARBON]
