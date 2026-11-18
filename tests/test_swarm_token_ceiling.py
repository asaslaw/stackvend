"""Row SWARM-TOK-1 (FD-4AK Fable RT F4): the swarm reads the admin's FinOps envelope and developer token limit.

Before: `get_platform_settings(db=self.db)` in the lead orchestrator and the swarm dispatcher was a TypeError (the
function has no `db` parameter), swallowed at DEBUG, so production always ran with 350 000 / 65 536 whatever the admin
set. The eval harness hid it: its stand-in accepted **kwargs. Offline: mocked LLM client, patched settings; no
network, no Firestore."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import asyncio
import inspect
import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "apps" / "orchestrator-gateway"))
sys.path.insert(0, str(ROOT / "eval"))

from shared import settings as S  # noqa: E402
from shared.gemini_model_config import Purpose, max_output_tokens_for  # noqa: E402
from developer_agent.lead_orchestrator import LeadDeveloperOrchestrator  # noqa: E402
from developer_agent.swarm_dispatcher import SwarmDispatcher  # noqa: E402
from developer_agent.swarm_schemas import SwarmExecutionMode  # noqa: E402
from stackvend_eval import stages as st  # noqa: E402

MODEL = "gemini-3.8-flash"
SETTINGS_TARGET = "shared.settings.get_platform_settings"


def _settings(envelope: int, dev_tokens: int) -> "S.PlatformSettings":
    base = S.PlatformSettings()
    return base.model_copy(update={"models": base.models.model_copy(update={
        "max_swarm_token_envelope": envelope, "developer_max_output_tokens": dev_tokens})})


def _lead_client(envelope_in_answer: int):
    client = MagicMock()
    res = MagicMock()
    res.text = json.dumps({"execution_mode": "STANDARD_SWARM", "max_swarm_token_envelope": envelope_in_answer,
                           "shared_contracts": {}, "tasks": [{
                               "task_id": "t1", "persona": "BACKEND_ENGINEER", "wave": 1,
                               "assigned_files": ["apps/workload/main.py"], "task_objective": "Build it"}]})
    res.candidates = []
    client.models.generate_content.return_value = res
    return client


def _decompose(lead, **kw):
    return lead.decompose_specification(product_id="p1", spec_text="Spec", task_dag=[{"task_id": "s1"}], **kw)


# ------------------------------------------------------------------------------------------- defaults: no change
def test_default_settings_give_exactly_the_old_fallback_values():
    """With default settings the effective values are the ones production ran with (350k / 65 536): no LLM request
    changes for an install whose admin never changed them (and none in the eval, which pins the defaults)."""
    m = S.PlatformSettings().models
    assert m.max_swarm_token_envelope == 350_000
    assert m.get_developer_token_limit() == 65536


# --------------------------------------------------------------------------------------------- lead orchestrator
def test_lead_applies_the_admin_envelope_and_token_limit():
    client = _lead_client(envelope_in_answer=300_000)
    with patch(SETTINGS_TARGET, autospec=True, return_value=_settings(120_000, 8192)) as gps, \
            patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent", return_value=[MODEL]):
        lead = LeadDeveloperOrchestrator(genai_client=client, model_name=MODEL, project_id="host-proj")
        plan = _decompose(lead)
    gps.assert_called_once_with(project_id="host-proj")
    assert plan.max_swarm_token_envelope == 120_000          # the model's 300k is capped by the admin's ceiling
    kwargs = client.models.generate_content.call_args.kwargs
    assert "Token Envelope Budget: 120,000 tokens" in kwargs["contents"]
    assert kwargs["config"].max_output_tokens == max_output_tokens_for(MODEL, 8192, Purpose.DEVELOPER)


def test_lead_fast_path_and_deterministic_plan_use_the_admin_envelope():
    with patch(SETTINGS_TARGET, autospec=True, return_value=_settings(60_000, 8192)):
        lead = LeadDeveloperOrchestrator(genai_client=None, project_id="host-proj")
        solo = _decompose(lead, existing_files={"apps/workload/main.py": "x = 1\n"})
        fallback = _decompose(lead)
    assert solo.execution_mode == SwarmExecutionMode.SOLO_FAST_PATH
    assert solo.max_swarm_token_envelope == 60_000            # min(100k, admin 60k); was always 100k
    assert fallback.max_swarm_token_envelope == 60_000         # was always 350k


def test_lead_settings_read_failure_keeps_the_previous_defaults():
    """Lenient on purpose: a failing read gives today's bounded defaults, never an unbounded or failed swarm."""
    client = _lead_client(envelope_in_answer=900_000)
    with patch(SETTINGS_TARGET, side_effect=RuntimeError("firestore down")), \
            patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent", return_value=[MODEL]):
        plan = _decompose(LeadDeveloperOrchestrator(genai_client=client, model_name=MODEL, project_id="h"))
    assert plan.max_swarm_token_envelope == 350_000
    assert client.models.generate_content.call_args.kwargs["config"].max_output_tokens == \
        max_output_tokens_for(MODEL, 65536, Purpose.DEVELOPER)


# ------------------------------------------------------------------------------------------------- dispatcher
def _dispatcher_call(settings_patch):
    client = MagicMock()
    res = MagicMock()
    res.text = json.dumps({"files": {"apps/workload/main.py": "x = 1\n"}})
    res.candidates = []
    res.usage_metadata = MagicMock(total_token_count=10)
    client.models.generate_content.return_value = res
    with settings_patch as gps:
        asyncio.run(SwarmDispatcher(genai_client=client, model_name=MODEL)._call_gemini_with_backoff(
            prompt="p", system_instruction="s", model_name=MODEL))
    return client.models.generate_content.call_args.kwargs["config"].max_output_tokens, gps


def test_dispatcher_applies_the_admin_developer_token_limit():
    got, gps = _dispatcher_call(patch(SETTINGS_TARGET, autospec=True, return_value=_settings(120_000, 8192)))
    # the dispatcher has no project id: PROJECT_ID (the host project, as for the lead) via the shared 60 s cache
    gps.assert_called_once_with()
    assert got == max_output_tokens_for(MODEL, 8192, Purpose.DEVELOPER)


def test_dispatcher_settings_read_failure_keeps_the_previous_default():
    got, _ = _dispatcher_call(patch(SETTINGS_TARGET, side_effect=RuntimeError("firestore down")))
    assert got == max_output_tokens_for(MODEL, 65536, Purpose.DEVELOPER)


# ------------------------------------------------------------------------------- every call binds to the signature
def _real_parameters():
    tree = ast.parse((ROOT / "shared" / "settings.py").read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "get_platform_settings")
    assert not fn.args.vararg and not fn.args.kwarg
    return [a.arg for a in fn.args.args] + [a.arg for a in fn.args.kwonlyargs]


def _product_files():
    for top in ("apps", "mcp-servers", "shared"):
        for p in sorted((ROOT / top).rglob("*.py")):
            if "node_modules" in p.parts or p.name.startswith("test_") or "tests" in p.parts:
                continue
            yield p


def test_every_product_call_binds_to_the_real_signature():
    """A real parser (ast), not text matching: each `get_platform_settings(...)` call in product code passes only
    parameters the function has. `db=` (or any other unknown keyword) fails here instead of at run time."""
    params = _real_parameters()
    calls, bad = 0, []
    for p in _product_files():
        for node in ast.walk(ast.parse(p.read_text(), filename=str(p))):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
            if name != "get_platform_settings":
                continue
            calls += 1
            kws = [k.arg for k in node.keywords]
            if None in kws or any(k not in params for k in kws) or len(node.args) > len(params):
                bad.append(f"{p.relative_to(ROOT)}:{node.lineno} {kws}")
    assert calls > 20 and not bad, bad


# ------------------------------------------------------------------------------------------- eval stand-in
def _real_main(force_refresh: bool = False, project_id=None):
    raise AssertionError("stand-in must not call through")


def _real_fd4ak(force_refresh: bool = False, project_id=None, strict: bool = False):
    raise AssertionError("stand-in must not call through")


@pytest.mark.parametrize("real", [_real_main, _real_fd4ak], ids=["main", "fd-4ak-strict"])
def test_eval_stand_in_has_exactly_the_real_signature(real, monkeypatch):
    fake = types.ModuleType("fake_settings_for_pin")
    fake.PlatformSettings = S.PlatformSettings
    fake.get_platform_settings = real
    fake._SETTINGS_CACHE, fake._LAST_FETCH_TIME = None, 0.0
    monkeypatch.setitem(sys.modules, fake.__name__, fake)
    st.pin_settings({"shared.settings": fake}, MODEL, None)
    stand_in = fake.get_platform_settings
    assert stand_in is not real
    assert inspect.signature(stand_in) == inspect.signature(real)
    pinned = fake._SETTINGS_CACHE
    assert stand_in() is pinned and stand_in(True, "p") is pinned and stand_in(project_id="p") is pinned
    with pytest.raises(TypeError):
        stand_in(db=object())                                   # the old swallowed production TypeError
    with pytest.raises(TypeError):
        stand_in(True, "p", False, "extra")
    if "strict" in inspect.signature(real).parameters:
        assert stand_in(project_id="p", strict=True) is pinned
    else:
        with pytest.raises(TypeError):
            stand_in(strict=True)
