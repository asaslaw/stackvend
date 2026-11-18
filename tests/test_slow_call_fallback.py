"""SLOW-CALL-FALLBACK (owner 11-13, option (b)): a too-slow developer-path model call walks down the fallback list.

Plan: docs/planning/slow-call-fallback-plan.md (scenario matrix §5). Hermetic: fake genai clients whose calls take
simulated time on an injected clock (no real sleeping), no Firestore client, no network.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import asyncio
import contextvars
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO, "apps", "orchestrator-gateway")
for _p in (GATEWAY, os.path.dirname(__file__)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse)

from developer_agent import llm_transport as T  # noqa: E402
from developer_agent.errors import LLM_STAGE_BUDGET_EXHAUSTED, LLM_UNAVAILABLE, DeveloperStageError  # noqa: E402

CARBON, ARGON, FLASH38, FLASH37 = "gemini-4-carbon", "gemini-4-argon", "gemini-3.8-flash", "gemini-3.7-flash"
CHAIN = [CARBON, ARGON, FLASH38, FLASH37]


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


# ------------------------------------------------------------------------------------------------ fakes
# A per-asyncio-task clock: each swarm task (and the worker thread its call runs in, which copies the task's context)
# advances its own time, so concurrent tasks never see each other's simulated latency.
_CLOCK: contextvars.ContextVar = contextvars.ContextVar("slow_call_test_clock", default=None)


def task_clock() -> float:
    box = _CLOCK.get()
    if box is None:
        box = [1000.0]
        _CLOCK.set(box)
    return box[0]


def advance(seconds: float) -> None:
    task_clock()
    _CLOCK.get()[0] += seconds


class Status(Exception):
    """An SDK APIError stand-in: the typed integer status code (llm_transport.transient_status reads only .code)."""

    def __init__(self, code):
        super().__init__(f"{code} status")
        self.code = code


def response(text, total=100):
    usage = SimpleNamespace(prompt_token_count=40, candidates_token_count=total - 40, thoughts_token_count=0,
                            total_token_count=total)
    cand = SimpleNamespace(finish_reason="STOP")
    return SimpleNamespace(text=text, candidates=[cand], usage_metadata=usage)


class SlowModels:
    """generate_content(model) takes `script[model]` = (seconds, answer-or-exception) on the injected clock; an entry
    may be a callable(contents) -> (seconds, outcome) for per-task behaviour."""

    def __init__(self, script, clock_advance=advance):
        self.script = script
        self.calls = []
        self.advance = clock_advance

    def generate_content(self, model=None, contents=None, config=None):
        self.calls.append({"model": model, "contents": contents, "config": config})
        entry = self.script[model]
        seconds, outcome = entry(contents) if callable(entry) else entry
        self.advance(seconds)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class Client:
    def __init__(self, script, clock_advance=advance):
        self.models = SlowModels(script, clock_advance)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


FILES = json.dumps({"files": {"apps/a/main.py": "print(1)\n"}})


# ------------------------------------------------------------------------------------------------ transport rules
def test_timeout_table_and_stage_budget_cap():
    t = T.DEFAULT_CALL_TIMEOUTS
    assert (t.wbs_s, t.junior_s, t.iac_s, t.repair_s, t.single_turn_s) == (240.0, 900.0, 420.0, 180.0, 900.0)
    assert T.call_timeout_s(T.CallPurpose.JUNIOR) == 900.0
    # S5: the stage budget is smaller than the per-call cap -> remaining minus the margin
    assert T.call_timeout_s(T.CallPurpose.JUNIOR, deadline=1100.0, now=1000.0) == 85.0
    assert T.call_timeout_s(T.CallPurpose.JUNIOR, deadline=5000.0, now=1000.0) == 900.0
    assert T.call_timeout_s(T.CallPurpose.JUNIOR, deadline=1030.0, now=1000.0) is None   # 15 s left < min_call_s
    with pytest.raises(ValueError):
        T.CallTimeouts(junior_s=0)
    with pytest.raises(ValueError):
        T.CallTimeouts(min_call_s=500)


def _walk_once(walk, client, contents="p", config=None):
    """Drive a walk in walk mode against a fake client (the shape every call site uses)."""
    for plan in walk:
        try:
            r = client.models.generate_content(model=plan.model, contents=contents,
                                               config=walk.config(plan, config if config is not None else {}))
        except Exception as e:  # noqa: BLE001
            if walk.failed(plan, e) is None:
                raise
            continue
        if walk.answered(plan, r):
            return r
    return None


def test_s1_primary_fast_is_one_call_and_no_fallback():
    clock = Clock()
    client = Client({CARBON: (90, response(FILES))}, clock.advance)
    walk = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock)
    r = _walk_once(walk, client, config={"temperature": 0.2})
    assert r is not None and len(client.models.calls) == 1 and client.models.calls[0]["model"] == CARBON
    assert client.models.calls[0]["config"] == {"temperature": 0.2, "http_options": {"timeout": 900000}}
    prov = walk.provenance()
    assert prov["model"] == CARBON and prov["fallback"] is False and prov["fallback_reason"] is None
    assert [a["outcome"] for a in prov["attempts"]] == ["OK"]


def test_s2_slow_primary_answer_is_discarded_billed_and_argon_answers():
    clock, sunk = Clock(), []
    late = response('{"files": {"late.py": "x"}}', total=5000)
    client = Client({CARBON: (950, late), ARGON: (60, response(FILES))}, clock.advance)
    walk = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock, abandoned=lambda a, r: sunk.append((a, r)))
    r = _walk_once(walk, client)
    assert r is not None and json.loads(r.text)["files"] == {"apps/a/main.py": "print(1)\n"}   # never the late one
    assert [c["model"] for c in client.models.calls] == [CARBON, ARGON]
    assert walk.provenance()["model"] == ARGON and walk.fallback_reason == "TIMEOUT"
    (att, resp), = sunk
    assert att.late and att.outcome == "TIMEOUT" and att.usage == "REPORTED" and att.billed_tokens == 5000
    assert resp is late


def test_s3_504_below_the_timeout_walks_at_once():
    clock = Clock()
    client = Client({CARBON: (30, Status(504)), ARGON: (20, response(FILES))}, clock.advance)
    walk = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock)
    assert _walk_once(walk, client) is not None
    assert walk.fallback_reason == "TRANSIENT_504" and walk.answered_model == ARGON
    assert [a.outcome for a in walk.attempts] == ["TRANSIENT_504", "OK"]


def test_504_at_the_bound_is_a_timeout():
    clock = Clock()
    client = Client({CARBON: (900, Status(504)), ARGON: (20, response(FILES))}, clock.advance)
    walk = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock)
    _walk_once(walk, client)
    assert walk.attempts[0].outcome == "TIMEOUT" and walk.attempts[0].usage == "UNKNOWN"


def test_s4_every_model_slow_is_a_typed_error_with_every_attempt():
    clock, sunk = Clock(), []
    client = Client({m: (999, response(FILES)) for m in CHAIN}, clock.advance)
    walk = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock, abandoned=lambda a, r: sunk.append(a))
    with pytest.raises(T.LlmFallbackExhausted) as e:
        _walk_once(walk, client)
    err = e.value
    assert isinstance(err, DeveloperStageError) and err.error_class == LLM_UNAVAILABLE
    assert err.reason == "LLM_FALLBACK_EXHAUSTED" and err.stage == "developer"
    assert [a.model for a in err.attempts] == CHAIN and {a.outcome for a in err.attempts} == {"TIMEOUT"}
    for m in CHAIN:
        assert m in str(err)
    assert len(sunk) == 4   # every abandoned answer reached the ledger sink
    body = err.to_body()
    assert body["error_class"] == LLM_UNAVAILABLE and len(body["attempts"]) == 4


def test_s5_stage_budget_caps_and_then_stops_without_a_call():
    clock = Clock()
    client = Client({CARBON: (60, response(FILES))}, clock.advance)
    walk = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock, deadline=clock() + 100)
    assert _walk_once(walk, client) is not None and walk.answered_model == CARBON
    assert client.models.calls[0]["config"]["http_options"] == {"timeout": 85000}   # 100 s left - 15 s margin
    # carbon took 95 s > 85 s + grace: late; 5 s left -> no room for argon -> typed stop, no call
    clock2 = Clock()
    client2 = Client({CARBON: (95, response(FILES)), ARGON: (10, response(FILES))}, clock2.advance)
    walk2 = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock2, deadline=clock2() + 100)
    with pytest.raises(T.LlmStageBudgetExhausted) as e:
        _walk_once(walk2, client2)
    assert e.value.error_class == LLM_STAGE_BUDGET_EXHAUSTED
    assert [c["model"] for c in client2.models.calls] == [CARBON]
    assert [a.outcome for a in e.value.attempts] == ["TIMEOUT", "NO_STAGE_BUDGET"]


def test_s8_client_timeout_exception_is_a_timeout_with_unknown_usage():
    httpx = pytest.importorskip("httpx")
    clock, sunk = Clock(), []
    client = Client({CARBON: (900, httpx.ReadTimeout("read timed out")), ARGON: (5, response(FILES))}, clock.advance)
    walk = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock, abandoned=lambda a, r: sunk.append((a, r)))
    _walk_once(walk, client)
    assert walk.fallback_reason == "TIMEOUT" and sunk[0][0].usage == "UNKNOWN" and sunk[0][1] is None


def test_s9_non_transient_error_is_not_walked():
    clock = Clock()
    client = Client({CARBON: (1, Status(400)), ARGON: (1, response(FILES))}, clock.advance)
    walk = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock)
    with pytest.raises(Status):
        _walk_once(walk, client)
    assert [c["model"] for c in client.models.calls] == [CARBON]
    # an untyped message that merely mentions a status is never read (invariant 2)
    client = Client({CARBON: (1, RuntimeError("429 RESOURCE_EXHAUSTED")), ARGON: (1, response(FILES))}, clock.advance)
    with pytest.raises(RuntimeError):
        _walk_once(T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock), client)


def test_s10_transient_on_the_last_model_is_retried_with_the_r3c_backoff():
    clock = Clock()
    calls = []

    def flaky(contents):
        calls.append(1)
        return (1, Status(429)) if len(calls) < 3 else (1, response(FILES))

    client = Client({FLASH37: flaky}, clock.advance)
    walk = T.CallWalk([FLASH37], purpose=T.CallPurpose.REPAIR, clock=clock)
    waits = []
    for plan in walk:
        waits.append(plan.backoff_s)
        try:
            r = client.models.generate_content(model=plan.model, contents="p", config=walk.config(plan, {}))
        except Exception as e:  # noqa: BLE001
            assert walk.failed(plan, e)
            continue
        if walk.answered(plan, r):
            break
    assert waits == [0.0, *T.RETRY_BACKOFF_S] and walk.answered_model == FLASH37


def test_http_timeout_is_transport_only():
    from google.genai import types
    cfg = types.GenerateContentConfig(temperature=0.2, max_output_tokens=1000, system_instruction="s")
    out = T.with_http_timeout(cfg, 420)
    assert out.http_options.timeout == 420000 and cfg.http_options is None   # the caller's object is untouched
    assert out.model_dump(exclude={"http_options"}) == cfg.model_dump(exclude={"http_options"})


def test_cassette_key_ignores_the_timeout():
    sys.path.insert(0, os.path.join(REPO, "eval"))
    from stackvend_eval.cassettes import normalize_request, request_hash
    from google.genai import types
    cfg = types.GenerateContentConfig(temperature=0.2, max_output_tokens=1000)
    assert request_hash(normalize_request("m", "p", cfg)) == \
        request_hash(normalize_request("m", "p", T.with_http_timeout(cfg, 85.0)))


def test_provenance_summary_says_who_wrote_what():
    rec = T.model_provenance_record([
        {"output": "wbs", "model": CARBON, "fallback": False},
        {"output": "task-db", "model": ARGON, "fallback": True, "fallback_reason": "TIMEOUT"},
        {"output": "task-api", "model": CARBON, "fallback": False},
        {"output": "task-iac", "model": FLASH38, "fallback": True, "fallback_reason": "TRANSIENT_504"}])
    assert rec["summary"] == (f"written by {CARBON}; task-db by {ARGON} (fallback: timeout); "
                              f"task-iac by {FLASH38} (fallback: transient 504)")
    assert rec["mixed"] is True
    assert T.model_provenance_record([{"output": "wbs", "model": CARBON}])["summary"] == f"written by {CARBON}"


def test_ledger_sink_records_billed_tokens_and_unknown_usage():
    payloads = []

    class Doc:
        def update(self, p):
            payloads.append(("update", p))

        def set(self, p, merge=False):
            payloads.append(("set", p))

    db = MagicMock()
    db.collection.return_value.document.return_value = Doc()
    sink = T.ledger_abandoned_sink(db, "trace-1", "developer_swarm")
    late = T.CallAttempt(CARBON, "TIMEOUT", 420, 500, usage="REPORTED", billed_tokens=100, late=True)
    sink(late, response(FILES, total=100))
    sink(T.CallAttempt(ARGON, "TIMEOUT", 420, 420, usage="UNKNOWN"), None)
    text = json.dumps([p for _k, p in payloads], default=str)
    assert "token_usage.by_agent.developer_swarm.total_tokens" in text          # billed tokens recorded
    assert "abandoned_calls_usage_reported" in text and "abandoned_calls_usage_unknown" in text
    assert T.ledger_abandoned_sink(None, "t", "a") is None


# ------------------------------------------------------------------------------------------------ swarm juniors
def _dispatcher(client):
    from developer_agent.swarm_dispatcher import SwarmDispatcher
    d = SwarmDispatcher(genai_client=client)
    d._clock = task_clock

    async def _no_wait(_s):
        return None

    d._async_sleep = _no_wait
    return d


def _plan(*tasks):
    from developer_agent.swarm_schemas import (JuniorPersona, JuniorTaskAssignment, LeadDeveloperDecompositionPlan,
                                               SwarmExecutionMode)
    return LeadDeveloperDecompositionPlan(
        execution_mode=SwarmExecutionMode.STANDARD_SWARM, iac_engine="OPENTOFU", vcs_provider="GITHUB",
        tasks=[JuniorTaskAssignment(task_id=tid, persona=JuniorPersona.BACKEND_ENGINEER, wave=1,
                                    assigned_files=[path], task_objective=tid) for tid, path in tasks])


def _junior(dispatcher, plan, i=0, model=CARBON):
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=list(CHAIN)), \
            patch("developer_agent.swarm_dispatcher.resolve_junior_prompt", return_value="sys"):
        return asyncio.run(dispatcher.invoke_junior_worker(plan.tasks[i], plan, {}, model))


def test_junior_s1_primary_fast_negative_same_single_call_and_config():
    """Do No Harm: the primary answers in time -> one call, the task's model, the request it sent before this change
    (only http_options.timeout added)."""
    from google.genai import types
    from shared.gemini_model_config import Purpose, adapt_generate_config_kwargs, max_output_tokens_for
    plan = _plan(("t1", "apps/a/main.py"))
    client = Client({CARBON: (120, response(FILES))})
    res = _junior(_dispatcher(client), plan)
    assert [c["model"] for c in client.models.calls] == [CARBON]
    sent = client.models.calls[0]["config"]
    assert sent.http_options.timeout == 900000
    from shared.settings import get_platform_settings
    limit = max_output_tokens_for(CARBON, get_platform_settings().models.get_developer_token_limit(),
                                  Purpose.DEVELOPER)
    expected = types.GenerateContentConfig(**adapt_generate_config_kwargs(
        CARBON, Purpose.DEVELOPER, dict(system_instruction=sent.system_instruction,
                                        response_mime_type="application/json", temperature=0.2,
                                        max_output_tokens=limit), types=types))
    assert sent.model_dump(exclude={"http_options"}) == expected.model_dump(exclude={"http_options"})
    assert res.model == CARBON and res.model_fallback_reason is None and res.files == {"apps/a/main.py": "print(1)\n"}


def test_junior_s2_slow_primary_falls_back_to_argon_and_records_it():
    plan = _plan(("t1", "apps/a/main.py"))
    client = Client({CARBON: (950, response('{"files": {"apps/a/main.py": "late"}}')),
                     ARGON: (60, response(FILES))})
    d = _dispatcher(client)
    res = _junior(d, plan)
    assert [c["model"] for c in client.models.calls] == [CARBON, ARGON]
    assert res.files == {"apps/a/main.py": "print(1)\n"}   # the late carbon answer is never used
    assert res.model == ARGON and res.model_fallback_reason == "TIMEOUT"
    assert [a["outcome"] for a in res.model_attempts] == ["TIMEOUT", "OK"] and res.model_attempts[0]["late"]


def test_junior_iac_intent_task_uses_the_iac_cap():
    from developer_agent.swarm_schemas import JuniorPersona
    plan = _plan(("t-iac", "infra/intent.json"))
    plan.tasks[0].persona = JuniorPersona.IAC_ENGINEER
    d = _dispatcher(Client({CARBON: (10, response(json.dumps({"files": {"infra/intent.json": "{}"}})))}))
    d.iac_intent = SimpleNamespace(system_prompt="INTENT", run_context="CTX", max_output_tokens=8192,
                                   thinking_budget=2048, structured_output=False, artifacts=None)
    with patch("developer_agent.swarm_dispatcher.normalize_intent_envelope", side_effect=lambda s: s):
        _junior(d, plan)
    assert d.genai_client.models.calls[0]["config"].http_options.timeout == 420000


def test_junior_s6_family_switch_rebuilds_the_config_per_model():
    """carbon (Gemini 4, thinking LEVEL) slow -> gemini-3.8-flash (thinking BUDGET family): the flash request carries
    the budget family's own kwargs (temperature kept, no level thinking config, its own output bound)."""
    plan = _plan(("t1", "apps/a/main.py"))
    client = Client({CARBON: (999, response(FILES)), FLASH38: (30, response(FILES))})
    d = _dispatcher(client)
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=[CARBON, FLASH38]), \
            patch("developer_agent.swarm_dispatcher.resolve_junior_prompt", return_value="sys"):
        res = asyncio.run(d.invoke_junior_worker(plan.tasks[0], plan, {}, CARBON))
    carbon_cfg, flash_cfg = (c["config"] for c in client.models.calls)
    assert carbon_cfg.temperature is None and carbon_cfg.thinking_config is not None   # level family request
    assert carbon_cfg.thinking_config.thinking_level is not None
    assert flash_cfg.temperature == 0.2                                                # budget family request
    assert flash_cfg.thinking_config is None or flash_cfg.thinking_config.thinking_level is None
    assert flash_cfg.max_output_tokens >= carbon_cfg.max_output_tokens
    assert res.model == FLASH38 and res.model_fallback_reason == "TIMEOUT"


def test_junior_s7_concurrent_tasks_fall_back_independently():
    plan = _plan(("task-db", "apps/a/db.py"), ("task-api", "apps/a/api.py"))

    def carbon(contents):
        if "task-db" in contents:
            return 950, response(json.dumps({"files": {"apps/a/db.py": "late"}}))
        return 200, response(json.dumps({"files": {"apps/a/api.py": "api"}}))

    client = Client({CARBON: carbon, ARGON: (60, response(json.dumps({"files": {"apps/a/db.py": "db"}})))})
    d = _dispatcher(client)
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=list(CHAIN)), \
            patch("developer_agent.swarm_dispatcher.resolve_junior_prompt", return_value="sys"):
        tree = asyncio.run(d.execute_phased_junior_swarm(plan, "trace", "noapp", CARBON))
    assert tree["apps/a/db.py"] == "db" and tree["apps/a/api.py"] == "api"
    by_task = {p["task_id"]: p for p in d.task_provenance}
    assert by_task["task-db"]["model"] == ARGON and by_task["task-db"]["fallback_reason"] == "TIMEOUT"
    assert by_task["task-api"]["model"] == CARBON and by_task["task-api"]["fallback"] is False


def test_junior_every_model_slow_raises_typed_and_is_not_retried_or_escalated():
    plan = _plan(("t1", "apps/a/main.py"))
    client = Client({m: (999, response(FILES)) for m in CHAIN})
    with pytest.raises(T.LlmFallbackExhausted) as e:
        _junior(_dispatcher(client), plan)
    assert len(client.models.calls) == 4 and [a.model for a in e.value.attempts] == CHAIN


# ------------------------------------------------------------------------------------------------ repair
def test_repair_s12_slow_primary_answers_from_argon_sized_for_argon():
    from developer_agent.swarm_dispatcher import SwarmDispatcher
    clock = Clock()
    client = Client({CARBON: (200, response(FILES)), ARGON: (40, response(FILES))}, clock.advance)
    d = SwarmDispatcher(genai_client=client)
    d._clock = clock
    sized = []

    def sizing(m):
        sized.append(m)
        return 12000, None

    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=list(CHAIN)):
        out = d.invoke_repair("BACKEND_ENGINEER", "sys", "prompt", CARBON, 9000, sizing=sizing)
    assert out["envelope_ok"] and out["model"] == ARGON and out["model_fallback_reason"] == "TIMEOUT"
    assert sized == [ARGON] and client.models.calls[1]["config"].max_output_tokens == 12000
    assert client.models.calls[0]["config"].http_options.timeout == 180000
    # RT F9: the late carbon answer was billed: 40 prompt tokens in, 60 output tokens out (never prompt as output)
    assert out["tokens_abandoned_in"] == 40 and out["tokens_abandoned_out"] == 60


def test_repair_event_carries_the_fallback_reason():
    from shared.diagnostics import RepairEvent
    ev = RepairEvent(trace_id="t", product_id="p", iteration=1, source="precommit", persona="IAC", files=[],
                     codes=[], fingerprints_before=[], fingerprints_after=[], accepted=True, model=ARGON,
                     model_fallback="TIMEOUT")
    assert ev.model_fallback == "TIMEOUT"
    assert RepairEvent(trace_id="t", product_id="p", iteration=1, source="precommit", persona="IAC", files=[],
                       codes=[], fingerprints_before=[], fingerprints_after=[], accepted=True,
                       model=CARBON).model_fallback is None


def test_repair_stage_budget_gone_raises_typed():
    from developer_agent.swarm_dispatcher import SwarmDispatcher
    clock = Clock()
    d = SwarmDispatcher(genai_client=Client({CARBON: (1, response(FILES))}, clock.advance))
    d._clock = clock
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=list(CHAIN)):
        with pytest.raises(T.LlmStageBudgetExhausted):
            d.invoke_repair("IAC", "sys", "prompt", CARBON, 9000, deadline=clock() + 10)
    assert d.genai_client.models.calls == []


# ------------------------------------------------------------------------------------------------ lead WBS
SVC = "slowcall"
GOOD_PLAN = {"execution_mode": "STANDARD_SWARM", "shared_contracts": {}, "tasks": [
    {"task_id": "db", "persona": "DATABASE_ENGINEER", "wave": 1, "assigned_files": [f"apps/{SVC}/models.py"],
     "read_dependencies": [], "task_objective": "db"}]}


def _lead(client, clock):
    from developer_agent.lead_orchestrator import LeadDeveloperOrchestrator
    lead = LeadDeveloperOrchestrator(genai_client=client, model_name=CARBON, db=None, project_id="")
    lead._clock = clock
    return lead


def test_lead_s11_carbon_times_out_and_argon_writes_the_plan():
    clock = Clock()
    client = Client({CARBON: (300, response(json.dumps(GOOD_PLAN))), ARGON: (50, response(json.dumps(GOOD_PLAN)))},
                    clock.advance)
    lead = _lead(client, clock)
    with patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent", return_value=list(CHAIN)):
        plan = lead.decompose_specification(product_id=SVC, spec_text="x" * 2000, task_dag=[{}, {}])
    assert [t.task_id for t in plan.tasks] == ["db"]
    assert [c["model"] for c in client.models.calls] == [CARBON, ARGON]
    assert client.models.calls[0]["config"].http_options.timeout == 240000
    prov = lead.last_model_provenance
    assert prov["model"] == ARGON and prov["fallback"] and prov["fallback_reason"] == "TIMEOUT"


def test_lead_primary_fast_negative_one_call():
    clock = Clock()
    client = Client({CARBON: (89, response(json.dumps(GOOD_PLAN)))}, clock.advance)
    lead = _lead(client, clock)
    with patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent", return_value=list(CHAIN)):
        lead.decompose_specification(product_id=SVC, spec_text="x" * 2000, task_dag=[{}, {}])
    assert [c["model"] for c in client.models.calls] == [CARBON]
    assert lead.last_model_provenance["fallback"] is False


def test_lead_every_model_slow_is_typed_not_the_deterministic_plan():
    clock = Clock()
    client = Client({m: (999, response(json.dumps(GOOD_PLAN))) for m in CHAIN}, clock.advance)
    lead = _lead(client, clock)
    with patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent", return_value=list(CHAIN)):
        with pytest.raises(T.LlmFallbackExhausted) as e:
            lead.decompose_specification(product_id=SVC, spec_text="x" * 2000, task_dag=[{}, {}])
    assert e.value.purpose == T.CallPurpose.WBS and len(e.value.attempts) == 4


# ------------------------------------------------------------------------------------------------ single turn
def test_single_turn_s13_all_models_time_out_is_typed_with_attempts():
    httpx = pytest.importorskip("httpx")
    from developer_agent import handler as H
    from developer_agent.handler import DeveloperAgent
    client = Client({"model-a": (0, httpx.ReadTimeout("t")), "model-b": (0, httpx.ReadTimeout("t"))})
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "ENABLE_DEVELOPER_SWARM": "false"}):
        agent = DeveloperAgent()
        agent.model_name = "model-a"
        agent.genai_client = client
        with patch.object(agent, "fetch_existing_repo_files", return_value={}), \
                patch.object(agent, "update_build_step_status"), \
                patch.object(H, "get_model_cascade_for_agent", return_value=["model-a", "model-b"]), \
                patch.object(H, "wait_for_rate_limit_cooldown", return_value=True):
            with pytest.raises(T.LlmFallbackExhausted) as e:
                agent.generate_code_files(product_id="noapp", spec_text="An app", task_dag=[],
                                          allow_unauthenticated=True, enable_direct_iap=False,
                                          domain_restricted_sharing=False)
    assert e.value.error_class == LLM_UNAVAILABLE and e.value.purpose == T.CallPurpose.SINGLE_TURN
    assert [a.model for a in e.value.attempts] == ["model-a", "model-b"]
    assert len(client.models.calls) == 2   # timeouts prune the model: no cooldown cycles re-ask a slow model
    assert client.models.calls[0]["config"].http_options.timeout == 900000


# ------------------------------------------------------------------------------------------------ sync endpoint
@pytest.mark.parametrize("budget", [False, True])
def test_sync_developer_answers_the_walk_errors_typed(budget):
    """The workflow's build_failure types any non-2xx JSON body with an error_class (no YAML change)."""
    pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
    from test_step1_typed_failures import _gateway_main
    gw = _gateway_main()
    attempts = [T.CallAttempt(CARBON, "TIMEOUT", 420, 420.5, usage="UNKNOWN")]
    exc = (T.LlmStageBudgetExhausted("developer", T.CallPurpose.JUNIOR, attempts) if budget
           else T.LlmFallbackExhausted("developer", T.CallPurpose.JUNIOR, attempts))
    req = gw.DeveloperExecuteRequest(product_id="shop", trace_id="trace-slow")
    with patch.object(gw, "_execute_developer_logic", side_effect=exc), patch.object(gw, "db", None):
        resp = gw.developer_execute(req)
    body = json.loads(resp.body)
    assert resp.status_code == (504 if budget else 503)
    assert body["status"] == "FAILED" and body["stage"] == "developer"
    assert body["error_class"] == (LLM_STAGE_BUDGET_EXHAUSTED if budget else LLM_UNAVAILABLE)
    assert body["reason"] == (LLM_STAGE_BUDGET_EXHAUSTED if budget else "LLM_FALLBACK_EXHAUSTED")
    assert body["attempts"][0]["model"] == CARBON and body["attempts"][0]["outcome"] == "TIMEOUT"



def test_single_turn_fallback_is_recorded_as_who_wrote_what():
    httpx = pytest.importorskip("httpx")
    from _lane19_fake_genai import canned_workload_files
    from developer_agent import handler as H
    from developer_agent.handler import DeveloperAgent
    good = SimpleNamespace(text=json.dumps({"files": canned_workload_files("noapp")}), candidates=[],
                           usage_metadata=None)
    client = Client({"model-a": (0, httpx.ReadTimeout("t")), "model-b": (0, good)})
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "ENABLE_DEVELOPER_SWARM": "false"}):
        agent = DeveloperAgent()
        agent.model_name = "model-a"
        agent.genai_client = client
        with patch.object(agent, "fetch_existing_repo_files", return_value={}), \
                patch.object(agent, "update_build_step_status"), \
                patch.object(H, "get_model_cascade_for_agent", return_value=["model-a", "model-b"]):
            files = agent.generate_code_files(product_id="noapp", spec_text="An app", task_dag=[],
                                              allow_unauthenticated=True, enable_direct_iap=False,
                                              domain_restricted_sharing=False)
    assert files
    rec = agent.stack_run(None)["model_provenance"]
    assert rec["summary"] == "written by model-b (fallback: timeout)"
    assert rec["outputs"][0]["primary_model"] == "model-a" and rec["outputs"][0]["output"] == "single_turn"


def test_provenance_summary_when_every_output_is_one_fallback():
    rec = T.model_provenance_record([{"output": "wbs", "model": ARGON, "fallback": True, "fallback_reason": "TIMEOUT"},
                                     {"output": "t1", "model": ARGON, "fallback": True, "fallback_reason": "TIMEOUT"}])
    assert rec["summary"] == f"written by {ARGON} (fallback: timeout)" and rec["mixed"] is False


@pytest.mark.parametrize("over,used", [(1.0, True), (T.LATE_GRACE_S, True), (T.LATE_GRACE_S + 0.5, False)])
def test_f4_an_answer_just_after_the_cap_is_used_not_redone(over, used):
    """RT F4 (negative): the walk's clock includes credential refresh / connect / parse, so an answer within the
    grace after the cap is the SDK's accepted answer and is used; only a later one is discarded."""
    clock = Clock()
    cap = T.DEFAULT_CALL_TIMEOUTS.junior_s
    client = Client({CARBON: (cap + over, response(FILES)), ARGON: (10, response(FILES))}, clock.advance)
    walk = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock)
    _walk_once(walk, client)
    assert (walk.answered_model == CARBON) is used
    assert len(client.models.calls) == (1 if used else 2)


def test_f10_one_same_model_retry_on_429_then_walk():
    clock = Clock()
    seq = []

    def carbon(contents):
        seq.append(1)
        return (1, Status(429)) if len(seq) == 1 else (1, response(FILES))

    client = Client({CARBON: carbon, ARGON: (1, response(FILES))}, clock.advance)
    walk = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock)
    waits = []
    for plan in walk:
        waits.append(plan.backoff_s)
        try:
            r = client.models.generate_content(model=plan.model, contents="p", config=walk.config(plan, {}))
        except Exception as e:  # noqa: BLE001
            assert walk.failed(plan, e)
            continue
        if walk.answered(plan, r):
            break
    assert waits == [0.0, T.RETRY_BACKOFF_S[0]] and walk.answered_model == CARBON and walk.fallback_reason is None


@pytest.mark.parametrize("first", [Status(500), Status(504)])
def test_f10_a_500_or_a_504_below_the_bound_walks_at_once(first):
    clock = Clock()
    client = Client({CARBON: (1, first), ARGON: (1, response(FILES))}, clock.advance)
    walk = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock)
    _walk_once(walk, client)
    assert [c["model"] for c in client.models.calls] == [CARBON, ARGON]


def test_f10_switch_off_walks_at_once():
    clock = Clock()
    client = Client({CARBON: (1, Status(429)), ARGON: (1, response(FILES))}, clock.advance)
    with patch.object(T, "SAME_MODEL_TRANSIENT_RETRY", False):
        walk = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock)
        _walk_once(walk, client)
    assert [c["model"] for c in client.models.calls] == [CARBON, ARGON]


def test_f10_lead_retries_a_429_once_on_the_same_model():
    clock, slept = Clock(), []
    seq = []

    def carbon(contents):
        seq.append(1)
        return (1, Status(429)) if len(seq) == 1 else (80, response(json.dumps(GOOD_PLAN)))

    client = Client({CARBON: carbon, ARGON: (1, response(json.dumps(GOOD_PLAN)))}, clock.advance)
    lead = _lead(client, clock)
    lead._sleep = slept.append
    with patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent", return_value=list(CHAIN)):
        lead.decompose_specification(product_id=SVC, spec_text="x" * 2000, task_dag=[{}, {}])
    assert [c["model"] for c in client.models.calls] == [CARBON, CARBON] and slept == [T.RETRY_BACKOFF_S[0]]
    assert lead.last_model_provenance["model"] == CARBON and lead.last_model_provenance["fallback"] is False


def test_f7_repair_model_outside_the_cascade_falls_back_to_the_fallbacks_only():
    from developer_agent.swarm_dispatcher import SwarmDispatcher, _chain_after
    assert _chain_after(FLASH37, [CARBON, ARGON, FLASH38]) == [FLASH37, ARGON, FLASH38]
    assert _chain_after(ARGON, [CARBON, ARGON, FLASH38]) == [ARGON, FLASH38]
    assert _chain_after(CARBON, [CARBON, ARGON]) == [CARBON, ARGON]
    clock = Clock()
    client = Client({"cheap-model": (1, Status(500)), ARGON: (1, response(FILES))}, clock.advance)
    d = SwarmDispatcher(genai_client=client)
    d._clock = clock
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=[CARBON, ARGON]):
        out = d.invoke_repair("IAC", "sys", "prompt", "cheap-model", 9000)
    assert [c["model"] for c in client.models.calls] == ["cheap-model", ARGON] and out["model"] == ARGON


def test_f6_repair_walk_is_bounded_by_the_repair_wall_clock():
    """RT F6: one iteration's walk cannot outlive the dispatch's repair wall clock (checked by the loop only between
    iterations). Its end is reported (the loop then stops on WALL_CLOCK), not raised as a stage stop."""
    from developer_agent.swarm_dispatcher import SwarmDispatcher
    clock = Clock()
    client = Client({CARBON: (100, response(FILES)), ARGON: (10, response(FILES))}, clock.advance)
    d = SwarmDispatcher(genai_client=client)
    d._clock = clock
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=list(CHAIN)):
        out = d.invoke_repair("IAC", "sys", "prompt", CARBON, 9000, repair_deadline=clock() + 100,
                              deadline=clock() + 5000)
    assert client.models.calls[0]["config"].http_options.timeout == 85000   # 100 s left - 15 s margin < 180 s cap
    assert out["error_code"] == "REPAIR_WALL_CLOCK" and [c["model"] for c in client.models.calls] == [CARBON]



class _StageStop(Exception):
    """Stand-in for G7's typed STAGE_DEADLINE_EXCEEDED stop (a GateError there)."""


def test_f5_an_active_stage_deadline_stops_with_its_own_class():
    clock = Clock()
    labels = []

    def stop(label):
        labels.append(label)
        return _StageStop(label)

    client = Client({CARBON: (1, response(FILES))}, clock.advance)
    walk = T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock, deadline=clock() + 30, stage_stop=stop)
    with pytest.raises(_StageStop):
        _walk_once(walk, client)
    assert client.models.calls == [] and labels == [f"before developer.JUNIOR call ({CARBON})"]
    # no stage stop given (direct callers): LlmStageBudgetExhausted, as before
    with pytest.raises(T.LlmStageBudgetExhausted):
        _walk_once(T.CallWalk(CHAIN, purpose=T.CallPurpose.JUNIOR, clock=clock, deadline=clock() + 30), client)


def test_f5_repair_wall_clock_end_is_never_reported_as_a_stage_stop():
    from developer_agent.swarm_dispatcher import SwarmDispatcher
    clock = Clock()
    d = SwarmDispatcher(genai_client=Client({CARBON: (1, response(FILES))}, clock.advance))
    d._clock = clock
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=list(CHAIN)):
        out = d.invoke_repair("IAC", "sys", "prompt", CARBON, 9000, repair_deadline=clock() + 10,
                              deadline=clock() + 5000, stage_stop=lambda label: _StageStop(label))
        assert out["error_code"] == "REPAIR_WALL_CLOCK"
        with pytest.raises(_StageStop):
            d.invoke_repair("IAC", "sys", "prompt", CARBON, 9000, deadline=clock() + 10,
                            stage_stop=lambda label: _StageStop(label))



def test_f8_a_recorded_timeout_or_status_replays_as_the_same_typed_error():
    """RT F8: record and replay walk the same way (a recorded 429 / timeout is not a plain RuntimeError)."""
    httpx = pytest.importorskip("httpx")
    sys.path.insert(0, os.path.join(REPO, "eval"))
    from stackvend_eval.llm_proxy import recorded_error
    t = recorded_error({"type": "ReadTimeout", "message": "read timed out"})
    assert isinstance(t, httpx.ReadTimeout) and T.is_timeout_exception(t)
    q = recorded_error({"type": "ClientError", "message": "429 RESOURCE_EXHAUSTED", "code": 429})
    assert T.transient_status(q) == 429
    assert T.transient_status(recorded_error({"type": "ServerError", "message": "x", "code": 503})) == 503
    # a cassette recorded before the code was kept replays exactly as before
    old = recorded_error({"type": "ClientError", "message": "429 RESOURCE_EXHAUSTED"})
    assert type(old) is RuntimeError and T.transient_status(old) is None
    assert type(recorded_error({"type": "ValueError", "message": "x"})) is RuntimeError


def test_f11_legacy_async_route_carries_the_typed_walk_error():
    pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
    from test_step1_typed_failures import _gateway_main
    gw = _gateway_main()
    sent = []
    exc = T.LlmFallbackExhausted("developer", T.CallPurpose.JUNIOR,
                                 [T.CallAttempt(CARBON, "TIMEOUT", 900, 900.5, usage="UNKNOWN")])
    req = gw.DeveloperExecuteRequest(product_id="shop", trace_id="trace-f11",
                                     callback_url="https://workflowexecutions.googleapis.com/v1/x/callbacks/c")
    with patch.object(gw, "_execute_developer_logic", side_effect=exc), patch.object(gw, "db", None), \
            patch.object(gw.CallbackDeliveryClient, "send_callback", side_effect=lambda **kw: sent.append(kw["payload"])):
        with pytest.raises(T.LlmFallbackExhausted):
            gw.run_developer_execute_in_background(req)
    out = sent[0]
    assert out["status"] == "FAILED" and out["error_class"] == LLM_UNAVAILABLE
    assert out["reason"] == "LLM_FALLBACK_EXHAUSTED" and out["stage"] == "developer"
    assert out["attempts"][0]["model"] == CARBON


# ------------------------------------------------------------------------------------------------ with G7 (RT F3)
def test_f3_active_stage_deadline_bounds_the_walk_and_stops_typed():
    import stage_deadline as sdm
    clock = Clock()
    sd = sdm.StageDeadline(sdm.budget_for("developer", sdm.StageMode.SYNC), trace_id="t", product_id="p")
    deadline, stop = T.active_stage_bound(None, None, clock)
    assert deadline is None and stop is None   # no active stage: unchanged
    tok = sdm._CURRENT.set(sd)
    try:
        deadline, stop = T.active_stage_bound(None, None, clock)
        assert abs(deadline - (clock() + sd.remaining_s())) < 5 and stop == sd.exceeded
        assert isinstance(stop("before developer.JUNIOR call"), sdm.STOP_ERRORS)
    finally:
        sdm._CURRENT.reset(tok)


def test_f3_a_stage_stop_inside_the_repair_walk_is_raised_not_reported():
    import stage_deadline as sdm
    from developer_agent.swarm_dispatcher import SwarmDispatcher
    clock = Clock()
    d = SwarmDispatcher(genai_client=Client({CARBON: (1, response(FILES))}, clock.advance))
    d._clock = clock
    stop = sdm.StageDeadline(sdm.budget_for("developer", sdm.StageMode.SYNC)).exceeded("test")
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=list(CHAIN)), \
            patch("developer_agent.swarm_dispatcher.stage_deadline.checkpoint", side_effect=stop):
        with pytest.raises(sdm.STOP_ERRORS):
            d.invoke_repair("IAC", "sys", "prompt", CARBON, 9000)
    assert d.genai_client.models.calls == []
