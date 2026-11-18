"""TI-3i-c (register FOLLOWUPS-1025, owner 10-25): before a plan-named stop (IAC.REQUESTED_SERVICE_DROPPED; TI-3i-e's
IAC.PLAN_API_NOT_PROVIDED once it is wired, held for 0.9.1) the IaC persona gets ONE repair turn with the stop as a
finding on the intent, naming the typed ways to provide what is missing (exact tables). A candidate that passes
ships; otherwise the typed stop is raised as before. No typed way / no repair model / an intent the run may not edit:
no turn, no LLM call. A build that does not stop never gets a turn (Do No Harm). Hermetic (no network, no LLM)."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

import test_ti3i_dropped_entries as D  # noqa: E402
import test_typed_iac_ti3_contract as T3  # noqa: E402
from developer_agent import iac_intent_contract as C  # noqa: E402
from shared.diagnostics import ErrorClass, StageError, fingerprint  # noqa: E402

ART = D.ART
AI = "aiplatform.googleapis.com"
OFF = "discoveryengine.googleapis.com"
VERTEX = D.VERTEX
VERTEX_ADDR = "google_vertex_ai_endpoint.ep"


def gen(draft_intent, repairs, plan_apis):
    draft = dict(T3.APP, **{C.INTENT_PATH: draft_intent})
    att = {p: ("IAC_ENGINEER" if p == C.INTENT_PATH else "BACKEND_ENGINEER") for p in draft}
    orig = T3.record_of
    agents = []
    with patch.object(T3, "record_of", lambda raw: {**orig(raw), "required_cloud_apis": list(plan_apis)}):
        try:
            files, agent, _c, seen = T3._generate("generate", draft, att, repairs=list(repairs),
                                                  repair_max_iterations_precommit=1, agent_out=agents)
            return files, agent, None, seen
        except StageError as e:
            return None, agents[0], e, None


def test_a_plan_named_drop_gets_the_turn_and_its_replacement_ships_with_the_warning():
    first = D.intent([T3.BUCKET_MODULE])                                     # repair 1 drops the endpoint
    fixed = D.intent([T3.BUCKET_MODULE], api_only=[AI])                       # the turn adds the api_only entry
    files, agent, err, seen = gen(D.intent([T3.BUCKET_MODULE], [VERTEX]), [{C.INTENT_PATH: first},
                                                                           {C.INTENT_PATH: fixed}], [AI])
    assert err is None, err
    assert len(seen["repair_tasks"]) == 2
    turn = seen["repair_tasks"][1]
    assert turn["persona"] == "IAC_ENGINEER" and C.REQUESTED_SERVICE_DROPPED in turn["prompt"]
    assert '{\\"service\\": \\"aiplatform.googleapis.com\\"}' in turn["prompt"]   # the typed way, as a hint
    run = agent.stack_run("t-ti3")
    assert run["intent_repair_turn"]["result"] == "PASSED"
    (w,) = run["iac_intent_warnings"]
    assert w["address"] == VERTEX_ADDR and w["stops_build"] is False and w["missing"] == []


def test_a_turn_that_does_not_fix_it_ends_in_the_typed_stop():
    first = D.intent([T3.BUCKET_MODULE])
    files, agent, err, _seen = gen(D.intent([T3.BUCKET_MODULE], [VERTEX]), [{C.INTENT_PATH: first},
                                                                            {C.INTENT_PATH: first}], [AI])
    assert files is None and err.error_class is ErrorClass.PLATFORM_DEFECT
    assert [d.code for d in err.report.diagnostics] == [C.REQUESTED_SERVICE_DROPPED]
    run = agent.stack_run("t-ti3")
    assert run["intent_repair_turn"]["ran"] is True and run["intent_repair_turn"]["result"] == "NOT_FIXED"
    turns = [e for e in run["repair_events"] if getattr(e, "kind", None) != "junior_reask"]
    assert len(turns) == 2 and turns[0].accepted is True and turns[1].accepted is False   # one turn, rejected


def test_no_typed_way_means_no_turn_and_no_repair_call():
    """A drop whose plan API nothing in the platform can provide stops at once: no turn is spent."""
    files, agent, err, _seen = gen(D.intent([T3.BUCKET_MODULE], [D.DOCS]),
                                   [{C.INTENT_PATH: D.intent([T3.BUCKET_MODULE])}], [OFF])
    assert [d.code for d in err.report.diagnostics] == [C.REQUESTED_SERVICE_DROPPED]
    assert "intent_repair_turn" not in agent.stack_run("t-ti3")   # nothing was asked
    turns = [e for e in agent.stack_run("t-ti3")["repair_events"] if getattr(e, "kind", None) != "junior_reask"]
    assert len(turns) == 1                                        # only the first loop's repair


def test_a_build_that_does_not_stop_never_gets_a_turn():
    files, agent, err, seen = gen(D.intent([T3.BUCKET_MODULE], [D.DOCS]),
                                  [{C.INTENT_PATH: D.intent([T3.BUCKET_MODULE])}], ["run.googleapis.com"])
    assert err is None and len(seen["repair_tasks"]) == 1                    # only the first loop's repair
    assert "intent_repair_turn" not in agent.stack_run("t-ti3")


# ------------------------------------------------------------------------------------------------ units
def _warnings(plan_apis, final_intent=None, dropped=()):
    """The stopping warnings of both outcome functions, called directly (independent of what intent_outcome wires)."""
    tree = {C.INTENT_PATH: final_intent or D.intent(), D.W + "main.tf": ""}
    w, _s = C.dropped_entry_outcome(list(dropped), tree, None, plan_apis, ART)
    named = {a for x in w if x.get("stops_build") for a in x.get("missing_apis") or ()}
    return w + C.plan_api_outcome(tree, plan_apis, ART, already=named)[0]


def test_seeds_only_for_stopping_warnings_with_a_typed_way():
    assert C.repair_turn_seeds(_warnings(()), ART) == []
    assert C.repair_turn_seeds(_warnings((OFF,)), ART) == []                 # stops, but no typed way
    (s,) = C.repair_turn_seeds(_warnings((AI, OFF)), ART)
    assert (s.code, s.error_class, s.file, s.symbol) == (C.PLAN_API_NOT_PROVIDED, ErrorClass.CODE_DEFECT,
                                                         C.INTENT_PATH, AI)
    assert '"service": "%s"' % AI in s.hint
    assert "ai-vertex-endpoint" not in s.hint   # review F2: a missing API is offered as pure enablement only
    not_stopping = [{**w, "stops_build": False} for w in _warnings((AI,))]
    assert C.repair_turn_seeds(not_stopping, ART) == []


def _api_stop(api):
    return {"stops_build": True, "kind": "plan_api", "address": api, "service": api, "missing_apis": [api],
            "type": None, "realizes": None, "message": f"the architect's plan needs {api}"}


def test_a_missing_api_with_only_module_or_resource_providers_gets_no_seed():
    """Review F2: a module or allow-listed resource that merely needs the API would add unrequested infrastructure,
    so the turn offers only an api_only row; the operator hint (plan_api_outcome) keeps the full list."""
    rt_only = {"api_only": [], "modules": [], "resource_types": ["google_logging_metric"]}
    with patch.object(C, "api_providers", lambda api, art: rt_only):
        assert C.repair_turn_seeds([_api_stop("logging.googleapis.com")], ART) == []
    sm = "secretmanager.googleapis.com"                       # real tables: modules + resource types, no api_only row
    assert C.api_providers(sm, ART)["modules"] and C.api_providers(sm, ART)["resource_types"]
    assert C.repair_turn_seeds([_api_stop(sm)], ART) == []
    _w, (d,) = C.plan_api_outcome({C.INTENT_PATH: D.intent()}, (sm,), ART)
    assert "security-secret" in d.hint and "google_secret_manager_secret" in d.hint   # operator hint: full list
    (s,) = C.repair_turn_seeds([_api_stop(AI)], ART)          # an api_only row: seeded
    assert s.symbol == AI


def test_seed_identity_is_stable_across_candidates():
    a = C.repair_turn_seeds(_warnings((AI,)), ART)
    b = C.repair_turn_seeds(_warnings((AI,), final_intent=D.intent([T3.BUCKET_MODULE])), ART)
    assert [fingerprint(x) for x in a] == [fingerprint(x) for x in b]
    dropped = D.drops(D.intent(resources=[VERTEX]), VERTEX_ADDR)
    (s,) = C.repair_turn_seeds(_warnings((AI,), dropped=dropped), ART)
    assert s.code == C.REQUESTED_SERVICE_DROPPED and s.block_address == VERTEX_ADDR


def test_no_turn_when_the_run_may_not_edit_the_intent_or_has_no_repair_model():
    from developer_agent import handler as h
    recorded = {}
    agent = SimpleNamespace(stack_run=lambda t: {"plan_required_apis": [AI]},
                            _record_stack=lambda t, **k: recorded.update(k))
    inputs = SimpleNamespace(trace_id="t", product_id="p", compute_intent=SimpleNamespace(topology=None),
                             iac_intent=SimpleNamespace(artifacts=ART))
    tree = {C.INTENT_PATH: D.intent()}
    drops = list(D.drops(D.intent(resources=[VERTEX]), VERTEX_ADDR))   # a plan-named drop with a typed way
    never = SimpleNamespace(run=lambda d: (_ for _ in ()).throw(AssertionError("no turn expected")))
    for ctx, reason in ((SimpleNamespace(repair_fn=None, repairable_paths=None, intent_drops=drops),
                         "NO_REPAIR_MODEL"),
                        (SimpleNamespace(repair_fn=print, repairable_paths=frozenset({"apps/x/main.py"}),
                                         intent_drops=drops), "INTENT_NOT_REPAIRABLE")):
        out = h.DeveloperAgent._intent_repair_turn(agent, inputs, ctx, SimpleNamespace(final_draft={}), tree,
                                                   "report", lambda c: never)
        assert out == (tree, "report") and recorded["intent_repair_turn"]["reason"] == reason
