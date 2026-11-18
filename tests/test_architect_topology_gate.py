"""Lane 10 (FD-51) stage 2: the architect's service-topology gate (plan R2 §5; RT F4, F5, F14; owner Q-B).

T-18/T-19 one patch repair, counted on the generate_content mock, never a second decompose; T-20 the fallback plan
never passes; T-21 google-genai keeps the nested schema; T-34 a failed record write fails the stage; the remediation
brief carries the draft's typed compute decision (Q-B, example 05); a map-reduce plan without a topology gets the
one repair. Hermetic: fake genai client, in-memory Firestore stand-ins."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from architect_agent.schemas import ArchitecturePlan, ArchitecturePlanDAG  # noqa: E402
from architect_agent.topology_gate import TopologyInvalidError, gate_service_topology  # noqa: E402
from shared.service_topology import ServiceTopologyIntent  # noqa: E402

BASE = {"product_id": "shop", "summary": "s", "architecture_overview": "o", "infra_tasks": [], "code_tasks": [],
        "target_compute_services": ["api", "core"], "compute_archetype": "cloudrun", "iac_engine": "tofu"}
GOOD = {"services": [{"name": "api", "kind": "cloudrun"}, {"name": "core", "kind": "cloudrun"}],
        "primary_service": "api", "edges": [{"caller": "api", "callee": "core", "protocol": "http"}], "resources": []}
RING = {**GOOD, "edges": [{"caller": "api", "callee": "core"}, {"caller": "core", "callee": "api"}]}


class _Client:
    """Fake genai client: the architect plan call answers `plan`; topology-repair calls (response_schema is
    ServiceTopologyIntent) answer from `repairs` in order. Every call is recorded."""

    def __init__(self, plan, repairs=()):
        self.plan = plan
        self.repairs = list(repairs)
        self.calls = []
        self.models = SimpleNamespace(generate_content=self._gen)

    def _gen(self, model, contents, config):
        schema = getattr(config, "response_schema", None)
        self.calls.append(("repair" if schema is ServiceTopologyIntent else "plan", model, contents))
        if schema is ServiceTopologyIntent:
            ans = self.repairs.pop(0)
        else:
            ans = self.plan
        return SimpleNamespace(text=ans if isinstance(ans, str) else json.dumps(ans), candidates=[],
                               usage_metadata=None)


class _DB:
    def __init__(self, fail=False):
        self.fail = fail
        self.writes = []

    def collection(self, c):
        db = self

        class _Doc:
            def __init__(self, d):
                self.d = d

            def set(self, payload, merge=False):
                if db.fail:
                    raise RuntimeError("firestore down")
                db.writes.append((c, self.d, payload, merge))

            def collection(self, *_a):
                return MagicMock()

        return SimpleNamespace(document=lambda d: _Doc(d))


@pytest.fixture()
def architect(monkeypatch):
    for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "PROJECT_ID", "K_SERVICE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ENABLE_DUAL_ARCHITECT_CONSENSUS", "false")
    fake_fs = SimpleNamespace(Client=lambda *a, **kw: MagicMock(), Increment=lambda n: ("INC", n))
    import google.cloud  # noqa: F401
    monkeypatch.setattr(sys.modules["google.cloud"], "firestore", fake_fs, raising=False)
    monkeypatch.setitem(sys.modules, "google.cloud.firestore", fake_fs)
    from architect_agent import handler as h
    monkeypatch.setattr(h.ArchitectAgent, "persist_build_plan_to_firestore", lambda self, *a, **kw: True)
    monkeypatch.setattr(h.ArchitectAgent, "persist_implementation_plan_to_firestore", lambda self, *a, **kw: True)
    monkeypatch.setattr(h, "get_model_cascade_for_agent", lambda *a, **kw: ["model-a"])
    monkeypatch.setattr(h, "build_architect_system_prompt", lambda **kw: "RENDERED ARCHITECT PROMPT")
    monkeypatch.setitem(sys.modules, "vertexai", None)
    agent = h.ArchitectAgent(project_id="")
    agent.project_id = ""
    agent.model_name = "model-a"
    agent.model = None
    agent.spec_decomposer = None
    return h, agent


def _run(agent, **kw):
    return agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="t-10", **kw)


# ------------------------------------------------------------------------------------------------ happy path
def test_valid_topology_passes_without_repair_and_reaches_the_v2_record(architect):
    h, agent = architect
    agent.genai_client = _Client({**BASE, "service_topology": GOOD})
    res = _run(agent)
    assert [c[0] for c in agent.genai_client.calls] == ["plan"]
    rec = res.compute_intent
    assert rec["schema"] == "architect_compute_intent/v2"
    assert rec["target_compute_services"] == ["api", "core"] and rec["compute_archetype"] == "cloudrun"
    assert rec["service_topology"]["intent"]["edges"][0]["callee"] == "core"
    assert rec["topology_provenance"]["repaired"] is False
    assert res.architecture_plan.service_topology == ServiceTopologyIntent.model_validate(GOOD)


def test_t34_record_is_persisted_inside_the_gate_and_a_failed_write_fails_the_stage(architect):
    h, agent = architect
    agent.project_id = "p"
    agent.db = _DB()
    agent.genai_client = _Client({**BASE, "service_topology": GOOD})
    res = _run(agent)
    ci = [w for w in agent.db.writes if "architect_compute_intent" in w[2]]
    # RT14-30: field-path merge, so the whole record is replaced (never deep-merged with an earlier run's record)
    assert [(w[0], w[1], w[3]) for w in ci] == [("pipeline_executions", "t-10",
                                                 ["architect_compute_intent", "stages.architect.repair_events"])]
    assert ci[0][2]["stages"] == {"architect": {"repair_events": []}}   # RT14 RT F4: no repair turn, events cleared
    assert ci[0][2]["architect_compute_intent"] == res.compute_intent
    agent.db = _DB(fail=True)
    agent.genai_client = _Client({**BASE, "service_topology": GOOD})
    with pytest.raises(h.GateUnavailableError) as ei:
        _run(agent)
    assert ei.value.reason == "ARCHITECT_TOPOLOGY_PERSIST_FAILED"
    assert ei.value.to_body()["error_class"] == "GATE_UNAVAILABLE"


# ------------------------------------------------------------------------------------------------ repair
def test_t18_ring_gets_exactly_one_patch_repair_then_passes(architect):
    h, agent = architect
    agent.project_id = "p"
    agent.db = _DB()
    agent.genai_client = _Client({**BASE, "service_topology": RING}, repairs=[GOOD])
    res = _run(agent)
    kinds = [c[0] for c in agent.genai_client.calls]
    assert kinds == ["plan", "repair"]                      # one plan call, one patch call, no second decompose
    prompt = agent.genai_client.calls[1][2]
    assert "TOPOLOGY.CYCLE" in prompt and "PREVIOUS service_topology" in prompt and "Build a shop" not in prompt
    assert res.compute_intent["topology_provenance"]["repaired"] is True
    events = [w[2]["stages"]["architect"]["repair_events"] for w in agent.db.writes if "stages" in w[2]
              and "repair_events" in w[2]["stages"].get("architect", {})]
    assert len(events) == 1 and events[0][0]["source"] == "architect" and events[0][0]["accepted"] is True
    assert events[0][0]["codes"] == ["TOPOLOGY.CYCLE"]


def test_t18_ring_twice_fails_typed_422_with_diagnostics(architect):
    h, agent = architect
    agent.genai_client = _Client({**BASE, "service_topology": RING}, repairs=[RING])
    with pytest.raises(TopologyInvalidError) as ei:
        _run(agent)
    assert [c[0] for c in agent.genai_client.calls] == ["plan", "repair"]
    err = ei.value
    body = err.to_body()
    assert err.http_status == 422 and body["error_class"] == "ARCHITECT_DEFECT"
    assert body["reason"] == "ARCHITECT_TOPOLOGY_INVALID"
    assert [d["code"] for d in body["diagnostics"]] == ["TOPOLOGY.CYCLE"]
    assert body["details"]["diagnostics"] == body["diagnostics"]          # RT F14: also in details (DLQ)
    assert body["details"]["repair_event"]["accepted"] is False
    assert "core -> api" in body["summary"] or "api -> core" in body["summary"]


def test_malformed_topology_is_diagnostics_not_a_plan_wide_fallback(architect):
    h, agent = architect
    bad = {**GOOD, "services": [{"name": "${var.product_id}-api", "kind": "cloudrun"}]}
    fallback = []
    agent._fallback_plan = lambda *a: fallback.append(a)
    agent.genai_client = _Client({**BASE, "service_topology": bad}, repairs=[GOOD])
    res = _run(agent)
    assert fallback == [] and res.compute_intent["target_compute_services"] == ["api", "core"]
    assert "TOPOLOGY.SCHEMA_INVALID" in agent.genai_client.calls[1][2]


def test_archetype_mismatch_is_repaired_never_resolved_by_picking_one(architect):
    h, agent = architect
    gke = {"services": [{"name": "proc", "kind": "gke-autopilot"}, {"name": "edge", "kind": "cloudrun"}],
           "primary_service": "proc"}
    agent.genai_client = _Client({**BASE, "compute_archetype": "gke-autopilot",
                                  "service_topology": {**gke, "primary_service": "edge"}}, repairs=[gke])
    res = _run(agent)
    assert "TOPOLOGY.ARCHETYPE_MISMATCH" in agent.genai_client.calls[1][2]
    assert res.compute_intent["compute_archetype"] == "gke-autopilot"
    assert res.compute_intent["target_compute_services"] == ["proc", "edge"]


def test_t20_fallback_plan_never_passes_and_gets_no_repair(architect):
    h, agent = architect
    agent.genai_client = _Client("{not json")                     # unparseable -> deterministic fallback plan
    with pytest.raises(TopologyInvalidError) as ei:
        _run(agent)
    assert [c[0] for c in agent.genai_client.calls] == ["plan"]   # no repair call for a fallback plan
    assert [d["code"] for d in ei.value.diagnostics] == ["TOPOLOGY.MISSING"]


def test_no_llm_client_fails_typed(architect):
    """RT F7: no model answered at all -> an outage (GATE_UNAVAILABLE, 503), not an architect defect."""
    h, agent = architect
    agent.genai_client = None
    with pytest.raises(h.GateUnavailableError) as ei:
        _run(agent)
    assert not isinstance(ei.value, TopologyInvalidError)
    assert ei.value.reason == "ARCHITECT_NO_MODEL_RESPONSE" and ei.value.to_body()["error_class"] == "GATE_UNAVAILABLE"


def test_rt_f7_every_model_erroring_is_unavailable_but_an_unparseable_answer_is_a_defect(architect):
    h, agent = architect

    class _Down:
        def __init__(self):
            self.models = self

        def generate_content(self, **kw):
            raise ValueError("400 INVALID_ARGUMENT: bad request")   # non-transient: no cooldown
    agent.genai_client = _Down()
    with pytest.raises(h.GateUnavailableError) as ei:
        _run(agent)
    assert ei.value.reason == "ARCHITECT_NO_MODEL_RESPONSE" and ei.value.http_status == 503
    agent.genai_client = _Client("{not json")
    with pytest.raises(TopologyInvalidError):
        _run(agent)


def test_map_reduce_plan_without_topology_gets_the_one_repair(architect):
    h, agent = architect
    agent.genai_client = _Client({**BASE}, repairs=[GOOD])
    reduced = ArchitecturePlanDAG(**{k: v for k, v in BASE.items()})
    agent.spec_decomposer = SimpleNamespace(should_activate_map_reduce=lambda text: True,
                                            decompose_large_specification=lambda text, prod, context=None: reduced)
    res = _run(agent)
    assert [c[0] for c in agent.genai_client.calls] == ["repair"]  # no single-turn call, one patch call
    assert "TOPOLOGY.MISSING" in agent.genai_client.calls[0][2]
    assert res.compute_intent["service_topology"]["service_names"] == ["api", "core"]


def test_t19_gate_runs_after_consensus_and_escapes_it(architect, monkeypatch):
    """The gate is outside both former swallow sites (consensus `except` and decompose's 'Proceeding with draft'):
    a topology still invalid after its repair always reaches the caller."""
    h, agent = architect
    monkeypatch.setenv("ENABLE_DUAL_ARCHITECT_CONSENSUS", "true")
    seen = []

    class _Consensus:
        def evaluate_and_reconcile(self, plan, **kw):
            seen.append(plan)
            return plan, None
    agent.consensus_engine = _Consensus()
    agent.genai_client = _Client({**BASE, "service_topology": RING}, repairs=[RING])
    with pytest.raises(TopologyInvalidError):
        _run(agent)
    assert len(seen) == 1 and [c[0] for c in agent.genai_client.calls] == ["plan", "repair"]


def test_remediation_inner_decompose_skips_the_gate_and_carries_the_draft_decision():
    """Owner Q-B: the remediation brief states the draft's typed compute decision; the inner decompose never gates
    (the outer call gates the final plan once)."""
    from architect_agent.consensus_engine import DualArchitectConsensusEngine
    from shared.critic_schemas import ArchitecturalCritique
    eng = DualArchitectConsensusEngine.__new__(DualArchitectConsensusEngine)
    plan = ArchitecturePlan(**{**BASE, "compute_archetype": "gke-autopilot"})
    plan._raw_service_topology = {"services": [{"name": "proc", "kind": "gke-autopilot"}], "primary_service": "proc"}
    calls = []
    arch = SimpleNamespace(decompose=lambda **kw: calls.append(kw) or SimpleNamespace(architecture_plan=plan))
    critique = ArchitecturalCritique(soundness_score=0.2, has_critical_findings=True, findings=[
        {"category": "TOPOLOGY_AND_ORDERING", "severity": "CRITICAL", "description": "IAM before APIs",
         "recommended_remediation": "reorder"}], gauntlet_checks=[], verdict_summary="x")
    eng._execute_remediation_turn(plan=plan, critique=critique, spec_text="spec", architect_agent=arch,
                                  product_id="shop", trace_id="t")
    assert calls[0]["topology_gate"] is False and calls[0]["bypass_consensus"] is True
    brief = calls[0]["remediation_brief"]   # RT14-16: the critique's own block (operator feedback stays separate)
    assert "TYPED COMPUTE DECISION OF THE DRAFT" in brief and '"gke-autopilot"' in brief and '"proc"' in brief


# ------------------------------------------------------------------------------------------------ schema / unit
def test_t21_genai_keeps_the_nested_topology_schema():
    t = pytest.importorskip("google.genai._transformers")
    client = MagicMock()
    client.vertexai = True
    schema = t.t_schema(client, ArchitecturePlanDAG).model_dump(exclude_none=True)
    assert "service_topology" in schema["required"]
    topo = schema["properties"]["service_topology"]
    svc = topo["properties"]["services"]["items"]["properties"]
    assert svc["kind"]["enum"] == ["cloudrun", "event-worker", "gke-autopilot", "gce-bastion", "gce-worker"]
    edge = topo["properties"]["edges"]["items"]["properties"]
    assert edge["protocol"]["enum"] == ["http", "pubsub", "launch"]   # lane 10 L10-v
    assert svc["name"]["pattern"].startswith("^[a-z]")
    repair = t.t_schema(client, ServiceTopologyIntent).model_dump(exclude_none=True)
    assert repair["required"] == ["services", "primary_service"]


def test_gate_unit_repair_failure_keeps_the_original_diagnostics():
    plan = ArchitecturePlan(**BASE)
    plan._raw_service_topology = RING

    def boom(system, prompt):
        raise RuntimeError("vertex down")
    with pytest.raises(TopologyInvalidError) as ei:
        gate_service_topology(plan, product_id="shop", trace_id="t", repair_fn=boom)
    assert [d["code"] for d in ei.value.diagnostics] == ["TOPOLOGY.CYCLE"]


def test_gate_unit_valid_input_is_unchanged_do_no_harm():
    plan = ArchitecturePlan(**BASE)
    plan._raw_service_topology = json.loads(json.dumps(GOOD))
    before = json.dumps(plan._raw_service_topology, sort_keys=True)
    calls = []
    res = gate_service_topology(plan, product_id="shop", trace_id="t",
                                repair_fn=lambda *a: calls.append(a) or ("{}", "m", 0, 0))
    assert calls == [] and res.repaired is False
    assert json.dumps(plan._raw_service_topology, sort_keys=True) == before
    assert plan.service_topology.model_dump(mode="json") == ServiceTopologyIntent.model_validate(GOOD).model_dump(mode="json")


def test_prompt_contract_is_appended_to_any_base_prompt(monkeypatch):
    from architect_agent import prompt as ap
    import shared.prompt_resolver as resolver
    from shared.service_topology import render_topology_contract
    monkeypatch.setattr(resolver, "get_agent_system_prompt", lambda **kw: "OPERATOR OVERRIDE PROMPT")
    monkeypatch.setattr(ap, "resolve_active_skills", lambda **kw: [])
    monkeypatch.delenv("PROJECT_ID", raising=False)
    out = ap.build_architect_system_prompt(task_context="spec")
    # ARCHITECT-PYTHON-PIN: the runtime fact line follows the contract (tests/test_architect_python_pin.py)
    # ARCHITECT-REFUSED-ROLES-FACT (ex02-g13) re-pin: then the IAM roles fact line
    assert out == ("OPERATOR OVERRIDE PROMPT\n\n" + render_topology_contract() + "\n" + ap.ARCHITECT_PYTHON_RUNTIME_FACT
                   + "\n" + ap.ARCHITECT_REFUSED_ROLES_FACT)
    assert "service_topology" in ap.ARCHITECT_SYSTEM_PROMPT


# ------------------------------------------------------------------------------------------------ brownfield context
def test_existing_workload_topology_is_given_to_the_architect_as_context(architect):
    """workloads/{pid}.service_topology (written after a committed topology run) reaches the prompt; a new product's
    prompt is unchanged (no block); a tampered record is never used."""
    from fd4f_support import FakeDB
    from shared.service_topology import validate_service_topology
    h, agent = architect
    vt, _ = validate_service_topology(GOOD, product_id="shop")
    agent.project_id = "p"
    agent.db = FakeDB()
    agent.db.docs["workloads/shop"] = {"service_topology": {"record": vt.as_record(), "trace_id": "old"}}
    agent.genai_client = _Client({**BASE, "service_topology": GOOD})
    _run(agent)
    prompt = agent.genai_client.calls[0][2]
    assert "CURRENT DEPLOYED SERVICE TOPOLOGY" in prompt and '"core"' in prompt
    agent.db = FakeDB()
    agent.genai_client = _Client({**BASE, "service_topology": GOOD})
    _run(agent)
    assert "CURRENT DEPLOYED SERVICE TOPOLOGY" not in agent.genai_client.calls[0][2]
    rec = vt.as_record()
    rec["intent"]["edges"] = []
    agent.db = FakeDB()
    agent.db.docs["workloads/shop"] = {"service_topology": {"record": rec}}
    agent.genai_client = _Client({**BASE, "service_topology": GOOD})
    _run(agent)
    assert "CURRENT DEPLOYED SERVICE TOPOLOGY" not in agent.genai_client.calls[0][2]
