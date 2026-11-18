"""PLAN-CONTRACT-CHECK (W3 commit 2): the plan-contract gate wired into `ArchitectAgent.decompose` (plan §3.1, §3.3,
§4, §5; tests §8.3).

The outer call (topology_gate=True) runs `plan_contract.gate_plan_contract` after consensus and the no-model outage
raise, before the topology gate. These tests drive the real `decompose` with a fake genai client (the draft answer,
then one answer per re-plan turn) and check the handler's half: Do No Harm on a valid plan, the swap of every derived
local on an accepted re-plan, the draft kept (and its stage-trace output restored) on a strip or a refusal, the
`plan_contract` stage-trace field on every exit, and that the inner re-plan call never re-enters the gate.
Hermetic: fake genai client, persistence and stage-trace writes captured in memory."""
import hermetic_guard  # noqa: F401  (first import)

import copy
import inspect
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

from architect_agent import plan_contract  # noqa: E402
from architect_agent.consensus_engine import DualArchitectConsensusEngine  # noqa: E402
from shared.service_topology import ServiceTopologyIntent  # noqa: E402

TOPO = {"services": [{"name": "api", "kind": "cloudrun"}], "primary_service": "api", "edges": [], "resources": []}
# Same services and primary as TOPO (so the re-plan keeps the draft's typed compute decision, code review finding 2),
# but an edge to a service that does not exist: the topology gate refuses it.
BAD_TOPO = {"services": [{"name": "api", "kind": "cloudrun"}], "primary_service": "api",
            "edges": [{"caller": "api", "callee": "ghost", "protocol": "http"}], "resources": []}
BASE = {"product_id": "shop", "summary": "s", "architecture_overview": "o", "target_compute_services": ["api"],
        "compute_archetype": "cloudrun", "iac_engine": "tofu", "service_topology": TOPO}


def _task(tid, category, targets, depends_on=(), description="Implement it."):
    return {"task_id": tid, "title": tid, "category": category, "target_files": list(targets),
            "description": description, "acceptance_criteria": ["works"], "depends_on": list(depends_on),
            "assigned_agent": "developer", "priority": "HIGH"}


def _step(sid, idx, category, targets, depends_on=()):
    return {"step_id": sid, "step_index": idx, "category": category, "title": sid, "target_files": list(targets),
            "description": f"{sid} step", "acceptance_criteria": ["done"], "depends_on": list(depends_on)}


def _plan(code_targets, steps=None, apis=None):
    plan = {**BASE,
            "infra_tasks": [_task("INFRA-01", "INFRA", ["infra/workload/main.tf"])],
            "code_tasks": [_task("CODE-01", "CODE", code_targets, ["INFRA-01"],
                                 description="Write the API; docker build is not used (prose is never read).")]}
    if steps is not None:
        plan["sequenced_build_plan"] = {"steps": steps, "required_cloud_apis": list(apis or [])}
    return plan


CLEAN_STEPS = [_step("STEP-01-APIS", 1, "FOUNDATION_API", ["infra/workload/main.tf"]),
               _step("STEP-APP", 2, "APP_CODE", ["apps/api/main.py"], ["STEP-01-APIS"]),
               _step("STEP-CD", 3, "CICD", [".github/workflows/deploy-api.yml"], ["STEP-APP"])]
CICD_STEPS = [_step("STEP-01-APIS", 1, "FOUNDATION_API", ["infra/workload/main.tf"]),
              _step("STEP-APP", 2, "APP_CODE", ["apps/api/main.py"], ["STEP-01-APIS"]),
              _step("STEP-CICD", 3, "CICD", ["cloudbuild.yaml", ".github/workflows/deploy-api.yml"], ["STEP-APP"])]
# Stage ordering inverted (IAM depends on COMPUTE): a DAG error already in the draft, never refused (RT 3).
INVERTED_STEPS = [_step("STEP-01-APIS", 1, "FOUNDATION_API", ["infra/workload/main.tf"]),
                  _step("STEP-COMPUTE", 2, "COMPUTE", ["infra/workload/main.tf"], ["STEP-01-APIS"]),
                  _step("STEP-IAM", 3, "IAM", ["infra/workload/main.tf"], ["STEP-COMPUTE"])]

VALID = _plan(["apps/api/main.py", "apps/api/requirements.txt"], CLEAN_STEPS, ["run.googleapis.com"])
DOCKER_DRAFT = _plan(["apps/api/main.py", "apps/api/Dockerfile"], CICD_STEPS,
                     ["run.googleapis.com", "cloudbuild.googleapis.com"])
REPLAN_CLEAN = _plan(["apps/api/main.py"], CLEAN_STEPS, ["run.googleapis.com", "firestore.googleapis.com"])
REPLAN_NO_BUILD_PLAN = _plan(["apps/api/main.py"])            # the inner call fills it with the keyword generator


class _Client:
    """Fake genai client: plan calls answer `plans` in order (the draft first, then one per re-plan turn); a plan
    answer that is an Exception is raised. Topology-repair calls answer from `repairs`. Every call is recorded."""

    def __init__(self, plans, repairs=()):
        self.plans = list(plans)
        self.repairs = list(repairs)
        self.calls = []
        self.models = SimpleNamespace(generate_content=self._gen)

    def _gen(self, model, contents, config):
        schema = getattr(config, "response_schema", None)
        if schema is ServiceTopologyIntent:
            self.calls.append(("repair", contents))
            ans = self.repairs.pop(0)
        else:
            self.calls.append(("replan" if "PLATFORM PLAN CONTRACT" in str(contents) else "plan", contents))
            ans = self.plans.pop(0)
        if isinstance(ans, BaseException):
            raise ans
        return SimpleNamespace(text=ans if isinstance(ans, str) else json.dumps(ans), candidates=[],
                               usage_metadata=None)

    def kinds(self):
        return [c[0] for c in self.calls]


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
    # `persisted` / `traces`: the OUTER call's writes only (the inner re-plan call's intermediate writes, which the
    # outer write overwrites, are in `inner_persisted`; plan §3.3 caveats).
    rec = SimpleNamespace(persisted=[], inner_persisted=[], traces=[], gates=[], topology_gates=0, subjects=[],
                          depth=0)
    real_decompose = h.ArchitectAgent.decompose

    def decompose_spy(self, *a, **kw):
        rec.depth += 1
        try:
            return real_decompose(self, *a, **kw)
        finally:
            rec.depth -= 1

    monkeypatch.setattr(h.ArchitectAgent, "decompose", decompose_spy)
    monkeypatch.setattr(h.ArchitectAgent, "persist_build_plan_to_firestore",
                        lambda self, bp, *a, **kw: (rec.persisted if rec.depth <= 1 else rec.inner_persisted).append(
                            bp) or True)
    monkeypatch.setattr(h.ArchitectAgent, "persist_implementation_plan_to_firestore", lambda self, *a, **kw: True)
    monkeypatch.setattr(h.ArchitectAgent, "_write_architect_stage_trace",
                        lambda self, trace, plan, telemetry, now_iso, **kw: rec.depth <= 1 and rec.traces.append(
                            {"agent_output": getattr(self, "last_architect_raw_output", None), **kw}))
    monkeypatch.setattr(h, "get_model_cascade_for_agent", lambda *a, **kw: ["model-a"])
    monkeypatch.setattr(h, "build_architect_system_prompt", lambda **kw: "RENDERED ARCHITECT PROMPT")
    monkeypatch.setitem(sys.modules, "vertexai", None)

    real_gate = h.gate_plan_contract

    def gate_spy(plan, **kw):
        before = plan.model_dump_json()
        rec.gates.append({"plan": plan, "before": before, **kw})
        result = real_gate(plan, **kw)
        rec.gates[-1]["result"] = result
        rec.gates[-1]["after"] = plan.model_dump_json()
        return result

    monkeypatch.setattr(h, "gate_plan_contract", gate_spy)
    real_topology_gate = h.gate_service_topology

    def topology_spy(*a, **kw):
        rec.topology_gates += 1
        return real_topology_gate(*a, **kw)

    monkeypatch.setattr(h, "gate_service_topology", topology_spy)

    # The brief's draft renderer is asked to name the contract (RT 13). Before W2's `subject` parameter is present
    # in this tree the spy renders without it; with it, the real renderer gets the subject.
    real_draft_json = DualArchitectConsensusEngine.__dict__["_draft_plan_json"].__func__
    takes_subject = "subject" in inspect.signature(real_draft_json).parameters

    def draft_json_spy(plan, subject=None):
        rec.subjects.append(subject)
        return real_draft_json(plan, subject=subject) if takes_subject else real_draft_json(plan)

    monkeypatch.setattr(DualArchitectConsensusEngine, "_draft_plan_json", staticmethod(draft_json_spy))
    monkeypatch.setattr(plan_contract, "PLAN_CONTRACT_ON_EXHAUSTION", "STRIP")

    agent = h.ArchitectAgent(project_id="")
    agent.project_id = ""
    agent.model_name = "model-a"
    agent.model = None
    agent.spec_decomposer = None
    return h, agent, rec


def _run(agent, vcs_kind="GITHUB", **kw):
    return agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="t-pc-1", vcs_kind=vcs_kind, **kw)


def _targets(plan):
    out = [p for t in list(plan.infra_tasks) + list(plan.code_tasks) for p in t.target_files]
    bp = plan.sequenced_build_plan
    return out + [p for s in (bp.steps if bp else []) for p in s.target_files]


# ------------------------------------------------------------------------------------------------ Do No Harm
def test_valid_plan_is_the_same_object_byte_identical_with_no_extra_call(architect):
    h, agent, rec = architect
    agent.genai_client = _Client([VALID])
    res = _run(agent)
    assert agent.genai_client.kinds() == ["plan"]                         # zero extra model calls
    assert len(rec.gates) == 1
    gate = rec.gates[0]
    assert gate["result"].plan is gate["plan"] is res.architecture_plan    # the same plan object continues
    assert gate["before"] == gate["after"]                                # byte-identical
    assert gate["result"].outcome == "PASSED"
    assert "Platform plan contract" not in (res.plan_markdown or "")
    assert rec.traces[-1]["plan_contract"]["outcome"] == "PASSED"
    assert rec.topology_gates == 1 and len(rec.persisted) == 1


def test_valid_plan_outputs_equal_a_run_with_the_gate_stubbed_out(architect, monkeypatch):
    """§5: the returned task DAG, plan markdown and architecture plan equal those of a run without the gate."""
    h, agent, rec = architect
    agent.genai_client = _Client([VALID])
    gated = _run(agent)
    monkeypatch.setattr(h, "gate_plan_contract", lambda plan, **kw: plan_contract.PlanContractResult(
        plan=plan, outcome="PASSED", record={"outcome": "PASSED"}, replanned_model_build_plan=None))
    agent.genai_client = _Client([VALID])
    plain = _run(agent)

    def dump(r):
        return (json.dumps([t.model_dump(mode="json") for t in r.task_dag], sort_keys=True),
                r.plan_markdown,
                r.architecture_plan.model_dump_json(exclude={"plan_markdown": True,
                                                             "sequenced_build_plan": {"created_at"}}),
                r.sequenced_build_plan.model_dump_json(exclude={"created_at"}), json.dumps(r.compute_intent,
                                                                                          sort_keys=True))
    assert dump(gated) == dump(plain)


def test_inner_calls_never_run_the_gate_and_fallback_drafts_skip_it(architect):
    """Outer call only: a consensus remediation turn's inner call (topology_gate=False) is not gated; the fallback
    plan goes straight to the topology gate, which refuses it."""
    h, agent, rec = architect
    agent.genai_client = _Client([DOCKER_DRAFT])
    inner = agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="t-pc-1", topology_gate=False,
                            bypass_consensus=True, vcs_kind="GITHUB")
    assert rec.gates == [] and "apps/api/Dockerfile" in _targets(inner.architecture_plan)
    agent.genai_client = _Client(["not json at all"])
    with pytest.raises(h.TopologyInvalidError):
        _run(agent)
    assert rec.gates == []


# ------------------------------------------------------------------------------------------------ re-plan + swap
def test_violating_draft_replanned_clean_swaps_every_derived_local(architect):
    h, agent, rec = architect
    agent.genai_client = _Client([DOCKER_DRAFT, REPLAN_CLEAN])
    res = _run(agent)
    assert agent.genai_client.kinds() == ["plan", "replan"]
    assert len(rec.gates) == 1 and rec.gates[0]["result"].outcome == "REPLANNED"
    assert rec.topology_gates == 1                                        # the accepted plan is gated once
    replan_prompt = agent.genai_client.calls[1][1]
    assert "apps/api/Dockerfile" in replan_prompt and "cloudbuild.yaml" in replan_prompt
    assert rec.subjects == [h.PLAN_CONTRACT_DRAFT_SUBJECT]                 # the draft renderer names the contract
    # 1-2: the plan and its build plan are the re-plan's, everywhere downstream
    plan = res.architecture_plan
    assert "apps/api/Dockerfile" not in _targets(plan) and "cloudbuild.yaml" not in _targets(plan)
    assert rec.persisted == [res.sequenced_build_plan] and res.sequenced_build_plan is plan.sequenced_build_plan
    assert [s.step_id for s in res.sequenced_build_plan.steps] == ["STEP-01-APIS", "STEP-APP", "STEP-CD"]
    # 3: the model wrote the re-plan's build plan, so its APIs are the typed plan_apis
    assert res.compute_intent["required_cloud_apis"] == ["firestore.googleapis.com", "run.googleapis.com"]
    # 4: the telemetry describes the audited draft and states the re-plan
    assert res.consensus_telemetry.remediation_diff_summary.endswith(h.PLAN_CONTRACT_TELEMETRY_NOTE)
    # 5: the markdown is the re-plan's (no refused target); 6: the stage trace's output is the accepted re-plan
    # (the appended "## Platform plan contract" note names the first plan's refused entries by design, plan §3.3 item 5)
    body, sep, note = res.plan_markdown.partition("## Platform plan contract")
    assert sep and "apps/api/Dockerfile" not in body
    assert "was not re-audited by the critic" in note and "apps/api/Dockerfile" in note
    final = rec.traces[-1]
    assert json.loads(final["agent_output"])["code_tasks"][0]["target_files"] == ["apps/api/main.py"]
    assert final["plan_contract"]["outcome"] == "REPLANNED"
    assert [t.task_id for t in res.task_dag] == ["INFRA-01", "CODE-01"]


def test_keyword_filled_replan_records_no_model_plan_apis(architect):
    h, agent, rec = architect
    agent.genai_client = _Client([DOCKER_DRAFT, REPLAN_NO_BUILD_PLAN])
    res = _run(agent)
    assert rec.gates[0]["result"].outcome == "REPLANNED"
    assert "required_cloud_apis" not in res.compute_intent            # keyword APIs are never model-typed plan_apis
    steps = res.sequenced_build_plan.steps
    assert "STEP-CICD" not in [s.step_id for s in steps]
    assert all("cloudbuild.yaml" not in s.target_files for s in steps)
    assert rec.persisted == [res.sequenced_build_plan]


def test_ordering_inverted_draft_with_dockerfile_faithful_replan_is_accepted(architect):
    """RT 3: a DAG error already in the draft is never refused; the re-plan that keeps it is accepted."""
    h, agent, rec = architect
    draft = _plan(["apps/api/main.py", "apps/api/Dockerfile"], INVERTED_STEPS, ["run.googleapis.com"])
    replan = _plan(["apps/api/main.py"], INVERTED_STEPS, ["run.googleapis.com"])
    agent.genai_client = _Client([draft, replan])
    res = _run(agent)
    assert rec.gates[0]["result"].outcome == "REPLANNED"
    assert "apps/api/Dockerfile" not in _targets(res.architecture_plan)
    assert rec.traces[-1]["plan_contract"]["dag_preexisting"]


# ------------------------------------------------------------------------------------------------ exhaustion
def test_unusable_replan_strips_the_draft_end_to_end(architect):
    h, agent, rec = architect
    agent.genai_client = _Client([DOCKER_DRAFT, "not json at all"])
    res = _run(agent)
    assert agent.genai_client.kinds() == ["plan", "replan"]
    result = rec.gates[0]["result"]
    assert result.outcome == "STRIPPED" and result.record["stopped"] == "REPLAN_UNUSABLE"
    plan = res.architecture_plan
    assert plan is rec.gates[0]["plan"]                                   # the audited draft, never the re-plan
    code = plan.code_tasks[0]
    assert code.target_files == ["apps/api/main.py"]                      # exactly the flagged entry removed
    assert code.description == DOCKER_DRAFT["code_tasks"][0]["description"] and code.depends_on == ["INFRA-01"]
    cicd = next(s for s in res.sequenced_build_plan.steps if s.step_id == "STEP-CICD")
    assert cicd.target_files == [".github/workflows/deploy-api.yml"]       # the deploy workflow stays
    assert "## Platform plan contract" in res.plan_markdown
    assert rec.topology_gates == 1 and rec.persisted == [res.sequenced_build_plan]
    final = rec.traces[-1]
    assert final["plan_contract"]["outcome"] == "STRIPPED" and final["plan_contract"]["stripped"]
    # the stage trace shows the draft's raw answer, not the refused re-plan's
    assert json.loads(final["agent_output"])["code_tasks"][0]["target_files"] == ["apps/api/main.py",
                                                                                   "apps/api/Dockerfile"]
    assert agent.last_build_plan_from_model is True


def test_unusable_replan_with_fail_mode_refuses_the_run(architect, monkeypatch):
    h, agent, rec = architect
    monkeypatch.setattr(plan_contract, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")
    agent.genai_client = _Client([DOCKER_DRAFT, "not json at all"])
    with pytest.raises(plan_contract.PlanContractViolationError) as ei:
        _run(agent)
    body = ei.value.to_body()
    assert body["error_class"] == "ARCHITECT_DEFECT" and ei.value.http_status == 422
    assert body["reason"] == "ARCHITECT_PLAN_CONTRACT_VIOLATION" and body["stage"] == "architect"
    assert rec.persisted == [] and rec.topology_gates == 0                # nothing after the gate ran
    final = rec.traces[-1]
    assert final["plan_contract"]["outcome"] == "REFUSED"
    assert final.get("topology_error") is None
    assert json.loads(final["agent_output"])["code_tasks"][0]["target_files"][-1] == "apps/api/Dockerfile"


def test_no_progress_replan_strips_after_one_turn(architect):
    h, agent, rec = architect
    agent.genai_client = _Client([DOCKER_DRAFT, DOCKER_DRAFT])
    res = _run(agent)
    assert agent.genai_client.kinds() == ["plan", "replan"]
    assert rec.gates[0]["result"].record["stopped"] == "NO_PROGRESS"
    assert "apps/api/Dockerfile" not in _targets(res.architecture_plan)


def test_replan_without_any_model_answer_is_an_outage_with_the_trace_written(architect, monkeypatch):
    """FAIL mode: no model answer to the re-plan is GATE_UNAVAILABLE (under STRIP it strips, below)."""
    h, agent, rec = architect
    monkeypatch.setattr(plan_contract, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")
    agent.genai_client = _Client([DOCKER_DRAFT, RuntimeError("backend down")])
    with pytest.raises(h.GateUnavailableError) as ei:
        _run(agent)
    assert ei.value.reason == "ARCHITECT_NO_MODEL_RESPONSE"
    assert not isinstance(ei.value, plan_contract.PlanContractViolationError)
    final = rec.traces[-1]
    assert final["plan_contract"] is not None
    assert final["topology_error"]["reason"] == "ARCHITECT_NO_MODEL_RESPONSE"
    assert json.loads(final["agent_output"])["code_tasks"][0]["target_files"][-1] == "apps/api/Dockerfile"
    assert rec.persisted == []


def _rate_limit_the_replan(h, monkeypatch):
    """The draft call answers; every later `_single_turn_decompose` (the re-plan) raises ArchitectRateLimitedError."""
    real_single = h.ArchitectAgent._single_turn_decompose
    calls = []

    def single(self, **kw):
        calls.append(kw)
        if len(calls) > 1:
            raise h.ArchitectRateLimitedError("rate limited", reason="ARCHITECT_RATE_LIMITED")
        return real_single(self, **kw)

    monkeypatch.setattr(h.ArchitectAgent, "_single_turn_decompose", single)
    return calls


def test_rate_limited_replan_under_strip_strips_the_audited_draft(architect, monkeypatch):
    """Orchestrator decision on code review finding 3 (owner policy: the check never fails a run that passes today):
    under STRIP a model outage in the re-plan turn is the failed turn MODEL_UNAVAILABLE, the loop stops, and the
    stage continues with the audited draft minus the flagged entries."""
    h, agent, rec = architect
    agent.genai_client = _Client([DOCKER_DRAFT])
    calls = _rate_limit_the_replan(h, monkeypatch)
    res = _run(agent)
    assert len(calls) == 2                                                # the draft, then one re-plan turn only
    result = rec.gates[0]["result"]
    assert result.outcome == "STRIPPED" and result.record["stopped"] == "REPLAN_MODEL_UNAVAILABLE"
    turn = result.record["turns"][0]
    assert turn["result"] == "MODEL_UNAVAILABLE" and len(result.record["turns"]) == 1
    assert turn["unavailable"] == {"type": "ArchitectRateLimitedError", "error_class": "GATE_UNAVAILABLE",
                                   "reason": "ARCHITECT_RATE_LIMITED"}
    plan = res.architecture_plan
    assert plan is rec.gates[0]["plan"]
    assert plan.code_tasks[0].target_files == ["apps/api/main.py"]
    assert "apps/api/Dockerfile" not in _targets(plan)
    assert rec.topology_gates == 1 and rec.persisted == [res.sequenced_build_plan]
    final = rec.traces[-1]
    assert final["plan_contract"]["outcome"] == "STRIPPED" and final.get("topology_error") is None
    assert final["plan_contract"]["turns"][0]["result"] == "MODEL_UNAVAILABLE"
    assert json.loads(final["agent_output"])["code_tasks"][0]["target_files"][-1] == "apps/api/Dockerfile"


def test_replan_without_any_model_answer_under_strip_strips_the_audited_draft(architect):
    h, agent, rec = architect
    agent.genai_client = _Client([DOCKER_DRAFT, RuntimeError("backend down")])
    res = _run(agent)
    result = rec.gates[0]["result"]
    assert result.outcome == "STRIPPED" and result.record["stopped"] == "REPLAN_MODEL_UNAVAILABLE"
    assert result.record["turns"][0]["unavailable"]["reason"] == "ARCHITECT_NO_MODEL_RESPONSE"
    assert res.architecture_plan is rec.gates[0]["plan"]
    assert "apps/api/Dockerfile" not in _targets(res.architecture_plan)
    assert rec.persisted == [res.sequenced_build_plan]
    assert rec.traces[-1].get("topology_error") is None


def test_typed_error_of_the_inner_call_propagates_with_the_trace_written(architect, monkeypatch):
    """FAIL mode: a rate-limited re-plan surfaces as GATE_UNAVAILABLE (ArchitectRateLimitedError), trace first."""
    h, agent, rec = architect
    monkeypatch.setattr(plan_contract, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")
    agent.genai_client = _Client([DOCKER_DRAFT])
    calls = _rate_limit_the_replan(h, monkeypatch)
    with pytest.raises(h.ArchitectRateLimitedError):
        _run(agent)
    assert len(calls) == 2
    final = rec.traces[-1]
    assert final["plan_contract"] is not None and final.get("topology_error") is None
    assert final["plan_contract"]["turns"][0]["result"] == "RAISED"
    assert rec.persisted == []


def test_rate_limit_of_the_outer_architect_call_is_never_swallowed_under_strip(architect, monkeypatch):
    """The outage mapping covers the re-plan turn only: a rate-limited draft (outer) call fails the stage as today,
    with no gate run."""
    h, agent, rec = architect
    agent.genai_client = _Client([])

    def single(self, **kw):
        raise h.ArchitectRateLimitedError("rate limited", reason="ARCHITECT_RATE_LIMITED")

    monkeypatch.setattr(h.ArchitectAgent, "_single_turn_decompose", single)
    with pytest.raises(h.ArchitectRateLimitedError):
        _run(agent)
    assert rec.gates == [] and rec.persisted == []


@pytest.mark.parametrize("mode", ["STRIP", "FAIL"])
def test_stage_stop_in_the_replan_propagates_without_a_trace_write(architect, monkeypatch, mode):
    """A STOP error during the re-plan is never an outage turn, in either mode."""
    h, agent, rec = architect
    import stage_deadline
    monkeypatch.setattr(plan_contract, "PLAN_CONTRACT_ON_EXHAUSTION", mode)
    agent.genai_client = _Client([DOCKER_DRAFT])
    real_single = h.ArchitectAgent._single_turn_decompose
    calls = []

    def single(self, **kw):
        calls.append(kw)
        if len(calls) > 1:
            raise stage_deadline.StageAbandonedError("superseded", reason="STAGE_ABANDONED")
        return real_single(self, **kw)

    monkeypatch.setattr(h.ArchitectAgent, "_single_turn_decompose", single)
    with pytest.raises(stage_deadline.StageAbandonedError):
        _run(agent)
    assert rec.traces == [] and rec.persisted == []


def test_topology_refusal_after_a_replan_still_writes_plan_contract(architect):
    h, agent, rec = architect
    replan = {**copy.deepcopy(REPLAN_CLEAN), "service_topology": BAD_TOPO}
    agent.genai_client = _Client([DOCKER_DRAFT, replan], repairs=["not json"])
    with pytest.raises(h.TopologyInvalidError):
        _run(agent)
    final = rec.traces[-1]
    assert final["topology_error"]["reason"] == "ARCHITECT_TOPOLOGY_INVALID"
    assert final["plan_contract"]["outcome"] == "REPLANNED"


def test_map_reduce_plan_gets_no_replan_call(architect):
    h, agent, rec = architect
    from architect_agent.schemas import ArchitecturePlanDAG
    dag = ArchitecturePlanDAG(**{k: v for k, v in DOCKER_DRAFT.items() if k != "sequenced_build_plan"})

    class _Decomposer:
        def should_activate_map_reduce(self, text):
            return True

        def decompose_large_specification(self, text, prod, context=None):
            return dag

    agent.spec_decomposer = _Decomposer()
    agent.genai_client = _Client([])
    res = _run(agent)
    assert [k for k in agent.genai_client.kinds() if k in ("plan", "replan")] == []
    assert rec.gates[0]["is_map_reduce"] is True
    assert rec.gates[0]["result"].record["stopped"] == "MAP_REDUCE"
    assert "apps/api/Dockerfile" not in _targets(res.architecture_plan)


def test_no_genai_client_means_no_replan_fn(architect, monkeypatch):
    h, agent, rec = architect
    agent.genai_client = _Client([DOCKER_DRAFT])
    real = h.ArchitectAgent._plan_contract_replan_fn
    monkeypatch.setattr(h.ArchitectAgent, "_plan_contract_replan_fn", lambda self, *a: None)
    _run(agent)
    assert rec.gates[0]["replan_fn"] is None and rec.gates[0]["result"].record["stopped"] == "NO_MODEL"
    monkeypatch.setattr(h.ArchitectAgent, "_plan_contract_replan_fn", real)


# ------------------------------------------------------------------------------------------------ code review 2-4
def test_replan_that_changes_compute_strips_the_audited_draft(architect):
    h, agent, rec = architect
    replan = {**copy.deepcopy(REPLAN_CLEAN), "target_compute_services": ["api", "worker"]}
    agent.genai_client = _Client([DOCKER_DRAFT, replan])
    res = _run(agent)
    result = rec.gates[0]["result"]
    assert result.outcome == "STRIPPED" and result.record["stopped"] == "REPLAN_CHANGED_COMPUTE"
    assert result.record["turns"][0]["compute_changed"] == ["target_compute_services"]
    assert res.architecture_plan is rec.gates[0]["plan"]
    assert list(res.architecture_plan.target_compute_services) == ["api"]
    assert rec.traces[-1]["plan_contract"]["outcome"] == "STRIPPED"


def test_off_enum_archetype_in_the_replan_strips_instead_of_failing(architect):
    """Code review finding 3: every model answering the re-plan with an off-enum archetype raises
    ArchitectOutputInvalidError inside the inner call; that is a bad answer, not an outage, so the turn fails
    (REPLAN_UNUSABLE) and STRIP keeps the audited draft. The run does not fail."""
    h, agent, rec = architect
    replan = {**copy.deepcopy(REPLAN_CLEAN), "compute_archetype": "lambda"}
    agent.genai_client = _Client([DOCKER_DRAFT, replan])
    res = _run(agent)
    assert agent.genai_client.kinds() == ["plan", "replan"]
    result = rec.gates[0]["result"]
    assert result.outcome == "STRIPPED" and result.record["stopped"] == "REPLAN_UNUSABLE"
    turn = result.record["turns"][0]
    assert turn["result"] == "UNUSABLE" and turn["error"].startswith("ARCHITECT_COMPUTE_ARCHETYPE_INVALID")
    assert res.architecture_plan.compute_archetype == "cloudrun"
    assert "apps/api/Dockerfile" not in _targets(res.architecture_plan)
    assert rec.persisted == [res.sequenced_build_plan]


def test_off_enum_archetype_in_the_replan_with_fail_mode_refuses(architect, monkeypatch):
    h, agent, rec = architect
    monkeypatch.setattr(plan_contract, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")
    agent.genai_client = _Client([DOCKER_DRAFT, {**copy.deepcopy(REPLAN_CLEAN), "compute_archetype": "lambda"}])
    with pytest.raises(plan_contract.PlanContractViolationError) as ei:
        _run(agent)
    assert ei.value.details["stopped"] == "REPLAN_UNUSABLE"


def test_gate_defect_is_a_typed_platform_defect_with_the_trace_written(architect, monkeypatch):
    """Code review finding 4: an unexpected exception inside the gate is PlatformDefectError
    PLAN_CONTRACT_GATE_DEFECT at stage architect (never an untyped 500), and the trace is written first."""
    h, agent, rec = architect

    def boom(_plan):
        raise ValueError("cycle detector exploded")

    monkeypatch.setattr(plan_contract, "_validate_dag", boom)
    agent.genai_client = _Client([DOCKER_DRAFT])
    with pytest.raises(plan_contract.PlatformDefectError) as ei:
        _run(agent)
    body = ei.value.to_body()
    assert body["error_class"] == "PLATFORM_DEFECT" and body["reason"] == "PLAN_CONTRACT_GATE_DEFECT"
    assert body["stage"] == "architect"
    final = rec.traces[-1]
    assert final["plan_contract"]["outcome"] == "INTERRUPTED"
    assert "ValueError" in final["plan_contract"]["defect"]
    assert rec.persisted == [] and rec.topology_gates == 0


def test_defect_around_the_gate_call_is_typed_too(architect, monkeypatch):
    h, agent, rec = architect

    def broken(self, *a):
        raise AttributeError("replan fn factory broke")

    monkeypatch.setattr(h.ArchitectAgent, "_plan_contract_replan_fn", broken)
    agent.genai_client = _Client([DOCKER_DRAFT])
    with pytest.raises(plan_contract.PlatformDefectError) as ei:
        _run(agent)
    assert ei.value.reason == "PLAN_CONTRACT_GATE_DEFECT" and ei.value.stage == "architect"
    assert isinstance(ei.value.__cause__, AttributeError)
    assert rec.traces[-1]["plan_contract"]["outcome"] == "INTERRUPTED"
    assert rec.persisted == []


# ------------------------------------------------------------------------------------------------ VCS kind
def test_vcs_kind_reaches_the_gate_and_unknown_vcs_records_not_checked(architect):
    h, agent, rec = architect
    root_cloudbuild = _plan(["apps/api/main.py"], [_step("STEP-CICD", 1, "CICD", ["cloudbuild.yaml"])],
                            ["run.googleapis.com"])
    agent.genai_client = _Client([root_cloudbuild])
    _run(agent, vcs_kind="SERVERLESS_GIT")
    assert rec.gates[-1]["vcs_kind"] == "SERVERLESS_GIT" and rec.gates[-1]["result"].outcome == "PASSED"
    agent.genai_client = _Client([root_cloudbuild])
    _run(agent, vcs_kind=None)
    assert rec.gates[-1]["vcs_kind"] is None and rec.gates[-1]["result"].outcome == "PASSED"
    assert rec.traces[-1]["plan_contract"]["not_checked"]
    assert agent.genai_client.kinds() == ["plan"]


def test_decompose_default_vcs_kind_is_none():
    from architect_agent import handler as h
    assert inspect.signature(h.ArchitectAgent.decompose).parameters["vcs_kind"].default is None


# ------------------------------------------------------------------------------------------------ stage trace
def test_stage_trace_field_is_owned_and_written(monkeypatch):
    from architect_agent import handler as h
    from architect_agent.schemas import ArchitecturePlan
    from google.cloud.firestore_v1.transforms import DELETE_FIELD
    assert "plan_contract" in h.ARCHITECT_STAGE_TRACE_FIELDS
    sets = []

    class _Doc:
        def collection(self, *_a):
            return SimpleNamespace(document=lambda *_a: self)

        def set(self, payload, merge=None):
            sets.append((payload, merge))

    fs = SimpleNamespace(collection=lambda *_a: SimpleNamespace(document=lambda *_a: _Doc()))
    agent = h.ArchitectAgent.__new__(h.ArchitectAgent)
    agent.project_id = "p"
    agent.db = fs
    plan = ArchitecturePlan(product_id="shop", summary="s", architecture_overview="o")
    agent._write_architect_stage_trace("t", plan, None, "now", plan_contract={"outcome": "STRIPPED"})
    payload, merge = sets[-1]
    assert payload["plan_contract"] == {"outcome": "STRIPPED"} and "plan_contract" in merge
    agent._write_architect_stage_trace("t", plan, None, "now")
    payload, _ = sets[-1]
    assert payload["plan_contract"] is DELETE_FIELD           # an earlier run's record never survives
