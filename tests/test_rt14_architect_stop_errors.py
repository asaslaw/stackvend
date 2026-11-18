"""RT14-24 (full-scope red-team 11-14): an abandoned architect stage (cancel, supersede, emergency stop) is never
swallowed into a SUCCESS answer.

Mechanism: a stop raised at a checkpoint was caught by a nearby broad `except Exception` (critic model loop, consensus
remediation, map-reduce fallback, topology repair), so the deterministic critic fallback answered CONSENSUS_VERIFIED
and the plan, compute intent, stage trace and the person's Google Doc were written. Fixed at both ends: every broad
`except` on the architect path re-raises `stage_deadline.STOP_ERRORS` (guard test below, structural), and
`run_with_deadline` answers typed once a checkpoint observed the abandonment, whatever the body did with it.

Hermetic: fake LLM clients, in-memory Firestore stand-ins, no network.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import json
import os
import sys
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")
ARCH_DIR = os.path.join(GW_DIR, "architect_agent")
for p in (GW_DIR, REPO):
    if p not in sys.path:
        sys.path.insert(0, p)

import stage_deadline as sdm  # noqa: E402
from gate_errors import StageAbandonedError, StageDeadlineExceededError  # noqa: E402
from stage_deadline import StageMode  # noqa: E402
from architect_agent.schemas import (ArchitecturePlan, BuildPlanStep, BuildStepCategory,  # noqa: E402
                                     SequencedBuildPlan)
from architect_agent import red_team_critic as rtc  # noqa: E402
from architect_agent.consensus_engine import DualArchitectConsensusEngine  # noqa: E402
from architect_agent.topology_gate import TopologyInvalidError, gate_service_topology  # noqa: E402

GOOD = {"services": [{"name": "api", "kind": "cloudrun"}], "primary_service": "api", "edges": [], "resources": []}
BASE = {"product_id": "shop", "summary": "s", "architecture_overview": "o", "infra_tasks": [], "code_tasks": [],
        "target_compute_services": ["api"], "compute_archetype": "cloudrun", "iac_engine": "tofu"}


@pytest.fixture(autouse=True)
def no_settings(monkeypatch):
    """Platform settings unreadable (no Firestore in tests): the call sites use their defaults."""
    import shared.settings as settings

    def unreadable(*a, **k):
        raise RuntimeError("no settings store in tests")
    monkeypatch.setattr(settings, "get_platform_settings", unreadable)
    monkeypatch.setattr(rtc, "get_model_cascade_for_agent", lambda *a, **k: ["m1", "m2"])


def _sd(stage="architect", probe=None):
    return sdm.StageDeadline(sdm.budget_for(stage, StageMode.SYNC), trace_id="tr-1", product_id="shop", probe=probe)


def _in_stage(sd, fn):
    tok = sdm._CURRENT.set(sd)
    try:
        return fn()
    finally:
        sdm._CURRENT.reset(tok)


def _cycle_plan():
    steps = [BuildPlanStep(step_id="S1", depends_on=["S2"], category=BuildStepCategory.FOUNDATION_API),
             BuildPlanStep(step_id="S2", depends_on=["S1"], category=BuildStepCategory.COMPUTE)]
    return ArchitecturePlan(product_id="shop", sequenced_build_plan=SequencedBuildPlan(steps=steps))


# ============================================================================================ run_with_deadline
def test_swallowed_abandonment_answers_typed_not_the_body_result():
    sd = _sd()

    def body():
        sd.abandon("SUPERSEDED", "a newer architect job owns this stage", quiet=True)
        try:
            sdm.checkpoint("architect.red_team")
        except Exception:      # a broad except swallowed the stop ...
            pass
        return {"status": "SUCCESS"}   # ... and the stage answered SUCCESS
    with pytest.raises(StageAbandonedError) as ei:
        sdm.run_with_deadline(sd, body)
    assert ei.value.reason == "SUPERSEDED" and ei.value.to_body()["error_class"] == "STAGE_ABANDONED"


def test_swallowed_abandonment_turned_into_another_error_answers_typed():
    sd = _sd()

    def body():
        sd.abandon("KILL_SWITCH_ACTIVE", "stop", quiet=True)
        try:
            sdm.guard_side_effect("architect.persist", reserve_s=0)
        except Exception as e:
            raise RuntimeError("persist failed") from e
    with pytest.raises(StageAbandonedError) as ei:
        sdm.run_with_deadline(sd, body)
    assert ei.value.reason == "KILL_SWITCH_ACTIVE"


def test_negative_unobserved_abandonment_and_normal_stage_answer_unchanged():
    """Do No Harm: a stage that never observed a stop answers exactly as before (result or its own exception)."""
    sd = _sd()
    sentinel = {"status": "SUCCESS"}
    assert sdm.run_with_deadline(sd, lambda: sentinel) is sentinel
    err = ValueError("boom")

    def body():
        raise err
    with pytest.raises(ValueError) as ei:
        sdm.run_with_deadline(_sd(), body)
    assert ei.value is err
    assert not sd.abandon_observed


# ============================================================================================ critic
class _CountingClient:
    def __init__(self, text="{}"):
        self.calls = 0
        self.text = text
        self.models = SimpleNamespace(generate_content=self._gen)

    def _gen(self, model, contents, config):
        self.calls += 1
        return SimpleNamespace(text=self.text, candidates=[])


def test_critic_never_turns_a_stop_into_the_deterministic_fallback(monkeypatch):
    monkeypatch.setattr(rtc, "get_model_cascade_for_agent", lambda *a, **k: ["m1", "m2"])
    client = _CountingClient()
    critic = rtc.RedTeamCritic(genai_client=client, model_name="m1")
    sd = _sd()
    sd.abandon("RUN_ENDED", "run tr-1 is ABORTED", quiet=True)
    with pytest.raises(StageAbandonedError):
        _in_stage(sd, lambda: critic.audit_plan(plan=ArchitecturePlan(product_id="shop"), spec_text="x"))
    assert client.calls == 0


def test_critic_stop_inside_the_model_call_is_reraised(monkeypatch):
    """bound_llm_config checkpoints inside the per-model try: the stop is re-raised, never cascaded to model 2."""
    monkeypatch.setattr(rtc, "get_model_cascade_for_agent", lambda *a, **k: ["m1", "m2"])
    sd = _sd()
    real = sdm.bound_llm_config

    def stop_then_bound(cfg, label, *, types):
        sd.abandon("SUPERSEDED", "newer execution", quiet=True)
        return real(cfg, label, types=types)
    monkeypatch.setattr(sdm, "bound_llm_config", stop_then_bound)
    client = _CountingClient()
    critic = rtc.RedTeamCritic(genai_client=client, model_name="m1")
    with pytest.raises(StageAbandonedError):
        _in_stage(sd, lambda: critic.audit_plan(plan=ArchitecturePlan(product_id="shop"), spec_text="x"))
    assert client.calls == 0


def test_negative_critic_without_a_stage_keeps_its_fallback():
    """No stage deadline (direct call): an LLM failure still gives the deterministic critique, as before."""
    class _Down:
        models = SimpleNamespace(generate_content=lambda **kw: (_ for _ in ()).throw(ValueError("400")))
    out = rtc.RedTeamCritic(genai_client=_Down(), model_name="m").audit_plan(plan=ArchitecturePlan(product_id="s"),
                                                                             spec_text="x")
    assert out.verdict_summary.startswith("Plan passed deterministic")


# ============================================================================================ consensus
def test_consensus_remediation_stop_is_not_critique_failed():
    arch = MagicMock()
    arch.uses_map_reduce = lambda text: False
    arch.decompose.side_effect = StageAbandonedError("architect stopped", reason="RUN_ENDED", stage="architect")
    with pytest.raises(StageAbandonedError):
        DualArchitectConsensusEngine(genai_client=None).evaluate_and_reconcile(
            plan=_cycle_plan(), spec_text="x", architect_agent=arch, product_id="shop", trace_id="tr-1")


def test_negative_consensus_remediation_error_is_still_critique_failed():
    arch = MagicMock()
    arch.uses_map_reduce = lambda text: False
    arch.decompose.side_effect = RuntimeError("429")
    plan = _cycle_plan()
    out, tel = DualArchitectConsensusEngine(genai_client=None).evaluate_and_reconcile(
        plan=plan, spec_text="x", architect_agent=arch, product_id="shop", trace_id="tr-1")
    assert tel.consensus_status == "CRITIQUE_FAILED" and out is plan


# ============================================================================================ topology gate
def test_topology_repair_stop_is_not_an_architect_defect():
    def repair(system, prompt):
        raise StageAbandonedError("stopped", reason="KILL_SWITCH_ACTIVE", stage="architect")
    plan = ArchitecturePlan(**BASE)
    with pytest.raises(StageAbandonedError):
        gate_service_topology(plan, product_id="shop", trace_id="tr-1", repair_fn=repair)


def test_negative_topology_repair_error_is_still_typed_invalid():
    def repair(system, prompt):
        raise RuntimeError("model down")
    with pytest.raises(TopologyInvalidError):
        gate_service_topology(ArchitecturePlan(**BASE), product_id="shop", trace_id="tr-1", repair_fn=repair)


# ============================================================================================ handler
class _Client:
    def __init__(self, plan, on_call=None):
        self.plan = plan
        self.calls = []
        self.on_call = on_call
        self.models = SimpleNamespace(generate_content=self._gen)

    def _gen(self, model, contents, config):
        self.calls.append(contents)
        if self.on_call:
            self.on_call()
        return SimpleNamespace(text=json.dumps(self.plan), candidates=[], usage_metadata=None)


class _DB:
    def __init__(self):
        self.writes = []

    def collection(self, c):
        db = self

        class _Doc:
            def __init__(self, d):
                self.d = d

            def set(self, payload, merge=False):
                db.writes.append((c, self.d, payload, merge))

            def get(self):
                return SimpleNamespace(exists=False, to_dict=lambda: {})

            def collection(self, sub):
                return SimpleNamespace(document=lambda d2: _Doc(f"{self.d}/{sub}/{d2}"))

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
    persisted = []
    monkeypatch.setattr(h.ArchitectAgent, "persist_build_plan_to_firestore",
                        lambda self, *a, **kw: persisted.append("build_plan") or True)
    monkeypatch.setattr(h.ArchitectAgent, "persist_implementation_plan_to_firestore",
                        lambda self, *a, **kw: persisted.append("implementation_plan") or True)
    monkeypatch.setattr(h, "get_model_cascade_for_agent", lambda *a, **kw: ["model-a"])
    monkeypatch.setattr(h, "build_architect_system_prompt", lambda **kw: "SYS")
    monkeypatch.setitem(sys.modules, "vertexai", None)
    agent = h.ArchitectAgent(project_id="")
    agent.project_id = "p"
    agent.db = _DB()
    agent.model_name = "model-a"
    agent.model = None
    agent.spec_decomposer = None
    appended = []
    agent.append_task_checklist_to_doc = lambda *a, **kw: appended.append(a) or True
    return h, agent, persisted, appended


def _decompose(agent, **kw):
    return agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="tr-1", spec_doc_id="doc-1",
                           workspace_mcp_url="https://ws.a.run.app", **kw)


def test_stop_during_the_plan_call_persists_nothing_and_edits_no_doc(architect):
    h, agent, persisted, appended = architect
    sd = _sd()
    agent.genai_client = _Client({**BASE, "service_topology": GOOD},
                                 on_call=lambda: sd.abandon("SUPERSEDED", "newer execution", quiet=True))
    with pytest.raises(StageAbandonedError) as ei:
        sdm.run_with_deadline(sd, lambda: _decompose(agent))
    assert ei.value.reason == "SUPERSEDED"
    assert persisted == [] and appended == [] and agent.db.writes == []


def test_negative_in_time_stage_persists_and_appends_as_before(architect):
    h, agent, persisted, appended = architect
    agent.genai_client = _Client({**BASE, "service_topology": GOOD})
    res = sdm.run_with_deadline(_sd(), lambda: _decompose(agent))
    assert res.compute_intent["target_compute_services"] == ["api"]
    assert persisted == ["build_plan", "implementation_plan"] and len(appended) == 1
    assert any(w[2].get("architect_compute_intent") for w in agent.db.writes)


def test_doc_append_that_could_outlast_the_answer_is_skipped(architect, monkeypatch):
    h, agent, persisted, appended = architect
    agent.genai_client = _Client({**BASE, "service_topology": GOOD})
    monkeypatch.setattr(sdm, "remaining_s", lambda: h.DOC_APPEND_TIMEOUT_S - 1)
    _in_stage(_sd(), lambda: _decompose(agent))
    assert persisted == ["build_plan", "implementation_plan"] and appended == []


def test_consensus_and_map_reduce_stops_reach_the_caller(architect, monkeypatch):
    h, agent, persisted, appended = architect
    agent.genai_client = _Client({**BASE, "service_topology": GOOD})
    monkeypatch.setenv("ENABLE_DUAL_ARCHITECT_CONSENSUS", "true")

    class _Consensus:
        def evaluate_and_reconcile(self, **kw):
            raise StageAbandonedError("stopped", reason="RUN_ENDED", stage="architect")
    agent.consensus_engine = _Consensus()
    with pytest.raises(StageAbandonedError):
        _decompose(agent)
    monkeypatch.setenv("ENABLE_DUAL_ARCHITECT_CONSENSUS", "false")

    def stopped(*a, **kw):
        raise StageDeadlineExceededError("late", reason="STAGE_DEADLINE", stage="architect")
    agent.spec_decomposer = SimpleNamespace(should_activate_map_reduce=lambda text: True,
                                            decompose_large_specification=stopped)
    agent.genai_client.calls.clear()
    with pytest.raises(StageDeadlineExceededError):
        _decompose(agent)
    assert agent.genai_client.calls == []      # never fell through to the single-turn path
    assert persisted == [] and appended == []


# ============================================================================================ guard (structural)
STOP_SEEDS = {"checkpoint", "bound_llm_config", "guard_side_effect",
              "repair_fn"}   # repair_fn: the injected topology-repair call (handler._topology_repair_fn)


def _call_name(node):
    f = node.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def _calls(nodes):
    """Call names in `nodes`, not descending into nested functions / lambdas (they run elsewhere)."""
    out, stack = set(), list(nodes)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(n, ast.Call):
            name = _call_name(n)
            if name:
                out.add(name)
        stack.extend(ast.iter_child_nodes(n))
    return out


def _architect_trees():
    return {f: ast.parse(open(os.path.join(ARCH_DIR, f), encoding="utf-8").read())
            for f in sorted(os.listdir(ARCH_DIR)) if f.endswith(".py") and not f.startswith("test_")}


def _may_stop(trees):
    defs = {}
    for tree in trees.values():
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs.setdefault(n.name, set()).update(_calls(n.body))
    stop = set(STOP_SEEDS)
    changed = True
    while changed:
        changed = False
        for name, calls in defs.items():
            if name not in stop and calls & stop:
                stop.add(name)
                changed = True
    return stop


def _is_broad(handler):
    t = handler.type
    if t is None:
        return True
    names = [e for e in (t.elts if isinstance(t, ast.Tuple) else [t])]
    return any(isinstance(e, ast.Name) and e.id in ("Exception", "BaseException") for e in names)


def _reraises_stop(handler):
    return (handler.type is not None and "STOP_ERRORS" in ast.unparse(handler.type)
            and len(handler.body) == 1 and isinstance(handler.body[0], ast.Raise) and handler.body[0].exc is None)


def test_every_broad_except_on_the_architect_path_reraises_stop_errors():
    trees = _architect_trees()
    stop = _may_stop(trees)
    assert {"audit_plan", "evaluate_and_reconcile", "decompose", "map_domain_subplan",
            "gate_service_topology"} <= stop      # the analysis reaches the stage's call chain
    bad = []
    for fname, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try) or not (_calls(node.body) & stop):
                continue
            for h in node.handlers:
                if _reraises_stop(h):
                    break
                if _is_broad(h):
                    bad.append(f"{fname}:{node.lineno}")
                    break
    assert bad == [], f"broad except swallows STOP_ERRORS (add `except stage_deadline.STOP_ERRORS: raise`): {bad}"


def test_guard_detects_a_new_swallowing_site():
    """The guard itself: a broad except around a stopping call without the re-raise is reported."""
    src = ("def f():\n    try:\n        stage_deadline.checkpoint('x')\n    except Exception:\n        pass\n")
    tree = ast.parse(src)
    stop = _may_stop({"x.py": tree})
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.Try))
    assert _calls(node.body) & stop and _is_broad(node.handlers[0]) and not _reraises_stop(node.handlers[0])
