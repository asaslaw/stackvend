"""RT14-06 (HIGH) + RT14-16 (full-scope red-team 11-14): one run context for every architect path, and an honest
consensus remediation.

RT14-06: a specification large enough for the chunked map-reduce path never showed a model the folder's organization
policies, the operator's REWORK feedback, the quota snapshot or the current topology; the critic's remediation re-ran
map-reduce and still reported the faults "Resolved". Now `decompose` builds ONE `ArchitectContext` that the single-turn
prompt, every map prompt and the topology repair render (parity tests + an AST guard that each path is handed it), the
map-reduce path is capped, a map-reduce plan is never "remediated", and AUTO_REMEDIATED / "Resolved" are written only
after the critic re-audited the patched plan.

Do No Harm: for the same inputs the single-turn prompt, an empty-context map prompt and the no-feedback critic prompt
are byte-identical to before (hashes pinned at the refactor from the previous code; change them only together with an
intended wording change).

Hermetic: fake LLM clients, in-memory Firestore stand-ins, no network.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import hashlib
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")
for p in (GW_DIR, REPO):
    if p not in sys.path:
        sys.path.insert(0, p)

from architect_agent import red_team_critic as rtc  # noqa: E402
from architect_agent.consensus_engine import DualArchitectConsensusEngine  # noqa: E402
from architect_agent.context import ArchitectContext  # noqa: E402
from architect_agent.schemas import (ArchitecturePlan, ArchitecturePlanDAG, BuildPlanStep,  # noqa: E402
                                     BuildStepCategory, SequencedBuildPlan)
from architect_agent.spec_decomposer import ChunkedSpecDecomposer, SpecTooLargeError  # noqa: E402
from architect_agent.topology_gate import build_repair_prompt  # noqa: E402
from shared.critic_schemas import ArchitecturalCritique, CritiqueSeverity  # noqa: E402

POLICY = {"disallow_vm_external_ip": True, "disallow_default_network": True, "require_os_login": True,
          "require_shielded_vm": True, "enforce_uniform_bucket_level_access": True,
          "enforce_public_access_prevention": True, "enforce_private_ingress": True, "restrict_public_sql": True,
          "domain_restricted_sharing": True, "allowed_domains": ["example.com"]}
TOPO = {"services": [{"name": "api", "kind": "cloudrun"}], "primary_service": "api"}
QUOTA = {"regions": {"us-central1": {"cpus": {"limit": 24, "usage": 4}}}}
FEEDBACK = "Remove Redis; keep the session cache in Firestore."
# sha256 of the prompts the previous code built (captured before the refactor, see the module docstring)
SINGLE_TURN_SHA = "d2b490d746ef54afc03a8e600e90ce64915eb07c4dbe4df6f03c0dc213301912"
MAP_EMPTY_SHA = "7f0580f72c627a4ebc2d0f3b929c9e95a7c2e27a9464d52c048d19c43119db4b"
GOOD = {"services": [{"name": "api", "kind": "cloudrun"}], "primary_service": "api", "edges": [], "resources": []}
BASE = {"product_id": "shop", "summary": "s", "architecture_overview": "o", "infra_tasks": [], "code_tasks": [],
        "target_compute_services": ["api"], "compute_archetype": "cloudrun", "iac_engine": "tofu"}


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def no_settings(monkeypatch):
    import shared.settings as settings

    def unreadable(*a, **k):
        raise RuntimeError("no settings store in tests")
    monkeypatch.setattr(settings, "get_platform_settings", unreadable)
    monkeypatch.setattr(rtc, "get_model_cascade_for_agent", lambda *a, **k: ["m"])


class _Recorder:
    """Fake genai client: records every prompt; answers `answer` (a dict -> JSON) or raises a 400."""

    def __init__(self, answer=None):
        self.answer = answer
        self.prompts = []
        self.models = SimpleNamespace(generate_content=self._gen)

    def _gen(self, model, contents, config):
        self.prompts.append(contents)
        if self.answer is None:
            raise ValueError("400 INVALID_ARGUMENT: stop")
        return SimpleNamespace(text=json.dumps(self.answer), candidates=[], usage_metadata=None)


class _DB:
    def __init__(self, docs=None):
        self.docs = docs or {}

    def collection(self, c):
        db = self

        class _Doc:
            def __init__(self, d):
                self.path = f"{c}/{d}"

            def get(self):
                d = db.docs.get(self.path)
                return SimpleNamespace(exists=d is not None, to_dict=lambda: d)

            def set(self, payload, merge=False):
                pass

            def collection(self, sub):
                return SimpleNamespace(document=lambda d2: MagicMock())

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
    sys_prompts = []
    monkeypatch.setattr(h, "build_architect_system_prompt", lambda **kw: sys_prompts.append(kw) or "SYS")
    monkeypatch.setitem(sys.modules, "vertexai", None)
    agent = h.ArchitectAgent(project_id="")
    agent.project_id = ""
    agent.model_name = "model-a"
    agent.model = None
    agent.spec_decomposer = None
    return h, agent, sys_prompts


# ============================================================================================ Do No Harm
def test_negative_single_turn_prompt_is_byte_identical_for_the_same_inputs(architect):
    h, agent, _ = architect
    agent.genai_client = _Recorder()
    ctx = ArchitectContext(policy_matrix=POLICY, human_feedback="  Remove Redis.  ", current_topology=TOPO)
    agent._single_turn_decompose(final_spec_text="Build a shop", prod="shop", trace="t-1", context=ctx)
    assert _sha(agent.genai_client.prompts[0]) == SINGLE_TURN_SHA


def test_negative_empty_context_leaves_the_map_prompt_unchanged():
    rec = _Recorder({})
    d = ChunkedSpecDecomposer(genai_client=rec, model_name="m")
    d.map_domain_subplan({"domain_title": "Payments", "content": "## Payments\nStripe."}, "shop", "Global summary")
    d.map_domain_subplan({"domain_title": "Payments", "content": "## Payments\nStripe."}, "shop", "Global summary",
                         context=ArchitectContext())
    assert [_sha(p) for p in rec.prompts] == [MAP_EMPTY_SHA, MAP_EMPTY_SHA]


def test_negative_repair_prompt_without_a_current_topology_is_unchanged():
    from shared.service_topology import validate_service_topology
    ring = {"services": [{"name": "api", "kind": "cloudrun"}, {"name": "core", "kind": "cloudrun"}],
            "primary_service": "api", "edges": [{"caller": "api", "callee": "core"}, {"caller": "core", "callee": "api"}]}
    _, diags = validate_service_topology(ring, product_id="shop", expected_archetype="cloudrun",
                                         file="architect:service_topology", source="architect")
    plain = build_repair_prompt(ring, diags, {"product_id": "shop"})
    assert plain == build_repair_prompt(ring, diags, {"product_id": "shop"}, current_topology=None)
    assert "CURRENT DEPLOYED" not in plain
    with_topo = build_repair_prompt(ring, diags, {"product_id": "shop"}, current_topology=TOPO)
    assert "CURRENT DEPLOYED SERVICE TOPOLOGY" in with_topo and '"api"' in with_topo


# ============================================================================================ parity
def _full_ctx():
    return ArchitectContext(policy_matrix=POLICY, human_feedback=FEEDBACK, quota_snapshot=QUOTA, current_topology=TOPO)


def test_every_context_block_reaches_the_single_turn_prompt_and_every_map_prompt(architect):
    h, agent, sys_prompts = architect
    ctx = _full_ctx()
    blocks = [b for b in ctx.prompt_blocks().split("\n\n") if b.strip()]
    assert any("ORGANIZATION POLICIES" in b for b in blocks) and any(FEEDBACK in b for b in blocks)
    assert any("CURRENT DEPLOYED SERVICE TOPOLOGY" in b for b in blocks)
    quota = ctx.quota_block()
    assert quota.startswith("### REGIONAL CAPACITY & QUOTA CONSTRAINTS:")

    agent.genai_client = _Recorder()
    agent._single_turn_decompose(final_spec_text="Build a shop", prod="shop", trace="t-1", context=ctx)
    single = agent.genai_client.prompts[0]
    assert all(b in single for b in blocks)
    assert sys_prompts[-1]["quota_snapshot"] is QUOTA          # single-turn: quota in the system prompt

    rec = _Recorder({})
    d = ChunkedSpecDecomposer(genai_client=rec, model_name="m")
    spec = "\n".join(f"# Domain {i}\n" + ("detail line for this domain.\n" * 700) for i in range(3))
    d.decompose_large_specification(spec, "shop", context=ctx)
    assert len(rec.prompts) >= 2
    map_blocks = [b for b in ctx.prompt_blocks(for_map=True).split("\n\n") if b.strip()]   # RT F6 wording
    assert len(map_blocks) == len(blocks)
    for prompt in rec.prompts:
        assert all(b in prompt for b in map_blocks), "a map prompt lost part of the run context"
        assert quota.rstrip() in prompt


def test_rt_f6_map_prompt_topology_line_names_the_map_schema_field():
    """RT F6: the map answer has a `services` name list (no service_topology), so its topology line says so; the
    single-turn wording is unchanged (Do No Harm)."""
    ctx = ArchitectContext(current_topology={"services": [{"name": "api", "kind": "cloudrun"}]})
    section = ChunkedSpecDecomposer.run_context_section(ctx)
    assert "in the services you list" in section and "service_topology" not in section
    single = ctx.prompt_blocks()
    assert ("Keep every existing service with the same name and kind in service_topology (removing, renaming or "
            "re-kinding a deployed service needs a decommission); add services only when the specification asks.\n"
            "--- END CURRENT TOPOLOGY ---") in single


def test_decompose_hands_the_same_context_to_either_path(architect):
    h, agent, _ = architect
    agent.project_id = "p"
    agent.db = _DB({"workloads/shop": {"service_topology": {"record": None}}})
    monkey_topo = {"services": [{"name": "api", "kind": "cloudrun"}], "primary_service": "api"}
    agent._load_current_topology = lambda prod: monkey_topo
    seen = {}
    reduced = ArchitecturePlanDAG(**BASE)

    def mr(text, prod, context=None):
        seen["map_reduce"] = context
        return reduced
    agent.spec_decomposer = SimpleNamespace(should_activate_map_reduce=lambda text: True,
                                            decompose_large_specification=mr)
    kw = dict(spec_text="Build a shop", product_id="shop", trace_id="t-6", policy_matrix=POLICY,
              human_feedback=FEEDBACK, quota_snapshot=QUOTA, topology_gate=False)
    agent.decompose(**kw)
    original = agent._single_turn_decompose

    def spy(**k):
        seen["single_turn"] = k["context"]
        return original(**k)
    agent._single_turn_decompose = spy
    agent.spec_decomposer = None
    agent.genai_client = _Recorder({**BASE, "service_topology": GOOD})
    agent.decompose(**kw)
    expected = ArchitectContext(policy_matrix=POLICY, human_feedback=FEEDBACK, quota_snapshot=QUOTA,
                                current_topology=monkey_topo)
    assert seen["map_reduce"] == expected and seen["single_turn"] == expected


def test_guard_every_decomposition_path_is_handed_the_context():
    """Structural guard: in ArchitectAgent.decompose each path (map-reduce, single-turn, consensus, topology gate)
    receives the run context; a new call site without it fails here."""
    src = open(os.path.join(GW_DIR, "architect_agent", "handler.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "decompose")
    need = {"decompose_large_specification": "context", "_single_turn_decompose": "context",
            "evaluate_and_reconcile": "context", "gate_service_topology": "current_topology"}
    found = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
            if name in need:
                found.setdefault(name, []).append({k.arg for k in node.keywords})
    assert set(found) == set(need)
    for name, kws in found.items():
        assert all(need[name] in k for k in kws), (name, kws)


# ============================================================================================ cap
def test_map_reduce_is_capped_typed_before_any_call(architect):
    rec = _Recorder({})
    d = ChunkedSpecDecomposer(genai_client=rec, model_name="m")
    d.MAX_DOMAIN_CHUNKS = 2
    spec = "\n".join(f"# Domain {i}\n" + ("detail line for this domain.\n" * 700) for i in range(3))
    with pytest.raises(SpecTooLargeError) as ei:
        d.decompose_large_specification(spec, "shop")
    body = ei.value.to_body()
    assert rec.prompts == [] and body["error_class"] == "OPERATOR_ACTION_REQUIRED"
    assert body["reason"] == "ARCHITECT_SPEC_TOO_LARGE" and body["details"]["chunks"] == 3
    # the architect never falls back to a single-turn plan for an over-cap specification
    h, agent, _ = architect
    agent.spec_decomposer = d
    agent.genai_client = _Recorder({**BASE, "service_topology": GOOD})
    with pytest.raises(SpecTooLargeError):
        agent.decompose(spec_text=spec, product_id="shop", trace_id="t-cap", topology_gate=False)
    assert agent.genai_client.prompts == []


def test_negative_default_cap_allows_a_90_page_spec():
    d = ChunkedSpecDecomposer(genai_client=None)
    spec = "\n".join(f"# Domain {i}\n" + ("detail line for this domain.\n" * 600) for i in range(15))
    assert len(spec) > 250_000 and len(d.split_spec_into_domains(spec)) <= d.MAX_DOMAIN_CHUNKS
    assert d.decompose_large_specification(spec, "shop").product_id == "shop"


# ============================================================================================ consensus
def _cycle_plan():
    steps = [BuildPlanStep(step_id="S1", depends_on=["S2"], category=BuildStepCategory.FOUNDATION_API),
             BuildPlanStep(step_id="S2", depends_on=["S1"], category=BuildStepCategory.COMPUTE)]
    return ArchitecturePlan(product_id="shop", sequenced_build_plan=SequencedBuildPlan(steps=steps))


def _sound_plan():
    steps = [BuildPlanStep(step_id="S1", depends_on=[], category=BuildStepCategory.FOUNDATION_API),
             BuildPlanStep(step_id="S2", depends_on=["S1"], category=BuildStepCategory.COMPUTE)]
    return ArchitecturePlan(product_id="shop", sequenced_build_plan=SequencedBuildPlan(steps=steps))


def _arch(patched=None, map_reduce=False):
    arch = MagicMock()
    arch.genai_client = None
    arch.db = None
    arch.last_decomposition_path = "map_reduce" if map_reduce else "single_turn"   # RT F3: the recorded path
    arch.decompose.return_value = SimpleNamespace(architecture_plan=patched)
    return arch


def test_map_reduce_plan_is_never_remediated_by_re_running_map_reduce():
    arch = _arch(map_reduce=True)
    plan = _cycle_plan()
    out, tel = DualArchitectConsensusEngine(genai_client=None).evaluate_and_reconcile(
        plan=plan, spec_text="x", architect_agent=arch, product_id="shop", trace_id="t", context=_full_ctx())
    arch.decompose.assert_not_called()
    assert out is plan and tel.consensus_status == "CRITIQUE_FAILED" and tel.has_critical_findings
    assert not tel.remediation_performed and "map-reduce" in tel.remediation_diff_summary
    assert "Resolved" not in tel.remediation_diff_summary


def test_rt_f3_large_spec_whose_map_reduce_failed_is_remediated_from_its_single_turn_draft():
    """RT F3: the skip reads the path that PRODUCED the plan, not the spec text. A map-reduce failure falls back to
    single-turn, and that draft gets the remediation turn (it used to be skipped as 'map-reduce')."""
    arch = _arch(patched=_sound_plan())
    arch.uses_map_reduce = lambda text: True          # the spec text alone would still say "map-reduce"
    out, tel = DualArchitectConsensusEngine(genai_client=None).evaluate_and_reconcile(
        plan=_cycle_plan(), spec_text="x", architect_agent=arch, product_id="shop", trace_id="t")
    arch.decompose.assert_called_once()
    assert tel.remediation_performed and tel.consensus_status == "AUTO_REMEDIATED"


def test_rt_f3_decompose_records_the_path_that_produced_the_plan(architect):
    h, agent, _ = architect

    def boom(text, prod, context=None):
        raise RuntimeError("map step failed")
    agent.spec_decomposer = SimpleNamespace(should_activate_map_reduce=lambda text: True,
                                            decompose_large_specification=boom)
    agent.genai_client = _Recorder({**BASE, "service_topology": GOOD})
    agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="t-f3a", topology_gate=False)
    assert agent.last_decomposition_path == "single_turn"
    agent.spec_decomposer = SimpleNamespace(should_activate_map_reduce=lambda text: True,
                                            decompose_large_specification=lambda t, p, context=None:
                                            ArchitecturePlanDAG(**BASE))
    agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="t-f3b", topology_gate=False)
    assert agent.last_decomposition_path == "map_reduce"


def test_rt_f3_remediation_turn_patches_the_draft_and_never_re_runs_map_reduce(architect):
    h, agent, _ = architect
    called = []
    agent.spec_decomposer = SimpleNamespace(should_activate_map_reduce=lambda text: True,
                                            decompose_large_specification=lambda *a, **k: called.append(1))
    agent.genai_client = _Recorder({**BASE, "service_topology": GOOD})
    agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="t-f3c", topology_gate=False,
                    bypass_consensus=True, remediation_brief="CRITICAL: fix the cycle")
    assert called == [] and agent.last_decomposition_path == "single_turn"


def test_resolved_only_after_a_clean_re_audit():
    arch = _arch(patched=_sound_plan())
    out, tel = DualArchitectConsensusEngine(genai_client=None).evaluate_and_reconcile(
        plan=_cycle_plan(), spec_text="x", architect_agent=arch, product_id="shop", trace_id="t")
    assert tel.consensus_status == "AUTO_REMEDIATED" and not tel.has_critical_findings
    assert "Re-audit of the patched plan found no critical finding" in tel.remediation_diff_summary
    assert "Resolved:" in tel.remediation_diff_summary and tel.soundness_score == 1.0     # the re-audit's score
    assert [s.persona for s in tel.subagents].count("RED_TEAM_CRITIC") == 2


def test_patched_plan_that_still_fails_the_re_audit_is_critique_failed():
    arch = _arch(patched=_cycle_plan())
    out, tel = DualArchitectConsensusEngine(genai_client=None).evaluate_and_reconcile(
        plan=_cycle_plan(), spec_text="x", architect_agent=arch, product_id="shop", trace_id="t")
    assert tel.consensus_status == "CRITIQUE_FAILED" and tel.has_critical_findings and tel.remediation_performed
    assert "Resolved" not in tel.remediation_diff_summary and "remain" in tel.remediation_diff_summary
    assert tel.soundness_score != 0.95


def test_llm_findings_are_not_claimed_resolved_by_an_offline_re_audit():
    eng = DualArchitectConsensusEngine(genai_client=None)
    crit = ArchitecturalCritique(soundness_score=0.3, has_critical_findings=True, findings=[
        {"category": "SPEC_COVERAGE", "severity": "CRITICAL", "description": "dropped the audit log",
         "recommended_remediation": "add it"}], gauntlet_checks=[], verdict_summary="x")
    clean = ArchitecturalCritique(soundness_score=1.0, has_critical_findings=False, findings=[], gauntlet_checks=[])
    audits = iter([(crit, True), (clean, False)])     # first audit by the LLM critic, the re-audit offline

    def audit_plan(**kw):
        result, used = next(audits)
        eng.critic.last_audit_used_llm = used
        return result
    eng.critic.audit_plan = audit_plan
    arch = _arch(patched=_sound_plan())
    out, tel = eng.evaluate_and_reconcile(plan=_sound_plan(), spec_text="x", architect_agent=arch,
                                          product_id="shop", trace_id="t")
    assert tel.consensus_status == "CRITIQUE_FAILED" and tel.has_critical_findings
    assert "Not verified" in tel.remediation_diff_summary and "Resolved" not in tel.remediation_diff_summary
    assert crit.findings[0].severity == CritiqueSeverity.CRITICAL


# ============================================================================================ RT14-16
CRITIC_NO_FEEDBACK_SHA = "796b4bda4f55e5110b7da42ce146d6c90f90228bf77f0e6c8eb095a2d6468018"


def _critical(desc="the plan keeps Redis although the spec names it"):
    return ArchitecturalCritique(soundness_score=0.2, has_critical_findings=True, findings=[
        {"category": "SPEC_COVERAGE", "severity": "CRITICAL", "description": desc,
         "recommended_remediation": "add Redis back"}], gauntlet_checks=[], verdict_summary="x")


def test_remediation_turn_gets_the_operator_feedback_quota_and_the_draft_plan():
    eng = DualArchitectConsensusEngine(genai_client=None)
    calls = []
    draft = ArchitecturePlan(**{**BASE, "code_tasks": [{"task_id": "CODE-SESSIONS-01", "title": "Firestore sessions"}]})
    arch = SimpleNamespace(decompose=lambda **kw: calls.append(kw) or SimpleNamespace(architecture_plan=draft))
    eng._execute_remediation_turn(plan=draft, critique=_critical(), spec_text="spec", architect_agent=arch,
                                  product_id="shop", trace_id="t", context=_full_ctx())
    kw = calls[0]
    assert kw["human_feedback"] == FEEDBACK and kw["quota_snapshot"] is QUOTA and kw["policy_matrix"] is POLICY
    brief = kw["remediation_brief"]
    assert "ADVERSARIAL RED-TEAM ARCHITECTURAL AUDIT" in brief and "takes precedence over this critique" in brief
    assert "--- DRAFT PLAN (typed JSON" in brief and "CODE-SESSIONS-01" in brief
    assert FEEDBACK not in brief      # the operator's words stay in the operator's own block


def test_negative_without_operator_feedback_the_brief_has_no_precedence_line():
    eng = DualArchitectConsensusEngine(genai_client=None)
    calls = []
    arch = SimpleNamespace(decompose=lambda **kw: calls.append(kw) or SimpleNamespace(architecture_plan=_sound_plan()))
    eng._execute_remediation_turn(plan=_sound_plan(), critique=_critical(), spec_text="spec", architect_agent=arch,
                                  product_id="shop", trace_id="t")
    assert calls[0]["human_feedback"] is None and "takes precedence" not in calls[0]["remediation_brief"]


def test_remediation_prompt_puts_the_operator_guidance_ahead_of_the_critique(architect):
    h, agent, _ = architect
    agent.genai_client = _Recorder({**BASE, "service_topology": GOOD})
    eng = DualArchitectConsensusEngine(genai_client=None)
    eng._execute_remediation_turn(plan=_sound_plan(), critique=_critical(), spec_text="Build a shop with Redis",
                                  architect_agent=agent, product_id="shop", trace_id="t-16",
                                  context=ArchitectContext(human_feedback=FEEDBACK))
    prompt = agent.genai_client.prompts[0]
    op = prompt.index("--- OPERATOR REWORK GUIDANCE / FEEDBACK ---")
    crit = prompt.index("--- ADVERSARIAL RED-TEAM ARCHITECTURAL AUDIT")
    assert op < crit and FEEDBACK in prompt[op:crit] and "--- DRAFT PLAN" in prompt[crit:]
    # the critique is never presented as the operator's words
    assert "ADVERSARIAL" not in prompt[op:prompt.index("--- END OPERATOR GUIDANCE ---")]


def test_critic_sees_the_operator_feedback_so_a_removal_is_not_a_dropped_directive():
    rec = _Recorder({"soundness_score": 1.0, "has_critical_findings": False, "findings": [], "gauntlet_checks": []})
    critic = rtc.RedTeamCritic(genai_client=rec, model_name="m")
    critic.audit_plan(plan=ArchitecturePlan(product_id="shop"), spec_text="Build a shop",
                      policy_matrix={"restrict_public_sql": True}, context=ArchitectContext(human_feedback=FEEDBACK))
    assert FEEDBACK in rec.prompts[0] and "has NOT dropped a directive" in rec.prompts[0]


def test_negative_critic_prompt_without_feedback_is_unchanged():
    rec = _Recorder({})
    for ctx in (None, ArchitectContext(policy_matrix={"restrict_public_sql": True})):
        rtc.RedTeamCritic(genai_client=rec, model_name="m").audit_plan(
            plan=ArchitecturePlan(product_id="shop"), spec_text="Build a shop",
            policy_matrix={"restrict_public_sql": True}, context=ctx)
    assert [_sha(p) for p in rec.prompts] == [CRITIC_NO_FEEDBACK_SHA, CRITIC_NO_FEEDBACK_SHA]


def test_consensus_gives_both_audits_and_the_remediation_the_same_context():
    eng = DualArchitectConsensusEngine(genai_client=None)
    seen = []
    results = iter([_critical(), ArchitecturalCritique(soundness_score=0.9, has_critical_findings=False)])

    def audit_plan(**kw):
        seen.append(kw["context"])
        return next(results)
    eng.critic.audit_plan = audit_plan
    arch = _arch(patched=_sound_plan())
    ctx = _full_ctx()
    out, tel = eng.evaluate_and_reconcile(plan=_sound_plan(), spec_text="x", architect_agent=arch,
                                          product_id="shop", trace_id="t", context=ctx)
    assert seen == [ctx, ctx] and arch.decompose.call_args.kwargs["human_feedback"] == FEEDBACK
    assert tel.consensus_status == "AUTO_REMEDIATED" and tel.soundness_score == 0.9
