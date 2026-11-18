"""FD-4AM-d (owner 10-20): three red-team critic changes.

1. The golden-module catalog given to the critic excludes the host-only `workflows` module (FD-4CB), reusing the
   existing named exclusion HOST_PLATFORM_ONLY_MODULES (FD-4AM-c).
2. The critic system prompt no longer names the invented module `cicd-github-actions-wif` as a catalog example.
3. When the LLM critic is unavailable or fails, the deterministic fallback reports the IAM, spec-coverage and FinOps
   items as WARNING "Not checked (...)" instead of an unchecked PASSED (grounding already did since FD-4AM-c).

Negative tests: a plan that passed before still passes (no new critical finding, same score / verdict / fast-pass),
the LLM path's own statuses are returned unchanged, and nothing else in the prompt or catalog moves.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import json
import os
import re
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if GATEWAY_DIR not in sys.path:
    sys.path.append(GATEWAY_DIR)

from architect_agent import red_team_critic as rtc  # noqa: E402
from architect_agent.consensus_engine import DualArchitectConsensusEngine  # noqa: E402
from architect_agent.schemas import ArchitecturePlan, TaskCategory, TaskItem  # noqa: E402

INVENTED = "cicd-github-actions-wif"
PROMPT_COPIES = [
    "shared/builtin_prompts.py",
    "apps/orchestrator-gateway/shared/builtin_prompts.py",
    "apps/control-center/shared/builtin_prompts.py",
    "mcp-servers/terraform/shared/builtin_prompts.py",  # unused, already-drifted copy (test_shared_packaging)
]
EXAMPLE_LIST = ("(e.g. `compute-cloudrun`, `networking-vpc`, `database-cloudsql`, `storage-bucket`, "
                "`messaging-pubsub`, `cache-redis`, `security-kms`).")
CHECK_ORDER = ["DAG Topology & Cycles", "IAM & Security Sequencing", "Golden Modules Grounding",
               "User Specification Coverage", "FinOps & Anti-Bloat Sizing Sanity"]
NOT_CHECKED_ITEMS = CHECK_ORDER[1:]
OLD_UNCHECKED_PASS_TEXT = ["Deterministic baseline verification", "assumed covered",
                           "Default budget guardrails enforced", "Verified against canonical golden catalog"]


def _prompt_constant(rel):
    tree = ast.parse(open(os.path.join(REPO_ROOT, rel), encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "ARCHITECT_RED_TEAM_CRITIC_PROMPT"
                                                for t in node.targets):
            return node.value.value
    raise AssertionError(f"no ARCHITECT_RED_TEAM_CRITIC_PROMPT in {rel}")


def _workload_catalog_keys():
    """BUILTIN_MODULE_METADATA keys (the modules offered to workloads), read with ast: importing the provider pulls
    in module_inspector, which this test does not need."""
    rel = "apps/orchestrator-gateway/shared/builtin_modules_provider.py"
    tree = ast.parse(open(os.path.join(REPO_ROOT, rel), encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", None) == "BUILTIN_MODULE_METADATA":
            return {k.value for k in node.value.keys}
    raise AssertionError("no BUILTIN_MODULE_METADATA")


def _plan(tasks=None):
    return ArchitecturePlan(product_id="p-fd4am-d", infra_tasks=list(tasks or []), code_tasks=[])


def _checks(critique):
    return {c.invariant_name: c for c in critique.gauntlet_checks}


# ---------------------------------------------------------------------------------------- 1. catalog exclusion
def test_workflows_is_a_named_host_only_exclusion_and_not_offered():
    assert "workflows" in rtc.HOST_PLATFORM_ONLY_MODULES
    assert "workflows" not in rtc.CANONICAL_GOLDEN_MODULES
    assert "cloud_build" not in rtc.CANONICAL_GOLDEN_MODULES


def test_workflows_reads_host_repo_files_so_it_is_host_only():
    """The FD-4CB evidence, pinned: the golden `workflows` module reads the host repo's workflow YAML."""
    main_tf = open(os.path.join(REPO_ROOT, "infra", "modules", "workflows", "main.tf"), encoding="utf-8").read()
    assert "/../../../workflows/main_orchestrator.yaml" in main_tf


def test_exclusion_drops_no_module_offered_to_workloads():
    """Negative: every module the workload catalog offers is still in the critic catalog (incl. `workflows-dag`),
    and no excluded module is one a workload is offered."""
    offered = _workload_catalog_keys()
    assert "workflows" not in offered and "cloud_build" not in offered
    assert offered <= set(rtc.CANONICAL_GOLDEN_MODULES), sorted(offered - set(rtc.CANONICAL_GOLDEN_MODULES))
    assert "workflows-dag" in rtc.CANONICAL_GOLDEN_MODULES
    assert not (offered & rtc.HOST_PLATFORM_ONLY_MODULES)


def test_catalog_shrinks_by_exactly_workflows():
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES

    # FD-4BH: the platform-rendered networking-vpc-connector is not offered either (a plan never names it)
    assert set(BUILTIN_MODULE_FILES) - set(rtc.CANONICAL_GOLDEN_MODULES) == {"workflows", "networking-vpc-connector"}
    assert len(rtc.CANONICAL_GOLDEN_MODULES) == len(BUILTIN_MODULE_FILES) - 2


# ---------------------------------------------------------------------------------------- 2. the system prompt
@pytest.mark.parametrize("rel", PROMPT_COPIES)
def test_prompt_copies_drop_the_invented_module(rel):
    prompt = _prompt_constant(rel)
    assert INVENTED not in prompt
    assert EXAMPLE_LIST in prompt  # the rest of the example list is unchanged


def test_every_prompt_example_is_a_real_offered_module():
    from shared.builtin_prompts import ARCHITECT_RED_TEAM_CRITIC_PROMPT

    line = next(ln for ln in ARCHITECT_RED_TEAM_CRITIC_PROMPT.splitlines() if "Golden Modules catalog (e.g." in ln)
    examples = re.findall(r"`([^`]+)`", line)
    assert examples == ["compute-cloudrun", "networking-vpc", "database-cloudsql", "storage-bucket",
                        "messaging-pubsub", "cache-redis", "security-kms"]
    assert set(examples) <= set(rtc.CANONICAL_GOLDEN_MODULES)


def test_the_three_live_prompt_copies_stay_identical():
    a, b, c = (_prompt_constant(r) for r in PROMPT_COPIES[:3])
    assert a == b == c


# ------------------------------------------------------------------------------- 1+2. what the critic actually sends
_CRITIQUE = {"soundness_score": 0.9, "has_critical_findings": False, "findings": [],
             "gauntlet_checks": [{"invariant_name": n, "status": "PASSED", "details": "llm checked"}
                                 for n in CHECK_ORDER],
             "verdict_summary": "Architectural plan verified without critical defects."}


@pytest.fixture()
def no_settings(monkeypatch):
    import shared.settings as settings_mod

    def _no_settings():  # no Firestore: the critic keeps its default token limit
        raise RuntimeError("no platform settings in this test")

    monkeypatch.setattr(settings_mod, "get_platform_settings", _no_settings)
    monkeypatch.setattr(rtc, "get_model_cascade_for_agent", lambda *a, **kw: ["fake-critic"])


def _client(response=None, error=None):
    client = MagicMock()
    if error is not None:
        client.models.generate_content.side_effect = error
    else:
        client.models.generate_content.return_value = response
    return client


def test_critic_request_has_no_workflows_entry_and_no_invented_example(no_settings):
    client = _client(SimpleNamespace(text=json.dumps(_CRITIQUE), candidates=[], usage_metadata=None))
    out = rtc.RedTeamCritic(genai_client=client, model_name="fake-critic").audit_plan(plan=_plan(), spec_text="x")
    kwargs = client.models.generate_content.call_args.kwargs
    catalog = json.loads(kwargs["contents"].split("### CANONICAL GOLDEN MODULES CATALOG (ALLOWED PLATFORM MODULES):\n")[1]
                         .split("\n\n### ORIGINAL USER SPECIFICATION:")[0])
    assert catalog == rtc.CANONICAL_GOLDEN_MODULES
    assert "workflows" not in catalog and "workflows-dag" in catalog
    system = kwargs["config"]["system_instruction"]  # Flash: adapt_generate_config_kwargs returns the kwargs dict
    assert INVENTED not in system and EXAMPLE_LIST in system
    # negative: the LLM path keeps the critic's own statuses (no "not checked" wording is injected)
    assert [(c.invariant_name, c.status, c.details) for c in out.gauntlet_checks] == [
        (n, "PASSED", "llm checked") for n in CHECK_ORDER]


# ------------------------------------------------------------------------------------ 3. fallback "not checked"
def _assert_honest_fallback(out):
    checks = _checks(out)
    assert [c.invariant_name for c in out.gauntlet_checks] == CHECK_ORDER
    for name in NOT_CHECKED_ITEMS:
        assert checks[name].status == "WARNING", name
        assert checks[name].details.startswith(rtc.FALLBACK_NOT_CHECKED + ": "), name
    assert rtc.FALLBACK_NOT_CHECKED == "Not checked (LLM critic unavailable)"
    for c in out.gauntlet_checks:
        for old in OLD_UNCHECKED_PASS_TEXT:
            assert old not in c.details, (c.invariant_name, old)


def test_fallback_without_a_client_says_not_checked():
    out = rtc.RedTeamCritic(genai_client=None).audit_plan(plan=_plan(), spec_text="Build a todo API")
    _assert_honest_fallback(out)
    assert _checks(out)["DAG Topology & Cycles"].status == "PASSED"  # the one check that really ran


def test_fallback_after_an_llm_error_says_not_checked(no_settings):
    client = _client(error=RuntimeError("503 UNAVAILABLE"))
    out = rtc.RedTeamCritic(genai_client=client, model_name="fake-critic").audit_plan(plan=_plan(), spec_text="x")
    assert client.models.generate_content.called
    _assert_honest_fallback(out)


def test_fallback_after_an_unparseable_llm_answer_says_not_checked(no_settings):
    client = _client(SimpleNamespace(text="not json", candidates=[], usage_metadata=None))
    out = rtc.RedTeamCritic(genai_client=client, model_name="fake-critic").audit_plan(plan=_plan(), spec_text="x")
    _assert_honest_fallback(out)


def test_fallback_keeps_a_valid_plan_passing():
    """Do No Harm: the honest wording is advisory only. 0 critical findings, score 1.0, same verdict, and the
    consensus engine still takes the fast pass (CONSENSUS_VERIFIED) with the plan unchanged."""
    out = rtc.RedTeamCritic(genai_client=None).audit_plan(plan=_plan(), spec_text="Build a todo API")
    assert out.has_critical_findings is False
    assert out.soundness_score == 1.0
    assert out.findings == []
    assert out.verdict_summary == "Plan passed deterministic topological validation (offline mode)."

    plan = _plan()
    architect = SimpleNamespace(genai_client=None)
    got_plan, tel = DualArchitectConsensusEngine().evaluate_and_reconcile(
        plan=plan, spec_text="Build a todo API", architect_agent=architect, product_id="p", trace_id="t")
    assert got_plan is plan
    assert tel.consensus_status == "CONSENSUS_VERIFIED"
    assert tel.has_critical_findings is False and tel.remediation_performed is False
    assert [c.status for c in tel.gauntlet_checks] == ["PASSED"] + ["WARNING"] * 4


def test_fallback_on_a_cyclic_plan_still_blocks():
    tasks = [TaskItem(task_id="INFRA-01", category=TaskCategory.INFRA, depends_on=["INFRA-02"]),
             TaskItem(task_id="INFRA-02", category=TaskCategory.INFRA, depends_on=["INFRA-01"])]
    out = rtc.RedTeamCritic(genai_client=None).audit_plan(plan=_plan(tasks), spec_text="x")
    assert out.has_critical_findings is True
    assert out.soundness_score == 0.5
    assert _checks(out)["DAG Topology & Cycles"].status == "CRITICAL"
    _assert_honest_fallback(out)
