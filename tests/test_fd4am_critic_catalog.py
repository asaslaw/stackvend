"""FD-4AM-c: the red-team critic's golden-module catalog is derived from the built-in module payload (the module set
the developer stage vends), and its deterministic fallback no longer reports a grounding check it did not run.

Before: CANONICAL_GOLDEN_MODULES was a hard-coded list of 24 names, 17 of which do not exist (`database-firestore`,
`cicd-github-actions-wif`, ...), and ~20 real modules were missing; the offline fallback said
"Golden Modules Grounding: PASSED - Verified against canonical golden catalog" without checking anything.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import functools
import json
import os
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
from architect_agent.cycle_detector import validate_dual_layer_dag  # noqa: E402
from architect_agent.schemas import ArchitecturePlan, TaskCategory, TaskItem  # noqa: E402

PAYLOAD_COPIES = [
    "shared/builtin_modules_payload.py",
    "apps/control-center/shared/builtin_modules_payload.py",
    "apps/orchestrator-gateway/shared/builtin_modules_payload.py",
    "mcp-servers/terraform/shared/builtin_modules_payload.py",
]
# The 17 names of the old hard-coded list that are not golden modules (FD27-19(d) / FD24-12).
INVENTED_NAMES = [
    "database-firestore", "security-secret-manager", "cicd-github-actions-wif", "iam-workload-identity",
    "observability-monitoring", "load-balancer-https", "api-gateway", "dns-managed-zone", "bigquery-dataset",
    "eventarc-trigger", "artifact-registry", "cloud-build-trigger", "cloud-tasks-queue", "workflows-pipeline",
    "spanner-instance", "alloydb-cluster", "composer-environment",
]
GROUNDING = "Golden Modules Grounding"


@functools.lru_cache(maxsize=None)
def _payload_keys(rel):
    ns = {}
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
        exec(compile(f.read(), rel, "exec"), ns)  # noqa: S102 - repo-owned data module
    return frozenset(ns["BUILTIN_MODULE_FILES"])


# ------------------------------------------------------------------------------------------------ 1. the catalog
def test_catalog_is_a_sorted_duplicate_free_list_of_str():
    cat = rtc.CANONICAL_GOLDEN_MODULES
    assert isinstance(cat, list) and cat and all(isinstance(m, str) for m in cat)
    assert cat == sorted(cat)
    assert len(cat) == len(set(cat))


@pytest.mark.parametrize("rel", PAYLOAD_COPIES)
def test_every_catalog_entry_is_a_payload_key_and_a_module_directory(rel):
    keys = _payload_keys(rel)
    for mod in rtc.CANONICAL_GOLDEN_MODULES:
        assert mod in keys, mod
        assert os.path.isdir(os.path.join(REPO_ROOT, "infra", "modules", mod)), mod


@pytest.mark.parametrize("rel", PAYLOAD_COPIES)
def test_every_payload_key_is_in_the_catalog_or_the_named_exclusion(rel):
    """A new golden module cannot silently go missing from the critic: it is either offered or explicitly excluded."""
    keys = _payload_keys(rel)
    cat = set(rtc.CANONICAL_GOLDEN_MODULES)
    excl = rtc.HOST_PLATFORM_ONLY_MODULES | rtc.PLATFORM_RENDERED_MODULES   # FD-4BH: the second named exclusion
    assert isinstance(excl, frozenset) and not (rtc.HOST_PLATFORM_ONLY_MODULES & rtc.PLATFORM_RENDERED_MODULES)
    assert not (cat & excl)
    assert excl <= keys, "an exclusion must name a real payload key"
    assert keys == cat | excl


def test_catalog_equals_the_imported_payload_minus_the_exclusion():
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES

    assert rtc.CANONICAL_GOLDEN_MODULES == sorted(set(BUILTIN_MODULE_FILES) - rtc.HOST_PLATFORM_ONLY_MODULES
                                                  - rtc.PLATFORM_RENDERED_MODULES)   # FD-4BH
    assert rtc.PLATFORM_RENDERED_MODULES == frozenset({"networking-vpc-connector"})


def test_exclusion_is_exactly_the_host_platform_modules():
    """FD-4AM-d (owner 10-20, FD-4CB): `workflows`, the host's own orchestrator / SRE workflows module, is excluded (tests/test_fd4am_d_critic.py). FD-4CB-b: the set comes from
    shared/host_platform_modules.py (tests/test_fd4cb_b_host_platform_modules.py)."""
    assert rtc.HOST_PLATFORM_ONLY_MODULES == frozenset({"workflows"})
    assert "workflows" not in rtc.CANONICAL_GOLDEN_MODULES


def test_invented_names_are_gone_and_real_modules_are_present():
    cat = set(rtc.CANONICAL_GOLDEN_MODULES)
    assert not (cat & set(INVENTED_NAMES))
    for real in ("compute-event-worker", "compute-gce-worker", "scheduling-cron", "tasks-queue", "security-secret",
                 "workload-foundation/base", "workload_auth"):
        assert real in cat, real


# ----------------------------------------------------------------------- 1b. FD-4AM-c disk <- payload (both copies)
@pytest.mark.parametrize("rel", ["networking-vpc/main.tf", "compute-gke-autopilot/outputs.tf"])
def test_disk_copies_of_the_fixed_drift_equal_the_payload(rel):
    """The two former KNOWN_DRIFT files: infra/modules and the Control Center copy equal the payload byte-for-byte."""
    ns = {}
    src = "apps/orchestrator-gateway/shared/builtin_modules_payload.py"
    with open(os.path.join(REPO_ROOT, src), encoding="utf-8") as f:
        exec(compile(f.read(), src, "exec"), ns)  # noqa: S102 - repo-owned data module
    mod, fname = rel.split("/")
    entry = ns["BUILTIN_MODULE_FILES"][mod][fname]
    for base in ("infra/modules", "apps/control-center/infra/modules"):
        with open(os.path.join(REPO_ROOT, base, mod, fname), encoding="utf-8", newline="") as f:
            assert f.read() == entry, f"{base}/{rel}"


# ------------------------------------------------------------------------------------- 2. deterministic fallback
def _plan(tasks=None):
    return ArchitecturePlan(product_id="p-fd4am", infra_tasks=list(tasks or []), code_tasks=[])


def _checks(critique):
    return {c.invariant_name: c for c in critique.gauntlet_checks}


def test_fallback_does_not_claim_a_grounding_check_it_did_not_run():
    out = rtc.RedTeamCritic(genai_client=None).audit_plan(plan=_plan(), spec_text="Build a todo API")
    g = _checks(out)[GROUNDING]
    assert g.status != "PASSED"
    assert g.status == "WARNING"
    assert "Verified" not in g.details
    assert g.details.startswith("Not checked (LLM critic unavailable)")


def test_fallback_still_passes_a_plan_that_passed_before():
    """Do No Harm: the honest status is advisory only. A valid plan keeps 0 critical findings, score 1.0, the same
    five checks in the same order, and the same verdict, so the consensus fast-pass is unchanged."""
    out = rtc.RedTeamCritic(genai_client=None).audit_plan(plan=_plan(), spec_text="Build a todo API")
    assert out.has_critical_findings is False
    assert out.soundness_score == 1.0
    assert out.findings == []
    assert [c.invariant_name for c in out.gauntlet_checks] == [
        "DAG Topology & Cycles", "IAM & Security Sequencing", GROUNDING, "User Specification Coverage",
        "FinOps & Anti-Bloat Sizing Sanity"]
    assert out.gauntlet_checks[0].status == "PASSED"
    assert out.verdict_summary == "Plan passed deterministic topological validation (offline mode)."


def test_fallback_on_a_cyclic_plan_is_unchanged():
    tasks = [TaskItem(task_id="INFRA-01", category=TaskCategory.INFRA, depends_on=["INFRA-02"]),
             TaskItem(task_id="INFRA-02", category=TaskCategory.INFRA, depends_on=["INFRA-01"])]
    assert not validate_dual_layer_dag(steps=[], infra_tasks=tasks, code_tasks=[]).is_valid
    out = rtc.RedTeamCritic(genai_client=None).audit_plan(plan=_plan(tasks), spec_text="x")
    assert out.has_critical_findings is True
    assert out.soundness_score == 0.5
    assert _checks(out)["DAG Topology & Cycles"].status == "CRITICAL"
    assert _checks(out)[GROUNDING].status == "WARNING"


# --------------------------------------------------------------------------------------- 3. the critic's prompt
_CRITIQUE = {"soundness_score": 0.9, "has_critical_findings": False, "findings": [],
             "gauntlet_checks": [{"invariant_name": "DAG Topology & Cycles", "status": "PASSED", "details": "ok"},
                                 {"invariant_name": GROUNDING, "status": "PASSED", "details": "llm checked"}],
             "verdict_summary": "Architectural plan verified without critical defects."}


@pytest.fixture()
def recorded_critic(monkeypatch):
    import shared.settings as settings_mod

    def _no_settings():  # no Firestore: the critic keeps its default token limit
        raise RuntimeError("no platform settings in this test")

    monkeypatch.setattr(settings_mod, "get_platform_settings", _no_settings)
    monkeypatch.setattr(rtc, "get_model_cascade_for_agent", lambda *a, **kw: ["fake-critic"])
    client = MagicMock()
    client.models.generate_content.return_value = SimpleNamespace(text=json.dumps(_CRITIQUE), candidates=[],
                                                                  usage_metadata=None)
    return rtc.RedTeamCritic(genai_client=client, model_name="fake-critic"), client


def test_critic_user_prompt_carries_the_derived_catalog(recorded_critic):
    critic, client = recorded_critic
    out = critic.audit_plan(plan=_plan(), spec_text="Build a todo API")
    assert client.models.generate_content.call_count == 1
    contents = client.models.generate_content.call_args.kwargs["contents"]
    block = ("### CANONICAL GOLDEN MODULES CATALOG (ALLOWED PLATFORM MODULES):\n"
             f"{json.dumps(rtc.CANONICAL_GOLDEN_MODULES, indent=2)}\n\n### ORIGINAL USER SPECIFICATION:\n")
    assert contents.startswith(block)
    catalog_part = contents.split("### ORIGINAL USER SPECIFICATION:")[0]
    for name in INVENTED_NAMES:
        assert f'"{name}"' not in catalog_part, name
    assert '"cloud_build"' not in catalog_part
    # the LLM path is unchanged: its own gauntlet result is returned as-is
    assert _checks(out)[GROUNDING].status == "PASSED" and _checks(out)[GROUNDING].details == "llm checked"
