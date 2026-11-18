"""PLAN-CONTRACT-CHECK §3.2 (W3 commit 1): the keyword build-plan generator no longer plans a CICD step.

`ArchitectAgent._generate_sequenced_build_plan` runs whenever the model omits `sequenced_build_plan` (309 of 915
recorded plans). It used to plant `STEP-CICD` with `target_files=["cloudbuild.yaml"]` and "docker build, push"
criteria, a file the developer deletes on GitHub and the platform writes itself on Serverless Git. New pins: no CICD
step, `STEP-COMPUTE.depends_on == ["STEP-IAM", "STEP-APP-CODE"]`, contiguous `step_index`, `total_steps`, and no
keyword plan targets a file the platform deletes (the developer's exact predicates; the plan-contract check itself
for GITHUB, SERVERLESS_GIT and an unknown VCS kind once `architect_agent.plan_contract` is present)."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from architect_agent.handler import ArchitectAgent  # noqa: E402
from architect_agent.schemas import ArchitecturePlan, BuildStepCategory  # noqa: E402

COMPUTE_SPECS = {
    "fastapi_firestore": "Deploy a FastAPI service with a Firestore database and an HTTP API.",
    "vpc_cloudsql": "Deploy a FastAPI service reaching Cloud SQL through a VPC connector.",
    "storage_pubsub": "Build a web API that stores uploads in a GCS bucket and publishes to a Pub/Sub topic.",
    "seed_email": "Deploy a FastAPI service for lead_developer@company.org with Firestore.",
}
NON_COMPUTE_SPECS = {
    "blank_shell": "A blank shell workload with no resources.",
    "bucket_only": "Create a GCS bucket.",
}
ALL_SPECS = {**COMPUTE_SPECS, **NON_COMPUTE_SPECS}


def _keyword_plan(spec, assigned_cidr=None):
    agent = ArchitectAgent.__new__(ArchitectAgent)   # the generator reads no agent state; no clients are built
    return agent._generate_sequenced_build_plan(product_id="kw-svc", trace_id="trace-kw-0001", spec_text=spec,
                                                assigned_cidr=assigned_cidr)


@pytest.mark.parametrize("name", sorted(ALL_SPECS))
def test_no_cicd_step_and_no_cloudbuild_target(name):
    plan = _keyword_plan(ALL_SPECS[name])
    assert all(s.category != BuildStepCategory.CICD for s in plan.steps)
    assert "STEP-CICD" not in [s.step_id for s in plan.steps]
    assert all("cloudbuild.yaml" not in s.target_files for s in plan.steps)
    for s in plan.steps:   # nothing depends on a step that no longer exists
        assert "STEP-CICD" not in s.depends_on


@pytest.mark.parametrize("name", sorted(COMPUTE_SPECS))
def test_compute_step_depends_on_iam_and_app_code(name):
    plan = _keyword_plan(COMPUTE_SPECS[name])
    compute = next(s for s in plan.steps if s.step_id == "STEP-COMPUTE")
    assert compute.depends_on == ["STEP-IAM", "STEP-APP-CODE"]
    ids = [s.step_id for s in plan.steps]
    assert ids.index("STEP-IAM") < ids.index("STEP-APP-CODE") < ids.index("STEP-COMPUTE")


def test_compute_plan_step_sequence_is_exact():
    plan = _keyword_plan(COMPUTE_SPECS["fastapi_firestore"])
    assert [s.step_id for s in plan.steps] == ["STEP-01-APIS", "STEP-02-DATABASE", "STEP-REGISTRY", "STEP-IAM",
                                               "STEP-APP-CODE", "STEP-COMPUTE", "STEP-TESTS"]


@pytest.mark.parametrize("name", sorted(ALL_SPECS))
@pytest.mark.parametrize("cidr", [None, "10.100.0.16/28"])
def test_step_indices_contiguous_and_total_steps(name, cidr):
    plan = _keyword_plan(ALL_SPECS[name], assigned_cidr=cidr)
    assert [s.step_index for s in plan.steps] == list(range(1, len(plan.steps) + 1))
    assert plan.total_steps == len(plan.steps)
    ids = {s.step_id for s in plan.steps}
    for s in plan.steps:   # every dependency names a step of this plan
        assert set(s.depends_on) <= ids


def test_required_cloud_apis_unchanged():
    """§3.2: `required_cloud_apis` is not a v1 kind and stays exactly as before."""
    plan = _keyword_plan(COMPUTE_SPECS["fastapi_firestore"])
    assert plan.required_cloud_apis == ["run.googleapis.com", "firestore.googleapis.com", "cloudbuild.googleapis.com",
                                        "artifactregistry.googleapis.com", "iam.googleapis.com"]


def test_non_compute_plans_are_unchanged():
    """Negative: plans without compute never had a CICD step; their step sequences are exactly as before."""
    assert [s.step_id for s in _keyword_plan(NON_COMPUTE_SPECS["blank_shell"]).steps] == [
        "STEP-01-SCAFFOLD", "STEP-02-DOCS"]
    assert [s.step_id for s in _keyword_plan(NON_COMPUTE_SPECS["bucket_only"]).steps] == [
        "STEP-01-APIS", "STEP-STORAGE", "STEP-IAM", "STEP-DOCS"]


@pytest.mark.parametrize("name", sorted(ALL_SPECS))
def test_no_target_is_a_file_the_platform_deletes(name):
    """The developer's exact predicates (imported, never copied): no keyword target is a CI file the platform purges
    (other than a generated deploy workflow) or a container file."""
    from qa_auditor.judge_input import is_platform_ci_path, is_platform_deploy_workflow
    from developer_agent.handler import is_prohibited_container_file
    for s in _keyword_plan(ALL_SPECS[name]).steps:
        for p in s.target_files:
            assert not (is_platform_ci_path(p) and not is_platform_deploy_workflow(p)), (s.step_id, p)
            assert not is_prohibited_container_file(p), (s.step_id, p)


@pytest.mark.parametrize("name", sorted(ALL_SPECS))
@pytest.mark.parametrize("vcs_kind", ["GITHUB", "SERVERLESS_GIT", None])
def test_every_keyword_plan_passes_the_plan_contract(name, vcs_kind):
    plan_contract = pytest.importorskip("architect_agent.plan_contract")
    plan = ArchitecturePlan(product_id="kw-svc", summary="s", architecture_overview="o", infra_tasks=[],
                            code_tasks=[], sequenced_build_plan=_keyword_plan(ALL_SPECS[name]))
    violations, _not_checked = plan_contract.check_plan_contract(plan, vcs_kind)
    assert violations == []
