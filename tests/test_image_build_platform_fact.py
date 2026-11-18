"""IMAGE-BUILD-PLATFORM-FACT (live ex01-g13 on stackvend13, 11-16; docs/handoff/ex01-g13-cloudbuild-plan-task-diagnosis.md).

Example 01 failed PLATFORM_DEFECT after a clean build (100% tests, bandit clean): the architect's INFRA-05 asked for a
`cloudbuild.yaml` that builds the image with Cloud Native Buildpacks, beside the platform's deploy workflow. The
developer wrote the file, the developer handler removed it (the platform owns every CI and build file), and the
adherence judge reported "cloudbuild.yaml is missing" (no file named). QA routed the finding to the task's one committed
target, the platform-rendered `.github/workflows/deploy-ex01-g13.yml`, and the developer stopped the run
(QA_FINDING_ON_PLATFORM_RENDERED_FILE). The platform builds every container image itself (`pack build` in its own Cloud
Build at deploy time), so the plan's build file is met by the platform.

Fix: the ADHERENCE-PLATFORM-SATISFIED facet IMAGE_BUILD (SATISFIED), handled when the commit's root module calls a
golden compute module of a container kind (exact parse). Its label applies to a finding on a plan task whose typed
kinds are infrastructure or CI/CD, or with no task to a named file under the workload IaC root or an exact platform CI
path; a CODE task's finding, an app file or a Procfile stays blocking. Every other facet keeps its rule exactly.
Scenario corpus 12a-12c replay the live route end to end.
"""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

import fd4f_support  # noqa: E402,F401  (gateway dir on sys.path)
from qa_auditor import platform_satisfied as PS  # noqa: E402

CLOUDBUILD_MSG = ("cloudbuild.yaml is missing from the repository; INFRA-05 requires cloudbuild.yaml to build the "
                  "container strictly via Google Cloud Native Buildpacks (pack / --pack)")
DAG = [
    {"task_id": "INFRA-05", "category": "INFRA", "target_files": ["cloudbuild.yaml", ".github/workflows/deploy-svc.yml"]},
    {"task_id": "STEP-CICD", "category": "CICD", "target_files": ["cloudbuild.yaml"]},
    {"task_id": "INFRA-IAC", "category": "INFRA", "target_files": ["infra/workload/main.tf"]},
    {"task_id": "CI-PATH", "target_files": ["cloudbuild.yaml"]},             # no category (RT 1: never by path alone)
    {"task_id": "CODE-01", "category": "CODE", "target_files": ["apps/svc/main.py", "apps/svc/Procfile"]},
    {"task_id": "CODE-CI", "category": "CODE",                              # RT 1: a code task with a CI target
     "target_files": ["apps/svc/main.py", ".github/workflows/deploy-svc.yml"]},
    {"task_id": "TEST-01", "category": "TEST", "target_files": ["tests/test_main.py"]},
    {"task_id": "CICD-APP", "category": "CICD",                             # RT 1: a CI task with an app target
     "target_files": ["cloudbuild.yaml", "apps/svc/Procfile"]},
    {"task_id": "CICD-BAD", "category": "CICD", "target_files": "cloudbuild.yaml"},   # malformed targets
]


# ------------------------------------------------------------------------------------------------ typed handling
def test_image_build_is_handled_only_from_the_typed_commit_fact():
    assert PS.FACET_IMAGE_BUILD not in PS.platform_handlings(None)
    assert PS.FACET_IMAGE_BUILD not in PS.platform_handlings({"budget_ceiling_monthly_usd": 10.0},
                                                             deploys_cloud_run=True)
    assert PS.FACET_IMAGE_BUILD not in PS.platform_handlings(None, builds_container_images="yes")   # exact True only
    h = PS.platform_handlings(None, builds_container_images=True)[PS.FACET_IMAGE_BUILD]
    assert h.kind == PS.KIND_SATISFIED and h.known_limitation is None
    assert PS.FACET_IMAGE_BUILD not in PS.SECURITY_FACETS   # the security reviewer is unchanged


def test_the_facts_line_says_the_build_is_met_by_the_platform():
    (line,) = PS.facts_lines(PS.platform_handlings(None, builds_container_images=True))
    assert "(facet IMAGE_BUILD)" in line and "is met by the platform" in line
    assert "`pack build`" in line and "`cloudbuild.yaml`" in line and "`.github/workflows/`" in line
    assert "If you still list it, label it IMAGE_BUILD." in line
    # RT 4: the meaning is an exhaustive list; the developer's own files and other image concerns are named OTHER
    meaning = PS.FACET_MEANINGS[PS.FACET_IMAGE_BUILD]
    assert meaning.startswith("the build of the workload's container images, limited to:")
    for other in ("`requirements.txt`", "`Procfile` or other entrypoint", "`project.toml`", "image signing",
                  "vulnerability scanning", "SBOM or attestation", "base-image pinning", "image tags: those are OTHER"):
        assert other in meaning, other
    # RT 5: VCS-neutral (the platform writes every CI and build file itself, on either provider)
    assert "writes every CI and build file itself (see the VCS provider fact)" in line


def test_without_the_fact_every_other_line_is_unchanged():
    """Do-No-Harm: the facts of a commit the platform builds no image for are exactly as before."""
    before = PS.facts_lines(PS.platform_handlings({"budget_ceiling_monthly_usd": 40}))
    assert all("IMAGE_BUILD" not in line for line in before) and len(before) == 1


# ------------------------------------------------------------------------------------------------ commit fact (gateway)
@pytest.fixture()
def gw(monkeypatch):
    mod = fd4f_support.load_gateway(monkeypatch, "image_build_gw")
    yield mod
    mod.app.dependency_overrides.clear()


def _iac_tree(modules):
    body = "".join(f'module "{label}" {{\n  source = "../modules/{module}"\n}}\n' for label, module in modules)
    return {"infra/workload/main.tf": body, "apps/svc/main.py": "x = 1\n"}


@pytest.mark.parametrize("modules, builds", [
    ([("compute", "compute-cloudrun")], True),
    ([("compute", "compute-event-worker")], True),
    ([("compute", "compute-gke-autopilot")], True),
    ([("compute", "compute-gke-autopilot"), ("compute_edge", "compute-cloudrun")], True),
    ([("compute", "compute-gce-bastion")], False),      # VM kinds: no Buildpacks image (NON_CONTAINER_KINDS)
    ([("compute", "compute-gce-worker")], False),
    ([("storage", "storage-bucket")], False),           # not a compute module
    ([], False),
])
def test_commit_builds_container_images_by_exact_parse(gw, modules, builds):
    assert gw._commit_builds_container_images(_iac_tree(modules)) is builds


def test_a_compute_module_nested_in_a_bundle_is_not_a_root_call(gw):
    bundle = {"infra/workload/main.tf": 'module "stack" {\n  source = "../bundles/three-tier"\n}\n',
              "infra/bundles/three-tier/main.tf": 'module "web" {\n  source = "../../modules/compute-cloudrun"\n}\n'}
    assert gw._commit_builds_container_images(bundle) is False
    assert gw._commit_builds_container_images({}) is False


def test_the_vm_kinds_match_the_terraform_servers_rule():
    from developer_agent.validators.container import NON_CONTAINER_KINDS
    assert NON_CONTAINER_KINDS == frozenset({"gce-bastion", "gce-worker"})


# ------------------------------------------------------------------------------------------------ adherence lens
def _lens(monkeypatch, facets, task_ids, files=None, *, image_build=True, record=None, msg=CLOUDBUILD_MSG, adh=0.94):
    import qa_auditor.judge as judge_mod
    from qa_auditor import adherence_lens as AL
    from qa_auditor.platform_facts import PlatformFacts

    seen = {}

    def fake(prompt, model, **k):
        seen["prompt"] = prompt
        seen["schema"] = k.get("response_schema")
        body = {"instruction_adherence_score": adh, "grounding_score": 1.0, "missed_directives": [msg],
                "hallucinated_features": [], "summary": "s", "missed_directive_task_ids": task_ids}
        if facets is not None:
            body["missed_directive_facets"] = facets
        if files is not None:
            body["missed_directive_files"] = files
        return json.dumps(body)

    monkeypatch.setattr(judge_mod, "call", fake)
    monkeypatch.setattr(judge_mod, "untrusted_block", lambda label, content: f"<<{label}>>{content}<</{label}>>")
    hand = PS.platform_handlings(record, builds_container_images=image_build)
    res = AL.evaluate_adherence_lens("diff --git a/x b/x", task_dag=DAG, pytest_logs="ok", compliance_summary="c",
                                     model_name="m", file_inventory="x",
                                     platform_facts=PlatformFacts(text="- fact", handled=hand))
    return res, seen


@pytest.mark.parametrize("task_id, named", [
    ("INFRA-05", ""), ("STEP-CICD", ""), ("INFRA-05", "cloudbuild.yaml"),
    ("STEP-CICD", ".github/workflows/deploy-svc.yml"), ("INFRA-IAC", "infra/workload/main.tf"),
])
def test_a_labelled_build_file_finding_on_an_infra_or_ci_task_is_satisfied(monkeypatch, task_id, named):
    res, seen = _lens(monkeypatch, ["IMAGE_BUILD"], [task_id], [named])
    assert res.passed is True and res.missed_directives == []
    (sat,) = res.platform_satisfied_directives
    assert sat.facet == "IMAGE_BUILD" and sat.task_id == task_id and sat.directive == CLOUDBUILD_MSG
    assert "IMAGE_BUILD" in seen["prompt"]
    assert "IMAGE_BUILD" in seen["schema"]["properties"]["missed_directive_facets"]["items"]["enum"]


@pytest.mark.parametrize("named", ["cloudbuild.yaml", ".github/workflows/deploy-svc.yml", "infra/workload/main.tf"])
def test_an_unattributed_labelled_finding_on_a_platform_ci_or_iac_path_is_satisfied(monkeypatch, named):
    res, _ = _lens(monkeypatch, ["IMAGE_BUILD"], [""], [named])
    assert res.passed is True and len(res.platform_satisfied_directives) == 1


@pytest.mark.parametrize("facets, task_ids, files, image_build", [
    (["OTHER"], ["INFRA-05"], [""], True),                    # judge did not label it
    (None, ["INFRA-05"], [""], True),                          # no facet field
    (["IMAGE_BUILD"], ["CODE-01"], ["apps/svc/Procfile"], True),   # a code task's finding blocks whatever its label
    (["IMAGE_BUILD"], ["CODE-CI"], [""], True),                # RT 1: a code task with a CI target
    (["IMAGE_BUILD"], ["TEST-01"], [""], True),                # a test task is not infrastructure or CI/CD
    (["IMAGE_BUILD"], ["CI-PATH"], [""], True),                # RT 1: no category, CI target only
    (["IMAGE_BUILD"], ["CICD-APP"], [""], True),               # RT 1: a CI task that also targets app code
    (["IMAGE_BUILD"], ["CICD-BAD"], [""], True),               # malformed target_files
    (["IMAGE_BUILD"], ["INFRA-05"], ["apps/svc/Procfile"], True),          # RT 2: named app file on an infra task
    (["IMAGE_BUILD"], ["INFRA-05"], ["apps/svc/requirements.txt"], True),
    (["IMAGE_BUILD"], ["STEP-CICD"], ["apps/svc/project.toml"], True),
    (["IMAGE_BUILD"], [""], [""], True),                       # RT 3: no task and no file: no positive evidence
    (["IMAGE_BUILD"], ["NO-SUCH-TASK"], [""], True),           # RT 3: unknown task id (attributes nothing)
    (["IMAGE_BUILD"], [""], ["apps/svc/Procfile"], True),      # unattributed, the developer's own file
    (["IMAGE_BUILD"], [""], ["apps/svc/main.py"], True),
    (["IMAGE_BUILD"], [""], ["./cloudbuild.yaml"], True),      # not an exact platform CI path
    (["IMAGE_BUILD"], [""], ["apps/svc/cloudbuild.yaml"], True),
    (["IMAGE_BUILD"], [""], [".github/workflows/../../apps/svc/main.py"], True),
    (["IMAGE_BUILD"], ["INFRA-05"], [""], False),              # no container compute in the commit: not handled
])
def test_otherwise_the_finding_still_blocks(monkeypatch, facets, task_ids, files, image_build):
    res, _ = _lens(monkeypatch, facets, task_ids, files, image_build=image_build)
    assert res.passed is False and res.missed_directives == [CLOUDBUILD_MSG]
    assert res.platform_satisfied_directives == []


@pytest.mark.parametrize("task_ids, files", [(["STEP-CICD"], [""]), ([""], ["cloudbuild.yaml"])])
def test_other_facets_keep_their_infrastructure_only_rules(monkeypatch, task_ids, files):
    """Do-No-Harm: the IMAGE_BUILD rules apply to IMAGE_BUILD only; a BUDGET_CAP label on a CI/CD task or on an
    unattributed CI file still blocks (ADHERENCE-PLATFORM-SATISFIED RT F3 / RT R1 unchanged)."""
    res, _ = _lens(monkeypatch, ["BUDGET_CAP"], task_ids, files, record={"budget_ceiling_monthly_usd": 10.0},
                   msg="no billing budget")
    assert res.passed is False and res.missed_directives == ["no billing budget"]


@pytest.mark.parametrize("task_ids, files, passed", [
    (["INFRA-05"], [""], True),
    (["CODE-CI"], [""], False),                  # CODE category: typed kinds are CI/CD only, never infrastructure
    ([""], [""], True),                          # RT 3 is IMAGE_BUILD only: no task and no file is still handled here
    (["INFRA-05"], ["apps/svc/Procfile"], True),   # RT 2 is IMAGE_BUILD only: a task-attributed file is not checked
])
def test_budget_cap_keeps_its_exact_old_rule(monkeypatch, task_ids, files, passed):
    res, _ = _lens(monkeypatch, ["BUDGET_CAP"], task_ids, files, record={"budget_ceiling_monthly_usd": 10.0},
                   msg="no billing budget")
    assert res.passed is passed
    if passed:
        assert res.platform_satisfied_directives[0].facet == "BUDGET_CAP"


def test_facet_rules_are_typed():
    from qa_auditor import adherence_lens as AL
    by_id = {t["task_id"]: t for t in DAG}
    assert AL.IMAGE_BUILD_TASK_CATEGORIES == frozenset({"CICD", "INFRA", "FOUNDATION_API", "DATABASE", "REGISTRY",
                                                        "IAM", "COMPUTE"})
    assert [tid for tid, t in by_id.items() if AL.image_build_task_applies(t)] == ["INFRA-05", "STEP-CICD",
                                                                                     "INFRA-IAC"]
    assert AL.image_build_task_applies(None) is False
    assert AL.image_build_handled(None, None) is False
    assert AL.image_build_handled(None, "cloudbuild.yaml") is True
    assert AL.image_build_handled(by_id["INFRA-05"], None) is True
    assert AL.image_build_handled(by_id["INFRA-05"], "apps/svc/Procfile") is False
    for facet in PS.FACETS:
        if facet != PS.FACET_IMAGE_BUILD:
            assert AL.facet_applies_to_task(facet, by_id["INFRA-05"]) is True     # INFRA category
            assert AL.facet_applies_to_task(facet, by_id["STEP-CICD"]) is False   # CICD category
            assert AL.satisfied_file_applies(facet, "cloudbuild.yaml") is False
            assert AL.satisfied_file_applies(facet, "infra/workload/main.tf") is True
