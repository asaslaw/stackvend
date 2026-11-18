"""PLAN-CONTRACT-CHECK (owner 11-17): the architect plan contract check and its bounded re-plan loop
(apps/orchestrator-gateway/architect_agent/plan_contract.py; plan docs/planning/plan-contract-check-plan.md §2-§5,
§8.1, §8.3 W1).

Pins: each code's positives and the RT 14 intended positives; every §2.2 negative (Do No Harm, prose never read); the
VCS clause and `not_checked`; the Diagnostic fields and the order; the brief text; the (code, symbol) progress
fingerprint; the room check; DAG regressions only when the re-plan introduced them; one test per inner re-plan
outcome; map-reduce / no model; exhaustion STRIP (exact entries, the draft only) and FAIL (typed body). Hermetic: no
model, no Firestore; the re-plan is a fake callable."""
import hermetic_guard  # noqa: F401  (first import)

import glob
import json
import os
import sys
from types import SimpleNamespace

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from architect_agent import plan_contract as pc  # noqa: E402
from architect_agent.schemas import (ArchitecturePlan, BuildPlanStep, SequencedBuildPlan,  # noqa: E402
                                     TaskItem)
from gate_errors import (GateUnavailableError, PlatformDefectError,  # noqa: E402
                         StageDeadlineExceededError)
import stage_deadline  # noqa: E402
from qa_auditor import judge_input  # noqa: E402

GITHUB, SERVERLESS_GIT = "GITHUB", "SERVERLESS_GIT"
VCS_ALL = (GITHUB, SERVERLESS_GIT, None)


# ------------------------------------------------------------------------------------------------- builders
def _task(tid, targets, category="CODE", depends_on=(), description="", criteria=()):
    return TaskItem(task_id=tid, title=f"title {tid}", category=category, target_files=list(targets),
                    description=description, acceptance_criteria=list(criteria), depends_on=list(depends_on))


def _step(sid, idx, category, targets, depends_on=()):
    return BuildPlanStep(step_id=sid, step_index=idx, category=category, title=f"step {sid}",
                         target_files=list(targets), description=f"describe {sid}",
                         acceptance_criteria=[f"criterion {sid}"], depends_on=list(depends_on))


def _plan(infra=(), code=(), steps=None):
    plan = ArchitecturePlan(product_id="shop", summary="s", architecture_overview="o",
                            infra_tasks=list(infra), code_tasks=list(code), target_compute_services=["api"],
                            compute_archetype="cloudrun", iac_engine="tofu")
    if steps is not None:
        plan.sequenced_build_plan = SequencedBuildPlan(plan_id="plan-1", steps=list(steps), total_steps=len(steps))
    return plan


def _steps(cicd_targets=None, compute_deps=("STEP-IAM", "STEP-APP-CODE")):
    out = [_step("STEP-APIS", 1, "FOUNDATION_API", ["infra/workload/main.tf"]),
           _step("STEP-IAM", 2, "IAM", ["infra/workload/main.tf"], ["STEP-APIS"]),
           _step("STEP-APP-CODE", 3, "APP_CODE", ["apps/api/main.py"], ["STEP-IAM"])]
    if cicd_targets is not None:
        out.append(_step("STEP-CICD", 4, "CICD", cicd_targets, ["STEP-APP-CODE"]))
    out.append(_step("STEP-COMPUTE", len(out) + 1, "COMPUTE", ["infra/workload/main.tf"], list(compute_deps)))
    return out


def _valid_plan():
    return _plan(infra=[_task("INFRA-01", ["infra/workload/main.tf", "infra/workload/variables.tf",
                                           "infra/workload/outputs.tf"], "INFRA")],
                 code=[_task("CODE-01", ["apps/api/main.py", "apps/api/.python-version", "apps/api/Procfile"]),
                       _task("CODE-02", [".github/workflows/deploy-api.yml"], depends_on=["CODE-01"])],
                 steps=_steps())


def _ex01_like_plan():
    """The ex01-g13 shape: INFRA-05 and the keyword STEP-CICD plan root `cloudbuild.yaml` beside the deploy workflow,
    and CODE-02 plans a Dockerfile."""
    return _plan(infra=[_task("INFRA-01", ["infra/workload/main.tf"], "INFRA"),
                        _task("INFRA-05", ["cloudbuild.yaml", ".github/workflows/deploy-api.yml"], "INFRA",
                              depends_on=["INFRA-01"],
                              description="Create cloudbuild.yaml and the GitHub Actions workflow; docker build.",
                              criteria=["cloudbuild.yaml exists", "no docker build in workflows"])],
                 code=[_task("CODE-01", ["apps/api/main.py"]),
                       _task("CODE-02", ["apps/api/requirements.txt", "apps/api/Dockerfile"],
                             depends_on=["CODE-01"])],
                 steps=_steps(cicd_targets=["cloudbuild.yaml"],
                              compute_deps=("STEP-IAM", "STEP-APP-CODE", "STEP-CICD")))


def _inner(plan):
    return SimpleNamespace(architecture_plan=plan)


class _Replan:
    """Fake replan_fn: answers from `answers` in order (a plan, a callable, or an exception to raise)."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, plan, violations):
        self.calls.append((plan, list(violations)))
        ans = self.answers.pop(0)
        if isinstance(ans, BaseException):
            raise ans
        return _inner(ans)


def _gate(plan, replan=None, *, vcs=GITHUB, map_reduce=False, model_build_plan=True):
    return pc.gate_plan_contract(plan, vcs_kind=vcs, replan_fn=replan, is_map_reduce=map_reduce, trace_id="t-1",
                                 product_id="shop", read_model_build_plan=lambda: model_build_plan)


@pytest.fixture(autouse=True)
def _no_stage_deadline(monkeypatch):
    """No stage deadline (unit tests): remaining_s() is None, checkpoints are no-ops; each test may override."""
    monkeypatch.setattr(stage_deadline, "remaining_s", lambda: None)
    monkeypatch.setattr(stage_deadline, "checkpoint", lambda label: None)
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", pc.EXHAUSTION_STRIP)


def _codes(plan, vcs=GITHUB):
    v, _ = pc.check_plan_contract(plan, vcs)
    return [(d.code, d.symbol, d.block_address) for d in v]


def _one_target(path):
    return _plan(code=[_task("CODE-01", [path])])


# ------------------------------------------------------------------------------------------------- constants
def test_constants_pinned():
    assert pc.MAX_PLAN_CONTRACT_REPLANS == 2                    # Q4
    assert pc.PLAN_CONTRACT_REPLAN_MIN_S == 360.0
    assert pc.EXHAUSTION_STRIP == "STRIP" and pc.EXHAUSTION_FAIL == "FAIL"
    assert pc.PLAN_FILE == "architect:plan"
    assert (pc.CODE_PLATFORM_CI_FILE, pc.CODE_CONTAINER_FILE, pc.CODE_DAG_INVALID) == (
        "PLAN.PLATFORM_CI_FILE", "PLAN.CONTAINER_FILE", "PLAN.DAG_INVALID")


def test_default_exhaustion_mode_is_strip():
    """Q5 default (the plan's recommendation): read from the module source, not the autouse-patched value."""
    import importlib.util
    spec = importlib.util.find_spec("architect_agent.plan_contract")
    src = open(spec.origin, encoding="utf-8").read()
    assert "\nPLAN_CONTRACT_ON_EXHAUSTION = EXHAUSTION_STRIP\n" in src


# ------------------------------------------------------------------------------------------------- the check: positives
def test_root_cloudbuild_on_github_is_a_ci_file_on_step_and_task():
    plan = _ex01_like_plan()
    got = _codes(plan)
    assert got == [
        ("PLAN.PLATFORM_CI_FILE", "cloudbuild.yaml", "infra_tasks[INFRA-05].target_files[0]"),
        ("PLAN.CONTAINER_FILE", "apps/api/Dockerfile", "code_tasks[CODE-02].target_files[1]"),
        ("PLAN.PLATFORM_CI_FILE", "cloudbuild.yaml", "sequenced_build_plan.steps[STEP-CICD].target_files[0]"),
    ]


@pytest.mark.parametrize("vcs", VCS_ALL)
@pytest.mark.parametrize("path", [".github/workflows/deploy-api.yaml", ".github/workflows/deploy.yml",
                                  ".github/workflows/ci.yml", ".github/workflows/build-and-push.yml"])
def test_rt14_intended_ci_positives(path, vcs):
    assert _codes(_one_target(path), vcs) == [("PLAN.PLATFORM_CI_FILE", path, "code_tasks[CODE-01].target_files[0]")]


@pytest.mark.parametrize("vcs", VCS_ALL)
@pytest.mark.parametrize("path", ["apps/api/Dockerfile", "Dockerfile", "apps/svc/Dockerfile.dev", ".dockerignore",
                                  "apps/svc/DOCKERFILE"])
def test_container_file_positives(path, vcs):
    assert _codes(_one_target(path), vcs) == [("PLAN.CONTAINER_FILE", path, "code_tasks[CODE-01].target_files[0]")]


def test_a_path_breaking_both_rules_gets_both_codes():
    path = ".github/workflows/Dockerfile"
    assert [c for c, _s, _b in _codes(_one_target(path))] == ["PLAN.PLATFORM_CI_FILE", "PLAN.CONTAINER_FILE"]


# ------------------------------------------------------------------------------------------------- the check: negatives
@pytest.mark.parametrize("vcs", VCS_ALL)
@pytest.mark.parametrize("path", [
    ".github/workflows/deploy-svc.yml",          # platform-written deploy workflow (prompt-mandated)
    "apps/svc/cloudbuild.yaml",                  # no table owns it; the developer keeps it
    "./cloudbuild.yaml",                         # `.` component: the exact rule refuses it; no normalising
    ".github/workflows/../x.yml",                # `..` component
    "dockerfile-notes.md",
    "apps/svc/Procfile",
    "infra/workload/main.tf", "infra/workload/variables.tf", "infra/workload/outputs.tf",
    "apps/svc/.python-version",
    "apps/svc/main.py", "README.md", "tests/test_main.py",
])
def test_must_pass_negatives(path, vcs):
    plan = _one_target(path)
    violations, _ = pc.check_plan_contract(plan, vcs)
    assert violations == []


def test_root_cloudbuild_passes_on_serverless_git():
    violations, not_checked = pc.check_plan_contract(_one_target("cloudbuild.yaml"), SERVERLESS_GIT)
    assert violations == [] and not_checked == []


@pytest.mark.parametrize("vcs", [None, "BITBUCKET", ""])
def test_root_cloudbuild_not_evaluated_with_unknown_vcs_and_recorded(vcs):
    """Q3: unknown VCS skips only the root `cloudbuild.yaml` clause and records it; every other clause still runs."""
    plan = _plan(code=[_task("CODE-01", ["cloudbuild.yaml", "apps/api/Dockerfile", ".github/workflows/ci.yml"])])
    violations, not_checked = pc.check_plan_contract(plan, vcs)
    assert [(d.code, d.symbol) for d in violations] == [("PLAN.CONTAINER_FILE", "apps/api/Dockerfile"),
                                                        ("PLAN.PLATFORM_CI_FILE", ".github/workflows/ci.yml")]
    assert not_checked == ["PLAN.PLATFORM_CI_FILE:cloudbuild.yaml (vcs unknown)"]


def test_known_vcs_records_nothing_not_checked():
    for vcs in (GITHUB, SERVERLESS_GIT):
        assert pc.check_plan_contract(_valid_plan(), vcs)[1] == []


def test_prose_is_never_read():
    """Invariant 2: a task whose description, criteria and title say docker build / cloudbuild.yaml / a privileged
    role passes (ex02-g13 shape: the role is prose only)."""
    prose = ("Create cloudbuild.yaml with a docker build step and a Dockerfile; grant "
             "roles/iam.serviceAccountTokenCreator for Cloud Scheduler OIDC; refuse roles/owner.")
    t = _task("INFRA-03", ["infra/workload/main.tf"], "INFRA", description=prose,
              criteria=["cloudbuild.yaml exists", "docker build succeeds", "roles/owner is never granted",
                        ".github/workflows/ci.yml runs"])
    t.title = "Dockerfile and cloudbuild.yaml"
    plan = _plan(infra=[t], steps=_steps())
    plan.sequenced_build_plan.steps[0].description = prose
    plan.risk_assessment = prose if hasattr(plan, "risk_assessment") else None
    for vcs in VCS_ALL:
        assert pc.check_plan_contract(plan, vcs)[0] == []


def test_non_string_targets_and_missing_build_plan_are_tolerated():
    plan = SimpleNamespace(infra_tasks=[SimpleNamespace(task_id="I-1", target_files=[None, 3, "apps/x/Dockerfile"])],
                           code_tasks=None, sequenced_build_plan=None)
    assert [(d.code, d.block_address) for d in pc.check_plan_contract(plan, GITHUB)[0]] == [
        ("PLAN.CONTAINER_FILE", "infra_tasks[I-1].target_files[2]")]


# ------------------------------------------------------------------------------------------------- diagnostics, order
def test_diagnostic_fields():
    v, _ = pc.check_plan_contract(_ex01_like_plan(), GITHUB)
    for d in v:
        assert d.tool == "platform" and d.severity == "error" and d.source == "architect"
        assert d.file == "architect:plan" and d.error_class.value == "ARCHITECT_DEFECT"
        assert d.message and d.hint
    ci = v[0]
    assert ci.message == ("StackVend builds every image with Buildpacks and writes the CI itself "
                          "(`.github/workflows/deploy-<service>.yml` on GitHub); a repository `cloudbuild.yaml` is "
                          "deleted.")
    # the root cloudbuild.yaml is a RENDER_SOURCES key: the hint names its typed render sources and their owners
    assert "Platform render sources of this path:" in ci.hint and "(PLATFORM)" in ci.hint
    dock = v[1]
    assert dock.message == "images are built with Buildpacks; every Dockerfile / .dockerignore is deleted."
    assert "Platform render sources" not in dock.hint


def test_order_is_deterministic_tasks_then_steps_then_index():
    plan = _plan(infra=[_task("INFRA-02", [".dockerignore", "x.py", "cloudbuild.yaml"], "INFRA")],
                 code=[_task("CODE-09", ["apps/a/Dockerfile"]), _task("CODE-01", [".github/workflows/ci.yml"])],
                 steps=[_step("STEP-B", 1, "CICD", ["cloudbuild.yaml"]), _step("STEP-A", 2, "APP_CODE",
                                                                                ["Dockerfile"])])
    first = _codes(plan)
    assert [b for _c, _s, b in first] == [
        "infra_tasks[INFRA-02].target_files[0]", "infra_tasks[INFRA-02].target_files[2]",
        "code_tasks[CODE-09].target_files[0]", "code_tasks[CODE-01].target_files[0]",
        "sequenced_build_plan.steps[STEP-B].target_files[0]", "sequenced_build_plan.steps[STEP-A].target_files[0]"]
    assert _codes(plan) == first


def test_check_is_read_only():
    plan = _ex01_like_plan()
    before = plan.model_dump_json()
    infra_lists = [id(t.target_files) for t in plan.infra_tasks]
    pc.check_plan_contract(plan, GITHUB)
    pc.check_plan_contract(plan, None)
    assert plan.model_dump_json() == before
    assert [id(t.target_files) for t in plan.infra_tasks] == infra_lists


def test_violation_key_is_code_and_exact_path():
    v, _ = pc.check_plan_contract(_ex01_like_plan(), GITHUB)
    assert [pc.violation_key(d) for d in v] == [("PLAN.PLATFORM_CI_FILE", "cloudbuild.yaml"),
                                                ("PLAN.CONTAINER_FILE", "apps/api/Dockerfile"),
                                                ("PLAN.PLATFORM_CI_FILE", "cloudbuild.yaml")]


# ------------------------------------------------------------------------------------------------- brief
def test_brief_text_pinned():
    plan = _plan(infra=[_task("INFRA-05", ["cloudbuild.yaml"], "INFRA")],
                 code=[_task("CODE-02", ["apps/api/main.py", "apps/api/Dockerfile"])])
    v, _ = pc.check_plan_contract(plan, GITHUB)
    assert pc.render_contract_brief(v) == (
        "--- PLATFORM PLAN CONTRACT (the platform refused the draft plan) ---\n"
        "Each line is one planned file the platform deletes before commit and never writes, so the task can never "
        "be met.\n"
        "For each line:\n"
        "- remove the file from the target_files of the task or step that names it;\n"
        "- in that same task or step, remove every instruction in its description and every acceptance criterion "
        "that asks for that file, because the platform provides what the file was for.\n"
        "If a task or step is then left with no target files and no other work, remove it and drop its id from "
        "every depends_on. Change nothing else.\n"
        "- PLAN.PLATFORM_CI_FILE infra_tasks[INFRA-05].target_files[0] `cloudbuild.yaml`: StackVend builds every "
        "image with Buildpacks and writes the CI itself (`.github/workflows/deploy-<service>.yml` on GitHub); a "
        "repository `cloudbuild.yaml` is deleted.\n"
        "- PLAN.CONTAINER_FILE code_tasks[CODE-02].target_files[1] `apps/api/Dockerfile`: images are built with "
        "Buildpacks; every Dockerfile / .dockerignore is deleted.\n"
        "--- END PLAN CONTRACT ---\n")


# ------------------------------------------------------------------------------------------------- gate: pass
def test_valid_plan_passes_as_the_same_object_with_no_call():
    plan = _valid_plan()
    before = plan.model_dump_json()
    replan = _Replan()
    res = _gate(plan, replan)
    assert res.plan is plan and res.outcome == "PASSED"
    assert plan.model_dump_json() == before
    assert replan.calls == []
    assert res.replanned_model_build_plan is None
    assert res.record["outcome"] == "PASSED" and res.record["violations"] == [] and res.record["turns"] == []
    assert res.record["stripped"] == [] and res.record["dag_preexisting"] is None
    assert pc.render_contract_note(res.record) == ""


def test_valid_plan_is_never_stripped_and_never_refused_in_either_mode(monkeypatch):
    for mode in ("STRIP", "FAIL"):
        monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", mode)
        plan = _valid_plan()
        before = plan.model_dump_json()
        res = _gate(plan, None, map_reduce=True)
        assert res.outcome == "PASSED" and res.plan is plan and plan.model_dump_json() == before


def test_fallback_draft_is_skipped_never_replanned():
    plan = _ex01_like_plan()
    plan._is_fallback = True
    replan = _Replan()
    res = _gate(plan, replan)
    assert res.outcome == "SKIPPED" and res.plan is plan and replan.calls == []


# ------------------------------------------------------------------------------------------------- gate: re-plan accepted
def test_clean_replan_is_accepted():
    draft = _ex01_like_plan()
    fixed = _valid_plan()
    replan = _Replan(fixed)
    res = _gate(draft, replan, model_build_plan=False)
    assert res.outcome == "REPLANNED" and res.plan is fixed
    assert res.replanned_model_build_plan is False
    assert len(replan.calls) == 1 and replan.calls[0][0] is draft
    assert [pc.violation_key(d) for d in replan.calls[0][1]] == [
        ("PLAN.PLATFORM_CI_FILE", "cloudbuild.yaml"), ("PLAN.CONTAINER_FILE", "apps/api/Dockerfile"),
        ("PLAN.PLATFORM_CI_FILE", "cloudbuild.yaml")]
    rec = res.record
    assert rec["outcome"] == "REPLANNED" and rec["stopped"] is None and rec["stripped"] == []
    assert len(rec["violations"]) == 3 and rec["turns"][0]["result"] == "ACCEPTED"
    assert rec["turns"][0]["after"] == [] and rec["exhaustion_mode"] == "STRIP"
    note = pc.render_contract_note(rec)
    assert note.startswith("## Platform plan contract\n") and "`apps/api/Dockerfile`" in note
    assert "not re-audited by the critic" in note


def test_model_build_plan_is_read_after_the_accepted_call():
    flags = iter([None])
    seen = []

    def read():
        seen.append(len(replan.calls))
        return next(flags)

    replan = _Replan(_valid_plan())
    res = pc.gate_plan_contract(_ex01_like_plan(), vcs_kind=GITHUB, replan_fn=replan, is_map_reduce=False,
                                trace_id="t", product_id="p", read_model_build_plan=read)
    assert seen == [1] and res.replanned_model_build_plan is None


# ------------------------------------------------------------------------------------------------- fingerprint
def test_same_path_at_new_index_is_no_progress():
    draft = _plan(code=[_task("CODE-02", ["apps/api/Dockerfile"])])
    moved = _plan(code=[_task("CODE-02", ["apps/api/main.py", "apps/api/Dockerfile"])])
    replan = _Replan(moved)
    res = _gate(draft, replan)
    assert len(replan.calls) == 1 and res.record["stopped"] == "NO_PROGRESS"
    assert res.outcome == "STRIPPED" and res.plan is draft


def test_same_path_under_renamed_task_is_no_progress():
    draft = _plan(infra=[_task("INFRA-05", ["cloudbuild.yaml"], "INFRA")])
    renamed = _plan(infra=[_task("INFRA-06", ["cloudbuild.yaml"], "INFRA")])
    replan = _Replan(renamed)
    res = _gate(draft, replan)
    assert len(replan.calls) == 1 and res.record["stopped"] == "NO_PROGRESS"


def test_all_told_fixed_and_new_ones_earns_turn_two_on_the_replan():
    draft = _plan(code=[_task("CODE-02", ["apps/api/Dockerfile"])])
    turn1 = _plan(code=[_task("CODE-02", [".github/workflows/ci.yml"])])
    turn2 = _plan(code=[_task("CODE-02", ["apps/api/main.py"])])
    replan = _Replan(turn1, turn2)
    res = _gate(draft, replan)
    assert res.outcome == "REPLANNED" and res.plan is turn2
    assert len(replan.calls) == 2
    assert replan.calls[1][0] is turn1
    assert [pc.violation_key(d) for d in replan.calls[1][1]] == [("PLAN.PLATFORM_CI_FILE", ".github/workflows/ci.yml")]
    assert [t["result"] for t in res.record["turns"]] == ["VIOLATING", "ACCEPTED"]
    assert res.record["turns"][1]["told"] == [{"code": "PLAN.PLATFORM_CI_FILE", "symbol": ".github/workflows/ci.yml"}]


def test_turn_two_still_violating_is_max_turns_and_strips_the_draft():
    draft = _plan(code=[_task("CODE-02", ["apps/api/main.py", "apps/api/Dockerfile"])])
    turn1 = _plan(code=[_task("CODE-02", [".github/workflows/ci.yml"])])
    turn2 = _plan(code=[_task("CODE-02", [".dockerignore"])])
    replan = _Replan(turn1, turn2)
    res = _gate(draft, replan)
    assert len(replan.calls) == 2 and res.record["stopped"] == "MAX_TURNS"
    assert res.plan is draft and res.outcome == "STRIPPED"
    assert draft.code_tasks[0].target_files == ["apps/api/main.py"]   # the draft's entries, not the re-plan's


def test_partial_progress_is_no_progress():
    draft = _plan(code=[_task("CODE-02", ["apps/api/Dockerfile", ".github/workflows/ci.yml"])])
    partial = _plan(code=[_task("CODE-02", [".github/workflows/ci.yml", ".dockerignore"])])
    replan = _Replan(partial)
    res = _gate(draft, replan)
    assert len(replan.calls) == 1 and res.record["stopped"] == "NO_PROGRESS"


# ------------------------------------------------------------------------------------------------- room check
def test_room_check_below_minimum_stops_without_a_call(monkeypatch):
    monkeypatch.setattr(stage_deadline, "remaining_s", lambda: pc.PLAN_CONTRACT_REPLAN_MIN_S - 1)
    replan = _Replan(_valid_plan())
    res = _gate(_ex01_like_plan(), replan)
    assert replan.calls == [] and res.record["stopped"] == "NO_STAGE_BUDGET" and res.outcome == "STRIPPED"
    assert res.record["stage_budget_left_s"] == pc.PLAN_CONTRACT_REPLAN_MIN_S - 1


def test_room_check_at_minimum_or_none_is_allowed(monkeypatch):
    for left in (None, pc.PLAN_CONTRACT_REPLAN_MIN_S, 1800.0):
        monkeypatch.setattr(stage_deadline, "remaining_s", lambda left=left: left)
        replan = _Replan(_valid_plan())
        assert _gate(_ex01_like_plan(), replan).outcome == "REPLANNED" and len(replan.calls) == 1


def test_room_check_runs_before_turn_two(monkeypatch):
    lefts = iter([1000.0, 10.0])
    monkeypatch.setattr(stage_deadline, "remaining_s", lambda: next(lefts))
    draft = _plan(code=[_task("CODE-02", ["apps/api/Dockerfile"])])
    replan = _Replan(_plan(code=[_task("CODE-02", [".github/workflows/ci.yml"])]), _valid_plan())
    res = _gate(draft, replan)
    assert len(replan.calls) == 1 and res.record["stopped"] == "NO_STAGE_BUDGET" and res.plan is draft


def test_checkpoint_before_each_turn_and_stop_propagates_with_record(monkeypatch):
    labels = []
    monkeypatch.setattr(stage_deadline, "checkpoint", lambda label: labels.append(label))
    draft = _plan(code=[_task("CODE-02", ["apps/api/Dockerfile"])])
    _gate(draft, _Replan(_plan(code=[_task("CODE-02", [".github/workflows/ci.yml"])]), _valid_plan()))
    assert labels == ["architect.plan_contract", "architect.plan_contract"]

    def stop(label):
        raise StageDeadlineExceededError("architect stage deadline", stage="architect")
    monkeypatch.setattr(stage_deadline, "checkpoint", stop)
    replan = _Replan(_valid_plan())
    with pytest.raises(StageDeadlineExceededError) as ei:
        _gate(_ex01_like_plan(), replan)
    assert replan.calls == []
    assert ei.value.plan_contract_record["outcome"] == "INTERRUPTED"


# ------------------------------------------------------------------------------------------------- DAG regression
def _dag(cycle=False, orphans=0, ordering=0):
    return SimpleNamespace(cycle_detected=cycle, orphan_dependencies=[f"orphan {i}" for i in range(orphans)],
                           ordering_violations=[f"order {i}" for i in range(ordering)],
                           errors=[f"e {i}" for i in range(orphans + ordering + int(cycle))])


def test_dag_regression_by_counts():
    assert pc.dag_regression(_dag(), _dag()) == []
    assert pc.dag_regression(_dag(cycle=True, orphans=2, ordering=3), _dag(cycle=True, orphans=2, ordering=3)) == []
    assert pc.dag_regression(_dag(orphans=2, ordering=3), _dag(orphans=1, ordering=0)) == []   # fewer is fine
    new_cycle = pc.dag_regression(_dag(), _dag(cycle=True))
    assert [(d.code, d.symbol) for d in new_cycle] == [("PLAN.DAG_INVALID", "cycle")]
    more = pc.dag_regression(_dag(orphans=1, ordering=1), _dag(orphans=2, ordering=2))
    assert [d.symbol for d in more] == ["orphan_dependencies", "ordering_violations"]
    for d in new_cycle + more:
        assert d.tool == "platform" and d.severity == "error" and d.source == "architect"
        assert d.file == "architect:plan" and d.error_class.value == "ARCHITECT_DEFECT"
    assert "orphan 0\norphan 1" == more[0].detail


def test_replan_introducing_a_cycle_is_refused_and_strips_the_draft():
    draft = _plan(code=[_task("CODE-01", ["apps/api/main.py"]),
                        _task("CODE-02", ["apps/api/Dockerfile"], depends_on=["CODE-01"])])
    cyc = _plan(code=[_task("CODE-01", ["apps/api/main.py"], depends_on=["CODE-02"]),
                      _task("CODE-02", ["apps/api/requirements.txt"], depends_on=["CODE-01"])])
    res = _gate(draft, _Replan(cyc))
    assert res.record["stopped"] == "REPLAN_DAG_INVALID" and res.plan is draft and res.outcome == "STRIPPED"
    assert res.record["turns"][0]["result"] == "DAG_REGRESSION"
    assert [d["code"] for d in res.record["turns"][0]["dag_regression"]] == ["PLAN.DAG_INVALID"]


@pytest.mark.parametrize("kind", ["orphan", "ordering"])
def test_replan_adding_orphans_or_ordering_violations_is_refused(kind):
    draft = _plan(code=[_task("CODE-02", ["apps/api/Dockerfile"])], steps=_steps())
    if kind == "orphan":
        bad = _plan(code=[_task("CODE-02", ["apps/api/main.py"], depends_on=["CODE-99"])], steps=_steps())
    else:
        bad = _plan(code=[_task("CODE-02", ["apps/api/main.py"])], steps=_steps())
        bad.sequenced_build_plan.steps[1].depends_on = ["STEP-COMPUTE"]   # IAM depends on a later stage
    res = _gate(draft, _Replan(bad))
    assert res.record["stopped"] == "REPLAN_DAG_INVALID"


def test_preexisting_ordering_inversion_with_dockerfile_faithful_replan_is_accepted():
    """RT 3: the draft already has a stage-ordering inversion (34 of 915 recorded plans); a re-plan that only drops
    the Dockerfile keeps it and is accepted; the baseline is recorded, never refused."""
    def build(code_targets):
        steps = _steps()
        steps[2].depends_on = ["STEP-APIS"]
        steps[1].depends_on = ["STEP-APP-CODE"]   # IAM (prio 3) depends on APP_CODE (prio 4): inverted, no cycle
        return _plan(code=[_task("CODE-01", code_targets)], steps=steps)
    draft = build(["apps/api/main.py", "apps/api/Dockerfile"])
    faithful = build(["apps/api/main.py"])
    res = _gate(draft, _Replan(faithful))
    assert res.outcome == "REPLANNED" and res.plan is faithful
    pre = res.record["dag_preexisting"]
    assert pre["ordering_violations"] == 1 and pre["count"] == 1 and pre["cycle_detected"] is False
    assert pre["errors"][0].startswith("Stage ordering inverted")


# ------------------------------------------------------------------------------------------------- inner outcomes
def test_replan_returning_fallback_is_unusable():
    fb = _valid_plan()
    fb._is_fallback = True
    res = _gate(_ex01_like_plan(), _Replan(fb))
    assert res.record["stopped"] == "REPLAN_UNUSABLE" and res.outcome == "STRIPPED"
    assert res.record["turns"][0]["result"] == "UNUSABLE"


def test_replan_returning_no_architecture_plan_is_unusable():
    class _R:
        calls = 0

        def __call__(self, plan, v):
            _R.calls += 1
            return SimpleNamespace()
    res = _gate(_ex01_like_plan(), _R())
    assert res.record["stopped"] == "REPLAN_UNUSABLE"


def test_replan_no_model_response_is_an_outage_never_architect_defect(monkeypatch):
    """FAIL mode: an outage of the re-plan surfaces as GATE_UNAVAILABLE (under STRIP it is a failed turn, below)."""
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")
    nm = _valid_plan()
    nm._is_fallback = True
    nm._no_model_response = True
    draft = _ex01_like_plan()
    before = draft.model_dump_json()
    with pytest.raises(GateUnavailableError) as ei:
        _gate(draft, _Replan(nm))
    err = ei.value
    assert type(err) is GateUnavailableError and err.reason == "ARCHITECT_NO_MODEL_RESPONSE"
    assert err.to_body()["error_class"] == "GATE_UNAVAILABLE" and err.http_status == 503
    assert err.details == {"trace_id": "t-1", "product_id": "shop"}
    rec = err.plan_contract_record
    assert rec["outcome"] == "INTERRUPTED" and rec["turns"][0]["result"] == "NO_MODEL_RESPONSE"
    assert draft.model_dump_json() == before   # never stripped on an outage


def test_typed_gate_error_propagates_unchanged_with_record(monkeypatch):
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")

    class ArchitectRateLimited(GateUnavailableError):
        pass
    boom = ArchitectRateLimited("rate limited", reason="ARCHITECT_RATE_LIMITED")
    draft = _ex01_like_plan()
    before = draft.model_dump_json()
    with pytest.raises(ArchitectRateLimited) as ei:
        _gate(draft, _Replan(boom))
    assert ei.value is boom
    rec = boom.plan_contract_record
    assert rec["outcome"] == "INTERRUPTED" and rec["interrupted_by"]["reason"] == "ARCHITECT_RATE_LIMITED"
    assert rec["turns"][0]["result"] == "RAISED" and len(rec["violations"]) == 3
    assert draft.model_dump_json() == before


class _RateLimited(GateUnavailableError):
    """Stands in for architect_agent.handler.ArchitectRateLimitedError (a GateUnavailableError subclass)."""


def _no_model_plan():
    nm = _valid_plan()
    nm._is_fallback = True
    nm._no_model_response = True
    return nm


def test_rate_limited_replan_under_strip_is_a_failed_turn_and_strips_the_draft():
    """Orchestrator decision on code review finding 3: under STRIP an outage of the re-plan never fails a run whose
    audited draft was usable; the turn records the typed class and reason, the loop stops, exhaustion strips."""
    boom = _RateLimited("rate limited", reason="ARCHITECT_RATE_LIMITED")
    draft = _ex01_like_plan()
    replan = _Replan(boom, _valid_plan())
    res = _gate(draft, replan)
    assert res.outcome == "STRIPPED" and res.plan is draft
    assert res.record["stopped"] == "REPLAN_MODEL_UNAVAILABLE" and len(replan.calls) == 1   # the loop stopped
    turn = res.record["turns"][0]
    assert turn["result"] == "MODEL_UNAVAILABLE"
    assert turn["unavailable"] == {"type": "_RateLimited", "error_class": "GATE_UNAVAILABLE",
                                   "reason": "ARCHITECT_RATE_LIMITED"}
    assert turn["error"].startswith("ARCHITECT_RATE_LIMITED: ")
    assert "interrupted_by" not in res.record and not hasattr(boom, "plan_contract_record")
    assert ("PLAN.CONTAINER_FILE", "apps/api/Dockerfile") not in [(c, p) for c, p, _ in _codes(draft)]
    json.dumps(res.record)
    _no_nested_arrays(res.record)


def test_no_model_response_replan_under_strip_is_a_failed_turn_and_strips_the_draft():
    draft = _ex01_like_plan()
    res = _gate(draft, _Replan(_no_model_plan()))
    assert res.outcome == "STRIPPED" and res.plan is draft
    assert res.record["stopped"] == "REPLAN_MODEL_UNAVAILABLE"
    turn = res.record["turns"][0]
    assert turn["result"] == "MODEL_UNAVAILABLE"
    assert turn["unavailable"] == {"type": "GateUnavailableError", "error_class": "GATE_UNAVAILABLE",
                                   "reason": "ARCHITECT_NO_MODEL_RESPONSE"}


def test_plain_gate_unavailable_from_the_replan_under_strip_is_a_failed_turn():
    res = _gate(_ex01_like_plan(), _Replan(GateUnavailableError("config missing", reason="SOME_TOOL_MISSING")))
    assert res.outcome == "STRIPPED" and res.record["stopped"] == "REPLAN_MODEL_UNAVAILABLE"
    assert res.record["turns"][0]["unavailable"]["reason"] == "SOME_TOOL_MISSING"


def test_outage_in_turn_two_under_strip_still_strips_the_draft():
    draft = _plan(code=[_task("CODE-02", ["apps/api/Dockerfile"])])
    turn1 = _plan(code=[_task("CODE-02", [".github/workflows/ci.yml"])])
    res = _gate(draft, _Replan(turn1, _RateLimited("rate limited", reason="ARCHITECT_RATE_LIMITED")))
    assert res.outcome == "STRIPPED" and res.plan is draft
    assert [t["result"] for t in res.record["turns"]] == ["VIOLATING", "MODEL_UNAVAILABLE"]
    assert res.record["stopped"] == "REPLAN_MODEL_UNAVAILABLE"


@pytest.mark.parametrize("err", [PlatformDefectError("defect", reason="X_DEFECT"),
                                 pc.PlanContractViolationError("nested", reason="Y")])
def test_non_outage_gate_errors_from_the_replan_still_propagate_under_strip(err):
    """Only GATE_UNAVAILABLE-class errors become a failed turn; every other typed GateError propagates unchanged."""
    with pytest.raises(type(err)) as ei:
        _gate(_ex01_like_plan(), _Replan(err))
    assert ei.value is err and err.plan_contract_record["turns"][0]["result"] == "RAISED"
    assert err.plan_contract_record["outcome"] == "INTERRUPTED"


def test_stop_errors_from_the_replan_propagate_under_strip_and_fail(monkeypatch):
    """STOP errors are never an outage turn, in either mode (tests/test_rt14_architect_stop_errors.py)."""
    for mode in ("STRIP", "FAIL"):
        monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", mode)
        for cls in stage_deadline.STOP_ERRORS:
            try:
                stop = cls("stopped")
            except TypeError:
                stop = cls.__new__(cls)
            with pytest.raises(cls) as ei:
                _gate(_ex01_like_plan(), _Replan(stop))
            assert ei.value is stop


def test_outage_outside_the_replan_turn_is_never_swallowed(monkeypatch):
    """The outage mapping covers the re-plan call only: a GATE_UNAVAILABLE error raised by the check itself (outside
    the turn) is not a failed turn (it is a GateError, so it propagates unchanged)."""
    boom = GateUnavailableError("judge input unavailable", reason="OUTSIDE_THE_TURN")

    def raise_boom(*_a, **_k):
        raise boom
    monkeypatch.setattr(pc, "_validate_dag", raise_boom)
    with pytest.raises(GateUnavailableError) as ei:
        _gate(_ex01_like_plan(), _Replan(_valid_plan()))
    assert ei.value is boom


def test_stop_errors_from_the_replan_propagate():
    for stop in (StageDeadlineExceededError("deadline", stage="architect"),):
        with pytest.raises(type(stop)) as ei:
            _gate(_ex01_like_plan(), _Replan(stop))
        assert ei.value is stop and stop.plan_contract_record["outcome"] == "INTERRUPTED"
    assert all(issubclass(c, BaseException) for c in stage_deadline.STOP_ERRORS)


def test_every_stop_error_class_propagates(monkeypatch):
    for cls in stage_deadline.STOP_ERRORS:
        try:
            stop = cls("stopped")
        except TypeError:   # a stop class with another constructor: build it without __init__
            stop = cls.__new__(cls)
        with pytest.raises(cls):
            _gate(_ex01_like_plan(), _Replan(stop))


def test_other_exception_is_a_failed_turn():
    res = _gate(_ex01_like_plan(), _Replan(RuntimeError("json parse blew up")))
    assert res.record["stopped"] == "REPLAN_FAILED" and res.outcome == "STRIPPED"
    assert res.record["turns"][0]["result"] == "FAILED"
    assert "RuntimeError: json parse blew up" in res.record["turns"][0]["error"]


def test_map_reduce_and_no_model_make_no_call():
    replan = _Replan(_valid_plan())
    res = _gate(_ex01_like_plan(), replan, map_reduce=True)
    assert replan.calls == [] and res.record["stopped"] == "MAP_REDUCE" and res.record["turns"] == []
    res2 = _gate(_ex01_like_plan(), None)
    assert res2.record["stopped"] == "NO_MODEL" and res2.outcome == "STRIPPED"


# ------------------------------------------------------------------------------------------------- exhaustion STRIP
def test_strip_removes_only_the_flagged_entries():
    draft = _ex01_like_plan()
    infra5 = draft.infra_tasks[1]
    desc, crit, deps = infra5.description, list(infra5.acceptance_criteria), list(infra5.depends_on)
    task_ids = [t.task_id for t in draft.infra_tasks + draft.code_tasks]
    step_ids = [s.step_id for s in draft.sequenced_build_plan.steps]
    compute_deps = list(draft.sequenced_build_plan.steps[-1].depends_on)
    res = _gate(draft, None)
    assert res.outcome == "STRIPPED" and res.plan is draft
    assert infra5.target_files == [".github/workflows/deploy-api.yml"]
    assert draft.code_tasks[1].target_files == ["apps/api/requirements.txt"]
    cicd = draft.sequenced_build_plan.steps[3]
    assert cicd.step_id == "STEP-CICD" and cicd.target_files == []          # an emptied step stays
    assert (infra5.description, infra5.acceptance_criteria, infra5.depends_on) == (desc, crit, deps)
    assert [t.task_id for t in draft.infra_tasks + draft.code_tasks] == task_ids
    assert [s.step_id for s in draft.sequenced_build_plan.steps] == step_ids
    assert draft.sequenced_build_plan.steps[-1].depends_on == compute_deps
    assert pc.check_plan_contract(draft, GITHUB)[0] == []                   # post-strip re-check is clean
    rec = res.record
    assert rec["stripped"] == [
        {"kind": "infra_task", "id": "INFRA-05", "removed": [
            {"index": 0, "path": "cloudbuild.yaml", "code": "PLAN.PLATFORM_CI_FILE",
             "message": rec["violations"][0]["message"]}]},
        {"kind": "code_task", "id": "CODE-02", "removed": [
            {"index": 1, "path": "apps/api/Dockerfile", "code": "PLAN.CONTAINER_FILE",
             "message": "images are built with Buildpacks; every Dockerfile / .dockerignore is deleted."}]},
        {"kind": "build_step", "id": "STEP-CICD", "removed": [
            {"index": 0, "path": "cloudbuild.yaml", "code": "PLAN.PLATFORM_CI_FILE",
             "message": rec["violations"][2]["message"]}]},
    ]
    assert rec["outcome"] == "STRIPPED" and rec["stopped"] == "NO_MODEL"
    note = pc.render_contract_note(rec)
    assert note.startswith("## Platform plan contract\n")
    assert "- Task `INFRA-05`: removed `cloudbuild.yaml` (PLAN.PLATFORM_CI_FILE:" in note
    assert "- Build step `STEP-CICD`: removed `cloudbuild.yaml`" in note
    assert "- Task `CODE-02`: removed `apps/api/Dockerfile`" in note
    assert "stopped: NO_MODEL" in note


def test_strip_with_no_violations_touches_nothing():
    plan = _ex01_like_plan()
    before = plan.model_dump_json()
    ids = [id(t.target_files) for t in plan.infra_tasks + plan.code_tasks]
    assert pc.strip_violations(plan, []) == []
    assert plan.model_dump_json() == before
    assert [id(t.target_files) for t in plan.infra_tasks + plan.code_tasks] == ids


def test_strip_removes_a_double_coded_entry_once():
    # the deploy workflow keeps the task's CI/CD judge fact, so the double-coded entry is removed (finding 1 rule)
    plan = _one_target(".github/workflows/Dockerfile")
    plan.code_tasks[0].target_files += ["apps/api/main.py", ".github/workflows/deploy-api.yml"]
    res = _gate(plan, None)
    assert plan.code_tasks[0].target_files == ["apps/api/main.py", ".github/workflows/deploy-api.yml"]
    assert [r["code"] for r in res.record["stripped"][0]["removed"]] == ["PLAN.PLATFORM_CI_FILE",
                                                                          "PLAN.CONTAINER_FILE"]
    assert "kept" not in res.record["stripped"][0]


# ------------------------------------------------------------------------------------------------- strip: judge facts
def _kinds(task):
    return judge_input.task_fact_kinds(task.model_dump(mode="json"))


def test_strip_keeps_a_ci_entry_the_judge_task_facts_rest_on():
    """Code review finding 1: a RELEASE task whose only CI/CD judge signal is `cloudbuild.yaml` keeps it (recorded),
    and its Dockerfile is still removed; the build step's entry is always removed (steps are not judged)."""
    plan = _plan(code=[_task("CODE-01", ["apps/api/main.py"]),
                       _task("CODE-02", ["cloudbuild.yaml", "apps/api/Dockerfile"], "RELEASE",
                             description="Create cloudbuild.yaml that builds the image.")],
                 steps=_steps(cicd_targets=["cloudbuild.yaml"]))
    code02 = plan.code_tasks[1]
    assert _kinds(code02) == ["CI/CD"]
    res = _gate(plan, None)
    assert res.outcome == "STRIPPED"
    assert code02.target_files == ["cloudbuild.yaml"]
    assert _kinds(code02) == ["CI/CD"]
    assert plan.sequenced_build_plan.steps[3].target_files == []
    assert res.record["stripped"] == [
        {"kind": "code_task", "id": "CODE-02",
         "removed": [{"index": 1, "path": "apps/api/Dockerfile", "code": "PLAN.CONTAINER_FILE",
                      "message": "images are built with Buildpacks; every Dockerfile / .dockerignore is deleted."}],
         "kept": [{"index": 0, "path": "cloudbuild.yaml", "code": "PLAN.PLATFORM_CI_FILE",
                   "reason": "JUDGE_TASK_FACTS"}]},
        {"kind": "build_step", "id": "STEP-CICD",
         "removed": [{"index": 0, "path": "cloudbuild.yaml", "code": "PLAN.PLATFORM_CI_FILE",
                      "message": res.record["violations"][2]["message"]}]},
    ]
    note = pc.render_contract_note(res.record)
    assert "- Task `CODE-02`: removed `apps/api/Dockerfile`" in note
    assert "kept in the target files" in note and "`cloudbuild.yaml` (PLAN.PLATFORM_CI_FILE)" in note
    # what is left is exactly the kept entry (never a refusal)
    assert [(d.symbol, d.block_address) for d in pc.check_plan_contract(plan, GITHUB)[0]] == [
        ("cloudbuild.yaml", "code_tasks[CODE-02].target_files[0]")]


def test_strip_keeps_a_double_coded_entry_alone_in_a_task():
    plan = _one_target(".github/workflows/Dockerfile")
    plan.code_tasks[0].target_files.append("apps/api/main.py")
    res = _gate(plan, None)
    assert res.outcome == "STRIPPED"
    assert plan.code_tasks[0].target_files == [".github/workflows/Dockerfile", "apps/api/main.py"]
    rec = res.record["stripped"][0]
    assert rec["removed"] == [] and [k["code"] for k in rec["kept"]] == ["PLAN.PLATFORM_CI_FILE",
                                                                         "PLAN.CONTAINER_FILE"]


def test_strip_keeps_only_entries_that_give_a_fact_kind():
    """Two CI files in one RELEASE task: removing both would drop the CI/CD fact, each on its own gives it, so both
    are kept; an INFRA task's CI file is kept too when it is the task's only CI signal (its category gives only the
    infrastructure fact)."""
    plan = _plan(infra=[_task("INFRA-01", ["infra/workload/main.tf", "cloudbuild.yaml"], "INFRA")],
                 code=[_task("CODE-02", ["cloudbuild.yaml", ".github/workflows/build.yml"], "RELEASE")])
    before = [_kinds(t) for t in plan.infra_tasks + plan.code_tasks]
    res = _gate(plan, None)
    assert plan.infra_tasks[0].target_files == ["infra/workload/main.tf", "cloudbuild.yaml"]
    assert plan.code_tasks[0].target_files == ["cloudbuild.yaml", ".github/workflows/build.yml"]
    assert [_kinds(t) for t in plan.infra_tasks + plan.code_tasks] == before
    assert res.outcome == "STRIPPED"


def test_strip_negative_valid_plan_is_never_touched_by_the_judge_rule():
    plan = _valid_plan()
    before = plan.model_dump_json()
    assert pc.strip_violations(plan, pc.check_plan_contract(plan, GITHUB)[0]) == []
    assert plan.model_dump_json() == before


def test_strip_leaves_untouched_items_list_objects_unchanged():
    plan = _ex01_like_plan()
    untouched = plan.code_tasks[0]
    ident = id(untouched.target_files)
    _gate(plan, None)
    assert id(untouched.target_files) == ident


def test_strip_left_violation_is_refused_never_passed(monkeypatch):
    real = pc._strip
    monkeypatch.setattr(pc, "_strip", lambda plan, v: real(plan, v[:1]))
    with pytest.raises(pc.PlanContractViolationError) as ei:
        _gate(_ex01_like_plan(), None)
    assert ei.value.plan_contract_record["outcome"] == "REFUSED"
    assert "the platform strip left a violation" in ei.value.message


# ------------------------------------------------------------------------------------------------- exhaustion FAIL
def test_fail_mode_error_body_shape(monkeypatch):
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")
    draft = _ex01_like_plan()
    before = draft.model_dump_json()
    replan = _Replan(_plan(code=[_task("CODE-02", ["apps/api/Dockerfile"])]))
    with pytest.raises(pc.PlanContractViolationError) as ei:
        _gate(draft, replan, vcs=GITHUB)
    err = ei.value
    assert draft.model_dump_json() == before   # FAIL never strips
    assert err.http_status == 422 and err.error_class.value == "ARCHITECT_DEFECT"
    assert err.reason == "ARCHITECT_PLAN_CONTRACT_VIOLATION" and err.stage == "architect"
    assert err.message == ("architect plan violates the platform contract after 1 re-plan turn(s): "
                           "PLAN.PLATFORM_CI_FILE cloudbuild.yaml; PLAN.CONTAINER_FILE apps/api/Dockerfile; "
                           "PLAN.PLATFORM_CI_FILE cloudbuild.yaml")
    assert [d["code"] for d in err.diagnostics] == ["PLAN.PLATFORM_CI_FILE", "PLAN.CONTAINER_FILE",
                                                    "PLAN.PLATFORM_CI_FILE"]
    assert set(err.details) == {"trace_id", "product_id", "vcs_kind", "not_checked", "turns", "stopped"}
    assert err.details["stopped"] == "NO_PROGRESS" and err.details["vcs_kind"] == "GITHUB"
    assert err.details["turns"][0]["turn"] == 1 and err.details["not_checked"] == []
    body = err.to_body()
    assert body["status"] == "FAILED" and body["error_class"] == "ARCHITECT_DEFECT"
    assert body["reason"] == "ARCHITECT_PLAN_CONTRACT_VIOLATION" and body["stage"] == "architect"
    rec = err.plan_contract_record
    assert rec["outcome"] == "REFUSED" and rec["exhaustion_mode"] == "FAIL" and rec["stripped"] == []
    json.dumps(body)


def test_fail_mode_carries_the_last_dag_regression(monkeypatch):
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")
    draft = _plan(code=[_task("CODE-02", ["apps/api/Dockerfile"])])
    bad = _plan(code=[_task("CODE-02", ["apps/api/main.py"], depends_on=["NOPE"])])
    with pytest.raises(pc.PlanContractViolationError) as ei:
        _gate(draft, _Replan(bad))
    assert [d["code"] for d in ei.value.diagnostics] == ["PLAN.CONTAINER_FILE", "PLAN.DAG_INVALID"]
    assert ei.value.details["stopped"] == "REPLAN_DAG_INVALID"


@pytest.mark.parametrize("stop", ["NO_MODEL", "MAP_REDUCE"])
def test_fail_mode_every_exhaustion_reason_refuses(monkeypatch, stop):
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")
    with pytest.raises(pc.PlanContractViolationError) as ei:
        _gate(_ex01_like_plan(), None, map_reduce=stop == "MAP_REDUCE")
    assert ei.value.details["stopped"] == stop and ei.value.message.startswith(
        "architect plan violates the platform contract after 0 re-plan turn(s): ")


def test_invalid_exhaustion_mode_is_a_platform_defect_only_on_a_violating_plan(monkeypatch):
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "MAYBE")
    assert _gate(_valid_plan(), None).outcome == "PASSED"
    with pytest.raises(PlatformDefectError):
        _gate(_ex01_like_plan(), None)


# ------------------------------------------------------------------------------------------------- record shape
def _no_nested_arrays(x, in_list=False):
    if isinstance(x, (list, tuple)):
        assert not in_list, "Firestore rejects an array directly inside an array"
        for v in x:
            _no_nested_arrays(v, True)
    elif isinstance(x, dict):
        for v in x.values():
            _no_nested_arrays(v, False)


def test_records_are_json_and_firestore_safe(monkeypatch):
    draft = _plan(code=[_task("CODE-02", ["apps/api/Dockerfile"])])
    turn1 = _plan(code=[_task("CODE-02", [".github/workflows/ci.yml"])])
    bad = _plan(code=[_task("CODE-02", ["apps/api/main.py"], depends_on=["NOPE"])])
    for res in (_gate(_valid_plan()), _gate(_ex01_like_plan(), _Replan(_valid_plan())),
                _gate(draft, _Replan(turn1, bad)), _gate(_ex01_like_plan(), None, vcs=None)):
        json.dumps(res.record)
        _no_nested_arrays(res.record)
        assert set(res.record) >= {"outcome", "vcs_kind", "not_checked", "violations", "turns", "stopped",
                                   "stripped", "dag_preexisting", "exhaustion_mode"}


# ------------------------------------------------------------------------------------------------- scenario corpus
def test_scenario_corpus_dags_only_flag_the_github_root_cloudbuild():
    """Do No Harm over every committed scenario DAG: the only violations are the GitHub root `cloudbuild.yaml` of the
    12a-12e INFRA-05 tasks; 12d's CODE-02 deploy-workflow target is not flagged; none on Serverless Git."""
    files = sorted(glob.glob(os.path.join(REPO_ROOT, "tests", "scenario_corpus", "*.json")))
    assert files
    for f in files:
        with open(f, encoding="utf-8") as fh:
            dag = json.load(fh).get("task_dag") or []
        tasks = [SimpleNamespace(task_id=t.get("task_id"), target_files=list(t.get("target_files") or []),
                                 depends_on=list(t.get("depends_on") or [])) for t in dag]
        plan = SimpleNamespace(infra_tasks=[], code_tasks=tasks, sequenced_build_plan=None)
        got = [(d.code, d.symbol, d.block_address) for d in pc.check_plan_contract(plan, GITHUB)[0]]
        name = os.path.basename(f)
        if name.startswith("12"):
            assert got == [("PLAN.PLATFORM_CI_FILE", "cloudbuild.yaml", "code_tasks[INFRA-05].target_files[0]")], name
        else:
            assert got == [], name
        assert pc.check_plan_contract(plan, SERVERLESS_GIT)[0] == [], name


# ------------------------------------------------------------------------------------------------- compute scope (finding 2)
def _with_topology(plan, services, primary):
    from shared.service_topology import ServiceTopologyIntent
    plan.service_topology = ServiceTopologyIntent(services=[{"name": n, "kind": k} for n, k in services],
                                                  primary_service=primary, edges=[], resources=[])
    return plan


def _clean_replan(**update):
    plan = _valid_plan()
    for k, v in update.items():
        setattr(plan, k, v)
    return plan


def test_compute_scope_unchanged_is_empty():
    a = _with_topology(_valid_plan(), [("api", "cloudrun"), ("worker", "event-worker")], "api")
    b = _with_topology(_valid_plan(), [("worker", "event-worker"), ("api", "cloudrun")], "api")   # order-free
    assert pc.compute_scope_changes(a, b) == []
    assert pc.compute_scope_changes(_valid_plan(), _valid_plan()) == []


@pytest.mark.parametrize("field,update", [
    ("compute_archetype", {"compute_archetype": "gke-autopilot"}),
    ("compute_archetype", {"compute_archetype": None}),
    ("target_compute_services", {"target_compute_services": ["api", "worker"]}),
    ("target_compute_services", {"target_compute_services": []}),
])
def test_compute_scope_detects_each_plan_field(field, update):
    assert pc.compute_scope_changes(_valid_plan(), _clean_replan(**update)) == [field]


def test_compute_scope_target_services_order_matters():
    a = _clean_replan(target_compute_services=["api", "worker"])
    b = _clean_replan(target_compute_services=["worker", "api"])   # [0] is the primary workload (schemas.py)
    assert pc.compute_scope_changes(a, b) == ["target_compute_services"]


@pytest.mark.parametrize("services,primary,field", [
    ([("api", "cloudrun"), ("jobs", "event-worker")], "api", "service_topology.services"),   # renamed service
    ([("api", "cloudrun"), ("worker", "cloudrun")], "api", "service_topology.services"),     # kind flipped
    ([("api", "cloudrun")], "api", "service_topology.services"),                              # service dropped
    ([("api", "cloudrun"), ("worker", "event-worker")], "worker", "service_topology.primary_service"),
])
def test_compute_scope_detects_each_topology_field(services, primary, field):
    draft = _with_topology(_valid_plan(), [("api", "cloudrun"), ("worker", "event-worker")], "api")
    assert pc.compute_scope_changes(draft, _with_topology(_valid_plan(), services, primary)) == [field]


def test_compute_scope_topology_dropped_and_draft_without_typed_topology():
    draft = _with_topology(_valid_plan(), [("api", "cloudrun")], "api")
    assert pc.compute_scope_changes(draft, _valid_plan()) == ["service_topology"]
    # a draft with no parsed topology (absent or malformed, the topology gate repairs it) has nothing to compare
    assert pc.compute_scope_changes(_valid_plan(), _with_topology(_valid_plan(), [("api", "cloudrun")], "api")) == []


def test_replan_changing_compute_is_a_failed_turn_and_strips_the_draft():
    draft = _ex01_like_plan()
    replan = _Replan(_clean_replan(compute_archetype="gke-autopilot"), _valid_plan())
    res = _gate(draft, replan)
    assert len(replan.calls) == 1                                    # no turn 2 on a re-plan that changed compute
    assert res.outcome == "STRIPPED" and res.plan is draft and res.record["stopped"] == "REPLAN_CHANGED_COMPUTE"
    turn = res.record["turns"][0]
    assert turn["result"] == "CHANGED_COMPUTE" and turn["compute_changed"] == ["compute_archetype"]
    assert draft.compute_archetype == "cloudrun"


def test_replan_changing_compute_in_fail_mode_refuses(monkeypatch):
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")
    with pytest.raises(pc.PlanContractViolationError) as ei:
        _gate(_ex01_like_plan(), _Replan(_clean_replan(target_compute_services=["api", "admin"])))
    assert ei.value.details["stopped"] == "REPLAN_CHANGED_COMPUTE"


def test_replan_with_the_same_compute_is_still_accepted():
    draft = _with_topology(_ex01_like_plan(), [("api", "cloudrun")], "api")
    clean = _with_topology(_valid_plan(), [("api", "cloudrun")], "api")
    res = _gate(draft, _Replan(clean))
    assert res.outcome == "REPLANNED" and res.plan is clean


# ------------------------------------------------------------------------------------------------- unusable answer (finding 3)
def test_unusable_answer_error_is_a_failed_turn_and_strips_the_draft():
    bad = pc.ReplanAnswerUnusableError("every model returned an off-enum archetype",
                                       reason="ARCHITECT_COMPUTE_ARCHETYPE_INVALID")
    draft = _ex01_like_plan()
    res = _gate(draft, _Replan(bad))
    assert res.outcome == "STRIPPED" and res.plan is draft and res.record["stopped"] == "REPLAN_UNUSABLE"
    turn = res.record["turns"][0]
    assert turn["result"] == "UNUSABLE" and turn["error"].startswith("ARCHITECT_COMPUTE_ARCHETYPE_INVALID: ")
    assert not issubclass(pc.ReplanAnswerUnusableError, pc.GateError)


def test_unusable_answer_error_in_fail_mode_refuses(monkeypatch):
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")
    with pytest.raises(pc.PlanContractViolationError) as ei:
        _gate(_ex01_like_plan(), _Replan(pc.ReplanAnswerUnusableError("bad", reason="X")))
    assert ei.value.details["stopped"] == "REPLAN_UNUSABLE"


# ------------------------------------------------------------------------------------------------- gate defects (finding 4)
def _boom(*_a, **_k):
    raise KeyError("defect in the check")


def test_defect_in_the_dag_check_is_a_typed_platform_defect(monkeypatch):
    monkeypatch.setattr(pc, "_validate_dag", _boom)
    with pytest.raises(PlatformDefectError) as ei:
        _gate(_ex01_like_plan(), _Replan(_valid_plan()))
    err = ei.value
    assert err.reason == "PLAN_CONTRACT_GATE_DEFECT" and err.stage == "architect"
    assert err.to_body()["error_class"] == "PLATFORM_DEFECT"
    assert isinstance(err.__cause__, KeyError)
    rec = err.plan_contract_record
    assert rec["outcome"] == "INTERRUPTED" and rec["interrupted_by"]["reason"] == "PLAN_CONTRACT_GATE_DEFECT"
    assert "KeyError" in rec["defect"] and len(rec["violations"]) == 3
    json.dumps(rec)
    _no_nested_arrays(rec)


def test_defect_in_the_check_of_a_valid_plan_is_typed_too(monkeypatch):
    monkeypatch.setattr(pc, "_path_codes", _boom)
    with pytest.raises(PlatformDefectError) as ei:
        _gate(_valid_plan(), None)
    assert ei.value.reason == "PLAN_CONTRACT_GATE_DEFECT"
    assert ei.value.plan_contract_record["outcome"] == "INTERRUPTED"


def test_defect_in_the_strip_is_typed(monkeypatch):
    monkeypatch.setattr(pc, "_strip", _boom)
    with pytest.raises(PlatformDefectError) as ei:
        _gate(_ex01_like_plan(), None)
    assert ei.value.plan_contract_record["stopped"] == "NO_MODEL"


def test_typed_errors_are_never_rewrapped_as_defects(monkeypatch):
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")
    with pytest.raises(pc.PlanContractViolationError):
        _gate(_ex01_like_plan(), None)
