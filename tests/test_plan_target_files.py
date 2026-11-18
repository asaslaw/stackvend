"""PLAN-TARGET-FILES + MANIFEST-PATH-DEFERS-TO-DAG (live ex09-1115 / ex04-1114 on stackvend12, 11-15; diagnosis
docs/handoff/ex09-1115-dag-target-file-diagnosis.md).

ex09-1115: the architect's DAG task CODE-01 named `apps/ex09-1115/models.py`; the lead developer put the models in
`apps/ex09-1115/schemas/portal.py`. Every pre-commit check passed, the build's 16 tests passed, and the QA judge's
file-less JUDGE.ADHERENCE finding ("models.py is missing") sent the whole passing build back (REGENERATE,
FINDING_NOT_ON_A_DRAFT_FILE) twice. Now V-PLAN-TARGETS reports the missing DAG target before commit as
PLAN.TARGET_FILE_MISSING, a file the developer's own repair loop creates. ex04-1114: the DAG named
`k8s/deployment.yaml`, the platform's hint `k8s/<service>.yaml`; the hint and the missing-workload finding now use the
DAG's path. Fakes only; no network."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

import pytest
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
pytest.importorskip("yaml", reason="PyYAML (gateway requirement) not installed")

from developer_agent import handler as dev_handler  # noqa: E402
from developer_agent import plan_targets as pt  # noqa: E402
from developer_agent import topology_wiring as tw  # noqa: E402
from developer_agent.repair_loop import (CREATE_FILE_CODES, Assembled, LoopContext, RepairLoop,  # noqa: E402
                                         Router)
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.container import (K8S_WORKLOAD_MISSING_CODE, K8sWorkloadValidator,  # noqa: E402
                                                  k8s_workload_hint)
from developer_agent.validators.plan_targets import CODE, VALIDATOR_ID, PlanTargetValidator  # noqa: E402
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from shared import service_topology as st  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import AssemblyRecord, Diagnostic, ErrorClass, MemoryLedgerStore  # noqa: E402
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

SVC = "ex09-1115"
# The live run's task DAG (pipeline_executions/intake-ex09-1115-837955/stage_traces/architect: infra_tasks +
# code_tasks), target files and categories exact; titles shortened.
EX09_DAG = [
    {"task_id": "INFRA-01", "category": "INFRA", "title": "APIs",
     "target_files": ["infra/workload/main.tf", "infra/workload/variables.tf"]},
    {"task_id": "INFRA-02", "category": "INFRA", "title": "Firestore", "target_files": ["infra/workload/main.tf"]},
    {"task_id": "INFRA-03", "category": "INFRA", "title": "IAM + Direct IAP",
     "target_files": ["infra/workload/main.tf", "infra/workload/outputs.tf"]},
    {"task_id": "INFRA-04", "category": "RELEASE", "title": "CI/CD",
     "target_files": [".github/workflows/deploy-ex09-1115.yml"]},
    {"task_id": "CODE-01", "category": "CODE", "title": "IAP middleware + RBAC",
     "target_files": [f"apps/{SVC}/auth.py", f"apps/{SVC}/models.py", f"apps/{SVC}/requirements.txt",
                      f"apps/{SVC}/Procfile"]},
    {"task_id": "CODE-02", "category": "CODE", "title": "Portal API, audit logger, UI",
     "target_files": [f"apps/{SVC}/main.py", f"apps/{SVC}/store.py", f"apps/{SVC}/ui.py"]},
    {"task_id": "CODE-03", "category": "TEST", "title": "pytest suite", "target_files": ["tests/test_main.py",
                                                                                         "README.md"]},
]
FASTAPI = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/health")\ndef health():\n    return {"ok": True}\n'
# the committed tree of attempt 0 (c53093e7) at the paths that matter: models in schemas/portal.py, no models.py
EX09_TREE = {
    f"apps/{SVC}/auth.py": "import store\n", f"apps/{SVC}/main.py": FASTAPI, f"apps/{SVC}/store.py": "X = 1\n",
    f"apps/{SVC}/ui.py": "Y = 1\n", f"apps/{SVC}/requirements.txt": "fastapi\n", f"apps/{SVC}/Procfile": "web: x\n",
    f"apps/{SVC}/schemas/portal.py": "class Role:\n    pass\n", "tests/test_main.py": "def test_x():\n    pass\n",
    "README.md": "# ex09\n",
}
ATTRIBUTION = {f"apps/{SVC}/auth.py": "BACKEND_ENGINEER", f"apps/{SVC}/requirements.txt": "DEVOPS_ENGINEER",
               f"apps/{SVC}/Procfile": "DEVOPS_ENGINEER", f"apps/{SVC}/main.py": "BACKEND_ENGINEER",
               f"apps/{SVC}/store.py": "DATABASE_ENGINEER", f"apps/{SVC}/ui.py": "BACKEND_ENGINEER",
               f"apps/{SVC}/schemas/portal.py": "DATABASE_ENGINEER", "tests/test_main.py": "TEST_ENGINEER",
               "README.md": "TEST_ENGINEER"}


def _paths(targets):
    return [t.path for t in targets]


def _ctx(files):
    return ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED, draft=dict(files))


# ================================================================================================ required targets
def test_ex09_required_targets_are_the_code_and_test_tasks_files():
    targets = pt.required_plan_targets(EX09_DAG, service_names=[SVC])
    assert _paths(targets) == [f"apps/{SVC}/auth.py", f"apps/{SVC}/models.py", f"apps/{SVC}/requirements.txt",
                               f"apps/{SVC}/Procfile", f"apps/{SVC}/main.py", f"apps/{SVC}/store.py",
                               f"apps/{SVC}/ui.py", "tests/test_main.py", "README.md"]
    models = targets[1]
    assert models.task_id == "CODE-01"
    assert models.siblings == (f"apps/{SVC}/auth.py", f"apps/{SVC}/requirements.txt", f"apps/{SVC}/Procfile")


def test_ex09_attempt_0_tree_misses_exactly_models_py():
    targets = pt.required_plan_targets(EX09_DAG, service_names=[SVC])
    assert _paths(pt.missing_plan_targets(targets, EX09_TREE)) == [f"apps/{SVC}/models.py"]
    found = PlanTargetValidator(targets).validate(_ctx(EX09_TREE))
    assert [(d.code, d.file, d.severity, d.error_class) for d in found] == [
        (CODE, f"apps/{SVC}/models.py", "error", ErrorClass.CODE_DEFECT)]
    assert "CODE-01" in found[0].message and "CODE-01" in found[0].hint
    assert f"apps/{SVC}/auth.py" in found[0].hint


def test_do_no_harm_a_tree_with_every_target_has_no_finding_and_is_unchanged():
    tree = dict(EX09_TREE, **{f"apps/{SVC}/models.py": "from schemas.portal import Role\n"})
    ctx = _ctx(tree)
    targets = pt.required_plan_targets(EX09_DAG, service_names=[SVC])
    assert PlanTargetValidator(targets).validate(ctx) == []
    assert dict(ctx.files) == tree


def test_a_target_the_repository_already_holds_is_not_missing():
    """The assembled tree includes the repository's files: an update run need not rewrite a target that exists."""
    targets = pt.required_plan_targets(EX09_DAG, service_names=[SVC])
    tree = dict(EX09_TREE, **{f"apps/{SVC}/models.py": "# committed by an earlier build\n"})
    assert pt.missing_plan_targets(targets, tree) == []


def test_tasks_the_platform_answers_contribute_nothing():
    dag = [{"task_id": "I", "category": "INFRA", "target_files": ["apps/x/db_setup.py"]},
           {"task_id": "C", "category": "CICD", "target_files": ["apps/x/ci.py"]}]
    assert pt.required_plan_targets(dag, service_names=["x"]) == ()


def test_rt_f4_a_platform_path_in_a_code_task_drops_only_itself():
    dag = [{"task_id": "P", "category": "CODE",
            "target_files": [".github/workflows/x.yml", "cloudbuild.yaml", "apps/x/main.py"]}]
    assert _paths(pt.required_plan_targets(dag, service_names=["x"])) == ["apps/x/main.py"]


@pytest.mark.parametrize("path", [
    "main.py", "requirements.txt", "Procfile", "src/app.py", "docs/guide.md",   # outside the platform layout
    "apps/backend/main.py", "apps/backend/requirements.txt",                       # not a typed service
    "apps/x/static/logo.png", "apps/x/package-lock.json", "apps/x/poetry.lock",   # assets / lock files
    ".env", "apps/x/.env", "docker-compose.yml",                                   # dotfile / root file
    "docs", "apps/x/templates", "apps/x/bin/run",                                 # no text file name
    "k8s/sub/a.yaml", "apps/x/k8s/deployment.yaml.bak",
])
def test_rt_f3_only_the_platform_layout_is_required(path):
    dag = [{"task_id": "C", "category": "CODE", "target_files": [path]}]
    assert pt.required_plan_targets(dag, service_names=["x"]) == ()


@pytest.mark.parametrize("path", ["apps/x/models.py", "apps/x/Procfile", "apps/x/templates/index.html",
                                  "apps/x/tests/test_a.py", "tests/test_a.py", "README.md", "k8s/app.yaml",
                                  "k8s/app.yml"])
def test_rt_f3_the_platform_layout_is_required(path):
    dag = [{"task_id": "C", "category": "CODE", "target_files": [path]}]
    assert _paths(pt.required_plan_targets(dag, service_names=["x"])) == [path]


@pytest.mark.parametrize("path", [
    "apps/x/*.py", "apps/x/[a].py", "apps/x/?.py",                      # patterns, not files
    "../x.py", "/abs/x.py", "apps//x.py", "apps/./x.py", "apps/.git/x",  # not safe relative paths
    "infra/workload/custom.tf", "infra/modules/m/main.tf", ".github/workflows/ci.yml",   # the platform's tree
    "cloudbuild.yaml",                                                   # a platform render
    ".python-version", "apps/x/.python-version",                         # runtime pins
    "Dockerfile", "apps/x/Dockerfile.dev", "apps/x/.dockerignore",       # Buildpacks only (invariant 4)
    "human.tf", "apps/x/override.tf",                                   # reserved for the human architect
    "apps/x/schemas.py", "apps/x/schemas/__init__.py", "apps/x/schemas/contracts.py",   # Wave 0 registry
    "contracts/schemas.py", "contracts/__init__.py",
])
def test_paths_the_developer_may_not_write_are_never_required(path):
    dag = [{"task_id": "C", "category": "CODE", "target_files": [path]}]
    assert pt.required_plan_targets(dag, service_names=["x"]) == ()


def test_root_tests_of_a_multi_service_workload_are_not_required():
    dag = [{"task_id": "T", "category": "TEST", "target_files": ["tests/test_a.py", "apps/a/tests/test_a.py"]}]
    assert _paths(pt.required_plan_targets(dag, service_names=["a", "b"])) == ["apps/a/tests/test_a.py"]
    assert _paths(pt.required_plan_targets(dag, service_names=["a"])) == ["tests/test_a.py", "apps/a/tests/test_a.py"]


@pytest.mark.parametrize("dag", [None, {}, "x", [], [None, 3, "t"], [{"task_id": "C"}],
                                 [{"task_id": "C", "target_files": "apps/x/a.py"}],
                                 [{"task_id": "C", "target_files": [None, 3, ""]}]])
def test_malformed_dags_require_nothing(dag):
    assert pt.required_plan_targets(dag) == ()


def test_first_task_naming_a_path_wins_and_ids_are_printable_only():
    dag = [{"task_id": "A\nB", "category": "CODE", "target_files": ["apps/x/a.py", "apps/x/b.py"]},
           {"task_id": "C", "category": "CODE", "target_files": ["apps/x/a.py"]}]
    targets = pt.required_plan_targets(dag, service_names=["x"])
    assert _paths(targets) == ["apps/x/a.py", "apps/x/b.py"]
    assert targets[0].task_id is None and targets[0].siblings == ("apps/x/b.py",)


# ================================================================================================ registration
def test_registered_blocking_only_with_targets():
    plain = build_step1_stack(validate_client=None, verifier_factory=None)
    assert VALIDATOR_ID not in plain.ids
    with_targets = build_step1_stack(validate_client=None, verifier_factory=None,
                                     plan_targets=pt.required_plan_targets(EX09_DAG))
    assert with_targets.mode_of(VALIDATOR_ID) == "blocking"
    assert [i for i in with_targets.ids if i != VALIDATOR_ID] == plain.ids


def test_code_is_a_create_code():
    assert CODE in CREATE_FILE_CODES


# ================================================================================================ routing
def _diag(path, code=CODE):
    return Diagnostic(tool="schema", code=code, severity="error", error_class=ErrorClass.CODE_DEFECT, file=path,
                      message="m", hint="h", source="precommit")


def _loop_ctx(draft, attribution, plan_map, **kw):
    return LoopContext(trace_id="t1", product_id=SVC, assemble=kw.pop("assemble", lambda d: None),
                       stack=kw.pop("stack", ValidatorStack()), ledger_store=MemoryLedgerStore(),
                       settings=HallucinationStackSettings(), attribution=dict(attribution),
                       llm_draft_paths=set(draft), preexisting=set(), model="m", plan_targets=plan_map, **kw)


def _router(draft, attribution, plan_map, **kw):
    ctx = _loop_ctx(draft, attribution, plan_map, **kw)
    return Router(ctx, draft, Assembled(tree=dict(draft), record=AssemblyRecord(), assembled_root={}))


def _plan_map(dag=EX09_DAG):
    return {t.path: t.siblings for t in pt.required_plan_targets(dag, service_names=[SVC])}


def test_missing_target_goes_to_the_author_of_another_target_of_the_same_task():
    r = _router(EX09_TREE, ATTRIBUTION, _plan_map()).route(_diag(f"apps/{SVC}/models.py"))
    assert (r.error_class, r.persona, r.draft_path) == (ErrorClass.CODE_DEFECT, "BACKEND_ENGINEER",
                                                        f"apps/{SVC}/models.py")
    assert r.hint == "h"


def test_prior_run_author_wins_like_every_other_route():
    ctx = _loop_ctx(EX09_TREE, ATTRIBUTION, _plan_map(), prior_llm={f"apps/{SVC}/auth.py": "SECURITY_ENGINEER"})
    router = Router(ctx, EX09_TREE, Assembled(tree=dict(EX09_TREE), record=AssemblyRecord(), assembled_root={}))
    assert router.route(_diag(f"apps/{SVC}/models.py")).persona == "SECURITY_ENGINEER"


def test_no_sibling_author_falls_back_to_the_same_directory_then_developer():
    dag = [{"task_id": "C", "category": "CODE", "target_files": ["apps/x/new.py"]}]
    draft = {"apps/x/main.py": FASTAPI, "apps/y/main.py": FASTAPI}
    attribution = {"apps/x/main.py": "BACKEND_ENGINEER", "apps/y/main.py": "OTHER_ENGINEER"}
    plan_map = {t.path: t.siblings for t in pt.required_plan_targets(dag, service_names=["x", "y"])}
    assert _router(draft, attribution, plan_map).route(_diag("apps/x/new.py")).persona == "BACKEND_ENGINEER"
    dag = [{"task_id": "C", "category": "CODE", "target_files": ["README.md"]}]
    plan_map = {t.path: t.siblings for t in pt.required_plan_targets(dag)}
    r = _router(draft, attribution, plan_map).route(_diag("README.md"))
    assert (r.error_class, r.persona) == (ErrorClass.CODE_DEFECT, "developer")


def test_rt_f5_a_file_the_repository_holds_is_never_routed_as_a_create():
    plan_map = {"apps/x/new.py": ()}
    r = _router({"apps/x/main.py": FASTAPI}, {"apps/x/main.py": "B"}, plan_map,
                preexisting_files={"apps/x/new.py": "X = 1\n"}).route(_diag("apps/x/new.py"))
    assert r.error_class is ErrorClass.PLATFORM_DEFECT


@pytest.mark.parametrize("path", ["apps/x/other.py", "../x.py", "apps/.git/x.py"])
def test_a_path_that_is_not_a_given_target_is_never_offered(path):
    plan_map = {"apps/x/new.py": ()}
    r = _router({"apps/x/main.py": FASTAPI}, {"apps/x/main.py": "B"}, plan_map).route(_diag(path))
    assert r.error_class is ErrorClass.PLATFORM_DEFECT


class _Persona:
    def __init__(self, *responses):
        self.responses, self.tasks = list(responses), []

    def __call__(self, task):
        self.tasks.append(task)
        return {"files": self.responses.pop(0) if self.responses else {}, "envelope_ok": True, "model": "m",
                "tokens_in": 10, "tokens_out": 10, "tokens_thoughts": 0}


def _assemble(d):
    return Assembled(tree=dict(d), record=AssemblyRecord(), assembled_root={})


def test_repair_loop_creates_the_missing_target_end_to_end_without_touching_other_files():
    models = "from schemas.portal import Role\n\n__all__ = ['Role']\n"
    persona = _Persona({f"apps/{SVC}/models.py": models})
    stack = ValidatorStack()
    stack.register(PlanTargetValidator(pt.required_plan_targets(EX09_DAG, service_names=[SVC])), "blocking")
    ctx = _loop_ctx(EX09_TREE, ATTRIBUTION, _plan_map(), assemble=_assemble, stack=stack, repair_fn=persona,
                    available_providers=["google"])
    tree, report = RepairLoop(ctx).run(dict(EX09_TREE))
    assert report.status == "PASS"
    assert tree == dict(EX09_TREE, **{f"apps/{SVC}/models.py": models})   # one file added, nothing else changed
    t = persona.tasks[0]
    assert t.persona == "BACKEND_ENGINEER"
    assert t.creates == [f"apps/{SVC}/models.py"] and t.files_to_fix == {f"apps/{SVC}/models.py": ""}
    assert "CODE-01" in t.prompt()
    assert ctx.attribution[f"apps/{SVC}/models.py"] == "BACKEND_ENGINEER"


def test_a_complete_build_never_calls_a_model():
    persona = _Persona()
    stack = ValidatorStack()
    stack.register(PlanTargetValidator(pt.required_plan_targets(EX09_DAG, service_names=[SVC])), "blocking")
    tree_in = dict(EX09_TREE, **{f"apps/{SVC}/models.py": "X = 1\n"})
    ctx = _loop_ctx(tree_in, ATTRIBUTION, _plan_map(), assemble=_assemble, stack=stack, repair_fn=persona,
                    available_providers=["google"])
    tree, report = RepairLoop(ctx).run(dict(tree_in))
    assert report.status == "PASS" and tree == tree_in and persona.tasks == []


# ================================================================================================ handler wiring
class _Intent:
    def __init__(self, archetype="cloudrun", service_names=(SVC,)):
        self.archetype, self.service_names = archetype, list(service_names)


class _Inputs:
    def __init__(self, archetype="cloudrun", task_dag=EX09_DAG):
        self.compute_intent, self.task_dag = _Intent(archetype), task_dag


def test_handler_checks_targets_on_a_full_build_only():
    """The stack gets the targets only when the dispatch is neither a QA nor a deploy repair."""
    full = dev_handler.dispatch_plan_targets(_Inputs(), None, None)
    assert full == pt.required_plan_targets(EX09_DAG, service_names=[SVC]) and full
    assert dev_handler.dispatch_plan_targets(_Inputs(), object(), None) == ()
    assert dev_handler.dispatch_plan_targets(_Inputs(), None, object()) == ()


def test_handler_wires_the_targets_into_the_stack_and_the_loop():
    import inspect
    src = inspect.getsource(dev_handler.DeveloperAgent._run_hallucination_stack)
    assert "dispatch_plan_targets(inputs, qa_plan, deploy_plan)" in src
    assert "plan_targets=required_targets" in src and "plan_targets={t.path: t.siblings" in src


# ================================================================================================ manifest paths
def _topo(services, primary):
    vt, diags = st.validate_service_topology(
        {"services": [{"name": n, "kind": k} for n, k in services], "primary_service": primary, "edges": [],
         "resources": []}, product_id="test-04")
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


EX04_DAG = [{"task_id": "CODE-02", "category": "CODE", "title": "k8s manifests",
             "target_files": ["k8s/deployment.yaml", "k8s/serviceaccount.yaml", "apps/ex04-1114/main.py"]},
            {"task_id": "CODE-03", "category": "TEST", "target_files": ["tests/test_k8s_manifests.py"]}]


def test_one_gke_service_owns_every_applied_manifest_target_in_dag_order():
    assert pt.dag_manifest_paths(EX04_DAG, ["ex04-1114"]) == {
        "ex04-1114": ("k8s/deployment.yaml", "k8s/serviceaccount.yaml")}


@pytest.mark.parametrize("path", ["apps/ex04-1114/k8s/deployment.yaml", "k8s/sub/deployment.yaml",
                                  "k8s/deployment.json", "k8s/*.yaml", "../k8s/deployment.yaml"])
def test_only_applied_manifest_paths_count(path):
    dag = [{"task_id": "C", "category": "CODE", "target_files": [path]}]
    assert pt.dag_manifest_paths(dag, ["ex04-1114"]) == {}


def test_yml_is_an_applied_manifest_too():
    dag = [{"task_id": "C", "category": "CODE", "target_files": ["k8s/app.yml"]}]
    assert pt.dag_manifest_paths(dag, ["svc"]) == {"svc": ("k8s/app.yml",)}


def test_several_gke_services_own_the_manifests_of_their_own_task_only():
    dag = [{"task_id": "A", "target_files": ["apps/a/main.py", "k8s/a-deploy.yaml"]},
           {"task_id": "B", "target_files": ["apps/b/main.py", "k8s/b-deploy.yaml"]},
           {"task_id": "AB", "target_files": ["apps/a/x.py", "apps/b/x.py", "k8s/shared.yaml"]},   # two services
           {"task_id": "N", "target_files": ["k8s/nobody.yaml"]},                                  # no service
           {"task_id": "A2", "target_files": ["apps/a/y.py", "k8s/both.yaml"]},
           {"task_id": "B2", "target_files": ["apps/b/y.py", "k8s/both.yaml"]}]                    # claimed twice
    assert pt.dag_manifest_paths(dag, ["a", "b"]) == {"a": ("k8s/a-deploy.yaml",), "b": ("k8s/b-deploy.yaml",)}


@pytest.mark.parametrize("dag,gke", [(None, ["s"]), ([], ["s"]), (EX04_DAG, []), (EX04_DAG, [None, ""])])
def test_no_dag_or_no_gke_service_defers_nothing(dag, gke):
    assert pt.dag_manifest_paths(dag, gke) == {}


def test_handler_helper_reads_the_typed_gke_kind():
    vt = _topo([("ex04-1114", "gke-autopilot")], "ex04-1114")
    assert dev_handler.dag_manifest_paths(EX04_DAG, vt) == {
        "ex04-1114": ("k8s/deployment.yaml", "k8s/serviceaccount.yaml")}
    assert dev_handler.dag_manifest_paths(EX04_DAG, _topo([("ex04-1114", "cloudrun")], "ex04-1114")) == {}
    assert dev_handler.dag_manifest_paths(EX04_DAG, None) == {}


# The clause and hint exactly as before MANIFEST-PATH-DEFERS-TO-DAG (byte-identical default).
def _old_clause(name):
    from developer_agent.preflight_validator import K8S_MANIFEST_PLACEHOLDERS
    tokens = ", ".join(f"`${{{t}}}`" for t in K8S_MANIFEST_PLACEHOLDERS)
    return (f"; it runs on the platform's GKE Autopilot cluster only through `k8s/{name}.yaml` (repository root; the "
            f"platform applies exactly `k8s/*.yaml`): a Deployment named `{name}` whose container `{name}` uses "
            f"`image: ${{ARTIFACT_REGISTRY}}/{name}:latest` (the image the platform builds from `apps/{name}/`); "
            f"the only placeholders the platform substitutes in these manifests are exactly {tokens}, and any other "
            f"`$` in an `image:` or `iam.gke.io/gcp-service-account` value stops the build (write a Google service "
            f"account email as `<account>@${{PROJECT_ID}}.iam.gserviceaccount.com`)")


def test_negative_clause_and_contract_are_byte_identical_without_dag_paths():
    assert tw.gke_manifest_clause("ex04-1114") == _old_clause("ex04-1114")
    vt = _topo([("ex04-1114", "gke-autopilot")], "ex04-1114")
    assert (tw.topology_contract_rule(vt) == tw.topology_contract_rule(vt, manifest_paths=None)
            == tw.topology_contract_rule(vt, manifest_paths={}) == tw.topology_contract_rule(
                vt, manifest_paths={"other": ("k8s/x.yaml",)}))
    assert _old_clause("ex04-1114") in tw.topology_contract_rule(vt)


def test_clause_names_the_dag_manifest_instead_of_the_service_name():
    clause = tw.gke_manifest_clause("ex04-1114", ("k8s/deployment.yaml",))
    assert "`k8s/deployment.yaml` (the manifest the architect's plan names for it;" in clause
    assert "k8s/ex04-1114.yaml" not in clause
    assert "a Deployment named `ex04-1114`" in clause and "${ARTIFACT_REGISTRY}/ex04-1114:latest" in clause
    several = tw.gke_manifest_clause("ex04-1114", ("k8s/deployment.yaml", "k8s/serviceaccount.yaml"))
    assert "`k8s/deployment.yaml`, `k8s/serviceaccount.yaml` (write each of them;" in several
    assert "one of them holds a Deployment named `ex04-1114`" in several and "k8s/ex04-1114.yaml" not in several
    vt = _topo([("ex04-1114", "gke-autopilot")], "ex04-1114")
    assert clause in tw.topology_contract_rule(vt, manifest_paths={"ex04-1114": ("k8s/deployment.yaml",)})


def _k8s(files, vt, manifest_paths=None):
    ctx = ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED, draft=dict(files))
    return K8sWorkloadValidator(vt, manifest_paths).validate(ctx)


DEPLOYMENT = ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: ex04-1114\nspec:\n  template:\n    spec:\n"
              "      containers:\n        - name: ex04-1114\n          image: ${ARTIFACT_REGISTRY}/ex04-1114:latest\n")
APP = {"apps/ex04-1114/main.py": FASTAPI, "apps/ex04-1114/Procfile": "web: uvicorn main:app\n"}


def test_negative_missing_workload_finding_is_unchanged_without_dag_paths():
    vt = _topo([("ex04-1114", "gke-autopilot")], "ex04-1114")
    for mp in (None, {}, {"other": ("k8s/x.yaml",)}):
        found = _k8s(APP, vt, mp)
        assert [(d.code, d.file, d.hint) for d in found] == [
            (K8S_WORKLOAD_MISSING_CODE, "k8s/ex04-1114.yaml", k8s_workload_hint("ex04-1114"))]
    assert k8s_workload_hint("ex04-1114") == (
        "Write k8s/ex04-1114.yaml (repository root: the platform applies exactly k8s/*.yaml) with a Deployment (or "
        "StatefulSet / DaemonSet / Job / CronJob) named `ex04-1114` whose container `ex04-1114` uses "
        "`image: ${ARTIFACT_REGISTRY}/ex04-1114:latest` (the image the platform builds from apps/ex04-1114/) and "
        "runs the service's Procfile command.")


def test_missing_workload_finding_names_the_dag_manifest():
    vt = _topo([("ex04-1114", "gke-autopilot")], "ex04-1114")
    mp = {"ex04-1114": ("k8s/deployment.yaml", "k8s/serviceaccount.yaml")}
    found = _k8s(APP, vt, mp)
    assert [(d.code, d.file) for d in found] == [(K8S_WORKLOAD_MISSING_CODE, "k8s/deployment.yaml")]
    assert "Write k8s/deployment.yaml (the manifest the architect's plan names" in found[0].hint
    # the first DAG manifest is there (a ServiceAccount only): the next one not in the tree is the file to create
    sa = "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: x\n"
    found = _k8s(dict(APP, **{"k8s/deployment.yaml": sa}), vt, mp)
    assert [d.file for d in found] == ["k8s/serviceaccount.yaml"]
    # every DAG manifest is there and none runs the service: the first one, repaired by its author
    found = _k8s(dict(APP, **{"k8s/deployment.yaml": sa, "k8s/serviceaccount.yaml": sa}), vt, mp)
    assert [d.file for d in found] == ["k8s/deployment.yaml"]
    # the Deployment in the DAG's file satisfies the check (any applied manifest did before, too)
    assert _k8s(dict(APP, **{"k8s/deployment.yaml": DEPLOYMENT}), vt, mp) == []


def test_k8s_create_of_a_dag_manifest_routes_through_the_service_it_was_named_for():
    draft = dict(APP)
    attribution = {p: "WORKER_ENGINEER" for p in APP}
    diag = Diagnostic(tool="container", code=K8S_WORKLOAD_MISSING_CODE, severity="error",
                      error_class=ErrorClass.CODE_DEFECT, file="k8s/deployment.yaml", message="m",
                      source="precommit")
    before = _router(draft, attribution, {}).route(diag)
    assert before.error_class is ErrorClass.PLATFORM_DEFECT   # stem `deployment` is no service: as before
    r = _router(draft, attribution, {}, manifest_services={"k8s/deployment.yaml": "ex04-1114"}).route(diag)
    assert (r.error_class, r.persona, r.draft_path) == (ErrorClass.CODE_DEFECT, "WORKER_ENGINEER",
                                                        "k8s/deployment.yaml")
    yml = diag.model_copy(update={"file": "k8s/app.yml"})
    assert _router(draft, attribution, {}).route(yml).error_class is ErrorClass.PLATFORM_DEFECT
    r = _router(draft, attribution, {}, manifest_services={"k8s/app.yml": "ex04-1114"}).route(yml)
    assert (r.error_class, r.draft_path) == (ErrorClass.CODE_DEFECT, "k8s/app.yml")


def test_dag_manifests_are_required_targets_so_the_plan_and_the_build_agree():
    """With the hint deferring to the DAG, V-PLAN-TARGETS asks for exactly the files the hint names."""
    assert _paths(pt.required_plan_targets(EX04_DAG, service_names=["ex04-1114"])) == [
        "k8s/deployment.yaml", "k8s/serviceaccount.yaml", "apps/ex04-1114/main.py", "tests/test_k8s_manifests.py"]


# ================================================================================================ RT hardening
def test_a_target_the_assembly_removed_from_the_draft_is_not_reported():
    """The draft holds it and the assembled tree does not: the platform's own assembly removed it (e.g. no `apps/` on
    a foundation-only workload), so a repair could never make it stay: not reported (no repair ping-pong)."""
    targets = pt.required_plan_targets(EX09_DAG, service_names=[SVC])
    draft = dict(EX09_TREE, **{f"apps/{SVC}/models.py": "X = 1\n"})
    assert pt.missing_plan_targets(targets, EX09_TREE, draft) == []
    ctx = ValidationContext.build(EX09_TREE, ownership=lambda p: Ownership.LLM_AUTHORED, draft=draft)
    assert PlanTargetValidator(targets).validate(ctx) == []


def test_a_target_that_is_a_directory_of_the_tree_or_under_a_tree_file_is_not_reported():
    dag = [{"task_id": "C", "category": "CODE", "target_files": ["apps/x/routers", "apps/x/main.py/extra.py",
                                                                  "apps/x/new.py"]}]
    targets = pt.required_plan_targets(dag, service_names=["x"])
    tree = {"apps/x/routers/items.py": "X = 1\n", "apps/x/main.py": FASTAPI}
    assert _paths(pt.missing_plan_targets(targets, tree)) == ["apps/x/new.py"]


@pytest.mark.parametrize("archetype", ["foundation-only", "none", "empty"])
def test_handler_skips_plan_targets_on_archetypes_without_app_code(archetype):
    assert dev_handler.dispatch_plan_targets(_Inputs(archetype), None, None) == ()


def test_no_app_code_archetypes_are_the_assemblys_own_set():
    import inspect
    src = inspect.getsource(dev_handler.DeveloperAgent._assemble_tree)
    assert 'if archetype in ("foundation-only", "none", "empty"):' in src
    assert dev_handler.NO_APP_CODE_ARCHETYPES == ("foundation-only", "none", "empty")


def test_one_creator_per_file_prefers_the_specific_create_route():
    from developer_agent.repair_loop import _one_creator_per_file
    by_persona = {
        "A_PLAN": {"files": {"k8s/deployment.yaml": "", "apps/s/models.py": ""},
                   "creates": {"k8s/deployment.yaml", "apps/s/models.py"},
                   "diags": [{"code": CODE, "file": "k8s/deployment.yaml"}, {"code": CODE, "file": "apps/s/models.py"}]},
        "Z_K8S": {"files": {"k8s/deployment.yaml": ""}, "creates": {"k8s/deployment.yaml"},
                  "diags": [{"code": K8S_WORKLOAD_MISSING_CODE, "file": "k8s/deployment.yaml"}]},
    }
    _one_creator_per_file(by_persona)
    assert by_persona["A_PLAN"]["files"] == {"apps/s/models.py": ""}
    assert by_persona["A_PLAN"]["creates"] == {"apps/s/models.py"}
    assert by_persona["Z_K8S"]["files"] == {"k8s/deployment.yaml": ""}
    assert sorted(x["code"] for x in by_persona["Z_K8S"]["diags"]) == sorted([K8S_WORKLOAD_MISSING_CODE, CODE])


def test_negative_one_creator_per_file_leaves_distinct_creates_alone():
    import copy
    from developer_agent.repair_loop import _one_creator_per_file
    by_persona = {"A": {"files": {"a.py": ""}, "creates": {"a.py"}, "diags": [{"code": CODE, "file": "a.py"}]},
                  "B": {"files": {"b.py": "", "c.py": "x"}, "creates": {"b.py"},
                        "diags": [{"code": CODE, "file": "b.py"}, {"code": "PY.SYNTAX", "file": "c.py"}]}}
    before = copy.deepcopy(by_persona)
    _one_creator_per_file(by_persona)
    assert by_persona == before


def test_a_plan_create_task_sees_the_drafts_other_files_and_other_tasks_do_not():
    persona = _Persona({f"apps/{SVC}/models.py": "from schemas.portal import Role\n"})
    stack = ValidatorStack()
    stack.register(PlanTargetValidator(pt.required_plan_targets(EX09_DAG, service_names=[SVC])), "blocking")
    ctx = _loop_ctx(EX09_TREE, ATTRIBUTION, _plan_map(), assemble=_assemble, stack=stack, repair_fn=persona,
                    available_providers=["google"])
    RepairLoop(ctx).run(dict(EX09_TREE))
    context = persona.tasks[0].read_only_context
    assert context[f"apps/{SVC}/schemas/portal.py"] == EX09_TREE[f"apps/{SVC}/schemas/portal.py"]
    assert f"apps/{SVC}/models.py" not in context
    assert "READ-ONLY CONTEXT" in persona.tasks[0].prompt()


def test_k8s_and_plan_findings_on_one_dag_manifest_make_one_create_task():
    vt = _topo([("ex04-1114", "gke-autopilot")], "ex04-1114")
    mp = {"ex04-1114": ("k8s/deployment.yaml",)}
    dag = [{"task_id": "CODE-02", "category": "CODE",
            "target_files": ["k8s/deployment.yaml", "apps/ex04-1114/main.py"]}]
    targets = pt.required_plan_targets(dag, service_names=["ex04-1114"])
    draft = dict(APP, **{"k8s/ns.yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: n\n"})
    attribution = {"apps/ex04-1114/main.py": "BACKEND_ENGINEER", "apps/ex04-1114/Procfile": "BACKEND_ENGINEER",
                   "k8s/ns.yaml": "DEVOPS_ENGINEER"}
    stack = ValidatorStack()
    stack.register(K8sWorkloadValidator(vt, mp), "blocking")
    stack.register(PlanTargetValidator(targets), "blocking")
    persona = _Persona({"k8s/deployment.yaml": DEPLOYMENT})
    ctx = _loop_ctx(draft, attribution, {t.path: t.siblings for t in targets}, assemble=_assemble, stack=stack,
                    repair_fn=persona, available_providers=["google"],
                    manifest_services={"k8s/deployment.yaml": "ex04-1114"})
    tree, report = RepairLoop(ctx).run(dict(draft))
    assert report.status == "PASS" and tree["k8s/deployment.yaml"] == DEPLOYMENT
    assert len(persona.tasks) == 1
    t = persona.tasks[0]
    assert t.persona == "DEVOPS_ENGINEER"   # the manifest author (V3c-k8s's own route) creates it
    assert t.creates == ["k8s/deployment.yaml"]
    assert sorted(x["code"] for x in t.diagnostics) == sorted([K8S_WORKLOAD_MISSING_CODE, CODE])


def test_rt_f1_an_update_run_whose_draft_omits_a_repository_target_passes_without_a_model_call():
    """RT F1 (probe p1): the assembled tree does not carry the repository's app files (the commit keeps them), so a
    DAG target the repository holds and the draft does not rewrite is present (the judge: "present, unchanged")."""
    repository = dict(EX09_TREE, **{f"apps/{SVC}/models.py": "from schemas.portal import Role\n"})
    draft = {f"apps/{SVC}/main.py": FASTAPI + "# v2\n"}
    persona = _Persona()
    stack = ValidatorStack()
    stack.register(PlanTargetValidator(pt.required_plan_targets(EX09_DAG, service_names=[SVC])), "blocking")
    ctx = _loop_ctx(draft, ATTRIBUTION, _plan_map(), assemble=_assemble, stack=stack, repair_fn=persona,
                    available_providers=["google"], preexisting_files=repository)
    ctx.preexisting = set(repository)
    tree, report = RepairLoop(ctx).run(dict(draft))
    assert report.status == "PASS" and persona.tasks == [] and tree == draft
    # and the validator alone, with and without the repository
    targets = pt.required_plan_targets(EX09_DAG, service_names=[SVC])
    assert pt.missing_plan_targets(targets, draft, draft, repository) == []
    assert _paths(pt.missing_plan_targets(targets, draft, draft)) == [p for p in _paths(targets) if p not in draft]
