"""Example 02 QA platform findings (owner 11-13, plan docs/planning/ex02-qa-platform-findings-plan.md; diagnosis
docs/handoff/ex02-1113-qa-diagnosis.md).

A. TEST-LAYOUT-PLATFORM-FACT: a multi-service plan never targets the repository-root `tests/` (architect contract,
   lead plan-time check), and the QA judges are told the platform's multi-service test layout rule as a typed fact.
B. SECURITY-LENS-PLATFORM-FACTS: one typed platform-facts object, rendered the same way, reaches every QA lens; the
   security lens keeps a Public app's per-service access finding on a platform IaC / CI file as a typed advisory.

Hermetic: fake judge, FakeDB, fake source backend, fake QA job, fake architect model client.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)

from developer_agent import workload_test_layout as TL  # noqa: E402
from qa_auditor import judge_input as ji  # noqa: E402

from test_adherence_platform_satisfied import (  # noqa: E402,F401  (helpers and the `gw` / `_no_firestore` fixtures)
    TREE, _db, _judge, _no_firestore, _run, gw)

TWO = ["service-a", "service-b"]
EX02_CODE03 = ["tests/test_service_a.py", "tests/test_service_b.py", "README.md"]


# ============================================================================ A. the plan contract (pure function)
def test_multi_service_root_tests_targets_are_relocated_when_the_task_names_one_service():
    out, moved = TL.plan_test_targets(["apps/service-a/main.py", "tests/test_api.py", "tests/conftest.py"], TWO)
    assert out == ["apps/service-a/main.py", "apps/service-a/tests/test_api.py", "apps/service-a/tests/conftest.py"]
    assert moved == ("tests/test_api.py", "tests/conftest.py")


def test_ex02_code03_root_tests_targets_are_removed_when_no_single_service_is_named():
    out, moved = TL.plan_test_targets(EX02_CODE03, TWO)
    assert out == ["README.md"] and moved == ("tests/test_service_a.py", "tests/test_service_b.py")
    # two services named by path: which one a root test belongs to is not a typed fact -> removed, never guessed
    out, _ = TL.plan_test_targets(["apps/service-a/main.py", "apps/service-b/main.py", "tests/test_x.py"], TWO)
    assert out == ["apps/service-a/main.py", "apps/service-b/main.py"]


def test_relocation_never_duplicates_an_existing_target():
    out, moved = TL.plan_test_targets(["apps/service-a/tests/test_api.py", "tests/test_api.py"], TWO)
    assert out == ["apps/service-a/tests/test_api.py"] and moved == ("tests/test_api.py",)


@pytest.mark.parametrize("services", [None, [], ["solo"], ["solo", "solo"], ("solo",)])
def test_single_service_plans_are_unchanged(services):
    """Negative: one service (or none) keeps root `tests/` (the layout rule's single-service case)."""
    targets = ["tests/test_main.py", "README.md", "apps/solo/main.py"]
    out, moved = TL.plan_test_targets(targets, services)
    assert out == targets and moved == () and out is not targets


@pytest.mark.parametrize("path, root", [
    ("tests/test_a.py", True), ("tests/sub/test_b.py", True), ("tests", False), ("apps/x/tests/test_a.py", False),
    ("tests_extra/test_a.py", False), ("./tests/test_a.py", False), ("tests/../x.py", False), ("tests//a.py", False),
    (None, False), (3, False)])
def test_root_test_path_is_an_exact_component_rule(path, root):
    assert TL.is_root_test_path(path) is root


def test_non_test_targets_are_kept_exactly():
    """Do no harm: entries other than root tests targets are never changed, reordered or deduplicated."""
    targets = ["README.md", "README.md", "infra/workload/main.tf", "apps/service-a/main.py"]
    out, moved = TL.plan_test_targets(targets, TWO)
    assert out == targets and moved == ()


# ============================================================================ A. the architect applies it
from test_architect_topology_gate import BASE, GOOD, _Client, architect  # noqa: E402,F401  (fixture reused)


def _plan_with_tests():
    return {**BASE, "service_topology": GOOD,
            "code_tasks": [
                {"task_id": "CODE-01", "category": "CODE", "target_files": ["apps/api/main.py", "tests/test_api.py"]},
                {"task_id": "CODE-03", "category": "CODE",
                 "target_files": ["tests/test_api.py", "tests/test_core.py", "README.md"]}],
            "sequenced_build_plan": {"steps": [
                {"step_id": "STEP-07-TESTS", "step_index": 1, "category": "TEST",
                 "target_files": ["tests/test_main.py", "README.md"]}]}}


def test_architect_multi_service_plan_has_no_root_tests_targets(architect):
    h, agent = architect
    agent.genai_client = _Client(_plan_with_tests())
    res = agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="t-1")
    by_id = {t.task_id: t.target_files for t in res.task_dag}
    assert by_id["CODE-01"] == ["apps/api/main.py", "apps/api/tests/test_api.py"]
    assert by_id["CODE-03"] == ["README.md"]
    assert [s.target_files for s in res.sequenced_build_plan.steps] == [["README.md"]]
    # the persisted compute record (the developer's input) is unchanged
    assert res.compute_intent["target_compute_services"] == ["api", "core"]


def test_architect_records_layout_changes_on_the_stage_trace_and_in_the_plan(architect, monkeypatch):
    """Red-team F3: a relocated or removed root tests/ target is visible on the architect stage trace and stated in
    the plan markdown, not only in an info log."""
    from unittest.mock import MagicMock as _MM
    h, agent = architect
    fs = _MM()
    agent.project_id = "p"
    monkeypatch.setattr(agent, "_firestore_client", lambda: fs)
    agent.genai_client = _Client(_plan_with_tests())
    res = agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="t-3")
    want = [{"kind": "task", "id": "CODE-01", "relocated": [["tests/test_api.py", "apps/api/tests/test_api.py"]],
             "removed": []},
            {"kind": "task", "id": "CODE-03", "relocated": [], "removed": ["tests/test_api.py", "tests/test_core.py"]},
            {"kind": "build_step", "id": "STEP-07-TESTS", "relocated": [], "removed": ["tests/test_main.py"]}]
    trace_set = fs.collection.return_value.document.return_value.collection.return_value.document.return_value.set
    payloads = [c.args[0] for c in trace_set.call_args_list if c.args and "stage_name" in c.args[0]]
    assert payloads and payloads[-1]["test_layout_changes"] == want
    md = res.plan_markdown
    assert "## Platform test layout" in md
    assert "- Task `CODE-01`: `tests/test_api.py` -> `apps/api/tests/test_api.py`" in md
    assert "- Task `CODE-03`: removed `tests/test_api.py`, `tests/test_core.py`" in md
    assert "- Build step `STEP-07-TESTS`: removed `tests/test_main.py`" in md


def test_architect_single_service_plan_has_no_layout_record(architect, monkeypatch):
    from unittest.mock import MagicMock as _MM
    h, agent = architect
    fs = _MM()
    agent.project_id = "p"
    monkeypatch.setattr(agent, "_firestore_client", lambda: fs)
    plan = _plan_with_tests()
    plan["target_compute_services"] = ["api"]
    plan["service_topology"] = {"services": [{"name": "api", "kind": "cloudrun"}], "primary_service": "api",
                                "edges": [], "resources": []}
    agent.genai_client = _Client(plan)
    res = agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="t-4")
    trace_set = fs.collection.return_value.document.return_value.collection.return_value.document.return_value.set
    # RT14-30: the stage trace owns the key; with no layout record it is cleared (DELETE_FIELD), never written
    from google.cloud.firestore_v1.transforms import DELETE_FIELD
    assert all(c.args[0].get("test_layout_changes", DELETE_FIELD) is DELETE_FIELD
               for c in trace_set.call_args_list if c.args)
    assert "Platform test layout" not in (res.plan_markdown or "")


def test_target_changes_record_relocations_and_removals():
    out, relocated, removed = TL.plan_test_target_changes(
        ["apps/service-a/main.py", "tests/test_a.py", "README.md"], TWO)
    assert out == ["apps/service-a/main.py", "apps/service-a/tests/test_a.py", "README.md"]
    assert relocated == (("tests/test_a.py", "apps/service-a/tests/test_a.py"),) and removed == ()
    assert TL.plan_test_target_changes(EX02_CODE03, TWO) == (["README.md"], (),
                                                             ("tests/test_service_a.py", "tests/test_service_b.py"))
    assert TL.plan_test_target_changes(EX02_CODE03, ["solo"]) == (EX02_CODE03, (), ())


def test_architect_single_service_plan_keeps_root_tests(architect):
    """Negative: a one-service topology leaves every target as the model wrote it."""
    h, agent = architect
    plan = _plan_with_tests()
    plan["target_compute_services"] = ["api"]
    plan["service_topology"] = {"services": [{"name": "api", "kind": "cloudrun"}], "primary_service": "api",
                                "edges": [], "resources": []}
    agent.genai_client = _Client(plan)
    res = agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="t-2")
    by_id = {t.task_id: t.target_files for t in res.task_dag}
    assert by_id["CODE-01"] == ["apps/api/main.py", "tests/test_api.py"]
    assert by_id["CODE-03"] == ["tests/test_api.py", "tests/test_core.py", "README.md"]
    assert [s.target_files for s in res.sequenced_build_plan.steps] == [["tests/test_main.py", "README.md"]]


# ============================================================================ A. the lead's plan-time check
from unittest.mock import MagicMock, patch  # noqa: E402

from developer_agent.lead_orchestrator import LeadDeveloperOrchestrator  # noqa: E402
from test_schemas_collision import _Models, plan_json, task  # noqa: E402

LEAD_TWO = ("svc-a", "svc-b")


def _lead(answers, services, cascade=("gemini-3.8-flash", "gemini-2.5-flash")):
    prompts = []
    client = MagicMock()
    client.models = _Models(answers, prompts)
    lead = LeadDeveloperOrchestrator(genai_client=client, model_name=cascade[0], db=None, project_id="")
    with patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent", return_value=list(cascade)):
        plan = lead.decompose_specification(product_id="svc-a", spec_text="x" * 2000, task_dag=[{}, {}],
                                            service_names=services)
    return plan, prompts


ROOT_TESTS_PLAN = plan_json(task("api", ["apps/svc-a/main.py"], wave=2),
                            task("qa", ["tests/test_api.py", "tests/conftest.py"], "TEST_ENGINEER", 3))
SVC_TESTS_PLAN = plan_json(task("api", ["apps/svc-a/main.py"], wave=2),
                           task("qa", ["apps/svc-a/tests/test_api.py"], "TEST_ENGINEER", 3))


def test_lead_plan_with_root_tests_in_a_multi_service_workload_is_reasked_with_the_exact_paths():
    plan, prompts = _lead([ROOT_TESTS_PLAN, SVC_TESTS_PLAN], LEAD_TWO)
    assert len(prompts) == 2
    assert prompts[1].endswith(TL.LEAD_TEST_LAYOUT_REASK.format(
        paths=json.dumps(["tests/conftest.py", "tests/test_api.py"])))
    assert [t.assigned_files for t in plan.tasks] == [["apps/svc-a/main.py"], ["apps/svc-a/tests/test_api.py"]]


def test_lead_plan_that_never_follows_the_layout_ends_in_the_deterministic_fallback():
    plan, prompts = _lead([ROOT_TESTS_PLAN, ROOT_TESTS_PLAN], LEAD_TWO)
    assert len(prompts) == 2 and TL.root_test_assignments(plan.tasks, LEAD_TWO) == []
    assert plan.tasks[0].task_id == "svc-a-w1-db"   # the deterministic fallback (tests under apps/<svc>/tests/)


@pytest.mark.parametrize("services", [(), ("svc-a",)])
def test_single_service_lead_plan_with_root_tests_is_accepted_unchanged(services):
    """Negative: one service (or none) keeps root `tests/`: no re-ask, the plan exactly as answered."""
    plan, prompts = _lead([ROOT_TESTS_PLAN], services)
    assert len(prompts) == 1 and "PY.TEST_LAYOUT" not in prompts[0]
    assert plan.tasks[1].assigned_files == ["tests/test_api.py", "tests/conftest.py"]


# ============================================================================ A. the QA fact
DAG03 = [{"task_id": "CODE-03", "category": "CODE", "target_files": EX02_CODE03},
         {"task_id": "CODE-01", "category": "CODE", "target_files": ["apps/service-a/main.py"]}]


def test_platform_facts_state_the_layout_rule_for_a_multi_service_workload():
    facts = ji.platform_facts_text("GITHUB", "generate", DAG03, test_layout_services=TWO)
    assert "- Test layout: this workload has 2 services (service-a, service-b)." in facts
    assert "`apps/service-a/tests/`, `apps/service-b/tests/`" in facts
    assert "never report the root `tests/` file as missing" in facts
    assert "  - Plan tasks with a target under root `tests/` (exact target path): CODE-03" in facts


@pytest.mark.parametrize("services", [None, [], ["solo"], ["a", "a"], "service-a,service-b", ["service-a", 3],
                                      ["Service A", "b"], ["ok", "bad\nname"], {"service-a": 1, "b": 2}])
def test_no_layout_fact_without_a_typed_multi_service_list(services):
    """Negative (fail closed): one service, malformed or unprintable list -> facts byte-identical to before."""
    before = ji.platform_facts_text("GITHUB", "generate", DAG03)
    assert ji.platform_facts_text("GITHUB", "generate", DAG03, test_layout_services=services) == before
    assert "Test layout" not in before


def test_files_block_describes_a_root_test_target_by_the_layout_rule_only_for_multi_service():
    head = {"apps/service-a/tests/test_service_a.py": "x", "README.md": "r"}
    multi = ji.build_judge_input({}, head, task_dag=DAG03, test_layout_services=TWO)
    assert f"- tests/test_service_a.py: {ji.LAYOUT_TARGET_STATE}" in multi.files
    single = ji.build_judge_input({}, head, task_dag=DAG03, test_layout_services=["solo"])
    plain = ji.build_judge_input({}, head, task_dag=DAG03)
    assert single.files == plain.files and "- tests/test_service_a.py: not in this commit at this exact path" \
        in plain.files
    assert multi.diff == plain.diff


def test_qa_tells_the_adherence_judge_the_layout_rule_from_the_developer_record(gw, monkeypatch):
    db, prompts = _db(), []
    db.docs["pipeline_executions/tr-1"]["stages"]["architect"]["details"]["task_dag"] = DAG03
    db.docs["pipeline_executions/tr-1"]["developer_compute_intent"] = {"service_names": TWO, "archetype": "cloudrun"}
    out = _run(gw, monkeypatch, _judge([], adh=1.0, prompts=prompts), db=db)
    assert out["passed"] is True
    (adh_prompt,) = [p for k, p in prompts if k == "adherence"]
    facts = adh_prompt.split("### PLATFORM FACTS", 1)[1].split("Sections marked UNTRUSTED", 1)[0]
    assert "- Test layout: this workload has 2 services (service-a, service-b)." in facts and "CODE-03" in facts
    assert ji.LAYOUT_TARGET_STATE in adh_prompt


def test_qa_without_a_developer_record_has_no_layout_fact(gw, monkeypatch):
    """Negative: no `developer_compute_intent` (or one service) -> the adherence prompt has no layout line."""
    for rec in (None, {"service_names": ["solo"]}, {"service_names": "service-a"}):
        db, prompts = _db(), []
        db.docs["pipeline_executions/tr-1"]["stages"]["architect"]["details"]["task_dag"] = DAG03
        if rec is not None:
            db.docs["pipeline_executions/tr-1"]["developer_compute_intent"] = rec
        _run(gw, monkeypatch, _judge([], adh=1.0, prompts=prompts), db=db)
        (adh_prompt,) = [p for k, p in prompts if k == "adherence"]
        assert "Test layout" not in adh_prompt and ji.LAYOUT_TARGET_STATE not in adh_prompt, rec


# ============================================================================ B. one platform-facts object, every lens
import hashlib  # noqa: E402
import importlib  # noqa: E402
import inspect  # noqa: E402
import pkgutil  # noqa: E402

import qa_auditor  # noqa: E402
import qa_auditor.coordinator as COORD  # noqa: E402
import qa_auditor.judge as judge_mod  # noqa: E402
from qa_auditor import platform_satisfied as PS  # noqa: E402
from qa_auditor import security_lens as SL  # noqa: E402
from qa_auditor import LensUnavailableError  # noqa: E402
from qa_auditor.platform_facts import PlatformFacts, build_platform_facts  # noqa: E402
from shared.qa_audit_schemas import AdherenceLensResult, SecurityLensResult  # noqa: E402

from test_adherence_platform_satisfied import (  # noqa: E402
    ADVISORY, CR_TREE, GKE_TREE, IAM, PUBLIC, _access_db, _run_tree)

SERVICES_TF = "infra/workload/services.tf"
DEPLOY_B = ".github/workflows/deploy-service-b.yml"
ORDERS = "apps/service-a/routers/orders.py"
B_TREE = {**CR_TREE, SERVICES_TF: 'module "compute_service_b" {\n  allow_unauthenticated = true\n}\n',
          DEPLOY_B: "name: deploy\n", ORDERS: "def reconcile(): pass\n"}
SVC_B_MSG = "module compute_service_b passes allow_unauthenticated = var.allow_unauthenticated: service-b is public"
WF_MSG = "deploy-service-b.yml runs gcloud run deploy service-b --allow-unauthenticated"
RECONCILE_MSG = "POST /api/v1/orders/reconcile does no caller verification before minting an OIDC token"
# sha256 of the security prompt / schema on main 43552421 (before this row) for the inputs of _sec_call below
MAIN_SEC_PROMPT_SHA = "350435499e84a9725d3cd7671b349375d6fb510170e5fba4ea4a74928b7d327f"
MAIN_SEC_SCHEMA_SHA = "afe526793e2cb460f0ff80bbe6ac73dde6503f1329984516a2b6a8b61355f97f"


def _sec_judge(crit, facets=None, files=None, *, passed=None, prompts=None, schemas=None):
    """Security judge reply with optional facet/file lists; adherence always clean."""
    def _call(prompt, model, **kw):
        if "Security Engineer" in prompt:
            if prompts is not None:
                prompts.append(prompt)
            if schemas is not None:
                schemas.append(kw.get("response_schema"))
            body = {"passed": (not crit) if passed is None else passed, "critical_vulnerabilities": crit}
            if facets is not None:
                body["critical_vulnerability_facets"] = facets
            if files is not None:
                body["critical_vulnerability_files"] = files
            return json.dumps(body)
        return json.dumps({"instruction_adherence_score": 1.0, "grounding_score": 1.0, "missed_directives": [],
                           "hallucinated_features": [], "summary": "s"})
    return _call


def _public_db():
    return _access_db(PUBLIC, public_decision=True, advisories=[dict(ADVISORY)])


def _sec(out):
    return [d for d in out["diagnostics"] if d["code"] == "JUDGE.SECURITY"]


def test_ex02_platform_access_findings_are_security_advisories_not_blocking(gw, monkeypatch):
    db, prompts, schemas = _public_db(), [], []
    judge = _sec_judge([SVC_B_MSG, WF_MSG], ["PER_SERVICE_ACCESS"] * 2, [SERVICES_TF, DEPLOY_B],
                       prompts=prompts, schemas=schemas)
    out = _run_tree(gw, monkeypatch, judge, B_TREE, db)
    assert out["passed"] is True and out["error_class"] is None and _sec(out) == []
    lens = db.docs["qa_test_runs/tr-1"]["security_lens"]
    assert lens["critical_vulnerabilities"] == [] and lens["passed"] is True
    adv = lens["platform_limitation_advisories"]
    assert [(a["finding"], a["facet"], a["file"]) for a in adv] == [
        (SVC_B_MSG, "PER_SERVICE_ACCESS", SERVICES_TF), (WF_MSG, "PER_SERVICE_ACCESS", DEPLOY_B)]
    assert all(a["known_limitation"] == PS.PER_SERVICE_ACCESS_LIMITATION for a in adv)
    assert adv[0]["access_advisory_services"] == ["core-processor"]
    # visible to the operator (invariant 8)
    assert "Documented platform limitation, not a code defect (advisory): PER_SERVICE_ACCESS" in out["summary"]
    assert "2 finding(s)" in out["summary"]
    # the judge was told, in the shared section, and asked for the typed facet
    (prompt,) = prompts
    assert "- Per-service access (facet PER_SERVICE_ACCESS): This workload is a Public app" in prompt
    assert '"critical_vulnerability_facets"' in prompt and "- Facets: for each entry" in prompt
    assert schemas[0]["properties"]["critical_vulnerability_facets"] == {
        "type": "ARRAY", "items": {"type": "STRING", "enum": ["PER_SERVICE_ACCESS", "OTHER"]}}
    assert schemas[0]["required"] == SL.SECURITY_RESPONSE_SCHEMA["required"]


@pytest.mark.parametrize("facets, files", [
    (["PER_SERVICE_ACCESS"], [ORDERS]),          # an application file: the app's own caller checks are judged
    (["PER_SERVICE_ACCESS"], [""]),              # no file named
    (["PER_SERVICE_ACCESS"], None),              # no file list
    (["PER_SERVICE_ACCESS"], ["infra/modules/compute-cloudrun/main.tf"]),   # not workload IaC or platform CI
    (["OTHER"], [SERVICES_TF]),
    (["BUDGET_CAP"], [SERVICES_TF]),             # not a security facet
    (["per_service_access"], [SERVICES_TF]),     # exact values only
    (None, [SERVICES_TF]),                       # no facet list
    (["PER_SERVICE_ACCESS", "OTHER"], [SERVICES_TF]),   # wrong length -> every finding OTHER
])
def test_security_findings_without_a_typed_handled_facet_on_a_platform_file_still_block(gw, monkeypatch, facets,
                                                                                        files):
    db = _public_db()
    out = _run_tree(gw, monkeypatch, _sec_judge([RECONCILE_MSG], facets, files), B_TREE, db)
    assert out["passed"] is False and out["error_class"] == "CODE_DEFECT"
    assert [d["message"] for d in _sec(out)] == [RECONCILE_MSG]
    assert db.docs["qa_test_runs/tr-1"]["security_lens"]["platform_limitation_advisories"] == []
    assert "Documented platform limitation" not in out["summary"]


def test_a_handled_finding_beside_a_real_one_keeps_the_real_one_blocking(gw, monkeypatch):
    db = _public_db()
    out = _run_tree(gw, monkeypatch, _sec_judge([SVC_B_MSG, RECONCILE_MSG], ["PER_SERVICE_ACCESS", "OTHER"],
                                                [SERVICES_TF, ORDERS]), B_TREE, db)
    assert out["passed"] is False
    assert [(d["message"], d["file"]) for d in _sec(out)] == [(RECONCILE_MSG, ORDERS)]   # routed to its own file
    lens = db.docs["qa_test_runs/tr-1"]["security_lens"]
    assert [a["finding"] for a in lens["platform_limitation_advisories"]] == [SVC_B_MSG]
    assert lens["critical_vulnerability_files"] == [ORDERS]


@pytest.mark.parametrize("access, public, tree", [
    (IAM, False, B_TREE),                                          # a private mode
    (PUBLIC, True, {**GKE_TREE, SERVICES_TF: B_TREE[SERVICES_TF]}),   # a Public app without the golden Cloud Run module
])
def test_without_the_per_service_handling_the_finding_blocks_and_gets_no_facet_field(gw, monkeypatch, access, public,
                                                                                     tree):
    """Negative: without the PER_SERVICE_ACCESS handling (a private mode, or no Cloud Run module) an `allUsers`
    finding on services.tf is a real defect: it blocks, and the security prompt carries no facet field or rubric."""
    db, prompts, schemas = _access_db(access, public_decision=public), [], []
    out = _run_tree(gw, monkeypatch, _sec_judge([SVC_B_MSG], ["PER_SERVICE_ACCESS"], [SERVICES_TF],
                                                prompts=prompts, schemas=schemas), tree, db)
    assert out["passed"] is False and [d["file"] for d in _sec(out)] == [SERVICES_TF]
    assert "critical_vulnerability_facets" not in prompts[0] and "- Facets:" not in prompts[0]
    assert schemas[0] is SL.SECURITY_RESPONSE_SCHEMA


def test_judge_passed_false_with_no_finding_still_fails(monkeypatch):
    pf = build_platform_facts(None, "off", [], platform_handled=PS.platform_handlings(
        {}, ingress_policy={"access_mode": "PUBLIC_APP", "allow_unauthenticated": True}, deploys_cloud_run=True),
        committed_paths=[SERVICES_TF])
    monkeypatch.setattr(judge_mod, "call", _sec_judge([], passed=False))
    # JUDGE-GATE-ENUMERATED-FINDINGS: passed=false with nothing listed contradicts the reply contract -> no verdict
    with pytest.raises(LensUnavailableError):
        SL.evaluate_security_lens("+x", model_name="m", platform_facts=pf)
    monkeypatch.setattr(judge_mod, "call", _sec_judge([SVC_B_MSG], ["PER_SERVICE_ACCESS"], [SERVICES_TF],
                                                      passed=False))
    res = SL.evaluate_security_lens("+x", model_name="m", platform_facts=pf)
    assert res.passed is True and len(res.platform_limitation_advisories) == 1


def _sec_call(monkeypatch, platform_facts):
    seen = {}

    def fake(prompt, model, **k):
        seen["prompt"], seen["schema"] = prompt, k.get("response_schema")
        return json.dumps({"passed": True, "critical_vulnerabilities": []})

    monkeypatch.setattr(judge_mod, "call", fake)
    monkeypatch.setattr(judge_mod, "untrusted_block", lambda label, content: f"<<{label}>>{content}<</{label}>>")
    SL.evaluate_security_lens("diff --git a/x b/x", ingress_policy={"access_mode": "PUBLIC_APP",
                                                                    "allow_unauthenticated": True},
                              model_name="m", file_inventory="x", platform_facts=platform_facts)
    return seen


def test_security_prompt_and_schema_without_facts_are_byte_identical_to_main(monkeypatch):
    seen = _sec_call(monkeypatch, None)
    assert hashlib.sha256(seen["prompt"].encode()).hexdigest() == MAIN_SEC_PROMPT_SHA
    assert seen["schema"] is SL.SECURITY_RESPONSE_SCHEMA
    assert hashlib.sha256(json.dumps(seen["schema"], sort_keys=True).encode()).hexdigest() == MAIN_SEC_SCHEMA_SHA


def test_security_prompt_with_facts_but_no_security_facet_adds_only_the_shared_section(monkeypatch):
    """Negative: a facts object whose handled facets are not security facets (budget cap) adds the shared PLATFORM
    FACTS section and nothing else: same schema object, no facet rubric."""
    pf = build_platform_facts("GITHUB", "generate", [],
                              platform_handled=PS.platform_handlings({"budget_ceiling_monthly_usd": 10.0}))
    with_facts = _sec_call(monkeypatch, pf)
    without = _sec_call(monkeypatch, None)
    assert with_facts["schema"] is SL.SECURITY_RESPONSE_SCHEMA
    assert with_facts["prompt"].replace(pf.section(), "") == without["prompt"]


# ---------------------------------------------------------------------------- B. the missing-consumer guard
def _is_lens_result(tp):
    """A lens verdict model: a pydantic model with a `lens_name` field (SecurityLensResult, AdherenceLensResult and
    any future lens's result)."""
    from pydantic import BaseModel
    return isinstance(tp, type) and issubclass(tp, BaseModel) and "lens_name" in tp.model_fields


def _lens_functions():
    """RT F5: every lens entry point of the qa_auditor package, found by type, not by name: a public module-level
    function of any qa_auditor module (defined there) whose return type is a lens verdict model. Private functions
    are not entry points (the FD-4F legacy heuristics are `_`-prefixed test-compat helpers that are never a verdict
    source; tests/test_fd4f_dual_lens_fail_closed.py proves no lens calls them)."""
    import typing

    found = {}
    for info in pkgutil.iter_modules(qa_auditor.__path__):
        mod = importlib.import_module(f"qa_auditor.{info.name}")
        for name, fn in inspect.getmembers(mod, inspect.isfunction):
            if fn.__module__ != mod.__name__ or name.startswith("_"):
                continue
            try:
                ret = typing.get_type_hints(fn).get("return")
            except Exception:  # noqa: BLE001 - an unresolvable annotation is not a lens return type
                ret = None
            if _is_lens_result(ret):
                found[f"{info.name}.{name}"] = fn
    return found


def test_lens_discovery_is_structural():
    """RT F5: discovery does not depend on the function name: a function of any name returning a lens result is
    found, and the two lenses of today are found by their return type."""
    import typing

    found = _lens_functions()
    assert {fn.__name__ for fn in found.values()} >= {"evaluate_security_lens", "evaluate_adherence_lens"}

    def judge_something(git_diff: str) -> SecurityLensResult:   # a lens with another name
        return SecurityLensResult()

    assert _is_lens_result(typing.get_type_hints(judge_something)["return"])
    assert not _is_lens_result(dict) and not _is_lens_result(None)


def test_platform_facts_object_is_immutable():
    """RT F4: the one object every lens thread shares cannot be changed after it is built."""
    import dataclasses

    source = PS.platform_handlings({"budget_ceiling_monthly_usd": 10.0})
    pf = build_platform_facts("GITHUB", "off", [], platform_handled=source, committed_paths=[SERVICES_TF])
    with pytest.raises(TypeError):
        pf.handled["PER_SERVICE_ACCESS"] = source["BUDGET_CAP"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        pf.text = "forged"
    source.clear()                                   # the caller's dict is copied, not shared
    assert list(pf.handled) == ["BUDGET_CAP"] and isinstance(pf.platform_rendered_paths, frozenset)
    direct = PlatformFacts(text="- x", handled={"BUDGET_CAP": pf.handled["BUDGET_CAP"]})
    with pytest.raises(TypeError):
        direct.handled["X"] = None


def test_every_qa_lens_takes_the_platform_facts_object():
    lenses = _lens_functions()
    assert len(lenses) >= 2
    for name, fn in lenses.items():
        assert "platform_facts" in inspect.signature(fn).parameters, f"{name} does not consume PlatformFacts"


def test_the_coordinator_gives_the_same_facts_object_to_every_lens(monkeypatch):
    import typing

    seen = {}

    def spy(attr, result):
        def _fn(**kw):
            seen[attr] = kw.get("platform_facts")
            return result
        return _fn

    lenses = set(_lens_functions().values())
    # the coordinator's references to lens functions, by identity (not by name)
    used = {attr: fn for attr, fn in vars(COORD).items() if inspect.isfunction(fn) and fn in lenses}
    assert set(used.values()) == lenses, "a lens of qa_auditor is not run by the coordinator"
    for attr, fn in used.items():
        monkeypatch.setattr(COORD, attr, spy(attr, typing.get_type_hints(fn)["return"](passed=True)))
    pf = build_platform_facts("GITHUB", "off", [])
    COORD.DualLensAuditorCoordinator(timeout_seconds=5).evaluate_stage_two(
        git_diff="+x", determ_report={"passed": True, "summary": "ok"}, task_dag=[{"task_id": "t"}],
        platform_facts=pf)
    assert set(seen) == set(used) and all(v is pf for v in seen.values())


def test_the_coordinator_refuses_to_run_a_lens_without_the_facts_object(monkeypatch):
    monkeypatch.setattr(judge_mod, "call", lambda *a, **k: pytest.fail("a judge ran without platform facts"))
    kw = dict(git_diff="+x", determ_report={"passed": True, "summary": "ok"}, task_dag=[{"task_id": "t"}])
    with pytest.raises(TypeError):
        COORD.DualLensAuditorCoordinator(timeout_seconds=5).evaluate_stage_two(**kw)
    for bad in (None, "- a fact", {"text": "x"}):
        with pytest.raises(qa_auditor.LensUnavailableError, match="platform facts"):
            COORD.DualLensAuditorCoordinator(timeout_seconds=5).evaluate_stage_two(platform_facts=bad, **kw)


def test_every_judge_call_of_stage_two_carries_the_facts_section(monkeypatch):
    """RT F5, the general rule: every judge call made while the coordinator runs Stage 2 (one per lens, whatever the
    lenses are) carries the one facts object's rendering and every line of it."""
    prompts = []
    monkeypatch.setattr(judge_mod, "call", lambda p, m, **k: prompts.append(p) or _sec_judge([])(p, m))
    pf = build_platform_facts("GITHUB", "generate", DAG03, test_layout_services=TWO,
                              platform_handled=PS.platform_handlings(
                                  {"budget_ceiling_monthly_usd": 5.0},
                                  ingress_policy={"access_mode": "PUBLIC_APP", "allow_unauthenticated": True},
                                  deploys_cloud_run=True))
    COORD.DualLensAuditorCoordinator(timeout_seconds=5).evaluate_stage_two(
        git_diff="+x", determ_report={"passed": True, "summary": "ok"}, task_dag=DAG03, platform_facts=pf)
    assert len(prompts) == len(_lens_functions()) and all(pf.section() in p for p in prompts)
    for line in pf.text.split("\n"):
        assert all(line in p for p in prompts), line


def test_release_certificate_lists_the_security_advisories(gw, monkeypatch):
    from release_gatekeeper import evaluate_release_decision

    db = _public_db()
    _run_tree(gw, monkeypatch, _sec_judge([SVC_B_MSG], ["PER_SERVICE_ACCESS"], [SERVICES_TF]), B_TREE, db)
    doc = db.docs["qa_test_runs/tr-1"]
    dec = evaluate_release_decision({"passed": True}, doc["security_lens"], doc["adherence_lens"],
                                    {"require_human_code_review": True})
    assert dec.security_clean is True and dec.blocking_reasons == []
    assert "0 critical defects; platform-handled, not code defects: PER_SERVICE_ACCESS x1" \
        in dec.release_certificate_markdown


# ---------------------------------------------------------------------------- RT F2: the CI path rule
@pytest.mark.parametrize("path, ci", [
    (".github/workflows/deploy-service-b.yml", True), ("cloudbuild.yaml", True),
    (".github/workflows/../../apps/svc/main.py", False), (".github/workflows/./deploy.yml", False),
    (".github/workflows//deploy.yml", False), (".github/workflows/", False), ("./cloudbuild.yaml", False),
    (".github/workflows", False), ("apps/svc/cloudbuild.yaml", False), (None, False), (3, False)])
def test_platform_ci_path_is_an_exact_component_rule(path, ci):
    assert ji.is_platform_ci_path(path) is ci


def test_traversal_through_the_ci_directory_never_makes_a_security_advisory(gw, monkeypatch):
    db = _public_db()
    out = _run_tree(gw, monkeypatch, _sec_judge([RECONCILE_MSG], ["PER_SERVICE_ACCESS"],
                                                [".github/workflows/../../apps/service-a/routers/orders.py"]),
                    B_TREE, db)
    assert out["passed"] is False and [d["message"] for d in _sec(out)] == [RECONCILE_MSG]
    assert db.docs["qa_test_runs/tr-1"]["security_lens"]["platform_limitation_advisories"] == []


# ---------------------------------------------------------------------------- RT F1: platform-rendered, not directory
PII_MSG = "google_storage_bucket_iam_member grants allUsers objectViewer on the PII bucket"
WORKLOAD_FILES = {"infra/workload/custom.tf": 'resource "x" "y" {}\n', "infra/workload/iac_intent.json": "{}\n",
                  "infra/workload/custom.tf.json": "{}\n", "infra/workload/human.tf": 'resource "h" "h" {}\n',
                  "infra/workload/modules/x/main.tf": 'resource "m" "m" {}\n'}
F1_TREE = {**B_TREE, **WORKLOAD_FILES}


def test_platform_rendered_paths_are_exact_platform_writes_of_the_commit():
    committed = list(F1_TREE) + ["cloudbuild.yaml", "infra/workload/terraform.tfvars", "infra/workload/main.tf"]
    got = ji.platform_rendered_paths(committed)
    assert {SERVICES_TF, DEPLOY_B, "cloudbuild.yaml", "infra/workload/terraform.tfvars",
            "infra/workload/main.tf"} <= got
    assert not got & set(WORKLOAD_FILES)            # AI documents, AI / person HCL and modules are never in it
    assert not got & {ORDERS, "apps/admin/main.py"}
    assert "infra/workload/variables.tf" not in got   # a platform path that is not in the commit
    assert ji.platform_rendered_paths([]) == frozenset()


@pytest.mark.parametrize("named, tree", [
    ("infra/workload/custom.tf", F1_TREE),                  # the AI's own HCL
    ("infra/workload/iac_intent.json", F1_TREE),            # the AI's typed document
    ("infra/workload/custom.tf.json", F1_TREE),             # rendered from the AI's document
    ("infra/workload/human.tf", F1_TREE),                   # a person's file
    ("infra/workload/modules/x/main.tf", F1_TREE),          # a module under the workload root
    ("infra/workload/does_not_exist.tf", F1_TREE),          # not in the commit
    (SERVICES_TF, {k: v for k, v in F1_TREE.items() if k != SERVICES_TF}),   # platform path, not in the commit
    (DEPLOY_B, {k: v for k, v in F1_TREE.items() if k != DEPLOY_B}),
    (".github/workflows/../../apps/svc/main.py", F1_TREE),  # traversal (F2)
])
def test_per_service_label_on_a_file_the_platform_did_not_write_still_blocks(gw, monkeypatch, named, tree):
    db = _public_db()
    out = _run_tree(gw, monkeypatch, _sec_judge([PII_MSG], ["PER_SERVICE_ACCESS"], [named]), tree, db)
    assert out["passed"] is False and [d["message"] for d in _sec(out)] == [PII_MSG]
    assert db.docs["qa_test_runs/tr-1"]["security_lens"]["platform_limitation_advisories"] == []


@pytest.mark.parametrize("named", [SERVICES_TF, DEPLOY_B])
def test_ex02_platform_files_still_qualify_beside_ai_files(gw, monkeypatch, named):
    db = _public_db()
    out = _run_tree(gw, monkeypatch, _sec_judge([SVC_B_MSG], ["PER_SERVICE_ACCESS"], [named]), F1_TREE, db)
    assert out["passed"] is True
    assert [a["file"] for a in db.docs["qa_test_runs/tr-1"]["security_lens"]["platform_limitation_advisories"]] \
        == [named]


def _adh_judge(missed, facets, files, task_ids):
    def _call(prompt, model, **kw):
        if "Security Engineer" in prompt:
            return json.dumps({"passed": True, "critical_vulnerabilities": []})
        return json.dumps({"instruction_adherence_score": 0.85, "grounding_score": 1.0, "missed_directives": missed,
                           "missed_directive_facets": facets, "missed_directive_files": files,
                           "missed_directive_task_ids": task_ids, "hallucinated_features": [], "summary": "s"})
    return _call


@pytest.mark.parametrize("named, handled", [
    (SERVICES_TF, True),                                    # platform-rendered, committed
    ("infra/workload/custom.tf", False), ("infra/workload/iac_intent.json", False),
    ("infra/workload/human.tf", False), ("infra/workload/does_not_exist.tf", False),
])
def test_adherence_limitation_without_a_task_needs_a_platform_rendered_file(gw, monkeypatch, named, handled):
    """RT F1 applied to the adherence lens for documented LIMITATIONS (PER_SERVICE_ACCESS). SATISFIED facets keep the
    workload-IaC rule (test_adherence_platform_satisfied: BUDGET_CAP naming iac_intent.json stays handled)."""
    db = _public_db()
    out = _run_tree(gw, monkeypatch, _adh_judge([SVC_B_MSG], ["PER_SERVICE_ACCESS"], [named], [""]), F1_TREE, db)
    assert out["passed"] is handled
    lims = db.docs["qa_test_runs/tr-1"]["adherence_lens"]["platform_limitation_advisories"]
    assert (len(lims) == 1) is handled
