"""QA-JUDGE-FILE-MAPPING: a Stage 2 adherence finding goes to the exact file the judge names (typed field
`missed_directive_files`), never to an arbitrary file of its task; a finding with no resolvable file stays file-less;
a finding on the platform's own runtime pin (`.python-version`) is never a repair seed and the judge is told the pin.

Live case (testplan01-e2, 10-30): the judge reported ".python-version was set to 3.13 instead of the mandated 3.11 in
apps/testplan01-e2/.python-version" and a /health directive. Both were attributed to a task whose FIRST committed
target file was `requirements.txt`, so the gateway routed them there (QA-JUDGE-FINGERPRINT's first-target rule), the
QA repair offered `requirements.txt` and stopped "repair budget exhausted (ITERATIONS)".

Hermetic: fake judge, FakeDB, fake source backend, fake QA job, fake LLM.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
from unittest.mock import MagicMock, patch

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import SHA_A, SHA_B, FakeBackend, FakeDB, FakeQAClient, backend_factory, passing_outcome, seed_context
from test_qa_feedback import (MAIN, _block_parts, _develop, _feedback, _first_build, _qa_diag,  # noqa: E402
                              _section, FIXED)

import qa_auditor.judge as judge_mod  # noqa: E402
from developer_agent import qa_repair as QR  # noqa: E402
from developer_agent import runtime_pin as RP  # noqa: E402
from qa_auditor import adherence_lens as AL  # noqa: E402
from qa_auditor import judge_input as ji  # noqa: E402

BRANCH = "castor/app-1"
SVC = "apps/testplan01-e2"
PYV, REQ, PROC, APPMAIN = f"{SVC}/.python-version", f"{SVC}/requirements.txt", f"{SVC}/Procfile", f"{SVC}/main.py"
TEST = "tests/test_main.py"
# the e2 shape: one plan task names the service's packaging files and its code, requirements.txt first
DAG = [
    {"task_id": "CODE-01", "category": "CODE", "target_files": [REQ, PROC, PYV, APPMAIN]},
    {"task_id": "TEST-01", "category": "TEST", "target_files": [TEST]},
    {"task_id": "DOC-01", "category": "CODE", "target_files": ["README.md"]},
]
E2_TREE = {APPMAIN: "from fastapi import FastAPI\napp = FastAPI()\n", REQ: "fastapi>=0.110.0\n",
           PROC: "web: uvicorn main:app\n", PYV: "3.13\n", ".python-version": "3.13\n", TEST: "def test(): pass\n"}
PYV_MSG = f".python-version was set to 3.13 instead of the mandated 3.11 in {PYV}"
HEALTH_MSG = "GET /health returns {'ok': true} instead of the mandated status/service/engine body"


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


@pytest.fixture()
def gw(monkeypatch):
    mod = fd4f_support.load_gateway(monkeypatch, "qa_jfm_gw")
    yield mod
    mod.app.dependency_overrides.clear()


def _judge(missed, task_ids=None, files=None, adh=0.5, prompts=None):
    def _call(prompt, model, **kw):
        if "Security Engineer" in prompt:
            return json.dumps({"passed": True, "critical_vulnerabilities": []})
        if prompts is not None:
            prompts.append(prompt)
        body = {"instruction_adherence_score": adh, "grounding_score": 1.0, "missed_directives": missed,
                "hallucinated_features": [], "summary": "a"}
        if task_ids is not None:
            body["missed_directive_task_ids"] = task_ids
        if files is not None:
            body["missed_directive_files"] = files
        return json.dumps(body)
    return _call


def _db():
    db = FakeDB()
    seed_context(db)
    db.docs["pipeline_executions/tr-1"]["stages"]["architect"]["details"]["task_dag"] = DAG
    return db


def _run(gw, monkeypatch, *, missed, task_ids=None, files=None, adh=0.5, tree=None, db=None, prompts=None):
    monkeypatch.setattr(judge_mod, "call", _judge(missed, task_ids, files, adh, prompts))
    head = {p: t.encode() for p, t in (E2_TREE if tree is None else tree).items()}
    backend = FakeBackend({BRANCH: head, "main": {}}, {BRANCH: SHA_A, "main": SHA_B})
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name=BRANCH, attempt=0)
    return gw.run_qa(req, client=FakeQAClient(passing_outcome()), source_backend_factory=backend_factory(backend),
                     evidence_db=db if db is not None else _db())


def _adh(out):
    return [d for d in out["diagnostics"] if d["code"] == "JUDGE.ADHERENCE"]


# ============================================================================ gateway: the e2 shape
def test_e2_finding_naming_python_version_is_routed_to_that_exact_file(gw, monkeypatch):
    out = _run(gw, monkeypatch, missed=[PYV_MSG, HEALTH_MSG], task_ids=["CODE-01", "CODE-01"], files=[PYV, APPMAIN])
    assert [(d["file"], d["task_id"]) for d in _adh(out)] == [(PYV, "CODE-01"), (APPMAIN, "CODE-01")]
    assert all(d["file"] != REQ for d in out["diagnostics"])
    assert out["passed"] is False and out["reason"] == "STAGE2_FAILED"   # routing never changes the verdict


def test_e2_reply_without_typed_files_is_no_longer_pinned_to_the_tasks_first_file(gw, monkeypatch):
    """The live reply shape (task ids only): the task has four committed targets, so no file is chosen (before: the
    first, requirements.txt)."""
    out = _run(gw, monkeypatch, missed=[PYV_MSG, HEALTH_MSG], task_ids=["CODE-01", "CODE-01"])
    assert [(d["file"], d["task_id"]) for d in _adh(out)] == [(None, "CODE-01"), (None, "CODE-01")]


@pytest.mark.parametrize("task_ids,files,expected", [
    # the typed path wins over the task, and needs no task
    (["TEST-01"], [APPMAIN], [APPMAIN]),
    ([""], [PYV], [PYV]),
    (None, [PROC], [PROC]),
    # a typed path that is not exactly a committed path names nothing: the task's single committed target, else none
    (["TEST-01"], ["apps/testplan01-e2/routes.py"], [TEST]),
    (["CODE-01"], ["apps/testplan01-e2/routes.py"], [None]),
    ([""], ["./" + APPMAIN], [None]),
    ([""], [APPMAIN.upper()], [None]),
    # a task whose only target is not committed, or an unknown task: none (as before)
    (["DOC-01"], [""], [None]),
    (["NOPE"], [""], [None]),
])
def test_typed_path_then_single_task_target_then_no_file(gw, monkeypatch, task_ids, files, expected):
    out = _run(gw, monkeypatch, missed=["a directive"], task_ids=task_ids, files=files)
    assert [d["file"] for d in _adh(out)] == expected


@pytest.mark.parametrize("files", [None, [PYV], PYV, [1, 2], [PYV, None]])
def test_unusable_file_list_names_nothing(gw, monkeypatch, files):
    """Wrong type or length: no file is named; the task rule alone applies (CODE-01 has several targets: none)."""
    out = _run(gw, monkeypatch, missed=["a", "b"], task_ids=["CODE-01", "TEST-01"], files=files)
    assert [d["file"] for d in _adh(out)] == [None, TEST]


def test_score_summary_is_not_a_finding_next_to_concrete_directives(gw, monkeypatch):
    """The live 3 blocking defects = 1 score line + 2 directives: only the 2 directives are findings (seedable).
    JUDGE-GATE-ENUMERATED-FINDINGS: the score is no blocking reason at all any more; it is informational summary
    text."""
    db = _db()
    out = _run(gw, monkeypatch, missed=[PYV_MSG, HEALTH_MSG], task_ids=["CODE-01", "CODE-01"], files=[PYV, APPMAIN],
               adh=0.90, db=db)
    assert [d["message"] for d in out["diagnostics"]] == [PYV_MSG, HEALTH_MSG]
    audit = db.docs["qa_test_runs/tr-1"]["composite_audit"]
    assert audit["blocking_reasons"] == [f"Missed Directive: {PYV_MSG}", f"Missed Directive: {HEALTH_MSG}"]
    assert "Adherence score 0.90, grounding score 1.00 (below 0.95): informational" in audit["summary"]


def test_score_only_answer_is_no_finding(gw, monkeypatch):
    """JUDGE-GATE-ENUMERATED-FINDINGS (was: a score-only failure is one file-less finding): a low score with nothing
    listed passes; no repair seed."""
    out = _run(gw, monkeypatch, missed=[], task_ids=[], files=[], adh=0.85)   # F1: from the 0.80 floor up
    assert out["passed"] is True and _adh(out) == []


def test_typed_files_are_kept_in_the_evidence_and_the_shared_schema_is_unchanged(gw, monkeypatch):
    db = _db()
    _run(gw, monkeypatch, missed=["a", "b"], task_ids=["CODE-01", ""], files=[PYV, ""], db=db)
    doc = db.docs["qa_test_runs/tr-1"]
    assert doc["adherence_lens"]["missed_directive_files"] == [PYV, None]
    assert "missed_directive_files" not in doc["composite_audit"]["adherence_lens"]


def test_fingerprint_follows_the_routed_file(gw, monkeypatch):
    """JUDGE-GATE-ENUMERATED-FINDINGS (replaces RT F4's "ignores the routed file"): the fingerprint is the typed repair
    seed, so the same finding routed to a file and to none are different seeds; the same routing matches."""
    typed = _adh(_run(gw, monkeypatch, missed=[PYV_MSG], task_ids=["CODE-01"], files=[PYV]))
    untyped = _adh(_run(gw, monkeypatch, missed=[PYV_MSG], task_ids=["CODE-01"]))
    reworded = _adh(_run(gw, monkeypatch, missed=["the runtime pin is wrong"], task_ids=["CODE-01"], files=[PYV]))
    assert typed[0]["file"] == PYV and untyped[0]["file"] is None
    assert typed[0]["fingerprint"] != untyped[0]["fingerprint"]
    assert typed[0]["fingerprint"] == reworded[0]["fingerprint"]


# ============================================================================ gateway: the runtime-pin fact
@pytest.mark.parametrize("tree,told", [
    (E2_TREE, True),
    ({p: t for p, t in E2_TREE.items() if p != PYV}, True),                         # the root pin alone
    ({p: ("3.11\n" if p.endswith(".python-version") else t) for p, t in E2_TREE.items()}, False),
    ({p: t for p, t in E2_TREE.items() if not p.endswith(".python-version")}, False),
])
def test_the_adherence_judge_is_told_the_runtime_pin_only_when_the_commit_holds_it(gw, monkeypatch, tree, told):
    prompts = []
    _run(gw, monkeypatch, missed=[], adh=1.0, tree=tree, prompts=prompts)
    (prompt,) = prompts
    facts = prompt.split("### PLATFORM FACTS", 1)[1].split("Sections marked UNTRUSTED", 1)[0]
    assert ("- Python runtime: the platform itself writes `.python-version` containing `3.13`" in facts) is told


def test_platform_facts_without_a_pin_are_byte_identical():
    base = ji.platform_facts_text("GITHUB", "off", DAG)
    assert ji.platform_facts_text("GITHUB", "off", DAG, python_runtime_pin=None) == base
    pinned = ji.platform_facts_text("GITHUB", "off", DAG, python_runtime_pin="3.13")
    lines = pinned.split("\n")
    assert lines[:2] == base.split("\n")[:2] and lines[2].startswith("- Python runtime:") and "`3.13`" in lines[2]
    assert "\n".join(lines[:2] + lines[3:]) == base


# ============================================================================ adherence lens: the typed field
@pytest.mark.parametrize("raw,expected", [
    ([PYV, ""], [PYV, None]),
    (None, [None, None]),
    ([PYV], [None, None]),
    (PYV, [None, None]),
    ([PYV, 3], [None, None]),
])
def test_directive_files_are_exact_or_nothing(raw, expected):
    data = {} if raw is None else {"missed_directive_files": raw}
    assert AL._directive_files(data, ["a", "b"]) == expected


def test_prompt_and_schema_ask_for_files_optionally():
    assert '"missed_directive_files"' in AL.ADHERENCE_AUDITOR_PROMPT_TEMPLATE
    field = AL.ADHERENCE_AUDITOR_PROMPT_TEMPLATE.split('"missed_directive_files"', 1)[1].split("\n", 1)[0]
    assert "exact repository path" in field and "empty string" in field
    assert "FILES UNDER AUDIT" not in field   # the FILES section is optional (test_qa_stage2_input)
    assert "missed_directive_files" in AL.ADHERENCE_RESPONSE_SCHEMA["properties"]
    assert "missed_directive_files" not in AL.ADHERENCE_RESPONSE_SCHEMA["required"]


# ============================================================================ runtime pin: one value with the developer
@pytest.mark.parametrize("path,pin", [
    (".python-version", True), ("apps/svc/.python-version", True),
    ("apps/.python-version", False), ("apps//.python-version", False), ("apps/svc/sub/.python-version", False),
    ("svc/.python-version", False), ("apps/svc/python-version", False), ("apps/svc/.python-version.bak", False),
    (None, False),
])
def test_pin_paths_are_exact(path, pin):
    assert RP.is_runtime_pin_path(path) is pin
    assert RP.is_platform_runtime_pin(path, "3.13\n") is pin
    assert RP.is_platform_runtime_pin(path, "3.11\n") is False and RP.is_platform_runtime_pin(path, "3.13") is False


def test_the_pin_is_exactly_what_the_container_contract_writes():
    from developer_agent.handler import enforce_container_contract
    files = {"apps/svc/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
             "apps/svc/requirements.txt": "fastapi\n", "apps/svc/.python-version": "3.11\n"}
    enforce_container_contract(files, "svc")
    assert files["apps/svc/.python-version"] == files[".python-version"] == RP.PLATFORM_PYTHON_VERSION_CONTENT
    assert RP.platform_runtime_pins(files) == [".python-version", "apps/svc/.python-version"]
    assert RP.PLATFORM_PYTHON_VERSION_CONTENT == RP.PLATFORM_PYTHON_VERSION + "\n"


# ============================================================================ developer: the QA repair plan
def _jd(file, message="a directive", code="JUDGE.ADHERENCE"):
    return {"tool": "judge", "code": code, "severity": "error", "file": file, "line": None, "message": message,
            "detail": None, "source": "qa", "iteration": 0, "fingerprint": "f" * 64, QR.JUDGE_FINDING_FIELD: True}


def _plan(tree, *diags):
    return QR.plan_qa_repair(_feedback(tree, *diags), stack_configured=True)


def test_e2_plan_repairs_the_named_code_file_and_carries_the_pin_finding_as_text():
    plan = _plan(E2_TREE, _jd(PYV, PYV_MSG), _jd(APPMAIN, HEALTH_MSG))
    assert (plan.mode, plan.reason, plan.findings) == (QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES", 2)
    assert plan.repairable_paths == {APPMAIN} and REQ not in plan.seed_files
    assert [(s.code, s.file) for s in plan.seeds] == [("JUDGE.ADHERENCE", APPMAIN)]
    assert "QA TEST OUTPUT finding 2" in plan.seeds[0].message                # numbering of the QA block kept
    _token, content = _block_parts(plan.untrusted_output)
    assert PYV_MSG in content and HEALTH_MSG in content


def test_a_python_version_the_platform_did_not_pin_is_offered_for_repair():
    tree = dict(E2_TREE, **{PYV: "3.12\n"})
    plan = _plan(tree, _jd(PYV, PYV_MSG))
    assert (plan.mode, plan.repairable_paths) == (QR.QA_REPAIR, {PYV})
    assert plan.seed_files == {PYV: "3.12\n"}


@pytest.mark.parametrize("diags,mode,reason", [
    # PLATFORM-RENDERED-FINDING (owner 11-13; was REGENERATE FINDING_ON_A_PLATFORM_PINNED_FILE): a pin is
    # platform-rendered, so a finding that would force a regeneration on it is a typed stop
    ([_jd(PYV, PYV_MSG)], QR.STOP, QR.PLATFORM_RENDERED_REASON),                          # nothing else to repair
    ([_jd(".python-version", PYV_MSG)], QR.STOP, QR.PLATFORM_RENDERED_REASON),
    ([_qa_diag(file=PYV)], QR.STOP, QR.PLATFORM_RENDERED_REASON),                         # a sandbox one: no seed
    ([_jd(PYV, PYV_MSG), _jd(None), _jd(APPMAIN)], QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE"),   # rides along
])
def test_pinned_findings_never_become_seeds(diags, mode, reason):
    plan = _plan(E2_TREE, *diags)
    assert (plan.mode, plan.reason) == (mode, reason) and not plan.seeds


def test_a_sandbox_finding_with_a_pinned_judge_finding_repairs_the_sandbox_file():
    plan = _plan(E2_TREE, _qa_diag(file=APPMAIN), _jd(PYV, PYV_MSG))
    assert (plan.mode, plan.repairable_paths) == (QR.QA_REPAIR, {APPMAIN})


# Do No Harm: every pre-existing plan shape (no pinned file named) decides exactly as before
@pytest.mark.parametrize("diags,mode,reason,seed_files", [
    ([_qa_diag(file=APPMAIN)], QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES", [APPMAIN]),
    ([_jd(APPMAIN)], QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES", [APPMAIN]),
    ([_jd(REQ), _jd(APPMAIN)], QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES", [APPMAIN, REQ]),
    ([_jd(None)], QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
    ([_jd(None, code="JUDGE.SECURITY"), _jd(APPMAIN)], QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
    ([_qa_diag(file=APPMAIN), _jd(None)], QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES", [APPMAIN]),
    ([_qa_diag(file=APPMAIN), _jd("infra/workload/main.tf")], QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES", [APPMAIN]),
    ([_qa_diag(file=None)], QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
    ([_qa_diag(file="apps/testplan01-e2/missing.py")], QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
    ([_qa_diag(file=APPMAIN), _qa_diag(file=None)], QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
])
def test_existing_plan_shapes_are_unchanged(diags, mode, reason, seed_files):
    for tree in (E2_TREE, {p: t for p, t in E2_TREE.items() if not p.endswith(".python-version")}):
        plan = _plan(tree, *diags)
        assert (plan.mode, plan.reason, sorted(plan.seed_files)) == (mode, reason, seed_files)


# ============================================================================ developer end to end
def test_developer_repairs_the_code_file_and_keeps_the_platform_pin():
    """The committed first build's own `.python-version` is the platform's pin; the judge reports it plus a code
    directive: one QA repair, FILES TO FIX = the code file only, both findings in the untrusted block, and the
    committed pin unchanged."""
    tree = _first_build("off")
    pyv = "apps/shop/.python-version"
    assert RP.is_platform_runtime_pin(pyv, tree[pyv])
    fb = _feedback(tree, _jd(pyv, "runtime must be 3.11"), _jd(MAIN, "add the EventAuditRecord model"))
    files, agent, _client, seen = _develop("off", feedback=fb, repairs=[{MAIN: FIXED}])
    assert seen["swarm"] == 0 and not seen["lead_calls"]
    (task,) = seen["repair_tasks"]
    assert json.loads(_section(task["prompt"], "FILES TO FIX:", QR.QA_OUTPUT_HEADER)) == {MAIN: tree[MAIN]}
    _head, rest = task["prompt"].split(QR.QA_OUTPUT_HEADER + "\n\n", 1)
    _token, content = _block_parts(rest.split("\n\nREAD-ONLY CONTEXT (do not return these):", 1)[0])
    assert "runtime must be 3.11" in content and "EventAuditRecord" in content
    assert files[MAIN] == FIXED and files[pyv] == RP.PLATFORM_PYTHON_VERSION_CONTENT
    rec = agent.stack_run("t-qa")["qa_repair"]
    assert (rec["mode"], rec["findings"], rec["seeds"]) == (QR.QA_REPAIR, 2, [{"code": "JUDGE.ADHERENCE",
                                                                                "file": MAIN}])
