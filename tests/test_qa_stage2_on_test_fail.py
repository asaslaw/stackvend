"""QA-STAGE2-ON-TEST-FAIL (register row, owner 10-28; gateway only, the workflow YAML is unchanged): when QA's sandbox
tests fail (Stage 1 CODE_DEFECT), the Stage 2 judges also review that same build, and the single repair round gets both
the test failures and the judges' blocking findings. When Stage 1 passes, QA behaves exactly as before.

Covered: Stage 1 fail + Stage 2 findings -> one repair instruction with both (gateway evidence -> the developer's
feedback -> the repair task's prompt); Stage 1 fail + Stage 2 clean -> today's response; Stage 1 pass and a non-CODE_DEFECT
Stage 1 failure -> unchanged (negatives); a judge that is unavailable, out of time or missing its context never blocks
the test failures' repair; findings without a repairable file reach the developer as text (Stage 2-only failures keep
today's rule); the repair budget is not touched by Stage 2; the no-progress rule is unchanged. Hermetic: fake judge,
FakeDB, fake source backend, fake QA job.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
from unittest.mock import MagicMock, patch

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import (SHA_A, SHA_B, FakeBackend, FakeDB, FakeQAClient, backend_factory, code_defect_outcome,
                          passing_outcome, seed_context)
import qa_feedback_capture as cap  # noqa: E402
from test_qa_feedback import (MAIN, _block_parts, _develop, _feedback, _first_build, _qa_diag,  # noqa: E402
                              _section, FIXED, TREE as PLAN_TREE)
from developer_agent import qa_repair as QR  # noqa: E402
from shared.diagnostics import RepairLedger  # noqa: E402

import qa_auditor.judge as judge_mod  # noqa: E402

BRANCH = "castor/app-1"
APP_FILE = "apps/svc/main.py"           # a draft file of cap.TREE (the tree the developer's feedback is fetched at)
DAG = [{"task_id": "t1", "title": "svc", "target_files": [APP_FILE]}]
TREE = {p: t.encode() for p, t in cap.TREE.items()}
PUBSUB = "Provision Pub/Sub push subscription for the events topic"


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


@pytest.fixture()
def gw(monkeypatch):
    mod = fd4f_support.load_gateway(monkeypatch, "qa_s2tf_gw")
    yield mod
    mod.app.dependency_overrides.clear()


def _judge(calls, *, crit=(), missed=(), task_ids=None, adh=None, fail=None):
    """A fake judge: the security lens reports `crit`; the adherence lens fails when `missed` (or `adh` < 0.95)."""
    def _call(prompt, model, **kw):
        calls.append("security" if "Security Engineer" in prompt else "adherence")
        if fail is not None:
            raise fail
        if "Security Engineer" in prompt:
            return json.dumps({"passed": not crit, "critical_vulnerabilities": list(crit),
                               "moderate_vulnerabilities": [], "compliance_flags": [], "summary": "s"})
        score = adh if adh is not None else (0.5 if missed else 1.0)
        body = {"instruction_adherence_score": score, "grounding_score": 1.0, "missed_directives": list(missed),
                "hallucinated_features": [], "summary": "a"}
        if task_ids is not None:
            body["missed_directive_task_ids"] = list(task_ids)
        return json.dumps(body)
    return _call


def _db(context=True):
    db = FakeDB()
    if context:
        seed_context(db)
        db.docs["pipeline_executions/tr-1"]["stages"]["architect"]["details"]["task_dag"] = DAG
    return db


def _run(gw, monkeypatch, db, outcome, judge=None, attempt=0):
    calls = []
    monkeypatch.setattr(judge_mod, "call", judge or _judge(calls))
    backend = FakeBackend({BRANCH: TREE, "main": {}}, {BRANCH: SHA_A, "main": SHA_B})
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name=BRANCH, attempt=attempt)
    return gw.run_qa(req, client=FakeQAClient(outcome), source_backend_factory=backend_factory(backend),
                     evidence_db=db)


def _stage1():
    return code_defect_outcome(code="PY.TEST_FAILED", message="tests/test_api.py::test_publish failed", file=APP_FILE)


def _findings_judge(calls):
    return _judge(calls, crit=["bucket is publicly readable"], missed=[PUBSUB, "Add a /health endpoint"],
                  task_ids=["t1", ""])


def _no_stage2(gw, monkeypatch):
    monkeypatch.setattr(gw, "STAGE_TWO_MIN_REMAINING_S", 10 ** 9)   # no time left: Stage 2 never starts


# ============================================================================ gateway: Stage 1 fail + Stage 2 findings
def test_stage1_failure_and_stage2_findings_go_to_one_repair_round_together(gw, monkeypatch):
    calls = []
    db = _db()
    body = _run(gw, monkeypatch, db, _stage1(), judge=_findings_judge(calls))
    assert sorted(calls) == ["adherence", "security"]                       # the judges reviewed the failed build
    assert (body["passed"], body["error_class"], body["retryable"]) == (False, "CODE_DEFECT", True)
    assert [(d["tool"], d["code"], d["file"]) for d in body["diagnostics"]] == [
        ("pytest", "PY.TEST_FAILED", APP_FILE),                              # Stage 1 first
        ("judge", "JUDGE.SECURITY", None),
        ("judge", "JUDGE.ADHERENCE", APP_FILE),                              # routed by task t1 (QA-JUDGE-FINGERPRINT)
        ("judge", "JUDGE.ADHERENCE", None)]
    assert all(d["source"] == "qa" and d["iteration"] == 0 and d["fingerprint"] for d in body["diagnostics"])
    assert "QA reviewer (Stage 2) on the same build: 3 blocking finding(s)" in body["summary"]
    doc = db.docs["qa_test_runs/tr-1"]
    assert doc["stage2_on_test_fail"]["status"] == "BLOCKING" and doc["stage2_on_test_fail"]["findings"] == 3
    assert doc["stage2_on_test_fail"]["adherence_lens"]["missed_directives"] == [PUBSUB, "Add a /health endpoint"]
    assert "composite_audit" not in doc and "security_lens" not in doc      # the pass path's keys stay its own
    assert doc["fingerprints"] == sorted(d["fingerprint"] for d in body["diagnostics"])

    # the developer's QA retry dispatch reads exactly this record (same trace rules) and plans one repair with both
    rec = cap.qa_record(diagnostics=doc["diagnostics"], fingerprints=doc["fingerprints"], summary=doc["summary"])
    kw, _ = cap.run(gw, monkeypatch, dict(retry_count=1), rec)
    plan = QR.plan_qa_repair(kw["qa_feedback"], stack_configured=True)
    assert (plan.mode, plan.reason, plan.findings) == (QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES", 4)
    assert [(s.code, s.file) for s in plan.seeds] == [("PY.TEST_FAILED", APP_FILE), ("JUDGE.ADHERENCE", APP_FILE)]
    _token, content = _block_parts(plan.untrusted_output)
    for text in ("test_publish failed", "bucket is publicly readable", PUBSUB, "Add a /health endpoint"):
        assert text in content


def test_the_repair_task_prompt_carries_the_test_failure_and_the_reviewer_findings():
    """Developer end to end: one QA repair (no regeneration); the seeded file is the test failure's, the reviewer's
    findings without a file are text in the same untrusted block."""
    tree = _first_build("off")
    sec = {"tool": "judge", "code": "JUDGE.SECURITY", "severity": "error", "file": None, "line": None,
           "message": "bucket is publicly readable", "detail": None, QR.JUDGE_FINDING_FIELD: True}
    adh = dict(sec, code="JUDGE.ADHERENCE", message=PUBSUB)
    files, agent, _client, seen = _develop("off", feedback=_feedback(tree, _qa_diag(), sec, adh), repairs=[{MAIN: FIXED}])
    assert seen["swarm"] == 0 and not seen["lead_calls"]
    (task,) = seen["repair_tasks"]
    diags = json.loads(_section(task["prompt"], "DIAGNOSTICS:", "FILES TO FIX:"))
    assert [(d["code"], d["file"]) for d in diags] == [("PY.TEST_FAILED", MAIN)]   # seeds: the repairable file only
    _head, rest = task["prompt"].split(QR.QA_OUTPUT_HEADER + "\n\n", 1)
    _token, content = _block_parts(rest.split("\n\nREAD-ONLY CONTEXT (do not return these):", 1)[0])
    assert "EventAuditRecord" in content and "bucket is publicly readable" in content and PUBSUB in content
    assert files[MAIN] == FIXED
    rec = agent.stack_run("t-qa")["qa_repair"]
    assert (rec["mode"], rec["findings"], rec["seeds"]) == (QR.QA_REPAIR, 3, [{"code": "PY.TEST_FAILED", "file": MAIN}])


# ============================================================================ gateway: Stage 1 fail + Stage 2 clean
def test_stage1_failure_with_a_clean_review_is_todays_response(gw, monkeypatch):
    calls = []
    clean_db = _db()
    clean = _run(gw, monkeypatch, clean_db, _stage1(), judge=_judge(calls))
    assert sorted(calls) == ["adherence", "security"]
    assert clean_db.docs["qa_test_runs/tr-1"]["stage2_on_test_fail"]["status"] == "CLEAN"
    _no_stage2(gw, monkeypatch)
    today = _run(gw, monkeypatch, _db(), _stage1())                         # Stage 2 never ran = before this row
    assert clean == today
    assert [d["code"] for d in clean["diagnostics"]] == ["PY.TEST_FAILED"] and clean["retryable"] is True


# ============================================================================ negatives: Stage 1 pass / other failures
def test_stage1_pass_is_unchanged(gw, monkeypatch):
    calls = []
    db = _db()
    ok = _run(gw, monkeypatch, db, passing_outcome(), judge=_judge(calls))
    assert ok["passed"] is True and ok["error_class"] is None and sorted(calls) == ["adherence", "security"]
    doc = db.docs["qa_test_runs/tr-1"]
    assert "stage2_on_test_fail" not in doc and doc["composite_audit"]["passed"] is True

    db = _db()
    failed = _run(gw, monkeypatch, db, passing_outcome(), judge=_findings_judge([]))
    assert (failed["error_class"], failed["reason"], failed["retryable"]) == ("CODE_DEFECT", "STAGE2_FAILED", True)
    assert [(d["code"], d["file"]) for d in failed["diagnostics"]] == [
        ("JUDGE.SECURITY", None), ("JUDGE.ADHERENCE", APP_FILE), ("JUDGE.ADHERENCE", None)]
    assert failed["summary"].startswith("Unified QA Verification Failed")
    assert "stage2_on_test_fail" not in db.docs["qa_test_runs/tr-1"]


def test_stage1_pass_with_no_time_left_is_still_gate_unavailable(gw, monkeypatch):
    from gate_errors import GateUnavailableError
    _no_stage2(gw, monkeypatch)
    with pytest.raises(GateUnavailableError) as ei:
        _run(gw, monkeypatch, _db(), passing_outcome())
    assert ei.value.reason == "DEADLINE"


def test_a_stage1_outage_never_runs_the_judges(gw, monkeypatch):
    from gate_errors import ErrorClass, GateUnavailableError
    from qa_job_client import QAOutcome
    calls = []
    out = QAOutcome(passed=False, error_class=ErrorClass.GATE_UNAVAILABLE, summary="runner error", reason="RUNNER_ERROR")
    with pytest.raises(GateUnavailableError):
        _run(gw, monkeypatch, _db(), out, judge=_judge(calls))
    assert calls == []


# ============================================================================ the judge never blocks Stage 1's repair
@pytest.mark.parametrize("case", ["judge_error", "no_context", "no_time"])
def test_an_unavailable_review_still_sends_the_test_failures_to_repair(gw, monkeypatch, case):
    calls = []
    judge = _judge(calls, fail=RuntimeError("vertex down")) if case == "judge_error" else _judge(calls)
    if case == "no_time":
        _no_stage2(gw, monkeypatch)
    db = _db(context=case != "no_context")
    body = _run(gw, monkeypatch, db, _stage1(), judge=judge)
    assert (body["passed"], body["error_class"], body["retryable"]) == (False, "CODE_DEFECT", True)
    assert [d["code"] for d in body["diagnostics"]] == ["PY.TEST_FAILED"]
    assert "QA reviewer" not in body["summary"]
    entry = db.docs["qa_test_runs/tr-1"]["stage2_on_test_fail"]
    assert entry["status"] == ("SKIPPED" if case == "no_time" else "UNAVAILABLE") and entry["findings"] == 0
    if case != "judge_error":
        assert calls == []


# ============================================================================ findings without a repairable file
SEC_NOFILE = {"tool": "judge", "code": "JUDGE.SECURITY", "severity": "error", "file": None, "line": None,
              "message": "bucket is publicly readable", "detail": None, QR.JUDGE_FINDING_FIELD: True}
ADH_NOFILE = dict(SEC_NOFILE, code="JUDGE.ADHERENCE", message=PUBSUB)
ADH_PLATFORM = dict(ADH_NOFILE, file="infra/workload/main.tf", task_id="t9")


def test_reviewer_findings_without_a_draft_file_ride_along_as_text():
    plan = QR.plan_qa_repair(_feedback(PLAN_TREE, _qa_diag(), SEC_NOFILE, ADH_NOFILE, ADH_PLATFORM),
                             stack_configured=True)
    assert (plan.mode, plan.findings) == (QR.QA_REPAIR, 4)
    assert [(s.code, s.file) for s in plan.seeds] == [("PY.TEST_FAILED", MAIN)] and plan.repairable_paths == {MAIN}
    _token, content = _block_parts(plan.untrusted_output)
    rendered = QR.render_findings([_qa_diag(), SEC_NOFILE, ADH_NOFILE, ADH_PLATFORM])
    assert content == rendered                                         # same numbering as the seeds' pointers
    assert '"finding": 2' in rendered and "bucket is publicly readable" in rendered and PUBSUB in rendered
    assert plan.seeds[0].message.startswith("QA finding 1 (PY.TEST_FAILED)")


@pytest.mark.parametrize("diags,mode,reason", [
    ([SEC_NOFILE, ADH_NOFILE], QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE"),   # a Stage 2-only failure: today's rule
    # PLATFORM-RENDERED-FINDING (owner 11-13): a finding forcing a regeneration on a platform-rendered file stops
    ([ADH_PLATFORM], QR.STOP, QR.PLATFORM_RENDERED_REASON),
    ([_qa_diag(file=None, code="PYTEST.REPORT_INVALID"), SEC_NOFILE], QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE"),
    ([_qa_diag(file="infra/workload/main.tf"), ADH_NOFILE], QR.STOP, QR.PLATFORM_RENDERED_REASON),
])
def test_without_a_repairable_sandbox_finding_the_rule_is_unchanged(diags, mode, reason):
    plan = QR.plan_qa_repair(_feedback(PLAN_TREE, *diags), stack_configured=True)
    assert (plan.mode, plan.reason) == (mode, reason) and not plan.seeds


def test_a_feedback_without_reviewer_findings_plans_exactly_as_before():
    """Do No Harm: with no judge finding the plan is the same object as before this row (byte-identical block aside
    from the per-call delimiters)."""
    plan = QR.plan_qa_repair(_feedback(PLAN_TREE, _qa_diag()), stack_configured=True)
    assert (plan.mode, plan.reason, plan.findings) == (QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES", 1)
    assert _block_parts(plan.untrusted_output)[1] == QR.render_findings([_qa_diag()])


# ============================================================================ the repair budget is not double-counted
def test_stage2_on_a_failed_build_writes_nothing_but_the_qa_evidence(gw, monkeypatch):
    with_review, without = _db(), _db()
    _run(gw, monkeypatch, with_review, _stage1(), judge=_findings_judge([]))
    _no_stage2(gw, monkeypatch)
    _run(gw, monkeypatch, without, _stage1())
    paths = lambda db: [w[0] for w in db.writes]   # noqa: E731
    assert paths(with_review) == paths(without)
    assert not any(p.startswith("pipeline_executions") for p in paths(with_review))   # the repair ledger's document
    assert "repair" not in with_review.docs["pipeline_executions/tr-1"]


def test_reviewer_findings_do_not_change_the_repair_budget_decision():
    tree = _first_build("off")
    left = RepairLedger(trace_id="t-qa", iteration=1)        # what the first build's own repairs left
    for fb in (_feedback(tree, _qa_diag()), _feedback(tree, _qa_diag(), SEC_NOFILE, ADH_NOFILE)):
        _files, agent, _c, seen = _develop("off", feedback=fb, repairs=[{MAIN: FIXED}], ledger=left)
        rec = agent.stack_run("t-qa")["qa_repair"]
        assert rec["mode"] == QR.QA_REPAIR and "budget" not in rec and len(seen["repair_tasks"]) == 1


# ============================================================================ no-progress rule
def test_identical_results_on_the_retry_are_no_progress(gw, monkeypatch):
    db = _db()
    _run(gw, monkeypatch, db, _stage1(), judge=_findings_judge([]))
    second = _run(gw, monkeypatch, db, _stage1(), judge=_findings_judge([]), attempt=1)
    assert second["retryable"] is False and second["reason"] == "NO_PROGRESS"


def test_a_different_result_on_the_retry_is_progress_as_before(gw, monkeypatch):
    db = _db()
    _run(gw, monkeypatch, db, _stage1(), judge=_findings_judge([]))
    second = _run(gw, monkeypatch, db, _stage1(), judge=_judge([], missed=["Add a README"]), attempt=1)
    assert second["retryable"] is True and second["reason"] != "NO_PROGRESS"
