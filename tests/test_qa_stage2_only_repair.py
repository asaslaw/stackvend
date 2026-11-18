"""QA-STAGE2-ONLY-REPAIR (register row, owner 11-02; gateway only, workflow YAML unchanged): when QA's tests pass but
the AI reviewer (Stage 2) blocks the build, the developer repairs the reviewer's findings that name a file of the build,
with the other findings shown as text, instead of regenerating the whole workload; when no finding names a file,
today's regeneration stays. Seen live 11-02 (testplan-01-e3, docs/handoff/sat-24-e3-qa-diagnosis.md): a test-passing
build was regenerated and the new build's test failures used up the retry budget.

Covered (F1, developer_agent/qa_repair.py plan_qa_repair): a reviewer-only failure with a file-named finding plans
QA_REPAIR seeded with exactly those findings, the rest text-only in the QA block; a reviewer-only failure with no
file-named finding is REGENERATE (unchanged); a finding naming a file that is not a draft file counts as file-less;
every plan with a sandbox finding is unchanged (Do No Harm, over the existing fixtures); a dispatch whose record does
not say STAGE2_FAILED plans exactly as before; gateway end to end (run_qa record -> _qa_repair_feedback -> plan) and
developer end to end (one repair, no swarm). F2 (main.py run_qa): one audit log line per Stage 2 finding with its typed
facts only. Hermetic: fake judge, FakeDB, fake source backend, fake QA job, fake LLM.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import logging

import pytest

import qa_feedback_capture as cap  # noqa: E402
from test_qa_feedback import (MAIN, SCHEMAS, FIXED, TREE as PLAN_TREE, _block_parts, _develop, _feedback,  # noqa: E402
                              _first_build, _qa_diag, _section)
from test_qa_judge_file_mapping import APPMAIN, E2_TREE, PYV, PYV_MSG, _jd  # noqa: E402
from test_qa_stage2_on_test_fail import (ADH_NOFILE, ADH_PLATFORM, APP_FILE, PUBSUB, SEC_NOFILE, _db,  # noqa: E402
                                         _findings_judge, _run, _stage1, gw)  # noqa: F401  (gw: fixture)
from test_typed_iac_ti3_contract import BUCKET_MODULE, C, intent  # noqa: E402
from fd4f_support import passing_outcome  # noqa: E402
from developer_agent import qa_repair as QR  # noqa: E402

STAGE2 = QR.STAGE2_FAILED_REASON
LIFECYCLE = "Storage bucket is missing the required 7-day Age lifecycle deletion rule"
INTENT_TREE = dict(PLAN_TREE, **{C.INTENT_PATH: intent([BUCKET_MODULE]), C.RENDER_PATH: "{}"})
GITHUB_WF = ".github/workflows/deploy-shop.yml"     # in the tested tree, but the platform's: not a draft file


def _s2(tree, *diags, reason=STAGE2):
    """A Stage 2-only feedback: the record's typed reason forwarded by the gateway (main._qa_repair_feedback)."""
    return dict(_feedback(tree, *diags), **{QR.QA_REASON_FIELD: reason})


def _plan(fb):
    return QR.plan_qa_repair(fb, stack_configured=True)


def _shape(plan):
    """Everything a plan decides, with the untrusted block reduced to its content (its delimiters are per call)."""
    content = _block_parts(plan.untrusted_output)[1] if plan.untrusted_output else ""
    return (plan.mode, plan.reason, plan.attempt, plan.commit_sha, tuple(s.model_dump_json() for s in plan.seeds),
            dict(plan.seed_files), dict(plan.draft), dict(plan.tree), content, plan.findings)


# ============================================================================ F1: reviewer-only, a finding names a file
def test_e3_shape_repairs_the_intent_finding_and_carries_the_file_less_ones_as_text():
    """testplan-01-e3 attempt 1: tests passed; the judge named the intent file for the lifecycle directive, and two
    other directives had no resolvable file -> QA_REPAIR on the intent only, not a regeneration."""
    diags = [_jd(C.INTENT_PATH, LIFECYCLE), _jd(None, PUBSUB), _jd(None, "Add a /health endpoint", "JUDGE.SECURITY")]
    plan = _plan(_s2(INTENT_TREE, *diags))
    assert (plan.mode, plan.reason, plan.findings) == (QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES", 3)
    assert [(s.code, s.file) for s in plan.seeds] == [("JUDGE.ADHERENCE", C.INTENT_PATH)]
    assert plan.repairable_paths == {C.INTENT_PATH} and plan.seed_files == {C.INTENT_PATH: INTENT_TREE[C.INTENT_PATH]}
    assert plan.seeds[0].message.startswith("QA finding 1 (JUDGE.ADHERENCE)")
    _token, content = _block_parts(plan.untrusted_output)
    assert content == QR.render_findings(diags)                       # every finding, same numbering as the seeds
    assert LIFECYCLE in content and PUBSUB in content and "Add a /health endpoint" in content
    for seed in plan.seeds:                                           # the text never reaches a seed
        assert LIFECYCLE not in seed.model_dump_json() and PUBSUB not in seed.model_dump_json()
    assert plan.tree == INTENT_TREE and C.RENDER_PATH not in plan.draft


@pytest.mark.parametrize("diags,seeded", [
    ([_jd(MAIN), _jd(None)], [MAIN]),
    ([_jd(None), _jd(MAIN, "first"), _jd(SCHEMAS, "second")], [MAIN, SCHEMAS]),
    ([_jd(MAIN), _jd("apps/shop/missing.py")], [MAIN]),               # a file not in the build counts as file-less
    ([_jd(MAIN), _jd(GITHUB_WF)], [MAIN]),                            # in the tree, not a draft file: file-less
    ([_jd(MAIN), _jd(C.INTENT_PATH)], [MAIN]),                        # no intent in this tree: not a draft file
    ([_jd(MAIN), ADH_PLATFORM, SEC_NOFILE], [MAIN]),
])
def test_reviewer_only_findings_on_draft_files_are_the_only_seeds(diags, seeded):
    plan = _plan(_s2(PLAN_TREE, *diags))
    assert (plan.mode, plan.reason, plan.findings) == (QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES", len(diags))
    assert [s.file for s in plan.seeds] == seeded and plan.repairable_paths == set(seeded)
    assert _block_parts(plan.untrusted_output)[1] == QR.render_findings(diags)


def test_a_pinned_file_finding_rides_along_and_never_becomes_a_seed():
    plan = _plan(_s2(E2_TREE, _jd(PYV, PYV_MSG), _jd(None), _jd(APPMAIN)))
    assert (plan.mode, plan.repairable_paths) == (QR.QA_REPAIR, {APPMAIN})
    assert PYV_MSG in _block_parts(plan.untrusted_output)[1]


# ============================================================================ F1: reviewer-only, no finding names a file
@pytest.mark.parametrize("diags,reason", [
    ([SEC_NOFILE, ADH_NOFILE], "FINDING_NOT_ON_A_DRAFT_FILE"),
    # PLATFORM-RENDERED-FINDING (owner 11-13): a platform-rendered file (IaC floor, CI workflow) is a typed stop
    ([ADH_PLATFORM], QR.PLATFORM_RENDERED_REASON),
    ([_jd("apps/shop/missing.py")], "FINDING_NOT_ON_A_DRAFT_FILE"),   # names a file that is not in the build
    ([_jd(GITHUB_WF), _jd(None)], QR.PLATFORM_RENDERED_REASON),
])
def test_reviewer_only_without_a_file_named_finding_is_todays_regeneration(diags, reason):
    plan = _plan(_s2(PLAN_TREE, *diags))
    mode = QR.STOP if reason == QR.PLATFORM_RENDERED_REASON else QR.REGENERATE
    assert (plan.mode, plan.reason) == (mode, reason) and not plan.seeds and not plan.untrusted_output
    assert _shape(plan) == _shape(_plan(_feedback(PLAN_TREE, *diags)))   # identical to before this row


def test_reviewer_only_pinned_file_alone_is_a_platform_stop():
    """PLATFORM-RENDERED-FINDING (owner 11-13; was REGENERATE FINDING_ON_A_PLATFORM_PINNED_FILE)."""
    plan = _plan(_s2(E2_TREE, _jd(PYV, PYV_MSG)))
    assert (plan.mode, plan.reason) == (QR.STOP, QR.PLATFORM_RENDERED_REASON) and not plan.seeds
    plan = _plan(_s2(E2_TREE, _jd(PYV, PYV_MSG), _jd(None)))
    assert (plan.mode, plan.reason) == (QR.STOP, QR.PLATFORM_RENDERED_REASON) and not plan.seeds


# ============================================================================ Do No Harm: only a STAGE2_FAILED record
@pytest.mark.parametrize("reason", [None, "", "NO_PROGRESS", "stage2_failed", 1, ["STAGE2_FAILED"]])
def test_a_record_that_does_not_say_stage2_failed_plans_exactly_as_before(reason):
    diags = [_jd(MAIN), _jd(None)]
    before = _plan(_feedback(PLAN_TREE, *diags))
    assert (before.mode, before.reason) == (QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE")
    assert _shape(_plan(_s2(PLAN_TREE, *diags, reason=reason))) == _shape(before)


# Every plan with a sandbox finding (the fixtures of test_qa_feedback, test_qa_stage2_on_test_fail,
# test_qa_judge_file_mapping and test_qa_repair_on_crash shapes) is byte-for-byte the same with any record reason.
SANDBOX_SHAPES = [
    (PLAN_TREE, [_qa_diag()]),
    (PLAN_TREE, [_qa_diag(), SEC_NOFILE, ADH_NOFILE, ADH_PLATFORM]),
    (PLAN_TREE, [_qa_diag(file=None, code="PYTEST.REPORT_INVALID"), SEC_NOFILE]),
    (PLAN_TREE, [_qa_diag(file="infra/workload/main.tf"), ADH_NOFILE]),
    (PLAN_TREE, [_qa_diag(), _qa_diag(file=None, code="JUDGE.SECURITY")]),
    (PLAN_TREE, [_qa_diag(file="apps/shop/missing.py")]),
    (PLAN_TREE, [_qa_diag(code="not a code")]),
    (PLAN_TREE, [_qa_diag(severity="warning"), _jd(None)]),
    (PLAN_TREE, [_qa_diag(), _jd(MAIN), _jd(None)]),
    (PLAN_TREE, [_qa_diag(file=None), _jd(MAIN)]),
    (PLAN_TREE, [_qa_diag(file=None, code="PYTEST.STARTUP_ERROR"), _jd(None)]),
    (dict(PLAN_TREE, **{"apps/shop/tests/conftest.py": "import x\n"}),
     [_qa_diag(file="apps/shop/requirements.txt", code="PYTEST.STARTUP_ERROR"), _jd(None), _jd(MAIN)]),
    (E2_TREE, [_qa_diag(file=APPMAIN), _jd(PYV, PYV_MSG)]),
    (E2_TREE, [_qa_diag(file=PYV)]),
    (E2_TREE, [_qa_diag(file=APPMAIN), _qa_diag(file=None)]),
    (E2_TREE, [_qa_diag(file=APPMAIN), _jd(None)]),
    (E2_TREE, [_qa_diag(file=APPMAIN), _jd("infra/workload/main.tf")]),
    (INTENT_TREE, [_qa_diag(), _jd(C.INTENT_PATH, LIFECYCLE), _jd(None)]),
]


@pytest.mark.parametrize("tree,diags", SANDBOX_SHAPES)
@pytest.mark.parametrize("reason", [STAGE2, None, "NO_PROGRESS"])
def test_every_plan_with_a_sandbox_finding_is_unchanged(tree, diags, reason):
    assert _shape(_plan(_s2(tree, *diags, reason=reason))) == _shape(_plan(_feedback(tree, *diags)))


@pytest.mark.parametrize("diags", [[_jd(MAIN)], [_jd(MAIN), _jd(SCHEMAS)], [_jd(None)], [SEC_NOFILE, ADH_NOFILE]])
def test_reviewer_only_shapes_the_old_rule_already_decided_are_unchanged(diags):
    """All on draft files (QA_REPAIR before this row) and all file-less (REGENERATE before): the same plan."""
    assert _shape(_plan(_s2(PLAN_TREE, *diags))) == _shape(_plan(_feedback(PLAN_TREE, *diags)))


def test_unusable_feedback_with_the_reason_is_still_unusable():
    for fb in ({"files": {}, "diagnostics": [], QR.QA_REASON_FIELD: STAGE2},
               {"files": PLAN_TREE, "diagnostics": "x", QR.QA_REASON_FIELD: STAGE2}):
        assert _plan(fb).reason == "FEEDBACK_INVALID"
    assert _plan(_s2(PLAN_TREE, dict(_jd(MAIN), severity="warning"))).reason == "NO_ERROR_FINDINGS"
    assert QR.plan_qa_repair(_s2(PLAN_TREE, _jd(MAIN), _jd(None)), stack_configured=False).reason == "NO_REPAIR_LOOP"


# ============================================================================ gateway end to end (run_qa -> plan)
def test_a_stage2_only_record_reaches_the_developer_as_a_repair(gw, monkeypatch):
    db = _db()
    body = _run(gw, monkeypatch, db, passing_outcome(), judge=_findings_judge([]))
    assert (body["error_class"], body["reason"], body["retryable"]) == ("CODE_DEFECT", STAGE2, True)
    doc = db.docs["qa_test_runs/tr-1"]
    assert doc["reason"] == STAGE2
    rec = cap.qa_record(diagnostics=doc["diagnostics"], fingerprints=doc["fingerprints"], summary=doc["summary"],
                        reason=doc["reason"])
    kw, _calls = cap.run(gw, monkeypatch, dict(retry_count=1), rec)
    fb = kw["qa_feedback"]
    assert fb[QR.QA_REASON_FIELD] == STAGE2
    plan = QR.plan_qa_repair(fb, stack_configured=True)
    assert (plan.mode, plan.reason, plan.findings) == (QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES", 3)
    assert [(s.code, s.file) for s in plan.seeds] == [("JUDGE.ADHERENCE", APP_FILE)]
    _token, content = _block_parts(plan.untrusted_output)
    for text in ("bucket is publicly readable", PUBSUB, "Add a /health endpoint"):
        assert text in content


def test_the_feedback_forwards_the_records_reason_only_as_a_string(gw, monkeypatch):
    for reason, forwarded in ((None, None), (STAGE2, STAGE2), (7, None)):
        kw, _calls = cap.run(gw, monkeypatch, dict(retry_count=1), cap.qa_record(reason=reason))
        assert kw["qa_feedback"][QR.QA_REASON_FIELD] == forwarded


def test_the_gateway_writes_the_reason_the_plan_reads(gw):
    assert gw._QA_STAGE2_FAILED == QR.STAGE2_FAILED_REASON == "STAGE2_FAILED"
    assert gw._QA_REASON_FIELD == QR.QA_REASON_FIELD


# ============================================================================ developer end to end
def test_the_developer_repairs_a_stage2_only_finding_in_place_without_regenerating():
    tree = _first_build("off")
    fb = _s2(tree, _jd(MAIN, "add the EventAuditRecord model"), _jd(None, PUBSUB))
    files, agent, _client, seen = _develop("off", feedback=fb, repairs=[{MAIN: FIXED}])
    assert seen["swarm"] == 0 and not seen["lead_calls"]               # no regeneration
    (task,) = seen["repair_tasks"]
    assert json.loads(_section(task["prompt"], "FILES TO FIX:", QR.QA_OUTPUT_HEADER)) == {MAIN: tree[MAIN]}
    diags = json.loads(_section(task["prompt"], "DIAGNOSTICS:", "FILES TO FIX:"))
    assert [(d["code"], d["file"]) for d in diags] == [("JUDGE.ADHERENCE", MAIN)]
    _head, rest = task["prompt"].split(QR.QA_OUTPUT_HEADER + "\n\n", 1)
    _token, content = _block_parts(rest.split("\n\nREAD-ONLY CONTEXT (do not return these):", 1)[0])
    assert "EventAuditRecord" in content and PUBSUB in content
    assert files[MAIN] == FIXED and {p: t for p, t in files.items() if p != MAIN} == {
        p: t for p, t in tree.items() if p != MAIN}
    rec = agent.stack_run("t-qa")["qa_repair"]
    assert (rec["mode"], rec["findings"], rec["seeds"]) == (QR.QA_REPAIR, 2, [{"code": "JUDGE.ADHERENCE",
                                                                                "file": MAIN}])


def test_the_e3_shape_repairs_the_typed_intent_in_generate_mode():
    """testplan-01-e3: the reviewer's lifecycle finding names the typed intent; the repair changes only the intent
    (the platform renders it again), the file-less finding is text, and nothing is regenerated."""
    tree = _first_build("generate")
    fixed = intent([dict(BUCKET_MODULE, args=dict(BUCKET_MODULE["args"], lifecycle_delete_age_days=7))])
    fb = _s2(tree, _jd(C.INTENT_PATH, LIFECYCLE), _jd(None, PUBSUB))
    files, agent, _client, seen = _develop("generate", feedback=fb, repairs=[{C.INTENT_PATH: fixed}])
    assert seen["swarm"] == 0 and not seen["lead_calls"]
    (task,) = seen["repair_tasks"]
    assert json.loads(_section(task["prompt"], "FILES TO FIX:", QR.QA_OUTPUT_HEADER)) == {
        C.INTENT_PATH: tree[C.INTENT_PATH]}
    _head, rest = task["prompt"].split(QR.QA_OUTPUT_HEADER + "\n\n", 1)
    assert LIFECYCLE in rest and PUBSUB in rest
    assert agent.last_validation_report.status == "PASS"
    assert json.loads(files[C.INTENT_PATH])["modules"][0]["args"]["lifecycle_delete_age_days"] == 7
    assert {p: t for p, t in files.items() if not p.startswith("infra/")} == {
        p: t for p, t in tree.items() if not p.startswith("infra/")}
    rec = agent.stack_run("t-qa")["qa_repair"]
    assert (rec["mode"], rec["seeds"]) == (QR.QA_REPAIR, [{"code": "JUDGE.ADHERENCE", "file": C.INTENT_PATH}])


# ============================================================================ F2: audit log, typed facts only
def _finding_lines(caplog):
    return [r for r in caplog.records if hasattr(r, "qa_stage2_finding")]


def test_each_stage2_finding_is_logged_with_its_typed_facts_only(gw, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="orchestrator-gateway-service")
    _run(gw, monkeypatch, _db(), passing_outcome(), judge=_findings_judge([]))
    lines = _finding_lines(caplog)
    assert [(r.qa_stage2_finding["code"], r.qa_stage2_finding["file"], r.qa_stage2_finding["task_id"],
             r.qa_stage2_finding["finding"], r.qa_stage2_finding["findings"]) for r in lines] == [
        ("JUDGE.SECURITY", None, None, 1, 3), ("JUDGE.ADHERENCE", APP_FILE, "t1", 2, 3),
        ("JUDGE.ADHERENCE", None, None, 3, 3)]
    for r in lines:
        assert r.levelno == logging.INFO
        assert r.qa_stage2_finding["qa_reason"] == STAGE2 and r.qa_stage2_finding["trace_id"] == "tr-1"
        text = r.getMessage() + json.dumps(r.qa_stage2_finding)
        for finding_text in ("bucket is publicly readable", PUBSUB, "Add a /health endpoint"):
            assert finding_text not in text
    assert "file 'none'" in lines[0].getMessage() and f"file '{APP_FILE}'" in lines[1].getMessage()


def test_findings_of_a_review_on_a_failed_test_run_are_logged_and_sandbox_ones_are_not(gw, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="orchestrator-gateway-service")
    _run(gw, monkeypatch, _db(), _stage1(), judge=_findings_judge([]))
    lines = _finding_lines(caplog)
    assert [r.qa_stage2_finding["code"] for r in lines] == ["JUDGE.SECURITY", "JUDGE.ADHERENCE", "JUDGE.ADHERENCE"]
    assert all(r.qa_stage2_finding["qa_reason"] is None for r in lines)


def test_a_clean_review_logs_no_finding(gw, monkeypatch, caplog):
    from test_qa_stage2_on_test_fail import _judge
    caplog.set_level(logging.INFO, logger="orchestrator-gateway-service")
    body = _run(gw, monkeypatch, _db(), passing_outcome(), judge=_judge([]))
    assert body["passed"] is True and _finding_lines(caplog) == []
    _run(gw, monkeypatch, _db(), _stage1(), judge=_judge([]))
    assert _finding_lines(caplog) == []
