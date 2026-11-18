"""QA-REPAIR-OWNERSHIP-PARITY (SAT-49, proposed register row): a QA repair treats as its draft exactly the files the
developer wrote in the build QA tested, never the whole tested tree.

Live case (castor testplan01-e2 relaunch, 11-02): the relaunch rebuilt over the morning build's repository. Its commit
left the morning build's `routes.py` / `services.py` in the repository (the commit is additive) but outside the
validated tree. QA failed attempt 0 on `tests/test_main.py`; the QA repair made the WHOLE tested tree its draft, so
the LLM-owned-only import check (V3e) judged the dead files for the first time, and the loop stopped before any LLM
call with `CODE_DEFECT diagnostics without a repairable owner`.

The rule: the gateway records each committed build's own draft paths
(`pipeline_executions/{trace}.stages.developer.committed_draft = {commit_sha, llm_draft_paths}`) and forwards them with
the QA feedback only when the record's commit is exactly QA's commit; the plan's draft is those files (exact set
membership); without them, today's regeneration (`DRAFT_PATHS_UNAVAILABLE`). Covered: (a) the e2 shape repairs; (b)
no record = today's regeneration with identical generation calls; (c) a record of another commit = the same; (d) Do
No Harm on a fresh repository (the honest difference: only the platform-written files leave the draft); (e) the
repair dispatch's own record and a second QA round; (f) the kept limitation (a stale QA-named file regenerates); (g)
the pin reason; (h) the gateway forwards / omits the paths; (i) the record write. Hermetic: fake LLM, fake /validate,
FakeDB, fake source backend.
"""
import hermetic_guard  # noqa: F401  (first import)

import json
import logging
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

import qa_feedback_capture as cap  # noqa: E402
from test_qa_feedback import (APP, FIXED, MAIN, SCHEMAS, TF_DRAFT, _block_parts, _develop, _feedback,  # noqa: E402
                              _qa_diag, _section)
from test_qa_judge_file_mapping import E2_TREE, PYV, PYV_MSG, _jd  # noqa: E402
from developer_agent import qa_repair as QR  # noqa: E402
from developer_agent import runtime_pin as RP  # noqa: E402
from shared.diagnostics import StageError  # noqa: E402
from fd4f_support import FakeDB, gw  # noqa: E402,F401  (gw: the gateway app fixture)

ROUTES = "apps/shop/routes.py"
STALE_ROUTES = "from schemas import EventInboundRequest\n\n\ndef route():\n    return EventInboundRequest\n"
STALE_TEST = "apps/shop/tests/test_routes.py"
CONTEXT_MARK = "READ-ONLY CONTEXT (do not return these):\n\n"
# the platform-written files of the fixture's first build outside infra/ and .github/ (Fable RT F1)
PLATFORM_WRITTEN = {".python-version", "apps/shop/.python-version", "apps/__init__.py", "apps/shop/__init__.py",
                    "docs/planning/0001-initial-workload-architecture.md"}


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


def _build():
    """Attempt 0 (mode off): (the committed tree QA tested, the dispatch's recorded llm_draft_paths)."""
    draft = dict(APP, **TF_DRAFT, **{SCHEMAS: "class Other:\n    pass\n"})
    att = {p: ("IAC_ENGINEER" if p.startswith("infra/workload/") else "BACKEND_ENGINEER") for p in draft}
    files, agent, _c, _seen = _develop("off", swarm_draft=draft, swarm_att=att)
    assert agent.last_validation_report.status == "PASS"
    return files, agent.stack_run("t-qa")["llm_draft_paths"]


def _e2_tree():
    """A relaunch's tested tree: the first build plus an earlier build's dead file (not written in this run) whose
    import the current `schemas` package no longer provides."""
    tree, paths = _build()
    return dict(tree, **{ROUTES: STALE_ROUTES}), paths


def _normalized(prompt):
    """The prompt with the QA block's per-call random delimiter token replaced (so two prompts compare by content)."""
    _head, rest = prompt.split(QR.QA_OUTPUT_HEADER + "\n\n", 1)
    token, _content = _block_parts(rest.split("\n\n" + CONTEXT_MARK.rstrip("\n"), 1)[0])
    return prompt.replace(token, "T" * 24)


# --------------------------------------------------------------------------------------------- (a) the e2 shape
def test_first_build_records_exactly_the_llm_draft():
    tree, paths = _build()
    assert paths == sorted(APP) + [SCHEMAS, "infra/workload/custom.tf"]
    assert PLATFORM_WRITTEN <= set(tree) and not PLATFORM_WRITTEN & set(paths)


def test_e2_shape_today_stops_before_any_repair():
    """The defect, reproduced: with the whole tested tree as the draft the dead file is judged as LLM-owned and the
    loop stops without a repairable owner (no repair task, no LLM call)."""
    tree, _paths = _e2_tree()
    with pytest.raises(StageError) as ei:
        _develop("off", feedback=_feedback(tree, _qa_diag()), repairs=[{MAIN: FIXED}])
    assert "without a repairable owner" in str(ei.value)
    assert "PY.LOCAL_IMPORT_UNRESOLVED" in {d.code for d in ei.value.report.diagnostics}
    assert ROUTES in {d.file for d in ei.value.report.diagnostics}


def test_e2_shape_with_the_recorded_draft_repairs_the_qa_named_file():
    tree, paths = _e2_tree()
    plan = QR.plan_qa_repair(_feedback(tree, _qa_diag(), draft_paths=paths), stack_configured=True)
    assert (plan.mode, plan.reason) == (QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES")
    assert ROUTES not in plan.draft and ROUTES in plan.tree and plan.repairable_paths == {MAIN}
    files, agent, _client, seen = _develop("off", feedback=_feedback(tree, _qa_diag(), draft_paths=paths),
                                           repairs=[{MAIN: FIXED}])
    (task,) = seen["repair_tasks"]                                   # the loop reached an iteration
    assert json.loads(_section(task["prompt"], "FILES TO FIX:", QR.QA_OUTPUT_HEADER)) == {MAIN: tree[MAIN]}
    assert agent.last_validation_report.status == "PASS" and files[MAIN] == FIXED
    assert ROUTES not in files                                        # outside the validated set, as in dispatch 1
    assert seen["swarm"] == 0 and not seen["lead_calls"]


# ------------------------------------------------------------------------ (b) (c) no matching record: regeneration
def test_without_draft_paths_it_is_todays_regeneration_with_identical_generation_calls():
    """No record forwarded: REGENERATE DRAFT_PATHS_UNAVAILABLE before the draft is built, and the generation calls
    are byte-identical to a dispatch without any QA feedback."""
    tree, _paths = _e2_tree()
    plan = QR.plan_qa_repair(_feedback(tree, _qa_diag(), draft_paths=None), stack_configured=True)
    assert (plan.mode, plan.reason, plan.seeds, plan.draft) == (QR.REGENERATE, QR.DRAFT_PATHS_UNAVAILABLE, (), {})
    draft = dict(APP, **TF_DRAFT)
    att = {p: ("IAC_ENGINEER" if p.startswith("infra/workload/") else "BACKEND_ENGINEER") for p in draft}
    runs = []
    for fb in (None, _feedback(tree, _qa_diag(), draft_paths=None)):
        files, agent, _c, seen = _develop("off", feedback=fb, swarm_draft=draft, swarm_att=att, existing={})
        runs.append((files, [c.kwargs for c in seen["lead_calls"]], seen["swarm_calls"], seen["repair_tasks"]))
    assert runs[0] == runs[1] and runs[0][2] and not runs[1][3]
    assert agent.stack_run("t-qa")["qa_repair"]["reason"] == QR.DRAFT_PATHS_UNAVAILABLE


@pytest.mark.parametrize("value", [None, [], "apps/shop/main.py", [MAIN, 1], [MAIN, None], {MAIN: 1},
                                   [f"apps/f{i}.py" for i in range(QR.DRAFT_PATHS_MAX + 1)]])
def test_an_unusable_draft_record_is_todays_regeneration(value):
    fb = _feedback(E2_TREE, _qa_diag(file="apps/testplan01-e2/main.py"))
    fb[QR.DRAFT_PATHS_FIELD] = value
    plan = QR.plan_qa_repair(fb, stack_configured=True)
    assert (plan.mode, plan.reason) == (QR.REGENERATE, QR.DRAFT_PATHS_UNAVAILABLE)


def test_no_repair_loop_still_outranks_the_missing_record():
    plan = QR.plan_qa_repair(_feedback(E2_TREE, _qa_diag(), draft_paths=None), stack_configured=False)
    assert plan.reason == "NO_REPAIR_LOOP"


# ------------------------------------------------------------------------------ (d) Do No Harm: a fresh repository
def test_fresh_repository_draft_is_todays_minus_the_platform_written_files():
    tree, paths = _build()
    today = QR.repair_draft(tree)
    restricted = QR.plan_qa_repair(_feedback(tree, _qa_diag(), draft_paths=paths), stack_configured=True).draft
    assert set(today) - set(restricted) == PLATFORM_WRITTEN and set(restricted) <= set(today)
    assert restricted == {p: t for p, t in today.items() if p not in PLATFORM_WRITTEN}
    assert QR.repair_draft(tree, frozenset(tree)) == today          # every path recorded = today's draft exactly


def test_fresh_repository_repair_of_a_qa_named_llm_file_differs_only_in_the_read_only_context():
    """The RC live-gate path: the same single repair task (same FILES TO FIX, DIAGNOSTICS and QA block), the same
    committed files. The differences are honest and both come from the platform-written files leaving the draft:
    READ-ONLY CONTEXT no longer lists the platform-written `__init__.py` files, and the assembly re-renders its
    fallback plan document (written only when the dispatch has no `plan_markdown`; the workflow always sends the
    architect's): the same lines, the file list in the draft's order, exactly as dispatch 1 rendered it.
    Fable RT (SAT-49 code review, LOW): that fallback document also carries the date of the dispatch that renders it
    (`time.strftime("%Y-%m-%d")` in DeveloperAgent._assemble_tree), so a QA repair on a later day than the tested
    build commits it with the new date; with `plan_markdown` (every workflow dispatch) the document is the
    architect's text, unchanged. Both runs here are on the same day, so their dates are equal."""
    tree, paths = _build()
    runs = []
    for dp in (sorted(tree), paths):   # today's draft (every file recorded) vs the recorded draft
        files, agent, _c, seen = _develop("off", feedback=_feedback(tree, _qa_diag(), draft_paths=dp),
                                          repairs=[{MAIN: FIXED}])
        (task,) = seen["repair_tasks"]
        assert agent.last_validation_report.status == "PASS"
        runs.append((files, task))
    (files_today, task_today), (files_now, task_now) = runs
    doc = "docs/planning/0001-initial-workload-architecture.md"
    assert set(files_now) == set(files_today) and files_now[MAIN] == FIXED
    assert {p: t for p, t in files_now.items() if p != doc} == {p: t for p, t in files_today.items() if p != doc}
    assert sorted(files_now[doc].splitlines()) == sorted(files_today[doc].splitlines())
    assert task_now["persona"] == task_today["persona"] and task_now["system"] == task_today["system"]
    head_today, ctx_today = _normalized(task_today["prompt"]).split(CONTEXT_MARK, 1)
    head_now, ctx_now = _normalized(task_now["prompt"]).split(CONTEXT_MARK, 1)
    assert head_now == head_today                                    # FILES TO FIX, DIAGNOSTICS, the QA block
    ctx_today, ctx_now = json.loads(ctx_today), json.loads(ctx_now)
    assert set(ctx_today) - set(ctx_now) == {"apps/__init__.py", "apps/shop/__init__.py"}
    assert ctx_now == {p: t for p, t in ctx_today.items() if p not in PLATFORM_WRITTEN}


def test_a_qa_finding_on_a_platform_written_file_is_now_a_regeneration():
    """Fable RT F1 (stated behaviour change): a platform-written `__init__.py` was repairable on a fresh repository;
    it is not the developer's draft, so it is today's regeneration reason FINDING_NOT_ON_A_DRAFT_FILE."""
    tree, paths = _build()
    fb = _feedback(tree, _qa_diag(file="apps/shop/__init__.py"), draft_paths=paths)
    plan = QR.plan_qa_repair(fb, stack_configured=True)
    assert (plan.mode, plan.reason) == (QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE")


def test_crash_repair_targets_are_draft_files_only():
    """Fable RT F-3 (stated in the row): a pytest crash is repaired on the test-setup files of the draft; when the
    service's only test-setup file is a platform-written `tests/__init__.py`, it is today's regeneration
    (CRASH_WITHOUT_TEST_SETUP_FILES)."""
    from test_qa_repair_on_crash import _crash
    init, test = "apps/shop/tests/__init__.py", "apps/shop/tests/test_main.py"
    tree = {MAIN: APP[MAIN], init: "# Auto-generated package init by StackVend\n", test: "def test(): pass\n"}
    today = QR.plan_qa_repair(_feedback(tree, _crash()), stack_configured=True)
    assert (today.mode, today.repairable_paths) == (QR.QA_REPAIR, {init})
    now = QR.plan_qa_repair(_feedback(tree, _crash(), draft_paths=[MAIN, test]), stack_configured=True)
    assert (now.mode, now.reason) == (QR.REGENERATE, "CRASH_WITHOUT_TEST_SETUP_FILES")


# ---------------------------------------------------------------------------- (e) the repair dispatch's own record
def test_the_qa_repair_records_its_draft_and_a_second_round_repairs_again():
    tree, paths = _e2_tree()
    files1, agent1, _c, _s = _develop("off", feedback=_feedback(tree, _qa_diag(), draft_paths=paths),
                                      repairs=[{MAIN: FIXED}])
    round1 = agent1.stack_run("t-qa")["llm_draft_paths"]
    assert round1 == sorted(QR.repair_draft(tree, frozenset(paths)))   # the restricted draft (no renames here)
    assert ROUTES not in round1
    # round 2: QA tested the repair commit (additive: the dead file is still in the repository) and failed again
    tested2 = dict(files1, **{ROUTES: STALE_ROUTES})
    fixed2 = FIXED + "\n\nclass EventOther:\n    pass\n"
    files2, agent2, _c, seen2 = _develop("off", feedback=_feedback(tested2, _qa_diag(), attempt=1,
                                                                   draft_paths=round1), repairs=[{MAIN: fixed2}])
    assert len(seen2["repair_tasks"]) == 1 and files2[MAIN] == fixed2
    assert agent2.stack_run("t-qa")["qa_repair"]["mode"] == QR.QA_REPAIR


def test_the_recorded_draft_is_the_loops_final_set_with_renamed_files():
    """Fable RT F3: a file a repair renamed into joins the loop's `llm_paths`; the record is that final set."""
    from developer_agent import repair_loop as RL
    tree, paths = _build()
    real_run = RL.RepairLoop.run

    def run_and_rename(self, draft):
        out = real_run(self, draft)
        self.ctx.llm_draft_paths.add("apps/shop/renamed.py")       # what repair_loop does for an accepted rename
        return out

    with patch.object(RL.RepairLoop, "run", run_and_rename):
        _files, agent, _c, _s = _develop("off", feedback=_feedback(tree, _qa_diag(), draft_paths=paths),
                                         repairs=[{MAIN: FIXED}])
    assert agent.stack_run("t-qa")["llm_draft_paths"] == sorted(
        set(QR.repair_draft(tree, frozenset(paths))) | {"apps/shop/renamed.py"})


# ------------------------------------------------------------------------------------- (f) the kept limitation
def test_a_qa_failure_in_a_stale_file_this_run_did_not_write_is_a_regeneration():
    """Fable RT F4 (documentation/known-limitations.md): a relaunch keeps an earlier build's files it no longer
    writes; a QA finding in one of them is not repaired in place (it is not this run's draft)."""
    tree, paths = _e2_tree()
    tree[STALE_TEST] = "from routes import route\n\n\ndef test_route():\n    assert route()\n"
    plan = QR.plan_qa_repair(_feedback(tree, _qa_diag(file=STALE_TEST, code="PY.TEST_FAILED"), draft_paths=paths),
                             stack_configured=True)
    assert (plan.mode, plan.reason, plan.seeds) == (QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", ())


def test_a_users_own_file_is_never_edited_in_place():
    """Fable RT F5: a person's own file in an imported repository is outside the draft: today's regeneration."""
    tree, paths = _build()
    tree["apps/shop/user_module.py"] = "VALUE = 1\n"
    plan = QR.plan_qa_repair(_feedback(tree, _qa_diag(file="apps/shop/user_module.py"), draft_paths=paths),
                             stack_configured=True)
    assert (plan.mode, plan.reason) == (QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE")


# ------------------------------------------------------------------------------------------- (g) the pin reason
def test_a_pin_finding_alone_keeps_its_reason_when_the_pin_is_not_a_draft_file():
    """Fable RT F1(a): `pinned()` tests the tested tree, so the reason label is unchanged."""
    draft = sorted(p for p in E2_TREE if not p.endswith(".python-version"))
    for dp in (sorted(E2_TREE), draft):
        plan = QR.plan_qa_repair(_feedback(E2_TREE, _jd(PYV, PYV_MSG), draft_paths=dp), stack_configured=True)
        # PLATFORM-RENDERED-FINDING (owner 11-13): the pin is platform-rendered: a typed stop (was REGENERATE)
        assert (plan.mode, plan.reason, plan.stop_files) == (QR.STOP, QR.PLATFORM_RENDERED_REASON, (PYV,))
        app = "apps/testplan01-e2/main.py"
        ride = QR.plan_qa_repair(_feedback(E2_TREE, _jd(PYV, PYV_MSG), _jd(app), draft_paths=dp),
                                 stack_configured=True)
        assert (ride.mode, ride.repairable_paths) == (QR.QA_REPAIR, {app})
    assert RP.is_platform_runtime_pin(PYV, E2_TREE[PYV])


# ---------------------------------------------------------------------------------------- (h) the gateway read
def _forwarded(gw, monkeypatch, draft):
    kw, _calls = cap.run(gw, monkeypatch, dict(retry_count=1), cap.qa_record(), draft=draft)
    return kw


def test_gateway_forwards_the_draft_only_for_exactly_the_tested_commit(gw, monkeypatch, caplog):
    with open(os.path.join(TESTS, "fixtures", "qa_feedback_unchanged_requests.json")) as fh:
        before = json.load(fh)
    matched = _forwarded(gw, monkeypatch, "match")
    fb = matched.pop("qa_feedback")
    assert fb[QR.DRAFT_PATHS_FIELD] == sorted(cap.TREE)
    assert cap.canonical(matched) == before["no_record"]            # everything else is unchanged
    base = {k: v for k, v in fb.items() if k != QR.DRAFT_PATHS_FIELD}
    for draft in (None, cap.committed_draft(sha=cap.OTHER_SHA), {"commit_sha": cap.SHA},
                  {"commit_sha": cap.SHA, "llm_draft_paths": [1]}, {"commit_sha": cap.SHA, "llm_draft_paths": []}):
        caplog.clear()
        kw = _forwarded(gw, monkeypatch, draft)
        other = kw.pop("qa_feedback")
        assert QR.DRAFT_PATHS_FIELD not in other and other == base, draft
        assert cap.canonical(kw) == before["no_record"]
        assert "DRAFT_PATHS_UNAVAILABLE" in caplog.text
        assert QR.plan_qa_repair(other, stack_configured=True).reason == QR.DRAFT_PATHS_UNAVAILABLE
    assert QR.plan_qa_repair(fb, stack_configured=True).mode == QR.QA_REPAIR


def test_gateway_unmatched_qa_retries_never_read_or_forward_a_draft(gw, monkeypatch):
    for name, (overrides, record, db_mode, backend_mode) in cap.scenarios().items():
        kw, _calls = cap.run(gw, monkeypatch, overrides, record, db_mode, backend_mode)
        assert "qa_feedback" not in kw and "deploy_draft_paths" not in kw, name


# ------------------------------------------------------------------------------------------- (i) the record write
def _agent_with(paths):
    return MagicMock(stack_run=MagicMock(return_value={"llm_draft_paths": paths} if paths is not None else {}))


# QA-REPAIR-KEEPS-ORPHAN-DELETIONS: both keys always written (no deletion, no committed-path list in these results);
# RT14-13: the base head the commit's base check saw, always written too (None: not checked in these results)
NO_EXTRAS = {QR.ORPHAN_DELETIONS_FIELD: [], QR.COMMITTED_PATHS_FIELD: None, QR.BASE_HEAD_SHA_FIELD: None}


def _committed(sha="c" * 40, status="COMMITTED"):
    return {"status": status, "commit_sha": sha, "branch_name": "castor/svc-1"}


def test_record_committed_draft_writes_exactly_the_commit_and_the_sorted_paths(gw, monkeypatch):
    db = FakeDB()
    monkeypatch.setattr(gw, "db", db)
    gw._record_committed_draft(_agent_with(["b.py", "a.py"]), "t-1", _committed())
    assert db.writes == [("pipeline_executions/t-1", {"stages": {"developer": {"committed_draft": {
        "commit_sha": "c" * 40, "llm_draft_paths": ["a.py", "b.py"], **NO_EXTRAS}}}}, True)]


@pytest.mark.parametrize("paths,result,reason", [
    (None, _committed(), "NO_DRAFT_PATHS"),
    ([], _committed(), "NO_DRAFT_PATHS"),
    (["a.py", 1], _committed(), "NO_DRAFT_PATHS"),
    ([f"f{i}.py" for i in range(2001)], _committed(), "TOO_MANY_PATHS"),
])
def test_record_committed_draft_refuses_loudly_and_never_raises(gw, monkeypatch, caplog, paths, result, reason):
    db = FakeDB()
    monkeypatch.setattr(gw, "db", db)
    with caplog.at_level(logging.ERROR):
        gw._record_committed_draft(_agent_with(paths), "t-1", result)
    assert db.writes == [] and gw.COMMITTED_DRAFT_NOT_RECORDED in caplog.text and reason in caplog.text


def test_record_committed_draft_write_failure_is_logged_never_raised(gw, monkeypatch, caplog):
    db = FakeDB()
    db.fail_writes = True
    monkeypatch.setattr(gw, "db", db)
    with caplog.at_level(logging.ERROR):
        gw._record_committed_draft(_agent_with(["a.py"]), "t-1", _committed())
    assert "COMMITTED_DRAFT_NOT_RECORDED" in caplog.text and "WRITE_FAILED" in caplog.text
    monkeypatch.setattr(gw, "db", None)
    gw._record_committed_draft(_agent_with(["a.py"]), "t-1", _committed())   # no store: logged, no raise


@pytest.mark.parametrize("result,written", [
    (_committed(), True),
    (_committed(status="SUCCESS"), True),       # the PyGithub fallback path (the same rule as _record_pr_ledger)
    (_committed(status="FAILED"), False),
    (_committed(status="MOCK"), False),
    (_committed(sha="main"), False),
    (_committed(sha=None), False),
])
def test_record_committed_draft_only_for_a_committed_sha(gw, monkeypatch, result, written):
    db = FakeDB()
    monkeypatch.setattr(gw, "db", db)
    gw._record_committed_draft(_agent_with(["a.py"]), "t-1", result)
    assert bool(db.writes) is written
    if written:
        assert db.writes[0][1]["stages"]["developer"]["committed_draft"] == {"commit_sha": "c" * 40,
                                                                             "llm_draft_paths": ["a.py"], **NO_EXTRAS}


def test_the_developer_dispatch_records_its_commit(gw, monkeypatch):
    """Through _execute_developer_logic: after commit_and_open_pr COMMITTED, the record of exactly that commit."""
    dbs = []
    monkeypatch.setattr(gw.developer_agent, "stack_run", lambda trace: {"llm_draft_paths": ["apps/svc/main.py"]})
    cap.run(gw, monkeypatch, dict(retry_count=0), None, draft=None, db_out=dbs)
    rec = dbs[0].docs[f"pipeline_executions/{cap.TRACE}"]["stages"]["developer"]["committed_draft"]
    assert {k: v for k, v in rec.items() if k not in NO_EXTRAS} == {"commit_sha": "c" * 40,
                                                                  "llm_draft_paths": ["apps/svc/main.py"]}
    assert rec[QR.ORPHAN_DELETIONS_FIELD] == []


def test_the_qa_repair_decision_is_persisted_for_the_operator():
    """Fable RT F6: the QA-FEEDBACK decision (mode, typed reason, commit) on stages.developer.qa_repair."""
    from developer_agent import handler as h
    from test_typed_iac_ti3_contract import PID, Client, _agent, _runtime
    agent = _agent(_runtime(Client()))
    db = FakeDB()
    agent.db = db
    assert h.DeveloperAgent._plan_qa_repair(agent, PID, "t-p", {"qa_feedback": _feedback(
        E2_TREE, _qa_diag(), draft_paths=None)}) is None
    rec = db.docs["pipeline_executions/t-p"]["stages"]["developer"]["qa_repair"]
    assert rec["reason"] == QR.DRAFT_PATHS_UNAVAILABLE
    # Fable RT F-4: every key always (Firestore merges leaf by leaf, so a missing key would keep a stale value)
    # QA-REPAIR-MISSING-MODULE: + missing_modules (the typed missing-module outcomes; [] without one)
    # QA-FINDING-ON-UNOWNED-FILE / PLATFORM-RENDERED-FINDING: + unowned_check, stop_files (None / [] when not used)
    assert set(rec) == {"mode", "reason", "attempt", "commit_sha", "findings", "seeds", "budget", "missing_modules",
                        "unowned_check", "stop_files"}
    assert rec["unowned_check"] is None and rec["stop_files"] == []
    assert rec["budget"] is None and rec["seeds"] == [] and rec["missing_modules"] == []
    db.fail_writes = True   # a failed write never changes the decision
    got = h.DeveloperAgent._plan_qa_repair(agent, PID, "t-p", {"qa_feedback": _feedback(
        E2_TREE, _qa_diag(file="apps/testplan01-e2/main.py"))})
    assert got is not None and got.mode == QR.QA_REPAIR
