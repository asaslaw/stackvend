"""STOP-KEEPS-EVIDENCE (owner 11-14, item C of docs/handoff/ex08-1114-qa-routing-diagnosis.md; plan
docs/planning/stop-keeps-evidence-plan.md).

Before: the gateway's `_execute_developer_logic` superseded the earlier StackVend PRs (closed the tested PR, deleted
its branch) BEFORE `generate_code_files` decided the QA repair plan, so a run that then STOPPED (PLATFORM_DEFECT
QA_FINDING_ON_PLATFORM_RENDERED_FILE, OPERATOR_ACTION_REQUIRED QA_FINDING_ON_UNOWNED_FILE, any typed failure) had
lost its evidence branch (ex08-1114: branch deleted 19:47:01, stop 19:47:02).
After: the reconcile runs only once this dispatch's own commit landed (RT F2), with the same keep_branch, and is
skipped (never raised) once the stage answered (RT F1); on a stop (generation or commit time) nothing is closed or
deleted and the typed stop names the tested branch / PR (details.evidence + its message). Class, reason, stage and
diagnostics are unchanged.
The synchronous route and the G7 stage-job body run the same `_execute_developer_logic`.
Hermetic: FakeDB, fake source backend, the developer agent's generate / commit replaced by recorders.
"""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import sys

import pytest

TESTS = os.path.dirname(os.path.abspath(__file__))
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

import qa_feedback_capture as cap  # noqa: E402
from fd4f_support import FakeBackend, FakeDB, backend_factory, gw  # noqa: E402,F401  (gw: gateway fixture)

REPO = os.path.dirname(TESTS)
GATEWAY_MAIN = os.path.join(REPO, "apps", "orchestrator-gateway", "main.py")
PR_URL = "https://example.invalid/example-org/svc/pull/2"
FILES = {"apps/svc/main.py": "x = 1\n"}


def _ledger_entry(**over):
    e = {"ledger_id": "led-tested", "product_id": cap.PID, "origin": "DEVELOPER", "provider": "GITHUB",
         "branch": cap.BRANCH, "head_sha": cap.SHA, "pr_number": 2, "pr_url": PR_URL, "state": "OPEN",
         "trace_id": cap.TRACE}
    e.update(over)
    return e


def _stop(kind):
    """The real typed stops of developer_agent/qa_repair.stop_error (and two other typed failures)."""
    from developer_agent import qa_repair as QR
    from gate_errors import GateUnavailableError
    plan = QR.QARepairPlan(QR.STOP, QR.PLATFORM_RENDERED_REASON, 0, cap.SHA,
                           stop_files=("infra/workload/topology.json",))
    feedback = {"diagnostics": [{"tool": "judge", "code": "JUDGE.ADHERENCE", "severity": "error",
                                 "file": "infra/workload/topology.json"}]}
    if kind == "platform_rendered":
        return QR.stop_error(plan, cap.PID, feedback)
    if kind == "unowned":
        outcome = {"files": [{"file": "apps/svc/legacy.py", "owner": "UNKNOWN", "cleanup": "NOT_PLATFORM_WRITTEN",
                              "stop": "INTRINSIC"}]}
        return QR.stop_error(plan, cap.PID, feedback, outcome)
    if kind == "gate_unavailable":
        return GateUnavailableError("developer called without a compliance decision", stage="developer",
                                    reason="COMPLIANCE_DECISION_MISSING")
    if kind == "stage_error":
        from developer_agent.errors import LLM_UNAVAILABLE, DeveloperStageError
        return DeveloperStageError(LLM_UNAVAILABLE, "no LLM client configured for the developer agent")
    raise AssertionError(kind)


def _dispatch(gw, monkeypatch, *, generate, record=True, ledger=(), db_fail_ledger=False, route="logic",
              commit=None, sd=None):
    """One gateway developer dispatch (QA retry 1 of cap.TRACE unless `record` is False); with `sd`, the logic runs
    under stage_deadline.run_with_deadline(sd, ...). Returns (result or raised exception, reconcile calls, commit
    calls, call order)."""
    db = FakeDB()
    db.docs[f"workloads/{cap.PID}/compliance_audits/{cap.TRACE}"] = {
        "product_id": cap.PID, "trace_id": cap.TRACE, "allow_unauthenticated": True, "enable_direct_iap": False,
        "domain_restricted_sharing": False, "allowed_domains": []}
    if record:
        db.docs[f"qa_test_runs/{cap.TRACE}"] = cap.qa_record()
        db.docs[f"pipeline_executions/{cap.TRACE}"] = {"stages": {"developer": {
            "committed_draft": cap.committed_draft()}}}
    for e in ledger:
        db.docs[f"vcs_ledger/{e['ledger_id']}"] = dict(e)
    if db_fail_ledger:
        class _NoLedger:
            def __init__(self, inner):
                self._inner = inner

            def collection(self, name):
                if name == "vcs_ledger":
                    raise RuntimeError("ledger store down")
                return self._inner.collection(name)
        store = _NoLedger(db)
    else:
        store = db
    monkeypatch.setattr(gw, "db", store)
    backend = FakeBackend({cap.BRANCH: {p: t.encode() for p, t in cap.TREE.items()}}, {cap.BRANCH: cap.SHA})
    monkeypatch.setattr(gw, "get_source_backend_factory", lambda: backend_factory(backend))
    reconciles, commits, order = [], [], []

    def reconcile(product_id, trace_id, keep_branch):
        order.append("reconcile")
        reconciles.append((product_id, trace_id, keep_branch))

    def gen(**kw):
        order.append("generate")
        return generate(**kw)

    def do_commit(**kw):
        order.append("commit")
        commits.append(kw)
        gw.stage_deadline.guard_side_effect("developer.commit")   # as the real commit_and_open_pr does
        if commit is not None:
            return commit(**kw)
        return {"status": "COMMITTED", "branch_name": kw["branch_name"], "commit_sha": "c" * 40,
                "files_committed": sorted(kw["files"]), "pull_request_url": "https://example.invalid/pr/3"}
    monkeypatch.setattr(gw, "_reconcile_superseded_prs", reconcile)
    monkeypatch.setattr(gw.developer_agent, "generate_code_files", gen)
    monkeypatch.setattr(gw.developer_agent, "commit_and_open_pr", do_commit)
    monkeypatch.setattr(gw, "_assert_tf_remediation_allowed", lambda *a, **k: None)
    monkeypatch.setattr(gw, "_record_pr_ledger", lambda *a, **k: None)
    fields = dict(product_id=cap.PID, trace_id=cap.TRACE, spec_text="audit service",
                  task_dag=[{"task_id": "t1", "title": "svc"}], retry_count=1 if record else 0)
    try:
        if sd is not None:
            out = gw.stage_deadline.run_with_deadline(
                sd, lambda: gw._execute_developer_logic(gw.DeveloperExecuteRequest(**fields)))
        elif route == "logic":
            out = gw._execute_developer_logic(gw.DeveloperExecuteRequest(**fields))
        elif route == "sync":
            out = gw._developer_execute_body(gw.DeveloperExecuteRequest(**fields))
        else:   # G7: the stage-runner job's body (the stored request rebuilt with the job route's model)
            out = gw.stage_job_body("developer", dict(fields, callback_url="https://example.invalid/cb"))()
    except Exception as e:  # noqa: BLE001 - the outcome under test
        out = e
    return out, reconciles, commits, order


def _raiser(kind):
    def gen(**kw):
        assert kw.get("qa_feedback") is not None   # the plan is decided with the tested evidence in hand
        raise _stop(kind)
    return gen


# ===================================================================== a typed stop keeps the evidence
@pytest.mark.parametrize("kind, error_class, reason", [
    ("platform_rendered", "PLATFORM_DEFECT", "QA_FINDING_ON_PLATFORM_RENDERED_FILE"),
    ("unowned", "OPERATOR_ACTION_REQUIRED", "QA_FINDING_ON_UNOWNED_FILE"),
    ("gate_unavailable", "GATE_UNAVAILABLE", "COMPLIANCE_DECISION_MISSING"),
])
def test_typed_stop_skips_the_reconcile_and_names_the_kept_pr(gw, monkeypatch, kind, error_class, reason):
    out, reconciles, commits, order = _dispatch(gw, monkeypatch, generate=_raiser(kind), ledger=[_ledger_entry()])
    assert isinstance(out, gw.GateError)
    assert reconciles == [] and commits == [] and order == ["generate"]
    assert (out.error_class.value, out.reason) == (error_class, reason)     # class / reason / stage unchanged
    ev = dict(out.details["evidence"])
    summary = ev.pop("summary")                     # RT F3: the sentence travels with the evidence
    assert ev == {"branch": cap.BRANCH, "commit_sha": cap.SHA, "pr_lookup": "FOUND",
                  "pull_request": {"number": 2, "url": PR_URL, "ledger_state": "OPEN", "ledger_id": "led-tested"}}
    assert out.message.endswith(" " + summary) and summary.startswith("Evidence kept:")
    body = out.to_body()
    assert cap.BRANCH in body["summary"] and cap.SHA in body["summary"] and "#2" in body["summary"]
    assert str(out) == out.message and "STOP-KEEPS-EVIDENCE" in out.message
    assert body["details"]["evidence"]["branch"] == cap.BRANCH


def test_stop_message_and_diagnostics_keep_the_original_text(gw, monkeypatch):
    original = _stop("platform_rendered")
    out, *_ = _dispatch(gw, monkeypatch, generate=_raiser("platform_rendered"), ledger=[_ledger_entry()])
    assert out.message.startswith(original.message + " Evidence kept:")
    assert out.diagnostics == original.diagnostics and out.stage == original.stage == "qa"
    assert {k: v for k, v in out.details.items() if k != "evidence"} == original.details


@pytest.mark.parametrize("ledger, fail, lookup", [
    ((), False, "NOT_IN_LEDGER"),
    ((_ledger_entry(head_sha="d" * 40),), False, "NOT_IN_LEDGER"),       # another commit on the branch: no match
    ((_ledger_entry(branch="castor/svc-other"),), False, "NOT_IN_LEDGER"),
    ((_ledger_entry(origin="IAC_UPGRADE"),), False, "NOT_IN_LEDGER"),
    ((), True, "LEDGER_UNAVAILABLE"),
])
def test_stop_names_the_branch_when_the_pr_is_not_exactly_in_the_ledger(gw, monkeypatch, ledger, fail, lookup):
    out, reconciles, *_ = _dispatch(gw, monkeypatch, generate=_raiser("platform_rendered"), ledger=ledger,
                                    db_fail_ledger=fail)
    assert isinstance(out, gw.PlatformDefectError) and reconciles == []
    ev = out.details["evidence"]
    assert (ev["branch"], ev["commit_sha"], ev["pull_request"], ev["pr_lookup"]) == (cap.BRANCH, cap.SHA, None,
                                                                                      lookup)
    assert cap.BRANCH in out.message and "pull request #" not in out.message


def test_untyped_and_stage_failures_also_keep_the_prs(gw, monkeypatch):
    for gen in (_raiser("stage_error"), lambda **kw: (_ for _ in ()).throw(RuntimeError("model down"))):
        out, reconciles, commits, order = _dispatch(gw, monkeypatch, generate=gen, ledger=[_ledger_entry()])
        assert isinstance(out, Exception) and not isinstance(out, gw.GateError)
        assert reconciles == [] and commits == [] and order == ["generate"]


def test_first_build_stop_attaches_no_evidence(gw, monkeypatch):
    """No matched QA feedback (a first build): nothing is named, nothing is closed, the stop is unchanged."""
    def gen(**kw):
        assert "qa_feedback" not in kw
        raise _stop("gate_unavailable")
    out, reconciles, *_ = _dispatch(gw, monkeypatch, generate=gen, record=False)
    assert isinstance(out, gw.GateUnavailableError) and reconciles == []
    assert "evidence" not in out.details and "Evidence kept" not in out.message


def _answered_deadline(gw):
    """A developer StageDeadline the runner already answered (504 / abandon): every later side effect must refuse."""
    sdm = gw.stage_deadline
    sd = sdm.StageDeadline(sdm.budget_for("developer", sdm.StageMode.SYNC), trace_id=cap.TRACE, product_id=cap.PID)
    sd.abandon("ANSWERED", "the stage deadline answered while the stage was still running", quiet=True)
    return sd


def test_rt_f1_reconcile_is_refused_once_the_stage_answered(gw, monkeypatch):
    """RT F1: a generation that returns after the stage answered closes and deletes nothing (the reconcile is a
    repository write); the commit's own orphan guard refuses first (RT F2: the reconcile follows the commit), and the
    refusal is the typed StageAbandonedError and names the kept branch."""
    sdm = gw.stage_deadline
    sd = _answered_deadline(gw)
    tok = sdm._CURRENT.set(sd)
    try:
        out, reconciles, commits, order = _dispatch(gw, monkeypatch, generate=lambda **kw: dict(FILES),
                                                    ledger=[_ledger_entry()])
    finally:
        sdm._CURRENT.reset(tok)
    assert isinstance(out, gw.GateError) and out.error_class.value == "STAGE_ABANDONED", out
    assert out.reason == "ANSWERED" and "developer.commit" in out.message
    assert reconciles == [] and order == ["generate", "commit"]
    assert out.details["evidence"]["branch"] == cap.BRANCH and sd.abandon_observed


def test_rt_f2_reconcile_is_skipped_not_raised_when_the_stage_answers_after_the_commit(gw, monkeypatch, caplog):
    """RT F2: the commit landed, then the stage answered: the reconcile is skipped with a log line and the landed
    commit is never turned into a failed stage."""
    sdm = gw.stage_deadline
    sd = sdm.StageDeadline(sdm.budget_for("developer", sdm.StageMode.SYNC), trace_id=cap.TRACE, product_id=cap.PID)

    def landed_then_answered(**kw):
        sd.abandon("ANSWERED", "the stage deadline answered while the stage was still running", quiet=True)
        return {"status": "COMMITTED", "branch_name": kw["branch_name"], "commit_sha": "c" * 40,
                "files_committed": sorted(kw["files"]), "pull_request_url": "https://example.invalid/pr/3"}
    tok = sdm._CURRENT.set(sd)
    try:
        with caplog.at_level("WARNING"):
            out, reconciles, commits, order = _dispatch(gw, monkeypatch, generate=lambda **kw: dict(FILES),
                                                        ledger=[_ledger_entry()], commit=landed_then_answered)
    finally:
        sdm._CURRENT.reset(tok)
    assert isinstance(out, dict) and out["status"] == "SUCCESS", out
    assert reconciles == [] and order == ["generate", "commit"] and not sd.abandon_observed
    assert any("PR ledger reconcile skipped" in r.getMessage() and "ANSWERED" in r.getMessage()
               for r in caplog.records)


def test_answered_accessor(gw):
    sdm = gw.stage_deadline
    assert sdm.answered() is None                        # no stage deadline
    sd = sdm.StageDeadline(sdm.budget_for("developer", sdm.StageMode.SYNC))
    tok = sdm._CURRENT.set(sd)
    try:
        assert sdm.answered() is None
        sd.abandon("RUN_ENDED", "run ended", quiet=True)
        assert sdm.answered() == ("RUN_ENDED", "run ended") and not sd.abandon_observed   # never raises
    finally:
        sdm._CURRENT.reset(tok)


# ===================================================================== Do No Harm: a proceeding plan cleans up
@pytest.mark.parametrize("record", [True, False], ids=["qa_repair_or_regeneration", "first_build"])
def test_negative_proceeding_dispatch_reconciles_exactly_as_before(gw, monkeypatch, record):
    out, reconciles, commits, order = _dispatch(gw, monkeypatch, generate=lambda **kw: dict(FILES), record=record,
                                                ledger=[_ledger_entry()])
    assert isinstance(out, dict) and out["status"] == "SUCCESS", out
    [(pid, trace, keep)] = reconciles
    assert (pid, trace) == (cap.PID, cap.TRACE)
    assert keep == out["branch_name"] == commits[0]["branch_name"] and keep.startswith(f"castor/{cap.PID}-")
    assert order == ["generate", "commit", "reconcile"]   # RT F2: after this dispatch's own commit
    assert "evidence" not in out


def test_rt_f2_commit_failure_keeps_the_prs_and_logs_the_evidence(gw, monkeypatch, caplog):
    """RT F2 (inverted): a commit failure after a proceeding plan closes and deletes nothing (the reconcile follows
    a landed commit only); the failure is raised unchanged and logged with the tested branch."""
    real_commit = []

    def failing_commit(**kw):
        real_commit.append(kw)
        return {"status": "FAILED", "error": "push rejected"}
    with caplog.at_level("ERROR"):
        out, reconciles, _, order = _dispatch(gw, monkeypatch, generate=lambda **kw: dict(FILES),
                                              commit=failing_commit, ledger=[_ledger_entry()])
    assert isinstance(out, RuntimeError) and "push rejected" in str(out)
    assert reconciles == [] and len(real_commit) == 1 and order == ["generate", "commit"]
    assert any("Evidence kept" in r.getMessage() and cap.BRANCH in r.getMessage() for r in caplog.records)


def _precommit_failed():
    from gate_errors import GateFailedError
    return GateFailedError("Gatekeeper pre-commit verification failed: ['x']", reason="PRECOMMIT_VERIFY_FAILED",
                           stage="developer")


def _no_credential():
    from gate_errors import GateUnavailableError
    return GateUnavailableError("no VCS credential for example-org/svc; the developer stage cannot commit",
                                reason="VCS_CREDENTIAL_UNAVAILABLE", stage="developer")


@pytest.mark.parametrize("make, error_class, reason", [
    (_precommit_failed, "CODE_DEFECT", "PRECOMMIT_VERIFY_FAILED"),
    (_no_credential, "GATE_UNAVAILABLE", "VCS_CREDENTIAL_UNAVAILABLE"),
])
def test_rt_f2_typed_commit_time_stop_keeps_and_names_the_tested_pr(gw, monkeypatch, make, error_class, reason):
    def stopping_commit(**kw):
        raise make()
    out, reconciles, _, order = _dispatch(gw, monkeypatch, generate=lambda **kw: dict(FILES),
                                          commit=stopping_commit, ledger=[_ledger_entry()])
    assert isinstance(out, gw.GateError) and (out.error_class.value, out.reason) == (error_class, reason)
    assert reconciles == [] and order == ["generate", "commit"]
    assert out.details["evidence"]["pull_request"]["number"] == 2 and "STOP-KEEPS-EVIDENCE" in out.message


# ===================================================================== both routes: synchronous and G7 stage job
@pytest.mark.parametrize("route", ["sync", "job"])
def test_sync_route_and_stage_job_body_keep_the_evidence_the_same_way(gw, monkeypatch, route):
    out, reconciles, commits, _ = _dispatch(gw, monkeypatch, generate=_raiser("platform_rendered"),
                                            ledger=[_ledger_entry()], route=route)
    assert isinstance(out, gw.PlatformDefectError) and reconciles == [] and commits == []
    assert out.details["evidence"]["pull_request"]["url"] == PR_URL


@pytest.mark.parametrize("route", ["sync", "job"])
def test_negative_sync_route_and_stage_job_body_reconcile_when_proceeding(gw, monkeypatch, route):
    out, reconciles, commits, order = _dispatch(gw, monkeypatch, generate=lambda **kw: dict(FILES), route=route)
    assert isinstance(out, dict) and out["status"] == "SUCCESS"
    assert len(reconciles) == 1 and order == ["generate", "commit", "reconcile"]


def test_attach_is_idempotent_and_never_raises(gw, monkeypatch):
    monkeypatch.setattr(gw, "db", FakeDB())
    stop = _stop("platform_rendered")
    fb = {"branch_name": cap.BRANCH, "commit_sha": cap.SHA}
    gw._attach_kept_evidence(stop, cap.PID, fb)
    first = stop.message
    gw._attach_kept_evidence(stop, cap.PID, fb)
    assert stop.message == first and first.count("Evidence kept") == 1
    for bad in (None, {}, {"branch_name": cap.BRANCH}, {"branch_name": 3, "commit_sha": cap.SHA}, "x"):
        s = _stop("platform_rendered")
        gw._attach_kept_evidence(s, cap.PID, bad)
        assert "evidence" not in s.details


# ===================================================================== structure: reconcile after the commit
def test_reconcile_follows_the_commit_in_execute_developer_logic():
    tree = ast.parse(open(GATEWAY_MAIN, encoding="utf-8").read())
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_execute_developer_logic")
    lines = {}
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            name = getattr(n.func, "attr", None) or getattr(n.func, "id", None)
            lines.setdefault(name, []).append(n.lineno)
    [gen] = lines["generate_code_files"]
    [rec] = lines["_reconcile_superseded_prs"]
    [com] = [ln for ln in lines["commit_and_open_pr"] if ln > gen]
    assert gen < com < rec                                  # RT F2: generate < commit < reconcile


# ===================================================================== RT F3: a replacing deadline answer keeps it
class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _late_stop(gw, sd, *, abandon=False):
    """A generation that observes (and swallows) the deadline / an abandon, then raises the QA plan's typed stop."""
    def gen(**kw):
        if abandon:
            sd.abandon("RUN_ENDED", "run is FAILED", quiet=True)
        else:
            sd._clock.t += sd.budget.budget_s + 1    # past the deadline, before the hard answer
        try:
            gw.stage_deadline.checkpoint("developer.qa_repair")
        except gw.GateError:
            pass
        raise _stop("platform_rendered")
    return gen


@pytest.mark.parametrize("abandon, error_class", [(False, "STAGE_DEADLINE_EXCEEDED"), (True, "STAGE_ABANDONED")])
def test_rt_f3_replacing_deadline_answer_still_names_the_kept_branch(gw, monkeypatch, abandon, error_class):
    sdm = gw.stage_deadline
    sd = sdm.StageDeadline(sdm.budget_for("developer", sdm.StageMode.SYNC), trace_id=cap.TRACE, product_id=cap.PID,
                           clock=_Clock())
    out, reconciles, commits, _ = _dispatch(gw, monkeypatch, generate=_late_stop(gw, sd, abandon=abandon),
                                            ledger=[_ledger_entry()], sd=sd)
    assert isinstance(out, gw.GateError) and out.error_class.value == error_class, out
    assert isinstance(out.__cause__, gw.PlatformDefectError)          # the body's own stop, chained
    assert out.details["evidence"] == out.__cause__.details["evidence"]
    assert out.details["evidence"]["pull_request"]["number"] == 2 and "progress" in out.details
    assert out.message.endswith(" " + out.details["evidence"]["summary"]) and str(out) == out.message
    assert cap.BRANCH in out.to_body()["summary"]
    assert reconciles == [] and commits == []


def test_rt_f3_negative_replacement_without_evidence_is_unchanged(gw, monkeypatch):
    """Do No Harm: a body error that names no evidence (a first build) leaves the replacement answer as it was."""
    sdm = gw.stage_deadline
    sd = sdm.StageDeadline(sdm.budget_for("developer", sdm.StageMode.SYNC), trace_id=cap.TRACE, product_id=cap.PID,
                           clock=_Clock())
    out, *_ = _dispatch(gw, monkeypatch, generate=_late_stop(gw, sd), record=False, sd=sd)
    assert isinstance(out, gw.GateError) and out.error_class.value == "STAGE_DEADLINE_EXCEEDED"
    assert "evidence" not in out.details
    assert out.message == sd.exceeded("(the stage failed after its deadline)").message
