"""JUDGE-GATE-ENUMERATED-FINDINGS (owner 11-13, plan docs/planning/judge-gate-enumerated-findings-plan.md).

QA Stage 2 blocks only on enumerated, typed judge findings (a critical vulnerability, a missed directive). The judge's
adherence / grounding scores are recorded and reported, never a blocking reason by themselves (ex02-1113: "Adherence
score 0.92 is below mandatory 0.95 threshold" on byte-identical files that passed earlier attempts). A failed lens
verdict that lists nothing is no verdict (GATE_UNAVAILABLE); judge findings are fingerprinted by typed fields
(code, task_id, file, facet) so NO_PROGRESS can fire on a reworded repeat. Fake judges only: no network, no LLM."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import json

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import (SHA_A, SHA_B, FakeBackend, FakeDB, FakeQAClient, backend_factory, passing_outcome,
                          sdk_response, seed_context)
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse)

import qa_auditor.coordinator as coord_mod  # noqa: E402
import qa_auditor.judge as judge_mod  # noqa: E402
import release_gatekeeper as RG  # noqa: E402
from qa_auditor.platform_facts import build_platform_facts  # noqa: E402
from qa_auditor import DualLensAuditorCoordinator, LensUnavailableError  # noqa: E402
from qa_auditor.security_lens import evaluate_security_lens  # noqa: E402
from shared.qa_audit_schemas import AdherenceLensResult, SecurityLensResult  # noqa: E402

BRANCH = "castor/app-1"
APPMAIN = "apps/api/main.py"
DAG = [
    {"task_id": "CODE-01", "category": "CODE", "target_files": [APPMAIN]},
    {"task_id": "CODE-02", "category": "CODE", "target_files": ["apps/api/orders.py"]},
]
TREE = {APPMAIN: b"x = 1\n", "apps/api/orders.py": b"y = 2\n", "tests/test_main.py": b"def test(): pass\n"}
STAMP = "stage2_judge"   # developer_agent.qa_repair.JUDGE_FINDING_FIELD


def _judge(missed=(), *, adh=1.0, gnd=1.0, task_ids=None, files=None, crit=(), crit_files=None, sec_passed=None):
    def _call(prompt, model, **kw):
        if "Security Engineer" in prompt:
            body = {"passed": (not crit) if sec_passed is None else sec_passed,
                    "critical_vulnerabilities": list(crit)}
            if crit_files is not None:
                body["critical_vulnerability_files"] = crit_files
            return json.dumps(body)
        body = {"instruction_adherence_score": adh, "grounding_score": gnd, "missed_directives": list(missed),
                "hallucinated_features": [], "summary": "s"}
        if task_ids is not None:
            body["missed_directive_task_ids"] = task_ids
        if files is not None:
            body["missed_directive_files"] = files
        return json.dumps(body)
    return _call


def _stage_two(monkeypatch, judge):
    monkeypatch.setattr(judge_mod, "call", judge)
    return DualLensAuditorCoordinator(timeout_seconds=300.0).evaluate_stage_two(
        git_diff="+x", determ_report={"passed": True, "summary": "ok"}, task_dag=DAG, ingress_policy={},
        model_name="m", platform_facts=build_platform_facts(None, "off", DAG))


# ======================================================================================== gate rule: scenario table
@pytest.mark.parametrize("name,judge,passed,reasons", [
    # low score + enumerated finding: blocks on the finding only (the score is no reason of its own)
    ("low score + finding", _judge(["no /health endpoint"], adh=0.80), False, ["Missed Directive: no /health endpoint"]),
    # low adherence score, nothing listed: advisory, passes
    ("low adherence, no finding", _judge(adh=0.80), True, []),
    # low grounding score, nothing listed: advisory, passes
    ("low grounding, no finding", _judge(gnd=0.60), True, []),
    # high score + enumerated finding: blocks exactly as before
    ("high score + finding", _judge(["no /health endpoint"], adh=0.99), False,
     ["Missed Directive: no /health endpoint"]),
    # a security critical blocks whatever the scores
    ("security critical", _judge(crit=["admin route trusts X-User header"], adh=1.0), False,
     ["Security: admin route trusts X-User header"]),
])
def test_gate_blocks_only_on_enumerated_findings(monkeypatch, name, judge, passed, reasons):
    sec, adh, rep = _stage_two(monkeypatch, judge)
    assert rep.passed is passed and adh.passed is (not adh.missed_directives)
    assert rep.blocking_reasons == reasons
    assert not any("score" in r.lower() for r in rep.blocking_reasons)


@pytest.mark.parametrize("adh,gnd,noted", [(0.80, 1.0, True), (1.0, 0.60, True), (0.95, 0.95, False),
                                           (1.0, 1.0, False)])
def test_scores_stay_recorded_and_reported_as_informational(monkeypatch, adh, gnd, noted):
    _sec, lens, rep = _stage_two(monkeypatch, _judge(adh=adh, gnd=gnd))
    assert (lens.instruction_adherence_score, lens.grounding_score) == (adh, gnd)   # recorded as the judge gave them
    assert rep.passed is True
    assert ("informational, not a blocking reason" in rep.summary) is noted
    if noted:
        assert f"Adherence score {adh:.2f}, grounding score {gnd:.2f}" in rep.summary


# ======================================================================================== F1: the contradiction floor
@pytest.mark.parametrize("adh", [0.80, 0.85, 0.88, 0.92, 0.949])
def test_flicker_range_with_nothing_listed_is_informational(monkeypatch, adh):
    """The live flicker cases (ex02 / ex09: 0.85 to 0.92) pass with nothing listed; 0.80 is the floor itself."""
    _sec, lens, rep = _stage_two(monkeypatch, _judge(adh=adh))
    assert rep.passed is True and lens.instruction_adherence_score == adh and rep.blocking_reasons == []


@pytest.mark.parametrize("adh,gnd", [(0.05, 0.0), (0.5, 1.0), (0.79, 1.0)])
def test_below_the_floor_with_nothing_listed_is_no_verdict(monkeypatch, adh, gnd):
    """RT dry run: 0.05 / 0.00 with nothing listed used to pass and auto-merge on this branch. Now no verdict."""
    with pytest.raises(LensUnavailableError, match="contradictory answer"):
        _stage_two(monkeypatch, _judge(adh=adh, gnd=gnd))


def test_below_the_floor_with_a_listed_directive_blocks_on_the_directive_only(monkeypatch):
    _sec, _adh, rep = _stage_two(monkeypatch, _judge(["no /health endpoint"], adh=0.05, gnd=0.0))
    assert rep.passed is False and rep.blocking_reasons == ["Missed Directive: no /health endpoint"]


ADH_LOW_NOTHING = json.dumps({"instruction_adherence_score": 0.79, "grounding_score": 1.0, "missed_directives": [],
                              "summary": "s"})
ADH_OK = json.dumps({"instruction_adherence_score": 0.92, "grounding_score": 1.0, "missed_directives": [],
                     "summary": "s"})


def test_below_the_floor_is_asked_again_once(monkeypatch):
    from qa_auditor.adherence_lens import evaluate_adherence_lens
    c = _Client(sdk_response(ADH_LOW_NOTHING), sdk_response(ADH_OK))
    monkeypatch.setattr(judge_mod, "_client", c)
    res = evaluate_adherence_lens("+x", task_dag=DAG, model_name="gemini-4-carbon")
    assert res.passed is True and res.instruction_adherence_score == 0.92 and c.calls == 2


def test_below_the_floor_twice_is_unavailable(monkeypatch):
    from qa_auditor.adherence_lens import evaluate_adherence_lens
    c = _Client(sdk_response(ADH_LOW_NOTHING), sdk_response(ADH_LOW_NOTHING))
    monkeypatch.setattr(judge_mod, "_client", c)
    with pytest.raises(LensUnavailableError) as ei:
        evaluate_adherence_lens("+x", task_dag=DAG, model_name="gemini-4-carbon")
    assert c.calls == 2 and "UNPARSEABLE" in str(ei.value)


def test_rubric_says_the_list_is_the_gate():
    """RT F2: the generation contract matches the gate (every shortfall is a listed item; only listed items fail)."""
    from qa_auditor.adherence_lens import ADHERENCE_AUDITOR_PROMPT_TEMPLATE as T
    assert "omitted or not implemented as specified. Only listed items fail the build." in T
    assert "completely omitted" not in T and "drops the score below 0.95" not in T


def test_score_note_sits_next_to_a_real_failure(monkeypatch):
    _sec, _adh, rep = _stage_two(monkeypatch, _judge(["no /health endpoint"], adh=0.70))
    assert rep.passed is False and "1 blocking defects" in rep.summary
    assert "Adherence score 0.70, grounding score 1.00 (below 0.95): informational" in rep.summary


def test_same_bytes_different_scores_same_verdict(monkeypatch):
    """ex02-1113: the same bytes judged on two attempts with scores either side of 0.95 and nothing listed."""
    verdicts = []
    for score in (0.97, 0.92):
        _sec, adh, rep = _stage_two(monkeypatch, _judge(adh=score))
        verdicts.append((rep.passed, rep.blocking_reasons, adh.passed))
    assert verdicts[0] == verdicts[1] == (True, [], True)


# ======================================================================================== no verdict: never a pass
def test_judge_unavailable_is_still_gate_unavailable(monkeypatch):
    def _down(prompt, model, **kw):
        raise judge_mod.JudgeUnavailableError("Vertex 503")
    monkeypatch.setattr(judge_mod, "call", _down)
    with pytest.raises(LensUnavailableError):
        DualLensAuditorCoordinator(timeout_seconds=300.0).evaluate_stage_two(
            git_diff="+x", determ_report={"passed": True, "summary": "ok"}, task_dag=DAG, ingress_policy={},
            model_name="m", platform_facts=build_platform_facts(None, "off", DAG))


class _Client:
    def __init__(self, *responses):
        self.responses, self.calls, self.models = list(responses), 0, self

    def generate_content(self, model, contents, config):
        self.calls += 1
        return self.responses.pop(0)


SEC_FAILED_NOTHING_LISTED = json.dumps({"passed": False, "critical_vulnerabilities": [], "summary": "meh"})
SEC_OK = json.dumps({"passed": True, "critical_vulnerabilities": [], "summary": "ok"})


def test_security_failed_with_nothing_listed_is_asked_again_once(monkeypatch):
    """The reply contract ties `passed` to the list: a contradiction is UNPARSEABLE (JUDGE-LEVEL-FAMILY-CONFIG)."""
    c = _Client(sdk_response(SEC_FAILED_NOTHING_LISTED), sdk_response(SEC_OK))
    monkeypatch.setattr(judge_mod, "_client", c)
    assert evaluate_security_lens("+x", model_name="gemini-4-carbon").passed is True and c.calls == 2


def test_security_failed_with_nothing_listed_twice_is_unavailable(monkeypatch):
    c = _Client(sdk_response(SEC_FAILED_NOTHING_LISTED), sdk_response(SEC_FAILED_NOTHING_LISTED))
    monkeypatch.setattr(judge_mod, "_client", c)
    with pytest.raises(LensUnavailableError) as ei:
        evaluate_security_lens("+x", model_name="gemini-4-carbon")
    assert c.calls == 2 and "UNPARSEABLE" in str(ei.value)


def test_security_passed_true_with_a_listed_critical_still_blocks(monkeypatch):
    _sec, _adh, rep = _stage_two(monkeypatch, _judge(crit=["hardcoded key"], sec_passed=True))
    assert rep.passed is False and rep.blocking_reasons == ["Security: hardcoded key"]


@pytest.mark.parametrize("lens", ["security", "adherence"])
def test_failed_lens_result_with_no_finding_is_unavailable_never_a_block_or_pass(monkeypatch, lens):
    """Defence in depth: a lens result object that failed with nothing listed (not producible by the real lenses)."""
    sec = SecurityLensResult(passed=lens != "security")
    adh = AdherenceLensResult(passed=lens != "adherence", instruction_adherence_score=0.5)
    monkeypatch.setattr(coord_mod, "evaluate_security_lens", lambda **kw: sec)
    monkeypatch.setattr(coord_mod, "evaluate_adherence_lens", lambda **kw: adh)
    with pytest.raises(LensUnavailableError, match="no enumerated"):
        DualLensAuditorCoordinator(timeout_seconds=30.0).evaluate_stage_two(
            git_diff="+x", determ_report={"passed": True, "summary": "ok"}, task_dag=DAG, ingress_policy={},
            platform_facts=build_platform_facts(None, "off", DAG))


# ======================================================================================== run_qa end to end
@pytest.fixture()
def gw(monkeypatch):
    mod = fd4f_support.load_gateway(monkeypatch, "judge_gate_enum_gw")
    yield mod
    mod.app.dependency_overrides.clear()


def _db():
    db = FakeDB()
    seed_context(db)
    db.docs["pipeline_executions/tr-1"]["stages"]["architect"]["details"]["task_dag"] = DAG
    return db


def _run(gw, monkeypatch, db, judge, attempt=0, tree=None):
    monkeypatch.setattr(judge_mod, "call", judge)
    backend = FakeBackend({BRANCH: tree or TREE, "main": {}}, {BRANCH: SHA_A, "main": SHA_B})
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name=BRANCH, attempt=attempt)
    return gw.run_qa(req, client=FakeQAClient(passing_outcome()), source_backend_factory=backend_factory(backend),
                     evidence_db=db)


def _judged(out):
    return [d for d in out["diagnostics"] if d.get(STAMP) is True]


def test_negative_enumerated_findings_block_exactly_as_today(gw, monkeypatch):
    """A security critical with a file and a missed directive on a task: the same verdict, the same two repair seeds
    (code, file, task) as before the change."""
    out = _run(gw, monkeypatch, _db(), _judge(["no /health endpoint"], adh=0.99, task_ids=["CODE-01"], files=[""],
                                              crit=["reconcile trusts any caller"], crit_files=["apps/api/orders.py"]))
    assert out["passed"] is False and out["reason"] == "STAGE2_FAILED" and out["retryable"] is True
    assert [(d["code"], d["file"], d.get("task_id"), d["message"]) for d in _judged(out)] == [
        ("JUDGE.SECURITY", "apps/api/orders.py", None, "reconcile trusts any caller"),
        ("JUDGE.ADHERENCE", APPMAIN, "CODE-01", "no /health endpoint"),
    ]


def test_low_score_with_no_finding_passes_with_the_score_recorded(gw, monkeypatch):
    db = _db()
    out = _run(gw, monkeypatch, db, _judge(adh=0.92))
    assert out["passed"] is True and _judged(out) == []
    doc = db.docs["qa_test_runs/tr-1"]
    assert doc["adherence_lens"]["instruction_adherence_score"] == 0.92 and doc["adherence_lens"]["passed"] is True
    assert doc["composite_audit"]["blocking_reasons"] == []
    assert "Adherence score 0.92" in out["summary"] and "informational" in out["summary"]


def test_low_score_with_a_finding_has_no_score_seed(gw, monkeypatch):
    out = _run(gw, monkeypatch, _db(), _judge(["no /health endpoint"], adh=0.5, task_ids=["CODE-01"]))
    assert [d["message"] for d in _judged(out)] == ["no /health endpoint"]


# ======================================================================================== typed fingerprints
def _fp(gw, **kw):
    d = {"tool": "judge", "code": "JUDGE.ADHERENCE", "file": None, "line": None, "message": "m", STAMP: True}
    d.update(kw)
    return gw._diagnostic_fingerprint(d)


def test_judge_fingerprint_is_the_typed_fields_only(gw):
    key = json.dumps(["judge", "JUDGE.ADHERENCE", "CODE-01", APPMAIN, None])
    assert _fp(gw, task_id="CODE-01", file=APPMAIN) == hashlib.sha256(key.encode()).hexdigest()
    # the judge's wording is not part of it
    assert _fp(gw, task_id="CODE-01", file=APPMAIN, message="GET /health missing") == \
        _fp(gw, task_id="CODE-01", file=APPMAIN, message="The plan's health endpoint was not implemented")


@pytest.mark.parametrize("change", [{"task_id": "CODE-02"}, {"file": "apps/api/orders.py"}, {"facet": "OTHER"},
                                    {"code": "JUDGE.SECURITY"}])
def test_each_typed_field_tells_findings_apart(gw, change):
    base = {"task_id": "CODE-01", "file": APPMAIN}
    assert _fp(gw, **base) != _fp(gw, **{**base, **change})


def test_non_string_typed_fields_read_as_absent(gw):
    assert _fp(gw, task_id=7, file=["x"], facet=True) == _fp(gw)


def test_reworded_repeat_on_retry_is_no_progress(gw, monkeypatch):
    """ex02-1113: the same CODE-03-style finding reworded every attempt never matched; now it does."""
    db = _db()
    first = _run(gw, monkeypatch, db, _judge(["GET /health is missing"], task_ids=["CODE-01"]))
    assert first["retryable"] is True
    second = _run(gw, monkeypatch, db, _judge(["The health endpoint required by CODE-01 was not implemented"],
                                              task_ids=["CODE-01"]), attempt=1)
    assert second["retryable"] is False and second["reason"] == "NO_PROGRESS"


def test_reworded_security_repeat_on_the_same_file_is_no_progress(gw, monkeypatch):
    db = _db()
    _run(gw, monkeypatch, db, _judge(crit=["reconcile has no caller check"], crit_files=["apps/api/orders.py"]))
    second = _run(gw, monkeypatch, db, _judge(crit=["anyone can trigger the reconcile route"],
                                              crit_files=["apps/api/orders.py"]), attempt=1)
    assert second["reason"] == "NO_PROGRESS"


def test_reworded_repeat_says_same_repair_targets_not_identical(gw, monkeypatch):
    """RT F3: the stored reason is truthful: the keys matched, the diagnostics were not identical."""
    db = _db()
    _run(gw, monkeypatch, db, _judge(["GET /health is missing"], task_ids=["CODE-01"]))
    second = _run(gw, monkeypatch, db, _judge(["health route absent"], task_ids=["CODE-01"]), attempt=1)
    assert second["reason"] == "NO_PROGRESS"
    assert "the same repair targets (code, task, file) as attempt 0, with no routed file changed" in second["summary"]
    assert "identical diagnostics" not in second["summary"]


def test_collision_a_then_b_on_an_unchanged_file_is_no_progress(gw, monkeypatch):
    """RT F3, pinned as a decision: two different findings on the same task and file share one key. When the
    developer changed nothing in that file, the second is NO_PROGRESS at once."""
    db = _db()
    _run(gw, monkeypatch, db, _judge(["GET /items is missing"], task_ids=["CODE-01"]))
    second = _run(gw, monkeypatch, db, _judge(["DELETE /items/{id} is missing"], task_ids=["CODE-01"]), attempt=1)
    assert second["retryable"] is False and second["reason"] == "NO_PROGRESS"


def test_collision_on_a_changed_file_gets_one_more_round_then_stops(gw, monkeypatch):
    """RT F3 hardening: the routed file changed (the developer acted where the finding points), so a same-key
    repeat gets one more round; the second consecutive repeat stops."""
    db = _db()
    _run(gw, monkeypatch, db, _judge(["GET /items is missing"], task_ids=["CODE-01"]))
    assert db.docs["qa_test_runs/tr-1"]["judge_repeat_grace"] == 0
    tree2 = dict(TREE, **{APPMAIN: b"x = 2  # GET /items\n"})
    second = _run(gw, monkeypatch, db, _judge(["DELETE /items/{id} is missing"], task_ids=["CODE-01"]), attempt=1,
                  tree=tree2)
    assert second["retryable"] is True and second["reason"] == "STAGE2_FAILED"
    assert "but a routed file changed since: one more round" in second["summary"]
    assert db.docs["qa_test_runs/tr-1"]["judge_repeat_grace"] == 1
    tree3 = dict(TREE, **{APPMAIN: b"x = 3  # DELETE /items\n"})
    third = _run(gw, monkeypatch, db, _judge(["PATCH /items/{id} is missing"], task_ids=["CODE-01"]), attempt=2,
                 tree=tree3)
    assert third["retryable"] is False and third["reason"] == "NO_PROGRESS"
    assert "repeated after one more round" in third["summary"]


def test_grace_resets_when_the_targets_change(gw, monkeypatch):
    db = _db()
    _run(gw, monkeypatch, db, _judge(["GET /items is missing"], task_ids=["CODE-01"]))
    _run(gw, monkeypatch, db, _judge(["DELETE /items is missing"], task_ids=["CODE-01"]), attempt=1,
         tree=dict(TREE, **{APPMAIN: b"x = 2\n"}))
    third = _run(gw, monkeypatch, db, _judge(["orders route missing"], task_ids=["CODE-02"]), attempt=2)
    assert third["retryable"] is True and db.docs["qa_test_runs/tr-1"]["judge_repeat_grace"] == 0


def test_routed_file_hashes_are_recorded_for_judge_findings_only(gw, monkeypatch):
    db = _db()
    _run(gw, monkeypatch, db, _judge(["GET /health is missing", "general gap"], task_ids=["CODE-01", ""]))
    shas = db.docs["qa_test_runs/tr-1"]["judge_routed_file_sha256"]
    assert list(shas) == [APPMAIN] and shas[APPMAIN] == hashlib.sha256(TREE[APPMAIN]).hexdigest()


def test_a_finding_on_another_task_is_progress(gw, monkeypatch):
    db = _db()
    _run(gw, monkeypatch, db, _judge(["GET /health is missing"], task_ids=["CODE-01"]))
    second = _run(gw, monkeypatch, db, _judge(["orders route missing"], task_ids=["CODE-02"]), attempt=1)
    assert second["retryable"] is True and second["reason"] == "STAGE2_FAILED"


def test_score_flicker_alone_never_reaches_the_fingerprint(gw, monkeypatch):
    """Same finding, scores 0.90 then 0.80: the finding set is what NO_PROGRESS compares."""
    db = _db()
    _run(gw, monkeypatch, db, _judge(["GET /health is missing"], adh=0.90, task_ids=["CODE-01"]))
    second = _run(gw, monkeypatch, db, _judge(["GET /health is missing"], adh=0.80, task_ids=["CODE-01"]), attempt=1)
    assert second["reason"] == "NO_PROGRESS"


# ======================================================================================== release gate
def _release(adh):
    return RG.evaluate_release_decision(
        determ_report={"passed": True}, sec_report={"passed": True, "critical_vulnerabilities": []}, adh_report=adh,
        workload_policy={"require_human_code_review": False}, product_id="app", branch_name=BRANCH)


@pytest.mark.parametrize("score", [0.79, 0.05, 0.0])
def test_release_gate_blocks_a_contradictory_stored_record(score):
    """F1 defence in depth: a passed record with nothing listed below the floor (the lens can no longer write one)."""
    dec = _release({"instruction_adherence_score": score, "grounding_score": 1.0, "passed": True,
                    "missed_directives": []})
    assert dec.recommended_action == "AUTO_REJECT"
    assert dec.blocking_reasons == [f"Adherence lens record is contradictory (score {score:.2f} below 0.80 with no "
                                    f"missed directive)."]


def test_release_gate_merges_a_low_score_with_no_finding():
    dec = _release({"instruction_adherence_score": 0.85, "grounding_score": 0.90, "passed": True,
                    "missed_directives": []})
    assert dec.recommended_action == "AUTO_MERGE" and dec.blocking_reasons == [] and dec.adherence_score == 0.85
    assert "| **Task DAG Adherence Lens** | ✅ PASSED |" in dec.release_certificate_markdown
    assert "score below 95%: informational, not a blocking reason" in dec.release_certificate_markdown


@pytest.mark.parametrize("adh,reason", [
    ({"instruction_adherence_score": 0.99, "grounding_score": 1.0, "passed": False, "missed_directives": ["x"]},
     "Missed Directive: x"),
    ({"instruction_adherence_score": 0.99, "grounding_score": 1.0, "passed": False, "missed_directives": []},
     "Adherence lens did not pass (missing or failed verdict)."),
    ({"instruction_adherence_score": True, "grounding_score": 1.0, "passed": True, "missed_directives": []},
     "Adherence lens record is malformed (no numeric adherence and grounding scores)."),
    ({"passed": True, "missed_directives": []},
     "Adherence lens record is malformed (no numeric adherence and grounding scores)."),
    # RT F4: a missing or non-numeric grounding score is malformed too
    ({"instruction_adherence_score": 0.99, "passed": True, "missed_directives": []},
     "Adherence lens record is malformed (no numeric adherence and grounding scores)."),
    ({"instruction_adherence_score": 0.99, "grounding_score": "1.0", "passed": True, "missed_directives": []},
     "Adherence lens record is malformed (no numeric adherence and grounding scores)."),
])
def test_release_gate_still_blocks_findings_failed_verdicts_and_malformed_records(adh, reason):
    dec = _release(adh)
    assert dec.recommended_action == "AUTO_REJECT" and dec.blocking_reasons == [reason]
    assert "| **Task DAG Adherence Lens** | ❌ DEFECTS |" in dec.release_certificate_markdown
