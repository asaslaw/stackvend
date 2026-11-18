"""JUDGE-NAMED-INTENT-REMOVAL (ex02-1115, docs/handoff/ex02-1115-iac-judge-repair-diagnosis.md): a QA judge finding on
infra/workload/iac_intent.json may name the exact intent entries that must be deleted to meet it (adherence lens
`missed_directive_removals`); the gateway keeps an address only when it is an entry of the committed intent, the QA
repair plan seeds one finding per kept address (block_address), and only such a seed justifies the repair deleting
exactly that entry. Before, every deletion a
judge finding asked for was PRESERVATION_VIOLATION (live: ex02-1115 iterations 2 and 4 deleted the duplicate scheduler
module and were rejected; the dispatch ran out of iterations). Without a named address everything is as before.
End to end: tests/scenario_corpus/02e (fixed) and 02f (negative)."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
from unittest.mock import MagicMock, patch

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import (SHA_A, SHA_B, FakeBackend, FakeDB, FakeQAClient, backend_factory,  # noqa: E402
                          firestore_nested_array_paths, passing_outcome, seed_context)
from test_qa_feedback import _feedback  # noqa: E402

import qa_auditor.judge as judge_mod  # noqa: E402
from developer_agent import iac_intent_contract as IC  # noqa: E402
from developer_agent import qa_repair as QR  # noqa: E402
from qa_auditor import adherence_lens as AL  # noqa: E402
from shared.diagnostics import AssemblyRecord, Diagnostic, ValidationReport, fingerprint  # noqa: E402

RL = pytest.importorskip("developer_agent.repair_loop")

INTENT = IC.INTENT_PATH
MOD = "module.daily_reconcile_cron"
RAW = "google_cloud_scheduler_job.daily_reconcile"
DOC = {"schema": "iac_intent/v1",
       "modules": [{"module": "scheduling-cron", "name": "daily_reconcile_cron", "args": {"schedule": "0 2 * * *"}}],
       "resources": [{"type": "google_cloud_scheduler_job", "name": "daily_reconcile", "arguments": {}}],
       "outputs": [{"name": "job_id", "value": "x"}],
       "api_only": [{"service": "translate.googleapis.com"}]}
INTENT_TEXT = json.dumps(DOC, indent=2)
APPMAIN = "apps/svc/main.py"
TREE = {INTENT: INTENT_TEXT, APPMAIN: "x = 1\n", "apps/svc/tests/test_x.py": "def test(): pass\n"}
MSG = "duplicate Cloud Scheduler jobs: the module targets / instead of /api/v1/reconcile"


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


# ============================================================================ the one intent parse
def test_intent_document_addresses_is_the_repair_loops_preserved_set():
    assert IC.intent_document_addresses(INTENT_TEXT) == {MOD, RAW, IC.API_ONLY_ENTRY_PREFIX + "translate.googleapis.com"}
    assert IC.intent_document_addresses(INTENT_TEXT, api_only=False) == {MOD, RAW}   # outputs never, api_only opt-in
    assert RL._intent_addresses({INTENT: INTENT_TEXT}) == IC.intent_document_addresses(INTENT_TEXT)
    for bad in (None, "", "not json", "[]", json.dumps({"modules": "x"})):
        assert IC.intent_document_addresses(bad) == set()


# ============================================================================ adherence lens: the typed field
@pytest.mark.parametrize("raw,expected", [
    ([[MOD, RAW]], [[MOD, RAW]]),
    ([[MOD, "", MOD]], [[MOD]]),                       # empty strings dropped, duplicates once, order kept
    ([[]], [[]]),
    ([[MOD], [RAW]], [[]]),                            # wrong length -> nothing named
    ([MOD], [[]]),                                     # a string, not a list -> nothing named
    ([[1]], [[]]),
    (None, [[]]),
])
def test_directive_removals_are_typed_lists_or_nothing(raw, expected):
    data = {"missed_directive_removals": raw} if raw is not None else {}
    assert AL._directive_removals(data, [MSG]) == expected


def test_directive_removals_are_capped():
    many = [f"module.m{i}" for i in range(20)]
    assert AL._directive_removals({"missed_directive_removals": [many]}, [MSG]) == [many[:AL.DIRECTIVE_REMOVALS_MAX]]


def test_prompt_and_schema_ask_for_addresses_optionally():
    assert '"missed_directive_removals"' in AL.ADHERENCE_AUDITOR_PROMPT_TEMPLATE
    assert AL.ADHERENCE_RESPONSE_SCHEMA["properties"]["missed_directive_removals"] == {
        "type": "ARRAY", "items": {"type": "ARRAY", "items": {"type": "STRING"}}}
    assert "missed_directive_removals" not in AL.ADHERENCE_RESPONSE_SCHEMA["required"]
    assert AL.adherence_response_schema(False) is AL.ADHERENCE_RESPONSE_SCHEMA


def _judge_call(missed, files=None, addresses=None, prompts=None):
    def _call(prompt, model, **kw):
        if "Security Engineer" in prompt:
            return json.dumps({"passed": True, "critical_vulnerabilities": []})
        if prompts is not None:
            prompts.append(prompt)
        body = {"instruction_adherence_score": 0.9, "grounding_score": 1.0, "missed_directives": missed,
                "hallucinated_features": [], "summary": "a"}
        if files is not None:
            body["missed_directive_files"] = files
        if addresses is not None:
            body["missed_directive_removals"] = addresses
        return json.dumps(body)
    return _call


def test_lens_carries_the_addresses_and_the_prompt_names_the_intent(monkeypatch):
    prompts = []
    monkeypatch.setattr(judge_mod, "call", _judge_call([MSG], [INTENT], [[MOD]], prompts))
    res = AL.evaluate_adherence_lens("+x", task_dag=[{"task_id": "INFRA-04"}], model_name="gemini-4-carbon")
    assert res.missed_directive_removals == [[MOD]] and res.missed_directive_files == [INTENT]
    assert f"the entries of {INTENT} that must be deleted to meet it" in prompts[0]


def test_lens_without_the_field_names_no_address(monkeypatch):
    monkeypatch.setattr(judge_mod, "call", _judge_call([MSG], [INTENT]))
    res = AL.evaluate_adherence_lens("+x", task_dag=[], model_name="gemini-4-carbon")
    assert res.missed_directive_removals == [[]] and res.passed is False   # never a verdict input


# ============================================================================ gateway: _judge_diagnostics via run_qa
DAG = [{"task_id": "INFRA-04", "title": "one scheduler", "target_files": [INTENT]}]
BRANCH = "castor/app-abc123"


@pytest.fixture()
def gw(monkeypatch):
    mod = fd4f_support.load_gateway(monkeypatch, "qa_jnir_gw")
    yield mod
    mod.app.dependency_overrides.clear()


def _run(gw, monkeypatch, *, files, addresses, tree=None, db_out=None):
    monkeypatch.setattr(judge_mod, "call", _judge_call([MSG], files, addresses))
    db = FakeDB()
    seed_context(db)
    db.docs["pipeline_executions/tr-1"]["stages"]["architect"]["details"]["task_dag"] = DAG
    head = {p: t.encode() for p, t in (TREE if tree is None else tree).items()}
    backend = FakeBackend({BRANCH: head, "main": {}}, {BRANCH: SHA_A, "main": SHA_B})
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name=BRANCH, attempt=0)
    out = gw.run_qa(req, client=FakeQAClient(passing_outcome()), source_backend_factory=backend_factory(backend),
                    evidence_db=db)
    if db_out is not None:
        db_out.append(db)
    return [d for d in out["diagnostics"] if d["code"] == "JUDGE.ADHERENCE"]


def test_gateway_keeps_only_exact_committed_intent_entries(gw, monkeypatch):
    (d,) = _run(gw, monkeypatch, files=[INTENT],
                addresses=[[RAW, MOD, "module.not_there", "output.job_id",
                            IC.API_ONLY_ENTRY_PREFIX + "translate.googleapis.com"]])
    assert d["file"] == INTENT and d[QR.JUDGE_REMOVALS_FIELD] == sorted([MOD, RAW])


def test_gateway_finding_without_addresses_is_unchanged(gw, monkeypatch):
    (plain,) = _run(gw, monkeypatch, files=[INTENT], addresses=None)
    (none_kept,) = _run(gw, monkeypatch, files=[INTENT], addresses=[["module.not_there"]])
    assert QR.JUDGE_REMOVALS_FIELD not in plain and QR.JUDGE_REMOVALS_FIELD not in none_kept
    assert plain["fingerprint"] == none_kept["fingerprint"]   # the typed fingerprint never reads the field
    (named,) = _run(gw, monkeypatch, files=[INTENT], addresses=[[MOD]])
    assert named["fingerprint"] == plain["fingerprint"]


def test_gateway_never_names_addresses_on_a_finding_off_the_intent(gw, monkeypatch):
    (d,) = _run(gw, monkeypatch, files=[APPMAIN], addresses=[[MOD]])
    assert d["file"] == APPMAIN and QR.JUDGE_REMOVALS_FIELD not in d


# ============================================================================ developer: the QA repair plan
def _jd(file, *, addresses=None, code="JUDGE.ADHERENCE", stamped=True):
    d = {"tool": "judge", "code": code, "severity": "error", "file": file, "line": None, "message": MSG,
         "detail": None, "source": "qa", "iteration": 0, "fingerprint": "f" * 64}
    if stamped:
        d[QR.JUDGE_FINDING_FIELD] = True
    if addresses is not None:
        d[QR.JUDGE_REMOVALS_FIELD] = addresses
    return d


def test_judge_named_intent_removals_exact_only():
    assert QR.judge_named_intent_removals(_jd(INTENT, addresses=[RAW, MOD, MOD]), INTENT_TEXT) == (RAW, MOD)
    assert QR.judge_named_intent_removals(_jd(INTENT, addresses=["module.x", "output.job_id"]), INTENT_TEXT) == ()
    assert QR.judge_named_intent_removals(_jd(INTENT, addresses=[MOD], stamped=False), INTENT_TEXT) == ()
    assert QR.judge_named_intent_removals(_jd(INTENT, addresses=[MOD], code="JUDGE.SECURITY"), INTENT_TEXT) == ()
    assert QR.judge_named_intent_removals(_jd(INTENT, addresses=MOD), INTENT_TEXT) == ()   # not a list
    assert QR.judge_named_intent_removals(_jd(INTENT, addresses=[MOD]), "not json") == ()


def test_plan_seeds_one_finding_per_named_entry():
    plan = QR.plan_qa_repair(_feedback(TREE, _jd(INTENT, addresses=[MOD, RAW])), stack_configured=True)
    assert (plan.mode, plan.reason) == (QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES")
    assert sorted((s.file, s.block_address) for s in plan.seeds) == [(INTENT, RAW), (INTENT, MOD)]
    assert {s.hint for s in plan.seeds} == {QR.JUDGE_REMOVAL_SEED_HINT}
    assert len({fingerprint(s) for s in plan.seeds}) == 2


@pytest.mark.parametrize("finding", [
    _jd(INTENT), _jd(INTENT, addresses=[]), _jd(INTENT, addresses=["module.not_there"]),
])
def test_plan_without_a_named_entry_is_exactly_as_before(finding):
    """Do No Harm: no usable address -> the one seed exactly as before (no block_address, the sandbox hint)."""
    before = QR.plan_qa_repair(_feedback(TREE, _jd(INTENT)), stack_configured=True)
    plan = QR.plan_qa_repair(_feedback(TREE, finding), stack_configured=True)
    assert [s.model_dump() for s in plan.seeds] == [s.model_dump() for s in before.seeds]
    (seed,) = plan.seeds
    assert seed.block_address is None and seed.hint == QR.SEED_HINT


def test_addresses_on_an_unstamped_or_non_intent_finding_never_seed_a_block():
    plan = QR.plan_qa_repair(_feedback(TREE, _jd(APPMAIN, addresses=[MOD])), stack_configured=True)
    assert [s.block_address for s in plan.seeds] == [None]


# ============================================================================ repair loop: the justification
def _seed(block, *, code="JUDGE.ADHERENCE", source="qa", file=INTENT):
    return Diagnostic(tool="pytest", code=code, severity="error", file=file, block_address=block, message="m",
                      source=source)


def _report(*diags):
    return ValidationReport(status="FAIL", source="precommit", artifact_hash="h", diagnostics=list(diags))


def _just(prev, removed, before=INTENT_TEXT):
    d1 = {INTENT: before}
    d2 = {INTENT: "{}"}
    a1 = RL.Assembled(tree=dict(d1), record=AssemblyRecord())
    a2 = RL.Assembled(tree=dict(d2), record=AssemblyRecord())
    return RL.removal_justifications(d1, d2, a1, a2, prev, set(removed))


def test_a_named_entry_may_be_deleted():
    assert _just(_report(_seed(MOD)), {MOD}) == {MOD: RL.JUDGE_REMOVAL_REASON_PREFIX + "JUDGE.ADHERENCE"}


@pytest.mark.parametrize("prev,removed", [
    (_report(_seed(MOD)), {RAW}),                                    # another entry the finding does not name
    (_report(_seed(None)), {MOD}),                                   # the finding names no entry (before the fix)
    (_report(_seed(MOD, source="precommit")), {MOD}),               # not a QA seed
    (_report(_seed(MOD, code="JUDGE.SECURITY")), {MOD}),             # not the adherence judge
    (_report(_seed(MOD, code="PY.TEST_FAILED")), {MOD}),             # a sandbox finding
    (_report(_seed(MOD, file="infra/workload/custom.tf.json")), {MOD}),   # not on the intent
])
def test_no_other_finding_justifies_a_deletion(prev, removed):
    assert _just(prev, removed) == {}


def test_an_address_not_in_the_starting_intent_is_not_justified():
    assert _just(_report(_seed(MOD)), {MOD}, before=json.dumps({"modules": [], "resources": []})) == {}


def test_a_warning_never_justifies():
    warn = Diagnostic(tool="pytest", code="JUDGE.ADHERENCE", severity="warning", file=INTENT, block_address=MOD,
                      message="m", source="qa")
    assert _just(_report(warn, _seed(None)), {MOD}) == {}


# ============================================================================ red-team hardening (RT F1-F6, F8)
def test_rt_f1_the_qa_record_holds_no_array_inside_an_array(gw, monkeypatch):
    """Firestore refuses an array directly inside an array; the lens field is a list of lists, so it is never persisted
    with the lens result (the routed finding carries the flat kept list). The fake store now enforces the rule."""
    for addresses in (None, [[MOD]], [[]]):
        dbs = []
        _run(gw, monkeypatch, files=[INTENT], addresses=addresses, db_out=dbs)
        doc = dbs[0].docs["qa_test_runs/tr-1"]
        assert firestore_nested_array_paths(doc) == []
        assert "missed_directive_removals" not in doc["adherence_lens"]
    assert firestore_nested_array_paths({"a": [[1]]}) == [".a[0]"]
    with pytest.raises(ValueError):
        FakeDB().collection("x").document("y").set({"a": [["b"]]})


def test_rt_f1_the_lens_result_dump_excludes_the_field(monkeypatch):
    monkeypatch.setattr(judge_mod, "call", _judge_call([MSG], [INTENT], [[MOD]]))
    res = AL.evaluate_adherence_lens("+x", task_dag=[], model_name="gemini-4-carbon")
    assert res.missed_directive_removals == [[MOD]] and "missed_directive_removals" not in res.model_dump()


def test_rt_f2_only_the_entry_named_for_deletion_may_go():
    """The duplicate case: the judge names the redundant copy; deleting the other job too is still refused."""
    assert _just(_report(_seed(MOD)), {MOD, RAW}) == {MOD: RL.JUDGE_REMOVAL_REASON_PREFIX + "JUDGE.ADHERENCE"}


def test_rt_f3_a_malformed_intent_names_nothing_and_the_plan_never_raises():
    for bad in ('{"modules": 5}', '{"resources": true}', "[" * 5000 + "]" * 5000):
        assert QR.judge_named_intent_removals(_jd(INTENT, addresses=[MOD]), bad) == ()
        tree = dict(TREE, **{INTENT: bad})
        plan = QR.plan_qa_repair(_feedback(tree, _jd(INTENT, addresses=[MOD])), stack_configured=True)
        assert [s.block_address for s in plan.seeds] == [None]


def test_rt_f3_no_judge_named_seed_means_no_intent_parse(monkeypatch):
    calls = []
    monkeypatch.setattr(RL, "_intent_addresses", lambda files: calls.append(1) or set())
    assert _just(_report(_seed(None)), {MOD}) == {} and calls == []


def test_rt_f4_a_removal_that_is_not_from_the_intent_is_not_justified():
    d1, d2 = {INTENT: INTENT_TEXT}, {INTENT: INTENT_TEXT}   # the intent entry is still there
    a1 = RL.Assembled(tree=dict(d1), record=AssemblyRecord())
    a2 = RL.Assembled(tree=dict(d2), record=AssemblyRecord())
    assert RL.removal_justifications(d1, d2, a1, a2, _report(_seed(MOD)), {MOD}) == {}


def test_rt_f5_a_finding_on_the_render_keeps_the_intent_entries(gw, monkeypatch):
    tree = dict(TREE, **{IC.RENDER_PATH: "{}\n"})
    (d,) = _run(gw, monkeypatch, files=[IC.RENDER_PATH], addresses=[[MOD, "module.not_there"]], tree=tree)
    assert d["file"] == IC.RENDER_PATH and d[QR.JUDGE_REMOVALS_FIELD] == [MOD]


def test_rt_f6_the_plan_summary_records_the_block_only_when_set():
    named = QR.plan_qa_repair(_feedback(TREE, _jd(INTENT, addresses=[MOD])), stack_configured=True)
    plain = QR.plan_qa_repair(_feedback(TREE, _jd(INTENT)), stack_configured=True)
    assert named.summary()["seeds"] == [{"code": "JUDGE.ADHERENCE", "file": INTENT, "block": MOD}]
    assert plain.summary()["seeds"] == [{"code": "JUDGE.ADHERENCE", "file": INTENT}]


def test_rt_f8_platform_handled_facets_keep_removals_aligned(monkeypatch):
    from qa_auditor import platform_satisfied as ps
    from qa_auditor.platform_facts import PlatformFacts
    handled = ps.platform_handlings({"budget_ceiling_monthly_usd": 10.0})
    assert ps.FACET_BUDGET_CAP in handled

    def _call(prompt, model, **kw):
        if "Security Engineer" in prompt:
            return json.dumps({"passed": True, "critical_vulnerabilities": []})
        return json.dumps({"instruction_adherence_score": 0.9, "grounding_score": 1.0,
                           "missed_directives": ["a monthly budget cap", MSG], "missed_directive_files": ["", INTENT],
                           "missed_directive_facets": [ps.FACET_BUDGET_CAP, ps.FACET_OTHER],
                           "missed_directive_removals": [["module.other"], [MOD]], "summary": "a"})
    monkeypatch.setattr(judge_mod, "call", _call)
    res = AL.evaluate_adherence_lens("+x", task_dag=[], model_name="gemini-4-carbon",
                                     platform_facts=PlatformFacts(text="- f", handled=handled))
    assert res.missed_directives == [MSG] and res.missed_directive_removals == [[MOD]]
