"""TI-5-R3 (register row TI-5-R3, owner 10-21): the workflow forwards the deploy's typed `validation_report` to the
developer stage, and a CODE_DEFECT on the intent continues the repair loop on infra/workload/iac_intent.json instead of
a full regeneration from the error text.

Covered: the plan table of developer_agent/deploy_repair.py; the repair loop's seeds (re-added while their intent entry
is unchanged; Do No Harm: no seeds = nothing changes); the developer end to end (repair on the committed intent, no
generation call; PLATFORM_DEFECT stops typed at $0; GATE_UNAVAILABLE / BROWNFIELD_CONFLICT / absent report ->
today's path; legacy workloads byte-identical with or without a report); the workflow simulator end to end (deploy
fails with a typed report -> repair on the intent -> redeploy) and mixed versions (old tf-applier without a report,
old workflow without the field, old gateway ignoring it). Hermetic: fake LLM, fake /validate, offline workflow
simulator."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from test_typed_iac_ti3_contract import (APP, BUCKET_MODULE, PID, TOPIC, UPLOADS, W, C, II, Client,  # noqa: E402
                                         _NoCallGenai, _agent, _assemble, _runtime, intent, record_of, topo, vt_of)
from developer_agent import deploy_repair as DR  # noqa: E402
from shared.diagnostics import (Diagnostic, ErrorClass, RepairBudgetExhausted, ValidationReport,  # noqa: E402
                                fingerprint)
from workflow_sim import Simulator, load_workflow  # noqa: E402
from fd4f_support import FakeDB, gw  # noqa: E402,F401  (gw: the gateway app fixture)

REPO = os.path.abspath(os.path.join(TESTS, ".."))
WORKFLOW = os.path.join(REPO, "workflows", "main_orchestrator.yaml")
REPAIRED_MODULE = dict(BUCKET_MODULE, args=dict(BUCKET_MODULE["args"], versioning_enabled=True))
WORKFLOW_FILE = ".github/workflows/deploy-shop.yml"


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


@pytest.fixture()
def tf(monkeypatch):
    from fd4g_support import load_tf_service
    return load_tf_service(monkeypatch)


# ------------------------------------------------------------------------------------------------ fixtures
def _committed_repo(doc=None):
    """An intent workload's main branch after its first build: app code, the intent, the platform's render of it
    and a platform CI file (the deploy applied exactly this)."""
    doc = doc or intent([BUCKET_MODULE])
    asm, _, rendered, _ = _assemble(vt_of(topo([UPLOADS])), {C.INTENT_PATH: doc})
    assert asm.diagnostics == ()
    return dict(APP, **{C.INTENT_PATH: doc, C.RENDER_PATH: rendered[C.RENDER_PATH], WORKFLOW_FILE: "name: x\n"})


def _apply_report(tf, tmp_path, repo, summary="Unsupported argument", extra=(), anchor='"uploads"'):
    """The REAL tf-applier report (mcp-servers/terraform/service.py apply_validation_report) for an engine error
    inside the render of the intent's `module.uploads` (the deploy flattens infra/workload/ into the workspace)."""
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    (ws / "iac_intent.json").write_text(repo[C.INTENT_PATH])
    render = repo[C.RENDER_PATH]
    (ws / "custom.tf.json").write_text(render)
    at = render.index("{", render.index(anchor)) + 1   # a byte inside the rendered object of that entry
    diags = [{"severity": "error", "summary": summary, "detail": "An argument named \"x\" is not expected here.",
              "range": {"filename": "custom.tf.json", "start": {"line": 3, "column": 5, "byte": at},
                        "end": {"line": 3, "column": 9, "byte": at + 2}}}] + list(extra)
    return tf.apply_validation_report(json.dumps({"diagnostics": diags}), str(ws),
                                      manifest_paths=[W + "custom.tf.json", W + "iac_intent.json", W + "human.tf"])


def _report(*diags, status="FAIL", source="apply"):
    return ValidationReport(status=status, source=source, artifact_hash="", diagnostics=list(diags),
                            tools_ran=["tofu"]).model_dump(mode="json")


def _diag(cls=ErrorClass.CODE_DEFECT, file=C.INTENT_PATH, block="module.uploads", code="TF.UNSUPPORTED_ARGUMENT",
          line=7):
    return Diagnostic(tool="tofu", code=code, severity="error", error_class=cls, file=file, line=line,
                      block_address=block, attribute_path="/modules/0", message="Unsupported argument",
                      source="apply")


INTENT_RUN = object()   # plan_deploy_repair only checks "an intent run exists"


# ------------------------------------------------------------------------------------------------ the plan table
def test_plan_no_report_and_legacy_workloads_keep_todays_path():
    repo = _committed_repo()
    assert DR.plan_deploy_repair(None, intent_run=INTENT_RUN, existing_files=repo).mode == DR.REGENERATE
    legacy = DR.plan_deploy_repair(_report(_diag()), intent_run=None, existing_files=repo)
    assert (legacy.mode, legacy.reason, legacy.report) == (DR.REGENERATE, "NOT_AN_INTENT_WORKLOAD", None)


@pytest.mark.parametrize("raw,reason", [
    ({"status": "FAIL"}, "REPORT_INVALID"),                                    # not a ValidationReport
    ("text", "REPORT_INVALID"),
    (dict(_report(_diag()), extra_key=1), "REPORT_INVALID"),                    # a newer schema: today's path
    (_report(_diag(), source="precommit"), "REPORT_NOT_FROM_APPLY"),
    (_report(status="UNAVAILABLE"), "REPORT_UNAVAILABLE"),                     # GATE_UNAVAILABLE -> today's path
    (_report(_diag(block="module.other")), "FINDING_NOT_ON_A_COMMITTED_INTENT_ENTRY"),
    (_report(_diag(file=C.RENDER_PATH)), "FINDING_NOT_ON_A_COMMITTED_INTENT_ENTRY"),
])
def test_plan_unusable_reports_keep_todays_path(raw, reason):
    p = DR.plan_deploy_repair(raw, intent_run=INTENT_RUN, existing_files=_committed_repo())
    assert (p.mode, p.reason) == (DR.REGENERATE, reason)


def test_plan_without_a_committed_intent_keeps_todays_path():
    p = DR.plan_deploy_repair(_report(_diag()), intent_run=INTENT_RUN, existing_files=dict(APP))
    assert (p.mode, p.reason) == (DR.REGENERATE, "NO_COMMITTED_INTENT")


def test_plan_platform_defect_stops_typed():
    raw = _report(_diag(), _diag(cls=ErrorClass.PLATFORM_DEFECT, file=W + "main.tf", block="module.compute"))
    p = DR.plan_deploy_repair(raw, intent_run=INTENT_RUN, existing_files=_committed_repo())
    assert (p.mode, p.reason) == (DR.STOP, "PLATFORM_DEFECT")
    err = DR.stop_error(p, PID)
    assert type(err).__name__ == "PlatformDefectError"
    body = err.to_body()
    assert (body["error_class"], body["stage"], body["reason"]) == ("PLATFORM_DEFECT", "developer",
                                                                    "APPLY_PLATFORM_DEFECT")
    assert [d["file"] for d in body["diagnostics"]] == [C.INTENT_PATH, W + "main.tf"]


@pytest.mark.parametrize("diags", [
    (_diag(cls=ErrorClass.BROWNFIELD_CONFLICT, file=W + "human.tf", block="null_resource.x"),),
    # mixed: a human.tf error beside an intent error still stops (the report's class outranks CODE_DEFECT)
    (_diag(), _diag(cls=ErrorClass.BROWNFIELD_CONFLICT, file=W + "human.tf", block="null_resource.x")),
])
def test_plan_user_owned_finding_stops_for_the_operator(diags):
    """TI-5-R3-b (owner 10-25): an error in human.tf / an override file stops for the operator (409), never a
    regeneration (the developer never edits user-owned files)."""
    p = DR.plan_deploy_repair(_report(*diags), intent_run=INTENT_RUN, existing_files=_committed_repo())
    assert (p.mode, p.reason) == (DR.STOP, "BROWNFIELD_CONFLICT")
    err = DR.stop_error(p, PID)
    assert type(err).__name__ == "OperatorActionRequiredError" and err.http_status == 409
    body = err.to_body()
    assert (body["error_class"], body["reason"], body["stage"]) == ("OPERATOR_ACTION_REQUIRED", "BROWNFIELD_CONFLICT",
                                                                    "developer")
    assert W + "human.tf" in [d["file"] for d in body["diagnostics"]]


def test_plan_platform_defect_outranks_a_user_owned_finding():
    raw = _report(_diag(cls=ErrorClass.BROWNFIELD_CONFLICT, file=W + "human.tf", block="null_resource.x"),
                  _diag(cls=ErrorClass.PLATFORM_DEFECT, file=W + "main.tf", block="module.compute"))
    p = DR.plan_deploy_repair(raw, intent_run=INTENT_RUN, existing_files=_committed_repo())
    assert (p.mode, p.reason) == (DR.STOP, "PLATFORM_DEFECT")
    assert type(DR.stop_error(p, PID)).__name__ == "PlatformDefectError"


def test_plan_user_owned_finding_on_a_legacy_workload_is_todays_path():
    """Do No Harm: the stop is for intent workloads only; a legacy workload ignores every report."""
    raw = _report(_diag(cls=ErrorClass.BROWNFIELD_CONFLICT, file=W + "human.tf", block="null_resource.x"))
    assert DR.plan_deploy_repair(raw, intent_run=None, existing_files=_committed_repo()).mode == DR.REGENERATE


def test_plan_code_defect_on_intent_entries_repairs_the_committed_intent():
    repo = _committed_repo()
    raw = _report(_diag(), _diag())   # a duplicate finding is one seed
    p = DR.plan_deploy_repair(raw, intent_run=INTENT_RUN, existing_files=repo, draft_paths=sorted(repo))
    assert (p.mode, p.reason) == (DR.INTENT_REPAIR, "CODE_DEFECT_ON_INTENT")
    (seed,) = p.seeds
    assert (seed.line, seed.column, seed.end_line) == (None, None, None)   # render positions are not intent lines
    assert p.seed_entries == {"module.uploads": json.dumps(BUCKET_MODULE, sort_keys=True)}
    # the draft: the committed bytes outside infra/ and .github/, plus the committed intent
    assert p.draft == dict(APP, **{C.INTENT_PATH: repo[C.INTENT_PATH]})
    assert p.summary() == {"mode": "INTENT_REPAIR", "reason": "CODE_DEFECT_ON_INTENT", "report_class": "CODE_DEFECT",
                           "seeds": [{"code": "TF.UNSUPPORTED_ARGUMENT", "block": "module.uploads"}]}


def test_the_real_apply_report_is_planned_as_an_intent_repair(tf, tmp_path):
    repo = _committed_repo()
    raw = _apply_report(tf, tmp_path, repo)
    p = DR.plan_deploy_repair(raw, intent_run=INTENT_RUN, existing_files=repo, draft_paths=sorted(repo))
    assert p.mode == DR.INTENT_REPAIR, p.reason
    assert [(d.code, d.block_address, d.attribute_path) for d in p.seeds] == [
        ("TF.UNSUPPORTED_ARGUMENT", "module.uploads", "/modules/0")]
    # one more finding in a vendored module (platform-owned) -> the whole report is PLATFORM_DEFECT: stop
    mod = {"severity": "error", "summary": "Bad", "range": {"filename": "modules/storage-bucket/main.tf",
                                                            "start": {"line": 1, "byte": 0}}}
    p2 = DR.plan_deploy_repair(_apply_report(tf, tmp_path, repo, extra=[mod]), intent_run=INTENT_RUN,
                               existing_files=repo)
    assert (p2.mode, p2.reason) == (DR.STOP, "PLATFORM_DEFECT")
    # an untyped failure (no engine result: init, build, ...) -> GATE_UNAVAILABLE -> today's path
    none = tf.apply_validation_report("", "", engine_result=False, fallback_error="init failed")
    assert DR.plan_deploy_repair(none, intent_run=INTENT_RUN, existing_files=repo).mode == DR.REGENERATE


# ------------------------------------------------------------------------------------------------ seeds
def test_seeds_live_only_while_their_entry_is_unchanged():
    seed = _diag(line=None)
    entries = {"module.uploads": json.dumps(BUCKET_MODULE, sort_keys=True)}
    same = json.dumps(json.loads(intent([BUCKET_MODULE])), indent=4)   # formatting is not a change
    assert DR.live_seeds((seed,), entries, same) == [seed]
    assert DR.live_seeds((seed,), entries, intent([REPAIRED_MODULE])) == []
    assert DR.live_seeds((seed,), entries, intent()) == []              # entry removed (the loop judges the removal)
    assert DR.live_seeds((seed,), entries, "not json") == []
    assert DR.live_seeds((), entries, same) == []


def test_with_seeds_turns_a_pass_into_a_fail_and_is_identity_without_seeds():
    ok = ValidationReport(status="PASS", source="precommit", artifact_hash="h", tools_ran=["tofu"])
    assert DR.with_seeds(ok, []) is ok                                   # DNH: no seeds, the same object
    seed = _diag(line=None)
    got = DR.with_seeds(ok, [seed])
    assert (got.status, got.error_class, got.artifact_hash) == ("FAIL", ErrorClass.CODE_DEFECT, "h")
    assert got.error_fingerprints() == [fingerprint(seed)]
    assert DR.with_seeds(got, [seed]) is got                             # already present: unchanged
    gone = ValidationReport(status="UNAVAILABLE", source="precommit", artifact_hash="", tools_unavailable=["V1b"])
    assert DR.with_seeds(gone, [seed]) is gone                           # an unavailable gate stays unavailable


# ------------------------------------------------------------------------------------------------ developer stage
class _RecordingGenai:
    """Single-turn answers; records every call (model, prompt, system instruction)."""

    def __init__(self, *texts):
        self.seen = []
        answers = list(texts)
        outer = self

        class models:  # noqa: N801
            @staticmethod
            def generate_content(*a, **k):
                cfg = k.get("config")
                outer.seen.append((k.get("model"), k.get("contents"), getattr(cfg, "system_instruction", None)))
                return SimpleNamespace(text=answers.pop(0), candidates=[SimpleNamespace(finish_reason="STOP")],
                                       usage_metadata=None)
        self.models = models


ALL_PATHS = object()   # SAT-49: the gateway's matched draft record = every file of the repository (before SAT-49)


def _develop(existing, report=None, repairs=(), mode="off", genai=None, swarm_draft=None, context=None,
             agent_out=None, draft_paths=ALL_PATHS, **settings):
    """One developer dispatch on the gateway's agent (fake LLM / swarm / validate). `swarm_draft` None = the swarm
    must not run (a regeneration would call it); `context` = the workflow's tf_remediation_context. SAT-49:
    `draft_paths` = the gateway's matched committed_draft paths (sent only with a report; None = not sent)."""
    if draft_paths is ALL_PATHS:
        draft_paths = sorted(existing)
    from developer_agent import handler as h
    client = Client()
    agent = _agent(_runtime(client, iac_intent_mode=mode, **settings))
    agent.genai_client = genai or _NoCallGenai()
    plan = MagicMock()
    plan.execution_mode = [m for m in h.SwarmExecutionMode if m != h.SwarmExecutionMode.SOLO_FAST_PATH][0]
    plan.tasks = [MagicMock()]
    seen = {"repair_tasks": [], "swarm": 0}
    answers = list(repairs)

    class FakeDispatcher:
        def __init__(self, *a, **k):
            self.last_file_attribution = {p: ("IAC_ENGINEER" if p == C.INTENT_PATH else "BACKEND_ENGINEER")
                                          for p in (swarm_draft or {})}
            self.envelope_checks = [{"ok": True, "error": None}]
            self.iac_intent = None

        async def execute_phased_junior_swarm(self, *a, **k):
            seen["swarm"] += 1
            if swarm_draft is None:
                raise AssertionError("regeneration: the swarm ran")
            return dict(swarm_draft)

        def invoke_repair(self, persona, system_instruction, prompt, model, max_out, **k):
            seen["repair_tasks"].append({"persona": persona, "system": system_instruction, "prompt": prompt})
            return {"files": answers.pop(0), "envelope_ok": True, "finish_reason": "STOP", "tokens_in": 1,
                    "tokens_out": 1, "tokens_thoughts": 0, "model": model, "persona": persona}

    if agent_out is not None:
        agent_out.append(agent)
    with patch.object(h, "LeadDeveloperOrchestrator") as lead, patch.object(h, "SwarmDispatcher", FakeDispatcher), \
            patch.object(h, "get_model_cascade_for_agent", return_value=["gemini-test"]), \
            patch.object(agent, "fetch_existing_repo_files", return_value=dict(existing)), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": "",
                                    "ENABLE_DEVELOPER_SWARM": "true" if swarm_draft is not None else "false"}), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
        lead.return_value.decompose_specification.return_value = plan
        try:
            files = agent.generate_code_files(product_id=PID, spec_text="uploads service", task_dag=[],
                                              trace_id="t-r3", architect_compute_intent=record_of(topo([UPLOADS])),
                                              allow_unauthenticated=True, enable_direct_iap=False,
                                              domain_restricted_sharing=False, tf_retry_count=1 if context else 0,
                                              tf_remediation_context=context, tf_validation_report=report,
                                              **({DR.DRAFT_PATHS_KWARG: list(draft_paths)}
                                                 if report is not None and draft_paths is not None else {}))
        finally:
            seen["lead_calls"] = lead.return_value.decompose_specification.call_count
    return files, agent, client, seen


def test_code_defect_on_the_intent_repairs_the_committed_intent_without_regenerating(tf, tmp_path):
    repo = _committed_repo()
    report = _apply_report(tf, tmp_path, repo)
    fixed = intent([REPAIRED_MODULE])
    files, agent, client, seen = _develop(repo, report, repairs=[{C.INTENT_PATH: fixed}], context="Shift-Left ...")
    assert seen["swarm"] == 0 and seen["lead_calls"] == 0                 # no regeneration, no generation call
    (task,) = seen["repair_tasks"]
    assert task["persona"] == "IAC_ENGINEER"
    assert task["system"].startswith("You are StackVend's Junior IaC Engineer. You do NOT write Terraform")
    files_to_fix = json.loads(task["prompt"].split("FILES TO FIX:\n\n", 1)[1].split("\n\n", 1)[0])
    assert files_to_fix == {C.INTENT_PATH: repo[C.INTENT_PATH]}           # the committed intent, only
    diags = json.loads(task["prompt"].split("DIAGNOSTICS:\n\n", 1)[1].split("\n\nFILES TO FIX", 1)[0])
    assert [(x["code"], x["file"], x["block"], x["line"]) for x in diags] == [
        ("TF.UNSUPPORTED_ARGUMENT", C.INTENT_PATH, "module.uploads", None)]
    assert "fix the entry in infra/workload/iac_intent.json" in diags[0]["hint"]
    # the repaired intent is gated, rendered and validated; the app code is the committed bytes
    assert agent.last_validation_report.status == "PASS"
    assert files[C.INTENT_PATH] == fixed
    res = II.validate_intent(fixed, C.II.load_artifacts(), C.intent_context(vt_of(topo([UPLOADS]))))
    assert res.ok and files[C.RENDER_PATH] == II.render_intent(res.validated).files[C.RENDER_PATH]
    assert files[C.RENDER_PATH] != repo[C.RENDER_PATH]
    assert all(files[p] == repo[p] for p in APP)
    assert client.validated and client.validated[-1][C.INTENT_PATH] == fixed
    assert agent.stack_run("t-r3")["deploy_repair"]["mode"] == DR.INTENT_REPAIR


def test_an_unchanged_intent_never_passes_the_seed_and_the_loop_stays_bounded(tf, tmp_path):
    repo = _committed_repo()
    report = _apply_report(tf, tmp_path, repo)
    with pytest.raises(RepairBudgetExhausted) as ei:   # the answer reproduces the entry: the finding stays
        _develop(repo, report, repairs=[{C.INTENT_PATH: repo[C.INTENT_PATH]}], repair_max_iterations_precommit=1)
    assert ei.value.error_class is ErrorClass.CODE_DEFECT
    assert [(d.code, d.file) for d in ei.value.report.diagnostics] == [("TF.UNSUPPORTED_ARGUMENT", C.INTENT_PATH)]


def test_a_repair_that_drops_the_diagnosed_entry_is_a_preservation_violation(tf, tmp_path):
    """TI-3c: an apply finding never justifies deleting the intent entry it names."""
    repo = _committed_repo(intent([BUCKET_MODULE], [TOPIC]))
    report = _apply_report(tf, tmp_path, repo, anchor='"audit"')
    assert [d["block_address"] for d in report["diagnostics"]] == ["google_pubsub_topic.audit"]
    agents = []
    with pytest.raises(RepairBudgetExhausted):
        _develop(repo, report, repairs=[{C.INTENT_PATH: intent([BUCKET_MODULE])}], repair_max_iterations_precommit=1,
                 agent_out=agents)
    ev = [e for e in agents[0].last_repair_events if e.kind != "junior_reask"]
    assert [(e.accepted, e.reject_reason, e.removed_addresses) for e in ev] == [
        (False, "PRESERVATION_VIOLATION", ["google_pubsub_topic.audit"])]


def test_platform_defect_stops_typed_before_any_llm_call(tf, tmp_path):
    from gate_errors import PlatformDefectError
    repo = _committed_repo()
    mod = {"severity": "error", "summary": "Bad", "range": {"filename": "modules/storage-bucket/main.tf",
                                                            "start": {"line": 1, "byte": 0}}}
    report = _apply_report(tf, tmp_path, repo, extra=[mod])
    with pytest.raises(PlatformDefectError) as ei:
        _develop(repo, report)   # _NoCallGenai, no swarm, no repair answers: any LLM call would fail the test
    body = ei.value.to_body()
    assert (body["error_class"], body["stage"], body["reason"]) == ("PLATFORM_DEFECT", "developer",
                                                                    "APPLY_PLATFORM_DEFECT")


HUMAN_TF_ERROR = {"severity": "error", "summary": "Unsupported argument",
                  "range": {"filename": "human.tf", "start": {"line": 3, "column": 3, "byte": 40}}}


def test_user_owned_file_error_stops_for_the_operator_before_any_llm_call(tf, tmp_path):
    """TI-5-R3-b with the REAL apply report: a human.tf error beside an intent error -> 409 OPERATOR_ACTION_REQUIRED."""
    from gate_errors import OperatorActionRequiredError
    repo = _committed_repo()
    report = _apply_report(tf, tmp_path, repo, extra=[HUMAN_TF_ERROR])
    assert [(d["file"], d["error_class"]) for d in report["diagnostics"]] == [
        (C.INTENT_PATH, "CODE_DEFECT"), (W + "human.tf", "BROWNFIELD_CONFLICT")]
    with pytest.raises(OperatorActionRequiredError) as ei:
        _develop(repo, report)   # any LLM / swarm / repair call would fail the test
    assert ei.value.http_status == 409 and ei.value.reason == "BROWNFIELD_CONFLICT"


def test_gate_unavailable_report_keeps_todays_regeneration(tf, tmp_path):
    repo = _committed_repo()
    none = tf.apply_validation_report("", "", engine_result=False, fallback_error="IaC init failed: x")
    draft = dict(APP, **{C.INTENT_PATH: repo[C.INTENT_PATH]})
    _files, agent, _c, seen = _develop(repo, none, swarm_draft=draft, context="IaC init failed: x")
    assert seen["swarm"] == 1 and not seen["repair_tasks"]                 # today's path: a regeneration
    assert agent.stack_run("t-r3")["deploy_repair"]["mode"] == DR.REGENERATE


def test_legacy_workload_requests_are_byte_identical_with_or_without_a_report():
    """Do No Harm: a legacy (HCL) workload never takes the new path; its single-turn request (model, prompt, system
    instruction) is byte-identical whether the workflow forwarded a report or not, and the tree is the same."""
    legacy_repo = dict(APP)
    tf_draft = {W + "custom.tf": 'resource "google_storage_bucket" "uploads" {\n  name = "${var.product_id}-u"\n'
                                 '  location = var.region\n  uniform_bucket_level_access = true\n}\n'}
    answer = json.dumps({"files": dict(APP, **tf_draft), "summary": "s"})
    report = _report(_diag())
    runs = []
    for rep in (None, report):
        genai = _RecordingGenai(answer)
        files, agent, _c, seen = _develop(legacy_repo, rep, genai=genai, context="Error: bad")
        runs.append((genai.seen, files, seen["repair_tasks"]))
        assert ("deploy_repair" in agent.stack_run("t-r3")) is (rep is not None)
    assert runs[0] == runs[1] and len(runs[0][0]) == 1
    assert "CRITICAL IAC REMEDIATION NOTICE (Attempt 1)" in runs[0][0][0][1]


def test_intent_workload_without_a_report_is_todays_regeneration():
    """An older workflow (no tf_validation_report) on an intent workload: the regeneration runs as before."""
    repo = _committed_repo()
    draft = dict(APP, **{C.INTENT_PATH: repo[C.INTENT_PATH]})
    _files, agent, _c, seen = _develop(repo, None, swarm_draft=draft, context="Error: bad")
    assert seen["swarm"] == 1 and "deploy_repair" not in agent.stack_run("t-r3")


# ------------------------------------------------------------------------------------------------ repair loop scope
def test_a_finding_outside_the_intent_stops_the_deploy_repair_instead_of_editing_app_code(tf, tmp_path):
    """Repairs edit only the intent: a precommit finding on a committed app file (a validator that disagrees with the
    first build) stops the loop typed; the app code is never sent to an LLM."""
    repo = _committed_repo()
    repo["apps/shop/main.py"] = repo["apps/shop/main.py"] + "\ndef broken(:\n"
    report = _apply_report(tf, tmp_path, repo)
    from shared.diagnostics import StageError
    with pytest.raises(StageError) as ei:
        _develop(repo, report, repairs=[{C.INTENT_PATH: intent([REPAIRED_MODULE])}])
    assert "without a repairable owner" in str(ei.value)


def test_repair_loop_without_seeds_or_scope_is_unchanged():
    """DNH: the new LoopContext fields default to 'nothing changes'."""
    from developer_agent.repair_loop import LoopContext
    ctx = LoopContext(trace_id="t", product_id="p", assemble=lambda d: None, stack=None, ledger_store=None,
                      settings=None, attribution={}, llm_draft_paths=set(), preexisting=set())
    assert ctx.seed_diagnostics == () and ctx.seed_entries == {} and ctx.repairable_paths is None


# ------------------------------------------------------------------------------------------------ gateway contract
def test_gateway_passes_tf_validation_report_to_the_developer(gw, monkeypatch):
    report = _report(_diag())
    assert gw.DeveloperExecuteRequest(product_id="svc").tf_validation_report is None   # an older workflow
    # an older gateway ignores the new body field: the request model ignores unknown keys (it never forbade them)
    assert gw.DeveloperExecuteRequest.model_config.get("extra") in (None, "ignore")
    assert not hasattr(gw.DeveloperExecuteRequest(product_id="svc", a_future_field=1), "a_future_field")
    req = gw.DeveloperExecuteRequest(product_id="svc", trace_id="t1", tf_validation_report=report)
    assert req.tf_validation_report == report
    db = FakeDB()
    db.docs["workloads/svc/compliance_audits/t1"] = {
        "product_id": "svc", "trace_id": "t1", "allow_unauthenticated": True, "enable_direct_iap": False,
        "domain_restricted_sharing": False, "allowed_domains": []}
    monkeypatch.setattr(gw, "db", db)
    monkeypatch.setattr(gw.developer_agent, "fetch_github_token", lambda *a, **k: None)
    got = {}
    monkeypatch.setattr(gw.developer_agent, "generate_code_files", lambda **kw: got.update(kw) or {"a.py": "x=1\n"})
    monkeypatch.setattr(gw.developer_agent, "commit_and_open_pr", lambda **kw: {
        "status": "COMMITTED", "branch_name": kw["branch_name"], "commit_sha": "c" * 40,
        "files_committed": ["a.py"], "pull_request_url": "https://example.invalid/pr/2"})
    gw._execute_developer_logic(req)
    assert got["tf_validation_report"] == report


# ------------------------------------------------------------------------------------------------ workflow simulator
@pytest.fixture(scope="module")
def workflow():
    return load_workflow(WORKFLOW)


def _wf_run(workflow, deploys, developer):
    from test_lane17_workflow_sim import Fleet, _args
    f = Fleet(**{"/agent/developer/execute": developer})
    f.callbacks["deploy"] = list(deploys)
    sim = Simulator(http_handler=f.http, callback_handler=f.callback, pubsub_handler=f.pubsub, null_map_get="error")
    return sim.run(workflow, _args()), f


def _dev_ok(body):
    return 200, {"status": "SUCCESS", "branch_name": "castor/app-1", "files_committed": ["apps/app/main.py"],
                 "commit_sha": "c" * 40}


def test_workflow_forwards_the_typed_report_and_the_intent_repair_redeploys(workflow, tf, tmp_path):
    """End to end: the deploy fails with a typed report -> the workflow forwards it -> the developer repairs the
    committed intent (no regeneration) -> redeploy succeeds."""
    repo = _committed_repo()
    report = _apply_report(tf, tmp_path, repo)
    fixed = intent([REPAIRED_MODULE])
    seen_dev = []

    def developer(body):
        seen_dev.append(body)
        if body.get("tf_validation_report") is None:
            return _dev_ok(body)
        files, _agent_, _c, seen = _develop(repo, body["tf_validation_report"], repairs=[{C.INTENT_PATH: fixed}],
                                             context=body["tf_remediation_context"])
        assert seen["swarm"] == 0 and files[C.INTENT_PATH] == fixed
        return _dev_ok(body)

    deploys = [{"status": "FAILED", "error": "Shift-Left IaC validation failed:\nUnsupported argument",
                "validation_report": report, "outputs": {"validation_report": report}},
               {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, f = _wf_run(workflow, deploys, developer)
    assert res.state == "SUCCEEDED", res.error
    assert [b.get("tf_validation_report") for b in seen_dev] == [None, report]
    assert seen_dev[1]["tf_remediation_context"].startswith("Shift-Left IaC validation failed")
    assert seen_dev[1]["tf_retry_count"] == 1
    assert len(res.calls_to("https://tf.test/deploy-async")) == 2


def test_workflow_platform_defect_stops_with_its_class_and_never_redeploys(workflow, tf, tmp_path):
    from gate_errors import GateError
    repo = _committed_repo()
    mod = {"severity": "error", "summary": "Bad", "range": {"filename": "modules/storage-bucket/main.tf",
                                                            "start": {"line": 1, "byte": 0}}}
    report = _apply_report(tf, tmp_path, repo, extra=[mod])

    def developer(body):
        if body.get("tf_validation_report") is None:
            return _dev_ok(body)
        try:
            _develop(repo, body["tf_validation_report"], context=body["tf_remediation_context"])
        except GateError as ge:   # the gateway's _gate_error_handler: status + typed body
            return ge.http_status, ge.to_body()
        raise AssertionError("PLATFORM_DEFECT did not stop")

    deploys = [{"status": "FAILED", "error": "Shift-Left IaC validation failed", "validation_report": report}]
    res, f = _wf_run(workflow, deploys, developer)
    assert res.state == "FAILED"
    assert (res.error["error_class"], res.error["stage"]) == ("PLATFORM_DEFECT", "developer")
    assert len(res.calls_to("https://tf.test/deploy-async")) == 1
    assert len(res.calls_to("/agent/developer/execute")) == 2


def test_workflow_old_tf_applier_without_a_report_is_todays_text_remediation(workflow):
    """Mixed versions: an older tf-applier sends no report -> the field is null and the error text rides as before;
    a later deploy without a report never carries the previous report forward."""
    seen_dev = []

    def developer(body):
        seen_dev.append(body)
        return _dev_ok(body)

    untyped = {"status": "FAILED", "error_class": "IAC_DEFECT", "error": "bad hcl"}
    typed = {"status": "FAILED", "error": "still bad", "validation_report": _report(_diag())}
    ok = {"status": "SUCCESS", "service_url": "https://app.run.app"}
    res, _f = _wf_run(workflow, [untyped, typed, ok], developer)
    assert res.state == "SUCCEEDED", res.error
    assert [(b["tf_remediation_context"], b["tf_validation_report"]) for b in seen_dev] == [
        ("", None), ("bad hcl", None), ("still bad", _report(_diag()))]
    seen_dev.clear()
    res, _f = _wf_run(workflow, [typed, untyped, ok], developer)
    assert res.state == "SUCCEEDED", res.error
    assert [b["tf_validation_report"] for b in seen_dev] == [None, _report(_diag()), None]


def test_workflow_first_build_sends_a_null_report(workflow):
    from test_lane17_workflow_sim import Fleet, _args
    seen_dev = []
    f = Fleet(**{"/agent/developer/execute": lambda body: seen_dev.append(body) or _dev_ok(body)})
    sim = Simulator(http_handler=f.http, callback_handler=f.callback, pubsub_handler=f.pubsub, null_map_get="error")
    res = sim.run(workflow, _args())
    assert res.state == "SUCCEEDED", res.error
    assert seen_dev[0]["tf_validation_report"] is None


def test_workflow_qa_retry_after_an_intent_repair_is_todays_regeneration(workflow):
    """A QA code defect is not a deploy finding: the QA re-run of the developer carries no report (today's path)."""
    from test_lane17_workflow_sim import Fleet, _args
    seen_dev = []
    passed = (200, {"passed": True, "error_class": None, "summary": "QA passed"})
    defect = (200, {"passed": False, "error_class": "CODE_DEFECT", "retryable": True, "summary": "tests failed"})
    f = Fleet(**{"/agent/developer/execute": lambda body: seen_dev.append(body) or _dev_ok(body),
                 "/agent/qa/verify": [passed, defect, passed]})
    f.callbacks["deploy"] = [{"status": "FAILED", "error": "still bad", "validation_report": _report(_diag())},
                             {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    sim = Simulator(http_handler=f.http, callback_handler=f.callback, pubsub_handler=f.pubsub, null_map_get="error")
    res = sim.run(workflow, _args())
    assert res.state == "SUCCEEDED", res.error
    assert [(b["retry_count"], b["tf_retry_count"], b["tf_validation_report"]) for b in seen_dev] == [
        (0, 0, None), (0, 1, _report(_diag())), (1, 1, None)]
    assert seen_dev[2]["tf_remediation_context"] == "still bad"   # the text context is kept, as before


# ------------------------------------------------------------------------------------------------ TI-5-R3-c
def _sync_dev(gw, monkeypatch, err):
    from fastapi.testclient import TestClient
    monkeypatch.setattr(gw, "_execute_developer_logic", lambda req: (_ for _ in ()).throw(err))
    return TestClient(gw.app).post("/agent/developer/execute", json={"trace_id": "t1", "product_id": "app"})


@pytest.mark.parametrize("cls,status", [(ErrorClass.CODE_DEFECT, 422), (ErrorClass.PLATFORM_DEFECT, 503),
                                        (ErrorClass.BROWNFIELD_CONFLICT, 409)])
def test_sync_developer_stage_error_keeps_its_class_and_status(gw, monkeypatch, cls, status):
    """TI-5-R3-c (owner 10-25): a typed developer StageError is answered with HTTP_STATUS[class] and the async
    callback's typed fields, never an untyped 500."""
    from shared.diagnostics import StageError
    rep = ValidationReport(status="FAIL", source="precommit", artifact_hash="",
                           diagnostics=[_diag(cls=cls, line=None).model_copy(update={"source": "precommit"})])
    r = _sync_dev(gw, monkeypatch, StageError(rep, "stopped"))
    assert r.status_code == status, r.text
    body = r.json()
    assert (body["error_class"], body["stage"], body["status"], body["validation_status"]) == (
        cls.value, "developer", "FAILED", "FAIL")
    assert body["diagnostics_total"] == 1 and body["diagnostics"][0]["code"] == "TF.UNSUPPORTED_ARGUMENT"
    assert "reason" not in body and body["exhausted_reason"] is None


def test_sync_developer_repair_budget_exhausted_is_409_with_its_reason(gw, monkeypatch):
    rep = ValidationReport(status="FAIL", source="precommit", artifact_hash="", diagnostics=[_diag(line=None)])
    r = _sync_dev(gw, monkeypatch, RepairBudgetExhausted(rep, "NO_PROGRESS"))
    assert r.status_code == 409, r.text
    body = r.json()
    assert (body["error_class"], body["reason"], body["exhausted_reason"]) == (
        "CODE_DEFECT", "REPAIR_BUDGET_EXHAUSTED", "NO_PROGRESS")


def test_sync_developer_gate_unavailable_stage_error_is_503(gw, monkeypatch):
    from shared.diagnostics import StageError
    rep = ValidationReport(status="UNAVAILABLE", source="precommit", artifact_hash="", tools_unavailable=["V1b"])
    r = _sync_dev(gw, monkeypatch, StageError(rep, "validate service not ready"))
    assert r.status_code == 503 and r.json()["error_class"] == "GATE_UNAVAILABLE"
    assert r.json()["tools_unavailable"] == ["V1b"]


def test_sync_developer_untyped_error_is_still_500(gw, monkeypatch):
    """Do No Harm: anything that is not a typed StageError / GateError keeps today's untyped 500."""
    r = _sync_dev(gw, monkeypatch, RuntimeError("boom"))
    assert r.status_code == 500 and r.json() == {"detail": "boom"}


def test_workflow_records_the_typed_developer_class_not_dependency_failed(workflow, gw, monkeypatch):
    """End to end: the gateway's typed 409 body reaches the workflow's failure handler with its class."""
    from fastapi.testclient import TestClient
    rep = ValidationReport(status="FAIL", source="precommit", artifact_hash="", diagnostics=[_diag(line=None)])
    monkeypatch.setattr(gw, "_execute_developer_logic",
                        lambda req: (_ for _ in ()).throw(RepairBudgetExhausted(rep, "ITERATIONS")))
    client = TestClient(gw.app)

    def developer(body):
        r = client.post("/agent/developer/execute", json={k: body[k] for k in ("trace_id", "product_id")})
        return r.status_code, r.json()

    res, _f = _wf_run(workflow, [{"status": "SUCCESS"}], developer)
    assert res.state == "FAILED"
    assert (res.error["error_class"], res.error["stage"], res.error["reason"]) == (
        "CODE_DEFECT", "developer", "REPAIR_BUDGET_EXHAUSTED")


def test_workflow_user_owned_deploy_error_stops_for_the_operator(workflow, tf, tmp_path):
    from gate_errors import GateError
    repo = _committed_repo()
    report = _apply_report(tf, tmp_path, repo, extra=[HUMAN_TF_ERROR])

    def developer(body):
        if body.get("tf_validation_report") is None:
            return _dev_ok(body)
        try:
            _develop(repo, body["tf_validation_report"], context=body["tf_remediation_context"])
        except GateError as ge:
            return ge.http_status, ge.to_body()
        raise AssertionError("BROWNFIELD_CONFLICT did not stop")

    res, _f = _wf_run(workflow, [{"status": "FAILED", "error": "x", "validation_report": report}], developer)
    assert res.state == "FAILED"
    assert (res.error["error_class"], res.error["reason"]) == ("OPERATOR_ACTION_REQUIRED", "BROWNFIELD_CONFLICT")
    assert len(res.calls_to("https://tf.test/deploy-async")) == 1


def test_workflow_f1_drops_the_callback_copies_on_remediation(workflow):
    """F1 (memory): increment_tf_retry reads the report first, then drops the callback copies; the redeploy
    reassigns them (the simulator raises on any read of an unassigned / null map)."""
    import yaml
    seen = []
    report = _report(_diag())
    res, _f = _wf_run(workflow, [{"status": "FAILED", "error": "bad", "validation_report": report},
                                 {"status": "SUCCESS", "service_url": "https://app.run.app"}],
                      lambda body: seen.append(body) or _dev_ok(body))
    assert res.state == "SUCCEEDED", res.error
    assert seen[1]["tf_validation_report"] == report
    with open(WORKFLOW) as fh:
        doc = yaml.safe_load(fh)
    steps = {k: v for s in doc["run_pipeline"]["steps"] for k, v in s.items()}
    assigns = [list(a)[0] for a in steps["increment_tf_retry"]["assign"]]
    assert assigns[-2:] == ["deploy_callback_response", "deployment_output"]
    assert assigns.index("tf_validation_report") < assigns.index("deployment_output")



# ------------------------------------------------------------------------------------------------ SAT-49 (Fable RT F2)
# QA-REPAIR-OWNERSHIP-PARITY: an INTENT_REPAIR's draft is exactly the released build's own files (the gateway's
# committed_draft record, matched to the trace's merged PR head by exact sha); every other file of the repository
# stays the repository's. Without the record an INTENT_REPAIR is today's regeneration (DRAFT_PATHS_UNAVAILABLE).
ROUTES = "apps/shop/routes.py"
SCHEMAS = "apps/shop/schemas/__init__.py"


def _relaunched_repo():
    """An intent workload's main branch after a relaunch: this build's files plus an earlier build's dead module
    whose import the current `schemas` package no longer provides (the e2 shape)."""
    repo = dict(_committed_repo(), **{SCHEMAS: "class Other:\n    pass\n"})
    released = sorted(p for p in repo if not p.startswith(".github/"))   # what the released dispatch wrote
    repo[ROUTES] = "from schemas import EventInboundRequest\n\n\ndef route():\n    return EventInboundRequest\n"
    return repo, released


def test_plan_intent_repair_draft_is_the_released_builds_own_files():
    repo, released = _relaunched_repo()
    raw = _report(_diag())
    p = DR.plan_deploy_repair(raw, intent_run=INTENT_RUN, existing_files=repo, draft_paths=released)
    assert (p.mode, p.reason) == (DR.INTENT_REPAIR, "CODE_DEFECT_ON_INTENT")
    assert ROUTES not in p.draft and p.draft == {k: v for k, v in DR.repair_draft(repo).items() if k != ROUTES}
    # every file recorded = the draft before SAT-49 exactly (Do No Harm on a fresh repository)
    assert DR.repair_draft(repo, frozenset(repo)) == DR.repair_draft(repo)


@pytest.mark.parametrize("paths", [None, [], [C.INTENT_PATH, 3], "x", [f"f{i}" for i in range(DR.DRAFT_PATHS_MAX + 1)]])
def test_plan_intent_repair_without_a_usable_record_is_todays_regeneration(paths):
    repo, _released = _relaunched_repo()
    p = DR.plan_deploy_repair(_report(_diag()), intent_run=INTENT_RUN, existing_files=repo, draft_paths=paths)
    assert (p.mode, p.reason, p.draft) == (DR.REGENERATE, DR.DRAFT_PATHS_UNAVAILABLE, {})


def test_plan_stops_and_other_rows_need_no_draft_record():
    """Only the INTENT_REPAIR row reads the record: the STOPs and every regeneration keep their reason."""
    repo = _committed_repo()
    stop = _report(_diag(), _diag(cls=ErrorClass.PLATFORM_DEFECT, file=W + "main.tf", block="module.compute"))
    assert DR.plan_deploy_repair(stop, intent_run=INTENT_RUN, existing_files=repo).mode == DR.STOP
    other = DR.plan_deploy_repair(_report(_diag(block="module.other")), intent_run=INTENT_RUN, existing_files=repo)
    assert other.reason == "FINDING_NOT_ON_A_COMMITTED_INTENT_ENTRY"
    assert DR.plan_deploy_repair(None, intent_run=INTENT_RUN, existing_files=repo).reason == "NO_REPORT"


def test_intent_repair_over_an_earlier_builds_dead_file_reaches_an_iteration(tf, tmp_path):
    """F2, the e2 relaunch: today the whole repository is the draft, so the dead module is judged as LLM-owned and the
    loop stops before any repair; with the released build's record the repair runs and the dead file stays the
    repository's (outside the validated set, as in the dispatch that released it)."""
    from shared.diagnostics import StageError
    repo, released = _relaunched_repo()
    report = _apply_report(tf, tmp_path, repo)
    fixed = intent([REPAIRED_MODULE])
    with pytest.raises(StageError) as ei:   # today's draft (every file)
        _develop(repo, report, repairs=[{C.INTENT_PATH: fixed}], draft_paths=sorted(repo))
    assert "without a repairable owner" in str(ei.value)
    assert ROUTES in {d.file for d in ei.value.report.diagnostics}
    files, agent, _client, seen = _develop(repo, report, repairs=[{C.INTENT_PATH: fixed}], draft_paths=released)
    (task,) = seen["repair_tasks"]
    assert task["persona"] == "IAC_ENGINEER" and seen["swarm"] == 0
    assert agent.last_validation_report.status == "PASS" and files[C.INTENT_PATH] == fixed
    assert ROUTES not in files
    assert agent.stack_run("t-r3")["llm_draft_paths"] == sorted(DR.repair_draft(repo, frozenset(released)))


def test_intent_repair_without_the_record_regenerates(tf, tmp_path):
    repo, _released = _relaunched_repo()
    report = _apply_report(tf, tmp_path, repo)
    draft = dict(APP, **{C.INTENT_PATH: repo[C.INTENT_PATH]})
    _files, agent, _c, seen = _develop(repo, report, swarm_draft=draft, context="Shift-Left ...", draft_paths=None)
    assert seen["swarm"] == 1 and not seen["repair_tasks"]
    assert agent.stack_run("t-r3")["deploy_repair"]["reason"] == DR.DRAFT_PATHS_UNAVAILABLE


def _gateway_dispatch(gw, monkeypatch, record, ledger):
    """The kwargs a terraform remediation dispatch passes to generate_code_files, with the trace's committed_draft
    `record` and PR ledger entries `ledger` in the store."""
    db = FakeDB()
    db.docs["workloads/svc/compliance_audits/t1"] = {
        "product_id": "svc", "trace_id": "t1", "allow_unauthenticated": True, "enable_direct_iap": False,
        "domain_restricted_sharing": False, "allowed_domains": []}
    if record is not None:
        db.docs["pipeline_executions/t1"] = {"stages": {"developer": {"committed_draft": record}}}
    for i, e in enumerate(ledger):
        db.docs[f"vcs_ledger/l{i}"] = dict({"ledger_id": f"l{i}", "product_id": "svc", "trace_id": "t1",
                                            "origin": "DEVELOPER", "state": "MERGED"}, **e)
    monkeypatch.setattr(gw, "db", db)
    monkeypatch.setattr(gw.developer_agent, "fetch_github_token", lambda *a, **k: None)
    got = {}
    monkeypatch.setattr(gw.developer_agent, "generate_code_files", lambda **kw: got.update(kw) or {"a.py": "x=1\n"})
    monkeypatch.setattr(gw.developer_agent, "commit_and_open_pr", lambda **kw: {
        "status": "COMMITTED", "branch_name": kw["branch_name"], "commit_sha": "c" * 40,
        "files_committed": ["a.py"], "pull_request_url": "https://example.invalid/pr/2"})
    monkeypatch.setattr(gw, "_assert_tf_remediation_allowed", lambda *a, **k: None)
    gw._execute_developer_logic(gw.DeveloperExecuteRequest(product_id="svc", trace_id="t1", tf_retry_count=1,
                                                           tf_validation_report=_report(_diag())))
    return got


SHA_A, SHA_B = "a" * 40, "b" * 40


def test_gateway_forwards_the_record_only_for_the_traces_latest_merged_commit(gw, monkeypatch):
    rec = {"commit_sha": SHA_A, "llm_draft_paths": [C.INTENT_PATH, "apps/shop/main.py"]}
    got = _gateway_dispatch(gw, monkeypatch, rec, [{"head_sha": SHA_A, "created_at": "2026-11-02T10:00:00+00:00"}])
    assert got[DR.DRAFT_PATHS_KWARG] == sorted(rec["llm_draft_paths"])
    for record, ledger in [
        (None, [{"head_sha": SHA_A, "created_at": "1"}]),                                       # no record
        (rec, []),                                                                              # nothing merged
        (rec, [{"head_sha": SHA_B, "created_at": "1"}]),                                        # another commit
        (rec, [{"head_sha": SHA_A, "created_at": "1"}, {"head_sha": SHA_B, "created_at": "2"}]),  # a later release
        (rec, [{"head_sha": SHA_A, "created_at": "1", "state": "OPEN"}]),                       # not merged
        (rec, [{"head_sha": SHA_A, "created_at": "1", "origin": "IAC_UPGRADE"}]),               # not the developer's
        (rec, [{"head_sha": SHA_A, "created_at": "1", "trace_id": "t-other"}]),                 # another trace
        (dict(rec, llm_draft_paths=[]), [{"head_sha": SHA_A, "created_at": "1"}]),              # an unusable record
    ]:
        got = _gateway_dispatch(gw, monkeypatch, record, ledger)
        assert DR.DRAFT_PATHS_KWARG not in got and got["tf_validation_report"] == _report(_diag()), (record, ledger)
