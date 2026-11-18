"""Step 1 R3c convergence fixes (10-13): explicit, diagnosed removals; consequential references; hints; deterministic
repair prompts; transient transport retry; specific feedback; the harness shadow-acceptance observer."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys
from unittest import mock

import pytest
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
EVAL = os.path.join(REPO_ROOT, "eval")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent import repair_loop as RL  # noqa: E402
from developer_agent.repair_loop import (Assembled, RepairTask, Router, _rejection_feedback, accept,  # noqa: E402
                                         removal_justifications, render_repair_prompt)
from shared.diagnostics import AssemblyRecord, Diagnostic, RepairEvent, ValidationReport  # noqa: E402

W = "infra/workload/"
MAIN = W + "main.tf"
ROOT = W + "root.tf"
EVENT_WORKER = {"infra/modules/event-worker/main.tf": 'resource "google_cloud_run_v2_job" "job" {\n  name = "j"\n}\n',
                "infra/modules/event-worker/outputs.tf": 'output "job_name" {\n  value = "j"\n}\n'}
CLOUDRUN = {"infra/modules/compute-cloudrun/main.tf": 'resource "google_cloud_run_v2_service" "svc" {\n  name = "s"\n}\n',
            "infra/modules/compute-cloudrun/outputs.tf": 'output "service_uri" {\n  value = "u"\n}\n'}
OLD = "google_cloud_run_v2_service.backend"
SA = 'resource "google_service_account" "sa" {\n  account_id = "sa"\n}\n'
IAM = ('resource "google_cloud_run_v2_service_iam_member" "invoker" {\n  name   = google_cloud_run_v2_service.backend.name\n'
       '  role   = "roles/run.invoker"\n  member = "serviceAccount:x"\n}\n')
CR = 'resource "google_cloud_run_v2_service" "backend" {\n  name = "b"\n}\n'
TOPIC = 'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n'


def _module(src):
    return f'module "compute" {{\n  source = "../modules/{src}"\n}}\n'


def _rec():
    rec = AssemblyRecord()
    rec.record(OLD, "module.compute", "CLOUD_RUN_REPLACED_BY_MODULE", MAIN)
    return rec


def _asm(draft, module_src="event-worker", modules=EVENT_WORKER, with_module=True):
    """Assembly as the platform does it: the LLM's Cloud Run block is replaced by module.compute."""
    root = {p: t.replace(CR, "") for p, t in draft.items() if p.endswith(".tf")}
    if with_module:
        root[ROOT] = _module(module_src)
    return Assembled(tree=dict(root, **modules), record=_rec(), assembled_root=root)


def _d(code, block=None, symbol=None, file=MAIN, msg="m"):
    return Diagnostic(tool="tofu", code=code, severity="error", file=file, block_address=block, symbol=symbol,
                      message=msg, source="precommit")


def _rep(*diags):
    return ValidationReport(status="FAIL" if diags else "PASS", source="precommit", artifact_hash="h",
                            diagnostics=list(diags))


REF = "TF.REFERENCE_TO_UNDECLARED_RESOURCE"


# ------------------------------------------------------------------------------------------------ removals
def test_removing_the_replaced_draft_block_is_justified_while_the_replacement_stays():
    d1 = {MAIN: SA + CR}
    d2 = {MAIN: SA}
    prev = _rep(_d(REF, "output.url", OLD, W + "outputs.tf"))
    removed = {OLD}
    asm1, asm2 = _asm(d1), _asm(d2)
    assert removal_justifications(d1, d2, asm1, asm2, prev, removed) == {OLD: "REPLACED:module.compute"}
    assert accept(d1, d2, asm1, asm2, prev, _rep(), removed, "x") == (True, None)


def test_removing_the_replaced_block_is_a_violation_when_the_replacement_disappears():
    """R3c 02-r3: deleting the draft's Cloud Run block made the platform stop synthesizing the module."""
    d1, d2 = {MAIN: SA + CR}, {MAIN: SA}
    prev = _rep(_d(REF, "output.url", OLD, W + "outputs.tf"))
    asm2 = _asm(d2, with_module=False)
    assert removal_justifications(d1, d2, _asm(d1), asm2, prev, {OLD}) == {}
    assert accept(d1, d2, _asm(d1), asm2, prev, _rep(), {OLD}, "x") == (False, "PRESERVATION_VIOLATION")


def test_dead_reference_block_may_be_removed_when_the_module_manages_no_equivalent():
    key = "google_cloud_run_v2_service_iam_member.invoker"
    d1, d2 = {MAIN: SA + CR + IAM}, {MAIN: SA + CR}
    prev = _rep(_d(REF, key, OLD))
    asm1, asm2 = _asm(d1), _asm(d2)
    assert removal_justifications(d1, d2, asm1, asm2, prev, {key}) == {key: "DEAD_REFERENCE:" + OLD}
    assert accept(d1, d2, asm1, asm2, prev, _rep(), {key}, "x") == (True, None)


def test_dead_reference_rule_does_not_apply_when_the_module_manages_the_replaced_type():
    """compute-cloudrun manages a google_cloud_run_v2_service: the reference must be rewired, not deleted."""
    key = "google_cloud_run_v2_service_iam_member.invoker"
    d1, d2 = {MAIN: SA + CR + IAM}, {MAIN: SA + CR}
    prev = _rep(_d(REF, key, OLD))
    asm1 = _asm(d1, "compute-cloudrun", CLOUDRUN)
    asm2 = _asm(d2, "compute-cloudrun", CLOUDRUN)
    assert removal_justifications(d1, d2, asm1, asm2, prev, {key}) == {}
    assert accept(d1, d2, asm1, asm2, prev, _rep(), {key}, "x") == (False, "PRESERVATION_VIOLATION")


def test_block_with_a_non_reference_diagnostic_is_not_a_dead_reference():
    key = "google_cloud_run_v2_service_iam_member.invoker"
    d1, d2 = {MAIN: SA + CR + IAM}, {MAIN: SA + CR}
    prev = _rep(_d(REF, key, OLD), _d("TF.UNSUPPORTED_ARGUMENT", key))
    assert accept(d1, d2, _asm(d1), _asm(d2), prev, _rep(), {key}, "x") == (False, "PRESERVATION_VIOLATION")


def test_undiagnosed_block_deletion_is_still_rejected_next_to_justified_removals():
    """NEGATIVE (R3c 01-r1 it 1): the candidate also deleted google_pubsub_subscription-like undiagnosed blocks."""
    key = "google_cloud_run_v2_service_iam_member.invoker"
    d1, d2 = {MAIN: SA + TOPIC + CR + IAM}, {MAIN: SA}
    prev = _rep(_d(REF, key, OLD))
    removed = {key, OLD, "google_pubsub_topic.t"}
    just = removal_justifications(d1, d2, _asm(d1), _asm(d2), prev, removed)
    assert "google_pubsub_topic.t" not in just and set(just) == {key, OLD}
    assert accept(d1, d2, _asm(d1), _asm(d2), prev, _rep(), removed, "x") == (False, "PRESERVATION_VIOLATION")


def test_privileged_role_block_may_be_removed():
    key = "google_project_iam_member.owner"
    blk = 'resource "google_project_iam_member" "owner" {\n  role = "roles/owner"\n  member = "user:x"\n}\n'
    d1, d2 = {MAIN: SA + blk}, {MAIN: SA}
    prev = _rep(_d("POLICY.PRIVILEGED_ROLE", key))
    a1 = Assembled(tree=dict(d1), record=AssemblyRecord())
    a2 = Assembled(tree=dict(d2), record=AssemblyRecord())
    assert removal_justifications(d1, d2, a1, a2, prev, {key}) == {key: "REMOVAL_CODE:POLICY.PRIVILEGED_ROLE"}
    assert accept(d1, d2, a1, a2, prev, _rep(), {key}, "x") == (True, None)
    # a warning-severity finding never justifies a removal
    warn = Diagnostic(tool="policy", code="POLICY.PRIVILEGED_ROLE", severity="warning", file=MAIN, block_address=key,
                      message="m", source="precommit")
    other = _d("TF.UNSUPPORTED_ARGUMENT", "google_service_account.sa")
    assert accept(d1, d2, a1, a2, _rep(other, warn), _rep(), {key}, "x") == (False, "PRESERVATION_VIOLATION")


def test_removal_reasons_is_an_optional_event_field():
    ev = RepairEvent(trace_id="t", product_id="p", iteration=1, source="precommit", persona="x", files=[], codes=[],
                     fingerprints_before=[], fingerprints_after=[], accepted=True, model="m")
    assert ev.removal_reasons == {}
    ev2 = ev.model_copy(update={"removal_reasons": {"a.b": "REPLACED:module.c"}})
    assert RepairEvent.model_validate(ev2.model_dump(mode="json")).removal_reasons == {"a.b": "REPLACED:module.c"}


# ------------------------------------------------------------------------------------------------ consequential refs
PSVC = 'resource "google_project_service" "apis" {\n  service = "run.googleapis.com"\n}\n'
NET = 'resource "google_compute_network" "vpc" {\n  name = "v"\n  depends_on = [google_project_service.apis]\n}\n'


def _plain(d):
    return Assembled(tree=dict(d), record=AssemblyRecord(), assembled_root=dict(d))


def test_dangling_reference_to_a_justified_removal_is_accepted_with_net_progress():
    """R3c 03-r1 / 04-r3 / 07-r1: deleting the platform-owned block leaves a depends_on to it."""
    d1, d2 = {MAIN: PSVC + NET}, {MAIN: NET}
    prev = _rep(_d("POLICY.PLATFORM_OWNED_TYPE", "google_project_service.apis"),
                _d("POLICY.PUBLIC_MEMBER", "google_x.y"))
    new = _rep(_d(REF, "google_compute_network.vpc", "google_project_service.apis"))
    assert accept(d1, d2, _plain(d1), _plain(d2), prev, new, {"google_project_service.apis"}, "x") == (True, None)


def test_dangling_reference_without_net_progress_is_rejected():
    d1, d2 = {MAIN: PSVC + NET}, {MAIN: NET}
    prev = _rep(_d("POLICY.PLATFORM_OWNED_TYPE", "google_project_service.apis"))
    new = _rep(_d(REF, "google_compute_network.vpc", "google_project_service.apis"))
    assert accept(d1, d2, _plain(d1), _plain(d2), prev, new, {"google_project_service.apis"}, "x") == \
        (False, "NEW_FINGERPRINT")


def test_real_regression_is_still_rejected():
    """NEGATIVE: a new error that is not a reference to a justified removal (R3c 01-r2: an invented module output;
    R3c 06-r2/08-r1: a file that stopped parsing) is a NEW_FINGERPRINT even when the count drops."""
    d1, d2 = {MAIN: PSVC + NET}, {MAIN: NET}
    prev = _rep(_d("POLICY.PLATFORM_OWNED_TYPE", "google_project_service.apis"), _d("POLICY.PUBLIC_MEMBER", "a.b"),
                _d("POLICY.PUBLIC_MEMBER", "a.c"))
    for bad in (_d("TF.UNSUPPORTED_ATTRIBUTE", "output.service_url"),
                _d(REF, "google_compute_network.vpc", "google_storage_bucket.never_declared"),
                _d(REF, "google_compute_network.vpc", "google_project_service.other")):
        assert accept(d1, d2, _plain(d1), _plain(d2), prev, _rep(bad), {"google_project_service.apis"}, "x") == \
            (False, "NEW_FINGERPRINT"), bad


# ------------------------------------------------------------------------------------------------ hints / prompt
def _router(tree, rec):
    ctx = type("C", (), {"llm_draft_paths": set(), "preexisting": set(), "preexisting_files": {}, "prior_llm": {},
                         "attribution": {}})()
    r = Router.__new__(Router)
    r.ctx, r.draft, r.asm = ctx, {}, Assembled(tree=tree, record=rec)
    return r


def test_hint_for_a_replaced_reference_says_delete_when_no_equivalent_exists():
    tree = dict({ROOT: _module("event-worker")}, **EVENT_WORKER)
    h = json.loads(_router(tree, _rec())._hint(_d(REF, "google_cloud_run_v2_service_iam_member.invoker", OLD)))
    assert h["old"] == OLD and h["new"] == "module.compute" and h["outputs"] == ["job_name"]
    assert "manages no google_cloud_run_v2_service" in h["action"] and "Delete this block" in h["action"]


def test_hint_for_a_replaced_reference_says_rewire_when_the_module_manages_the_type():
    tree = dict({ROOT: _module("compute-cloudrun")}, **CLOUDRUN)
    h = json.loads(_router(tree, _rec())._hint(_d(REF, "output.url", OLD)))
    assert h["outputs"] == ["service_uri"] and h["action"].startswith("Replace the reference with module.compute")


def test_hint_for_a_reference_to_a_platform_owned_type():
    h = json.loads(_router({}, AssemblyRecord())._hint(_d(REF, "google_compute_network.vpc",
                                                          "google_project_service.apis")))
    assert h == {"reference": "google_project_service.apis", "action": RL.PLATFORM_OWNED_REFERENCE_ACTION}
    # any other undeclared reference keeps the validator's own hint
    assert _router({}, AssemblyRecord())._hint(_d(REF, "output.x", "google_storage_bucket.b")) is None


def test_repair_prompt_does_not_depend_on_the_validators_finding_order():
    diags = [{"code": c, "file": f, "line": n, "block": b, "message": "m", "detail": None, "snippet": None,
              "hint": None} for c, f, n, b in (("TF.B", MAIN, 3, "x.y"), ("TF.A", MAIN, 9, "x.z"),
                                              ("POLICY.C", W + "a.tf", 1, "q.r"))]

    def task(ds):
        return RepairTask(persona="IAC", files_to_fix={MAIN: "x"}, diagnostics=ds, read_only_context={}, iteration=1,
                          remaining_iterations=2, feedback="", max_output_tokens=100)
    assert render_repair_prompt(task(diags)) == render_repair_prompt(task(list(reversed(diags))))
    assert RL.REPAIR_PROMPT_VERSION == "step1-repair-v2"


def test_feedback_names_the_lost_declarations_and_is_empty_after_a_transport_failure():
    d1, d2 = {MAIN: SA + TOPIC}, {MAIN: SA}
    prev = _rep(_d("TF.UNSUPPORTED_ARGUMENT", "google_service_account.sa"))
    fb = _rejection_feedback("PRESERVATION_VIOLATION", d1, d2, _plain(d1), _plain(d2), prev, _rep(),
                             {"google_pubsub_topic.t"}, [{"envelope_ok": True}])
    assert '"google_pubsub_topic.t"' in fb
    transport = [{"envelope_ok": False, "error": "RuntimeError: 429", "finish_reason": None, "tokens_out": 0}]
    assert _rejection_feedback("ENVELOPE_INVALID", d1, None, _plain(d1), None, prev, None, set(), transport) == ""
    truncated = [{"envelope_ok": False, "error": "FINISH_REASON_MAX_TOKENS", "finish_reason": "MAX_TOKENS",
                  "tokens_out": 50}]
    assert "complete JSON" in _rejection_feedback("ENVELOPE_INVALID", d1, None, _plain(d1), None, prev, None, set(),
                                                  truncated)
    new = _rep(_d("TF.UNSUPPORTED_ATTRIBUTE", "output.u", file=W + "outputs.tf", msg="Unsupported attribute"))
    assert "TF.UNSUPPORTED_ATTRIBUTE in infra/workload/outputs.tf at output.u" in _rejection_feedback(
        "NEW_FINGERPRINT", d1, d1, _plain(d1), _plain(d1), prev, new, set(), [{}])


# ------------------------------------------------------------------------------------------------ transport retry
class _Status(Exception):
    def __init__(self, code):
        super().__init__(f"{code} status")
        self.code = code


class _Client:
    def __init__(self, failures):
        self.failures = list(failures)
        self.calls = 0
        self.models = self

    def generate_content(self, model, contents, config):
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)
        part = type("P", (), {})()
        cand = type("C", (), {"finish_reason": "STOP"})()
        usage = type("U", (), {"prompt_token_count": 10, "candidates_token_count": 5, "thoughts_token_count": 0,
                               "total_token_count": 15})()
        return type("R", (), {"text": json.dumps({"files": {MAIN: "x"}}), "candidates": [cand],
                              "usage_metadata": usage, "parts": [part]})()


def _dispatcher(failures, chain=("m",)):
    pytest.importorskip("google.genai")
    from developer_agent import swarm_dispatcher as SD
    disp = SD.SwarmDispatcher(genai_client=_Client(failures))
    slept = []
    disp._repair_sleep = slept.append
    # SLOW-CALL-FALLBACK: the repair call walks the developer cascade after its model; pinned here
    patcher = mock.patch.object(SD, "get_model_cascade_for_agent", lambda *a, **k: list(chain))
    patcher.start()
    disp._patcher = patcher
    return disp, slept


def test_transient_status_retries_once_then_walks_to_the_next_model():
    # SLOW-CALL-FALLBACK (owner 11-13) + RT F10 (owner 11-14): a 429 / 503 is retried once on the same model after
    # 4 s, then the walk goes to the next model of the cascade (was: the same model again after 4 s and 16 s)
    disp, slept = _dispatcher([_Status(429), _Status(503)], chain=("m", "m2", "m3"))
    try:
        out = disp.invoke_repair("IAC", "sys", "prompt", "m", 1000)
    finally:
        disp._patcher.stop()
    assert out["envelope_ok"] and out["files"] == {MAIN: "x"} and out["transport_attempts"] == 3
    assert out["model"] == "m2" and out["model_fallback_reason"] == "TRANSIENT_503"
    assert slept == [4.0] and disp.genai_client.calls == 3


def test_a_500_walks_at_once():
    disp, slept = _dispatcher([_Status(500)], chain=("m", "m2"))
    try:
        out = disp.invoke_repair("IAC", "sys", "prompt", "m", 1000)
    finally:
        disp._patcher.stop()
    assert out["model"] == "m2" and slept == [] and disp.genai_client.calls == 2


def test_transient_on_the_last_model_is_retried_with_bounded_backoff():
    from developer_agent.swarm_dispatcher import REPAIR_RETRY_BACKOFF_S
    disp, slept = _dispatcher([_Status(429), _Status(503)])
    try:
        out = disp.invoke_repair("IAC", "sys", "prompt", "m", 1000)
    finally:
        disp._patcher.stop()
    assert out["envelope_ok"] and out["files"] == {MAIN: "x"} and out["transport_attempts"] == 3
    assert slept == list(REPAIR_RETRY_BACKOFF_S) and disp.genai_client.calls == 3


def test_retry_is_bounded_and_other_errors_are_not_retried():
    disp, slept = _dispatcher([_Status(429), _Status(429), _Status(429), _Status(429)])
    try:
        out = disp.invoke_repair("IAC", "sys", "prompt", "m", 1000)
    finally:
        disp._patcher.stop()
    assert not out["envelope_ok"] and "TRANSIENT_429" in out["error"] and disp.genai_client.calls == 3
    assert len(slept) == 2 and out["error_code"] == "LLM_FALLBACK_EXHAUSTED"
    for exc in (_Status(400), RuntimeError("429 RESOURCE_EXHAUSTED (no status attribute)"), _Status(True)):
        disp, slept = _dispatcher([exc])
        try:
            out = disp.invoke_repair("IAC", "sys", "prompt", "m", 1000)
        finally:
            disp._patcher.stop()
        assert out["error"] and disp.genai_client.calls == 1 and slept == [], exc


# ------------------------------------------------------------------------------------------------ harness observer
def test_shadow_observer_returns_the_recorded_verdict_and_records_the_products(tmp_path):
    if EVAL not in sys.path:
        sys.path.insert(0, EVAL)
    from stackvend_eval.stages import install_accept_observer
    real = RL.accept
    sink = []
    try:
        info = install_accept_observer(sink, {1: (False, "NEW_FINGERPRINT")})
        assert info["installed"] and info["shadow"]
        d1, d2 = {MAIN: SA + CR}, {MAIN: SA}
        prev = _rep(_d(REF, "output.url", OLD, W + "outputs.tf"))
        new = _rep().model_copy(update={"repair_iteration": 1})
        assert RL.accept(d1, d2, _asm(d1), _asm(d2), prev, new, {OLD}, "x") == (False, "NEW_FINGERPRINT")
        assert sink[0]["product_verdict"] == [True, None] and sink[0]["forced_verdict"] == [False, "NEW_FINGERPRINT"]
        assert sink[0]["removal_justifications"] == {OLD: "REPLACED:module.compute"}
        new2 = _rep().model_copy(update={"repair_iteration": 2})   # not in the shadow map: product verdict
        assert RL.accept(d1, d2, _asm(d1), _asm(d2), prev, new2, {OLD}, "x") == (True, None)
    finally:
        RL.accept = real


def test_shadow_verdicts_are_read_from_recorded_repair_events(tmp_path):
    if EVAL not in sys.path:
        sys.path.insert(0, EVAL)
    import run_examples
    run = tmp_path / "runs" / "01-r1"
    run.mkdir(parents=True)
    events = [{"iteration": 1, "accepted": False, "reject_reason": "PRESERVATION_VIOLATION"},
              {"iteration": 2, "accepted": True, "reject_reason": None}]
    (run / "result.json").write_text(json.dumps({"hallucination_stack": {"repair_events": events}}))
    assert run_examples._shadow_verdicts(str(tmp_path), "01-r1") == {"1": [False, "PRESERVATION_VIOLATION"],
                                                                     "2": [True, None]}
    assert run_examples._shadow_verdicts(str(tmp_path), "02-r1") == {}


def test_rescore_tool_projects_only_what_the_recording_can_show(tmp_path):
    if REPO_ROOT not in sys.path:
        sys.path.insert(0, REPO_ROOT)
    from eval.tools.rescore_repairs import rescore

    def ev(it, acc, why, persona="IAC"):
        return {"iteration": it, "persona": persona, "accepted": acc, "reject_reason": why}

    def put(root, key, events, outcome, trace=None, valid=True):
        d = root / "runs" / key
        d.mkdir(parents=True)
        body = {"pipeline_outcome": outcome, "valid_run": valid, "hallucination_stack": {"repair_events": events}}
        if trace is not None:
            body["accept_trace"] = trace
        (d / "result.json").write_text(json.dumps(body))

    rec, sh = tmp_path / "rec", tmp_path / "sh"
    events = [ev(1, False, "PRESERVATION_VIOLATION"), ev(2, False, "NEW_FINGERPRINT")]
    put(rec, "01-r1", events, "developer_failed_typed")     # newly accepted, PASS -> converges
    put(sh, "01-r1", events, "developer_failed_typed",
        [{"iteration": 1, "product_verdict": [True, None], "status_after": "PASS", "n_before": 3, "n_after": 0},
         {"iteration": 2, "product_verdict": [False, "NEW_FINGERPRINT"], "status_after": "FAIL", "n_before": 3,
          "n_after": 2}])
    put(rec, "02-r1", events, "developer_failed_typed")     # newly accepted, still FAIL -> unknown
    put(sh, "02-r1", events, "developer_failed_typed",
        [{"iteration": 1, "product_verdict": [True, None], "status_after": "FAIL", "n_before": 3, "n_after": 1}])
    put(rec, "03-r1", events, "developer_failed_typed")     # shadow followed another path -> unscored
    put(sh, "03-r1", [ev(1, False, "OUT_OF_SCOPE_WRITE"), ev(2, False, "NEW_FINGERPRINT")], "developer_failed_typed",
        [{"iteration": 2, "product_verdict": [False, "NEW_FINGERPRINT"], "status_after": "FAIL", "n_before": 3,
          "n_after": 2}])
    out = rescore(rec, sh)
    assert {k: v["projected_outcome"] for k, v in out["runs"].items()} == {
        "01-r1": "committed_passed", "02-r1": "unknown", "03-r1": "unscored"}
    assert out["transitions_by_call"]["PRESERVATION_VIOLATION -> ACCEPTED"] == 2


# ------------------------------------------------------------------------------------------------ R3c-fix RT (10-13)
BROKEN_EVENT_WORKER = {  # python-hcl2 rejects main.tf (unterminated heredoc): the module's contents are unknown
    "infra/modules/event-worker/main.tf": 'resource "google_cloud_run_v2_job" "job" {\n  name = <<EOT\nj\n}\n',
    "infra/modules/event-worker/outputs.tf": 'output "job_name" {\n  value = "j"\n}\n'}


def test_unparseable_module_is_unknown_and_never_justifies_a_dead_reference():
    """NEGATIVE (RT fix 1): a module file python-hcl2 cannot parse makes the module 'unknown' (None), not 'manages
    nothing' (set()): no DEAD_REFERENCE removal and no 'Delete this block' hint."""
    from developer_agent.assembly import index_blocks
    assert index_blocks(BROKEN_EVENT_WORKER["infra/modules/event-worker/main.tf"]) is None
    key = "google_cloud_run_v2_service_iam_member.invoker"
    d1, d2 = {MAIN: SA + CR + IAM}, {MAIN: SA + CR}
    asm1, asm2 = _asm(d1, modules=BROKEN_EVENT_WORKER), _asm(d2, modules=BROKEN_EVENT_WORKER)
    assert RL._module_resource_types(asm1.tree, "module.compute") is None
    prev = _rep(_d(REF, key, OLD))
    assert removal_justifications(d1, d2, asm1, asm2, prev, {key}) == {}
    assert accept(d1, d2, asm1, asm2, prev, _rep(), {key}, "x") == (False, "PRESERVATION_VIOLATION")
    tree = dict({ROOT: _module("event-worker")}, **BROKEN_EVENT_WORKER)
    h = json.loads(_router(tree, _rec())._hint(_d(REF, key, OLD)))
    assert h["action"].startswith("Replace the reference") and "Delete this block" not in h["action"]


def test_warning_severity_legacy_code_never_justifies_a_removal():
    """RT fix 2: the rule-5 codes justify a removal only when blocking, like POLICY.PRIVILEGED_ROLE."""
    key = "google_cloud_run_v2_service_iam_member.pub"
    blk = 'resource "google_cloud_run_v2_service_iam_member" "pub" {\n  role = "roles/run.invoker"\n  member = "allUsers"\n}\n'
    d1, d2 = {MAIN: SA + blk}, {MAIN: SA}
    warn = Diagnostic(tool="policy", code="POLICY.PUBLIC_MEMBER", severity="warning", file=MAIN, block_address=key,
                      message="m", source="precommit")
    other = _d("TF.UNSUPPORTED_ARGUMENT", "google_service_account.sa")
    a1, a2 = _plain(d1), _plain(d2)
    assert removal_justifications(d1, d2, a1, a2, _rep(other, warn), {key}) == {}
    assert accept(d1, d2, a1, a2, _rep(other, warn), _rep(), {key}, "x") == (False, "PRESERVATION_VIOLATION")
    blocking = _d("POLICY.PUBLIC_MEMBER", key)
    assert removal_justifications(d1, d2, a1, a2, _rep(blocking), {key}) == {key: "REMOVAL_CODE:POLICY.PUBLIC_MEMBER"}


def test_preservation_feedback_lists_only_the_unjustified_removals():
    """M7: the feedback names `removed - justified`, never a removal the rules allowed."""
    d1, d2 = {MAIN: SA + PSVC + TOPIC}, {MAIN: SA}
    prev = _rep(_d("POLICY.PLATFORM_OWNED_TYPE", "google_project_service.apis"))
    removed = {"google_project_service.apis", "google_pubsub_topic.t"}
    fb = _rejection_feedback("PRESERVATION_VIOLATION", d1, d2, _plain(d1), _plain(d2), prev, _rep(), removed,
                             [{"envelope_ok": True}])
    assert '["google_pubsub_topic.t"]' in fb and "google_project_service.apis" not in fb


def test_non_reference_finding_on_a_justified_address_is_a_new_fingerprint():
    """M11: only TF.REFERENCE_TO_UNDECLARED_RESOURCE can be consequential; another new code whose symbol is a
    justified removal is a regression even with net progress."""
    d1, d2 = {MAIN: PSVC + NET}, {MAIN: NET}
    prev = _rep(_d("POLICY.PLATFORM_OWNED_TYPE", "google_project_service.apis"), _d("POLICY.PUBLIC_MEMBER", "a.b"),
                _d("POLICY.PUBLIC_MEMBER", "a.c"))
    bad = _d("TF.UNSUPPORTED_ATTRIBUTE", "google_compute_network.vpc", "google_project_service.apis")
    assert accept(d1, d2, _plain(d1), _plain(d2), prev, _rep(bad), {"google_project_service.apis"}, "x") == \
        (False, "NEW_FINGERPRINT")


def test_module_resource_types_follow_local_sub_modules():
    """M8: a wrapper module whose local sub-module manages the replaced type is not 'no equivalent'."""
    wrapper = {"infra/modules/wrapper/main.tf": 'module "inner" {\n  source = "./inner"\n}\n',
               "infra/modules/wrapper/inner/main.tf": CLOUDRUN["infra/modules/compute-cloudrun/main.tf"]}
    tree = dict({ROOT: _module("wrapper")}, **wrapper)
    assert RL._module_resource_types(tree, "module.compute") == {"google_cloud_run_v2_service"}
    key = "google_cloud_run_v2_service_iam_member.invoker"
    d1, d2 = {MAIN: SA + CR + IAM}, {MAIN: SA + CR}
    asm1, asm2 = _asm(d1, "wrapper", wrapper), _asm(d2, "wrapper", wrapper)
    assert removal_justifications(d1, d2, asm1, asm2, _rep(_d(REF, key, OLD)), {key}) == {}
