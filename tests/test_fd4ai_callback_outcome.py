"""FD-4AI-c (FD27-07): a worker that reports nothing is FAILED, never SUCCESS.

`guaranteed_callback_scope` delivers SUCCESS only for an exact word in SUCCESS_STATUSES. Every replica of
callbacks.py is loaded by file path and exercised. Hermetic: CallbackDeliveryClient.send_callback is patched to
capture the payload, time.time is frozen, and Firestore is a fake recorder, so nothing leaves the process.
"""
import hermetic_guard  # noqa: F401  (lane 2: must be the first import)

import copy
import hashlib
import json
import importlib.util
import os

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPLICAS = [
    "shared/callbacks.py",
    "apps/orchestrator-gateway/shared/callbacks.py",
    "apps/project-vending/shared/callbacks.py",
    "apps/qa-runner/shared/callbacks.py",
    "mcp-servers/terraform/shared/callbacks.py",
    "apps/control-center/shared/callbacks.py",
]
CB_URL = "http://127.0.0.1:9/v1/callbacks/fd4ai"
FROZEN_T = 1_700_000_000.0


def _load(rel):
    name = "fd4ai_cb_" + rel.replace("/", "_").replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO_ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(params=REPLICAS)
def cb(request):
    return _load(request.param)


class _FakeDb:
    def __init__(self):
        self.writes = []

    def collection(self, name):
        db = self

        class _Doc:
            def __init__(self, doc_id):
                self.doc_id = doc_id

            def set(self, data, merge=False):
                db.writes.append((name, self.doc_id, copy.deepcopy(data), merge))

        class _Coll:
            def document(self, doc_id):
                return _Doc(doc_id)

        return _Coll()


def _run(cb, monkeypatch, body, raises=None):
    """Run `body(outcome)` inside the scope; return (delivered callback payloads, firestore writes)."""
    sent = []

    def _capture(callback_url, payload, timeout=15, max_attempts=5):
        json.dumps(payload)  # FD-4AI-c RT F2: every delivered payload must be JSON-serializable
        sent.append(copy.deepcopy(payload))
        return {}

    monkeypatch.setattr(cb.CallbackDeliveryClient, "send_callback", staticmethod(_capture))
    monkeypatch.setattr(cb.time, "time", lambda: FROZEN_T)
    db = _FakeDb()
    if raises is None:
        with cb.guaranteed_callback_scope(CB_URL, "trace-fd4ai", "terraform", "prod-fd4ai", db) as outcome:
            body(outcome)
    else:
        with pytest.raises(raises):
            with cb.guaranteed_callback_scope(CB_URL, "trace-fd4ai", "terraform", "prod-fd4ai", db) as outcome:
                body(outcome)
    assert len(sent) == 1
    return sent[0], db.writes


# --- the rule -----------------------------------------------------------------------------------------------------

def test_success_set_is_exact_named_constant(cb):
    # FD-4D-c / FD-4AI-c F1: the DEPLOYED alias is removed; success is exactly SUCCESS.
    assert cb.SUCCESS_STATUSES == frozenset({"SUCCESS"})
    assert cb.WORKER_NO_OUTCOME == "WORKER_NO_OUTCOME"


def test_untouched_body_is_failed_worker_no_outcome(cb, monkeypatch):
    payload, writes = _run(cb, monkeypatch, lambda o: None)
    assert payload["status"] == "FAILED"
    assert payload["error_class"] == "WORKER_NO_OUTCOME"
    assert payload["reported_status"] == "IN_PROGRESS"
    assert payload["error"] == "WORKER_NO_OUTCOME: worker finished without reporting an outcome"
    (_, doc_id, doc, merge), = writes
    assert doc_id == "trace-fd4ai" and merge is True
    # STAGE-FAIL-NOT-RUN-FAIL: the outcome reached the workflow, so only the stage is FAILED; the run's status is the
    # workflow's terminal notify to set.
    assert doc["stages"]["terraform"]["status"] == "FAILED"
    assert "status" not in doc and "current_stage" not in doc and "error" not in doc


def test_outputs_only_body_is_not_success(cb, monkeypatch):
    # The old test_guaranteed_callback_success shape: outputs filled, status never set.
    payload, _ = _run(cb, monkeypatch, lambda o: o.update(outputs={"service_url": "https://x.example"}))
    assert payload["status"] == "FAILED" and payload["error_class"] == "WORKER_NO_OUTCOME"


def test_untouched_status_with_caller_error_keeps_caller_error_and_class(cb, monkeypatch):
    def body(o):
        o["error"] = "gate refused"
        o["error_class"] = "GATE_UNAVAILABLE"

    payload, _ = _run(cb, monkeypatch, body)
    assert payload["status"] == "FAILED"
    assert payload["error"] == "gate refused"
    assert payload["error_class"] == "GATE_UNAVAILABLE"
    assert payload["reported_status"] == "IN_PROGRESS"


# Do No Harm: today's (base 44643a2e) delivered payload for an explicit SUCCESS, pinned byte for byte.
_BASE_SUCCESS_PAYLOAD = {
    "status": "SUCCESS",
    "stage": "terraform",
    "trace_id": "trace-fd4ai",
    "product_id": "prod-fd4ai",
    "error": None,
    "traceback": None,
    "execution_duration_seconds": 0.0,
    "outputs": {"service_url": "https://svc.example"},
}
_BASE_SUCCESS_DOC = {
    "stages": {"terraform": {"status": "SUCCESS", "duration_seconds": 0.0, "error": None,
                             "summary": "Terraform stage completed successfully", "state": "CALLBACK_DELIVERED"}},
    "outputs": {"service_url": "https://svc.example"},
}


@pytest.mark.parametrize("word", ["SUCCESS"])
def test_success_words_deliver_todays_payload_unchanged(cb, monkeypatch, word):
    def body(o):
        o["status"] = word
        o["outputs"] = {"service_url": "https://svc.example"}

    payload, writes = _run(cb, monkeypatch, body)
    assert payload == _BASE_SUCCESS_PAYLOAD
    assert list(payload) == list(_BASE_SUCCESS_PAYLOAD)
    # TI-5-R3-d (RT 11-07 F1): every stage status write also carries a fresh attempt id (32 hex characters)
    attempt = writes[0][2]["stages"]["terraform"].pop("attempt_id")
    assert isinstance(attempt, str) and len(attempt) == 32 and int(attempt, 16) >= 0
    assert writes == [("pipeline_executions", "trace-fd4ai", _BASE_SUCCESS_DOC, True)]


def test_explicit_failed_payload_unchanged(cb, monkeypatch):
    # Do No Harm: an explicit FAILED gets no new keys.
    def body(o):
        o["status"] = "FAILED"
        o["error"] = "boom"

    payload, _ = _run(cb, monkeypatch, body)
    assert payload == {"status": "FAILED", "stage": "terraform", "trace_id": "trace-fd4ai", "product_id": "prod-fd4ai",
                       "error": "boom", "traceback": None, "execution_duration_seconds": 0.0, "outputs": {}}


@pytest.mark.parametrize("word", ["PASSED", "COMMITTED", "APPLIED", "WORKLOAD_VENDED", "success", "SUCCESS ",
                                  "SUCCESSFUL", "VALIDATION_FAILED", "DEPLOYED"])
def test_unknown_status_is_failed_with_reported_status(cb, monkeypatch, word):
    payload, _ = _run(cb, monkeypatch, lambda o: o.update(status=word))
    assert payload["status"] == "FAILED"
    assert payload["reported_status"] == word
    assert payload["error"] == f"worker reported status {word!r}, which is not a success status"
    assert "error_class" not in payload


def test_unknown_status_keeps_caller_error(cb, monkeypatch):
    payload, _ = _run(cb, monkeypatch, lambda o: o.update(status="VALIDATION_FAILED", error="undeclared resource"))
    assert payload["status"] == "FAILED"
    assert payload["error"] == "undeclared resource"
    assert payload["reported_status"] == "VALIDATION_FAILED"


def test_unhashable_status_is_failed_not_typeerror(cb, monkeypatch):
    payload, _ = _run(cb, monkeypatch, lambda o: o.update(status=["SUCCESS"]))
    assert payload["status"] == "FAILED" and payload["reported_status"] == "['SUCCESS']"


def test_non_json_status_is_reported_as_repr_and_delivered(cb, monkeypatch):
    # RT F2: a non-JSON status (here an object) must not break delivery; reported_status is its repr().
    payload, _ = _run(cb, monkeypatch, lambda o: o.update(status={"SUCCESS"}))
    assert payload["status"] == "FAILED" and payload["reported_status"] == "{'SUCCESS'}"


def test_exception_is_failed_and_reraised(cb, monkeypatch):
    def body(o):
        o["status"] = "SUCCESS"
        raise RuntimeError("worker crashed")

    payload, writes = _run(cb, monkeypatch, body, raises=RuntimeError)
    assert payload["status"] == "FAILED"
    assert payload["error"] == "RuntimeError: worker crashed"
    assert "worker crashed" in payload["traceback"]
    assert "reported_status" not in payload and "error_class" not in payload
    assert writes[0][2]["stages"]["terraform"]["status"] == "FAILED" and "status" not in writes[0][2]


def test_callbacks_six_copies_byte_identical():
    digests = {rel: hashlib.sha256(open(os.path.join(REPO_ROOT, rel), "rb").read()).hexdigest() for rel in REPLICAS}
    assert len(set(digests.values())) == 1, digests


# --- audited caller patterns (docs/handoff/fd-4ai-c-report.md); each mirrors the body's exact outcome writes --------

def test_caller_terraform_update_then_success(cb, monkeypatch):
    # FD-4AI-c F1: mcp-servers/terraform/main.py run_deploy_in_background (success branch) and applier.py run_job
    # (success branch): outcome.update(res) where res["status"] == "SUCCESS", THEN status SUCCESS.
    res = {"status": "SUCCESS", "service_url": "https://svc.example", "error": None}

    def body(o):
        o["error"] = None
        o["outputs"] = res
        o.update(res)
        o["status"] = "SUCCESS"

    payload, _ = _run(cb, monkeypatch, body)
    assert payload["status"] == "SUCCESS" and payload["error"] is None
    assert "reported_status" not in payload


def test_old_deployed_alias_after_success_is_no_longer_success(cb, monkeypatch):
    # FD-4D-c / FD-4AI-c F1: the pre-F1 order (SUCCESS, then update(res) with the removed DEPLOYED word) is FAILED.
    # No producer emits DEPLOYED any more; this pins that the alias is really gone from the scope.
    res = {"status": "DEPLOYED", "service_url": "https://svc.example", "error": None}

    def body(o):
        o["status"] = "SUCCESS"
        o["error"] = None
        o["outputs"] = res
        o.update(res)

    payload, _ = _run(cb, monkeypatch, body)
    assert payload["status"] == "FAILED" and payload["reported_status"] == "DEPLOYED"


def test_caller_terraform_failure_then_update_res(cb, monkeypatch):
    # mcp-servers/terraform/main.py failure branch: status FAILED, then outcome.update(res) (res status FAILED).
    res = {"status": "FAILED", "error": "tofu apply failed"}

    def body(o):
        o["status"] = "FAILED"
        o["error"] = res["error"]
        o["outputs"] = res
        o.update(res)

    payload, _ = _run(cb, monkeypatch, body)
    assert payload["status"] == "FAILED" and payload["error"] == "tofu apply failed"


def test_caller_vending_update_then_explicit_success(cb, monkeypatch):
    # apps/project-vending/main.py run_vending_in_background: update(res) (WORKLOAD_VENDED), then status SUCCESS.
    res = {"status": "WORKLOAD_VENDED", "project_id": "castor-x"}

    def body(o):
        o["outputs"] = res
        o.update(res)
        o["status"] = "SUCCESS"
        o["error"] = None

    payload, _ = _run(cb, monkeypatch, body)
    assert payload["status"] == "SUCCESS" and payload["project_id"] == "castor-x"


def test_caller_gateway_gate_error_body_is_failed(cb, monkeypatch):
    # apps/orchestrator-gateway/main.py developer GateError branch (early return) and QA GateError branch:
    # outcome.update(GateError.to_body(...)) sets status FAILED + error_class, then error = message.
    def body(o):
        o.update({"status": "FAILED", "passed": False, "error_class": "GATE_UNAVAILABLE", "summary": "no tree"})
        o["error"] = "no tree"

    payload, _ = _run(cb, monkeypatch, body)
    assert payload["status"] == "FAILED" and payload["error_class"] == "GATE_UNAVAILABLE"
    assert "reported_status" not in payload


@pytest.mark.parametrize("passed", [True, False])
def test_caller_gateway_qa_verdict(cb, monkeypatch, passed):
    # apps/orchestrator-gateway/main.py run_qa_verify_in_background: update(run_qa body); status SUCCESS|FAILED.
    qa = {"status": "SUCCESS" if passed else "FAILED", "passed": passed, "summary": "s", "outputs": {}}

    def body(o):
        o.update(qa)
        o["outputs"] = qa.get("outputs", {})
        o["error"] = None if qa.get("passed") else qa.get("summary")

    payload, _ = _run(cb, monkeypatch, body)
    assert payload["status"] == ("SUCCESS" if passed else "FAILED")


# --- STAGE-FAIL-NOT-RUN-FAIL: a failed stage callback the workflow received does not end the run ------------------

def _run_with_delivery(cb, monkeypatch, body, callback_url, deliver_ok):
    sent = []

    def _send(callback_url, payload, timeout=15, max_attempts=5):
        if not deliver_ok:
            raise ConnectionRefusedError("callback endpoint unreachable")
        sent.append(copy.deepcopy(payload))
        return {}

    monkeypatch.setattr(cb.CallbackDeliveryClient, "send_callback", staticmethod(_send))
    db = _FakeDb()
    with cb.guaranteed_callback_scope(callback_url, "trace-sfnrf", "terraform", "prod-sfnrf", db) as outcome:
        body(outcome)
    (_, _, doc, _), = db.writes
    return sent, doc


def _tf_failed(o):
    o["status"] = "FAILED"
    o["error"] = "tofu apply failed"


def test_delivered_terraform_failure_marks_stage_not_run(cb, monkeypatch):
    # The workflow received the FAILED outcome and may remediate (bounded terraform remediation loop): the run stays
    # under way; stages.terraform carries the failure.
    sent, doc = _run_with_delivery(cb, monkeypatch, _tf_failed, CB_URL, deliver_ok=True)
    assert len(sent) == 1 and sent[0]["status"] == "FAILED"
    assert doc["stages"]["terraform"]["status"] == "FAILED"
    assert doc["stages"]["terraform"]["error"] == "tofu apply failed"
    assert doc["stages"]["terraform"]["state"] == "CALLBACK_DELIVERED"
    assert "status" not in doc and "current_stage" not in doc and "error" not in doc


def test_undelivered_failure_still_fails_the_run(cb, monkeypatch):
    # No workflow received the outcome: the record is the only place the failure lands, so the run is FAILED (as before).
    _, doc = _run_with_delivery(cb, monkeypatch, _tf_failed, CB_URL, deliver_ok=False)
    assert doc["stages"]["terraform"]["state"] == "CALLBACK_FAILED"
    assert doc["status"] == "FAILED" and doc["current_stage"] == "FAILED" and doc["error"] == "tofu apply failed"


def test_no_callback_url_failure_still_fails_the_run(cb, monkeypatch):
    _, doc = _run_with_delivery(cb, monkeypatch, _tf_failed, None, deliver_ok=True)
    assert doc["status"] == "FAILED" and doc["current_stage"] == "FAILED"


def test_success_never_writes_run_status(cb, monkeypatch):
    # Do No Harm: a successful stage writes only its stage (unchanged by STAGE-FAIL-NOT-RUN-FAIL).
    def body(o):
        o["status"] = "SUCCESS"

    for deliver_ok in (True, False):
        _, doc = _run_with_delivery(cb, monkeypatch, body, CB_URL, deliver_ok=deliver_ok)
        assert doc["stages"]["terraform"]["status"] == "SUCCESS"
        assert "status" not in doc and "current_stage" not in doc and "error" not in doc
