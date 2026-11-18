"""FD-7L Phase 5b (SAT-31b): the synchronous credentialed runs of a Per-workload install as tf-applier executions
(D3-a): sync /deploy (Express, vending redeploy) and both force-unlock routes. Staged payload (its sha256 in the signed
dispatch record; RUNNER_PAYLOAD_MISMATCH), result channel (runner_results/<dispatch_id>, polled within the request's
deadline), no in-process run. SAT-37 (5b part 2): /plan and the MCP plan tool run as executions too; the result is used
only with the fingerprint vending signed; /apply, /drift-check and the MCP drift tool stay refused (RUNNER_MODE_UNSUPPORTED).

Do No Harm (Shared installs: STACKVEND_TF_RUNNER_IDENTITY unset or PLATFORM): every one of these routes calls the
service method in-process exactly as before, with the same arguments and the same answer; no stager, result store or
vending client is touched; the tf-applier's workflow deploy path is unchanged.

Hermetic: fake stager / GCS session / result store / vending / guard database, signatures with tests/fd7l_fakes.py's
real RSA key; no network, no cloud clients.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import json
import logging
import os
import re
from unittest.mock import MagicMock

import pytest

import fd7l_fakes as fk
from test_fd4g_terraform_workspace import (  # noqa: F401  (pytest fixtures reused by name)
    _isolated_tf_service, _load_tf_module, base, sent_callbacks)
from test_fd7l_5a_dispatch import (  # noqa: F401  (pytest fixtures and helpers reused by name)
    ARCHITECT, CALLBACK, CHILD, EXECUTION, MODE, PRODUCT, FakeGuardDb, _client, _post, per_workload, tf_main)
from test_fd7l_2a_runner_service import (  # noqa: F401
    JOB_ENV, NONCE, SESSION_KEY, FakeBroker, _DB, _dispatch, _signed as _signed_2a, ri)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO, "mcp-servers", "terraform")
STAGING = "stackvend-runner-staging-mock-stackvend-project"
DISPATCH_ID = "d" * 64
T0 = 1_800_000_000.0


# ------------------------------------------------------------------------------------------------ fakes
class FakeStager:
    def __init__(self, bucket, fail=None):
        self.bucket, self.fail, self.staged = bucket, fail, []

    def stage(self, *, product_id, trace_id, data):
        if self.fail is not None:
            raise self.fail
        self.staged.append((product_id, trace_id, data))
        return f"gs://{self.bucket}/runs/{product_id}/{trace_id}/x.json", hashlib.sha256(data).hexdigest()


class FakeResults:
    """The result documents. `on_set` (the pw fixture) has vending's signed record carry the fingerprint of every
    document a test sets, as the real execution does before it writes (SAT-37)."""

    def __init__(self, doc=None, appear_after=0):
        self.on_set = None
        self.doc, self.appear_after, self.reads = doc, appear_after, 0

    @property
    def doc(self):
        return self._doc

    @doc.setter
    def doc(self, value):
        self._doc = value
        if value is not None and self.on_set is not None:
            self.on_set(value)

    def get(self, dispatch_id):
        self.reads += 1
        return dict(self.doc) if self.doc is not None and self.reads > self.appear_after else None


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += max(s, 0.001)


def _result_doc(result, **over):
    doc = {"schema": "runner_result/v1", "dispatch_id": DISPATCH_ID, "execution": EXECUTION, "product_id": PRODUCT,
           "trace_id": "t1", "mode": "deploy", "result_json": json.dumps(result, sort_keys=True),
           "result_truncated": False}
    doc.update(over)
    return doc


def _fp(doc):
    """The fingerprint the execution has vending sign: sha256 of the document's result_json."""
    return hashlib.sha256(doc["result_json"].encode("utf-8")).hexdigest()


def _resign(tf, rec, **over):
    body = {k: v for k, v in rec.items() if k not in ("signature", "signed_by", "signed_at")}
    body.update(over)
    return tf.ri.sign_record(tf.ri.nonce_doc_path(DISPATCH_ID), body, signer_email=fk.BROKER,
                             signed_at="2026-11-01T00:00:00Z", sign_blob=fk.BROKER_KEY.sign)


def _nonce_rec(tf, **over):
    rec = {"schema": tf.ri.NONCE_SCHEMA, "redeemed": True, "execution": EXECUTION,
           "created_at": "2026-11-01T00:00:00Z"}
    rec.update(over)
    return tf.ri.sign_record(tf.ri.nonce_doc_path(DISPATCH_ID), rec, signer_email=fk.BROKER,
                             signed_at="2026-11-01T00:00:00Z", sign_blob=fk.BROKER_KEY.sign)


@pytest.fixture
def pw(monkeypatch, per_workload):
    """Per-workload server with a staging bucket, a fake stager, a fake result store and a fake clock."""
    tf, vending, guard = per_workload
    monkeypatch.setenv("STACKVEND_RUNNER_STAGING_BUCKET", STAGING)
    stagers, clock = [], Clock()
    results = FakeResults(_result_doc({"status": "SUCCESS", "service_url": "https://svc.run.app"}))
    tf.STAGER_FACTORY = lambda bucket: stagers.append(FakeStager(bucket)) or stagers[-1]
    tf.RESULT_STORE_FACTORY = lambda: results
    tf.SYNC_CLOCK, tf.SYNC_SLEEP = clock, clock.sleep
    key = (tf.ri.NONCE_COLLECTION, DISPATCH_ID)
    guard.docs[key] = _nonce_rec(tf)   # vending's signed, redeemed record

    def sign_fingerprint(doc):       # what the real execution has vending do before it writes the document
        if key in guard.docs and "signature" in guard.docs[key]:
            guard.docs[key] = _resign(tf, guard.docs[key], result_sha256=_fp(doc))
    results.on_set = sign_fingerprint
    sign_fingerprint(results.doc)
    # RT L2: vending's /runner/dispatch-status answers (running unless a test says otherwise)
    vending.states = []
    vending.state = {"dispatch_id": DISPATCH_ID, "execution": EXECUTION, "redeemed": True, "result_signed": True,
                     "ended": False}
    real_post = vending.post

    def post(url, **kw):
        if url.endswith("/runner/dispatch-status"):
            vending.states.append(kw["json"])
            resp = MagicMock()
            if isinstance(vending.state, dict):
                resp.status_code, resp.json.return_value = 200, dict(vending.state)
            else:
                resp.status_code, resp.json.return_value = vending.state
            return resp
        return real_post(url, **kw)
    vending.post = post
    for name in ("deploy_workload", "force_unlock", "generate_plan", "apply_plan", "check_drift"):
        getattr(tf.service, name).side_effect = lambda *a, **k: pytest.fail("credentialed run in the server process")
    return tf, vending, guard, stagers, results, clock


def _sent_body(vending):
    dispatches = [c for c in vending.calls if c[0].endswith("/runner/dispatch")]
    assert len(dispatches) == 1 and len(vending.calls) == 1
    return dispatches[0][1]["json"]


# ------------------------------------------------------------------------------------------------ Do No Harm
SHARED_CALLS = [
    ("/deploy", {"product_id": PRODUCT, "trace_id": "t1", "target_project_id": CHILD, "branch": "rel",
                 "hcl_files": {"infra/workload/main.tf": "# x\n"}, "iac_engine": "OPENTOFU", "refuse_destroy": True,
                 "approved_removals": ["a.b"]}, "deploy_workload"),
    ("/force-unlock", {"product_id": PRODUCT, "lock_id": "17", "trace_id": "t1"}, "force_unlock"),
    (f"/api/workloads/{PRODUCT}/force-unlock", {"product_id": PRODUCT, "lock_id": "17"}, "force_unlock"),
    ("/plan", {"product_id": PRODUCT, "trace_id": "t1", "hcl_files": {"main.tf": ""}}, "generate_plan"),
    ("/apply", {"product_id": PRODUCT, "trace_id": "t1"}, "apply_plan"),
    ("/drift-check", {"product_id": PRODUCT, "trace_id": "t1"}, "check_drift"),
    # RT L6: the MCP plan / drift tools on a Shared install run in-process as before
    ("/mcp", {"method": "tools/call", "params": {"name": "terraform_plan", "arguments": {
        "product_id": PRODUCT, "trace_id": "t1", "hcl_files": {"main.tf": ""}}}}, "generate_plan"),
    ("/mcp", {"method": "tools/call", "params": {"name": "terraform_drift_check", "arguments": {
        "product_id": PRODUCT, "trace_id": "t1"}}}, "check_drift"),
]


@pytest.mark.parametrize("mode", [None, "PLATFORM"])
@pytest.mark.parametrize("path,body,method", SHARED_CALLS)
def test_shared_install_routes_run_in_process_exactly_as_before(monkeypatch, tf_main, mode, path, body, method):
    if mode is None:
        monkeypatch.delenv(MODE, raising=False)
    else:
        monkeypatch.setenv(MODE, mode)
    tf_main.STAGER_FACTORY = lambda *a: pytest.fail("a Shared install staged a payload")
    tf_main.RESULT_STORE_FACTORY = lambda: pytest.fail("a Shared install read a result document")
    getattr(tf_main.service, method).return_value = {"status": "UNLOCKED" if "unlock" in path else "SUCCESS",
                                                     "service_url": "https://x"}
    r = _post(tf_main, path, body, token=None)
    assert r.status_code == 200, r.text
    assert getattr(tf_main.service, method).call_count == 1


def test_shared_install_sync_deploy_arguments_and_answers_unchanged(monkeypatch, tf_main):
    monkeypatch.delenv(MODE, raising=False)
    svc = tf_main.service
    body = dict(SHARED_CALLS[0][1])
    svc.deploy_workload.return_value = {"status": "SUCCESS", "service_url": "https://x"}
    assert _post(tf_main, "/deploy", body, token=None).json() == {"status": "SUCCESS", "service_url": "https://x"}
    kw = svc.deploy_workload.call_args.kwargs
    assert (kw["product_id"], kw["trace_id"], kw["hcl_files"], kw["target_project_id"], kw["branch"],
            kw["iac_engine"], kw["time_budget_s"]) == (PRODUCT, "t1", body["hcl_files"], CHILD, "rel", "OPENTOFU",
                                                       tf_main.SYNC_DEPLOY_TIME_BUDGET_S)
    assert kw["destroy_policy"].approved_removals == frozenset({"a.b"})
    # EXP-7 409 and EXP-8 typed 500 keep their exact detail shapes (_deploy_answer moved unchanged)
    svc.deploy_workload.return_value = {"status": "FAILED", "error_class": "DESTROY_REQUIRES_APPROVAL", "error": "e",
                                        "removal_addresses": ["x"], "destroy_requires_approval": True,
                                        "approved_removals": []}
    r = _post(tf_main, "/deploy", body, token=None)
    assert r.status_code == 409 and r.json()["detail"] == {
        "error_class": "DESTROY_REQUIRES_APPROVAL", "error": "e", "removal_addresses": ["x"],
        "destroy_requires_approval": True, "approved_removals": []}
    svc.deploy_workload.return_value = {"status": "FAILED", "error_class": "STATE_LOCKED", "error": "locked"}
    r = _post(tf_main, "/deploy", body, token=None)
    assert r.status_code == 500 and r.json()["detail"] == {"error_class": "STATE_LOCKED",
                                                           "error": "Terraform deployment failed: locked"}
    r = _post(tf_main, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"}, token=None)
    assert r.status_code == 500 and r.json()["detail"] == "Terraform deployment failed: locked"


# ------------------------------------------------------------------------------------------------ sync /deploy
def test_per_workload_sync_deploy_runs_in_one_execution_with_a_staged_payload(pw):
    tf, vending, guard, stagers, results, clock = pw
    body = {"product_id": PRODUCT, "trace_id": "t1", "target_project_id": CHILD, "branch": "rel",
            "hcl_files": {"infra/workload/main.tf": "# x\n"}, "iac_engine": "OPENTOFU", "refuse_destroy": True,
            "approved_removals": ["a.b"]}
    r = _post(tf, "/deploy", body)
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "SUCCESS", "service_url": "https://svc.run.app"}
    (pid, trace, data), = stagers[0].staged
    assert (pid, trace, stagers[0].bucket) == (PRODUCT, "t1", STAGING)
    payload = json.loads(data)
    assert payload == {"schema": "runner_payload/v1", "mode": "deploy", "product_id": PRODUCT, "trace_id": "t1",
                       "options": {"hcl_files": body["hcl_files"], "iac_engine": "OPENTOFU", "refuse_destroy": True,
                                   "approved_removals": ["a.b"],
                                   "deadline_epoch": T0 + tf.SYNC_DEPLOY_TIME_BUDGET_S - 40.0}}
    assert data == tf.rr.build_payload(mode="deploy", product_id=PRODUCT, trace_id="t1", options=payload["options"])
    sent = _sent_body(vending)
    assert sent == {"product_id": PRODUCT, "trace_id": "t1", "branch": "rel", "mode": "deploy", "callback_url": None,
                    "payload_ref": f"gs://{STAGING}/runs/{PRODUCT}/t1/x.json",
                    "payload_sha256": hashlib.sha256(data).hexdigest()}
    assert not tf.watches.docs and not tf.scheduled          # a sync run is answered here, not watched


def test_per_workload_vending_redeploy_shape_without_hcl_files(pw):
    tf, vending, _g, stagers, _r, _c = pw
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1", "target_project_id": CHILD,
                              "iac_engine": "TERRAFORM"})
    assert r.status_code == 200
    opts = json.loads(stagers[0].staged[0][2])["options"]
    assert opts["hcl_files"] is None and opts["refuse_destroy"] is False and opts["approved_removals"] is None
    assert _sent_body(vending)["branch"] == "main"


@pytest.mark.parametrize("result,express,status,detail", [
    ({"status": "FAILED", "error_class": "DESTROY_REQUIRES_APPROVAL", "error": "e", "removal_addresses": ["x"],
      "destroy_requires_approval": True, "approved_removals": []}, True, 409,
     {"error_class": "DESTROY_REQUIRES_APPROVAL", "error": "e", "removal_addresses": ["x"],
      "destroy_requires_approval": True, "approved_removals": []}),
    ({"status": "FAILED", "error_class": "RUNNER_PAYLOAD_MISMATCH", "error": "bad"}, True, 500,
     {"error_class": "RUNNER_PAYLOAD_MISMATCH", "error": "Terraform deployment failed: bad"}),
    ({"status": "FAILED", "error": "boom"}, False, 500, "Terraform deployment failed: boom"),
])
def test_per_workload_sync_deploy_answers_have_the_in_process_shape(pw, result, express, status, detail):
    tf, _v, _g, _s, results, _c = pw
    results.doc = _result_doc(result)
    body = {"product_id": PRODUCT, "trace_id": "t1"}
    if express:
        body.update(refuse_destroy=True, hcl_files={"infra/workload/main.tf": ""})
    r = _post(tf, "/deploy", body)
    assert r.status_code == status and r.json()["detail"] == detail


def _code(r):
    d = r.json()["detail"]
    return d["error_class"] if isinstance(d, dict) else d


def test_per_workload_target_mismatch_is_refused_before_anything_is_staged(pw):
    tf, vending, _g, stagers, _r, _c = pw
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1", "target_project_id": "victim-project"})
    assert r.status_code == 409 and _code(r) == "RUNNER_TARGET_MISMATCH"
    assert not stagers and not vending.calls


def test_per_workload_without_a_staging_bucket_dispatches_nothing(monkeypatch, pw):
    tf, vending, _g, stagers, _r, _c = pw
    monkeypatch.delenv("STACKVEND_RUNNER_STAGING_BUCKET")
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 503 and _code(r) == "RUNNER_PAYLOAD_UNCONFIGURED"
    assert not vending.calls and r.json()["detail"]["operator_required"] is True


def test_per_workload_staging_failure_dispatches_nothing(pw):
    tf, vending, _g, _s, _r, _c = pw
    tf.STAGER_FACTORY = lambda bucket: FakeStager(bucket, fail=tf.ri.RunnerIdentityError(
        "RUNNER_PAYLOAD_STAGING_FAILED", "HTTP 403", http_status=503))
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 503 and _code(r) == "RUNNER_PAYLOAD_STAGING_FAILED" and not vending.calls


def test_per_workload_dispatch_refusal_is_typed_and_never_waits(pw):
    tf, vending, _g, _s, results, _c = pw
    vending.status, vending.body = 409, {"detail": {"code": "RUNNER_IDENTITY_NOT_READY"}}
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 502
    d = r.json()["detail"]
    assert d["error_class"] == "TF_APPLIER_DISPATCH_FAILED" and d["cause"] == "RUNNER_IDENTITY_NOT_READY"
    assert results.reads == 0


def test_per_workload_no_result_before_the_deadline_is_a_typed_timeout(pw, caplog):
    tf, _v, guard, _s, results, clock = pw
    results.doc = None
    with caplog.at_level(logging.ERROR):
        r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 504 and _code(r) == "RUNNER_RESULT_TIMEOUT"
    assert clock.t >= T0 + tf.SYNC_REQUEST_LIMIT_S - tf.SYNC_DEPLOY_RESPONSE_MARGIN_S
    assert clock.t < T0 + tf.SYNC_REQUEST_LIMIT_S                      # answered inside Cloud Run's request limit
    assert EXECUTION in r.json()["detail"]["error"]


def test_per_workload_unredeemed_dispatch_fails_after_the_window_not_at_the_deadline(pw):
    tf, _v, guard, _s, results, clock = pw
    results.doc = None
    guard.docs[(tf.ri.NONCE_COLLECTION, DISPATCH_ID)] = _nonce_rec(tf, redeemed=False)
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 502 and _code(r) == "TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM"
    assert clock.t < T0 + tf.ri.REDEEM_WINDOW_SECONDS + tf.rd.WATCH_MARGIN_S + 10


def test_per_workload_forged_dispatch_record_never_ends_the_wait_early(pw):
    tf, _v, guard, _s, results, clock = pw
    results.doc = None
    guard.docs[(tf.ri.NONCE_COLLECTION, DISPATCH_ID)] = {"schema": tf.ri.NONCE_SCHEMA, "redeemed": False}
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert _code(r) == "RUNNER_RESULT_TIMEOUT"


@pytest.mark.parametrize("field,value", [("execution", "projects/x/executions/other"), ("product_id", "other"),
                                         ("trace_id", "t2"), ("mode", "force_unlock"), ("schema", "x"),
                                         ("dispatch_id", "e" * 64), ("result_json", "[1]")])
def test_per_workload_result_that_is_not_this_runs_is_refused(pw, field, value):
    tf, _v, _g, _s, results, _c = pw
    results.doc = _result_doc({"status": "SUCCESS"}, **{field: value})
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 502 and _code(r) == "RUNNER_RESULT_MISMATCH"


@pytest.mark.parametrize("case", ["other_execution", "forged", "missing"])
def test_per_workload_result_needs_the_signed_redeem_of_that_execution(pw, case):
    """The result document is unsigned: a result is used only when vending's signed record shows that exactly the
    dispatched execution redeemed it. The refusal says the execution may still be running (RT M1)."""
    tf, _v, guard, _s, _r, _c = pw
    key = (tf.ri.NONCE_COLLECTION, DISPATCH_ID)
    if case == "other_execution":
        guard.docs[key] = _nonce_rec(tf, execution="projects/x/executions/other")
    elif case == "forged":
        guard.docs[key] = dict(guard.docs[key], execution="projects/x/executions/other")
    else:
        del guard.docs[key]
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 502 and _code(r) == "RUNNER_RESULT_MISMATCH"
    assert "may still be running" in r.json()["detail"]["error"] and EXECUTION in r.json()["detail"]["error"]


def test_per_workload_document_planted_before_the_redeem_never_ends_the_request(pw):
    """RT M1: a result document that exists before vending's signed redeem is not used and does not end the request;
    once the record shows the redeem of that execution, the (then real) result is answered."""
    tf, _v, guard, _s, results, clock = pw
    key = (tf.ri.NONCE_COLLECTION, DISPATCH_ID)
    guard.docs[key] = _nonce_rec(tf, redeemed=False)
    real = guard.collection
    looks = {"n": 0}

    def collection(name):
        if name == tf.ri.NONCE_COLLECTION:
            looks["n"] += 1
            if looks["n"] == 3:   # the execution redeems (and has its result's fingerprint signed)
                guard.docs[key] = _nonce_rec(tf, result_sha256=_fp(results.doc))
        return real(name)
    guard.collection = collection
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 200 and looks["n"] >= 3


def test_per_workload_planted_document_and_no_redeem_end_at_the_window_not_with_a_mismatch(pw):
    tf, _v, guard, _s, _r, clock = pw
    guard.docs[(tf.ri.NONCE_COLLECTION, DISPATCH_ID)] = _nonce_rec(tf, redeemed=False)
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 502 and _code(r) == "TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM"
    assert clock.t >= T0 + tf.ri.REDEEM_WINDOW_SECONDS + tf.rd.WATCH_MARGIN_S


@pytest.mark.parametrize("path,body", [
    ("/deploy", {"product_id": PRODUCT, "trace_id": "t1"}),
    ("/force-unlock", {"product_id": PRODUCT, "lock_id": "17", "trace_id": "t1"}),
])
def test_per_workload_without_a_broker_identity_dispatches_nothing(monkeypatch, pw, path, body):
    """RT L1: an unverifiable signer is refused at once, never a full-length wait."""
    tf, vending, _g, stagers, results, _c = pw
    monkeypatch.delenv("STACKVEND_BROKER_SA")
    monkeypatch.delenv("PROJECT_ID")                       # no derived provisioner identity either
    monkeypatch.setenv("TF_SERVER_WORKLOAD_CALLERS", ARCHITECT)
    r = _post(tf, path, body)
    assert r.status_code == 503 and _code(r) == "RUNNER_IDENTITY_NOT_READY"
    assert not stagers and not vending.calls and results.reads == 0


def test_per_workload_unreadable_dispatch_record_is_looked_at_again(pw):
    tf, _v, guard, _s, results, clock = pw
    real = guard.collection
    fails = {"n": 2}

    def collection(name):
        if name == tf.ri.NONCE_COLLECTION and fails["n"] > 0:
            fails["n"] -= 1
            raise RuntimeError("guard db down")
        return real(name)
    guard.collection = collection
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 200 and fails["n"] == 0 and clock.t == T0 + 2 * tf.rr.RESULT_POLL_S


def test_per_workload_result_that_appears_later_is_answered(pw):
    tf, _v, _g, _s, results, clock = pw
    results.appear_after = 3
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 200 and results.reads == 4 and clock.t == T0 + 3 * tf.rr.RESULT_POLL_S


# ------------------------------------------------------------------------------------------------ force-unlock
@pytest.mark.parametrize("path", ["/force-unlock", f"/api/workloads/{PRODUCT}/force-unlock"])
def test_per_workload_force_unlock_runs_in_an_execution(pw, path):
    tf, vending, _g, stagers, results, _c = pw
    results.doc = _result_doc({"status": "UNLOCKED", "product_id": PRODUCT, "lock_id": "17"}, mode="force_unlock")
    r = _post(tf, path, {"product_id": PRODUCT, "lock_id": "17", "trace_id": "t1", "iac_engine": "OPENTOFU"})
    assert r.status_code == 200 and r.json()["status"] == "UNLOCKED"
    assert json.loads(stagers[0].staged[0][2])["options"] == {"lock_id": "17", "iac_engine": "OPENTOFU"}
    sent = _sent_body(vending)
    assert sent["mode"] == "force_unlock" and sent["callback_url"] is None and sent["branch"] == "main"


def test_per_workload_force_unlock_failure_keeps_the_route_shape(pw):
    tf, _v, _g, _s, results, _c = pw
    results.doc = _result_doc({"status": "FAILED", "error_class": "STATE_MOVED_DO_NOT_UNLOCK",
                               "error": "STATE_MOVED_DO_NOT_UNLOCK: tombstone"}, mode="force_unlock")
    r = _post(tf, "/force-unlock", {"product_id": PRODUCT, "lock_id": "17", "trace_id": "t1"})
    assert r.status_code == 500 and r.json()["detail"] == "STATE_MOVED_DO_NOT_UNLOCK: tombstone"


def test_per_workload_force_unlock_default_trace_is_a_valid_dispatch_trace(pw):
    tf, vending, _g, _s, results, clock = pw
    trace = f"force-unlock-{PRODUCT}-{int(T0)}"
    results.doc = _result_doc({"status": "UNLOCKED"}, mode="force_unlock", trace_id=trace)
    r = _post(tf, f"/api/workloads/{PRODUCT}/force-unlock", {"product_id": "", "lock_id": "17"})
    assert r.status_code == 200 and _sent_body(vending)["trace_id"] == trace


# ------------------------------------------------------------------------------------------------ not yet executions
@pytest.mark.parametrize("path,body", [
    ("/apply", {"product_id": PRODUCT, "trace_id": "t1"}),
    ("/drift-check", {"product_id": PRODUCT, "trace_id": "t1"}),
])
def test_per_workload_apply_drift_are_refused_typed_before_anything_runs(pw, path, body):
    tf, vending, _g, stagers, _r, _c = pw
    r = _post(tf, path, body)
    assert r.status_code == 422 and _code(r) == "RUNNER_MODE_UNSUPPORTED"
    assert r.json()["detail"]["operator_required"] is True and not stagers and not vending.calls


@pytest.mark.parametrize("tool", ["terraform_drift_check"])
def test_per_workload_mcp_drift_is_a_json_rpc_refusal(pw, tool):
    """RT L3: the MCP refusal is a JSON-RPC error object with the typed detail (not an HTTP error)."""
    tf, vending, _g, stagers, _r, _c = pw
    r = _post(tf, "/mcp", {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": tool, "arguments": {
        "product_id": PRODUCT, "trace_id": "t1", "hcl_files": {"main.tf": ""}}}})
    body = r.json()
    assert r.status_code == 200 and body["id"] == 7 and body["error"]["code"] == -32000
    assert body["error"]["data"]["error_class"] == "RUNNER_MODE_UNSUPPORTED" and not stagers and not vending.calls
    assert tf.service.generate_plan.call_count == 0 and tf.service.check_drift.call_count == 0


@pytest.mark.parametrize("arguments", [{"product_id": PRODUCT}, "not-a-dict"])
def test_per_workload_unknown_mcp_tool_keeps_method_not_found(pw, arguments):
    tf = pw[0]
    r = _post(tf, "/mcp", {"id": 1, "method": "tools/call", "params": {"name": "terraform_apply",
                                                                       "arguments": arguments}})
    assert r.status_code == 200 and r.json()["error"]["code"] == -32601


def test_per_workload_mcp_tools_list_still_answers(pw):
    tf = pw[0]
    r = _post(tf, "/mcp", {"method": "tools/list"})
    assert r.status_code == 200 and r.json()["result"]["tools"]


# ------------------------------------------------------------------------------------------------ runner_runs units
@pytest.fixture
def rr(monkeypatch, base):
    monkeypatch.syspath_prepend(TF_DIR)
    import runner_runs
    return runner_runs


class FakeSession:
    def __init__(self, status=200, content=b"", raises=None):
        self.status, self.content, self.raises, self.calls = status, content, raises, []

    def _resp(self):
        if self.raises is not None:
            raise self.raises
        resp = MagicMock()
        resp.status_code, resp.content = self.status, self.content
        return resp

    def post(self, url, **kw):
        self.calls.append(("post", url, kw))
        return self._resp()

    def get(self, url, **kw):
        self.calls.append(("get", url, kw))
        return self._resp()


def test_stager_creates_once_never_overwrites(rr):
    s = FakeSession()
    data = rr.build_payload(mode="deploy", product_id=PRODUCT, trace_id="t1", options={"hcl_files": None})
    ref, sha = rr.PayloadStager(STAGING, session=s).stage(product_id=PRODUCT, trace_id="t1", data=data)
    (verb, url, kw), = s.calls
    assert verb == "post" and "ifGenerationMatch=0" in url and "uploadType=media" in url
    assert kw["data"] == data and sha == hashlib.sha256(data).hexdigest()
    assert re.fullmatch(rf"gs://{STAGING}/runs/{PRODUCT}/t1/[0-9a-f]{{32}}\.json", ref)


@pytest.mark.parametrize("session", [FakeSession(status=412), FakeSession(raises=ConnectionError("x"))])
def test_stager_failure_is_typed(rr, session):
    with pytest.raises(Exception) as ei:
        rr.PayloadStager(STAGING, session=session).stage(product_id=PRODUCT, trace_id="t1", data=b"{}")
    assert ei.value.code == "RUNNER_PAYLOAD_STAGING_FAILED" and ei.value.http_status == 503


def _record(rr, data, **over):
    rec = {"mode": "deploy", "product_id": PRODUCT, "trace_id": "t1",
           "payload_ref": f"gs://{STAGING}/runs/{PRODUCT}/t1/a.json", "payload_sha256": hashlib.sha256(data).hexdigest()}
    rec.update(over)
    return rec


ENV = {"STACKVEND_RUNNER_STAGING_BUCKET": STAGING}


def test_read_payload_returns_the_options_of_the_exact_bytes(rr):
    data = rr.build_payload(mode="deploy", product_id=PRODUCT, trace_id="t1", options={"lock_id": None, "a": 1})
    s = FakeSession(content=data)
    assert rr.read_payload(_record(rr, data), ENV, session=s) == {"lock_id": None, "a": 1}
    assert s.calls[0][1].endswith(f"/b/{STAGING}/o/runs%2F{PRODUCT}%2Ft1%2Fa.json?alt=media")


@pytest.mark.parametrize("case", ["bytes", "sha", "bucket", "mode", "product", "trace", "not_json", "schema",
                                  "no_ref"])
def test_read_payload_mismatch_is_refused(rr, case):
    data = rr.build_payload(mode="deploy", product_id=PRODUCT, trace_id="t1", options={})
    served, rec = data, _record(rr, data)
    if case == "bytes":
        served = data.replace(b"t1", b"t2")
    elif case == "sha":
        rec["payload_sha256"] = "0" * 64
    elif case == "bucket":
        rec["payload_ref"] = f"gs://other-bucket/runs/{PRODUCT}/t1/a.json"
    elif case in ("mode", "product", "trace"):
        field = {"mode": "mode", "product": "product_id", "trace": "trace_id"}[case]
        rec[field] = "force_unlock" if case == "mode" else "other"
    elif case == "not_json":
        served = b"not json"
        rec["payload_sha256"] = hashlib.sha256(served).hexdigest()
    elif case == "schema":
        served = json.dumps({"schema": "x", "mode": "deploy", "product_id": PRODUCT, "trace_id": "t1",
                             "options": {}}).encode()
        rec["payload_sha256"] = hashlib.sha256(served).hexdigest()
    elif case == "no_ref":
        rec["payload_ref"] = None
    with pytest.raises(Exception) as ei:
        rr.read_payload(rec, ENV, session=FakeSession(content=served))
    assert ei.value.code == "RUNNER_PAYLOAD_MISMATCH"


@pytest.mark.parametrize("session", [FakeSession(status=404), FakeSession(raises=ConnectionError("x"))])
def test_read_payload_unreadable_is_typed(rr, session):
    data = b"{}"
    with pytest.raises(Exception) as ei:
        rr.read_payload(_record(rr, data), ENV, session=session)
    assert ei.value.code == "RUNNER_PAYLOAD_UNREADABLE"


def test_read_payload_without_a_staging_bucket_is_unconfigured(rr):
    with pytest.raises(Exception) as ei:
        rr.read_payload(_record(rr, b"{}"), {}, session=FakeSession())
    assert ei.value.code == "RUNNER_PAYLOAD_UNCONFIGURED"


def test_result_store_creates_once_and_shortens_large_output(rr):
    db = MagicMock()
    text, truncated = rr.result_text({"status": "FAILED", "stdout": "x" * 2_000_000, "error": "boom"})
    rr.ResultStore(db).write("f" * 64, execution="e", product_id=PRODUCT, trace_id="t1", mode="deploy",
                             result_json=text, result_truncated=truncated, finished_at="2026-11-01T00:00:00Z")
    doc = db.collection.return_value.document.return_value.create.call_args.args[0]
    db.collection.assert_called_with("runner_results")
    assert doc["result_truncated"] is True and len(doc["result_json"]) <= rr.RESULT_MAX_CHARS
    assert doc["result_json"] == text
    parsed = json.loads(doc["result_json"])
    assert parsed["error"] == "boom" and parsed["result_truncated"] is True     # inside the signed text (SAT-37)


@pytest.mark.parametrize("result", [{"b": 1, "a": [1, 2], "status": "SUCCESS"},
                                    {"status": "FAILED", "stderr": "e" * 2_000_000, "error_class": "X"},
                                    {"status": "FAILED", "error": "z" * 2_000_000}])
def test_result_text_is_canonical_and_its_fingerprint_is_the_documents(rr, result):
    """SAT-37: the same result always gives the same text (sorted keys), the fingerprint is sha256 of exactly that
    text, and a small result is unchanged by the round trip (Do No Harm: nothing added to it)."""
    text, truncated = rr.result_text(result)
    assert rr.result_text(dict(reversed(list(result.items())))) == (text, truncated)
    assert rr.result_fingerprint(text) == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert len(text) <= rr.RESULT_MAX_CHARS
    if not truncated:
        assert json.loads(text) == result
    else:
        assert json.loads(text)["result_truncated"] is True and json.loads(text)["status"] == "FAILED"

def test_payload_is_never_logged_and_server_never_handles_a_nonce():
    import ast
    tree = ast.parse(open(os.path.join(TF_DIR, "runner_runs.py"), encoding="utf-8").read())
    consts = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert "RUNNER_NONCE" not in consts and "nonce" not in consts
    logged = [ast.unparse(n) for n in ast.walk(tree) if isinstance(n, ast.Call)
              and ast.unparse(n.func).startswith("logger.")]
    assert all("data" not in s and "options" not in s for s in logged)


# ------------------------------------------------------------------------------------------------ tf-applier
class FakeResultStore:
    def __init__(self, fail=False, signed=None):
        self.fail, self.docs, self.signed = fail, {}, signed

    def write(self, dispatch_id, **kw):
        if self.fail:
            raise RuntimeError("firestore down")
        assert dispatch_id not in self.docs
        # SAT-37: the document is written only after vending signed exactly its fingerprint
        assert self.signed is not None and self.signed[-1] == hashlib.sha256(
            kw["result_json"].encode("utf-8")).hexdigest()
        self.docs[dispatch_id] = dict(kw, result=json.loads(kw["result_json"]))


def _sync_job(monkeypatch, base, ri, *, mode="deploy", options=None, served=None, record_over=None, now=T0,
              store=None, deploy_result=None, unlock_result=None, sign_error=None, plan_result=None):
    applier = _load_tf_module(monkeypatch, base, "applier.py", "fd7l_5b_applier")
    rr_mod = applier.rr
    options = options if options is not None else {"hcl_files": {"infra/workload/main.tf": "# x\n"},
                                                   "iac_engine": "OPENTOFU", "refuse_destroy": True,
                                                   "approved_removals": ["a.b"], "deadline_epoch": T0 + 1000}
    data = rr_mod.build_payload(mode=mode, product_id=PRODUCT, trace_id="t-brokered", options=options)
    rec = _dispatch(mode=mode, callback_url=None, payload_ref=f"gs://{STAGING}/runs/{PRODUCT}/t/a.json",
                    payload_sha256=hashlib.sha256(data).hexdigest(), execution=EXECUTION)
    rec.update(record_over or {})
    calls = {}
    real = applier.TerraformService

    def factory(*a, **k):
        inst = real(*a, **k)
        inst.db = _DB({("workloads", PRODUCT): {"project_id": CHILD}})

        def deploy(**kw):
            calls["deploy"] = dict(kw, limits=inst.tofu_time_limits,
                                   runner=inst._workspace_runner(os.path.join(base, kw["trace_id"], PRODUCT)))
            return deploy_result or {"status": "SUCCESS", "service_url": "https://x"}

        def unlock(**kw):
            calls["unlock"] = dict(kw, runner=inst._workspace_runner(os.path.join(base, kw["trace_id"], PRODUCT)))
            return unlock_result or {"status": "UNLOCKED", "product_id": PRODUCT, "lock_id": kw["lock_id"]}
        def plan(pid, trace_id, hcl_files, iac_engine=None):
            calls["plan"] = dict(product_id=pid, trace_id=trace_id, hcl_files=hcl_files, iac_engine=iac_engine,
                                 limits=inst.tofu_time_limits,
                                 runner=inst._workspace_runner(os.path.join(base, trace_id, PRODUCT)))
            if isinstance(plan_result, Exception):
                raise plan_result
            return plan_result or {"status": "PLAN_READY", "product_id": pid, "trace_id": trace_id,
                                   "resource_changes": {"add": 1, "change": 0, "destroy": 0},
                                   "is_safe_autonomous": True}
        inst.deploy_workload, inst.force_unlock, inst.generate_plan = deploy, unlock, plan
        return inst

    monkeypatch.setattr(applier, "TerraformService", factory)
    monkeypatch.setattr(applier.runner_creds, "check_state_bucket_owner", lambda *a: None)
    for k, v in JOB_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("STACKVEND_RUNNER_STAGING_BUCKET", STAGING)
    broker = FakeBroker(ri)
    broker.redeem = lambda nonce, execution: (broker.redeemed.append((nonce, execution)) or rec, SESSION_KEY)
    broker.signed = []

    def sign_result(session_key, result_sha256):     # SAT-37: vending's /runner/result
        assert session_key == SESSION_KEY
        if sign_error is not None:
            raise sign_error
        broker.signed.append(result_sha256)
    broker.sign_result = sign_result
    guard = _DB({("workload_provenance", PRODUCT): {"project_id": CHILD, "runner_identity": _signed_2a(ri)}})
    store = store if store is not None else FakeResultStore()
    if getattr(store, "signed", 0) is None:
        store.signed = broker.signed
    ok = applier.run_brokered_job(broker=broker, region_lookup=lambda: "us-central1", guard_db_factory=lambda: guard,
                                  certs=fk.certs_for(), tick_s=3600,
                                  payload_session=FakeSession(content=served if served is not None else data),
                                  result_store=store, clock=lambda: now)
    return applier, ok, calls, broker, store


def test_job_sync_deploy_reads_the_payload_deploys_and_writes_the_result(monkeypatch, base, sent_callbacks, ri,
                                                                         caplog):
    with caplog.at_level(logging.INFO):
        applier, ok, calls, broker, store = _sync_job(monkeypatch, base, ri)
    assert ok is True and not sent_callbacks                         # no callback: the result document answers
    d = calls["deploy"]
    assert (d["product_id"], d["trace_id"], d["target_project_id"], d["branch"], d["iac_engine"]) == \
        (PRODUCT, "t-brokered", CHILD, "main", "OPENTOFU")
    assert d["hcl_files"] == {"infra/workload/main.tf": "# x\n"}
    assert d["destroy_policy"].approved_removals == frozenset({"a.b"})
    assert d["time_budget_s"] == 1000 and d["limits"] == applier.TOFU_TIME_LIMITS_SERVICE
    assert d["runner"] is not None                                    # the brokered deployer, registered
    dispatch_id = hashlib.sha256(NONCE.encode()).hexdigest()
    doc = store.docs[dispatch_id]
    assert (doc["execution"], doc["product_id"], doc["trace_id"], doc["mode"]) == \
        (EXECUTION, PRODUCT, "t-brokered", "deploy")
    assert doc["result"] == {"status": "SUCCESS", "service_url": "https://x"}
    assert NONCE not in caplog.text and SESSION_KEY not in caplog.text and "# x" not in caplog.text


@pytest.mark.parametrize("case,code", [
    ("bytes", "RUNNER_PAYLOAD_MISMATCH"),
    ("deadline", "RUNNER_SYNC_DEADLINE_PASSED"),
    ("bad_key", "RUNNER_PAYLOAD_MISMATCH"),
    ("drift_mode", "RUNNER_MODE_UNSUPPORTED"),
    ("saved_plan", "RUNNER_MODE_UNSUPPORTED"),
    ("no_payload", "RUNNER_MODE_UNSUPPORTED"),
])
def test_job_sync_refusals_are_typed_results_and_mint_nothing(monkeypatch, base, sent_callbacks, ri, case, code):
    kw = {}
    if case == "bytes":
        kw["served"] = b'{"tampered": true}'
    elif case == "deadline":
        kw["now"] = T0 + 1001
    elif case == "bad_key":
        kw["options"] = {"hcl_files": {"../terraform.rc": ""}, "deadline_epoch": T0 + 1000}
    elif case == "drift_mode":
        kw["record_over"] = {"mode": "drift"}
    elif case == "saved_plan":
        kw["record_over"] = {"saved_plan_sha256": "a" * 64}
    elif case == "no_payload":
        kw["record_over"] = {"payload_ref": None}
    applier, ok, calls, broker, store = _sync_job(monkeypatch, base, ri, **kw)
    assert ok is False and not calls and broker.calls == 0 and not sent_callbacks
    res = next(iter(store.docs.values()))["result"]
    assert res["status"] == "FAILED" and res["error_class"] == code and res["operator_required"] is True


def test_job_sync_force_unlock_runs_with_the_brokered_deployer(monkeypatch, base, sent_callbacks, ri):
    applier, ok, calls, broker, store = _sync_job(monkeypatch, base, ri, mode="force_unlock",
                                                  options={"lock_id": "17", "iac_engine": None})
    assert ok is True and calls["unlock"]["lock_id"] == "17" and calls["unlock"]["trace_id"] == "t-brokered"
    assert calls["unlock"]["runner"] is not None and broker.calls >= 1
    assert next(iter(store.docs.values()))["result"]["status"] == "UNLOCKED"


def test_job_sync_unlock_without_a_lock_id_is_refused(monkeypatch, base, sent_callbacks, ri):
    applier, ok, calls, broker, store = _sync_job(monkeypatch, base, ri, mode="force_unlock", options={})
    assert ok is False and not calls and broker.calls == 0
    assert next(iter(store.docs.values()))["result"]["error_class"] == "RUNNER_PAYLOAD_MISMATCH"


def test_job_sync_failed_deploy_is_recorded_and_the_execution_fails(monkeypatch, base, sent_callbacks, ri):
    applier, ok, calls, broker, store = _sync_job(monkeypatch, base, ri, deploy_result={
        "status": "FAILED", "error_class": "DESTROY_REQUIRES_APPROVAL", "error": "e"})
    assert ok is False and next(iter(store.docs.values()))["result"]["error_class"] == "DESTROY_REQUIRES_APPROVAL"


def test_job_sync_result_not_written_fails_the_execution_loudly(monkeypatch, base, sent_callbacks, ri, caplog):
    with caplog.at_level(logging.ERROR):
        applier, ok, calls, broker, store = _sync_job(monkeypatch, base, ri, store=FakeResultStore(fail=True))
    assert ok is False and "RUNNER_RESULT_NOT_RECORDED" in caplog.text


def test_job_workflow_deploy_with_a_payload_is_still_refused(monkeypatch, base, sent_callbacks, ri):
    applier, ok, calls, broker, store = _sync_job(monkeypatch, base, ri, record_over={"callback_url": CALLBACK})
    assert ok is False and not calls and not store.docs
    assert sent_callbacks[-1]["error_class"] == "RUNNER_MODE_UNSUPPORTED"


# ------------------------------------------------------------------------------------------------ end to end
def test_end_to_end_server_payload_reaches_the_execution_and_its_result_the_caller(monkeypatch, base, pw, ri):
    """The server's staged bytes and sha256 travel through the (fake) signed dispatch record to the job; the job's
    result document is the server's answer."""
    tf, vending, _g, stagers, _r, clock = pw
    store = {}

    class Store:
        def get(self, dispatch_id):
            doc = store.get(dispatch_id)
            return dict(doc, schema="runner_result/v1", dispatch_id=dispatch_id) if doc else None

    key = (tf.ri.NONCE_COLLECTION, DISPATCH_ID)
    _g.docs[key] = _nonce_rec(tf)                # redeemed, no fingerprint yet

    class JobStore:
        signed = None

        def write(self, dispatch_id, **kw):
            # vending signed the job's fingerprint into the record before this write (SAT-37)
            _g.docs[key] = _resign(tf, _g.docs[key], result_sha256=self.signed[-1])
            store[DISPATCH_ID] = kw          # the server's fake vending answers dispatch id DISPATCH_ID
    tf.RESULT_STORE_FACTORY = Store
    staged = {}

    class Stager(FakeStager):
        def stage(self, **kw):
            ref, sha = super().stage(**kw)
            staged.update(ref=ref, sha=sha, data=kw["data"])
            return ref, sha
    tf.STAGER_FACTORY = Stager
    real_post = vending.post

    def post(url, **kw):
        resp = real_post(url, **kw)
        body = kw["json"]
        _sync_job(monkeypatch, base, ri, options=json.loads(staged["data"])["options"],
                  served=staged["data"], record_over={"payload_ref": body["payload_ref"],
                                                      "payload_sha256": body["payload_sha256"],
                                                      "trace_id": body["trace_id"]},
                  store=JobStore(), now=T0)
        return resp
    vending.post = post
    monkeypatch.setenv("STACKVEND_RUNNER_STAGING_BUCKET", STAGING)
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t-brokered", "target_project_id": CHILD,
                              "hcl_files": {"infra/workload/main.tf": "# x\n"}})
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "SUCCESS", "service_url": "https://x"}


# ------------------------------------------------------------------------------------------------ SAT-37: plan (5b part 2)
PLAN_READY = {"status": "PLAN_READY", "product_id": PRODUCT, "trace_id": "t1", "workspace_dir": "/w/t1/x",
              "resource_changes": {"add": 1, "change": 0, "destroy": 0, "destroy_addresses": []},
              "is_safe_autonomous": True, "plan_output": "Plan: 1 to add", "raw_plan_json": {"format_version": "1.2"}}


def test_per_workload_plan_runs_in_one_execution_with_a_staged_payload(pw):
    tf, vending, _g, stagers, results, _c = pw
    results.doc = _result_doc(PLAN_READY, mode="plan")
    body = {"product_id": PRODUCT, "trace_id": "t1", "hcl_files": {"infra/workload/main.tf": "# x\n"},
            "iac_engine": "OPENTOFU"}
    r = _post(tf, "/plan", body)
    assert r.status_code == 200, r.text
    assert r.json() == dict(PLAN_READY, saved_plan_kept=False)
    (pid, trace, data), = stagers[0].staged
    assert json.loads(data) == {"schema": "runner_payload/v1", "mode": "plan", "product_id": PRODUCT, "trace_id": "t1",
                                "options": {"hcl_files": body["hcl_files"], "iac_engine": "OPENTOFU",
                                            "deadline_epoch": T0 + tf.SYNC_DEPLOY_TIME_BUDGET_S - 40.0}}
    sent = _sent_body(vending)
    assert (sent["mode"], sent["callback_url"], sent["branch"], sent["trace_id"]) == ("plan", None, "main", "t1")
    assert tf.service.generate_plan.call_count == 0 and not tf.watches.docs


def test_per_workload_plan_default_trace_is_the_in_process_one(pw):
    tf, vending, _g, _s, results, _c = pw
    results.doc = _result_doc(PLAN_READY, mode="plan", trace_id="auto-trace")
    r = _post(tf, "/plan", {"product_id": PRODUCT, "hcl_files": {"main.tf": ""}})
    assert r.status_code == 200 and _sent_body(vending)["trace_id"] == "auto-trace"


@pytest.mark.parametrize("result,status,detail", [
    ({"status": "PLAN_FAILED", "error": "boom", "stdout": ""}, 200, None),
    ({"status": "FAILED", "error_class": "RUNNER_IDENTITY_NOT_REGISTERED", "error": "x", "operator_required": True},
     200, None),
    ({"status": "FAILED", "error_class": "IAC_ENGINE_DOWNGRADE_BLOCKED", "error": "tofu state, terraform asked"}, 400,
     "tofu state, terraform asked"),
    ({"status": "FAILED", "error": "RuntimeError: kaput"}, 500, "RuntimeError: kaput"),
])
def test_per_workload_plan_answers_have_the_in_process_shape(pw, result, status, detail):
    """In-process: generate_plan's dict (any status, typed refusals included) is the 200 body, the engine gate is a
    400 with its text, an exception a 500 with its text."""
    tf, _v, _g, _s, results, _c = pw
    results.doc = _result_doc(result, mode="plan")
    r = _post(tf, "/plan", {"product_id": PRODUCT, "trace_id": "t1", "hcl_files": {"main.tf": ""}})
    assert r.status_code == status
    if status == 200:
        assert r.json() == dict(result, saved_plan_kept=False)
    else:
        assert r.json()["detail"] == detail


def test_per_workload_plan_runner_refusal_is_typed_and_runs_nothing(monkeypatch, pw):
    tf, vending, _g, stagers, _r, _c = pw
    monkeypatch.delenv("STACKVEND_RUNNER_STAGING_BUCKET")
    r = _post(tf, "/plan", {"product_id": PRODUCT, "trace_id": "t1", "hcl_files": {"main.tf": ""}})
    assert r.status_code == 503 and _code(r) == "RUNNER_PAYLOAD_UNCONFIGURED" and not vending.calls


def test_per_workload_mcp_plan_runs_in_an_execution(pw):
    tf, vending, _g, stagers, results, _c = pw
    results.doc = _result_doc(PLAN_READY, mode="plan")
    r = _post(tf, "/mcp", {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
        "name": "terraform_plan", "arguments": {"product_id": PRODUCT, "trace_id": "t1",
                                                "hcl_files": {"main.tf": ""}}}})
    body = r.json()
    assert r.status_code == 200 and body["id"] == 3
    import ast
    assert ast.literal_eval(body["result"]["content"][0]["text"]) == dict(PLAN_READY, saved_plan_kept=False)
    assert _sent_body(vending)["mode"] == "plan" and tf.service.generate_plan.call_count == 0


@pytest.mark.parametrize("hcl_files", [{"../" + "x.tf": ""}, {".terraform/" + "x.tf": ""}, ["main.tf"], None])
def test_per_workload_mcp_plan_checks_the_files_before_anything_is_staged(pw, hcl_files):
    """RT L1 (rt-sat-37): the MCP plan tool applies /plan's file-map checks before staging or dispatching; an unsafe or
    malformed map is a JSON-RPC -32000 error and costs no execution."""
    tf, vending, _g, stagers, results, _c = pw
    r = _post(tf, "/mcp", {"id": 5, "method": "tools/call", "params": {"name": "terraform_plan", "arguments": {
        "product_id": PRODUCT, "trace_id": "t1", "hcl_files": hcl_files}}})
    assert r.status_code == 200 and r.json()["error"]["code"] == -32000
    assert not stagers and not vending.calls and results.reads == 0


@pytest.mark.parametrize("case", ["unconfigured", "unsafe_product", "no_files", "not_a_dict", "downgrade"])
def test_per_workload_mcp_plan_failures_are_json_rpc_errors(monkeypatch, pw, case):
    tf, vending, _g, stagers, results, _c = pw
    arguments = {"product_id": PRODUCT, "trace_id": "t1", "hcl_files": {"main.tf": ""}}
    if case == "unconfigured":
        monkeypatch.delenv("STACKVEND_RUNNER_STAGING_BUCKET")
    elif case == "unsafe_product":
        arguments["product_id"] = "../x"
    elif case == "no_files":
        del arguments["hcl_files"]
    elif case == "not_a_dict":
        arguments = "nope"
    else:
        results.doc = _result_doc({"status": "FAILED", "error_class": "IAC_ENGINE_DOWNGRADE_BLOCKED",
                                   "error": "downgrade"}, mode="plan")
    r = _post(tf, "/mcp", {"id": 4, "method": "tools/call", "params": {"name": "terraform_plan",
                                                                        "arguments": arguments}})
    err = r.json()["error"]
    assert r.status_code == 200 and err["code"] == -32000
    if case == "unconfigured":
        assert err["data"]["error_class"] == "RUNNER_PAYLOAD_UNCONFIGURED"
    elif case == "downgrade":
        assert err["message"] == "downgrade"
    if case != "downgrade":
        assert not vending.calls
    assert tf.service.generate_plan.call_count == 0


def test_job_sync_plan_runs_generate_plan_with_the_brokered_deployer(monkeypatch, base, sent_callbacks, ri):
    applier, ok, calls, broker, store = _sync_job(
        monkeypatch, base, ri, mode="plan",
        options={"hcl_files": {"infra/workload/main.tf": "# x\n"}, "iac_engine": "OPENTOFU",
                 "deadline_epoch": T0 + 1000})
    p = calls["plan"]
    assert ok is True and (p["product_id"], p["trace_id"], p["iac_engine"]) == (PRODUCT, "t-brokered", "OPENTOFU")
    assert p["hcl_files"] == {"infra/workload/main.tf": "# x\n"} and p["runner"] is not None
    assert p["limits"] == applier.TOFU_TIME_LIMITS_SERVICE and "deploy" not in calls and not sent_callbacks
    (doc,) = store.docs.values()
    assert doc["mode"] == "plan" and doc["result"]["status"] == "PLAN_READY" and len(broker.signed) == 1


@pytest.mark.parametrize("case,code", [("no_files", "RUNNER_PAYLOAD_MISMATCH"), ("bad_key", "RUNNER_PAYLOAD_MISMATCH"),
                                       ("deadline", "RUNNER_SYNC_DEADLINE_PASSED")])
def test_job_sync_plan_refusals_mint_nothing(monkeypatch, base, sent_callbacks, ri, case, code):
    options = {"hcl_files": {"main.tf": ""}, "iac_engine": None, "deadline_epoch": T0 + 1000}
    kw = {}
    if case == "no_files":
        options["hcl_files"] = None
    elif case == "bad_key":
        options["hcl_files"] = {"../terraform.rc": ""}
    else:
        kw["now"] = T0 + 1001
    applier, ok, calls, broker, store = _sync_job(monkeypatch, base, ri, mode="plan", options=options, **kw)
    (doc,) = store.docs.values()
    assert ok is False and not calls and broker.calls == 0 and doc["result"]["error_class"] == code
    if case == "deadline":
        assert "nothing was planned" in doc["result"]["error"]


def test_job_sync_plan_engine_downgrade_is_typed(monkeypatch, base, sent_callbacks, ri):
    applier = _load_tf_module(monkeypatch, base, "applier.py", "fd7l_5b_applier_probe")
    err = applier.IaCEngineDowngradeBlockedError("tofu state cannot go back to terraform")
    applier, ok, calls, broker, store = _sync_job(
        monkeypatch, base, ri, mode="plan", plan_result=err,
        options={"hcl_files": {"main.tf": ""}, "iac_engine": "TERRAFORM", "deadline_epoch": T0 + 1000})
    (doc,) = store.docs.values()
    assert ok is False and doc["result"]["error_class"] == "IAC_ENGINE_DOWNGRADE_BLOCKED"
    assert doc["result"]["error"] == "tofu state cannot go back to terraform"


def test_result_text_drops_a_large_plan_json_first(rr):
    big = {"status": "PLAN_READY", "is_safe_autonomous": False, "resource_changes": {"add": 1},
           "raw_plan_json": {"resources": ["r" * 1000] * 1000}, "plan_output": "p"}
    text, truncated = rr.result_text(big)
    out = json.loads(text)
    assert truncated and out["raw_plan_json"] is None and out["resource_changes"] == {"add": 1}
    assert out["is_safe_autonomous"] is False and out["result_truncated"] is True


# ------------------------------------------------------------------------------------------------ SAT-37: signed result
def test_per_workload_result_whose_sha256_is_not_the_signed_fingerprint_is_refused_at_once(pw):
    """The SAT-31b residual (RT M1): a default-database writer substitutes the answer after the redeem. Vending's
    signed record carries the fingerprint of the execution's real result, so the forged document is refused, never
    answered."""
    tf, _v, guard, _s, results, clock = pw
    real = _result_doc({"status": "FAILED", "error_class": "STATE_LOCKED", "error": "locked"})
    key = (tf.ri.NONCE_COLLECTION, DISPATCH_ID)
    results.on_set = None
    results.doc = _result_doc({"status": "SUCCESS", "service_url": "https://attacker.example"})
    guard.docs[key] = _resign(tf, guard.docs[key], result_sha256=_fp(real))
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 502 and _code(r) == "RUNNER_RESULT_MISMATCH"
    assert "fingerprint" in r.json()["detail"]["error"] and EXECUTION in r.json()["detail"]["error"]
    assert "attacker" not in r.text and clock.t == T0


def test_per_workload_result_before_its_fingerprint_is_signed_is_looked_at_again(pw):
    tf, _v, guard, _s, results, clock = pw
    key = (tf.ri.NONCE_COLLECTION, DISPATCH_ID)
    signed = guard.docs[key]
    guard.docs[key] = _nonce_rec(tf)                      # redeemed, fingerprint not signed yet
    real = guard.collection
    looks = {"n": 0}

    def collection(name):
        if name == tf.ri.NONCE_COLLECTION:
            looks["n"] += 1
            if looks["n"] == 3:
                guard.docs[key] = signed                  # vending signs the execution's fingerprint
        return real(name)
    guard.collection = collection
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 200 and clock.t == T0 + 2 * tf.rr.RESULT_POLL_S


def test_per_workload_result_whose_fingerprint_is_never_signed_is_never_answered(pw):
    tf, _v, guard, _s, results, clock = pw
    guard.docs[(tf.ri.NONCE_COLLECTION, DISPATCH_ID)] = _nonce_rec(tf)
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 504 and _code(r) == "RUNNER_RESULT_TIMEOUT"


@pytest.mark.parametrize("signed", ["0" * 64, 17, "F" * 64, "\u00e9" * 64])
def test_per_workload_malformed_or_other_fingerprint_is_refused(pw, signed):
    tf, _v, guard, _s, results, _c = pw
    key = (tf.ri.NONCE_COLLECTION, DISPATCH_ID)
    guard.docs[key] = _resign(tf, guard.docs[key], result_sha256=signed)
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 502 and _code(r) == "RUNNER_RESULT_MISMATCH"


def test_per_workload_shortened_result_keeps_its_flag_from_the_signed_text(pw):
    tf, _v, _g, _s, results, _c = pw
    text, truncated = tf.rr.result_text({"status": "SUCCESS", "stdout": "x" * 2_000_000, "service_url": "u"})
    results.doc = _result_doc({}, result_json=text, result_truncated=False)   # the document flag is not trusted
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert truncated and r.status_code == 200 and r.json()["result_truncated"] is True


# ------------------------------------------------------------------------------------------------ SAT-37: RT L2
def test_per_workload_execution_that_ended_without_a_result_ends_the_wait_early(pw):
    tf, vending, _g, _s, results, clock = pw
    results.doc = None
    vending.state = dict(vending.state, ended=True, failed_count=1, succeeded_count=0, result_signed=False)
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 502 and _code(r) == "TF_APPLIER_EXECUTION_ENDED_WITHOUT_RESULT"
    detail = r.json()["detail"]["error"]
    assert EXECUTION in detail and "may have applied" in detail and "failed 1" in detail
    assert clock.t == T0 + tf.rr.EXECUTION_STATE_FIRST_S + tf.rr.EXECUTION_ENDED_GRACE_S
    assert vending.states == [{"dispatch_id": DISPATCH_ID}] * 2


def test_per_workload_execution_reported_ended_before_its_completion_time_ends_the_wait_early(pw):
    """SAT-52 RT LOW (rt-sat-52-lows F2): vending's `ended` now reads every structured field, so a failed task is
    reported ended while `completion_time` is still None. The server decides on `ended` alone, exactly as before."""
    tf, vending, _g, _s, results, clock = pw
    results.doc = None
    vending.state = dict(vending.state, ended=True, completion_time=None, failed_count=1, succeeded_count=None,
                         cancelled_count=None, result_signed=False)
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 502 and _code(r) == "TF_APPLIER_EXECUTION_ENDED_WITHOUT_RESULT"
    assert "failed 1" in r.json()["detail"]["error"]
    assert clock.t == T0 + tf.rr.EXECUTION_STATE_FIRST_S + tf.rr.EXECUTION_ENDED_GRACE_S


def test_per_workload_execution_that_ended_unredeemed_is_failed_before_redeem_without_the_window(pw):
    tf, vending, guard, _s, results, clock = pw
    results.doc = None
    guard.docs[(tf.ri.NONCE_COLLECTION, DISPATCH_ID)] = _nonce_rec(tf, redeemed=False)
    vending.state = dict(vending.state, ended=True, redeemed=False)
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 502 and _code(r) == "TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM"
    assert "applied nothing" in r.json()["detail"]["error"]
    assert clock.t < T0 + tf.ri.REDEEM_WINDOW_SECONDS


@pytest.mark.parametrize("record", ["redeemed", "forged", "unreadable"])
def test_per_workload_applied_nothing_is_never_decided_from_the_status_answer_alone(pw, record):
    """RT L2 (rt-sat-37): vending's status says "not redeemed", but the SIGNED record says redeemed, is forged or
    cannot be read: the conservative TF_APPLIER_EXECUTION_ENDED_WITHOUT_RESULT, never "it applied nothing"."""
    tf, vending, guard, _s, results, clock = pw
    results.doc = None
    key = (tf.ri.NONCE_COLLECTION, DISPATCH_ID)
    if record == "forged":
        guard.docs[key] = dict(guard.docs[key], redeemed=False)          # signature no longer verifies
    elif record == "unreadable":
        real = guard.collection

        def collection(name):
            if name == tf.ri.NONCE_COLLECTION and clock.t >= T0 + tf.rr.EXECUTION_STATE_FIRST_S:
                raise RuntimeError("guard db down")
            return real(name)
        guard.collection = collection
    vending.state = dict(vending.state, ended=True, redeemed=False)
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 502 and _code(r) == "TF_APPLIER_EXECUTION_ENDED_WITHOUT_RESULT"
    assert "applied nothing" not in r.json()["detail"]["error"]


def test_per_workload_result_written_just_before_the_end_is_answered(pw):
    tf, vending, _g, _s, results, clock = pw
    results.appear_after = 20                                  # appears at T0 + 100 s, after the first "ended"
    vending.state = dict(vending.state, ended=True)
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 200 and clock.t == T0 + 100 and len(vending.states) == 1


def test_per_workload_no_state_question_before_the_first_minute(pw):
    tf, vending, _g, _s, results, clock = pw
    results.appear_after = 11                                  # T0 + 55 s
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 200 and vending.states == []


@pytest.mark.parametrize("state", [(503, {"detail": {"code": "RUNNER_EXECUTION_UNVERIFIED"}}),
                                   (200, {"dispatch_id": "e" * 64, "execution": EXECUTION, "ended": True}),
                                   {"dispatch_id": DISPATCH_ID, "execution": "projects/x/executions/other",
                                    "ended": True, "redeemed": True},
                                   {"dispatch_id": DISPATCH_ID, "execution": EXECUTION, "ended": None,
                                    "redeemed": True}])
def test_per_workload_unknown_execution_state_decides_nothing(pw, state):
    """Vending unavailable, an answer about another dispatch or execution, or an unknown state: the wait goes on to
    the request's deadline (the honest 504), asking at most once a minute."""
    tf, vending, _g, _s, results, clock = pw
    results.doc = None
    vending.state = state
    r = _post(tf, "/deploy", {"product_id": PRODUCT, "trace_id": "t1"})
    assert r.status_code == 504 and _code(r) == "RUNNER_RESULT_TIMEOUT"
    wait = tf.SYNC_REQUEST_LIMIT_S - tf.SYNC_DEPLOY_RESPONSE_MARGIN_S - tf.rr.EXECUTION_STATE_FIRST_S
    assert 1 <= len(vending.states) <= wait // tf.rd.WATCH_RETRY_S + 1


def test_execution_state_client_reads_vending_and_types_every_failure(tf_main):
    rd = tf_main.rd
    calls = []

    def post(url, **kw):
        calls.append((url, kw))
        resp = MagicMock()
        resp.status_code, resp.json.return_value = answers.pop(0)
        return resp
    answers = [(200, {"dispatch_id": DISPATCH_ID, "ended": True}), (403, {"detail": {"code": "CALLER_NOT_ALLOWED"}}),
               (200, {"dispatch_id": "e" * 64}), (200, ["not", "a", "dict"])]
    client = rd.DispatchClient("https://vending.example", id_token=lambda aud: "id", post=post)
    assert client.execution_state(DISPATCH_ID)["ended"] is True
    assert calls[0][0] == "https://vending.example/runner/dispatch-status"
    assert calls[0][1]["json"] == {"dispatch_id": DISPATCH_ID} and calls[0][1]["timeout"] == rd.STATUS_TIMEOUT_S
    for _ in range(3):
        with pytest.raises(tf_main.ri.RunnerIdentityError) as ei:
            client.execution_state(DISPATCH_ID)
        assert ei.value.code == "RUNNER_DISPATCH_STATUS_UNAVAILABLE"


# ------------------------------------------------------------------------------------------------ SAT-37: job side
def test_job_signs_the_fingerprint_of_exactly_the_written_result_before_writing(monkeypatch, base, sent_callbacks,
                                                                               ri):
    applier, ok, calls, broker, store = _sync_job(monkeypatch, base, ri)
    (doc,) = store.docs.values()
    assert ok is True and broker.signed == [hashlib.sha256(doc["result_json"].encode("utf-8")).hexdigest()]
    assert doc["result_truncated"] is False


def test_job_writes_no_result_when_vending_does_not_sign_it(monkeypatch, base, sent_callbacks, ri, caplog):
    err = ri.RunnerIdentityError("RUNNER_SESSION_ENDED", "the execution is not running", http_status=403)
    with caplog.at_level(logging.ERROR):
        applier, ok, calls, broker, store = _sync_job(monkeypatch, base, ri, sign_error=err)
    assert ok is False and store.docs == {} and calls["deploy"]
    assert "RUNNER_RESULT_NOT_RECORDED" in caplog.text and "RUNNER_SESSION_ENDED" in caplog.text
    assert SESSION_KEY not in caplog.text


def test_job_refusal_results_are_signed_too(monkeypatch, base, sent_callbacks, ri):
    applier, ok, calls, broker, store = _sync_job(monkeypatch, base, ri, served=b'{"tampered": true}')
    (doc,) = store.docs.values()
    assert ok is False and doc["result"]["error_class"] == "RUNNER_PAYLOAD_MISMATCH" and len(broker.signed) == 1


# ------------------------------------------------------------------------------------------------ docs
def test_new_classes_are_in_the_fail_loudly_policy():
    doc = open(os.path.join(REPO, "documentation", "fail-loudly-policy.md")).read()
    for code in ("RUNNER_PAYLOAD_UNCONFIGURED", "RUNNER_PAYLOAD_STAGING_FAILED", "RUNNER_PAYLOAD_MISMATCH",
                 "RUNNER_PAYLOAD_UNREADABLE", "RUNNER_RESULT_TIMEOUT", "RUNNER_RESULT_MISMATCH",
                 "RUNNER_RESULT_NOT_RECORDED", "RUNNER_SYNC_DEADLINE_PASSED",
                 "TF_APPLIER_EXECUTION_ENDED_WITHOUT_RESULT", "RUNNER_RESULT_ALREADY_SIGNED", "RUNNER_RESULT_INVALID",
                 "IAC_ENGINE_DOWNGRADE_BLOCKED"):
        assert code in doc, code
