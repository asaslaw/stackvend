"""FD-7L Phase 5a (SAT-31): one tf-applier execution per credentialed run (D3-a) on the workflow's deploy path.

* Every install: a failed tf-applier dispatch of /deploy-async is a typed FAILED callback (TF_APPLIER_DISPATCH_FAILED,
  operator_required); the deploy is never run in the server container as a fallback.
* Per-workload installs: /deploy-async is dispatched through vending `/runner/dispatch` (the server never calls RunJob
  and never sees the nonce); caller-supplied hcl_files and a request target_project_id other than the signed record's
  project are refused; every workload route accepts only an allow-listed caller (plan 2.13).

Do No Harm (Shared installs: STACKVEND_TF_RUNNER_IDENTITY unset or PLATFORM): no header, token or record is read on any
route; the /deploy-async answer, the pipeline record, the RunJob request and the job's env overrides are unchanged;
a job switched off by configuration still deploys in-process exactly as before.

Hermetic: fake verifier, fake vending (HTTP post stand-in), fake guard database, signatures with tests/fd7l_fakes.py's
real RSA key; no network, no cloud clients.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import logging
import os
from unittest.mock import MagicMock, patch

import pytest

import fd7l_fakes as fk
from test_fd4g_terraform_workspace import (  # noqa: F401  (pytest fixtures reused by name)
    _isolated_tf_service, _load_tf_module, base, sent_callbacks)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO, "mcp-servers", "terraform")
MODE = "STACKVEND_TF_RUNNER_IDENTITY"
HOST = fk.HOST
CHILD = "claims-prod-1a2b"
PRODUCT = "claims"
BUCKET = f"{CHILD}-tfstate"
CALLBACK = "https://workflowexecutions.googleapis.com/v1/projects/h/locations/r/workflows/w/executions/e/callbacks/c"
VENDING = "https://project-repo-vending-service-123.us-central1.run.app"
EXECUTION = f"{fk.EXEC_PREFIX}tf-applier-abc12"
SERVER_TOKEN = "eyJ.test-only-server-id-token"     # test value only
CALLER_TOKEN = "eyJ.test-only-caller-id-token"     # test value only
ARCHITECT = f"sa-castor-architect@{HOST}.iam.gserviceaccount.com"
QA = f"sa-castor-qa@{HOST}.iam.gserviceaccount.com"

WORKLOAD_ROUTES = [
    ("/deploy-async", {"product_id": PRODUCT, "trace_id": "t1", "callback_url": CALLBACK}),
    ("/deploy", {"product_id": PRODUCT, "trace_id": "t1"}),
    ("/plan", {"product_id": PRODUCT, "trace_id": "t1", "hcl_files": {"main.tf": ""}}),
    ("/apply", {"product_id": PRODUCT, "trace_id": "t1"}),
    ("/drift-check", {"product_id": PRODUCT, "trace_id": "t1"}),
    ("/force-unlock", {"product_id": PRODUCT, "lock_id": "1"}),
    (f"/api/workloads/{PRODUCT}/force-unlock", {"product_id": PRODUCT, "lock_id": "1"}),
    ("/mcp", {"method": "tools/list"}),
]
SERVICE_METHODS = ("generate_plan", "apply_plan", "check_drift", "force_unlock", "deploy_workload")


# ------------------------------------------------------------------------------------------------ fixtures
@pytest.fixture
def tf_main(monkeypatch, base):
    for k in (MODE, "TF_SERVER_WORKLOAD_CALLERS", "STACKVEND_BROKER_SA", "VENDING_SERVICE_URL",
              "STACKVEND_GUARD_FIRESTORE_DATABASE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PROJECT_ID", HOST)
    mod = _load_tf_module(monkeypatch, base, "main.py", "fd7l_5a_main")
    for name in SERVICE_METHODS:
        setattr(mod.service, name, MagicMock(return_value={"status": "SUCCESS"}))
    mod.CALLER_TOKEN_VERIFIER = lambda token: pytest.fail("a Shared install read a caller token")
    mod.GUARD_DB_FACTORY = lambda: pytest.fail("a Shared install read the guard database")
    mod.DISPATCH_CLIENT_FACTORY = lambda *a, **k: pytest.fail("a Shared install dispatched through vending")
    return mod


def _client(mod):
    from fastapi.testclient import TestClient
    return TestClient(mod.app)


def _claims(email=ARCHITECT, aud="https://testserver/deploy-async", **over):
    c = {"iss": "https://accounts.google.com", "aud": aud, "email": email, "email_verified": True}
    c.update(over)
    return c


class FakeVending:
    """Stands in for requests.post to vending's /runner/dispatch (and the server's own ID token)."""

    def __init__(self, status=200, body=None, raises=None):
        self.status, self.raises = status, raises
        self.body = body if body is not None else {"status": "DISPATCHED", "dispatch_id": "d" * 64,
                                                   "execution": EXECUTION, "product_id": PRODUCT, "mode": "deploy"}
        self.calls = []
        self.audiences = []

    def id_token(self, audience):
        self.audiences.append(audience)
        return SERVER_TOKEN

    def post(self, url, **kw):
        self.calls.append((url, kw))
        if self.raises is not None:
            raise self.raises
        resp = MagicMock()
        resp.status_code = self.status
        resp.json.return_value = self.body
        return resp


class FakeGuardDb:
    def __init__(self, docs=None, raises=None):
        self.docs, self.raises, self.reads = docs or {}, raises, []

    def collection(self, name):
        db = self

        class _C:
            def document(self, doc_id):
                class _D:
                    def get(self):
                        db.reads.append((name, doc_id))
                        if db.raises is not None:
                            raise db.raises
                        snap = MagicMock()
                        snap.exists = (name, doc_id) in db.docs
                        snap.to_dict.return_value = db.docs.get((name, doc_id))
                        return snap
                return _D()
        return _C()


class FakeWatchStore:
    """runner_dispatch.WatchStore stand-in: an atomic claim (one lock), like the Firestore transaction."""

    def __init__(self, fail_create=False):
        import threading
        self.docs, self.fail_create, self._lock = {}, fail_create, threading.Lock()

    def create(self, dispatch_id, doc):
        if self.fail_create:
            raise RuntimeError("firestore down")
        with self._lock:
            if dispatch_id in self.docs:
                raise RuntimeError("exists")
            self.docs[dispatch_id] = dict(doc)

    def get(self, dispatch_id):
        with self._lock:
            d = self.docs.get(dispatch_id)
            return dict(d) if d is not None else None

    def claim(self, dispatch_id, fields):
        with self._lock:
            cur = self.docs.get(dispatch_id)
            if cur is not None and cur.get("state") != "WATCHING":
                return False
            self.docs[dispatch_id] = dict(cur or {}, **fields)
            return True

    def set_state(self, dispatch_id, fields):
        with self._lock:
            self.docs[dispatch_id] = dict(self.docs.get(dispatch_id) or {}, **fields)

    def pending(self, *a, **k):
        with self._lock:
            return [d for d, v in self.docs.items() if v.get("state") == "WATCHING"]

    def sending(self, *a, **k):
        with self._lock:
            return [(d, dict(v)) for d, v in self.docs.items() if v.get("state") == "SENDING"]


def _signed(ri, key=None, signer=None, **over):
    rec = ri.new_runner_identity_record(product_id=PRODUCT, project_id=CHILD, project_number="123456789",
                                        state_bucket=BUCKET, status="READY", updated_at="2026-11-01T00:00:00Z")
    rec.update(over)
    return ri.sign_record(ri.provenance_doc_path(PRODUCT), rec, signer_email=signer or fk.BROKER,
                          signed_at="2026-11-01T00:00:00Z", sign_blob=(key or fk.BROKER_KEY).sign)


@pytest.fixture
def per_workload(monkeypatch, tf_main):
    """A Per-workload install with step-A env, a listed caller, a fake vending and a fake guard database."""
    monkeypatch.setenv(MODE, "PER_WORKLOAD")
    monkeypatch.setenv("VENDING_SERVICE_URL", VENDING)
    monkeypatch.setenv("STACKVEND_BROKER_SA", fk.BROKER)
    vending = FakeVending()
    watches, scheduled = FakeWatchStore(), []
    tf_main.CALLER_TOKEN_VERIFIER = lambda token: _claims()
    tf_main.DISPATCH_CLIENT_FACTORY = lambda url: tf_main.rd.DispatchClient(url, id_token=vending.id_token,
                                                                            post=vending.post)
    ri = tf_main.ri
    guard = FakeGuardDb({(ri.PROVENANCE_COLLECTION, PRODUCT): {"project_id": CHILD,
                                                                "runner_identity": _signed(ri)}})
    tf_main.GUARD_DB_FACTORY = lambda: guard
    tf_main.PROVENANCE_CERTS = fk.certs_for()
    tf_main.WATCH_STORE_FACTORY = lambda: watches
    tf_main.WATCH_SCHEDULER = lambda delay, fn, *args: scheduled.append((delay, fn, args))
    tf_main.watches, tf_main.scheduled = watches, scheduled
    monkeypatch.setattr(tf_main, "trigger_tf_applier_job",
                        lambda *a, **k: pytest.fail("a Per-workload deploy called RunJob from the server"))
    monkeypatch.setattr(tf_main, "run_deploy_in_background",
                        lambda *a, **k: pytest.fail("a Per-workload deploy ran in the server"))
    return tf_main, vending, guard


def _post(mod, path, body, token=CALLER_TOKEN):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return _client(mod).post(path, json=body, headers=headers)


# ------------------------------------------------------------------------------------------------ Shared installs
@pytest.mark.parametrize("mode", [None, "PLATFORM", ""])
@pytest.mark.parametrize("path,body", WORKLOAD_ROUTES)
def test_shared_install_workload_routes_read_no_token(monkeypatch, tf_main, mode, path, body):
    if mode is None:
        monkeypatch.delenv(MODE, raising=False)
    else:
        monkeypatch.setenv(MODE, mode)
    monkeypatch.setattr(tf_main, "trigger_tf_applier_job", lambda req: True)
    r = _post(tf_main, path, body, token=None)
    assert r.status_code in (200, 202), r.text


def test_shared_install_deploy_async_answer_and_record_unchanged(monkeypatch, tf_main):
    db = MagicMock()
    tf_main.service.db = db
    seen = []
    monkeypatch.setattr(tf_main, "trigger_tf_applier_job", lambda req: seen.append(req) or True)
    r = _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "trace_id": "t1", "callback_url": CALLBACK,
                                         "target_project_id": CHILD, "branch": "main"}, token=None)
    assert r.status_code == 202
    assert r.json() == {"status": "ACCEPTED", "product_id": PRODUCT, "trace_id": "t1",
                        "message": "Terraform deployment dispatched to background worker. Workflow will resume via "
                                   "callback."}
    doc = db.collection.return_value.document
    db.collection.assert_called_with("pipeline_executions")
    doc.assert_called_with("t1")
    written = doc.return_value.set.call_args
    assert written.kwargs == {"merge": True}
    stage = written.args[0]["stages"]["terraform"]
    assert written.args[0]["current_stage"] == "TERRAFORM"
    assert {k: v for k, v in stage.items() if k != "started_at"} == {
        "status": "IN_FLIGHT", "state": "AWAITING_CALLBACK",
        "summary": "Building container image via Cloud Buildpacks & deploying Cloud Run"}
    assert len(seen) == 1 and seen[0].target_project_id == CHILD


def _shared_req(tf_main, **over):
    kw = dict(product_id="testapp", trace_id="trace-999", callback_url=CALLBACK, target_project_id="child-1",
              branch="release", hcl_files={"infra/workload/main.tf": "# x\n"})
    kw.update(over)
    return tf_main.AsyncDeployRequest(**kw)


def test_shared_install_run_job_request_and_env_overrides_unchanged(monkeypatch, tf_main):
    monkeypatch.setenv("REGION", "us-central1")
    monkeypatch.setenv("ENABLE_TF_APPLIER_JOB", "true")
    monkeypatch.setenv("VCS_PROVIDER", "GITHUB")
    monkeypatch.setenv("GIT_SERVER_URL", "https://git.example.test")
    monkeypatch.setenv("GITHUB_ORG", "Acme")
    monkeypatch.setenv("GITHUB_OWNER", "Acme")
    monkeypatch.setenv("GITHUB_MCP_URL", "https://gh.example.test")
    run_v2 = MagicMock()
    with patch.dict("sys.modules", {"google.cloud.run_v2": run_v2}):
        assert tf_main.trigger_tf_applier_job(_shared_req(tf_main)) is True
    assert run_v2.RunJobRequest.call_args.kwargs["name"] == f"projects/{HOST}/locations/us-central1/jobs/tf-applier"
    env = run_v2.RunJobRequest.Overrides.ContainerOverride.call_args.kwargs["env"]
    assert env == [
        {"name": "PRODUCT_ID", "value": "testapp"}, {"name": "TRACE_ID", "value": "trace-999"},
        {"name": "BRANCH", "value": "release"}, {"name": "TARGET_PROJECT_ID", "value": "child-1"},
        {"name": "CALLBACK_URL", "value": CALLBACK},
        {"name": "HCL_FILES_JSON", "value": '{"infra/workload/main.tf": "# x\\n"}'},
        {"name": "VCS_PROVIDER", "value": "GITHUB"}, {"name": "GIT_SERVER_URL", "value": "https://git.example.test"},
        {"name": "GITHUB_MCP_URL", "value": "https://gh.example.test"}, {"name": "GITHUB_ORG", "value": "Acme"},
        {"name": "GITHUB_OWNER", "value": "Acme"}]


def _both_dispatch_methods_fail(sdk_exc, rest):
    """run_v2 raising `sdk_exc` (ImportError = not installed) and the REST call answering `rest` (an int status or
    an exception)."""
    run_v2 = MagicMock()
    run_v2.JobsClient.side_effect = sdk_exc
    creds = MagicMock()
    creds.token = "test-only-token"
    if isinstance(rest, int):
        resp = MagicMock()
        resp.status_code = rest
        resp.text = "denied"
        post = patch("requests.post", return_value=resp)
    else:
        post = patch("requests.post", side_effect=rest)
    modules = patch.dict("sys.modules", {"google.cloud.run_v2": None if sdk_exc is ImportError else run_v2})
    return [modules, patch("google.auth.default", return_value=(creds, HOST)),
            patch("google.auth.transport.requests.Request"), post]


@pytest.mark.parametrize("sdk_exc,rest,unknown", [
    (ImportError, 403, False),                      # nothing started: SDK absent, REST refused
    (RuntimeError("sdk"), 503, True),               # SDK client not built; REST 503 without the API body: ambiguous
    (ImportError, ConnectionError("reset"), True),  # the REST attempt may have reached the API
])
def test_dispatch_failure_is_typed_never_in_process(monkeypatch, tf_main, sent_callbacks, sdk_exc, rest, unknown):
    monkeypatch.setenv("ENABLE_TF_APPLIER_JOB", "true")
    patches = _both_dispatch_methods_fail(sdk_exc, rest)
    for p in patches:
        p.start()
    try:
        with pytest.raises(tf_main.rd.TfApplierDispatchFailed) as ei:
            tf_main.trigger_tf_applier_job(_shared_req(tf_main))
        assert ei.value.cause == "RUN_JOB_FAILED" and ei.value.outcome_unknown is unknown
        tf_main.run_deploy_in_background(_shared_req(tf_main))
    finally:
        for p in reversed(patches):
            p.stop()
    tf_main.service.deploy_workload.assert_not_called()
    assert len(sent_callbacks) == 1
    cb = sent_callbacks[0]
    assert cb["status"] == "FAILED" and cb["error_class"] == "TF_APPLIER_DISPATCH_FAILED"
    assert cb["operator_required"] is True and cb["cause"] == "RUN_JOB_FAILED"
    assert cb["outcome_unknown"] is unknown and cb["trace_id"] == "trace-999"


def test_project_id_unset_is_typed_never_in_process(monkeypatch, tf_main, sent_callbacks):
    monkeypatch.delenv("PROJECT_ID", raising=False)
    monkeypatch.setenv("ENABLE_TF_APPLIER_JOB", "true")
    tf_main.run_deploy_in_background(_shared_req(tf_main))
    tf_main.service.deploy_workload.assert_not_called()
    assert sent_callbacks[-1]["error_class"] == "TF_APPLIER_DISPATCH_FAILED"
    assert sent_callbacks[-1]["cause"] == "PROJECT_ID_UNSET" and sent_callbacks[-1]["outcome_unknown"] is False


def test_job_switched_off_by_configuration_still_deploys_in_process(monkeypatch, tf_main, sent_callbacks):
    """Negative: ENABLE_TF_APPLIER_JOB=false (local runs, tests) is a configuration, not a fallback: unchanged."""
    monkeypatch.setenv("ENABLE_TF_APPLIER_JOB", "false")
    tf_main.run_deploy_in_background(_shared_req(tf_main, hcl_files=None))
    tf_main.service.deploy_workload.assert_called_once()
    assert sent_callbacks[-1]["status"] == "SUCCESS"


# ------------------------------------------------------------------------------------------------ Per-workload dispatch
def test_per_workload_deploy_async_is_dispatched_through_vending_only(per_workload):
    tf_main, vending, guard = per_workload
    db = MagicMock()
    tf_main.service.db = db
    r = _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "trace_id": "t1", "callback_url": CALLBACK,
                                         "target_project_id": CHILD, "branch": "release"})
    assert r.status_code == 202, r.text
    assert r.json()["status"] == "ACCEPTED" and r.json()["execution"] == EXECUTION
    assert len(vending.calls) == 1                                     # exactly one dispatch, never retried
    url, kw = vending.calls[0]
    assert url == f"{VENDING}/runner/dispatch"
    assert kw["json"] == {"product_id": PRODUCT, "trace_id": "t1", "branch": "release", "mode": "deploy",
                          "callback_url": CALLBACK}
    assert kw["headers"] == {"Authorization": f"Bearer {SERVER_TOKEN}"}
    assert vending.audiences == [VENDING]
    for name in SERVICE_METHODS:
        getattr(tf_main.service, name).assert_not_called()
    assert guard.reads == [("workload_provenance", PRODUCT)]
    db.collection.assert_any_call("pipeline_executions")          # same in-flight record as before


def test_per_workload_derived_trace_and_default_branch(per_workload):
    tf_main, vending, _ = per_workload
    r = _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK})
    assert r.status_code == 202
    assert vending.calls[0][1]["json"]["trace_id"] == f"deploy-async-{PRODUCT}"
    assert vending.calls[0][1]["json"]["branch"] == "main"


def test_per_workload_ignores_the_in_process_switch(monkeypatch, per_workload):
    """ENABLE_TF_APPLIER_JOB=false never makes a Per-workload deploy run in the server."""
    tf_main, vending, _ = per_workload
    monkeypatch.setenv("ENABLE_TF_APPLIER_JOB", "false")
    assert _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK}).status_code == 202
    assert len(vending.calls) == 1


def test_per_workload_caller_hcl_files_refused_before_dispatch(per_workload):
    tf_main, vending, _ = per_workload
    r = _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK,
                                         "hcl_files": {"infra/workload/main.tf": "# x\n"}})
    assert r.status_code == 422
    d = r.json()["detail"]
    assert d["error_class"] == "RUNNER_MODE_UNSUPPORTED" and d["operator_required"] is True
    assert not vending.calls


@pytest.mark.parametrize("case,status,code", [
    ("other_project", 409, "RUNNER_TARGET_MISMATCH"),
    ("unsigned", 409, "RUNNER_RECORD_UNSIGNED"),
    ("field_changed", 409, "RUNNER_RECORD_UNSIGNED"),
    ("not_ready", 409, "RUNNER_IDENTITY_NOT_READY"),
    ("no_record", 409, "RUNNER_IDENTITY_NOT_READY"),
    ("unreadable", 503, "RUNNER_IDENTITY_NOT_READY"),
])
def test_per_workload_request_target_must_equal_signed_provenance(per_workload, case, status, code):
    tf_main, vending, guard = per_workload
    ri = tf_main.ri
    key = (ri.PROVENANCE_COLLECTION, PRODUCT)
    target = CHILD
    if case == "other_project":
        target = "victim-project-9"
    elif case == "unsigned":
        guard.docs[key] = {"project_id": CHILD, "runner_identity": _signed(ri, key=fk.OTHER_KEY, signer=fk.CC)}
    elif case == "field_changed":
        rec = _signed(ri)
        rec["project_id"] = "victim-project-9"
        guard.docs[key] = {"project_id": "victim-project-9", "runner_identity": rec}
        target = "victim-project-9"
    elif case == "not_ready":
        guard.docs[key] = {"project_id": CHILD, "runner_identity": _signed(ri, status="MIGRATING")}
    elif case == "no_record":
        guard.docs[key] = {"project_id": CHILD}
    elif case == "unreadable":
        guard.raises = RuntimeError("firestore down")
    r = _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK,
                                         "target_project_id": target})
    assert r.status_code == status, r.text
    d = r.json()["detail"]
    assert d["error_class"] == code and d["operator_required"] is True
    assert not vending.calls


def test_per_workload_without_target_checks_no_record(per_workload):
    """The execution takes its target from the signed records only; no request target -> nothing to compare."""
    tf_main, vending, guard = per_workload
    assert _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK}).status_code == 202
    assert guard.reads == [] and len(vending.calls) == 1


@pytest.mark.parametrize("missing,code", [("VENDING_SERVICE_URL", "RUNNER_IDENTITY_NOT_READY"),
                                          ("STACKVEND_GUARD_FIRESTORE_DATABASE", "RUNNER_IDENTITY_NOT_READY")])
def test_per_workload_unconfigured_server_is_typed(monkeypatch, per_workload, missing, code):
    tf_main, vending, _ = per_workload
    monkeypatch.delenv(missing, raising=False)
    if missing == "STACKVEND_GUARD_FIRESTORE_DATABASE":
        tf_main.GUARD_DB_FACTORY = None
        tf_main._guard_db_client = None
    r = _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK,
                                         "target_project_id": CHILD})
    assert r.status_code == 503 and r.json()["detail"]["error_class"] == code
    assert not vending.calls


def _requests_exc(name):
    import requests
    return getattr(requests.exceptions, name)("test")


@pytest.mark.parametrize("vend,cause,unknown", [
    (dict(status=409, body={"detail": {"code": "RUNNER_IDENTITY_NOT_READY", "stage": "runner-identity"}}),
     "RUNNER_IDENTITY_NOT_READY", False),
    (dict(status=502, body={"detail": {"code": "RUNNER_DISPATCH_FAILED"}}), "RUNNER_DISPATCH_FAILED", False),
    (dict(status=403, body={"detail": {"code": "CALLER_NOT_ALLOWED"}}), "CALLER_NOT_ALLOWED", False),
    (dict(status=422, body={"detail": [{"type": "missing"}]}), "HTTP_422", False),
    (dict(status=504, body=None), "HTTP_504", True),                       # untyped: vending may still bind
    (dict(status=200, body={"status": "DISPATCHED"}), "MALFORMED_ANSWER", True),
    ("ConnectTimeout", "TRANSPORT", False),                                # never left this process
    ("ReadTimeout", "TRANSPORT", True),
])
def test_per_workload_dispatch_failure_is_a_typed_http_error_never_retried(per_workload, caplog, vend, cause,
                                                                           unknown):
    tf_main, _, _ = per_workload
    vending = FakeVending(raises=_requests_exc(vend)) if isinstance(vend, str) else FakeVending(**vend)
    if isinstance(vend, dict) and vend["body"] is None:
        vending.body = None
    tf_main.DISPATCH_CLIENT_FACTORY = lambda url: tf_main.rd.DispatchClient(url, id_token=vending.id_token,
                                                                            post=vending.post)
    db = MagicMock()
    tf_main.service.db = db
    with caplog.at_level(logging.DEBUG):
        r = _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "trace_id": "t1", "callback_url": CALLBACK})
    assert r.status_code in (502, 503), r.text
    d = r.json()["detail"]
    assert d["error_class"] == "TF_APPLIER_DISPATCH_FAILED" and d["cause"] == cause
    assert d["outcome_unknown"] is unknown and d["operator_required"] is True
    assert len(vending.calls) == 1
    db.collection.assert_not_called()                                # no in-flight record for a refused deploy
    assert SERVER_TOKEN not in caplog.text and CALLER_TOKEN not in caplog.text


def test_per_workload_no_server_identity_sends_nothing(per_workload):
    tf_main, _, _ = per_workload
    posts = []

    def no_token(aud):
        raise RuntimeError("metadata down")

    tf_main.DISPATCH_CLIENT_FACTORY = lambda url: tf_main.rd.DispatchClient(url, id_token=no_token,
                                                                            post=lambda *a, **k: posts.append(a))
    r = _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK})
    assert r.status_code == 503 and r.json()["detail"]["cause"] == "NO_ID_TOKEN" and not posts


def test_dispatch_client_refuses_a_non_https_vending_url(tf_main):
    with pytest.raises(tf_main.ri.RunnerIdentityError) as ei:
        tf_main.rd.DispatchClient("http://vending.internal")
    assert ei.value.code == "RUNNER_IDENTITY_NOT_READY"


# ------------------------------------------------------------------------------------------------ route allow-list
@pytest.mark.parametrize("path,body", WORKLOAD_ROUTES)
def test_per_workload_unlisted_caller_refused_on_every_workload_route(per_workload, caplog, path, body):
    tf_main, vending, _ = per_workload
    tf_main.CALLER_TOKEN_VERIFIER = lambda token: _claims(email=QA, aud=f"https://testserver{path}")
    with caplog.at_level(logging.WARNING):
        r = _post(tf_main, path, body)
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "CALLER_NOT_ALLOWED"
    assert not vending.calls
    for name in SERVICE_METHODS:
        getattr(tf_main.service, name).assert_not_called()
    assert "tf_server_workload_caller_refused" in [getattr(rec, "security_event", None) for rec in caplog.records]
    assert CALLER_TOKEN not in caplog.text


@pytest.mark.parametrize("path,body", [("/validate", {"files": {}}), ("/health", None)])
def test_per_workload_validate_and_health_stay_open(per_workload, path, body):
    tf_main, _, _ = per_workload
    tf_main.CALLER_TOKEN_VERIFIER = lambda token: pytest.fail("validate / health read a token")
    tf_main.validate_service.validate = MagicMock(return_value={"status": "PASS"})
    c = _client(tf_main)
    r = c.get(path) if body is None else c.post(path, json=body)
    assert r.status_code == 200


@pytest.mark.parametrize("token,claims,status,code", [
    (None, None, 401, "UNAUTHENTICATED"),
    ("x", "raise", 401, "UNAUTHENTICATED"),
    ("x", _claims(iss="https://evil.example"), 401, "UNAUTHENTICATED"),
    ("x", _claims(aud="https://other-service-123.us-central1.run.app"), 401, "UNAUTHENTICATED"),
    ("x", _claims(aud="https://testserver.evil.example/deploy-async"), 401, "UNAUTHENTICATED"),
    ("x", _claims(aud="https://user@testserver/"), 401, "UNAUTHENTICATED"),
    ("x", _claims(aud="http://testserver/"), 401, "UNAUTHENTICATED"),
    ("x", _claims(aud=["https://testserver/"]), 401, "UNAUTHENTICATED"),
    ("x", _claims(email_verified=False), 403, "CALLER_NOT_ALLOWED"),
    ("x", _claims(email=None), 403, "CALLER_NOT_ALLOWED"),
])
def test_per_workload_caller_token_checks(per_workload, token, claims, status, code):
    tf_main, vending, _ = per_workload

    def verifier(t):
        if claims == "raise":
            raise ValueError("bad signature")
        return claims

    tf_main.CALLER_TOKEN_VERIFIER = verifier
    r = _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK}, token=token)
    assert r.status_code == status and r.json()["detail"]["code"] == code
    assert not vending.calls


@pytest.mark.parametrize("account", ["sa-castor-architect", "sa-castor-developer", "sa-stackvend-control-center",
                                     "sa-project-provisioner"])
@pytest.mark.parametrize("aud", ["https://testserver", "https://testserver/", "https://testserver/deploy-async"])
def test_per_workload_default_callers_before_step_a(per_workload, account, aud):
    tf_main, vending, _ = per_workload
    tf_main.CALLER_TOKEN_VERIFIER = lambda t: _claims(email=f"{account}@{HOST}.iam.gserviceaccount.com".upper(),
                                                      aud=aud)
    assert _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK}).status_code == 202


def test_per_workload_terraform_owned_caller_list_wins(monkeypatch, per_workload):
    tf_main, _, _ = per_workload
    monkeypatch.setenv("TF_SERVER_WORKLOAD_CALLERS", f"{fk.SERVER_SA},{ARCHITECT}")
    tf_main.CALLER_TOKEN_VERIFIER = lambda t: _claims(email=fk.DEVELOPER)
    assert _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK}).status_code == 403
    tf_main.CALLER_TOKEN_VERIFIER = lambda t: _claims(email=ARCHITECT)
    assert _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK}).status_code == 202


def test_per_workload_unconfigured_caller_list_refuses(monkeypatch, per_workload):
    tf_main, _, _ = per_workload
    monkeypatch.delenv("PROJECT_ID", raising=False)
    monkeypatch.setenv("TF_SERVER_WORKLOAD_CALLERS", "   ")
    r = _post(tf_main, "/plan", {"product_id": PRODUCT, "hcl_files": {"main.tf": ""}})
    assert r.status_code == 503 and r.json()["detail"]["code"] == "CALLERS_UNCONFIGURED"


@pytest.mark.parametrize("path,body", WORKLOAD_ROUTES)
def test_unknown_mode_refuses_workload_routes(monkeypatch, tf_main, path, body):
    monkeypatch.setenv(MODE, "PER-WORKLOAD")
    r = _post(tf_main, path, body, token=None)
    assert r.status_code == 503 and r.json()["detail"]["error_class"] == "RUNNER_IDENTITY_MODE_INVALID"
    for name in SERVICE_METHODS:
        getattr(tf_main.service, name).assert_not_called()


# ------------------------------------------------------------------------------------------------ pins
def _hcl_platform():
    import hcl2
    locals_, modules = {}, {}
    # The files that declare these identities (tf_runner_identity.tf: step-A code, SAT-33, when on this base).
    for name in ("main.tf", "destructive_guard.tf", "tf_runner_identity.tf"):
        path = os.path.join(REPO, "infra", "platform", name)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            doc = hcl2.load(fh)
        for block in doc.get("locals", []):
            locals_.update(block)
        for block in doc.get("module", []):
            modules.update(block)
    return locals_, modules


def test_default_callers_are_the_platform_terraform_accounts(tf_main):
    """Plan 2.13: the derived list (before step A) is exactly the accounts infra/platform names for the workflow, the
    gateway, the Control Center and vending; when the step-A local exists it names exactly those identities."""
    locals_, modules = _hcl_platform()
    assert modules["workflows"]["orchestrator_service_account_email"] == \
        '${google_service_account.agents["sa-castor-architect"].email}'
    assert locals_["developer_sa_email"] == '${google_service_account.agents["sa-castor-developer"].email}'
    assert locals_["cc_sa_email"] == '${google_service_account.stackvend_personas["sa-stackvend-control-center"].email}'
    assert locals_["vending_sa_key"] == \
        '${var.vending_runs_as_provisioner ? "sa-project-provisioner" : "sa-castor-developer"}'
    assert locals_["vending_sa_email"] == '${google_service_account.agents[local.vending_sa_key].email}'
    assert tf_main.rd.DEFAULT_WORKLOAD_CALLER_ACCOUNTS == (
        "sa-castor-architect", "sa-castor-developer", "sa-stackvend-control-center", "sa-project-provisioner")
    if "tf_server_workload_callers" in locals_:   # step-A code (SAT-33) on this base
        assert locals_["tf_server_workload_callers"] == (
            '${distinct([${google_service_account.agents["sa-castor-architect"].email}, '
            '${local.developer_sa_email}, ${local.cc_sa_email}, ${local.vending_sa_email}])}')
        env = locals_["tf_runner_service_env"]["mcp-terraform-server"]
        assert env["TF_SERVER_WORKLOAD_CALLERS"] == '${join(",", local.tf_server_workload_callers)}'
        assert tf_main.rd.CALLERS_ENV == "TF_SERVER_WORKLOAD_CALLERS"
        assert tf_main.rd.VENDING_URL_ENV in env and tf_main.rd.GUARD_DB_ENV in env


def _calls(tree, dotted):
    return [n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and ast.unparse(n) == dotted]


def test_mode_is_read_only_through_the_shared_function():
    """FD-7L-F4: main.py reads the install mode only through service.install_runner_identity_mode()."""
    for name in ("main.py", "runner_dispatch.py"):
        tree = ast.parse(open(os.path.join(TF_DIR, name), encoding="utf-8").read())
        assert not _calls(tree, "ri.MODE_ENV"), name
        consts = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        assert "STACKVEND_TF_RUNNER_IDENTITY" not in consts, name
    main_tree = ast.parse(open(os.path.join(TF_DIR, "main.py"), encoding="utf-8").read())
    calls = [n.func.id for n in ast.walk(main_tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
    assert "install_runner_identity_mode" in calls          # the runner's one reader (service.py, 2b F5)
    assert not _calls(main_tree, "ri.runner_identity_mode")


def test_runner_dispatch_never_uses_the_platform_identity_helpers():
    tree = ast.parse(open(os.path.join(TF_DIR, "runner_dispatch.py"), encoding="utf-8").read())
    for dotted in ("google.auth.default", "storage.Client", "google.cloud.storage.Client"):
        assert not _calls(tree, dotted)


def test_server_never_handles_a_nonce():
    """The server never sees, reads or forwards the nonce (vending puts it in the execution's env)."""
    for name in ("main.py", "runner_dispatch.py"):
        consts = [n.value for n in ast.walk(ast.parse(open(os.path.join(TF_DIR, name), encoding="utf-8").read()))
                  if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        assert "RUNNER_NONCE" not in consts and "nonce" not in consts, name
