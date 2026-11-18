"""FD vending-redeploy (EXP-8 Opus RT, separate finding; deploy-dispatch Opus RT R2-R4, S3-S5, low).

Project-vending ProjectRepoVendingEngine.redeploy_workload:
    no terraform service URL              -> REDEPLOY_TERRAFORM_UNCONFIGURED (503) BEFORE anything is written or
                                             vended: the workload stays DECOMMISSIONED (R3)
    terraform /deploy HTTP 200            -> ACTIVE with the top-level string `service_url` it reported (R2), never an
                                             invented URL and never the tofu output object
    HTTP 504, or a read/write timeout     -> FAILED REDEPLOY_OUTCOME_UNKNOWN (504)
    a connect/pool timeout, a failed call,
    or no request budget left             -> FAILED REDEPLOY_DEPLOY_CALL_FAILED (502): nothing was sent (S3, S5)
    any other non-200 status              -> FAILED REDEPLOY_DEPLOY_FAILED (502), the string detail kept as a string
Classified by HTTP status / exception type only (a detail text naming another class changes nothing).
Vending resolves the terraform URL itself (env, else Cloud Run lookup of mcp-terraform-server); a caller-supplied
URL is never called and never receives the ID token. The call carries an ID token for the resolved URL (R4). The wait is one deadline: what is left of the 1800 s
request budget minus a margin, never past it (S5).

Control Center /api/workloads/{pid}/redeploy: sends no terraform URL (vending resolves it); writes ACTIVE only on a
vending HTTP 200, with the project id / URL from vending's body only (R2); any other outcome writes nothing and
answers with a typed error_class (vending's passed through; connect/pool timeout = CALL_FAILED, read timeout =
OUTCOME_UNKNOWN (S3); an untyped upstream 401/403 = 502 (low)).

Hermetic: MagicMock Firestore, fake httpx module, stubbed ID-token minting; no cloud client, no network.
"""
import hermetic_guard  # noqa: F401  (first import)

import importlib.util
import os
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VENDING_DIR = os.path.join(REPO_ROOT, "apps", "project-vending")
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
PID = "dormant-api"
TF_URL = "https://mcp-terraform-server-123.example.run.app"


class _Timeout(Exception):
    pass


class _ConnectTimeout(_Timeout):
    pass


class _PoolTimeout(_Timeout):
    pass


class _ReadTimeout(_Timeout):
    pass


class _HxTimeout:
    def __init__(self, total, connect=None):
        self.total, self.connect = total, connect


def _fake_httpx(post=None, raises=None):
    """A stand-in httpx module: Client(timeout=...) context manager whose post() returns `post` or raises."""
    mod = types.ModuleType("httpx")
    mod.TimeoutException, mod.ConnectTimeout, mod.PoolTimeout = _Timeout, _ConnectTimeout, _PoolTimeout
    mod.ReadTimeout, mod.Timeout = _ReadTimeout, _HxTimeout
    calls = []

    class _Client:
        def __init__(self, timeout=None, **kw):
            calls.append({"timeout": timeout})

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json=None, headers=None):
            calls[-1].update({"url": url, "json": json, "headers": headers})
            if raises is not None:
                raise raises
            return post

    mod.Client = _Client
    mod.calls = calls
    return mod


def _resp(status, body=None, text=""):
    r = MagicMock(status_code=status, text=text)
    if isinstance(body, Exception):
        r.json.side_effect = body
    else:
        r.json.return_value = body
    return r


# vending.py imports cloud SDKs at module level, and other test modules replace parts of the `google` namespace in
# sys.modules, so a load at run time can fail on the real SDKs. The code under test never touches them (Firestore,
# CRM and the deploy client are injected; ID-token minting is stubbed), so this file loads its own copy with the SDK
# modules stubbed during the load only; sys.modules is restored afterwards.
_SDK_STUBS = {name: MagicMock() for name in (
    "google.auth", "google.auth.transport", "google.auth.transport.requests", "googleapiclient",
    "googleapiclient.discovery", "googleapiclient.errors", "google.cloud.firestore", "google.cloud.secretmanager",
    "jwt", "github")}


def _load(name, path, extra=None):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    stubs = dict(_SDK_STUBS)
    stubs["google.cloud"] = MagicMock(firestore=stubs["google.cloud.firestore"],
                                      secretmanager=stubs["google.cloud.secretmanager"])
    stubs.update(extra or {})
    with patch.dict(sys.modules, stubs), patch.object(sys, "path", [VENDING_DIR, REPO_ROOT] + sys.path):
        spec.loader.exec_module(mod)
    return mod


_VENDING = _load("vending_redeploy_under_test", os.path.join(VENDING_DIR, "vending.py"))
_VENDING_MAIN = _load("vending_main_redeploy_under_test", os.path.join(VENDING_DIR, "main.py"),
                      extra={"vending": _VENDING})


@pytest.fixture()
def vending(monkeypatch):
    monkeypatch.setenv("GITHUB_OWNER", "example-org")  # FD-4AY: no built-in owner
    mod = _VENDING
    db = MagicMock()
    snap = MagicMock(exists=True)
    snap.to_dict.return_value = {"product_id": PID, "status": "DECOMMISSIONED", "folder_id": "folders/old",
                                 "project_id": "dormant-api-old"}
    db.collection.return_value.document.return_value.get.return_value = snap
    engine = mod.ProjectRepoVendingEngine(platform_project_id="mock-stackvend-project", firestore_client=db,
                                          crm_service=MagicMock(), github_owner="example-org")
    vended = []
    monkeypatch.setattr(engine, "vend_gcp_project",
                        lambda **k: vended.append(k["force_new_project_id"]) or {"project_id": k["force_new_project_id"]})
    ipam = []
    monkeypatch.setattr(engine, "_sync_redeploy_ipam", lambda pid, proj: ipam.append((pid, proj)))
    audiences = []
    monkeypatch.setattr(mod, "_fetch_id_token", lambda aud: audiences.append(aud) or "tok-1")
    monkeypatch.delenv("TERRAFORM_SERVICE_URL", raising=False)
    monkeypatch.delenv("TERRAFORM_MCP_URL", raising=False)
    monkeypatch.setattr(mod, "_CACHED_TERRAFORM_SERVICE_URL", None)
    discovered = []
    monkeypatch.setattr(mod, "_discover_cloud_run_service_url",
                        lambda service, project: discovered.append((service, project)) or None)
    return types.SimpleNamespace(mod=mod, engine=engine, db=db, ipam=ipam, vended=vended, audiences=audiences,
                                 discovered=discovered)


def _run(v, monkeypatch, httpx_mod, tf_url=TF_URL, body_url=None):
    """`tf_url` is what vending resolves itself (TERRAFORM_SERVICE_URL); `body_url` is a caller-supplied URL."""
    monkeypatch.setitem(sys.modules, "httpx", httpx_mod)
    if tf_url is not None:
        monkeypatch.setenv("TERRAFORM_SERVICE_URL", tf_url)
    return v.engine.redeploy_workload(product_id=PID, operator_email="admin@example.com",
                                      terraform_service_url=body_url, target_folder_id="folders/new")


def _workload_writes(db):
    return [c.args[0] for c in db.collection.return_value.document.return_value.set.call_args_list]


def _audit(db):
    return db.collection.return_value.document.return_value.collection.return_value.document.return_value.set


SVC = "https://dormant-api-xyz-uc.a.run.app"
TOFU_OUTPUTS = {"service_url": {"sensitive": False, "type": "string", "value": SVC}}


def test_negative_http_200_is_active_with_the_reported_url(vending, monkeypatch):
    v = vending
    hx = _fake_httpx(post=_resp(200, {"status": "SUCCESS", "service_url": SVC, "outputs": TOFU_OUTPUTS}))
    res = _run(v, monkeypatch, hx)
    assert res["status"] == "ACTIVE" and res["service_url"] == SVC
    writes = _workload_writes(v.db)
    assert [w["status"] for w in writes] == ["REDEPLOYING", "ACTIVE"]
    assert writes[-1]["service_url"] == SVC and writes[-1]["folder_id"] == "folders/new"
    assert _audit(v.db).call_args.args[0]["action"] == "WORKLOAD_REDEPLOYED"
    assert hx.calls[0]["url"] == f"{TF_URL}/deploy" and hx.calls[0]["json"]["product_id"] == PID
    assert v.vended == [res["project_id"]] and v.ipam == [(PID, res["project_id"])]


def test_the_tofu_output_object_is_never_stored_as_the_url(vending, monkeypatch):
    """R2: `outputs.service_url` is the raw tofu output map; only the top-level string is used."""
    v = vending
    res = _run(v, monkeypatch, _fake_httpx(post=_resp(200, {"status": "SUCCESS", "outputs": TOFU_OUTPUTS})))
    assert res["status"] == "ACTIVE" and res["service_url"] is None
    assert _workload_writes(v.db)[-1]["service_url"] is None


@pytest.mark.parametrize("body", [ValueError("not json"), {}, {"service_url": {"value": SVC}}, ["x"]])
def test_negative_200_without_a_string_url_is_active_and_invents_none(vending, monkeypatch, body):
    v = vending
    res = _run(v, monkeypatch, _fake_httpx(post=_resp(200, body)))
    assert res["status"] == "ACTIVE" and res["service_url"] is None
    assert _workload_writes(v.db)[-1]["status"] == "ACTIVE"
    assert all(".a.run.app" not in str(w.get("service_url")) for w in _workload_writes(v.db))


def test_the_call_carries_an_id_token_for_the_terraform_url(vending, monkeypatch):
    v = vending
    hx = _fake_httpx(post=_resp(200, {"service_url": SVC}))
    _run(v, monkeypatch, hx)
    assert v.audiences == [TF_URL] and hx.calls[0]["headers"]["Authorization"] == "Bearer tok-1"


def test_negative_no_token_sends_no_authorization_header(vending, monkeypatch):
    v = vending
    monkeypatch.setattr(v.mod, "_fetch_id_token", lambda aud: None)
    hx = _fake_httpx(post=_resp(200, {"service_url": SVC}))
    assert _run(v, monkeypatch, hx)["status"] == "ACTIVE"
    assert "Authorization" not in hx.calls[0]["headers"]


def _assert_failed(v, res, error_class, http_status=None):
    assert res["status"] == "FAILED" and res["error_class"] == error_class
    assert res["http_status"] == http_status
    assert v.mod.REDEPLOY_FAILURE_HTTP_STATUS[error_class] in (502, 503, 504)
    writes = _workload_writes(v.db)
    assert [w["status"] for w in writes] == ["REDEPLOYING", "FAILED"]
    failed = writes[-1]
    assert failed["redeploy_error_class"] == error_class and failed["failure_reason"].startswith(error_class + ": ")
    assert failed["project_id"] == res["project_id"] and failed["folder_id"] == "folders/new"
    assert failed["redeploy_http_status"] == http_status
    assert "service_url" not in failed  # no invented URL on a failure
    audit = _audit(v.db).call_args.args[0]
    assert audit["action"] == "WORKLOAD_REDEPLOY_FAILED" and audit["error_class"] == error_class
    assert v.ipam == [(PID, res["project_id"])]  # the vended project exists: its CIDRs are tracked either way


@pytest.mark.parametrize("env", [{}, {"TERRAFORM_SERVICE_URL": ""}])
def test_no_terraform_service_vends_and_writes_nothing(vending, monkeypatch, env):
    """R3: refused before the REDEPLOYING write and before any project is vended (nothing billed)."""
    v = vending
    for k, val in env.items():
        monkeypatch.setenv(k, val)
    hx = _fake_httpx(post=_resp(200, {}))
    res = _run(v, monkeypatch, hx, tf_url=None)
    assert res["status"] == "FAILED" and res["error_class"] == "REDEPLOY_TERRAFORM_UNCONFIGURED"
    assert v.mod.REDEPLOY_FAILURE_HTTP_STATUS["REDEPLOY_TERRAFORM_UNCONFIGURED"] == 503
    assert res["project_id"] is None
    assert _workload_writes(v.db) == [] and not _audit(v.db).called
    assert v.vended == [] and v.ipam == [] and hx.calls == []


EVIL = "https://attacker.example.com"


def test_a_caller_supplied_url_is_never_called_and_never_gets_the_token(vending, monkeypatch):
    """Security: vending resolves the terraform service itself; a body URL elsewhere is ignored."""
    v = vending
    hx = _fake_httpx(post=_resp(200, {"service_url": SVC}))
    res = _run(v, monkeypatch, hx, body_url=EVIL)
    assert res["status"] == "ACTIVE"
    assert [c["url"] for c in hx.calls] == [f"{TF_URL}/deploy"] and v.audiences == [TF_URL]


def test_a_caller_supplied_url_cannot_stand_in_for_an_unresolvable_one(vending, monkeypatch):
    v = vending
    hx = _fake_httpx(post=_resp(200, {"service_url": SVC}))
    res = _run(v, monkeypatch, hx, tf_url=None, body_url=EVIL)
    assert res["status"] == "FAILED" and res["error_class"] == "REDEPLOY_TERRAFORM_UNCONFIGURED"
    assert hx.calls == [] and v.audiences == [] and v.vended == [] and _workload_writes(v.db) == []


def test_negative_a_body_url_equal_to_the_resolved_one_changes_nothing(vending, monkeypatch):
    v = vending
    hx = _fake_httpx(post=_resp(200, {"service_url": SVC}))
    assert _run(v, monkeypatch, hx, body_url=TF_URL)["status"] == "ACTIVE"
    assert [c["url"] for c in hx.calls] == [f"{TF_URL}/deploy"] and v.audiences == [TF_URL]


def test_without_env_the_cloud_run_lookup_is_used_and_cached(vending, monkeypatch):
    v = vending
    found = "https://mcp-terraform-server-abc-uc.a.run.app"
    calls = []
    monkeypatch.setattr(v.mod, "_discover_cloud_run_service_url",
                        lambda service, project: calls.append((service, project)) or found)
    hx = _fake_httpx(post=_resp(200, {"service_url": SVC}))
    assert _run(v, monkeypatch, hx, tf_url=None)["status"] == "ACTIVE"
    assert calls == [("mcp-terraform-server", "mock-stackvend-project")]
    assert hx.calls[0]["url"] == f"{found}/deploy" and v.audiences == [found]
    assert v.mod.resolve_terraform_service_url("mock-stackvend-project") == found and len(calls) == 1  # cached


def test_negative_env_url_wins_over_the_lookup(vending, monkeypatch):
    v = vending
    monkeypatch.setenv("TERRAFORM_SERVICE_URL", TF_URL + "/")
    assert v.mod.resolve_terraform_service_url("mock-stackvend-project") == TF_URL and v.discovered == []


def test_the_lookup_off_cloud_run_does_nothing(monkeypatch):
    """No K_SERVICE (not on Cloud Run): no metadata or Admin API call, just None."""
    monkeypatch.delenv("K_SERVICE", raising=False)
    assert _VENDING._discover_cloud_run_service_url("mcp-terraform-server", "mock-stackvend-project") is None


@pytest.mark.parametrize("status", [500, 400, 409, 502, 503, 404, 403])
def test_non_200_is_deploy_failed_and_the_string_detail_stays_a_string(vending, monkeypatch, status):
    v = vending
    detail = "Terraform deployment failed: Error acquiring the state lock"
    res = _run(v, monkeypatch, _fake_httpx(post=_resp(status, {"detail": detail})))
    _assert_failed(v, res, "REDEPLOY_DEPLOY_FAILED", http_status=status)
    assert res["error"] == f"HTTP {status}: {detail}"


def test_http_504_is_outcome_unknown(vending, monkeypatch):
    res = _run(vending, monkeypatch, _fake_httpx(post=_resp(504, None, text="upstream request timeout")))
    _assert_failed(vending, res, "REDEPLOY_OUTCOME_UNKNOWN", http_status=504)


@pytest.mark.parametrize("exc", [_ReadTimeout("read timed out"), _Timeout("write timed out")])
def test_read_or_write_timeout_is_outcome_unknown(vending, monkeypatch, exc):
    res = _run(vending, monkeypatch, _fake_httpx(raises=exc))
    _assert_failed(vending, res, "REDEPLOY_OUTCOME_UNKNOWN")


@pytest.mark.parametrize("exc", [_ConnectTimeout("connect"), _PoolTimeout("pool"), ConnectionError("refused")])
def test_nothing_sent_is_deploy_call_failed(vending, monkeypatch, exc):
    """S3: a connect or pool timeout means the request never left: not an unknown outcome."""
    res = _run(vending, monkeypatch, _fake_httpx(raises=exc))
    _assert_failed(vending, res, "REDEPLOY_DEPLOY_CALL_FAILED")


def test_class_comes_from_the_status_code_not_the_detail_text(vending, monkeypatch):
    body = {"detail": "REDEPLOY_OUTCOME_UNKNOWN timeout SUCCESS ACTIVE"}
    res = _run(vending, monkeypatch, _fake_httpx(post=_resp(500, body)))
    _assert_failed(vending, res, "REDEPLOY_DEPLOY_FAILED", http_status=500)


def test_a_typed_detail_from_deploy_is_recorded_not_classified(vending, monkeypatch):
    """An Agent /deploy dict detail (EXP-8 style) is kept in the message; the class still comes from the status."""
    body = {"detail": {"error_class": "STATE_LOCKED", "error": "locked"}}
    res = _run(vending, monkeypatch, _fake_httpx(post=_resp(500, body)))
    _assert_failed(vending, res, "REDEPLOY_DEPLOY_FAILED", http_status=500)
    assert "STATE_LOCKED" in res["error"]


def _clock(monkeypatch, mod, *values):
    import time as real_time

    it = iter(values)
    monkeypatch.setattr(mod, "time", types.SimpleNamespace(monotonic=lambda: next(it), time=real_time.time,
                                                           sleep=real_time.sleep))


def test_the_deploy_wait_is_the_rest_of_the_request_budget(vending, monkeypatch):
    v = vending
    _clock(monkeypatch, v.mod, 0.0, 300.0)  # vending the project took 300 s
    hx = _fake_httpx(post=_resp(200, {}))
    _run(v, monkeypatch, hx)
    t = hx.calls[0]["timeout"]
    assert t.total == v.mod.REDEPLOY_REQUEST_BUDGET_S - v.mod.REDEPLOY_RECORD_MARGIN_S - 300.0
    assert t.connect == v.mod.REDEPLOY_CONNECT_TIMEOUT_S and t.total > 180.0


@pytest.mark.parametrize("elapsed", [1711.0, 1769.0, 1800.0, 10_000.0])
def test_no_budget_left_sends_nothing_and_records_call_failed(vending, monkeypatch, elapsed):
    """S5: the wait never runs past the deadline (no 30 s floor past it); with too little left nothing is sent."""
    v = vending
    _clock(monkeypatch, v.mod, 0.0, elapsed)
    hx = _fake_httpx(post=_resp(200, {}))
    res = _run(v, monkeypatch, hx)
    assert hx.calls == []
    _assert_failed(v, res, "REDEPLOY_DEPLOY_CALL_FAILED")


def test_negative_just_enough_budget_still_calls_within_the_deadline(vending, monkeypatch):
    v = vending
    remaining = v.mod.REDEPLOY_MIN_DEPLOY_WAIT_S
    _clock(monkeypatch, v.mod, 0.0, v.mod.REDEPLOY_REQUEST_BUDGET_S - v.mod.REDEPLOY_RECORD_MARGIN_S - remaining)
    hx = _fake_httpx(post=_resp(200, {}))
    assert _run(v, monkeypatch, hx)["status"] == "ACTIVE"
    assert hx.calls[0]["timeout"].total == remaining


# ------------------------------------------------------------------------------------------------ vending route
@pytest.fixture()
def vending_route(monkeypatch):
    monkeypatch.setattr(_VENDING_MAIN, "vending_engine", MagicMock())
    return _VENDING_MAIN


@pytest.mark.parametrize("cls, code", [("REDEPLOY_OUTCOME_UNKNOWN", 504), ("REDEPLOY_TERRAFORM_UNCONFIGURED", 503),
                                       ("REDEPLOY_DEPLOY_FAILED", 502), ("REDEPLOY_DEPLOY_CALL_FAILED", 502)])
def test_vending_route_answers_the_typed_failure(vending_route, cls, code):
    HTTPException = vending_route.HTTPException  # the class the route module was loaded with

    vending_route.vending_engine.redeploy_workload = MagicMock(return_value={
        "status": "FAILED", "error_class": cls, "error": "no answer", "product_id": PID,
        "project_id": "dormant-api-abc123", "trace_id": "redeploy-x", "http_status": None})
    with pytest.raises(HTTPException) as ei:
        vending_route.redeploy_project(PID, None)
    assert ei.value.status_code == code
    assert ei.value.detail["error_class"] == cls


def test_negative_vending_route_success_is_unchanged(vending_route):
    ok = {"status": "ACTIVE", "product_id": PID, "project_id": "dormant-api-abc123", "service_url": "https://x"}
    vending_route.vending_engine.redeploy_workload = MagicMock(return_value=dict(ok))
    assert vending_route.redeploy_project(PID, None) == ok


def test_vending_route_passes_the_terraform_url_through(vending_route):
    vending_route.vending_engine.redeploy_workload = MagicMock(return_value={"status": "ACTIVE"})
    vending_route.redeploy_project(PID, vending_route.RedeployProjectRequest(terraform_service_url=TF_URL))
    assert vending_route.vending_engine.redeploy_workload.call_args.kwargs["terraform_service_url"] == TF_URL


# ------------------------------------------------------------------------------------------------ vend step raises
# VENDING-CLIENT-FAIL-LOUD gap 4: a vend that raises used to leave the workload REDEPLOYING forever.
def _vend_raises(v, monkeypatch, err):
    def _raise(**k):
        v.vended.append(k["force_new_project_id"])
        raise err
    monkeypatch.setattr(v.engine, "vend_gcp_project", _raise)


def _assert_vend_failed(v, error_class, hx):
    writes = _workload_writes(v.db)
    assert [w["status"] for w in writes] == ["REDEPLOYING", "FAILED"]
    failed = writes[-1]
    assert failed["redeploy_error_class"] == failed["vending_error_class"] == error_class
    assert failed["failure_reason"].startswith(error_class + ": ") and failed["redeploy_stage"] == "vending"
    assert "service_url" not in failed
    audit = _audit(v.db).call_args.args[0]
    assert audit["action"] == "WORKLOAD_REDEPLOY_FAILED" and audit["error_class"] == error_class
    assert audit["stage"] == "vending" and audit["new_project_id"] == v.vended[0]
    assert hx.calls == [] and v.ipam == []   # nothing deployed, no CIDRs tracked for a project that may not exist


def test_vend_failure_records_the_typed_class_and_is_raised_unchanged(vending, monkeypatch):
    v = vending
    err = v.mod.VendingFailure("BILLING_NOT_LINKED", "Billing account 'x' could not be linked.")
    _vend_raises(v, monkeypatch, err)
    hx = _fake_httpx(post=_resp(200, {}))
    with pytest.raises(v.mod.VendingFailure) as ei:
        _run(v, monkeypatch, hx)
    assert ei.value is err
    _assert_vend_failed(v, "BILLING_NOT_LINKED", hx)


def test_untyped_vend_error_is_recorded_as_redeploy_vend_failed(vending, monkeypatch):
    v = vending
    _vend_raises(v, monkeypatch, RuntimeError("CHILD_OWNER_GRANT_FAILED secret-ish text"))
    hx = _fake_httpx(post=_resp(200, {}))
    with pytest.raises(RuntimeError, match="CHILD_OWNER_GRANT_FAILED"):
        _run(v, monkeypatch, hx)
    _assert_vend_failed(v, "REDEPLOY_VEND_FAILED", hx)
    assert _workload_writes(v.db)[-1]["failure_reason"] == "REDEPLOY_VEND_FAILED: RuntimeError"


def test_a_failed_record_write_never_replaces_the_vend_failure(vending, monkeypatch):
    v = vending
    err = v.mod.VendingFailure("VENDING.RESOURCE_MANAGER_CLIENT_UNAVAILABLE", "no client")
    _vend_raises(v, monkeypatch, err)
    doc = v.db.collection.return_value.document.return_value
    doc.set.side_effect = [None, RuntimeError("503 writing")]   # REDEPLOYING lands, the FAILED write fails
    with pytest.raises(v.mod.VendingFailure) as ei:
        _run(v, monkeypatch, _fake_httpx(post=_resp(200, {})))
    assert ei.value is err


# RT 11-07 F1: a vend that could not start leaves the workload DECOMMISSIONED (no REDEPLOYING write, nothing vended).
def _redeploy(v, monkeypatch, target_folder_id="folders/new"):
    monkeypatch.setitem(sys.modules, "httpx", _fake_httpx(post=_resp(200, {})))
    monkeypatch.setenv("TERRAFORM_SERVICE_URL", TF_URL)
    return v.engine.redeploy_workload(product_id=PID, operator_email="admin@example.com",
                                      target_folder_id=target_folder_id)


def _assert_nothing_started(v):
    assert v.vended == [] and v.ipam == []
    assert _workload_writes(v.db) == [] and not _audit(v.db).called


def test_redeploy_without_a_resource_manager_client_leaves_it_decommissioned(vending, monkeypatch):
    v = vending
    v.engine._crm = None

    def _no_client(service, version):
        raise RuntimeError("no credentials")

    monkeypatch.setattr(v.mod, "_build_thread_safe", _no_client)
    with pytest.raises(v.mod.VendingFailure) as ei:
        _redeploy(v, monkeypatch)
    assert ei.value.error_class == "VENDING.RESOURCE_MANAGER_CLIENT_UNAVAILABLE" and ei.value.http_status == 503
    _assert_nothing_started(v)


def test_redeploy_without_a_firestore_client_reads_and_writes_nothing(vending, monkeypatch):
    v = vending
    v.engine._db, v.engine.platform_project_id = None, ""
    with pytest.raises(v.mod.VendingFailure) as ei:
        _redeploy(v, monkeypatch)
    assert ei.value.error_class == "VENDING.FIRESTORE_CLIENT_UNAVAILABLE"
    _assert_nothing_started(v)
    assert not v.db.collection.called


def test_redeploy_without_a_parent_folder_leaves_it_decommissioned(vending, monkeypatch):
    v = vending
    v.engine.folder_id = ""
    v.db.collection.return_value.document.return_value.get.return_value.to_dict.return_value = {
        "product_id": PID, "status": "DECOMMISSIONED", "project_id": "dormant-api-old"}
    with pytest.raises(v.mod.VendingFailure) as ei:
        _redeploy(v, monkeypatch, target_folder_id=None)
    assert ei.value.error_class == "VENDING.PARENT_FOLDER_UNCONFIGURED" and "DECOMMISSIONED" in ei.value.detail
    _assert_nothing_started(v)


def test_negative_redeploy_with_the_record_folder_only_still_vends(vending, monkeypatch):
    v = vending
    v.engine.folder_id = ""
    assert _redeploy(v, monkeypatch, target_folder_id=None)["status"] == "ACTIVE"   # record names folders/old
    assert len(v.vended) == 1


# RT 11-07 F3: an unreadable record stops the redeploy typed; an unknown workload is refused.
def test_redeploy_with_an_unreadable_record_is_typed_and_writes_nothing(vending, monkeypatch):
    v = vending
    v.db.collection.return_value.document.return_value.get.side_effect = RuntimeError("503 reading")
    with pytest.raises(v.mod.VendingFailure) as ei:
        _redeploy(v, monkeypatch)
    assert ei.value.error_class == "VENDING.WORKLOAD_RECORD_UNREADABLE" and "RuntimeError" in ei.value.detail
    assert "503 reading" not in ei.value.detail
    _assert_nothing_started(v)


def test_redeploy_of_an_unknown_workload_is_refused(vending, monkeypatch):
    v = vending
    v.db.collection.return_value.document.return_value.get.return_value.exists = False
    with pytest.raises(ValueError, match="does not exist"):
        _redeploy(v, monkeypatch)
    _assert_nothing_started(v)


def test_vending_route_answers_a_vend_failure_typed(vending_route):
    HTTPException = vending_route.HTTPException
    vending_route.vending_engine.redeploy_workload = MagicMock(
        side_effect=vending_route.VendingFailure("VENDING.PARENT_FOLDER_UNCONFIGURED", "no parent folder"))
    with pytest.raises(HTTPException) as ei:
        vending_route.redeploy_project(PID, None)
    assert ei.value.status_code == 503   # RT 11-07 F4: a configuration class
    assert ei.value.detail == {"error_class": "VENDING.PARENT_FOLDER_UNCONFIGURED", "stage": "vending",
                               "detail": "no parent folder"}


# ------------------------------------------------------------------------------------------------ CC route
def _cc(monkeypatch, vending_result=None, vending_exc=None, tf_url=TF_URL):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl

    monkeypatch.setattr(cc_db, "_db_client", False)
    db = MagicMock()
    snap = MagicMock(exists=True)
    snap.to_dict.return_value = {"product_id": PID, "status": "DECOMMISSIONED"}
    db.collection.return_value.document.return_value.get.return_value = snap
    monkeypatch.setattr(wl, "db", db)
    monkeypatch.setattr(wl, "verify_admin_access", lambda *a, **k: None)
    monkeypatch.setattr(wl, "get_caller_main_module", lambda: None)
    monkeypatch.setattr(wl, "get_terraform_service_url", lambda request=None: tf_url)
    _settings_maintenance_off(monkeypatch, wl)
    vend = MagicMock()
    if vending_exc is not None:
        vend.side_effect = vending_exc
    else:
        vend.return_value = vending_result
    monkeypatch.setattr(wl, "make_vending_request", vend)
    monkeypatch.setitem(sys.modules, "httpx", _fake_httpx())
    return wl, db, vend


def _settings_maintenance_off(monkeypatch, module):
    """settings-toggles ST-1: the route reads platform settings strictly (maintenance mode) before any side effect.
    Serve the compile-time defaults (maintenance off) so these tests exercise the dispatch / redeploy paths."""
    from routes.settings import PlatformSettings

    defaults = PlatformSettings()
    assert defaults.governance.maintenance_mode is False
    monkeypatch.setattr(module, "get_platform_settings", lambda *a, **k: defaults)


def _cc_redeploy(wl):
    from fastapi import HTTPException

    request = MagicMock()
    request.state.user_email = "admin@example.com"
    try:
        return wl.redeploy_workload_endpoint(PID, request, None)
    except HTTPException as he:
        return he


def _cc_writes(db):
    return db.collection.return_value.document.return_value.set.call_args_list


def test_negative_cc_vending_200_is_active_unchanged(monkeypatch):
    wl, db, vend = _cc(monkeypatch, _resp(200, {"status": "ACTIVE", "project_id": "dormant-api-abc123",
                                                "service_url": SVC}))
    out = _cc_redeploy(wl)
    assert out.status == "ACTIVE" and out.new_project_id == "dormant-api-abc123" and out.service_url == SVC
    written = _cc_writes(db)[-1].args[0]
    assert written["status"] == "ACTIVE" and written["project_id"] == "dormant-api-abc123"
    assert written["service_url"] == SVC
    assert vend.call_args.kwargs["path"] == f"/projects/{PID}/redeploy"


def test_cc_never_sends_a_terraform_url_to_vending(monkeypatch):
    """Vending resolves the terraform service itself; the CC does not pass one."""
    wl, db, vend = _cc(monkeypatch, _resp(200, {"project_id": "p-1", "service_url": SVC}))
    _cc_redeploy(wl)
    assert "terraform_service_url" not in vend.call_args.kwargs["json_body"]


@pytest.mark.parametrize("body", [ValueError("not json"), {}, {"project_id": {"x": 1}, "service_url": TOFU_OUTPUTS}])
def test_cc_never_invents_a_project_or_url_on_a_200(monkeypatch, body):
    """R2: values only from vending's body; a missing one leaves vending's own record untouched (no 500 either)."""
    wl, db, _ = _cc(monkeypatch, _resp(200, body))
    out = _cc_redeploy(wl)
    assert out.status == "ACTIVE" and out.new_project_id is None and out.service_url is None
    written = _cc_writes(db)[-1].args[0]
    assert written["status"] == "ACTIVE" and "project_id" not in written and "service_url" not in written


@pytest.mark.parametrize("status, cls", [(504, "REDEPLOY_OUTCOME_UNKNOWN"), (502, "REDEPLOY_DEPLOY_FAILED"),
                                         (503, "REDEPLOY_TERRAFORM_UNCONFIGURED")])
def test_cc_passes_the_vending_typed_failure_through_and_writes_nothing(monkeypatch, status, cls):
    detail = {"error_class": cls, "detail": "x", "product_id": PID, "project_id": "dormant-api-abc123"}
    wl, db, _ = _cc(monkeypatch, _resp(status, {"detail": detail}))
    out = _cc_redeploy(wl)
    assert out.status_code == status and out.detail == detail
    assert _cc_writes(db) == []


# RT 11-07 F2: dotted VENDING.* classes reach the operator (str.isidentifier() used to drop them).
@pytest.mark.parametrize("status, cls", [(503, "VENDING.PARENT_FOLDER_UNCONFIGURED"),
                                         (503, "VENDING.RESOURCE_MANAGER_CLIENT_UNAVAILABLE"),
                                         (502, "VENDING.WORKLOAD_RECORD_UNREADABLE"), (502, "BILLING_NOT_LINKED")])
def test_cc_passes_a_dotted_vending_class_through(monkeypatch, status, cls):
    detail = {"error_class": cls, "stage": "vending", "detail": "x"}
    wl, db, _ = _cc(monkeypatch, _resp(status, {"detail": detail}))
    out = _cc_redeploy(wl)
    assert out.status_code == status and out.detail == detail
    assert _cc_writes(db) == []


@pytest.mark.parametrize("bad", ["", "VENDING.", ".X", "VENDING..X", "A B", "1X", "VENDING.X-Y", None, 7])
def test_negative_cc_malformed_class_is_still_redeploy_failed(monkeypatch, bad):
    wl, db, _ = _cc(monkeypatch, _resp(502, {"detail": {"error_class": bad, "detail": "x"}}))
    out = _cc_redeploy(wl)
    assert out.status_code == 502 and out.detail["error_class"] == "REDEPLOY_FAILED"


def test_cc_express_readers_keep_a_dotted_class(monkeypatch):
    wl, _, _ = _cc(monkeypatch)
    body = {"detail": {"error_class": "VENDING.PARENT_FOLDER_UNCONFIGURED", "detail": "no folder"}}
    vend = wl._express_vending_failure(_resp(503, body))
    assert vend == {"error_class": "VENDING.PARENT_FOLDER_UNCONFIGURED", "http_status": 503, "error": "no folder"}
    tf = wl._express_deploy_failure(_resp(500, {"detail": {"error_class": "TF.SOME_CLASS", "error": "e"}}))
    assert tf["error_class"] == "TF.SOME_CLASS"
    # negative: a malformed class is still untyped on both readers
    assert wl._express_vending_failure(_resp(502, {"detail": {"error_class": "A B"}})) is None
    assert wl._express_deploy_failure(_resp(500, {"detail": {"error_class": "A."}}))["error_class"] == \
        "EXPRESS_DEPLOY_FAILED"


def test_cc_untyped_vending_error_is_redeploy_failed(monkeypatch):
    wl, db, _ = _cc(monkeypatch, _resp(400, {"detail": "Only DECOMMISSIONED workloads can be redeployed."}))
    out = _cc_redeploy(wl)
    assert out.status_code == 400 and out.detail["error_class"] == "REDEPLOY_FAILED"
    assert out.detail["detail"] == "Only DECOMMISSIONED workloads can be redeployed."
    assert _cc_writes(db) == []


@pytest.mark.parametrize("status", [401, 403])
def test_cc_untyped_upstream_auth_refusal_is_502_not_the_operators(monkeypatch, status):
    wl, db, _ = _cc(monkeypatch, _resp(status, {"detail": "Forbidden"}))
    out = _cc_redeploy(wl)
    assert out.status_code == 502 and out.detail["error_class"] == "REDEPLOY_FAILED"
    assert out.detail["http_status"] == status and _cc_writes(db) == []


def test_cc_no_vending_service_is_unavailable_not_a_fabricated_active(monkeypatch):
    wl, db, _ = _cc(monkeypatch, None)
    out = _cc_redeploy(wl)
    assert out.status_code == 503 and out.detail["error_class"] == "REDEPLOY_VENDING_UNAVAILABLE"
    assert _cc_writes(db) == []


@pytest.mark.parametrize("exc", [_ReadTimeout("read timed out"), _Timeout("write timed out")])
def test_cc_vending_read_timeout_is_outcome_unknown(monkeypatch, exc):
    wl, db, _ = _cc(monkeypatch, vending_exc=exc)
    out = _cc_redeploy(wl)
    assert out.status_code == 504 and out.detail["error_class"] == "REDEPLOY_OUTCOME_UNKNOWN"
    assert _cc_writes(db) == []


@pytest.mark.parametrize("exc", [_ConnectTimeout("connect"), _PoolTimeout("pool"), ConnectionError("refused")])
def test_cc_vending_not_sent_is_call_failed(monkeypatch, exc):
    wl, db, _ = _cc(monkeypatch, vending_exc=exc)
    out = _cc_redeploy(wl)
    assert out.status_code == 502 and out.detail["error_class"] == "REDEPLOY_VENDING_CALL_FAILED"
    assert _cc_writes(db) == []


def test_dashboard_shows_outcome_unknown_as_still_running():
    """S4: keyed on error_class, an info toast, and the workload list is refreshed."""
    with open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8") as f:
        html = f.read()
    i = html.index("d.error_class === 'REDEPLOY_OUTCOME_UNKNOWN'")
    branch = html[i:i + 600]
    assert "'info'" in branch and "this.fetchWorkloads()" in branch


# ------------------------------------------------------------------------------------------------ SAT-38
# redeploy records and deploys the project vending actually created. After a 409 + 403/404, vend_gcp_project creates a
# fallback id, and the workload used to be recorded (ACTIVE / FAILED), deployed to, IPAM-synced and reported under the
# requested id, which then names no project.
FALLBACK = "dormant-api-f00bar"


def _vend_fallback(v, monkeypatch, result):
    requested = []
    monkeypatch.setattr(v.engine, "vend_gcp_project", lambda **k: requested.append(k["force_new_project_id"]) or result)
    secrets = []
    monkeypatch.setattr(v.engine, "_write_deploy_secrets", lambda pid, data, proj, **kw: secrets.append(proj) or True)
    return requested, secrets


def test_redeploy_records_and_deploys_the_vended_fallback_project(vending, monkeypatch):
    v = vending
    requested, secrets = _vend_fallback(v, monkeypatch, {"project_id": FALLBACK})
    hx = _fake_httpx(post=_resp(200, {"status": "SUCCESS", "service_url": SVC}))
    res = _run(v, monkeypatch, hx)
    assert requested and requested[0] != FALLBACK
    assert res["status"] == "ACTIVE" and res["project_id"] == FALLBACK and FALLBACK in res["message"]
    assert _workload_writes(v.db)[-1]["project_id"] == FALLBACK
    assert _audit(v.db).call_args.args[0]["new_project_id"] == FALLBACK
    assert hx.calls[0]["json"]["target_project_id"] == FALLBACK
    assert secrets == [FALLBACK] and v.ipam == [(PID, FALLBACK)]


def test_failed_redeploy_records_the_vended_fallback_project(vending, monkeypatch):
    v = vending
    _vend_fallback(v, monkeypatch, {"project_id": FALLBACK})
    res = _run(v, monkeypatch, _fake_httpx(post=_resp(500, {"detail": "boom"})))
    assert res["status"] == "FAILED" and res["project_id"] == FALLBACK
    assert _workload_writes(v.db)[-1]["status"] == "FAILED" and _workload_writes(v.db)[-1]["project_id"] == FALLBACK
    assert v.ipam == [(PID, FALLBACK)]


@pytest.mark.parametrize("result", [None, {}, {"project_id": ""}, {"project_id": 7}, "not-a-dict"])
def test_negative_vend_result_without_a_project_id_keeps_the_requested_id(vending, monkeypatch, result):
    """Unchanged: only a real (non-empty string) vended id replaces the requested one."""
    v = vending
    requested, secrets = _vend_fallback(v, monkeypatch, result)
    hx = _fake_httpx(post=_resp(200, {"status": "SUCCESS", "service_url": SVC}))
    res = _run(v, monkeypatch, hx)
    assert res["project_id"] == requested[0] and hx.calls[0]["json"]["target_project_id"] == requested[0]
    assert _workload_writes(v.db)[-1]["project_id"] == requested[0] and secrets == requested


def test_negative_vended_id_equal_to_requested_is_unchanged(vending, monkeypatch):
    v = vending
    hx = _fake_httpx(post=_resp(200, {"status": "SUCCESS", "service_url": SVC}))
    res = _run(v, monkeypatch, hx)
    writes = _workload_writes(v.db)
    assert writes[0]["status"] == "REDEPLOYING" and writes[0]["project_id"] == res["project_id"] == v.vended[0]
    assert writes[-1]["project_id"] == v.vended[0] and hx.calls[0]["json"]["target_project_id"] == v.vended[0]
