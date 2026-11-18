"""FD-4L / FD27-05: mcp-gcloud-server typed tools (lane 14 plan §3.1; rows L14-g inspection, L14-o ops).

Hermetic: the server modules are loaded by path; the Firestore ledger and the Google REST session are in-memory
fakes (no credentials, no network). Negatives first: free-form commands, the host project, another workload's
project, filter injection, scale-to-zero, audit failure, missing credentials.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import base64
import copy
import json
import os
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GC_DIR = os.path.join(REPO, "mcp-servers", "gcloud")
sys.path.insert(0, os.path.dirname(__file__))

HOST = "host-platform"
CHILD = "claims-child-123"
OTHER = "other-child-9"
NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
SVC_URL = f"https://run.googleapis.com/v2/projects/{CHILD}/locations/us-east4/services/claims-api"


# ----------------------------------------------------------------------------------------------- fakes
class _Snap:
    def __init__(self, doc_id, data):
        self.id, self._d, self.exists = doc_id, data, data is not None

    def to_dict(self):
        return copy.deepcopy(self._d)


class _Doc:
    def __init__(self, db, path):
        self.db, self.path = db, path

    def get(self):
        return _Snap(self.path.split("/")[-1], self.db.store.get(self.path))

    def set(self, data, merge=False):
        if self.db.fail_writes:
            raise RuntimeError("firestore down")
        self.db.events.append(("audit", self.path, data.get("status")))
        base = dict(self.db.store.get(self.path) or {}) if merge else {}
        base.update(copy.deepcopy(data))
        self.db.store[self.path] = base


class _Coll:
    def __init__(self, db, name, flt=None):
        self.db, self.name, self.flt = db, name, flt

    def where(self, filter=None):  # noqa: A002
        return _Coll(self.db, self.name, filter)

    def limit(self, n):
        return self

    def stream(self):
        return [_Snap(k.split("/", 1)[1], v) for k, v in sorted(self.db.store.items())
                if k.startswith(self.name + "/") and (self.flt is None or v.get(self.flt[0]) == self.flt[1])]

    def document(self, doc_id):
        return _Doc(self.db, f"{self.name}/{doc_id}")


class FakeDB:
    def __init__(self, events):
        self.events, self.fail_writes = events, False
        self.store = {"workloads/claims": {"status": "ACTIVE", "project_id": CHILD},
                      "workloads/other": {"status": "ACTIVE", "project_id": OTHER},
                      "workloads/hosty": {"status": "ACTIVE", "project_id": HOST}}

    def collection(self, name):
        return _Coll(self, name)


class _Resp:
    def __init__(self, status, payload):
        self.status_code, self._payload = status, payload

    def json(self):
        if self._payload is None:
            raise ValueError("no body")
        return self._payload


class FakeSession:
    def __init__(self, events):
        self.events, self.routes, self.calls = events, {}, []

    def request(self, method, url, params=None, json=None, timeout=None):  # noqa: A002
        self.calls.append((method, url, copy.deepcopy(params), copy.deepcopy(json)))
        self.events.append(("http", method, url))
        status, payload = self.routes.get((method, url), (404, {"error": {"message": "not found"}}))
        return _Resp(status, payload)


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


SIGNED = "valid-google-signature"


def _token(email, signature=SIGNED, alg="RS256"):
    return f"Bearer {_b64({'alg': alg})}.{_b64({'email': email, 'aud': 'https://mcp-gcloud-server.test'})}.{signature}"


def fake_verifier(token):
    """Stands in for google.oauth2.id_token.verify_token: only tokens carrying the fake Google signature verify."""
    header, payload, signature = token.split(".")
    if signature != SIGNED:
        raise ValueError("Could not verify token signature.")
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


@pytest.fixture()
def gc(monkeypatch):
    from fastapi.testclient import TestClient

    from fd4g_support import load_module, real_modules

    real_modules(monkeypatch)
    seam = load_module(monkeypatch, "managed_target_seam", os.path.join(GC_DIR, "managed_target_seam.py"))
    monkeypatch.setattr(seam, "_field_filter", lambda field, value: (field, value))
    executor_mod = load_module(monkeypatch, "executor", os.path.join(GC_DIR, "executor.py"))
    main = load_module(monkeypatch, "fd4l_gcloud_main", os.path.join(GC_DIR, "main.py"))
    events = []
    db, session = FakeDB(events), FakeSession(events)
    ex = executor_mod.GcloudExecutor(db_factory=lambda: db, session_factory=lambda: session,
                                     env={"PROJECT_ID": HOST}, clock=lambda: NOW, caller_verifier=fake_verifier)
    monkeypatch.setattr(main, "executor", ex)
    session.routes[("GET", SVC_URL)] = (200, {
        "name": SVC_URL.split("/v2/")[1], "latestReadyRevision": "claims-api-00002-abc",
        "template": {"scaling": {"minInstanceCount": 0, "maxInstanceCount": 5}, "annotations": {"team": "claims"}},
        "traffic": [{"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST", "percent": 100}]})
    session.routes[("GET", SVC_URL + "/revisions")] = (200, {"revisions": [
        {"name": SVC_URL.split("/v2/")[1] + "/revisions/claims-api-00001-xyz"},
        {"name": SVC_URL.split("/v2/")[1] + "/revisions/claims-api-00002-abc"}]})
    session.routes[("PATCH", SVC_URL)] = (200, {"name": "projects/x/locations/us-east4/operations/op-1"})
    return SimpleNamespace(main=main, ex=ex, mod=executor_mod, db=db, session=session, events=events,
                           client=TestClient(main.app))


SERVICE = dict(product_id="claims", region="us-east4", service="claims-api")


def _audits(gc):
    return {k: v for k, v in gc.db.store.items() if k.startswith("gcloud_mcp_ops/")}


# ----------------------------------------------------------------------------------------------- free-form refused
@pytest.mark.parametrize("command", ["projects  delete victim-proj --quiet", "run services list",
                                     "projects add-iam-policy-binding p --member=user:x --role=roles/owner",
                                     "secrets versions access latest --secret=github-app-key"])
def test_free_form_command_on_exec_is_refused_with_zero_calls(gc, command):
    r = gc.client.post("/exec", json={"command": command, "project_id": CHILD})
    assert r.status_code == 422
    assert gc.session.calls == [] and _audits(gc) == {}
    r = gc.client.post("/exec", json={"command": command})
    assert r.status_code == 422 and r.json()["detail"]["status"] == "FREE_FORM_COMMAND_REFUSED"


def test_mcp_exec_gcloud_command_is_refused(gc):
    r = gc.client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "exec_gcloud_command", "arguments": {"command": "projects  delete victim-proj --quiet"}}}).json()
    assert "result" not in r and r["error"]["data"]["status"] == "FREE_FORM_COMMAND_REFUSED"
    assert gc.session.calls == []


def test_unknown_tool_and_bad_args_are_typed_refusals(gc):
    r = gc.client.post("/exec", json={"tool": "delete_project", "args": {"product_id": "claims"}})
    assert r.status_code == 422 and r.json()["detail"]["status"] == "UNKNOWN_TOOL"
    r = gc.client.post("/exec", json={"tool": "get_cloud_run_service", "args": {"region": "us-east4", "service": "a"}})
    assert r.status_code == 422 and r.json()["detail"]["status"] == "ARGS_INVALID"  # product_id missing
    r = gc.client.post("/exec", json={"tool": "get_cloud_run_service", "args": dict(SERVICE, command="x")})
    assert r.status_code == 422 and r.json()["detail"]["status"] == "ARGS_INVALID"
    assert gc.session.calls == []


# ----------------------------------------------------------------------------------------------- target
TOOL_ARGS = {
    "get_cloud_run_service": dict(region="us-east4", service="claims-api"),
    "list_cloud_run_services": dict(region="us-east4"),
    "get_project_iam_policy": {},
    "list_service_accounts": {},
    "query_logs": dict(severity="ERROR"),
    "update_cloud_run_scaling": dict(region="us-east4", service="claims-api", min_instance_count=0,
                                     max_instance_count=3),
    "update_cloud_run_traffic": dict(region="us-east4", service="claims-api", traffic={"claims-api-00001-xyz": 100}),
    "restart_cloud_run_service": dict(region="us-east4", service="claims-api"),
}


@pytest.mark.parametrize("tool", sorted(TOOL_ARGS))
@pytest.mark.parametrize("product_id,project_id,code", [
    ("hosty", None, "REFUSED:HOST_PROJECT"),          # the ledger points at the host project
    ("claims", HOST, "REFUSED:TARGET_MISMATCH"),      # the request names the host project
    ("claims", OTHER, "REFUSED:TARGET_MISMATCH"),     # the request names another workload's project
    ("missing", None, "REFUSED:LEDGER_MISSING"),      # no ledger record: no PROJECT_ID default
])
def test_every_tool_targets_only_the_workload_ledger_project(gc, tool, product_id, project_id, code):
    args = dict(TOOL_ARGS[tool], product_id=product_id)
    if project_id is not None:
        args["project_id"] = project_id
    with pytest.raises(gc.mod.GcloudRefused) as exc:
        gc.ex.run_tool(tool, args)
    assert exc.value.code == code and exc.value.http_status == 403
    assert gc.session.calls == [] and _audits(gc) == {}


def test_inspection_reads_the_workload_project_by_rest(gc):
    res = gc.ex.run_tool("get_cloud_run_service", dict(SERVICE))
    assert res["status"] == "OK" and res["project_id"] == CHILD
    assert gc.session.calls == [("GET", SVC_URL, None, None)]
    gc.session.routes[("POST", f"https://cloudresourcemanager.googleapis.com/v3/projects/{CHILD}:getIamPolicy")] = (
        200, {"bindings": []})
    assert gc.ex.run_tool("get_project_iam_policy", {"product_id": "claims"})["policy"] == {"bindings": []}


def test_list_follows_pages(gc):
    url = f"https://iam.googleapis.com/v1/projects/{CHILD}/serviceAccounts"
    gc.session.routes[("GET", url)] = (200, {"accounts": [{"email": "a@x"}]})
    res = gc.ex.list_service_accounts(product_id="claims")
    assert res["accounts"] == [{"email": "a@x"}]


# ----------------------------------------------------------------------------------------------- query_logs
@pytest.mark.parametrize("field,value,code", [
    ("service_name", 'api" OR logName:*', "SERVICE_NAME_INVALID"),
    ("service_name", "--impersonate-service-account=sa@x", "SERVICE_NAME_INVALID"),
    ("service_name", "API", "SERVICE_NAME_INVALID"),
    ("severity", "ERROR --project=other-proj", "SEVERITY_INVALID"),
    ("resource_type", 'cloud_run_revision" OR "1"="1', "RESOURCE_TYPE_INVALID"),
    ("since", '2026-10-01T00:00:00Z" OR "', "SINCE_INVALID"),
    ("since", "2026-10-01T00:00:00", "SINCE_INVALID"),
    ("limit", 100000, "LIMIT_INVALID"),
    ("limit", True, "LIMIT_INVALID"),
])
def test_query_logs_fields_are_typed_and_injection_is_refused(gc, field, value, code):
    args = {"product_id": "claims", "resource_type": "cloud_run_revision", field: value}
    with pytest.raises(gc.mod.GcloudRefused) as exc:
        gc.ex.run_tool("query_logs", args)
    assert exc.value.code == code and exc.value.http_status == 422 and gc.session.calls == []


def test_query_logs_negative_valid_fields_build_the_exact_filter(gc):
    gc.session.routes[("POST", "https://logging.googleapis.com/v2/entries:list")] = (200, {"entries": [{"x": 1}]})
    res = gc.ex.query_logs(product_id="claims", severity="ERROR", resource_type="cloud_run_revision",
                           service_name="claims-api", since="2026-10-17T00:00:00Z", limit=20)
    assert res["filter"] == ('resource.type="cloud_run_revision" AND resource.labels.service_name="claims-api" '
                             'AND severity>=ERROR AND timestamp>="2026-10-17T00:00:00+00:00"')
    method, url, params, body = gc.session.calls[0]
    assert body == {"resourceNames": [f"projects/{CHILD}"], "orderBy": "timestamp desc", "pageSize": 20,
                    "filter": res["filter"]}
    assert res["entries"] == [{"x": 1}]


def test_logs_route_rejects_the_old_free_form_filter_field(gc):
    r = gc.client.post("/logs", json={"product_id": "claims", "filter_query": "severity>=ERROR"})
    assert r.status_code == 422 and gc.session.calls == []


# ----------------------------------------------------------------------------------------------- ops
@pytest.mark.parametrize("mn,mx,code", [
    (0, 0, "QUARANTINE_IS_ENFORCER_ONLY"),
    (0, 10000, "SCALING_INVALID"),
    (5, 2, "SCALING_INVALID"),
    (-1, 2, "SCALING_INVALID"),
    (True, 2, "SCALING_INVALID"),
])
def test_scaling_bounds_and_scale_to_zero_are_refused_before_any_call(gc, mn, mx, code):
    with pytest.raises(gc.mod.GcloudRefused) as exc:
        gc.ex.update_cloud_run_scaling(**SERVICE, min_instance_count=mn, max_instance_count=mx)
    assert exc.value.code == code and exc.value.http_status == 422
    assert gc.session.calls == [] and _audits(gc) == {}


def test_scaling_writes_the_audit_entry_before_the_cloud_run_call(gc):
    r = gc.client.post("/exec", headers={"Authorization": _token("sre-agent@host.iam.gserviceaccount.com")},
                       json={"tool": "update_cloud_run_scaling",
                             "args": dict(SERVICE, min_instance_count=1, max_instance_count=4, caller="spoofed@x")})
    assert r.status_code == 200 and r.json()["status"] == "SUBMITTED"
    kinds = [e[0] + ":" + (e[1] if e[0] == "http" else str(e[2])) for e in gc.events]
    assert kinds == ["http:GET", "audit:PENDING", "http:PATCH", "audit:SUBMITTED"]
    method, url, params, body = gc.session.calls[-1]
    assert params == {"updateMask": "template.scaling.minInstanceCount,template.scaling.maxInstanceCount"}
    assert body == {"template": {"scaling": {"minInstanceCount": 1, "maxInstanceCount": 4}}}
    (audit,) = _audits(gc).values()
    assert audit["caller"] == "sre-agent@host.iam.gserviceaccount.com"  # from the verified token, not args
    assert audit["before"] == {"minInstanceCount": 0, "maxInstanceCount": 5} and audit["project_id"] == CHILD


def test_audit_write_failure_refuses_the_op_with_no_cloud_run_mutation(gc):
    gc.db.fail_writes = True
    for tool, extra in (("update_cloud_run_scaling", dict(min_instance_count=0, max_instance_count=3)),
                        ("update_cloud_run_traffic", dict(traffic={"claims-api-00002-abc": 100})),
                        ("restart_cloud_run_service", {})):
        with pytest.raises(gc.mod.GcloudRefused) as exc:
            gc.ex.run_tool(tool, dict(SERVICE, **extra))
        assert exc.value.code == "AUDIT_UNAVAILABLE" and exc.value.http_status == 503
    assert [m for m, *_ in gc.session.calls if m == "PATCH"] == []


@pytest.mark.parametrize("traffic,code", [
    ({"claims-api-00001-xyz": 60, "claims-api-00002-abc": 30}, "TRAFFIC_INVALID"),
    ({"claims-api-00001-xyz": 100.0}, "TRAFFIC_INVALID"),
    ({}, "TRAFFIC_INVALID"),
    ({"claims-api-00009-zzz": 100}, "REVISION_NOT_FOUND"),
])
def test_traffic_must_name_existing_revisions_and_sum_to_100(gc, traffic, code):
    with pytest.raises(gc.mod.GcloudRefused) as exc:
        gc.ex.update_cloud_run_traffic(**SERVICE, traffic=traffic)
    assert exc.value.code == code
    assert [m for m, *_ in gc.session.calls if m == "PATCH"] == [] and _audits(gc) == {}


def test_traffic_split_patches_only_traffic(gc):
    res = gc.ex.update_cloud_run_traffic(**SERVICE, traffic={"claims-api-00001-xyz": 10, "claims-api-00002-abc": 90})
    assert res["status"] == "SUBMITTED"
    method, url, params, body = gc.session.calls[-1]
    assert (method, url, params) == ("PATCH", SVC_URL, {"updateMask": "traffic"})
    assert [t["percent"] for t in body["traffic"]] == [10, 90]


def test_restart_keeps_the_spec_and_only_bumps_the_restart_annotation(gc):
    res = gc.ex.restart_cloud_run_service(**SERVICE)
    assert res["status"] == "SUBMITTED"
    method, url, params, body = gc.session.calls[-1]
    assert params == {"updateMask": "template.annotations"}
    assert body == {"template": {"annotations": {"team": "claims", "stackvend.dev/restarted-at": NOW.isoformat()}}}


def test_upstream_error_is_typed_and_the_audit_records_it(gc):
    gc.session.routes[("PATCH", SVC_URL)] = (403, {"error": {"message": "denied"}})
    with pytest.raises(gc.mod.GcloudRefused) as exc:
        gc.ex.restart_cloud_run_service(**SERVICE)
    assert exc.value.code == "PERMISSION_DENIED" and exc.value.http_status == 403
    (audit,) = _audits(gc).values()
    assert audit["status"] == "FAILED:PERMISSION_DENIED"


# ----------------------------------------------------------------------------------------------- honesty
def test_missing_credentials_are_an_error_never_a_mock(gc):
    def no_creds():
        raise RuntimeError("DefaultCredentialsError")

    ex = gc.mod.GcloudExecutor(db_factory=lambda: gc.db, session_factory=no_creds, env={"PROJECT_ID": HOST})
    with pytest.raises(gc.mod.GcloudRefused) as exc:
        ex.get_cloud_run_service(**SERVICE)
    assert exc.value.code == "CREDENTIALS_UNAVAILABLE" and exc.value.http_status == 503
    assert ex.credentials_status().startswith("UNAVAILABLE:")


def test_health_reports_credentials_and_typed_tools(gc):
    body = gc.client.get("/health").json()
    assert body["credentials"] == "AVAILABLE" and "exec_gcloud_command" not in body["tools"]


def test_tools_list_is_typed_and_every_tool_requires_product_id(gc):
    tools = gc.client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).json()["result"]["tools"]
    names = {t["name"] for t in tools}
    assert names == set(gc.mod.INSPECTION_TOOLS + gc.mod.OPS_TOOLS) and "exec_gcloud_command" not in names
    assert all("product_id" in t["inputSchema"]["required"] for t in tools)


def test_executor_runs_no_cli_and_has_no_mock_branch():
    tree = ast.parse(open(os.path.join(GC_DIR, "executor.py"), encoding="utf-8").read())
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not imported & {"subprocess", "shlex"}
    strings = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert "MOCK_SUCCESS" not in strings


# ----------------------------------------------------------------------------------------------- RT F1: verified caller
@pytest.mark.parametrize("header", [
    _token("owner@example.test", signature=""),                      # alg=none style: empty signature
    _token("owner@example.test", signature="", alg="none"),
    _token("owner@example.test", signature="forged"),                # wrong signature
    "Basic dXNlcjpwYXNz",                                            # not a bearer token
    "Bearer not-a-jwt",
])
def test_rt_f1_forged_or_unverifiable_caller_token_refuses_ops_before_any_call(gc, header):
    r = gc.client.post("/exec", headers={"Authorization": header}, json={
        "tool": "update_cloud_run_scaling", "args": dict(SERVICE, min_instance_count=1, max_instance_count=4)})
    assert r.status_code == 401 and r.json()["detail"]["status"] == "CALLER_UNVERIFIED"
    rpc = gc.client.post("/mcp", headers={"Authorization": header}, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "restart_cloud_run_service", "arguments": dict(SERVICE)}}).json()
    assert rpc["error"]["data"]["status"] == "CALLER_UNVERIFIED"
    assert gc.session.calls == [] and _audits(gc) == {}  # no audit row, no GET, no PATCH


def test_rt_f1_inspection_needs_no_verified_caller(gc):
    r = gc.client.post("/exec", headers={"Authorization": _token("x@y", signature="forged")},
                       json={"tool": "get_cloud_run_service", "args": dict(SERVICE)})
    assert r.status_code == 200 and r.json()["status"] == "OK"


def test_rt_f1_no_authorization_header_audits_unknown(gc):
    r = gc.client.post("/exec", json={"tool": "restart_cloud_run_service", "args": dict(SERVICE)})
    assert r.status_code == 200
    (audit,) = _audits(gc).values()
    assert audit["caller"] == "unknown"


def test_rt_f1_default_verifier_checks_the_service_audience_and_google_issuer(gc, monkeypatch):
    seen = {}

    def verify_token(token, request, audience=None):
        seen["audience"] = audience
        return {"email": "a@b", "iss": seen.get("iss", "https://accounts.google.com")}

    from google.oauth2 import id_token

    monkeypatch.setattr(id_token, "verify_token", verify_token)
    monkeypatch.setenv("GCLOUD_MCP_URL", "https://mcp-gcloud-server-123.us-east4.run.app")
    assert gc.mod._default_caller_verifier("t")["email"] == "a@b"
    assert seen["audience"] == "https://mcp-gcloud-server-123.us-east4.run.app"
    seen["iss"] = "https://evil.example"
    with pytest.raises(ValueError):
        gc.mod._default_caller_verifier("t")


# ----------------------------------------------------------------------------------------------- RT F2: ASCII only
@pytest.mark.parametrize("label", ["s\u00e9rvice", "svc\u0663", "\u00aa", "\u0441laims"])
def test_rt_f2_non_ascii_labels_are_refused(gc, label):
    assert gc.mod.is_rfc1123_label(label) is False
    with pytest.raises(gc.mod.GcloudRefused) as exc:
        gc.ex.get_cloud_run_service(product_id="claims", region="us-east4", service=label)
    assert exc.value.code == "SERVICE_INVALID" and gc.session.calls == []


@pytest.mark.parametrize("region", ["\u00fc-central1", "us-centr\u0430l1", "us-central\u0661"])
def test_rt_f2_non_ascii_regions_are_refused(gc, region):
    assert gc.mod.is_region(region) is False


def test_rt_f2_negative_valid_ascii_labels_and_regions_are_unchanged(gc):
    for label in ("claims-api", "a", "x1", "svc-00002-abc", "a" * 63):
        assert gc.mod.is_rfc1123_label(label) is True
    for region in ("us-central1", "europe-west4", "asia-southeast1", "me-central2", "northamerica-northeast1"):
        assert gc.mod.is_region(region) is True
