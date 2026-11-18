"""RT14 cc-authz group (owner 11-14, `docs/planning/rt14-cc-authz-plan.md`): Control Center authorization and
trust-boundary fixes from the full-scope red-team scan (`docs/planning/full-scope-red-team-1114.md`).

- RT14-03: workload details never read another tenant's state (exact folder, segment check), mask what the engine
  marks sensitive, show only fixed non-secret attributes, and withhold OpenTofu outputs from VIEWERs.

Hermetic: real route functions on in-memory fakes; no network, no GCP.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from fd4f_support import FakeDB, gw  # noqa: F401  (gw is a fixture)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO, "apps", "control-center")


def _routes(monkeypatch, store=None):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl

    monkeypatch.setattr(cc_db, "_db_client", False)
    monkeypatch.setattr(wl, "db", store if store is not None else FakeDB())
    return wl


def _request(role, assigned=(), email="someone@example.com"):
    request = MagicMock()
    request.state.user_email = email
    request.state.user_role = role
    request.state.assigned_workloads = list(assigned)
    return request


# ============================================================================================ RT14-03
class _GcsBucket:
    """GCS semantics that matter here: `blob(path).exists()` is exact; `list_blobs(prefix)` is a plain string prefix
    (so "workloads/app" also lists "workloads/app-billing/...")."""

    def __init__(self, objects):
        self.objects, self.downloads, self.prefixes = dict(objects), [], []

    def blob(self, path):
        bucket = self

        class _Blob:
            name = path

            def exists(self):
                return path in bucket.objects

            def download_as_text(self):
                bucket.downloads.append(path)
                return bucket.objects[path]
        return _Blob()

    def list_blobs(self, prefix=None, max_results=None):
        self.prefixes.append(prefix)
        return [self.blob(n) for n in sorted(self.objects) if n.startswith(prefix or "")]


def _storage(bucket):
    class _Client:
        def __init__(self, project=None):
            pass

        def bucket(self, name):
            return bucket
    return MagicMock(Client=_Client)


def _state(name="api", outputs=None, attributes=None, sensitive_attributes=None):
    inst = {"attributes": attributes if attributes is not None else {"name": name, "location": "us-central1"}}
    if sensitive_attributes is not None:
        inst["sensitive_attributes"] = sensitive_attributes
    return json.dumps({"version": 4, "serial": 2, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": "google_cloud_run_v2_service", "name": name, "provider": "p", "instances": [inst]}],
        "outputs": outputs or {}})


@pytest.fixture()
def wl_gcs(monkeypatch):
    wl = _routes(monkeypatch)
    monkeypatch.setenv("TFSTATE_BUCKET", "castor-tfstate-host")
    from services import runner_state
    monkeypatch.setattr(runner_state, "state_bucket", lambda pid, default: default)

    def _use(objects):
        bucket = _GcsBucket(objects)
        monkeypatch.setattr(wl, "storage", _storage(bucket))
        return bucket
    return wl, _use


def test_rt14_03_another_tenants_state_is_never_read(wl_gcs):
    """`app` has no state; `app-billing` does. The old prefix `workloads/app` listed and served it."""
    wl, use = wl_gcs
    bucket = use({"workloads/app-billing/default.tfstate": _state("billing", {"db_url": {"value": "postgres://x"}})})
    assert wl.fetch_workload_state_from_gcs("app", "host") is None
    assert bucket.downloads == [] and bucket.prefixes == ["workloads/app/"]


def test_rt14_03_archives_are_not_the_current_state(wl_gcs):
    wl, use = wl_gcs
    bucket = use({"workloads/app/state_history/decommission_1.tfstate": _state()})
    assert wl.fetch_workload_state_from_gcs("app", "host") is None and bucket.downloads == []


def test_rt14_03_negative_own_state_files_are_still_read(wl_gcs):
    """Do No Harm: the exact paths and a state file directly in the workload's own folder are read as before."""
    wl, use = wl_gcs
    use({"workloads/app/default.tfstate": _state()})
    assert wl.fetch_workload_state_from_gcs("app", "host")["state_source"] == \
        "gs://castor-tfstate-host/workloads/app/default.tfstate"
    use({"workloads/app/staging.tfstate": _state(), "workloads/app-billing/default.tfstate": _state("billing")})
    out = wl.fetch_workload_state_from_gcs("app", "host")
    assert out["state_source"] == "gs://castor-tfstate-host/workloads/app/staging.tfstate"
    assert [r.resource_name for r in out["resources"]] == ["api"]


@pytest.mark.parametrize("name,want", [
    ("workloads/app/default.tfstate", True), ("workloads/app/staging.tfstate", True),
    ("workloads/app-billing/default.tfstate", False), ("workloads/app/state_history/d_1.tfstate", False),
    ("workloads/app/.tfstate", False), ("workloads/app/default.tfstate.backup", False), ("workloads/app", False),
    ("other/app/default.tfstate", False), (None, False)])
def test_rt14_03_state_object_segment_check(monkeypatch, name, want):
    wl = _routes(monkeypatch)
    assert wl._is_workload_state_object(name, "app") is want


def test_rt14_03_sensitive_outputs_are_masked_by_the_engine_flag(monkeypatch):
    wl = _routes(monkeypatch)
    out = wl.parse_tfstate_json(_state(outputs={
        "db_password": {"value": "hunter2", "type": "string", "sensitive": True},
        "url": {"value": "https://api.example", "type": "string"},
        "flagged_false": {"value": "visible", "type": "string", "sensitive": False}}), "src")["outputs"]
    assert out == {"db_password": "(sensitive value)", "url": "https://api.example", "flagged_false": "visible"}


def test_rt14_03_negative_unmarked_state_parses_exactly_as_before(monkeypatch):
    """Do No Harm: a state without sensitive marks gives the same resources and outputs as the old parser."""
    wl = _routes(monkeypatch)
    outputs = {"url": {"value": "https://api.example", "type": "string"}, "n": {"value": 3, "type": "number"},
               "m": {"value": {"a": [1, 2]}, "type": ["object", {}]}}
    attrs = {"name": "api", "location": "us-central1", "uri": "https://api.example", "project": "p1", "extra": "x"}
    got = wl.parse_tfstate_json(_state(outputs=outputs, attributes=attrs), "src")
    assert got["outputs"] == {"url": "https://api.example", "n": 3, "m": {"a": [1, 2]}}
    (res,) = got["resources"]
    assert res.attributes == {"location": "us-central1", "uri": "https://api.example", "name": "api", "project": "p1"}
    assert res.resource_id == "api"


def test_rt14_03_attributes_the_engine_marks_sensitive_are_dropped(monkeypatch):
    wl = _routes(monkeypatch)
    got = wl.parse_tfstate_json(_state(
        attributes={"name": "db-user", "location": "us-central1", "email": "secret@example.com"},
        sensitive_attributes=[[{"type": "get_attr", "value": "email"}]]), "src")
    assert got["resources"][0].attributes == {"name": "db-user", "location": "us-central1"}


def test_rt14_03_unreadable_sensitive_marks_hide_every_attribute(monkeypatch):
    wl = _routes(monkeypatch)
    got = wl.parse_tfstate_json(_state(attributes={"name": "a", "location": "l"},
                                       sensitive_attributes=[{"unknown": "shape"}]), "src")
    (res,) = got["resources"]
    assert res.attributes == {} and res.resource_id == "google_cloud_run_v2_service.api"


def test_rt14_03_fallback_never_shows_arbitrary_attributes(monkeypatch):
    """The old fallback showed the first 6 scalar attributes, e.g. a tls_private_key's private_key_pem."""
    wl = _routes(monkeypatch)
    got = wl.parse_tfstate_json(_state(attributes={
        "algorithm": "RSA", "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----", "id": "k1"}), "src")
    assert got["resources"][0].attributes == {}
    got = wl.parse_tfstate_json(_state(attributes={"role": "roles/run.invoker", "member": "user:a@example.com",
                                                   "etag": "x", "condition": []}), "src")
    assert got["resources"][0].attributes == {"role": "roles/run.invoker", "member": "user:a@example.com"}


def _details(monkeypatch, role, outputs):
    store = FakeDB()
    store.docs["workloads/app"] = {"product_id": "app", "project_id": "app-proj", "status": "ACTIVE"}
    wl = _routes(monkeypatch, store)
    state = {"terraform_version": "1.9.0", "serial": 1, "state_source": "s", "resources_count": 1, "resources": [],
             "outputs": outputs}
    with patch.object(wl, "verify_workload_access", lambda *a, **k: None), \
         patch.object(wl, "fetch_workload_state_from_gcs", return_value=state):
        return wl.get_workload_details("app", _request(role, ["app"]))


def test_rt14_03_viewers_do_not_get_outputs(monkeypatch):
    _routes(monkeypatch)
    from schemas import UserRole

    resp = _details(monkeypatch, UserRole.VIEWER, {"conn": "postgres://u:p@h/db"})
    assert resp.outputs == {} and resp.outputs_withheld_reason == "OUTPUTS_MANAGER_ONLY"
    resp = _details(monkeypatch, "NOT_A_ROLE", {"conn": "x"})            # unreadable role: fails closed
    assert resp.outputs == {} and resp.outputs_withheld_reason == "OUTPUTS_MANAGER_ONLY"


@pytest.mark.parametrize("role", ["ADMIN", "WORKLOAD_MANAGER", "APPROVER"])
def test_rt14_03_negative_managers_and_admins_get_outputs_unchanged(monkeypatch, role):
    _routes(monkeypatch)
    from schemas import UserRole

    resp = _details(monkeypatch, UserRole(role), {"url": "https://api.example"})
    assert resp.outputs == {"url": "https://api.example"} and resp.outputs_withheld_reason is None
    resp = _details(monkeypatch, role, {"url": "https://api.example"})   # a plain string role, as some callers store
    assert resp.outputs == {"url": "https://api.example"}


def test_rt14_03_viewer_without_outputs_gets_no_withheld_reason(monkeypatch):
    _routes(monkeypatch)
    from schemas import UserRole

    resp = _details(monkeypatch, UserRole.VIEWER, {})
    assert resp.outputs == {} and resp.outputs_withheld_reason is None


def test_rt14_03_guard_every_workloads_prefix_listing_ends_with_a_separator():
    """Structural guard: a Control Center `list_blobs(prefix=f"workloads/{...}...")` must end the prefix with "/"."""
    bad = []
    for root, _dirs, files in os.walk(CC_DIR):
        for fn in files:
            if not fn.endswith(".py") or fn.startswith("test_"):
                continue
            path = os.path.join(root, fn)
            tree = ast.parse(open(path, encoding="utf-8").read())
            prefixes = {}
            for node in ast.walk(tree):     # `prefix = f"..."` assignments, so a name passed as prefix is checked too
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    prefixes[node.targets[0].id] = node.value
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "list_blobs"):
                    continue
                for kw in node.keywords:
                    if kw.arg != "prefix":
                        continue
                    val = prefixes.get(kw.value.id, kw.value) if isinstance(kw.value, ast.Name) else kw.value
                    if not isinstance(val, ast.JoinedStr) or not val.values:
                        continue
                    head, tail = val.values[0], val.values[-1]
                    if (isinstance(head, ast.Constant) and str(head.value).startswith("workloads/")
                            and not (isinstance(tail, ast.Constant) and str(tail.value).endswith("/"))):
                        bad.append(f"{os.path.relpath(path, REPO)}:{node.lineno}")
    assert bad == []


# ============================================================================================ RT14-11
def _csrf():
    if CC_DIR not in sys.path:
        sys.path.insert(0, CC_DIR)
    import csrf_guard
    return csrf_guard


SAME = {"host": "cc.example", "origin": "https://cc.example", "sec-fetch-site": "same-origin"}


@pytest.mark.parametrize("headers", [
    SAME,
    {"host": "cc.example"},                                                   # curl, Pub/Sub push, the test client
    {"host": "cc.example", "origin": "https://cc.example"},                  # a browser without fetch metadata
    {"host": "cc.example", "sec-fetch-site": "same-origin"},                 # fetch metadata without Origin
    {"host": "CC.example", "origin": "https://cc.EXAMPLE", "sec-fetch-site": "Same-Origin"},
    {"host": "localhost:8080", "origin": "http://localhost:8080"},
    # RT14-11 review F1: the CLI proxy (`gcloud run services proxy`) forwards the run.app Host while the browser's
    # Origin is localhost; the browser-set Sec-Fetch-Site decides alone.
    {"host": "svc-1.a.run.app", "origin": "http://localhost:8080", "sec-fetch-site": "same-origin"},
])
def test_rt14_11_negative_same_origin_and_non_browser_requests_pass(headers):
    g = _csrf()
    for method in ("POST", "PUT", "PATCH", "DELETE", "GET"):
        assert g.cross_site_refusal(method, headers) is None


@pytest.mark.parametrize("headers", [
    {"host": "cc.example", "origin": "https://evil.example", "sec-fetch-site": "cross-site"},
    {"host": "cc.example", "sec-fetch-site": "cross-site"},
    {"host": "cc.example", "sec-fetch-site": "same-site", "origin": "https://other.cc.example"},
    {"host": "cc.example", "sec-fetch-site": "none"},
    {"host": "cc.example", "origin": "https://evil.example"},                # old browser: Origin only
    {"host": "cc.example", "origin": "null"},                                # sandboxed iframe / opaque origin
    {"host": "cc.example", "origin": "https://cc.example.evil.example"},
    {"host": "cc.example", "origin": "https://cc.example/path"},
    {"host": "", "origin": "https://cc.example"},
])
def test_rt14_11_cross_site_state_changes_are_refused(headers):
    g = _csrf()
    for method in ("POST", "PUT", "PATCH", "DELETE", "post"):
        assert g.cross_site_refusal(method, headers)
    for method in ("GET", "HEAD", "OPTIONS"):                               # reads are unchanged
        assert g.cross_site_refusal(method, headers) is None


def _csrf_harness():
    """Run in a clean subprocess on the FD-4E hermetic prefix: every mutating route of the real app, enumerated."""
    marker = "# ================================================================ public mode"
    here = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(here, "cc_identity_harness.py")
    src = open(src_path, encoding="utf-8").read()
    assert marker in src, "FD-4E harness prefix changed"
    ns = {"__file__": src_path, "__name__": "rt14_csrf_harness"}
    exec(compile(src.split(marker, 1)[0], src_path, "exec"), ns)
    ns["mode"]("")   # public mode: the owner's session cookie authenticates
    main = ns["main"]
    import re

    import authz
    from fastapi.routing import APIRoute

    mutating = []
    for route, path, methods in authz.iter_effective_routes(main.app.routes):
        if isinstance(route, APIRoute):
            for m in sorted(methods):
                if m not in ("GET", "HEAD", "OPTIONS"):
                    mutating.append((m, path))
    client = ns["TestClient"](main.app, raise_server_exceptions=False)
    cookie = ns["OWNER_COOKIE"]
    attacks = {"fetch_metadata": {"origin": "https://evil.example", "sec-fetch-site": "cross-site"},
               "origin_only": {"origin": "https://evil.example"},
               "null_origin": {"origin": "null"}}
    out = {"mutating": [list(x) for x in mutating], "not_refused": []}
    for m, path in mutating:
        url = re.sub(r"\{[^}]+\}", "x", path)
        for name, headers in attacks.items():
            r = client.request(m, url, headers=headers, cookies=cookie)
            body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            if r.status_code != 403 or body.get("error_class") != "CSRF_CROSS_SITE_REFUSED":
                out["not_refused"].append([m, path, name, r.status_code])
    # A probe route: same-origin and header-less requests reach the handler; a cross-site one does not.
    hits = []
    main.app.router.add_api_route("/api/rt14-csrf-probe", lambda: hits.append(1) or {"ok": True}, methods=["POST"],
                                  dependencies=[authz.require(authz.AUTHENTICATED)])
    probe = {}
    for name, headers in {"same_origin": {"origin": "http://testserver", "sec-fetch-site": "same-origin"},
                          "no_headers": {},
                          "cross_site": {"origin": "https://evil.example", "sec-fetch-site": "cross-site"}}.items():
        probe[name] = client.post("/api/rt14-csrf-probe", headers=headers, cookies=cookie).status_code
    out["probe"], out["probe_hits"] = probe, len(hits)
    out["cross_site_get_health"] = client.get("/health", headers=attacks["fetch_metadata"]).status_code
    out["network_attempts"] = ns["NETWORK_ATTEMPTS"]
    print(json.dumps(out))


@pytest.fixture(scope="module")
def csrf_inv():
    import subprocess

    env = hermetic_guard.child_env(drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL"),
                                   extra={"PROJECT_ID": "mock-stackvend-project",
                                          "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project"})
    out = subprocess.run([sys.executable, os.path.abspath(__file__), "--harness-csrf"],
                         capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_rt14_11_every_mutating_route_refuses_a_cross_site_request(csrf_inv):
    """Guard: enumerated from the live app, so a new mutating route is covered (or this fails) automatically."""
    mutating = {tuple(x) for x in csrf_inv["mutating"]}
    assert len(mutating) > 50
    for named in (("POST", "/api/workloads/{product_id}/retrigger"),
                  ("POST", "/api/workloads/{product_id}/deploy-infra"),
                  ("POST", "/api/workloads/sweep-expired-sandboxes"), ("POST", "/auth/google-login"),
                  ("POST", "/api/pipeline/executions/{trace_id}/abort")):
        assert named in mutating
    assert {m for m, _ in mutating} >= {"POST", "PUT", "PATCH", "DELETE"}
    assert csrf_inv["not_refused"] == []


def test_rt14_11_negative_same_origin_and_header_less_requests_reach_the_handler(csrf_inv):
    assert csrf_inv["probe"] == {"same_origin": 200, "no_headers": 200, "cross_site": 403}
    assert csrf_inv["probe_hits"] == 2
    assert csrf_inv["cross_site_get_health"] == 200
    assert csrf_inv["network_attempts"] == []


# ============================================================================================ RT14-34
def _upgrade(monkeypatch, request, author="owner@company.example"):
    from test_fd4dc_archive_and_partial_readers import (WORKLOAD, _cc_routes, _Store, _upgrade_recorders,
                                                        _UpgradeProvider, _use_provider, _workload_tree)

    wl = _cc_routes(monkeypatch)
    monkeypatch.setattr(wl, "get_db", lambda: _Store(dict(WORKLOAD)))
    rec = _upgrade_recorders(monkeypatch, wl)
    prov = _UpgradeProvider(_workload_tree(drift=True))
    prs = []
    real_pr = prov.create_pull_request
    prov.create_pull_request = lambda repo, **kw: prs.append(kw) or real_pr(repo, **kw)
    commits = []
    real_commit = prov.commit_files
    prov.commit_files = lambda repo, branch, files, commit_message=None, **kw: (
        commits.append(kw) or real_commit(repo, branch, files, commit_message))
    _use_provider(monkeypatch, wl, prov)
    req = wl.TriggerIaCUpgradeRequest(author=author, modules_to_upgrade=["compute-cloudrun"])
    return wl, rec, prs, commits, (lambda: wl.trigger_workload_iac_upgrade("app", req, request))


def test_rt14_34_a_forged_body_author_is_never_recorded(monkeypatch):
    request = _request("WORKLOAD_MANAGER", ["app"], email="manager@example.com")
    wl, rec, prs, commits, run = _upgrade(monkeypatch, request, author="owner@company.example")
    out = run()
    assert out["status"] == "SUCCESS"
    (start_args, _), = rec["start"]
    assert start_args[1] == "manager@example.com"
    assert all(kw["author"] == "manager@example.com" for _, kw in rec["complete"])
    assert commits[0]["author_name"] == "manager@example.com (via StackVend IaC Engine)"
    assert "manager@example.com" in prs[0]["body"] and "owner@company.example" not in prs[0]["body"]


def test_rt14_34_negative_dashboard_body_without_author_records_the_caller(monkeypatch):
    request = _request("ADMIN", email="admin@example.com")
    wl, rec, prs, commits, run = _upgrade(monkeypatch, request, author=None)
    assert run()["status"] == "SUCCESS"
    assert rec["start"][0][0][1] == "admin@example.com"


@pytest.mark.parametrize("email", [None, "", "   ", 7])
def test_rt14_34_no_verified_identity_is_refused_typed_before_anything(monkeypatch, email):
    request = MagicMock()
    request.state.user_email = email
    wl, rec, prs, commits, run = _upgrade(monkeypatch, request)
    with pytest.raises(wl.HTTPException) as ei:
        run()
    assert ei.value.status_code == 401 and ei.value.detail["error_class"] == "IDENTITY_UNVERIFIED"
    assert ei.value.detail["stage"] == "iac_upgrade"
    assert rec["start"] == [] and commits == [] and prs == []


def test_rt14_34_guard_no_route_takes_a_value_from_a_body_author_field():
    """Structural guard: no Control Center route assigns or passes on `<anything>.author` (a request-body field)."""
    bad = []
    for path in sorted(os.listdir(os.path.join(CC_DIR, "routes"))):
        if not path.endswith(".py"):
            continue
        full = os.path.join(CC_DIR, "routes", path)
        for node in ast.walk(ast.parse(open(full, encoding="utf-8").read())):
            values = []
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and node.value is not None:
                values.append(node.value)
            elif isinstance(node, ast.Call):
                values.extend(k.value for k in node.keywords)
            for v in values:
                if any(isinstance(n, ast.Attribute) and n.attr == "author" for n in ast.walk(v)):
                    bad.append(f"routes/{path}:{node.lineno}")
    assert bad == []


# ============================================================================================ RT14-31
HOST = "mock-stackvend-project"


class _Entry:
    def __init__(self, ts, msg, service="api", product_id=None):
        from datetime import datetime, timezone
        self.timestamp = datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
        self.severity = "INFO"
        self.resource = MagicMock(type="cloud_run_revision", labels={"service_name": service})
        self.payload = {"message": msg, **({"product_id": product_id} if product_id else {})}
        self.insert_id = f"id-{msg}"


class _Logging:
    """list_entries by project: {project: [entries] | Exception}. Records every call."""
    DESCENDING = "timestamp desc"

    def __init__(self, by_project):
        self.by_project, self.calls = by_project, []

    def list_entries(self, resource_names=None, filter_=None, max_results=None, order_by=None):
        self.calls.append({"resource_names": resource_names, "filter": filter_})
        (name,) = resource_names
        got = self.by_project.get(name.split("/", 1)[1], [])
        if isinstance(got, Exception):
            raise got
        return list(got)


def _telemetry(monkeypatch, client, workload=None):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import telemetry

    monkeypatch.setattr(cc_db, "_db_client", False)
    store = FakeDB()
    if workload is not None:
        store.docs["workloads/app"] = workload
    monkeypatch.setattr(telemetry, "db", store)
    monkeypatch.setattr(telemetry, "PROJECT_ID", HOST)
    monkeypatch.setattr(telemetry, "get_cloud_logging", lambda: client)
    monkeypatch.setattr(telemetry, "verify_workload_access", lambda *a, **k: None)
    return telemetry


def _denied():
    from google.api_core import exceptions as gexc
    return gexc.PermissionDenied("caller lacks logging.logEntries.list")


def test_rt14_31_workload_logs_come_from_its_child_project_and_are_labelled(monkeypatch):
    client = _Logging({"app-proj": [_Entry("2026-11-14T10:00:02", "child-runtime")],
                       HOST: [_Entry("2026-11-14T10:00:01", "pipeline", service="mcp-terraform-server",
                                     product_id="app")]})
    t = _telemetry(monkeypatch, client, {"project_id": "app-proj"})
    resp = t.get_workload_logs("app", _request("VIEWER", ["app"]))
    assert [(c["resource_names"]) for c in client.calls] == [["projects/app-proj"], [f"projects/{HOST}"]]
    assert client.calls[1]["filter"].startswith('jsonPayload.product_id="app"')
    assert 'resource.type="cloud_run_revision"' in client.calls[0]["filter"]
    assert [(r.message, r.log_source) for r in resp.logs] == [("child-runtime", "WORKLOAD"),
                                                             ("pipeline", "PLATFORM_PIPELINE")]
    assert resp.project_id == "app-proj" and resp.source_errors == []


def test_rt14_31_an_unreadable_child_project_is_a_typed_source_error_not_no_logs(monkeypatch):
    client = _Logging({"app-proj": _denied(), HOST: [_Entry("2026-11-14T10:00:01", "pipeline", product_id="app")]})
    t = _telemetry(monkeypatch, client, {"project_id": "app-proj"})
    resp = t.get_workload_logs("app", _request("VIEWER", ["app"]))
    assert [r.log_source for r in resp.logs] == ["PLATFORM_PIPELINE"]
    (err,) = resp.source_errors
    assert (err["source"], err["project"], err["code"]) == ("WORKLOAD", "app-proj", "PERMISSION_DENIED")


def test_rt14_31_every_source_failing_is_a_typed_502(monkeypatch):
    client = _Logging({"app-proj": _denied(), HOST: RuntimeError("quota")})
    t = _telemetry(monkeypatch, client, {"project_id": "app-proj"})
    with pytest.raises(HTTPException) as ei:
        t.get_workload_logs("app", _request("VIEWER", ["app"]))
    assert ei.value.status_code == 502 and ei.value.detail["error_class"] == "LOGS_UNAVAILABLE"
    assert [(f["source"], f["code"]) for f in ei.value.detail["failures"]] == [
        ("WORKLOAD", "PERMISSION_DENIED"), ("PLATFORM_PIPELINE", "QUERY_FAILED")]


@pytest.mark.parametrize("workload,code", [({"project_id": HOST}, "HOST_PROJECT_REFUSED"),
                                           ({}, "NO_CHILD_PROJECT"), ({"project_id": None}, "NO_CHILD_PROJECT")])
def test_rt14_31_the_host_is_never_read_as_the_workloads_project(monkeypatch, workload, code):
    client = _Logging({HOST: [_Entry("2026-11-14T10:00:01", "pipeline", product_id="app")]})
    t = _telemetry(monkeypatch, client, workload)
    resp = t.get_workload_logs("app", _request("ADMIN"))
    assert [c["resource_names"] for c in client.calls] == [[f"projects/{HOST}"]]   # the pipeline source only
    assert "resource.type" not in client.calls[0]["filter"]
    assert [e["code"] for e in resp.source_errors] == [code]


def test_rt14_31_unknown_workload_is_404_and_bad_severity_is_422(monkeypatch):
    t = _telemetry(monkeypatch, _Logging({}), None)
    with pytest.raises(HTTPException) as ei:
        t.get_workload_logs("app", _request("ADMIN"))
    assert ei.value.status_code == 404
    t = _telemetry(monkeypatch, _Logging({}), {"project_id": "app-proj"})
    with pytest.raises(HTTPException) as ei:
        t.get_workload_logs("app", _request("ADMIN"), severity='INFO" OR severity>="DEFAULT')
    assert ei.value.status_code == 422 and ei.value.detail["error_class"] == "LOG_SEVERITY_INVALID"


def test_rt14_31_negative_severity_filter_and_empty_result_are_unchanged(monkeypatch):
    client = _Logging({})
    t = _telemetry(monkeypatch, client, {"project_id": "app-proj"})
    resp = t.get_workload_logs("app", _request("VIEWER", ["app"]), severity="warning")
    assert resp.logs == [] and resp.source_errors == []        # really no logs: an empty, error-free answer
    assert all(c["filter"].endswith(" AND severity>=WARNING") for c in client.calls)
    client.calls.clear()
    t.get_workload_logs("app", _request("VIEWER", ["app"]), severity="ALL")
    assert not any("severity" in c["filter"] for c in client.calls)


def test_rt14_31_platform_logs_fail_typed_without_a_made_up_entry(monkeypatch):
    t = _telemetry(monkeypatch, _Logging({HOST: _denied()}))
    with pytest.raises(HTTPException) as ei:
        t.get_workload_logs("project-castor", _request("ADMIN"))
    assert ei.value.status_code == 502
    assert [(f["source"], f["code"]) for f in ei.value.detail["failures"]] == [("PLATFORM", "PERMISSION_DENIED")]
    t = _telemetry(monkeypatch, None)
    with pytest.raises(HTTPException) as ei:
        t.get_workload_logs("project-castor", _request("ADMIN"))
    assert ei.value.detail["failures"][0]["code"] == "CLIENT_UNAVAILABLE"


def test_rt14_31_aar_is_not_built_or_cached_from_unreadable_logs(monkeypatch):
    t = _telemetry(monkeypatch, _Logging({HOST: _denied()}))
    doc = MagicMock(exists=True)
    doc.to_dict.return_value = {"status": "FAILED", "product_id": "app", "project_id": "app-proj", "stages": {}}
    db = MagicMock()
    doc_ref = db.collection.return_value.document.return_value
    doc_ref.get.return_value = doc
    monkeypatch.setattr(t, "db", db)
    with pytest.raises(HTTPException) as ei:
        t.generate_execution_aar(trace_id="t1", request=None)
    assert ei.value.status_code == 502 and ei.value.detail["error_class"] == "LOGS_UNAVAILABLE"
    doc_ref.set.assert_not_called()


def test_rt14_31_aar_reads_only_the_platform_pipeline_source(monkeypatch):
    client = _Logging({HOST: []})
    t = _telemetry(monkeypatch, client)
    logs, _ = t.fetch_workload_logs_from_cloud_logging(product_id="app", project_id_val="app-proj", limit=100,
                                                       sources=(t.LOG_SOURCE_PLATFORM_PIPELINE,))
    assert logs == [] and [c["resource_names"] for c in client.calls] == [[f"projects/{HOST}"]]


def _trace_telemetry(monkeypatch, client):
    from types import SimpleNamespace
    t = _telemetry(monkeypatch, client)
    monkeypatch.setattr(t, "get_caller_main_module", lambda: SimpleNamespace(project_id=HOST, cloud_logging=None))
    return t


def test_rt14_31_trace_logs_name_the_host_and_fail_typed(monkeypatch):
    entry = _Entry("2026-11-14T10:00:01", "synthesizing", service="developer-agent")
    entry.payload = "synthesizing"                     # a text entry (the trace view's own payload handling)
    client = _Logging({HOST: [entry]})
    t = _trace_telemetry(monkeypatch, client)
    out = t.get_pipeline_execution_logs("tr-1", limit=10, request=None)
    assert [l["message"] for l in out["logs"]] == ["synthesizing"]
    assert client.calls[0]["resource_names"] == [f"projects/{HOST}"]
    assert client.calls[0]["filter"].startswith('(textPayload:"tr-1" OR jsonPayload.trace_id="tr-1")')
    t = _trace_telemetry(monkeypatch, _Logging({HOST: _denied()}))
    with pytest.raises(HTTPException) as ei:
        t.get_pipeline_execution_logs("tr-1", limit=10, request=None)
    assert ei.value.status_code == 502
    assert [(f["source"], f["code"]) for f in ei.value.detail["failures"]] == [("PIPELINE_TRACE", "PERMISSION_DENIED")]
    t = _trace_telemetry(monkeypatch, None)
    with pytest.raises(t.WorkloadLogsUnavailable) as ei:
        t.fetch_trace_logs_from_cloud_logging("tr-1")
    assert ei.value.failures[0]["code"] == "CLIENT_UNAVAILABLE"


def test_rt14_31_flight_deck_keeps_the_run_and_reports_the_log_failure(monkeypatch):
    t = _trace_telemetry(monkeypatch, _Logging({HOST: RuntimeError("boom")}))
    from schemas import PipelineExecutionItem
    item = PipelineExecutionItem.model_construct(trace_id="tr-1")
    monkeypatch.setattr(t, "get_pipeline_execution", lambda **k: item)
    resp = t.get_pipeline_flight_deck_telemetry("tr-1", request=None)
    assert resp.live_logs == [] and resp.live_logs_error["error_class"] == "LOGS_UNAVAILABLE"
    t = _trace_telemetry(monkeypatch, _Logging({HOST: []}))
    monkeypatch.setattr(t, "get_pipeline_execution", lambda **k: item)
    resp = t.get_pipeline_flight_deck_telemetry("tr-1", request=None)
    assert resp.live_logs == [] and resp.live_logs_error is None      # negative: really no logs, no error


def test_rt14_31_guard_every_log_query_names_its_project():
    """Structural guard: every Control Center `list_entries(...)` call passes `resource_names=` (never the client's
    default project)."""
    bad = []
    for root, _dirs, files in os.walk(CC_DIR):
        for fn in files:
            if not fn.endswith(".py") or fn.startswith("test_"):
                continue
            path = os.path.join(root, fn)
            for node in ast.walk(ast.parse(open(path, encoding="utf-8").read())):
                if (isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "list_entries"
                        and "resource_names" not in {k.arg for k in node.keywords}):
                    bad.append(f"{os.path.relpath(path, REPO)}:{node.lineno}")
    assert bad == []


# ============================================================================================ RT14-07
REFUSAL = {"removal_addresses": ["module.worker_a.google_pubsub_topic.t"], "trace_id": "tr-1", "refused_at": "x"}
EXPRESS_REFUSED = {"creation_mode": "EXPRESS", "destroy_requires_approval": REFUSAL}
NOT_REFUSED = [{"creation_mode": "EXPRESS", "destroy_requires_approval": None}, {"creation_mode": "EXPRESS"},
               {"creation_mode": "EXPRESS", "destroy_requires_approval": {}},
               {"creation_mode": "AGENT", "destroy_requires_approval": {"removal_addresses": ["a.x"]}}, {}]


class _Publisher:
    def __init__(self):
        self.published = []

    def publish(self, topic, data, **kw):
        self.published.append((topic, json.loads(data)))
        fut = MagicMock()
        fut.result.return_value = "msg-1"
        return fut


def _retrigger(monkeypatch, workload, prev_exec=None):
    """A retrigger of feature request fr-1 on workload `app` (Fast-Path inputs), the publisher recorded."""
    store = FakeDB()
    store.docs["workloads/app"] = dict(workload, project_id="app-proj", github_repo="org/app", default_branch="main")
    store.docs["feature_requests/fr-1"] = {"product_id": "app", "request_id": "fr-1", "title": "t", "description": "d"}
    if prev_exec is not None:
        store.docs["pipeline_executions/tr-prev"] = prev_exec
    wl = _routes(monkeypatch, store)
    monkeypatch.setattr(wl, "verify_workload_access", lambda *a, **k: None)
    monkeypatch.setattr(wl, "_refuse_new_run_in_maintenance", lambda *a, **k: None)
    pub = _Publisher()
    monkeypatch.setattr(wl, "get_pubsub_publisher", lambda *a, **k: pub, raising=False)
    from types import SimpleNamespace
    monkeypatch.setattr(wl, "get_caller_main_module",
                        lambda: SimpleNamespace(project_id=HOST, get_pubsub_publisher=lambda: pub))
    return wl, store, pub


# The Express refusal recorded by `_record_express_terraform_failed` (error_message, stages.terraform FAILED): Auto
# routes this run to DEPLOY_ONLY (late-stage terraform failure).
REFUSED_EXEC = {"product_id": "app", "request_id": "fr-1", "trace_id": "tr-prev", "status": "FAILED",
                "current_stage": "FAILED", "started_at": "2026-11-14T10:00:00", "error_class": "DESTROY_REQUIRES_APPROVAL",
                "error_message": "would delete", "stages": {"terraform": {"status": "FAILED",
                                                                          "error_class": "DESTROY_REQUIRES_APPROVAL"}}}


@pytest.mark.parametrize("body,prev", [({"execution_mode": "DEPLOY_ONLY"}, None),
                                       ({"execution_mode": "AUTO"}, REFUSED_EXEC), (None, REFUSED_EXEC)])
def test_rt14_07_fast_path_relaunch_of_a_refused_express_workload_is_refused(monkeypatch, body, prev):
    wl, store, pub = _retrigger(monkeypatch, EXPRESS_REFUSED, prev)
    with pytest.raises(HTTPException) as ei:
        wl.retrigger_feature_request_build("app", "fr-1", _request("WORKLOAD_MANAGER", ["app"]), body=body)
    assert ei.value.status_code == 409 and ei.value.detail["error_class"] == "DESTROY_REQUIRES_APPROVAL"
    assert ei.value.detail["removal_addresses"] == REFUSAL["removal_addresses"]
    assert pub.published == []
    assert [k for k in store.docs if k.startswith("pipeline_executions/") and k != "pipeline_executions/tr-prev"] == []


@pytest.mark.parametrize("workload", NOT_REFUSED)
def test_rt14_07_negative_fast_path_relaunch_otherwise_unchanged(monkeypatch, workload):
    wl, store, pub = _retrigger(monkeypatch, workload)
    out = wl.retrigger_feature_request_build("app", "fr-1", _request("WORKLOAD_MANAGER", ["app"]),
                                             body={"execution_mode": "DEPLOY_ONLY"})
    assert out["execution_mode"] == "DEPLOY_ONLY"
    assert [p["execution_mode"] for _, p in pub.published] == ["DEPLOY_ONLY"]


def test_rt14_07_negative_full_rebuild_of_a_refused_express_workload_is_not_this_check(monkeypatch):
    """Only a DEPLOY_ONLY relaunch applies the refused configuration as is; this check does not touch other modes."""
    wl, store, pub = _retrigger(monkeypatch, EXPRESS_REFUSED)
    try:
        wl.retrigger_feature_request_build("app", "fr-1", _request("WORKLOAD_MANAGER", ["app"]),
                                           body={"execution_mode": "FULL"})
    except HTTPException as e:   # later admission steps are not under test; this guard must not be what stops it
        assert not (isinstance(e.detail, dict) and e.detail.get("error_class") == "DESTROY_REQUIRES_APPROVAL")


def test_rt14_07_predicate_is_the_same_in_the_cc_and_the_gateway(monkeypatch):
    wl = _routes(monkeypatch)
    gw_src = open(os.path.join(REPO, "apps", "orchestrator-gateway", "main.py"), encoding="utf-8").read()
    fn = next(n for n in ast.parse(gw_src).body if isinstance(n, ast.FunctionDef)
              and n.name == "_express_destroy_refusal_open")
    ns = {"Any": object}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "gw", "exec"), ns)
    for doc in [EXPRESS_REFUSED, *NOT_REFUSED, None, "x", {"creation_mode": "EXPRESS", "destroy_requires_approval": [1]}]:
        assert ns["_express_destroy_refusal_open"](doc) is wl.express_destroy_refusal_open(doc)
    assert wl.express_destroy_refusal_open(EXPRESS_REFUSED) is True


def test_rt14_07_gateway_deploy_only_gate_refuses_an_open_express_refusal(gw):
    from test_lane17_gateway_gates import PID, TRACE, _client

    db = FakeDB()
    db.docs[f"workloads/{PID}"] = dict(EXPRESS_REFUSED, default_branch="main")
    r = _client(gw, db).post("/governance/deploy-only-gate", json={"trace_id": TRACE, "product_id": PID,
                                                                   "branch": "main"})
    assert r.status_code == 403 and r.json()["error_class"] == "POLICY_REJECTED"
    assert r.json()["reason"] == "DESTROY_REQUIRES_APPROVAL" and r.json()["stage"] == "deploy_only_gate"


@pytest.mark.parametrize("workload", NOT_REFUSED)
def test_rt14_07_negative_gateway_gate_otherwise_unchanged(gw, workload):
    from test_lane17_gateway_gates import PID, TRACE, _client

    db = FakeDB()
    db.docs[f"workloads/{PID}"] = dict(workload, default_branch="main")
    r = _client(gw, db).post("/governance/deploy-only-gate", json={"trace_id": TRACE, "product_id": PID,
                                                                   "branch": "main"})
    assert r.status_code == 200 and r.json()["status"] == "ALLOW"


def test_rt14_07_guard_every_cc_deploy_only_dispatcher_calls_the_refusal():
    """Structural guard: a Control Center function that can put DEPLOY_ONLY into an intake event (the constant in a
    dict or a comparison/assignment) and publishes must call _refuse_open_express_destroy_refusal."""
    path = os.path.join(CC_DIR, "routes", "workloads.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    missing = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        names = {getattr(c.func, "attr", getattr(c.func, "id", "")) for c in ast.walk(fn) if isinstance(c, ast.Call)}
        deploy_only = any(isinstance(c, ast.Constant) and c.value == "DEPLOY_ONLY" for c in ast.walk(fn))
        if deploy_only and "publish" in names and "_refuse_open_express_destroy_refusal" not in names:
            missing.append(fn.name)
    assert missing == []
    dispatchers = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                   and "_refuse_open_express_destroy_refusal" in {getattr(c.func, "id", "") for c in ast.walk(n)
                                                                if isinstance(c, ast.Call)}}
    assert dispatchers == {"retrigger_feature_request_build", "deploy_workload_infra"}


if __name__ == "__main__" and "--harness-csrf" in sys.argv:
    _csrf_harness()
