"""SAT-43: the Control Center cancels running Cloud Workflows executions through the Workflows REST API, with typed
outcomes (AGENTS.md invariant 8).

Before SAT-43 the Emergency Stop, the run Abort button, the decommission cascade and the stale-run reconcile imported
`google.cloud.workflows`, which is not in apps/control-center/requirements.txt: in the deployed image the import failed,
a warning was logged and no workflow execution was cancelled, while the stop still reported success.

Hermetic: a fake requests-like session (no google-auth, no network), an in-memory Firestore stand-in.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import json
import os
import sys
import urllib.parse
from types import SimpleNamespace

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
API = "https://workflowexecutions.googleapis.com/v1"
PROJECT, REGION = "mock-stackvend-project", "us-central1"
MAIN, SRE = "castor-main-orchestrator", "castor-sre-remediation"


def _ex(workflow, eid, project_number="123"):
    return f"projects/{project_number}/locations/{REGION}/workflows/{workflow}/executions/{eid}"


# ------------------------------------------------------------------------------------------------- fake Workflows API
class _Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no JSON")
        return copy.deepcopy(self._body)


def _err(status, api_status, message="boom"):
    return _Resp(status, {"error": {"code": status, "status": api_status, "message": message}})


class FakeWorkflows:
    """active: workflow -> [execution names] (served 2 per page); list_status / cancel_status / state override."""

    def __init__(self, active=None, page_size=2):
        self.active = {MAIN: [], SRE: []}
        self.active.update(active or {})
        self.page_size = page_size
        self.list_errors = {}    # workflow -> _Resp
        self.cancel_errors = {}  # execution name -> _Resp
        self.states = {}         # execution name -> state served by GET (and by the list, like the server filter)
        self.listed_states = {}  # execution name -> state the list serves although it matched the filter (race)
        self.cancel_states = {}  # execution name -> state a 200 cancel answers with (default CANCELLED)
        self.late = {}           # workflow -> names that appear from the second list call of that workflow on
        self.list_counts = {}
        self.calls = []

    def get(self, url, timeout=None):
        assert timeout, "every call has a timeout"
        self.calls.append(("GET", url))
        parsed = urllib.parse.urlparse(url)
        assert parsed.scheme == "https" and parsed.netloc == "workflowexecutions.googleapis.com"
        path = urllib.parse.unquote(parsed.path)[len("/v1/"):]
        parts = path.split("/")
        if parts[-1] == "executions":  # list
            q = urllib.parse.parse_qs(parsed.query)
            assert q["filter"] == ['state="ACTIVE"'], q  # the API refuses the unquoted form (HTTP 400)
            workflow = parts[5]
            self.list_counts[workflow] = self.list_counts.get(workflow, 0) + 1
            if workflow in self.list_errors:
                return self.list_errors[workflow]
            names = self.active.get(workflow)
            if names is None:
                return _err(404, "NOT_FOUND", f"workflow {workflow} does not exist")
            if self.list_counts[workflow] >= 2:
                names = names + self.late.get(workflow, [])
            names = [n for n in names if n in self.listed_states or self.states.get(n, "ACTIVE") == "ACTIVE"]
            start = int(q.get("pageToken", ["0"])[0])
            page = names[start:start + self.page_size]
            body = {}
            if page:
                body["executions"] = [{"name": n, "state": self.listed_states.get(n, "ACTIVE")} for n in page]
            if start + self.page_size < len(names):
                body["nextPageToken"] = str(start + self.page_size)
            return _Resp(200, body)
        state = self.states.get(path, "ACTIVE")
        return _Resp(200, {"name": path, "state": state})

    def post(self, url, json=None, timeout=None):
        assert timeout, "every call has a timeout"
        self.calls.append(("POST", url))
        assert json == {}
        path = urllib.parse.unquote(urllib.parse.urlparse(url).path)[len("/v1/"):]
        assert path.endswith(":cancel"), path
        name = path[:-len(":cancel")]
        if name in self.cancel_errors:
            return self.cancel_errors[name]
        state = self.cancel_states.get(name, "CANCELLED")
        self.states[name] = state
        return _Resp(200, {"name": name, "state": state})

    def cancels(self):
        return [urllib.parse.unquote(u)[len(API) + 1:-len(":cancel")] for m, u in self.calls if m == "POST"]


@pytest.fixture
def wfx(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    import workflow_executions as mod
    fake = FakeWorkflows()
    monkeypatch.setattr(mod, "session_provider", lambda: fake)
    monkeypatch.setattr(mod, "region_provider", lambda: REGION)
    mod.fake = fake
    yield mod
    mod.fake = None


# ------------------------------------------------------------------------------------- list + cancel (the helper)
def test_lists_every_page_and_cancels_each_active_execution(wfx):
    names = [_ex(MAIN, f"m{i}") for i in range(3)]
    wfx.fake.active.update({MAIN: names, SRE: [_ex(SRE, "s1")]})
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "OK" and r["detail"] is None
    assert (r["cancelled"], r["already_finished"], r["failed"]) == (4, 0, 0)
    assert wfx.fake.cancels() == names + [_ex(SRE, "s1")]
    assert [x["outcome"] for x in r["executions"]] == ["CANCELLED"] * 4
    assert {x["workflow"] for x in r["executions"]} == {MAIN, SRE}
    assert r["list_failures"] == []
    lists = [u for m, u in wfx.fake.calls if m == "GET"]
    assert len(lists) == 5  # pass 1: main two pages, sre one; pass 2 (nothing left): one each
    assert {x["pass"] for x in r["executions"]} == {1}
    assert all(f"/projects/{PROJECT}/locations/{REGION}/workflows/" in u for u in lists)


def test_no_active_executions_is_ok_and_cancels_nothing(wfx):
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "OK" and r["cancelled"] == 0 and r["executions"] == [] and r["list_failures"] == []
    assert wfx.fake.cancels() == []


def test_list_failure_is_typed_and_the_other_workflow_is_still_cancelled(wfx):
    wfx.fake.active.update({SRE: [_ex(SRE, "s1")]})
    wfx.fake.list_errors[MAIN] = _err(500, "INTERNAL")
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "WORKFLOW_LIST_FAILED"
    assert r["list_failures"] == [{"workflow": MAIN, "reason": "WORKFLOW_LIST_FAILED",
                                   "detail": f"list {MAIN}: HTTP 500 INTERNAL boom", "pass": 1}]
    assert r["cancelled"] == 1 and wfx.fake.cancels() == [_ex(SRE, "s1")]
    assert MAIN in r["detail"]


def test_a_missing_workflow_is_a_list_failure_not_zero_runs(wfx):
    wfx.fake.active.update({MAIN: None})
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "WORKFLOW_LIST_FAILED" and r["list_failures"][0]["workflow"] == MAIN
    assert "HTTP 404" in r["list_failures"][0]["detail"]


def test_one_cancel_failure_among_several_is_reported_per_execution(wfx):
    names = [_ex(MAIN, "a"), _ex(MAIN, "b"), _ex(MAIN, "c")]
    wfx.fake.active.update({MAIN: names})
    wfx.fake.cancel_errors[names[1]] = _err(500, "INTERNAL", "backend error")
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "WORKFLOW_CANCEL_FAILED"
    assert (r["cancelled"], r["failed"]) == (2, 1)
    by_name = {x["name"]: x for x in r["executions"]}
    assert by_name[names[0]]["outcome"] == by_name[names[2]]["outcome"] == "CANCELLED"
    bad = by_name[names[1]]
    assert bad["outcome"] == "FAILED" and bad["reason"] == "WORKFLOW_CANCEL_FAILED" and bad["state"] == "ACTIVE"
    assert "HTTP 500" in bad["detail"]
    assert "1 execution(s) could not be cancelled" in r["detail"]


def test_an_execution_that_ended_before_the_cancel_is_not_a_failure(wfx):
    name = _ex(MAIN, "done")
    wfx.fake.active.update({MAIN: [name]})
    wfx.fake.cancel_errors[name] = _err(400, "FAILED_PRECONDITION", "execution is not active")
    wfx.fake.listed_states[name] = "ACTIVE"  # listed while running ...
    wfx.fake.states[name] = "SUCCEEDED"      # ... ended before the cancel reached it
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "OK" and r["cancelled"] == 0 and r["already_finished"] == 1 and r["failed"] == 0
    assert r["executions"][0]["outcome"] == "ALREADY_FINISHED" and r["executions"][0]["state"] == "SUCCEEDED"


def test_permission_denied_on_list_is_typed_not_permitted(wfx):
    wfx.fake.list_errors[MAIN] = _err(403, "PERMISSION_DENIED", "workflows.executions.list denied")
    wfx.fake.list_errors[SRE] = _err(403, "PERMISSION_DENIED", "workflows.executions.list denied")
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "WORKFLOW_CANCEL_NOT_PERMITTED" and r["cancelled"] == 0
    assert [f["reason"] for f in r["list_failures"]] == ["WORKFLOW_CANCEL_NOT_PERMITTED"] * 2


def test_permission_denied_on_cancel_is_typed_not_permitted(wfx):
    names = [_ex(MAIN, "a"), _ex(MAIN, "b")]
    wfx.fake.active.update({MAIN: names})
    wfx.fake.cancel_errors[names[0]] = _err(403, "PERMISSION_DENIED", "workflows.executions.cancel denied")
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "WORKFLOW_CANCEL_NOT_PERMITTED"
    assert r["executions"][0]["outcome"] == "FAILED" and r["executions"][0]["reason"] == "WORKFLOW_CANCEL_NOT_PERMITTED"
    assert r["executions"][1]["outcome"] == "CANCELLED"
    assert ("GET", f"{API}/{names[0]}") not in wfx.fake.calls  # a 403 is final: no state probe


def test_transport_error_on_list_is_typed(wfx, monkeypatch):
    class Broken(FakeWorkflows):
        def get(self, url, timeout=None):
            raise ConnectionError("network unreachable")
    monkeypatch.setattr(wfx, "session_provider", lambda: Broken())
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "WORKFLOW_LIST_FAILED"
    assert all("ConnectionError" in f["detail"] for f in r["list_failures"])


def test_no_project_is_unconfigured_and_calls_nothing(wfx):
    r = wfx.cancel_active_platform_workflows("")
    assert r["status"] == "WORKFLOW_CANCEL_UNCONFIGURED" and r["cancelled"] == 0
    assert [f["workflow"] for f in r["list_failures"]] == [MAIN, SRE]
    assert wfx.fake.calls == []


def test_no_region_is_unconfigured(wfx, monkeypatch):
    monkeypatch.setattr(wfx, "region_provider", lambda: "")
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "WORKFLOW_CANCEL_UNCONFIGURED" and "region" in r["detail"]


def test_no_credentials_is_unconfigured(wfx, monkeypatch):
    """The real google-auth path with no ADC (the hermetic guard): typed, never a silent zero."""
    monkeypatch.setattr(wfx, "session_provider", None)
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "WORKFLOW_CANCEL_UNCONFIGURED" and "no Google credentials" in r["detail"]


def test_a_malformed_execution_name_is_refused_without_a_call(wfx):
    r = wfx.cancel_execution("projects/p/workflows/w")
    assert r["outcome"] == "FAILED" and r["reason"] == "WORKFLOW_EXECUTION_NAME_INVALID"
    assert wfx.fake.calls == []


def test_get_execution_state(wfx):
    name = _ex(MAIN, "x")
    wfx.fake.states[name] = "FAILED"
    assert wfx.get_execution_state(name) == "FAILED"


# --------------------------------------------------------------------------------- the Emergency Stop route itself
class _Doc:
    def __init__(self, db, path):
        self.db, self.path, self.id = db, path, path.rsplit("/", 1)[-1]

    def get(self):
        data = self.db.docs.get(self.path)
        return SimpleNamespace(id=self.id, exists=data is not None, update_time=None,
                               to_dict=lambda: copy.deepcopy(data))

    def set(self, data, merge=False):
        cur = self.db.docs.setdefault(self.path, {}) if merge else {}
        cur.update(copy.deepcopy(data))
        self.db.docs[self.path] = cur


class _Coll:
    def __init__(self, db, path):
        self.db, self.path = db, path

    def document(self, doc_id):
        return _Doc(self.db, f"{self.path}/{doc_id}")

    def stream(self):
        prefix = self.path + "/"
        for p in sorted(self.db.docs):
            if p.startswith(prefix) and "/" not in p[len(prefix):]:
                d = self.db.docs[p]
                yield SimpleNamespace(id=p[len(prefix):], to_dict=lambda d=d: copy.deepcopy(d))


class FakeDB:
    def __init__(self):
        self.docs = {"workloads/app": {"status": "ACTIVE", "code_freeze": False, "sre_auto_healing_enabled": True}}

    def collection(self, name):
        return _Coll(self, name)


@pytest.fixture
def st(wfx, monkeypatch):
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    monkeypatch.setattr(cc_db, "_db_client", False)
    from routes import settings as st_mod
    monkeypatch.setattr(st_mod, "PROJECT_ID", PROJECT)
    db = FakeDB()
    monkeypatch.setattr(st_mod, "db", db)
    st_mod.fake_db = db
    return st_mod


def _engage(st):
    request = SimpleNamespace(state=SimpleNamespace(user_role=st.UserRole.ADMIN, user_email="admin@example.com"))
    return st.toggle_emergency_stop_api(st.EmergencyStopRequest(activate=True, reason="incident"), request)


def test_engage_cancels_running_executions_and_reports_ok(st, wfx):
    wfx.fake.active.update({MAIN: [_ex(MAIN, "m1")], SRE: [_ex(SRE, "s1")]})
    r = _engage(st)
    assert r.emergency_stop_active is True and r.workloads_frozen_count == 1
    assert r.workflows_cancelled_count == 2 and r.workflows_cancel_status == "OK"
    assert r.workflows_cancel_failed_count == 0 and r.workflow_list_failures == []
    assert [x["outcome"] for x in r.workflow_cancel_results] == ["CANCELLED", "CANCELLED"]
    rec = st.fake_db.docs["governance/platform_kill_switch"]["last_engage_result"]
    assert rec["workflows_cancelled"] == 2 and rec["workflows_cancel_status"] == "OK"


def test_engage_never_reports_ok_when_a_cancel_failed(st, wfx):
    names = [_ex(MAIN, "a"), _ex(MAIN, "b")]
    wfx.fake.active.update({MAIN: names})
    wfx.fake.cancel_errors[names[0]] = _err(503, "UNAVAILABLE")
    r = _engage(st)
    assert r.workflows_cancel_status == "WORKFLOW_CANCEL_FAILED"
    assert r.workflows_cancelled_count == 1 and r.workflows_cancel_failed_count == 1
    failed = [x for x in r.workflow_cancel_results if x["outcome"] == "FAILED"]
    assert failed[0]["name"] == names[0] and failed[0]["reason"] == "WORKFLOW_CANCEL_FAILED"
    rec = st.fake_db.docs["governance/platform_kill_switch"]["last_engage_result"]
    assert rec["workflows_cancel_status"] == "WORKFLOW_CANCEL_FAILED"
    assert rec["workflow_cancel_failures"][0]["name"] == names[0]
    # The kill switch and the freeze still happened (they do not depend on the cancel).
    assert st.fake_db.docs["governance/platform_kill_switch"]["emergency_stop_active"] is True
    assert st.fake_db.docs["workloads/app"]["code_freeze"] is True


def test_engage_reports_permission_denied_typed(st, wfx):
    wfx.fake.list_errors[MAIN] = _err(403, "PERMISSION_DENIED")
    wfx.fake.list_errors[SRE] = _err(403, "PERMISSION_DENIED")
    r = _engage(st)
    assert r.workflows_cancel_status == "WORKFLOW_CANCEL_NOT_PERMITTED" and r.workflows_cancelled_count == 0
    assert len(r.workflow_list_failures) == 2 and r.workflows_cancel_detail


def test_get_while_engaged_returns_the_engage_cancel_status(st, wfx):
    wfx.fake.list_errors[MAIN] = _err(500, "INTERNAL")
    _engage(st)
    req = SimpleNamespace(state=SimpleNamespace(user_role=st.UserRole.ADMIN, user_email="u@example.com"))
    g = st.get_emergency_stop_status(req)
    assert g.emergency_stop_active is True and g.workflows_cancel_status == "WORKFLOW_LIST_FAILED"
    assert MAIN in g.workflows_cancel_detail


def test_old_response_shape_still_validates(st):
    r = st.EmergencyStopResponse(emergency_stop_active=True, status="ACTIVE", workflows_cancelled_count=1)
    assert r.workflows_cancel_status is None and r.workflow_cancel_results == []


# ------------------------------------------------------------------------------------- packaging (the root cause)
def _cc_python_files():
    for root, dirs, files in os.walk(CC_DIR):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", "node_modules")]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(root, f)


def test_control_center_never_imports_the_workflows_client_library():
    """google-cloud-workflows is not in apps/control-center/requirements.txt; any import of it fails in the image."""
    reqs = open(os.path.join(CC_DIR, "requirements.txt"), encoding="utf-8").read().lower()
    assert "google-cloud-workflows" not in reqs  # if it is ever added, this test (and the REST helper) can be revisited
    offenders = []
    for path in _cc_python_files():
        tree = ast.parse(open(path, encoding="utf-8").read(), filename=path)
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            for m in mods:
                if m == "google.cloud.workflows" or m.startswith(("google.cloud.workflows.", "google.cloud.workflows_")):
                    offenders.append(f"{os.path.relpath(path, REPO_ROOT)}:{node.lineno} {m}")
    assert not offenders, offenders


def test_the_rest_helper_needs_only_packages_in_the_image():
    """workflow_executions.py imports only the standard library and google-auth (google-auth + requests are pinned)."""
    reqs = open(os.path.join(CC_DIR, "requirements.txt"), encoding="utf-8").read().lower()
    assert "google-auth" in reqs and "requests" in reqs
    tree = ast.parse(open(os.path.join(CC_DIR, "workflow_executions.py"), encoding="utf-8").read())
    third_party = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            third_party.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            third_party.add(node.module.split(".")[0])
    assert third_party <= {"__future__", "logging", "urllib", "typing", "google", "routes"}, third_party


UUID = "3f2a9c1e-0b4d-4c55-9a1e-2b7c8d9e0f11"
BUILT = f"projects/{PROJECT}/locations/{REGION}/workflows/{MAIN}/executions/{UUID}"


def _gw_record(**extra):
    """Exactly what the gateway stores: workflow_execution_id = response.name.split("/")[-1] (a bare id; the workflow's
    own callbacks write GOOGLE_CLOUD_WORKFLOW_EXECUTION_ID, also bare). Records from before SAT-43 have no name."""
    rec = {"product_id": "app", "status": "ACTIVE", "workflow_execution_id": BUILT.split("/")[-1]}
    rec.update(extra)
    return rec


def test_execution_name_of_builds_the_name_from_the_bare_gateway_id(wfx):
    assert wfx.execution_name_of(_gw_record(), PROJECT) == BUILT


def test_execution_name_of_prefers_the_stored_full_name(wfx):
    stored = _ex(MAIN, UUID, project_number="247512")
    assert wfx.execution_name_of(_gw_record(workflow_execution_name=stored), PROJECT) == stored


def test_a_stored_name_of_another_execution_is_not_used(wfx):
    assert wfx.execution_name_of(_gw_record(workflow_execution_name=_ex(MAIN, "older-run")), PROJECT) == BUILT


def test_execution_name_of_unbound_invalid_and_unconfigured(wfx):
    assert wfx.execution_name_of({"status": "ACTIVE"}, PROJECT) is None
    with pytest.raises(wfx.WorkflowExecutionsError) as e:
        wfx.execution_name_of({"workflow_execution_id": "a/b"}, PROJECT)
    assert e.value.code == "WORKFLOW_EXECUTION_NAME_INVALID"
    with pytest.raises(wfx.WorkflowExecutionsError) as e:
        wfx.execution_name_of(_gw_record(), "")
    assert e.value.code == "WORKFLOW_CANCEL_UNCONFIGURED"


# ---------------------------------------------------------------------------------------- F3-F7 (review 11-02)
def test_an_unexpected_error_is_a_typed_result_not_a_crash(wfx, monkeypatch):
    class Odd(FakeWorkflows):
        def get(self, url, timeout=None):
            return object()  # no status_code: an AttributeError deep inside
    monkeypatch.setattr(wfx, "session_provider", lambda: Odd())
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "WORKFLOW_CANCEL_FAILED" and r["detail"].startswith("unexpected: AttributeError")


def test_page_cap_overflow_still_cancels_what_was_listed(wfx, monkeypatch):
    monkeypatch.setattr(wfx, "MAX_PAGES", 1)
    names = [_ex(MAIN, f"m{i}") for i in range(3)]  # 2 per page: page 1 listed, page 2 over the cap
    wfx.fake.active.update({MAIN: names})
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "WORKFLOW_LIST_FAILED"
    assert wfx.fake.cancels()[:2] == names[:2] and r["cancelled"] >= 2
    assert any(f["workflow"] == MAIN and "only the first 2" in f["detail"] for f in r["list_failures"])


def test_a_listed_execution_that_is_no_longer_active_is_accounted_as_finished(wfx):
    name = _ex(MAIN, "ended")
    wfx.fake.active.update({MAIN: [name]})
    wfx.fake.listed_states[name] = "SUCCEEDED"
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "OK" and r["already_finished"] == 1 and wfx.fake.cancels() == []
    assert r["executions"][0]["outcome"] == "ALREADY_FINISHED" and r["executions"][0]["state"] == "SUCCEEDED"


def test_a_cancel_answered_200_but_still_active_is_a_failure(wfx):
    name = _ex(MAIN, "stuck")
    wfx.fake.active.update({MAIN: [name]})
    wfx.fake.cancel_states[name] = "ACTIVE"
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "WORKFLOW_CANCEL_FAILED" and r["cancelled"] == 0 and r["failed"] == 1
    assert "HTTP 200 but the execution is ACTIVE" in r["executions"][0]["detail"]


def test_the_second_pass_cancels_a_run_that_started_during_the_engage(wfx):
    first, late = _ex(MAIN, "first"), _ex(MAIN, "late")
    wfx.fake.active.update({MAIN: [first]})
    wfx.fake.late[MAIN] = [late]
    r = wfx.cancel_active_platform_workflows(PROJECT)
    assert r["status"] == "OK" and r["cancelled"] == 2 and wfx.fake.cancels() == [first, late]
    assert [(x["name"], x["pass"]) for x in r["executions"]] == [(first, 1), (late, 2)]


# ------------------------------------------------------------------- the other cancel sites (same helper, same types)
class _RunDoc:
    def __init__(self, data):
        self.id = "trace-1"
        self.exists = True
        self._data = data
        self.writes = []
        self.reference = self

    def to_dict(self):
        return dict(self._data)

    def get(self):
        return self

    def set(self, data, merge=False):
        self.writes.append(data)


class _RunsDB:
    """pipeline_executions/<trace> is `doc`; every other document (audit logs) just accepts writes."""

    def __init__(self, doc):
        self.doc = doc

    def collection(self, name):
        db = self

        class _C:
            def document(self, *_a):
                return db.doc if name == "pipeline_executions" else _RunDoc({})

            def collection(self, *_a):
                return self

            def where(self, *_a, **_k):
                return self

            def stream(self):
                return [db.doc]
        return _C()


@pytest.fixture
def cc_env(wfx, monkeypatch):
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    monkeypatch.setattr(cc_db, "_db_client", False)
    return wfx


def _abort(monkeypatch, record):
    from routes import telemetry
    doc = _RunDoc(record)
    monkeypatch.setattr(telemetry, "db", _RunsDB(doc))
    monkeypatch.setattr(telemetry, "PROJECT_ID", PROJECT)
    monkeypatch.setattr(telemetry, "verify_workload_access", lambda *a, **k: True)
    req = SimpleNamespace(state=SimpleNamespace(user_email="admin@example.com"))
    return doc, (lambda: telemetry.abort_pipeline_execution("trace-1", req))


def test_abort_with_the_gateway_bare_id_cancels_the_execution(cc_env, monkeypatch):
    doc, call = _abort(monkeypatch, _gw_record())
    res = call()
    assert cc_env.fake.cancels() == [BUILT]
    assert res["status"] == "ABORTED" and res["workflow_cancel_status"] == "OK"
    assert "successfully aborted" in res["message"]
    assert doc.writes[0]["status"] == "ABORTED" and doc.writes[0]["workflow_cancel"]["outcome"] == "CANCELLED"


def test_abort_uses_the_stored_full_name_when_present(cc_env, monkeypatch):
    stored = _ex(MAIN, UUID, project_number="247512")
    _, call = _abort(monkeypatch, _gw_record(workflow_execution_name=stored))
    assert call()["workflow_cancel_status"] == "OK" and cc_env.fake.cancels() == [stored]


@pytest.mark.parametrize("resp,code", [(_err(500, "INTERNAL"), "WORKFLOW_CANCEL_FAILED"),
                                       (_err(403, "PERMISSION_DENIED"), "WORKFLOW_CANCEL_NOT_PERMITTED")])
def test_abort_fails_closed_when_the_execution_could_not_be_cancelled(cc_env, monkeypatch, resp, code):
    cc_env.fake.cancel_errors[BUILT] = resp  # the execution stays ACTIVE
    doc, call = _abort(monkeypatch, _gw_record())
    with pytest.raises(Exception) as e:
        call()
    assert getattr(e.value, "status_code", None) == 502
    assert e.value.detail["code"] == code and "NOT aborted" in e.value.detail["message"]
    assert all(w.get("status") != "ABORTED" for w in doc.writes)
    assert doc.writes == [{"abort_attempt": {"at": doc.writes[0]["abort_attempt"]["at"], "by": "admin@example.com",
                                             "workflow_cancel": {"name": BUILT, "outcome": "FAILED", "reason": code,
                                                                 "detail": doc.writes[0]["abort_attempt"]
                                                                 ["workflow_cancel"]["detail"],
                                                                 "state": doc.writes[0]["abort_attempt"]
                                                                 ["workflow_cancel"]["state"]}}}]


def test_abort_of_an_execution_that_already_ended_marks_the_run_aborted(cc_env, monkeypatch):
    cc_env.fake.cancel_errors[BUILT] = _err(400, "FAILED_PRECONDITION")
    cc_env.fake.states[BUILT] = "SUCCEEDED"
    doc, call = _abort(monkeypatch, _gw_record())
    res = call()
    assert res["status"] == "ABORTED" and res["workflow_cancel"]["outcome"] == "ALREADY_FINISHED"
    assert doc.writes[0]["status"] == "ABORTED"


def test_abort_without_a_bound_execution_marks_the_run_aborted(cc_env, monkeypatch):
    doc, call = _abort(monkeypatch, {"product_id": "app", "status": "ACTIVE"})
    res = call()
    assert res["status"] == "ABORTED" and res["workflow_cancel_status"] is None and cc_env.fake.calls == []


def _cascade(monkeypatch, record):
    from routes import workloads
    doc = _RunDoc(record)
    monkeypatch.setattr(workloads, "db", _RunsDB(doc))
    monkeypatch.setattr(workloads, "PROJECT_ID", PROJECT)
    failures = []
    n = workloads.cancel_workload_active_executions("app", "admin@example.com", "decommissioned", failures=failures)
    return doc, n, failures


def test_decommission_cascade_with_the_gateway_bare_id_cancels_and_aborts(cc_env, monkeypatch):
    doc, n, failures = _cascade(monkeypatch, _gw_record())
    assert n == 1 and failures == [] and cc_env.fake.cancels() == [BUILT]
    assert doc.writes[0]["status"] == "ABORTED" and doc.writes[0]["workflow_cancel"]["outcome"] == "CANCELLED"


def test_decommission_cascade_fails_closed_and_reports_the_run(cc_env, monkeypatch):
    cc_env.fake.cancel_errors[BUILT] = _err(503, "UNAVAILABLE")
    doc, n, failures = _cascade(monkeypatch, _gw_record())
    assert n == 0
    assert failures == [{"trace_id": "trace-1", "execution": BUILT, "reason": "WORKFLOW_CANCEL_FAILED",
                         "detail": failures[0]["detail"]}]
    assert all(w.get("status") != "ABORTED" for w in doc.writes)
    assert doc.writes[0]["abort_attempt"]["workflow_cancel"]["reason"] == "WORKFLOW_CANCEL_FAILED"


def test_decommission_cascade_note_names_the_runs(cc_env):
    from routes import workloads
    note = workloads._cascade_failure_note([{"trace_id": "trace-1", "reason": "WORKFLOW_CANCEL_FAILED"}])
    assert "NOT aborted" in note and "trace-1 (WORKFLOW_CANCEL_FAILED)" in note


def test_stale_run_reconcile_reads_the_state_from_the_bare_gateway_id(cc_env, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from unittest.mock import MagicMock
    from routes import telemetry
    ten_min_ago = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    run = MagicMock()
    run.id = "trace-1"
    run.to_dict.return_value = _gw_record(current_stage="DEVELOPER", started_at=ten_min_ago,
                                          last_heartbeat_at=ten_min_ago)
    cc_env.fake.states[BUILT] = "SUCCEEDED"
    workload = MagicMock(exists=True)
    workload.to_dict.return_value = {"status": "ACTIVE"}

    def col(name):
        c = MagicMock()
        if name == "pipeline_executions":
            c.where.return_value.stream.return_value = [run]
            c.where.return_value.where.return_value.stream.return_value = [run]
            c.order_by.return_value.limit.return_value.stream.return_value = []
        elif name == "workloads":
            c.document.return_value.get.return_value = workload
        return c
    db = MagicMock()
    db.collection.side_effect = col
    monkeypatch.setattr(telemetry, "db", db)
    monkeypatch.setattr(telemetry, "PROJECT_ID", PROJECT)
    monkeypatch.setattr(telemetry, "_wf_check_cache", {})
    telemetry.get_active_pipeline_executions()
    assert ("GET", f"{API}/{BUILT}") in cc_env.fake.calls
    # STALE-RUN-AUTOFAIL-BOUND (RT F3): the reconcile is a write conditional on the record's version as read
    run.reference.update.assert_called_once()
    assert run.reference.update.call_args[0][0]["status"] == "SUCCEEDED"
    assert run.reference.update.call_args[1]["option"] is db.write_option.return_value


# ------------------------------------- Flight Deck "Check 1" phantom auto-abort (fail closed, coordinator 11-02)
def _phantom_poll(monkeypatch, record, parent_status="DECOMMISSIONED"):
    """One Flight Deck active poll over one run whose parent workload is `parent_status`. Returns (run, response)."""
    from unittest.mock import MagicMock
    from routes import telemetry
    run = MagicMock()
    run.id = "trace-1"
    run.to_dict.return_value = dict(record, current_stage="DEVELOPER", started_at="2026-11-02T00:00:00+00:00")
    workload = MagicMock(exists=parent_status != "NOT_FOUND")
    workload.to_dict.return_value = {"status": parent_status}

    def col(name):
        c = MagicMock()
        if name == "pipeline_executions":
            c.where.return_value.stream.return_value = [run]
            c.where.return_value.where.return_value.stream.return_value = [run]
            c.order_by.return_value.limit.return_value.stream.return_value = []
        elif name == "workloads":
            c.document.return_value.get.return_value = workload
        return c
    db = MagicMock()
    db.collection.side_effect = col
    monkeypatch.setattr(telemetry, "db", db)
    monkeypatch.setattr(telemetry, "PROJECT_ID", PROJECT)
    return run, telemetry.get_active_pipeline_executions()


@pytest.fixture
def phantom_env(cc_env, monkeypatch):
    from routes import telemetry
    monkeypatch.setattr(telemetry, "_phantom_cancel_cache", {})
    monkeypatch.setattr(telemetry, "_wf_check_cache", {})
    return cc_env


@pytest.mark.parametrize("parent_status", ["DECOMMISSIONED", "ARCHIVED", "NOT_FOUND"])
def test_phantom_run_is_cancelled_then_aborted(phantom_env, monkeypatch, parent_status):
    run, _ = _phantom_poll(monkeypatch, _gw_record(), parent_status)
    assert phantom_env.fake.cancels() == [BUILT]
    written = run.reference.set.call_args[0][0]
    assert written["status"] == "ABORTED" and written["workflow_cancel"]["outcome"] == "CANCELLED"


def test_phantom_run_whose_execution_already_ended_is_aborted(phantom_env, monkeypatch):
    phantom_env.fake.cancel_errors[BUILT] = _err(400, "FAILED_PRECONDITION")
    phantom_env.fake.states[BUILT] = "FAILED"
    run, _ = _phantom_poll(monkeypatch, _gw_record())
    assert run.reference.set.call_args[0][0]["status"] == "ABORTED"


def test_phantom_run_without_a_bound_execution_is_aborted_without_a_call(phantom_env, monkeypatch):
    run, _ = _phantom_poll(monkeypatch, {"product_id": "app", "status": "ACTIVE"})
    assert run.reference.set.call_args[0][0]["status"] == "ABORTED" and phantom_env.fake.calls == []


def test_phantom_run_fails_closed_and_retries_at_most_once_per_window(phantom_env, monkeypatch, caplog):
    from routes import telemetry
    phantom_env.fake.cancel_errors[BUILT] = _err(403, "PERMISSION_DENIED")
    with caplog.at_level("ERROR"):
        run, res = _phantom_poll(monkeypatch, _gw_record())
    writes = [c[0][0] for c in run.reference.set.call_args_list]
    assert all(w.get("status") != "ABORTED" for w in writes)
    attempt = writes[0]["abort_attempt"]
    assert attempt["workflow_cancel"]["reason"] == "WORKFLOW_CANCEL_NOT_PERMITTED" and attempt["by"]
    assert res.total_active == 1  # still shown as running: it may be
    errors = [r for r in caplog.records if "NOT aborted" in r.getMessage()]
    assert len(errors) == 1 and "WORKFLOW_CANCEL_NOT_PERMITTED" in errors[0].getMessage()

    # The next poll inside the window: no call, no write, no log.
    calls_before = len(phantom_env.fake.calls)
    caplog.clear()
    with caplog.at_level("ERROR"):
        run2, _ = _phantom_poll(monkeypatch, _gw_record())
    assert len(phantom_env.fake.calls) == calls_before and run2.reference.set.call_count == 0
    assert not [r for r in caplog.records if "NOT aborted" in r.getMessage()]

    # After the window it retries; once the cancel works the run is aborted.
    telemetry._phantom_cancel_cache["trace-1"] -= telemetry._PHANTOM_CANCEL_RETRY_SECONDS + 1
    del phantom_env.fake.cancel_errors[BUILT]
    run3, _ = _phantom_poll(monkeypatch, _gw_record())
    assert run3.reference.set.call_args[0][0]["status"] == "ABORTED"
    assert "trace-1" not in telemetry._phantom_cancel_cache
