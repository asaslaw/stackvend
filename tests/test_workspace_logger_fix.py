"""
mcp-workspace-connector: undefined ``logger`` in ``mcp-servers/workspace/main.py`` (lane 14 PR-2b RT finding 7) and
the fake-success fallbacks that the NameError was hiding.

Reproduces on the pre-fix code:
- ``POST /request-approval`` with ``PROJECT_ID`` set raises ``NameError: logger`` on its SUCCESS path;
- ``POST /append-status`` with a Docs failure is a 500 ``NameError`` instead of a coded response.
Then pins the fixed contract: every failure is a non-2xx with a TOP-LEVEL ``error_class``; nothing reports success
for an action that failed (no ``APPROVAL_RECORDED_FALLBACK`` / ``ERROR_SUPPRESSED``); the routes are kept.

And the caller: ``workflows/main_orchestrator.yaml`` ``await_human_approval`` must neither continue the build on a
typed error (it goes to the DLQ) nor continue the build after a 200 without a human decision (it suspends on the
Control Center approval callback gate).

Hermetic: main.py's module-level ``WorkspaceService()`` gets mock Drive/Docs clients; Firestore is a stub behind
``main._firestore_client`` (no real client is ever built).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import logging
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parent.parent
WS_DIR = REPO / "mcp-servers" / "workspace"
WORKFLOW = REPO / "workflows" / "main_orchestrator.yaml"


def _load_workspace():
    spec = importlib.util.spec_from_file_location("wslog_ws_service", WS_DIR / "service.py")
    real_service = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(real_service)

    shim = types.ModuleType("service")
    shim.WorkspaceService = lambda: real_service.WorkspaceService(drive_service=MagicMock(), docs_service=MagicMock())
    shim.InvalidDriveIdError = real_service.InvalidDriveIdError   # FD-4AG-b: main.py imports it
    # FD-4BM: main.py imports the incident document module (pure; loaded from its file, not from sys.path)
    doc_spec = importlib.util.spec_from_file_location("wslog_ws_incident_doc", WS_DIR / "incident_doc.py")
    incident_doc = importlib.util.module_from_spec(doc_spec)
    doc_spec.loader.exec_module(incident_doc)
    saved = {name: sys.modules.get(name) for name in ("service", "incident_doc")}
    sys.modules["service"] = shim
    sys.modules["incident_doc"] = incident_doc
    try:
        spec = importlib.util.spec_from_file_location("wslog_ws_main", WS_DIR / "main.py")
        main_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(main_mod)
    finally:
        for name, mod in saved.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod
    return real_service, main_mod


ws_service, ws_main = _load_workspace()

APPROVAL_BODY = {
    "trace_id": "tr-1234abcd",
    "spec_doc_id": "1SpecDocId",
    "cost_delta_monthly": "+$412.00/mo",
    "risk_assessment": "High-cost dedicated infrastructure detected (GKE). Tier 3 Human-in-the-Loop approval required.",
}


class _FakeFirestore:
    def __init__(self, fail=False):
        self.fail = fail
        self.writes = []

    def collection(self, name):
        fs = self

        class _Doc:
            def __init__(self, doc_id):
                self.doc_id = doc_id

            def set(self, data, merge=False):
                if fs.fail:
                    raise RuntimeError("firestore unavailable")
                fs.writes.append((name, self.doc_id, data, merge))

        class _Coll:
            def document(self, doc_id):
                return _Doc(doc_id)

        return _Coll()


@pytest.fixture
def ws(monkeypatch):
    docs = MagicMock()
    docs.documents.return_value.get.return_value.execute.return_value = {"body": {"content": [{"endIndex": 10}]}}
    svc = ws_service.WorkspaceService(drive_service=MagicMock(), docs_service=docs)
    monkeypatch.setattr(ws_main, "service", svc)
    fs = _FakeFirestore()
    monkeypatch.setattr(ws_main, "_firestore_client", lambda project_id: fs, raising=False)
    # Belt and braces (and what lets this file reproduce the NameError on the pre-fix main.py, which imports
    # google.cloud.firestore inline): any ``from google.cloud import firestore`` gets the stub, never a real client.
    fake_fs_mod = types.ModuleType("google.cloud.firestore")
    fake_fs_mod.Client = lambda *a, **k: fs
    import google.cloud
    monkeypatch.setitem(sys.modules, "google.cloud.firestore", fake_fs_mod)
    monkeypatch.setattr(google.cloud, "firestore", fake_fs_mod, raising=False)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    return types.SimpleNamespace(client=TestClient(ws_main.app), docs=docs, fs=fs)


def _batch_update(ws):
    return ws.docs.documents.return_value.batchUpdate


# ---------------------------------------------------------------------------------------------------------------
# The logger itself
# ---------------------------------------------------------------------------------------------------------------
def test_main_defines_module_logger_like_service():
    assert isinstance(ws_main.logger, logging.Logger)
    assert ws_main.logger.name == "mcp-workspace-connector" == ws_service.logger.name


# ---------------------------------------------------------------------------------------------------------------
# /request-approval
# ---------------------------------------------------------------------------------------------------------------
def test_request_approval_success_with_project_id_is_200_not_nameerror(ws):
    """Repro: pre-fix, the logger.info after a successful Firestore write raised NameError (-> 500)."""
    r = ws.client.post("/request-approval", json=APPROVAL_BODY)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "APPROVAL_REQUESTED"
    assert body["document_id"] == "1SpecDocId"
    assert body["approval_id"] == "appr-tr-1234abcd"
    [(coll, doc_id, data, merge)] = ws.fs.writes
    assert (coll, doc_id, data["status"], merge) == ("approval_requests", "appr-tr-1234abcd", "PENDING", True)
    assert _batch_update(ws).call_count == 1


def test_request_approval_without_doc_records_pending_only(ws):
    r = ws.client.post("/request-approval", json={**APPROVAL_BODY, "spec_doc_id": "  "})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "APPROVAL_RECORDED_CONTROL_CENTER"
    assert body["approval_status"] == "PENDING" and body["approval_id"] == "appr-tr-1234abcd"
    assert "not an approval" in body["message"]
    assert len(ws.fs.writes) == 1
    assert _batch_update(ws).call_count == 0


def test_request_approval_persist_failure_is_typed_502_and_posts_no_callout(ws, caplog):
    ws.fs.fail = True
    with caplog.at_level(logging.WARNING, logger="mcp-workspace-connector"):
        r = ws.client.post("/request-approval", json=APPROVAL_BODY)
    assert r.status_code == 502
    body = r.json()
    assert body["error_class"] == "APPROVAL_PERSIST_FAILED" and body["status"] == "FAILED"
    assert "firestore unavailable" in body["detail"]
    assert _batch_update(ws).call_count == 0
    assert {rec.levelname for rec in caplog.records if rec.name == "mcp-workspace-connector"} == {"WARNING"}


def test_request_approval_callout_failure_is_typed_502_never_fallback_success(ws):
    _batch_update(ws).return_value.execute.side_effect = RuntimeError("docs 403")
    r = ws.client.post("/request-approval", json=APPROVAL_BODY)
    assert r.status_code == 502
    body = r.json()
    assert body["error_class"] == "APPROVAL_CALLOUT_FAILED"
    assert body["approval_id"] == "appr-tr-1234abcd" and body["document_id"] == "1SpecDocId"
    assert "APPROVAL_RECORDED" not in r.text


def test_request_approval_without_project_id_and_without_doc_is_typed_503(ws, monkeypatch):
    monkeypatch.delenv("PROJECT_ID", raising=False)
    r = ws.client.post("/request-approval", json={**APPROVAL_BODY, "spec_doc_id": ""})
    assert r.status_code == 503
    assert r.json()["error_class"] == "APPROVAL_NOT_RECORDED"
    assert ws.fs.writes == []


def test_request_approval_without_project_id_posts_callout_only(ws, monkeypatch):
    monkeypatch.delenv("PROJECT_ID", raising=False)
    r = ws.client.post("/request-approval", json=APPROVAL_BODY)
    assert r.status_code == 200
    assert r.json() == {"document_id": "1SpecDocId", "status": "APPROVAL_REQUESTED"}
    assert ws.fs.writes == []


# ---------------------------------------------------------------------------------------------------------------
# AG-7 (bundle RT F4): the workflow gate owns the approval record -> the workspace only notifies (one card)
# ---------------------------------------------------------------------------------------------------------------
GATE_ID = "appr-plan-tr-1234abcd-0"


def test_request_approval_with_gate_id_posts_callout_and_writes_no_record(ws):
    r = ws.client.post("/request-approval", json={**APPROVAL_BODY, "approval_id": GATE_ID})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "APPROVAL_REQUESTED" and body["approval_id"] == GATE_ID
    assert ws.fs.writes == []  # no second (orphan) approval card
    assert _batch_update(ws).call_count == 1


def test_request_approval_with_gate_id_callout_failure_is_typed_502(ws):
    _batch_update(ws).return_value.execute.side_effect = RuntimeError("docs 403")
    r = ws.client.post("/request-approval", json={**APPROVAL_BODY, "approval_id": GATE_ID})
    assert r.status_code == 502
    body = r.json()
    assert body["error_class"] == "APPROVAL_CALLOUT_FAILED" and body["approval_id"] == GATE_ID
    assert ws.fs.writes == []


def test_request_approval_with_gate_id_and_no_doc_writes_and_posts_nothing(ws):
    r = ws.client.post("/request-approval", json={**APPROVAL_BODY, "spec_doc_id": "", "approval_id": GATE_ID})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "SKIPPED" and body["approval_id"] == GATE_ID and "not an approval" in body["message"]
    assert ws.fs.writes == [] and _batch_update(ws).call_count == 0


@pytest.mark.parametrize("gate_id", [None, "", "   "])
def test_request_approval_without_gate_id_keeps_ws1_behaviour(ws, gate_id):
    """Older workflow revisions / the MCP tool send no approval_id: the WS-1 record is still written."""
    body = dict(APPROVAL_BODY) if gate_id is None else {**APPROVAL_BODY, "approval_id": gate_id}
    r = ws.client.post("/request-approval", json=body)
    assert r.status_code == 200 and r.json()["approval_id"] == "appr-tr-1234abcd"
    assert len(ws.fs.writes) == 1


def test_await_human_approval_passes_the_gate_approval_id(wf):
    body, _ = wf["await_human_approval"]
    assert body["try"]["args"]["body"]["approval_id"] == "${plan_approval_id}"


# ---------------------------------------------------------------------------------------------------------------
# /append-status
# ---------------------------------------------------------------------------------------------------------------
def test_append_status_docs_failure_is_typed_502_not_500(ws, caplog):
    """Repro: pre-fix, the except path's logger.warning raised NameError (-> 500)."""
    _batch_update(ws).return_value.execute.side_effect = RuntimeError("docs quota")
    with caplog.at_level(logging.WARNING, logger="mcp-workspace-connector"):
        r = ws.client.post("/append-status", json={"document_id": "1SpecDocId", "status_text": "plan"})
    assert r.status_code == 502
    body = r.json()
    assert body["error_class"] == "DOC_APPEND_FAILED" and body["document_id"] == "1SpecDocId"
    assert "ERROR_SUPPRESSED" not in r.text
    assert {rec.levelname for rec in caplog.records if rec.name == "mcp-workspace-connector"} == {"WARNING"}


def test_append_status_success_and_skip_unchanged(ws):
    ok = ws.client.post("/append-status", json={"document_id": "1SpecDocId", "status_text": "plan"})
    assert ok.status_code == 200 and ok.json()["status"] == "APPENDED"
    skip = ws.client.post("/append-status", json={"document_id": "", "status_text": "plan"})
    assert skip.status_code == 200 and skip.json()["status"] == "SKIPPED"


def test_routes_kept_and_fake_success_statuses_gone():
    paths = {getattr(route, "path", None) for route in ws_main.app.routes}
    for p in ("/append-status", "/request-approval", "/read-doc", "/list-folder", "/move-doc",
              "/create-incident-spec", "/mcp", "/health"):
        assert p in paths
    src = (WS_DIR / "main.py").read_text()
    assert "APPROVAL_RECORDED_FALLBACK" not in src and "ERROR_SUPPRESSED" not in src


# ---------------------------------------------------------------------------------------------------------------
# Caller: workflows/main_orchestrator.yaml
# ---------------------------------------------------------------------------------------------------------------
def _flatten(steps, follow, out):
    """Name -> (body, implicit fall-through target) for every step, nested try/except steps included."""
    names = [next(iter(s)) for s in steps]
    for i, step in enumerate(steps):
        name, body = next(iter(step.items()))
        nxt = names[i + 1] if i + 1 < len(names) else follow
        out[name] = (body, nxt)
        for key in ("steps",):
            if isinstance(body.get(key), list):
                _flatten(body[key], nxt, out)
        for key in ("try", "except"):
            sub = body.get(key)
            if isinstance(sub, dict) and isinstance(sub.get("steps"), list):
                _flatten(sub["steps"], body.get("next", nxt), out)
    return out


def _edges(name, flat):
    body, fall = flat[name]
    out = set()
    if "switch" in body:
        out |= {c["next"] for c in body["switch"] if "next" in c}
    exc = body.get("except")
    if isinstance(exc, dict) and exc.get("steps"):
        out.add(next(iter(exc["steps"][0])))
    tr = body.get("try")
    if isinstance(tr, dict) and tr.get("steps"):
        out.add(next(iter(tr["steps"][0])))
    if "next" in body:
        out.add(body["next"])
    elif "raise" not in body and "return" not in body and fall:
        out.add(fall)
    return {e for e in out if e != "end"}


@pytest.fixture(scope="module")
def wf():
    doc = yaml.safe_load(WORKFLOW.read_text())
    # Lane 17 PR-2: the pipeline body lives in the `run_pipeline` subworkflow (main = guarded call + failure handler).
    body = doc["run_pipeline"] if "run_pipeline" in doc else doc["main"]
    return _flatten(body["steps"], None, {})


def test_await_human_approval_typed_error_goes_to_dlq(wf):
    body, _ = wf["await_human_approval"]
    assert body["try"]["call"] == "http.post"
    assert body["try"]["args"]["url"] == '${workspace_mcp_url + "/request-approval"}'
    [handler] = body["except"]["steps"]
    hname, hbody = next(iter(handler.items()))
    assert hbody["next"] == "prep_dead_letter_payload"
    assert "error_detail" in hbody["assign"][0]


def test_await_human_approval_success_suspends_on_callback_gate(wf):
    """No path from the approval request reaches the build (quota preflight) without the human callback wait."""
    assert _edges("await_human_approval", wf) >= {"route_finops_hitl_to_approval_gate"}
    seen, stack = set(), ["await_human_approval"]
    while stack:
        n = stack.pop()
        if n in seen or n == "await_plan_approval_callback":
            continue
        seen.add(n)
        stack.extend(_edges(n, wf))
    # Lane 17 PR-2: the callback and its approval record are created BEFORE the Doc callout (the gateway's pre-build
    # gate is the only approval writer); after the callout the run goes straight to the wait.
    assert {"route_finops_hitl_to_approval_gate", "notify_plan_approval_pending"} <= seen
    assert "await_plan_approval_callback" in _edges("notify_plan_approval_pending", wf)
    assert "check_quota_preflight" not in seen
    assert "dispatch_developer_implementation" not in seen


def test_finops_gate_guard_is_initialised_set_and_reset_on_rework(wf):
    init = {k: v for item in wf["init_context"][0]["assign"] for k, v in item.items()}
    assert init["finops_hitl_requested"] is False
    route = wf["route_finops_hitl_to_approval_gate"][0]
    assert route["assign"] == [{"finops_hitl_requested": True}]
    assert route["next"] == "notify_plan_approval_pending"  # lane 17 PR-2: the callback already exists
    [gate] = [c for c in wf["check_policy_gates"][0]["switch"] if c.get("next") == "await_human_approval"]
    assert "finops_hitl_requested != true" in gate["condition"]
    rework = [c for c in wf["handle_plan_approval_decision"][0]["switch"] if "REWORK" in str(c["condition"])]
    assert rework and {"finops_hitl_requested": False} in rework[0]["assign"]
    assert rework[0]["next"] == "architect_decomposition"
