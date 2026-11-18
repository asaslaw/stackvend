"""
FD-4BM: mcp-workspace-connector ``POST /create-incident-spec`` creates a real incident document.

Pins:
- configured (``IN_PROGRESS_FOLDER_ID``): ONE Drive ``files.create`` (text/html converted to a Google Doc, in the
  folder, shared drives supported, no permission added) whose HTML holds every template section, filled from the
  request and the incident's Firestore records (timeline in time order, failure summary from the pipeline record,
  recommended next steps); values are HTML-escaped; the response carries Drive's id, never another one;
- not configured (no folder, several folders, invalid ids, no Drive client): 503 INCIDENT_TEMPLATE_NOT_CONFIGURED
  with a ``reason``; nothing is sent to Drive; no ``document_id`` key (L14-u kept);
- Drive / Docs error or a response without an id: 502 INCIDENT_DOC_CREATE_FAILED, no ``document_id`` (negative);
- an operator Drive template (``INCIDENT_TEMPLATE_ID``) is copied and its placeholders replaced;
- the caller's contract (``workflows/sre_remediation.yaml``) is unchanged: every body key it sends is accepted and
  its 503 error class is the one the route returns.

Hermetic: real ``service.py`` / ``incident_doc.py`` with fake Drive / Docs clients and a fake Firestore reader (no
real client is ever built; Firestore REST is exercised through a fake ``documents()`` resource).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import html as html_lib
import importlib.util
import logging
import sys
import types
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import MagicMock

import httplib2
import pytest
import yaml
from fastapi.testclient import TestClient
from googleapiclient.errors import HttpError

REPO = Path(__file__).resolve().parent.parent
WS_DIR = REPO / "mcp-servers" / "workspace"
SRE_WORKFLOW = REPO / "workflows" / "sre_remediation.yaml"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_workspace():
    real_service = _load("fd4bm_ws_service", WS_DIR / "service.py")
    incident_doc = _load("fd4bm_ws_incident_doc", WS_DIR / "incident_doc.py")
    shim = types.ModuleType("service")
    shim.WorkspaceService = lambda: real_service.WorkspaceService(drive_service=MagicMock(), docs_service=MagicMock())
    shim.InvalidDriveIdError = real_service.InvalidDriveIdError
    saved = {n: sys.modules.get(n) for n in ("service", "incident_doc")}
    sys.modules["service"] = shim
    sys.modules["incident_doc"] = incident_doc
    try:
        main_mod = _load("fd4bm_ws_main", WS_DIR / "main.py")
    finally:
        for n, mod in saved.items():
            if mod is None:
                sys.modules.pop(n, None)
            else:
                sys.modules[n] = mod
    return real_service, incident_doc, main_mod


ws_service, ws_doc, ws_main = _load_workspace()
ORIGINAL_PIPELINE_READER = ws_main._pipeline_reader

FOLDER = "1InProgressFolder_abc"
DOC_ID = "1RealDriveDocId-xyz"

# Exactly the body workflows/sre_remediation.yaml create_incident_ticket sends (pinned below against the YAML).
BODY = {
    "trace_id": "sre-tr-77aa",
    "incident_id": "inc-1a2b3c4d",
    "product_id": "orders-api",
    "severity": "HIGH",
    "service_name": "orders-api",
    "stack_trace": 'Traceback (most recent call last):\n  File "app.py", line 9, in handler\nKeyError: "sku"',
    "root_cause_summary": "Unhandled KeyError in app.py: \"sku\"",
    "affected_repository": "acme/orders-api",
}

RECORDS = {
    ("incidents", "inc-1a2b3c4d"): {
        "incident_id": "inc-1a2b3c4d", "trace_id": "sre-tr-77aa", "product_id": "orders-api",
        "service_name": "orders-api", "fingerprint_hash": "f00dfeed", "created_at": "2026-10-28T10:05:00+00:00",
        "status": "OPEN", "auto_remediation_status": "DISPATCHED", "error_message": "KeyError: sku",
        "link_status": "LINKED", "linked_pipeline_trace_id": "tr-build-9",
        "rca": {"severity": "HIGH", "recommended_action": "Patch app.py to handle KeyError gracefully and add pytest "
                                                          "regression test.",
                "affected_repository": "acme/orders-api", "root_cause_summary": "Unhandled KeyError in app.py"},
    },
    ("incident_clusters", "f00dfeed"): {"occurrence_count": 3, "last_seen_at": "2026-10-28T10:20:00+00:00",
                                         "created_at": "2026-10-28T10:05:00+00:00"},
    ("pipeline_executions", "tr-build-9"): {
        "status": "FAILED", "started_at": "2026-10-28T09:00:00+00:00", "completed_at": "2026-10-28T09:40:00+00:00",
        "failed_stage": "QA", "error_class": "QA_TESTS_FAILED", "failure_reason": "3 tests failed in test_orders.py"},
    ("workloads", "orders-api"): {"project_id": "orders-api-child-1", "status": "DEPLOYED"},
}

HEADINGS = ["Incident", "Timeline", "Failure summary", "Stack trace", "Recommended next steps", "Record sources"]


class _Exec:
    def __init__(self, fn):
        self._fn = fn

    def execute(self):
        return self._fn()


class FakeDrive:
    """Only files().create / files().copy exist: any other Drive call (permissions, list, ...) is an AttributeError."""

    def __init__(self, create_result=None, create_error=None, copy_error=None):
        self.creates, self.copies = [], []
        self.create_result = {"id": DOC_ID, "name": "t", "webViewLink": f"https://docs.google.com/d/{DOC_ID}"} \
            if create_result is None else create_result
        self.create_error, self.copy_error = create_error, copy_error

    def files(self):
        drive = self

        class _Files:
            def create(self, **kw):
                drive.creates.append(kw)

                def run():
                    if drive.create_error:
                        raise drive.create_error
                    return {**drive.create_result, "name": kw["body"]["name"]} if drive.create_result else {}
                return _Exec(run)

            def copy(self, **kw):
                drive.copies.append(kw)

                def run():
                    if drive.copy_error:
                        raise drive.copy_error
                    return {"id": "1CopiedDoc", "name": kw["body"]["name"], "webViewLink": "https://d/1CopiedDoc"}
                return _Exec(run)
        return _Files()


class FakeDocs:
    def __init__(self):
        self.updates = []

    def documents(self):
        docs = self

        class _Documents:
            def batchUpdate(self, documentId, body):
                docs.updates.append((documentId, body))
                return _Exec(lambda: {"documentId": documentId})
        return _Documents()


class FakeReader:
    def __init__(self, records=None, fail=()):
        self.records = dict(RECORDS if records is None else records)
        self.fail = set(fail)
        self.reads = []

    def get(self, collection, doc_id):
        self.reads.append((collection, doc_id))
        if collection in self.fail:
            raise RuntimeError("firestore down")
        return self.records.get((collection, doc_id))


@pytest.fixture
def ws(monkeypatch):
    drive, docs, reader = FakeDrive(), FakeDocs(), FakeReader()
    monkeypatch.setattr(ws_main, "service", ws_service.WorkspaceService(drive_service=drive, docs_service=docs))
    monkeypatch.setattr(ws_main, "_pipeline_reader", lambda: ws.reader)
    monkeypatch.setenv("IN_PROGRESS_FOLDER_ID", FOLDER)
    monkeypatch.delenv("INCIDENT_TEMPLATE_ID", raising=False)
    ws = types.SimpleNamespace(client=TestClient(ws_main.app), drive=drive, docs=docs, reader=reader)
    return ws


class _Outline(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self._cur = {"h1": [], "h2": [], "li": [], "pre": []}, None

    def handle_starttag(self, tag, attrs):
        if tag in self.tags:
            self._cur = tag
            self.tags[tag].append("")

    def handle_endtag(self, tag):
        if tag == self._cur:
            self._cur = None

    def handle_data(self, data):
        if self._cur:
            self.tags[self._cur][-1] += data


def _uploaded_html(create_call):
    media = create_call["media_body"]
    assert media.mimetype() == "text/html"
    return media.getbytes(0, media.size()).decode("utf-8")


def _outline(text):
    parser = _Outline()
    parser.feed(text)
    return parser.tags


# ---------------------------------------------------------------------------------------------------------------
# Configured: a real document from the built-in template
# ---------------------------------------------------------------------------------------------------------------
def test_doc_created_from_builtin_template_with_every_section(ws):
    r = ws.client.post("/create-incident-spec", json=BODY)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["document_id"] == DOC_ID and body["status"] == "CREATED"
    assert body["folder_id"] == FOLDER and body["template"] == "builtin:incident_doc_template.html"
    assert body["web_view_link"] == f"https://docs.google.com/d/{DOC_ID}"

    assert len(ws.drive.creates) == 1 and ws.drive.copies == [] and ws.docs.updates == []
    call = ws.drive.creates[0]
    assert call["body"] == {"name": "INCIDENT-FIX: orders-api (inc-1a2b3c4d)", "parents": [FOLDER],
                            "mimeType": "application/vnd.google-apps.document"}
    assert call["supportsAllDrives"] is True and call["fields"] == "id, name, webViewLink"

    out = _outline(_uploaded_html(call))
    assert out["h1"] == ["INCIDENT-FIX: orders-api (inc-1a2b3c4d)"]
    assert out["h2"] == HEADINGS
    text = html_lib.unescape(_uploaded_html(call))
    for expected in ("inc-1a2b3c4d", "HIGH", "orders-api (project orders-api-child-1)", "acme/orders-api",
                     "sre-tr-77aa", "tr-build-9", "Unhandled KeyError in app.py", "KeyError: sku",
                     "run tr-build-9; status FAILED; failed stage QA; QA_TESTS_FAILED: 3 tests failed in test_orders.py"):
        assert expected in text, expected
    assert out["pre"] == [BODY["stack_trace"]]

    timeline = [li for li in out["li"] if li.startswith("2026-") or ": Incident document created" in li]
    assert [t.split(": ", 1)[1] for t in timeline[:4]] == [
        "Pipeline run tr-build-9 started",
        "Pipeline run tr-build-9 ended FAILED (failed stage: QA)",
        "Incident recorded by the SRE sentinel (status OPEN, auto-remediation DISPATCHED)",
        "Last occurrence seen (3 occurrences)",
    ]
    assert timeline[4].endswith(": Incident document created")
    steps = out["li"][len(timeline):len(timeline) + 4]
    assert steps[0] == ("Recommended fix (deterministic analysis): Patch app.py to handle KeyError gracefully and "
                        "add pytest regression test.")
    assert steps[1] == "Check the failed stage QA of pipeline run tr-build-9 in Control Center."
    assert "Control Center > Approvals" in steps[2] and "sre-tr-77aa" in steps[3]
    assert ws.reader.reads == [("incidents", "inc-1a2b3c4d"), ("incident_clusters", "f00dfeed"),
                               ("pipeline_executions", "tr-build-9"), ("workloads", "orders-api")]
    assert "incidents/inc-1a2b3c4d: read" in text and "workloads/orders-api: read" in text


def test_values_are_escaped_and_substituted_in_one_pass(ws):
    hostile = dict(BODY, stack_trace="<script>alert(1)</script> ${TITLE} {{INCIDENT_ID}}",
                   service_name="svc<b>")
    r = ws.client.post("/create-incident-spec", json=hostile)
    assert r.status_code == 200, r.text
    raw = _uploaded_html(ws.drive.creates[0])
    assert "<script>" not in raw and "&lt;script&gt;" in raw and "<b>" not in raw.split("<body>")[1].split("<h2>")[0]
    out = _outline(raw)
    assert out["pre"] == ["<script>alert(1)</script> ${TITLE} {{INCIDENT_ID}}"]  # literal, not substituted
    assert len(out["h1"]) == 1 and out["h1"][0] == "INCIDENT-FIX: svc<b> (inc-1a2b3c4d)"


def test_unreadable_records_are_named_never_invented(ws):
    ws.reader.fail = {"incidents"}
    r = ws.client.post("/create-incident-spec", json=BODY)
    assert r.status_code == 200 and r.json()["document_id"] == DOC_ID
    text = html_lib.unescape(_uploaded_html(ws.drive.creates[0]))
    assert "incidents/inc-1a2b3c4d: unavailable (RuntimeError)" in text
    assert "no pipeline record linked to this incident" in text and "tr-build-9" not in text
    assert "Unhandled KeyError in app.py" in text  # from the request


def test_project_id_unset_reads_nothing_and_says_so(ws, monkeypatch):
    monkeypatch.setattr(ws_main, "_pipeline_reader", ORIGINAL_PIPELINE_READER)
    monkeypatch.delenv("PROJECT_ID", raising=False)
    assert ws_main._pipeline_reader() is None
    r = ws.client.post("/create-incident-spec", json=BODY)
    assert r.status_code == 200
    text = html_lib.unescape(_uploaded_html(ws.drive.creates[0]))
    assert "Firestore records: not read (PROJECT_ID is not set on mcp-workspace-connector)" in text


def test_request_folder_wins_and_an_invalid_one_is_422(ws):
    ok = ws.client.post("/create-incident-spec", json=dict(BODY, inbox_folder_id="1CallerFolder"))
    assert ok.status_code == 200 and ws.drive.creates[0]["body"]["parents"] == ["1CallerFolder"]
    bad = ws.client.post("/create-incident-spec", json=dict(BODY, inbox_folder_id="x' or name contains 'y"))
    assert bad.status_code == 422 and bad.json()["error_class"] == "INVALID_DRIVE_ID"
    assert "document_id" not in bad.json() and len(ws.drive.creates) == 1


def test_operator_drive_template_is_copied_and_filled(ws, monkeypatch):
    monkeypatch.setenv("INCIDENT_TEMPLATE_ID", "1OperatorTemplate")
    r = ws.client.post("/create-incident-spec", json=BODY)
    assert r.status_code == 200, r.text
    assert r.json()["document_id"] == "1CopiedDoc" and r.json()["template"] == "drive:1OperatorTemplate"
    assert ws.drive.creates == []
    copy = ws.drive.copies[0]
    assert copy["fileId"] == "1OperatorTemplate" and copy["body"]["parents"] == [FOLDER]
    assert copy["supportsAllDrives"] is True
    (doc_id, update), = ws.docs.updates
    keys = {req["replaceAllText"]["containsText"]["text"] for req in update["requests"]}
    assert doc_id == "1CopiedDoc"
    assert {"{{INCIDENT_ID}}", "{{SEVERITY}}", "{{SERVICE_NAME}}", "{{AFFECTED_REPO}}", "{{ROOT_CAUSE}}",
            "{{STACK_TRACE}}", "{{TIMELINE}}", "{{FAILURE_SUMMARY}}", "{{NEXT_STEPS}}", "{{WORKLOAD}}",
            "{{TRACE_ID}}"} <= keys


# ---------------------------------------------------------------------------------------------------------------
# Not configured: honest 503, nothing sent to Drive
# ---------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("env,reason", [
    ({"IN_PROGRESS_FOLDER_ID": ""}, "FOLDER_NOT_CONFIGURED"),
    ({}, "FOLDER_NOT_CONFIGURED"),
    ({"IN_PROGRESS_FOLDER_ID": "1FolderA,1FolderB"}, "FOLDER_AMBIGUOUS"),
    ({"IN_PROGRESS_FOLDER_ID": "not a folder!"}, "FOLDER_ID_INVALID"),
    ({"IN_PROGRESS_FOLDER_ID": FOLDER, "INCIDENT_TEMPLATE_ID": "bad/id"}, "TEMPLATE_ID_INVALID"),
])
def test_not_configured_is_503_and_nothing_is_created(ws, monkeypatch, caplog, env, reason):
    monkeypatch.delenv("IN_PROGRESS_FOLDER_ID", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with caplog.at_level(logging.INFO, logger="mcp-workspace-connector"):
        r = ws.client.post("/create-incident-spec", json=BODY)
    assert r.status_code == 503
    body = r.json()
    assert body["error_class"] == "INCIDENT_TEMPLATE_NOT_CONFIGURED" and body["reason"] == reason
    assert body["status"] == "FAILED" and "document_id" not in body and body["incident_id"] == "inc-1a2b3c4d"
    assert ws.drive.creates == [] and ws.drive.copies == [] and ws.reader.reads == []
    assert {rec.levelname for rec in caplog.records if rec.name == "mcp-workspace-connector"} == {"WARNING"}


def test_no_drive_client_is_503(ws, monkeypatch):
    monkeypatch.setattr(ws_main, "service", types.SimpleNamespace(drive_service=None, docs_service=None))
    r = ws.client.post("/create-incident-spec", json=BODY)
    assert r.status_code == 503 and r.json()["reason"] == "WORKSPACE_CLIENT_UNAVAILABLE"
    assert "document_id" not in r.json()


# ---------------------------------------------------------------------------------------------------------------
# API errors: typed 502, never an id (negative)
# ---------------------------------------------------------------------------------------------------------------
def _http_error(status, reason):
    content = ('{"error": {"code": %d, "message": "%s", "errors": [{"reason": "%s"}]}}'
               % (status, reason, reason)).encode()
    return HttpError(httplib2.Response({"status": status}), content)


@pytest.mark.parametrize("error", [_http_error(403, "storageQuotaExceeded"), _http_error(404, "notFound"),
                                   RuntimeError("socket timeout")])
def test_drive_error_is_typed_502_without_an_id(ws, caplog, error):
    ws.drive.create_error = error
    with caplog.at_level(logging.INFO, logger="mcp-workspace-connector"):
        r = ws.client.post("/create-incident-spec", json=BODY)
    assert r.status_code == 502
    body = r.json()
    assert body["error_class"] == "INCIDENT_DOC_CREATE_FAILED" and body["folder_id"] == FOLDER
    assert "document_id" not in body and type(error).__name__ in body["detail"]
    assert "mock" not in r.text.lower()
    assert {rec.levelname for rec in caplog.records if rec.name == "mcp-workspace-connector"} == {"WARNING"}


@pytest.mark.parametrize("result", [{"name": "t"}, {"id": ""}, {"id": None}])
def test_drive_response_without_id_is_502(ws, result):
    ws.drive.create_result = result
    r = ws.client.post("/create-incident-spec", json=BODY)
    assert r.status_code == 502 and r.json()["error_class"] == "INCIDENT_DOC_CREATE_FAILED"
    assert "document_id" not in r.json()


def test_operator_template_copy_error_is_502(ws, monkeypatch):
    monkeypatch.setenv("INCIDENT_TEMPLATE_ID", "1OperatorTemplate")
    ws.drive.copy_error = _http_error(404, "notFound")
    r = ws.client.post("/create-incident-spec", json=BODY)
    assert r.status_code == 502 and "document_id" not in r.json() and ws.docs.updates == []


def test_no_fabricated_id_left_in_the_source():
    src = (WS_DIR / "main.py").read_text()
    assert "mock-doc" not in src and "DRAFTED_MOCK" not in src


# ---------------------------------------------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------------------------------------------
def test_template_placeholders_match_the_renderer():
    import re
    names = set(re.findall(r"\$\{([A-Z_]+)\}", ws_doc.TEMPLATE_PATH.read_text()))
    assert names == set(ws_doc.TEXT_KEYS) | set(ws_doc.LIST_KEYS)
    text = ws_doc.TEMPLATE_PATH.read_text()
    assert [h for h in re.findall(r"<h2>([^<]+)</h2>", text)] == HEADINGS


class _FakeDocuments:
    def __init__(self, response=None, error=None):
        self.names, self.response, self.error = [], response, error

    def get(self, name):
        self.names.append(name)

        def run():
            if self.error:
                raise self.error
            return self.response
        return _Exec(run)


def test_firestore_rest_reader_decodes_typed_values():
    docs = _FakeDocuments(response={"name": "x", "fields": {
        "status": {"stringValue": "OPEN"}, "count": {"integerValue": "3"}, "ok": {"booleanValue": True},
        "ratio": {"doubleValue": 0.5}, "none": {"nullValue": None},
        "created_at": {"timestampValue": "2026-10-28T10:05:00Z"},
        "rca": {"mapValue": {"fields": {"severity": {"stringValue": "HIGH"}}}},
        "tags": {"arrayValue": {"values": [{"stringValue": "a"}, {"integerValue": "2"}]}},
        "empty": {"arrayValue": {}}}})
    reader = ws_doc.FirestoreRestReader("mock-stackvend-project", client=docs)
    assert reader.get("incidents", "inc-1") == {
        "status": "OPEN", "count": 3, "ok": True, "ratio": 0.5, "none": None, "created_at": "2026-10-28T10:05:00Z",
        "rca": {"severity": "HIGH"}, "tags": ["a", 2], "empty": []}
    assert docs.names == ["projects/mock-stackvend-project/databases/(default)/documents/incidents/inc-1"]


def test_firestore_rest_reader_404_is_none_other_errors_raise_bad_ids_never_sent():
    assert ws_doc.FirestoreRestReader("p", client=_FakeDocuments(error=_http_error(404, "notFound"))) \
        .get("incidents", "inc-1") is None
    with pytest.raises(HttpError):
        ws_doc.FirestoreRestReader("p", client=_FakeDocuments(error=_http_error(403, "denied"))).get("incidents", "i")
    docs = _FakeDocuments(response={})
    for bad in ("../workloads/x", "a/b", "", "x" * 300):
        with pytest.raises(ValueError):
            ws_doc.FirestoreRestReader("p", client=docs).get("incidents", bad)
    assert docs.names == []


def test_invalid_record_ids_are_not_read():
    reader = FakeReader(records={("incidents", "inc-1"): {"fingerprint_hash": "../x", "product_id": "a/b",
                                                          "linked_pipeline_trace_id": "tr/../1"}})
    records, notes = ws_doc.read_pipeline_records(reader, "inc-1", "")
    assert reader.reads == [("incidents", "inc-1")]
    assert records["cluster"] is None and records["pipeline"] is None and records["workload"] is None
    assert "incident_clusters: not read (no valid record id)" in notes


# ---------------------------------------------------------------------------------------------------------------
# Caller contract: workflows/sre_remediation.yaml (not changed by FD-4BM)
# ---------------------------------------------------------------------------------------------------------------
def _find_step(steps, name):
    for step in steps:
        (key, body), = step.items()
        if key == name:
            return body
        for nested in ("steps",):
            if isinstance(body, dict) and nested in body:
                found = _find_step(body[nested], name)
                if found is not None:
                    return found
        if isinstance(body, dict):
            for part in ("try", "except"):
                sub = body.get(part)
                if isinstance(sub, dict) and "steps" in sub:
                    found = _find_step(sub["steps"], name)
                    if found is not None:
                        return found
    return None


def test_workflow_body_is_accepted_and_error_class_matches():
    wf = yaml.safe_load(SRE_WORKFLOW.read_text())
    call = _find_step(wf["main"]["steps"], "call_create_incident_spec")
    assert call["args"]["url"] == '${workspace_mcp_url + "/create-incident-spec"}'
    sent = set(call["args"]["body"])
    assert sent == set(BODY)
    assert sent <= set(ws_main.CreateIncidentSpecRequest.model_fields)
    assert '"%s"' % ws_main.INCIDENT_TEMPLATE_NOT_CONFIGURED in SRE_WORKFLOW.read_text()
    read = _find_step(wf["main"]["steps"], "read_ticket")
    assert read["assign"] == [{"spec_doc_id": '${default(map.get(ticket_output.body, "document_id"), "")}'}]
