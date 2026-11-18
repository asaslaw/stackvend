"""VENDING-PROJECT-QUOTA-TYPED (owner 11-16; live 11-16 on stackvend12): a project create that Resource Manager refuses
because the project quota is exhausted stops with the typed VENDING.PROJECT_QUOTA_EXCEEDED.

Live failure: the finished projects.create operation answered
`{'code': 8, 'message': 'The project cannot be created because you have exceeded your allotted project quota.',
'details': [{'@type': 'type.googleapis.com/google.rpc.QuotaFailure', ...}]}`; vending raised a plain RuntimeError and the
workflow recorded the default DEPENDENCY_FAILED.

* The operation's `error` (a google.rpc.Status) is classified by its structured fields only: `code` exactly int 8
  (RESOURCE_EXHAUSTED) or a `details` entry whose `@type` is exactly type.googleapis.com/google.rpc.QuotaFailure.
  Never by `message` (invariant 2).
* The message names the project being created, who owns the quota, the ~30-day pending-deletion rule and the
  known-limitations section; never the billing account or the non-existent `force_new_project_id` spec field.
* The old "HTTP 403 whose text contains 'quota'" branch is gone: a 403 is raised as Google's own error.
* The async route puts the class on the callback outcome (the workflow's handle_vending_failure lifts it unchanged).

Negatives (Do No Harm): any other operation error (code 7 PERMISSION_DENIED, 6 ALREADY_EXISTS, 13, a quota-sounding
message with another code, a non-int code) raises exactly the RuntimeError it raised before; a folder create's quota
error stays untyped; a clean create is unchanged.
Hermetic: a recording fake Resource Manager client, tests/destructive_guard_fakes.FakeDB, a fake clock."""

import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import copy
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import destructive_guard_fakes as f  # noqa: E402

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VENDING_MAIN = f.load_vending_main()
V = sys.modules[VENDING_MAIN.ProjectRepoVendingEngine.__module__]
PID = "fresh-svc"
PROJECT = "fresh-svc-123abc"
NUMBER = f.NUMBER
OP = {"name": "operations/cp.42"}
OP_DONE = {"name": "operations/cp.42", "done": True, "response": {"name": f"projects/{NUMBER}", "projectId": PROJECT}}
QUOTA_FAILURE = {"@type": "type.googleapis.com/google.rpc.QuotaFailure",
                 "violations": [{"subject": "subject-x", "description": "desc-y"}]}
GOOGLE_TEXT = "The project cannot be created because you have exceeded your allotted project quota."
LIVE_ERROR = {"code": 8, "message": GOOGLE_TEXT, "details": [QUOTA_FAILURE]}


def _failed(error):
    return {"name": "operations/cp.42", "done": True, "error": error}


class HttpError(Exception):
    """Shape of googleapiclient.errors.HttpError (resp.status), patched in as vending.HttpError."""

    def __init__(self, status, content=b""):
        super().__init__(f"<HttpError {status}>")
        self.resp = SimpleNamespace(status=status, reason="r")
        self.content = content


class _Clock:
    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def time(self):
        return self.now

    def sleep(self, s):
        self.sleeps.append(s)
        self.now += s


class _Call:
    def __init__(self, fn):
        self.fn = fn

    def execute(self):
        return self.fn()


class _Script:
    def __init__(self, *items):
        self.items = list(items)

    def next(self):
        item = self.items.pop(0) if len(self.items) > 1 else self.items[0]
        if isinstance(item, BaseException):
            raise item
        return item


class FakeCRM:
    """Resource Manager v3 fake recording (method, target)."""

    def __init__(self, get=(HttpError(404),), create=(OP,), op=(OP_DONE,)):
        self.get_script, self.create_script, self.op_script = _Script(*get), _Script(*create), _Script(*op)
        self.calls, self.created_ids = [], []

    def projects(self):
        return self

    def folders(self):
        crm = self

        class _Folders:
            def create(self, body):
                def run():
                    crm.calls.append(("folders.create", body["displayName"]))
                    return crm.create_script.next()
                return _Call(run)
        return _Folders()

    def operations(self):
        crm = self

        class _Ops:
            def get(self, name):
                def run():
                    crm.calls.append(("operations.get", name))
                    return crm.op_script.next()
                return _Call(run)
        return _Ops()

    def tagBindings(self):
        crm = self

        class _Tags:
            def create(self, body):
                def run():
                    crm.calls.append(("tagBindings.create", body["parent"]))
                    return {"name": "tagBindings/x"}
                return _Call(run)
        return _Tags()

    def get(self, name):
        def run():
            self.calls.append(("projects.get", name))
            return self.get_script.next()
        return _Call(run)

    def create(self, body):
        def run():
            self.calls.append(("projects.create", body["projectId"]))
            self.created_ids.append(body["projectId"])
            return self.create_script.next()
        return _Call(run)

    def getIamPolicy(self, resource):
        return _Call(lambda: self.calls.append(("projects.getIamPolicy", resource)) or {"bindings": []})

    def setIamPolicy(self, resource, body):
        return _Call(lambda: self.calls.append(("projects.setIamPolicy", resource)) or body["policy"])


@pytest.fixture(autouse=True)
def _fakes(monkeypatch):
    import importlib
    live = importlib.import_module("shared.settings")
    live.invalidate_settings_cache()
    monkeypatch.setattr(live, "get_platform_settings", lambda *a, **k: live.PlatformSettings())
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", f.TAG)
    monkeypatch.delenv("STACKVEND_GUARD_FIRESTORE_DATABASE", raising=False)
    monkeypatch.delenv("STACKVEND_CHILD_PROJECT_OWNER_MEMBERS", raising=False)
    clock = _Clock()
    monkeypatch.setattr(V, "time", SimpleNamespace(time=clock.time, sleep=clock.sleep))
    monkeypatch.setattr(V, "HttpError", HttpError)
    monkeypatch.setattr(V.ProjectRepoVendingEngine, "enable_child_apis", lambda self, pid: {"status": "ENABLED"})
    monkeypatch.setattr(V.ProjectRepoVendingEngine, "check_child_org_policies", lambda self, pid: [])
    yield clock
    live.invalidate_settings_cache()


def _engine(db, crm):
    eng = VENDING_MAIN.ProjectRepoVendingEngine(iam_client=f.FakeChildIAM(), platform_project_id=f.HOST,
                                                firestore_client=db, crm_service=crm, billing_service=MagicMock(),
                                                storage_client=MagicMock())
    eng.billing_account_id = "billingAccounts/000000-AAAAAA-BBBBBB"
    eng.devops_sa_email = ""
    return eng


def _record(db, status="PROVISIONING", project_id=PROJECT):
    db.docs[f"workloads/{PID}"] = {"product_id": PID, "project_id": project_id, "status": status}


def _vend(eng):
    return eng.vend_gcp_project(PID, "tr-1", folder_id=f.ROOT)


def _quota_stop(error, **crm_kw):
    db = f.FakeDB()
    _record(db)
    crm = FakeCRM(op=(_failed(error),), **crm_kw)
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend(_engine(db, crm))
    return exc.value, crm, db


# ------------------------------------------------------------------------------------------------ typed quota stop
def test_live_error_code_8_with_quota_failure_is_typed():
    err, crm, db = _quota_stop(LIVE_ERROR)
    assert err.error_class == "VENDING.PROJECT_QUOTA_EXCEEDED" == V.PROJECT_QUOTA_EXCEEDED
    assert err.stage == "vending" and err.http_status == 502
    assert str(err).startswith("VENDING.PROJECT_QUOTA_EXCEEDED: ")
    # the original operation error is chained, structured status intact
    assert isinstance(err.__cause__, V.CrmOperationError) and err.__cause__.error == LIVE_ERROR
    assert crm.created_ids == [PROJECT]                         # one create, no retry, no fallback id
    assert db.doc(f"workload_provenance/{PID}") is None         # nothing created, nothing recorded as created
    assert "status" in db.doc(f"workloads/{PID}") and db.doc(f"workloads/{PID}")["status"] == "PROVISIONING"


def test_quota_message_tells_the_truth():
    err, _, _ = _quota_stop(LIVE_ERROR)
    d = err.detail
    assert f"project '{PROJECT}'" in d and "project quota is exhausted" in d
    assert "code 8 RESOURCE_EXHAUSTED" in d and "type.googleapis.com/google.rpc.QuotaFailure" in d
    assert "Nothing was created" in d
    assert "project-vending service account" in d and "organization" in d
    assert "about 30 days" in d and "pending deletion" in d
    assert "cloudresourcemanager.googleapis.com/projects_count" in d
    assert ("documentation/known-limitations.md, section 'Every workload uses one Google Cloud project: the project "
            "quota'") in d
    assert '"' not in d   # no double quotes: they would be escaped in the workflow's JSON-encoded failure_reason
    # no billing blame, no non-existent spec field, no free text or ids from Google's answer, no billing account
    for banned in ("billing", "force_new_project_id", "feature specification", GOOGLE_TEXT, "subject-x", "desc-y",
                   "000000-AAAAAA-BBBBBB", f.ROOT, f.HOST, "operations/cp.42"):
        assert banned not in d, banned


def test_documented_section_exists():
    with open(os.path.join(REPO_ROOT, "documentation", "known-limitations.md"), encoding="utf-8") as fh:
        doc = fh.read()
    assert "## Every workload uses one Google Cloud project: the project quota" in doc
    assert "VENDING.PROJECT_QUOTA_EXCEEDED" in doc


def test_service_log_carries_googles_structured_status_and_message_does_not(caplog):
    """Review fix 1: the service log names the operation and Google's status (incl. QuotaFailure violations) so
    operators can see which quota tripped; the operator message stays free of Google's text."""
    with caplog.at_level("ERROR", logger=V.logger.name):
        err, _, _ = _quota_stop(LIVE_ERROR)
    lines = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"
             and r.getMessage().startswith("VENDING.PROJECT_QUOTA_EXCEEDED")]
    assert len(lines) == 1
    line = lines[0]
    assert "operations/cp.42" in line and f"'{PROJECT}'" in line and str(LIVE_ERROR) in line
    assert "subject-x" in line and "desc-y" in line and GOOGLE_TEXT in line
    for google in ("subject-x", "desc-y", GOOGLE_TEXT, "operations/cp.42"):
        assert google not in err.detail


@pytest.mark.parametrize("error", [
    {"code": 9, "details": [QUOTA_FAILURE]},          # QuotaFailure detail alone (another code)
    {"details": [QUOTA_FAILURE]},                     # QuotaFailure detail alone (no code)
    {"code": 13, "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo"}, QUOTA_FAILURE]},
], ids=["code9", "nocode", "second-detail"])
def test_quota_failure_detail_alone_is_typed(error):
    err, _, _ = _quota_stop(error)
    assert err.error_class == V.PROJECT_QUOTA_EXCEEDED
    assert "type.googleapis.com/google.rpc.QuotaFailure" in err.detail
    assert "RESOURCE_EXHAUSTED" not in err.detail          # only what Google actually returned is named


def test_code_8_alone_is_typed():
    err, _, _ = _quota_stop({"code": 8, "message": "anything"})
    assert err.error_class == V.PROJECT_QUOTA_EXCEEDED
    assert "code 8 RESOURCE_EXHAUSTED" in err.detail and "QuotaFailure" not in err.detail


def test_fallback_create_after_409_is_typed_with_the_fallback_id():
    """The 409 fallback create (a pre-assigned id taken outside StackVend) waits on its operation the same way."""
    db = f.FakeDB()
    _record(db)
    crm = FakeCRM(get=(HttpError(404),), create=(HttpError(409), OP), op=(_failed(LIVE_ERROR),))
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend(_engine(db, crm))
    assert exc.value.error_class == V.PROJECT_QUOTA_EXCEEDED
    assert len(crm.created_ids) == 2 and crm.created_ids[0] == PROJECT
    assert f"project '{crm.created_ids[1]}'" in exc.value.detail and f"'{PROJECT}'" not in exc.value.detail


# ------------------------------------------------------------------------------------------------ Do No Harm
@pytest.mark.parametrize("error", [
    {"code": 7, "message": "Permission denied"},                                         # PERMISSION_DENIED
    {"code": 6, "message": "Requested entity already exists"},                           # ALREADY_EXISTS
    {"code": 13, "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "QUOTA"}]},
    {"code": 7, "message": GOOGLE_TEXT},                       # quota-sounding text, other code: text is never read
    {"code": "8", "details": []},                              # not an int: not the typed field
    {"code": True},                                            # a bool is not a gRPC code
    {"code": 7, "details": [{"@type": "type.googleapis.com/google.rpc.QuotaFailureX"}]},   # exact @type only
    {"code": 7, "details": "type.googleapis.com/google.rpc.QuotaFailure"},                # details not a list
    "a plain string error",
], ids=["perm7", "exists6", "errorinfo13", "text-only", "str-code", "bool-code", "near-type", "details-str", "str"])
def test_negative_other_operation_errors_unchanged(error):
    db = f.FakeDB()
    _record(db)
    crm = FakeCRM(op=(_failed(error),))
    with pytest.raises(RuntimeError) as exc:
        _vend(_engine(db, crm))
    assert not isinstance(exc.value, VENDING_MAIN.VendingFailure)
    assert type(exc.value) is V.CrmOperationError and isinstance(exc.value, RuntimeError)
    assert str(exc.value) == f"GCP Project creation operation failed: {error}"   # the exact message as before
    assert crm.created_ids == [PROJECT]


@pytest.mark.parametrize("error", [LIVE_ERROR, {"code": 7}, {"details": [QUOTA_FAILURE]}, None, {}, []])
def test_classifier_reads_structured_fields_only(error):
    expected = error in (LIVE_ERROR, {"details": [QUOTA_FAILURE]})
    assert V._is_quota_exhausted_status(error) is expected


def test_negative_clean_create_unchanged():
    db = f.FakeDB()
    _record(db)
    crm = FakeCRM()
    res = _vend(_engine(db, crm))
    assert res["project_id"] == PROJECT and crm.created_ids == [PROJECT]
    assert ("operations.get", "operations/cp.42") in crm.calls


def test_negative_folder_create_quota_error_stays_untyped():
    """Only project-create waits classify: a folder create keeps raising the operation's RuntimeError."""
    crm = FakeCRM(op=(_failed(LIVE_ERROR),))
    eng = _engine(f.FakeDB(), crm)
    with pytest.raises(RuntimeError) as exc:
        eng.create_folder("team-a", parent_folder_id=f.ROOT)
    assert not isinstance(exc.value, VENDING_MAIN.VendingFailure)
    assert isinstance(exc.value, V.CrmOperationError) and exc.value.error == LIVE_ERROR


# ------------------------------------------------------------------------------------------------ 403 branch removed
def test_create_403_with_quota_text_is_googles_own_error():
    db = f.FakeDB()
    _record(db)
    err403 = HttpError(403, content=b"The project creation quota has been reached for this account.")
    crm = FakeCRM(create=(err403,))
    with pytest.raises(HttpError) as exc:
        _vend(_engine(db, crm))
    assert exc.value is err403
    assert crm.created_ids == [PROJECT] and not any(c[0] == "operations.get" for c in crm.calls)


def test_old_misleading_text_is_gone():
    with open(os.path.join(REPO_ROOT, "apps", "project-vending", "vending.py"), encoding="utf-8") as fh:
        src = fh.read()
    assert "GCP Project Creation Quota has been reached" not in src
    assert "in the feature specification" not in src
    assert '"project creation quota" in err_str' not in src   # the 403 project-create substring branch


# ------------------------------------------------------------------------------------------------ surfaces
def _capture_callbacks(monkeypatch):
    cbmod = sys.modules[VENDING_MAIN.guaranteed_callback_scope.__module__]
    sent = []

    def _send(callback_url, payload, timeout=15, max_attempts=5):
        json.dumps(payload)
        sent.append(copy.deepcopy(payload))
        return {}

    monkeypatch.setattr(cbmod.CallbackDeliveryClient, "send_callback", staticmethod(_send))
    return sent


def test_async_route_delivers_the_typed_class(monkeypatch):
    """The workflow's handle_vending_failure takes error_class from the callback body unchanged (no workflow change)."""
    sent = _capture_callbacks(monkeypatch)
    db = f.FakeDB()
    _record(db)
    eng = _engine(db, FakeCRM(op=(_failed(LIVE_ERROR),)))
    monkeypatch.setattr(eng, "vend_all", lambda **kw: eng.vend_gcp_project(PID, "tr-async", folder_id=f.ROOT))
    monkeypatch.setattr(VENDING_MAIN, "vending_engine", eng)
    VENDING_MAIN.run_vending_in_background(VENDING_MAIN.AsyncVendingRequest(
        product_id=PID, trace_id="tr-async", callback_url="http://127.0.0.1:9/cb"))
    assert len(sent) == 1
    payload = sent[0]
    assert payload["status"] == "FAILED" and payload["error_class"] == "VENDING.PROJECT_QUOTA_EXCEEDED"
    assert payload["error_stage"] == "vending"
    assert payload["error"].startswith("VENDING.PROJECT_QUOTA_EXCEEDED: Resource Manager did not create project")


def test_workflow_lifts_the_vending_error_class_unchanged():
    with open(os.path.join(REPO_ROOT, "workflows", "main_orchestrator.yaml"), encoding="utf-8") as fh:
        wf = fh.read()
    assert ("- error_class: '${default(map.get(vending_output, \"error_class\"), \"DEPENDENCY_FAILED\")}'") in wf
