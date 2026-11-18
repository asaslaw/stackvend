"""VENDING-CLIENT-FAIL-LOUD (SAT-51 review follow-up): a Resource Manager client that cannot be built fails loudly.

Before: the engine's `crm` property logged a warning and returned None when the discovery client could not be built,
and every Resource Manager step of `vend_gcp_project` was guarded by `if self.crm`: the existence check, the project
create, the admin / DevOps IAM grants and the project-number read were all skipped and the vend still answered
PROJECT_VENDED (and wrote a PROVISIONED workload record for a project that was never created). `create_folder`
answered a made-up `folders/<random>` id.

After: both stop with VendingFailure(VENDING.RESOURCE_MANAGER_CLIENT_UNAVAILABLE) naming the step and the build
error's class, before anything is read or created; the sync routes answer it typed. Negative (Do No Harm): with a
client (injected, or built) the vend and the folder create are unchanged.
Hermetic: fakes only (tests/destructive_guard_fakes.py); the client build is patched, nothing touches the network.
"""
import hermetic_guard  # noqa: F401  (must stay the first import)

import os
import sys
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))

import destructive_guard_fakes as f  # noqa: E402

VENDING_MAIN = f.load_vending_main()
VENDING = sys.modules[VENDING_MAIN.ProjectRepoVendingEngine.__module__]
BILLING = "billingAccounts/000000-AAAAAA-BBBBBB"   # synthetic
CLASS = "VENDING.RESOURCE_MANAGER_CLIENT_UNAVAILABLE"


@pytest.fixture(autouse=True)
def _settings_without_firestore(monkeypatch):
    import importlib
    live = importlib.import_module("shared.settings")
    live.invalidate_settings_cache()
    monkeypatch.setattr(live, "get_platform_settings", lambda *a, **k: live.PlatformSettings())
    yield
    live.invalidate_settings_cache()


class _NoCredentials(Exception):
    """Stands in for google.auth.exceptions.DefaultCredentialsError (the class name is what the detail carries)."""


def _crm(number=f.NUMBER, project_id="fresh-svc-123abc"):
    crm = MagicMock()
    projects = crm.projects.return_value
    projects.create.return_value.execute.return_value = {"name": "operations/cp.42"}
    projects.get.return_value.execute.return_value = {"name": f"projects/{number}", "projectId": project_id,
                                                      "state": "ACTIVE"}
    projects.getIamPolicy.return_value.execute.return_value = {"bindings": []}
    crm.operations.return_value.get.return_value.execute.return_value = {"done": True}
    return crm


def _billing():
    billing = MagicMock()
    billing.projects.return_value.updateBillingInfo.return_value.execute.return_value = {"billingEnabled": True}
    return billing


def _engine(db, crm=None, billing=None):
    eng = VENDING_MAIN.ProjectRepoVendingEngine(iam_client=f.FakeChildIAM(), platform_project_id=f.HOST, firestore_client=db, crm_service=crm,
                                                billing_service=billing or _billing(), storage_client=MagicMock())
    eng.billing_account_id = BILLING
    eng.devops_sa_email = ""
    return eng


def _build_fails(monkeypatch):
    calls = []

    def _raise(service, version):
        calls.append((service, version))
        raise _NoCredentials("Your default credentials were not found")

    monkeypatch.setattr(VENDING, "_build_thread_safe", _raise)
    return calls


def _vend(eng, pid="fresh-svc", **kw):
    return eng.vend_gcp_project(pid, "tr-1", folder_id=f.ROOT, force_new_project_id="fresh-svc-123abc", **kw)


# ------------------------------------------------------------------------------------------- vend_gcp_project
def test_vend_without_a_resource_manager_client_is_typed_and_creates_nothing(monkeypatch):
    calls = _build_fails(monkeypatch)
    db, billing = f.FakeDB(), _billing()
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend(_engine(db, billing=billing))
    assert exc.value.error_class == CLASS
    assert "_NoCredentials" in exc.value.detail and "fresh-svc" in exc.value.detail
    assert "default credentials were not found" not in exc.value.detail   # class only, never the message text
    assert ("cloudresourcemanager", "v3") in calls
    # stopped before anything: no workload record, no vend-target marker, no provenance, no billing call
    assert db.doc("workloads/fresh-svc") is None and db.doc("workload_provenance/fresh-svc") is None
    billing.projects.assert_not_called()


def test_vend_of_a_recorded_project_without_a_client_is_typed(monkeypatch):
    """The existence check of a PROVISIONED workload's recorded project is never skipped either."""
    _build_fails(monkeypatch)
    db = f.FakeDB()
    db.docs["workloads/old-svc"] = {"product_id": "old-svc", "project_id": "old-svc-abc123", "status": "PROVISIONED"}
    eng = _engine(db)
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        eng.vend_gcp_project("old-svc", "tr-2", folder_id=f.ROOT)
    assert exc.value.error_class == CLASS
    assert db.doc("workloads/old-svc") == {"product_id": "old-svc", "project_id": "old-svc-abc123",
                                           "status": "PROVISIONED"}


def test_negative_injected_client_vend_is_unchanged(monkeypatch):
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", f.TAG)
    calls = _build_fails(monkeypatch)
    db, crm = f.FakeDB(), _crm()
    res = _vend(_engine(db, crm))
    assert res["status"] == "PROJECT_VENDED" and res["project_number"] == f.NUMBER
    assert res["provenance_status"] == "RECORDED"
    crm.projects.return_value.create.assert_called_once()
    assert db.doc("workloads/fresh-svc")["status"] == "PROVISIONED"
    assert calls == []   # an injected client is used as is


def test_negative_built_client_vend_is_unchanged(monkeypatch):
    crm = _crm()
    monkeypatch.setattr(VENDING, "_build_thread_safe",
                        lambda s, v: crm if s == "cloudresourcemanager" else pytest.fail(f"unexpected {s}"))
    db = f.FakeDB()
    res = _vend(_engine(db))
    assert res["status"] == "PROJECT_VENDED"
    crm.projects.return_value.create.assert_called_once()


def test_require_crm_returns_the_client_unchanged():
    eng = VENDING.ProjectRepoVendingEngine.__new__(VENDING.ProjectRepoVendingEngine)
    crm = object()
    eng._crm = crm
    assert eng._require_crm("a step") is crm


# ------------------------------------------------------------------------------------------- create_folder
def test_create_folder_without_a_client_is_typed_never_a_made_up_id(monkeypatch):
    _build_fails(monkeypatch)
    eng = _engine(f.FakeDB())
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        eng.create_folder(display_name="team-a", parent_folder_id="folders/1000000001")
    assert exc.value.error_class == CLASS and "team-a" in exc.value.detail


def test_negative_create_folder_with_a_client_is_unchanged():
    crm = MagicMock()
    crm.folders.return_value.create.return_value.execute.return_value = {"name": "operations/fc.1"}
    crm.operations.return_value.get.return_value.execute.return_value = {
        "done": True, "response": {"name": "folders/2000000002"}}
    res = _engine(f.FakeDB(), crm).create_folder(display_name="team-a", parent_folder_id="folders/1000000001")
    assert res["status"] == "SUCCESS" and res["folder_id"] == "folders/2000000002"
    assert crm.folders.return_value.create.call_args.kwargs == {
        "body": {"displayName": "team-a", "parent": "folders/1000000001"}}


# ------------------------------------------------------------------------------------------- routes
def test_vend_project_route_answers_the_typed_class(monkeypatch):
    _build_fails(monkeypatch)
    monkeypatch.setattr(VENDING_MAIN, "vending_engine", _engine(f.FakeDB()))
    r = TestClient(VENDING_MAIN.app).post("/vend-project", json={"product_id": "fresh-svc", "folder_id": f.ROOT})
    assert r.status_code == 503   # RT 11-07 F4: client unavailable
    body = r.json()["detail"]
    assert body["error_class"] == CLASS and body["stage"] == "vending"


def test_folders_route_answers_the_typed_class(monkeypatch):
    _build_fails(monkeypatch)
    monkeypatch.setattr(VENDING_MAIN, "vending_engine", _engine(f.FakeDB()))
    r = TestClient(VENDING_MAIN.app).post("/folders", json={"display_name": "team-a",
                                                            "parent_folder_id": "folders/1000000001"})
    assert r.status_code == 503   # RT 11-07 F4: client unavailable
    body = r.json()["detail"]
    assert body["error_class"] == CLASS and body["stage"] == "vending"


def test_negative_folders_route_value_error_is_unchanged(monkeypatch):
    monkeypatch.setattr(VENDING_MAIN, "vending_engine", _engine(f.FakeDB(), MagicMock()))
    r = TestClient(VENDING_MAIN.app).post("/folders", json={"display_name": "   "})
    assert r.status_code == 400


# ------------------------------------------------------------------------------------------- gap 1: Firestore client
DB_CLASS = "VENDING.FIRESTORE_CLIENT_UNAVAILABLE"


class _FailSecondRecordWrite(f.FakeDB):
    """The pre-create target marker is written; the vend's final workload record write then fails."""

    def __init__(self, path="workloads/fresh-svc"):
        super().__init__()
        self._path, self._seen = path, 0

    def _maybe_fail_write(self, path):
        super()._maybe_fail_write(path)
        if path == self._path:
            self._seen += 1
            if self._seen == 2:
                raise RuntimeError("503 Service Unavailable writing the record")


def _http(status):
    from googleapiclient.errors import HttpError
    return HttpError(MagicMock(status=status, reason="x"), b"{}")


def _bare_engine(crm, platform_project_id):
    eng = VENDING_MAIN.ProjectRepoVendingEngine(iam_client=f.FakeChildIAM(), platform_project_id=platform_project_id, firestore_client=None,
                                                crm_service=crm, billing_service=_billing(),
                                                storage_client=MagicMock())
    eng.billing_account_id, eng.devops_sa_email = BILLING, ""
    return eng


def test_vend_without_a_firestore_client_is_typed_and_creates_nothing():
    crm = _crm()
    eng = _bare_engine(crm, "")
    eng.platform_project_id = ""   # the constructor falls back to $PROJECT_ID
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend(eng)
    assert exc.value.error_class == DB_CLASS and "no platform project configured" in exc.value.detail
    crm.projects.return_value.create.assert_not_called()


def test_vend_when_the_firestore_client_build_fails_is_typed(monkeypatch):
    def _raise(project=None, database=None):
        raise _NoCredentials("Your default credentials were not found")

    monkeypatch.setattr(VENDING.firestore, "Client", _raise)
    crm = _crm()
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend(_bare_engine(crm, f.HOST))
    assert exc.value.error_class == DB_CLASS and "_NoCredentials" in exc.value.detail
    assert "default credentials were not found" not in exc.value.detail
    crm.projects.return_value.create.assert_not_called()


def test_unwritten_record_is_typed_never_vended_and_the_re_vend_reuses_the_project(monkeypatch):
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", f.TAG)
    db, crm = _FailSecondRecordWrite(), _crm()
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend(_engine(db, crm))
    assert exc.value.error_class == "VENDING.WORKLOAD_RECORD_UNWRITTEN" and "fresh-svc-123abc" in exc.value.detail
    assert db.doc("workloads/fresh-svc")["project_id"] == "fresh-svc-123abc"          # the target marker landed
    assert db.doc("workloads/fresh-svc").get("status") != "PROVISIONED"
    assert db.doc("workload_provenance/fresh-svc")["project_id"] == "fresh-svc-123abc"
    # re-vend (Firestore back): the id answers 409, the labelled + provenanced project is adopted, no second project
    db2 = f.FakeDB()
    db2.docs = db.docs
    crm2 = _crm()
    crm2.projects.return_value.create.return_value.execute.side_effect = _http(409)
    crm2.projects.return_value.get.return_value.execute.return_value = {
        "name": f"projects/{f.NUMBER}", "projectId": "fresh-svc-123abc", "state": "ACTIVE",
        "labels": {"stackvend-managed": "true", "stackvend-product-id": "fresh-svc", "stackvend-type": "standard"}}
    res = _engine(db2, crm2).vend_gcp_project("fresh-svc", "tr-2", folder_id=f.ROOT)
    assert res["status"] == "PROJECT_VENDED" and res["project_id"] == "fresh-svc-123abc"
    created = [c.kwargs["body"]["projectId"] for c in crm2.projects.return_value.create.call_args_list]
    assert created == ["fresh-svc-123abc"]
    assert db2.doc("workloads/fresh-svc")["status"] == "PROVISIONED"


# ------------------------------------------------------------------------------------------- gap 2: parent folder
def _no_folder_engine(db, crm):
    eng = _engine(db, crm)
    eng.folder_id = ""
    return eng


def test_vend_without_a_parent_folder_is_typed_and_creates_nothing():
    db, crm = f.FakeDB(), _crm()
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _no_folder_engine(db, crm).vend_gcp_project("fresh-svc", "tr-1", force_new_project_id="fresh-svc-123abc")
    assert exc.value.error_class == "VENDING.PARENT_FOLDER_UNCONFIGURED" and "fresh-svc-123abc" in exc.value.detail
    crm.projects.return_value.create.assert_not_called()
    assert db.doc("workloads/fresh-svc") is None   # no target marker, no record


def test_negative_recorded_existing_project_needs_no_parent_folder():
    db, crm = f.FakeDB(), _crm(project_id="old-svc-abc123")
    db.docs["workloads/old-svc"] = {"product_id": "old-svc", "project_id": "old-svc-abc123", "status": "PROVISIONED"}
    res = _no_folder_engine(db, crm).vend_gcp_project("old-svc", "tr-2")
    assert res["status"] == "PROJECT_VENDED" and res["project_id"] == "old-svc-abc123"
    crm.projects.return_value.create.assert_not_called()


def test_negative_configured_folder_is_used_unchanged():
    db, crm = f.FakeDB(), _crm()
    eng = _engine(db, crm)
    eng.folder_id = "folders/1000000001"
    eng.vend_gcp_project("fresh-svc", "tr-1", force_new_project_id="fresh-svc-123abc")
    assert crm.projects.return_value.create.call_args.kwargs["body"]["parent"] == "folders/1000000001"


# ------------------------------------------------------------------------------------------- gap 3: folder id
def _folder_crm(create_answer, finished_op=None):
    crm = MagicMock()
    crm.folders.return_value.create.return_value.execute.return_value = create_answer
    crm.operations.return_value.get.return_value.execute.return_value = finished_op or {"done": True}
    return crm


@pytest.mark.parametrize("create_answer, finished_op", [
    ({}, None),                                                             # no operation name
    ("not-a-dict", None),
    ({"name": "operations/fc.1"}, {"done": True}),                          # finished, no response
    ({"name": "operations/fc.1"}, {"done": True, "response": {}}),          # response names no folder
    ({"name": "operations/fc.1"}, {"done": True, "response": {"name": "folders/"}}),
    ({"name": "operations/fc.1"}, {"done": True, "response": "folders/9"}),
])
def test_create_folder_without_a_folder_id_in_the_answer_is_typed(create_answer, finished_op):
    eng = _engine(f.FakeDB(), _folder_crm(create_answer, finished_op))
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        eng.create_folder(display_name="team-a", parent_folder_id="folders/1000000001")
    assert exc.value.error_class == "VENDING.FOLDER_CREATE_UNCONFIRMED" and "team-a" in exc.value.detail


def test_negative_create_folder_answer_with_a_folder_id_is_unchanged():
    crm = _folder_crm({"name": "operations/fc.1"}, {"done": True, "response": {"name": "folders/77"}})
    res = _engine(f.FakeDB(), crm).create_folder(display_name="team-a", parent_folder_id="1000000001")
    assert res["folder_id"] == "folders/77" and res["folder_number"] == "77"
    assert res["parent_folder_id"] == "folders/1000000001"


# ------------------------------------------------------------------------------------------- RT 11-07 F4 / F5
@pytest.mark.parametrize("cls, status", [
    ("VENDING.RESOURCE_MANAGER_CLIENT_UNAVAILABLE", 503), ("VENDING.FIRESTORE_CLIENT_UNAVAILABLE", 503),
    ("VENDING.PARENT_FOLDER_UNCONFIGURED", 503),
    # negative: every other class keeps 502
    ("VENDING.FOLDER_CREATE_UNCONFIRMED", 502), ("VENDING.WORKLOAD_RECORD_UNWRITTEN", 502),
    ("BILLING_NOT_LINKED", 502), ("VENDING.PROJECT_READ_FAILED", 502),
])
def test_vending_failure_http_status_by_class(cls, status):
    assert VENDING.VendingFailure(cls, "x").http_status == status


def test_build_error_attributes_start_unset():
    eng = _engine(f.FakeDB(), _crm())
    assert eng._crm_build_error is None and eng._db_build_error is None


def test_require_db_returns_the_client_unchanged():
    eng = VENDING.ProjectRepoVendingEngine.__new__(VENDING.ProjectRepoVendingEngine)
    db = f.FakeDB()
    eng._db, eng.platform_project_id = db, f.HOST
    assert eng._require_db("a step") is db
