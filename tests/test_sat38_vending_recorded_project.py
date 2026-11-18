"""SAT-38 (RT SAT-25 follow-ups M1, M2, L4, I2; register row drafted, NOT approved): vending never makes a second
project for, and never silently adopts, a project StackVend may already own.

* M1: a project a PROVISIONED / ACTIVE workload record names that Resource Manager answers 403 / 404 for is never
  created again (ids are not reusable: that could only 409 into a fallback, second project):
  VENDING.RECORDED_PROJECT_UNREADABLE, at the existence check and, should a recorded id reach a create, after the 409.
* M2: the target project id is written on workloads/{pid} before every projects.create (a failed write stops the vend:
  VENDING.PROJECT_TARGET_UNRECORDED); after a 409 an existing project that carries this product's StackVend labels is
  adopted only when a provenance record names exactly it, else VENDING.PROJECT_UNPROVENANCED
  (VENDING.PROJECT_PROVENANCE_UNREADABLE when the record cannot be read).
* L4: a recorded or 409-found project in DELETE_REQUESTED -> VENDING.PROJECT_PENDING_DELETION.
* A 409-found project whose exact `stackvend-product-id` label names ANOTHER product is never adopted:
  VENDING.PROJECT_LABELLED_FOR_OTHER_PRODUCT.
* I2: the existence / 409 reads' other non-transient errors -> VENDING.PROJECT_READ_FAILED (tested in
  test_vending_read_transient.py, whose call-list snapshots also pin the normal new-vend and re-vend paths).

Negatives (Do No Harm): a fresh or pre-assigned id keeps the fallback on 409 + 403/404; a 409-found project without
this product's labels, or with a matching provenance record, is adopted as before; the normal first vend and the
normal re-vend make the same Resource Manager calls; a record that already names the target gets no extra write.
Hermetic: a recording fake Resource Manager client, tests/destructive_guard_fakes.FakeDB, a fake clock."""

import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import destructive_guard_fakes as f  # noqa: E402

VENDING_MAIN = f.load_vending_main()
V = sys.modules[VENDING_MAIN.ProjectRepoVendingEngine.__module__]
PID = "fresh-svc"
PROJECT = "fresh-svc-123abc"
NUMBER = f.NUMBER
OP = {"name": "operations/cp.42"}
OP_DONE = {"name": "operations/cp.42", "done": True, "response": {"name": f"projects/{NUMBER}", "projectId": PROJECT}}
ACTIVE = {"name": f"projects/{NUMBER}", "projectId": PROJECT, "state": "ACTIVE"}
OURS = {"stackvend-managed": "true", "stackvend-product-id": PID, "stackvend-workload-type": "standard"}
LABELLED = dict(ACTIVE, labels=OURS)
PROVENANCE = {"created_by": "stackvend-vending", "product_id": PID, "project_id": PROJECT, "project_number": NUMBER}


class HttpError(Exception):
    """Shape of googleapiclient.errors.HttpError (resp.status), patched in as vending.HttpError."""

    def __init__(self, status):
        super().__init__(f"<HttpError {status}>")
        self.resp = SimpleNamespace(status=status, reason="r")


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
    """Resource Manager v3 fake recording (method, target); on each create it snapshots the workload record."""

    def __init__(self, db, get=(ACTIVE,), create=(OP,), op=(OP_DONE,)):
        self.db = db
        self.get_script, self.create_script, self.op_script = _Script(*get), _Script(*create), _Script(*op)
        self.calls, self.created_ids, self.record_at_create = [], [], []

    def projects(self):
        return self

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
            self.record_at_create.append(dict(self.db.doc(f"workloads/{PID}") or {}))
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


def _engine(db, crm, devops_sa=""):
    eng = VENDING_MAIN.ProjectRepoVendingEngine(iam_client=f.FakeChildIAM(), platform_project_id=f.HOST, firestore_client=db, crm_service=crm,
                                                billing_service=MagicMock(), storage_client=MagicMock())
    eng.billing_account_id = ""
    eng.devops_sa_email = devops_sa
    return eng


def _record(db, status, project_id=PROJECT):
    db.docs[f"workloads/{PID}"] = {"product_id": PID, "project_id": project_id, "status": status}


def _vend(eng, **kw):
    return eng.vend_gcp_project(PID, "tr-1", folder_id=f.ROOT, **kw)


def _stop(eng, **kw):
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend(eng, **kw)
    return exc.value


def _workload(db):
    return db.doc(f"workloads/{PID}") or {}


# ------------------------------------------------------------------------------------------------ M1 recorded project
@pytest.mark.parametrize("status", ["PROVISIONED", "ACTIVE"])
@pytest.mark.parametrize("http", [403, 404])
def test_recorded_project_not_found_stops_typed_and_creates_nothing(status, http):
    db = f.FakeDB()
    crm = FakeCRM(db, get=(HttpError(http),))
    _record(db, status)
    before = dict(_workload(db))
    err = _stop(_engine(db, crm))
    assert err.error_class == "VENDING.RECORDED_PROJECT_UNREADABLE" == V.RECORDED_PROJECT_UNREADABLE
    assert PROJECT in err.detail and status in err.detail
    assert crm.created_ids == [] and crm.calls == [("projects.get", f"projects/{PROJECT}")]
    assert _workload(db) == before and db.doc(f"workload_provenance/{PID}") is None


def test_recorded_project_reaching_a_create_never_falls_back(_fakes):
    """A recorded project in a state the existence check does not know is created again (unchanged); its 409 is then
    followed by 403: no fallback (second) project, a typed stop."""
    db = f.FakeDB()
    crm = FakeCRM(db, get=(dict(ACTIVE, state="SOMETHING_NEW"), HttpError(403)), create=(HttpError(409),))
    _record(db, "ACTIVE")
    err = _stop(_engine(db, crm))
    assert err.error_class == "VENDING.RECORDED_PROJECT_UNREADABLE" and "409" in err.detail
    assert crm.created_ids == [PROJECT]   # one create of the recorded id; no fallback id
    assert _workload(db)["project_id"] == PROJECT


@pytest.mark.parametrize("http", [403, 404])
def test_negative_pre_assigned_id_keeps_the_fallback(http):
    """A PROVISIONING record's pre-assigned id (Control Center derives it from the name) was never created: 409 +
    403/404 still creates the fallback id, now written on the record before its create."""
    db = f.FakeDB()
    crm = FakeCRM(db, get=(HttpError(http),), create=(HttpError(409), OP))
    _record(db, "PROVISIONING")
    res = _vend(_engine(db, crm))
    assert len(crm.created_ids) == 2 and crm.created_ids[0] == PROJECT
    fallback = crm.created_ids[1]
    assert fallback.startswith(PROJECT[:23].rstrip("-") + "-") and res["project_id"] == fallback
    assert crm.record_at_create[0]["project_id"] == PROJECT    # already named
    assert crm.record_at_create[0]["vend_target"]["project_id"] == PROJECT   # L3 marker before the first create
    assert crm.record_at_create[1]["project_id"] == fallback   # M2: recorded before the fallback create
    assert crm.record_at_create[1]["vend_target"]["project_id"] == fallback
    assert res["provenance_status"] == "RECORDED" and _workload(db)["status"] == "PROVISIONED"


def test_negative_fresh_generated_id_keeps_the_fallback(_fakes):
    db = f.FakeDB()
    crm = FakeCRM(db, get=(HttpError(404),), create=(HttpError(409), OP))
    res = _vend(_engine(db, crm))   # no record: the id is generated from the product id
    assert crm.created_ids[0] == PID and len(crm.created_ids) == 2 and res["project_id"] == crm.created_ids[1]
    assert res["provenance_status"] == "RECORDED"


# ------------------------------------------------------------------------------------------------ L4 pending deletion
@pytest.mark.parametrize("project", [dict(ACTIVE, state="DELETE_REQUESTED"),
                                     {"projectId": PROJECT, "projectNumber": NUMBER,
                                      "lifecycleState": "DELETE_IN_PROGRESS"}])
def test_recorded_project_pending_deletion_stops_typed(project):
    db = f.FakeDB()
    crm = FakeCRM(db, get=(project,))
    _record(db, "ACTIVE")
    err = _stop(_engine(db, crm))
    assert err.error_class == "VENDING.PROJECT_PENDING_DELETION" == V.PROJECT_PENDING_DELETION
    assert PROJECT in err.detail and "undelete" in err.detail
    assert crm.created_ids == [] and len(crm.calls) == 1


@pytest.mark.parametrize("status", ["PROVISIONED", "ACTIVE"])
def test_recorded_pending_deletion_says_decommission_before_redeploy(status):
    """RT SAT-38 L5: Redeploy runs only on a DECOMMISSIONED workload; a live record is told to decommission first."""
    db = f.FakeDB()
    _record(db, status)
    detail = _stop(_engine(db, FakeCRM(db, get=(dict(ACTIVE, state="DELETE_REQUESTED"),)))).detail
    assert detail.index("decommission the workload") < detail.index("Redeploy it")


def test_decommissioned_record_pending_deletion_says_redeploy(_fakes):
    """A plain re-vend of a decommissioned workload within the 30-day hold (deterministic id): Redeploy directly."""
    db = f.FakeDB()
    _record(db, "DECOMMISSIONED")
    crm = FakeCRM(db, get=(dict(ACTIVE, state="DELETE_REQUESTED"),), create=(HttpError(409),))
    err = _stop(_engine(db, crm))
    assert err.error_class == "VENDING.PROJECT_PENDING_DELETION"
    assert "Redeploy the workload" in err.detail and "decommission the workload" not in err.detail
    assert _workload(db)["status"] == "DECOMMISSIONED"


def test_409_found_pending_deletion_without_record_says_decommission_first(_fakes):
    db = f.FakeDB()
    crm = FakeCRM(db, get=(dict(ACTIVE, state="DELETE_REQUESTED"),), create=(HttpError(409),))
    assert "decommission the workload, then Redeploy" in _stop(_engine(db, crm), force_new_project_id=PROJECT).detail


def test_409_found_pending_deletion_is_not_adopted(_fakes):
    db = f.FakeDB()
    crm = FakeCRM(db, get=(dict(LABELLED, state="DELETE_REQUESTED"),), create=(HttpError(409),))
    err = _stop(_engine(db, crm), force_new_project_id=PROJECT)
    assert err.error_class == "VENDING.PROJECT_PENDING_DELETION" and crm.created_ids == [PROJECT]
    assert "status" not in _workload(db)   # not registered as PROVISIONED


# ------------------------------------------------------------------------------------------------ M2 adoption
def test_409_found_labelled_without_provenance_is_a_typed_stop(_fakes):
    db = f.FakeDB()
    crm = FakeCRM(db, get=(LABELLED,), create=(HttpError(409),))
    err = _stop(_engine(db, crm), force_new_project_id=PROJECT)
    assert err.error_class == "VENDING.PROJECT_UNPROVENANCED" == V.PROJECT_UNPROVENANCED
    assert PROJECT in err.detail and f"delete projects/{PROJECT}" in err.detail
    assert crm.created_ids == [PROJECT] and db.doc(f"workload_provenance/{PID}") is None
    assert "status" not in _workload(db) and _workload(db)["project_id"] == PROJECT


def test_unprovenanced_messages_say_to_wait_for_a_concurrent_vend_before_deleting(_fakes):
    """RT SAT-38 L2: a concurrent vend of the same workload may be about to record the provenance; the operator is told
    to wait for it before deleting anything (both the 409 stop and the created-in-this-vend note)."""
    db = f.FakeDB()
    crm = FakeCRM(db, get=(LABELLED,), create=(HttpError(409),))
    detail = _stop(_engine(db, crm), force_new_project_id=PROJECT).detail
    assert "may still be running" in detail
    assert detail.index("wait for it to finish") < detail.index(f"delete projects/{PROJECT}")
    note = V._unprovenanced_note(PROJECT)
    assert "may still be running" in note and note.index("wait for it to finish") < note.index("first delete")
    assert note.count("re-run the vend") == 1   # one order only (SAT-25 RT L2), unchanged


@pytest.mark.parametrize("prov", [
    dict(PROVENANCE, project_id="fresh-svc-older"),        # an earlier project of the same product
    dict(PROVENANCE, project_number="999999999999"),       # same id, another number
    dict(PROVENANCE, created_by="someone-else"),
    dict(PROVENANCE, project_number=None),
])
def test_409_found_labelled_with_provenance_of_something_else_is_a_typed_stop(prov):
    db = f.FakeDB()
    db.docs[f"workload_provenance/{PID}"] = prov
    crm = FakeCRM(db, get=(LABELLED,), create=(HttpError(409),))
    assert _stop(_engine(db, crm), force_new_project_id=PROJECT).error_class == "VENDING.PROJECT_UNPROVENANCED"


def test_409_found_labelled_provenance_unreadable_fails_closed(_fakes):
    db = f.FakeDB()
    db.fail_paths.add(f"workload_provenance/{PID}")
    crm = FakeCRM(db, get=(LABELLED,), create=(HttpError(409),))
    err = _stop(_engine(db, crm), force_new_project_id=PROJECT)
    assert err.error_class == "VENDING.PROJECT_PROVENANCE_UNREADABLE" == V.PROJECT_PROVENANCE_UNREADABLE
    assert crm.created_ids == [PROJECT]


@pytest.mark.parametrize("created_by", ["stackvend-vending", "owner-backfill"])
def test_negative_409_found_labelled_with_its_provenance_is_adopted_as_before(created_by):
    """The normal re-run of a workload whose record is not PROVISIONED / ACTIVE (FAILED, PROVISIONING, ...)."""
    db = f.FakeDB()
    db.docs[f"workload_provenance/{PID}"] = dict(PROVENANCE, created_by=created_by)
    _record(db, "FAILED")
    crm = FakeCRM(db, get=(LABELLED,), create=(HttpError(409),))
    res = _vend(_engine(db, crm))
    assert res["status"] == "PROJECT_VENDED" and res["project_id"] == PROJECT
    assert crm.created_ids == [PROJECT] and res["provenance_status"] == "NOT_CREATED_IN_THIS_CALL"
    assert db.doc(f"workload_provenance/{PID}")["created_by"] == created_by   # untouched


@pytest.mark.parametrize("labels", [None, {}, {"stackvend-managed": "TRUE", "stackvend-product-id": PID},
                                    {"stackvend-product-id": PID}, {"stackvend-managed": "true"},
                                    {"stackvend-product-id": ""}, {"stackvend-product-id": 7}, {"team": "other-svc"},
                                    "not-a-dict"])
def test_negative_409_found_without_this_products_labels_is_adopted_as_before(labels):
    """Brownfield / forced ids and projects without a product label naming another workload: exactly as before (no
    provenance read)."""
    db = f.FakeDB()
    db.fail_paths.add(f"workload_provenance/{PID}")   # would fail the vend if it were read
    project = dict(ACTIVE) if labels is None else dict(ACTIVE, labels=labels)
    crm = FakeCRM(db, get=(project,), create=(HttpError(409),))
    res = _vend(_engine(db, crm), force_new_project_id=PROJECT)
    assert res["status"] == "PROJECT_VENDED" and crm.created_ids == [PROJECT]
    assert res["provenance_status"] == "NOT_CREATED_IN_THIS_CALL"


@pytest.mark.parametrize("labels", [
    {"stackvend-managed": "true", "stackvend-product-id": "other-svc", "stackvend-workload-type": "standard"},
    {"stackvend-product-id": "other-svc"},                                  # the product label alone names it
    {"stackvend-managed": "false", "stackvend-product-id": PID + "-x"},     # exact compare: a prefix match is another
])
def test_409_found_labelled_for_another_product_is_a_typed_stop(labels):
    db = f.FakeDB()
    db.docs[f"workload_provenance/{PID}"] = PROVENANCE   # even with this product's provenance on record
    crm = FakeCRM(db, get=(dict(ACTIVE, labels=labels),), create=(HttpError(409),))
    err = _stop(_engine(db, crm), force_new_project_id=PROJECT)
    assert err.error_class == "VENDING.PROJECT_LABELLED_FOR_OTHER_PRODUCT" == V.PROJECT_LABELLED_FOR_OTHER_PRODUCT
    assert PROJECT in err.detail and labels["stackvend-product-id"] in err.detail
    assert crm.created_ids == [PROJECT] and "status" not in _workload(db)   # no fallback, not registered


def test_409_found_another_products_label_wins_over_pending_deletion(_fakes):
    """RT SAT-38 L1: another workload's project is refused first, whatever its state, so the operator is never told
    to undelete another workload's project."""
    db = f.FakeDB()
    project = dict(ACTIVE, state="DELETE_REQUESTED", labels={"stackvend-product-id": "other-svc"})
    crm = FakeCRM(db, get=(project,), create=(HttpError(409),))
    err = _stop(_engine(db, crm), force_new_project_id=PROJECT)
    assert err.error_class == "VENDING.PROJECT_LABELLED_FOR_OTHER_PRODUCT" and "undelete" not in err.detail


def test_negative_409_found_own_or_unlabelled_pending_deletion_still_stops_pending(_fakes):
    for labels in (OURS, None, {"stackvend-product-id": PID}):
        db = f.FakeDB()
        project = dict(ACTIVE, state="DELETE_REQUESTED", **({"labels": labels} if labels else {}))
        crm = FakeCRM(db, get=(project,), create=(HttpError(409),))
        err = _stop(_engine(db, crm), force_new_project_id=PROJECT)
        assert err.error_class == "VENDING.PROJECT_PENDING_DELETION" and "undelete" in err.detail


def test_labelled_product_of_is_exact():
    assert V._labelled_product_of(LABELLED) == PID
    assert V._labelled_product_of(dict(ACTIVE, labels={"stackvend-product-id": ""})) == ""
    assert V._labelled_product_of(dict(ACTIVE, labels={"stackvend-product-id": 7})) == ""
    assert V._labelled_product_of(dict(ACTIVE, labels="x")) == "" and V._labelled_product_of(None) == ""


def test_a_vend_that_stopped_after_create_is_rerun_against_the_same_id_and_stopped():
    """The M2 scenario end to end: a random-suffix id (product id too short to be an id) is created, the vend stops
    before provenance (the create poll times out), the re-run uses the recorded id (no second project) and refuses to
    adopt the labelled, unprovenanced project."""
    pid = "ab"
    db = f.FakeDB()
    crm = FakeCRM(db, create=(OP, HttpError(409)), op=(TimeoutError("poll deadline"),))
    eng = _engine(db, crm)
    with pytest.raises(TimeoutError):
        eng.vend_gcp_project(pid, "tr-1", folder_id=f.ROOT)
    first = crm.created_ids[0]
    rec = db.doc(f"workloads/{pid}")
    assert set(rec) == {"project_id", "vend_target"} and rec["project_id"] == first   # before the create, nothing else
    assert rec["vend_target"]["project_id"] == first and rec["vend_target"]["trace_id"] == "tr-1"

    crm.get_script = _Script({"name": f"projects/{NUMBER}", "projectId": first, "state": "ACTIVE",
                              "labels": {"stackvend-managed": "true", "stackvend-product-id": pid,
                                         "stackvend-workload-type": "standard"}})
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        eng.vend_gcp_project(pid, "tr-2", folder_id=f.ROOT)
    assert exc.value.error_class == "VENDING.PROJECT_UNPROVENANCED"
    assert crm.created_ids == [first, first]   # the same id twice (the second answered 409): no second project


def test_target_write_failure_stops_before_any_create(_fakes):
    db = f.FakeDB()
    db.fail_write_paths.add("workloads")
    crm = FakeCRM(db)
    err = _stop(_engine(db, crm), force_new_project_id=PROJECT)
    assert err.error_class == "VENDING.PROJECT_TARGET_UNRECORDED" == V.PROJECT_TARGET_UNRECORDED
    assert crm.calls == [] and "Nothing was created" in err.detail


def test_record_already_naming_the_target_gets_only_the_marker(_fakes):
    """VENDING-TARGET-MARKER: a pre-assigned record gets the marker (and the same project_id); status untouched."""
    db = f.FakeDB()
    _record(db, "PROVISIONING")
    crm = FakeCRM(db)
    _vend(_engine(db, crm))
    snap = crm.record_at_create[0]
    assert snap["project_id"] == PROJECT and snap["status"] == "PROVISIONING"
    assert snap["vend_target"]["project_id"] == PROJECT and snap["vend_target"]["trace_id"] == "tr-1"
    assert crm.created_ids == [PROJECT]


def test_negative_record_with_the_marker_for_the_target_gets_no_extra_write(_fakes):
    db = f.FakeDB()
    _record(db, "PROVISIONING")
    db.docs[f"workloads/{PID}"]["vend_target"] = {"project_id": PROJECT, "trace_id": "tr-0", "recorded_at": "t0"}
    crm = FakeCRM(db)
    _vend(_engine(db, crm))
    assert crm.record_at_create[0]["vend_target"]["trace_id"] == "tr-0"   # not rewritten
    assert not [w for w in db.writes if w[1] == f"workloads/{PID}" and "vend_target" in w[2]]


def test_negative_decommissioned_record_is_not_rewritten_before_create(_fakes):
    db = f.FakeDB()
    _record(db, "DECOMMISSIONED", project_id="fresh-svc-old111")
    crm = FakeCRM(db)
    _vend(_engine(db, crm), force_new_project_id=PROJECT)
    assert crm.record_at_create == [{"product_id": PID, "project_id": "fresh-svc-old111", "status": "DECOMMISSIONED"}]


@pytest.mark.parametrize("force", [None, PROJECT])
def test_unreadable_record_stops_typed_before_anything_is_created(force):
    """VENDING-RECORD-UNREADABLE (RT SAT-38 L4): the record may name a project this workload owns; an unreadable
    record used to be taken for "no record" (new id, possibly a second project). Nothing is created or written."""
    db = f.FakeDB()
    _record(db, "ACTIVE", project_id="fresh-svc-other1")
    db.fail_paths.add(f"workloads/{PID}")
    crm = FakeCRM(db)
    kw = {"force_new_project_id": force} if force else {}
    err = _stop(_engine(db, crm), **kw)
    assert err.error_class == "VENDING.WORKLOAD_RECORD_UNREADABLE" == V.WORKLOAD_RECORD_UNREADABLE
    assert f"workloads/{PID}" in err.detail and isinstance(err.__cause__, RuntimeError)
    assert crm.calls == [] and db.writes == []
    assert _workload(db) == {"product_id": PID, "project_id": "fresh-svc-other1", "status": "ACTIVE"}


def test_negative_missing_record_is_not_unreadable(_fakes):
    """No record at all (Drive intake, a force id) is a readable answer: the vend goes on as before."""
    db = f.FakeDB()
    crm = FakeCRM(db)
    res = _vend(_engine(db, crm), force_new_project_id=PROJECT)
    assert res["status"] == "PROJECT_VENDED" and crm.created_ids == [PROJECT]


def test_new_record_gets_the_target_before_the_create(_fakes):
    db = f.FakeDB()
    crm = FakeCRM(db)
    res = _vend(_engine(db, crm), force_new_project_id=PROJECT)
    assert len(crm.record_at_create) == 1 and set(crm.record_at_create[0]) == {"project_id", "vend_target"}
    assert crm.record_at_create[0]["project_id"] == PROJECT and res["provenance_status"] == "RECORDED"


# ------------------------------------------------------------------------------------------------ L3 target marker
def _marked(db, status="PROVISIONING", marker_id=PROJECT):
    _record(db, status)
    db.docs[f"workloads/{PID}"]["vend_target"] = {"project_id": marker_id, "trace_id": "tr-0",
                                                  "recorded_at": "2026-11-02T10:00:00+00:00"}


@pytest.mark.parametrize("http", [403, 404])
def test_earlier_marker_for_the_id_taken_and_unreadable_stops_typed(http):
    """VENDING-TARGET-MARKER (RT SAT-38 L3): an earlier vend attempted this id (e.g. it crashed while the create was
    in flight); 409 + 403/404 now stops instead of creating a fallback (second) project."""
    db = f.FakeDB()
    _marked(db)
    crm = FakeCRM(db, get=(HttpError(http),), create=(HttpError(409),))
    err = _stop(_engine(db, crm))
    assert err.error_class == "VENDING.VEND_TARGET_UNREADABLE" == V.VEND_TARGET_UNREADABLE
    assert PROJECT in err.detail and "tr-0" in err.detail and "vend_target" in err.detail
    assert crm.created_ids == [PROJECT] and _workload(db)["project_id"] == PROJECT   # no fallback, not repointed


@pytest.mark.parametrize("http", [403, 404])
def test_failed_record_of_a_vended_project_never_falls_back_to_a_second_project(http):
    """WORKLOAD-STATUS-PRE-DEPLOY-FAILURE: a run that stopped after vending now leaves FAILED on a record that was
    PROVISIONED, so the re-run is no longer "recorded as created". The marker of the vend that created the project still
    stops a fallback id (the adoption path is test_negative_409_found_labelled_with_its_provenance_is_adopted_as_before)."""
    db = f.FakeDB()
    _marked(db, status="FAILED")
    crm = FakeCRM(db, get=(HttpError(http),), create=(HttpError(409),))
    err = _stop(_engine(db, crm))
    assert err.error_class == "VENDING.VEND_TARGET_UNREADABLE"
    assert crm.created_ids == [PROJECT] and _workload(db)["project_id"] == PROJECT   # no fallback, not repointed


def test_crash_while_create_in_flight_then_rerun_while_unreadable_stops(_fakes):
    """The review's L3 scenario end to end: the first vend crashes after Google accepted the create (poll deadline);
    the re-run reads 403 (create not visible yet) and stops instead of falling back to a second project."""
    db = f.FakeDB()
    _record(db, "PROVISIONING")
    crm = FakeCRM(db, create=(OP, HttpError(409)), op=(TimeoutError("poll deadline"),), get=(HttpError(403),))
    eng = _engine(db, crm)
    with pytest.raises(TimeoutError):
        _vend(eng)
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        eng.vend_gcp_project(PID, "tr-2", folder_id=f.ROOT)
    assert exc.value.error_class == "VENDING.VEND_TARGET_UNREADABLE" and "tr-1" in exc.value.detail
    assert crm.created_ids == [PROJECT, PROJECT]   # no second project


def test_negative_first_run_pre_assigned_external_id_still_falls_back(_fakes):
    """A first run with a Control Center pre-assigned id has no marker: an id taken outside StackVend still gets the
    fallback id, exactly as before (the run's own marker write is not in its start-of-vend snapshot)."""
    db = f.FakeDB()
    _record(db, "PROVISIONING")
    crm = FakeCRM(db, get=(HttpError(403),), create=(HttpError(409), OP))
    res = _vend(_engine(db, crm))
    assert len(crm.created_ids) == 2 and res["project_id"] == crm.created_ids[1] != PROJECT


def test_negative_marker_for_another_id_still_falls_back(_fakes):
    db = f.FakeDB()
    _marked(db, marker_id="fresh-svc-other1")
    crm = FakeCRM(db, get=(HttpError(404),), create=(HttpError(409), OP))
    res = _vend(_engine(db, crm))
    assert len(crm.created_ids) == 2 and res["project_id"] == crm.created_ids[1]


def test_negative_decommissioned_record_marker_is_ignored(_fakes):
    """A decommissioned workload's marker names its old (possibly purged) project: a plain re-vend of the same
    deterministic id that reads 403 falls back exactly as before."""
    db = f.FakeDB()
    _marked(db, status="DECOMMISSIONED", marker_id=PID)
    db.docs[f"workloads/{PID}"]["project_id"] = PID
    crm = FakeCRM(db, get=(HttpError(403),), create=(HttpError(409), OP))
    res = _vend(_engine(db, crm))
    assert crm.created_ids[0] == PID and len(crm.created_ids) == 2 and res["project_id"] == crm.created_ids[1]


@pytest.mark.parametrize("marker", [None, "x", {}, {"project_id": ""}, {"project_id": 7}])
def test_negative_malformed_marker_is_no_marker(marker):
    db = f.FakeDB()
    _record(db, "PROVISIONING")
    db.docs[f"workloads/{PID}"]["vend_target"] = marker
    crm = FakeCRM(db, get=(HttpError(403),), create=(HttpError(409), OP))
    res = _vend(_engine(db, crm))
    assert len(crm.created_ids) == 2 and res["project_id"] == crm.created_ids[1]


def test_negative_earlier_marker_with_a_found_project_takes_the_normal_adoption_path(_fakes):
    """The marker only changes the not-found answer: a found, provenanced project is adopted as before."""
    db = f.FakeDB()
    _marked(db, status="FAILED")
    db.docs[f"workload_provenance/{PID}"] = PROVENANCE
    crm = FakeCRM(db, get=(LABELLED,), create=(HttpError(409),))
    res = _vend(_engine(db, crm))
    assert res["status"] == "PROJECT_VENDED" and res["provenance_status"] == "NOT_CREATED_IN_THIS_CALL"


# ------------------------------------------------------------------------------------------------ normal paths
BEFORE_NEW_VEND = [   # pinned before SAT-38 (test_vending_read_transient.BEFORE_NEW_VEND minus answered reads)
    ("projects.create", PROJECT), ("operations.get", "operations/cp.42"),
    ("projects.getIamPolicy", f"projects/{PROJECT}"), ("projects.setIamPolicy", f"projects/{PROJECT}"),
    ("tagBindings.create", f"//cloudresourcemanager.googleapis.com/projects/{NUMBER}"),
]


def test_negative_normal_first_vend_calls_and_record_unchanged(_fakes):
    db = f.FakeDB()
    _record(db, "PROVISIONING")
    crm = FakeCRM(db)
    res = _vend(_engine(db, crm, devops_sa="sa-devops@host.iam.gserviceaccount.com"))
    assert crm.calls == BEFORE_NEW_VEND and _fakes.sleeps == []
    assert res["project_id"] == PROJECT and res["provenance_status"] == "RECORDED"
    assert _workload(db)["status"] == "PROVISIONED" and _workload(db)["project_number"] == NUMBER


@pytest.mark.parametrize("status", ["PROVISIONED", "ACTIVE"])
def test_negative_normal_revend_calls_unchanged_and_no_write_before_create(status):
    db = f.FakeDB()
    _record(db, status)
    crm = FakeCRM(db, get=(LABELLED,))
    res = _vend(_engine(db, crm, devops_sa="sa-devops@host.iam.gserviceaccount.com"))
    assert crm.calls == [
        ("projects.get", f"projects/{PROJECT}"),
        ("projects.getIamPolicy", f"projects/{PROJECT}"),
        ("projects.get", f"projects/{PROJECT}"),
        ("projects.setIamPolicy", f"projects/{PROJECT}"),
        ("projects.get", f"projects/{PROJECT}"),
    ]
    assert res["provenance_status"] == "NOT_CREATED_IN_THIS_CALL" and crm.created_ids == []
    assert not any(w[2] == {"project_id": PROJECT} for w in db.writes)


# ------------------------------------------------------------------------------------------------ helpers
def test_labelled_for_product_is_exact():
    assert V._labelled_for_product(LABELLED, PID)
    assert not V._labelled_for_product(LABELLED, PID + "x")
    assert not V._labelled_for_product(LABELLED, "")
    assert not V._labelled_for_product(dict(ACTIVE, labels=dict(OURS, **{"stackvend-managed": "yes"})), PID)
    assert not V._labelled_for_product(None, PID)


def test_project_number_of_uses_typed_fields_only():
    assert V._project_number_of(ACTIVE) == NUMBER
    assert V._project_number_of({"projectNumber": NUMBER}) == NUMBER
    assert V._project_number_of({"name": f"projects/{PROJECT}"}) == ""
    assert V._project_number_of({"name": f"folders/{NUMBER}", "projectNumber": "x1"}) == ""
