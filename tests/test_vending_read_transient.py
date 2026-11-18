"""VENDING-READ-TRANSIENT (SAT-25, row drafted, NOT approved yet): vending's single Resource Manager projects.get reads
are read again after a TRANSIENT error, within a bound, and never mistaken for "no such project".

Before: the existence check of a recorded project took any error (a timeout too) for "not created" and created it; the
ownership check after a 409 on create took any error for "taken by someone else" and created a SECOND project under a
fallback id; the project-number read swallowed any error, so provenance was skipped (PROVENANCE_SKIPPED_NO_NUMBER) and
the project was never deletable by StackVend.

Now (`ProjectRepoVendingEngine._get_project`): transient = vending._is_transient_poll_error (class and HTTP status only,
the merged VENDING-POLL-TRANSIENT classifier); read again with the poll backoff (1 s x1.5, cap 5 s) within
PROJECT_READ_MAX_WAIT_S; only HTTP 403 / 404 means "not ours / not found" (OQ-29); any other error is raised unchanged;
still transient at the bound -> VendingFailure(VENDING.PROJECT_READ_UNAVAILABLE). The project number of a project
created in this call comes from the finished create operation's response (F-C), else the read; still unknown ->
VendingFailure(VENDING.PROJECT_NUMBER_UNRESOLVED) (OQ-28). The BILLING_NOT_LINKED path records `provenance_status`.

Negatives (Do No Harm): a clean vend makes the same calls in the same order as before, minus the number reads the create
operation already answered; a re-vend of a recorded project makes exactly the same calls; a non-transient 400 is raised
unchanged; a re-vend whose number read fails non-transiently goes on as before.
Hermetic: a recording fake Resource Manager client, tests/destructive_guard_fakes.FakeDB, a fake clock."""

import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import logging
import os
import socket
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import destructive_guard_fakes as f  # noqa: E402

# Imported at collection time: the root conftest snapshots each test module's sys.modules view at import (FD-05A).
VENDING_MAIN = f.load_vending_main()
V = sys.modules[VENDING_MAIN.ProjectRepoVendingEngine.__module__]   # the vending module the engine runs in
BILLING = "billingAccounts/000000-AAAAAA-BBBBBB"   # synthetic
PID = "fresh-svc"
PROJECT = "fresh-svc-123abc"
NUMBER = f.NUMBER
OP_DONE = {"name": "operations/cp.42", "done": True, "response": {"name": f"projects/{NUMBER}", "projectId": PROJECT}}
OP_DONE_NO_RESPONSE = {"name": "operations/cp.42", "done": True}
ACTIVE = {"name": f"projects/{NUMBER}", "projectId": PROJECT, "state": "ACTIVE"}


class HttpError(Exception):
    """Shape of googleapiclient.errors.HttpError (resp.status). Patched in as vending.HttpError, because other test
    modules may have stubbed googleapiclient out before this one runs."""

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
    """Answers the next scripted item (an exception is raised); the last item repeats."""

    def __init__(self, *items):
        self.items = list(items)

    def next(self):
        item = self.items.pop(0) if len(self.items) > 1 else self.items[0]
        if isinstance(item, BaseException):
            raise item
        return item


class FakeCRM:
    """Resource Manager v3 fake that records every call, in order, as (method, target)."""

    def __init__(self, get=(ACTIVE,), create=({"name": "operations/cp.42"},), op=(OP_DONE,)):
        self.get_script = _Script(*get)
        self.create_script = _Script(*create)
        self.op_script = _Script(*op)
        self.calls = []
        self.created_ids = []

    # projects() / operations() / tagBindings() all hand back this object; the method names do not collide.
    def projects(self):
        return self

    def operations(self):
        return _Ops(self)

    def tagBindings(self):
        return _Tags(self)

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
        def run():
            self.calls.append(("projects.getIamPolicy", resource))
            return {"bindings": []}
        return _Call(run)

    def setIamPolicy(self, resource, body):
        def run():
            self.calls.append(("projects.setIamPolicy", resource))
            self.last_policy = body["policy"]
            return body["policy"]
        return _Call(run)


class _Ops:
    def __init__(self, crm):
        self.crm = crm

    def get(self, name):
        def run():
            self.crm.calls.append(("operations.get", name))
            return self.crm.op_script.next()
        return _Call(run)


class _Tags:
    def __init__(self, crm):
        self.crm = crm

    def create(self, body):
        def run():
            self.crm.calls.append(("tagBindings.create", body["parent"]))
            return {"name": "tagBindings/x"}
        return _Call(run)


@pytest.fixture(autouse=True)
def _fakes(monkeypatch):
    """Fake clock + typed HttpError in the vending module; platform settings without Firestore; tag configured."""
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
    # API enablement and the org-policy check use their own clients; not under test here.
    monkeypatch.setattr(V.ProjectRepoVendingEngine, "enable_child_apis", lambda self, pid: {"status": "ENABLED"})
    monkeypatch.setattr(V.ProjectRepoVendingEngine, "check_child_org_policies", lambda self, pid: [])
    yield clock
    live.invalidate_settings_cache()


def _engine(db, crm, billing_account="", billing=None, devops_sa=""):
    eng = VENDING_MAIN.ProjectRepoVendingEngine(iam_client=f.FakeChildIAM(), platform_project_id=f.HOST, firestore_client=db, crm_service=crm,
                                                billing_service=billing or MagicMock(), storage_client=MagicMock())
    eng.billing_account_id = billing_account
    eng.devops_sa_email = devops_sa
    return eng


def _vend_new(eng):
    return eng.vend_gcp_project(PID, "tr-1", folder_id=f.ROOT, force_new_project_id=PROJECT)


def _recorded(db, status="ACTIVE"):
    db.docs[f"workloads/{PID}"] = {"product_id": PID, "project_id": PROJECT, "status": status}


def _revend(eng):
    return eng.vend_gcp_project(PID, "tr-2", folder_id=f.ROOT)


def _gets(crm):
    return [c for c in crm.calls if c[0] == "projects.get"]


# ------------------------------------------------------------------------------------------------ _get_project
def test_negative_clean_read_is_one_call_no_sleep_no_warning(_fakes, caplog):
    crm = FakeCRM(get=(ACTIVE,))
    with caplog.at_level(logging.WARNING):
        assert _engine(f.FakeDB(), crm)._get_project(PROJECT, "x") == (True, ACTIVE)
    assert crm.calls == [("projects.get", f"projects/{PROJECT}")] and _fakes.sleeps == []
    assert "VENDING_READ_TRANSIENT" not in caplog.text


@pytest.mark.parametrize("err", [TimeoutError("The read operation timed out"), socket.timeout("timed out"),
                                 ConnectionResetError(54, "reset"), HttpError(429), HttpError(500), HttpError(502),
                                 HttpError(503), HttpError(504)])
def test_transient_read_is_read_again(_fakes, caplog, err):
    crm = FakeCRM(get=(err, ACTIVE))
    with caplog.at_level(logging.WARNING):
        assert _engine(f.FakeDB(), crm)._get_project(PROJECT, "existence check") == (True, ACTIVE)
    assert len(crm.calls) == 2 and _fakes.sleeps == [1.0]
    warning = [r.getMessage() for r in caplog.records if "VENDING_READ_TRANSIENT" in r.getMessage()]
    assert len(warning) == 1 and type(err).__name__ in warning[0] and PROJECT in warning[0]
    assert "timed out" not in warning[0] and "reset" not in warning[0]   # class / status only, never the message


@pytest.mark.parametrize("status", [403, 404])
def test_typed_not_ours_is_not_found(_fakes, status):
    crm = FakeCRM(get=(HttpError(status),))
    assert _engine(f.FakeDB(), crm)._get_project(PROJECT, "x") == (False, None)
    assert len(crm.calls) == 1 and _fakes.sleeps == []


@pytest.mark.parametrize("err", [HttpError(400), HttpError(401), HttpError(409), HttpError(501), HttpError(None),
                                 RuntimeError("The read operation timed out"), ValueError("503")])
def test_non_transient_error_is_raised_unchanged(_fakes, err):
    crm = FakeCRM(get=(err,))
    with pytest.raises(type(err)) as exc:
        _engine(f.FakeDB(), crm)._get_project(PROJECT, "x")
    assert exc.value is err and len(crm.calls) == 1 and _fakes.sleeps == []


def test_transient_until_the_bound_is_typed_failure(_fakes):
    last = TimeoutError("t")
    crm = FakeCRM(get=(HttpError(503), last))
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _engine(f.FakeDB(), crm)._get_project(PROJECT, "ownership check after 409 on create")
    assert exc.value.error_class == "VENDING.PROJECT_READ_UNAVAILABLE" == V.PROJECT_READ_UNAVAILABLE
    assert PROJECT in exc.value.detail and "ownership check after 409 on create" in exc.value.detail
    assert "TimeoutError" in exc.value.detail and exc.value.__cause__ is last
    assert sum(_fakes.sleeps) <= V.PROJECT_READ_MAX_WAIT_S and max(_fakes.sleeps) == 5.0
    assert _fakes.sleeps[:4] == [1.0, 1.5, 2.25, 3.375]
    assert len(crm.calls) == len(_fakes.sleeps) + 1


# ------------------------------------------------------------------------------------------------ existence check
def test_existence_check_timeout_then_active_creates_nothing(_fakes):
    db, crm = f.FakeDB(), FakeCRM(get=(TimeoutError("t"), ACTIVE))
    _recorded(db)
    res = _revend(_engine(db, crm))
    assert res["status"] == "PROJECT_VENDED" and res["project_id"] == PROJECT
    assert crm.created_ids == [] and res["provenance_status"] == "NOT_CREATED_IN_THIS_CALL"


def test_existence_check_transient_until_bound_fails_typed_and_creates_nothing(_fakes):
    db, crm = f.FakeDB(), FakeCRM(get=(TimeoutError("t"),))
    _recorded(db)
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _revend(_engine(db, crm))
    assert exc.value.error_class == "VENDING.PROJECT_READ_UNAVAILABLE"
    assert "existence check of the recorded project" in exc.value.detail
    assert crm.created_ids == [] and db.doc(f"workload_provenance/{PID}") is None


@pytest.mark.parametrize("status", [403, 404])
def test_existence_check_not_found_stops_typed_without_create(_fakes, status):
    """SAT-38 (RT SAT-25 M1) changed this: a recorded project that reads 403/404 used to be created again (which can
    only 409 into a fallback, second project); it is now VENDING.RECORDED_PROJECT_UNREADABLE with nothing created."""
    db, crm = f.FakeDB(), FakeCRM(get=(HttpError(status),))
    _recorded(db)
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _revend(_engine(db, crm))
    assert exc.value.error_class == "VENDING.RECORDED_PROJECT_UNREADABLE" and PROJECT in exc.value.detail
    assert crm.created_ids == []


def test_existence_check_non_transient_error_stops_typed_and_creates_nothing(_fakes):
    """SAT-38 (RT SAT-25 I2): still stops, now typed VENDING.PROJECT_READ_FAILED, chained to the original error."""
    err = HttpError(400)
    db, crm = f.FakeDB(), FakeCRM(get=(err,))
    _recorded(db)
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _revend(_engine(db, crm))
    assert exc.value.error_class == "VENDING.PROJECT_READ_FAILED" and exc.value.__cause__ is err
    assert "HttpError 400" in exc.value.detail and crm.created_ids == []


# ------------------------------------------------------------------------------------------------ 409 branch
def test_409_then_timeout_then_found_proceeds_with_same_id_and_one_create(_fakes):
    db, crm = f.FakeDB(), FakeCRM(create=(HttpError(409),), get=(TimeoutError("t"), ACTIVE))
    res = _vend_new(_engine(db, crm))
    assert res["status"] == "PROJECT_VENDED" and res["project_id"] == PROJECT
    assert crm.created_ids == [PROJECT]   # exactly one projects.create: no second project
    assert res["provenance_status"] == "NOT_CREATED_IN_THIS_CALL"


def test_409_then_transient_until_bound_fails_typed_without_fallback_create(_fakes):
    db, crm = f.FakeDB(), FakeCRM(create=(HttpError(409),), get=(HttpError(503),))
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend_new(_engine(db, crm))
    assert exc.value.error_class == "VENDING.PROJECT_READ_UNAVAILABLE"
    assert "ownership check after 409 on create" in exc.value.detail
    assert crm.created_ids == [PROJECT]


def test_409_then_unknown_error_stops_typed_without_fallback_create(_fakes):
    """SAT-38 (RT SAT-25 I2): still stops, now typed VENDING.PROJECT_READ_FAILED, chained to the original error."""
    err = HttpError(400)
    db, crm = f.FakeDB(), FakeCRM(create=(HttpError(409),), get=(err,))
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend_new(_engine(db, crm))
    assert exc.value.error_class == "VENDING.PROJECT_READ_FAILED" and exc.value.__cause__ is err
    assert crm.created_ids == [PROJECT]


@pytest.mark.parametrize("status", [403, 404])
def test_409_then_typed_not_ours_creates_the_fallback_id_as_before(_fakes, status):
    db, crm = f.FakeDB(), FakeCRM(create=(HttpError(409), {"name": "operations/cp.43"}), get=(HttpError(status),))
    res = _vend_new(_engine(db, crm))
    assert len(crm.created_ids) == 2 and crm.created_ids[0] == PROJECT
    fallback = crm.created_ids[1]
    assert fallback != PROJECT and fallback.startswith(PROJECT[:23].rstrip("-") + "-")
    assert res["project_id"] == fallback and res["provenance_status"] == "RECORDED"
    assert res["project_number"] == NUMBER   # from the fallback create operation's response


# ------------------------------------------------------------------------------------------------ project number
def test_number_from_create_operation_needs_no_read(_fakes):
    db, crm = f.FakeDB(), FakeCRM()
    res = _vend_new(_engine(db, crm))
    assert res["project_number"] == NUMBER and res["provenance_status"] == "RECORDED"
    assert _gets(crm) == []
    assert db.doc(f"workload_provenance/{PID}")["project_number"] == NUMBER


def test_operation_without_number_falls_back_to_the_read(_fakes):
    db, crm = f.FakeDB(), FakeCRM(op=(OP_DONE_NO_RESPONSE,), get=(TimeoutError("t"), ACTIVE))
    res = _vend_new(_engine(db, crm))
    assert res["project_number"] == NUMBER and res["provenance_status"] == "RECORDED"
    assert len(_gets(crm)) == 2


@pytest.mark.parametrize("response", [{"name": "projects/fresh-svc-123abc"}, {"name": "projects/"}, {},
                                      {"name": f"organizations/{NUMBER}"}])
def test_operation_response_without_an_exact_number_is_not_trusted(_fakes, response):
    op = dict(OP_DONE, response=response)
    db, crm = f.FakeDB(), FakeCRM(op=(op,), get=(ACTIVE,))
    res = _vend_new(_engine(db, crm))
    assert res["project_number"] == NUMBER and len(_gets(crm)) == 1


@pytest.mark.parametrize("status", [403, 404])
def test_created_project_number_still_missing_fails_typed(_fakes, status):
    db, crm = f.FakeDB(), FakeCRM(op=(OP_DONE_NO_RESPONSE,), get=(HttpError(status),))
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend_new(_engine(db, crm))
    assert exc.value.error_class == "VENDING.PROJECT_NUMBER_UNRESOLVED" == V.PROJECT_NUMBER_UNRESOLVED
    assert PROJECT in exc.value.detail and f"delete projects/{PROJECT}" in exc.value.detail
    wdoc = db.doc(f"workloads/{PID}")
    assert wdoc["project_id"] == PROJECT and wdoc["vending_error_class"] == "VENDING.PROJECT_NUMBER_UNRESOLVED"
    assert wdoc["provenance_status"] == "PROVENANCE_SKIPPED_NO_NUMBER" and "status" not in wdoc
    assert db.doc(f"workload_provenance/{PID}") is None


def test_created_project_number_read_transient_until_bound_fails_typed(_fakes):
    last = TimeoutError("t")
    db, crm = f.FakeDB(), FakeCRM(op=(OP_DONE_NO_RESPONSE,), get=(last,))
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend_new(_engine(db, crm))
    assert exc.value.error_class == "VENDING.PROJECT_READ_UNAVAILABLE" and exc.value.__cause__ is last
    assert "(project number)" in exc.value.detail and f"delete projects/{PROJECT}" in exc.value.detail
    # one order only (RT L2): delete first, then re-run; no generic "re-run the vend" tail before it
    assert exc.value.detail.count("re-run the vend") == 1 and "The vend stopped at this read" not in exc.value.detail
    assert exc.value.detail.index("first delete") < exc.value.detail.index("re-run the vend")
    assert db.doc(f"workloads/{PID}")["vending_error_class"] == "VENDING.PROJECT_READ_UNAVAILABLE"


def test_created_project_number_read_non_transient_error_fails_typed(_fakes):
    err = HttpError(400)
    db, crm = f.FakeDB(), FakeCRM(op=(OP_DONE_NO_RESPONSE,), get=(err,))
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend_new(_engine(db, crm))
    assert exc.value.error_class == "VENDING.PROJECT_NUMBER_UNRESOLVED" and exc.value.__cause__ is err


def test_revend_number_read_transient_until_bound_fails_typed(_fakes):
    db, crm = f.FakeDB(), FakeCRM(get=(ACTIVE, TimeoutError("t")))
    _recorded(db)
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _revend(_engine(db, crm))
    assert exc.value.error_class == "VENDING.PROJECT_READ_UNAVAILABLE" and "(project number)" in exc.value.detail
    assert crm.created_ids == []


@pytest.mark.parametrize("err", [HttpError(400), HttpError(404)])
def test_negative_revend_number_read_non_transient_goes_on_as_before(_fakes, err):
    db, crm = f.FakeDB(), FakeCRM(get=(ACTIVE, err))
    _recorded(db)
    res = _revend(_engine(db, crm))
    assert res["status"] == "PROJECT_VENDED" and res["project_number"] == ""
    assert res["provenance_status"] == "NOT_CREATED_IN_THIS_CALL"


def test_build_grants_use_the_operation_number(_fakes):
    db, crm = f.FakeDB(), FakeCRM()
    _vend_new(_engine(db, crm, devops_sa="sa-devops@host.iam.gserviceaccount.com"))
    assert _gets(crm) == []
    writers = next(b for b in crm.last_policy["bindings"] if b["role"] == "roles/logging.logWriter")["members"]
    assert f"serviceAccount:{NUMBER}@cloudbuild.gserviceaccount.com" in writers


def test_build_grants_read_again_after_a_transient_error(_fakes):
    db, crm = f.FakeDB(), FakeCRM(op=(OP_DONE_NO_RESPONSE,), get=(TimeoutError("t"), ACTIVE))
    _vend_new(_engine(db, crm, devops_sa="sa-devops@host.iam.gserviceaccount.com"))
    writers = next(b for b in crm.last_policy["bindings"] if b["role"] == "roles/logging.logWriter")["members"]
    assert f"serviceAccount:{NUMBER}@cloudbuild.gserviceaccount.com" in writers


# ------------------------------------------------------------------------------------------------ unbilled path
def _billing_fails():
    billing = MagicMock()
    billing.projects.return_value.updateBillingInfo.return_value.execute.side_effect = HttpError(403)
    return billing


def test_unbilled_number_from_operation_and_provenance_status_recorded(_fakes):
    db, crm = f.FakeDB(), FakeCRM()
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend_new(_engine(db, crm, billing_account=BILLING, billing=_billing_fails()))
    assert exc.value.error_class == "BILLING_NOT_LINKED"   # the billing failure stays the vend's result
    assert _gets(crm) == []
    wdoc = db.doc(f"workloads/{PID}")
    assert wdoc["vending_error_class"] == "BILLING_NOT_LINKED" and wdoc["provenance_status"] == "RECORDED"
    assert db.doc(f"workload_provenance/{PID}")["project_number"] == NUMBER


def test_unbilled_provenance_write_failure_is_recorded_on_the_workload(_fakes):
    db, crm = f.FakeDB(), FakeCRM()
    db.fail_write_paths.add("workload_provenance")
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend_new(_engine(db, crm, billing_account=BILLING, billing=_billing_fails()))
    assert exc.value.error_class == "BILLING_NOT_LINKED"
    assert db.doc(f"workloads/{PID}")["provenance_status"] == "PROVENANCE_WRITE_FAILED"


def test_unbilled_number_unresolved_is_recorded_and_billing_stays_the_result(_fakes):
    db, crm = f.FakeDB(), FakeCRM(op=(OP_DONE_NO_RESPONSE,), get=(TimeoutError("t"),))
    with pytest.raises(VENDING_MAIN.VendingFailure) as exc:
        _vend_new(_engine(db, crm, billing_account=BILLING, billing=_billing_fails()))
    assert exc.value.error_class == "BILLING_NOT_LINKED"
    assert db.doc(f"workloads/{PID}")["provenance_status"] == "PROVENANCE_SKIPPED_NO_NUMBER"


def test_unbilled_without_operation_number_reads_after_a_transient_error(_fakes):
    db, crm = f.FakeDB(), FakeCRM(op=(OP_DONE_NO_RESPONSE,), get=(HttpError(503), ACTIVE))
    with pytest.raises(VENDING_MAIN.VendingFailure):
        _vend_new(_engine(db, crm, billing_account=BILLING, billing=_billing_fails()))
    assert db.doc(f"workloads/{PID}")["provenance_status"] == "RECORDED"


def test_negative_unbilled_adopted_project_writes_no_provenance_status(_fakes):
    db, crm = f.FakeDB(), FakeCRM()
    _recorded(db)
    with pytest.raises(VENDING_MAIN.VendingFailure):
        _revend(_engine(db, crm, billing_account=BILLING, billing=_billing_fails()))
    wdoc = db.doc(f"workloads/{PID}")
    assert wdoc["vending_error_class"] == "BILLING_NOT_LINKED" and "provenance_status" not in wdoc


# ------------------------------------------------------------------------------------------------ call-list snapshots
BEFORE_NEW_VEND = [   # a clean new vend before SAT-25 (the create operation's answer was discarded)
    ("projects.create", PROJECT), ("operations.get", "operations/cp.42"),
    ("projects.getIamPolicy", f"projects/{PROJECT}"), ("projects.get", f"projects/{PROJECT}"),
    ("projects.setIamPolicy", f"projects/{PROJECT}"),
    ("projects.get", f"projects/{PROJECT}"),
    ("tagBindings.create", f"//cloudresourcemanager.googleapis.com/projects/{NUMBER}"),
]


def test_negative_clean_new_vend_calls_are_unchanged_minus_the_answered_number_reads(_fakes):
    db, crm = f.FakeDB(), FakeCRM()
    _vend_new(_engine(db, crm, devops_sa="sa-devops@host.iam.gserviceaccount.com"))
    assert crm.calls == [c for c in BEFORE_NEW_VEND if c[0] != "projects.get"]


def test_negative_clean_new_vend_without_operation_number_calls_are_unchanged(_fakes):
    db, crm = f.FakeDB(), FakeCRM(op=(OP_DONE_NO_RESPONSE,))
    res = _vend_new(_engine(db, crm, devops_sa="sa-devops@host.iam.gserviceaccount.com"))
    assert crm.calls == BEFORE_NEW_VEND and _fakes.sleeps == []
    assert res["project_number"] == NUMBER and res["provenance_status"] == "RECORDED"


def test_negative_clean_revend_calls_are_unchanged(_fakes):
    db, crm = f.FakeDB(), FakeCRM()
    _recorded(db)
    res = _revend(_engine(db, crm, devops_sa="sa-devops@host.iam.gserviceaccount.com"))
    assert crm.calls == [
        ("projects.get", f"projects/{PROJECT}"),            # existence check
        ("projects.getIamPolicy", f"projects/{PROJECT}"),
        ("projects.get", f"projects/{PROJECT}"),            # build grants' number
        ("projects.setIamPolicy", f"projects/{PROJECT}"),
        ("projects.get", f"projects/{PROJECT}"),            # step 4 number
    ]
    assert _fakes.sleeps == [] and res["project_number"] == NUMBER
    assert res["provenance_status"] == "NOT_CREATED_IN_THIS_CALL"
