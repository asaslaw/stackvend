"""
Lane 18 single window, step S2: the Control Center's destructive paths go through project-vending.

Plan: docs/planning/wave2-lane18-destructive-guards-plan.md §2.5 / §3.2; S1 code red-team "minimum S2 content" (i)-(vi).
  (i)   no in-process CRM fallback: any non-200 from vending -> HTTP 502 with vending's {code, detail}, ledger unchanged
  (ii)  destructive_approvals minted with principal_type from the auth layer (typed), approved_by_role, approved_at,
        a 15-minute expiry and the exact action + target, in the guard DB (STACKVEND_GUARD_FIRESTORE_DATABASE)
  (iii) vending is called through make_vending_request (the CC's ID token for the vending URL)
  (iv)  extend / promote / confirm -> vending /projects/{pid}/lifecycle
  (v)   vend requests (express /vend-all, the AGENT intake -> workflow vend-all-async) carry the explicit sandbox fields
  (vi)  BUDGET_BREACH DECOMMISSION -> mint + vending (EXECUTION_FAILED on failure, workload not flipped)
The sweeper -> vending SANDBOX_TTL path is covered end to end in tests/test_cc_sandbox_guard.py. Hermetic fakes only.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(BASE_DIR, "apps", "control-center")
for _p in (BASE_DIR, CC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import HTTPException  # noqa: E402

# No real Firestore client, ever (FD-08 ratchet = 0 for this file): config.py looks the OAuth client id up in
# Firestore at import when GOOGLE_OAUTH_CLIENT_ID is unset, so it is set for the duration of the imports only.
_saved_client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "lane18-test.apps.googleusercontent.com"
try:
    import authz  # noqa: E402
    import db as cc_db  # noqa: E402
    import destructive_actions as da  # noqa: E402
    from routes import approvals as appr_routes  # noqa: E402
    from routes import workloads as wl  # noqa: E402
    from schemas import (  # noqa: E402
        ApprovalDecisionRequest, ApprovalStatus, ConfirmSandboxRequest, CreateWorkloadRequest, DecommissionRequest,
        ExtendSandboxRequest, UserRole,
    )
finally:
    if _saved_client_id is None:
        os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
    else:
        os.environ["GOOGLE_OAUTH_CLIENT_ID"] = _saved_client_id

ADMIN = "owner@example.com"
PID = "shop-api"
PROJECT = "shop-api-a1b2c3"
NUMBER = "123456789012"
PLATFORM_SA = "sa-castor-finops@mock-stackvend-project.iam.gserviceaccount.com"


# ---------------------------------------------------------------------------------------------- fakes
class _Snap:
    def __init__(self, doc_id, data):
        self.id, self._d, self.exists = doc_id, copy.deepcopy(data), data is not None

    def to_dict(self):
        return copy.deepcopy(self._d) if self._d is not None else None


class _Doc:
    def __init__(self, db, path):
        self.db, self.path, self.id = db, path, path.rsplit("/", 1)[-1]

    def get(self, transaction=None):
        if self.path in self.db.fail_reads:
            raise RuntimeError("503 Firestore unavailable")
        return _Snap(self.id, self.db.docs.get(self.path))

    def set(self, data, merge=False):
        self.db.writes.append(("set", self.path, copy.deepcopy(data)))
        cur = self.db.docs.get(self.path) if merge else None
        self.db.docs[self.path] = {**(cur or {}), **copy.deepcopy(data)}

    def create(self, data):
        if self.path in self.db.docs:
            raise RuntimeError("AlreadyExists")
        self.db.writes.append(("create", self.path, copy.deepcopy(data)))
        self.db.docs[self.path] = copy.deepcopy(data)

    def collection(self, name):
        return _Coll(self.db, f"{self.path}/{name}")


class _Coll:
    def __init__(self, db, path, filters=()):
        self.db, self.path, self.filters = db, path, filters

    def document(self, doc_id=None):
        self.db.auto += 1
        return _Doc(self.db, f"{self.path}/{doc_id or 'auto' + str(self.db.auto)}")

    def where(self, field, op, value):
        return _Coll(self.db, self.path, self.filters + ((field, op, value),))

    def limit(self, *_):
        return self

    def stream(self):
        prefix = self.path + "/"
        for p, d in sorted(self.db.docs.items()):
            rest = p[len(prefix):] if p.startswith(prefix) else None
            if rest and "/" not in rest and all(
                    (op == "==" and d.get(f) == v) or (op == "in" and d.get(f) in v) for f, op, v in self.filters):
                yield _Snap(rest, d)


class FakeDB:
    def __init__(self):
        self.docs, self.writes, self.auto, self.fail_reads = {}, [], 0, set()

    def collection(self, name):
        return _Coll(self, name)

    def ledger_writes(self, pid=PID):
        return [w for w in self.writes if w[1] == f"workloads/{pid}"]

    def audits(self, pid=PID):
        return [d.get("action") for p, d in sorted(self.docs.items()) if p.startswith(f"workloads/{pid}/audit_logs/")]

    def approvals(self):
        return {p.split("/", 1)[1]: d for p, d in self.docs.items() if p.startswith("destructive_approvals/")}


class _Resp:
    def __init__(self, status_code, body):
        self.status_code, self._body, self.text = status_code, body, json.dumps(body)

    def json(self):
        return self._body


class FakeVending:
    def __init__(self, status_code=200, body=None):
        self.status_code, self.body, self.calls = status_code, body, []

    def __call__(self, method, path, json_body=None, timeout=60.0, request=None):
        self.calls.append((method, path, copy.deepcopy(json_body)))
        if self.status_code is None:
            return None
        return _Resp(self.status_code, self.body if self.body is not None else {})


def refusal(code, status, detail="refused"):
    return FakeVending(status, {"detail": {"code": code, "detail": detail}})


def human(role=UserRole.ADMIN, method="session", email=ADMIN):
    return SimpleNamespace(state=SimpleNamespace(user_email=email, user_role=role, auth_method=method,
                                                 token_audience=""), headers={})


def seed(db, **fields):
    rec = {"product_id": PID, "project_id": PROJECT, "project_number": NUMBER, "status": "ACTIVE", "is_castor": False}
    rec.update(fields)
    db.docs[f"workloads/{PID}"] = rec
    return rec


@pytest.fixture
def world(monkeypatch):
    """Default DB doubles as the guard DB (STACKVEND_GUARD_FIRESTORE_DATABASE unset); no CRM/discovery client may be
    built by the Control Center (any attempt fails the test)."""
    monkeypatch.delenv("STACKVEND_GUARD_FIRESTORE_DATABASE", raising=False)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    monkeypatch.delenv("PLATFORM_PROJECT_ID", raising=False)
    db = FakeDB()
    monkeypatch.setattr(wl, "db", db)
    monkeypatch.setattr(appr_routes, "db", db)
    monkeypatch.setattr(da, "get_guard_db", lambda: db)
    cancel = MagicMock(return_value=0)
    monkeypatch.setattr(wl, "cancel_workload_active_executions", cancel)

    def _forbidden(*a, **k):
        raise AssertionError("the Control Center must not build a Resource Manager / DNS client (lane 18 S2)")

    import googleapiclient.discovery as gdisc
    monkeypatch.setattr(gdisc, "build", _forbidden)
    return SimpleNamespace(db=db, cancel=cancel)


def _decommission(vending, request=None, confirm=PID, approval_ref=None):
    with patch.object(wl, "make_vending_request", vending):
        return wl.decommission_workload_endpoint(PID, DecommissionRequest(confirm_product_id=confirm, reason="test",
                                                                         approval_id=approval_ref),
                                                 request or human())


def _json(resp):
    return json.loads(resp.body)


# ---------------------------------------------------------------------------------------------- (ii) principal typing
@pytest.mark.parametrize("method,expected", [("session", "USER"), ("iap", "USER"), ("", ""), ("bearer", "")])
def test_principal_type_is_typed_from_the_auth_method(method, expected):
    assert authz.principal_type(human(method=method)) == expected


def test_platform_bearer_is_a_service_account_even_with_a_user_looking_email(monkeypatch):
    monkeypatch.setattr(authz.identity, "platform_callers", lambda: frozenset({"ops@example.com"}))
    assert authz.principal_type(human(method="bearer", email="ops@example.com")) == "SERVICE_ACCOUNT"
    # and an SA-looking email on a human session is still typed by HOW it was verified (no email-suffix test)
    assert authz.principal_type(human(method="session", email=PLATFORM_SA)) == "USER"


# ---------------------------------------------------------------------------------------------- (ii) mint
def test_mint_writes_the_vending_approval_schema(world):
    now = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)
    aid = da.mint_approval(human(email="Owner@Example.com"), action="PROJECT_DECOMMISSION", product_id=PID,
                           project_id=PROJECT, project_number=NUMBER, reason="r", now=now)
    rec = world.db.approvals()[aid]
    assert rec == {"status": "APPROVED", "action": "PROJECT_DECOMMISSION", "product_id": PID, "project_id": PROJECT,
                   "project_number": NUMBER, "resource_name": None, "principal_type": "USER",
                   "approved_by": "owner@example.com", "approved_by_role": "ADMIN",
                   "approved_at": now.isoformat(), "expires_at": (now + timedelta(minutes=15)).isoformat(),
                   "minted_by": "control-center", "reason": "r"}
    assert [w[0] for w in world.db.writes] == ["create"]


@pytest.mark.parametrize("req,code", [
    (human(method="bearer", email=PLATFORM_SA), "APPROVAL_NOT_HUMAN"),
    (human(method=""), "APPROVAL_NOT_HUMAN"),
    (human(role=UserRole.WORKLOAD_MANAGER), "APPROVAL_NOT_ADMIN"),
    (human(role=UserRole.VIEWER), "APPROVAL_NOT_ADMIN"),
])
def test_mint_refuses_non_human_or_non_admin(world, req, code):
    with pytest.raises(da.MintRefused) as ei:
        da.mint_approval(req, action="PROJECT_DECOMMISSION", product_id=PID, project_id=PROJECT,
                         project_number=NUMBER)
    assert ei.value.code == code and ei.value.http_status == 403
    assert world.db.writes == []


def test_mint_refuses_when_the_configured_guard_db_is_unavailable(world, monkeypatch):
    monkeypatch.setattr(da, "get_guard_db", lambda: None)
    with pytest.raises(da.MintRefused) as ei:
        da.mint_approval(human(), action="PROJECT_DECOMMISSION", product_id=PID, project_id=PROJECT,
                         project_number=NUMBER)
    assert (ei.value.http_status, ei.value.code) == (503, "APPROVAL_STORE_UNAVAILABLE")
    assert world.db.writes == []


def test_guard_db_named_database_never_falls_back_to_default(monkeypatch):
    class _Firestore:
        calls = []

        @classmethod
        def Client(cls, project=None, database=None):
            cls.calls.append((project, database))
            raise RuntimeError("PERMISSION_DENIED")

    monkeypatch.setenv("STACKVEND_GUARD_FIRESTORE_DATABASE", "stackvend-guard")
    monkeypatch.setattr(cc_db, "firestore", _Firestore)
    monkeypatch.setattr(cc_db, "PROJECT_ID", "mock-stackvend-project")
    monkeypatch.setattr(cc_db, "_guard_db_client", None)
    monkeypatch.setattr(cc_db, "get_db", lambda: pytest.fail("fell back to the default database"))
    assert cc_db.get_guard_db() is None
    assert _Firestore.calls == [("mock-stackvend-project", "stackvend-guard")]


def test_guard_db_unset_is_the_default_db(monkeypatch):
    sentinel = object()
    monkeypatch.delenv("STACKVEND_GUARD_FIRESTORE_DATABASE", raising=False)
    monkeypatch.setattr(cc_db, "get_db", lambda: sentinel)
    assert cc_db.get_guard_db() is sentinel


# ---------------------------------------------------------------------------------------------- (i)(iii) decommission
def test_decommission_mints_and_vending_executes(world):
    seed(world.db, is_sandbox=True)
    vending = FakeVending(200, {"status": "DECOMMISSIONED", "deleted_project_id": PROJECT,
                                "deleted_project_number": NUMBER, "decommissioned_by": ADMIN,
                                "decommissioned_at": "2026-10-12T12:00:00+00:00", "crm_operation": "operations/d-1",
                                "message": "deleted", "warnings": []})
    res = _decommission(vending, approval_ref="client-chosen-id")
    [(method, path, body)] = vending.calls
    assert (method, path) == ("POST", f"/projects/{PID}/decommission")
    [(aid, appr)] = world.db.approvals().items()
    assert body == {"action_class": "PROJECT_DECOMMISSION", "approval_id": aid, "operator_email": ADMIN}
    assert aid != "client-chosen-id"  # a client-supplied id is never forwarded
    assert (appr["action"], appr["project_id"], appr["project_number"], appr["principal_type"]) == \
        ("PROJECT_DECOMMISSION", PROJECT, NUMBER, "USER")
    assert res.status == "DECOMMISSIONED" and res.deleted_project_id == PROJECT
    # the CC writes only its own bookkeeping; status/spend/archive/IPAM are vending's
    assert {k for w in world.db.ledger_writes() for k in w[2]} == {"sandbox_decommission_status"}
    assert "HITL_MANUAL_APPROVED_DECOMMISSION" in world.db.audits()
    world.cancel.assert_called_once()


@pytest.mark.parametrize("vending,code,status", [
    (refusal("LIEN_PRESENT", 409), "LIEN_PRESENT", 409),
    (refusal("NOT_STACKVEND_OWNED", 403), "NOT_STACKVEND_OWNED", 403),
    (refusal("GUARD_UNCONFIGURED", 503), "GUARD_UNCONFIGURED", 503),
    (refusal("DECOMMISSION_FAILED", 502), "DECOMMISSION_FAILED", 502),
    (FakeVending(None), "VENDING_UNCONFIGURED", 0),
    (FakeVending(500, {"detail": "boom"}), "VENDING_HTTP_500", 500),
])
def test_decommission_non_200_is_502_with_vending_code_and_no_fallback(world, vending, code, status):
    seed(world.db)
    res = _decommission(vending)
    assert res.status_code == 502
    body = _json(res)
    assert (body["code"], body["vending_status"]) == (code, status)
    assert body["detail"].startswith(f"{code}: ")
    assert world.db.ledger_writes() == [] and world.db.audits() == []
    world.cancel.assert_not_called()


def test_decommission_vending_exception_is_502_unreachable(world):
    seed(world.db)

    def boom(**kw):
        raise TimeoutError("read timeout")

    with patch.object(wl, "make_vending_request", boom):
        res = wl.decommission_workload_endpoint(PID, DecommissionRequest(confirm_product_id=PID), human())
    assert res.status_code == 502 and _json(res)["code"] == "VENDING_UNREACHABLE"
    assert world.db.ledger_writes() == []


def test_decommission_ledger_read_error_is_503_and_vending_not_called(world):
    seed(world.db)
    world.db.fail_reads.add(f"workloads/{PID}")
    vending = FakeVending(200, {})
    with pytest.raises(HTTPException) as ei:
        _decommission(vending)
    assert ei.value.status_code == 503 and vending.calls == [] and world.db.writes == []


def test_decommission_missing_workload_is_404(world):
    vending = FakeVending(200, {})
    with pytest.raises(HTTPException) as ei:
        _decommission(vending)
    assert ei.value.status_code == 404 and vending.calls == []


def test_decommission_confirmation_mismatch_mints_nothing(world):
    seed(world.db)
    vending = FakeVending(200, {})
    with pytest.raises(HTTPException) as ei:
        _decommission(vending, confirm="wrong")
    assert ei.value.status_code == 422 and vending.calls == [] and world.db.approvals() == {}


def test_decommission_by_non_human_principal_is_refused_before_vending(world, monkeypatch):
    seed(world.db)
    monkeypatch.setattr(authz.identity, "platform_callers", lambda: frozenset({PLATFORM_SA}))
    vending = FakeVending(200, {})
    res = _decommission(vending, request=human(method="bearer", email=PLATFORM_SA))
    body = _json(res)
    # same status and `detail` string as before; the typed `code` is added for the dashboard (backward-compatible)
    assert res.status_code == 403 and body["code"] == "APPROVAL_NOT_HUMAN"
    assert body["detail"] == f"APPROVAL_NOT_HUMAN: {body['reason']}" and body["reason"]
    assert vending.calls == [] and world.db.writes == []


def test_decommission_unprovenanced_refusal_502_body_is_typed_for_the_dashboard(world):
    """Live 10-29 (testplan02-c): vending refuses LEDGER_UNPROVENANCED; the CC answers 502 with a body the dashboard
    reads without parsing text: `code` (exact), `detail` (string, "CODE: detail"), `vending_detail`, `vending_status`."""
    seed(world.db)
    vending = refusal("LEDGER_UNPROVENANCED", 403, detail=f"workload_provenance/{PID} does not exist")
    res = _decommission(vending)
    assert res.status_code == 502
    body = _json(res)
    assert body == {"detail": f"LEDGER_UNPROVENANCED: workload_provenance/{PID} does not exist",
                    "code": "LEDGER_UNPROVENANCED",
                    "vending_detail": f"workload_provenance/{PID} does not exist",
                    "vending_status": 403}
    assert world.db.ledger_writes() == [] and world.db.audits() == []


@pytest.mark.parametrize("http_status,code", [(409, "APPROVAL_TARGET_UNKNOWN"), (503, "APPROVAL_STORE_UNAVAILABLE")])
def test_decommission_mint_refusal_keeps_status_and_carries_code(world, monkeypatch, http_status, code):
    seed(world.db)

    def refuse(*a, **k):
        raise da.MintRefused(http_status, code, "why")

    monkeypatch.setattr(da, "mint_approval", refuse)
    vending = FakeVending(200, {})
    res = _decommission(vending)
    assert res.status_code == http_status
    assert _json(res) == {"detail": f"{code}: why", "code": code, "reason": "why"}
    assert vending.calls == []


def test_unprovenanced_ledger_calls_vending_without_an_approval(world):
    """No project number in the ledger or provenance: nothing is minted; vending reports the exact refusal."""
    seed(world.db, project_number="")
    vending = refusal("LEDGER_UNPROVENANCED", 403)
    res = _decommission(vending)
    assert vending.calls[0][2]["approval_id"] is None and world.db.approvals() == {}
    assert res.status_code == 502 and _json(res)["code"] == "LEDGER_UNPROVENANCED"


def test_project_number_falls_back_to_vending_provenance(world):
    seed(world.db, project_number="")
    world.db.docs[f"workload_provenance/{PID}"] = {"project_id": PROJECT, "project_number": NUMBER}
    vending = FakeVending(200, {"status": "DECOMMISSIONED"})
    _decommission(vending)
    [(aid, appr)] = world.db.approvals().items()
    assert appr["project_number"] == NUMBER and vending.calls[0][2]["approval_id"] == aid


def test_no_in_process_project_delete_remains_in_the_control_center():
    """Source pin (RT (i)): the CC never calls the CRM delete / lien delete / DNS delete APIs any more."""
    src = open(os.path.join(CC_DIR, "routes", "workloads.py"), encoding="utf-8").read()
    for forbidden in ("projects().delete(", "liens().delete(", "resourceRecordSets().delete(", ".delete_project(",
                      "sandbox_guard.assert_sandbox_deletable", "sandbox_crm_factory"):
        assert forbidden not in src, forbidden


# ---------------------------------------------------------------------------------------------- (iv) lifecycle
def _sandbox(db, **fields):
    exp = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    rec = dict(is_sandbox=True, sandbox_auto_decommission=True, sandbox_designation_source="API_FIELD",
               sandbox_expires_at=exp, sandbox_ttl_days=30, cumulative_lifespan_days=30, extension_count=0)
    rec.update(fields)
    return seed(db, **rec)


def test_extend_refusal_is_502_and_ledger_unchanged(world):
    _sandbox(world.db)
    before = copy.deepcopy(world.db.docs)
    vending = refusal("EXTENSION_LIMIT", 409, "already extended 3 times")
    with patch.object(wl, "make_vending_request", vending):
        res = wl.extend_sandbox_endpoint(PID, human(), ExtendSandboxRequest(extend_days=10))
    assert res.status_code == 502 and _json(res)["code"] == "EXTENSION_LIMIT"
    assert world.db.docs == before
    assert vending.calls == [("POST", f"/projects/{PID}/lifecycle", {"action": "EXTEND", "ttl_days": 10})]


@pytest.mark.parametrize("vending", [refusal("CRM_UNAVAILABLE", 503), FakeVending(None),
                                     refusal("NOT_STACKVEND_OWNED", 403)])
def test_extend_never_falls_back_to_a_ledger_only_extension_when_vending_is_the_authority(world, vending):
    """RT effect 3: a ledger-only extension of a provenance-bearing sandbox would be ignored by the TTL authority."""
    _sandbox(world.db)
    before = copy.deepcopy(world.db.docs)
    with patch.object(wl, "make_vending_request", vending):
        res = wl.extend_sandbox_endpoint(PID, human(), ExtendSandboxRequest(extend_days=10))
    assert res.status_code == 502 and world.db.docs == before


@pytest.mark.parametrize("code", ["LEDGER_UNPROVENANCED", "SANDBOX_NOT_ELIGIBLE"])
def test_extend_of_a_never_ttl_deleted_workload_updates_the_display_only(world, code):
    """Vending never TTL-deletes these (no vend-time record / not an auto-decommission sandbox), so the CC countdown
    is display-only and the operator's button keeps working (no feature loss)."""
    _sandbox(world.db)
    with patch.object(wl, "make_vending_request", refusal(code, 403 if code == "LEDGER_UNPROVENANCED" else 409)):
        res = wl.extend_sandbox_endpoint(PID, human(), ExtendSandboxRequest(extend_days=10))
    assert res.extension_count == 1 and "Display only" in res.message and code in res.message
    audit = [d for p, d in world.db.docs.items() if p.startswith(f"workloads/{PID}/audit_logs/")][0]
    assert audit["ttl_authority"] == "LEDGER_DISPLAY_ONLY" and audit["vending_code"] == code


def test_promote_goes_through_vending_and_refusal_keeps_the_ledger(world):
    _sandbox(world.db)
    before = copy.deepcopy(world.db.docs)
    vending = refusal("CRM_UNAVAILABLE", 503)
    with patch.object(wl, "make_vending_request", vending):
        res = wl.promote_sandbox_endpoint(PID, human())
    assert res.status_code == 502 and world.db.docs == before
    assert vending.calls == [("POST", f"/projects/{PID}/lifecycle", {"action": "PROMOTE"})]
    with patch.object(wl, "make_vending_request", FakeVending(200, {"status": "OK", "warnings": []})):
        res = wl.promote_sandbox_endpoint(PID, human())
    assert res.is_sandbox is False
    assert world.db.docs[f"workloads/{PID}"]["sandbox_decommission_status"] == "PROMOTED"


def test_confirm_sandbox_mints_confirm_approval_and_calls_lifecycle(world):
    _sandbox(world.db, sandbox_designation_source="KEYWORD_DETECTED", sandbox_auto_decommission=True)
    exp = "2026-11-11T12:00:00+00:00"
    vending = FakeVending(200, {"status": "OK", "action": "CONFIRM_SANDBOX", "sandbox_expires_at": exp})
    with patch.object(wl, "make_vending_request", vending):
        res = wl.confirm_sandbox_endpoint(PID, human(), ConfirmSandboxRequest(ttl_days=14))
    [(aid, appr)] = world.db.approvals().items()
    assert appr["action"] == "CONFIRM_SANDBOX" and appr["principal_type"] == "USER"
    assert vending.calls == [("POST", f"/projects/{PID}/lifecycle",
                              {"action": "CONFIRM_SANDBOX", "ttl_days": 14, "approval_id": aid})]
    led = world.db.docs[f"workloads/{PID}"]
    assert (led["sandbox_designation_source"], led["sandbox_expires_at"]) == ("OPERATOR_CONFIRMED", exp)
    assert res.sandbox_expires_at == exp


def test_confirm_sandbox_refusal_keeps_the_ledger(world):
    _sandbox(world.db, sandbox_designation_source="KEYWORD_DETECTED")
    before = {k: v for k, v in world.db.docs.items() if k.startswith("workloads/")}
    with patch.object(wl, "make_vending_request", refusal("APPROVAL_EXPIRED", 403)):
        res = wl.confirm_sandbox_endpoint(PID, human(), ConfirmSandboxRequest(ttl_days=14))
    assert res.status_code == 502 and _json(res)["code"] == "APPROVAL_EXPIRED"
    assert {k: v for k, v in world.db.docs.items() if k.startswith("workloads/")} == before


def test_confirm_sandbox_mint_refusal_keeps_status_and_carries_code(world, monkeypatch):
    _sandbox(world.db, sandbox_designation_source="KEYWORD_DETECTED")
    vending = FakeVending(200, {})
    with patch.object(wl, "make_vending_request", vending):
        res = wl.confirm_sandbox_endpoint(PID, human(method="bearer", email=PLATFORM_SA), ConfirmSandboxRequest(ttl_days=14))
    body = _json(res)
    assert res.status_code == 403 and body["code"] == "APPROVAL_NOT_HUMAN"
    assert body["detail"] == f"APPROVAL_NOT_HUMAN: {body['reason']}"
    assert vending.calls == [] and world.db.approvals() == {}


def test_confirm_sandbox_already_explicit_is_409(world):
    _sandbox(world.db)
    vending = FakeVending(200, {})
    with pytest.raises(HTTPException) as ei, patch.object(wl, "make_vending_request", vending):
        wl.confirm_sandbox_endpoint(PID, human(), ConfirmSandboxRequest(ttl_days=14))
    assert ei.value.status_code == 409 and vending.calls == [] and world.db.approvals() == {}


# ---------------------------------------------------------------------------------------------- (v) vend fields
@pytest.mark.parametrize("args,expected", [
    (dict(is_sandbox=False, auto_decommission=True, designation_source="API_FIELD", ttl_days=30),
     dict(is_sandbox=False, sandbox_auto_decommission=False, sandbox_designation_source=None, sandbox_ttl_days=None)),
    (dict(is_sandbox=True, auto_decommission=True, designation_source="API_FIELD", ttl_days=7),
     dict(is_sandbox=True, sandbox_auto_decommission=True, sandbox_designation_source="API_FIELD", sandbox_ttl_days=7)),
    (dict(is_sandbox=True, auto_decommission=True, designation_source="KEYWORD_DETECTED", ttl_days=30),
     dict(is_sandbox=True, sandbox_auto_decommission=True, sandbox_designation_source="KEYWORD", sandbox_ttl_days=30)),
    (dict(is_sandbox=True, auto_decommission="true", designation_source="SOMETHING", ttl_days=120),
     dict(is_sandbox=True, sandbox_auto_decommission=False, sandbox_designation_source=None, sandbox_ttl_days=None)),
    (dict(is_sandbox="true", auto_decommission=True, designation_source="API_FIELD", ttl_days=True),
     dict(is_sandbox=False, sandbox_auto_decommission=False, sandbox_designation_source=None, sandbox_ttl_days=None)),
])
def test_vend_sandbox_fields_mapping(args, expected):
    assert da.vend_sandbox_fields(**args) == expected


def test_express_vend_sends_the_explicit_sandbox_fields(world, monkeypatch):
    vending = FakeVending(200, {"project_id": "p-1", "github_repo": "o/r"})
    monkeypatch.setattr(wl, "ExpressHCLSynthesizer", None)
    monkeypatch.setattr(wl, "VCSProviderFactory", None)
    with patch.object(wl, "make_vending_request", vending), \
            patch.object(wl, "make_terraform_request", return_value=None):
        wl.execute_express_provisioning(
            product_id=PID, target_project_id=PROJECT, clean_vcs_provider="GITHUB", full_github_repo="o/r",
            target_branch="main", target_folder="folders/1", budget=50.0, clean_engine="OPENTOFU", is_sandbox=True,
            admin_email=ADMIN, module_instances=[], include_vpc=False, trace_id="tr-1",
            sandbox_auto_decommission=True, sandbox_designation_source="API_FIELD", sandbox_ttl_days=14,
            region="us-central1")   # FD-7M-a: as create passes it
    [(_, path, body)] = vending.calls
    assert path == "/vend-all"
    assert {k: body[k] for k in ("is_sandbox", "sandbox_auto_decommission", "sandbox_designation_source",
                                 "sandbox_ttl_days")} == {
        "is_sandbox": True, "sandbox_auto_decommission": True, "sandbox_designation_source": "API_FIELD",
        "sandbox_ttl_days": 14}


@pytest.mark.parametrize("is_sandbox,spec,expected", [
    (True, "Normal service", {"is_sandbox": True, "sandbox_auto_decommission": True,
                              "sandbox_designation_source": "API_FIELD"}),
    (None, "A temporary test sandbox environment for billing.", {"is_sandbox": True, "sandbox_auto_decommission": True,
                                                                "sandbox_designation_source": "KEYWORD"}),
    (False, "Core banking ledger", {"is_sandbox": False, "sandbox_auto_decommission": False,
                                    "sandbox_designation_source": None}),
])
def test_agent_intake_carries_the_designation_for_the_workflow_vend(world, monkeypatch, is_sandbox, spec, expected):
    published = []

    class _Pub:
        def publish(self, topic, data):
            published.append(json.loads(data))
            return SimpleNamespace(result=lambda timeout=None: "msg-1")

    monkeypatch.setenv("GITHUB_OWNER", "example-org")
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", "111111111111")
    monkeypatch.setattr(wl, "get_pubsub_publisher", lambda: _Pub())
    monkeypatch.setattr(wl, "project_id", "mock-stackvend-project")

    # lane18-window-v4: FD-4AK made create_workload read settings strictly (unreadable -> 503, never defaults), so
    # this test serves the compile-time defaults explicitly instead of making the read fail.
    settings_cls = sys.modules[wl.get_platform_settings.__module__].PlatformSettings

    def _default_settings(*_args, **_kwargs):
        return settings_cls()

    monkeypatch.setattr(wl, "get_platform_settings", _default_settings)
    req = CreateWorkloadRequest(product_id="billing-svc", title="Billing", spec_content=spec, is_sandbox=is_sandbox,
                                sandbox_ttl_days=30)
    wl.create_workload(req, human())
    [payload] = published
    assert {k: payload[k] for k in expected} == expected


WORKFLOW = os.path.join(BASE_DIR, "workflows", "main_orchestrator.yaml")


def _vend_step_body():
    import yaml
    doc = yaml.safe_load(open(WORKFLOW, encoding="utf-8"))
    # Lane 17 moved the pipeline into the `run_pipeline` subworkflow (`main` calls it with `args`): look in the top-level
    # steps of every subworkflow, and require exactly one vend step.
    found = [step["dispatch_vending_task"] for sub in doc.values() if isinstance(sub, dict)
             for step in sub.get("steps", []) if isinstance(step, dict) and "dispatch_vending_task" in step]
    if len(found) != 1:
        raise AssertionError(f"expected exactly one dispatch_vending_task, found {len(found)}")
    return found[0]["try"]["args"]["body"]


def _vending_sandbox_fields():
    """Field names of SandboxVendFields in apps/project-vending/main.py (parsed, not imported)."""
    tree = ast.parse(open(os.path.join(BASE_DIR, "apps", "project-vending", "main.py"), encoding="utf-8").read())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "SandboxVendFields")
    return {n.target.id for n in cls.body if isinstance(n, ast.AnnAssign)}


def test_workflow_vend_call_forwards_the_explicit_sandbox_fields():
    body = _vend_step_body()
    assert body["is_sandbox"] == '${default(map.get(args, "is_sandbox"), false)}'
    assert body["sandbox_auto_decommission"] == '${default(map.get(args, "sandbox_auto_decommission"), false)}'
    assert body["sandbox_designation_source"] == '${default(map.get(args, "sandbox_designation_source"), null)}'
    assert body["sandbox_ttl_days"] == '${default(map.get(args, "sandbox_ttl_days"), null)}'
    assert _vending_sandbox_fields() == {"is_sandbox", "sandbox_auto_decommission", "sandbox_designation_source",
                                         "sandbox_ttl_days"} <= set(body)
    # the rest of the vend call is unchanged, except FD-4CI-b: no hardcoded initial_budget (vending keeps the
    # workload's own budget, or gives a new record the platform default)
    assert {k: body[k] for k in ("product_id", "trace_id", "callback_url")} == {
        "product_id": "${product_id}", "trace_id": "${trace_id}", "callback_url": "${vending_callback.url}"}
    assert "initial_budget" not in body


# ---------------------------------------------------------------------------------------------- (vi) budget breach
def _budget_approval(db, appr_id="appr-bb-1"):
    db.docs[f"approval_requests/{appr_id}"] = {"approval_id": appr_id, "approval_type": "BUDGET_BREACH",
                                               "product_id": PID, "status": "PENDING"}
    return appr_id


def _decide(appr_id, request, vending):
    with patch.object(appr_routes, "make_vending_request", vending), \
            patch.object(appr_routes, "verify_workload_access", return_value=True):
        return appr_routes.decide_approval_request(
            appr_id, ApprovalDecisionRequest(decision=ApprovalStatus.APPROVED, action="DECOMMISSION"), request)


def test_budget_breach_decommission_goes_through_vending(world):
    seed(world.db, status="QUARANTINED")
    appr_id = _budget_approval(world.db)
    vending = FakeVending(200, {"status": "DECOMMISSIONED", "crm_operation": "operations/d-9"})
    res = _decide(appr_id, human(), vending)
    assert res.status == ApprovalStatus.APPROVED
    [(aid, appr)] = world.db.approvals().items()
    assert vending.calls[0][1:] == (f"/projects/{PID}/decommission",
                                    {"action_class": "PROJECT_DECOMMISSION", "approval_id": aid,
                                     "operator_email": ADMIN})
    assert world.db.docs[f"workloads/{PID}"]["status"] == "QUARANTINED"  # vending writes the ledger status
    assert world.db.docs[f"approval_requests/{appr_id}"]["decommission_crm_operation"] == "operations/d-9"


def test_budget_breach_decommission_failure_is_execution_failed_and_redecidable(world):
    seed(world.db, status="QUARANTINED")
    appr_id = _budget_approval(world.db)
    with pytest.raises(HTTPException) as ei:
        _decide(appr_id, human(), refusal("LIEN_PRESENT", 409))
    assert ei.value.status_code == 502 and "EXECUTION_FAILED" in ei.value.detail and "LIEN_PRESENT" in ei.value.detail
    assert world.db.docs[f"workloads/{PID}"]["status"] == "QUARANTINED"
    rec = world.db.docs[f"approval_requests/{appr_id}"]
    assert rec["status"] == "EXECUTION_FAILED"
    # re-decidable once the cause is fixed
    res = _decide(appr_id, human(), FakeVending(200, {"status": "DECOMMISSIONED"}))
    assert res.status == ApprovalStatus.APPROVED


def test_budget_breach_decommission_by_manager_is_403_and_nothing_happens(world):
    seed(world.db, status="QUARANTINED")
    appr_id = _budget_approval(world.db)
    vending = FakeVending(200, {})
    with pytest.raises(HTTPException) as ei:
        _decide(appr_id, human(role=UserRole.WORKLOAD_MANAGER), vending)
    assert ei.value.status_code == 403 and vending.calls == [] and world.db.approvals() == {}
    assert world.db.docs[f"approval_requests/{appr_id}"]["status"] == "PENDING"
