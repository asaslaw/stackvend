"""Lane 19 L19-11 (minimal access intake, Fable FD-4I RT §10): private builds work after FD-4I.

FD-4I makes every private (IAP / IAM / domain-restricted) build stop with ACCESS_POLICY_INCOMPLETE unless
`workloads/{pid}.access` exists. This file pins the intake that writes that record:

* `CreateWorkloadRequest.access` (mode + exact principals + the A8 answer), validated by shared.access_policy: invalid
  answers are 422 at the door, nothing is prefixed, trimmed, widened or guessed (no server-side submitter fill);
* the create route stores `workload_record["access"]` and the Pub/Sub intake event carries the same record;
* the gateway intake accepts an `access` record only from the CC form and only when it validates;
* `PATCH /api/workloads/{pid}/access`: administrator only, audited (record + audit entry in one batch), 422 on
  invalid bodies, no write on any refusal;
* the developer resolves the stored record to the exact members, and with no record the typed stop still applies;
* the create form defaults to Private (IAP) with the signed-in submitter pre-filled and the A8 question unanswered.

Hermetic: FastAPI TestClient on the real workloads router, a test-only middleware that sets the identity the CC's
AuthorizationMiddleware would set (the real `require(ADMIN)` dependency and `verify_admin_access` run), an in-memory
Firestore fake, a fake Pub/Sub publisher. No network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy
import hashlib
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO, "apps", "control-center")
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")
for _p in (GW_DIR,):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from developer_agent.access_resolution import PRIVATE_IAP, SOURCE_WORKLOAD_RECORD, resolve_access  # noqa: E402
from developer_agent.errors import ACCESS_COMPLIANCE_CONFLICT, ACCESS_POLICY_INCOMPLETE, DeveloperStageError  # noqa: E402
from shared.access_policy import AccessPolicy  # noqa: E402

SUBMITTER = "ana@example.com"
INVALID_PRINCIPALS = [
    "allUsers",
    "allAuthenticatedUsers",
    "domain:allAuthenticatedUsers",
    "ana@example.com",                 # unprefixed: never auto-prefixed
    "example.com",                     # unprefixed domain
    "C0abc123",                        # org customer id (never a member)
    "domain:C0abc123",
    "projectOwner:my-project",
    "principalSet://iam.googleapis.com/locations/global/workforcePools/p/*",
    " user:ana@example.com",           # never trimmed server-side
    "user:ana@example.com ",
    "user:",
    "User:ana@example.com",            # kinds are exact
    "user:ana@@example.com",
    "domain:*.example.com",
]


# ============================================================================ fakes
class _Snap:
    def __init__(self, data, version=0):
        self._data = copy.deepcopy(data)
        self.exists = data is not None
        self.update_time = version  # version token at read time (L19-F4 RT R4 precondition writes)

    def to_dict(self):
        return copy.deepcopy(self._data)


class _Doc:
    def __init__(self, store, path):
        self.store, self.path = store, path
        self.id = path.rsplit("/", 1)[-1]

    def get(self):
        return _Snap(self.store.get(self.path), self.store.versions.get(self.path, 0))

    def set(self, data, merge=False):
        self.store.writes.append(("set", self.path))
        base = dict(self.store.get(self.path) or {}) if merge else {}
        base.update(copy.deepcopy(data))
        self.store[self.path] = base
        self.store.versions[self.path] = self.store.versions.get(self.path, 0) + 1

    def create(self, data):
        """Firestore create(): AlreadyExists when the document exists (OSS-D23 RT F5 create-semantics writes)."""
        if self.path in self.store:
            from google.api_core import exceptions as gexc

            raise gexc.AlreadyExists(f"{self.path} already exists")
        self.set(data)

    def update(self, data, option=None):
        """Firestore update(): KeyError when absent; FailedPrecondition when `option` (FakeDB.write_option) no longer
        matches the stored version."""
        if self.path not in self.store:
            raise KeyError(f"no document {self.path}")
        if option is not None and option.get("last_update_time") != self.store.versions.get(self.path, 0):
            from google.api_core import exceptions as gexc

            raise gexc.FailedPrecondition(f"{self.path} changed since it was read")
        self.store.writes.append(("update", self.path))
        self.store[self.path].update(copy.deepcopy(data))
        self.store.versions[self.path] = self.store.versions.get(self.path, 0) + 1

    def collection(self, name):
        return _Col(self.store, f"{self.path}/{name}")


class _Col:
    def __init__(self, store, path):
        self.store, self.path = store, path

    def document(self, doc_id=None):
        if doc_id is None:
            self.store.auto += 1
            doc_id = f"auto{self.store.auto}"
        return _Doc(self.store, f"{self.path}/{doc_id}")


class _Batch:
    def __init__(self, store):
        self.store, self.ops = store, []

    def update(self, ref, data, option=None):
        self.ops.append(("update", ref, data, option))

    def set(self, ref, data):
        self.ops.append(("set", ref, data, None))

    def commit(self):
        """All or nothing: every precondition is checked before any write (as a Firestore batch commit)."""
        if self.store.fail_commit:
            raise RuntimeError("commit failed")
        from google.api_core import exceptions as gexc

        for op, ref, data, option in self.ops:
            if option is not None and (ref.path not in self.store or option.get("last_update_time")
                                       != self.store.versions.get(ref.path, 0)):
                raise gexc.FailedPrecondition(f"{ref.path} changed since it was read")
        for op, ref, data, option in self.ops:
            getattr(ref, op)(data)
        self.store.commits += 1


class FakeDB(dict):
    def __init__(self, initial=None, fail_commit=False):
        super().__init__(copy.deepcopy(initial or {}))
        self.writes, self.auto, self.commits, self.fail_commit = [], 0, 0, fail_commit
        self.versions = {}

    def __bool__(self):  # a client, not a container: the routes test `if db:`
        return True

    @staticmethod
    def write_option(**kw):
        return dict(kw)

    def collection(self, name):
        return _Col(self, name)

    def batch(self):
        return _Batch(self)


# ============================================================================ CC loading
@pytest.fixture
def cc(monkeypatch):
    """The real CC schemas + workloads router (same import pattern as test_compliance_profile_explicit)."""
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    import schemas
    from routes import workloads as wl_routes

    monkeypatch.setattr(cc_db, "_db_client", False)
    monkeypatch.setattr(wl_routes, "project_id", "mock-stackvend-project", raising=False)
    return schemas, wl_routes


def _client(wl_routes, monkeypatch, fake_db):
    monkeypatch.setattr(wl_routes, "db", fake_db)
    app = FastAPI()

    @app.middleware("http")
    async def _identity(request: Request, call_next):  # what AuthorizationMiddleware sets for a signed-in human
        email = request.headers.get("x-test-email")
        if email:
            request.state.user_email = email
            request.state.user_role = request.headers.get("x-test-role", "VIEWER")
            request.state.auth_method = request.headers.get("x-test-auth-method", "session")
            request.state.assigned_workloads = ["shop-app"]
        return await call_next(request)

    app.include_router(wl_routes.router)
    return TestClient(app, raise_server_exceptions=False)


ADMIN_H = {"x-test-email": "admin@example.com", "x-test-role": "ADMIN"}
MANAGER_H = {"x-test-email": "mgr@example.com", "x-test-role": "WORKLOAD_MANAGER"}
VIEWER_H = {"x-test-email": "viewer@example.com", "x-test-role": "VIEWER"}


def _create(wl_routes, monkeypatch, body, headers=ADMIN_H, initial=None):
    fake_db = FakeDB(initial)
    client = _client(wl_routes, monkeypatch, fake_db)
    publisher = MagicMock()
    publisher.publish.return_value.result.return_value = "msg-1"
    with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
         patch.object(wl_routes, "get_pubsub_publisher", return_value=publisher), \
         patch.object(wl_routes, "get_platform_settings",  # FD-4AK: an unreadable settings doc now refuses (503)
                      return_value=__import__("routes.settings", fromlist=["x"]).PlatformSettings()):
        r = client.post("/api/workloads", json={"product_id": "shop-app", "spec_content": "a shop", **body},
                        headers=headers)
    payload = (json.loads(publisher.publish.call_args[0][1].decode("utf-8"))
               if publisher.publish.call_args else None)
    return r, fake_db, payload


IAP_INTAKE = {"mode": "PRIVATE_IAP", "invoker_principals": [f"user:{SUBMITTER}", "group:staff@example.com"]}


# ============================================================================ 1. schema: typed answers only
def test_replica_is_byte_identical_to_root():
    root = open(os.path.join(REPO, "shared", "access_policy.py"), "rb").read()
    cc_copy = open(os.path.join(CC_DIR, "shared", "access_policy.py"), "rb").read()
    assert hashlib.sha256(root).hexdigest() == hashlib.sha256(cc_copy).hexdigest()


@pytest.mark.parametrize("principal", INVALID_PRINCIPALS)
def test_invalid_principal_is_422_on_create_and_nothing_is_written(cc, monkeypatch, principal):
    _, wl = cc
    r, fake_db, payload = _create(wl, monkeypatch, {"access": {"mode": "PRIVATE_IAP",
                                                               "invoker_principals": [principal]}})
    assert r.status_code == 422, r.text
    assert dict(fake_db) == {} and fake_db.writes == [] and payload is None


@pytest.mark.parametrize("access, needle", [
    ({"mode": "PRIVATE_IAP", "invoker_principals": []}, ACCESS_POLICY_INCOMPLETE),
    ({"mode": "PRIVATE_IAM"}, ACCESS_POLICY_INCOMPLETE),
    ({"mode": "PUBLIC_APP"}, "tenant_isolation_required"),                      # A8: no default
    ({"mode": "PUBLIC_APP", "tenant_isolation_required": None}, "tenant_isolation_required"),
    ({"mode": "PUBLIC_APP", "tenant_isolation_required": "yes"}, "bool"),       # strict: no coercion
    ({"mode": "PUBLIC_APP", "tenant_isolation_required": 1}, "bool"),
    ({"mode": "PUBLIC_APP", "tenant_isolation_required": False,
      "invoker_principals": ["user:ana@example.com"]}, "PUBLIC_APP takes no invoker_principals"),
    ({"mode": "private_iap", "invoker_principals": ["user:ana@example.com"]}, "mode"),  # exact enum
    ({"mode": "PRIVATE_IAP", "invoker_principals": ["user:ana@example.com", "user:ANA@example.com"]}, "duplicates"),
    ({"mode": "PRIVATE_IAP", "invoker_principals": ["user:ana@example.com"], "sign_in": {"google": "BYO"}}, "extra"),
    ({"mode": "PRIVATE_IAP", "invoker_principals": "user:ana@example.com"}, "list"),
    # RT F7: the A8 answer is for PUBLIC_APP only; a private record never stores one.
    ({"mode": "PRIVATE_IAP", "invoker_principals": ["user:ana@example.com"], "tenant_isolation_required": False},
     "takes no tenant_isolation_required"),
    ({"mode": "PRIVATE_IAM", "invoker_principals": ["user:ana@example.com"], "tenant_isolation_required": True},
     "takes no tenant_isolation_required"),
])
def test_incomplete_or_malformed_access_is_422(cc, monkeypatch, access, needle):
    _, wl = cc
    r, fake_db, payload = _create(wl, monkeypatch, {"access": access})
    assert r.status_code == 422, r.text
    assert needle.lower() in r.text.lower()
    assert fake_db.writes == [] and payload is None


def test_composition_is_exact_and_nothing_is_added(cc):
    schemas, _ = cc
    iap = schemas.AccessIntake(**IAP_INTAKE).to_policy("intake")
    assert iap.invoker_members() == [f"user:{SUBMITTER}", "group:staff@example.com"]
    assert iap.sign_in.google.value == "DISABLED" and iap.source == "intake" and iap.app_admin_emails == []
    # The server never adds the submitter (or anyone): a group-only answer stays group-only.
    only_group = schemas.AccessIntake(mode="PRIVATE_IAM", invoker_principals=["group:staff@example.com"])
    assert only_group.to_policy("intake").invoker_members() == ["group:staff@example.com"]
    pub_iso = schemas.AccessIntake(mode="PUBLIC_APP", tenant_isolation_required=True).to_policy("intake")
    pub_shared = schemas.AccessIntake(mode="PUBLIC_APP", tenant_isolation_required=False).to_policy("intake")
    assert (pub_iso.sign_in.google.value, pub_shared.sign_in.google.value) == ("BYO", "SHARED_PLATFORM_CLIENT")
    assert pub_iso.invoker_members() == [] and pub_iso.tenant_isolation_required is True
    # Canonical form only: the address is lower-cased by the model (IAM stores it so); the kind is never changed.
    assert schemas.AccessIntake(mode="PRIVATE_IAP", invoker_principals=["user:Ana@Example.com"]).to_policy(
        "intake").invoker_members() == ["user:ana@example.com"]


def test_access_is_optional_on_create(cc):
    schemas, _ = cc
    assert schemas.CreateWorkloadRequest(product_id="p").access is None


# ============================================================================ 2. create stores the record
def test_create_stores_the_record_and_the_intake_event_carries_no_copy(cc, monkeypatch):
    _, wl = cc
    r, fake_db, payload = _create(wl, monkeypatch, {"access": IAP_INTAKE})
    assert r.status_code == 200, r.text
    stored = fake_db["workloads/shop-app"]["access"]
    assert stored == {
        "mode": "PRIVATE_IAP",
        "invoker_principals": [f"user:{SUBMITTER}", "group:staff@example.com"],
        "app_admin_emails": [],
        "public_api_routes": ["GET /api/config"],
        "sign_in": {"google": "DISABLED", "email_password": False, "additional_authorized_domains": []},
        "tenant_isolation_required": None,
        "source": "intake",
    }
    # RT F9: the event is not a second (spoofable) source of truth; the developer reads only the stored record.
    assert "access" not in payload and payload["source_channel"] == "control_center_form"
    # The stored record is exactly what the developer validates again (round trip through the one model).
    assert AccessPolicy.model_validate(stored).invoker_members() == stored["invoker_principals"]


def test_create_without_access_stores_the_private_platform_default_and_sends_none(cc, monkeypatch):
    """OSS-D23 (owner 10-19/10-20): a NEW workload with no access answer gets the platform default record (PRIVATE_IAP,
    listing the verified signed-in submitter), never public by omission; the event still carries no copy (RT F9)."""
    _, wl = cc
    r, fake_db, payload = _create(wl, monkeypatch, {})
    assert r.status_code == 200, r.text
    stored = fake_db["workloads/shop-app"]["access"]
    assert stored["mode"] == "PRIVATE_IAP" and stored["invoker_principals"] == ["user:admin@example.com"]
    assert stored["source"] == "platform_default" and "access" not in payload


def test_create_public_records_the_a8_answer(cc, monkeypatch):
    _, wl = cc
    r, fake_db, payload = _create(wl, monkeypatch, {"access": {"mode": "PUBLIC_APP",
                                                               "tenant_isolation_required": False}})
    assert r.status_code == 200, r.text
    stored = fake_db["workloads/shop-app"]["access"]
    assert stored["mode"] == "PUBLIC_APP" and stored["tenant_isolation_required"] is False
    assert stored["invoker_principals"] == [] and stored["sign_in"]["google"] == "SHARED_PLATFORM_CLIENT"


OLD_PUBLIC = {"mode": "PUBLIC_APP", "invoker_principals": [], "app_admin_emails": [],
              "public_api_routes": ["GET /api/config"],
              "sign_in": {"google": "SHARED_PLATFORM_CLIENT", "email_password": False, "additional_authorized_domains": []},
              "tenant_isolation_required": False, "source": "intake"}


def test_recreate_with_a_different_record_is_409_and_writes_nothing(cc, monkeypatch):
    """RT F2: a second POST never changes an existing record silently; the audited admin PATCH does that."""
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app", "access": OLD_PUBLIC}}
    r, fake_db, payload = _create(wl, monkeypatch, {"access": IAP_INTAKE}, initial=initial)
    assert r.status_code == 409, r.text
    assert "PATCH /api/workloads/shop-app/access" in r.json()["detail"]
    assert fake_db.writes == [] and payload is None and dict(fake_db) == initial


def test_recreate_with_the_identical_record_is_unchanged(cc, monkeypatch):
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app", "access": OLD_PUBLIC}}
    r, fake_db, _ = _create(wl, monkeypatch, {"access": {"mode": "PUBLIC_APP", "tenant_isolation_required": False}},
                            initial=initial)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["access"] == OLD_PUBLIC


def test_recreate_without_access_keeps_the_record(cc, monkeypatch):
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app", "access": OLD_PUBLIC}}
    r, fake_db, _ = _create(wl, monkeypatch, {}, initial=initial)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["access"] == OLD_PUBLIC


def test_express_with_access_stores_the_record(cc, monkeypatch):
    """RT F3 resolved by FD-4CS: the Express synthesizer applies the access record, so Express stores it like Agent
    mode (tests/test_fd4cs_express_private_default.py covers the rendering)."""
    _, wl = cc
    monkeypatch.setattr(wl, "execute_express_provisioning", lambda **k: None)
    r, fake_db, payload = _create(wl, monkeypatch, {"creation_mode": "EXPRESS", "access": IAP_INTAKE})
    assert r.status_code == 200, r.text
    stored = fake_db["workloads/shop-app"]["access"]
    assert stored["mode"] == "PRIVATE_IAP" and stored["source"] == "intake"
    assert stored["invoker_principals"] == IAP_INTAKE["invoker_principals"]
    assert payload is None   # Express never publishes an intake event


def test_create_stays_admin_only(cc, monkeypatch):
    _, wl = cc
    for headers, code in ((MANAGER_H, 403), (VIEWER_H, 403), ({}, 401)):
        r, fake_db, payload = _create(wl, monkeypatch, {"access": IAP_INTAKE}, headers=headers)
        assert r.status_code == code, r.text
        assert fake_db.writes == [] and payload is None


# ============================================================================ 3. developer: record used, else typed stop
def test_the_stored_record_resolves_to_exactly_its_members(cc, monkeypatch):
    _, wl = cc
    _, fake_db, _ = _create(wl, monkeypatch, {"access": IAP_INTAKE})
    resolved = resolve_access(workload_access=fake_db["workloads/shop-app"]["access"],
                              allow_unauthenticated=True, enable_direct_iap=False)  # stricter record wins
    assert resolved.mode == PRIVATE_IAP and resolved.source == SOURCE_WORKLOAD_RECORD
    assert resolved.invoker_members == (f"user:{SUBMITTER}", "group:staff@example.com")
    assert resolved.allow_unauthenticated is False and resolved.enable_direct_iap is True


def test_without_a_record_a_private_build_still_stops_typed(cc, monkeypatch):
    """Omitting `access` is allowed at the CC. OSS-D23 (owner 10-20): a new workload's default record lists exactly
    the verified signed-in submitter (nobody else is added); a workload with no record at all still stops typed."""
    _, wl = cc
    _, fake_db, _ = _create(wl, monkeypatch, {})
    for flags in ({"enable_direct_iap": True}, {"allow_unauthenticated": False}):
        resolved = resolve_access(workload_access=fake_db["workloads/shop-app"].get("access"), **flags)
        assert resolved.invoker_members == ("user:admin@example.com",)
        with pytest.raises(DeveloperStageError) as ei:
            resolve_access(workload_access=None, **flags)
        assert ei.value.error_class == ACCESS_POLICY_INCOMPLETE


def test_a_public_form_answer_never_overrides_a_private_compliance_decision(cc, monkeypatch):
    """RT F5: choosing Public on the form under an IAP / private-ingress compliance decision is a typed stop."""
    _, wl = cc
    _, fake_db, _ = _create(wl, monkeypatch, {"access": {"mode": "PUBLIC_APP", "tenant_isolation_required": False}})
    stored = fake_db["workloads/shop-app"]["access"]
    for flags in ({"enable_direct_iap": True}, {"allow_unauthenticated": False}):
        with pytest.raises(DeveloperStageError) as ei:
            resolve_access(workload_access=stored, **flags)
        assert ei.value.error_class == ACCESS_COMPLIANCE_CONFLICT
    # Negative: a public decision keeps the public record exactly.
    assert resolve_access(workload_access=stored, allow_unauthenticated=True, enable_direct_iap=False).mode == "PUBLIC_APP"


# ============================================================================ 4. PATCH /api/workloads/{pid}/access
WL = {"workloads/shop-app": {"product_id": "shop-app", "status": "FAILED"}}


def _patch(wl, monkeypatch, body, headers=ADMIN_H, initial=WL, **db_kw):
    fake_db = FakeDB(initial, **db_kw)
    client = _client(wl, monkeypatch, fake_db)
    r = client.patch("/api/workloads/shop-app/access", json=body, headers=headers)
    return r, fake_db


def test_patch_sets_the_record_and_audits_it_in_one_batch(cc, monkeypatch):
    _, wl = cc
    # L19-F4: the first record is a widening (nothing was granted), so it needs confirm_widening.
    r, fake_db = _patch(wl, monkeypatch, {**IAP_INTAKE, "reason": "answering ACCESS_POLICY_INCOMPLETE",
                                          "confirm_widening": True})
    assert r.status_code == 200, r.text
    doc = fake_db["workloads/shop-app"]
    assert doc["access"]["mode"] == "PRIVATE_IAP" and doc["access"]["source"] == "operator_hitl"
    assert doc["access"]["invoker_principals"] == IAP_INTAKE["invoker_principals"]
    assert doc["access_updated_by"] == "admin@example.com" and doc["status"] == "FAILED"
    (audit_path,) = [k for k in fake_db if k.startswith("workloads/shop-app/audit_logs/")]
    audit = fake_db[audit_path]
    assert audit["action"] == "WORKLOAD_ACCESS_SET" and audit["operator_email"] == "admin@example.com"
    assert audit["previous_access"] is None and audit["new_access"] == doc["access"]
    assert audit["reason"] == "answering ACCESS_POLICY_INCOMPLETE" and audit["source"] == "operator_hitl"
    assert audit["widening"] is True and audit["widening_changes"] == ["NO_PREVIOUS_RECORD"]
    assert fake_db.commits == 1 and r.json()["access"] == doc["access"]


def test_patch_replaces_the_record_whole_and_audits_the_previous_one(cc, monkeypatch):
    _, wl = cc
    old = {"mode": "PRIVATE_IAP", "invoker_principals": ["user:old@example.com", "group:wide@example.com"],
           "app_admin_emails": ["old@example.com"], "public_api_routes": ["GET /api/config"],
           "sign_in": {"google": "DISABLED", "email_password": False, "additional_authorized_domains": []},
           "tenant_isolation_required": None, "source": "intake"}
    initial = {"workloads/shop-app": {"product_id": "shop-app", "access": old}}
    r, fake_db = _patch(wl, monkeypatch, {"mode": "PRIVATE_IAM",
                                          "invoker_principals": ["serviceAccount:c@p.iam.gserviceaccount.com"],
                                          "source": "migration", "confirm_widening": True}, initial=initial)
    assert r.status_code == 200, r.text
    new = fake_db["workloads/shop-app"]["access"]
    assert new["invoker_principals"] == ["serviceAccount:c@p.iam.gserviceaccount.com"]
    assert new["app_admin_emails"] == [] and new["source"] == "migration"  # nothing kept from the wider record
    (audit_path,) = [k for k in fake_db if k.startswith("workloads/shop-app/audit_logs/")]
    assert fake_db[audit_path]["previous_access"] == old


@pytest.mark.parametrize("headers, code", [(MANAGER_H, 403), (VIEWER_H, 403), ({}, 401)])
def test_patch_is_admin_only_and_a_refusal_writes_nothing(cc, monkeypatch, headers, code):
    _, wl = cc
    r, fake_db = _patch(wl, monkeypatch, IAP_INTAKE, headers=headers)
    assert r.status_code == code, r.text
    assert fake_db.writes == [] and fake_db.commits == 0 and dict(fake_db) == WL


@pytest.mark.parametrize("body", [
    {"mode": "PRIVATE_IAP", "invoker_principals": []},                    # ACCESS_POLICY_INCOMPLETE
    {"mode": "PRIVATE_IAP", "invoker_principals": ["allAuthenticatedUsers"]},
    {"mode": "PRIVATE_IAP", "invoker_principals": ["ana@example.com"]},
    {"mode": "PUBLIC_APP"},                                               # A8 unanswered
    {"mode": "PRIVATE_IAP", "invoker_principals": ["user:ana@example.com"], "source": "intake"},
    {"mode": "PRIVATE_IAP", "invoker_principals": ["user:ana@example.com"], "reason": "x" * 501},
])
def test_patch_invalid_body_is_422_and_writes_nothing(cc, monkeypatch, body):
    _, wl = cc
    r, fake_db = _patch(wl, monkeypatch, body)
    assert r.status_code == 422, r.text
    assert fake_db.writes == [] and fake_db.commits == 0


def test_patch_needs_a_json_body(cc, monkeypatch):
    """CSRF posture: a cross-site HTML form cannot send PATCH, and a form-encoded body is not accepted (422); the
    CC has no CORS middleware and its session cookie is SameSite=Lax."""
    _, wl = cc
    fake_db = FakeDB(WL)
    client = _client(wl, monkeypatch, fake_db)
    r = client.patch("/api/workloads/shop-app/access", data={"mode": "PRIVATE_IAP"}, headers=ADMIN_H)
    assert r.status_code == 422 and fake_db.writes == []


def test_patch_unknown_workload_is_404(cc, monkeypatch):
    _, wl = cc
    r, fake_db = _patch(wl, monkeypatch, IAP_INTAKE, initial={})
    assert r.status_code == 404 and fake_db.writes == []


def test_patch_failed_commit_is_500_and_nothing_lands(cc, monkeypatch):
    _, wl = cc
    r, fake_db = _patch(wl, monkeypatch, {**IAP_INTAKE, "confirm_widening": True}, fail_commit=True)
    assert r.status_code == 500 and dict(fake_db) == WL


# ============================================================================ 5. gateway Pub/Sub intake
@pytest.fixture
def intake_policy(monkeypatch):
    from fd4g_support import load_module

    return load_module(monkeypatch, "l1911_intake_policy", os.path.join(GW_DIR, "intake_policy.py"))


def _cc_event(**kw):
    return {"product_id": "shop-app", "source_channel": "control_center_form", "trace_id": "intake-shop-app-1", **kw}


def test_gateway_passes_record_less_events_unchanged(intake_policy):
    assert intake_policy.validate_intake(copy.deepcopy(_cc_event())) == _cc_event()
    assert intake_policy.validate_intake({"product_id": "shop-app"}) == {"product_id": "shop-app"}


_VALID_IAP_RECORD = {"mode": "PRIVATE_IAP", "invoker_principals": ["user:a@example.com"],
                     "sign_in": {"google": "DISABLED"}, "source": "intake"}


@pytest.mark.parametrize("event", [
    _cc_event(access=_VALID_IAP_RECORD),                       # even a valid record from the CC channel (F9)
    _cc_event(access={"mode": "PRIVATE_IAP", "invoker_principals": ["allAuthenticatedUsers"],
                      "sign_in": {"google": "DISABLED"}, "source": "intake"}),
    _cc_event(access="PRIVATE_IAP"),
    _cc_event(access=None),
    {"product_id": "shop-app", "access": _VALID_IAP_RECORD},  # google_docs
    {"product_id": "shop-app", "source_channel": "control_center_retrigger", "access": _VALID_IAP_RECORD},
])
def test_gateway_refuses_any_access_field_on_any_channel(intake_policy, event):
    """RT F9: `source_channel` is spoofable payload data; the only record is workloads/{pid}.access."""
    with pytest.raises(intake_policy.IntakeRejected) as ei:
        intake_policy.validate_intake(event)
    assert ei.value.status_code == 422 and ei.value.status == "SUPPRESSED:INVALID_ACCESS_POLICY"


def test_gateway_intake_check_never_needs_the_model(monkeypatch, intake_policy):
    monkeypatch.setitem(sys.modules, "shared.access_policy", None)  # import -> ImportError
    with pytest.raises(intake_policy.IntakeRejected) as ei:
        intake_policy.validate_intake(_cc_event(access=_VALID_IAP_RECORD))
    assert ei.value.status_code == 422
    assert intake_policy.validate_intake(_cc_event()) == _cc_event()


def test_workflow_never_forwards_an_access_record_to_the_developer():
    """RT F9: the request `access` outranks the stored record, so no workflow call may carry one."""
    import yaml

    wf = yaml.safe_load(open(os.path.join(REPO, "workflows", "main_orchestrator.yaml"), encoding="utf-8"))
    developer_calls = []

    def walk(node):
        if isinstance(node, dict):
            url = node.get("url")
            if isinstance(url, str) and "/agent/developer/" in url:
                developer_calls.append(node.get("body"))
            # LONG-STAGE-CALLBACK (owner 11-13): the developer is a callback job (run_stage_job `request`)
            if node.get("call") == "run_stage_job" and "/agent/developer/" in str((node.get("args") or {}).get("path")):
                developer_calls.append(node["args"].get("request"))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(wf)
    assert developer_calls, "the developer dispatch step was not found"
    for body in developer_calls:
        assert "access" not in (body or {})


# ============================================================================ 6. the create form
def test_create_form_defaults_private_iap_with_the_submitter_prefilled_and_a8_unanswered():
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    start = html.index("openNewWorkloadModal() {")
    opener = html[start:html.index("buildAccessIntake() {", start)]
    assert "mode: 'PRIVATE_IAP'" in opener
    assert "principals_text: this.userEmail ? ('user:' + this.userEmail) : ''" in opener
    assert "tenant_isolation_required: null" in opener
    assert "Who may use this app *" in html
    # Owner row 45 (Q19) / Fable R3 H1: exactly this question; NOT "serves users outside the org".
    assert "Does this app handle money, personal data, or other customers' data? *" in html
    assert "outside your organisation" not in html and "outside the org" not in html
    submit = html[html.index("async submitNewWorkload() {"):]
    submit = submit[:submit.index("async fetchEmergencyStopStatus()")]
    assert "createBody.access = access;" in submit and "JSON.stringify(createBody)" in submit
