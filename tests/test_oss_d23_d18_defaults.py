"""OSS-D23 + OSS-D18 (owner 10-19, docs/planning/behavior-change-register.md).

OSS-D23: the platform default access for a NEW workload is Private with Google sign-in (IAP). A new workload created
without an access answer (CC create API, or an intake event for a product with no workload document) gets
``shared.access_policy.platform_default_access_record(submitter)`` (PRIVATE_IAP, source ``platform_default``). Owner
10-20: it lists the SUBMITTER only when the platform verified who that is (the CC's authenticated human caller; the
Drive file owner from Drive API metadata); otherwise nobody, and the build stops with ACCESS_POLICY_INCOMPLETE until
an administrator lists who may use it. Nothing from the spec, titles or event bodies is ever listed. An explicit
PUBLIC_APP choice is still stored as public; an existing workload (with or without a record) is never changed.

OSS-D18: zero-config Drive folder discovery runs only when ``governance.drive_folder_auto_discovery`` is True (off by
default until FD-4AS authorized submitters); explicitly configured inbox folders always poll.

Hermetic: the in-memory Firestore fakes and fixtures of the L19-11, settings-toggles and FD-4F suites. No network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import pytest

from fd4f_support import FakeDB as GwFakeDB, gw  # noqa: F401  (gw is a fixture)
from test_l19_11_access_intake import ADMIN_H, OLD_PUBLIC, FakeDB as CcFakeDB, _client, _create, cc  # noqa: F401
from test_settings_toggles import _gw_settings, _intake, _settings, _spec_settings, spec  # noqa: F401  (spec: fixture)

from developer_agent.access_resolution import resolve_access  # noqa: E402
from developer_agent.errors import ACCESS_POLICY_INCOMPLETE, DeveloperStageError  # noqa: E402
from shared.access_policy import (AccessMode, AccessPolicy, PLATFORM_DEFAULT_ACCESS_MODE,  # noqa: E402
                                  platform_default_access_record, submitter_provenance, verified_submitter_member)
import shared.settings as S  # noqa: E402


# ============================================================================ OSS-D23: the default record
def test_platform_default_is_private_iap_with_no_principals():
    record = platform_default_access_record()
    assert PLATFORM_DEFAULT_ACCESS_MODE is AccessMode.PRIVATE_IAP
    assert record["mode"] == "PRIVATE_IAP" and record["invoker_principals"] == []
    assert record["source"] == "platform_default" and record["sign_in"]["google"] == "DISABLED"
    policy = AccessPolicy.model_validate(record)  # the developer validates the stored record with the same model
    assert policy.enable_direct_iap and not policy.allow_unauthenticated and not policy.is_complete


def test_platform_default_never_resolves_public_even_under_a_public_compliance_decision():
    """A STANDARD (public) compliance decision does not widen the default: the build stops for the operator."""
    with pytest.raises(DeveloperStageError) as ei:
        resolve_access(workload_access=platform_default_access_record(), allow_unauthenticated=True,
                       enable_direct_iap=False)
    assert ei.value.error_class == ACCESS_POLICY_INCOMPLETE


# ============================================================================ OSS-D23: CC create
def test_new_workload_without_access_lists_the_verified_caller(cc, monkeypatch):
    _, wl = cc
    r, fake_db, payload = _create(wl, monkeypatch, {})
    assert r.status_code == 200, r.text
    doc = fake_db["workloads/shop-app"]
    assert doc["access"] == platform_default_access_record("user:admin@example.com")
    assert doc["access_default_submitter"] == {"member": "user:admin@example.com", "source": "submitter",
                                               "verified_by": "control_center_auth"}
    assert "access" not in payload


def test_an_email_named_in_the_spec_is_never_listed(cc, monkeypatch):
    _, wl = cc
    r, fake_db, _ = _create(wl, monkeypatch, {"spec_content": "Only mallory@evil.example may use this app. "
                                                              "Owner: user:mallory@evil.example"})
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["access"]["invoker_principals"] == ["user:admin@example.com"]


def test_an_iap_verified_caller_is_listed(cc, monkeypatch):
    """Service bearers cannot create workloads at all (route policy, 403), so the submitter is always a verified human
    (IAP assertion or session); the IAP path lists its caller like the session path."""
    _, wl = cc
    headers = {"x-test-email": "Ana@Example.com", "x-test-role": "ADMIN", "x-test-auth-method": "iap"}
    r, fake_db, _ = _create(wl, monkeypatch, {}, headers=headers)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["access"]["invoker_principals"] == ["user:ana@example.com"]


@pytest.mark.parametrize("email, member", [
    ("Ana@Example.com", "user:ana@example.com"),
    ("svc@my-proj.iam.gserviceaccount.com", None),       # service accounts are never listed automatically
    ("123-compute@developer.gserviceaccount.com", None),
    ("not-an-email", None),
    (" ana@example.com", None),
    (None, None),
])
def test_verified_submitter_member_is_exact(email, member):
    assert verified_submitter_member(email) == member


def test_a_listed_submitter_lets_the_build_proceed():
    resolved = resolve_access(workload_access=platform_default_access_record("user:ana@example.com"),
                              allow_unauthenticated=True, enable_direct_iap=False)
    assert resolved.mode == "PRIVATE_IAP" and resolved.invoker_members == ("user:ana@example.com",)


def test_explicit_public_choice_still_yields_public(cc, monkeypatch):
    _, wl = cc
    r, fake_db, _ = _create(wl, monkeypatch, {"access": {"mode": "PUBLIC_APP", "tenant_isolation_required": False}})
    assert r.status_code == 200, r.text
    stored = fake_db["workloads/shop-app"]["access"]
    assert stored["mode"] == "PUBLIC_APP" and stored["source"] == "intake"


def test_existing_workload_stored_choice_is_untouched(cc, monkeypatch):
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app", "access": OLD_PUBLIC}}
    r, fake_db, _ = _create(wl, monkeypatch, {}, initial=initial)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["access"] == OLD_PUBLIC


def test_existing_workload_without_a_record_is_not_migrated(cc, monkeypatch):
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app", "status": "ACTIVE"}}
    r, fake_db, _ = _create(wl, monkeypatch, {}, initial=initial)
    assert r.status_code == 200, r.text
    assert "access" not in fake_db["workloads/shop-app"]


# ============================================================================ OSS-D23: gateway intake (Drive, GitHub)
def _maintenance_off(monkeypatch):
    _gw_settings(monkeypatch, lambda **k: _settings(maintenance_mode=False))


def test_drive_intake_without_a_known_owner_lists_nobody(gw, monkeypatch):
    _maintenance_off(monkeypatch)
    db = GwFakeDB()
    r, created = _intake(gw, monkeypatch, db, {"product_id": "drive-app", "trace_id": "tr-d23-1",
                                               "source_channel": "google_docs"})
    assert r.status_code == 200, r.text
    assert len(created) == 1
    assert db.docs["workloads/drive-app"]["access"] == platform_default_access_record()
    assert "access_default_submitter" not in db.docs["workloads/drive-app"]


def test_drive_intake_lists_the_drive_verified_file_owner(gw, monkeypatch):
    _maintenance_off(monkeypatch)
    db = GwFakeDB()
    db.docs["intake_submitters/tr-d23-4"] = {"product_id": "drive-app", "email": "ana@example.com",
                                             "verified_by": "drive_file_owner"}
    r, created = _intake(gw, monkeypatch, db, {"product_id": "drive-app", "trace_id": "tr-d23-4",
                                               "source_channel": "google_docs"})
    assert r.status_code == 200, r.text
    doc = db.docs["workloads/drive-app"]
    assert doc["access"] == platform_default_access_record("user:ana@example.com")
    assert doc["access_default_submitter"]["verified_by"] == "drive_file_owner" and len(created) == 1


@pytest.mark.parametrize("record", [
    {"product_id": "other-app", "email": "ana@example.com", "verified_by": "drive_file_owner"},  # another product
    {"product_id": "drive-app", "email": "ana@example.com", "verified_by": "spec_text"},         # not Drive-verified
    {"product_id": "drive-app", "email": "svc@p.iam.gserviceaccount.com", "verified_by": "drive_file_owner"},
])
def test_drive_intake_lists_nobody_for_an_unusable_owner_record(gw, monkeypatch, record):
    _maintenance_off(monkeypatch)
    db = GwFakeDB()
    db.docs["intake_submitters/tr-d23-5"] = record
    r, _ = _intake(gw, monkeypatch, db, {"product_id": "drive-app", "trace_id": "tr-d23-5",
                                         "source_channel": "google_docs"})
    assert r.status_code == 200, r.text
    assert db.docs["workloads/drive-app"]["access"]["invoker_principals"] == []


def test_non_drive_channels_list_nobody_even_with_an_owner_record(gw, monkeypatch):
    """Only Drive has a platform-verified submitter; any other channel (there is no GitHub spec-intake channel; a
    GitHub login is not a Google identity) lists nobody."""
    _maintenance_off(monkeypatch)
    db = GwFakeDB()
    db.docs["intake_submitters/tr-d23-6"] = {"product_id": "drive-app", "email": "ana@example.com",
                                             "verified_by": "drive_file_owner"}
    r, _ = _intake(gw, monkeypatch, db, {"product_id": "drive-app", "trace_id": "tr-d23-6",
                                         "source_channel": "deploy_to_folder"})
    assert r.status_code == 200, r.text
    assert db.docs["workloads/drive-app"]["access"]["invoker_principals"] == []


@pytest.mark.parametrize("existing", [{"status": "ACTIVE"}, {"status": "ACTIVE", "access": OLD_PUBLIC}])
def test_intake_never_changes_an_existing_workload(gw, monkeypatch, existing):
    _maintenance_off(monkeypatch)
    db = GwFakeDB()
    db.docs["workloads/drive-app"] = dict(existing)
    r, created = _intake(gw, monkeypatch, db, {"product_id": "drive-app", "trace_id": "tr-d23-2",
                                               "source_channel": "google_docs"})
    assert r.status_code == 200, r.text
    assert db.docs["workloads/drive-app"] == existing and len(created) == 1


def test_intake_default_write_failure_is_503_and_dispatches_nothing(gw, monkeypatch):
    _maintenance_off(monkeypatch)
    db = GwFakeDB()
    db.fail_writes = True
    r, created = _intake(gw, monkeypatch, db, {"product_id": "drive-app", "trace_id": "tr-d23-3",
                                               "source_channel": "google_docs"})
    assert r.status_code == 503 and created == []


# ============================================================================ OSS-D18: Drive folder auto-discovery
def test_auto_discovery_setting_defaults_off():
    assert S.PlatformSettings().governance.drive_folder_auto_discovery is False
    assert S.drive_folder_auto_discovery_enabled(read=lambda **k: S.PlatformSettings()) is False


def test_auto_discovery_off_when_settings_cannot_be_read():
    def boom(**k):
        raise S.PlatformSettingsReadError("down")
    assert S.drive_folder_auto_discovery_enabled(read=boom) is False


def test_poll_does_not_discover_by_default(spec, monkeypatch):
    monkeypatch.delenv("INBOX_FOLDER_ID", raising=False)
    monkeypatch.delenv("IN_PROGRESS_FOLDER_ID", raising=False)
    _spec_settings(monkeypatch, lambda **k: _settings(maintenance_mode=False))
    out = spec.mod.execute_poll()
    assert out["status"] == "IDLE" and "authorized submitters" in out["message"]
    spec.poller.auto_discover_shared_folders.assert_not_called()
    spec.poller.poll_and_ingest.assert_not_called()


def test_poll_discovers_when_the_flag_is_on(spec, monkeypatch):
    _spec_settings(monkeypatch, lambda **k: _settings(maintenance_mode=False, drive_folder_auto_discovery=True))
    spec.poller.auto_discover_shared_folders.return_value = [("inbox-a", "prog-a")]
    spec.poller.poll_and_ingest.return_value = []
    out = spec.mod.execute_poll()
    assert out["status"] == "SUCCESS" and out["shared_folders_discovered"] == 1
    spec.poller.poll_and_ingest.assert_called_once_with("inbox-a", "prog-a")


@pytest.mark.parametrize("call", ["poll", "webhook"])
def test_explicitly_configured_folders_still_poll_with_discovery_off(spec, monkeypatch, call):
    monkeypatch.setenv("INBOX_FOLDER_ID", "inbox-x")
    monkeypatch.setenv("IN_PROGRESS_FOLDER_ID", "prog-x")
    _spec_settings(monkeypatch, lambda **k: _settings(maintenance_mode=False))
    spec.poller.poll_and_ingest.return_value = []
    {"poll": spec.mod.execute_poll, "webhook": spec.mod.handle_drive_push_notification}[call]()
    spec.poller.auto_discover_shared_folders.assert_not_called()
    spec.poller.poll_and_ingest.assert_called_once_with("inbox-x", "prog-x")


# ============================================================================ OSS-D23: poller records the Drive owner
def _poller():
    import importlib.util
    import os
    import sys
    path = os.path.join(os.path.dirname(__file__), "..", "apps", "spec-ingestion", "poller.py")
    spec_dir = os.path.dirname(os.path.abspath(path))
    if spec_dir not in sys.path:
        sys.path.insert(0, spec_dir)
    mod_spec = importlib.util.spec_from_file_location("oss_d23_poller", path)
    mod = importlib.util.module_from_spec(mod_spec)
    mod_spec.loader.exec_module(mod)
    return mod.SpecIngestionPoller


@pytest.mark.parametrize("doc, email", [
    ({"name": "NEW_PRODUCT_SPEC: shop (owner mallory@evil.example)", "owners": [{"emailAddress": "ana@example.com"}]},
     "ana@example.com"),
    ({"name": "shop by mallory@evil.example", "description": "contact mallory@evil.example"}, None),  # no metadata
    ({"name": "shop", "owners": [{"emailAddress": "sa@p.iam.gserviceaccount.com", "me": True}]}, None),  # the poller
    ({"name": "shop", "owners": [{"emailAddress": "a@example.com"}, {"emailAddress": "b@example.com"}]}, None),
])
def test_poller_takes_the_owner_only_from_drive_metadata(doc, email):
    assert _poller().drive_file_owner_email(doc) == email


def test_poller_records_the_owner_for_the_gateway():
    poller = object.__new__(_poller())
    db = GwFakeDB()
    poller.db = db
    poller.record_submitter("tr-9", "shop", "doc-1", "ana@example.com")
    stored = db.docs["intake_submitters/tr-9"]
    assert stored["email"] == "ana@example.com" and stored["product_id"] == "shop"
    assert stored["verified_by"] == "drive_file_owner"
    poller.record_submitter("tr-10", "shop", "doc-2", None)
    assert "intake_submitters/tr-10" not in db.docs


# ============================================================================ Fable RT fixes (F1, F2, F4, F5, F7)
import ast  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
from types import SimpleNamespace  # noqa: E402
from unittest.mock import MagicMock, patch  # noqa: E402

CC_SRC = os.path.join(os.path.dirname(__file__), "..", "apps", "control-center")


def _promote(wl, monkeypatch, fake_db, headers=ADMIN_H):
    """POST /api/workloads/src-app/deploy-to-folder on the real router (destination = the managed root itself)."""
    import folders

    monkeypatch.setattr(folders, "_default_get_folder", lambda name: {"name": name, "parent": "organizations/1"})
    monkeypatch.setattr(wl, "get_caller_main_module", lambda: SimpleNamespace())
    monkeypatch.setattr(wl, "create_or_verify_branch", lambda **k: None)
    client = _client(wl, monkeypatch, fake_db)
    publisher = MagicMock()
    publisher.publish.return_value.result.return_value = "msg-1"
    with patch.dict(os.environ, {"MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
         patch.object(wl, "get_pubsub_publisher", return_value=publisher), \
         patch.object(wl, "get_platform_settings",
                      return_value=__import__("routes.settings", fromlist=["x"]).PlatformSettings()):
        r = client.post("/api/workloads/src-app/deploy-to-folder", headers=headers,
                        json={"destination_folder_id": "folders/111111111111", "new_product_id": "src-app-prod",
                              "target_branch": "prod"})
    payload = (json.loads(publisher.publish.call_args[0][1].decode("utf-8"))
               if publisher.publish.call_args else None)
    return r, payload


SRC = {"workloads/src-app": {"product_id": "src-app", "status": "ACTIVE", "github_repo": "example-org/src-app",
                             "access": OLD_PUBLIC}}


def test_promotion_gets_the_private_default_listing_the_admin_not_the_source_record(cc, monkeypatch):
    _, wl = cc
    fake_db = CcFakeDB(SRC)
    r, payload = _promote(wl, monkeypatch, fake_db)
    assert r.status_code == 200, r.text
    doc = fake_db["workloads/src-app-prod"]
    assert doc["access"] == platform_default_access_record("user:admin@example.com")  # never OLD_PUBLIC copied
    assert doc["access_default_submitter"] == {"member": "user:admin@example.com", "source": "submitter",
                                               "verified_by": "control_center_auth"}
    assert payload is not None and "access" not in payload
    assert fake_db["workloads/src-app"]["access"] == OLD_PUBLIC  # the source is untouched


def test_promotion_never_overwrites_an_existing_target(cc, monkeypatch):
    _, wl = cc
    initial = dict(SRC)
    initial["workloads/src-app-prod"] = {"product_id": "src-app-prod", "access": OLD_PUBLIC}
    fake_db = CcFakeDB(initial)
    r, payload = _promote(wl, monkeypatch, fake_db)
    assert r.status_code == 409 and payload is None
    assert fake_db["workloads/src-app-prod"] == initial["workloads/src-app-prod"]


def test_every_cc_route_creating_a_provisioning_workload_applies_the_default():
    """Sweep (RT F1/F7g): any Control Center function that builds a workload document with status PROVISIONING must
    apply ``_default_access_fields`` (the private platform default), so no new route is public by omission."""
    offenders, found = [], []
    for root, _dirs, names in os.walk(CC_SRC):
        if "shared" in root.split(os.sep) or "__pycache__" in root:
            continue
        for name in names:
            if not name.endswith(".py") or name.startswith("test_"):
                continue
            path = os.path.join(root, name)
            tree = ast.parse(open(path).read())
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                creates = any(isinstance(n, ast.Dict) and any(
                    isinstance(k, ast.Constant) and k.value == "status" and isinstance(v, ast.Constant)
                    and v.value == "PROVISIONING" for k, v in zip(n.keys, n.values)) for n in ast.walk(fn))
                if not creates:
                    continue
                found.append(fn.name)
                if not any(isinstance(n, ast.Name) and n.id == "_default_access_fields" for n in ast.walk(fn)):
                    offenders.append(f"{name}:{fn.name}")
    assert sorted(found) == ["create_workload", "deploy_workload_to_folder_endpoint"], found
    assert offenders == []


@pytest.mark.parametrize("method", ["bearer", "", None])
def test_default_fields_list_nobody_without_a_verified_human(cc, method):
    """RT F7a: the route policy already refuses service bearers on create/promote; the helper itself also lists
    nobody for a bearer, an unset or an unknown auth method (the IAP/session branch is tested via the test middleware;
    extract_user_email has its own suite)."""
    _, wl = cc
    req = SimpleNamespace(state=SimpleNamespace(user_email="admin@example.com", auth_method=method))
    assert wl._default_access_fields(req) == {"access": platform_default_access_record()}


def test_cc_create_default_path_unreadable_store_is_503(cc, monkeypatch):
    """RT F7c: cannot tell whether the workload is new -> 503, nothing written."""
    _, wl = cc

    class _Unreadable(CcFakeDB):
        def collection(self, name):
            col = super().collection(name)
            if name != "workloads":
                return col
            doc = col.document

            def _document(doc_id=None):
                ref = doc(doc_id)
                ref.get = lambda: (_ for _ in ()).throw(RuntimeError("firestore read failed"))
                return ref
            col.document = _document
            return col

    fake_db = _Unreadable()
    client = _client(wl, monkeypatch, fake_db)
    with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
         patch.object(wl, "get_pubsub_publisher", return_value=MagicMock()), \
         patch.object(wl, "get_platform_settings",
                      return_value=__import__("routes.settings", fromlist=["x"]).PlatformSettings()):
        r = client.post("/api/workloads", json={"product_id": "shop-app", "spec_content": "a shop"}, headers=ADMIN_H)
    assert r.status_code == 503 and fake_db.writes == []


def test_cc_create_race_never_overwrites_a_concurrent_create(cc, monkeypatch):
    """RT F5: the document appears between the existence read and the write (a concurrent explicit PUBLIC_APP
    create): the default is written with create() semantics, so the answer is 409 and the other record stays."""
    _, wl = cc

    class _Racy(CcFakeDB):
        def collection(self, name):
            col = super().collection(name)
            if name != "workloads":
                return col
            doc = col.document
            store = self

            def _document(doc_id=None):
                ref = doc(doc_id)
                real_get = ref.get

                def _get():
                    snap = real_get()
                    store[ref.path] = {"product_id": doc_id, "access": OLD_PUBLIC}  # lands right after the read
                    return snap
                ref.get = _get
                return ref
            col.document = _document
            return col

    fake_db = _Racy()
    client = _client(wl, monkeypatch, fake_db)
    with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
         patch.object(wl, "get_pubsub_publisher", return_value=MagicMock()), \
         patch.object(wl, "get_platform_settings",
                      return_value=__import__("routes.settings", fromlist=["x"]).PlatformSettings()):
        r = client.post("/api/workloads", json={"product_id": "shop-app", "spec_content": "a shop"}, headers=ADMIN_H)
    assert r.status_code == 409, r.text
    assert fake_db["workloads/shop-app"]["access"] == OLD_PUBLIC


def test_submitter_provenance_refuses_an_unknown_verification():
    with pytest.raises(ValueError):
        submitter_provenance("user:ana@example.com", "spec_text")


@pytest.mark.parametrize("trace", [None, "", 123])
def test_drive_submitter_needs_a_string_trace(gw, trace):
    db = GwFakeDB()
    db.docs["intake_submitters/123"] = {"product_id": "p", "email": "ana@example.com", "verified_by": "drive_file_owner"}
    assert gw._drive_verified_submitter(db, trace, "p") is None


class _GwDB(GwFakeDB):
    """The FD-4F fake, plus real Firestore's id rule (a '/' in a document id is ValueError) and an optional read
    failure for intake_submitters only."""

    def __init__(self, fail_submitter_reads=False):
        super().__init__()
        self.fail_submitter_reads = fail_submitter_reads

    def collection(self, name):
        col = super().collection(name)
        if name != "intake_submitters":
            return col
        db, doc = self, col.document

        def _document(doc_id):
            if "/" in doc_id:
                raise ValueError(f"invalid document id {doc_id!r}")
            ref = doc(doc_id)
            if db.fail_submitter_reads:
                ref.get = lambda: (_ for _ in ()).throw(RuntimeError("firestore read failed"))
            return ref
        col.document = _document
        return col


def test_drive_submitter_with_a_malformed_trace_lists_nobody(gw):
    """RT F4: an id Firestore refuses is "no listable record", not a 503 retry loop."""
    assert gw._drive_verified_submitter(_GwDB(), "a/b", "drive-app") is None


def test_drive_submitter_unreadable_is_503_and_dispatches_nothing(gw, monkeypatch):
    """RT F7b."""
    _maintenance_off(monkeypatch)
    db = _GwDB(fail_submitter_reads=True)
    r, created = _intake(gw, monkeypatch, db, {"product_id": "drive-app", "trace_id": "tr-d23-7",
                                               "source_channel": "google_docs"})
    assert r.status_code == 503 and created == [] and "workloads/drive-app" not in db.docs


def test_poll_records_the_owner_before_publishing_and_routing_never_sees_owners(monkeypatch):
    """RT F2/F7e: poll_and_ingest records the listing's owner before publishing, and folder routing gets the file
    without ``owners``, so the owner-email folder assignment tier stays inactive exactly as before."""
    cls = _poller()
    poller = object.__new__(cls)
    poller.db, events, routed = GwFakeDB(), [], []
    doc = {"id": "doc-1", "name": "NEW_PRODUCT_SPEC: Shop", "owners": [{"emailAddress": "ana@example.com"}]}
    poller.db.docs["users/ana@example.com"] = {"assigned_folder_id": "folders/999"}  # would route if owners leaked
    poller.db.docs["authorized_users/ana@example.com"] = {"role": "WORKLOAD_MANAGER", "is_active": True}  # FD-4AS
    monkeypatch.setattr(poller, "list_inbox_specs", lambda inbox: [dict(doc)], raising=False)
    monkeypatch.setattr(poller, "move_to_in_progress", lambda *a: True, raising=False)
    monkeypatch.setattr(poller, "read_doc_text", lambda doc_id: "", raising=False)
    real_resolve = cls.resolve_target_folder

    def _resolve(d, parent_drive_folder_id=None):
        routed.append(dict(d))
        return real_resolve(poller, d, parent_drive_folder_id=None)
    monkeypatch.setattr(poller, "resolve_target_folder", _resolve, raising=False)

    def _publish(payload):
        events.append(("publish", poller.db.docs.get(f"intake_submitters/{payload['trace_id']}")))
        return "m-1"
    monkeypatch.setattr(poller, "publish_intake_event", _publish, raising=False)
    monkeypatch.setattr(poller, "record_ingestion", lambda *a: None, raising=False)
    monkeypatch.delenv("MANAGED_WORKLOADS_FOLDER_ID", raising=False)
    items = poller.poll_and_ingest("inbox", "prog")
    assert len(items) == 1 and events[0][1]["email"] == "ana@example.com"
    assert routed and all("owners" not in d for d in routed)
    assert items[0]["folder_id"] != "folders/999"


def test_poller_listing_fetches_owners_in_the_same_call():
    """RT F2: owners come from the existing files.list call (one call, owners in its fields)."""
    cls = _poller()
    poller = object.__new__(cls)
    calls = []

    class _Files:
        def list(self, **kw):
            calls.append(kw)
            return SimpleNamespace(execute=lambda: {"files": []})
    poller.drive_service = SimpleNamespace(files=lambda: _Files())
    assert poller.list_inbox_specs("inbox") == []
    assert len(calls) == 1 and "owners(emailAddress, me)" in calls[0]["fields"]
