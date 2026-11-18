"""FD-4AS (owner-approved 10-20, register row FD-4AS): Drive spec intake accepts only authorized submitters and only
managed target folders.

- A document is moved / published only when its Drive owner (``drive_file_owner_email``: the same Drive-verified
  identity OSS-D23 records in ``intake_submitters``) has an ACTIVE Control Center user record
  ``authorized_users/{email}`` with role ADMIN, WORKLOAD_MANAGER or legacy APPROVER. Anything else is a typed skip
  (SPEC_SUBMITTER_UNAUTHORIZED) on the poll result and the ``spec_ingestions`` audit record.
- Auto-discovered (and request-supplied) inboxes are polled only when owned by an authorized submitter, or when they
  are the configured INBOX_FOLDER_ID.
- Every target-folder candidate must be an active ``managed_folders`` document (exact id; whole-name casefold for
  names, unique); otherwise TARGET_FOLDER_NOT_MANAGED and the document is skipped (never re-routed).
- Any unreadable decision input -> the whole pass is skipped (SPEC_INTAKE_UNAVAILABLE): zero moves, zero publishes.

Hermetic: in-memory Drive / Pub/Sub / Firestore fakes passed to the poller constructor. No network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

SPEC_DIR = os.path.join(os.path.dirname(__file__), "..", "apps", "spec-ingestion")
if os.path.abspath(SPEC_DIR) not in sys.path:
    sys.path.insert(0, os.path.abspath(SPEC_DIR))

import intake_outcomes as IO  # noqa: E402


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def P():
    return _load(os.path.join(SPEC_DIR, "poller.py"), "fd4as_poller")


# ----------------------------------------------------------------------------------------------------- fakes
class _Snap:
    def __init__(self, data):
        self._data = data
        self.exists = data is not None

    def to_dict(self):
        return None if self._data is None else dict(self._data)


class _Query:
    def __init__(self, col, filters=(), n=None):
        self.col, self.filters, self.n = col, list(filters), n

    def where(self, field, op, value):
        assert op == "=="
        return _Query(self.col, self.filters + [(field, value)], self.n)

    def limit(self, n):
        return _Query(self.col, self.filters, n)

    def stream(self):
        self.col.fs._maybe_fail(self.col.name)
        rows = [d for d in self.col.fs.data.get(self.col.name, {}).values()
                if all(d.get(f) == v for f, v in self.filters)]
        return [_Snap(r) for r in rows[: self.n if self.n is not None else None]]


class _DocRef:
    def __init__(self, col, doc_id):
        self.col, self.doc_id = col, doc_id

    def get(self):
        self.col.fs._maybe_fail(self.col.name)
        return _Snap(self.col.fs.data.get(self.col.name, {}).get(self.doc_id))

    def set(self, data, merge=False):
        self.col.fs.writes.append((self.col.name, self.doc_id, dict(data), merge))
        col = self.col.fs.data.setdefault(self.col.name, {})
        col[self.doc_id] = dict(col.get(self.doc_id, {}), **data) if merge else dict(data)


class _Col(_Query):
    def __init__(self, fs, name):
        self.fs, self.name = fs, name
        super().__init__(self)

    def document(self, doc_id):
        if "/" in doc_id or not doc_id:
            raise ValueError("invalid document id")
        return _DocRef(self, doc_id)


class FakeFS:
    def __init__(self, data=None, fail=()):
        self.data = {k: dict(v) for k, v in (data or {}).items()}
        self.fail = set(fail)
        self.writes = []

    def _maybe_fail(self, name):
        if name in self.fail:
            raise RuntimeError("firestore unavailable")

    def collection(self, name):
        return _Col(self, name)


class _Exec:
    def __init__(self, fn):
        self.fn = fn

    def execute(self):
        return self.fn()


class FakeDrive:
    """files().list by query shape; files().update records moves; files().get by id."""

    def __init__(self, listings=None, discovery=None, siblings=None, meta=None):
        self.listings, self.discovery = listings or {}, discovery or []
        self.siblings, self.meta = siblings or {}, meta or {}
        self.moves, self.list_calls, self.get_calls = [], [], []

    def files(self):
        return self

    def list(self, q, fields, pageSize=None):
        self.list_calls.append((q, fields))
        folder = q.split("'")[1]
        if q.startswith("name = '01_Inbox_Requests'"):
            return _Exec(lambda: {"files": [dict(f) for f in self.discovery]})
        if "name = '02_In_Progress'" in q:
            return _Exec(lambda: {"files": self.siblings.get(folder, [])})
        return _Exec(lambda: {"files": [dict(f) for f in self.listings.get(folder, [])]})

    def update(self, fileId, addParents, removeParents, fields):
        def _do():
            self.moves.append((fileId, removeParents, addParents))
            return {"id": fileId, "parents": [addParents]}
        return _Exec(_do)

    def get(self, fileId, fields):
        self.get_calls.append((fileId, fields))

        def _do():
            if fileId not in self.meta:
                raise RuntimeError("drive get failed")
            if isinstance(self.meta[fileId], int):  # an HTTP status: raise the real Drive client error
                import httplib2
                from googleapiclient.errors import HttpError
                raise HttpError(httplib2.Response({"status": self.meta[fileId]}), b"{}")
            return dict(self.meta[fileId])
        return _Exec(_do)


class FakePublisher:
    def __init__(self):
        self.published = []

    def topic_path(self, project, topic):
        return f"projects/{project}/topics/{topic}"

    def publish(self, topic, data):
        self.published.append((topic, data))
        return SimpleNamespace(result=lambda: f"msg-{len(self.published)}")


class FakeDocs:
    def documents(self):
        return SimpleNamespace(get=lambda documentId: _Exec(lambda: {"body": {"content": []}}))


ANA = "ana@example.com"
USERS = {ANA: {"email": ANA, "role": "WORKLOAD_MANAGER", "is_active": True}}
FINANCE = {"folder_id": "folders/444555", "display_name": "Finance", "status": "ACTIVE", "is_default": False}
DEFAULT = {"folder_id": "folders/777000", "display_name": "Platform Default", "status": "ACTIVE", "is_default": True}
MANAGED = {"folders_444555": FINANCE, "folders_777000": DEFAULT}


def _owner(email, me=False):
    return [{"emailAddress": email, "me": me}]


def _doc(doc_id="doc-1", name="NEW_PRODUCT_SPEC: Shop", owners=None, **extra):
    d = {"id": doc_id, "name": name, "mimeType": "application/vnd.google-apps.document",
         "webViewLink": f"https://docs.example/{doc_id}"}
    if owners is not None:
        d["owners"] = owners
    d.update(extra)
    return d


def _poller(mod, docs=(), users=None, managed=None, fail=(), drive=None, meta=None):
    fs = FakeFS({"authorized_users": USERS if users is None else users,
                 "managed_folders": MANAGED if managed is None else managed}, fail=fail)
    drive = drive or FakeDrive(listings={"inbox": list(docs)},
                               meta={"inbox": {"name": "01_Inbox_Requests"}} if meta is None else meta)
    pub = FakePublisher()
    p = mod.SpecIngestionPoller(project_id="mock-stackvend-project", drive_service=drive, publisher_client=pub,
                                firestore_client=fs, docs_service=FakeDocs())
    return SimpleNamespace(p=p, fs=fs, drive=drive, pub=pub)


def _freeze(monkeypatch, mod):
    class _DT(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "datetime", _DT)
    monkeypatch.setattr(mod.uuid, "uuid4", lambda: uuid.UUID("12345678-1234-5678-1234-567812345678"))


def _audit(fs, doc_id):
    return fs.data.get("spec_ingestions", {}).get(doc_id)


# ---------------------------------------------------------------- Do No Harm: authorized flow is byte-identical
# Captured with these exact fakes from the base poller (main 7fb13c02, before FD-4AS) for a Finance-tagged doc owned
# by an authorized user: the FD-4AS poller must publish the very same bytes.
BASE_PAYLOAD_BYTES = (
    b'{"trace_id": "12345678-1234-5678-1234-567812345678", "spec_doc_id": "doc-1", "doc_title": "NEW_PRODUCT_SPEC: '
    b'Shop [folder: Finance]", "product_id": "shop-folder-finance", "folder_id": "folders/444555", "source_channel": '
    b'"google_docs", "ingested_at": "2026-10-20T12:00:00+00:00", "status": "IN_PROGRESS", "web_view_link": '
    b'"https://docs.example/doc-1", "is_sandbox": false, "sandbox_ttl_days": 30, "sandbox_expires_at": null, '
    b'"folders": {"inbox": "inbox", "in_progress": "prog"}}'
)


def run_authorized_pass(mod, monkeypatch):
    """Shared by the payload capture on the base commit and the assertion below."""
    _freeze(monkeypatch, mod)
    monkeypatch.delenv("MANAGED_WORKLOADS_FOLDER_ID", raising=False)
    h = _poller(mod, [_doc(name="NEW_PRODUCT_SPEC: Shop [folder: Finance]", owners=_owner(ANA))])
    items = h.p.poll_and_ingest("inbox", "prog")
    return h, items


def test_authorized_doc_publishes_byte_identical_payload(P, monkeypatch):
    h, items = run_authorized_pass(P, monkeypatch)
    assert [data for _, data in h.pub.published] == [BASE_PAYLOAD_BYTES]
    assert h.drive.moves == [("doc-1", "inbox", "prog")]
    assert len(items) == 1 and items.skipped == []
    assert h.fs.data["intake_submitters"]["12345678-1234-5678-1234-567812345678"]["email"] == ANA  # OSS-D23 intact


# ---------------------------------------------------------------- 1. authorized submitter
@pytest.mark.parametrize("owners, users, why", [
    (_owner("mallory@outsider.example"), None, "not a Control Center user"),
    (None, None, "no single Drive owner"),                                      # shared drive: no owners
    (_owner("svc@proj.iam.gserviceaccount.com", me=True), None, "no single Drive owner"),
    (_owner(ANA) + _owner("bob@example.com"), None, "no single Drive owner"),   # two owners
    (_owner(ANA), {ANA: {"role": "VIEWER", "is_active": True}}, "cannot submit"),
    (_owner(ANA), {ANA: {"role": "SUPERUSER", "is_active": True}}, "cannot submit"),
    (_owner(ANA), {ANA: {"role": "ADMIN", "is_active": False}}, "inactive"),
    (_owner(ANA), {ANA: {"role": "ADMIN", "is_active": None}}, "inactive"),
    (_owner(ANA), {ANA: {"role": "ADMIN", "is_active": "maybe"}}, "inactive"),
    (_owner("a/b@example.com"), None, "not a valid"),
])
def test_unauthorized_owner_is_not_moved_not_published_and_typed(P, owners, users, why):
    h = _poller(P, [_doc(owners=owners)], users=users)
    items = h.p.poll_and_ingest("inbox", "prog")
    assert list(items) == [] and h.pub.published == [] and h.drive.moves == []
    assert [s["skip_code"] for s in items.skipped] == [IO.SPEC_SUBMITTER_UNAUTHORIZED]
    assert why in items.skipped[0]["skip_reason"]
    audit = _audit(h.fs, "doc-1")
    assert audit["last_skip"]["skip_code"] == IO.SPEC_SUBMITTER_UNAUTHORIZED and "status" not in audit
    assert "intake_submitters" not in h.fs.data


@pytest.mark.parametrize("record", [
    {"role": "ADMIN", "is_active": True}, {"role": "WORKLOAD_MANAGER"}, {"role": "APPROVER", "is_active": "true"},
    {"is_active": True},  # missing role = legacy APPROVER, exactly as the Control Center decodes it
])
def test_authorized_roles_are_ingested(P, record, monkeypatch):
    monkeypatch.delenv("MANAGED_WORKLOADS_FOLDER_ID", raising=False)
    h = _poller(P, [_doc(owners=_owner(ANA))], users={ANA: record})
    items = h.p.poll_and_ingest("inbox", "prog")
    assert len(items) == 1 and items[0]["folder_id"] == "folders/777000" and len(h.pub.published) == 1


def test_owner_email_is_case_normalized_exactly(P):
    h = _poller(P, [_doc(owners=_owner("  Ana@Example.COM "))])
    assert len(h.p.poll_and_ingest("inbox", "prog")) == 1


def test_no_domain_matching(P):
    """Same domain as an authorized user is not authorization."""
    h = _poller(P, [_doc(owners=_owner("eve@example.com"))])
    items = h.p.poll_and_ingest("inbox", "prog")
    assert list(items) == [] and items.skipped[0]["skip_code"] == IO.SPEC_SUBMITTER_UNAUTHORIZED


def test_mixed_inbox_ingests_only_the_authorized_doc(P):
    h = _poller(P, [_doc("doc-out", owners=_owner("mallory@outsider.example")), _doc("doc-in", owners=_owner(ANA))])
    items = h.p.poll_and_ingest("inbox", "prog")
    assert [i["spec_doc_id"] for i in items] == ["doc-in"] and h.drive.moves == [("doc-in", "inbox", "prog")]
    assert [s["spec_doc_id"] for s in items.skipped] == ["doc-out"]


# ---------------------------------------------------------------- fail closed: store unreadable
@pytest.mark.parametrize("fail", [("authorized_users",), ("managed_folders",)])
def test_firestore_raising_skips_the_whole_pass(P, fail):
    h = _poller(P, [_doc("doc-a", owners=_owner(ANA)), _doc("doc-b", owners=_owner(ANA))], fail=fail)
    with pytest.raises(IO.IntakeUnavailableError) as ei:
        h.p.poll_and_ingest("inbox", "prog")
    assert ei.value.code == IO.SPEC_INTAKE_UNAVAILABLE
    assert h.drive.moves == [] and h.pub.published == [] and h.fs.writes == []


def test_no_firestore_client_is_unavailable_not_proceed(P):
    h = _poller(P, [_doc(owners=_owner(ANA))])
    h.p.db = None
    with pytest.raises(IO.IntakeUnavailableError):
        h.p.poll_and_ingest("inbox", "prog")
    assert h.drive.moves == [] and h.pub.published == []


def test_parent_folder_name_unreadable_is_unavailable(P):
    h = _poller(P, [_doc(owners=_owner(ANA))], meta={})  # Drive get of the inbox fails
    with pytest.raises(IO.IntakeUnavailableError):
        h.p.poll_and_ingest("inbox", "prog")
    assert h.drive.moves == [] and h.pub.published == []


# ---------------------------------------------------------------- 3. target folder: managed folders only
@pytest.mark.parametrize("name", ["Shop [folder: 123456789012]", "Shop [folder: folders/123456789012]",
                                  "Shop [target_folder: Not A Managed Folder]", "Shop [folder: folders/abc]"])
def test_unmanaged_tag_is_rejected_with_no_fallback_to_default(P, name):
    h = _poller(P, [_doc(name=name, owners=_owner(ANA))])  # a default managed folder exists
    items = h.p.poll_and_ingest("inbox", "prog")
    assert list(items) == [] and h.drive.moves == [] and h.pub.published == []
    assert items.skipped[0]["skip_code"] == IO.TARGET_FOLDER_NOT_MANAGED


@pytest.mark.parametrize("name", ["Shop [folder: 444555]", "Shop [folder: finance]",
                                  "Shop [target-folder:  FINANCE ]"])
def test_managed_tag_routes_to_that_folder(P, name):
    h = _poller(P, [_doc(name=name, owners=_owner(ANA))])
    items = h.p.poll_and_ingest("inbox", "prog")
    assert items[0]["folder_id"] == "folders/444555"


def test_rt14_37_id_form_title_tag_gives_an_invalid_product_id_and_stays_in_the_inbox(P):
    """RT14-37: the title tag is part of the product id, so `folders/444555` made the id `shop-folder-folders/444555`
    (a Firestore subcollection path: 503, retries, DLQ after the doc had moved). It is now a typed skip, nothing moved;
    the same folder id in the description still routes."""
    h = _poller(P, [_doc("d1", name="Shop [folder: folders/444555]", owners=_owner(ANA)),
                    _doc("d2", name="Shop", owners=_owner(ANA), description="folder: folders/444555")])
    items = h.p.poll_and_ingest("inbox", "prog")
    assert [i["spec_doc_id"] for i in items] == ["d2"] and items[0]["folder_id"] == "folders/444555"
    assert [(s["spec_doc_id"], s["skip_code"]) for s in items.skipped] == [("d1", IO.SPEC_PRODUCT_ID_INVALID)]
    assert h.drive.moves == [("d2", "inbox", "prog")]


def test_description_and_property_candidates_are_checked_too(P):
    h = _poller(P, [_doc("d1", owners=_owner(ANA), description="folder: 999"),
                    _doc("d2", owners=_owner(ANA), properties={"target_folder": "folders/999"}),
                    _doc("d3", owners=_owner(ANA), properties={"target_folder": "folders/444555"})])
    items = h.p.poll_and_ingest("inbox", "prog")
    assert [i["spec_doc_id"] for i in items] == ["d3"] and items[0]["folder_id"] == "folders/444555"
    assert {s["spec_doc_id"]: s["skip_code"] for s in items.skipped} == {
        "d1": IO.TARGET_FOLDER_NOT_MANAGED, "d2": IO.TARGET_FOLDER_NOT_MANAGED}


def test_name_tag_matching_two_folders_is_ambiguous_and_rejected(P):
    managed = dict(MANAGED, folders_1={"folder_id": "folders/1", "display_name": "FINANCE", "status": "ACTIVE"})
    h = _poller(P, [_doc(name="Shop [folder: Finance]", owners=_owner(ANA))], managed=managed)
    items = h.p.poll_and_ingest("inbox", "prog")
    assert list(items) == [] and items.skipped[0]["skip_code"] == IO.TARGET_FOLDER_NOT_MANAGED


def test_name_match_is_whole_name_not_substring(P):
    h = _poller(P, [_doc(name="Shop [folder: Fin]", owners=_owner(ANA))])
    assert h.p.poll_and_ingest("inbox", "prog").skipped[0]["skip_code"] == IO.TARGET_FOLDER_NOT_MANAGED


def test_disabled_managed_folder_is_not_a_target(P):
    managed = dict(MANAGED, folders_444555=dict(FINANCE, status="DISABLED"))
    h = _poller(P, [_doc(name="Shop [folder: 444555]", owners=_owner(ANA))], managed=managed)
    assert h.p.poll_and_ingest("inbox", "prog").skipped[0]["skip_code"] == IO.TARGET_FOLDER_NOT_MANAGED


def test_parent_folder_name_match_and_default(P):
    h = _poller(P, [_doc(owners=_owner(ANA))], meta={"inbox": {"name": "finance"}})
    assert h.p.poll_and_ingest("inbox", "prog")[0]["folder_id"] == "folders/444555"
    h = _poller(P, [_doc(owners=_owner(ANA))])  # parent '01_Inbox_Requests' matches nothing -> the default
    assert h.p.poll_and_ingest("inbox", "prog")[0]["folder_id"] == "folders/777000"


def test_owner_assignment_tier_must_be_managed(P):
    """Tier 2 is inactive on the poll path (routing never sees ``owners``); direct callers still get the check."""
    h = _poller(P)
    h.fs.data["users"] = {ANA: {"assigned_folder_id": "folders/999"}}
    with pytest.raises(IO.IntakeRejected) as ei:
        h.p.resolve_target_folder({"name": "x", "owners": _owner(ANA)})
    assert ei.value.code == IO.TARGET_FOLDER_NOT_MANAGED
    h.fs.data["users"] = {ANA: {"assigned_folder_id": "444555"}}
    assert h.p.resolve_target_folder({"name": "x", "owners": _owner(ANA)}) == "folders/444555"


def test_poll_routing_never_uses_the_owner_assignment(P):
    h = _poller(P, [_doc(owners=_owner(ANA))])
    h.fs.data["users"] = {ANA: {"assigned_folder_id": "folders/444555"}}
    assert h.p.poll_and_ingest("inbox", "prog")[0]["folder_id"] == "folders/777000"


@pytest.mark.parametrize("managed, env, outcome", [
    ({}, "123", "123"),                                                              # fresh install: env fallback
    ({"folders_444555": FINANCE}, "444555", "444555"),                               # env is a managed folder
    ({"folders_444555": FINANCE}, "folders/888", IO.TARGET_FOLDER_NOT_MANAGED),      # env not managed
    ({"folders_444555": FINANCE}, None, None),                                       # nothing configured: unchanged
])
def test_env_fallback_only_when_managed_or_fresh_install(P, monkeypatch, managed, env, outcome):
    if env is None:
        monkeypatch.delenv("MANAGED_WORKLOADS_FOLDER_ID", raising=False)
    else:
        monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", env)
    h = _poller(P, [_doc(owners=_owner(ANA))], managed=managed)
    items = h.p.poll_and_ingest("inbox", "prog")
    if outcome == IO.TARGET_FOLDER_NOT_MANAGED:
        assert list(items) == [] and items.skipped[0]["skip_code"] == outcome and h.pub.published == []
    else:
        assert items[0]["folder_id"] == outcome


# ---------------------------------------------------------------- 2. auto-discovery allow-list
def _discovery_drive(owner_a, owner_b):
    return FakeDrive(discovery=[{"id": "inbox-a", "parents": ["pa"], "owners": owner_a},
                                {"id": "inbox-b", "parents": ["pb"], "owners": owner_b}],
                     siblings={"pa": [{"id": "prog-a"}], "pb": [{"id": "prog-b"}]})


def test_discovery_ignores_an_outsider_inbox(P, monkeypatch):
    monkeypatch.delenv("INBOX_FOLDER_ID", raising=False)
    h = _poller(P, drive=_discovery_drive(_owner(ANA), _owner("mallory@outsider.example")))
    pairs = h.p.auto_discover_shared_folders()
    assert list(pairs) == [("inbox-a", "prog-a")]
    assert [(s["inbox_folder_id"], s["code"]) for s in pairs.skipped] == [("inbox-b", IO.INBOX_FOLDER_UNAUTHORIZED)]
    assert "owners(emailAddress, me)" in h.drive.list_calls[0][1]  # same listing call, owners in its fields


def test_discovery_keeps_the_configured_inbox(P, monkeypatch):
    monkeypatch.setenv("INBOX_FOLDER_ID", "inbox-b")
    h = _poller(P, drive=_discovery_drive(_owner("mallory@outsider.example"), _owner("mallory@outsider.example")))
    assert list(h.p.auto_discover_shared_folders()) == [("inbox-b", "prog-b")]


def test_discovery_with_store_unreadable_raises(P, monkeypatch):
    monkeypatch.delenv("INBOX_FOLDER_ID", raising=False)
    h = _poller(P, drive=_discovery_drive(_owner(ANA), _owner(ANA)), fail=("authorized_users",))
    with pytest.raises(IO.IntakeUnavailableError):
        h.p.auto_discover_shared_folders()


# ---------------------------------------------------------------- service endpoints with the real poller
@pytest.fixture
def svc(P, monkeypatch):
    monkeypatch.setitem(sys.modules, "poller", P)
    mod = _load(os.path.join(SPEC_DIR, "main.py"), "fd4as_spec_main")
    import shared.settings as spec_settings
    spec_settings.invalidate_settings_cache()
    monkeypatch.setattr(mod, "_refuse_intake_in_maintenance", lambda action: None)
    return mod


def _use(svc, h):
    svc.poller = h.p
    return h


def test_poll_endpoint_lists_typed_skips(P, svc, monkeypatch):
    monkeypatch.setenv("INBOX_FOLDER_ID", "inbox")
    monkeypatch.setenv("IN_PROGRESS_FOLDER_ID", "prog")
    monkeypatch.setattr(svc, "_auto_discovery_enabled", lambda: False)
    h = _use(svc, _poller(P, [_doc("doc-out", owners=_owner("mallory@outsider.example")),
                              _doc("doc-in", owners=_owner(ANA))]))
    out = svc.execute_poll()
    assert out["status"] == "SUCCESS" and out["ingested_count"] == 1 and out["skipped_count"] == 1
    assert out["skipped"][0]["skip_code"] == IO.SPEC_SUBMITTER_UNAUTHORIZED
    assert "owner_email" not in out["skipped"][0]  # the address stays in the audit record only
    assert _audit(h.fs, "doc-out")["last_skip"]["owner_email"] == "mallory@outsider.example"


def test_poll_endpoint_store_unreadable_is_503_with_nothing_moved(P, svc, monkeypatch):
    from fastapi import HTTPException
    monkeypatch.setenv("INBOX_FOLDER_ID", "inbox")
    monkeypatch.setenv("IN_PROGRESS_FOLDER_ID", "prog")
    monkeypatch.setattr(svc, "_auto_discovery_enabled", lambda: False)
    h = _use(svc, _poller(P, [_doc(owners=_owner(ANA))], fail=("authorized_users",)))
    with pytest.raises(HTTPException) as ei:
        svc.execute_poll()
    assert ei.value.status_code == 503 and ei.value.detail["code"] == IO.SPEC_INTAKE_UNAVAILABLE
    assert h.drive.moves == [] and h.pub.published == []


def test_request_supplied_outsider_inbox_is_not_polled(P, svc, monkeypatch):
    monkeypatch.setenv("INBOX_FOLDER_ID", "inbox")
    monkeypatch.setattr(svc, "_auto_discovery_enabled", lambda: False)
    drive = FakeDrive(listings={"evil": [_doc(owners=_owner(ANA))]},
                      meta={"evil": {"id": "evil", "owners": _owner("mallory@outsider.example")}})
    h = _use(svc, _poller(P, drive=drive))
    out = svc.execute_poll(svc.PollRequest(inbox_folder_id="evil", in_progress_folder_id="prog"))
    assert out["status"] == "IDLE" and out["skipped"][0]["code"] == IO.INBOX_FOLDER_UNAUTHORIZED
    assert drive.list_calls == [] and h.pub.published == []


def test_request_supplied_configured_or_authorized_inbox_polls(P, svc, monkeypatch):
    monkeypatch.setenv("INBOX_FOLDER_ID", "inbox")
    monkeypatch.setenv("IN_PROGRESS_FOLDER_ID", "p")  # RT F1: the in-progress folder is checked too (configured here)
    monkeypatch.setattr(svc, "_auto_discovery_enabled", lambda: False)
    drive = FakeDrive(listings={"inbox": [_doc("d1", owners=_owner(ANA))], "mine": [_doc("d2", owners=_owner(ANA))]},
                      meta={"inbox": {"name": "x"}, "mine": {"id": "mine", "name": "x", "owners": _owner(ANA)}})
    _use(svc, _poller(P, drive=drive))
    assert svc.execute_poll(svc.PollRequest(inbox_folder_id="inbox", in_progress_folder_id="p"))["ingested_count"] == 1
    assert svc.execute_poll(svc.PollRequest(inbox_folder_id="mine", in_progress_folder_id="p"))["ingested_count"] == 1


def test_ingest_doc_checks_the_drive_owner(P, svc):
    from fastapi import HTTPException
    # RT14-27: the single-document intake reads the doc's name (its product id) like the poll path does.
    drive = FakeDrive(meta={"d-out": {"name": "Shop", "owners": _owner("mallory@outsider.example")},
                            "d-in": {"name": "Shop", "owners": _owner(ANA)}})
    h = _use(svc, _poller(P, drive=drive))
    with pytest.raises(HTTPException) as ei:
        svc.ingest_single_document(svc.IngestDocRequest(document_id="d-out"))
    assert ei.value.status_code == 403 and ei.value.detail["code"] == IO.SPEC_SUBMITTER_UNAUTHORIZED
    assert h.pub.published == []
    with pytest.raises(HTTPException) as ei:
        svc.ingest_single_document(svc.IngestDocRequest(document_id="d-unknown"))  # Drive cannot answer
    assert ei.value.status_code == 503 and h.pub.published == []
    assert svc.ingest_single_document(svc.IngestDocRequest(document_id="d-in"))["status"] == "INGESTED"
    assert len(h.pub.published) == 1 and json.loads(h.pub.published[0][1])["spec_doc_id"] == "d-in"


# ---------------------------------------------------------------- Fable RT fixes (F1, F4-F8)
def test_rt_f1_request_supplied_outsider_in_progress_folder_is_not_used(P, svc, monkeypatch):
    """RT F1: documents are moved into the in-progress folder and inherit its sharing: outsider folder -> not used."""
    monkeypatch.setenv("INBOX_FOLDER_ID", "inbox")
    monkeypatch.setenv("IN_PROGRESS_FOLDER_ID", "prog")
    monkeypatch.setattr(svc, "_auto_discovery_enabled", lambda: False)
    drive = FakeDrive(listings={"inbox": [_doc("d1", owners=_owner(ANA))]},
                      meta={"inbox": {"name": "x"},
                            "evil-prog": {"id": "evil-prog", "owners": _owner("mallory@outsider.example")}})
    h = _use(svc, _poller(P, drive=drive))
    out = svc.execute_poll(svc.PollRequest(inbox_folder_id="inbox", in_progress_folder_id="evil-prog"))
    assert out["status"] == "IDLE" and out["skipped"][0]["code"] == IO.IN_PROGRESS_FOLDER_UNAUTHORIZED
    assert out["skipped"][0]["in_progress_folder_id"] == "evil-prog"
    assert drive.moves == [] and drive.list_calls == [] and h.pub.published == []


def test_rt_f1_configured_or_authorized_in_progress_folder_still_polls(P, svc, monkeypatch):
    monkeypatch.setenv("INBOX_FOLDER_ID", "inbox")
    monkeypatch.setenv("IN_PROGRESS_FOLDER_ID", "prog")
    monkeypatch.setattr(svc, "_auto_discovery_enabled", lambda: False)
    # RT14 RT F4: one document per workload id per poll, so the two documents name two workloads
    drive = FakeDrive(listings={"inbox": [_doc("d1", owners=_owner(ANA)),
                                          _doc("d2", "NEW_PRODUCT_SPEC: Shop Two", owners=_owner(ANA))]},
                      meta={"inbox": {"name": "x"}, "mine": {"id": "mine", "owners": _owner(ANA)}})
    h = _use(svc, _poller(P, drive=drive))
    assert svc.execute_poll(svc.PollRequest(inbox_folder_id="inbox", in_progress_folder_id="prog"))["ingested_count"] == 2
    assert drive.moves[-1][2] == "prog"
    h.drive.listings["inbox"] = [_doc("d3", owners=_owner(ANA))]
    assert svc.execute_poll(svc.PollRequest(inbox_folder_id="inbox", in_progress_folder_id="mine"))["ingested_count"] == 1
    assert drive.moves[-1] == ("d3", "inbox", "mine")


def test_rt_f4_skip_never_overwrites_an_earlier_ingestion_audit_and_is_not_rewritten(P):
    h = _poller(P, [_doc(owners=_owner(ANA))])
    assert len(h.p.poll_and_ingest("inbox", "prog")) == 1
    ingested = dict(_audit(h.fs, "doc-1"))
    assert ingested["pubsub_message_id"] == "msg-1"
    h.fs.data["authorized_users"][ANA] = dict(USERS[ANA], is_active=False)  # owner deactivated; doc back in inbox
    for _ in range(3):
        items = h.p.poll_and_ingest("inbox", "prog")
        assert items.skipped[0]["skip_code"] == IO.SPEC_SUBMITTER_UNAUTHORIZED
    audit = _audit(h.fs, "doc-1")
    assert {k: audit[k] for k in ingested} == ingested  # trace_id, pubsub_message_id, ... intact
    assert audit["last_skip"]["skip_code"] == IO.SPEC_SUBMITTER_UNAUTHORIZED
    skip_writes = [w for w in h.fs.writes if w[0] == "spec_ingestions" and "last_skip" in w[2]]
    assert len(skip_writes) == 1 and skip_writes[0][3] is True  # merge, written once for three identical polls


def test_rt_f5_non_ascii_owner_address_is_refused(P):
    h = _poller(P, [_doc(owners=_owner("Kim@example.com"))], users={"kim@example.com": {"role": "ADMIN"}})
    items = h.p.poll_and_ingest("inbox", "prog")
    assert list(items) == [] and "not a valid" in items.skipped[0]["skip_reason"]


@pytest.mark.parametrize("status, code", [(404, 403), (403, 403), (500, 503)])
def test_rt_f6_drive_http_403_404_is_a_refusal_not_unavailable(P, svc, status, code):
    from fastapi import HTTPException
    h = _use(svc, _poller(P, drive=FakeDrive(meta={"d-x": status})))
    with pytest.raises(HTTPException) as ei:
        svc.ingest_single_document(svc.IngestDocRequest(document_id="d-x"))
    assert ei.value.status_code == code and h.pub.published == []


def test_rt_f7_two_default_managed_folders_are_ambiguous(P):
    managed = dict(MANAGED, folders_1={"folder_id": "folders/1", "display_name": "Other", "status": "ACTIVE",
                                       "is_default": True})
    h = _poller(P, [_doc(owners=_owner(ANA))], managed=managed)
    items = h.p.poll_and_ingest("inbox", "prog")
    assert list(items) == [] and h.drive.moves == []
    assert items.skipped[0]["skip_code"] == IO.TARGET_FOLDER_NOT_MANAGED and "default" in items.skipped[0]["skip_reason"]


def test_rt_f8b_webhook_refuses_an_outsider_doc(P, svc, monkeypatch):
    monkeypatch.setenv("INBOX_FOLDER_ID", "inbox")
    monkeypatch.setenv("IN_PROGRESS_FOLDER_ID", "prog")
    monkeypatch.setattr(svc, "_auto_discovery_enabled", lambda: False)
    h = _use(svc, _poller(P, [_doc("d-out", owners=_owner("mallory@outsider.example"))]))
    out = svc.handle_drive_push_notification()
    assert out == {"status": "PROCESSED", "ingested_count": 0, "skipped_count": 1}
    assert h.drive.moves == [] and h.pub.published == []


def test_rt_f8c_configured_inbox_exemption_is_folder_only(P, svc, monkeypatch):
    """Discovery keeps an outsider-owned configured inbox, but its outsider document is still refused."""
    monkeypatch.setenv("INBOX_FOLDER_ID", "inbox-b")
    monkeypatch.setattr(svc, "_auto_discovery_enabled", lambda: True)
    drive = _discovery_drive(_owner("mallory@outsider.example"), _owner("mallory@outsider.example"))
    drive.listings = {"inbox-b": [_doc("d-out", owners=_owner("mallory@outsider.example")),
                                  _doc("d-in", owners=_owner(ANA))]}
    drive.meta = {"inbox-b": {"name": "01_Inbox_Requests"}}
    h = _use(svc, _poller(P, drive=drive))
    out = svc.execute_poll()
    assert [i["spec_doc_id"] for i in out["items"]] == ["d-in"]
    codes = {(s.get("spec_doc_id") or s.get("inbox_folder_id")): s.get("skip_code") or s.get("code")
             for s in out["skipped"]}
    assert codes == {"inbox-a": IO.INBOX_FOLDER_UNAUTHORIZED, "d-out": IO.SPEC_SUBMITTER_UNAUTHORIZED}
    assert h.drive.moves == [("d-in", "inbox-b", "prog-b")]


def test_rt_f8d_discovered_inbox_owned_by_the_service_account_is_refused(P, monkeypatch):
    monkeypatch.delenv("INBOX_FOLDER_ID", raising=False)
    h = _poller(P, drive=_discovery_drive(_owner("svc@proj.iam.gserviceaccount.com", me=True), _owner(ANA)))
    pairs = h.p.auto_discover_shared_folders()
    assert list(pairs) == [("inbox-b", "prog-b")] and pairs.skipped[0]["inbox_folder_id"] == "inbox-a"
