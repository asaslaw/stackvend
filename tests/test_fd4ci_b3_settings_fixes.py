"""FD-4CI-b items (6), (8), (9-10) (register row FD-4CI-b, owner 10-21: "fix, never remove").

(6)    Drive discovery polls the discovered inboxes AND the configured inbox pair (one inbox polled once).
(8)    The region and the global plan-approval labels on the Settings page say exactly what they do.
(9-10) VCS setup hints name the secret the services read; Switch Default VCS saves only the VCS field; user
       grant / change / revoke are audited; the legacy APPROVER role is stored as what authorization gives it
       (WORKLOAD_MANAGER, no new powers); the GCP folder labels name the managed workloads root; the create form's
       "Platform Default" breach policy is accepted and resolves to the platform default end to end.
Hermetic: in-memory fakes only (no Firestore, no network).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import base64
import copy
import importlib.util
import json
import os
import re
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(TESTS, ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
SPEC_DIR = os.path.join(REPO_ROOT, "apps", "spec-ingestion")
DASHBOARD = os.path.join(CC_DIR, "templates", "dashboard.html")
SETTINGS_REF = os.path.join(REPO_ROOT, "documentation", "settings-reference.md")
for p in (TESTS, REPO_ROOT, SPEC_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import settings as S  # noqa: E402
from test_l19_11_access_intake import cc  # noqa: F401,E402  (cc: fixture)
from test_fd4cu_freeze_new_workloads import _create  # noqa: E402


def _html() -> str:
    with open(DASHBOARD, encoding="utf-8") as f:
        return f.read()


def _ref() -> str:
    with open(SETTINGS_REF, encoding="utf-8") as f:
        return f.read()


def _known_gaps() -> str:
    return _ref().split("## Known gaps between the page and the platform", 1)[1]


# ============================================================================================ (6) Drive discovery
@pytest.fixture
def spec(monkeypatch):
    fake = MagicMock()
    fake.auto_discover_shared_folders.return_value = []
    fake.poll_and_ingest.return_value = []
    fake.inbox_folder_refusal.return_value = None
    fake.in_progress_folder_refusal.return_value = None
    monkeypatch.setitem(sys.modules, "poller", SimpleNamespace(SpecIngestionPoller=lambda: fake))
    mod_spec = importlib.util.spec_from_file_location("fd4ci_b3_spec_main", os.path.join(SPEC_DIR, "main.py"))
    mod = importlib.util.module_from_spec(mod_spec)
    mod_spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "_refuse_intake_in_maintenance", lambda action: None)
    monkeypatch.setenv("INBOX_FOLDER_ID", "inbox-cfg")
    monkeypatch.setenv("IN_PROGRESS_FOLDER_ID", "prog-cfg")
    return SimpleNamespace(mod=mod, poller=fake)


def _discovery(spec, monkeypatch, on):
    monkeypatch.setattr(spec.mod, "_auto_discovery_enabled", lambda: on)


def _polled(spec):
    return [c.args for c in spec.poller.poll_and_ingest.call_args_list]


def test_discovery_off_polls_only_the_configured_pair(spec, monkeypatch):
    """Negative: discovery off -> exactly the configured pair; Drive is never searched (as before)."""
    _discovery(spec, monkeypatch, False)
    spec.poller.auto_discover_shared_folders.return_value = [("inbox-a", "prog-a")]
    out = spec.mod.execute_poll()
    spec.poller.auto_discover_shared_folders.assert_not_called()
    assert _polled(spec) == [("inbox-cfg", "prog-cfg")] and out["shared_folders_discovered"] == 1


@pytest.mark.parametrize("call", ["poll", "webhook"])
def test_discovery_on_polls_the_configured_pair_and_every_discovered_inbox(spec, monkeypatch, call):
    _discovery(spec, monkeypatch, True)
    spec.poller.auto_discover_shared_folders.return_value = [("inbox-a", "prog-a"), ("inbox-b", "prog-b")]
    {"poll": spec.mod.execute_poll, "webhook": spec.mod.handle_drive_push_notification}[call]()
    assert _polled(spec) == [("inbox-cfg", "prog-cfg"), ("inbox-a", "prog-a"), ("inbox-b", "prog-b")]


def test_an_inbox_both_configured_and_discovered_is_polled_once_with_the_configured_progress_folder(spec, monkeypatch):
    _discovery(spec, monkeypatch, True)
    spec.poller.auto_discover_shared_folders.return_value = [("inbox-a", "prog-a"), ("inbox-cfg", "prog-sibling"),
                                                             ("inbox-a", "prog-a")]
    out = spec.mod.execute_poll()
    assert _polled(spec) == [("inbox-cfg", "prog-cfg"), ("inbox-a", "prog-a")]
    assert out["shared_folders_discovered"] == 2


def test_discovery_on_without_a_configured_pair_polls_the_discovered_inboxes(spec, monkeypatch):
    monkeypatch.delenv("INBOX_FOLDER_ID")
    monkeypatch.delenv("IN_PROGRESS_FOLDER_ID")
    _discovery(spec, monkeypatch, True)
    spec.poller.auto_discover_shared_folders.return_value = [("inbox-a", "prog-a")]
    spec.mod.execute_poll()
    assert _polled(spec) == [("inbox-a", "prog-a")]


def test_discovery_on_and_nothing_found_still_polls_the_configured_pair(spec, monkeypatch):
    _discovery(spec, monkeypatch, True)
    spec.mod.execute_poll()
    assert _polled(spec) == [("inbox-cfg", "prog-cfg")]


def test_refused_request_inbox_is_skipped_and_the_discovered_inboxes_still_polled(spec, monkeypatch):
    """FD-4AS owner check unchanged: a request-supplied inbox owned by nobody authorized is not polled."""
    _discovery(spec, monkeypatch, True)
    spec.poller.inbox_folder_refusal.return_value = "owner is not an authorized submitter"
    spec.poller.auto_discover_shared_folders.return_value = [("inbox-a", "prog-a")]
    out = spec.mod.execute_poll(spec.mod.PollRequest(inbox_folder_id="inbox-x", in_progress_folder_id="prog-x"))
    assert _polled(spec) == [("inbox-a", "prog-a")]
    assert [s["code"] for s in out["skipped"]] == ["INBOX_FOLDER_UNAUTHORIZED"]


def test_discovery_refusals_are_still_reported(spec, monkeypatch):
    class _Found(list):
        skipped = [{"inbox_folder_id": "inbox-z", "code": "INBOX_FOLDER_UNAUTHORIZED", "reason": "not a submitter"}]
    _discovery(spec, monkeypatch, True)
    spec.poller.auto_discover_shared_folders.return_value = _Found([("inbox-a", "prog-a")])
    out = spec.mod.execute_poll()
    assert _polled(spec) == [("inbox-cfg", "prog-cfg"), ("inbox-a", "prog-a")]
    assert out["skipped"] == _Found.skipped


def test_docs_describe_the_combined_polling():
    assert "Drive Folder Auto-Discovery" not in _known_gaps()
    assert "The configured inbox and in-progress folders are still polled as well" in _ref()


# ============================================================================================ (8) labels
def test_region_label_says_it_is_the_region_of_every_workload():
    html = _html()
    assert "Default GCP Region" not in html
    i = html.index('x-model="platformSettings.orchestration.default_gcp_region"')
    block = html[i - 300:i + 600]
    # FD-7M-a (owner 10-31): a workload now keeps its own region; this setting is the default (and the region of
    # workloads created before approved regions).
    assert "Default Workload Region" in block
    assert "the region of every workload created before approved regions" in block
    assert "#### Default Workload Region" in _ref()


def test_global_plan_approval_label_says_every_run_of_every_workload():
    html = _html()
    assert "Require Plan Approval Before Development (Architect HITL Gate)" not in html
    i = html.index('x-model="platformSettings.governance.require_plan_approval"')
    block = html[i:i + 1200]
    assert "Require Plan Approval for Every Run of Every Workload (Architect HITL Gate)" in block
    for phrase in ("every Agent-mode build of every workload, existing ones included, that reaches the compliance step",
                   "a resumed run keeps the decision it already had", "pre-ticks Plan approval on the create form",
                   "whatever the workload's own Plan approval setting"):
        assert phrase in block, phrase
    assert "#### Require Plan Approval for Every Run of Every Workload (Architect HITL Gate)" in _ref()


def test_plan_approval_policy_options_match_the_gate():
    html = _html()
    i = html.index('x-model="platformSettings.governance.plan_approval_policy"')
    block = html[i:i + 1500]
    assert "Org Policy conflicts/violations only" not in block   # advisories also pause with strict gates on
    assert "compliance advisories never pause" in block and "every plan of every workload waits" in block


def test_the_global_switch_is_what_the_gate_reads():
    """The label claims 'every run of every workload': the compliance gate reads exactly that switch first."""
    src = open(os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "compliance_agent", "handler.py"),
               encoding="utf-8").read()
    gate = src.split("def _determine_approval_requirement", 1)[1].split("\n    def ", 1)[0]
    assert 'if getattr(gov, "require_plan_approval", False):\n                return True' in gate


# ============================================================================================ (9-10) VCS hints
def test_vcs_hints_name_the_json_secret_the_services_read():
    html = _html()
    assert "castor-github-token" not in html
    assert "gcloud secrets create castor-github-app-private-key" not in html   # the install creates it (empty)
    assert "gcloud secrets versions add castor-github-app-private-key --data-file=github-credentials.json" in html
    for key in ('"app_id"', '"installation_id"', '"private_key"'):
        assert key in html, key
    # GITHUB-ORG-ONLY (owner 11-12): no personal-access-token option is offered (tests/test_github_org_only.py)
    assert '"pat"' not in html
    gaps = _known_gaps()
    assert "VCS card setup hints" not in gaps and "Switch Default VCS" not in gaps


def test_the_secret_name_in_the_hint_is_the_one_the_token_manager_reads():
    src = open(os.path.join(REPO_ROOT, "shared", "github_resilience.py"), encoding="utf-8").read()
    assert "/secrets/castor-github-app-private-key/versions/latest" in src
    for key in ('data.get("app_id")', 'data.get("installation_id"', 'data.get("private_key"', 'data.get("pat")'):
        assert key in src, key


# ============================================================================================ (9-10) Switch VCS
class _SettingsDoc:
    def __init__(self, data):
        self.exists, self._data = data is not None, data

    def to_dict(self):
        return copy.deepcopy(self._data)


class _SettingsStore:
    def __init__(self, data=None, fail=False):
        self.data, self.fail = data, fail

    def collection(self, name):
        return self

    def document(self, name):
        return self

    def get(self):
        if self.fail:
            raise RuntimeError("firestore down")
        return _SettingsDoc(self.data)


STORED = {
    "finops": {"default_monthly_budget_usd": 75.0, "default_breach_policy": "ALERT_ONLY"},
    "orchestration": {"default_gcp_region": "europe-west1"},
    "governance": {"vcs_provider": "GITHUB", "require_plan_approval": True, "maintenance_mode": False},
    "version": 7,
}


@pytest.fixture
def vcs(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    monkeypatch.setattr(cc_db, "_db_client", False)
    from routes import settings as rs
    cc_store = MagicMock()
    doc_ref = MagicMock()
    cc_store.collection.return_value.document.return_value = doc_ref
    monkeypatch.setattr(rs, "db", cc_store)
    from settings_write_fake import wire_settings_writes
    writes = wire_settings_writes(cc_store, doc_ref)   # FD-4CI-b-3a: preconditioned write
    store = _SettingsStore(copy.deepcopy(STORED))
    monkeypatch.setattr("google.cloud.firestore.Client", lambda *a, **k: store)

    def invalidate():
        for name in ("shared.settings", "shared_settings"):
            mod = sys.modules.get(name)
            if mod is not None and hasattr(mod, "invalidate_settings_cache"):
                mod.invalidate_settings_cache()
    invalidate()
    yield SimpleNamespace(rs=rs, doc_ref=doc_ref, store=store, writes=writes)
    invalidate()


def _admin(rs, role=None):
    request = MagicMock()
    request.state.user_role, request.state.user_email = role or rs.UserRole.ADMIN, "admin@example.com"
    return request


def _stored_now(rs):
    """The current stored document as the strict reader validates it (the comparison base)."""
    return rs._get_current_platform_settings(force_refresh=True, project_id=rs.PROJECT_ID, strict=True).model_dump()


def test_switch_vcs_changes_only_the_vcs_field(vcs):
    rs = vcs.rs
    before = _stored_now(rs)
    out = rs.switch_vcs_provider_api(rs.SwitchVcsProviderRequest(vcs_provider="SERVERLESS_GIT"), _admin(rs))
    (stored,), kw = vcs.doc_ref.set.call_args
    assert kw == {"merge": False}
    assert stored["governance"]["vcs_provider"] == "SERVERLESS_GIT" and out.governance.vcs_provider == "SERVERLESS_GIT"
    for section in ("finops", "orchestration", "models", "runtimes"):
        assert stored[section] == before[section], section
    gov_before = dict(before["governance"], vcs_provider="SERVERLESS_GIT")
    assert stored["governance"] == gov_before
    assert stored["version"] == 8 and stored["updated_by"] == "admin@example.com"
    entry = stored["audit_log"][0]
    assert entry["action"] == "UPDATE_SETTINGS" and entry["admin_email"] == "admin@example.com"
    assert entry["changed_fields"] == {"governance.vcs_provider": {"from": "GITHUB", "to": "SERVERLESS_GIT"}}


def test_switch_vcs_with_a_dirty_parameters_form_saves_only_the_vcs_field(vcs):
    """Negative: whatever else a client sends (the unsaved Parameters form) is not part of the request model."""
    rs = vcs.rs
    before = _stored_now(rs)
    dirty = {"vcs_provider": "SERVERLESS_GIT", "finops": {"default_monthly_budget_usd": 999.0},
             "orchestration": {"default_gcp_region": "asia-east1"}, "governance": {"require_plan_approval": False}}
    rs.switch_vcs_provider_api(rs.SwitchVcsProviderRequest(**dirty), _admin(rs))
    (stored,), _ = vcs.doc_ref.set.call_args
    assert stored["finops"] == before["finops"] and stored["orchestration"] == before["orchestration"]
    assert stored["governance"]["require_plan_approval"] is True


def test_the_page_sends_only_the_vcs_field_and_keeps_the_form_unsaved():
    html = _html()
    fn = html.split("async toggleDefaultVcsProvider(newProvider) {", 1)[1].split("\n                },", 1)[0]
    assert "savePlatformSettings" not in fn and "'/api/settings/vcs-provider'" in fn
    assert "body: JSON.stringify({ vcs_provider: newProvider })" in fn
    # only the switched field and the bookkeeping fields are copied back into the (possibly dirty) form
    assert "for (const k of ['version', 'updated_at', 'updated_by', 'audit_log'])" in fn


def test_switch_vcs_is_refused_when_the_stored_settings_are_invalid(vcs):
    rs = vcs.rs
    from fastapi import HTTPException
    vcs.store.data = {"governance": {"plan_approval_policy": "BOGUS"}}
    with pytest.raises(HTTPException) as ei:
        rs.switch_vcs_provider_api(rs.SwitchVcsProviderRequest(vcs_provider="SERVERLESS_GIT"), _admin(rs))
    assert ei.value.status_code == 409 and "Repair them" in ei.value.detail["message"]
    vcs.doc_ref.set.assert_not_called()


def test_switch_vcs_is_refused_when_the_settings_cannot_be_read(vcs):
    rs = vcs.rs
    from fastapi import HTTPException
    vcs.store.fail = True
    with pytest.raises(HTTPException) as ei:
        rs.switch_vcs_provider_api(rs.SwitchVcsProviderRequest(vcs_provider="SERVERLESS_GIT"), _admin(rs))
    assert ei.value.status_code == 503
    vcs.doc_ref.set.assert_not_called()


def test_switch_vcs_is_admin_only_and_takes_known_providers_only(vcs):
    rs = vcs.rs
    from fastapi import HTTPException
    from pydantic import ValidationError
    for role in [r for r in rs.UserRole if r != rs.UserRole.ADMIN]:
        with pytest.raises(HTTPException) as ei:
            rs.switch_vcs_provider_api(rs.SwitchVcsProviderRequest(vcs_provider="GITHUB"), _admin(rs, role))
        assert ei.value.status_code == 403
    for bad in ("GITLAB", "github", "", None):
        with pytest.raises(ValidationError):
            rs.SwitchVcsProviderRequest(vcs_provider=bad)
    vcs.doc_ref.set.assert_not_called()
    src = open(os.path.join(CC_DIR, "routes", "settings.py"), encoding="utf-8").read()
    assert '@router.put("/api/settings/vcs-provider", response_model=PlatformSettings, dependencies=[require(ADMIN)])' in src


# ============================================================================================ (9-10) users audit
class _USnap:
    def __init__(self, data):
        self.exists, self._data = data is not None, copy.deepcopy(data)

    def to_dict(self):
        return copy.deepcopy(self._data)


class _URef:
    def __init__(self, db, path):
        self.db, self.path, self.id = db, path, path.rsplit("/", 1)[-1]

    def get(self):
        if self.db.fail_reads:
            raise RuntimeError("read failed")
        return _USnap(self.db.docs.get(self.path))

    def set(self, data, merge=False):
        base = dict(self.db.docs.get(self.path) or {}) if merge else {}
        base.update(copy.deepcopy(data))
        self.db.docs[self.path] = base

    def delete(self):
        self.db.docs.pop(self.path, None)


class _UCol:
    def __init__(self, db, name):
        self.db, self.name = db, name

    def document(self, doc_id=None):
        if doc_id is None:
            self.db.auto += 1
            doc_id = f"auto{self.db.auto}"
        return _URef(self.db, f"{self.name}/{doc_id}")


class _UBatch:
    def __init__(self, db):
        self.db, self.ops = db, []

    def set(self, ref, data, merge=False):
        self.ops.append(lambda: ref.set(data, merge=merge))

    def delete(self, ref):
        self.ops.append(ref.delete)

    def commit(self):
        if self.db.fail_commit:  # True = an untyped error; an exception instance (FD-4CI-b-3d) is raised as is
            raise (self.db.fail_commit if isinstance(self.db.fail_commit, BaseException)
                   else RuntimeError("commit failed"))
        for op in self.ops:
            op()


class _UDB:
    def __init__(self, docs=None):
        self.docs, self.auto, self.fail_commit, self.fail_reads = dict(docs or {}), 0, False, False

    def collection(self, name):
        return _UCol(self, name)

    def batch(self):
        return _UBatch(self)

    def audit(self):
        return [v for k, v in sorted(self.docs.items()) if k.startswith("user_access_audit/")]


@pytest.fixture
def users(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    monkeypatch.setattr(cc_db, "_db_client", False)
    import schemas
    from routes import users as ru
    fake = _UDB({"authorized_users/old@example.com": {"email": "old@example.com", "role": "VIEWER",
                                                       "assigned_workloads": ["a"], "added_at": "2026-01-01",
                                                       "is_active": True}})
    monkeypatch.setattr(ru, "db", fake)
    monkeypatch.setattr(ru, "DEFAULT_ADMIN_EMAIL", "owner@example.com")
    monkeypatch.setattr(ru, "MOCK_AUTHORIZED_USERS", {})
    req = MagicMock()
    req.state.user_role, req.state.user_email = schemas.UserRole.ADMIN, "admin@example.com"
    return SimpleNamespace(ru=ru, schemas=schemas, db=fake, req=req)


def test_grant_is_audited_with_before_and_after(users):
    ru, s = users.ru, users.schemas
    ru.add_approved_user(s.AddUserRequest(email="New@Example.com", role="WORKLOAD_MANAGER", assigned_workloads=["w1"]),
                         users.req)
    assert users.db.docs["authorized_users/new@example.com"]["role"] == "WORKLOAD_MANAGER"
    (entry,) = users.db.audit()
    assert entry["action"] == "USER_ACCESS_GRANTED" and entry["email"] == "new@example.com"
    assert entry["operator_email"] == "admin@example.com" and entry["timestamp"]
    assert entry["before"] is None
    assert entry["after"] == {"role": "WORKLOAD_MANAGER", "is_active": True, "assigned_workloads": ["w1"]}


def test_re_grant_of_an_existing_user_records_the_previous_access(users):
    ru, s = users.ru, users.schemas
    ru.add_approved_user(s.AddUserRequest(email="old@example.com", role="ADMIN"), users.req)
    (entry,) = users.db.audit()
    assert entry["before"] == {"role": "VIEWER", "is_active": True, "assigned_workloads": ["a"]}
    assert entry["after"]["role"] == "ADMIN" and entry["after"]["assigned_workloads"] == []


def test_role_change_is_audited(users):
    ru, s = users.ru, users.schemas
    ru.update_user_workloads("old@example.com", s.UpdateUserWorkloadsRequest(assigned_workloads=["a", "b"],
                                                                             role="WORKLOAD_MANAGER"), users.req)
    (entry,) = users.db.audit()
    assert entry["action"] == "USER_ACCESS_UPDATED"
    assert entry["before"]["role"] == "VIEWER" and entry["after"] == {"role": "WORKLOAD_MANAGER", "is_active": True,
                                                                      "assigned_workloads": ["a", "b"]}


def test_revoke_is_audited_and_removes_the_user(users):
    ru = users.ru
    out = ru.remove_approved_user("Old@Example.com", users.req)
    assert out["status"] == "REMOVED" and "authorized_users/old@example.com" not in users.db.docs
    (entry,) = users.db.audit()
    assert entry["action"] == "USER_ACCESS_REVOKED" and entry["email"] == "old@example.com"
    assert entry["before"] == {"role": "VIEWER", "is_active": True, "assigned_workloads": ["a"]}
    assert entry["after"] is None


def test_revoking_the_platform_owner_is_refused_and_writes_no_audit(users):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        users.ru.remove_approved_user("owner@example.com", users.req)
    assert ei.value.status_code == 400 and users.db.audit() == []


def test_change_and_audit_entry_land_together_or_not_at_all(users):
    ru, s = users.ru, users.schemas
    from fastapi import HTTPException
    users.db.fail_commit = True
    with pytest.raises(HTTPException) as ei:  # FD-4CI-b-3b: typed 503 (before: the raw error, an untyped 500)
        ru.update_user_workloads("old@example.com", s.UpdateUserWorkloadsRequest(assigned_workloads=["z"]), users.req)
    assert ei.value.status_code == 503
    assert users.db.docs["authorized_users/old@example.com"]["assigned_workloads"] == ["a"] and users.db.audit() == []


def test_an_unreadable_record_never_blocks_a_revoke(users):
    users.db.fail_reads = True
    users.ru.remove_approved_user("old@example.com", users.req)
    assert "authorized_users/old@example.com" not in users.db.docs
    (entry,) = users.db.audit()
    assert entry["before_unreadable"] is True and entry["before"] is None


def test_non_admins_cannot_grant_or_revoke(users):
    from fastapi import HTTPException
    ru, s = users.ru, users.schemas
    for role in (s.UserRole.WORKLOAD_MANAGER, s.UserRole.VIEWER):
        users.req.state.user_role = role
        with pytest.raises(HTTPException):
            ru.add_approved_user(s.AddUserRequest(email="x@example.com", role="ADMIN"), users.req)
        with pytest.raises(HTTPException):
            ru.remove_approved_user("old@example.com", users.req)
    assert users.db.audit() == [] and "authorized_users/old@example.com" in users.db.docs


@pytest.mark.parametrize("path", ["grant", "update"])
def test_legacy_approver_is_stored_as_workload_manager_on_every_path(users, path):
    """APPROVER keeps exactly what authorization gives it (WORKLOAD_MANAGER); before, the update path stored the raw
    "APPROVER" while the grant path stored WORKLOAD_MANAGER."""
    ru, s = users.ru, users.schemas
    if path == "grant":
        rec = ru.add_approved_user(s.AddUserRequest(email="old@example.com", role="APPROVER"), users.req)
    else:
        rec = ru.update_user_workloads("old@example.com",
                                       s.UpdateUserWorkloadsRequest(assigned_workloads=["a"], role="APPROVER"),
                                       users.req)
    assert rec.role == s.UserRole.WORKLOAD_MANAGER
    assert users.db.docs["authorized_users/old@example.com"]["role"] == "WORKLOAD_MANAGER"
    assert users.db.audit()[0]["after"]["role"] == "WORKLOAD_MANAGER"


def test_approver_gets_no_new_powers(users):
    s = users.schemas
    rec = s.UserAccessRecord(email="a@example.com", role="APPROVER", added_at="2026-01-01")
    assert rec.role == s.UserRole.WORKLOAD_MANAGER
    assert users.ru._stored_role(s.UserRole.APPROVER) == "WORKLOAD_MANAGER"
    for role in ("ADMIN", "WORKLOAD_MANAGER", "VIEWER"):
        assert users.ru._stored_role(role) == role
    html = _html()
    form = html.split('<select x-model="newUserRole"', 1)[1].split("</select>", 1)[0]
    assert re.findall(r'<option value="([A-Z_]+)"', form) == ["ADMIN", "WORKLOAD_MANAGER", "VIEWER"]


def test_access_control_docs_describe_the_audit():
    ref = _ref()
    assert "Changes are logged to the Control Center logs, not to the settings audit history." not in ref
    assert "`user_access_audit`" in ref and "stores it as `WORKLOAD_MANAGER`" in ref


# ============================================================================================ (9-10) folder label
def test_folder_labels_name_the_managed_workloads_root():
    html = _html()
    assert "castorworkload" not in html and "created under organization root" not in html
    assert '<option value="">Managed workloads root folder</option>' in html
    src = open(os.path.join(CC_DIR, "routes", "settings.py"), encoding="utf-8").read()
    assert "castorworkload" not in src and 'display_name="Managed workloads root folder"' in src


# ============================================================================================ (10) Platform Default
def test_create_schema_empty_breach_policy_means_platform_default(cc):
    from pydantic import ValidationError
    schemas, _ = cc
    assert schemas.CreateWorkloadRequest(product_id="p", budget_breach_policy="").budget_breach_policy is None
    assert schemas.CreateWorkloadRequest(product_id="p").budget_breach_policy is None
    assert schemas.CreateWorkloadRequest(product_id="p", budget_breach_policy="ALERT_ONLY").budget_breach_policy.value \
        == "ALERT_ONLY"
    for bad in ("alert_only", "BOGUS", " ", "PLATFORM_DEFAULT"):   # negative: only "" means unset
        with pytest.raises(ValidationError):
            schemas.CreateWorkloadRequest(product_id="p", budget_breach_policy=bad)


def _platform(policy):
    return S.PlatformSettings(finops={"default_breach_policy": policy})


@pytest.mark.parametrize("body", [{"budget_breach_policy": ""}, {}])
def test_platform_default_is_accepted_and_stores_the_platform_policy(cc, monkeypatch, body):
    _, wl = cc
    r, fake_db, _ = _create(wl, monkeypatch, _platform("HITL_CONFIRMATION_REQUIRED"), body=body)
    assert r.status_code == 200, r.text
    stored = fake_db["workloads/shop-app"]["budget_breach_policy"]
    assert stored == "HITL_CONFIRMATION_REQUIRED" and type(stored) is str


def test_an_explicit_breach_policy_is_kept(cc, monkeypatch):
    _, wl = cc
    r, fake_db, _ = _create(wl, monkeypatch, _platform("HITL_CONFIRMATION_REQUIRED"),
                            body={"budget_breach_policy": "NUCLEAR_UNLINK_BILLING"})
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["budget_breach_policy"] == "NUCLEAR_UNLINK_BILLING"


def test_platform_default_reaches_the_budget_enforcer(cc, monkeypatch):
    """End to end: the create form's Platform Default -> stored platform policy -> the enforcer gets that policy."""
    _, wl = cc
    r, fake_db, _ = _create(wl, monkeypatch, _platform("ALERT_ONLY"), body={"budget_breach_policy": ""})
    assert r.status_code == 200, r.text
    record = dict(fake_db["workloads/shop-app"], project_id="shop-app-child", budget_ceiling_monthly_usd=50.0)

    from routes import approvals, finops
    snap = SimpleNamespace(id="shop-app", exists=True, to_dict=lambda: copy.deepcopy(record))
    db = MagicMock()
    db.collection.return_value.document.return_value.get.return_value = snap
    enforcer = MagicMock()
    enforcer.quarantine_workload.return_value = {"status": "ALERTED"}
    monkeypatch.setattr(finops, "db", db)
    monkeypatch.setattr(approvals, "get_finops_enforcer", lambda: enforcer)
    data = base64.b64encode(json.dumps({"budgetDisplayName": "budget-shop-app", "costAmount": 60.0}).encode()).decode()
    monkeypatch.setenv("BILLING_ACCOUNT_ID", "01ABCD-234567-89EF01")   # C10: install billing account check
    envelope = finops.PubSubAlertEnvelope(message=finops.PubSubAlertMessage(
        data=data, attributes={"billingAccountId": "01ABCD-234567-89EF01"}))
    out = finops.billing_alert_webhook(envelope, MagicMock())
    assert out["status"] == "QUARANTINE_EXECUTED"
    assert enforcer.quarantine_workload.call_args.kwargs["policy"] == "ALERT_ONLY"
