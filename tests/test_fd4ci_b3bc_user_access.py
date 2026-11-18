"""FD-4CI-b-3b / FD-4CI-b-3c (proposed rows, pending owner approval) and the fd-4ci-b-3 review follow-ups.

3b: a user access write (grant, role / workload change, revoke) that Firestore did not store answers 503 with a typed
    detail (code USER_ACCESS_NOT_STORED) instead of claiming success. Success paths are unchanged.
3c: GET /api/users/access-audit (ADMIN only) returns the last 50 ``user_access_audit`` entries, newest first, with only
    the known fields; the Access Control tab shows them.
Review follow-ups: the global plan-approval help text is qualified; the VCS switch (and grant / revoke) show a FastAPI
validation list as its msg values; the in-memory update path stores APPROVER as WORKLOAD_MANAGER.
Hermetic: in-memory fakes only (no Firestore, no network).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from test_fd4ci_b3_settings_fixes import (  # noqa: E402
    REPO_ROOT, _UCol, _UDB, _URef, _html, _ref, users,  # noqa: F401  (users: fixture)
)

AUDIT = "user_access_audit"


class _AuditQuery:
    """order_by(field, direction="DESCENDING").limit(n).stream() over the fake store, like Firestore."""

    def __init__(self, db, name, field=None, desc=False, n=None):
        self.db, self.name, self.field, self.desc, self.n = db, name, field, desc, n

    def order_by(self, field, direction="ASCENDING"):
        return _AuditQuery(self.db, self.name, field, direction == "DESCENDING", self.n)

    def limit(self, n):
        return _AuditQuery(self.db, self.name, self.field, self.desc, n)

    def stream(self):
        if self.db.fail_reads:
            raise RuntimeError("read failed")
        snaps = [_URef(self.db, k).get() for k in self.db.docs if k.startswith(self.name + "/")]
        if self.field:  # Firestore leaves out documents without the ordered field
            snaps = [s for s in snaps if self.field in s.to_dict()]
            snaps.sort(key=lambda s: s.to_dict()[self.field], reverse=self.desc)
        return snaps[: self.n] if self.n is not None else snaps


class _QCol(_UCol):
    def order_by(self, field, direction="ASCENDING"):
        return _AuditQuery(self.db, self.name).order_by(field, direction)


class _QDB(_UDB):
    def collection(self, name):
        return _QCol(self, name)


def _http_error():
    from fastapi import HTTPException
    return HTTPException


def _not_stored(ei):
    assert ei.value.status_code == 503
    assert ei.value.detail["code"] == "USER_ACCESS_NOT_STORED"
    return ei.value.detail["message"]


# ============================================================================== 3b: no success on a failed write
def test_revoke_that_firestore_did_not_store_is_503_and_the_user_keeps_the_record(users):
    users.db.fail_commit = True
    with pytest.raises(_http_error()) as ei:
        users.ru.remove_approved_user("old@example.com", users.req)
    msg = _not_stored(ei)
    assert "NOT revoked" in msg and "commit failed" not in msg  # exception type only, never its text
    assert "authorized_users/old@example.com" in users.db.docs and users.db.audit() == []


def test_revoke_success_is_unchanged(users):
    out = users.ru.remove_approved_user("old@example.com", users.req)
    assert out == {"status": "REMOVED", "email": "old@example.com"}
    assert "authorized_users/old@example.com" not in users.db.docs and len(users.db.audit()) == 1


def test_grant_that_firestore_did_not_store_is_503_and_only_the_break_glass_registry_has_it(users):
    from google.api_core import exceptions as gexc
    s = users.schemas
    # FD-4CI-b-3d: the break-glass copy is kept only when Firestore could not be reached (a refused write: no copy,
    # tests/test_fd4dj_settings_and_grant_copies.py)
    users.db.fail_commit = gexc.ServiceUnavailable("commit failed")
    with pytest.raises(_http_error()) as ei:
        users.ru.add_approved_user(s.AddUserRequest(email="new@example.com", role="VIEWER"), users.req)
    msg = _not_stored(ei)
    assert "was not saved" in msg
    assert "authorized_users/new@example.com" not in users.db.docs and users.db.audit() == []
    # N2 break-glass unchanged: the per-instance registry (read only while Firestore is unreadable) has the grant
    assert users.ru.MOCK_AUTHORIZED_USERS["new@example.com"].role == s.UserRole.VIEWER


def test_grant_success_is_unchanged(users):
    s = users.schemas
    rec = users.ru.add_approved_user(s.AddUserRequest(email="new@example.com", role="VIEWER"), users.req)
    assert rec.email == "new@example.com" and users.db.docs["authorized_users/new@example.com"]["role"] == "VIEWER"
    assert "new@example.com" not in users.ru.MOCK_AUTHORIZED_USERS


def test_update_with_an_unreadable_record_is_503_and_changes_nothing(users):
    s = users.schemas
    users.db.fail_reads = True
    with pytest.raises(_http_error()) as ei:
        users.ru.update_user_workloads("old@example.com", s.UpdateUserWorkloadsRequest(assigned_workloads=["z"]),
                                       users.req)
    assert "was not changed" in _not_stored(ei)
    assert users.db.docs["authorized_users/old@example.com"]["assigned_workloads"] == ["a"] and users.db.audit() == []


def test_update_whose_write_fails_is_503_and_changes_nothing(users):
    s = users.schemas
    users.db.fail_commit = True
    with pytest.raises(_http_error()) as ei:
        users.ru.update_user_workloads("old@example.com",
                                       s.UpdateUserWorkloadsRequest(assigned_workloads=["z"], role="ADMIN"), users.req)
    _not_stored(ei)
    assert users.db.docs["authorized_users/old@example.com"]["role"] == "VIEWER" and users.db.audit() == []


def test_update_of_an_unknown_user_is_still_404(users):
    s = users.schemas
    with pytest.raises(_http_error()) as ei:
        users.ru.update_user_workloads("nobody@example.com", s.UpdateUserWorkloadsRequest(assigned_workloads=[]),
                                       users.req)
    assert ei.value.status_code == 404


def test_update_success_is_unchanged(users):
    s = users.schemas
    rec = users.ru.update_user_workloads("old@example.com", s.UpdateUserWorkloadsRequest(assigned_workloads=["b"]),
                                         users.req)
    assert rec.assigned_workloads == ["b"] and users.db.docs["authorized_users/old@example.com"]["role"] == "VIEWER"


def test_refused_requests_still_answer_as_before(users):
    HTTPException = _http_error()
    with pytest.raises(HTTPException) as ei:
        users.ru.remove_approved_user("owner@example.com", users.req)
    assert ei.value.status_code == 400
    users.req.state.user_role = users.schemas.UserRole.VIEWER
    with pytest.raises(HTTPException) as ei:
        users.ru.remove_approved_user("old@example.com", users.req)
    assert ei.value.status_code == 403 and "authorized_users/old@example.com" in users.db.docs


# ========================================================== review item 3: APPROVER on the in-memory update path
def test_in_memory_update_stores_approver_as_workload_manager(users, monkeypatch):
    s, ru = users.schemas, users.ru
    monkeypatch.setattr(ru, "db", None)
    ru.MOCK_AUTHORIZED_USERS["mem@example.com"] = s.UserAccessRecord(email="mem@example.com", role="VIEWER",
                                                                     added_at="2026-01-01")
    rec = ru.update_user_workloads("mem@example.com",
                                   s.UpdateUserWorkloadsRequest(assigned_workloads=["w"], role="APPROVER"), users.req)
    assert rec.role is s.UserRole.WORKLOAD_MANAGER
    assert ru.MOCK_AUTHORIZED_USERS["mem@example.com"].role is s.UserRole.WORKLOAD_MANAGER
    rec = ru.update_user_workloads("mem@example.com",  # negative: other roles stored as given
                                   s.UpdateUserWorkloadsRequest(assigned_workloads=[], role="VIEWER"), users.req)
    assert rec.role is s.UserRole.VIEWER


# ======================================================================================= 3c: access audit view
@pytest.fixture
def audit(users, monkeypatch):
    db = _QDB(users.db.docs)
    monkeypatch.setattr(users.ru, "db", db)
    users.db = db
    return users


def _seed(db, n):
    for i in range(n):
        db.docs[f"{AUDIT}/e{i:03d}"] = {
            "action": "USER_ACCESS_UPDATED", "email": f"u{i}@example.com", "operator_email": "admin@example.com",
            "timestamp": f"2026-10-{1 + i // 24:02d}T{i % 24:02d}:00:00+00:00",
            "before": {"role": "VIEWER", "is_active": True, "assigned_workloads": ["a"]},
            "after": {"role": "WORKLOAD_MANAGER", "is_active": True, "assigned_workloads": ["a", "b"]},
        }


def test_audit_view_is_newest_first_and_at_most_50(audit):
    _seed(audit.db, 60)
    out = audit.ru.list_user_access_audit(audit.req)
    entries = out["entries"]
    assert out["limit"] == 50 and len(entries) == 50
    stamps = [e["timestamp"] for e in entries]
    assert stamps == sorted(stamps, reverse=True)
    assert entries[0]["email"] == "u59@example.com" and entries[-1]["email"] == "u10@example.com"


def test_audit_view_shows_who_when_what_before_and_after_only(audit):
    audit.db.docs[f"{AUDIT}/x"] = {
        "action": "USER_ACCESS_REVOKED", "email": "old@example.com", "operator_email": "admin@example.com",
        "timestamp": "2026-10-24T10:00:00+00:00", "before": None, "before_unreadable": True, "after": None,
        "token": "should-never-be-returned", "added_by": "x",
    }
    (entry,) = audit.ru.list_user_access_audit(audit.req)["entries"]
    assert set(entry) == {"action", "email", "operator_email", "timestamp", "before", "after", "before_unreadable"}
    assert entry["before_unreadable"] is True and entry["after"] is None
    assert "should-never-be-returned" not in repr(entry)


def test_audit_view_lists_real_grant_change_and_revoke_entries(audit):
    s, ru = audit.schemas, audit.ru
    ru.add_approved_user(s.AddUserRequest(email="n@example.com", role="VIEWER"), audit.req)
    ru.update_user_workloads("n@example.com", s.UpdateUserWorkloadsRequest(assigned_workloads=["w"]), audit.req)
    ru.remove_approved_user("n@example.com", audit.req)
    actions = {e["action"] for e in ru.list_user_access_audit(audit.req)["entries"]}
    assert actions == {"USER_ACCESS_GRANTED", "USER_ACCESS_UPDATED", "USER_ACCESS_REVOKED"}


def test_audit_view_unreadable_or_no_firestore_is_503_not_an_empty_list(audit, monkeypatch):
    HTTPException = _http_error()
    audit.db.fail_reads = True
    with pytest.raises(HTTPException) as ei:
        audit.ru.list_user_access_audit(audit.req)
    assert ei.value.status_code == 503 and ei.value.detail["code"] == "USER_ACCESS_AUDIT_UNAVAILABLE"
    monkeypatch.setattr(audit.ru, "db", None)
    with pytest.raises(HTTPException) as ei:
        audit.ru.list_user_access_audit(audit.req)
    assert ei.value.status_code == 503


@pytest.mark.parametrize("role", ["WORKLOAD_MANAGER", "VIEWER"])
def test_audit_view_is_admin_only(audit, role):
    _seed(audit.db, 3)
    audit.req.state.user_role = audit.schemas.UserRole(role)
    with pytest.raises(_http_error()) as ei:
        audit.ru.list_user_access_audit(audit.req)
    assert ei.value.status_code == 403
    src = open(os.path.join(REPO_ROOT, "apps", "control-center", "routes", "users.py"), encoding="utf-8").read()
    assert '@router.get("/api/users/access-audit", dependencies=[require(ADMIN)])' in src


# ============================================================================================ page and docs
def test_access_tab_shows_the_audit_and_loads_it():
    html = _html()
    tab = html.split("<!-- SUB-TAB 2: ACCESS CONTROL REGISTRY -->", 1)[1].split("<!-- SUB-TAB 3:", 1)[0]
    assert "Access Changes (last 50, newest first)" in tab and 'x-for="(a, i) in userAccessAudit"' in tab
    assert "@click=\"settingsTab = 'access'; fetchUserAccessAudit()\"" in html
    fn = html.split("async fetchUserAccessAudit() {", 1)[1].split("\n                },", 1)[0]
    assert "fetch('/api/users/access-audit')" in fn


def test_error_toasts_use_the_shared_formatter():
    html = _html()
    helper = html.split("apiErrorText(d, fallback) {", 1)[1].split("\n                },", 1)[0]
    assert "Array.isArray(d)" in helper and "x.msg" in helper and "join('; ')" in helper
    assert "d.code" in helper and "d.message" in helper
    vcs = html.split("async toggleDefaultVcsProvider(newProvider) {", 1)[1].split("\n                },", 1)[0]
    assert "this.apiErrorText(d, 'Failed to update VCS provider')" in vcs
    assert "this.apiErrorText(err.detail, 'Failed to add user')" in html
    assert "this.apiErrorText(err.detail, 'Failed to revoke user')" in html


def test_global_plan_approval_help_text_is_qualified():
    html = _html()
    i = html.index('x-model="platformSettings.governance.require_plan_approval"')
    block = html[i:i + 1200]
    assert "On: every run of every workload, existing ones included" not in block
    assert "every Agent-mode build of every workload" in block and "that reaches the compliance step" in block
    assert "a resumed run keeps the decision it already had" in block
    ref = _ref()
    assert "for Agent-mode builds that reach the compliance step. A resumed run" in ref


def test_docs_describe_failed_writes_and_the_audit_list():
    ref = _ref()
    assert "`USER_ACCESS_NOT_STORED`" in ref and "a failed revoke means the user can still sign in" in ref
    assert "These entries are not shown on the page" not in ref
    assert "**Access Changes** list shows the last 50 entries" in ref and "/api/users/access-audit" in ref
