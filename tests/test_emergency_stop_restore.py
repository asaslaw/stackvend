"""FD-4CI-b #1 (owner 10-21, register row FD-4CI-b): Emergency Stop resume restores each workload's pre-engage
freeze/SRE state; engage skips decommissioned workloads.

Engage (POST /api/platform/emergency-stop, activate=true) writes code_freeze=True / sre_auto_healing_enabled=False and,
in the same write, `emergency_stop_snapshot` (the pre-engage values, absent fields listed in `prior_absent`). A repeated
engage keeps the existing snapshot. Resume (activate=false) clears the switch, then per workload with a snapshot
restores the snapshot values (removing fields that were absent) unless an operator changed the field during the stop
(current value != the value engage wrote -> current kept), removes the snapshot and writes an audit_logs entry.

Hermetic: the real Control Center route function, an in-memory fake Firestore, no project (no Workflows call), no
network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy
import os
import sys
from types import SimpleNamespace

import pytest
from google.api_core import exceptions as gexc
from google.cloud import firestore

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")


# ----------------------------------------------------------------------------------------------------- fake Firestore
class _Snap:
    def __init__(self, doc_id, data, update_time=None):
        self.id = doc_id
        self._data = data
        self.exists = data is not None
        self.update_time = update_time

    def to_dict(self):
        return copy.deepcopy(self._data) if self._data is not None else None


def _merge(dst, src):
    for k, v in src.items():
        if v is firestore.DELETE_FIELD:
            dst.pop(k, None)
        elif isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge(dst[k], v)
        else:
            dst[k] = copy.deepcopy(v)


class _Doc:
    def __init__(self, db, path):
        self.db, self.path = db, path
        self.id = path.rsplit("/", 1)[-1]

    def get(self):
        snap = _Snap(self.id, copy.deepcopy(self.db.docs.get(self.path)), self.db.update_times.get(self.path))
        self.db.fire("after_get", self.path)
        return snap

    def set(self, data, merge=False):
        self.db.apply(self.path, data, merge)

    def create(self, data):
        """Firestore create(): fails with AlreadyExists when the document exists."""
        if self.path in self.db.docs:
            raise gexc.AlreadyExists(f"{self.path} already exists")
        self.db.apply(self.path, data, False)

    def update(self, data, option=None):
        """Firestore update(): the document must exist; `option` = write_option(last_update_time=...) precondition."""
        if self.path not in self.db.docs:
            raise gexc.NotFound(f"{self.path} does not exist")
        if option is not None and option.last_update_time != self.db.update_times.get(self.path):
            raise gexc.FailedPrecondition(f"{self.path} changed since it was read")
        self.db.apply(self.path, data, True)

    def collection(self, name):
        return _Coll(self.db, f"{self.path}/{name}")


class _Coll:
    def __init__(self, db, path):
        self.db, self.path = db, path

    def document(self, doc_id=None):
        if doc_id is None:
            self.db.auto_ids += 1
            doc_id = f"auto{self.db.auto_ids}"
        return _Doc(self.db, f"{self.path}/{doc_id}")

    def stream(self):
        """Lazy, like Firestore: each document is read when it is reached; may fail part-way (fail_stream_after)."""
        if self.path in self.db.fail_stream:
            raise RuntimeError(f"stream {self.path} unavailable")
        prefix = self.path + "/"
        paths = sorted(p for p in self.db.docs if p.startswith(prefix) and "/" not in p[len(prefix):])
        for n, p in enumerate(paths):
            if self.db.fail_stream_after.get(self.path) == n:
                raise RuntimeError(f"stream {self.path} broke after {n}")
            if p in self.db.docs:
                yield _Snap(p[len(prefix):], copy.deepcopy(self.db.docs[p]), self.db.update_times.get(p))


class _Batch:
    def __init__(self, db):
        self.db, self.ops = db, []

    def set(self, ref, data, merge=False):
        self.ops.append((ref.path, data, merge))

    def commit(self):
        for path, _, _ in self.ops:
            self.db.check_write(path)
        for path, data, merge in self.ops:
            self.db.apply(path, data, merge, check=False)
        for path, _, _ in self.ops:
            self.db.fire("after_commit", path)


class FakeDB:
    def __init__(self, docs=None):
        self.docs = copy.deepcopy(docs or {})
        self.update_times = {p: 0 for p in self.docs}
        self.clock = 0
        self.fail_writes, self.fail_stream = set(), set()
        self.fail_next = {}  # path -> number of upcoming writes that fail
        self.fail_stream_after = {}  # collection path -> index at which the stream raises
        self.hooks = {}  # (event, path) -> one-shot callable
        self.writes = []
        self.auto_ids = 0

    def collection(self, name):
        return _Coll(self, name)

    def batch(self):
        return _Batch(self)

    def write_option(self, last_update_time=None):
        return SimpleNamespace(last_update_time=last_update_time)

    def fire(self, event, path):
        hook = self.hooks.pop((event, path), None)
        if hook:
            hook()

    def check_write(self, path):
        if path in self.fail_writes:
            raise RuntimeError(f"write {path} failed")
        if self.fail_next.get(path):
            self.fail_next[path] -= 1
            raise RuntimeError(f"write {path} failed (transient)")

    def apply(self, path, data, merge, check=True):
        if check:
            self.check_write(path)
        self.writes.append(path)
        self.clock += 1
        self.update_times[path] = self.clock
        if merge and path in self.docs:
            _merge(self.docs[path], data)
        else:
            fresh = {}
            _merge(fresh, data)
            self.docs[path] = fresh

    def audit(self, pid):
        prefix = f"workloads/{pid}/audit_logs/"
        return [d for p, d in self.docs.items() if p.startswith(prefix)]


# ---------------------------------------------------------------------------------------------------------- harness
@pytest.fixture
def st(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db

    monkeypatch.setattr(cc_db, "_db_client", False)
    from routes import settings as st_mod

    monkeypatch.setattr(st_mod, "PROJECT_ID", "")  # no project: no Workflows call (WORKFLOW_CANCEL_UNCONFIGURED; tests/test_sat43_*)
    monkeypatch.delenv("PROJECT_ID", raising=False)
    return st_mod


def _call(st, db, monkeypatch, activate, reason="incident"):
    monkeypatch.setattr(st, "db", db)
    request = SimpleNamespace(state=SimpleNamespace(user_role=st.UserRole.ADMIN, user_email="admin@example.com"))
    return st.toggle_emergency_stop_api(st.EmergencyStopRequest(activate=activate, reason=reason), request)


def _get(st, role=None):
    """GET as an ADMIN by default; pass another role name (e.g. "VIEWER") for a non-admin caller."""
    r = st.UserRole.ADMIN if role is None else getattr(st.UserRole, role)
    return st.get_emergency_stop_status(SimpleNamespace(state=SimpleNamespace(user_role=r, user_email="u@example.com")))


def _wl(db, pid):
    return db.docs[f"workloads/{pid}"]


SEED = {
    "workloads/plain": {"status": "ACTIVE", "code_freeze": False, "sre_auto_healing_enabled": True},
    "workloads/frozen": {"status": "ACTIVE", "code_freeze": True, "sre_auto_healing_enabled": False},
    "workloads/legacy": {"status": "ACTIVE"},  # neither field stored (readers default: not frozen, healing on)
    "workloads/gone": {"status": "DECOMMISSIONED", "code_freeze": False, "sre_auto_healing_enabled": True},
    "workloads/deleted": {"status": "DELETED"},
}


# ------------------------------------------------------------------------------------------------------------ engage
def test_engage_freezes_with_snapshot_and_skips_decommissioned(st, monkeypatch):
    db = FakeDB(SEED)
    r = _call(st, db, monkeypatch, True)
    assert r.emergency_stop_active is True and r.status == "ACTIVE"
    assert r.workloads_frozen_count == 3 and r.workloads_skipped_decommissioned_count == 2
    assert r.workloads_failed_count == 0 and r.errors == [] and r.stop_id
    for pid in ("plain", "frozen", "legacy"):
        w = _wl(db, pid)
        assert w["code_freeze"] is True and w["sre_auto_healing_enabled"] is False
        snap = w["emergency_stop_snapshot"]
        assert snap["stop_id"] == r.stop_id and snap["engaged_by"] == "admin@example.com"
        assert snap["applied"] == {"code_freeze": True, "sre_auto_healing_enabled": False}
    assert _wl(db, "plain")["emergency_stop_snapshot"]["prior"] == {"code_freeze": False, "sre_auto_healing_enabled": True}
    assert _wl(db, "frozen")["emergency_stop_snapshot"]["prior"] == {"code_freeze": True, "sre_auto_healing_enabled": False}
    assert _wl(db, "legacy")["emergency_stop_snapshot"]["prior"] == {}
    assert _wl(db, "legacy")["emergency_stop_snapshot"]["prior_absent"] == ["code_freeze", "sre_auto_healing_enabled"]
    # decommissioned / deleted records: never written
    assert _wl(db, "gone") == SEED["workloads/gone"] and _wl(db, "deleted") == SEED["workloads/deleted"]
    assert "workloads/gone" not in db.writes and "workloads/deleted" not in db.writes
    ks = db.docs["governance/platform_kill_switch"]
    assert ks["emergency_stop_active"] is True and ks["stop_id"] == r.stop_id
    assert ks["last_engage_result"]["workloads_frozen"] == 3
    assert ks["last_engage_result"]["workloads_skipped_decommissioned"] == 2


def test_double_engage_keeps_the_original_snapshot_and_stop_id(st, monkeypatch):
    db = FakeDB(SEED)
    r1 = _call(st, db, monkeypatch, True)
    first = copy.deepcopy(_wl(db, "plain")["emergency_stop_snapshot"])
    r2 = _call(st, db, monkeypatch, True, reason="again")
    assert r2.stop_id == r1.stop_id
    assert r2.workloads_frozen_count == 3 and r2.workloads_snapshot_kept_count == 3
    assert _wl(db, "plain")["emergency_stop_snapshot"] == first  # still says "unfrozen before the stop"
    r3 = _call(st, db, monkeypatch, False)
    assert r3.workloads_restored_count == 3
    assert _wl(db, "plain")["code_freeze"] is False and _wl(db, "plain")["sre_auto_healing_enabled"] is True


# ------------------------------------------------------------------------------------------------------------ resume
def test_resume_restores_pre_engage_state(st, monkeypatch):
    db = FakeDB(SEED)
    engaged = _call(st, db, monkeypatch, True)
    r = _call(st, db, monkeypatch, False)
    assert r.emergency_stop_active is False and r.status == "NORMAL" and r.stop_id == engaged.stop_id
    assert r.workloads_restored_count == 3 and r.workloads_operator_override_count == 0
    assert r.workloads_without_snapshot_count == 0 and r.workloads_skipped_decommissioned_count == 2
    assert r.workloads_failed_count == 0 and r.errors == []
    # unfrozen before -> unfrozen; frozen before -> stays frozen; absent before -> absent again
    assert _wl(db, "plain") == SEED["workloads/plain"]
    assert _wl(db, "frozen") == SEED["workloads/frozen"]
    assert _wl(db, "legacy") == SEED["workloads/legacy"]
    assert _wl(db, "gone") == SEED["workloads/gone"] and _wl(db, "deleted") == SEED["workloads/deleted"]
    audit = db.audit("plain")
    assert len(audit) == 1 and audit[0]["action"] == "EMERGENCY_STOP_RESTORE"
    assert audit[0]["stop_id"] == engaged.stop_id
    assert audit[0]["restored_fields"] == {"code_freeze": False, "sre_auto_healing_enabled": True}
    assert db.audit("legacy")[0]["restored_absent_fields"] == ["code_freeze", "sre_auto_healing_enabled"]
    ks = db.docs["governance/platform_kill_switch"]
    assert ks["emergency_stop_active"] is False
    assert ks["last_resume_result"]["workloads_restored"] == 3 and ks["last_resume_result"]["workloads_failed"] == 0


def test_operator_change_during_the_stop_wins(st, monkeypatch):
    db = FakeDB(SEED)
    _call(st, db, monkeypatch, True)
    # During the stop an operator unfreezes "frozen" (was frozen before) and re-enables healing on "plain" only.
    _wl(db, "frozen")["code_freeze"] = False
    _wl(db, "plain")["sre_auto_healing_enabled"] = True
    r = _call(st, db, monkeypatch, False)
    assert r.workloads_restored_count == 3 and r.workloads_operator_override_count == 2
    # operator's value kept; the untouched field restored from the snapshot
    assert _wl(db, "frozen")["code_freeze"] is False and _wl(db, "frozen")["sre_auto_healing_enabled"] is False
    assert _wl(db, "plain")["code_freeze"] is False and _wl(db, "plain")["sre_auto_healing_enabled"] is True
    assert "emergency_stop_snapshot" not in _wl(db, "frozen")
    assert db.audit("frozen")[0]["operator_kept_fields"] == {"code_freeze": False}


def test_workloads_without_snapshot_are_untouched(st, monkeypatch):
    db = FakeDB(SEED)
    _call(st, db, monkeypatch, True)
    # A workload created during the stop (no snapshot) with its own settings.
    db.docs["workloads/new"] = {"status": "ACTIVE", "code_freeze": True, "sre_auto_healing_enabled": False}
    db.writes.clear()
    r = _call(st, db, monkeypatch, False)
    assert r.workloads_without_snapshot_count == 1
    assert _wl(db, "new") == {"status": "ACTIVE", "code_freeze": True, "sre_auto_healing_enabled": False}
    assert not any(p.startswith("workloads/new") for p in db.writes)


def test_negative_resume_with_no_stop_engaged_modifies_no_workload(st, monkeypatch):
    seed = {**SEED, "workloads/frozen-by-operator": {"status": "ACTIVE", "code_freeze": True}}
    db = FakeDB(seed)
    r = _call(st, db, monkeypatch, False)
    assert r.workloads_restored_count == 0 and r.workloads_without_snapshot_count == len(seed) - 2
    assert r.workloads_skipped_decommissioned_count == 2
    assert {p: d for p, d in db.docs.items() if p.startswith("workloads/")} == seed
    assert not any(p.startswith("workloads/") for p in db.writes)


# ----------------------------------------------------------------------------------------------------------- failures
def test_partial_restore_failure_is_reported_and_retried(st, monkeypatch):
    db = FakeDB(SEED)
    _call(st, db, monkeypatch, True)
    db.fail_writes.add("workloads/plain")
    r = _call(st, db, monkeypatch, False)
    assert r.emergency_stop_active is False
    assert r.workloads_restored_count == 2 and r.workloads_failed_count == 1 and r.failed_workloads == ["plain"]
    assert any("restore plain" in e for e in r.errors)
    # the failed workload stays frozen (safe side) and keeps its snapshot; no audit entry for it
    assert _wl(db, "plain")["code_freeze"] is True and "emergency_stop_snapshot" in _wl(db, "plain")
    assert db.audit("plain") == []
    assert db.docs["governance/platform_kill_switch"]["last_resume_result"]["failed_workloads"] == ["plain"]
    # the next resume retries it
    db.fail_writes.clear()
    r2 = _call(st, db, monkeypatch, False)
    assert r2.workloads_restored_count == 1 and r2.workloads_failed_count == 0
    assert _wl(db, "plain") == SEED["workloads/plain"]


def test_resume_refused_when_the_switch_cannot_be_cleared(st, monkeypatch):
    db = FakeDB(SEED)
    _call(st, db, monkeypatch, True)
    before = copy.deepcopy(db.docs)
    db.fail_writes.add("governance/platform_kill_switch")
    with pytest.raises(Exception) as ei:
        _call(st, db, monkeypatch, False)
    assert getattr(ei.value, "status_code", None) == 503
    assert db.docs == before  # still engaged, every workload still frozen with its snapshot


def test_partial_engage_failure_is_reported(st, monkeypatch):
    db = FakeDB(SEED)
    db.fail_writes.add("workloads/legacy")
    r = _call(st, db, monkeypatch, True)
    assert r.workloads_frozen_count == 2 and r.workloads_failed_count == 1 and r.failed_workloads == ["legacy"]
    assert any("freeze legacy" in e for e in r.errors)
    assert _wl(db, "legacy") == SEED["workloads/legacy"]  # neither frozen nor snapshotted (one write)


def test_engage_reports_an_unlistable_workload_collection(st, monkeypatch):
    db = FakeDB(SEED)
    db.fail_stream.add("workloads")
    r = _call(st, db, monkeypatch, True)
    assert r.emergency_stop_active is True and r.workloads_frozen_count == 0
    assert any("list workloads" in e for e in r.errors)
    assert db.docs["governance/platform_kill_switch"]["emergency_stop_active"] is True


def test_response_model_stays_backward_compatible(st):
    old_shape = {"emergency_stop_active": True, "status": "ACTIVE", "workflows_cancelled_count": 1,
                 "workloads_frozen_count": 2}
    r = st.EmergencyStopResponse(**old_shape)
    assert r.workloads_restored_count == 0 and r.failed_workloads == [] and r.errors == [] and r.stop_id is None


# ------------------------------------------------------------------------------------- review fixes (FD-4CI-b-1a)
def _frozen_with_original_snapshot(db):
    for pid in ("plain", "frozen", "legacy"):
        w = _wl(db, pid)
        assert w["code_freeze"] is True and w["sre_auto_healing_enabled"] is False, pid
        snap = w["emergency_stop_snapshot"]
        orig = SEED[f"workloads/{pid}"]
        assert snap["prior"] == {k: orig[k] for k in ("code_freeze", "sre_auto_healing_enabled") if k in orig}, pid


def _set_switch_concurrently(db):
    db.apply("governance/platform_kill_switch", {"emergency_stop_active": True, "stop_id": "other",
                                                 "activated_by": "other@example.com"}, True)


def test_engage_retries_the_switch_write_after_freezing(st, monkeypatch):
    db = FakeDB(SEED)
    db.fail_next["governance/platform_kill_switch"] = 1
    r = _call(st, db, monkeypatch, True)
    assert r.emergency_stop_active is True and r.workloads_frozen_count == 3
    assert any("retry succeeded" in e for e in r.errors)
    assert db.docs["governance/platform_kill_switch"]["emergency_stop_active"] is True


def test_engage_refused_503_when_the_switch_cannot_be_set(st, monkeypatch):
    db = FakeDB(SEED)
    db.fail_writes.add("governance/platform_kill_switch")
    with pytest.raises(Exception) as ei:
        _call(st, db, monkeypatch, True)
    assert getattr(ei.value, "status_code", None) == 503
    assert "3 workloads frozen but the kill switch could not be set" in str(ei.value.detail)
    _frozen_with_original_snapshot(db)  # freezing happened first and is kept
    assert "governance/platform_kill_switch" not in db.docs


def test_concurrent_engage_before_the_clear_fails_resume_into_503(st, monkeypatch):
    db = FakeDB(SEED)
    _call(st, db, monkeypatch, True)
    # Another admin engages between resume's read of the switch and its clear.
    db.hooks[("after_get", "governance/platform_kill_switch")] = lambda: _set_switch_concurrently(db)
    before_workloads = {p: copy.deepcopy(d) for p, d in db.docs.items() if p.startswith("workloads/")}
    with pytest.raises(Exception) as ei:
        _call(st, db, monkeypatch, False)
    assert getattr(ei.value, "status_code", None) == 503
    assert db.docs["governance/platform_kill_switch"]["emergency_stop_active"] is True
    assert {p: d for p, d in db.docs.items() if p.startswith("workloads/")} == before_workloads


def test_concurrent_engage_during_the_restore_loop_refreezes(st, monkeypatch):
    db = FakeDB(SEED)
    _call(st, db, monkeypatch, True)
    # Paths stream in sorted order: "frozen" is the first workload restored; a full engage lands right after it.
    db.hooks[("after_commit", "workloads/frozen")] = lambda: _call(st, db, monkeypatch, True, reason="second incident")
    r = _call(st, db, monkeypatch, False)
    assert r.emergency_stop_active is True and r.status == "ACTIVE"
    assert any("re-engaged by admin@example.com during resume; workloads re-frozen" in e for e in r.errors)
    _frozen_with_original_snapshot(db)  # frozen again, snapshots still hold the state from before both stops
    ks = db.docs["governance/platform_kill_switch"]
    assert ks["emergency_stop_active"] is True and ks["stop_id"] == r.stop_id
    assert _wl(db, "plain")["emergency_stop_snapshot"]["stop_id"] == r.stop_id
    # and the next resume restores the true pre-stop state
    r2 = _call(st, db, monkeypatch, False)
    assert r2.emergency_stop_active is False and r2.workloads_restored_count == 3
    for pid in ("plain", "frozen", "legacy"):
        assert _wl(db, pid) == SEED[f"workloads/{pid}"]


def test_get_reports_last_resume_failures_for_retry(st, monkeypatch):
    db = FakeDB(SEED)
    _call(st, db, monkeypatch, True)
    monkeypatch.setattr(st, "db", db)
    assert _get(st).workloads_failed_count == 0  # engaged: nothing to retry
    db.fail_writes.add("workloads/plain")
    _call(st, db, monkeypatch, False)
    g = _get(st)
    assert g.emergency_stop_active is False and g.workloads_failed_count == 1 and g.failed_workloads == ["plain"]
    db.fail_writes.clear()
    _call(st, db, monkeypatch, False)  # "Retry restore" = the same POST activate=false
    g = _get(st)
    assert g.workloads_failed_count == 0 and g.failed_workloads == []
    assert _wl(db, "plain") == SEED["workloads/plain"]


@pytest.mark.parametrize("role", ["VIEWER", "WORKLOAD_MANAGER", None])
def test_get_hides_failed_workloads_from_non_admins(st, monkeypatch, role):
    db = FakeDB(SEED)
    _call(st, db, monkeypatch, True)
    db.fail_writes.add("workloads/plain")
    _call(st, db, monkeypatch, False)
    assert _get(st).failed_workloads == ["plain"]  # an admin sees it
    g = st.get_emergency_stop_status(None) if role is None else _get(st, role)
    assert g.emergency_stop_active is False and g.status == "NORMAL"
    assert g.workloads_failed_count == 0 and g.failed_workloads == []  # the old shape


def test_engage_that_read_the_old_stop_id_before_the_clear_still_refreezes(st, monkeypatch):
    db = FakeDB(SEED)
    first = _call(st, db, monkeypatch, True)
    # A second engage read the switch (active, old stop_id) before resume cleared it and writes it back -- same
    # stop_id -- once "frozen" (the first workload) has been restored.
    db.hooks[("after_commit", "workloads/frozen")] = lambda: db.apply(
        "governance/platform_kill_switch",
        {"emergency_stop_active": True, "stop_id": first.stop_id, "activated_by": "late@example.com"}, True)
    r = _call(st, db, monkeypatch, False)
    assert r.emergency_stop_active is True and r.stop_id == first.stop_id
    assert any("re-engaged by late@example.com during resume; workloads re-frozen" in e for e in r.errors)
    assert r.workloads_frozen_count == 3
    _frozen_with_original_snapshot(db)


def test_refreeze_failures_are_merged_into_the_active_response(st, monkeypatch):
    db = FakeDB(SEED)
    _call(st, db, monkeypatch, True)
    db.fail_writes.add("workloads/plain")  # fails its restore AND its re-freeze
    # After legacy's restore: another admin engages, and frozen's next write (its re-freeze) fails once.
    db.hooks[("after_commit", "workloads/legacy")] = lambda: (_set_switch_concurrently(db),
                                                              db.fail_next.__setitem__("workloads/frozen", 1))
    r = _call(st, db, monkeypatch, False)
    # sorted: frozen restored, legacy restored (-> re-engage; frozen's next write will fail), plain restore fails;
    # re-freeze: frozen fails (transient), legacy ok, plain fails.
    assert r.emergency_stop_active is True
    assert r.workloads_failed_count == 3  # 1 (resume: plain) + 2 (re-freeze: frozen, plain)
    assert r.failed_workloads == ["frozen", "plain"]
    assert r.workloads_frozen_count == 1


def test_resume_without_a_stop_record_creates_it_and_a_racing_create_is_503(st, monkeypatch):
    db = FakeDB(SEED)
    r = _call(st, db, monkeypatch, False)  # never engaged: the record is created, no workload touched
    assert r.emergency_stop_active is False
    assert db.docs["governance/platform_kill_switch"]["emergency_stop_active"] is False
    db2 = FakeDB(SEED)
    # An engage creates the record between resume's read (no record) and its create -> AlreadyExists -> 503.
    db2.hooks[("after_get", "governance/platform_kill_switch")] = lambda: _set_switch_concurrently(db2)
    with pytest.raises(Exception) as ei:
        _call(st, db2, monkeypatch, False)
    assert getattr(ei.value, "status_code", None) == 503
    assert db2.docs["governance/platform_kill_switch"]["emergency_stop_active"] is True
    assert not any(p.startswith("workloads/") for p in db2.writes)


def test_engage_keeps_freezes_when_the_listing_breaks_part_way(st, monkeypatch):
    db = FakeDB(SEED)
    db.fail_stream_after["workloads"] = 2  # sorted: deleted (skipped), frozen (frozen), then the stream breaks
    r = _call(st, db, monkeypatch, True)
    assert r.workloads_frozen_count == 1 and r.workloads_skipped_decommissioned_count == 1
    assert any(e.startswith("list workloads after 2:") for e in r.errors)
    assert "emergency_stop_snapshot" in _wl(db, "frozen")
    assert _wl(db, "plain") == SEED["workloads/plain"] and _wl(db, "legacy") == SEED["workloads/legacy"]


def test_resume_never_writes_a_workload_closed_during_the_stop(st, monkeypatch):
    db = FakeDB(SEED)
    _call(st, db, monkeypatch, True)
    _wl(db, "plain")["status"] = "DECOMMISSIONED"
    closed = copy.deepcopy(_wl(db, "plain"))
    db.writes.clear()
    r = _call(st, db, monkeypatch, False)
    assert r.workloads_restored_count == 2 and r.workloads_skipped_decommissioned_count == 3
    assert _wl(db, "plain") == closed and db.audit("plain") == []
    assert not any(p.startswith("workloads/plain") for p in db.writes)
    # the leftover snapshot is inert: a new engage skips the closed record too
    db.writes.clear()
    _call(st, db, monkeypatch, True)
    assert not any(p.startswith("workloads/plain") for p in db.writes)


@pytest.mark.parametrize("bad", [
    {"applied": "x", "prior": {"code_freeze": False}, "prior_absent": []},
    {"applied": {"code_freeze": True, "sre_auto_healing_enabled": False}, "prior": [], "prior_absent": []},
    {"applied": {"code_freeze": True, "sre_auto_healing_enabled": False}, "prior": {}, "prior_absent": "nope"},
    {"applied": {"code_freeze": True, "sre_auto_healing_enabled": False}, "prior": {"code_freeze": False},
     "prior_absent": []},  # sre_auto_healing_enabled in neither prior nor prior_absent
], ids=["applied-not-map", "prior-not-map", "absent-not-list", "field-missing"])
def test_malformed_snapshot_keeps_current_values_and_is_removed(st, monkeypatch, bad):
    db = FakeDB(SEED)
    _call(st, db, monkeypatch, True)
    _wl(db, "plain")["emergency_stop_snapshot"] = {"stop_id": "s", **bad}
    r = _call(st, db, monkeypatch, False)
    assert r.workloads_malformed_snapshot_count == 1 and r.workloads_restored_count == 2
    assert any("malformed snapshot on plain" in e for e in r.errors)
    w = _wl(db, "plain")
    assert w["code_freeze"] is True and w["sre_auto_healing_enabled"] is False  # safe side: stays frozen
    assert "emergency_stop_snapshot" not in w
    entry = db.audit("plain")[0]
    assert entry["malformed_snapshot"] is True and entry["restored_fields"] == {}
