"""FD-4CI-b-R3 and FD-4CI-b-3a (owner 10-24):

* R3: "the Settings save is transactional (Firestore precondition on the version), closing the read-then-write window
  of the 409 lock". `routes/settings.store_settings_document` reads the stored document, requires its version to be the
  one the save was based on, and writes with an update_time precondition (create when there is no document).
* 3a: "the Switch Default VCS write uses a precondition, so a concurrent Settings save gets 409 instead of being
  overwritten".

A concurrent write -> 409 SETTINGS_VERSION_CONFLICT and nothing is overwritten; the store stays exact; other write
errors stay 500. Hermetic: tests/settings_write_fake.py emulates the Firestore preconditions.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy
import os
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(TESTS, ".."))
for p in (TESTS, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import settings as S  # noqa: E402
from test_fd4ak_settings_fail_closed import _store, cc  # noqa: F401,E402  (cc: fixture)
import test_fd4ci_b3_settings_fixes as b3  # noqa: E402
from test_fd4ci_b3_settings_fixes import vcs  # noqa: F401,E402  (fixture)


@pytest.fixture(autouse=True)
def _fresh_cache():
    S.invalidate_settings_cache()
    yield
    S.invalidate_settings_cache()


# ================================================================================================ R3: PUT /api/settings
def test_a_save_landing_after_the_read_makes_the_put_409_and_is_not_overwritten(cc, monkeypatch):
    _store(monkeypatch, {"version": 5})
    other = {"version": 6, "finops": {"default_monthly_budget_usd": 300.0}}
    cc.writes.concurrent = lambda st: st.bump(other)   # another administrator saves inside the window
    with pytest.raises(Exception) as ei:
        cc.rs.update_settings_api(S.PlatformSettings(finops={"default_monthly_budget_usd": 90.0}, version=5),
                                  cc.request)
    assert ei.value.status_code == 409 and ei.value.detail["code"] == "SETTINGS_VERSION_CONFLICT"
    assert "Nothing was saved" in ei.value.detail["message"]
    cc.doc_ref.set.assert_not_called()                 # nothing overwritten
    assert cc.writes.current() == (True, other)


def test_a_save_between_the_version_check_and_the_write_is_409(cc, monkeypatch):
    _store(monkeypatch, {"version": 5})                 # what the strict read (version check) sees
    cc.writes.override = (True, {"version": 6})         # what is stored by the time the write reads
    with pytest.raises(Exception) as ei:
        cc.rs.update_settings_api(S.PlatformSettings(version=5), cc.request)
    assert ei.value.status_code == 409 and ei.value.detail["stored_version"] == 6
    cc.doc_ref.set.assert_not_called()


def test_negative_an_uncontended_save_is_written_exactly_as_before(cc, monkeypatch):
    _store(monkeypatch, {"version": 5})
    out = cc.rs.update_settings_api(S.PlatformSettings(finops={"default_monthly_budget_usd": 90.0}, version=5),
                                    cc.request)
    (stored,), kw = cc.doc_ref.set.call_args
    assert kw == {"merge": False} and out.version == 6 and stored["finops"]["default_monthly_budget_usd"] == 90.0
    assert cc.doc_ref.update.call_args.kwargs["option"] == {"last_update_time": 1}


def test_fresh_install_creates_and_a_concurrent_create_is_409(cc, monkeypatch):
    _store(monkeypatch, None, exists=False)
    out = cc.rs.update_settings_api(S.PlatformSettings(version=1), cc.request)
    assert out.version == 2 and cc.doc_ref.create.called and not cc.doc_ref.update.called
    cc.doc_ref.set.reset_mock()
    cc.doc_ref.create.reset_mock()
    S.invalidate_settings_cache()
    cc.writes.concurrent = lambda st: st.bump({"version": 2})   # someone else created it first
    with pytest.raises(Exception) as ei:
        cc.rs.update_settings_api(S.PlatformSettings(version=1), cc.request)
    assert ei.value.status_code == 409
    cc.doc_ref.set.assert_not_called()


def test_other_write_errors_stay_500(cc, monkeypatch):
    _store(monkeypatch, {"version": 5})
    cc.doc_ref.update.side_effect = RuntimeError("quota exceeded")
    with pytest.raises(Exception) as ei:
        cc.rs.update_settings_api(S.PlatformSettings(version=5), cc.request)
    assert ei.value.status_code == 500


def test_store_is_exact_and_serializes_with_the_real_client(cc):
    """The update replaces every top-level field and deletes a stale one (what set(merge=False) did); the real
    google-cloud-firestore client turns it into ONE write carrying the update_time precondition (dry run, no I/O)."""
    from google.cloud.firestore_v1 import DELETE_FIELD, _helpers
    rs = cc.rs
    ref = MagicMock()
    ref.get.return_value = SimpleNamespace(exists=True, update_time="t-1",
                                           to_dict=lambda: {"version": 3, "legacy-key": 1, "finops": {}})
    db = MagicMock()
    db.collection.return_value.document.return_value = ref
    db.write_option = lambda **kw: dict(kw)
    doc = S.PlatformSettings(version=4).model_dump()
    with patch.object(rs, "db", db):
        rs.store_settings_document(doc, 3)
    (update,), kw = ref.update.call_args
    assert kw == {"option": {"last_update_time": "t-1"}}
    assert update["`legacy-key`"] is DELETE_FIELD and {k: update[k] for k in doc} == doc
    pbs = _helpers.pbs_for_update("projects/p/databases/(default)/documents/system_config/platform_settings",
                                  update, _helpers.LastUpdateOption(datetime.now(timezone.utc)))
    assert len(pbs) == 1 and pbs[0].current_document.update_time
    assert set(pbs[0].update_mask.field_paths) == set(doc) | {"`legacy-key`"}
    ref.create.assert_not_called()
    # and a stale stored version is refused before any write
    with patch.object(rs, "db", db), pytest.raises(rs.SettingsChangedMeanwhile):
        rs.store_settings_document(doc, 2)


# ================================================================================================ 3a: Switch Default VCS
def test_vcs_switch_with_a_concurrent_settings_save_is_409_and_not_overwritten(vcs):
    saved = dict(copy.deepcopy(b3.STORED), version=8)
    vcs.writes.concurrent = lambda st: st.bump(saved)   # a Settings save lands after the switch read
    with pytest.raises(Exception) as ei:
        vcs.rs.switch_vcs_provider_api(vcs.rs.SwitchVcsProviderRequest(vcs_provider="SERVERLESS_GIT"),
                                       b3._admin(vcs.rs))
    assert ei.value.status_code == 409 and ei.value.detail["code"] == "SETTINGS_VERSION_CONFLICT"
    assert "Nothing was changed" in ei.value.detail["message"]
    vcs.doc_ref.set.assert_not_called()
    assert vcs.writes.current() == (True, saved)


def test_vcs_switch_after_the_version_moved_is_409(vcs):
    vcs.writes.override = (True, dict(copy.deepcopy(b3.STORED), version=9))
    with pytest.raises(Exception) as ei:
        vcs.rs.switch_vcs_provider_api(vcs.rs.SwitchVcsProviderRequest(vcs_provider="SERVERLESS_GIT"),
                                       b3._admin(vcs.rs))
    assert ei.value.status_code == 409 and ei.value.detail["stored_version"] == 9
    vcs.doc_ref.set.assert_not_called()


def test_negative_uncontended_vcs_switch_is_written(vcs):
    out = vcs.rs.switch_vcs_provider_api(vcs.rs.SwitchVcsProviderRequest(vcs_provider="SERVERLESS_GIT"),
                                         b3._admin(vcs.rs))
    (stored,), kw = vcs.doc_ref.set.call_args
    assert kw == {"merge": False} and out.version == 8 and stored["governance"]["vcs_provider"] == "SERVERLESS_GIT"


def test_both_writes_go_through_the_preconditioned_store():
    src = open(os.path.join(REPO_ROOT, "apps", "control-center", "routes", "settings.py"), encoding="utf-8").read()
    for fn in ("def update_settings_api(", "def switch_vcs_provider_api("):
        body = src.split(fn, 1)[1].split("\n@router.", 1)[0]
        assert "store_settings_document(stored_doc," in body and '.document("platform_settings").set(' not in body
