"""FD-4CU (owner 10-21, register row FD-4CU): Settings toggle "Freeze new workloads by default",
``governance.freeze_new_workloads``, default ON.

* shared reader: True unless exactly False on a strict read; missing -> True (default); unreadable / invalid /
  non-bool -> True (fail toward frozen); never raises.
* every new-workload creation point sets the INITIAL ``code_freeze`` from it: Control Center create (form / API /
  Express share the record), promote (deploy-to-folder), project vending (a record with no code_freeze yet, e.g. a
  Drive intake). Nothing else in the initial record changes (sre_auto_healing_enabled / refactor_scanner_enabled /
  review fields are as before).
* existing workloads are never changed: a re-create or a re-vend of a record that already has a code_freeze value
  keeps it (either way); an unreadable record is only ever frozen, never unfrozen.
* the StackVend platform record (bootstrap-castor) keeps its own logic.
* the toggle is saved through the audited, admin-only PUT /api/settings and the Settings page explains it.
Hermetic: in-memory fakes only (no Firestore, no network).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(TESTS, ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
for p in (TESTS, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import settings as S  # noqa: E402
from test_l19_11_access_intake import ADMIN_H, FakeDB as CcFakeDB, _client, cc  # noqa: F401,E402  (cc: fixture)
from test_ti3h_intent_generate_toggle import cc_settings  # noqa: F401,E402  (fixture)
import destructive_guard_fakes as f  # noqa: E402
from test_destructive_guard_vending import VENDING_MAIN, _vend_crm, _vend_engine  # noqa: E402

SETTINGS_COPIES = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared",
                   "apps/project-vending/shared", "apps/spec-ingestion/shared", "mcp-servers/terraform/shared"]


def _settings(**gov):
    return S.PlatformSettings(governance=gov)


def _raises(err):
    def read(*a, **k):
        raise err
    return read


ON, OFF, DEFAULT = _settings(freeze_new_workloads=True), _settings(freeze_new_workloads=False), S.PlatformSettings()


@pytest.fixture(autouse=True)
def _fresh_cache():
    S.invalidate_settings_cache()
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield
    S.invalidate_settings_cache()


# ================================================================================================ 1. shared reader
def test_setting_defaults_on_in_the_schema_and_the_reader():
    assert S.PlatformSettings().governance.freeze_new_workloads is True
    assert S.GovernanceSettings.model_fields["freeze_new_workloads"].annotation is bool
    assert S.freeze_new_workloads_enabled(read=lambda **k: DEFAULT) is True
    # a stored document without the key (every install before FD-4CU) reads as on
    assert S.platform_settings_from_stored({"governance": {"maintenance_mode": False}}).governance \
        .freeze_new_workloads is True


def test_reader_is_off_only_when_exactly_false_on_a_strict_read():
    seen = {}

    def read(**k):
        seen.update(k)
        return OFF
    assert S.freeze_new_workloads_enabled(project_id="host-p", read=read) is False
    assert seen == {"project_id": "host-p", "strict": True}
    assert S.freeze_new_workloads_enabled(read=lambda **k: ON) is True
    for odd in ("false", 0, None, "off"):   # not exactly False (a hand-edited document read without the schema)
        ns = SimpleNamespace(governance=SimpleNamespace(freeze_new_workloads=odd))
        assert S.freeze_new_workloads_enabled(read=lambda **k: ns) is True
    assert S.freeze_new_workloads_enabled(read=lambda **k: SimpleNamespace()) is True   # no governance section
    assert S.freeze_new_workloads_enabled(read=lambda **k: None) is True


@pytest.mark.parametrize("err", [S.PlatformSettingsReadError("down"), S.PlatformSettingsInvalid("bad"),
                                 RuntimeError("anything else")])
def test_reader_is_on_when_settings_cannot_be_read(err):
    assert S.freeze_new_workloads_enabled(read=_raises(err)) is True


def test_reader_end_to_end_store_unreadable_is_on():
    assert S.freeze_new_workloads_enabled() is True   # the autouse patch makes the Firestore client raise


def test_settings_copies_are_byte_identical_and_carry_the_setting():
    root = open(os.path.join(REPO_ROOT, "shared", "settings.py"), "rb").read()
    assert b"freeze_new_workloads: bool = Field(" in root and b"def freeze_new_workloads_enabled(" in root
    for d in SETTINGS_COPIES:
        assert open(os.path.join(REPO_ROOT, d, "settings.py"), "rb").read() == root, d


# ================================================================================================ 2. CC create
def _create(wl, monkeypatch, settings, body=None, initial=None):
    fake_db = CcFakeDB(initial)
    client = _client(wl, monkeypatch, fake_db)
    publisher = MagicMock()
    publisher.publish.return_value.result.return_value = "msg-1"
    reader = settings if callable(settings) else (lambda *a, **k: settings)
    with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
         patch.object(wl, "get_pubsub_publisher", return_value=publisher), \
         patch.object(wl, "get_platform_settings", side_effect=reader):
        r = client.post("/api/workloads", json={"product_id": "shop-app", "spec_content": "a shop", **(body or {})},
                        headers=ADMIN_H)
    payload = (json.loads(publisher.publish.call_args[0][1].decode("utf-8"))
               if publisher.publish.call_args else None)
    return r, fake_db, payload


@pytest.mark.parametrize("settings, frozen", [(ON, True), (OFF, False), (DEFAULT, True)])
def test_cc_create_sets_the_initial_freeze_from_the_toggle(cc, monkeypatch, settings, frozen):
    _, wl = cc
    r, fake_db, payload = _create(wl, monkeypatch, settings)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["code_freeze"] is frozen
    assert r.json()["code_freeze"] is frozen
    assert payload is not None and "code_freeze" not in payload   # the intake event is unchanged


def test_cc_create_toggle_changes_nothing_else_in_the_record(cc, monkeypatch):
    _, wl = cc
    on = _create(wl, monkeypatch, ON)
    off = _create(wl, monkeypatch, OFF)
    volatile = {"created_at", "spend_last_updated_at", "project_id"}
    rec_on = {k: v for k, v in on[1]["workloads/shop-app"].items() if k not in volatile}
    rec_off = {k: v for k, v in off[1]["workloads/shop-app"].items() if k not in volatile}
    assert rec_on.pop("code_freeze") is True and rec_off.pop("code_freeze") is False
    assert rec_on == rec_off
    assert rec_on["sre_auto_healing_enabled"] is True and rec_on["refactor_scanner_enabled"] is True
    resp_on = {k: v for k, v in on[0].json().items() if k not in volatile}
    resp_off = {k: v for k, v in off[0].json().items() if k not in volatile}
    assert resp_on.pop("code_freeze") is True and resp_off.pop("code_freeze") is False
    assert resp_on == resp_off
    assert on[2] is not None and off[2] is not None
    event_volatile = volatile | {"trace_id", "sandbox_expires_at"}
    assert ({k: v for k, v in on[2].items() if k not in event_volatile}
            == {k: v for k, v in off[2].items() if k not in event_volatile})


@pytest.mark.parametrize("stored, settings", [(False, ON), (True, OFF), (True, ON), (False, OFF)])
def test_cc_recreate_of_an_existing_workload_keeps_its_freeze(cc, monkeypatch, stored, settings):
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app", "status": "ACTIVE", "code_freeze": stored}}
    r, fake_db, _ = _create(wl, monkeypatch, settings, initial=initial)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["code_freeze"] is stored
    assert r.json()["code_freeze"] is stored


def test_cc_create_over_a_record_without_a_freeze_value_applies_the_toggle(cc, monkeypatch):
    """A document seeded before the workload record (e.g. a compliance selection or an access seed) has no
    code_freeze: the workload is new."""
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app"}}
    r, fake_db, _ = _create(wl, monkeypatch, ON, initial=initial)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["code_freeze"] is True


@pytest.mark.parametrize("settings, written", [(ON, True), (OFF, None)])
def test_cc_create_with_an_unreadable_record_only_ever_freezes(cc, monkeypatch, settings, written):
    """Review nit: with nothing written (toggle off) the response never claims False: the stored value may be True.
    FD-4CU-b: nor are the SRE / scanner switches written (nothing is turned back on)."""
    _, wl = cc
    monkeypatch.setattr(wl, "_stored_workload_doc", lambda pid: None)
    initial = {"workloads/shop-app": {"product_id": "shop-app", "status": "ACTIVE", "sre_auto_healing_enabled": False}}
    r, fake_db, _ = _create(wl, monkeypatch, settings, initial=initial)
    assert r.status_code == 200, r.text
    doc = fake_db["workloads/shop-app"]
    assert doc.get("code_freeze") is written
    assert r.json()["code_freeze"] is True
    assert doc["sre_auto_healing_enabled"] is False and "refactor_scanner_enabled" not in doc


def test_stored_workload_doc_states(cc, monkeypatch):
    _, wl = cc
    monkeypatch.setattr(wl, "db", CcFakeDB({"workloads/a": {"code_freeze": True}}))
    assert wl._stored_workload_doc("a") == {"code_freeze": True}
    assert wl._stored_workload_doc("missing") == {}
    broken = MagicMock()
    broken.collection.return_value.document.return_value.get.side_effect = RuntimeError("down")
    monkeypatch.setattr(wl, "db", broken)
    assert wl._stored_workload_doc("a") is None
    assert wl.KEPT_ON_RECREATE == ("code_freeze", "sre_auto_healing_enabled", "refactor_scanner_enabled")


# ------------------------------------------------------------------ FD-4CU-b: SRE / scanner switches on re-create
@pytest.mark.parametrize("sre, scan", [(False, False), (False, True), (True, False), (True, True)])
def test_cc_recreate_keeps_the_sre_and_scanner_switches(cc, monkeypatch, sre, scan):
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app", "status": "ACTIVE", "code_freeze": False,
                                      "sre_auto_healing_enabled": sre, "refactor_scanner_enabled": scan}}
    r, fake_db, _ = _create(wl, monkeypatch, ON, initial=initial)
    assert r.status_code == 200, r.text
    doc = fake_db["workloads/shop-app"]
    assert doc["sre_auto_healing_enabled"] is sre and doc["refactor_scanner_enabled"] is scan
    assert r.json()["sre_auto_healing_enabled"] is sre   # WorkloadSummary has no scanner field
    assert doc["code_freeze"] is False


def test_cc_recreate_without_the_switches_and_new_workloads_get_both_on(cc, monkeypatch):
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app", "status": "ACTIVE"}}
    for init in (initial, None):
        r, fake_db, _ = _create(wl, monkeypatch, ON, initial=init)
        assert r.status_code == 200, r.text
        doc = fake_db["workloads/shop-app"]
        assert doc["sre_auto_healing_enabled"] is True and doc["refactor_scanner_enabled"] is True


@pytest.mark.parametrize("err", [S.PlatformSettingsReadError("down"), RuntimeError("anything")])
def test_cc_helper_fails_toward_frozen_and_never_raises(cc, err):
    _, wl = cc
    assert wl._freeze_new_workloads(_raises(err)) is True
    assert wl._freeze_new_workloads(lambda **k: OFF) is False
    assert wl._freeze_new_workloads(lambda **k: None) is True


def test_cc_helper_without_the_reader_is_frozen(cc, monkeypatch):
    _, wl = cc
    monkeypatch.setitem(sys.modules, "shared.settings", SimpleNamespace())   # an older copy without the reader
    assert wl._freeze_new_workloads(lambda **k: OFF) is True


# ================================================================================================ 3. CC promote
SRC = {"workloads/src-app": {"product_id": "src-app", "status": "ACTIVE", "github_repo": "example-org/src-app",
                             "code_freeze": False}}


def _promote(wl, monkeypatch, fake_db, settings):
    import folders

    monkeypatch.setattr(folders, "_default_get_folder", lambda name: {"name": name, "parent": "organizations/1"})
    monkeypatch.setattr(wl, "get_caller_main_module", lambda: SimpleNamespace())
    monkeypatch.setattr(wl, "create_or_verify_branch", lambda **k: None)
    client = _client(wl, monkeypatch, fake_db)
    publisher = MagicMock()
    publisher.publish.return_value.result.return_value = "msg-1"
    reader = settings if callable(settings) else (lambda *a, **k: settings)
    with patch.dict(os.environ, {"MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
         patch.object(wl, "get_pubsub_publisher", return_value=publisher), \
         patch.object(wl, "get_platform_settings", side_effect=reader):
        return client.post("/api/workloads/src-app/deploy-to-folder", headers=ADMIN_H,
                           json={"destination_folder_id": "folders/111111111111", "new_product_id": "src-app-prod",
                                 "target_branch": "prod"})


@pytest.mark.parametrize("settings, frozen", [(ON, True), (OFF, False), (DEFAULT, True),
                                              (SimpleNamespace(governance=SimpleNamespace(maintenance_mode=False)),
                                               True)])   # a settings object without the field
def test_promote_sets_the_initial_freeze_from_the_toggle(cc, monkeypatch, settings, frozen):
    """(Settings that cannot be read at all already refuse a promotion at the maintenance gate, FD-4AK, before the
    freeze is read; the freeze reader's own failure handling is covered in sections 1 and 2.)"""
    _, wl = cc
    fake_db = CcFakeDB(SRC)
    r = _promote(wl, monkeypatch, fake_db, settings)
    assert r.status_code == 200, r.text
    doc = fake_db["workloads/src-app-prod"]
    assert doc["code_freeze"] is frozen and r.json()["code_freeze"] is frozen
    assert doc["sre_auto_healing_enabled"] is True and doc["refactor_scanner_enabled"] is True
    assert doc["require_human_code_review"] is True
    assert fake_db["workloads/src-app"] == SRC["workloads/src-app"]   # the source is untouched


def test_promote_never_copies_the_source_freeze(cc, monkeypatch):
    _, wl = cc
    src = {"workloads/src-app": dict(SRC["workloads/src-app"], code_freeze=True)}
    fake_db = CcFakeDB(src)
    r = _promote(wl, monkeypatch, fake_db, OFF)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/src-app-prod"]["code_freeze"] is False
    assert fake_db["workloads/src-app"]["code_freeze"] is True


# ================================================================================================ 4. sweep + platform
CC_SRC = CC_DIR


def test_every_cc_route_creating_a_provisioning_workload_applies_the_toggle():
    """Any Control Center function that builds a workload record with status PROVISIONING (a new workload) must take
    its initial code_freeze from _freeze_new_workloads, and none hardcodes "code_freeze": False any more."""
    offenders, found, hardcoded = [], [], []
    for root, _dirs, names in os.walk(CC_SRC):
        if "shared" in root.split(os.sep) or "__pycache__" in root:
            continue
        for name in names:
            if not name.endswith(".py") or name.startswith("test_"):
                continue
            tree = ast.parse(open(os.path.join(root, name)).read())
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                dicts = [n for n in ast.walk(fn) if isinstance(n, ast.Dict)]
                creates = any(any(isinstance(k, ast.Constant) and k.value == "status" and isinstance(v, ast.Constant)
                                  and v.value == "PROVISIONING" for k, v in zip(d.keys, d.values)) for d in dicts)
                if not creates:
                    continue
                found.append(fn.name)
                if not any(isinstance(n, ast.Name) and n.id == "_freeze_new_workloads" for n in ast.walk(fn)):
                    offenders.append(f"{name}:{fn.name}")
                for d in dicts:
                    for k, v in zip(d.keys, d.values):
                        if isinstance(k, ast.Constant) and k.value == "code_freeze" and isinstance(v, ast.Constant):
                            hardcoded.append(f"{name}:{fn.name}")
    assert sorted(found) == ["create_workload", "deploy_workload_to_folder_endpoint"], found
    assert offenders == [] and hardcoded == []


def test_platform_record_keeps_its_own_freeze_logic(cc, monkeypatch):
    """bootstrap-castor is excluded: the record is always frozen, whatever the toggle says; it never reads it."""
    _, wl = cc
    src = open(os.path.join(CC_DIR, "routes", "workloads.py"), encoding="utf-8").read()
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == "bootstrap_castor_workload")
    assert not any(isinstance(n, ast.Name) and n.id == "_freeze_new_workloads" for n in ast.walk(fn))
    for toggle in (ON, OFF):
        fake_db = CcFakeDB()
        client = _client(wl, monkeypatch, fake_db)
        with patch.dict(os.environ, {"GITHUB_REPO": "example-org/stackvend"}), \
             patch.object(wl, "get_platform_settings", side_effect=lambda *a, **k: toggle):
            r = client.post("/api/workloads/bootstrap-castor", headers=ADMIN_H)
        assert r.status_code == 200, r.text
        assert fake_db["workloads/project-castor"]["code_freeze"] is True and r.json()["code_freeze"] is True


# ================================================================================================ 5. project vending
class _RecordUnreadableAfterStartDB(f.FakeDB):
    """SAT-38 VENDING-RECORD-UNREADABLE: a record that cannot be read at the START of a vend now stops it before
    anything is created, so `fail_read` makes the record unreadable from the second read on: the later read of the
    existing record's settings, which is what these tests cover (still swallowed there, as before)."""

    def __init__(self, path):
        super().__init__()
        self._path, self._reads = path, 0

    def _maybe_fail(self, path):
        if path == self._path:
            self._reads += 1
            if self._reads > 1:
                raise RuntimeError(f"503 Service Unavailable reading {path}")
        super()._maybe_fail(path)


@pytest.fixture
def vend(monkeypatch):
    """A vending engine on the destructive-guard fakes, with the shared settings reader the vending module imports
    patched to `settings` (an object, or a callable that raises)."""
    monkeypatch.delenv("STACKVEND_MANAGED_TAG_VALUE", raising=False)
    vending_mod = sys.modules[VENDING_MAIN.ProjectRepoVendingEngine.__module__]
    assert hasattr(vending_mod, "_freeze_new_workloads_default")

    def run(settings, pid="fresh-svc", initial=None, fail_read=False):
        live = importlib.import_module("shared.settings")
        live.invalidate_settings_cache()
        reader = settings if callable(settings) else (lambda *a, **k: settings)
        monkeypatch.setattr(live, "get_platform_settings", reader)
        db = _RecordUnreadableAfterStartDB(f"workloads/{pid}") if fail_read else f.FakeDB()
        for path, doc in (initial or {}).items():
            db.docs[path] = dict(doc)
        res = _vend_engine(VENDING_MAIN, db, _vend_crm()).vend_gcp_project(
            pid, "tr-1", folder_id=f.ROOT, force_new_project_id="fresh-svc-123abc")
        written = [w for w in db.writes if w[0] == "set" and w[1] == f"workloads/{pid}"]
        return res, db, written[-1][2]
    return run


@pytest.mark.parametrize("settings, frozen", [(ON, True), (OFF, False), (DEFAULT, True),
                                              (_raises(S.PlatformSettingsReadError("down")), True),
                                              (_raises(RuntimeError("boom")), True)])
def test_vending_a_new_record_sets_the_initial_freeze_from_the_toggle(vend, settings, frozen):
    res, db, record = vend(settings)
    assert res["status"] == "PROJECT_VENDED"   # the read never fails the vend
    assert record["code_freeze"] is frozen and db.doc("workloads/fresh-svc")["code_freeze"] is frozen


def test_vending_a_drive_intake_seed_applies_the_toggle(vend):
    """The gateway seeds only the access record of a Drive intake before vending: the workload is new."""
    seed = {"workloads/fresh-svc": {"product_id": "fresh-svc", "access": {"mode": "PRIVATE_IAP"}}}
    _, db, record = vend(ON, initial=seed)
    assert record["code_freeze"] is True and db.doc("workloads/fresh-svc")["access"] == {"mode": "PRIVATE_IAP"}


@pytest.mark.parametrize("stored, settings", [(False, ON), (True, OFF), (True, ON), (False, OFF)])
def test_revending_an_existing_record_never_changes_its_freeze(vend, stored, settings):
    initial = {"workloads/fresh-svc": {"product_id": "fresh-svc", "status": "PROVISIONING", "code_freeze": stored,
                                       "require_human_code_review": True}}
    _, db, record = vend(settings, initial=initial)
    assert "code_freeze" not in record   # the merge write leaves the stored value alone
    assert db.doc("workloads/fresh-svc")["code_freeze"] is stored


@pytest.mark.parametrize("settings, written", [(ON, True), (OFF, None)])
def test_vending_with_an_unreadable_record_only_ever_freezes(vend, settings, written):
    _, _, record = vend(settings, fail_read=True)
    assert record.get("code_freeze") is written


# ------------------------------------------------------------------ FD-4CU-b: SRE / scanner switches on re-vend
@pytest.mark.parametrize("sre, scan", [(False, False), (False, True), (True, False)])
def test_revending_keeps_the_sre_and_scanner_switches(vend, sre, scan):
    initial = {"workloads/fresh-svc": {"product_id": "fresh-svc", "status": "PROVISIONING", "code_freeze": False,
                                       "sre_auto_healing_enabled": sre, "refactor_scanner_enabled": scan}}
    _, db, record = vend(ON, initial=initial)
    assert "sre_auto_healing_enabled" not in record and "refactor_scanner_enabled" not in record
    doc = db.doc("workloads/fresh-svc")
    assert doc["sre_auto_healing_enabled"] is sre and doc["refactor_scanner_enabled"] is scan


def test_vending_a_new_or_seeded_record_turns_both_switches_on(vend):
    for initial in (None, {"workloads/fresh-svc": {"product_id": "fresh-svc", "access": {"mode": "PRIVATE_IAP"}}}):
        _, db, record = vend(ON, initial=initial)
        assert record["sre_auto_healing_enabled"] is True and record["refactor_scanner_enabled"] is True


def test_vending_an_unreadable_record_writes_neither_switch(vend):
    _, _, record = vend(ON, fail_read=True)
    assert "sre_auto_healing_enabled" not in record and "refactor_scanner_enabled" not in record


# ------------------------------------------------------------------ FD-4CU-c: vending's default code-review read
@pytest.mark.parametrize("settings, hitl", [(_settings(default_require_human_code_review=False), False),
                                            (_settings(default_require_human_code_review=True), True),
                                            (DEFAULT, True),
                                            (_raises(S.PlatformSettingsReadError("down")), True),
                                            (_raises(RuntimeError("boom")), True)])
def test_vending_honours_the_default_code_review_setting(vend, settings, hitl):
    """Before FD-4CU-c the read used a non-existent engine attribute, always failed and kept review on."""
    seen = []

    def reader(*a, **k):
        seen.append(k)
        return settings(*a, **k) if callable(settings) else settings
    _, _, record = vend(reader)
    assert record["require_human_code_review"] is hitl and record["auto_merge"] is (not hitl)
    assert {"project_id": f.HOST, "strict": True} in seen   # the engine's platform project, strict


def test_vending_keeps_an_existing_review_choice_over_the_setting(vend):
    initial = {"workloads/fresh-svc": {"product_id": "fresh-svc", "require_human_code_review": True}}
    _, _, record = vend(_settings(default_require_human_code_review=False), initial=initial)
    assert record["require_human_code_review"] is True and record["auto_merge"] is False


@pytest.mark.parametrize("settings", [_settings(default_require_human_code_review=False),
                                      _settings(default_require_human_code_review=True), DEFAULT])
def test_vending_an_unreadable_record_never_writes_the_review_fields(vend, settings):
    """Re-check R2-1: a transient read error on an existing reviewed workload must never write
    require_human_code_review False / auto_merge True from the platform default; neither field is written."""
    initial = {"workloads/fresh-svc": {"product_id": "fresh-svc", "status": "PROVISIONING",
                                       "require_human_code_review": True, "auto_merge": False}}
    _, db, record = vend(settings, initial=initial, fail_read=True)
    assert "require_human_code_review" not in record and "auto_merge" not in record
    doc = db.doc("workloads/fresh-svc")
    assert doc["require_human_code_review"] is True and doc["auto_merge"] is False


def test_an_absent_review_field_means_review_required_downstream():
    """The omission above is safe: the release gatekeeper and the gateway's merge decision read only
    require_human_code_review, and anything but an explicit False requires a human."""
    gw_src = open(os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "main.py"), encoding="utf-8").read()
    gk_src = open(os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "release_gatekeeper.py"),
                  encoding="utf-8").read()
    assert 'require_review = not (wdata.get("require_human_code_review") is False)' in gw_src
    assert 'require_human = workload_policy.get("require_human_code_review") is not False' in gk_src


def test_vending_engine_has_no_other_project_id_attribute_reads():
    src = open(os.path.join(REPO_ROOT, "apps", "project-vending", "vending.py"), encoding="utf-8").read()
    uses = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Attribute) and n.attr == "project_id"
            and isinstance(n.value, ast.Name) and n.value.id == "self"]
    assert uses == []


def test_vending_toggle_changes_nothing_else_in_the_record(vend):
    _, _, rec_on = vend(ON)
    _, _, rec_off = vend(OFF)
    volatile = {"created_at", "spend_last_updated_at"}
    rec_on = {k: v for k, v in rec_on.items() if k not in volatile}
    rec_off = {k: v for k, v in rec_off.items() if k not in volatile}
    assert rec_on.pop("code_freeze") is True and rec_off.pop("code_freeze") is False
    assert rec_on == rec_off
    assert rec_on["sre_auto_healing_enabled"] is True and rec_on["refactor_scanner_enabled"] is True


# ================================================================================================ 6. gateway seed (Drive)
from fd4f_support import FakeDB as GwFakeDB, gw  # noqa: E402,F401  (gw: fixture)
from test_settings_toggles import _gw_settings, _intake  # noqa: E402


@pytest.mark.parametrize("settings, frozen", [(ON, True), (OFF, False), (DEFAULT, True)])
def test_drive_intake_seed_is_frozen_atomically_from_the_toggle(gw, monkeypatch, settings, frozen):
    """Review fix 3: the seeded first record carries code_freeze (one create() with the access record), so the page
    never shows a Drive workload unfrozen before vending; vending then keeps the value."""
    _gw_settings(monkeypatch, lambda **k: settings)
    db = GwFakeDB()
    r, created = _intake(gw, monkeypatch, db, {"product_id": "drive-app", "trace_id": "tr-4cu-1",
                                               "source_channel": "google_docs"})
    assert r.status_code == 200, r.text
    assert len(created) == 1
    assert db.docs["workloads/drive-app"]["code_freeze"] is frozen


@pytest.mark.parametrize("err", [S.PlatformSettingsReadError("down"), RuntimeError("boom")])
def test_seed_with_an_unreadable_setting_is_frozen_and_still_written(gw, monkeypatch, err):
    import shared.settings as gw_settings
    gw_settings.invalidate_settings_cache()
    monkeypatch.setattr(gw_settings, "get_platform_settings", _raises(err))
    db = GwFakeDB()
    # FD-4CI-b-R1: the seed returns the seeded branch (truthy) instead of True; unreadable settings -> main
    assert gw._seed_platform_default_access(db, "drive-app") == "main"
    assert db.docs["workloads/drive-app"]["code_freeze"] is True
    monkeypatch.setitem(sys.modules, "shared.settings", SimpleNamespace())   # reader missing -> frozen
    assert gw._freeze_new_workloads_setting() is True


def test_seed_never_touches_an_existing_workload(gw, monkeypatch):
    _gw_settings(monkeypatch, lambda **k: ON)
    db = GwFakeDB()
    db.docs["workloads/drive-app"] = {"product_id": "drive-app", "code_freeze": False}
    assert gw._seed_platform_default_access(db, "drive-app") is None   # FD-4CI-b-R1: None (was False) = not seeded
    assert db.docs["workloads/drive-app"] == {"product_id": "drive-app", "code_freeze": False}


# ================================================================================================ 7. Settings API + page
def test_cc_admin_toggle_is_saved_and_audited(cc_settings):
    rs, doc_ref = cc_settings
    request = MagicMock()
    request.state.user_role, request.state.user_email = rs.UserRole.ADMIN, "admin@example.com"
    out = rs.update_settings_api(_settings(freeze_new_workloads=False), request)
    (stored,), _ = doc_ref.set.call_args
    assert stored["governance"]["freeze_new_workloads"] is False and out.governance.freeze_new_workloads is False
    entry = out.audit_log[0]
    assert entry.admin_email == "admin@example.com" and entry.action == "UPDATE_SETTINGS"
    assert entry.changed_fields["governance.freeze_new_workloads"] == {"from": True, "to": False}
    # and the stored document reads back through the strict reader as off
    assert S.freeze_new_workloads_enabled(read=lambda **k: S.platform_settings_from_stored(stored)) is False


def test_cc_non_admin_cannot_change_the_toggle(cc_settings):
    rs, doc_ref = cc_settings
    from fastapi import HTTPException
    for role in [r for r in rs.UserRole if r != rs.UserRole.ADMIN]:
        request = MagicMock()
        request.state.user_role, request.state.user_email = role, "someone@example.com"
        with pytest.raises(HTTPException) as ei:
            rs.update_settings_api(_settings(freeze_new_workloads=False), request)
        assert ei.value.status_code == 403
    doc_ref.set.assert_not_called()


def test_cc_settings_page_has_the_toggle_and_explains_it():
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    key = 'x-model="platformSettings.governance.freeze_new_workloads"'
    assert html.count(key) == 1
    block = html[html.index(key):html.index(key) + 2000]
    assert "Freeze new workloads by default" in block
    for phrase in ("On by default", "SRE auto-healing", "scanner", "Upgrade IaC", "Unfreeze",
                   "The first build and deploy of its spec still run", "affects new workloads only",
                   "existing workloads keep their current freeze"):
        assert phrase in block, phrase
