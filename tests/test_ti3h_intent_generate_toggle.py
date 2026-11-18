"""TI-3h (owner 10-21, register row TI-3h): typed infrastructure (generate mode) is switched per install from Control
Center Settings -- governance.iac_intent_generate -- instead of a code-default flip. GEN-DEFAULT (owner 10-26): the
schema default is on, so a fresh install (no stored document, or a document without the key) is in generate mode; an
explicitly stored value (off included) is kept.

* shared reader: exactly True on a strict read -> on (the default included); False, non-bool, unreadable -> off
  (never raises).
* gateway: the developer run's HallucinationStackSettings.iac_intent_mode is "generate" only when the install's
  setting is exactly True; without the hallucination stack the setting does not apply (not even read); a reader error
  is "off" and never fails the run; TI-3e stickiness is unchanged (an intent workload stays on the intent path, a
  legacy workload stays legacy, whatever the setting says).
* eval harness: the mode is passed explicitly ("off" too), and the harness runtime has no settings reader.
* Control Center: the toggle is saved through the audited, admin-only PUT /api/settings, and the page explains it.
Hermetic: fakes only, no Firestore.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import os
import sys
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(TESTS, ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
EVAL_DIR = os.path.join(REPO_ROOT, "eval")
for p in (TESTS, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import settings as S  # noqa: E402
from test_typed_iac_ti3_contract import (ART, STICKY_REPO, UPLOADS, W, C, II, Client, _agent,  # noqa: E402
                                         _runtime, intent, topo, vt_of, BUCKET_MODULE)
from test_typed_iac_ti3_rt_fixes import _committed  # noqa: E402

SETTINGS_COPIES = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared",
                   "apps/project-vending/shared", "apps/spec-ingestion/shared", "mcp-servers/terraform/shared"]


@pytest.fixture(autouse=True)
def _no_firestore_and_fresh_cache():
    S.invalidate_settings_cache()
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield
    S.invalidate_settings_cache()


def _settings(**gov):
    return S.PlatformSettings(governance=gov)


def _raises(err):
    def read(*a, **k):
        raise err
    return read


def _never_read(*a, **k):
    raise AssertionError("the platform setting must not be read here")


# ================================================================================================ 1. shared reader
def test_setting_defaults_on_in_the_schema_and_the_reader():
    # GEN-DEFAULT (owner 10-26): generate mode ships on by default
    assert S.PlatformSettings().governance.iac_intent_generate is True
    assert S.GovernanceSettings.model_fields["iac_intent_generate"].annotation is bool
    assert S.GovernanceSettings.model_fields["iac_intent_generate"].default is True
    assert S.iac_intent_generate_enabled(read=lambda **k: S.PlatformSettings()) is True


def _stored(doc):
    """Patch the one Firestore read of get_platform_settings: `doc` is the stored mapping (None = no document)."""
    return patch.object(S, "_read_stored_document", lambda project_id: copy.deepcopy(doc))


@pytest.mark.parametrize("doc", [None, {}, {"governance": {}}, {"governance": {"maintenance_mode": False}}],
                         ids=["no-document", "empty-document", "empty-governance", "governance-without-the-key"])
def test_gen_default_a_fresh_settings_document_resolves_to_generate_mode(doc):
    """GEN-DEFAULT: with no stored value the real strict read gives the schema default -> on."""
    with _stored(doc):
        assert S.get_platform_settings(force_refresh=True, strict=True).governance.iac_intent_generate is True
        S.invalidate_settings_cache()
        assert S.iac_intent_generate_enabled(project_id="host-p") is True
        S.invalidate_settings_cache()
        # gateway end to end: a new typed-topology workload goes on the intent path
        agent = _gw_agent(lambda project_id=None: S.iac_intent_generate_enabled(project_id=project_id))
        assert agent._resolve_intent_run(_ci(), {}, READY) is not None


def test_gen_default_an_explicit_stored_off_stays_off():
    """Negative: the default never overrides an explicitly stored value (an install that turned it off, or saved the
    form while the old default was off)."""
    doc = {"governance": {"iac_intent_generate": False}}
    with _stored(doc):
        assert S.get_platform_settings(force_refresh=True, strict=True).governance.iac_intent_generate is False
        S.invalidate_settings_cache()
        assert S.iac_intent_generate_enabled(project_id="host-p") is False
        S.invalidate_settings_cache()
        agent = _gw_agent(lambda project_id=None: S.iac_intent_generate_enabled(project_id=project_id))
        with patch.object(II, "load_artifacts", side_effect=AssertionError("artifacts read on mode off")):
            assert agent._resolve_intent_run(_ci(), {}, READY) is None
    # and an explicit stored on stays on
    S.invalidate_settings_cache()
    with _stored({"governance": {"iac_intent_generate": True}}):
        assert S.iac_intent_generate_enabled() is True


def test_gen_default_does_not_move_existing_workloads_off_their_path():
    """The default changes only what a NEW workload does: a legacy workload stays legacy with the setting on."""
    with _stored(None):
        agent = _gw_agent(lambda project_id=None: S.iac_intent_generate_enabled(project_id=project_id))
        assert agent._resolve_intent_run(_ci(), {W + "custom.tf": 'resource "x" "y" {}'}, READY) is None


def test_gen_default_invalid_stored_document_is_off():
    """Unreadable / invalid settings keep it off, as before (the default is not substituted for a bad document)."""
    with _stored({"governance": {"iac_intent_generate": "yes please"}}):
        assert S.iac_intent_generate_enabled() is False


def test_reader_is_on_only_when_exactly_true_on_a_strict_read():
    seen = {}

    def read(**k):
        seen.update(k)
        return _settings(iac_intent_generate=True)
    assert S.iac_intent_generate_enabled(project_id="host-p", read=read) is True
    assert seen == {"project_id": "host-p", "strict": True}
    assert S.iac_intent_generate_enabled(read=lambda **k: _settings(iac_intent_generate=False)) is False
    for odd in ("true", 1, None):   # not exactly True (a hand-edited document read without the schema)
        ns = SimpleNamespace(governance=SimpleNamespace(iac_intent_generate=odd))
        assert S.iac_intent_generate_enabled(read=lambda **k: ns) is False
    assert S.iac_intent_generate_enabled(read=lambda **k: SimpleNamespace()) is False   # no governance section


@pytest.mark.parametrize("err", [S.PlatformSettingsReadError("down"), S.PlatformSettingsInvalid("bad"),
                                 RuntimeError("anything else")])
def test_reader_is_off_when_settings_cannot_be_read(err):
    assert S.iac_intent_generate_enabled(read=_raises(err)) is False


def test_reader_end_to_end_store_unreadable_is_off():
    # the autouse patch makes the Firestore client raise: a real read fails -> off, no exception
    assert S.iac_intent_generate_enabled() is False


def test_settings_copies_are_byte_identical_and_carry_the_setting():
    root = open(os.path.join(REPO_ROOT, "shared", "settings.py"), "rb").read()
    assert b"iac_intent_generate: bool = Field(" in root and b"def iac_intent_generate_enabled(" in root
    for d in SETTINGS_COPIES:
        assert open(os.path.join(REPO_ROOT, d, "settings.py"), "rb").read() == root, d


# ================================================================================================ 2. gateway
READY = {"provider_versions": Client().ready()["provider_versions"]}


def _ci(resources=(UPLOADS,)):
    from developer_agent.compute_intent import ComputeIntent
    ci = MagicMock(spec=ComputeIntent)
    ci.topology = vt_of(topo(list(resources)))
    return ci


def _gw_agent(reader, **settings):
    """A developer agent whose runtime is the gateway's shape: the stack configured and a platform-setting reader."""
    return _agent(replace(_runtime(Client(), **settings), intent_generate_setting=reader))


def _reader(value, calls=None):
    def read(**k):
        if calls is not None:
            calls.append(k)
        return value
    return read


def test_gateway_default_off_keeps_the_legacy_contract_and_never_loads_the_intent_artifacts():
    agent = _gw_agent(_reader(False))
    with patch.object(II, "load_artifacts", side_effect=AssertionError("artifacts read on mode off")):
        assert agent._resolve_intent_run(_ci(), {}, READY) is None
    # the runtime's code default stays "off" (harness / no reader); the install default is the platform setting
    from shared.hallucination_stack import HallucinationStackSettings
    assert HallucinationStackSettings().iac_intent_mode == "off"


def test_gateway_setting_true_puts_a_new_workload_on_the_intent_path():
    calls = []
    agent = _gw_agent(_reader(True, calls))
    agent.project_id = "host-p"
    run = agent._resolve_intent_run(_ci(), {}, READY)
    assert run is not None
    assert calls == [{"project_id": "host-p"}]
    # the runtime's own settings object is not changed: the next run reads the setting again
    assert agent.stack_runtime().settings.iac_intent_mode == "off"


@pytest.mark.parametrize("value", ["true", 1, None, "generate"])
def test_gateway_setting_not_exactly_true_is_off(value):
    assert _gw_agent(_reader(value))._resolve_intent_run(_ci(), {}, READY) is None


@pytest.mark.parametrize("err", [S.PlatformSettingsReadError("down"), RuntimeError("boom"), ImportError("x")])
def test_gateway_unreadable_setting_is_off_and_never_fails_the_run(err):
    agent = _gw_agent(_raises(err))
    with patch.object(II, "load_artifacts", side_effect=AssertionError("artifacts read on mode off")):
        assert agent._resolve_intent_run(_ci(), {}, READY) is None


def test_gateway_real_reader_with_unreadable_firestore_is_off():
    agent = _gw_agent(lambda project_id=None: S.iac_intent_generate_enabled(project_id=project_id))
    assert agent._resolve_intent_run(_ci(), {}, READY) is None


def test_without_the_validation_stack_the_setting_does_not_apply_and_is_not_read():
    agent = _gw_agent(_never_read)
    assert agent._resolve_intent_run(_ci(), {}, None) is None
    # even a setting that would say "on": no stack -> legacy contract, no failure
    assert _gw_agent(_reader(True))._resolve_intent_run(_ci(), {}, None) is None


def test_sticky_intent_workload_stays_on_the_intent_path_with_the_setting_off():
    existing = _committed(vt_of(topo([UPLOADS])), intent([BUCKET_MODULE]))
    for value in (False, True):
        assert _gw_agent(_reader(value))._resolve_intent_run(_ci(), existing, READY) is not None
    # the sticky fail-closed rules are unchanged: no stack for a sticky workload is GATE_UNAVAILABLE
    from developer_agent.handler import StageError
    with pytest.raises(StageError):
        _gw_agent(_never_read)._resolve_intent_run(_ci(), STICKY_REPO, None)


def test_legacy_workload_stays_legacy_with_the_setting_on():
    legacy = {W + "custom.tf": 'resource "google_storage_bucket" "uploads" {}\n'}
    with patch.object(II, "load_artifacts", side_effect=AssertionError("artifacts read for a legacy workload")):
        assert _gw_agent(_reader(True))._resolve_intent_run(_ci(), legacy, READY) is None


def test_network_bound_topology_takes_the_intent_path_with_the_setting_on():
    """TI-5c (owner 10-21, replaces TI-3f): the platform supplies the network fact, so a Cloud SQL topology is no
    longer kept on today's (legacy) path when the setting is on; with the setting off nothing changes."""
    cloudsql = {"type": "google_sql_database_instance", "logical_name": "db", "purpose": "app database",
                "consumers": [{"service": "shop", "env_key": "DB_CONNECTION", "attribute": None}]}
    assert _gw_agent(_reader(True))._resolve_intent_run(_ci([cloudsql]), {}, READY) is not None
    assert _gw_agent(_reader(False))._resolve_intent_run(_ci([cloudsql]), {}, READY) is None


def test_runtime_without_a_reader_keeps_its_own_settings():
    """Eval harness / unit tests: no platform reader; the explicit runtime mode decides (generate and off)."""
    assert _agent(_runtime(Client(), iac_intent_mode="generate"))._resolve_intent_run(_ci(), {}, READY) is not None
    assert _agent(_runtime(Client(), iac_intent_mode="off"))._resolve_intent_run(_ci(), {}, READY) is None
    assert _agent(_runtime(Client()))._resolve_intent_run(_ci(), {}, READY) is None


def test_gateway_startup_attaches_the_platform_setting_reader(monkeypatch):
    from fd4f_support import load_gateway
    mod = load_gateway(monkeypatch, name="ti3h_gw_main")
    try:
        rt = mod.developer_agent.stack_runtime()
        assert rt.intent_generate_setting is mod._iac_intent_generate_setting
        seen = {}

        def fake(*, project_id=None, read=None):
            seen["project_id"] = project_id
            return True
        monkeypatch.setattr(S, "iac_intent_generate_enabled", fake)
        monkeypatch.setitem(sys.modules, "shared.settings", S)
        assert rt.intent_generate_setting(project_id="host-p") is True and seen == {"project_id": "host-p"}
    finally:
        mod.app.dependency_overrides.clear()


def test_harness_runtime_has_no_platform_reader():
    from developer_agent import hallucination_runtime as hr
    try:
        hr.configure_for_harness(validate_client=None, settings_overrides={"iac_intent_mode": "off"})
        rt = hr.get_runtime()
        assert rt.intent_generate_setting is None and rt.settings.iac_intent_mode == "off"
    finally:
        hr.reset_for_tests()


# ================================================================================================ 3. eval harness
def test_harness_passes_the_mode_explicitly_off_included():
    src_stages = open(os.path.join(EVAL_DIR, "stackvend_eval", "stages.py"), encoding="utf-8").read()
    src_child = open(os.path.join(EVAL_DIR, "run_child.py"), encoding="utf-8").read()
    src_examples = open(os.path.join(EVAL_DIR, "run_examples.py"), encoding="utf-8").read()
    assert 'if iac_intent_mode:   # TI-3h' in src_stages
    assert 'cfg.get("iac_intent_mode") is not None' in src_child
    assert 'cfg["iac_intent_mode"] = getattr(a, "iac_intent_mode", "off")' in src_examples


def test_harness_install_records_an_explicit_off_override(monkeypatch, tmp_path):
    if EVAL_DIR not in sys.path:
        monkeypatch.syspath_prepend(EVAL_DIR)
    from stackvend_eval import stages as st
    captured = {}
    fake_rt = SimpleNamespace(configure_for_harness=lambda **k: captured.update(k) or {"source": "harness"})
    monkeypatch.setattr(st.importlib, "import_module", lambda name: fake_rt)
    out = st.install_hallucination_runtime({}, run_dir=tmp_path, validate_client="harness", repair_iterations=None,
                                           repair_model=None, iac_intent_mode="off")
    assert out["installed"] is True and captured["settings_overrides"] == {"iac_intent_mode": "off"}
    st.install_hallucination_runtime({}, run_dir=tmp_path, validate_client="harness", repair_iterations=None,
                                     repair_model=None)
    assert captured["settings_overrides"] == {}


# ================================================================================================ 4. Control Center
class _Doc:
    def __init__(self, data):
        self.exists, self._data = data is not None, data

    def to_dict(self):
        return copy.deepcopy(self._data)


class _SettingsStore:
    def __init__(self, data=None):
        self.data = data

    def collection(self, name):
        return self

    def document(self, name):
        return self

    def get(self):
        return _Doc(self.data)


@pytest.fixture
def cc_settings(monkeypatch):
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
    wire_settings_writes(cc_store, doc_ref)   # FD-4CI-b-R3: preconditioned settings write
    store = _SettingsStore({"governance": {"iac_intent_generate": False}})
    monkeypatch.setattr("google.cloud.firestore.Client", lambda *a, **k: store)
    for name in ("shared.settings", "shared_settings"):
        mod = sys.modules.get(name)
        if mod is not None and hasattr(mod, "invalidate_settings_cache"):
            mod.invalidate_settings_cache()
    return rs, doc_ref


def test_cc_admin_toggle_is_saved_and_audited(cc_settings):
    rs, doc_ref = cc_settings
    request = MagicMock()
    request.state.user_role, request.state.user_email = rs.UserRole.ADMIN, "admin@example.com"
    out = rs.update_settings_api(_settings(iac_intent_generate=True), request)
    (stored,), _ = doc_ref.set.call_args
    assert stored["governance"]["iac_intent_generate"] is True and out.governance.iac_intent_generate is True
    entry = out.audit_log[0]
    assert entry.admin_email == "admin@example.com" and entry.action == "UPDATE_SETTINGS"
    assert entry.changed_fields["governance.iac_intent_generate"] == {"from": False, "to": True}


def test_cc_non_admin_cannot_change_the_toggle(cc_settings):
    rs, doc_ref = cc_settings
    from fastapi import HTTPException
    for role in [r for r in rs.UserRole if r != rs.UserRole.ADMIN]:
        request = MagicMock()
        request.state.user_role, request.state.user_email = role, "someone@example.com"
        with pytest.raises(HTTPException) as ei:
            rs.update_settings_api(_settings(iac_intent_generate=True), request)
        assert ei.value.status_code == 403
    doc_ref.set.assert_not_called()


def test_cc_settings_put_route_is_admin_only():
    src = open(os.path.join(CC_DIR, "routes", "settings.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "update_settings_api")
    decos = [ast.unparse(d) for d in fn.decorator_list]
    assert any("router.put('/api/settings'" in d and "require(ADMIN)" in d for d in decos), decos


def test_cc_settings_page_has_the_toggle_and_explains_it():
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    assert 'x-model="platformSettings.governance.iac_intent_generate"' in html
    i = html.index('x-model="platformSettings.governance.iac_intent_generate"')
    block = html[i:i + 2000]
    assert "Typed infrastructure (generate mode)" in block
    # TI-5c + TI-5-R2 (owner 10-21): Cloud SQL, Redis, AlloyDB, Vertex AI endpoints and Bigtable are on the typed path
    for phrase in ("new workloads only", "keep their current path",
                   "Cloud SQL, Redis, AlloyDB, Vertex AI endpoints or Bigtable are built this way too",
                   "Turning it off affects new workloads only"):
        assert phrase in block, phrase
