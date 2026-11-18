"""settings-toggles (FD-4AK Fable RT F5): the three governance toggles that had no reader now do something.

* maintenance_mode -- no new run starts: Control Center create / retrigger / deploy-infra / deploy-to-folder /
  redeploy, the Docs intake service and gateway dispatch answer 503 MAINTENANCE_MODE. Runs in flight, settings,
  approvals and decommission are untouched.
* require_hitl_for_destructive_tf -- the terraform MCP gated apply stops a plan that deletes / replaces a resource
  (DESTROY_REQUIRES_APPROVAL, an operator class).
* strict_compliance_gates -- a compliance profile advisory makes the pre-build gate wait for a human.

Each toggle: on / off / unreadable (strict read, fail closed), plus Do No Harm (off, or nothing to decide -> exactly
today's behavior; the settings are not even read when there is nothing to decide). Hermetic: fakes only.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import base64
import copy
import importlib.util
import json
import os
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
SPEC_DIR = os.path.join(REPO_ROOT, "apps", "spec-ingestion")
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.dirname(__file__))

from shared import settings as S  # noqa: E402


def _settings(**gov):
    return S.PlatformSettings(governance=gov)


def _raises(err):
    def read(*a, **k):
        raise err
    return read


def _never_read(*a, **k):
    raise AssertionError("the settings must not be read when there is nothing to decide")


@pytest.fixture(autouse=True)
def _fresh_settings_caches():
    def clear():
        for name in ("shared.settings", "shared_settings"):
            mod = sys.modules.get(name)
            if mod is not None and hasattr(mod, "invalidate_settings_cache"):
                mod.invalidate_settings_cache()
        S.invalidate_settings_cache()
    clear()
    yield
    clear()


ERRORS = [S.PlatformSettingsReadError("down"), S.PlatformSettingsInvalid("bad"), RuntimeError("anything else")]
ERROR_CODES = ["PLATFORM_SETTINGS_READ_FAILED", "PLATFORM_SETTINGS_INVALID", "PLATFORM_SETTINGS_UNAVAILABLE"]


# ================================================================================================ 1. shared readers
def test_maintenance_refusal_on_off_unknown():
    on = S.maintenance_refusal(_settings(maintenance_mode=True), "workload creation")
    assert on["code"] == "MAINTENANCE_MODE" and on["errors"] == []
    assert "workload creation was refused" in on["message"] and "in progress continue" in on["message"]
    assert "approvals and decommission still work" in on["message"]
    assert S.maintenance_refusal(_settings(maintenance_mode=False), "x") is None
    assert S.maintenance_refusal(S.PlatformSettings(), "x") is None            # schema default: off
    for unknown in (None, SimpleNamespace(), SimpleNamespace(governance=SimpleNamespace(maintenance_mode="yes"))):
        assert S.maintenance_refusal(unknown, "x")["code"] == "PLATFORM_SETTINGS_UNAVAILABLE"


@pytest.mark.parametrize("err, code", list(zip(ERRORS, ERROR_CODES)))
def test_new_run_refusal_fails_closed_on_unreadable_settings(err, code):
    out = S.new_run_refusal("retrigger", read=_raises(err))
    assert out["code"] == code and "retrigger was refused" in out["message"]


def test_new_run_refusal_reads_strictly_and_passes_project():
    seen = {}

    def read(**kw):
        seen.update(kw)
        return _settings(maintenance_mode=False)
    assert S.new_run_refusal("x", project_id="host-p", read=read) is None
    assert seen == {"project_id": "host-p", "strict": True}


class _Doc:
    def __init__(self, data):
        self.exists, self._data = data is not None, data

    def to_dict(self):
        return copy.deepcopy(self._data)


class _SettingsStore:
    def __init__(self, data=None, error=None):
        self.data, self.error, self.reads = data, error, 0

    def collection(self, name):
        assert name == "system_config"
        return self

    def document(self, name):
        assert name == "platform_settings"
        return self

    def get(self):
        self.reads += 1
        if self.error is not None:
            raise self.error
        return _Doc(self.data)


def _store(monkeypatch, data=None, error=None):
    store = _SettingsStore(data, error)
    monkeypatch.setattr("google.cloud.firestore.Client", lambda *a, **k: store)
    return store


def test_new_run_refusal_end_to_end_store(monkeypatch):
    _store(monkeypatch, {"governance": {"maintenance_mode": True}})
    assert S.new_run_refusal("x")["code"] == "MAINTENANCE_MODE"
    S.invalidate_settings_cache()
    _store(monkeypatch, None)                                    # fresh install: the defaults are the settings
    assert S.new_run_refusal("x") is None
    S.invalidate_settings_cache()
    _store(monkeypatch, {"governance": {"maintenance_mode": True}, "finops": {"default_monthly_budget_usd": "forty"}})
    assert S.new_run_refusal("x")["code"] == "PLATFORM_SETTINGS_INVALID"
    S.invalidate_settings_cache()
    _store(monkeypatch, error=RuntimeError("firestore down"))
    assert S.new_run_refusal("x")["code"] == "PLATFORM_SETTINGS_READ_FAILED"


@pytest.mark.parametrize("fn, field", [(S.destructive_tf_requires_approval, "require_hitl_for_destructive_tf"),
                                       (S.compliance_advisories_block, "strict_compliance_gates")])
def test_boolean_governance_readers_on_off_unreadable(fn, field):
    assert fn(read=lambda **k: _settings(**{field: True})) is True
    assert fn(read=lambda **k: _settings(**{field: False})) is False
    assert fn(read=lambda **k: S.PlatformSettings()) is True               # schema default: on
    for err in ERRORS:
        assert fn(read=_raises(err)) is True                               # unreadable: the safe value
    assert fn(read=lambda **k: SimpleNamespace()) is True                  # no governance section: unknown


def test_advisories_block_is_subordinate_to_the_autonomous_plan_approval_policy():
    """ST-3 RT F8: plan_approval_policy AUTONOMOUS_UNLESS_FAILED -> advisories never hold the run."""
    read = lambda pol, strict=True: (lambda **k: _settings(strict_compliance_gates=strict,  # noqa: E731
                                                            plan_approval_policy=pol))
    assert S.compliance_advisories_block(read=read("AUTONOMOUS_UNLESS_FAILED")) is False
    assert S.compliance_advisories_block(read=read("ON_COMPLIANCE_CONFLICT")) is True
    assert S.compliance_advisories_block(read=read("ALWAYS")) is True
    assert S.compliance_advisories_block(read=read("ON_COMPLIANCE_CONFLICT", strict=False)) is False


@pytest.mark.parametrize("name", ["settings.py", "gemini_model_config.py"])
def test_spec_ingestion_copies_are_byte_identical_to_root(name):
    root = open(os.path.join(REPO_ROOT, "shared", name), "rb").read()
    assert open(os.path.join(SPEC_DIR, "shared", name), "rb").read() == root


# ================================================================================================ 2. Control Center
@pytest.fixture
def cc(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    monkeypatch.setattr(cc_db, "_db_client", False)
    from routes import workloads as wl
    mock_db = MagicMock()
    monkeypatch.setattr(wl, "db", mock_db)
    publisher = MagicMock()
    monkeypatch.setattr(wl, "get_pubsub_publisher", lambda *a, **k: publisher)
    request = MagicMock()
    request.state.user_email, request.state.user_role = "admin@example.com", "ADMIN"
    return SimpleNamespace(wl=wl, db=mock_db, publisher=publisher, request=request)


def _cc_calls(cc):
    """Every Control Center endpoint that starts a new run, called with minimal valid arguments."""
    from schemas import CreateWorkloadRequest, DeployToFolderRequest
    wl, r = cc.wl, cc.request
    return {
        "create": lambda: wl.create_workload(CreateWorkloadRequest(product_id="shop-app", spec_content="a shop"), r),
        "retrigger": lambda: wl.retrigger_feature_request_build("shop-app", "fr-1", r),
        "retrigger_latest": lambda: wl.retrigger_workload_latest("shop-app", r),
        "deploy_infra": lambda: wl.deploy_workload_infra("shop-app", r),
        "deploy_to_folder": lambda: wl.deploy_workload_to_folder_endpoint(
            "shop-app", DeployToFolderRequest(destination_folder_id="111", new_product_id="shop-app-eu", target_branch="eu"), r),
        "redeploy": lambda: wl.redeploy_workload_endpoint("shop-app", r),
    }


@pytest.mark.parametrize("endpoint", ["create", "retrigger", "retrigger_latest", "deploy_infra", "deploy_to_folder",
                                      "redeploy"])
def test_cc_new_run_endpoints_refuse_503_in_maintenance_before_any_side_effect(cc, monkeypatch, endpoint):
    from fastapi import HTTPException
    monkeypatch.setattr(cc.wl, "get_platform_settings", lambda **k: _settings(maintenance_mode=True))
    if endpoint == "retrigger_latest":   # its latest execution names a feature request -> the inner retrigger
        execution = MagicMock()
        execution.to_dict.return_value = {"request_id": "fr-1"}
        cc.db.collection.return_value.where.return_value.order_by.return_value.limit.return_value.stream \
            .return_value = [execution]
    with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}):
        with pytest.raises(HTTPException) as ei:
            _cc_calls(cc)[endpoint]()
    assert ei.value.status_code == 503 and ei.value.detail["code"] == "MAINTENANCE_MODE"
    assert "in progress continue" in ei.value.detail["message"]
    if endpoint != "retrigger_latest":   # latest reads its executions first (read-only), then the same gate refuses
        cc.db.collection.assert_not_called()
    else:
        assert [c.args for c in cc.db.collection.call_args_list] == [("pipeline_executions",)]
    cc.db.collection.return_value.document.return_value.set.assert_not_called()
    cc.publisher.publish.assert_not_called()


@pytest.mark.parametrize("endpoint", ["retrigger", "deploy_infra", "deploy_to_folder", "redeploy"])
@pytest.mark.parametrize("err", ERRORS[:2])
def test_cc_new_run_endpoints_refuse_503_when_settings_unreadable(cc, monkeypatch, endpoint, err):
    from fastapi import HTTPException
    monkeypatch.setattr(cc.wl, "get_platform_settings", _raises(err))
    with pytest.raises(HTTPException) as ei:
        _cc_calls(cc)[endpoint]()
    assert ei.value.status_code == 503 and ei.value.detail["code"] == err.code
    cc.db.collection.assert_not_called()
    cc.publisher.publish.assert_not_called()


@pytest.mark.parametrize("endpoint", ["retrigger", "deploy_infra"])
def test_cc_negative_maintenance_off_passes_the_gate_unchanged(cc, monkeypatch, endpoint):
    """Do No Harm: maintenance off -> the endpoint continues to its own next step (here: the existing no-db 503)."""
    from fastapi import HTTPException
    monkeypatch.setattr(cc.wl, "get_platform_settings", lambda **k: _settings(maintenance_mode=False))
    monkeypatch.setattr(cc.wl, "db", None)
    with pytest.raises(HTTPException) as ei:
        _cc_calls(cc)[endpoint]()
    assert ei.value.status_code == 503 and ei.value.detail == "Firestore database unavailable"


def test_cc_helper_does_not_reread_when_the_caller_already_read(cc, monkeypatch):
    monkeypatch.setattr(cc.wl, "get_platform_settings", _never_read)
    assert cc.wl._refuse_new_run_in_maintenance("workload creation", S.PlatformSettings()) is None


def _calls_gate(fn: ast.FunctionDef) -> bool:
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_refuse_new_run_in_maintenance"
               for n in ast.walk(fn))


def test_cc_exactly_the_new_run_endpoints_call_the_gate():
    """Admin operations (decommission, archive, budget, policies, sandbox, approvals, settings) and actions on a run
    already in flight (resume-cooldown, lock release) are not gated."""
    tree = ast.parse(open(os.path.join(CC_DIR, "routes", "workloads.py"), encoding="utf-8").read())
    gated = {n.name for n in tree.body if isinstance(n, ast.FunctionDef) and _calls_gate(n)}
    assert gated == {"create_workload", "retrigger_feature_request_build", "deploy_workload_infra",
                     "redeploy_workload_endpoint", "deploy_workload_to_folder_endpoint"}
    for other in ("approvals.py", "settings.py", "telemetry.py", "finops.py", "users.py"):
        src = open(os.path.join(CC_DIR, "routes", other), encoding="utf-8").read()
        assert "_refuse_new_run_in_maintenance" not in src, other


def test_cc_admin_can_turn_maintenance_off_while_it_is_on(monkeypatch):
    """The settings write path is never gated: an admin turns maintenance mode off during maintenance."""
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
    _store(monkeypatch, {"governance": {"maintenance_mode": True}})
    request = MagicMock()
    request.state.user_role, request.state.user_email = rs.UserRole.ADMIN, "admin@example.com"
    out = rs.update_settings_api(_settings(maintenance_mode=False), request)
    (stored,), _ = doc_ref.set.call_args
    assert stored["governance"]["maintenance_mode"] is False and out.governance.maintenance_mode is False


def test_cc_settings_page_describes_what_maintenance_mode_does():
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    assert "503 MAINTENANCE_MODE" in html and "Runs already in progress continue" in html


# ================================================================================================ 3. gateway dispatch
from fd4f_support import FakeDB, gw  # noqa: E402,F401  (gw is a fixture)

TRACE, PID = "tr-toggles-1", "app"


def _envelope(payload):
    return {"message": {"data": base64.b64encode(json.dumps(payload).encode()).decode(), "messageId": "m1"}}


def _gw_settings(monkeypatch, read):
    import shared.settings as gw_settings   # the module the gateway's lazy import resolves to
    gw_settings.invalidate_settings_cache()
    monkeypatch.setattr(gw_settings, "get_platform_settings", read)


def _intake(gw, monkeypatch, db, payload=None):
    from fastapi.testclient import TestClient
    import google.cloud.firestore as fs_mod

    monkeypatch.setattr(fs_mod, "Client", lambda *a, **k: db)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    monkeypatch.setenv("REGION", "us-central1")   # FALLBACK-URLS: dispatch needs REGION (no default)
    created = []

    class _Exec:
        def __init__(self, argument=None):
            self.argument = argument

    class _Client:
        def workflow_path(self, *a):
            return "projects/p/locations/r/workflows/w"

        def create_execution(self, parent=None, execution=None):
            created.append(execution)
            return types.SimpleNamespace(name=parent + "/executions/e-1")

    fake_exec_mod = types.SimpleNamespace(ExecutionsClient=_Client, Execution=_Exec)
    monkeypatch.setitem(sys.modules, "google.cloud.workflows", types.SimpleNamespace(executions_v1=fake_exec_mod))
    monkeypatch.setitem(sys.modules, "google.cloud.workflows.executions_v1", fake_exec_mod)
    monkeypatch.setitem(sys.modules, "google.cloud.workflows_v1", types.SimpleNamespace())
    monkeypatch.setattr(gw, "resolve_service_url", lambda name, *a, **k: f"https://{name}.example.run.app")
    r = TestClient(gw.app).post("/events/pubsub-intake", json=_envelope(payload or {"product_id": PID, "trace_id": TRACE}))
    return r, created


def test_gateway_dispatch_refused_503_in_maintenance(gw, monkeypatch):
    _gw_settings(monkeypatch, lambda **k: _settings(maintenance_mode=True))
    r, created = _intake(gw, monkeypatch, FakeDB())
    assert r.status_code == 503 and created == []
    assert r.json()["detail"]["code"] == "MAINTENANCE_MODE"


@pytest.mark.parametrize("err, code", list(zip(ERRORS, ERROR_CODES)))
def test_gateway_dispatch_refused_503_when_settings_unreadable(gw, monkeypatch, err, code):
    _gw_settings(monkeypatch, _raises(err))
    r, created = _intake(gw, monkeypatch, FakeDB())
    assert r.status_code == 503 and created == [] and r.json()["detail"]["code"] == code


def test_gateway_negative_maintenance_off_dispatches_once(gw, monkeypatch):
    _gw_settings(monkeypatch, lambda **k: _settings(maintenance_mode=False))
    r, created = _intake(gw, monkeypatch, FakeDB())
    assert r.status_code == 200 and r.json()["status"] == "DISPATCHED" and len(created) == 1


def test_gateway_negative_fresh_install_store_dispatches(gw, monkeypatch):
    """No settings document (the defaults: maintenance off) read through the real strict path."""
    import shared.settings as gw_settings
    gw_settings.invalidate_settings_cache()
    r, created = _intake(gw, monkeypatch, FakeDB())
    assert r.status_code == 200 and r.json()["status"] == "DISPATCHED" and len(created) == 1


def test_gateway_redelivery_of_a_dispatched_event_still_acks_during_maintenance(gw, monkeypatch):
    _gw_settings(monkeypatch, lambda **k: _settings(maintenance_mode=True))
    db = FakeDB()
    db.docs[f"pipeline_executions/{TRACE}"] = {"workflow_execution_id": "e-0"}
    r, created = _intake(gw, monkeypatch, db)
    assert r.status_code == 200 and r.json()["status"] == "DUPLICATE" and created == []


def test_gateway_emergency_stop_still_takes_precedence(gw, monkeypatch):
    _gw_settings(monkeypatch, lambda **k: _settings(maintenance_mode=True))
    db = FakeDB()
    db.docs["governance/platform_kill_switch"] = {"emergency_stop_active": True}
    r, created = _intake(gw, monkeypatch, db)
    assert r.json()["status"] == "SUPPRESSED_BY_EMERGENCY_STOP" and created == []


# ================================================================================================ 6. Docs intake
@pytest.fixture
def spec(monkeypatch):
    fake = MagicMock()
    fake.auto_discover_shared_folders.return_value = []
    monkeypatch.setitem(sys.modules, "poller", SimpleNamespace(SpecIngestionPoller=lambda: fake))
    # main.py imports its sibling modules (intake_outcomes) by bare name, as in the service image. Put the service
    # directory on sys.path here so this file (and test_oss_d23_d18_defaults, which reuses this fixture) also pass
    # when run alone, not only after another spec-ingestion test has added it.
    monkeypatch.syspath_prepend(SPEC_DIR)
    path = os.path.join(SPEC_DIR, "main.py")
    mod_spec = importlib.util.spec_from_file_location("settings_toggles_spec_main", path)
    mod = importlib.util.module_from_spec(mod_spec)
    mod_spec.loader.exec_module(mod)
    return SimpleNamespace(mod=mod, poller=fake)


def _spec_settings(monkeypatch, read):
    import shared.settings as spec_settings
    spec_settings.invalidate_settings_cache()
    monkeypatch.setattr(spec_settings, "get_platform_settings", read)


@pytest.mark.parametrize("call", ["poll", "ingest", "webhook"])
@pytest.mark.parametrize("read, code", [(lambda **k: _settings(maintenance_mode=True), "MAINTENANCE_MODE"),
                                        (_raises(ERRORS[0]), "PLATFORM_SETTINGS_READ_FAILED")])
def test_docs_intake_refused_before_any_drive_move_or_publish(spec, monkeypatch, call, read, code):
    from fastapi import HTTPException
    _spec_settings(monkeypatch, read)
    fn = {"poll": lambda: spec.mod.execute_poll(),
          "ingest": lambda: spec.mod.ingest_single_document(spec.mod.IngestDocRequest(document_id="d1")),
          "webhook": lambda: spec.mod.handle_drive_push_notification()}[call]
    with pytest.raises(HTTPException) as ei:
        fn()
    assert ei.value.status_code == 503 and ei.value.detail["code"] == code
    spec.poller.auto_discover_shared_folders.assert_not_called()
    spec.poller.poll_and_ingest.assert_not_called()
    spec.poller.publish_intake_event.assert_not_called()


def test_docs_intake_negative_maintenance_off_polls_as_today(spec, monkeypatch):
    # OSS-D18: auto-discovery is off by default; turned on, the poll discovers exactly as before.
    _spec_settings(monkeypatch, lambda **k: _settings(maintenance_mode=False, drive_folder_auto_discovery=True))
    out = spec.mod.execute_poll()
    assert out["status"] == "IDLE" and spec.poller.auto_discover_shared_folders.call_count == 1


# ------------------------------------------------------------------------------------------------ RT F1: claim order
REFACTOR = {"product_id": PID, "trace_id": "refactor-app-scan-1", "scan_id": "scan-1", "findings_digest": "d" * 64,
            "source_channel": "github_refactor_scanner", "execution_mode": "FULL_BUILD"}
CLAIM = f"refactor_intake_requests/{PID}--" + "d" * 64


def _refactor_db():
    db = FakeDB()
    db.docs[f"workloads/{PID}"] = {"status": "ACTIVE", "project_id": "child-app"}
    return db


def test_gateway_maintenance_refuses_refactor_event_without_writing_a_claim(gw, monkeypatch):
    """RT F1: the maintenance refusal comes before the autonomous refactor claim, so a 503'd (later dead-lettered)
    event leaves no refactor_intake claim that would suppress the next scan for 7 days."""
    _gw_settings(monkeypatch, lambda **k: _settings(maintenance_mode=True))
    db = _refactor_db()
    r, created = _intake(gw, monkeypatch, db, dict(REFACTOR))
    assert r.status_code == 503 and r.json()["detail"]["code"] == "MAINTENANCE_MODE" and created == []
    assert CLAIM not in db.docs and not [p for p, _d, _m in db.writes if p.startswith("refactor_intake")]


def test_gateway_negative_maintenance_off_refactor_claim_created_once(gw, monkeypatch):
    _gw_settings(monkeypatch, lambda **k: _settings(maintenance_mode=False))
    db = _refactor_db()
    r, created = _intake(gw, monkeypatch, db, dict(REFACTOR))
    assert r.status_code == 200 and r.json()["status"] == "DISPATCHED" and len(created) == 1
    assert db.docs[CLAIM]["trace_id"] == REFACTOR["trace_id"]
    assert len([p for p, _d, _m in db.writes if p == CLAIM]) == 1
