"""DEPLOY-FAILURE-OWNER-ROUTER (register row, owner 11-13): the Control Center's After-Action Report shows the terraform
server's typed owner class of a failed deploy (PLATFORM_DEFECT, OPERATOR_REQUIRED, PROVIDER_TRANSIENT,
DEPLOY_FAILURE_UNATTRIBUTED) as the failure class, whether a model or the deterministic rules wrote the report; a
platform defect is never shown as a code defect. Negative: an untyped terraform failure keeps today's deterministic
report. Hermetic: no model call, no cloud client (same setup as tests/test_aar_fallback_stage.py)."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "control-center")))


@pytest.fixture(autouse=True)
def cc_env(monkeypatch):
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    monkeypatch.setattr(cc_db, "_db_client", False)
    monkeypatch.setitem(sys.modules, "shared.agent_evaluator",
                        SimpleNamespace(_call_gemini_inference=lambda *a, **k: None))
    from routes import telemetry

    def no_model(*a, **k):
        raise telemetry.AARModelFailure(telemetry.AAR_MODEL_CALL_FAILED, [])
    monkeypatch.setattr(telemetry, "aar_model_report", no_model)


def _aar(error_class, error="Terraform deployment failed: X (operator action required, no automatic retry): e"):
    from routes import telemetry
    return telemetry.synthesize_after_action_report(
        trace_id="t1", product_id="shop", status="FAILED", harvested_interventions=[], error_message=error,
        stages_dict={"terraform": {"status": "FAILED"}}, outputs_dict={}, cloud_logs=[], failed_stage="terraform",
        error_class=error_class)


@pytest.mark.parametrize("cls,mode", [("PLATFORM_DEFECT", None), ("OPERATOR_REQUIRED", None),
                                      ("PROVIDER_TRANSIENT", "DEPLOY_ONLY"), ("DEPLOY_FAILURE_UNATTRIBUTED", None)])
def test_deterministic_report_uses_the_typed_class(cls, mode):
    aar = _aar(cls, error="Terraform deployment failed: invalid value doesn't match regexp quota permission 403")
    assert aar.root_cause.failure_class == cls   # never guessed from the text
    assert aar.remediation.recommended_mode == mode
    assert aar.model_used == "deterministic-rules"


def test_model_report_shows_the_typed_class(monkeypatch):
    from routes import telemetry
    from schemas import RootCauseAnalysis
    monkeypatch.setattr(telemetry, "aar_model_report", lambda prompt: ({
        "executive_summary": "s", "root_cause": RootCauseAnalysis(failing_component="c", failure_class="CODE_DEFECT"),
        "blast_radius": None, "remediation": None}, "model-x"))
    aar = _aar("PLATFORM_DEFECT")
    assert aar.root_cause.failure_class == "PLATFORM_DEFECT" and aar.root_cause.failing_component == "c"
    monkeypatch.setattr(telemetry, "aar_model_report", lambda prompt: ({
        "executive_summary": "s", "root_cause": None, "blast_radius": None, "remediation": None}, "model-x"))
    assert _aar("OPERATOR_REQUIRED").root_cause.failure_class == "OPERATOR_REQUIRED"


def test_negative_untyped_terraform_failure_is_unchanged(monkeypatch):
    from routes import telemetry
    from schemas import RootCauseAnalysis
    aar = _aar("DEPLOY_FAILED", error="boom")
    assert aar.root_cause.failure_class == "INFRASTRUCTURE_FAILURE" and aar.remediation.recommended_mode == "DEPLOY_ONLY"
    monkeypatch.setattr(telemetry, "aar_model_report", lambda prompt: ({
        "executive_summary": "s", "root_cause": RootCauseAnalysis(failure_class="QUOTA_EXHAUSTED"),
        "blast_radius": None, "remediation": None}, "model-x"))
    assert _aar("DEPLOY_FAILED").root_cause.failure_class == "QUOTA_EXHAUSTED"


# ===================================================================================== RT F2: Auto relaunch
def _relaunch_harness():
    """Child process (the Control Center's own `shared`): the real retrigger route on a prior run whose terraform
    stage FAILED with an error text that holds a code-defect phrase, under each typed route owner."""
    import json as _json

    import test_faithful_rt_resume_handoff as fh
    here = os.path.dirname(os.path.abspath(__file__))
    marker = "# ================================================================ public mode"
    src_path = os.path.join(here, "cc_identity_harness.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    ns = {"__file__": src_path, "__name__": "cc_dfr_relaunch_harness"}
    exec(compile(src.split(marker, 1)[0], src_path, "exec"), ns)
    from unittest.mock import MagicMock, patch

    import routes.workloads as wl

    def run(owner, tf_status="FAILED"):
        db, pub = fh.FakeDB(), fh.FakePublisher()
        tf = {"status": tf_status, "state": "CALLBACK_DELIVERED",
              "error": "PLATFORM_DEFECT (plan failed; ...). Engine error: Error: Reference to undeclared resource"}
        if owner is not None:
            tf["failure_route"] = {"owner": owner, "phase": "plan", "basis": "ENGINE_JSON_DIAGNOSTICS"}
        prior = {"trace_id": "trace-prev-1", "product_id": "demo", "status": "FAILED", "current_stage": "FAILED",
                 "started_at": "2026-11-13T10:00:00Z",
                 "stages": {"developer": {"status": "SUCCESS"}, "qa": {"status": "SUCCESS"}, "terraform": tf}}
        fh._seed(db, prior)
        main_mod = SimpleNamespace(project_id="mock-stackvend-project", get_pubsub_publisher=lambda: pub)
        req = MagicMock()
        req.state.user_email = "operator@example.com"
        # BUILD-ADMISSION-QUEUE: this fake store has no create()/preconditions; admit every build (the admission
        # itself is pinned by tests/test_build_admission_queue.py)
        from build_admission_support import every_build_admitted
        with patch.object(wl, "db", db), patch.object(wl, "verify_workload_access", lambda *a, **k: None), \
                patch.object(wl, "get_caller_main_module", lambda: main_mod), every_build_admitted(wl):
            res = wl.retrigger_feature_request_build("demo", "fr-1", req, body=None)
        return res["execution_mode"]

    out = {o or "none": run(o) for o in ("PLATFORM_DEFECT", "OPERATOR_REQUIRED", "PROVIDER_TRANSIENT", "UNKNOWN",
                                         "DEVELOPER", None)}
    out["owners"] = sorted(wl.DEPLOY_FAILURE_NON_DEVELOPER_OWNERS)
    out["network_attempts"] = ns["NETWORK_ATTEMPTS"]
    print(_json.dumps(out, default=str))


@pytest.fixture(scope="module")
def relaunch():
    import json as _json
    import subprocess

    env = hermetic_guard.child_env(drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL"),
                                   extra={"PROJECT_ID": "mock-stackvend-project",
                                          "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project",
                                          "MANAGED_WORKLOADS_FOLDER_ID": "111111111111", "GITHUB_OWNER": "example-org"})
    out = subprocess.run([sys.executable, os.path.abspath(__file__), "--harness"],
                         capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    return _json.loads(out.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("owner", ["PLATFORM_DEFECT", "OPERATOR_REQUIRED", "PROVIDER_TRANSIENT", "UNKNOWN"])
def test_auto_relaunch_never_resumes_the_developer_for_a_non_developer_owner(relaunch, owner):
    """RT F2: the error text holds "reference to undeclared" (a phrase that picks RESUME_DEVELOPER), but the typed
    owner is not the developer: Auto relaunches as Fast-Path Deploy (0 LLM)."""
    assert relaunch[owner] == "DEPLOY_ONLY"


def test_auto_relaunch_negative_developer_or_untyped_keeps_todays_phrase_rule(relaunch):
    assert relaunch["DEVELOPER"] == "RESUME_DEVELOPER" and relaunch["none"] == "RESUME_DEVELOPER"
    assert not relaunch["network_attempts"]


def test_auto_relaunch_owner_is_read_only_for_a_failed_stage():
    from routes.workloads import typed_deploy_failure_owner
    route = {"failure_route": {"owner": "PLATFORM_DEFECT"}}
    assert typed_deploy_failure_owner(dict(route, status="FAILED")) == "PLATFORM_DEFECT"
    assert typed_deploy_failure_owner(dict(route, status="SUCCESS")) is None
    assert typed_deploy_failure_owner(dict(route, status="IN_FLIGHT")) is None
    assert typed_deploy_failure_owner({"status": "FAILED"}) is None
    assert typed_deploy_failure_owner({"status": "FAILED", "failure_route": "x"}) is None


def test_cc_owner_set_matches_the_terraform_router(relaunch):
    import importlib.util
    path = os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "terraform", "deploy_failure_router.py")
    spec = importlib.util.spec_from_file_location("dfr_cc_parity", path)
    dfr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dfr)
    assert set(relaunch["owners"]) == set(dfr.OWNERS) - {dfr.DEVELOPER}


if __name__ == "__main__" and "--harness" in sys.argv:
    _relaunch_harness()
