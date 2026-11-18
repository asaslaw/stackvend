"""AAR-FALLBACK-STAGE: the deterministic debrief speaks of OpenTofu and offers DEPLOY_ONLY only for a run that failed at
the `terraform` stage. Every other failure names its recorded stage and typed class and offers AUTO; nothing is guessed
from the error text. Hermetic: no model call, no cloud client."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "control-center")))


@pytest.fixture(autouse=True)
def cc_env(monkeypatch):
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    monkeypatch.setattr(cc_db, "_db_client", False)   # importing the routes must not build a real client
    # a stub module: the real one builds a Firestore client when it is imported
    monkeypatch.setitem(sys.modules, "shared.agent_evaluator",
                        SimpleNamespace(_call_gemini_inference=lambda *a, **k: None))
    # AAR-SETTINGS-MODEL: no model writes the report here (typed failure), so the deterministic debrief is tested
    from routes import telemetry

    def no_model(*a, **k):
        raise telemetry.AARModelFailure(telemetry.AAR_MODEL_CALL_FAILED, [])
    monkeypatch.setattr(telemetry, "aar_model_report", no_model)


def synthesize_after_action_report(**kw):
    from routes import telemetry
    return telemetry.synthesize_after_action_report(**kw)


def _aar(error="boom", stages=None, **kw):
    return synthesize_after_action_report(
        trace_id="t1", product_id="shop", status="FAILED", harvested_interventions=[], error_message=error,
        stages_dict=stages if stages is not None else {}, outputs_dict={}, cloud_logs=[], **kw)


def _text(aar):
    return " ".join(str(v) for v in (aar.executive_summary, aar.root_cause.failing_component,
                                     aar.root_cause.failure_class, aar.blast_radius.failed_resource,
                                     aar.blast_radius.blocked_resources, aar.remediation.recommended_mode,
                                     aar.remediation.immediate_action, aar.remediation.preventative_guidance))


@pytest.mark.parametrize("stage", ["architect", "compliance", "prebuild_gate", "plan_approval", "quota_gate", "vending",
                                   "developer", "gatekeeper", "qa", "release", "deploy_only_gate"])
def test_a_failure_outside_terraform_names_its_stage(stage):
    aar = _aar(failed_stage=stage, error_class="QA_TESTS_FAILED")
    text = _text(aar)
    for claim in ("OpenTofu", "Terraform", "DEPLOY_ONLY", "Cloud Run"):
        assert claim not in text, claim
    assert stage in aar.root_cause.failing_component and stage in aar.blast_radius.failed_resource
    assert stage in aar.executive_summary
    assert aar.root_cause.failure_class == "QA_TESTS_FAILED" and aar.root_cause.technical_explanation == "boom"
    assert aar.remediation.recommended_mode == "AUTO" and aar.model_used == "deterministic-rules"


def test_the_stage_comes_from_the_one_stage_marked_failed_when_the_run_has_no_typed_field():
    aar = _aar(stages={"qa": {"status": "FAILED"}, "developer": {"status": "SUCCESS"}, "bad": "x"})
    assert "qa" in aar.root_cause.failing_component and aar.remediation.recommended_mode == "AUTO"


def test_the_typed_field_wins_over_the_stage_records():
    aar = _aar(failed_stage="qa", stages={"terraform": {"status": "FAILED"}})
    assert "qa" in aar.root_cause.failing_component and aar.remediation.recommended_mode == "AUTO"


@pytest.mark.parametrize("stages", [{}, {"qa": {"status": "FAILED"}, "vending": {"status": "FAILED"}},
                                    {"terraform": {"status": "SUCCESS"}}])
def test_no_single_recorded_stage_is_said_and_not_guessed(stages):
    aar = _aar(stages=stages)
    assert aar.root_cause.failing_component == "Pipeline (failed stage not recorded)"
    assert aar.remediation.recommended_mode == "AUTO"
    assert "OpenTofu" not in _text(aar) and "DEPLOY_ONLY" not in _text(aar)


def test_negative_no_class_is_guessed_from_the_error_text_outside_terraform():
    aar = _aar(error="403 permission denied, quota exceeded", failed_stage="qa")
    assert aar.root_cause.failure_class is None and aar.remediation.recommended_mode == "AUTO"


@pytest.mark.parametrize("kwargs", [{"failed_stage": "terraform"}, {"stages": {"terraform": {"status": "FAILED"}}}])
@pytest.mark.parametrize("error,failure_class,mode", [
    ("boom", "INFRASTRUCTURE_FAILURE", "DEPLOY_ONLY"),
    ('"name" doesn\'t match regexp "^x$"', "TYPE_SEMANTIC_MISMATCH", "FULL"),
    ("Quota exceeded", "QUOTA_EXHAUSTED", "DEPLOY_ONLY"),
    ("403 from the API", "IAM_PERMISSION_DENIED", "DEPLOY_ONLY"),
])
def test_negative_a_terraform_failure_keeps_todays_text_exactly(kwargs, error, failure_class, mode):
    aar = _aar(error=error, **kwargs)
    assert aar.executive_summary == f"Deployment halted at terminal stage: {error[:160]}"
    assert aar.root_cause.model_dump() == {"failing_component": "OpenTofu IaC Engine", "failure_class": failure_class,
                                           "technical_explanation": error}
    assert aar.blast_radius.model_dump() == {"provisioned_resources": [], "failed_resource": "Terraform apply operation",
                                             "blocked_resources": ["Downstream Cloud Run ingress"]}
    assert aar.remediation.model_dump() == {
        "recommended_mode": mode, "immediate_action": f"Re-dispatch mission using {mode} mode to remediate defect.",
        "preventative_guidance": "Verify schema contracts and naming conventions."}


def test_negative_a_succeeded_run_has_no_failure_sections():
    aar = synthesize_after_action_report(
        trace_id="t1", product_id="shop", status="SUCCEEDED", harvested_interventions=[], error_message=None,
        stages_dict={}, outputs_dict={}, cloud_logs=[], failed_stage="qa", error_class="X")
    assert aar.root_cause is None and aar.blast_radius is None and aar.remediation is None


def test_the_route_passes_the_runs_typed_fields(monkeypatch):
    from routes import telemetry
    doc = MagicMock(exists=True)
    doc.to_dict.return_value = {"status": "FAILED", "product_id": "shop", "error": "tests failed", "stages": {},
                                "failed_stage": "qa", "error_class": "QA_TESTS_FAILED"}
    db = MagicMock()
    doc_ref = db.collection.return_value.document.return_value
    doc_ref.get.return_value = doc
    monkeypatch.setattr(telemetry, "db", db)
    monkeypatch.setattr(telemetry, "fetch_workload_logs_from_cloud_logging", lambda **_: ([], None))
    aar = telemetry.generate_execution_aar(trace_id="t1", request=None).aar
    assert "qa" in aar.root_cause.failing_component and aar.root_cause.failure_class == "QA_TESTS_FAILED"
    assert aar.remediation.recommended_mode == "AUTO"
    doc_ref.set.assert_called_once()


@pytest.mark.parametrize("error_class", ["STAGE_DEADLINE_EXCEEDED", "STAGE_TIMEOUT", "STAGE_INTERRUPTED",
                                         "STAGE_ABANDONED", "CONTRACT_VIOLATION"])
def test_stage_stop_classes_get_operator_text_and_auto(error_class):
    """RT S9: the stage-stop classes say what to do (relaunch), by exact class; the mode stays AUTO."""
    aar = _aar(error="Developer implementation failed: the stage job did not answer", failed_stage="developer",
               error_class=error_class)
    assert aar.root_cause.failure_class == error_class and aar.remediation.recommended_mode == "AUTO"
    assert "Relaunch" in aar.remediation.immediate_action
    assert "fix its cause" not in aar.remediation.immediate_action


def test_negative_other_classes_keep_the_generic_action():
    aar = _aar(failed_stage="qa", error_class="QA_TESTS_FAILED")
    assert aar.remediation.immediate_action.startswith("Read the error for this stage and fix its cause")
