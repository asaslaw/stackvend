"""WF-OPERATOR-FLAG (owner row, 10-27).

A deploy result can say ``operator_required: true``; the workflow's ``check_deploy_status`` then stops the run for an
operator (``handle_operator_deploy_failure``) whatever the result's class, exactly like the listed operator classes.
Only the JSON boolean true counts. Nothing sets the flag yet, so behaviour is unchanged.

Pinned here:
- the YAML: success first, the class list unchanged (and still equal to gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES),
  then the flag condition, then the remediation fall-through;
- the simulated workflow: a flagged result goes to the operator (agent mode and DEPLOY_ONLY), no developer
  remediation; negative cases (flag false / absent / the string "true" / null) keep today's routing;
- the gateway's remediation guard treats a persisted ``operator_required is True`` like a non-remediable class;
- the terraform server and tf-applier pass the flag through to the callback unchanged.

Hermetic: tests/workflow_sim.py; fake deploy results and a captured callback (no network, no cloud clients).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
from unittest.mock import MagicMock, patch

import pytest
import yaml

from fd4f_support import FakeDB, gw  # noqa: F401  (gw is a fixture)
from test_fd4dc_deploy_success_word import _workflow_operator_list
from test_fd4g_terraform_workspace import (  # noqa: F401  (pytest fixtures reused by name)
    _isolated_tf_service, _no_network, _patched_applier, base, sent_callbacks, tf_main)
from test_lane17_workflow_sim import TF, Fleet, assert_failed, calls, run, workflow  # noqa: F401

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKFLOW = os.path.join(REPO, "workflows", "main_orchestrator.yaml")
FLAG_CONDITION = '${default(map.get(deployment_output, "operator_required"), false) == true}'


def _switch():
    with open(WORKFLOW, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    for sub in doc.values():
        for entry in sub.get("steps", []):
            if "check_deploy_status" in entry:
                return entry["check_deploy_status"]["switch"]
    raise AssertionError("check_deploy_status not found")


# ================================================================================ YAML (static)
def test_flag_condition_order_success_classes_flag_fallthrough():
    sw = _switch()
    assert len(sw) == 4
    assert sw[0] == {"condition": '${deploy_status == "SUCCESS"}', "next": "notify_workflow_success"}
    assert sw[1]["next"] == "handle_operator_deploy_failure"
    assert sw[2] == {"condition": FLAG_CONDITION, "next": "handle_operator_deploy_failure"}
    assert sw[3] == {"condition": True, "next": "check_tf_remediation"}


def test_class_list_unchanged_and_still_in_parity_with_the_gateway():
    import importlib.util

    listed = _workflow_operator_list()
    assert listed == ["STATE_LOCKED", "DEPLOY_TIMEOUT", "QUOTA_EXHAUSTED", "GCE_STOCKOUT", "PERMISSION_DENIED",
                      "DESTROY_BLOCKED", "DESTROY_REQUIRES_APPROVAL", "REPO_TREE_INCOMPLETE", "APPLY_CONTENT_POLICY",
                      "PROVIDER_NOT_ALLOWED", "TOFU_TIMEOUT", "WORKFLOW_INVALID"]
    spec = importlib.util.spec_from_file_location(
        "wfop_gate_errors", os.path.join(REPO, "apps", "orchestrator-gateway", "gate_errors.py"))
    gate_errors = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate_errors)
    assert gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES == frozenset(listed)


# ================================================================================ workflow (simulated)
def _flagged(cls="NEW_OPERATOR_STOP", flag=True):
    body = {"status": "FAILED", "error": "a new typed stop: an operator must act"}
    if cls is not None:
        body["error_class"] = cls
    if flag is not _ABSENT:
        body["operator_required"] = flag
    return body


_ABSENT = object()


def test_flagged_result_with_an_unlisted_class_stops_for_the_operator(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [_flagged(), {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert_failed(res, "NEW_OPERATOR_STOP", "terraform")
    assert "operator action required" in res.error["message"] and "a new typed stop" in res.error["message"]
    assert "handle_operator_deploy_failure" in res.steps_executed
    assert "increment_tf_retry" not in res.steps_executed and "handle_deploy_failure" not in res.steps_executed
    assert len(calls(res, "/agent/developer/execute")) == 1  # no developer remediation
    assert len(calls(res, TF + "/deploy-async")) == 1


def test_flagged_iac_defect_is_not_remediated(workflow):
    # The flag wins over a class that would otherwise be remediable.
    f = Fleet()
    f.callbacks["deploy"] = [_flagged("IAC_DEFECT"), {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert_failed(res, "IAC_DEFECT", "terraform")
    assert "handle_operator_deploy_failure" in res.steps_executed
    assert len(calls(res, "/agent/developer/execute")) == 1


def test_flagged_result_deploy_only_goes_to_the_operator(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [_flagged()]
    res, _ = run(workflow, f, execution_mode="DEPLOY_ONLY", target_branch="main")
    assert_failed(res, "NEW_OPERATOR_STOP", "terraform")
    assert "handle_operator_deploy_failure" in res.steps_executed
    assert "handle_deploy_failure" not in res.steps_executed


def test_flag_on_a_success_result_still_succeeds(workflow):
    # Success is checked first: a stray flag on a SUCCESS result changes nothing.
    f = Fleet()
    f.callbacks["deploy"] = [{"status": "SUCCESS", "service_url": "https://app.run.app", "operator_required": True}]
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    assert "handle_operator_deploy_failure" not in res.steps_executed


@pytest.mark.parametrize("flag", [False, "true", None, 1, _ABSENT])
def test_negative_not_exactly_true_keeps_remediation(workflow, flag):
    # Only the JSON boolean true counts: an IAC_DEFECT with any other value is remediated as today.
    f = Fleet()
    f.callbacks["deploy"] = [_flagged("IAC_DEFECT", flag), {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    assert "increment_tf_retry" in res.steps_executed
    assert "handle_operator_deploy_failure" not in res.steps_executed
    assert len(calls(res, "/agent/developer/execute")) == 2


def test_negative_listed_class_without_flag_still_stops_for_the_operator(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [{"status": "FAILED", "error_class": "STATE_LOCKED", "error": "locked"}]
    res, _ = run(workflow, f)
    assert_failed(res, "STATE_LOCKED", "terraform")


# ================================================================================ gateway remediation guard
TRACE = "tr-wfop-1"


def _dev_req(g):
    return g.DeveloperExecuteRequest(trace_id=TRACE, product_id="app", tf_remediation_context="Error: x")


@pytest.mark.parametrize("cls", ["NEW_OPERATOR_STOP", "IAC_DEFECT", "", None])
def test_gateway_guard_refuses_a_flagged_stage(gw, cls):
    from gate_errors import OperatorActionRequiredError

    db = FakeDB()
    db.docs[f"pipeline_executions/{TRACE}"] = {"stages": {"terraform": {"error_class": cls,
                                                                         "operator_required": True}}}
    with pytest.raises(OperatorActionRequiredError) as ei:
        gw._assert_tf_remediation_allowed(_dev_req(gw), db)
    assert ei.value.to_body()["error_class"] == "OPERATOR_ACTION_REQUIRED"
    assert ei.value.reason == (cls or "operator_required")


@pytest.mark.parametrize("flag", [False, "true", 1, None])
def test_gateway_guard_negative_not_exactly_true_is_allowed(gw, flag):
    db = FakeDB()
    db.docs[f"pipeline_executions/{TRACE}"] = {"stages": {"terraform": {"error_class": "IAC_DEFECT",
                                                                         "operator_required": flag}}}
    gw._assert_tf_remediation_allowed(_dev_req(gw), db)  # no raise


# ================================================================================ terraform server / tf-applier
def test_async_deploy_passes_the_flag_to_the_callback(tf_main, sent_callbacks):
    tf_main.service.deploy_workload = MagicMock(return_value={
        "status": "FAILED", "error": "stop", "error_class": "NEW_OPERATOR_STOP", "operator_required": True})
    req = tf_main.AsyncDeployRequest(product_id="app", trace_id="t-wfop-1", callback_url="http://127.0.0.1:9/cb")
    with patch.object(tf_main, "trigger_tf_applier_job", return_value=False):
        tf_main.run_deploy_in_background(req)
    last = sent_callbacks[-1]
    assert last["status"] == "FAILED" and last["operator_required"] is True
    assert last["error_class"] == "NEW_OPERATOR_STOP"


def test_applier_passes_the_flag_to_the_callback(monkeypatch, base, sent_callbacks):
    res = MagicMock(return_value={
        "status": "FAILED", "error": "stop", "error_class": "NEW_OPERATOR_STOP", "operator_required": True})
    applier = _patched_applier(monkeypatch, base, "wfop_tf_applier", res)
    monkeypatch.setenv("PRODUCT_ID", "app")
    with pytest.raises(SystemExit) as ei:
        applier.run_job()
    assert ei.value.code == 1
    last = sent_callbacks[-1]
    assert last["status"] == "FAILED" and last["operator_required"] is True
    assert last["error_class"] == "NEW_OPERATOR_STOP"
