"""FD-4D-c / FD-4AI-c F1 (owner row, 10-20).

1. ``REPO_TREE_INCOMPLETE`` is in the workflow's operator list: a deploy that could not read the repository completely
   stops for the operator with its own class (no developer remediation, no generic DEPLOY_FAILED).
2. Deploy success is reported as exactly ``SUCCESS``: ``TerraformService.deploy_workload`` returns SUCCESS, the
   callback scope accepts only SUCCESS, the workflow's success check is ``deploy_status == "SUCCESS"``, and the
   terraform server / tf-applier set the outcome status AFTER ``outcome.update(res)`` so a result word can never
   override it. No producer emits the old ``DEPLOYED`` alias; a stray DEPLOYED is not a success anywhere.

Kept (negative tests): a SUCCESS deploy still succeeds end to end; the other operator classes and the IAC_DEFECT /
unknown-class routing are unchanged (tests/test_lane17_workflow_sim.py); the workloads/{id} lifecycle field keeps its
own word (DEPLOYED is a lifecycle state there, not a deploy result).

Hermetic: the workflow runs in tests/workflow_sim.py; the terraform modules are loaded with fake deploy results and a
captured callback (no network, no cloud clients).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
import yaml

from test_fd4g_terraform_workspace import (  # noqa: F401  (pytest fixtures reused by name)
    _isolated_tf_service, _no_network, _patched_applier, base, sent_callbacks, tf_main)
from test_lane17_workflow_sim import TF, Fleet, assert_failed, calls, run, workflow  # noqa: F401

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKFLOW = os.path.join(REPO, "workflows", "main_orchestrator.yaml")
TF_DIR = os.path.join(REPO, "mcp-servers", "terraform")


# ================================================================================ workflow (static)
def _step(name):
    with open(WORKFLOW, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    for sub in doc.values():
        for entry in sub.get("steps", []):
            if name in entry:
                return entry[name]
    raise AssertionError(f"step {name} not found")


def test_success_condition_is_exactly_success():
    switch = _step("check_deploy_status")["switch"]
    assert switch[0] == {"condition": '${deploy_status == "SUCCESS"}', "next": "notify_workflow_success"}
    with open(WORKFLOW, encoding="utf-8") as fh:
        text = fh.read()
    assert '"DEPLOYED"' not in text


def _workflow_operator_list():
    """The operator-routed classes, read from the YAML-parsed check_deploy_status switch. The condition is
    `${deploy_error_class in [...]}`; its list literal is a JSON array of strings, parsed with json."""
    switch = _step("check_deploy_status")["switch"]
    assert switch[1]["next"] == "handle_operator_deploy_failure"
    cond = switch[1]["condition"]
    prefix = "${deploy_error_class in "
    assert cond.startswith(prefix) and cond.endswith("}"), cond
    listed = json.loads(cond[len(prefix):-1])
    assert isinstance(listed, list) and all(isinstance(c, str) for c in listed)
    return listed


def test_repo_tree_incomplete_is_in_the_operator_list():
    assert _workflow_operator_list() == ["STATE_LOCKED", "DEPLOY_TIMEOUT", "QUOTA_EXHAUSTED", "GCE_STOCKOUT",
                                         "PERMISSION_DENIED", "DESTROY_BLOCKED", "DESTROY_REQUIRES_APPROVAL",
                                         "REPO_TREE_INCOMPLETE", "APPLY_CONTENT_POLICY",
                                         "PROVIDER_NOT_ALLOWED",
                                         "TOFU_TIMEOUT",
                                         "WORKFLOW_INVALID"]  # + FD-4AW-b-r, FD-4AQ W1b, TOFU-TIMEOUT-OP, FD55-W6c


def test_gateway_non_remediable_set_equals_the_workflow_operator_list():
    # Opus RT low fix: the gateway's terraform-remediation guard refuses exactly the classes the workflow sends to the
    # operator, so a REPO_TREE_INCOMPLETE remediation dispatch is refused even if one reached the developer.
    spec = importlib.util.spec_from_file_location(
        "fd4dc_gate_errors", os.path.join(REPO, "apps", "orchestrator-gateway", "gate_errors.py"))
    gate_errors = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate_errors)
    listed = _workflow_operator_list()
    assert len(listed) == len(set(listed))
    assert gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES == frozenset(listed)
    assert "REPO_TREE_INCOMPLETE" in gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES


# ================================================================================ workflow (simulated)
_TREE_INCOMPLETE = {"status": "FAILED", "error_class": "REPO_TREE_INCOMPLETE",
                    "error": "REPO_TREE_INCOMPLETE: tree truncated at 2500 files. Nothing was built, planned or applied."}


def test_repo_tree_incomplete_stops_for_the_operator_with_its_class(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [_TREE_INCOMPLETE, {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert_failed(res, "REPO_TREE_INCOMPLETE", "terraform")
    assert "operator action required" in res.error["message"] and "tree truncated" in res.error["message"]
    assert len(calls(res, "/agent/developer/execute")) == 1  # no developer remediation
    assert len(calls(res, TF + "/deploy-async")) == 1
    assert "increment_tf_retry" not in res.steps_executed
    assert "handle_deploy_failure" not in res.steps_executed


def test_repo_tree_incomplete_deploy_only_also_goes_to_the_operator(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [_TREE_INCOMPLETE]
    res, _ = run(workflow, f, execution_mode="DEPLOY_ONLY", target_branch="main")
    assert_failed(res, "REPO_TREE_INCOMPLETE", "terraform")
    assert "handle_operator_deploy_failure" in res.steps_executed


def test_success_still_succeeds(workflow):
    res, _ = run(workflow)
    assert res.state == "SUCCEEDED", res.error
    assert "notify_workflow_success" in res.steps_executed


def test_a_stray_deployed_word_is_not_a_success(workflow):
    # The callback scope normalizes every result to SUCCESS/FAILED, so this cannot arrive; if it ever did, the
    # workflow must not report success on it.
    f = Fleet()
    f.callbacks["deploy"] = [{"status": "DEPLOYED", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert res.state == "FAILED"
    assert "notify_workflow_success" not in res.steps_executed


# ================================================================================ terraform server / tf-applier
def test_async_deploy_success_reports_success(tf_main, sent_callbacks):
    tf_main.service.deploy_workload = MagicMock(return_value={"status": "SUCCESS", "service_url": "https://x"})
    req = tf_main.AsyncDeployRequest(product_id="app", trace_id="t-fd4dc-1", callback_url="http://127.0.0.1:9/cb")
    with patch.object(tf_main, "trigger_tf_applier_job", return_value=False):
        tf_main.run_deploy_in_background(req)
    last = sent_callbacks[-1]
    assert last["status"] == "SUCCESS" and last["error"] is None and "reported_status" not in last
    assert last["service_url"] == "https://x" and last["outputs"]["status"] == "SUCCESS"


def test_async_deploy_old_deployed_word_is_failed(tf_main, sent_callbacks):
    tf_main.service.deploy_workload = MagicMock(return_value={"status": "DEPLOYED", "service_url": "https://x"})
    req = tf_main.AsyncDeployRequest(product_id="app", trace_id="t-fd4dc-2", callback_url="http://127.0.0.1:9/cb")
    with patch.object(tf_main, "trigger_tf_applier_job", return_value=False):
        tf_main.run_deploy_in_background(req)
    assert sent_callbacks[-1]["status"] == "FAILED"


def test_async_deploy_failure_word_cannot_override_failed(tf_main, sent_callbacks):
    # F1: the status is set after update(res): the result's own word stays in outputs, the outcome says FAILED.
    tf_main.service.deploy_workload = MagicMock(return_value={"status": "VALIDATION_FAILED", "error": "undeclared"})
    req = tf_main.AsyncDeployRequest(product_id="app", trace_id="t-fd4dc-3", callback_url="http://127.0.0.1:9/cb")
    with patch.object(tf_main, "trigger_tf_applier_job", return_value=False):
        tf_main.run_deploy_in_background(req)
    last = sent_callbacks[-1]
    assert last["status"] == "FAILED" and last["error"] == "undeclared"
    assert "reported_status" not in last and last["outputs"]["status"] == "VALIDATION_FAILED"


def test_sync_deploy_success_and_stray_deployed(tf_main):
    from fastapi.testclient import TestClient

    c = TestClient(tf_main.app)
    tf_main.service.deploy_workload = MagicMock(return_value={"status": "SUCCESS", "service_url": "https://x"})
    r = c.post("/deploy", json={"product_id": "app", "trace_id": "t-fd4dc-4"})
    assert r.status_code == 200 and r.json()["status"] == "SUCCESS"
    tf_main.service.deploy_workload = MagicMock(return_value={"status": "DEPLOYED", "service_url": "https://x"})
    r = c.post("/deploy", json={"product_id": "app", "trace_id": "t-fd4dc-5"})
    assert r.status_code == 500


def test_applier_success_exits_0_and_a_stray_deployed_exits_1(monkeypatch, base, sent_callbacks):
    ok = MagicMock(return_value={"status": "SUCCESS", "service_url": "https://x"})
    applier = _patched_applier(monkeypatch, base, "fd4dc_tf_applier_ok", ok)
    monkeypatch.setenv("PRODUCT_ID", "app")
    with pytest.raises(SystemExit) as ei:
        applier.run_job()
    assert ei.value.code == 0 and sent_callbacks[-1]["status"] == "SUCCESS"

    stray = MagicMock(return_value={"status": "DEPLOYED", "service_url": "https://x"})
    applier = _patched_applier(monkeypatch, base, "fd4dc_tf_applier_stray", stray)
    monkeypatch.setenv("PRODUCT_ID", "app")
    with pytest.raises(SystemExit) as ei:
        applier.run_job()
    assert ei.value.code == 1 and sent_callbacks[-1]["status"] == "FAILED"


# ================================================================================ no producer emits DEPLOYED
def _string_constants(path):
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    return [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and n.value == "DEPLOYED"]


@pytest.mark.parametrize("filename", ["main.py", "applier.py"])
def test_terraform_server_and_applier_have_no_deployed_word(filename):
    assert _string_constants(os.path.join(TF_DIR, filename)) == []


def test_service_keeps_deployed_only_as_the_workload_lifecycle_word():
    # Exactly one "DEPLOYED" literal remains in service.py: the workloads/{id} lifecycle status (not a deploy result).
    path = os.path.join(TF_DIR, "service.py")
    hits = _string_constants(path)
    assert len(hits) == 1
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    line = lines[hits[0].lineno - 1]
    assert '"status": "DEPLOYED" if is_successful_deploy else "FAILED"' in line
    assert any("workload_update = {" in lines[i] for i in range(hits[0].lineno - 3, hits[0].lineno - 1))
