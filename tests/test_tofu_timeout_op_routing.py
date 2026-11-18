"""TOFU-TIMEOUT-OP (owner 10-25): a deploy whose OpenTofu command ran past its time limit goes to the operator.

`TOFU_TIMEOUT` (FD-4AQ W3 / AQ-5: the command was interrupted at its limit, then killed after the grace period if it
did not stop; the state lock may still be held) cannot be fixed by developer IaC remediation, so the workflow routes
it to ``handle_operator_deploy_failure`` with its class, and the gateway's terraform-remediation guard refuses it
(``gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES``; YAML/gateway parity pinned in tests/test_fd4dc_deploy_success_word.py).
Hermetic: the workflow runs in tests/workflow_sim.py. Mirrors tests/test_fd4aq_w1b_routing.py.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import os

from test_lane17_workflow_sim import TF, Fleet, assert_failed, calls, run, workflow  # noqa: F401

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO, "mcp-servers", "terraform")

_TIMED_OUT = {"status": "FAILED", "error_class": "TOFU_TIMEOUT",
              "error": "TOFU_TIMEOUT: the OpenTofu command `apply` did not finish within 1200 seconds and was "
                       "interrupted. Nothing more is run for this deploy."}


def test_tofu_timeout_stops_for_the_operator_with_its_class(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [_TIMED_OUT, {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert_failed(res, "TOFU_TIMEOUT", "terraform")
    assert "operator action required" in res.error["message"]
    assert "did not finish within 1200 seconds" in res.error["message"]
    assert len(calls(res, "/agent/developer/execute")) == 1  # no developer remediation
    assert len(calls(res, TF + "/deploy-async")) == 1
    assert "handle_operator_deploy_failure" in res.steps_executed
    assert "increment_tf_retry" not in res.steps_executed and "handle_deploy_failure" not in res.steps_executed


def test_tofu_timeout_deploy_only_also_goes_to_the_operator(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [_TIMED_OUT]
    res, _ = run(workflow, f, execution_mode="DEPLOY_ONLY", target_branch="main")
    assert_failed(res, "TOFU_TIMEOUT", "terraform")
    assert "handle_operator_deploy_failure" in res.steps_executed


def test_iac_defect_still_goes_to_developer_remediation(workflow):
    # negative: the remediable class keeps its route (bounded developer retry with the error text)
    f = Fleet()
    f.callbacks["deploy"] = [{"status": "FAILED", "error_class": "IAC_DEFECT", "error": "Unsupported argument"},
                             {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    assert len(calls(res, "/agent/developer/execute")) == 2
    assert "handle_operator_deploy_failure" not in res.steps_executed


def test_gateway_set_and_terraform_constant_agree():
    spec = importlib.util.spec_from_file_location(
        "tofu_timeout_gate_errors", os.path.join(REPO, "apps", "orchestrator-gateway", "gate_errors.py"))
    gate_errors = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate_errors)
    assert "TOFU_TIMEOUT" in gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES
    # the listed string is the terraform server's own constant (read with ast, no import)
    with open(os.path.join(TF_DIR, "service.py"), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    values = [n.value.value for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
              and any(isinstance(t, ast.Name) and t.id == "TOFU_TIMEOUT" for t in n.targets)]
    assert values == ["TOFU_TIMEOUT"]
