"""FD-4AW-b-r (owner row, 10-24): an apply refused by the content policy goes to the operator.

The tf-applier refuses a plan that breaks the platform content policy (``APPLY_CONTENT_POLICY``, FD-4AW-b: nothing was
applied; human-written files included). The workflow routes that class to ``handle_operator_deploy_failure`` (class
kept, no developer IaC remediation, no generic DEPLOY_FAILED), and the gateway's terraform-remediation guard refuses
a remediation dispatch for it (``gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES``; parity with the YAML list is pinned in
tests/test_fd4dc_deploy_success_word.py).

Kept (negative tests): IAC_DEFECT still gets bounded developer remediation; an unknown class is still DEPLOY_FAILED.
Hermetic: the workflow runs in tests/workflow_sim.py.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os

from test_lane17_workflow_sim import TF, Fleet, assert_failed, calls, run, workflow  # noqa: F401

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO, "mcp-servers", "terraform")

_REFUSED = {"status": "FAILED", "error_class": "APPLY_CONTENT_POLICY",
            "error": "APPLY_CONTENT_POLICY: the plan breaks the platform's content policy (PROVISIONER): local-exec in "
                     "null_resource.x. Nothing was applied.",
            "content_policy_violations": [{"code": "PROVISIONER", "message": "local-exec in null_resource.x"}]}


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_content_policy_refusal_stops_for_the_operator_with_its_class(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [_REFUSED, {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert_failed(res, "APPLY_CONTENT_POLICY", "terraform")
    assert "operator action required" in res.error["message"] and "Nothing was applied" in res.error["message"]
    assert len(calls(res, "/agent/developer/execute")) == 1  # no developer remediation
    assert len(calls(res, TF + "/deploy-async")) == 1
    assert "handle_operator_deploy_failure" in res.steps_executed
    assert "increment_tf_retry" not in res.steps_executed and "handle_deploy_failure" not in res.steps_executed


def test_content_policy_refusal_deploy_only_also_goes_to_the_operator(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [_REFUSED]
    res, _ = run(workflow, f, execution_mode="DEPLOY_ONLY", target_branch="main")
    assert_failed(res, "APPLY_CONTENT_POLICY", "terraform")
    assert "handle_operator_deploy_failure" in res.steps_executed


def test_iac_defect_is_still_remediated(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [{"status": "FAILED", "error_class": "IAC_DEFECT", "error": "bad hcl"},
                             {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    assert len(calls(res, "/agent/developer/execute")) == 2


def test_unknown_class_is_still_deploy_failed(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [{"status": "FAILED", "error_class": "SOMETHING_NEW", "error": "x"}]
    res, _ = run(workflow, f)
    assert_failed(res, "DEPLOY_FAILED", "terraform")


def test_gateway_set_and_terraform_constant_agree():
    gate_errors = _load("fd4awbr_gate_errors", os.path.join(REPO, "apps", "orchestrator-gateway", "gate_errors.py"))
    assert "APPLY_CONTENT_POLICY" in gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES
    # The class string the workflow and gateway list is the terraform service's own constant (read with ast, no import).
    import ast

    with open(os.path.join(TF_DIR, "service.py"), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    values = [n.value.value for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
              and any(isinstance(t, ast.Name) and t.id == "ERROR_APPLY_CONTENT_POLICY" for t in n.targets)]
    assert values == ["APPLY_CONTENT_POLICY"]
