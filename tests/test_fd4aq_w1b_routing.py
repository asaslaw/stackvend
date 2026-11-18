"""FD-4AQ W1b (owner row AQ-6, Fable F1): a deploy whose init refused a provider outside the allow-list goes to the
operator.

`PROVIDER_NOT_ALLOWED` (named in the configuration or recorded in state) cannot be fixed by developer IaC
remediation alone (a state-only provider needs an operator `state rm`), so the workflow routes it to
``handle_operator_deploy_failure`` with its class, and the gateway's terraform-remediation guard refuses it
(``gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES``; YAML/gateway parity pinned in tests/test_fd4dc_deploy_success_word.py).
Hermetic: the workflow runs in tests/workflow_sim.py.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import os

from test_lane17_workflow_sim import TF, Fleet, assert_failed, calls, run, workflow  # noqa: F401

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO, "mcp-servers", "terraform")

_REFUSED = {"status": "FAILED", "error_class": "PROVIDER_NOT_ALLOWED",
            "error": "IaC init failed: PROVIDER_NOT_ALLOWED: this workload's Terraform requires "
                     "registry.opentofu.org/hashicorp/external, which the platform does not install.",
            "providers_not_allowed": ["registry.opentofu.org/hashicorp/external"]}


def test_provider_not_allowed_stops_for_the_operator_with_its_class(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [_REFUSED, {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert_failed(res, "PROVIDER_NOT_ALLOWED", "terraform")
    assert "operator action required" in res.error["message"]
    assert "registry.opentofu.org/hashicorp/external" in res.error["message"]
    assert len(calls(res, "/agent/developer/execute")) == 1  # no developer remediation
    assert len(calls(res, TF + "/deploy-async")) == 1
    assert "handle_operator_deploy_failure" in res.steps_executed
    assert "increment_tf_retry" not in res.steps_executed and "handle_deploy_failure" not in res.steps_executed


def test_provider_not_allowed_deploy_only_also_goes_to_the_operator(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [_REFUSED]
    res, _ = run(workflow, f, execution_mode="DEPLOY_ONLY", target_branch="main")
    assert_failed(res, "PROVIDER_NOT_ALLOWED", "terraform")
    assert "handle_operator_deploy_failure" in res.steps_executed


def test_gateway_set_and_terraform_constant_agree():
    spec = importlib.util.spec_from_file_location(
        "fd4aq_gate_errors", os.path.join(REPO, "apps", "orchestrator-gateway", "gate_errors.py"))
    gate_errors = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate_errors)
    assert "PROVIDER_NOT_ALLOWED" in gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES
    # the listed string is the terraform server's own constant (read with ast, no import)
    with open(os.path.join(TF_DIR, "provider_allowlist.py"), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    values = [n.value.value for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
              and any(isinstance(t, ast.Name) and t.id == "ERROR_PROVIDER_NOT_ALLOWED" for t in n.targets)]
    assert values == ["PROVIDER_NOT_ALLOWED"]
