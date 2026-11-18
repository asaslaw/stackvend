"""FD-55 W6c (register FD55-W6c): legacy validate / apply errors are no longer healed by text rewrites at deploy.

mcp-servers/terraform/service.py deploy_workload / generate_plan:
- A42: the pre-apply tfvars reconciler (name-guessed values, HD-14) is deleted (tests/test_fd55_w3_deploy_gaps.py
  pins the legacy and intent tfvars; the helper functions' absence is pinned here).
- A44 / A45 / A46: on a legacy validate error the locals curing, the undeclared `google_cloud_run_v2_service.<x>`
  rewrite and the custom.tf output purge are gone: validate runs once, no file changes, VALIDATION_FAILED carries the
  engine's text (the workflow's existing bounded regeneration, `tf_retry_count`).
- A47 / A48: on an apply error the self-referential block rewrite and the locals curing are gone (and their loop
  triggers): one apply, no file changes, FAILED with the engine's text.
- A49: the IdP block bypass is gone (tests/test_fd4aq_w1_no_host_secret.py: initializeAuth + one retry, main.tf
  byte-identical).
- W6a review F3: a committed workflow file that fails the workflow validator is a typed stop, APPLY.WORKFLOW_INVALID
  (status FAILED, file + line, error_class WORKFLOW_INVALID), in deploy_workload and generate_plan; nothing is
  rewritten, built, planned or applied. The workflow routes the class to the operator (gateway parity).
- Control Center: the two apply-side self-healing markers of A42 / A47 are no longer harvested
  (tests/test_after_action_report.py).

Each "no file written" check compares every workspace file at the moment the engine first reported the error with the
workspace at the end of the deploy (byte identity), so any re-added healer that writes fails. Negatives (Do No Harm):
a valid legacy deploy applies once with nothing changed; the kept Cloud Run timeout retry still retries; a valid
committed workflow passes as committed. Hermetic: no network, no ADC, no tofu (the engine is faked).
"""
import hermetic_guard  # noqa: F401  (first import)

import ast
import importlib.util
import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

pytest.importorskip("hcl2", reason="python-hcl2 (terraform MCP requirement) not installed")

from fd4g_support import load_tf_service  # noqa: E402
from test_fd55_w3_deploy_gaps import PROJECT, W, _legacy_tree, _service  # noqa: E402
from test_lane17_workflow_sim import TF, Fleet, assert_failed, calls, run, workflow  # noqa: E402,F401

TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
WF = ".github/workflows/deploy-shop.yml"
VALID_WF = (
    "name: deploy\n"
    "on:\n"
    "  push:\n"
    "    branches: [main]\n"
    "env:\n"
    "  REGION: ${{ vars.REGION }}\n"
    "jobs:\n"
    "  build:\n"
    "    runs-on: ubuntu-latest\n"
)
INVALID_WF = VALID_WF.replace("  REGION: ${{ vars.REGION }}\n",
                              "  REGION: ${{ vars.REGION }}\n  ZONE: ${{ env.REGION }}-a\n")   # line 7
OK = {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}


@pytest.fixture
def tf(monkeypatch):
    return load_tf_service(monkeypatch)


class _UnexpectedApply(BaseException):
    """A second apply: what a deleted heal-and-retry branch would do."""


def _snapshot(ws):
    out = {}
    for root, dirs, names in os.walk(ws):
        dirs[:] = [d for d in dirs if d != ".terraform" and not os.path.islink(os.path.join(root, d))]
        for n in names:
            p = os.path.join(root, n)
            if not os.path.islink(p):
                with open(p, "rb") as fh:
                    out[os.path.relpath(p, ws)] = fh.read()
    return out


def _deploy(tf, monkeypatch, tmp_path, files, validate_err=None, apply_results=(), on_first_apply=None):
    """The REAL deploy_workload with a fake engine. validate fails with `validate_err` (every call) when given; each
    gated apply returns the next of `apply_results` (one more raises _UnexpectedApply). The workspace is snapshotted
    when the engine first reports the error (first failing validate / first apply)."""
    svc, _vcs = _service(tf, monkeypatch, tmp_path, files)
    monkeypatch.setattr(svc, "_build_and_push_container", lambda *a, **k: True)
    monkeypatch.setattr(svc, "_sync_feature_requests", lambda **k: None)
    seen = {"cmds": [], "applies": 0}

    def _sub(cmd, cwd=None, **kw):
        seen["cmds"].append(list(cmd))
        if "validate" in cmd and "-json" in cmd and validate_err is not None:
            # DEPLOY-FAILURE-OWNER-ROUTER: the read-only `validate -json` names the failing file (every error here is
            # in the AI's custom.tf -> DEVELOPER, the result stays the untyped regeneration path)
            return {"success": False, "exit_code": 1, "stderr": "", "stdout": json.dumps({"diagnostics": [
                {"severity": "error", "summary": validate_err.split("\n", 1)[0][len("Error: "):],
                 "range": {"filename": "custom.tf", "start": {"line": 2, "column": 3, "byte": 40}}}]})}
        if "validate" in cmd and validate_err is not None:
            seen.setdefault("ws", cwd)
            seen.setdefault("snap", _snapshot(cwd))
            return {"success": False, "exit_code": 1, "stdout": "", "stderr": validate_err}
        if cmd == ["terraform", "show", "-json"]:   # FD55-3D: the applied state the rollout reads (no Cloud Run service)
            return dict(OK, stdout='{"format_version": "1.0"}')
        return dict(OK)

    results = list(apply_results)

    def _gated(product_id, trace_id, workspace_dir, *a, **k):
        seen["applies"] += 1
        seen.setdefault("ws", workspace_dir)
        if seen["applies"] == 1:
            if on_first_apply:
                on_first_apply(workspace_dir)
            seen.setdefault("snap", _snapshot(workspace_dir))
        if not results:
            raise _UnexpectedApply()
        return results.pop(0)

    monkeypatch.setattr(svc, "_run_subprocess", _sub)
    monkeypatch.setattr(svc, "_compliance_gated_apply", _gated)
    res = svc.deploy_workload(product_id="shop", trace_id="t-w6c", target_project_id=PROJECT, branch="main",
                              iac_engine="OPENTOFU")
    return res, seen, svc


def _validates(seen):
    # the engine's validate runs (DEPLOY-FAILURE-OWNER-ROUTER's read-only `validate -json` classification is not one)
    return [c for c in seen["cmds"] if c[:2] == ["terraform", "validate"] and "-json" not in c]


def _unchanged(seen):
    assert _snapshot(seen["ws"]) == seen["snap"]


def _apply_err(text):
    return {"success": False, "exit_code": 1, "stdout": "", "stderr": text}


# ------------------------------------------------------------------------------------------------ helpers gone
def test_deleted_w6c_helpers_are_gone(tf):
    for name in ("generate_rfc1123_variable_default", "parse_variables_tf_schema", "_ACCESS_KEY_DEFAULTS",
                 "strip_invalid_hcl_blocks", "strip_hcl_output", "sanitize_self_referential_hcl_blocks"):
        assert not hasattr(tf, name), name


# ------------------------------------------------------------------------------------------------ A44 / A45 / A46
LOCALS_ERR = ('Error: Reference to undeclared local value\n\n  on custom.tf line 2, in resource "google_pubsub_topic" '
              '"t":\n   2:   name = local.topic_name\n\nA local value with the name "topic_name" has not been declared.')
CR_ERR = ("Error: Reference to undeclared resource\n\n  on custom.tf line 3: google_cloud_run_v2_service.service_a\n\n"
          'A managed resource "google_cloud_run_v2_service" "service_a" has not been declared in the root module.')
OUTPUT_ERR = ('Error: Unsupported attribute\n\n  on custom.tf line 6, in output "db_conn":\n'
              '   6:   value = google_sql_database_instance.db.conn_name')
CUSTOM = (
    'resource "google_pubsub_topic" "t" {\n'
    '  name = "t"\n'
    '}\n'
    'resource "google_cloud_scheduler_job" "c" {\n'
    '  name       = "c"\n'
    '  depends_on = [google_cloud_run_v2_service.service_a]\n'
    '}\n'
    'output "db_conn" {\n'
    '  value = google_sql_database_instance.db.conn_name\n'
    '}\n'
    'output "topic" {\n'
    '  value = google_pubsub_topic.t.id\n'
    '}\n'
)


@pytest.mark.parametrize("err", [LOCALS_ERR, CR_ERR, OUTPUT_ERR], ids=["A44_locals", "A45_cloud_run_ref", "A46_outputs"])
def test_legacy_validate_error_is_returned_without_a_heal(tf, monkeypatch, tmp_path, err):
    res, seen, _svc = _deploy(tf, monkeypatch, tmp_path, _legacy_tree(**{W + "custom.tf": CUSTOM}), validate_err=err)
    assert res["status"] == "VALIDATION_FAILED" and err in res["error"]
    assert "validation_report" not in res and not res.get("error_class")    # the legacy untyped regeneration path
    assert len(_validates(seen)) == 1                                       # no heal-and-revalidate
    assert seen["applies"] == 0
    _unchanged(seen)
    with open(os.path.join(seen["ws"], "custom.tf"), encoding="utf-8", newline="") as fh:
        assert fh.read() == CUSTOM                                          # outputs and references as committed


def test_valid_legacy_deploy_applies_once_and_changes_nothing(tf, monkeypatch, tmp_path):
    """Do No Harm: a deploy whose validate and apply pass runs neither the error path nor any file write after the
    engine started."""
    res, seen, _svc = _deploy(tf, monkeypatch, tmp_path, _legacy_tree(**{W + "custom.tf": CUSTOM}),
                              apply_results=[dict(OK)])
    assert res["status"] == "SUCCESS", res
    assert len(_validates(seen)) == 1 and seen["applies"] == 1
    _unchanged(seen)


# ------------------------------------------------------------------------------------------------ A47 / A48
SELF_REF_CUSTOM = (
    'resource "google_secret_manager_secret" "signing_key" {\n'
    '  secret_id = google_secret_manager_secret.signing_key.secret_id\n'
    '  replication {\n'
    '    auto {}\n'
    '  }\n'
    '}\n'
)
SELF_REF_ERR = ('Error: Self-referential block\n\n  on custom.tf line 2, in resource "google_secret_manager_secret" '
                '"signing_key":\n   2:   secret_id = google_secret_manager_secret.signing_key.secret_id\n\n'
                'Configuration for google_secret_manager_secret.signing_key may not refer to itself.')
PLURAL_LOCALS = 'locals {\n  greeting = "hi"\n}\n\noutput "greeting" {\n  value = locals.greeting\n}\n'
PLURAL_ERR = ('Error: Reference to undeclared resource\n\n  on extra.tf line 6, in output "greeting":\n'
              '   6:   value = locals.greeting\n\nA managed resource "locals" "greeting" has not been declared.')


def test_a47_self_referential_apply_error_is_returned_without_a_rewrite(tf, monkeypatch, tmp_path):
    res, seen, _svc = _deploy(tf, monkeypatch, tmp_path, _legacy_tree(**{W + "custom.tf": SELF_REF_CUSTOM}),
                              apply_results=[_apply_err(SELF_REF_ERR)])
    assert res["status"] == "FAILED" and SELF_REF_ERR in res["error"]
    assert seen["applies"] == 1                                             # no rewrite-and-retry
    _unchanged(seen)
    with open(os.path.join(seen["ws"], "custom.tf"), encoding="utf-8") as fh:
        assert fh.read() == SELF_REF_CUSTOM


def test_a48_locals_apply_error_is_returned_without_curing(tf, monkeypatch, tmp_path):
    """The plural `locals.` file is written into the workspace at the first apply (after prepare_workspace), so the
    still-live A28 preparation curing (FD-55 W6b) cannot hide what the deleted apply-error curing would do."""
    def _plant(ws):
        with open(os.path.join(ws, "extra.tf"), "w", encoding="utf-8") as fh:
            fh.write(PLURAL_LOCALS)

    res, seen, _svc = _deploy(tf, monkeypatch, tmp_path, _legacy_tree(), apply_results=[_apply_err(PLURAL_ERR)],
                              on_first_apply=_plant)
    assert res["status"] == "FAILED" and PLURAL_ERR in res["error"]
    assert seen["applies"] == 1
    _unchanged(seen)
    with open(os.path.join(seen["ws"], "extra.tf"), encoding="utf-8") as fh:
        assert fh.read() == PLURAL_LOCALS


def test_kept_cloud_run_timeout_retry_still_retries(tf, monkeypatch, tmp_path):
    """Negative: the loop's kept triggers are unchanged (a Cloud Run creation timeout is retried once more)."""
    timeout = _apply_err("Error: timeout while waiting for Creating Service to complete")
    res, seen, _svc = _deploy(tf, monkeypatch, tmp_path, _legacy_tree(), apply_results=[timeout, dict(OK)])
    assert res["status"] == "SUCCESS", res
    assert seen["applies"] == 2
    _unchanged(seen)


# ------------------------------------------------------------------------------------------------ APPLY.WORKFLOW_INVALID
def test_invalid_committed_workflow_is_a_typed_deploy_stop(tf, monkeypatch, tmp_path):
    res, seen, _svc = _deploy(tf, monkeypatch, tmp_path, _legacy_tree(**{WF: INVALID_WF}))
    assert (res["status"], res["error_class"], res["code"]) == ("FAILED", "WORKFLOW_INVALID", "APPLY.WORKFLOW_INVALID")
    assert (res["file"], res["line"]) == (WF, 7)
    assert res["error"].startswith(f"APPLY.WORKFLOW_INVALID: the committed workflow {WF}:7 is not valid (")
    assert seen["cmds"] == [] and seen["applies"] == 0                      # nothing built, planned or applied
    assert "validation_report" not in res


def test_invalid_committed_workflow_is_a_typed_plan_stop(tf, monkeypatch, tmp_path):
    svc, _vcs = _service(tf, monkeypatch, tmp_path, {})
    cmds = []
    monkeypatch.setattr(svc, "_run_subprocess", lambda cmd, **k: cmds.append(cmd) or dict(OK))
    res = svc.generate_plan("shop", "t-w6c-plan", dict(_legacy_tree(), **{WF: INVALID_WF}), iac_engine="OPENTOFU")
    assert (res["status"], res["error_class"], res["code"]) == ("FAILED", "WORKFLOW_INVALID", "APPLY.WORKFLOW_INVALID")
    assert (res["file"], res["line"]) == (WF, 7) and res["is_safe_autonomous"] is False
    assert cmds == []


def test_valid_committed_workflow_is_applied_as_committed(tf, monkeypatch, tmp_path):
    """Negative: a workflow that passes the validator reaches the workspace byte-identical and the deploy goes on."""
    res, seen, _svc = _deploy(tf, monkeypatch, tmp_path, _legacy_tree(**{WF: VALID_WF}), apply_results=[dict(OK)])
    assert res["status"] == "SUCCESS", res
    with open(os.path.join(seen["ws"], WF), encoding="utf-8", newline="") as fh:
        assert fh.read() == VALID_WF


def test_only_the_workflow_validation_error_is_typed(tf, monkeypatch, tmp_path):
    """The fallback class is never `Exception`, and any other preparation error still propagates (not relabelled)."""
    assert tf.WorkflowValidationError is not Exception
    svc, _vcs = _service(tf, monkeypatch, tmp_path, _legacy_tree())

    def _boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(svc, "prepare_workspace", _boom)
    with pytest.raises(RuntimeError, match="disk full"):
        svc.generate_plan("shop", "t-w6c-boom", _legacy_tree(), iac_engine="OPENTOFU")


def test_workflow_invalid_stops_for_the_operator(workflow):
    bad = {"status": "FAILED", "error_class": "WORKFLOW_INVALID", "code": "APPLY.WORKFLOW_INVALID",
           "error": f"APPLY.WORKFLOW_INVALID: the committed workflow {WF}:7 is not valid (x). The file was not changed; "
                    "nothing was built, planned or applied.", "file": WF, "line": 7}
    f = Fleet()
    f.callbacks["deploy"] = [bad, {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert_failed(res, "WORKFLOW_INVALID", "terraform")
    assert "operator action required" in res.error["message"] and f"{WF}:7" in res.error["message"]
    assert len(calls(res, "/agent/developer/execute")) == 1                 # no developer remediation
    assert len(calls(res, TF + "/deploy-async")) == 1
    f2 = Fleet()
    f2.callbacks["deploy"] = [bad]
    res2, _ = run(workflow, f2, execution_mode="DEPLOY_ONLY", target_branch="main")
    assert_failed(res2, "WORKFLOW_INVALID", "terraform")
    assert "handle_operator_deploy_failure" in res2.steps_executed


def test_legacy_validation_failure_reaches_the_bounded_regeneration_with_its_text(workflow):
    """Plan acceptance: a legacy deploy failure (VALIDATION_FAILED, no error_class) goes to the existing developer
    regeneration with the engine's error string as its context."""
    err = "Shift-Left IaC validation failed:\n" + CR_ERR
    f = Fleet()
    f.callbacks["deploy"] = [{"status": "VALIDATION_FAILED", "error": err},
                             {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    devs = calls(res, "/agent/developer/execute")
    assert len(devs) == 2 and devs[1]["body"]["tf_remediation_context"] == err


def test_gateway_set_and_terraform_constants_agree():
    spec = importlib.util.spec_from_file_location(
        "w6c_gate_errors", os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "gate_errors.py"))
    gate_errors = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate_errors)
    assert "WORKFLOW_INVALID" in gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES
    with open(os.path.join(TF_DIR, "service.py"), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    consts = {t.id: n.value.value for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
              for t in n.targets if isinstance(t, ast.Name)}
    assert consts["ERROR_WORKFLOW_INVALID"] == "WORKFLOW_INVALID"
    assert consts["APPLY_WORKFLOW_INVALID"] == "APPLY.WORKFLOW_INVALID"
