"""DEPLOY-ROOT-VARS (follow-up of AI-TFVARS-REFUSED; owner 11-07 backlog approval): every gated plan of a deploy is
checked against the exact input values the platform supplies (root terraform.tfvars keys, TF_VAR_* secrets, the access
variables when the access file was rendered). A root-declared platform variable whose value in the plan's own
`variables` differs (or is missing) refuses the apply typed: APPLY.ROOT_VARIABLE_OVERRIDDEN, error class
TFVARS_OVERRIDES_PLATFORM, operator_required, naming the variable and never its value. Nothing is imported or applied.

Negatives: equal values, a variable the root does not declare, and callers without expected values change nothing.
The OpenTofu contract this relies on (`variables` holds each root variable's raw input value, sensitive ones included)
is pinned against the real binary when it is installed.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import)

import ast
import copy
import json
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from test_lane14_compliance_gate import HIPAA_DECISION, FakeRunner, _svc, _wire_gate  # noqa: E402

PASS = {"gate_contract_version": 1, "decision": "PASS", "violations": []}
SECRET = "s3cr3t-value-never-shown"
EXPECTED_TFVARS = {"project_id": '"child-1"', "region": '"us-central1"', "product_id": '"claims"',
                   "container_image": '"us-central1-docker.pkg.dev/child-1/claims/app:latest"',
                   "enable_github_actions_deploy": "true"}
ACCESS = json.dumps({"allow_unauthenticated": False, "enable_direct_iap": True,
                     "authorized_invoker_members": ["user:a@example.com", "group:g@example.com"]})


@pytest.fixture()
def tf(monkeypatch):
    from fd4g_support import load_tf_service

    return load_tf_service(monkeypatch)


def _expected(tf, access=ACCESS):
    return tf.platform_root_variable_values(EXPECTED_TFVARS, {"oauth_client_secret": "", "firebase_api_key": SECRET},
                                            access)


def _plan(variables):
    plan = {"format_version": "1.2", "configuration": {"root_module": {}}, "resource_changes": []}
    if variables is not None:
        plan["variables"] = {k: {"value": v} for k, v in variables.items()}
    return plan


def _same(tf, **override):
    vals = dict(_expected(tf))
    vals.update(override)
    return vals


# --------------------------------------------------------------------------------------------- pure
def test_platform_values_are_the_exact_inputs(tf):
    exp = _expected(tf)
    assert exp["project_id"] == "child-1" and exp["enable_github_actions_deploy"] is True
    assert exp["firebase_api_key"] == SECRET and exp["oauth_client_secret"] == ""
    assert exp["authorized_invoker_members"] == ["user:a@example.com", "group:g@example.com"]
    assert exp["allow_unauthenticated"] is False
    assert "allow_unauthenticated" not in tf.platform_root_variable_values(EXPECTED_TFVARS, {}, "{}")
    assert "allow_unauthenticated" not in tf.platform_root_variable_values(EXPECTED_TFVARS, {}, None)


def test_negative_equal_values_and_undeclared_variables_are_no_finding(tf):
    exp = _expected(tf)
    assert tf.root_variable_overrides(_plan(exp), exp) == []
    assert tf.root_variable_overrides(_plan({"project_id": "child-1"}), exp) == []   # the rest are not declared
    assert tf.root_variable_overrides(_plan({}), exp) == []
    assert tf.root_variable_overrides(_plan(None), exp) == []   # a root without variables: no `variables` member
    assert tf.root_variable_overrides(_plan(dict(exp, own_var="anything")), exp) == []


@pytest.mark.parametrize("name,value", [
    ("project_id", "other-project"), ("region", "europe-west1"), ("container_image", "evil/image:1"),
    ("firebase_api_key", "replaced"), ("enable_github_actions_deploy", "true"),   # "true" is not true (exact)
    ("enable_github_actions_deploy", 1), ("allow_unauthenticated", True),
    ("authorized_invoker_members", ["group:g@example.com", "user:a@example.com"]),   # order counts
    ("authorized_invoker_members", ["allUsers"]), ("oauth_client_secret", None),
])
def test_a_different_value_is_a_finding_naming_only_the_variable(tf, name, value):
    exp = _expected(tf)
    findings = tf.root_variable_overrides(_plan(_same(tf, **{name: value})), exp)
    assert [f["variable"] for f in findings] == [name]
    result = tf.root_variable_overridden_result("claims", "t", findings)
    assert result["code"] == "APPLY.ROOT_VARIABLE_OVERRIDDEN" and result["error_class"] == "TFVARS_OVERRIDES_PLATFORM"
    assert result["operator_required"] is True and result["variables"] == [name]
    assert result["error"].startswith("APPLY.ROOT_VARIABLE_OVERRIDDEN: ")
    assert "remove it from the repository or the runner environment" in result["error"]   # RT F6
    assert SECRET not in json.dumps(result) and "replaced" not in result["error"]


def test_no_value_and_unreadable_variables_are_findings(tf):
    exp = _expected(tf)
    plan = _plan({"region": "us-central1"})
    plan["variables"]["project_id"] = {}
    assert tf.root_variable_overrides(plan, exp) == [{"variable": "project_id", "reason": "has no value in the plan"}]
    assert [f["variable"] for f in tf.root_variable_overrides(dict(plan, variables=[]), exp)] == ["*"]


def test_an_undecodable_platform_value_never_matches(tf):
    exp = tf.platform_root_variable_values({"project_id": "not-json"}, {}, None)
    assert [f["variable"] for f in tf.root_variable_overrides(_plan({"project_id": "not-json"}), exp)] == \
        ["project_id"]


# --------------------------------------------------------------------------------------------- gated apply
def _gated(monkeypatch, tf, tmp_path, plan_json):
    calls = []
    _wire_gate(monkeypatch, tf, None, calls, status=200, payload=PASS)
    store = copy.deepcopy(HIPAA_DECISION)
    svc, ws = _svc(tf, tmp_path, store)
    runner = FakeRunner(plan_json)
    monkeypatch.setattr(svc, "_run_subprocess", runner)
    return svc, ws, runner, calls, store


def test_gated_apply_refuses_an_override_before_anything_is_imported_or_applied(monkeypatch, tf, tmp_path):
    svc, ws, runner, calls, store = _gated(monkeypatch, tf, tmp_path, _plan(_same(tf, region="europe-west1")))
    adopted = []
    with pytest.raises(tf.RootVariableOverridden) as ei:
        svc._compliance_gated_apply("claims", "t-rv", ws, "OPENTOFU", pre_apply_adopt=lambda p: adopted.append(p) or 0,
                                    expected_root_vars=_expected(tf))
    assert isinstance(ei.value, tf.DestroyBlocked)   # every DestroyBlocked handler returns .result
    assert ei.value.result["variables"] == ["region"]
    assert runner.calls == ["plan", "show"] and calls == [] and adopted == []
    assert not os.path.exists(os.path.join(ws, tf.compliance_gate.GATE_PLAN_FILE))
    ev = store["workloads/claims/compliance_audits/t-rv"]["enforcement"]
    assert ev["gate"] == "root_variables" and ev["variables"] == ["region"] and SECRET not in json.dumps(ev)


def test_negative_gated_apply_with_the_platform_values_applies(monkeypatch, tf, tmp_path):
    svc, ws, runner, calls, _ = _gated(monkeypatch, tf, tmp_path, _plan(_expected(tf)))
    res = svc._compliance_gated_apply("claims", "t", ws, "OPENTOFU", expected_root_vars=_expected(tf))
    assert res["success"] is True and runner.calls == ["plan", "show", "apply"] and len(calls) == 1


def test_negative_gated_apply_without_expected_values_checks_nothing(monkeypatch, tf, tmp_path):
    """Callers other than the deploy (none passes the argument) are unchanged."""
    svc, ws, runner, calls, _ = _gated(monkeypatch, tf, tmp_path, _plan(_same(tf, region="europe-west1")))
    assert svc._compliance_gated_apply("claims", "t", ws, "OPENTOFU")["success"] is True
    assert runner.calls == ["plan", "show", "apply"]


def test_every_gated_apply_of_the_deploy_passes_the_expected_values(tf):
    tree = ast.parse(open(tf.__file__).read())
    impl = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_deploy_workload_impl"][0]
    gated = [c for c in ast.walk(impl) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
             and c.func.attr == "_compliance_gated_apply"]
    assert len(gated) == 4   # CLOUDSQL-CREATE-OWN-OPERATION: + the retry after adopting the deploy's own Cloud SQL
    for c in gated:
        kw = {k.arg: k.value for k in c.keywords}
        assert isinstance(kw.get("expected_root_vars"), ast.Name) and kw["expected_root_vars"].id == "expected_root_vars"


def test_deploy_supplies_exactly_its_platform_values(tf, tmp_path, monkeypatch):
    """The real deploy hands the gated apply the values it writes: every platform tfvars key (container_image the
    runtime value) and the TF_VAR_* secrets; no access keys without a rendered access record."""
    import importlib
    import types
    from unittest.mock import MagicMock

    import google.auth
    import google.auth.transport.requests as gatr
    settings = importlib.import_module("shared.settings")
    monkeypatch.setattr(settings, "_SETTINGS_CACHE", settings.PlatformSettings())
    monkeypatch.setattr(settings, "_LAST_FETCH_TIME", float("inf"))
    sess = MagicMock(name="session")
    sess.get.return_value = types.SimpleNamespace(status_code=404, json=lambda: {}, text="")
    sess.post.return_value = types.SimpleNamespace(status_code=404, json=lambda: {}, text="")
    monkeypatch.setattr(google.auth, "default", lambda *a, **k: (MagicMock(valid=True, token="t"), "p"))
    monkeypatch.setattr(gatr, "AuthorizedSession", lambda *a, **k: sess)

    svc = tf.TerraformService(project_id="castor-parent", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock(name="firestore"))
    svc.db = None
    svc.state_bucket = ""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "main.tf").write_text('resource "google_cloud_run_v2_service" "app" {\n  name = "shop"\n}\n')
    (ws / "main.py").write_text("print('hi')\n")
    seen = {}

    def _gated(product_id, trace_id, workspace_dir, active_engine, **kw):
        seen.setdefault("expected", kw.get("expected_root_vars"))
        return {"success": True, "returncode": 0, "stdout": "Apply complete!", "stderr": ""}

    svc._fetch_repo_files = lambda *a, **k: {}
    svc.prepare_workspace = lambda *a, **k: str(ws)
    svc._build_and_push_container = lambda *a, **k: True
    svc._ensure_provider_mirror = lambda *a, **k: "/nonexistent/terraform.rc"
    svc._validate_no_engine_downgrade = lambda *a, **k: None
    svc._list_cloud_run_services = lambda *a, **k: ([], None)
    svc._compliance_gated_apply = _gated
    svc._run_subprocess = lambda cmd, **k: {"success": True, "returncode": 0,
                                           "stdout": '{"format_version": "1.0"}' if "show" in cmd else "{}",
                                           "stderr": ""}
    res = svc.deploy_workload(product_id="shop", trace_id="t-rv", target_project_id="child-1",
                              hcl_files={"main.tf": 'variable "project_id" {}\n'})
    assert res["status"] == "SUCCESS", res
    exp = seen["expected"]
    assert exp["project_id"] == "child-1" and exp["product_id"] == "shop"
    assert exp["container_image"].endswith("/app:latest") and exp["container_image"].startswith(exp["region"])
    assert exp["oauth_client_secret"] == "" and exp["firebase_api_key"] == ""
    assert {"github_repo_full_name", "oauth_client_id", "firebase_auth_domain"} <= set(exp)
    assert not {"allow_unauthenticated", "enable_direct_iap", "authorized_invoker_members"} & set(exp)


# --------------------------------------------------------------------------------------------- OpenTofu contract
@pytest.mark.skipif(shutil.which("tofu") is None, reason="OpenTofu is not installed")
def test_opentofu_plan_json_variables_are_the_raw_inputs(tmp_path):
    """`tofu show -json <plan>`: `variables` holds every root variable's input value as given (sensitive values in
    plain text, no type conversion, list order kept), from terraform.tfvars, *.auto.tfvars*, -var-file and TF_VAR_*,
    the winner of OpenTofu's precedence. No provider: init needs no network."""
    (tmp_path / "main.tf").write_text(
        'variable "firebase_api_key" {\n  type      = string\n  sensitive = true\n}\n'
        'variable "region" { type = string }\nvariable "flag" { type = string }\n'
        'variable "members" { type = set(string) }\nvariable "project_id" { type = string }\n'
        'variable "dflt" {\n  type    = string\n  default = "d"\n}\n')
    (tmp_path / "terraform.tfvars").write_text('region = "us-central1"\nflag = true\nproject_id = "child-1"\n')
    (tmp_path / "x.auto.tfvars").write_text('project_id = "other"\n')
    (tmp_path / "access.auto.tfvars.json").write_text('{"members": ["b", "a"]}')
    env = dict(os.environ, TF_VAR_firebase_api_key=SECRET, TF_IN_AUTOMATION="1", TF_CLI_CONFIG_FILE=os.devnull)
    for cmd in (["tofu", "init", "-input=false", "-no-color"],
                ["tofu", "plan", "-out=tfplan", "-input=false", "-no-color", "-var-file=access.auto.tfvars.json"]):
        done = subprocess.run(cmd, cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
        assert done.returncode == 0, done.stderr
    shown = subprocess.run(["tofu", "show", "-json", "tfplan"], cwd=tmp_path, env=env, capture_output=True, text=True,
                           timeout=60)
    variables = json.loads(shown.stdout)["variables"]
    assert {k: v["value"] for k, v in variables.items()} == {
        "firebase_api_key": SECRET, "region": "us-central1", "flag": True, "members": ["b", "a"],
        "project_id": "other", "dflt": "d"}
