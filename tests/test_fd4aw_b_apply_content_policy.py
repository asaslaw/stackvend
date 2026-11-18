"""FD-4AW-b (register row, owner 10-20): apply-time content policy on the saved plan's JSON.

Before any apply (the gated deploy apply and apply_plan), the plan `tofu show -json` printed is checked: provisioners,
module sources, provider sources and terraform_remote_state, over every file the engine loaded (human-written files
and nested modules included). A violation is a typed APPLY_CONTENT_POLICY refusal and nothing is applied.

Pure tests on plan JSON shaped like OpenTofu's (the shape is pinned by a real offline tofu run below), wiring tests
with a mocked subprocess, parity with the gateway's FD-4AW-a tables. Hermetic: no network, no GCP.
"""
import hermetic_guard  # noqa: F401  (first import: tests/hermetic_guard.py)

import json
import os
import shutil
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW = os.path.join(REPO, "apps", "orchestrator-gateway")
BUCKET = "castor-tfstate-mock"
PID = "shop"
OTF = "registry.opentofu.org/hashicorp/"


@pytest.fixture
def tf(monkeypatch):
    from fd4g_support import load_tf_service

    return load_tf_service(monkeypatch)


def _res(address, mode="managed", provisioners=None, expressions=None):
    rtype, name = address.split(".")[-2:]
    out = {"address": address, "mode": mode, "type": rtype, "name": name, "provider_config_key": "google"}
    if provisioners:
        out["provisioners"] = [{"type": p} for p in provisioners]
    if expressions is not None:
        out["expressions"] = expressions
    return out


def _plan(root=None, providers=("google",), changes=()):
    """A saved-plan JSON shaped like OpenTofu's `show -json` (see the real-engine test)."""
    return {
        "format_version": "1.2",
        "configuration": {
            "provider_config": {p: {"name": p, "full_name": OTF + p} for p in providers},
            "root_module": root if root is not None else {},
        },
        "resource_changes": [{"address": a, "provider_name": OTF + "google", "change": {"actions": ["create"]}}
                             for a in changes],
    }


def _golden_root():
    """What a valid workload's plan configuration looks like: golden modules by local path, google resources."""
    return {
        "resources": [_res("google_storage_bucket.uploads")],
        "module_calls": {
            "compute": {"source": "./infra/modules/compute-cloudrun", "module": {
                "resources": [_res("google_cloud_run_v2_service.svc")],
                "module_calls": {"inner": {"source": "../workload-foundation/base", "module": {}}}}},
            "foundation": {"source": "./infra/modules/workload-foundation/base", "module": {}},
            "db": {"source": "./modules/db", "module": {
                "module_calls": {"bucket": {"source": "../../infra/modules/storage-bucket", "module": {}}}}},
        },
    }


def _codes(violations):
    return sorted(v["code"] for v in violations)


# ------------------------------------------------------------------------------------------- negative (allowed)
def test_valid_workload_plan_has_no_violation(tf):
    plan = _plan(_golden_root(), providers=("google", "google-beta", "random", "kubernetes"),
                 changes=("google_storage_bucket.uploads", "module.compute.google_cloud_run_v2_service.svc"))
    plan["configuration"]["provider_config"]["terraform"] = {"name": "terraform",
                                                             "full_name": "terraform.io/builtin/terraform"}
    assert tf.plan_content_policy_violations(plan, BUCKET, PID) == []


def test_both_registry_hosts_of_the_pinned_providers_are_allowed(tf):
    plan = _plan()
    plan["resource_changes"] = [{"address": "x.y", "provider_name": f"{host}/hashicorp/{p}"}
                                for host in ("registry.opentofu.org", "registry.terraform.io")
                                for p in ("google", "google-beta", "kubernetes", "random")]
    assert tf.plan_content_policy_violations(plan, BUCKET, PID) == []


def test_typed_intent_render_sources_through_the_parent_modules_link_are_allowed(tf):
    """custom.tf.json (shared/iac_intent MODULE_SOURCE_PREFIX "../modules/") is copied to the workspace root as
    rendered; prepare_workspace links <trace>/modules to the workspace's infra/modules, so `../modules/<id>` (and a
    golden module's own `../<sibling>` calls from there) are platform modules."""
    root = {"module_calls": {"uploads": {"source": "../modules/storage-bucket", "module": {
        "module_calls": {"base": {"source": "../workload-foundation/base", "module": {}}}}}}}
    assert tf.plan_content_policy_violations(_plan(root), BUCKET, PID) == []


def test_own_state_remote_state_is_allowed(tf):
    own = _res("data.terraform_remote_state.self", mode="data", expressions={
        "backend": {"constant_value": "gcs"},
        "config": {"constant_value": {"bucket": BUCKET, "prefix": f"workloads/{PID}"}}})
    assert tf.plan_content_policy_violations(_plan({"resources": [own]}), BUCKET, PID) == []


# ------------------------------------------------------------------------------------------- refusals
@pytest.mark.parametrize("ptype", ["local-exec", "remote-exec", "file"])
def test_any_provisioner_in_any_module_is_refused(tf, ptype):
    root = {"resources": [_res("terraform_data.h", provisioners=[ptype])],
            "module_calls": {"db": {"source": "./modules/db", "module": {
                "resources": [_res("google_compute_instance.vm", provisioners=[ptype])]}}}}
    out = tf.plan_content_policy_violations(_plan(root), BUCKET, PID)
    assert _codes(out) == ["POLICY.PROVISIONER_FORBIDDEN"] * 2
    assert sorted(v["address"] for v in out) == ["module.db.google_compute_instance.vm", "terraform_data.h"]
    assert all(v["provisioner"] == ptype for v in out)


@pytest.mark.parametrize("call", [
    {"source": "terraform-google-modules/network/google", "version_constraint": "~> 9.0"},
    {"source": "git::https://example.com/m.git"},
    {"source": "https://example.com/m.zip"},
    {"source": "gcs::https://www.googleapis.com/storage/v1/b/m.zip"},
    {"source": "../outside-the-workspace"},
    {"source": "./infra/../../escape"},
    {"source": "./"},
    {"source": "./infra/modules/compute-cloudrun", "version_constraint": "1.0.0"},
    {"source": "../modules"},                 # the parent link itself is not a module directory
    {"source": "../bundles/web"},             # only ../modules is a platform link
    {"source": "../../modules/x"},
    {"source": "../modules/../secrets"},
])
def test_non_local_or_escaping_module_source_is_refused(tf, call):
    out = tf.plan_content_policy_violations(_plan({"module_calls": {"m": dict(call, module={})}}), BUCKET, PID)
    assert _codes(out) == ["POLICY.MODULE_SOURCE_NOT_LOCAL"] and out[0]["address"] == "module.m"


def test_nested_module_escaping_from_its_own_directory_is_refused(tf):
    root = {"module_calls": {"db": {"source": "./modules/db", "module": {
        "module_calls": {"up": {"source": "../../../etc", "module": {}}}}}}}
    out = tf.plan_content_policy_violations(_plan(root), BUCKET, PID)
    assert _codes(out) == ["POLICY.MODULE_SOURCE_NOT_LOCAL"] and out[0]["address"] == "module.db.module.up"


@pytest.mark.parametrize("full_name", [
    "registry.opentofu.org/hashicorp/null", "registry.opentofu.org/hashicorp/external",
    "registry.opentofu.org/evil/google", "example.com/hashicorp/google", "registry.terraform.io/hashicorp/local",
])
def test_provider_outside_the_pinned_set_is_refused_wherever_it_appears(tf, full_name):
    for where in ("provider_config", "resource_changes", "prior_state"):
        plan = _plan()
        if where == "provider_config":
            plan["configuration"]["provider_config"]["x"] = {"name": "x", "full_name": full_name}
        elif where == "resource_changes":
            plan["resource_changes"] = [{"address": "x.y", "provider_name": full_name}]
        else:
            plan["prior_state"] = {"values": {"root_module": {"child_modules": [
                {"resources": [{"address": "module.a.data.x.y", "provider_name": full_name}]}]}}}
        out = tf.plan_content_policy_violations(plan, BUCKET, PID)
        assert _codes(out) == ["POLICY.PROVIDER_SOURCE_MISMATCH"] and out[0]["provider"] == full_name, where


@pytest.mark.parametrize("expressions", [
    {"backend": {"constant_value": "gcs"}, "config": {"constant_value": {"bucket": "other", "prefix": f"workloads/{PID}"}}},
    {"backend": {"constant_value": "gcs"}, "config": {"constant_value": {"bucket": BUCKET, "prefix": "workloads/other"}}},
    {"backend": {"constant_value": "gcs"}, "config": {"constant_value": {"bucket": BUCKET, "prefix": f"workloads/{PID}",
                                                                         "impersonate_service_account": "x@y"}}},
    {"backend": {"constant_value": "gcs"}, "config": {"references": ["var.bucket"]}},
    {"backend": {"constant_value": "local"}, "config": {"constant_value": {"path": "/etc/state"}}},
    {"backend": {"constant_value": "http"}, "config": {"constant_value": {"address": "https://x"}}},
    {},
])
def test_remote_state_other_than_the_workloads_own_is_refused(tf, expressions):
    res = _res("data.terraform_remote_state.other", mode="data", expressions=expressions)
    out = tf.plan_content_policy_violations(_plan({"module_calls": {"m": {"source": "./modules/m", "module": {
        "resources": [res]}}}}), BUCKET, PID)
    assert _codes(out) == ["POLICY.REMOTE_STATE_FORBIDDEN"] and out[0]["address"] == \
        "module.m.data.terraform_remote_state.other"


def test_remote_state_is_refused_without_a_state_bucket(tf):
    own = _res("data.terraform_remote_state.self", mode="data", expressions={
        "backend": {"constant_value": "gcs"}, "config": {"constant_value": {"bucket": "", "prefix": f"workloads/{PID}"}}})
    assert _codes(tf.plan_content_policy_violations(_plan({"resources": [own]}), "", PID)) == [
        "POLICY.REMOTE_STATE_FORBIDDEN"]


@pytest.mark.parametrize("plan", [{}, {"resource_changes": []}, {"configuration": None}, {"configuration": []}])
def test_plan_without_configuration_fails_closed(tf, plan):
    assert _codes(tf.plan_content_policy_violations(plan, BUCKET, PID)) == ["POLICY.PLAN_NOT_CHECKABLE"]


# ------------------------------------------------------------------------------------------- parity
def test_provider_tables_match_the_gateway_fd4aw_a_tables(tf):
    for p in (GW, REPO):
        if p not in sys.path:
            sys.path.insert(0, p)
    from developer_agent.validators import policy_tables as T

    assert tf.APPLY_PLATFORM_PROVIDER_SOURCES == T.PLATFORM_PROVIDER_SOURCES
    assert tf.APPLY_PROVIDER_REGISTRIES == T.PLATFORM_PROVIDER_REGISTRIES
    fq = {f for forms in T.PLATFORM_PROVIDER_SOURCE_FORMS.values() for f in forms if f.count("/") == 2}
    assert tf.APPLY_ALLOWED_PROVIDERS == frozenset(fq | {"terraform.io/builtin/terraform"})


# ------------------------------------------------------------------------------------------- wiring
def _ok(stdout=""):
    return {"success": True, "exit_code": 0, "stdout": stdout, "stderr": ""}


_HUMAN_PROVISIONER_PLAN = _plan({"resources": [_res("terraform_data.from_human_tf", provisioners=["local-exec"])]})


def _svc(tf, tmp_path):
    return tf.TerraformService(project_id="mock-stackvend-project", state_bucket=BUCKET,
                               workspace_base_dir=str(tmp_path), firestore_client=MagicMock())


def test_gated_apply_refuses_before_any_apply_and_removes_the_plan_file(tf, tmp_path):
    svc = _svc(tf, tmp_path)
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / tf.compliance_gate.GATE_PLAN_FILE).write_text("saved")
    with patch.object(svc, "_run_subprocess", side_effect=[_ok("Plan"), _ok(json.dumps(_HUMAN_PROVISIONER_PLAN))]) as sub, \
            patch.object(svc, "_compliance_gate_check", side_effect=AssertionError("gate must not run")):
        with pytest.raises(tf.ContentPolicyRefused) as exc:
            svc._compliance_gated_apply(PID, "t-aw", str(ws), "OPENTOFU")
    assert [c.args[0][1] for c in sub.call_args_list] == ["plan", "show"]            # never `apply`
    res = exc.value.result
    assert (res["status"], res["error_class"]) == ("FAILED", "APPLY_CONTENT_POLICY")
    assert res["content_policy_violations"][0]["address"] == "terraform_data.from_human_tf"
    assert not (ws / tf.compliance_gate.GATE_PLAN_FILE).exists()
    assert isinstance(exc.value, tf.DestroyBlocked)   # every DestroyBlocked handler returns the typed result


def test_gated_apply_with_a_clean_plan_is_unchanged(tf, tmp_path):
    """Do No Harm (negative): a valid plan goes on to the compliance gate and the apply exactly as before."""
    svc = _svc(tf, tmp_path)
    ws = tmp_path / "ws"
    ws.mkdir()
    plan = _plan(_golden_root(), changes=("google_storage_bucket.uploads",))
    with patch.object(svc, "_run_subprocess", side_effect=[_ok("Plan"), _ok(json.dumps(plan)), _ok("Apply complete!")]) \
            as sub, patch.object(svc, "_compliance_gate_check", return_value={"passed": True}) as gate:
        res = svc._compliance_gated_apply(PID, "t-aw", str(ws), "OPENTOFU")
    assert res["success"] and gate.call_count == 1
    assert [c.args[0][1] for c in sub.call_args_list] == ["plan", "show", "apply"]


def test_deploy_workload_returns_the_typed_refusal(tf, tmp_path):
    svc = _svc(tf, tmp_path)
    refusal = tf.content_policy_refusal(PID, "t-aw", tf.plan_content_policy_violations(_HUMAN_PROVISIONER_PLAN))
    with patch.object(svc, "_deploy_workload_impl", side_effect=tf.ContentPolicyRefused(refusal)), \
            patch.object(svc, "_sync_feature_requests"):
        res = svc.deploy_workload(product_id=PID, trace_id="t-aw", hcl_files={})
    assert res == refusal and res["error"].startswith("APPLY_CONTENT_POLICY:")


def test_apply_plan_refuses_a_violating_saved_plan_without_applying(tf, tmp_path):
    svc = _svc(tf, tmp_path)
    ws = svc._workspace_dir("t-ap", PID)
    os.makedirs(ws, exist_ok=True)
    with open(os.path.join(ws, "tfplan"), "w") as fh:
        fh.write("saved")
    with patch.object(svc, "_validate_no_engine_downgrade"), \
            patch.object(svc, "_run_subprocess", return_value=_ok(json.dumps(_HUMAN_PROVISIONER_PLAN))) as sub:
        res = svc.apply_plan(PID, "t-ap", iac_engine="OPENTOFU")
    assert (res["status"], res["reason"], res["error_class"]) == ("REFUSED", "APPLY_CONTENT_POLICY",
                                                                   "APPLY_CONTENT_POLICY")
    assert [c.args[0][1] for c in sub.call_args_list] == ["show"]


# ------------------------------------------------------------------------------------------- real engine
# The eval harness's pinned production engine (OpenTofu 1.9.0), preferred when present on this machine.
PINNED_TOFU = os.environ.get("STACKVEND_PINNED_TOFU", "")  # the production tofu 1.9.0 when set; else the local tofu


def _tofu():
    if os.path.isfile(PINNED_TOFU) and os.access(PINNED_TOFU, os.X_OK):
        return PINNED_TOFU
    return shutil.which("tofu") or ("/opt/homebrew/bin/tofu" if os.path.exists("/opt/homebrew/bin/tofu") else None)


def test_real_engine_plan_of_a_human_tf_provisioner_is_refused(tf, tmp_path):
    """Engine check (local tofu, built-in provider only, no backend, no network): the plan JSON OpenTofu itself
    prints for a workspace whose human.tf and nested module declare provisioners and a local remote state is refused
    for exactly those blocks; the same workspace without them passes."""
    tofu = _tofu()
    if not tofu:
        pytest.skip("needs a local tofu")
    env = dict(os.environ, TF_IN_AUTOMATION="1", CHECKPOINT_DISABLE="1", TF_INPUT="0")

    def plan_of(files):
        ws = tmp_path / str(len(list(tmp_path.iterdir())))
        for rel, text in files.items():
            (ws / rel).parent.mkdir(parents=True, exist_ok=True)
            (ws / rel).write_text(text)
        for args in (["init", "-backend=false", "-no-color"], ["plan", "-out=p.tfplan", "-no-color"]):
            r = subprocess.run([tofu, *args], cwd=ws, capture_output=True, text=True, env=env, timeout=120)
            assert r.returncode == 0, r.stderr
        r = subprocess.run([tofu, "show", "-json", "p.tfplan"], cwd=ws, capture_output=True, text=True, env=env,
                           timeout=120)
        return json.loads(r.stdout)

    clean = {"main.tf": 'module "db" {\n  source = "./modules/db"\n}\n',
             "modules/db/main.tf": 'module "g" {\n  source = "../../infra/modules/g"\n}\n',
             "infra/modules/g/main.tf": 'resource "terraform_data" "y" {\n  input = "ok"\n}\n'}
    assert tf.plan_content_policy_violations(plan_of(clean), BUCKET, PID) == []
    bad = dict(clean, **{
        "human.tf": 'resource "terraform_data" "h" {\n  provisioner "local-exec" {\n    command = "id"\n  }\n}\n'
                    'data "terraform_remote_state" "o" {\n  backend = "local"\n  config = {\n'
                    '    path = "other.tfstate"\n  }\n}\n',
        "other.tfstate": json.dumps({"version": 4, "terraform_version": "1.9.0", "serial": 1, "lineage": "x",
                                     "outputs": {}, "resources": []}),
        "infra/modules/g/main.tf": 'resource "terraform_data" "y" {\n  provisioner "file" {\n    source = "a"\n'
                                   '    destination = "b"\n  }\n}\n'})
    out = tf.plan_content_policy_violations(plan_of(bad), BUCKET, PID)
    assert sorted((v["code"], v["address"]) for v in out) == [
        ("POLICY.PROVISIONER_FORBIDDEN", "module.db.module.g.terraform_data.y"),
        ("POLICY.PROVISIONER_FORBIDDEN", "terraform_data.h"),
        ("POLICY.REMOTE_STATE_FORBIDDEN", "data.terraform_remote_state.o")]
