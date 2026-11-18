"""FD-55 W6e (register FD55-W6e, owner 11-07 blanket backlog approval; plan docs/planning/fd55-w6e-w7-plan.md §2): the
last legacy apply-time edits of `_deploy_workload_impl` are deleted.

- A33 (HB-15): no block of infra/workloads/ (plural) is merged into custom.tf / variables.tf by text pattern. The plural
  directory is the root config only when nothing else gives the workspace a main.tf (then every plural .tf is copied
  to its path); beside another root config any plural .tf stops the deploy typed (APPLY.PLURAL_WORKLOADS_NOT_APPLIED).
- A34: the `env { name = "PORT" }` regex strip is gone; a planned Cloud Run service that sets PORT stops the gated
  apply before any import or apply (APPLY.RESERVED_ENV_PORT, read from the plan JSON).
- A35 (GKE guardrail 4) and A43 (Layer 3b): pinned in mcp-servers/terraform/test_service.py (a GKE workload applies
  as committed; no synthetic compute module).

Hermetic: fakes only (no network, no GCP, no tofu binary)."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import)

import ast
import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from test_fd4d_b_workload_paths import (  # noqa: E402
    ROOT_TF, ROOT_TF_FLAT, VARS_TF, OUT_TF, _files_reaching_the_workspace, _no_gcp, _svc as _ws_svc)
from test_lane14_compliance_gate import HIPAA_DECISION, FakeRunner, _svc, _wire_gate  # noqa: E402

PASS = {"gate_contract_version": 1, "decision": "PASS", "violations": []}
P = "infra/workloads/"


@pytest.fixture
def tf(monkeypatch):
    from fd4g_support import load_tf_service

    return load_tf_service(monkeypatch)


# --------------------------------------------------------------------------------------------- A33 plural workloads
def _deploy_result(tf, monkeypatch, tmp_path, tree):
    """deploy_workload's result for `tree` when it stops before prepare_workspace (nothing built, no tofu)."""
    svc = _ws_svc(tf, tmp_path)
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: dict(tree))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **k: pytest.fail("tofu ran"))
    monkeypatch.setattr(svc, "_build_and_push_container", lambda *a, **k: pytest.fail("built"))
    monkeypatch.setattr(svc, "prepare_workspace", lambda *a, **k: pytest.fail("workspace prepared"))
    _no_gcp(monkeypatch)
    return svc.deploy_workload(product_id="app", trace_id="t-w6e", target_project_id="p-1", branch="main",
                               iac_engine="OPENTOFU")


def test_plural_only_repository_copies_every_plural_file(tf, monkeypatch, tmp_path):
    """Before W6e the per-file `"main.tf" in files` check sent the plural variables.tf / outputs.tf (listed after
    main.tf) to the merge branch, which dropped outputs.tf and merged variables.tf only into an existing one."""
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, {
        P + "main.tf": ROOT_TF, P + "outputs.tf": OUT_TF, P + "variables.tf": VARS_TF})
    assert files["main.tf"] == ROOT_TF_FLAT
    assert files["outputs.tf"] == OUT_TF and files["variables.tf"] == VARS_TF
    assert "custom.tf" not in files


def test_plural_beside_a_singular_root_stops_typed_nothing_built(tf, monkeypatch, tmp_path):
    res = _deploy_result(tf, monkeypatch, tmp_path, {
        "infra/workload/main.tf": ROOT_TF,
        P + "main.tf": 'resource "google_storage_bucket" "b" {\n  name = "b"\n}\n', P + "variables.tf": VARS_TF})
    assert res["status"] == "FAILED" and res["code"] == "APPLY.PLURAL_WORKLOADS_NOT_APPLIED"
    assert res["error_class"] == "IAC_DEFECT"
    assert res["error"].startswith("APPLY.PLURAL_WORKLOADS_NOT_APPLIED: ")
    assert P + "main.tf" in res["error"] and P + "variables.tf" in res["error"]
    assert "Nothing was built, planned or applied." in res["error"]


def test_plural_beside_a_repository_root_main_stops_typed(tf, monkeypatch, tmp_path):
    res = _deploy_result(tf, monkeypatch, tmp_path, {"main.tf": ROOT_TF, P + "outputs.tf": OUT_TF})
    assert res["code"] == "APPLY.PLURAL_WORKLOADS_NOT_APPLIED" and P + "outputs.tf" in res["error"]


def test_plural_beside_a_root_main_names_every_root_source(tf, monkeypatch, tmp_path):
    """Review F4: the root main.tf may also come from the deploy request's hcl_files; the message names all three."""
    res = _deploy_result(tf, monkeypatch, tmp_path, {"infra/workload/main.tf": ROOT_TF, P + "outputs.tf": OUT_TF})
    assert "infra/workload/, the repository root or the deploy request" in res["error"]


def test_plural_on_an_intent_workspace_stops_typed(tf, monkeypatch, tmp_path):
    """Review F6: a typed-intent workspace never uses infra/workloads/; a plural .tf there stops typed instead of being
    left where OpenTofu ignores it (before: neither copied nor refused)."""
    from test_fd4d_b_workload_paths import _intent_tree

    res = _deploy_result(tf, monkeypatch, tmp_path, dict(_intent_tree(), **{P + "extra.tf": OUT_TF}))
    assert res["code"] == "APPLY.PLURAL_WORKLOADS_NOT_APPLIED" and P + "extra.tf" in res["error"]
    assert "the typed IaC intent is this workload's root configuration" in res["error"]


def test_negative_intent_workspace_without_plural_files_is_unchanged(tf, monkeypatch, tmp_path):
    from test_fd4d_b_workload_paths import _intent_tree

    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, _intent_tree())
    assert files["main.tf"] == ROOT_TF_FLAT and "infra/workload/iac_intent.json" in files


def test_negative_no_plural_files_give_exactly_the_old_manifest(tf, monkeypatch, tmp_path):
    """Do No Harm: without infra/workloads/ the manifest is the FD-4D-b one (keys, values, order)."""
    W = "infra/workload/"
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, {
        W + "main.tf": ROOT_TF, W + "variables.tf": VARS_TF, W + "outputs.tf": OUT_TF})
    assert list(files.items()) == [
        (W + "main.tf", ROOT_TF), (W + "variables.tf", VARS_TF), (W + "outputs.tf", OUT_TF),
        (W + "stackvend-access.auto.tfvars.json", "{}"),
        ("main.tf", ROOT_TF_FLAT), ("variables.tf", VARS_TF), ("outputs.tf", OUT_TF),
        ("stackvend-access.auto.tfvars.json", "{}")]


def test_negative_non_tf_plural_files_never_stop(tf, monkeypatch, tmp_path):
    """Only `.tf` files of infra/workloads/ are IaC the deploy would apply (exact suffix, as before)."""
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, {
        "infra/workload/main.tf": ROOT_TF, P + "README.md": "# notes\n"})
    assert files["main.tf"] == ROOT_TF_FLAT and files[P + "README.md"] == "# notes\n"


def test_plural_merge_code_is_gone(tf):
    src = open(tf.__file__).read()
    impl = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)
            and n.name == "_deploy_workload_impl"][0]
    body = ast.get_source_segment(src, impl)
    for gone in ("Auto-merged bespoke resources", "Auto-merged {len(missing_vars)}", "Auto-healed missing 'cluster_ca",
                 "Auto-wired secondary Cloud Run module", "name\\s*=\\s*\"PORT\"", "is_gke_workload",
                 "Autonomous Multi-Tier Auto-Wiring"):
        assert gone not in body, gone


# --------------------------------------------------------------------------------------------- A34 PORT plan check
def _rc(rtype, actions, after, address=None, mode="managed"):
    return {"address": address or f"{rtype}.svc", "mode": mode, "type": rtype,
            "change": {"actions": actions, "after": after, "after_unknown": {}}}


def _v2(*envs, name="app"):
    return {"template": [{"containers": [{"name": name, "image": "i", "env": [dict(e) for e in envs]}]}]}


def _v1(*envs):
    return {"template": [{"spec": [{"containers": [{"image": "i", "env": [dict(e) for e in envs]}]}]}]}


PORT = {"name": "PORT", "value": "8080"}
OTHER = {"name": "LOG_LEVEL", "value": "info"}


def _plan(*changes):
    return {"format_version": "1.2", "configuration": {"root_module": {}}, "resource_changes": list(changes)}


@pytest.mark.parametrize("rc,expected", [
    (_rc("google_cloud_run_v2_service", ["create"], _v2(OTHER, PORT)),
     [{"address": "google_cloud_run_v2_service.svc", "container": "app"}]),
    (_rc("google_cloud_run_v2_service", ["update"], _v2(PORT), address="module.compute.google_cloud_run_v2_service.s"),
     [{"address": "module.compute.google_cloud_run_v2_service.s", "container": "app"}]),
    (_rc("google_cloud_run_v2_service", ["delete", "create"], _v2(PORT)),
     [{"address": "google_cloud_run_v2_service.svc", "container": "app"}]),
    (_rc("google_cloud_run_service", ["create"], _v1(PORT)),
     [{"address": "google_cloud_run_service.svc", "container": "0"}]),
], ids=["v2-create", "v2-update-in-module", "v2-replace", "v1-create"])
def test_a_planned_cloud_run_port_is_a_finding(tf, rc, expected):
    assert tf.reserved_env_port_findings(_plan(rc)) == expected


@pytest.mark.parametrize("rc", [
    _rc("google_cloud_run_v2_service", ["create"], _v2(OTHER)),
    _rc("google_cloud_run_v2_service", ["create"], _v2({"name": "port", "value": "1"})),      # exact name
    _rc("google_cloud_run_v2_service", ["create"], _v2({"name": "APP_PORT", "value": "1"})),
    _rc("google_cloud_run_v2_service", ["create"], _v2(OTHER, {"value": "x"})),               # unknown name
    _rc("google_cloud_run_v2_service", ["delete"], None),
    _rc("google_cloud_run_v2_service", ["no-op"], _v2(PORT)),     # nothing is sent to Cloud Run
    _rc("google_cloud_run_v2_service", ["read"], _v2(PORT), mode="data"),
    _rc("google_cloud_run_v2_job", ["create"], {"template": [{"template": [{"containers": [{"env": [PORT]}]}]}]}),
    _rc("kubernetes_deployment", ["create"], {"spec": [{"container": [{"env": [PORT]}]}]}),
    _rc("google_cloud_run_v2_service", ["create"], {"template": "not-a-block"}),
], ids=["other-env", "lower-case", "suffix", "no-name", "delete", "no-op", "data", "job", "k8s", "malformed"])
def test_negative_no_finding(tf, rc):
    assert tf.reserved_env_port_findings(_plan(rc)) == []


def test_negative_unreadable_plans_are_no_finding(tf):
    for plan in (None, {}, {"resource_changes": None}, {"resource_changes": ["x", 1]}, []):
        assert tf.reserved_env_port_findings(plan) == []


def test_result_is_typed_and_names_the_service(tf):
    res = tf.reserved_env_port_result("claims", "t", [{"address": "module.compute.x", "container": "app"}])
    assert res["status"] == "FAILED" and res["code"] == "APPLY.RESERVED_ENV_PORT" and res["error_class"] == "IAC_DEFECT"
    assert res["error"].startswith("APPLY.RESERVED_ENV_PORT: ") and "module.compute.x" in res["error"]
    assert "Nothing was applied." in res["error"]


def _gated(monkeypatch, tf, tmp_path, plan_json):
    calls = []
    _wire_gate(monkeypatch, tf, None, calls, status=200, payload=PASS)
    store = copy.deepcopy(HIPAA_DECISION)
    svc, ws = _svc(tf, tmp_path, store)
    runner = FakeRunner(plan_json)
    monkeypatch.setattr(svc, "_run_subprocess", runner)
    return svc, ws, runner, calls, store


def test_gated_apply_refuses_port_before_any_import_or_apply(monkeypatch, tf, tmp_path):
    plan = _plan(_rc("google_cloud_run_v2_service", ["create"], _v2(PORT)))
    svc, ws, runner, calls, store = _gated(monkeypatch, tf, tmp_path, plan)
    adopted = []
    with pytest.raises(tf.ReservedEnvRefused) as ei:
        svc._compliance_gated_apply("claims", "t-port", ws, "OPENTOFU",
                                    pre_apply_adopt=lambda p: adopted.append(p) or 0)
    assert isinstance(ei.value, tf.DestroyBlocked)   # every DestroyBlocked handler returns .result
    assert ei.value.result["code"] == "APPLY.RESERVED_ENV_PORT"
    assert runner.calls == ["plan", "show"] and calls == [] and adopted == []
    assert not os.path.exists(os.path.join(ws, tf.compliance_gate.GATE_PLAN_FILE))
    ev = store["workloads/claims/compliance_audits/t-port"]["enforcement"]
    assert ev["gate"] == "reserved_env" and ev["code"] == "APPLY.RESERVED_ENV_PORT"


def test_negative_gated_apply_without_port_applies(monkeypatch, tf, tmp_path):
    plan = _plan(_rc("google_cloud_run_v2_service", ["create"], _v2(OTHER)))
    svc, ws, runner, calls, _ = _gated(monkeypatch, tf, tmp_path, plan)
    res = svc._compliance_gated_apply("claims", "t", ws, "OPENTOFU")
    assert res["success"] is True and runner.calls == ["plan", "show", "apply"] and len(calls) == 1


def test_the_replan_after_pass0_is_checked_too(tf):
    """Both saved plans of the gated apply (the first one and the re-plan after a Pass 0 import) are checked."""
    src = open(tf.__file__).read()
    gated = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)
             and n.name == "_compliance_gated_apply"][0]
    names = [c.func.attr for c in ast.walk(gated) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)]
    assert names.count("_refuse_reserved_env_port") == 2 == names.count("_read_saved_plan")
