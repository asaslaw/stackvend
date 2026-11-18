"""settings-toggles ST-2: governance.require_hitl_for_destructive_tf in the terraform MCP gated apply.

On (or unreadable: strict read, fail closed) -> a plan that deletes / replaces a resource (not a tainted replacement)
stops before the apply with DESTROY_REQUIRES_APPROVAL (an operator class). Off, or a plan without removals (the setting
is then not even read) -> exactly today's behavior. Hermetic: fake runner, in-process compliance server.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
SPEC_DIR = os.path.join(REPO_ROOT, "apps", "spec-ingestion")
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.dirname(__file__))

from shared import settings as S  # noqa: E402


def _settings(**gov):
    return S.PlatformSettings(governance=gov)


def _raises(err):
    def read(*a, **k):
        raise err
    return read


def _never_read(*a, **k):
    raise AssertionError("the settings must not be read when there is nothing to decide")


@pytest.fixture(autouse=True)
def _fresh_settings_caches():
    def clear():
        for name in ("shared.settings", "shared_settings"):
            mod = sys.modules.get(name)
            if mod is not None and hasattr(mod, "invalidate_settings_cache"):
                mod.invalidate_settings_cache()
        S.invalidate_settings_cache()
    clear()
    yield
    clear()


ERRORS = [S.PlatformSettingsReadError("down"), S.PlatformSettingsInvalid("bad"), RuntimeError("anything else")]
ERROR_CODES = ["PLATFORM_SETTINGS_READ_FAILED", "PLATFORM_SETTINGS_INVALID", "PLATFORM_SETTINGS_UNAVAILABLE"]

# ================================================================================================ destructive TF HITL
from test_lane14_compliance_gate import (  # noqa: E402
    AUDIT, HIPAA_DECISION, FakeRunner, _svc, _wire_gate, bucket, compliance, plan, tf)  # noqa: F401 (fixtures)


def _change(rtype, actions, before=None, reason=None, address=None, deposed=None):
    c = {"address": address or f"module.app.{rtype}.x", "type": rtype, "mode": "managed", "name": "x",
         "change": {"actions": list(actions), "before": before or {}, "after": {}, "after_unknown": {}}}
    if reason:
        c["action_reason"] = reason
    if deposed:
        c["deposed"] = deposed
    return c


# Non-data resources: deletes / replaces apply as today (the self-healing loop keeps working).
TOPIC_DELETE = _change("google_pubsub_topic", ("delete",), {"name": "t"})
JOB_REPLACE = _change("google_cloud_run_v2_job", ("delete", "create"), {"deletion_protection": False})
SERVICE_REPLACE = _change("google_cloud_run_v2_service", ("create", "delete"), {"deletion_protection": False},
                          reason="replace_because_cannot_update")
IAM_REPLACE = _change("google_project_iam_member", ("delete", "create"), {"role": "roles/run.invoker"})
# Data-holding resources (owner-set DATA_HOLDING_RESOURCE_TYPES), unprotected (so not DESTROY_BLOCKED first).
BUCKET_DELETE = _change("google_storage_bucket", ("delete",), {"name": "b", "force_destroy": True},
                        reason="delete_because_no_resource_config")
DATASET_REPLACE = _change("google_bigquery_dataset", ("delete", "create"), {"dataset_id": "d"},
                          reason="replace_because_cannot_update")
SECRET_DELETE = _change("google_secret_manager_secret", ("delete",), {"secret_id": "s"})
SUB_REPLACE = _change("google_pubsub_subscription", ("create", "delete"), {"name": "s"})
WRAPPED_REDIS = _change("google_redis_instance", ("delete",), {"name": "cache"},
                        address='module.data["eu"].google_redis_instance.cache')
DEPOSED_DISK = _change("google_compute_disk", ("delete",), {"name": "d"}, deposed="abc123")
TAINTED_DATA = _change("google_redis_instance", ("delete", "create"), {"name": "cache"},
                       reason="replace_because_tainted")


def _standard_decision():
    """The HIPAA fixture re-profiled to STANDARD: no CMEK / ingress checks, so the apply cases test only the toggle."""
    store = copy.deepcopy(HIPAA_DECISION)
    wl = store["workloads/claims"]
    wl["compliance_profile"] = wl["requested_compliance_profile"] = "STANDARD"
    wl["compliance_decision"].update({"profile": "STANDARD", "requested_profile": "STANDARD",
                                      "allow_unauthenticated": True})
    return store


def _gated(monkeypatch, tf, compliance, tmp_path, *changes, hitl, standard=False):
    calls = []
    _wire_gate(monkeypatch, tf, compliance, calls)
    store = _standard_decision() if standard else copy.deepcopy(HIPAA_DECISION)
    svc, ws = _svc(tf, tmp_path, store)
    runner = FakeRunner(plan(bucket(), AUDIT, *changes))
    monkeypatch.setattr(svc, "_run_subprocess", runner)
    monkeypatch.setattr(tf, "destructive_tf_requires_approval", hitl)
    return svc, ws, runner, calls, store


def test_data_holding_table_is_the_owner_set_list(tf):
    assert set(tf.DATA_HOLDING_RESOURCE_TYPES) == {
        "google_storage_bucket", "google_firestore_database", "google_bigquery_dataset", "google_bigquery_table",
        "google_redis_instance", "google_filestore_instance", "google_alloydb_cluster", "google_alloydb_instance",
        "google_sql_database_instance", "google_sql_database", "google_secret_manager_secret",
        "google_artifact_registry_repository", "google_pubsub_subscription", "google_container_cluster",
        "google_compute_disk", "google_kms_crypto_key", "google_kms_key_ring",
        # ST-2b (owner 10-19)
        "google_spanner_instance", "google_spanner_database", "google_bigtable_instance", "google_bigtable_table",
        "google_composer_environment", "google_cloud_tasks_queue", "google_compute_instance"}
    assert "google_secret_manager_secret_version" not in tf.DATA_HOLDING_RESOURCE_TYPES   # rotations keep applying


def test_st2b_secret_version_rotation_applies_with_the_toggle_on(monkeypatch, tf, compliance, tmp_path):
    rotation = _change("google_secret_manager_secret_version", ("create", "delete"), {"secret_data": "x"},
                       reason="replace_because_cannot_update")
    svc, ws, runner, _, _ = _gated(monkeypatch, tf, compliance, tmp_path, rotation, hitl=_never_read, standard=True)
    assert svc._compliance_gated_apply("claims", "t-rot", ws, "OPENTOFU")["success"] is True


@pytest.mark.parametrize("rtype", ["google_spanner_database", "google_bigtable_table", "google_cloud_tasks_queue",
                                   "google_compute_instance"])
def test_st2b_added_types_stop_when_removed(monkeypatch, tf, compliance, tmp_path, rtype):
    removal = _change(rtype, ("delete", "create"), {"name": "x", "deletion_protection": False},
                      reason="replace_because_cannot_update")
    svc, ws, runner, _, _ = _gated(monkeypatch, tf, compliance, tmp_path, removal, hitl=lambda: True)
    with pytest.raises(tf.DestroyBlocked) as ei:
        svc._compliance_gated_apply("claims", "t-2b", ws, "OPENTOFU")
    assert ei.value.result["error_class"] == "DESTROY_REQUIRES_APPROVAL" and "apply" not in runner.calls


@pytest.mark.parametrize("removal", [BUCKET_DELETE, DATASET_REPLACE, SECRET_DELETE, SUB_REPLACE, WRAPPED_REDIS,
                                     DEPOSED_DISK])
def test_hitl_on_data_holding_removal_stops_before_apply(monkeypatch, tf, compliance, tmp_path, removal):
    svc, ws, runner, calls, store = _gated(monkeypatch, tf, compliance, tmp_path, removal, hitl=lambda: True)
    with pytest.raises(tf.DestroyBlocked) as ei:
        svc._compliance_gated_apply("claims", "t-hitl", ws, "OPENTOFU")
    res = ei.value.result
    assert res["status"] == "FAILED" and res["error_class"] == "DESTROY_REQUIRES_APPROVAL"
    assert res["removal_addresses"] == [removal["address"]] and "approved_removals" not in res
    assert "apply" not in runner.calls and calls == []     # nothing applied; the compliance server not asked
    assert not os.path.exists(os.path.join(ws, tf.compliance_gate.GATE_PLAN_FILE))
    ev = store["workloads/claims/compliance_audits/t-hitl"]["enforcement"]
    assert ev["error_class"] == "DESTROY_REQUIRES_APPROVAL" and ev["gate"] == "destroy_hitl"
    assert ev["destroy_requires_approval"][0]["address"] == removal["address"]


def test_hitl_names_only_the_data_holding_removals(monkeypatch, tf, compliance, tmp_path):
    svc, ws, runner, _, _ = _gated(monkeypatch, tf, compliance, tmp_path, JOB_REPLACE, BUCKET_DELETE, IAM_REPLACE,
                                   hitl=lambda: True)
    with pytest.raises(tf.DestroyBlocked) as ei:
        svc._compliance_gated_apply("claims", "t-mixed", ws, "OPENTOFU")
    assert ei.value.result["removal_addresses"] == [BUCKET_DELETE["address"]]


@pytest.mark.parametrize("removal", [TOPIC_DELETE, JOB_REPLACE, SERVICE_REPLACE, IAM_REPLACE])
def test_hitl_negative_on_non_data_removal_applies_as_today_without_reading(monkeypatch, tf, compliance, tmp_path,
                                                                            removal):
    svc, ws, runner, calls, _ = _gated(monkeypatch, tf, compliance, tmp_path, removal, hitl=_never_read,
                                       standard=True)
    res = svc._compliance_gated_apply("claims", "t-nondata", ws, "OPENTOFU")
    assert res["success"] is True and runner.calls == ["plan", "show", "apply"] and len(calls) == 1


def test_hitl_negative_off_data_removal_is_applied_as_today(monkeypatch, tf, compliance, tmp_path):
    svc, ws, runner, calls, _ = _gated(monkeypatch, tf, compliance, tmp_path, SECRET_DELETE, SUB_REPLACE,
                                       hitl=lambda: False)
    res = svc._compliance_gated_apply("claims", "t-off", ws, "OPENTOFU")
    assert res["success"] is True and runner.calls == ["plan", "show", "apply"] and len(calls) == 1


def test_hitl_negative_no_removal_never_reads_the_setting(monkeypatch, tf, compliance, tmp_path):
    svc, ws, runner, calls, _ = _gated(monkeypatch, tf, compliance, tmp_path,
                                       _change("google_project_iam_member", ("update",), {"role": "r"}),
                                       hitl=_never_read)
    res = svc._compliance_gated_apply("claims", "t-none", ws, "OPENTOFU")
    assert res["success"] is True and runner.calls == ["plan", "show", "apply"]


def test_hitl_negative_tainted_data_replacement_applies(monkeypatch, tf, compliance, tmp_path):
    svc, ws, runner, _, _ = _gated(monkeypatch, tf, compliance, tmp_path, TAINTED_DATA, hitl=_never_read,
                                   standard=True)
    assert svc._compliance_gated_apply("claims", "t-taint", ws, "OPENTOFU")["success"] is True
    assert tf.data_holding_removals(plan(TAINTED_DATA)) == []


def test_hitl_protected_destroy_stays_destroy_blocked_whatever_the_setting(monkeypatch, tf, compliance, tmp_path):
    protected = _change("google_sql_database_instance", ("delete", "create"), {"deletion_protection": True})
    svc, ws, runner, _, _ = _gated(monkeypatch, tf, compliance, tmp_path, protected, hitl=_never_read)
    with pytest.raises(tf.DestroyBlocked) as ei:
        svc._compliance_gated_apply("claims", "t-prot", ws, "OPENTOFU")
    assert ei.value.result["error_class"] == "DESTROY_BLOCKED" and "apply" not in runner.calls


def test_express_destroy_policy_keeps_exp7_exact_address_approval_and_never_reads_the_toggle(
        monkeypatch, tf, compliance, tmp_path):
    svc, ws, runner, _, _ = _gated(monkeypatch, tf, compliance, tmp_path, SECRET_DELETE, hitl=_never_read)
    approved = tf.DestroyPolicy(approved_removals=frozenset({SECRET_DELETE["address"]}))
    assert svc._compliance_gated_apply("claims", "t-exp7", ws, "OPENTOFU", destroy_policy=approved)["success"] is True
    svc2, ws2, runner2, _, _ = _gated(monkeypatch, tf, compliance, tmp_path / "b", SECRET_DELETE, hitl=_never_read)
    with pytest.raises(tf.DestroyBlocked) as ei:
        svc2._compliance_gated_apply("claims", "t-exp7b", ws2, "OPENTOFU", destroy_policy=tf.DestroyPolicy())
    assert ei.value.result["error_class"] == "DESTROY_REQUIRES_APPROVAL" and "approved_removals" in ei.value.result
    assert "apply" not in runner2.calls


def test_one_copy_of_the_exp7_removal_rule():
    src = open(os.path.join(REPO_ROOT, "mcp-servers", "terraform", "service.py"), encoding="utf-8").read()
    assert src.count("def removals_requiring_approval(") == 1
    assert src.count('ERROR_DESTROY_REQUIRES_APPROVAL = "DESTROY_REQUIRES_APPROVAL"') == 1
    assert src.count('TAINTED_REPLACE_REASON = "replace_because_tainted"') == 1


@pytest.mark.parametrize("read, expected", [(lambda **k: _settings(require_hitl_for_destructive_tf=True), True),
                                            (lambda **k: _settings(require_hitl_for_destructive_tf=False), False),
                                            (_raises(ERRORS[0]), True), (_raises(ERRORS[1]), True)])
def test_hitl_module_reader_uses_the_strict_shared_reader(monkeypatch, tf, read, expected):
    import shared.settings as tf_settings   # the module the terraform MCP's lazy import resolves to
    tf_settings.invalidate_settings_cache()
    monkeypatch.setattr(tf_settings, "get_platform_settings", read)
    assert tf.destructive_tf_requires_approval() is expected


def test_hitl_refusal_reaches_the_deploy_result_typed(monkeypatch, tf, tmp_path):
    from test_lane14_compliance_gate import FakeDB as TfFakeDB
    svc = tf.TerraformService(project_id="host", state_bucket="b", workspace_base_dir=str(tmp_path / "ws"),
                              firestore_client=TfFakeDB({}))
    refusal = tf.hitl_destroy_refusal("claims", "t1", tf.data_holding_removals(plan(BUCKET_DELETE)))

    def impl(**kw):
        raise tf.DestroyBlocked(refusal)
    monkeypatch.setattr(svc, "_deploy_workload_impl", impl)
    monkeypatch.setattr(svc, "_sync_feature_requests", lambda **kw: None)
    res = svc.deploy_workload(product_id="claims", trace_id="t1")
    assert res["status"] == "FAILED" and res["error_class"] == "DESTROY_REQUIRES_APPROVAL"


def test_hitl_class_goes_to_the_operator_never_to_developer_remediation(tf):
    wf = open(os.path.join(REPO_ROOT, "workflows", "main_orchestrator.yaml"), encoding="utf-8").read()
    line = next(ln for ln in wf.splitlines() if '"DESTROY_BLOCKED"' in ln and "deploy_error_class in" in ln)
    assert wf.splitlines()[wf.splitlines().index(line) + 1].strip() == "next: handle_operator_deploy_failure"
    assert '"DESTROY_REQUIRES_APPROVAL"' in line and tf.ERROR_DESTROY_REQUIRES_APPROVAL == "DESTROY_REQUIRES_APPROVAL"
    if GW_DIR not in sys.path:
        sys.path.insert(0, GW_DIR)
    import gate_errors
    assert "DESTROY_REQUIRES_APPROVAL" in gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES


def test_settings_page_describes_the_destructive_tf_gate():
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    assert "DESTROY_REQUIRES_APPROVAL" in html and "data-holding resource" in html
    assert "Deletion-protected resources are always blocked" in html


def test_every_gated_apply_call_passes_the_deploys_destroy_policy():
    """RT plan step 3: the HITL check keys on `destroy_policy is None`, so every gated-apply call site must forward
    the deploy's own policy (Express) instead of dropping it (which would make an Express deploy look like Agent)."""
    import ast
    tree = ast.parse(open(os.path.join(REPO_ROOT, "mcp-servers", "terraform", "service.py"), encoding="utf-8").read())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "_compliance_gated_apply"]
    # FD-55 W6c: the IdP-block bypass retry (A49) was the 4th call site; CLOUDSQL-CREATE-OWN-OPERATION adds the retry
    # after adopting this deploy's own Cloud SQL instance (it forwards the same policy)
    assert len(calls) == 4
    for c in calls:
        kw = {k.arg: k.value for k in c.keywords}
        assert isinstance(kw.get("destroy_policy"), ast.Name) and kw["destroy_policy"].id == "destroy_policy"
