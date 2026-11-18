"""Lane 14 PR-0 (FD-4S / FD-4R): the compliance enforcement gate that makes the "Enforced" claims true.

Hermetic: the compliance server runs in-process (FastAPI TestClient over the real mcp-servers/compliance app), the
terraform side uses the real TerraformService with a fake `_run_subprocess`, Firestore is a dict-backed fake.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy
import json
import os
import sys
from types import SimpleNamespace

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COMPLIANCE_DIR = os.path.join(REPO, "mcp-servers", "compliance")
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")
sys.path.insert(0, os.path.dirname(__file__))

KEY = "projects/child-p/locations/us-central1/keyRings/kr/cryptoKeys/k"


# ------------------------------------------------------------------------------------------------- fixtures / fakes
@pytest.fixture()
def compliance(monkeypatch):
    from fastapi.testclient import TestClient

    from fd4g_support import load_module, real_modules

    real_modules(monkeypatch)
    monkeypatch.delenv("PROJECT_ID", raising=False)
    svc = load_module(monkeypatch, "service", os.path.join(COMPLIANCE_DIR, "service.py"))
    main = load_module(monkeypatch, "lane14_compliance_server_main", os.path.join(COMPLIANCE_DIR, "main.py"))
    return SimpleNamespace(service=svc, engine=svc.ComplianceService(project_id="p"), client=TestClient(main.app),
                           plan_gate=svc.plan_gate)


@pytest.fixture()
def tf(monkeypatch, tmp_path):
    from fd4g_support import load_tf_service

    mod = load_tf_service(monkeypatch)
    return mod


class FakeDoc:
    def __init__(self, store, path):
        self.store, self.path = store, path

    def get(self):
        if self.store.get("__raise_get__"):
            raise RuntimeError("firestore down")
        data = self.store.get(self.path)
        return SimpleNamespace(exists=data is not None, to_dict=lambda: copy.deepcopy(data))

    def set(self, data, merge=False):
        cur = self.store.get(self.path) if merge else None
        new = dict(cur or {})
        new.update(copy.deepcopy(data))
        self.store[self.path] = new

    def collection(self, name):
        return FakeCollection(self.store, f"{self.path}/{name}")


class FakeCollection:
    def __init__(self, store, path):
        self.store, self.path = store, path

    def document(self, doc_id):
        return FakeDoc(self.store, f"{self.path}/{doc_id}")


class FakeDB:
    def __init__(self, store=None):
        self.store = store if store is not None else {}

    def collection(self, name):
        return FakeCollection(self.store, name)

    def batch(self):
        return FakeBatch(self.store)


class FakeBatch:
    """WriteBatch: buffered sets applied on commit(), all or nothing."""

    def __init__(self, store):
        self.store, self.ops = store, []

    def set(self, ref, data, merge=False):
        self.ops.append((ref, data, merge))

    def commit(self):
        if self.store.get("__raise_set__"):
            raise RuntimeError("firestore down")
        for ref, data, merge in self.ops:
            ref.set(data, merge=merge)


# ------------------------------------------------------------------------------------------------- plan builders
def rc(rtype, name, after, *, unknown=None, actions=("create",), module_address=None):
    entry = {
        "address": (f"{module_address}." if module_address else "") + f"{rtype}.{name}",
        "mode": "managed", "type": rtype, "name": name,
        "change": {"actions": list(actions), "after": after, "after_unknown": unknown or {}},
    }
    if module_address:
        entry["module_address"] = module_address
    return entry


def plan(*changes, configuration=None, variables=None):
    p = {"format_version": "1.2", "resource_changes": list(changes)}
    # FD-4AW-b: a real `show -json` always carries `configuration` (the apply-time content policy reads it)
    p["configuration"] = configuration if configuration is not None else {"root_module": {}}
    if variables is not None:
        p["variables"] = variables
    return p


AUDIT = rc("google_project_iam_audit_config", "all", {
    "project": "child-p", "service": "allServices",
    "audit_log_config": [{"log_type": "DATA_READ"}, {"log_type": "DATA_WRITE"}, {"log_type": "ADMIN_READ"}],
})


def bucket(location="us-central1", key=KEY, **kw):
    after = {"name": "b", "location": location}
    if key is not None:
        after["encryption"] = [{"default_kms_key_name": key}]
    return rc("google_storage_bucket", "b", after, **kw)


def ev(compliance, p, profile, ingress=None, org=None):
    return compliance.engine.evaluate_plan_compliance(p, profile, ingress or {}, org or [])


def codes(result):
    return sorted(v["code"] for v in result["violations"])


# ================================================================================================ 1. engine (plan)
def test_hipaa_bucket_without_cmek_is_a_violation(compliance):
    r = ev(compliance, plan(bucket(key=None), AUDIT), "HIPAA")
    assert r["decision"] == "VIOLATION" and r["error_class"] == "COMPLIANCE_VIOLATION"
    assert codes(r) == ["CMEK_MISSING"]
    assert r["violations"][0]["address"] == "google_storage_bucket.b"


def test_hipaa_bucket_with_key_passes(compliance):
    r = ev(compliance, plan(bucket(), AUDIT), "HIPAA")
    assert r["decision"] == "PASS" and r["violations"] == []
    assert {"CMEK", "AUDIT_LOGGING", "REGIONS"} <= set(r["checks_run"])


def test_cmek_known_after_apply_passes_only_when_it_references_a_kms_key(compliance):
    config = {"root_module": {"resources": [{
        "address": "google_storage_bucket.b", "mode": "managed", "type": "google_storage_bucket", "name": "b",
        "expressions": {"encryption": [{"default_kms_key_name": {"references": ["google_kms_crypto_key.k.id",
                                                                                "google_kms_crypto_key.k"]}}]},
    }]}}
    unknown_bucket = rc("google_storage_bucket", "b", {"name": "b", "location": "us-central1", "encryption": [{}]},
                        unknown={"encryption": [{"default_kms_key_name": True}]})
    assert ev(compliance, plan(unknown_bucket, AUDIT, configuration=config), "HIPAA")["decision"] == "PASS"
    config["root_module"]["resources"][0]["expressions"]["encryption"][0]["default_kms_key_name"] = {
        "references": ["local.some_key"]}
    r = ev(compliance, plan(unknown_bucket, AUDIT, configuration=config), "HIPAA")
    assert codes(r) == ["CMEK_UNVERIFIABLE"]


def test_cmek_through_a_module_variable_is_resolved(compliance):
    config = {"root_module": {
        "resources": [],
        "module_calls": {"data": {
            "expressions": {"kms_key": {"references": ["google_kms_crypto_key.k.id", "google_kms_crypto_key.k"]}},
            "module": {"resources": [{
                "address": "google_storage_bucket.b", "mode": "managed", "type": "google_storage_bucket",
                "name": "b",
                "expressions": {"encryption": [{"default_kms_key_name": {"references": ["var.kms_key"]}}]},
            }]},
        }},
    }}
    mod_bucket = rc("google_storage_bucket", "b", {"name": "b", "location": "us-central1", "encryption": [{}]},
                    unknown={"encryption": [{"default_kms_key_name": True}]}, module_address='module.data["x"]')
    assert ev(compliance, plan(mod_bucket, AUDIT, configuration=config), "HIPAA")["decision"] == "PASS"


def test_invalid_key_string_is_not_cmek(compliance):
    r = ev(compliance, plan(bucket(key="my-key"), AUDIT), "HIPAA")
    assert codes(r) == ["CMEK_INVALID_KEY"]


def test_standard_profile_runs_no_cmek_audit_or_region_check(compliance):
    """Negative (Do No Harm): a STANDARD plan with no CMEK, no audit config, in europe-west1 passes unchanged."""
    p = plan(bucket(location="europe-west1", key=None))
    before = copy.deepcopy(p)
    r = ev(compliance, p, "STANDARD")
    assert r["decision"] == "PASS" and r["checks_run"] == []
    assert p == before  # the gate never mutates the plan


def test_hipaa_resource_in_a_disallowed_region_is_a_violation(compliance):
    r = ev(compliance, plan(bucket(location="europe-west1"), AUDIT), "HIPAA")
    assert codes(r) == ["REGION_NOT_ALLOWED"]


def test_zone_is_resolved_to_its_region(compliance):
    vm = rc("google_compute_instance", "vm", {"name": "vm", "zone": "us-central1-a"})
    assert ev(compliance, plan(bucket(), AUDIT, vm), "HIPAA")["decision"] == "PASS"
    vm_eu = rc("google_compute_instance", "vm", {"name": "vm", "zone": "europe-west1-b"})
    assert codes(ev(compliance, plan(bucket(), AUDIT, vm_eu), "HIPAA")) == ["REGION_NOT_ALLOWED"]


def test_provider_default_region_is_checked_when_the_attribute_is_computed(compliance):
    config = {"provider_config": {"google": {"name": "google", "expressions": {"region": {"references": ["var.region"]}}}},
              "root_module": {"resources": [{"mode": "managed", "type": "google_compute_subnetwork", "name": "s",
                                             "expressions": {"name": {"constant_value": "s"}}}]}}
    subnet = rc("google_compute_subnetwork", "s", {"name": "s"}, unknown={"region": True})
    ok = plan(bucket(), AUDIT, subnet, configuration=config, variables={"region": {"value": "us-east1"}})
    bad = plan(bucket(), AUDIT, subnet, configuration=config, variables={"region": {"value": "europe-west1"}})
    assert ev(compliance, ok, "HIPAA")["decision"] == "PASS"
    assert codes(ev(compliance, bad, "HIPAA")) == ["REGION_NOT_ALLOWED"]


def test_org_location_groups_intersect_and_unknown_group_refuses(compliance):
    p = plan(bucket(location="us-east1"), AUDIT)
    assert ev(compliance, p, "HIPAA", org=["in:us-locations"])["decision"] == "PASS"
    assert codes(ev(compliance, p, "HIPAA", org=["in:us-central1-locations"])) == ["REGION_NOT_ALLOWED"]
    r = ev(compliance, p, "HIPAA", org=["in:mars-locations"])
    assert r["decision"] == "REFUSED" and r["error_class"] == "UNRESOLVED_LOCATION_GROUP"


def test_unknown_profile_is_refused_not_treated_as_standard(compliance):
    r = ev(compliance, plan(bucket(key=None)), "FOO")
    assert r["decision"] == "REFUSED" and r["error_class"] == "UNKNOWN_PROFILE"


def test_audit_logging_required_for_hipaa(compliance):
    assert codes(ev(compliance, plan(bucket()), "HIPAA")) == ["AUDIT_LOGGING_NOT_CONFIGURED"]
    partial = rc("google_project_iam_audit_config", "a", {"service": "allServices",
                                                         "audit_log_config": [{"log_type": "DATA_READ"}]})
    assert codes(ev(compliance, plan(bucket(), partial), "HIPAA")) == ["AUDIT_LOGGING_NOT_CONFIGURED"]


def test_ingress_flags_from_the_decision_are_enforced(compliance):
    svc_public = rc("google_cloud_run_v2_service", "app", {"name": "app", "location": "us-central1",
                                                            "iap_enabled": False, "ingress": "INGRESS_TRAFFIC_ALL"})
    all_users = rc("google_cloud_run_v2_service_iam_member", "pub", {"role": "roles/run.invoker", "member": "allUsers"})
    authn = rc("google_cloud_run_v2_service_iam_member", "authn",
               {"role": "roles/run.invoker", "member": "allAuthenticatedUsers"})
    r = ev(compliance, plan(svc_public, all_users), "STANDARD",
           ingress={"enable_direct_iap": True, "allow_unauthenticated": False, "enforce_private_ingress": True})
    assert codes(r) == ["IAP_NOT_ENABLED", "PRIVATE_INGRESS_NOT_SET", "PUBLIC_INVOKER"]
    # allAuthenticatedUsers is the handler's own no-admin fallback invoker: not "unauthenticated".
    assert ev(compliance, plan(authn), "STANDARD", ingress={"allow_unauthenticated": False})["decision"] == "PASS"
    policy = rc("google_cloud_run_v2_service_iam_policy", "p", {"policy_data": json.dumps(
        {"bindings": [{"role": "roles/run.invoker", "members": ["allUsers"]}]})})
    assert codes(ev(compliance, plan(policy), "STANDARD", ingress={"allow_unauthenticated": False})) == ["PUBLIC_INVOKER"]
    # Negative: a public decision checks nothing about invokers.
    assert ev(compliance, plan(svc_public, all_users), "STANDARD", ingress={"allow_unauthenticated": True})["decision"] == "PASS"


def test_deleted_resources_are_not_evaluated(compliance):
    gone = bucket(location="europe-west1", key=None, actions=("delete",))
    gone["change"]["after"] = None
    assert ev(compliance, plan(gone, AUDIT), "HIPAA")["decision"] == "PASS"


def test_malformed_plan_is_refused(compliance):
    assert ev(compliance, {"resource_changes": []}, "HIPAA")["error_class"] == "PLAN_INVALID"
    assert ev(compliance, plan({"mode": "managed", "type": "x", "name": "y"}), "HIPAA")["error_class"] == "PLAN_INVALID"


def test_kms_name_and_module_address_parsers(compliance):
    pg = compliance.plan_gate
    assert pg.is_kms_crypto_key_name(KEY)
    assert pg.is_kms_crypto_key_name(KEY + "/cryptoKeyVersions/1")
    for bad in ("", "kms_key_name", KEY.replace("keyRings", "rings"), KEY + "/x", "projects//locations/l/keyRings/r/cryptoKeys/k"):
        assert not pg.is_kms_crypto_key_name(bad), bad
    assert pg.parse_module_address('module.a["x.y"].module.b[0]') == ("a", "b")
    with pytest.raises(pg.PlanInvalid):
        pg.parse_module_address("modulea.b")


# ================================================================================================ 2. HTTP routes
def test_evaluate_plan_route(compliance):
    body = {"gate_contract_version": 1, "product_id": "p", "trace_id": "t", "profile": "HIPAA",
            "ingress": {}, "org_allowed_locations": [], "plan": plan(bucket(key=None), AUDIT)}
    res = compliance.client.post("/evaluate-plan", json=body)
    assert res.status_code == 200
    assert res.json()["decision"] == "VIOLATION" and res.json()["gate_contract_version"] == 1
    res = compliance.client.post("/evaluate-plan", json=dict(body, gate_contract_version=99))
    assert res.status_code == 422
    assert compliance.client.get("/health").json()["gate_contract_version"] == 1


# ================================================================================================ 3. /evaluate-hcl
HCL_OK = '''
resource "google_project_iam_audit_config" "all" {
  project = "child-p"
  service = "allServices"
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
resource "google_kms_crypto_key" "k" {
  name     = "k"
  key_ring = "projects/child-p/locations/us-central1/keyRings/kr"
}
resource "google_storage_bucket" "b" {
  name     = "b"
  location = "us-central1"
  encryption {
    default_kms_key_name = google_kms_crypto_key.k.id
  }
}
'''


def test_evaluate_hcl_parser_based(compliance):
    r = compliance.engine.evaluate_hcl_compliance({"main.tf": HCL_OK}, "HIPAA")
    assert r["compliant"] is True and r["error_class"] is None
    res = compliance.client.post("/evaluate-hcl", json={"hcl_files": {"main.tf": HCL_OK}, "profile": "HIPAA"})
    assert res.status_code == 200 and res.json()["compliant"] is True


def test_evaluate_hcl_cloud_run_cmek_mirrors_the_server_unit_test(compliance):
    """Same inputs as mcp-servers/compliance/test_compliance.py (rewritten to the parser engine; not run here)."""
    ok = '''
resource "google_kms_crypto_key" "key" {
  name     = "workload-cmek"
  key_ring = "keyring"
}
resource "google_project_iam_audit_config" "all" {
  project = "p"
  service = "allServices"
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
resource "google_cloud_run_v2_service" "app" {
  location = "us-central1"
  template {
    encryption_key = google_kms_crypto_key.key.id
  }
}
'''
    r = compliance.engine.evaluate_hcl_compliance({"main.tf": ok}, "HIPAA")
    assert r["compliant"] is True and r["violations"] == []
    bad = 'resource "google_cloud_run_v2_service" "app" {\n  location = "us-central1"\n}\n'
    r = compliance.engine.evaluate_hcl_compliance({"main.tf": bad}, "HIPAA")
    assert r["compliant"] is False and any("CMEK" in v for v in r["violations"])


def test_evaluate_hcl_comment_no_longer_satisfies_cmek(compliance):
    """The old substring engine accepted any file containing `kms_key_name`, even in a comment."""
    hcl = '# kms_key_name google_kms_crypto_key\nresource "google_storage_bucket" "b" {\n  name = "b"\n  location = "us-central1"\n}\n'
    r = compliance.engine.evaluate_hcl_compliance({"main.tf": hcl}, "HIPAA")
    assert r["compliant"] is False and any(v.startswith("CMEK_MISSING") for v in r["violations"])


def test_evaluate_hcl_unparsable_is_parse_error(compliance):
    r = compliance.engine.evaluate_hcl_compliance({"main.tf": 'resource "x" "y" {\n  a = \n'}, "HIPAA")
    assert r["compliant"] is False and r["error_class"] == "PARSE_ERROR"


def test_evaluate_hcl_var_region_is_left_to_the_plan_gate(compliance):
    hcl = HCL_OK.replace('location = "us-central1"', "location = var.region")
    r = compliance.engine.evaluate_hcl_compliance({"main.tf": hcl}, "HIPAA")
    assert r["compliant"] is True and any(u.startswith("LOCATION_UNVERIFIABLE") for u in r["unverified"])
    r = compliance.engine.evaluate_hcl_compliance({"main.tf": HCL_OK.replace("us-central1\"\n  encryption", "europe-west1\"\n  encryption")}, "HIPAA")
    assert r["compliant"] is False


# ================================================================================================ 4. terraform side
def _wire_gate(monkeypatch, tf, compliance, calls=None, status=None, payload=None):
    cg = tf.compliance_gate
    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://compliance.invalid")
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("CLOUD_RUN_JOB", raising=False)

    def post(url, body, headers, timeout):
        if calls is not None:
            calls.append({"url": url, "body": body, "headers": headers})
        if status is not None:
            return status, payload
        res = compliance.client.post("/evaluate-plan", json=body)
        return res.status_code, res.json()

    monkeypatch.setattr(cg, "_default_http_post", post)
    return cg


class FakeRunner:
    """Stands in for TerraformService._run_subprocess: plan/show/apply recorded; show returns `plan_json`."""

    def __init__(self, plan_json, plan_ok=True, plan_stderr=""):
        self.plan_json, self.plan_ok, self.plan_stderr, self.calls = plan_json, plan_ok, plan_stderr, []
        self.cmds, self.plan_file_at_apply = [], []

    def __call__(self, cmd, cwd=None, env=None, iac_engine=None):
        self.calls.append(cmd[1])
        self.cmds.append(list(cmd))
        if cmd[1] == "apply" and cwd:
            self.plan_file_at_apply.append(os.path.exists(os.path.join(cwd, cmd[-1])))
        if cmd[1] == "plan":
            if not self.plan_ok:
                return {"success": False, "exit_code": 1, "stdout": "", "stderr": self.plan_stderr}
            open(os.path.join(cwd, cmd[2].split("=", 1)[1]), "w").write("binary plan")
            return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}
        if cmd[1] == "show":
            return {"success": True, "exit_code": 0, "stdout": json.dumps(self.plan_json), "stderr": ""}
        if cmd[1] == "apply":
            return {"success": True, "exit_code": 0, "stdout": "Apply complete!", "stderr": ""}
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}


def _svc(tf, tmp_path, store):
    svc = tf.TerraformService(project_id="host", state_bucket="b", workspace_base_dir=str(tmp_path / "ws"),
                              firestore_client=FakeDB(store))
    ws = tmp_path / "work"
    ws.mkdir(exist_ok=True)
    (ws / "main.tf").write_text('resource "google_storage_bucket" "b" {}\n')
    return svc, str(ws)


# compliance-profile-explicit (RT F1): a current decision carries profile_source / requested_profile, matching the
# workload's stored selection (a decision without profile_source is a pre-change keyword decision and is rebased).
HIPAA_DECISION = {"workloads/claims": {"compliance_profile": "HIPAA", "requested_compliance_profile": "HIPAA",
                                       "compliance_decision": {
    "profile": "HIPAA", "enable_direct_iap": False, "allow_unauthenticated": False, "enforce_private_ingress": False,
    "allowed_locations": [], "profile_source": "EXPLICIT_REQUEST", "requested_profile": "HIPAA"}}}


def test_gated_apply_refuses_a_violating_plan_and_never_applies(monkeypatch, tf, compliance, tmp_path):
    """DEPLOY_ONLY / Express / retrigger fixture: the stored HIPAA decision applies whatever the execution mode."""
    store = copy.deepcopy(HIPAA_DECISION)
    _wire_gate(monkeypatch, tf, compliance)
    svc, ws = _svc(tf, tmp_path, store)
    runner = FakeRunner(plan(bucket(key=None), AUDIT))
    monkeypatch.setattr(svc, "_run_subprocess", runner)
    with pytest.raises(tf.compliance_gate.ComplianceGateRefused) as ei:
        svc._compliance_gated_apply("claims", "trace-deploy-only", ws, "OPENTOFU")
    assert "apply" not in runner.calls
    assert ei.value.result["error_class"] == "COMPLIANCE_VIOLATION" and ei.value.result["status"] == "FAILED"
    assert not os.path.exists(os.path.join(ws, tf.compliance_gate.GATE_PLAN_FILE))  # plan file removed
    ev_doc = store["workloads/claims/compliance_audits/trace-deploy-only"]["enforcement"]
    assert ev_doc["verified"] is False and ev_doc["profile_source"] == "WORKLOAD_DECISION"


def test_gated_apply_applies_the_gated_plan_file_every_time(monkeypatch, tf, compliance, tmp_path):
    """RT F4: the applied plan IS the gated plan (saved-plan apply of the gate's own file); no PASS cache, so a
    retry after imports (same configuration, changed state) is planned and gated again. RT F6: no per-process cache."""
    store = copy.deepcopy(HIPAA_DECISION)
    calls = []
    _wire_gate(monkeypatch, tf, compliance, calls)
    svc, ws = _svc(tf, tmp_path, store)
    runner = FakeRunner(plan(bucket(), AUDIT))
    monkeypatch.setattr(svc, "_run_subprocess", runner)
    assert svc._compliance_gated_apply("claims", "t1", ws, "OPENTOFU")["success"] is True
    assert runner.calls == ["plan", "show", "apply"]
    gate_file = tf.compliance_gate.GATE_PLAN_FILE
    assert runner.cmds[0][2] == f"-out={gate_file}" and runner.cmds[1][-1] == gate_file
    assert runner.cmds[2] == ["terraform", "apply", "-input=false", "-auto-approve", "-no-color", gate_file]
    assert runner.plan_file_at_apply == [True]
    assert not os.path.exists(os.path.join(ws, gate_file))  # removed after the apply
    svc._compliance_gated_apply("claims", "t1", ws, "OPENTOFU")  # same configuration: gated again
    assert runner.calls == ["plan", "show", "apply"] * 2 and len(calls) == 2
    assert "_compliance_gate_passed" not in svc.__dict__
    assert calls[0]["body"]["profile"] == "HIPAA"
    assert store["workloads/claims/compliance_audits/t1"]["enforcement"]["verified"] is True


def test_rt_f8_failed_plan_file_removal_is_logged(monkeypatch, tf, compliance, tmp_path, caplog):
    import logging

    _wire_gate(monkeypatch, tf, compliance)
    svc, ws = _svc(tf, tmp_path, copy.deepcopy(HIPAA_DECISION))
    monkeypatch.setattr(svc, "_run_subprocess", FakeRunner(plan(bucket(), AUDIT)))
    real_remove = os.remove

    def failing_remove(path):
        if path.endswith(tf.compliance_gate.GATE_PLAN_FILE):
            raise PermissionError("read-only")
        return real_remove(path)

    monkeypatch.setattr(tf.os, "remove", failing_remove)
    with caplog.at_level(logging.WARNING):
        svc._compliance_gated_apply("claims", "t1", ws, "OPENTOFU")
    assert any("GATE_PLAN_FILE_NOT_REMOVED" in r.getMessage() for r in caplog.records)


def _replace(rtype, before, actions=("delete", "create"), address=None):
    return {"address": address or f"module.foundation.{rtype}.x", "type": rtype, "mode": "managed", "name": "x",
            "change": {"actions": list(actions), "before": before, "after": {}, "after_unknown": {}}}


@pytest.mark.parametrize("change", [
    _replace("google_sql_database_instance", {"deletion_protection": True}),
    _replace("google_sql_database_instance", {"deletion_protection": False,
                                              "settings": [{"deletion_protection_enabled": True}]}),
    _replace("google_firestore_database", {"delete_protection_state": "DELETE_PROTECTION_ENABLED"}, ("delete",)),
    _replace("google_bigtable_table", {"deletion_protection": "PROTECTED"}, ("create", "delete")),
    _replace("google_spanner_database", {"deletion_protection": True}),
    _replace("google_storage_bucket", {"force_destroy": False}),
])
def test_fd4az_f2_protected_delete_or_replace_is_destroy_blocked_before_any_apply(monkeypatch, tf, compliance,
                                                                                   tmp_path, change):
    calls = []
    _wire_gate(monkeypatch, tf, compliance, calls)
    svc, ws = _svc(tf, tmp_path, copy.deepcopy(HIPAA_DECISION))
    runner = FakeRunner(plan(change))   # FD-4AW-b: with `configuration`
    monkeypatch.setattr(svc, "_run_subprocess", runner)
    with pytest.raises(tf.DestroyBlocked) as ei:
        svc._compliance_gated_apply("claims", "t1", ws, "OPENTOFU")
    res = ei.value.result
    assert res["status"] == "FAILED" and res["error_class"] == "DESTROY_BLOCKED"
    assert res["destroy_blocked"][0]["address"] == change["address"]
    assert "apply" not in runner.calls and calls == []  # nothing applied; the compliance server not even asked
    assert not os.path.exists(os.path.join(ws, tf.compliance_gate.GATE_PLAN_FILE))


def test_fd4az_f2_negative_creates_updates_and_unprotected_deletes_are_unchanged(tf):
    plan_json = {"resource_changes": [
        _replace("google_sql_database_instance", {"deletion_protection": True}, ("create",)),
        _replace("google_sql_database_instance", {"deletion_protection": True}, ("update",)),
        _replace("google_sql_database_instance", {"deletion_protection": False}),
        _replace("google_spanner_database", {"deletion_protection": False}, ("delete",)),
        _replace("google_storage_bucket", {"force_destroy": True}),
        _replace("google_firestore_database", {"delete_protection_state": "DELETE_PROTECTION_ENABLED"}, ("update",)),
        _replace("google_artifact_registry_repository", {"repository_id": "r"}, ("create",)),
        _replace("google_artifact_registry_repository", {"repository_id": "r"}, ("update",)),
        _replace("google_pubsub_topic", {"name": "t"}, ("delete",)),
        _replace("google_sql_database_instance", {"deletion_protection": "true"}),  # wrong type: not the provider's
    ]}
    assert tf.protected_destroys(plan_json) == []
    assert tf.protected_destroys({}) == []


@pytest.mark.parametrize("change", [
    _replace("google_firestore_database", {"delete_protection_state": "DELETE_PROTECTION_DISABLED"}, ("delete",)),
    _replace("google_firestore_database", {"delete_protection_state": "DELETE_PROTECTION_DISABLED"}),
    _replace("google_firestore_database", None, ("create", "delete")),
    _replace("google_artifact_registry_repository", {"repository_id": "r"}),
    _replace("google_artifact_registry_repository", {"repository_id": "r"}, ("delete",)),
])
def test_fd4cg_replace_blocked_types_are_blocked_whatever_their_flags(tf, change):
    blocked = tf.protected_destroys({"resource_changes": [change]})
    assert len(blocked) == 1 and blocked[0]["protection"] == "REPLACE_BLOCKED_TYPE"
    assert blocked[0]["address"] == change["address"]
    assert tf.REPLACE_BLOCKED_TYPES == {"google_firestore_database", "google_artifact_registry_repository"}


def test_n5_blocked_destroy_writes_enforcement_evidence(monkeypatch, tf, compliance, tmp_path):
    _wire_gate(monkeypatch, tf, compliance)
    store = copy.deepcopy(HIPAA_DECISION)
    svc, ws = _svc(tf, tmp_path, store)
    change = _replace("google_artifact_registry_repository", {"repository_id": "r"})
    monkeypatch.setattr(svc, "_run_subprocess", FakeRunner(plan(change)))   # FD-4AW-b: with `configuration`
    with pytest.raises(tf.DestroyBlocked):
        svc._compliance_gated_apply("claims", "t-blocked", ws, "OPENTOFU")
    ev_doc = store["workloads/claims/compliance_audits/t-blocked"]["enforcement"]
    assert ev_doc["error_class"] == "DESTROY_BLOCKED" and ev_doc["verified"] is False
    assert ev_doc["destroy_blocked"][0]["address"] == change["address"] and len(ev_doc["plan_digest"]) == 64


def test_n3_dead_digest_helpers_are_gone(tf):
    for name in ("workspace_config_digest", "CONFIG_SUFFIXES", "SKIP_DIRS"):
        assert not hasattr(tf.compliance_gate, name), name


def test_fd4az_f2_destroy_blocked_reaches_the_deploy_result_typed(monkeypatch, tf, tmp_path):
    svc = tf.TerraformService(project_id="host", state_bucket="b", workspace_base_dir=str(tmp_path / "ws"),
                              firestore_client=FakeDB({}))
    blocked = tf.destroy_blocked_result("claims", "t1", [{"address": "a", "type": "t", "actions": ["delete"],
                                                          "protection": "deletion_protection"}])

    def impl(**kw):
        raise tf.DestroyBlocked(blocked)

    monkeypatch.setattr(svc, "_deploy_workload_impl", impl)
    monkeypatch.setattr(svc, "_sync_feature_requests", lambda **kw: None)
    res = svc.deploy_workload(product_id="claims", trace_id="t1")
    assert res["error_class"] == "DESTROY_BLOCKED" and res["status"] == "FAILED"


def test_destroy_blocked_is_a_class_the_workflow_routes_to_the_operator(tf):
    wf = open(os.path.join(REPO, "workflows", "main_orchestrator.yaml"), encoding="utf-8").read()
    assert tf.ERROR_DESTROY_BLOCKED == "DESTROY_BLOCKED" and '"DESTROY_BLOCKED"' in wf


def test_plan_time_error_is_returned_without_applying(monkeypatch, tf, compliance, tmp_path):
    _wire_gate(monkeypatch, tf, compliance)
    svc, ws = _svc(tf, tmp_path, {})
    runner = FakeRunner(None, plan_ok=False, plan_stderr="Error: Self-referential block")
    monkeypatch.setattr(svc, "_run_subprocess", runner)
    res = svc._compliance_gated_apply("claims", "t", ws, "OPENTOFU")
    assert res["success"] is False and res["stderr"] == "Error: Self-referential block"
    assert res["compliance_gate_phase"] == "plan" and runner.calls == ["plan"]


@pytest.mark.parametrize("status,payload,failure", [
    (None, None, "TRANSPORT"),
    (500, {"detail": "boom"}, "HTTP_STATUS"),
    (403, {"detail": "forbidden"}, "HTTP_STATUS"),
    (200, {"decision": "PASS", "violations": []}, "CONTRACT"),
    (200, {"gate_contract_version": 1, "decision": "MAYBE", "violations": []}, "CONTRACT"),
    (200, {"gate_contract_version": 1, "decision": "PASS", "violations": [{"code": "X"}]}, "CONTRACT"),
    (200, ["not", "an", "object"], "INVALID_JSON"),
])
def test_compliance_server_failures_fail_closed(monkeypatch, tf, compliance, tmp_path, status, payload, failure):
    """FD-4R: no outage shape ever yields PASS / an apply."""
    cg = _wire_gate(monkeypatch, tf, compliance, status=status, payload=payload)
    if status is None:
        def boom(*a, **k):
            raise ConnectionError("connection refused")
        monkeypatch.setattr(cg, "_default_http_post", boom)
    out = cg.gate_plan(db=FakeDB({}), product_id="p", trace_id="t", plan_json=plan(bucket()))
    assert out["passed"] is False
    assert out["result"]["error_class"] == "COMPLIANCE_UNAVAILABLE"
    assert out["result"]["compliance_gate"]["failure"] == failure


def test_decision_absent_defaults_to_standard_and_says_so(monkeypatch, tf, compliance):
    calls = []
    cg = _wire_gate(monkeypatch, tf, compliance, calls)
    store = {}
    out = cg.gate_plan(db=FakeDB(store), product_id="p", trace_id="t", plan_json=plan(bucket(key=None)))
    assert out["passed"] is True
    assert calls[0]["body"]["profile"] == "STANDARD" and calls[0]["body"]["ingress"] == {}
    assert out["evidence"]["profile_source"] == "DEFAULT_STANDARD"
    assert store["workloads/p/compliance_audits/t"]["enforcement"]["profile_source"] == "DEFAULT_STANDARD"


def test_secrets_never_leave_the_terraform_runner(monkeypatch, tf, compliance):
    """Data minimization: sensitive planned values, prior state, non-location constants, sensitive root variables and
    variable defaults are not sent to the compliance server; the decision is unchanged."""
    calls = []
    cg = _wire_gate(monkeypatch, tf, compliance, calls)
    secret = rc("google_secret_manager_secret_version", "v", {"secret_data": "hunter2", "secret": "s"})
    secret["change"]["after_sensitive"] = {"secret_data": True}
    secret["change"]["before"] = {"secret_data": "old-hunter2"}
    config = {"root_module": {
        "variables": {"db_password": {"sensitive": True, "default": "pw-default"}, "region": {"default": "us-east1"}},
        "resources": [{"mode": "managed", "type": "google_secret_manager_secret_version", "name": "v",
                       "expressions": {"secret_data": {"constant_value": "hunter2"}}},
                      {"mode": "managed", "type": "google_storage_bucket", "name": "b",
                       "expressions": {"location": {"constant_value": "us-central1"}}}]},
        "provider_config": {"google": {"name": "google", "expressions": {
            "region": {"constant_value": "us-central1"}, "access_token": {"constant_value": "ya29.token"}}}}}
    p = plan(bucket(), AUDIT, secret, configuration=config,
             variables={"db_password": {"value": "pw-live"}, "region": {"value": "us-east1"}})
    out = cg.gate_plan(db=FakeDB(copy.deepcopy(HIPAA_DECISION)), product_id="claims", trace_id="t", plan_json=p)
    sent = json.dumps(calls[0]["body"])
    for leaked in ("hunter2", "pw-live", "pw-default", "ya29.token"):
        assert leaked not in sent, leaked
    assert '"us-central1"' in sent  # location constants the gate needs survive
    assert out["passed"] is True


def test_unreadable_decision_is_never_treated_as_absent(monkeypatch, tf, compliance):
    calls = []
    cg = _wire_gate(monkeypatch, tf, compliance, calls)
    out = cg.gate_plan(db=FakeDB({"__raise_get__": True}), product_id="p", trace_id="t", plan_json=plan(bucket()))
    assert out["passed"] is False and out["result"]["error_class"] == "COMPLIANCE_UNAVAILABLE" and calls == []
    out = cg.gate_plan(db=None, product_id="p", trace_id="t", plan_json=plan(bucket()))
    assert out["passed"] is False and out["result"]["error_class"] == "COMPLIANCE_UNAVAILABLE"


def test_unknown_stored_profile_is_typed(monkeypatch, tf, compliance):
    cg = _wire_gate(monkeypatch, tf, compliance)
    out = cg.gate_plan(db=FakeDB({"workloads/p": {"compliance_profile": "FOO"}}), product_id="p", trace_id="t",
                       plan_json=plan(bucket()))
    assert out["passed"] is False and out["result"]["error_class"] == "UNKNOWN_PROFILE"


def test_id_token_is_sent_to_the_cloud_run_origin(monkeypatch, tf):
    cg = tf.compliance_gate
    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "https://mcp-compliance-server-123.us-central1.run.app")
    monkeypatch.setenv("CLOUD_RUN_JOB", "tf-applier")
    seen = {}

    def post(url, body, headers, timeout):
        seen.update(url=url, headers=headers)
        return 200, {"gate_contract_version": 1, "decision": "PASS", "violations": []}

    client = cg.ComplianceGateClient(http_post=post, id_token_fetcher=lambda aud: f"tok-for-{aud}")
    client.evaluate({"plan": {}})
    assert seen["url"] == "https://mcp-compliance-server-123.us-central1.run.app/evaluate-plan"
    assert seen["headers"]["Authorization"] == "Bearer tok-for-https://mcp-compliance-server-123.us-central1.run.app"
    # A non-Cloud-Run URL on Cloud Run never gets the identity's token, and the call is not made.
    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://mcp-compliance-server:8080")
    seen.clear()
    with pytest.raises(RuntimeError, match="^CONFIG"):
        cg.ComplianceGateClient(http_post=post, id_token_fetcher=lambda aud: "tok").evaluate({})
    assert seen == {}


def test_url_resolved_from_the_metadata_server(monkeypatch, tf):
    cg = tf.compliance_gate
    monkeypatch.delenv("COMPLIANCE_SERVER_URL", raising=False)
    monkeypatch.setenv("CLOUD_RUN_JOB", "tf-applier")
    md = {"project/numeric-project-id": "123456789012", "instance/region": "projects/123456789012/regions/us-east4"}
    client = cg.ComplianceGateClient(metadata_get=md.__getitem__)
    assert client.resolve_url() == "https://mcp-compliance-server-123456789012.us-east4.run.app"
    bad = cg.ComplianceGateClient(metadata_get={"project/numeric-project-id": "x", "instance/region": "r"}.__getitem__)
    with pytest.raises(RuntimeError):
        bad.resolve_url()
    monkeypatch.delenv("CLOUD_RUN_JOB")
    with pytest.raises(RuntimeError):
        cg.ComplianceGateClient(metadata_get=md.__getitem__).resolve_url()


def test_deploy_workload_returns_the_typed_refusal(monkeypatch, tf, tmp_path):
    svc, _ = _svc(tf, tmp_path, {})
    refusal = {"status": "FAILED", "error_class": "COMPLIANCE_VIOLATION", "error": "COMPLIANCE_VIOLATION: x"}
    synced = []

    def impl(**kw):
        raise tf.compliance_gate.ComplianceGateRefused(refusal)

    monkeypatch.setattr(svc, "_deploy_workload_impl", impl)
    monkeypatch.setattr(svc, "_sync_feature_requests", lambda **kw: synced.append(kw))
    res = svc.deploy_workload("claims", "t")
    assert res == refusal and synced[0]["is_successful_deploy"] is False


def test_apply_plan_refuses_on_gate_and_never_applies(monkeypatch, tf, compliance, tmp_path):
    store = copy.deepcopy(HIPAA_DECISION)
    _wire_gate(monkeypatch, tf, compliance)
    svc, _ = _svc(tf, tmp_path, store)
    ws = svc._workspace_dir("t", "claims")
    os.makedirs(ws, exist_ok=True)
    open(os.path.join(ws, "tfplan"), "w").write("x")
    runner = FakeRunner(plan(bucket(key=None), AUDIT))
    monkeypatch.setattr(svc, "_run_subprocess", runner)
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    res = svc.apply_plan("claims", "t", iac_engine="OPENTOFU")
    assert res["status"] == "REFUSED" and res["error_class"] == "COMPLIANCE_VIOLATION"
    assert "apply" not in runner.calls
    runner.plan_json = plan(bucket(), AUDIT)
    monkeypatch.setattr(svc, "_run_subprocess", runner)
    assert svc.apply_plan("claims", "t", iac_engine="OPENTOFU")["status"] == "APPLIED"


def test_every_plan_less_apply_in_deploy_workload_goes_through_the_gate(tf):
    """Static guard: no direct `apply -auto-approve -no-color` subprocess call is left outside the gated helper."""
    import ast

    src = open(tf.__file__).read()
    tree = ast.parse(src)
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name != "_compliance_gated_apply":
            for sub in ast.walk(node):
                if isinstance(sub, ast.List) and len(sub.elts) >= 2 and all(isinstance(e, ast.Constant) for e in sub.elts[:2]):
                    # RT: a `tofu` argv head would slip past a terraform-only check.
                    if sub.elts[0].value in ("terraform", "tofu") and sub.elts[1].value == "apply":
                        offenders.append((node.name, sub.lineno))
    # apply_plan applies the exact saved plan after its own gate call; nothing else may build an apply argv.
    assert sorted({name for name, _ in offenders}) == ["apply_plan"], offenders
    # RT F4: the gated helper's only apply is a saved-plan apply of the gate's own plan file.
    helper = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_compliance_gated_apply"][0]
    applies = [sub for sub in ast.walk(helper) if isinstance(sub, ast.List) and len(sub.elts) >= 2
               and isinstance(sub.elts[1], ast.Constant) and sub.elts[1].value == "apply"]
    assert len(applies) == 1 and isinstance(applies[0].elts[-1], ast.Name) and applies[0].elts[-1].id == "plan_file"


def test_static_guard_recognises_a_tofu_argv_head():
    """Negative control for the guard above: a `tofu apply` argv outside the helper is found."""
    import ast

    tree = ast.parse('def rogue():\n    run(["tofu", "apply", "-auto-approve"])\n')
    found = [sub for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) for sub in ast.walk(node)
             if isinstance(sub, ast.List) and len(sub.elts) >= 2 and all(isinstance(e, ast.Constant) for e in sub.elts[:2])
             and sub.elts[0].value in ("terraform", "tofu") and sub.elts[1].value == "apply"]
    assert len(found) == 1


def test_rt_f3_unresolvable_location_group_is_unavailable_not_a_violation(monkeypatch, tf, compliance):
    """End to end through gate_plan with the real server: a server REFUSED other than UNKNOWN_PROFILE is
    COMPLIANCE_UNAVAILABLE carrying the server's class (a table gap is not an HCL defect)."""
    cg = _wire_gate(monkeypatch, tf, compliance)
    decision = copy.deepcopy(HIPAA_DECISION)
    decision["workloads/claims"]["compliance_decision"]["allowed_locations"] = ["in:mars-locations"]
    out = cg.gate_plan(db=FakeDB(decision), product_id="claims", trace_id="t", plan_json=plan(bucket(), AUDIT))
    res = out["result"]
    assert out["passed"] is False and res["error_class"] == "COMPLIANCE_UNAVAILABLE"
    assert res["compliance_gate"]["failure"] == "UNRESOLVED_LOCATION_GROUP"
    # PLAN_INVALID keeps its own failure kind; a real violation is still a violation.
    out = cg.gate_plan(db=FakeDB(copy.deepcopy(HIPAA_DECISION)), product_id="claims", trace_id="t",
                       plan_json={"resource_changes": []})
    assert out["result"]["error_class"] == "COMPLIANCE_UNAVAILABLE" and out["result"]["compliance_gate"]["failure"] == "PLAN_INVALID"
    out = cg.gate_plan(db=FakeDB(copy.deepcopy(HIPAA_DECISION)), product_id="claims", trace_id="t",
                       plan_json=plan(bucket(key=None), AUDIT))
    assert out["result"]["error_class"] == "COMPLIANCE_VIOLATION"


def test_rt_f5_projection_tables_mirror_the_server(tf, compliance):
    cg, pg = tf.compliance_gate, compliance.plan_gate
    assert cg.CMEK_ATTRIBUTE_PATHS == pg.CMEK_ATTRIBUTE_PATHS
    assert tuple(cg.PROJECTED_LOCATION_ATTRIBUTES) == tuple(pg.LOCATION_ATTRIBUTES)
    assert cg.PROJECTED_TYPE_ATTRIBUTES[pg.AUDIT_CONFIG_TYPE] == ("service", "audit_log_config")
    for t in pg.RUN_IAM_MEMBER_TYPES:
        assert set(cg.PROJECTED_TYPE_ATTRIBUTES[t]) == {"role", "member"}
    for t in pg.RUN_IAM_BINDING_TYPES:
        assert set(cg.PROJECTED_TYPE_ATTRIBUTES[t]) == {"role", "members"}
    for t in pg.RUN_IAM_POLICY_TYPES:
        assert cg.PROJECTED_TYPE_ATTRIBUTES[t] == ("policy_data",)
    assert set(cg.PROJECTED_TYPE_ATTRIBUTES[pg.CLOUD_RUN_V2_SERVICE]) == {"iap_enabled", "invoker_iam_disabled", "ingress"}


def test_rt_f5_only_read_attributes_leave_the_runner_and_decisions_are_unchanged(monkeypatch, tf, compliance):
    calls = []
    cg = _wire_gate(monkeypatch, tf, compliance, calls)
    run = rc("google_cloud_run_v2_service", "app", {
        "name": "app", "location": "us-central1", "ingress": "INGRESS_TRAFFIC_ALL", "iap_enabled": False,
        "invoker_iam_disabled": False,
        "template": [{"encryption_key": KEY, "containers": [{"env": [{"name": "DB", "value": "hunter2-from-llm-env"}],
                                                             "image": "img"}]}]})
    secret = rc("google_secret_manager_secret", "s", {"secret_id": "s", "labels": {"note": "plain-secret-label"},
                                                      "replication": [{"auto": [{"customer_managed_encryption": [
                                                          {"kms_key_name": KEY}]}]}]})
    p = plan(bucket(), AUDIT, run, secret)
    out = cg.gate_plan(db=FakeDB(copy.deepcopy(HIPAA_DECISION)), product_id="claims", trace_id="t", plan_json=p)
    sent = json.dumps(calls[0]["body"])
    for leaked in ("hunter2-from-llm-env", "plain-secret-label", '"img"'):
        assert leaked not in sent, leaked
    assert KEY in sent and "allServices" in sent and "INGRESS_TRAFFIC_ALL" in sent
    # Negative test: the projected plan gets the same decision as the full plan.
    full = ev(compliance, p, "HIPAA", {"enable_direct_iap": False, "allow_unauthenticated": False})
    assert out["passed"] is (full["decision"] == "PASS")
    for variant in (plan(bucket(key=None), AUDIT, run), plan(bucket(location="europe-west1"), AUDIT, run),
                    plan(bucket(), run)):
        projected = cg.minimize_plan(variant)
        assert codes(ev(compliance, projected, "HIPAA")) == codes(ev(compliance, variant, "HIPAA"))


# ================================================================================================ 5. gateway record
def test_audit_record_writes_the_decision_the_gate_reads(monkeypatch):
    from fd4g_support import real_modules

    real_modules(monkeypatch)
    monkeypatch.syspath_prepend(GW_DIR)
    import compliance_agent.handler as ch
    h = ch.ComplianceAgentHandler.__new__(ch.ComplianceAgentHandler)  # no model clients (hermetic)
    store = {}
    h._db = FakeDB(store)
    h.require_remote_engine = True
    # Integration (FD-4R R-6 seam): the persist takes the complete v2 record; the gate's map is projected from it.
    h._persist_audit_record({"schema_version": 2, "product_id": "claims", "trace_id": "t1",
                             "compliance_profile": "HIPAA", "is_regulated": True, "summary": "s",
                             "allow_unauthenticated": False, "enable_direct_iap": True,
                             "enforce_private_ingress": True, "decided_at": 1.5,
                             "policy_matrix": {"allowed_locations": ["in:us-locations", 7]}})
    dec = store["workloads/claims"]["compliance_decision"]
    assert store["workloads/claims"]["compliance_profile"] == "HIPAA"
    assert dec["enable_direct_iap"] is True and dec["allow_unauthenticated"] is False
    assert dec["enforce_private_ingress"] is True and dec["allowed_locations"] == ["in:us-locations"]
    assert store["workloads/claims/compliance_audits/t1"]["is_regulated"] is True
    assert dec["trace_id"] == "t1" and dec["recorded_at"] == 1.5


def _bare_compliance_handler(monkeypatch, store):
    from fd4g_support import real_modules

    real_modules(monkeypatch)
    monkeypatch.syspath_prepend(GW_DIR)
    import compliance_agent.handler as ch
    h = ch.ComplianceAgentHandler.__new__(ch.ComplianceAgentHandler)
    h._db = FakeDB(store)
    h.require_remote_engine = True
    return h


def test_integration_projection_keeps_the_rest_of_the_workload_doc_and_replaces_the_old_map(monkeypatch):
    """Do No Harm (integration of PR-0 into R-6): only the two projected fields of workloads/{pid} change; a key of an
    older compliance_decision map does not survive."""
    store = {"workloads/claims": {"owner": "u@example.com", "requested_compliance_profile": "HIPAA",
                                  "compliance_decision": {"profile": "PCI_DSS", "stale_key": 1}}}
    h = _bare_compliance_handler(monkeypatch, store)
    h._persist_audit_record({"product_id": "claims", "trace_id": "t2", "compliance_profile": "STANDARD",
                             "is_regulated": False, "allow_unauthenticated": True, "enable_direct_iap": False,
                             "enforce_private_ingress": False, "decided_at": 2.0, "policy_matrix": {}})
    doc = store["workloads/claims"]
    assert doc["owner"] == "u@example.com" and doc["requested_compliance_profile"] == "HIPAA"
    assert "stale_key" not in doc["compliance_decision"] and doc["compliance_decision"]["profile"] == "STANDARD"


def test_integration_projection_write_failure_is_persist_failed_and_writes_nothing(monkeypatch):
    from gate_errors import GateUnavailableError

    store = {"__raise_set__": True, "workloads/claims": {"compliance_decision": {"profile": "HIPAA"}}}
    h = _bare_compliance_handler(monkeypatch, store)
    with pytest.raises(GateUnavailableError) as ei:
        h._persist_audit_record({"product_id": "claims", "trace_id": "t3", "compliance_profile": "STANDARD",
                                 "decided_at": 3.0})
    assert ei.value.reason == "COMPLIANCE_PERSIST_FAILED" and ei.value.details["failure"] == "WRITE"
    assert store["workloads/claims"] == {"compliance_decision": {"profile": "HIPAA"}}
    assert "workloads/claims/compliance_audits/t3" not in store
