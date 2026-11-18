"""Lane 19 L19-4: report-only IaC access-policy validator (plan §2.3, §3 "Validator").

Every case asserts the input is byte-identical afterwards (sha256 of the files dict): the validator never rewrites.
Inputs are `.tf.json` (parsed with json, lane 15 FD-54 format) so the suite runs without python-hcl2; the `.tf` cases
run only where python-hcl2 is installed (Step 1 adds it to the gateway requirements) and otherwise assert the loud
HclUnavailable instead of a silent skip of the check.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import hashlib
import importlib.util
import json
import os
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "apps", "orchestrator-gateway"))

from developer_agent import access_policy_validator as apv  # noqa: E402
from shared.access_policy import AccessPolicy  # noqa: E402

HAS_HCL2 = importlib.util.find_spec("hcl2") is not None
CUSTOM = "infra/workload/custom.tf.json"


def _iap(principals=("user:alice@example.com",)):
    return AccessPolicy(mode="PRIVATE_IAP", invoker_principals=list(principals), sign_in={"google": "DISABLED"},
                        source="intake")


def _iam():
    return AccessPolicy(mode="PRIVATE_IAM", invoker_principals=["group:ops@example.com"],
                        sign_in={"google": "DISABLED"}, source="intake")


def _public(google="SHARED_PLATFORM_CLIENT"):
    return AccessPolicy(mode="PUBLIC_APP", sign_in={"google": google, "email_password": google == "DISABLED"},
                        tenant_isolation_required=False, source="intake")


def _digest(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def _run(files, access, **kw):
    before = _digest(files)
    snapshot = {k: v for k, v in files.items()}
    diags = apv.validate(files, access, **kw)
    assert _digest(files) == before and files == snapshot, "validator mutated its input"
    return diags


def _tfjson(doc):
    return json.dumps(doc)


def _codes(diags):
    return [d["code"] for d in diags]


VALID = {
    CUSTOM: _tfjson({
        "resource": {
            "google_storage_bucket": {"data": {"name": "b", "location": "US"}},
            "google_storage_bucket_iam_member": {"reader": {"bucket": "b", "role": "roles/storage.objectViewer",
                                                            "member": "serviceAccount:app@p.iam.gserviceaccount.com"}},
            "google_compute_firewall": {"lb": {"name": "lb", "network": "n", "source_ranges": ["0.0.0.0/0"]}},
            "google_project_iam_member": {"ds": {"project": "${var.project_id}", "role": "roles/datastore.user",
                                                 "member": "serviceAccount:app@p.iam.gserviceaccount.com"}},
        },
        "variable": {"project_id": {"type": "string"}},
    }),
    "apps/svc/main.py": "print('not IaC')\n",
}


# ------------------------------------------------------------------------------------------------ Do No Harm
@pytest.mark.parametrize("access", [_iap(), _iam(), _public()])
def test_valid_workload_has_zero_diagnostics_and_is_untouched(access):
    assert _run(dict(VALID), access) == []


def test_firewall_open_range_is_out_of_scope():
    files = {CUSTOM: _tfjson({"resource": {"google_compute_firewall": {"a": {"source_ranges": ["0.0.0.0/0"]}}}})}
    assert _run(files, _iap()) == []


# ------------------------------------------------------------------------------------------------ public principals
@pytest.mark.parametrize("member", ["allAuthenticatedUsers", "allUsers"])
def test_public_member_literal(member):
    files = {CUSTOM: _tfjson({"resource": {"google_storage_bucket_iam_member": {"pub": {
        "bucket": "b", "role": "roles/storage.objectViewer", "member": member}}}})}
    diags = _run(files, _iap())
    assert _codes(diags) == ["POLICY.PUBLIC_PRINCIPAL_FORBIDDEN"]
    d = diags[0]
    assert d["file"] == CUSTOM and d["block_address"] == "google_storage_bucket_iam_member.pub"
    assert d["disposition"] == "REPAIR" and d["persona"] == "iac" and d["severity"] == "error"


def test_public_members_list_on_binding_resource():
    files = {CUSTOM: _tfjson({"resource": {"google_pubsub_topic_iam_binding": {"b": {
        "topic": "t", "role": "roles/pubsub.subscriber", "members": ["user:a@example.com", "allUsers"]}}}})}
    assert _codes(_run(files, _iap())) == ["POLICY.PUBLIC_PRINCIPAL_FORBIDDEN"]


def test_public_member_via_variable_default():
    files = {CUSTOM: _tfjson({
        "variable": {"who": {"default": "allAuthenticatedUsers"}},
        "resource": {"google_storage_bucket_iam_member": {"pub": {"bucket": "b", "role": "r",
                                                                  "member": "${var.who}"}}}})}
    assert _codes(_run(files, _iap())) == ["POLICY.PUBLIC_PRINCIPAL_FORBIDDEN"]


def test_public_member_via_tfvars_overrides_default():
    files = {CUSTOM: _tfjson({
        "variable": {"who": {"default": "user:a@example.com"}},
        "resource": {"google_storage_bucket_iam_member": {"pub": {"bucket": "b", "role": "r",
                                                                  "member": "${var.who}"}}}})}
    assert _run(files, _iap()) == []
    assert _codes(_run(files, _iap(), tfvars={"who": "allAuthenticatedUsers"})) == ["POLICY.PUBLIC_PRINCIPAL_FORBIDDEN"]


def test_members_list_variable_resolved():
    files = {CUSTOM: _tfjson({
        "variable": {"ms": {"default": ["user:a@example.com", "allUsers"]}},
        "resource": {"google_storage_bucket_iam_binding": {"b": {"bucket": "b", "role": "r", "members": "${var.ms}"}}}})}
    assert _codes(_run(files, _iap())) == ["POLICY.PUBLIC_PRINCIPAL_FORBIDDEN"]


def test_unresolvable_expression_is_not_guessed():
    files = {CUSTOM: _tfjson({"resource": {"google_storage_bucket_iam_member": {"x": {
        "bucket": "b", "role": "r", "member": "${local.m}"}}}})}
    assert _run(files, _iap()) == []


def test_data_google_iam_policy_binding():
    files = {CUSTOM: _tfjson({"data": {"google_iam_policy": {"p": {"binding": [
        {"role": "roles/run.invoker", "members": ["allUsers"]}]}}}})}
    diags = _run(files, _iap())
    assert _codes(diags) == ["POLICY.PUBLIC_PRINCIPAL_FORBIDDEN"]
    assert diags[0]["block_address"] == "data.google_iam_policy.p"


@pytest.mark.parametrize("acl", ["publicRead", "publicReadWrite", "authenticatedRead"])
def test_predefined_acl_public(acl):
    files = {CUSTOM: _tfjson({"resource": {"google_storage_object_acl": {"a": {"bucket": "b", "object": "o",
                                                                               "predefined_acl": acl}}}})}
    assert _codes(_run(files, _iap())) == ["POLICY.PUBLIC_PRINCIPAL_FORBIDDEN"]


def test_predefined_acl_private_ok():
    files = {CUSTOM: _tfjson({"resource": {"google_storage_bucket_acl": {"a": {"bucket": "b",
                                                                               "predefined_acl": "private"}}}})}
    assert _run(files, _iap()) == []


def test_storage_role_entity_split_on_first_colon():
    files = {CUSTOM: _tfjson({"resource": {"google_storage_bucket_acl": {"a": {"bucket": "b", "role_entity": [
        "OWNER:user-a@example.com", "READER:allUsers"]}}}})}
    assert _codes(_run(files, _iap())) == ["POLICY.PUBLIC_PRINCIPAL_FORBIDDEN"]
    ok = {CUSTOM: _tfjson({"resource": {"google_storage_bucket_acl": {"a": {"bucket": "b", "role_entity": [
        "READER:group-allUsers@example.com"]}}}})}
    assert _run(ok, _iap()) == []


def test_platform_owned_golden_module_excluded_by_provenance():
    golden = "infra/modules/compute-cloudrun/main.tf.json"
    files = {golden: _tfjson({"resource": {"google_cloud_run_v2_service_iam_member": {"public": {
        "name": "s", "role": "roles/run.invoker", "member": "allUsers"}}}})}
    assert _run(files, _public(), platform_owned_paths={golden}) == []
    assert _codes(_run(files, _public())) == ["POLICY.PUBLIC_PRINCIPAL_FORBIDDEN"]  # same file, not provenance-owned


def test_unparseable_file_reported_not_skipped():
    files = {CUSTOM: "{not json"}
    assert _codes(_run(files, _iap())) == ["POLICY.UNCHECKABLE_FILE"]


# ------------------------------------------------------------------------------------------------ tfvars mismatch
def test_access_policy_mismatch_platform_keys():
    access = _iap(["user:alice@example.com"])
    ok = {"allow_unauthenticated": False, "enable_direct_iap": True,
          "authorized_invoker_members": ["user:alice@example.com"]}
    assert _run({}, access, tfvars=ok) == []
    for key, bad in (("allow_unauthenticated", True), ("enable_direct_iap", False),
                     ("authorized_invoker_members", ["allAuthenticatedUsers"]),
                     ("authorized_invoker_members", []), ("enable_direct_iap", "true")):
        diags = _run({}, access, tfvars={**ok, key: bad})
        assert _codes(diags) == ["POLICY.ACCESS_POLICY_MISMATCH"], (key, bad)
        assert diags[0]["disposition"] == "PLATFORM_DEFECT" and diags[0]["persona"] is None


def test_absent_platform_keys_are_not_a_mismatch():
    assert _run({}, _iap(), tfvars={"region": "x"}) == []


# ------------------------------------------------------------------------------------------------ IdP in IaC
@pytest.mark.parametrize("rtype", sorted(apv.IDP_RESOURCE_TYPES))
def test_idp_resource_in_llm_iac(rtype):
    files = {CUSTOM: _tfjson({"resource": {rtype: {"g": {"enabled": True}}}})}
    for access in (_public(), _iap()):
        assert _codes(_run(files, access)) == ["POLICY.IDP_CONFIG_IN_IAC"]


def test_golden_workload_auth_files_excluded():
    golden = "infra/modules/workload_auth/main.tf.json"
    files = {golden: _tfjson({"resource": {"google_identity_platform_config": {"auth": {"project": "p"}}}})}
    assert _run(files, _public(), platform_owned_paths={golden}) == []


@pytest.mark.parametrize("access", [_iap(), _iam()])
def test_workload_auth_module_in_private_workload(access):
    files = {CUSTOM: _tfjson({"module": {"auth": {"source": "../modules/workload_auth"}}})}
    diags = _run(files, access)
    assert _codes(diags) == ["POLICY.IDP_CONFIG_IN_IAC"] and diags[0]["block_address"] == "module.auth"


def test_workload_auth_module_in_public_app_is_not_flagged():
    """Do No Harm (row 42 keyed on the mode enum only)."""
    files = {CUSTOM: _tfjson({"module": {"auth": {"source": "../modules/workload_auth"}}})}
    assert _run(files, _public()) == []


def test_other_module_sources_not_flagged():
    files = {CUSTOM: _tfjson({"module": {"x": {"source": "../modules/workload_auth_helpers"},
                                         "y": {"source": "../modules/compute-cloudrun"}}})}
    assert _run(files, _iap()) == []


# ------------------------------------------------------------------------------------------------ IdP secret readers
def _role_files(role):
    return {CUSTOM: _tfjson({"resource": {"google_project_iam_member": {"r": {
        "project": "p", "role": role, "member": "serviceAccount:app@p.iam.gserviceaccount.com"}}}})}


def test_idp_secret_reader_in_shared_mode():
    assert _codes(_run(_role_files("roles/firebaseauth.admin"), _public())) == ["POLICY.IDP_SECRET_READER_FORBIDDEN"]


@pytest.mark.parametrize("access", [_public("BYO"), _public("DISABLED"), _iap()])
def test_idp_secret_reader_only_in_shared_mode(access):
    assert _run(_role_files("roles/firebaseauth.admin"), access) == []


def test_ordinary_role_not_flagged():
    assert _run(_role_files("roles/datastore.user"), _public()) == []


def test_custom_role_with_configs_get_permission():
    files = {CUSTOM: _tfjson({"resource": {"google_project_iam_custom_role": {"c": {
        "role_id": "x", "title": "x", "permissions": ["datastore.entities.get", "firebaseauth.configs.get"]}}}})}
    assert _codes(_run(files, _public())) == ["POLICY.IDP_SECRET_READER_FORBIDDEN"]


# ------------------------------------------------------------------------------------------------ HCL path
CUSTOM_TF_PUBLIC = '''
resource "google_storage_bucket_iam_member" "pub" {
  bucket = "b"
  role   = "roles/storage.objectViewer"
  member = "allAuthenticatedUsers"
}
'''


# Lane 19 RT F5 (docs/planning/wave2-lane19-stage2-code-red-team-fable.md): the validator's `.tf` path. Un-skipped in
# the step1 merge: Step 1 pins python-hcl2==7.3.1 in apps/orchestrator-gateway/requirements.txt (shipped in the
# gateway image, installed by CI and the AGENTS.md setup), so a missing package is a FAILURE here, never a silent skip.
def _gateway_requirement_pin(name):
    path = os.path.join(REPO, "apps", "orchestrator-gateway", "requirements.txt")
    for line in open(path):
        spec = line.split("#", 1)[0].strip()
        if spec.startswith(name + "=="):
            return spec[len(name) + 2:]
    return None


def test_hcl2_installed_at_the_gateway_pin():
    # `_unquote` label handling differs across python-hcl2 versions: the .tf path is only proven at the pinned version.
    import importlib.metadata
    pin = _gateway_requirement_pin("python-hcl2")
    assert pin == "7.3.1"
    assert HAS_HCL2, "python-hcl2 (gateway requirement) must be installed to run the validator's .tf path"
    assert importlib.metadata.version("python-hcl2") == pin


def test_hcl_tf_input_same_result():
    files = {"infra/workload/custom.tf": CUSTOM_TF_PUBLIC}
    assert _codes(_run(files, _iap())) == ["POLICY.PUBLIC_PRINCIPAL_FORBIDDEN"]
    ok = {"infra/workload/custom.tf": CUSTOM_TF_PUBLIC.replace("allAuthenticatedUsers", "user:a@example.com")}
    assert _run(ok, _iap()) == []


@pytest.mark.skipif(HAS_HCL2, reason="python-hcl2 installed")
def test_tf_input_without_hcl2_fails_loudly():
    with pytest.raises(apv.HclUnavailable):
        apv.validate({"infra/workload/custom.tf": CUSTOM_TF_PUBLIC}, _iap())


# ------------------------------------------------------------------------------------------------ hygiene
def test_validator_source_has_no_regex():
    src = open(os.path.join(REPO, "apps/orchestrator-gateway/developer_agent/access_policy_validator.py")).read()
    tree = ast.parse(src)
    names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert "re" not in names and "regex" not in names
