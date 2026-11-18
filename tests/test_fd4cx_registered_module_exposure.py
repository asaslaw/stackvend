"""FD-4CX: a registered (non-golden) module may not grant public access by itself.

* ``shared/module_exposure.py``: parsed (python-hcl2 / json) findings for allUsers / allAuthenticatedUsers IAM members,
  public storage ACLs and ``invoker_iam_disabled = true`` on Cloud Run v2; negative tests (Do No Harm): private
  modules, caller-supplied members, ingress / IAP settings, templates and non-Terraform files give no finding.
* Express: a PRIVATE_* access record stops (``REGISTERED_MODULE_PUBLIC_EXPOSURE``) before anything is returned when a
  registered module it vendors grants public access; no record and PUBLIC_APP render exactly as before; golden modules
  (compute-cloudrun has a gated ``allUsers`` binding) are never inspected.
* Agent mode: ``handler.refuse_public_registered_modules`` judges only the non-golden modules the platform vendored;
  ``_assemble_tree`` calls it only for a private workload (AST pin).
* Control Center registration / update / sync: see ``tests/test_custom_golden_modules_lean.py`` (FD-4CX cases).
Hermetic: no network, no Firestore (MagicMock documents only).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO = Path(__file__).resolve().parent.parent
for p in (str(REPO), str(REPO / "apps" / "orchestrator-gateway")):
    if p not in sys.path:
        sys.path.insert(0, p)

import shared.module_exposure as mx  # noqa: E402
import shared.express_synthesizer as express_mod  # noqa: E402
from shared.access_policy import (AccessMode, AccessPolicy, GoogleIdpMode, SignInPolicy,  # noqa: E402
                                  platform_default_access_policy)

PUBLIC_RUN = {
    "main.tf": '''resource "google_cloud_run_v2_service" "svc" {
  name     = var.name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"
  template {
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello"
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  name     = google_cloud_run_v2_service.svc.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}
''',
    "variables.tf": 'variable "name" {\n  type = string\n}\n\nvariable "region" {\n  type = string\n}\n',
}

PRIVATE_RUN = {
    "main.tf": '''resource "google_cloud_run_v2_service" "svc" {
  name                 = var.name
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_ALL"
  invoker_iam_disabled = false
  iap_enabled          = false
  template {
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello"
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "invokers" {
  for_each = toset(var.invoker_members)
  name     = google_cloud_run_v2_service.svc.name
  location = var.region
  role     = "roles/run.invoker"
  member   = each.value
}

resource "google_storage_bucket_iam_member" "reader" {
  bucket = "b"
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${var.sa}"
}
''',
    "variables.tf": ('variable "name" {\n  type = string\n}\n\nvariable "region" {\n  type = string\n}\n\n'
                     'variable "sa" {\n  type = string\n}\n\nvariable "invoker_members" {\n  type = list(string)\n}\n'),
    "README.md": "This module never grants allUsers access.\n",
}


def _kinds(findings):
    return sorted((f.kind, f.address, f.attribute, json.loads(f.value) if f.kind != "UNCHECKABLE" else f.value)
                  for f in findings)


# ============================================================================ inspector
@pytest.mark.parametrize("hcl, expected", [
    ('resource "google_cloud_run_v2_service_iam_member" "p" {\n  member = "allUsers"\n}\n',
     [("PUBLIC_MEMBER", "google_cloud_run_v2_service_iam_member.p", "member", "allUsers")]),
    ('resource "google_cloudfunctions2_function_iam_binding" "p" {\n  members = ["user:a@x.com", "allAuthenticatedUsers"]\n}\n',
     [("PUBLIC_MEMBER", "google_cloudfunctions2_function_iam_binding.p", "members", "allAuthenticatedUsers")]),
    ('resource "google_storage_bucket_iam_member" "p" {\n  member = "allUsers"\n}\n',
     [("PUBLIC_MEMBER", "google_storage_bucket_iam_member.p", "member", "allUsers")]),
    ('resource "google_pubsub_topic_iam_member" "p" {\n  member = "allAuthenticatedUsers"\n}\n',
     [("PUBLIC_MEMBER", "google_pubsub_topic_iam_member.p", "member", "allAuthenticatedUsers")]),
    ('data "google_iam_policy" "p" {\n  binding {\n    role    = "roles/run.invoker"\n    members = ["allUsers"]\n  }\n}\n',
     [("PUBLIC_MEMBER", "data.google_iam_policy.p", "binding.members", "allUsers")]),
    ('resource "google_storage_bucket_access_control" "p" {\n  entity = "allUsers"\n  role = "READER"\n}\n',
     [("PUBLIC_MEMBER", "google_storage_bucket_access_control.p", "entity", "allUsers")]),
    ('resource "google_storage_bucket_acl" "p" {\n  role_entity = ["OWNER:project-owners-1", "READER:allUsers"]\n}\n',
     [("PUBLIC_ACL", "google_storage_bucket_acl.p", "role_entity", "READER:allUsers")]),
    ('resource "google_storage_bucket_object" "p" {\n  predefined_acl = "publicRead"\n}\n',
     [("PUBLIC_ACL", "google_storage_bucket_object.p", "predefined_acl", "publicRead")]),
    ('resource "google_cloud_run_v2_service" "p" {\n  invoker_iam_disabled = true\n}\n',
     [("INVOKER_IAM_DISABLED", "google_cloud_run_v2_service.p", "invoker_iam_disabled", True)]),
    # a bare var.NAME is resolved through the variable's default in the same directory
    ('variable "who" {\n  default = "allUsers"\n}\n\nresource "google_storage_bucket_iam_member" "p" {\n  member = var.who\n}\n',
     [("PUBLIC_MEMBER", "google_storage_bucket_iam_member.p", "member", "allUsers")]),
    ('variable "off" {\n  type    = bool\n  default = true\n}\n\nresource "google_cloud_run_v2_service" "p" {\n'
     '  invoker_iam_disabled = var.off\n}\n',
     [("INVOKER_IAM_DISABLED", "google_cloud_run_v2_service.p", "invoker_iam_disabled", True)]),
    # a nested call that opens a golden compute module (literal, or through a variable default)
    ('module "run" {\n  source = "../compute-cloudrun"\n  allow_unauthenticated = true\n}\n',
     [("PUBLIC_MODULE_INPUT", "module.run", "allow_unauthenticated", True)]),
    ('variable "pub" {\n  default = true\n}\n\nmodule "run" {\n  source = "../compute-cloudrun"\n'
     '  allow_unauthenticated = var.pub\n}\n',
     [("PUBLIC_MODULE_INPUT", "module.run", "allow_unauthenticated", True)]),
    # count-gated public bindings are still a finding: a registered module may not carry its own public switch
    ('resource "google_cloud_run_v2_service_iam_member" "p" {\n  count  = var.public ? 1 : 0\n  member = "allUsers"\n}\n',
     [("PUBLIC_MEMBER", "google_cloud_run_v2_service_iam_member.p", "member", "allUsers")]),
])
def test_each_public_exposure_primitive_is_found(hcl, expected):
    assert _kinds(mx.inspect_module_files({"main.tf": hcl})) == sorted(expected)


@pytest.mark.parametrize("key, text, expected", [
    # RT F2b: OpenTofu loads .tofu / .tofu.json
    ("iam.tofu", 'resource "google_storage_bucket_iam_member" "p" {\n  member = "allUsers"\n}\n',
     ("PUBLIC_MEMBER", "google_storage_bucket_iam_member.p", "member", "allUsers")),
    ("iam.tofu.json", json.dumps({"resource": {"google_pubsub_topic_iam_member": {"p": {"member": "allUsers"}}}}),
     ("PUBLIC_MEMBER", "google_pubsub_topic_iam_member.p", "member", "allUsers")),
    # RT F2a: the string "true" is converted to true by OpenTofu
    ("main.tf", 'resource "google_cloud_run_v2_service" "p" {\n  invoker_iam_disabled = "true"\n}\n',
     ("INVOKER_IAM_DISABLED", "google_cloud_run_v2_service.p", "invoker_iam_disabled", True)),
    ("main.tf.json", json.dumps({"resource": {"google_cloud_run_v2_service": {"p": {"invoker_iam_disabled": "true"}}}}),
     ("INVOKER_IAM_DISABLED", "google_cloud_run_v2_service.p", "invoker_iam_disabled", True)),
    ("main.tf", 'module "run" {\n  source = "../compute-cloudrun"\n  allow_unauthenticated = "true"\n}\n',
     ("PUBLIC_MODULE_INPUT", "module.run", "allow_unauthenticated", True)),
    # RT F2c: the Cloud Run v1 spelling of the invoker-check switch
    ("main.tf", 'resource "google_cloud_run_service" "p" {\n  metadata {\n    annotations = {\n'
                '      "run.googleapis.com/invoker-iam-disabled" = "true"\n    }\n  }\n}\n',
     ("INVOKER_IAM_DISABLED", "google_cloud_run_service.p",
      'metadata.annotations["run.googleapis.com/invoker-iam-disabled"]', True)),
])
def test_rt_f2_shapes_are_found(key, text, expected):
    assert _kinds(mx.inspect_module_files({key: text})) == [expected]


@pytest.mark.parametrize("value", ['"false"', '"True"', '"1"', "false"])
def test_negative_only_exact_true_strings_count(value):
    hcl = (f'resource "google_cloud_run_v2_service" "p" {{\n  invoker_iam_disabled = {value}\n}}\n\n'
           f'module "run" {{\n  source = "../compute-cloudrun"\n  allow_unauthenticated = {value}\n}}\n\n'
           f'resource "google_cloud_run_service" "v1" {{\n  metadata {{\n    annotations = {{\n'
           f'      "run.googleapis.com/invoker-iam-disabled" = {value}\n    }}\n  }}\n}}\n')
    assert mx.inspect_module_files({"main.tf": hcl}) == []


def test_negative_private_tofu_module_and_other_files_pass():
    files = {"main.tofu": PRIVATE_RUN["main.tf"], "variables.tofu": PRIVATE_RUN["variables.tf"],
             "main.md": 'member = "allUsers"',
             "v1.tf": 'resource "google_cloud_run_service" "s" {\n  metadata {\n    annotations = {\n'
                      '      "run.googleapis.com/ingress" = "all"\n    }\n  }\n}\n'}
    assert mx.inspect_module_files(files) == []


def test_tf_json_files_are_inspected():
    doc = {"resource": {"google_storage_bucket_iam_member": {"p": {"member": "allUsers", "bucket": "b"}}}}
    assert _kinds(mx.inspect_module_files({"main.tf.json": json.dumps(doc)})) == [
        ("PUBLIC_MEMBER", "google_storage_bucket_iam_member.p", "member", "allUsers")]


def test_an_unparseable_file_cannot_be_shown_private():
    found = mx.inspect_module_files({"main.tf": 'resource "x" "y" {\n  a = \n}\n'})
    assert [f.kind for f in found] == ["UNCHECKABLE"]
    assert "cannot be checked for public access" in found[0].describe()


def test_the_public_cloud_run_module_of_the_row_is_refused_with_a_precise_reason():
    with pytest.raises(mx.RegisteredModulePublicExposureError) as ei:
        mx.check_registered_module("acme-run", PUBLIC_RUN)
    err = ei.value
    assert err.reason == "REGISTERED_MODULE_PUBLIC_EXPOSURE" and err.module_id == "acme-run"
    assert str(err).startswith("REGISTERED_MODULE_PUBLIC_EXPOSURE: registered module 'acme-run'")
    assert 'main.tf: google_cloud_run_v2_service_iam_member.public member = "allUsers"' in str(err)
    assert len(err.findings) == 1   # ingress = INGRESS_TRAFFIC_ALL alone is not a finding


# ---------------------------------------------------------------------------- negative (Do No Harm)
def test_negative_a_private_module_has_no_finding_and_passes():
    files = copy.deepcopy(PRIVATE_RUN)
    assert mx.inspect_module_files(files) == []
    mx.check_registered_module("acme-private-run", files)   # does not raise
    assert files == PRIVATE_RUN   # never mutated


@pytest.mark.parametrize("hcl", [
    'variable "m" {\n  type = string\n}\n\nresource "google_storage_bucket_iam_member" "p" {\n  member = var.m\n}\n',
    'resource "google_storage_bucket_iam_member" "p" {\n  member = "user:${var.who}@example.com"\n}\n',
    'resource "google_storage_bucket_iam_member" "p" {\n  member = "group:allUsers@example.com"\n}\n',
    'resource "google_cloud_run_v2_service" "p" {\n  ingress = "INGRESS_TRAFFIC_ALL"\n  iap_enabled = false\n}\n',
    'resource "google_cloud_run_v2_service" "p" {\n  invoker_iam_disabled = false\n}\n',
    'resource "google_storage_bucket" "p" {\n  name = "allUsers"\n  public_access_prevention = "enforced"\n}\n',
    'resource "google_storage_bucket_acl" "p" {\n  predefined_acl = "private"\n  role_entity = ["READER:user-a@x.com"]\n}\n',
    '# member = "allUsers"\nresource "google_compute_network" "n" {\n  name = "allUsers"\n}\n',
    'module "run" {\n  source = "../compute-cloudrun"\n  allow_unauthenticated = false\n}\n',
    'variable "pub" {\n  type = bool\n}\n\nmodule "run" {\n  source = "../compute-cloudrun"\n'
    '  allow_unauthenticated = var.pub\n}\n',
])
def test_negative_non_public_settings_are_not_findings(hcl):
    assert mx.inspect_module_files({"main.tf": hcl}) == []


def test_negative_non_terraform_files_and_empty_modules_are_ignored():
    assert mx.inspect_module_files({"README.md": 'member = "allUsers"', "x.tfvars": 'm = "allUsers"'}) == []
    assert mx.inspect_module_files({}) == []


def test_tables_match_the_lane19_access_policy_validator():
    from developer_agent import access_policy_validator as apv
    assert mx.PUBLIC_MEMBERS == apv.PUBLIC_MEMBERS
    assert mx.PUBLIC_PREDEFINED_ACLS == apv.PUBLIC_PREDEFINED_ACLS
    assert mx.STORAGE_ACL_TYPES == apv.STORAGE_ACL_TYPES


def test_replicas_are_byte_identical():
    root = (REPO / "shared" / "module_exposure.py").read_bytes()
    for rel in ("apps/control-center/shared/module_exposure.py", "apps/orchestrator-gateway/shared/module_exposure.py"):
        assert (REPO / rel).read_bytes() == root, rel


def test_modules_under_groups_by_exact_module_directory():
    files = {"infra/modules/a/main.tf": "1", "infra/modules/a/sub/x.tf": "2", "infra/modules/ab/main.tf": "3",
             "infra/workload/main.tf": "4"}
    assert mx.modules_under(files, ["a", "zz"]) == {"a": {"main.tf": "1", "sub/x.tf": "2"}}


# ---------------------------------------------------------------------------- REMOTE_GIT file read
def test_remote_module_files_are_the_module_subtree_with_module_relative_keys_read_completely():
    """RT F5: every IaC file under the module directory, subdirectories included (a module may call ./iam)."""
    provider = MagicMock()
    provider.fetch_file_tree.return_value = {
        "modules/run/main.tf": "a", "modules/run/variables.tf": "b", "modules/run/README.md": "c",
        "modules/run/sub/x.tf": "d", "modules/run/iam.tofu": "g", "modules/other/main.tf": "e", "main.tf": "f",
        "modules/runner/main.tf": "h"}
    with patch("shared.vcs_provider.VCSProviderFactory.get_provider", return_value=provider):
        got = mx.fetch_remote_module_files("https://github.com/acme/tf-modules", "/modules/run/", "v1.2.0")
    assert got == {"main.tf": "a", "variables.tf": "b", "sub/x.tf": "d", "iam.tofu": "g"}
    provider.fetch_file_tree.assert_called_once_with("acme/tf-modules", branch="v1.2.0", require_complete=True)


def test_remote_module_in_a_subdirectory_with_a_public_grant_is_found():
    provider = MagicMock()
    provider.fetch_file_tree.return_value = {
        "modules/run/main.tf": 'module "iam" {\n  source = "./iam"\n}\n',
        "modules/run/iam/main.tf": 'resource "google_cloud_run_v2_service_iam_member" "p" {\n  member = "allUsers"\n}\n'}
    with patch("shared.vcs_provider.VCSProviderFactory.get_provider", return_value=provider):
        files = mx.fetch_remote_module_files("https://github.com/acme/tf-modules", "modules/run", "main")
    with pytest.raises(mx.RegisteredModulePublicExposureError, match="iam/main.tf"):
        mx.check_registered_module("acme-run", files)


def test_remote_module_without_terraform_files_is_refused():
    provider = MagicMock()
    provider.fetch_file_tree.return_value = {"README.md": "x"}
    with patch("shared.vcs_provider.VCSProviderFactory.get_provider", return_value=provider):
        with pytest.raises(ValueError, match="no Terraform files"):
            mx.fetch_remote_module_files("https://github.com/acme/tf-modules", "", "main")


@pytest.mark.parametrize("status, transient, text", [
    ({"complete": False, "truncated": True, "error": None}, False, "2,500"),
    ({"complete": False, "truncated": False, "error": "RateLimitExceededException: 403"}, True, "try again later"),
])
def test_remote_incomplete_read_is_typed_by_cause(status, transient, text):
    """RT F4 (deferred option): truncated -> not transient (400 at the CC), a failed read -> transient (503)."""
    from shared.vcs_provider import IncompleteRepoTreeError
    provider = MagicMock()
    provider.fetch_file_tree.side_effect = IncompleteRepoTreeError("acme/tf-modules", "main", status)
    with patch("shared.vcs_provider.VCSProviderFactory.get_provider", return_value=provider):
        with pytest.raises(mx.RemoteModuleReadError, match=text) as ei:
            mx.fetch_remote_module_files("https://github.com/acme/tf-modules", "modules/run", "main")
    assert ei.value.transient is transient


# ============================================================================ Express
def _fake_db(hcl_files):
    db = MagicMock()
    doc = MagicMock()
    doc.exists = True
    doc.to_dict.return_value = {"module_id": "acme-run", "source_type": "DIRECT_CODE", "hcl_files": hcl_files}
    db.collection.return_value.document.return_value.get.return_value = doc
    return db


def _synth(hcl_files, access, extra_instances=()):
    instances = [{"module_id": "compute-cloudrun", "instance_name": "api", "parameters": {}},
                 {"module_id": "acme-run", "instance_name": "edge", "parameters": {"name": "edge"}},
                 *extra_instances]
    return express_mod.ExpressHCLSynthesizer(db=_fake_db(hcl_files)).synthesize_workload(
        product_id="shop-app", project_id="shop-app-123", region="us-central1",
        github_repo_full_name="acme/shop-app", module_instances=instances, access=access)


PRIVATE_IAM = AccessPolicy(mode=AccessMode.PRIVATE_IAM, invoker_principals=["user:b@example.com"],
                           sign_in=SignInPolicy(google=GoogleIdpMode.DISABLED), source="intake")
PUBLIC = AccessPolicy(mode=AccessMode.PUBLIC_APP, sign_in=SignInPolicy(google=GoogleIdpMode.SHARED_PLATFORM_CLIENT),
                      tenant_isolation_required=False, source="intake")


@pytest.mark.parametrize("access", [PRIVATE_IAM, platform_default_access_policy("user:a@example.com")],
                         ids=["private_iam", "private_iap"])
def test_express_private_record_refuses_a_public_registered_module(access):
    with pytest.raises(express_mod.ExpressRegisteredModuleExposureError) as ei:
        _synth(PUBLIC_RUN, access)
    err = ei.value
    assert isinstance(err, express_mod.ExpressSynthesisRefused)   # -> the CC's typed hcl_synthesis failure
    assert err.reason == "REGISTERED_MODULE_PUBLIC_EXPOSURE" and err.module_id == "acme-run"
    assert "google_cloud_run_v2_service_iam_member.public" in str(err)


def test_negative_express_private_record_with_a_private_registered_module_renders():
    files = _synth(PRIVATE_RUN, PRIVATE_IAM)
    assert files["infra/modules/acme-run/main.tf"] == PRIVATE_RUN["main.tf"]
    # the golden compute-cloudrun module (gated allUsers binding inside) is vendored and never judged
    assert 'member   = "allUsers"' in files["infra/modules/compute-cloudrun/main.tf"]


@pytest.mark.parametrize("access", [None, PUBLIC], ids=["no_record", "public_app"])
def test_negative_express_without_a_private_record_is_unchanged(access):
    """No record (created before FD-4CS) and PUBLIC_APP render exactly what the synthesizer rendered before FD-4CX."""
    files = _synth(PUBLIC_RUN, access)
    assert files["infra/modules/acme-run/main.tf"] == PUBLIC_RUN["main.tf"]
    # the same files as the pre-FD-4CX code path: the registered set is only collected, never used to change output
    synth = express_mod.ExpressHCLSynthesizer(db=_fake_db(PUBLIC_RUN))
    instances = [{"module_id": "compute-cloudrun", "instance_name": "api", "parameters": {}},
                 {"module_id": "acme-run", "instance_name": "edge", "parameters": {"name": "edge"}}]
    again = synth.synthesize_workload(product_id="shop-app", project_id="shop-app-123", region="us-central1",
                                      github_repo_full_name="acme/shop-app", module_instances=instances,
                                      access=access)
    assert again == files


def _synth_params(params, access):
    instances = [{"module_id": "compute-cloudrun", "instance_name": "api", "parameters": {}},
                 {"module_id": "acme-run", "instance_name": "edge", "parameters": params}]
    return express_mod.ExpressHCLSynthesizer(db=_fake_db(PRIVATE_RUN)).synthesize_workload(
        product_id="shop-app", project_id="shop-app-123", region="us-central1",
        github_repo_full_name="acme/shop-app", module_instances=instances, access=access)


@pytest.mark.parametrize("params, member", [
    ({"name": "edge", "invoker_members": ["user:a@example.com", "allUsers"]}, "allUsers"),
    ({"name": "edge", "member": "allAuthenticatedUsers"}, "allAuthenticatedUsers"),
])
def test_express_private_record_refuses_a_public_principal_parameter_of_a_registered_module(params, member):
    """RT F3i: the module's own files are private, but the parameter would open it."""
    with pytest.raises(express_mod.ExpressRegisteredModuleParameterError) as ei:
        _synth_params(params, PRIVATE_IAM)
    err = ei.value
    assert isinstance(err, express_mod.ExpressSynthesisRefused)
    assert err.reason == "REGISTERED_MODULE_PUBLIC_EXPOSURE" and err.instance_name == "edge"
    assert err.members == [member] and member in str(err)


@pytest.mark.parametrize("access", [None, PUBLIC], ids=["no_record", "public_app"])
def test_negative_public_principal_parameter_without_a_private_record_renders(access):
    files = _synth_params({"name": "edge", "invoker_members": ["allUsers"]}, access)
    assert '"allUsers"' in files["infra/workload/main.tf"]


def test_negative_private_record_non_public_parameters_render():
    files = _synth_params({"name": "allUsers-edge", "invoker_members": ["user:a@example.com"]}, PRIVATE_IAM)
    assert "user:a@example.com" in files["infra/workload/main.tf"]


def test_express_registered_set_holds_only_catalog_modules():
    synth = express_mod.ExpressHCLSynthesizer(db=_fake_db(PRIVATE_RUN))
    seen: set = set()
    files: dict = {}
    synth._vendor_module_files("compute-cloudrun", files, registered=seen)
    synth._vendor_module_files("acme-run", files, registered=seen)
    assert seen == {"acme-run"}


def test_express_replicas_are_byte_identical():
    root = (REPO / "shared" / "express_synthesizer.py").read_bytes()
    for rel in ("apps/control-center/shared/express_synthesizer.py",
                "apps/orchestrator-gateway/shared/express_synthesizer.py"):
        assert (REPO / rel).read_bytes() == root, rel


# ============================================================================ Agent mode (gateway)
@pytest.fixture
def handler_mod():
    from developer_agent import handler
    return handler


DRAFT = {"infra/workload/custom.tf": 'module "edge" {\n  source = "../modules/acme-run"\n  name = "edge"\n}\n'}


def _vendored(handler_mod, hcl_files=None, *, exists=True, raises=None, draft=None):
    """vendor_platform_files with a registered module `acme-run` read from a MagicMock Firestore (no real client):
    `exists=False` = the module was removed from Settings; `raises` = the catalog read fails."""
    fs = MagicMock()
    doc = MagicMock()
    doc.exists = exists
    doc.to_dict.return_value = {"module_id": "acme-run", "source_type": "DIRECT_CODE", "hcl_files": hcl_files or {}}
    get = fs.Client.return_value.collection.return_value.document.return_value.get
    if raises is not None:
        get.side_effect = raises
    else:
        get.return_value = doc
    gc = MagicMock()
    gc.firestore = fs
    with patch.dict(sys.modules, {"google.cloud": gc, "google.cloud.firestore": fs}):
        return handler_mod.vendor_platform_files(dict(DRAFT if draft is None else draft), "cloudrun")


def test_agent_private_workload_refuses_a_public_registered_module(handler_mod):
    files, platform_files = _vendored(handler_mod, PUBLIC_RUN)
    assert "infra/modules/acme-run/main.tf" in platform_files
    with pytest.raises(handler_mod.DeveloperStageError) as ei:
        handler_mod.refuse_public_registered_modules(platform_files, files)
    assert ei.value.error_class == "REGISTERED_MODULE_PUBLIC_EXPOSURE"
    msg = str(ei.value)
    assert msg.startswith("REGISTERED_MODULE_PUBLIC_EXPOSURE: registered module 'acme-run'")
    assert msg.count("REGISTERED_MODULE_PUBLIC_EXPOSURE") == 1
    assert "google_cloud_run_v2_service_iam_member.public" in msg


def test_negative_agent_private_registered_module_and_golden_modules_pass(handler_mod):
    files, platform_files = _vendored(handler_mod, PRIVATE_RUN)
    golden_run = "infra/modules/compute-cloudrun/main.tf"
    assert golden_run in platform_files and 'member   = "allUsers"' in platform_files[golden_run]
    handler_mod.refuse_public_registered_modules(platform_files, files)   # golden allUsers (gated) never judged


def test_negative_agent_golden_only_tree_passes(handler_mod):
    files, platform_files = handler_mod.vendor_platform_files({}, "cloudrun")
    handler_mod.refuse_public_registered_modules(platform_files, files, {})


OLD_REPO = {"infra/modules/acme-run/main.tf": PUBLIC_RUN["main.tf"], "infra/workload/custom.tf": DRAFT[
    "infra/workload/custom.tf"]}


@pytest.mark.parametrize("kw", [{"raises": RuntimeError("firestore unavailable")}, {"exists": False}],
                         ids=["catalog_read_fails", "module_removed"])
def test_agent_private_rebuild_refuses_a_called_module_it_could_not_read(handler_mod, kw):
    """RT F1: no files for the called module in this run, while the repository still holds older ones."""
    files, platform_files = _vendored(handler_mod, PUBLIC_RUN, **kw)
    assert not any(p.startswith("infra/modules/acme-run/") for p in files)
    with pytest.raises(handler_mod.DeveloperStageError) as ei:
        handler_mod.refuse_public_registered_modules(platform_files, files, OLD_REPO)
    assert ei.value.error_class == "REGISTERED_MODULE_PUBLIC_EXPOSURE"
    assert "['acme-run']" in str(ei.value) and "cannot be checked" in str(ei.value)


@pytest.mark.parametrize("kw", [{"raises": RuntimeError("firestore unavailable")}, {"exists": False}],
                         ids=["catalog_read_fails", "module_removed"])
def test_negative_agent_called_module_with_no_files_anywhere_is_left_to_v2j(handler_mod, kw):
    """Nothing could deploy it (V2j POLICY.MODULE_SOURCE_NOT_LOCAL repairs the call); a hallucinated module name in a
    private workload stays a repairable finding, not an assembly stop."""
    files, platform_files = _vendored(handler_mod, PUBLIC_RUN, **kw)
    handler_mod.refuse_public_registered_modules(platform_files, files, {})
    handler_mod.refuse_public_registered_modules(platform_files, files, None)


def test_negative_agent_ai_authored_local_module_passes(handler_mod):
    draft = {"infra/workload/custom.tf": 'module "own" {\n  source = "../modules/own"\n}\n',
             "infra/modules/own/main.tf": 'resource "google_compute_network" "n" {\n  name = "n"\n}\n'}
    files, platform_files = _vendored(handler_mod, raises=RuntimeError("not consulted"), draft=draft)
    assert "infra/modules/own/main.tf" in files and "infra/modules/own/main.tf" not in platform_files
    handler_mod.refuse_public_registered_modules(platform_files, files,
                                                 {"infra/modules/own/main.tf": "old"})


def test_error_class_is_a_developer_error_class():
    from developer_agent import errors
    assert errors.REGISTERED_MODULE_PUBLIC_EXPOSURE == mx.REGISTERED_MODULE_PUBLIC_EXPOSURE
    assert errors.REGISTERED_MODULE_PUBLIC_EXPOSURE in errors.ERROR_CLASSES
    assert errors.REGISTERED_MODULE_PUBLIC_EXPOSURE not in errors.ACCESS_ERROR_CLASSES   # raised after the draft


def test_assemble_tree_runs_the_check_right_after_vendoring_for_private_workloads_only():
    tree = ast.parse((REPO / "apps/orchestrator-gateway/developer_agent/handler.py").read_text())
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_assemble_tree")
    body = list(ast.walk(fn))
    guards = [n for n in body if isinstance(n, ast.If)
              and any(isinstance(c, ast.Call) and getattr(c.func, "id", None) == "refuse_public_registered_modules"
                      for c in ast.walk(n))]
    assert len(guards) == 1
    test = guards[0].test
    assert isinstance(test, ast.Compare) and isinstance(test.ops[0], ast.IsNot)
    assert test.left.id == "allow_unauthenticated" and test.comparators[0].value is True
    call = next(c for c in ast.walk(guards[0]) if isinstance(c, ast.Call))
    assert [a.id for a in call.args] == ["platform_files", "files", "existing_files"]
    # it follows the vendoring assignment directly
    stmts = None
    for node in ast.walk(fn):
        for field in ("body", "orelse"):
            seq = getattr(node, field, None)
            if isinstance(seq, list) and guards[0] in seq:
                stmts = seq
    i = stmts.index(guards[0])
    prev = stmts[i - 1]
    assert isinstance(prev, ast.Assign) and prev.value.func.id == "vendor_platform_files"
