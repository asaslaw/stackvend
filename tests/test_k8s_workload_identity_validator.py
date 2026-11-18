"""K8S-WI-UNBOUND (W6e review F5; owner 11-07 blanket backlog approval, row text to confirm): V-K8S-WI reports, report
only, an annotated Kubernetes service account that no `roles/iam.workloadIdentityUser` grant names. Parsers only
(yaml.safe_load_all, python-hcl2, json) and GKE's documented member grammar; never a rewrite. Negatives: a bound KSA
(manifest or Terraform, member or binding, project level), a KSA without the annotation, a GKE workload without
manifests, and every "not judged" case."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: F401,E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt", pytrace=False)

from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators.k8s_identity import (CODE, WorkloadIdentityBindingValidator,  # noqa: E402
                                                     parse_wi_member, unbound_service_accounts)
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402

CUSTOM = "infra/workload/custom.tf"
MANIFEST = "k8s/app.yaml"
KSA_YAML = """apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa-stream-worker
  namespace: stream-apps
  annotations:
    iam.gke.io/gcp-service-account: worker@${PROJECT_ID}.iam.gserviceaccount.com
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    spec:
      serviceAccountName: sa-stream-worker
      containers:
        - name: worker
          image: ${ARTIFACT_REGISTRY}/worker:latest
"""
GSA = 'resource "google_service_account" "worker" {\n  account_id = "worker"\n}\n'


def _grant(member, typ="google_service_account_iam_member", attr="member", role="roles/iam.workloadIdentityUser"):
    value = json.dumps([member]) if attr == "members" else json.dumps(member)
    sa = "" if typ.startswith("google_project_") else "  service_account_id = google_service_account.worker.name\n"
    proj = "  project = var.project_id\n" if typ.startswith("google_project_") else ""
    return f'resource "{typ}" "wi" {{\n{sa}{proj}  role = "{role}"\n  {attr} = {value}\n}}\n'


MEMBER = "serviceAccount:${var.project_id}.svc.id.goog[stream-apps/sa-stream-worker]"


def _findings(files):
    return WorkloadIdentityBindingValidator().validate(ValidationContext.build(files, ownership=lambda p: None))


# --------------------------------------------------------------------------------------------- findings
def test_annotated_manifest_ksa_without_a_grant_is_a_finding():
    out = _findings({MANIFEST: KSA_YAML, CUSTOM: GSA})
    assert [(d.code, d.symbol, d.file, d.severity) for d in out] == \
        [(CODE, "stream-apps/sa-stream-worker", CUSTOM, "warning")]
    assert "k8s/app.yaml" in out[0].message and "svc.id.goog[stream-apps/sa-stream-worker]" in out[0].hint


def test_annotated_terraform_ksa_without_a_grant_is_a_finding():
    tf_ksa = ('resource "kubernetes_service_account" "app" {\n  metadata {\n    name = "app-ksa"\n'
              '    annotations = {\n      "iam.gke.io/gcp-service-account" = google_service_account.worker.email\n'
              '    }\n  }\n}\n')
    assert unbound_service_accounts({CUSTOM: GSA + tf_ksa}) == [(CUSTOM, "default", "app-ksa")]


@pytest.mark.parametrize("grant", [
    _grant(MEMBER, role="roles/iam.serviceAccountUser"),                              # another role
    _grant("serviceAccount:${var.project_id}.svc.id.goog[stream-apps/other]"),        # another KSA
    _grant("serviceAccount:${var.project_id}.svc.id.goog[default/sa-stream-worker]"),  # another namespace
    _grant("principalSet://iam.googleapis.com/x/attribute.repository/o/r"),           # another principal
], ids=["role", "ksa", "namespace", "principal-set"])
def test_a_grant_for_something_else_does_not_bind(grant):
    assert unbound_service_accounts({MANIFEST: KSA_YAML, CUSTOM: GSA + grant}) == \
        [(MANIFEST, "stream-apps", "sa-stream-worker")]


def test_list_kind_manifest_is_read():
    doc = {"apiVersion": "v1", "kind": "List", "items": [{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {
        "name": "k", "annotations": {"iam.gke.io/gcp-service-account": "g@p.iam.gserviceaccount.com"}}}]}
    assert unbound_service_accounts({"k8s/l.yaml": json.dumps(doc)}) == [("k8s/l.yaml", "default", "k")]


# --------------------------------------------------------------------------------------------- negatives
@pytest.mark.parametrize("grant", [
    _grant(MEMBER),
    _grant(MEMBER, typ="google_service_account_iam_binding", attr="members"),
    _grant(MEMBER, typ="google_project_iam_member"),
    _grant(MEMBER, typ="google_project_iam_binding", attr="members"),
    _grant("serviceAccount:my-proj.svc.id.goog[stream-apps/sa-stream-worker]"),       # literal pool
], ids=["sa-member", "sa-binding", "project-member", "project-binding", "literal-pool"])
def test_negative_a_bound_ksa_is_no_finding(grant):
    assert _findings({MANIFEST: KSA_YAML, CUSTOM: GSA + grant}) == []


def test_negative_grant_in_a_tf_json_root_file_binds():
    render = {"resource": {"google_service_account_iam_member": {"wi": {
        "service_account_id": "${google_service_account.worker.name}", "role": "roles/iam.workloadIdentityUser",
        "member": MEMBER}}}}
    assert _findings({MANIFEST: KSA_YAML, "infra/workload/custom.tf.json": json.dumps(render)}) == []


def test_negative_ksa_without_the_annotation_and_gke_without_manifests():
    plain = KSA_YAML.replace("  annotations:\n    iam.gke.io/gcp-service-account: worker@${PROJECT_ID}"
                             ".iam.gserviceaccount.com\n", "")
    assert _findings({MANIFEST: plain, CUSTOM: GSA}) == []
    assert _findings({CUSTOM: GSA, "infra/workload/main.tf": 'module "compute" {\n  source = "../modules/x"\n}\n'}) == []
    assert _findings({}) == []


def test_negative_manifests_the_platform_does_not_apply_are_not_read():
    assert _findings({"apps/worker/k8s/sa.yaml": KSA_YAML, "k8s/sub/sa.yaml": KSA_YAML}) == []


@pytest.mark.parametrize("files", [
    {MANIFEST: KSA_YAML, CUSTOM: GSA + _grant("serviceAccount:${var.project_id}.svc.id.goog[${var.ns}/${var.ksa}]")},
    {MANIFEST: KSA_YAML, CUSTOM: 'resource "x" "y" {\n  a = \n'},                      # unparseable HCL
    {MANIFEST: KSA_YAML, "infra/workload/custom.tf.json": "{not json"},
    {MANIFEST: KSA_YAML, CUSTOM: 'resource "google_service_account_iam_policy" "p" {\n  service_account_id = "x"\n'
                                 '  policy_data = data.google_iam_policy.p.policy_data\n}\n'},
    {MANIFEST: KSA_YAML.replace("name: sa-stream-worker\n  namespace", "name: ${KSA}\n  namespace")},
], ids=["grant-expression", "hcl-unparseable", "json-unparseable", "whole-policy", "ksa-name-expression"])
def test_negative_not_judged_is_no_finding(files):
    assert unbound_service_accounts(files) is None
    assert _findings(files) == []


def test_negative_non_yaml_manifest_is_skipped_not_judged_here():
    assert _findings({MANIFEST: "kind: [unclosed\n", CUSTOM: GSA}) == []


def test_member_grammar():
    assert parse_wi_member(MEMBER) == ("stream-apps", "sa-stream-worker")
    for other in ("user:a@b.c", "serviceAccount:x@p.iam.gserviceaccount.com", "serviceAccount:p.svc.id.goog[nons]",
                  "serviceAccount:.svc.id.goog[a/b]", "serviceAccount:p.svc.id.goog[a/b/c]", None, 1):
        assert parse_wi_member(other) is None, other


def test_validator_never_writes():
    files = {MANIFEST: KSA_YAML, CUSTOM: GSA}
    before = dict(files)
    _findings(files)
    assert files == before


# --------------------------------------------------------------------------------------------- registration
def test_registered_report_only_after_v2m():
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    assert stack.mode_of("V-K8S-WI") == "report_only"
    assert stack.ids.index("V-K8S-WI") == stack.ids.index("V2m") + 1
