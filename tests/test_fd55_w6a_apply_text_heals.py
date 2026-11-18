"""FD-55 W6a (register FD55-W6a, owner 10-24): `prepare_workspace` applies exactly the files that were committed.

Deleted (plan docs/planning/fd-55-healer-deletion-plan.md §2.4 / §2.5, appendix A3-A7, A9-A26, A41): the legacy
root-file drop, the `default = "${var..}"` wipe, the Cloud Run deletion_protection add / flip, the provider 5.x pin
rewrite, the workflow YAML sanitizer, the guessed `variable` declarations, the GCP naming rewrite (also its
deploy-time second pass), the duplicate-output delete, the module.compute collision re-pointing, the compute-cloudrun
/ root variables text heals, and the whole per-file chain (HB-10 output strip and its newline trim, service_url,
locals placeholders, firestore / data / source rewrites, google-beta / bucket / repository_id heals, timeouts /
lifecycle / Workload Identity injections, `app-(default)`).

Each case below is an input the deleted step rewrote (verified against the pre-W6a product: every case fails there);
now every file comes back byte-identical, final newline included, and nothing is added or removed. A mutant re-adding
any of those steps fails its case. The healers W6b / W6d / W6c own (A27-A31, A42-A49) are not exercised here
beyond what they leave alone. Hermetic: prepare_workspace into tmp_path (no backend, no subprocess, no network)."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from fd4g_support import load_tf_service  # noqa: E402

PID = "shopx"

WORKFLOW = ("name: Deploy\non:\n  push:\n    branches: [main]\nenv:\n  SERVICE_NAME: shop\njobs:\n  deploy:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: gcloud run deploy ${{ env.SERVICE_NAME }} --source . --no-allow-unauthenticated\n")

CLOUD_RUN = ('resource "google_cloud_run_v2_service" "api" {\n  name     = "api"\n  location = var.region\n'
             '  template {\n    containers {\n      image = var.image\n    }\n  }\n}\n')

# A-id -> {path: committed text}; each was rewritten (or dropped) by the deleted step.
CASES = {
    "A3_root_files_kept_beside_apps": {
        "main.py": "print('root app')\n", "Procfile": "web: python main.py\n", "requirements.txt": "fastapi\n",
        "apps/api/main.py": "print('api')\n", "main.tf": 'locals {\n  a = "b"\n}\n'},
    "A4_default_interpolation_kept": {
        "variables.tf": 'variable "svc" {\n  type    = string\n  default = "${var.product_id}-svc"\n}\n'},
    "A5_cloud_run_without_deletion_protection": {"custom.tf": CLOUD_RUN},
    "A5_cloud_run_protection_true_kept": {
        "custom.tf": CLOUD_RUN.replace('  location = var.region\n',
                                       '  location = var.region\n  deletion_protection = true\n')},
    "A6_provider_5x_pin_kept": {
        "versions.tf": ('terraform {\n  required_providers {\n    google = {\n      source  = "hashicorp/google"\n'
                        '      version = "~> 5.40"\n    }\n  }\n}\n')},
    "A7_workflow_text_kept": {".github/workflows/deploy.yml": WORKFLOW},
    "A9_undeclared_variable_not_declared": {
        "main.tf": 'resource "google_pubsub_topic" "t" {\n  name = var.topic_name\n}\n'},
    "A10_name_interpolation_kept": {
        "custom.tf": 'resource "google_pubsub_topic" "dl" {\n  name = "${var.pubsub_topic_name}-dead-letter"\n}\n'},
    "A10_long_connector_name_kept": {
        "network.tf": ('resource "google_vpc_access_connector" "c" {\n'
                       '  name          = "shopx-network-connector-overly-long"\n'
                       '  region        = var.region\n  ip_cidr_range = "10.8.0.0/28"\n  network       = "default"\n}\n')},
    "A10_secret_ref_kept": {
        "secrets.tf": ('resource "google_secret_manager_secret" "api_key" {\n  secret_id = "api-key"\n'
                       '  replication {\n    auto {}\n  }\n}\n\n'
                       'resource "google_secret_manager_secret_iam_member" "m" {\n  secret_id = "api-key"\n'
                       '  role      = "roles/secretmanager.secretAccessor"\n  member    = "user:a@example.com"\n}\n')},
    "A11_and_A14_duplicate_and_custom_outputs_kept": {
        "outputs.tf": 'output "url" {\n  value = "a"\n}\n',
        "custom.tf": 'output "url" {\n  value = "b"\n}\n\noutput "extra" {\n  value = "c"\n}\n'},
    "A13_root_variables_without_env_vars": {
        "infra/workload/variables.tf": 'variable "project_id" {\n  type = string\n}\n'},
    "A14_budget_and_project_number_kept": {
        "custom.tf": ('resource "google_billing_budget" "b" {\n  billing_account = "x"\n'
                      '  display_name    = "b-${var.project_number}"\n}\n')},
    "A15_platform_render_final_newline": {"services.tf": 'locals {\n  rendered = true\n}\n'},
    "A16_service_url_reference_kept": {"custom.tf": 'output "u" {\n  value = module.compute.service_url\n}\n'},
    "A18_firestore_reference_kept": {
        "custom.tf": 'output "db" {\n  value = google_firestore_database.db.name\n}\n'},
    "A19_project_data_source_not_added": {
        "custom.tf": 'output "n" {\n  value = data.google_project.project.number\n}\n'},
    "A20_relative_module_source_kept": {
        "custom.tf": 'module "m" {\n  source = "../modules/storage-bucket"\n}\n'},
    "A21_iap_cloud_run_and_root_main_kept": {
        "main.tf": ('terraform {\n  required_providers {\n    google = {\n      source = "hashicorp/google"\n'
                    '    }\n  }\n}\n'),
        "custom.tf": CLOUD_RUN.replace('  location = var.region\n', '  location    = var.region\n  iap_enabled = true\n')},
    "A21_bucket_policy_and_repository_id_kept": {
        "custom.tf": ('resource "google_storage_bucket" "b" {\n  name                       = "b"\n'
                      '  location                   = "US"\n  enforce_bucket_policy_only = true\n}\n'),
        "variables.tf": 'variable "repository_id" {\n  type    = string\n  default = "shop-repository"\n}\n'},
    "A23_subnet_without_ignore_changes": {
        "network.tf": ('resource "google_compute_subnetwork" "s" {\n  name          = "s"\n'
                       '  ip_cidr_range = "10.0.0.0/24"\n  network       = "default"\n}\n')},
    "A24_kubernetes_deployment_without_timeouts": {
        "k8s.tf": 'resource "kubernetes_deployment" "d" {\n  metadata {\n    name = "d"\n  }\n}\n'},
    "A25_annotated_ksa_without_injected_binding": {
        "k8s.tf": ('resource "kubernetes_service_account" "ksa" {\n  metadata {\n    name = "ksa"\n'
                   '    annotations = {\n      "iam.gke.io/gcp-service-account" = "sa@p.iam.gserviceaccount.com"\n'
                   '    }\n  }\n}\n')},
    "A26_app_default_name_kept": {
        "custom.tf": 'resource "google_firestore_database" "db" {\n  name = "app-(default)"\n}\n'},
}


@pytest.fixture
def tf(monkeypatch):
    return load_tf_service(monkeypatch)


def _svc(tf, tmp_path, db=None):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock())
    svc.db = db
    svc.state_bucket = ""
    return svc


def _read_tree(ws):
    out = {}
    for root, dirs, names in os.walk(ws):
        for n in names:
            p = os.path.join(root, n)
            if not os.path.islink(p):
                out[os.path.relpath(p, ws).replace(os.sep, "/")] = Path(p).read_bytes()
    return out


@pytest.mark.parametrize("case", sorted(CASES))
def test_prepare_workspace_writes_every_committed_file_byte_identical(tf, tmp_path, case):
    files = CASES[case]
    svc = _svc(tf, tmp_path)
    ws = svc.prepare_workspace(PID, f"trace-w6a-{case.lower()[:20]}", dict(files), region="us-central1")
    got = _read_tree(ws)
    assert got == {k: v.encode("utf-8") for k, v in files.items()}, case     # nothing changed, added or removed
    assert not getattr(svc, "_last_healed_files", {}).get(PID)                # nothing to write back


def test_a17_no_placeholder_local_from_the_product_id(tf, tmp_path):
    """A17 (HB-51) synthesized `<service local> = "<product id>"`. FD-55 W6b deleted the locals curing (A28) too, so
    the undeclared local reaches the workspace byte-identical (a validate error, reported back)."""
    files = {"app.tf": 'resource "google_pubsub_topic" "t" {\n  name = local.service_name\n}\n'}
    ws = _svc(tf, tmp_path).prepare_workspace(PID, "trace-w6a-a17", files)
    assert f'service_name = "{PID}"' not in Path(ws, "app.tf").read_text(encoding="utf-8")
    assert Path(ws, "app.tf").read_text(encoding="utf-8") == files["app.tf"]


def test_a7_no_firestore_read_for_the_workflow(tf, tmp_path):
    """A7: the workload metadata read that fed the sanitizer is gone (prepare_workspace reads no Firestore doc)."""
    db = MagicMock()
    _svc(tf, tmp_path, db=db).prepare_workspace(PID, "trace-w6a-a7db", {".github/workflows/d.yml": WORKFLOW})
    db.collection.assert_not_called()


def test_platform_renders_and_ai_outputs_are_byte_identical(tf, tmp_path):
    """Plan acceptance (C4 shape, in-repo): a legacy tree of real platform renders (main / variables / outputs /
    workflow, as committed by the gateway) plus an AI custom.tf that declares outputs comes back byte-identical."""
    from developer_agent import handler as h
    from developer_agent import terraform_engine as te
    files = {
        "main.tf": te.generate_golden_main_tf(PID, "cloudrun"),
        "variables.tf": te.generate_golden_variables_tf(PID, "acme/shopx", region="us-central1"),
        "outputs.tf": te.generate_golden_outputs_tf(PID, "cloudrun"),
        "custom.tf": ('resource "google_pubsub_topic" "events" {\n  name = "${var.product_id}-events"\n}\n\n'
                      'output "events_topic" {\n  value = google_pubsub_topic.events.name\n}\n'),
        ".github/workflows/deploy-api.yml": h.generate_service_workflow("api", PID, "child-p", "123",
                                                                        region="us-central1"),
        "apps/api/main.py": "print('api')\n",
    }
    for k, v in files.items():
        assert v.endswith("\n"), k
    ws = _svc(tf, tmp_path).prepare_workspace(PID, "trace-w6a-renders", dict(files), region="us-central1")
    assert _read_tree(ws) == {k: v.encode("utf-8") for k, v in files.items()}


def test_deleted_apply_text_healers_are_gone(tf):
    for name in ("sanitize_github_workflow", "_deduplicate_env_block", "sanitize_gcp_naming_invariants",
                 "sanitize_secret_manager_references", "inject_cloud_run_timeouts"):
        assert not hasattr(tf, name), name
    for name in ("_reconcile_modular_compute_collisions", "_cloud_run_deletion_protection_off"):
        assert not hasattr(tf.TerraformService, name), name
    # FD-55 W6c deleted the reconciler's guesser / schema reader, the validate-error strip and the self-reference
    # rewrite (tests/test_fd55_w6c_apply_error_heals.py); FD-55 W6e deleted GKE guardrail 4's three injectors
    # (tests/test_fd55_w6e_legacy_apply.py)
    for name in ("inject_subnet_lifecycle_ignore_changes", "inject_kubernetes_deployment_timeouts",
                 "inject_gke_workload_identity_bindings"):
        assert not hasattr(tf, name), name
