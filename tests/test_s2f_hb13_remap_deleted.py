"""S2-F HB-13 (proposed register row, not approved): ``TerraformService.prepare_workspace`` no longer remaps
``google_service_account.workload_sa`` / Artifact Registry / WIF pool+provider references to ``module.foundation.*``.

The deleted block ran on every deploy, on every ``custom.tf`` and on every root ``.tf`` mentioning
``module.foundation``, with no validate gate (HC-11's remap table run unconditionally). Harm: an AI that DECLARES its
own ``google_service_account "workload_sa"`` kept the resource but every reference to it was re-pointed at the
foundation SA in the deploy workspace (IAM bindings point at the wrong principal; the declared SA is an orphan): a
distinct-resource merge. (On the cassette trees the platform's moved.tf also blocks such a tree at plan, old and new.)

Now an undeclared reference reaches the engine unchanged: ``tofu validate`` reports "Reference to undeclared
resource", which V1b maps to ``TF.REFERENCE_TO_UNDECLARED_RESOURCE`` with the referenced address as its symbol
(the repair loop's input), and the apply shift-left validate returns VALIDATION_FAILED with the engine's own text.

Hermetic: one ``prepare_workspace`` into tmp_path (no backend, no subprocess, no network) + pure mapping functions.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import os
import sys
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")

# The AI declares its own SA named workload_sa and binds it: valid HCL that the old remap re-pointed at the
# foundation SA (references -> module.foundation.workload_sa_email / _id; the declared resource kept, orphaned).
DECLARED_SA_TF = '''resource "google_service_account" "workload_sa" {
  project      = var.project_id
  account_id   = "worker-sa"
  display_name = "Worker"
}

resource "google_project_iam_member" "worker_pubsub" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${google_service_account.workload_sa.email}"
}

resource "google_service_account_iam_member" "worker_self" {
  service_account_id = google_service_account.workload_sa.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.workload_sa.email}"
}
'''

# References the foundation SA without declaring it (0 occurrences in the 10-12..10-18 cassette corpus; the shape V1b
# reports as TF.REFERENCE_TO_UNDECLARED_RESOURCE).
UNDECLARED_SA_TF = '''resource "google_project_iam_member" "sa_invoker" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.workload_sa.email}"
}
'''

MAIN_TF = '''module "foundation" {
  source     = "./infra/modules/workload-foundation"
  project_id = var.project_id
}
'''

VARIABLES_TF = 'variable "project_id" {\n  type = string\n}\n'

DELETED_TARGETS = ("module.foundation.workload_sa_id", "module.foundation.workload_sa_email",
                   "module.foundation.docker_repo_id", "module.foundation.wif_pool_name",
                   "module.foundation.wif_provider_name")


@pytest.fixture(scope="module")
def svc_mod():
    if TF_DIR not in sys.path:
        sys.path.insert(0, TF_DIR)
    spec = importlib.util.spec_from_file_location("stackvend_tf_service_s2f_hb13", os.path.join(TF_DIR, "service.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _prepare(svc_mod, tmp_path, custom_tf):
    s = svc_mod.TerraformService(project_id="test-proj", db=MagicMock(), workspace_base_dir=str(tmp_path / "ws"))
    files = {"main.tf": MAIN_TF, "variables.tf": VARIABLES_TF, "custom.tf": custom_tf,
             "infra/workload/custom.tf": custom_tf}
    ws = s.prepare_workspace(product_id="s2fhb13", trace_id="trace-s2fhb13", hcl_files=dict(files))
    return {p: open(os.path.join(ws, p), encoding="utf-8").read()
            for p in ("custom.tf", "infra/workload/custom.tf", "main.tf")}


def _refs(text, needle):
    return text.count(needle)


def test_declared_workload_sa_references_survive_prepare_workspace(svc_mod, tmp_path):
    """Do No Harm (negative test): valid HCL that declares google_service_account.workload_sa keeps every reference
    to it; nothing is re-pointed at module.foundation.*."""
    out = _prepare(svc_mod, tmp_path, DECLARED_SA_TF)
    for path in ("custom.tf", "infra/workload/custom.tf"):
        text = out[path]
        assert 'resource "google_service_account" "workload_sa"' in text
        assert _refs(text, "google_service_account.workload_sa.email") == 2, path
        assert _refs(text, "google_service_account.workload_sa.name") == 1, path
        for target in DELETED_TARGETS:
            assert target not in text, (path, target)


def test_undeclared_workload_sa_reference_reaches_validate_unchanged(svc_mod, tmp_path):
    """An undeclared reference is no longer hidden at apply: the workspace keeps it as written, so the engine's
    validate (shift-left at apply; V1b at generation) reports it instead of a silent remap."""
    out = _prepare(svc_mod, tmp_path, UNDECLARED_SA_TF)
    for path in ("custom.tf", "infra/workload/custom.tf"):
        assert "${google_service_account.workload_sa.email}" in out[path], path
        assert "module.foundation.workload_sa_email" not in out[path], path
    assert out["main.tf"].count("module.foundation") == MAIN_TF.count("module.foundation")


def _prepare_workspace_fn():
    tree = ast.parse(open(os.path.join(TF_DIR, "service.py"), encoding="utf-8").read())
    return next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "prepare_workspace")


def test_prepare_workspace_has_no_foundation_remap_targets():
    """Tombstone: no string constant in prepare_workspace names a deleted remap target."""
    consts = [n.value for n in ast.walk(_prepare_workspace_fn()) if isinstance(n, ast.Constant)
              and isinstance(n.value, str)]
    for target in DELETED_TARGETS:
        assert not [c for c in consts if c == target], target
