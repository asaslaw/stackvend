"""Wave 1 lane 8, register row 38 pre-merge (owner 10-12; code red-team F2).

reconcile_multi_service_declarations (HB-04, terraform_engine.py) used to strip every `random_*` resource and
`provider "random"` from LLM-written custom.tf, leaving references such as `random_password.x.result` dangling
(plan failure). LLM-written random_* is legitimate: it must survive generation unchanged.

- Fixed point: a custom.tf already in the platform's rendered form (header + blocks, as committed by a previous
  generation) containing random_password + a reference to it is byte-identical after the reconciler, and after the
  whole DeveloperAgent.generate_code_files path (verifier, healers, preflight, self_correct_hcl) up to trailing
  blank lines left by the unrelated duplicate-output dedup.
- Not covered (pre-existing, HB-04 is replaced by lanes 10/15): extract_hcl_blocks only recognizes
  resource/module/output/data/locals, so ANY provider/terraform/variable block in custom.tf is dropped on re-render.
  For random this is harmless (the provider needs no configuration; resources resolve to hashicorp/random).
- LLM form (no header, with random_id/random_string and an empty provider "random"): every random_* block survives
  verbatim and no random_* reference dangles, single- and multi-service.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import os
import re
import sys
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY_PATH, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

for m in [
    "httpx", "fastapi", "fastapi.responses", "google", "google.genai", "google.genai.types", "google.cloud",
    "google.cloud.firestore", "google.cloud.storage", "google.cloud.logging", "google.cloud.pubsub_v1", "github", "jwt",
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

CUSTOM_KEY = "infra/workload/custom.tf"
RENDERED_HEADER = (
    "# ==============================================================================\n"
    "# PROJECT CASTOR: WORKLOAD EXTENSIONS (SHIFT-LEFT AST RECONCILED)\n"
    "# ==============================================================================\n\n"
)
RANDOM_PASSWORD_BLOCK = '''resource "random_password" "api_key" {
  length  = 32
  special = false
}'''
SECRET_BLOCKS = '''resource "google_secret_manager_secret" "api_key" {
  project   = var.project_id
  secret_id = "${var.product_id}-api-key"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "api_key" {
  secret      = google_secret_manager_secret.api_key.id
  secret_data = random_password.api_key.result
}'''
RENDERED_CUSTOM_TF = RENDERED_HEADER + RANDOM_PASSWORD_BLOCK + "\n\n" + SECRET_BLOCKS + "\n"

RANDOM_ID_BLOCK = '''resource "random_id" "bucket_suffix" {
  byte_length = 4
}'''
RANDOM_STRING_BLOCK = '''resource "random_string" "token" {
  length  = 16
  special = false
}'''
LLM_CUSTOM_TF = (
    'provider "random" {}\n\n'
    + RANDOM_ID_BLOCK + "\n\n"
    + RANDOM_STRING_BLOCK + "\n\n"
    + RANDOM_PASSWORD_BLOCK + "\n\n"
    + SECRET_BLOCKS + "\n\n"
    + '''resource "google_storage_bucket" "uploads" {
  project  = var.project_id
  name     = "${var.product_id}-uploads-${random_id.bucket_suffix.hex}"
  location = var.region
  labels = {
    token = random_string.token.result
  }
}
'''
)

_REF = re.compile(r"\b(random_[a-z_]+)\.([A-Za-z0-9_-]+)\.")
_DECL = re.compile(r'^\s*resource\s+"(random_[a-z_]+)"\s+"([^"]+)"', re.MULTILINE)


def _dangling_random_refs(files):
    tf = {k: v for k, v in files.items() if k.endswith(".tf") and isinstance(v, str)}
    declared = {m.groups() for text in tf.values() for m in _DECL.finditer(text)}
    return sorted(
        f"{path}: {t}.{n}" for path, text in tf.items() for t, n in (m.groups() for m in _REF.finditer(text))
        if (t, n) not in declared
    )


def _main_tf():
    return 'module "compute" {\n  source       = "../modules/compute-cloudrun"\n  service_name = var.product_id\n}\n'


class TestReconcilerKeepsRandomResources(unittest.TestCase):
    def setUp(self):
        from developer_agent.terraform_engine import reconcile_multi_service_declarations
        self.reconcile = reconcile_multi_service_declarations

    def test_rendered_custom_tf_with_random_password_is_a_fixed_point(self):
        files = {"infra/workload/main.tf": _main_tf(), CUSTOM_KEY: RENDERED_CUSTOM_TF, "apps/keyapp/main.py": "app = 1\n"}
        self.reconcile(files=files, product_id="keyapp", spec_text="A single REST API that issues API keys")
        self.assertEqual(files[CUSTOM_KEY], RENDERED_CUSTOM_TF)
        self.assertEqual(_dangling_random_refs(files), [])

    def test_llm_custom_tf_random_blocks_survive_single_service(self):
        files = {"infra/workload/main.tf": _main_tf(), CUSTOM_KEY: LLM_CUSTOM_TF, "apps/keyapp/main.py": "app = 1\n"}
        self.reconcile(files=files, product_id="keyapp", spec_text="A single REST API that issues API keys")
        for block in (RANDOM_ID_BLOCK, RANDOM_STRING_BLOCK, RANDOM_PASSWORD_BLOCK):
            self.assertIn(block, files[CUSTOM_KEY])
        self.assertIn("random_id.bucket_suffix.hex", files[CUSTOM_KEY])
        self.assertEqual(_dangling_random_refs(files), [])

    def test_llm_custom_tf_random_blocks_survive_multi_service(self):
        files = {
            "infra/workload/main.tf": _main_tf(),
            CUSTOM_KEY: LLM_CUSTOM_TF,
            "apps/api/main.py": "app = 1\n",
            "apps/worker/main.py": "app = 1\n",
        }
        self.reconcile(files=files, product_id="keyapp", spec_text="An api service and a worker service")
        self.assertIn('module "compute_worker"', files[CUSTOM_KEY])  # multi-service branch really ran
        for block in (RANDOM_ID_BLOCK, RANDOM_STRING_BLOCK, RANDOM_PASSWORD_BLOCK):
            self.assertIn(block, files[CUSTOM_KEY])
        self.assertEqual(_dangling_random_refs(files), [])


class TestGenerationPathKeepsRandomResources(unittest.TestCase):
    def test_generate_code_files_custom_tf_with_random_password_byte_identical(self):
        from developer_agent.handler import DeveloperAgent

        # Lane 19 L19-3b (owner row 27a): the deleted template fallback used to supply the app; a fake model does now.
        from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
        agent = DeveloperAgent()
        agent.genai_client = FakeGenaiClient(files=canned_workload_files("keyapp"))
        with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}), \
                patch.object(agent, "fetch_existing_repo_files", return_value={CUSTOM_KEY: RENDERED_CUSTOM_TF}):
            files = agent.generate_code_files(
                product_id="keyapp", spec_text="FastAPI service that issues API keys", task_dag=[], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False
            )
        # Byte-identical except trailing blank lines: the pipeline appends the root outputs to custom.tf and the
        # self_correct_hcl duplicate-output dedup then removes them, leaving newlines (pre-existing, not random-related).
        self.assertEqual(files[CUSTOM_KEY].rstrip("\n") + "\n", RENDERED_CUSTOM_TF)
        self.assertEqual(_dangling_random_refs(files), [])
        # FD-55 W4: the regex HCL pre-flight (preflight_validate_terraform) is deleted; V1b judges the tree


if __name__ == "__main__":
    unittest.main()
