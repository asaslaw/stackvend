"""
Test Human Architect Terraform Extensibility & Overrides
Verifies that:
1. Initial scaffolding creates baseline infra/workload/human.tf, human_override.tf, and infra/workload/README.md.
2. The Developer Agent strictly preserves human edits in human.tf, human_override.tf, and custom .tf files across automated builds.
3. The Developer Agent regenerates main.tf from golden templates to maintain platform governance.
4. Preflight in-memory validation and AST verification succeed with human extension files present.
5. TerraformService stages human.tf and human_override.tf into the deployment workspace.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure mocks for third-party libs if not installed in host environment
for m in [
    'httpx', 'fastapi', 'fastapi.responses', 'google', 'google.genai',
    'google.genai.types', 'google.cloud', 'google.cloud.firestore',
    'google.cloud.storage', 'google.cloud.logging', 'google.cloud.pubsub_v1',
    'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

OG_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if OG_DIR not in sys.path:
    sys.path.insert(0, OG_DIR)

TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
if TF_DIR not in sys.path:
    sys.path.insert(0, TF_DIR)

from developer_agent.handler import DeveloperAgent
from developer_agent.terraform_engine import (
    generate_human_override_tf_template,
    generate_human_tf_template,
    generate_infra_readme,
)


class TestHumanTerraformExtensibility(unittest.TestCase):

    def setUp(self):
        # Lane 19 L19-3b (owner register row 27a): no template / swarm stubs without an LLM. A fake model returns
        # a small canned workload through the single-turn LLM seam; the assertions are unchanged.
        from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
        env = patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"})
        env.start()
        self.addCleanup(env.stop)
        self.agent = DeveloperAgent()
        self.agent.genai_client = FakeGenaiClient(files=canned_workload_files("my-portal"))

    def _generate(self, product_id, spec_text):
        with patch.object(self.agent, "fetch_existing_repo_files", return_value={}):
            return self.agent.generate_code_files(product_id=product_id, spec_text=spec_text, task_dag=[], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)

    def test_scaffold_creates_human_extension_files(self):
        """Verifies initial scaffolding generates human.tf, human_override.tf, and README.md."""
        scaffold = self._generate("my-portal", "Deploy an internal web portal")

        self.assertIn("infra/workload/human.tf", scaffold)
        self.assertIn("infra/workload/human_override.tf", scaffold)
        self.assertIn("infra/workload/README.md", scaffold)
        self.assertIn("StackVend: Human Architect & Custom Infrastructure Additions", scaffold["infra/workload/human.tf"])
        self.assertIn("StackVend: Human Architect Configuration Overrides", scaffold["infra/workload/human_override.tf"])
        self.assertIn("Governance Model: Paved Road vs. Human Extensions", scaffold["infra/workload/README.md"])

    def test_foundation_only_scaffold_creates_human_extension_files(self):
        """Verifies foundation-only workloads also generate human.tf, human_override.tf, and README.md."""
        scaffold = self._generate("empty-shell", "Create an empty project with APIs only, no compute")

        self.assertIn("infra/workload/human.tf", scaffold)
        self.assertIn("infra/workload/human_override.tf", scaffold)
        self.assertIn("infra/workload/README.md", scaffold)
        self.assertNotIn("apps/empty-shell/main.py", scaffold)

    @patch.object(DeveloperAgent, "fetch_existing_repo_files")
    def test_generate_code_files_preserves_human_tf_edits(self, mock_fetch):
        """Verifies that human additions to human.tf are strictly preserved across automated builds."""
        human_content = """# Custom Human Storage Bucket
resource "google_storage_bucket" "human_bucket" {
  name                        = "${var.product_id}-custom-bucket"
  location                    = var.region
  uniform_bucket_level_access = true
}
"""
        mock_fetch.return_value = {
            "infra/workload/human.tf": human_content,
            "infra/workload/main.tf": "# Old main.tf that should be replaced by golden main.tf",
        }

        files = self.agent.generate_code_files(
            product_id="testapp",
            spec_text="Add a feature to existing workload",
            task_dag=[], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False
        )

        # human.tf MUST match the human's custom code verbatim
        self.assertIn("infra/workload/human.tf", files)
        self.assertEqual(files["infra/workload/human.tf"], human_content)
        # main.tf MUST be regenerated by Castor's golden engine
        self.assertIn("infra/workload/main.tf", files)
        self.assertIn('module "foundation"', files["infra/workload/main.tf"])
        self.assertNotIn("Old main.tf that should be replaced", files["infra/workload/main.tf"])

    def test_llm_draft_at_human_names_never_reaches_the_tree(self):
        """FD-4AW-a F2: human.tf / human_override.tf come only from the repository's existing files; an LLM draft at
        those keys (here with a local-exec provisioner) is replaced by the template, never kept."""
        from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
        evil = ('resource "terraform_data" "x" {\n  provisioner "local-exec" {\n    command = "id"\n  }\n}\n')
        draft = dict(canned_workload_files("my-portal"))
        draft["infra/workload/human.tf"] = evil
        draft["infra/workload/human_override.tf"] = evil
        self.agent.genai_client = FakeGenaiClient(files=draft)
        files = self._generate("my-portal", "A portal")
        self.assertEqual(files["infra/workload/human.tf"], generate_human_tf_template())
        self.assertEqual(files["infra/workload/human_override.tf"], generate_human_override_tf_template())

    @patch.object(DeveloperAgent, "fetch_existing_repo_files")
    def test_generate_code_files_preserves_human_override_tf_edits(self, mock_fetch):
        """Verifies that human overrides in human_override.tf are preserved across builds."""
        override_content = """# Override Cloud Run min instances
module "compute" {
  min_instance_count = 5
  timeout_seconds    = 900
}
"""
        mock_fetch.return_value = {
            "infra/workload/human_override.tf": override_content,
        }

        files = self.agent.generate_code_files(
            product_id="testapp",
            spec_text="Deploy upgrade",
            task_dag=[], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False
        )

        self.assertIn("infra/workload/human_override.tf", files)
        self.assertEqual(files["infra/workload/human_override.tf"], override_content)

    @patch.object(DeveloperAgent, "fetch_existing_repo_files")
    def test_generate_code_files_preserves_arbitrary_custom_tf_files(self, mock_fetch):
        """Verifies that arbitrary human files like database.tf or storage.tf are preserved."""
        db_tf_content = """resource "google_sql_database_instance" "master" {
  name             = "master-instance"
  database_version = "POSTGRES_15"
}
"""
        mock_fetch.return_value = {
            "infra/workload/database.tf": db_tf_content,
        }

        files = self.agent.generate_code_files(
            product_id="testapp",
            spec_text="Add microservice route",
            task_dag=[], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False
        )

        # Step 1 S1-A (register HS-08): pre-existing auxiliary files like database.tf are kept byte-identical in
        # place (never purged, never copied into custom.tf)
        self.assertEqual(files.get("infra/workload/database.tf"), db_tf_content)
        self.assertNotIn("google_sql_database_instance", files.get("infra/workload/custom.tf", ""))


    def test_terraform_service_stages_human_files(self):
        """Verifies TerraformService prepares human.tf and human_override.tf in the workspace."""
        from service import TerraformService

        service = TerraformService(project_id="test-proj")
        mock_files = {
            "main.tf": 'module "foundation" {}',
            "human.tf": 'resource "google_storage_bucket" "b" {}',
            "human_override.tf": 'module "compute" { min_instances = 3 }',
            "infra/workload/README.md": '# Docs',
        }

        workspace_dir = service.prepare_workspace(
            product_id="testapp",
            trace_id="test-trace-human-123",
            hcl_files=mock_files,
        )
        try:
            self.assertTrue(os.path.exists(os.path.join(workspace_dir, "human.tf")))
            self.assertTrue(os.path.exists(os.path.join(workspace_dir, "human_override.tf")))
            with open(os.path.join(workspace_dir, "human.tf")) as f:
                content = f.read()
                self.assertIn("google_storage_bucket", content)
            with open(os.path.join(workspace_dir, "human_override.tf")) as f:
                content = f.read()
                self.assertIn("min_instances = 3", content)
        finally:
            import shutil
            if os.path.exists(workspace_dir):
                shutil.rmtree(workspace_dir)

    def test_terraform_service_does_not_mutate_human_override_tf_or_comments(self):
        """Verifies TerraformService never injects deletion_protection into human_override.tf or commented blocks."""
        from service import TerraformService

        service = TerraformService(project_id="test-proj")
        mock_files = {
            "main.tf": 'resource "google_cloud_run_v2_service" "app" {\n  name = "app"\n}',
            "human_override.tf": generate_human_override_tf_template(),
        }

        workspace_dir = service.prepare_workspace(
            product_id="testapp",
            trace_id="test-trace-human-override-comment-check",
            hcl_files=mock_files,
        )
        try:
            # FD-55 W6a (register FD55-W6a, A5): main.tf is written as committed (no deletion_protection injection)
            with open(os.path.join(workspace_dir, "main.tf")) as f:
                main_content = f.read()
                self.assertEqual(main_content, mock_files["main.tf"])

            # Check human_override.tf was NOT mutated with top-level bare deletion_protection = false
            with open(os.path.join(workspace_dir, "human_override.tf")) as f:
                override_content = f.read()
                # Must not have an uncommented deletion_protection line
                for line in override_content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("deletion_protection"):
                        self.fail(f"Found illegal uncommented deletion_protection line in human_override.tf: {line}")
        finally:
            import shutil
            if os.path.exists(workspace_dir):
                shutil.rmtree(workspace_dir)


if __name__ == "__main__":
    unittest.main()
