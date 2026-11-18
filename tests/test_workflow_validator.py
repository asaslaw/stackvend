"""
Unit tests for Pre-Commit Pure-Python Workflow Validator and Single-Generator Architecture.
Verifies duplicate mapping key prevention, expression syntax integrity, schema requirements,
service account naming convention guards, and DeveloperAgent pre-commit hook integration.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock

# Ensure mocks for third-party libs if not installed in host environment
for m in [
    'httpx', 'fastapi', 'fastapi.responses', 'fastapi.staticfiles', 'google', 'google.genai',
    'google.genai.types', 'google.cloud', 'google.cloud.firestore',
    'google.cloud.storage', 'google.cloud.logging', 'google.cloud.pubsub_v1',
    'github', 'jwt', 'pydantic'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GATEWAY_PATH not in sys.path:
    sys.path.insert(0, GATEWAY_PATH)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from developer_agent.workflow_validator import (
    WorkflowValidationError,
    validate_github_workflow_yaml,
    validate_all_staged_workflows,
)
from developer_agent.handler import DeveloperAgent, generate_service_workflow


class TestWorkflowValidator(unittest.TestCase):

    def test_golden_workflows_pass(self):
        """Verify canonically generated workflows for all archetypes pass validation."""
        archetypes = ["cloudrun", "event-worker", "gce-bastion", "gke-autopilot"]
        for arch in archetypes:
            wf = generate_service_workflow(
                service_name="paymentservice",
                product_id="paymentservice",
                project_id="castor-paymentservice-abc123",
                project_number="123456789012",
                archetype=arch,
            )
            try:
                validate_github_workflow_yaml(wf, filename=f"deploy-{arch}.yml")
            except WorkflowValidationError as e:
                self.fail(f"Golden workflow for archetype '{arch}' failed validation: {e}")

    def test_detect_duplicate_key_in_top_level_env(self):
        """Verify duplicate mapping keys in top-level env: block are strictly caught."""
        broken_wf = """name: Test Deploy
on:
  push:
    branches: [main]
env:
  PROJECT_ID: castor-test
  SERVICE_NAME: test-service
  APP_NAME: test-service
  APP_NAME: test-service
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        with self.assertRaises(WorkflowValidationError) as ctx:
            validate_github_workflow_yaml(broken_wf, filename="deploy.yml")
        self.assertIn("Duplicate mapping key 'APP_NAME'", str(ctx.exception))

    def test_detect_duplicate_key_in_step_definition(self):
        """Verify duplicate mapping keys within a step definition are caught."""
        broken_wf = """name: Test Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Step 1
        uses: actions/checkout@v4
        uses: actions/checkout@v3
"""
        with self.assertRaises(WorkflowValidationError) as ctx:
            validate_github_workflow_yaml(broken_wf, filename="deploy.yml")
        self.assertIn("Duplicate mapping key 'uses'", str(ctx.exception))

    def test_sibling_steps_same_keys_allowed(self):
        """Verify identical keys in distinct sibling list items (- name: ...) are NOT treated as duplicates."""
        valid_wf = """name: Test Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Step 1
        uses: actions/checkout@v4
      - name: Step 2
        uses: google-github-actions/setup-gcloud@v2
"""
        try:
            validate_github_workflow_yaml(valid_wf, filename="deploy.yml")
        except WorkflowValidationError as e:
            self.fail(f"Valid sibling steps wrongly failed validation: {e}")

    def test_detect_corrupted_expression_context(self):
        """Verify illegal vars.env. and secrets.env. expressions are caught."""
        broken_wf = """name: Test Deploy
on:
  push:
    branches: [main]
env:
  PROJECT_ID: ${{ vars.env.PROJECT_ID || 'default' }}
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        with self.assertRaises(WorkflowValidationError) as ctx:
            validate_github_workflow_yaml(broken_wf, filename="deploy.yml")
        self.assertIn("Illegal context 'vars.env.'", str(ctx.exception))

    def test_detect_top_level_env_interpolation(self):
        """Verify illegal ${{ env.VAR }} inside top-level env: block is caught."""
        broken_wf = """name: Test Deploy
on:
  push:
    branches: [main]
env:
  SERVICE_NAME: myservice
  APP_NAME: ${{ env.SERVICE_NAME }}
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        with self.assertRaises(WorkflowValidationError) as ctx:
            validate_github_workflow_yaml(broken_wf, filename="deploy.yml")
        self.assertIn("GitHub Actions does not allow env context interpolation within the top-level env block", str(ctx.exception))

    def test_detect_unbalanced_expression_braces(self):
        """Verify unbalanced ${{ and }} are detected."""
        broken_wf = """name: Test Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Run
        run: echo ${{ secrets.MY_SECRET
"""
        with self.assertRaises(WorkflowValidationError) as ctx:
            validate_github_workflow_yaml(broken_wf, filename="deploy.yml")
        self.assertIn("Unbalanced GitHub Actions expression braces", str(ctx.exception))

    def test_detect_missing_required_top_level_keys(self):
        """Verify missing name:, on:, or jobs: is caught."""
        broken_wf = """name: Incomplete Workflow
env:
  PROJECT_ID: my-proj
"""
        with self.assertRaises(WorkflowValidationError) as ctx:
            validate_github_workflow_yaml(broken_wf, filename="deploy.yml")
        self.assertIn("Missing required top-level GitHub Actions keys", str(ctx.exception))

    def test_detect_legacy_service_account_format(self):
        """Verify non-canonical '<name>-sa@...' service account format is caught."""
        broken_wf = """name: Test Deploy
on:
  push:
    branches: [main]
env:
  GCP_WORKLOAD_SA: "${{ secrets.GCP_WORKLOAD_SA || 'castorcloudruntest-sa@castor-proj.iam.gserviceaccount.com' }}"
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        with self.assertRaises(WorkflowValidationError) as ctx:
            validate_github_workflow_yaml(broken_wf, filename="deploy.yml")
        self.assertIn("Non-canonical service account format", str(ctx.exception))

    def test_validate_all_staged_workflows_filters_correctly(self):
        """Verify validate_all_staged_workflows checks all workflows and ignores non-workflow files."""
        files = {
            "apps/svc/main.py": "print('hello')",
            "infra/workload/main.tf": "resource \"google_cloud_run_v2_service\" \"svc\" {}",
            ".github/workflows/deploy-svc.yml": generate_service_workflow("svc", "svc"),
            "README.md": "# Docs",
        }
        validated = validate_all_staged_workflows(files)
        self.assertEqual(validated, [".github/workflows/deploy-svc.yml"])

    def test_developer_agent_commit_and_open_pr_fast_fails_on_broken_workflow(self):
        """Verify DeveloperAgent.commit_and_open_pr() aborts with RuntimeError if workflow is invalid."""
        agent = DeveloperAgent()
        bad_files = {
            "apps/svc/main.py": "print('hello')",
            ".github/workflows/deploy-svc.yml": """name: Bad Workflow
on:
  push:
    branches: [main]
env:
  APP_NAME: svc
  APP_NAME: svc
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
        }
        with self.assertRaises(RuntimeError) as ctx:
            agent.commit_and_open_pr("svc", bad_files)
        self.assertIn("Workflow pre-commit validation failed", str(ctx.exception))
        self.assertIn("Duplicate mapping key 'APP_NAME'", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
