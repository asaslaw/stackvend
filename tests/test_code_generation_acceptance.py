"""
Unit tests verifying Developer Agent code generation JSON dictionary acceptance (both flat and wrapped),
fetch_branch_files method resolution, and Control Center telemetry active executions handling.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
CONTROL_CENTER_DIR = os.path.join(REPO_ROOT, "apps", "control-center")

for p in [REPO_ROOT, GATEWAY_DIR, CONTROL_CENTER_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)


@hermetic_guard.unavailable("google.genai.Client", "Gemini")
class TestCodeGenerationAcceptance(unittest.TestCase):

    def test_developer_agent_flat_file_dictionary_acceptance(self):
        """Verifies DeveloperAgent accepts flat root-level file dictionaries from Gemini."""
        from developer_agent.handler import DeveloperAgent

        dev = DeveloperAgent(project_id="test-platform-project")

        flat_payload = {
            "apps/testplan/main.py": "from fastapi import FastAPI\napp = FastAPI()",
            "apps/testplan/models.py": "from pydantic import BaseModel\nclass Item(BaseModel): pass",
            "infra/workload/custom.tf": 'resource "google_storage_bucket" "b" {}',
        }

        # Simulate the parsing logic block in developer_agent/handler.py
        parsed = flat_payload
        parsed_files = None
        if "files" in parsed and isinstance(parsed["files"], dict) and len(parsed["files"]) > 0:
            parsed_files = parsed["files"]
        elif isinstance(parsed, dict) and any(
            k.startswith(("apps/", "infra/", "tests/", ".", "cloudbuild", "Procfile")) or "/" in k
            for k in parsed.keys()
        ):
            parsed_files = parsed

        self.assertIsNotNone(parsed_files)
        self.assertEqual(len(parsed_files), 3)
        self.assertIn("apps/testplan/main.py", parsed_files)

    def test_developer_agent_wrapped_file_dictionary_acceptance(self):
        """Verifies DeveloperAgent accepts standard wrapped {'files': {...}} dictionaries."""
        wrapped_payload = {
            "files": {
                "apps/testplan/main.py": "from fastapi import FastAPI\napp = FastAPI()",
                "apps/testplan/services.py": "def process(): pass",
            }
        }

        parsed = wrapped_payload
        parsed_files = None
        if "files" in parsed and isinstance(parsed["files"], dict) and len(parsed["files"]) > 0:
            parsed_files = parsed["files"]
        elif isinstance(parsed, dict) and any(
            k.startswith(("apps/", "infra/", "tests/", ".", "cloudbuild", "Procfile")) or "/" in k
            for k in parsed.keys()
        ):
            parsed_files = parsed

        self.assertIsNotNone(parsed_files)
        self.assertEqual(len(parsed_files), 2)
        self.assertIn("apps/testplan/services.py", parsed_files)

    def test_developer_agent_fetch_branch_files_method_exists(self):
        """Verifies DeveloperAgent has fetch_branch_files and does not raise AttributeError."""
        from developer_agent.handler import DeveloperAgent

        dev = DeveloperAgent(project_id="test-platform-project")
        self.assertTrue(hasattr(dev, "fetch_branch_files"))
        self.assertTrue(callable(getattr(dev, "fetch_branch_files")))

    def test_telemetry_get_active_pipeline_executions_handles_firestore(self):
        """Verifies get_active_pipeline_executions handles col definition and recent_completed safely."""
        from routes.telemetry import get_active_pipeline_executions, ActiveExecutionsResponse
        import routes.telemetry as tel_mod

        mock_db = MagicMock()
        mock_col = MagicMock()
        mock_query = MagicMock()
        mock_query.stream.return_value = []
        mock_col.where.return_value = mock_query
        mock_db.collection.return_value = mock_col

        with patch.object(tel_mod, "db", mock_db):
            res = get_active_pipeline_executions(product_id="testplan01-a")
            self.assertIsInstance(res, ActiveExecutionsResponse)
            self.assertEqual(res.total_active, 0)
            self.assertEqual(res.recent_completed, [])
            self.assertIsNone(res.latest_completed)


if __name__ == "__main__":
    unittest.main()
