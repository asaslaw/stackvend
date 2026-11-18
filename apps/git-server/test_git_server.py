"""
Unit Tests for Serverless Git Microservice (`apps/git-server/main.py`)
Tests bare repo initialization, Smart HTTP proxying, branch creation,
atomic commits, tree fetches, archive exports, and server-side squash merges.
"""

import os
import shutil
import tempfile
import unittest
from fastapi.testclient import TestClient

# Configure test data directory before importing app
_test_tmp_dir = tempfile.mkdtemp(prefix="castor_git_test_")
os.environ["GIT_DATA_DIR"] = _test_tmp_dir

import sys
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import main  # noqa: E402
from main import app, GIT_DATA_DIR  # noqa: E402


class _TestAuthenticator:
    """FD-4K: real token verification is covered by tests/test_fd4k_git_server_auth.py; this app-local suite only
    exercises the git engine, so the caller identity is fixed."""

    def authenticate(self, authorization_headers, *, read_route=False):   # FD-7L Phase 4 keyword
        return "app-local-test@example.iam.gserviceaccount.com"

    def config(self):
        return frozenset(), frozenset()


class TestServerlessGitMicroservice(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.authenticator = _TestAuthenticator()
        cls.client = TestClient(app)
        cls.product_id = "test-order-service"

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(_test_tmp_dir):
            shutil.rmtree(_test_tmp_dir, ignore_errors=True)

    def test_01_health_check(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["service"], "castor-git-server")

    def test_02_vend_repository(self):
        res = self.client.post("/api/v1/repos", json={
            "product_id": self.product_id,
            "description": "Test order processing microservice",
            "initial_branch": "main",
        })
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["status"], "CREATED")
        self.assertEqual(data["product_id"], self.product_id)
        self.assertIn("initial_commit", data)

        # Verify idempotency
        res_dup = self.client.post("/api/v1/repos", json={"product_id": self.product_id})
        self.assertEqual(res_dup.status_code, 201)
        self.assertEqual(res_dup.json()["status"], "EXISTS")

    def test_03_get_metadata_and_fetch_tree(self):
        res = self.client.get(f"/api/v1/repos/{self.product_id}/metadata")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["default_branch"], "main")
        self.assertIn("main", data["branches"])

        # Fetch initial tree
        tree_res = self.client.get(f"/api/v1/repos/{self.product_id}/tree/main")
        self.assertEqual(tree_res.status_code, 200)
        tree_data = tree_res.json()
        self.assertIn("README.md", tree_data["files"])
        self.assertIn(".gitignore", tree_data["files"])
        self.assertIn("Test order processing", tree_data["files"]["README.md"])

    def test_04_create_branch(self):
        res = self.client.post(f"/api/v1/repos/{self.product_id}/branches", json={
            "branch_name": "stage",
            "source_branch": "main",
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["branch"], "stage")
        self.assertEqual(data["status"], "CREATED")

    def test_05_atomic_programmatic_commit(self):
        files_to_commit = {
            "app.py": "print('Hello Serverless Git')\n",
            "config/settings.json": '{"env": "stage", "active": true}\n',
            "README.md": "# test-order-service\nUpdated documentation.\n",
        }
        res = self.client.post(f"/api/v1/repos/{self.product_id}/commits", json={
            "branch": "stage",
            "files": files_to_commit,
            "commit_message": "feat: add app code and configuration",
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "COMMITTED")
        self.assertEqual(data["branch"], "stage")

        # Fetch updated blob
        blob_res = self.client.get(f"/api/v1/repos/{self.product_id}/blob/stage/app.py")
        self.assertEqual(blob_res.status_code, 200)
        self.assertIn("Hello Serverless Git", blob_res.json()["content"])

        # Fetch entire tree
        tree_res = self.client.get(f"/api/v1/repos/{self.product_id}/tree/stage")
        self.assertEqual(tree_res.status_code, 200)
        tree_data = tree_res.json()
        self.assertIn("app.py", tree_data["files"])
        self.assertIn("config/settings.json", tree_data["files"])
        self.assertIn("Updated documentation", tree_data["files"]["README.md"])

    def test_06_server_side_squash_merge(self):
        # Merge stage into main
        res = self.client.post(f"/api/v1/repos/{self.product_id}/merge", json={
            "source_branch": "stage",
            "target_branch": "main",
            "commit_message": "release: merge stage into main",
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "MERGED")
        self.assertEqual(data["target_branch"], "main")

        # Verify main branch now contains the new files
        main_tree = self.client.get(f"/api/v1/repos/{self.product_id}/tree/main").json()
        self.assertIn("app.py", main_tree["files"])
        self.assertIn("config/settings.json", main_tree["files"])

    def test_07_export_archive(self):
        res = self.client.get(f"/api/v1/repos/{self.product_id}/archive/main")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["content-type"], "application/gzip")
        self.assertGreater(len(res.content), 0)


if __name__ == "__main__":
    unittest.main()
