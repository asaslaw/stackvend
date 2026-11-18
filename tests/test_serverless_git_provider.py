"""
Unit Tests for Serverless Git Provider (`shared/providers/serverless_git_provider.py`)
Verifies contract compliance with VCSProvider, metadata generation, authenticated clone URLs,
synthetic Pull Request lifecycle, Cloud Build pipeline contracts, and mock REST interactions.
"""

import io
import os
import unittest
from unittest.mock import MagicMock, patch

from shared.vcs_provider import (
    VCSProvider,
    VCSProviderFactory,
    RepositoryMetadata,
    PipelineConfig,
)
from shared.providers.serverless_git_provider import ServerlessGitProvider


class TestServerlessGitProvider(unittest.TestCase):
    def setUp(self):
        self.provider = ServerlessGitProvider(
            server_url="https://git.example.com",
            project_id="test-castor-project",
            auth_token="test-oauth-token",
        )

    def test_01_initialization_defaults(self):
        # FD-4K (Q11): no guessed hostname. Construction never fails; the first network call raises a config error.
        from shared.providers.serverless_git_provider import ServerlessGitConfigError

        env = {k: v for k, v in os.environ.items()
               if k not in ("GIT_SERVER_URL", "CASTOR_GIT_SERVER_URL", "REGION", "DEFAULT_REGION")}
        with patch.dict(os.environ, env, clear=True), \
                patch("shared.settings.get_platform_settings", side_effect=RuntimeError("no settings")):
            provider = ServerlessGitProvider(project_id="my-gcp-proj")
            self.assertIsNone(provider.server_url)
            with self.assertRaises(ServerlessGitConfigError):
                provider.fetch_file_tree("inventory-api")
            # Local docker-compose default only when no project is known at all.
            env.pop("PROJECT_ID", None)
            env.pop("GOOGLE_CLOUD_PROJECT", None)
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(ServerlessGitProvider(project_id="").server_url, "http://castor-git-server:8080")

    @patch("shared.providers.serverless_git_provider.requests")
    def test_02_metadata_generation(self, mock_requests):
        mock_res = MagicMock()
        mock_res.status_code = 200
        mock_res.json.return_value = {"default_branch": "main"}
        mock_requests.get.return_value = mock_res
        meta = self.provider.get_repository_metadata("inventory-api")
        self.assertIsInstance(meta, RepositoryMetadata)
        self.assertEqual(meta.provider, "SERVERLESS_GIT")
        self.assertEqual(meta.repo_name, "inventory-api")
        self.assertEqual(meta.full_name, "castor/inventory-api")
        self.assertEqual(meta.clone_url_http, "https://git.example.com/git/inventory-api.git")
        self.assertEqual(meta.ui_icon, "☁️")
        self.assertEqual(meta.default_branch, "main")

    def test_03_authenticated_clone_url_generation(self):
        # Embeds oauth2 token into clone URL for automated runners
        clone_url = self.provider.get_authenticated_clone_url("inventory-api")
        self.assertEqual(
            clone_url,
            "https://oauth2:test-oauth-token@git.example.com/git/inventory-api.git",
        )

        # Fallback when no token is present
        unauth_provider = ServerlessGitProvider(
            server_url="https://git.example.com",
            project_id="test-proj",
            auth_token=None,
        )
        with patch.object(unauth_provider, "_resolve_iam_token", return_value=None):
            plain_clone = unauth_provider.get_authenticated_clone_url("inventory-api")
            self.assertEqual(plain_clone, "https://git.example.com/git/inventory-api.git")

    @patch("shared.providers.serverless_git_provider.requests")
    def test_04_vend_repository_mocked_api(self, mock_requests):
        mock_res = MagicMock()
        mock_res.status_code = 201
        mock_res.json.return_value = {
            "status": "CREATED",
            "product_id": "payment-api",
            "clone_url": "/git/payment-api.git",
            "default_branch": "main",
        }
        mock_requests.post.return_value = mock_res

        meta = self.provider.vend_repository("payment-api", description="Payments")
        self.assertEqual(meta.provider, "SERVERLESS_GIT")
        self.assertEqual(meta.repo_name, "payment-api")
        self.assertEqual(meta.clone_url_http, "https://git.example.com/git/payment-api.git")
        self.assertEqual(meta.ui_icon, "☁️")

        # Verify API request
        mock_requests.post.assert_called_once()
        call_url = mock_requests.post.call_args[0][0]
        self.assertEqual(call_url, "https://git.example.com/api/v1/repos")

    @patch("shared.providers.serverless_git_provider.requests")
    def test_05_fetch_file_tree_and_blob_mocked_api(self, mock_requests):
        # 1. Fetch Tree
        mock_tree_res = MagicMock()
        mock_tree_res.status_code = 200
        mock_tree_res.json.return_value = {
            "files": {
                "main.py": "print('hello')",
                "Procfile": "web: uvicorn main:app",
            }
        }
        mock_requests.get.return_value = mock_tree_res

        tree = self.provider.fetch_file_tree("payment-api", branch="stage")
        self.assertEqual(len(tree), 2)
        self.assertIn("main.py", tree)
        self.assertEqual(tree["main.py"], "print('hello')")

        # 2. Fetch Blob
        mock_blob_res = MagicMock()
        mock_blob_res.status_code = 200
        mock_blob_res.json.return_value = {"content": "print('hello')"}
        mock_requests.get.return_value = mock_blob_res

        content = self.provider.fetch_file_content("payment-api", "main.py", branch="main")
        self.assertEqual(content, "print('hello')")

    @patch("shared.providers.serverless_git_provider.requests")
    def test_06_commit_and_archive_mocked_api(self, mock_requests):
        # 1. Programmatic commit
        mock_commit_res = MagicMock()
        mock_commit_res.status_code = 200
        mock_commit_res.json.return_value = {"commit_sha": "a1b2c3d4e5f6"}
        mock_requests.post.return_value = mock_commit_res

        sha = self.provider.commit_files(
            repo_identifier="payment-api",
            branch="dev",
            files={"test.txt": "sample data"},
            commit_message="feat: add test file",
        )
        self.assertEqual(sha, "a1b2c3d4e5f6")

        # 2. Export archive
        mock_archive_res = MagicMock()
        mock_archive_res.status_code = 200
        mock_archive_res.content = b"\x1f\x8b\x08\x00fake_tarball_data"
        mock_requests.get.return_value = mock_archive_res

        stream = self.provider.export_archive_stream("payment-api", branch="main")
        self.assertIsInstance(stream, io.BytesIO)
        self.assertEqual(stream.read(), b"\x1f\x8b\x08\x00fake_tarball_data")

    def test_07_synthetic_pull_request_contract(self):
        # Verifies zero-database synthetic PR reference URL
        pr = self.provider.create_pull_request(
            repo_identifier="payment-api",
            title="Automated feature branch",
            body="PR body",
            head_branch="feature/payment-v2",
            base_branch="main",
        )
        self.assertEqual(pr["status"], "OPEN")
        self.assertEqual(pr["head_branch"], "feature/payment-v2")
        self.assertEqual(pr["base_branch"], "main")
        self.assertIn("https://git.example.com/git/payment-api.git/refs/heads/feature/payment-v2", pr["pull_request_url"])

    @patch("shared.providers.serverless_git_provider.requests")
    def test_08_merge_pull_request_mocked_api(self, mock_requests):
        mock_merge_res = MagicMock()
        mock_merge_res.status_code = 200
        mock_merge_res.json.return_value = {
            "status": "MERGED",
            "commit_sha": "merge_commit_sha_123",
            "target_branch": "main",
        }
        mock_requests.post.return_value = mock_merge_res

        merge_res = self.provider.merge_pull_request("payment-api", pr_number=1)
        self.assertEqual(merge_res["status"], "MERGED")
        self.assertTrue(merge_res["merged"])
        self.assertEqual(merge_res["commit_sha"], "merge_commit_sha_123")

    def test_09_cloudbuild_pipeline_contract_and_sanitization(self):
        contract = self.provider.get_pipeline_contract("order-service", "orders")
        self.assertEqual(contract.pipeline_type, "CLOUD_BUILD")
        self.assertEqual(contract.target_file, "cloudbuild.yaml")
        self.assertIn("steps:", contract.template_content)
        self.assertIn("buildpack-compile", contract.template_content)

        # Validation passes on valid pipeline
        self.provider.validate_pipeline_content("cloudbuild.yaml", contract.template_content)

        # Validation catches missing steps
        with self.assertRaises(ValueError):
            self.provider.validate_pipeline_content("cloudbuild.yaml", "invalid: true\n")

        # FD-55 W1 (FD55-W1): sanitize_pipeline_content (HB-44, no production caller) is deleted from every provider
        self.assertFalse(hasattr(self.provider, "sanitize_pipeline_content"))


if __name__ == "__main__":
    unittest.main()
