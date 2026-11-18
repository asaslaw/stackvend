"""
Unit Tests for Project Castor Universal VCS Gateway (`VCSProvider`)
Verifies provider factory resolution, GitHubProvider interface compliance,
dynamic pipeline contracts, and pre-deploy pipeline sanitization.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import unittest
from unittest.mock import MagicMock, patch

from shared.vcs_provider import (
    VCSProvider,
    VCSProviderFactory,
    RepositoryMetadata,
    PipelineConfig,
)
from shared.providers.github_provider import GitHubProvider
from shared.path_safety import UnsafePathError


class TestVCSProviderGateway(unittest.TestCase):
    def test_factory_resolves_default_github(self):
        with patch.dict(os.environ, {"GITHUB_ORG": "example-org"}, clear=True):
            provider = VCSProviderFactory.get_provider()
            self.assertIsInstance(provider, GitHubProvider)
            self.assertIsInstance(provider, VCSProvider)

    def test_factory_default_github_without_owner_fails_loudly(self):
        # FD-4AY: no built-in GitHub owner; an unconfigured GitHub install fails at provider construction.
        from shared.github_identity import GitHubOwnerNotConfiguredError
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(GitHubOwnerNotConfiguredError):
                VCSProviderFactory.get_provider()

    def test_factory_resolves_github_case_insensitive(self):
        provider = VCSProviderFactory.get_provider("github")
        self.assertIsInstance(provider, GitHubProvider)

        provider_upper = VCSProviderFactory.get_provider("GITHUB")
        self.assertIsInstance(provider_upper, GitHubProvider)

    def test_factory_unsupported_provider_raises_error(self):
        with self.assertRaises(ValueError) as ctx:
            VCSProviderFactory.get_provider("UNKNOWN_VCS")
        self.assertIn("Unsupported VCS provider", str(ctx.exception))

    def test_factory_resolves_serverless_git(self):
        from shared.providers.serverless_git_provider import ServerlessGitProvider
        provider = VCSProviderFactory.get_provider("SERVERLESS_GIT")
        self.assertIsInstance(provider, ServerlessGitProvider)
        self.assertIsInstance(provider, VCSProvider)

        provider_lower = VCSProviderFactory.get_provider("serverless_git")
        self.assertIsInstance(provider_lower, ServerlessGitProvider)

    def test_factory_resolves_from_governance_settings(self):
        from shared.providers.serverless_git_provider import ServerlessGitProvider
        from shared.settings import PlatformSettings

        mock_settings = PlatformSettings()
        mock_settings.governance.vcs_provider = "SERVERLESS_GIT"

        with patch("shared.settings.get_platform_settings", return_value=mock_settings):
            with patch.dict(os.environ, {}, clear=True):
                provider = VCSProviderFactory.get_provider()
                self.assertIsInstance(provider, ServerlessGitProvider)

    def test_factory_precedence_explicit_over_settings_over_env(self):
        from shared.providers.serverless_git_provider import ServerlessGitProvider
        from shared.settings import PlatformSettings

        mock_settings = PlatformSettings()
        mock_settings.governance.vcs_provider = "GITHUB"

        # Explicit parameter wins over settings and env
        with patch("shared.settings.get_platform_settings", return_value=mock_settings):
            with patch.dict(os.environ, {"VCS_PROVIDER": "GITHUB"}, clear=True):
                provider = VCSProviderFactory.get_provider("SERVERLESS_GIT")
                self.assertIsInstance(provider, ServerlessGitProvider)

        # Settings wins over env when explicit is None
        mock_settings.governance.vcs_provider = "SERVERLESS_GIT"
        with patch("shared.settings.get_platform_settings", return_value=mock_settings):
            with patch.dict(os.environ, {"VCS_PROVIDER": "GITHUB"}, clear=True):
                provider = VCSProviderFactory.get_provider(None)
                self.assertIsInstance(provider, ServerlessGitProvider)


    def test_factory_autodetects_serverless_git(self):
        from shared.providers.serverless_git_provider import ServerlessGitProvider
        from shared.settings import PlatformSettings

        mock_settings = PlatformSettings()
        mock_settings.governance.vcs_provider = "GITHUB"

        with patch("shared.settings.get_platform_settings", return_value=mock_settings):
            with patch.dict(os.environ, {}, clear=True):
                # Auto-detect from default_owner
                p1 = VCSProviderFactory.get_provider(default_owner="serverless-git")
                self.assertIsInstance(p1, ServerlessGitProvider)

                # Auto-detect from repo_name
                p2 = VCSProviderFactory.get_provider(repo_name="serverless-git/testingcr123")
                self.assertIsInstance(p2, ServerlessGitProvider)

                # Auto-detect from full_repo_name
                p3 = VCSProviderFactory.get_provider(full_repo_name="serverless-git/my-app.git")
                self.assertIsInstance(p3, ServerlessGitProvider)

    def test_github_metadata_resolution(self):
        provider = GitHubProvider(default_owner="AcmeOrg")
        meta = provider.get_repository_metadata("payment-service")
        self.assertEqual(meta.provider, "GITHUB")
        self.assertEqual(meta.repo_name, "payment-service")
        self.assertEqual(meta.full_name, "AcmeOrg/payment-service")
        self.assertEqual(meta.html_url, "https://github.com/AcmeOrg/payment-service")
        self.assertEqual(meta.clone_url_http, "https://github.com/AcmeOrg/payment-service.git")
        self.assertEqual(meta.ui_icon, "🐙")

    def test_get_authenticated_clone_url(self):
        provider = GitHubProvider(default_owner="AcmeOrg", github_token="ghp_test12345")
        clone_url = provider.get_authenticated_clone_url("payment-service")
        self.assertEqual(clone_url, "https://x-access-token:ghp_test12345@github.com/AcmeOrg/payment-service.git")

    def test_pipeline_contract_generation(self):
        provider = GitHubProvider()
        contract = provider.get_pipeline_contract("order-api", "order-system")
        self.assertEqual(contract.pipeline_type, "GITHUB_ACTIONS")
        self.assertEqual(contract.target_file, ".github/workflows/deploy-order-api.yml")
        self.assertIn("Workload Identity Federation", contract.template_content)
        self.assertIn("deploy-order-api.yml", contract.target_file)

    def test_sanitize_pipeline_content_is_deleted(self):
        # FD-55 W1 (FD55-W1): HB-44 had no production caller (abstract method + both implementations, every copy);
        # tests/test_fd55_w1_dead_code.py pins its absence from all seven shared copies.
        provider = GitHubProvider(project_id="test-proj")
        self.assertFalse(hasattr(provider, "sanitize_pipeline_content"))
        self.assertNotIn("sanitize_pipeline_content", VCSProvider.__abstractmethods__)

    @patch.object(GitHubProvider, "get_client")
    def test_mocked_vend_repository_success(self, mock_client):
        gh_mock = MagicMock()
        mock_client.return_value = gh_mock
        repo_mock = MagicMock()
        repo_mock.full_name = "AcmeOrg/castor-newapp"
        repo_mock.html_url = "https://github.com/AcmeOrg/castor-newapp"
        repo_mock.clone_url = "https://github.com/AcmeOrg/castor-newapp.git"
        repo_mock.ssh_url = "git@github.com:AcmeOrg/castor-newapp.git"
        repo_mock.default_branch = "main"

        org_mock = MagicMock()
        org_mock.create_repo.return_value = repo_mock
        gh_mock.get_repo.side_effect = Exception("Not found")
        gh_mock.get_organization.return_value = org_mock

        provider = GitHubProvider(default_owner="AcmeOrg", github_token="fake-token")
        meta = provider.vend_repository("newapp")

        self.assertEqual(meta.provider, "GITHUB")
        self.assertEqual(meta.full_name, "AcmeOrg/castor-newapp")
        self.assertEqual(meta.is_reused, False)
        self.assertEqual(meta.ui_icon, "🐙")

    # FD-05 B-13 / B-14: commit_files is git CLI -> Dulwich -> RuntimeError. The PyGithub REST create_git_tree path
    # (and its GitRPC retry) was removed on purpose in 285d275 ("Never fall back to broken REST create_git_tree API").
    # The old tests mocked that REST path and so ran a REAL git clone + Dulwich fetch of github.com.
    def _commit(self, provider):
        return provider.commit_files(
            repo_identifier="my-repo",
            branch="main",
            files={"main.py": "print('hello')"},
            commit_message="feat: initial commit",
        )

    @patch.object(GitHubProvider, "_get_repo")
    def test_mocked_commit_files(self, mock_get_repo):
        """git CLI available: its SHA is returned; Dulwich and the REST API are never touched."""
        provider = GitHubProvider(default_owner="AcmeOrg", github_token="fake-token")
        with patch("shared.providers.github_provider.shutil.which", return_value="/usr/bin/git"), \
                patch.object(GitHubProvider, "_commit_files_via_git_cli", return_value="commit789abc") as cli, \
                patch.object(GitHubProvider, "_commit_files_via_dulwich") as dul:
            sha = self._commit(provider)
        self.assertEqual(sha, "commit789abc")
        cli.assert_called_once()
        self.assertEqual(cli.call_args.kwargs["files"], {"main.py": "print('hello')"})
        dul.assert_not_called()
        mock_get_repo.assert_not_called()

    @patch.object(GitHubProvider, "_get_repo")
    def test_commit_files_falls_back_to_dulwich_then_fails_closed(self, mock_get_repo):
        """git CLI fails -> Dulwich; Dulwich fails -> RuntimeError. Never the REST create_git_tree API."""
        provider = GitHubProvider(default_owner="AcmeOrg", github_token="fake-token")
        with patch("shared.providers.github_provider.shutil.which", return_value="/usr/bin/git"), \
                patch.object(GitHubProvider, "_commit_files_via_git_cli", side_effect=RuntimeError("cli down")), \
                patch.object(GitHubProvider, "_commit_files_via_dulwich", return_value="dulwich-sha") as dul:
            self.assertEqual(self._commit(provider), "dulwich-sha")
            dul.assert_called_once()

        with patch("shared.providers.github_provider.shutil.which", return_value=None), \
                patch.object(GitHubProvider, "_commit_files_via_dulwich", side_effect=RuntimeError("dulwich down")):
            with self.assertRaises(RuntimeError):
                self._commit(provider)

        with patch("shared.providers.github_provider.shutil.which", return_value=None), \
                patch("shared.providers.github_provider.DULWICH_AVAILABLE", False):
            with self.assertRaises(RuntimeError) as ctx:
                self._commit(provider)
            self.assertIn("No Git engine available", str(ctx.exception))

        mock_get_repo.assert_not_called()  # the REST tree/commit API is never used, on any path

    @patch("subprocess.run")
    def test_native_git_commit_files_success(self, mock_subproc):
        def fake_run(cmd, *args, **kwargs):
            m = MagicMock()
            m.returncode = 0
            if "status" in cmd:
                m.stdout = " M main.py\n"
            elif "rev-parse" in cmd:
                m.stdout = "cli_commit_sha_12345\n"
            else:
                m.stdout = ""
            m.stderr = ""
            return m

        mock_subproc.side_effect = fake_run

        provider = GitHubProvider(default_owner="AcmeOrg", github_token="fake-token")
        sha = provider._commit_files_via_git_cli(
            repo_identifier="my-repo",
            branch="feature/my-branch",
            files={"main.py": "print('hello from cli')"},
            commit_message="feat: native git commit",
        )
        self.assertEqual(sha, "cli_commit_sha_12345")
        # RT14-10: the auth header reaches git through the child environment only, never the argv.
        clone_calls = [call for call in mock_subproc.call_args_list if "clone" in call[0][0]]
        self.assertTrue(len(clone_calls) > 0)
        clone_cmd = clone_calls[0][0][0]
        self.assertFalse(any("Authorization" in str(arg) for arg in clone_cmd))
        self.assertFalse(any("fake-token" in str(arg) for arg in clone_cmd))
        clone_env = clone_calls[0][1]["env"]
        count = int(clone_env["GIT_CONFIG_COUNT"])
        header_slots = [i for i in range(count) if clone_env.get(f"GIT_CONFIG_KEY_{i}") == "http.extraHeader"]
        self.assertEqual(len(header_slots), 1)
        self.assertTrue(clone_env[f"GIT_CONFIG_VALUE_{header_slots[0]}"].startswith("Authorization: Basic "))
        # Ensure no token in the clone URL itself
        self.assertTrue(clone_cmd[-2].startswith("https://github.com/"))
        self.assertNotIn("fake-token", clone_cmd[-2])

    @patch("subprocess.run")
    def test_native_git_clean_working_tree(self, mock_subproc):
        def fake_run(cmd, *args, **kwargs):
            m = MagicMock()
            m.returncode = 0
            if "status" in cmd:
                m.stdout = ""  # Clean working tree
            elif "rev-parse" in cmd:
                m.stdout = "existing_head_sha_999\n"
            else:
                m.stdout = ""
            m.stderr = ""
            return m

        mock_subproc.side_effect = fake_run

        provider = GitHubProvider(default_owner="AcmeOrg", github_token="fake-token")
        sha = provider._commit_files_via_git_cli(
            repo_identifier="my-repo",
            branch="feature/my-branch",
            files={"main.py": "print('already identical')"},
            commit_message="feat: identical",
        )
        self.assertEqual(sha, "existing_head_sha_999")
        # Ensure git commit was NOT called because working tree was clean
        commit_calls = [call for call in mock_subproc.call_args_list if "commit" in call[0][0]]
        self.assertEqual(len(commit_calls), 0)

    @patch("subprocess.run")
    def test_native_git_path_traversal_rejection(self, mock_subproc):
        m = MagicMock()
        m.returncode = 0
        m.stdout = ""
        mock_subproc.return_value = m

        provider = GitHubProvider(default_owner="AcmeOrg", github_token="fake-token")
        with self.assertRaises(UnsafePathError):  # FD-4G: typed rejection (was PermissionError)
            provider._commit_files_via_git_cli(
                repo_identifier="my-repo",
                branch="feature/my-branch",
                files={"../../etc/passwd": "malicious content"},
                commit_message="feat: exploit",
            )


if __name__ == "__main__":
    unittest.main()
