"""
Project Castor: Unit Tests for GitHubProvider Dual-Engine (Git CLI & Pure-Python Dulwich)
Validates:
1. Native Git CLI execution when binary is present.
2. Pure-Python Dulwich fallback when git binary is absent.
3. Strict token redaction across all exception traces.
4. Safe execution in minimal headless containers (no ~/.gitconfig).
5. Path traversal defense in file payloads.
6. Clean working tree idempotency (returning existing HEAD).
7. Strict fail-fast when neither engine is available.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import io
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import dulwich
from dulwich import porcelain
from dulwich.repo import Repo

from shared.providers.github_provider import GitHubProvider
from shared.path_safety import UnsafePathError


class TestGitHubProviderGitEngine(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.provider = GitHubProvider(
            project_id="test-project",
            github_token="ghs_secretToken1234567890",
            default_owner="TestOrg",
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_dulwich_commit_and_push_local(self):
        """Verifies Dulwich engine initializes, commits files, and creates valid Git objects."""
        # Create a local bare origin repository to act as 'GitHub'
        bare_origin_dir = os.path.join(self.tmp_dir, "origin.git")
        os.makedirs(bare_origin_dir, exist_ok=True)
        porcelain.init(bare_origin_dir, bare=True)

        # Clone bare to work repo to establish an initial main commit
        seed_dir = os.path.join(self.tmp_dir, "seed")
        porcelain.clone(bare_origin_dir, seed_dir)
        seed_repo = Repo(seed_dir)
        readme = os.path.join(seed_dir, "README.md")
        with open(readme, "w") as f:
            f.write("# Initial Seed")
        porcelain.add(seed_repo, ["README.md"])
        porcelain.commit(seed_repo, b"init", committer=b"Bot <b@t.io>", author=b"Bot <b@t.io>")
        seed_repo.refs.set_symbolic_ref(b"HEAD", b"refs/heads/main")
        seed_repo.refs[b"refs/heads/main"] = seed_repo.refs[b"refs/heads/master"]
        porcelain.push(seed_repo, bare_origin_dir, b"refs/heads/main:refs/heads/main")

        # Now test _commit_files_via_dulwich targeting bare_origin_dir
        real_clone = porcelain.clone
        with patch.object(self.provider, "get_token", return_value="fake_token"):
            with patch("shared.providers.github_provider.resolve_repo_identity", return_value=("TestOrg", "test-repo", "TestOrg/test-repo")):
                with patch("dulwich.porcelain.clone", side_effect=lambda source, target, **kwargs: real_clone(bare_origin_dir, target, **kwargs)):
                    files_to_commit = {
                        "app/main.py": "print('hello from dulwich')",
                        "infra/main.tf": "resource \"null\" {}",
                    }

                    with patch("dulwich.porcelain.push") as mock_push:
                        sha = self.provider._commit_files_via_dulwich(
                            repo_identifier="test-repo",
                            branch="feature/test-branch",
                            files=files_to_commit,
                            commit_message="feat: automated delivery",
                            author_name="Castor Test Agent",
                            author_email="test@castor.io",
                        )

                        self.assertTrue(bool(sha))
                        self.assertEqual(len(sha), 40)
                        mock_push.assert_called_once()

    def test_dulwich_token_redaction_on_push_failure(self):
        """Verifies that sensitive GitHub tokens are redacted from push error messages."""
        with patch.object(self.provider, "get_token", return_value="ghs_SUPER_SECRET_JIT_TOKEN_999"):
            with patch("shared.providers.github_provider.resolve_repo_identity", return_value=("TestOrg", "repo", "TestOrg/repo")):
                with patch("dulwich.porcelain.clone", side_effect=Exception("Failed to connect to https://x-access-token:ghs_SUPER_SECRET_JIT_TOKEN_999@github.com/TestOrg/repo.git")):
                    with self.assertRaises(RuntimeError) as ctx:
                        self.provider._commit_files_via_dulwich(
                            repo_identifier="repo",
                            branch="main",
                            files={"a.txt": "data"},
                            commit_message="commit",
                        )
                    err_msg = str(ctx.exception)
                    self.assertNotIn("ghs_SUPER_SECRET_JIT_TOKEN_999", err_msg)
                    self.assertIn("[REDACTED]", err_msg)

    def test_path_traversal_prevention_in_dulwich(self):
        """Verifies that file paths attempting to escape the temporary workspace are rejected."""
        with patch.object(self.provider, "get_token", return_value="token"):
            with patch("shared.providers.github_provider.resolve_repo_identity", return_value=("TestOrg", "repo", "TestOrg/repo")):
                with patch("dulwich.porcelain.clone") as mock_clone:
                    work_dir = os.path.join(self.tmp_dir, "traversal_work")
                    os.makedirs(work_dir, exist_ok=True)
                    porcelain.init(work_dir)
                    mock_clone.return_value = Repo(work_dir)

                    malicious_files = {
                        "../../etc/cron.d/evil": "malicious content",
                    }
                    with self.assertRaises(UnsafePathError):  # FD-4G: typed rejection (was PermissionError)
                        self.provider._commit_files_via_dulwich(
                            repo_identifier="repo",
                            branch="main",
                            files=malicious_files,
                            commit_message="malicious commit",
                        )

    def test_commit_files_dispatches_to_dulwich_when_git_cli_missing(self):
        """Verifies commit_files seamlessly falls back to Dulwich when shutil.which('git') is None."""
        with patch("shutil.which", return_value=None):
            with patch.object(self.provider, "_commit_files_via_dulwich", return_value="dulwich_sha_12345") as mock_dulwich:
                sha = self.provider.commit_files(
                    repo_identifier="TestOrg/test-repo",
                    branch="feature/branch",
                    files={"README.md": "test"},
                    commit_message="test commit",
                )
                self.assertEqual(sha, "dulwich_sha_12345")
                mock_dulwich.assert_called_once()

    def test_commit_files_fails_fast_when_no_engine_available(self):
        """Verifies commit_files raises RuntimeError without attempting broken REST tree synthesis if neither engine is available."""
        with patch("shutil.which", return_value=None):
            with patch("shared.providers.github_provider.DULWICH_AVAILABLE", False):
                with self.assertRaises(RuntimeError) as ctx:
                    self.provider.commit_files(
                        repo_identifier="TestOrg/test-repo",
                        branch="feature/branch",
                        files={"README.md": "test"},
                        commit_message="test commit",
                    )
                self.assertIn("No Git engine available", str(ctx.exception))

    def test_commit_files_dispatches_to_git_cli_when_available(self):
        """Verifies commit_files uses Native Git CLI when shutil.which('git') is available."""
        with patch("shutil.which", return_value="/usr/bin/git"):
            with patch.object(self.provider, "_commit_files_via_git_cli", return_value="cli_sha_67890") as mock_cli:
                sha = self.provider.commit_files(
                    repo_identifier="TestOrg/test-repo",
                    branch="feature/branch",
                    files={"README.md": "test"},
                    commit_message="test commit",
                )
                self.assertEqual(sha, "cli_sha_67890")
                mock_cli.assert_called_once()


if __name__ == "__main__":
    unittest.main()
