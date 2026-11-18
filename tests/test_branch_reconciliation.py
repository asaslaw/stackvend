"""
Unit tests for StackVend PR & branch lifecycle management.

FD-4P (owner row 23: reconcile REWRITTEN on the PR ledger). The old tests encoded the removed behaviour: PRs were
found by listing every open PR and matching branch-name prefixes, body text and labels, so a human PR on a
`feature/<pid>-` branch lost its branch and other products' PRs were closed. Now reconcile receives the exact
ledger identities to supersede; anything the ledger does not name (human PRs, legacy pre-ledger PRs, forks, other
products, the current attempt) is unreachable. Verifies:
1. Human PRs: zero mutations, nothing listed.
2. A superseded ledger PR is closed with a comment and its branch deleted (SHA-guarded).
3. Legacy pre-ledger automated PRs are left for humans (lane 16 OQ-3).
4. The current attempt is never superseded (the gateway excludes it: keep_branch).
5. Ingestion of machine metadata comments and governance labels on PR creation (unchanged).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import pytest

from shared.providers.github_provider import GitHubProvider
from shared.vcs_provider import PRIdentity

REPO, REPO_ID, SHA = "test-owner/castor-testplan08-a", 4242, "c" * 40


@pytest.fixture
def mock_github_provider():
    provider = GitHubProvider(github_token="mock-token", default_owner="test-owner")
    provider.actor_identity = lambda: (4242, "Bot")  # RT M1: the platform identity (no network)
    return provider


def _repo(prs, refs=None):
    repo = MagicMock()
    repo.id, repo.full_name = REPO_ID, REPO
    repo.get_pull.side_effect = lambda n: prs[n]
    refs = refs or {}

    def _ref(name):
        ref = MagicMock()
        ref.object.sha = refs.get(name[len("heads/"):], SHA)
        return ref
    repo.get_git_ref.side_effect = _ref
    return repo


def _pr(number, head_ref, *, head_sha=SHA, head_repo_id=REPO_ID):
    pr = MagicMock()
    pr.number, pr.state, pr.merged = number, "open", False
    pr.user = SimpleNamespace(id=4242, type="Bot")
    pr.head = SimpleNamespace(ref=head_ref, sha=head_sha, repo=SimpleNamespace(id=head_repo_id, full_name=REPO))
    pr.base = SimpleNamespace(ref="main", repo=SimpleNamespace(id=REPO_ID, full_name=REPO))
    return pr


def _ident(number, branch):
    return PRIdentity(provider="GITHUB", repo_full_name=REPO, branch=branch, base_branch="main", head_sha=SHA,
                      pr_number=number, repo_id=REPO_ID)


def test_human_pr_isolation(mock_github_provider):
    """Human PRs must never be touched, closed, or commented on (even on a `feature/<pid>-` branch)."""
    human_pr = _pr(42, "feature/testplan08-a-login-form")
    mock_repo = _repo({42: human_pr})
    with patch.object(mock_github_provider, "_get_repo", return_value=mock_repo):
        res = mock_github_provider.reconcile_automated_pull_requests(REPO, superseded=[])
    assert res == {"status": "RECONCILED", "results": []}
    human_pr.create_issue_comment.assert_not_called()
    human_pr.edit.assert_not_called()
    mock_repo.get_git_ref.assert_not_called()
    mock_repo.get_pulls.assert_not_called()
    mock_repo.get_branches.assert_not_called()


def test_stale_castor_pr_cleanup(mock_github_provider):
    """A superseded ledger PR is closed with a comment and its (unchanged) branch deleted."""
    castor_pr = _pr(3, "castor/testplan08-a-277084")
    mock_repo = _repo({3: castor_pr})
    with patch.object(mock_github_provider, "_get_repo", return_value=mock_repo):
        res = mock_github_provider.reconcile_automated_pull_requests(
            REPO, superseded=[_ident(3, "castor/testplan08-a-277084")])
    assert res["status"] == "RECONCILED"
    assert res["results"] == [{"branch": "castor/testplan08-a-277084", "pr_number": 3, "outcome": "SUPERSEDED",
                               "branch_deleted": True}]
    castor_pr.create_issue_comment.assert_called_once()
    assert "superseded by a newer StackVend run" in castor_pr.create_issue_comment.call_args[0][0]
    castor_pr.edit.assert_called_once_with(state="closed")
    mock_repo.get_git_ref.assert_called_once_with("heads/castor/testplan08-a-277084")


def test_legacy_automated_pr_cleanup(mock_github_provider):
    """Pre-ledger automated PRs (title/branch prefix only) are no longer closed: the prefix match also hit human PRs
    (FD27-01). They are left for humans (lane 16 OQ-3; no backfill, Q11)."""
    legacy_pr = _pr(3, "feature/testplan08-a-277084")
    legacy_pr.title = "feat(testplan08-a): automated implementation by Project Castor Developer Agent"
    mock_repo = _repo({3: legacy_pr})
    with patch.object(mock_github_provider, "_get_repo", return_value=mock_repo):
        res = mock_github_provider.reconcile_automated_pull_requests(REPO, superseded=[])
    assert res["results"] == []
    legacy_pr.edit.assert_not_called()
    mock_repo.get_git_ref.assert_not_called()


def test_intra_execution_retry_preservation(mock_github_provider):
    """The current attempt is never in `superseded` (gateway keep_branch); a ledger PR someone pushed to since
    StackVend created it is DIVERGED and left open."""
    active_pr = _pr(7, "castor/testplan08-a-retry1", head_sha="d" * 40)
    mock_repo = _repo({7: active_pr})
    with patch.object(mock_github_provider, "_get_repo", return_value=mock_repo):
        res = mock_github_provider.reconcile_automated_pull_requests(
            REPO, superseded=[_ident(7, "castor/testplan08-a-retry1")])
    assert [r["outcome"] for r in res["results"]] == ["DIVERGED"]
    active_pr.edit.assert_not_called()
    mock_repo.get_git_ref.assert_not_called()


def test_create_pull_request_metadata_tagging(mock_github_provider):
    """Newly created PRs must embed castor-metadata and attach managed-by:project-castor label."""
    mock_repo = MagicMock()
    mock_pr = MagicMock()
    mock_pr.number = 10
    mock_pr.title = "feat(testplan08-a): fresh build"
    mock_pr.html_url = "https://github.com/test-owner/castor-testplan08-a/pull/10"
    mock_pr.diff_url = "https://github.com/test-owner/castor-testplan08-a/pull/10.diff"
    mock_repo.create_pull.return_value = mock_pr

    with patch.object(mock_github_provider, "_get_repo", return_value=mock_repo):
        res = mock_github_provider.create_pull_request(
            repo_identifier="test-owner/castor-testplan08-a",
            title="feat(testplan08-a): fresh build",
            body="Here is the implementation.",
            head_branch="castor/testplan08-a-fresh",
            base_branch="main",
            trace_id="trace-xyz",
            product_id="testplan08-a",
        )

    assert res["status"] == "PR_CREATED"
    assert res["pr_number"] == 10

    # Verify body had metadata injected
    created_body = mock_repo.create_pull.call_args[1]["body"]
    assert "<!-- castor-metadata:" in created_body
    assert '"trace_id": "trace-xyz"' in created_body
    assert "<!-- managed-by: project-castor -->" in created_body

    # Verify label was attached
    mock_pr.add_to_labels.assert_called_once_with("managed-by:project-castor")
