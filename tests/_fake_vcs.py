"""In-memory VCS provider for DeveloperAgent.commit_and_open_pr tests.

FD-4F A9 (Q-E): with no VCS credential commit_and_open_pr raises GATE_UNAVAILABLE `VCS_CREDENTIAL_UNAVAILABLE`
instead of returning a fabricated MOCK_COMMITTED; tests that exercise the commit path give it a token and this fake.
"""

from contextlib import contextmanager
from typing import Any, Dict, List
from unittest.mock import patch


class FakeVCS:
    def __init__(self) -> None:
        self.commits: List[Dict[str, str]] = []

    def create_or_verify_branch(self, repo: str, branch: str, source_branch: str = "main") -> None:
        return None

    def commit_files(self, repo: str, branch: str, files: Dict[str, str], msg: str) -> str:
        self.commits.append(dict(files))
        return "a" * 40

    def create_pull_request(self, repo: str, **kw: Any) -> Dict[str, Any]:
        return {"pull_request_url": f"https://example.invalid/{repo}/pull/7", "pr_number": 7}


class PassThroughVerifier:
    """FD-4F A9: the pre-commit verifier is mandatory (patching it to None now fails closed). Tests that only exercise
    the commit transport use this one: it passes the tree through unchanged."""

    def __init__(self, product_id: Any = None) -> None:
        pass

    def purge_shadowed_package_files(self, files: Dict[str, str]):
        return dict(files), []

    def verify_and_cure(self, files: Dict[str, str], product_id: Any = None, **kw: Any):
        return dict(files), True, []


@contextmanager
def fake_vcs_commit(agent: Any):
    """Patch `agent` to commit through a FakeVCS (token present, no sleep); yields the fake."""
    from developer_agent import handler as h

    vcs = FakeVCS()
    with patch.object(agent, "fetch_github_token", return_value="test-token"), \
            patch.object(h.VCSProviderFactory, "get_provider", return_value=vcs), \
            patch.object(h.time, "sleep", return_value=None):
        yield vcs
