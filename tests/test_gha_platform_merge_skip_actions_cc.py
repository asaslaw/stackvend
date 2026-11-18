"""GHA-PLATFORM-MERGE-SKIP-ACTIONS (owner 11-16), Control Center half: the human-approval merge
(`routes/approvals.py::_merge_workload_pr`) carries GitHub's `[skip actions]` directive on GitHub and leaves the
Serverless Git message byte-identical. The gateway half, the shared constant and the copy parity are in
tests/test_gha_platform_merge_skip_actions.py. A separate file because tests/test_approvals.py (which loads
routes.approvals) stubs fastapi / google.* at import, and the gateway release fixture needs the real libraries.
Hermetic: in-memory Firestore fake, MagicMock / real GitHubProvider over a recording PyGithub requester.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import sys
from unittest.mock import MagicMock

import pytest

# Helpers first (real libraries), then test_approvals (its import-time stubs; it loads routes.approvals).
from test_gha_platform_merge_skip_actions import DIRECTIVE, _live, _put_bodies  # noqa: E402
import test_approvals as _ta  # noqa: E402

CC_PID, CC_REPO, CC_BRANCH = "tenant-a", "example-org/tenant-a", "feature-x"
CC_MSG = f"feat({CC_PID}): HITL approved merge of '{CC_BRANCH}' into main by admin@example.com"


@pytest.fixture()
def cc(monkeypatch):
    appr = sys.modules["routes.approvals"]
    db = _ta._MemDB()
    monkeypatch.setattr(appr, "db", db)
    return appr, db


def _cc_seed(db, provider):
    db.collection("workloads").document(CC_PID).set(
        {"product_id": CC_PID, "github_repo": CC_REPO, "vcs_provider": provider, "default_branch": "main"})
    lid = _ta._seed_ledger(db, product_id=CC_PID, repo=CC_REPO, branch=CC_BRANCH, provider=provider)
    return {"approval_type": "PULL_REQUEST", "product_id": CC_PID, "branch_name": CC_BRANCH, "github_repo": CC_REPO,
            "pr_number": 7 if provider == "GITHUB" else None, "ledger_id": lid, "trace_id": "tr-1"}


def _cc_factory(monkeypatch, appr, vcs):
    factory = MagicMock(name="VCSProviderFactory")
    factory.get_provider.return_value = vcs
    monkeypatch.setattr(appr, "VCSProviderFactory", factory)
    return factory


def test_cc_github_approval_merge_sends_the_directive(cc, monkeypatch):
    appr, db = cc
    record = _cc_seed(db, "GITHUB")
    vcs = MagicMock(name="vcs")
    vcs.merge_pull_request.return_value = {"status": "MERGED", "merged": True}
    _cc_factory(monkeypatch, appr, vcs)
    assert appr._merge_workload_pr(record, CC_PID, CC_BRANCH, "admin@example.com") is None
    vcs.merge_pull_request.assert_called_once()
    args, kwargs = vcs.merge_pull_request.call_args
    assert args == (CC_REPO,) and set(kwargs) == {"expected", "commit_message", "require_provenance"}
    assert kwargs["require_provenance"] is False  # unchanged: a human approved this card
    assert kwargs["commit_message"] == f"{CC_MSG}\n\n{DIRECTIVE}"
    assert kwargs["commit_message"].count(DIRECTIVE) == 1
    exp = kwargs["expected"]
    assert (exp.pr_number, exp.branch, exp.head_sha, exp.repo_id) == (7, CC_BRANCH, _ta.LEDGER_SHA, 100)


def test_cc_github_approval_merge_real_provider_put_body(cc, monkeypatch):
    appr, db = cc
    record = _cc_seed(db, "GITHUB")
    prov, requester = _live(monkeypatch, appr.vcs_ledger, repo_id=100, full_name=CC_REPO, branch=CC_BRANCH,
                            head_sha=_ta.LEDGER_SHA)
    _cc_factory(monkeypatch, appr, prov)
    assert appr._merge_workload_pr(record, CC_PID, CC_BRANCH, "admin@example.com") is None
    (body,) = _put_bodies(requester)
    assert body == {"commit_message": f"{CC_MSG}\n\n{DIRECTIVE}", "merge_method": "squash", "sha": _ta.LEDGER_SHA}


def test_negative_cc_serverless_approval_merge_message_is_byte_identical(cc, monkeypatch):
    appr, db = cc
    record = _cc_seed(db, "SERVERLESS_GIT")
    vcs = MagicMock(name="vcs")
    vcs.merge_pull_request.return_value = {"status": "MERGED", "merged": True, "commit_sha": "c0ffee"}
    _cc_factory(monkeypatch, appr, vcs)
    assert appr._merge_workload_pr(record, CC_PID, CC_BRANCH, "admin@example.com") is None
    args, kwargs = vcs.merge_pull_request.call_args
    assert args == (CC_REPO,)
    assert kwargs == {"pr_number": 0, "commit_message": CC_MSG, "source_branch": CC_BRANCH, "target_branch": "main",
                      "expected_source_sha": _ta.LEDGER_SHA}
