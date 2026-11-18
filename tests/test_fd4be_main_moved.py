"""FD-4BE (register row 11 follow-up): the git server's fast-forward-only release merge 409 ("main moved since the
branch was cut") reaches the workflow as a typed MAIN_MOVED failure at once: no approval card, no 24 h wait, no
auto-rebase. The gateway half lives here; the Control Center (human-approval merge) half is in
tests/test_approvals.py::TestServerlessGitMergesTheApprovedBranch."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import pytest

from fd4f_support import SHA_A, gw  # noqa: F401
from test_fd4f_release_evidence import BRANCH, _approvals, _evidence, _promote, rel  # noqa: F401
from test_lane17_workflow_sim import TF, Fleet, assert_failed, calls, run, workflow  # noqa: F401


def _serverless_entry():
    return {"ledger_id": "lid-1", "repo_full_name": "castor/app", "branch": BRANCH, "base_branch": "main",
            "head_sha": SHA_A}


class _Vcs:
    def __init__(self, exc=None, result=None):
        self.exc, self.result, self.calls = exc, result, []

    def merge_pull_request(self, repo, **kwargs):
        self.calls.append((repo, kwargs))
        if self.exc is not None:
            raise self.exc
        return self.result


def _with_vcs(gw, monkeypatch, vcs):
    monkeypatch.setattr(gw, "_release_vcs", lambda kind, pid, repo: vcs)


# ------------------------------------------------------------------ _release_merge: exactly the FF-only 409 is typed
def test_serverless_ff_only_409_is_main_moved(gw, monkeypatch):
    vcs = _Vcs(exc=gw.ServerlessGitMergeConflict("Serverless Git conflict on /api/v1/repos/app/merge: {...}"))
    _with_vcs(gw, monkeypatch, vcs)
    with pytest.raises(gw.MainMovedError) as ei:
        gw._release_merge("SERVERLESS_GIT", _serverless_entry(), "app", "msg")
    err = ei.value
    assert err.http_status == 409 and err.error_class.value == "MAIN_MOVED" and err.stage == "release"
    assert err.details == {"branch_name": BRANCH, "base_branch": "main"}
    assert isinstance(err.__cause__, gw.ServerlessGitMergeConflict)
    (_, kwargs), = vcs.calls  # one merge attempt, no rebase / retry
    assert (kwargs["source_branch"], kwargs["target_branch"]) == (BRANCH, "main")


@pytest.mark.parametrize("label,make_exc", [
    ("http_500", lambda gw: gw_sgp(gw).ServerlessGitError("Serverless Git POST /merge returned HTTP 500")),
    ("auth_403", lambda gw: gw_sgp(gw).ServerlessGitAuthError("rejected (HTTP 403)")),
    ("transport", lambda gw: ConnectionError("reset")),
])
def test_negative_other_serverless_failures_are_unchanged(gw, monkeypatch, label, make_exc):
    exc = make_exc(gw)
    _with_vcs(gw, monkeypatch, _Vcs(exc=exc))
    with pytest.raises(type(exc)) as ei:
        gw._release_merge("SERVERLESS_GIT", _serverless_entry(), "app", "msg")
    assert ei.value is exc and not isinstance(ei.value, gw.MainMovedError), label


def test_negative_serverless_success_is_unchanged(gw, monkeypatch):
    res = {"status": "MERGED", "merged": True, "commit_sha": "c0ffee", "target_branch": "main",
           "source_sha_checked": True}  # SERVERLESS-AUTOMERGE-SHA: the server confirmed the tested-commit check
    _with_vcs(gw, monkeypatch, _Vcs(result=res))
    assert gw._release_merge("SERVERLESS_GIT", _serverless_entry(), "app", "msg") is res


def test_negative_github_409_is_not_main_moved(gw, monkeypatch):
    """GitHub's 409 means the PR HEAD moved (already PRIdentityMismatch -> human card), never "main moved"."""
    exc = gw.PRIdentityMismatch("head_sha", SHA_A, "moved before merge")
    _with_vcs(gw, monkeypatch, _Vcs(exc=exc))
    entry = {**_serverless_entry(), "repo_full_name": "o/r", "pr_number": 7, "repo_id": 77}
    monkeypatch.setattr(gw.vcs_ledger, "identity", lambda e: object())
    with pytest.raises(gw.PRIdentityMismatch):
        gw._release_merge("GITHUB", entry, "app", "msg")


def gw_sgp(gw):
    import sys
    return sys.modules[gw.ServerlessGitMergeConflict.__module__]


# ------------------------------------------------------------------ release_promote -> workflow contract
def _main_moved(gw):
    def _raise(*_a, **_k):
        raise gw.MainMovedError("main moved since the branch was cut; nothing merged, re-run the workload",
                                reason="MAIN_MOVED", stage="release",
                                details={"branch_name": BRANCH, "base_branch": "main"})
    return _raise


def test_release_main_moved_is_a_typed_409_with_no_approval_card(rel, monkeypatch):
    gw, db, merge, _ = rel
    monkeypatch.setattr(gw, "_release_merge", _main_moved(gw))
    db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 409, r.text
    body = r.json()
    assert (body["error_class"], body["stage"], body["reason"], body["status"]) == ("MAIN_MOVED", "release", "MAIN_MOVED", "FAILED")
    assert "re-run" in body["summary"]
    assert _approvals(db) == []  # no card: nothing a human approval could ever fast-forward
    from shared import vcs_ledger
    entry = db.docs[f"vcs_ledger/{vcs_ledger.ledger_id('GITHUB', 'o/r', BRANCH)}"]
    assert entry["state"] == "MERGE_FAILED"


def test_release_main_moved_body_ends_the_workflow_run_typed(rel, monkeypatch, workflow):
    """The gateway's real 409 body, fed to the workflow: the run fails MAIN_MOVED at the release stage, registers no
    approval callback (no 24 h wait) and never deploys."""
    gw, db, merge, _ = rel
    monkeypatch.setattr(gw, "_release_merge", _main_moved(gw))
    db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_A)
    res, _ = run(workflow, Fleet(**{"/agent/release/promote": (r.status_code, r.json())}))
    assert_failed(res, "MAIN_MOVED", "release")
    assert not calls(res, "/events/approval-callback") and not calls(res, TF)


def test_negative_release_success_is_unchanged(rel):
    gw, db, merge, _ = rel
    db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200 and r.json()["auto_merged"] is True and r.json()["status"] == "SUCCESS"
    merge.assert_called_once()


@pytest.mark.parametrize("label,make_exc", [
    ("merge_not_completed", lambda gw: gw.PRMergeNotCompleted("GitHub did not merge PR #7")),
    ("provider_error", lambda gw: RuntimeError("GitHub 502")),
])
def test_negative_other_merge_failures_still_open_a_human_card(rel, label, make_exc):
    gw, db, merge, _ = rel
    merge.side_effect = make_exc(gw)
    db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200, (label, r.text)
    assert r.json()["auto_merged"] is False and r.json()["approval_id"], label
    assert len(_approvals(db)) == 1, label
