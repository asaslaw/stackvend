"""SERVERLESS-HITL-WORDING (owner 10-29): when a Serverless Git release that the workload lets merge by itself still
waits for a person, every place that says so names the cause in plain words with a typed code (`hitl_reason_code`),
never "HITL enforced by workload policy" (the workload asked for no review).
SERVERLESS-AUTOMERGE-SHA: that now happens only with a git server that cannot refuse a moved release branch (the
release fixture's provider double does not confirm the check); the Control Center notes are gone (see
tests/test_serverless_automerge_sha.py for the auto-merge itself)."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import logging
import os

import pytest

from fd4f_support import SHA_A, gw  # noqa: F401
from test_fd4f_release_evidence import BRANCH, _approvals, _evidence, _promote, rel  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_TEXT = "HITL enforced by workload policy"
CODE = "SERVERLESS_GIT_SOURCE_CHECK_UNSUPPORTED"


def _serverless(db, *, require_review):
    from shared import vcs_ledger

    db.docs = {k: v for k, v in db.docs.items() if not k.startswith("vcs_ledger/")}
    db.docs["workloads/app"] = {"require_human_code_review": require_review, "vcs_provider": "SERVERLESS_GIT"}
    vcs_ledger.record_created(db, provider="SERVERLESS_GIT", repo_full_name="o/r", repo_id=None, product_id="app",
                              trace_id="tr-1", origin=vcs_ledger.ORIGIN_DEVELOPER, branch=BRANCH, base_branch="main",
                              head_sha=SHA_A, pr_number=None, pr_url=None)
    db.docs["qa_test_runs/tr-1"] = _evidence()


def test_serverless_rule_is_named_on_the_card_the_log_and_the_certificate(rel, caplog):
    gw, db, merge, _ = rel
    _serverless(db, require_review=False)
    with caplog.at_level(logging.INFO):
        r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["auto_merged"] is False and body["approval_id"] and body["hitl_reason_code"] == CODE
    merge.assert_not_called()
    (appr,) = _approvals(db)
    text = appr["risk_assessment"]
    reason = gw.SERVERLESS_HITL_REASONS[CODE]
    assert appr["hitl_reason_code"] == CODE
    assert POLICY_TEXT not in text and "workload policy" not in text
    assert f"{reason}." in text and text.count(reason) == 1  # named once, not repeated as a blocking reason
    assert "even though the workload does not require code review" in text
    assert reason in appr["release_decision"]["blocking_reasons"]  # the certificate still lists the cause
    log = [rec.getMessage() for rec in caplog.records if "needs a human decision" in rec.getMessage()]
    assert log and reason in log[0] and POLICY_TEXT not in log[0]


@pytest.mark.parametrize("vcs", ["GITHUB", "SERVERLESS_GIT"])
def test_negative_review_required_by_the_workload_still_says_workload_policy(rel, vcs):
    gw, db, merge, _ = rel
    if vcs == "SERVERLESS_GIT":
        _serverless(db, require_review=True)
    else:
        db.docs["workloads/app"]["require_human_code_review"] = True
        db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200, r.text
    assert r.json()["hitl_reason_code"] is None
    (appr,) = _approvals(db)
    assert POLICY_TEXT in appr["risk_assessment"] and appr["hitl_reason_code"] is None
    assert gw.SERVERLESS_HITL_REASONS[CODE] not in appr["risk_assessment"]


def test_negative_github_auto_merge_is_unchanged(rel):
    gw, db, merge, _ = rel
    db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200 and r.json()["auto_merged"] is True and r.json()["hitl_reason_code"] is None
    merge.assert_called_once()
    assert _approvals(db) == []


def test_action_text_is_chosen_from_the_typed_reason_not_from_text(gw):
    class _D:
        recommended_action = "BLOCK_FOR_HITL_REVIEW"

    class _R:
        recommended_action = "AUTO_REJECT"

    reason = gw.SERVERLESS_HITL_REASONS[CODE]
    assert gw._release_hitl_action(_D(), reason) == reason
    assert gw._release_hitl_action(_D(), None) == POLICY_TEXT
    assert gw._release_hitl_action(_R(), reason) == "Policy or QA Gatekeeper Blocked"
    assert gw._release_hitl_action(None, None) == "Policy or QA Gatekeeper Blocked"


def _read(rel_path):
    with open(os.path.join(ROOT, rel_path), encoding="utf-8") as fh:
        return fh.read()


def _note_lines(html, testid):
    return [ln for ln in html.splitlines() if f'data-testid="{testid}"' in ln]


def test_dashboard_has_no_serverless_git_approval_note_after_the_fix():
    """SERVERLESS-AUTOMERGE-SHA: with the current git server a Serverless Git release merges by itself, so the
    create form and the review card say nothing more; an older git server is explained on the approval card."""
    html = _read("apps/control-center/templates/dashboard.html")
    assert _note_lines(html, "serverless-git-approval-note-create") == []
    assert _note_lines(html, "serverless-git-approval-note") == []
    assert "releases still need an approval on this install" not in html


def test_docs_describe_the_serverless_git_merge_check():
    assert "Serverless Git releases always need an approval" not in _read("documentation/known-limitations.md")
    guide = _read("documentation/user-guide.md")
    assert "**Serverless Git releases merge only the commit QA tested.**" in guide
    assert CODE in guide and "SERVERLESS_GIT_SOURCE_CHECK_UNCONFIRMED" in guide
    assert "SERVERLESS_GIT_APPROVAL_REQUIRED" not in guide
