"""RELEASE-STAGE-OUTCOME (FD-4DT): pipeline_executions/{trace}.stages.release records the release's real outcome.

The human-review decision is written by the Control Center (tests/test_approvals.py::TestReleaseStageOutcome). Here:
the gateway's own auto-merge (no approval card) records SUCCESS; a release that opens a review card writes no release
stage (the workflow's PAUSED_FOR_APPROVAL heartbeat owns it until the decision); the merge itself is unchanged."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from fd4f_support import SHA_A, FakeBackend, FakeDB, backend_factory, gw  # noqa: F401

BRANCH = "castor/app-1"


def _evidence():
    return {"trace_id": "tr-1", "branch_name": BRANCH, "passed": True, "error_class": None, "commit_sha": SHA_A,
            "security_lens": {"passed": True, "critical_vulnerabilities": []},
            "adherence_lens": {"passed": True, "instruction_adherence_score": 1.0, "grounding_score": 1.0,
                               "missed_directives": []}}


@pytest.fixture()
def rel(gw, monkeypatch):
    from shared import vcs_ledger

    db = FakeDB()
    db.docs["workloads/app"] = {"auto_merge": True, "require_human_code_review": False, "vcs_provider": "GITHUB"}
    vcs_ledger.record_created(db, provider="GITHUB", repo_full_name="o/r", repo_id=77, product_id="app",
                              trace_id="tr-1", origin=vcs_ledger.ORIGIN_DEVELOPER, branch=BRANCH, base_branch="main",
                              head_sha=SHA_A, pr_number=7, pr_url="https://github.com/o/r/pull/7")
    db.docs["qa_test_runs/tr-1"] = _evidence()
    monkeypatch.setenv("PROJECT_ID", "p-test")
    import google.cloud.firestore as fs

    monkeypatch.setattr(fs, "Client", lambda project=None, **kw: db)
    merge = MagicMock(return_value={"status": "MERGED", "merged": True, "pr_number": 7})
    monkeypatch.setattr(gw, "_release_vcs", lambda kind, pid, repo: MagicMock(merge_pull_request=merge))
    monkeypatch.setattr(gw.developer_agent, "get_full_repo_name", lambda pid, github_repo=None: "o/r")
    monkeypatch.setattr(gw, "post_release_certificate_to_vcs", MagicMock())
    gw.app.dependency_overrides[gw.get_source_backend_factory] = lambda: backend_factory(FakeBackend({}, {BRANCH: SHA_A}))
    return gw, db, merge


def _promote(gw):
    return TestClient(gw.app).post("/agent/release/promote", json={
        "trace_id": "tr-1", "product_id": "app", "branch_name": BRANCH, "expected_commit_sha": SHA_A})


def _release_writes(db):
    return [(d, m) for p, d, m in db.writes if p == "pipeline_executions/tr-1" and "stages" in d]


def test_github_auto_merge_records_release_success(rel):
    gw, db, merge = rel
    r = _promote(gw)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["auto_merged"] is True and body["approval_id"] == ""
    merge.assert_called_once()  # unchanged: one merge with the ledger identity
    assert set(merge.call_args.kwargs) == {"expected", "commit_message"}
    ((data, merged),) = _release_writes(db)
    assert merged is True and set(data) == {"stages"} and set(data["stages"]) == {"release"}
    assert data["stages"]["release"] == {
        "status": "SUCCESS",
        "summary": "Auto-merged into main at https://github.com/o/r/pull/7 (no human review required)"}


def test_negative_review_required_writes_no_release_stage(rel):
    """The workflow's PAUSED_FOR_APPROVAL heartbeat owns the stage until the Control Center decision."""
    gw, db, merge = rel
    db.docs["workloads/app"]["require_human_code_review"] = True
    r = _promote(gw)
    assert r.status_code == 200, r.text
    assert r.json()["auto_merged"] is False and r.json()["approval_id"]
    merge.assert_not_called()
    assert _release_writes(db) == []


def test_already_merged_rerun_records_release_success(rel):
    from shared import vcs_ledger

    gw, db, merge = rel
    vcs_ledger.mark(db, vcs_ledger.ledger_id("GITHUB", "o/r", BRANCH), vcs_ledger.STATE_MERGED, merged_by="ops@example.com")
    r = _promote(gw)
    assert r.status_code == 200 and r.json()["already_merged"] is True, r.text
    merge.assert_not_called()  # never merged again
    ((data, _),) = _release_writes(db)
    assert data["stages"]["release"]["status"] == "SUCCESS"
    assert "ops@example.com" in data["stages"]["release"]["summary"]


def test_stage_write_failure_never_fails_the_release(gw):
    db = MagicMock()
    db.collection.return_value.document.return_value.set.side_effect = RuntimeError("firestore down")
    gw._record_release_stage_merged(db, "tr-1", "Auto-merged into main")  # logged, not raised


def test_merged_summary_names_no_base_when_the_ledger_has_none(gw):
    assert gw._merged_stage_summary("Auto-merged", {}, "at u") == "Auto-merged at u (no human review required)"
    assert gw._merged_stage_summary("Auto-merged", {"base_branch": "release"}, "at u") == \
        "Auto-merged into release at u (no human review required)"
