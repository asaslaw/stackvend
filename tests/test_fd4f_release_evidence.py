"""FD-4F RL-1..3 + D7/D10: auto-merge only on QA evidence for this trace, branch and the current head commit."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from fd4f_support import SHA_A, SHA_B, FakeBackend, FakeDB, backend_factory, gw  # noqa: F401

BRANCH = "castor/app-1"


def _evidence(**over):
    doc = {
        "trace_id": "tr-1", "branch_name": BRANCH, "passed": True, "error_class": None, "commit_sha": SHA_A,
        "security_lens": {"passed": True, "critical_vulnerabilities": []},
        "adherence_lens": {"passed": True, "instruction_adherence_score": 1.0, "grounding_score": 1.0, "missed_directives": []},
    }
    doc.update(over)
    return doc


def seed_ledger(db, *, product_id="app", trace_id="tr-1", branch=BRANCH, head_sha=SHA_A, repo="o/r"):
    """FD-4P: the entry the developer step writes when it creates the PR (identity from the PR-creation response)."""
    from shared import vcs_ledger

    return vcs_ledger.record_created(db, provider="GITHUB", repo_full_name=repo, repo_id=77, product_id=product_id,
                                     trace_id=trace_id, origin=vcs_ledger.ORIGIN_DEVELOPER, branch=branch,
                                     base_branch="main", head_sha=head_sha, pr_number=7,
                                     pr_url=f"https://github.com/{repo}/pull/7")


@pytest.fixture()
def rel(gw, monkeypatch):
    db = FakeDB()
    # What the CC writes from the per-workload auto-merge toggle (both fields); only the exact bool is read (RT F7).
    db.docs["workloads/app"] = {"auto_merge": True, "require_human_code_review": False, "vcs_provider": "GITHUB"}
    seed_ledger(db)
    monkeypatch.setenv("PROJECT_ID", "p-test")
    import google.cloud.firestore as fs

    monkeypatch.setattr(fs, "Client", lambda project=None, **kw: db)
    # FD-4BB: the release merges through the provider with the ledger identity (no DeveloperAgent.merge_pull_request).
    merge = MagicMock(return_value={"status": "MERGED", "merged": True, "pr_number": 7})
    monkeypatch.setattr(gw, "_release_vcs", lambda kind, pid, repo: MagicMock(merge_pull_request=merge))
    monkeypatch.setattr(gw.developer_agent, "get_full_repo_name", lambda pid, github_repo=None: "o/r")
    monkeypatch.setattr(gw, "post_release_certificate_to_vcs", MagicMock())
    backend = FakeBackend({}, {BRANCH: SHA_A})
    gw.app.dependency_overrides[gw.get_source_backend_factory] = lambda: backend_factory(backend)
    return gw, db, merge, backend


def _promote(gw, **body):
    payload = {"trace_id": "tr-1", "product_id": "app", "branch_name": BRANCH}
    payload.update(body)
    return TestClient(gw.app).post("/agent/release/promote", json=payload)


def test_negative_full_evidence_auto_merges(rel):
    gw, db, merge, _ = rel
    db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200, r.text
    assert r.json()["auto_merged"] is True
    merge.assert_called_once()
    args, kwargs = merge.call_args
    exp = kwargs["expected"]
    assert (args[0], exp.pr_number, exp.branch, exp.head_sha, exp.repo_id) == ("o/r", 7, BRANCH, SHA_A, 77)
    assert set(kwargs) == {"expected", "commit_message"}  # no pr_number guess, no source_branch lookup
    from shared import vcs_ledger
    assert db.docs[f"vcs_ledger/{vcs_ledger.ledger_id('GITHUB', 'o/r', BRANCH)}"]["state"] == "MERGED"


@pytest.mark.parametrize("label,setup", [
    ("no_doc", lambda db, be: None),
    ("trace_mismatch", lambda db, be: db.docs.__setitem__("qa_test_runs/tr-1", _evidence(trace_id="other"))),
    ("branch_mismatch", lambda db, be: db.docs.__setitem__("qa_test_runs/tr-1", _evidence(branch_name="x"))),
    ("qa_failed", lambda db, be: db.docs.__setitem__("qa_test_runs/tr-1", _evidence(passed=False, error_class="CODE_DEFECT"))),
    ("no_sha", lambda db, be: db.docs.__setitem__("qa_test_runs/tr-1", _evidence(commit_sha=None))),
    ("head_moved", lambda db, be: (db.docs.__setitem__("qa_test_runs/tr-1", _evidence()), be.shas.__setitem__(BRANCH, SHA_B))),
    ("head_unreadable", lambda db, be: (db.docs.__setitem__("qa_test_runs/tr-1", _evidence()), setattr(be, "fail", True))),
    ("lens_missing", lambda db, be: db.docs.__setitem__("qa_test_runs/tr-1", _evidence(security_lens=None))),
])
def test_unusable_evidence_never_merges_and_opens_hitl(rel, label, setup):
    gw, db, merge, backend = rel
    setup(db, backend)
    r = _promote(gw)
    assert r.status_code == 200, r.text
    assert r.json()["auto_merged"] is False, label
    merge.assert_not_called()
    assert any(p.startswith("approval_requests/") for p in db.docs), label


def test_gatekeeper_sha_mismatch_never_merges(rel):
    gw, db, merge, _ = rel
    db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_B)
    assert r.json()["auto_merged"] is False
    merge.assert_not_called()


def test_firestore_read_failure_never_merges(rel):
    """FD-4P (RT H1): an unreadable workload / ledger store is a typed 503 GATE_UNAVAILABLE (was 200 + HITL)."""
    gw, db, merge, _ = rel
    db.docs["qa_test_runs/tr-1"] = _evidence()
    db.fail_reads = True
    r = _promote(gw)
    assert r.status_code == 503, r.text
    assert r.json()["error_class"] == "GATE_UNAVAILABLE"
    merge.assert_not_called()


# ============================================================================ FD-4P / FD-4BB: ledger-bound release
def _approvals(db):
    return [v for p, v in db.docs.items() if p.startswith("approval_requests/")]


@pytest.mark.parametrize("label,mutate,reason", [
    ("no_ledger_entry", lambda db: [db.docs.pop(p) for p in list(db.docs) if p.startswith("vcs_ledger/")], "NO_LEDGER_ENTRY"),
    ("other_products_entry", lambda db: ([db.docs.pop(p) for p in list(db.docs) if p.startswith("vcs_ledger/")],
                                         seed_ledger(db, product_id="app-v2")), "PRODUCT_MISMATCH"),
    ("other_traces_entry", lambda db: ([db.docs.pop(p) for p in list(db.docs) if p.startswith("vcs_ledger/")],
                                       seed_ledger(db, trace_id="tr-0")), "TRACE_MISMATCH"),
    ("entry_in_another_repo", lambda db: ([db.docs.pop(p) for p in list(db.docs) if p.startswith("vcs_ledger/")],
                                          seed_ledger(db, repo="o/other")), "NO_LEDGER_ENTRY"),
    ("already_superseded", lambda db: [d.__setitem__("state", "SUPERSEDED") for p, d in db.docs.items()
                                       if p.startswith("vcs_ledger/")], "LEDGER_STATE"),
    ("unknown_vcs_provider", lambda db: db.docs["workloads/app"].__setitem__("vcs_provider", "GITLAB"), "VCS_PROVIDER_UNKNOWN"),
    ("workload_missing", lambda db: db.docs.pop("workloads/app"), "WORKLOAD_NOT_FOUND"),
])
def test_negative_release_without_a_matching_ledger_entry_is_a_typed_refusal(rel, label, mutate, reason):
    """N14 / RT H1: nothing StackVend created for this run -> 409 RELEASE_FAILED, no merge, no approval card."""
    gw, db, merge, _ = rel
    db.docs["qa_test_runs/tr-1"] = _evidence()
    mutate(db)
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 409, (label, r.text)
    body = r.json()
    assert (body["error_class"], body["reason"]) == ("RELEASE_FAILED", reason), label
    merge.assert_not_called()
    assert _approvals(db) == [], label


def test_negative_qa_tested_commit_is_not_the_ledger_commit(rel):
    """RT H2: the ledger head_sha is the SHA authority. A branch someone pushed to after StackVend (QA tested the
    new head) never auto-merges; it goes to a human with the reason."""
    gw, db, merge, backend = rel
    db.docs["qa_test_runs/tr-1"] = _evidence(commit_sha=SHA_B)
    backend.shas[BRANCH] = SHA_B
    r = _promote(gw, expected_commit_sha=SHA_B)
    assert r.status_code == 200 and r.json()["auto_merged"] is False
    merge.assert_not_called()
    (appr,) = _approvals(db)
    assert "StackVend pushed" in appr["risk_assessment"]


def test_negative_derived_auto_merge_flag_alone_never_overrides_review(rel):
    """RT F7 / P2: `auto_merge: true` with `require_human_code_review` true (or absent) -> human review."""
    gw, db, merge, _ = rel
    db.docs["qa_test_runs/tr-1"] = _evidence()
    for policy in ({"auto_merge": True, "require_human_code_review": True}, {"auto_merge": True}):
        db.docs["workloads/app"] = {**policy, "vcs_provider": "GITHUB"}
        r = _promote(gw, expected_commit_sha=SHA_A)
        assert r.status_code == 200 and r.json()["auto_merged"] is False, policy
    merge.assert_not_called()


def test_negative_request_can_only_tighten_policy(rel):
    """P1 / owner row 23: `auto_merge` is not a release field (422); `require_human_code_review: false` is refused
    (422); `true` forces human review even when the workload allows auto-merge."""
    gw, db, merge, _ = rel
    db.docs["qa_test_runs/tr-1"] = _evidence()
    assert _promote(gw, auto_merge=True).status_code == 422
    assert _promote(gw, require_human_code_review=False).status_code == 422
    r = _promote(gw, expected_commit_sha=SHA_A, require_human_code_review=True)
    assert r.status_code == 200 and r.json()["auto_merged"] is False
    merge.assert_not_called()


def test_hitl_record_carries_the_ledger_identity(rel):
    """P-d: the approval card the CC merges from names the ledger entry, the int PR number and the real PR URL."""
    gw, db, merge, _ = rel
    db.docs["workloads/app"]["require_human_code_review"] = True
    db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200 and r.json()["approval_id"]
    (appr,) = _approvals(db)
    from shared import vcs_ledger
    assert appr["ledger_id"] == vcs_ledger.ledger_id("GITHUB", "o/r", BRANCH)
    assert (appr["pr_number"], appr["head_sha"], appr["pull_request_url"]) == (7, SHA_A, "https://github.com/o/r/pull/7")
    merge.assert_not_called()


def test_negative_auto_merge_identity_mismatch_falls_back_to_a_human(rel):
    """A live PR that no longer matches the ledger (fork head, moved head...) is never merged: ledger MERGE_FAILED,
    approval card with the reason (the HITL merge re-runs every check)."""
    gw, db, merge, _ = rel
    from shared.vcs_provider import PRIdentityMismatch
    merge.side_effect = PRIdentityMismatch("head_repo_id", 77, 999)
    db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200 and r.json()["auto_merged"] is False
    (appr,) = _approvals(db)
    assert "head_repo_id" in appr["risk_assessment"]
    from shared import vcs_ledger
    assert db.docs[f"vcs_ledger/{vcs_ledger.ledger_id('GITHUB', 'o/r', BRANCH)}"]["state"] == "MERGE_FAILED"


def test_negative_approval_write_failure_is_503_never_an_empty_approval_id(rel):
    """N25 / RT H1."""
    gw, db, merge, _ = rel
    db.docs["workloads/app"]["require_human_code_review"] = True
    db.docs["qa_test_runs/tr-1"] = _evidence()
    db.fail_writes = True
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 503, r.text
    assert r.json()["reason"] == "APPROVAL_WRITE_FAILED"


def test_trace_id_required(rel):
    gw, *_ = rel
    assert TestClient(gw.app).post("/agent/release/promote", json={"product_id": "app", "branch_name": BRANCH}).status_code == 422


def test_release_gatekeeper_missing_verdicts_are_failures():
    import release_gatekeeper as rg

    d = rg.evaluate_release_decision({}, {}, {}, {"require_human_code_review": False, "auto_merge": True})
    assert d.is_approved is False and d.recommended_action == "AUTO_REJECT"
    assert d.deterministic_passed is False and d.security_clean is False
    # security judged failed with no listed criticals is still a failure
    d2 = rg.evaluate_release_decision(
        {"passed": True}, {"passed": False, "critical_vulnerabilities": []},
        {"passed": True, "instruction_adherence_score": 1.0}, {"auto_merge": True})
    assert d2.is_approved is False
    # adherence lens failed on grounding alone (score fields fine) is still a failure
    d3 = rg.evaluate_release_decision(
        {"passed": True}, {"passed": True, "critical_vulnerabilities": []},
        {"passed": False, "instruction_adherence_score": 1.0, "grounding_score": 0.5}, {"auto_merge": True})
    assert d3.is_approved is False


def test_release_gatekeeper_negative_clean_reports_approve():
    import release_gatekeeper as rg

    d = rg.evaluate_release_decision(
        {"passed": True}, {"passed": True, "critical_vulnerabilities": []},
        {"passed": True, "instruction_adherence_score": 1.0, "grounding_score": 1.0, "missed_directives": []},
        {"require_human_code_review": False, "auto_merge": True})
    assert d.is_approved is True and d.recommended_action == "AUTO_MERGE"


def test_deploy_only_gate_allows_a_branch_whose_ledger_entry_merged(rel):
    """Lane 17 RT F2 contract, now wired: a non-default branch is reviewed code only when its ledger entry MERGED."""
    gw, db, merge, _ = rel
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: db
    c = TestClient(gw.app)
    body = {"trace_id": "tr-1", "product_id": "app", "branch": BRANCH}
    assert c.post("/governance/deploy-only-gate", json=body).status_code == 403  # OPEN, not merged yet
    db.docs["qa_test_runs/tr-1"] = _evidence()
    assert _promote(gw, expected_commit_sha=SHA_A).json()["auto_merged"] is True
    r = c.post("/governance/deploy-only-gate", json=body)
    assert r.status_code == 200 and r.json()["reason"] == "LEDGER_MERGED", r.text


def _dev_result(branch, sha=SHA_A, **pr_over):
    pr = {"pr_number": 9, "pull_request_url": "https://example.invalid/o/r/pull/9", "head_ref": branch, "head_sha": sha,
          "head_repo_full_name": "o/r", "head_repo_id": 77, "base_ref": "main", "base_repo_full_name": "o/r",
          "base_repo_id": 77}
    pr.update(pr_over)
    return {"status": "COMMITTED", "repo_name": "o/r", "branch_name": branch, "commit_sha": sha, "base_branch": "main",
            "pull_request": pr}


def test_developer_ledger_write_is_identity_checked_and_fails_loud(rel, monkeypatch):
    gw, db, *_ = rel
    from shared import vcs_ledger
    monkeypatch.setattr(gw, "db", db)
    lid = gw._record_pr_ledger("tr-2", "app", "castor/app-2", _dev_result("castor/app-2"), vcs_ledger.ORIGIN_DEVELOPER)
    assert db.docs[f"vcs_ledger/{lid}"]["pr_number"] == 9
    # fork head / foreign commit: nothing recorded (so nothing can ever merge it)
    assert gw._record_pr_ledger("tr-2", "app", "castor/app-3", _dev_result("castor/app-3", head_repo_id=999),
                                vcs_ledger.ORIGIN_DEVELOPER) is None
    assert gw._record_pr_ledger("tr-2", "app", "castor/app-4", _dev_result("castor/app-4", head_sha=SHA_B),
                                vcs_ledger.ORIGIN_DEVELOPER) is None
    # the store refusing the write is a typed 503 for the developer stage (fail loud)
    db.fail_writes = True
    from gate_errors import GateUnavailableError
    with pytest.raises(GateUnavailableError):
        gw._record_pr_ledger("tr-2", "app", "castor/app-5", _dev_result("castor/app-5"), vcs_ledger.ORIGIN_DEVELOPER)


def test_gateway_reconcile_supersedes_only_this_products_earlier_ledger_prs(rel, monkeypatch):
    """FD-4P (owner row 23): reconcile reads the ledger; the current attempt, other products and anything not in
    the ledger (human PRs) are never passed to the provider."""
    gw, db, *_ = rel
    from shared import vcs_ledger
    import shared.vcs_provider as vp
    monkeypatch.setattr(gw, "db", db)
    for pid, branch in (("app", "castor/app-old"), ("app", "castor/app-now"), ("app-v2", "castor/app-v2-old")):
        vcs_ledger.record_created(db, provider="GITHUB", repo_full_name="o/r", repo_id=77, product_id=pid,
                                  trace_id="tr-0", origin=vcs_ledger.ORIGIN_DEVELOPER, branch=branch,
                                  base_branch="main", head_sha=SHA_A, pr_number=5, pr_url="u")
    fake = MagicMock()
    fake.reconcile_automated_pull_requests.return_value = {"status": "RECONCILED", "results": [
        {"branch": "castor/app-old", "pr_number": 5, "outcome": "SUPERSEDED"}]}
    monkeypatch.setattr(vp.VCSProviderFactory, "get_provider", staticmethod(lambda *a, **k: fake))
    monkeypatch.setattr(type(gw.developer_agent), "fetch_github_token", lambda self: "test-token")
    gw._reconcile_superseded_prs("app", "tr-1", keep_branch="castor/app-now")
    (call,) = fake.reconcile_automated_pull_requests.call_args_list
    names = sorted(i.branch for i in call.kwargs["superseded"])
    # the rel fixture's own entry (BRANCH) is an earlier open attempt of this product too
    assert names == sorted(["castor/app-old", BRANCH])
    assert db.docs[f"vcs_ledger/{vcs_ledger.ledger_id('GITHUB', 'o/r', 'castor/app-old')}"]["state"] == "SUPERSEDED"
    assert db.docs[f"vcs_ledger/{vcs_ledger.ledger_id('GITHUB', 'o/r', 'castor/app-now')}"]["state"] == "OPEN"
    assert db.docs[f"vcs_ledger/{vcs_ledger.ledger_id('GITHUB', 'o/r', 'castor/app-v2-old')}"]["state"] == "OPEN"



# ============================================================================ Fable code RT fixes
def test_rt_f1_serverless_git_release_never_auto_merges(rel):
    """Row 23 condition H6 -> SERVERLESS-AUTOMERGE-SHA: a git server that does not confirm the tested-commit check
    (the fixture's provider double does not) => the Serverless Git release goes to a human
    (tests/test_serverless_automerge_sha.py: the auto-merge once the server confirms it)."""
    gw, db, merge, _ = rel
    from shared import vcs_ledger
    db.docs = {k: v for k, v in db.docs.items() if not k.startswith("vcs_ledger/")}
    db.docs["workloads/app"] = {"require_human_code_review": False, "vcs_provider": "SERVERLESS_GIT"}
    vcs_ledger.record_created(db, provider="SERVERLESS_GIT", repo_full_name="o/r", repo_id=None, product_id="app",
                              trace_id="tr-1", origin=vcs_ledger.ORIGIN_DEVELOPER, branch=BRANCH, base_branch="main",
                              head_sha=SHA_A, pr_number=None, pr_url=None)
    db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["auto_merged"] is False and body["approval_id"]
    merge.assert_not_called()
    (appr,) = _approvals(db)
    assert appr["hitl_reason_code"] == "SERVERLESS_GIT_SOURCE_CHECK_UNSUPPORTED" and appr["pr_number"] is None
    assert "Serverless Git release needs a human approval" in appr["risk_assessment"]


def _serverless_release(rel, *, synthetic_url):
    gw, db, merge, _ = rel
    from shared import vcs_ledger
    db.docs = {k: v for k, v in db.docs.items() if not k.startswith("vcs_ledger/")}
    db.docs["workloads/app"] = {"require_human_code_review": False, "vcs_provider": "SERVERLESS_GIT"}
    vcs_ledger.record_created(db, provider="SERVERLESS_GIT", repo_full_name="o/r", repo_id=None, product_id="app",
                              trace_id="tr-1", origin=vcs_ledger.ORIGIN_DEVELOPER, branch=BRANCH, base_branch="main",
                              head_sha=SHA_A, pr_number=None, pr_url=synthetic_url)
    db.docs["qa_test_runs/tr-1"] = _evidence()
    return gw, db, merge, _promote(gw, expected_commit_sha=SHA_A)


@pytest.mark.parametrize("synthetic_url", [None, "https://git.example.invalid/git/app.git/refs/heads/x"])
def test_install_polish_serverless_git_card_names_the_branch_and_has_no_link(rel, synthetic_url):
    """install-polish: no Control Center route or git-server page shows a Serverless Git branch to a browser, so the
    approval card names the branch in plain text and carries no URL (the old `/workloads/<id>?tab=vcs` had no
    route; the provider's synthetic git-protocol URL is not a page either)."""
    gw, db, merge, r = _serverless_release(rel, synthetic_url=synthetic_url)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pull_request_url"] == "" and body["approval_id"]
    (appr,) = _approvals(db)
    assert appr["pull_request_url"] == ""
    text = appr["risk_assessment"]
    assert text.startswith(f"Release awaiting human review on branch {BRANCH} in the StackVend git server "
                           "(no pull request page; approving here merges it into main).")
    assert "tab=vcs" not in text and "/workloads/" not in text and "http" not in text.split("Blocking reasons")[0]
    assert "Serverless Git release needs a human approval" in text  # the RT F1 cause is still shown
    assert body["summary"] == f"Release awaiting human code review on branch {BRANCH} in the StackVend git server"
    merge.assert_not_called()


def test_install_polish_serverless_git_already_merged_summary_has_no_link(rel):
    gw, db, merge, _ = rel
    from shared import vcs_ledger
    _serverless_release(rel, synthetic_url="https://git.example.invalid/git/app.git/refs/heads/x")
    db.docs[f"vcs_ledger/{vcs_ledger.ledger_id('SERVERLESS_GIT', 'o/r', BRANCH)}"]["state"] = "MERGED"
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200, r.text
    assert r.json()["already_merged"] is True and r.json()["pull_request_url"] == ""
    assert r.json()["summary"].endswith(f"on branch {BRANCH} in the StackVend git server")


def test_install_polish_negative_github_card_keeps_the_pr_link(rel):
    """Negative: a GitHub release's card text and URL are unchanged (the PR's html_url from the ledger)."""
    gw, db, merge, _ = rel
    db.docs["workloads/app"]["require_human_code_review"] = True
    db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200, r.text
    (appr,) = _approvals(db)
    assert appr["pull_request_url"] == r.json()["pull_request_url"] == "https://github.com/o/r/pull/7"
    assert appr["risk_assessment"].startswith("Pull Request awaiting human review at https://github.com/o/r/pull/7. ")
    assert r.json()["summary"] == "Pull Request awaiting human code review at https://github.com/o/r/pull/7"


def test_rt_f4_release_re_invoked_after_the_merge_is_idempotent(rel):
    gw, db, merge, _ = rel
    db.docs["qa_test_runs/tr-1"] = _evidence()
    assert _promote(gw, expected_commit_sha=SHA_A).json()["auto_merged"] is True
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200, r.text
    assert (r.json()["status"], r.json()["auto_merged"], r.json()["already_merged"]) == ("SUCCESS", True, True)
    assert merge.call_count == 1  # never merged twice
    assert _approvals(db) == []


def test_rt_f4_merged_entry_of_another_trace_is_still_refused(rel):
    gw, db, merge, _ = rel
    from shared import vcs_ledger
    lid = vcs_ledger.ledger_id("GITHUB", "o/r", BRANCH)
    db.docs[f"vcs_ledger/{lid}"].update({"state": "MERGED", "trace_id": "tr-0"})
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 409 and r.json()["reason"] == "TRACE_MISMATCH"
    merge.assert_not_called()


def test_rt_f7_deploy_only_ignores_a_merged_entry_in_another_repository(rel):
    gw, db, merge, _ = rel
    from shared import vcs_ledger
    vcs_ledger.record_created(db, provider="GITHUB", repo_full_name="o/other", repo_id=78, product_id="app",
                              trace_id="tr-9", origin=vcs_ledger.ORIGIN_DEVELOPER, branch="castor/app-x",
                              base_branch="main", head_sha=SHA_A, pr_number=3, pr_url="u")
    vcs_ledger.mark(db, vcs_ledger.ledger_id("GITHUB", "o/other", "castor/app-x"), vcs_ledger.STATE_MERGED)
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: db
    r = TestClient(gw.app).post("/governance/deploy-only-gate", json={"trace_id": "tr-1", "product_id": "app",
                                                                       "branch": "castor/app-x"})
    assert r.status_code == 403, r.text


def test_rt_f3_handler_rest_fallback_pr_is_recorded(gw, monkeypatch):
    """The developer agent's PyGithub fallback returns the PR identity, so its PRs are recorded (not DLQ'd)."""
    from developer_agent import handler as hmod
    pr = MagicMock()
    pr.number, pr.html_url = 12, "https://example.invalid/o/r/pull/12"
    pr.head.ref, pr.head.sha, pr.head.repo.full_name, pr.head.repo.id = "castor/app-9", SHA_A, "o/r", 77
    pr.base.ref, pr.base.repo.full_name, pr.base.repo.id = "main", "o/r", 77
    ident = hmod._pr_identity_from_pull(pr)
    assert ident == {"pr_number": 12, "pull_request_url": "https://example.invalid/o/r/pull/12", "head_ref": "castor/app-9",
                     "head_sha": SHA_A, "head_repo_full_name": "o/r", "head_repo_id": 77, "base_ref": "main",
                     "base_repo_full_name": "o/r", "base_repo_id": 77}
    assert set(ident) == set(hmod.PR_IDENTITY_KEYS)
    from shared import vcs_ledger
    assert vcs_ledger.creation_problems("GITHUB", repo_full_name="o/r", branch="castor/app-9", base_branch="main",
                                        commit_sha=SHA_A, pull_request=ident) == []
