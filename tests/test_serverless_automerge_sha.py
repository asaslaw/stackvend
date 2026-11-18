"""SERVERLESS-AUTOMERGE-SHA (owner 10-29): the Serverless Git release merge is pinned to the QA-tested commit, like
GitHub's merge at the ledger head SHA, so a Serverless Git release may merge by itself again.

- git server: `expected_source_sha` on /merge; under the per-repo lock a source head that is not that commit is a
  typed 409 SOURCE_MOVED and nothing is written; no field = the old behavior; GET /api/v1/capabilities says so.
- client: sends the field; reports `source_sha_checked` only from the server's echo for exactly that commit; asks
  the server first (`merge_source_check_supported`), an older server (404) is never trusted.
- gateway: auto-merges a Serverless Git release only after the server confirms the check; an older or unreachable
  server keeps the approval (typed hitl_reason_code); SOURCE_MOVED takes GitHub's moved-head path; GitHub unchanged.
Hermetic: real git server app on a temp dir (fd4k_support), stubbed requests, FakeDB.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import shutil
import sys

import pytest
from fastapi.testclient import TestClient

from fd4f_support import SHA_A, SHA_B, gw  # noqa: F401
from fd4k_support import load_git_server
from test_fd4f_release_evidence import BRANCH, _approvals, _evidence, _promote, rel  # noqa: F401
from test_fd4k_serverless_git_client import SERVER, _Requests, _Resp, _provider, sgp  # noqa: F401


# ============================================================================ git server
@pytest.fixture()
def gs(monkeypatch):
    mod, client, outer = load_git_server(monkeypatch, import_name="sv_automerge_git_server_main")
    assert client.post("/api/v1/repos", json={"product_id": "app"}).status_code == 201
    assert client.post("/api/v1/repos/app/branches", json={"branch_name": "feature/x"}).status_code == 200
    yield mod, client, os.path.join(outer, "data")
    shutil.rmtree(outer, ignore_errors=True)


def _commit(client, branch, files):
    r = client.post("/api/v1/repos/app/commits", json={"branch": branch, "files": files})
    assert r.status_code == 200, r.text
    return r.json()["commit_sha"]


def _ref(data, branch):
    from dulwich.repo import Repo

    refs = Repo(os.path.join(data, "app.git")).refs
    key = f"refs/heads/{branch}".encode()
    return refs[key].decode() if key in refs else None


def _merge(client, **body):
    return client.post("/api/v1/repos/app/merge", json={"source_branch": "feature/x", **body})


def test_gs_moved_source_branch_is_refused_and_nothing_is_written(gs):
    _, client, data = gs
    tested = _commit(client, "feature/x", {"a.txt": "tested"})
    moved = _commit(client, "feature/x", {"a.txt": "pushed after QA"})
    main_before = _ref(data, "main")
    r = _merge(client, expected_source_sha=tested)
    assert r.status_code == 409, r.text
    body = r.json()
    assert (body["status"], body["reason_code"]) == ("CONFLICT", "SOURCE_MOVED")
    assert (body["expected_source_sha"], body["source_sha"], body["source_sha_checked"]) == (tested, moved, True)
    assert _ref(data, "main") == main_before  # nothing merged
    assert _ref(data, "feature/x") == moved  # source branch kept as it is


def test_gs_matching_sha_merges_and_echoes_the_check(gs):
    _, client, data = gs
    tested = _commit(client, "feature/x", {"a.txt": "tested"})
    r = _merge(client, expected_source_sha=tested)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "MERGED" and body["source_sha_checked"] is True and body["source_sha"] == tested
    assert _ref(data, "main") == body["commit_sha"] and _ref(data, "feature/x") is None
    files = client.get("/api/v1/repos/app/tree/main").json()["files"]
    assert files.get("a.txt") == "tested"


def test_gs_no_field_is_the_old_behavior(gs):
    _, client, data = gs
    head = _commit(client, "feature/x", {"a.txt": "x"})
    r = _merge(client)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "MERGED" and body["source_sha_checked"] is False and body["source_sha"] == head
    assert _ref(data, "feature/x") is None


def test_gs_already_up_to_date_is_checked_too(gs):
    _, client, data = gs
    main = _ref(data, "main")  # feature/x was cut from main and has no commit of its own
    r = _merge(client, expected_source_sha=SHA_A)
    assert r.status_code == 409 and r.json()["reason_code"] == "SOURCE_MOVED"
    assert _ref(data, "feature/x") == main  # kept
    r = _merge(client, expected_source_sha=main)
    assert r.status_code == 200 and r.json()["status"] == "ALREADY_UP_TO_DATE" and r.json()["source_sha_checked"] is True


def test_gs_target_advanced_keeps_its_own_reason_code(gs):
    _, client, data = gs
    tested = _commit(client, "feature/x", {"a.txt": "f"})
    _commit(client, "main", {"hotfix.txt": "h"})
    r = _merge(client, expected_source_sha=tested)
    assert r.status_code == 409, r.text
    assert (r.json()["reason_code"], r.json()["source_sha_checked"]) == ("TARGET_ADVANCED", True)
    assert _ref(data, "feature/x") == tested


@pytest.mark.parametrize("bad", ["E" * 40, "e" * 39, "main", "", 7])
def test_gs_malformed_expected_sha_is_422_and_nothing_merged(gs, bad):
    _, client, data = gs
    head = _commit(client, "feature/x", {"a.txt": "x"})
    main = _ref(data, "main")
    assert _merge(client, expected_source_sha=bad).status_code == 422
    assert (_ref(data, "main"), _ref(data, "feature/x")) == (main, head)


def test_gs_the_check_runs_under_the_per_repo_lock(gs, monkeypatch):
    mod, client, _ = gs
    tested = _commit(client, "feature/x", {"a.txt": "x"})
    real, seen = mod.merge_branch_dulwich, []

    def _spy(*args, **kwargs):
        seen.append((mod.get_repo_lock("app").locked(), kwargs.get("expected_source_sha")))
        return real(*args, **kwargs)

    monkeypatch.setattr(mod, "merge_branch_dulwich", _spy)
    assert _merge(client, expected_source_sha=tested).status_code == 200
    assert seen == [(True, tested)]
    assert not mod.get_repo_lock("app").locked()


def test_gs_capabilities_route_is_authenticated(gs):
    mod, client, _ = gs
    r = client.get("/api/v1/capabilities")
    assert r.status_code == 200 and r.json()["capabilities"]["merge_expected_source_sha"] is True
    assert TestClient(mod.app).get("/api/v1/capabilities").status_code == 401


# ============================================================================ client (ServerlessGitProvider)
def _merge_call(sgp, monkeypatch, resp, **kw):
    fake = _Requests(resp)
    monkeypatch.setattr(sgp, "requests", fake)
    out = _provider(sgp).merge_pull_request("castor/app", pr_number=0, source_branch=BRANCH, target_branch="main", **kw)
    return out, fake


def test_client_sends_the_sha_and_trusts_only_the_exact_echo(sgp, monkeypatch):
    out, fake = _merge_call(sgp, monkeypatch, _Resp(200, {"status": "MERGED", "commit_sha": "c", "source_sha": SHA_A,
                                                          "source_sha_checked": True}), expected_source_sha=SHA_A)
    (_, url, kw), = fake.calls
    assert url.endswith("/api/v1/repos/app/merge") and kw["json"]["expected_source_sha"] == SHA_A
    assert out["merged"] is True and out["source_sha_checked"] is True


@pytest.mark.parametrize("label,body", [
    ("old_server_no_echo", {"status": "MERGED", "commit_sha": "c"}),
    ("echo_other_commit", {"status": "MERGED", "commit_sha": "c", "source_sha": SHA_B, "source_sha_checked": True}),
    ("echo_not_bool", {"status": "MERGED", "commit_sha": "c", "source_sha": SHA_A, "source_sha_checked": "true"}),
    ("echo_false", {"status": "MERGED", "commit_sha": "c", "source_sha": SHA_A, "source_sha_checked": False}),
])
def test_client_old_or_odd_echo_is_never_a_checked_merge(sgp, monkeypatch, label, body):
    out, _ = _merge_call(sgp, monkeypatch, _Resp(200, body), expected_source_sha=SHA_A)
    assert out["merged"] is True and out["source_sha_checked"] is False, label


def test_negative_client_without_the_sha_sends_the_old_request(sgp, monkeypatch):
    out, fake = _merge_call(sgp, monkeypatch, _Resp(200, {"status": "MERGED", "commit_sha": "c"}))
    (_, _, kw), = fake.calls
    assert "expected_source_sha" not in kw["json"] and out["source_sha_checked"] is False


def test_client_source_moved_409_is_a_typed_head_sha_mismatch(sgp, monkeypatch):
    from shared.vcs_provider import PRIdentityMismatch

    resp = _Resp(409, {"status": "CONFLICT", "reason_code": "SOURCE_MOVED", "source_sha": SHA_B})
    with pytest.raises(sgp.ServerlessGitSourceMoved) as ei:
        _merge_call(sgp, monkeypatch, resp, expected_source_sha=SHA_A)
    err = ei.value
    assert isinstance(err, PRIdentityMismatch) and not isinstance(err, sgp.ServerlessGitMergeConflict)
    assert (err.field, err.expected, err.actual, err.error_class) == ("head_sha", SHA_A, SHA_B, "SOURCE_MOVED")


@pytest.mark.parametrize("body", [{"status": "CONFLICT", "reason_code": "TARGET_ADVANCED"},
                                  {"status": "CONFLICT", "reason": "target advanced since the branch point"}])
def test_negative_client_target_conflict_is_still_main_moved(sgp, monkeypatch, body):
    with pytest.raises(sgp.ServerlessGitMergeConflict) as ei:
        _merge_call(sgp, monkeypatch, _Resp(409, body), expected_source_sha=SHA_A)
    assert not isinstance(ei.value, sgp.ServerlessGitSourceMoved) and ei.value.body == body


def test_client_non_json_409_has_an_empty_body(sgp, monkeypatch):
    class _Bad(_Resp):
        def json(self):
            raise ValueError("not json")

    with pytest.raises(sgp.ServerlessGitMergeConflict) as ei:
        _merge_call(sgp, monkeypatch, _Bad(409), expected_source_sha=SHA_A)
    assert ei.value.body == {}


def test_client_malformed_sha_is_refused_before_any_call(sgp, monkeypatch):
    fake = _Requests(_Resp(200, {"status": "MERGED"}))
    monkeypatch.setattr(sgp, "requests", fake)
    with pytest.raises(sgp.ServerlessGitError):
        _provider(sgp).merge_pull_request("castor/app", pr_number=0, source_branch=BRANCH,
                                          expected_source_sha=SHA_A.upper())
    assert fake.calls == []


@pytest.mark.parametrize("label,resp,expected", [
    ("new_server", _Resp(200, {"capabilities": {"merge_expected_source_sha": True}}), True),
    ("old_server_404", _Resp(404, {"detail": "Not Found"}), False),
    ("no_capability", _Resp(200, {"capabilities": {}}), False),
    ("string_true", _Resp(200, {"capabilities": {"merge_expected_source_sha": "true"}}), False),
    ("not_a_dict", _Resp(200, ["merge_expected_source_sha"]), False),
])
def test_client_capability_probe(sgp, monkeypatch, label, resp, expected):
    fake = _Requests(resp)
    monkeypatch.setattr(sgp, "requests", fake)
    assert _provider(sgp).merge_source_check_supported() is expected, label
    (method, url, _), = fake.calls
    assert (method, url) == ("get", f"{SERVER}/api/v1/capabilities")


@pytest.mark.parametrize("code,exc_name", [(500, "ServerlessGitError"), (403, "ServerlessGitAuthError")])
def test_client_capability_probe_failure_raises(sgp, monkeypatch, code, exc_name):
    monkeypatch.setattr(sgp, "requests", _Requests(_Resp(code, {})))
    with pytest.raises(getattr(sgp, exc_name)):
        _provider(sgp).merge_source_check_supported()


# ============================================================================ gateway release
class _Vcs:
    """Serverless Git provider double: the capability answer and the merge outcome."""

    def __init__(self, supported=True, result=None, exc=None, probe_exc=None):
        self.supported, self.exc, self.probe_exc = supported, exc, probe_exc
        self.result = result if result is not None else {"status": "MERGED", "merged": True, "commit_sha": "c0",
                                                         "source_sha_checked": True}
        self.merges, self.probes = [], 0

    def merge_source_check_supported(self):
        self.probes += 1
        if self.probe_exc is not None:
            raise self.probe_exc
        return self.supported

    def merge_pull_request(self, repo, **kwargs):
        self.merges.append(kwargs)
        if self.exc is not None:
            raise self.exc
        return self.result


def _sgp_of(gw):
    return sys.modules[gw.ServerlessGitMergeConflict.__module__]


def _serverless_release(rel, monkeypatch, vcs, *, require_review=False):
    gw, db, merge, _ = rel
    from shared import vcs_ledger

    db.docs = {k: v for k, v in db.docs.items() if not k.startswith("vcs_ledger/")}
    db.docs["workloads/app"] = {"require_human_code_review": require_review, "vcs_provider": "SERVERLESS_GIT"}
    vcs_ledger.record_created(db, provider="SERVERLESS_GIT", repo_full_name="o/r", repo_id=None, product_id="app",
                              trace_id="tr-1", origin=vcs_ledger.ORIGIN_DEVELOPER, branch=BRANCH, base_branch="main",
                              head_sha=SHA_A, pr_number=None, pr_url=None)
    db.docs["qa_test_runs/tr-1"] = _evidence()
    monkeypatch.setattr(gw, "_release_vcs", lambda kind, pid, repo: vcs)
    return gw, db, _promote(gw, expected_commit_sha=SHA_A)


def _ledger_doc(db, provider="SERVERLESS_GIT"):
    from shared import vcs_ledger
    return db.docs[f"vcs_ledger/{vcs_ledger.ledger_id(provider, 'o/r', BRANCH)}"]


def test_gw_serverless_auto_merges_when_the_server_confirms_the_check(rel, monkeypatch):
    vcs = _Vcs()
    gw, db, r = _serverless_release(rel, monkeypatch, vcs)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["auto_merged"] is True and body["approval_id"] == "" and body["hitl_reason_code"] is None
    (kw,) = vcs.merges
    assert kw["expected_source_sha"] == SHA_A  # the ledger head = the QA-tested commit
    assert (kw["source_branch"], kw["target_branch"]) == (BRANCH, "main")
    assert vcs.probes == 1 and _approvals(db) == [] and _ledger_doc(db)["state"] == "MERGED"


def test_gw_old_git_server_keeps_the_approval(rel, monkeypatch):
    vcs = _Vcs(supported=False)
    gw, db, r = _serverless_release(rel, monkeypatch, vcs)
    assert r.status_code == 200, r.text
    assert r.json()["auto_merged"] is False and r.json()["hitl_reason_code"] == "SERVERLESS_GIT_SOURCE_CHECK_UNSUPPORTED"
    assert vcs.merges == []
    (appr,) = _approvals(db)
    assert appr["hitl_reason_code"] == "SERVERLESS_GIT_SOURCE_CHECK_UNSUPPORTED"
    text = appr["risk_assessment"]
    assert "cannot refuse a release branch that changed after QA tested it" in text
    assert "workload policy" not in text and "update the git server" in text


def test_gw_unreadable_capabilities_keep_the_approval_and_say_why(rel, monkeypatch):
    gw = rel[0]
    vcs = _Vcs(probe_exc=_sgp_of(gw).ServerlessGitError("Serverless Git GET /api/v1/capabilities returned HTTP 503"))
    gw, db, r = _serverless_release(rel, monkeypatch, vcs)
    assert r.status_code == 200, r.text
    assert r.json()["hitl_reason_code"] == "SERVERLESS_GIT_SOURCE_CHECK_UNCONFIRMED" and vcs.merges == []
    (appr,) = _approvals(db)
    assert "could not be asked" in appr["risk_assessment"] and "HTTP 503" in appr["risk_assessment"]


def test_negative_gw_serverless_review_required_never_probes(rel, monkeypatch):
    vcs = _Vcs()
    gw, db, r = _serverless_release(rel, monkeypatch, vcs, require_review=True)
    assert r.status_code == 200 and r.json()["auto_merged"] is False and r.json()["hitl_reason_code"] is None
    assert vcs.probes == 0 and vcs.merges == []
    (appr,) = _approvals(db)
    assert "HITL enforced by workload policy" in appr["risk_assessment"]


def test_gw_source_moved_takes_githubs_moved_head_path(rel, monkeypatch):
    """Like GitHub's 409 (PRIdentityMismatch on head_sha): nothing merged, MERGE_FAILED, a card that says the
    merge was refused (never MAIN_MOVED, never a silent card); approving that card is refused again (CC test)."""
    gw = rel[0]
    vcs = _Vcs(exc=_sgp_of(gw).ServerlessGitSourceMoved(SHA_A, SHA_B))
    gw, db, r = _serverless_release(rel, monkeypatch, vcs)
    assert r.status_code == 200, r.text
    assert r.json()["auto_merged"] is False and r.json()["approval_id"]
    (appr,) = _approvals(db)
    assert "Auto-merge refused: PR identity mismatch on head_sha" in appr["risk_assessment"]
    assert SHA_B in appr["risk_assessment"]
    assert _ledger_doc(db)["state"] == "MERGE_FAILED"


def test_gw_unconfirmed_echo_after_a_confirmed_probe_stops_typed(rel, monkeypatch):
    vcs = _Vcs(result={"status": "MERGED", "merged": True, "commit_sha": "c0", "source_sha_checked": False})
    gw, db, r = _serverless_release(rel, monkeypatch, vcs)
    assert r.status_code == 503, r.text
    body = r.json()
    assert (body["error_class"], body["reason"], body["stage"]) == ("PLATFORM_DEFECT", "SOURCE_CHECK_UNCONFIRMED", "release")
    assert _approvals(db) == []
    entry = _ledger_doc(db)
    assert entry["state"] == "MERGED" and entry["state_reason"].startswith("SOURCE_CHECK_UNCONFIRMED")


def test_gw_unconfirmed_echo_ends_the_workflow_run_typed(rel, monkeypatch):
    from test_lane17_workflow_sim import TF, Fleet, assert_failed, calls, run
    from workflow_sim import load_workflow

    vcs = _Vcs(result={"status": "MERGED", "merged": True, "commit_sha": "c0"})
    gw, db, r = _serverless_release(rel, monkeypatch, vcs)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    wf = load_workflow(os.path.join(root, "workflows", "main_orchestrator.yaml"))
    res, _ = run(wf, Fleet(**{"/agent/release/promote": (r.status_code, r.json())}))
    assert res.state == "FAILED" and res.error["error_class"] == "PLATFORM_DEFECT"
    assert not calls(res, "/events/approval-callback") and not calls(res, TF)


def test_gw_real_provider_end_to_end(rel, monkeypatch):
    """The gateway with the real ServerlessGitProvider (stubbed HTTP): probe, then a merge that names the commit."""
    gw = rel[0]
    mod = _sgp_of(gw)
    monkeypatch.setenv("CASTOR_GIT_AUTH_TOKEN", "test-id-token")
    monkeypatch.setenv("GOOGLE_OIDC_ID_TOKEN", "test-id-token")

    class _Http:
        def __init__(self):
            self.calls = []

        def get(self, url, **kw):
            self.calls.append(("get", url, kw))
            return _Resp(200, {"capabilities": {"merge_expected_source_sha": True}})

        def post(self, url, **kw):
            self.calls.append(("post", url, kw))
            return _Resp(200, {"status": "MERGED", "commit_sha": "c0", "source_sha": SHA_A, "source_sha_checked": True})

    http = _Http()
    monkeypatch.setattr(mod, "requests", http)
    provider = mod.ServerlessGitProvider(server_url=SERVER, project_id="mock-stackvend-project")
    gw, db, r = _serverless_release(rel, monkeypatch, provider)
    assert r.status_code == 200 and r.json()["auto_merged"] is True, r.text
    assert [c[0] for c in http.calls] == ["get", "post"]
    assert http.calls[1][2]["json"]["expected_source_sha"] == SHA_A


def test_negative_gw_github_path_is_unchanged(rel, monkeypatch):
    gw, db, merge, _ = rel
    db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200 and r.json()["auto_merged"] is True and r.json()["hitl_reason_code"] is None
    (call,) = merge.call_args_list
    assert "expected_source_sha" not in call.kwargs and "expected" in call.kwargs
    assert "source_sha_checked" not in merge.return_value  # GitHub results are not asked for the echo


def test_negative_gw_serverless_main_moved_is_still_main_moved(rel, monkeypatch):
    gw = rel[0]
    vcs = _Vcs(exc=_sgp_of(gw).ServerlessGitMergeConflict("conflict", body={"reason_code": "TARGET_ADVANCED"}))
    gw, db, r = _serverless_release(rel, monkeypatch, vcs)
    assert r.status_code == 409 and r.json()["error_class"] == "MAIN_MOVED"
    assert _approvals(db) == []


# ============================================================================ RT fixes (APPROVE WITH FIXES)
def test_rt_f1_reinvoke_after_an_unconfirmed_merge_is_refused_typed(rel, monkeypatch):
    vcs = _Vcs(result={"status": "MERGED", "merged": True, "commit_sha": "c0", "source_sha_checked": False})
    gw, db, r = _serverless_release(rel, monkeypatch, vcs)
    assert r.status_code == 503, r.text
    entry = _ledger_doc(db)
    assert entry["state"] == "MERGED" and entry["source_check_confirmed"] is False
    again = _promote(gw, expected_commit_sha=SHA_A)
    assert again.status_code == 409, again.text
    body = again.json()
    assert (body["error_class"], body["reason"], body["stage"]) == ("RELEASE_FAILED", "MERGE_UNCONFIRMED", "release")
    assert body.get("auto_merged") is not True and body.get("status") != "SUCCESS"
    assert len(vcs.merges) == 1 and _approvals(db) == []  # never merged again, no card


def test_rt_f1_negative_confirmed_merge_reinvoke_is_still_idempotent(rel, monkeypatch):
    vcs = _Vcs()
    gw, db, r = _serverless_release(rel, monkeypatch, vcs)
    assert r.status_code == 200 and r.json()["auto_merged"] is True
    assert _ledger_doc(db)["source_check_confirmed"] is True
    again = _promote(gw, expected_commit_sha=SHA_A)
    assert again.status_code == 200 and again.json()["already_merged"] is True and again.json()["auto_merged"] is True
    assert len(vcs.merges) == 1


def test_rt_f1_negative_github_ledger_has_no_source_check_field(rel):
    gw, db, merge, _ = rel
    db.docs["qa_test_runs/tr-1"] = _evidence()
    assert _promote(gw, expected_commit_sha=SHA_A).json()["auto_merged"] is True
    entry = _ledger_doc(db, provider="GITHUB")
    assert entry["state"] == "MERGED" and "source_check_confirmed" not in entry
    again = _promote(gw, expected_commit_sha=SHA_A)
    assert again.status_code == 200 and again.json()["already_merged"] is True


def _requests_connection_error():
    import requests

    return requests.ConnectionError("reset")


@pytest.mark.parametrize("label,make_exc", [
    ("requests_connection", _requests_connection_error),
    ("os_error", lambda: OSError("network unreachable")),
])
def test_rt_f4_transport_errors_keep_the_approval(rel, monkeypatch, label, make_exc):
    vcs = _Vcs(probe_exc=make_exc())
    gw, db, r = _serverless_release(rel, monkeypatch, vcs)
    assert r.status_code == 200, (label, r.text)
    assert r.json()["hitl_reason_code"] == "SERVERLESS_GIT_SOURCE_CHECK_UNCONFIRMED" and vcs.merges == []


@pytest.mark.parametrize("exc", [TypeError("bad call"), KeyError("x"), AttributeError("no such method")])
def test_rt_f4_a_platform_defect_in_the_probe_is_typed_not_a_card(rel, monkeypatch, exc):
    vcs = _Vcs(probe_exc=exc)
    gw, db, r = _serverless_release(rel, monkeypatch, vcs)
    assert r.status_code == 503, r.text
    body = r.json()
    assert (body["error_class"], body["reason"], body["stage"]) == ("PLATFORM_DEFECT", "SOURCE_CHECK_PROBE_FAILED", "release")
    assert _approvals(db) == [] and vcs.merges == []


def test_rt_f6_user_guide_names_the_upgrade_iac_pin():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "documentation", "user-guide.md"), encoding="utf-8") as fh:
        guide = fh.read()
    assert "approving an **Upgrade IaC** card on Serverless Git: the upgrade is merged at the upgrade commit" in guide
