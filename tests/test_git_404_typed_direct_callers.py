"""GIT-404-TYPED-DIRECT-CALLERS (owner 11-07 blanket backlog approval; row text to confirm): the git server marks every
answer `X-StackVend-Git-Server: 1` (row GIT-404-TYPED). The two callers that talk to it over HTTP without
ServerlessGitProvider apply the provider's rule: a 404 means "not found" only with that header; a 404 without it is
the typed GIT_SERVER_UNREACHABLE (Cloud Run's front end refusing a caller, a wrong URL), never "not found".

- apps/orchestrator-gateway/qa_source.py `ServerlessGitSource` (QA / gatekeeper / release trees): GitServerUnreachable
  (a BranchFetchError, so every fail-closed caller stays fail-closed); the QA diff base `main` no longer turns it into
  "first run, empty base" (503 GATE_UNAVAILABLE, reason GIT_SERVER_UNREACHABLE).
- apps/refactor-scanner/scanner.py `ArchiveClient.fetch` (SERVERLESS_GIT): ScanFailed stage GIT_SERVER_UNREACHABLE
  with no http_status.
The other git-server readers go through ServerlessGitProvider (tf-applier tree read, gateway), whose own copies carry
the rule. Negatives: a marked 404 keeps today's meaning, any other status is unchanged, GitHub is untouched."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import json
import os
import sys
from types import SimpleNamespace

import pytest

import fd4f_support  # noqa: F401
from fd4f_support import (  # noqa: F401,F811  (gw is a fixture)
    SHA_A, FakeBackend, FakeDB, FakeQAClient, backend_factory, gw, judge_reply, make_tar, passing_outcome, seed_context)

from qa_source import BranchFetchError, GitServerUnreachable, ServerlessGitSource, fetch_tree_at_head
import qa_source

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RS_DIR = os.path.join(REPO_ROOT, "apps", "refactor-scanner")
HEADER = "X-StackVend-Git-Server"


class _Res:
    def __init__(self, status=200, content=b"", headers=None):
        self.status_code, self.content, self.headers = status, content, headers or {}


class _Http:
    def __init__(self, res):
        self.res, self.calls = res, []

    def get(self, url, **kw):
        self.calls.append(url)
        return self.res


def _src(res):
    return ServerlessGitSource("https://git.example", "app", {"Authorization": "Bearer t"}, _Http(res))


# --------------------------------------------------------------------------------------------- qa_source
@pytest.mark.parametrize("headers", [{}, {HEADER: "0"}, {HEADER: ""}, {"X-StackVend-Git": "1"}, {"Server": "1"}],
                         ids=["none", "other-value", "empty", "other-name", "unrelated"])
def test_unmarked_404_is_git_server_unreachable(headers):
    with pytest.raises(GitServerUnreachable) as ei:
        fetch_tree_at_head(_src(_Res(404, b"<html>404</html>", headers)), "main")
    assert isinstance(ei.value, BranchFetchError)   # every fail-closed caller stays fail-closed
    assert ei.value.error_class == "GIT_SERVER_UNREACHABLE" and ei.value.stage == "vcs"
    assert str(ei.value).startswith("GIT_SERVER_UNREACHABLE: ")


@pytest.mark.parametrize("name", [HEADER, HEADER.lower(), HEADER.upper()])
def test_negative_marked_404_keeps_branch_not_found(name):
    with pytest.raises(BranchFetchError) as ei:
        fetch_tree_at_head(_src(_Res(404, b"", {name: "1"})), "main")
    assert not isinstance(ei.value, GitServerUnreachable) and "HTTP 404" in str(ei.value)


@pytest.mark.parametrize("status", [401, 403, 500, 503])
def test_negative_other_statuses_are_unchanged(status):
    with pytest.raises(BranchFetchError) as ei:
        fetch_tree_at_head(_src(_Res(status, b"", {})), "main")
    assert not isinstance(ei.value, GitServerUnreachable) and f"HTTP {status}" in str(ei.value)


def test_negative_200_is_unchanged_with_or_without_the_marker():
    tar = make_tar({"a.py": b"x = 1\n"})
    for extra in ({}, {HEADER: "1"}):
        tree = fetch_tree_at_head(_src(_Res(200, tar, {"X-Commit-Sha": SHA_A, **extra})), "main")
        assert tree.commit_sha == SHA_A and tree.files_text == {"a.py": "x = 1\n"}


# --------------------------------------------------------------------------------------------- QA diff base
BRANCH = "castor/app-1"
TREE = {"apps/app/main.py": b"print('hi')\n", "apps/app/tests/test_a.py": b"def test_a():\n    assert True\n"}


class _UnreachableMain(FakeBackend):
    def head_sha(self, branch):
        if branch == "main":
            raise GitServerUnreachable("GIT_SERVER_UNREACHABLE: archive of 'main' returned HTTP 404 without the header")
        return super().head_sha(branch)


def _qa(gw, backend, monkeypatch):
    from fastapi.testclient import TestClient

    db = FakeDB()
    seed_context(db)
    client = FakeQAClient(passing_outcome())
    gw.app.dependency_overrides[gw.get_qa_job_client] = lambda: client
    gw.app.dependency_overrides[gw.get_source_backend_factory] = lambda: backend_factory(backend)
    gw.app.dependency_overrides[gw.get_evidence_db] = lambda: db
    import qa_auditor.judge as judge_mod

    monkeypatch.setattr(judge_mod, "call", judge_reply())
    r = TestClient(gw.app).post("/agent/qa/verify", json={"trace_id": "tr-1", "product_id": "app",
                                                          "branch_name": BRANCH})
    return r, client


def test_qa_diff_base_unreachable_is_gate_unavailable_never_an_empty_base(gw, monkeypatch):
    r, client = _qa(gw, _UnreachableMain({BRANCH: TREE}, {BRANCH: SHA_A}), monkeypatch)
    assert r.status_code == 503, r.text
    assert r.json()["error_class"] == "GATE_UNAVAILABLE" and r.json()["reason"] == "GIT_SERVER_UNREACHABLE"
    assert client.calls == []   # the QA job never ran against a guessed empty base


def test_negative_qa_diff_base_missing_main_still_diffs_against_an_empty_base(gw, monkeypatch):
    r, client = _qa(gw, FakeBackend({BRANCH: TREE}, {BRANCH: SHA_A}), monkeypatch)   # "main" not found (marked)
    assert r.status_code == 200, r.text
    assert r.json()["passed"] is True and len(client.calls) == 1


# --------------------------------------------------------------------------------------------- refactor scanner
@pytest.fixture()
def rs(monkeypatch):
    from fd4g_support import real_modules

    real_modules(monkeypatch)
    spec = importlib.util.spec_from_file_location("git404_rs_scanner", os.path.join(RS_DIR, "scanner.py"))
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "git404_rs_scanner", mod)
    spec.loader.exec_module(mod)
    return mod


def _client(rs, status, headers):
    def get(url, hdrs):
        if url.endswith("/github-token"):
            return 200, json.dumps({"token": "ghs_x"}).encode(), {}
        return status, (b"tar" if status == 200 else b"Not Found"), headers

    env = {"GIT_SERVER_URL": "https://git.run.app", "VENDING_SERVICE_URL": "https://vend.run.app"}
    return rs.ArchiveClient(env, http_get=get, id_token=lambda aud: "id")


@pytest.mark.parametrize("headers", [{}, {HEADER: "0"}, None], ids=["none", "other-value", "no-mapping"])
def test_scanner_unmarked_git_server_404_is_typed(rs, headers):
    with pytest.raises(rs.ScanFailed) as ei:
        _client(rs, 404, headers).fetch(rs.ScanTarget("app", "x/app", "main", "SERVERLESS_GIT"))
    assert ei.value.stage == "GIT_SERVER_UNREACHABLE" and ei.value.http_status is None


def test_negative_scanner_marked_404_is_the_archive_failure_as_before(rs):
    with pytest.raises(rs.ScanFailed) as ei:
        _client(rs, 404, {HEADER.lower(): "1"}).fetch(rs.ScanTarget("app", "x/app", "main", "SERVERLESS_GIT"))
    assert ei.value.stage == "ARCHIVE" and ei.value.http_status == 404


def test_negative_scanner_github_404_and_git_server_200_are_unchanged(rs):
    with pytest.raises(rs.ScanFailed) as ei:
        _client(rs, 404, {}).fetch(rs.ScanTarget("app", "acme/app", "main", "GITHUB"))
    assert ei.value.stage == "ARCHIVE" and ei.value.http_status == 404
    assert _client(rs, 200, {}).fetch(rs.ScanTarget("app", "x/app", "main", "SERVERLESS_GIT")) == b"tar"


def test_scanner_unmarked_404_is_never_not_configured(rs):
    """An unmarked 404 from the git server fails typed (SCAN_FAILED:GIT_SERVER_UNREACHABLE), never NOT_CONFIGURED."""
    saved = []
    s = SimpleNamespace(archives=_client(rs, 404, {}), _clock=lambda: __import__("datetime").datetime(2026, 11, 7),
                        _save_scan=saved.append)
    target = rs.ScanTarget("app", "x/app", "main", "SERVERLESS_GIT")
    report = rs.RefactorScanner.scan_target(s, target, "run-1")
    assert report["status"] == "SCAN_FAILED:GIT_SERVER_UNREACHABLE" and saved == [report]


# --------------------------------------------------------------------------------------------- one header contract
def _module_constants(path):
    out = {}
    for node in ast.parse(open(path).read()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and isinstance(node.value, ast.Constant):
            out[node.targets[0].id] = node.value.value
    return out


def test_every_copy_of_the_header_contract_is_identical(rs):
    want = ("X-StackVend-Git-Server", "1")
    assert (qa_source.GIT_SERVER_HEADER, qa_source.GIT_SERVER_HEADER_VALUE) == want
    assert (rs.GIT_SERVER_HEADER, rs.GIT_SERVER_HEADER_VALUE) == want
    # The server sets the header and the provider (every replica) reads it (row GIT-404-TYPED): all must match.
    rels = ["apps/git-server/main.py"] + sorted(
        os.path.relpath(os.path.join(d, f), REPO_ROOT)
        for base in ("shared", "apps", "mcp-servers") for d, _, fs in os.walk(os.path.join(REPO_ROOT, base))
        for f in fs if f == "serverless_git_provider.py")
    assert "shared/providers/serverless_git_provider.py" in rels
    for rel in rels:
        consts = _module_constants(os.path.join(REPO_ROOT, rel))
        assert (consts.get("GIT_SERVER_HEADER"), consts.get("GIT_SERVER_HEADER_VALUE")) == want, rel
