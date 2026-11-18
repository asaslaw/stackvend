"""FD-4K / FD-4V client side: ServerlessGitProvider sends only ID tokens (dual header), fails closed, and surfaces 409.

Hermetic: requests and google.oauth2.id_token.fetch_id_token are stubbed; socket.connect is blocked.
"""
import hermetic_guard  # noqa: F401  (lane 2: must be the first import)

import hashlib
import os
import socket

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPLICA_DIRS = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared",
                "apps/project-vending/shared", "apps/qa-runner/shared", "mcp-servers/github/shared",
                "mcp-servers/terraform/shared"]
SERVER = "https://castor-git-server-test.a.run.app"


@pytest.fixture()
def sgp(monkeypatch):
    from fd4g_support import real_modules

    real_modules(monkeypatch)

    def _blocked(self, addr):
        raise OSError(f"network blocked in FD-4K client test: {addr}")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    for k in ("GOOGLE_OIDC_ID_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN", "CASTOR_GIT_AUTH_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    import google.oauth2.id_token as id_token_mod
    from shared.providers import serverless_git_provider as mod

    audiences = []

    def _fetch(_req, audience):
        audiences.append(audience)
        return "ID.TOKEN.SIG"

    monkeypatch.setattr(id_token_mod, "fetch_id_token", _fetch)
    mod._fd4k_audiences = audiences
    return mod


# GIT-404-TYPED: every answer of the real git server carries this header (tests/test_git404_typed_contract.py covers
# a 404 without it: GitServerUnreachable).
GIT_SERVER_HEADERS = {"X-StackVend-Git-Server": "1"}


class _Resp:
    def __init__(self, code, body=None, content=b""):
        self.status_code, self._body, self.content, self.text = code, body if body is not None else {}, content, "x"
        self.headers = dict(GIT_SERVER_HEADERS)

    def json(self):
        return self._body


class _Requests:
    def __init__(self, resp=None, exc=None):
        self.resp, self.exc, self.calls = resp, exc, []

    def _do(self, method, url, **kw):
        self.calls.append((method, url, kw))
        if self.exc:
            raise self.exc
        return self.resp

    def get(self, url, **kw):
        return self._do("get", url, **kw)

    def post(self, url, **kw):
        return self._do("post", url, **kw)


def _provider(mod, **kw):
    return mod.ServerlessGitProvider(server_url=SERVER, project_id="mock-stackvend-project", **kw)


def test_dual_header_id_token_with_origin_audience(sgp, monkeypatch):
    fake = _Requests(_Resp(200, {"commit_sha": "abc"}))
    monkeypatch.setattr(sgp, "requests", fake)
    assert _provider(sgp).commit_files("castor/app", "main", {"a": "b"}, "m") == "abc"
    method, url, kw = fake.calls[0]
    assert url == f"{SERVER}/api/v1/repos/app/commits"
    assert kw["headers"]["Authorization"] == "Bearer ID.TOKEN.SIG"
    assert kw["headers"]["X-Serverless-Authorization"] == "Bearer ID.TOKEN.SIG"
    assert kw["allow_redirects"] is False
    assert sgp._fd4k_audiences == [SERVER]


def test_never_sends_an_access_token(sgp, monkeypatch):
    import google.auth
    import google.oauth2.id_token as id_token_mod

    class _Creds:
        token = "ya29.ACCESS-TOKEN"
        id_token = "user-id-token-wrong-aud"
        valid = True

    monkeypatch.setattr(google.auth, "default", lambda *a, **k: (_Creds(), "p"))
    monkeypatch.setenv("GOOGLE_OAUTH_ACCESS_TOKEN", "ya29.ENV-ACCESS-TOKEN")

    def _no_id_token(_req, audience):
        raise RuntimeError("no ID token source")

    monkeypatch.setattr(id_token_mod, "fetch_id_token", _no_id_token)
    fake = _Requests(_Resp(200, {"commit_sha": "abc"}))
    monkeypatch.setattr(sgp, "requests", fake)
    p = _provider(sgp)
    assert p._resolve_iam_token() is None
    with pytest.raises(sgp.ServerlessGitAuthError):
        p.commit_files("app", "main", {"a": "b"}, "m")
    assert fake.calls == []


@pytest.mark.parametrize("code", [401, 403])
def test_auth_rejection_raises_everywhere(sgp, monkeypatch, code):
    monkeypatch.setattr(sgp, "requests", _Requests(_Resp(code)))
    p = _provider(sgp)
    for call in (lambda: p.commit_files("app", "main", {"a": "b"}, "m"),
                 lambda: p.fetch_file_tree("app"),
                 lambda: p.fetch_file_content("app", "README.md"),
                 lambda: p.create_or_verify_branch("app", "feature/x"),
                 lambda: p.vend_repository("app"),
                 lambda: p.merge_pull_request("app", 1, source_branch="feature/x"),
                 lambda: p.export_archive_stream("app")):
        with pytest.raises(sgp.ServerlessGitAuthError):
            call()


def test_commit_failure_never_fakes_a_sha(sgp, monkeypatch):
    monkeypatch.setattr(sgp, "requests", _Requests(_Resp(500)))
    with pytest.raises(sgp.ServerlessGitError):
        _provider(sgp).commit_files("app", "main", {"a": "b"}, "m")
    monkeypatch.setattr(sgp, "requests", _Requests(exc=ConnectionError("down")))
    with pytest.raises(sgp.ServerlessGitError):
        _provider(sgp).commit_files("app", "main", {"a": "b"}, "m")


def test_merge_conflict_raises(sgp, monkeypatch):
    monkeypatch.setattr(sgp, "requests", _Requests(_Resp(409, {"status": "CONFLICT"})))
    with pytest.raises(sgp.ServerlessGitMergeConflict):
        _provider(sgp).merge_pull_request("app", 1, source_branch="feature/x")


@pytest.mark.parametrize("resp,exc", [(_Resp(500), None), (_Resp(200, {"status": "WEIRD"}), None),
                                      (None, ConnectionError("down"))])
def test_merge_failure_never_reports_merged(sgp, monkeypatch, resp, exc):
    monkeypatch.setattr(sgp, "requests", _Requests(resp, exc))
    with pytest.raises(sgp.ServerlessGitError):
        _provider(sgp).merge_pull_request("app", 1, source_branch="feature/x")


@pytest.mark.parametrize("status", ["MERGED", "ALREADY_UP_TO_DATE"])
def test_merge_success(sgp, monkeypatch, status):
    monkeypatch.setattr(sgp, "requests", _Requests(_Resp(200, {"status": status, "commit_sha": "c"})))
    res = _provider(sgp).merge_pull_request("app", 1, source_branch="feature/x")
    assert res["merged"] is True and res["status"] == status


def test_missing_requests_package_raises(sgp, monkeypatch):
    monkeypatch.setattr(sgp, "requests", None)
    p = _provider(sgp)
    with pytest.raises(sgp.ServerlessGitError):
        p.commit_files("app", "main", {"a": "b"}, "m")
    with pytest.raises(sgp.ServerlessGitError):
        p.merge_pull_request("app", 1, source_branch="feature/x")
    with pytest.raises(sgp.ServerlessGitError):
        p.vend_repository("app")


def test_not_found_reads(sgp, monkeypatch):
    """Register row 40: a 404 on tree/blob (missing repo or branch) raises ServerlessGitNotFound; only a missing file
    on an existing branch (`X-Git-Not-Found: file`) stays ''. The legacy archive stream is unchanged."""
    monkeypatch.setattr(sgp, "requests", _Requests(_Resp(404)))
    p = _provider(sgp)
    with pytest.raises(sgp.ServerlessGitNotFound):
        p.fetch_file_tree("app")
    with pytest.raises(sgp.ServerlessGitNotFound):
        p.fetch_file_content("app", "x")
    assert p.export_archive_stream("app").read() == b""
    for hdr in ({}, {"X-Git-Not-Found": "branch"}, {"X-Git-Not-Found": "File"}):
        monkeypatch.setattr(sgp, "requests", _Requests(_HResp(404, headers=hdr)))
        with pytest.raises(sgp.ServerlessGitNotFound):
            p.fetch_file_content("app", "x")
    monkeypatch.setattr(sgp, "requests", _Requests(_HResp(404, headers={"X-Git-Not-Found": "file"})))
    assert p.fetch_file_content("app", "x") == ""


def test_tree_and_blob_urls_carry_slashed_branch(sgp, monkeypatch):
    fake = _Requests(_HResp(200, {"files": {"a": "b"}, "content": "c"}))
    monkeypatch.setattr(sgp, "requests", fake)
    p = _provider(sgp)
    assert p.fetch_file_tree("castor/app", "castor/app-1a2b3c", max_files=10) == {"a": "b"}
    assert p.fetch_file_content("castor/app", "/infra/main.tf", "castor/app-1a2b3c") == "c"
    assert [c[1] for c in fake.calls] == [f"{SERVER}/api/v1/repos/app/tree/castor/app-1a2b3c?max_files=10",
                                          f"{SERVER}/api/v1/repos/app/blob/castor/app-1a2b3c/infra/main.tf"]
    with pytest.raises(sgp.ServerlessGitError):
        p.fetch_file_tree("app", "")


def test_clone_auth_has_no_userinfo(sgp):
    url, headers = _provider(sgp).get_clone_auth("castor/app")
    assert url == f"{SERVER}/git/app.git"
    assert "@" not in url
    assert dict(headers) == {"Authorization": "Bearer ID.TOKEN.SIG", "X-Serverless-Authorization": "Bearer ID.TOKEN.SIG"}


@pytest.mark.parametrize("ident,expected", [("castor/app.git", "app"), ("app", "app"), ("serverless-git/my-app", "my-app")])
def test_clean_product_id_ok(sgp, ident, expected):
    assert _provider(sgp)._clean_product_id(ident) == expected


@pytest.mark.parametrize("ident", ["castor/team.gitops", "Team", "a_b", "..", "castor/", "app.git.git"])
def test_clean_product_id_rejects(sgp, ident):
    with pytest.raises(ValueError):
        _provider(sgp)._clean_product_id(ident)


def test_provider_replica_parity():
    rel = os.path.join("providers", "serverless_git_provider.py")
    digests = {d: hashlib.sha256(open(os.path.join(REPO_ROOT, d, rel), "rb").read()).hexdigest() for d in REPLICA_DIRS}
    assert len(set(digests.values())) == 1, digests


# ------------------------------------------------------------------ 19c: commit-bound archive (X-Commit-Sha)

GOOD_SHA = "0123456789abcdef0123456789abcdef01234567"


class _HResp(_Resp):
    def __init__(self, code, body=None, content=b"", headers=None):
        super().__init__(code, body, content)
        self.headers = {**GIT_SERVER_HEADERS, **(headers if headers is not None else {})}


def test_export_archive_with_sha_returns_header_sha_and_body(sgp, monkeypatch):
    fake = _Requests(_HResp(200, content=b"\x1f\x8bTAR", headers={"X-Commit-Sha": GOOD_SHA}))
    monkeypatch.setattr(sgp, "requests", fake)
    sha, content = _provider(sgp).export_archive_with_sha("castor/app", "castor/app-1a2b3c")
    assert (sha, content) == (GOOD_SHA, b"\x1f\x8bTAR")
    method, url, kw = fake.calls[0]
    assert method == "get" and url == f"{SERVER}/api/v1/repos/app/archive/castor/app-1a2b3c"
    assert kw["headers"]["Authorization"] == kw["headers"]["X-Serverless-Authorization"] == "Bearer ID.TOKEN.SIG"
    assert kw["allow_redirects"] is False


@pytest.mark.parametrize("headers", [{}, {"X-Commit-Sha": ""}, {"X-Commit-Sha": GOOD_SHA.upper()},
                                     {"X-Commit-Sha": GOOD_SHA[:39]}, {"X-Commit-Sha": GOOD_SHA + "0"},
                                     {"X-Commit-Sha": "g" * 40}, {"X-Commit-Sha": "HEAD"}])
def test_export_archive_with_sha_fails_closed_without_a_valid_header(sgp, monkeypatch, headers):
    monkeypatch.setattr(sgp, "requests", _Requests(_HResp(200, content=b"\x1f\x8bTAR", headers=headers)))
    with pytest.raises(sgp.ServerlessGitError):
        _provider(sgp).export_archive_with_sha("app", "main")


def test_export_archive_with_sha_rejects_empty_body_and_missing_branch(sgp, monkeypatch):
    monkeypatch.setattr(sgp, "requests", _Requests(_HResp(200, content=b"", headers={"X-Commit-Sha": GOOD_SHA})))
    with pytest.raises(sgp.ServerlessGitError):
        _provider(sgp).export_archive_with_sha("app", "main")
    monkeypatch.setattr(sgp, "requests", _Requests(_HResp(404)))
    with pytest.raises(sgp.ServerlessGitNotFound):
        _provider(sgp).export_archive_with_sha("app", "nope")


@pytest.mark.parametrize("resp,exc,err", [(_HResp(401), None, "ServerlessGitAuthError"),
                                          (_HResp(500), None, "ServerlessGitError"),
                                          (None, ConnectionError("down"), "ServerlessGitError")])
def test_commit_bound_reads_raise_on_failure(sgp, monkeypatch, resp, exc, err):
    monkeypatch.setattr(sgp, "requests", _Requests(resp, exc))
    p = _provider(sgp)
    with pytest.raises(getattr(sgp, err)):
        p.export_archive_with_sha("app", "main")
    with pytest.raises(getattr(sgp, err)):
        p.get_branch_head_sha("app", "main")


def test_get_branch_head_sha(sgp, monkeypatch):
    fake = _Requests(_HResp(200, {"commit_sha": GOOD_SHA}))
    monkeypatch.setattr(sgp, "requests", fake)
    assert _provider(sgp).get_branch_head_sha("app", "castor/app-1a2b3c") == GOOD_SHA
    assert fake.calls[0][1] == f"{SERVER}/api/v1/repos/app/refs/heads/castor/app-1a2b3c"
    monkeypatch.setattr(sgp, "requests", _Requests(_HResp(404)))
    with pytest.raises(sgp.ServerlessGitNotFound):
        _provider(sgp).get_branch_head_sha("app", "nope")
    for body in ({}, {"commit_sha": "abc"}, {"commit_sha": GOOD_SHA.upper()}):
        monkeypatch.setattr(sgp, "requests", _Requests(_HResp(200, body)))
        with pytest.raises(sgp.ServerlessGitError):
            _provider(sgp).get_branch_head_sha("app", "main")


def test_negative_export_archive_stream_unchanged(sgp, monkeypatch):
    """Do No Harm: the VCSProvider export_archive_stream contract is unchanged (body on 200, empty on 404)."""
    monkeypatch.setattr(sgp, "requests", _Requests(_HResp(200, content=b"TAR")))
    assert _provider(sgp).export_archive_stream("app").read() == b"TAR"
    monkeypatch.setattr(sgp, "requests", _Requests(_HResp(404)))
    assert _provider(sgp).export_archive_stream("app").read() == b""
