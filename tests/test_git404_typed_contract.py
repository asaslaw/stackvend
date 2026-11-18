"""Row GIT-404-TYPED (internal-ingress plan §6.3): a 404 from the git server is "not found" only when the git server
itself sent it.

- apps/git-server sets `X-StackVend-Git-Server: 1` on every answer: 200, its own 404s (missing repository, missing
  branch, unknown route), 401 from the identity middleware;
- ServerlessGitProvider (every replica, byte-identical) reads a headered 404 as before (ServerlessGitNotFound /
  allowed 404) and raises the typed GitServerUnreachable (stage vcs) for a 404 without it (e.g. Cloud Run's front end
  refusing an off-network caller of an internal-only service);
- negative (Do No Harm): the 200 paths are unchanged, with or without the header.
Hermetic: fake transport for the client, TestClient + fake identity for the server.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import shutil

import pytest
from fastapi.testclient import TestClient

from fd4k_support import load_git_server
from test_fd4k_serverless_git_client import GOOD_SHA, _HResp, _Requests, _provider, sgp  # noqa: F401

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HEADER = "X-StackVend-Git-Server"


class _BareResp:
    """What Cloud Run's front end answers a caller its ingress refuses: no git-server header."""

    def __init__(self, code, headers=None):
        self.status_code, self.text, self.content = code, "<html>404 Page not found</html>", b""
        self.headers = headers if headers is not None else {}

    def json(self):
        raise ValueError("not JSON")


# ============================================================================ server
@pytest.fixture()
def gs(monkeypatch):
    mod, client, outer = load_git_server(monkeypatch, import_name="git404_typed_git_server_main")
    assert client.post("/api/v1/repos", json={"product_id": "app"}).status_code == 201
    yield mod, client
    shutil.rmtree(outer, ignore_errors=True)


def test_server_marks_every_answer_including_its_own_404s(gs):
    mod, client = gs
    answers = [
        client.get("/health"),                                   # public path, 200
        client.get("/api/v1/repos/app/metadata"),                # 200
        client.get("/api/v1/repos/nope/metadata"),               # missing repository, 404
        client.get("/api/v1/repos/app/refs/heads/nope"),         # missing branch, 404
        client.get("/api/v1/no-such-route"),                     # unknown route, 404
        TestClient(mod.app).get("/api/v1/repos/app/metadata"),   # no token, 401 from the identity middleware
    ]
    assert [r.status_code for r in answers] == [200, 200, 404, 404, 404, 401]
    assert all(r.headers.get(HEADER) == "1" for r in answers), [dict(r.headers) for r in answers]


def test_server_and_client_name_the_same_header(gs, sgp):
    mod, _ = gs
    assert (mod.GIT_SERVER_HEADER, mod.GIT_SERVER_HEADER_VALUE) == (sgp.GIT_SERVER_HEADER, sgp.GIT_SERVER_HEADER_VALUE)
    assert sgp.GIT_SERVER_HEADER == HEADER and sgp.GIT_SERVER_HEADER_VALUE == "1"


# ============================================================================ client
def _reads(p):
    return [
        lambda: p.fetch_file_tree("app"),
        lambda: p.fetch_file_content("app", "x"),
        lambda: p.export_archive_stream("app"),
        lambda: p.export_archive_with_sha("app", "main"),
        lambda: p.get_branch_head_sha("app", "main"),
        lambda: p.get_repository_metadata("castor/app"),
        lambda: p.merge_source_check_supported(),
        lambda: p.commit_files("castor/app", "b1", {"a.tf": "x"}, "m", files_to_delete=["old.tf"]),
    ]


@pytest.mark.parametrize("headers", [{}, {HEADER: "0"}, {HEADER: ""}, {"X-Git-Not-Found": "file"}])
def test_a_404_without_the_header_is_git_server_unreachable(sgp, monkeypatch, headers):
    monkeypatch.setattr(sgp, "requests", _Requests(_BareResp(404, headers)))
    p = _provider(sgp)
    for call in _reads(p):
        with pytest.raises(sgp.GitServerUnreachable) as ei:
            call()
        assert not isinstance(ei.value, sgp.ServerlessGitNotFound)
        assert isinstance(ei.value, sgp.ServerlessGitError)   # existing broad handlers still catch it
    assert sgp.GitServerUnreachable.error_class == "GIT_SERVER_UNREACHABLE"
    assert sgp.GitServerUnreachable.stage == "vcs"


@pytest.mark.parametrize("name", [HEADER, HEADER.lower(), HEADER.upper()])
def test_a_headered_404_is_still_not_found(sgp, monkeypatch, name):
    monkeypatch.setattr(sgp, "requests", _Requests(_BareResp(404, {name: "1"})))
    p = _provider(sgp)
    with pytest.raises(sgp.ServerlessGitNotFound):
        p.fetch_file_tree("app")
    with pytest.raises(sgp.ServerlessGitNotFound):
        p.get_branch_head_sha("app", "main")
    assert p.export_archive_stream("app").read() == b""
    assert p.merge_source_check_supported() is False
    with pytest.raises(sgp.ServerlessGitDeletionUnsupported):
        p.commit_files("castor/app", "b1", {"a.tf": "x"}, "m", files_to_delete=["old.tf"])


def test_requests_case_insensitive_headers_are_read(sgp, monkeypatch):
    from requests.structures import CaseInsensitiveDict

    monkeypatch.setattr(sgp, "requests", _Requests(_BareResp(404, CaseInsensitiveDict({HEADER.lower(): "1"}))))
    with pytest.raises(sgp.ServerlessGitNotFound):
        _provider(sgp).fetch_file_tree("app")


@pytest.mark.parametrize("headers", [{}, {HEADER: "1"}])
def test_negative_the_200_paths_are_unchanged(sgp, monkeypatch, headers):
    resp = _HResp(200, {"commit_sha": GOOD_SHA}, content=b"TAR", headers={"X-Commit-Sha": GOOD_SHA})
    resp.headers = {"X-Commit-Sha": GOOD_SHA, **headers}
    monkeypatch.setattr(sgp, "requests", _Requests(resp))
    p = _provider(sgp)
    assert p.get_branch_head_sha("app", "main") == GOOD_SHA
    assert p.export_archive_stream("app").read() == b"TAR"
    assert p.export_archive_with_sha("app", "main") == (GOOD_SHA, b"TAR")


def test_header_check_is_one_function_in_every_replica():
    copies = [os.path.join(REPO, d, "shared", "providers", "serverless_" + "g" + "it_provider.py") for d in (
        ".", "apps/control-center", "apps/orchestrator-gateway", "apps/project-vending", "apps/qa-runner",
        "mcp-servers/github", "mcp-servers/terraform")]
    blobs = {c: open(c, "rb").read() for c in copies}
    assert len(set(blobs.values())) == 1
    assert all(b"def answered_by_git_server" in b for b in blobs.values())
