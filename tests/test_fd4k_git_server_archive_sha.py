"""Register 19c (lane 13 contract §6.1): the git server's archive is bound to one commit and says which.

GET /api/v1/repos/{id}/archive/{branch} resolves only refs/heads/{branch} (missing -> 404, never the HEAD tree),
resolves it once, archives exactly that commit and returns `X-Commit-Sha: <40 lowercase hex>`. The optional
read-only GET /api/v1/repos/{id}/refs/heads/{branch} returns the same SHA. Branch names may contain '/'
(pipeline branches are `castor/<id>-<suffix>`).

Real git server app (Dulwich) on a temp GIT_DATA_DIR, authenticated with fd4k_support test tokens. Hermetic.
"""
import hermetic_guard  # noqa: F401  (lane 2: must be the first import)

import io
import os
import shutil
import tarfile

import pytest
from fastapi.testclient import TestClient

from fd4k_support import load_git_server

PIPELINE_BRANCH = "castor/app-1a2b3c"


@pytest.fixture()
def gs(monkeypatch):
    mod, client, outer = load_git_server(monkeypatch)
    assert client.post("/api/v1/repos", json={"product_id": "app"}).status_code == 201
    yield mod, client, os.path.join(outer, "data")
    shutil.rmtree(outer, ignore_errors=True)


def _head(data, branch):
    from dulwich.repo import Repo

    return Repo(os.path.join(data, "app.git")).refs[f"refs/heads/{branch}".encode()].decode("ascii")


def _commit(client, branch, files):
    r = client.post("/api/v1/repos/app/commits", json={"branch": branch, "files": files})
    assert r.status_code == 200, r.text
    return r.json()["commit_sha"]


def _members(content):
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
        out = {}
        for m in tar.getmembers():
            assert m.isfile(), m.name
            out[m.name] = tar.extractfile(m).read().decode()
        return out


def _is_sha(value):
    return isinstance(value, str) and len(value) == 40 and all(c in "0123456789abcdef" for c in value)


def test_archive_carries_x_commit_sha_equal_to_branch_head(gs):
    _, client, data = gs
    sha = _commit(client, "main", {"app.py": "print(1)\n"})
    r = client.get("/api/v1/repos/app/archive/main")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/gzip"
    got = r.headers["X-Commit-Sha"]
    assert _is_sha(got)
    assert got == sha == _head(data, "main")
    files = _members(r.content)
    # Body unchanged: regular files only, paths relative to the repo root (no top-level directory).
    assert files["app.py"] == "print(1)\n" and "README.md" in files and ".gitignore" in files
    assert all(not name.startswith(("/", "app/")) for name in files)


def test_pipeline_branch_with_slash_is_archived_at_its_own_head(gs):
    _, client, data = gs
    assert client.post("/api/v1/repos/app/branches", json={"branch_name": PIPELINE_BRANCH}).status_code == 200
    feature_sha = _commit(client, PIPELINE_BRANCH, {"feature.py": "x = 1\n"})
    main_sha = _commit(client, "main", {"hotfix.py": "y = 2\n"})
    # Raw slash (provider) and %2F (lane 13 qa_source quotes with safe='') reach the same branch.
    for path in (f"/api/v1/repos/app/archive/{PIPELINE_BRANCH}", "/api/v1/repos/app/archive/castor%2Fapp-1a2b3c"):
        r = client.get(path)
        assert r.status_code == 200, (path, r.text)
        assert r.headers["X-Commit-Sha"] == feature_sha == _head(data, PIPELINE_BRANCH) != main_sha
        files = _members(r.content)
        assert "feature.py" in files and "hotfix.py" not in files
        assert "/" not in r.headers["content-disposition"].split("filename=", 1)[1]


def test_missing_branch_is_404_not_the_head_tree(gs):
    _, client, _ = gs
    _commit(client, "main", {"app.py": "print(1)\n"})
    for branch in ("nope", "castor/app-missing"):
        r = client.get(f"/api/v1/repos/app/archive/{branch}")
        assert r.status_code == 404, (branch, r.status_code)
        assert "X-Commit-Sha" not in r.headers
        assert r.content[:2] != b"\x1f\x8b"  # not a gzip archive of HEAD


def test_missing_repo_is_404(gs):
    _, client, _ = gs
    assert client.get("/api/v1/repos/ghost/archive/main").status_code == 404
    assert client.get("/api/v1/repos/ghost/refs/heads/main").status_code == 404


def test_push_between_resolve_and_archive_cannot_mix_commits(gs, monkeypatch):
    """The ref is resolved once: a commit that moves the branch while the archive is being built is not included,
    and the header names the commit whose tree was archived."""
    mod, client, data = gs
    before = _commit(client, "main", {"app.py": "v1\n"})
    real_repo = mod.Repo
    state = {"pushed": False, "after": None}
    repo_path = os.path.join(data, "app.git")

    class RacingRepo(real_repo):
        def __getitem__(self, key):
            obj = super().__getitem__(key)
            if not state["pushed"] and isinstance(obj, mod.Commit):
                state["pushed"] = True  # first commit lookup happens right after the ref was resolved
                state["after"] = mod.commit_files_dulwich(repo_path, "main", {"app.py": "v2\n", "late.py": "1\n"},
                                                          "concurrent push", "a", "a@example.com")
            return obj

    monkeypatch.setattr(mod, "Repo", RacingRepo)
    r = client.get("/api/v1/repos/app/archive/main")
    assert r.status_code == 200
    assert state["pushed"] and state["after"] and state["after"] != before
    assert _head(data, "main") == state["after"]  # the push really landed mid-request
    assert r.headers["X-Commit-Sha"] == before
    files = _members(r.content)
    assert files["app.py"] == "v1\n" and "late.py" not in files


def test_refs_endpoint_returns_branch_head(gs):
    _, client, data = gs
    assert client.post("/api/v1/repos/app/branches", json={"branch_name": PIPELINE_BRANCH}).status_code == 200
    feature_sha = _commit(client, PIPELINE_BRANCH, {"feature.py": "x\n"})
    r = client.get(f"/api/v1/repos/app/refs/heads/{PIPELINE_BRANCH}")
    assert r.status_code == 200
    assert r.json() == {"product_id": "app", "branch": PIPELINE_BRANCH, "commit_sha": feature_sha}
    main = client.get("/api/v1/repos/app/refs/heads/main").json()["commit_sha"]
    assert main == _head(data, "main") == client.get("/api/v1/repos/app/archive/main").headers["X-Commit-Sha"]
    assert client.get("/api/v1/repos/app/refs/heads/nope").status_code == 404


@pytest.mark.parametrize("branch", ["-x", "--output=x", "a..b", "a.lock", "HEAD", "@", "x~1", "x^", "x:y", "a/",
                                    "castor/.a", "castor/a.lock"])
def test_bad_branch_rejected_on_archive_and_refs(gs, branch):
    _, client, _ = gs
    for route in ("archive", "refs/heads"):
        r = client.get(f"/api/v1/repos/app/{route}/{branch}")
        assert r.status_code in (400, 404), (route, branch, r.status_code)
        assert "X-Commit-Sha" not in r.headers and "commit_sha" not in r.text


@pytest.mark.parametrize("path", ["/api/v1/repos/app/archive/main", f"/api/v1/repos/app/archive/{PIPELINE_BRANCH}",
                                  "/api/v1/repos/app/refs/heads/main"])
def test_archive_and_refs_require_a_token(gs, path):
    mod, _, _ = gs
    anon = TestClient(mod.app)
    r = anon.get(path)
    assert r.status_code in (401, 403)
    assert "X-Commit-Sha" not in r.headers and "commit_sha" not in r.text
