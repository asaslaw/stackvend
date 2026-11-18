"""Register row 40 (owner 10-12): the git server's tree and blob reads use exactly refs/heads/{branch} or 404.

- No silent fallback to HEAD: a missing branch never yields the default branch's files.
- Slash-named branches (pipeline branches are `castor/<id>-<suffix>`) work, raw and `%2F`.
- Existing branches: response bodies unchanged (Do No Harm).
- Every read is authenticated (FD-4K middleware).
- Client (ServerlessGitProvider): a missing repo/branch raises ServerlessGitNotFound; a missing file on an existing
  branch still returns ''.

Real git server app (Dulwich) on a temp GIT_DATA_DIR, authenticated with fd4k_support test tokens. Hermetic.
"""
import hermetic_guard  # noqa: F401  (lane 2: must be the first import)

import os
import shutil

import pytest
from fastapi.testclient import TestClient

from fd4k_support import load_git_server, make_token

PIPELINE_BRANCH = "castor/app-1a2b3c"
PCT_BRANCH = "castor%2Fapp-1a2b3c"


@pytest.fixture()
def gs(monkeypatch):
    mod, client, outer = load_git_server(monkeypatch)
    assert client.post("/api/v1/repos", json={"product_id": "app"}).status_code == 201
    yield mod, client, os.path.join(outer, "data")
    shutil.rmtree(outer, ignore_errors=True)


def _commit(client, branch, files):
    r = client.post("/api/v1/repos/app/commits", json={"branch": branch, "files": files})
    assert r.status_code == 200, r.text
    return r.json()["commit_sha"]


def _pipeline_repo(client):
    """main: app.py=v-main + hotfix.py; castor/app-1a2b3c (branched before hotfix): app.py=v-feature + infra/main.tf."""
    _commit(client, "main", {"app.py": "v-main\n"})
    assert client.post("/api/v1/repos/app/branches", json={"branch_name": PIPELINE_BRANCH}).status_code == 200
    _commit(client, PIPELINE_BRANCH, {"app.py": "v-feature\n", "infra/main.tf": "# feature\n"})
    _commit(client, "main", {"hotfix.py": "h\n"})


# ------------------------------------------------------------------ existing branches: bodies unchanged

def test_existing_branch_tree_body_unchanged(gs):
    mod, client, _ = gs
    _commit(client, "main", {"app.py": "print(1)\n", "src/lib/util.py": "u\n", "logo.png": "bin"})
    r = client.get("/api/v1/repos/app/tree/main")
    assert r.status_code == 200
    body = r.json()
    readme = "# app\n\nVended workload managed by StackVend.\n"
    assert body == {
        "product_id": "app",
        "branch": "main",
        "files": {".gitignore": body["files"][".gitignore"], "README.md": readme, "app.py": "print(1)\n",
                  "src/lib/util.py": "u\n"},
        "total_files": 4,
        "truncated": False,   # FD-4DC: additive flag (the branch has no more text files than max_files)
    }
    # Same tiering/order as before (root files first), binaries still skipped, max_files still honoured.
    assert list(body["files"]) == sorted(body["files"], key=mod._tree_priority_key)
    capped = client.get("/api/v1/repos/app/tree/main?max_files=1").json()
    assert capped["total_files"] == 1 and list(capped["files"]) == [".gitignore"]
    assert capped["truncated"] is True


def test_existing_branch_blob_body_unchanged(gs):
    _, client, _ = gs
    _commit(client, "main", {"app.py": "print(1)\n", "src/lib/util.py": "u\n"})
    assert client.get("/api/v1/repos/app/blob/main/app.py").json() == {
        "product_id": "app", "branch": "main", "file_path": "app.py", "content": "print(1)\n"}
    assert client.get("/api/v1/repos/app/blob/main/src/lib/util.py").json() == {
        "product_id": "app", "branch": "main", "file_path": "src/lib/util.py", "content": "u\n"}
    # Leading slash in the file path: stripped for the lookup, echoed as sent (as before).
    assert client.get("/api/v1/repos/app/blob/main//app.py").json() == {
        "product_id": "app", "branch": "main", "file_path": "/app.py", "content": "print(1)\n"}


def test_missing_file_on_existing_branch_keeps_its_404_body(gs):
    _, client, _ = gs
    r = client.get("/api/v1/repos/app/blob/main/nope.py")
    assert r.status_code == 404
    assert r.json() == {"detail": "File 'nope.py' not found on branch 'main'."}
    assert r.headers["X-Git-Not-Found"] == "file"


# ------------------------------------------------------------------ slash-named branches (raw and %2F)

@pytest.mark.parametrize("branch", [PIPELINE_BRANCH, PCT_BRANCH])
def test_tree_of_slashed_branch_is_that_branch(gs, branch):
    _, client, _ = gs
    _pipeline_repo(client)
    r = client.get(f"/api/v1/repos/app/tree/{branch}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["branch"] == PIPELINE_BRANCH
    assert body["files"]["app.py"] == "v-feature\n" and body["files"]["infra/main.tf"] == "# feature\n"
    assert "hotfix.py" not in body["files"]


@pytest.mark.parametrize("branch", [PIPELINE_BRANCH, PCT_BRANCH])
def test_blob_of_slashed_branch_is_that_branch(gs, branch):
    _, client, _ = gs
    _pipeline_repo(client)
    r = client.get(f"/api/v1/repos/app/blob/{branch}/app.py")
    assert r.status_code == 200, r.text
    assert r.json() == {"product_id": "app", "branch": PIPELINE_BRANCH, "file_path": "app.py", "content": "v-feature\n"}
    nested = client.get(f"/api/v1/repos/app/blob/{branch}/infra/main.tf")
    assert nested.status_code == 200
    assert nested.json()["file_path"] == "infra/main.tf" and nested.json()["content"] == "# feature\n"
    # A file that exists only on main is not served from the pipeline branch.
    only_main = client.get(f"/api/v1/repos/app/blob/{branch}/hotfix.py")
    assert only_main.status_code == 404 and only_main.headers["X-Git-Not-Found"] == "file"
    assert "h\n" not in only_main.text


# ------------------------------------------------------------------ missing branch: 404, never HEAD's content

@pytest.mark.parametrize("branch", ["nope", "castor/app-missing", "castor%2Fapp-missing"])
def test_tree_of_missing_branch_is_404_not_head(gs, branch):
    _, client, _ = gs
    _commit(client, "main", {"app.py": "v-main\n"})
    r = client.get(f"/api/v1/repos/app/tree/{branch}")
    assert r.status_code == 404, (branch, r.text)
    assert "files" not in r.json() and "v-main" not in r.text and "README" not in r.text


@pytest.mark.parametrize("branch", ["nope", "castor/app-missing", "castor%2Fapp-missing"])
def test_blob_of_missing_branch_is_404_not_head(gs, branch):
    _, client, _ = gs
    _commit(client, "main", {"app.py": "v-main\n", "app-missing/app.py": "nested-main\n"})
    for f in ("app.py", "README.md"):
        r = client.get(f"/api/v1/repos/app/blob/{branch}/{f}")
        assert r.status_code == 404, (branch, f, r.text)
        assert r.headers["X-Git-Not-Found"] == "branch"
        assert "content" not in r.json() and "v-main" not in r.text and "nested-main" not in r.text


@pytest.mark.parametrize("src", ["castor/app-ff0001", "stage-ff0001"])
def test_merged_and_deleted_source_branch_reads_404(gs, src):
    _, client, _ = gs
    _pipeline_repo(client)
    # Fast-forwardable branch: create from current main, commit, merge (source ref is removed on merge).
    assert client.post("/api/v1/repos/app/branches", json={"branch_name": src}).status_code == 200
    _commit(client, src, {"ff.py": "ff\n"})
    r = client.post("/api/v1/repos/app/merge", json={"source_branch": src, "target_branch": "main"})
    assert r.status_code == 200, r.text
    assert client.get(f"/api/v1/repos/app/tree/{src}").status_code == 404
    assert client.get(f"/api/v1/repos/app/blob/{src}/ff.py").status_code == 404
    assert client.get("/api/v1/repos/app/blob/main/ff.py").json()["content"] == "ff\n"


def test_missing_repo_is_404(gs):
    _, client, _ = gs
    assert client.get("/api/v1/repos/ghost/tree/main").status_code == 404
    assert client.get("/api/v1/repos/ghost/blob/main/README.md").status_code == 404


def test_ambiguous_packed_refs_fail_closed(gs):
    """git forbids `castor` and `castor/x` together; a hand-edited packed-refs that has both is refused, not guessed."""
    mod, client, data = gs
    _pipeline_repo(client)
    from dulwich.repo import Repo

    repo = Repo(os.path.join(data, "app.git"))
    sha = repo.refs[f"refs/heads/{PIPELINE_BRANCH}".encode()]
    with open(os.path.join(data, "app.git", "packed-refs"), "ab") as fh:
        fh.write(sha + b" refs/heads/castor\n")
    assert Repo(os.path.join(data, "app.git")).refs[b"refs/heads/castor"] == sha
    raw = TestClient(mod.app, raise_server_exceptions=False, headers=dict(client.headers))
    r = raw.get(f"/api/v1/repos/app/blob/{PIPELINE_BRANCH}/app.py")
    assert r.status_code == 500 and "v-feature" not in r.text


# ------------------------------------------------------------------ validation and authentication

@pytest.mark.parametrize("branch", ["-x", "HEAD", "@", "a..b", "x~1", "x^", "x:y", "a.lock"])
def test_bad_branch_rejected_on_tree_and_blob(gs, branch):
    _, client, _ = gs
    for path in (f"/api/v1/repos/app/tree/{branch}", f"/api/v1/repos/app/blob/{branch}/README.md"):
        r = client.get(path)
        assert r.status_code == 400, (path, r.status_code, r.text)
        assert "content" not in r.text and "files" not in r.text


@pytest.mark.parametrize("path", ["/api/v1/repos/app/tree/main", f"/api/v1/repos/app/tree/{PIPELINE_BRANCH}",
                                  f"/api/v1/repos/app/tree/{PCT_BRANCH}", "/api/v1/repos/app/blob/main/README.md",
                                  f"/api/v1/repos/app/blob/{PIPELINE_BRANCH}/app.py",
                                  f"/api/v1/repos/app/blob/{PCT_BRANCH}/app.py"])
def test_tree_and_blob_require_a_token(gs, path):
    mod, client, _ = gs
    _pipeline_repo(client)
    r = TestClient(mod.app).get(path)
    assert r.status_code in (401, 403)
    assert "content" not in r.text and "files" not in r.text


# ------------------------------------------------------------------ client against the real app

class _AppRequests:
    """`requests` stand-in that sends the provider's calls to the real git server app."""

    def __init__(self, app):
        self.client = TestClient(app)
        self.urls = []

    def get(self, url, headers=None, timeout=None, allow_redirects=False, **kw):
        self.urls.append(url)
        return self.client.get(url, headers=headers, follow_redirects=allow_redirects, **kw)


@pytest.fixture()
def provider(gs, monkeypatch):
    mod, client, _ = gs
    from shared.providers import serverless_git_provider as sgp

    fake = _AppRequests(mod.app)
    monkeypatch.setattr(sgp, "requests", fake)
    p = sgp.ServerlessGitProvider(server_url="http://testserver", project_id="mock-stackvend-project",
                                  auth_token=make_token())
    return sgp, p, client, fake


def test_client_reads_slashed_branch_exactly(provider):
    sgp, p, client, fake = provider
    _pipeline_repo(client)
    tree = p.fetch_file_tree("castor/app", branch=PIPELINE_BRANCH)
    assert tree["app.py"] == "v-feature\n" and "hotfix.py" not in tree
    assert p.fetch_file_content("castor/app", "infra/main.tf", branch=PIPELINE_BRANCH) == "# feature\n"
    assert p.fetch_file_content("castor/app", "/app.py", branch=PIPELINE_BRANCH) == "v-feature\n"
    assert fake.urls[0] == f"http://testserver/api/v1/repos/app/tree/{PIPELINE_BRANCH}?max_files=2500"
    assert fake.urls[1] == f"http://testserver/api/v1/repos/app/blob/{PIPELINE_BRANCH}/infra/main.tf"
    # Existing branch, missing file: '' as before.
    assert p.fetch_file_content("castor/app", "hotfix.py", branch=PIPELINE_BRANCH) == ""
    # main is unchanged.
    assert p.fetch_file_content("app", "app.py") == "v-main\n"
    assert p.fetch_file_tree("app")["hotfix.py"] == "h\n"


@pytest.mark.parametrize("branch", ["nope", "castor/app-missing"])
def test_client_missing_branch_raises_not_found(provider, branch):
    sgp, p, client, _ = provider
    _pipeline_repo(client)
    with pytest.raises(sgp.ServerlessGitNotFound):
        p.fetch_file_tree("app", branch=branch)
    with pytest.raises(sgp.ServerlessGitNotFound):
        p.fetch_file_content("app", "app.py", branch=branch)


def test_client_missing_repo_raises_not_found(provider):
    sgp, p, _, _ = provider
    with pytest.raises(sgp.ServerlessGitNotFound):
        p.fetch_file_tree("ghost")
    with pytest.raises(sgp.ServerlessGitNotFound):
        p.fetch_file_content("ghost", "README.md")
