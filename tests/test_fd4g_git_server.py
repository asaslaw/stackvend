"""FD-4G: Serverless Git server repo-path containment (T9) and commit key validation (T10, H1).

Imports apps/git-server/main.py by file path with GIT_DATA_DIR in a temp dir; FastAPI TestClient; hermetic.
"""

import importlib.util
import os
import socket
import tempfile

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GS_MAIN = os.path.join(REPO_ROOT, "apps", "git-server", "main.py")
GIT_META = ".git"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def _blocked(self, addr):
        raise OSError(f"network blocked in FD-4G test: {addr}")

    monkeypatch.setattr(socket.socket, "connect", _blocked)


@pytest.fixture()
def gs(monkeypatch):
    # FD-4K: the server now requires a verified Google ID token; fd4k_support signs real test tokens.
    from fd4k_support import load_git_server

    mod, client, outer = load_git_server(monkeypatch, import_name="fd4g_git_server_main")
    mod._fd4g = {"outer": outer, "data": os.path.join(outer, "data"), "client": client}
    yield mod
    import shutil

    shutil.rmtree(outer, ignore_errors=True)


def _listing(root):
    out = set()
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            out.add(os.path.relpath(os.path.join(dirpath, n), root))
    return out


def _tree(gs, pid, branch="main"):
    r = gs._fd4g["client"].get(f"/api/v1/repos/{pid}/tree/{branch}")
    assert r.status_code == 200, r.text
    body = r.json()
    return body.get("files", body)


# ---------------------------------------------------------------- attacks

@pytest.mark.parametrize("pid", ["../rt-escaped", "..", "a/b", "Bad_ID", "-x", "x" * 64])
def test_create_rejects_bad_product_id_and_creates_nothing(gs, pid):
    before = _listing(gs._fd4g["outer"])
    r = gs._fd4g["client"].post("/api/v1/repos", json={"product_id": pid})
    assert r.status_code in (400, 422), r.text
    assert _listing(gs._fd4g["outer"]) == before


@pytest.mark.parametrize("key", ["../../terraform.rc", "/abs.tf", ".git/config", "apps/x/.GIT/hooks/post-update",
                                 "a//b.tf", "./a.tf", "a\\b.tf"])
def test_commit_rejects_unsafe_keys_tree_unchanged(gs, key):
    c = gs._fd4g["client"]
    assert c.post("/api/v1/repos", json={"product_id": "my-app"}).status_code == 201
    before = _tree(gs, "my-app")
    r = c.post("/api/v1/repos/my-app/commits", json={"branch": "main", "files": {key: "x", "ok.tf": "y"}})
    assert r.status_code == 422, r.text
    assert "unsafe path" in r.text
    assert _tree(gs, "my-app") == before


@pytest.mark.parametrize("url", ["/api/v1/repos/..%2Fx/metadata", "/api/v1/repos/../x/metadata",
                                 "/api/v1/repos/%2e%2e/metadata", "/git/../info/refs", "/git/%2e%2e/info/refs"])
def test_traversal_route_params_never_create_or_escape(gs, url):
    before = _listing(gs._fd4g["outer"])
    r = gs._fd4g["client"].get(url)
    assert r.status_code in (400, 404, 422)
    assert _listing(gs._fd4g["outer"]) == before


def test_get_repo_path_rejects_non_component(gs):
    from shared.path_safety import UnsafePathError

    for bad in ["..", "a/b", "", "../x"]:
        with pytest.raises(UnsafePathError):
            gs.get_repo_path(bad)


# ---------------------------------------------------------------- Do-No-Harm

@pytest.mark.parametrize("pid", ["my-app", "3d-render"])
def test_create_legit_ids_same_path(gs, pid):
    r = gs._fd4g["client"].post("/api/v1/repos", json={"product_id": pid})
    assert r.status_code == 201, r.text
    assert os.path.isfile(os.path.join(gs._fd4g["data"], f"{pid}.git", "HEAD"))
    assert gs.get_repo_path(pid) == os.path.join(gs._fd4g["data"], f"{pid}.git")


def test_commit_legit_keys_same_tree(gs):
    c = gs._fd4g["client"]
    assert c.post("/api/v1/repos", json={"product_id": "my-app"}).status_code == 201
    files = {
        "infra/workload/main.tf": "# main\n",
        ".github/workflows/x.yml": "name: x\n",
        ".gitignore": "x\n",
        "apps/web/app/[id]/page.tsx": "export {}\n",
    }
    r = c.post("/api/v1/repos/my-app/commits", json={"branch": "main", "files": files})
    assert r.status_code == 200, r.text
    tree = _tree(gs, "my-app")
    for k, v in files.items():
        assert tree[k] == v
    assert "README.md" in tree


def test_dotgit_ids_rejected_no_collision(gs):
    # FD-4K (FD26-21): the legacy .replace(".git", "") mapping (team.gitops -> teamops.git) is gone; every route
    # takes the anchored RFC 1123 id, so ids can no longer collide.
    from shared.path_safety import UnsafePathError

    for bad in ("team.gitops", "my-app.git"):
        with pytest.raises(UnsafePathError):
            gs.get_repo_path(bad)
    assert os.path.basename(gs.get_repo_path("my-app")) == "my-app.git"
