"""FD-4V: the Serverless Git merge is fast-forward-only; it never reverts commits that reached the target.

Real git server app (Dulwich) on a temp GIT_DATA_DIR, authenticated with fd4k_support test tokens. Hermetic.
Also: a real end-to-end `git clone` over Smart HTTP (uvicorn on 127.0.0.1) with the token in http.extraHeader.
"""
import hermetic_guard  # noqa: F401  (lane 2: must be the first import)

import os
import shutil
import socket
import subprocess
import threading
import time

import pytest

from fd4k_support import AUDIENCE, load_git_server, make_authenticator, make_token


@pytest.fixture()
def gs(monkeypatch):
    mod, client, outer = load_git_server(monkeypatch)
    assert client.post("/api/v1/repos", json={"product_id": "app"}).status_code == 201
    yield mod, client, os.path.join(outer, "data")
    shutil.rmtree(outer, ignore_errors=True)


def _tree(client, branch="main"):
    r = client.get(f"/api/v1/repos/app/tree/{branch}")
    assert r.status_code == 200, r.text
    return r.json()["files"]


def _branches(client):
    return set(client.get("/api/v1/repos/app/metadata").json()["branches"])


def _ref(data, branch):
    from dulwich.repo import Repo

    return Repo(os.path.join(data, "app.git")).refs[f"refs/heads/{branch}".encode()]


def _commit(client, branch, files):
    r = client.post("/api/v1/repos/app/commits", json={"branch": branch, "files": files})
    assert r.status_code == 200, r.text
    return r.json()["commit_sha"]


def _git_available():
    return shutil.which("git") is not None


def _is_ancestor(data, a, b):
    rc = subprocess.run(["git", "--git-dir", os.path.join(data, "app.git"), "merge-base", "--is-ancestor", a, b],
                        capture_output=True).returncode
    return rc == 0


def test_regression_target_advanced_is_409_and_nothing_lost(gs):
    """Probe fd26-vending-day2_git_server_unauth.py section 5: main gets a hotfix after the feature branch point."""
    _, client, data = gs
    assert client.post("/api/v1/repos/app/branches", json={"branch_name": "feature/x"}).status_code == 200
    _commit(client, "feature/x", {"feature.txt": "f"})
    _commit(client, "main", {"hotfix.txt": "h"})
    main_before, main_tree_before = _ref(data, "main"), _tree(client)
    src_before = _ref(data, "feature/x")

    r = client.post("/api/v1/repos/app/merge", json={"source_branch": "feature/x"})
    assert r.status_code == 409, r.text
    assert r.json()["status"] == "CONFLICT"
    assert _ref(data, "main") == main_before
    assert _tree(client) == main_tree_before and "hotfix.txt" in main_tree_before and "feature.txt" not in main_tree_before
    assert _ref(data, "feature/x") == src_before  # source kept
    if _git_available():
        assert not _is_ancestor(data, main_before.decode(), src_before.decode())


def test_fast_forwardable_squash_merges_and_deletes_source(gs):
    _, client, data = gs
    client.post("/api/v1/repos/app/branches", json={"branch_name": "feature/x"})
    _commit(client, "feature/x", {"feature.txt": "f"})
    main_before, src = _ref(data, "main"), _ref(data, "feature/x")
    if _git_available():
        assert _is_ancestor(data, main_before.decode(), src.decode())
    # (the REST tree route takes a single path segment, so a slash branch is compared via the expected content)
    feature_tree = dict(_tree(client), **{"feature.txt": "f"})

    r = client.post("/api/v1/repos/app/merge", json={"source_branch": "feature/x"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "MERGED"
    assert _tree(client) == feature_tree
    from dulwich.repo import Repo

    new = Repo(os.path.join(data, "app.git"))[_ref(data, "main")]
    assert new.parents == [main_before]
    assert "feature/x" not in _branches(client)


def test_fast_forward_method_moves_target_to_source(gs):
    _, client, data = gs
    client.post("/api/v1/repos/app/branches", json={"branch_name": "feature/x"})
    _commit(client, "feature/x", {"feature.txt": "f"})
    src = _ref(data, "feature/x")
    r = client.post("/api/v1/repos/app/merge", json={"source_branch": "feature/x", "merge_method": "fast-forward"})
    assert r.status_code == 200 and r.json()["status"] == "MERGED"
    assert _ref(data, "main") == src


@pytest.mark.parametrize("advance_main", [False, True])
def test_source_equal_or_behind_target_is_up_to_date(gs, advance_main):
    _, client, data = gs
    client.post("/api/v1/repos/app/branches", json={"branch_name": "feature/x"})
    if advance_main:
        _commit(client, "main", {"later.txt": "l"})
    main_before = _ref(data, "main")
    r = client.post("/api/v1/repos/app/merge", json={"source_branch": "feature/x"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "ALREADY_UP_TO_DATE"
    assert _ref(data, "main") == main_before


def test_orphan_source_branch_is_409(gs):
    _, client, data = gs
    _commit(client, "orphan/x", {"only.txt": "o"})  # commit to a non-existent branch creates a root commit
    main_before = _ref(data, "main")
    assert client.post("/api/v1/repos/app/merge", json={"source_branch": "orphan/x"}).status_code == 409
    assert _ref(data, "main") == main_before


def test_cas_race_is_409_and_source_kept(gs, monkeypatch):
    mod, client, data = gs
    client.post("/api/v1/repos/app/branches", json={"branch_name": "feature/x"})
    _commit(client, "feature/x", {"feature.txt": "f"})
    from dulwich.refs import DiskRefsContainer

    monkeypatch.setattr(DiskRefsContainer, "set_if_equals", lambda self, *a, **k: False)
    main_before = _ref(data, "main")
    r = client.post("/api/v1/repos/app/merge", json={"source_branch": "feature/x"})
    assert r.status_code == 409
    assert _ref(data, "main") == main_before
    assert "feature/x" in _branches(client)


@pytest.mark.parametrize("body,code", [
    ({"source_branch": "feature/x", "merge_method": "rebase"}, 422),
    ({"source_branch": "feature/x", "merge_method": "merge"}, 422),
    ({"source_branch": "missing"}, 400),
    ({"source_branch": "feature/x", "target_branch": "missing"}, 400),
])
def test_bad_merge_requests(gs, body, code):
    _, client, _ = gs
    client.post("/api/v1/repos/app/branches", json={"branch_name": "feature/x"})
    assert client.post("/api/v1/repos/app/merge", json=body).status_code == code


# ------------------------------------------------------------------ Smart HTTP end to end (H2)

@pytest.mark.skipif(shutil.which("git") is None, reason="git binary not available")
def test_real_git_clone_over_smart_http(monkeypatch, tmp_path):
    import uvicorn

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    base = f"http://127.0.0.1:{port}"
    auth = make_authenticator(audiences=(AUDIENCE,))
    mod, client, outer = load_git_server(monkeypatch, authenticator=auth)
    try:
        assert client.post("/api/v1/repos", json={"product_id": "app"}).status_code == 201
        assert client.post("/api/v1/repos/app/commits",
                           json={"branch": "main", "files": {"infra/workload/main.tf": "# tf\n"}}).status_code == 200

        server = uvicorn.Server(uvicorn.Config(mod.app, host="127.0.0.1", port=port, log_level="warning", lifespan="off"))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.time() + 10
        while not server.started and time.time() < deadline:
            time.sleep(0.05)
        assert server.started

        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp_path), "GIT_TERMINAL_PROMPT": "0",
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
               "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {make_token()}"}
        dest = tmp_path / "clone"
        res = subprocess.run(["git", "clone", "--depth", "1", "--branch", "main", "--", f"{base}/git/app.git", str(dest)],
                             env=env, capture_output=True, text=True, timeout=60)
        assert res.returncode == 0, res.stderr
        assert (dest / "infra" / "workload" / "main.tf").read_text() == "# tf\n"
        git_config = (dest / ".git" / "config").read_text()
        assert "Bearer" not in git_config and "Authorization" not in git_config

        # Without a token the clone is refused (401), and push is refused even with a token.
        env_noauth = {k: v for k, v in env.items() if not k.startswith("GIT_CONFIG_")}
        res2 = subprocess.run(["git", "clone", "--", f"{base}/git/app.git", str(tmp_path / "noauth")],
                              env=env_noauth, capture_output=True, text=True, timeout=60)
        assert res2.returncode != 0
        (dest / "new.txt").write_text("x")
        subprocess.run(["git", "-C", str(dest), "add", "new.txt"], env=env, check=True, capture_output=True)
        subprocess.run(["git", "-C", str(dest), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "x"],
                       env=env, check=True, capture_output=True)
        res3 = subprocess.run(["git", "-C", str(dest), "push", "origin", "HEAD:main"], env=env, capture_output=True,
                              text=True, timeout=60)
        assert res3.returncode != 0
        server.should_exit = True
        thread.join(timeout=10)
    finally:
        shutil.rmtree(outer, ignore_errors=True)
