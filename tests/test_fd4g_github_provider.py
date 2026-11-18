"""FD-4G: git working-tree sinks in github_provider (T11, T12, H1; CLI + Dulwich) and handler.py (T12).

All git/Dulwich operations are mocked: the fake 'clone' materialises a working tree (with repository metadata
and a sibling victim file outside the clone) so we can observe exactly what the provider writes or deletes.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import socket
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")

import shared.providers.github_provider as gp  # noqa: E402
from shared.path_safety import UnsafePathError  # noqa: E402

GIT_META = ".git"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def _blocked(self, addr):
        raise OSError(f"network blocked in FD-4G test: {addr}")

    monkeypatch.setattr(socket.socket, "connect", _blocked)


@pytest.fixture()
def sandbox(monkeypatch):
    """Pin tempfile.tempdir under a scratch root that also holds a victim file beside the clone dirs."""
    outer = tempfile.mkdtemp(prefix="fd4g-gp-")
    tmp_root = os.path.join(outer, "tmp")
    os.makedirs(tmp_root)
    victim = os.path.join(tmp_root, "victim.txt")
    with open(victim, "w") as fh:
        fh.write("keep me\n")
    monkeypatch.setattr(tempfile, "tempdir", tmp_root)
    state = SimpleNamespace(outer=outer, tmp_root=tmp_root, victim=victim, staged=None, clone_dir=None)
    yield state
    import shutil

    shutil.rmtree(outer, ignore_errors=True)


def _materialise_clone(target, state):
    os.makedirs(os.path.join(target, GIT_META), exist_ok=True)
    with open(os.path.join(target, GIT_META, "config"), "w") as fh:
        fh.write("[core]\n\tbare = false\n")
    os.makedirs(os.path.join(target, "apps", "old"), exist_ok=True)
    with open(os.path.join(target, "apps", "old", "main.py"), "w") as fh:
        fh.write("print('old')\n")
    with open(os.path.join(target, "README.md"), "w") as fh:
        fh.write("# repo\n")
    state.clone_dir = target


def _tree(root):
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        if GIT_META in dirnames and dirpath == root:
            dirnames.remove(GIT_META)
        for n in filenames:
            p = os.path.join(dirpath, n)
            with open(p) as fh:
                out[os.path.relpath(p, root)] = fh.read()
    return out


def _fake_git_run(state):
    def run(cmd, cwd=None, **kw):
        if "clone" in cmd:
            _materialise_clone(cmd[-1], state)
        elif cmd[:2] == ["git", "add"]:
            state.staged = _tree(cwd)
            with open(os.path.join(cwd, GIT_META, "config")) as fh:
                state.git_config = fh.read()
        if cmd[:2] == ["git", "status"]:
            return MagicMock(returncode=0, stdout=" M file\n", stderr="")
        if cmd[:2] == ["git", "rev-parse"]:
            return MagicMock(returncode=0, stdout="abc1234\n", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    return run


def _provider():
    p = gp.GitHubProvider.__new__(gp.GitHubProvider)
    p.project_id = ""
    p._explicit_token = "test-token"
    p.default_owner = "castor-org"
    p._token_manager = None
    return p


def _cli_commit(state, files, files_to_delete=None):
    with patch.object(gp.subprocess, "run", side_effect=_fake_git_run(state)):
        return _provider()._commit_files_via_git_cli("castor-org/app", "feature/x", files, "msg",
                                                      files_to_delete=files_to_delete)


class _FakePorcelain:
    def __init__(self, state):
        self.state = state
        self.added = None
        self.removed = None

    def clone(self, source, target, **kw):
        _materialise_clone(target, self.state)
        repo = MagicMock()
        repo.head.return_value = b"abc1234"
        # DULWICH-DELETE-LOUD: the provider reads the clone's index (tracked paths) to resolve deletions
        tracked = [p.replace(os.sep, "/").encode() for p in sorted(_tree(target))]
        repo.open_index.return_value = tracked
        return repo

    def add(self, repo, paths):
        self.added = sorted(paths)
        self.state.staged = _tree(self.state.clone_dir)

    def remove(self, repo, paths, cached=False):
        self.removed = sorted(paths)

    def status(self, repo):
        # DULWICH-DELETE-LOUD: the provider verifies every requested deletion is a staged delete
        return SimpleNamespace(staged={"add": [b"x"], "modify": [],
                                       "delete": [p.encode() for p in (self.removed or [])]})

    def commit(self, repo, **kw):
        return b"abc1234"

    def push(self, repo, **kw):
        return None

    def branch_create(self, *a, **k):
        return None


def _dulwich_commit(state, files, files_to_delete=None):
    fake = _FakePorcelain(state)
    with patch.object(gp, "porcelain", fake, create=True), patch.object(gp, "DULWICH_AVAILABLE", True):
        sha = _provider()._commit_files_via_dulwich("castor-org/app", "feature/x", files, "msg",
                                                     files_to_delete=files_to_delete)
    return sha, fake


ENGINES = ["cli", "dulwich"]


def _explicit_rmtree_calls(rm):
    """rmtree calls made by the code under test (TemporaryDirectory cleanup passes onexc=/onerror=)."""
    return [c for c in rm.call_args_list if not c.kwargs]


def _commit(engine, state, files, files_to_delete=None):
    if engine == "cli":
        return _cli_commit(state, files, files_to_delete)
    return _dulwich_commit(state, files, files_to_delete)[0]


# ---------------------------------------------------------------- attacks

@pytest.mark.parametrize("engine", ENGINES)
def test_delete_traversal_rejected_victim_survives(sandbox, engine):
    with pytest.raises(UnsafePathError):
        _commit(engine, sandbox, {"apps/api/main.py": "x = 1\n"}, files_to_delete=["../victim.txt"])
    assert os.path.exists(sandbox.victim)


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("key", [".", "/", ""])
def test_write_key_resolving_to_clone_root_rejected_no_rmtree(sandbox, engine, key):
    with patch.object(gp.shutil, "rmtree") as rm:
        with pytest.raises(UnsafePathError):
            _commit(engine, sandbox, {key: "x"})
    assert _explicit_rmtree_calls(rm) == []
    assert sandbox.staged is None


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("key", [".git/config", ".GIT/config", "apps/x/.git/config", "/.git/hooks/pre-commit"])
def test_write_into_git_metadata_rejected(sandbox, engine, key):
    with pytest.raises(UnsafePathError):
        _commit(engine, sandbox, {key: "[core]\n\tsshCommand = evil\n"})
    assert sandbox.staged is None  # rejected before any git add / commit / push


@pytest.mark.parametrize("engine", ENGINES)
def test_delete_git_metadata_rejected(sandbox, engine):
    with pytest.raises(UnsafePathError):
        _commit(engine, sandbox, {"apps/api/main.py": "x = 1\n"}, files_to_delete=[".git"])


@pytest.mark.parametrize("key", ["../victim.txt", "../../x"])
def test_write_traversal_rejected(sandbox, key):
    for engine in ENGINES:
        with pytest.raises(UnsafePathError):
            _commit(engine, sandbox, {key: "pwned"})
    with open(sandbox.victim) as fh:
        assert fh.read() == "keep me\n"


def test_commit_files_does_not_fall_back_to_dulwich_on_unsafe_key(sandbox):
    p = _provider()
    with patch.object(gp.shutil, "which", return_value="/usr/bin/git"), \
         patch.object(p, "_commit_files_via_git_cli", side_effect=UnsafePathError("../x", "non-canonical component '..'")), \
         patch.object(p, "_commit_files_via_dulwich") as dul:
        with pytest.raises(UnsafePathError):
            p.commit_files("castor-org/app", "b", {"../x": ""}, "m")
    dul.assert_not_called()


# ---------------------------------------------------------------- Do-No-Harm

LEGIT_FILES = {
    "infra/workload/main.tf": "# main\n",
    "apps/api/main.py": "print('api')\n",
    "apps/api/.python-version": "3.12\n",
    ".github/workflows/deploy-app.yml": (
        "name: deploy\non:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo ok\n"
    ),
    ".gitignore": "__pycache__/\n",
    "apps/web/app/[id]/page.tsx": "export {}\n",
}


@pytest.mark.parametrize("engine", ENGINES)
def test_ordinary_writes_and_deletes_identical(sandbox, engine):
    sha = _commit(engine, sandbox, dict(LEGIT_FILES), files_to_delete=["apps/old/main.py"])
    assert sha == "abc1234"
    expected = dict(LEGIT_FILES)
    expected["README.md"] = "# repo\n"
    assert sandbox.staged == expected
    assert os.path.exists(sandbox.victim)


def test_dulwich_staged_paths_identical(sandbox):
    _, fake = _dulwich_commit(sandbox, dict(LEGIT_FILES), files_to_delete=["apps/old/main.py"])
    assert fake.added == sorted(LEGIT_FILES)
    assert fake.removed == ["apps/old/main.py"]


@pytest.mark.parametrize("engine", ENGINES)
def test_leading_slash_and_backslash_normalisation_kept(sandbox, engine):
    _commit(engine, sandbox, {"/apps/api/main.py": "a\n", "apps\\web\\main.py": "b\n"})
    assert sandbox.staged["apps/api/main.py"] == "a\n"
    assert sandbox.staged["apps/web/main.py"] == "b\n"


# ---------------------------------------------------------------- handler.py git CLI sink (T12)

class _PassThroughVerifier:
    """FD-4F A9: the pre-commit verifier is mandatory (a None verifier now fails closed); this one passes the tree
    through unchanged so these tests reach the CLI commit writer they exercise."""

    def __init__(self, product_id=None):
        pass

    def purge_shadowed_package_files(self, files):
        return dict(files), []

    def verify_and_cure(self, files, product_id=None, **kw):
        return dict(files), True, []


def _handler_commit(sandbox, files):
    if GW_DIR not in sys.path:
        sys.path.insert(0, GW_DIR)
    from developer_agent import handler as h

    agent = h.DeveloperAgent.__new__(h.DeveloperAgent)
    agent.db = None
    agent.project_id = ""
    agent.vcs_provider = "GITHUB"
    rest = MagicMock()
    with patch.object(h, "VCSProviderFactory", None), \
         patch.object(h, "SynthesisVerifierAgent", _PassThroughVerifier), \
         patch.object(h, "Github", rest), \
         patch.object(h.shutil, "which", return_value="/usr/bin/git"), \
         patch.object(h.subprocess, "run", side_effect=_fake_git_run(sandbox)), \
         patch.object(agent, "get_full_repo_name", return_value="castor-org/castor-app", create=True), \
         patch.object(agent, "fetch_github_token", return_value="test-token", create=True):
        try:
            return agent.commit_and_open_pr("app", files, branch_name="main"), rest
        except Exception as e:  # noqa: BLE001 - re-raised with the REST mock for assertions
            e.rest_mock = rest
            raise


@pytest.mark.parametrize("key", [".git/config", ".", "../victim.txt"])
def test_handler_cli_rejects_unsafe_keys_and_does_not_fall_back_to_rest(sandbox, key):
    with patch("shutil.rmtree") as rm:
        with pytest.raises(UnsafePathError) as ei:
            _handler_commit(sandbox, {key: "x"})
    ei.value.rest_mock.assert_not_called()
    assert _explicit_rmtree_calls(rm) == []
    assert sandbox.staged is None
    with open(sandbox.victim) as fh:
        assert fh.read() == "keep me\n"


def test_handler_cli_ordinary_writes_identical(sandbox):
    res, rest = _handler_commit(sandbox, dict(LEGIT_FILES))
    assert res["status"] == "COMMITTED"
    expected = dict(LEGIT_FILES)
    expected.update({"README.md": "# repo\n", "apps/old/main.py": "print('old')\n"})
    assert sandbox.staged == expected
