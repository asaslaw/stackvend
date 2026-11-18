"""Commit hardening (owner 10-29): GIT-COMMITS-STRICT, DULWICH-DELETE-LOUD, IAC-UPGRADE-DEFAULT-BRANCH.

1. GIT-COMMITS-STRICT: the git server's `/commits` (CommitRequest) refuses unknown keys with 422 before writing, so a
   client that sends `files_to_delete` there gets a refusal instead of a commit that silently keeps the paths. Every
   existing client payload (ServerlessGitProvider, both routes) is accepted unchanged.
2. DULWICH-DELETE-LOUD: `GitHubProvider._commit_files_via_dulwich` no longer swallows `porcelain.remove` failures; a
   directory path is expanded to the tracked files under it; after staging, every requested deletion must be a
   staged delete or VCSDeletionNotStaged is raised before the commit and the push (nothing committed). A path with
   nothing tracked at or under it stays "already absent, not an error" (the git CLI path and git server contract).
3. IAC-UPGRADE-DEFAULT-BRANCH: the gateway IAC_UPGRADE branch reads the tree from the workload's recorded
   default_branch, the branch commit_and_open_pr cuts the upgrade branch from (was always "main").

Real dulwich repositories in temp dirs, the real git server on a temp dir, the real gateway function with fakes.
Hermetic: no network, no GCP.
"""
import hermetic_guard  # noqa: F401  (first import: tests/hermetic_guard.py)

import hashlib
import os
import shutil
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from dulwich import porcelain
from dulwich.objects import Blob
from dulwich.repo import Repo

from shared.providers import github_provider as ghp
from shared.providers import serverless_git_provider as sgp

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ID = b"Seed <seed@example.invalid>"


# =============================================================================================== GIT-COMMITS-STRICT
@pytest.fixture()
def server(monkeypatch):
    from fd4k_support import load_git_server

    mod, client, outer = load_git_server(monkeypatch)
    assert client.post("/api/v1/repos", json={"product_id": "app"}).status_code == 201
    assert client.post("/api/v1/repos/app/commits",
                       json={"branch": "main", "files": {"a.tf": "a", "old.tf": "o"}}).status_code == 200
    yield mod, client
    shutil.rmtree(outer, ignore_errors=True)


def _server_tree(client, branch="main"):
    return client.get(f"/api/v1/repos/app/tree/{branch}").json()["files"]


@pytest.mark.parametrize("extra", [{"files_to_delete": ["old.tf"]}, {"unknown": 1}, {"delete": ["old.tf"]}])
def test_commits_refuses_an_unknown_key_before_writing(server, extra):
    _, client = server
    before = _server_tree(client)
    r = client.post("/api/v1/repos/app/commits", json=dict({"branch": "main", "files": {"n.tf": "n"}}, **extra))
    assert r.status_code == 422, r.text
    assert _server_tree(client) == before


def test_commits_with_deletions_refuses_an_unknown_key_before_writing(server):
    _, client = server
    before = _server_tree(client)
    r = client.post("/api/v1/repos/app/commits-with-deletions",
                    json={"branch": "main", "files": {}, "files_to_delete": ["old.tf"], "unknown": 1})
    assert r.status_code == 422, r.text
    assert _server_tree(client) == before


def _client_payloads(monkeypatch, files_to_delete):
    """The exact JSON the real ServerlessGitProvider.commit_files sends (route, body)."""
    sent = []

    class _R:
        status_code = 200

        def json(self):
            return {"commit_sha": "c" * 40, "files_deleted": list(files_to_delete or [])}

    def post(url, **kw):
        sent.append((url.split("/api/v1/repos/app", 1)[1], kw.get("json")))
        return _R()

    monkeypatch.setattr(sgp, "requests", MagicMock(post=post))
    prov = sgp.ServerlessGitProvider(server_url="https://git.example.invalid", project_id="mock-stackvend-project")
    monkeypatch.setattr(prov, "_get_headers", lambda: {})
    kw = {} if files_to_delete is None else {"files_to_delete": files_to_delete}
    prov.commit_files("castor/app", "main", {"n.tf": "n"}, "msg", author_name="A", author_email="a@example.invalid",
                      **kw)
    return sent


@pytest.mark.parametrize("dels", [None, [], ["old.tf"]])
def test_every_client_payload_is_accepted_by_the_strict_server(server, monkeypatch, dels):
    """Do No Harm: the only /commits client (ServerlessGitProvider, 7 byte-identical copies) sends known keys only;
    its exact payloads are accepted on both routes."""
    ((route, body),) = _client_payloads(monkeypatch, dels)
    _, client = server
    r = client.post(f"/api/v1/repos/app{route}", json=body)
    assert r.status_code == 200, r.text
    tree = _server_tree(client)
    assert tree["n.tf"] == "n" and ("old.tf" in tree) == (not dels)


def test_commit_request_fields_are_what_the_client_sends(server):
    mod, _ = server
    assert set(mod.CommitRequest.model_fields) == {"branch", "files", "commit_message", "author_name",
                                                   "author_email"}
    assert set(mod.CommitChangesRequest.model_fields) == set(mod.CommitRequest.model_fields) | {"files_to_delete"}
    assert mod.CommitRequest.model_config.get("extra") == "forbid"


# =============================================================================================== DULWICH-DELETE-LOUD
SEED = {"a.tf": "a\n", "mod/x.tf": "x\n", "mod/sub/y.tf": "y\n", "modx.tf": "sibling\n", "keep/k.tf": "k\n"}


@pytest.fixture()
def origin():
    """A bare repository on main holding SEED (stands in for GitHub)."""
    tmp = tempfile.mkdtemp(prefix="dulwich-del-")
    seed = os.path.join(tmp, "seed")
    os.makedirs(seed)
    r = Repo.init(seed)
    for p, c in SEED.items():
        os.makedirs(os.path.dirname(os.path.join(seed, p)), exist_ok=True)
        with open(os.path.join(seed, p), "w") as f:
            f.write(c)
    porcelain.add(r, paths=list(SEED))
    sha = porcelain.commit(r, message=b"seed", author=ID, committer=ID)
    r.refs[b"refs/heads/main"] = sha
    bare = os.path.join(tmp, "origin")
    porcelain.clone(seed, bare, bare=True, branch=b"main")
    yield bare
    shutil.rmtree(tmp, ignore_errors=True)


def _origin_tree(bare, branch=b"main"):
    repo = Repo(bare)
    commit = repo[repo.refs[b"refs/heads/" + branch]]
    out = {}
    for e in repo.object_store.iter_tree_contents(commit.tree):
        obj = repo[e.sha]
        if isinstance(obj, Blob):
            out[e.path.decode()] = obj.data.decode()
    return out


def _provider():
    return ghp.GitHubProvider(project_id="mock-stackvend-project", github_token="test-token",
                              default_owner="example-org")


def _dulwich_commit(bare, files, files_to_delete=None, *, remove=None):
    """Run the real _commit_files_via_dulwich with clone/push redirected to the local bare origin."""
    real_clone, real_push = porcelain.clone, porcelain.push
    pushes = []

    def push(repo, remote_location=None, refspecs=None, **kw):
        pushes.append(refspecs)
        return real_push(repo, bare, refspecs, **kw)

    patches = [
        patch("shared.providers.github_provider.resolve_repo_identity",
              return_value=("example-org", "app", "example-org/app")),
        patch.object(porcelain, "clone", side_effect=lambda source, target, **kw: real_clone(bare, target, **kw)),
        patch.object(porcelain, "push", side_effect=push),
    ]
    if remove is not None:
        patches.append(patch.object(porcelain, "remove", side_effect=remove))
    for p in patches:
        p.start()
    try:
        sha = _provider()._commit_files_via_dulwich("example-org/app", "main", files, "msg",
                                                    files_to_delete=files_to_delete)
    finally:
        for p in reversed(patches):
            p.stop()
    return sha, pushes


def test_no_deletions_commits_exactly_the_written_files(origin):
    """Do No Harm: without files_to_delete the commit is the old one (writes only, everything else kept)."""
    sha, pushes = _dulwich_commit(origin, {"a.tf": "a2\n", "new.tf": "n\n"})
    assert len(pushes) == 1 and len(sha) == 40
    assert _origin_tree(origin) == dict(SEED, **{"a.tf": "a2\n", "new.tf": "n\n"})


def test_file_deletion_is_committed(origin):
    _dulwich_commit(origin, {"new.tf": "n\n"}, ["mod/x.tf"])
    after = _origin_tree(origin)
    assert "mod/x.tf" not in after
    assert after == {p: c for p, c in dict(SEED, **{"new.tf": "n\n"}).items() if p != "mod/x.tf"}


@pytest.mark.parametrize("path", ["mod", "/mod"])
def test_directory_deletion_removes_every_tracked_file_under_it(origin, path):
    """The silent-keep bug: a directory path used to raise inside porcelain.remove, swallowed; the commit landed with
    the files still there. Now every file under it is deleted; the sibling `modx.tf` (same prefix) is kept."""
    _dulwich_commit(origin, {"new.tf": "n\n"}, [path])
    after = _origin_tree(origin)
    assert not [p for p in after if p.startswith("mod/")]
    assert after["modx.tf"] == "sibling\n" and after["keep/k.tf"] == "k\n" and after["new.tf"] == "n\n"


def test_deletions_only_commit(origin):
    sha, pushes = _dulwich_commit(origin, {}, ["keep"])
    assert len(pushes) == 1
    assert _origin_tree(origin) == {p: c for p, c in SEED.items() if not p.startswith("keep/")}


def test_an_absent_path_is_not_an_error(origin):
    """Contract kept: a path with nothing tracked at or under it is already absent (same as the git CLI path and
    the git server's /commits-with-deletions): not an error; the other changes land."""
    _dulwich_commit(origin, {"new.tf": "n\n"}, ["nope.tf", "nodir", "mod/x.tf"])
    after = _origin_tree(origin)
    assert "mod/x.tf" not in after and after["new.tf"] == "n\n" and after["mod/sub/y.tf"] == "y\n"


def test_only_absent_deletions_change_nothing(origin):
    head = Repo(origin).refs[b"refs/heads/main"].decode()
    sha, pushes = _dulwich_commit(origin, {}, ["nope.tf"])
    assert sha == head and pushes == [] and _origin_tree(origin) == SEED


def test_a_deletion_that_is_not_staged_is_a_typed_refusal_and_nothing_is_committed(origin):
    head = Repo(origin).refs[b"refs/heads/main"]
    with pytest.raises(ghp.VCSDeletionNotStaged) as ei:
        _dulwich_commit(origin, {"new.tf": "n\n"}, ["mod"], remove=lambda *a, **k: None)   # remove does nothing
    assert ei.value.error_class == "VCS_DELETION_NOT_STAGED"
    assert ei.value.paths == ["mod/sub/y.tf", "mod/x.tf"] and "Nothing was committed" in str(ei.value)
    assert Repo(origin).refs[b"refs/heads/main"] == head and _origin_tree(origin) == SEED


def test_a_remove_failure_is_raised_not_swallowed(origin):
    def boom(*a, **k):
        raise RuntimeError("index locked")

    with pytest.raises(RuntimeError, match="Dulwich staging failed: index locked"):
        _dulwich_commit(origin, {"new.tf": "n\n"}, ["mod/x.tf"], remove=boom)
    assert _origin_tree(origin) == SEED


@pytest.mark.parametrize("files,dels", [({"mod/x.tf": "x2\n"}, ["mod/x.tf"]), ({"mod/x.tf": "x2\n"}, ["mod"])])
def test_a_path_both_written_and_deleted_is_refused(origin, files, dels):
    with pytest.raises(ghp.VCSDeletionNotStaged, match="both written and deleted"):
        _dulwich_commit(origin, files, dels)
    assert _origin_tree(origin) == SEED


def test_commit_files_keeps_the_typed_refusal(monkeypatch):
    """commit_files wraps dulwich failures in RuntimeError; the typed refusal passes through with its class."""
    prov = _provider()
    err = ghp.VCSDeletionNotStaged("example-org/app", "main", ["mod/x.tf"], "the deletions are not staged")
    monkeypatch.setattr(ghp.shutil, "which", lambda name: None)
    with patch.object(prov, "_commit_files_via_dulwich", side_effect=err):
        with pytest.raises(ghp.VCSDeletionNotStaged):
            prov.commit_files("example-org/app", "main", {}, "msg", files_to_delete=["mod/x.tf"])


@pytest.mark.parametrize("path", ["../escape.tf", ".git/config", "mod/"])
def test_unsafe_deletion_path_still_fails_closed(origin, path):
    """Unchanged: a non-canonical deletion path (traversal, .git, trailing slash) is refused by safe_join."""
    from shared.path_safety import UnsafePathError

    with pytest.raises(UnsafePathError):
        _dulwich_commit(origin, {}, [path])
    assert _origin_tree(origin) == SEED


def test_github_provider_replicas_are_byte_identical():
    copies = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared", "apps/project-vending/shared",
              "apps/qa-runner/shared", "mcp-servers/github/shared", "mcp-servers/terraform/shared"]
    digests = {c: hashlib.sha256(open(os.path.join(REPO_ROOT, c, "providers", "github_provider.py"), "rb").read())
               .hexdigest() for c in copies}
    assert len(set(digests.values())) == 1, digests


# =============================================================================================== IAC-UPGRADE-DEFAULT-BRANCH
class _WorkloadFs:
    def __init__(self, workload):
        self.workload = workload

    def collection(self, name):
        data = dict(self.workload) if name == "workloads" and self.workload is not None else None

        class _Doc:
            exists = data is not None

            def to_dict(self):
                return dict(data or {})

        class _Ref:
            def get(self):
                return _Doc()

            def update(self, payload):
                pass

        class _Col:
            def document(self, doc_id):
                return _Ref()

        return _Col()


class _BranchProvider:
    def __init__(self, files):
        self.files, self.fetched, self.sources, self.commits = dict(files), [], [], []

    def fetch_file_tree(self, repo, branch="main", **kw):
        self.fetched.append(branch)
        return dict(self.files)

    def create_or_verify_branch(self, repo, branch_name, source_branch="main"):
        self.sources.append(source_branch)
        return branch_name

    def commit_files(self, repo, branch, files, commit_message, **kw):
        self.commits.append(dict(files))
        return "a" * 40

    def create_pull_request(self, repo, **kw):
        self.pr_base = kw.get("base_branch")
        return {"pr_number": 7, "pull_request_url": "https://example.invalid/pull/7"}


def _gateway(monkeypatch, workload):
    from test_fd4dc_archive_and_partial_readers import _gateway_main, _workload_tree
    import shared.vcs_provider as vp

    gw = _gateway_main()
    prov = _BranchProvider(_workload_tree(drift=True))
    monkeypatch.setattr(vp.VCSProviderFactory, "get_provider", staticmethod(lambda *a, **k: prov))
    fs = _WorkloadFs(workload)
    monkeypatch.setattr(gw, "db", fs)
    monkeypatch.setattr(gw, "_record_pr_ledger", lambda *a, **k: None)
    req = gw.DeveloperExecuteRequest(product_id="app", trace_id="tr-1", change_type="IAC_UPGRADE",
                                     modules_to_upgrade=["compute-cloudrun"])
    return gw, prov, req, fs


WL = {"product_id": "app", "github_repo": "example-org/app", "vcs_provider": "GITHUB"}


@pytest.mark.parametrize("workload,expected", [
    (dict(WL, default_branch="release"), "release"),
    (dict(WL, default_branch="main"), "main"),
    (dict(WL), "main"),                       # no recorded branch (older workload): main, as commit_and_open_pr
    (dict(WL, default_branch=""), "main"),
    (None, "main"),                           # no workload document: main, as before
])
def test_gateway_upgrade_reads_the_tree_from_the_default_branch(monkeypatch, workload, expected):
    gw, prov, req, _ = _gateway(monkeypatch, workload)
    dev = MagicMock()
    dev.commit_and_open_pr.return_value = {"status": "COMMITTED", "pull_request_url": "https://example.invalid/p/1"}
    monkeypatch.setattr(gw, "developer_agent", dev)
    gw.developer_execute(req)
    assert prov.fetched == [expected]


def test_gateway_upgrade_reads_and_cuts_from_the_same_non_main_branch(monkeypatch):
    """End to end with the real commit_and_open_pr: the tree read, the branch cut and the PR base are one branch."""
    from test_fd4dc_followups import _agent, _Verifier

    gw, prov, req, fs = _gateway(monkeypatch, dict(WL, default_branch="release"))
    h, agent = _agent()
    agent.project_id = "mock-stackvend-project"
    agent.db = fs      # RT14-28: commit_and_open_pr reads workloads/{id} through the agent's own client
    verifier = type("V", (_Verifier,), {"seen": [], "cure": {}, "purge": ()})
    monkeypatch.setattr(gw, "developer_agent", agent)
    from google.cloud import firestore

    with patch.object(firestore, "Client", return_value=fs), \
            patch.object(h, "SynthesisVerifierAgent", verifier), \
            patch.object(h.VCSProviderFactory, "get_provider", return_value=prov), \
            patch.object(h.time, "sleep", return_value=None), \
            patch.object(agent, "get_full_repo_name", return_value="example-org/app", create=True), \
            patch.object(agent, "fetch_github_token", return_value="test-token", create=True), \
            patch.object(agent, "_write_iac_provenance"):
        out = gw.developer_execute(req)
    assert out["status"] == "SUCCESS", out
    assert prov.fetched == ["release"] and prov.sources == ["release"] and prov.pr_base == "release"
