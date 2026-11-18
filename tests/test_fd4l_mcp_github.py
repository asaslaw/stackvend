"""FD-4L / FD27-17: mcp-github-toolserver acts only on the workload's own repository (lane 14 plan §3.4, row 23).

Hermetic: modules loaded by path; the ledger is an in-memory fake and GitHub is a fake PyGithub client (no token,
no network). Negatives first: another workload's repository, case variants, a repository outside GITHUB_ORG, the
host project, a renamed repository, fork PRs, retries of non-idempotent writes.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy
import os
import sys
from types import SimpleNamespace

import pytest
from github import GithubException

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GH_DIR = os.path.join(REPO, "mcp-servers", "github")
sys.path.insert(0, os.path.dirname(__file__))

HOST = "host-platform"
ORG = "acme-workloads"
OWN = f"{ORG}/castor-claims"
OTHER = f"{ORG}/castor-other"


# ----------------------------------------------------------------------------------------------- fakes
class _Snap:
    def __init__(self, doc_id, data):
        self.id, self._d, self.exists = doc_id, data, data is not None

    def to_dict(self):
        return copy.deepcopy(self._d)


class _Doc:
    def __init__(self, store, path):
        self.store, self.path = store, path

    def get(self):
        return _Snap(self.path.split("/")[-1], self.store.get(self.path))

    def set(self, data, merge=False):
        self.store[self.path] = copy.deepcopy(data)


class _Coll:
    def __init__(self, store, name, flt=None):
        self.store, self.name, self.flt = store, name, flt

    def where(self, filter=None):  # noqa: A002
        return _Coll(self.store, self.name, filter)

    def limit(self, n):
        return self

    def stream(self):
        return [_Snap(k.split("/", 1)[1], v) for k, v in sorted(self.store.items())
                if k.startswith(self.name + "/") and (self.flt is None or v.get(self.flt[0]) == self.flt[1])]

    def document(self, doc_id):
        return _Doc(self.store, f"{self.name}/{doc_id}")


class FakeDB:
    def __init__(self):
        self.store = {
            "workloads/claims": {"status": "ACTIVE", "project_id": "claims-child-123", "github_repo": OWN},
            "workloads/other": {"status": "ACTIVE", "project_id": "other-child-9", "github_repo": OTHER},
            "workloads/hosty": {"status": "ACTIVE", "project_id": HOST, "github_repo": f"{ORG}/castor-hosty"},
            "workloads/platform": {"status": "ACTIVE", "project_id": "p-1", "is_castor": True,
                                   "github_repo": f"{ORG}/projectcastor"},
            "workloads/outside": {"status": "ACTIVE", "project_id": "out-1", "github_repo": "someone-else/castor-x"},
            "workloads/norepo": {"status": "ACTIVE", "project_id": "nr-1"},
        }

    def collection(self, name):
        return _Coll(self.store, name)


def _gh_err(status):
    return GithubException(status, {"message": "x"}, {})


class FakePR:
    def __init__(self, number, head_repo, head_ref="feature/x", merged=False):
        self.number, self.title, self.merged = number, "t", merged
        self.html_url, self.diff_url = f"https://github.com/{OWN}/pull/{number}", "d"
        self.head = SimpleNamespace(ref=head_ref, sha=f"head-sha-{number}", repo=SimpleNamespace(full_name=head_repo))
        self.base = SimpleNamespace(ref="main", repo=SimpleNamespace(full_name=OWN))
        self.merge_calls, self.merge_shas, self.head_moved = [], [], False

    def merge(self, commit_message=None, merge_method=None, sha=None):
        self.merge_calls.append(merge_method)
        self.merge_shas.append(sha)
        if self.head_moved:
            raise _gh_err(409)
        return SimpleNamespace(merged=True, sha="m-sha", message="merged")


class FakeRepo:
    def __init__(self, full_name, calls):
        self.full_name, self.calls = full_name, calls
        self.branches = {"main": "sha-main"}
        self.open_pulls, self.pulls = [], {}
        self.fail_create_ref = None
        self.fail_create_pull = None
        self.deleted_refs = []

    def get_branch(self, name):
        self.calls.append(("get_branch", name))
        if name not in self.branches:
            raise _gh_err(404)
        return SimpleNamespace(commit=SimpleNamespace(sha=self.branches[name]))

    def create_git_ref(self, ref, sha):
        self.calls.append(("create_git_ref", ref))
        if self.fail_create_ref:
            raise _gh_err(self.fail_create_ref)
        self.branches[ref.split("refs/heads/", 1)[1]] = sha

    def get_git_tree(self, sha):
        return "tree"

    def create_git_tree(self, elements, base):
        self.calls.append(("create_git_tree", len(elements)))
        return "new-tree"

    def get_git_commit(self, sha):
        return "parent"

    def create_git_commit(self, message, tree, parents):
        self.calls.append(("create_git_commit", message))
        return SimpleNamespace(sha="new-commit-sha")

    def get_git_ref(self, ref):
        repo = self

        class _Ref:
            def edit(self, sha, force=False):
                repo.calls.append(("ref_edit", ref, sha, force))

            def delete(self):
                repo.deleted_refs.append(ref)

        return _Ref()

    def get_pulls(self, state=None, head=None, base=None):
        self.calls.append(("get_pulls", state, head, base))
        return [p for p in self.open_pulls if f"{ORG}:{p.head.ref}" == head]

    def create_pull(self, title, body, head, base):
        self.calls.append(("create_pull", head, base))
        if self.fail_create_pull:
            raise _gh_err(self.fail_create_pull)
        return FakePR(7, OWN, head)

    def get_pull(self, number):
        return self.pulls[number]

    def get_contents(self, path, ref=None):
        return SimpleNamespace(decoded_content=b"print('hi')\n", sha="blob", size=12)

    def compare(self, base, head):
        return SimpleNamespace(total_commits=1, files=[])


class FakeGithub:
    def __init__(self):
        self.calls, self.repos = [], {}

    def get_repo(self, name):
        self.calls.append(("get_repo", name))
        if name not in self.repos:
            self.repos[name] = FakeRepo(name, self.calls)
        return self.repos[name]


@pytest.fixture()
def gh(monkeypatch):
    from fastapi.testclient import TestClient

    from fd4g_support import load_module, real_modules

    real_modules(monkeypatch)
    seam = load_module(monkeypatch, "managed_target_seam", os.path.join(GH_DIR, "managed_target_seam.py"))
    monkeypatch.setattr(seam, "_field_filter", lambda field, value: (field, value))
    service_mod = load_module(monkeypatch, "service", os.path.join(GH_DIR, "service.py"))
    main = load_module(monkeypatch, "fd4l_github_main", os.path.join(GH_DIR, "main.py"))
    db, fake = FakeDB(), FakeGithub()
    svc = service_mod.GithubService(fake, db_factory=lambda: db, env={"PROJECT_ID": HOST, "GITHUB_ORG": ORG})
    monkeypatch.setattr(main, "service", svc)
    return SimpleNamespace(mod=service_mod, svc=svc, db=db, gh=fake, main=main, client=TestClient(main.app))


def _repo_calls(gh):
    return [c for c in gh.gh.calls if c[0] == "get_repo"]


# ----------------------------------------------------------------------------------------------- repository identity
TOOL_CALLS = {
    "create_branch": lambda s, **t: s.create_branch(new_branch="feature/x", **t),
    "read_file_content": lambda s, **t: s.read_file_content(file_path="README.md", **t),
    "commit_files": lambda s, **t: s.commit_files(branch="feature/x", commit_message="m", files={"a.txt": "x"}, **t),
    "get_diff": lambda s, **t: s.get_diff(base="main", head="feature/x", **t),
    "create_pull_request": lambda s, **t: s.create_pull_request(title="t", body="b", head_branch="feature/x", **t),
}


@pytest.mark.parametrize("tool", sorted(TOOL_CALLS))
@pytest.mark.parametrize("product_id,repo_name,code", [
    ("claims", OTHER, "REFUSED:REPO_MISMATCH"),                       # another workload's repository
    ("claims", "Acme-Workloads/Castor-Claims", "REFUSED:REPO_MISMATCH"),  # exact match, no case folding
    ("claims", f"{OWN}-fork", "REFUSED:REPO_MISMATCH"),               # no prefix match
    ("claims", "another-org/castor-claims", "REFUSED:REPO_MISMATCH"),         # same name, other owner
    ("outside", None, "REFUSED:REPO_OUTSIDE_ORG"),                    # ledger repo outside GITHUB_ORG
    ("norepo", None, "REFUSED:REPO_NOT_RECORDED"),
    ("hosty", None, "REFUSED:HOST_PROJECT"),
    ("platform", None, "REFUSED:PLATFORM_WORKLOAD"),                  # the platform repo itself
    ("missing", None, "REFUSED:LEDGER_MISSING"),
    ("", None, "REFUSED:LEDGER_MISSING"),
])
def test_every_tool_acts_only_on_the_ledger_repository(gh, tool, product_id, repo_name, code):
    with pytest.raises(gh.mod.GithubRefused) as exc:
        TOOL_CALLS[tool](gh.svc, product_id=product_id, repo_name=repo_name)
    assert exc.value.code == code and exc.value.http_status == 403
    assert gh.gh.calls == []  # refused before any GitHub call


def test_github_org_unset_fails_closed(gh):
    svc = gh.mod.GithubService(gh.gh, db_factory=lambda: gh.db, env={"PROJECT_ID": HOST})
    with pytest.raises(gh.mod.GithubRefused) as exc:
        svc.read_file_content("claims", "README.md")
    assert exc.value.code == "REFUSED:GITHUB_ORG_UNCONFIGURED" and exc.value.http_status == 503
    assert gh.gh.calls == []


def test_renamed_repository_redirect_is_refused(gh):
    gh.gh.repos[OWN] = FakeRepo(f"{ORG}/castor-claims-renamed", gh.gh.calls)
    with pytest.raises(gh.mod.GithubRefused) as exc:
        gh.svc.read_file_content("claims", "README.md")
    assert exc.value.code == "REFUSED:REPO_MISMATCH"


def test_negative_own_repository_by_product_or_exact_name_reads_unchanged(gh):
    a = gh.svc.read_file_content("claims", "README.md")
    b = gh.svc.read_file_content("claims", "README.md", repo_name=OWN)
    assert a == b and a["content"] == "print('hi')\n"
    assert _repo_calls(gh) == [("get_repo", OWN), ("get_repo", OWN)]


# ----------------------------------------------------------------------------------------------- typed inputs
@pytest.mark.parametrize("branch", ["--force", "a..b", "refs/../x", "/main", "main/", "a//b", "x.lock", ".hidden",
                                    "has space", "", "a" * 201])
def test_branch_names_are_typed(gh, branch):
    with pytest.raises(gh.mod.GithubRefused) as exc:
        gh.svc.create_branch("claims", branch)
    assert exc.value.code == "NEW_BRANCH_INVALID" and gh.gh.calls == []


@pytest.mark.parametrize("path", ["../escape.txt", "/etc/passwd", "a//b", "a/./b", "a\\b", "", "x\0y"])
def test_commit_paths_are_repository_relative(gh, path):
    with pytest.raises(gh.mod.GithubRefused) as exc:
        gh.svc.commit_files("claims", "feature/x", "m", {path: "x"})
    assert exc.value.code == "FILES_INVALID" and gh.gh.calls == []


# ----------------------------------------------------------------------------------------------- writes: check before write
def test_create_branch_refuses_an_existing_branch(gh):
    with pytest.raises(gh.mod.GithubRefused) as exc:
        gh.svc.create_branch("claims", "main")
    assert exc.value.code == "BRANCH_EXISTS" and exc.value.http_status == 409
    assert not [c for c in gh.gh.calls if c[0] == "create_git_ref"]


def test_create_branch_is_not_retried_and_records_the_branch(gh):
    res = gh.svc.create_branch("claims", "feature/x")
    assert res["status"] == "BRANCH_CREATED" and res["repo"] == OWN and res["branch_recorded"] is True
    assert [k for k in gh.db.store if k.startswith("github_mcp_branches/")]
    repo = gh.gh.repos[OWN]
    repo.fail_create_ref = 502
    with pytest.raises(GithubException):
        gh.svc.create_branch("claims", "feature/y")
    assert [c for c in gh.gh.calls if c[0] == "create_git_ref"] == [
        ("create_git_ref", "refs/heads/feature/x"), ("create_git_ref", "refs/heads/feature/y")]  # one try each


def test_commit_is_one_fast_forward_never_forced(gh):
    res = gh.svc.commit_files("claims", "main", "feat: x", {"app/main.py": "print(1)\n"})
    assert res["status"] == "COMMITTED"
    assert ("ref_edit", "heads/main", "new-commit-sha", False) in gh.gh.calls


def test_create_pull_request_returns_the_open_pr_instead_of_a_duplicate(gh):
    repo = gh.gh.get_repo(OWN)
    gh.gh.calls.clear()
    repo.open_pulls.append(FakePR(3, OWN, "feature/x"))
    res = gh.svc.create_pull_request("claims", "t", "b", "feature/x")
    assert res["status"] == "PR_EXISTS" and res["pr_number"] == 3
    assert not [c for c in gh.gh.calls if c[0] == "create_pull"]


def test_create_pull_request_failure_is_not_retried(gh):
    gh.gh.get_repo(OWN).fail_create_pull = 502
    with pytest.raises(GithubException):
        gh.svc.create_pull_request("claims", "t", "b", "feature/new")
    assert len([c for c in gh.gh.calls if c[0] == "create_pull"]) == 1


# ----------------------------------------------------------------------------------------------- routes
def test_rest_and_mcp_return_typed_refusals(gh):
    r = gh.client.post("/commit", json={"product_id": "claims", "repo_name": OTHER, "branch": "main",
                                        "commit_message": "m", "files": {"a": "b"}})
    assert r.status_code == 403 and r.json()["detail"]["status"] == "REFUSED:REPO_MISMATCH"
    # FD-4P / FD-4BB (owner row 23, L16-k): the merge route is deleted; this server never merges
    r = gh.client.post("/merge", json={"product_id": "claims", "repo_name": OWN, "pr_number": 1})
    assert r.status_code in (404, 405)
    rpc = gh.client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "read_file", "arguments": {"product_id": "claims", "repo_name": OTHER, "file_path": "a"}}}).json()
    assert "result" not in rpc and rpc["error"]["data"]["status"] == "REFUSED:REPO_MISMATCH"
    assert gh.gh.calls == []


def test_github_api_errors_become_typed_refusals_on_routes(gh):
    gh.gh.get_repo(OWN).fail_create_pull = 422
    gh.gh.calls.clear()
    r = gh.client.post("/pull-request", json={"product_id": "claims", "title": "t", "body": "b",
                                              "head_branch": "feature/z"})
    assert r.status_code == 422 and r.json()["detail"]["status"] == "GITHUB_ERROR"


def test_mcp_tools_list_requires_product_id_and_has_no_merge(gh):
    tools = gh.client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).json()["result"]["tools"]
    assert {t["name"] for t in tools} == {"create_branch", "read_file", "commit_files", "get_diff",
                                          "create_pull_request"}
    assert all("product_id" in t["inputSchema"]["required"] for t in tools)


# ----------------------------------------------------------------------------------------------- FD-4P / FD-4BB
def test_github_mcp_server_never_merges(gh):
    """Owner row 23 / L16-k (Fable RT §6 ruling): the merge path is deleted, not stubbed. StackVend merges only
    ledger-recorded PRs through the gateway release step and the Control Center approval."""
    assert not hasattr(gh.svc, "merge_pull_request")
    assert not hasattr(gh.mod, "MERGE_METHODS")
    assert "merge_pull_request" not in gh.main.TOOLS and not hasattr(gh.main, "MergePRRequest")
    assert gh.client.post("/merge", json={"product_id": "claims", "pr_number": 1}).status_code in (404, 405)
