"""RT14-13 (full-scope red-team 11-14): the developer commit wrote the start-of-build tree onto a branch cut from the
base branch's CURRENT head, so a person's commit on the base during the 20-60 minute build (or the QA-repair window)
was silently reverted by the pull request.

Now the commit compares, for every path it writes or deletes, what the build read of the base (the tree it read, or
for a QA repair the base its tested commit was cut from) with the base's current head: a path a person changed that
the commit would overwrite stops it typed (MAIN_MOVED, reason BASE_BRANCH_MOVED, the paths named; nothing is
written). Changes on paths the commit does not write are kept, and an unmoved base commits exactly as before
(negative tests). Exact path and byte comparison only. Plan: docs/planning/rt14-developer-qa-context-plan.md.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
from unittest.mock import patch

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import make_tar

sys.path.insert(0, os.path.dirname(__file__))

from test_rt14_base_branch import _DB, _agent, _commit  # noqa: E402

from developer_agent import handler as H  # noqa: E402
from developer_agent import qa_repair  # noqa: E402
from gate_errors import GateUnavailableError, MainMovedError  # noqa: E402
from qa_source import BranchFetchError  # noqa: E402

HUMAN = "infra/workload/human.tf"
APP = "apps/app/main.py"          # the path _commit writes ("x\n")
S0, S1 = "1" * 40, "2" * 40


class _Repo:
    """A base branch with commits by sha (qa_source backend shape: head_sha + archive at a sha)."""

    strip_top_dir = False

    def __init__(self, commits, head, readable=None):
        self.commits, self.head = commits, head
        self.readable = readable if readable is not None else set(commits)
        self.calls = []

    def head_sha(self, branch):
        self.calls.append(("head", branch))
        return self.head

    def archive(self, branch, sha):
        self.calls.append(("archive", sha))
        if sha not in self.readable:
            raise BranchFetchError(f"no archive for {sha}")
        return sha, make_tar({p: c.encode() for p, c in self.commits[sha].items()})


def _agent_with(snapshot, repo):
    agent = _agent(_DB(None))
    if snapshot is not None:
        agent._record_stack("tr-1", **{H.BASE_SNAPSHOT_FIELD: snapshot})
    agent._base_source = lambda product_id: repo
    return agent


def _start(files, complete=True):
    return {"branch": "main", "files": dict(files), "complete": complete}


START = {HUMAN: "# person v1\n", APP: "x\n"}


def test_person_edit_during_the_build_is_never_overwritten():
    repo = _Repo({S1: {HUMAN: "# person v2\n", APP: "x\n"}}, S1)
    agent = _agent_with(_start({HUMAN: "# person v1\n"}), repo)
    # the build would write the start-of-build copy of human.tf back
    with patch.object(agent, "commit_and_open_pr", wraps=agent.commit_and_open_pr):
        with pytest.raises(MainMovedError) as ei:
            _commit_files(agent, {HUMAN: "# person v1\n", APP: "x\n"})
    assert ei.value.reason == "BASE_BRANCH_MOVED" and ei.value.details["paths"] == [HUMAN]
    assert ei.value.vcs.commits == [] and ei.value.vcs.branches == []


def _commit_files(agent, files, deletes=None):
    from _fake_vcs import PassThroughVerifier
    from test_rt14_base_branch import _VCS
    vcs = _VCS()
    with patch.object(agent, "fetch_github_token", return_value="t"), \
            patch.object(H.VCSProviderFactory, "get_provider", return_value=vcs), \
            patch.object(H, "SynthesisVerifierAgent", PassThroughVerifier), \
            patch.object(H.time, "sleep", return_value=None):
        try:
            kw = {"files_to_delete": deletes, "commit_paths": sorted(files)} if deletes else {}
            return agent.commit_and_open_pr(product_id="app", files=dict(files), branch_name="castor/app-1",
                                            trace_id="tr-1", **kw), vcs
        except Exception as e:
            e.vcs = vcs
            raise


def test_n_unmoved_base_commits_as_before_and_records_the_base_head():
    repo = _Repo({S0: dict(START)}, S0)
    res, vcs = _commit_files(_agent_with(_start(START), repo), {HUMAN: START[HUMAN], APP: "x2\n"})
    assert res["status"] == "COMMITTED" and res["base_head_sha"] == S0 and vcs.commits == ["castor/app-1"]


def test_n_change_on_a_path_this_commit_does_not_write_is_kept():
    repo = _Repo({S1: dict(START, **{"docs/notes.md": "person\n"})}, S1)
    res, vcs = _commit_files(_agent_with(_start(START), repo), {APP: "x2\n"})
    assert res["status"] == "COMMITTED" and vcs.commits == ["castor/app-1"]


def test_n_writing_exactly_the_persons_new_content_is_no_conflict():
    repo = _Repo({S1: {HUMAN: "# person v2\n", APP: "x\n"}}, S1)
    res, _vcs = _commit_files(_agent_with(_start(START), repo), {HUMAN: "# person v2\n", APP: "x2\n"})
    assert res["status"] == "COMMITTED"


@pytest.mark.parametrize("now, label", [
    ({APP: "x\n"}, "person deleted a file the commit writes"),
    ({HUMAN: "# person v1\n", APP: "x\n", "apps/app/new.py": "person\n"}, "person added a path the build generates"),
])
def test_other_person_changes_on_written_paths_conflict(now, label):
    repo = _Repo({S1: now}, S1)
    files = {HUMAN: "# person v1\n", APP: "x\n", "apps/app/new.py": "generated\n"}
    with pytest.raises(MainMovedError) as ei:
        _commit_files(_agent_with(_start(START), repo), files)
    assert ei.value.details["paths"], label


def test_deleting_a_path_a_person_changed_conflicts():
    repo = _Repo({S1: {HUMAN: "# person v2\n", APP: "x\n"}}, S1)
    with pytest.raises(MainMovedError) as ei:
        _commit_files(_agent_with(_start(START), repo), {APP: "x2\n"}, deletes=[HUMAN])
    assert ei.value.details["paths"] == [HUMAN]


def test_qa_repair_compares_with_the_base_its_tested_commit_was_cut_from():
    base0 = dict(START)
    repo = _Repo({S0: base0, S1: dict(base0, **{HUMAN: "# person v2\n"})}, S1)
    snap = {"branch": "main", "base_sha": S0}
    with pytest.raises(MainMovedError) as ei:
        _commit_files(_agent_with(snap, repo), {HUMAN: "# person v1\n", APP: "x2\n"})
    assert ei.value.details["paths"] == [HUMAN]


def test_n_qa_repair_on_an_unmoved_base_reads_only_the_head():
    repo = _Repo({S0: dict(START)}, S0)
    res, _vcs = _commit_files(_agent_with({"branch": "main", "base_sha": S0}, repo), {APP: "x2\n"})
    assert res["status"] == "COMMITTED" and repo.calls == [("head", "main"), ("archive", S0)]


def test_qa_repair_with_an_unreadable_earlier_base_stops_typed():
    repo = _Repo({S0: dict(START), S1: dict(START)}, S1, readable={S1})
    with pytest.raises(MainMovedError) as ei:
        _commit_files(_agent_with({"branch": "main", "base_sha": S0}, repo), {APP: "x2\n"})
    assert ei.value.reason == "BASE_BRANCH_MOVED" and ei.value.vcs.commits == []


def test_unreadable_base_is_gate_unavailable_never_unchecked():
    repo = _Repo({}, S1, readable=set())
    with pytest.raises(GateUnavailableError) as ei:
        _commit_files(_agent_with(_start(START), repo), {APP: "x2\n"})
    assert ei.value.reason == "BASE_TREE_UNREADABLE" and ei.value.vcs.commits == []


def test_n_without_a_snapshot_nothing_is_read():
    def boom(product_id):
        raise AssertionError("no base read without a snapshot")
    agent = _agent(_DB(None))
    agent._base_source = boom
    res, vcs, _ = _commit(agent)
    assert res["status"] == "COMMITTED" and "base_head_sha" not in res


# ------------------------------------------------------------------------------------------------ snapshot capture
def test_tree_read_records_the_start_snapshot():
    agent = _agent(_DB(None))
    agent._base_source = lambda product_id: _Repo({S0: dict(START)}, S0)
    with patch.object(type(agent), "fetch_branch_files",
                      lambda self, product_id, branch_name="main": (setattr(self, "last_tree_status",
                                                                            {"complete": True}) or dict(START))):
        read = agent.fetch_existing_repo_files("app")
    assert read == START and read.snapshot == {"branch": "main", "files": START, "complete": True, "base_sha": S0}
    agent._record_base_read("tr-1", read)
    assert agent.stack_run("tr-1")[H.BASE_SNAPSHOT_FIELD] == read.snapshot
    assert agent.stack_run("tr-1")["base_branch"] == "main"
    assert not hasattr(agent, "last_start_snapshot") and not hasattr(agent, "last_base_branch")


def test_rt_f2_concurrent_dispatches_on_other_branches_keep_their_own_reads():
    """RT F2: a second dispatch (another workload, another base branch) reading between the first one's tree read and
    its record cannot change what the first one records (the read carries its branch and snapshot)."""
    agent = _agent(_DB(None))
    branches = {"a": "prod", "b": "main"}
    agent._recorded_workload_branch = lambda product_id: branches[product_id]
    heads = {"prod": S0, "main": S1}
    agent._base_source = lambda product_id: type("_H", (), {"head_sha": lambda self, br: heads[br]})()
    reads = {}

    def fetch_branch_files(self, product_id, branch_name="main"):
        if product_id == "a":                       # B's whole read happens inside A's
            reads["b"] = self.fetch_existing_repo_files("b")
        return {f"{product_id}.txt": branch_name}

    with patch.object(type(agent), "fetch_branch_files", fetch_branch_files):
        reads["a"] = agent.fetch_existing_repo_files("a")
    agent._record_base_read("tr-a", reads["a"])
    agent._record_base_read("tr-b", reads["b"])
    run_a, run_b = agent.stack_run("tr-a"), agent.stack_run("tr-b")
    assert run_a["base_branch"] == "prod" and run_a[H.BASE_SNAPSHOT_FIELD]["base_sha"] == S0
    assert run_a[H.BASE_SNAPSHOT_FIELD]["files"] == {"a.txt": "prod"}
    assert run_b["base_branch"] == "main" and run_b[H.BASE_SNAPSHOT_FIELD]["base_sha"] == S1


def test_rt_f2_n_a_read_that_is_not_the_agents_own_records_nothing():
    agent = _agent(_DB(None))
    agent._record_base_read("tr-1", {"a.txt": "x"})          # eval replay / a test double: a plain dict
    assert agent.stack_run("tr-1") == {}


def test_rt_f2_generate_code_files_keeps_no_base_read_on_the_instance():
    import ast
    import inspect
    src = inspect.getsource(H.DeveloperAgent)
    attrs = {n.attr for n in ast.walk(ast.parse(__import__("textwrap").dedent(src)))
             if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "self"}
    assert not attrs & {"last_base_branch", "last_start_snapshot"}


# ------------------------------------------------------------------- RT F1: GitHub start view through the real filter
WF = ".github/workflows/deploy-app.yml"
GITIGNORE = ".gitignore"

def _wf(version):
    return (f"name: deploy {version}\non:\n  push:\n    branches: [main]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo deploy\n")


BASE0 = {WF: _wf("v1"), GITIGNORE: "*.pyc\n", HUMAN: "# person v1\n", APP: "x\n"}


class _GitHubRepo(_Repo):
    provider = "GITHUB"


class _PyGithubRepo:
    """The PyGithub repository object GitHubProvider.fetch_file_tree reads (tree + blobs; no archive link)."""

    full_name = "example-org/app"

    def __init__(self, files):
        self.items = [(p, f"{i:040x}", c) for i, (p, c) in enumerate(files.items())]

    def get_git_tree(self, branch, recursive=True):
        from types import SimpleNamespace
        return SimpleNamespace(truncated=False,
                               tree=[SimpleNamespace(path=p, type="blob", sha=sha) for p, sha, _c in self.items])

    def get_git_blob(self, sha):
        import base64
        from types import SimpleNamespace
        return SimpleNamespace(content=base64.b64encode(next(c for _p, s, c in self.items if s == sha).encode()))


def _github_build(repo, base_files=BASE0):
    """A first build's tree read through the real GitHubProvider filter, recorded for trace tr-1."""
    from shared.providers.github_provider import GitHubProvider
    agent = _agent(_DB(None))
    agent._base_source = lambda product_id: repo
    prov = GitHubProvider(project_id="", github_token="test-token", default_owner="example-org")
    with patch.object(H.VCSProviderFactory, "get_provider", return_value=prov), \
            patch.object(prov, "_get_repo", return_value=_PyGithubRepo(base_files)):
        files = agent.fetch_existing_repo_files("app")
    assert WF not in files and GITIGNORE not in files and files[HUMAN] == base_files[HUMAN]   # the lossy view
    agent._record_base_read("tr-1", files)
    return agent


def test_rt_f1_n_unmoved_github_base_commits_a_changed_workflow_and_gitignore():
    repo = _GitHubRepo({S0: dict(BASE0)}, S0)
    agent = _github_build(repo)
    assert agent.stack_run("tr-1")[H.BASE_SNAPSHOT_FIELD]["base_sha"] == S0
    res, vcs = _commit_files(agent, {WF: _wf("v2"), GITIGNORE: "*.pyc\n.env\n", APP: "x2\n"})
    assert res["status"] == "COMMITTED" and res["base_head_sha"] == S0 and vcs.commits == ["castor/app-1"]
    assert repo.calls == [("head", "main"), ("head", "main"), ("archive", S0)]   # read, then the commit's head only


def test_rt_f1_n_moved_github_base_compares_exact_bytes_of_the_recorded_commit():
    repo = _GitHubRepo({S0: dict(BASE0)}, S0)
    agent = _github_build(repo)
    repo.commits[S1], repo.head = dict(BASE0, **{"docs/notes.md": "person\n"}), S1
    repo.readable = set(repo.commits)
    res, _vcs = _commit_files(agent, {WF: _wf("v2"), GITIGNORE: "*.pyc\n.env\n", APP: "x2\n"})
    assert res["status"] == "COMMITTED" and res["base_head_sha"] == S1


def test_rt_f1_person_commit_on_a_github_base_names_only_the_persons_path():
    repo = _GitHubRepo({S0: dict(BASE0)}, S0)
    agent = _github_build(repo)
    repo.commits[S1], repo.head = dict(BASE0, **{HUMAN: "# person v2\n"}), S1
    repo.readable = set(repo.commits)
    with pytest.raises(MainMovedError) as ei:
        _commit_files(agent, {WF: _wf("v2"), HUMAN: "# person v1\n", APP: "x2\n"})
    assert ei.value.reason == "BASE_BRANCH_MOVED" and ei.value.details["paths"] == [HUMAN]
    assert ei.value.vcs.commits == []


def test_rt_f1_unreadable_recorded_github_commit_is_gate_unavailable_never_the_lossy_view():
    repo = _GitHubRepo({S0: dict(BASE0)}, S0)
    agent = _github_build(repo)
    repo.commits[S1], repo.head, repo.readable = dict(BASE0), S1, {S1}
    with pytest.raises(GateUnavailableError) as ei:
        _commit_files(agent, {WF: _wf("v2"), APP: "x2\n"})
    assert ei.value.reason == "BASE_TREE_UNREADABLE" and ei.value.vcs.commits == []


@pytest.mark.parametrize("written, conflict", [({APP: "x2\n"}, []), ({HUMAN: "# person v1\n"}, [HUMAN])])
def test_rt_f1_git_server_moved_base_falls_back_to_the_tree_read(written, conflict):
    # the git server archives only the head: the recorded commit cannot be read, the build's own view is compared
    repo = _Repo({S1: {HUMAN: "# person v2\n", APP: "x\n"}}, S1)
    agent = _agent_with(dict(_start(START), base_sha=S0), repo)
    if conflict:
        with pytest.raises(MainMovedError) as ei:
            _commit_files(agent, written)
        assert ei.value.details["paths"] == conflict
    else:
        assert _commit_files(agent, written)[0]["status"] == "COMMITTED"


def test_rt_f1_unreadable_head_at_the_tree_read_records_no_commit_and_never_fails_the_build():
    def unreadable(product_id):
        raise BranchFetchError("no credential")
    agent = _agent(_DB(None))
    agent._base_source = unreadable
    with patch.object(type(agent), "fetch_branch_files", lambda self, product_id, branch_name="main": dict(START)):
        read = agent.fetch_existing_repo_files("app")
    assert read == START and "base_sha" not in read.snapshot and read.snapshot["files"] == START


def test_qa_repair_base_is_recorded_from_the_forwarded_commit_record():
    agent = _agent(_DB(None))
    agent._record_qa_repair_base("app", "tr-9", {qa_repair.BASE_HEAD_SHA_FIELD: S0})
    assert agent.stack_run("tr-9")[H.BASE_SNAPSHOT_FIELD] == {"branch": "main", "base_sha": S0}
    agent._record_qa_repair_base("app", "tr-8", {qa_repair.BASE_HEAD_SHA_FIELD: "not-a-sha"})
    assert H.BASE_SNAPSHOT_FIELD not in agent.stack_run("tr-8")


def test_gateway_records_and_forwards_the_base_head(monkeypatch):
    gw = fd4f_support.load_gateway(monkeypatch, "rt14_bm_gw1")
    extras = gw._committed_draft_extras({}, {"files_committed": ["a"], "base_head_sha": S0})
    assert extras[qa_repair.BASE_HEAD_SHA_FIELD] == S0
    assert gw._committed_draft_extras({}, {"files_committed": ["a"]})[qa_repair.BASE_HEAD_SHA_FIELD] is None
    db = fd4f_support.FakeDB()
    db.docs["pipeline_executions/tr-1"] = {"stages": {"developer": {gw.COMMITTED_DRAFT_FIELD: {
        "commit_sha": "c" * 40, "llm_draft_paths": ["a"], **extras}}}}
    assert gw._matched_commit_extras(db, "tr-1", "c" * 40)[qa_repair.BASE_HEAD_SHA_FIELD] == S0
