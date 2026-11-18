"""RT14-28 (full-scope red-team 11-14): the base branch was hardcoded to, or silently fell back to, `main`.

QA diffed against "main" whatever the workload's recorded branch, and any base fetch error became an empty base (the
judges then audit the whole repository as new code). The developer commit read the workload record through a
second client under `except Exception: pass`, so a transient error cut the branch from "main" with the default VCS.

Now: one resolver (handler.workflow_branch of workloads/{pid}.default_branch) for the tree read, the commit, the
IaC upgrade, QA's diff base and the PR ledger; an unreadable record is typed (developer WORKLOAD_RECORD_UNREADABLE,
QA GATE_UNAVAILABLE WORKLOAD_RECORD_UNREADABLE); only a typed "no such branch" or an empty tree is an empty QA base;
a tree read from one branch is never committed against another (MAIN_MOVED BASE_BRANCH_CHANGED); the ledger refuses a
commit whose base is not the recorded branch. A workload with no recorded branch keeps "main" (negative tests).
Plan: docs/planning/rt14-developer-qa-context-plan.md.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
from unittest.mock import patch

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import (SHA_A, SHA_B, FakeBackend, FakeDB, FakeQAClient, backend_factory, judge_reply,
                          passing_outcome, seed_context)

sys.path.insert(0, os.path.dirname(__file__))

import qa_auditor.judge as judge_mod  # noqa: E402
from qa_auditor import judge_input as ji  # noqa: E402
from qa_source import BranchFetchError, BranchNotFoundError, EmptyArchiveError, normalize_archive  # noqa: E402

BRANCH = "castor/app-1"
TREE = {"apps/app/main.py": b"print('hi')\n"}


# ============================================================================================ QA diff base
def _capture(monkeypatch):
    seen = []
    monkeypatch.setattr(judge_mod, "call", lambda p, m, **k: seen.append(p) or judge_reply()(p, m))
    return seen


def _qa(gw, db, backend, client=None):
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name=BRANCH)
    return gw.run_qa(req, client=client or FakeQAClient(passing_outcome()),
                     source_backend_factory=backend_factory(backend), evidence_db=db)


def test_qa_diff_base_is_the_recorded_branch(monkeypatch):
    gw = fd4f_support.load_gateway(monkeypatch, "rt14_bb_gw1")
    seen = _capture(monkeypatch)
    db = FakeDB()
    seed_context(db)
    db.docs["workloads/app"]["default_branch"] = "prod"
    backend = FakeBackend({BRANCH: TREE, "prod": {"README.md": b"# a\n"}}, {BRANCH: SHA_A, "prod": SHA_B})
    assert _qa(gw, db, backend)["passed"] is True
    assert ("head", "prod") in backend.calls and ("head", "main") not in backend.calls
    assert all("base branch prod -> this commit" in p for p in seen)


def test_n_qa_without_a_recorded_branch_diffs_against_main(monkeypatch):
    gw = fd4f_support.load_gateway(monkeypatch, "rt14_bb_gw2")
    seen = _capture(monkeypatch)
    db = FakeDB()
    seed_context(db)
    backend = FakeBackend({BRANCH: TREE, "main": {"README.md": b"# a\n"}}, {BRANCH: SHA_A, "main": SHA_B})
    assert _qa(gw, db, backend)["passed"] is True
    assert ("head", "main") in backend.calls
    assert all("base branch main -> this commit" in p for p in seen)


class _BaseOutage(FakeBackend):
    def head_sha(self, branch):
        if branch == "main":
            raise BranchFetchError("GitHub branch lookup for 'main' returned HTTP 502")
        return super().head_sha(branch)


def test_qa_base_outage_is_gate_unavailable_never_an_empty_base(monkeypatch):
    gw = fd4f_support.load_gateway(monkeypatch, "rt14_bb_gw3")
    db = FakeDB()
    seed_context(db)
    client = FakeQAClient(passing_outcome())
    with pytest.raises(gw.GateUnavailableError) as ei:
        _qa(gw, db, _BaseOutage({BRANCH: TREE}, {BRANCH: SHA_A}), client)
    assert ei.value.reason == "SOURCE_FETCH" and ei.value.details == {"base_branch": "main"}
    assert client.calls == []   # the QA job never ran against a guessed empty base


@pytest.mark.parametrize("trees, shas", [({BRANCH: TREE}, {BRANCH: SHA_A}),                  # typed: no base branch
                                         ({BRANCH: TREE, "main": {}}, {BRANCH: SHA_A, "main": SHA_B})])  # empty tree
def test_n_qa_missing_or_empty_base_still_diffs_against_an_empty_base(monkeypatch, trees, shas):
    gw = fd4f_support.load_gateway(monkeypatch, "rt14_bb_gw4")
    _capture(monkeypatch)
    db = FakeDB()
    seed_context(db)
    assert _qa(gw, db, FakeBackend(trees, shas))["passed"] is True


class _WorkloadsDown(FakeDB):
    def __init__(self):
        super().__init__()
        self.down = False

    def collection(self, name):
        if name == "workloads" and self.down:
            raise RuntimeError("firestore unavailable")
        return super().collection(name)


def test_qa_unreadable_workload_record_is_typed(monkeypatch):
    gw = fd4f_support.load_gateway(monkeypatch, "rt14_bb_gw5")
    db = _WorkloadsDown()
    seed_context(db)
    db.down = True
    with pytest.raises(gw.GateUnavailableError) as ei:
        gw._qa_base_branch(db, "app")
    assert ei.value.reason == "WORKLOAD_RECORD_UNREADABLE"


def test_typed_source_errors():
    assert issubclass(BranchNotFoundError, BranchFetchError) and issubclass(EmptyArchiveError, BranchFetchError)
    import io
    import tarfile
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w"):
        pass
    with pytest.raises(EmptyArchiveError):
        normalize_archive(raw.getvalue(), strip_top_dir=False)


def test_n_judge_input_header_default_is_byte_identical():
    a = ji.build_judge_input({}, {"a.py": "x\n"})
    b = ji.build_judge_input({}, {"a.py": "x\n"}, base_branch="main")
    assert a == b and "base branch main -> this commit" in a.files
    assert "base branch prod -> this commit" in ji.build_judge_input({}, {"a.py": "x\n"}, base_branch="prod").files


# ============================================================================================ developer commit
class _Snap:
    def __init__(self, data):
        self._d = data
        self.exists = data is not None

    def to_dict(self):
        return dict(self._d) if self._d is not None else None


class _DB:
    def __init__(self, data=None, error=None):
        self.data, self.error = data, error

    def collection(self, name):
        db = self

        class _Ref:
            def document(self, _id):
                class _Doc:
                    def get(self_inner):
                        if db.error is not None:
                            raise db.error
                        return _Snap(db.data)
                return _Doc()
        return _Ref()


def _agent(db):
    from developer_agent.handler import DeveloperAgent
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": ""}):
        a = DeveloperAgent()
    a.db = db
    return a


class _VCS:
    def __init__(self):
        self.branches, self.prs, self.commits = [], [], []

    def create_or_verify_branch(self, repo, branch, source_branch="main"):
        self.branches.append((branch, source_branch))

    def commit_files(self, repo, branch, files, msg, **kw):
        self.commits.append(branch)
        return "a" * 40

    def create_pull_request(self, repo, **kw):
        self.prs.append(kw.get("base_branch"))
        return {"pull_request_url": "https://example.invalid/pull/1", "pr_number": 1}


def _commit(agent, trace="tr-1"):
    from _fake_vcs import PassThroughVerifier
    from developer_agent import handler as h
    vcs = _VCS()
    with patch.object(agent, "fetch_github_token", return_value="t"), \
            patch.object(h.VCSProviderFactory, "get_provider", return_value=vcs) as gp, \
            patch.object(h, "SynthesisVerifierAgent", PassThroughVerifier), \
            patch.object(h.time, "sleep", return_value=None):
        try:
            return agent.commit_and_open_pr(product_id="app", files={"apps/app/main.py": "x\n"},
                                            branch_name="castor/app-1", trace_id=trace), vcs, gp
        except Exception as e:
            e.vcs = vcs
            raise


def test_commit_uses_the_recorded_branch_and_provider():
    res, vcs, gp = _commit(_agent(_DB({"default_branch": "prod", "vcs_provider": "GITHUB"})))
    assert res["base_branch"] == "prod" and vcs.branches == [("castor/app-1", "prod")] and vcs.prs == ["prod"]
    assert gp.call_args.kwargs["provider_name"] == "GITHUB"


def test_n_commit_without_a_record_or_store_uses_main():
    res, vcs, _ = _commit(_agent(_DB(None)))
    assert res["base_branch"] == "main" and vcs.branches == [("castor/app-1", "main")]
    res, vcs, _ = _commit(_agent(None))
    assert res["base_branch"] == "main"


def test_commit_with_an_unreadable_record_is_typed_and_writes_nothing():
    from developer_agent.errors import WORKLOAD_RECORD_UNREADABLE, DeveloperStageError
    db = _CountingDB(error=RuntimeError("deadline exceeded"))
    with pytest.raises(DeveloperStageError) as ei:
        _commit(_agent(db))
    assert ei.value.error_class == WORKLOAD_RECORD_UNREADABLE and "after 3 attempts" in str(ei.value)
    assert ei.value.vcs.commits == [] and ei.value.vcs.branches == []
    from developer_agent import handler as h
    assert db.reads == h.WORKLOAD_RECORD_READ_ATTEMPTS          # bounded: RT F3


class _CountingDB(_DB):
    """_DB whose first `fail` reads raise `error` (all of them when fail is None), counting reads."""

    def __init__(self, data=None, error=None, fail=None):
        super().__init__(data)
        self.err, self.fail, self.reads = error, fail, 0

    def collection(self, name):
        db = self

        class _Ref:
            def document(self, _id):
                class _Doc:
                    def get(self_inner):
                        db.reads += 1
                        if db.err is not None and (db.fail is None or db.reads <= db.fail):
                            raise db.err
                        return _Snap(db.data)
                return _Doc()
        return _Ref()


def test_rt_f3_one_transient_record_error_at_commit_is_retried_and_commits():
    db = _CountingDB({"default_branch": "prod"}, error=RuntimeError("deadline exceeded"), fail=1)
    res, vcs, _ = _commit(_agent(db))
    assert res["status"] == "COMMITTED" and res["base_branch"] == "prod" and vcs.commits
    assert db.reads >= 2


def test_rt_f3_n_a_readable_record_is_read_once():
    db = _CountingDB({"default_branch": "prod"})
    agent = _agent(db)
    assert agent._workload_record("app") == {"default_branch": "prod"} and db.reads == 1


def test_commit_refuses_a_base_branch_changed_during_the_build():
    from gate_errors import MainMovedError
    agent = _agent(_DB({"default_branch": "prod"}))
    agent._record_stack("tr-1", base_branch="main")   # the tree was read from main
    with pytest.raises(MainMovedError) as ei:
        _commit(agent)
    assert ei.value.reason == "BASE_BRANCH_CHANGED" and ei.value.vcs.commits == []


def test_n_commit_on_the_branch_the_tree_was_read_from():
    agent = _agent(_DB({"default_branch": "prod"}))
    agent._record_stack("tr-1", base_branch="prod")
    res, _vcs, _ = _commit(agent)
    assert res["base_branch"] == "prod"


def test_tree_read_records_its_branch():
    agent = _agent(_DB({"default_branch": "prod"}))
    agent._base_source = lambda product_id: type("_Head", (), {"head_sha": lambda self, branch: "0" * 40})()
    seen = {}
    with patch.object(type(agent), "fetch_branch_files",
                      lambda self, product_id, branch_name="main": seen.setdefault("b", branch_name) and {}):
        read = agent.fetch_existing_repo_files("app")
    assert seen["b"] == "prod" and read.branch == "prod" and read.snapshot["branch"] == "prod"


# ============================================================================================ PR ledger
def test_ledger_refuses_a_commit_against_another_base(monkeypatch):
    gw = fd4f_support.load_gateway(monkeypatch, "rt14_bb_gw6")
    from shared import vcs_ledger
    db = FakeDB()
    db.docs["workloads/app"] = {"vcs_provider": "GITHUB", "default_branch": "prod"}
    monkeypatch.setattr(gw, "db", db)

    def result(base):
        pr = {"pr_number": 9, "pull_request_url": "https://example.invalid/o/r/pull/9", "head_ref": BRANCH,
              "head_sha": SHA_A, "head_repo_full_name": "o/r", "head_repo_id": 77, "base_ref": base,
              "base_repo_full_name": "o/r", "base_repo_id": 77}
        return {"status": "COMMITTED", "repo_name": "o/r", "branch_name": BRANCH, "commit_sha": SHA_A,
                "base_branch": base, "pull_request": pr}

    assert gw._record_pr_ledger("tr-1", "app", BRANCH, result("main"), vcs_ledger.ORIGIN_DEVELOPER) is None
    assert gw._record_pr_ledger("tr-1", "app", BRANCH, result("prod"), vcs_ledger.ORIGIN_DEVELOPER) is not None


# ============================================================================================ deploy workflow branch
@pytest.mark.parametrize("recorded, read_branch, want", [
    ("prod", "main", "prod"),          # the record read here wins (as before)
    (None, "prod", "prod"),            # the record read here failed / gave nothing: the tree read's branch
    ("", "prod", "prod"),
    (None, None, "main"),              # negative: neither -> main, as before
    ("bad branch", None, "main"),      # negative: not a plain branch name -> main (logged), as before
])
def test_deploy_workflow_branch_never_defaults_to_main_when_the_branch_is_known(recorded, read_branch, want):
    from developer_agent.handler import deploy_workflow_branch
    assert deploy_workflow_branch(recorded, read_branch) == want
