"""FD-4P / FD-4BB: PR ledger (shared/vcs_ledger.py) and the GitHub provider's ledger-bound merge / reconcile.

Hermetic: fake PyGithub objects with explicit numeric ids, an in-memory Firestore fake, no network, no credentials.
Negative tests (nothing merged / closed / deleted): fork PR, deleted fork, other product's PR, human PR on a similar
branch name, head moved after QA, PR-lookup failure (no direct-merge fallback), missing ledger entry.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import os

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from fd4f_support import FakeDB  # noqa: E402
from shared import vcs_ledger  # noqa: E402
from shared.providers.github_provider import GitHubProvider  # noqa: E402
from shared.vcs_provider import PRIdentity, PRIdentityMismatch, PRMergeNotCompleted  # noqa: E402

REPO, REPO_ID = "example-org/tenant-a", 100
SHA, SHA2 = "1" * 40, "2" * 40
BRANCH = "castor/tenant-a-0a1b2c"
BOT_UID = 41898282  # the platform App's "<slug>[bot]" user (RT M1)
ACTOR = (BOT_UID, "Bot")


# ------------------------------------------------------------------ fakes
class FakeRef:
    def __init__(self, repo, name, sha):
        self.repo, self.name, self.object = repo, name, SimpleNamespace(sha=sha)

    def delete(self):
        self.repo.deleted_refs.append(self.name)


class FakePR:
    def __init__(self, number, *, head_ref=BRANCH, head_sha=SHA, head_repo_id=REPO_ID, head_repo_name=REPO,
                 base_ref="main", base_repo_id=REPO_ID, base_repo_name=REPO, state="open", merged=False,
                 merge_result=True, user_id=BOT_UID, user_type="Bot"):
        self.number, self.title, self.state, self.merged = number, f"PR {number}", state, merged
        self.user = SimpleNamespace(id=user_id, type=user_type, login="stackvend[bot]")
        head_repo = None if head_repo_id is None else SimpleNamespace(id=head_repo_id, full_name=head_repo_name)
        self.head = SimpleNamespace(ref=head_ref, sha=head_sha, repo=head_repo, label=f"x:{head_ref}")
        self.base = SimpleNamespace(ref=base_ref, repo=SimpleNamespace(id=base_repo_id, full_name=base_repo_name))
        self.merge_commit_sha = "m" * 40 if merged else None
        self.merge_calls, self.comments, self.edits = [], [], []
        self._merge_result = merge_result

    def merge(self, **kw):
        self.merge_calls.append(kw)
        return SimpleNamespace(merged=self._merge_result, sha="m" * 40, message="ok")

    def create_issue_comment(self, body):
        self.comments.append(body)

    def edit(self, **kw):
        self.edits.append(kw)


class FakeRepo:
    def __init__(self, prs, *, repo_id=REPO_ID, full_name=REPO, refs=None, get_pull_error=None):
        self.id, self.full_name, self.prs = repo_id, full_name, {p.number: p for p in prs}
        self.refs = dict(refs or {BRANCH: SHA})
        self.deleted_refs, self.merge_calls, self.listing_calls = [], [], []
        self.get_pull_error = get_pull_error

    def get_pull(self, n):
        if self.get_pull_error:
            raise self.get_pull_error
        return self.prs[n]

    def get_git_ref(self, name):
        branch = name[len("heads/"):]
        if branch not in self.refs:
            raise RuntimeError("404 ref")
        return FakeRef(self, name, self.refs[branch])

    # Anything below is forbidden on the identity paths: listing / branch merges.
    def get_pulls(self, **kw):
        self.listing_calls.append(("get_pulls", kw))
        return list(self.prs.values())

    def get_branches(self):
        self.listing_calls.append(("get_branches",))
        return []

    def merge(self, *a, **kw):
        self.merge_calls.append((a, kw))
        return SimpleNamespace(sha="d" * 40)


def provider_for(repo, actor=ACTOR):
    prov = GitHubProvider(project_id="", github_token="test-token", default_owner="example-org")
    prov._get_repo = lambda _ident: repo
    prov.actor_identity = lambda: actor  # RT M1: the platform identity (resolution is tested separately below)
    return prov


def ident(**over):
    base = dict(provider="GITHUB", repo_full_name=REPO, branch=BRANCH, base_branch="main", head_sha=SHA,
                pr_number=7, repo_id=REPO_ID)
    base.update(over)
    return PRIdentity(**base)


# ------------------------------------------------------------------ merge: happy path (Do No Harm)
def test_positive_ledger_pr_merges_once_at_the_ledger_sha_and_deletes_its_branch():
    pr = FakePR(7)
    repo = FakeRepo([pr])
    res = provider_for(repo).merge_pull_request(REPO, expected=ident(), commit_message="m")
    assert res["status"] == "MERGED" and res["merged"] is True
    assert pr.merge_calls == [{"commit_message": "m", "merge_method": "squash", "sha": SHA}]
    assert repo.deleted_refs == [f"heads/{BRANCH}"]
    assert repo.listing_calls == [] and repo.merge_calls == []


def test_positive_already_merged_pr_is_not_merged_again():
    pr = FakePR(7, merged=True, state="closed")
    res = provider_for(FakeRepo([pr])).merge_pull_request(REPO, expected=ident())
    assert res["already_merged"] is True and pr.merge_calls == []


def test_positive_repo_name_case_differs_still_same_repo():
    pr = FakePR(7)
    res = provider_for(FakeRepo([pr], full_name="Example-Org/Tenant-A")).merge_pull_request(REPO, expected=ident())
    assert res["merged"] is True


# ------------------------------------------------------------------ merge: negatives (nothing merged, nothing deleted)
@pytest.mark.parametrize("label,pr_kw,repo_kw,field", [
    ("fork_pr", {"head_repo_id": 999, "head_repo_name": "attacker/tenant-a"}, {}, "head_repo_id"),
    ("fork_same_name_other_id", {"head_repo_id": 999}, {}, "head_repo_id"),
    ("deleted_fork", {"head_repo_id": None}, {}, "head_repo_id"),
    ("other_repo_same_pr_number", {}, {"repo_id": 555, "full_name": "example-org/tenant-b"}, "repo_id"),
    ("pr_targets_another_repo", {"base_repo_id": 555}, {}, "base_repo_id"),
    ("human_pr_similar_branch", {"head_ref": "castor/tenant-a-0a1b2c-hotfix"}, {}, "head_ref"),
    ("other_product_branch", {"head_ref": "castor/tenant-a-v2-0a1b2c"}, {}, "head_ref"),
    ("head_moved_after_qa", {"head_sha": SHA2}, {}, "head_sha"),
    ("retargeted_base", {"base_ref": "release"}, {}, "base_ref"),
    ("closed_pr", {"state": "closed"}, {}, "state"),
    ("pr_opened_by_a_human", {"user_id": 777, "user_type": "User"}, {}, "pr_user_id"),
    ("pr_opened_by_another_bot", {"user_id": 999}, {}, "pr_user_id"),
    ("same_uid_but_not_a_bot", {"user_type": "User"}, {}, "pr_user_type"),
])
def test_negative_identity_mismatch_never_merges_or_deletes(label, pr_kw, repo_kw, field):
    pr = FakePR(7, **pr_kw)
    repo = FakeRepo([pr], **repo_kw)
    with pytest.raises(PRIdentityMismatch) as ei:
        provider_for(repo).merge_pull_request(REPO, expected=ident())
    assert ei.value.field == field, label
    assert pr.merge_calls == [] and repo.deleted_refs == [] and repo.merge_calls == [] and repo.listing_calls == []


def test_negative_pr_lookup_error_has_no_direct_merge_fallback():
    repo = FakeRepo([], get_pull_error=RuntimeError("502 Bad Gateway"))
    with pytest.raises(RuntimeError):
        provider_for(repo).merge_pull_request(REPO, expected=ident())
    assert repo.merge_calls == [] and repo.listing_calls == [] and repo.deleted_refs == []


@pytest.mark.parametrize("bad", [
    {"pr_number": None}, {"pr_number": 1.0}, {"pr_number": True}, {"pr_number": 0}, {"repo_id": None},
    {"head_sha": ""}, {"branch": " castor/x"}, {"provider": "SERVERLESS_GIT"},
])
def test_negative_incomplete_ledger_identity_refused_before_any_call(bad):
    repo = FakeRepo([FakePR(7)])
    repo.get_pull = MagicMock(side_effect=AssertionError("GitHub called"))
    with pytest.raises(PRIdentityMismatch):
        provider_for(repo).merge_pull_request(REPO, expected=ident(**bad))


def test_negative_old_call_shapes_fail_loudly():
    prov = provider_for(FakeRepo([FakePR(7)]))
    with pytest.raises(TypeError):
        prov.merge_pull_request(REPO, pr_number=7)  # no pr_number guess
    with pytest.raises(TypeError):
        prov.merge_pull_request(REPO, source_branch=BRANCH)  # no branch-name lookup
    with pytest.raises(TypeError):
        prov.reconcile_automated_pull_requests(REPO, product_id="tenant-a", current_trace_id="t")


def test_negative_github_reports_not_merged():
    pr = FakePR(7, merge_result=False)
    repo = FakeRepo([pr])
    with pytest.raises(PRMergeNotCompleted):
        provider_for(repo).merge_pull_request(REPO, expected=ident())
    assert repo.deleted_refs == []


def test_negative_branch_moved_after_merge_is_not_deleted():
    pr = FakePR(7)
    repo = FakeRepo([pr], refs={BRANCH: SHA2})
    provider_for(repo).merge_pull_request(REPO, expected=ident())
    assert repo.deleted_refs == []


# ------------------------------------------------------------------ reconcile (rewritten on the ledger)
def test_reconcile_closes_only_ledger_prs_that_still_match():
    ours = FakePR(7)
    moved = FakePR(8, head_ref="castor/tenant-a-111111", head_sha=SHA2)
    fork = FakePR(9, head_ref="castor/tenant-a-222222", head_repo_id=999)
    human = FakePR(12, head_ref="castor/tenant-a-hotfix")  # never named by the ledger
    repo = FakeRepo([ours, moved, fork, human], refs={BRANCH: SHA, "castor/tenant-a-111111": SHA2,
                                                       "castor/tenant-a-hotfix": SHA})
    res = provider_for(repo).reconcile_automated_pull_requests(REPO, superseded=[
        ident(),
        ident(pr_number=8, branch="castor/tenant-a-111111", head_sha=SHA),  # someone pushed SHA2 since
        ident(pr_number=9, branch="castor/tenant-a-222222"),
    ])
    outcomes = {r["pr_number"]: r["outcome"] for r in res["results"]}
    assert outcomes == {7: "SUPERSEDED", 8: "DIVERGED", 9: "DIVERGED"}
    assert ours.edits == [{"state": "closed"}] and moved.edits == [] and fork.edits == [] and human.edits == []
    assert repo.deleted_refs == [f"heads/{BRANCH}"]
    assert repo.listing_calls == []  # nothing is listed; a human PR is unreachable


def test_reconcile_with_nothing_superseded_touches_nothing():
    repo = FakeRepo([FakePR(12, head_ref="feature/tenant-a-login")])
    assert provider_for(repo).reconcile_automated_pull_requests(REPO, superseded=[])["results"] == []
    assert repo.listing_calls == [] and repo.deleted_refs == []


# ------------------------------------------------------------------ ledger module
def _record(db, **over):
    kw = dict(provider="GITHUB", repo_full_name=REPO, repo_id=REPO_ID, product_id="tenant-a", trace_id="tr-1",
              origin=vcs_ledger.ORIGIN_DEVELOPER, branch=BRANCH, base_branch="main", head_sha=SHA, pr_number=7,
              pr_url=f"https://github.com/{REPO}/pull/7")
    kw.update(over)
    return vcs_ledger.record_created(db, **kw)


def test_ledger_round_trip_and_exact_lookup():
    db = FakeDB()
    lid = _record(db)
    assert lid == vcs_ledger.ledger_id("GITHUB", "Example-Org/Tenant-A", BRANCH)  # GitHub names: case-insensitive
    entry = vcs_ledger.require_entry(db, provider="GITHUB", repo_full_name=REPO, branch=BRANCH, product_id="tenant-a",
                                     trace_id="tr-1")
    assert vcs_ledger.identity(entry) == ident()
    assert entry["state"] == vcs_ledger.STATE_OPEN


@pytest.mark.parametrize("over,reason", [
    ({"product_id": "tenant-a-v2"}, "PRODUCT_MISMATCH"),
    ({"trace_id": "tr-other"}, "TRACE_MISMATCH"),
])
def test_ledger_entry_of_another_product_or_trace_is_refused(over, reason):
    db = FakeDB()
    _record(db)
    kw = dict(provider="GITHUB", repo_full_name=REPO, branch=BRANCH, product_id="tenant-a", trace_id="tr-1")
    kw.update(over)
    with pytest.raises(vcs_ledger.LedgerMismatch) as ei:
        vcs_ledger.require_entry(db, **kw)
    assert ei.value.reason == reason


def test_missing_ledger_entry_is_typed():
    with pytest.raises(vcs_ledger.LedgerNotFound) as ei:
        vcs_ledger.require_entry(FakeDB(), provider="GITHUB", repo_full_name=REPO, branch=BRANCH, product_id="tenant-a")
    assert ei.value.reason == "NO_LEDGER_ENTRY"
    other_repo = FakeDB()
    _record(other_repo)
    with pytest.raises(vcs_ledger.LedgerNotFound):  # same branch name, another repository -> another entry
        vcs_ledger.require_entry(other_repo, provider="GITHUB", repo_full_name="example-org/tenant-b", branch=BRANCH,
                                 product_id="tenant-a")


def test_duplicate_claim_and_incomplete_entries_are_refused():
    db = FakeDB()
    _record(db)
    with pytest.raises(vcs_ledger.LedgerUnavailable):
        _record(db)  # create() refuses an existing entry
    for bad in ({"pr_number": None}, {"pr_number": "7"}, {"repo_id": None}, {"head_sha": ""}, {"origin": "HUMAN"},
                {"branch": "main"}):
        with pytest.raises(vcs_ledger.LedgerMismatch):
            _record(FakeDB(), **bad)
    with pytest.raises(vcs_ledger.LedgerMismatch):
        _record(FakeDB(), provider="SERVERLESS_GIT")  # serverless entries carry no PR number
    assert _record(FakeDB(), provider="SERVERLESS_GIT", pr_number=None, repo_id=None, pr_url=None)


def test_non_mergeable_states_are_refused():
    db = FakeDB()
    lid = _record(db)
    for state in (vcs_ledger.STATE_MERGED, vcs_ledger.STATE_SUPERSEDED, vcs_ledger.STATE_DIVERGED):
        vcs_ledger.mark(db, lid, state)
        with pytest.raises(vcs_ledger.LedgerMismatch):
            vcs_ledger.require_entry(db, provider="GITHUB", repo_full_name=REPO, branch=BRANCH, product_id="tenant-a")
    vcs_ledger.mark(db, lid, vcs_ledger.STATE_MERGE_FAILED)
    assert vcs_ledger.require_entry(db, provider="GITHUB", repo_full_name=REPO, branch=BRANCH, product_id="tenant-a")


def test_supersedable_is_exact():
    db = FakeDB()
    _record(db)
    _record(db, branch="castor/tenant-a-111111", trace_id="tr-0", pr_number=5)
    _record(db, branch="castor/tenant-a-v2-333333", product_id="tenant-a-v2", pr_number=6)  # other product
    _record(db, branch="castor/tenant-a-444444", repo_full_name="example-org/other", pr_number=4)  # other repo
    _record(db, branch="iac-upgrade/tenant-a-555555", origin=vcs_ledger.ORIGIN_IAC_UPGRADE, pr_number=3)
    entries = vcs_ledger.entries_for_product(db, "tenant-a")
    got = vcs_ledger.supersedable(entries, provider="GITHUB", repo_full_name=REPO, keep_branch="castor/tenant-a-999999")
    assert sorted(e["branch"] for e in got) == sorted([BRANCH, "castor/tenant-a-111111"])  # incl. same trace (RT H5)
    got2 = vcs_ledger.supersedable(entries, provider="GITHUB", repo_full_name=REPO, keep_branch=BRANCH)
    assert [e["branch"] for e in got2] == ["castor/tenant-a-111111"]  # the current attempt is never superseded


def test_creation_problems_refuse_fork_and_foreign_prs():
    good = {"pr_number": 7, "pull_request_url": "u", "head_ref": BRANCH, "head_sha": SHA, "head_repo_full_name": REPO,
            "head_repo_id": REPO_ID, "base_ref": "main", "base_repo_full_name": REPO, "base_repo_id": REPO_ID}
    kw = dict(repo_full_name=REPO, branch=BRANCH, base_branch="main", commit_sha=SHA)
    assert vcs_ledger.creation_problems("GITHUB", pull_request=good, **kw) == []
    for bad in ({"head_repo_id": 999}, {"head_repo_full_name": "attacker/tenant-a"}, {"base_repo_full_name": "o/other"},
                {"head_ref": "other"}, {"head_sha": SHA2}, {"base_ref": "dev"}, {"pr_number": None}, {"head_repo_id": None}):
        assert vcs_ledger.creation_problems("GITHUB", pull_request={**good, **bad}, **kw), bad
    assert vcs_ledger.creation_problems("GITHUB", pull_request=None, **kw)
    assert vcs_ledger.creation_problems("SERVERLESS_GIT", pull_request=None, **kw) == []


def test_ledger_module_has_no_string_heuristics():
    """Invariant 2: identity is equality only (no startswith/endswith/regex/substring `in`)."""
    for path in ("shared/vcs_ledger.py",):
        tree = ast.parse(open(os.path.join(REPO_ROOT, path)).read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in ("startswith", "endswith", "find", "search", "match", "fullmatch"), (path, node.attr)
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
                assert "re" not in names, path
            if isinstance(node, ast.Compare):
                for op, comp in zip(node.ops, node.comparators):
                    if isinstance(op, (ast.In, ast.NotIn)):
                        assert isinstance(comp, ast.Name) and comp.id.isupper(), (path, ast.dump(comp))


def test_provider_identity_paths_have_no_listing_or_string_matching():
    """The rewritten merge / reconcile code never lists PRs or branches and never prefix/suffix-matches."""
    src = open(os.path.join(REPO_ROOT, "shared", "providers", "github_provider.py")).read()
    tree = ast.parse(src)
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    for name in ("merge_pull_request", "reconcile_automated_pull_requests", "_verify_identity",
                 "_delete_branch_if_unchanged", "_check_expected"):
        for node in ast.walk(funcs[name]):
            if isinstance(node, ast.Attribute):
                assert node.attr not in ("get_pulls", "get_branches", "startswith", "endswith", "merge_branch"), (name, node.attr)
                if node.attr == "merge":
                    assert isinstance(node.value, ast.Name) and node.value.id == "pr", name  # only pr.merge(sha=...)


# ------------------------------------------------------------------ RT M1: PR-creator provenance
def test_m1_unresolvable_platform_identity_refuses_auto_merge_before_any_call():
    pr = FakePR(7)
    repo = FakeRepo([pr])
    repo.get_pull = MagicMock(side_effect=AssertionError("GitHub called"))
    with pytest.raises(PRIdentityMismatch) as ei:
        provider_for(repo, actor=None).merge_pull_request(REPO, expected=ident())
    assert ei.value.field == "pr_user_id"


def test_m1_human_approval_without_a_resolvable_identity_is_bound_by_the_other_checks():
    """The CC passes require_provenance=False: a human approved; every other identity check still applies."""
    pr = FakePR(7, user_id=777, user_type="User")
    res = provider_for(FakeRepo([pr]), actor=None).merge_pull_request(REPO, expected=ident(), require_provenance=False)
    assert res["merged"] is True and len(pr.merge_calls) == 1
    fork = FakePR(7, head_repo_id=999)
    with pytest.raises(PRIdentityMismatch):
        provider_for(FakeRepo([fork]), actor=None).merge_pull_request(REPO, expected=ident(), require_provenance=False)
    # a known identity is enforced on the human path too
    with pytest.raises(PRIdentityMismatch) as ei:
        provider_for(FakeRepo([FakePR(7, user_id=777, user_type="User")])).merge_pull_request(
            REPO, expected=ident(), require_provenance=False)
    assert ei.value.field == "pr_user_id"


def test_m1_reconcile_never_closes_a_pr_another_identity_opened():
    pr = FakePR(7, user_id=777, user_type="User")
    repo = FakeRepo([pr])
    res = provider_for(repo).reconcile_automated_pull_requests(REPO, superseded=[ident()])
    assert [r["outcome"] for r in res["results"]] == ["DIVERGED"] and pr.edits == [] and repo.deleted_refs == []


def _resolution_provider(monkeypatch, creds, client):
    import shared.providers.github_provider as gp
    monkeypatch.setattr(gp, "_ACTOR_CACHE", {})
    prov = GitHubProvider(project_id="", github_token="test-token", default_owner="example-org")
    prov._token_manager = MagicMock(_get_credentials=MagicMock(return_value=creds))
    prov.get_client = lambda: client
    return prov, gp


def test_m1_identity_resolution_app_and_pat(monkeypatch):
    # App mode: the App's slug from the App JWT, then the "<slug>[bot]" user id
    client = MagicMock()
    client.get_user.return_value = SimpleNamespace(id=BOT_UID)
    prov, gp = _resolution_provider(monkeypatch, {"app_id": "123", "installation_id": "9", "private_key": "pem"}, client)
    app_client = MagicMock()
    app_client.get_app.return_value = SimpleNamespace(slug="stackvend")
    monkeypatch.setattr(gp, "Github", MagicMock(return_value=app_client))
    import github
    monkeypatch.setattr(github, "Auth", MagicMock(), raising=False)
    assert prov.actor_identity() == (BOT_UID, "Bot")
    client.get_user.assert_called_once_with("stackvend[bot]")
    # PAT mode: the authenticated user
    client2 = MagicMock()
    client2.get_user.return_value = SimpleNamespace(id=55)
    prov2, _ = _resolution_provider(monkeypatch, {"pat": "x"}, client2)
    assert prov2.actor_identity() == (55, "User")
    client2.get_user.assert_called_once_with()
    # unresolvable (API error) -> None, never a guess
    client3 = MagicMock()
    client3.get_user.side_effect = RuntimeError("401")
    prov3, _ = _resolution_provider(monkeypatch, {"pat": "x"}, client3)
    assert prov3.actor_identity() is None



def test_rt_f5_serverless_reconcile_follows_the_keyword_only_contract():
    from shared.providers.serverless_git_provider import ServerlessGitProvider
    import inspect
    sig = inspect.signature(ServerlessGitProvider.reconcile_automated_pull_requests)
    assert sig.parameters["superseded"].kind is inspect.Parameter.KEYWORD_ONLY
    res = ServerlessGitProvider.reconcile_automated_pull_requests(object(), "castor/app", superseded=[ident()])
    assert res == {"status": "RECONCILED", "results": [{"branch": BRANCH, "pr_number": None, "outcome": "SKIPPED",
                                                         "reason": "Serverless Git has no SHA-guarded branch delete yet"}]}
