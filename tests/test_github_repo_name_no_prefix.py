import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

"""GITHUB-REPO-NAME-NO-PREFIX (register row GITHUB-REPO-NAME-NO-PREFIX, owner 11-12): a new workload's GitHub
repository is named after the workload id, without the internal `castor-` prefix.

Pinned here:
- shared/github_identity.py `default_repository_name` is the one default; `resolve_repo_identity` uses it, and every
  ImportError fallback copy of `resolve_repo_identity` (vending, CC, gateway handler + terraform engine, terraform
  MCP) gives the same answer (executed from its AST, so the copies cannot drift again);
- a record that stores `github_repo` keeps it (a `castor-<id>` workload is not moved to another repository);
- an existing GitHub repository under the vended name is used only when it is the workload's own
  (`repository_is_workloads_own`); any other raises GitHubRepositoryNameTakenError (GITHUB_REPOSITORY_NAME_TAKEN,
  stage vcs_repository_vending) before it is changed or recorded, in the provider path and the direct path;
- the same workload's own repository is still reused (re-run);
- the New Workload placeholder and the docs state the new default.
"""
import ast
import os
import sys
from types import SimpleNamespace as NS

import pytest

import destructive_guard_fakes as f
from test_destructive_guard_vending import (  # noqa: F401  (fixtures)
    _freeze_setting_without_firestore, _vend_crm, _vend_engine, vmain,
)
from test_l19_11_access_intake import cc  # noqa: F401  (fixture: the Control Center routes on fakes)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from shared import github_identity as gi  # noqa: E402

COPIES = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared", "apps/project-vending/shared",
          "apps/qa-runner/shared", "mcp-servers/terraform/shared"]
FALLBACKS = ["apps/project-vending/vending.py", "apps/control-center/routes/workloads.py",
             "apps/orchestrator-gateway/developer_agent/handler.py",
             "apps/orchestrator-gateway/developer_agent/terraform_engine.py", "mcp-servers/terraform/service.py"]


def _read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return fh.read()


# ------------------------------------------------------------------------------------------------- the default
@pytest.mark.parametrize("pid,name", [
    ("finalrun-testplan01-a", "finalrun-testplan01-a"),
    ("Payment_Service", "payment-service"),
    ("payments", "payments"),
])
def test_default_name_is_the_clean_workload_id(pid, name):
    assert gi.default_repository_name(pid) == name
    assert gi.resolve_repo_identity(None, default_owner="Acme", product_id=pid) == ("Acme", name, f"Acme/{name}")
    assert gi.resolve_repo_identity("", default_owner="Acme", product_id=pid)[2] == f"Acme/{name}"


@pytest.mark.parametrize("stored", ["Acme/castor-shop", "https://github.com/Acme/castor-shop.git",
                                    "git@github.com:Acme/castor-shop.git", {"full_name": "Acme/castor-shop"}])
def test_a_stored_repository_is_kept(stored):
    """Negative: a workload vended before 11-12 keeps its castor-<id> repository (no rename, no other repository)."""
    assert gi.resolve_repo_identity(stored, default_owner="Other", product_id="shop") == \
        ("Acme", "castor-shop", "Acme/castor-shop")


def test_a_bare_stored_name_is_kept():
    assert gi.resolve_repo_identity("castor-shop", default_owner="Acme", product_id="shop")[2] == "Acme/castor-shop"


def test_github_identity_copies_are_identical():
    texts = {c: _read(f"{c}/github_identity.py") for c in COPIES}
    assert len(set(texts.values())) == 1, sorted(texts)


def _fallback_resolver(rel):
    """The ImportError fallback `resolve_repo_identity` of `rel`, executed alone (owner from default_owner)."""
    tree = ast.parse(_read(rel))
    fns = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "resolve_repo_identity"]
    assert len(fns) == 1, rel
    ns = {"os": os, "get_default_github_owner": lambda: pytest.fail("default_owner is given")}
    exec(compile(ast.Module(body=[fns[0]], type_ignores=[]), rel, "exec"), ns)  # noqa: S102 - repo source
    return ns["resolve_repo_identity"]


@pytest.mark.parametrize("rel", FALLBACKS)
@pytest.mark.parametrize("repo", [None, "", "Acme/castor-shop", "custom-repo"])
def test_import_fallbacks_match_the_shared_default(rel, repo):
    resolver = _fallback_resolver(rel)
    for pid in ("shop", "Payment_Service"):
        assert resolver(repo, default_owner="Acme", product_id=pid) == \
            gi.resolve_repo_identity(repo, default_owner="Acme", product_id=pid), (rel, repo, pid)


def test_no_github_repository_default_keeps_the_prefix():
    for rel in FALLBACKS + ["shared/github_identity.py"]:
        src = _read(rel)
        fn = next(n for n in ast.walk(ast.parse(src))
                  if isinstance(n, ast.FunctionDef) and n.name == "resolve_repo_identity")
        assert "castor-" not in ast.get_source_segment(src, fn), rel
    # the CC's feature-request plan links (were f"{_owner}/castor-{clean_pid}")
    assert "/castor-{clean_pid}" not in _read("apps/control-center/routes/workloads.py")


# ----------------------------------------------------------------------------------------- ownership (shared rule)
REC = {"full_name": "Acme/shop", "repository_id": "4242"}


@pytest.mark.parametrize("record,name,rid,own", [
    (REC, "acme/shop", 4242, True),                                          # same repository (names case-insensitive)
    (REC, "Acme/shop", "4242", True),
    (REC, "Acme/shop", 9999, False),                                          # re-created under the same name
    (REC, "Acme/shop", None, None),                                           # id unreadable: unknown (RT F4)
    ({"full_name": "Acme/shop", "repository_id": None}, "Acme/shop", 7, True),   # id not read at that vend
    (REC, "Acme/payments", 4242, False),                                      # another repository
    (None, "Acme/shop", 4242, False),                                         # first vend: nothing recorded
    ({}, "Acme/shop", 4242, False),
    ("Acme/shop", "Acme/shop", 4242, False),
    (REC, "", 4242, False),
])
def test_repository_is_workloads_own(record, name, rid, own):
    assert gi.repository_is_workloads_own(record, name, rid) is own


# ------------------------------------------------------------------------------------- vending: provider path
class _Vcs:
    """The GitHub provider's answer for a repository named `app` (created, or found existing)."""

    def __init__(self, is_reused, repo_id, provider="GITHUB"):
        self.repo_id = repo_id
        self.meta = NS(provider=provider, repo_name="app", full_name="acme/app", html_url="h", clone_url_http="c",
                       is_reused=is_reused)
        self.asked_for = []

    def vend_repository(self, product_id, **kw):
        self.asked_for.append(product_id)
        return self.meta

    def get_client(self):
        repo_id = self.repo_id
        return NS(get_repo=lambda name: NS(full_name=name, id=repo_id))


def _engine(vmain, monkeypatch, vcs=None, client=None, db=None):
    eng = _vend_engine(vmain, db or f.FakeDB(), _vend_crm())
    globs = vmain.ProjectRepoVendingEngine.vend_gcp_project.__globals__
    if vcs is not None:
        monkeypatch.setitem(globs, "VCSProviderFactory", NS(get_provider=lambda **kw: vcs))
    else:
        def _unavailable(**kw):
            raise RuntimeError("provider unavailable")
        monkeypatch.setitem(globs, "VCSProviderFactory", NS(get_provider=_unavailable))
    if client is not None:
        monkeypatch.setitem(globs, "Github", lambda token: client)
        monkeypatch.setattr(eng, "fetch_github_app_credentials", lambda *a, **k: {})
        monkeypatch.setattr(eng, "generate_github_jit_token", lambda *a, **k: "jit-token")
    return eng, globs


def test_provider_path_refuses_an_unrelated_existing_repository(vmain, monkeypatch):
    eng, globs = _engine(vmain, monkeypatch, vcs=_Vcs(is_reused=True, repo_id=777))
    with pytest.raises(globs["GitHubRepositoryNameTakenError"]) as exc:
        eng.vend_github_repo("app", github_owner="acme", vcs_provider="GITHUB")
    err = exc.value
    assert isinstance(err, globs["GitHubRepositoryCreateError"])
    assert err.error_class == "GITHUB_REPOSITORY_NAME_TAKEN" and err.stage == "vcs_repository_vending"
    assert err.status is None and err.full_name == "acme/app"
    assert "Target GitHub Repository" in str(err) and "another workload id" in str(err)


def test_provider_path_reuses_the_workloads_own_repository(vmain, monkeypatch):
    eng, _ = _engine(vmain, monkeypatch, vcs=_Vcs(is_reused=True, repo_id=4242))
    res = eng.vend_github_repo("app", github_owner="acme", vcs_provider="GITHUB",
                               recorded_identity={"full_name": "acme/app", "repository_id": "4242"})
    assert res["status"] == "REPO_REUSED" and res["reused_existing"] is True and res["repository_id"] == 4242


def test_provider_path_refuses_a_recreated_repository_of_the_same_name(vmain, monkeypatch):
    """RT D2: the recorded repository with another id is GITHUB_REPOSITORY_ID_CHANGED, not name-taken."""
    eng, globs = _engine(vmain, monkeypatch, vcs=_Vcs(is_reused=True, repo_id=5555))
    with pytest.raises(globs["GitHubRepositoryIdChangedError"]):
        eng.vend_github_repo("app", github_owner="acme", vcs_provider="GITHUB",
                             recorded_identity={"full_name": "acme/app", "repository_id": "4242"})


def test_provider_path_creates_as_before(vmain, monkeypatch):
    """Negative: a repository the provider created is never refused (nothing recorded yet)."""
    eng, _ = _engine(vmain, monkeypatch, vcs=_Vcs(is_reused=False, repo_id=31))
    res = eng.vend_github_repo("app", github_owner="acme", vcs_provider="GITHUB")
    assert res["status"] == "REPO_VENDED" and res["reused_existing"] is False and res["repository_id"] == 31


def test_serverless_git_reuse_is_not_checked(vmain, monkeypatch):
    eng, _ = _engine(vmain, monkeypatch, vcs=_Vcs(is_reused=True, repo_id=None, provider="SERVERLESS_GIT"))
    assert eng.vend_github_repo("app", vcs_provider="SERVERLESS_GIT")["status"] == "REPO_REUSED"


# --------------------------------------------------------------------------------------- vending: direct path
class _Client:
    """PyGithub-shaped client: an existing repository `acme/app` (id `existing_id`) or none."""

    def __init__(self, existing_id=None):
        self.existing_id, self.created, self.edited = existing_id, [], []
        client = self

        class _Repo:
            def __init__(self, full_name, rid):
                self.full_name, self.id, self.html_url, self.clone_url = full_name, rid, "h", "c"
                self.default_branch = "main"

            def edit(self, **kw):
                client.edited.append(kw)

        self._Repo = _Repo

    def get_repo(self, full_name):
        if self.existing_id is None:
            raise RuntimeError("404")
        return self._Repo(full_name, self.existing_id)

    def get_organization(self, owner):
        client = self

        class _Org:
            id = 1

            def create_repo(self, name, **kw):
                client.created.append(name)
                return client._Repo(f"{owner}/{name}", 99)
        return _Org()


def test_direct_path_refuses_an_unrelated_existing_repository_without_touching_it(vmain, monkeypatch):
    client = _Client(existing_id=777)
    eng, globs = _engine(vmain, monkeypatch, client=client)
    with pytest.raises(globs["GitHubRepositoryNameTakenError"]):
        eng.vend_github_repo("app", github_owner="acme", vcs_provider="GITHUB")
    assert client.edited == [] and client.created == []


def test_direct_path_reuses_the_workloads_own_repository(vmain, monkeypatch):
    client = _Client(existing_id=4242)
    eng, _ = _engine(vmain, monkeypatch, client=client)
    res = eng.vend_github_repo("app", github_owner="acme", vcs_provider="GITHUB",
                               recorded_identity={"full_name": "acme/app", "repository_id": 4242})
    assert res["full_name"] == "acme/app" and res["reused_existing"] is True and client.created == []


def test_direct_path_creates_the_bare_workload_id(vmain, monkeypatch):
    client = _Client()
    eng, _ = _engine(vmain, monkeypatch, client=client)
    res = eng.vend_github_repo("app", github_owner="acme", vcs_provider="GITHUB")
    assert client.created == ["app"] and res["full_name"] == "acme/app" and res["reused_existing"] is False


# ------------------------------------------------------------------- vending: vend_all with the real GitHub provider
# RT F8: these drive the real GitHubProvider.vend_repository (with its retry decorator), vend_github_repo and vend_all
# against a PyGithub-shaped fake (GitHub's typed GithubException statuses), not a fixed provider answer.
from github import GithubException  # noqa: E402


def _gh(status):
    return GithubException(status, {"message": f"HTTP {status}"}, None)


class _World:
    """One GitHub organization `acme`: repositories by full name, and switches for the failures under test."""

    def __init__(self, repos=None):
        self.repos = dict(repos or {})          # full_name -> id
        self.created, self.edited = [], []
        self.next_id = 500
        self.create_then_fail = None            # an exception raised AFTER the repository was created
        self.create_error = None                # an exception raised instead of creating
        self.failing_reads = 0                  # get_repo calls that answer 502 before answering normally

    def repo(self, full_name):
        world = self
        return NS(full_name=full_name, id=self.repos[full_name], html_url=f"https://github.com/{full_name}",
                  clone_url=f"https://github.com/{full_name}.git", ssh_url="s", default_branch="main",
                  edit=lambda **kw: world.edited.append((full_name, kw)))

    def client(self):
        world = self

        class _Client:
            def get_repo(self, full_name):
                if world.failing_reads:
                    world.failing_reads -= 1
                    raise _gh(502)
                if full_name not in world.repos:
                    raise _gh(404)
                return world.repo(full_name)

            def get_organization(self, owner):
                class _Org:
                    id = 1

                    def create_repo(self, name, **kw):
                        if world.create_error is not None:
                            raise world.create_error
                        full_name = f"{owner}/{name}"
                        world.next_id += 1
                        world.repos[full_name] = world.next_id
                        world.created.append(full_name)
                        if world.create_then_fail is not None:
                            err, world.create_then_fail = world.create_then_fail, None
                            raise err
                        return world.repo(full_name)
                return _Org()
        return _Client()


def _real_engine(vmain, monkeypatch, world, db, doc=None):
    """vend_all with the real provider class (the module vending itself imports) over `world`; the project step is
    a stub. Returns (engine, vending globals, calls to the project step)."""
    globs = vmain.ProjectRepoVendingEngine.vend_gcp_project.__globals__
    gp = sys.modules[globs["GitHubRepositoryCreateError"].__module__]
    prov = gp.GitHubProvider.__new__(gp.GitHubProvider)
    prov.default_owner = "acme"
    client = world.client()
    prov.get_client = lambda: client
    prov.get_token = lambda: "installation-token"
    monkeypatch.setitem(globs, "VCSProviderFactory", NS(get_provider=lambda **kw: prov))
    monkeypatch.setitem(globs, "Github", lambda token: client)
    import time
    monkeypatch.setattr(time, "sleep", lambda s: None)   # the provider's GitHub retry backoff
    if doc is not None:
        db.docs["workloads/app"] = dict(doc)
    eng = _vend_engine(vmain, db, _vend_crm())
    eng.github_owner = "acme"
    monkeypatch.setattr(eng, "fetch_github_app_credentials", lambda *a, **k: {})
    monkeypatch.setattr(eng, "generate_github_jit_token", lambda *a, **k: "jit-token")
    projects = []
    eng.vend_gcp_project = lambda product_id, trace_id, **kw: projects.append(product_id) or {
        "project_id": "p-1", "project_number": f.NUMBER}
    return eng, globs, projects


SUBMITTED = {"github_repo": "acme/app"}   # what the Control Center records at submit (the default name)


def test_new_workload_gets_the_bare_name_and_its_identity(vmain, monkeypatch):
    world, db = _World(), f.FakeDB()
    eng, _, _ = _real_engine(vmain, monkeypatch, world, db, SUBMITTED)
    res = eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    assert res["status"] == "WORKLOAD_VENDED" and world.created == ["acme/app"]
    rec = db.doc("workloads/app")
    assert rec["github_repo"] == "acme/app"
    assert rec["github_repository_identity"] == {"full_name": "acme/app", "repository_id": str(world.repos["acme/app"])}


def test_the_claim_is_written_before_the_create(vmain, monkeypatch):
    world, db = _World(), f.FakeDB()
    eng, _, _ = _real_engine(vmain, monkeypatch, world, db, SUBMITTED)
    eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    identity_writes = [w for w in db.writes if "github_repository_identity" in w[2]]
    assert identity_writes[0][2] == {"github_repository_identity": {"full_name": "acme/app", "repository_id": None}}


@pytest.mark.parametrize("after_create", [_gh(502), TimeoutError("read timed out")])
def test_f1_a_create_github_completed_but_answered_with_an_error_reuses_the_repository(vmain, monkeypatch,
                                                                                      after_create):
    """RT F1: 502 after the create (the provider's own retry finds the repository) and a timeout (no status: vending's
    direct path finds it) both end with the workload's own repository, never GITHUB_REPOSITORY_NAME_TAKEN."""
    world, db = _World(), f.FakeDB()
    world.create_then_fail = after_create
    eng, _, _ = _real_engine(vmain, monkeypatch, world, db, SUBMITTED)
    res = eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    assert res["status"] == "WORKLOAD_VENDED" and world.created == ["acme/app"]
    rec = db.doc("workloads/app")
    assert rec["github_repo"] == "acme/app"
    assert rec["github_repository_identity"] == {"full_name": "acme/app", "repository_id": str(world.repos["acme/app"])}


def test_f2_a_failed_record_write_is_a_typed_failure_and_the_next_run_reuses_the_repository(vmain, monkeypatch):
    world, db = _World(), f.FakeDB()
    eng, globs, _ = _real_engine(vmain, monkeypatch, world, db, SUBMITTED)
    claim = eng._claim_repository

    def claim_then_break_writes(*a, **k):
        out = claim(*a, **k)
        db.fail_write_paths.add("workloads/app")
        return out

    monkeypatch.setattr(eng, "_claim_repository", claim_then_break_writes)
    with pytest.raises(globs["VendingFailure"]) as exc:
        eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    assert exc.value.error_class == "VENDING.WORKLOAD_RECORD_NOT_WRITTEN" and world.created == ["acme/app"]
    db.fail_write_paths.clear()
    monkeypatch.setattr(eng, "_claim_repository", claim)
    res = eng.vend_all("app", "tr-2", vcs_provider="GITHUB")   # the claim names it: reused, not refused
    assert res["status"] == "WORKLOAD_VENDED" and world.created == ["acme/app"]
    assert db.doc("workloads/app")["github_repository_identity"]["repository_id"] == str(world.repos["acme/app"])


def test_f2_a_claim_that_cannot_be_written_creates_nothing(vmain, monkeypatch):
    world, db = _World(), f.FakeDB()
    eng, globs, _ = _real_engine(vmain, monkeypatch, world, db, SUBMITTED)
    db.fail_write_paths.add("workloads/app")
    with pytest.raises(globs["VendingFailure"]) as exc:
        eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    assert exc.value.error_class == "REPOSITORY_CLAIM_NOT_RECORDED" and world.created == []


def test_unrelated_existing_repository_is_refused_cleared_and_never_touched(vmain, monkeypatch):
    """Claim 2 + RT F5: refused before anything is created, changed or claimed; `github_repo` is cleared so a step
    that skips vending (RESUME_DEVELOPER / DEPLOY_ONLY) cannot target the staff repository."""
    world, db = _World({"acme/app": 77}), f.FakeDB()
    eng, globs, _ = _real_engine(vmain, monkeypatch, world, db, SUBMITTED)
    with pytest.raises(globs["VendingFailure"]) as exc:
        eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    err = exc.value
    assert err.error_class == "GITHUB_REPOSITORY_NAME_TAKEN" and err.stage == "vcs_repository_vending"
    assert str(err).count("GITHUB_REPOSITORY_NAME_TAKEN") == 1          # RT F7: the class once
    assert "Rename or remove that repository" in str(err) and "another workload id" in str(err)
    rec = db.doc("workloads/app")
    assert rec["github_repo"] is None and rec["vending_error_class"] == "GITHUB_REPOSITORY_NAME_TAKEN"
    assert "github_repository_identity" not in rec
    assert world.created == [] and world.edited == []


def test_rerun_of_the_same_workload_reuses_its_repository(vmain, monkeypatch):
    world, db = _World({"acme/app": 4242}), f.FakeDB()
    doc = {"github_repo": "acme/app", "github_repository_identity": {"full_name": "acme/app", "repository_id": "4242"}}
    eng, _, _ = _real_engine(vmain, monkeypatch, world, db, doc)
    res = eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    assert res["status"] == "WORKLOAD_VENDED" and res["github_repo"]["reused_existing"] is True
    assert world.created == []
    assert db.doc("workloads/app")["github_repository_identity"] == {"full_name": "acme/app", "repository_id": "4242"}


def test_f4_an_unreadable_id_on_a_rerun_is_not_name_taken(vmain, monkeypatch):
    """RT F4: the repository is found but its id cannot be read (twice): GITHUB_REPOSITORY_UNREADABLE, the record keeps
    its repository, and the next run (GitHub readable) reuses it."""
    world, db = _World({"acme/app": 4242}), f.FakeDB()
    doc = {"github_repo": "acme/app", "github_repository_identity": {"full_name": "acme/app", "repository_id": "4242"}}
    eng, globs, _ = _real_engine(vmain, monkeypatch, world, db, doc)
    reads = []

    def unreadable_id(vcs, meta):
        reads.append(meta.full_name)
        return None

    monkeypatch.setattr(vmain.ProjectRepoVendingEngine, "_github_repository_id", staticmethod(unreadable_id))
    with pytest.raises(globs["VendingFailure"]) as exc:
        eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    assert exc.value.error_class == "GITHUB_REPOSITORY_UNREADABLE" and len(reads) == 2
    assert db.doc("workloads/app")["github_repo"] == "acme/app" and world.created == []


def test_f4_github_unreadable_before_the_first_create_is_typed_and_creates_nothing(vmain, monkeypatch):
    world, db = _World(), f.FakeDB()
    world.failing_reads = 1
    eng, globs, _ = _real_engine(vmain, monkeypatch, world, db, SUBMITTED)
    with pytest.raises(globs["VendingFailure"]) as exc:
        eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    assert exc.value.error_class == "GITHUB_REPOSITORY_UNREADABLE" and world.created == []
    assert "github_repository_identity" not in db.doc("workloads/app")
    assert db.doc("workloads/app")["github_repo"] == "acme/app"   # not "taken": nothing cleared


@pytest.mark.parametrize("status,withdrawn", [(422, True), (403, True), (502, True), (503, True)])
def test_a_refused_create_withdraws_the_claim_only_when_nothing_was_created(vmain, monkeypatch, status, withdrawn):
    """422 (a repository the App cannot see holds the name) / 403 (no permission): GitHub created nothing, so the
    claim is withdrawn and can never make a repository someone creates later "own". 502 / 503 on every attempt (RT
    D1): it may have been created, so GitHub is read once more; its clean 404 withdraws the claim too."""
    world, db = _World(), f.FakeDB()
    world.create_error = _gh(status)
    eng, globs, _ = _real_engine(vmain, monkeypatch, world, db, SUBMITTED)
    with pytest.raises(globs["VendingFailure"]) as exc:
        eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    assert exc.value.error_class == "GITHUB_REPOSITORY_CREATE_FAILED"
    identity = db.doc("workloads/app").get("github_repository_identity")
    assert identity == (None if withdrawn else {"full_name": "acme/app", "repository_id": None})


def test_f6_an_unreadable_record_stops_the_vend_before_anything_is_created(vmain, monkeypatch):
    world, db = _World({"acme/castor-app": 9}), f.FakeDB()
    eng, globs, projects = _real_engine(vmain, monkeypatch, world, db, {"github_repo": "acme/castor-app"})
    db.fail_paths.add("workloads/app")
    with pytest.raises(globs["VendingFailure"]) as exc:
        eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    assert exc.value.error_class == "VENDING.WORKLOAD_RECORD_UNREADABLE"
    assert projects == [] and world.created == []


def test_legacy_castor_repository_is_kept(vmain, monkeypatch):
    """A workload vended before 11-12 (record `acme/castor-app`) is reused as recorded: no create, no rename."""
    world, db = _World({"acme/castor-app": 9}), f.FakeDB()
    eng, _, _ = _real_engine(vmain, monkeypatch, world, db, {"github_repo": "acme/castor-app"})
    res = eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    assert res["github_repo"]["reused_existing"] is True and world.created == []
    rec = db.doc("workloads/app")
    assert rec["github_repo"] == "acme/castor-app"
    assert rec["github_repository_identity"] == {"full_name": "acme/castor-app", "repository_id": "9"}


def test_f7_vend_repo_route_reads_the_workloads_identity(vmain, monkeypatch):
    world, db = _World({"acme/app": 4242}), f.FakeDB()
    doc = {"github_repository_identity": {"full_name": "acme/app", "repository_id": "4242"}}
    eng, _, _ = _real_engine(vmain, monkeypatch, world, db, doc)
    monkeypatch.setattr(vmain, "vending_engine", eng)
    req = vmain.VendRepoRequest(product_id="app", vcs_provider="GITHUB")
    assert vmain.vend_repo(req)["reused_existing"] is True
    db.docs["workloads/app"] = {}
    with pytest.raises(vmain.HTTPException) as exc:
        vmain.vend_repo(req)
    assert exc.value.status_code == 502 and exc.value.detail["error_class"] == "GITHUB_REPOSITORY_NAME_TAKEN"
    db.fail_paths.add("workloads/app")
    with pytest.raises(vmain.HTTPException) as exc:
        vmain.vend_repo(req)
    assert exc.value.status_code == 503 and exc.value.detail["error_class"] == "VENDING.WORKLOAD_RECORD_UNREADABLE"
    assert world.created == []


# -------------------------------------------------------------------------- Control Center re-submit (RT F3)
def test_f3_resubmit_without_a_target_keeps_the_recorded_repository(cc, monkeypatch):
    """New Workload re-submit of an existing id with an empty Target: a pre-11-12 workload stays on castor-<id>."""
    from test_fd4cu_freeze_new_workloads import ON, _create
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app", "status": "ACTIVE",
                                      "github_repo": "example-org/castor-shop-app"}}
    r, fake_db, _ = _create(wl, monkeypatch, ON, initial=initial)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["github_repo"] == "example-org/castor-shop-app"
    specs = [v for k, v in fake_db.items() if k.startswith("feature_requests/")]
    assert specs and all(s["github_repo"] == "example-org/castor-shop-app" for s in specs)


def test_f3_resubmit_with_a_target_or_a_new_workload_uses_it(cc, monkeypatch):
    from test_fd4cu_freeze_new_workloads import ON, _create
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app", "status": "ACTIVE",
                                      "github_repo": "example-org/castor-shop-app"}}
    r, fake_db, _ = _create(wl, monkeypatch, ON, body={"github_repo": "shop-repo"}, initial=initial)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["github_repo"] == "example-org/shop-repo"
    r, fake_db, _ = _create(wl, monkeypatch, ON)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["github_repo"] == "example-org/shop-app"


def test_f3_resubmit_with_an_unreadable_record_does_not_overwrite_the_repository(cc, monkeypatch):
    from test_fd4cu_freeze_new_workloads import ON, _create
    _, wl = cc
    monkeypatch.setattr(wl, "_stored_workload_doc", lambda pid: None)
    initial = {"workloads/shop-app": {"product_id": "shop-app", "status": "ACTIVE",
                                      "github_repo": "example-org/castor-shop-app"}}
    r, fake_db, _ = _create(wl, monkeypatch, ON, initial=initial)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["github_repo"] == "example-org/castor-shop-app"


# ------------------------------------------------------------------------------------------------- CC + docs
def _cc_routes(monkeypatch, store):
    cc_dir = os.path.join(REPO, "apps", "control-center")
    if cc_dir not in sys.path:
        monkeypatch.syspath_prepend(cc_dir)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl_routes

    monkeypatch.setattr(cc_db, "_db_client", False)
    monkeypatch.setattr(wl_routes, "db", store)
    monkeypatch.setattr(wl_routes, "github_owner", lambda: "Acme")
    return wl_routes


def test_feature_request_link_uses_the_workloads_recorded_repository(monkeypatch):
    """A feature request without its own `github_repo` links to the workload's recorded repository (a castor-<id>
    workload keeps its repository), else to the workload's default repository (the bare id)."""
    from fd4f_support import FakeDB
    store = FakeDB()
    store.docs["workloads/shop"] = {"product_id": "shop", "github_repo": "Acme/castor-shop"}
    store.docs["workloads/new-app"] = {"product_id": "new-app"}
    wl = _cc_routes(monkeypatch, store)
    assert wl._workload_repo_for_feature_request("shop") == "Acme/castor-shop"
    assert wl._workload_repo_for_feature_request("new-app") == "Acme/new-app"
    assert wl._workload_repo_for_feature_request("missing") == "Acme/missing"
    assert store.docs["workloads/shop"] == {"product_id": "shop", "github_repo": "Acme/castor-shop"}   # read only


def test_new_workload_placeholder_states_the_workload_id():
    html = _read("apps/control-center/templates/dashboard.html")
    assert 'placeholder="e.g. payment-service (empty: the workload id, in your organization)"' in html
    assert "castor-&lt;workload id&gt;" not in html


@pytest.mark.parametrize("rel", ["README.md", "documentation/configuration.md", "documentation/platform-internals.md",
                                 "documentation/user-guide.md"])
def test_docs_state_the_new_default(rel):
    text = _read(rel)
    assert "(named `castor-<product_id>` by default)" not in text
    assert "castor-<product_id>/                 # default repository name" not in text


def test_register_row_is_approved():
    if not os.path.exists(os.path.join(REPO, "docs", "planning", "behavior-change-register.md")):
        pytest.skip("docs/ is internal and not part of the public export")
    rows = [ln for ln in _read("docs/planning/behavior-change-register.md").splitlines()
            if ln.startswith("| GITHUB-REPO-NAME-NO-PREFIX")]
    assert len(rows) == 1 and rows[0].rstrip().endswith("| github-repo-name-no-prefix | ✅ owner 11-12 |")


# ------------------------------------------------------------------------------------- delta re-check D1 / D2 / D3
def test_d1_a_kept_claim_cannot_adopt_a_repository_created_later(vmain, monkeypatch):
    """RT D1 (reproduced by the reviewer): 503 on every create, nothing created; the claim is withdrawn (GitHub 404),
    so a staff repository created under the name before the re-run is refused, not adopted."""
    world, db = _World(), f.FakeDB()
    world.create_error = _gh(503)
    eng, globs, _ = _real_engine(vmain, monkeypatch, world, db, SUBMITTED)
    with pytest.raises(globs["VendingFailure"]):
        eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    assert world.created == [] and db.doc("workloads/app")["github_repository_identity"] is None
    world.create_error = None
    world.repos["acme/app"] = 31337                       # someone else creates the exact name
    with pytest.raises(globs["VendingFailure"]) as exc:
        eng.vend_all("app", "tr-2", vcs_provider="GITHUB")
    assert exc.value.error_class == "GITHUB_REPOSITORY_NAME_TAKEN" and world.edited == []


def test_d1_the_claim_stays_when_the_second_read_is_not_a_clean_404(vmain, monkeypatch):
    world, db = _World(), f.FakeDB()
    world.create_error = _gh(503)
    eng, globs, _ = _real_engine(vmain, monkeypatch, world, db, SUBMITTED)
    answers = iter([False, None])                           # pre-check 404, then an unreadable second read
    monkeypatch.setattr(eng, "_github_repository_presence", lambda *a, **k: next(answers))
    with pytest.raises(globs["VendingFailure"]):
        eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    assert db.doc("workloads/app")["github_repository_identity"] == {"full_name": "acme/app", "repository_id": None}


RECORDED = {"github_repo": "acme/app", "github_repository_identity": {"full_name": "acme/app", "repository_id": "4242"}}


def test_d2_a_recreated_recorded_repository_keeps_the_record_and_says_what_to_do(vmain, monkeypatch):
    world, db = _World({"acme/app": 999}), f.FakeDB()
    eng, globs, _ = _real_engine(vmain, monkeypatch, world, db, dict(RECORDED))
    with pytest.raises(globs["VendingFailure"]) as exc:
        eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    err = exc.value
    assert err.error_class == "GITHUB_REPOSITORY_ID_CHANGED" and err.stage == "vcs_repository_vending"
    assert "remove or rename that new repository on GitHub, then restore the original" in str(err)   # RT E1
    assert "Only on a Shared runner install" in str(err) and "VENDING.RUNNER_REPOSITORY_MISMATCH" in str(err)
    rec = db.doc("workloads/app")
    assert rec["github_repo"] == "acme/app" and rec["github_repository_identity"] == RECORDED["github_repository_identity"]
    assert world.created == [] and world.edited == []


def test_d2_restoring_the_original_repository_vends_again(vmain, monkeypatch):
    world, db = _World({"acme/app": 999}), f.FakeDB()
    eng, globs, _ = _real_engine(vmain, monkeypatch, world, db, dict(RECORDED))
    with pytest.raises(globs["VendingFailure"]):
        eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    world.repos["acme/app"] = 4242                         # restored on GitHub: the same id
    assert eng.vend_all("app", "tr-2", vcs_provider="GITHUB")["status"] == "WORKLOAD_VENDED"


def test_d2_renaming_and_naming_it_in_target_moves_the_workload(vmain, monkeypatch):
    """The message's second remedy: the re-created repository renamed to `app-v2` and named in Target (the CC records
    `acme/app-v2`): reused as an operator-named repository, its own id pinned."""
    world, db = _World({"acme/app-v2": 999}), f.FakeDB()
    doc = dict(RECORDED, github_repo="acme/app-v2")
    eng, _, _ = _real_engine(vmain, monkeypatch, world, db, doc)
    assert eng.vend_all("app", "tr-1", vcs_provider="GITHUB")["status"] == "WORKLOAD_VENDED"
    assert world.created == []
    assert db.doc("workloads/app")["github_repository_identity"] == {"full_name": "acme/app-v2", "repository_id": "999"}


def test_d2_first_vend_collision_still_clears_github_repo(vmain, monkeypatch):
    world, db = _World({"acme/app": 77}), f.FakeDB()
    doc = dict(SUBMITTED, github_repository_identity={"full_name": "acme/other", "repository_id": "1"})
    eng, globs, _ = _real_engine(vmain, monkeypatch, world, db, doc)
    with pytest.raises(globs["VendingFailure"]) as exc:
        eng.vend_all("app", "tr-1", vcs_provider="GITHUB")
    assert exc.value.error_class == "GITHUB_REPOSITORY_NAME_TAKEN" and db.doc("workloads/app")["github_repo"] is None


@pytest.mark.parametrize("arg,env,want", [
    ("GITHUB", "SERVERLESS_GIT", "GITHUB"), ("serverless_git", None, "SERVERLESS_GIT"),
    (None, "SERVERLESS_GIT", "SERVERLESS_GIT"), (None, None, "GITHUB"), ("", "SERVERLESS_GIT", "SERVERLESS_GIT"),
])
def test_d3_vcs_provider_resolves_as_the_factory(vmain, monkeypatch, arg, env, want):
    if env is None:
        monkeypatch.delenv("VCS_PROVIDER", raising=False)
    else:
        monkeypatch.setenv("VCS_PROVIDER", env)
    assert vmain.ProjectRepoVendingEngine._resolved_vcs_provider(arg) == want


def test_d3_no_claim_on_a_serverless_install_without_a_recorded_provider(vmain, monkeypatch):
    monkeypatch.setenv("VCS_PROVIDER", "SERVERLESS_GIT")
    eng, _ = _engine(vmain, monkeypatch, vcs=_Vcs(is_reused=False, repo_id=None, provider="SERVERLESS_GIT"))
    monkeypatch.setattr(eng, "_claim_repository", lambda *a, **k: pytest.fail("no GitHub claim on Serverless Git"))
    assert eng.vend_github_repo("app", vcs_provider=None, claim=True)["status"] == "REPO_VENDED"
