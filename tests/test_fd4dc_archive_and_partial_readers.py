"""FD-4DC (FD-4D remainder): archive fetch, partial-tree readers, and the Upgrade-IaC PR's file set.

1. GitHubProvider.fetch_file_tree reads the contents from one tarball where each file's git blob SHA matches the
   tree listing; every other kept file is still read with its blob call. The result (dict, key order, status) equals
   the per-file read on every fixture; truncation stays a typed IncompleteRepoTreeError (REPO_TREE_INCOMPLETE).
2. Serverless Git: the git server's tree answer says `truncated`; the client believes the flag (a tree of exactly
   max_files files is complete) and keeps the old rule for a server without it.
3. The readers that used to work on a partial tree refuse it with the typed class: the CC plans list, IaC drift
   view and Upgrade IaC (`apps/control-center/routes/workloads.py`), a remote custom module's upstream read
   (`iac_upgrade_engine.get_upstream_module_files`) and the gateway's IAC_UPGRADE branch.
4. The Upgrade-IaC PR commits exactly the module files it changes (plus the module manifest).

Real functions with fakes only (fake PyGithub repo, fake httpx, real git server on a temp dir, CC routes on fakes).
Hermetic: no network, no GCP.
"""
import hermetic_guard  # noqa: F401  (first import: tests/hermetic_guard.py)

import ast
import base64
import io
import json
import logging
import os
import shutil
import sys
import tarfile
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import pytest

from shared.providers import github_provider as ghp
from shared.providers import serverless_git_provider as sgp
from shared.vcs_provider import IncompleteRepoTreeError

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
ARCHIVE_URL = "https://codeload.example.invalid/example-org/app/legacy.tar.gz/main?token=SECRET-TOKEN"

FIXTURE = {
    "README.md": "# app\n",
    "apps/api/main.py": "print('hi')\n",
    "apps/api/requirements.txt": "fastapi==0.110.0\n",
    "docs/planning/0001-plan.md": "# plan\n",
    "infra/workload/main.tf": 'module "svc" {\n  source = "../modules/compute-cloudrun"\n}\n',
    "infra/workload/variables.tf": 'variable "project_id" {\n  type = string\n}\n',
    "infra/modules/compute-cloudrun/main.tf": "# module\n",
    "unicode.txt": "café ✓\n",
    "empty.txt": "",
}
API_ORDER = sorted(FIXTURE)   # GitHub's recursive tree listing is in path order


# ------------------------------------------------------------------------------------------------ fakes
class _Repo:
    """PyGithub Repository stand-in with REAL git blob SHAs, so the archive check runs on true object ids."""

    def __init__(self, files, api_truncated=False, archive_link=ARCHIVE_URL, fail_blob_at=None, symlinks=None):
        self.full_name = "example-org/app"
        self.files = dict(files)
        self.symlinks = dict(symlinks or {})          # path -> target (a git blob holding the target)
        blobs = {**{p: c.encode() for p, c in self.files.items()}, **{p: t.encode() for p, t in self.symlinks.items()}}
        self._blobs = {ghp.git_blob_sha(b): b for b in blobs.values()}
        self._entries = [NS(type="blob", path=p, sha=ghp.git_blob_sha(blobs[p])) for p in sorted(blobs)]
        self._api_truncated = api_truncated
        self._archive_link = archive_link
        self._fail_blob_at = fail_blob_at
        self.blob_calls, self.link_calls = [], []

    def get_git_tree(self, branch, recursive=True):
        return NS(tree=list(self._entries), truncated=self._api_truncated)

    def get_git_blob(self, sha):
        if self._fail_blob_at is not None and len(self.blob_calls) == self._fail_blob_at:
            raise RuntimeError("403 API rate limit exceeded (fake)")
        self.blob_calls.append(sha)
        return NS(content=base64.b64encode(self._blobs[sha]).decode())

    def get_archive_link(self, archive_format, ref):
        self.link_calls.append((archive_format, ref))
        if isinstance(self._archive_link, Exception):
            raise self._archive_link
        return self._archive_link


def _tarball(files, top="example-org-app-abc1234", symlinks=None, extra=None, override=None):
    """A `git archive`-shaped .tar.gz: a pax header, the top directory, then every file below it."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT,
                      pax_headers={"comment": "abc1234" * 5 + "abcde"}) as tar:
        d = tarfile.TarInfo(top)
        d.type = tarfile.DIRTYPE
        tar.addfile(d)
        for path, text in {**files, **(extra or {}), **(override or {})}.items():
            data = text.encode() if isinstance(text, str) else text
            ti = tarfile.TarInfo(f"{top}/{path}")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
        for path, target in (symlinks or {}).items():
            ti = tarfile.TarInfo(f"{top}/{path}")
            ti.type = tarfile.SYMTYPE
            ti.linkname = target
            tar.addfile(ti)
    return buf.getvalue()


class _FakeHttpx:
    """The two httpx calls `_archive_blobs` makes: Client(...) as a context manager and client.stream(GET, url)."""

    def __init__(self, body=b"", status_error=None, chunk=65536):
        self.body, self.status_error, self.chunk, self.urls = body, status_error, chunk, []
        outer = self

        class _Res:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def raise_for_status(self):
                if outer.status_error is not None:
                    raise outer.status_error

            def iter_bytes(self):
                for i in range(0, len(outer.body), outer.chunk):
                    yield outer.body[i:i + outer.chunk]

        class _Client:
            def __init__(self, **kw):
                outer.client_kwargs = kw

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def stream(self, method, url):
                outer.urls.append((method, url))
                return _Res()

        self.Client = _Client


def _provider(repo, monkeypatch, http=None):
    prov = ghp.GitHubProvider.__new__(ghp.GitHubProvider)
    monkeypatch.setattr(prov, "_get_repo", lambda _ident: repo, raising=False)
    monkeypatch.setattr(ghp, "httpx", http)
    return prov


def _per_file(files, monkeypatch, **kw):
    """The reference read: the same provider with no archive available (every file is a blob call)."""
    repo = _Repo(files, archive_link=None)
    prov = _provider(repo, monkeypatch, http=None)
    return prov.fetch_file_tree("example-org/app", **kw), prov.last_tree_status, repo


# ------------------------------------------------------------------------------------------------ 1. archive fetch
def test_git_blob_sha_is_the_git_object_id():
    assert ghp.git_blob_sha(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"          # git hash-object /dev/null
    assert ghp.git_blob_sha(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"   # printf 'hello\n'


@pytest.mark.parametrize("strict", [False, True])
def test_archive_read_equals_per_file_read_with_no_blob_calls(monkeypatch, strict):
    http = _FakeHttpx(_tarball(FIXTURE))
    repo = _Repo(FIXTURE)
    prov = _provider(repo, monkeypatch, http=http)
    got = prov.fetch_file_tree("example-org/app", "main", require_complete=strict)
    want, want_status, ref_repo = _per_file(FIXTURE, monkeypatch, branch="main", require_complete=strict)
    assert got == want == FIXTURE and list(got) == list(want) == API_ORDER
    assert prov.last_tree_status == want_status == {"complete": True, "truncated": False, "error": None}
    assert repo.blob_calls == [] and len(ref_repo.blob_calls) == len(FIXTURE)
    assert repo.link_calls == [("tarball", "main")] and http.urls == [("GET", ARCHIVE_URL)]
    assert http.client_kwargs["follow_redirects"] is True


def test_member_whose_sha_differs_is_read_with_its_blob_call(monkeypatch):
    """export-subst / LFS / a moved branch: the archive's bytes are not the listed blob -> the blob call decides."""
    tampered = "infra/workload/main.tf"
    http = _FakeHttpx(_tarball(FIXTURE, override={tampered: "# not the committed bytes\n"}))
    repo = _Repo(FIXTURE)
    got = _provider(repo, monkeypatch, http=http).fetch_file_tree("example-org/app")
    assert got == FIXTURE and list(got) == API_ORDER
    assert repo.blob_calls == [ghp.git_blob_sha(FIXTURE[tampered].encode())]


def test_member_missing_from_the_archive_is_read_with_its_blob_call(monkeypatch):
    missing = "apps/api/main.py"
    http = _FakeHttpx(_tarball({p: c for p, c in FIXTURE.items() if p != missing}))
    repo = _Repo(FIXTURE)
    got = _provider(repo, monkeypatch, http=http).fetch_file_tree("example-org/app")
    assert got == FIXTURE and repo.blob_calls == [ghp.git_blob_sha(FIXTURE[missing].encode())]


def test_the_archive_cannot_add_a_file(monkeypatch):
    """Members that the tree listing does not name (extra files, traversal names) never reach the result."""
    # pairs, not a dict display: these names are unsafe on purpose (test_fd4g_do_no_harm scans dict literals)
    extra = dict([("apps/api/extra.py", "x = 1\n"), ("../outside.txt", "nope\n"), (".git/config", "[core]\n")])
    http = _FakeHttpx(_tarball(FIXTURE, extra=extra))
    repo = _Repo(FIXTURE)
    got = _provider(repo, monkeypatch, http=http).fetch_file_tree("example-org/app")
    assert got == FIXTURE and repo.blob_calls == []


def test_symlink_is_verified_by_its_target(monkeypatch):
    links = {"infra/current": "workload"}
    http = _FakeHttpx(_tarball(FIXTURE, symlinks=links))
    repo = _Repo(FIXTURE, symlinks=links)
    got = _provider(repo, monkeypatch, http=http).fetch_file_tree("example-org/app")
    ref = _Repo(FIXTURE, symlinks=links, archive_link=None)
    want = _provider(ref, monkeypatch, http=None).fetch_file_tree("example-org/app")
    assert got == want and got["infra/current"] == "workload" and repo.blob_calls == []


@pytest.mark.parametrize("case", ["download_error", "no_link", "link_error", "not_https", "bad_gzip", "no_httpx"])
def test_archive_unusable_falls_back_to_blob_calls_unchanged(monkeypatch, case):
    """Do No Harm: whenever the archive cannot be used, the read is exactly the per-file read (same blob calls)."""
    body = b"not a tarball" if case == "bad_gzip" else _tarball(FIXTURE)
    http = None if case == "no_httpx" else _FakeHttpx(
        body, status_error=RuntimeError("502 Bad Gateway") if case == "download_error" else None)
    link = {"no_link": None, "link_error": RuntimeError("404"), "not_https": "http://plain.example/x"}.get(
        case, ARCHIVE_URL)
    repo = _Repo(FIXTURE, archive_link=link)
    if case == "no_link":
        repo.get_archive_link = None                    # a repository object without a callable archive link
    prov = _provider(repo, monkeypatch, http=http)
    got = prov.fetch_file_tree("example-org/app", require_complete=True)
    want, status, ref = _per_file(FIXTURE, monkeypatch, require_complete=True)
    assert got == want and list(got) == list(want) and prov.last_tree_status == status
    assert repo.blob_calls == ref.blob_calls


@pytest.mark.parametrize("limit", ["ARCHIVE_MAX_COMPRESSED_BYTES", "ARCHIVE_MAX_MEMBER_BYTES"])
def test_size_limits_stop_the_archive_not_the_read(monkeypatch, limit):
    http = _FakeHttpx(_tarball(FIXTURE), chunk=16)
    monkeypatch.setattr(ghp, limit, 20)
    repo = _Repo(FIXTURE)
    got = _provider(repo, monkeypatch, http=http).fetch_file_tree("example-org/app", require_complete=True)
    assert got == FIXTURE and len(repo.blob_calls) == len(FIXTURE)


def test_few_files_make_no_archive_call(monkeypatch):
    small = {"main.py": "x\n", "README.md": "r\n"}
    assert len(small) < ghp.ARCHIVE_MIN_BLOBS
    http = _FakeHttpx(_tarball(small))
    repo = _Repo(small)
    assert _provider(repo, monkeypatch, http=http).fetch_file_tree("example-org/app") == small
    assert repo.link_calls == [] and http.urls == [] and len(repo.blob_calls) == 2


def test_truncated_tree_strict_raises_typed_before_any_archive_or_blob_call(monkeypatch):
    http = _FakeHttpx(_tarball(FIXTURE))
    for repo, kw in ((_Repo(FIXTURE), {"max_files": 3}), (_Repo(FIXTURE, api_truncated=True), {})):
        prov = _provider(repo, monkeypatch, http=http)
        with pytest.raises(IncompleteRepoTreeError) as ei:
            prov.fetch_file_tree("example-org/app", require_complete=True, **kw)
        assert ei.value.error_class == "REPO_TREE_INCOMPLETE" and ei.value.tree_status["truncated"] is True
        assert repo.blob_calls == [] and repo.link_calls == []
    assert http.urls == []


def test_capped_default_read_uses_the_archive_for_the_kept_set_only(monkeypatch):
    """Default mode on a cut tree: same kept set, order and status as the per-file read (infra/ and root first)."""
    http = _FakeHttpx(_tarball(FIXTURE))
    repo = _Repo(FIXTURE)
    prov = _provider(repo, monkeypatch, http=http)
    got = prov.fetch_file_tree("example-org/app", max_files=5)
    want, status, _ = _per_file(FIXTURE, monkeypatch, max_files=5)
    assert got == want and list(got) == list(want) and prov.last_tree_status == status
    assert status == {"complete": False, "truncated": True, "error": None} and repo.blob_calls == []


def test_blob_error_after_a_partial_archive_is_still_typed(monkeypatch):
    missing = {"apps/api/main.py", "README.md"}
    http = _FakeHttpx(_tarball({p: c for p, c in FIXTURE.items() if p not in missing}))
    repo = _Repo(FIXTURE, fail_blob_at=1)
    prov = _provider(repo, monkeypatch, http=http)
    with pytest.raises(IncompleteRepoTreeError) as ei:
        prov.fetch_file_tree("example-org/app", require_complete=True)
    assert "rate limit" in ei.value.tree_status["error"]
    loose = _provider(_Repo(FIXTURE, fail_blob_at=1), monkeypatch, http=_FakeHttpx(http.body))
    partial = loose.fetch_file_tree("example-org/app")
    assert loose.last_tree_status["complete"] is False and set(partial) < set(FIXTURE)


def test_the_archive_url_is_never_logged(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    for http in (_FakeHttpx(_tarball(FIXTURE)), _FakeHttpx(b"", status_error=RuntimeError(f"boom {ARCHIVE_URL}"))):
        _provider(_Repo(FIXTURE), monkeypatch, http=http).fetch_file_tree("example-org/app")
    assert "SECRET-TOKEN" not in caplog.text and "codeload" not in caplog.text


# ------------------------------------------------------------------------------------------------ 2. Serverless Git
class _SgResp:
    def __init__(self, body):
        self.status_code, self._body = 200, body

    def json(self):
        return self._body


def _serverless(body, monkeypatch):
    prov = sgp.ServerlessGitProvider.__new__(sgp.ServerlessGitProvider)
    monkeypatch.setattr(prov, "_call", lambda *a, **k: _SgResp(body), raising=False)
    return prov


def test_serverless_believes_the_server_flag(monkeypatch):
    files = {p: "x" for p in API_ORDER}
    exact = _serverless({"files": files, "truncated": False}, monkeypatch)
    assert exact.fetch_file_tree("app", max_files=len(files), require_complete=True) == files
    assert exact.last_tree_status == {"complete": True, "truncated": False, "error": None}
    cut = _serverless({"files": files, "truncated": True}, monkeypatch)
    with pytest.raises(IncompleteRepoTreeError):
        cut.fetch_file_tree("app", max_files=len(files) + 5, require_complete=True)
    # a non-boolean flag is not a flag: the old rule applies
    odd = _serverless({"files": files, "truncated": "no"}, monkeypatch)
    with pytest.raises(IncompleteRepoTreeError):
        odd.fetch_file_tree("app", max_files=len(files), require_complete=True)


def test_serverless_old_server_keeps_the_cap_rule(monkeypatch):
    files = {p: "x" for p in API_ORDER}
    old = _serverless({"files": files}, monkeypatch)
    assert old.fetch_file_tree("app", max_files=len(files) + 1, require_complete=True) == files
    with pytest.raises(IncompleteRepoTreeError):
        _serverless({"files": files}, monkeypatch).fetch_file_tree("app", max_files=len(files),
                                                                    require_complete=True)


@pytest.fixture()
def git_server(monkeypatch):
    from fd4k_support import load_git_server

    mod, client, outer = load_git_server(monkeypatch)
    assert client.post("/api/v1/repos", json={"product_id": "app"}).status_code == 201
    r = client.post("/api/v1/repos/app/commits", json={"branch": "main", "files": dict(FIXTURE)})
    assert r.status_code == 200, r.text
    yield mod, client
    shutil.rmtree(outer, ignore_errors=True)


def test_git_server_tree_flag_and_client_end_to_end(git_server, monkeypatch):
    mod, client = git_server
    full = client.get("/api/v1/repos/app/tree/main").json()
    n = full["total_files"]
    assert full["truncated"] is False and set(FIXTURE) <= set(full["files"])
    exact = client.get(f"/api/v1/repos/app/tree/main?max_files={n}").json()
    assert exact["truncated"] is False and exact["files"] == full["files"]
    cut = client.get(f"/api/v1/repos/app/tree/main?max_files={n - 1}").json()
    assert cut["truncated"] is True and cut["total_files"] == n - 1
    # the old function still returns the same dict (Do No Harm for any in-process caller)
    assert mod.fetch_tree_dulwich(mod.get_repo_path("app"), "main") == full["files"]

    prov = sgp.ServerlessGitProvider.__new__(sgp.ServerlessGitProvider)
    monkeypatch.setattr(prov, "_call", lambda method, path, **k: client.get(path), raising=False)
    assert prov.fetch_file_tree("app", "main", max_files=n, require_complete=True) == full["files"]
    with pytest.raises(IncompleteRepoTreeError):
        prov.fetch_file_tree("app", "main", max_files=n - 1, require_complete=True)


# ------------------------------------------------------------------------------------------------ 3. readers
def _cc_routes(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl

    monkeypatch.setattr(cc_db, "_db_client", False)
    monkeypatch.setattr(wl, "verify_workload_access", lambda *a, **k: None)
    return wl


class _Doc:
    def __init__(self, data):
        self.exists, self._data = data is not None, data

    def to_dict(self):
        return dict(self._data or {})


class _Store:
    """workloads/{pid} reads and updates only (what the drift and upgrade routes touch here)."""

    def __init__(self, workload):
        self.workload, self.updates = workload, []

    def collection(self, name):
        store = self

        class _Col:
            def document(self, doc_id):
                class _Ref:
                    def get(self):
                        return _Doc(store.workload)

                    def update(self, data):
                        store.updates.append(data)
                return _Ref()
        return _Col()


WORKLOAD = {"product_id": "app", "github_repo": "example-org/app", "vcs_provider": "GITHUB",
            "default_branch": "main"}


class _UpgradeProvider:
    """A complete-tree provider that records what the Upgrade-IaC route writes."""

    def __init__(self, files):
        self.files, self.commits, self.fetch_kwargs, self.branches = dict(files), [], [], []

    def fetch_file_tree(self, repo, branch="main", **kw):
        self.fetch_kwargs.append(kw)
        return dict(self.files)

    def create_or_verify_branch(self, repo, branch_name, source_branch="main"):
        self.branches.append((branch_name, source_branch))
        return branch_name

    def commit_files(self, repo, branch, files, commit_message, **kw):
        self.commits.append(dict(files))
        return "a" * 40

    def create_pull_request(self, repo, **kw):
        return {"pr_number": 7, "pull_request_url": "https://example.invalid/pull/7"}


def _strict_github(monkeypatch):
    """A real GitHubProvider on a listing GitHub marks truncated: require_complete raises the real typed error."""
    return _provider(_Repo(FIXTURE, api_truncated=True), monkeypatch, http=None)


def _use_provider(monkeypatch, wl, provider):
    import shared.vcs_provider as vp

    assert wl.IncompleteRepoTreeError is vp.IncompleteRepoTreeError is IncompleteRepoTreeError
    monkeypatch.setattr(vp.VCSProviderFactory, "get_provider", staticmethod(lambda *a, **k: provider))


def _manager_request(email="op@example.com"):
    """RT14-34: the Upgrade-IaC author is the verified caller (request.state.user_email), never the request body."""
    request = MagicMock()
    request.state.user_email = email
    return request


def _upgrade_recorders(monkeypatch, wl):
    rec = {"start": [], "complete": []}
    monkeypatch.setattr(wl, "record_iac_upgrade_start", lambda *a, **k: rec["start"].append((a, k)) or "up-1")
    monkeypatch.setattr(wl, "record_iac_upgrade_complete", lambda *a, **k: rec["complete"].append((a, k)))
    monkeypatch.setattr(wl, "_record_iac_upgrade_ledger", lambda *a, **k: {"ledger_recorded": True,
                                                                           "ledger_reason": None})
    return rec


def test_drift_view_refuses_a_partial_tree_and_keeps_the_cache(monkeypatch):
    wl = _cc_routes(monkeypatch)
    store = _Store(dict(WORKLOAD, iac_drift_detected=True, iac_drift_count=2))
    monkeypatch.setattr(wl, "get_db", lambda: store)
    _use_provider(monkeypatch, wl, _strict_github(monkeypatch))
    with pytest.raises(wl.HTTPException) as ei:
        wl.get_workload_iac_drift_status("app", MagicMock())
    assert ei.value.status_code == 409 and ei.value.detail.startswith("REPO_TREE_INCOMPLETE: ")
    assert store.updates == []                                        # the cached summary is not overwritten


def test_drift_view_on_a_complete_tree_is_unchanged(monkeypatch):
    wl = _cc_routes(monkeypatch)
    store = _Store(dict(WORKLOAD))
    monkeypatch.setattr(wl, "get_db", lambda: store)
    prov = _UpgradeProvider(_workload_tree(drift=True))
    _use_provider(monkeypatch, wl, prov)
    resp = wl.get_workload_iac_drift_status("app", MagicMock())
    assert prov.fetch_kwargs == [{"require_complete": True}]
    assert resp.drift_detected is True and "compute-cloudrun" in {m.name for m in resp.modules if m.drift_detected}
    assert store.updates == [{"iac_drift_detected": True, "iac_drift_count": resp.outdated_modules}]


def test_upgrade_refuses_a_partial_tree_and_commits_nothing(monkeypatch):
    wl = _cc_routes(monkeypatch)
    monkeypatch.setattr(wl, "get_db", lambda: _Store(dict(WORKLOAD)))
    rec = _upgrade_recorders(monkeypatch, wl)
    prov = _strict_github(monkeypatch)
    for name in ("create_or_verify_branch", "commit_files", "create_pull_request"):
        monkeypatch.setattr(prov, name, MagicMock(side_effect=AssertionError(f"{name} must not run")))
    _use_provider(monkeypatch, wl, prov)
    req = wl.TriggerIaCUpgradeRequest(author="op@example.com", modules_to_upgrade=["compute-cloudrun"])
    with pytest.raises(wl.HTTPException) as ei:
        wl.trigger_workload_iac_upgrade("app", req, _manager_request())
    assert ei.value.status_code == 409 and ei.value.detail.startswith("REPO_TREE_INCOMPLETE: ")
    (_, kw), = rec["complete"]
    assert kw["status"] == "FAILED" and kw["validation_error"].startswith("REPO_TREE_INCOMPLETE: ")


def test_plans_list_refuses_a_partial_tree_instead_of_inventing_a_baseline(monkeypatch):
    wl = _cc_routes(monkeypatch)
    monkeypatch.setattr(wl, "db", None)
    monkeypatch.setattr(wl.VCSProviderFactory, "get_provider",
                        staticmethod(lambda *a, **k: _strict_github(monkeypatch)))
    with pytest.raises(wl.HTTPException) as ei:
        wl.get_workload_implementation_plans("app", MagicMock())
    assert ei.value.status_code == 409 and ei.value.detail.startswith("REPO_TREE_INCOMPLETE: ")


def test_plans_list_on_a_complete_tree_is_unchanged(monkeypatch):
    wl = _cc_routes(monkeypatch)
    monkeypatch.setattr(wl, "db", None)
    prov = _UpgradeProvider(FIXTURE)
    monkeypatch.setattr(wl.VCSProviderFactory, "get_provider", staticmethod(lambda *a, **k: prov))
    resp = wl.get_workload_implementation_plans("app", MagicMock())
    assert [p.file_path for p in resp.plans] == ["docs/planning/0001-plan.md"]
    assert prov.fetch_kwargs == [{"require_complete": True}]


class _CustomModuleStore:
    def __init__(self, doc):
        self.doc = doc

    def collection(self, name):
        assert name == "custom_modules"
        doc = self.doc

        class _Col:
            def document(self, _id):
                return NS(get=lambda: _Doc(doc))
        return _Col()


REMOTE_MODULE = {"source_type": "REMOTE_GIT", "version_tag": "v2.0.0",
                 "source_url": "https://github.com/example-org/app", "repo_path": "infra"}


def _engine_with_provider(monkeypatch, provider):
    import shared.iac_upgrade_engine as engine
    import shared.vcs_provider as vp

    assert engine.IncompleteRepoTreeError is vp.IncompleteRepoTreeError
    monkeypatch.setattr(vp.VCSProviderFactory, "get_provider", staticmethod(lambda *a, **k: provider))
    return engine


def test_remote_custom_module_partial_upstream_is_refused(monkeypatch):
    engine = _engine_with_provider(monkeypatch, _strict_github(monkeypatch))
    with pytest.raises(IncompleteRepoTreeError):
        engine.get_upstream_module_files("remote-mod", {}, {}, _CustomModuleStore(REMOTE_MODULE))


def test_remote_custom_module_complete_upstream_is_unchanged(monkeypatch):
    prov = _UpgradeProvider(FIXTURE)
    engine = _engine_with_provider(monkeypatch, prov)
    files, asset_type, version, _src = engine.get_upstream_module_files(
        "remote-mod", {}, {}, _CustomModuleStore(REMOTE_MODULE))
    assert files == {p[len("infra/"):]: c for p, c in FIXTURE.items() if p.startswith("infra/")}
    assert version == "v2.0.0" and prov.fetch_kwargs == [{"require_complete": True}]


def _calls_named(path, attr):
    tree = ast.parse(open(os.path.join(REPO_ROOT, path), encoding="utf-8").read())
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == attr]


@pytest.mark.parametrize("path,count", [
    ("apps/control-center/routes/workloads.py", 3),
    ("apps/orchestrator-gateway/main.py", 1),
    ("shared/iac_upgrade_engine.py", 1),
    ("apps/control-center/shared/iac_upgrade_engine.py", 1),
    ("apps/orchestrator-gateway/shared/iac_upgrade_engine.py", 1),
    ("mcp-servers/terraform/shared/iac_upgrade_engine.py", 1),
])
def test_every_iac_and_cc_tree_reader_asks_for_the_whole_tree(path, count):
    """Inventory: the plans list, drift view, Upgrade IaC (CC), the gateway IAC_UPGRADE branch and the remote module
    read all pass require_complete=True and no smaller max_files cap."""
    calls = _calls_named(path, "fetch_file_tree")
    assert len(calls) == count, [c.lineno for c in calls]
    for c in calls:
        kws = {k.arg: k.value for k in c.keywords}
        assert isinstance(kws.get("require_complete"), ast.Constant) and kws["require_complete"].value is True, c.lineno
        assert "max_files" not in kws, c.lineno


# ------------------------------------------------------------------------------------------------ 4. upgrade file set
def _canonical(module):
    from shared.iac_upgrade_engine import get_canonical_module_files

    prefix = f"infra/modules/{module}/"
    return {p: c for p, c in get_canonical_module_files().items() if p.startswith(prefix)}


def _workload_tree(drift):
    """A workload repo: app code, root IaC, a human override, a current second module, and compute-cloudrun."""
    from shared.iac_upgrade_engine import get_canonical_module_files

    cloudrun = _canonical("compute-cloudrun")
    assert cloudrun, "compute-cloudrun canonical files"
    tree = dict(FIXTURE)
    tree.pop("infra/modules/compute-cloudrun/main.tf")
    tree.update(cloudrun)
    tree["infra/human.tf"] = "# operator override\n"
    flat = {p.split("/")[2] for p in get_canonical_module_files() if p.count("/") == 3}
    other = sorted(flat - {"compute-cloudrun"})[0]
    tree.update(_canonical(other))
    if drift:
        tree["infra/modules/compute-cloudrun/main.tf"] = cloudrun["infra/modules/compute-cloudrun/main.tf"] + \
            "\n# local drift\n"
    return tree


def test_upgrade_pr_writes_exactly_the_module_files_it_updates(monkeypatch):
    wl = _cc_routes(monkeypatch)
    monkeypatch.setattr(wl, "get_db", lambda: _Store(dict(WORKLOAD)))
    rec = _upgrade_recorders(monkeypatch, wl)
    existing = _workload_tree(drift=True)
    prov = _UpgradeProvider(existing)
    _use_provider(monkeypatch, wl, prov)
    req = wl.TriggerIaCUpgradeRequest(author="op@example.com", modules_to_upgrade=["compute-cloudrun"])
    out = wl.trigger_workload_iac_upgrade("app", req, _manager_request())
    (committed,) = prov.commits
    main_tf, manifest = "infra/modules/compute-cloudrun/main.tf", "infra/modules/compute-cloudrun/.castor-module.json"
    assert set(committed) == {main_tf, manifest}
    assert committed[main_tf] == _canonical("compute-cloudrun")[main_tf]
    assert json.loads(committed[manifest])["module_name"] == "compute-cloudrun"
    assert out["files_updated_count"] == 2 and out["upgraded_modules"] == ["compute-cloudrun"]
    # nothing else: app code, root IaC, the human override, the other module and the unchanged module files
    assert not set(committed) & ({p for p in existing if not p.startswith("infra/modules/compute-cloudrun/")}
                                 | {p for p in existing if p.startswith("infra/modules/compute-cloudrun/")
                                    and p != main_tf})
    assert prov.fetch_kwargs == [{"require_complete": True}]
    (_, kw), = rec["complete"]
    assert kw["status"] == "SUCCESS" and sorted(kw["details"]["files_updated"]) == sorted([main_tf, manifest])


# ------------------------------------------------------------------------------------------------ RT fixes
def _real_httpx_with(monkeypatch, handler):
    """The REAL httpx client (its own request logging included) on a MockTransport: no socket is opened."""
    import functools

    import httpx

    assert ghp.httpx is httpx
    monkeypatch.setattr(httpx, "Client", functools.partial(httpx.Client, transport=httpx.MockTransport(handler)))
    return httpx


def _codeload_handler(body, seen):
    """api.github.com tarball / codeload start -> 302 -> codeload?token=... -> 200 (the live redirect shape)."""
    import httpx

    def handler(request):
        seen.append(str(request.url))
        if request.url.path.endswith("/final"):
            return httpx.Response(200, content=body)
        return httpx.Response(302, headers={"Location": "https://codeload.example.invalid/final?token=HOP-SECRET"})
    return handler


def test_rt_f1_real_httpx_never_logs_the_token_bearing_url(monkeypatch, caplog):
    """RT F1: httpx logs "HTTP Request: GET <url>" at INFO; the provider keeps httpx / httpcore at WARNING, so neither
    the archive read nor export_archive_stream writes a token-bearing URL to the logs (root logger at DEBUG)."""
    caplog.set_level(logging.DEBUG)
    seen = []
    tarball = _tarball(FIXTURE)   # built once: the gzip header holds the wall-clock second
    _real_httpx_with(monkeypatch, _codeload_handler(tarball, seen))
    start = "https://codeload.example.invalid/start?token=LINK-SECRET"
    repo = _Repo(FIXTURE, archive_link=start)
    prov = ghp.GitHubProvider.__new__(ghp.GitHubProvider)
    monkeypatch.setattr(prov, "_get_repo", lambda _ident: repo, raising=False)
    assert prov.fetch_file_tree("example-org/app", require_complete=True) == FIXTURE
    assert repo.blob_calls == []                                   # the real client read the archive
    prov._explicit_token, prov.default_owner = "gh-test-token", "example-org"
    assert prov.export_archive_stream("example-org/app", "main").read() == tarball
    assert seen == [start, "https://codeload.example.invalid/final?token=HOP-SECRET",
                    "https://api.github.com/repos/example-org/app/tarball/main",
                    "https://codeload.example.invalid/final?token=HOP-SECRET"]
    assert "token=" not in caplog.text and "SECRET" not in caplog.text
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING


def _gateway_main():
    import importlib.util
    from unittest.mock import patch

    pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
    gateway = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
    for p in (gateway, REPO_ROOT):
        if p not in sys.path:
            sys.path.insert(0, p)
    spec = importlib.util.spec_from_file_location("orchestrator_gateway_main_fd4dc", os.path.join(gateway, "main.py"))
    mod = importlib.util.module_from_spec(spec)
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": "",
                                 "GEMINI_API_KEY": ""}), \
            patch("google.genai.Client", side_effect=RuntimeError("no genai in tests")), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
        spec.loader.exec_module(mod)
    return mod


def test_rt_f2_gateway_iac_upgrade_on_a_partial_tree_is_a_typed_409(monkeypatch):
    gw = _gateway_main()
    assert gw.IncompleteRepoTreeError is IncompleteRepoTreeError
    _use_provider_anywhere = _strict_github(monkeypatch)
    import shared.vcs_provider as vp

    monkeypatch.setattr(vp.VCSProviderFactory, "get_provider", staticmethod(lambda *a, **k: _use_provider_anywhere))
    monkeypatch.setattr(gw, "db", None)
    dev = MagicMock()
    monkeypatch.setattr(gw, "developer_agent", dev)
    req = gw.DeveloperExecuteRequest(product_id="app", trace_id="tr-1", change_type="IAC_UPGRADE")
    with pytest.raises(gw.HTTPException) as ei:
        gw.developer_execute(req)
    assert ei.value.status_code == 409
    assert ei.value.detail.startswith("REPO_TREE_INCOMPLETE: ")
    assert ei.value.detail.endswith("Nothing was committed and no pull request was opened.")
    dev.commit_and_open_pr.assert_not_called()


@pytest.mark.parametrize("limit,value", [("ARCHIVE_MAX_MEMBER_BYTES", 500 * 1024), ("ARCHIVE_MAX_MEMBERS", 1_000)])
def test_rt_f3_header_only_members_count_against_the_caps(monkeypatch, limit, value):
    """RT F3: 2,000 empty members are ~1 MB of tar headers (0 data bytes): the archive is unusable, the read is not."""
    padding = {f"pad/{i:05d}.txt": "" for i in range(2000)}
    http = _FakeHttpx(_tarball(FIXTURE, extra=padding))
    monkeypatch.setattr(ghp, limit, value)
    repo = _Repo(FIXTURE)
    got = _provider(repo, monkeypatch, http=http).fetch_file_tree("example-org/app", require_complete=True)
    want, _, ref = _per_file(FIXTURE, monkeypatch, require_complete=True)
    assert got == want and list(got) == list(want) and repo.blob_calls == ref.blob_calls


def test_rt_f3_within_the_caps_the_padding_is_ignored(monkeypatch):
    padding = {f"pad/{i:05d}.txt": "" for i in range(2000)}
    repo = _Repo(FIXTURE)
    got = _provider(repo, monkeypatch, http=_FakeHttpx(_tarball(FIXTURE, extra=padding))).fetch_file_tree(
        "example-org/app")
    assert got == FIXTURE and repo.blob_calls == []


def test_rt_f4_the_download_has_a_whole_deadline(monkeypatch):
    """RT F4: a download still running past ARCHIVE_TIMEOUT_SECONDS is abandoned; the blobs are read one by one."""
    monkeypatch.setattr(ghp, "ARCHIVE_TIMEOUT_SECONDS", -1.0)     # the deadline has passed at the first chunk
    repo = _Repo(FIXTURE)
    got = _provider(repo, monkeypatch, http=_FakeHttpx(_tarball(FIXTURE))).fetch_file_tree("example-org/app")
    assert got == FIXTURE and len(repo.blob_calls) == len(FIXTURE)


def test_rt_f5_tarball_reader_takes_bytes_or_a_file_object():
    wanted = {p: ghp.git_blob_sha(c.encode()) for p, c in FIXTURE.items()}
    body = _tarball(FIXTURE)
    as_bytes = ghp.verified_blobs_from_tarball(body, wanted)
    as_file = ghp.verified_blobs_from_tarball(io.BytesIO(body), wanted)
    assert as_bytes == as_file == {p: c.encode() for p, c in FIXTURE.items()}
