"""FD-4D (R04-1 / R04-2): a deploy never runs on an incomplete repository tree, and never without a root main.tf.

- GitHubProvider.fetch_file_tree: a capped fetch keeps `infra/` (git-server `_tree_priority_key` rule); the returned
  dict keeps the API's path order; `require_complete=True` raises IncompleteRepoTreeError on a truncated or errored
  tree. Default (`require_complete=False`) is the same dict, order, status and blob calls as before (Do No Harm).
- ServerlessGitProvider.fetch_file_tree: same strict accessor (the server cuts at max_files).
- mcp-servers/terraform/service.py: `_fetch_repo_files` asks the provider for a complete tree and never falls
  through to the legacy fetch on an incomplete one; the legacy fetch itself refuses a partial read; the deploy
  returns the typed REPO_TREE_INCOMPLETE failure; the manifest guard requires the root `main.tf`.

Real functions with fakes only (no copied production expressions). Hermetic: no network, no tofu, no GCP.
"""
import hermetic_guard  # noqa: F401  (first import: tests/hermetic_guard.py)

import base64
import filecmp
import importlib
import os
import shutil
import sys
import types
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPLICA_DIRS = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared",
                "apps/project-vending/shared", "apps/qa-runner/shared", "mcp-servers/github/shared",
                "mcp-servers/terraform/shared"]
REPLICATED = ["vcs_provider.py", "providers/github_provider.py", "providers/serverless_git_provider.py",
              "providers/__init__.py"]

from shared.providers import github_provider as ghp  # noqa: E402
from shared.providers import serverless_git_provider as sgp  # noqa: E402
from shared.vcs_provider import IncompleteRepoTreeError  # noqa: E402


# ------------------------------------------------------------------------------------------------ fakes
class _FakeRepo:
    """A PyGithub Repository stand-in: `get_git_tree` returns the given entries; blob calls are recorded."""

    def __init__(self, paths, api_truncated=False, fail_blob_at=None, fail_tree=None):
        self.full_name = "example-org/app"
        self._entries = [NS(type="blob", path=p, sha=f"sha-{p}") for p in paths]
        self._api_truncated = api_truncated
        self._fail_blob_at = fail_blob_at
        self._fail_tree = fail_tree
        self.blob_calls = []
        self.tree_calls = 0

    def get_git_tree(self, branch, recursive=True):
        self.tree_calls += 1
        if self._fail_tree is not None:
            raise self._fail_tree
        return NS(tree=list(self._entries), truncated=self._api_truncated)

    def get_git_blob(self, sha):
        if self._fail_blob_at is not None and len(self.blob_calls) == self._fail_blob_at:
            raise RuntimeError("403 API rate limit exceeded (fake)")
        self.blob_calls.append(sha)
        return NS(content=base64.b64encode(f"content of {sha}".encode()).decode())


def _github(repo, monkeypatch, provider_module=ghp):
    prov = provider_module.GitHubProvider.__new__(provider_module.GitHubProvider)
    monkeypatch.setattr(prov, "_get_repo", lambda _ident: repo, raising=False)
    return prov


APP_PATHS = [f"apps/svc/src/m{i:02d}.py" for i in range(8)]
INFRA_PATHS = ["infra/modules/compute-cloudrun/main.tf", "infra/workload/README.md", "infra/workload/main.tf",
               "infra/workload/variables.tf"]
API_ORDER = sorted(APP_PATHS + INFRA_PATHS + ["README.md", "docs/guide.md"])   # GitHub returns path order


# ------------------------------------------------------------------------------------------------ GitHubProvider
def test_complete_tree_is_identical_with_and_without_require_complete(monkeypatch):
    """Do No Harm: a complete tree -> same dict (same key order), same status, same blob calls in API order."""
    loose_repo, strict_repo = _FakeRepo(API_ORDER), _FakeRepo(API_ORDER)
    loose = _github(loose_repo, monkeypatch)
    strict = _github(strict_repo, monkeypatch)
    a = loose.fetch_file_tree("example-org/app", "main")
    b = strict.fetch_file_tree("example-org/app", "main", require_complete=True)
    assert a == b and list(a) == list(b) == API_ORDER
    assert loose.last_tree_status == strict.last_tree_status == {"complete": True, "truncated": False, "error": None}
    assert loose_repo.blob_calls == strict_repo.blob_calls == [f"sha-{p}" for p in API_ORDER]


def test_tree_exactly_at_the_cap_is_complete_and_unchanged(monkeypatch):
    repo = _FakeRepo(API_ORDER)
    prov = _github(repo, monkeypatch)
    files = prov.fetch_file_tree("example-org/app", max_files=len(API_ORDER), require_complete=True)
    assert list(files) == API_ORDER and prov.last_tree_status["complete"] is True


def test_capped_fetch_keeps_every_infra_file_and_api_order(monkeypatch):
    cap = len(INFRA_PATHS) + 1       # tier 0 = the infra/ files + the root README.md; apps/ and docs/ are tier 1
    repo = _FakeRepo(API_ORDER)
    prov = _github(repo, monkeypatch)
    files = prov.fetch_file_tree("example-org/app", max_files=cap)
    assert prov.last_tree_status == {"complete": False, "truncated": True, "error": None}
    assert len(files) == cap
    assert set(INFRA_PATHS) <= set(files)                         # infra/ never lost first
    assert "README.md" in files                                   # root files are tier 0 too
    assert list(files) == [p for p in API_ORDER if p in files]    # API path order kept
    assert set(files) == set(INFRA_PATHS) | {"README.md"}         # tier 1 (apps/, docs/) only after tier 0
    assert len(repo.blob_calls) == cap

    one_more = _github(_FakeRepo(API_ORDER), monkeypatch).fetch_file_tree("example-org/app", max_files=cap + 1)
    assert set(one_more) - set(files) == {APP_PATHS[0]}          # then tier 1 in path order


def test_truncated_tree_require_complete_raises_without_blob_calls(monkeypatch):
    repo = _FakeRepo(API_ORDER)
    prov = _github(repo, monkeypatch)
    with pytest.raises(IncompleteRepoTreeError) as ei:
        prov.fetch_file_tree("example-org/app", "main", max_files=3, require_complete=True)
    assert ei.value.tree_status == {"complete": False, "truncated": True, "error": None}
    assert ei.value.branch == "main" and "truncated" in str(ei.value)
    assert repo.blob_calls == []                                  # no wasted API budget


def test_api_truncated_flag_is_incomplete(monkeypatch):
    repo = _FakeRepo(API_ORDER, api_truncated=True)
    prov = _github(repo, monkeypatch)
    assert list(prov.fetch_file_tree("example-org/app")) == API_ORDER    # default: unchanged return value
    assert prov.last_tree_status["truncated"] is True
    with pytest.raises(IncompleteRepoTreeError):
        _github(_FakeRepo(API_ORDER, api_truncated=True), monkeypatch).fetch_file_tree(
            "example-org/app", require_complete=True)


def test_blob_error_mid_loop_is_error_status_and_strict_raises(monkeypatch):
    repo = _FakeRepo(API_ORDER, fail_blob_at=3)
    prov = _github(repo, monkeypatch)
    partial = prov.fetch_file_tree("example-org/app")
    assert list(partial) == API_ORDER[:3]                         # default: the partial dict, as before
    assert prov.last_tree_status["complete"] is False and "rate limit" in prov.last_tree_status["error"]

    strict_repo = _FakeRepo(API_ORDER, fail_blob_at=3)
    strict = _github(strict_repo, monkeypatch)
    with pytest.raises(IncompleteRepoTreeError) as ei:
        strict.fetch_file_tree("example-org/app", require_complete=True)
    assert "rate limit" in ei.value.tree_status["error"] and ei.value.tree_status["truncated"] is False


def test_strict_error_is_not_retried_by_the_github_backoff_decorator(monkeypatch):
    """IncompleteRepoTreeError carries `tree_status` (a dict), never an int `status`: the retry decorator raises it
    at once instead of sleeping and re-fetching."""
    repo = _FakeRepo(API_ORDER)
    prov = _github(repo, monkeypatch)
    with pytest.raises(IncompleteRepoTreeError):
        prov.fetch_file_tree("example-org/app", max_files=1, require_complete=True)
    assert repo.tree_calls == 1


def test_tree_api_failure_strict_raises_default_returns_empty(monkeypatch):
    prov = _github(_FakeRepo([], fail_tree=RuntimeError("timeout")), monkeypatch)
    assert prov.fetch_file_tree("example-org/app") == {}
    with pytest.raises(IncompleteRepoTreeError):
        _github(_FakeRepo([], fail_tree=RuntimeError("timeout")), monkeypatch).fetch_file_tree(
            "example-org/app", require_complete=True)


def test_priority_key_matches_the_git_server_rule(monkeypatch):
    from fd4k_support import load_git_server

    mod, _client, outer = load_git_server(monkeypatch)
    try:
        sample = API_ORDER + ["Procfile", "Dockerfile", "requirements.txt", "main.py", "app.py", "a/b/x.tf",
                              "apps/main.py", "infra", "infra.md", "x/infra/y.py", ".python-version"]
        assert [ghp._tree_priority_key(p) for p in sample] == [mod._tree_priority_key(p) for p in sample]
    finally:
        shutil.rmtree(outer, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ ServerlessGit
class _SgResp:
    def __init__(self, files):
        self.status_code = 200
        self._files = files

    def json(self):
        return {"files": self._files}


def _serverless(files, monkeypatch):
    prov = sgp.ServerlessGitProvider.__new__(sgp.ServerlessGitProvider)
    calls = []
    monkeypatch.setattr(prov, "_call", lambda *a, **k: calls.append(a) or _SgResp(dict(files)), raising=False)
    return prov, calls


def test_serverless_strict_raises_at_the_cap_and_default_is_unchanged(monkeypatch):
    files = {p: "x" for p in API_ORDER}
    loose, _ = _serverless(files, monkeypatch)
    assert loose.fetch_file_tree("app", "main", max_files=len(files)) == files
    assert loose.last_tree_status["truncated"] is True            # the server cuts without a flag
    strict, calls = _serverless(files, monkeypatch)
    with pytest.raises(IncompleteRepoTreeError) as ei:
        strict.fetch_file_tree("app", "main", max_files=len(files), require_complete=True)
    assert ei.value.tree_status["truncated"] is True and len(calls) == 1


def test_serverless_complete_tree_identical_with_require_complete(monkeypatch):
    files = {p: "x" for p in API_ORDER}
    loose, _ = _serverless(files, monkeypatch)
    strict, _ = _serverless(files, monkeypatch)
    a = loose.fetch_file_tree("app", "main")
    b = strict.fetch_file_tree("app", "main", require_complete=True)
    assert a == b == files and loose.last_tree_status == strict.last_tree_status


# ------------------------------------------------------------------------------------------------ replicas
@pytest.mark.parametrize("rel", REPLICATED)
def test_vcs_replicas_are_byte_identical(rel):
    root = os.path.join(REPO_ROOT, "shared", rel)
    for d in REPLICA_DIRS[1:]:
        assert filecmp.cmp(root, os.path.join(REPO_ROOT, d, rel), shallow=False), f"{d}/{rel} drifted"


# ------------------------------------------------------------------------------------------------ terraform MCP
class _StopAfterGuard(Exception):
    pass


@pytest.fixture
def tf(monkeypatch):
    from fd4g_support import load_tf_service

    return load_tf_service(monkeypatch)


def _svc(tf, tmp_path):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock())
    svc.db = None
    svc.state_bucket = ""
    return svc


def _tf_github_provider_module(tf):
    """The GitHubProvider module of the same `shared` package service.py imported (same exception class)."""
    pkg = tf.IncompleteRepoTreeError.__module__.rsplit(".", 1)[0]
    return importlib.import_module(f"{pkg}.providers.github_provider")


def _legacy_must_not_run(tf, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(tf, "get_github_token", lambda *_a, **_k: pytest.fail("legacy fetch must not run"))


def test_fetch_repo_files_incomplete_vcs_tree_is_typed_and_skips_legacy(tf, monkeypatch, tmp_path):
    mod = _tf_github_provider_module(tf)
    repo = _FakeRepo(API_ORDER)
    prov = _github(repo, monkeypatch, provider_module=mod)
    monkeypatch.setattr(tf, "VCSProviderFactory", NS(get_provider=lambda **_k: prov))
    _legacy_must_not_run(tf, monkeypatch)
    svc = _svc(tf, tmp_path)
    orig = mod.GitHubProvider.fetch_file_tree

    def _capped(self, ident, branch="main", max_files=2500, require_complete=False):
        assert require_complete is True                           # the deploy path always asks for completeness
        return orig(self, ident, branch=branch, max_files=3, require_complete=require_complete)

    monkeypatch.setattr(mod.GitHubProvider, "fetch_file_tree", _capped)
    with pytest.raises(tf.IncompleteRepoTreeError) as ei:
        svc._fetch_repo_files("app", github_repo="example-org/app", branch="main")
    assert ei.value.tree_status["truncated"] is True and repo.blob_calls == []


def test_fetch_repo_files_errored_vcs_tree_is_typed_and_skips_legacy(tf, monkeypatch, tmp_path):
    mod = _tf_github_provider_module(tf)
    repo = _FakeRepo(API_ORDER, fail_blob_at=2)
    prov = _github(repo, monkeypatch, provider_module=mod)
    monkeypatch.setattr(tf, "VCSProviderFactory", NS(get_provider=lambda **_k: prov))
    _legacy_must_not_run(tf, monkeypatch)
    with pytest.raises(tf.IncompleteRepoTreeError) as ei:
        _svc(tf, tmp_path)._fetch_repo_files("app", github_repo="example-org/app", branch="main")
    assert "rate limit" in ei.value.tree_status["error"]


def test_fetch_repo_files_complete_vcs_tree_unchanged(tf, monkeypatch, tmp_path):
    """Do No Harm: a complete provider tree is returned as is (same dict, same order), legacy not consulted."""
    mod = _tf_github_provider_module(tf)
    prov = _github(_FakeRepo(API_ORDER), monkeypatch, provider_module=mod)
    monkeypatch.setattr(tf, "VCSProviderFactory", NS(get_provider=lambda **_k: prov))
    _legacy_must_not_run(tf, monkeypatch)
    files = _svc(tf, tmp_path)._fetch_repo_files("app", github_repo="example-org/app", branch="main")
    assert list(files) == API_ORDER and files[API_ORDER[0]] == f"content of sha-{API_ORDER[0]}"


# ---- legacy (direct REST) fetch: reached only when no provider could be built or it raised a non-tree error
class _HttpResp:
    def __init__(self, status, body=None, text=""):
        self.status_code, self._body, self.text = status, body or {}, text
        self.content = text.encode("utf-8")   # RT14-21: the raw fallback reads bytes

    def json(self):
        return self._body

    def raise_for_status(self):
        raise RuntimeError(f"HTTP {self.status_code}")


class _HttpClient:
    def __init__(self, routes, calls):
        self._routes, self._calls = routes, calls

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def get(self, url, headers=None):
        self._calls.append(url)
        route = self._routes.get(url)
        if isinstance(route, Exception):
            raise route
        return route if route is not None else _HttpResp(404)


def _legacy(tf, monkeypatch, routes):
    """The REAL legacy branch of _fetch_repo_files: no provider factory, a test token, httpx faked by URL."""
    calls = []
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = lambda *a, **k: _HttpClient(routes, calls)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    monkeypatch.setattr(tf, "VCSProviderFactory", None)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-fd4d-not-a-secret")
    return calls


TREE_URL = "https://api.github.com/repos/example-org/app/git/trees/main?recursive=1"


def _blob_url(p):
    return f"https://api.github.com/blob/{p}"


def _raw_url(p):
    return f"https://raw.githubusercontent.com/example-org/app/main/{p}"


def _tree(paths, truncated=False):
    return _HttpResp(200, {"tree": [{"type": "blob", "path": p, "url": _blob_url(p)} for p in paths],
                           "truncated": truncated})


def _blob(text):
    return _HttpResp(200, {"content": base64.b64encode(text.encode()).decode()})


def test_legacy_complete_tree_unchanged(tf, monkeypatch, tmp_path):
    paths = ["infra/workload/main.tf", "main.py"]
    _legacy(tf, monkeypatch, {TREE_URL: _tree(paths), _blob_url(paths[0]): _blob("tf"),
                              _raw_url(paths[1]): _HttpResp(200, text="py")})   # blob API miss -> raw fallback
    files = _svc(tf, tmp_path)._fetch_repo_files("app", github_repo="example-org/app", branch="main")
    assert files == {"infra/workload/main.tf": "tf", "main.py": "py"}


@pytest.mark.parametrize("case", ["api_truncated", "unreadable_file", "error_mid_loop"])
def test_legacy_partial_read_is_typed(tf, monkeypatch, tmp_path, case):
    paths = ["infra/workload/main.tf", "main.py"]
    routes = {TREE_URL: _tree(paths, truncated=(case == "api_truncated")), _blob_url(paths[0]): _blob("tf"),
              _blob_url(paths[1]): _blob("py")}
    if case == "unreadable_file":
        routes.pop(_blob_url(paths[1]))                            # blob 404 and raw 404 -> file unread
    if case == "error_mid_loop":
        routes[_blob_url(paths[1])] = RuntimeError("connection reset")
        routes[_raw_url(paths[1])] = RuntimeError("connection reset")
    _legacy(tf, monkeypatch, routes)
    with pytest.raises(tf.IncompleteRepoTreeError):
        _svc(tf, tmp_path)._fetch_repo_files("app", github_repo="example-org/app", branch="main")


def test_legacy_tree_unreadable_returns_empty_as_before(tf, monkeypatch, tmp_path):
    """No tree at all (404 branch / bad token) is not a partial read: {} as before (the manifest guard refuses it)."""
    _legacy(tf, monkeypatch, {})
    assert _svc(tf, tmp_path)._fetch_repo_files("app", github_repo="example-org/app", branch="main") == {}


# ---- deploy_workload: typed refusal and the root-manifest guard, before any tofu process
def _no_gcp(monkeypatch):
    import google.auth
    import google.cloud

    def _no_client(*_a, **_k):
        raise RuntimeError("no Secret Manager in tests")

    fake_sm = types.ModuleType("google.cloud.secretmanager")
    fake_sm.SecretManagerServiceClient = _no_client
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", fake_sm)
    monkeypatch.setattr(sys.modules["google.cloud"], "secretmanager", fake_sm, raising=False)
    monkeypatch.setattr(sys.modules["google.auth"], "default", _no_client, raising=False)


def _deploy(tf, monkeypatch, tmp_path, fetch):
    svc = _svc(tf, tmp_path)
    monkeypatch.setattr(svc, "_fetch_repo_files", fetch)
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    subprocess_calls, builds = [], []
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **k: subprocess_calls.append(a) or pytest.fail("tofu ran"))
    monkeypatch.setattr(svc, "_build_and_push_container", lambda *a, **k: builds.append(a) or True)

    def _prepare(*_a, **_k):
        raise _StopAfterGuard()

    monkeypatch.setattr(svc, "prepare_workspace", _prepare)
    _no_gcp(monkeypatch)
    return svc, subprocess_calls, builds


def _deploy_call(svc):
    return svc.deploy_workload(product_id="app", trace_id="t-fd4d", target_project_id="p-1", branch="main",
                               iac_engine="OPENTOFU")


def test_deploy_incomplete_tree_is_typed_failure_before_any_tofu(tf, monkeypatch, tmp_path):
    def _raise(*_a, **_k):
        raise tf.IncompleteRepoTreeError("example-org/app", "main",
                                         {"complete": False, "truncated": True, "error": None})

    svc, subprocess_calls, builds = _deploy(tf, monkeypatch, tmp_path, _raise)
    res = _deploy_call(svc)
    assert res["status"] == "FAILED" and res["error_class"] == tf.REPO_TREE_INCOMPLETE == "REPO_TREE_INCOMPLETE"
    assert res["error"].startswith("REPO_TREE_INCOMPLETE:") and res["tree_status"]["truncated"] is True
    assert res["product_id"] == "app" and subprocess_calls == [] and builds == []


def test_deploy_without_root_main_tf_is_refused_before_any_tofu(tf, monkeypatch, tmp_path):
    tree = {"infra/workload/README.md": "# app\n", "infra/workload/custom.tf": 'resource "null_resource" "x" {}\n',
            "infra/workload/variables.tf": 'variable "project_id" {\n  type = string\n}\n'}
    svc, subprocess_calls, builds = _deploy(tf, monkeypatch, tmp_path, lambda *a, **k: dict(tree))
    res = _deploy_call(svc)
    assert res["status"] == "FAILED" and "main.tf" in res["error"]
    assert subprocess_calls == [] and builds == []


def test_deploy_with_infra_workload_main_tf_passes_the_guard(tf, monkeypatch, tmp_path):
    """Negative: a normal tree (infra/workload/main.tf) passes the guard and reaches the workspace step."""
    tree = {"infra/workload/README.md": "# app\n",
            "infra/workload/main.tf": 'module "compute" {\n  source = "../modules/compute-cloudrun"\n}\n',
            "infra/workload/variables.tf": 'variable "project_id" {\n  type = string\n}\n'}
    svc, subprocess_calls, _builds = _deploy(tf, monkeypatch, tmp_path, lambda *a, **k: dict(tree))
    with pytest.raises(_StopAfterGuard):
        _deploy_call(svc)
    assert subprocess_calls == []


# ---- RT F1: the root main.tf is one of the exact pre-flatten keys; a nested infra/workload/**/main.tf is not
ROOT_TF = 'module "compute" {\n  source = "../modules/compute-cloudrun"\n}\n'
VARS_TF = 'variable "project_id" {\n  type = string\n}\n'
OUT_TF = 'output "url" {\n  value = module.compute.service_uri\n}\n'
MODULE_TF = 'resource "null_resource" "db" {}\n'


def _hcl_files_reaching_the_workspace(tf, monkeypatch, tmp_path, tree):
    svc, subprocess_calls, _builds = _deploy(tf, monkeypatch, tmp_path, lambda *a, **k: dict(tree))
    seen = {}

    def _prep(_pid, _trace_id, hcl_files, *_a, **_k):
        seen["files"] = dict(hcl_files)
        raise _StopAfterGuard()

    monkeypatch.setattr(svc, "prepare_workspace", _prep)
    with pytest.raises(_StopAfterGuard):
        _deploy_call(svc)
    assert subprocess_calls == []
    return seen["files"]


def test_deploy_nested_only_main_tf_is_refused_with_the_root_error(tf, monkeypatch, tmp_path):
    tree = {"infra/workload/modules/db/main.tf": MODULE_TF, "infra/workload/variables.tf": VARS_TF}
    svc, subprocess_calls, builds = _deploy(tf, monkeypatch, tmp_path, lambda *a, **k: dict(tree))
    res = _deploy_call(svc)
    assert res["status"] == "FAILED" and "no infrastructure definition" in res["error"] and "main.tf" in res["error"]
    assert subprocess_calls == [] and builds == []


@pytest.mark.parametrize("root_key", ["main.tf", "infra/workload/main.tf", "infra/workloads/main.tf"])
def test_deploy_with_a_root_main_tf_passes_the_guard(tf, monkeypatch, tmp_path, root_key):
    files = _hcl_files_reaching_the_workspace(tf, monkeypatch, tmp_path, {root_key: ROOT_TF,
                                                                          "infra/workload/variables.tf": VARS_TF})
    assert "main.tf" in files


def test_flat_tree_hcl_files_to_prepare_workspace_are_pinned(tf, monkeypatch, tmp_path):
    """Do No Harm: a flat infra/workload/ tree hands prepare_workspace exactly the dict main @ 44643a2e handed it
    (captured before the RT F1 change; terraform.tfvars values depend on the install env, so its keys are pinned)."""
    files = _hcl_files_reaching_the_workspace(tf, monkeypatch, tmp_path, {
        "infra/workload/main.tf": ROOT_TF, "infra/workload/variables.tf": VARS_TF, "infra/workload/outputs.tf": OUT_TF})
    tfvars = files.pop("terraform.tfvars")
    assert files == {"infra/workload/main.tf": ROOT_TF, "infra/workload/variables.tf": VARS_TF,
                     "infra/workload/outputs.tf": OUT_TF,
                     "main.tf": 'module "compute" {\n  source = "./infra/modules/compute-cloudrun"\n}\n',
                     "variables.tf": VARS_TF, "outputs.tf": OUT_TF,
                     # FD-4DT: the platform access var file ("{}": no access record) and its flattened copy
                     "infra/workload/stackvend-access.auto.tfvars.json": "{}",
                     "stackvend-access.auto.tfvars.json": "{}"}
    assert [ln.split("=", 1)[0].strip() for ln in tfvars.splitlines()] == [
        "project_id", "region", "product_id", "github_repo_full_name", "container_image", "oauth_client_id",
        "firebase_auth_domain"]


# ---- RT F2: a non-GitHub provider that could not read the repo is refused, never read through GitHub REST
def _serverless_for_tf(tf, monkeypatch, behaviour):
    pkg = tf.IncompleteRepoTreeError.__module__.rsplit(".", 1)[0]
    mod = importlib.import_module(f"{pkg}.providers.serverless_git_provider")
    prov = mod.ServerlessGitProvider.__new__(mod.ServerlessGitProvider)

    def _fetch(*_a, **_k):
        if behaviour == "error":
            raise mod.ServerlessGitError("git server returned 503 (fake)")
        return {}

    monkeypatch.setattr(prov, "fetch_file_tree", _fetch, raising=False)
    return prov


@pytest.mark.parametrize("behaviour", ["error", "empty"])
def test_fetch_repo_files_serverless_unreadable_never_falls_back_to_github(tf, monkeypatch, tmp_path, behaviour):
    calls = _legacy(tf, monkeypatch, {TREE_URL: _tree(["infra/workload/main.tf"]),
                                      _blob_url("infra/workload/main.tf"): _blob("foreign")})
    prov = _serverless_for_tf(tf, monkeypatch, behaviour)
    monkeypatch.setattr(tf, "VCSProviderFactory", NS(get_provider=lambda **_k: prov))
    assert _svc(tf, tmp_path)._fetch_repo_files("app", github_repo="example-org/app", branch="main") == {}
    assert calls == []                                            # no GitHub REST call at all


def test_fetch_repo_files_github_provider_error_still_uses_the_legacy_read(tf, monkeypatch, tmp_path):
    """Negative: a GitHubProvider that could not be used (e.g. _get_repo failed) keeps the legacy fallback."""
    mod = _tf_github_provider_module(tf)
    prov = mod.GitHubProvider.__new__(mod.GitHubProvider)

    def _no_repo(_ident):
        raise RuntimeError("401 bad credentials (fake)")

    monkeypatch.setattr(prov, "_get_repo", _no_repo, raising=False)
    _legacy(tf, monkeypatch, {TREE_URL: _tree(["infra/workload/main.tf"]),
                              _blob_url("infra/workload/main.tf"): _blob("tf")})
    monkeypatch.setattr(tf, "VCSProviderFactory", NS(get_provider=lambda **_k: prov))
    assert _svc(tf, tmp_path)._fetch_repo_files("app", github_repo="example-org/app", branch="main") == {
        "infra/workload/main.tf": "tf"}
