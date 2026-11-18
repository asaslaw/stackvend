"""FD-7L Phase 4 (SAT-30; plan rev 3 §2.10, §8 row 4): on a Per-workload install the runner reads the one repository
vending's SIGNED provenance record pins, GitHub with vending's read-only `/runner/repo-token` token and Serverless Git
with the job's own ID token; GITHUB_TOKEN, the GitHub App key and the legacy REST fallback are never used. The git
server gains a read-only invoker class (`GIT_SERVER_READONLY_INVOKERS`) that may call only the read routes.

Do No Harm (negatives): on a Shared install (`STACKVEND_TF_RUNNER_IDENTITY` unset / PLATFORM / blank)
`_fetch_repo_files` makes exactly the calls it made before (same provider factory arguments, same tree call, the
legacy GITHUB_TOKEN read) and never consults a registered runner; `GIT_SERVER_ALLOWED_INVOKERS` callers get the same
answers on every route whether or not a read-only list is configured.

Hermetic: fake broker, fake provider factory, real ServerlessGitProvider with `requests` faked, the real git server
with real RS256 tokens (tests/fd4k_support.py); no network, no cloud clients.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib
import logging
import os
import shutil
import socket
import sys
import types
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import pytest

from test_fd4g_terraform_workspace import base, sent_callbacks  # noqa: F401,F811  (pytest fixtures reused by name)

MODE = "STACKVEND_TF_RUNNER_IDENTITY"
PRODUCT = "claims"
CHILD = "claims-prod-1a2b"
SESSION_KEY = "a" * 64 + "." + "s" * 43            # test value only
REPO_TOKEN = "ghs_test-only-read-token-sat30"       # test value only
DEPLOYER_TOKEN = "ya29.test-only-deployer-token"   # test value only
ID_TOKEN = "eyJ.test-only-job-id-token.sig"        # test value only
PINNED_GH = {"provider": "GITHUB", "full_name": "Acme/claims", "id": "42"}
PINNED_SG = {"provider": "SERVERLESS_GIT", "full_name": "serverless-git/claims", "id": None}
TREE = {"infra/workload/main.tf": 'terraform {}\n', "apps/api/main.py": "print('x')\n"}
POISON = {"GITHUB_TOKEN": "poison-github-token", "CASTOR_GIT_AUTH_TOKEN": "poison-git-auth",
          "GOOGLE_OIDC_ID_TOKEN": "poison-oidc"}


# ------------------------------------------------------------------------------------------------ fixtures
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


class FakeBroker:
    """BrokerClient stand-in: records every call; never sees anything but the session key."""

    def __init__(self, rc, answer=None, refuse=None):
        self.rc, self.calls = rc, []
        self.answer = answer if answer is not None else {"repository": "Acme/claims", "expires_at": "x",
                                                         "permissions": {"contents": "read"}}
        self.refuse = refuse

    def deployer_token(self, session_key):
        self.calls.append(("deployer_token", session_key))
        import time
        return DEPLOYER_TOKEN, time.time() + 3600, {}

    def repo_token(self, session_key):
        self.calls.append(("repo_token", session_key))
        if self.refuse is not None:
            raise self.rc.ri.RunnerIdentityError(self.refuse, "refused (test)", stage="runner-repo-token",
                                                 http_status=403)
        return REPO_TOKEN, dict(self.answer)


def _register(tf, svc, tmp_path, *, product=PRODUCT, repository=PINNED_GH, broker=None, key="ws"):
    rc = tf.runner_creds
    broker = broker or FakeBroker(rc)
    creds = rc.BrokeredCredentials(broker, SESSION_KEY, project_id=CHILD,
                                   deployer_email=f"stackvend-deployer@{CHILD}.iam.gserviceaccount.com")
    runner = rc.WorkspaceRunner(creds, NS(failure=None), "broker-key-1", product_id=product,
                                repository=dict(repository) if repository is not None else None)
    svc._register_workspace_runner(str(tmp_path / key), runner)
    return runner, broker


class FakeFactory:
    """VCSProviderFactory stand-in: records the kwargs of every get_provider call and returns `provider`."""

    def __init__(self, provider):
        self.provider, self.calls = provider, []

    def get_provider(self, **kwargs):
        self.calls.append(dict(kwargs))
        return self.provider


class FakeProvider:
    def __init__(self, tree=None, error=None):
        self.tree, self.error, self.calls = dict(TREE if tree is None else tree), error, []

    def fetch_file_tree(self, repo, branch="main", max_files=2500, require_complete=False):
        self.calls.append((repo, branch, require_complete))
        if self.error is not None:
            raise self.error
        return dict(self.tree)


def _provider_module(tf, name):
    """The provider module of the same `shared` package service.py imports from (what its lazy import resolves)."""
    pkg = tf.IncompleteRepoTreeError.__module__.rsplit(".", 1)[0]
    return importlib.import_module(f"{pkg}.providers.{name}")


def _github_reader(tf, monkeypatch, provider=None):
    """Replaces the brokered GitHub REST read (SAT-50: `_read_github_tree_rest`); records the token it was given and
    reads from `provider` (its calls = (repository, branch, True))."""
    built, prov = [], provider or FakeProvider()

    def _read(full_name, branch, token):
        built.append({"github_token": token})
        return prov.fetch_file_tree(full_name, branch=branch, require_complete=True)

    monkeypatch.setattr(tf.TerraformService, "_read_github_tree_rest", staticmethod(_read))
    return built, prov


def _no_factory(tf, monkeypatch):
    """A Per-workload read never uses VCSProviderFactory (its settings / Firestore / env resolution)."""
    monkeypatch.setattr(tf, "VCSProviderFactory",
                        NS(get_provider=lambda **k: pytest.fail("VCSProviderFactory used on a Per-workload read")))


def _no_platform_credentials(tf, monkeypatch):
    """Every platform credential path of the old read fails the test if reached."""
    monkeypatch.setattr(tf, "get_github_token", lambda *a, **k: pytest.fail("platform GitHub token read"))
    fake_sm = types.ModuleType("google.cloud.secretmanager")
    fake_sm.SecretManagerServiceClient = lambda *a, **k: pytest.fail("Secret Manager read")
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", fake_sm)
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = lambda *a, **k: pytest.fail("legacy GitHub REST read")
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    _no_factory(tf, monkeypatch)


def _per_workload(monkeypatch, poison=True):
    monkeypatch.setenv(MODE, "PER_WORKLOAD")
    for k, v in POISON.items():
        if poison:
            monkeypatch.setenv(k, v)
        else:
            monkeypatch.delenv(k, raising=False)


# ------------------------------------------------------------------------------------------------ Shared install
@pytest.mark.parametrize("mode", [None, "PLATFORM", ""])
def test_shared_install_fetch_makes_exactly_the_old_calls_and_ignores_registered_runners(tf, monkeypatch, tmp_path,
                                                                                        mode):
    """Negative: same factory arguments, same tree call, the runner (with a pinned repository) is never consulted."""
    if mode is None:
        monkeypatch.delenv(MODE, raising=False)
    else:
        monkeypatch.setenv(MODE, mode)
    svc = _svc(tf, tmp_path)
    _runner, broker = _register(tf, svc, tmp_path)
    prov = FakeProvider()
    factory = FakeFactory(prov)
    monkeypatch.setattr(tf, "VCSProviderFactory", factory)
    files = svc._fetch_repo_files("app", github_repo="example-org/app", branch="main")
    assert files == TREE
    assert factory.calls == [{"default_owner": "example-org", "project_id": "mock-stackvend-project",
                              "product_id": "app", "full_repo_name": "example-org/app"}]
    assert prov.calls == [("example-org/app", "main", True)]
    assert broker.calls == []


def test_shared_install_legacy_read_still_uses_github_token(tf, monkeypatch, tmp_path):
    """Negative: with no provider factory the Shared read is the legacy GITHUB_TOKEN read, as before."""
    monkeypatch.delenv(MODE, raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-sat30-not-a-secret")
    seen = []

    class _Client:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, headers=None):
            seen.append((url, (headers or {}).get("Authorization")))
            return NS(status_code=404, json=lambda: {}, text="")

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = _Client
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    monkeypatch.setattr(tf, "VCSProviderFactory", None)
    assert _svc(tf, tmp_path)._fetch_repo_files("app", github_repo="example-org/app", branch="main") == {}
    assert seen == [("https://api.github.com/repos/example-org/app/git/trees/main?recursive=1",
                     "Bearer test-token-sat30-not-a-secret")]


# ------------------------------------------------------------------------------------------------ Per-workload GitHub
def test_per_workload_github_read_uses_only_the_brokered_read_only_token(tf, monkeypatch, tmp_path, caplog):
    _per_workload(monkeypatch)
    _no_platform_credentials(tf, monkeypatch)
    svc = _svc(tf, tmp_path)
    _runner, broker = _register(tf, svc, tmp_path)
    built, prov = _github_reader(tf, monkeypatch)
    with caplog.at_level(logging.INFO):
        files = svc._fetch_repo_files(PRODUCT, github_repo="acme/Claims", branch="release")   # GitHub: any case
    assert files == TREE
    assert broker.calls == [("repo_token", SESSION_KEY)]                  # one mint, this session only
    assert built == [{"github_token": REPO_TOKEN}]
    assert prov.calls == [("Acme/claims", "release", True)]               # the PINNED name, a complete tree
    ignored = [r.getMessage() for r in caplog.records if r.getMessage().startswith("RUNNER_ENV_IGNORED")]
    assert len(ignored) == 1 and all(name in ignored[0] for name in POISON)
    for secret in [REPO_TOKEN, SESSION_KEY, *POISON.values()]:
        assert secret not in caplog.text                                  # names only, never a value or a token


# ------------------------------------------------------------------------------------------------ SAT-50: the REST read
API = "https://api.github.com/repos/Acme/claims"
BLOBS = {"sha-main-tf": TREE["infra/workload/main.tf"], "sha-api-py": TREE["apps/api/main.py"]}


def _tree_body(truncated=False):
    return {"sha": "t", "truncated": truncated, "tree": [
        {"path": "infra", "type": "tree", "sha": "sha-dir"},
        {"path": "infra/workload/main.tf", "type": "blob", "sha": "sha-main-tf",
         "url": "https://attacker.invalid/blob"},                       # never followed: URLs come from the SHA
        {"path": "vendor/lib", "type": "commit", "sha": "sha-submodule"},
        {"path": "apps/api/main.py", "type": "blob", "sha": "sha-api-py"},
    ]}


def _github_api(monkeypatch, answers=None, raise_on=None):
    """A fake `httpx` whose Client answers the GitHub REST calls; records (url, Authorization, Accept) of each call.
    `answers` overrides {url: (status, body[, headers])}, or {url: [answer, ...]} answered in order (the last one
    repeats); `raise_on` = a url whose GET raises a transport error."""
    import base64
    seen = []
    table = {f"{API}/git/trees/release?recursive=1": (200, _tree_body())}
    table.update({f"{API}/git/blobs/{sha}": (200, {"content": base64.b64encode(text.encode()).decode(),
                                                    "encoding": "base64"}) for sha, text in BLOBS.items()})
    table.update(answers or {})

    class _Client:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, headers=None):
            seen.append((url, (headers or {}).get("Authorization"), (headers or {}).get("Accept")))
            if url == raise_on:
                raise ConnectionError("connection reset (fake)")
            answer = table.get(url, (404, {"message": "Not Found"}))
            if isinstance(answer, list):
                answer = answer.pop(0) if len(answer) > 1 else answer[0]
            status, body, *rest = answer
            return NS(status_code=status, json=lambda: body, text=str(body), headers=dict(rest[0]) if rest else {},
                      raise_for_status=lambda: (_ for _ in ()).throw(RuntimeError(f"HTTP {status} (fake)")))

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = _Client
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    return seen


def _without_pygithub(monkeypatch):
    """The tf-applier / mcp-terraform-server image: no PyGithub, no dulwich (mcp-servers/terraform/requirements.txt)."""
    for name in ("github", "dulwich"):
        monkeypatch.setitem(sys.modules, name, None)   # `import github` -> ImportError


def _rest_ready(tf, monkeypatch, tmp_path, **api):
    _per_workload(monkeypatch)
    _no_platform_credentials(tf, monkeypatch)
    _without_pygithub(monkeypatch)
    seen = _github_api(monkeypatch, **api)          # after _no_platform_credentials: the brokered read's httpx
    svc = _svc(tf, tmp_path)
    _runner, broker = _register(tf, svc, tmp_path)
    return svc, broker, seen


def test_per_workload_github_read_works_without_pygithub(tf, monkeypatch, tmp_path, caplog):
    """SAT-50 (live 11-02, tf-applier-vfb8f: "PyGithub is not installed"): the brokered GitHub read needs only what
    this image installs. One tree call and one call per blob, all to api.github.com with the brokered token only."""
    svc, broker, seen = _rest_ready(tf, monkeypatch, tmp_path)
    with caplog.at_level(logging.INFO):
        files = svc._fetch_repo_files(PRODUCT, github_repo="acme/Claims", branch="release")
    assert files == TREE
    assert broker.calls == [("repo_token", SESSION_KEY)]
    accept = "application/vnd.github.v3+json"
    assert seen == [(f"{API}/git/trees/release?recursive=1", f"Bearer {REPO_TOKEN}", accept),
                    (f"{API}/git/blobs/sha-main-tf", f"Bearer {REPO_TOKEN}", accept),
                    (f"{API}/git/blobs/sha-api-py", f"Bearer {REPO_TOKEN}", accept)]
    for secret in [REPO_TOKEN, SESSION_KEY, *POISON.values()]:
        assert secret not in caplog.text


def test_per_workload_github_rest_read_quotes_the_branch(tf, monkeypatch, tmp_path):
    branch = "feat/a#b+c"                     # a valid git branch name whose characters a URL must escape
    svc, _broker, seen = _rest_ready(tf, monkeypatch, tmp_path, answers={
        f"{API}/git/trees/feat/a%23b%2Bc?recursive=1": (200, _tree_body())})
    assert svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch=branch) == TREE
    assert seen[0][0] == f"{API}/git/trees/feat/a%23b%2Bc?recursive=1"


@pytest.mark.parametrize("branch", ["release/v1.2", "main", "feature/SAT-50_fix", "v1.2.3", "a@b", "x/y.locked"])
def test_per_workload_well_formed_branch_names_are_read(tf, monkeypatch, tmp_path, branch):
    """RT F2 negative: a well-formed branch name is read exactly as before (one tree call naming it)."""
    import urllib.parse
    tree_url = f"{API}/git/trees/{urllib.parse.quote(branch, safe='/')}?recursive=1"
    svc, _broker, seen = _rest_ready(tf, monkeypatch, tmp_path, answers={tree_url: (200, _tree_body())})
    assert svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch=branch) == TREE
    assert seen[0][0] == tree_url


@pytest.mark.parametrize("provider", ["GITHUB", "SERVERLESS_GIT"])
def test_per_workload_malformed_branch_is_refused_before_any_token_or_call(tf, monkeypatch, tmp_path, provider):
    """RT F2: a branch that is not a well-formed git ref name (here one that would address another repository's API
    path) is RUNNER_TARGET_MISMATCH before a token is minted or any URL is called."""
    _per_workload(monkeypatch)
    _no_platform_credentials(tf, monkeypatch)
    _without_pygithub(monkeypatch)
    seen = _github_api(monkeypatch)
    monkeypatch.setattr(tf.runner_creds, "job_id_token", lambda *a, **k: pytest.fail("ID token minted"))
    monkeypatch.setenv("GIT_SERVER_URL", "https://castor-git-server-x.a.run.app/")
    seen_sg = _sg_requests(tf, monkeypatch, NS(status_code=200, json=lambda: {"files": dict(TREE)}, text="",
                                               headers={}))
    svc = _svc(tf, tmp_path)
    pinned = PINNED_GH if provider == "GITHUB" else PINNED_SG
    _runner, broker = _register(tf, svc, tmp_path, repository=pinned)
    repo = pinned["full_name"]
    with pytest.raises(tf.RunnerIdentityRefused) as ei:
        svc._fetch_repo_files(PRODUCT, github_repo=repo, branch="../../Other/repo/git/trees/main")
    assert ei.value.error_class == "RUNNER_TARGET_MISMATCH"
    assert seen == [] and seen_sg == [] and broker.calls == []


def test_repo_read_max_files_is_the_github_providers_bound(tf):
    import inspect
    ghp = _provider_module(tf, "github_provider")
    default = inspect.signature(ghp.GitHubProvider.fetch_file_tree).parameters["max_files"].default
    assert tf.REPO_READ_MAX_FILES == default == 2500


@pytest.mark.parametrize("extra", [0, 1])
def test_per_workload_github_read_is_bounded_to_max_files(tf, monkeypatch, tmp_path, extra):
    """RT F1: more than REPO_READ_MAX_FILES blobs is a typed truncated tree with exactly one HTTP call (the tree);
    exactly REPO_READ_MAX_FILES is read in full."""
    import base64
    n = tf.REPO_READ_MAX_FILES + extra
    body = {"truncated": False, "tree": [{"path": f"f{i}.txt", "type": "blob", "sha": f"s{i}"} for i in range(n)]}
    answers = {f"{API}/git/trees/main?recursive=1": (200, body)}
    answers.update({f"{API}/git/blobs/s{i}": (200, {"content": base64.b64encode(b"x").decode()}) for i in range(n)})
    svc, _broker, seen = _rest_ready(tf, monkeypatch, tmp_path, answers=answers)
    if extra:
        with pytest.raises(tf.IncompleteRepoTreeError) as ei:
            svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch="main")
        assert ei.value.tree_status == {"complete": False, "truncated": True,
                                        "error": f"the tree has {n} files, more than {tf.REPO_READ_MAX_FILES}"}
        assert len(seen) == 1
    else:
        files = svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch="main")
        assert len(files) == n and len(seen) == n + 1


@pytest.mark.parametrize("branch,ok", [
    ("main", True), ("release/v1.2", True), ("a@b", True), ("x/y.locked", True), ("feat/a#b+c", True),
    ("", False), (None, False), (7, False), ("@", False), ("-main", False), ("a..b", False),
    ("../../Other/repo/git/trees/main", False), ("/main", False), ("main/", False), ("a//b", False),
    (".hidden", False), ("a/.b", False), ("a.lock", False), ("a/b.lock/c", False), ("main.", False),
    ("a@{1}", False), ("a b", False), ("a~1", False), ("a^", False), ("a:b", False), ("a?", False), ("a*", False),
    ("a[b", False), ("a\\b", False), ("a\tb", False), ("a\x7fb", False), ("a\nb", False),
])
def test_is_git_branch_name(tf, branch, ok):
    assert tf.runner_creds.is_git_branch_name(branch) is ok
    if ok:
        tf.runner_creds.check_branch_name(branch)
    else:
        with pytest.raises(tf.runner_creds.ri.RunnerIdentityError) as ei:
            tf.runner_creds.check_branch_name(branch)
        assert ei.value.code == "RUNNER_TARGET_MISMATCH"


@pytest.mark.parametrize("case", ["tree_404", "tree_401", "tree_403_rate_limit", "truncated", "blob_404", "blob_502",
                                  "transport", "entry_without_sha"])
def test_per_workload_github_rest_read_is_complete_or_typed(tf, monkeypatch, tmp_path, case):
    """Never a partial tree: every failure is the deploy's typed REPO_TREE_INCOMPLETE, with no fallback read (no
    raw.githubusercontent.com, no other token), no retry (a 403 without GitHub's rate-limit headers included; the
    bounded rate-limit retry is tested below) and nothing read after a refused tree."""
    tree_url = f"{API}/git/trees/main?recursive=1"
    answers, raise_on = {tree_url: (200, _tree_body())}, None
    if case == "tree_404":
        answers[tree_url] = (404, {"message": "Not Found"})
    elif case == "tree_403_rate_limit":
        answers[tree_url] = (403, {"message": "API rate limit exceeded"})
    elif case == "tree_401":
        answers[tree_url] = (401, {"message": "Bad credentials"})
    elif case == "truncated":
        answers[tree_url] = (200, _tree_body(truncated=True))
    elif case == "blob_404":
        answers[f"{API}/git/blobs/sha-api-py"] = (404, {"message": "Not Found"})
    elif case == "blob_502":
        answers[f"{API}/git/blobs/sha-main-tf"] = (502, {})
    elif case == "transport":
        raise_on = f"{API}/git/blobs/sha-api-py"
    elif case == "entry_without_sha":
        body = _tree_body()
        del body["tree"][3]["sha"]
        answers[tree_url] = (200, body)
    svc, _broker, seen = _rest_ready(tf, monkeypatch, tmp_path, answers=answers, raise_on=raise_on)
    with pytest.raises(tf.IncompleteRepoTreeError) as ei:
        svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch="main")
    status = ei.value.tree_status
    assert status["complete"] is False
    expected = {"tree_404": "GitHub tree read answered HTTP 404", "tree_401": "GitHub tree read answered HTTP 401",
                "tree_403_rate_limit": "GitHub tree read answered HTTP 403 (no rate-limit headers)", "truncated": None, "blob_404": "blob of 'apps/api/main.py' answered HTTP 404",
                "blob_502": "blob of 'infra/workload/main.tf' answered HTTP 502",
                "transport": "ConnectionError: connection reset (fake)",
                "entry_without_sha": "GitHub tree entry without a path or SHA"}[case]
    assert status["error"] == expected and status["truncated"] is (case == "truncated")
    assert all(url.startswith(f"{API}/git/") for url, _auth, _acc in seen)         # no raw-content fallback
    assert {auth for _url, auth, _acc in seen} == {f"Bearer {REPO_TOKEN}"}
    if case in ("tree_404", "tree_401", "tree_403_rate_limit", "truncated"):
        assert len(seen) == 1                                       # no retry, no blob read after the tree
    assert REPO_TOKEN not in str(status) and REPO_TOKEN not in str(ei.value)


NOW = 1_800_000_000   # the fake clock of the bounded rate-limit retry (epoch seconds)


def _sleeps(tf, monkeypatch):
    """Replaces the read's sleep and clock seams; returns the list of requested waits (nothing really sleeps)."""
    slept = []
    monkeypatch.setattr(tf, "_repo_read_sleep", slept.append)
    monkeypatch.setattr(tf, "_repo_read_clock", lambda: NOW)
    return slept


@pytest.mark.parametrize("where,status,headers,note,waits", [
    ("tree", 403, {"Retry-After": "60"}, "HTTP 403 (retry-after: 60) after 3 rate-limit retries", [60, 60, 60]),
    ("tree", 403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1"},
     "HTTP 403 (x-ratelimit-remaining: 0) after 3 rate-limit retries", [1, 1, 1]),           # reset passed: 1 s
    ("tree", 429, {"retry-after": "5", "x-ratelimit-remaining": "0"},
     "HTTP 429 (retry-after: 5, x-ratelimit-remaining: 0) after 3 rate-limit retries", [5, 5, 5]),
    ("tree", 403, {"X-RateLimit-Remaining": "12"}, "HTTP 403 (no rate-limit headers)", []),   # a permission refusal
    ("blob", 403, {"Retry-After": "30"}, "HTTP 403 (retry-after: 30) after 3 rate-limit retries", [30, 30, 30]),
    ("blob", 404, {"Retry-After": "30"}, "HTTP 404", []),                                     # only on 403 / 429
])
def test_per_workload_github_rest_refusal_names_rate_limit_headers(tf, monkeypatch, tmp_path, where, status,
                                                                   headers, note, waits):
    """RT M1: a 403/429 names the rate-limit headers GitHub sent (presence/value of `retry-after` and
    `x-ratelimit-remaining: 0`, never the body), so an operator can tell a rate limit from a permission refusal.
    SAT-50 follow-up: a lasting rate limit is retried at most 3 times per call, then typed."""
    slept = _sleeps(tf, monkeypatch)
    url = f"{API}/git/trees/main?recursive=1" if where == "tree" else f"{API}/git/blobs/sha-main-tf"
    answers = {f"{API}/git/trees/main?recursive=1": (200, _tree_body())}
    answers[url] = (status, {"message": "API rate limit exceeded for installation"}, headers)
    svc, _broker, seen = _rest_ready(tf, monkeypatch, tmp_path, answers=answers)
    with pytest.raises(tf.IncompleteRepoTreeError) as ei:
        svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch="main")
    prefix = "GitHub tree read answered " if where == "tree" else "blob of 'infra/workload/main.tf' answered "
    assert ei.value.tree_status["error"] == prefix + note
    assert "API rate limit exceeded" not in str(ei.value)           # the body is never quoted or matched
    assert slept == waits
    assert len(seen) == (1 if where == "tree" else 2) + len(waits)  # one call, plus one per retry


def test_bounded_rate_limit_retry_bounds_are_pinned(tf):
    assert (tf.REPO_READ_RATE_LIMIT_RETRIES, tf.REPO_READ_RATE_LIMIT_MAX_WAIT_S,
            tf.REPO_READ_RATE_LIMIT_TOTAL_WAIT_S) == (3, 60, 180)


@pytest.mark.parametrize("where", ["tree", "blob"])
def test_a_short_rate_limit_is_waited_out_and_the_read_completes(tf, monkeypatch, tmp_path, caplog, where):
    """GitHub asks for a 2 s wait once: the read waits exactly that, repeats the same call and returns the same files
    as an unlimited read, with the brokered token only; the warning names no token."""
    slept = _sleeps(tf, monkeypatch)
    tree_url = f"{API}/git/trees/main?recursive=1"
    url = tree_url if where == "tree" else f"{API}/git/blobs/sha-api-py"
    ok = (200, _tree_body()) if where == "tree" else None
    answers = {tree_url: (200, _tree_body())}
    if where == "blob":
        import base64
        ok = (200, {"content": base64.b64encode(BLOBS["sha-api-py"].encode()).decode(), "encoding": "base64"})
    answers[url] = [(403, {"message": "secondary rate limit"}, {"Retry-After": "2"}), ok]
    svc, _broker, seen = _rest_ready(tf, monkeypatch, tmp_path, answers=answers)
    with caplog.at_level(logging.WARNING):
        files = svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch="main")
    assert files == {"infra/workload/main.tf": BLOBS["sha-main-tf"], "apps/api/main.py": BLOBS["sha-api-py"]}
    assert slept == [2]
    assert [u for u, _a, _c in seen].count(url) == 2 and len(seen) == 4
    assert {auth for _url, auth, _acc in seen} == {f"Bearer {REPO_TOKEN}"}
    assert "retry 1 of 3 in 2 s" in caplog.text and REPO_TOKEN not in caplog.text


@pytest.mark.parametrize("headers,note", [
    ({"Retry-After": "61"}, "HTTP 403 (retry-after: 61) (not retried: GitHub asks for a 61 s wait, more than 60 s)"),
    ({"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(NOW + 3600)},
     "HTTP 403 (x-ratelimit-remaining: 0) (not retried: GitHub asks for a 3601 s wait, more than 60 s)"),
])
def test_a_long_rate_limit_is_typed_without_waiting(tf, monkeypatch, tmp_path, headers, note):
    slept = _sleeps(tf, monkeypatch)
    tree_url = f"{API}/git/trees/main?recursive=1"
    svc, _broker, seen = _rest_ready(tf, monkeypatch, tmp_path, answers={tree_url: (403, {}, headers)})
    with pytest.raises(tf.IncompleteRepoTreeError) as ei:
        svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch="main")
    assert ei.value.tree_status["error"] == "GitHub tree read answered " + note
    assert slept == [] and len(seen) == 1


def test_the_whole_read_waits_at_most_the_total_budget(tf, monkeypatch, tmp_path):
    """Waits add up across calls: 2 x 60 s on the tree, 60 s on the first blob (180 s, the budget), then a further
    rate limit is typed without waiting."""
    slept = _sleeps(tf, monkeypatch)
    limited = (403, {}, {"Retry-After": "60"})
    tree_url, blob_url = f"{API}/git/trees/main?recursive=1", f"{API}/git/blobs/sha-main-tf"
    answers = {tree_url: [limited, limited, (200, _tree_body())], blob_url: [limited, limited, (200, {})]}
    svc, _broker, seen = _rest_ready(tf, monkeypatch, tmp_path, answers=answers)
    with pytest.raises(tf.IncompleteRepoTreeError) as ei:
        svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch="main")
    assert ei.value.tree_status["error"] == ("blob of 'infra/workload/main.tf' answered HTTP 403 (retry-after: 60) "
                                             "(not retried: this read already waited 180 s of its 180 s)")
    assert slept == [60, 60, 60] and len(seen) == 5


@pytest.mark.parametrize("value", ["Wed, 21 Oct 2026 07:28:00 GMT", "-1", "1.5", "", "６"])
def test_a_retry_after_that_is_not_plain_seconds_is_not_retried(tf, monkeypatch, tmp_path, value):
    slept = _sleeps(tf, monkeypatch)
    tree_url = f"{API}/git/trees/main?recursive=1"
    svc, _broker, seen = _rest_ready(tf, monkeypatch, tmp_path,
                                     answers={tree_url: (429, {}, {"Retry-After": value})})
    with pytest.raises(tf.IncompleteRepoTreeError) as ei:
        svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch="main")
    assert ei.value.tree_status["error"].startswith("GitHub tree read answered HTTP 429 (retry-after: ")
    assert "rate-limit retries" not in ei.value.tree_status["error"]
    assert slept == [] and len(seen) == 1


@pytest.mark.parametrize("status,headers,wait", [
    (403, {"Retry-After": "7"}, 7),
    (429, {"retry-after": " 0 "}, 0),
    (403, {"Retry-After": "7", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(NOW + 30)}, 7),  # Retry-After first
    (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(NOW + 30)}, 31),
    (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(NOW - 30)}, 1),
    (403, {"X-RateLimit-Remaining": "0"}, None),                       # no reset: unknown wait
    (403, {"X-RateLimit-Remaining": "1", "X-RateLimit-Reset": str(NOW + 30)}, None),
    (403, {}, None),                                                   # a permission refusal
    (404, {"Retry-After": "7"}, None),
    (500, {"Retry-After": "7"}, None),                                 # 5xx: not retried (parity with Shared)
    (200, {"Retry-After": "7"}, None),
])
def test_rate_limit_wait_reads_headers_only(tf, status, headers, wait):
    res = NS(status_code=status, headers=headers, text="API rate limit exceeded", json=lambda: {})
    assert tf.TerraformService._rate_limit_wait(res, NOW) == wait


def test_per_workload_github_token_env_absent_logs_nothing(tf, monkeypatch, tmp_path, caplog):
    _per_workload(monkeypatch, poison=False)
    _no_platform_credentials(tf, monkeypatch)
    svc = _svc(tf, tmp_path)
    _register(tf, svc, tmp_path)
    _github_reader(tf, monkeypatch)
    with caplog.at_level(logging.INFO):
        assert svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch="main") == TREE
    assert "RUNNER_ENV_IGNORED" not in caplog.text


def test_per_workload_github_read_never_reads_the_github_token_env(tf, monkeypatch, tmp_path):
    """GITHUB_TOKEN is only tested for presence (its name is logged); its value is never read."""
    _per_workload(monkeypatch)
    _no_platform_credentials(tf, monkeypatch)
    svc = _svc(tf, tmp_path)
    _register(tf, svc, tmp_path)
    _github_reader(tf, monkeypatch)
    real_getenv = os.getenv

    def _getenv(name, *a):
        assert name not in POISON, f"{name} was read"
        return real_getenv(name, *a)

    monkeypatch.setattr(tf.os, "getenv", _getenv)
    assert svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch="main") == TREE


@pytest.mark.parametrize("case,code", [
    ("no_runner", "RUNNER_IDENTITY_NOT_REGISTERED"),
    ("other_product", "RUNNER_IDENTITY_NOT_REGISTERED"),
    ("no_pin", "RUNNER_REPOSITORY_NOT_PINNED"),
    ("unknown_provider", "RUNNER_REPOSITORY_NOT_PINNED"),
    ("other_repository", "RUNNER_TARGET_MISMATCH"),
    ("broker_refuses", "RUNNER_REPO_TOKEN_UNSUPPORTED"),
    ("broker_down", "RUNNER_BROKER_UNAVAILABLE"),
    ("token_for_other_repo", "RUNNER_TARGET_MISMATCH"),
    ("token_with_write", "RUNNER_TARGET_MISMATCH"),
    ("token_without_permissions", "RUNNER_TARGET_MISMATCH"),
])
def test_per_workload_refusals_are_typed_and_read_nothing(tf, monkeypatch, tmp_path, case, code):
    _per_workload(monkeypatch)
    _no_platform_credentials(tf, monkeypatch)
    svc = _svc(tf, tmp_path)
    rc = tf.runner_creds
    broker = FakeBroker(rc)
    repo = "Acme/claims"
    if case == "other_product":
        _register(tf, svc, tmp_path, product="victim", broker=broker)
    elif case == "no_pin":
        _register(tf, svc, tmp_path, repository=None, broker=broker)
    elif case == "unknown_provider":
        _register(tf, svc, tmp_path, repository=dict(PINNED_GH, provider="GITLAB"), broker=broker)
    elif case != "no_runner":
        _register(tf, svc, tmp_path, broker=broker)
    if case == "other_repository":
        repo = "Acme/victim"
    elif case == "broker_refuses":
        broker.refuse = "RUNNER_REPO_TOKEN_UNSUPPORTED"
    elif case == "broker_down":
        broker.refuse = "RUNNER_BROKER_UNAVAILABLE"
    elif case == "token_for_other_repo":
        broker.answer = dict(broker.answer, repository="Acme/victim")
    elif case == "token_with_write":
        broker.answer = dict(broker.answer, permissions={"contents": "read", "pull_requests": "write"})
    elif case == "token_without_permissions":
        broker.answer = {"repository": "Acme/claims"}
    built, _prov = _github_reader(tf, monkeypatch)
    with pytest.raises(tf.RunnerIdentityRefused) as ei:
        svc._fetch_repo_files(PRODUCT, github_repo=repo, branch="main")
    assert ei.value.error_class == code
    assert built == []                                                    # no provider, no repository call
    if case in ("no_runner", "other_product", "no_pin", "unknown_provider", "other_repository"):
        assert broker.calls == []                                         # refused before any mint
    assert REPO_TOKEN not in str(ei.value) and SESSION_KEY not in str(ei.value)


def test_a_second_brokered_runner_in_one_process_is_refused_before_any_read(tf, monkeypatch, tmp_path):
    """Phase 5a L3 (one brokered runner per process) now refuses the second registration itself, before the
    repository read (Phase 4) could see two runners; nothing is minted or read."""
    _per_workload(monkeypatch)
    _no_platform_credentials(tf, monkeypatch)
    svc = _svc(tf, tmp_path)
    broker = FakeBroker(tf.runner_creds)
    _register(tf, svc, tmp_path, broker=broker, key="a")
    with pytest.raises(tf.runner_creds.ri.RunnerIdentityError) as ei:
        _register(tf, svc, tmp_path, broker=broker, key="b")
    assert ei.value.code == "RUNNER_NOT_SINGLE_TENANT"
    assert broker.calls == []


@pytest.mark.parametrize("error", ["incomplete", "provider_error"])
def test_per_workload_read_failure_is_typed_and_never_falls_back(tf, monkeypatch, tmp_path, error):
    _per_workload(monkeypatch)
    _no_platform_credentials(tf, monkeypatch)
    svc = _svc(tf, tmp_path)
    _register(tf, svc, tmp_path)
    exc = (tf.IncompleteRepoTreeError("Acme/claims", "main", {"complete": False, "truncated": True, "error": None})
           if error == "incomplete" else RuntimeError("401 Bad credentials (fake)"))
    _github_reader(tf, monkeypatch, FakeProvider(error=exc))
    with pytest.raises(tf.IncompleteRepoTreeError) as ei:
        svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch="main")
    if error == "provider_error":
        assert ei.value.tree_status == {"complete": False, "truncated": False,
                                        "error": "RuntimeError: 401 Bad credentials (fake)"}
    assert REPO_TOKEN not in str(ei.value.tree_status)


def test_unknown_mode_refuses_the_read(tf, monkeypatch, tmp_path):
    monkeypatch.setenv(MODE, "per_workload")
    monkeypatch.setattr(tf, "VCSProviderFactory", FakeFactory(FakeProvider()))
    with pytest.raises(tf.RunnerIdentityRefused) as ei:
        _svc(tf, tmp_path)._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch="main")
    assert ei.value.error_class == "RUNNER_IDENTITY_MODE_INVALID"


def test_the_brokered_reader_is_used_only_to_read_the_tree():
    """W6bd F1's rule for the brokered read too: the provider it builds is bound to one name, used only for
    `fetch_file_tree`, and the function never touches VCSProviderFactory."""
    import ast
    src = open(os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "terraform", "service.py"),
               encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "_fetch_repo_files_brokered")
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert "VCSProviderFactory" not in names
    parents = {id(c): p for p in ast.walk(fn) for c in ast.iter_child_nodes(p)}
    uses = [parents[id(n)] for n in ast.walk(fn) if isinstance(n, ast.Name) and n.id == "reader"
            and isinstance(n.ctx, ast.Load)]
    # RT14-21: besides the tree, the reader is handed to add_serverless_git_binaries (read-only archive read, guarded
    # in tests/test_rt14_tf_destructive_fake_success.py)
    assert uses and all((isinstance(p, ast.Attribute) and p.attr == "fetch_file_tree")
                        or (isinstance(p, ast.Call) and isinstance(p.func, ast.Name)
                            and p.func.id == "add_serverless_git_binaries") for p in uses)


# ------------------------------------------------------------------------------------------------ Serverless Git
def _sg_archive(files):
    """RT14-21: the git server's `/archive/<branch>` answer (.tar.gz of the branch, X-Commit-Sha) for `files`."""
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, text in files.items():
            data = text if isinstance(text, bytes) else text.encode("utf-8")
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return NS(status_code=200, content=buf.getvalue(), text="", headers={"X-Commit-Sha": "a" * 40})


def _sg_requests(tf, monkeypatch, answer, archive=None):
    sgp = _provider_module(tf, "serverless_git_provider")
    sent = []

    def _get(url, headers=None, timeout=None, allow_redirects=None, **kw):
        sent.append((url, dict(headers or {})))
        if "/archive/" in url:
            return archive if archive is not None else _sg_archive(TREE)
        return answer

    monkeypatch.setattr(sgp, "requests", NS(get=_get))
    return sent


def test_per_workload_serverless_git_read_uses_the_jobs_own_id_token(tf, monkeypatch, tmp_path, caplog):
    _per_workload(monkeypatch)
    _no_platform_credentials(tf, monkeypatch)
    monkeypatch.setenv("GIT_SERVER_URL", "https://castor-git-server-x.a.run.app/")
    monkeypatch.setenv("CASTOR_GIT_SERVER_URL", "https://evil.example")          # never used
    sent = _sg_requests(tf, monkeypatch, NS(status_code=200, json=lambda: {"files": dict(TREE), "truncated": False},
                                            text="", headers={}))
    audiences = []
    monkeypatch.setattr(tf.runner_creds, "job_id_token", lambda aud: audiences.append(aud) or ID_TOKEN)
    svc = _svc(tf, tmp_path)
    _runner, broker = _register(tf, svc, tmp_path, repository=PINNED_SG)
    with caplog.at_level(logging.INFO):
        assert svc._fetch_repo_files(PRODUCT, github_repo="serverless-git/claims", branch="main") == TREE
    assert broker.calls == []                                             # no GitHub token for Serverless Git
    assert audiences == ["https://castor-git-server-x.a.run.app"]
    hdrs = {"Content-Type": "application/json", "Accept": "application/json",
            "Authorization": f"Bearer {ID_TOKEN}", "X-Serverless-Authorization": f"Bearer {ID_TOKEN}"}
    assert sent == [("https://castor-git-server-x.a.run.app/api/v1/repos/claims/tree/main?max_files=2500", hdrs),
                    # RT14-21: the same branch's archive, read with the same job ID token, for the binary files
                    ("https://castor-git-server-x.a.run.app/api/v1/repos/claims/archive/main", hdrs)]
    assert ID_TOKEN not in caplog.text and "poison" not in caplog.text


@pytest.mark.parametrize("url", [None, "", "http://castor-git-server-x.a.run.app", "https://", "castor-git-server"])
def test_per_workload_serverless_git_without_an_https_server_url_is_not_ready(tf, monkeypatch, tmp_path, url):
    _per_workload(monkeypatch)
    _no_platform_credentials(tf, monkeypatch)
    if url is None:
        monkeypatch.delenv("GIT_SERVER_URL", raising=False)
    else:
        monkeypatch.setenv("GIT_SERVER_URL", url)
    sent = _sg_requests(tf, monkeypatch, NS(status_code=200, json=lambda: {"files": {}}, text="", headers={}))
    monkeypatch.setattr(tf.runner_creds, "job_id_token", lambda aud: pytest.fail("ID token fetched"))
    svc = _svc(tf, tmp_path)
    _register(tf, svc, tmp_path, repository=PINNED_SG)
    with pytest.raises(tf.RunnerIdentityRefused) as ei:
        svc._fetch_repo_files(PRODUCT, github_repo="serverless-git/claims", branch="main")
    assert ei.value.error_class == "RUNNER_IDENTITY_NOT_READY" and sent == []


def test_per_workload_serverless_git_without_an_id_token_is_typed(tf, monkeypatch, tmp_path):
    _per_workload(monkeypatch)
    monkeypatch.setenv("GIT_SERVER_URL", "https://castor-git-server-x.a.run.app")
    sent = _sg_requests(tf, monkeypatch, NS(status_code=200, json=lambda: {"files": {}}, text="", headers={}))

    def _boom(aud):
        raise OSError("metadata unreachable (test)")

    monkeypatch.setattr(tf.runner_creds, "job_id_token", _boom)
    svc = _svc(tf, tmp_path)
    _register(tf, svc, tmp_path, repository=PINNED_SG)
    with pytest.raises(tf.IncompleteRepoTreeError) as ei:
        svc._fetch_repo_files(PRODUCT, github_repo="serverless-git/claims", branch="main")
    assert ei.value.tree_status["error"] == "job ID token unavailable (OSError)" and sent == []


def test_per_workload_github_untyped_token_failure_names_the_repository_token(tf, monkeypatch, tmp_path):
    """SAT-30 RT L2: a non-typed failure while getting the GitHub token (e.g. a malformed broker answer) is labelled
    as the repository token, never as the Serverless job ID token."""
    _per_workload(monkeypatch)
    _no_platform_credentials(tf, monkeypatch)
    svc = _svc(tf, tmp_path)
    _runner, broker = _register(tf, svc, tmp_path)
    monkeypatch.setattr(broker, "repo_token", lambda key: (REPO_TOKEN, ["not", "a", "mapping"]))
    built, _prov = _github_reader(tf, monkeypatch)
    with pytest.raises(tf.IncompleteRepoTreeError) as ei:
        svc._fetch_repo_files(PRODUCT, github_repo="Acme/claims", branch="main")
    assert ei.value.tree_status["error"] == "repository token unavailable (AttributeError)"
    assert built == [] and REPO_TOKEN not in str(ei.value.tree_status)


def test_per_workload_serverless_git_refused_by_the_git_server_is_typed(tf, monkeypatch, tmp_path):
    _per_workload(monkeypatch)
    monkeypatch.setenv("GIT_SERVER_URL", "https://castor-git-server-x.a.run.app")
    _sg_requests(tf, monkeypatch, NS(status_code=403, text="read-only caller", headers={}))
    monkeypatch.setattr(tf.runner_creds, "job_id_token", lambda aud: ID_TOKEN)
    svc = _svc(tf, tmp_path)
    _register(tf, svc, tmp_path, repository=PINNED_SG)
    with pytest.raises(tf.IncompleteRepoTreeError) as ei:
        svc._fetch_repo_files(PRODUCT, github_repo="serverless-git/claims", branch="main")
    assert ei.value.tree_status["error"].startswith("ServerlessGitAuthError")


def test_per_workload_serverless_git_name_is_exact(tf, monkeypatch, tmp_path):
    _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path)
    _register(tf, svc, tmp_path, repository=PINNED_SG)
    _no_factory(tf, monkeypatch)
    with pytest.raises(tf.RunnerIdentityRefused) as ei:
        svc._fetch_repo_files(PRODUCT, github_repo="serverless-git/other", branch="main")
    assert ei.value.error_class == "RUNNER_TARGET_MISMATCH"


# ------------------------------------------------------------------------------------------------ the deploy
def test_deploy_returns_the_typed_refusal_before_anything_is_built(tf, monkeypatch, tmp_path):
    svc = _svc(tf, tmp_path)

    def _refuse(*_a, **_k):
        raise tf.RunnerIdentityRefused("RUNNER_TARGET_MISMATCH", "test refusal")

    monkeypatch.setattr(svc, "_fetch_repo_files", _refuse)
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **k: pytest.fail("tofu ran"))
    monkeypatch.setattr(svc, "_build_and_push_container", lambda *a, **k: pytest.fail("built"))
    monkeypatch.setattr(svc, "prepare_workspace", lambda *a, **k: pytest.fail("workspace prepared"))
    res = svc.deploy_workload(product_id="app", trace_id="t-sat30", target_project_id="p-1", branch="main",
                              iac_engine="OPENTOFU")
    assert res["status"] == "FAILED" and res["error_class"] == "RUNNER_TARGET_MISMATCH"
    assert res["operator_required"] is True and res["product_id"] == "app"


# ------------------------------------------------------------------------------------------------ runner_credentials
class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


def _client(rc, status, body, posted):
    def post(url, **kw):
        posted.append((url, kw.get("json")))
        return _Resp(status, body)

    return rc.BrokerClient("https://vending.example.run.app", id_token=lambda aud: "job-id-token", post=post,
                           sleep=lambda s: None)


def test_broker_client_repo_token(tf):
    rc, posted = tf.runner_creds, []
    body = {"token": REPO_TOKEN, "expires_at": "2026-11-01T01:00:00Z", "repository": "Acme/claims",
            "permissions": {"contents": "read"}}
    token, meta = _client(rc, 200, body, posted).repo_token(SESSION_KEY)
    assert token == REPO_TOKEN and "token" not in meta and meta["repository"] == "Acme/claims"
    assert posted == [("https://vending.example.run.app/runner/repo-token", {"session_key": SESSION_KEY})]


@pytest.mark.parametrize("status,body,code", [
    (403, {"detail": {"code": "RUNNER_REPO_TOKEN_UNSUPPORTED"}}, "RUNNER_REPO_TOKEN_UNSUPPORTED"),
    (409, {"detail": {"code": "RUNNER_REPOSITORY_NOT_PINNED"}}, "RUNNER_REPOSITORY_NOT_PINNED"),
    (503, {"detail": {"code": "RUNNER_REPO_TOKEN_UNAVAILABLE"}}, "RUNNER_BROKER_UNAVAILABLE"),
    (200, {"repository": "Acme/claims"}, "RUNNER_BROKER_UNAVAILABLE"),
    (200, {"token": "", "repository": "Acme/claims"}, "RUNNER_BROKER_UNAVAILABLE"),
])
def test_broker_client_repo_token_refusals_are_typed(tf, status, body, code):
    rc = tf.runner_creds
    with pytest.raises(rc.ri.RunnerIdentityError) as ei:
        _client(rc, status, body, []).repo_token(SESSION_KEY)
    assert ei.value.code == code and SESSION_KEY not in str(ei.value) and SESSION_KEY not in ei.value.detail


def test_brokered_credentials_repository_token_keeps_the_session_key_private(tf):
    rc = tf.runner_creds
    broker = FakeBroker(rc)
    creds = rc.BrokeredCredentials(broker, SESSION_KEY, project_id=CHILD, deployer_email="d@x")
    assert creds.repository_token()[0] == REPO_TOKEN and broker.calls == [("repo_token", SESSION_KEY)]
    assert SESSION_KEY not in repr(creds) and "session_key" not in vars(creds)


@pytest.mark.parametrize("answer,ok", [
    ({"repository": "Acme/claims", "permissions": {"contents": "read"}}, True),
    ({"repository": "acme/CLAIMS", "permissions": {"contents": "read"}}, True),
    ({"repository": "Acme/victim", "permissions": {"contents": "read"}}, False),
    ({"repository": "Acme/claims", "permissions": {"contents": "write"}}, False),
    ({"repository": "Acme/claims", "permissions": {"contents": "read", "metadata": "read"}}, False),
    ({"repository": "Acme/claims"}, False),
    ({"permissions": {"contents": "read"}}, False),
])
def test_check_repo_token_answer(tf, answer, ok):
    rc = tf.runner_creds
    if ok:
        rc.check_repo_token_answer(answer, "Acme/claims")
    else:
        with pytest.raises(rc.ri.RunnerIdentityError) as ei:
            rc.check_repo_token_answer(answer, "Acme/claims")
        assert ei.value.code == "RUNNER_TARGET_MISMATCH"


# ------------------------------------------------------------------------------------------------ tf-applier
def test_brokered_run_registers_the_product_and_the_signed_repository(monkeypatch, base, sent_callbacks, ri):
    from test_fd7l_2a_runner_service import PRODUCT as P2A, _brokered

    _applier, ok, deployed, _broker, _owner = _brokered(monkeypatch, base, ri)
    assert ok is True
    runner = deployed["runner"]
    assert runner.product_id == P2A
    assert runner.repository == {"provider": "GITHUB", "full_name": "Acme/claims", "id": "42"}   # from provenance


@pytest.fixture
def ri():
    from shared import runner_identity
    return runner_identity



# ------------------------------------------------------------------------------------------------ git server
@pytest.fixture
def _no_network(monkeypatch):
    from fd4g_support import real_modules

    real_modules(monkeypatch)

    def _blocked(self, addr):
        raise OSError(f"network blocked in SAT-30 test: {addr}")

    monkeypatch.setattr(socket.socket, "connect", _blocked)


READER = "sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com"
STRANGER = "sa-someone-else@mock-stackvend-project.iam.gserviceaccount.com"


def _gs(monkeypatch, readonly=READER, invokers=None):
    from fd4k_support import CALLER, load_git_server, make_authenticator

    env_extra = {} if readonly is None else {"GIT_SERVER_READONLY_INVOKERS": readonly}
    auth = make_authenticator(invokers=invokers or (CALLER,), env_extra=env_extra)
    mod, client, outer = load_git_server(monkeypatch, authenticator=auth)
    assert client.post("/api/v1/repos", json={"product_id": "app"}).status_code == 201
    return mod, client, outer


def _as(email):
    from fd4k_support import make_token
    return {"Authorization": f"Bearer {make_token(email=email)}"}


READS = [
    ("get", "/api/v1/capabilities", {}),
    ("get", "/api/v1/repos/app/metadata", {}),
    ("get", "/api/v1/repos/app/tree/main", {}),
    ("get", "/api/v1/repos/app/blob/main/README.md", {}),
    ("get", "/api/v1/repos/app/refs/heads/main", {}),
    ("get", "/api/v1/repos/app/archive/main", {}),
]
WRITES_AND_OTHERS = [
    ("post", "/api/v1/repos", {"json": {"product_id": "other"}}),
    ("post", "/api/v1/repos/app/branches", {"json": {"branch_name": "feature/x"}}),
    ("post", "/api/v1/repos/app/commits", {"json": {"branch": "main", "files": {"a.txt": "x"}}}),
    ("post", "/api/v1/repos/app/commits-with-deletions", {"json": {"branch": "main", "files": {"a.txt": "x"}}}),
    ("post", "/api/v1/repos/app/merge", {"json": {"source_branch": "feature/x"}}),
    ("get", "/git/app.git/info/refs?service=git-upload-pack", {}),
    ("get", "/git/app.git/info/refs?service=git-receive-pack", {}),
    ("post", "/git/app.git/git-upload-pack", {"content": b""}),
    ("post", "/git/app.git/git-receive-pack", {"content": b""}),
    ("get", "/api/v1/repos/app/tree", {}),                    # no route
    ("post", "/api/v1/repos/app/tree/main", {}),              # a read path with a write method (405 for others)
    ("get", "/nonexistent-route", {}),
]


@pytest.mark.parametrize("method,path,kw", READS)
def test_read_only_invoker_can_call_every_read_route(_no_network, monkeypatch, method, path, kw):
    mod, client, outer = _gs(monkeypatch)
    try:
        res = getattr(client, method)(path, headers=_as(READER), **kw)
        assert res.status_code == 200, (path, res.status_code, res.text[:200])
    finally:
        shutil.rmtree(outer, ignore_errors=True)


@pytest.mark.parametrize("method,path,kw", WRITES_AND_OTHERS)
def test_read_only_invoker_is_refused_on_every_other_route_and_nothing_changes(_no_network, monkeypatch, method,
                                                                               path, kw):
    mod, client, outer = _gs(monkeypatch)
    try:
        before = client.get("/api/v1/repos/app/refs/heads/main").json()
        res = getattr(client, method)(path, headers=_as(READER), **kw)
        assert res.status_code == 403 and res.json()["detail"] == "read-only caller: this route is not a read route"
        assert client.get("/api/v1/repos/app/refs/heads/main").json() == before
        assert client.get("/api/v1/repos/other/metadata").status_code == 404     # no repository was created
    finally:
        shutil.rmtree(outer, ignore_errors=True)


def test_every_route_is_classified_and_the_read_set_is_get_only(_no_network, monkeypatch):
    """The read set is exactly the six GET routes; every other route of the app is a refusal for a read-only caller
    (WRITES_AND_OTHERS covers each of them), so a new route is refused until it is listed."""
    mod, _client, outer = _gs(monkeypatch)
    try:
        from fastapi.routing import APIRoute
        routes = [r for r in mod.app.routes if isinstance(r, APIRoute)]
        read = {r.endpoint.__name__ for r in routes if r.endpoint in mod.READ_ONLY_ENDPOINTS}
        assert read == {"capabilities", "get_metadata", "fetch_tree", "fetch_blob", "get_branch_head",
                        "export_archive"}
        for r in routes:
            if r.endpoint in mod.READ_ONLY_ENDPOINTS:
                assert r.methods <= {"GET", "HEAD"}, r.path
        others = {r.endpoint.__name__ for r in routes if r.endpoint not in mod.READ_ONLY_ENDPOINTS}
        assert others == {"health_check", "git_info_refs", "git_upload_pack", "git_receive_pack", "vend_repository",
                          "create_branch", "commit_files", "commit_files_with_deletions", "merge_branch"}
    finally:
        shutil.rmtree(outer, ignore_errors=True)


SEQUENCE = READS + [
    ("post", "/api/v1/repos/app/branches", {"json": {"branch_name": "feature/x"}}),
    ("post", "/api/v1/repos/app/commits", {"json": {"branch": "feature/x", "files": {"a.txt": "x"}}}),
    ("get", "/api/v1/repos/app/tree/feature/x", {}),
    ("post", "/api/v1/repos/app/merge", {"json": {"source_branch": "feature/x"}}),
    ("get", "/git/app.git/info/refs?service=git-receive-pack", {}),
    ("get", "/nonexistent-route", {}),
]


def _statuses(monkeypatch, readonly, email):
    mod, client, outer = _gs(monkeypatch, readonly=readonly)
    try:
        out = []
        for method, path, kw in SEQUENCE:
            res = getattr(client, method)(path, headers=_as(email), **kw)
            out.append((path, res.status_code, res.json().get("detail") if res.status_code in (401, 403) else None))
        return out
    finally:
        shutil.rmtree(outer, ignore_errors=True)


def test_allowed_invokers_behaviour_is_unchanged_by_the_read_only_list(_no_network, monkeypatch):
    """Negative: a GIT_SERVER_ALLOWED_INVOKERS caller gets the same answer on every route with no read-only list,
    an empty one, and one that names another caller or the caller itself (a full invoker keeps full access)."""
    from fd4k_support import CALLER

    baseline = _statuses(monkeypatch, None, CALLER)
    assert all(code not in (401, 403) for _p, code, _d in baseline[:-2])
    for readonly in ("", READER, f"{READER},{CALLER}"):
        assert _statuses(monkeypatch, readonly, CALLER) == baseline


def test_unlisted_caller_is_refused_as_before_on_read_routes(_no_network, monkeypatch):
    """Negative: a caller in neither list gets the unchanged FD-4K 403 on read and write routes alike."""
    for readonly in (None, READER):
        out = _statuses(monkeypatch, readonly, STRANGER)
        assert {(code, detail) for _p, code, detail in out} == {(403, "caller is not allowed to use this git server")}


def test_without_a_read_only_list_the_runner_has_no_access(_no_network, monkeypatch):
    out = _statuses(monkeypatch, None, READER)
    assert {(code, detail) for _p, code, detail in out} == {(403, "caller is not allowed to use this git server")}


def test_authenticator_read_route_flag(_no_network):
    from fd4k_support import CALLER, make_authenticator, make_token

    auth = make_authenticator(env_extra={"GIT_SERVER_READONLY_INVOKERS": f" {READER.upper()} , {CALLER} "})
    assert auth.readonly_invokers() == frozenset({READER.casefold()})       # a full invoker is never read-only
    ro = [f"Bearer {make_token(email=READER)}"]
    assert auth.authenticate(ro, read_route=True) == READER
    with pytest.raises(Exception) as ei:
        auth.authenticate(ro)
    assert getattr(ei.value, "status", None) == 403
    full = [f"Bearer {make_token(email=CALLER)}"]
    assert auth.authenticate(full) == CALLER and auth.authenticate(full, read_route=True) == CALLER
