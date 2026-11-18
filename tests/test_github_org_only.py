import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

"""GITHUB-ORG-ONLY (register row GITHUB-ORG-ONLY, owner 11-12): the GitHub VCS provider is organization-only.

StackVend acts through short-lived GitHub App installation tokens, which can create repositories only in an
organization where the App is installed. Pinned here:
- shared/providers/github_provider.py `require_github_organization` decides from GitHub's typed answers (status
  codes, the account `type`), never from message text: a personal account or an unknown owner raises
  GitHubOwnerNotOrganizationError; any other GitHub error is re-raised unchanged;
- GitHubProvider.vend_repository and vending's direct-creation path never fall back to the signed-in user's account;
- the installer prompt asks for an organization; the docs no longer offer a personal account or a personal access
  token for GitHub repository vending.
"""
import os
import re
import sys
from types import SimpleNamespace as NS

import pytest

from github import GithubException

from test_destructive_guard_vending import (  # noqa: F401  (fixtures)
    _freeze_setting_without_firestore, _vend_crm, _vend_engine, vmain,
)
import destructive_guard_fakes as f

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from shared.providers import github_provider as gp  # noqa: E402


def _read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return fh.read()


def _gh_err(status):
    return GithubException(status, {"message": "x"}, None)


class _FakeClient:
    """PyGithub-shaped client: /orgs/{owner} and /users/{owner} answers, and a trap on the user fallback."""

    def __init__(self, org_error=None, user_type="User", user_error=None, create_error=None):
        self.org_error, self.user_type, self.user_error, self.create_error = org_error, user_type, user_error, create_error
        self.user_fallback_used = False
        self.created = []

    def get_repo(self, full_name):
        raise _gh_err(404)

    def get_organization(self, owner):
        if self.org_error:
            raise self.org_error
        client = self

        class _Org:
            id = 1

            def create_repo(self, name, **kw):
                if client.create_error:
                    raise client.create_error
                client.created.append(name)
                return NS(full_name=f"{owner}/{name}", html_url="h", clone_url="c", ssh_url="s", default_branch="main",
                          id=7, edit=lambda **k: None)
        return _Org()

    def get_user(self, login=None):
        if login is None:
            self.user_fallback_used = True
            return NS(create_repo=lambda **kw: pytest.fail("personal-account fallback must not run"))
        if self.user_error:
            raise self.user_error
        return NS(type=self.user_type, login=login)


# ------------------------------------------------------------------------------- require_github_organization
def test_organization_is_returned():
    assert gp.require_github_organization(_FakeClient(), "acme").id == 1


@pytest.mark.parametrize("user_type,user_error,expected", [
    ("User", None, "User"),
    (None, _gh_err(404), "NOT_FOUND"),
    ("Bot", None, "Bot"),
])
def test_owner_that_is_not_an_organization_is_refused(user_type, user_error, expected):
    client = _FakeClient(org_error=_gh_err(404), user_type=user_type, user_error=user_error)
    with pytest.raises(gp.GitHubOwnerNotOrganizationError) as exc:
        gp.require_github_organization(client, "someone")
    err = exc.value
    assert err.error_class == "GITHUB_OWNER_NOT_ORGANIZATION" and err.stage == "vcs_repository_vending"
    assert err.owner == "someone" and err.owner_type == expected
    msg = str(err)
    assert msg.startswith("GITHUB_OWNER_NOT_ORGANIZATION:") and "'someone'" in msg
    assert "organization with the StackVend GitHub App installed" in msg and "Nothing was created" in msg
    assert not client.user_fallback_used


@pytest.mark.parametrize("status", [401, 403, 500])
def test_other_github_errors_are_not_reclassified(status):
    """Do No Harm: a failure that says nothing about the owner's kind keeps its own class and status."""
    err = _gh_err(status)
    with pytest.raises(GithubException) as exc:
        gp.require_github_organization(_FakeClient(org_error=err), "acme")
    assert exc.value is err


def test_an_organization_the_token_cannot_see_keeps_the_original_404():
    err = _gh_err(404)
    with pytest.raises(GithubException) as exc:
        gp.require_github_organization(_FakeClient(org_error=err, user_type="Organization"), "acme")
    assert exc.value is err and not isinstance(exc.value, gp.GitHubOwnerNotOrganizationError)


def test_user_lookup_error_other_than_404_is_re_raised():
    err = _gh_err(500)
    with pytest.raises(GithubException) as exc:
        gp.require_github_organization(_FakeClient(org_error=_gh_err(404), user_error=err), "acme")
    assert exc.value is err


# ------------------------------------------------------------------------------- GitHubProvider.vend_repository
def _provider(client):
    prov = gp.GitHubProvider.__new__(gp.GitHubProvider)
    prov.default_owner = "acme"
    prov.get_client = lambda: client
    return prov


def test_provider_refuses_a_personal_account_without_user_fallback():
    client = _FakeClient(org_error=_gh_err(404), user_type="User")
    with pytest.raises(gp.GitHubOwnerNotOrganizationError):
        _provider(client).vend_repository("app", github_owner="someone")
    assert not client.user_fallback_used and client.created == []


def test_provider_creates_in_an_organization():
    client = _FakeClient()
    meta = _provider(client).vend_repository("app", github_owner="acme")
    assert client.created and meta.full_name.startswith("acme/") and not client.user_fallback_used


def test_provider_403_names_the_app_installation_fix():
    client = _FakeClient(create_error=_gh_err(403))
    with pytest.raises(gp.GitHubRepositoryCreateError) as exc:
        _provider(client).vend_repository("app", github_owner="acme")
    err = exc.value
    assert err.status == 403 and err.owner == "acme" and err.full_name == "acme/app"
    assert err.error_class == "GITHUB_REPOSITORY_CREATE_FAILED" and err.stage == "vcs_repository_vending"
    assert str(err) == ("GITHUB_REPOSITORY_CREATE_FAILED: the GitHub repository 'acme/app' was not created (HTTP 403: "
                        "x). Check the StackVend GitHub App is installed on acme with repository permission "
                        "Administration: Read & Write.")


def test_provider_422_names_the_app_repository_access():
    client = _FakeClient(create_error=_gh_err(422))
    with pytest.raises(gp.GitHubRepositoryCreateError) as exc:
        _provider(client).vend_repository("app", github_owner="acme")
    assert exc.value.status == 422
    assert ("give the App access to it (installation repository access \"All repositories\", or include "
            "'acme/app'), or use another name.") in str(exc.value)


def test_provider_other_status_has_no_guessed_hint():
    client = _FakeClient(create_error=_gh_err(401))
    with pytest.raises(gp.GitHubRepositoryCreateError) as exc:
        _provider(client).vend_repository("app", github_owner="acme")
    assert exc.value.status == 401 and str(exc.value).endswith("(HTTP 401: x).")


def test_provider_without_a_client_is_a_typed_failure():
    with pytest.raises(gp.GitHubRepositoryCreateError) as exc:
        _provider(None).vend_repository("app", github_owner="acme")
    assert exc.value.status is None and "credentials are missing or unusable" in str(exc.value)


def test_typed_create_error_keeps_githubs_retry_metadata():
    """The retry decorator classifies the typed error exactly like GitHub's own exception (status/headers/body)."""
    from shared.github_resilience import extract_error_metadata, is_rate_limit_or_transient
    original = GithubException(403, {"message": "You have exceeded a secondary rate limit"}, {"Retry-After": "5"})
    typed = gp.GitHubRepositoryCreateError.from_exception("acme", "acme/castor-app", original)
    assert extract_error_metadata(typed)[0] == 403
    assert is_rate_limit_or_transient(*extract_error_metadata(typed)) is True
    plain = gp.GitHubRepositoryCreateError.from_exception("acme", "acme/castor-app", _gh_err(403))
    assert is_rate_limit_or_transient(*extract_error_metadata(plain)) is False


def test_vend_all_surfaces_the_typed_class_and_stage(vmain):
    """The vend answers a VendingFailure carrying the GitHub error's class and stage, and the workload record names
    them (fail-loudly policy); nothing is reported vended."""
    db = f.FakeDB()
    eng = _vend_engine(vmain, db, _vend_crm())
    globs = vmain.ProjectRepoVendingEngine.vend_gcp_project.__globals__
    eng.vend_gcp_project = lambda product_id, trace_id, **kw: {"project_id": "p-1", "project_number": f.NUMBER}

    def refuse(product_id, **kw):
        raise globs["GitHubRepositoryCreateError"]("acme", "acme/castor-app", 403, "Resource not accessible by integration")

    eng.vend_github_repo = refuse
    with pytest.raises(globs["VendingFailure"]) as exc:
        eng.vend_all("app", "tr-org-only", vcs_provider="GITHUB")
    assert exc.value.error_class == "GITHUB_REPOSITORY_CREATE_FAILED" and exc.value.stage == "vcs_repository_vending"
    stored = db.doc("workloads/app")
    assert stored["vending_error_class"] == "GITHUB_REPOSITORY_CREATE_FAILED"
    assert stored["vending_error_stage"] == "vcs_repository_vending" and stored["project_id"] == "p-1"
    assert "github_repo" not in stored


def test_no_personal_account_create_call_left_in_any_provider_copy():
    src = _read("shared/providers/github_provider.py")
    assert "get_user().create_repo" not in src and "user.create_repo" not in src
    assert "user.create_repo" not in _read("apps/project-vending/vending.py")


# ------------------------------------------------------------------------------- vending direct-creation path
def _vending_engine(vmain, monkeypatch, client, provider_error):
    eng = _vend_engine(vmain, f.FakeDB(), _vend_crm())
    globs = vmain.ProjectRepoVendingEngine.vend_gcp_project.__globals__

    def _get_provider(**kw):
        def _vend(*a, **k):
            raise provider_error
        return NS(vend_repository=_vend)

    monkeypatch.setitem(globs, "VCSProviderFactory", NS(get_provider=_get_provider))
    monkeypatch.setitem(globs, "Github", lambda token: client)
    monkeypatch.setattr(eng, "fetch_github_app_credentials", lambda *a, **k: {})
    monkeypatch.setattr(eng, "generate_github_jit_token", lambda *a, **k: "jit-token")
    return eng, globs


def test_vending_re_raises_the_providers_refusal(vmain, monkeypatch):
    globs = vmain.ProjectRepoVendingEngine.vend_gcp_project.__globals__
    refusal = globs["GitHubOwnerNotOrganizationError"]("someone", "User")
    client = _FakeClient()
    eng, _ = _vending_engine(vmain, monkeypatch, client, refusal)
    with pytest.raises(globs["GitHubOwnerNotOrganizationError"]):
        eng.vend_github_repo("app", github_owner="someone", vcs_provider="GITHUB")
    assert client.created == [] and not client.user_fallback_used


def test_vending_direct_path_refuses_a_personal_account(vmain, monkeypatch):
    client = _FakeClient(org_error=_gh_err(404), user_type="User")
    eng, globs = _vending_engine(vmain, monkeypatch, client, RuntimeError("provider unavailable"))
    with pytest.raises(globs["GitHubOwnerNotOrganizationError"]) as exc:
        eng.vend_github_repo("app", github_owner="someone", vcs_provider="GITHUB")
    assert exc.value.owner_type == "User" and not client.user_fallback_used


@pytest.mark.parametrize("where", ["org", "create"])
@pytest.mark.parametrize("status", [401, 403, 422])
def test_vending_direct_path_github_error_is_a_typed_failure(vmain, monkeypatch, status, where):
    """GITHUB-REPO-CREATE-FAIL-LOUD (owner 11-12, review F1; was F6's pin of REPO_VENDED_MOCK): a GitHub error that
    says nothing about the owner's kind is not reclassified as GITHUB_OWNER_NOT_ORGANIZATION, and the direct path
    raises GitHubRepositoryCreateError with GitHub's status instead of returning invented repository metadata."""
    client = (_FakeClient(org_error=_gh_err(status)) if where == "org"
              else _FakeClient(create_error=_gh_err(status)))
    eng, globs = _vending_engine(vmain, monkeypatch, client, RuntimeError("provider unavailable"))
    with pytest.raises(globs["GitHubRepositoryCreateError"]) as exc:
        eng.vend_github_repo("app", github_owner="acme", vcs_provider="GITHUB")
    err = exc.value
    assert not isinstance(err, globs["GitHubOwnerNotOrganizationError"])
    assert err.status == status and err.error_class == "GITHUB_REPOSITORY_CREATE_FAILED"
    assert err.stage == "vcs_repository_vending" and err.full_name == "acme/app"
    assert client.created == [] and not client.user_fallback_used


def test_vending_direct_path_without_any_token_is_a_typed_failure(vmain, monkeypatch):
    """No token at all: a typed failure (no HTTP status), never REPO_VENDED_MOCK."""
    client = _FakeClient()
    eng, globs = _vending_engine(vmain, monkeypatch, client, RuntimeError("provider unavailable"))
    monkeypatch.setattr(eng, "generate_github_jit_token", lambda *a, **k: "")
    for var in ("GITHUB_PAT", "GITHUB_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(globs["GitHubRepositoryCreateError"]) as exc:
        eng.vend_github_repo("app", github_owner="acme", vcs_provider="GITHUB")
    assert exc.value.status is None and "no GitHub token" in str(exc.value)


def test_no_invented_repository_result_is_left():
    """REPO_VENDED_MOCK and the provider's made-up RepositoryMetadata are gone (in every mode, TEST_MODE included:
    no hermetic test needs them)."""
    assert "REPO_VENDED_MOCK" not in _read("apps/project-vending/vending.py")
    assert "mock metadata" not in _read("shared/providers/github_provider.py").lower()


def test_vending_direct_path_still_creates_in_an_organization(vmain, monkeypatch):
    client = _FakeClient()
    eng, _ = _vending_engine(vmain, monkeypatch, client, RuntimeError("provider unavailable"))
    res = eng.vend_github_repo("app", github_owner="acme", vcs_provider="GITHUB")
    assert res["status"] == "REPO_VENDED" and client.created and not client.user_fallback_used


# ------------------------------------------------------------------------------- installer prompt + docs
def test_bootstrap_asks_for_an_organization():
    sh = _read("scripts/bootstrap.sh")
    assert ('read -r -p "Enter the GitHub organization that will own the workload repositories (your StackVend GitHub '
            'App must be installed on it; personal accounts are not supported): " GITHUB_OWNER') in sh
    assert "Username / Organization" not in sh and "your-github-username" not in sh
    assert "account/organization" not in sh and "account or organization" not in sh
    assert "GitHub App / PAT" not in sh
    assert 'echo -e "${RED}[ERROR]${RESET} The GitHub organization is required."' in sh   # non-empty check kept


def _section(text, heading):
    start = text.index(heading)
    nxt = re.search(r"^#{2,3} ", text[start + len(heading):], re.M)
    return text[start: start + len(heading) + nxt.start()] if nxt else text[start:]


@pytest.mark.parametrize("rel,heading", [
    ("README.md", "### GitHub repository vending"),
    ("documentation/quickstart.md", "### GitHub App (GitHub VCS provider"),
    ("documentation/configuration.md", "### GitHub\n"),
])
def test_github_vending_docs_offer_no_personal_account_or_pat(rel, heading):
    sec = _section(_read(rel), heading)
    low = sec.lower()
    assert '"pat"' not in sec                                              # no JSON example tells anyone to add one
    assert "personal github accounts are not supported" in low and "GITHUB_OWNER_NOT_ORGANIZATION" in sec
    assert "for a personal account" not in low and "personal accounts need" not in low
    # Review F3: the code still reads a `pat` as a fallback token (owner 11-12: removed next release), so no doc
    # claims tokens are unsupported; configuration.md says exactly what a `pat` still does.
    assert "personal access tokens are not supported" not in low
    if rel == "documentation/configuration.md":
        assert ("A `pat` key, if present, is still read as a fallback token for organization repositories; it does not "
                "enable personal accounts and will be removed in the next release.") in sec


def test_settings_reference_secret_and_reuse_wording():
    sec = _section(_read("documentation/settings-reference.md"), "### VCS (Git provider) card")
    assert "optionally `pat`" not in sec
    assert "already exists under a personal account still reuses it on redeploy" in " ".join(sec.split())


def test_control_center_offers_no_pat_option():
    html = _read("apps/control-center/templates/dashboard.html")
    assert "Option B: Personal Access Token" not in html and '{"pat": "ghp_xxx"}' not in html
    assert "GITHUB_OWNER_NOT_ORGANIZATION" in html and "Owner Not an Organization" in html


def test_register_row_is_approved():
    path = os.path.join(REPO, "docs", "planning", "behavior-change-register.md")
    if not os.path.exists(path):
        pytest.skip("docs/ is internal and not part of the public export")
    reg = _read("docs/planning/behavior-change-register.md")
    row = next(line for line in reg.splitlines() if line.startswith("| GITHUB-ORG-ONLY"))
    assert row.rstrip().endswith("| github-org-only | ✅ owner 11-12 |")
