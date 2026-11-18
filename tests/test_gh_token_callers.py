"""
GH-TOKEN-CALLERS (owner 10-29): vending GET /github-token answers only an exact caller allow-list.

The route returns a GitHub App installation token (every repository, the installation's write permissions). Cloud Run
IAM admits every agent SA (main.tf agent_run_invokers), so the route itself checks the caller's Google ID token
(same verifier as the destructive routes) against GITHUB_TOKEN_ALLOWED_CALLERS, by default the refactor scanner's
runtime SA (sa-castor-developer in the host project). Hermetic: fake verifier, fake token minting, no network.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import logging
import os
import sys

import pytest
from fastapi.testclient import TestClient

import destructive_guard_fakes as f
from destructive_guard_fakes import dg

HOST = "mock-stackvend-project"
AUD = "https://project-repo-vending-service-999000999000.us-central1.run.app"
SCANNER_SA = f"sa-castor-developer@{HOST}.iam.gserviceaccount.com"
OTHER_PERSONAS = ["sa-castor-architect", "sa-castor-gcp-devops", "sa-castor-qa", "sa-castor-release",
                  "sa-castor-finops", "sa-castor-sre", "sa-project-provisioner"]
OTHER_SAS = [f"{p}@{HOST}.iam.gserviceaccount.com" for p in OTHER_PERSONAS] + [
    f"sa-stackvend-control-center@{HOST}.iam.gserviceaccount.com",
    f"sa-stackvend-sandbox-cleaner@{HOST}.iam.gserviceaccount.com",
]
GH_TOKEN = "ghs_installation_token_value_never_logged"


def _claims(email, aud=AUD, **over):
    return {"iss": "https://accounts.google.com", "aud": aud, "email": email, "email_verified": True, **over}


TOKENS = {"scanner": _claims(SCANNER_SA), "scanner-upper": _claims(SCANNER_SA.upper()),
          "unverified": _claims(SCANNER_SA, email_verified=False),
          "evil-iss": _claims(SCANNER_SA, iss="https://evil.example")}
TOKENS.update({f"tok-{e}": _claims(e) for e in OTHER_SAS})


def fake_verifier(token, audiences):
    """Mirrors google.oauth2.id_token.verify_oauth2_token: an audience outside `audiences` raises."""
    if token == "wrong-aud":
        raise ValueError("Token has wrong audience https://other-service.run.app")
    if token not in TOKENS:
        raise ValueError("Could not verify token signature")
    claims = dict(TOKENS[token])
    if claims["aud"] not in audiences:
        raise ValueError(f"Token has wrong audience {claims['aud']}")
    return claims


VENDING_MAIN = f.load_vending_main()


class FakeEngine:
    def __init__(self):
        self.minted = 0

    def generate_github_jit_token(self):
        self.minted += 1
        return GH_TOKEN


@pytest.fixture
def vmain():
    return VENDING_MAIN


@pytest.fixture
def engine(vmain, monkeypatch):
    eng = FakeEngine()
    monkeypatch.setattr(vmain, "vending_engine", eng)
    monkeypatch.setattr(vmain, "CALLER_TOKEN_VERIFIER", fake_verifier)
    monkeypatch.setenv("PROJECT_ID", HOST)
    monkeypatch.setenv("VENDING_SERVICE_URL", AUD)
    monkeypatch.delenv(dg.GITHUB_TOKEN_CALLERS_ENV, raising=False)
    return eng


@pytest.fixture
def client(vmain, engine):
    return TestClient(vmain.app)


def _get(client, token=None, raw=None):
    headers = {}
    if raw is not None:
        headers["Authorization"] = raw
    elif token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return client.get("/github-token", headers=headers)


# ------------------------------------------------------------------------------------------------ the route
def test_allow_listed_scanner_sa_gets_the_token(client, engine):
    r = _get(client, "scanner")
    assert r.status_code == 200 and r.json() == {"token": GH_TOKEN, "status": "SUCCESS"}
    assert engine.minted == 1


def test_email_comparison_is_case_insensitive_exact_match(client, engine):
    assert _get(client, "scanner-upper").status_code == 200


@pytest.mark.parametrize("email", OTHER_SAS)
def test_every_other_agent_and_persona_sa_is_refused_403(client, engine, email):
    r = _get(client, f"tok-{email}")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "CALLER_NOT_ALLOWED"
    assert r.json()["detail"]["stage"] == "github-token"
    assert "GitHub token caller" in r.json()["detail"]["detail"]
    assert engine.minted == 0 and GH_TOKEN not in r.text


@pytest.mark.parametrize("raw", [None, "", "Bearer", "Bearer ", "Basic abc", "bearer scanner", "Bearer a b"])
def test_missing_or_malformed_authorization_is_401(client, engine, raw):
    r = _get(client, raw=raw) if raw is not None else _get(client)
    assert r.status_code == 401 and r.json()["detail"]["code"] == "UNAUTHENTICATED"
    assert r.headers.get("WWW-Authenticate") == "Bearer"
    assert engine.minted == 0


@pytest.mark.parametrize("token", ["wrong-aud", "forged", "evil-iss"])
def test_wrong_audience_bad_signature_or_issuer_is_401(client, engine, token):
    r = _get(client, token)
    assert r.status_code == 401 and r.json()["detail"]["code"] == "UNAUTHENTICATED"
    assert engine.minted == 0


def test_audience_is_checked_against_this_service_url(client, engine, monkeypatch):
    # A scanner ID token minted for another audience (vending's URL changed) is refused 401.
    monkeypatch.setenv("VENDING_SERVICE_URL", "https://some-other-service.run.app")
    r = _get(client, "scanner")
    assert r.status_code == 401 and engine.minted == 0


def test_unverified_email_is_403(client, engine):
    r = _get(client, "unverified")
    assert r.status_code == 403 and engine.minted == 0


def test_explicit_env_allow_list_replaces_the_default(client, engine, monkeypatch):
    other = OTHER_SAS[0]
    monkeypatch.setenv(dg.GITHUB_TOKEN_CALLERS_ENV, f" {other.upper()} ")
    assert _get(client, f"tok-{other}").status_code == 200
    r = _get(client, "scanner")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "CALLER_NOT_ALLOWED"


def test_blank_env_falls_back_to_the_derived_default(client, engine, monkeypatch):
    monkeypatch.setenv(dg.GITHUB_TOKEN_CALLERS_ENV, "  ")
    assert _get(client, "scanner").status_code == 200
    assert _get(client, f"tok-{OTHER_SAS[0]}").status_code == 403


def test_env_with_no_email_fails_closed_503(client, engine, monkeypatch):
    monkeypatch.setenv(dg.GITHUB_TOKEN_CALLERS_ENV, " , ")
    r = _get(client, "scanner")
    assert r.status_code == 503 and r.json()["detail"]["code"] == "CALLERS_UNCONFIGURED"
    assert dg.GITHUB_TOKEN_CALLERS_ENV in r.json()["detail"]["detail"] and engine.minted == 0


def test_no_project_id_and_no_env_fails_closed_503(client, engine, monkeypatch):
    monkeypatch.delenv("PROJECT_ID", raising=False)
    r = _get(client, "scanner")
    assert r.status_code == 503 and r.json()["detail"]["code"] == "CALLERS_UNCONFIGURED" and engine.minted == 0


def test_no_audience_fails_closed_503(client, engine, monkeypatch):
    monkeypatch.delenv("VENDING_SERVICE_URL", raising=False)
    r = _get(client, "scanner")
    assert r.status_code == 503 and r.json()["detail"]["code"] == "AUDIENCE_UNCONFIGURED" and engine.minted == 0


def test_test_mode_does_not_bypass_the_check(client, engine, monkeypatch):
    monkeypatch.setenv("TEST_MODE", "true")
    assert _get(client).status_code == 401 and engine.minted == 0


def test_refusal_is_a_logged_security_event_without_secrets(client, engine, caplog):
    with caplog.at_level(logging.INFO, logger="project-repo-vending-api"):
        _get(client, f"tok-{OTHER_SAS[0]}")
        _get(client, "scanner")
    refused = [r for r in caplog.records if getattr(r, "security_event", None) == "github_token_caller_refused"]
    assert len(refused) == 1 and refused[0].levelno == logging.WARNING
    assert refused[0].refusal_code == "CALLER_NOT_ALLOWED" and refused[0].http_status == 403
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert GH_TOKEN not in text and f"tok-{OTHER_SAS[0]}" not in text and "Bearer" not in text
    assert f"GitHub installation token issued to {SCANNER_SA}" in text


def test_derived_default_is_exactly_the_scanner_sa(monkeypatch):
    monkeypatch.setenv("PROJECT_ID", HOST)
    monkeypatch.setenv("VENDING_SERVICE_URL", AUD + "/")
    monkeypatch.delenv(dg.GITHUB_TOKEN_CALLERS_ENV, raising=False)
    assert dg.github_token_caller_config_from_env() == (frozenset({SCANNER_SA}), [AUD])


def test_destructive_refusal_texts_are_unchanged():
    # The shared verifier's default wording (destructive routes) is untouched by the new keyword arguments.
    with pytest.raises(dg.CallerRefused) as e:
        dg.authenticate_caller("Bearer x", allowed=frozenset(), audiences=[AUD], verifier=fake_verifier)
    assert e.value.detail == "DESTRUCTIVE_CALLERS is not configured"
    with pytest.raises(dg.CallerRefused) as e:
        dg.authenticate_caller(f"Bearer tok-{OTHER_SAS[0]}", allowed=frozenset({SCANNER_SA}), audiences=[AUD],
                               verifier=fake_verifier)
    assert e.value.detail.endswith("is not an allow-listed destructive caller")


# ------------------------------------------------------------------------------------------------ scanner client
@pytest.fixture()
def rs(monkeypatch):
    from fd4g_support import real_modules

    real_modules(monkeypatch)
    path = os.path.join(f.REPO_ROOT, "apps", "refactor-scanner", "scanner.py")
    spec = importlib.util.spec_from_file_location("gh_token_callers_rs_scanner", path)
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "gh_token_callers_rs_scanner", mod)
    spec.loader.exec_module(mod)
    return mod


def _wired_archive_client(rs, client, id_token_for):
    """The real scanner ArchiveClient, its /github-token GET served by the real vending route (TestClient)."""
    seen = []

    def get(url, headers):
        seen.append(url)
        if url == f"{AUD}/github-token":
            r = client.get("/github-token", headers=headers)
            return r.status_code, r.content, r.headers
        assert url.startswith("https://api.github.com/repos/acme/app/tarball/")
        assert headers["Authorization"] == f"Bearer {GH_TOKEN}"
        return 200, b"tar", {}

    return rs.ArchiveClient({"VENDING_SERVICE_URL": AUD}, http_get=get, id_token=id_token_for), seen


def test_scanner_client_works_against_the_guarded_route(rs, client, engine):
    audiences = []

    def id_token(aud):
        audiences.append(aud)
        return "scanner"

    archive, seen = _wired_archive_client(rs, client, id_token)
    assert archive.fetch(rs.ScanTarget("app", "acme/app", "main", "GITHUB")) == b"tar"
    assert audiences == [AUD] and seen == [f"{AUD}/github-token", "https://api.github.com/repos/acme/app/tarball/main"]
    assert engine.minted == 1


def test_scanner_client_running_as_another_sa_fails_typed(rs, client, engine):
    archive, seen = _wired_archive_client(rs, client, lambda aud: f"tok-{OTHER_SAS[0]}")
    with pytest.raises(rs.ScanFailed) as e:
        archive.fetch(rs.ScanTarget("app", "acme/app", "main", "GITHUB"))
    assert "403" in str(e.value) and seen == [f"{AUD}/github-token"] and engine.minted == 0


# ------------------------------------------------------------------------------------------------ callers
def test_terraform_server_has_no_unauthenticated_vending_token_fallback():
    # The terraform MCP's old fallback sent no ID token (and VENDING_SERVICE_URL is not set on that server).
    import ast
    tree = ast.parse(open(os.path.join(f.REPO_ROOT, "mcp-servers", "terraform", "service.py")).read())
    literals = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert not [v for v in literals if "/github-token" in v]
