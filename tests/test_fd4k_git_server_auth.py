"""FD-4K: castor-git-server requires a verified Google ID token from an allow-listed SA on every non-health route.

Real RS256 tokens (throwaway key + self-signed cert injected as the Google cert set), verified by google-auth.
Hermetic: socket.connect is blocked; the authenticator's HTTP collaborator is a stub.
"""
import hermetic_guard  # noqa: F401  (lane 2: must be the first import)

import base64
import json
import os
import shutil
import socket
import time

import pytest

from fd4k_support import AUDIENCE, CALLER, FakeCertsHttp, load_git_server, make_authenticator, make_token


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    from fd4g_support import real_modules

    real_modules(monkeypatch)

    def _blocked(self, addr):
        raise OSError(f"network blocked in FD-4K test: {addr}")

    monkeypatch.setattr(socket.socket, "connect", _blocked)


@pytest.fixture()
def gs(monkeypatch):
    mod, client, outer = load_git_server(monkeypatch)
    assert client.post("/api/v1/repos", json={"product_id": "app"}).status_code == 201
    yield mod, client
    shutil.rmtree(outer, ignore_errors=True)


ROUTES = [
    ("post", "/api/v1/repos", {"json": {"product_id": "other"}}),
    ("get", "/api/v1/repos/app/metadata", {}),
    ("post", "/api/v1/repos/app/branches", {"json": {"branch_name": "feature/x"}}),
    ("get", "/api/v1/repos/app/tree/main", {}),
    ("get", "/api/v1/repos/app/blob/main/README.md", {}),
    ("post", "/api/v1/repos/app/commits", {"json": {"branch": "main", "files": {"a.txt": "x"}}}),
    ("post", "/api/v1/repos/app/merge", {"json": {"source_branch": "feature/x"}}),
    ("get", "/api/v1/repos/app/archive/main", {}),
    ("get", "/git/app.git/info/refs?service=git-upload-pack", {}),
    ("post", "/git/app.git/git-upload-pack", {"content": b""}),
    ("post", "/git/app.git/git-receive-pack", {"content": b""}),
    ("get", "/docs", {}),
    ("get", "/openapi.json", {}),
    ("get", "/nonexistent-route", {}),
    ("get", "/health/", {}),
]


def _strip_signature(tok):
    h, p, _ = tok.split(".")
    return f"{h}.{p}.SIGNATURE_REMOVED_BY_GOOGLE"


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _unsigned(alg):
    now = int(time.time())
    claims = {"iss": "https://accounts.google.com", "aud": AUDIENCE, "email": CALLER, "email_verified": True,
              "iat": now, "exp": now + 600}
    return f"{_b64({'alg': alg, 'typ': 'JWT'})}.{_b64(claims)}." + ("" if alg == "none" else _b64({"x": 1}))


# Built lazily (inside tests, after real google.auth modules are restored), never at collection time.
def _now():
    return int(time.time())


UNAUTHORIZED = {
    "no header": lambda: None,
    "basic": lambda: "Basic b2F1dGgyOnRva2Vu",
    "empty bearer": lambda: "Bearer ",
    "garbage": lambda: "Bearer not.a.jwt",
    "two segments": lambda: "Bearer abc.def",
    "alg none": lambda: "Bearer " + _unsigned("none"),
    "alg HS256": lambda: "Bearer " + _unsigned("HS256"),
    "stripped signature (Cloud Run IAM)": lambda: "Bearer " + _strip_signature(make_token()),
    "unknown signing key": lambda: "Bearer " + make_token(key="attacker"),
    "unknown kid": lambda: "Bearer " + make_token(kid="rotated-kid"),
    "expired": lambda: "Bearer " + make_token(iat=_now() - 7200, exp=_now() - 3600),
    "other audience": lambda: "Bearer " + make_token(aud="https://some-other-service.a.run.app"),
    "audience with path": lambda: "Bearer " + make_token(aud=AUDIENCE + "/api"),
    "wrong issuer": lambda: "Bearer " + make_token(iss="https://evil.example.com"),
    "missing issuer": lambda: "Bearer " + make_token(iss=None),
    "missing exp": lambda: "Bearer " + make_token(exp=None),
    "lifetime one year": lambda: "Bearer " + make_token(exp=_now() + 365 * 86400),
}
FORBIDDEN = {
    "email_verified false": lambda: "Bearer " + make_token(email_verified=False),
    "email_verified string": lambda: "Bearer " + make_token(email_verified="true"),
    "missing email": lambda: "Bearer " + make_token(email=None),
    "email not allowed": lambda: "Bearer " + make_token(email="attacker@evil-proj.iam.gserviceaccount.com"),
    "email suffix trick": lambda: "Bearer " + make_token(email=CALLER + ".evil.com"),
}


def _bare_client(mod):
    from fastapi.testclient import TestClient

    return TestClient(mod.app)


@pytest.mark.parametrize("method,path,kw", ROUTES)
@pytest.mark.parametrize("case", sorted(UNAUTHORIZED))
def test_every_route_rejects_unauthenticated(gs, method, path, kw, case):
    mod, _ = gs
    header = UNAUTHORIZED[case]()
    r = getattr(_bare_client(mod), method)(path, headers={"Authorization": header} if header is not None else {}, **kw)
    assert r.status_code == 401, (case, r.status_code, r.text)
    assert r.headers.get("www-authenticate") == "Bearer"


@pytest.mark.parametrize("method,path,kw", ROUTES)
@pytest.mark.parametrize("case", sorted(FORBIDDEN))
def test_every_route_rejects_unlisted_or_unverified_identity(gs, method, path, kw, case):
    mod, _ = gs
    r = getattr(_bare_client(mod), method)(path, headers={"Authorization": FORBIDDEN[case]()}, **kw)
    assert r.status_code == 403, (case, r.status_code, r.text)


def test_stripped_signature_has_explicit_message(gs):
    _, client = gs
    r = client.get("/api/v1/repos/app/metadata", headers={"Authorization": "Bearer " + _strip_signature(make_token())})
    assert r.status_code == 401
    assert "X-Serverless-Authorization" in r.json()["detail"]


def test_dual_header_request_accepted(gs):
    _, client = gs
    tok = make_token()
    r = client.get("/api/v1/repos/app/metadata",
                   headers={"Authorization": f"Bearer {tok}", "X-Serverless-Authorization": f"Bearer {tok}"})
    assert r.status_code == 200, r.text


def test_duplicate_authorization_headers_rejected(gs):
    mod, _ = gs
    from fastapi.testclient import TestClient

    tok = make_token()
    client = TestClient(mod.app)
    r = client.get("/api/v1/repos/app/metadata", headers=[("Authorization", f"Bearer {tok}"), ("Authorization", f"Bearer {tok}")])
    assert r.status_code == 401


@pytest.mark.parametrize("method,path,kw,ok", [
    ("get", "/api/v1/repos/app/metadata", {}, 200),
    ("post", "/api/v1/repos/app/branches", {"json": {"branch_name": "feature/x"}}, 200),
    ("get", "/api/v1/repos/app/tree/main", {}, 200),
    ("get", "/api/v1/repos/app/blob/main/README.md", {}, 200),
    ("post", "/api/v1/repos/app/commits", {"json": {"branch": "main", "files": {"a.txt": "x"}}}, 200),
    ("get", "/api/v1/repos/app/archive/main", {}, 200),
    ("post", "/api/v1/repos", {"json": {"product_id": "second"}}, 201),
])
def test_valid_token_allowed(gs, method, path, kw, ok):
    _, client = gs
    assert getattr(client, method)(path, **kw).status_code == ok


def test_case_insensitive_email_match(gs):
    _, client = gs
    r = client.get("/api/v1/repos/app/metadata", headers={"Authorization": "Bearer " + make_token(email=CALLER.upper())})
    assert r.status_code == 200


def test_health_public_and_minimal(gs):
    mod, client = gs
    client.headers.pop("Authorization", None)
    for path in ("/health", "/healthz"):
        r = client.get(path)
        assert r.status_code == 200
        assert r.json() == {"status": "OK", "service": "castor-git-server"}


def test_docs_disabled_even_when_authenticated(gs):
    _, client = gs
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


# ------------------------------------------------------------------ Smart HTTP

def test_push_refused_by_route(gs):
    _, client = gs
    assert client.get("/git/app.git/info/refs?service=git-receive-pack").status_code == 403
    assert client.post("/git/app.git/git-receive-pack", content=b"").status_code == 403


@pytest.mark.parametrize("query", ["", "?service=git-upload-pack&service=git-receive-pack", "?service=x"])
def test_dumb_or_ambiguous_info_refs_refused(gs, query):
    _, client = gs
    assert client.get(f"/git/app.git/info/refs{query}").status_code == 403


def test_cgi_env_minimal_with_verified_remote_user(gs, monkeypatch):
    mod, client = gs
    seen = {}

    class _Proc:
        returncode = 0

        def __init__(self, argv, cwd=None, stdin=None, stdout=None, stderr=None, env=None):
            seen["env"], seen["cwd"] = env, cwd

        def communicate(self, input=None):
            return b"Content-Type: text/plain\r\n\r\nok", b""

    monkeypatch.setattr(mod.subprocess, "Popen", _Proc)
    monkeypatch.setenv("FD4K_PARENT_SECRET", "must-not-leak")
    r = client.get("/git/app.git/info/refs?service=git-upload-pack")
    assert r.status_code == 200
    env = seen["env"]
    assert env["REMOTE_USER"] == CALLER
    assert env["PATH_INFO"] == "/app.git/info/refs"
    assert env["QUERY_STRING"] == "service=git-upload-pack"
    assert env["GIT_CONFIG_KEY_0"] == "http.receivepack" and env["GIT_CONFIG_VALUE_0"] == "false"
    assert "FD4K_PARENT_SECRET" not in env
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in env


@pytest.mark.parametrize("repo", ["app", "app.git.git", "team.gitops.git", "App.git", "a_b.git", "-x.git"])
def test_smart_http_repo_segment_must_be_id_dot_git(gs, repo):
    _, client = gs
    assert client.get(f"/git/{repo}/info/refs?service=git-upload-pack").status_code in (400, 404)


# ------------------------------------------------------------------ identifiers

@pytest.mark.parametrize("pid", ["team.gitops", "Team", "a_b", "app.git", "-x", "x" * 64])
@pytest.mark.parametrize("route", ["/api/v1/repos/{}/metadata", "/api/v1/repos/{}/tree/main",
                                   "/api/v1/repos/{}/archive/main", "/api/v1/repos/{}/blob/main/README.md"])
def test_bad_product_id_rejected_on_every_route(gs, pid, route):
    _, client = gs
    assert client.get(route.format(pid)).status_code == 400


@pytest.mark.parametrize("branch", ["-x", "--output=/tmp/x", "a..b", "a.lock", "HEAD", "@", "x y", "x\x7f",
                                    "x~1", "x^", "x:y", "a//b", "/a", "a/", ".a", "café"])
def test_bad_branch_names_rejected(gs, branch):
    _, client = gs
    assert client.post("/api/v1/repos/app/branches", json={"branch_name": branch}).status_code == 422
    assert client.post("/api/v1/repos/app/commits", json={"branch": branch, "files": {"a": "b"}}).status_code == 422
    assert client.post("/api/v1/repos/app/merge", json={"source_branch": branch}).status_code == 422


@pytest.mark.parametrize("branch", ["main", "feature/x", "castor/app-1a2b3c", "iac-upgrade/app-9f"])
def test_good_branch_names_accepted(gs, branch):
    _, client = gs
    assert client.post("/api/v1/repos/app/branches", json={"branch_name": branch}).status_code == 200


def test_bad_branch_path_param_rejected(gs):
    _, client = gs
    assert client.get("/api/v1/repos/app/archive/--output=x").status_code == 400
    assert client.get("/api/v1/repos/app/tree/-x").status_code == 400


# ------------------------------------------------------------------ fail-closed configuration

def _call_with(mod, monkeypatch, auth):
    mod.authenticator = auth
    from fastapi.testclient import TestClient

    return TestClient(mod.app).get("/api/v1/repos/app/metadata", headers={"Authorization": f"Bearer {make_token()}"})


def test_cert_fetch_failure_is_503(gs, monkeypatch):
    mod, _ = gs
    assert _call_with(mod, monkeypatch, make_authenticator(http=FakeCertsHttp(fail=True))).status_code == 503


def test_empty_invokers_is_503(gs, monkeypatch):
    mod, _ = gs
    # env unset -> metadata server lookup -> unreachable in tests -> 503 (fail closed)
    auth = make_authenticator(invokers=())
    assert _call_with(mod, monkeypatch, auth).status_code == 503


def test_discovery_failure_is_503(gs, monkeypatch):
    mod, _ = gs

    def _boom():
        raise RuntimeError("run.googleapis.com unreachable")

    auth = make_authenticator(audiences=(), service_lookup=_boom)
    assert _call_with(mod, monkeypatch, auth).status_code == 503


def test_discovered_audiences_include_urls_and_custom_audiences(gs, monkeypatch):
    mod, _ = gs
    svc = {"uri": "https://castor-git-server-123.us-central1.run.app",
           "urls": ["https://castor-git-server-123.us-central1.run.app", AUDIENCE],
           "customAudiences": ["castor-git-server"]}
    auth = make_authenticator(audiences=(), service_lookup=lambda: svc)
    assert _call_with(mod, monkeypatch, auth).status_code == 200
    from fastapi.testclient import TestClient

    r = TestClient(mod.app).get("/api/v1/repos/app/metadata",
                                headers={"Authorization": f"Bearer {make_token(aud='castor-git-server')}"})
    assert r.status_code == 200


def test_unknown_kid_refetch_is_rate_limited():
    http = FakeCertsHttp()
    clock = [1000.0]
    auth = make_authenticator(http=http, clock=lambda: clock[0])
    assert auth.authenticate([f"Bearer {make_token()}"]) == CALLER
    assert http.cert_fetches == 1
    for _ in range(5):
        with pytest.raises(Exception):
            auth.authenticate([f"Bearer {make_token(kid='random-kid')}"])
    assert http.cert_fetches == 1  # within 60 s: no amplification
    clock[0] += 61
    with pytest.raises(Exception):
        auth.authenticate([f"Bearer {make_token(kid='random-kid')}"])
    assert http.cert_fetches == 2


def test_metadata_region_last_segment_used(monkeypatch):
    calls = {}

    def _http(url, headers=None, timeout=5.0):
        if url.endswith("instance/region"):
            return 200, {}, b"projects/123/regions/europe-west1"
        if url.endswith("project/project-id"):
            return 200, {}, b"proj-x"
        raise OSError(url)

    auth = make_authenticator(http=_http, env_extra={"K_SERVICE": "castor-git-server"})

    class _Resp:
        status_code = 200

        def json(self):
            return {"uri": "https://u"}

    class _Session:
        def __init__(self, creds):
            pass

        def get(self, url, timeout=None):
            calls["url"] = url
            return _Resp()

    import google.auth
    import google.auth.transport.requests as gatr

    monkeypatch.setattr(google.auth, "default", lambda scopes=None: (object(), "p"))
    monkeypatch.setattr(gatr, "AuthorizedSession", _Session)
    assert auth._lookup_own_service() == {"uri": "https://u"}
    assert calls["url"] == "https://run.googleapis.com/v2/projects/proj-x/locations/europe-west1/services/castor-git-server"
