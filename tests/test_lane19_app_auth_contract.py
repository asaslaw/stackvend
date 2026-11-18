"""Lane 19 L19-3c: platform-owned auth module + contract test renderer (plan §2.2, §3 "Generated app" and the [R2]
JWT matrix; owner rows 27, 27b, 42, 46).

Hermetic: tokens are real RS256 JWTs signed by a throw-away test key; google-auth's certificate fetch is monkeypatched
to return the matching self-signed certificate (no network). Firestore membership is a fake.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import datetime
import importlib.util
import itertools
import json
import os
import sys
import time
from unittest.mock import patch

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from google.oauth2 import id_token as google_id_token

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "apps", "orchestrator-gateway"))

from developer_agent import app_auth_contract as AAC  # noqa: E402
from shared.access_policy import AccessPolicy  # noqa: E402

PROJECT = "tenant-proj-1"
OTHER = "tenant-proj-2"
KID = "test-kid"
_SEQ = itertools.count()

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lane19-test")])
_now = datetime.datetime.now(datetime.timezone.utc)
_CERT = (x509.CertificateBuilder().subject_name(_name).issuer_name(_name).public_key(_KEY.public_key())
         .serial_number(1).not_valid_before(_now - datetime.timedelta(days=1))
         .not_valid_after(_now + datetime.timedelta(days=1)).sign(_KEY, hashes.SHA256()))
CERT_PEM = _CERT.public_bytes(serialization.Encoding.PEM).decode()
KEY_PEM = _KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _policy(mode="PUBLIC_APP", **kw):
    if mode == "PUBLIC_APP":
        return AccessPolicy(mode=mode, sign_in={"google": "SHARED_PLATFORM_CLIENT"}, tenant_isolation_required=False,
                            source="intake", **kw)
    return AccessPolicy(mode=mode, invoker_principals=["user:a@example.com"], sign_in={"google": "DISABLED"},
                        source="intake", **kw)


def _load(mode="PUBLIC_APP", env=None, tmp_path=None):
    src = AAC.render_auth_module(_policy(mode))
    path = os.path.join(str(tmp_path), f"stackvend_auth_{next(_SEQ)}.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(src)
    base = {"STACKVEND_ACCESS_MODE": mode, "PROJECT_ID": PROJECT,
            "STACKVEND_APP_ADMIN_EMAILS": json.dumps(["boss@example.com"]),
            "STACKVEND_SIGN_IN_PROVIDERS": json.dumps(["google.com"]),
            "STACKVEND_IAP_AUDIENCE": "/projects/123/locations/r/services/svc",
            "STACKVEND_SERVICE_AUDIENCE": "https://svc.example.run.app"}
    base.update(env or {})
    base = {k: v for k, v in base.items() if v is not None}
    with patch.dict(os.environ, base, clear=False):
        for k in [k for k, v in (env or {}).items() if v is None]:
            os.environ.pop(k, None)
        spec = importlib.util.spec_from_file_location(f"sv_auth_{next(_SEQ)}", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


def _app(mod, members=()):
    mod._member_is_active = lambda email: email in members
    written = []
    mod._write_member = lambda email, record: written.append((email, record))
    app = FastAPI()

    @app.get("/api/config")
    def config():
        return {"ok": True}

    @app.get("/api/items")
    def items(user=Depends(mod.require_user)):
        return {"email": user.email, "role": user.role.value}

    @app.post("/api/admin/members")
    def add(body: dict, user=Depends(mod.require_admin)):
        mod.add_member(body.get("email"), user)
        return {"ok": True}

    return TestClient(app), written


def _token(**over):
    now = int(time.time())
    claims = {"iss": f"https://securetoken.google.com/{PROJECT}", "aud": PROJECT, "sub": "uid-1",
              "iat": now - 5, "exp": now + 3000, "auth_time": now - 30, "email": "member@example.com",
              "email_verified": True, "firebase": {"sign_in_provider": "google.com"}}
    for k, v in over.items():
        if v is None:
            claims.pop(k, None)
        else:
            claims[k] = v
    return jwt.encode(claims, KEY_PEM, algorithm="RS256", headers={"kid": KID})


@pytest.fixture(autouse=True)
def _certs(monkeypatch):
    monkeypatch.setattr(google_id_token, "_fetch_certs", lambda request, url: {KID: CERT_PEM})


@pytest.fixture
def public(tmp_path):
    return _load("PUBLIC_APP", tmp_path=tmp_path)


def _get(client, token=None, header=None):
    headers = {}
    if header is not None:
        headers["Authorization"] = header
    elif token is not None:
        headers["Authorization"] = "Bearer " + token
    return client.get("/api/items", headers=headers)


# ------------------------------------------------------------------------------------------------ PUBLIC_APP matrix
def test_own_project_token_accepted(public):
    client, _ = _app(public, members={"member@example.com"})
    r = _get(client, _token())
    assert r.status_code == 200 and r.json() == {"email": "member@example.com", "role": "member"}


@pytest.mark.parametrize("header", [None, "Bearer MOCK", "Basic x", "Bearer", "Bearer garbage", "bearer x"])
def test_missing_or_malformed_credentials_401(public, header):
    client, _ = _app(public, members={"member@example.com"})
    r = client.get("/api/items", headers={} if header is None else {"Authorization": header})
    assert r.status_code == 401 and r.json()["detail"] == "Unauthorized"


@pytest.mark.parametrize("over", [
    {"aud": OTHER},
    {"iss": f"https://securetoken.google.com/{OTHER}"},
    {"iss": "https://accounts.google.com"},
    {"firebase": {"sign_in_provider": "google.com", "tenant": "t1"}},
    {"firebase": {"sign_in_provider": "anonymous"}},
    {"firebase": {"sign_in_provider": "custom"}},
    {"firebase": {"sign_in_provider": "phone"}},
    {"firebase": {"sign_in_provider": "password"}},   # not in STACKVEND_SIGN_IN_PROVIDERS here
    {"email_verified": False},
    {"email_verified": None},
    {"email_verified": "true"},
    {"auth_time": None},
    {"firebase": None},
])
def test_rejected_tokens_401(public, over):
    client, _ = _app(public, members={"member@example.com"})
    assert _get(client, _token(**over)).status_code == 401


def test_token_signed_by_another_key_or_expired_is_rejected(public):
    client, _ = _app(public, members={"member@example.com"})
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    now = int(time.time())
    forged = jwt.decode(_token(), options={"verify_signature": False})
    assert _get(client, jwt.encode(forged, other, algorithm="RS256", headers={"kid": KID})).status_code == 401
    assert _get(client, _token(iat=now - 7200, exp=now - 3600)).status_code == 401


def test_raw_google_id_token_for_the_tenant_client_is_rejected(public):
    """C1/host-audience tombstone: a Google ID token (aud = an OAuth client id) never passes."""
    client, _ = _app(public, members={"member@example.com"})
    tok = _token(iss="https://accounts.google.com", aud="123-tenant.apps.googleusercontent.com")
    assert _get(client, tok).status_code == 401


def test_password_provider_when_enabled(tmp_path):
    mod = _load(env={"STACKVEND_SIGN_IN_PROVIDERS": json.dumps(["google.com", "password"])}, tmp_path=tmp_path)
    client, _ = _app(mod, members={"member@example.com"})
    assert _get(client, _token(firebase={"sign_in_provider": "password"})).status_code == 200


def test_per_role_auth_age(public):
    client, _ = _app(public, members={"member@example.com"})
    now = int(time.time())
    admin_2h = _token(email="boss@example.com", auth_time=now - 7200)
    r = _get(client, admin_2h)
    assert r.status_code == 401 and r.json()["detail"] == "REAUTH_REQUIRED"
    assert _get(client, _token(auth_time=now - 7200)).status_code == 200            # member, 2 h: fine
    r = _get(client, _token(auth_time=now - 13 * 3600))                             # member, 13 h
    assert r.status_code == 401 and r.json()["detail"] == "REAUTH_REQUIRED"
    r = _get(client, _token(auth_time=now + 600))                                   # future auth_time
    assert r.status_code == 401 and r.json()["detail"] == "REAUTH_REQUIRED"
    assert _get(client, _token(email="boss@example.com", auth_time=now - 60)).json()["role"] == "admin"


def test_non_member_403_member_on_admin_route_403_admin_200(public):
    client, written = _app(public, members={"member@example.com"})
    assert _get(client, _token(email="stranger@example.com")).status_code == 403
    member = {"Authorization": "Bearer " + _token()}
    assert client.post("/api/admin/members", json={"email": "x@example.com"}, headers=member).status_code == 403
    admin = {"Authorization": "Bearer " + _token(email="Boss@Example.com")}
    r = client.post("/api/admin/members", json={"email": "New@Example.com", "role": "admin"}, headers=admin)
    assert r.status_code == 200
    assert written == [("new@example.com", {"role": "member", "status": "ACTIVE", "added_by": "boss@example.com"})]


def test_add_member_requires_admin_actor(public):
    with pytest.raises(Exception):
        public.add_member("a@example.com", public.AppUser(email="m@example.com", role=public.AppRole.MEMBER))
    with pytest.raises(Exception):
        public.add_member("a@example.com", {"email": "x", "role": "admin"})


def test_public_route_unaffected(public):
    client, _ = _app(public)
    assert client.get("/api/config").status_code == 200


def test_membership_store_outage_is_503_not_200(public):
    client, _ = _app(public)

    def _down(email):
        raise RuntimeError("firestore down")

    public._member_is_active = _down
    assert _get(client, _token()).status_code == 503


# ------------------------------------------------------------------------------------------------ import-time checks
@pytest.mark.parametrize("env", [
    {"PROJECT_ID": None}, {"PROJECT_ID": ""}, {"STACKVEND_ACCESS_MODE": None}, {"STACKVEND_ACCESS_MODE": "PRIVATE_IAP"},
    {"STACKVEND_ACCESS_MODE": "public_app"}, {"STACKVEND_APP_ADMIN_EMAILS": None},
    {"STACKVEND_APP_ADMIN_EMAILS": '"boss@example.com"'}, {"STACKVEND_SIGN_IN_PROVIDERS": '["anonymous"]'},
    {"STACKVEND_SIGN_IN_PROVIDERS": "[]"}, {"STACKVEND_MAX_AUTH_AGE_ADMIN_S": "0"},
    {"STACKVEND_MAX_AUTH_AGE_ADMIN_S": "abc"}, {"STACKVEND_MAX_AUTH_AGE_MEMBER_S": "-5"},
])
def test_bad_environment_fails_at_import(tmp_path, env):
    with pytest.raises((KeyError, RuntimeError, ValueError)):
        _load("PUBLIC_APP", env=env, tmp_path=tmp_path)


# ------------------------------------------------------------------------------------------------ private modes
def test_private_iap_uses_the_iap_header(tmp_path, monkeypatch):
    mod = _load("PRIVATE_IAP", tmp_path=tmp_path)
    client, _ = _app(mod, members={"member@example.com"})
    seen = {}

    def _verify_token(token, request, audience=None, certs_url=None, **kw):
        seen.update(audience=audience, certs_url=certs_url)
        if token != "good-iap":
            raise ValueError("bad")
        return {"iss": "https://cloud.google.com/iap", "aud": audience, "email": "member@example.com"}

    monkeypatch.setattr(mod._id_token, "verify_token", _verify_token)
    assert client.get("/api/items", headers={"X-Goog-IAP-JWT-Assertion": "good-iap"}).status_code == 200
    assert seen == {"audience": "/projects/123/locations/r/services/svc",
                    "certs_url": "https://www.gstatic.com/iap/verify/public_key"}
    assert client.get("/api/items", headers={"Authorization": "Bearer " + _token()}).status_code == 401
    assert client.get("/api/items", headers={"X-Goog-IAP-JWT-Assertion": "forged"}).status_code == 401
    assert client.get("/api/items").status_code == 401


def test_private_iam_uses_the_service_audience(tmp_path, monkeypatch):
    mod = _load("PRIVATE_IAM", tmp_path=tmp_path)
    client, _ = _app(mod, members={"member@example.com"})

    def _verify_oauth2(token, request, audience=None, **kw):
        if token != "good":
            raise ValueError("bad")
        return {"iss": "https://accounts.google.com", "aud": audience, "email": "member@example.com",
                "email_verified": True}

    monkeypatch.setattr(mod._id_token, "verify_oauth2_token", _verify_oauth2)
    assert client.get("/api/items", headers={"Authorization": "Bearer good"}).status_code == 200
    assert client.get("/api/items", headers={"Authorization": "Bearer other"}).status_code == 401


@pytest.mark.parametrize("mode", ["PRIVATE_IAP", "PRIVATE_IAM"])
def test_private_modules_have_no_firebase_path(mode):
    """Rows 42/46: no verify_firebase_token call and no STACKVEND_SIGN_IN_PROVIDERS for private workloads."""
    src = AAC.render_auth_module(_policy(mode))
    calls = {n.func.attr for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "verify_firebase_token" not in calls
    assert "STACKVEND_SIGN_IN_PROVIDERS" not in src


@pytest.mark.parametrize("mode", ["PUBLIC_APP", "PRIVATE_IAP", "PRIVATE_IAM"])
def test_no_host_client_path_and_no_mock_token(mode):
    src = AAC.render_auth_module(_policy(mode))
    tree = ast.parse(src)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "GOOGLE_CLIENT_ID" not in names and "GOOGLE_CLIENT_ID" not in src
    if mode != "PRIVATE_IAM":
        assert "verify_oauth2_token" not in attrs
    assert "MOCK" not in src and "allAuthenticatedUsers" not in src


def test_rendering_is_deterministic():
    p = _policy()
    assert AAC.render_auth_module(p) == AAC.render_auth_module(p)
    one = ("svc-a",)  # single-service workload (row L3-PRB-t: root tests/ unchanged)
    assert AAC.render_contract_test("svc-a", p, service_names=one) == AAC.render_contract_test(
        "svc-a", p, service_names=one)
    files = AAC.render_service_files("svc-a", p, service_names=one)
    assert set(files) == {"apps/svc-a/stackvend_auth.py", "tests/test_stackvend_auth_contract_svc_a.py"}


# ------------------------------------------------------------------------------------------------ contract test
_PROTECTED_MAIN = '''from fastapi import Depends, FastAPI
from stackvend_auth import require_admin, require_user

app = FastAPI()


@app.get("/api/config")
def config():
    return {"ok": True}


@app.get("/api/items/{item_id}")
def item(item_id: int, user=Depends(require_user)):
    return {"id": item_id}


@app.post("/api/admin")
def admin(user=Depends(require_admin)):
    return {"ok": True}


@app.get("/health")
def health():
    return {"status": "ok"}
'''


def _run_contract(tmp_path, main_src, svc="svc-a"):
    import subprocess
    (tmp_path / "apps" / svc).mkdir(parents=True)
    (tmp_path / "tests").mkdir()
    files = AAC.render_service_files(svc, _policy(), service_names=(svc,))
    for rel, text in files.items():
        (tmp_path / rel).write_text(text)
    (tmp_path / "apps" / svc / "main.py").write_text(main_src)
    test_file = tmp_path / AAC.contract_test_path(svc, service_names=(svc,))
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(test_file)],
                          cwd=str(tmp_path), capture_output=True, text=True, timeout=120,
                          env=hermetic_guard.child_env())


def test_contract_test_passes_for_a_protected_app(tmp_path):
    res = _run_contract(tmp_path, _PROTECTED_MAIN)
    assert res.returncode == 0, res.stdout + res.stderr


def test_contract_test_names_an_unprotected_route(tmp_path):
    leaky = _PROTECTED_MAIN + '''

@app.get("/api/leak")
def leak():
    return {"secret": 1}
'''
    res = _run_contract(tmp_path, leaky)
    assert res.returncode != 0
    assert "APP.ROUTE_UNAUTHENTICATED" in res.stdout and "GET /api/leak" in res.stdout
