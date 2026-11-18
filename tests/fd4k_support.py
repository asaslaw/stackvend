"""FD-4K test support: real RS256 Google-style ID tokens signed by a throwaway key, and a git-server loader whose
authenticator verifies them against an injected cert set (no network, no ADC)."""

import datetime
import importlib.util
import json
import os
import sys
import tempfile
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GS_DIR = os.path.join(REPO_ROOT, "apps", "git-server")
GS_MAIN = os.path.join(GS_DIR, "main.py")
AUDIENCE = "https://castor-git-server-test.a.run.app"
CALLER = "sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com"
KID = "fd4k-test-kid"

_KEYS = {}


def _keypair(name="primary"):
    if name not in _KEYS:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"fd4k-{name}")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
        priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()).decode()
        _KEYS[name] = (priv, cert.public_bytes(serialization.Encoding.PEM).decode())
    return _KEYS[name]


def make_token(*, key="primary", kid=KID, **claims):
    from google.auth import crypt, jwt

    now = int(time.time())
    payload = {"iss": "https://accounts.google.com", "aud": AUDIENCE, "email": CALLER, "email_verified": True,
               "iat": now, "exp": now + 3600, "sub": "1234567890"}
    for k, v in claims.items():
        if v is None:
            payload.pop(k, None)
        else:
            payload[k] = v
    signer = crypt.RSASigner.from_string(_keypair(key)[0], key_id=kid)
    return jwt.encode(signer, payload).decode()


class FakeCertsHttp:
    """http_get stub: serves the cert set and counts fetches. Anything else is an error (metadata unreachable)."""

    def __init__(self, certs=None, fail=False):
        self.certs = certs if certs is not None else {KID: _keypair()[1]}
        self.fail = fail
        self.cert_fetches = 0
        self.other_calls = []

    def __call__(self, url, headers=None, timeout=5.0):
        if url.startswith("https://www.googleapis.com/oauth2/v1/certs"):
            self.cert_fetches += 1
            if self.fail:
                raise OSError("cert endpoint unreachable")
            return 200, {"cache-control": "public, max-age=20000"}, json.dumps(self.certs).encode()
        self.other_calls.append(url)
        raise OSError(f"unexpected HTTP call in test: {url}")


def make_authenticator(*, audiences=(AUDIENCE,), invokers=(CALLER,), http=None, env_extra=None, **kwargs):
    sys.path.insert(0, GS_DIR)
    try:
        import git_server_auth
    finally:
        sys.path.remove(GS_DIR)
    env = {"GIT_SERVER_AUDIENCES": ",".join(audiences), "GIT_SERVER_ALLOWED_INVOKERS": ",".join(invokers)}
    env.update(env_extra or {})
    return git_server_auth.GoogleIdTokenAuthenticator(env=env, http_get=http or FakeCertsHttp(), **kwargs)


def load_git_server(monkeypatch, data_dir=None, authenticator=None, import_name="fd4k_git_server_main"):
    """Load apps/git-server/main.py fresh with GIT_DATA_DIR in a temp dir and a hermetic authenticator.

    Returns (module, TestClient, outer_tmp_dir). The client sends a valid token on every request by default.
    """
    from fd4g_support import real_modules

    real_modules(monkeypatch)
    outer = tempfile.mkdtemp(prefix="fd4k-gs-")
    data = data_dir or os.path.join(outer, "data")
    monkeypatch.setenv("GIT_DATA_DIR", data)
    for k in ("PROJECT_ID", "PLATFORM_PROJECT", "GIT_SERVER_ALLOW_SMART_HTTP_PUSH"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.syspath_prepend(GS_DIR)
    spec = importlib.util.spec_from_file_location(import_name, GS_MAIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.authenticator = authenticator or make_authenticator()
    from fastapi.testclient import TestClient

    client = TestClient(mod.app, headers={"Authorization": f"Bearer {make_token()}"})
    return mod, client, outer
