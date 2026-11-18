"""
FD-4E: real-crypto Control Center identity harness (NOT collected by pytest; run by
tests/test_cc_identity_fd4e.py in a clean subprocess).

Hermetic by construction:
- Outbound IPv4/IPv6 connections are refused at the socket layer; every attempt is recorded and reported
  as "network_attempts" (the test asserts the list is empty).
- google.auth.default() raises (no ADC), GOOGLE_APPLICATION_CREDENTIALS points at a missing file.
- google.cloud.secretmanager and google.cloud.firestore are stubbed; Firestore is an in-memory fake.
- Tokens are really signed (RS256 Google OIDC, ES256 IAP) with locally generated keys; only
  google.oauth2.id_token._fetch_certs is patched to serve those public keys.

Prints a single JSON object {case_id: value} as the last stdout line.
"""
import base64
import hashlib
import hmac
import json
import os
import socket
import sys
import time
import types
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------- hermetic guards (before any google import)
NETWORK_ATTEMPTS = []
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex


def _guarded_connect(self, address, *a, **k):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        NETWORK_ATTEMPTS.append(repr(address))
        raise ConnectionRefusedError(f"network disabled in FD-4E harness: {address!r}")
    return _real_connect(self, address, *a, **k)


def _guarded_connect_ex(self, address, *a, **k):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        NETWORK_ATTEMPTS.append(repr(address))
        return 111
    return _real_connect_ex(self, address, *a, **k)


def _guarded_getaddrinfo(host, *a, **k):
    NETWORK_ATTEMPTS.append(f"getaddrinfo:{host}")
    raise socket.gaierror(f"DNS disabled in FD-4E harness: {host}")


socket.socket.connect = _guarded_connect
socket.socket.connect_ex = _guarded_connect_ex
socket.getaddrinfo = _guarded_getaddrinfo

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC = os.path.join(REPO, "apps", "control-center")
sys.path.insert(0, CC)
os.chdir(CC)

os.environ["TEST_MODE"] = "true"  # import only; removed before any request
os.environ["PROJECT_ID"] = "mock-stackvend-project"
os.environ["GOOGLE_CLOUD_PROJECT"] = "mock-stackvend-project"
os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "111-legit.apps.googleusercontent.com"
os.environ["ADMIN_EMAIL"] = "owner@example.com"
os.environ["ENVIRONMENT"] = "test"
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = os.path.join(REPO, "nonexistent-fd4e-adc.json")
os.environ["NO_GCE_CHECK"] = "True"
for _k in ("SESSION_SECRET", "K_SERVICE"):
    os.environ.pop(_k, None)

import google.auth  # noqa: E402
import google.auth.exceptions  # noqa: E402


def _no_adc(*a, **k):
    raise google.auth.exceptions.DefaultCredentialsError("ADC disabled in FD-4E harness")


google.auth.default = _no_adc


# ---------------------------------------------------------------- fake Firestore
class Snap:
    def __init__(self, id_, data):
        self.id, self._d, self.exists = id_, data, data is not None

    def to_dict(self):
        return dict(self._d) if self._d is not None else None


class DocRef:
    def __init__(self, store, path):
        self.store, self.path, self.id = store, path, path[-1]

    def get(self):
        return Snap(self.id, self.store.get(self.path))

    def set(self, data, merge=False):
        cur = self.store.get(self.path) if merge else None
        self.store[self.path] = {**(cur or {}), **data}

    def create(self, data):
        """Firestore create(): AlreadyExists when the document exists (OSS-D23 create-semantics writes)."""
        if self.store.get(self.path) is not None:
            from google.api_core import exceptions as gexc

            raise gexc.AlreadyExists("/".join(self.path))
        self.set(data)

    def update(self, data):
        self.set(data, merge=True)

    def delete(self):
        self.store.pop(self.path, None)

    def collection(self, name):
        return ColRef(self.store, self.path + (name,))


class ColRef:
    def __init__(self, store, path):
        self.store, self.path = store, path

    def document(self, id_=None):
        if id_ is None:  # Firestore auto id (FD-4CI-b: audit entries)
            import uuid

            id_ = uuid.uuid4().hex
        return DocRef(self.store, self.path + (id_,))

    def where(self, *a, **k):
        return self

    def order_by(self, *a, **k):
        return self

    def limit(self, *a, **k):
        return self

    def stream(self):
        return [Snap(p[-1], d) for p, d in list(self.store.items()) if len(p) == len(self.path) + 1 and p[:-1] == self.path]


class Batch:
    """Firestore WriteBatch: the writes apply together at commit (FD-4CI-b: user access change + its audit entry)."""

    def __init__(self):
        self.ops = []

    def set(self, ref, data, merge=False):
        self.ops.append(lambda: ref.set(data, merge=merge))

    def update(self, ref, data, option=None):
        self.ops.append(lambda: ref.update(data))

    def delete(self, ref):
        self.ops.append(ref.delete)

    def commit(self):
        for op in self.ops:
            op()


class FakeDB:
    def __init__(self):
        self.store = {}

    def collection(self, name):
        return ColRef(self.store, (name,))

    def batch(self):
        return Batch()

    def get_all(self, refs):
        return [r.get() for r in refs]


fake = FakeDB()

sm = types.ModuleType("google.cloud.secretmanager")
sm.SecretManagerServiceClient = MagicMock(name="SecretManagerServiceClient")
sys.modules["google.cloud.secretmanager"] = sm

fs = types.ModuleType("google.cloud.firestore")
FS_FAIL = []  # non-empty => firestore.Client(...) raises (simulated transient outage)


def _fs_client(*a, **k):
    if FS_FAIL:
        raise RuntimeError("503 Firestore unavailable (simulated)")
    return fake


fs.Client = _fs_client
fs.Query = MagicMock(name="Query")
fs.SERVER_TIMESTAMP = "SERVER_TIMESTAMP"
fs.Increment = lambda n: n
fs.ArrayUnion = lambda v: v
fs.FieldFilter = MagicMock(name="FieldFilter")
sys.modules["google.cloud.firestore"] = fs
import google.cloud  # noqa: E402

google.cloud.firestore = fs
google.cloud.secretmanager = sm

# ---------------------------------------------------------------- keys + fake cert endpoints
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from google.auth import crypt, jwt as gjwt  # noqa: E402
import google.oauth2.id_token as gid  # noqa: E402


def _pem_priv(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _pem_pub(k):
    return k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


google_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
iap_ec = ec.generate_private_key(ec.SECP256R1())
GOOGLE_KID, IAP_KID = "google-kid-1", "iap-kid-1"
CERTS = {
    "https://www.googleapis.com/oauth2/v1/certs": {GOOGLE_KID: _pem_pub(google_rsa)},
    "https://www.gstatic.com/iap/verify/public_key": {IAP_KID: _pem_pub(iap_ec)},
}
CERT_FETCHES = []


def _fake_fetch_certs(request, certs_url):
    CERT_FETCHES.append(certs_url)
    return CERTS[certs_url]


gid._fetch_certs = _fake_fetch_certs
google_signer = crypt.RSASigner.from_string(_pem_priv(google_rsa), key_id=GOOGLE_KID)
iap_signer = crypt.ES256Signer.from_string(_pem_priv(iap_ec), key_id=IAP_KID)


def google_token(email, aud, iss="https://accounts.google.com", verified=True, exp_delta=3600):
    now = int(time.time())
    return gjwt.encode(google_signer, {"iss": iss, "aud": aud, "email": email, "email_verified": verified,
                                       "sub": "1", "iat": now, "exp": now + exp_delta}).decode()


def iap_token(email, aud, iss="https://cloud.google.com/iap", exp_delta=600, signer=None):
    now = int(time.time())
    return gjwt.encode(signer or iap_signer, {"iss": iss, "aud": aud, "email": email, "sub": "accounts.google.com:1",
                                              "iat": now, "exp": now + exp_delta}).decode()


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


# ---------------------------------------------------------------- load the real Control Center app
import main  # noqa: E402
import auth  # noqa: E402
import config  # noqa: E402
import identity  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

main.db = fake
auth.db = fake
os.environ.pop("TEST_MODE", None)
fake.collection("authorized_users").document("viewer@example.com").set(
    {"role": "VIEWER", "assigned_workloads": [], "is_active": True})

CC_URLS = ("https://product-control-center-ui-123456789.us-central1.run.app",
           "https://product-control-center-ui-abcdefghij-uc.a.run.app")
FINOPS = "sa-castor-finops@mock-stackvend-project.iam.gserviceaccount.com"
IAP_AUD = "/projects/123456789/locations/us-central1/services/product-control-center-ui"
DEFAULT_SECRET = "castor-platform-session-secret-key-2026"
LEGIT_CLIENT = "111-legit.apps.googleusercontent.com"
NEW = "222-owner.apps.googleusercontent.com"
ATTACKER_CLIENT = "666-attacker.apps.googleusercontent.com"

R = {}
client = TestClient(main.app, raise_server_exceptions=False)


def forged_cookie(secret, email="owner@example.com"):
    payload = f"{email}:{int(time.time())}"
    return f"{payload}:{hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()}"


def bearer(tok):
    return {"Authorization": f"Bearer {tok}"}


def mode(iap_audience, urls=CC_URLS, callers=frozenset({FINOPS})):
    identity._cert_cache.clear()
    identity.set_runtime_identity_for_tests(identity.RuntimeIdentity(iap_audience, tuple(urls), frozenset(callers)))


OWNER_COOKIE = {"stackvend_session": auth.create_session_token("owner@example.com")}
VIEWER_COOKIE = {"stackvend_session": auth.create_session_token("viewer@example.com")}

# ================================================================ public mode
mode("")
R["pub_forged_iap_header"] = client.get(
    "/api/users", headers={"X-Goog-Authenticated-User-Email": "accounts.google.com:owner@example.com"}).status_code
R["pub_signed_iap_jwt_ignored"] = client.get(
    "/api/users", headers={"x-goog-iap-jwt-assertion": iap_token("owner@example.com", IAP_AUD)}).status_code
R["pub_unsigned_jwt"] = client.get(
    "/api/users", headers=bearer(f"{b64({'alg': 'none'})}.{b64({'email': 'owner@example.com'})}.x")).status_code
R["pub_bad_signature_jwt"] = client.get(
    "/api/users", headers=bearer(f"{b64({'alg': 'RS256', 'kid': GOOGLE_KID})}.{b64({'email': FINOPS, 'aud': CC_URLS[1]})}.AAAA")).status_code
R["pub_cookie_default_secret"] = client.get(
    "/api/users", cookies={"stackvend_session": forged_cookie(DEFAULT_SECRET)}).status_code
R["pub_attacker_sa_genuine"] = client.get(
    "/api/users", headers=bearer(google_token("pwn@attacker-proj.iam.gserviceaccount.com", CC_URLS[1]))).status_code
R["pub_lookalike_sa"] = client.get(
    "/api/users", headers=bearer(google_token("sa-castor-finops@attacker-proj.iam.gserviceaccount.com", CC_URLS[1]))).status_code
R["pub_finops_wrong_aud"] = client.get(
    "/api/users", headers=bearer(google_token(FINOPS, "https://orchestrator-gateway-service-x-uc.a.run.app"))).status_code
R["pub_finops_path_aud_wrong_path"] = client.get(
    "/api/users", headers=bearer(google_token(FINOPS, CC_URLS[1] + "/api/alerts/billing"))).status_code
R["pub_finops_expired"] = client.get(
    "/api/users", headers=bearer(google_token(FINOPS, CC_URLS[1], exp_delta=-3600))).status_code
R["pub_finops_unverified_email"] = client.get(
    "/api/users", headers=bearer(google_token(FINOPS, CC_URLS[1], verified=False))).status_code
# Legit (Do-No-Harm) paths
# Lane 4 (Q1/H2, register L4-a): the platform SA bearer is confined to its job routes (GET /api/users -> 403), so the
# legit bearer paths are exercised on the sync-spend job route.
R["pub_scheduler_legit_hash_url"] = client.post("/api/finops/sync-spend", headers=bearer(google_token(FINOPS, CC_URLS[1]))).status_code
R["pub_scheduler_legit_deterministic_url"] = client.post("/api/finops/sync-spend", headers=bearer(google_token(FINOPS, CC_URLS[0]))).status_code
R["pub_scheduler_sync_spend"] = client.post("/api/finops/sync-spend", headers=bearer(google_token(FINOPS, CC_URLS[1]))).status_code
R["pub_scheduler_sweep"] = client.post(
    "/api/workloads/sweep-expired-sandboxes", headers=bearer(google_token(FINOPS, CC_URLS[1]))).status_code
# Real budget-notification body (base64 JSON), as Cloud Billing publishes it. Seeded workload doc so the
# handler's Firestore write path runs too; 10 < 100 so no quarantine is triggered.
fake.collection("workloads").document("fd4e-billing-test").set({"budget_ceiling_monthly_usd": 100.0, "project_id": "fd4e-child"})
_billing = {"budgetDisplayName": "budget-fd4e-billing-test", "costAmount": 10.0, "budgetAmount": 100.0,
            "currencyCode": "USD", "costIntervalStart": "2026-10-01T07:00:00Z"}
_billing_data = base64.b64encode(json.dumps(_billing).encode()).decode()
r = client.post(
    "/api/alerts/billing", headers=bearer(google_token(FINOPS, CC_URLS[1] + "/api/alerts/billing")),
    json={"message": {"data": _billing_data, "messageId": "1"},
          "subscription": "projects/mock-stackvend-project/subscriptions/billing-push"})
R["pub_pubsub_push_billing"] = r.status_code
R["pub_pubsub_push_billing_body"] = [r.json().get("status"), r.json().get("product_id")] if r.status_code == 200 else r.text[:200]
R["pub_pubsub_push_billing_spend_written"] = (
    fake.collection("workloads").document("fd4e-billing-test").get().to_dict() or {}).get("current_spend_usd")
fake.collection("workloads").document("fd4e-billing-test").delete()
R["pub_pubsub_push_billing_anon"] = client.post(
    "/api/alerts/billing", json={"message": {"data": _billing_data}}).status_code
# X-CloudScheduler bypass removed
R["pub_viewer_sweep_with_header"] = client.post(
    "/api/workloads/sweep-expired-sandboxes", cookies=VIEWER_COOKIE, headers={"X-CloudScheduler": "true"}).status_code
R["pub_anon_sweep_with_header"] = client.post(
    "/api/workloads/sweep-expired-sandboxes", headers={"X-CloudScheduler": "true", "X-Appengine-Cron": "true"}).status_code
R["pub_owner_sweep_cookie"] = client.post("/api/workloads/sweep-expired-sandboxes", cookies=OWNER_COOKIE).status_code
# Google Sign-In
# Separate client: the login sets cookies in its jar, and `client` must stay cookie-free for later cases.
login_client = TestClient(main.app, raise_server_exceptions=False)
r = login_client.post("/auth/google-login", json={"credential": google_token("owner@example.com", LEGIT_CLIENT)})
R["pub_google_login_legit"] = r.status_code
R["pub_google_login_sets_cookie"] = bool(r.cookies.get("stackvend_session"))
login_cookie = r.cookies.get("stackvend_session") or ""
R["pub_cookie_from_login"] = TestClient(main.app, raise_server_exceptions=False).get(
    "/api/users", cookies={"stackvend_session": login_cookie}).status_code
R["pub_google_login_wrong_client"] = TestClient(main.app, raise_server_exceptions=False).post(
    "/auth/google-login", json={"credential": google_token("owner@example.com", "999-other.apps.googleusercontent.com")}).status_code
R["pub_viewer_cookie_admin_route"] = client.get("/api/users", cookies=VIEWER_COOKIE).status_code
mode("", urls=(), callers={FINOPS})
R["pub_discovery_failed_bearer"] = client.get("/api/users", headers=bearer(google_token(FINOPS, CC_URLS[1]))).status_code

# ================================================================ Direct-IAP mode
mode(IAP_AUD)
R["iap_valid_owner"] = client.get("/api/users", headers={"x-goog-iap-jwt-assertion": iap_token("owner@example.com", IAP_AUD)}).status_code
R["iap_valid_viewer_admin_route"] = client.get(
    "/api/users", headers={"x-goog-iap-jwt-assertion": iap_token("viewer@example.com", IAP_AUD)}).status_code
R["iap_header_without_jwt"] = client.get(
    "/api/users", headers={"x-goog-authenticated-user-email": "accounts.google.com:owner@example.com"}).status_code
R["iap_wrong_aud_lb"] = client.get(
    "/api/users", headers={"x-goog-iap-jwt-assertion": iap_token("owner@example.com", "/projects/123456789/global/backendServices/42")}).status_code
R["iap_wrong_issuer"] = client.get(
    "/api/users", headers={"x-goog-iap-jwt-assertion": iap_token("owner@example.com", IAP_AUD, iss="https://accounts.google.com")}).status_code
R["iap_expired"] = client.get(
    "/api/users", headers={"x-goog-iap-jwt-assertion": iap_token("owner@example.com", IAP_AUD, exp_delta=-600)}).status_code
R["iap_wrong_key"] = client.get(
    "/api/users", headers={"x-goog-iap-jwt-assertion": iap_token("owner@example.com", IAP_AUD, signer=google_signer)}).status_code
R["iap_alg_none"] = client.get(
    "/api/users", headers={"x-goog-iap-jwt-assertion": f"{b64({'alg': 'none', 'kid': IAP_KID})}."
                                                       f"{b64({'iss': 'https://cloud.google.com/iap', 'aud': IAP_AUD, 'email': 'owner@example.com'})}."}).status_code
R["iap_invalid_jwt_plus_admin_cookie"] = client.get(
    "/api/users", headers={"x-goog-iap-jwt-assertion": "garbage"}, cookies=OWNER_COOKIE).status_code
R["iap_scheduler_legit"] = client.post("/api/finops/sync-spend", headers=bearer(google_token(FINOPS, CC_URLS[1]))).status_code  # lane 4: SA confined to job routes
# FINOPS-IAP-ACCESS (owner 10-26): what IAP really forwards for the platform SA: its own bearer PLUS an IAP assertion
# naming the SA. Legit: accepted as the bearer (job routes only). Attacks: assertion alone / other bearer -> 401.
_finops_iap = {"x-goog-iap-jwt-assertion": iap_token(FINOPS, IAP_AUD)}
R["iap_fwd_scheduler_sync_spend"] = client.post(
    "/api/finops/sync-spend", headers={**_finops_iap, **bearer(google_token(FINOPS, CC_URLS[1]))}).status_code
R["iap_fwd_scheduler_sweep"] = client.post(
    "/api/workloads/sweep-expired-sandboxes", headers={**_finops_iap, **bearer(google_token(FINOPS, CC_URLS[0]))}).status_code
fake.collection("workloads").document("fd4e-billing-test").set({"budget_ceiling_monthly_usd": 100.0, "project_id": "fd4e-child"})
R["iap_fwd_pubsub_push_billing"] = client.post(
    "/api/alerts/billing", headers={**_finops_iap, **bearer(google_token(FINOPS, CC_URLS[1] + "/api/alerts/billing"))},
    json={"message": {"data": _billing_data, "messageId": "2"},
          "subscription": "projects/mock-stackvend-project/subscriptions/billing-push"}).status_code
fake.collection("workloads").document("fd4e-billing-test").delete()
R["iap_fwd_admin_route_still_confined"] = client.get(
    "/api/users", headers={**_finops_iap, **bearer(google_token(FINOPS, CC_URLS[1]))}).status_code
R["iap_fwd_assertion_only"] = client.post("/api/finops/sync-spend", headers=_finops_iap).status_code
R["iap_fwd_assertion_plus_foreign_bearer"] = client.post(
    "/api/finops/sync-spend",
    headers={**_finops_iap, **bearer(google_token("pwn@attacker-proj.iam.gserviceaccount.com", CC_URLS[1]))}).status_code
R["iap_fwd_assertion_plus_wrong_aud_bearer"] = client.post(
    "/api/finops/sync-spend",
    headers={**_finops_iap, **bearer(google_token(FINOPS, "https://orchestrator-gateway-service-x-uc.a.run.app"))}).status_code
R["iap_fwd_human_assertion_plus_finops_bearer"] = client.get(
    "/api/users", headers={"x-goog-iap-jwt-assertion": iap_token("owner@example.com", IAP_AUD),
                           **bearer(google_token(FINOPS, CC_URLS[1]))}).status_code  # human path unchanged (IAP wins)
R["iap_fwd_human_assertion_job_route"] = client.post(
    "/api/finops/sync-spend", headers={"x-goog-iap-jwt-assertion": iap_token("owner@example.com", IAP_AUD),
                                       **bearer(google_token(FINOPS, CC_URLS[1]))}).status_code

# ================================================================ F2: identity resolution runs off the event loop
import asyncio  # noqa: E402
import threading  # noqa: E402

import httpx  # noqa: E402

mode("")
_real_extract = auth.extract_user_email
_extract_on_main_thread = []


def _slow_extract(request):
    _extract_on_main_thread.append(threading.current_thread() is threading.main_thread())
    if request.headers.get("x-fd4e-slow"):
        time.sleep(1.5)  # blocking, like a stalled Admin API discovery or cert fetch
    return _real_extract(request)


async def _concurrency_probe():
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver", cookies=OWNER_COOKIE) as ac:
        done = []

        async def call(tag, headers):
            t0 = time.monotonic()
            resp = await ac.get("/api/users", headers=headers)
            done.append((tag, resp.status_code, time.monotonic() - t0))

        slow = asyncio.create_task(call("slow", {"x-fd4e-slow": "1"}))
        await asyncio.sleep(0.2)  # the slow request is now blocked inside extract_user_email
        await call("fast", {})
        await slow
        return done


auth.extract_user_email = _slow_extract
try:
    _done = asyncio.run(_concurrency_probe())
finally:
    auth.extract_user_email = _real_extract
R["f2_completion_order"] = [d[0] for d in _done]
R["f2_statuses"] = [d[1] for d in _done]
R["f2_fast_elapsed_under_1s"] = next(d[2] for d in _done if d[0] == "fast") < 1.0
R["f2_extract_ran_off_main_thread"] = len(_extract_on_main_thread) == 2 and not any(_extract_on_main_thread)

# ================================================================ first-run OAuth client-id bootstrap
from google.api_core import exceptions as gexc  # noqa: E402

mode("")
config.GOOGLE_OAUTH_CLIENT_ID = ""
config.GOOGLE_OAUTH_CLIENT_ID_ENV_PINNED = False  # first run = configured nowhere, no Terraform env pin (lane 19 L19-0c)
_sm = sm.SecretManagerServiceClient.return_value
fake.collection("platform_config").document("auth").delete()
anon = TestClient(main.app, raise_server_exceptions=False)
_phished = {"client_id": ATTACKER_CLIENT, "credential": google_token("owner@example.com", ATTACKER_CLIENT)}
_sm_writes_before = _sm.add_secret_version.call_count

# F1: a transient read error must never be treated as "first run" (fail closed, nothing stored),
# even with a valid owner token minted for the attacker's client.
_sm.access_secret_version.side_effect = gexc.ServiceUnavailable("Secret Manager 503 (simulated)")
R["fr_state_sm_transient"] = config.oauth_client_id_state()
R["fr_transient_sm_error_503"] = anon.post("/auth/config-client-id", json=_phished).status_code
_sm.access_secret_version.side_effect = gexc.PermissionDenied("403 (simulated)")
R["fr_transient_sm_denied_503"] = anon.post("/auth/config-client-id", json=_phished).status_code
_sm.access_secret_version.side_effect = gexc.NotFound("secret castor-oauth-client-id not found")
FS_FAIL.append(1)
R["fr_state_fs_transient"] = config.oauth_client_id_state()
R["fr_transient_fs_error_503"] = anon.post("/auth/config-client-id", json=_phished).status_code
FS_FAIL.clear()
R["fr_transient_nothing_stored"] = [config.GOOGLE_OAUTH_CLIENT_ID,
                                    fake.collection("platform_config").document("auth").get().exists,
                                    _sm.add_secret_version.call_count - _sm_writes_before]

# Genuine absence (Secret Manager NotFound AND no Firestore doc): first-run proceeds below.
R["fr_state_absent"] = config.oauth_client_id_state()
R["fr_precondition_unconfigured"] = config.get_google_oauth_client_id()
R["fr_no_credential"] = anon.post("/auth/config-client-id", json={"client_id": NEW}).status_code
R["fr_empty_id"] = anon.post("/auth/config-client-id", json={"client_id": "   "}).status_code
R["fr_malformed_id"] = anon.post("/auth/config-client-id", json={"client_id": "evil"}).status_code
R["fr_suffix_only_id"] = anon.post("/auth/config-client-id", json={"client_id": ".apps.googleusercontent.com"}).status_code
R["fr_attacker_own_account"] = anon.post("/auth/config-client-id", json={
    "client_id": ATTACKER_CLIENT, "credential": google_token("attacker@gmail.com", ATTACKER_CLIENT)}).status_code
R["fr_attacker_replays_owner_token"] = anon.post("/auth/config-client-id", json={
    "client_id": ATTACKER_CLIENT, "credential": google_token("owner@example.com", NEW)}).status_code
R["fr_still_unconfigured"] = config.GOOGLE_OAUTH_CLIENT_ID
R["fr_no_firestore_write_after_attacks"] = fake.collection("platform_config").document("auth").get().exists
R["fr_login_refused_unconfigured"] = anon.post(
    "/auth/google-login", json={"credential": google_token("owner@example.com", "999-other.apps.googleusercontent.com")}).status_code
r = anon.post("/auth/config-client-id", json={"client_id": NEW, "credential": google_token("owner@example.com", NEW)})
R["fr_owner_completes"] = r.status_code
R["fr_owner_completes_cookie"] = bool(r.cookies.get("stackvend_session"))
R["fr_configured_value"] = config.GOOGLE_OAUTH_CLIENT_ID
R["fr_configured_persisted"] = (fake.collection("platform_config").document("auth").get().to_dict() or {}).get("google_oauth_client_id", "")
R["fr_state_after_configured"] = config.oauth_client_id_state()
after = TestClient(main.app, raise_server_exceptions=False)
R["fr_after_unauthenticated"] = after.post("/auth/config-client-id", json={"client_id": ATTACKER_CLIENT}).status_code
R["fr_after_firstrun_proof_rejected"] = after.post("/auth/config-client-id", json={
    "client_id": ATTACKER_CLIENT, "credential": google_token("owner@example.com", ATTACKER_CLIENT)}).status_code
R["fr_after_viewer"] = after.post(
    "/auth/config-client-id", json={"client_id": "333-x.apps.googleusercontent.com"}, cookies=VIEWER_COOKIE).status_code
R["fr_after_value_unchanged"] = config.GOOGLE_OAUTH_CLIENT_ID
R["fr_after_admin_rotates"] = after.post(
    "/auth/config-client-id", json={"client_id": "333-x.apps.googleusercontent.com"}, cookies=OWNER_COOKIE).status_code
R["fr_after_rotated_value"] = config.GOOGLE_OAUTH_CLIENT_ID


# ================================================================ unit: session secret resolution
def _secret(env):
    try:
        return config._resolve_session_secret(env)
    except RuntimeError:
        return "RuntimeError"


R["secret_cloudrun_unset"] = _secret({"K_SERVICE": "x"})
R["secret_cloudrun_default"] = _secret({"K_SERVICE": "x", "SESSION_SECRET": DEFAULT_SECRET})
R["secret_cloudrun_short"] = _secret({"K_SERVICE": "x", "SESSION_SECRET": "a" * 31})
R["secret_cloudrun_ok"] = _secret({"K_SERVICE": "x", "SESSION_SECRET": "b" * 64}) == "b" * 64
_local = _secret({})
R["secret_local_unset_len"] = len(_local) if _local != "RuntimeError" else -1
R["secret_local_unset_random"] = _local != _secret({}) and _local != DEFAULT_SECRET
R["secret_process_value_not_default"] = config.SESSION_SECRET != DEFAULT_SECRET


# ================================================================ unit: runtime identity discovery
def _ri_tuple(ri):
    return [ri.iap_audience, list(ri.service_urls), sorted(ri.platform_callers)]


os.environ.pop("K_SERVICE", None)
R["discover_local_public"] = _ri_tuple(identity._discover())


class _Resp:
    def __init__(self, text="", js=None):
        self.text, self._js = text, js

    def json(self):
        return self._js

    def raise_for_status(self):
        return None


def _md_get(url, headers=None, timeout=None):
    assert headers == {"Metadata-Flavor": "Google"}
    if url.endswith("project/numeric-project-id"):
        return _Resp("123456789")
    if url.endswith("instance/region"):
        return _Resp("projects/123456789/regions/us-central1")
    raise AssertionError(url)


RUN_CALLS = []


def _run_get_factory(payload):
    def _get(self, url, timeout=None):
        RUN_CALLS.append(url)
        if isinstance(payload, Exception):
            raise payload
        return _Resp(js=payload)
    return _get


def _discover_with(payload):
    os.environ["K_SERVICE"] = "product-control-center-ui"
    try:
        with patch("requests.get", _md_get), \
                patch("google.auth.default", lambda scopes=None: (MagicMock(name="creds"), "mock-stackvend-project")), \
                patch("google.auth.transport.requests.AuthorizedSession.__init__", lambda self, creds: None), \
                patch("google.auth.transport.requests.AuthorizedSession.get", _run_get_factory(payload)):
            return identity._discover()
    finally:
        os.environ.pop("K_SERVICE", None)


ri = _discover_with({"iapEnabled": True, "urls": [CC_URLS[0], CC_URLS[1] + "/"], "uri": CC_URLS[1]})
R["discover_iap_enabled"] = _ri_tuple(ri)
R["discover_run_api_url"] = RUN_CALLS[-1]
R["discover_public_service"] = _ri_tuple(_discover_with({"urls": list(CC_URLS), "uri": CC_URLS[1]}))
R["discover_uri_only_fallback"] = _ri_tuple(_discover_with({"uri": CC_URLS[1]}))

identity.set_runtime_identity_for_tests(None)
os.environ["K_SERVICE"] = "product-control-center-ui"
try:
    with patch("requests.get", _md_get), \
            patch("time.sleep", lambda s: None), \
            patch("google.auth.default", lambda scopes=None: (MagicMock(name="creds"), "mock-stackvend-project")), \
            patch("google.auth.transport.requests.AuthorizedSession.__init__", lambda self, creds: None), \
            patch("google.auth.transport.requests.AuthorizedSession.get", _run_get_factory(RuntimeError("503 from Run API"))):
        _t0 = time.time()
        failed = identity.get_runtime_identity()
        R["discover_failure_fails_closed"] = _ri_tuple(failed)
        R["discover_failure_retry_scheduled"] = identity._retry_after > _t0
        R["discover_failure_not_cached"] = identity._cached is None
        _n = len(RUN_CALLS)
        identity.get_runtime_identity()  # inside the retry window: no new Admin API call
        R["discover_failure_backoff_no_call"] = len(RUN_CALLS) == _n
finally:
    os.environ.pop("K_SERVICE", None)
    identity.set_runtime_identity_for_tests(None)

# ================================================================ unit: platform caller allow-list
R["allowlist_exact_finops"] = auth.get_user_access_record(FINOPS).role.value if auth.get_user_access_record(FINOPS) else None
R["allowlist_other_sa_denied"] = auth.get_user_access_record("sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com") is None
R["allowlist_lookalike_denied"] = auth.get_user_access_record("sa-castor-finops@attacker-proj.iam.gserviceaccount.com") is None
R["allowlist_any_gsa_denied"] = auth.get_user_access_record("pwn@attacker-proj.iam.gserviceaccount.com") is None

R["shared_client_cookie_jar_empty"] = len(client.cookies) == 0
R["cert_urls_fetched"] = sorted(set(CERT_FETCHES))
R["network_attempts"] = NETWORK_ATTEMPTS
print(json.dumps(R))
