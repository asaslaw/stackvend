"""
FD-103 harness (NOT collected by pytest; run by tests/test_cc_first_run_fd103.py in a clean `python -I` subprocess).
Reuses the hermetic prefix of tests/cc_identity_harness.py (FD-4E) verbatim, exactly like
tests/cc_identity_harness_lane19.py: sockets/DNS refused and recorded, ADC disabled, Firestore/Secret Manager stubbed,
really-signed Google ID tokens, IAP assertions and session cookies.

Cases (SEC-HOTFIX-FIRST-RUN-CLIENT): one per step of the POST /auth/config-client-id route order, the R1a-02 replay
(also inside a forced IAP-discovery failure window, C-12), the unchanged legitimate sign-in paths, the Secret Manager
error rule of config.get_google_oauth_client_id, /health without has_google_oauth_client_id, and the absent-state
sign-in page (instructions only). Prints a single JSON object {case_id: value} as the last stdout line.
"""
import json
import os
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_PREFIX_MARKER = "# ================================================================ public mode"
with open(os.path.join(_HERE, "cc_identity_harness.py"), encoding="utf-8") as _f:
    _src = _f.read()
assert _PREFIX_MARKER in _src, "FD-4E harness prefix changed"
exec(compile(_src.split(_PREFIX_MARKER, 1)[0], os.path.join(_HERE, "cc_identity_harness.py"), "exec"), globals())
(R, NETWORK_ATTEMPTS, OWNER_COOKIE, VIEWER_COOKIE, TestClient, auth, config, fake, google_token, iap_token, main, mode,
 sm, identity, IAP_AUD, FS_FAIL, DocRef) = (
    globals()[_n] for _n in ("R", "NETWORK_ATTEMPTS", "OWNER_COOKIE", "VIEWER_COOKIE", "TestClient", "auth", "config",
                             "fake", "google_token", "iap_token", "main", "mode", "sm", "identity", "IAP_AUD", "FS_FAIL",
                             "DocRef"))

from google.api_core import exceptions as gexc  # noqa: E402
from routes import web  # noqa: E402

ATTACKER_CLIENT = "666-attacker.apps.googleusercontent.com"
NEW = "222-owner.apps.googleusercontent.com"
FS_CLIENT = "555-firestore.apps.googleusercontent.com"
PINNED = "123456789012-ccpinned.apps.googleusercontent.com"
_sm = sm.SecretManagerServiceClient.return_value


def _doc(name):
    """Reads the fake store directly (not through DocRef.get), so the harness's own checks are not counted."""
    d = fake.store.get(("platform_config", name))
    return dict(d) if d is not None else None


# Spies: the route must never verify a Google token, and strangers must cause no configuration read.
CALLS = {"verify": 0, "state": 0, "fs_platform_config_reads": 0}
_real_docref_get = DocRef.get


def _counting_get(self):
    if self.path and self.path[0] == "platform_config":
        CALLS["fs_platform_config_reads"] += 1
    return _real_docref_get(self)


DocRef.get = _counting_get
_real_verify = identity.verify_google_login_credential
_real_state = config.oauth_client_id_state


def _spy_verify(*a, **k):
    CALLS["verify"] += 1
    return _real_verify(*a, **k)


def _spy_state(*a, **k):
    CALLS["state"] += 1
    return _real_state(*a, **k)


identity.verify_google_login_credential = _spy_verify
config.oauth_client_id_state = _spy_state


def _unpinned_absent():
    """A hand install with no client anywhere: no env pin, Secret Manager NotFound, no Firestore value."""
    config.GOOGLE_OAUTH_CLIENT_ID = ""
    config.GOOGLE_OAUTH_CLIENT_ID_SOURCE = ""
    config.GOOGLE_OAUTH_CLIENT_ID_ENV_PINNED = False
    _sm.access_secret_version.side_effect = gexc.NotFound("secret castor-oauth-client-id not found")
    fake.collection("platform_config").document("auth").delete()


def _post(client, body, **kw):
    """One POST /auth/config-client-id, with what it changed: status, detail code, cookie, writes, calls."""
    before = {"auth": _doc("auth"), "identity": _doc("cc_identity"), "sm": _sm.add_secret_version.call_count,
              "client": config.GOOGLE_OAUTH_CLIENT_ID, "verify": CALLS["verify"], "state": CALLS["state"],
              "sm_reads": _sm.access_secret_version.call_count, "fs_reads": CALLS["fs_platform_config_reads"]}
    r = client.post("/auth/config-client-id", json=body, **kw)
    detail = None
    try:
        detail = r.json().get("detail")
    except Exception:
        detail = r.text[:200]
    return {
        "status": r.status_code,
        "code": detail.get("code") if isinstance(detail, dict) else None,
        "detail": detail,
        "set_cookie": "set-cookie" in r.headers,
        "auth_doc_unchanged": _doc("auth") == before["auth"],
        "cc_identity_unchanged": _doc("cc_identity") == before["identity"],
        "sm_writes": _sm.add_secret_version.call_count - before["sm"],
        "client_unchanged": config.GOOGLE_OAUTH_CLIENT_ID == before["client"],
        "verify_calls": CALLS["verify"] - before["verify"],
        "state_reads": CALLS["state"] - before["state"],
        "sm_reads": _sm.access_secret_version.call_count - before["sm_reads"],
        "fs_platform_config_reads": CALLS["fs_platform_config_reads"] - before["fs_reads"],
    }


mode("")  # public mode
c = TestClient(main.app, raise_server_exceptions=False)
web.publish_cc_identity()
_phished = {"client_id": ATTACKER_CLIENT, "credential": google_token("owner@example.com", ATTACKER_CLIENT)}

# ------------------------------------------------------------ route order, one case per step
# 1. pinned -> 409 (unchanged, before the identity check)
config.GOOGLE_OAUTH_CLIENT_ID = PINNED
config.GOOGLE_OAUTH_CLIENT_ID_SOURCE = "env"
config.GOOGLE_OAUTH_CLIENT_ID_ENV_PINNED = True
R["step1_pinned_anon"] = _post(c, _phished)
R["step1_pinned_admin"] = _post(c, {"client_id": NEW}, cookies=OWNER_COOKIE)

# 2. no session and no IAP identity -> 401, no configuration read
_unpinned_absent()
R["step2_anonymous"] = _post(c, _phished)
R["step2_anonymous_no_credential"] = _post(c, {"client_id": NEW})

# 3. a signed-in identity that is not ADMIN -> 403, no configuration read
R["step3_viewer"] = _post(c, _phished, cookies=VIEWER_COOKIE)
R["step3_unlisted_user"] = _post(c, _phished, cookies={"stackvend_session": auth.create_session_token("stranger@example.com")})

# 4. format -> 400 (after the identity check)
R["step4_admin_malformed"] = _post(c, {"client_id": "evil"}, cookies=OWNER_COOKIE)
R["step4_anonymous_malformed"] = _post(c, {"client_id": "evil"})

# 5. state unknown -> 503
_sm.access_secret_version.side_effect = gexc.ServiceUnavailable("Secret Manager 503 (simulated)")
R["step5_admin_unknown"] = _post(c, _phished, cookies=OWNER_COOKIE)
_unpinned_absent()

# 6. configured -> administrator rotation (unchanged, Do No Harm)
config.GOOGLE_OAUTH_CLIENT_ID = NEW
config.GOOGLE_OAUTH_CLIENT_ID_SOURCE = "secret_manager"
R["step6_admin_rotation"] = _post(c, {"client_id": "333-rotated.apps.googleusercontent.com"}, cookies=OWNER_COOKIE)
R["step6_rotated_value"] = config.GOOGLE_OAUTH_CLIENT_ID
R["step6_viewer_rotation"] = _post(c, {"client_id": ATTACKER_CLIENT}, cookies=VIEWER_COOKIE)
_unpinned_absent()

# 7. absent behind IAP -> 403 (row 41, unchanged)
mode(IAP_AUD)
R["step7_iap_admin_absent"] = _post(c, _phished, headers={"x-goog-iap-jwt-assertion": iap_token("owner@example.com", IAP_AUD)})
mode("")

# 8. absent -> typed 409 FIRST_RUN_CLIENT_OUT_OF_BAND (no token verification, no write, no cookie)
R["step8_admin_absent"] = _post(c, _phished, cookies=OWNER_COOKIE)
R["step8_admin_absent_no_credential"] = _post(c, {"client_id": NEW}, cookies=OWNER_COOKIE)
R["step8_state_after"] = _real_state()

# ------------------------------------------------------------ R1a-02 replay: the phished owner token for the attacker's client
_unpinned_absent()
R["replay_public"] = _post(c, _phished)
R["replay_public_client_after"] = config.GOOGLE_OAUTH_CLIENT_ID

# The same inside a forced IAP-discovery failure window (C-12): IAP trust is off, so the Control Center behaves like a
# public one for 30 s. Nothing is left to mint.
identity._cert_cache.clear()
identity._cached = None
identity._retry_after = time.time() + 30
R["window_identity_has_no_iap"] = identity.get_runtime_identity().iap_audience == ""
R["replay_window_anonymous"] = _post(c, _phished)
R["replay_window_admin_cookie"] = _post(c, _phished, cookies=OWNER_COOKIE)
R["replay_window_iap_assertion"] = _post(c, _phished, headers={"x-goog-iap-jwt-assertion": iap_token("owner@example.com", IAP_AUD)})
R["replay_window_client_after"] = config.GOOGLE_OAUTH_CLIENT_ID
mode("")

# ------------------------------------------------------------ legitimate sign-in paths (Do No Harm)
# Pinned env client: Google sign-in works.
config.GOOGLE_OAUTH_CLIENT_ID = PINNED
config.GOOGLE_OAUTH_CLIENT_ID_SOURCE = "env"
config.GOOGLE_OAUTH_CLIENT_ID_ENV_PINNED = True
r = TestClient(main.app, raise_server_exceptions=False).post(
    "/auth/google-login", json={"credential": google_token("owner@example.com", PINNED)})
R["legit_pinned_login"] = [r.status_code, bool(r.cookies.get("stackvend_session"))]

# A Firestore-configured install (Secret Manager NotFound, value in platform_config/auth) still signs in.
_unpinned_absent()
fake.collection("platform_config").document("auth").set({"google_oauth_client_id": FS_CLIENT})
r = TestClient(main.app, raise_server_exceptions=False).post(
    "/auth/google-login", json={"credential": google_token("owner@example.com", FS_CLIENT)})
R["legit_firestore_login"] = [r.status_code, bool(r.cookies.get("stackvend_session")), config.GOOGLE_OAUTH_CLIENT_ID_SOURCE]

# ------------------------------------------------------------ get_google_oauth_client_id: Secret Manager error rule
def _resolve_with(sm_effect, sm_value=None):
    config.GOOGLE_OAUTH_CLIENT_ID = ""
    config.GOOGLE_OAUTH_CLIENT_ID_SOURCE = ""
    config.GOOGLE_OAUTH_CLIENT_ID_ENV_PINNED = False
    fake.collection("platform_config").document("auth").set({"google_oauth_client_id": FS_CLIENT})
    _sm.access_secret_version.side_effect = sm_effect
    if sm_value is not None:
        import types as _t
        _sm.access_secret_version.return_value = _t.SimpleNamespace(payload=_t.SimpleNamespace(data=sm_value.encode()))
    got = config.get_google_oauth_client_id()
    return [got, config.GOOGLE_OAUTH_CLIENT_ID, config.GOOGLE_OAUTH_CLIENT_ID_SOURCE]


R["sm_permission_denied"] = _resolve_with(gexc.PermissionDenied("403 (simulated)"))
R["sm_unavailable"] = _resolve_with(gexc.ServiceUnavailable("503 (simulated)"))
R["sm_other_error"] = _resolve_with(RuntimeError("socket closed (simulated)"))
# Login during a Secret Manager outage is refused, not served from Firestore.
_resolve_with(gexc.PermissionDenied("403 (simulated)"))
r = TestClient(main.app, raise_server_exceptions=False).post(
    "/auth/google-login", json={"credential": google_token("owner@example.com", FS_CLIENT)})
R["sm_denied_login"] = [r.status_code, "set-cookie" in r.headers]
# Negative tests (unchanged): definitive absence falls through to Firestore; a Secret Manager value wins.
R["sm_not_found"] = _resolve_with(gexc.NotFound("not found (simulated)"))
R["sm_failed_precondition"] = _resolve_with(gexc.FailedPrecondition("no enabled version (simulated)"))
R["sm_value"] = _resolve_with(None, sm_value=NEW)
R["sm_empty_value"] = _resolve_with(None, sm_value="  ")

# ------------------------------------------------------------ /health without has_google_oauth_client_id
_unpinned_absent()
h = c.get("/health")
R["health_status"] = h.status_code
R["health_keys"] = sorted(h.json())

# ------------------------------------------------------------ absent-state sign-in page: instructions only
_unpinned_absent()
page = c.get("/", headers={"accept": "text/html"})
R["page_status"] = page.status_code
R["page_text"] = page.text



# ------------------------------------------------------------ fail loudly when the configuration cannot be read
def _login(body):
    before = {"sm": _sm.access_secret_version.call_count, "fs": CALLS["fs_platform_config_reads"],
              "verify": CALLS["verify"]}
    r = TestClient(main.app, raise_server_exceptions=False).post("/auth/google-login", json=body)
    try:
        detail = r.json().get("detail")
    except Exception:
        detail = r.text[:200]
    return {"status": r.status_code, "code": detail.get("code") if isinstance(detail, dict) else None,
            "set_cookie": "set-cookie" in r.headers, "sm_reads": _sm.access_secret_version.call_count - before["sm"],
            "fs_platform_config_reads": CALLS["fs_platform_config_reads"] - before["fs"],
            "verify_calls": CALLS["verify"] - before["verify"]}


def _x_data(text):
    from html.parser import HTMLParser

    class _P(HTMLParser):
        found = None

        def handle_starttag(self, tag, attrs):
            if tag == "body":
                type(self).found = dict(attrs).get("x-data")

    p = _P(convert_charrefs=True)
    p.feed(text)
    return p.found


_owner_token = google_token("owner@example.com", FS_CLIENT)
# Secret Manager outage: typed 503, no Firestore fallback, no session.
_unpinned_absent()
fake.collection("platform_config").document("auth").set({"google_oauth_client_id": FS_CLIENT})
_sm.access_secret_version.side_effect = gexc.ServiceUnavailable("Secret Manager 503 (simulated)")
R["login_sm_outage"] = _login({"credential": _owner_token})
R["login_sm_outage_missing_credential"] = _login({})
R["page_sm_outage_x_data"] = _x_data(c.get("/", headers={"accept": "text/html"}).text)
# Firestore outage after a definitive Secret Manager absence: typed 503 too.
_unpinned_absent()
_sm.access_secret_version.side_effect = gexc.NotFound("not found (simulated)")
FS_FAIL.append(1)
R["login_fs_outage"] = _login({"credential": _owner_token})
R["page_fs_outage_x_data"] = _x_data(c.get("/", headers={"accept": "text/html"}).text)
FS_FAIL.clear()
# Negative tests: absent stays "not configured" (401, setup panel); configured is unaffected.
_unpinned_absent()
R["login_absent"] = _login({"credential": _owner_token})
R["page_absent_x_data"] = _x_data(c.get("/", headers={"accept": "text/html"}).text)
_unpinned_absent()
fake.collection("platform_config").document("auth").set({"google_oauth_client_id": FS_CLIENT})
R["login_configured"] = _login({"credential": _owner_token})
R["page_configured_x_data"] = _x_data(c.get("/", headers={"accept": "text/html"}).text)
R["login_configured_cached"] = _login({"credential": _owner_token})

R["network_attempts"] = NETWORK_ATTEMPTS
print(json.dumps(R))
