"""
FD-4M: Control Center identity/exposure harness (NOT collected by pytest; run by
tests/test_cc_identity_fd4m.py in a clean subprocess with `python -I`).

Reuses the hermetic prefix of tests/cc_identity_harness.py (FD-4E) verbatim: outbound sockets and DNS are
refused and recorded, ADC is disabled, Firestore/Secret Manager are stubbed, tokens are really signed.
It runs as a fresh process so Starlette builds the middleware stack from the code under test (never patch
AuthorizationMiddleware in-process: BaseHTTPMiddleware binds `dispatch` when the stack is first built).

Cookies are always passed explicitly: httpx does not resend `Secure` cookies from its jar over http://.

Usage: python -I tests/cc_identity_harness_fd4m.py [main|unset|empty]
  main  : ADMIN_EMAIL=owner@example.com (the FD-4E setting)
  unset : ADMIN_EMAIL not in the environment
  empty : ADMIN_EMAIL=""
Prints a single JSON object {case_id: value} as the last stdout line.
"""
import json
import os
import sys

MODE = sys.argv[1] if len(sys.argv) > 1 else "main"
assert MODE in ("main", "unset", "empty"), MODE

_HERE = os.path.dirname(os.path.abspath(__file__))
_PREFIX_MARKER = "# ================================================================ public mode"
_ADMIN_LINE = 'os.environ["ADMIN_EMAIL"] = "owner@example.com"\n'
with open(os.path.join(_HERE, "cc_identity_harness.py"), encoding="utf-8") as _f:
    _src = _f.read()
assert _PREFIX_MARKER in _src and _src.count(_ADMIN_LINE) == 1, "FD-4E harness prefix changed"
_prefix = _src.split(_PREFIX_MARKER, 1)[0]
if MODE == "unset":
    _prefix = _prefix.replace(_ADMIN_LINE, 'os.environ.pop("ADMIN_EMAIL", None)\n')
elif MODE == "empty":
    _prefix = _prefix.replace(_ADMIN_LINE, 'os.environ["ADMIN_EMAIL"] = ""\n')
# Defines: fake, client, main, auth, config, identity, mode(), google_token(), iap_token(), bearer(),
# OWNER_COOKIE, VIEWER_COOKIE, FINOPS, IAP_AUD, LEGIT_CLIENT, NETWORK_ATTEMPTS, R, TestClient, ...
exec(compile(_prefix, os.path.join(_HERE, "cc_identity_harness.py"), "exec"), globals())
R = globals()["R"]  # bound by the exec above; named here so static checks (ruff F821 in CI) can see it
# Bound by the exec above and named here so static checks see them: CI runs ruff F821 with
# --ignore-noqa (code-RT finding 5), so a noqa comment cannot hide an undefined name.
(
    CC_URLS, FINOPS, IAP_AUD, LEGIT_CLIENT, NETWORK_ATTEMPTS, OWNER_COOKIE, TestClient, VIEWER_COOKIE, auth,
    bearer, config, fake, google_token, iap_token, main, mode,
) = (globals()[_n] for _n in (
    "CC_URLS", "FINOPS", "IAP_AUD", "LEGIT_CLIENT", "NETWORK_ATTEMPTS", "OWNER_COOKIE", "TestClient",
    "VIEWER_COOKIE", "auth", "bearer", "config", "fake", "google_token", "iap_token", "main", "mode",
))


USERS = fake.collection("authorized_users")


def cookie(email):
    return {"stackvend_session": auth.create_session_token(email)}


def role_of(email):
    rec = auth.get_user_access_record(email)
    return rec.role.value if rec else None


def fresh():
    return TestClient(main.app, raise_server_exceptions=False)


def set_cookie_headers(resp):
    return resp.headers.get_list("set-cookie")


def _attrs(header):
    """Lower-cased cookie attribute names/values after the first name=value pair."""
    return [p.strip().lower() for p in header.split(";")[1:]]


class _BoomDB:
    """Firestore that raises on every lookup (outage)."""

    def collection(self, *a, **k):
        # FD-4CI-b-3d: an outage is the typed "unavailable" error the Firestore client raises (the users routes keep a
        # break-glass copy of a failed grant only for that kind of error; any read error is an outage for auth).
        from google.api_core import exceptions as gexc
        raise gexc.ServiceUnavailable("Firestore unavailable (simulated)")


R["mode"] = MODE
R["config_default_admin_email"] = config.DEFAULT_ADMIN_EMAIL
R["registry_keys"] = sorted(auth.MOCK_AUTHORIZED_USERS)
R["sign_in_html_mentions_docs"] = any(t in auth.render_sign_in_html() for t in ("openapi", "/docs", "/redoc"))
R["sign_in_html_mentions_default_admin"] = any(
    t in auth.render_sign_in_html() for t in ("admin@castor.local", "admin@example.com"))

mode("")  # public mode
anon = fresh()

if MODE == "main":
    # ============================================================ F1: API docs gated
    for p in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
        r = anon.get(p)
        R[f"f1_anon{p}"] = [r.status_code, r.headers.get("content-type", "").split(";")[0], '"paths"' in r.text]
    R["f1_anon_health"] = anon.get("/health").status_code
    r = anon.post("/auth/google-login", json={"credential": "not-a-jwt"})
    R["f1_anon_google_login_bad_cred"] = [r.status_code, r.headers.get("content-type", "").split(";")[0]]
    r = anon.get("/")
    R["f1_anon_root"] = [r.status_code, "accounts.google.com/gsi/client" in r.text or "g_id_onload" in r.text
                         or "google-login" in r.text]
    for who, ck in (("viewer", VIEWER_COOKIE), ("owner", OWNER_COOKIE)):
        r = anon.get("/docs", cookies=ck)
        R[f"f1_{who}_docs"] = [r.status_code, "/openapi.json" in r.text]
        r = anon.get("/openapi.json", cookies=ck)
        paths = (r.json().get("paths") or {}) if r.status_code == 200 else {}
        R[f"f1_{who}_openapi"] = [r.status_code, sum(1 for k in paths if k.startswith("/api/")) >= 1]
        R[f"f1_{who}_redoc"] = anon.get("/redoc", cookies=ck).status_code
    r = anon.get("/docs", cookies=cookie("stranger@example.com"))
    R["f1_stranger_docs"] = [r.status_code, r.headers.get("content-type", "").split(";")[0]]
    # Lane 4 (Q1/H2, register L4-a): the platform SA bearer is confined to its job routes (GET /api/users -> 403).
    R["f1_finops_bearer_job_route"] = anon.post(
        "/api/finops/sync-spend", headers=bearer(google_token(FINOPS, CC_URLS[1]))).status_code
    R["f1_finops_bearer_openapi"] = anon.get(
        "/openapi.json", headers=bearer(google_token(FINOPS, CC_URLS[1]))).status_code
    mode(IAP_AUD)
    R["f1_iap_valid_openapi"] = anon.get(
        "/openapi.json", headers={"x-goog-iap-jwt-assertion": iap_token("viewer@example.com", IAP_AUD)}).status_code
    R["f1_iap_no_assertion_docs"] = anon.get("/docs").status_code
    mode("")

    # ============================================================ F2/H2/H3: Firestore authoritative
    OWNER = "owner@example.com"
    R["f2_owner_no_doc"] = role_of(OWNER)
    R["f2_owner_no_doc_http"] = anon.get("/api/users", cookies=OWNER_COOKIE).status_code
    for tag, doc in (
        ("bootstrap_string_true", {"role": "ADMIN", "is_active": "true"}),
        ("bool_true", {"role": "ADMIN", "is_active": True}),
        ("no_field", {"role": "ADMIN"}),
        ("viewer_doc", {"role": "VIEWER", "is_active": True}),
        ("bool_false", {"role": "ADMIN", "is_active": False}),
        ("string_false", {"role": "ADMIN", "is_active": "false"}),
        ("explicit_null", {"role": "ADMIN", "is_active": None}),
        ("garbage", {"role": "ADMIN", "is_active": "garbage"}),
    ):
        USERS.document(OWNER).set(doc)
        R[f"f2_owner_{tag}"] = role_of(OWNER)
        if tag in ("bool_false", "string_false", "bootstrap_string_true"):
            R[f"f2_owner_{tag}_http"] = anon.get("/api/users", cookies=OWNER_COOKIE).status_code
    USERS.document(OWNER).delete()

    USERS.document("bob@example.com").set({"role": "WORKLOAD_MANAGER", "is_active": "false"})
    R["f2_bob_string_false"] = role_of("bob@example.com")
    USERS.document("bob@example.com").set({"role": "WORKLOAD_MANAGER", "is_active": True, "assigned_workloads": ["w1"]})
    _bob = auth.get_user_access_record("bob@example.com")
    R["f2_bob_active"] = [_bob.role.value, _bob.assigned_workloads, _bob.is_active] if _bob else None
    USERS.document("bob@example.com").delete()
    R["f2_viewer_active"] = role_of("viewer@example.com")

    USERS.document(FINOPS).set({"role": "VIEWER", "is_active": False})
    R["f2_finops_inactive_doc"] = role_of(FINOPS)
    USERS.document(FINOPS).delete()

    # H2: stale in-memory grant after another instance deleted the Firestore doc
    r = anon.post("/api/users", cookies=OWNER_COOKIE,
                  json={"email": "carol@example.com", "role": "WORKLOAD_MANAGER", "assigned_workloads": []})
    R["f2_carol_added"] = [r.status_code, USERS.document("carol@example.com").get().exists]
    # N2: a successful Firestore write no longer populates the per-instance registry.
    R["n2_carol_in_registry_after_post"] = "carol@example.com" in auth.MOCK_AUTHORIZED_USERS
    R["f2_carol_active"] = role_of("carol@example.com")
    # A stale per-instance grant (e.g. written during an earlier outage) for the same user.
    auth.MOCK_AUTHORIZED_USERS["carol@example.com"] = auth.UserAccessRecord(
        email="carol@example.com", role="WORKLOAD_MANAGER", added_at="x", added_by="outage", is_active=True)
    USERS.document("carol@example.com").delete()  # as another instance's DELETE would
    R["f2_carol_still_in_local_registry"] = "carol@example.com" in auth.MOCK_AUTHORIZED_USERS
    R["f2_carol_after_fs_delete"] = role_of("carol@example.com")
    R["f2_carol_after_fs_delete_http"] = anon.get(
        "/", cookies=cookie("carol@example.com")).status_code

    # Break-glass: Firestore outage -> in-memory registry, then ADMIN_EMAIL
    _real_db = auth.db
    auth.db = _BoomDB()
    try:
        R["f2_outage_owner"] = role_of(OWNER)
        R["f2_outage_carol_registry"] = role_of("carol@example.com")
        R["f2_outage_viewer"] = role_of("viewer@example.com")
        R["f2_outage_finops"] = role_of(FINOPS)
    finally:
        auth.db = _real_db
    auth.db = None
    try:
        R["f2_db_none_owner"] = role_of(OWNER)
        R["f2_db_none_carol_registry"] = role_of("carol@example.com")
    finally:
        auth.db = _real_db
    auth.MOCK_AUTHORIZED_USERS.pop("carol@example.com", None)

    # ============================================================ N2: no resurrection during an outage
    r = anon.post("/api/users", cookies=OWNER_COOKIE,
                  json={"email": "frank@example.com", "role": "WORKLOAD_MANAGER", "assigned_workloads": []})
    R["n2_frank_added"] = [r.status_code, USERS.document("frank@example.com").get().exists,
                           "frank@example.com" in auth.MOCK_AUTHORIZED_USERS]
    r = anon.put("/api/users/frank@example.com/workloads", cookies=OWNER_COOKIE,
                 json={"assigned_workloads": ["w9"], "role": "VIEWER"})
    R["n2_frank_put"] = [r.status_code, "frank@example.com" in auth.MOCK_AUTHORIZED_USERS,
                         (USERS.document("frank@example.com").get().to_dict() or {}).get("role")]
    USERS.document("frank@example.com").delete()  # revoked on another instance
    import routes.users as _users_routes  # same module object main.py registered

    def _set_db(value):
        auth.db = value
        _users_routes.db = value

    _set_db(_BoomDB())
    try:
        R["n2_frank_outage_after_revoke"] = role_of("frank@example.com")
        # Firestore write fails -> the registry IS the break-glass store.
        r = anon.post("/api/users", cookies=OWNER_COOKIE,
                      json={"email": "hank@example.com", "role": "WORKLOAD_MANAGER", "assigned_workloads": []})
        R["n2_hank_post_during_outage"] = [r.status_code, role_of("hank@example.com")]
    finally:
        _set_db(_real_db)
    _set_db(None)
    try:
        r = anon.post("/api/users", cookies=OWNER_COOKIE,
                      json={"email": "gina@example.com", "role": "WORKLOAD_MANAGER", "assigned_workloads": []})
        R["n2_db_none_post"] = [r.status_code, role_of("gina@example.com")]
        r = anon.put("/api/users/gina@example.com/workloads", cookies=OWNER_COOKIE,
                     json={"assigned_workloads": ["w2"]})
        _gina = auth.get_user_access_record("gina@example.com")
        R["n2_db_none_put"] = [r.status_code, _gina.assigned_workloads if _gina else None]
    finally:
        _set_db(_real_db)
    for _e in ("hank@example.com", "gina@example.com"):
        auth.MOCK_AUTHORIZED_USERS.pop(_e, None)

    # ============================================================ N1: record build is type-normalised
    import datetime as _dt
    _ts = _dt.datetime(2026, 10, 1, 12, 0, tzinfo=_dt.timezone.utc)
    USERS.document(OWNER).set({"role": "VIEWER", "is_active": True, "added_at": _ts})
    R["n1_owner_viewer_ts_added_at"] = role_of(OWNER)
    USERS.document(OWNER).set({"role": "VIEWER", "is_active": True, "assigned_workloads": "wl-a"})
    R["n1_owner_viewer_str_workloads"] = role_of(OWNER)
    USERS.document(OWNER).delete()
    USERS.document("ivy@example.com").set({"role": "WORKLOAD_MANAGER", "is_active": True, "added_at": _ts,
                                           "assigned_workloads": ("w1", "w2")})
    _ivy = auth.get_user_access_record("ivy@example.com")
    R["n1_user_ts_added_at"] = [_ivy.role.value, _ivy.added_at, _ivy.assigned_workloads] if _ivy else None
    USERS.document("ivy@example.com").delete()
    # Negative (Do No Harm): a normal admin doc is returned field-for-field.
    USERS.document("jill@example.com").set({"role": "ADMIN", "is_active": True, "added_at": "2026-09-01T00:00:00+00:00",
                                            "added_by": "owner@example.com", "assigned_workloads": ["a", "b"]})
    _jill = auth.get_user_access_record("jill@example.com")
    R["n1_legit_admin_doc"] = [_jill.role.value, _jill.added_at, _jill.added_by, _jill.assigned_workloads] if _jill else None
    USERS.document("jill@example.com").delete()

    class _UnreadableDoc:
        exists = True

        def to_dict(self):
            raise ValueError("corrupt document (simulated)")

    class _UnreadableDB:
        def collection(self, *a, **k):
            return self

        def document(self, *a, **k):
            return self

        def get(self):
            return _UnreadableDoc()

    auth.db = _UnreadableDB()
    try:
        R["n1_owner_unreadable_doc"] = role_of(OWNER)
    finally:
        auth.db = _real_db

    # ============================================================ H8 / Q3: console delete guard
    USERS.document("dave@example.com").set({"role": "VIEWER", "is_active": True})
    r = anon.delete("/api/users/dave@example.com", cookies=OWNER_COOKIE)
    R["h8_delete_normal_user"] = [r.status_code, USERS.document("dave@example.com").get().exists]
    R["h8_delete_env_admin_guard"] = anon.delete("/api/users/owner@example.com", cookies=OWNER_COOKIE).status_code

    # ============================================================ F4: Secure cookie
    def _login(env_overrides):
        saved = {k: os.environ.get(k) for k in ("ENVIRONMENT", "K_SERVICE", "CC_INSECURE_LOCAL_COOKIES")}
        try:
            for k, v in env_overrides.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            return fresh().post("/auth/google-login", json={"credential": google_token(OWNER, LEGIT_CLIENT)})
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def _secure_flags(resp):
        hs = set_cookie_headers(resp)
        return [resp.status_code, sorted(h.split("=", 1)[0] for h in hs), ["secure" in _attrs(h) for h in hs]]

    for env_val in ("prod", "production", "dev", "test", None):
        R[f"f4_login_env_{env_val or 'unset'}"] = _secure_flags(
            _login({"ENVIRONMENT": env_val, "K_SERVICE": None, "CC_INSECURE_LOCAL_COOKIES": None}))
    R["f4_login_k_service_ignores_optout"] = _secure_flags(
        _login({"K_SERVICE": "product-control-center-ui", "CC_INSECURE_LOCAL_COOKIES": "true"}))
    R["f4_login_local_optout"] = _secure_flags(_login({"K_SERVICE": None, "CC_INSECURE_LOCAL_COOKIES": "true"}))
    R["f4_login_local_optout_other_value"] = _secure_flags(
        _login({"K_SERVICE": None, "CC_INSECURE_LOCAL_COOKIES": "false"}))
    _r = _login({"K_SERVICE": None, "CC_INSECURE_LOCAL_COOKIES": None})
    R["f4_login_set_cookie_raw"] = [h for h in set_cookie_headers(_r) if h.startswith("stackvend_session=")][0].split(";", 1)[1].strip()
    _tok = _r.cookies.get("stackvend_session") or ""
    R["f4_round_trip"] = fresh().get("/api/users", cookies={"stackvend_session": _tok}).status_code
    _lo = fresh().get("/auth/logout")
    R["f4_logout"] = [_lo.status_code, sorted(
        [h.split("=", 1)[0], sorted(a for a in _attrs(h) if not a.startswith("expires="))]
        for h in set_cookie_headers(_lo))]
    _lo = fresh().post("/auth/logout")
    R["f4_logout_post_status"] = _lo.status_code

else:
    # ============================================================ F3: no predictable default admin
    R["f3_castor_local_cookie_users"] = anon.get("/api/users", cookies=cookie("admin@castor.local")).status_code
    R["f3_castor_local_cookie_root"] = anon.get("/", cookies=cookie("admin@castor.local")).status_code
    R["f3_castor_local_record"] = role_of("admin@castor.local")
    R["f3_empty_email_record"] = role_of("")
    USERS.document("fsadmin@example.com").set({"role": "ADMIN", "is_active": True})
    R["f3_fs_admin_users"] = anon.get("/api/users", cookies=cookie("fsadmin@example.com")).status_code
    USERS.document("erin@example.com").set({"role": "VIEWER", "is_active": True})
    r = anon.delete("/api/users/erin@example.com", cookies=cookie("fsadmin@example.com"))
    R["f3_h8_delete_with_empty_admin"] = [r.status_code, USERS.document("erin@example.com").get().exists]
    _real_db = auth.db
    auth.db = _BoomDB()
    try:
        R["f3_outage_castor_local"] = role_of("admin@castor.local")
    finally:
        auth.db = _real_db

R["shared_anon_cookie_jar_empty"] = len(anon.cookies) == 0
R["network_attempts"] = NETWORK_ATTEMPTS
print(json.dumps(R))
