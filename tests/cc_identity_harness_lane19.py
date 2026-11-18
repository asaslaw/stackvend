"""
Lane 19 L19-0c harness (NOT collected by pytest; run by tests/test_lane19_cc_identity.py in a clean `python -I`
subprocess). Reuses the hermetic prefix of tests/cc_identity_harness.py (FD-4E) verbatim, exactly like
tests/cc_identity_harness_fd4m.py: sockets/DNS refused and recorded, ADC disabled, Firestore/Secret Manager stubbed.

Cases: the Terraform pin guard on /auth/config-client-id (409, no Secret Manager / Firestore write) and the
platform_config/cc_identity record (source env | secret_manager | firestore | none | iap_only, revision).
Prints a single JSON object {case_id: value} as the last stdout line.
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PREFIX_MARKER = "# ================================================================ public mode"
with open(os.path.join(_HERE, "cc_identity_harness.py"), encoding="utf-8") as _f:
    _src = _f.read()
assert _PREFIX_MARKER in _src, "FD-4E harness prefix changed"
os.environ["K_REVISION"] = "product-control-center-ui-00042-abc"
exec(compile(_src.split(_PREFIX_MARKER, 1)[0], os.path.join(_HERE, "cc_identity_harness.py"), "exec"), globals())
(R, NETWORK_ATTEMPTS, OWNER_COOKIE, TestClient, config, fake, google_token, main, mode, sm, IAP_AUD) = (
    globals()[_n] for _n in ("R", "NETWORK_ATTEMPTS", "OWNER_COOKIE", "TestClient", "config", "fake",
                             "google_token", "main", "mode", "sm", "IAP_AUD"))

from routes import web  # noqa: E402

PINNED = "123456789012-ccpinned.apps.googleusercontent.com"
OTHER = "333-other.apps.googleusercontent.com"
_sm = sm.SecretManagerServiceClient.return_value


def _auth_doc():
    snap = fake.collection("platform_config").document("auth").get()
    return snap.to_dict() if snap.exists else None


def _identity_doc():
    snap = fake.collection("platform_config").document("cc_identity").get()
    return snap.to_dict() if snap.exists else None


mode("")  # public mode

# ------------------------------------------------------------ pinned: 409, nothing written anywhere
config.GOOGLE_OAUTH_CLIENT_ID = PINNED
config.GOOGLE_OAUTH_CLIENT_ID_SOURCE = "env"
config.GOOGLE_OAUTH_CLIENT_ID_ENV_PINNED = True
auth_before, sm_before = _auth_doc(), _sm.add_secret_version.call_count
c = TestClient(main.app, raise_server_exceptions=False)
r_admin = c.post("/auth/config-client-id", json={"client_id": OTHER}, cookies=OWNER_COOKIE)
r_anon = c.post("/auth/config-client-id", json={"client_id": OTHER, "credential": google_token("owner@example.com", OTHER)})
R["pinned_admin_status"] = r_admin.status_code
R["pinned_anon_status"] = r_anon.status_code
R["pinned_detail_names_tfvar"] = "cc_google_oauth_client_id" in (r_admin.json().get("detail") or "")
R["pinned_no_sm_write"] = _sm.add_secret_version.call_count - sm_before
R["pinned_auth_doc_unchanged"] = _auth_doc() == auth_before
R["pinned_value_unchanged"] = config.GOOGLE_OAUTH_CLIENT_ID

# ------------------------------------------------------------ cc_identity record
fake.collection("platform_config").document("cc_identity").delete()
web.publish_cc_identity()
rec = _identity_doc() or {}
R["record_env"] = [rec.get("google_client_id"), rec.get("source"), rec.get("env_pinned"), rec.get("revision")]
R["record_keys"] = sorted(rec)

mode(IAP_AUD)  # behind Direct IAP: row 41, no Google Sign-In session at all
web.publish_cc_identity()
R["record_iap_source"] = (_identity_doc() or {}).get("source")
mode("")

# ------------------------------------------------------------ not pinned: route unchanged (Do No Harm)
config.GOOGLE_OAUTH_CLIENT_ID_ENV_PINNED = False
config.GOOGLE_OAUTH_CLIENT_ID_SOURCE = "secret_manager"
config.GOOGLE_OAUTH_CLIENT_ID = "111-legit.apps.googleusercontent.com"
sm_before = _sm.add_secret_version.call_count
r_rot = c.post("/auth/config-client-id", json={"client_id": OTHER}, cookies=OWNER_COOKIE)
R["unpinned_admin_rotation_status"] = r_rot.status_code
R["unpinned_rotation_sm_writes"] = _sm.add_secret_version.call_count - sm_before
R["unpinned_rotation_record_source"] = (_identity_doc() or {}).get("source")
R["unpinned_rotation_record_client"] = (_identity_doc() or {}).get("google_client_id")
R["unpinned_bad_id_status"] = c.post("/auth/config-client-id", json={"client_id": "evil"}, cookies=OWNER_COOKIE).status_code

# ------------------------------------------------------------ startup publishes the record
fake.collection("platform_config").document("cc_identity").delete()
with TestClient(main.app, raise_server_exceptions=False):
    pass
R["startup_published"] = _identity_doc() is not None

# ------------------------------------------------------------ publish never raises
class _Boom:
    def collection(self, *a, **k):
        raise RuntimeError("503 Firestore unavailable (simulated)")


import db as _dbmod  # noqa: E402
_saved = _dbmod.db
_dbmod.db = _Boom()
try:
    web.publish_cc_identity()
    R["publish_outage_swallowed"] = True
except Exception:
    R["publish_outage_swallowed"] = False
finally:
    _dbmod.db = _saved

# ------------------------------------------------------------ RT F6: source names the store that holds the value
import types  # noqa: E402

config.GOOGLE_OAUTH_CLIENT_ID_ENV_PINNED = False
config.GOOGLE_OAUTH_CLIENT_ID_SOURCE = "secret_manager"
config.GOOGLE_OAUTH_CLIENT_ID = "111-legit.apps.googleusercontent.com"
_sm.add_secret_version.side_effect = RuntimeError("Secret Manager 503 (simulated)")
R["f6_sm_write_failed_status"] = c.post("/auth/config-client-id", json={"client_id": OTHER},
                                        cookies=OWNER_COOKIE).status_code
R["f6_sm_write_failed_record"] = [(_identity_doc() or {}).get("source"), (_identity_doc() or {}).get("google_client_id"),
                                  (_auth_doc() or {}).get("google_oauth_client_id")]
_sm.add_secret_version.side_effect = None

# ------------------------------------------------------------ RT F3: lazy resolution after a failed boot read
config.GOOGLE_OAUTH_CLIENT_ID = ""
config.GOOGLE_OAUTH_CLIENT_ID_SOURCE = ""
fake.collection("platform_config").document("auth").delete()
_sm.access_secret_version.side_effect = RuntimeError("Secret Manager 503 (simulated)")
web.publish_cc_identity()  # what the startup hook publishes after a failed import-time read
R["f3_boot_record"] = [(_identity_doc() or {}).get("source"), (_identity_doc() or {}).get("google_client_id")]
config.get_google_oauth_client_id()  # still failing: nothing changed, record stays "none"
R["f3_still_failing_record"] = (_identity_doc() or {}).get("source")
LAZY = "444-lazy.apps.googleusercontent.com"
_sm.access_secret_version.side_effect = None
_sm.access_secret_version.return_value = types.SimpleNamespace(payload=types.SimpleNamespace(data=LAZY.encode()))
R["f3_lazy_value"] = config.get_google_oauth_client_id()
R["f3_lazy_record"] = [(_identity_doc() or {}).get("source"), (_identity_doc() or {}).get("google_client_id")]

# same through oauth_client_id_state(): SM says NotFound, Firestore holds the value
from google.api_core import exceptions as _gexc  # noqa: E402

config.GOOGLE_OAUTH_CLIENT_ID = ""
config.GOOGLE_OAUTH_CLIENT_ID_SOURCE = ""
web.publish_cc_identity()
_sm.access_secret_version.side_effect = _gexc.NotFound("secret castor-oauth-client-id not found")
fake.collection("platform_config").document("auth").set({"google_oauth_client_id": OTHER})
R["f3_state"] = config.oauth_client_id_state()
R["f3_state_record"] = [(_identity_doc() or {}).get("source"), (_identity_doc() or {}).get("google_client_id")]
_sm.access_secret_version.side_effect = None

R["network_attempts"] = NETWORK_ATTEMPTS
print(json.dumps(R, default=str))
