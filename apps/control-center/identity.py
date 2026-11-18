"""
StackVend Control Center: verified caller identity (FD-4E).

Single home for every identity decision. Rules:
- IAP identity only from a verified ES256 x-goog-iap-jwt-assertion, and only when Cloud Run
  reports iapEnabled for THIS service (Admin API, not a header or env flag).
- Service bearers only from the exact platform caller SA, only for this service's own URLs.
- Google Sign-In credentials only for a configured OAuth client ID (never audience=None).
- A failed verification means unauthenticated. There is no unverified decode.

google-auth modules are imported inside the functions that use them (not at module import):
several root-suite test files replace `google.auth` with a MagicMock in sys.modules before the
Control Center is imported, and a module-level `import google.auth.jwt` would then fail to import.
"""
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import FrozenSet, Optional, Tuple

import config

logger = logging.getLogger("control-center-identity")

IAP_ISSUER = "https://cloud.google.com/iap"
IAP_CERTS_URL = "https://www.gstatic.com/iap/verify/public_key"
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")
CLOCK_SKEW_SECONDS = 10
CERT_TTL_SECONDS = 3600
DISCOVERY_RETRY_SECONDS = 30
_METADATA = "http://metadata.google.internal/computeMetadata/v1/"
_RUN_SERVICE_URL = "https://run.googleapis.com/v2/projects/{project}/locations/{region}/services/{service}"


@dataclass(frozen=True)
class RuntimeIdentity:
    iap_audience: str = ""                          # non-empty <=> Cloud Run reports iapEnabled
    service_urls: Tuple[str, ...] = ()              # this service's status urls (both run.app forms)
    platform_callers: FrozenSet[str] = frozenset()  # exact SA emails allowed to call with an OIDC bearer


_lock = threading.Lock()
_cached: Optional[RuntimeIdentity] = None
_retry_after = 0.0
_cert_cache: dict = {}
_transport_obj = None


def _transport():
    global _transport_obj
    if _transport_obj is None:
        from google.auth.transport import requests as google_requests
        _transport_obj = google_requests.Request()
    return _transport_obj


def platform_callers() -> FrozenSet[str]:
    """Exact allow-list of service accounts that may call the CC with an OIDC bearer. EMPTY since C10 (owner 11-07,
    register row C10-MACHINE-CALLERS-OFF-CC): nothing machine-calls the Control Center any more (the two schedulers run
    Cloud Run jobs, the billing subscription is drained by a job). Fail closed: every service bearer is refused, so
    the PUBSUB_PUSH route refuses every caller and ADMIN routes accept humans only."""
    return frozenset()


def _discover() -> RuntimeIdentity:
    service = os.getenv("K_SERVICE", "")
    project = (config.PROJECT_ID or os.getenv("PROJECT_ID", "")).strip()
    callers = platform_callers()
    if not service or not project:
        return RuntimeIdentity(platform_callers=callers)  # local dev / tests: public mode, no bearer audiences
    import google.auth
    import requests
    from google.auth.transport.requests import AuthorizedSession

    md = {"Metadata-Flavor": "Google"}
    number = requests.get(_METADATA + "project/numeric-project-id", headers=md, timeout=2).text.strip()
    region_path = requests.get(_METADATA + "instance/region", headers=md, timeout=2).text.strip()
    region = region_path.rsplit("/", 1)[-1]  # documented form: projects/<number>/regions/<region>
    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    resp = AuthorizedSession(creds).get(
        _RUN_SERVICE_URL.format(project=project, region=region, service=service), timeout=5
    )
    resp.raise_for_status()
    svc = resp.json()
    urls = tuple(u.rstrip("/") for u in (svc.get("urls") or [svc.get("uri", "")]) if u)
    iap_aud = f"/projects/{number}/locations/{region}/services/{service}" if svc.get("iapEnabled") else ""
    return RuntimeIdentity(iap_audience=iap_aud, service_urls=urls, platform_callers=callers)


def get_runtime_identity() -> RuntimeIdentity:
    """Cached after first success. On failure: fail closed (no IAP trust, no bearer) and retry after 30 s."""
    global _cached, _retry_after
    if _cached is not None:
        return _cached
    with _lock:
        if _cached is not None:
            return _cached
        if time.time() < _retry_after:
            return RuntimeIdentity(platform_callers=platform_callers())
        last_err = None
        for delay in (0.0, 0.5, 1.5):
            if delay:
                time.sleep(delay)
            try:
                _cached = _discover()
                logger.info(
                    "CC identity mode: %s; bearer audiences=%d; platform callers=%s",
                    f"IAP (aud={_cached.iap_audience})" if _cached.iap_audience else "PUBLIC (IAP headers ignored)",
                    len(_cached.service_urls), sorted(_cached.platform_callers),
                )
                return _cached
            except Exception as e:  # noqa: BLE001 - logged and fails closed
                last_err = e
        _retry_after = time.time() + DISCOVERY_RETRY_SECONDS
        logger.error(
            "CC runtime identity discovery failed (%s). IAP and service-bearer auth are DISABLED (fail closed); retry in %ss.",
            last_err, DISCOVERY_RETRY_SECONDS,
        )
        return RuntimeIdentity(platform_callers=platform_callers())


def set_runtime_identity_for_tests(ri: Optional[RuntimeIdentity]) -> None:
    global _cached, _retry_after
    _cached, _retry_after = ri, 0.0


def _certs(url: str, kid: Optional[str]) -> dict:
    from google.oauth2 import id_token
    hit = _cert_cache.get(url)
    if hit and hit[0] > time.time() and (kid is None or kid in hit[1]):
        return hit[1]
    certs = id_token._fetch_certs(_transport(), url)  # refetch on TTL expiry or unknown kid (key rotation)
    _cert_cache[url] = (time.time() + CERT_TTL_SECONDS, certs)
    return certs


def verify_iap_assertion(assertion: str, ri: RuntimeIdentity) -> str:
    import google.auth.jwt
    kid = google.auth.jwt.decode_header(assertion).get("kid")
    info = google.auth.jwt.decode(
        assertion, certs=_certs(IAP_CERTS_URL, kid), audience=ri.iap_audience,
        clock_skew_in_seconds=CLOCK_SKEW_SECONDS,
    )
    if info.get("iss") != IAP_ISSUER:
        raise ValueError(f"wrong IAP issuer {info.get('iss')!r}")
    email = (info.get("email") or "").strip().lower()
    if not email:
        raise ValueError("IAP assertion has no email claim")
    return email


def verify_service_bearer_claims(token: str, path: str, ri: RuntimeIdentity) -> Tuple[str, str]:
    """(email, aud) of a verified platform-caller OIDC bearer. `aud` is one of this service's URLs, or
    URL+path; route policies (authz.PUBSUB_PUSH) can require the exact per-path audience."""
    if not ri.service_urls or not ri.platform_callers:
        raise ValueError("service bearer auth unavailable (runtime identity not discovered)")
    from google.oauth2 import id_token
    audiences = list(ri.service_urls) + [u + path for u in ri.service_urls]  # exact membership
    info = id_token.verify_oauth2_token(token, _transport(), audience=audiences, clock_skew_in_seconds=CLOCK_SKEW_SECONDS)
    email = (info.get("email") or "").strip().lower()
    if not info.get("email_verified") or email not in ri.platform_callers:
        raise ValueError(f"bearer principal {email!r} is not an allow-listed platform caller")
    aud = info.get("aud")
    return email, aud if isinstance(aud, str) else ""


def verify_service_bearer(token: str, path: str, ri: RuntimeIdentity) -> str:
    return verify_service_bearer_claims(token, path, ri)[0]


def verify_google_login_credential(credential: str, client_id: str) -> dict:
    if not client_id:
        raise ValueError("Google Sign-In is not configured on this install.")
    from google.oauth2 import id_token
    info = id_token.verify_oauth2_token(credential, _transport(), audience=client_id, clock_skew_in_seconds=CLOCK_SKEW_SECONDS)
    if info.get("iss") not in GOOGLE_ISSUERS:
        raise ValueError(f"Invalid token issuer: {info.get('iss')}")
    if not info.get("email_verified", False):
        raise ValueError("Google account email is not verified.")
    if not (info.get("email") or "").strip():
        raise ValueError("No email found in verified Google token.")
    return info
