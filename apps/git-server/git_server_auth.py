"""FD-4K: Google ID-token authentication for castor-git-server.

Every request except the exact public paths must carry a Google-signed ID token in ``Authorization: Bearer``.
The token is verified in-app (RS256 signature against Google's published certs, ``exp``/``iat``, lifetime,
``aud`` in the allowed audiences, ``iss`` is Google, ``email_verified is True``, ``email`` in an exact allow-list).

Cloud Run IAM: when IAM validates the ``Authorization`` header it replaces the token signature with
``SIGNATURE_REMOVED_BY_GOOGLE`` before the request reaches the container. Clients therefore send the same token in
``X-Serverless-Authorization`` (validated and consumed by Cloud Run IAM) AND in ``Authorization`` (verified here).
A stripped signature is rejected with an explicit message. There is no "trust the front door" mode.

Configuration (no patterns; exact values only):
- ``GIT_SERVER_ALLOWED_INVOKERS``: comma-separated service-account emails. Unset: the server's own runtime SA
  (metadata server). Empty result: every request gets 503.
- ``GIT_SERVER_AUDIENCES``: comma-separated audiences (service URLs). Unset: the service's own ``uri``, ``urls[]``
  and ``customAudiences[]`` from the Cloud Run Admin v2 API. Empty result: 503.
- ``GIT_SERVER_READONLY_INVOKERS`` (FD-7L Phase 4, plan 2.10): comma-separated service-account emails that may call
  only the read routes (``main.READ_ONLY_ENDPOINTS``; every other route answers 403). Unset or empty: no read-only
  caller (nothing changes). An email that is also in ``GIT_SERVER_ALLOWED_INVOKERS`` keeps full access. The
  terraform runner job's identity is listed here (platform step B), never in ``GIT_SERVER_ALLOWED_INVOKERS``.
"""

import base64
import json
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple

logger = logging.getLogger("castor-git-server.auth")

PUBLIC_PATHS = frozenset({"/health", "/healthz"})
GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v1/certs"
GOOGLE_ISSUERS = frozenset({"accounts.google.com", "https://accounts.google.com"})
METADATA_ROOT = "http://metadata.google.internal/computeMetadata/v1/"
STRIPPED_SIGNATURE = "SIGNATURE_REMOVED_BY_GOOGLE"
CLOCK_SKEW_S = 30
MAX_TOKEN_LIFETIME_S = 3600
CERT_TTL_MAX_S = 3600
KID_REFETCH_MIN_INTERVAL_S = 60
CONFIG_TTL_S = 3600
RSA_SIGNATURE_BYTES = frozenset({256, 384, 512})  # RSA-2048/3072/4096


class AuthError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def _unauthorized(detail: str) -> AuthError:
    return AuthError(401, detail)


def _b64url_decode(segment: str) -> bytes:
    if not segment or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in segment):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _split_csv(value: str) -> List[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _default_http_get(url: str, headers: Optional[Mapping[str, str]] = None, timeout: float = 5.0) -> Tuple[int, Dict[str, str], bytes]:
    import requests

    resp = requests.get(url, headers=dict(headers or {}), timeout=timeout, allow_redirects=False)
    return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, resp.content


def _cache_max_age(headers: Mapping[str, str]) -> int:
    for directive in headers.get("cache-control", "").split(","):
        name, _, value = directive.strip().partition("=")
        if name.strip().lower() == "max-age" and value.strip().isdigit():
            return int(value.strip())
    return CERT_TTL_MAX_S


class GoogleIdTokenAuthenticator:
    """Verifies Google ID tokens. All network collaborators are injectable for hermetic tests."""

    def __init__(
        self,
        *,
        env: Optional[Mapping[str, str]] = None,
        http_get: Optional[Callable[..., Tuple[int, Dict[str, str], bytes]]] = None,
        service_lookup: Optional[Callable[[], Dict[str, Any]]] = None,
        clock: Callable[[], float] = time.time,
    ):
        self._env = env if env is not None else os.environ
        self._http_get = http_get or _default_http_get
        self._service_lookup = service_lookup or self._lookup_own_service
        self._clock = clock
        self._lock = threading.Lock()
        self._certs: Dict[str, str] = {}
        self._certs_expiry = 0.0
        self._certs_fetched_at = -1e18
        self._config: Optional[Tuple[FrozenSet[str], FrozenSet[str]]] = None
        self._config_expiry = 0.0
        self._readonly: FrozenSet[str] = frozenset()   # FD-7L Phase 4: read-route-only callers (resolved by config())

    # ------------------------------------------------------------------ configuration
    def _metadata(self, path: str) -> str:
        status, _, body = self._http_get(METADATA_ROOT + path, headers={"Metadata-Flavor": "Google"}, timeout=2.0)
        if status != 200:
            raise RuntimeError(f"metadata {path} returned HTTP {status}")
        return body.decode("utf-8").strip()

    def _lookup_own_service(self) -> Dict[str, Any]:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession

        service = self._env.get("K_SERVICE", "")
        project = self._env.get("PROJECT_ID", "") or self._metadata("project/project-id")
        region = self._metadata("instance/region").rsplit("/", 1)[-1]  # projects/N/regions/R -> R
        if not (service and project and region):
            raise RuntimeError("cannot identify own Cloud Run service (K_SERVICE/project/region)")
        creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        resp = AuthorizedSession(creds).get(
            f"https://run.googleapis.com/v2/projects/{project}/locations/{region}/services/{service}", timeout=5
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Cloud Run service lookup returned HTTP {resp.status_code}")
        return resp.json()

    def _resolve_config(self) -> Tuple[FrozenSet[str], FrozenSet[str]]:
        invokers_env = self._env.get("GIT_SERVER_ALLOWED_INVOKERS")
        if invokers_env is not None and invokers_env.strip():
            invokers = _split_csv(invokers_env)
        else:
            invokers = [self._metadata("instance/service-accounts/default/email")]
        audiences_env = self._env.get("GIT_SERVER_AUDIENCES")
        if audiences_env is not None and audiences_env.strip():
            audiences = _split_csv(audiences_env)
        else:
            svc = self._service_lookup()
            audiences = [svc.get("uri") or ""] + list(svc.get("urls") or []) + list(svc.get("customAudiences") or [])
        invoker_set = frozenset(i.casefold() for i in invokers if i)
        audience_set = frozenset(a.rstrip("/") for a in audiences if a and a.rstrip("/"))
        return invoker_set, audience_set

    def config(self) -> Tuple[FrozenSet[str], FrozenSet[str]]:
        """(allowed invoker emails, allowed audiences). Raises AuthError(503) when either is unavailable/empty."""
        with self._lock:
            now = self._clock()
            if self._config is not None and now < self._config_expiry:
                return self._config
            try:
                invokers, audiences = self._resolve_config()
            except Exception as cfg_err:
                logger.error(f"FD-4K auth config unavailable: {type(cfg_err).__name__}: {cfg_err}")
                raise AuthError(503, "authentication configuration unavailable") from None
            if not invokers or not audiences:
                logger.error("FD-4K auth config is empty (no allowed invokers or no audiences); refusing all requests")
                raise AuthError(503, "authentication configuration unavailable")
            if self._config != (invokers, audiences):
                logger.info(f"FD-4K git-server auth: allowed invokers={sorted(invokers)} audiences={sorted(audiences)}")
            readonly = self._resolve_readonly() - invokers   # a full invoker keeps full access
            if readonly != self._readonly:
                logger.info(f"FD-7L git-server auth: read-only invokers={sorted(readonly)}")
            self._readonly = readonly
            self._config, self._config_expiry = (invokers, audiences), now + CONFIG_TTL_S
            return self._config

    def _resolve_readonly(self) -> FrozenSet[str]:
        """FD-7L Phase 4: GIT_SERVER_READONLY_INVOKERS (exact emails; unset or empty = none). Never a fallback."""
        return frozenset(i.casefold() for i in _split_csv(self._env.get("GIT_SERVER_READONLY_INVOKERS") or ""))

    def readonly_invokers(self) -> FrozenSet[str]:
        """The read-route-only callers of the current configuration (empty when none are configured)."""
        self.config()
        return self._readonly

    # ------------------------------------------------------------------ certificates
    def _fetch_certs(self) -> None:
        try:
            status, headers, body = self._http_get(GOOGLE_CERTS_URL, timeout=5.0)
            if status != 200:
                raise RuntimeError(f"HTTP {status}")
            certs = json.loads(body.decode("utf-8"))
            if not isinstance(certs, dict) or not certs:
                raise RuntimeError("empty cert set")
        except Exception as cert_err:
            logger.error(f"FD-4K could not fetch Google signing certs: {type(cert_err).__name__}: {cert_err}")
            raise AuthError(503, "token verification keys unavailable") from None
        now = self._clock()
        self._certs = {str(k): str(v) for k, v in certs.items()}
        self._certs_fetched_at = now
        self._certs_expiry = now + min(_cache_max_age(headers), CERT_TTL_MAX_S)

    def _certs_for(self, kid: Optional[str]) -> Dict[str, str]:
        with self._lock:
            now = self._clock()
            if not self._certs or now >= self._certs_expiry:
                self._fetch_certs()
            elif kid is not None and kid not in self._certs and now - self._certs_fetched_at >= KID_REFETCH_MIN_INTERVAL_S:
                self._fetch_certs()  # key rotation; globally rate-limited so random kids cannot amplify
            return dict(self._certs)

    # ------------------------------------------------------------------ verification
    def authenticate(self, authorization_headers: List[str], *, read_route: bool = False) -> str:
        """Return the verified caller email or raise AuthError (401/403/503).
        FD-7L Phase 4: `read_route=True` (the middleware passes it only for a route in main.READ_ONLY_ENDPOINTS) also
        admits a GIT_SERVER_READONLY_INVOKERS caller; on any other route such a caller gets 403."""
        if len(authorization_headers) != 1:
            raise _unauthorized("exactly one Authorization: Bearer <Google ID token> header is required")
        scheme, _, token = authorization_headers[0].strip().partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            raise _unauthorized("Authorization must be 'Bearer <Google ID token>'")
        parts = token.split(".")
        if len(parts) != 3:
            raise _unauthorized("malformed ID token")
        if parts[2] == STRIPPED_SIGNATURE:
            raise _unauthorized(
                "ID token signature was removed by Cloud Run IAM; send the token in X-Serverless-Authorization "
                "as well as Authorization"
            )
        try:
            header = json.loads(_b64url_decode(parts[0]))
            signature = _b64url_decode(parts[2])
        except Exception:
            raise _unauthorized("malformed ID token") from None
        if not isinstance(header, dict) or header.get("alg") != "RS256":
            raise _unauthorized("ID token must be RS256")
        if len(signature) not in RSA_SIGNATURE_BYTES:
            raise _unauthorized("ID token signature is not an RSA signature")
        kid = header.get("kid")
        if kid is not None and not isinstance(kid, str):
            raise _unauthorized("malformed ID token")

        invokers, audiences = self.config()
        if not audiences:  # google.auth.jwt.decode(audience=None) would skip the audience check
            raise AuthError(503, "authentication configuration unavailable")
        certs = self._certs_for(kid)
        from google.auth import jwt as google_jwt

        try:
            claims = google_jwt.decode(token, certs=certs, audience=sorted(audiences), clock_skew_in_seconds=CLOCK_SKEW_S)
        except Exception as verify_err:
            aud = None
            try:
                aud = json.loads(_b64url_decode(parts[1])).get("aud")
            except Exception:
                pass
            logger.warning(f"FD-4K rejected ID token ({type(verify_err).__name__}: {verify_err}); presented aud={aud!r}")
            raise _unauthorized("ID token verification failed") from None

        if claims.get("iss") not in GOOGLE_ISSUERS:
            raise _unauthorized("ID token issuer is not Google")
        iat, exp = claims.get("iat"), claims.get("exp")
        if not isinstance(iat, int) or not isinstance(exp, int) or exp - iat > MAX_TOKEN_LIFETIME_S + CLOCK_SKEW_S:
            raise _unauthorized("ID token lifetime is not acceptable")
        email = claims.get("email")
        if claims.get("email_verified") is not True or not isinstance(email, str) or not email:
            raise AuthError(403, "caller identity is not a verified email")
        if email.casefold() not in invokers:
            if email.casefold() in self._readonly:
                if read_route:
                    return email
                logger.warning(f"FD-7L denied read-only caller {email!r} on a route that is not a read route")
                raise AuthError(403, "read-only caller: this route is not a read route")
            logger.warning(f"FD-4K denied caller {email!r}: not in the allowed invoker list")
            raise AuthError(403, "caller is not allowed to use this git server")
        return email
