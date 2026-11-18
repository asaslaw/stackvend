"""
FD-7L Phase 5a (SAT-31; plan docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3, sections 2.3, 2.12, 2.13,
8 row 5; register rows "FD-7L plan", FD-7L Phase 1 and FD-7L-n): the terraform SERVER's side of "one execution per
credentialed run" (D3-a).

* `TfApplierDispatchFailed`: the typed failure of a tf-applier dispatch (`TF_APPLIER_DISPATCH_FAILED`). It replaces
  the old "execute in-process" fallback of `/deploy-async` on every install: a deploy that could not be handed to a
  tf-applier execution is reported FAILED for an operator, never run inside the shared server container.
* `DispatchClient`: on a Per-workload install `/deploy-async` asks vending `POST /runner/dispatch` (mode `deploy`) with
  the server's own Google ID token. Vending signs the dispatch record, creates the single-use nonce and runs the
  tf-applier job with ONLY that nonce in its environment; the server never sees the nonce or any token. The call is
  never retried (a retry could start a second execution for the same deploy).
* `authenticate_workload_caller` / `workload_callers`: plan 2.13 route caller allow-list (Per-workload installs only).
  The server's workload routes accept only Google-signed ID tokens of `TF_SERVER_WORKLOAD_CALLERS` (Terraform-owned,
  plan step A: workflow, gateway, Control Center, vending); before step A the same exact emails are derived from
  `PROJECT_ID` and the fixed account ids (pinned against `infra/platform/*.tf` by a test).
* `check_request_target`: a request `target_project_id` is accepted only when it equals the project of vending's SIGNED,
  READY runner identity record (`RUNNER_TARGET_MISMATCH` otherwise).

Every refusal is a `shared.runner_identity.RunnerIdentityError` (code, stage, HTTP status). Nothing here logs an
Authorization header, an ID token or a dispatch nonce.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from shared import runner_identity as ri

logger = logging.getLogger("tf-runner-dispatch")

# ------------------------------------------------------------------------------------------------ typed classes
TF_APPLIER_DISPATCH_FAILED = "TF_APPLIER_DISPATCH_FAILED"
RUNNER_MODE_UNSUPPORTED = "RUNNER_MODE_UNSUPPORTED"       # same class as the job's (runner_credentials)
RUNNER_IDENTITY_NOT_READY = "RUNNER_IDENTITY_NOT_READY"
RUNNER_TARGET_MISMATCH = "RUNNER_TARGET_MISMATCH"
# Route caller refusals: the same codes vending's caller-checked routes answer (destructive_guard.authenticate_caller).
CALLERS_UNCONFIGURED = "CALLERS_UNCONFIGURED"
UNAUTHENTICATED = "UNAUTHENTICATED"
CALLER_NOT_ALLOWED = "CALLER_NOT_ALLOWED"

DISPATCH_STAGE = "terraform-dispatch"
CALLER_STAGE = "terraform-server-caller"

VENDING_URL_ENV = "VENDING_SERVICE_URL"
GUARD_DB_ENV = "STACKVEND_GUARD_FIRESTORE_DATABASE"


class TfApplierDispatchFailed(Exception):
    """A deploy could not be handed to a tf-applier execution. `cause` names what failed (vending's typed code, or
    RUN_JOB_FAILED / PROJECT_ID_UNSET / NO_ID_TOKEN / TRANSPORT / MALFORMED_ANSWER); `outcome_unknown` is True only
    when the request may have reached vending and its answer was lost (an execution may still run: an operator
    checks the tf-applier executions of the trace before a relaunch)."""

    code = TF_APPLIER_DISPATCH_FAILED

    def __init__(self, cause: str, detail: str, *, http_status: int = 502, outcome_unknown: bool = False,
                 upstream_status: Optional[int] = None):
        super().__init__(f"{TF_APPLIER_DISPATCH_FAILED} ({cause}): {detail}")
        self.cause, self.detail, self.http_status = cause, detail, http_status
        self.outcome_unknown, self.upstream_status = bool(outcome_unknown), upstream_status
        self.stage = DISPATCH_STAGE

    def result(self, product_id: Optional[str], trace_id: Optional[str]) -> Dict[str, Any]:
        """The typed FAILED deploy result (callback body / HTTP detail). Always operator_required: a developer
        regeneration cannot fix a dispatch."""
        return {"status": "FAILED", "error_class": TF_APPLIER_DISPATCH_FAILED, "cause": self.cause,
                "error": str(self), "stage": self.stage, "outcome_unknown": self.outcome_unknown,
                "upstream_status": self.upstream_status, "product_id": product_id, "trace_id": trace_id,
                "operator_required": True}


def refusal_detail(err: "ri.RunnerIdentityError", product_id: Optional[str] = None,
                   trace_id: Optional[str] = None) -> Dict[str, Any]:
    """HTTP detail of a typed runner refusal (operator_required: nothing a developer run changes)."""
    return {"status": "FAILED", "error_class": err.code, "error": f"{err.code}: {err.detail}", "stage": err.stage,
            "product_id": product_id, "trace_id": trace_id, "operator_required": True}


# ------------------------------------------------------------------------------------------------ route callers
CALLERS_ENV = "TF_SERVER_WORKLOAD_CALLERS"
# Plan 2.13, before step A: the workflow (orchestrator runtime sa-castor-architect), the gateway (sa-castor-developer),
# the Control Center (sa-stackvend-control-center) and vending (sa-project-provisioner; with the rollback lever
# vending runs as sa-castor-developer, already listed). Exactly the accounts of infra/platform tf_server_workload_callers.
DEFAULT_WORKLOAD_CALLER_ACCOUNTS = ("sa-castor-architect", "sa-castor-developer", "sa-stackvend-control-center",
                                    "sa-project-provisioner")
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")
CLOCK_SKEW_SECONDS = 10


def workload_callers(environ: Mapping[str, str]) -> FrozenSet[str]:
    """TF_SERVER_WORKLOAD_CALLERS (comma-separated emails) when set and not blank; else the default accounts in this
    host project (PROJECT_ID). Empty when neither is configured (every workload route then answers 503)."""
    raw = environ.get(CALLERS_ENV)
    if raw is not None and raw.strip():
        return ri.csv_emails(raw)
    host = (environ.get("PROJECT_ID") or "").strip()
    if not host:
        return frozenset()
    return frozenset(ri.service_account_email(a, host).lower() for a in DEFAULT_WORKLOAD_CALLER_ACCOUNTS)


CERTS_CACHE_SECONDS = 600


class CachingCertsRequest:
    """SAT-31 RT L5: a google-auth transport `Request` that answers repeated GETs of the same URL (Google's public
    OAuth2 certificates) from memory for CERTS_CACHE_SECONDS, so token verification does not fetch the certificates
    on every request. Only successful GETs are cached; every other call goes to the wrapped transport. (google-auth's
    documented alternative, a CacheControl session, needs a package the server does not ship.)"""

    def __init__(self, inner: Optional[Callable[..., Any]] = None, clock: Optional[Callable[[], float]] = None):
        import threading
        import time
        self._inner, self._clock = inner, clock or time.monotonic
        self._cache: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def _transport(self):
        if self._inner is None:
            from google.auth.transport import requests as google_requests
            self._inner = google_requests.Request()
        return self._inner

    def __call__(self, url, method="GET", body=None, headers=None, timeout=None, **kwargs):
        # SAT-31 re-check F3: a timeout is forwarded only when the caller gave one, so google-auth's own default
        # (120 s) still bounds the certificate fetch (requests treats timeout=None as "wait forever").
        if timeout is not None:
            kwargs["timeout"] = timeout
        if method != "GET" or body is not None:
            return self._transport()(url, method=method, body=body, headers=headers, **kwargs)
        now = self._clock()
        with self._lock:
            hit = self._cache.get(url)
            if hit is not None and now - hit[0] < CERTS_CACHE_SECONDS:
                return hit[1]
        resp = self._transport()(url, method=method, headers=headers, **kwargs)
        if getattr(resp, "status", None) == 200:
            with self._lock:
                self._cache[url] = (now, resp)
        return resp


_CERTS_REQUEST = CachingCertsRequest()


def verify_google_id_token(token: str) -> Dict[str, Any]:
    """Google-signed OIDC ID token (signature, expiry, Google issuer). The audience is checked by the caller against
    this request's own host (callers use the service URL with or without a path: Cloud Workflows' default OIDC
    audience is the full request URL). Google's certificates come from a 10-minute cache (L5)."""
    from google.oauth2 import id_token
    return id_token.verify_oauth2_token(token, _CERTS_REQUEST, audience=None,
                                        clock_skew_in_seconds=CLOCK_SKEW_SECONDS)


def audience_is_this_service(aud: Any, request_host: Optional[str]) -> bool:
    """True only for an https URL whose host is exactly this request's host (no user info, no port). Structural
    (urlsplit), exact equality."""
    if not isinstance(aud, str) or not isinstance(request_host, str) or not request_host:
        return False
    try:
        parts = urlsplit(aud)
        port = parts.port
    except ValueError:
        return False
    host = request_host.lower()
    return (parts.scheme == "https" and port is None and parts.username is None and parts.password is None
            and parts.hostname == host and parts.netloc.lower() == host)


def _caller_refusal(code: str, detail: str, status: int) -> "ri.RunnerIdentityError":
    return ri.RunnerIdentityError(code, detail, stage=CALLER_STAGE, http_status=status)


def authenticate_workload_caller(authorization: Optional[str], request_host: Optional[str], *,
                                 allowed: FrozenSet[str], verifier: Callable[[str], Dict[str, Any]]) -> str:
    """The verified, allow-listed caller email. Unconfigured -> 503 CALLERS_UNCONFIGURED; no / invalid token, wrong
    issuer or audience -> 401 UNAUTHENTICATED; unverified email or an identity not listed -> 403 CALLER_NOT_ALLOWED."""
    if not allowed:
        raise _caller_refusal(CALLERS_UNCONFIGURED, f"{CALLERS_ENV} is not configured and PROJECT_ID is not set", 503)
    parts = (authorization or "").split(" ")
    if len(parts) != 2 or parts[0] != "Bearer" or not parts[1]:
        raise _caller_refusal(UNAUTHENTICATED, "a Google-signed Bearer ID token is required", 401)
    try:
        info = verifier(parts[1])
    except Exception as e:  # noqa: BLE001 - any verification failure is unauthenticated
        raise _caller_refusal(UNAUTHENTICATED, f"ID token rejected ({type(e).__name__})", 401) from None
    if not isinstance(info, dict) or info.get("iss") not in GOOGLE_ISSUERS:
        raise _caller_refusal(UNAUTHENTICATED, "ID token issuer is not Google", 401)
    if not audience_is_this_service(info.get("aud"), request_host):
        raise _caller_refusal(UNAUTHENTICATED, "ID token audience is not this service", 401)
    email = info.get("email")
    if info.get("email_verified") is not True or not isinstance(email, str) or not email.strip():
        raise _caller_refusal(CALLER_NOT_ALLOWED, "ID token has no verified email", 403)
    email = email.strip().lower()
    if email not in allowed:
        raise _caller_refusal(CALLER_NOT_ALLOWED, f"{email} is not an allow-listed workload caller", 403)
    return email


# ------------------------------------------------------------------------------------------------ request target
def check_request_target(product_id: str, target_project_id: Optional[str], *,
                         provenance: Optional[Mapping[str, Any]], expected_signer: Optional[str],
                         certs: Callable[..., Mapping[str, str]]) -> Optional[Dict[str, Any]]:
    """Plan 2.13: a request `target_project_id` only when it equals the project of vending's signed, READY runner
    identity record. None (no target in the request) -> nothing to check (the execution takes its target from the
    signed records only). Raises RunnerIdentityError: RUNNER_RECORD_UNSIGNED / _KEY_RETIRED / _UNVERIFIABLE,
    RUNNER_IDENTITY_NOT_READY, RUNNER_TARGET_MISMATCH."""
    if target_project_id is None:
        return None
    if not expected_signer:
        raise ri.RunnerIdentityError("RUNNER_RECORD_UNVERIFIABLE", f"{product_id}: the broker identity is not "
                                     "configured", stage=DISPATCH_STAGE, http_status=503)
    raw = provenance.get(ri.RUNNER_IDENTITY_FIELD) if isinstance(provenance, Mapping) else None
    if raw is None:
        raise ri.RunnerIdentityError(RUNNER_IDENTITY_NOT_READY, f"{product_id} has no runner identity record",
                                     stage=DISPATCH_STAGE, http_status=409)
    rec = ri.verify_record(ri.provenance_doc_path(product_id), raw, expected_signer=expected_signer, certs=certs)
    rec = ri.check_runner_identity(rec, product_id=product_id, project_id=provenance.get("project_id"))
    if target_project_id != rec["project_id"]:
        raise ri.RunnerIdentityError(RUNNER_TARGET_MISMATCH, f"{product_id}: the request's target_project_id "
                                     f"{target_project_id!r} is not the workload's project", stage=DISPATCH_STAGE,
                                     http_status=409)
    return rec


def read_provenance(guard_db: Any, product_id: str) -> Optional[Dict[str, Any]]:
    """`workload_provenance/{product_id}` from the guard database (read only). A read that fails is never assumed:
    RUNNER_IDENTITY_NOT_READY (503)."""
    try:
        snap = guard_db.collection(ri.PROVENANCE_COLLECTION).document(product_id).get()
        return snap.to_dict() if getattr(snap, "exists", False) is True else None
    except Exception as e:  # noqa: BLE001
        raise ri.RunnerIdentityError(RUNNER_IDENTITY_NOT_READY, f"{product_id}: provenance unreadable "
                                     f"({type(e).__name__})", stage=DISPATCH_STAGE, http_status=503) from None


# ------------------------------------------------------------------------------------------------ vending dispatch
DISPATCH_TIMEOUT_S = 120.0   # vending verifies the identity, signs twice and runs the job (cold start included)
DISPATCH_MODE_DEPLOY = "deploy"
STATUS_TIMEOUT_S = 30.0      # RT L2 (SAT-37): /runner/dispatch-status (one Run API read inside vending)
RUNNER_DISPATCH_STATUS_UNAVAILABLE = "RUNNER_DISPATCH_STATUS_UNAVAILABLE"   # a log class: decides nothing


def _default_id_token(audience: str) -> str:
    """The server's own Google ID token for vending (never handed to tofu)."""
    from google.auth.transport.requests import Request
    from google.oauth2 import id_token
    return id_token.fetch_id_token(Request(), audience)


def _default_post(url: str, **kwargs):
    import requests
    return requests.post(url, allow_redirects=False, **kwargs)


def _not_sent(exc: Exception) -> bool:
    """True only for a connect timeout (the request never left this process). Exception type only."""
    try:
        import requests
    except ImportError:  # pragma: no cover
        return False
    return isinstance(exc, requests.exceptions.ConnectTimeout)


class DispatchClient:
    """POST {VENDING_SERVICE_URL}/runner/dispatch, once. Answers vending's DISPATCHED body ({status, dispatch_id,
    execution, ...}); anything else raises TfApplierDispatchFailed with vending's typed code as the cause."""

    def __init__(self, base_url: Optional[str], *, id_token: Optional[Callable[[str], str]] = None,
                 post: Optional[Callable[..., Any]] = None):
        if not isinstance(base_url, str) or not base_url.strip().startswith("https://"):
            raise ri.RunnerIdentityError(RUNNER_IDENTITY_NOT_READY, f"{VENDING_URL_ENV} is not an https URL on this "
                                         "server (plan step A)", stage="runner-config", http_status=503)
        self.base_url = base_url.strip().rstrip("/")
        self._id_token = id_token or _default_id_token
        self._post = post or _default_post

    def dispatch(self, *, product_id: str, trace_id: str, branch: str, callback_url: Optional[str],
                 mode: str = DISPATCH_MODE_DEPLOY, payload_ref: Optional[str] = None,
                 payload_sha256: Optional[str] = None) -> Dict[str, Any]:
        try:
            token = self._id_token(self.base_url)
        except Exception as e:  # noqa: BLE001 - the server's own identity is unavailable; nothing was sent
            raise TfApplierDispatchFailed("NO_ID_TOKEN", f"no ID token for vending ({type(e).__name__})",
                                          http_status=503) from None
        body = {"product_id": product_id, "trace_id": trace_id, "branch": branch, "mode": mode,
                "callback_url": callback_url}
        if payload_ref is not None or payload_sha256 is not None:   # FD-7L 5b: a staged payload (sync runs only)
            body.update(payload_ref=payload_ref, payload_sha256=payload_sha256)
        try:
            resp = self._post(f"{self.base_url}/runner/dispatch", json=body,
                              headers={"Authorization": f"Bearer {token}"}, timeout=DISPATCH_TIMEOUT_S)
        except Exception as e:  # noqa: BLE001 - transport failure
            unknown = not _not_sent(e)
            raise TfApplierDispatchFailed("TRANSPORT", f"/runner/dispatch: {type(e).__name__}"
                                          + ("; the request may have reached vending" if unknown else ""),
                                          http_status=503, outcome_unknown=unknown) from None
        status = getattr(resp, "status_code", None)
        try:
            payload = resp.json()
        except Exception:  # noqa: BLE001
            payload = None
        if status == 200:
            execution = payload.get("execution") if isinstance(payload, dict) else None
            if isinstance(payload, dict) and payload.get("status") == "DISPATCHED" and isinstance(execution, str) \
                    and execution and is_dispatch_id(payload.get("dispatch_id")):
                return payload
            raise TfApplierDispatchFailed("MALFORMED_ANSWER", "/runner/dispatch answered 200 without an execution "
                                          "and a dispatch id", outcome_unknown=True, upstream_status=status)
        detail = payload.get("detail") if isinstance(payload, dict) else None
        code = detail.get("code") if isinstance(detail, dict) and isinstance(detail.get("code"), str) else None
        # A typed refusal of vending's broker leaves no redeemable execution: it refuses before RunJob, or its record
        # stays unbound (RUNNER_DISPATCH_FAILED), which no execution can redeem. An untyped 5xx (for example Cloud
        # Run's own 504 while vending's handler still runs) may still end in a bound execution: outcome unknown.
        untyped_5xx = code is None and (not isinstance(status, int) or status >= 500)
        raise TfApplierDispatchFailed(code or f"HTTP_{status}", f"/runner/dispatch answered HTTP {status}",
                                      outcome_unknown=untyped_5xx,
                                      upstream_status=status if isinstance(status, int) else None)

    def execution_state(self, dispatch_id: str) -> Dict[str, Any]:
        """FD-7L 5b RT L2 (SAT-37): POST {VENDING_SERVICE_URL}/runner/dispatch-status (read only): vending's view of
        the dispatch's bound execution ({execution, redeemed, ended, ...}). Any failure raises RunnerIdentityError
        RUNNER_DISPATCH_STATUS_UNAVAILABLE (the caller decides nothing from it)."""
        def _fail(why: str):
            raise ri.RunnerIdentityError(RUNNER_DISPATCH_STATUS_UNAVAILABLE, f"/runner/dispatch-status: {why}",
                                         stage=DISPATCH_STAGE, http_status=503)
        try:
            token = self._id_token(self.base_url)
            resp = self._post(f"{self.base_url}/runner/dispatch-status", json={"dispatch_id": dispatch_id},
                              headers={"Authorization": f"Bearer {token}"}, timeout=STATUS_TIMEOUT_S)
        except Exception as e:  # noqa: BLE001 - read only; the caller looks again later
            _fail(type(e).__name__)
        status = getattr(resp, "status_code", None)
        try:
            payload = resp.json()
        except Exception:  # noqa: BLE001
            payload = None
        if status != 200 or not isinstance(payload, dict) or payload.get("dispatch_id") != dispatch_id:
            detail = payload.get("detail") if isinstance(payload, dict) else None
            code = detail.get("code") if isinstance(detail, dict) else None
            _fail(f"HTTP {status} ({code or 'no code'})")
        return payload


# ------------------------------------------------------------------------------------------------ dispatch watcher
# SAT-27 open item 4 / owner 11-01 (register "FD-7L-TF amendment: callback grant"): a tf-applier execution that ends,
# or never starts, WITHOUT redeeming its nonce knows no callback URL, so without this the workflow waits 24 h. The
# server that dispatched it watches vending's SIGNED dispatch record (guard database, read only). Once the redeem
# window has passed (vending refuses every later redeem) and the record is still not redeemed, the server sends ONE
# typed FAILED callback to the record's own callback URL with its own identity (step A grants it the callback role).
# A redeemed run is never reported: its execution owns the callback. Idempotent across server instances: a watch
# document in the default database moves WATCHING -> SENDING in a Firestore transaction (or is created as SENDING when
# it is missing) before anything is sent; SENDING / SENT are never claimed again (at most once, never twice).
TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM = "TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM"
WATCH_COLLECTION = "runner_dispatch_watches"
WATCH_MARGIN_S = 120.0                  # past vending's redeem window (clock skew between the two services)
WATCH_GIVE_UP_S = 24 * 3600.0           # the workflow's own callback timeout has passed by then: stop watching
WATCH_RETRY_S = 60.0
WATCH_SWEEP_PAGE = 50
WATCH_SWEEP_MAX_PAGES = 40              # at most 2000 watches per sweep
WATCH_STUCK_SENDING_S = 600.0           # RT L8: a SENDING watch older than this is logged once (never re-sent)
WATCHING, SENDING, SENT, REDEEMED, EXPIRED, UNVERIFIED = ("WATCHING", "SENDING", "SENT", "REDEEMED", "EXPIRED",
                                                         "UNVERIFIED")
_HEX = frozenset("0123456789abcdef")


def is_dispatch_id(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def _epoch(value: Any) -> Optional[float]:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


class WatchStore:
    """The watch documents (default database; the server's own `datastore.user`). Transactions through
    google-cloud-firestore; tests pass a fake with the same five methods."""

    def __init__(self, db: Any):
        self.db = db

    def _ref(self, dispatch_id: str):
        return self.db.collection(WATCH_COLLECTION).document(dispatch_id)

    def create(self, dispatch_id: str, doc: Dict[str, Any]) -> None:
        self._ref(dispatch_id).create(doc)

    def get(self, dispatch_id: str) -> Optional[Dict[str, Any]]:
        snap = self._ref(dispatch_id).get()
        return snap.to_dict() if getattr(snap, "exists", False) is True else None

    def claim(self, dispatch_id: str, fields: Dict[str, Any]) -> bool:
        """Compare-and-set in one transaction: WATCHING (or a missing document) -> `fields`, which carry the new
        state. False when another instance already moved it."""
        from google.cloud import firestore as gcf
        ref = self._ref(dispatch_id)
        outcome = {"ok": False}

        def _body(txn):
            snap = ref.get(transaction=txn)
            current = snap.to_dict() if getattr(snap, "exists", False) is True else None
            if current is None:
                txn.create(ref, fields)
            elif current.get("state") == WATCHING:
                txn.update(ref, fields)
            else:
                outcome["ok"] = False
                return
            outcome["ok"] = True

        gcf.transactional(_body)(self.db.transaction())
        return outcome["ok"]

    def set_state(self, dispatch_id: str, fields: Dict[str, Any]) -> None:
        self._ref(dispatch_id).set(fields, merge=True)

    def _in_state(self, state: str, page_size: int, max_pages: int) -> List[Any]:
        """Every document in `state`, paged by document id (RT L1: an equality filter + `__name__` order needs no
        composite index; a fixed unordered limit returned the same first page every sweep). Bounded by max_pages."""
        from google.cloud.firestore_v1.base_query import FieldFilter
        base = self.db.collection(WATCH_COLLECTION).where(filter=FieldFilter("state", "==", state))
        out, last = [], None
        for _ in range(max_pages):
            query = base.order_by("__name__").limit(page_size)
            if last is not None:
                query = query.start_after(last)
            page = list(query.stream())
            out.extend(page)
            if len(page) < page_size:
                break
            last = page[-1]
        return out

    def pending(self, page_size: int = WATCH_SWEEP_PAGE, max_pages: int = WATCH_SWEEP_MAX_PAGES) -> List[str]:
        return [s.id for s in self._in_state(WATCHING, page_size, max_pages)]

    def sending(self, page_size: int = WATCH_SWEEP_PAGE,
                max_pages: int = WATCH_SWEEP_MAX_PAGES) -> List[Tuple[str, Dict[str, Any]]]:
        return [(s.id, s.to_dict() or {}) for s in self._in_state(SENDING, page_size, max_pages)]


def read_signed_dispatch_record(guard_db: Callable[[], Any], dispatch_id: str, signer: Optional[str],
                                certs: Callable[..., Mapping[str, str]]) -> Dict[str, Any]:
    """Vending's SIGNED dispatch record `runner_nonces/<dispatch_id>` (guard database, read only), verified for the
    broker. RUNNER_RECORD_UNVERIFIABLE (503) when it cannot be read now; RUNNER_RECORD_UNSIGNED when it is missing,
    forged or not a dispatch record."""
    if not signer:
        raise ri.RunnerIdentityError("RUNNER_RECORD_UNVERIFIABLE", "the broker identity is not configured",
                                     stage="runner-watch", http_status=503)
    try:
        snap = guard_db().collection(ri.NONCE_COLLECTION).document(dispatch_id).get()
        doc = snap.to_dict() if getattr(snap, "exists", False) is True else None
    except Exception as e:  # noqa: BLE001 - unreadable now: checked again, never assumed
        raise ri.RunnerIdentityError("RUNNER_RECORD_UNVERIFIABLE", f"dispatch record unreadable "
                                     f"({type(e).__name__})", stage="runner-watch", http_status=503) from None
    if doc is None:
        raise ri.RunnerIdentityError("RUNNER_RECORD_UNSIGNED", "the dispatch record is missing",
                                     stage="runner-watch")
    rec = ri.verify_record(ri.nonce_doc_path(dispatch_id), doc, expected_signer=signer, certs=certs)
    if rec.get("schema") != ri.NONCE_SCHEMA:
        raise ri.RunnerIdentityError("RUNNER_RECORD_UNSIGNED", "not a dispatch record", stage="runner-watch")
    return rec


class DispatchWatcher:
    """Decides, for one dispatch, whether its tf-applier execution failed before redeeming the nonce, and reports it
    once. Every decision comes from vending's SIGNED dispatch record, never from the watch document."""

    def __init__(self, store: Any, *, guard_db: Callable[[], Any], expected_signer: Callable[[], Optional[str]],
                 certs: Callable[..., Mapping[str, str]], report: Callable[[Dict[str, Any]], None],
                 clock: Callable[[], float]):
        self.store, self._guard_db, self._signer, self._certs = store, guard_db, expected_signer, certs
        self._report, self._clock = report, clock

    def _now_iso(self) -> str:
        return datetime.fromtimestamp(self._clock(), tz=timezone.utc).isoformat()

    def _set(self, dispatch_id: str, state: str, **extra) -> str:
        self.store.set_state(dispatch_id, dict(extra, state=state, decided_at=self._now_iso()))
        return state

    def register(self, *, dispatch_id: str, execution: str, product_id: str, trace_id: str) -> None:
        """The watch document (state WATCHING; a scheduling hint, never trusted for a decision). A write failure is
        logged (fail-loudly 2): this instance still checks the dispatch and creates the document when it claims."""
        now = self._clock()
        try:
            self.store.create(dispatch_id, {
                "state": WATCHING, "dispatch_id": dispatch_id, "execution": execution, "product_id": product_id,
                "trace_id": trace_id, "registered_at": self._now_iso(),
                "due_at_epoch": now + ri.REDEEM_WINDOW_SECONDS + WATCH_MARGIN_S,
                "give_up_at_epoch": now + WATCH_GIVE_UP_S})
        except Exception as e:  # noqa: BLE001
            logger.error(f"RUNNER_WATCH_NOT_RECORDED for dispatch {dispatch_id[:12]} ({product_id}, trace "
                         f"{trace_id}): {type(e).__name__}; this instance still checks it")

    def _signed_record(self, dispatch_id: str) -> Dict[str, Any]:
        return read_signed_dispatch_record(self._guard_db, dispatch_id, self._signer(), self._certs)

    def check(self, dispatch_id: str) -> str:
        """One decision; returns the watch state after it: WATCHING (not decided yet, check again later), REDEEMED,
        SENT, EXPIRED, UNVERIFIED, or SENDING when another instance is reporting it."""
        if not is_dispatch_id(dispatch_id):
            return UNVERIFIED
        now = self._clock()
        watch = self.store.get(dispatch_id) or {}
        if watch.get("state") not in (None, WATCHING):
            return watch["state"]
        give_up = watch.get("give_up_at_epoch")
        try:
            rec = self._signed_record(dispatch_id)
        except ri.RunnerIdentityError as e:
            if e.code == "RUNNER_RECORD_UNVERIFIABLE" and not (isinstance(give_up, (int, float)) and now > give_up):
                logger.warning(f"runner watch {dispatch_id[:12]}: {e.code} ({e.detail}); checked again later")
                return WATCHING
            # A missing, forged or never-verifiable record is never trusted to say "not redeemed": no callback.
            logger.error(f"runner watch {dispatch_id[:12]}: {e.code} ({e.detail}); no callback is sent (operator: "
                         "check the tf-applier execution and the workflow)")
            return self._set(dispatch_id, UNVERIFIED, error_class=e.code)
        if rec.get("redeemed") is not False:
            return self._set(dispatch_id, REDEEMED)       # the execution owns the callback
        created = _epoch(rec.get("created_at"))
        if created is None:
            logger.error(f"runner watch {dispatch_id[:12]}: the signed record has no creation time; no callback")
            return self._set(dispatch_id, UNVERIFIED, error_class="RUNNER_RECORD_UNSIGNED")
        if now < created + ri.REDEEM_WINDOW_SECONDS + WATCH_MARGIN_S:
            return WATCHING                               # vending may still accept the redeem
        if now > created + WATCH_GIVE_UP_S:
            return self._set(dispatch_id, EXPIRED)
        product_id, trace_id, execution = rec.get("product_id"), rec.get("trace_id"), rec.get("execution")
        if not self.store.claim(dispatch_id, {"state": SENDING, "dispatch_id": dispatch_id, "execution": execution,
                                              "product_id": product_id, "trace_id": trace_id,
                                              "claimed_at": self._now_iso(), "claimed_at_epoch": now}):
            return (self.store.get(dispatch_id) or {}).get("state") or SENDING
        # RT L2: a redeem that passed vending's window check just before the window closed can commit late (slow
        # signBlob / Run API); re-read the signed record once after the claim and send nothing for a redeemed run.
        try:
            again = self._signed_record(dispatch_id)
        except ri.RunnerIdentityError as e:
            logger.warning(f"runner watch {dispatch_id[:12]}: re-read after the claim failed ({e.code}); the first "
                           "read (not redeemed, window passed) decides")
            again = rec
        if again.get("redeemed") is not False:
            logger.warning(f"runner watch {dispatch_id[:12]}: redeemed after the window check; no callback")
            return self._set(dispatch_id, REDEEMED, late_redeem=True)
        callback_url = rec.get("callback_url")
        error = (f"{TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM}: tf-applier execution {execution} did not redeem its "
                 f"dispatch within {ri.REDEEM_WINDOW_SECONDS} s (it ended, never started, or was refused before the "
                 "redeem; see its log). It held no deployer credentials, so it applied nothing.")
        logger.error(f"{error} [{product_id}, trace {trace_id}]")
        if not callback_url:
            return self._set(dispatch_id, SENT, callback=False)
        try:
            self._report({"status": "FAILED", "error_class": TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM,
                          "error": error, "stage": DISPATCH_STAGE, "execution": execution, "product_id": product_id,
                          "trace_id": trace_id, "callback_url": callback_url, "operator_required": True})
        finally:
            self._set(dispatch_id, SENT, callback=True)
        return SENT

    def sweep(self) -> Dict[str, str]:
        """Every pending watch of the install (whichever instance dispatched it), each decided by `check`."""
        out: Dict[str, str] = {}
        for dispatch_id in self.store.pending():
            try:
                out[dispatch_id] = self.check(dispatch_id)
            except Exception as e:  # noqa: BLE001 - one watch never stops the sweep; logged, checked again next time
                logger.error(f"runner watch {str(dispatch_id)[:12]}: {type(e).__name__}; checked again next sweep")
                out[dispatch_id] = WATCHING
        try:
            self.report_stuck_sending()
        except Exception as e:  # noqa: BLE001 - re-check F6: the decided watches above stay decided; logged
            logger.error(f"runner watch: listing SENDING watches failed ({type(e).__name__}); retried next sweep")
        return out

    def report_stuck_sending(self) -> List[str]:
        """RT L8: a watch left in SENDING (its instance stopped while sending) is never sent again (at most once), but
        it is logged once for the operator: the workflow may not have received its callback."""
        stuck = []
        now = self._clock()
        for dispatch_id, doc in self.store.sending():
            claimed = doc.get("claimed_at_epoch")
            if doc.get("stuck_logged") is True or not isinstance(claimed, (int, float)) \
                    or now - claimed < WATCH_STUCK_SENDING_S:
                continue
            logger.error(f"RUNNER_WATCH_STUCK_SENDING: dispatch {str(dispatch_id)[:12]} ({doc.get('product_id')}, trace "
                         f"{doc.get('trace_id')}, {doc.get('execution')}) was claimed for the "
                         f"{TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM} callback at {doc.get('claimed_at')} and never "
                         "marked sent; it is not sent again. Operator: check the workflow execution for that trace.")
            self.store.set_state(dispatch_id, {"stuck_logged": True})
            stuck.append(dispatch_id)
        return stuck
