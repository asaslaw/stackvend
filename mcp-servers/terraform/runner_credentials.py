"""
FD-7L Phase 2a (plan docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3, section 2.4; register rows "FD-7L
plan", FD-7L Phase 1 and FD-7L-n): the runner's side of the per-workload identity, inside one tf-applier execution.

Everything here is inert on a Shared install (`STACKVEND_TF_RUNNER_IDENTITY` unset or PLATFORM) EXCEPT the tofu
environment allow-list (`tofu_base_env`), which `TerraformService._run_subprocess` applies in both modes.

* `BrokerClient`: the job's calls to vending's broker (`/runner/redeem`, `/runner/deployer-token`, `/runner/repo-token`,
  `/runner/result`) with the job's own
  Google ID token. The nonce, the session key and every token are never logged, never written to a file and never put
  into an environment.
* `BrokeredCredentials`: google-auth credentials for the workload's deployer (`stackvend-deployer@<child>`), minted by
  the broker for this execution only, quota project = the child. Refreshed while at least REFRESH_BEFORE_EXPIRY_S are
  left (plan R6: a broker outage shorter than the remaining lifetime does not stop a running apply); when the current
  token is about to expire and the broker still fails -> RUNNER_BROKER_UNAVAILABLE (typed, never a fallback).
* `LocalMetadataEndpoint`: a GCE-metadata-shaped HTTP endpoint on 127.0.0.1:<ephemeral> per workspace that serves only
  the deployer's token, email and project id. OpenTofu's Google SDKs honour GCE_METADATA_HOST, so ADC inside tofu
  resolves to the deployer only. A broker failure that ends the token's usable life interrupts every tofu process
  attached to it (SIGINT to its process group: OpenTofu stops cleanly and releases the state lock).
* `verify_run_target`: the run's project, deployer, state bucket and repository come only from vending's SIGNED
  provenance record (guard database); the dispatch record, the workload record and the bucket's owner must agree
  (RUNNER_RECORD_UNSIGNED / RUNNER_TARGET_MISMATCH / STATE_BUCKET_NOT_OWNED).
* `mode_log_record`: the one structured mode line every run logs (plan re-RT R10).
"""
import http.server
import json
import logging
import os
import signal
import socketserver
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from shared import runner_identity as ri

try:   # google-auth's base class (storage clients require it); tests that stub google.* keep an importable module
    from google.auth.credentials import Credentials as _GoogleCredentials
    if not isinstance(_GoogleCredentials, type):
        raise ImportError("google.auth.credentials is stubbed")
except ImportError:  # pragma: no cover - only under a stubbed google package
    _GoogleCredentials = object

logger = logging.getLogger("tf-runner-identity")

CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

# Job / server environment (names only; values never logged).
NONCE_ENV = "RUNNER_NONCE"                       # set by vending's RunJob override (runner_broker.NONCE_ENV_NAME)
VENDING_URL_ENV = "VENDING_SERVICE_URL"          # Terraform-owned, plan step A
GUARD_DB_ENV = "STACKVEND_GUARD_FIRESTORE_DATABASE"
# The tf-applier inputs of a Shared install. On a Per-workload install the job reads ONLY RUNNER_NONCE (re-RT R3); any of
# these that is present is ignored and named in one RUNNER_ENV_IGNORED line.
LEGACY_JOB_ENV = ("PRODUCT_ID", "TRACE_ID", "TARGET_PROJECT_ID", "CALLBACK_URL", "BRANCH", "HCL_FILES_JSON")

# Typed classes (documentation/fail-loudly-policy.md 1.5; every refusal is operator_required).
RUNNER_IDENTITY_NOT_REGISTERED = "RUNNER_IDENTITY_NOT_REGISTERED"
RUNNER_IDENTITY_NOT_READY = "RUNNER_IDENTITY_NOT_READY"
RUNNER_BROKER_UNAVAILABLE = "RUNNER_BROKER_UNAVAILABLE"
RUNNER_TARGET_MISMATCH = "RUNNER_TARGET_MISMATCH"
RUNNER_RECORD_UNSIGNED = "RUNNER_RECORD_UNSIGNED"
STATE_BUCKET_NOT_OWNED = "STATE_BUCKET_NOT_OWNED"
RUNNER_MODE_UNSUPPORTED = "RUNNER_MODE_UNSUPPORTED"
RUNNER_NOT_SINGLE_TENANT = "RUNNER_NOT_SINGLE_TENANT"   # SAT-27 RT L3: a second brokered runner in one process
RUNNER_ENV_IGNORED = "RUNNER_ENV_IGNORED"        # a log event, not a failure
IDENTITY_TOKEN_NOT_SERVED = "IDENTITY_TOKEN_NOT_SERVED"
# FD-7L Phase 4 (plan 2.10): the repository read of a Per-workload run.
RUNNER_REPOSITORY_NOT_PINNED = "RUNNER_REPOSITORY_NOT_PINNED"   # same code as vending's broker (runner_broker.py)
# Repository credentials a Per-workload run never reads from its environment (named in one RUNNER_ENV_IGNORED line
# when present; the value is never read): it reads GitHub only with vending's read-only token and Serverless Git only
# with the job's own Google ID token.
REPO_READ_IGNORED_ENV = ("GITHUB_TOKEN", "CASTOR_GIT_AUTH_TOKEN", "GOOGLE_OIDC_ID_TOKEN")
REPO_TOKEN_PERMISSIONS = {"contents": "read"}

# ------------------------------------------------------------------------------------------------ tofu environment
# The only variables a tofu process inherits from the runner's own environment (plan 2.4). Everything else the
# platform sets explicitly in _run_subprocess: HOME (a fresh empty directory per command), TF_CLI_CONFIG_FILE,
# TF_PLUGIN_CACHE_DIR, the workspace's TF_VAR_*, the quota project variables and, with brokered credentials,
# GCE_METADATA_HOST / GCE_METADATA_IP. Never inherited (pinned by tests): GITHUB_TOKEN, RUNNER_NONCE,
# GOOGLE_APPLICATION_CREDENTIALS, GOOGLE_OAUTH_ACCESS_TOKEN, GOOGLE_CREDENTIALS, GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES,
# GOOGLE_IMPERSONATE_SERVICE_ACCOUNT, GCE_METADATA_ROOT, TF_LOG*, KUBECONFIG, KUBE_*, PROJECT_ID, TFSTATE_BUCKET,
# K_SERVICE, CLOUD_RUN_*, and every other secret or setting of the runner process.
TOFU_INHERITED_ENV = ("PATH", "LANG", "TMPDIR", "TF_IN_AUTOMATION", "TF_INPUT")
# `validate` (validate_service.scrubbed_env) and nothing else: an address where nothing answers, so ADC inside tofu can
# never reach the container's real metadata server.
UNROUTABLE_METADATA_HOST = "127.0.0.1:9"


def tofu_base_env(environ: Mapping[str, str]) -> Dict[str, str]:
    """The allow-listed part of the runner's environment for a tofu process (exact names, nothing else)."""
    return {name: environ[name] for name in TOFU_INHERITED_ENV if isinstance(environ.get(name), str)}


# ------------------------------------------------------------------------------------------------ broker client
REDEEM_ATTEMPTS = 4                 # RUNNER_DISPATCH_NOT_BOUND (vending binds the execution right after RunJob) / 5xx
REDEEM_RETRY_DELAY_S = 5.0
BROKER_TIMEOUT_S = 30.0
_RETRYABLE_REDEEM_CODES = frozenset({"RUNNER_DISPATCH_NOT_BOUND"})
# SAT-52: vending answers 409 RUNNER_EXECUTION_NOT_YET_RUNNING (same code as runner_broker.py) while the Admin API
# still reads this just-started execution as not running and nothing shows it ended. Classified by the typed code AND
# the status, never message text; its own bounded backoff (60 s in all, well inside the 600 s redeem window).
RUNNER_EXECUTION_NOT_YET_RUNNING = "RUNNER_EXECUTION_NOT_YET_RUNNING"
NOT_YET_RUNNING_STATUS = 409
REDEEM_NOT_YET_RUNNING_DELAYS_S = (1.0, 2.0, 4.0, 8.0, 15.0, 15.0, 15.0)
# RUNNER-REDEEM-CONNECT-RETRY: the wait before each retry of a redeem whose TCP connection to vending was never
# established (_connection_never_established), so the request cannot have reached the broker and the single-use nonce
# is untouched. Replaces REDEEM_ATTEMPTS for that one failure: six calls of up to BROKER_TIMEOUT_S each plus these
# waits is 275 s, against 135 s before. A read timeout or an answer never spends this budget: vending's redeem is not
# idempotent (the first call that commits spends the nonce, and repeating it answers RUNNER_NONCE_SPENT).
REDEEM_CONNECT_RETRY_DELAYS_S = (5.0, 10.0, 20.0, 30.0, 30.0)
# SAT-52 RT LOW loop guard: the redeem loop's hard caps. Calls: every retried answer spends one of the three budgets
# above, so the most calls one redeem can make is one per NOT_YET_RUNNING delay, one per connect delay, plus
# REDEEM_ATTEMPTS. Time: no retry is slept once it would end past REDEEM_TOTAL_BUDGET_S from the first call, so with
# the last call's BROKER_TIMEOUT_S a redeem ends within 450 s of its first call, inside the broker's 600 s redeem
# window. Each budget alone fits under this cap; the worst mix of all three is cut by it. Either cap raises a typed
# error.
REDEEM_MAX_CALLS = len(REDEEM_NOT_YET_RUNNING_DELAYS_S) + len(REDEEM_CONNECT_RETRY_DELAYS_S) + REDEEM_ATTEMPTS
REDEEM_TOTAL_BUDGET_S = 420.0
SIGN_RESULT_ATTEMPTS = 3            # FD-7L 5b (SAT-37): /runner/result, RUNNER_BROKER_UNAVAILABLE only


def _default_id_token(audience: str) -> str:
    """The job's own Google ID token for vending (runner process only; never handed to tofu)."""
    from google.auth.transport.requests import Request
    from google.oauth2 import id_token
    return id_token.fetch_id_token(Request(), audience)


def _default_post(url: str, **kwargs):
    import requests
    return requests.post(url, allow_redirects=False, **kwargs)


def _connection_never_established(error: Exception) -> bool:
    """True only for the `requests` errors that mean the TCP connection was not established, so no byte of the request
    was sent: ConnectTimeout, and a ConnectionError caused by urllib3's NewConnectionError (refused, unreachable, name
    resolution). Decided by exception type, never message text. False for everything else that may have reached
    vending: a read timeout, a connection dropped after the request was sent, a TLS failure."""
    from requests.exceptions import ConnectionError as RequestsConnectionError, ConnectTimeout
    from urllib3.exceptions import MaxRetryError, NewConnectionError
    if isinstance(error, ConnectTimeout):
        return True
    cause = error.args[0] if isinstance(error, RequestsConnectionError) and error.args else None
    return isinstance(cause, MaxRetryError) and isinstance(cause.reason, NewConnectionError)


class _BrokerConnectionNotEstablished(ri.RunnerIdentityError):
    """RUNNER_BROKER_UNAVAILABLE for a request that never reached vending; only `BrokerClient.redeem` tells it apart."""


class BrokerClient:
    """POSTs to vending's runner routes. Answers: the JSON body on 200; RunnerIdentityError otherwise -- the broker's
    own typed code for a 4xx refusal, RUNNER_BROKER_UNAVAILABLE for a transport failure, a 5xx or a 429."""

    def __init__(self, base_url: str, *, id_token: Optional[Callable[[str], str]] = None,
                 post: Optional[Callable[..., Any]] = None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        if not isinstance(base_url, str) or not base_url.startswith("https://"):
            raise ri.RunnerIdentityError(RUNNER_IDENTITY_NOT_READY, f"{VENDING_URL_ENV} is not an https URL",
                                         stage="runner-config", http_status=503)
        self.base_url = base_url.rstrip("/")
        self._id_token = id_token or _default_id_token
        self._post = post or _default_post
        self._sleep = sleep
        self._clock = clock

    def _call(self, path: str, body: Dict[str, Any], stage: str) -> Dict[str, Any]:
        try:
            token = self._id_token(self.base_url)
        except Exception as e:  # noqa: BLE001 - the job's own identity is unavailable
            raise ri.RunnerIdentityError(RUNNER_BROKER_UNAVAILABLE, f"{path}: no ID token ({type(e).__name__})",
                                         stage=stage, http_status=503) from None
        try:
            resp = self._post(f"{self.base_url}{path}", json=body, headers={"Authorization": f"Bearer {token}"},
                              timeout=BROKER_TIMEOUT_S)
        except Exception as e:  # noqa: BLE001 - transport failure
            error_type = _BrokerConnectionNotEstablished if _connection_never_established(e) else ri.RunnerIdentityError
            raise error_type(RUNNER_BROKER_UNAVAILABLE, f"{path}: {type(e).__name__}", stage=stage,
                             http_status=503) from None
        status = getattr(resp, "status_code", None)
        try:
            payload = resp.json()
        except Exception:  # noqa: BLE001
            payload = None
        if status == 200 and isinstance(payload, dict):
            return payload
        detail = payload.get("detail") if isinstance(payload, dict) else None
        code = detail.get("code") if isinstance(detail, dict) and isinstance(detail.get("code"), str) else None
        if not isinstance(status, int) or status >= 500 or status == 429 or status == 200:
            raise ri.RunnerIdentityError(RUNNER_BROKER_UNAVAILABLE, f"{path}: HTTP {status} ({code or 'no code'})",
                                         stage=stage, http_status=503)
        raise ri.RunnerIdentityError(code or "RUNNER_BROKER_REFUSED", f"{path}: HTTP {status}", stage=stage,
                                     http_status=status)

    def redeem(self, nonce: str, execution: str) -> Tuple[Dict[str, Any], str]:
        """(dispatch record, session key). Bounded retries for an unbound dispatch or an unavailable broker
        (REDEEM_ATTEMPTS), for a connection that was never established (REDEEM_CONNECT_RETRY_DELAYS_S), and SAT-52 for
        an execution vending does not yet read as running (REDEEM_NOT_YET_RUNNING_DELAYS_S); every other refusal -- an
        ended execution's RUNNER_EXECUTION_NOT_RUNNING
        included, even after not-yet retries -- raises at once with the broker's typed code. RT LOW loop guard: at most
        REDEEM_MAX_CALLS calls and no retry past REDEEM_TOTAL_BUDGET_S; exhausting either raises the last refusal's
        typed code with the reason in its detail."""
        failures = 0
        not_yet = 0
        connect_retries = 0
        started = self._clock()
        last: Optional[ri.RunnerIdentityError] = None
        for _call in range(REDEEM_MAX_CALLS):
            try:
                out = self._call("/runner/redeem", {"nonce": nonce, "execution": execution}, "runner-redeem")
            except ri.RunnerIdentityError as e:
                last = e
                if e.code == RUNNER_EXECUTION_NOT_YET_RUNNING and e.http_status == NOT_YET_RUNNING_STATUS:
                    if not_yet >= len(REDEEM_NOT_YET_RUNNING_DELAYS_S):
                        waited = sum(REDEEM_NOT_YET_RUNNING_DELAYS_S)
                        raise ri.RunnerIdentityError(e.code, f"{e.detail} (still not running after {not_yet} "
                                                     f"retries over {waited:.0f} s)", stage=e.stage,
                                                     http_status=e.http_status) from None
                    delay = REDEEM_NOT_YET_RUNNING_DELAYS_S[not_yet]
                    self._within_budget(e, started, delay)
                    not_yet += 1
                    logger.warning(f"{e.code} (runner-redeem): {execution} is not running yet at vending; retry "
                                   f"{not_yet}/{len(REDEEM_NOT_YET_RUNNING_DELAYS_S)} in {delay:.0f} s")
                    self._sleep(delay)
                    continue
                if isinstance(e, _BrokerConnectionNotEstablished):
                    if connect_retries >= len(REDEEM_CONNECT_RETRY_DELAYS_S):
                        raise ri.RunnerIdentityError(e.code, f"{e.detail} (no connection after {connect_retries} "
                                                     "retries)", stage=e.stage, http_status=e.http_status) from None
                    delay = REDEEM_CONNECT_RETRY_DELAYS_S[connect_retries]
                    self._within_budget(e, started, delay)
                    connect_retries += 1
                    logger.warning(f"{e.code} (runner-redeem): {e.detail}; the request never reached vending; retry "
                                   f"{connect_retries}/{len(REDEEM_CONNECT_RETRY_DELAYS_S)} in {delay:.0f} s")
                    self._sleep(delay)
                    continue
                failures += 1
                if (e.code in _RETRYABLE_REDEEM_CODES or e.code == RUNNER_BROKER_UNAVAILABLE) \
                        and failures < REDEEM_ATTEMPTS:
                    self._within_budget(e, started, REDEEM_RETRY_DELAY_S)
                    self._sleep(REDEEM_RETRY_DELAY_S)
                    continue
                raise
            record, session_key = out.get("record"), out.get("session_key")
            if not isinstance(record, dict) or not isinstance(session_key, str) or not session_key:
                raise ri.RunnerIdentityError(RUNNER_BROKER_UNAVAILABLE, "/runner/redeem: malformed answer",
                                             stage="runner-redeem", http_status=503)
            return record, session_key
        # Unreachable while each retried answer spends a budget above; the explicit backstop if that ever changes.
        code = last.code if last is not None else RUNNER_BROKER_UNAVAILABLE
        raise ri.RunnerIdentityError(code, f"/runner/redeem: no redeem after {REDEEM_MAX_CALLS} calls",
                                     stage="runner-redeem", http_status=last.http_status if last else 503)

    def _within_budget(self, e: ri.RunnerIdentityError, started: float, delay: float) -> None:
        """RT LOW loop guard: raise `e`'s typed code instead of sleeping a retry that would end past the budget."""
        elapsed = self._clock() - started
        if elapsed + delay > REDEEM_TOTAL_BUDGET_S:
            raise ri.RunnerIdentityError(e.code, f"{e.detail} (redeem retry budget of {REDEEM_TOTAL_BUDGET_S:.0f} s "
                                         f"exhausted after {elapsed:.0f} s)", stage=e.stage,
                                         http_status=e.http_status) from None

    def deployer_token(self, session_key: str) -> Tuple[str, float, Dict[str, Any]]:
        """(access token, expiry as epoch seconds, the answer without the token)."""
        out = self._call("/runner/deployer-token", {"session_key": session_key}, "runner-deployer-token")
        token = out.get("access_token")
        if not isinstance(token, str) or not token:
            raise ri.RunnerIdentityError(RUNNER_BROKER_UNAVAILABLE, "/runner/deployer-token: no token",
                                         stage="runner-deployer-token", http_status=503)
        return token, _expiry_epoch(out.get("expire_time")), {k: v for k, v in out.items() if k != "access_token"}

    def repo_token(self, session_key: str) -> Tuple[str, Dict[str, Any]]:
        """FD-7L Phase 4: (read-only repository token, the answer without the token) from `/runner/repo-token`. A
        broker refusal keeps its typed code (RUNNER_REPOSITORY_NOT_PINNED, RUNNER_REPO_TOKEN_UNSUPPORTED, ...)."""
        out = self._call("/runner/repo-token", {"session_key": session_key}, "runner-repo-token")
        token = out.get("token")
        if not isinstance(token, str) or not token:
            raise ri.RunnerIdentityError(RUNNER_BROKER_UNAVAILABLE, "/runner/repo-token: no token",
                                         stage="runner-repo-token", http_status=503)
        return token, {k: v for k, v in out.items() if k != "token"}

    def sign_result(self, session_key: str, result_sha256: str) -> None:
        """FD-7L 5b (SAT-37): vending signs the synchronous run's result fingerprint into the dispatch record
        (`/runner/result`, session-bound). Idempotent at vending for the same fingerprint, so an unavailable broker is
        retried a bounded number of times; a refusal keeps its typed code. The answer must echo the fingerprint."""
        last: Optional[ri.RunnerIdentityError] = None
        for attempt in range(1, SIGN_RESULT_ATTEMPTS + 1):
            try:
                out = self._call("/runner/result", {"session_key": session_key, "result_sha256": result_sha256},
                                 "runner-result")
            except ri.RunnerIdentityError as e:
                last = e
                if e.code == RUNNER_BROKER_UNAVAILABLE and attempt < SIGN_RESULT_ATTEMPTS:
                    self._sleep(REDEEM_RETRY_DELAY_S)
                    continue
                raise
            if out.get("status") != "SIGNED" or out.get("result_sha256") != result_sha256:
                raise ri.RunnerIdentityError(RUNNER_BROKER_UNAVAILABLE, "/runner/result: malformed answer",
                                             stage="runner-result", http_status=503)
            return None
        raise last  # pragma: no cover - the loop always returns or raises


def job_id_token(audience: str) -> str:
    """FD-7L Phase 4: this execution's own Google ID token for `audience` (the Serverless Git read; runner process
    only, never handed to tofu, never logged)."""
    return _default_id_token(audience)


GIT_SERVER_URL_ENV = "GIT_SERVER_URL"            # Terraform-owned on the tf-applier job (the git server's run.app uri)


def git_server_url(environ: Mapping[str, str]) -> str:
    """FD-7L Phase 4: the Serverless Git server address of a Per-workload run, only from the job's Terraform-owned
    GIT_SERVER_URL (an https URL); unset or not https -> RUNNER_IDENTITY_NOT_READY (job configuration)."""
    from urllib.parse import urlsplit
    value = (environ.get(GIT_SERVER_URL_ENV) or "").strip().rstrip("/")
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.netloc:
        _refuse(RUNNER_IDENTITY_NOT_READY, f"{GIT_SERVER_URL_ENV} is not an https URL on this job", stage="runner-config",
                status=503)
    return value


def url_origin(url: str) -> str:
    """scheme://host[:port] of `url` (the ID-token audience the git server accepts; same rule as the provider's)."""
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def check_repo_token_answer(answer: Mapping[str, Any], pinned_full_name: str) -> None:
    """FD-7L Phase 4: the broker's repository token must be for exactly the pinned repository (GitHub names compare
    case-insensitively) with exactly contents:read; anything else -> RUNNER_TARGET_MISMATCH (the token is not used)."""
    name = answer.get("repository")
    if not isinstance(name, str) or name.lower() != pinned_full_name.lower():
        _refuse(RUNNER_TARGET_MISMATCH, f"the repository token is for {name!r}, provenance pins {pinned_full_name!r}")
    if answer.get("permissions") != REPO_TOKEN_PERMISSIONS:
        _refuse(RUNNER_TARGET_MISMATCH, f"the repository token for {pinned_full_name!r} is not exactly contents:read")


_REF_FORBIDDEN_CHARS = frozenset(" ~^:?*[\\")


def is_git_branch_name(branch: Any) -> bool:
    """SAT-50 RT F2: True when `branch` is a well-formed git branch name (`git check-ref-format --branch` rules):
    non-empty; no `..`, `@{`, `//`; no leading or trailing `/`; does not start with `-`, end with `.` or equal `@`; no
    component that is empty, starts with `.` or ends with `.lock`; no ASCII control character, space or ``~^:?*[\\``."""
    if not isinstance(branch, str) or not branch or branch == "@" or branch.startswith("-"):
        return False
    if ".." in branch or "@{" in branch or branch.endswith("."):
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F or c in _REF_FORBIDDEN_CHARS for c in branch):
        return False
    return all(part and not part.startswith(".") and not part.endswith(".lock") for part in branch.split("/"))


def check_branch_name(branch: Any) -> None:
    """The deploy's branch must be a well-formed git branch name before any repository URL is built from it (a
    `../`-style name could address another path of the API); anything else -> RUNNER_TARGET_MISMATCH, read nothing."""
    if not is_git_branch_name(branch):
        _refuse(RUNNER_TARGET_MISMATCH, f"the deploy's branch {branch!r} is not a well-formed git branch name")


# A token whose expiry cannot be read is treated as one that lives this long (refreshed early, never late).
UNREADABLE_EXPIRY_LIFETIME_S = 15 * 60.0


def _expiry_epoch(value: Any, now: Optional[float] = None) -> float:
    now = time.time() if now is None else now
    fallback = now + UNREADABLE_EXPIRY_LIFETIME_S
    if not isinstance(value, str) or not value.endswith("Z"):
        return fallback
    body = value[:-1]
    head, dot, frac = body.partition(".")
    try:
        parsed = datetime.strptime(head, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return fallback
    seconds = parsed.timestamp()
    if dot and frac.isdigit():
        seconds += float(f"0.{frac[:6]}")
    return min(seconds, now + ri.DEPLOYER_TOKEN_LIFETIME_SECONDS)


# ------------------------------------------------------------------------------------------------ credentials
REFRESH_BEFORE_EXPIRY_S = 30 * 60.0   # refresh while at least this much is left (>= 15 min, plan R6)
RETRY_INTERVAL_S = 30.0               # at most one broker attempt per interval while refreshing
MIN_USABLE_S = 120.0                  # a token with less than this left is never served


class BrokeredCredentials(_GoogleCredentials):
    """The workload deployer's credentials, minted by vending for this execution. The session key lives only in this
    object's memory (never in env, never on disk, never in a tofu-visible file, never in repr or a log line)."""

    def __init__(self, broker: BrokerClient, session_key: str, *, project_id: str, deployer_email: str,
                 clock: Callable[[], float] = time.time):
        super().__init__()
        self.token: Optional[str] = None
        self.expiry: Optional[datetime] = None
        self._broker = broker
        self.__session_key = session_key
        self.project_id = project_id
        self.deployer_email = deployer_email
        self._quota_project_id = project_id
        self._clock = clock
        self._lock = threading.RLock()
        self._expiry_ts = 0.0
        self._last_failure_at: Optional[float] = None
        self._last_error: Optional[ri.RunnerIdentityError] = None
        self.refresh_count = 0

    def __repr__(self) -> str:
        return f"BrokeredCredentials(project={self.project_id!r}, deployer={self.deployer_email!r})"

    def _fetch(self) -> None:
        token, expiry, _meta = self._broker.deployer_token(self.__session_key)
        self.token = token
        self._expiry_ts = expiry
        self.expiry = datetime.fromtimestamp(expiry, timezone.utc).replace(tzinfo=None)
        self.refresh_count += 1

    def seconds_left(self) -> float:
        return self._expiry_ts - self._clock()

    def current_token(self) -> Tuple[str, float]:
        """(token, seconds left). Refreshes while REFRESH_BEFORE_EXPIRY_S or less are left, at most once per
        RETRY_INTERVAL_S after a failure; keeps serving the current token through a broker outage while more than
        MIN_USABLE_S are left; then RUNNER_BROKER_UNAVAILABLE."""
        with self._lock:
            now = self._clock()
            if self.token is None or self.seconds_left() <= REFRESH_BEFORE_EXPIRY_S:
                due = self._last_failure_at is None or now - self._last_failure_at >= RETRY_INTERVAL_S
                if due:
                    try:
                        self._fetch()
                        self._last_failure_at, self._last_error = None, None
                    except ri.RunnerIdentityError as e:
                        self._last_failure_at, self._last_error = now, e
                        logger.warning(f"Deployer token refresh for {self.project_id} failed ({e.code}); "
                                       f"{max(self.seconds_left(), 0):.0f} s left on the current token")
            left = self.seconds_left()
            if self.token is None or left < MIN_USABLE_S:
                last = self._last_error
                raise ri.RunnerIdentityError(
                    RUNNER_BROKER_UNAVAILABLE,
                    f"no usable deployer token for {self.project_id} (broker: {last.code if last else 'no answer'})",
                    stage="runner-credentials", http_status=503)
            return self.token, left

    @property
    def valid(self) -> bool:
        return self.token is not None and self.seconds_left() >= MIN_USABLE_S

    @property
    def expired(self) -> bool:
        return not self.valid

    def refresh(self, request) -> None:  # noqa: ARG002 - google-auth hook (e.g. after a 401): mint now
        with self._lock:
            try:
                self._fetch()
            except ri.RunnerIdentityError as e:
                self._last_failure_at, self._last_error = self._clock(), e
                raise

    def apply(self, headers, token=None) -> None:
        headers["authorization"] = f"Bearer {token or self.current_token()[0]}"
        headers["x-goog-user-project"] = self.project_id

    def before_request(self, request, method, url, headers) -> None:  # noqa: ARG002
        self.apply(headers)

    def session(self):
        from google.auth.transport.requests import AuthorizedSession
        return AuthorizedSession(self)

    def repository_token(self) -> Tuple[str, Dict[str, Any]]:
        """FD-7L Phase 4: the read-only token for the provenance repository, minted by vending for this execution's
        session (the session key never leaves this object)."""
        return self._broker.repo_token(self.__session_key)


# ------------------------------------------------------------------------------------------------ metadata endpoint
TICK_S = 30.0
_MD = "/computeMetadata/v1"
_SA = f"{_MD}/instance/service-accounts/default"


def _signal_process_group(proc: Any, sig: int) -> None:
    pid = getattr(proc, "pid", None)
    if not isinstance(pid, int) or pid <= 1:
        return                                # never killpg(0 / 1 / -1): only a real child's own group
    try:
        os.killpg(pid, sig)
    except (ProcessLookupError, PermissionError):
        pass
    except OSError:
        try:
            proc.send_signal(sig)
        except OSError:
            pass


class _QuietServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class LocalMetadataEndpoint:
    """One per brokered workspace. Serves only (GET, `Metadata-Flavor: Google`, no `X-Forwarded-For`; query strings
    such as `?scopes=` are accepted and ignored): `/`, `/computeMetadata/v1/`, `.../instance/service-accounts/default/`
    (`?recursive=true` -> JSON), `.../default/token`, `.../default/email`, `/computeMetadata/v1/project/project-id`.
    `.../default/identity` -> 404 IDENTITY_TOKEN_NOT_SERVED; `universe/universe-domain` and everything else -> 404."""

    def __init__(self, credentials: BrokeredCredentials, *, tick_s: float = TICK_S,
                 interrupt: Callable[[Any, int], None] = _signal_process_group):
        self.credentials = credentials
        self.tick_s = tick_s
        self._interrupt = interrupt
        self._lock = threading.Lock()
        self._procs: List[Any] = []
        self.failure: Optional[ri.RunnerIdentityError] = None
        self._server: Optional[_QuietServer] = None
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []

    # -- lifecycle -------------------------------------------------------------------------------------------
    def start(self, ticker: bool = True) -> "LocalMetadataEndpoint":
        endpoint = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            server_version = "StackVendRunnerMetadata"
            sys_version = ""

            def log_message(self, fmt, *args):  # noqa: D401 - no request log (paths only, but keep it quiet)
                return

            def _send(self, status: int, body: str, content_type: str = "application/text"):
                data = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Metadata-Flavor", "Google")
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):  # noqa: N802
                status, body, ctype = endpoint.answer(self.path, self.headers)
                self._send(status, body, ctype)

            def _refuse_method(self):
                self._send(405, "method not allowed")

            do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _refuse_method  # noqa: N815

        self._server = _QuietServer(("127.0.0.1", 0), _Handler)
        serve = threading.Thread(target=self._server.serve_forever, name="runner-metadata", daemon=True)
        serve.start()
        self._threads.append(serve)
        if ticker:
            tick = threading.Thread(target=self._tick_loop, name="runner-token-refresh", daemon=True)
            tick.start()
            self._threads.append(tick)
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()

    @property
    def host(self) -> str:
        if self._server is None:
            raise ri.RunnerIdentityError(RUNNER_IDENTITY_NOT_READY, "metadata endpoint not started",
                                         stage="runner-metadata", http_status=500)
        addr, port = self._server.server_address[:2]
        return f"{addr}:{port}"

    # -- refresh and interruption ----------------------------------------------------------------------------
    def _tick_loop(self) -> None:
        while not self._stop.wait(self.tick_s):
            self.tick()

    def tick(self) -> None:
        """Proactive refresh (so tofu, which asks only near expiry, always gets a fresh token); a terminal broker
        failure interrupts the attached tofu processes."""
        if self.failure is not None:
            return
        try:
            self.credentials.current_token()
        except ri.RunnerIdentityError as e:
            self.abort(e)

    def attach(self, proc: Any) -> None:
        with self._lock:
            self._procs = [p for p in self._procs if _alive(p)] + [proc]
            failed = self.failure is not None
        if failed:
            self._interrupt(proc, signal.SIGINT)

    def abort(self, err: ri.RunnerIdentityError) -> None:
        with self._lock:
            if self.failure is not None:
                return
            self.failure = err
            procs = [p for p in self._procs if _alive(p)]
        logger.error(f"{err.code}: {err.detail}; interrupting {len(procs)} OpenTofu process(es) (SIGINT, state lock "
                     "release)")
        for proc in procs:
            self._interrupt(proc, signal.SIGINT)

    # -- request handling (pure: unit-testable without a socket) ---------------------------------------------
    def answer(self, raw_path: str, headers: Mapping[str, str]) -> Tuple[int, str, str]:
        if headers.get("Metadata-Flavor") != "Google":
            return 403, "Missing required header: Metadata-Flavor: Google", "application/text"
        if headers.get("X-Forwarded-For") is not None:
            return 403, "Requests with X-Forwarded-For are refused", "application/text"
        path, _, query = (raw_path or "").partition("?")
        params = {k: v for k, _, v in (p.partition("=") for p in query.split("&") if p)}
        creds = self.credentials
        if path == "/":
            return 200, "computeMetadata/\n", "application/text"
        if path in (_MD, f"{_MD}/"):
            return 200, "instance/\nproject/\n", "application/text"
        if path == f"{_SA}/":
            if params.get("recursive") == "true":
                return 200, json.dumps({"aliases": ["default"], "email": creds.deployer_email,
                                        "scopes": [CLOUD_PLATFORM_SCOPE]}), "application/json"
            return 200, "aliases\nemail\nscopes\ntoken\n", "application/text"
        if path == f"{_SA}/email":
            return 200, creds.deployer_email, "application/text"
        if path == f"{_MD}/project/project-id":
            return 200, creds.project_id, "application/text"
        if path == f"{_SA}/token":
            if self.failure is not None:
                return 503, self.failure.code, "application/text"
            try:
                token, left = creds.current_token()
            except ri.RunnerIdentityError as e:
                self.abort(e)
                return 503, e.code, "application/text"
            return 200, json.dumps({"access_token": token, "expires_in": int(left),
                                    "token_type": "Bearer"}), "application/json"
        if path == f"{_SA}/identity":
            return 404, IDENTITY_TOKEN_NOT_SERVED, "application/text"
        return 404, "not found", "application/text"


def _alive(proc: Any) -> bool:
    poll = getattr(proc, "poll", None)
    try:
        return poll is None or poll() is None
    except Exception:  # noqa: BLE001
        return False


@dataclass
class WorkspaceRunner:
    """What `TerraformService._register_workspace_runner` keeps for one workspace (memory only)."""
    credentials: BrokeredCredentials
    endpoint: LocalMetadataEndpoint
    key_id: Optional[str] = None
    # FD-7L Phase 4: the product of the verified dispatch and the repository its SIGNED provenance record pins
    # ({"provider", "full_name", "id"}); the run reads only that repository.
    product_id: Optional[str] = None
    repository: Optional[Dict[str, Any]] = None

    @property
    def project_id(self) -> str:
        return self.credentials.project_id


# ------------------------------------------------------------------------------------------------ target check
def _refuse(code: str, detail: str, stage: str = "runner-target", status: int = 409):
    raise ri.RunnerIdentityError(code, detail, stage=stage, http_status=status)


TARGET_FIELDS = ("project_id", "project_number", "deployer_email", "state_bucket")


def verify_run_target(dispatch: Mapping[str, Any], *, provenance: Optional[Mapping[str, Any]],
                      workload: Optional[Mapping[str, Any]], expected_signer: Optional[str],
                      certs: Callable[..., Mapping[str, str]]) -> Tuple[Dict[str, Any], Optional[str]]:
    """(the verified, READY runner identity record, its signature key id). The record must verify for the broker
    (RUNNER_RECORD_UNSIGNED / _KEY_RETIRED / _UNVERIFIABLE), be READY for this product (RUNNER_IDENTITY_NOT_READY),
    and agree with the dispatch record the broker returned and with the workload record's project and pinned
    repository (RUNNER_TARGET_MISMATCH). Nothing here is trusted from the dispatch or the workload record."""
    product_id = dispatch.get("product_id")
    if not isinstance(product_id, str) or not product_id:
        _refuse(RUNNER_TARGET_MISMATCH, "the dispatch record names no product")
    if not expected_signer:
        _refuse("RUNNER_RECORD_UNVERIFIABLE", f"{product_id}: the broker identity is not configured",
                status=503)
    raw = provenance.get(ri.RUNNER_IDENTITY_FIELD) if isinstance(provenance, Mapping) else None
    if raw is None:
        _refuse(RUNNER_IDENTITY_NOT_READY, f"{product_id} has no runner identity record")
    rec = ri.verify_record(ri.provenance_doc_path(product_id), raw, expected_signer=expected_signer, certs=certs)
    rec = ri.check_runner_identity(rec, product_id=product_id, project_id=provenance.get("project_id"))
    for field in TARGET_FIELDS:
        if dispatch.get(field) != rec.get(field):
            _refuse(RUNNER_TARGET_MISMATCH, f"{product_id}: the dispatch record's {field} differs from provenance")
    if isinstance(workload, Mapping):
        recorded = workload.get("project_id")
        if recorded is not None and recorded != rec["project_id"]:
            _refuse(RUNNER_TARGET_MISMATCH, f"{product_id}: workloads/{product_id}.project_id differs from provenance")
        _check_repository(product_id, rec.get("repository"), workload)
    key_id = (raw.get("signature") or {}).get("key_id") if isinstance(raw, Mapping) else None
    return rec, key_id if isinstance(key_id, str) else None


def _check_repository(product_id: str, pinned: Any, workload: Mapping[str, Any]) -> None:
    """The workload record's typed repository identity (`github_repository_identity`: full_name + repository_id) must
    name the repository provenance pins, when both are present (GitHub names compare case-insensitively)."""
    if not isinstance(pinned, Mapping):
        return
    identity = workload.get("github_repository_identity")
    if not isinstance(identity, Mapping):
        return
    name, pinned_name = identity.get("full_name"), pinned.get("full_name")
    if isinstance(name, str) and isinstance(pinned_name, str) and name.lower() != pinned_name.lower():
        _refuse(RUNNER_TARGET_MISMATCH, f"{product_id}: the workload record's repository differs from provenance")
    rid, pinned_id = identity.get("repository_id"), pinned.get("id")
    if rid is not None and pinned_id is not None and str(rid) != str(pinned_id):
        _refuse(RUNNER_TARGET_MISMATCH, f"{product_id}: the workload record's repository id differs from provenance")


def check_state_bucket_owner(session: Any, bucket: str, project_number: str) -> None:
    """STATE_BUCKET_NOT_OWNED unless the bucket's typed `projectNumber` equals provenance's (REST GET with the
    deployer's session; a bucket name is global, so the name alone proves nothing)."""
    try:
        resp = session.get(f"https://storage.googleapis.com/storage/v1/b/{bucket}", params={"fields": "projectNumber"},
                           timeout=15.0)
        status = resp.status_code
        body = resp.json() if status == 200 else {}
    except ri.RunnerIdentityError:
        raise
    except Exception as e:  # noqa: BLE001
        _refuse(STATE_BUCKET_NOT_OWNED, f"gs://{bucket}: owner unreadable ({type(e).__name__})", status=503)
    number = body.get("projectNumber") if isinstance(body, dict) else None
    if status != 200 or str(number) != str(project_number):
        _refuse(STATE_BUCKET_NOT_OWNED, f"gs://{bucket}: not a bucket of project number {project_number} "
                                        f"(HTTP {status})")


# ------------------------------------------------------------------------------------------------ execution name
def execution_name(environ: Mapping[str, str], region: Optional[str]) -> str:
    """projects/<host>/locations/<region>/jobs/<job>/executions/<execution> of this Cloud Run job execution (the
    broker binds the nonce to exactly this name and checks the execution is running and started by the broker)."""
    host, job, exe = environ.get("PROJECT_ID"), environ.get("CLOUD_RUN_JOB"), environ.get("CLOUD_RUN_EXECUTION")
    if not (host and job and exe and region):
        _refuse(RUNNER_IDENTITY_NOT_READY, "not a Cloud Run job execution (PROJECT_ID, CLOUD_RUN_JOB, "
                                           "CLOUD_RUN_EXECUTION or the region is missing)", stage="runner-config",
                status=503)
    return f"projects/{host}/locations/{region}/jobs/{job}/executions/{exe}"


def metadata_region() -> Optional[str]:
    """The execution's region from the container's OWN metadata server (runner process only)."""
    import requests
    resp = requests.get("http://metadata.google.internal/computeMetadata/v1/instance/region",
                        headers={"Metadata-Flavor": "Google"}, timeout=5)
    if resp.status_code != 200:
        return None
    value = resp.text.strip()
    return value.rsplit("/", 1)[-1] or None


# ------------------------------------------------------------------------------------------------ mode log (R10)
def mode_log_record(*, run: str, product_id: Optional[str], trace_id: Optional[str], key_id: Optional[str],
                    brokered: bool, mode: Optional[str], mode_error: Optional[str] = None,
                    environ: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """The R10 mode line. `mode` / `mode_error` come from the caller's one mode reader
    (TerraformService._runner_identity_mode, FD-7L 2b F5); this module never reads the mode itself."""
    env = os.environ if environ is None else environ
    return {
        "event": "runner_identity_mode", "run": run, "product_id": product_id, "trace_id": trace_id,
        "mode": mode, "mode_label": ri.MODE_LABELS.get(mode) if mode else None, "mode_error": mode_error,
        # FD-7L-n: the mode is the Terraform-owned install env, so its source is that variable; it has no
        # updated_at / updated_by of its own (a platform release sets it).
        "mode_source": f"env:{ri.MODE_ENV}", "mode_set": bool((env.get(ri.MODE_ENV) or "").strip()),
        "setting_updated_at": None, "setting_updated_by": None,
        "provenance_key_id": key_id, "brokered": bool(brokered),
    }


def log_mode(**kwargs) -> Dict[str, Any]:
    record = mode_log_record(**kwargs)
    logger.info(f"RUNNER_IDENTITY_MODE {json.dumps(record, sort_keys=True)}")
    return record
