"""
FD-7L: per-workload Terraform runner identity -- names, the install mode, and vending-signed records.

Plan: docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3 (owner 10-30), sections 2.1-2.3 and (Phase 3)
2.7-2.9; register rows "FD-7L plan" and FD-7L-n. Replicated byte-identical (tests/test_fd7l_runner_identity_shared.py)
into apps/project-vending/shared/, mcp-servers/terraform/shared/, apps/control-center/shared/ and
apps/infra-rollback/shared/.

Stdlib only at import time. Signature verification imports google-auth's RSA verifier and the certificate fetcher
imports `requests`, both lazily (every consumer image already ships them).

* Names: the deployer service account of a workload project is `stackvend-deployer@<project>.iam.gserviceaccount.com`
  (no `sa-` prefix, so it never collides with `sa-<pid>`, `sa-gh-deployer`, `sa-bastion-*`, `gcew-*`); its state
  bucket is `<project>-tfstate`, or `<project>-tfstate-<6 hex>` when that global name is taken (the recorded name is
  authoritative); the object prefix stays `workloads/<product_id>`.
* Mode (register rows FD-7L-n, FD-7L-F4): the install DECLARES `STACKVEND_TF_RUNNER_IDENTITY` = `PLATFORM` ("Shared";
  also when unset or blank) or `PER_WORKLOAD` ("Per workload"); any other value is a typed configuration error.
  Terraform owns the variable. `PER_WORKLOAD` is final (the operative mode, nothing else is read). On an install that
  declares Shared, the OPERATIVE mode is the vending-signed record `install_settings/runner_identity` in the guard
  database (set from Control Center Settings through vending); no record AND no change entry = PLATFORM (an install
  never switched). Every reader goes through `runner_identity_mode()`. A missing record after a switch, a record that
  is not the newest logged change (replay), or one that cannot be read or verified is a typed error, never a default.
* Records: vending signs every `runner_identity` provenance field and every runner nonce record with IAM `signBlob` as
  itself. The signature covers the canonical JSON of the document path plus every field of the record except
  `signature`; readers verify it against Google's published x509 certificates of the EXPECTED signer (never a signer
  named by the record), so a write by any other identity (the Control Center SA can also write the guard database)
  can deny service but cannot change what a record says.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Any, Callable, Dict, FrozenSet, Mapping, Optional, Tuple

SCHEMA = "runner_identity/v1"
NONCE_SCHEMA = "runner_nonce/v1"

DEPLOYER_ACCOUNT_ID = "stackvend-deployer"
STATE_BUCKET_SUFFIX = "-tfstate"
STATE_BUCKET_RANDOM_HEX = 6
STATE_PREFIX_ROOT = "workloads"

PROVENANCE_COLLECTION = "workload_provenance"
RUNNER_IDENTITY_FIELD = "runner_identity"
NONCE_COLLECTION = "runner_nonces"

# Install mode (FD-7L-n). The UI labels are the owner's words; the stored values are these two tokens only.
MODE_ENV = "STACKVEND_TF_RUNNER_IDENTITY"
MODE_PLATFORM = "PLATFORM"
MODE_PER_WORKLOAD = "PER_WORKLOAD"
MODES = (MODE_PLATFORM, MODE_PER_WORKLOAD)
MODE_LABELS = {MODE_PLATFORM: "Shared", MODE_PER_WORKLOAD: "Per workload"}

# Terraform-owned vending env (plan 2.3, step A). Before step A sets them, vending derives them (runner_broker.py).
BROKER_SA_ENV = "STACKVEND_BROKER_SA"
RUNNER_MEMBERS_ENV = "STACKVEND_TF_RUNNER_MEMBERS"
SERVER_MEMBERS_ENV = "STACKVEND_TF_SERVER_MEMBERS"

# runner_identity.status values (plan 2.1).
STATUS_NONE = "NONE"
STATUS_SA_READY = "SA_READY"
STATUS_BUCKET_READY = "BUCKET_READY"
STATUS_MIGRATING = "MIGRATING"
STATUS_READY = "READY"
STATUS_FAILED = "FAILED"
STATUSES = (STATUS_NONE, STATUS_SA_READY, STATUS_BUCKET_READY, STATUS_MIGRATING, STATUS_READY, STATUS_FAILED)

# Dispatch modes (plan 2.12). The backfill mode is never accepted from /runner/dispatch (vending starts it itself).
DISPATCH_MODES = ("deploy", "plan", "apply", "drift", "force_unlock")
BACKFILL_MODE = "runner_identity_backfill"

REDEEM_WINDOW_SECONDS = 600          # a nonce is redeemable for about 10 minutes after dispatch (plan 2.3)
DEPLOYER_TOKEN_LIFETIME_SECONDS = 3600
SIGNATURE_ALG = "RS256"
X509_CERT_URL = "https://www.googleapis.com/service_accounts/v1/metadata/x509/{email}"
CERT_CACHE_SECONDS = 600

_PROJECT_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_HEX = frozenset("0123456789abcdef")


class RunnerIdentityError(Exception):
    """A typed FD-7L refusal: `code` (e.g. RUNNER_RECORD_UNSIGNED), `stage` (where), `detail`, `http_status`."""

    def __init__(self, code: str, detail: str, *, stage: str = "runner-identity", http_status: int = 409):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.stage, self.http_status = code, detail, stage, http_status


# ------------------------------------------------------------------------------------------------ names
def is_project_id(value: Any) -> bool:
    """Google Cloud project id shape: 6-30 chars of [a-z0-9-], starts with a letter, does not end with '-'."""
    return (isinstance(value, str) and 6 <= len(value) <= 30 and set(value) <= _PROJECT_ID_CHARS
            and value[0].isalpha() and not value.endswith("-"))


def _require_project_id(project_id: Any) -> str:
    if not is_project_id(project_id):
        raise RunnerIdentityError("RUNNER_IDENTITY_INVALID_PROJECT", f"{project_id!r} is not a project id",
                                  http_status=422)
    return project_id


def deployer_email(project_id: str) -> str:
    return f"{DEPLOYER_ACCOUNT_ID}@{_require_project_id(project_id)}.iam.gserviceaccount.com"


def state_bucket_name(project_id: str, suffix: Optional[str] = None) -> str:
    base = f"{_require_project_id(project_id)}{STATE_BUCKET_SUFFIX}"
    if suffix is None:
        return base
    if not (isinstance(suffix, str) and len(suffix) == STATE_BUCKET_RANDOM_HEX and set(suffix) <= _HEX):
        raise RunnerIdentityError("RUNNER_IDENTITY_INVALID_BUCKET", f"suffix {suffix!r} is not 6 lowercase hex",
                                  http_status=422)
    return f"{base}-{suffix}"


def is_state_bucket_name_for(project_id: str, name: Any) -> bool:
    """True when `name` is exactly `<project>-tfstate` or `<project>-tfstate-<6 hex>` (structural, no pattern)."""
    if not is_project_id(project_id) or not isinstance(name, str):
        return False
    base = state_bucket_name(project_id)
    if name == base:
        return True
    head, rest = name[:len(base) + 1], name[len(base) + 1:]
    return head == base + "-" and len(rest) == STATE_BUCKET_RANDOM_HEX and set(rest) <= _HEX


def random_bucket_suffix() -> str:
    return secrets.token_hex(STATE_BUCKET_RANDOM_HEX // 2)


def state_prefix(product_id: str) -> str:
    if not isinstance(product_id, str) or not product_id or "/" in product_id:
        raise RunnerIdentityError("RUNNER_IDENTITY_INVALID_PRODUCT", f"{product_id!r} is not a product id",
                                  http_status=422)
    return f"{STATE_PREFIX_ROOT}/{product_id}"


def service_account_email(account_id: str, project_id: str) -> str:
    return f"{account_id}@{project_id}.iam.gserviceaccount.com"


# ------------------------------------------------------------------------------------------------ mode
def declared_mode(environ: Optional[Mapping[str, str]] = None) -> str:
    """The install's DECLARATION (Terraform-owned env). Unset or blank -> PLATFORM. Exact tokens only; anything else ->
    RunnerIdentityError(RUNNER_IDENTITY_MODE_INVALID, 503): a misconfigured install never guesses a mode. Not the
    operative mode on a Shared install: call runner_identity_mode()."""
    env = os.environ if environ is None else environ
    raw = env.get(MODE_ENV)
    value = (raw or "").strip()
    if not value:
        return MODE_PLATFORM
    if value not in MODES:
        raise RunnerIdentityError("RUNNER_IDENTITY_MODE_INVALID",
                                  f"{MODE_ENV}={value!r}; expected one of {', '.join(MODES)}", http_status=503)
    return value


# The operative mode record (FD-7L-F4): guard database, written and signed only by vending.
GUARD_DB_ENV = "STACKVEND_GUARD_FIRESTORE_DATABASE"
INSTALL_SETTINGS_COLLECTION = "install_settings"
MODE_RECORD_ID = "runner_identity"
MODE_CHANGES_COLLECTION = "changes"      # install_settings/runner_identity/changes/{id}: one per change, never trimmed
MODE_RECORD_SCHEMA = "runner_identity_mode/v1"
MODE_CHANGE_SCHEMA = "runner_identity_mode_change/v1"
MODE_RECORD_KEYS = frozenset({"schema", "mode", "version", "previous_mode", "set_by", "set_at", "change_id",
                              "signed_by", "signed_at"})
# Readers cache a SUCCESSFUL read of the record for MODE_CACHE_SECONDS per (project, guard database, signer) and per
# process (monotonic clock): a Settings change reaches every reader within about this long without a new revision.
# Failures are never cached. vending clears its own cache after a write.
MODE_CACHE_SECONDS = 15.0

_mode_cache: Dict[Tuple[str, str, str], Tuple[float, str]] = {}
# FD-7L-F4 RT round 2, Q1 (partial mitigation, process-local): the highest record version this process has accepted
# per (project, guard database, signer). A later read of the same key that finds no record and no change entry (the
# record AND the whole log deleted) -> RUNNER_MODE_RECORD_MISSING; a lower version -> RUNNER_MODE_RECORD_STALE. Lost on
# restart / scale to zero; the full mitigation is the post-RC Firestore audit-log row FD-7L-F4-AUDIT.
_mode_high_water: Dict[Tuple[str, str, str], int] = {}
_mode_cache_lock = threading.Lock()
_default_guard_clients: Dict[Tuple[str, str], Any] = {}


def mode_record_doc_path() -> str:
    return f"{INSTALL_SETTINGS_COLLECTION}/{MODE_RECORD_ID}"


def mode_change_doc_path(change_id: str) -> str:
    return f"{mode_record_doc_path()}/{MODE_CHANGES_COLLECTION}/{change_id}"


def clear_mode_cache(*, high_water: bool = False) -> None:
    """Drops cached modes (vending after a write). `high_water=True` also forgets the versions seen (tests only)."""
    with _mode_cache_lock:
        _mode_cache.clear()
        if high_water:
            _mode_high_water.clear()


def new_mode_record(*, mode: str, version: int, previous_mode: Optional[str], set_by: str, set_at: str,
                    change_id: str) -> Dict[str, Any]:
    """An unsigned operative-mode record (vending signs it with sign_record(mode_record_doc_path(), ...))."""
    if mode not in MODES or (previous_mode is not None and previous_mode not in MODES):
        raise RunnerIdentityError("RUNNER_IDENTITY_MODE_INVALID", f"mode {mode!r} / previous {previous_mode!r}",
                                  http_status=422)
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise RunnerIdentityError("RUNNER_MODE_RECORD_INVALID", f"version {version!r}", http_status=500)
    return {"schema": MODE_RECORD_SCHEMA, "mode": mode, "version": version, "previous_mode": previous_mode,
            "set_by": set_by, "set_at": set_at, "change_id": change_id}


def check_mode_record(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Structural check of a VERIFIED operative-mode record: exact key set, schema, mode token, version. Raises
    RunnerIdentityError(RUNNER_MODE_RECORD_INVALID, 503)."""
    def _bad(why: str):
        raise RunnerIdentityError("RUNNER_MODE_RECORD_INVALID", f"{mode_record_doc_path()}: {why}",
                                  stage="runner-identity-mode", http_status=503)

    if set(record) != MODE_RECORD_KEYS:
        _bad(f"keys {sorted(record)}")
    if record.get("schema") != MODE_RECORD_SCHEMA:
        _bad(f"schema {record.get('schema')!r}")
    if record.get("mode") not in MODES:
        _bad(f"mode {record.get('mode')!r}")
    if record.get("previous_mode") is not None and record.get("previous_mode") not in MODES:
        _bad(f"previous mode {record.get('previous_mode')!r}")
    version = record.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        _bad(f"version {version!r}")
    return dict(record)


def _changes_collection(client: Any) -> Any:
    return client.collection(INSTALL_SETTINGS_COLLECTION).document(MODE_RECORD_ID).collection(MODE_CHANGES_COLLECTION)


def any_mode_change(client: Any) -> bool:
    """True when the change log has at least one entry (existence only: no signature, no ordering, no index)."""
    return any(True for _ in _changes_collection(client).limit(1).stream())


def newest_mode_change(client: Any) -> Optional[Dict[str, Any]]:
    """The change entry with the highest NUMERIC `to_version` >= 1 (raw, unverified), or None. The range filter is
    type-scoped in Firestore (RT round 2, N1): a forged string / boolean / map `to_version` never ranks, so readers and
    vending (which ranks the same way) agree on "newest". One single-field-index query."""
    query = _changes_collection(client).where("to_version", ">=", 1)
    for snap in query.order_by("to_version", direction="DESCENDING").limit(1).stream():
        data = snap.to_dict()
        return data if isinstance(data, dict) else {}
    return None


def check_mode_record_current(record: Mapping[str, Any], newest: Optional[Mapping[str, Any]]) -> None:
    """FD-7L-F4 RT M1: the live record must be the one the newest change entry wrote (same version and change id).
    An older, genuinely signed record put back by a guard-database writer (a replay) -> RUNNER_MODE_RECORD_STALE.
    The entry's own signature is not checked here (a forged newer entry only makes readers refuse: fail closed);
    vending's Settings view checks it (RUNNER_MODE_TAMPERED)."""
    if not isinstance(newest, Mapping) or newest.get("to_version") != record.get("version") \
            or newest.get("change_id") != record.get("change_id"):
        raise RunnerIdentityError("RUNNER_MODE_RECORD_STALE",
                                  f"{mode_record_doc_path()} (version {record.get('version')!r}) is not the newest "
                                  "logged change; switch the mode again in Settings",
                                  stage="runner-identity-mode", http_status=503)


def _host_project(env: Mapping[str, str]) -> str:
    return (env.get("PROJECT_ID") or env.get("GOOGLE_CLOUD_PROJECT") or "").strip()


def _default_guard_db(env: Mapping[str, str], database: str) -> Any:
    """A Firestore client for the named guard database of this host (one per process). google-cloud-firestore is
    imported here only (every reader image ships it)."""
    key = (_host_project(env), database)
    with _mode_cache_lock:
        client = _default_guard_clients.get(key)
    if client is not None:
        return client
    from google.cloud import firestore
    client = firestore.Client(project=key[0] or None, database=database)
    with _mode_cache_lock:
        _default_guard_clients[key] = client
    return client


def read_mode_record(environ: Optional[Mapping[str, str]] = None, *, guard_db: Any = None,
                     certs: Optional[Callable[..., Mapping[str, str]]] = None) -> Optional[Dict[str, Any]]:
    """The verified operative-mode record (without `signature`), or None when there is none. Never cached.

    * No guard database configured (`STACKVEND_GUARD_FIRESTORE_DATABASE` unset): None while this service has no
      Terraform-owned broker identity either (before step A: vending refuses to write a Per-workload record there,
      so none can be operative); with `STACKVEND_BROKER_SA` set (step A reached this service) the record must be
      readable -> RUNNER_STORE_UNAVAILABLE (503).
    * No record: None only while the change log is empty (never switched); otherwise RUNNER_MODE_RECORD_MISSING
      (FD-7L-F4 RT H1: a deleted record is never a silent fallback to PLATFORM).
    * Guard database unreadable -> RUNNER_STORE_UNAVAILABLE (503); signer not configured -> RUNNER_RECORD_UNVERIFIABLE;
      signature -> verify_record's codes (RUNNER_RECORD_UNSIGNED / _UNVERIFIABLE / _KEY_RETIRED); content ->
      RUNNER_MODE_RECORD_INVALID; not the newest logged change -> RUNNER_MODE_RECORD_STALE (RT M1). All 503: the
      install, not one workload, is misconfigured."""
    env = os.environ if environ is None else environ
    database = (env.get(GUARD_DB_ENV) or "").strip()
    if not database:
        if (env.get(BROKER_SA_ENV) or "").strip():
            raise RunnerIdentityError("RUNNER_STORE_UNAVAILABLE",
                                      f"{GUARD_DB_ENV} is not set but {BROKER_SA_ENV} is: the runner identity mode "
                                      "record cannot be read", stage="runner-identity-mode", http_status=503)
        return None
    def _unreadable(e: Exception, what: str):
        raise RunnerIdentityError("RUNNER_STORE_UNAVAILABLE", f"{what} unreadable ({type(e).__name__})",
                                  stage="runner-identity-mode", http_status=503) from None

    try:
        client = guard_db if guard_db is not None else _default_guard_db(env, database)
        snap = client.collection(INSTALL_SETTINGS_COLLECTION).document(MODE_RECORD_ID).get()
        exists = getattr(snap, "exists", False) is True
        doc = snap.to_dict() if exists else None
    except Exception as e:  # noqa: BLE001 - an unreadable record is never "no record"
        _unreadable(e, mode_record_doc_path())
    if not exists:
        try:
            switched = any_mode_change(client)
        except Exception as e:  # noqa: BLE001
            _unreadable(e, f"{mode_record_doc_path()}/{MODE_CHANGES_COLLECTION}")
        if switched:
            raise RunnerIdentityError("RUNNER_MODE_RECORD_MISSING",
                                      f"{mode_record_doc_path()} is missing but the mode was switched before (the "
                                      f"change log has entries); switch the mode again in Settings",
                                      stage="runner-identity-mode", http_status=503)
        return None
    signer = expected_broker_email(env)
    if not signer:
        raise RunnerIdentityError("RUNNER_RECORD_UNVERIFIABLE", f"{mode_record_doc_path()}: the broker identity is "
                                  "not configured", stage="runner-identity-mode", http_status=503)
    try:
        rec = verify_record(mode_record_doc_path(), doc, expected_signer=signer,
                            certs=certs if certs is not None else _default_certs())
    except RunnerIdentityError as e:
        raise RunnerIdentityError(e.code, e.detail, stage="runner-identity-mode", http_status=503) from None
    rec = check_mode_record(rec)
    try:
        newest = newest_mode_change(client)
    except Exception as e:  # noqa: BLE001
        _unreadable(e, f"{mode_record_doc_path()}/{MODE_CHANGES_COLLECTION}")
    check_mode_record_current(rec, newest)
    return rec


def runner_identity_mode(environ: Optional[Mapping[str, str]] = None, *, guard_db: Any = None,
                         certs: Optional[Callable[..., Mapping[str, str]]] = None) -> str:
    """THE operative runner identity mode (FD-7L-F4); every reader calls this.

    1. The declaration (declared_mode): an unknown value -> RUNNER_IDENTITY_MODE_INVALID (503); `PER_WORKLOAD` ->
       PER_WORKLOAD (final; nothing is read).
    2. Otherwise the signed record (read_mode_record): its mode; no record and no change entry -> PLATFORM; anything
       else is the typed error read_mode_record raises (never a default once the mode was switched).
    A successful record read is cached MODE_CACHE_SECONDS (see there)."""
    env = os.environ if environ is None else environ
    declared = declared_mode(env)
    if declared == MODE_PER_WORKLOAD:
        return declared
    database = (env.get(GUARD_DB_ENV) or "").strip()
    key = (_host_project(env), database, expected_broker_email(env) or "")
    now = time.monotonic()
    if database:
        with _mode_cache_lock:
            hit = _mode_cache.get(key)
        if hit is not None and 0 <= now - hit[0] < MODE_CACHE_SECONDS:
            return hit[1]
    rec = read_mode_record(env, guard_db=guard_db, certs=certs)
    if database:
        with _mode_cache_lock:
            seen = _mode_high_water.get(key, 0)
        if rec is None and seen >= 1:
            raise RunnerIdentityError("RUNNER_MODE_RECORD_MISSING",
                                      f"{mode_record_doc_path()} and its change log are gone, but this process read "
                                      f"version {seen}; switch the mode again in Settings",
                                      stage="runner-identity-mode", http_status=503)
        if rec is not None and rec["version"] < seen:
            raise RunnerIdentityError("RUNNER_MODE_RECORD_STALE",
                                      f"{mode_record_doc_path()} version {rec['version']} is older than version "
                                      f"{seen} this process read; switch the mode again in Settings",
                                      stage="runner-identity-mode", http_status=503)
        if rec is not None:
            with _mode_cache_lock:
                _mode_high_water[key] = max(seen, rec["version"])
    mode = rec["mode"] if rec is not None else MODE_PLATFORM
    if database:
        with _mode_cache_lock:
            _mode_cache[key] = (now, mode)
    return mode


_default_cert_fetcher: Optional["X509CertFetcher"] = None


def _default_certs() -> Callable[..., Mapping[str, str]]:
    global _default_cert_fetcher
    with _mode_cache_lock:
        if _default_cert_fetcher is None:
            _default_cert_fetcher = X509CertFetcher()
        return _default_cert_fetcher


def csv_emails(raw: Optional[str]) -> FrozenSet[str]:
    return frozenset(p.strip().lower() for p in (raw or "").split(",") if p.strip())


def service_account_members(raw: Optional[str]) -> FrozenSet[str]:
    """Emails of the `serviceAccount:<email>` entries of a comma-separated IAM member list (other kinds ignored)."""
    out = set()
    for part in (raw or "").split(","):
        kind, sep, ident = part.strip().partition(":")
        if sep and kind == "serviceAccount" and ident and ident == ident.strip():
            out.add(ident.lower())
    return frozenset(out)


# ------------------------------------------------------------------------------------------------ signing payload
def _json_value_ok(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool)):
        return True
    if isinstance(value, int):
        return True
    if isinstance(value, list):
        return all(_json_value_ok(v) for v in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and _json_value_ok(v) for k, v in value.items())
    return False   # floats, datetimes, bytes: never in a signed record (they do not round-trip exactly)


def canonical_payload(doc_path: str, record: Mapping[str, Any]) -> bytes:
    """The bytes vending signs: {"doc": <path>, "record": <record without 'signature'>} as sorted, compact JSON."""
    body = {k: v for k, v in record.items() if k != "signature"}
    if not isinstance(doc_path, str) or not doc_path or not _json_value_ok(body):
        raise RunnerIdentityError("RUNNER_RECORD_UNSIGNABLE", f"{doc_path!r}: record holds a non-JSON value",
                                  http_status=500)
    return json.dumps({"doc": doc_path, "record": body}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def provenance_doc_path(product_id: str) -> str:
    """The path a runner_identity record is signed for: the provenance document plus the field name."""
    return f"{PROVENANCE_COLLECTION}/{product_id}#{RUNNER_IDENTITY_FIELD}"


def nonce_doc_path(doc_id: str) -> str:
    return f"{NONCE_COLLECTION}/{doc_id}"


def attach_signature(record: Dict[str, Any], *, key_id: str, signature_b64: str) -> Dict[str, Any]:
    out = dict(record)
    out["signature"] = {"alg": SIGNATURE_ALG, "key_id": key_id, "value": signature_b64}
    return out


def sign_record(doc_path: str, record: Dict[str, Any], *, signer_email: str, signed_at: str,
                sign_blob: Callable[[bytes], Tuple[str, str]]) -> Dict[str, Any]:
    """Returns a copy of `record` with `signed_by` / `signed_at` set and a `signature` from `sign_blob(payload)`, which
    answers (key_id, base64 signature) -- IAM signBlob as `signer_email` in production."""
    body = {k: v for k, v in record.items() if k != "signature"}
    body["signed_by"] = signer_email.lower()
    body["signed_at"] = signed_at
    key_id, sig = sign_blob(canonical_payload(doc_path, body))
    if not isinstance(key_id, str) or not key_id or not isinstance(sig, str) or not sig:
        raise RunnerIdentityError("RUNNER_RECORD_SIGN_FAILED", "signBlob returned no key id or signature",
                                  http_status=503)
    return attach_signature(body, key_id=key_id, signature_b64=sig)


def _rsa_verify(cert_pem: str, payload: bytes, signature: bytes) -> bool:
    from google.auth import crypt
    try:
        return bool(crypt.RSAVerifier.from_string(cert_pem).verify(payload, signature))
    except Exception:  # noqa: BLE001 - an unusable certificate verifies nothing
        return False


def verify_record(doc_path: str, doc: Any, *, expected_signer: str,
                  certs: Callable[..., Mapping[str, str]]) -> Dict[str, Any]:
    """The record (without `signature`) when its signature verifies for `expected_signer`; else
    RunnerIdentityError(RUNNER_RECORD_UNSIGNED). `certs(email, refresh=False)` returns {key_id: PEM certificate}; a key
    id missing from a cached answer is looked up once more with refresh=True."""
    def _refuse(why: str):
        raise RunnerIdentityError("RUNNER_RECORD_UNSIGNED", f"{doc_path}: {why}", http_status=409)

    if not isinstance(doc, dict):
        _refuse("no record")
    sig = doc.get("signature")
    if not isinstance(sig, dict) or sig.get("alg") != SIGNATURE_ALG:
        _refuse("no signature")
    key_id, value = sig.get("key_id"), sig.get("value")
    if not isinstance(key_id, str) or not key_id or not isinstance(value, str) or not value:
        _refuse("malformed signature")
    signer = (expected_signer or "").strip().lower()
    if not signer or doc.get("signed_by") != signer:
        _refuse("not signed by the broker")
    try:
        raw_sig = base64.b64decode(value.encode("ascii"), validate=True)
        payload = canonical_payload(doc_path, doc)
    except RunnerIdentityError:
        _refuse("record holds a non-JSON value")
    except Exception:  # noqa: BLE001
        _refuse("malformed signature")
    try:
        keys = certs(signer, refresh=False) or {}
        if key_id not in keys:
            keys = certs(signer, refresh=True) or {}
    except Exception as e:  # noqa: BLE001 - certificates unavailable: nothing can be verified
        raise RunnerIdentityError("RUNNER_RECORD_UNVERIFIABLE",
                                  f"{doc_path}: signer certificates unavailable ({type(e).__name__})",
                                  http_status=503) from None
    if key_id not in keys:
        # FD-7L RT F1: a well-formed record from the broker whose Google-managed key is no longer published (the key
        # was rotated out). Still a refusal, never a fallback, but not reported as a forgery: an operator re-signs.
        raise RunnerIdentityError("RUNNER_RECORD_KEY_RETIRED",
                                  f"{doc_path}: signing key {key_id} of {signer} is no longer published; run the "
                                  "runner-identity re-sign sweep", http_status=409)
    cert = keys.get(key_id)
    if not isinstance(cert, str) or not _rsa_verify(cert, payload, raw_sig):
        _refuse("signature does not verify")
    return {k: v for k, v in doc.items() if k != "signature"}


class X509CertFetcher:
    """Google's published x509 certificates of a service account ({key_id: PEM}), cached CERT_CACHE_SECONDS. Public,
    unauthenticated endpoint; any failure raises (the caller maps it to RUNNER_RECORD_UNVERIFIABLE)."""

    def __init__(self, http_get: Optional[Callable[..., Any]] = None, clock: Callable[[], float] = time.monotonic):
        self._get = http_get
        self._clock = clock
        self._cache: Dict[str, Tuple[float, Dict[str, str]]] = {}
        self._lock = threading.Lock()

    def __call__(self, email: str, refresh: bool = False) -> Dict[str, str]:
        email = email.strip().lower()
        with self._lock:
            hit = self._cache.get(email)
            if hit and not refresh and self._clock() - hit[0] < CERT_CACHE_SECONDS:
                return dict(hit[1])
        get = self._get
        if get is None:
            import requests
            get = requests.get
        resp = get(X509_CERT_URL.format(email=email), timeout=10)
        if getattr(resp, "status_code", None) != 200:
            raise RuntimeError(f"x509 certificates of {email}: HTTP {getattr(resp, 'status_code', None)}")
        body = resp.json()
        if not isinstance(body, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in body.items()):
            raise RuntimeError(f"x509 certificates of {email}: unexpected body")
        with self._lock:
            self._cache[email] = (self._clock(), dict(body))
        return dict(body)


# ------------------------------------------------------------------------------------------------ records
RUNNER_IDENTITY_KEYS = ("schema", "product_id", "project_id", "project_number", "deployer_email", "state_bucket",
                        "state_prefix", "repository", "status", "migration", "error_class", "updated_at",
                        "signed_by", "signed_at")


def new_runner_identity_record(*, product_id: str, project_id: str, project_number: str, state_bucket: Optional[str],
                               status: str, updated_at: str, repository: Optional[Dict[str, Any]] = None,
                               error_class: Optional[str] = None) -> Dict[str, Any]:
    """An unsigned runner_identity record with every key present (constant shape; update() replaces the field)."""
    if status not in STATUSES:
        raise RunnerIdentityError("RUNNER_IDENTITY_INVALID_STATUS", f"{status!r}", http_status=500)
    return {
        "schema": SCHEMA,
        "product_id": product_id,
        "project_id": project_id,
        "project_number": str(project_number),
        "deployer_email": deployer_email(project_id),
        "state_bucket": state_bucket,
        "state_prefix": state_prefix(product_id),
        "repository": repository,
        "status": status,
        "migration": None,
        "error_class": error_class,
        "updated_at": updated_at,
    }


def check_runner_identity(record: Mapping[str, Any], *, product_id: str, project_id: Optional[str] = None,
                          project_number: Optional[str] = None, require_ready: bool = True) -> Dict[str, Any]:
    """Structural check of a VERIFIED record against the expected product (and project, when given). Re-derives the
    deployer email and the bucket name shape; never trusts them from the record. Raises RunnerIdentityError."""
    def _bad(code: str, why: str, status: int = 409):
        raise RunnerIdentityError(code, f"{product_id}: {why}", http_status=status)

    if record.get("schema") != SCHEMA:
        _bad("RUNNER_RECORD_UNSIGNED", f"schema {record.get('schema')!r}")
    if record.get("product_id") != product_id:
        _bad("RUNNER_TARGET_MISMATCH", "record names another product")
    pid = record.get("project_id")
    if not is_project_id(pid):
        _bad("RUNNER_TARGET_MISMATCH", "record has no valid project id")
    if project_id is not None and pid != project_id:
        _bad("RUNNER_TARGET_MISMATCH", f"record project {pid!r} differs from {project_id!r}")
    number = record.get("project_number")
    if not (isinstance(number, str) and number.isdigit()):
        _bad("RUNNER_TARGET_MISMATCH", "record has no numeric project number")
    if project_number is not None and number != str(project_number):
        _bad("RUNNER_TARGET_MISMATCH", "record project number differs")
    if record.get("deployer_email") != deployer_email(pid):
        _bad("RUNNER_TARGET_MISMATCH", "record deployer is not the project's stackvend-deployer")
    if record.get("state_prefix") != state_prefix(product_id):
        _bad("RUNNER_TARGET_MISMATCH", "record state prefix differs")
    if require_ready:
        if record.get("status") != STATUS_READY:
            _bad("RUNNER_IDENTITY_NOT_READY", f"status {record.get('status')!r}")
        if not is_state_bucket_name_for(pid, record.get("state_bucket")):
            _bad("RUNNER_TARGET_MISMATCH", "record state bucket is not the project's")
    return dict(record)


# ------------------------------------------------------------------------------------------------ nonce / session
def new_nonce() -> str:
    return secrets.token_urlsafe(32)


def nonce_doc_id(nonce: str) -> str:
    """The guard-DB id of a nonce record: sha256 of the nonce (the nonce itself is never stored)."""
    if not isinstance(nonce, str) or len(nonce) < 32:
        raise RunnerIdentityError("RUNNER_NONCE_UNKNOWN", "malformed nonce", http_status=404)
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()


def _is_doc_id(value: str) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def new_session_key(doc_id: str) -> str:
    if not _is_doc_id(doc_id):
        raise RunnerIdentityError("RUNNER_SESSION_INVALID", "bad record id", http_status=500)
    return f"{doc_id}.{secrets.token_urlsafe(32)}"


def session_doc_id(session_key: Any) -> str:
    """The nonce record a session key belongs to (its first component). Raises RUNNER_SESSION_INVALID (401)."""
    head, sep, tail = (session_key if isinstance(session_key, str) else "").partition(".")
    if not sep or not _is_doc_id(head) or len(tail) < 32:
        raise RunnerIdentityError("RUNNER_SESSION_INVALID", "malformed session key", http_status=401)
    return head


def secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def secret_matches(value: str, expected_hash: Any) -> bool:
    return isinstance(expected_hash, str) and hmac.compare_digest(secret_hash(value), expected_hash)


# ------------------------------------------------------------------------------------------------ state (phase 3)
# Object names under a state prefix (OpenTofu GCS backend, workspace `default`). Unchanged by FD-7L.
STATE_OBJECT = "default.tfstate"
LOCK_OBJECT = "default.tflock"
PROVISIONER_ACCOUNT_ID = "sa-project-provisioner"   # vending's own runtime SA (infra/platform, step A broker)

# Migration lock and tombstone (plan 2.7 steps 3 and 6). Both are OpenTofu LockInfo JSON objects at
# <platform bucket>/workloads/<pid>/default.tflock. OpenTofu treats either as a held lock (its ID is never one a tofu
# run created), so a run that still points at the platform bucket stops with a lock error that names the new state
# location. They are recognised by their exact `Operation` field (typed equality, never text in `Info`).
MIGRATION_LOCK_OPERATION = "StackVendStateMigration"
TOMBSTONE_OPERATION = "StackVendStateMoved"
TOMBSTONE_MARKER = "STACKVEND_STATE_MOVED"
LOCK_WHO = "stackvend-vending"


def state_object_name(product_id: str) -> str:
    return f"{state_prefix(product_id)}/{STATE_OBJECT}"


def lock_object_name(product_id: str) -> str:
    return f"{state_prefix(product_id)}/{LOCK_OBJECT}"


def lock_info(*, operation: str, lock_id: str, info: str, path: str, created: str) -> Dict[str, Any]:
    """An OpenTofu LockInfo document (the GCS backend stores exactly these keys)."""
    return {"ID": lock_id, "Operation": operation, "Info": info, "Who": LOCK_WHO, "Version": "", "Created": created,
            "Path": path}


def tombstone_info(bucket: str, product_id: str) -> str:
    return f"{TOMBSTONE_MARKER} gs://{bucket}/{state_prefix(product_id)} -- do not force-unlock"


def is_tombstone(lock: Any) -> bool:
    """True when a parsed lock object is the FD-7L tombstone (exact Operation and Who; plan 2.7 step 6). Phase 2b's
    force_unlock refuses such a lock (STATE_MOVED_DO_NOT_UNLOCK)."""
    return isinstance(lock, dict) and lock.get("Operation") == TOMBSTONE_OPERATION and lock.get("Who") == LOCK_WHO


def is_migration_lock(lock: Any, lock_id: Optional[str] = None) -> bool:
    return (isinstance(lock, dict) and lock.get("Operation") == MIGRATION_LOCK_OPERATION
            and lock.get("Who") == LOCK_WHO and (lock_id is None or lock.get("ID") == lock_id))


def expected_broker_email(environ: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """The signer every reader expects on a runner_identity record: STACKVEND_BROKER_SA (Terraform-owned, step A),
    else vending's own provisioner identity of this host (PROJECT_ID). None when neither is configured."""
    env = os.environ if environ is None else environ
    named = (env.get(BROKER_SA_ENV) or "").strip().lower()
    if named:
        return named
    host = (env.get("PROJECT_ID") or "").strip()
    return service_account_email(PROVISIONER_ACCOUNT_ID, host).lower() if host else None


def state_location(product_id: str, provenance: Optional[Mapping[str, Any]], *, legacy_bucket: str,
                   expected_signer: Optional[str], certs: Callable[..., Mapping[str, str]]) -> Dict[str, Any]:
    """Where a reader (Control Center, FinOps sync, rollback) finds a workload's state on a Per-workload install
    (plan 2.9): the provenance record's bucket when the signed runner_identity record is READY; the platform bucket
    (`legacy_bucket`) while there is no record or it is not READY. A record that does not verify, or that names another
    product / a bucket that is not its project's, raises RunnerIdentityError (never a silent fallback)."""
    prefix = state_prefix(product_id)
    raw = provenance.get(RUNNER_IDENTITY_FIELD) if isinstance(provenance, Mapping) else None
    if raw is None:
        return {"bucket": legacy_bucket, "prefix": prefix, "source": "platform", "status": STATUS_NONE}
    if not expected_signer:
        raise RunnerIdentityError("RUNNER_RECORD_UNVERIFIABLE", f"{product_id}: the broker identity is not configured",
                                  http_status=503)
    rec = verify_record(provenance_doc_path(product_id), raw, expected_signer=expected_signer, certs=certs)
    status = rec.get("status")
    if status != STATUS_READY:
        check_runner_identity(rec, product_id=product_id, project_id=provenance.get("project_id"),
                              require_ready=False)
        return {"bucket": legacy_bucket, "prefix": prefix, "source": "platform", "status": status}
    rec = check_runner_identity(rec, product_id=product_id, project_id=provenance.get("project_id"))
    return {"bucket": rec["state_bucket"], "prefix": prefix, "source": "provenance", "status": status}
