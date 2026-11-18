"""
FD-7L Phase 5b (SAT-31b; plan docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3, section 2.12, D3-a): the
synchronous runs of a Per-workload install as tf-applier executions. Nothing here runs on a Shared install.

* Staged payload (re-RT R3): the request's inputs (Express or plan `hcl_files`, the destroy approval, the engine, the
  lock ID of an unlock, the run's deadline) go into ONE canonical JSON object in the host staging bucket
  (`STACKVEND_RUNNER_STAGING_BUCKET`, plan step A), never into the job's environment. The server creates it once
  (`ifGenerationMatch=0`: no overwrite; its account may only create objects there) and passes `payload_ref` and the
  payload's sha256 to vending's `/runner/dispatch`, which puts both into the SIGNED dispatch record. The execution reads
  the object and refuses bytes whose sha256 differs, or a payload naming another mode, product or trace
  (`RUNNER_PAYLOAD_MISMATCH`).
* Result channel: the execution writes one result document `runner_results/<dispatch_id>` (default database, created
  once) and the server polls it until the request's deadline (`RUNNER_RESULT_TIMEOUT`). A document whose dispatch,
  execution, product, trace or mode is not this run's is refused (`RUNNER_RESULT_MISMATCH`), and the server accepts a
  result only when vending's SIGNED dispatch record shows that exactly this execution redeemed it. The result is ONE
  canonical JSON string (`result_text`: sorted keys; Firestore keeps no nested lists; oversized output fields are
  shortened and `result_truncated` is inside it).
* Signed result fingerprint (SAT-37, closes the SAT-31b residual): BEFORE it writes the document the execution posts
  sha256(result_json) to vending's session-bound `/runner/result`; vending signs it into the dispatch record
  (`result_sha256`). The server uses a document only when the sha256 of its `result_json` equals that signed
  fingerprint (`RUNNER_RESULT_MISMATCH` otherwise; a document without a signed fingerprint yet is looked at again), so
  a default-database writer can no longer substitute the answer. When vending cannot sign it, the execution writes no
  document and fails (`RUNNER_RESULT_NOT_RECORDED`).

The server's staging write uses the server's own identity on the HOST staging bucket only (`_host_storage_session`,
allow-listed in the `ast` guard); the job's read uses the job's own identity on the same bucket. Neither ever holds a
deployer credential. Nothing here logs a token, a nonce or the payload's content.
"""
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Any, Callable, Dict, Mapping, Optional, Tuple
from urllib.parse import quote, urlsplit

from shared import runner_identity as ri

logger = logging.getLogger("tf-runner-runs")

# ------------------------------------------------------------------------------------------------ typed classes
RUNNER_PAYLOAD_UNCONFIGURED = "RUNNER_PAYLOAD_UNCONFIGURED"        # no staging bucket on this server / job (step A)
RUNNER_PAYLOAD_STAGING_FAILED = "RUNNER_PAYLOAD_STAGING_FAILED"    # the server could not create the payload object
RUNNER_PAYLOAD_MISMATCH = "RUNNER_PAYLOAD_MISMATCH"                # bytes / fields differ from the signed record
RUNNER_PAYLOAD_UNREADABLE = "RUNNER_PAYLOAD_UNREADABLE"            # the execution could not read the payload object
RUNNER_RESULT_TIMEOUT = "RUNNER_RESULT_TIMEOUT"                    # no result before the request's deadline
RUNNER_RESULT_MISMATCH = "RUNNER_RESULT_MISMATCH"                  # a result document that is not this run's
RUNNER_RESULT_NOT_RECORDED = "RUNNER_RESULT_NOT_RECORDED"          # the execution could not write its result
RUNNER_SYNC_DEADLINE_PASSED = "RUNNER_SYNC_DEADLINE_PASSED"        # the execution started after the request's deadline
# RT L2 (SAT-37): vending reports the bound execution ended, and no accepted result appeared within the grace period.
TF_APPLIER_EXECUTION_ENDED_WITHOUT_RESULT = "TF_APPLIER_EXECUTION_ENDED_WITHOUT_RESULT"
# SAT-37 (5b part 2): a plan run refused by the one-way OpenTofu -> Terraform gate (in-process: an HTTP 400).
IAC_ENGINE_DOWNGRADE_BLOCKED = "IAC_ENGINE_DOWNGRADE_BLOCKED"

PAYLOAD_STAGE = "runner-payload"
RESULT_STAGE = "runner-result"

STAGING_BUCKET_ENV = "STACKVEND_RUNNER_STAGING_BUCKET"
PAYLOAD_SCHEMA = "runner_payload/v1"
RESULT_SCHEMA = "runner_result/v1"
RESULT_COLLECTION = "runner_results"
# The synchronous dispatch modes run in an execution (SAT-37: + plan; its saved plan is not kept, so saved-plan apply
# and drift, which need a kept workspace, are not executions yet).
SYNC_MODES = ("deploy", "force_unlock", "plan")
RESULT_POLL_S = 5.0
RETRY = object()                                 # wait_for_result's `confirm`: not decidable now, look again
# RT M2 (11-01): the sync deploy's deadline in the execution is this much earlier than the in-process one, so a
# budget-killed deploy's own typed result (SIGINT grace + pipe drain after the deadline) is written before the server's
# last poll (two polls + the result write and the signed-record check).
# SAT-37: plus the execution's one call to vending's /runner/result (the signed fingerprint) before the write.
RESULT_SIGN_ALLOWANCE_S = 10.0
SYNC_RESULT_MARGIN_S = 2 * RESULT_POLL_S + 20.0 + RESULT_SIGN_ALLOWANCE_S
# RT L2 (SAT-37): the server asks vending for the execution's state once a minute from this long after the dispatch;
# an execution that vending reports ended this long ago without an accepted result ends the wait.
EXECUTION_STATE_FIRST_S = 60.0
EXECUTION_ENDED_GRACE_S = 60.0
RESULT_MAX_CHARS = 700_000                       # Firestore keeps 1 MiB per document
RESULT_TRIM_KEYS = ("stdout", "stderr", "plan_output", "log")
RESULT_DROP_KEYS = ("raw_plan_json",)            # SAT-37: a plan's full JSON is dropped first when the result is too big
STAGING_TIMEOUT_S = 60.0
_GCS = "https://storage.googleapis.com"
_RW_SCOPE = "https://www.googleapis.com/auth/devstorage.read_write"
_RO_SCOPE = "https://www.googleapis.com/auth/devstorage.read_only"


def _err(code: str, detail: str, status: int, stage: str) -> ri.RunnerIdentityError:
    return ri.RunnerIdentityError(code, detail, stage=stage, http_status=status)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_payload(*, mode: str, product_id: str, trace_id: str, options: Mapping[str, Any]) -> bytes:
    """The canonical payload bytes (sorted keys, no whitespace): the sha256 in the signed record covers exactly these."""
    if mode not in SYNC_MODES:
        raise _err(RUNNER_PAYLOAD_MISMATCH, f"mode {mode!r} has no staged payload", 422, PAYLOAD_STAGE)
    body = {"schema": PAYLOAD_SCHEMA, "mode": mode, "product_id": product_id, "trace_id": trace_id,
            "options": dict(options)}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def staging_bucket(environ: Mapping[str, str]) -> str:
    name = (environ.get(STAGING_BUCKET_ENV) or "").strip()
    if not name:
        raise _err(RUNNER_PAYLOAD_UNCONFIGURED, f"{STAGING_BUCKET_ENV} is not set (plan step A)", 503, PAYLOAD_STAGE)
    return name


def _host_storage_session(scope: str):
    """This container's OWN identity for the host staging bucket (the server: create only; the job: read only).
    Never a child project, never a deployer credential."""
    import google.auth
    from google.auth.transport.requests import AuthorizedSession
    creds, _ = google.auth.default(scopes=[scope])
    return AuthorizedSession(creds)


class PayloadStager:
    """Server side: one create-only upload per run. Never retried (a new name per run; a failed upload dispatches
    nothing)."""

    def __init__(self, bucket: str, *, session: Any = None):
        self.bucket = bucket
        self._session = session

    def stage(self, *, product_id: str, trace_id: str, data: bytes) -> Tuple[str, str]:
        name = f"runs/{product_id}/{trace_id}/{secrets.token_hex(16)}.json"
        url = (f"{_GCS}/upload/storage/v1/b/{quote(self.bucket, safe='')}/o?uploadType=media"
               f"&name={quote(name, safe='')}&ifGenerationMatch=0")
        try:
            session = self._session or _host_storage_session(_RW_SCOPE)
            resp = session.post(url, data=data, headers={"Content-Type": "application/json"},
                                timeout=STAGING_TIMEOUT_S)
            status = getattr(resp, "status_code", None)
        except Exception as e:  # noqa: BLE001 - nothing is dispatched without the payload
            raise _err(RUNNER_PAYLOAD_STAGING_FAILED, f"staging upload failed ({type(e).__name__}); nothing was "
                       "dispatched", 503, PAYLOAD_STAGE) from None
        if status != 200:
            raise _err(RUNNER_PAYLOAD_STAGING_FAILED, f"staging upload answered HTTP {status}; nothing was "
                       "dispatched", 503, PAYLOAD_STAGE)
        return f"gs://{self.bucket}/{name}", sha256_hex(data)


def read_payload(record: Mapping[str, Any], environ: Mapping[str, str], *, session: Any = None) -> Dict[str, Any]:
    """Job side: the staged payload of a verified dispatch record, after the sha256 and field checks. Returns the
    payload's `options`. Raises RunnerIdentityError (typed)."""
    ref, want = record.get("payload_ref"), record.get("payload_sha256")
    bucket = staging_bucket(environ)
    parts = urlsplit(ref) if isinstance(ref, str) else None
    obj = parts.path.lstrip("/") if parts is not None else ""
    if parts is None or parts.scheme != "gs" or parts.netloc != bucket or not obj or parts.query or parts.fragment \
            or not isinstance(want, str) or len(want) != 64:
        raise _err(RUNNER_PAYLOAD_MISMATCH, "the dispatch record names no payload in this install's staging bucket",
                   409, PAYLOAD_STAGE)
    url = f"{_GCS}/storage/v1/b/{quote(bucket, safe='')}/o/{quote(obj, safe='')}?alt=media"
    try:
        resp = (session or _host_storage_session(_RO_SCOPE)).get(url, timeout=STAGING_TIMEOUT_S)
        status = getattr(resp, "status_code", None)
        data = resp.content if status == 200 else None
    except Exception as e:  # noqa: BLE001
        raise _err(RUNNER_PAYLOAD_UNREADABLE, f"payload read failed ({type(e).__name__})", 503,
                   PAYLOAD_STAGE) from None
    if not isinstance(data, (bytes, bytearray)):
        raise _err(RUNNER_PAYLOAD_UNREADABLE, f"payload read answered HTTP {status}", 503, PAYLOAD_STAGE)
    if not hmac.compare_digest(sha256_hex(bytes(data)), want):
        raise _err(RUNNER_PAYLOAD_MISMATCH, "the payload's sha256 is not the one in the signed dispatch record", 409,
                   PAYLOAD_STAGE)
    try:
        body = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _err(RUNNER_PAYLOAD_MISMATCH, "the payload is not JSON", 409, PAYLOAD_STAGE) from None
    if not isinstance(body, dict) or body.get("schema") != PAYLOAD_SCHEMA or not isinstance(body.get("options"), dict):
        raise _err(RUNNER_PAYLOAD_MISMATCH, "the payload is not a runner payload", 409, PAYLOAD_STAGE)
    for key in ("mode", "product_id", "trace_id"):
        if body.get(key) != record.get(key):
            raise _err(RUNNER_PAYLOAD_MISMATCH, f"the payload's {key} is not the signed dispatch record's", 409,
                       PAYLOAD_STAGE)
    return body["options"]


# ------------------------------------------------------------------------------------------------ result channel
def _dumps(result: Mapping[str, Any]) -> str:
    return json.dumps(result, default=str, sort_keys=True)


def result_text(result: Dict[str, Any]) -> Tuple[str, bool]:
    """(the canonical result JSON, shortened?). The text is exactly what the document's `result_json` holds and what
    vending signs the sha256 of; a shortened result carries `result_truncated: true` INSIDE the text (covered by the
    fingerprint)."""
    text = _dumps(result)
    if len(text) <= RESULT_MAX_CHARS:
        return text, False
    short = dict(result, result_truncated=True)
    for key in RESULT_DROP_KEYS:
        if short.get(key) is not None:
            short[key] = None
    budget = RESULT_MAX_CHARS // (2 * len(RESULT_TRIM_KEYS))
    for key in RESULT_TRIM_KEYS:
        if isinstance(short.get(key), str) and len(short[key]) > budget:
            short[key] = "...[shortened]..." + short[key][-budget:]
    text = _dumps(short)
    if len(text) <= RESULT_MAX_CHARS:
        return text, True
    keep = {k: short.get(k) for k in ("status", "error_class", "error", "product_id", "trace_id", "service_url",
                                      "operator_required", "lock_id", "is_safe_autonomous") if k in short}
    keep["error"] = (str(keep.get("error") or ""))[-20_000:] or None
    keep["result_truncated"] = True
    return _dumps(keep), True


def result_fingerprint(result_json: str) -> str:
    """sha256 of the result document's `result_json` (UTF-8): what vending signs into the dispatch record."""
    return sha256_hex(result_json.encode("utf-8"))


class ResultStore:
    """`runner_results/<dispatch_id>` in the default database (the job writes once, the server reads)."""

    def __init__(self, db: Any):
        self.db = db

    def _ref(self, dispatch_id: str):
        return self.db.collection(RESULT_COLLECTION).document(dispatch_id)

    def write(self, dispatch_id: str, *, execution: str, product_id: str, trace_id: str, mode: str,
              result_json: str, result_truncated: bool, finished_at: str) -> None:
        self._ref(dispatch_id).create({
            "schema": RESULT_SCHEMA, "dispatch_id": dispatch_id, "execution": execution, "product_id": product_id,
            "trace_id": trace_id, "mode": mode, "result_json": result_json, "result_truncated": result_truncated,
            "finished_at": finished_at})

    def get(self, dispatch_id: str) -> Optional[Dict[str, Any]]:
        snap = self._ref(dispatch_id).get()
        return snap.to_dict() if getattr(snap, "exists", False) is True else None


def wait_for_result(store: Any, *, dispatch_id: str, expected: Mapping[str, str], deadline: float,
                    clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                    redeem_failed: Optional[Callable[[], Optional[ri.RunnerIdentityError]]] = None,
                    confirm: Optional[Callable[[str], Any]] = None) -> Dict[str, Any]:
    """Poll the result document until `deadline` (epoch seconds). Returns the run's result dict. Raises
    RUNNER_RESULT_TIMEOUT (504, the execution may still run), RUNNER_RESULT_MISMATCH (502), or whatever
    `redeem_failed` returns (the execution failed before it redeemed its nonce, or ended without a result). A read
    error is retried until the deadline (logged once). `confirm(fingerprint)` (called once a matching document is
    found, with the sha256 of its `result_json`) accepts it (None), refuses it (returns a RunnerIdentityError, raised)
    or asks for another look later (RETRY)."""
    read_error_logged = False
    while True:
        try:
            doc = store.get(dispatch_id)
        except Exception as e:  # noqa: BLE001 - a read error is retried until the deadline
            doc = None
            if not read_error_logged:
                logger.warning(f"runner result {dispatch_id[:12]}: read failed ({type(e).__name__}); retrying")
                read_error_logged = True
        if doc is not None:
            if doc.get("schema") != RESULT_SCHEMA or doc.get("dispatch_id") != dispatch_id or any(
                    doc.get(k) != v for k, v in expected.items()):
                raise _err(RUNNER_RESULT_MISMATCH, f"the result document of dispatch {dispatch_id[:12]} is not this "
                           "run's", 502, RESULT_STAGE)
            text = doc.get("result_json")
            try:
                result = json.loads(text) if isinstance(text, str) else None
            except ValueError:
                result = None
            if not isinstance(result, dict):
                raise _err(RUNNER_RESULT_MISMATCH, f"the result of dispatch {dispatch_id[:12]} is not a JSON object",
                           502, RESULT_STAGE)
            verdict = confirm(result_fingerprint(text)) if confirm is not None else None
            if verdict is None:
                return result
            if verdict is not RETRY:
                raise verdict
        if redeem_failed is not None:   # also after a RETRY verdict: an unredeemed run still ends at the window
            failed = redeem_failed()
            if failed is not None:
                raise failed
        if clock() >= deadline:
            raise _err(RUNNER_RESULT_TIMEOUT, f"no result from tf-applier execution {expected.get('execution')} "
                       "before the request's deadline; it may still be running (check the execution and the "
                       "workload's state before a retry)", 504, RESULT_STAGE)
        sleep(min(RESULT_POLL_S, max(0.0, deadline - clock())))
