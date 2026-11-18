"""
StackVend: sandbox-garbage-collector-job (C32, FD-4BC) - ephemeral-resource TTL cleaner.

Runs every 2 hours (scheduler ``castor-sandbox-ttl-cleaner``, unchanged). Each run reads the vending-written
ephemeral ledger ``ephemeral_resources`` (records with ``status == "REGISTERED"`` whose
``resource_create_time + ttl_seconds`` has passed, oldest first, at most ``BATCH_CAP`` per run) and asks
project-repo-vending to expire each one: ``POST /ephemeral/{eid}:expire`` with this job's Google ID token.

Wave 2 lane 14 PR-6 (plan docs/planning/wave2-lane14-core-services-plan.md sections 1.6, 2.0, 2.2; register row
L14-l; row 26 / L18-m: the cleaner holds no delete permission):
- The cleaner never lists, matches or deletes anything by name, label, prefix or substring. The three earlier sweeps
  (host-project Cloud Run services selected by test-runner name fragments, tfstate objects under a bucket prefix, and
  the job container's own temp directories) are replaced by this ledger loop.
- Vending's guard is the SOLE authority for every delete (checks 1-7 + the ephemeral checks of lane 18 S1e). The
  cleaner adds no ownership logic of its own and never writes the ledger (vending is its single writer).
- Fail closed: any error reading the ledger, writing the run record or the audit entry means no vending call.
  An empty ledger means zero calls and exit 0.
- Before lane 18's ``EPHEMERAL_TTL`` executor (step S1e) exists, vending answers 404 for the route: every call is
  recorded ``REFUSED:EXECUTOR_UNAVAILABLE`` and the run still exits 0.

Exit codes (plan 2.0): 0 = no target errored (``REFUSED`` is not an error), 1 = an error, 2 = usage,
3 = ``NOT_CONFIGURED`` (logged once at WARNING with ``error_class`` and recorded on the run record, so the sentinel
never dispatches it).

SEAMS (marked ``SEAM(...)`` below):
- lane 18 S0b: the ledger lives in the named guard database once ``STACKVEND_GUARD_FIRESTORE_DATABASE`` is set on this
  job (lane 5 / lane 18 TF); until then it is read from the default database.
- lane 18 S1e: the route, the response body (``{"status": "DELETED", ...}`` on 200; ``{"detail": {"code", "detail"}}``
  on refusal, the vending convention) and the audience vending accepts. Vending accepts only ``aud`` in its own
  ``VENDING_SERVICE_URL`` (the deterministic ``https://project-repo-vending-service-<number>.<region>.run.app``), so
  this job calls the URL in ITS ``VENDING_SERVICE_URL`` env (the same install contract the Control Center uses; RT
  F6-2) and mints the token for exactly that URL. Only when the variable is absent does it fall back to Run Admin
  ``services.get``; present but empty or not a bare ``https://`` origin -> ``VENDING_URL_UNRESOLVED`` (fail closed).
- lane 14 PR-M: once ``shared/managed_target.py`` is vendored here, run ``verify_managed_target`` per record for the
  report only (vending stays the authority).
"""

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

logger = logging.getLogger("sandbox-garbage-collector-job")
logging.basicConfig(level=logging.INFO)

JOB_NAME = "sandbox-garbage-collector-job"
VENDING_SERVICE = "project-repo-vending-service"

LEDGER_COLLECTION = "ephemeral_resources"      # vending-written (lane 18 S1e); read-only here
STATUS_REGISTERED = "REGISTERED"
RUN_RECORD_COLLECTION = f"{JOB_NAME}_runs"     # read by the sentinel (sre_classifier.run_record_collection)
AUDIT_COLLECTION = "ephemeral_ttl_requests"    # one entry per vending call, written BEFORE the call
SUMMARY_COLLECTION = "sandbox_cleanups"        # per-run summary (existing collection, kept)
AUDIT_ACTION = "EPHEMERAL_TTL_REQUEST"

GUARD_DB_ENV = "STACKVEND_GUARD_FIRESTORE_DATABASE"
VENDING_URL_ENV = "VENDING_SERVICE_URL"
BATCH_CAP = 10
HTTP_TIMEOUT_SECONDS = 30
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_NOT_CONFIGURED = 3

# Per-record outcomes
DELETED = "DELETED"
REFUSED = "REFUSED"
FAILED = "FAILED"
WOULD_REQUEST = "WOULD_REQUEST"

# Run outcomes (run record ``outcome``)
RUN_RUNNING = "RUNNING"
RUN_COMPLETED = "COMPLETED"
RUN_COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"
RUN_FAILED = "FAILED"
RUN_NOT_CONFIGURED = "NOT_CONFIGURED"
RUN_OUTCOME_EXIT_CODES: Dict[str, int] = {
    RUN_COMPLETED: EXIT_OK,
    RUN_COMPLETED_WITH_ERRORS: EXIT_ERROR,
    RUN_FAILED: EXIT_ERROR,
    RUN_NOT_CONFIGURED: EXIT_NOT_CONFIGURED,
    RUN_RUNNING: EXIT_ERROR,  # an earlier attempt of this execution was interrupted: no second mutation
}

# Vending answers without a typed code that mean "the EPHEMERAL_TTL route does not exist yet" (plan 1.6).
EXECUTOR_UNAVAILABLE_STATUSES = frozenset({404, 501})
# Vending answers WITH a typed code that are executor failures (an error), not guard refusals.
EXECUTOR_FAILURE_STATUSES = frozenset({500, 502})
# Vending answers that mean "this job's identity or audience is wrong" (lane 18 authenticate_caller): an error, never a
# guard refusal (RT F6-1). Exact codes from apps/project-vending/destructive_guard.py. HTTP 401 is always an error.
CALLER_IDENTITY_FAILURE_CODES = frozenset({"UNAUTHENTICATED", "CALLER_NOT_ALLOWED"})


class NotConfigured(Exception):
    def __init__(self, missing: List[str]):
        super().__init__("missing configuration: " + ", ".join(missing))
        self.missing = list(missing)


class StoreUnavailable(Exception):
    """A Firestore read or write the run depends on failed (the run fails closed)."""


# ----------------------------------------------------------------------------------------------------------------
# Ledger records
# ----------------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class LedgerRecord:
    eid: str
    product_id: str
    rest_name: str
    resource_create_time: datetime
    ttl_seconds: int

    @property
    def expires_at(self) -> datetime:
        return self.resource_create_time + timedelta(seconds=self.ttl_seconds)


def canonical_eid(value: Any) -> Optional[str]:
    """The ledger id is a UUID4 chosen by the producer (plan 1.6). Parsed with ``uuid.UUID`` and accepted only in its
    canonical text form, so nothing but a UUID is ever placed in the vending URL path."""
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return value if str(parsed) == value else None


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Firestore timestamp (a ``datetime``) or an RFC 3339 string; timezone required."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed.tzinfo is not None else None


def parse_ledger_record(doc_id: Any, data: Any) -> Tuple[Optional[LedgerRecord], str]:
    """(record, "") for a well-formed REGISTERED record, else (None, <reason>)."""
    if not isinstance(data, Mapping):
        return None, "NOT_A_DOCUMENT"
    eid = canonical_eid(doc_id)
    if eid is None:
        return None, "EID_NOT_A_UUID"
    if data.get("status") != STATUS_REGISTERED:
        return None, "STATUS_NOT_REGISTERED"
    created = parse_timestamp(data.get("resource_create_time"))
    if created is None:
        return None, "RESOURCE_CREATE_TIME_INVALID"
    ttl = data.get("ttl_seconds")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        return None, "TTL_SECONDS_INVALID"
    product_id = data.get("product_id") if isinstance(data.get("product_id"), str) else ""
    rest_name = data.get("rest_name") if isinstance(data.get("rest_name"), str) else ""
    return LedgerRecord(eid=eid, product_id=product_id, rest_name=rest_name,
                        resource_create_time=created, ttl_seconds=ttl), ""


# ----------------------------------------------------------------------------------------------------------------
# Vending response -> outcome (exact status codes and typed body fields only)
# ----------------------------------------------------------------------------------------------------------------
def _typed_code(body: Any) -> str:
    """Vending's refusal code: ``{"detail": {"code": ...}}`` (FastAPI HTTPException, lane 18 convention) or a
    top-level ``{"code": ...}``. "" when the body carries no typed code."""
    if not isinstance(body, Mapping):
        return ""
    detail = body.get("detail")
    if isinstance(detail, Mapping) and isinstance(detail.get("code"), str) and detail.get("code"):
        return detail["code"]
    if isinstance(body.get("code"), str) and body.get("code"):
        return body["code"]
    return ""


def classify_vending_response(status_code: int, body: Any) -> Tuple[str, str, bool]:
    """(outcome, code, is_error) for one ``:expire`` answer."""
    if status_code == 200:
        if isinstance(body, Mapping) and body.get("status") == DELETED:
            return DELETED, "", False
        return FAILED, "UNEXPECTED_RESPONSE", True
    code = _typed_code(body)
    if status_code == 401:  # "the caller is not authenticated": never a guard refusal (RT F6-1)
        return FAILED, code or "HTTP_401", True
    if code:
        if status_code in EXECUTOR_FAILURE_STATUSES or code in CALLER_IDENTITY_FAILURE_CODES:
            return FAILED, code, True
        return REFUSED, code, False
    if status_code in EXECUTOR_UNAVAILABLE_STATUSES:
        return REFUSED, "EXECUTOR_UNAVAILABLE", False
    return FAILED, f"HTTP_{status_code}", True


# ----------------------------------------------------------------------------------------------------------------
# Default cloud adapters (REST via AuthorizedSession / google.oauth2; no gcloud). Replaced in tests.
# ----------------------------------------------------------------------------------------------------------------
def _authorized_session():
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    credentials, _ = google.auth.default(scopes=[CLOUD_PLATFORM_SCOPE])
    return AuthorizedSession(credentials)


def default_service_url_resolver(project_id: str, region: str, service_name: str) -> Optional[str]:
    """Run Admin v2 ``services.get`` by exact service name (plan G14) -> its HTTPS ``uri``, or None."""
    resp = _authorized_session().get(
        f"https://run.googleapis.com/v2/projects/{project_id}/locations/{region}/services/{service_name}",
        timeout=HTTP_TIMEOUT_SECONDS)
    resp.raise_for_status()
    uri = (resp.json() or {}).get("uri")
    return uri.rstrip("/") if isinstance(uri, str) and uri.startswith("https://") else None


def env_vending_url(value: Any) -> Optional[str]:
    """``VENDING_SERVICE_URL`` from this job's env: accepted only as one bare ``https://`` origin (parsed with
    ``urllib.parse``; no path, query, fragment or userinfo), returned without a trailing ``/``. None otherwise."""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    try:
        parts = urlsplit(candidate)
        port_ok = parts.port is None or parts.port > 0
    except ValueError:
        return None
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None or parts.password is not None
            or parts.path not in ("", "/") or parts.query or parts.fragment or not port_ok):
        return None
    return candidate.rstrip("/")


def default_id_token_fetcher(audience: str) -> str:
    import google.auth.transport.requests
    from google.oauth2 import id_token

    return id_token.fetch_id_token(google.auth.transport.requests.Request(), audience)


def default_http_post(url: str, *, headers: Dict[str, str], json_body: Dict[str, Any], timeout: int) -> Tuple[int, Any]:
    import requests

    resp = requests.post(url, headers=headers, json=json_body, timeout=timeout, allow_redirects=False)
    try:
        body = resp.json()
    except ValueError:
        body = None
    return resp.status_code, body


def _default_firestore(project_id: str, database: str = ""):
    from google.cloud import firestore

    if database:
        return firestore.Client(project=project_id, database=database)
    return firestore.Client(project=project_id)


def _is_already_exists(exc: Exception) -> bool:
    try:
        from google.api_core.exceptions import AlreadyExists, Conflict

        return isinstance(exc, (AlreadyExists, Conflict))
    except Exception:  # pragma: no cover - api_core always ships with firestore
        return False


def _registered_filter():
    from google.cloud.firestore_v1.base_query import FieldFilter

    return FieldFilter("status", "==", STATUS_REGISTERED)


# ----------------------------------------------------------------------------------------------------------------
# The job
# ----------------------------------------------------------------------------------------------------------------
@dataclass
class _Run:
    run_id: str
    dry_run: bool
    started_at: str
    results: List[Dict[str, Any]] = field(default_factory=list)
    invalid_records: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    not_due: int = 0
    deferred: int = 0


class SandboxGarbageCollector:
    def __init__(
        self,
        project_id: Optional[str] = None,
        *,
        env: Optional[Mapping[str, str]] = None,
        firestore_client: Optional[Any] = None,
        ledger_client: Optional[Any] = None,
        service_url_resolver: Optional[Callable[[str, str, str], Optional[str]]] = None,
        id_token_fetcher: Optional[Callable[[str], str]] = None,
        http_post: Optional[Callable[..., Tuple[int, Any]]] = None,
        clock: Optional[Callable[[], datetime]] = None,
        firestore_factory: Optional[Callable[[str, str], Any]] = None,
    ):
        self._env = env if env is not None else os.environ
        self.project_id = project_id if project_id is not None else self._env.get("PROJECT_ID", "")
        self._db = firestore_client
        self._ledger = ledger_client
        self._firestore_factory = firestore_factory or _default_firestore
        self._service_url_resolver = service_url_resolver or default_service_url_resolver
        self._id_token_fetcher = id_token_fetcher or default_id_token_fetcher
        self._http_post = http_post or default_http_post
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._vending_url: Optional[str] = None

    # ------------------------------------------------------------------ configuration
    def config(self) -> Dict[str, Any]:
        region = self._env.get("REGION", "")
        if VENDING_URL_ENV in self._env:  # the install contract; present -> authoritative (fail closed if invalid)
            env_url = env_vending_url(self._env.get(VENDING_URL_ENV))
            source = "env" if env_url else "unresolved"
        else:
            env_url = None
            source = "services.get" if region else "unresolved"
        return {
            "project_id": self.project_id,
            "region": region,
            "guard_database": (self._env.get(GUARD_DB_ENV) or "").strip(),
            "vending_url_source": source,
            "vending_url_env": env_url,
        }

    def health(self) -> Dict[str, Any]:
        cfg = self.config()
        degraded = [name for name, value in (("PROJECT_ID", cfg["project_id"]), ("REGION", cfg["region"])) if not value]
        if VENDING_URL_ENV in self._env and cfg["vending_url_env"] is None:
            degraded.append(VENDING_URL_ENV)
        return {
            "status": "degraded" if degraded else "healthy",
            "service": JOB_NAME,
            "missing_configuration": degraded,
            "vending_url_source": cfg["vending_url_source"],
            "ledger": LEDGER_COLLECTION,
            "ledger_database": cfg["guard_database"] or "(default)",
            "ttl_source": "per-record ttl_seconds in the vending-written ephemeral ledger",
            "batch_cap": BATCH_CAP,
        }

    def _default_db(self):
        if self._db is None:
            self._db = self._firestore_factory(self.project_id, "")
        return self._db

    def _ledger_db(self, cfg: Dict[str, Any]):
        # SEAM(lane 18 S0b): vending writes the ledger into the guard database; this job reads it there as soon as
        # STACKVEND_GUARD_FIRESTORE_DATABASE is exported to it (read-only grant, lane 18 guard_db_readers).
        if self._ledger is None:
            self._ledger = (self._firestore_factory(self.project_id, cfg["guard_database"])
                            if cfg["guard_database"] else self._default_db())
        return self._ledger

    # ------------------------------------------------------------------ ledger
    def read_due_records(self, cfg: Dict[str, Any], now: datetime, run: _Run) -> List[LedgerRecord]:
        """REGISTERED records whose TTL has passed, oldest expiry first, capped at BATCH_CAP. Malformed records are
        reported (an error) and never sent. Raises StoreUnavailable when the ledger cannot be read."""
        try:
            docs = list(self._ledger_db(cfg).collection(LEDGER_COLLECTION).where(filter=_registered_filter()).stream())
        except Exception as e:
            raise StoreUnavailable(f"{LEDGER_COLLECTION}: {type(e).__name__}: {e}") from e
        due: List[LedgerRecord] = []
        for doc in docs:
            record, reason = parse_ledger_record(getattr(doc, "id", None), doc.to_dict())
            if record is None:
                run.invalid_records.append({"eid": str(getattr(doc, "id", "")), "reason": reason})
                continue
            if now >= record.expires_at:
                due.append(record)
            else:
                run.not_due += 1
        due.sort(key=lambda r: (r.expires_at, r.eid))
        run.deferred = max(0, len(due) - BATCH_CAP)
        return due[:BATCH_CAP]

    # ------------------------------------------------------------------ run record (idempotency, plan 2.0)
    def _claim_run(self, run: _Run) -> Optional[Dict[str, Any]]:
        """``create()`` the run record. Returns None when this attempt owns the run, else the existing record (a retry
        or re-run of the same execution: no second mutation). Raises StoreUnavailable."""
        ref = self._default_db().collection(RUN_RECORD_COLLECTION).document(run.run_id)
        try:
            ref.create({"job": JOB_NAME, "run_id": run.run_id, "outcome": RUN_RUNNING, "started_at": run.started_at})
            return None
        except Exception as e:
            if not _is_already_exists(e):
                raise StoreUnavailable(f"{RUN_RECORD_COLLECTION}/{run.run_id}: {type(e).__name__}: {e}") from e
        try:
            snap = ref.get()
        except Exception as e:
            raise StoreUnavailable(f"{RUN_RECORD_COLLECTION}/{run.run_id}: {type(e).__name__}: {e}") from e
        return (snap.to_dict() or {}) if snap.exists else {"outcome": RUN_RUNNING}

    def _finish_run_record(self, run: _Run, outcome: str, summary: Dict[str, Any]) -> None:
        try:
            self._default_db().collection(RUN_RECORD_COLLECTION).document(run.run_id).set(
                {"job": JOB_NAME, "run_id": run.run_id, "outcome": outcome, "started_at": run.started_at,
                 "finished_at": self._clock().isoformat(), "summary": summary})
        except Exception as e:
            logger.warning(f"Could not finish run record {RUN_RECORD_COLLECTION}/{run.run_id}: {e}")

    def _write_summary(self, run: _Run, report: Dict[str, Any]) -> None:
        try:
            self._default_db().collection(SUMMARY_COLLECTION).document(run.run_id).set(report)
        except Exception as e:
            logger.warning(f"Could not write cleanup summary {SUMMARY_COLLECTION}/{run.run_id}: {e}")

    # ------------------------------------------------------------------ vending
    def _vending_endpoint(self, cfg: Dict[str, Any]) -> Optional[str]:
        if cfg["vending_url_source"] == "env":
            return cfg["vending_url_env"]
        if VENDING_URL_ENV in self._env:  # present but empty / not a bare https origin: fail closed, no lookup
            return None
        if self._vending_url is None:
            try:
                self._vending_url = self._service_url_resolver(cfg["project_id"], cfg["region"], VENDING_SERVICE) or None
            except Exception as e:
                logger.warning(f"Could not resolve the {VENDING_SERVICE} URL: {e}")
                self._vending_url = None
        return self._vending_url

    def _request_expiry(self, cfg: Dict[str, Any], run: _Run, record: LedgerRecord) -> Dict[str, Any]:
        result: Dict[str, Any] = {"eid": record.eid, "product_id": record.product_id, "rest_name": record.rest_name,
                                  "expired_at": record.expires_at.isoformat()}
        if run.dry_run:
            result.update({"outcome": WOULD_REQUEST, "code": ""})
            return result

        audit_ref = None
        try:
            audit_ref = self._default_db().collection(AUDIT_COLLECTION).document(f"{run.run_id}--{record.eid}")
            audit_ref.create({"action": AUDIT_ACTION, "job": JOB_NAME, "run_id": run.run_id, "eid": record.eid,
                              "product_id": record.product_id, "rest_name": record.rest_name,
                              "requested_at": self._clock().isoformat(), "outcome": "REQUESTING"})
        except Exception as e:  # audit first: no audit entry, no call
            result.update({"outcome": FAILED, "code": "AUDIT_UNAVAILABLE", "detail": f"{type(e).__name__}: {e}"})
            return result

        result.update(self._call_vending(cfg, run, record))
        try:
            audit_ref.update({"outcome": result["outcome"], "code": result["code"],
                              "http_status": result.get("http_status"), "completed_at": self._clock().isoformat()})
        except Exception as e:
            logger.warning(f"Could not complete audit entry for {record.eid}: {e}")
        return result

    def _call_vending(self, cfg: Dict[str, Any], run: _Run, record: LedgerRecord) -> Dict[str, Any]:
        base = self._vending_endpoint(cfg)
        if not base:
            return {"outcome": FAILED, "code": "VENDING_URL_UNRESOLVED"}
        try:
            token = self._id_token_fetcher(base)
        except Exception as e:
            return {"outcome": FAILED, "code": "ID_TOKEN_UNAVAILABLE", "detail": f"{type(e).__name__}: {e}"}
        # SEAM(lane 18 S1e): route + body contract of the EPHEMERAL_TTL executor (plan 1.6).
        url = f"{base}/ephemeral/{record.eid}:expire"
        try:
            status_code, body = self._http_post(
                url, headers={"Authorization": f"Bearer {token}"},
                json_body={"eid": record.eid, "requested_by": JOB_NAME, "run_id": run.run_id},
                timeout=HTTP_TIMEOUT_SECONDS)
        except Exception as e:
            return {"outcome": FAILED, "code": "VENDING_UNREACHABLE", "detail": f"{type(e).__name__}: {e}"}
        outcome, code, _ = classify_vending_response(status_code, body)
        out: Dict[str, Any] = {"outcome": outcome, "code": code, "http_status": status_code}
        if outcome == DELETED and isinstance(body, Mapping) and isinstance(body.get("operation"), str):
            out["operation"] = body["operation"]
        return out

    # ------------------------------------------------------------------ entry point
    def execute_cleanup(self, dry_run: bool = False, run_id: Optional[str] = None) -> Dict[str, Any]:
        """One run. Returns the report; ``report["exit_code"]`` is the process exit code (plan 2.0)."""
        now = self._clock()
        run = _Run(run_id=run_id or self._env.get("CLOUD_RUN_EXECUTION") or f"manual-{uuid.uuid4().hex[:12]}",
                   dry_run=dry_run, started_at=now.isoformat())
        cfg = self.config()
        try:
            if not cfg["project_id"]:
                raise NotConfigured(["PROJECT_ID"])
            if not dry_run:
                existing = self._claim_run(run)
                if existing is not None:
                    recorded = existing.get("outcome") if isinstance(existing.get("outcome"), str) else RUN_RUNNING
                    logger.warning(f"Run {run.run_id} already recorded with outcome {recorded}; no second run.")
                    return {"job": JOB_NAME, "run_id": run.run_id, "status": "ALREADY_RECORDED",
                            "recorded_outcome": recorded,
                            "exit_code": RUN_OUTCOME_EXIT_CODES.get(recorded, EXIT_ERROR)}
            due = self.read_due_records(cfg, now, run)
            if due and not dry_run and not cfg["region"] and VENDING_URL_ENV not in self._env:
                # REGION is needed only to resolve vending via services.get (VENDING_SERVICE_URL absent); an empty
                # run needs none.
                raise NotConfigured(["REGION"])
            for record in due:
                run.results.append(self._request_expiry(cfg, run, record))
        except NotConfigured as e:
            logger.warning(json.dumps({"error_class": "NOT_CONFIGURED", "job": JOB_NAME, "missing": e.missing}))
            report = self._report(run, RUN_NOT_CONFIGURED, EXIT_NOT_CONFIGURED, missing=e.missing)
            if cfg["project_id"] and not dry_run:
                self._finish_run_record(run, RUN_NOT_CONFIGURED, report)
            return report
        except StoreUnavailable as e:
            run.errors.append(f"STORE_UNAVAILABLE: {e}")
            logger.error(f"Sandbox cleaner run {run.run_id} failed closed (no vending call made after the failure): {e}")
            report = self._report(run, RUN_FAILED, EXIT_ERROR)
            if not dry_run:
                self._finish_run_record(run, RUN_FAILED, report)
            return report

        errored = bool(run.invalid_records) or any(r["outcome"] == FAILED for r in run.results)
        outcome = RUN_COMPLETED_WITH_ERRORS if errored else RUN_COMPLETED
        report = self._report(run, outcome, EXIT_ERROR if errored else EXIT_OK)
        for r in run.results:
            if r["outcome"] == REFUSED:
                logger.warning(f"EPHEMERAL_TTL refused for {r['eid']} ({r['rest_name']}): REFUSED:{r['code']}")
            elif r["outcome"] == FAILED:
                logger.error(f"EPHEMERAL_TTL request failed for {r['eid']} ({r['rest_name']}): FAILED:{r['code']}")
        for bad in run.invalid_records:
            logger.error(f"Malformed ephemeral ledger record {bad['eid']!r}: {bad['reason']} (not sent to vending)")
        if not dry_run:
            self._finish_run_record(run, outcome, report)
            self._write_summary(run, report)
        logger.info(f"Sandbox cleaner run {run.run_id}: {outcome}, {len(run.results)} request(s), "
                    f"{run.not_due} not yet due, {run.deferred} deferred")
        return report

    def _report(self, run: _Run, outcome: str, exit_code: int, **extra: Any) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for r in run.results:
            key = r["outcome"] if r["outcome"] in (DELETED, WOULD_REQUEST) else f"{r['outcome']}:{r['code']}"
            counts[key] = counts.get(key, 0) + 1
        report = {
            "job": JOB_NAME,
            "run_id": run.run_id,
            "cleanup_id": run.run_id,
            "executed_at": run.started_at,
            "dry_run": run.dry_run,
            "status": outcome,
            "exit_code": exit_code,
            "ledger": LEDGER_COLLECTION,
            "requests": run.results,
            "outcome_counts": counts,
            "deleted_count": counts.get(DELETED, 0),
            "not_yet_due_count": run.not_due,
            "deferred_count": run.deferred,
            "invalid_records": run.invalid_records,
            "errors": run.errors,
        }
        report.update(extra)
        return report
