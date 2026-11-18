"""
StackVend: Log SRE Sentinel Engine (C27).

Ingests Cloud Logging error entries (Pub/Sub push from ``castor-sre-error-sink``), classifies each entry by exact
identity (``sre_classifier.py``), fingerprints and de-duplicates it, RECORDS every incident in Firestore
(``incidents/{id}``, read by the Control Center incident card) and dispatches the ``castor-sre-remediation``
workflow only when the dispatch rules allow it.

Wave 2 lane 14 PR-2 (owner register row 24; plan docs/planning/wave2-lane14-core-services-plan.md section 2.5):
- classification by exact ``resource.type`` + ``logName`` project + host project number (no substring maps);
- every incident recorded;
- tenant (WORKLOAD) incidents dispatch with an explicit ``execution_mode: "FULL_BUILD"`` once the orchestrator's
  intake contract is accepted on the install (lane 17 R17-2); until then ``SUPPRESSED:INTAKE_CONTRACT_PENDING``;
- platform incidents are record-only (``RECORD_ONLY:CONSUMER_MODE``: StackVend never remediates its own services);
  Workflows pipeline failures are linked to their pipeline run and never re-dispatched; the SRE workflow's own failures and the sentinel's own errors are never dispatched (self-loop guard);
  a job incident whose run record says ``NOT_CONFIGURED`` is never dispatched (G11).

Which execution modes the install's orchestrator accepts from the SRE channel is the env ``SRE_INTAKE_ACCEPTED_MODES``
(JSON list, exact members of ``ACCEPTED_MODE_VALUES``; absent = none). It is a dispatch rule input set per install
when the accepting orchestrator YAML is deployed there, not a component flag: the sentinel, the sink, the workflow and
the incident record keep working either way.
"""

import hashlib
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from google.cloud import firestore

import sre_classifier as clf

logger = logging.getLogger("log-sre-sentinel-service")
logging.basicConfig(level=logging.INFO)

# Keys the castor-sre-remediation workflow reads from its arguments (pinned both ways against
# workflows/sre_remediation.yaml by tests/test_lane14_sre_workflow_args.py).
REMEDIATION_ARG_KEYS: Tuple[str, ...] = (
    "trace_id",
    "incident_id",
    "sre_sentinel_url",
    "workspace_mcp_url",
    "spec_intake_topic",
    "execution_mode",
)

EXECUTION_MODE_FULL_BUILD = "FULL_BUILD"
EXECUTION_MODE_PLATFORM_REMEDIATION = "PLATFORM_REMEDIATION"
ACCEPTED_MODE_VALUES: FrozenSet[str] = frozenset({EXECUTION_MODE_FULL_BUILD, EXECUTION_MODE_PLATFORM_REMEDIATION})

SENTINEL_SERVICE = clf.SENTINEL_SERVICE_NAME
WORKSPACE_SERVICE = "mcp-workspace-connector"
DEFAULT_SRE_WORKFLOW_NAME = "castor-sre-remediation"
SPEC_INTAKE_TOPIC_NAME = "spec-intake-events"

# Outcomes the remediation workflow may report back (POST /incidents/{id}/outcome). Exact allow-set.
OUTCOME_REMEDIATION_FAILED = "REMEDIATION_FAILED"
OUTCOME_INTAKE_PUBLISHED = "INTAKE_PUBLISHED"
REMEDIATION_OUTCOMES: FrozenSet[str] = frozenset({OUTCOME_REMEDIATION_FAILED, OUTCOME_INTAKE_PUBLISHED})

# Cluster statuses after which a recurrence opens a new incident.
CLOSED_CLUSTER_STATUSES: FrozenSet[str] = frozenset({"CLOSED", "RESOLVED"})

DEFAULT_DEDUP_COOLDOWN_SECONDS = 3600
DEFAULT_OPEN_REQUEST_TTL_SECONDS = 86400
HOST_NUMBER_RETRY_SECONDS = 300
SPEC_TEXT_TRACE_LIMIT = 8000

CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

# Cloud Logging LogEntry fields that identify one delivery / one occurrence, never the error itself (exact field names
# of the LogEntry schema). Dropped from the fallback fingerprint of entries that have no jsonPayload.stack_trace /
# jsonPayload.message / textPayload, so recurrences of such an error cluster (RT F4). Entries that have one of those
# fields fingerprint exactly as before.
VOLATILE_LOG_ENTRY_FIELDS: FrozenSet[str] = frozenset({
    "insertId", "timestamp", "receiveTimestamp", "labels", "trace", "spanId", "traceSampled", "operation",
})

# Control Center (routes/workloads.py, schemas.py), project vending and the pre-PR-2 sentinel all treat a ledger doc
# WITHOUT ``sre_auto_healing_enabled`` as enabled; the sentinel uses the same default so the CC card and the dispatch
# gate agree (RT F8). A present value must be exactly ``True``; False, None or any non-bool value suppresses.
SRE_AUTO_HEALING_DEFAULT_WHEN_ABSENT = True

# Registered incidents (``register_incident``, POST /incidents/register; plan 2.5 item 6). Exact allow-set of
# StackVend sources; the classification's resource_type marks the incident as registered, not a Cloud Logging entry.
REGISTRATION_SOURCES: FrozenSet[str] = frozenset({"sre-telemetry-digest-job"})
REGISTERED_RESOURCE_TYPE = "stackvend.registered_finding"
REGISTRATION_SEVERITIES: FrozenSet[str] = frozenset({"WARNING", "ERROR"})
REGISTRATION_MAX_ID_LENGTH = 256
REGISTRATION_MAX_EVIDENCE_BYTES = 16384

# Caller identity on POST /incidents/register (RT F3-1; lane 18 ``authenticate_caller`` pattern). A Google-signed ID
# token whose ``aud`` is this service's own URL and whose verified email is in the exact allow-list. Unset allow-list
# -> 503 CALLERS_UNCONFIGURED and nothing is recorded (fail closed). No test-mode bypass.
REGISTRATION_CALLERS_ENV = "SRE_REGISTRATION_CALLERS"  # comma-separated SA emails (TF I2)
SENTINEL_URL_ENV = "SRE_SENTINEL_URL"                   # optional: this service's URL(s), comma-separated
GOOGLE_ISSUERS: Tuple[str, ...] = ("accounts.google.com", "https://accounts.google.com")
ID_TOKEN_CLOCK_SKEW_SECONDS = 10


def stable_entry_projection(log_payload: Mapping[str, Any]) -> str:
    """Deterministic text of a log entry without its per-occurrence fields (``VOLATILE_LOG_ENTRY_FIELDS``)."""
    stable = {k: v for k, v in log_payload.items() if k not in VOLATILE_LOG_ENTRY_FIELDS}
    return json.dumps(stable, sort_keys=True, default=str)


class FirestoreUnavailable(RuntimeError):
    """Raised when an incident cannot be recorded (Pub/Sub should redeliver)."""


class RegistrationRejected(ValueError):
    """``register_incident`` refused the request (typed ``code``); nothing was recorded."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class CallerRefused(Exception):
    """POST /incidents/register refused the caller (typed ``code``, HTTP ``status``); nothing was recorded."""

    def __init__(self, status: int, code: str, detail: str = ""):
        super().__init__(f"{status} {code}: {detail}")
        self.status = status
        self.code = code
        self.detail = detail


def csv_emails(raw: Optional[str]) -> FrozenSet[str]:
    return frozenset(p.strip().lower() for p in (raw or "").split(",") if p.strip())


def https_origin(value: Any) -> Optional[str]:
    """One bare ``https://`` origin (parsed with ``urllib.parse``; no path, query, fragment or userinfo), without a
    trailing ``/``; None otherwise."""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError:
        return None
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None or parts.password is not None
            or parts.path not in ("", "/") or parts.query or parts.fragment or port == 0):
        return None
    return candidate.rstrip("/")


def verify_google_id_token(token: str, audiences: List[str]) -> Dict[str, Any]:
    """Google-signed OIDC ID token (Cloud Run service-to-service); same verifier as lane 18 vending."""
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token

    return id_token.verify_oauth2_token(token, google_requests.Request(), audience=audiences,
                                        clock_skew_in_seconds=ID_TOKEN_CLOCK_SKEW_SECONDS)


def authenticate_caller(authorization: Optional[str], *, allowed: FrozenSet[str], audiences: List[str],
                        verifier: Callable[[str, List[str]], Dict[str, Any]]) -> str:
    """The verified, allow-listed caller email, or CallerRefused (401/403/503). Exact checks only."""
    if not allowed:
        raise CallerRefused(503, "CALLERS_UNCONFIGURED", f"{REGISTRATION_CALLERS_ENV} is not configured")
    if not audiences:
        raise CallerRefused(503, "AUDIENCE_UNCONFIGURED", "this service's own URL is unresolved")
    parts = (authorization or "").split(" ")
    if len(parts) != 2 or parts[0] != "Bearer" or not parts[1]:
        raise CallerRefused(401, "UNAUTHENTICATED", "a Google-signed Bearer ID token is required")
    try:
        info = verifier(parts[1], audiences)
    except Exception as e:  # noqa: BLE001 - any verification failure is unauthenticated
        raise CallerRefused(401, "UNAUTHENTICATED", f"ID token rejected ({type(e).__name__})") from None
    if not isinstance(info, dict) or info.get("iss") not in GOOGLE_ISSUERS:
        raise CallerRefused(401, "UNAUTHENTICATED", "ID token issuer is not Google")
    if info.get("aud") not in audiences:
        raise CallerRefused(401, "UNAUTHENTICATED", "ID token audience is not this service")
    email = info.get("email")
    if info.get("email_verified") is not True or not isinstance(email, str) or not email:
        raise CallerRefused(403, "CALLER_NOT_ALLOWED", "ID token has no verified email")
    email = email.strip().lower()
    if email not in allowed:
        raise CallerRefused(403, "CALLER_NOT_ALLOWED", f"{email[:100]} is not an allow-listed registration caller")
    return email


def is_sentinel_own_entry(log_payload: Any, host_project_id: str) -> bool:
    """True for a log entry written by this sentinel service in the host project (exact type, service name and
    ``logName`` project; no substring matching). Used by the push endpoint to keep its own failures from re-entering
    the sink as ERROR entries (RT F7)."""
    if not isinstance(log_payload, Mapping) or not host_project_id:
        return False
    resource = log_payload.get("resource") if isinstance(log_payload.get("resource"), Mapping) else {}
    labels = resource.get("labels") if isinstance(resource.get("labels"), Mapping) else {}
    return (resource.get("type") == clf.CLOUD_RUN_REVISION
            and labels.get(clf.RUN_SERVICE_NAME_LABEL) == clf.SENTINEL_SERVICE_NAME
            and clf.entry_project(log_payload) == host_project_id)


def _authorized_session():
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    credentials, _ = google.auth.default(scopes=[CLOUD_PLATFORM_SCOPE])
    return AuthorizedSession(credentials)


def default_host_number_resolver(project_id: str) -> Optional[str]:
    """CRM v3 ``projects.get`` (REST, no gcloud) -> project number, or None."""
    resp = _authorized_session().get(f"https://cloudresourcemanager.googleapis.com/v3/projects/{project_id}", timeout=10)
    resp.raise_for_status()
    return clf.parse_project_number((resp.json() or {}).get("name"))


def default_service_url_resolver(project_id: str, region: str, service_name: str) -> Optional[str]:
    """Run Admin v2 ``services.get`` by exact service name (G14) -> HTTPS uri, or None."""
    resp = _authorized_session().get(
        f"https://run.googleapis.com/v2/projects/{project_id}/locations/{region}/services/{service_name}", timeout=10)
    resp.raise_for_status()
    uri = (resp.json() or {}).get("uri")
    return uri.rstrip("/") if isinstance(uri, str) and uri.startswith("https://") else None


def default_workflow_starter(parent: str, argument_json: str) -> str:
    from google.cloud.workflows import executions_v1

    client = executions_v1.ExecutionsClient()
    execution = executions_v1.Execution(argument=argument_json)
    return client.create_execution(parent=parent, execution=execution).name


def _is_already_exists(exc: Exception) -> bool:
    try:
        from google.api_core.exceptions import AlreadyExists, Conflict

        return isinstance(exc, (AlreadyExists, Conflict))
    except Exception:  # pragma: no cover - api_core always ships with firestore
        return False


def _is_write_conflict(exc: Exception) -> bool:
    """A precondition lost to a concurrent writer (create() of an existing doc, stale last_update_time)."""
    try:
        from google.api_core.exceptions import AlreadyExists, Conflict, FailedPrecondition

        return isinstance(exc, (AlreadyExists, Conflict, FailedPrecondition))
    except Exception:  # pragma: no cover - api_core always ships with firestore
        return False


@dataclass(frozen=True)
class _ClusterRead:
    """Result of reading ``incident_clusters/{fingerprint}`` (see ``LogSRESentinel._read_cluster``)."""
    ref: Any
    exists: bool = False
    duplicate_of: Optional[str] = None
    update_time: Any = None
    previous_incident_id: Optional[str] = None
    created_at: Optional[str] = None


class LogSRESentinel:
    def __init__(
        self,
        project_id: Optional[str] = None,
        firestore_client: Optional[Any] = None,
        *,
        env: Optional[Mapping[str, str]] = None,
        host_number_resolver: Optional[Callable[[str], Optional[str]]] = None,
        service_url_resolver: Optional[Callable[[str, str, str], Optional[str]]] = None,
        workflow_starter: Optional[Callable[[str, str], str]] = None,
        clock: Optional[Callable[[], datetime]] = None,
        id_token_verifier: Optional[Callable[[str, List[str]], Dict[str, Any]]] = None,
    ):
        self._env = env if env is not None else os.environ
        self.project_id = project_id or self._env.get("PROJECT_ID", "")
        if firestore_client is not None:
            self.db = firestore_client
        else:
            try:
                self.db = firestore.Client(project=self.project_id) if self.project_id else None
            except Exception as e:
                logger.warning(f"Could not initialize Firestore client for SRE Sentinel: {e}")
                self.db = None
        self._host_number_resolver = host_number_resolver or default_host_number_resolver
        self._service_url_resolver = service_url_resolver or default_service_url_resolver
        self._workflow_starter = workflow_starter or default_workflow_starter
        self._id_token_verifier = id_token_verifier or verify_google_id_token
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._host_number: Optional[str] = None
        self._host_number_checked_at: Optional[datetime] = None
        self._url_cache: Dict[str, str] = {}

    # ------------------------------------------------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------------------------------------------------
    def _json_name_set(self, key: str, default: FrozenSet[str], warnings: List[str]) -> FrozenSet[str]:
        raw = self._env.get(key)
        if raw is None or raw == "":
            return default
        try:
            value = json.loads(raw)
        except ValueError:
            warnings.append(f"{key}_INVALID_JSON")
            return default
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            warnings.append(f"{key}_NOT_A_LIST_OF_NAMES")
            return default
        return frozenset(value)

    def config(self) -> Dict[str, Any]:
        warnings: List[str] = []
        accepted = self._json_name_set("SRE_INTAKE_ACCEPTED_MODES", frozenset(), warnings)
        unknown_modes = sorted(accepted - ACCEPTED_MODE_VALUES)
        if unknown_modes:
            warnings.append("SRE_INTAKE_ACCEPTED_MODES_UNKNOWN:" + ",".join(unknown_modes))
        region = self._env.get("REGION", "")
        topic = self._env.get("SPEC_INTAKE_TOPIC", "") or (
            f"projects/{self.project_id}/topics/{SPEC_INTAKE_TOPIC_NAME}" if self.project_id else "")

        def _int(key: str, default: int) -> int:
            raw = self._env.get(key, "")
            if raw == "":
                return default
            try:
                parsed = int(raw)
            except ValueError:
                warnings.append(f"{key}_INVALID")
                return default
            if parsed <= 0:
                warnings.append(f"{key}_INVALID")
                return default
            return parsed

        return {
            "region": region,
            "sre_workflow_name": self._env.get("SRE_WORKFLOW_NAME", "") or DEFAULT_SRE_WORKFLOW_NAME,
            "spec_intake_topic": topic,
            "platform_services": self._json_name_set("PLATFORM_SERVICES", clf.DEFAULT_PLATFORM_SERVICES, warnings),
            "platform_jobs": self._json_name_set("PLATFORM_JOBS", clf.DEFAULT_PLATFORM_JOBS, warnings),
            "accepted_modes": accepted & ACCEPTED_MODE_VALUES,
            "dedup_cooldown_seconds": _int("SRE_DEDUP_COOLDOWN_SECONDS", DEFAULT_DEDUP_COOLDOWN_SECONDS),
            "open_request_ttl_seconds": _int("SRE_OPEN_REQUEST_TTL_SECONDS", DEFAULT_OPEN_REQUEST_TTL_SECONDS),
            "warnings": warnings,
        }

    def host_project_number(self) -> Optional[str]:
        """Resolved once (CRM ``projects.get``); a failure is retried at most every HOST_NUMBER_RETRY_SECONDS."""
        if self._host_number:
            return self._host_number
        now = self._clock()
        if self._host_number_checked_at and (now - self._host_number_checked_at).total_seconds() < HOST_NUMBER_RETRY_SECONDS:
            return None
        self._host_number_checked_at = now
        if not self.project_id:
            return None
        try:
            self._host_number = self._host_number_resolver(self.project_id) or None
        except Exception as e:
            logger.warning(f"Host project number unresolved (Workflows entries will be UNATTRIBUTED): {e}")
            self._host_number = None
        return self._host_number

    def health(self) -> Dict[str, Any]:
        cfg = self.config()
        degraded: List[str] = list(cfg["warnings"])
        if self.db is None:
            degraded.append("FIRESTORE_UNAVAILABLE")
        if not self.project_id:
            degraded.append("PROJECT_ID_MISSING")
        if not cfg["region"]:
            degraded.append("REGION_MISSING")
        if self.host_project_number() is None:
            degraded.append(clf.R_HOST_NUMBER_UNRESOLVED)
        return {
            "status": "degraded" if degraded else "healthy",
            "degraded_reasons": degraded,
            "accepted_modes": sorted(cfg["accepted_modes"]),
        }

    # ------------------------------------------------------------------------------------------------------------
    # Fingerprint + de-duplication
    # ------------------------------------------------------------------------------------------------------------
    def compute_stack_fingerprint(self, stack_trace: str, service_name: str) -> str:
        """
        Normalizes a stack trace by stripping volatile line numbers, timestamps,
        and memory addresses to compute a deterministic SHA256 cluster fingerprint.
        (Unchanged by lane 14: existing incident_clusters keep matching.)
        """
        clean = re.sub(r'0x[0-9a-fA-F]+', '0xMEM', stack_trace)
        clean = re.sub(r'line \d+', 'line N', clean)
        clean = re.sub(r':\d+:', ':N:', clean)
        clean = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', 'TIMESTAMP', clean)
        normalized = f"{service_name.strip().lower()}::{clean.strip()}"
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def _parse_ts(self, value: Any) -> Optional[datetime]:
        if not isinstance(value, str) or not value:
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def _read_cluster(self, fingerprint_hash: str, now: datetime, cooldown: int) -> "_ClusterRead":
        """
        One cluster per fingerprint (``incident_clusters/{fingerprint}``). A recurrence is a DUPLICATE of the active
        incident while the cluster is open and was last seen within the cooldown (default 1 h, sliding: a storm stays
        one incident). A new incident opens when no cluster exists, the cluster is CLOSED/RESOLVED, or the error was
        quiet for longer than the cooldown.

        Read only. The cluster is written together with the new incident in ONE atomic batch (``_commit_incident``):
        a failed incident write leaves no cluster behind (RT F1), and the batch carries a precondition (``create()``
        for a first sighting, ``last_update_time`` of this read for a reopen), so concurrent deliveries open exactly
        one incident (RT F2).
        """
        ref = self.db.collection("incident_clusters").document(fingerprint_hash)
        try:
            snap = ref.get()
        except Exception as e:
            raise FirestoreUnavailable(f"incident_clusters/{fingerprint_hash[:8]}: {e}") from e
        if not snap.exists:
            return _ClusterRead(ref=ref)
        data = snap.to_dict() or {}
        incident_id = data.get("active_incident_id")
        last_seen = self._parse_ts(data.get("last_seen_at"))
        is_open = data.get("status") not in CLOSED_CLUSTER_STATUSES
        within = last_seen is not None and (now - last_seen).total_seconds() <= cooldown
        if is_open and within and incident_id:
            return _ClusterRead(ref=ref, exists=True, duplicate_of=incident_id)
        return _ClusterRead(ref=ref, exists=True, update_time=getattr(snap, "update_time", None),
                            previous_incident_id=incident_id, created_at=data.get("created_at"))

    def _count_duplicate(self, cluster: "_ClusterRead", fingerprint_hash: str, now_iso: str) -> None:
        try:
            cluster.ref.update({"occurrence_count": firestore.Increment(1), "last_seen_at": now_iso})
        except Exception as e:
            raise FirestoreUnavailable(f"incident_clusters/{fingerprint_hash[:8]}: {e}") from e
        logger.info(f"Duplicate error clustered for fingerprint {fingerprint_hash[:8]} (Incident: {cluster.duplicate_of})")

    @staticmethod
    def _cluster_doc(cluster: "_ClusterRead", fingerprint_hash: str, incident_id: str, now_iso: str) -> Dict[str, Any]:
        doc: Dict[str, Any] = {
            "fingerprint_hash": fingerprint_hash,
            "active_incident_id": incident_id,
            "created_at": now_iso,
            "last_seen_at": now_iso,
            "occurrence_count": 1,
            "status": "TRIAGING",
        }
        if cluster.exists:  # reopen after CLOSED/RESOLVED or a quiet period
            doc.update({"previous_incident_id": cluster.previous_incident_id,
                        "created_at": cluster.created_at or now_iso, "reopened_at": now_iso})
        return doc

    def _commit_incident(self, cluster: "_ClusterRead", cluster_doc: Dict[str, Any], incident_id: str,
                         record: Dict[str, Any]) -> None:
        """Cluster + incident in one atomic WriteBatch with a precondition on the cluster (RT F1 + F2). A lost race
        raises AlreadyExists / FailedPrecondition; any failure leaves neither document written."""
        batch = self.db.batch()
        if cluster.exists:
            option = (self.db.write_option(last_update_time=cluster.update_time)
                      if cluster.update_time is not None else None)
            batch.update(cluster.ref, cluster_doc, option=option)
        else:
            batch.create(cluster.ref, cluster_doc)
        batch.set(self.db.collection("incidents").document(incident_id), record)
        batch.commit()

    # ------------------------------------------------------------------------------------------------------------
    # RCA (deterministic)
    # ------------------------------------------------------------------------------------------------------------
    def perform_rca(
        self,
        stack_trace: str,
        error_msg: str,
        service_name: str,
        log_severity: Optional[str] = None,
        affected_repository: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Deterministic RCA from the stack trace. The affected repository comes from an exact component -> source-dir
        table for platform components, or from the workload's ledger ``github_repo`` for tenant incidents; unknown ->
        "" (no guess). Severity comes from the log entry's own ``severity`` field.
        """
        repo_path = affected_repository if affected_repository is not None else clf.PLATFORM_SOURCE_DIRS.get(service_name, "")

        file_matches = re.findall(r'File "([^"]+)", line \d+', stack_trace)
        failing_file = file_matches[-1] if file_matches else ""
        clean_file = failing_file.split("/")[-1] if failing_file else ""

        exc_match = re.search(r'([A-Za-z]+Error|Exception|KeyError|ValueError|HTTPException): (.+)', stack_trace)
        exception_type = exc_match.group(1) if exc_match else "RuntimeError"
        exception_detail = exc_match.group(2) if exc_match else error_msg

        location = clean_file or service_name or "unknown component"
        root_cause = f"Unhandled {exception_type} in {location}: {exception_detail}"
        severity = "CRITICAL" if (log_severity or "").upper() in {"CRITICAL", "ALERT", "EMERGENCY"} else "HIGH"

        return {
            "service_name": service_name,
            "affected_repository": repo_path,
            "failing_file": failing_file,
            "exception_type": exception_type,
            "root_cause_summary": root_cause,
            "severity": severity,
            "recommended_action": f"Patch {location} to handle {exception_type} gracefully and add pytest regression test.",
        }

    # ------------------------------------------------------------------------------------------------------------
    # Dispatch rules
    # ------------------------------------------------------------------------------------------------------------
    def _link_pipeline(self, execution_id: str) -> Dict[str, Any]:
        if not execution_id:
            return {"link_status": "EXECUTION_ID_MISSING"}
        try:
            docs = list(self.db.collection("pipeline_executions")
                        .where("workflow_execution_id", "==", execution_id).limit(2).stream())
        except Exception as e:
            logger.warning(f"pipeline_executions lookup failed for execution {execution_id}: {e}")
            return {"link_status": "LOOKUP_FAILED"}
        if len(docs) == 1:
            data = docs[0].to_dict() or {}
            return {"link_status": "LINKED", "linked_pipeline_trace_id": data.get("trace_id") or docs[0].id,
                    "linked_product_id": data.get("product_id", "")}
        return {"link_status": "PIPELINE_NOT_FOUND" if not docs else "PIPELINE_AMBIGUOUS"}

    def _job_run_outcome(self, job_name: str, execution_name: str) -> Optional[str]:
        """Outcome of the job's run record ``<job>_runs/{execution_name}`` ("" when there is none); None when it
        cannot be read (the caller fails closed: such an incident is never dispatched)."""
        if not job_name or not execution_name:
            return None
        try:
            snap = self.db.collection(clf.run_record_collection(job_name)).document(execution_name).get()
        except Exception as e:
            logger.warning(f"Run record lookup failed for {job_name}/{execution_name}: {e}")
            return None
        if not snap.exists:
            return ""
        outcome = (snap.to_dict() or {}).get("outcome")
        return outcome if isinstance(outcome, str) else ""

    def resolve_product_for_project(self, project_id: str) -> Tuple[str, str]:
        """
        Exact reverse ledger lookup: ``workloads where project_id == X``; exactly one non-platform match -> its
        product id. Zero or several -> unresolved (recorded UNATTRIBUTED). Read-only.
        Follow-up (plan PR-M): replace with ``shared/managed_target.resolve_product_for_project`` (adds the
        provenance, CRM, tag and ancestry checks) once that module lands and is vendored to this service.
        """
        try:
            docs = list(self.db.collection("workloads").where("project_id", "==", project_id).limit(2).stream())
        except Exception as e:
            logger.warning(f"Ledger reverse lookup failed for {project_id}: {e}")
            return "", "LEDGER_UNAVAILABLE"
        if not docs:
            return "", "PRODUCT_NOT_IN_LEDGER"
        if len(docs) > 1:
            return "", "PRODUCT_AMBIGUOUS"
        data = docs[0].to_dict() or {}
        if data.get("is_castor") is True:
            return "", "PLATFORM_WORKLOAD"
        return docs[0].id, ""

    def _governance_gate(self, product_id: str) -> str:
        """Returns "" when dispatch is allowed, else the SUPPRESSED reason."""
        try:
            kill = self.db.collection("governance").document("platform_kill_switch").get()
            if kill.exists and (kill.to_dict() or {}).get("emergency_stop_active") is True:
                return "KILL_SWITCH"
            snap = self.db.collection("workloads").document(product_id).get()
        except Exception as e:
            logger.warning(f"Governance read failed for {product_id}: {e}")
            return "GOVERNANCE_UNAVAILABLE"
        if not snap.exists:
            return "LEDGER_MISSING"
        data = snap.to_dict() or {}
        if data.get("code_freeze") is True:
            return "CODE_FREEZE"
        if data.get("sre_auto_healing_enabled", SRE_AUTO_HEALING_DEFAULT_WHEN_ABSENT) is not True:
            return "AUTO_HEALING_DISABLED"
        if data.get("status") != "ACTIVE":
            return "WORKLOAD_NOT_ACTIVE"
        return ""

    def decide_dispatch(self, c: clf.Classification, cfg: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
        """Class-level rules first (record-only), then contract, then governance gates. Pure apart from reads."""
        if c.incident_class == clf.UNATTRIBUTED:
            return {"dispatch": False, "status": "RECORD_ONLY:UNATTRIBUTED"}
        if c.incident_class == clf.PLATFORM_INCIDENT:
            if c.kind == clf.KIND_SRE_WORKFLOW:
                return {"dispatch": False, "status": "RECORD_ONLY:SELF_LOOP"}
            if c.kind == clf.KIND_PIPELINE:
                return {"dispatch": False, "status": "RECORD_ONLY:PIPELINE_LINKED"}
            if c.kind == clf.KIND_SERVICE and c.component == SENTINEL_SERVICE:
                return {"dispatch": False, "status": "RECORD_ONLY:SELF_LOOP"}
            if c.kind == clf.KIND_JOB and extra.get("error_class") == "NOT_CONFIGURED":
                return {"dispatch": False, "status": "RECORD_ONLY:NOT_CONFIGURED"}
            if c.kind == clf.KIND_JOB and extra.get("run_record_status") == "UNAVAILABLE":
                return {"dispatch": False, "status": "RECORD_ONLY:RUN_RECORD_UNAVAILABLE"}
            return {"dispatch": False, "status": "RECORD_ONLY:CONSUMER_MODE"}
        elif c.incident_class == clf.WORKLOAD_INCIDENT:
            if EXECUTION_MODE_FULL_BUILD not in cfg["accepted_modes"]:
                return {"dispatch": False, "status": "SUPPRESSED:INTAKE_CONTRACT_PENDING"}
            mode, product_id = EXECUTION_MODE_FULL_BUILD, c.product_id
        else:  # pragma: no cover - classifier only emits the three classes
            return {"dispatch": False, "status": "RECORD_ONLY:UNATTRIBUTED"}

        gate = self._governance_gate(product_id)
        if gate:
            return {"dispatch": False, "status": f"SUPPRESSED:{gate}"}
        if not cfg["region"] or not self.project_id or not cfg["spec_intake_topic"]:
            return {"dispatch": False, "status": "SUPPRESSED:NOT_CONFIGURED"}
        return {"dispatch": True, "status": "DISPATCH_PENDING", "execution_mode": mode, "dispatch_product_id": product_id}

    def resolve_service_url(self, service_name: str, region: str) -> Optional[str]:
        if service_name in self._url_cache:
            return self._url_cache[service_name]
        try:
            url = self._service_url_resolver(self.project_id, region, service_name)
        except Exception as e:
            logger.warning(f"Could not resolve Cloud Run URL for {service_name}: {e}")
            return None
        if url:
            self._url_cache[service_name] = url
        return url or None

    def build_remediation_args(self, *, incident_id: str, trace_id: str, execution_mode: str,
                               sre_sentinel_url: str, workspace_mcp_url: str, spec_intake_topic: str) -> Dict[str, str]:
        args = {
            "trace_id": trace_id,
            "incident_id": incident_id,
            "sre_sentinel_url": sre_sentinel_url,
            "workspace_mcp_url": workspace_mcp_url,
            "spec_intake_topic": spec_intake_topic,
            "execution_mode": execution_mode,
        }
        assert tuple(args) == REMEDIATION_ARG_KEYS
        return args

    def _acquire_open_request(self, product_id: str, incident_id: str, ttl_seconds: int) -> bool:
        """One open remediation request per product (``sre_open_requests/{product_id}``), expiring after the TTL."""
        now = self._clock()
        ref = self.db.collection("sre_open_requests").document(product_id)
        lock = {"product_id": product_id, "incident_id": incident_id, "opened_at": now.isoformat(),
                "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat()}
        try:
            ref.create(lock)
            return True
        except Exception as e:
            if not _is_already_exists(e):
                logger.warning(f"Open-request lock failed for {product_id}: {e}")
                return False
        snap = ref.get()
        expires = self._parse_ts((snap.to_dict() or {}).get("expires_at")) if snap.exists else None
        if expires is not None and now > expires:
            ref.set(lock)
            return True
        return False

    def _release_open_request(self, product_id: str, incident_id: str) -> None:
        try:
            ref = self.db.collection("sre_open_requests").document(product_id)
            snap = ref.get()
            if snap.exists and (snap.to_dict() or {}).get("incident_id") == incident_id:
                ref.delete()
        except Exception as e:
            logger.warning(f"Could not release open-request lock for {product_id}: {e}")

    # ------------------------------------------------------------------------------------------------------------
    # Event processing
    # ------------------------------------------------------------------------------------------------------------
    def _fingerprint_scope(self, c: clf.Classification, legacy_service_name: str) -> str:
        if c.incident_class == clf.PLATFORM_INCIDENT and c.kind == clf.KIND_SERVICE:
            return c.component  # identical to the pre-PR-2 key (resource.labels.service_name): clusters keep matching
        if c.incident_class == clf.PLATFORM_INCIDENT and c.kind in (clf.KIND_PIPELINE, clf.KIND_SRE_WORKFLOW):
            return f"workflow/{c.workflow_id}/{c.execution_id}"
        if c.incident_class == clf.PLATFORM_INCIDENT and c.kind == clf.KIND_JOB:
            return f"job/{c.job_name}"
        if c.incident_class == clf.WORKLOAD_INCIDENT:
            return f"product/{c.product_id}/{c.component or c.resource_type}"
        return legacy_service_name

    def _prepare_incident(self, c: clf.Classification, cfg: Dict[str, Any], log_payload: Dict[str, Any],
                          stack_trace: str, error_msg: str, legacy_service_name: str,
                          rca_override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Class evidence, deterministic RCA and the dispatch decision (without the open-request lock) for a new
        incident. Reads only; computed once per delivery even when the cluster write is retried.
        ``rca_override`` (registered incidents, ``register_incident``) replaces the stack-trace RCA."""
        extra: Dict[str, Any] = {}
        if c.incident_class == clf.PLATFORM_INCIDENT and c.kind == clf.KIND_PIPELINE:
            extra.update(self._link_pipeline(c.execution_id))
        if c.incident_class == clf.PLATFORM_INCIDENT and c.kind == clf.KIND_JOB:
            run_outcome = self._job_run_outcome(c.job_name, c.execution_name)
            if run_outcome is None:
                extra["run_record_status"] = "UNAVAILABLE"
            elif run_outcome == "NOT_CONFIGURED":
                extra["error_class"] = "NOT_CONFIGURED"

        affected_repository: Optional[str] = None
        if c.incident_class == clf.WORKLOAD_INCIDENT:
            affected_repository = self._workload_repo(c.product_id)
        display_name = c.component or legacy_service_name
        if rca_override is not None:
            rca = dict(rca_override)
            rca["affected_repository"] = affected_repository if affected_repository is not None else ""
        else:
            rca = self.perform_rca(stack_trace, error_msg, display_name, log_payload.get("severity"),
                                   affected_repository)
        rca["product_id"] = c.product_id if c.incident_class == clf.WORKLOAD_INCIDENT else ""

        # Dispatch decision (before recording, so the record carries the reason)
        decision = self.decide_dispatch(c, cfg, extra)
        urls: Dict[str, str] = {}
        if decision["dispatch"]:
            for key, svc in (("sre_sentinel_url", SENTINEL_SERVICE), ("workspace_mcp_url", WORKSPACE_SERVICE)):
                url = self.resolve_service_url(svc, cfg["region"])
                if not url:
                    decision = {"dispatch": False, "status": "SUPPRESSED:URL_UNRESOLVED", "unresolved_service": svc}
                    break
                urls[key] = url
        return {"extra": extra, "rca": rca, "display_name": display_name, "decision": decision, "urls": urls,
                "trace_id": f"sre-{uuid.uuid4().hex[:8]}"}

    def process_log_event(self, log_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Classify, de-duplicate, RECORD, then dispatch per the rules. Raises FirestoreUnavailable when the incident
        cannot be recorded (the push endpoint answers 503 so Pub/Sub redelivers)."""
        if not self.db:
            raise FirestoreUnavailable("incidents")
        cfg = self.config()
        resource = log_payload.get("resource") if isinstance(log_payload.get("resource"), dict) else {}
        rlabels = resource.get("labels") if isinstance(resource.get("labels"), dict) else {}
        legacy_service_name = rlabels.get("service_name") or log_payload.get("service_name") or "unknown-service"
        if not isinstance(legacy_service_name, str):
            legacy_service_name = "unknown-service"

        host = clf.HostIdentity(
            project_id=self.project_id,
            project_number=self.host_project_number(),
            sre_workflow_name=cfg["sre_workflow_name"],
            platform_services=cfg["platform_services"],
            platform_jobs=cfg["platform_jobs"],
        )
        c = clf.classify_entry(log_payload, host, self.resolve_product_for_project)

        text_payload = log_payload.get("textPayload", "")
        json_payload = log_payload.get("jsonPayload", {}) if isinstance(log_payload.get("jsonPayload"), dict) else {}
        primary_trace = json_payload.get("stack_trace") or json_payload.get("message") or text_payload
        stack_trace = primary_trace or str(log_payload)
        error_msg = json_payload.get("error") or text_payload or "Unhandled service error"
        if not isinstance(stack_trace, str):
            stack_trace = json.dumps(stack_trace, sort_keys=True, default=str)
        if not isinstance(error_msg, str):
            error_msg = json.dumps(error_msg, sort_keys=True, default=str)
        # Entries without stack_trace/message/textPayload fingerprint a stable projection of the entry (RT F4);
        # every other entry fingerprints exactly as before (existing clusters keep matching).
        fingerprint_text = stack_trace if primary_trace else stable_entry_projection(log_payload)
        fingerprint = self.compute_stack_fingerprint(fingerprint_text, self._fingerprint_scope(c, legacy_service_name))
        return self._record_and_dispatch(c, cfg, log_payload, stack_trace, error_msg, legacy_service_name, fingerprint)

    def _record_and_dispatch(self, c: clf.Classification, cfg: Dict[str, Any], log_payload: Dict[str, Any],
                             stack_trace: str, error_msg: str, legacy_service_name: str, fingerprint: str, *,
                             rca_override: Optional[Dict[str, Any]] = None,
                             extra_record: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """De-duplicate, RECORD, then dispatch per the rules (shared by log-sink entries and ``register_incident``).
        ``log_payload`` supplies only ``severity`` / ``logName`` for the record (a registration passes its own
        severity and no ``logName``). Raises FirestoreUnavailable when the incident cannot be recorded."""
        # 1. De-duplicate. The cluster is written only together with the incident (one atomic batch with a
        #    precondition): a failed write leaves nothing behind and a lost race re-reads once (RT F1/F2).
        now = self._clock()
        now_iso = now.isoformat()
        incident_id = f"inc-{uuid.uuid4().hex[:8]}"
        prepared: Optional[Dict[str, Any]] = None
        for attempt in (1, 2):
            cluster = self._read_cluster(fingerprint, now, cfg["dedup_cooldown_seconds"])
            if cluster.duplicate_of:
                self._count_duplicate(cluster, fingerprint, now_iso)
                return {
                    "status": "DUPLICATE_CLUSTERED",
                    "incident_id": cluster.duplicate_of,
                    "fingerprint_hash": fingerprint,
                    "classification": c.to_dict(),
                    "message": f"Log clustered with active incident {cluster.duplicate_of}.",
                }
            if prepared is None:
                prepared = self._prepare_incident(c, cfg, log_payload, stack_trace, error_msg, legacy_service_name,
                                                  rca_override=rca_override)
            decision, urls = dict(prepared["decision"]), prepared["urls"]
            locked = False
            if decision["dispatch"]:
                locked = self._acquire_open_request(
                    decision["dispatch_product_id"], incident_id, cfg["open_request_ttl_seconds"])
                if not locked:
                    decision = {"dispatch": False, "status": "SUPPRESSED:REQUEST_OPEN"}

            incident_record = {
                "incident_id": incident_id,
                "trace_id": prepared["trace_id"],
                "service_name": prepared["display_name"],
                "product_id": prepared["rca"]["product_id"],
                "fingerprint_hash": fingerprint,
                "created_at": now_iso,
                "status": "OPEN",
                "auto_remediation_status": decision["status"],
                "classification": c.to_dict(),
                "log_severity": log_payload.get("severity"),
                "log_name": log_payload.get("logName"),
                "stack_trace": stack_trace,
                "error_message": error_msg,
                "rca": prepared["rca"],
                **prepared["extra"],
                **(extra_record or {}),
            }
            if decision.get("execution_mode"):
                incident_record["execution_mode"] = decision["execution_mode"]
                incident_record["require_plan_approval"] = True

            # 2. Record (every incident, both installs): cluster + incident, atomically
            try:
                self._commit_incident(cluster, self._cluster_doc(cluster, fingerprint, incident_id, now_iso),
                                      incident_id, incident_record)
            except Exception as e:
                if locked:
                    self._release_open_request(decision["dispatch_product_id"], incident_id)
                if attempt == 1 and _is_write_conflict(e):
                    continue  # a concurrent delivery wrote the cluster first: re-read it once
                raise FirestoreUnavailable(f"incidents/{incident_id}: {e}") from e
            break
        else:  # pragma: no cover - the loop always returns, breaks or raises
            raise FirestoreUnavailable("incident_clusters")
        trace_id, rca = prepared["trace_id"], prepared["rca"]
        logger.info(f"Recorded incident {incident_id} ({c.incident_class}/{c.kind or c.reason}): {decision['status']}")

        # 3. Dispatch castor-sre-remediation
        workflow_execution = ""
        if decision["dispatch"]:
            args = self.build_remediation_args(
                incident_id=incident_id, trace_id=trace_id, execution_mode=decision["execution_mode"],
                sre_sentinel_url=urls["sre_sentinel_url"], workspace_mcp_url=urls["workspace_mcp_url"],
                spec_intake_topic=cfg["spec_intake_topic"])
            parent = f"projects/{self.project_id}/locations/{cfg['region']}/workflows/{cfg['sre_workflow_name']}"
            try:
                workflow_execution = self._workflow_starter(parent, json.dumps(args))
                final_status = "DISPATCHED"
                logger.info(f"Triggered SRE Remediation workflow: {workflow_execution}")
            except Exception as wkf_err:
                final_status = "DISPATCH_FAILED"
                self._release_open_request(decision["dispatch_product_id"], incident_id)
                logger.warning(f"SRE remediation workflow start failed for {incident_id}: {wkf_err}")
            try:
                self.db.collection("incidents").document(incident_id).update({
                    "auto_remediation_status": final_status,
                    "remediation_workflow_execution": workflow_execution,
                })
            except Exception as e:
                logger.warning(f"Could not update dispatch status of {incident_id}: {e}")
            incident_record["auto_remediation_status"] = final_status

        dispatched = incident_record["auto_remediation_status"] == "DISPATCHED"
        return {
            "status": "INCIDENT_DISPATCHED" if dispatched else "INCIDENT_RECORDED",
            "incident_id": incident_id,
            "trace_id": trace_id,
            "fingerprint_hash": fingerprint,
            "classification": c.to_dict(),
            "auto_remediation_status": incident_record["auto_remediation_status"],
            "rca": rca,
            "workflow_triggered": dispatched,
            "workflow_execution": workflow_execution,
            "auto_remediation_allowed": dispatched,
        }

    # ------------------------------------------------------------------------------------------------------------
    # Registered incidents (plan 2.5 item 6: the sre-telemetry-digest-job hook, lane 14 PR-3)
    # ------------------------------------------------------------------------------------------------------------
    def registration_audiences(self) -> List[str]:
        """This service's own URL(s): ``SRE_SENTINEL_URL`` entries (bare https origins) and the Run Admin
        ``services.get`` ``uri`` of ``log-sre-sentinel-service`` (the URL the digest resolves and mints its token
        for). Empty when neither is available."""
        out: List[str] = []
        for raw in (self._env.get(SENTINEL_URL_ENV) or "").split(","):
            origin = https_origin(raw) if raw.strip() else None
            if origin and origin not in out:
                out.append(origin)
        region = self._env.get("REGION", "")
        if region and self.project_id:
            uri = https_origin(self.resolve_service_url(SENTINEL_SERVICE, region) or "")
            if uri and uri not in out:
                out.append(uri)
        return out

    def authenticate_registration(self, authorization: Optional[str]) -> str:
        """Caller identity for POST /incidents/register (RT F3-1). Returns the caller email or raises CallerRefused.
        The allow-list is checked before the audience is resolved (no lookup for an unconfigured install)."""
        allowed = csv_emails(self._env.get(REGISTRATION_CALLERS_ENV))
        if not allowed:
            raise CallerRefused(503, "CALLERS_UNCONFIGURED", f"{REGISTRATION_CALLERS_ENV} is not configured")
        return authenticate_caller(authorization, allowed=allowed, audiences=self.registration_audiences(),
                                   verifier=self._id_token_verifier)

    def register_incident(self, product_id: Any, fingerprint: Any, evidence: Any, source: Any, *,
                          registered_by: str = "") -> Dict[str, Any]:
        """
        Record a finding from a registered StackVend source (exact allow-set ``REGISTRATION_SOURCES``) as a
        WORKLOAD_INCIDENT for ``product_id``, through the same de-duplication, record and dispatch rules as a log
        entry (the sentinel's gates decide dispatch; nothing here bypasses them).

        The product must be in the ledger, not the platform pseudo-workload, and its ``project_id`` must reverse-map
        to exactly this product (exact lookups only). Raises RegistrationRejected (typed code) or FirestoreUnavailable.
        Follow-up (plan PR-M): ``shared/managed_target.verify_managed_target`` replaces the ledger-only check.
        """
        if not self.db:
            raise FirestoreUnavailable("incidents")
        if not isinstance(source, str) or source not in REGISTRATION_SOURCES:
            raise RegistrationRejected("UNKNOWN_SOURCE", str(source)[:100])
        for name, value in (("product_id", product_id), ("fingerprint", fingerprint)):
            if not isinstance(value, str) or not value or len(value) > REGISTRATION_MAX_ID_LENGTH:
                raise RegistrationRejected("INVALID_REQUEST", f"{name} must be a non-empty string "
                                           f"of at most {REGISTRATION_MAX_ID_LENGTH} characters")
        if not isinstance(evidence, Mapping):
            raise RegistrationRejected("INVALID_REQUEST", "evidence must be an object")
        evidence_text = json.dumps(evidence, sort_keys=True, default=str)
        if len(evidence_text) > REGISTRATION_MAX_EVIDENCE_BYTES:
            raise RegistrationRejected("INVALID_REQUEST", f"evidence exceeds {REGISTRATION_MAX_EVIDENCE_BYTES} bytes")

        try:
            snap = self.db.collection("workloads").document(product_id).get()
        except Exception as e:
            raise FirestoreUnavailable(f"workloads/{product_id}: {e}") from e
        if not snap.exists:
            raise RegistrationRejected("PRODUCT_NOT_IN_LEDGER", product_id)
        data = snap.to_dict() or {}
        if data.get("is_castor") is True:
            raise RegistrationRejected("PLATFORM_WORKLOAD", product_id)
        project_id = data.get("project_id")
        if not isinstance(project_id, str) or not project_id:
            raise RegistrationRejected("LEDGER_PROJECT_MISSING", product_id)
        if project_id == self.project_id:
            raise RegistrationRejected("HOST_PROJECT", product_id)
        resolved, reason = self.resolve_product_for_project(project_id)
        if reason == "LEDGER_UNAVAILABLE":
            raise FirestoreUnavailable(f"workloads where project_id == {project_id}")
        if resolved != product_id:
            raise RegistrationRejected(reason or "LEDGER_MISMATCH", product_id)

        component = evidence.get("service_name") if isinstance(evidence.get("service_name"), str) else ""
        summary = evidence.get("summary") if isinstance(evidence.get("summary"), str) and evidence.get("summary") \
            else f"{source} finding {fingerprint}"
        severity = evidence.get("severity") if evidence.get("severity") in REGISTRATION_SEVERITIES else "WARNING"
        c = clf.Classification(
            incident_class=clf.WORKLOAD_INCIDENT, kind=clf.KIND_WORKLOAD, resource_type=REGISTERED_RESOURCE_TYPE,
            entry_project=project_id, product_id=product_id, component=component,
            detail={"source": source, "fingerprint": fingerprint})
        rca = {
            "service_name": component or source,
            "failing_file": "",
            "exception_type": str(evidence.get("finding_type") or "RegisteredFinding"),
            "root_cause_summary": summary,
            "severity": "HIGH",
            "recommended_action": str(evidence.get("recommendation") or f"Investigate the {source} finding."),
        }
        incident_fingerprint = hashlib.sha256(f"{source}::{product_id}::{fingerprint}".encode("utf-8")).hexdigest()
        return self._record_and_dispatch(
            c, self.config(), {"severity": severity}, evidence_text, summary, component or source,
            incident_fingerprint, rca_override=rca,
            extra_record={"source": source, "registered_fingerprint": fingerprint, "evidence": dict(evidence),
                          **({"registered_by": registered_by} if registered_by else {})})

    def _workload_repo(self, product_id: str) -> str:
        try:
            snap = self.db.collection("workloads").document(product_id).get()
        except Exception:
            return ""
        repo = (snap.to_dict() or {}).get("github_repo") if snap.exists else ""
        return repo if isinstance(repo, str) else ""

    # ------------------------------------------------------------------------------------------------------------
    # Workflow callbacks
    # ------------------------------------------------------------------------------------------------------------
    @staticmethod
    def build_spec_text(record: Dict[str, Any]) -> str:
        rca = record.get("rca") or {}
        trace = str(record.get("stack_trace") or "")[:SPEC_TEXT_TRACE_LIMIT]
        lines = [
            f"SRE incident {record.get('incident_id', '')} (trace {record.get('trace_id', '')})",
            f"Product: {record.get('product_id', '')}",
            f"Component: {record.get('service_name', '')}",
            f"Severity: {rca.get('severity', '')}",
            f"Root cause summary: {rca.get('root_cause_summary', '')}",
            f"Recommended action: {rca.get('recommended_action', '')}",
            "Stack trace:",
            trace,
        ]
        return "\n".join(lines)

    def triage_incident(self, incident_data: Dict[str, Any], trace_id: str, incident_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Step 1 of sre_remediation.yaml. With ``incident_id`` (PR-2 contract) the recorded incident is loaded and its
        product id, RCA and a deterministic ``spec_text`` are returned; KeyError when it does not exist. Without it
        the legacy ``incident_data`` body is analysed as before (no product id).
        """
        if incident_id:
            if not self.db:
                raise FirestoreUnavailable("incidents")
            snap = self.db.collection("incidents").document(incident_id).get()
            if not snap.exists:
                raise KeyError(incident_id)
            record = snap.to_dict() or {}
            rca = record.get("rca") or {}
            return {
                "status": "TRIAGED",
                "trace_id": record.get("trace_id") or trace_id,
                "incident_id": incident_id,
                "product_id": record.get("product_id", ""),
                "service_name": record.get("service_name", ""),
                "severity": rca.get("severity", "HIGH"),
                "affected_repository": rca.get("affected_repository", ""),
                "root_cause_summary": rca.get("root_cause_summary", ""),
                "stack_trace": record.get("stack_trace", ""),
                "recommended_action": rca.get("recommended_action", ""),
                "spec_text": self.build_spec_text(record),
            }

        service_name = incident_data.get("service_name", "unknown")
        stack_trace = incident_data.get("stack_trace", "")
        error_msg = incident_data.get("error_message", "Runtime Error")
        rca = self.perform_rca(stack_trace, error_msg, service_name)

        return {
            "status": "TRIAGED",
            "trace_id": trace_id,
            "incident_id": incident_data.get("incident_id", f"inc-{trace_id[:6]}"),
            "product_id": "",
            "service_name": service_name,
            "severity": rca["severity"],
            "affected_repository": rca["affected_repository"],
            "root_cause_summary": rca["root_cause_summary"],
            "stack_trace": stack_trace,
            "recommended_action": rca["recommended_action"],
        }

    def record_outcome(self, incident_id: str, outcome: str, error_class: str = "", detail: str = "") -> Dict[str, Any]:
        """Remediation workflow outcome (POST /incidents/{id}/outcome). ValueError on an unknown outcome, KeyError
        when the incident does not exist. A REMEDIATION_FAILED outcome releases the product's open-request lock."""
        if outcome not in REMEDIATION_OUTCOMES:
            raise ValueError(outcome)
        if not self.db:
            raise FirestoreUnavailable("incidents")
        ref = self.db.collection("incidents").document(incident_id)
        snap = ref.get()
        if not snap.exists:
            raise KeyError(incident_id)
        record = snap.to_dict() or {}
        ref.update({
            "remediation_outcome": outcome,
            "remediation_error_class": error_class,
            "remediation_outcome_detail": detail[:2000],
            "remediation_outcome_at": self._clock().isoformat(),
        })
        if outcome == OUTCOME_REMEDIATION_FAILED:
            lock_product = record.get("product_id", "")
            if lock_product:
                self._release_open_request(lock_product, incident_id)
        return {"status": "OUTCOME_RECORDED", "incident_id": incident_id, "outcome": outcome}
