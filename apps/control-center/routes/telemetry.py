"""
Project Castor: Telemetry, Observability & Topology Visualizer
Provides live pipeline execution metrics, Cloud Logging streaming, and Mermaid.js architecture diagrams.
"""

from datetime import datetime, timezone
import json
import logging
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Request
from authz import ADMIN, PLATFORM_PSEUDO_WORKLOADS, SCOPED, TRACE, WORKLOAD, WORKLOAD_BY_PROJECT, require, workload_scope

from auth import verify_admin_access, verify_workload_access
from config import PROJECT_ID, DynamicHTTPException as HTTPException, get_caller_main_module
from db import db, get_cloud_logging
import workflow_executions as wfx
import build_queue  # BUILD-ADMISSION-QUEUE (G4)
from shared import build_admission as _build_admission
from shared import callbacks as _callbacks  # RT14-25: redelivery of an outcome a running workflow never received
from diagram import ArchitectureDiagramEngine
from schemas import (
    AAROutcomeType,
    AARResponse,
    ActiveExecutionsResponse,
    AfterActionReport,
    AgentStatusSummary,
    AgentTaskRecord,
    AgentTaskStatus,
    ArchitectureDiagramResponse,
    BlastRadius,
    FeatureRequestPriority,
    FlightDeckResponse,
    LogEntryRecord,
    PipelineExecutionItem,
    PipelineOverviewResponse,
    RemediationPlan,
    RootCauseAnalysis,
    SelfHealingIntervention,
    StageExecutionDetail,
    TaskSourceType,
    ToolServerSummary,
    UserRole,
    WorkloadExecutionRun,
    WorkloadLogsResponse,
)

try:
    from google.cloud import firestore
except ImportError:
    firestore = None

logger = logging.getLogger("control-center-telemetry")

router = APIRouter(tags=["Telemetry"])
diagram_engine = ArchitectureDiagramEngine()

# In-memory rate-limit cache for GCP Cloud Workflows API checks: trace_id -> last_checked_epoch
_wf_check_cache: Dict[str, float] = {}
# SAT-43: phantom runs (parent workload gone) whose workflow execution could not be cancelled: trace_id -> epoch of
# the last failed cancel. The poll retries at most once per _PHANTOM_CANCEL_RETRY_SECONDS per run (no call / log storm).
_phantom_cancel_cache: Dict[str, float] = {}
_PHANTOM_CANCEL_RETRY_SECONDS = 60

# STALE-RUN-AUTOFAIL-BOUND: how the active-runs poll decides that a run has ended.
# - A run bound to a workflow execution (workflow_execution_name / _id, written by the gateway at dispatch) is never
#   failed for silence: developer and QA may each run 30 min without any event. Its state comes from the Workflows API
#   (at most once per _WF_STATE_CHECK_INTERVAL_SECONDS per run, once the run has been quiet for
#   _WF_STATE_CHECK_AFTER_SECONDS) and the record is reconciled only on a terminal state. A failed read leaves the
#   run as it is (fail-loudly policy §2: nothing is reported as ended; the failure is recorded as `workflow_state_check`
#   on the record, and Abort still cancels by trace id).
# - A run with no bound execution (the M52 case: a record no workflow owns) is failed after
#   _UNBOUND_SILENCE_LIMIT_SECONDS of silence, unless its current_stage is one of the exact stages below.
_WF_STATE_CHECK_AFTER_SECONDS = 300
_WF_STATE_CHECK_INTERVAL_SECONDS = 60
_UNBOUND_SILENCE_LIMIT_SECONDS = 1800
# The exact current_stage values written while a run legitimately waits on a person or a callback
# (workflows/main_orchestrator.yaml notify_* steps; passed through verbatim by the gateway's /events/workflow-status).
_SILENCE_EXEMPT_STAGES = frozenset({
    "AWAITING_PLAN_APPROVAL",   # notify_plan_approval_pending
    "AWAITING_PR_APPROVAL",     # release pull request review
    "QUOTA_PAUSED",             # quota approval gate
    "VENDING_CALLBACK",         # project vending callback (developer dispatch follows without a stage notify)
    "TERRAFORM_CALLBACK",       # tf-applier callback
})
_RUN_SILENT_NO_WORKFLOW = "RUN_SILENT_NO_WORKFLOW"
# RT F4: a Workflows outage must not make one dashboard poll wait N x 15 s.
_WF_STATE_CHECKS_PER_POLL = 5
_WF_STATE_READ_TIMEOUT_SECONDS = 5.0
# RT F1 / F2 / F8: typed reasons of a reconcile and of a read error.
WORKFLOW_EXECUTION_NOT_FOUND = "WORKFLOW_EXECUTION_NOT_FOUND"
WORKFLOW_STATE_READ_NOT_PERMITTED = "WORKFLOW_STATE_READ_NOT_PERMITTED"
_TERMINAL_WITHOUT_NOTIFY = {
    "FAILED": ("WORKFLOW_EXECUTION_FAILED",
               "Workflow execution ended FAILED; its final status notification was not received, so the run was "
               "closed by the Control Center"),
    "CANCELLED": ("WORKFLOW_EXECUTION_CANCELLED",
                  "Workflow execution was cancelled; the run was closed by the Control Center"),
}
_RUN_ACTIVITY_FIELDS = ("last_heartbeat_at", "updated_at", "started_at")
# (trace_id, field, kind) already warned about: an unparseable timestamp is logged once per process, not on every poll.
_ts_parse_warned: set = set()


def _parse_record_time(value: Any, trace_id: str, field: str) -> Optional[datetime]:
    """A pipeline_executions timestamp as an aware UTC datetime: an ISO-8601 string (the CC / gateway / workflow
    writers), an epoch number (the gateway's plan / quota approval writes use time.time()) or a Firestore timestamp
    (a datetime subclass). None when the field is absent. A value that cannot be read is logged (once) and gives None."""
    if value is None or value == "":
        return None
    try:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return datetime.fromtimestamp(float(value), timezone.utc)
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        raise TypeError(f"unsupported type {type(value).__name__}")
    except (TypeError, ValueError, OverflowError, OSError) as e:
        key = (trace_id, field, type(value).__name__)
        if key not in _ts_parse_warned:
            _ts_parse_warned.add(key)
            logger.warning(f"Run '{trace_id}': cannot read {field}={value!r} as a time ({type(e).__name__}: {e}); "
                           f"the field is ignored by the active-runs checks")
        return None


def _last_activity(data: Dict[str, Any], trace_id: str) -> Optional[datetime]:
    """The latest readable activity time of a run record (heartbeat, update or start); None when none is readable."""
    times = [t for t in (_parse_record_time(data.get(f), trace_id, f) for f in _RUN_ACTIVITY_FIELDS) if t is not None]
    return max(times) if times else None


def _record_state_check(doc_ref: Any, trace_id: str, check: Dict[str, Any]) -> None:
    try:
        doc_ref.set({"workflow_state_check": check}, merge=True)
    except Exception as rec_err:
        logger.warning(f"Could not record the workflow state check on '{trace_id}': {rec_err}")


class _ShortTimeoutSession:
    """Wraps a Workflows session so every state read of the dashboard poll uses the short timeout (RT F4)."""

    def __init__(self, inner: Any, timeout: float):
        self._inner, self._timeout = inner, timeout

    def get(self, url: str, timeout: Optional[float] = None, **kwargs: Any) -> Any:
        return self._inner.get(url, timeout=self._timeout, **kwargs)


class _WorkflowStateReader:
    """One per active-runs poll (RT F4): at most _WF_STATE_CHECKS_PER_POLL state reads, one session for all of them
    (credentials built once per poll, not per read), each read with _WF_STATE_READ_TIMEOUT_SECONDS. A run left over by
    the cap is not marked checked, so it is read on a following poll."""

    def __init__(self) -> None:
        self.reads_left = _WF_STATE_CHECKS_PER_POLL
        self._session: Any = None
        self._session_error: Optional[Exception] = None

    def take(self) -> bool:
        if self.reads_left <= 0:
            return False
        self.reads_left -= 1
        return True

    def state(self, name: str) -> str:
        if self._session_error is not None:
            raise self._session_error
        if self._session is None:
            try:
                # The module's own session factory (test seam `session_provider`, else the CC's ADC session).
                self._session = _ShortTimeoutSession(wfx._session(), _WF_STATE_READ_TIMEOUT_SECONDS)
            except Exception as e:  # noqa: BLE001 - typed by the caller
                self._session_error = e
                raise
        return wfx.get_execution_state(name, session=self._session)


def _stored_execution_names(data: Dict[str, Any]) -> set:
    """The execution names the record itself stores (not one built from a bare id)."""
    return {v for v in (data.get("workflow_execution_name"), data.get("workflow_execution_id"))
            if wfx._is_execution_name(v)}


def _write_terminal(snapshot: Any, trace_id: str, payload: Dict[str, Any]) -> bool:
    """Writes a reconcile only if the record has not changed since this poll read it (RT F3: a terminal notify that
    lands meanwhile wins). Without an update time (never for a Firestore read) it falls back to a merge-set."""
    update_time = getattr(snapshot, "update_time", None)
    try:
        if update_time is not None and db is not None:
            snapshot.reference.update(payload, option=db.write_option(last_update_time=update_time))
        else:
            snapshot.reference.set(payload, merge=True)
        return True
    except Exception as e:  # noqa: BLE001 - a precondition conflict or a store error: the next poll re-checks
        logger.warning(f"Run '{trace_id}' not reconciled to {payload.get('status')}: the record changed since it was "
                       f"read or the write failed ({type(e).__name__}: {e}); the next poll checks again")
        return False


def _reconcile_bound_run(snapshot: Any, data: Dict[str, Any], trace_id: str, now_dt: datetime,
                         reader: _WorkflowStateReader) -> bool:
    """STALE-RUN-AUTOFAIL-BOUND: reads the bound execution's state from the Workflows API. True when the run was
    reconciled to a terminal state (it leaves the active list):
    - SUCCEEDED / FAILED / CANCELLED -> SUCCEEDED / FAILED / ABORTED (FAILED and ABORTED with a typed error_class);
    - HTTP 404 on the execution name the record itself stores (RT F1) -> FAILED, WORKFLOW_EXECUTION_NOT_FOUND: the API's
      answer that the execution does not exist (a 404 on a name built from a bare id may be a wrong region: kept).
    Any other read error never ends the run: it is logged and recorded as `workflow_state_check`
    {outcome: READ_FAILED, reason, detail} (written when it changes)."""
    previous = data.get("workflow_state_check") if isinstance(data.get("workflow_state_check"), dict) else {}
    now_iso = now_dt.isoformat()
    name = None
    try:
        name = wfx.execution_name_of(data, PROJECT_ID or os.getenv("PROJECT_ID", ""))
        if name is None:  # caller only passes bound records; kept typed rather than assumed
            raise wfx.WorkflowExecutionsError(wfx.BAD_EXECUTION_NAME, "no workflow execution is bound to the record")
        wf_state = reader.state(name)
    except Exception as e:  # noqa: BLE001 - typed below
        typed = isinstance(e, wfx.WorkflowExecutionsError)
        if typed and e.http_status == 404 and name in _stored_execution_names(data):
            message = (f"Workflow execution {name} was not found (HTTP 404); it no longer exists, so the run was "
                       f"closed by the Control Center")
            logger.warning(f"Run '{trace_id}': {message}")
            payload = {"status": "FAILED", "current_stage": "FAILED", "ended_at": now_iso,
                       "error_class": WORKFLOW_EXECUTION_NOT_FOUND, "error_message": message,
                       "workflow_state_check": {"at": now_iso, "outcome": "RECONCILED_NOT_FOUND",
                                                "reason": WORKFLOW_EXECUTION_NOT_FOUND, "detail": e.detail[:500]}}
            if not data.get("error"):
                payload["error"] = message
            return _write_terminal(snapshot, trace_id, payload)
        reason = e.code if typed else wfx.STATE_READ_FAILED
        if reason == wfx.NOT_PERMITTED:  # RT F8: the shared module names a 403 for its cancel callers
            reason = WORKFLOW_STATE_READ_NOT_PERMITTED
        detail = e.detail if typed else f"unexpected: {type(e).__name__}: {e}"
        logger.warning(f"Run '{trace_id}': workflow state not read ({reason}): {detail}; the run is left as it is")
        if previous.get("outcome") != "READ_FAILED" or previous.get("reason") != reason:
            _record_state_check(snapshot.reference, trace_id, {"at": now_iso, "outcome": "READ_FAILED",
                                                               "reason": reason, "detail": str(detail)[:500]})
        return False
    if wf_state in wfx.TERMINAL_STATES:
        target_status = {"SUCCEEDED": "SUCCEEDED", "CANCELLED": "ABORTED"}.get(wf_state, "FAILED")
        logger.info(f"Reconciling execution '{trace_id}' from GCP Workflows state '{wf_state}' -> '{target_status}'")
        payload = {"status": target_status, "ended_at": now_iso, "current_stage": target_status,
                   "workflow_state_check": {"at": now_iso, "outcome": "RECONCILED", "state": wf_state}}
        if wf_state != "SUCCEEDED":  # RT F2: the reason the UI shows
            error_class, message = _TERMINAL_WITHOUT_NOTIFY[wf_state]
            payload.update(error_class=error_class, error_message=message)
            if not data.get("error"):
                payload["error"] = message
        return _write_terminal(snapshot, trace_id, payload)
    if previous.get("outcome") == "READ_FAILED":  # the API answers again: clear the recorded failure
        _record_state_check(snapshot.reference, trace_id, {"at": now_iso, "outcome": "OK", "state": wf_state})
    # RT14-25: the workflow still waits; an outcome that never reached it (a lost tf-applier or vending callback) is
    # sent again to its own callback URL (shared.callbacks; never raises), so the run goes on instead of waiting out
    # its await bound.
    if db is not None and _callbacks.has_undelivered_stage(data):
        _callbacks.redeliver_undelivered_callbacks(db, trace_id)
    return False


# RT14-31: workload logs are read from named projects, by typed source, and a failed read is a typed error -- never
# the client's default (host) project, never an empty list, never a made-up entry.
LOG_SOURCE_WORKLOAD = "WORKLOAD"                    # the workload's own runtime, in its child project
LOG_SOURCE_PLATFORM_PIPELINE = "PLATFORM_PIPELINE"  # platform services' logs about this workload (host, exact product_id)
LOG_SOURCE_PLATFORM = "PLATFORM"                    # host-wide platform logs (platform pseudo-workloads, ADMIN-only)
LOG_SOURCE_PIPELINE_TRACE = "PIPELINE_TRACE"        # one run's platform logs (host, exact trace id)
LOGS_UNAVAILABLE = "LOGS_UNAVAILABLE"
LOGS_STAGE = "workload_logs"
LOG_SEVERITIES = ("DEFAULT", "DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY")
# Typed runtime resource types of a workload's child project (Cloud Run services and jobs, GKE, Compute Engine,
# Cloud Functions). Audit and platform-agent activity in the child project is not the workload's runtime log.
WORKLOAD_RUNTIME_RESOURCE_TYPES = ("cloud_run_revision", "cloud_run_job", "k8s_container", "gce_instance",
                                   "cloud_function")
_PIPELINE_EXCLUDED_SERVICES = ("product-control-center-ui", "orchestrator-gateway-service")


class LogSeverityInvalid(ValueError):
    """A severity that is not one of Cloud Logging's LogSeverity names (typed 422 at the route)."""


class WorkloadLogsUnavailable(Exception):
    """RT14-31: a log source could not be read (class LOGS_UNAVAILABLE, stage workload_logs). `failures` is a list of
    {source, project, code, detail}; code is NO_CHILD_PROJECT, HOST_PROJECT_REFUSED, CLIENT_UNAVAILABLE,
    PERMISSION_DENIED or QUERY_FAILED."""
    error_class = LOGS_UNAVAILABLE
    stage = LOGS_STAGE

    def __init__(self, failures: List[Dict[str, Any]]):
        self.failures = failures
        super().__init__("; ".join(f"{f['source']}: {f['code']}" for f in failures))

    def http_detail(self) -> Dict[str, Any]:
        return {"error_class": self.error_class, "stage": self.stage, "failures": self.failures,
                "detail": "Workload logs could not be read: " + str(self)}


def _log_literal(value: str) -> str:
    """A Cloud Logging query string literal (backslash and double quote escaped)."""
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _checked_severity(severity: Optional[str]) -> Optional[str]:
    if not severity or severity.strip().upper() == "ALL":
        return None
    sev = severity.strip().upper()
    if sev not in LOG_SEVERITIES:
        raise LogSeverityInvalid(severity)
    return sev


def _log_error_code(err: Exception) -> str:
    """PERMISSION_DENIED by the API's typed status (google.api_core exception class / HTTP code), else QUERY_FAILED."""
    try:
        from google.api_core import exceptions as gexc
        if isinstance(err, (gexc.PermissionDenied, gexc.Forbidden, gexc.Unauthenticated)):
            return "PERMISSION_DENIED"
    except ImportError:
        pass
    return "PERMISSION_DENIED" if getattr(err, "code", None) in (401, 403) else "QUERY_FAILED"


def _log_entry_record(entry: Any, product_id: str, source: str) -> Optional[LogEntryRecord]:
    if hasattr(entry, "timestamp") and entry.timestamp:
        ts_str = entry.timestamp.isoformat()
    else:
        ts_str = datetime.now(timezone.utc).isoformat()
    sev = getattr(entry, "severity", "INFO") or "INFO"
    res = getattr(entry, "resource", None)
    res_type = getattr(res, "type", "cloud_run_revision") or "cloud_run_revision"
    res_labels = getattr(res, "labels", {}) or {}
    svc_name = res_labels.get("service_name") or res_labels.get("job_name") or res_labels.get("workflow_id") or product_id
    if source == LOG_SOURCE_PLATFORM_PIPELINE and svc_name in _PIPELINE_EXCLUDED_SERVICES:
        return None

    msg = ""
    json_data = {}
    payload = getattr(entry, "payload", None)
    text_payload = getattr(entry, "text_payload", None)
    json_payload = getattr(entry, "json_payload", None)
    http_req = getattr(entry, "http_request", None)

    if isinstance(payload, str) and payload:
        msg = payload
    elif isinstance(payload, dict) and payload:
        msg = payload.get("message") or payload.get("textPayload") or json.dumps(payload)
        json_data = payload
    elif text_payload:
        msg = text_payload
    elif json_payload:
        json_data = dict(json_payload) if isinstance(json_payload, dict) else {}
        msg = json_data.get("message") or json.dumps(json_data)
    elif http_req and isinstance(http_req, dict):
        msg = f"{http_req.get('requestMethod', 'HTTP')} {http_req.get('requestUrl', '')} -> {http_req.get('status', '')}"
        json_data = dict(http_req)
    else:
        msg = str(payload or f"Log event recorded for {svc_name}")

    return LogEntryRecord(
        timestamp=ts_str,
        severity=str(sev),
        service_name=str(svc_name),
        resource_type=str(res_type),
        message=str(msg).strip(),
        json_payload=json_data,
        insert_id=str(getattr(entry, "insert_id", None) or ""),
        log_source=source,
    )


def collect_workload_logs(
    product_id: str,
    project_id_val: str,
    severity: Optional[str] = None,
    limit: int = 100,
    sources: Optional[Tuple[str, ...]] = None,
) -> Tuple[List[LogEntryRecord], str, List[Dict[str, Any]]]:
    """RT14-31: (logs newest first, the applied filters, typed per-source failures). Each source is queried with
    `resource_names=[projects/<its project>]`:
    - WORKLOAD: the workload's child project (`project_id_val`), its runtime resource types. Never the host project.
    - PLATFORM_PIPELINE: the host project, entries whose `jsonPayload.product_id` is exactly this workload.
    - PLATFORM (platform pseudo-workloads only, ADMIN via route policy): the host's platform services.
    A source that cannot be read is a failure entry, never an empty result. Raises LogSeverityInvalid."""
    sev = _checked_severity(severity)
    host = PROJECT_ID or os.getenv("PROJECT_ID", "")
    if sources is None:
        sources = ((LOG_SOURCE_PLATFORM,) if product_id in PLATFORM_PSEUDO_WORKLOADS
                   else (LOG_SOURCE_WORKLOAD, LOG_SOURCE_PLATFORM_PIPELINE))
    cloud_client = get_cloud_logging()
    logs: List[LogEntryRecord] = []
    filters: List[str] = []
    failures: List[Dict[str, Any]] = []

    for source in sources:
        if source == LOG_SOURCE_WORKLOAD:
            target = (project_id_val or "").strip()
            types = " OR ".join(f"resource.type={_log_literal(t)}" for t in WORKLOAD_RUNTIME_RESOURCE_TYPES)
            filter_expr = f"({types})"
            if not target:
                failures.append({"source": source, "project": "", "code": "NO_CHILD_PROJECT",
                                 "detail": f"Workload '{product_id}' has no recorded project yet."})
                continue
            if host and target == host:
                failures.append({"source": source, "project": target, "code": "HOST_PROJECT_REFUSED",
                                 "detail": "The workload's recorded project is the platform host project; its "
                                           "logs are not read as the workload's."})
                continue
        elif source == LOG_SOURCE_PLATFORM_PIPELINE:
            target = host
            filter_expr = f"jsonPayload.product_id={_log_literal(product_id)}" + "".join(
                f" AND NOT resource.labels.service_name={_log_literal(svc)}" for svc in _PIPELINE_EXCLUDED_SERVICES)
        elif source == LOG_SOURCE_PLATFORM:
            target = host
            filter_expr = ('(resource.type="cloud_run_revision" OR resource.type="cloud_run_job" OR '
                           'resource.type="workflows.googleapis.com/Workflow")')
        else:
            raise ValueError(f"unknown log source {source!r}")
        if sev:
            filter_expr += f" AND severity>={sev}"
        filters.append(f"[{source} projects/{target}] {filter_expr}")
        if not cloud_client or not target:
            failures.append({"source": source, "project": target, "code": "CLIENT_UNAVAILABLE",
                             "detail": "No Cloud Logging client or no host project configured."})
            continue
        try:
            entries = list(cloud_client.list_entries(
                resource_names=[f"projects/{target}"],
                filter_=filter_expr,
                max_results=limit,
                order_by=cloud_client.DESCENDING,
            ))
        except Exception as log_err:  # noqa: BLE001 - typed below, never an empty result
            code = _log_error_code(log_err)
            logger.error(f"Cloud Logging query ({source}) for '{product_id}' in project {target} failed "
                         f"({code}, {type(log_err).__name__}): {log_err}")
            failures.append({"source": source, "project": target, "code": code,
                             "detail": f"{type(log_err).__name__}: {str(log_err)[:300]}"})
            continue
        for entry in entries:
            rec = _log_entry_record(entry, product_id, source)
            if rec is not None:
                if not rec.insert_id:
                    rec.insert_id = f"{source.lower()}-{len(logs)}"
                logs.append(rec)

    logs.sort(key=lambda r: r.timestamp, reverse=True)
    return logs[:limit], " || ".join(filters), failures


def fetch_workload_logs_from_cloud_logging(
    product_id: str,
    project_id_val: str,
    severity: Optional[str] = None,
    limit: int = 100,
    sources: Optional[Tuple[str, ...]] = None,
) -> Tuple[List[LogEntryRecord], str]:
    """All-or-nothing read for internal callers (the AAR): raises WorkloadLogsUnavailable when any requested source
    could not be read (RT14-31: an error is never an empty result)."""
    logs, filter_expr, failures = collect_workload_logs(product_id, project_id_val, severity, limit, sources)
    if failures:
        raise WorkloadLogsUnavailable(failures)
    return logs, filter_expr


def fetch_trace_logs_from_cloud_logging(
    trace_id: str,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Queries Google Cloud Logging for log entries associated with a specific workflow execution trace_id.
    RT14-31: the platform pipeline's logs live in the host project, which is named in `resource_names`; a query that
    cannot run raises WorkloadLogsUnavailable (source PIPELINE_TRACE) instead of answering an empty list."""
    logs_list: List[Dict[str, Any]] = []
    main_mod = get_caller_main_module()
    target_project = getattr(main_mod, "project_id", None) or PROJECT_ID or os.getenv("PROJECT_ID", "")
    if not target_project:
        try:
            import google.auth
            _, _auth_proj = google.auth.default()
            target_project = _auth_proj or ""
        except Exception:
            pass

    active_logging = getattr(main_mod, "cloud_logging", None)
    if active_logging and hasattr(active_logging, "Client"):
        try:
            cloud_client = active_logging.Client(project=target_project)
        except Exception:
            cloud_client = get_cloud_logging()
    else:
        cloud_client = get_cloud_logging()

    if not trace_id:
        return logs_list
    if not cloud_client or not target_project:
        raise WorkloadLogsUnavailable([{"source": LOG_SOURCE_PIPELINE_TRACE, "project": target_project or "",
                                        "code": "CLIENT_UNAVAILABLE",
                                        "detail": "No Cloud Logging client or no host project configured."}])

    descending_order = getattr(active_logging, "DESCENDING", None) or getattr(cloud_client, "DESCENDING", "DESCENDING")
    trace_lit = _log_literal(trace_id)
    filter_expr = f'(textPayload:{trace_lit} OR jsonPayload.trace_id={trace_lit}) AND NOT resource.labels.service_name="product-control-center-ui"'
    try:
        entries = list(cloud_client.list_entries(
            resource_names=[f"projects/{target_project}"],
            filter_=filter_expr,
            max_results=min(limit, 200),
            order_by=descending_order,
        ))
        for entry in entries:
            ts_str = entry.timestamp.isoformat() if hasattr(entry, "timestamp") and entry.timestamp else datetime.now(timezone.utc).isoformat()
            sev = getattr(entry, "severity", "INFO") or "INFO"
            res = getattr(entry, "resource", None)
            res_labels = getattr(res, "labels", {}) or {}
            svc_name = res_labels.get("service_name") or res_labels.get("job_name") or res_labels.get("workflow_id") or "orchestrator"

            if svc_name == "product-control-center-ui":
                continue

            msg = ""
            payload = getattr(entry, "payload", None)
            text_payload = getattr(entry, "text_payload", None)
            json_payload = getattr(entry, "json_payload", None)
            if isinstance(payload, str) and payload:
                msg = payload
            elif text_payload:
                msg = text_payload
            elif json_payload:
                json_data = dict(json_payload) if isinstance(json_payload, dict) else {}
                msg = json_data.get("message") or json.dumps(json_data)
            else:
                msg = str(payload or "")

            if "GET /api/pipeline/executions/" in msg or "/api/workloads/" in msg:
                continue

            logs_list.append({
                "timestamp": ts_str,
                "severity": str(sev),
                "service_name": str(svc_name),
                "message": msg.strip(),
            })
    except Exception as e:  # noqa: BLE001 - typed, never an empty result (RT14-31)
        code = _log_error_code(e)
        logger.error(f"Failed to query trace logs for {trace_id} ({code}, {type(e).__name__}): {e}")
        raise WorkloadLogsUnavailable([{"source": LOG_SOURCE_PIPELINE_TRACE, "project": target_project, "code": code,
                                        "detail": f"{type(e).__name__}: {str(e)[:300]}"}]) from e

    return sorted(logs_list, key=lambda x: x.get("timestamp", ""))


def get_castor_agent_roster() -> List[Dict[str, Any]]:
    """Defines the static metadata and capabilities for the 9 Project Castor operational agents."""
    return [
        {
            "agent_id": "architect",
            "name": "The Architect",
            "role_title": "Task Orchestration & Spec Ingestion",
            "avatar_icon": "🧠",
            "tooling": ["Google Docs MCP", "Google Drive Intake", "Vertex AI Gemini", "PubSub Events"],
        },
        {
            "agent_id": "compliance",
            "name": "The Compliance Agent",
            "role_title": "Assured Workloads & Regulatory Policy Sentinel",
            "avatar_icon": "🛡️",
            "tooling": ["mcp-compliance-server", "Assured Workloads API", "CMEK Cloud KMS", "Audit Sinks", "Policy-as-Code"],
        },
        {
            "agent_id": "developer",
            "name": "The Developer",
            "role_title": "Software Engineering & Code Health",
            "avatar_icon": "💻",
            "tooling": ["mcp-github-toolserver", "AST Code Smells", "Pytest Suite", "Git CLI"],
        },
        {
            "agent_id": "gatekeeper",
            "name": "The Anti-Hallucination Gatekeeper",
            "role_title": "AST Import Transformer & Compiler Quality Gate",
            "avatar_icon": "🔬",
            "tooling": ["AST Node Transformer", "Canonical PyPI Resolver", "Procfile / Contract Enforcer", "py_compile Sandbox"],
        },
        {
            "agent_id": "gcp-devops",
            "name": "The GCP DevOps Agent",
            "role_title": "Cloud Infrastructure & Terraform",
            "avatar_icon": "☁️",
            "tooling": ["mcp-terraform-server", "mcp-gcloud-server", "Cloud Run MCP", "GCS Remote State"],
        },
        {
            "agent_id": "qa-reviewer",
            "name": "The QA Reviewer",
            "role_title": "Quality Assurance & Security Auditor",
            "avatar_icon": "🧪",
            "tooling": ["qa-sandbox-test-runner", "E2E Regression", "Security Scanner", "AST Linters"],
        },
        {
            "agent_id": "release-engineer",
            "name": "The Release Engineer",
            "role_title": "GitOps Governance & Continuous Delivery",
            "avatar_icon": "🚀",
            "tooling": ["mcp-github-toolserver", "Cloud Build CI/CD", "Workflows Promotion", "Changelog Gen"],
        },
        {
            "agent_id": "finops",
            "name": "The FinOps Agent",
            "role_title": "FinOps Budget & Cost Sentinel",
            "avatar_icon": "💰",
            "tooling": ["mcp-infracost-server", "Cloud Billing API", "Budget Sentinel", "Auto-Kill Circuit"],
        },
        {
            "agent_id": "sre",
            "name": "The SRE Agent",
            "role_title": "Observability & Incident Sentinel",
            "avatar_icon": "🚨",
            "tooling": ["log-sre-sentinel", "Cloud Logging Sink", "Stack Fingerprinting", "Automated RCA"],
        },
    ]


def get_castor_tool_servers_roster() -> List[Dict[str, Any]]:
    """Defines the metadata and capabilities for core tool servers."""
    return [
        {
            "server_id": "project-repo-vending",
            "name": "Project & Repo Vending Machine",
            "role_description": "Provisions isolated GCP child projects under the managed workloads folder, attaches Cloud Billing accounts, mints 1-hour GitHub JIT tokens, and auto-initializes repositories.",
            "service_name": "project-repo-vending-service",
            "icon": "🏭",
            "status": "HEALTHY",
        },
        {
            "server_id": "mcp-compliance",
            "name": "Assured Workloads & Compliance MCP Server",
            "role_description": "Inspects GCP folder compliance regimes (HIPAA, FedRAMP Moderate/High, GDPR, CJIS), mandates CMEK key rotation, and enforces Policy-as-Code.",
            "service_name": "mcp-compliance-server",
            "icon": "🛡️",
            "status": "HEALTHY",
        },
        {
            "server_id": "mcp-terraform",
            "name": "Deterministic Terraform MCP Server",
            "role_description": "Executes declarative terraform init, plan, and apply in ephemeral sandboxes against remote state buckets (gs://castor-tfstate-*).",
            "service_name": "mcp-terraform-server",
            "icon": "☁️",
            "status": "HEALTHY",
        },
        {
            "server_id": "mcp-infracost",
            "name": "Infracost Pre-Flight FinOps Server",
            "role_description": "Performs pre-flight HCL diff cost estimation against workload budget ceilings before cloud deployments. Runtime budget breaches are handled by the FinOps enforcer according to each workload's breach policy.",
            "service_name": "mcp-infracost-server",
            "icon": "💰",
            "status": "HEALTHY",
        },
        {
            "server_id": "mcp-github",
            "name": "GitHub GitOps Tool Server",
            "role_description": "Manages Git feature branches, atomic code commits, Pull Request promotion, and branch protection policies.",
            "service_name": "mcp-github-toolserver",
            "icon": "🐙",
            "status": "HEALTHY",
        },
        {
            "server_id": "mcp-workspace",
            "name": "Google Workspace Connector",
            "role_description": "Ingests product specs from Google Drive '📁 01_Inbox_Requests', updates living spec checklists, and issues HITL approval callouts.",
            "service_name": "mcp-workspace-connector",
            "icon": "📄",
            "status": "HEALTHY",
        },
        {
            "server_id": "mcp-gcloud",
            "name": "GCloud CLI Tool Server",
            "role_description": "Executes imperative gcloud CLI commands, IAM permission checks, and Cloud Run revision inspections.",
            "service_name": "mcp-gcloud-server",
            "icon": "⚡",
            "status": "HEALTHY",
        },
        {
            "server_id": "mcp-kubernetes",
            "name": "Kubernetes Container Orchestrator MCP Server",
            "role_description": "Dynamic GKE Workload Identity auth, declarative manifest validation/apply, Helm lifecycle, pod log streaming, and SRE crash diagnostics.",
            "service_name": "mcp-kubernetes-server",
            "icon": "☸️",
            "status": "HEALTHY",
        },
        {
            "server_id": "mcp-agent-builder",
            "name": "Google ADK & Agent Engine Vending MCP Server",
            "role_description": "Autonomous synthesis of Google ADK agents, Discovery Engine search datastores, dependency whitelisting, and serverless deployment to Agent Engine.",
            "service_name": "mcp-agent-builder-server",
            "icon": "🤖",
            "status": "HEALTHY",
        },
    ]


def build_pipeline_overview(target_project_id: str) -> PipelineOverviewResponse:
    """Aggregates real-time pipeline status across all 7 agents and core tool servers."""
    now_iso = datetime.now(timezone.utc).isoformat()
    roster_defs = get_castor_agent_roster()
    agents_summary: List[AgentStatusSummary] = []
    recent_intake: List[AgentTaskRecord] = []

    agent_active_tasks: Dict[str, Optional[AgentTaskRecord]] = {a["agent_id"]: None for a in roster_defs}
    agent_backlogs: Dict[str, List[AgentTaskRecord]] = {a["agent_id"]: [] for a in roster_defs}
    agent_completed_counts: Dict[str, int] = {a["agent_id"]: 0 for a in roster_defs}

    if db:
        try:
            fr_docs = db.collection("feature_requests").order_by("created_at", direction=firestore.Query.DESCENDING).limit(20).stream()
            for doc in fr_docs:
                data = doc.to_dict() or {}
                status_raw = data.get("status", "PENDING_TRIAGE")
                prio_str = data.get("priority", "MEDIUM")
                try:
                    prio_enum = FeatureRequestPriority(prio_str)
                except ValueError:
                    prio_enum = FeatureRequestPriority.MEDIUM

                task_status = AgentTaskStatus.QUEUED
                assigned_agent = "architect"
                if status_raw in ["IN_PROGRESS", "IN_DEVELOPMENT"]:
                    fr_trace_id = data.get("trace_id")
                    is_still_active = True
                    if fr_trace_id and db:
                        try:
                            pe_doc = db.collection("pipeline_executions").document(fr_trace_id).get()
                            if pe_doc.exists:
                                pe_data = pe_doc.to_dict() or {}
                                pe_status = pe_data.get("status")
                                if pe_status in ["SUCCEEDED", "FAILED"]:
                                    is_still_active = False
                                    status_raw = "COMPLETED" if pe_status == "SUCCEEDED" else "FAILED"
                                    db.collection("feature_requests").document(doc.id).set({
                                        "status": status_raw,
                                        "completed_at": pe_data.get("completed_at") or now_iso,
                                        "service_url": pe_data.get("outputs", {}).get("service_url") or "",
                                    }, merge=True)
                        except Exception as pe_sync_err:
                            logger.debug(f"Could not reconcile feature request {doc.id}: {pe_sync_err}")

                    if is_still_active:
                        task_status = AgentTaskStatus.IN_PROGRESS
                        assigned_agent = "developer"
                    elif status_raw == "COMPLETED":
                        task_status = AgentTaskStatus.COMPLETED
                        assigned_agent = "release-engineer"
                    elif status_raw in ["FAILED", "REJECTED", "CANCELLED"]:
                        task_status = AgentTaskStatus.FAILED
                        assigned_agent = "architect"
                    else:
                        task_status = AgentTaskStatus.QUEUED
                        assigned_agent = "architect"
                elif status_raw in ["COMPLETED", "RESOLVED"]:
                    task_status = AgentTaskStatus.COMPLETED
                    assigned_agent = "release-engineer"
                elif status_raw in ["FAILED", "REJECTED", "CANCELLED"]:
                    task_status = AgentTaskStatus.FAILED
                    assigned_agent = "architect"

                task_item = AgentTaskRecord(
                    task_id=data.get("request_id", doc.id),
                    agent_id=assigned_agent,
                    workload_id=data.get("product_id", "project-castor"),
                    project_id=data.get("project_id", target_project_id),
                    github_repo=data.get("github_repo"),
                    title=data.get("title", "Feature Request Intake"),
                    description=data.get("description", ""),
                    source_type=TaskSourceType.FEATURE_REQUEST,
                    priority=prio_enum,
                    status=task_status,
                    created_at=data.get("created_at", now_iso),
                    updated_at=data.get("created_at", now_iso),
                )
                recent_intake.append(task_item)

                if task_status == AgentTaskStatus.IN_PROGRESS:
                    if not agent_active_tasks[assigned_agent]:
                        agent_active_tasks[assigned_agent] = task_item
                    else:
                        agent_backlogs[assigned_agent].append(task_item)
                elif task_status == AgentTaskStatus.QUEUED:
                    agent_backlogs[assigned_agent].append(task_item)
                elif task_status == AgentTaskStatus.COMPLETED:
                    agent_completed_counts[assigned_agent] += 1
        except Exception as e:
            logger.warning(f"Could not read feature_requests for pipeline overview: {e}")

        try:
            inc_docs = db.collection("incidents").limit(10).stream()
            for doc in inc_docs:
                data = doc.to_dict() or {}
                inc_status = data.get("status", "OPEN")
                task_status = AgentTaskStatus.IN_PROGRESS if inc_status in ["OPEN", "TRIAGING"] else AgentTaskStatus.QUEUED
                task_item = AgentTaskRecord(
                    task_id=data.get("incident_id", doc.id),
                    agent_id="sre",
                    workload_id="project-castor",
                    project_id=target_project_id,
                    github_repo=None,
                    title=f"Log Incident: {data.get('service_name', 'Service Error')}",
                    description=data.get("error_message") or data.get("stack_trace", "Runtime error detected"),
                    source_type=TaskSourceType.SRE_INCIDENT,
                    priority=FeatureRequestPriority.HIGH,
                    status=task_status,
                    created_at=data.get("created_at", now_iso),
                    trace_id=data.get("trace_id"),
                )
                recent_intake.append(task_item)
                if task_status == AgentTaskStatus.IN_PROGRESS and not agent_active_tasks["sre"]:
                    agent_active_tasks["sre"] = task_item
                else:
                    agent_backlogs["sre"].append(task_item)
        except Exception as e:
            logger.warning(f"Could not read incidents for pipeline overview: {e}")

    total_active = 0
    total_backlog = 0
    total_completed = 0

    for a_def in roster_defs:
        aid = a_def["agent_id"]
        cur_task = agent_active_tasks[aid]
        backlog_items = agent_backlogs[aid]
        comp_count = agent_completed_counts[aid]

        status_str = "ACTIVE" if cur_task else "STANDBY"
        if cur_task:
            total_active += 1
        total_backlog += len(backlog_items)
        total_completed += comp_count

        agents_summary.append(
            AgentStatusSummary(
                agent_id=aid,
                name=a_def["name"],
                role_title=a_def["role_title"],
                avatar_icon=a_def["avatar_icon"],
                status=status_str,
                tooling=a_def["tooling"],
                current_task=cur_task,
                backlog_count=len(backlog_items),
                backlog=backlog_items,
                completed_count=comp_count,
            )
        )

    tool_roster_defs = get_castor_tool_servers_roster()
    tool_servers_summary: List[ToolServerSummary] = []
    vended_workloads_count = 0
    if db:
        try:
            w_docs = db.collection("workloads").stream()
            vended_workloads_count = sum(1 for w in w_docs if not w.to_dict().get("is_castor"))
        except Exception:
            pass

    for t_def in tool_roster_defs:
        ops_cnt = 0
        if t_def["server_id"] == "project-repo-vending":
            ops_cnt = vended_workloads_count
        elif t_def["server_id"] in ["mcp-infracost", "mcp-terraform"]:
            ops_cnt = len(recent_intake)
        elif t_def["server_id"] == "mcp-github":
            ops_cnt = vended_workloads_count + total_completed

        tool_servers_summary.append(
            ToolServerSummary(
                server_id=t_def["server_id"],
                name=t_def["name"],
                role_description=t_def["role_description"],
                service_name=t_def["service_name"],
                icon=t_def["icon"],
                status=t_def.get("status", "HEALTHY"),
                operations_count=ops_cnt,
                recent_operations=[],
            )
        )

    return PipelineOverviewResponse(
        total_active_tasks=total_active,
        total_backlog=total_backlog,
        total_completed=total_completed,
        agents_count=len(agents_summary),
        is_placeholder=False,
        agents=agents_summary,
        tool_servers=tool_servers_summary,
        recent_intake_stream=recent_intake,
    )


def _sanitize_execution_stages(data: dict) -> dict:
    """
    Sanitizes stage models and reconciles terminal execution states.
    In particular, when an execution has SUCCEEDED (or current_stage is COMPLETE),
    any stage that was left IN_FLIGHT (especially 'discovery') is auto-reconciled to SUCCESS.
    """
    status = data.get("status")
    current_stage = str(data.get("current_stage") or "").upper()
    is_succeeded = status == "SUCCEEDED" or current_stage == "COMPLETE"

    stages_raw = data.get("stages") or {}
    stages_clean = {}

    for sk, sv in stages_raw.items():
        if isinstance(sv, dict):
            sv_copy = dict(sv)
            if is_succeeded and sv_copy.get("status") in ["IN_FLIGHT", "QUEUED"]:
                if sk == "discovery":
                    sv_copy["status"] = "SUCCESS"
                    if not sv_copy.get("summary") or "Harvesting" in sv_copy.get("summary", ""):
                        sv_copy["summary"] = "GCP Org Policies harvested & verified"
                elif sk != "sre":
                    sv_copy["status"] = "SUCCESS"
            try:
                stages_clean[sk] = StageExecutionDetail(**sv_copy)
            except Exception:
                stages_clean[sk] = sv_copy
        else:
            stages_clean[sk] = sv

    # If discovery stage is completely missing but execution succeeded, add it as SUCCESS
    if is_succeeded and "discovery" not in stages_clean:
        stages_clean["discovery"] = StageExecutionDetail(
            status="SUCCESS",
            summary="GCP Org Policies harvested & verified"
        )

    data["stages"] = stages_clean
    return data


@router.get("/api/pipeline/executions/active", response_model=ActiveExecutionsResponse, dependencies=[require(SCOPED)])
def get_active_pipeline_executions(product_id: Optional[str] = None, request: Request = None):
    if product_id and request:
        verify_workload_access(product_id, request)
    # FD-4N (red-team H11): explicit scope; HTTP callers always pass `request` (direct in-process calls do not).
    scope = workload_scope(request) if request is not None else None

    active_list: List[PipelineExecutionItem] = []
    recent_completed: List[PipelineExecutionItem] = []
    latest_completed: Optional[PipelineExecutionItem] = None
    queued_list: List[PipelineExecutionItem] = []
    queue_summary: Optional[Dict[str, Any]] = None

    if db:
        try:
            col = db.collection("pipeline_executions")
            try:
                query = col.where("status", "in", ["ACTIVE", "RUNNING", "PAUSED_RATE_LIMIT_COOLDOWN"])
                if product_id:
                    query = query.where("product_id", "==", product_id)
                docs = list(query.stream())
            except Exception as q_err:
                logger.warning(f"Error querying active executions with in operator: {q_err}, falling back to status==ACTIVE")
                query = col.where("status", "==", "ACTIVE")
                if product_id:
                    query = query.where("product_id", "==", product_id)
                docs = list(query.stream())

            now_dt = datetime.now(timezone.utc)
            wf_reader = _WorkflowStateReader()  # STALE-RUN-AUTOFAIL-BOUND (RT F4): capped reads, one session per poll
            workload_status_cache: Dict[str, str] = {}

            for d in docs:
                data = d.to_dict() or {}
                trace_id_val = d.id
                data["trace_id"] = data.get("trace_id") or trace_id_val
                status_val = data.get("status", "ACTIVE")
                pid = str(data.get("product_id") or "").strip().lower()

                # Check 1: Inactive Parent Workload Reconciliation
                phantom_cancel_pending = False  # SAT-43: its execution could not be cancelled; status left as is
                if pid and pid != "default-workload" and pid != "project-castor":
                    if pid not in workload_status_cache:
                        try:
                            w_doc = db.collection("workloads").document(pid).get()
                            workload_status_cache[pid] = (w_doc.to_dict() or {}).get("status", "") if w_doc.exists else "NOT_FOUND"
                        except Exception:
                            workload_status_cache[pid] = "UNKNOWN"

                    parent_status = workload_status_cache.get(pid)
                    if parent_status in ["DECOMMISSIONED", "ARCHIVED", "NOT_FOUND"]:
                        # SAT-43 (fail closed, as Abort and the decommission cascade): cancel the bound workflow
                        # execution first; mark ABORTED only when it was cancelled, had already ended, or none is bound.
                        last_failed = _phantom_cancel_cache.get(trace_id_val)
                        if last_failed is not None and time.time() - last_failed < _PHANTOM_CANCEL_RETRY_SECONDS:
                            phantom_cancel_pending = True  # failed recently: leave the run as it is, no call, no log
                        else:
                            wf_cancel = wfx.cancel_bound_execution(data, PROJECT_ID or os.getenv("PROJECT_ID", ""))
                            if wf_cancel is None or wf_cancel["outcome"] != wfx.FAILED:
                                _phantom_cancel_cache.pop(trace_id_val, None)
                                logger.info(f"Reconciling phantom execution '{trace_id_val}' because parent workload "
                                            f"'{pid}' is {parent_status} (workflow cancel: "
                                            f"{wf_cancel['outcome'] if wf_cancel else 'no bound execution'})")
                                record = {
                                    "status": "ABORTED",
                                    "error_message": f"Execution auto-aborted: Parent workload '{pid}' is {parent_status}",
                                    "ended_at": now_dt.isoformat(),
                                    "current_stage": "ABORTED",
                                }
                                if wf_cancel is not None:
                                    record["workflow_cancel"] = {"outcome": wf_cancel["outcome"],
                                                                 "reason": wf_cancel["reason"],
                                                                 "detail": wf_cancel["detail"]}
                                try:
                                    d.reference.set(record, merge=True)
                                except Exception as rec_err:
                                    logger.warning(f"Failed to auto-abort orphaned execution '{trace_id_val}': {rec_err}")
                                continue
                            _phantom_cancel_cache[trace_id_val] = time.time()
                            phantom_cancel_pending = True
                            logger.error(f"Phantom execution '{trace_id_val}' (parent workload '{pid}' is "
                                         f"{parent_status}) NOT aborted: its workflow execution {wf_cancel['name']!r} "
                                         f"could not be cancelled ({wf_cancel['reason']}): {wf_cancel['detail']}")
                            try:
                                d.reference.set({"abort_attempt": {
                                    "at": now_dt.isoformat(), "by": "flight-deck-phantom-reconcile",
                                    "reason": f"Parent workload '{pid}' is {parent_status}",
                                    "workflow_cancel": {"name": wf_cancel["name"], "outcome": wf_cancel["outcome"],
                                                        "reason": wf_cancel["reason"], "detail": wf_cancel["detail"],
                                                        "state": wf_cancel["state"]}}}, merge=True)
                            except Exception as rec_err:
                                logger.warning(f"Could not record the abort attempt on '{trace_id_val}': {rec_err}")

                # STALE-RUN-AUTOFAIL-BOUND (replaces the M52 silence auto-fail and the SAT-43 state check that ran
                # after it; constants and helpers at the top of this module).
                bound = bool(data.get("workflow_execution_name") or data.get("workflow_execution_id"))
                if not phantom_cancel_pending:
                    last_activity = _last_activity(data, trace_id_val)
                    quiet_seconds = (now_dt - last_activity).total_seconds() if last_activity else None
                    if bound:
                        # Check 2 (bound run): the Workflows API decides; silence alone never ends it.
                        if quiet_seconds is None or quiet_seconds > _WF_STATE_CHECK_AFTER_SECONDS:
                            current_epoch = time.time()
                            if (current_epoch - _wf_check_cache.get(trace_id_val, 0) > _WF_STATE_CHECK_INTERVAL_SECONDS
                                    and wf_reader.take()):
                                _wf_check_cache[trace_id_val] = current_epoch
                                if _reconcile_bound_run(d, data, trace_id_val, now_dt, wf_reader):
                                    continue
                    else:
                        # Check 3 (no bound execution): nothing will report this run's end; fail it after the
                        # silence limit unless it waits in one of the exact exempt stages.
                        curr_stage = str(data.get("current_stage") or "")
                        is_exempt = (
                            status_val == "PAUSED_RATE_LIMIT_COOLDOWN"
                            or (data.get("cooldown_state") or {}).get("is_paused")
                            or curr_stage in _SILENCE_EXEMPT_STAGES
                        )
                        if (not is_exempt and quiet_seconds is not None
                                and quiet_seconds > _UNBOUND_SILENCE_LIMIT_SECONDS):
                            logger.warning(f"Auto-failing stale execution '{trace_id_val}' ({quiet_seconds:.0f}s "
                                           f"silent in stage '{curr_stage}', no workflow execution bound)")
                            silent_message = (f"Execution timed out: no workflow execution is bound to this run and "
                                              f"it had no activity for >{_UNBOUND_SILENCE_LIMIT_SECONDS // 60} "
                                              f"minutes in stage '{curr_stage}'")
                            silent_fail = {
                                "status": "FAILED",
                                "error_class": _RUN_SILENT_NO_WORKFLOW,
                                "error_message": silent_message,
                                "ended_at": now_dt.isoformat(),
                                "current_stage": "FAILED",
                            }
                            if not data.get("error"):  # RT F2: the field the Flight Deck shows
                                silent_fail["error"] = silent_message
                            try:
                                d.reference.set(silent_fail, merge=True)
                            except Exception as fail_err:
                                logger.warning(f"Failed to auto-fail stale execution '{trace_id_val}': {fail_err}")
                            continue

                started_at_str = data.get("started_at")
                if started_at_str:
                    try:
                        started_dt = datetime.fromisoformat(started_at_str.replace("Z", "+00:00"))
                        data["elapsed_seconds"] = round((now_dt - started_dt).total_seconds(), 1)
                    except Exception:
                        pass
                data = _sanitize_execution_stages(data)

                try:
                    active_list.append(PipelineExecutionItem(**data))
                except Exception as parse_err:
                    logger.warning(f"Error parsing pipeline execution item {d.id}: {parse_err}")

            # BUILD-ADMISSION-QUEUE (G4) reconcile safety net: the loop above closed the runs whose workflow ended
            # (Workflows API); their build slots are released now and queued builds dispatched (published). Then the
            # queue itself, in order. Never raises.
            build_queue.reconcile_and_pump(db)
            # F2 option A: a running run that waits for a person holds no slot; an approved one may wait for a slot.
            slot_state, slot_limit = build_queue.slot_annotations(db)
            if slot_state:
                for item in active_list:
                    item.build_queue = _build_admission.slot_view(slot_state, item.trace_id, slot_limit)
            queued_raw, queue_summary = build_queue.queued_runs(db, product_id)
            for q in queued_raw:
                try:
                    queued_list.append(PipelineExecutionItem(**_sanitize_execution_stages(q)))
                except Exception as parse_err:
                    logger.warning(f"Error parsing queued pipeline execution item {q.get('trace_id')}: {parse_err}")

            try:
                comp_docs = []
                if product_id:
                    try:
                        comp_query = col.where("product_id", "==", product_id).order_by("started_at", direction=firestore.Query.DESCENDING).limit(50)
                        comp_docs = list(comp_query.stream())
                    except Exception:
                        p_query = col.where("product_id", "==", product_id).limit(50)
                        comp_docs = sorted(list(p_query.stream()), key=lambda x: (x.to_dict() or {}).get("started_at", ""), reverse=True)[:50]
                elif scope is not None and not scope.all:
                    # Filter BEFORE the limit: query only the caller's workloads (Firestore `in` takes <= 30 values).
                    ids = sorted(scope.ids)
                    for i in range(0, len(ids), 30):
                        comp_docs.extend(col.where("product_id", "in", ids[i:i + 30]).limit(50).stream())
                    comp_docs = sorted(comp_docs, key=lambda x: str((x.to_dict() or {}).get("started_at", "")), reverse=True)[:50]
                else:
                    try:
                        comp_query = col.order_by("started_at", direction=firestore.Query.DESCENDING).limit(50)
                        comp_docs = list(comp_query.stream())
                    except Exception:
                        comp_docs = list(col.limit(50).stream())

                for cd in comp_docs:
                    comp_data = cd.to_dict() or {}
                    if comp_data.get("status") == "ACTIVE" and any(a.trace_id == comp_data.get("trace_id") for a in active_list):
                        continue
                    if comp_data.get("status") == _build_admission.RUN_STATUS_QUEUED:
                        continue   # BUILD-ADMISSION-QUEUE: listed under queued_executions
                    comp_data = _sanitize_execution_stages(comp_data)
                    try:
                        recent_completed.append(PipelineExecutionItem(**comp_data))
                    except Exception as parse_err:
                        logger.debug(f"Error parsing completed pipeline execution item {cd.id}: {parse_err}")

                if recent_completed:
                    latest_completed = recent_completed[0]
            except Exception as comp_err:
                logger.debug(f"Could not fetch recent completed executions: {comp_err}")
        except Exception as e:
            logger.warning(f"Failed to query active pipeline executions from Firestore: {e}")

    if scope is not None and not scope.all:
        active_list = [e for e in active_list if scope.allows(e.product_id)]
        recent_completed = [e for e in recent_completed if scope.allows(e.product_id)]
        latest_completed = recent_completed[0] if recent_completed else None
        queued_list = [e for e in queued_list if scope.allows(e.product_id)]

    return ActiveExecutionsResponse(
        active_executions=active_list,
        total_active=len(active_list),
        latest_completed=latest_completed,
        recent_completed=recent_completed,
        queued_executions=queued_list,
        build_queue=queue_summary,
    )


@router.get("/api/pipeline/executions/{trace_id}", response_model=PipelineExecutionItem, dependencies=[require(TRACE())])
def get_pipeline_execution(trace_id: str, request: Request = None):
    """Retrieves real-time execution status and stage DAG details for a specific trace."""
    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")

    doc = db.collection("pipeline_executions").document(trace_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Pipeline execution '{trace_id}' not found")

    data = doc.to_dict() or {}
    if request:
        exec_pid = data.get("product_id")
        if exec_pid:
            verify_workload_access(exec_pid, request)
        elif getattr(request.state, "user_role", None) != UserRole.ADMIN:
            # FD-4N (Q11): an execution with no product_id is visible to administrators only.
            raise HTTPException(status_code=403, detail="Access denied.")
    if data.get("status") == "ACTIVE" and data.get("started_at"):
        try:
            started_dt = datetime.fromisoformat(data["started_at"].replace("Z", "+00:00"))
            data["elapsed_seconds"] = round((datetime.now(timezone.utc) - started_dt).total_seconds(), 1)
        except Exception:
            pass
    if data.get("status") == _build_admission.RUN_STATUS_QUEUED:   # BUILD-ADMISSION-QUEUE: its place in line
        data["build_queue"] = build_queue.queue_position(db, trace_id)
    elif data.get("status") in ("ACTIVE", "RUNNING", "PAUSED_RATE_LIMIT_COOLDOWN"):
        slot_state, slot_limit = build_queue.slot_annotations(db)   # F2: waiting for a person / for a slot
        if slot_state:
            data["build_queue"] = _build_admission.slot_view(slot_state, trace_id, slot_limit)

    data = _sanitize_execution_stages(data)

    return PipelineExecutionItem(**data)


@router.get("/api/pipeline/executions/{trace_id}/logs", dependencies=[require(TRACE())])
def get_pipeline_execution_logs(trace_id: str, limit: int = 100, request: Request = None):
    if request:
        get_pipeline_execution(trace_id=trace_id, request=request)
    try:
        logs = fetch_trace_logs_from_cloud_logging(trace_id=trace_id, limit=limit)
    except WorkloadLogsUnavailable as logs_err:   # RT14-31: typed, never "no logs"
        raise HTTPException(status_code=502, detail=logs_err.http_detail())
    return {"trace_id": trace_id, "total_logs": len(logs), "logs": logs}


@router.get("/api/pipeline/executions/{trace_id}/telemetry", response_model=FlightDeckResponse, dependencies=[require(TRACE())])
def get_pipeline_flight_deck_telemetry(trace_id: str, request: Request = None):
    exec_item = get_pipeline_execution(trace_id=trace_id, request=request)
    try:
        logs, logs_error = fetch_trace_logs_from_cloud_logging(trace_id=trace_id, limit=150), None
    except WorkloadLogsUnavailable as logs_err:   # RT14-31: the run is still shown; the log failure is typed beside it
        logs, logs_error = [], logs_err.http_detail()
    return FlightDeckResponse(execution=exec_item, live_logs=logs, live_logs_error=logs_error)


@router.post("/api/pipeline/executions/{trace_id}/abort", dependencies=[require(TRACE(manager=True))])
def abort_pipeline_execution(trace_id: str, request: Request):
    """
    Aborts an active or paused pipeline execution:
    1. Validates caller authorization (Admin or Assigned Workload Manager)
    2. Cancels the underlying Cloud Workflows execution if running
    3. Updates Firestore document to status='ABORTED' with termination reason and audit trail
    """
    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")

    doc_ref = db.collection("pipeline_executions").document(trace_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Pipeline execution '{trace_id}' not found")

    data = doc.to_dict() or {}
    product_id = data.get("product_id") or "default-workload"
    verify_workload_access(product_id, request, require_manager=True)

    caller_email = getattr(request.state, "user_email", "admin-console")
    now_iso = datetime.now(timezone.utc).isoformat()

    # BUILD-ADMISSION-QUEUE (G4): a run still waiting for a build slot is cancelled in the queue (it never starts). One
    # that has just been granted a slot is being started: 409, abort it once it runs. A QUEUED record the queue does
    # not hold (left over) is aborted below like any unbound run.
    if data.get("status") == _build_admission.RUN_STATUS_QUEUED:
        try:
            cancelled = build_queue.cancel_queued(db, trace_id, caller_email)
        except _build_admission.BuildAdmissionError as q_err:
            if q_err.error_class != _build_admission.BUILD_QUEUE_NOT_QUEUED:
                raise HTTPException(status_code=409 if q_err.error_class ==
                                    _build_admission.BUILD_QUEUE_ALREADY_DISPATCHING else 503, detail=q_err.body())
        else:
            try:
                db.collection("workloads").document(product_id).collection("audit_logs").document().set({
                    "action": "QUEUED_BUILD_CANCELLED", "operator_email": caller_email, "trace_id": trace_id,
                    "reason": "Queued build cancelled before it started", "timestamp": now_iso})
            except Exception as audit_err:
                logger.warning(f"Could not write audit log for cancelled queued trace '{trace_id}': {audit_err}")
            return {"status": "ABORTED", "trace_id": trace_id, "product_id": product_id, "aborted_by": caller_email,
                    "aborted_at": now_iso, "workflow_cancel_status": None, "workflow_cancel": None,
                    "build_queue": cancelled,
                    "message": f"Queued build '{trace_id}' was cancelled before it started."}

    # Cancel the Cloud Workflows execution if bound (SAT-43: Workflows REST API, typed outcome). Fail closed: when the
    # execution could not be cancelled (it may still be running), the run is NOT marked ABORTED; the attempt is kept on
    # the record (abort_attempt) and the call answers 502 with the typed reason.
    wf_cancel = wfx.cancel_bound_execution(data, PROJECT_ID or os.getenv("PROJECT_ID", ""))
    if wf_cancel is not None and wf_cancel["outcome"] == wfx.FAILED:
        logger.error(f"Abort of trace '{trace_id}' refused: its workflow execution {wf_cancel['name']!r} could not be "
                     f"cancelled ({wf_cancel['reason']}): {wf_cancel['detail']}")
        try:
            doc_ref.set({"abort_attempt": {"at": now_iso, "by": caller_email, "workflow_cancel": {
                "name": wf_cancel["name"], "outcome": wf_cancel["outcome"], "reason": wf_cancel["reason"],
                "detail": wf_cancel["detail"], "state": wf_cancel["state"]}}}, merge=True)
        except Exception as rec_err:  # noqa: BLE001 - the 502 below is the answer either way
            logger.error(f"Could not record the abort attempt on trace '{trace_id}': {rec_err}")
        raise HTTPException(status_code=502, detail={
            "code": wf_cancel["reason"],
            "message": (f"Run '{trace_id}' was NOT aborted: its Cloud Workflows execution could not be cancelled "
                        f"({wf_cancel['reason']}) and may still be running. {wf_cancel['detail'] or ''}").strip(),
            "workflow_cancel": wf_cancel,
        })
    if wf_cancel is not None:
        logger.info(f"Workflow execution {wf_cancel['name']!r} for trace '{trace_id}': {wf_cancel['outcome']}")
    wf_cancel_status = None if wf_cancel is None else wfx.OK

    record = {
        "status": "ABORTED",
        "error_message": f"Mission aborted by operator ({caller_email})",
        "ended_at": now_iso,
        "current_stage": "ABORTED",
    }
    if wf_cancel is not None:
        record["workflow_cancel"] = {"outcome": wf_cancel["outcome"], "reason": wf_cancel["reason"],
                                     "detail": wf_cancel["detail"]}
    doc_ref.set(record, merge=True)
    build_queue.release_after_abort(db, trace_id)   # BUILD-ADMISSION-QUEUE: its slot / wait / queue place goes now

    # Record audit log under workload if available
    try:
        w_audit_ref = db.collection("workloads").document(product_id).collection("audit_logs").document()
        w_audit_ref.set({
            "action": "PIPELINE_EXECUTION_ABORTED",
            "operator_email": caller_email,
            "trace_id": trace_id,
            "reason": "Mission aborted via Flight Deck Cockpit",
            "timestamp": now_iso,
        })
    except Exception as audit_err:
        logger.warning(f"Could not write audit log for aborted trace '{trace_id}': {audit_err}")

    logger.info(f"Pipeline execution '{trace_id}' aborted by {caller_email} "
                f"(workflow cancel: {wf_cancel['outcome'] if wf_cancel else 'no bound execution'})")
    message = f"Pipeline execution '{trace_id}' has been successfully aborted."
    return {
        "status": "ABORTED",
        "trace_id": trace_id,
        "product_id": product_id,
        "aborted_by": caller_email,
        "aborted_at": now_iso,
        "workflow_cancel_status": wf_cancel_status,
        "workflow_cancel": wf_cancel,
        "message": message,
    }


@router.get("/api/workloads/{product_id}/logs", response_model=WorkloadLogsResponse, dependencies=[require(WORKLOAD())])
def get_workload_logs(
    product_id: str,
    request: Request,
    severity: Optional[str] = None,
    limit: int = 100,
):
    """RT14-31: the workload's own runtime logs (its child project) and the platform pipeline's logs about it (host,
    exact product_id), each entry labelled with its `log_source`. A source that cannot be read is listed in
    `source_errors` (typed); when no requested source can be read the answer is 502 LOGS_UNAVAILABLE."""
    verify_workload_access(product_id, request)
    is_platform = product_id in PLATFORM_PSEUDO_WORKLOADS
    host = PROJECT_ID or os.getenv("PROJECT_ID", "")
    proj_id = host if is_platform else ""
    record_failure: List[Dict[str, Any]] = []
    if not is_platform:
        if not db:
            record_failure.append({"source": LOG_SOURCE_WORKLOAD, "project": "", "code": "WORKLOAD_RECORD_UNREADABLE",
                                   "detail": "Firestore unavailable: the workload's project cannot be resolved."})
        else:
            try:
                w_doc = db.collection("workloads").document(product_id).get()
            except Exception as e:  # noqa: BLE001 - typed below
                logger.error(f"Could not read workload {product_id} for its logs: {e}")
                w_doc = None
                record_failure.append({"source": LOG_SOURCE_WORKLOAD, "project": "",
                                       "code": "WORKLOAD_RECORD_UNREADABLE", "detail": type(e).__name__})
            if w_doc is not None:
                if not w_doc.exists:
                    raise HTTPException(status_code=404, detail=f"Workload '{product_id}' not found.")
                recorded = (w_doc.to_dict() or {}).get("project_id")
                proj_id = recorded.strip() if isinstance(recorded, str) else ""

    sources = ((LOG_SOURCE_PLATFORM,) if is_platform else
               ((LOG_SOURCE_PLATFORM_PIPELINE,) if record_failure else
                (LOG_SOURCE_WORKLOAD, LOG_SOURCE_PLATFORM_PIPELINE)))
    try:
        logs, applied_filter, failures = collect_workload_logs(
            product_id=product_id,
            project_id_val=proj_id,
            severity=severity,
            limit=max(1, min(limit, 100)),
            sources=sources,
        )
    except LogSeverityInvalid:
        raise HTTPException(status_code=422, detail={
            "error_class": "LOG_SEVERITY_INVALID", "stage": LOGS_STAGE,
            "detail": f"severity must be ALL or one of {list(LOG_SEVERITIES)}."})
    failures = record_failure + failures
    if failures and not logs and len(failures) >= len(sources) + len(record_failure):
        raise HTTPException(status_code=502, detail=WorkloadLogsUnavailable(failures).http_detail())

    return WorkloadLogsResponse(
        product_id=product_id,
        project_id=proj_id,
        total_count=len(logs),
        log_filter=applied_filter,
        logs=logs,
        source_errors=failures,
    )


@router.get("/api/pipeline/overview", response_model=PipelineOverviewResponse, dependencies=[require(ADMIN)])
def get_pipeline_overview():
    target_project = PROJECT_ID or os.getenv("PROJECT_ID", "")
    return build_pipeline_overview(target_project)


@router.get("/api/pipeline/agents", response_model=List[AgentStatusSummary], dependencies=[require(ADMIN)])
def get_pipeline_agents():
    """Platform agent roster. ADMIN (code RT F2): each agent's current_task/backlog carries feature requests of ALL
    workloads (title, description, workload, project, repo), exactly like /api/pipeline/overview, and building it
    reconciles feature_requests (Firestore writes). The dashboard never calls this route (it reads the ADMIN-only
    overview), so no role's dashboard changes."""
    overview = get_pipeline_overview()
    return overview.agents


@router.get("/api/diagram/{product_id}", response_model=ArchitectureDiagramResponse, dependencies=[require(WORKLOAD())])
def get_architecture_diagram(product_id: str, request: Request):
    verify_workload_access(product_id, request)
    workload_data = {}
    build_plan_data = {}
    if db:
        try:
            doc = db.collection("workloads").document(product_id).get()
            if doc.exists:
                workload_data = doc.to_dict() or {}
        except Exception:
            pass

        try:
            bp_stream = (
                db.collection("workloads")
                .document(product_id)
                .collection("build_plans")
                .order_by("created_at", direction=firestore.Query.DESCENDING)
                .limit(1)
                .stream()
            )
            for b in bp_stream:
                build_plan_data = b.to_dict() or {}
                break
            if not build_plan_data:
                bp_root = db.collection("build_plans").where("product_id", "==", product_id).limit(1).stream()
                for b in bp_root:
                    build_plan_data = b.to_dict() or {}
                    break
        except Exception:
            pass

    return diagram_engine.generate_mermaid_diagram(product_id, workload_data, build_plan_data)


def _approved_quota_regions() -> List[str]:
    """FD-7M-a: the default regions of the quota view = Settings > Approved Deployable Regions (lenient display read)."""
    from shared.settings import approved_deployable_regions, get_platform_settings
    return approved_deployable_regions(get_platform_settings().orchestration)


@router.get("/api/quotas/regional/{project_id}", dependencies=[require(WORKLOAD_BY_PROJECT())])
def get_regional_quotas(project_id: str, regions: Optional[str] = None):
    """
    Returns regional quota headroom and active in-flight claims for the target project. FD-7M-a: without `regions`,
    the install's approved deployable regions (Settings; display read: the last good settings, else the defaults).
    """
    try:
        from shared.quota_inspector import CloudQuotaInspector
    except ImportError:
        try:
            from apps.control_center.shared.quota_inspector import CloudQuotaInspector
        except ImportError:
            return {"status": "DEGRADED", "regions": {}, "global": {}, "active_claims": {}}

    inspector = CloudQuotaInspector(db_client=db)
    target_regions = [r.strip() for r in regions.split(",") if r.strip()] if regions else _approved_quota_regions()
    snapshot = inspector.harvest_quota_snapshot(project_id=project_id, regions=target_regions)
    return snapshot



# ==============================================================================
# Autonomous Mission Debrief & Self-Healing Ledger (AAR) Endpoints
# ==============================================================================

def harvest_self_healing_markers(
    logs_list: List[Dict[str, Any]],
    stages_dict: Dict[str, Any],
) -> List[SelfHealingIntervention]:
    """Deterministically extracts ground-truth self-healing interventions from logs and stage metadata."""
    interventions: List[SelfHealingIntervention] = []
    seen_keys = set()

    # 1. Harvest from stage metadata
    arch_stage = stages_dict.get("architect") or {}
    arch_details = arch_stage.get("details") or {}
    consensus = arch_details.get("architect_consensus") or {}
    if consensus.get("remediation_performed"):
        k = "CONSENSUS_AUDIT::Targeted DAG Patch"
        if k not in seen_keys:
            seen_keys.add(k)
            interventions.append(
                SelfHealingIntervention(
                    category="CONSENSUS_AUDIT",
                    component="Architecture Task DAG",
                    issue_detected="Lead Architect draft plan had structural or invariant critique findings",
                    autonomous_cure=consensus.get("remediation_diff_summary") or "Targeted DAG Patch (N=1) auto-remediated invariant violations",
                )
            )

    # 2. Harvest from log markers
    for lg in logs_list:
        msg = lg.get("message") or ""

        # Packaging sanitization
        if "Physical package sanitization: generated missing '__init__.py'" in msg:
            m = re.search(r"in '([^']+)'", msg)
            comp = m.group(1) if m else "Python package"
            k = f"PACKAGING::{comp}"
            if k not in seen_keys:
                seen_keys.add(k)
                interventions.append(
                    SelfHealingIntervention(
                        category="PACKAGING",
                        component=comp,
                        issue_detected="Directory lacked required __init__.py module descriptor for Google Cloud Buildpacks",
                        autonomous_cure="Synthesized valid __init__.py package descriptor during source pre-packaging",
                    )
                )

        # Dynamic API enablement
        if "Dynamic API enablement completed on" in msg or "Dynamically ensuring" in msg:
            m = re.search(r"batch: (\[.*?\])", msg)
            batch = m.group(1) if m else "14 required Google Cloud APIs"
            k = f"GCP_APIS::{batch}"
            if k not in seen_keys:
                seen_keys.add(k)
                interventions.append(
                    SelfHealingIntervention(
                        category="GCP_APIS",
                        component="Google Cloud Resource Manager",
                        issue_detected="Workload IaC required Google Cloud APIs that were not pre-activated",
                        autonomous_cure=f"Dynamically enabled API batch: {batch}",
                    )
                )

        # CIDR auto-healing
        if "Self-healed invalid CIDR declaration" in msg or "Autonomous CIDR self-healing" in msg:
            m = re.search(r"declaration:\s*(.*)", msg)
            det = m.group(1) if m else "unnormalized IP CIDR"
            k = f"NETWORKING_CIDR::{det[:40]}"
            if k not in seen_keys:
                seen_keys.add(k)
                interventions.append(
                    SelfHealingIntervention(
                        category="NETWORKING_CIDR",
                        component="variables.tf / main.tf",
                        issue_detected="CIDR parameter failed Google Cloud VPC or RFC 1918 formatting rules",
                        autonomous_cure=f"Self-healed invalid CIDR declaration: {det}",
                    )
                )

        # 409 Resource adoption
        if "Universal 409 Resource Adoption Engine" in msg or "adopted existing GCP" in msg:
            k = "RESOURCE_ADOPTION::Universal 409"
            if k not in seen_keys:
                seen_keys.add(k)
                interventions.append(
                    SelfHealingIntervention(
                        category="RESOURCE_ADOPTION",
                        component="OpenTofu State / GCP Resource",
                        issue_detected="Resource pre-existed in Google Cloud project outside OpenTofu state (HTTP 409 Conflict)",
                        autonomous_cure="Imported existing GCP resource directly into state without destroying or recreating",
                    )
                )

        # FD-55 W6c (register FD55-W6c): the two apply-side markers harvested here ("Auto-cured self-referential
        # block in" and "Pre-apply reconciler populated missing/empty variable") are gone with their healers (A47
        # self-reference rewrite, A42 tfvars reconciler), so they are no longer counted as self-healing.

    return interventions


# The deterministic debrief speaks of OpenTofu and offers Fast-Path only for this exact recorded stage.
AAR_TERRAFORM_STAGE = "terraform"
# A real relaunch mode: the Control Center's own failure-aware routing picks the restart point.
AAR_AUTO_MODE = "AUTO"
# DEPLOY-FAILURE-OWNER-ROUTER (owner 11-13): the terraform server's typed owner classes for a failed deploy
# (mcp-servers/terraform/deploy_failure_router.ERROR_CLASS_BY_OWNER; parity test tests/test_deploy_failure_owner_router.py)
# with the deterministic report's recommended mode and action.
DEPLOY_ROUTER_REMEDIATION = {
    "PLATFORM_DEFECT": (None, "A StackVend platform defect: the failing file is the platform's (named in the error). "
                              "A relaunch fails the same way until the platform is fixed; report it."),
    "OPERATOR_REQUIRED": (None, "The failing file is a person's (named in the error): change it in the repository, "
                                "then relaunch."),
    "PROVIDER_TRANSIENT": ("DEPLOY_ONLY", "The failed plan passed when it was run again (that plan applied "
                                          "nothing). Re-run the deploy with Fast-Path Deploy."),
    "DEPLOY_FAILURE_UNATTRIBUTED": (None, "Nothing typed names who can fix this failure, so it was not sent to the "
                                          "developer. Read the engine error, then choose how to relaunch."),
}
DEPLOY_ROUTER_FAILURE_CLASSES = frozenset(DEPLOY_ROUTER_REMEDIATION)


# RT S9 (STAGE-DEADLINE / LONG-STAGE-CALLBACK / STAGE-JOB-RUNNER): what an operator does about the typed stage-stop
# classes (exact error_class keys from the gateway's gate_errors.ErrorClass and the workflow; never read from the error
# text). None of them is a defect in the specification: relaunch (AUTO restarts from the stopped stage).
_STAGE_STOP_ACTIONS: Dict[str, str] = {
    "STAGE_DEADLINE_EXCEEDED": "The stage ran out of its time budget; nothing was committed after that point. Relaunch "
                               "the workload (AUTO restarts from this stage). If it happens again, the model was slow: "
                               "try again later or pick a faster model in Settings.",
    "STAGE_TIMEOUT": "The workflow waited the stage's full budget and no answer arrived. Relaunch the workload (AUTO "
                     "restarts from this stage).",
    "STAGE_INTERRUPTED": "The stage's job was stopped before it answered (task timeout, cancel or crash); nothing was "
                         "committed after that point. Relaunch the workload (AUTO restarts from this stage).",
    "STAGE_ABANDONED": "The stage stopped because its run ended, a newer run took over or the emergency stop was on; "
                       "nothing was committed after that point. Relaunch the workload once the emergency stop is off.",
    "CONTRACT_VIOLATION": "A platform component answered outside its contract (a platform defect, not your "
                          "specification). Relaunch once; if it repeats, report it with this trace id.",
}


def _aar_failed_stage(failed_stage: Any, stages_dict: Dict[str, Any]) -> Optional[str]:
    """The stage a failed run stopped at: the run's typed `failed_stage`, else the one stage recorded as FAILED, else
    None (not recorded, or more than one candidate: never a guess)."""
    if isinstance(failed_stage, str) and failed_stage:
        return failed_stage
    failed = [name for name, info in stages_dict.items() if isinstance(info, dict) and info.get("status") == "FAILED"]
    return failed[0] if len(failed) == 1 else None


# AAR-SETTINGS-MODEL (DEFAULT-MODEL-GEMINI-4-CARBON follow-up, owner 11-11 "yes to all three"): the report is written
# by the Control Center Assistant Model's cascade (models.assistant_model + models.fallback_models): the report is a
# Control Center summary for operators, made in the Control Center like the assistant's answers, so it uses the
# Control Center's own model setting. Each request is built by its model's family rules with the "auxiliary" role
# (shared.gemini_model_config): a Gemini 4 model gets its thinking level and no thinking budget or temperature. It used
# to call the retired gemini-2.5-flash / gemini-2.0-flash ids through the evaluator's bare client.
AAR_MODEL_ROLE = "assistant"
AAR_MODEL_TIMEOUT_SECONDS = 60.0
AAR_MODEL_UNAVAILABLE = "AAR_MODEL_UNAVAILABLE"        # no model client could be built
AAR_MODEL_CALL_FAILED = "AAR_MODEL_CALL_FAILED"        # every model in the cascade failed or answered invalid JSON
AAR_DETERMINISTIC_ENGINE = "deterministic-rules"


class AARModelFailure(Exception):
    """Typed: no model of the cascade wrote the report. `failures` = [{model, error}] (Google's message, trimmed, no
    credential). The caller writes the deterministic report from recorded facts and stores this code with it."""

    def __init__(self, code: str, failures: List[Dict[str, str]]):
        self.code = code
        self.failures = failures
        super().__init__(f"{code}: " + "; ".join(f"{f.get('model')}: {f.get('error')}" for f in failures))

    def as_record(self) -> Dict[str, Any]:
        return {"code": self.code, "models": [dict(f) for f in self.failures]}


def _aar_json(text: Any) -> Dict[str, Any]:
    """The JSON object a model answered (a ```json fence is allowed); ValueError for anything else."""
    clean = str(text or "").strip()
    if "```json" in clean:
        clean = clean.split("```json")[1].split("```")[0].strip()
    elif "```" in clean:
        clean = clean.split("```")[1].split("```")[0].strip()
    data = json.loads(clean)
    if not isinstance(data, dict):
        raise ValueError(f"the answer is a JSON {type(data).__name__}, not an object")
    return data


_AAR_SECTIONS = (("root_cause", RootCauseAnalysis), ("blast_radius", BlastRadius), ("remediation", RemediationPlan))


def _aar_validated(data: Dict[str, Any]) -> Dict[str, Any]:
    """RT D1: a model's report answer checked against the report schema INSIDE the cascade, so a malformed answer is
    that model's failure (the next model is tried), never a 500 and never a deterministic report stored under the
    model's name. Returns {executive_summary: str | None, root_cause / blast_radius / remediation: the schema object
    or None}. ValueError when the answer has no report content (e.g. {}), executive_summary is not a string, a
    section is not an object, or a section does not validate."""
    summary = data.get("executive_summary")
    if summary is not None and not isinstance(summary, str):
        raise ValueError(f"executive_summary is a {type(summary).__name__}, not a string")
    out: Dict[str, Any] = {"executive_summary": summary.strip() if isinstance(summary, str) and summary.strip()
                           else None}
    for key, schema in _AAR_SECTIONS:
        value = data.get(key)
        if value is None:
            out[key] = None
            continue
        if not isinstance(value, dict):
            raise ValueError(f"{key} is a {type(value).__name__}, not an object")
        value = dict(value)
        if key == "remediation" and value.get("recommended_mode") == "ARCHITECT_AND_DEV":
            value["recommended_mode"] = "FULL"   # legacy mode name
        out[key] = schema(**value)               # pydantic ValidationError (a ValueError) on a bad field
    if out["executive_summary"] is None and all(out[key] is None for key, _ in _AAR_SECTIONS):
        raise ValueError("the answer has no report content (no executive_summary and no section)")
    return out


def _aar_model_cascade() -> List[str]:
    from shared.settings import get_model_cascade_for_agent
    return [m for m in get_model_cascade_for_agent(AAR_MODEL_ROLE) if m]


def aar_model_report(llm_prompt: str, client_factory: Any = None, cascade: Optional[List[str]] = None
                     ) -> Tuple[Dict[str, Any], str]:
    """(checked report, model id) from the first model of the cascade whose answer is a JSON object that passes the
    report schema (_aar_validated: the sections are schema objects). Raises AARModelFailure
    (AAR_MODEL_UNAVAILABLE / AAR_MODEL_CALL_FAILED) when none does; never a made-up answer. The client is the one the
    Settings live check builds (services/model_check.default_client_factory: the AI Studio key, else Vertex AI on
    GEMINI_LOCATION), with a request timeout."""
    from google.genai import types
    from services import model_check
    from shared.gemini_model_config import Purpose, adapt_generate_config_kwargs
    models = list(cascade) if cascade is not None else _aar_model_cascade()
    factory = client_factory or model_check.default_client_factory
    try:
        client = factory(AAR_MODEL_TIMEOUT_SECONDS)
    except Exception as e:  # noqa: BLE001 - typed below; the message carries no credential (model_check.error_text)
        raise AARModelFailure(AAR_MODEL_UNAVAILABLE, [{"model": "", "error": model_check.error_text(e)}]) from e
    failures: List[Dict[str, str]] = []
    for model in models:
        try:
            config = types.GenerateContentConfig(**adapt_generate_config_kwargs(
                model, Purpose.AUXILIARY, {"response_mime_type": "application/json", "temperature": 0.2},
                types=types))
            response = client.models.generate_content(model=model, contents=llm_prompt, config=config)
            return _aar_validated(_aar_json(getattr(response, "text", None))), model
        except Exception as e:  # noqa: BLE001 - this model failed: the next one is tried, the reason is kept
            failures.append({"model": model, "error": model_check.error_text(e)})
    raise AARModelFailure(AAR_MODEL_CALL_FAILED, failures or [{"model": "", "error": "no model configured"}])


def synthesize_after_action_report(
    trace_id: str,
    product_id: str,
    status: str,
    harvested_interventions: List[SelfHealingIntervention],
    error_message: Optional[str],
    stages_dict: Dict[str, Any],
    outputs_dict: Dict[str, Any],
    cloud_logs: List[Dict[str, Any]],
    failed_stage: Optional[str] = None,
    error_class: Optional[str] = None,
) -> AfterActionReport:
    """Synthesizes structured After-Action Report via Gemini with guaranteed deterministic fallback."""
    now_iso = datetime.now(timezone.utc).isoformat()
    service_urls: List[str] = []
    if outputs_dict.get("service_url"):
        service_urls.append(str(outputs_dict["service_url"]))
    for k, v in outputs_dict.items():
        if "url" in k.lower() and isinstance(v, str) and v.startswith("http") and v not in service_urls:
            service_urls.append(v)

    if status == "SUCCEEDED":
        outcome_type = (
            AAROutcomeType.SUCCESS_WITH_HEALING
            if harvested_interventions
            else AAROutcomeType.SUCCESS_CLEAN
        )
    else:
        outcome_type = AAROutcomeType.FAILURE_RECOVERABLE

    llm_prompt = f"""
You are the Principal Staff SRE and Systems Architect for StackVend.
Generate a structured, executive-ready After-Action Report (AAR) for the following mission execution:

Mission Trace ID: {trace_id}
Target Workload: {product_id}
Final Status: {status}
Terminal Error (if any): {error_message or 'None'}
Identified Autonomous Self-Healing Interventions: {json.dumps([i.model_dump() for i in harvested_interventions], indent=2)}
Deployed Service URLs (no health probe ran; do not claim they are healthy or serving): {json.dumps(service_urls)}
Pipeline Stages: {json.dumps(stages_dict, default=str)[:2000]}

Respond ONLY with a valid JSON object matching this schema:
{{
  "executive_summary": "1-2 sentence high-level summary of what was accomplished or why it failed",
  "root_cause": {{
    "failing_component": "File or resource name if failed, else null",
    "failure_class": "e.g. TYPE_SEMANTIC_MISMATCH, IAM_PERMISSION_DENIED, QUOTA_EXHAUSTED, or null if succeeded",
    "technical_explanation": "Explanation of failure or null"
  }},
  "blast_radius": {{
    "provisioned_resources": ["list of resources provisioned"],
    "failed_resource": "resource that failed or null",
    "blocked_resources": ["downstream blocked resources"]
  }},
  "remediation": {{
    "recommended_mode": "One of: FULL, DEPLOY_ONLY, RESUME_DEVELOPER, or null if succeeded",
    "immediate_action": "Actionable instructions for operator or null",
    "preventative_guidance": "Advice to prevent recurrence or null"
  }}
}}
"""

    report_data = None
    model_used = AAR_DETERMINISTIC_ENGINE
    model_failure: Optional[Dict[str, Any]] = None

    try:
        report_data, model_used = aar_model_report(llm_prompt)
    except AARModelFailure as e:
        # Typed and recorded on the report: the report below is the deterministic one, written only from the run's
        # recorded stages, error and outputs, and labelled as such (model_used = deterministic-rules).
        model_failure = e.as_record()
        logger.error(f"{e.code}: no model wrote the After-Action Report for '{trace_id}' ({e}); the deterministic "
                     "report is stored with this code")

    if report_data:
        # RT D1: report_data was checked inside the cascade (_aar_validated): its sections are schema objects
        exec_sum = report_data.get("executive_summary") or ("Mission completed successfully" if status == "SUCCEEDED" else f"Mission failed: {error_message}")
        failed_run = status != "SUCCEEDED"
        root_cause = report_data.get("root_cause") if failed_run else None
        blast_radius = report_data.get("blast_radius") if failed_run else None
        remediation = report_data.get("remediation") if failed_run else None
        if failed_run and error_class in DEPLOY_ROUTER_FAILURE_CLASSES:
            # DEPLOY-FAILURE-OWNER-ROUTER: the run's typed owner class is the failure class shown, whatever the model
            # wrote (a platform defect is never shown as a code defect)
            root_cause = (root_cause.model_copy(update={"failure_class": error_class})
                          if isinstance(root_cause, RootCauseAnalysis)
                          else RootCauseAnalysis(failure_class=error_class, technical_explanation=error_message))
    else:
        # Deterministic Rule-Based Fallback
        if status == "SUCCEEDED":
            if harvested_interventions:
                exec_sum = f"Workload '{product_id}' provisioned successfully with {len(harvested_interventions)} autonomous self-healing interventions. All services deployed (no health probe ran)."
            else:
                exec_sum = f"Workload '{product_id}' successfully provisioned. All declared cloud resources deployed (no health probe ran)."
            root_cause = None
            blast_radius = None
            remediation = None
        else:
            err_str = str(error_message or "Unknown failure")
            stage = _aar_failed_stage(failed_stage, stages_dict)
            if stage != AAR_TERRAFORM_STAGE:
                # Only the recorded stage and typed class are stated. Fast-Path re-applies merged infrastructure code,
                # which a run that stopped before deployment may not have.
                stage_label = f"Pipeline stage '{stage}'" if stage else "Pipeline (failed stage not recorded)"
                exec_sum = f"Run stopped at stage '{stage}': {err_str[:160]}" if stage else f"Run stopped: {err_str[:160]}"
                root_cause = RootCauseAnalysis(
                    failing_component=stage_label,
                    failure_class=error_class if isinstance(error_class, str) and error_class else None,
                    technical_explanation=err_str,
                )
                blast_radius = BlastRadius(provisioned_resources=[], failed_resource=stage_label, blocked_resources=[])
                remediation = RemediationPlan(
                    recommended_mode=AAR_AUTO_MODE,
                    immediate_action=_STAGE_STOP_ACTIONS.get(error_class if isinstance(error_class, str) else "",
                                                             "Read the error for this stage and fix its cause, then "
                                                             "relaunch the workload. AUTO chooses where the run "
                                                             "restarts from this failure."),
                    preventative_guidance=None,
                )
            elif error_class in DEPLOY_ROUTER_FAILURE_CLASSES:
                # DEPLOY-FAILURE-OWNER-ROUTER: the terraform server named the owner (typed); no class is guessed from
                # the text, and no automatic mode is offered for a failure a rebuild cannot change.
                rec_mode, action = DEPLOY_ROUTER_REMEDIATION[error_class]
                exec_sum = f"Deployment stopped ({error_class}): {err_str[:160]}"
                root_cause = RootCauseAnalysis(failing_component="OpenTofu IaC Engine", failure_class=error_class,
                                               technical_explanation=err_str)
                blast_radius = BlastRadius(provisioned_resources=[], failed_resource="Terraform deployment",
                                           blocked_resources=[])
                remediation = RemediationPlan(recommended_mode=rec_mode, immediate_action=action,
                                              preventative_guidance=None)
            else:
                f_class = "INFRASTRUCTURE_FAILURE"
                rec_mode = "DEPLOY_ONLY"
                if "doesn't match regexp" in err_str or "invalid value" in err_str:
                    f_class = "TYPE_SEMANTIC_MISMATCH"
                    rec_mode = "FULL"
                elif "quota" in err_str.lower():
                    f_class = "QUOTA_EXHAUSTED"
                    rec_mode = "DEPLOY_ONLY"
                elif "permission" in err_str.lower() or "403" in err_str:
                    f_class = "IAM_PERMISSION_DENIED"
                    rec_mode = "DEPLOY_ONLY"

                exec_sum = f"Deployment halted at terminal stage: {err_str[:160]}"
                root_cause = RootCauseAnalysis(
                    failing_component="OpenTofu IaC Engine",
                    failure_class=f_class,
                    technical_explanation=err_str,
                )
                blast_radius = BlastRadius(
                    provisioned_resources=[],
                    failed_resource="Terraform apply operation",
                    blocked_resources=["Downstream Cloud Run ingress"],
                )
                remediation = RemediationPlan(
                    recommended_mode=rec_mode,
                    immediate_action=f"Re-dispatch mission using {rec_mode} mode to remediate defect.",
                    preventative_guidance="Verify schema contracts and naming conventions.",
                )

    return AfterActionReport(
        trace_id=trace_id,
        product_id=product_id,
        status=status,
        outcome_type=outcome_type,
        executive_summary=exec_sum,
        self_healing_interventions=harvested_interventions,
        root_cause=root_cause,
        blast_radius=blast_radius,
        remediation=remediation,
        total_resources_provisioned=len(outputs_dict) if outputs_dict else 0,
        live_service_urls=service_urls,
        generated_at=now_iso,
        model_used=model_used,
        model_failure=model_failure,
    )


@router.get("/api/pipeline/executions/{trace_id}/aar", response_model=AARResponse, dependencies=[require(TRACE())])
def get_execution_aar(trace_id: str, request: Request = None):
    """Retrieves cached After-Action Report (AAR) for an execution trace."""
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")
    doc = db.collection("pipeline_executions").document(trace_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Execution trace '{trace_id}' not found")
    data = doc.to_dict() or {}
    aar_data = data.get("after_action_report")
    if not aar_data:
        return AARResponse(has_aar=False, aar=None)
    try:
        aar_obj = AfterActionReport(**aar_data)
        return AARResponse(has_aar=True, aar=aar_obj)
    except Exception as e:
        logger.warning(f"Error parsing cached AAR for '{trace_id}': {e}")
        return AARResponse(has_aar=False, aar=None)


@router.post("/api/pipeline/executions/{trace_id}/aar", response_model=AARResponse, dependencies=[require(TRACE(manager=True))])
def generate_execution_aar(trace_id: str, request: Request = None):
    """Generates, persists, and returns the After-Action Report for an execution trace."""
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")
    doc_ref = db.collection("pipeline_executions").document(trace_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Execution trace '{trace_id}' not found")
    data = doc.to_dict() or {}

    # If already cached, return immediately
    existing_aar = data.get("after_action_report")
    if existing_aar:
        try:
            return AARResponse(has_aar=True, aar=AfterActionReport(**existing_aar))
        except Exception:
            pass

    status = data.get("status", "FAILED")
    product_id = data.get("product_id", "workload")
    stages_dict = data.get("stages") or {}
    outputs_dict = data.get("outputs") or {}
    error_message = data.get("error") or data.get("error_message")
    if not error_message:
        for st_name, st_info in stages_dict.items():
            if isinstance(st_info, dict) and st_info.get("status") == "FAILED":
                error_message = st_info.get("error") or st_info.get("summary")
                break

    # Fetch correlated logs
    # RT14-31: the self-healing markers come from the platform pipeline's own logs (host, exact product_id). When they
    # cannot be read, no report is built (or cached) from missing evidence: 502 LOGS_UNAVAILABLE, retry later.
    try:
        cloud_logs_res, _ = fetch_workload_logs_from_cloud_logging(
            product_id=product_id,
            project_id_val=data.get("project_id", ""),
            limit=100,
            sources=(LOG_SOURCE_PLATFORM_PIPELINE,),
        )
    except WorkloadLogsUnavailable as logs_err:
        raise HTTPException(status_code=502, detail=logs_err.http_detail())
    logs_raw = [{"message": l.message, "severity": l.severity} for l in cloud_logs_res]

    # Harvest interventions
    harvested = harvest_self_healing_markers(logs_raw, stages_dict)

    # Synthesize AAR
    aar_report = synthesize_after_action_report(
        trace_id=trace_id,
        product_id=product_id,
        status=status,
        harvested_interventions=harvested,
        error_message=error_message,
        stages_dict=stages_dict,
        outputs_dict=outputs_dict,
        cloud_logs=logs_raw,
        failed_stage=data.get("failed_stage"),
        error_class=data.get("error_class"),
    )

    # Persist directly into Firestore
    try:
        doc_ref.set({"after_action_report": aar_report.model_dump()}, merge=True)
    except Exception as save_err:
        logger.warning(f"Could not persist AAR to Firestore for '{trace_id}': {save_err}")

    return AARResponse(has_aar=True, aar=aar_report)


@router.get("/api/workloads/{product_id}/latest-aar", response_model=AARResponse, dependencies=[require(WORKLOAD())])
def get_workload_latest_aar(product_id: str, request: Request = None):
    """Retrieves the latest After-Action Report (AAR) for a workload across its executions."""
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    try:
        col = db.collection("pipeline_executions")
        query = (
            col.where("product_id", "==", product_id)
            .order_by("started_at", direction=firestore.Query.DESCENDING)
            .limit(1)
        )
        docs = list(query.stream())
    except Exception:
        col = db.collection("pipeline_executions")
        docs = [d for d in col.where("product_id", "==", product_id).stream()]
        docs.sort(key=lambda d: (d.to_dict() or {}).get("started_at", ""), reverse=True)
        docs = docs[:1]

    if not docs:
        return AARResponse(has_aar=False, aar=None, latest_trace_id=None, latest_status=None)

    data = docs[0].to_dict() or {}
    trace_id = docs[0].id
    status = data.get("status")
    aar_data = data.get("after_action_report")
    if aar_data:
        try:
            return AARResponse(has_aar=True, aar=AfterActionReport(**aar_data), latest_trace_id=trace_id, latest_status=status)
        except Exception as e:
            logger.warning(f"Error parsing cached AAR for workload '{product_id}': {e}")

    return AARResponse(has_aar=False, aar=None, latest_trace_id=trace_id, latest_status=status)


@router.post("/api/workloads/{product_id}/latest-aar", response_model=AARResponse, dependencies=[require(WORKLOAD(manager=True))])
def generate_workload_latest_aar(product_id: str, request: Request = None):
    """Generates the After-Action Report for the latest execution of a workload."""
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    try:
        col = db.collection("pipeline_executions")
        query = (
            col.where("product_id", "==", product_id)
            .order_by("started_at", direction=firestore.Query.DESCENDING)
            .limit(1)
        )
        docs = list(query.stream())
    except Exception:
        col = db.collection("pipeline_executions")
        docs = [d for d in col.where("product_id", "==", product_id).stream()]
        docs.sort(key=lambda d: (d.to_dict() or {}).get("started_at", ""), reverse=True)
        docs = docs[:1]

    if not docs:
        raise HTTPException(status_code=404, detail=f"No execution runs found for workload '{product_id}'")

    latest_trace_id = docs[0].id
    resp = generate_execution_aar(trace_id=latest_trace_id, request=request)
    resp.latest_trace_id = latest_trace_id
    resp.latest_status = (docs[0].to_dict() or {}).get("status")
    return resp


@router.get("/api/workloads/{product_id}/executions", response_model=List[WorkloadExecutionRun], dependencies=[require(WORKLOAD())])
def get_workload_executions(product_id: str, limit: int = 20, request: Request = None):
    """Retrieves historical pipeline execution runs for a workload, including AAR metadata."""
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    try:
        col = db.collection("pipeline_executions")
        query = (
            col.where("product_id", "==", product_id)
            .order_by("started_at", direction=firestore.Query.DESCENDING)
            .limit(limit)
        )
        docs = list(query.stream())
    except Exception:
        col = db.collection("pipeline_executions")
        docs = [d for d in col.where("product_id", "==", product_id).stream()]
        docs.sort(key=lambda d: str((d.to_dict() or {}).get("started_at", "") or (d.to_dict() or {}).get("created_at", "")), reverse=True)
        docs = docs[:limit]

    results: List[WorkloadExecutionRun] = []
    for d in docs:
        data = d.to_dict() or {}
        trace_id = d.id
        status = data.get("status") or "UNKNOWN"
        started_at = data.get("started_at") or data.get("created_at")
        completed_at = data.get("completed_at")
        feature_title = data.get("feature_title")
        request_id = data.get("request_id")
        execution_mode = data.get("execution_mode")

        aar_data = data.get("after_action_report") or {}
        has_aar = bool(aar_data)
        outcome_type = aar_data.get("outcome_type")
        healing_count = len(aar_data.get("self_healing_interventions") or [])

        results.append(WorkloadExecutionRun(
            trace_id=trace_id,
            started_at=started_at,
            completed_at=completed_at,
            status=status,
            feature_title=feature_title,
            request_id=request_id,
            execution_mode=execution_mode,
            has_aar=has_aar,
            outcome_type=outcome_type,
            healing_count=healing_count,
        ))

    return results

