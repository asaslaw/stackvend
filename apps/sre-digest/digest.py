"""
StackVend: sre-telemetry-digest-job (C33) - weekly warning-log and latency digest from REAL telemetry.

Wave 2 lane 14 PR-3 (plan docs/planning/wave2-lane14-core-services-plan.md section 2.4, section 2.0; register row
L14-m). Before PR-3 the job scored hardcoded sample logs and metrics ("96 EXCELLENT") and saved that as the weekly
digest; nothing here is sampled, defaulted or floored any more:

- Scope: every ``ACTIVE`` ledger workload (``workloads``, not the platform pseudo-workload) whose identity check
  passes (C33/C77).
- Data: Cloud Logging v2 ``entries:list`` (``severity>=WARNING`` in the window, paged, hard cap) and Cloud Monitoring
  v3 ``timeSeries.list`` on ``run.googleapis.com/request_latencies`` (p95 and request count per Cloud Run service) for
  this window and the previous one. REST via ``AuthorizedSession`` (no gcloud, AGENTS.md invariant 7).
- Per workload ``OK | NO_DATA | NO_BASELINE | ERROR`` (or ``REFUSED:<code>`` when the identity check refuses it).
  The score is computed from real data only (no floor); with no data there is no score. A latency regression needs
  at least ``DIGEST_MIN_SAMPLES`` requests in BOTH windows, else that service is ``NO_BASELINE``.
- A HIGH regression of a tenant workload is registered with the sentinel (``POST /incidents/register``); the
  sentinel's gates decide whether anything is dispatched.
- Plan 2.0 job contract: run record ``sre-telemetry-digest-job_runs/{CLOUD_RUN_EXECUTION}`` via ``create()`` (a retry
  never writes a second digest or registers twice); exit 0 = no target errored, 1 = an error (``PARTIAL`` /
  ``FAILED``), 2 = usage, 3 = ``NOT_CONFIGURED`` (WARNING + run record; never dispatched by the sentinel).

SEAM(lane 14 PR-M): ``ledger_target_verifier`` is the ledger-only identity subset (ledger doc, not the platform
pseudo-workload, not the host project, exact reverse uniqueness). Once ``shared/managed_target.py`` is vendored here,
``verify_managed_target`` replaces it (adds provenance, CRM, IAM-gated tag and folder-ancestry checks; refusal codes
are the same lane 18 codes, e.g. ``NOT_STACKVEND_OWNED``). The job only READS telemetry and writes its own records.
"""

import hashlib
import json
import logging
import math
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

logger = logging.getLogger("sre-telemetry-digest-job")
logging.basicConfig(level=logging.INFO)

JOB_NAME = "sre-telemetry-digest-job"
SENTINEL_SERVICE = "log-sre-sentinel-service"
RUN_RECORD_COLLECTION = f"{JOB_NAME}_runs"  # read by the sentinel (sre_classifier.run_record_collection)
DIGEST_COLLECTION = "telemetry_digests"
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
HTTP_TIMEOUT_SECONDS = 60

LATENCY_METRIC = "run.googleapis.com/request_latencies"
LATENCY_RESOURCE_TYPE = "cloud_run_revision"

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_NOT_CONFIGURED = 0, 1, 2, 3

# Per-workload status
OK, NO_DATA, NO_BASELINE, ERROR, REFUSED = "OK", "NO_DATA", "NO_BASELINE", "ERROR", "REFUSED"

# Run outcomes (run record ``outcome``)
RUN_RUNNING, RUN_COMPLETED, RUN_PARTIAL, RUN_FAILED, RUN_NOT_CONFIGURED = (
    "RUNNING", "COMPLETED", "PARTIAL", "FAILED", "NOT_CONFIGURED")
RUN_OUTCOME_EXIT_CODES: Dict[str, int] = {
    RUN_COMPLETED: EXIT_OK, RUN_PARTIAL: EXIT_ERROR, RUN_FAILED: EXIT_ERROR,
    RUN_NOT_CONFIGURED: EXIT_NOT_CONFIGURED, RUN_RUNNING: EXIT_ERROR,
}

# Settings (env), with their defaults. Invalid values -> NOT_CONFIGURED (exit 3), never a silent fallback.
SETTINGS_DEFAULTS: Dict[str, Any] = {
    "DIGEST_LOOKBACK_DAYS": 7,
    "DIGEST_MIN_SAMPLES": 50,           # requests per window per service before a regression is evaluated
    "DIGEST_REGRESSION_RATIO": 1.2,     # current p95 / baseline p95 above this = regression (was: drift > 20 %)
    "DIGEST_INCIDENT_RATIO": 1.5,       # above this = HIGH, registered with the sentinel (was: drift > 50 % = HIGH)
    "DIGEST_MAX_LOG_ENTRIES": 5000,     # hard cap per workload per run
}

SCORE_REGRESSION_PENALTY = 5
SCORE_CLUSTER_PENALTY = 2
SCORE_MAX_CLUSTERS_COUNTED = 5


class NotConfigured(Exception):
    def __init__(self, missing: List[str]):
        super().__init__("missing configuration: " + ", ".join(missing))
        self.missing = list(missing)


class StoreUnavailable(Exception):
    """A Firestore read or write the run depends on failed (the run fails closed)."""


class TargetRefused(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


# ----------------------------------------------------------------------------------------------------------------
# Pure helpers
# ----------------------------------------------------------------------------------------------------------------
def entry_component(entry: Mapping[str, Any]) -> str:
    """Cloud Run service / job name from the entry's resource labels (exact keys), else the resource type."""
    resource = entry.get("resource") if isinstance(entry.get("resource"), Mapping) else {}
    labels = resource.get("labels") if isinstance(resource.get("labels"), Mapping) else {}
    for key in ("service_name", "job_name"):
        if isinstance(labels.get(key), str) and labels.get(key):
            return labels[key]
    return resource.get("type") if isinstance(resource.get("type"), str) and resource.get("type") else "unknown"


def entry_message(entry: Mapping[str, Any]) -> str:
    """``textPayload``, else ``jsonPayload.message``, else the JSON payload itself (exact fields)."""
    if isinstance(entry.get("textPayload"), str):
        return entry["textPayload"]
    payload = entry.get("jsonPayload")
    if isinstance(payload, Mapping):
        if isinstance(payload.get("message"), str):
            return payload["message"]
        return json.dumps(payload, sort_keys=True, default=str)
    return ""


def latency_verdict(current: Optional[Mapping[str, Any]], baseline: Optional[Mapping[str, Any]],
                    min_samples: int, regression_ratio: float, incident_ratio: float) -> Dict[str, Any]:
    """One service: OK (with ``ratio``), REGRESSION (``severity`` MEDIUM/HIGH) or NO_BASELINE. Exact arithmetic."""
    cur_n = int(current.get("samples", 0)) if current else 0
    base_n = int(baseline.get("samples", 0)) if baseline else 0
    out: Dict[str, Any] = {"current_samples": cur_n, "baseline_samples": base_n,
                           "current_p95_ms": current.get("p95_ms") if current else None,
                           "baseline_p95_ms": baseline.get("p95_ms") if baseline else None}
    if cur_n < min_samples or base_n < min_samples or not out["baseline_p95_ms"] or out["current_p95_ms"] is None:
        out["status"] = NO_BASELINE
        return out
    ratio = float(out["current_p95_ms"]) / float(out["baseline_p95_ms"])
    out["ratio"] = ratio
    if ratio > regression_ratio:
        out["status"] = "REGRESSION"
        out["severity"] = "HIGH" if ratio > incident_ratio else "MEDIUM"
    else:
        out["status"] = OK
    return out


def health_score(regressions: int, clusters: int) -> int:
    """Same weights as before PR-3, computed only from real data and without the old floor of 70."""
    return max(0, 100 - regressions * SCORE_REGRESSION_PENALTY
               - min(clusters, SCORE_MAX_CLUSTERS_COUNTED) * SCORE_CLUSTER_PENALTY)


def system_status(score: Optional[int]) -> str:
    if score is None:
        return NO_DATA
    return "EXCELLENT" if score >= 95 else "HEALTHY" if score >= 85 else "NEEDS_ATTENTION"


# ----------------------------------------------------------------------------------------------------------------
# Default cloud adapters (REST; replaced in tests)
# ----------------------------------------------------------------------------------------------------------------
def _authorized_session():
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    credentials, _ = google.auth.default(scopes=[CLOUD_PLATFORM_SCOPE])
    return AuthorizedSession(credentials)


def _rfc3339(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_log_reader(project_id: str, start: datetime, end: datetime, max_entries: int) -> Tuple[List[Dict], bool]:
    """Logging v2 ``entries:list`` for one project: WARNING and above in [start, end). Returns (entries, truncated)."""
    session = _authorized_session()
    entries: List[Dict[str, Any]] = []
    token = ""
    while True:
        body: Dict[str, Any] = {
            "resourceNames": [f"projects/{project_id}"],
            "filter": f'severity>=WARNING AND timestamp>="{_rfc3339(start)}" AND timestamp<"{_rfc3339(end)}"',
            "orderBy": "timestamp desc",
            "pageSize": min(1000, max_entries - len(entries)),
        }
        if token:
            body["pageToken"] = token
        resp = session.post("https://logging.googleapis.com/v2/entries:list", json=body, timeout=HTTP_TIMEOUT_SECONDS)
        resp.raise_for_status()
        data = resp.json() or {}
        entries.extend(e for e in data.get("entries", []) if isinstance(e, dict))
        token = data.get("nextPageToken") or ""
        if len(entries) >= max_entries:
            return entries[:max_entries], bool(token) or len(entries) > max_entries
        if not token:
            return entries, False


def _time_series(session, project_id: str, start: datetime, end: datetime, reducer: str) -> List[Dict[str, Any]]:
    params = {
        "filter": f'metric.type="{LATENCY_METRIC}" AND resource.type="{LATENCY_RESOURCE_TYPE}"',
        "interval.startTime": _rfc3339(start),
        "interval.endTime": _rfc3339(end),
        "aggregation.alignmentPeriod": f"{int((end - start).total_seconds())}s",
        "aggregation.perSeriesAligner": "ALIGN_DELTA",
        "aggregation.crossSeriesReducer": reducer,
        "aggregation.groupByFields": "resource.label.service_name",
    }
    series: List[Dict[str, Any]] = []
    while True:
        resp = session.get(f"https://monitoring.googleapis.com/v3/projects/{project_id}/timeSeries", params=params,
                           timeout=HTTP_TIMEOUT_SECONDS)
        resp.raise_for_status()
        data = resp.json() or {}
        series.extend(s for s in data.get("timeSeries", []) if isinstance(s, dict))
        token = data.get("nextPageToken") or ""
        if not token:
            return series
        params["pageToken"] = token


def _series_service(series: Mapping[str, Any]) -> str:
    resource = series.get("resource") if isinstance(series.get("resource"), Mapping) else {}
    labels = resource.get("labels") if isinstance(resource.get("labels"), Mapping) else {}
    name = labels.get("service_name")
    return name if isinstance(name, str) else ""


def default_latency_reader(project_id: str, start: datetime, end: datetime) -> Dict[str, Dict[str, Any]]:
    """Monitoring v3: per Cloud Run service, p95 of ``request_latencies`` over [start, end) (``ALIGN_DELTA`` +
    ``REDUCE_PERCENTILE_95`` grouped by ``service_name``; ms) and the request count (``REDUCE_SUM`` distribution
    ``count``). One alignment period = the whole window; if Monitoring returns more than one point the p95 is the
    largest point (conservative) and the counts are summed."""
    session = _authorized_session()
    out: Dict[str, Dict[str, Any]] = {}
    for s in _time_series(session, project_id, start, end, "REDUCE_PERCENTILE_95"):
        values = [p.get("value", {}).get("doubleValue") for p in s.get("points", []) if isinstance(p, dict)]
        values = [float(v) for v in values if isinstance(v, (int, float))]
        if _series_service(s) and values:
            out.setdefault(_series_service(s), {"samples": 0})["p95_ms"] = max(values)
    for s in _time_series(session, project_id, start, end, "REDUCE_SUM"):
        total = 0
        for p in s.get("points", []):
            count = (p.get("value", {}).get("distributionValue") or {}).get("count") if isinstance(p, dict) else None
            if isinstance(count, (int, str)) and str(count).isdigit():
                total += int(count)
        if _series_service(s):
            out.setdefault(_series_service(s), {})["samples"] = total
    return out


def default_service_url_resolver(project_id: str, region: str, service_name: str) -> Optional[str]:
    """Run Admin v2 ``services.get`` by exact service name (plan G14) -> its HTTPS ``uri``, or None."""
    resp = _authorized_session().get(
        f"https://run.googleapis.com/v2/projects/{project_id}/locations/{region}/services/{service_name}",
        timeout=HTTP_TIMEOUT_SECONDS)
    resp.raise_for_status()
    uri = (resp.json() or {}).get("uri")
    return uri.rstrip("/") if isinstance(uri, str) and uri.startswith("https://") else None


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


def _default_firestore(project_id: str):
    from google.cloud import firestore

    return firestore.Client(project=project_id)


def _is_already_exists(exc: Exception) -> bool:
    try:
        from google.api_core.exceptions import AlreadyExists, Conflict

        return isinstance(exc, (AlreadyExists, Conflict))
    except Exception:  # pragma: no cover - api_core always ships with firestore
        return False


def _field_filter(field_path: str, value: Any):
    from google.cloud.firestore_v1.base_query import FieldFilter

    return FieldFilter(field_path, "==", value)


def ledger_target_verifier(db: Any, host_project_id: str) -> Callable[[str, Mapping[str, Any]], str]:
    """SEAM(lane 14 PR-M): ledger-only identity subset; returns the project id or raises TargetRefused (lane 18
    codes). Read-only, exact comparisons only."""

    def verify(product_id: str, data: Mapping[str, Any]) -> str:
        if data.get("is_castor") is True:
            raise TargetRefused("PLATFORM_WORKLOAD", product_id)
        project_id = data.get("project_id")
        if not isinstance(project_id, str) or not project_id:
            raise TargetRefused("LEDGER_MISMATCH", "ledger doc has no project_id")
        if project_id == host_project_id:
            raise TargetRefused("HOST_PROJECT", project_id)
        try:
            same = list(db.collection("workloads").where(filter=_field_filter("project_id", project_id))
                        .limit(2).stream())
        except Exception as e:
            raise TargetRefused("LEDGER_UNAVAILABLE", f"{type(e).__name__}: {e}") from e
        if [getattr(d, "id", None) for d in same] != [product_id]:
            raise TargetRefused("LEDGER_MISMATCH", f"{project_id} is not owned by exactly {product_id}")
        return project_id

    return verify


# ----------------------------------------------------------------------------------------------------------------
# The job
# ----------------------------------------------------------------------------------------------------------------
@dataclass
class _Run:
    run_id: str
    started_at: datetime
    workloads: List[Dict[str, Any]] = field(default_factory=list)
    registrations: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class SRETelemetryDigest:
    def __init__(
        self,
        project_id: Optional[str] = None,
        firestore_client: Optional[Any] = None,
        *,
        env: Optional[Mapping[str, str]] = None,
        log_reader: Optional[Callable[..., Tuple[List[Dict], bool]]] = None,
        latency_reader: Optional[Callable[..., Dict[str, Dict[str, Any]]]] = None,
        target_verifier: Optional[Callable[[str, Mapping[str, Any]], str]] = None,
        service_url_resolver: Optional[Callable[[str, str, str], Optional[str]]] = None,
        id_token_fetcher: Optional[Callable[[str], str]] = None,
        http_post: Optional[Callable[..., Tuple[int, Any]]] = None,
        clock: Optional[Callable[[], datetime]] = None,
        firestore_factory: Optional[Callable[[str], Any]] = None,
    ):
        self._env = env if env is not None else os.environ
        self.project_id = project_id if project_id is not None else self._env.get("PROJECT_ID", "")
        self._db = firestore_client
        self._firestore_factory = firestore_factory or _default_firestore
        self._log_reader = log_reader or default_log_reader
        self._latency_reader = latency_reader or default_latency_reader
        self._target_verifier = target_verifier
        self._service_url_resolver = service_url_resolver or default_service_url_resolver
        self._id_token_fetcher = id_token_fetcher or default_id_token_fetcher
        self._http_post = http_post or default_http_post
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._sentinel_url: Optional[str] = None

    # ------------------------------------------------------------------ configuration
    def settings(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        invalid: List[str] = []
        for key, default in SETTINGS_DEFAULTS.items():
            raw = self._env.get(key, "")
            if raw == "":
                out[key] = default
                continue
            try:
                value = type(default)(raw)
            except ValueError:
                invalid.append(f"{key} (invalid)")
                continue
            if isinstance(value, float) and not math.isfinite(value):  # nan/inf would disable every comparison (RT F3-3)
                invalid.append(f"{key} (invalid)")
                continue
            if value <= 0:
                invalid.append(f"{key} (invalid)")
                continue
            out[key] = value
        if not invalid and out["DIGEST_INCIDENT_RATIO"] < out["DIGEST_REGRESSION_RATIO"]:
            invalid.append("DIGEST_INCIDENT_RATIO (below DIGEST_REGRESSION_RATIO)")
        if invalid:
            raise NotConfigured(invalid)
        return out

    def _db_client(self):
        if self._db is None:
            self._db = self._firestore_factory(self.project_id)
        return self._db

    def _verifier(self):
        if self._target_verifier is None:
            self._target_verifier = ledger_target_verifier(self._db_client(), self.project_id)
        return self._target_verifier

    # ------------------------------------------------------------------ analysis (pure apart from the readers)
    def cluster_warning_logs(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalizes and clusters recurring WARNING-level messages (UUIDs and numbers replaced) per component.
        Kept unchanged by PR-3 (HEALERS.md HE-07: "Keep"); it now receives real log entries.
        """
        clusters: Dict[str, Dict[str, Any]] = {}
        for log in entries:
            service = log.get("service_name", "unknown-service")
            msg = log.get("message", "")
            normalized = re.sub(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '<UUID>', msg)
            normalized = re.sub(r'\d+', '<NUM>', normalized)
            key = f"{service}::{normalized.strip()}"
            if key not in clusters:
                clusters[key] = {
                    "pattern": normalized.strip(),
                    "service_name": service,
                    "count": 0,
                    "first_seen": log.get("timestamp", ""),
                    "sample_message": msg,
                }
            clusters[key]["count"] += 1
            clusters[key]["last_seen"] = log.get("timestamp", "")
        return sorted(clusters.values(), key=lambda x: x["count"], reverse=True)

    def analyze_target(self, scope: str, product_id: str, project_id: str, cfg: Dict[str, Any],
                       now: datetime) -> Dict[str, Any]:
        lookback = timedelta(days=cfg["DIGEST_LOOKBACK_DAYS"])
        cur_start, base_start = now - lookback, now - 2 * lookback
        result: Dict[str, Any] = {"scope": scope, "product_id": product_id, "project_id": project_id,
                                  "warning_clusters": [], "latency": {}, "latency_regressions": [], "errors": []}
        log_status = latency_status = NO_DATA
        clusters: List[Dict[str, Any]] = []
        try:
            raw, truncated = self._log_reader(project_id, cur_start, now, cfg["DIGEST_MAX_LOG_ENTRIES"])
            entries = [{"service_name": entry_component(e), "message": entry_message(e),
                        "timestamp": e.get("timestamp", ""), "severity": e.get("severity", "")} for e in raw]
            clusters = self.cluster_warning_logs(entries)
            result.update({"warning_entries": len(entries), "warning_entries_truncated": truncated,
                           "warning_clusters": clusters[:5]})
            log_status = OK if entries else NO_DATA
        except Exception as e:
            log_status = ERROR
            result["errors"].append(f"LOGGING_READ_FAILED: {type(e).__name__}: {e}")

        regressions: List[Dict[str, Any]] = []
        try:
            current = self._latency_reader(project_id, cur_start, now)
            baseline = self._latency_reader(project_id, base_start, cur_start)
            verdicts = {svc: latency_verdict(current.get(svc), baseline.get(svc), cfg["DIGEST_MIN_SAMPLES"],
                                             cfg["DIGEST_REGRESSION_RATIO"], cfg["DIGEST_INCIDENT_RATIO"])
                        for svc in sorted(current)}
            result["latency"] = verdicts
            for svc, v in verdicts.items():
                if v["status"] == "REGRESSION":
                    regressions.append({"service_name": svc, "current_p95_ms": v["current_p95_ms"],
                                        "baseline_p95_ms": v["baseline_p95_ms"], "ratio": v["ratio"],
                                        "drift_percentage": f"+{round((v['ratio'] - 1) * 100, 1)}%",
                                        "severity": v["severity"],
                                        "recommendation": f"Profile request handling of {svc}: p95 rose from "
                                                          f"{v['baseline_p95_ms']} ms to {v['current_p95_ms']} ms."})
            has_samples = any(v["current_samples"] > 0 for v in verdicts.values())
            evaluated = any(v["status"] != NO_BASELINE for v in verdicts.values())
            latency_status = (OK if evaluated else NO_BASELINE) if has_samples else NO_DATA
        except Exception as e:
            latency_status = ERROR
            result["errors"].append(f"MONITORING_READ_FAILED: {type(e).__name__}: {e}")
        result["latency_regressions"] = regressions

        if ERROR in (log_status, latency_status):
            status = ERROR
        elif log_status == NO_DATA and latency_status == NO_DATA:
            status = NO_DATA
        elif log_status == NO_DATA and latency_status == NO_BASELINE:
            status = NO_BASELINE
        else:
            status = OK
        basis = [name for name, s in (("warning_logs", log_status), ("latency", latency_status)) if s == OK]
        result.update({"status": status, "log_status": log_status, "latency_status": latency_status,
                       "score_basis": basis,
                       "health_score": health_score(len(regressions), len(clusters)) if status == OK else None})
        return result

    # ------------------------------------------------------------------ targets
    def _targets(self, cfg: Dict[str, Any], run: _Run) -> List[Tuple[str, str, str]]:
        try:
            docs = list(self._db_client().collection("workloads").where(filter=_field_filter("status", "ACTIVE"))
                        .stream())
        except Exception as e:
            raise StoreUnavailable(f"workloads: {type(e).__name__}: {e}") from e
        targets: List[Tuple[str, str, str]] = []
        verify = self._verifier()
        for doc in sorted(docs, key=lambda d: str(getattr(d, "id", ""))):
            data = doc.to_dict() or {}
            if data.get("is_castor") is True:
                continue  # the platform pseudo-workload: never in scope
            try:
                targets.append(("workload", doc.id, verify(doc.id, data)))
            except TargetRefused as e:
                run.workloads.append({"scope": "workload", "product_id": doc.id, "status": f"{REFUSED}:{e.code}",
                                      "detail": e.detail, "health_score": None})
        return targets

    # ------------------------------------------------------------------ sentinel hook (plan 2.4 item 4)
    def _register(self, region: str, workload: Dict[str, Any], regression: Dict[str, Any], run: _Run) -> Dict[str, Any]:
        fingerprint = f"latency_regression/{regression['service_name']}"
        evidence = {
            "finding_type": "LatencyRegression",
            "service_name": regression["service_name"],
            "summary": (f"p95 latency of {regression['service_name']} rose {regression['drift_percentage']} "
                        f"week over week ({regression['baseline_p95_ms']} ms -> {regression['current_p95_ms']} ms)"),
            "severity": "WARNING",
            "current_p95_ms": regression["current_p95_ms"],
            "baseline_p95_ms": regression["baseline_p95_ms"],
            "ratio": regression["ratio"],
            "recommendation": regression["recommendation"],
            "digest_run_id": run.run_id,
        }
        out: Dict[str, Any] = {"product_id": workload["product_id"], "fingerprint": fingerprint}
        if not region:
            out.update({"status": "NOT_CONFIGURED", "code": "REGION"})
            return out
        if self._sentinel_url is None:
            try:
                self._sentinel_url = self._service_url_resolver(self.project_id, region, SENTINEL_SERVICE) or ""
            except Exception as e:
                logger.warning(f"Could not resolve the {SENTINEL_SERVICE} URL: {e}")
                self._sentinel_url = ""
        if not self._sentinel_url:
            out.update({"status": "FAILED", "code": "SENTINEL_URL_UNRESOLVED"})
            return out
        try:
            token = self._id_token_fetcher(self._sentinel_url)
            status, body = self._http_post(
                f"{self._sentinel_url}/incidents/register", headers={"Authorization": f"Bearer {token}"},
                json_body={"product_id": workload["product_id"], "fingerprint": fingerprint, "source": JOB_NAME,
                           "evidence": evidence}, timeout=HTTP_TIMEOUT_SECONDS)
        except Exception as e:
            out.update({"status": "FAILED", "code": "SENTINEL_UNREACHABLE", "detail": f"{type(e).__name__}: {e}"})
            return out
        body = body if isinstance(body, Mapping) else {}
        if status == 200:
            out.update({"status": "REGISTERED", "incident_id": body.get("incident_id"),
                        "sentinel_status": body.get("status"),
                        "auto_remediation_status": body.get("auto_remediation_status")})
        elif status == 422 and isinstance(body.get("error_class"), str):
            out.update({"status": "REFUSED", "code": body["error_class"]})
        else:
            out.update({"status": "FAILED", "code": f"HTTP_{status}"})
        return out

    # ------------------------------------------------------------------ run record (plan 2.0)
    def _claim_run(self, run: _Run) -> Optional[Dict[str, Any]]:
        ref = self._db_client().collection(RUN_RECORD_COLLECTION).document(run.run_id)
        try:
            ref.create({"job": JOB_NAME, "run_id": run.run_id, "outcome": RUN_RUNNING,
                        "started_at": run.started_at.isoformat()})
            return None
        except Exception as e:
            if not _is_already_exists(e):
                raise StoreUnavailable(f"{RUN_RECORD_COLLECTION}/{run.run_id}: {type(e).__name__}: {e}") from e
        try:
            snap = ref.get()
        except Exception as e:
            raise StoreUnavailable(f"{RUN_RECORD_COLLECTION}/{run.run_id}: {type(e).__name__}: {e}") from e
        return (snap.to_dict() or {}) if snap.exists else {"outcome": RUN_RUNNING}

    def _finish_run_record(self, run: _Run, outcome: str, extra: Dict[str, Any]) -> None:
        try:
            self._db_client().collection(RUN_RECORD_COLLECTION).document(run.run_id).set(
                {"job": JOB_NAME, "run_id": run.run_id, "outcome": outcome, "started_at": run.started_at.isoformat(),
                 "finished_at": self._clock().isoformat(), **extra})
        except Exception as e:
            logger.warning(f"Could not finish run record {RUN_RECORD_COLLECTION}/{run.run_id}: {e}")

    # ------------------------------------------------------------------ entry point
    def generate_digest_report(self, run_id: Optional[str] = None) -> Dict[str, Any]:
        """One weekly run. Returns the report; ``report["exit_code"]`` is the process exit code (plan 2.0)."""
        now = self._clock()
        run = _Run(run_id=run_id or self._env.get("CLOUD_RUN_EXECUTION") or f"manual-{uuid.uuid4().hex[:12]}",
                   started_at=now)
        try:
            if not self.project_id:
                raise NotConfigured(["PROJECT_ID"])
            cfg = self.settings()
        except NotConfigured as e:
            logger.warning(json.dumps({"error_class": "NOT_CONFIGURED", "job": JOB_NAME, "missing": e.missing}))
            if self.project_id:
                self._finish_run_record(run, RUN_NOT_CONFIGURED, {"missing": e.missing})
            return {"job": JOB_NAME, "run_id": run.run_id, "status": RUN_NOT_CONFIGURED, "missing": e.missing,
                    "exit_code": EXIT_NOT_CONFIGURED}

        try:
            existing = self._claim_run(run)
            if existing is not None:
                recorded = existing.get("outcome") if isinstance(existing.get("outcome"), str) else RUN_RUNNING
                logger.warning(f"Run {run.run_id} already recorded with outcome {recorded}; no second digest.")
                return {"job": JOB_NAME, "run_id": run.run_id, "status": "ALREADY_RECORDED",
                        "recorded_outcome": recorded, "exit_code": RUN_OUTCOME_EXIT_CODES.get(recorded, EXIT_ERROR)}
            targets = self._targets(cfg, run)
        except StoreUnavailable as e:
            logger.error(f"SRE digest run {run.run_id} failed closed: {e}")
            self._finish_run_record(run, RUN_FAILED, {"errors": [str(e)]})
            return {"job": JOB_NAME, "run_id": run.run_id, "status": RUN_FAILED, "errors": [str(e)],
                    "exit_code": EXIT_ERROR}

        region = self._env.get("REGION", "")
        for scope, product_id, project_id in targets:
            workload = self.analyze_target(scope, product_id, project_id, cfg, now)
            run.workloads.append(workload)
            for regression in workload["latency_regressions"]:
                if regression["severity"] == "HIGH":
                    run.registrations.append(self._register(region, workload, regression, run))

        report = self._compile(run, cfg, now)
        if any(w["status"] == ERROR for w in run.workloads) or any(r["status"] == "FAILED" for r in run.registrations):
            outcome, code = RUN_PARTIAL, EXIT_ERROR
        elif any(r["status"] == "NOT_CONFIGURED" for r in run.registrations):
            outcome, code = RUN_NOT_CONFIGURED, EXIT_NOT_CONFIGURED
            logger.warning(json.dumps({"error_class": "NOT_CONFIGURED", "job": JOB_NAME, "missing": ["REGION"]}))
        else:
            outcome, code = RUN_COMPLETED, EXIT_OK
        report.update({"run_outcome": outcome, "exit_code": code})

        try:
            self._db_client().collection(DIGEST_COLLECTION).document(report["digest_id"]).set(report)
            logger.info(f"Saved telemetry digest {DIGEST_COLLECTION}/{report['digest_id']} ({outcome})")
        except Exception as e:
            logger.error(f"Could not save digest {report['digest_id']}: {e}")
            outcome, code = RUN_FAILED, EXIT_ERROR
            report.update({"run_outcome": outcome, "exit_code": code})
        self._finish_run_record(run, outcome, {"digest_id": report["digest_id"],
                                               **({"missing": ["REGION"]} if outcome == RUN_NOT_CONFIGURED else {})})
        for w in run.workloads:
            if w["status"] == ERROR:
                logger.error(f"Digest of {w['product_id']} failed: {w['errors']}")
        for r in run.registrations:
            if r["status"] == "FAILED":
                logger.error(f"Incident registration for {r['product_id']} failed: {r['code']}")
        return report

    def _compile(self, run: _Run, cfg: Dict[str, Any], now: datetime) -> Dict[str, Any]:
        scored = [w["health_score"] for w in run.workloads if w.get("health_score") is not None]
        overall = min(scored) if scored else None
        clusters = [c for w in run.workloads for c in w.get("warning_clusters", [])]
        regressions = [dict(r, product_id=w["product_id"]) for w in run.workloads for r in w.get("latency_regressions", [])]
        counts: Dict[str, int] = {}
        for w in run.workloads:
            counts[w["status"]] = counts.get(w["status"], 0) + 1
        digest_hash = hashlib.sha256(run.run_id.encode("utf-8")).hexdigest()[:6]
        return {
            "digest_id": f"digest-{now.strftime('%Y-%U')}-{digest_hash}",
            "job": JOB_NAME,
            "run_id": run.run_id,
            "generated_at": now.isoformat(),
            "period_start": (now - timedelta(days=cfg["DIGEST_LOOKBACK_DAYS"])).isoformat(),
            "period_end": now.isoformat(),
            "data_source": "cloud_logging_v2+cloud_monitoring_v3",
            "overall_health_score": overall,
            "system_status": system_status(overall),
            "workload_status_counts": counts,
            "workloads": run.workloads,
            "warning_clusters_count": len(clusters),
            "top_warning_clusters": sorted(clusters, key=lambda c: c["count"], reverse=True)[:5],
            "latency_regressions_count": len(regressions),
            "latency_regressions": regressions,
            "proactive_maintenance_recommendations": [r["recommendation"] for r in regressions],
            "incident_registrations": run.registrations,
            "settings": cfg,
        }
