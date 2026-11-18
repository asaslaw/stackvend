"""
StackVend gcloud MCP Tool Server - typed tools (FD-4L / FD27-05; lane 14 plan §3.1; rows L14-g inspection, L14-o ops).

No free-form command runs here any more. The old substring denylist / domain allowlist is gone with the CLI: the
image has no `gcloud` binary, and every tool is a typed Google Cloud REST call (`AuthorizedSession`) built from
validated fields only. Nothing free-form is left to bypass.

Target: every tool takes `product_id`; the project comes only from the workload ledger (`managed_target_seam.
verify_ledger_target`: exact `workloads/{product_id}.project_id`, never the host project, reverse-unique). An
optional request `project_id` must equal it exactly. There is no `PROJECT_ID` default target.

Inspection (read-only): get_cloud_run_service, list_cloud_run_services, get_project_iam_policy,
list_service_accounts, query_logs (filter assembled from typed fields: severity enum, resource type enum, an RFC 1123
service / job name, an RFC 3339 `since`, a bounded `limit`).

Ops (service-affecting; owner Q9 = A: typed + audited): update_cloud_run_scaling (`max_instance_count == 0` refused
QUARANTINE_IS_ENFORCER_ONLY: scale-to-zero is the FinOps enforcer's restorable quarantine; `min > max` and
`max > GCLOUD_MCP_OPS_MAX_INSTANCES` refused), update_cloud_run_traffic (revisions must exist, integer percents sum
to 100), restart_cloud_run_service (new revision, same spec). The audit entry `gcloud_mcp_ops/{id}` (caller, target,
before / after) is written BEFORE the Cloud Run call; an audit failure refuses the op. IAM grants and deletes are not
gcloud tools (deletes: lane 18 executor with HITL; IAM: workload IaC).

Errors are typed (`GcloudRefused(code, detail, http_status)`); missing credentials are an explicit error, never a
mock success.
"""

from __future__ import annotations

import inspect
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional

import managed_target_seam as seam

logger = logging.getLogger("mcp-gcloud-server")
logging.basicConfig(level=logging.INFO)

RUN_API = "https://run.googleapis.com/v2"
CRM_API = "https://cloudresourcemanager.googleapis.com/v3"
IAM_API = "https://iam.googleapis.com/v1"
LOGGING_API = "https://logging.googleapis.com/v2"
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
HTTP_TIMEOUT_S = 30.0
MAX_PAGES = 20

OPS_AUDIT_COLLECTION = "gcloud_mcp_ops"
OPS_MAX_INSTANCES_ENV = "GCLOUD_MCP_OPS_MAX_INSTANCES"
DEFAULT_OPS_MAX_INSTANCES = 100
RESTART_ANNOTATION = "stackvend.dev/restarted-at"

SEVERITIES = ("DEFAULT", "DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY")
# Exact Cloud Logging monitored-resource types -> the label that names the resource (None: no name filter allowed).
LOG_RESOURCE_TYPES: Dict[str, Optional[str]] = {
    "cloud_run_revision": "service_name",
    "cloud_run_job": "job_name",
    "cloud_function": "function_name",
    "k8s_container": "container_name",
    "gce_instance": None,
    "cloudsql_database": None,
    "global": None,
}
MAX_LOG_LIMIT = 1000

INSPECTION_TOOLS = ("get_cloud_run_service", "list_cloud_run_services", "get_project_iam_policy",
                    "list_service_accounts", "query_logs")
OPS_TOOLS = ("update_cloud_run_scaling", "update_cloud_run_traffic", "restart_cloud_run_service")


class GcloudRefused(Exception):
    def __init__(self, code: str, detail: str = "", http_status: int = 422):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.http_status = code, detail, http_status


# --------------------------------------------------------------------------------------------------- typed checks
def is_rfc1123_label(value: Any, max_len: int = 63) -> bool:
    if not isinstance(value, str) or not value or len(value) > max_len or not value.isascii():  # RT F2: ASCII only
        return False
    if not all(ch.islower() or ch.isdigit() or ch == "-" for ch in value):
        return False
    return value[0].isalnum() and value[-1].isalnum()


def is_region(value: Any) -> bool:
    """A GCP region id: two or more dash-separated lowercase alphanumeric labels (e.g. us-central1)."""
    if not isinstance(value, str) or len(value) > 40 or not value.isascii():  # RT F2: ASCII only
        return False
    parts = value.split("-")
    return len(parts) >= 2 and all(p and all(ch.islower() or ch.isdigit() for ch in p) for p in parts)


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def parse_since(value: Any) -> str:
    """RFC 3339 timestamp with an offset -> normalized UTC ISO string (re-emitted, never passed through)."""
    if not isinstance(value, str) or not value:
        raise GcloudRefused("SINCE_INVALID", "since must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as e:
        raise GcloudRefused("SINCE_INVALID", "since must be an RFC 3339 timestamp") from e
    if parsed.tzinfo is None:
        raise GcloudRefused("SINCE_INVALID", "since needs a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat()


def build_log_filter(severity: Optional[str], resource_type: Optional[str], service_name: Optional[str],
                     since: Optional[str]) -> str:
    """Cloud Logging filter from typed fields only. Every value is an enum member, an RFC 1123 label or a re-emitted
    timestamp, so no quote, operator or flag can be injected."""
    parts: List[str] = []
    if resource_type is not None:
        if resource_type not in LOG_RESOURCE_TYPES:
            raise GcloudRefused("RESOURCE_TYPE_INVALID", f"resource_type must be one of {sorted(LOG_RESOURCE_TYPES)}")
        parts.append(f'resource.type="{resource_type}"')
    if service_name is not None:
        label = LOG_RESOURCE_TYPES.get(resource_type) if resource_type else None
        if label is None:
            raise GcloudRefused("SERVICE_NAME_INVALID", "service_name needs a resource_type that names a resource")
        if not is_rfc1123_label(service_name):
            raise GcloudRefused("SERVICE_NAME_INVALID", "service_name must be an RFC 1123 label")
        parts.append(f'resource.labels.{label}="{service_name}"')
    if severity is not None:
        if severity not in SEVERITIES:
            raise GcloudRefused("SEVERITY_INVALID", f"severity must be one of {list(SEVERITIES)}")
        parts.append(f"severity>={severity}")
    if since is not None:
        parts.append(f'timestamp>="{parse_since(since)}"')
    return " AND ".join(parts)


GOOGLE_ID_TOKEN_ISSUERS = frozenset({"accounts.google.com", "https://accounts.google.com"})
GCLOUD_MCP_SERVICE = "mcp-gcloud-server"
GCLOUD_MCP_URL_ENV = "GCLOUD_MCP_URL"


def caller_from_authorization(header: Optional[str], *, verify: Callable[[str], Mapping[str, Any]]) -> str:
    """RT F1: the audited caller of an op is the VERIFIED identity of the bearer ID token (`verify` checks the Google
    signature, the audience = this service's URL and the issuer). No `Authorization` header -> "unknown" (the caller
    used `X-Serverless-Authorization`; Cloud Run IAM authorized it). A header whose token does not verify ->
    401 CALLER_UNVERIFIED (an unsigned or foreign token is never written to the audit as the caller)."""
    if not header:
        return "unknown"
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise GcloudRefused("CALLER_UNVERIFIED", "Authorization is not a bearer ID token", 401)
    try:
        claims = verify(token)
    except Exception as e:
        raise GcloudRefused("CALLER_UNVERIFIED", f"ID token did not verify ({type(e).__name__})", 401) from e
    who = (claims or {}).get("email") or (claims or {}).get("sub")
    if not isinstance(who, str) or not who:
        raise GcloudRefused("CALLER_UNVERIFIED", "verified token names no principal", 401)
    return who


def _default_caller_verifier(token: str) -> Mapping[str, Any]:
    """google.oauth2.id_token.verify_token against this service's own URL (GCLOUD_MCP_URL, else the Cloud Run URL
    from the metadata server); issuer must be Google. Raises on any failure (the caller maps it to 401)."""
    from google.auth.transport.requests import Request
    from google.oauth2 import id_token

    audience = seam.platform_service_url(GCLOUD_MCP_SERVICE, GCLOUD_MCP_URL_ENV)
    claims = id_token.verify_token(token, Request(), audience=audience)
    if claims.get("iss") not in GOOGLE_ID_TOKEN_ISSUERS:
        raise ValueError("issuer is not Google")
    return claims


def _default_session_factory() -> Any:
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    credentials, _ = google.auth.default(scopes=SCOPES)
    return AuthorizedSession(credentials)


def _default_db_factory() -> Any:
    from google.cloud import firestore

    project = os.getenv("PROJECT_ID") or None
    return firestore.Client(project=project) if project else None


class GcloudExecutor:
    def __init__(self, *, db_factory: Optional[Callable[[], Any]] = None,
                 session_factory: Optional[Callable[[], Any]] = None,
                 env: Optional[Mapping[str, str]] = None, clock: Optional[Callable[[], datetime]] = None,
                 caller_verifier: Optional[Callable[[str], Mapping[str, Any]]] = None):
        self._db_factory = db_factory or _default_db_factory
        self._verify_caller = caller_verifier or _default_caller_verifier
        self._session_factory = session_factory or _default_session_factory
        self._env = os.environ if env is None else env
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._db: Any = None
        self._db_ready = False
        self._session: Any = None

    # ------------------------------------------------------------------ plumbing
    def _ledger_db(self) -> Any:
        if not self._db_ready:
            try:
                self._db = self._db_factory()
            except Exception as e:
                logger.warning(f"Firestore client unavailable: {type(e).__name__}")
                self._db = None
            self._db_ready = True
        return self._db

    def _http(self) -> Any:
        if self._session is None:
            try:
                self._session = self._session_factory()
            except Exception as e:
                raise GcloudRefused("CREDENTIALS_UNAVAILABLE", type(e).__name__, 503) from e
        return self._session

    def credentials_status(self) -> str:
        try:
            self._http()
        except GcloudRefused as e:
            return f"UNAVAILABLE:{e.detail}"
        return "AVAILABLE"

    def _call(self, method: str, url: str, *, params: Optional[Dict[str, Any]] = None,
              body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        session = self._http()
        try:
            res = session.request(method, url, params=params, json=body, timeout=HTTP_TIMEOUT_S)
        except Exception as e:
            raise GcloudRefused("GCP_API_UNREACHABLE", type(e).__name__, 502) from e
        try:
            payload = res.json()
        except ValueError:
            payload = None
        if 200 <= res.status_code < 300:
            return payload if isinstance(payload, dict) else {}
        message = ""
        if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
            message = str(payload["error"].get("message") or "")[:300]
        mapped = {400: ("INVALID_ARGUMENT", 422), 403: ("PERMISSION_DENIED", 403), 404: ("NOT_FOUND", 404),
                  409: ("CONFLICT", 409)}.get(res.status_code, ("GCP_API_ERROR", 502))
        raise GcloudRefused(mapped[0], f"HTTP {res.status_code} {message}".strip(), mapped[1])

    def _list(self, url: str, key: str, params: Optional[Dict[str, Any]] = None) -> List[Any]:
        items: List[Any] = []
        query = dict(params or {})
        for _ in range(MAX_PAGES):
            page = self._call("GET", url, params=query)
            items.extend(page.get(key) or [])
            token = page.get("nextPageToken")
            if not token:
                return items
            query["pageToken"] = token
        raise GcloudRefused("RESULT_TOO_LARGE", f"more than {MAX_PAGES} pages", 502)

    def _target(self, product_id: Any, project_id: Optional[str]) -> seam.ManagedTarget:
        try:
            target = seam.verify_ledger_target(self._ledger_db(), product_id, seam.host_project_ids(self._env))
        except seam.TargetRefused as e:
            raise GcloudRefused(f"REFUSED:{e.code}", e.detail, 403) from e
        if project_id is not None and project_id != target.project_id:
            raise GcloudRefused("REFUSED:TARGET_MISMATCH", "project_id is not the workload's project", 403)
        return target

    @staticmethod
    def _region(region: Any) -> str:
        if not is_region(region):
            raise GcloudRefused("REGION_INVALID", "region must be a GCP region id (e.g. us-central1)")
        return region

    @staticmethod
    def _service(service: Any) -> str:
        if not is_rfc1123_label(service, 49):
            raise GcloudRefused("SERVICE_INVALID", "service must be a Cloud Run service name (RFC 1123, <= 49)")
        return service

    def _service_url(self, project: str, region: str, service: str) -> str:
        return f"{RUN_API}/projects/{project}/locations/{region}/services/{service}"

    # ------------------------------------------------------------------ inspection (row L14-g)
    def get_cloud_run_service(self, *, product_id: str, region: str, service: str,
                              project_id: Optional[str] = None) -> Dict[str, Any]:
        region, service = self._region(region), self._service(service)
        target = self._target(product_id, project_id)
        body = self._call("GET", self._service_url(target.project_id, region, service))
        return {"status": "OK", "project_id": target.project_id, "service": body}

    def list_cloud_run_services(self, *, product_id: str, region: str,
                                project_id: Optional[str] = None) -> Dict[str, Any]:
        region = self._region(region)
        target = self._target(product_id, project_id)
        items = self._list(f"{RUN_API}/projects/{target.project_id}/locations/{region}/services", "services")
        return {"status": "OK", "project_id": target.project_id, "services": items}

    def get_project_iam_policy(self, *, product_id: str, project_id: Optional[str] = None) -> Dict[str, Any]:
        target = self._target(product_id, project_id)
        body = self._call("POST", f"{CRM_API}/projects/{target.project_id}:getIamPolicy",
                          body={"options": {"requestedPolicyVersion": 3}})
        return {"status": "OK", "project_id": target.project_id, "policy": body}

    def list_service_accounts(self, *, product_id: str, project_id: Optional[str] = None) -> Dict[str, Any]:
        target = self._target(product_id, project_id)
        items = self._list(f"{IAM_API}/projects/{target.project_id}/serviceAccounts", "accounts")
        return {"status": "OK", "project_id": target.project_id, "accounts": items}

    def query_logs(self, *, product_id: str, severity: Optional[str] = None, resource_type: Optional[str] = None,
                   service_name: Optional[str] = None, since: Optional[str] = None, limit: int = 50,
                   project_id: Optional[str] = None) -> Dict[str, Any]:
        if not is_int(limit) or not 1 <= limit <= MAX_LOG_LIMIT:
            raise GcloudRefused("LIMIT_INVALID", f"limit must be an integer in 1..{MAX_LOG_LIMIT}")
        log_filter = build_log_filter(severity, resource_type, service_name, since)
        target = self._target(product_id, project_id)
        body = {"resourceNames": [f"projects/{target.project_id}"], "orderBy": "timestamp desc", "pageSize": limit}
        if log_filter:
            body["filter"] = log_filter
        res = self._call("POST", f"{LOGGING_API}/entries:list", body=body)
        return {"status": "OK", "project_id": target.project_id, "filter": log_filter,
                "entries": (res.get("entries") or [])[:limit]}

    # ------------------------------------------------------------------ ops (row L14-o; owner Q9 = A)
    def _ops_max(self) -> int:
        raw = str(self._env.get(OPS_MAX_INSTANCES_ENV) or "").strip()
        return int(raw) if raw.isdigit() and int(raw) > 0 else DEFAULT_OPS_MAX_INSTANCES

    def _audit_first(self, *, op: str, caller: str, target: seam.ManagedTarget, region: str, service: str,
                     before: Any, after: Any) -> Dict[str, Any]:
        record = {"op_id": f"gcmop-{uuid.uuid4().hex[:16]}", "op": op, "caller": caller or "unknown",
                  "product_id": target.product_id, "project_id": target.project_id, "region": region,
                  "service": service, "before": before, "after": after, "status": "PENDING",
                  "requested_at": self._clock().isoformat()}
        db = self._ledger_db()
        try:
            if db is None:
                raise RuntimeError("no Firestore client")
            db.collection(OPS_AUDIT_COLLECTION).document(record["op_id"]).set(record)
        except Exception as e:
            raise GcloudRefused("AUDIT_UNAVAILABLE", f"audit entry not written ({type(e).__name__}); op refused",
                                503) from e
        return record

    def _audit_finish(self, record: Dict[str, Any], status: str, detail: Any = None) -> bool:
        try:
            self._ledger_db().collection(OPS_AUDIT_COLLECTION).document(record["op_id"]).set(
                {"status": status, "detail": detail, "finished_at": self._clock().isoformat()}, merge=True)
            return True
        except Exception:
            return False

    def _patch_service(self, record: Dict[str, Any], url: str, mask: str, body: Dict[str, Any]) -> Dict[str, Any]:
        try:
            operation = self._call("PATCH", url, params={"updateMask": mask}, body=body)
        except GcloudRefused as e:
            self._audit_finish(record, f"FAILED:{e.code}", e.detail)
            raise
        finished = self._audit_finish(record, "SUBMITTED", operation.get("name"))
        return {"status": "SUBMITTED", "op_id": record["op_id"], "operation": operation.get("name"),
                "before": record["before"], "after": record["after"], "audit_finalized": finished}

    def update_cloud_run_scaling(self, *, product_id: str, region: str, service: str, min_instance_count: int,
                                 max_instance_count: int, caller: str = "unknown",
                                 project_id: Optional[str] = None) -> Dict[str, Any]:
        region, service = self._region(region), self._service(service)
        if not is_int(min_instance_count) or not is_int(max_instance_count):
            raise GcloudRefused("SCALING_INVALID", "min_instance_count and max_instance_count must be integers")
        if max_instance_count == 0:
            raise GcloudRefused("QUARANTINE_IS_ENFORCER_ONLY",
                                "scale-to-zero is the FinOps enforcer's restorable quarantine, not a gcloud op")
        bound = self._ops_max()
        if min_instance_count < 0 or max_instance_count < 1 or min_instance_count > max_instance_count \
                or max_instance_count > bound:
            raise GcloudRefused("SCALING_INVALID", f"need 0 <= min <= max <= {bound}")
        target = self._target(product_id, project_id)
        url = self._service_url(target.project_id, region, service)
        current = self._call("GET", url)
        scaling = (current.get("template") or {}).get("scaling") or {}
        before = {"minInstanceCount": scaling.get("minInstanceCount"), "maxInstanceCount": scaling.get("maxInstanceCount")}
        after = {"minInstanceCount": min_instance_count, "maxInstanceCount": max_instance_count}
        record = self._audit_first(op="update_cloud_run_scaling", caller=caller, target=target, region=region,
                                   service=service, before=before, after=after)
        return self._patch_service(record, url, "template.scaling.minInstanceCount,template.scaling.maxInstanceCount",
                                   {"template": {"scaling": after}})

    def update_cloud_run_traffic(self, *, product_id: str, region: str, service: str, traffic: Dict[str, int],
                                 caller: str = "unknown", project_id: Optional[str] = None) -> Dict[str, Any]:
        region, service = self._region(region), self._service(service)
        if not isinstance(traffic, dict) or not traffic:
            raise GcloudRefused("TRAFFIC_INVALID", "traffic must be a non-empty {revision: percent} object")
        for revision, percent in traffic.items():
            if not is_rfc1123_label(revision) or not is_int(percent) or not 0 <= percent <= 100:
                raise GcloudRefused("TRAFFIC_INVALID", "each entry is an RFC 1123 revision name -> integer 0..100")
        if sum(traffic.values()) != 100:
            raise GcloudRefused("TRAFFIC_INVALID", "percentages must sum to 100")
        target = self._target(product_id, project_id)
        url = self._service_url(target.project_id, region, service)
        current = self._call("GET", url)
        revisions = {str(r.get("name") or "").rpartition("/")[2] for r in self._list(f"{url}/revisions", "revisions")}
        missing = sorted(r for r in traffic if r not in revisions)
        if missing:
            raise GcloudRefused("REVISION_NOT_FOUND", f"{missing} are not revisions of {service}")
        after = [{"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION", "revision": r, "percent": p}
                 for r, p in sorted(traffic.items())]
        record = self._audit_first(op="update_cloud_run_traffic", caller=caller, target=target, region=region,
                                   service=service, before=current.get("traffic"), after=after)
        return self._patch_service(record, url, "traffic", {"traffic": after})

    def restart_cloud_run_service(self, *, product_id: str, region: str, service: str, caller: str = "unknown",
                                  project_id: Optional[str] = None) -> Dict[str, Any]:
        """A new revision with the same spec: only the template annotation `stackvend.dev/restarted-at` changes."""
        region, service = self._region(region), self._service(service)
        target = self._target(product_id, project_id)
        url = self._service_url(target.project_id, region, service)
        current = self._call("GET", url)
        annotations = dict((current.get("template") or {}).get("annotations") or {})
        before = {"latestReadyRevision": current.get("latestReadyRevision"),
                  RESTART_ANNOTATION: annotations.get(RESTART_ANNOTATION)}
        annotations[RESTART_ANNOTATION] = self._clock().isoformat()
        record = self._audit_first(op="restart_cloud_run_service", caller=caller, target=target, region=region,
                                   service=service, before=before, after={RESTART_ANNOTATION: annotations[RESTART_ANNOTATION]})
        return self._patch_service(record, url, "template.annotations", {"template": {"annotations": annotations}})

    # ------------------------------------------------------------------ dispatch
    def run_tool(self, tool: Any, args: Any, *, authorization: Optional[str] = None) -> Dict[str, Any]:
        """Typed dispatch for /exec and the MCP endpoint. Unknown tools and non-object args are refused. Ops verify the
        caller's bearer ID token first (RT F1: 401 CALLER_UNVERIFIED before any call); inspection needs no caller."""
        if tool not in INSPECTION_TOOLS + OPS_TOOLS:
            raise GcloudRefused("UNKNOWN_TOOL", f"tool must be one of {list(INSPECTION_TOOLS + OPS_TOOLS)}")
        if not isinstance(args, dict):
            raise GcloudRefused("ARGS_INVALID", "args must be an object")
        kwargs = dict(args)
        kwargs.pop("caller", None)  # the audited caller comes from the verified request, never from args
        if tool in OPS_TOOLS:
            kwargs["caller"] = caller_from_authorization(authorization, verify=self._verify_caller)
        fn = getattr(self, tool)
        try:
            inspect.signature(fn).bind(**kwargs)
        except TypeError as e:
            raise GcloudRefused("ARGS_INVALID", f"{tool}: {e}") from e
        return fn(**kwargs)
