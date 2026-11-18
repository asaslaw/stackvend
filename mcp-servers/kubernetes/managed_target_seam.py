"""
Managed-target identity seam + human approval check for the lane 14 MCP servers (agent-builder, kubernetes, gcloud,
github).

IDENTICAL COPIES: mcp-servers/{agent-builder,kubernetes,gcloud,github}/managed_target_seam.py (each server deploys
alone; parity enforced by tests/test_lane14_mcp_helm.py::test_seam_copies_are_identical). All are replaced by the
vendored root `shared/managed_target.py` when lane 14 PR-M lands (lane 12 manifest).

SEAM(lane 14 PR-M): `verify_ledger_target` is the ledger-only subset of `verify_managed_target` (plan §1.1 checks
2 and 4 + reverse uniqueness), the same subset the SRE digest uses today. PR-M adds provenance, CRM identity, the
IAM-gated tag and folder ancestry. Refusal codes are lane 18's. Read-only; exact comparisons only.

Approvals (plan §3 common; docs/planning/mcp-action-approval-plan.md): lane 18's `destructive_approvals/{id}` record
shape, read from the guard database (`STACKVEND_GUARD_FIRESTORE_DATABASE`, lane 18 S0b) for a local pre-check. The
MCP server never writes an approval. A call without an approval records an `approval_requests/{id}` card
(`MCP_ACTION`, default database) for a human administrator in the Control Center; only the Control Center mints the
approval, bound to the exact action, target and arguments (`binding`). Consumption is project-vending's
`POST /approvals/{id}/consume` (one Firestore transaction on the guard database), called with this server's ID
token; anything but its 200 refuses the action, and an unreachable vending is APPROVAL_CONSUME_UNAVAILABLE (fail
closed). Nothing machine-driven goes through the Control Center (owner 11-07).
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Mapping, Optional, Tuple
from urllib.parse import urlsplit

SEAM_VERSION = 1

GUARD_DB_ENV = "STACKVEND_GUARD_FIRESTORE_DATABASE"
VENDING_URL_ENV = "VENDING_SERVICE_URL"
VENDING_SERVICE = "project-repo-vending-service"
CLOUD_RUN_HOST_SUFFIX = ".run.app"
METADATA_BASE = "http://metadata.google.internal/computeMetadata/v1/"

INACTIVE_STATUSES = frozenset({"DECOMMISSIONED", "QUARANTINED", "DELETED"})

APPROVAL_COLLECTION = "destructive_approvals"
APPROVAL_STATUS_APPROVED = "APPROVED"
APPROVAL_SPENT_STATUSES = frozenset({"CONSUMED", "EXECUTED", "EXECUTION_FAILED"})  # vending's single-use states
APPROVAL_PRINCIPAL_USER = "USER"
APPROVAL_ROLE_ADMIN = "ADMIN"
SERVICE_ACCOUNT_EMAIL_SUFFIX = ".gserviceaccount.com"

# MCP action approvals (docs/planning/mcp-action-approval-plan.md §2). The SAME table and digest live in
# apps/control-center/destructive_actions.py and apps/project-vending/mcp_approvals.py (parity-tested).
MCP_ACTION_BINDING_KEYS = {
    "HELM_UNINSTALL": ("cluster", "location", "namespace", "release"),
    "AGENT_ENGINE_DEPLOY": ("agent_name", "display_name", "source_digest"),
    "DATASTORE_CREATE": ("datastore_id", "location", "content_type"),
}
REQUEST_COLLECTION = "approval_requests"
REQUEST_TYPE = "MCP_ACTION"
REQUEST_STATUS_PENDING = "PENDING"


class TargetRefused(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


class ApprovalRefused(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


@dataclass(frozen=True)
class ManagedTarget:
    product_id: str
    project_id: str
    workload: Dict[str, Any]


def _field_filter(field_path: str, value: Any):
    from google.cloud.firestore_v1.base_query import FieldFilter

    return FieldFilter(field_path, "==", value)


def host_project_ids(env: Optional[Mapping[str, str]] = None) -> frozenset:
    env = os.environ if env is None else env
    return frozenset(v for v in (env.get("PROJECT_ID"), env.get("PLATFORM_PROJECT_ID")) if v)


def verify_ledger_target(db: Any, product_id: str, host_ids: frozenset,
                         field_filter: Optional[Callable[[str, Any], Any]] = None) -> ManagedTarget:
    """Ledger identity of a managed workload. Raises TargetRefused with a lane 18 code."""
    field_filter = field_filter or _field_filter
    if not host_ids:
        raise TargetRefused("GUARD_UNCONFIGURED", "PROJECT_ID is not set")
    if not isinstance(product_id, str) or not product_id or "/" in product_id:
        raise TargetRefused("LEDGER_MISSING", "product_id is required")
    if db is None:
        raise TargetRefused("LEDGER_UNAVAILABLE", "no Firestore client")
    try:
        snap = db.collection("workloads").document(product_id).get()
    except Exception as e:
        raise TargetRefused("LEDGER_UNAVAILABLE", f"{type(e).__name__}") from e
    if not getattr(snap, "exists", False):
        raise TargetRefused("LEDGER_MISSING", product_id)
    data = snap.to_dict() or {}
    if data.get("is_castor") is True:
        raise TargetRefused("PLATFORM_WORKLOAD", product_id)
    project_id = data.get("project_id")
    if not isinstance(project_id, str) or not project_id:
        raise TargetRefused("LEDGER_MISMATCH", "ledger doc has no project_id")
    if project_id in host_ids:
        raise TargetRefused("HOST_PROJECT", project_id)
    if data.get("status") in INACTIVE_STATUSES:
        raise TargetRefused("NOT_ACTIVE", str(data.get("status")))
    try:
        same = list(db.collection("workloads").where(filter=field_filter("project_id", project_id)).limit(2).stream())
    except Exception as e:
        raise TargetRefused("LEDGER_UNAVAILABLE", f"{type(e).__name__}") from e
    if [getattr(d, "id", None) for d in same] != [product_id]:
        raise TargetRefused("LEDGER_MISMATCH", f"{project_id} is not owned by exactly {product_id}")
    return ManagedTarget(product_id=product_id, project_id=project_id, workload=data)


def _as_datetime(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _is_human_email(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    local, sep, domain = value.rpartition("@")
    return bool(sep and local and domain and "." in domain and not value.lower().endswith(SERVICE_ACCOUNT_EMAIL_SUFFIX))


def binding_digest(binding: Mapping[str, str]) -> str:
    """SHA-256 of the canonical JSON of a binding (sorted keys, compact separators)."""
    canonical = json.dumps(dict(binding), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def validate_binding(action: str, binding: Any) -> Dict[str, str]:
    """Exactly the action's binding keys, each a non-empty string. Raises ApprovalRefused(APPROVAL_BINDING_INVALID)."""
    keys = MCP_ACTION_BINDING_KEYS.get(action)
    if keys is None:
        raise ApprovalRefused("APPROVAL_BINDING_INVALID", f"{action!r} is not an MCP approval action")
    if not isinstance(binding, Mapping) or set(binding) != set(keys) \
            or not all(isinstance(binding[k], str) and binding[k] for k in keys):
        raise ApprovalRefused("APPROVAL_BINDING_INVALID", f"{action} binding must be exactly {list(keys)} (strings)")
    return {k: binding[k] for k in keys}


def check_approval(guard_db: Any, approval_id: Optional[str], *, action: str, product_id: str, project_id: str,
                   binding: Optional[Mapping[str, str]] = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Lane 18 check 9a rules for an MCP mutating tool, plus the argument binding when one is given. Returns the
    record; raises ApprovalRefused. Vending repeats every check inside its consume transaction (authoritative)."""
    if not isinstance(approval_id, str) or not approval_id or "/" in approval_id:
        raise ApprovalRefused("APPROVAL_REQUIRED", f"{action} needs an approved operator record (approval_id)")
    if guard_db is None:
        raise ApprovalRefused("APPROVAL_UNAVAILABLE", "no Firestore client")
    try:
        snap = guard_db.collection(APPROVAL_COLLECTION).document(approval_id).get()
    except Exception as e:
        raise ApprovalRefused("APPROVAL_UNAVAILABLE", type(e).__name__) from e
    if not getattr(snap, "exists", False):
        raise ApprovalRefused("APPROVAL_NOT_FOUND", approval_id)
    rec = snap.to_dict() or {}
    now = now or datetime.now(timezone.utc)
    if rec.get("consumed_at") or rec.get("status") in APPROVAL_SPENT_STATUSES:
        raise ApprovalRefused("APPROVAL_CONSUMED", str(rec.get("consumed_at") or rec.get("status")))
    if rec.get("status") != APPROVAL_STATUS_APPROVED:
        raise ApprovalRefused("APPROVAL_NOT_APPROVED", str(rec.get("status")))
    if rec.get("action") != action:
        raise ApprovalRefused("APPROVAL_ACTION_MISMATCH", f"{rec.get('action')!r} != {action!r}")
    if rec.get("product_id") != product_id or rec.get("project_id") != project_id:
        raise ApprovalRefused("APPROVAL_TARGET_MISMATCH", "approval was granted for a different workload")
    if rec.get("principal_type") != APPROVAL_PRINCIPAL_USER:
        raise ApprovalRefused("APPROVAL_NOT_HUMAN", str(rec.get("principal_type")))
    if rec.get("approved_by_role") != APPROVAL_ROLE_ADMIN:
        raise ApprovalRefused("APPROVAL_NOT_ADMIN", str(rec.get("approved_by_role")))
    if not _is_human_email(rec.get("approved_by")):
        raise ApprovalRefused("APPROVAL_APPROVER_UNVERIFIED", "approved_by is not a user email")
    expires = _as_datetime(rec.get("expires_at"))
    if expires is None:
        raise ApprovalRefused("APPROVAL_INVALID", "expires_at missing or unreadable")
    if now >= expires:
        raise ApprovalRefused("APPROVAL_EXPIRED", expires.isoformat())
    if binding is not None and rec.get("binding_digest") != binding_digest(validate_binding(action, binding)):
        raise ApprovalRefused("APPROVAL_BINDING_MISMATCH", "approval was granted for different arguments")
    return rec


def _request_id(action: str, product_id: str, project_id: str, digest: str) -> str:
    key = hashlib.sha256("\n".join((action, product_id, project_id, digest)).encode("utf-8")).hexdigest()[:20]
    return f"mcp-{action.lower().replace('_', '-')}-{key}"


def record_approval_request(db: Any, *, action: str, product_id: str, project_id: str, binding: Mapping[str, str],
                            requested_by: str, reason: str, details: Optional[Mapping[str, Any]] = None,
                            now: Optional[datetime] = None, new_id: Optional[Callable[[], str]] = None) -> str:
    """Writes (or finds) the PENDING `approval_requests/{id}` MCP_ACTION card a human administrator decides in the
    Control Center. The card carries no authority (the Control Center re-reads the target from the ledger). A repeat
    call while the card is PENDING returns the same id; once decided, a new card is opened. Returns the request id;
    raises ApprovalRefused(APPROVAL_REQUEST_NOT_RECORDED) when it cannot be written (fail loudly)."""
    clean = validate_binding(action, binding)
    digest = binding_digest(clean)
    if db is None:
        raise ApprovalRefused("APPROVAL_REQUEST_NOT_RECORDED", "no Firestore client")
    now = now or datetime.now(timezone.utc)
    request_id = _request_id(action, product_id, project_id, digest)
    try:
        snap = db.collection(REQUEST_COLLECTION).document(request_id).get()
        if getattr(snap, "exists", False):
            existing = snap.to_dict() or {}
            if existing.get("status") == REQUEST_STATUS_PENDING and existing.get("mcp_binding_digest") == digest:
                return request_id
            request_id = f"{request_id}-{(new_id or (lambda: uuid.uuid4().hex))()[:8]}"
        db.collection(REQUEST_COLLECTION).document(request_id).create({
            "approval_id": request_id, "approval_type": REQUEST_TYPE, "status": REQUEST_STATUS_PENDING,
            "product_id": product_id, "trace_id": "", "mcp_action": action, "mcp_project_id": project_id,
            "mcp_binding": clean, "mcp_binding_digest": digest, "mcp_details": dict(details or {}),
            "mcp_requested_by": requested_by, "reason": reason, "requested_at": now.isoformat(),
            "risk_assessment": f"{requested_by} asks to run {action} in {project_id}: "
                               + ", ".join(f"{k}={clean[k]}" for k in sorted(clean)),
        })
    except Exception as e:
        raise ApprovalRefused("APPROVAL_REQUEST_NOT_RECORDED", type(e).__name__) from e
    return request_id


def id_token_audience(url: str) -> Optional[str]:
    try:
        parts = urlsplit(url or "")
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host or parts.username is not None or parts.password is not None:
        return None
    if port not in (None, 443) or not host.endswith(CLOUD_RUN_HOST_SUFFIX):
        return None
    return f"https://{host}"


def _default_metadata_get(path: str) -> str:
    import requests

    res = requests.get(METADATA_BASE + path, headers={"Metadata-Flavor": "Google"}, timeout=5.0)
    if res.status_code != 200:
        raise RuntimeError(f"metadata {path}: HTTP {res.status_code}")
    return res.text.strip()


def platform_service_url(service_name: str, env_var: str, metadata_get: Optional[Callable[[str], str]] = None) -> str:
    """`$env_var`, else `https://<service>-<number>.<region>.run.app` from this Cloud Run runtime's metadata."""
    explicit = (os.getenv(env_var) or "").strip().rstrip("/")
    if explicit:
        return explicit
    if not (os.getenv("K_SERVICE") or os.getenv("CLOUD_RUN_JOB")):
        raise RuntimeError(f"{env_var} unset and not running on Cloud Run")
    get = metadata_get or _default_metadata_get
    number = get("project/numeric-project-id")
    parts = get("instance/region").split("/")
    if not number.isdigit() or len(parts) != 4 or parts[0] != "projects" or parts[2] != "regions" or not parts[3]:
        raise RuntimeError("metadata server returned an unexpected project number / region")
    return f"https://{service_name}-{number}.{parts[3]}.run.app"


def _default_id_token(audience: str) -> str:
    from google.auth.transport.requests import Request
    from google.oauth2 import id_token as google_id_token

    token = google_id_token.fetch_id_token(Request(), audience)
    if not isinstance(token, str) or not token:
        raise RuntimeError("empty ID token")
    return token


def _default_post(url: str, body: Dict[str, Any], headers: Dict[str, str], timeout: float) -> Tuple[int, Any]:
    import requests

    res = requests.post(url, json=body, headers=headers, timeout=timeout, allow_redirects=False)
    try:
        return res.status_code, res.json()
    except ValueError:
        return res.status_code, None


def _vending_code(payload: Any) -> Optional[str]:
    detail = payload.get("detail") if isinstance(payload, dict) else None
    code = detail.get("code") if isinstance(detail, dict) else None
    return code if isinstance(code, str) and code else None


def consume_approval(approval_id: str, *, action: str, product_id: str, project_id: str, binding: Mapping[str, str],
                     post: Optional[Callable[..., Tuple[int, Any]]] = None,
                     id_token: Optional[Callable[[str], str]] = None,
                     metadata_get: Optional[Callable[[str], str]] = None) -> Dict[str, Any]:
    """Asks project-vending to consume the approval (single use, one transaction). Returns vending's CONSUMED answer;
    raises ApprovalRefused with vending's typed code on a refusal, APPROVAL_CONSUME_UNAVAILABLE when vending cannot
    be reached or answers without a typed code, and APPROVAL_CONSUME_FAILED on any other answer."""
    clean = validate_binding(action, binding)
    try:
        base = platform_service_url(VENDING_SERVICE, VENDING_URL_ENV, metadata_get)
    except RuntimeError as e:
        raise ApprovalRefused("APPROVAL_CONSUME_UNAVAILABLE", str(e)) from e
    audience = id_token_audience(base)
    headers: Dict[str, str] = {}
    if audience is not None:
        try:
            headers["Authorization"] = f"Bearer {(id_token or _default_id_token)(audience)}"
        except Exception as e:
            raise ApprovalRefused("APPROVAL_CONSUME_UNAVAILABLE", f"ID token: {type(e).__name__}") from e
    elif os.getenv("K_SERVICE") or os.getenv("CLOUD_RUN_JOB"):
        raise ApprovalRefused("APPROVAL_CONSUME_UNAVAILABLE", f"{base!r} is not an https Cloud Run URL")
    body = {"action": action, "product_id": product_id, "project_id": project_id, "binding": clean}
    try:
        status, payload = (post or _default_post)(f"{base}/approvals/{approval_id}/consume", body, headers, 30.0)
    except Exception as e:
        raise ApprovalRefused("APPROVAL_CONSUME_UNAVAILABLE", f"{type(e).__name__}") from e
    if status == 200:
        if isinstance(payload, dict) and payload.get("status") == "CONSUMED" \
                and payload.get("approval_id") == approval_id:
            return payload
        raise ApprovalRefused("APPROVAL_CONSUME_FAILED", "vending answered 200 without a CONSUMED record")
    code = _vending_code(payload)
    if isinstance(status, int) and status >= 500:
        raise ApprovalRefused("APPROVAL_CONSUME_UNAVAILABLE", f"vending HTTP {status} {code or ''}".rstrip())
    if code:
        raise ApprovalRefused(code, f"vending HTTP {status}")
    if status in (404, 405):
        raise ApprovalRefused("APPROVAL_CONSUME_UNAVAILABLE", f"vending HTTP {status} (consume route not live)")
    raise ApprovalRefused("APPROVAL_CONSUME_FAILED", f"vending HTTP {status}")


def guard_database_name(env: Optional[Mapping[str, str]] = None) -> str:
    env = os.environ if env is None else env
    return (env.get(GUARD_DB_ENV) or "").strip()
