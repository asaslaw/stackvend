"""
StackVend project vending: single-use consumption of MCP action approvals (register row APPROVAL-CONSUME-VIA-VENDING,
owner 11-07; docs/planning/mcp-action-approval-plan.md).

Three MCP tools act only with a human administrator's approval: `helm_uninstall` (HELM_UNINSTALL), Agent Engine deploy
(AGENT_ENGINE_DEPLOY) and Discovery Engine datastore create (DATASTORE_CREATE). The Control Center mints the approval
(`destructive_approvals/{id}` in the guard database, human ADMIN session only) bound to the exact action, target and
arguments (`binding`). The MCP server then calls `POST /approvals/{id}/consume` here with its ID token; vending is the
only machine-facing consumer (nothing machine-driven goes through the Control Center).

Inside ONE Firestore transaction on the guard database the record must: exist; not be consumed; be APPROVED; name an
MCP action (decommission / lifecycle approvals are never consumable here); name the same action, product and project;
carry the same binding digest (and its own binding must hash to it); have been minted by a human ADMIN; be inside its
window (lane 18's rule: at most 15 minutes, approved_at not in the future, now < expires_at). Then it becomes CONSUMED
with consumed_at / consumed_by. A record read back without this call's stamp is APPROVAL_CONSUMED (lost race).
Every refusal is a typed ConsumeRefused(code, detail, http_status); nothing is consumed on a refusal.

The binding table and digest are the SAME as in mcp-servers/*/managed_target_seam.py and
apps/control-center/destructive_actions.py (tests/test_mcp_action_approvals.py checks the three agree).
"""
import hashlib
import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

import destructive_guard as dg

MCP_ACTION_BINDING_KEYS = {
    "HELM_UNINSTALL": ("cluster", "location", "namespace", "release"),
    "AGENT_ENGINE_DEPLOY": ("agent_name", "display_name", "source_digest"),
    "DATASTORE_CREATE": ("datastore_id", "location", "content_type"),
}
CONSUMERS_ENV = "MCP_APPROVAL_CONSUMERS"
# The kubernetes and agent-builder MCP servers run as sa-castor-developer (infra/platform: not in
# local.service_runtime_sa). Without the env var the allow-list is that account in this host project (the same
# narrow default as GITHUB_TOKEN_ALLOWED_CALLERS); Terraform also sets it explicitly (destructive_guard.tf).
DEFAULT_CONSUMER_ACCOUNT = "sa-castor-developer"
CONSUMED_VIA = "vending:/approvals/consume"
MAX_APPROVAL_ID_LENGTH = 128
_SPENT_STATUSES = frozenset({"CONSUMED", "EXECUTED", "EXECUTION_FAILED"})


class ConsumeRefused(Exception):
    def __init__(self, code: str, detail: str, http_status: int):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.http_status = code, detail, http_status


def binding_digest(binding: Mapping[str, str]) -> str:
    canonical = json.dumps(dict(binding), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def clean_binding(action: str, binding: Any) -> Dict[str, str]:
    keys = MCP_ACTION_BINDING_KEYS[action]
    if not isinstance(binding, Mapping) or set(binding) != set(keys) \
            or not all(isinstance(binding[k], str) and binding[k] for k in keys):
        raise ConsumeRefused("INVALID_REQUEST", f"{action} binding must be exactly {list(keys)} (strings)", 422)
    return {k: binding[k] for k in keys}


def consumer_config_from_env() -> Tuple[FrozenSet[str], List[str]]:
    raw = os.getenv(CONSUMERS_ENV)
    if raw is not None and raw.strip():
        callers = dg._csv_emails(raw)
    else:
        host = (os.getenv("PROJECT_ID") or "").strip()
        callers = frozenset({f"{DEFAULT_CONSUMER_ACCOUNT}@{host}.iam.gserviceaccount.com".lower()}) if host \
            else frozenset()
    _, audiences = dg.caller_config_from_env()
    return callers, audiences


def _is_human_email(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    local, sep, domain = value.rpartition("@")
    return bool(sep and local and domain and "." in domain
                and not value.lower().endswith(".gserviceaccount.com"))


def check_record(rec: Optional[Dict[str, Any]], *, approval_id: str, action: str, product_id: str, project_id: str,
                 digest: str, now: datetime) -> None:
    """Every rule, in a fixed order. Raises ConsumeRefused. Read-only."""
    if rec is None:
        raise ConsumeRefused("APPROVAL_NOT_FOUND", approval_id, 404)
    if rec.get("consumed_at") or rec.get("status") in _SPENT_STATUSES:
        raise ConsumeRefused("APPROVAL_CONSUMED", f"approval {approval_id} was already used", 409)
    if rec.get("status") != "APPROVED":
        raise ConsumeRefused("APPROVAL_NOT_APPROVED", f"approval status is {rec.get('status')!r}", 409)
    if rec.get("action") not in MCP_ACTION_BINDING_KEYS:
        raise ConsumeRefused("APPROVAL_ACTION_NOT_CONSUMABLE",
                             f"{rec.get('action')!r} approvals are not consumed through this route", 403)
    if rec.get("action") != action:
        raise ConsumeRefused("APPROVAL_ACTION_MISMATCH", f"{rec.get('action')!r} != {action!r}", 403)
    if rec.get("product_id") != product_id or rec.get("project_id") != project_id:
        raise ConsumeRefused("APPROVAL_TARGET_MISMATCH", "approval was granted for a different workload", 403)
    rec_binding = rec.get("binding")
    try:
        rec_digest = binding_digest(clean_binding(action, rec_binding))
    except ConsumeRefused:
        rec_digest = None
    if rec_digest is None or rec.get("binding_digest") != rec_digest or rec_digest != digest:
        raise ConsumeRefused("APPROVAL_BINDING_MISMATCH", "approval was granted for different arguments", 403)
    if rec.get("principal_type") != "USER" or rec.get("approved_by_role") != "ADMIN" \
            or not _is_human_email(rec.get("approved_by")):
        raise ConsumeRefused("APPROVAL_NOT_HUMAN", "approval was not minted by a human ADMIN session", 403)
    approved_at, expires_at = dg._parse_ts(rec.get("approved_at")), dg._parse_ts(rec.get("expires_at"))
    if approved_at is None or expires_at is None or not approved_at < expires_at \
            or expires_at - approved_at > dg.APPROVAL_MAX_LIFETIME \
            or approved_at > now + timedelta(seconds=dg.CLOCK_SKEW_SECONDS) \
            or not now < expires_at:
        raise ConsumeRefused("APPROVAL_EXPIRED",
                             "approval is expired, dated in the future, or has no valid 15-minute window", 403)


def consume(store: "dg.FirestoreGuardStore", approval_id: str, *, action: Any, product_id: Any, project_id: Any,
            binding: Any, caller_email: str, now: datetime) -> Dict[str, Any]:
    """Atomically consumes one MCP action approval. Returns the CONSUMED answer; raises ConsumeRefused."""
    if not isinstance(approval_id, str) or not approval_id or "/" in approval_id \
            or len(approval_id) > MAX_APPROVAL_ID_LENGTH:
        raise ConsumeRefused("INVALID_REQUEST", "approval_id is malformed", 422)
    if action not in MCP_ACTION_BINDING_KEYS:
        raise ConsumeRefused("APPROVAL_ACTION_NOT_CONSUMABLE",
                             f"{action!r} approvals are not consumed through this route", 403)
    for label, value in (("product_id", product_id), ("project_id", project_id)):
        if not isinstance(value, str) or not value:
            raise ConsumeRefused("INVALID_REQUEST", f"{label} is required", 422)
    digest = binding_digest(clean_binding(action, binding))
    stamp = now.isoformat()

    def _check(rec: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        check_record(rec, approval_id=approval_id, action=action, product_id=product_id, project_id=project_id,
                     digest=digest, now=now)
        return {"status": "CONSUMED", "consumed_at": stamp, "consumed_by": caller_email,
                "consumed_via": CONSUMED_VIA}

    try:
        store.consume_approval_checked(approval_id, _check)
    except ConsumeRefused:
        raise
    except dg.StoreUnavailable as e:
        raise ConsumeRefused("APPROVAL_UNAVAILABLE", str(e), 503) from None
    try:
        after = store.get_approval(approval_id) or {}
    except dg.StoreUnavailable as e:
        raise ConsumeRefused("APPROVAL_UNAVAILABLE", f"consumed, but the record could not be re-read: {e}", 503) \
            from None
    if after.get("consumed_at") != stamp or after.get("consumed_by") != caller_email:
        raise ConsumeRefused("APPROVAL_CONSUMED", f"approval {approval_id} was consumed by someone else", 409)
    return {"status": "CONSUMED", "approval_id": approval_id, "action": action, "product_id": product_id,
            "project_id": project_id, "consumed_at": stamp, "consumed_by": caller_email,
            "approved_by": after.get("approved_by")}
