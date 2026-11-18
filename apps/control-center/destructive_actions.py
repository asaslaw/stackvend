"""
StackVend Control Center: destructive actions go through project-vending (wave 2 lane 18, step S2).

Plan: docs/planning/wave2-lane18-destructive-guards-plan.md §2.5 / §3.2; S1 code red-team "minimum S2 content".
Register row 26 (owner 10-12) and rows L18-a/b/e/f/g.

The Control Center never deletes a GCP project itself (the in-process CRM fallback is gone). Vending is the only
executor and runs the destructive guard (apps/project-vending/destructive_guard.py). The CC:

* mints a single-use approval `destructive_approvals/{uuid}` for a human ADMIN request -- `principal_type` comes from
  the auth layer (authz.principal_type: IAP / session => "USER"), never from the email text -- with the exact action
  and target (product, project id and number from the ledger) and a 15-minute window; the record lives in the guard
  database (env STACKVEND_GUARD_FIRESTORE_DATABASE, lane 18 S0b) when that is set;
* calls vending with its own Google ID token for the vending URL (routes.settings.make_vending_request) and
* on any non-200 answer surfaces vending's `{code, detail}` as HTTP 502 and changes nothing in the ledger; its own
  approval refusals (MintRefused) keep their status and carry the same typed `code` (refusal_response).

Approval record schema (checked by vending, destructive_guard.check_approval): status "APPROVED"; action; product_id;
project_id; project_number; resource_name (None for project-level actions); principal_type "USER"; approved_by (the
verified email); approved_by_role "ADMIN"; approved_at; expires_at (= approved_at + 15 min).

MCP action approvals (register row APPROVAL-CONSUME-VIA-VENDING, owner 11-07; docs/planning/mcp-action-approval-plan.md):
HELM_UNINSTALL, AGENT_ENGINE_DEPLOY and DATASTORE_CREATE are minted the same way from an MCP_ACTION approval card
(routes/approvals.py) and additionally carry `binding` (the exact tool arguments, MCP_ACTION_BINDING_KEYS),
`binding_digest` and `request_id`. The MCP server consumes them through project-vending, never through the CC.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from typing import Any, Callable, Dict, Optional
import uuid

from authz import PRINCIPAL_USER, principal_type
# C10: one definition of the sweep vocabulary and helpers for the Control Center and the sandbox-workload-sweeper-job.
from shared.sandbox_sweep import (  # noqa: F401 - re-exported (destructive_actions.<name> is the CC's spelling)
    DECOMMISSION_TIMEOUT_SECONDS,
    EXPLICIT_DESIGNATION_SOURCES,
    SANDBOX_TTL,
    TTL_AUTHORITY_DISPLAY_ONLY,
    sandbox_awaiting_confirmation,
    sandbox_notice_suffix,
    vending_error as _vending_error,
)
from db import get_guard_db
from schemas import UserRole

logger = logging.getLogger("control-center-destructive-actions")

APPROVALS = "destructive_approvals"
PROVENANCE = "workload_provenance"
APPROVAL_LIFETIME = timedelta(minutes=15)

PROJECT_DECOMMISSION = "PROJECT_DECOMMISSION"
CONFIRM_SANDBOX = "CONFIRM_SANDBOX"

# MCP action approvals. The SAME table and digest live in mcp-servers/*/managed_target_seam.py and
# apps/project-vending/mcp_approvals.py (tests/test_mcp_action_approvals.py checks the three agree).
MCP_ACTION_BINDING_KEYS = {
    "HELM_UNINSTALL": ("cluster", "location", "namespace", "release"),
    "AGENT_ENGINE_DEPLOY": ("agent_name", "display_name", "source_digest"),
    "DATASTORE_CREATE": ("datastore_id", "location", "content_type"),
}


def binding_digest(binding: Dict[str, str]) -> str:
    canonical = json.dumps(dict(binding), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def clean_mcp_binding(action: Any, binding: Any) -> Optional[Dict[str, str]]:
    """The binding with exactly the action's keys (non-empty strings), else None."""
    keys = MCP_ACTION_BINDING_KEYS.get(action) if isinstance(action, str) else None
    if keys is None or not isinstance(binding, dict) or set(binding) != set(keys) \
            or not all(isinstance(binding[k], str) and binding[k] for k in keys):
        return None
    return {k: binding[k] for k in keys}

# Sandbox designation vocabulary: CC ledger value -> vending vend-request value (exact table, lane 14 Q1 / lane 18 9b).
# Only OPERATOR_CHECKBOX / API_FIELD / OPERATOR_CONFIRMED are ever TTL-eligible; KEYWORD is recorded, never eligible.
VEND_DESIGNATION_SOURCE = {
    "OPERATOR_CHECKBOX": "OPERATOR_CHECKBOX",
    "API_FIELD": "API_FIELD",
    "OPERATOR_CONFIRMED": "OPERATOR_CONFIRMED",
    "KEYWORD_DETECTED": "KEYWORD",
    "KEYWORD": "KEYWORD",
}
# EXPLICIT_DESIGNATION_SOURCES: shared.sandbox_sweep (C10; imported at the top of this module).
MAX_VEND_TTL_DAYS = 90  # vending's MAX_SANDBOX_TTL_DAYS

# Where a sandbox's expiry is enforced (ledger field `ttl_authority`, lane 18 window RT H3). VENDING_PROVENANCE: the
# vend-time provenance that vending's SANDBOX_TTL guard enforces. LEDGER_DISPLAY_ONLY: vending answered
# LEDGER_UNPROVENANCED / SANDBOX_NOT_ELIGIBLE to an extend or promote, so nothing will ever auto-delete the project and
# the ledger countdown is informational only.
TTL_AUTHORITY_VENDING = "VENDING_PROVENANCE"
# TTL_AUTHORITY_DISPLAY_ONLY = "LEDGER_DISPLAY_ONLY": shared.sandbox_sweep (C10).

# Project-delete calls can take a while inside vending (guard reads + F8 re-check, each CRM call up to 10 s, then DNS,
# state archive and IPAM). The CC waits long enough that a slow success is not reported as VENDING_UNREACHABLE
# (lane 18 window RT H4; the CC's Cloud Run request timeout is far above this).
# DECOMMISSION_TIMEOUT_SECONDS = 180.0: shared.sandbox_sweep (C10; the sweeper job uses the same timeout).


class MintRefused(Exception):
    def __init__(self, http_status: int, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.http_status, self.code, self.detail = http_status, code, detail


@dataclass
class VendingOutcome:
    ok: bool
    http_status: int          # vending's HTTP status (0 = no answer)
    code: str
    detail: str
    body: Dict[str, Any] = field(default_factory=dict)


def _digits(value) -> str:
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value) if value > 0 else ""
    if isinstance(value, str) and value.isdigit():
        return value
    return ""


def resolve_target(product_id: str, workload: Dict[str, Any]) -> Dict[str, str]:
    """Project id and number for an approval, from the ledger (vending writes both at vend; its guard refuses when the
    ledger number differs from the provenance number). When the ledger has no number, the provenance record in the
    guard database is read (best effort). Missing values are "" (no approval is minted; vending reports why)."""
    project_id = workload.get("project_id") if isinstance(workload.get("project_id"), str) else ""
    number = _digits(workload.get("project_number"))
    if project_id and not number:
        try:
            gdb = get_guard_db()
            snap = gdb.collection(PROVENANCE).document(product_id).get() if gdb else None
            prov = (snap.to_dict() or {}) if snap is not None and getattr(snap, "exists", False) is True else {}
            if prov.get("project_id") == project_id:
                number = _digits(prov.get("project_number"))
        except Exception as e:  # noqa: BLE001 - the approval is then not minted; vending refuses with its own code
            logger.warning(f"Could not read provenance of '{product_id}' for the approval target: {e}")
    return {"project_id": project_id or "", "project_number": number}


def ledger_target_refusal(db, product_id: str, project_id: str, env=None) -> Optional[str]:
    """APPROVAL-CONSUME-VIA-VENDING RT F4: the MCP seam's remaining ledger rules (verify_ledger_target) before an MCP
    approval is minted. Returns a reason (the approval is then refused APPROVAL_TARGET_UNKNOWN) or None:
    no host project id configured, the project is a host project, or not exactly this workload claims it. A
    Firestore error is a reason too (fail closed)."""
    import os
    env = os.environ if env is None else env
    hosts = {v for v in (env.get("PROJECT_ID"), env.get("PLATFORM_PROJECT_ID")) if v}
    if not hosts:
        return "PROJECT_ID is not set"
    if project_id in hosts:
        return f"{project_id} is a host project"
    try:
        claimers = [getattr(d, "id", None)
                    for d in db.collection("workloads").where("project_id", "==", project_id).limit(2).stream()]
    except Exception as e:  # noqa: BLE001
        return f"ledger reverse lookup failed ({type(e).__name__})"
    if claimers != [product_id]:
        return f"{project_id} is not owned by exactly {product_id}"
    return None


def mint_approval(request, *, action: str, product_id: str, project_id: str, project_number: str,
                  reason: Optional[str] = None, now: Optional[datetime] = None,
                  delete_without_archive: bool = False, binding: Optional[Dict[str, str]] = None,
                  request_id: Optional[str] = None) -> str:
    """Writes destructive_approvals/{uuid} for this exact action and target. Only a human (principal_type USER) with the
    ADMIN role may mint; raises MintRefused (403/503) otherwise. Returns the approval id. An MCP action
    (MCP_ACTION_BINDING_KEYS) must carry its exact binding (MintRefused 409 APPROVAL_BINDING_INVALID otherwise); any
    other action never carries one."""
    state = getattr(request, "state", None)
    if principal_type(request) != PRINCIPAL_USER:
        raise MintRefused(403, "APPROVAL_NOT_HUMAN", "destructive actions need a human session (IAP or sign-in)")
    role = getattr(state, "user_role", None)
    if role != UserRole.ADMIN and role != UserRole.ADMIN.value:
        raise MintRefused(403, "APPROVAL_NOT_ADMIN", "destructive actions need the ADMIN role")
    email = getattr(state, "user_email", None)
    if not isinstance(email, str) or not email.strip():
        raise MintRefused(401, "APPROVAL_NOT_HUMAN", "no verified email on this session")
    if not product_id or not project_id or not _digits(project_number):
        raise MintRefused(409, "APPROVAL_TARGET_UNKNOWN", "the ledger has no project id and number for this workload")
    clean_binding = None
    if action in MCP_ACTION_BINDING_KEYS:
        clean_binding = clean_mcp_binding(action, binding)
        if clean_binding is None:
            raise MintRefused(409, "APPROVAL_BINDING_INVALID", f"{action} needs exactly {list(MCP_ACTION_BINDING_KEYS[action])}")
    elif binding is not None:
        raise MintRefused(409, "APPROVAL_BINDING_INVALID", f"{action} approvals carry no binding")
    gdb = get_guard_db()
    if not gdb:
        raise MintRefused(503, "APPROVAL_STORE_UNAVAILABLE", "the guard database is unavailable")
    approved_at = now or datetime.now(timezone.utc)
    record = {
        "status": "APPROVED",
        "action": action,
        "product_id": product_id,
        "project_id": project_id,
        "project_number": _digits(project_number),
        "resource_name": None,
        "principal_type": PRINCIPAL_USER,
        "approved_by": email.strip().lower(),
        "approved_by_role": UserRole.ADMIN.value,
        "approved_at": approved_at.isoformat(),
        "expires_at": (approved_at + APPROVAL_LIFETIME).isoformat(),
        "minted_by": "control-center",
        "reason": reason,
    }
    if delete_without_archive is True and action == PROJECT_DECOMMISSION:
        record["delete_without_archive"] = True   # FD-7L plan 2.8 / Q4: only ever set by the human ADMIN's choice
    if clean_binding is not None:
        record.update(binding=clean_binding, binding_digest=binding_digest(clean_binding), request_id=request_id)
    approval_id = uuid.uuid4().hex
    try:
        gdb.collection(APPROVALS).document(approval_id).create(record)
    except Exception as e:  # noqa: BLE001
        logger.error(f"Could not mint {action} approval for '{product_id}': {e}")
        raise MintRefused(503, "APPROVAL_STORE_UNAVAILABLE", f"could not write the approval ({type(e).__name__})")
    logger.info(f"Minted {action} approval {approval_id} for '{product_id}' ({project_id}) by {record['approved_by']}")
    return approval_id


def void_approval(approval_id: Optional[str], outcome: "VendingOutcome", *, now: Optional[datetime] = None) -> bool:
    """Lane 18 window RT H2: after vending ANSWERED with a refusal, an approval it never consumed is set to VOID so it
    is never "live but unused" for the rest of its 15 minutes (vending refuses any status other than APPROVED).
    Only when vending answered (http_status != 0): on no answer vending may still be working with the approval.
    Only an APPROVED, unconsumed record is touched (CONSUMED / EXECUTION_FAILED written by vending are kept). The CC
    never forwards the id to anyone but vending, which has finished with it, so nothing else can consume it in
    between. Best effort: a failure is logged and never changes the HTTP outcome. Returns True when voided."""
    if not approval_id or outcome.ok or not outcome.http_status:
        return False
    try:
        gdb = get_guard_db()
        if not gdb:
            return False
        ref = gdb.collection(APPROVALS).document(approval_id)
        snap = ref.get()
        data = snap.to_dict() if getattr(snap, "exists", False) is True else None
        if not isinstance(data, dict) or data.get("status") != "APPROVED" or data.get("consumed_at"):
            return False
        ref.set({"status": "VOID", "void_reason": outcome.code,
                 "voided_at": (now or datetime.now(timezone.utc)).isoformat()}, merge=True)
        logger.info(f"Voided approval {approval_id} after vending refused it ({outcome.code})")
        return True
    except Exception as e:  # noqa: BLE001 - best effort; the approval expires on its own after 15 minutes
        logger.warning(f"Could not void approval {approval_id}: {e}")
        return False


def sandbox_display_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    """Fields the dashboard needs to tell an enforced countdown from one that will not delete anything (RT H1/H3)."""
    source = data.get("sandbox_designation_source")
    authority = data.get("ttl_authority")
    return {
        "sandbox_designation_source": source if isinstance(source, str) else None,
        "sandbox_awaiting_confirmation": sandbox_awaiting_confirmation(data),
        "ttl_authority": authority if isinstance(authority, str) else None,
    }


def call_vending(requester: Callable[..., Any], path: str, body: Dict[str, Any], *, request=None,
                 timeout: float = 60.0) -> VendingOutcome:
    """POST to vending with the CC's ID token (requester = routes.settings.make_vending_request or a test double)."""
    try:
        resp = requester(method="POST", path=path, json_body=body, timeout=timeout, request=request)
    except Exception as e:  # noqa: BLE001
        return VendingOutcome(False, 0, "VENDING_UNREACHABLE", f"{type(e).__name__}: {e}")
    if resp is None:
        return VendingOutcome(False, 0, "VENDING_UNCONFIGURED", "VENDING_SERVICE_URL is not configured")
    status = getattr(resp, "status_code", 0)
    if status == 200:
        try:
            data = resp.json()
        except Exception:  # noqa: BLE001
            data = {}
        return VendingOutcome(True, 200, "OK", "", data if isinstance(data, dict) else {})
    err = _vending_error(resp)
    return VendingOutcome(False, status, err["code"], err["detail"])


def failure_response(outcome: VendingOutcome, *, action: str, product_id: str):
    """HTTP 502 carrying vending's {code, detail}. `detail` stays a string so the dashboard toast shows it as-is."""
    from fastapi.responses import JSONResponse  # lazy: several root-suite tests replace `fastapi` in sys.modules
    logger.warning(f"{action} for '{product_id}' not executed by vending: HTTP {outcome.http_status} "
                   f"{outcome.code}: {outcome.detail}")
    return JSONResponse(status_code=502, content={
        "detail": f"{outcome.code}: {outcome.detail}",
        "code": outcome.code,
        "vending_detail": outcome.detail,
        "vending_status": outcome.http_status,
    })


def refusal_response(refused: MintRefused):
    """The CC's own typed refusal (MintRefused) as an HTTP answer. Same status and the same `detail` string as before
    ("CODE: detail"); `code` and `reason` were added (backward-compatible) so the dashboard reads the typed code the same
    way as from failure_response, never out of the message text."""
    from fastapi.responses import JSONResponse  # lazy: several root-suite tests replace `fastapi` in sys.modules
    return JSONResponse(status_code=refused.http_status, content={
        "detail": f"{refused.code}: {refused.detail}",
        "code": refused.code,
        "reason": refused.detail,
    })


def vend_sandbox_fields(*, is_sandbox: Any, auto_decommission: Any, designation_source: Any,
                        ttl_days: Any) -> Dict[str, Any]:
    """The explicit sandbox fields vending's vend routes accept (strict types), from the workload's sandbox selection.
    Not a sandbox -> all off. A keyword-detected sandbox is sent as source KEYWORD (recorded, never TTL-eligible)."""
    sandbox = is_sandbox is True
    ttl = ttl_days if (isinstance(ttl_days, int) and not isinstance(ttl_days, bool)
                       and 0 < ttl_days <= MAX_VEND_TTL_DAYS) else None
    source = VEND_DESIGNATION_SOURCE.get(designation_source) if isinstance(designation_source, str) else None
    return {
        "is_sandbox": sandbox,
        "sandbox_auto_decommission": sandbox and auto_decommission is True,
        "sandbox_designation_source": source if sandbox else None,
        "sandbox_ttl_days": ttl if sandbox else None,
    }
