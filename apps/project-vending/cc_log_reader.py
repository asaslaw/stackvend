"""
StackVend project vending: the Control Center may read each child project's logs (RT14-31, owner decision D4 11-14,
Option A).

The Control Center's Logs tab reads a workload's runtime logs from its child project (`resource_names =
[projects/<child>]`, RT14-31). The Control Center's runtime service account (`sa-stackvend-control-center`, the
Terraform-owned runtime identity of product-control-center-ui, infra/platform/destructive_guard.tf
`local.service_runtime_sa`) holds `roles/logging.viewer` on the host only. Owner decision D4: vending grants that one
read-only role on each child project, with no platform Terraform change:

* at vend time (`ensure_grant`, called by `vend_gcp_project` for every vended project: new, re-vend, adopted,
  redeploy). A grant that cannot be made fails the vend with `VENDING.CC_LOG_READER_GRANT_FAILED` (stage
  `vending.cc_log_reader`), never a vended project whose logs the Control Center cannot read;
* for workloads vended before this change, an admin-triggered, idempotent backfill (`backfill`, vending route
  `POST /guard/cc-log-reader/backfill`, caller in DESTRUCTIVE_CALLERS = the Control Center). It grants only on the
  project that the workload's provenance record (guard database, written by vending) names and the ledger agrees with;
  never on the host project, never by name, label or text match. Per-workload results are typed; a project that
  already has the grant is ALREADY_GRANTED with zero writes. Audited per grant (workloads/{pid}/audit_logs).

The email is built from the fixed persona account id (`runner_broker.CONTROL_CENTER_ACCOUNT_ID`) and the host project
(`PROJECT_ID`); no project id is hardcoded. The grant only adds one member to one unconditional binding; no other
binding is changed.
"""
from datetime import datetime, timezone
import logging
import time
from typing import Any, Callable, Dict, FrozenSet, List, Optional

import destructive_guard as dg
import managed_tag_backfill as mtb
from runner_broker import CONTROL_CENTER_ACCOUNT_ID
from shared import runner_identity as ri

logger = logging.getLogger("project-vending-cc-log-reader")

CC_LOG_READER_ROLE = "roles/logging.viewer"
CC_LOG_READER_GRANT_FAILED = "VENDING.CC_LOG_READER_GRANT_FAILED"
CC_LOG_READER_STAGE = "vending.cc_log_reader"
BACKFILL_ACTION = "CC_LOG_READER_BACKFILL"
GRANT_ATTEMPTS = 3
# Retried statuses (as the B1 owner grant): 404 right after a project is created (CRM eventual consistency), 409 etag
# conflict, 429 / 5xx transient. Status codes only, never message text.
GRANT_RETRY_STATUSES = frozenset({404, 409, 429, 500, 503})
MAX_RECORDS = mtb.MAX_RECORDS


class CCLogReaderGrantError(RuntimeError):
    """The Control Center's roles/logging.viewer grant on a child project could not be made or confirmed."""

    error_class = CC_LOG_READER_GRANT_FAILED
    stage = CC_LOG_READER_STAGE

    def __init__(self, project_id: str, detail: str):
        super().__init__(f"{CC_LOG_READER_GRANT_FAILED}: {detail}")
        self.project_id = project_id
        self.detail = detail


def control_center_member(host_project_id: str) -> str:
    """`serviceAccount:<the Control Center's runtime SA>` of this install. Raises CCLogReaderGrantError without a
    host project id (configuration; never a guessed identity)."""
    host = (host_project_id or "").strip()
    if not host:
        raise CCLogReaderGrantError("", "PROJECT_ID (the host project) is not configured, so the Control Center's "
                                        "service account is unknown")
    return f"serviceAccount:{ri.service_account_email(CONTROL_CENTER_ACCOUNT_ID, host).lower()}"


def _plain_binding(bindings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    return next((b for b in bindings if b.get("role") == CC_LOG_READER_ROLE and not b.get("condition")), None)


def _has_member(policy: Any, member: str) -> bool:
    bindings = (policy or {}).get("bindings") if isinstance(policy, dict) else None
    b = _plain_binding([x for x in (bindings or []) if isinstance(x, dict)]) or {}
    return member in (b.get("members") or [])


def ensure_grant(iam_client: Any, project_id: str, *, host_project_ids: FrozenSet[str], member: str,
                 dry_run: bool = False, retry_delay: float = 2.0,
                 sleep: Callable[[float], None] = time.sleep) -> str:
    """Idempotent: "ALREADY_GRANTED" (no write), "WOULD_GRANT" (dry run, no write) or "GRANTED" (confirmed in the
    returned policy). Raises CCLogReaderGrantError for the host project, an API error that survives GRANT_ATTEMPTS, or a
    returned policy without the member."""
    if not project_id or project_id in host_project_ids:
        raise CCLogReaderGrantError(project_id, f"refused: {project_id!r} is not a child project (host or empty)")
    last_err: Optional[Exception] = None
    for attempt in range(1, GRANT_ATTEMPTS + 1):
        try:
            policy = iam_client.get_iam_policy(project_id)
            policy = dict(policy) if isinstance(policy, dict) else {}
            if _has_member(policy, member):
                return "ALREADY_GRANTED"
            if dry_run:
                return "WOULD_GRANT"
            bindings = [dict(b) for b in (policy.get("bindings") or []) if isinstance(b, dict)]
            binding = _plain_binding(bindings)
            if binding is None:
                binding = {"role": CC_LOG_READER_ROLE, "members": []}
                bindings.append(binding)
            binding["members"] = list(binding.get("members") or []) + [member]
            policy["bindings"] = bindings
            result = iam_client.set_iam_policy(project_id, policy)
            if not _has_member(result, member):
                raise CCLogReaderGrantError(project_id, f"setIamPolicy on '{project_id}' returned a policy without "
                                                        f"{member} in {CC_LOG_READER_ROLE}")
            logger.info(f"Granted {CC_LOG_READER_ROLE} on '{project_id}' to {member} (Control Center log reads)")
            return "GRANTED"
        except dg.CRMUnavailable as e:
            last_err = e
            if e.status not in GRANT_RETRY_STATUSES or attempt == GRANT_ATTEMPTS:
                break
            logger.warning(f"{CC_LOG_READER_ROLE} grant on '{project_id}' attempt {attempt} failed ({e}); retrying")
            sleep(retry_delay)
        except CCLogReaderGrantError:
            raise
        except Exception as e:  # noqa: BLE001 - typed below, the original is chained
            last_err = e
            break
    raise CCLogReaderGrantError(project_id, f"{CC_LOG_READER_ROLE} for {member} on '{project_id}' could not be "
                                            f"granted ({type(last_err).__name__}: {last_err}). The vending identity "
                                            "needs resourcemanager.projects.setIamPolicy on the child.") from last_err


# ------------------------------------------------------------------------------------------------ backfill
def _backfill_one(pid: str, prov: Dict[str, Any], ctx: dg.GuardContext, iam_client: Any, *, member: str,
                  caller_email: str, operator_email: Optional[str], dry_run: bool, now: datetime,
                  retry_delay: float, sleep: Callable[[float], None]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"product_id": pid}

    def skip(code: str, detail: str = "") -> Dict[str, Any]:
        out.update(decision=f"SKIPPED:{code}", detail=detail)
        return out

    if pid in dg.PLATFORM_PSEUDO_WORKLOADS:
        return skip("PLATFORM_WORKLOAD", f"{pid!r} is not a tenant workload")
    if prov.get("created_by") not in dg.PROVENANCE_CREATORS:
        return skip("NOT_PROVENANCED", f"provenance created_by {prov.get('created_by')!r} is not StackVend's")
    try:
        w = ctx.store.get_workload(pid)
        owners = ctx.store.workloads_claiming(prov.get("project_id"))
    except Exception as e:  # noqa: BLE001
        return skip("LEDGER_UNAVAILABLE", type(e).__name__)
    if not isinstance(w, dict):
        return skip("LEDGER_MISSING", f"workloads/{pid} does not exist")
    if w.get("is_castor") is True:
        return skip("PLATFORM_WORKLOAD", f"workloads/{pid} is the platform workload")
    if w.get("status") in mtb.CLOSED_STATUSES:
        return skip("CLOSED", f"ledger status {w.get('status')!r}")
    project_id = w.get("project_id")
    if not isinstance(project_id, str) or not project_id or prov.get("project_id") != project_id:
        return skip("LEDGER_MISMATCH", "provenance project_id differs from the workload record")
    if owners != [pid]:
        return skip("LEDGER_MISMATCH", f"project {project_id} is claimed by {sorted(owners or [])}")
    if project_id in ctx.host_project_ids:
        return skip("HOST_PROJECT", f"{project_id} is the host project")
    out["project_id"] = project_id

    base = {"action": BACKFILL_ACTION, "product_id": pid, "project_id": project_id, "role": CC_LOG_READER_ROLE,
            "member": member, "caller": caller_email, "operator": operator_email}
    try:
        state = ensure_grant(iam_client, project_id, host_project_ids=ctx.host_project_ids, member=member,
                             dry_run=True, retry_delay=retry_delay, sleep=sleep)
    except CCLogReaderGrantError as e:
        out.update(decision="FAILED", error_class=CC_LOG_READER_GRANT_FAILED, detail=e.detail)
        return out
    if state == "ALREADY_GRANTED" or dry_run:
        out.update(decision=state)
        return out
    try:
        dg._audit(ctx, pid, {**base, "status": "ATTEMPT", "at": now.isoformat()})
    except Exception as e:  # noqa: BLE001 - no audit, no grant
        return skip("AUDIT_UNAVAILABLE", type(e).__name__)
    try:
        state = ensure_grant(iam_client, project_id, host_project_ids=ctx.host_project_ids, member=member,
                             retry_delay=retry_delay, sleep=sleep)
    except CCLogReaderGrantError as e:
        out.update(decision="FAILED", error_class=CC_LOG_READER_GRANT_FAILED, detail=e.detail)
        try:
            dg._audit(ctx, pid, {**base, "status": "FAILED", "error": e.detail, "at": now.isoformat()})
        except Exception:  # noqa: BLE001
            logger.error(f"{BACKFILL_ACTION} audit of the failure for '{pid}' could not be written")
        return out
    out.update(decision=state)
    try:
        dg._audit(ctx, pid, {**base, "status": state, "at": now.isoformat()})
    except Exception:  # noqa: BLE001
        logger.error(f"{BACKFILL_ACTION} result audit for '{pid}' could not be written")
    return out


def backfill(ctx: dg.GuardContext, iam_client: Any, *, host_project_id: str, caller_email: str,
             operator_email: Optional[str] = None, dry_run: bool = False, limit: int = MAX_RECORDS,
             now: Optional[datetime] = None, retry_delay: float = 2.0,
             sleep: Callable[[float], None] = time.sleep) -> Dict[str, Any]:
    """Grant the Control Center roles/logging.viewer on every provenance-proven, open workload's child project.
    Idempotent and resumable (re-run after a FAILED entry). Raises CCLogReaderGrantError without a host project id and
    dg.StoreUnavailable when the guard database cannot be listed (fail loudly; never an empty success)."""
    member = control_center_member(host_project_id)
    now = now or datetime.now(timezone.utc)
    records, truncated = mtb._provenance_records(ctx, limit)
    results = [_backfill_one(pid, prov, ctx, iam_client, member=member, caller_email=caller_email,
                             operator_email=operator_email, dry_run=dry_run, now=now, retry_delay=retry_delay,
                             sleep=sleep)
               for pid, prov in records]
    counts: Dict[str, int] = {}
    for r in results:
        counts[r["decision"]] = counts.get(r["decision"], 0) + 1
    logger.info(f"{BACKFILL_ACTION} by {caller_email} for {operator_email!r} (dry_run={dry_run}): {counts}")
    return {"role": CC_LOG_READER_ROLE, "member": member, "dry_run": dry_run, "results": results, "counts": counts,
            "truncated": truncated}
