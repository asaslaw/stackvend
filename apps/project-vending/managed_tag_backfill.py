"""
StackVend project vending: deletion-safety tag status and backfill (lane 18 v3, owner rule 10-18).

Owner rule: "Install must be simple, smooth and never fail, only providing warnings in settings for lack of billing
user and tag admin." When the installer is not an organization Tag Administrator, `scripts/apply.sh` does not plan the
stackvend-managed tag (infra/platform/destructive_guard.tf, create_stackvend_managed_tag = false). Then
STACKVEND_MANAGED_TAG_VALUE is unset, vending births projects untagged (provenance `tag_bound: false`) and the
destructive guard refuses every delete (GUARD_UNCONFIGURED; fail closed, unchanged).

This module serves the Control Center Settings page:

* `tag_status` (read-only): is the tag set up; which projects StackVend vended (workload_provenance records in the
  guard database) are untagged; which ledger workloads have NO provenance record (never tagged automatically; listed
  for the owner, who may use the owner-run `backfill_provenance.py`).
* `backfill_tags` (admin action, executed by vending, the only identity with tagUser on the value): once the tag
  exists, binds it to projects whose provenance record was written by vending AT BIRTH (`created_by ==
  "stackvend-vending"`) and that pass the same ledger/CRM identity checks as the guard. Never by project name, label
  or any text match. Non-destructive (one tagBindings.create per project, nothing is deleted or relabelled),
  idempotent (a project that already has the direct binding is reported ALREADY_TAGGED with zero writes) and audited
  (workloads/{pid}/audit_logs, before and after the binding).

Not tagged (reported, nothing written): owner-backfill provenance (the owner already decided those by hand),
expired auto-decommission sandboxes (tagging them would make them auto-deletable at the next sweep; the owner decides),
any failed ledger / provenance / CRM / ancestry check, and every project without a provenance record.
"""
from datetime import datetime, timezone
import itertools
import logging
from typing import Any, Dict, List, Optional, Tuple

import destructive_guard as dg

logger = logging.getLogger("project-vending-managed-tag-backfill")

TAG_ADMIN_ROLE = "roles/resourcemanager.tagAdmin"
BACKFILL_ACTOR = "managed-tag-backfill"
MAX_RECORDS = 200  # status/backfill scan bound per call (CRM calls are 10 s each at worst)
CLOSED_STATUSES = frozenset({"DECOMMISSIONED", "DELETED"})


def organization_name(raw: Optional[str]) -> str:
    """'organizations/<digits>' from STACKVEND_ORGANIZATION_ID ('organizations/<n>' or '<n>'); anything else ''."""
    v = (raw or "").strip()
    parts = v.split("/")
    if len(parts) == 2 and parts[0] == "organizations":
        v = parts[1]
    return f"organizations/{v}" if v.isdigit() else ""


def _stream(db, collection: str, limit: int) -> Tuple[List[Tuple[str, Dict[str, Any]]], bool]:
    if db is None or isinstance(db, dg.UnavailableDB):
        raise dg.StoreUnavailable(f"{collection} unreadable: Firestore client unavailable")
    try:
        docs = list(itertools.islice(db.collection(collection).stream(), limit + 1))
    except Exception as e:  # noqa: BLE001
        raise dg.StoreUnavailable(f"{collection} unreadable: {type(e).__name__}") from None
    out = []
    for snap in docs[:limit]:
        data = snap.to_dict() if getattr(snap, "exists", True) else None
        out.append((snap.id, data if isinstance(data, dict) else {}))
    return out, len(docs) > limit


def _provenance_records(ctx: dg.GuardContext, limit: int):
    return _stream(ctx.store.guard_db, dg.PROVENANCE, limit)


def _direct_binding(bindings, number: str, tag_value: str) -> bool:
    parent = f"{dg._CRM_FULL_PROJECT}{number}"
    return any(isinstance(b, dict) and b.get("parent") == parent and b.get("tagValue") == tag_value
               for b in (bindings or []))


def _sandbox_expired(prov: Dict[str, Any], now: datetime) -> bool:
    if prov.get("is_sandbox") is not True or prov.get("sandbox_auto_decommission") is not True:
        return False
    expires = dg._parse_ts(prov.get("sandbox_expires_at"))
    return expires is not None and expires <= now


# ------------------------------------------------------------------------------------------------ status
def tag_status(ctx: dg.GuardContext, *, organization_raw: Optional[str], limit: int = MAX_RECORDS) -> Dict[str, Any]:
    """Read-only. Raises dg.StoreUnavailable when the guard database / ledger cannot be read."""
    tag = ctx.managed_tag_value
    now = ctx.clock()
    records, truncated = _provenance_records(ctx, limit)
    workloads, w_truncated = _stream(ctx.store.db, dg.WORKLOADS, limit)
    ledger = dict(workloads)
    proven_ids = {pid for pid, _ in records}

    vended: List[Dict[str, Any]] = []
    for pid, prov in records:
        w = ledger.get(pid) or {}
        number = dg._num(prov.get("project_number"))
        entry = {
            "product_id": pid,
            "project_id": prov.get("project_id"),
            "project_number": number or None,
            "created_by": prov.get("created_by"),
            "born_by_vending": prov.get("created_by") == dg.CREATED_BY_VENDING,
            "ledger_status": w.get("status"),
            # RT F2: backfill_tags always skips these (SANDBOX_EXPIRED); the owner decides.
            "sandbox_expired": _sandbox_expired(prov, now),
        }
        if w.get("status") in CLOSED_STATUSES:
            entry["tag"] = "CLOSED"
        elif not tag:
            entry["tag"] = "NOT_SET_UP"
        elif not number:
            entry["tag"] = "UNKNOWN"
        else:
            try:
                entry["tag"] = "TAGGED" if _direct_binding(ctx.crm.list_tag_bindings(number), number, tag) else "UNTAGGED"
            except dg.CRMUnavailable as e:
                entry["tag"] = "UNKNOWN"
                entry["detail"] = str(e)
        vended.append(entry)

    unprovenanced = []
    for pid, w in workloads:
        project_id = w.get("project_id")
        if pid in proven_ids or pid in dg.PLATFORM_PSEUDO_WORKLOADS or w.get("is_castor") is True:
            continue
        if not isinstance(project_id, str) or not project_id or w.get("status") in CLOSED_STATUSES:
            continue
        unprovenanced.append({"product_id": pid, "project_id": project_id, "ledger_status": w.get("status")})

    untagged = [v for v in vended if v["tag"] in ("NOT_SET_UP", "UNTAGGED")]
    return {
        "tag_configured": bool(tag),
        "managed_tag_value": tag,
        "managed_folder_configured": bool(ctx.managed_root_folder_id),
        "organization_id": organization_name(organization_raw),
        "required_role": TAG_ADMIN_ROLE,
        "vended_projects": vended,
        "untagged_vended": untagged,
        "backfill_candidates": [v["product_id"] for v in untagged
                                if tag and v["born_by_vending"] and not v["sandbox_expired"]],
        "sandbox_expired_untagged": [v for v in untagged if v["born_by_vending"] and v["sandbox_expired"]],
        "max_records": limit,
        "unprovenanced_workloads": unprovenanced,
        "truncated": truncated or w_truncated,
    }


# ------------------------------------------------------------------------------------------------ backfill
def _audit(ctx: dg.GuardContext, pid: str, record: Dict[str, Any]) -> None:
    dg._audit(ctx, pid, record)


def _backfill_one(pid: str, ctx: dg.GuardContext, *, caller_email: str, operator_email: Optional[str],
                  now: datetime) -> Dict[str, Any]:
    out: Dict[str, Any] = {"product_id": pid}

    def skip(code: str, detail: str = "") -> Dict[str, Any]:
        out.update(decision=f"SKIPPED:{code}", detail=detail)
        return out

    checks: List[str] = []
    try:
        # Checks 1-4 of the guard, on FRESH reads: config, ledger, provenance (creator, ids, numeric number, reverse
        # uniqueness), not the host project.
        _w, prov, project_id, number = dg._ledger_checks(pid, ctx, checks)
    except dg.DeletionRefused as e:
        return skip(e.code, e.detail)
    out.update(project_id=project_id, project_number=number)
    if prov.get("created_by") != dg.CREATED_BY_VENDING:
        return skip("NOT_VENDING_BIRTH", f"provenance created_by {prov.get('created_by')!r}: the owner decides")
    if _sandbox_expired(prov, now):
        return skip("SANDBOX_EXPIRED", "an expired auto-decommission sandbox would become deletable at once")

    try:
        host_numbers = ctx.host_numbers()
        project = ctx.crm.get_project(number)
    except dg.CRMUnavailable as e:
        return skip("CRM_UNAVAILABLE", str(e))
    if not isinstance(project, dict) or dg._number_of(project) != number or project.get("projectId") != project_id:
        return skip("CRM_MISMATCH", f"projects/{number} is not {project_id}")
    if number in host_numbers:
        return skip("HOST_PROJECT", f"projects/{number} is the host project")
    if project.get("state") != "ACTIVE":
        return skip("NOT_ACTIVE", f"project state is {project.get('state')!r}")
    try:
        # Check 6, label half (lane 18 v3 RT F1): vending writes these labels at birth; a guard-DB writer cannot
        # forge them without rights on the child project. No labels -> the guard would never recognise it.
        dg._check_labels(project, pid)
        dg._check_ancestry(project_id, number, ctx)
        bindings = ctx.crm.list_tag_bindings(number)
    except dg.DeletionRefused as e:
        return skip(e.code, e.detail)
    except dg.CRMUnavailable as e:
        return skip("CRM_UNAVAILABLE", str(e))
    if _direct_binding(bindings, number, ctx.managed_tag_value):
        out.update(decision="ALREADY_TAGGED")
        return out

    base = {"action": "MANAGED_TAG_BACKFILL", "product_id": pid, "project_id": project_id,
            "project_number": number, "tag_value": ctx.managed_tag_value, "caller": caller_email,
            "operator": operator_email, "proof": "workload_provenance created_by stackvend-vending + guard checks 1-7 minus the tag binding"}
    try:
        _audit(ctx, pid, {**base, "status": "ATTEMPT", "at": now.isoformat()})
    except Exception as e:  # noqa: BLE001 - no audit, no binding
        return skip("AUDIT_UNAVAILABLE", f"{type(e).__name__}")
    try:
        ctx.crm.create_tag_binding(number, ctx.managed_tag_value)
    except Exception as e:  # noqa: BLE001
        out.update(decision="FAILED", detail=str(e))
        try:
            _audit(ctx, pid, {**base, "status": "FAILED", "error": str(e), "at": now.isoformat()})
        except Exception:  # noqa: BLE001
            logger.error(f"MANAGED_TAG_BACKFILL audit of the failure for '{pid}' could not be written")
        return out
    out.update(decision="TAGGED")
    try:
        ctx.store.update_provenance(pid, {"tag_bound": True, "tag_bound_at": now.isoformat(),
                                          "tag_bound_by": BACKFILL_ACTOR})
    except Exception as e:  # noqa: BLE001 - the binding is what the guard reads; the record is informational
        out["detail"] = f"provenance tag_bound not updated: {type(e).__name__}"
    try:
        _audit(ctx, pid, {**base, "status": "TAGGED", "at": now.isoformat()})
    except Exception:  # noqa: BLE001
        logger.error(f"MANAGED_TAG_BACKFILL result audit for '{pid}' could not be written")
    return out


def backfill_tags(ctx: dg.GuardContext, *, caller_email: str, operator_email: Optional[str] = None,
                  limit: int = MAX_RECORDS, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Bind the stackvend-managed tag to provenance-proven, vending-born projects. Raises dg.DeletionRefused
    (GUARD_UNCONFIGURED) when the tag / managed folder / host id is not configured, dg.StoreUnavailable when the guard
    database cannot be listed."""
    dg._check_config(ctx)
    now = now or ctx.clock() or datetime.now(timezone.utc)
    records, truncated = _provenance_records(ctx, limit)
    results = [_backfill_one(pid, ctx, caller_email=caller_email, operator_email=operator_email, now=now)
               for pid, _prov in records]
    counts: Dict[str, int] = {}
    for r in results:
        counts[r["decision"]] = counts.get(r["decision"], 0) + 1
    logger.info(f"MANAGED_TAG_BACKFILL by {caller_email} for {operator_email!r}: {counts}")
    return {"results": results, "counts": counts, "truncated": truncated}
