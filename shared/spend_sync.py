"""
StackVend: the ONE all-workload spend sync (C10, owner 11-07; register row C10-MACHINE-CALLERS-OFF-CC).

Used by the Control Center's human manual trigger POST /api/finops/sync-spend (routes/finops.py) and by the
finops-spend-sync-job Cloud Run job (apps/finops-spend-sync/main.py, Cloud Scheduler castor-finops-nightly-spend-sync).
For every workload that is not DECOMMISSIONED: `reconcile(product_id, workload, host_project, db=db)`
(services/finops_sync.reconcile_workload_spend, byte-identical in both images) and a merge write of its result into
Firestore workloads/{id}. The Control Center reads those fields (spend_last_updated_at, projected_monthly_spend_usd,
is_overrun_projected, spend_source, ...).

`continue_on_error` False (the route, unchanged): the first failing workload raises. True (the job, pre-review F17):
each workload is tried, failures are listed in `failed` and the job ends COMPLETED_WITH_ERRORS.

Replicated (byte-identical, tests/test_c10_platform_tf.py::test_c10_copies_are_byte_identical): shared/, apps/control-center/shared/,
apps/finops-spend-sync/shared/. Standard library only.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List

logger = logging.getLogger("stackvend-spend-sync")


class SpendSyncUnavailable(RuntimeError):
    """No Firestore database: the route answers 503, the job ends FAILED (exit 1)."""


def sync_all_workloads(db: Any, reconcile: Callable[..., Dict[str, Any]], host_project: str, *,
                       continue_on_error: bool = False) -> Dict[str, Any]:
    now_iso = datetime.now(timezone.utc).isoformat()
    if not db:
        raise SpendSyncUnavailable("Firestore database unavailable")
    synced: List[Dict[str, Any]] = []
    failed: List[Dict[str, str]] = []
    docs = db.collection("workloads").stream()
    for d in docs:
        data = d.to_dict() or {}
        if data.get("status") == "DECOMMISSIONED":
            continue
        try:
            update_dict = reconcile(d.id, data, host_project, db=db)
            db.collection("workloads").document(d.id).set(update_dict, merge=True)
            synced.append({
                "product_id": d.id,
                "current_spend_usd": update_dict["current_spend_usd"],
                "projected_monthly_spend_usd": update_dict["projected_monthly_spend_usd"],
                "budget_ceiling_monthly_usd": float(data.get("budget_ceiling_monthly_usd", 40.0)),
                "is_overrun_projected": update_dict["is_overrun_projected"],
                "spend_source": update_dict.get("spend_source"),
            })
        except Exception as e:  # noqa: BLE001 - the route re-raises; the job records it and goes on
            if not continue_on_error:
                raise
            logger.error(f"Spend sync failed for '{d.id}': {type(e).__name__}: {e}")
            failed.append({"product_id": d.id, "error_class": type(e).__name__, "error": str(e)[:300]})
    logger.info(f"FinOps synced spend metrics for {len(synced)} workloads at {now_iso}")
    result: Dict[str, Any] = {"status": "SUCCESS", "synced_at": now_iso, "count": len(synced), "workloads": synced}
    if continue_on_error:
        result["failed"] = failed
    return result
