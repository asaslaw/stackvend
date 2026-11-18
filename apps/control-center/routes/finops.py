"""
Project Castor: FinOps Spend Tracking & Run-Rate Projections
Nightly and on-demand cloud spend synchronization with Firestore.
"""

import calendar
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from authz import ADMIN, PUBSUB_PUSH, WORKLOAD, require
from pydantic import BaseModel, Field

from auth import verify_admin_access, verify_workload_access
from db import db

logger = logging.getLogger("control-center-finops")

router = APIRouter(tags=["FinOps"])


def calculate_run_rate_projection(
    current_spend: float,
    as_of_date: Optional[datetime] = None,
    deployed_at: Optional[str] = None,
    hourly_rate: Optional[float] = None,
) -> float:
    """Extrapolates month-to-date spend to the projected total monthly run-rate."""
    if hourly_rate and hourly_rate > 0.0:
        return round(hourly_rate * 730.0, 2)
    now = as_of_date or datetime.now(timezone.utc)
    current_day = max(1, now.day)
    _, total_days = calendar.monthrange(now.year, now.month)

    if deployed_at:
        try:
            dep_dt = datetime.fromisoformat(deployed_at.replace("Z", "+00:00"))
            uptime_days = max(0.04, (now - dep_dt).total_seconds() / 86400.0)
            effective_days = min(float(current_day), uptime_days)
            return round((current_spend / effective_days) * total_days, 2)
        except Exception:
            pass

    return round((current_spend / current_day) * total_days, 2)


try:
    from services.finops_sync import reconcile_workload_spend
except ImportError:
    _cc_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _cc_dir not in sys.path:
        sys.path.insert(0, _cc_dir)
    from services.finops_sync import reconcile_workload_spend

# C10: the shared bodies (byte-identical copies in the job images; tests/test_c10_platform_tf.py::test_c10_copies_are_byte_identical).
from shared import billing_alerts, spend_sync  # noqa: E402


@router.post("/api/finops/sync-spend", dependencies=[require(ADMIN)])
def sync_all_spend(request: Request):
    """
    Manual all-workload spend synchronization for a human Platform Administrator. C10 (owner 11-07): the nightly run is
    the finops-spend-sync-job Cloud Run job (apps/finops-spend-sync, Cloud Scheduler castor-finops-nightly-spend-sync);
    nothing machine-calls the Control Center any more, so the route policy is ADMIN (was ADMIN_OR_JOB). Same work:
    shared.spend_sync.sync_all_workloads with reconcile_workload_spend (unchanged answers: 200 / 500 / 503).
    """
    verify_admin_access(request)
    host_project = os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT", "")
    try:
        return spend_sync.sync_all_workloads(db, reconcile_workload_spend, host_project)
    except spend_sync.SpendSyncUnavailable:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")
    except Exception as e:
        logger.error(f"Failed to sync spend metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to sync spend: {e}")


@router.post("/api/workloads/{product_id}/sync-spend", dependencies=[require(WORKLOAD(manager=True))])
def sync_workload_spend(product_id: str, request: Request):
    """On-demand real-time spend and projection recalculation for a specific workload."""
    verify_workload_access(product_id, request, require_manager=True)
    now_iso = datetime.now(timezone.utc).isoformat()
    host_project = os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT", "")
    if db:
        try:
            doc = db.collection("workloads").document(product_id).get()
            if not doc.exists:
                raise HTTPException(status_code=404, detail=f"Workload {product_id} not found")
            data = doc.to_dict() or {}
            if data.get("status") == "DECOMMISSIONED":
                return {
                    "status": "SKIPPED_DECOMMISSIONED",
                    "product_id": product_id,
                    "current_spend_usd": 0.0,
                    "projected_monthly_spend_usd": 0.0,
                    "message": "Workload is decommissioned; cloud spend is zero.",
                }
            update_dict = reconcile_workload_spend(product_id, data, host_project, db=db)
            db.collection("workloads").document(product_id).set(update_dict, merge=True)
            logger.info(
                f"FinOps synced spend on demand for {product_id}: Spend=${update_dict['current_spend_usd']:.2f}, "
                f"Projected=${update_dict['projected_monthly_spend_usd']:.2f}/mo (Source: {update_dict.get('spend_source')})"
            )
            return {"status": "SUCCESS", "product_id": product_id, "updated": update_dict}
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to sync spend for {product_id}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to sync spend: {e}")

    raise HTTPException(status_code=503, detail="Firestore database unavailable")


class PubSubAlertMessage(BaseModel):
    data: str
    messageId: Optional[str] = None
    publishTime: Optional[str] = None
    attributes: Optional[Dict[str, str]] = None


class PubSubAlertEnvelope(BaseModel):
    message: PubSubAlertMessage
    subscription: Optional[str] = None


@router.post("/api/alerts/billing", dependencies=[require(PUBSUB_PUSH("/api/alerts/billing"))])
def billing_alert_webhook(
    envelope: PubSubAlertEnvelope,
    request: Request,
):
    """
    Cloud Billing budget notification (Pub/Sub push) -> workload spend update and, over threshold, quarantine.

    FD-4O hardening:
    - Authorization is the route policy PUBSUB_PUSH: a verified OIDC bearer from the exact platform push SA with
      audience == <this service URL>/api/alerts/billing. Human sessions (even ADMIN) are refused.
    - The PAYLOAD IS UNTRUSTED until topic-level IAM limits publishers of `billing-budget-alerts` to Cloud Billing
      (lane 5, infra item 2a): the agent SAs lost project-level pubsub.publisher (FD-4AS-c), but no Terraform grant
      names Cloud Billing as the only publisher and project Owners / Editors can still publish; every push carries a
      valid push token. Mapping below is a lookup, not authentication.
    - Workload mapping is exact: `billing_budget_id` == the budgetId attribute (only when trusted code wrote that
      field), else budgetDisplayName == "budget-<workload doc id>" with the doc required to exist. No prefix
      stripping fallbacks, no product_id from attributes or payload. Unknown => IGNORED, zero writes.
    - The budget ceiling is never overwritten from the payload; the threshold comes from the workload doc.
    - The target project comes only from the workload doc; missing => IGNORED. The enforcer's own guard refuses
      the host project and non-descendants of the managed workloads folder.

    C10 (owner 11-07): nothing pushes here any more and the platform-caller allow-list is empty, so PUBSUB_PUSH refuses
    every caller; the route stays registered (required components). The subscription is a PULL subscription drained
    every 30 minutes by billing-alert-drain-job (apps/billing-alert-drain), which runs the same
    shared.billing_alerts.process_billing_notification (billing-account check, exact mapping, latch).
    """
    try:
        data, cost_amount = billing_alerts.decode_billing_notification(envelope.message.data)
    except Exception as e:
        logger.error(f"Failed to parse Pub/Sub envelope data: {e}")
        raise HTTPException(status_code=400, detail="Invalid Base64 or JSON in message.data")
    try:
        return billing_alerts.process_billing_notification(
            db, data, cost_amount, envelope.message.attributes or {}, _control_center_enforcer,
            install_billing_account=os.getenv("BILLING_ACCOUNT_ID", ""), enforcement_enabled=True,
            message_id=envelope.message.messageId or "")
    except billing_alerts.BillingAlertError as e:
        raise HTTPException(status_code=e.http_status, detail=e.detail)


def _control_center_enforcer():
    """The route's enforcer: the in-process engine (FD26-07: not packaged in this container, so None -> 503)."""
    from routes.approvals import get_finops_enforcer
    return get_finops_enforcer()


def _billing_period(data: Dict[str, Any]) -> str:
    """FD-4CI-b RT F1 (C10: shared.billing_alerts.billing_period)."""
    return billing_alerts.billing_period(data)


def _finops_percent(name: str, fallback: Optional[float]) -> Optional[float]:
    """FD-4CI-b: finops.<name> through the Control Center's own Firestore client (shared.billing_alerts)."""
    return billing_alerts.finops_percent(db, name, fallback)
