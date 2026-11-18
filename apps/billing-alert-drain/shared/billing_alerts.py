"""
StackVend: the ONE Cloud Billing budget-notification handler (C10, owner 11-07 "B"; register row
C10-MACHINE-CALLERS-OFF-CC, enforcement ON).

Used by billing-alert-drain-job (apps/billing-alert-drain/main.py), which pulls the billing-alerts subscription every
30 minutes, and by the Control Center's POST /api/alerts/billing route (kept registered; since C10 its PUBSUB_PUSH
policy refuses every caller because the platform-caller allow-list is empty, so it is never exercised).

Trust (pre-review F13; the PAYLOAD IS UNTRUSTED: project Owners / Editors can publish to the topic, and IAM is
additive, so no topic grant can take that away; documentation/known-limitations.md):
- the message attribute `billingAccountId` must equal this install's billing account (Terraform var
  billing_account_id); anything else is IGNORED with zero writes;
- workload mapping is exact: `billing_budget_id` == the `budgetId` attribute; else (documented fallback) the
  budgetDisplayName is exactly "budget-<workload doc id>" with that doc existing, and when that workload records a
  `billing_budget_id` the `budgetId` attribute must equal it. No prefix games, no product id from the payload;
- the threshold comes from the workload doc only (ceiling x Circuit Breaker %, or an approved buffer ceiling as it
  is); the target project only from the workload doc; the policy from the workload doc (default
  AUTONOMOUS_SCALE_TO_ZERO, exactly as before; the enforcer engine applies it: ALERT_ONLY, HITL card, billing unlink,
  scale to zero, region-not-approved -> card, FD-4O host/ancestry guard).

Idempotency (pre-review F14): Cloud Billing re-sends notifications several times a day with NEW message ids. A breach
already enforced (ENFORCED_STATUSES) for the same billing period and the same threshold
(`workloads/{id}.budget_breach_latch`) is never enforced again (no second quarantine, no second card); spend is still
recorded. The enforcer's restore clears the latch. A REFUSED enforcement is recorded in `budget_breach_refusal` and
re-asked at most once per 24 hours (RT finding 3). The caller claims each message id
(`billing_alert_deliveries/{messageId}`, claim_delivery / finish_delivery) before any side effect.

Replicated (byte-identical, tests/test_c10_platform_tf.py::test_c10_copies_are_byte_identical): shared/, apps/control-center/shared/,
apps/billing-alert-drain/shared/. Standard library + shared.settings.
"""

import base64
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger("stackvend-billing-alerts")

DELIVERIES = "billing_alert_deliveries"
LATCH_FIELD = "budget_breach_latch"
# RT finding 3: a REFUSED enforcement (the enforcer's target guard, often a configuration state) is not latched for
# the month; it is re-asked at most once per REFUSAL_RETRY_HOURS, so a fixed configuration takes effect the next day.
REFUSAL_FIELD = "budget_breach_refusal"
REFUSAL_RETRY_HOURS = 24
DEFAULT_POLICY = "AUTONOMOUS_SCALE_TO_ZERO"
# Outcomes of the enforcer engine (apps/finops-enforcer/main.py ENFORCED_STATUSES; parity test) and its typed refusal.
ENFORCED_STATUSES = frozenset({"QUARANTINED", "ALERTED_ONLY", "BILLING_UNLINKED", "HITL_CONFIRMATION_PENDING"})
REFUSED = "REFUSED"


class BillingAlertError(Exception):
    """A notification that was NOT processed; the sender must retry (the drain job does not ack it: redelivery, then
    castor-dlq after the subscription's max delivery attempts; the push route answers `http_status`). Codes:
    FIRESTORE_UNAVAILABLE, ENFORCEMENT_DISABLED (BUDGET_BREACH_ENFORCER_NOT_ENABLED), ENFORCER_UNAVAILABLE,
    QUARANTINE_FAILED."""

    def __init__(self, code: str, http_status: int, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.http_status, self.detail = code, http_status, detail


def decode_billing_notification(data_b64: str) -> Tuple[Dict[str, Any], float]:
    """A budget notification's Pub/Sub `data` (base64 JSON object) -> (payload, costAmount). Raises on anything else."""
    raw_bytes = base64.b64decode(data_b64)
    data = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("payload is not a JSON object")
    return data, float(data.get("costAmount", 0.0))


def billing_period(data: Dict[str, Any]) -> str:
    """FD-4CI-b RT F1: the budget period of a notification as YYYY-MM (its costIntervalStart, an RFC 3339 timestamp,
    parsed); the current UTC month when it is absent or unparseable."""
    start = data.get("costIntervalStart") if isinstance(data, dict) else None
    if isinstance(start, str) and start:
        try:
            return datetime.fromisoformat(start.replace("Z", "+00:00")).strftime("%Y-%m")   # as stated
        except ValueError:
            pass
    return datetime.now(timezone.utc).strftime("%Y-%m")


def finops_percent(db: Any, name: str, fallback: Optional[float]) -> Optional[float]:
    """FD-4CI-b: finops.<name> (a percentage) read through `db`; `fallback` (the behaviour before the setting was
    wired) when the settings cannot be read or the value is unusable."""
    try:
        from shared.settings import is_setting_number, stored_setting_value
    except ImportError:
        return fallback
    value = stored_setting_value(db, "finops", name, fallback, accept=lambda v: is_setting_number(v) and v > 0)
    return float(value) if value is not None else None


def normalize_billing_account(value: Any) -> str:
    """`billingAccounts/XXXXXX-XXXXXX-XXXXXX` or the bare id -> the bare id (exact prefix only); "" for non-strings."""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    return value[len("billingAccounts/"):] if value.startswith("billingAccounts/") else value


def resolve_budget_workload(db: Any, data: Dict[str, Any], attributes: Dict[str, str]
                            ) -> Tuple[Optional[str], Dict[str, Any], str]:
    """Exact lookups only (module docstring). Returns (product_id, workload_doc, "") or (None, {}, reason)."""
    budget_id = attributes.get("budgetId") if isinstance(attributes, dict) else None
    budget_id = budget_id if isinstance(budget_id, str) and budget_id else ""
    if budget_id:
        try:
            for snap in db.collection("workloads").where("billing_budget_id", "==", budget_id).stream():
                w = snap.to_dict() or {}
                if w.get("billing_budget_id") == budget_id:
                    return snap.id, w, ""
        except Exception as e:
            logger.warning(f"billing_budget_id lookup failed: {e}")
    name = data.get("budgetDisplayName")
    prefix = "budget-"
    if isinstance(name, str) and name.startswith(prefix) and len(name) > len(prefix):
        candidate = name[len(prefix):]
        try:
            snap = db.collection("workloads").document(candidate).get()
        except Exception as e:
            logger.warning(f"Workload lookup for budget '{name}' failed: {e}")
            return None, {}, "WORKLOAD_LOOKUP_FAILED"
        if snap.exists and f"{prefix}{snap.id}" == name:
            w = snap.to_dict() or {}
            recorded = w.get("billing_budget_id")
            if isinstance(recorded, str) and recorded and recorded != budget_id:
                return None, {}, "BUDGET_ID_MISMATCH"
            return snap.id, w, ""
    return None, {}, "UNMAPPED"


def _same_breach(record: Any, period: str, threshold: float) -> bool:
    if not isinstance(record, dict) or record.get("period") != period:
        return False
    try:
        return abs(float(record.get("threshold")) - float(threshold)) < 0.005
    except (TypeError, ValueError):
        return False


def latch_matches(latch: Any, period: str, threshold: float) -> bool:
    """True when this workload's breach was already enforced for this billing period at this threshold. Only an
    ENFORCED_STATUSES outcome is a latch (RT finding 3); `restore_workload` clears it (RT finding 6)."""
    return _same_breach(latch, period, threshold) and latch.get("outcome") in ENFORCED_STATUSES


def refusal_recent(refusal: Any, period: str, threshold: float, now: datetime) -> bool:
    """True when the enforcer REFUSED this same breach (period, threshold) less than REFUSAL_RETRY_HOURS ago."""
    if not _same_breach(refusal, period, threshold):
        return False
    try:
        at = datetime.fromisoformat(str(refusal.get("at")))
    except ValueError:
        return False
    return timedelta(0) <= now - at < timedelta(hours=REFUSAL_RETRY_HOURS)


def process_billing_notification(db: Any, data: Dict[str, Any], cost_amount: float, attributes: Dict[str, str],
                                 get_enforcer: Callable[[], Any], *, install_billing_account: str,
                                 enforcement_enabled: bool = True, message_id: str = "",
                                 now: Optional[datetime] = None) -> Dict[str, Any]:
    """The typed outcome (status IGNORED / UNDER_THRESHOLD / WARNING_THRESHOLD / ALREADY_ENFORCED / ALREADY_REFUSED /
    QUARANTINE_EXECUTED / REFUSED), or BillingAlertError when the notification must be retried. `get_enforcer()` is
    called only on a breach that is not latched and returns an object with `quarantine_workload(...)` (None:
    ENFORCER_UNAVAILABLE)."""
    now = now or datetime.now(timezone.utc)
    if not db:
        raise BillingAlertError("FIRESTORE_UNAVAILABLE", 503, "Firestore database unavailable")
    attributes = attributes if isinstance(attributes, dict) else {}

    install = normalize_billing_account(install_billing_account)
    sent = normalize_billing_account(attributes.get("billingAccountId"))
    if not install or sent != install:
        reason = "BILLING_ACCOUNT_UNCONFIGURED" if not install else "BILLING_ACCOUNT_MISMATCH"
        return {"status": "IGNORED", "reason": reason}

    product_id, w_data, why = resolve_budget_workload(db, data, attributes)
    if not product_id:
        return {"status": "IGNORED", "reason": why or "UNMAPPED",
                "detail": "Budget notification does not map to a registered workload"}

    target_project_id = w_data.get("project_id")
    if not target_project_id:
        return {"status": "IGNORED", "product_id": product_id, "reason": "NO_PROJECT_ID",
                "detail": "Workload has no registered project_id"}

    breach_policy = w_data.get("budget_breach_policy", DEFAULT_POLICY)
    buffer_ceiling = w_data.get("buffer_ceiling_usd")
    ceiling = w_data.get("budget_ceiling_monthly_usd")
    try:
        db.collection("workloads").document(product_id).set({"current_spend_usd": cost_amount}, merge=True)
    except Exception as err:
        logger.warning(f"Could not record spend for '{product_id}': {err}")

    threshold = buffer_ceiling if buffer_ceiling is not None else ceiling
    try:
        threshold = float(threshold) if threshold is not None else None
    except (TypeError, ValueError):
        threshold = None
    # FD-4CI-b: the Circuit Breaker (%) applies to the workload's own ceiling (100 = at the ceiling, as before); an
    # approved buffer ceiling is an absolute the operator chose and is used as it is.
    alert_base = threshold
    if threshold and buffer_ceiling is None:
        threshold = threshold * finops_percent(db, "circuit_breaker_threshold_pct", 100.0) / 100.0
    period = billing_period(data)
    if threshold and cost_amount >= threshold:
        if latch_matches(w_data.get(LATCH_FIELD), period, threshold):
            logger.info(json.dumps({"event": "BUDGET_BREACH_ALREADY_ENFORCED", "product_id": product_id,
                                    "period": period, "threshold": threshold, "message_id": message_id}))
            return {"status": "ALREADY_ENFORCED", "product_id": product_id, "cost_amount": cost_amount,
                    "threshold": threshold, "period": period}
        if refusal_recent(w_data.get(REFUSAL_FIELD), period, threshold, now):
            logger.info(json.dumps({"event": "BUDGET_BREACH_REFUSED_RECENTLY", "product_id": product_id,
                                    "period": period, "threshold": threshold, "message_id": message_id}))
            return {"status": "ALREADY_REFUSED", "product_id": product_id, "cost_amount": cost_amount,
                    "threshold": threshold, "period": period}
        logger.warning(f"Spend ${cost_amount:.2f} exceeded threshold ${threshold:.2f} for '{product_id}'. Triggering quarantine.")
        if not enforcement_enabled:
            logger.error(json.dumps({"error_class": "BUDGET_BREACH_ENFORCER_NOT_ENABLED", "product_id": product_id,
                                     "cost_amount": cost_amount, "threshold": threshold, "message_id": message_id}))
            raise BillingAlertError("ENFORCEMENT_DISABLED", 503,
                                    "BUDGET_BREACH_ENFORCER_NOT_ENABLED: billing_breach_enforcement_enabled is false")
        enforcer = get_enforcer()
        if not enforcer:
            # FD26-07: the enforcer is not packaged in the Control Center container. Say so (redelivery, then DLQ).
            raise BillingAlertError("ENFORCER_UNAVAILABLE", 503,
                                    "ENFORCER_UNAVAILABLE: budget breach detected but the enforcer is not available.")
        try:
            res = enforcer.quarantine_workload(
                product_id=product_id,
                target_project_id=target_project_id,
                spend_amount=cost_amount,
                budget_amount=threshold,
                policy=breach_policy,
            )
        except Exception as q_err:
            logger.error(f"Failed to execute quarantine: {q_err}")
            raise BillingAlertError("QUARANTINE_FAILED", 502, f"Quarantine failed: {q_err}")
        outcome = (res or {}).get("status")
        record = {"period": period, "threshold": threshold, "outcome": outcome, "message_id": message_id,
                  "execution": (res or {}).get("execution"), "at": now.isoformat()}
        if outcome == REFUSED:
            record["reason"] = str((res or {}).get("reason") or "")[:300]
        field = LATCH_FIELD if outcome in ENFORCED_STATUSES else REFUSAL_FIELD
        try:
            db.collection("workloads").document(product_id).set({field: record}, merge=True)
        except Exception as err:  # noqa: BLE001 - enforced; a re-sent alert gets the same outcome (RT14-05)
            logger.error(json.dumps({"error_class": "BUDGET_BREACH_LATCH_WRITE_FAILED", "product_id": product_id,
                                     "detail": f"{type(err).__name__}: {err}"[:300]}))
        return {"status": "QUARANTINE_EXECUTED" if outcome != REFUSED else REFUSED,
                "product_id": product_id, "result": res}

    # FD-4CI-b: Warning Threshold (%) -- spend at or above this share of the ceiling (or the approved buffer ceiling)
    # records a WARNING billing alert; nothing is stopped. Unreadable settings: no warning (the behaviour before).
    warning_pct = finops_percent(db, "warning_threshold_pct", None)
    if alert_base and warning_pct and cost_amount >= alert_base * warning_pct / 100.0:
        warning_at = round(alert_base * warning_pct / 100.0, 2)
        logger.warning(f"BUDGET_WARNING_THRESHOLD: '{product_id}' spend ${cost_amount:.2f} reached {warning_pct:g}% "
                       f"(${warning_at:.2f}) of its ${alert_base:.2f} ceiling; nothing is stopped.")
        # RT F1: one alert per workload and billing period (deterministic id, merge), updated with the latest spend.
        try:
            db.collection("billing_alerts").document(f"budget-warning-{product_id}-{period}").set({
                "product_id": product_id,
                "project_id": target_project_id,
                "code": "BUDGET_WARNING_THRESHOLD",
                "severity": "WARNING",
                "billing_period": period,
                "spend_amount": cost_amount,
                "budget_amount": alert_base,
                "warning_threshold_pct": warning_pct,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "message": f"Workload {product_id} reached {warning_pct:g}% of its budget ceiling "
                           f"(${cost_amount:.2f} / ${alert_base:.2f})",
            }, merge=True)
        except Exception as err:  # noqa: BLE001 - the notification is still logged above
            logger.warning(f"Could not record the budget warning for '{product_id}': {err}")
        return {
            "status": "WARNING_THRESHOLD",
            "product_id": product_id,
            "cost_amount": cost_amount,
            "threshold": threshold,
            "warning_at": warning_at,
        }

    return {
        "status": "UNDER_THRESHOLD",
        "product_id": product_id,
        "cost_amount": cost_amount,
        "threshold": threshold,
    }


# ------------------------------------------------------------------------------------------------ delivery claims
def _is_already_exists(exc: BaseException) -> bool:
    return type(exc).__name__ == "AlreadyExists" or getattr(exc, "code", None) == 409


def claim_delivery(db: Any, message_id: str, now_iso: str, run_id: str) -> str:
    """`billing_alert_deliveries/{messageId}` before any side effect. Returns "CLAIMED" (process it) or "DONE" (an
    earlier delivery of this exact message was processed: ack it, nothing else). A claim left PROCESSING or FAILED by
    an earlier attempt is taken over (the drain job holds a lease, so no other drain is processing it)."""
    ref = db.collection(DELIVERIES).document(message_id)
    record = {"message_id": message_id, "status": "PROCESSING", "claimed_at": now_iso, "run_id": run_id}
    try:
        ref.create(record)
        return "CLAIMED"
    except Exception as e:  # noqa: BLE001 - classified
        if not _is_already_exists(e):
            raise
    prior = ref.get()
    prior = (prior.to_dict() or {}) if getattr(prior, "exists", False) else {}
    if prior.get("status") == "DONE":
        return "DONE"
    ref.set(dict(record, attempts=int(prior.get("attempts", 1) or 1) + 1), merge=True)
    return "CLAIMED"


def record_unparseable(db: Any, message_id: str, message: Dict[str, Any], run_id: str, now_iso: str,
                       error_class: str) -> None:
    """RT finding 5: a notification that can never parse is acked, but leaves this record (what the dead-letter queue
    used to keep): the attributes, the publish time and the first 200 characters of its data."""
    attrs = message.get("attributes") if isinstance(message.get("attributes"), dict) else {}
    db.collection(DELIVERIES).document(message_id).set({
        "message_id": message_id, "status": "UNPARSEABLE", "error_class": error_class, "run_id": run_id,
        "recorded_at": now_iso, "publish_time": message.get("publishTime"), "attributes": dict(attrs),
        "data_prefix": str(message.get("data") or "")[:200],
    })


def finish_delivery(db: Any, message_id: str, status: str, outcome: Dict[str, Any], now_iso: str) -> None:
    """status DONE (acked) or FAILED (not acked; a redelivery takes it over)."""
    db.collection(DELIVERIES).document(message_id).set({
        "status": status, "finished_at": now_iso, "outcome": str((outcome or {}).get("status") or ""),
        "product_id": (outcome or {}).get("product_id"), "code": (outcome or {}).get("code"),
    }, merge=True)
