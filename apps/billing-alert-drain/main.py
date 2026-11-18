"""
StackVend: billing-alert-drain-job (C10, owner 11-07 "B"; register row C10-MACHINE-CALLERS-OFF-CC, enforcement ON).

Cloud Billing budget notifications land on the topic billing-budget-alerts. Its subscription
billing-alerts-push-subscription (the name is historical) is a PULL subscription since C10: until then it pushed to the
Control Center's /api/alerts/billing as sa-castor-finops, which Direct IAP refused. Cloud Scheduler
stackvend-billing-alert-drain runs this job every 30 minutes. It pulls the messages ONE at a time and handles each with
shared/billing_alerts.py process_billing_notification (a byte copy of the Control Center's): the install billing-account
check, the exact workload mapping, the spend record, the Warning Threshold record and, on a breach, the workload's
breach policy through finops-budget-enforcer-job (the enforcer is not packaged in the Control Center image, FD26-07):
one execution with the FINOPS_ENFORCE_* env overrides of its job contract, then this job waits for that execution's run
record `finops-budget-enforcer-job_runs/{execution}` (the verified outcome).

Per message (pre-review F14/F15):
- `billing_alert_deliveries/{messageId}` is claimed with create() before any side effect; a message already DONE is
  acked with nothing else (duplicate delivery). Exactly-once delivery is on for the subscription as well.
- the lease is extended (modifyAckDeadline 600 s) before processing and every 240 s while an enforcer execution runs.
- processed (UNDER_THRESHOLD / WARNING_THRESHOLD / ALREADY_ENFORCED / ALREADY_REFUSED / QUARANTINE_EXECUTED / REFUSED)
  or IGNORED (wrong billing account, unmapped, no project; typed log) -> the claim is DONE, then the message is acked.
- unparseable (not base64 JSON with a numeric costAmount) -> `billing_alert_deliveries/{messageId}` UNPARSEABLE
  (attributes, publish time, a 200-character data prefix), a typed log, then the ack; listed in the run record.
- pulls are batches of 10; the subscription counts as empty after 3 empty pulls in a row; an exactly-once
  PERMANENT_FAILURE_INVALID_ACK_ID on an ack / lease extension is counted (WARNING), never fatal.
- not processed (BillingAlertError: Firestore / enforcer unavailable, enforcement disabled, quarantine failed; or any
  unexpected error) -> the claim is FAILED and the message is NOT acked: it is held out of this run and redelivered to
  a later run; after the subscription's 5 delivery attempts Pub/Sub dead-letters it to castor-dlq.
Re-sent alerts (new message ids, same period and threshold) never enforce twice: the per-workload latch in
shared/billing_alerts.py. A per-run cap (MAX_MESSAGES_PER_RUN, PULL_TIME_BUDGET_S) keeps the job inside its task timeout.

Identity: sa-stackvend-billing-drain: subscriber on this one subscription, a custom role {run.jobs.run,
run.jobs.runWithOverrides, run.executions.get} on finops-budget-enforcer-job only, default-database datastore.user,
logWriter. Outcome: COMPLETED (exit 0) when every pulled message was acked; COMPLETED_WITH_ERRORS (exit 1) when any was
not; FAILED (exit 1) when the subscription cannot be read or acked; NOT_CONFIGURED (exit 3). Job contract:
shared/day2_job.py.

    python3 main.py            (Procfile; a Cloud Run job, max_retries = 0)
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Tuple

from shared import billing_alerts
from shared import day2_job as contract
# The enforcer-job client (quarantine here, restore in the Control Center): shared/enforcer_job.py.
from shared.enforcer_job import EnforcerJob

logger = logging.getLogger("billing-alert-drain-job")

JOB_NAME = "billing-alert-drain-job"
REQUIRED_ENV = ("PROJECT_ID", "REGION", "BILLING_ALERTS_SUBSCRIPTION", "FINOPS_ENFORCER_JOB", "BILLING_ACCOUNT_ID",
                "BILLING_BREACH_ENFORCEMENT")
PUBSUB_API = "https://pubsub.googleapis.com/v1"
HTTP_TIMEOUT_S = 60
MAX_MESSAGES_PER_RUN = 100
PULL_BATCH = 10                     # RT finding 2: a batch per pull, handled one message at a time
EMPTY_PULLS_TO_STOP = 3             # an empty answer is allowed with a backlog: stop only after 3 in a row
EMPTY_PULL_WAIT_S = 1
PULL_TIME_BUDGET_S = 600            # no new pull after this; the task timeout (Terraform local.job_timeouts) is 1800 s
HOLD_SECONDS = 600                  # ack deadline while a message is processed, or after it was not processed
EXTEND_EVERY_S = 240
ENFORCER_WAIT_S = 900               # the enforcer job's task timeout is the Cloud Run default (600 s) + start-up
POLL_INTERVAL_S = 10
LEASE_SECONDS = 3600                # > the task timeout


class DrainError(RuntimeError):
    """The subscription could not be read or acked (the run is FAILED; unacked messages are redelivered)."""


class AckIdExpired(RuntimeError):
    """RT finding 9: exactly-once delivery answered PERMANENT_FAILURE_INVALID_ACK_ID for this ack id (the lease had
    expired). Benign: the delivery claim decides what a redelivery does. Counted with a WARNING, never fatal."""


def _log(level: int, event: str, **fields: Any) -> None:
    logger.log(level, json.dumps({"event": event, "job": JOB_NAME, **fields}, sort_keys=True, default=str))


def _invalid_ack_ids(body: Any) -> Set[str]:
    """The ack ids an exactly-once acknowledge / modifyAckDeadline refused as PERMANENT_FAILURE_INVALID_ACK_ID: the
    google.rpc.ErrorInfo detail of the error body, its metadata {ackId: reason} read field by field."""
    err = body.get("error") if isinstance(body, dict) else None
    details = err.get("details") if isinstance(err, dict) else None
    out: Set[str] = set()
    for d in details if isinstance(details, list) else []:
        if isinstance(d, dict) and d.get("@type") == "type.googleapis.com/google.rpc.ErrorInfo":
            for ack_id, reason in (d.get("metadata") or {}).items():
                if reason == "PERMANENT_FAILURE_INVALID_ACK_ID":
                    out.add(ack_id)
    return out


class Subscription:
    """Pub/Sub REST pull / acknowledge / modifyAckDeadline on one subscription (projects/<p>/subscriptions/<s>)."""

    def __init__(self, session: Any, path: str):
        self.session, self.path = session, path

    def _post(self, verb: str, body: Dict[str, Any], ack_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        try:
            res = self.session.post(f"{PUBSUB_API}/{self.path}:{verb}", json=body, timeout=HTTP_TIMEOUT_S)
        except Exception as e:  # noqa: BLE001 - typed
            raise DrainError(f"PUBSUB_{verb.upper()}_FAILED: {type(e).__name__}: {e}")
        if res.status_code != 200:
            if ack_ids:   # acknowledge / modifyAckDeadline only; a pull failure stays fatal
                try:
                    expired = _invalid_ack_ids(res.json())
                except Exception:  # noqa: BLE001
                    expired = set()
                if expired and set(ack_ids) <= expired:
                    raise AckIdExpired(f"{verb}: {sorted(expired)}")
            raise DrainError(f"PUBSUB_{verb.upper()}_FAILED: HTTP {res.status_code}")
        try:
            body = res.json()
        except Exception:  # noqa: BLE001 - acknowledge / modifyAckDeadline answer {}
            return {}
        return body if isinstance(body, dict) else {}

    def pull(self, max_messages: int = PULL_BATCH) -> List[Dict[str, Any]]:
        received = self._post("pull", {"maxMessages": max_messages}).get("receivedMessages") or []
        return [r for r in received if isinstance(r, dict)]

    def ack(self, ack_id: str) -> None:
        self._post("acknowledge", {"ackIds": [ack_id]}, ack_ids=[ack_id])

    def hold(self, ack_ids: Any, seconds: int = HOLD_SECONDS) -> None:
        ids = [ack_ids] if isinstance(ack_ids, str) else list(ack_ids)
        if ids:
            self._post("modifyAckDeadline", {"ackIds": ids, "ackDeadlineSeconds": seconds}, ack_ids=ids)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def drain(sub: Subscription, database: Any, run_id: str, process: Callable[..., Dict[str, Any]],
          enforcer_for: Callable[[str, Callable[[], None]], Any],
          clock: Callable[[], float] = time.monotonic,
          sleep: Callable[[float], None] = time.sleep) -> Tuple[str, Dict[str, Any]]:
    """Pull batches of PULL_BATCH and handle the messages one at a time until EMPTY_PULLS_TO_STOP consecutive empty
    pulls, MAX_MESSAGES_PER_RUN or PULL_TIME_BUDGET_S (messages of a batch left over are released, deadline 0).
    `process(data, cost, attributes, get_enforcer, message_id)` -> the outcome dict, or raises BillingAlertError."""
    started = clock()
    by_status: Dict[str, int] = {}
    not_acked: List[Dict[str, Any]] = []
    enforcements: List[Dict[str, Any]] = []
    unparseable: List[str] = []
    held: Set[str] = set()
    handled = 0
    ack_expired = 0
    empty = 0
    batch: List[Dict[str, Any]] = []

    def count(status: str) -> None:
        by_status[status] = by_status.get(status, 0) + 1

    def tolerant(call: Callable[[], None], mid: str) -> None:
        nonlocal ack_expired
        try:
            call()
        except AckIdExpired as e:
            ack_expired += 1
            _log(logging.WARNING, "BILLING_ALERT_ACK_ID_EXPIRED", message_id=mid, detail=str(e)[:300])

    while handled < MAX_MESSAGES_PER_RUN and clock() - started < PULL_TIME_BUDGET_S:
        if not batch:
            batch = sub.pull(PULL_BATCH)
            if not batch:
                empty += 1
                if empty >= EMPTY_PULLS_TO_STOP:
                    break
                sleep(EMPTY_PULL_WAIT_S)
                continue
            empty = 0
        received = batch.pop(0)
        ack_id = received.get("ackId") or ""
        msg = received.get("message") or {}
        mid = str(msg.get("messageId") or "")
        attempt = received.get("deliveryAttempt")
        if mid and mid in held:
            tolerant(lambda: sub.hold(ack_id), mid)   # not processed earlier in this run: a later run retries it
            continue
        handled += 1
        try:
            data, cost = billing_alerts.decode_billing_notification(msg.get("data") or "")
        except Exception as e:  # noqa: BLE001 - it can never parse: a forensic record, a typed log, then the ack
            _log(logging.ERROR, "BILLING_ALERT_UNPARSEABLE", message_id=mid, delivery_attempt=attempt,
                 error_class=type(e).__name__)
            if mid:   # RT finding 5: the evidence the dead-letter queue used to keep
                billing_alerts.record_unparseable(database, mid, msg, run_id, _now_iso(), type(e).__name__)
                unparseable.append(mid)
            tolerant(lambda: sub.ack(ack_id), mid)
            count("UNPARSEABLE")
            continue

        if mid and billing_alerts.claim_delivery(database, mid, _now_iso(), run_id) == "DONE":
            _log(logging.INFO, "BILLING_ALERT_DUPLICATE_DELIVERY", message_id=mid, delivery_attempt=attempt)
            tolerant(lambda: sub.ack(ack_id), mid)
            count("DUPLICATE_DELIVERY")
            continue

        last = [clock()]

        def keepalive(ack_id=ack_id, last=last, mid=mid):
            # the message being processed and the rest of its batch keep their leases while an enforcer runs
            if clock() - last[0] >= EXTEND_EVERY_S:
                tolerant(lambda: sub.hold([ack_id] + [r.get("ackId") for r in batch if r.get("ackId")]), mid)
                last[0] = clock()

        tolerant(lambda: sub.hold(ack_id), mid)   # never let the lease lapse mid-processing
        try:
            result = process(data, cost, msg.get("attributes") or {}, lambda: enforcer_for(mid, keepalive), mid)
        except Exception as e:  # noqa: BLE001 - BillingAlertError or unexpected: not acked, typed
            code = getattr(e, "code", "PROCESSING_FAILED") if isinstance(e, billing_alerts.BillingAlertError) \
                else "PROCESSING_FAILED"
            _log(logging.ERROR, "BILLING_ALERT_NOT_PROCESSED", message_id=mid, delivery_attempt=attempt, code=code,
                 error_class=type(e).__name__, detail=str(getattr(e, "detail", e))[:500])
            not_acked.append({"message_id": mid, "code": code, "delivery_attempt": attempt})
            held.add(mid)
            if mid:
                billing_alerts.finish_delivery(database, mid, "FAILED", {"code": code}, _now_iso())
            tolerant(lambda: sub.hold(ack_id), mid)
            continue
        status = str((result or {}).get("status") or "UNKNOWN")
        if status == "IGNORED":
            _log(logging.WARNING, "BILLING_ALERT_IGNORED", message_id=mid, reason=result.get("reason", ""),
                 product_id=result.get("product_id", ""))
        if status in ("QUARANTINE_EXECUTED", billing_alerts.REFUSED):
            enforcements.append({"message_id": mid, "product_id": result.get("product_id"), "status": status,
                                 "outcome": (result.get("result") or {}).get("status"),
                                 "execution": (result.get("result") or {}).get("execution")})
        if mid:
            billing_alerts.finish_delivery(database, mid, "DONE", result, _now_iso())
        tolerant(lambda: sub.ack(ack_id), mid)
        count(status)

    leftover = [r.get("ackId") for r in batch if r.get("ackId")]
    if leftover:   # the run cap was reached mid-batch: give them back now instead of holding them
        tolerant(lambda: sub.hold(leftover, 0), "")
    detail = {"handled": handled, "by_status": by_status, "not_acked": not_acked, "enforcements": enforcements,
              "unparseable": unparseable, "ack_expired": ack_expired, "released": len(leftover)}
    return (contract.COMPLETED_WITH_ERRORS if not_acked else contract.COMPLETED), detail


def _default_session() -> Any:
    import google.auth
    from google.auth.transport.requests import AuthorizedSession
    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    return AuthorizedSession(creds)


def _db(project: str):
    from google.cloud import firestore
    try:
        return firestore.Client(project=project)
    except Exception as e:  # noqa: BLE001 - run_job reports RUN_RECORD_UNAVAILABLE
        logger.error(f"Could not open the Firestore database: {type(e).__name__}: {e}")
        return None


def run(env: Optional[Mapping[str, str]] = None, database: Any = None, session: Any = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep) -> Tuple[int, Dict[str, Any]]:
    env = os.environ if env is None else env
    project = (env.get("PROJECT_ID") or "").strip()
    if database is None and project:
        database = _db(project)

    def work(run_id: str) -> Tuple[str, Dict[str, Any]]:
        flag = (env.get("BILLING_BREACH_ENFORCEMENT") or "").strip()
        if flag not in ("true", "false"):
            raise ValueError(f"BILLING_BREACH_ENFORCEMENT must be exactly true or false, not {flag!r}")
        http = session if session is not None else _default_session()
        sub = Subscription(http, env["BILLING_ALERTS_SUBSCRIPTION"].strip())

        def enforcer_for(message_id: str, keepalive: Callable[[], None]) -> EnforcerJob:
            return EnforcerJob(http, database, project, env["REGION"].strip(), env["FINOPS_ENFORCER_JOB"].strip(),
                               keepalive=keepalive, trace_id=f"billing-alert-{message_id}" if message_id else "",
                               clock=clock, sleep=sleep, wait_s=ENFORCER_WAIT_S, poll_s=POLL_INTERVAL_S)

        def process(data, cost, attributes, get_enforcer, message_id):
            return billing_alerts.process_billing_notification(
                database, data, cost, attributes, get_enforcer,
                install_billing_account=env["BILLING_ACCOUNT_ID"], enforcement_enabled=(flag == "true"),
                message_id=message_id)

        return drain(sub, database, run_id, process, enforcer_for, clock=clock, sleep=sleep)

    return contract.run_job(JOB_NAME, work, database, env, required_env=REQUIRED_ENV, lease_seconds=LEASE_SECONDS)


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    release_info.log_release("billing-alert-drain-job")  # FD-7C P3a: one stackvend.release line per run
    code, summary = run()
    print(json.dumps(summary, indent=2, default=str))
    return code


if __name__ == "__main__":
    sys.exit(main())
