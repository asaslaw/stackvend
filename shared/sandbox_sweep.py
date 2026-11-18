"""
StackVend: the ONE sandbox sweep (C10, owner 11-07; register row C10-MACHINE-CALLERS-OFF-CC).

Used by the Control Center's human manual trigger POST /api/workloads/sweep-expired-sandboxes (routes/workloads.py)
and by the sandbox-workload-sweeper-job Cloud Run job (apps/sandbox-sweeper/main.py, Cloud Scheduler
castor-sandbox-workload-sweeper). The body moved here verbatim from the Control Center route; only the calls that
differ between the two processes are injected:

- `decommission(product_id)` -> an outcome with `.ok .http_status .code .detail .body` (the Control Center:
  destructive_actions.call_vending with its ID token; the job: SandboxVendingClient below with ITS ID token). Lane 18
  S2: project-vending's destructive guard decides and executes every delete; nothing here deletes anything.
- `cancel_executions(target_product_id, operator_email, reason, failures)` -> the number of runs marked ABORTED (the
  Control Center: routes.workloads.cancel_workload_active_executions; the job: cancel_active_executions below with
  workflow_executions.cancel_bound_execution; SAT-43 fail-closed Workflows cascade cancel).

Guards kept exactly (pinned by tests/test_c10_sandbox_sweep.py): the platform self-preservation id set, the in-flight
(`feature_requests` IN_PROGRESS / RUNNING / DEPLOYING or an in-flight ledger status) and pending-review deferrals
(+24 h), BATCH_LIMIT = 10, `operator_email` "system-sandbox-sweeper" on every audit record, the statuses the dashboard
reads (DEFERRED_*, GUARD_REFUSED, DECOMMISSION_FAILED, DECOMMISSIONED, decommission_reason AUTO_SANDBOX_EXPIRATION),
the idempotent T-7 / T-2 notice flags. The sweep never mints or passes an approval (SANDBOX_TTL is approval-less).

Replicated (byte-identical, tests/test_c10_platform_tf.py::test_c10_copies_are_byte_identical): shared/, apps/control-center/shared/,
apps/sandbox-sweeper/shared/. Standard library only (+ shared.sandbox_detection).
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from shared.sandbox_detection import compute_days_remaining

logger = logging.getLogger("stackvend-sandbox-sweep")

SANDBOX_TTL = "SANDBOX_TTL"
SWEEP_OPERATOR = "system-sandbox-sweeper"
BATCH_LIMIT = 10
# Project-delete calls can take a while inside vending (guard reads + F8 re-check, each CRM call up to 10 s, then DNS,
# state archive and IPAM). Long enough that a slow success is not reported as VENDING_UNREACHABLE (lane 18 RT H4).
DECOMMISSION_TIMEOUT_SECONDS = 180.0

# Sandbox designation: only these are ever TTL-eligible at vending (lane 14 Q1 / lane 18 9b; exact set).
EXPLICIT_DESIGNATION_SOURCES = frozenset({"OPERATOR_CHECKBOX", "API_FIELD", "OPERATOR_CONFIRMED"})
# Ledger `ttl_authority` meaning vending will never auto-delete the project (lane 18 window RT H3).
TTL_AUTHORITY_DISPLAY_ONLY = "LEDGER_DISPLAY_ONLY"


class SandboxSweepUnavailable(RuntimeError):
    """No Firestore database: the route answers 503, the job ends FAILED (exit 1)."""


def sandbox_awaiting_confirmation(data: Dict[str, Any]) -> bool:
    """A sandbox whose designation is not explicit (keyword-detected, docs poller, or none recorded) is never
    TTL-deleted by vending until an ADMIN confirms it (POST /api/workloads/{pid}/sandbox/confirm). Exact-set test."""
    return data.get("is_sandbox") is True and data.get("sandbox_designation_source") not in EXPLICIT_DESIGNATION_SOURCES


def sandbox_notice_suffix(data: Dict[str, Any]) -> str:
    """The honest tail of a T-7 / T-2 notice: only an explicit, vending-enforced sandbox is auto-deleted at expiry."""
    if sandbox_awaiting_confirmation(data):
        return ("It will be deleted only after you confirm it (Confirm sandbox in the Control Center); until then "
                "nothing is deleted.")
    if data.get("ttl_authority") == TTL_AUTHORITY_DISPLAY_ONLY:
        return "Display only: vending has no vend-time record for it, so it is never auto-deleted."
    return "It will be auto-decommissioned at expiry unless extended or promoted."


def vending_error(resp) -> Dict[str, str]:
    """Vending's typed {code, detail} from a non-200 answer (its HTTPException detail object), else the HTTP status."""
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        body = None
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict) and isinstance(detail.get("code"), str):
        return {"code": detail["code"], "detail": str(detail.get("detail") or "")}
    text = detail if isinstance(detail, str) else (getattr(resp, "text", "") or "")
    return {"code": f"VENDING_HTTP_{resp.status_code}", "detail": str(text)[:500]}


class VendingResult:
    """The outcome shape the sweep reads (the Control Center's destructive_actions.VendingOutcome has the same fields)."""

    def __init__(self, ok: bool, http_status: int, code: str, detail: str, body: Optional[Dict[str, Any]] = None):
        self.ok, self.http_status, self.code, self.detail, self.body = ok, http_status, code, detail, body or {}


class SandboxVendingClient:
    """The sweeper job's own vending client (pre-review F21: not routes/settings.py): POST
    /projects/{id}/decommission {action_class: SANDBOX_TTL} with a Google ID token minted for VENDING_SERVICE_URL, the
    exact audience vending accepts. `http_post(url, json, headers, timeout)` -> a response with status_code / json()."""

    def __init__(self, vending_url: str, id_token: Callable[[str], str], http_post: Callable[..., Any]):
        self.url, self.id_token, self.http_post = vending_url.rstrip("/"), id_token, http_post

    def decommission(self, product_id: str) -> VendingResult:
        try:
            token = self.id_token(self.url)
            resp = self.http_post(f"{self.url}/projects/{product_id}/decommission", json={"action_class": SANDBOX_TTL},
                                  headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                           "Accept": "application/json"},
                                  timeout=DECOMMISSION_TIMEOUT_SECONDS)
        except Exception as e:  # noqa: BLE001 - typed, the sweep records it on the workload
            return VendingResult(False, 0, "VENDING_UNREACHABLE", f"{type(e).__name__}: {e}")
        status = getattr(resp, "status_code", 0)
        if status == 200:
            try:
                data = resp.json()
            except Exception:  # noqa: BLE001
                data = {}
            return VendingResult(True, 200, "OK", "", data if isinstance(data, dict) else {})
        err = vending_error(resp)
        return VendingResult(False, status, err["code"], err["detail"])


def cancel_active_executions(db: Any, target_product_id: str, operator_email: str, reason: str,
                             failures: Optional[List[Dict[str, Any]]], cancel_bound_execution: Callable[..., Any],
                             workflow_failed: str, project: str) -> int:
    """
    Finds and aborts any active/running pipeline executions for target_product_id: cancels the bound Cloud Workflows
    execution (SAT-43: Workflows REST API, typed outcome) and marks the record ABORTED. Returns the number marked.

    Fail closed (SAT-43): when the bound execution could not be cancelled (it may still be running) the record is NOT
    marked ABORTED; the attempt is kept on it (abort_attempt) and one entry {trace_id, execution, reason, detail} is
    appended to `failures` (when given), so the caller reports it. A failure to read the run records is appended too
    (trace_id None, reason PIPELINE_EXECUTIONS_UNREADABLE).
    """
    clean_pid = target_product_id.strip().lower()
    if not db:
        return 0
    failures = failures if failures is not None else []

    aborted_count = 0
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        col = db.collection("pipeline_executions")
        active_statuses = ["ACTIVE", "RUNNING", "PAUSED_RATE_LIMIT_COOLDOWN"]
        try:
            docs = list(col.where("product_id", "==", clean_pid).where("status", "in", active_statuses).stream())
        except Exception:
            docs = [d for d in col.where("product_id", "==", clean_pid).stream() if (d.to_dict() or {}).get("status") in active_statuses]

        for doc in docs:
            data = doc.to_dict() or {}
            wf_cancel = cancel_bound_execution(data, project)
            if wf_cancel is not None and wf_cancel["outcome"] == workflow_failed:
                logger.error(f"Run '{doc.id}' of workload '{clean_pid}' NOT aborted: its workflow execution "
                             f"{wf_cancel['name']!r} could not be cancelled ({wf_cancel['reason']}): "
                             f"{wf_cancel['detail']}")
                failures.append({"trace_id": doc.id, "execution": wf_cancel["name"], "reason": wf_cancel["reason"],
                                 "detail": wf_cancel["detail"]})
                doc.reference.set({"abort_attempt": {"at": now_iso, "by": operator_email, "reason": reason,
                                                     "workflow_cancel": {"name": wf_cancel["name"],
                                                                         "outcome": wf_cancel["outcome"],
                                                                         "reason": wf_cancel["reason"],
                                                                         "detail": wf_cancel["detail"],
                                                                         "state": wf_cancel["state"]}}}, merge=True)
                continue
            record = {
                "status": "ABORTED",
                "error_message": f"Execution aborted: {reason} (by {operator_email})",
                "ended_at": now_iso,
                "current_stage": "ABORTED",
            }
            if wf_cancel is not None:
                record["workflow_cancel"] = {"outcome": wf_cancel["outcome"], "reason": wf_cancel["reason"],
                                             "detail": wf_cancel["detail"]}
                logger.info(f"Workflow execution {wf_cancel['name']!r} for workload '{clean_pid}': "
                            f"{wf_cancel['outcome']}")
            doc.reference.set(record, merge=True)
            aborted_count += 1
            logger.info(f"Auto-aborted dangling execution '{doc.id}' for decommissioned workload '{clean_pid}'")
    except Exception as err:
        logger.error(f"Error checking active executions for decommission cascade on '{clean_pid}': {err}")
        failures.append({"trace_id": None, "execution": None, "reason": "PIPELINE_EXECUTIONS_UNREADABLE",
                         "detail": f"{type(err).__name__}: {err}"[:500]})

    return aborted_count


def cascade_failure_note(failures: List[Dict[str, Any]]) -> str:
    """One line for the decommission message / sweep errors (SAT-43)."""
    return ("Running workflow runs NOT aborted (they may still be running; cancel them in the Google Cloud console, "
            "Workflows): " + "; ".join(f"{f.get('trace_id') or 'run records'} ({f.get('reason')})" for f in failures))


def run_sweep(db: Any, *, decommission: Callable[[str], Any], cancel_executions: Callable[..., int]) -> Dict[str, Any]:
    """
    Sweeper for expired sandbox workloads. Returns the SandboxSweepResult fields (scanned_count, expired_count,
    decommissioned_workloads, deferred_workloads, notifications_sent, errors, not_eligible_workloads,
    refused_workloads).
    RT finding 4: an expired sandbox vending will never TTL-delete (awaiting confirmation, or a display-only TTL) is
    listed in `not_eligible_workloads` and never sent to vending (its dashboard status is untouched); a typed vending
    refusal (HTTP 403 / 409) is listed in `refused_workloads` (GUARD_REFUSED still recorded on the workload); only a
    failure (5xx, unreachable, anything else) is an `errors` entry.
    1. Scans Firestore for active sandboxes (is_sandbox == True, status != 'DECOMMISSIONED')
    2. Sends advance warning notifications:
       - T-7 advance warning if days_remaining <= 7.0 (and not sent)
       - T-2 urgent warning if days_remaining <= 2.0 (and not sent)
    3. Identifies expired sandboxes (days_remaining <= 0.0)
    4. Evaluates Red-Team Safeguards:
       - In-flight pipeline / active mission execution deferral (+24h)
       - Pending review / approval deferral (+24h)
       - Platform self-preservation guardrail
    5. Decommissions up to 10 expired sandboxes per batch through project-vending (lane 18 S2), one
       POST /projects/{id}/decommission {action_class: SANDBOX_TTL} per workload with the caller's ID token. Vending's
       guard decides (vend-time provenance + tag + ancestry + no liens + vend-time expiry; row 26) and executes:
       delete by project number, state archive, IPAM, ledger DECOMMISSIONED. Refusals/failures are reported in
       `errors` (GUARD_REFUSED / DECOMMISSION_FAILED on the workload), no retry loop. Nothing here deletes anything.
    """
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    if not db:
        raise SandboxSweepUnavailable("Database unavailable")

    platform_ids = {
        os.getenv("PROJECT_ID", "").strip(),
        os.getenv("PLATFORM_PROJECT_ID", "").strip(),
        "project-castor",
        "castor-platform",
        "castor",
        "platform",
    } - {""}

    scanned_count = 0
    expired_count = 0
    decommissioned_workloads: List[str] = []
    deferred_workloads: List[str] = []
    notifications_sent: List[str] = []
    errors: List[str] = []
    not_eligible_workloads: List[str] = []
    refused_workloads: List[str] = []

    def _result() -> Dict[str, Any]:
        return {"scanned_count": scanned_count, "expired_count": expired_count,
                "decommissioned_workloads": decommissioned_workloads, "deferred_workloads": deferred_workloads,
                "notifications_sent": notifications_sent, "errors": errors,
                "not_eligible_workloads": not_eligible_workloads, "refused_workloads": refused_workloads}

    try:
        docs = db.collection("workloads").where("is_sandbox", "==", True).stream()
    except Exception as e:
        logger.error(f"Error querying sandbox workloads: {e}")
        errors = [f"Failed to query sandboxes: {str(e)}"]
        return _result()

    expired_candidates = []

    for doc in docs:
        scanned_count += 1
        data = doc.to_dict() or {}
        pid = data.get("product_id") or doc.id
        status = data.get("status", "ACTIVE")

        # Skip already decommissioned workloads
        if status == "DECOMMISSIONED":
            continue

        expires_at_str = data.get("sandbox_expires_at")
        days_rem = compute_days_remaining(expires_at_str)
        if days_rem is None:
            continue

        # --- Advance Notifications (T-7 and T-2) ---
        creator_email = data.get("creator_email") or data.get("initialized_by") or "ops-team@company.internal"

        # T-7 Warning
        if days_rem <= 7.0 and days_rem > 2.0 and not data.get("warn_t7_sent"):
            warn_msg = (f"[T-7 Notice] Sandbox workload '{pid}' expires in {days_rem:.1f} days ({expires_at_str}). "
                        f"{sandbox_notice_suffix(data)} Creator: {creator_email}")
            logger.info(warn_msg)
            notifications_sent.append(warn_msg)
            try:
                db.collection("workloads").document(pid).set({"warn_t7_sent": True}, merge=True)
                audit_ref = db.collection("workloads").document(pid).collection("audit_logs").document()
                audit_ref.set({
                    "action": "SANDBOX_EXPIRATION_WARNING_T7",
                    "operator_email": SWEEP_OPERATOR,
                    "message": warn_msg,
                    "awaiting_confirmation": sandbox_awaiting_confirmation(data),
                    "days_remaining": days_rem,
                    "expires_at": expires_at_str,
                    "target_recipient": creator_email,
                    "timestamp": now_iso,
                })
            except Exception as w7_err:
                logger.warning(f"Failed to record T-7 warning for '{pid}': {w7_err}")

        # T-2 Urgent Warning
        if days_rem <= 2.0 and days_rem > 0.0 and not data.get("warn_t2_sent"):
            if sandbox_awaiting_confirmation(data) or data.get("ttl_authority") == TTL_AUTHORITY_DISPLAY_ONLY:
                warn_msg = (f"[T-2 Notice] Sandbox workload '{pid}' expires in {days_rem:.1f} days ({expires_at_str}). "
                            f"{sandbox_notice_suffix(data)} Creator: {creator_email}")
            else:
                warn_msg = (f"[T-2 URGENT] Sandbox workload '{pid}' will auto-decommission in {days_rem:.1f} days "
                            f"({expires_at_str}). Creator: {creator_email}")
            logger.warning(warn_msg)
            notifications_sent.append(warn_msg)
            try:
                db.collection("workloads").document(pid).set({"warn_t2_sent": True}, merge=True)
                audit_ref = db.collection("workloads").document(pid).collection("audit_logs").document()
                audit_ref.set({
                    "action": "SANDBOX_EXPIRATION_WARNING_T2",
                    "operator_email": SWEEP_OPERATOR,
                    "message": warn_msg,
                    "awaiting_confirmation": sandbox_awaiting_confirmation(data),
                    "days_remaining": days_rem,
                    "expires_at": expires_at_str,
                    "target_recipient": creator_email,
                    "timestamp": now_iso,
                })
            except Exception as w2_err:
                logger.warning(f"Failed to record T-2 warning for '{pid}': {w2_err}")

        # --- Identify Expired Sandboxes ---
        if days_rem <= 0.0:
            expired_count += 1
            if sandbox_awaiting_confirmation(data) or data.get("ttl_authority") == TTL_AUTHORITY_DISPLAY_ONLY:
                # Vending never TTL-deletes these (the T-2 notice says so): a known answer, not a request to make.
                logger.info(f"Expired sandbox '{pid}' is not TTL-eligible (awaiting confirmation or display-only "
                            "TTL); not sent to vending.")
                not_eligible_workloads.append(pid)
                continue
            expired_candidates.append((pid, data))

    # Process up to 10 expired workloads per batch
    batch_candidates = expired_candidates[:BATCH_LIMIT]

    for pid, data in batch_candidates:
        target_project_id = data.get("project_id") or pid
        status = data.get("status", "ACTIVE")

        # Safeguard 1: Platform Self-Preservation Guardrail
        if pid in platform_ids or target_project_id in platform_ids or target_project_id.startswith("castor-platform"):
            msg = f"Platform protection safeguard triggered: Sandbox sweep blocked deletion of platform project '{target_project_id}' for '{pid}'."
            logger.critical(msg)
            errors.append(msg)
            continue

        # Safeguard 2: In-flight Deployment / Mission Pipeline Deferral
        in_flight_statuses = ["IN_PROGRESS", "BUILDING", "DEPLOYING", "PROVISIONING"]
        is_in_flight = status in in_flight_statuses
        if not is_in_flight:
            try:
                reqs = db.collection("feature_requests").where("product_id", "==", pid).where("status", "in", ["IN_PROGRESS", "RUNNING", "DEPLOYING"]).limit(1).stream()
                if any(reqs):
                    is_in_flight = True
            except Exception as f_err:
                logger.warning(f"Could not check feature request status for '{pid}': {f_err}")

        if is_in_flight:
            defer_expiry = (now + timedelta(hours=24)).isoformat()
            db.collection("workloads").document(pid).set({
                "sandbox_expires_at": defer_expiry,
                "sandbox_decommission_status": "DEFERRED_ACTIVE_PIPELINE",
            }, merge=True)
            try:
                audit_ref = db.collection("workloads").document(pid).collection("audit_logs").document()
                audit_ref.set({
                    "action": "SANDBOX_DECOMMISSION_DEFERRED_ACTIVE_PIPELINE",
                    "operator_email": SWEEP_OPERATOR,
                    "deferred_until": defer_expiry,
                    "reason": "Active CI/CD or mission execution detected; deferred by 24 hours.",
                    "timestamp": now_iso,
                })
            except Exception as da_err:
                logger.warning(f"Audit log error for '{pid}': {da_err}")
            deferred_workloads.append(f"{pid} (active pipeline)")
            logger.info(f"Deferred decommission of sandbox '{pid}' due to active in-flight pipeline until {defer_expiry}")
            continue

        # Safeguard 3: Pending Review / Plan Approval Deferral
        has_pending_review = False
        try:
            p_reqs = db.collection("feature_requests").where("product_id", "==", pid).where("status", "in", ["PENDING_APPROVAL", "IN_REVIEW", "AWAITING_REVIEW"]).limit(1).stream()
            if any(p_reqs):
                has_pending_review = True
        except Exception as p_err:
            logger.warning(f"Could not check pending reviews for '{pid}': {p_err}")

        if has_pending_review:
            defer_expiry = (now + timedelta(hours=24)).isoformat()
            db.collection("workloads").document(pid).set({
                "sandbox_expires_at": defer_expiry,
                "sandbox_decommission_status": "DEFERRED_PENDING_REVIEW",
            }, merge=True)
            try:
                audit_ref = db.collection("workloads").document(pid).collection("audit_logs").document()
                audit_ref.set({
                    "action": "SANDBOX_DECOMMISSION_DEFERRED_PENDING_REVIEW",
                    "operator_email": SWEEP_OPERATOR,
                    "deferred_until": defer_expiry,
                    "reason": "Pending architect or human approval review detected; deferred by 24 hours.",
                    "timestamp": now_iso,
                })
            except Exception as dp_err:
                logger.warning(f"Audit log error for '{pid}': {dp_err}")
            deferred_workloads.append(f"{pid} (pending review)")
            logger.info(f"Deferred decommission of sandbox '{pid}' due to pending review until {defer_expiry}")
            continue

        # Lane 18 S2: vending decides and executes (SANDBOX_TTL, automatic; register row 26). Nothing here deletes.
        outcome = decommission(pid)
        if not outcome.ok:
            sweep_status = "DECOMMISSION_FAILED" if outcome.http_status == 502 else "GUARD_REFUSED"
            msg = (f"Sandbox sweep: vending {'failed to decommission' if sweep_status == 'DECOMMISSION_FAILED' else 'REFUSED deletion of'} "
                   f"'{pid}' ({outcome.code}): {outcome.detail}")
            if outcome.http_status in (403, 409):   # vending's typed guard answer: listed, not a failure
                logger.warning(msg)
                refused_workloads.append(f"{pid} ({outcome.code})")
            else:
                logger.error(msg)
                errors.append(msg)
            try:
                db.collection("workloads").document(pid).set({
                    "sandbox_decommission_status": sweep_status,
                    "sandbox_guard_refusal": outcome.code,
                }, merge=True)
                db.collection("workloads").document(pid).collection("audit_logs").document().set({
                    "action": "SANDBOX_TTL_DELETE_REFUSED", "operator_email": SWEEP_OPERATOR,
                    "refusal_code": outcome.code, "detail": outcome.detail, "vending_status": outcome.http_status,
                    "timestamp": now_iso})
            except Exception as rf_err:  # noqa: BLE001 - the refusal itself already happened
                logger.warning(f"Could not record the vending refusal for '{pid}': {rf_err}")
            continue

        # Vending deleted the project by number, archived state, freed IPAM and marked the ledger DECOMMISSIONED.
        vended = outcome.body
        deleted_project_id = vended.get("deleted_project_id") or target_project_id
        try:
            doc_ref = db.collection("workloads").document(pid)
            doc_ref.set({
                "sandbox_decommission_status": "DECOMMISSIONED",
                "decommission_reason": "AUTO_SANDBOX_EXPIRATION",
            }, merge=True)
            doc_ref.collection("audit_logs").document().set({
                "action": "AUTO_SANDBOX_DECOMMISSION_EXPIRED",
                "operator_email": SWEEP_OPERATOR,
                "deleted_project_id": deleted_project_id,
                "deleted_project_number": vended.get("deleted_project_number"),
                "crm_operation": vended.get("crm_operation"),
                "executed_by": "project-vending",
                "reason": "Autonomous Sandbox Lifecycle Expiration",
                "cumulative_lifespan_days": int(data.get("cumulative_lifespan_days", data.get("sandbox_ttl_days", 30)) or 0),
                "extension_count": int(data.get("extension_count", 0) or 0),
                "timestamp": now_iso,
            })

            # Cascade decommission to any active/running pipeline executions
            cascade_failures: List[Dict[str, Any]] = []
            aborted_runs = cancel_executions(
                target_product_id=pid,
                operator_email=SWEEP_OPERATOR,
                reason="Sandbox workload expired and was automatically decommissioned",
                failures=cascade_failures,
            )
            if cascade_failures:
                errors.append(f"{pid}: {cascade_failure_note(cascade_failures)}")
            if aborted_runs > 0:
                logger.info(f"Sandbox sweep decommission cascade aborted {aborted_runs} active execution(s) for '{pid}'")
        except Exception as post_err:  # noqa: BLE001 - the project is already deleted; never hide that
            logger.warning(f"Post-decommission bookkeeping notice for sandbox '{pid}': {post_err}")

        decommissioned_workloads.append(pid)
        logger.info(f"Vending auto-decommissioned expired sandbox workload '{pid}' ({deleted_project_id})")

    return _result()
