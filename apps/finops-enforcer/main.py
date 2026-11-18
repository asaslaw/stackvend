"""
Project Castor: FinOps Budget Enforcer Service API
FastAPI interface for executing budget auto-kill actions, restoring workload services,
and ingesting real-time Google Cloud Billing Budget Pub/Sub alerts with OIDC verification.

FD-4AV-a: POST /enforce and the Cloud Run job share ``perform_enforce`` (same request model, same engine call, same
FD-4O host/ancestry guard inside ``quarantine_workload``). Job contract (``run_batch``, plan 2.0): inputs only from
FINOPS_ENFORCE_PRODUCT_ID + FINOPS_ENFORCE_TARGET_PROJECT_ID (required) and FINOPS_ENFORCE_TRACE_ID /
FINOPS_ENFORCE_SPEND_AMOUNT / FINOPS_ENFORCE_BUDGET_AMOUNT / FINOPS_ENFORCE_POLICY (optional, same defaults as
/enforce). Run record ``finops-budget-enforcer-job_runs/{CLOUD_RUN_EXECUTION}`` via create() (a retry of the same
execution never enforces twice). Exit 0 = the engine reported an action it took (ENFORCED_STATUSES), 1 = refused or
failed, 2 = malformed input, 3 = NOT_CONFIGURED (WARNING; a required env var is missing). There is no sweep mode.
C10: FINOPS_ACTION=RESTORE runs one restore instead (run_restore_batch; the Control Center's budget-breach approvals,
through shared/enforcer_job.py); unset or QUARANTINE is the contract above, unchanged.
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

from fastapi import Depends, FastAPI, HTTPException, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError, field_validator

from enforcer import ADVISOR_WAIT_S, FinopsBudgetEnforcer, BudgetBreachPolicy

logger = logging.getLogger("finops-enforcer-api")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="StackVend FinOps Budget Enforcer Service",
    description="Automates 100% budget breach quarantine workflows (multi-resource scale-to-zero) and service restoration.",
    version="1.1.0",
)

enforcer = FinopsBudgetEnforcer()

JOB_NAME = "finops-budget-enforcer-job"
RUN_COLLECTION = f"{JOB_NAME}_runs"  # read by the sentinel (sre_classifier.run_record_collection)
EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_NOT_CONFIGURED = 0, 1, 2, 3
# Exact statuses quarantine_workload returns after acting (anything else, e.g. REFUSED, is not a success).
ENFORCED_STATUSES = frozenset({"QUARANTINED", "ALERTED_ONLY", "BILLING_UNLINKED", "HITL_CONFIRMATION_PENDING"})
# C10 (RT residual R3): the job also restores (FINOPS_ACTION=RESTORE): the Control Center cannot import the engine
# (FD26-07), so its budget-breach approvals run this job (shared/enforcer_job.py). Exact statuses restore_workload
# returns after acting; anything else (REFUSED, FAILED) is not a success.
RESTORE_STATUSES = frozenset({"RESTORED", "BILLING_RESTORED", "NOTHING_TO_RESTORE"})
ACTIONS = frozenset({"QUARANTINE", "RESTORE"})
RESTORE_MAX_INSTANCES_CAP = 100   # RT D3: an override above this is INVALID_REQUEST
# FD-4AV-a F5 / F5-b: POST /enforce and POST /restore answer a refusal (the engine's FD-4O target guard, status
# REFUSED) with HTTP 409 and the engine's typed body unchanged, so no HTTP caller can read a refusal as a 200 success. 409, not 5xx: retrying the
# same request cannot change the guard's answer, and 5xx would invite automatic retries.
REFUSED_HTTP_STATUS = 409


# ------------------------------------------------------------------------------
# Request & Webhook Models
# ------------------------------------------------------------------------------
KNOWN_POLICIES = frozenset(p.value for p in BudgetBreachPolicy)


def policy_is_known(policy: str) -> bool:
    """Exact enum match after the engine's own normalization (``str(policy).upper()``), so a known value the engine
    accepts today is never refused here."""
    return str(policy).upper() in KNOWN_POLICIES


class QuarantineRequest(BaseModel):
    product_id: str
    target_project_id: Optional[str] = None
    trace_id: Optional[str] = None
    spend_amount: Optional[float] = 0.0
    budget_amount: Optional[float] = 0.0
    policy: Optional[str] = "AUTONOMOUS_SCALE_TO_ZERO"

    @field_validator("policy")
    @classmethod
    def _policy_must_be_known(cls, value: Optional[str]) -> Optional[str]:
        # FD-4AV-a F5-c: the engine treats any unknown policy as AUTONOMOUS_SCALE_TO_ZERO (its final branch). An
        # unknown policy is refused at the request boundary instead (POST /enforce -> 422; the batch job -> exit 2
        # INVALID_REQUEST). None / "" keep today's meaning (the default policy); the value is passed on unchanged.
        if value is None or value == "" or policy_is_known(value):
            return value
        raise ValueError(f"unknown policy {value!r}; allowed: {sorted(KNOWN_POLICIES)}")


class RestoreRequest(BaseModel):
    product_id: str
    target_project_id: Optional[str] = None
    max_instances: Optional[int] = None   # C10 (RT D3): None = a snapshot entry without a max keeps its max
    root_billing_account: Optional[str] = None   # must equal the recorded / install account (else refused)


class PubSubMessage(BaseModel):
    data: str
    messageId: Optional[str] = None
    publishTime: Optional[str] = None
    attributes: Optional[Dict[str, str]] = None


class PubSubPushEnvelope(BaseModel):
    message: PubSubMessage
    subscription: Optional[str] = None


# ------------------------------------------------------------------------------
# Health Check
# ------------------------------------------------------------------------------
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "finops-budget-enforcer-job",
        "environment": os.getenv("ENVIRONMENT", "prod"),
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


# ------------------------------------------------------------------------------
# Caller verification (FD-4O / FD26-20). Fails closed; no TEST_MODE / ENVIRONMENT bypass.
# The duplicate Pub/Sub billing webhook that lived here (no audience, optional header) is deleted: the Control
# Center's /api/alerts/billing is the only billing ingress.
# ------------------------------------------------------------------------------
def require_platform_caller(authorization: Optional[str] = Header(None)) -> str:
    audience = (os.getenv("FINOPS_SERVICE_URL") or "").strip().rstrip("/")
    allowed = {e.strip().lower() for e in (os.getenv("FINOPS_ALLOWED_CALLERS") or "").split(",") if e.strip()}
    if not audience or not allowed:
        raise HTTPException(status_code=503, detail="Caller verification is not configured (FINOPS_SERVICE_URL / FINOPS_ALLOWED_CALLERS).")
    if not authorization or not authorization.startswith("Bearer ") or not authorization[7:].strip():
        raise HTTPException(status_code=401, detail="Missing Authorization Bearer token.")
    try:
        from google.oauth2 import id_token
        from google.auth.transport import requests as auth_requests
        info = id_token.verify_oauth2_token(authorization[7:].strip(), auth_requests.Request(), audience=audience)
    except Exception as e:
        logger.warning(f"Rejected enforcer caller token: {e}")
        raise HTTPException(status_code=401, detail="Invalid OIDC token.")
    email = (info.get("email") or "").strip().lower()
    if not info.get("email_verified") or email not in allowed:
        raise HTTPException(status_code=403, detail="Caller is not an allow-listed platform service account.")
    return email


def perform_enforce(req: QuarantineRequest, engine: Optional[FinopsBudgetEnforcer] = None) -> Dict[str, Any]:
    """The one enforcement call used by POST /enforce and the batch job (the FD-4O guard runs inside)."""
    return (engine or enforcer).quarantine_workload(
        product_id=req.product_id,
        target_project_id=req.target_project_id,
        trace_id=req.trace_id,
        spend_amount=req.spend_amount or 0.0,
        budget_amount=req.budget_amount or 0.0,
        policy=req.policy or "AUTONOMOUS_SCALE_TO_ZERO",
    )


# ------------------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------------------
@app.post("/enforce", dependencies=[Depends(require_platform_caller)])
def enforce_quarantine(req: QuarantineRequest):
    """Executes budget enforcement: scales services to 0 or detaches billing based on policy.

    409 = REFUSED (same typed body as the engine returned); 500 = the engine raised; 200 = any other engine result
    (today only ENFORCED_STATUSES); 422 = an unknown policy (FD-4AV-a F5-c; the engine is never called)."""
    try:
        result = perform_enforce(req)
    except Exception as e:
        logger.error(f"Quarantine enforcement failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    if isinstance(result, dict) and result.get("status") == "REFUSED":
        return JSONResponse(status_code=REFUSED_HTTP_STATUS, content=result)
    return result


@app.post("/restore", dependencies=[Depends(require_platform_caller)])
def restore_services(req: RestoreRequest):
    """Restores operational scaling limits for a previously quarantined workload.

    FD-4AV-a F5-b: 409 = REFUSED (same typed body as the engine returned, like /enforce); 500 = the engine raised;
    200 = any other engine result."""
    try:
        result = enforcer.restore_workload(
            product_id=req.product_id,
            target_project_id=req.target_project_id,
            max_instances=req.max_instances,
            root_billing_account=req.root_billing_account,
        )
    except Exception as e:
        logger.error(f"Workload restoration failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    if isinstance(result, dict) and result.get("status") == "REFUSED":
        return JSONResponse(status_code=REFUSED_HTTP_STATUS, content=result)
    return result


# ------------------------------------------------------------------------------
# Cloud Run job (plan 2.0 job contract)
# ------------------------------------------------------------------------------
def _is_already_exists(exc: BaseException) -> bool:
    return type(exc).__name__ == "AlreadyExists" or getattr(exc, "code", None) == 409


def _record_terminal(db: Any, env: Mapping[str, str], summary: Dict[str, Any]) -> None:
    """RT L2: an execution that ends before the claim (NOT_CONFIGURED / INVALID_REQUEST) still leaves a run record,
    so the sentinel reads its outcome instead of "no record"."""
    if db is None:
        return
    run_id = env.get("CLOUD_RUN_EXECUTION") or f"manual-{uuid.uuid4().hex[:12]}"
    try:
        db.collection(RUN_COLLECTION).document(run_id).set(dict(summary, run_id=run_id))
    except Exception as e:
        logger.warning(f"Could not record {summary.get('outcome')} run {run_id}: {type(e).__name__}")


def run_batch(env: Optional[Mapping[str, str]] = None,
              engine: Optional[FinopsBudgetEnforcer] = None) -> Tuple[int, Dict[str, Any]]:
    """One explicit enforcement from env inputs. Returns (exit code, summary). FINOPS_ACTION unset or QUARANTINE is
    the original contract (unchanged); RESTORE runs run_restore_batch; anything else is INVALID_REQUEST (exit 2)."""
    env = os.environ if env is None else env
    eng = engine if engine is not None else enforcer
    action = (env.get("FINOPS_ACTION") or "").strip().upper() or "QUARANTINE"
    if action not in ACTIONS:
        summary = {"job": JOB_NAME, "outcome": "INVALID_REQUEST", "error": f"unknown FINOPS_ACTION {action!r}"}
        _record_terminal(eng.db if (env.get("PROJECT_ID") or "").strip() else None, env, summary)
        return EXIT_USAGE, summary
    if action == "RESTORE":
        return run_restore_batch(env, eng)
    missing = [k for k in ("PROJECT_ID", "FINOPS_ENFORCE_PRODUCT_ID", "FINOPS_ENFORCE_TARGET_PROJECT_ID")
               if not (env.get(k) or "").strip()]
    if missing:
        logger.warning(json.dumps({"error_class": "NOT_CONFIGURED", "missing": missing, "job": JOB_NAME}))
        summary = {"job": JOB_NAME, "outcome": "NOT_CONFIGURED", "missing": missing}
        _record_terminal(eng.db if "PROJECT_ID" not in missing else None, env, summary)
        return EXIT_NOT_CONFIGURED, summary

    fields: Dict[str, Any] = {"product_id": env["FINOPS_ENFORCE_PRODUCT_ID"].strip(),
                              "target_project_id": env["FINOPS_ENFORCE_TARGET_PROJECT_ID"].strip()}
    for key, field in (("FINOPS_ENFORCE_TRACE_ID", "trace_id"), ("FINOPS_ENFORCE_SPEND_AMOUNT", "spend_amount"),
                       ("FINOPS_ENFORCE_BUDGET_AMOUNT", "budget_amount"), ("FINOPS_ENFORCE_POLICY", "policy")):
        value = (env.get(key) or "").strip()
        if value:
            fields[field] = value
    # RT F3: the engine treats any unknown policy as AUTONOMOUS_SCALE_TO_ZERO. At the job boundary a typo (set by
    # hand at `jobs execute`) must not escalate to the destructive default: exact enum match after the engine's upper().
    if "policy" in fields and not policy_is_known(fields["policy"]):
        summary = {"job": JOB_NAME, "outcome": "INVALID_REQUEST",
                   "error": f"unknown FINOPS_ENFORCE_POLICY {fields['policy']!r}"}
        _record_terminal(eng.db, env, summary)
        return EXIT_USAGE, summary
    try:
        req = QuarantineRequest(**fields)  # the same request model (and coercion) as POST /enforce
    except ValidationError as e:
        summary = {"job": JOB_NAME, "outcome": "INVALID_REQUEST", "error": str(e)}
        _record_terminal(eng.db, env, summary)
        return EXIT_USAGE, summary

    if eng.db is None:
        logger.error(f"{JOB_NAME}: no Firestore client; refusing to enforce without a run record")
        return EXIT_ERROR, {"job": JOB_NAME, "outcome": "ERROR", "error": "RUN_RECORD_UNAVAILABLE"}
    run_id = env.get("CLOUD_RUN_EXECUTION") or f"manual-{uuid.uuid4().hex[:12]}"
    run_ref = eng.db.collection(RUN_COLLECTION).document(run_id)
    started = datetime.now(timezone.utc).isoformat()
    try:
        run_ref.create({"job": JOB_NAME, "run_id": run_id, "outcome": "RUNNING", "started_at": started})
    except Exception as e:
        if not _is_already_exists(e):
            logger.error(f"Run record {run_id} could not be created: {type(e).__name__}")
            return EXIT_ERROR, {"job": JOB_NAME, "outcome": "ERROR", "error": "RUN_RECORD_UNAVAILABLE"}
        prior = run_ref.get().to_dict() or {}
        logger.info(f"Run {run_id} already recorded ({prior.get('outcome')}); no second enforcement.")
        if prior.get("outcome") == "RUNNING":
            return EXIT_ERROR, dict(prior, outcome="INTERRUPTED")
        return (EXIT_OK if prior.get("outcome") in ENFORCED_STATUSES else EXIT_ERROR), prior

    try:
        result = perform_enforce(req, eng)
        outcome = result.get("status") if isinstance(result, dict) else None
        detail = {"reason": result.get("reason")} if isinstance(result, dict) and result.get("reason") else {}
        # RT14-20: the run record keeps a copy of the pre-quarantine snapshot (with the quarantine record's copy and
        # quarantine_snapshots/{id}), and the typed class of a stop.
        if isinstance(result, dict) and isinstance(result.get("snapshot"), dict):
            detail["snapshot"] = result["snapshot"]
        if isinstance(result, dict) and result.get("error_class"):
            detail["error_class"] = result["error_class"]
    except Exception as e:
        logger.error(f"FinOps enforcement failed: {type(e).__name__}: {e}")
        outcome, detail = "FAILED", {"error": f"{type(e).__name__}: {e}"}
    outcome = outcome if isinstance(outcome, str) and outcome else "FAILED"
    summary = {"job": JOB_NAME, "run_id": run_id, "outcome": outcome, "started_at": started,
               "finished_at": datetime.now(timezone.utc).isoformat(), "product_id": req.product_id,
               "target_project_id": req.target_project_id, "policy": req.policy, **detail}
    try:
        run_ref.set(summary)
    except Exception as e:
        logger.warning(f"Could not finish run record {run_id}: {type(e).__name__}")
    # FD-4CI-b-R2: the card recommendation started after the enforcement action may still be running; the run record
    # above is already final, so this bounded wait only keeps the process alive until the advisor call ends.
    waiter = getattr(eng, "wait_for_recommendations", None)
    if callable(waiter):
        waiter(ADVISOR_WAIT_S)
    return (EXIT_OK if outcome in ENFORCED_STATUSES else EXIT_ERROR), summary


def run_restore_batch(env: Mapping[str, str], eng: FinopsBudgetEnforcer) -> Tuple[int, Dict[str, Any]]:
    """C10: one restore (engine restore_workload, with its FD-4O target guard) from env inputs: FINOPS_ENFORCE_PRODUCT_ID
    and FINOPS_ENFORCE_TARGET_PROJECT_ID (required), FINOPS_RESTORE_MAX_INSTANCES (optional int, 1..100: the max for
    snapshot entries that recorded none). The billing account is never an input (RT D5): the engine relinks the one
    recorded at unlink time, else BILLING_ACCOUNT_ID. The same run-record contract as the quarantine: create() claim (a
    retry of the same execution never restores twice), exit 0 = RESTORE_STATUSES, 1 = refused / failed / partial,
    2 = malformed input, 3 = NOT_CONFIGURED."""
    missing = [k for k in ("PROJECT_ID", "FINOPS_ENFORCE_PRODUCT_ID", "FINOPS_ENFORCE_TARGET_PROJECT_ID")
               if not (env.get(k) or "").strip()]
    if missing:
        logger.warning(json.dumps({"error_class": "NOT_CONFIGURED", "missing": missing, "job": JOB_NAME,
                                   "action": "RESTORE"}))
        summary = {"job": JOB_NAME, "action": "RESTORE", "outcome": "NOT_CONFIGURED", "missing": missing}
        _record_terminal(eng.db if "PROJECT_ID" not in missing else None, env, summary)
        return EXIT_NOT_CONFIGURED, summary
    product_id = env["FINOPS_ENFORCE_PRODUCT_ID"].strip()
    target = env["FINOPS_ENFORCE_TARGET_PROJECT_ID"].strip()
    raw_max = (env.get("FINOPS_RESTORE_MAX_INSTANCES") or "").strip()
    kwargs: Dict[str, Any] = {}
    if raw_max:
        if not raw_max.isdigit() or not 1 <= int(raw_max) <= RESTORE_MAX_INSTANCES_CAP:
            summary = {"job": JOB_NAME, "action": "RESTORE", "outcome": "INVALID_REQUEST",
                       "error": f"FINOPS_RESTORE_MAX_INSTANCES must be an integer 1..{RESTORE_MAX_INSTANCES_CAP}, "
                                f"not {raw_max!r}"}
            _record_terminal(eng.db, env, summary)
            return EXIT_USAGE, summary
        kwargs["max_instances"] = int(raw_max)
    if (env.get("FINOPS_RESTORE_BILLING_ACCOUNT") or "").strip():
        summary = {"job": JOB_NAME, "action": "RESTORE", "outcome": "INVALID_REQUEST",
                   "error": "FINOPS_RESTORE_BILLING_ACCOUNT is not accepted: the restore relinks the account recorded "
                            "at unlink time (else BILLING_ACCOUNT_ID)"}
        _record_terminal(eng.db, env, summary)
        return EXIT_USAGE, summary

    if eng.db is None:
        logger.error(f"{JOB_NAME}: no Firestore client; refusing to restore without a run record")
        return EXIT_ERROR, {"job": JOB_NAME, "action": "RESTORE", "outcome": "ERROR", "error": "RUN_RECORD_UNAVAILABLE"}
    run_id = env.get("CLOUD_RUN_EXECUTION") or f"manual-{uuid.uuid4().hex[:12]}"
    run_ref = eng.db.collection(RUN_COLLECTION).document(run_id)
    started = datetime.now(timezone.utc).isoformat()
    try:
        run_ref.create({"job": JOB_NAME, "action": "RESTORE", "run_id": run_id, "outcome": "RUNNING",
                        "started_at": started})
    except Exception as e:
        if not _is_already_exists(e):
            logger.error(f"Run record {run_id} could not be created: {type(e).__name__}")
            return EXIT_ERROR, {"job": JOB_NAME, "action": "RESTORE", "outcome": "ERROR",
                                "error": "RUN_RECORD_UNAVAILABLE"}
        prior = run_ref.get().to_dict() or {}
        logger.info(f"Run {run_id} already recorded ({prior.get('outcome')}); no second restore.")
        if prior.get("outcome") == "RUNNING":
            return EXIT_ERROR, dict(prior, outcome="INTERRUPTED")
        return (EXIT_OK if prior.get("outcome") in RESTORE_STATUSES else EXIT_ERROR), prior
    try:
        result = eng.restore_workload(product_id=product_id, target_project_id=target, **kwargs)
        outcome = result.get("status") if isinstance(result, dict) else None
        detail = {"reason": result.get("reason")} if isinstance(result, dict) and result.get("reason") else {}
        # RT14-05: which resources a RESTORE_PARTIAL did not restore or could not confirm
        for key in ("failed", "unverified"):
            if isinstance(result, dict) and result.get(key):
                detail[key] = list(result[key])
    except Exception as e:
        logger.error(f"FinOps restore failed: {type(e).__name__}: {e}")
        outcome, detail = "FAILED", {"error": f"{type(e).__name__}: {e}"}
    outcome = outcome if isinstance(outcome, str) and outcome else "FAILED"
    summary = {"job": JOB_NAME, "action": "RESTORE", "run_id": run_id, "outcome": outcome, "started_at": started,
               "finished_at": datetime.now(timezone.utc).isoformat(), "product_id": product_id,
               "target_project_id": target, **detail}
    try:
        run_ref.set(summary)
    except Exception as e:
        logger.warning(f"Could not finish run record {run_id}: {type(e).__name__}")
    return (EXIT_OK if outcome in RESTORE_STATUSES else EXIT_ERROR), summary


if __name__ == "__main__":
    # If executed as a batch Cloud Run Job or CLI runner
    if os.getenv("CLOUD_RUN_JOB") or os.getenv("CLOUD_RUN_EXECUTION") or "--batch" in sys.argv or not os.getenv("PORT"):
        release_info.log_release("finops-budget-enforcer-job")  # FD-7C P3a: one stackvend.release line per run
        logger.info("Executing FinOps Budget Enforcer as Cloud Run Batch Job...")
        code, summary = run_batch()
        print(json.dumps(summary, indent=2, default=str))
        sys.exit(code)
    else:
        import uvicorn

        port = int(os.getenv("PORT", "8080"))
        uvicorn.run(app, host="0.0.0.0", port=port)
