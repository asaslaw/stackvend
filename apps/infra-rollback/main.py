"""
StackVend: Infrastructure Rollback Service API
FastAPI interface for inspecting Terraform state versions and executing GCS state snapshot rollbacks.

FD-4AV-a: the HTTP endpoint and the Cloud Run job share ``perform_rollback`` and report the real outcome.
  HTTP: REVERTED 200; NO_PREVIOUS_VERSION 409; REFUSED_STATE_LOCKED 409; SUPERSEDED 409 (FD-4AV-b: a concurrent
        apply wrote over the restore, or holds the lock, right after the copy); ROLLBACK_UNAVAILABLE 503;
        ROLLBACK_FAILED 500; malformed input 422. The body is always the outcome record.
  Job (``run_batch``; plan 2.0 job contract): inputs only from ROLLBACK_PRODUCT_ID + ROLLBACK_TRACE_ID (required),
        ROLLBACK_TARGET_GENERATION and ROLLBACK_REASON (optional). Run record
        ``infra-rollback-job_runs/{CLOUD_RUN_EXECUTION}`` via create() (a retry of the same execution never rolls back
        twice). Exit 0 = REVERTED, 1 = any other outcome / failure, 2 = malformed input,
        3 = NOT_CONFIGURED (logged at WARNING; a required env var is missing). There is no sweep mode.
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Tuple

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from rollback import (
    InfraRollbackEngine, InvalidRollbackRequest, NO_PREVIOUS_VERSION, REFUSED_STATE_LOCKED, REVERTED,
    ROLLBACK_FAILED, ROLLBACK_UNAVAILABLE, RollbackUnavailable, SUPERSEDED,
)

logger = logging.getLogger("infra-rollback-runner")

JOB_NAME = "infra-rollback-job"
RUN_COLLECTION = f"{JOB_NAME}_runs"  # read by the sentinel (sre_classifier.run_record_collection)
EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_NOT_CONFIGURED = 0, 1, 2, 3
INVALID_REQUEST = "INVALID_REQUEST"

OUTCOME_HTTP_STATUS = {
    REVERTED: 200,
    NO_PREVIOUS_VERSION: 409,   # nothing was rolled back: not a success the caller may act on
    REFUSED_STATE_LOCKED: 409,
    SUPERSEDED: 409,            # FD-4AV-b: the restore did not stay the live state
    ROLLBACK_UNAVAILABLE: 503,
    ROLLBACK_FAILED: 500,
    INVALID_REQUEST: 422,
}
OUTCOME_EXIT_CODE = {REVERTED: EXIT_OK, INVALID_REQUEST: EXIT_USAGE}  # everything else -> EXIT_ERROR

app = FastAPI(
    title="StackVend Infrastructure Rollback Service",
    description="GCS Terraform remote state snapshot reversion for failed workload deployments.",
    version="1.1.0",
)

engine = InfraRollbackEngine()


# ------------------------------------------------------------------------------
# Request Models
# ------------------------------------------------------------------------------
class RollbackRequest(BaseModel):
    product_id: str
    trace_id: Optional[str] = None
    target_generation: Optional[str] = None
    reason: Optional[str] = "Deployment failure remediation"


def perform_rollback(req: RollbackRequest, rollback_engine: Optional[InfraRollbackEngine] = None) -> Dict[str, Any]:
    """The one rollback call used by POST /rollback and the batch job. Returns the outcome record; malformed input
    returns ``{"status": INVALID_REQUEST, ...}`` and touches nothing."""
    eng = rollback_engine or engine
    trace_id = req.trace_id or f"rb-tr-{req.product_id}-{uuid.uuid4().hex[:8]}"  # RT F4: unique audit doc
    try:
        return eng.execute_rollback(
            product_id=req.product_id,
            trace_id=trace_id,
            target_generation=req.target_generation,
            reason=req.reason or "Automated deployment failure rollback",
        )
    except InvalidRollbackRequest as e:
        return {"status": INVALID_REQUEST, "product_id": req.product_id, "trace_id": trace_id, "error": str(e)}


# ------------------------------------------------------------------------------
# Health Check
# ------------------------------------------------------------------------------
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "infra-rollback-job",
        "state_bucket": os.getenv("TFSTATE_BUCKET", ""),
        "environment": os.getenv("ENVIRONMENT", "prod"),
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


# ------------------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------------------
@app.post("/rollback")
def execute_rollback(req: RollbackRequest):
    """Restores the previous GCS state generation; the HTTP status reflects the real outcome."""
    record = perform_rollback(req)
    return JSONResponse(status_code=OUTCOME_HTTP_STATUS.get(record.get("status"), 500), content=record)


@app.get("/history/{product_id}")
def get_state_history(product_id: str):
    """Retrieves available GCS state snapshot versions for a specific workload."""
    try:
        versions = engine.get_state_history(product_id)
    except InvalidRollbackRequest as e:
        raise HTTPException(status_code=422, detail=str(e))
    except RollbackUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")
    return {
        "product_id": product_id,
        "state_versions_count": len(versions),
        "versions": versions,
    }


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
              rollback_engine: Optional[InfraRollbackEngine] = None) -> Tuple[int, Dict[str, Any]]:
    """One explicit rollback from env inputs. Returns (exit code, summary)."""
    env = os.environ if env is None else env
    missing = [k for k in ("PROJECT_ID", "ROLLBACK_PRODUCT_ID", "ROLLBACK_TRACE_ID") if not (env.get(k) or "").strip()]
    eng = rollback_engine if rollback_engine is not None else engine
    if missing:
        logger.warning(json.dumps({"error_class": "NOT_CONFIGURED", "missing": missing, "job": JOB_NAME}))
        summary = {"job": JOB_NAME, "outcome": "NOT_CONFIGURED", "missing": missing}
        _record_terminal(eng.db if "PROJECT_ID" not in missing else None, env, summary)
        return EXIT_NOT_CONFIGURED, summary

    try:
        req = RollbackRequest(product_id=env["ROLLBACK_PRODUCT_ID"].strip(), trace_id=env["ROLLBACK_TRACE_ID"].strip(),
                              target_generation=(env.get("ROLLBACK_TARGET_GENERATION") or "").strip() or None,
                              reason=(env.get("ROLLBACK_REASON") or "").strip() or None)
    except ValidationError as e:
        summary = {"job": JOB_NAME, "outcome": INVALID_REQUEST, "error": str(e)}
        _record_terminal(eng.db, env, summary)
        return EXIT_USAGE, summary

    if eng.db is None:
        logger.error(f"{JOB_NAME}: no Firestore client; refusing to roll back without a run record")
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
        logger.info(f"Run {run_id} already recorded ({prior.get('outcome')}); no second rollback.")
        if prior.get("outcome") == "RUNNING":
            return EXIT_ERROR, dict(prior, outcome="INTERRUPTED")
        return OUTCOME_EXIT_CODE.get(prior.get("outcome"), EXIT_ERROR), prior

    record = perform_rollback(req, eng)
    outcome = record.get("status") or ROLLBACK_FAILED
    summary = {"job": JOB_NAME, "run_id": run_id, "outcome": outcome, "started_at": started,
               "finished_at": datetime.now(timezone.utc).isoformat(), "product_id": req.product_id,
               "trace_id": req.trace_id, "target_generation": record.get("target_generation"),
               "message": record.get("message") or record.get("error")}
    try:
        run_ref.set(summary)
    except Exception as e:
        logger.warning(f"Could not finish run record {run_id}: {type(e).__name__}")
    return OUTCOME_EXIT_CODE.get(outcome, EXIT_ERROR), summary


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # If executed as a batch Cloud Run Job or CLI runner
    if os.getenv("CLOUD_RUN_JOB") or os.getenv("CLOUD_RUN_EXECUTION") or "--batch" in sys.argv or not os.getenv("PORT"):
        release_info.log_release("infra-rollback-job")  # FD-7C P3a: one stackvend.release line per run
        logger.info("Executing Infrastructure Rollback as Cloud Run Batch Job...")
        code, summary = run_batch()
        print(json.dumps(summary, indent=2, default=str))
        sys.exit(code)
    else:
        import uvicorn

        port = int(os.getenv("PORT", "8080"))
        uvicorn.run(app, host="0.0.0.0", port=port)
