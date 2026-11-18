"""
StackVend: Log SRE Sentinel Service API (C27).
Event-driven microservice recording Cloud Logging error incidents and dispatching the castor-sre-remediation workflow
per the dispatch rules in sentinel.py (Wave 2 lane 14 PR-2, owner register row 24).
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import base64
import json
import logging
import os
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from sentinel import CallerRefused, FirestoreUnavailable, LogSRESentinel, RegistrationRejected, is_sentinel_own_entry

logger = logging.getLogger("log-sre-sentinel-service")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="StackVend Log SRE Sentinel Service",
    description="Incident classification, recording, stack trace fingerprinting and SRE remediation dispatch.",
    version="2.0.0",
)

_sentinel: Optional[LogSRESentinel] = None


def get_sentinel() -> LogSRESentinel:
    """Built on first use (not at import), so importing this module never constructs a cloud client."""
    global _sentinel
    if _sentinel is None:
        _sentinel = LogSRESentinel()
    return _sentinel


# ------------------------------------------------------------------------------
# Request Models
# ------------------------------------------------------------------------------
class PubSubMessage(BaseModel):
    data: str
    messageId: Optional[str] = None
    publishTime: Optional[str] = None


class PubSubPushEnvelope(BaseModel):
    message: PubSubMessage
    subscription: Optional[str] = None


class TriageRequest(BaseModel):
    trace_id: Optional[str] = None
    incident_id: Optional[str] = None
    incident_data: Dict[str, Any] = Field(default_factory=dict)


class OutcomeRequest(BaseModel):
    outcome: str
    error_class: str = ""
    detail: str = ""


class RegisterIncidentRequest(BaseModel):
    product_id: str
    fingerprint: str
    source: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


# ------------------------------------------------------------------------------
# Health Check
# ------------------------------------------------------------------------------
@app.get("/health")
def health_check():
    body = {
        "service": "log-sre-sentinel-service",
        "environment": os.getenv("ENVIRONMENT", "prod"),
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }
    try:
        body.update(get_sentinel().health())
    except Exception as e:  # health must answer even when configuration is broken
        body.update({"status": "degraded", "degraded_reasons": [f"HEALTH_CHECK_ERROR:{type(e).__name__}"]})
    return body


# ------------------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------------------
@app.post("/events/log-sink")
def handle_log_sink_event(envelope: PubSubPushEnvelope):
    """
    Pub/Sub push endpoint receiving error log entries from castor-sre-error-sink (and the managed-folder sink).
    Records every incident; dispatches remediation only per the dispatch rules.
    A malformed message is acknowledged (400 would be redelivered forever); a recording failure answers 503 so
    Pub/Sub redelivers it.
    """
    try:
        raw_data = base64.b64decode(envelope.message.data).decode("utf-8")
        log_payload = json.loads(raw_data)
    except Exception as e:
        logger.warning(f"Discarding undecodable log sink message {envelope.message.messageId}: {e}")
        return {"status": "DISCARDED_UNDECODABLE", "message_id": envelope.message.messageId}
    if not isinstance(log_payload, dict):
        logger.warning(f"Discarding non-object log sink message {envelope.message.messageId}")
        return {"status": "DISCARDED_UNDECODABLE", "message_id": envelope.message.messageId}

    logger.info(f"Received SRE log event: {log_payload.get('logName', 'log')}")
    try:
        return get_sentinel().process_log_event(log_payload)
    except FirestoreUnavailable as e:
        logger.warning(f"Incident not recorded (will be redelivered): {e}")
        return JSONResponse(status_code=503, content={"status": "NOT_RECORDED", "error_class": "FIRESTORE_UNAVAILABLE"})
    except Exception as e:
        # 500 -> Pub/Sub retries (max 5) then dead-letters: the DLQ is the signal for the message itself. The failure is
        # logged at ERROR once per generation so it is recorded as a SELF_LOOP incident, but a failure while processing
        # the sentinel's OWN log entry is logged at WARNING: otherwise every retry of a deterministic failure would
        # produce a new ERROR entry that is ingested and fails again, growing without bound (RT F7).
        host_project = _sentinel.project_id if _sentinel is not None else os.getenv("PROJECT_ID", "")
        own_entry = is_sentinel_own_entry(log_payload, host_project)
        (logger.warning if own_entry else logger.error)(
            f"Failed to process log sink event {envelope.message.messageId}: {type(e).__name__}: {e}",
            exc_info=not own_entry)
        return JSONResponse(status_code=500, content={"status": "NOT_PROCESSED", "error_class": "PROCESSING_ERROR",
                                                      "exception_type": type(e).__name__, "detail": str(e)[:500]})


@app.post("/triage")
def triage_incident(req: TriageRequest):
    """
    Step 1 of sre_remediation.yaml: RCA + product id + spec text for a recorded incident (``incident_id``), or the
    legacy ``incident_data`` analysis.
    """
    trace_id = req.trace_id or "auto-sre-trace"
    try:
        return get_sentinel().triage_incident(req.incident_data, trace_id, incident_id=req.incident_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"error_class": "INCIDENT_NOT_FOUND", "incident_id": req.incident_id})
    except FirestoreUnavailable:
        raise HTTPException(status_code=503, detail={"error_class": "FIRESTORE_UNAVAILABLE"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/incidents/{incident_id}/outcome")
def record_incident_outcome(incident_id: str, req: OutcomeRequest):
    """Outcome reported by the castor-sre-remediation workflow (REMEDIATION_FAILED / INTAKE_PUBLISHED)."""
    try:
        return get_sentinel().record_outcome(incident_id, req.outcome, req.error_class, req.detail)
    except ValueError:
        raise HTTPException(status_code=422, detail={"error_class": "UNKNOWN_OUTCOME", "outcome": req.outcome})
    except KeyError:
        raise HTTPException(status_code=404, detail={"error_class": "INCIDENT_NOT_FOUND", "incident_id": incident_id})
    except FirestoreUnavailable:
        raise HTTPException(status_code=503, detail={"error_class": "FIRESTORE_UNAVAILABLE"})


@app.post("/incidents/register")
def register_incident(req: RegisterIncidentRequest, authorization: Optional[str] = Header(default=None)):
    """
    A registered StackVend source (sre-telemetry-digest-job, plan 2.5 item 6) records a finding for a managed workload.
    Same de-duplication, record and dispatch rules as a log entry.
    Caller identity first (RT F3-1): a Google ID token for this service's URL whose email is in
    ``SRE_REGISTRATION_CALLERS``; 401 ``UNAUTHENTICATED`` / 403 ``CALLER_NOT_ALLOWED`` / 503 ``CALLERS_UNCONFIGURED`` or
    ``AUDIENCE_UNCONFIGURED`` (typed, nothing recorded). Then 422 with a typed ``error_class`` when refused (nothing
    recorded); 503 when Firestore is unavailable.
    """
    sentinel = get_sentinel()
    try:
        caller = sentinel.authenticate_registration(authorization)
    except CallerRefused as e:
        logger.warning(f"Registration caller refused: {e.status} {e.code}")
        return JSONResponse(status_code=e.status, content={"status": "NOT_RECORDED", "error_class": e.code,
                                                           "detail": e.detail})
    try:
        return sentinel.register_incident(req.product_id, req.fingerprint, req.evidence, req.source,
                                          registered_by=caller)
    except RegistrationRejected as e:
        return JSONResponse(status_code=422, content={"status": "NOT_RECORDED", "error_class": e.code,
                                                      "detail": e.detail})
    except FirestoreUnavailable:
        return JSONResponse(status_code=503, content={"status": "NOT_RECORDED", "error_class": "FIRESTORE_UNAVAILABLE"})


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
