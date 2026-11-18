"""
Project Castor: Specification Ingestion Service API
FastAPI microservice for scheduled polling and spec intake from Google Drive inbox folders.

OSS-D18 (owner 10-19): zero-config Drive folder discovery (every '01_Inbox_Requests' folder shared with the service
account) is OFF by default until authorized submitters (FD-4AS) lands; it runs only when the platform setting
governance.drive_folder_auto_discovery is True. Explicitly configured folders (the poll request or
INBOX_FOLDER_ID / IN_PROGRESS_FOLDER_ID) are always polled, also when discovery finds other inboxes (FD-4CI-b (6)).

FD-4AS (owner 10-20): every document is ingested only when its Drive owner is an authorized submitter (an active
Control Center user, role ADMIN / WORKLOAD_MANAGER / legacy APPROVER) and its target folder is an active managed
folder; a discovered or request-supplied inbox is polled only when its owner is an authorized submitter (the
configured INBOX_FOLDER_ID is exempt). Refusals are typed and listed on the response (``skipped``); an unreadable
authorization store answers 503 SPEC_INTAKE_UNAVAILABLE with nothing moved or published.

Who can call these endpoints (FD-4AS item 5, report only): the service is a private Cloud Run service (no allUsers
invoker); Cloud Run IAM admits principals holding roles/run.invoker on the host project (Cloud Scheduler's OIDC token
for sa-castor-architect, and the agent service accounts granted project-level invoker). The app itself does no
further authentication, so a request-supplied inbox_folder_id or in_progress_folder_id gets the same owner check as
discovery (unless it is the configured INBOX_FOLDER_ID / IN_PROGRESS_FOLDER_ID).
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import logging
import os
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from poller import SpecIngestionPoller
from intake_outcomes import (IN_PROGRESS_FOLDER_UNAUTHORIZED, INBOX_FOLDER_UNAUTHORIZED, INBOX_POLL_FAILED,
                             SPEC_INGEST_FAILED, SPEC_INTAKE_UNAVAILABLE, SPEC_PRODUCT_ID_INVALID, SPEC_PUBLISH_FAILED,
                             SPEC_SUBMITTER_UNAUTHORIZED, SPEC_TARGET_PLATFORM_WORKLOAD, SPEC_WORKLOAD_NOT_ASSIGNED,
                             TARGET_FOLDER_NOT_MANAGED, IntakePublishError, IntakeRejected, IntakeUnavailableError)

logger = logging.getLogger("spec-ingestion-service")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="StackVend Specification Ingestion Service",
    description="Polls the configured Google Drive 01_Inbox_Requests folders (zero-config discovery only when enabled in Settings), transitions docs to 02_In_Progress, and dispatches Pub/Sub intake events.",
    version="1.0.0",
)

poller = SpecIngestionPoller()


def _refuse_intake_in_maintenance(action: str) -> None:
    """settings-toggles (FD-4AK Fable RT F5): maintenance mode -> 503 MAINTENANCE_MODE before any Drive move, record
    or publish, so the specs stay in 01_Inbox_Requests and the next poll after maintenance picks them up. Settings
    unreadable / invalid, or no settings module -> 503 too (fail closed)."""
    try:
        from shared.settings import new_run_refusal
        refusal = new_run_refusal(action)
    except ImportError as imp_err:
        refusal = {"code": "PLATFORM_SETTINGS_UNAVAILABLE", "errors": [],
                   "message": f"Platform settings module unavailable ({imp_err}): {action} was refused."}
    if refusal is not None:
        logger.warning(f"{refusal['code']}: {action} refused")
        raise HTTPException(status_code=503, detail=refusal)


AUTO_DISCOVERY_OFF_NOTE = ("Drive folder auto-discovery is off (OSS-D18 default); set INBOX_FOLDER_ID and "
                           "IN_PROGRESS_FOLDER_ID, or enable governance.drive_folder_auto_discovery in Settings "
                           "(discovered inboxes and documents are accepted only from authorized submitters, FD-4AS).")


def _auto_discovery_enabled() -> bool:
    """OSS-D18: the platform setting, exactly True on a strict read; no settings module -> off (fail closed)."""
    try:
        from shared.settings import drive_folder_auto_discovery_enabled
    except ImportError:
        return False
    return drive_folder_auto_discovery_enabled()


def _explicit_folder_pair(req: Optional["PollRequest"]) -> List[tuple]:
    """The explicitly configured (inbox, in-progress) pair: the poll request's ids, else the environment's."""
    inbox_raw = (req and req.inbox_folder_id) or os.getenv("INBOX_FOLDER_ID", "")
    in_progress_raw = (req and req.in_progress_folder_id) or os.getenv("IN_PROGRESS_FOLDER_ID", "")
    if inbox_raw and in_progress_raw:
        return [(inbox_raw.strip(), in_progress_raw.strip())]
    return []


def _intake_folder_pairs(req: Optional["PollRequest"], auto_discovery: bool,
                         folder_skips: Optional[List[dict]] = None) -> List[tuple]:
    """Folders to poll: the explicit pair (owner-checked below when request-supplied), plus, with auto-discovery on
    (OSS-D18 setting), every discovered pair. FD-4CI-b (6): the explicit pair is polled whether or not discovery
    finds anything; an inbox that appears twice (the configured inbox is also discovered) is polled once, with the
    explicit pair's in-progress folder. Off (the default): only the explicit pair; Drive is never searched.
    FD-4AS: discovery returns only authorized inboxes (its refusals are appended to ``folder_skips``); a
    request-supplied inbox that is not the configured INBOX_FOLDER_ID must be owned by an authorized submitter.
    Raises IntakeUnavailableError when that cannot be decided."""
    skips = folder_skips if folder_skips is not None else []
    pairs = _authorized_explicit_pair(req, skips)
    if auto_discovery:
        discovered = poller.auto_discover_shared_folders()
        skips.extend(getattr(discovered, "skipped", None) or [])
        seen = {inbox_id for inbox_id, _ in pairs}
        for inbox_id, prog_id in discovered:
            if inbox_id in seen:
                logger.info(f"Inbox {inbox_id} is both configured and discovered; polled once")
                continue
            seen.add(inbox_id)
            pairs.append((inbox_id, prog_id))
    return pairs


def _authorized_explicit_pair(req: Optional["PollRequest"], skips: List[dict]) -> List[tuple]:
    """The explicit pair, or [] when there is none or a request-supplied folder is refused (FD-4AS)."""
    pairs = _explicit_folder_pair(req)
    if pairs and req is not None and req.inbox_folder_id:
        inbox_id = pairs[0][0]
        refusal = poller.inbox_folder_refusal(inbox_id)
        if refusal:
            logger.warning(f"{INBOX_FOLDER_UNAUTHORIZED}: request-supplied inbox {inbox_id} not polled ({refusal})")
            skips.append({"inbox_folder_id": inbox_id, "code": INBOX_FOLDER_UNAUTHORIZED, "reason": refusal})
            return []
    if pairs and req is not None and req.in_progress_folder_id:
        # RT F1: documents are MOVED into this folder (and inherit its sharing): same owner rule as the inbox.
        inbox_id, prog_id = pairs[0]
        refusal = poller.in_progress_folder_refusal(prog_id)
        if refusal:
            logger.warning(f"{IN_PROGRESS_FOLDER_UNAUTHORIZED}: request-supplied in-progress folder {prog_id} not "
                           f"used ({refusal})")
            skips.append({"inbox_folder_id": inbox_id, "in_progress_folder_id": prog_id,
                          "code": IN_PROGRESS_FOLDER_UNAUTHORIZED, "reason": refusal})
            return []
    return pairs


def _unavailable(action: str, err: Exception) -> HTTPException:
    logger.error(f"{SPEC_INTAKE_UNAVAILABLE}: {action} skipped ({err})")
    return HTTPException(status_code=503, detail={
        "code": SPEC_INTAKE_UNAVAILABLE,
        "message": f"{action} skipped: the authorization inputs could not be read ({err}). Nothing was moved or "
                   "published; the documents stay in the inbox for the next poll."})


def _run_intake(pairs: List[tuple], action: str) -> Dict[str, Any]:
    """Polls every pair. FD-4AS: per-document skips are collected (typed); a pass whose authorization inputs are
    unreadable raises 503 SPEC_INTAKE_UNAVAILABLE (that pass moved and published nothing; passes of other folders
    that already completed stay done and are idempotent); any other per-folder failure is reported, not swallowed."""
    ingested, skipped, failures, unavailable = [], [], [], None
    for inbox_id, prog_id in pairs:
        try:
            result = poller.poll_and_ingest(inbox_id, prog_id)
        except IntakeUnavailableError as e:
            unavailable = unavailable or e
            continue
        except Exception as e:  # noqa: BLE001 - one folder's Drive failure must not stop the others
            logger.error(f"{INBOX_POLL_FAILED}: inbox {inbox_id} ({type(e).__name__})")
            failures.append({"inbox_folder_id": inbox_id, "code": INBOX_POLL_FAILED, "reason": type(e).__name__})
            continue
        ingested.extend(result)
        skipped.extend(getattr(result, "skipped", None) or [])
    if unavailable is not None:
        raise _unavailable(action, unavailable)
    return {"ingested": ingested, "skipped": skipped, "failures": failures}


# ------------------------------------------------------------------------------
# Request Models
# ------------------------------------------------------------------------------
class PollRequest(BaseModel):
    inbox_folder_id: Optional[str] = None
    in_progress_folder_id: Optional[str] = None


class IngestDocRequest(BaseModel):
    document_id: str
    inbox_folder_id: Optional[str] = None
    in_progress_folder_id: Optional[str] = None


# ------------------------------------------------------------------------------
# Health Check
# ------------------------------------------------------------------------------
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "spec-ingestion-service",
        "environment": os.getenv("ENVIRONMENT", "prod"),
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


# ------------------------------------------------------------------------------
# Core Endpoints
# ------------------------------------------------------------------------------
@app.post("/poll")
def execute_poll(req: Optional[PollRequest] = None):
    """
    Main entrypoint invoked by Cloud Scheduler every 5 minutes. Polls the explicitly configured folders; also
    discovers every shared '01_Inbox_Requests' folder only when governance.drive_folder_auto_discovery is on (OSS-D18).
    FD-4AS: refused documents / folders are listed on ``skipped`` (typed codes); 503 SPEC_INTAKE_UNAVAILABLE when the
    authorization inputs cannot be read.
    """
    _refuse_intake_in_maintenance("Google Docs intake (poll)")
    auto_discovery = _auto_discovery_enabled()
    folder_skips: List[dict] = []
    try:
        discovered_pairs = _intake_folder_pairs(req, auto_discovery, folder_skips)
    except IntakeUnavailableError as e:
        raise _unavailable("Google Docs intake (poll)", e)

    if not discovered_pairs:
        return {
            "status": "IDLE",
            "message": (f"No inbox folders to poll. {AUTO_DISCOVERY_OFF_NOTE}" if not auto_discovery
                        else "No shared '01_Inbox_Requests' folders found in Google Drive and no explicit "
                             "INBOX_FOLDER_ID / IN_PROGRESS_FOLDER_ID configured."),
            "ingested_count": 0,
            "items": [],
            "skipped": folder_skips,
        }

    run = _run_intake(discovered_pairs, "Google Docs intake (poll)")
    return {
        "status": "SUCCESS",
        "shared_folders_discovered": len(discovered_pairs),
        "ingested_count": len(run["ingested"]),
        "items": run["ingested"],
        "skipped_count": len(folder_skips) + len(run["skipped"]),
        "skipped": folder_skips + run["skipped"],
        "failures": run["failures"],
    }


# RT14-27: HTTP status of each typed single-document refusal (who may submit / what may be targeted -> 403; what the
# document says is unusable -> 422).
_SINGLE_DOC_REFUSAL_STATUS = {
    SPEC_SUBMITTER_UNAUTHORIZED: 403,
    SPEC_WORKLOAD_NOT_ASSIGNED: 403,
    SPEC_TARGET_PLATFORM_WORKLOAD: 403,
    SPEC_PRODUCT_ID_INVALID: 422,
    TARGET_FOLDER_NOT_MANAGED: 422,
}


@app.post("/ingest-doc")
def ingest_single_document(req: IngestDocRequest):
    """Manually triggers intake of a specific Google Doc specification.
    FD-4AS + RT14-27: the same decision as the poll path, on the document's own Drive metadata (Drive owner is an
    authorized submitter, target folder is a managed folder, the title gives a valid product id the submitter may
    target): a refusal is 403 / 422 with its typed code; owner, user or workload store unreadable -> 503
    SPEC_INTAKE_UNAVAILABLE; nothing is published in those cases. Each request gets its own trace id and the poll path's
    payload (product_id, folder_id); the OSS-D23 submitter is recorded. The document is not moved (the request's
    folder fields are not used). A failed publish is 502 SPEC_PUBLISH_FAILED (nothing recorded as ingested); any other
    error is 500 SPEC_INGEST_FAILED with its class (RT14 RT F2: never reported as a publish failure)."""
    _refuse_intake_in_maintenance("Google Docs intake (single document)")
    try:
        payload = poller.ingest_document(req.document_id)
    except IntakeUnavailableError as e:
        raise _unavailable("Google Docs intake (single document)", e)
    except IntakeRejected as rej:
        logger.warning(f"{rej.code}: doc {req.document_id} not ingested ({rej.reason})")
        raise HTTPException(status_code=_SINGLE_DOC_REFUSAL_STATUS.get(rej.code, 422),
                            detail={"code": rej.code, "message": rej.reason, "document_id": req.document_id})
    except IntakePublishError as e:  # the publish failed: typed, never a fake INGESTED
        logger.error(f"{SPEC_PUBLISH_FAILED}: doc {req.document_id} ({e.cause_class})")
        raise HTTPException(status_code=502, detail={
            "code": SPEC_PUBLISH_FAILED, "document_id": req.document_id,
            "message": f"the intake event was not published ({e.cause_class}); nothing was started"})
    except Exception as e:  # noqa: BLE001 - RT14 RT F2: any other error keeps its own class (500), never a fake INGESTED
        logger.error(f"{SPEC_INGEST_FAILED}: doc {req.document_id} ({type(e).__name__})")
        raise HTTPException(status_code=500, detail={
            "code": SPEC_INGEST_FAILED, "error_class": type(e).__name__, "document_id": req.document_id,
            "message": f"the intake failed before its event was published ({type(e).__name__}); nothing was started"})
    return {"status": "INGESTED", "pubsub_message_id": payload["pubsub_message_id"],
            "document_id": req.document_id, "trace_id": payload["trace_id"], "product_id": payload["product_id"]}


@app.post("/webhook")
def handle_drive_push_notification():
    """Webhook handler for real-time Google Drive change notifications."""
    _refuse_intake_in_maintenance("Google Docs intake (Drive notification)")
    try:
        discovered_pairs = _intake_folder_pairs(None, _auto_discovery_enabled())
    except IntakeUnavailableError as e:
        raise _unavailable("Google Docs intake (Drive notification)", e)
    run = _run_intake(discovered_pairs, "Google Docs intake (Drive notification)")
    return {"status": "PROCESSED", "ingested_count": len(run["ingested"]), "skipped_count": len(run["skipped"])}


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
