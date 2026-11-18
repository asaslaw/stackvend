"""
StackVend Control Center: the "Update StackVend" button (SELFUP P3b, Control Center side; plan
docs/planning/self-upgrade-plan.md §3.1, §3.5-§3.9, §4.4-§4.5; plan RT 11-02 §7 row B4, H-2, M-6, M-10).

The Control Center gains NO deploy power. Its whole part of an upgrade is:
  1. write the request `platform_upgrades/{id}` and the lease `platform_upgrades/_lease` (guard database; the lease is
     created only if absent, in the same atomic commit as the request);
  2. turn maintenance mode on (new workload runs refused; runs in flight continue), recording the previous value;
  3. publish ONE message to the topic named by STACKVEND_PLATFORM_UPGRADE_TOPIC, with the request id as the message
     attribute `request_id` (the Cloud Build trigger maps it to a substitution; scripts/upgrade/verify.sh refuses
     anything but 32 lowercase hex).
Everything else (verifying the signed tag, the platform guard, building, deploying, health checks, rollback) is done
by the Cloud Build trigger running as sa-stackvend-upgrader, whose step 0 is fixed in core Terraform and re-checks
every condition below (fail closed even when the Control Center is bypassed). The Control Center never calls Cloud
Build or a Cloud Run write API; it reads Cloud Run (version display, roles/run.viewer), Firestore and GitHub (the
update check, plus resolving the target tag to its commit).

GET  /api/settings/platform-upgrade                       (ADMIN) button state + one-line reason, lease, progress of
                                                          the current request (stages, per component), history,
                                                          maintenance. Releases a finished lease and restores
                                                          maintenance by the rules below (housekeeping only).
POST /api/settings/platform-upgrade                       (ADMIN, human, typed project id, idempotency key) start.
POST /api/settings/platform-upgrade/{request_id}/retry    (ADMIN, human, typed project id) run a failed request again
                                                          (same verified tag and commit; a new request id).
POST /api/settings/platform-upgrade/{request_id}/rollback (ADMIN, human, typed project id) "Roll back services": a
                                                          ROLLBACK request through the same trigger (B2: rollback.sh
                                                          restores the recorded previous revisions / digests).
POST /api/settings/platform-upgrade/lease/clear           (ADMIN, human, typed project id) clear a stale lease, only
                                                          when its build is finished or the lease has expired.
POST /api/settings/platform-upgrade/{request_id}/maintenance/restore
                                                          (ADMIN, human, typed project id) turn maintenance mode back
                                                          to its value before a failed upgrade.

Refusals (HTTP 409 unless noted; `detail.code`): UPGRADER_NOT_INSTALLED (env unset/blank/not a topic name: the button
is hidden), UPDATE_CHECK_OFF, RELEASE_SOURCE_INVALID, SOURCE_SETTING_CHANGED, UPGRADE_IN_PROGRESS (a lease is held),
NO_TARGET (with `reason`: the last check is not OK + update_available + guard ALLOW), TARGET_CHANGED,
WORKLOAD_RUNS_ACTIVE, REQUEST_ID_IN_USE, NOT_RETRYABLE, ROLLBACK_NOT_OFFERED, LEASE_ACTIVE, NO_LEASE,
CONFIRMATION_MISMATCH (422), EXECUTIONS_UNKNOWN / MAINTENANCE_UNAVAILABLE / GUARD_DATABASE_UNAVAILABLE (503),
TAG_UNRESOLVED / PUBLISH_FAILED (502).

Maintenance rules (plan §3.9, §6 F-BUILD): starting turns maintenance mode on and records the previous value. When the
request ends it is restored to that value if the install is in a known state: SUCCEEDED, ROLLED_BACK, or a request
that changed nothing (REFUSED_*, a failure before any deploy, a lease cleared before the build started) and is not a
follow-up of an earlier failure. After a failure that deployed something (PARTIAL, FAILED_CHECKING, ...) or a build
that timed out, it stays on (fail closed) with a banner and a "Turn maintenance off" button. A retry or rollback of a
failed request inherits the original's previous value, so the final success restores what the admin had before.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Request
from pydantic import BaseModel, StrictBool, StrictStr

import release_source as rsrc
from authz import ADMIN, require
from config import DynamicHTTPException as HTTPException, apply_where
from db import get_db
from routes import platform_release as pr
from shared import release_manifest as rm

logger = logging.getLogger("control-center-platform-upgrade")
router = APIRouter(tags=["Settings"])

TOPIC_ENV = "STACKVEND_PLATFORM_UPGRADE_TOPIC"
APPROVAL_ENV = "STACKVEND_PLATFORM_UPGRADE_APPROVAL_REQUIRED"  # optional; Terraform default is approval ON (H-2)
REQUESTS = "platform_upgrades"          # guard database (scripts/upgrade/guard.py REQUESTS)
LEASE_DOC = "_lease"                    # guard database (guard.py LEASE_DOC)
PROGRESS = "platform_upgrades_progress"  # default database, written only by the upgrader (guard.py PROGRESS)
KIND_UPGRADE, KIND_ROLLBACK = "UPGRADE", "ROLLBACK"
REQUEST_SCHEMA = 1
BUILD_TIMEOUT_SECONDS = 7200           # == guard.BUILD_TIMEOUT_S == the trigger's timeout (parity test, RT M-4)
APPROVAL_WINDOW_SECONDS = 3600         # how long the build may wait for its console approval (review A M-A)
BUILD_START_MARGIN_SECONDS = 600       # Cloud Build queue + machine start after the approval (RT L-1)
# Step 0 claims a request only while the lease still covers a whole build (`expires_at >= now + 7200 s`, review A
# M-A), so the lease is request time + approval window + start margin + build timeout: a build approved within the
# window can always claim, one approved much later refuses (LEASE_NOT_HELD), and two builds can never overlap.
LEASE_SECONDS = APPROVAL_WINDOW_SECONDS + BUILD_START_MARGIN_SECONDS + BUILD_TIMEOUT_SECONDS
RUNNING_SLACK_SECONDS = 900
HISTORY_LIMIT = 20
MAIN_WORKFLOW = "castor-main-orchestrator"
WORKFLOW_EXECUTIONS_API = "https://workflowexecutions.googleapis.com/v1"
# The API's filter grammar needs the value quoted: unquoted `state=ACTIVE` is HTTP 400 INVALID_ARGUMENT (found live,
# 11-02). TODO(sat-43): use apps/control-center/workflow_executions.py once it is on main.
ACTIVE_FILTER = 'state="ACTIVE"'
VIA = "control-center"

# Request statuses the Control Center writes (step 0 runs only a REQUESTED one).
REQ_REQUESTED, REQ_DONE, REQ_NOT_SENT, REQ_CANCELLED = "REQUESTED", "DONE", "NOT_SENT", "CANCELLED"
# Review A M-B: as soon as the Control Center sees the progress record it moves the request to STARTED, so a
# redelivered Pub/Sub message is refused by step 0 (REQUEST_NOT_PENDING) even if the forgeable progress record
# (default database) was deleted meanwhile.
REQ_STARTED = "STARTED"

# Progress statuses (scripts/upgrade/run.sh, guard.py): RUNNING, then SUCCEEDED | ROLLED_BACK | PARTIAL |
# REFUSED_<CODE> | FAILED_<STAGE>.
SUCCESS_STATUSES = ("SUCCEEDED", "ROLLED_BACK")
ROLLBACK_OFFERED_STATUSES = ("PARTIAL", "FAILED_CHECKING", "FAILED_DEPLOYING")

# Button reasons (one line each; the dashboard shows the text, never builds its own).
READY = "READY"
REASONS: Dict[str, str] = {
    "UPGRADER_NOT_INSTALLED": ("The upgrader is not installed on this install yet (it comes with a platform "
                               "apply.sh). Update from a terminal with scripts/upgrade.sh."),
    "UPDATE_CHECK_OFF": "Update check is off: updates are manual on this install (scripts/upgrade.sh).",
    "RELEASE_SOURCE_INVALID": "The release source is invalid: an administrator must save a valid one first.",
    "REPOSITORY_NOT_FOUND": ("The release repository is not published yet (or it is private), so there is nothing "
                             "to install."),
    "NO_RELEASES": "The release repository has no release yet, so there is nothing to install.",
    "COULD_NOT_CHECK": "The update check did not finish, so there is nothing to install yet. Check again.",
    "UP_TO_DATE": "This install runs the newest release.",
    "MANIFEST_UNAVAILABLE": ("The newest release's release-manifest.json could not be read or is invalid, so it "
                             "cannot be installed from here."),
    "PLATFORM_STAMP_UNKNOWN": "The platform release of this install is unknown, so the button refuses (fail closed).",
    "NEEDS_APPLY_SH": ("This release changes the platform Terraform: an administrator must run the apply.sh steps "
                       "from a terminal first, then Check again."),
    "UPGRADE_IN_PROGRESS": "An upgrade is in progress (one at a time).",
    READY: "Ready: installs the newest release's services and jobs (never Terraform).",
}
HIDDEN_REASONS = ("UPGRADER_NOT_INSTALLED", "UPDATE_CHECK_OFF")
APPROVAL_TEXT = ("An administrator must approve this build in the Google Cloud console (Cloud Build ▸ History) "
                 f"within {APPROVAL_WINDOW_SECONDS // 60} minutes of the request. A build approved later refuses to "
                 "start; then clear the lease here and request the upgrade again.")
NO_APPROVAL_TEXT = "Waiting for the build to start (Cloud Build ▸ History in the Google Cloud console)."

# ------------------------------------------------------------------------------------------------ test seams
# None = the real implementation.
publisher_provider: Optional[Callable[[], Any]] = None          # object with publish(topic, data, **attributes)
active_executions_provider: Optional[Callable[[], int]] = None  # active main-orchestrator executions
maintenance_reader: Optional[Callable[[], bool]] = None         # current governance.maintenance_mode (strict)
maintenance_writer: Optional[Callable[[bool, str, str], None]] = None  # (value, by, reason)
progress_db_provider: Optional[Callable[[], Any]] = None        # the default database (progress records)
updates_provider: Optional[Callable[[Request], Dict[str, Any]]] = None  # the update-check result
terraform_ready_probe: Optional[Callable[[], Tuple[int, Any]]] = None  # GET /validate/ready with the CC's ID token
clock: Callable[[], float] = time.time


# ------------------------------------------------------------------------------------------------ CC readiness check
# UPGRADER-READY-INGRESS (review F2): the upgrader cannot call the terraform server's /validate/ready (it has no
# invoker right, and an internal-only server refuses Cloud Build), so it reports NOT_CHECKED. For a finished upgrade
# whose check says NOT_CHECKED, the Control Center (which has an invoker right and is on the platform network after
# the ingress flip) probes /validate/ready itself with its own ID token and shows the answer on the Upgrades card:
#   READY        200 with `ready: true`;
#   NOT_READY    200 with `ready` not true, or any other answer of the server (5xx, ...): the reason is shown;
#   NOT_CHECKED  the Control Center could not ask (URL unknown, refused 401/403, unreachable 404, network error).
# Never a pass by default: only READY is ready. Display only (nothing is written); cached CC_READY_CACHE_SECONDS.
CC_READY_CACHE_SECONDS = 60
CC_READY, CC_NOT_READY, CC_NOT_CHECKED = "READY", "NOT_READY", "NOT_CHECKED"
_cc_ready_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def _probe_terraform_ready() -> Tuple[int, Any]:
    if terraform_ready_probe is not None:
        return terraform_ready_probe()
    from routes import settings as settings_routes   # lazy: the CC's terraform requester (its own ID token)
    resp = settings_routes.make_terraform_request("GET", "/validate/ready", timeout=30.0)
    if resp is None:
        raise LookupError("the terraform server's URL is unknown (TERRAFORM_SERVICE_URL / Cloud Run lookup)")
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        body = None
    return int(getattr(resp, "status_code", 0) or 0), body


def cc_terraform_ready() -> Dict[str, Any]:
    """The Control Center's own /validate/ready answer, typed (see above)."""
    checked_at = _iso_z(clock())
    try:
        status, body = _probe_terraform_ready()
    except LookupError as e:
        return {"state": CC_NOT_CHECKED, "reason": str(e), "checked_at": checked_at}
    except Exception as e:  # noqa: BLE001
        return {"state": CC_NOT_CHECKED, "reason": f"the terraform server did not answer ({type(e).__name__})",
                "checked_at": checked_at}
    if status == 200 and isinstance(body, dict) and body.get("ready") is True:
        return {"state": CC_READY, "reason": "", "checked_at": checked_at}
    if status == 200:
        why = body.get("reason") if isinstance(body, dict) and isinstance(body.get("reason"), str) else ""
        ready = body.get("ready") if isinstance(body, dict) else None
        return {"state": CC_NOT_READY, "reason": (f"ready={ready!r}" + (f": {why}" if why else ""))[:300],
                "checked_at": checked_at}
    if status in (401, 403):
        return {"state": CC_NOT_CHECKED, "reason": f"the terraform server refused the Control Center (HTTP {status})",
                "checked_at": checked_at}
    if status == 404:
        return {"state": CC_NOT_CHECKED, "reason": "the terraform server was not reachable from the Control Center "
                "(HTTP 404: an ingress refusal, or the route is missing)", "checked_at": checked_at}
    return {"state": CC_NOT_READY, "reason": f"HTTP {status}", "checked_at": checked_at}


def cc_terraform_ready_for(view: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """For a finished request whose upgrader check is NOT_CHECKED: the CC's own check (cached per request); else None."""
    if not view or not view.get("terminal") or not str(view.get("terraform_ready") or "").startswith("NOT_CHECKED"):
        return None
    rid = str(view.get("request_id") or "")
    now = clock()
    hit = _cc_ready_cache.get(rid)
    if hit is not None and now - hit[0] < CC_READY_CACHE_SECONDS:
        return hit[1]
    result = cc_terraform_ready()
    _cc_ready_cache.clear()   # only the shown request is ever cached
    _cc_ready_cache[rid] = (now, result)
    return result


# ------------------------------------------------------------------------------------------------ helpers
def _err(http_status: int, code: str, message: str, **extra: Any) -> HTTPException:
    return HTTPException(status_code=http_status, detail={"code": code, "message": message, **extra})


def _iso_z(ts: float) -> str:
    """RFC 3339 UTC with a Z (the format scripts/upgrade/guard.py reads for expires_at)."""
    return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ts(v: Any) -> Optional[float]:
    if not isinstance(v, str) or not v:
        return None
    try:
        dt = datetime.fromisoformat(v[:-1] + "+00:00" if v.endswith("Z") else v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.timestamp()


def _is_hex(v: Any, n: int) -> bool:
    return isinstance(v, str) and len(v) == n and all(c in "0123456789abcdef" for c in v)


def _topic_id_ok(t: str) -> bool:
    """Pub/Sub topic id rules: 3-255 characters, starts with a letter, letters/digits/-_.~+%, not goog*."""
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~+%")
    return 3 <= len(t) <= 255 and t[0].isalpha() and t.isascii() and set(t) <= allowed \
        and not t.lower().startswith("goog")


def _project_id_ok(p: str) -> bool:
    return 6 <= len(p) <= 30 and p[0].isalpha() and p.isascii() and p[-1] != "-" \
        and set(p) <= set("abcdefghijklmnopqrstuvwxyz0123456789-")


def upgrade_topic() -> Tuple[str, str]:
    """(full topic path, "") when STACKVEND_PLATFORM_UPGRADE_TOPIC names a topic; ("", why) when it is unset, blank
    or not a topic name. Accepts `projects/<project>/topics/<topic>` or a bare topic id in this project. Unset is the
    "inert until applied" switch (review §5 row 14): the button is hidden and every start refuses."""
    raw = (os.getenv(TOPIC_ENV) or "").strip()
    if not raw:
        return "", f"{TOPIC_ENV} is not set"
    parts = raw.split("/")
    if len(parts) == 4 and parts[0] == "projects" and parts[2] == "topics":
        project, topic = parts[1], parts[3]
    elif len(parts) == 1:
        project, topic = pr._project(), raw
    else:
        return "", f"{TOPIC_ENV} is not a Pub/Sub topic name"
    if not _project_id_ok(project) or not _topic_id_ok(topic):
        return "", f"{TOPIC_ENV} is not a Pub/Sub topic name"
    return f"projects/{project}/topics/{topic}", ""


def _approval_required() -> bool:
    return (os.getenv(APPROVAL_ENV) or "").strip().lower() != "false"


def waiting_text() -> str:
    return APPROVAL_TEXT if _approval_required() else NO_APPROVAL_TEXT


def request_id_for(email: str, idempotency_key: str) -> str:
    """The request id: 32 lowercase hex derived from the caller and their idempotency key, so a repeated POST (double
    click, retry after a timeout) finds the same request, and one caller can never name another caller's request."""
    return hashlib.sha256(f"stackvend-upgrade\n{email}\n{idempotency_key}".encode("utf-8")).hexdigest()[:32]


def is_terminal(status: Any) -> bool:
    return isinstance(status, str) and (status in SUCCESS_STATUSES or status == "PARTIAL"
                                        or status.startswith("REFUSED_") or status.startswith("FAILED_"))


def _nonempty_map(v: Any) -> bool:
    return isinstance(v, dict) and len(v) > 0


def changed_nothing(progress: Optional[Dict[str, Any]]) -> bool:
    """True when the run deployed nothing: refused, or failed before any component was updated (the upgrader writes
    `deployed` / `rolled_back` once something was)."""
    if progress is None:
        return True
    status = progress.get("status")
    if isinstance(status, str) and status.startswith("REFUSED_"):
        return True
    if isinstance(status, str) and status.startswith("FAILED_"):
        return not _nonempty_map(progress.get("deployed")) and not _nonempty_map(progress.get("rolled_back"))
    return False


def maintenance_outcome(req: Dict[str, Any], progress: Optional[Dict[str, Any]]) -> str:
    """RESTORE or KEEP for a finished request (module docstring, "Maintenance rules")."""
    status = (progress or {}).get("status")
    if status in SUCCESS_STATUSES:
        return "RESTORE"
    follow_up = bool(req.get("retry_of") or req.get("rollback_of"))
    if changed_nothing(progress) and not follow_up:
        return "RESTORE"
    return "KEEP"


def lease_state(lease: Dict[str, Any], req: Optional[Dict[str, Any]], progress: Optional[Dict[str, Any]],
                now: float) -> str:
    """FINISHED (release it), ACTIVE (waiting for approval or running), or STALE (can no longer start or finish).
    Without a progress record the build can still claim the request only while the lease covers a whole build
    (step 0, review A M-A: expires_at >= now + build timeout), i.e. until expires_at - 2 h (+ slack); after that a
    build approved late refuses LEASE_NOT_HELD, so the lease is stale and may be cleared."""
    if progress is not None and is_terminal(progress.get("status")):
        return "FINISHED"
    if not isinstance(req, dict) or req.get("status") in (REQ_NOT_SENT, REQ_CANCELLED, REQ_DONE):
        return "FINISHED"
    expires = _parse_ts(lease.get("expires_at"))
    if progress is not None:  # step 0 claimed the request while the lease covered a whole build
        started = _parse_ts(progress.get("started_at"))
        deadline = max(expires or 0, (started or 0) + BUILD_TIMEOUT_SECONDS + RUNNING_SLACK_SECONDS)
        cap = lease_cap(lease)
        deadline = min(deadline, cap) if cap is not None else (expires or 0)
        return "ACTIVE" if now < deadline else "STALE"
    if expires is None:
        return "STALE"
    claim_deadline = expires - BUILD_TIMEOUT_SECONDS + RUNNING_SLACK_SECONDS
    return "ACTIVE" if now < claim_deadline else "STALE"


def lease_cap(lease: Dict[str, Any]) -> Optional[float]:
    """The latest any honest build of this lease can end: created_at + LEASE_SECONDS + slack (RT M-1). It comes from
    the lease the Control Center wrote (guard database), never from the forgeable progress record, so a forged
    `started_at` cannot hold the lease longer. None when the lease has no readable created_at."""
    created = _parse_ts(lease.get("created_at"))
    return None if created is None else created + LEASE_SECONDS + RUNNING_SLACK_SECONDS


def renewed_expiry(lease: Dict[str, Any], progress: Optional[Dict[str, Any]]) -> Optional[str]:
    """Review A M-A: while the progress record is non-terminal the lease is renewed to cover the running build
    (started_at + build timeout + slack), never past lease_cap (RT M-1); no created_at -> no renewal. None when no
    renewal is needed."""
    if progress is None or is_terminal(progress.get("status")):
        return None
    started = _parse_ts(progress.get("started_at"))
    expires = _parse_ts(lease.get("expires_at"))
    cap = lease_cap(lease)
    if started is None or cap is None:
        return None
    wanted = min(started + BUILD_TIMEOUT_SECONDS + RUNNING_SLACK_SECONDS, cap)
    return _iso_z(wanted) if expires is None or expires < wanted else None


# ------------------------------------------------------------------------------------------------ data access
def _gdb():
    return pr._guard_db()


def _pdb():
    db = progress_db_provider() if progress_db_provider is not None else get_db()
    if not db:
        raise _err(503, "FIRESTORE_UNAVAILABLE", "The default Firestore database cannot be opened.")
    return db


def _requests(gdb):
    return gdb.collection(REQUESTS)


def _lease_ref(gdb):
    return _requests(gdb).document(LEASE_DOC)


def _get(ref) -> Tuple[Any, Optional[Dict[str, Any]]]:
    try:
        snap = ref.get()
    except Exception as e:  # noqa: BLE001
        raise _err(503, "GUARD_DATABASE_UNAVAILABLE", f"Could not read the upgrade records: {type(e).__name__}")
    data = snap.to_dict() if getattr(snap, "exists", False) else None
    return snap, (data if isinstance(data, dict) else None)


def _progress(pdb, request_id: str) -> Optional[Dict[str, Any]]:
    """platform_upgrades_progress/{id}: written by the upgrader only. Display data, and the terminal state that
    releases the lease (review M-11: every agent SA can write the default database; a forged record can release a
    lease early or misreport, never start or widen an upgrade: step 0 re-checks everything)."""
    try:
        snap = pdb.collection(PROGRESS).document(request_id).get()
    except Exception as e:  # noqa: BLE001
        raise _err(503, "FIRESTORE_UNAVAILABLE", f"Could not read the upgrade progress: {type(e).__name__}")
    data = snap.to_dict() if getattr(snap, "exists", False) else None
    return data if isinstance(data, dict) else None


def _read_maintenance() -> bool:
    if maintenance_reader is not None:
        return maintenance_reader()
    from routes import settings as sr
    current, invalid = sr._read_current_settings_for_write()  # 503 when unreadable
    if current is None:
        raise _err(503, "MAINTENANCE_UNAVAILABLE", "The platform settings do not validate, so maintenance mode cannot "
                   "be set for the upgrade. Repair them (Settings ▸ Parameters ▸ Save) and retry.")
    return bool(current.governance.maintenance_mode)


def _write_maintenance(value: bool, by: str, reason: str) -> None:
    """governance.maintenance_mode only, the one-field pattern of the VCS switch (fresh read, audit entry, version + 1,
    preconditioned store). Raises on any failure (never a silent no-op: a Control Center without Firestore refuses)."""
    if maintenance_writer is not None:
        maintenance_writer(value, by, reason)
        return
    from routes import settings as sr
    current, invalid = sr._read_current_settings_for_write()
    if current is None:
        raise _err(503, "MAINTENANCE_UNAVAILABLE", "The platform settings do not validate; maintenance mode was not "
                   "changed. Repair them (Settings ▸ Parameters ▸ Save) and retry.")
    if bool(current.governance.maintenance_mode) is value:
        return
    if not sr.db:
        raise _err(503, "MAINTENANCE_UNAVAILABLE", "Firestore is unavailable; maintenance mode was not changed.")
    now_iso = datetime.now(timezone.utc).isoformat()
    updated = current.model_copy(deep=True)
    updated.governance.maintenance_mode = value
    history = list(current.audit_log or [])
    history.insert(0, sr.SettingsAuditEntry(timestamp=now_iso, admin_email=by, action="PLATFORM_UPGRADE_MAINTENANCE",
                                            changed_fields={"governance.maintenance_mode": {"from": not value,
                                                                                            "to": value},
                                                            "reason": reason}))
    updated.audit_log = history[:15]
    updated.updated_at, updated.updated_by = now_iso, by
    updated.version = (current.version or 1) + 1
    try:
        sr.store_settings_document(sr.validated_settings_document(updated), current.version or 1)
    except sr.SettingsChangedMeanwhile:
        raise _err(409, "SETTINGS_VERSION_CONFLICT", "The platform settings changed while maintenance mode was being "
                   "set; nothing was changed. Retry.")
    sr._invalidate_current_settings_cache()


def _active_executions() -> int:
    if active_executions_provider is not None:
        return active_executions_provider()
    # Workflows Executions REST (read-only GET with the CC's own credentials): google-cloud-workflows is not in the
    # Control Center image (tests/test_shared_packaging.py KNOWN_GUARDED_GAPS), so the client library is not used.
    project, region = pr._project(), pr._region()
    if not project or not region:
        raise RuntimeError("PROJECT_ID or region unknown")
    url = (f"{WORKFLOW_EXECUTIONS_API}/projects/{urllib.parse.quote(project, safe='')}/locations/"
           f"{urllib.parse.quote(region, safe='')}/workflows/{MAIN_WORKFLOW}/executions?pageSize=100&filter="
           + urllib.parse.quote(ACTIVE_FILTER, safe=""))
    status, body = pr._run_get_json()(url)
    if status != 200 or not isinstance(body, dict):
        raise RuntimeError(f"executions list: HTTP {status}")
    executions = body.get("executions") or []
    if not isinstance(executions, list):
        raise RuntimeError("executions list: unexpected answer")
    return len(executions)


def _publisher():
    if publisher_provider is not None:
        return publisher_provider()
    from db import get_pubsub_publisher
    return get_pubsub_publisher()


def _publish(topic: str, request_id: str, kind: str) -> str:
    """The Control Center's ONE new permission (roles/pubsub.publisher on this topic): one message, the request id as
    the attribute the trigger reads. Returns the message id; raises on failure."""
    pub = _publisher()
    if pub is None:
        raise RuntimeError("no Pub/Sub publisher client")
    data = json.dumps({"request_id": request_id, "kind": kind}, sort_keys=True).encode("utf-8")
    future = pub.publish(topic, data, request_id=request_id)
    return str(future.result(timeout=30))


def _updates(request: Request) -> Dict[str, Any]:
    if updates_provider is not None:
        return updates_provider(request)
    return pr.get_platform_updates(request, force=False)


def _resolve_commit(repository: str, tag: str) -> str:
    """The commit the release tag points at (GitHub, unauthenticated): pinned in the request; step 0 refuses when the
    signed tag no longer resolves to it (SOURCE_CHANGED). The qualified ref `tags/<tag>` (RT L-2): a branch with the
    same name must never shadow the tag."""
    try:
        status, body = pr._github("GET", f"/repos/{repository}/commits/tags/" + urllib.parse.quote(tag, safe=""))
    except Exception as e:  # noqa: BLE001
        raise _err(502, "TAG_UNRESOLVED", f"GitHub could not be reached to resolve {tag} ({type(e).__name__}); "
                   "nothing was started. Retry.")
    sha = body.get("sha") if isinstance(body, dict) else None
    if status != 200 or not _is_hex(sha, 40):
        raise _err(502, "TAG_UNRESOLVED", f"GitHub did not resolve {tag} to a commit (HTTP {status}); nothing was "
                   "started. Check again.")
    return sha


# ------------------------------------------------------------------------------------------------ admin + confirm
def _require_admin(request: Request, write: bool = False) -> str:
    return pr._require_admin(request, write=write)


def _confirm(typed: str) -> None:
    project = pr._project()
    if not project or typed.strip() != project:
        raise _err(422, "CONFIRMATION_MISMATCH", "Type this install's project id exactly to confirm.")


# ------------------------------------------------------------------------------------------------ button
def button_state(installed: bool, source_view: Dict[str, Any], updates: Optional[Dict[str, Any]],
                 lease: Optional[str]) -> Dict[str, Any]:
    """Pure: the button's visibility, enabled state, reason code and one-line text, plus the target when there is one.
    Shown only when the last check is OK with update_available and the guard says ALLOW (review §4)."""
    def out(reason: str, target: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {"visible": reason not in HIDDEN_REASONS, "enabled": reason == READY, "reason": reason,
                "text": REASONS[reason], "target": target,
                "apply_where": apply_where(pr._project()) if reason == "NEEDS_APPLY_SH" else ""}

    if not installed:
        return out("UPGRADER_NOT_INSTALLED")
    if not source_view.get("valid", False):
        return out("RELEASE_SOURCE_INVALID")
    if source_view.get("update_check") is False:
        return out("UPDATE_CHECK_OFF")
    if lease in ("ACTIVE", "STALE"):
        return out("UPGRADE_IN_PROGRESS")
    status = (updates or {}).get("status")
    if status == "UPDATE_CHECK_OFF":
        return out("UPDATE_CHECK_OFF")
    if status == "SOURCE_INVALID":
        return out("RELEASE_SOURCE_INVALID")
    if status in (pr.REPOSITORY_NOT_FOUND, pr.NO_RELEASES):
        return out(status)
    if status != "OK":
        return out("COULD_NOT_CHECK")
    latest = updates.get("latest") or {}
    if not updates.get("update_available") or not latest.get("tag"):
        return out("UP_TO_DATE")
    if not updates.get("manifest"):
        return out("MANIFEST_UNAVAILABLE")
    decision = (updates.get("guard") or {}).get("decision")
    if decision == rm.NEEDS_APPLY_SH:
        return out("NEEDS_APPLY_SH")
    if decision != rm.ALLOW:
        return out("PLATFORM_STAMP_UNKNOWN")
    return out(READY, {"tag": latest["tag"], "release": latest.get("release"),
                       "prerelease": bool(latest.get("prerelease"))})


# ------------------------------------------------------------------------------------------------ views
def _build_url(build_id: Any) -> str:
    if not isinstance(build_id, str) or not build_id or not set(build_id) <= set("0123456789abcdef-"):
        return ""
    region = pr._region()
    return (f"https://console.cloud.google.com/cloud-build/builds;region={urllib.parse.quote(region, safe='')}/"
            f"{build_id}?project={urllib.parse.quote(pr._project(), safe='')}")


def _history_url() -> str:
    return (f"https://console.cloud.google.com/cloud-build/builds;region={urllib.parse.quote(pr._region(), safe='')}"
            f"?project={urllib.parse.quote(pr._project(), safe='')}")


def _components(progress: Dict[str, Any]) -> List[Dict[str, Any]]:
    built = progress.get("built") if isinstance(progress.get("built"), dict) else {}
    deployed = progress.get("deployed") if isinstance(progress.get("deployed"), dict) else {}
    check = progress.get("check") if isinstance(progress.get("check"), dict) else {}
    previous = progress.get("previous") if isinstance(progress.get("previous"), dict) else {}
    rolled = progress.get("rolled_back") if isinstance(progress.get("rolled_back"), dict) else {}
    rows = []
    for name, kind, _ in rm.COMPONENTS:
        c = check.get(name) if isinstance(check.get(name), dict) else None
        if name in rolled:
            result = "ROLLED_BACK"
        elif c is not None:
            result = "OK" if c.get("ok") is True else "CHECK_FAILED"
        elif name in deployed:
            result = "DEPLOYED"
        elif name in built:
            result = "BUILT"
        else:
            result = "PENDING"
        prev = previous.get(name) if isinstance(previous.get(name), dict) else {}
        rows.append({"name": name, "kind": kind, "result": result, "built": name in built,
                     "deployed": name in deployed,
                     "reason": str(c.get("reason") or "")[:300] if c is not None else "",
                     "previous_revision": prev.get("revision") if isinstance(prev.get("revision"), str) else ""})
    return rows


def request_view(rid: str, req: Dict[str, Any], progress: Optional[Dict[str, Any]], lease: Optional[str],
                 holds_lease: bool) -> Dict[str, Any]:
    p = progress or {}
    status = p.get("status") if isinstance(p.get("status"), str) else None
    if status is None:
        if req.get("status") in (REQ_NOT_SENT, REQ_CANCELLED):
            status = req["status"]
        elif holds_lease and lease == "STALE":
            status = "STALE"
        elif holds_lease:
            status = "WAITING_FOR_BUILD"
        else:
            status = "NO_BUILD"
    kind = req.get("kind")
    terminal = is_terminal(status) or status in (REQ_NOT_SENT, REQ_CANCELLED, "NO_BUILD")
    previous = p.get("previous")
    rollback_offered = (kind == KIND_UPGRADE and status in ROLLBACK_OFFERED_STATUSES and _nonempty_map(previous))
    retry_offered = terminal and status not in SUCCESS_STATUSES
    maint = req.get("maintenance") if isinstance(req.get("maintenance"), dict) else {}
    return {
        "request_id": rid, "kind": kind, "target_tag": req.get("target_tag"), "release": req.get("release"),
        "expected_commit": req.get("expected_commit"), "requested_by": req.get("requested_by"),
        "requested_at": req.get("requested_at"), "rollback_of": req.get("rollback_of") or "",
        "retry_of": req.get("retry_of") or "", "status": status, "terminal": terminal,
        "stage": p.get("stage") or "", "code": p.get("code") or "", "message": str(p.get("message") or "")[:2000],
        "steps": [s for s in (p.get("steps") or []) if isinstance(s, str)][:20] if isinstance(p.get("steps"), list) else [],
        "build_id": p.get("build_id") or "", "build_url": _build_url(p.get("build_id")),
        "started_at": p.get("started_at"), "updated_at": p.get("updated_at"),
        "terraform_ready": p.get("terraform_ready") if isinstance(p.get("terraform_ready"), str) else "",
        "components": _components(p) if progress is not None else [],
        "waiting_text": waiting_text() if status == "WAITING_FOR_BUILD" else "",
        "rollback_offered": rollback_offered, "retry_offered": retry_offered,
        "maintenance": {"before": maint.get("before"), "set_by_upgrade": maint.get("set") is True,
                        "restored_at": maint.get("restored_at"), "kept_on": maint.get("kept_on") is True,
                        "restore_error": maint.get("restore_error") or ""},
        "published": bool(req.get("message_id")),
    }


# ------------------------------------------------------------------------------------------------ lease housekeeping
def _apply_maintenance_outcome(gdb, rid: str, req: Dict[str, Any], progress: Optional[Dict[str, Any]],
                               by: str) -> Dict[str, Any]:
    """Restore or keep maintenance for a finished request; recorded once on the request (`maintenance`)."""
    maint = dict(req.get("maintenance") or {}) if isinstance(req.get("maintenance"), dict) else {}
    if maint.get("restored_at") or maint.get("kept_on") or not maint.get("set"):
        return maint
    now_iso = _iso_z(clock())
    if maintenance_outcome(req, progress) == "RESTORE":
        try:
            _write_maintenance(bool(maint.get("before")), by, f"platform upgrade {rid} ended")
            maint["restored_at"] = now_iso
            maint.pop("restore_error", None)
        except Exception as e:  # noqa: BLE001 - fail-loudly §2: typed on the request + card banner; next look retries
            detail = getattr(e, "detail", None)
            maint["restore_error"] = (detail.get("code") if isinstance(detail, dict) else "") or type(e).__name__
            logger.error(f"MAINTENANCE_NOT_RESTORED: maintenance mode not restored after upgrade {rid}: {detail or e}")
    else:
        maint["kept_on"] = True
        maint["kept_on_at"] = now_iso
    try:
        _requests(gdb).document(rid).update({"maintenance": maint})
    except Exception as e:  # noqa: BLE001
        logger.error(f"could not record the maintenance outcome on upgrade {rid}: {e}")
    return maint


def _release_lease(gdb, lease_snap, rid: str, req: Optional[Dict[str, Any]], progress: Optional[Dict[str, Any]],
                   by: str, new_status: str) -> None:
    """Delete the lease (precondition: unchanged since read) and close the request, in one commit."""
    batch = gdb.batch()
    batch.delete(_lease_ref(gdb), option=gdb.write_option(last_update_time=lease_snap.update_time))
    if req is not None:
        fields: Dict[str, Any] = {"status": new_status, "closed_at": _iso_z(clock())}
        if progress is not None and isinstance(progress.get("status"), str):
            fields["result"] = progress["status"]
        batch.update(_requests(gdb).document(rid), fields)
    batch.commit()
    logger.warning(json.dumps({"event": "stackvend.platform_upgrade_lease_released", "request_id": rid, "by": by,
                               "status": new_status, "result": (progress or {}).get("status")}, sort_keys=True))


def _mark_started(gdb, rid: str, req: Dict[str, Any]) -> Dict[str, Any]:
    """Review A M-B: REQUESTED -> STARTED once the progress record exists (step 0 runs only a REQUESTED request)."""
    if req.get("status") != REQ_REQUESTED:
        return req
    try:
        _requests(gdb).document(rid).update({"status": REQ_STARTED, "started_seen_at": _iso_z(clock())})
        return {**req, "status": REQ_STARTED}
    except Exception as e:  # noqa: BLE001 - the next look retries; step 0's progress claim still runs it once
        logger.error(f"REQUEST_NOT_MARKED_STARTED: upgrade request {rid}: {e}")
        return req


def _lease_now(gdb, pdb, by: str, release_finished: bool = True) -> Tuple[Optional[Dict[str, Any]], Any]:
    """The lease as {request_id, state, expires_at} (None when there is none). A FINISHED lease is released here
    (plan §3.9: "the CC releases it when the progress document shows a terminal state") and its maintenance rule
    applied; then None is returned."""
    snap, lease = _get(_lease_ref(gdb))
    if lease is None:
        return None, snap
    rid = lease.get("request_id") if isinstance(lease.get("request_id"), str) else ""
    _rs, req = _get(_requests(gdb).document(rid)) if _is_hex(rid, 32) else (None, None)
    progress = _progress(pdb, rid) if _is_hex(rid, 32) else None
    if req is not None and progress is not None:
        req = _mark_started(gdb, rid, req)
    state = lease_state(lease, req, progress, clock())
    if state == "ACTIVE":
        renewal = renewed_expiry(lease, progress)
        if renewal is not None:
            try:
                _lease_ref(gdb).update({"expires_at": renewal, "renewed_at": _iso_z(clock())},
                                       option=gdb.write_option(last_update_time=snap.update_time))
                lease = {**lease, "expires_at": renewal}
            except Exception as e:  # noqa: BLE001 - changed meanwhile; the next look renews it
                logger.info(f"lease of {rid} not renewed here ({type(e).__name__})")
    if state == "FINISHED" and release_finished:
        try:
            _release_lease(gdb, snap, rid, req, progress, by,
                           REQ_DONE if (req or {}).get("status") in (REQ_REQUESTED, REQ_STARTED)
                           else (req or {}).get("status", REQ_DONE))
        except Exception as e:  # noqa: BLE001 - someone else released or replaced it meanwhile
            logger.info(f"lease of {rid} not released here ({type(e).__name__}); re-reading")
            snap2, lease2 = _get(_lease_ref(gdb))
            if lease2 is not None:
                return {"request_id": lease2.get("request_id"), "state": "ACTIVE",
                        "expires_at": lease2.get("expires_at")}, snap2
            return None, snap2
        if req is not None:
            _apply_maintenance_outcome(gdb, rid, req, progress, by)
        return None, None
    return {"request_id": rid, "state": state, "expires_at": lease.get("expires_at"),
            "kind": (req or {}).get("kind"), "requested_by": (req or {}).get("requested_by")}, snap


# ------------------------------------------------------------------------------------------------ GET status
def _history(gdb, pdb, lease: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    try:
        docs = list(_requests(gdb).order_by("requested_at", direction="DESCENDING").limit(HISTORY_LIMIT).stream())
    except Exception as e:  # noqa: BLE001
        logger.warning(f"could not list upgrade requests: {e}")
        return []
    out = []
    for d in docs:
        rid = getattr(d, "id", "")
        data = d.to_dict() if callable(getattr(d, "to_dict", None)) else None
        if not _is_hex(rid, 32) or not isinstance(data, dict):
            continue
        holds = lease is not None and lease.get("request_id") == rid
        prog = _progress(pdb, rid)
        if prog is not None:
            data = _mark_started(gdb, rid, data)
        out.append(request_view(rid, data, prog, lease.get("state") if holds else None, holds))
    return out


@router.get("/api/settings/platform-upgrade", dependencies=[require(ADMIN)])
def get_platform_upgrade(request: Request):
    email = _require_admin(request)
    topic, topic_why = upgrade_topic()
    if not topic:  # RT L-3: upgrader not installed -> no database read, no GitHub call, the card stays hidden
        button = button_state(False, {}, None, None)
        button["detail"] = topic_why
        return {"installed": False, "approval_required": _approval_required(), "approval_text": APPROVAL_TEXT,
                "button": button, "lease": None, "current": None, "history": [], "maintenance_kept_on": None,
                "cloud_build_history_url": "", "update_status": None}
    gdb, pdb = _gdb(), _pdb()
    lease, _snap = _lease_now(gdb, pdb, email or "control-center")
    src, _s, doc, error = pr._load_source(gdb)
    source_view = pr._source_view(src, doc, error)
    updates: Optional[Dict[str, Any]] = None
    if topic and error is None and (src or rsrc.default_source()).update_check and lease is None:
        updates = _updates(request)  # the cached update check (no GitHub call while it is fresh)
    button = button_state(bool(topic), source_view, updates, lease.get("state") if lease else None)
    if not topic:
        button["detail"] = topic_why
    history = _history(gdb, pdb, lease)
    current = next((h for h in history if lease and h["request_id"] == lease.get("request_id")), None)
    if current is None and history:
        current = history[0]
    if current is not None:
        current = {**current, "terraform_ready_cc": cc_terraform_ready_for(current)}
    # the newest finished request that managed maintenance decides the banner (a later success supersedes a failure)
    last = None if lease else next((h for h in history if h["maintenance"]["set_by_upgrade"] and h["terminal"]), None)
    if last and last["maintenance"]["restore_error"] and not last["maintenance"]["restored_at"]:
        _rs, raw = _get(_requests(gdb).document(last["request_id"]))  # retry the failed restore (fail-loudly §2)
        if raw is not None:
            maint = _apply_maintenance_outcome(gdb, last["request_id"], raw, _progress(pdb, last["request_id"]),
                                               email or "control-center")
            last = {**last, "maintenance": {**last["maintenance"], "restored_at": maint.get("restored_at"),
                                            "restore_error": maint.get("restore_error") or ""}}
    banner = None
    if last and not last["maintenance"]["restored_at"]:
        if last["maintenance"]["kept_on"]:
            banner = {"request_id": last["request_id"], "status": last["status"], "code": "MAINTENANCE_KEPT_ON",
                      "message": "Maintenance mode stays on after this upgrade failed (new workload runs are refused). "
                                 "Roll back or retry, or turn maintenance mode off when you are done."}
        elif last["maintenance"]["restore_error"]:
            banner = {"request_id": last["request_id"], "status": last["status"], "code": "MAINTENANCE_NOT_RESTORED",
                      "message": "Maintenance mode could not be turned back after this upgrade ("
                                 f"{last['maintenance']['restore_error']}); this page retries it on every look, or "
                                 "turn it off here."}
    return {
        "installed": bool(topic), "approval_required": _approval_required(), "approval_text": APPROVAL_TEXT,
        "button": button, "lease": lease, "current": current, "history": history,
        "maintenance_kept_on": banner,
        "cloud_build_history_url": _history_url() if topic else "",
        "update_status": (updates or {}).get("status"),
    }


# ------------------------------------------------------------------------------------------------ submit (shared)
def _refuse_common(gdb, pdb, email: str, expected_fingerprint: str) -> Tuple[str, rsrc.ReleaseSource]:
    """The refusals every start / retry / rollback shares, in the order the button shows them."""
    topic, why = upgrade_topic()
    if not topic:
        raise _err(409, "UPGRADER_NOT_INSTALLED", f"{REASONS['UPGRADER_NOT_INSTALLED']} ({why})")
    src, _s, _doc, error = pr._load_source(gdb)
    if error is not None:
        raise _err(409, "RELEASE_SOURCE_INVALID", REASONS["RELEASE_SOURCE_INVALID"], error=error.detail())
    effective = src or rsrc.default_source()
    if not effective.update_check:
        raise _err(409, "UPDATE_CHECK_OFF", REASONS["UPDATE_CHECK_OFF"])
    if expected_fingerprint != effective.fingerprint:
        raise _err(409, "SOURCE_SETTING_CHANGED", "The release source changed after this page was loaded; nothing "
                   "was started. Reload and retry.", fingerprint=effective.fingerprint)
    lease, _snap = _lease_now(gdb, pdb, email)
    if lease is not None:
        raise _err(409, "UPGRADE_IN_PROGRESS", REASONS["UPGRADE_IN_PROGRESS"], lease=lease)
    return topic, effective


def _existing(gdb, rid: str, email: str, kind: str, target_tag: str) -> Optional[Dict[str, Any]]:
    """Idempotency: the same caller + key -> the same request id. Same request -> its view (published again only if
    the first attempt never reached Pub/Sub and it still holds the lease); a different one -> 409."""
    _snap, req = _get(_requests(gdb).document(rid))
    if req is None:
        return None
    if req.get("requested_by") != email or req.get("kind") != kind or req.get("target_tag") != target_tag:
        raise _err(409, "REQUEST_ID_IN_USE", "This idempotency key was already used for another request; reload.")
    return req


def _publish_existing(gdb, pdb, rid: str, req: Dict[str, Any]) -> Dict[str, Any]:
    if req.get("status") in (REQ_NOT_SENT, REQ_CANCELLED):  # RT H-1: never a 202 for a request that was never sent
        raise _err(409, "REQUEST_NOT_SENT", "The earlier attempt was not sent, so nothing was started; request the "
                   "upgrade again.", status=req["status"])
    if req.get("status") == REQ_REQUESTED and not req.get("message_id"):
        topic, _ = upgrade_topic()
        _ls, lease = _get(_lease_ref(gdb))
        if topic and lease is not None and lease.get("request_id") == rid:
            mid = _publish(topic, rid, req.get("kind", KIND_UPGRADE))
            _requests(gdb).document(rid).update({"message_id": mid, "published_at": _iso_z(clock())})
            req = {**req, "message_id": mid}
    lease, _snap = _lease_now(gdb, pdb, str(req.get("requested_by") or "control-center"), release_finished=False)
    holds = lease is not None and lease.get("request_id") == rid
    return {**request_view(rid, req, _progress(pdb, rid), lease.get("state") if holds else None, holds),
            "idempotent": True}


def _recent_requests(gdb) -> List[Tuple[str, Dict[str, Any]]]:
    """(id, document) of the newest requests, newest first (the `_lease` document has no requested_at)."""
    try:
        docs = list(_requests(gdb).order_by("requested_at", direction="DESCENDING").limit(HISTORY_LIMIT).stream())
    except Exception as e:  # noqa: BLE001
        raise _err(503, "GUARD_DATABASE_UNAVAILABLE", f"Could not list the upgrade requests: {type(e).__name__}")
    out = []
    for d in docs:
        data = d.to_dict() if callable(getattr(d, "to_dict", None)) else None
        if _is_hex(getattr(d, "id", ""), 32) and isinstance(data, dict):
            out.append((d.id, data))
    return out


def _pending_maintenance(gdb) -> Tuple[str, Optional[Dict[str, Any]]]:
    """RT M-2: the newest request that managed maintenance mode; when it left maintenance on (kept on after a failure,
    or its restore failed), its pre-upgrade value is what the next upgrade must restore. ("", None) otherwise."""
    for rid, data in _recent_requests(gdb):
        maint = data.get("maintenance") if isinstance(data.get("maintenance"), dict) else None
        if not maint or not maint.get("set"):
            continue
        if not maint.get("restored_at") and (maint.get("kept_on") or maint.get("restore_error")):
            return rid, maint
        return "", None
    return "", None


def _superseded_by(gdb, pdb, orig_id: str, orig: Dict[str, Any]) -> str:
    """RT L-4: the id of a newer request that changed the install (a progress record that deployed or rolled back
    something, or succeeded), or "". Rolling back an older upgrade after it would move services backwards."""
    since = _parse_ts(orig.get("requested_at"))
    for rid, data in _recent_requests(gdb):
        if rid == orig_id:
            continue
        when = _parse_ts(data.get("requested_at"))
        if since is None or when is None or when <= since:
            continue
        progress = _progress(pdb, rid)
        if progress is not None and (progress.get("status") in SUCCESS_STATUSES or not changed_nothing(progress)):
            return rid
    return ""


def _check_executions(upgrade_anyway: bool) -> None:
    try:
        active = _active_executions()
    except Exception as e:  # noqa: BLE001
        if upgrade_anyway:
            return
        raise _err(503, "EXECUTIONS_UNKNOWN", f"Could not list running workload executions ({type(e).__name__}); "
                   "nothing was started. Retry, or tick \"upgrade anyway\".")
    if active and not upgrade_anyway:
        raise _err(409, "WORKLOAD_RUNS_ACTIVE", f"{active} workload run(s) are in progress. Wait for them to finish, "
                   "or tick \"upgrade anyway\" (they keep running; new runs are paused during the upgrade).",
                   active=active)


def _submit(request: Request, gdb, pdb, *, email: str, rid: str, kind: str, target_tag: str, expected_commit: str,
            release: str, fingerprint: str, topic: str, rollback_of: str = "", retry_of: str = "",
            inherit_maintenance: Optional[Dict[str, Any]] = None, upgrade_anyway: bool = False) -> Dict[str, Any]:
    """Lease + request (one commit), maintenance on, one message. Any failure after the commit undoes what this call
    did (request closed so a late message cannot run it, lease released, maintenance restored) and raises."""
    _check_executions(upgrade_anyway)
    current_maintenance = _read_maintenance()
    inherited_from = ""
    if inherit_maintenance is None:  # RT M-2: a fresh start after a failure that kept maintenance on
        inherited_from, inherit_maintenance = _pending_maintenance(gdb)
    else:
        inherited_from = retry_of or rollback_of
    if inherit_maintenance and inherit_maintenance.get("set") and not inherit_maintenance.get("restored_at"):
        before = bool(inherit_maintenance.get("before"))  # the value before the failed request this one follows
    else:
        before, inherited_from = current_maintenance, ""
    now = clock()
    maintenance = {"before": before, "set": True, "restored_at": None, "kept_on": False}
    if inherited_from:
        maintenance["inherited_from"] = inherited_from
    req = {"schema_version": REQUEST_SCHEMA, "kind": kind, "status": REQ_REQUESTED, "target_tag": target_tag,
           "expected_commit": expected_commit, "source_fingerprint": fingerprint, "requested_by": email,
           "rollback_of": rollback_of, "retry_of": retry_of, "release": release, "requested_at": _iso_z(now),
           "via": VIA, "upgrade_anyway": bool(upgrade_anyway), "maintenance": maintenance}
    lease = {"request_id": rid, "expires_at": _iso_z(now + LEASE_SECONDS), "created_at": _iso_z(now),
             "created_by": email, "kind": kind}
    try:
        batch = gdb.batch()  # create-if-absent: the commit fails when a lease (or this request) already exists
        batch.create(_lease_ref(gdb), lease)
        batch.create(_requests(gdb).document(rid), req)
        batch.commit()
    except Exception as e:  # noqa: BLE001 - classified below (RT L-6)
        from google.api_core import exceptions as gexc
        if isinstance(e, gexc.Conflict):  # AlreadyExists: the lease (or this request) exists
            logger.info(f"upgrade lease not taken for {rid}: {type(e).__name__}")
            raise _err(409, "UPGRADE_IN_PROGRESS", "Another upgrade took the lease first; nothing was started.")
        logger.error(f"upgrade request {rid} not written: {type(e).__name__}: {e}")
        raise _err(503, "GUARD_DATABASE_UNAVAILABLE", f"The upgrade request could not be written "
                   f"({type(e).__name__}); nothing was started. Retry.")

    def undo(status: str, restore: bool) -> str:
        """Close the request and release the lease; restore maintenance. Returns what could NOT be undone ("" = all)."""
        left = []
        try:
            snap, cur = _get(_lease_ref(gdb))
            if cur is not None and cur.get("request_id") == rid:
                _release_lease(gdb, snap, rid, req, None, email, status)
            else:
                _requests(gdb).document(rid).update({"status": status, "closed_at": _iso_z(clock())})
        except Exception as e:  # noqa: BLE001
            logger.error(f"could not close upgrade request {rid} after a failed start: {e}")
            left.append("the upgrade lease is still held (clear it once it expires)")
        if restore and not current_maintenance:
            try:
                _write_maintenance(False, email, f"platform upgrade {rid} not started")
            except Exception as e:  # noqa: BLE001
                logger.error(f"maintenance mode left on after the failed start of {rid}: {getattr(e, 'detail', e)}")
                left.append("maintenance mode is still on (turn it off in Settings)")
        return "; ".join(left)

    try:
        if not current_maintenance:
            _write_maintenance(True, email, f"platform upgrade {rid} ({kind} {target_tag})")
    except Exception as e:  # noqa: BLE001
        left = undo(REQ_CANCELLED, restore=False)
        if isinstance(getattr(e, "detail", None), dict) and not left:
            raise
        raise _err(503, "MAINTENANCE_UNAVAILABLE", f"Maintenance mode could not be turned on ({type(e).__name__}); "
                   "nothing was started." + (f" Not undone: {left}." if left else ""))
    try:
        mid = _publish(topic, rid, kind)
    except Exception as e:  # noqa: BLE001
        logger.error(f"upgrade request {rid} not published: {e}")
        left = undo(REQ_NOT_SENT, restore=True)
        raise _err(502, "PUBLISH_FAILED", f"The upgrade request could not be sent ({type(e).__name__}); nothing was "
                   "started" + (f". Not undone: {left}." if left else " and maintenance mode is back to its earlier "
                                "value. Retry."))
    try:
        _requests(gdb).document(rid).update({"message_id": mid, "published_at": _iso_z(clock())})
        req.update(message_id=mid)
    except Exception as e:  # noqa: BLE001 - the message is out; the record only says when
        logger.warning(f"upgrade request {rid} was published but not marked as sent: {e}")
    logger.warning(json.dumps({"event": "stackvend.platform_upgrade_requested", "request_id": rid, "kind": kind,
                               "target_tag": target_tag, "expected_commit": expected_commit, "by": email,
                               "rollback_of": rollback_of, "retry_of": retry_of, "message_id": mid},
                              sort_keys=True))
    return {**request_view(rid, req, None, "ACTIVE", True), "idempotent": False}


# ------------------------------------------------------------------------------------------------ POST start
class StartRequest(BaseModel):
    target_tag: StrictStr
    expected_source_fingerprint: StrictStr
    confirm_project: StrictStr
    idempotency_key: StrictStr
    upgrade_anyway: StrictBool = False


def _key_ok(key: str) -> None:
    if not (16 <= len(key) <= 64) or not key.isascii() or not key.replace("-", "").isalnum():
        raise _err(422, "BAD_IDEMPOTENCY_KEY", "idempotency_key must be 16-64 letters, digits or dashes.")


@router.post("/api/settings/platform-upgrade", dependencies=[require(ADMIN)], status_code=202)
def start_platform_upgrade(req: StartRequest, request: Request):
    email = _require_admin(request, write=True)
    _key_ok(req.idempotency_key)
    _confirm(req.confirm_project)
    gdb, pdb = _gdb(), _pdb()
    rid = request_id_for(email, req.idempotency_key)
    existing = _existing(gdb, rid, email, KIND_UPGRADE, req.target_tag)
    if existing is not None:
        return _publish_existing(gdb, pdb, rid, existing)
    topic, effective = _refuse_common(gdb, pdb, email, req.expected_source_fingerprint)
    src, _s, doc, error = pr._load_source(gdb)
    button = button_state(True, pr._source_view(src, doc, error), _updates(request), None)
    if button["reason"] != READY:
        raise _err(409, "NO_TARGET", button["text"], reason=button["reason"])
    target = button["target"]
    if target["tag"] != req.target_tag:
        raise _err(409, "TARGET_CHANGED", f"The newest release is now {target['tag']}, not {req.target_tag}; nothing "
                   "was started. Reload and confirm again.", target_tag=target["tag"])
    commit = _resolve_commit(effective.repository, target["tag"])
    return _submit(request, gdb, pdb, email=email, rid=rid, kind=KIND_UPGRADE, target_tag=target["tag"],
                   expected_commit=commit, release=str(target.get("release") or ""), fingerprint=effective.fingerprint,
                   topic=topic, upgrade_anyway=req.upgrade_anyway)


# ------------------------------------------------------------------------------------------------ retry / rollback
class FollowUpRequest(BaseModel):
    expected_source_fingerprint: StrictStr
    confirm_project: StrictStr
    idempotency_key: StrictStr
    upgrade_anyway: StrictBool = False


def _original(gdb, pdb, request_id: str) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    if not _is_hex(request_id, 32):
        raise _err(404, "REQUEST_NOT_FOUND", "No such upgrade request.")
    _snap, req = _get(_requests(gdb).document(request_id))
    if req is None:
        raise _err(404, "REQUEST_NOT_FOUND", "No such upgrade request.")
    return req, _progress(pdb, request_id)


@router.post("/api/settings/platform-upgrade/{request_id}/retry", dependencies=[require(ADMIN)], status_code=202)
def retry_platform_upgrade(request_id: str, req: FollowUpRequest, request: Request):
    """Run a request that did not succeed again: the same kind, verified tag and commit (and, for a rollback, the same
    upgrade to roll back) under a new request id. Step 0 re-verifies everything; the build redeploys by digest."""
    email = _require_admin(request, write=True)
    _key_ok(req.idempotency_key)
    _confirm(req.confirm_project)
    gdb, pdb = _gdb(), _pdb()
    orig, progress = _original(gdb, pdb, request_id)
    rid = request_id_for(email, req.idempotency_key)
    existing = _existing(gdb, rid, email, orig.get("kind"), orig.get("target_tag"))
    if existing is not None:
        return _publish_existing(gdb, pdb, rid, existing)
    topic, effective = _refuse_common(gdb, pdb, email, req.expected_source_fingerprint)
    view = request_view(request_id, orig, progress, None, False)
    if not view["retry_offered"]:
        raise _err(409, "NOT_RETRYABLE", f"Request {request_id} is {view['status']}; only a request that ended "
                   "without success can be run again.", status=view["status"])
    if orig.get("source_fingerprint") != effective.fingerprint:
        raise _err(409, "SOURCE_SETTING_CHANGED", "The release source changed since this request; start a new upgrade "
                   "from the newest release instead.")
    if orig.get("kind") not in (KIND_UPGRADE, KIND_ROLLBACK) or not _is_hex(orig.get("expected_commit"), 40):
        raise _err(409, "NOT_RETRYABLE", "The stored request is not complete; start a new upgrade instead.")
    return _submit(request, gdb, pdb, email=email, rid=rid, kind=orig["kind"], target_tag=orig.get("target_tag"),
                   expected_commit=orig["expected_commit"], release=str(orig.get("release") or ""),
                   fingerprint=effective.fingerprint, topic=topic, rollback_of=orig.get("rollback_of") or "",
                   retry_of=request_id, inherit_maintenance=orig.get("maintenance"),
                   upgrade_anyway=req.upgrade_anyway)


@router.post("/api/settings/platform-upgrade/{request_id}/rollback", dependencies=[require(ADMIN)], status_code=202)
def rollback_platform_upgrade(request_id: str, req: FollowUpRequest, request: Request):
    """"Roll back services" for an upgrade that ended PARTIAL / FAILED_CHECKING with recorded previous revisions: a
    ROLLBACK request naming the upgraded tag + commit (re-verified by step 0) and rollback_of = that upgrade."""
    email = _require_admin(request, write=True)
    _key_ok(req.idempotency_key)
    _confirm(req.confirm_project)
    gdb, pdb = _gdb(), _pdb()
    orig, progress = _original(gdb, pdb, request_id)
    rid = request_id_for(email, req.idempotency_key)
    existing = _existing(gdb, rid, email, KIND_ROLLBACK, orig.get("target_tag"))
    if existing is not None:
        return _publish_existing(gdb, pdb, rid, existing)
    topic, effective = _refuse_common(gdb, pdb, email, req.expected_source_fingerprint)
    view = request_view(request_id, orig, progress, None, False)
    if not view["rollback_offered"] or not _is_hex(orig.get("expected_commit"), 40):
        raise _err(409, "ROLLBACK_NOT_OFFERED", f"Request {request_id} is {view['status']}: roll back is offered for "
                   "an upgrade that ended PARTIAL or with a failed health check, with recorded previous revisions.",
                   status=view["status"])
    newer = _superseded_by(gdb, pdb, request_id, orig)
    if newer:
        raise _err(409, "ROLLBACK_SUPERSEDED", f"A newer request ({newer}) changed the services after this upgrade; "
                   "rolling this one back would move them backwards. Use the newer request instead.", newer=newer)
    return _submit(request, gdb, pdb, email=email, rid=rid, kind=KIND_ROLLBACK, target_tag=orig.get("target_tag"),
                   expected_commit=orig["expected_commit"], release=str(orig.get("release") or ""),
                   fingerprint=effective.fingerprint, topic=topic, rollback_of=request_id,
                   inherit_maintenance=orig.get("maintenance"), upgrade_anyway=req.upgrade_anyway)


# ------------------------------------------------------------------------------------------------ clear lease
class ClearLeaseRequest(BaseModel):
    expected_request_id: StrictStr
    confirm_project: StrictStr


@router.post("/api/settings/platform-upgrade/lease/clear", dependencies=[require(ADMIN)])
def clear_platform_upgrade_lease(req: ClearLeaseRequest, request: Request):
    """Clear a stale lease: only when its build finished, or the lease expired and no build is still within its
    timeout (plan §3.9; the Control Center never asks Cloud Build). A request that never started is closed
    (CANCELLED), so a build approved later refuses it (REQUEST_NOT_PENDING / LEASE_NOT_HELD)."""
    email = _require_admin(request, write=True)
    _confirm(req.confirm_project)
    gdb, pdb = _gdb(), _pdb()
    snap, lease = _get(_lease_ref(gdb))
    if lease is None:
        return {"cleared": False, "message": "There is no upgrade lease."}
    rid = lease.get("request_id") if isinstance(lease.get("request_id"), str) else ""
    if rid != req.expected_request_id:
        raise _err(409, "LEASE_CHANGED", "The lease belongs to another request now; reload.", request_id=rid)
    _rs, orig = _get(_requests(gdb).document(rid)) if _is_hex(rid, 32) else (None, None)
    progress = _progress(pdb, rid) if _is_hex(rid, 32) else None
    state = lease_state(lease, orig, progress, clock())
    if state == "ACTIVE":
        raise _err(409, "LEASE_ACTIVE", "The upgrade's build may still be waiting or running; the lease can be "
                   "cleared once it finished or expired.", expires_at=lease.get("expires_at"))
    status = REQ_CANCELLED if progress is None else REQ_DONE
    if orig is not None and orig.get("status") in (REQ_NOT_SENT, REQ_CANCELLED):
        status = orig["status"]
    try:
        _release_lease(gdb, snap, rid, orig, progress, email, status)
    except Exception as e:  # noqa: BLE001
        raise _err(409, "LEASE_CHANGED", f"The lease changed meanwhile ({type(e).__name__}); reload.")
    maint = _apply_maintenance_outcome(gdb, rid, orig, progress, email) if orig is not None else {}
    logger.warning(json.dumps({"event": "stackvend.platform_upgrade_lease_cleared", "request_id": rid, "by": email,
                               "state": state, "progress": (progress or {}).get("status")}, sort_keys=True))
    return {"cleared": True, "request_id": rid, "state": state, "maintenance": maint}


# ------------------------------------------------------------------------------------------------ maintenance restore
class ConfirmRequest(BaseModel):
    confirm_project: StrictStr


@router.post("/api/settings/platform-upgrade/{request_id}/maintenance/restore", dependencies=[require(ADMIN)])
def restore_platform_upgrade_maintenance(request_id: str, req: ConfirmRequest, request: Request):
    """"Turn maintenance off" after a failed upgrade kept it on: back to the value recorded before the upgrade. Refused
    while an upgrade holds the lease."""
    email = _require_admin(request, write=True)
    _confirm(req.confirm_project)
    gdb, pdb = _gdb(), _pdb()
    orig, _progress_doc = _original(gdb, pdb, request_id)
    lease, _snap = _lease_now(gdb, pdb, email)
    if lease is not None:
        raise _err(409, "UPGRADE_IN_PROGRESS", REASONS["UPGRADE_IN_PROGRESS"], lease=lease)
    maint = dict(orig.get("maintenance") or {}) if isinstance(orig.get("maintenance"), dict) else {}
    if not maint.get("set") or maint.get("restored_at"):
        return {"restored": False, "message": "Nothing to restore for this request."}
    before = bool(maint.get("before"))
    _write_maintenance(before, email, f"after platform upgrade {request_id} (restored by an administrator)")
    maint["restored_at"] = _iso_z(clock())
    maint.pop("restore_error", None)
    _requests(gdb).document(request_id).update({"maintenance": maint})
    logger.warning(json.dumps({"event": "stackvend.platform_upgrade_maintenance_restored", "request_id": request_id,
                               "by": email, "maintenance_mode": before}, sort_keys=True))
    return {"restored": True, "maintenance_mode": before}


# ------------------------------------------------------------------------------------------------ release source hook
def refuse_while_upgrading(gdb) -> None:
    """Release source changes are refused while an upgrade holds the lease (plan §3.9, §3.10.5; step 0 also refuses
    SOURCE_SETTING_CHANGED). A finished lease is released first. Without the upgrader (no topic env) no lease can
    be taken, so nothing is read (RT L-3: as before P3b)."""
    if not upgrade_topic()[0]:
        return
    _snap, held = _get(_lease_ref(gdb))
    if held is None:
        return
    lease, _snap = _lease_now(gdb, _pdb(), "control-center")
    if lease is not None:
        raise _err(409, "UPGRADE_IN_PROGRESS", "An upgrade is in progress: the release source cannot be changed until "
                   "it ends.", lease=lease)
