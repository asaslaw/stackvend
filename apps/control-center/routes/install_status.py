"""
StackVend Control Center: install warnings in Settings (lane 18 v3, owner rule 10-18).

Owner rule: "Install must be simple, smooth and never fail, only providing warnings in settings for lack of billing
user and tag admin." The install no longer stops for these; this page says what is missing and the exact fix.

GET  /api/settings/install-warnings      (ADMIN) warning cards:
  MANAGED_TAG_NOT_SET_UP       the deletion-safety tag does not exist (the installer was not an org Tag Administrator,
                               or organization / managed folder unset). Project deletes stay refused (fail closed).
                               Names the role, the organization and lists the StackVend-vended projects without it.
  MANAGED_TAG_BACKFILL_PENDING the tag exists but projects vended before it are untagged; one admin action binds it
                               (vending executes it, provenance-proven projects only).
  PROJECTS_WITHOUT_PROVENANCE  ledger workloads with no vend-time provenance record: never tagged automatically.
  GUARD_STATUS_UNAVAILABLE     vending could not answer (deletes stay refused).
  CC_BILLING_VIEWER_MISSING    the Control Center's own service account cannot read the billing account (old install
                               step A4): the exact gcloud command for a Billing Account Administrator.
POST /api/settings/managed-tag/backfill  (ADMIN) runs vending's backfill (non-destructive, idempotent, audited).
POST /api/settings/cc-log-reader/backfill (ADMIN) RT14-31 / owner decision D4 (11-14): runs vending's backfill that
                               grants this Control Center's runtime SA roles/logging.viewer on every provenance-proven,
                               open workload's child project (workloads vended before the vend-time grant), so the
                               Logs tab can read their runtime logs. Additive, idempotent, audited; {"dry_run": true}
                               lists what it would grant.
GET  /api/deletion-safety/status         (AUTHENTICATED) DELETION-TAG-BANNER (owner 11-11): the one deletion-safety state
                               behind the global banner on every Control Center page and the note on the new-workload
                               forms, for every signed-in user. Derived from the same typed cards as above (no project
                               lists, no organization id): NOT_SET_UP, BACKFILL_PENDING, SET_UP or UNAVAILABLE (never
                               SET_UP unless vending confirmed it). Admins get it inside install-warnings instead.

The tag facts come from vending (GET /guard/managed-tag, the CC's own ID token); the CC never reads or writes tags.
"""
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Request
from pydantic import BaseModel, StrictBool
from authz import ADMIN, AUTHENTICATED, is_human_admin, require

from config import PROJECT_ID, apply_where
import destructive_actions as da
from routes import settings as settings_routes

logger = logging.getLogger("control-center-install-status")

router = APIRouter()

TAG_ADMIN_ROLE = "roles/resourcemanager.tagAdmin"
BILLING_VIEWER_ROLE = "roles/billing.viewer"
# infra/platform/destructive_guard.tf google_service_account.stackvend_personas key (the CC's runtime identity).
CC_SA_ACCOUNT_ID = "sa-stackvend-control-center"
TAG_NOT_SET_UP = ("Deletion safety tag not set up: StackVend cannot decommission projects until a Tag Administrator "
                  "re-runs apply.sh apply")

# Test seams (None = the real Control Center helpers).
vending_requester: Optional[Callable[..., Any]] = None
billing_status_provider: Optional[Callable[[Request], Dict[str, Any]]] = None


def _project() -> str:
    return PROJECT_ID or os.getenv("PROJECT_ID", "") or os.getenv("GOOGLE_CLOUD_PROJECT", "")


def _requester() -> Callable[..., Any]:
    return vending_requester or settings_routes.make_vending_request


def _vending_get(path: str, request: Request) -> da.VendingOutcome:
    try:
        resp = _requester()(method="GET", path=path, json_body=None, timeout=30.0, request=request)
    except Exception as e:  # noqa: BLE001
        return da.VendingOutcome(False, 0, "VENDING_UNREACHABLE", f"{type(e).__name__}: {e}")
    if resp is None:
        return da.VendingOutcome(False, 0, "VENDING_UNCONFIGURED", "VENDING_SERVICE_URL is not configured")
    status = getattr(resp, "status_code", 0)
    if status != 200:
        err = da._vending_error(resp)
        return da.VendingOutcome(False, status, err["code"], err["detail"])
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        data = None
    if not isinstance(data, dict):
        return da.VendingOutcome(False, status, "VENDING_BAD_RESPONSE", "vending answered without a JSON object")
    return da.VendingOutcome(True, 200, "OK", "", data)


def _entries(value) -> List[Dict[str, Any]]:
    """A list of dict entries from vending's status, or ValueError (contract drift -> GUARD_STATUS_UNAVAILABLE)."""
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(e, dict) for e in value):
        raise ValueError("vending status list is not a list of objects")
    return value


def _projects(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{"product_id": e.get("product_id"), "project_id": e.get("project_id")} for e in entries]


def _cap_note(st: Dict[str, Any]) -> str:
    """RT F7: vending scans at most max_records provenance records / workloads per call."""
    if st.get("truncated") is True:
        return f" Only the first {st.get('max_records') or 'N'} records were checked; the list may be incomplete."
    return ""


def _tag_warnings(st: Dict[str, Any], project: str) -> List[Dict[str, Any]]:
    """Cards from vending's GET /guard/managed-tag body. Raises on a malformed body; the route turns that into the
    GUARD_STATUS_UNAVAILABLE card, never a 500 (RT F3)."""
    out: List[Dict[str, Any]] = []
    org = st.get("organization_id") or ""
    if not isinstance(org, str):
        raise ValueError("organization_id is not a string")
    org_scheme, _sep, org_number = org.partition("/")
    org_ok = org_scheme == "organizations" and org_number.isdigit()
    untagged = _entries(st.get("untagged_vended"))
    expired = _entries(st.get("sandbox_expired_untagged"))
    unprovenanced = _entries(st.get("unprovenanced_workloads"))
    candidates = st.get("backfill_candidates") or []
    if not isinstance(candidates, list):
        raise ValueError("backfill_candidates is not a list")
    cap = _cap_note(st)
    if st.get("tag_configured") is not True:
        fix = []
        if org_ok and st.get("managed_folder_configured"):
            message = f"{TAG_NOT_SET_UP} (needs {TAG_ADMIN_ROLE} on {org})."
            fix.append(f"gcloud organizations add-iam-policy-binding {org_number} "
                       f"--member=user:<TAG_ADMIN_EMAIL> --role={TAG_ADMIN_ROLE}")
        else:
            message = (f"{TAG_NOT_SET_UP}. organization_id and castor_managed_workloads_folder_id must be set in "
                       f"infra/platform/{project or '<project_id>'}.tfvars first; the Tag Administrator then needs "
                       f"{TAG_ADMIN_ROLE} on that organization.")
        fix.append(f"PROJECT_ID={project or '<project_id>'} bash scripts/apply.sh apply")
        out.append({"code": "MANAGED_TAG_NOT_SET_UP", "severity": "warning", "title": "Deletion safety tag not set up",
                    "message": message + cap, "role": TAG_ADMIN_ROLE, "organization_id": org if org_ok else "",
                    "fix": fix, "fix_where": apply_where(project), "projects": _projects(untagged),
                    "projects_label": "StackVend-vended projects without the tag"})
    else:
        wanted = {c for c in candidates if isinstance(c, str)}
        pending = [e for e in untagged if e.get("product_id") in wanted]
        if pending:
            out.append({"code": "MANAGED_TAG_BACKFILL_PENDING", "severity": "warning",
                        "title": "Projects vended before the deletion safety tag existed are untagged",
                        "message": (f"{len(pending)} project(s) have a vend-time provenance record but no tag, so "
                                    "StackVend cannot decommission them. Binding the tag deletes nothing; vending "
                                    "binds it only to projects its own vend-time record and labels prove. A sandbox "
                                    "whose recorded expiry has not passed becomes auto-deletable at that expiry. A "
                                    "large backfill can outlast the Control Center's 120 s wait: vending keeps going, "
                                    "and pressing the button again is safe (tagged projects are skipped)." + cap),
                        "fix": [], "projects": _projects(pending), "projects_label": "Will be tagged",
                        "action": {"method": "POST", "path": "/api/settings/managed-tag/backfill",
                                   "label": "Bind deletion safety tag"}})
    if expired:
        out.append({"code": "MANAGED_TAG_SANDBOXES_EXPIRED", "severity": "info",
                    "title": "Expired auto-delete sandboxes without the tag",
                    "message": ("These sandboxes passed their recorded expiry while they had no tag. They are never "
                                "tagged automatically: tagging them would let the next sweep delete them. Owner "
                                "decision."),
                    "fix": [], "projects": _projects(expired),
                    "projects_label": "Expired auto-delete sandboxes, not tagged (owner decision)"})
    if unprovenanced:
        out.append({"code": "PROJECTS_WITHOUT_PROVENANCE", "severity": "info",
                    "title": "Projects without a vend-time record",
                    "message": ("These workloads have no provenance record, so StackVend never tags or deletes them "
                                "automatically. The owner can review them with apps/project-vending/"
                                "backfill_provenance.py (dry run by default)." + cap),
                    "fix": [], "projects": _projects(unprovenanced),
                    "projects_label": "Not provenance-proven (never tagged automatically)"})
    return out


def _billing_warning(request: Request, project: str) -> Optional[Dict[str, Any]]:
    provider = billing_status_provider or settings_routes.get_billing_status_api
    try:
        b = provider(request)
    except Exception as e:  # noqa: BLE001
        return {"code": "BILLING_STATUS_UNAVAILABLE", "severity": "info", "title": "Billing access not checked",
                "message": f"The billing access check failed ({type(e).__name__}).", "fix": [], "projects": []}
    if not isinstance(b, dict) or not b.get("configured") or b.get("has_billing_access"):
        return None
    account = b.get("billing_account_id") or "<BILLING_ACCOUNT_ID>"
    member = f"serviceAccount:{CC_SA_ACCOUNT_ID}@{project or '<project_id>'}.iam.gserviceaccount.com"
    return {"code": "CC_BILLING_VIEWER_MISSING", "severity": "warning",
            "title": "Control Center cannot read the billing account",
            "message": (f"The Control Center service account has no {BILLING_VIEWER_ROLE} on billing account "
                        f"{account}, so billing status in Settings is incomplete. Installs and builds are not "
                        "affected. A Billing Account Administrator can fix it:"),
            "role": BILLING_VIEWER_ROLE, "member": member,
            "fix": [f"gcloud billing accounts add-iam-policy-binding {account} --member={member} "
                    f"--role={BILLING_VIEWER_ROLE}"],
            "projects": []}


def _guard_unavailable(message: str) -> Dict[str, Any]:
    return {"code": "GUARD_STATUS_UNAVAILABLE", "severity": "warning", "title": "Deletion safety status unavailable",
            "message": message, "fix": [], "projects": []}


def _tag_cards(outcome: da.VendingOutcome, project: str) -> List[Dict[str, Any]]:
    """The deletion-safety cards for one vending answer; a failed or malformed answer is GUARD_STATUS_UNAVAILABLE."""
    if not outcome.ok:
        return [_guard_unavailable(f"Project vending did not report the deletion safety tag status "
                                   f"({outcome.code}: {outcome.detail}). Project deletes stay refused until it does.")]
    try:
        return _tag_warnings(outcome.body, project)
    except Exception as e:  # noqa: BLE001 - RT F3: vending contract drift is a warning card, never a 500
        logger.warning(f"Unexpected deletion-safety status from vending: {type(e).__name__}: {e}")
        return [_guard_unavailable(f"Project vending answered with an unexpected deletion safety status "
                                   f"({type(e).__name__}). Project deletes stay refused until it is fixed.")]


# ---------------------------------------------------------------- DELETION-TAG-BANNER (owner 11-11)
DS_NOT_SET_UP, DS_BACKFILL_PENDING, DS_SET_UP, DS_UNAVAILABLE = "NOT_SET_UP", "BACKFILL_PENDING", "SET_UP", "UNAVAILABLE"
DS_STATES = (DS_NOT_SET_UP, DS_BACKFILL_PENDING, DS_SET_UP, DS_UNAVAILABLE)
# Card code -> banner state, most severe first. Exact typed codes from _tag_cards; nothing else is read.
_DS_STATE_BY_CODE = (("GUARD_STATUS_UNAVAILABLE", DS_UNAVAILABLE), ("MANAGED_TAG_NOT_SET_UP", DS_NOT_SET_UP),
                     ("MANAGED_TAG_BACKFILL_PENDING", DS_BACKFILL_PENDING))
DS_CANNOT_DELETE = ("StackVend can't delete or decommission the projects it creates until an organization Tag "
                    f"Administrator ({TAG_ADMIN_ROLE}) re-runs apply.sh apply.")
DS_FORM_NOT_SET_UP = ("Deletion safety is not set up: StackVend can't delete or decommission the project this creates "
                      "until an organization Tag Administrator re-runs apply.sh apply. You can still submit.")
DS_FORM_UNAVAILABLE = ("Couldn't check deletion safety status, so it is not known whether StackVend can delete the "
                       "project this creates. You can still submit.")
# A per-instance cache for the AUTHENTICATED status route only (every page load of every user would otherwise call
# vending, whose scan is expensive); install-warnings always reads vending fresh and refreshes it; the backfill clears
# it. Only confirmed answers are cached: an UNAVAILABLE read is retried on the next page load (no negative cache).
# RT F1: on a miss the status route single-flights the read (_ds_fetch_lock): requests that queued behind an in-flight
# read reuse its result, an UNAVAILABLE one included, for that round only. RT F2: an entry is stamped with the time
# taken BEFORE its vending call. RT F3: clearing bumps _ds_epoch, and a read that started before the clear never
# writes its (pre-clear) answer back.
DS_CACHE_TTL_S = 60.0
_ds_cache: Dict[str, Any] = {}
_ds_lock = threading.Lock()
_ds_fetch_lock = threading.Lock()
_ds_epoch = 0
_ds_round: Dict[str, Any] = {"n": 0, "result": None}  # completed single-flight reads, and the last one's answer


def _ds_state(cards: List[Dict[str, Any]]) -> Tuple[str, int]:
    """(state, pending project count) from the typed card codes."""
    by_code = {c.get("code"): c for c in cards}
    for code, state in _DS_STATE_BY_CODE:
        if code in by_code:
            return state, len(by_code[code].get("projects") or []) if state == DS_BACKFILL_PENDING else 0
    return DS_SET_UP, 0


def deletion_safety(state: str, pending: int, admin: bool) -> Dict[str, Any]:
    """The banner + form note for one state. No banner only for SET_UP (vending confirmed the tag)."""
    if state not in DS_STATES:
        state, pending = DS_UNAVAILABLE, 0
    ask = "Ask an administrator to fix it; the details are in Settings."
    if state == DS_NOT_SET_UP:
        banner = {"level": "warning", "title": "Deletion safety is not set up",
                  "message": f"{DS_CANNOT_DELETE} " + ("Details in Settings." if admin else ask)}
        form_note = DS_FORM_NOT_SET_UP
    elif state == DS_BACKFILL_PENDING:
        banner = {"level": "notice", "title": "Some projects are not covered by deletion safety",
                  "message": (f"{pending} project(s) created before the deletion safety tag existed are untagged, so "
                              "StackVend can't decommission them yet. "
                              + ("Tag them with one click in Settings (Bind deletion safety tag)." if admin else
                                 "Ask an administrator to tag them; the button is in Settings."))}
        form_note = None
    elif state == DS_UNAVAILABLE:
        banner = {"level": "neutral", "title": "Couldn't check deletion safety status",
                  "message": ("Project vending did not report whether the deletion safety tag is set up, so this page "
                              "can't say whether StackVend can delete the projects it creates. "
                              + ("Details in Settings." if admin else "If this persists, tell an administrator."))}
        form_note = DS_FORM_UNAVAILABLE
    else:
        banner, form_note = None, None
    return {"state": state, "pending_count": pending, "banner": banner, "form_note": form_note}


def _ds_epoch_now() -> int:
    with _ds_lock:
        return _ds_epoch


def _ds_cache_put(state: str, pending: int, started: float, epoch: int) -> None:
    """Cache a confirmed answer read from vending at `started` (monotonic, before the call). An answer from a read
    that began before the last clear is dropped; UNAVAILABLE empties the cache."""
    with _ds_lock:
        if epoch != _ds_epoch:
            return
        if state == DS_UNAVAILABLE:
            _ds_cache.clear()
        else:
            _ds_cache.update({"state": state, "pending": pending, "at": started})


def _ds_cache_get() -> Optional[Tuple[str, int]]:
    with _ds_lock:
        if _ds_cache and time.monotonic() - _ds_cache["at"] < DS_CACHE_TTL_S:
            return _ds_cache["state"], _ds_cache["pending"]
    return None


def clear_deletion_safety_cache() -> None:
    global _ds_epoch
    with _ds_lock:
        _ds_cache.clear()
        _ds_epoch += 1


def _ds_read(request: Request) -> Tuple[str, int]:
    """One vending read -> (state, pending), cached when confirmed."""
    epoch, started = _ds_epoch_now(), time.monotonic()
    state, pending = _ds_state(_tag_cards(_vending_get("/guard/managed-tag", request), _project()))
    _ds_cache_put(state, pending, started, epoch)
    return state, pending


def _ds_single_flight(request: Request) -> Tuple[str, int]:
    cached = _ds_cache_get()
    if cached is not None:
        return cached
    with _ds_lock:
        seen = _ds_round["n"]
    with _ds_fetch_lock:
        cached = _ds_cache_get()
        if cached is not None:
            return cached
        with _ds_lock:
            if _ds_round["n"] != seen and _ds_round["result"] is not None:
                return _ds_round["result"]  # a read finished while this request waited: reuse it (this round only)
        result = _ds_read(request)
        with _ds_lock:
            _ds_round["n"] += 1
            _ds_round["result"] = result
        return result


@router.get("/api/deletion-safety/status", dependencies=[require(AUTHENTICATED)])
def get_deletion_safety_status_api(request: Request):
    state, pending = _ds_single_flight(request)
    return deletion_safety(state, pending, is_human_admin(request))


@router.get("/api/settings/install-warnings", dependencies=[require(ADMIN)])
def get_install_warnings_api(request: Request):
    project = _project()
    epoch, started = _ds_epoch_now(), time.monotonic()
    outcome = _vending_get("/guard/managed-tag", request)
    tag_status: Optional[Dict[str, Any]] = outcome.body if outcome.ok else None
    warnings: List[Dict[str, Any]] = _tag_cards(outcome, project)
    state, pending = _ds_state(warnings)
    _ds_cache_put(state, pending, started, epoch)
    billing = _billing_warning(request, project)
    if billing:
        warnings.append(billing)
    return {"warnings": warnings, "managed_tag": tag_status, "deletion_safety": deletion_safety(state, pending, True)}


@router.post("/api/settings/managed-tag/backfill", dependencies=[require(ADMIN)])
def run_managed_tag_backfill_api(request: Request):
    admin_email = getattr(request.state, "user_email", None)
    clear_deletion_safety_cache()  # the page re-reads install-warnings right after; never serve the pre-backfill state
    try:
        outcome = da.call_vending(_requester(), "/guard/managed-tag/backfill", {"operator_email": admin_email},
                                  request=request, timeout=120.0)
    finally:
        clear_deletion_safety_cache()  # RT F3: drop anything a read during the backfill cached (and any read in flight)
    if not outcome.ok:
        return da.failure_response(outcome, action="MANAGED_TAG_BACKFILL", product_id="*")
    logger.info(f"MANAGED_TAG_BACKFILL requested by {admin_email}: {outcome.body.get('counts')}")
    return outcome.body


class CCLogReaderBackfillBody(BaseModel):
    dry_run: StrictBool = False


@router.post("/api/settings/cc-log-reader/backfill", dependencies=[require(ADMIN)])
def run_cc_log_reader_backfill_api(request: Request, body: Optional[CCLogReaderBackfillBody] = None):
    """RT14-31 / D4: vending grants the Control Center roles/logging.viewer on existing child projects (vending
    executes it; the CC never changes IAM). Typed per-workload results; a failure answers vending's typed error."""
    admin_email = getattr(request.state, "user_email", None)
    dry_run = bool(body and body.dry_run)
    outcome = da.call_vending(_requester(), "/guard/cc-log-reader/backfill",
                              {"operator_email": admin_email, "dry_run": dry_run}, request=request, timeout=300.0)
    if not outcome.ok:
        return da.failure_response(outcome, action="CC_LOG_READER_BACKFILL", product_id="*")
    logger.info(f"CC_LOG_READER_BACKFILL requested by {admin_email} (dry_run={dry_run}): {outcome.body.get('counts')}")
    return outcome.body
