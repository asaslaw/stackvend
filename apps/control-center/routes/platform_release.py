"""
StackVend Control Center: Settings ▸ Upgrades (FD-7C P3a + FD-4DA item 3). Read-only display plus two settings;
nothing here installs, deploys or runs Terraform.

GET /api/settings/platform-version   (ADMIN) the deployed version record (system_config/platform_release, written by
                                     deploy-services.sh, the upgrader and the push triggers; when there is none, a
                                     typed record_state with one plain sentence, SAT-48) merged with what Cloud Run actually runs (digest cross-check:
                                     a component whose running image is not the recorded one is "not from a recorded
                                     deploy"), mixed versions, this Control Center's own release.json, and the platform
                                     Terraform line (FD-4DA-STAMP; SELFUP-STAMP-RETIRE: no stamp = "unknown", fail
                                     closed). When a stamp exists and differs from the services' release:
                                     "Platform update pending: run upgrade.sh" (platform older) or "Services are
                                     behind the platform: redeploy the services" (platform newer).
GET /api/settings/platform-updates   (ADMIN) the newest release from the release source (GitHub, unauthenticated,
                                     cached 1 h, failures never cached) with its release-manifest.json and the apply.sh
                                     guard for display. Discovery is display only: nothing read from GitHub is trusted.
                                     "Repository not found" (HTTP 404: not published yet, or private) and "no release
                                     yet" are plain typed states (REPOSITORY_NOT_FOUND / NO_RELEASES), cached like OK.
GET /api/settings/release-source     (ADMIN) where upgrades come from + the banner level.
PUT /api/settings/release-source     (ADMIN, human, sign-in younger than 15 minutes, typed confirmation) stored in the
                                     guard database with a never-trimmed change record in the same batch.
PUT /api/settings/update-check       (ADMIN, human; no recent sign-in, no typed confirmation) the "Check for updates"
                                     switch (P3a-OFF, plan §3.12): one more field of the release source document, same
                                     batch, change record and optimistic version. Off: platform-updates answers
                                     UPDATE_CHECK_OFF and upstream-sync answers the commands, both without any GitHub
                                     call (and without touching the updates cache).
GET /api/settings/upstream-sync      (ADMIN) the weekly upstream-sync switch (FD-4BF, repository variable
                                     STACKVEND_UPSTREAM_SYNC; default off).
PUT /api/settings/upstream-sync      (ADMIN, human) sets the repository variable through the GitHub API when the Control
                                     Center's GitHub token may; otherwise answers the exact `gh variable set` command.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Request
from pydantic import BaseModel, StrictBool, StrictInt

import authz
import recent_sign_in
import release_info
import release_source as rsrc
from authz import ADMIN, require
from config import PROJECT_ID, DynamicHTTPException as HTTPException, apply_where
from db import get_db, get_guard_db
from schemas import UserRole
from shared import release_manifest as rm

logger = logging.getLogger("control-center-platform-release")
router = APIRouter(tags=["Settings"])

# The terminal path for installs behind Identity-Aware Proxy (owner, 11-01): same validation, confirmation and records.
CLI_COMMAND = "PROJECT_ID=<project> python3 scripts/release-source.py set --repository <owner>/<repo> --official-key"
RECENT_SIGN_IN_SECONDS = recent_sign_in.RECENT_SIGN_IN_SECONDS  # OQ-12c Q2 (one rule: recent_sign_in.py)
UPDATES_CACHE_SECONDS = 3600
GITHUB_API = "https://api.github.com"
GITHUB_TIMEOUT = 8.0
MAX_NOTES = 4000
SYNC_VARIABLE = "STACKVEND_UPSTREAM_SYNC"
SYNC_REPO_VARIABLE = "STACKVEND_UPSTREAM_REPO"
SYNC_DOC = ("governance", "upstream_sync")

# ------------------------------------------------------------------------------------------------ test seams
# None = the real implementation. Each returns (status, body) / (status, body, headers) and never makes up a value.
cloud_run_get_json: Optional[Callable[[str], Tuple[int, Any]]] = None
github_request: Optional[Callable[..., Tuple[int, Any]]] = None
github_token_provider: Optional[Callable[[], str]] = None
region_provider: Optional[Callable[[], str]] = None
guard_db_provider: Optional[Callable[[], Any]] = None
clock: Callable[[], float] = time.time

_updates_cache: Dict[Tuple, Tuple[float, Dict[str, Any]]] = {}
_cache_lock = threading.Lock()


def _project() -> str:
    return (PROJECT_ID or os.getenv("PROJECT_ID", "") or os.getenv("GOOGLE_CLOUD_PROJECT", "")).strip()


def _require_admin(request: Request, write: bool = False) -> str:
    """The Settings pattern: require(ADMIN) on the route + an explicit role re-check; writes also need a human
    principal (never a service account)."""
    if getattr(request.state, "user_role", None) != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Forbidden: Admin role required.")
    if write and authz.principal_type(request) != authz.PRINCIPAL_USER:
        raise HTTPException(status_code=403, detail={"code": "HUMAN_ADMIN_REQUIRED",
                                                     "message": "Only a signed-in administrator can change this."})
    return str(getattr(request.state, "user_email", "") or "")


def _require_recent_sign_in(request: Request) -> None:
    """A sign-in younger than 15 minutes (plan §4.4). Only the session cookie carries a sign-in time. Behind
    Identity-Aware Proxy the Control Center cannot see when the administrator signed in, so the change is refused
    (fail closed; open owner question in the SAT-11 report)."""
    refusal = recent_sign_in.sign_in_refusal(request, clock())
    if refusal is None:
        return
    if refusal == recent_sign_in.RECENT_SIGN_IN_REQUIRED:
        raise HTTPException(status_code=403, detail={
            "code": "RECENT_SIGN_IN_REQUIRED",
            "message": "Sign out and sign in again (a sign-in younger than 15 minutes is needed), then retry."})
    raise HTTPException(status_code=403, detail={
        "code": "RECENT_SIGN_IN_UNAVAILABLE", "command": CLI_COMMAND,
        "message": ("This Control Center cannot confirm a recent sign-in (Identity-Aware Proxy does not pass the "
                    "sign-in time), so the release source cannot be changed from the browser on this install. "
                    f"Change it from a terminal with your own Google credentials instead: {CLI_COMMAND}")})


# ------------------------------------------------------------------------------------------------ Cloud Run reads
def _region() -> str:
    if region_provider is not None:
        return region_provider()
    env = (os.getenv("REGION") or "").strip()
    if env:
        return env
    try:
        import requests as _requests
        region_path = _requests.get("http://metadata.google.internal/computeMetadata/v1/instance/region",
                                    headers={"Metadata-Flavor": "Google"}, timeout=2).text.strip()
        return region_path.rsplit("/", 1)[-1]
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Could not read this instance's region: {e}")
        return ""


def _run_get_json() -> Callable[[str], Tuple[int, Any]]:
    if cloud_run_get_json is not None:
        return cloud_run_get_json
    import google.auth
    from google.auth.transport.requests import AuthorizedSession
    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    session = AuthorizedSession(credentials)

    def get(url: str) -> Tuple[int, Any]:
        resp = session.get(url, timeout=10.0)
        try:
            return resp.status_code, resp.json()
        except ValueError:
            return resp.status_code, None
    return get


def _read_live(project: str, region: str) -> Dict[str, Dict[str, Any]]:
    try:
        get = _run_get_json()
    except Exception as e:  # noqa: BLE001
        return {n: {"error": "READ_FAILED", "detail": f"no credentials: {type(e).__name__}"} for n, _, _ in rm.COMPONENTS}

    def one(item):
        name, kind, _ = item
        try:
            return name, rm.read_component(get, project, region, name, kind)
        except rm.ComponentReadError as e:
            return name, {"error": e.code, "detail": e.detail}
    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(pool.map(one, rm.COMPONENTS))


def _read_record() -> Tuple[Optional[Dict[str, Any]], str]:
    """The deployed version record `system_config/platform_release` in the (default) database. DISPLAY ONLY: every
    agent service account with project-wide datastore.user (including tf-applier's identity) can write it, so it is
    shown only where the running digest matches and must never be used as the installed version for an upgrade
    decision (review L2; P3b reads that from the guard database or the image's own release.json)."""
    db = get_db()
    if not db:
        return None, "Firestore unavailable"
    try:
        snap = db.collection(rm.RECORD_COLLECTION).document(rm.RECORD_DOCUMENT).get()
    except Exception as e:  # noqa: BLE001
        return None, f"could not read the version record: {type(e).__name__}"
    if not getattr(snap, "exists", False):
        return None, ""
    data = snap.to_dict()
    if not isinstance(data, dict) or not isinstance(data.get("components", {}), dict):
        return None, "the version record has an unexpected shape"
    return data, ""


# ------------------------------------------------------------------------------------------------ version view (pure)
PENDING_TEXT = "Platform update pending: run upgrade.sh"  # the platform Terraform is older than the services
SERVICES_BEHIND_TEXT = "Services are behind the platform: redeploy the services (scripts/deploy-services.sh --all-jobs)"


def pending_direction(platform_release: Optional[str], services_release: Optional[str]) -> Tuple[str, str]:
    """Which side is behind when the platform stamp and the services' release differ: (direction, text).
    PLATFORM_BEHIND -> run upgrade.sh; SERVICES_BEHIND -> redeploy the services. DIFFERENT when the two cannot be ordered (never a guessed direction)."""
    pv, sv = rm.parse_semver(platform_release), rm.parse_semver(services_release)
    if pv is None or sv is None or rm.compare(pv, sv) == 0:
        return "DIFFERENT", (f"Platform ({platform_release}) and services ({services_release}) releases differ: "
                             "check which one was deployed last")
    return ("PLATFORM_BEHIND", PENDING_TEXT) if rm.compare(pv, sv) < 0 else ("SERVICES_BEHIND", SERVICES_BEHIND_TEXT)


# SAT-48: why there is no version record, as a typed state with one plain sentence (never a bare "unknown"). Decided
# only from this Control Center's own release.json (typed fields): its `builder`, or that it has none.
RECORD_STATE_RECORDED = "RECORDED"
RECORD_STATE_UNREADABLE = "UNREADABLE"            # the record exists but could not be read (record_error says why)
RECORD_STATE_NONE_UNSTAMPED = "NONE_UNSTAMPED"     # this build has no release.json: built without a version stamp
RECORD_STATE_NONE = "NONE"                         # stamped by deploy-services / the upgrader, but nothing recorded
RECORD_NOTES = {
    RECORD_STATE_NONE_UNSTAMPED: (
        "No deploy has been recorded yet, and this Control Center image carries no version stamp. Deploys from before "
        "version records have none. Each component shows its release here after its next recorded deploy "
        "(a scripts/deploy-services.sh run or an Update StackVend run)."),
    RECORD_STATE_NONE: (
        "No deploy has been recorded yet: components show \"unknown\" until the next recorded deploy "
        "(scripts/deploy-services.sh). If a deploy just ran, its output has a version record warning that says why."),
}


def record_state(record: Optional[Dict[str, Any]], record_error: str, own_release: Dict[str, Any]) -> Tuple[str, str]:
    """(state, plain note) for the version record (SAT-48)."""
    if record is not None:
        return RECORD_STATE_RECORDED, ""
    if record_error:
        return RECORD_STATE_UNREADABLE, ""
    if own_release.get("release") == "unknown":
        state = RECORD_STATE_NONE_UNSTAMPED
    else:
        state = RECORD_STATE_NONE
    return state, RECORD_NOTES[state]


def services_text(pairs: Dict[Tuple[str, str], List[str]], record: Optional[Dict[str, Any]]) -> str:
    """The "Services and jobs" line. One (release, commit): the release. One release from several commits (one
    service redeployed from a later commit): that release, with the commit count."""
    if len(pairs) == 1:
        return next(iter(pairs))[0]
    releases = {r for r, _ in pairs}
    if len(releases) == 1:
        return f"{next(iter(releases))} (components from {len(pairs)} commits)"
    if pairs:
        return "mixed"
    return "not recorded yet" if record is None else "unknown"


def control_center_build_text(own_release: Dict[str, Any]) -> str:
    release = own_release.get("release") or "unknown"
    if release == "unknown":
        return f"unknown ({own_release.get('reason') or 'no version stamp'})"
    commit = own_release.get("commit")
    text = release + (f" ({commit[:12]})" if isinstance(commit, str) and commit and commit != "unknown" else "")
    return text + (" +dirty" if own_release.get("dirty") is True else "")


def build_version_view(record: Optional[Dict[str, Any]], record_error: str, live: Dict[str, Dict[str, Any]],
                       own_release: Dict[str, Any]) -> Dict[str, Any]:
    recorded = (record or {}).get("components") or {}
    components, pairs, unknown = [], {}, []
    for name, kind, _ in rm.COMPONENTS:
        lv = live.get(name) or {"error": "READ_FAILED", "detail": "not read"}
        row: Dict[str, Any] = {"name": name, "kind": kind}
        rec = recorded.get(name) if isinstance(recorded.get(name), dict) else None
        if lv.get("error") == "NOT_DEPLOYED":
            row.update(state="NOT_DEPLOYED", text="not deployed on this install")
        elif lv.get("error"):
            row.update(state="UNREADABLE", text=f"could not read from Cloud Run ({lv['error']})", detail=lv.get("detail"))
            unknown.append(name)
        elif lv.get("image_tag"):
            # Deployed by tag (the Cloud Build triggers deploy jobs this way): the image is mutable, so it is never
            # compared with the record and never shown as a recorded release (review M4). Not an error.
            row.update(state="IMAGE_BY_TAG", text=f"deployed by tag — digest not verifiable ({lv['image_tag']})",
                       image_tag=lv["image_tag"], revision=lv.get("revision", ""))
            unknown.append(name)
        elif record is None:
            row.update(state="NO_RECORD", text="unknown (no recorded deploy yet)",
                       image_digest=lv["image_digest"], revision=lv.get("revision", ""))
            unknown.append(name)
        elif rec is None or rec.get("image_digest") != lv["image_digest"]:
            row.update(state="NOT_RECORDED", text="unknown (not from a recorded deploy)",
                       image_digest=lv["image_digest"], revision=lv.get("revision", ""))
            unknown.append(name)
        else:
            row.update(state="RECORDED", release=rec.get("release"), commit=rec.get("commit"), dirty=rec.get("dirty"),
                       source_repo=rec.get("source_repo"), deployed_at=rec.get("deployed_at"),
                       image_digest=lv["image_digest"], revision=lv.get("revision", ""))
            key = (str(rec.get("release")), str(rec.get("commit")))
            pairs.setdefault(key, []).append(name)
        components.append(row)
    mixed = len(pairs) > 1
    services_release = next(iter(pairs))[0] if len(pairs) == 1 else None
    groups = [{"release": r, "commit": c, "components": sorted(n)} for (r, c), n in sorted(pairs.items())]

    cc_live = live.get(rm.CONTROL_CENTER_SERVICE) or {}
    if cc_live.get("error"):
        platform = {"state": "UNKNOWN", "release": None, "commit": None, "assumed": False, "dirty": False,
                    "text": "unknown (could not read the Control Center service)"}
        stamp = None
    else:
        stamp = rm.stamp_from_annotations(cc_live.get("annotations") or {})
        installed = rm.parse_semver(services_release) if services_release else None
        platform_ver, _assumed, error = rm.platform_release_for(stamp, installed)
        if platform_ver is None:
            platform = {"state": "UNKNOWN", "release": None, "commit": stamp.commit, "assumed": False,
                        "dirty": stamp.dirty, "text": f"unknown ({error})", "apply_where": apply_where(_project())}
        else:
            platform = {"state": "STAMPED", "release": str(platform_ver), "commit": stamp.commit, "assumed": False,
                        "dirty": stamp.dirty, "text": f"{platform_ver}" + (f" ({stamp.commit[:12]})" if stamp.commit else "")}
    pending = bool(stamp is not None and stamp.present and platform.get("state") == "STAMPED" and services_release
                   and services_release != platform["release"])
    direction, pending_text = pending_direction(platform["release"], services_release) if pending else ("", "")
    rec_meta = {k: (record or {}).get(k) for k in ("release", "commit", "dirty", "source_repo", "deployed_at",
                                                   "deployed_by", "deployer", "run_id")}
    history = [h for h in ((record or {}).get("history") or []) if isinstance(h, dict)][:rm.HISTORY_LIMIT]
    state, note = record_state(record, record_error, own_release)
    return {
        "components": components,
        "groups": groups,
        "mixed": mixed,
        "unknown": unknown,
        "services_release": services_release,
        "services_text": services_text(pairs, record),
        "control_center_build": own_release,
        "control_center_build_text": control_center_build_text(own_release),
        "record_state": state,
        "record_note": note,
        "platform": platform,
        "platform_update_pending": pending,
        "pending_direction": direction,
        "pending_text": pending_text,
        "record": rec_meta if record is not None else None,
        "record_error": record_error,
        "history": history,
    }


@router.get("/api/settings/platform-version", dependencies=[require(ADMIN)])
def get_platform_version(request: Request):
    _require_admin(request)
    project, region = _project(), _region()
    if not project or not region:
        raise HTTPException(status_code=503, detail={"code": "PROJECT_OR_REGION_UNKNOWN",
                                                     "message": "PROJECT_ID or this instance's region is not known."})
    record, record_error = _read_record()
    live = _read_live(project, region)
    return build_version_view(record, record_error, live, release_info.current_release())


# ------------------------------------------------------------------------------------------------ release source
def _guard_db():
    gdb = guard_db_provider() if guard_db_provider is not None else get_guard_db()
    if not gdb:
        raise HTTPException(status_code=503, detail={"code": "GUARD_DATABASE_UNAVAILABLE",
                                                     "message": "The guard database cannot be opened."})
    return gdb


def _source_ref(gdb):
    return gdb.collection(rsrc.COLLECTION).document(rsrc.DOCUMENT)


def _load_source(gdb) -> Tuple[Optional[rsrc.ReleaseSource], Any, Optional[Dict[str, Any]], Optional[rsrc.SourceError]]:
    """(source or None when nothing is stored, snapshot, stored doc, error when the stored doc is invalid)."""
    try:
        snap = _source_ref(gdb).get()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail={"code": "GUARD_DATABASE_UNAVAILABLE",
                                                     "message": f"Could not read the release source: {type(e).__name__}"})
    if not getattr(snap, "exists", False):
        return None, snap, None, None
    doc = snap.to_dict()
    try:
        return rsrc.read_stored(doc), snap, doc, None
    except rsrc.SourceError as e:
        return None, snap, doc if isinstance(doc, dict) else None, e


def _source_view(src: Optional[rsrc.ReleaseSource], doc: Optional[Dict[str, Any]],
                 error: Optional[rsrc.SourceError]) -> Dict[str, Any]:
    if error is not None:
        return {"valid": False, "error": error.detail(), "stored": doc is not None,
                "line": "Release source invalid: an administrator must save a valid one. Upgrade checks are off.",
                "level": "INVALID", "update_check": False, "version": (doc or {}).get("version") if isinstance((doc or {}).get("version"), int) else 0}
    effective = src or rsrc.default_source()
    return {
        "valid": True, "stored": src is not None, "is_default": effective.is_default, "level": effective.level,
        "line": effective.describe(), "repository": effective.repository, "follow": effective.follow,
        "branch": effective.branch, "allow_unsigned": effective.allow_unsigned,
        "signers": [dict(s) for s in effective.signers], "include_previews": effective.include_previews,
        "update_check": effective.update_check, "update_check_line": effective.describe_update_check(),
        "fingerprint": effective.fingerprint, "official_repository": rm.OFFICIAL_RELEASE_REPOSITORY,
        "version": (doc or {}).get("version", 0), "updated_by": (doc or {}).get("updated_by"),
        "updated_at": (doc or {}).get("updated_at"),
    }


@router.get("/api/settings/release-source", dependencies=[require(ADMIN)])
def get_release_source(request: Request):
    _require_admin(request)
    src, _snap, doc, error = _load_source(_guard_db())
    return _source_view(src, doc, error)


class ReleaseSourceRequest(BaseModel):
    repository: str
    follow: str = rsrc.FOLLOW_TAGS
    branch: str = ""
    allow_unsigned: bool = False
    include_previews: bool = rsrc.DEFAULT_INCLUDE_PREVIEWS
    signers: List[Dict[str, Any]]
    expected_version: int
    confirm_repository: str = ""
    confirm_key_suffixes: List[str] = []


def _replace_fields(stored: Dict[str, Any], doc: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The `update` payload that makes the stored document exactly `stored`: every key of the old document that is not
    in `stored` is deleted (DELETE_FIELD, quoted as a field path so a key with a `.` names itself). A valid stored
    document has exactly the model's keys, so for it this is `stored` unchanged."""
    extra = [k for k in (doc or {}) if k not in stored]
    if not extra:
        return dict(stored)
    from google.cloud.firestore_v1 import DELETE_FIELD
    from google.cloud.firestore_v1.field_path import FieldPath
    return {**stored, **{FieldPath(k).to_api_repr(): DELETE_FIELD for k in extra}}


def _verify_saved(gdb) -> None:
    """Read the saved document back: a save is reported only when the next GET shows a valid source (never a 200
    `changed: true` while the stored document is still invalid; review M1)."""
    try:
        _src, _snap, _doc, error = _load_source(gdb)
    except HTTPException as e:
        raise HTTPException(status_code=500, detail={
            "code": "RELEASE_SOURCE_NOT_VERIFIED",
            "message": "The release source was saved but could not be read back; reload to see what is stored."}) from e
    if error is not None:
        logger.error(f"release source still invalid after save: {error.detail()}")
        raise HTTPException(status_code=500, detail={
            "code": "RELEASE_SOURCE_STILL_INVALID", "error": error.detail(),
            "message": "The release source was written but is still invalid; reload and save it again."})


@router.put("/api/settings/release-source", dependencies=[require(ADMIN)])
def put_release_source(req: ReleaseSourceRequest, request: Request):
    email = _require_admin(request, write=True)
    _require_recent_sign_in(request)
    gdb = _guard_db()
    from routes import platform_upgrade  # lazy: platform_upgrade imports this module
    platform_upgrade.refuse_while_upgrading(gdb)  # SELFUP P3b: no source change while an upgrade holds the lease
    current, snap, doc, error = _load_source(gdb)
    stored_version = (doc or {}).get("version") if isinstance((doc or {}).get("version"), int) else 0
    if req.expected_version != stored_version:
        raise HTTPException(status_code=409, detail={
            "code": "RELEASE_SOURCE_CHANGED", "stored_version": stored_version,
            "message": "The release source was changed by someone else. Nothing was saved; reload and retry."})
    now_iso = datetime.now(timezone.utc).isoformat()
    try:  # the same plan as scripts/release-source.py (one validation, one record shape)
        plan = rsrc.plan_change(req.model_dump(include=set(rsrc.REQUEST_FIELDS)), current, error, stored_version,
                                email, now_iso, req.confirm_repository, req.confirm_key_suffixes,
                                rsrc.VIA_CONTROL_CENTER)
    except rsrc.SourceError as e:
        raise HTTPException(status_code=422, detail=e.detail())
    if plan is None:
        return {**_source_view(current, doc, None), "changed": False}
    _commit_plan(gdb, snap, doc, plan, email, rsrc.VIA_CONTROL_CENTER)
    return {**_source_view(plan.new, plan.stored, None), "changed": True}


def _commit_plan(gdb, snap, doc: Optional[Dict[str, Any]], plan: rsrc.PlannedChange, email: str, via: str) -> None:
    """Write one planned change (both routes): the setting and its never-trimmed change record in one batch, the
    structured log line, the updates cache cleared, then the read-back check."""
    new, stored, change, version = plan.new, plan.stored, plan.change, plan.version
    ref = _source_ref(gdb)
    try:
        batch = gdb.batch()  # the setting and its never-trimmed change record land together or not at all
        batch.set(ref.collection(rsrc.CHANGES).document(uuid.uuid4().hex), change)
        if getattr(snap, "exists", False):
            # `update` merges fields: a stored key outside the model (one that made the stored document invalid,
            # `release_source.read_stored`) would survive the save. Remove every such key in the same write (review M1).
            batch.update(ref, _replace_fields(stored, doc), option=gdb.write_option(last_update_time=snap.update_time))
        else:
            batch.create(ref, stored)
        batch.commit()
    except Exception as e:  # noqa: BLE001
        logger.error(f"release source save failed: {e}")
        raise HTTPException(status_code=409, detail={
            "code": "RELEASE_SOURCE_NOT_SAVED",
            "message": f"The release source was not saved ({type(e).__name__}); it may have changed meanwhile. "
                       "Reload and retry."})
    logger.warning(json.dumps({"event": "stackvend.release_source_changed", "by": email, "via": via,
                               "from_fingerprint": change["from"].get("fingerprint"), "to_fingerprint": new.fingerprint,
                               "to_repository": new.repository, "to_follow": new.follow,
                               "to_allow_unsigned": new.allow_unsigned, "to_update_check": new.update_check,
                               "version": version}, sort_keys=True))
    with _cache_lock:
        _updates_cache.clear()  # the next check lists the new repository's releases
    _verify_saved(gdb)  # after the log line and cache clear: the write happened even when this refuses


class UpdateCheckRequest(BaseModel):
    enabled: StrictBool
    expected_version: StrictInt


@router.put("/api/settings/update-check", dependencies=[require(ADMIN)])
def put_update_check(req: UpdateCheckRequest, request: Request):
    """The "Check for updates" switch (P3a-OFF, plan §3.12). ADMIN + human principal; no recent sign-in and no typed
    confirmation in either direction (off reduces exposure; on re-enables an unauthenticated read of the configured
    repository's public data and installs nothing), so it also works behind Identity-Aware Proxy. Every other field of
    the release source is kept; the same batch, change record and log line as a release-source save."""
    email = _require_admin(request, write=True)
    gdb = _guard_db()
    from routes import platform_upgrade  # lazy: platform_upgrade imports this module
    platform_upgrade.refuse_while_upgrading(gdb)  # SELFUP P3b RT L-5: like the release source (plan §3.10.5)
    current, snap, doc, error = _load_source(gdb)
    stored_version = (doc or {}).get("version") if isinstance((doc or {}).get("version"), int) else 0
    if req.expected_version != stored_version:
        raise HTTPException(status_code=409, detail={
            "code": "RELEASE_SOURCE_CHANGED", "stored_version": stored_version,
            "message": "The release source was changed by someone else. Nothing was saved; reload and retry."})
    if error is not None:
        raise HTTPException(status_code=409, detail={
            "code": "RELEASE_SOURCE_INVALID", "error": error.detail(),
            "message": "The stored release source is invalid (update checks are already off). Save a valid release "
                       "source first."})
    effective = current or rsrc.default_source()
    if effective.update_check is req.enabled:  # already so: nothing is written, no change record
        return {**_source_view(current, doc, None), "changed": False}
    try:
        plan = rsrc.plan_change(rsrc.update_check_request(effective, req.enabled), current, None, stored_version,
                                email, datetime.now(timezone.utc).isoformat(), "", [],
                                rsrc.VIA_CONTROL_CENTER)
    except rsrc.SourceError as e:
        raise HTTPException(status_code=422, detail=e.detail())
    if plan is None:
        return {**_source_view(current, doc, None), "changed": False}
    _commit_plan(gdb, snap, doc, plan, email, rsrc.VIA_CONTROL_CENTER)
    return {**_source_view(plan.new, plan.stored, None), "changed": True}


# ------------------------------------------------------------------------------------------------ updates check
def _github(method: str, path: str, token: str = "", body: Optional[Dict[str, Any]] = None,
            accept: str = "application/vnd.github+json") -> Tuple[int, Any]:
    if github_request is not None:
        return github_request(method, path, token=token, body=body, accept=accept)
    headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "StackVend-ControlCenter"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(GITHUB_API + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=GITHUB_TIMEOUT) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    if accept.endswith("raw+json") and status == 200:
        return status, raw
    try:
        return status, json.loads(raw.decode("utf-8")) if raw else None
    except ValueError:
        return status, None


def _could_not_check(code: str, message: str) -> Dict[str, Any]:
    return {"status": "COULD_NOT_CHECK", "error_code": code, "message": message}


def _github_failure(status: int, what: str) -> Dict[str, Any]:
    """A check that failed (amber "Could not check", never cached). HTTP 404 is not a failure: see _not_found."""
    if status == 403 or status == 429:
        return _could_not_check("GITHUB_RATE_LIMITED", f"GitHub refused {what} (HTTP {status}, rate limit); try later.")
    return _could_not_check("GITHUB_ERROR", f"{what}: HTTP {status}.")


# Plain states, not errors (owner 11-02; review §4): before the public release the official repository does not exist,
# so every install sees one of these. Cached for the hour like OK (`force` bypasses), shown grey.
REPOSITORY_NOT_FOUND = "REPOSITORY_NOT_FOUND"
NO_RELEASES = "NO_RELEASES"
CACHED_STATUSES = ("OK", REPOSITORY_NOT_FOUND, NO_RELEASES)
TRANSIENT_MANIFEST_ERRORS = ("GITHUB_ERROR", "GITHUB_UNREACHABLE")  # MANIFEST_MISSING / _UNSUPPORTED etc. are stable


def _not_found(src: rsrc.ReleaseSource) -> Dict[str, Any]:
    """GitHub answered HTTP 404 for the repository (unauthenticated: it does not exist yet, or it is private)."""
    message = (f"The release repository {src.repository} is not published yet, or it is private. Updates are "
               "manual until it is published; Settings checks again every hour.")
    return {"status": REPOSITORY_NOT_FOUND, "repository": src.repository, "update_available": False,
            "steps": manual_steps("<tag>"), "message": message}


UPDATE_CHECK_OFF_MESSAGE = ("Update check is off: this Control Center makes no GitHub call from Settings ▸ Upgrades. "
                            "Updates are manual on this install: run scripts/upgrade.sh <tag> from the checkout you "
                            "installed from (it verifies the signed tag, then applies the platform Terraform and deploys "
                            "the services). Release notes: CHANGELOG.md in the release.")


def manual_steps(tag: str) -> List[str]:
    """The terminal path (plan §3.4.4; review H-5), typed fields only: scripts/upgrade.sh, which verifies the tag's
    signature with the installed checkout's trusted keys, then runs apply.sh plan / apply and deploy-services.sh. One
    line only: a services-only `deploy-services.sh` alternative would skip the signature check, and it would be chosen
    by a manifest read from GitHub, which is display-only (code review M-1; reconsidered with P3b)."""
    return [f"PROJECT_ID=<project> bash scripts/upgrade.sh {tag}"]


def check_tags(src: rsrc.ReleaseSource, installed: Optional[str], stamp: Optional[rm.PlatformStamp]) -> Dict[str, Any]:
    try:
        status, body = _github("GET", f"/repos/{src.repository}/releases?per_page=50")
    except Exception as e:  # noqa: BLE001
        return _could_not_check("GITHUB_UNREACHABLE", f"GitHub could not be reached ({type(e).__name__}).")
    if status == 404:
        return _not_found(src)
    if status != 200 or not isinstance(body, list):
        return _github_failure(status, f"the releases of {src.repository}") if status != 200 else \
            _could_not_check("GITHUB_BAD_RESPONSE", "GitHub answered without a release list.")
    candidates, hidden_previews = [], 0
    for rel in body:
        if not isinstance(rel, dict) or rel.get("draft") is True:
            continue
        ver = rm.parse_release_tag(rel.get("tag_name"))
        if ver is None:
            continue
        preview = ver.is_prerelease or rel.get("prerelease") is True
        if preview and not src.include_previews:
            hidden_previews += 1
            continue
        candidates.append((ver, preview, rel))
    if not candidates:
        return {"status": NO_RELEASES, "repository": src.repository, "latest": None, "update_available": False,
                "steps": manual_steps("<tag>"),
                "message": f"{src.repository} has no release yet."
                           + (" (Preview releases are hidden by the release source setting.)" if hidden_previews else "")}
    ver, preview, rel = max(candidates, key=lambda c: c[0].key())
    url = rel.get("html_url") if isinstance(rel.get("html_url"), str) and rel["html_url"].startswith(
        "https://github.com/") else ""
    notes = rel.get("body") if isinstance(rel.get("body"), str) else ""
    latest = {"tag": f"v{ver}", "release": str(ver), "prerelease": preview, "url": url,
              "published_at": rel.get("published_at") if isinstance(rel.get("published_at"), str) else None,
              "notes": notes[:MAX_NOTES], "notes_truncated": len(notes) > MAX_NOTES}
    inst = rm.parse_semver(installed) if installed else None
    out: Dict[str, Any] = {"status": "OK", "latest": latest, "installed": installed,
                           "update_available": inst is None or rm.compare(ver, inst) > 0}
    try:
        mstatus, mbody = _github("GET", f"/repos/{src.repository}/contents/{rm.MANIFEST_FILE}?ref="
                                 + urllib.parse.quote(latest["tag"], safe=""), accept="application/vnd.github.raw+json")
    except Exception as e:  # noqa: BLE001
        mstatus, mbody = 0, None
        out["manifest_error"] = {"code": "GITHUB_UNREACHABLE", "message": type(e).__name__}
    if mstatus == 200:
        try:
            manifest = rm.parse_manifest(mbody)
        except rm.ManifestError as e:
            out["manifest_error"] = {"code": e.code, "message": e.detail}
        else:
            out["manifest"] = {"release": str(manifest.release), "requires_apply_sh": manifest.requires_apply_sh,
                               "min_platform_release": str(manifest.min_platform_release)}
            if stamp is not None:
                g = rm.guard_decision(stamp, manifest, inst)
                out["guard"] = {"decision": g.decision, "platform_release": g.platform_release, "assumed": g.assumed,
                                "warnings": list(g.warnings)}
    elif "manifest_error" not in out:
        out["manifest_error"] = {"code": "MANIFEST_MISSING" if mstatus == 404 else "GITHUB_ERROR",
                                 "message": f"{rm.MANIFEST_FILE} at {latest['tag']}: HTTP {mstatus}"}
    out["steps"] = manual_steps(latest["tag"])
    return out


@router.get("/api/settings/platform-updates", dependencies=[require(ADMIN)])
def get_platform_updates(request: Request, force: bool = False):
    _require_admin(request)
    src, _snap, doc, error = _load_source(_guard_db())
    source_view = _source_view(src, doc, error)
    if error is not None:
        return {"source": source_view, "status": "SOURCE_INVALID", "error_code": "RELEASE_SOURCE_INVALID",
                "message": "The release source is invalid; no update check is made until an administrator saves a valid one."}
    effective = src or rsrc.default_source()
    project, region = _project(), _region()
    live = _read_live(project, region) if project and region else {}
    record, _err = _read_record()
    view = build_version_view(record, "", live, release_info.current_release())
    if not effective.update_check:
        # P3a-OFF: no GitHub call and no cache read or write; the manual path instead (plan §3.12).
        return {"source": source_view, "platform": view["platform"], "status": "UPDATE_CHECK_OFF",
                "update_available": False, "message": UPDATE_CHECK_OFF_MESSAGE,
                "manual_steps": manual_steps("<tag>"),
                "changed_by": (doc or {}).get("updated_by"), "changed_at": (doc or {}).get("updated_at")}
    installed = view["services_release"] or (release_info.current_release().get("release")
                                             if release_info.current_release().get("release") != "unknown" else None)
    cc_live = live.get(rm.CONTROL_CENTER_SERVICE) or {"error": "READ_FAILED"}
    stamp = None if cc_live.get("error") else rm.stamp_from_annotations(cc_live.get("annotations") or {})
    key = (effective.fingerprint, effective.include_previews, installed, stamp)
    now = clock()
    with _cache_lock:
        hit = _updates_cache.get(key)
    if hit and not force and now - hit[0] < UPDATES_CACHE_SECONDS:
        result = hit[1]
    else:
        result = check_tags(effective, installed, stamp)
        result = {**result, "checked_at": datetime.fromtimestamp(now, timezone.utc).isoformat()}
        # Stable states are cached; failures never are (review L-1). An OK whose manifest read failed transiently is
        # not cached either, so `requires apply.sh` and the guard come back on the next look (code review L-4).
        manifest_failed = (result.get("manifest_error") or {}).get("code") in TRANSIENT_MANIFEST_ERRORS
        if result.get("status") in CACHED_STATUSES and not manifest_failed:
            with _cache_lock:
                _updates_cache[key] = (now, result)
    return {"source": source_view, "platform": view["platform"], **result}


# ------------------------------------------------------------------------------------------------ upstream sync toggle
def _platform_repository() -> str:
    raw = (os.getenv("GITHUB_REPO") or "").strip()
    if "/" not in raw and raw:
        owner = (os.getenv("GITHUB_OWNER") or "").strip()
        raw = f"{owner}/{raw}" if owner else ""
    return raw if rm.is_valid_repository(raw) else ""


def _sync_commands(repo: str, enabled: bool) -> List[str]:
    target = repo or "<owner>/<repo>"
    cmds = [f"gh variable set {SYNC_VARIABLE} --body {'true' if enabled else 'false'} --repo {target}"]
    if enabled:
        cmds.append(f"gh variable set {SYNC_REPO_VARIABLE} --body {rm.OFFICIAL_RELEASE_REPOSITORY} --repo {target}")
    return cmds


def _github_token() -> str:
    if github_token_provider is not None:
        return github_token_provider()
    try:
        from routes import settings as settings_routes
        return settings_routes.get_github_token(project_id=_project()) or ""
    except Exception as e:  # noqa: BLE001 - no token: the page shows the command instead
        logger.warning(f"No GitHub token for the upstream-sync switch: {type(e).__name__}")
        return ""


def _read_variable(repo: str, name: str, token: str) -> Tuple[Optional[str], str]:
    """(value or None when unset, error code or "")."""
    try:
        status, body = _github("GET", f"/repos/{repo}/actions/variables/{name}", token=token)
    except Exception as e:  # noqa: BLE001
        return None, f"GITHUB_UNREACHABLE ({type(e).__name__})"
    if status == 200 and isinstance(body, dict) and isinstance(body.get("value"), str):
        return body["value"], ""
    if status == 404:
        return None, ""
    return None, f"HTTP_{status}"


def _sync_record() -> Dict[str, Any]:
    db = get_db()
    if not db:
        return {}
    try:
        snap = db.collection(SYNC_DOC[0]).document(SYNC_DOC[1]).get()
        return (snap.to_dict() or {}) if getattr(snap, "exists", False) else {}
    except Exception as e:  # noqa: BLE001
        logger.warning(f"could not read {SYNC_DOC}: {e}")
        return {}


def _github_calls_off() -> Tuple[str, str]:
    """(state, message) when the Control Center must make no GitHub call for the upstream-sync variables (review M-5):
    the update check is off, or the stored release source is invalid (then the switch's value is unknown: fail
    closed). ("", "") when calls are allowed. An unreadable guard database is a 503 (GUARD_DATABASE_UNAVAILABLE)."""
    src, _snap, _doc, error = _load_source(_guard_db())
    if error is not None:
        return "SOURCE_INVALID", ("The release source is invalid, so this Control Center makes no GitHub call; "
                                  "use the command.")
    if not (src or rsrc.default_source()).update_check:
        return "UPDATE_CHECK_OFF", ("Update check is off, so this Control Center makes no GitHub call; "
                                    "use the command.")
    return "", ""


@router.get("/api/settings/upstream-sync", dependencies=[require(ADMIN)])
def get_upstream_sync(request: Request):
    _require_admin(request)
    repo = _platform_repository()
    off_state, off_message = _github_calls_off()
    token = _github_token() if repo and not off_state else ""
    out: Dict[str, Any] = {"repository": repo, "variable": SYNC_VARIABLE, "enabled": False, "state": "UNKNOWN",
                           "last_change": _sync_record().get("last_change")}
    if off_state:
        out.update(state=off_state, message=off_message)
    elif not repo:
        out.update(state="REPOSITORY_NOT_CONFIGURED",
                   message="GITHUB_REPO is not set on this Control Center; set the variable with the command.")
    elif not token:
        out.update(state="NO_TOKEN", message="The Control Center has no GitHub token; use the command.")
    else:
        value, err = _read_variable(repo, SYNC_VARIABLE, token)
        upstream, err2 = _read_variable(repo, SYNC_REPO_VARIABLE, token)
        if err:
            out.update(state="CANNOT_READ", message=f"Could not read the repository variable ({err}); use the command.")
        else:
            out.update(state="READ", enabled=value == "true", value=value, upstream_repository=upstream,
                       upstream_repository_set=bool(upstream) and rm.is_valid_repository(upstream))
            if err2:
                out["upstream_repository_error"] = err2
    out["commands"] = {"enable": _sync_commands(repo, True), "disable": _sync_commands(repo, False)}
    return out


class UpstreamSyncRequest(BaseModel):
    enabled: bool


def _sync_effective(repo: str, token: str) -> Tuple[bool, str, str]:
    """After STACKVEND_UPSTREAM_SYNC=true: will `.github/workflows/sync-upstream.yml` actually run? Its job gate also
    needs STACKVEND_UPSTREAM_REPO set to an owner/repo name other than this repository. (effective, code, message).

    The Control Center only reads that variable and never writes it: it is the sync's supply-chain pointer (which
    repository's releases are pulled into the platform repository), so setting it stays a terminal step for an
    operator with admin rights on the repository (the answer carries the exact command)."""
    upstream, err = _read_variable(repo, SYNC_REPO_VARIABLE, token)
    if err:
        return False, "UPSTREAM_REPO_UNREADABLE", (
            f"The switch is on, but {SYNC_REPO_VARIABLE} could not be read ({err}); the workflow skips every run "
            "unless it is set. Run the command.")
    if not upstream or not rm.is_valid_repository(upstream):
        return False, "UPSTREAM_REPO_NOT_SET", (
            f"The switch is on, but {SYNC_REPO_VARIABLE} is not set to an owner/repo name, so the workflow skips "
            "every run. Run the command.")
    if upstream == repo:
        return False, "UPSTREAM_REPO_IS_THIS_REPOSITORY", (
            f"The switch is on, but {SYNC_REPO_VARIABLE} names this repository, so the workflow skips every run. "
            "Run the command.")
    return True, "", ""


@router.put("/api/settings/upstream-sync", dependencies=[require(ADMIN)])
def put_upstream_sync(req: UpstreamSyncRequest, request: Request):
    email = _require_admin(request, write=True)
    repo = _platform_repository()
    commands = _sync_commands(repo, req.enabled)
    value = "true" if req.enabled else "false"
    off_state, off_message = _github_calls_off()
    token = _github_token() if repo and not off_state else ""
    applied, code, message = False, "", ""
    effective: Optional[bool] = None  # None until the switch is applied; then whether the workflow will run
    if off_state:  # no GitHub write (and no read): the answer is the command (review M-5)
        code, message = off_state, off_message
    elif not repo:
        code, message = "REPOSITORY_NOT_CONFIGURED", "GITHUB_REPO is not set on this Control Center: run the command."
    elif not token:
        code, message = "NO_TOKEN", "The Control Center has no GitHub token: run the command."
    else:
        current, err = _read_variable(repo, SYNC_VARIABLE, token)
        status = int(err[5:]) if err.startswith("HTTP_") and err[5:].isdigit() else 0
        if not err:
            try:
                if current is None:  # unset: create it
                    status, _ = _github("POST", f"/repos/{repo}/actions/variables", token=token,
                                        body={"name": SYNC_VARIABLE, "value": value})
                else:
                    status, _ = _github("PATCH", f"/repos/{repo}/actions/variables/{SYNC_VARIABLE}", token=token,
                                        body={"name": SYNC_VARIABLE, "value": value})
            except Exception as e:  # noqa: BLE001
                status, err = 0, f"GITHUB_UNREACHABLE ({type(e).__name__})"
        if status in (200, 201, 204):
            applied, effective = True, True  # off is off: the workflow skips whatever the pointer says
            if req.enabled:  # the workflow also needs its upstream pointer (review M2)
                effective, code, message = _sync_effective(repo, token)
                if not effective:
                    commands = [_sync_commands(repo, True)[1]]
        elif status in (401, 403, 404):
            code, message = "TOKEN_CANNOT_SET_VARIABLE", ("The Control Center's GitHub token may not change "
                                                          "repository variables: run the command.")
        else:
            code, message = "GITHUB_ERROR", f"GitHub did not set the variable ({err or f'HTTP {status}'}): run the command."
    db = get_db()
    if db:
        try:
            db.collection(SYNC_DOC[0]).document(SYNC_DOC[1]).set({"last_change": {
                "requested": req.enabled, "applied": applied, "effective": effective, "code": code, "by": email,
                "at": datetime.now(timezone.utc).isoformat()}}, merge=True)
        except Exception as e:  # noqa: BLE001 - the GitHub variable is the switch; this is its history line
            logger.warning(f"could not record the upstream-sync change: {e}")
    logger.info(json.dumps({"event": "stackvend.upstream_sync_changed", "by": email, "requested": req.enabled,
                            "applied": applied, "effective": effective, "code": code}, sort_keys=True))
    return {"repository": repo, "requested": req.enabled, "applied": applied, "enabled": req.enabled if applied else None,
            "effective": effective, "code": code, "message": message or ("Weekly auto-update from upstream is now "
                                                 f"{'on' if req.enabled else 'off'}."),
            "commands": commands}
