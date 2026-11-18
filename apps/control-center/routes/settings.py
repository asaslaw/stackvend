"""
Project Castor: Settings, Governance, Folders & IPAM Routes
Manages platform global settings, audit logs, GCP folders, IPAM network ledger, and emergency stop.
"""

from datetime import datetime, timezone
import json
import logging
import os
import re
import sys
import time
from typing import Any, Dict, List, Literal, Optional
import urllib.error
import urllib.parse
import urllib.request
import uuid

from fastapi import APIRouter, Body, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from authz import ADMIN, AUTHENTICATED, require

from auth import verify_admin_access
from config import PROJECT_ID, DynamicHTTPException as HTTPException, apply_where, get_caller_main_module
from folders import FolderConfigError, is_descendant_of_root, managed_root_folder, normalize_folder_name
from db import db
import workflow_executions as wfx
from schemas import (
    CreateFolderRequest,
    EmergencyStopRequest,
    EmergencyStopResponse,
    ManagedFolder,
    UserRole,
    CustomGoldenModuleRecord,
    CustomModuleSourceType,
    CustomModuleCategory,
    RegisterCustomModuleRequest,
    UpdateCustomModuleRequest,
    CustomModulesListResponse,
    TargetAgentRole,
    SkillSourceType,
    AgentSkillRecord,
    CreateSkillRequest,
    UpdateSkillRequest,
    SkillsListResponse,
    CompositeBundleRecord,
    CompositeBundleSourceType,
    RegisterBundleRequest,
    ScanRepositoryBundlesRequest,
    DiscoveredBundleSummary,
    BundleDriftStatusResponse,
    UpdateBundleRequest,
    CustomBundlesListResponse,
)

try:
    from shared.module_inspector import (
        parse_hcl_variables_and_outputs,
        fetch_and_inspect_github_module,
        fetch_and_inspect_git_bundle,
        scan_repository_git_bundles,
        parse_bundle_source_url,
    )
except ImportError:
    try:
        from .shared.module_inspector import (
            parse_hcl_variables_and_outputs,
            fetch_and_inspect_github_module,
            fetch_and_inspect_git_bundle,
            scan_repository_git_bundles,
            parse_bundle_source_url,
        )
    except ImportError:
        import importlib.util
        from pathlib import Path
        _insp_path = Path(__file__).parent.parent / "shared" / "module_inspector.py"
        if not _insp_path.exists():
            _insp_path = Path(__file__).parent.parent.parent.parent / "shared" / "module_inspector.py"
        _spec = importlib.util.spec_from_file_location("module_inspector", str(_insp_path))
        _mod = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        parse_hcl_variables_and_outputs = _mod.parse_hcl_variables_and_outputs
        fetch_and_inspect_github_module = _mod.fetch_and_inspect_github_module
        fetch_and_inspect_git_bundle = getattr(_mod, "fetch_and_inspect_git_bundle", None)
        scan_repository_git_bundles = getattr(_mod, "scan_repository_git_bundles", None)
        parse_bundle_source_url = getattr(_mod, "parse_bundle_source_url", None)

try:
    from shared.builtin_bundles_payload import list_builtin_bundles, get_builtin_bundle
except ImportError:
    try:
        from .shared.builtin_bundles_payload import list_builtin_bundles, get_builtin_bundle
    except ImportError:
        import importlib.util
        from pathlib import Path
        _bbp_path = Path(__file__).parent.parent / "shared" / "builtin_bundles_payload.py"
        if not _bbp_path.exists():
            _bbp_path = Path(__file__).parent.parent.parent.parent / "shared" / "builtin_bundles_payload.py"
        _spec_bb = importlib.util.spec_from_file_location("builtin_bundles_payload", str(_bbp_path))
        _mod_bb = importlib.util.module_from_spec(_spec_bb)
        _spec_bb.loader.exec_module(_mod_bb)
        list_builtin_bundles = _mod_bb.list_builtin_bundles
        get_builtin_bundle = _mod_bb.get_builtin_bundle


# FD-4CX: a registered module may not grant public access by itself (no fallback: a missing checker is a deployment
# defect, never a skipped check).
from shared.module_exposure import (
    ModuleExposureUnavailable,
    RegisteredModulePublicExposureError,
    RemoteModuleReadError,
    check_registered_module,
    fetch_remote_module_files,
)

try:
    from shared.builtin_modules_provider import get_builtin_modules
except ImportError:
    try:
        from .shared.builtin_modules_provider import get_builtin_modules
    except ImportError:
        import importlib.util
        from pathlib import Path
        _bmp_path = Path(__file__).parent.parent / "shared" / "builtin_modules_provider.py"
        if not _bmp_path.exists():
            _bmp_path = Path(__file__).parent.parent.parent.parent / "shared" / "builtin_modules_provider.py"
        _spec_b = importlib.util.spec_from_file_location("builtin_modules_provider", str(_bmp_path))
        _mod_b = importlib.util.module_from_spec(_spec_b)
        _spec_b.loader.exec_module(_mod_b)
        get_builtin_modules = _mod_b.get_builtin_modules


try:
    from shared.builtin_skills_provider import get_builtin_skills
except ImportError:
    try:
        from .shared.builtin_skills_provider import get_builtin_skills
    except ImportError:
        import importlib.util
        from pathlib import Path
        _bsp_path = Path(__file__).parent.parent / "shared" / "builtin_skills_provider.py"
        if not _bsp_path.exists():
            _bsp_path = Path(__file__).parent.parent.parent.parent / "shared" / "builtin_skills_provider.py"
        _spec_s = importlib.util.spec_from_file_location("builtin_skills_provider", str(_bsp_path))
        _mod_s = importlib.util.module_from_spec(_spec_s)
        _spec_s.loader.exec_module(_mod_s)
        get_builtin_skills = _mod_s.get_builtin_skills


try:
    from shared.settings import (
        get_platform_settings,
        invalidate_settings_cache,
        maintenance_refusal,
        new_run_refusal,
        PlatformSettings,
        SettingsAuditEntry,
    )
except (ImportError, AttributeError):
    try:
        from .shared.settings import (
            get_platform_settings,
            invalidate_settings_cache,
            maintenance_refusal,
            new_run_refusal,
            PlatformSettings,
            SettingsAuditEntry,
        )
    except (ImportError, ValueError):
        try:
            import importlib.util
            from pathlib import Path
            _s_path = Path(__file__).parent.parent / "shared" / "settings.py"
            if not _s_path.exists():
                _s_path = Path(__file__).parent.parent.parent.parent / "shared" / "settings.py"
            _spec = importlib.util.spec_from_file_location("control_center_settings", str(_s_path))
            _mod = importlib.util.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)
            get_platform_settings = _mod.get_platform_settings
            invalidate_settings_cache = _mod.invalidate_settings_cache
            maintenance_refusal = _mod.maintenance_refusal
            new_run_refusal = _mod.new_run_refusal
            PlatformSettings = _mod.PlatformSettings
            SettingsAuditEntry = _mod.SettingsAuditEntry
        except Exception:
            class SettingsAuditEntry:
                pass
            class PlatformSettings:
                pass
            def get_platform_settings(*args, **kwargs):
                return None
            def invalidate_settings_cache(*args, **kwargs):
                pass
            # settings-toggles: no settings module = settings unknown = no new run (fail closed)
            def maintenance_refusal(settings, action):
                return {"code": "PLATFORM_SETTINGS_UNAVAILABLE", "errors": [],
                        "message": f"Platform settings module unavailable: {action} was refused."}
            def new_run_refusal(action, **kwargs):
                return maintenance_refusal(None, action)


class _NoSettingsError(Exception):
    """Stand-in for a settings module without the FD-4AK error types (never raised)."""


def _current_settings_module():
    return (sys.modules.get("shared.settings") or sys.modules.get("shared_settings")
            or sys.modules.get(getattr(get_platform_settings, "__module__", None) or ""))


def _get_current_platform_settings(*args, **kwargs):
    shared_mod = _current_settings_module()
    fn = getattr(shared_mod, "get_platform_settings", None) or get_platform_settings
    return fn(*args, **kwargs)


def _settings_error_types():
    """(Unavailable, Invalid) from the SAME module whose get_platform_settings the routes call, so `except` matches
    the class that module raises (the shared settings file is loaded under more than one module name)."""
    mod = _current_settings_module()
    return (getattr(mod, "PlatformSettingsUnavailable", None) or _NoSettingsError,
            getattr(mod, "PlatformSettingsInvalid", None) or _NoSettingsError)


def _settings_error_detail(err: Exception) -> Dict[str, Any]:
    """FD-4AK: the typed error as an API detail: code, message and (loc, msg, type) errors -- never stored values."""
    return {"code": getattr(err, "code", type(err).__name__), "message": getattr(err, "message", str(err)),
            "errors": list(getattr(err, "errors", None) or [])}


def _read_current_settings_for_write():
    """FD-4AK: the current stored settings for an admin write path. Returns (settings, invalid_error):
    (PlatformSettings, None) normally; (None, PlatformSettingsInvalid) when the stored document is invalid -- a write
    replaces it with a validated one (repair). A failed read refuses the write (503): the audit history and version
    of a document that could not be read must not be overwritten."""
    unavailable_t, invalid_t = _settings_error_types()
    try:
        return _get_current_platform_settings(force_refresh=True, project_id=PROJECT_ID, strict=True), None
    except invalid_t as e:
        logger.error(f"Admin settings write replaces an invalid stored settings document: {e}")
        return None, e
    except unavailable_t as e:
        raise HTTPException(status_code=503, detail=_settings_error_detail(e))


def _salvaged_audit_and_version(invalid_err: Exception) -> tuple:
    """The audit entries (each one that still validates) and version of an invalid stored document."""
    doc = getattr(invalid_err, "document", None) or {}
    entries = []
    raw_log = doc.get("audit_log") if isinstance(doc, dict) else None
    for raw in raw_log if isinstance(raw_log, list) else []:
        try:
            entries.append(raw if isinstance(raw, SettingsAuditEntry) else SettingsAuditEntry(**raw))
        except Exception:  # noqa: BLE001 - an unparseable entry is dropped, the rest of the history is kept
            continue
    version = doc.get("version") if isinstance(doc, dict) else None
    return entries, (version if isinstance(version, int) and not isinstance(version, bool) else 1)


class SettingsChangedMeanwhile(Exception):
    """FD-4CI-b-R3 / 3a: the stored settings document is not the one this write was based on."""

    def __init__(self, stored_version: Any = None):
        super().__init__(f"stored settings version is {stored_version!r}")
        self.stored_version = stored_version


def _stored_version(raw: Any) -> int:
    """The Config Version of a raw stored document, by the same rule as PlatformSettings / the repair path: an int
    `version`, else 1 (no document, no field, or not an int)."""
    v = raw.get("version") if isinstance(raw, dict) else None
    return v if isinstance(v, int) and not isinstance(v, bool) else 1


def _is_write_conflict(err: BaseException) -> bool:
    """Firestore answers a failed precondition (the document changed after our read), an existing document on create,
    a deleted document on update, or an aborted write with these API errors."""
    try:
        from google.api_core import exceptions as gexc
    except ImportError:  # pragma: no cover
        return False
    return isinstance(err, (gexc.FailedPrecondition, gexc.Conflict, gexc.NotFound, gexc.Aborted))


def store_settings_document(stored_doc: Dict[str, Any], expected_version: int) -> None:
    """FD-4CI-b-R3 / FD-4CI-b-3a (owner 10-24): write the validated settings document only if the stored one is still
    the version this write was based on. The stored document is read once (its version must be `expected_version`),
    then written with a Firestore precondition on that read's update_time, so a save landing in between makes the
    write fail instead of being overwritten. With no document, it is created (fails if one appeared meanwhile).
    The store stays exact (as `set(merge=False)`): every top-level field is replaced and a top-level field the new
    document no longer has is deleted. Raises SettingsChangedMeanwhile on any of these conflicts."""
    ref = db.collection("system_config").document("platform_settings")
    snap = ref.get()
    exists = getattr(snap, "exists", None) is True
    raw = snap.to_dict() if exists else None
    if exists and not isinstance(raw, dict):
        raw = {}
    stored_version = _stored_version(raw)
    if stored_version != expected_version:
        raise SettingsChangedMeanwhile(stored_version)
    try:
        if not exists:
            ref.create(stored_doc)
            return
        from google.cloud.firestore_v1 import DELETE_FIELD
        from google.cloud.firestore_v1.field_path import FieldPath
        update = dict(stored_doc)
        for key in raw:
            if key not in update:
                update[FieldPath(key).to_api_repr()] = DELETE_FIELD
        ref.update(update, option=db.write_option(last_update_time=snap.update_time))
    except Exception as e:  # noqa: BLE001 - classified below
        if _is_write_conflict(e):
            raise SettingsChangedMeanwhile(None) from e
        raise


def _version_conflict_detail(message: str, stored_version: Any) -> Dict[str, Any]:
    return {
        "code": "SETTINGS_VERSION_CONFLICT",
        "message": message,
        "errors": [{"loc": ["version"], "msg": f"stale config version (stored {stored_version})",
                    "type": "version_conflict"}],
        "stored_version": stored_version,
    }


def _fields_set(model: Any) -> set:
    """FD-4CI-b: the fields the request body set explicitly (pydantic v2 / v1); without pydantic every field counts."""
    fields = getattr(model, "model_fields_set", None)
    if fields is None:
        fields = getattr(model, "__fields_set__", None)
    return set(fields) if fields is not None else {"version"}


def validated_settings_document(settings: Any) -> Dict[str, Any]:
    """FD-4AK validate-on-write: the document exactly as it will be stored, validated whole against PlatformSettings.
    An invalid field is refused (422) instead of being stored (where it would make every later read invalid)."""
    doc = settings.model_dump() if callable(getattr(settings, "model_dump", None)) else settings
    validate = getattr(_current_settings_module(), "validate_settings_document", None)
    if validate is None:
        return doc
    _, invalid_t = _settings_error_types()
    try:
        validate(doc)
    except invalid_t as e:
        raise HTTPException(status_code=422, detail=_settings_error_detail(e))
    return doc


# ------------------------------------------------------------------------------
# FD-7M-a (owner 10-31): Settings > Approved Deployable Regions. A save that ADDS a region checks it against Cloud
# Run's locations for the host project (OQ-22); a save that REMOVES a region still recorded on a workload that is not
# decommissioned is refused (OQ-23). A save that changes neither does no lookup and no query (Do No Harm).
# ------------------------------------------------------------------------------
REGION_UNKNOWN = "REGION_UNKNOWN"
REGION_LOOKUP_UNAVAILABLE = "REGION_LOOKUP_UNAVAILABLE"
REGION_IN_USE = "REGION_IN_USE"
_RUN_LOCATIONS_URL = "https://run.googleapis.com/v1/projects/{project}/locations"


class RegionLookupUnavailable(RuntimeError):
    """Cloud Run's location list could not be read (no project, no credentials, an HTTP error or an unusable
    answer): the save is refused, never treated as 'region exists'."""


def _effective_regions(orchestration: Any) -> List[str]:
    """The effective approved list (empty stored list = [default_gcp_region]) of a settings section, through the same
    settings module the routes use."""
    fn = getattr(_current_settings_module(), "approved_deployable_regions", None)
    if callable(fn):
        return list(fn(orchestration))
    regions = list(getattr(orchestration, "approved_deployable_regions", None) or [])
    return regions or [getattr(orchestration, "default_gcp_region", None)]


def cloud_run_locations() -> set:
    """The location ids Cloud Run offers to the host project (Cloud Run Admin API v1 `projects.locations.list`,
    typed `locationId`, every page). Raises RegionLookupUnavailable on any failure."""
    proj = (PROJECT_ID or os.getenv("PROJECT_ID") or "").strip()
    if not proj:
        raise RegionLookupUnavailable("no host project is configured (PROJECT_ID)")
    try:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession

        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        session = AuthorizedSession(credentials)
        found: set = set()
        page_token = None
        for _ in range(20):   # bounded: Cloud Run has a few dozen locations (one or two pages)
            params = {"pageSize": 500}
            if page_token:
                params["pageToken"] = page_token
            resp = session.get(_RUN_LOCATIONS_URL.format(project=proj), params=params, timeout=10.0)
            if resp.status_code != 200:
                raise RegionLookupUnavailable(f"Cloud Run locations answered HTTP {resp.status_code}")
            body = resp.json()
            locations = body.get("locations") if isinstance(body, dict) else None
            if not isinstance(locations, list):
                raise RegionLookupUnavailable("Cloud Run locations answer has no `locations` list")
            for loc in locations:
                loc_id = loc.get("locationId") if isinstance(loc, dict) else None
                if isinstance(loc_id, str) and loc_id:
                    found.add(loc_id)
            page_token = body.get("nextPageToken")
            if not page_token:
                break
        else:
            raise RegionLookupUnavailable("Cloud Run locations did not finish paging")
    except RegionLookupUnavailable:
        raise
    except Exception as e:  # noqa: BLE001 - auth, transport or JSON failure: the lookup did not happen
        raise RegionLookupUnavailable(f"{type(e).__name__}: {e}") from e
    if not found:
        raise RegionLookupUnavailable("Cloud Run locations answer is empty")
    return found


def _workloads_in_regions(regions: List[str]) -> Dict[str, List[str]]:
    """region -> the product ids of workloads (not DECOMMISSIONED) whose recorded region it is. Raises on a read
    failure (the caller refuses the save)."""
    in_use: Dict[str, List[str]] = {}
    if not db:
        return in_use
    for region in regions:
        for doc in db.collection("workloads").where("region", "==", region).stream():
            data = doc.to_dict() or {}
            if data.get("status") == "DECOMMISSIONED":
                continue
            in_use.setdefault(region, []).append(str(data.get("product_id") or doc.id))
    return in_use


def _region_refusal(status: int, code: str, message: str, regions: List[str], **extra: Any):
    return HTTPException(status_code=status, detail={
        "code": code, "message": message,
        "errors": [{"loc": ["orchestration", "approved_deployable_regions"], "msg": code, "type": "value_error"}],
        "regions": list(regions), **extra})


def check_approved_regions_change(old_regions: List[str], new_orchestration: Any, *, check_added: bool = True) -> None:
    """FD-7M-a: refuse a Settings write whose approved-region change is not safe. `old_regions` is the effective
    list before the write. Removed regions (old effective - new effective) still recorded on a live workload -> 422
    REGION_IN_USE; added regions (new effective - old effective) that Cloud Run does not offer -> 422 REGION_UNKNOWN; the location lookup or
    the workload query failing -> 503 (nothing stored). Nothing removed and nothing added: no call at all.
    `check_added=False` (Reset Defaults): the factory default region is not looked up."""
    new_regions = _effective_regions(new_orchestration)
    removed = [r for r in old_regions if r not in new_regions]
    added = [r for r in new_regions if r not in old_regions]   # a new default with an empty list counts too
    if removed:
        try:
            in_use = _workloads_in_regions(removed)
        except Exception as e:  # noqa: BLE001 - cannot tell whether a removed region is in use: refuse
            raise _region_refusal(503, REGION_LOOKUP_UNAVAILABLE,
                                  f"Could not check whether a removed region is still used by a workload "
                                  f"({type(e).__name__}). Nothing was saved; retry.", removed)
        if in_use:
            used = sorted(in_use)
            raise _region_refusal(422, REGION_IN_USE,
                                  f"Region(s) {', '.join(used)} cannot be removed: workloads still deploy there "
                                  f"({'; '.join(r + ': ' + ', '.join(sorted(in_use[r])) for r in used)}). A workload "
                                  "keeps its region. Nothing was saved. To change the default region, first save "
                                  "the approved list with both the current and the new default region in it, then "
                                  "change the default. Workloads without a recorded region (created before approved "
                                  "regions) follow a changed default at their next deploy.", used,
                                  workloads={r: sorted(in_use[r]) for r in used})
    if added and check_added:
        try:
            offered = cloud_run_locations()
        except RegionLookupUnavailable as e:
            raise _region_refusal(503, REGION_LOOKUP_UNAVAILABLE,
                                  f"Could not read Cloud Run's region list to check {', '.join(added)} ({e}). "
                                  "Nothing was saved; retry.", added)
        unknown = [r for r in added if r not in offered]
        if unknown:
            raise _region_refusal(422, REGION_UNKNOWN,
                                  f"Cloud Run does not offer region(s) {', '.join(unknown)} to this project. "
                                  "Nothing was saved.", unknown)


def _old_effective_regions(current: Any, stored_invalid: Any) -> List[str]:
    """The effective approved list before a write: from the current settings, or (repair of an invalid stored
    document) the defaults' list plus every region-shaped string the invalid document listed or named as default, so a
    repair cannot silently drop a region in use."""
    if current is not None:
        return _effective_regions(current.orchestration)
    regions = _effective_regions(PlatformSettings().orchestration)
    doc = getattr(stored_invalid, "document", None)
    orch = doc.get("orchestration") if isinstance(doc, dict) else None
    is_region = getattr(_current_settings_module(), "is_region_id", None)
    if isinstance(orch, dict) and callable(is_region):
        raw = orch.get("approved_deployable_regions")
        for r in (raw if isinstance(raw, list) else []) + [orch.get("default_gcp_region")]:
            if is_region(r) and r not in regions:
                regions.append(r)
    return regions


def _invalidate_current_settings_cache(*args, **kwargs):
    shared_mod = sys.modules.get("shared.settings") or sys.modules.get("shared_settings")
    fn = getattr(shared_mod, "invalidate_settings_cache", None) or invalidate_settings_cache
    return fn(*args, **kwargs)

try:
    from shared.github_resilience import (
        GitHubTokenManager,
        TokenManager,
        get_github_token,
        get_token_manager,
    )
except ImportError:
    GitHubTokenManager = None
    TokenManager = None
    def get_github_token(*args, **kwargs):
        return ""
    def get_token_manager(*args, **kwargs):
        return None

try:
    from shared.github_identity import get_default_github_owner
except ImportError:
    def get_default_github_owner(proj=None):
        return os.getenv("GITHUB_OWNER", "")

logger = logging.getLogger("control-center-settings")

router = APIRouter(tags=["Settings"])


# ------------------------------------------------------------------------------
# Emergency Stop Kill Switch
# ------------------------------------------------------------------------------
@router.get("/api/platform/emergency-stop", response_model=EmergencyStopResponse, dependencies=[require(AUTHENTICATED)])
def get_emergency_stop_status(request: Request = None):
    """Returns the current platform emergency stop status from Firestore.

    FD-4CI-b-1a: while the switch is off, the failures of the last resume (workloads still frozen with their snapshot)
    are returned too, so the page can offer "Retry restore". Those product ids are for ADMIN callers only (the same
    check as the POST); everyone else gets the old shape (count 0, empty list)."""
    if db:
        try:
            doc = db.collection("governance").document("platform_kill_switch").get()
            if doc.exists:
                data = doc.to_dict() or {}
                active = data.get("emergency_stop_active") is True
                last_resume = data.get("last_resume_result") if isinstance(data.get("last_resume_result"), dict) else {}
                failed = [] if (active or not _is_admin_caller(request)) else [
                    str(p) for p in (last_resume.get("failed_workloads") or []) if isinstance(p, str)]
                # SAT-43: while engaged, the workflow-cancel outcome of the engage (status + failed count only).
                last_engage = data.get("last_engage_result") if isinstance(data.get("last_engage_result"), dict) else {}
                same_stop = active and last_engage.get("stop_id") == data.get("stop_id")
                wf_status = last_engage.get("workflows_cancel_status") if same_stop else None
                wf_failed = last_engage.get("workflows_cancel_failed") if same_stop else 0
                return EmergencyStopResponse(
                    emergency_stop_active=bool(data.get("emergency_stop_active", False)),
                    status="ACTIVE" if data.get("emergency_stop_active") else "NORMAL",
                    activated_at=data.get("activated_at"),
                    activated_by=data.get("activated_by"),
                    reason=data.get("reason"),
                    stop_id=data.get("stop_id") if isinstance(data.get("stop_id"), str) else None,
                    workloads_failed_count=len(failed),
                    failed_workloads=failed,
                    workflows_cancel_status=wf_status if isinstance(wf_status, str) else None,
                    workflows_cancel_detail=(last_engage.get("workflows_cancel_detail") if same_stop
                                             and isinstance(last_engage.get("workflows_cancel_detail"), str) else None),
                    workflows_cancel_failed_count=wf_failed if isinstance(wf_failed, int) else 0,
                )
        except Exception as e:
            logger.warning(f"Error reading platform_kill_switch from Firestore: {e}")

    return EmergencyStopResponse(
        emergency_stop_active=False,
        status="NORMAL",
    )


def _is_admin_caller(request) -> bool:
    """The POST's own admin check (auth.verify_admin_access), as a bool; no request -> not an admin."""
    if request is None:
        return False
    try:
        return bool(verify_admin_access(request))
    except Exception:  # noqa: BLE001 - the 403 HTTPException means "not an admin" here
        return False


# FD-4CI-b #1 (owner 10-21, register rows FD-4CI-b + FD-4CI-b-1a): engage snapshots each workload's pre-engage
# freeze/SRE state in the same write that freezes it, and resume restores that state. Closed (decommissioned/deleted)
# workload records are never written by either.
_EMERGENCY_STOP_SNAPSHOT_FIELD = "emergency_stop_snapshot"
# The values engage writes. Resume compares a workload's current value with these to tell an operator's change made
# during the stop (current != applied -> the operator's value wins) from the untouched engage value (-> restore).
_EMERGENCY_STOP_APPLIED = {"code_freeze": True, "sre_auto_healing_enabled": False}
# Same closed set as project-vending's managed_tag_backfill.CLOSED_STATUSES (exact status values, not matching).
_CLOSED_WORKLOAD_STATUSES = frozenset({"DECOMMISSIONED", "DELETED"})
_KILL_SWITCH_PATH = ("governance", "platform_kill_switch")

try:
    from google.cloud import firestore as _firestore
except ImportError:  # pragma: no cover - the Control Center image always ships google-cloud-firestore
    _firestore = None


def _kill_switch_ref():
    return db.collection(_KILL_SWITCH_PATH[0]).document(_KILL_SWITCH_PATH[1])


def _delete_field_sentinel():
    if _firestore is None:
        raise RuntimeError("google-cloud-firestore is not importable: cannot remove a field")
    return _firestore.DELETE_FIELD


def _emergency_stop_snapshot(data: Dict[str, Any], stop_id: str, now_iso: str, admin_email: str) -> Dict[str, Any]:
    """The pre-engage values of the fields engage overwrites. A field the record did not have goes in `prior_absent`
    (restored by removing it again: every reader applies its own default to an absent field)."""
    return {
        "stop_id": stop_id,
        "engaged_at": now_iso,
        "engaged_by": admin_email,
        "prior": {k: data[k] for k in _EMERGENCY_STOP_APPLIED if k in data},
        "prior_absent": [k for k in _EMERGENCY_STOP_APPLIED if k not in data],
        "applied": dict(_EMERGENCY_STOP_APPLIED),
    }


def _emergency_stop_restore_plan(data: Dict[str, Any], snapshot: Dict[str, Any]):
    """-> (update dict for the workload record, restored field names, operator-kept field names, malformed: bool).

    Per field: when the record still holds the value engage wrote, the snapshot value is restored (or the field is
    removed if the record did not have it before the stop). When it holds anything else, an operator changed it
    during the stop and that value is kept.

    A malformed snapshot (`applied`/`prior` not maps, `prior_absent` not a list, or a field in neither `prior` nor
    `prior_absent`) cannot say what to restore: no field is restored and every field keeps its current value (frozen
    stays frozen, the safe side). The snapshot is removed in every case so it cannot be restored later."""
    applied, prior, prior_absent = snapshot.get("applied"), snapshot.get("prior"), snapshot.get("prior_absent")
    malformed = not (isinstance(applied, dict) and isinstance(prior, dict) and isinstance(prior_absent, list)) or any(
        f not in applied or (f not in prior and f not in prior_absent) for f in _EMERGENCY_STOP_APPLIED)
    update: Dict[str, Any] = {}
    restored: List[str] = []
    kept: List[str] = []
    for field in _EMERGENCY_STOP_APPLIED:
        if malformed or field not in data or data[field] != applied[field]:
            kept.append(field)
            continue
        update[field] = prior[field] if field in prior else _delete_field_sentinel()
        restored.append(field)
    update[_EMERGENCY_STOP_SNAPSHOT_FIELD] = _delete_field_sentinel()
    return update, restored, kept, malformed


def _record_emergency_stop_result(field: str, result: Dict[str, Any], errors: List[str]) -> None:
    """Audit: the counts of the last engage/resume on the kill-switch record (best effort; logged either way)."""
    try:
        _kill_switch_ref().set({field: result}, merge=True)
    except Exception as e:  # noqa: BLE001 - the counts are also in the response and the log
        logger.error(f"Could not record {field} on platform_kill_switch: {e}")
        errors.append(f"audit record: {e}")


def _stream_workloads(errors: List[str], what: str):
    """Yields workload snapshots lazily. A listing error (at the start or part-way) is logged, recorded in `errors` as
    "list workloads after N: ..." and ends the iteration; the caller keeps what it already did."""
    seen = 0
    try:
        for d in db.collection("workloads").stream():
            yield d
            seen += 1
    except Exception as e:  # noqa: BLE001
        logger.error(f"Emergency stop {what}: listing workloads failed after {seen}: {e}")
        errors.append(f"list workloads after {seen}: {e}")


def _engage_freeze_workloads(stop_id: str, now_iso: str, admin_email: str, errors: List[str]) -> Dict[str, Any]:
    counts = {"frozen": 0, "skipped_decommissioned": 0, "snapshot_kept": 0, "failed": 0, "failed_workloads": []}
    for d in _stream_workloads(errors, "engage"):
        try:
            data = d.to_dict() or {}
            if data.get("status") in _CLOSED_WORKLOAD_STATUSES:
                counts["skipped_decommissioned"] += 1
                continue
            update = dict(_EMERGENCY_STOP_APPLIED)
            if isinstance(data.get(_EMERGENCY_STOP_SNAPSHOT_FIELD), dict):
                # Repeated engage (or a snapshot a failed resume left behind): the existing snapshot still holds the
                # state from before any stop froze this workload. Overwriting it would make resume restore "frozen".
                counts["snapshot_kept"] += 1
            else:
                update[_EMERGENCY_STOP_SNAPSHOT_FIELD] = _emergency_stop_snapshot(data, stop_id, now_iso, admin_email)
            # One write: the freeze and the snapshot land together or not at all.
            db.collection("workloads").document(d.id).set(update, merge=True)
            counts["frozen"] += 1
        except Exception as e:  # noqa: BLE001 - keep freezing the others; the failure is counted and returned
            logger.error(f"Emergency stop: could not freeze workload {d.id}: {e}")
            counts["failed"] += 1
            counts["failed_workloads"].append(d.id)
            errors.append(f"freeze {d.id}: {e}")
    return counts


def _resume_restore_workloads(now_iso: str, admin_email: str, stop_id: Optional[str], errors: List[str]) -> Dict[str, Any]:
    counts = {"restored": 0, "operator_override": 0, "without_snapshot": 0, "skipped_decommissioned": 0,
              "malformed_snapshot": 0, "failed": 0, "failed_workloads": []}
    for d in _stream_workloads(errors, "resume"):
        try:
            data = d.to_dict() or {}
            snapshot = data.get(_EMERGENCY_STOP_SNAPSHOT_FIELD)
            if data.get("status") in _CLOSED_WORKLOAD_STATUSES:
                # Never written (as on engage). A snapshot left on a record closed during the stop is inert: engage and
                # resume both skip closed records.
                counts["skipped_decommissioned"] += 1
                continue
            if not isinstance(snapshot, dict):
                counts["without_snapshot"] += 1
                continue
            update, restored, kept, malformed = _emergency_stop_restore_plan(data, snapshot)
            prior = snapshot.get("prior") if isinstance(snapshot.get("prior"), dict) else {}
            doc_ref = db.collection("workloads").document(d.id)
            batch = db.batch()  # the restore and its audit entry land together or not at all
            batch.set(doc_ref, update, merge=True)
            batch.set(doc_ref.collection("audit_logs").document(), {
                "action": "EMERGENCY_STOP_RESTORE",
                "timestamp": now_iso,
                "operator": admin_email,
                "stop_id": snapshot.get("stop_id") or stop_id,
                "restored_fields": {f: prior[f] for f in restored if f in prior},
                "restored_absent_fields": [f for f in restored if f not in prior],
                "operator_kept_fields": {f: data.get(f) for f in kept},
                "malformed_snapshot": malformed,
            })
            batch.commit()
            if malformed:
                counts["malformed_snapshot"] += 1
                errors.append(f"malformed snapshot on {d.id}: kept its current freeze/SRE values, snapshot removed")
            else:
                counts["restored"] += 1
                if kept:
                    counts["operator_override"] += 1
        except Exception as e:  # noqa: BLE001 - the workload stays frozen with its snapshot; retried by the next resume
            logger.error(f"Emergency stop resume: could not restore workload {d.id}: {e}")
            counts["failed"] += 1
            counts["failed_workloads"].append(d.id)
            errors.append(f"restore {d.id}: {e}")
    return counts


def _cancel_running_workflows() -> Dict[str, Any]:
    """SAT-43: lists and cancels the ACTIVE executions of the platform workflows over the Workflows REST API
    (workflow_executions.py; google-cloud-workflows is not in this image). Never raises: the report's `status` is OK or
    the typed reason not every running execution was cancelled (WORKFLOW_CANCEL_NOT_PERMITTED,
    WORKFLOW_CANCEL_UNCONFIGURED, WORKFLOW_LIST_FAILED, WORKFLOW_CANCEL_FAILED)."""
    return wfx.cancel_active_platform_workflows(PROJECT_ID or os.getenv("PROJECT_ID", ""))


@router.post("/api/platform/emergency-stop", response_model=EmergencyStopResponse, dependencies=[require(ADMIN)])
def toggle_emergency_stop_api(req: EmergencyStopRequest, request: Request):
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin-console")
    now_iso = datetime.now(timezone.utc).isoformat()
    errors: List[str] = []

    if req.activate:
        stop_id = uuid.uuid4().hex
        counts = {"frozen": 0, "skipped_decommissioned": 0, "snapshot_kept": 0, "failed": 0, "failed_workloads": []}
        switch_error = None
        if db:
            try:
                current = _kill_switch_ref().get()
                current_data = (current.to_dict() or {}) if current.exists else {}
                if current_data.get("emergency_stop_active") is True and current_data.get("stop_id"):
                    stop_id = str(current_data["stop_id"])  # repeated engage: same stop
            except Exception as e:  # noqa: BLE001 - a new stop id is fine; snapshots are never overwritten anyway
                logger.warning(f"Could not read platform_kill_switch before engaging: {e}")
            kill_switch_data = {
                "emergency_stop_active": True,
                "activated_at": now_iso,
                "activated_by": admin_email,
                "reason": req.reason or "Operator manual override",
                "stop_id": stop_id,
            }
            try:
                _kill_switch_ref().set(kill_switch_data, merge=True)
            except Exception as e:  # noqa: BLE001 - freeze first anyway; the switch write is retried below
                logger.error(f"Error setting emergency stop in Firestore (retried after the freeze): {e}")
                switch_error = e
            counts = _engage_freeze_workloads(stop_id, now_iso, admin_email, errors)

        wf = _cancel_running_workflows()
        cancelled_count = wf["cancelled"]
        wf_failed = [r for r in wf["executions"] if r["outcome"] == wfx.FAILED]

        if db and switch_error is not None:
            try:
                _kill_switch_ref().set(kill_switch_data, merge=True)
                errors.append(f"kill switch: first write failed ({switch_error}); the retry succeeded")
            except Exception as e:  # noqa: BLE001
                logger.error(f"🚨 Emergency stop: {counts['frozen']} workloads frozen but the kill switch could not "
                             f"be set: {e}")
                raise HTTPException(
                    status_code=503,
                    detail=f"{counts['frozen']} workloads frozen but the kill switch could not be set: {e}. "
                           f"New runs are not blocked; engage again.",
                )

        if db:
            _record_emergency_stop_result("last_engage_result", {
                "stop_id": stop_id, "at": now_iso, "by": admin_email, "workloads_frozen": counts["frozen"],
                "workloads_skipped_decommissioned": counts["skipped_decommissioned"],
                "workloads_snapshot_kept": counts["snapshot_kept"], "workloads_failed": counts["failed"],
                "failed_workloads": counts["failed_workloads"], "workflows_cancelled": cancelled_count,
                "workflows_cancel_status": wf["status"], "workflows_cancel_detail": wf["detail"],
                "workflows_already_finished": wf["already_finished"], "workflows_cancel_failed": wf["failed"],
                "workflow_list_failures": wf["list_failures"],
                "workflow_cancel_failures": [{k: r.get(k) for k in ("name", "workflow", "reason", "detail")}
                                             for r in wf_failed[:50]]}, errors)
        logger.warning(f"🚨 PLATFORM EMERGENCY STOP ACTIVATED by {admin_email} (stop {stop_id}). "
                       f"{counts['frozen']} workloads frozen ({counts['snapshot_kept']} kept an earlier snapshot), "
                       f"{counts['skipped_decommissioned']} decommissioned skipped, {counts['failed']} failed, "
                       f"{cancelled_count} workflows cancelled (workflow cancel status {wf['status']}"
                       + (f": {wf['detail']}" if wf["detail"] else "") + ").")
        if wf["status"] != wfx.OK:
            logger.error(f"🚨 Emergency stop engaged but running workflow executions were NOT all cancelled "
                         f"({wf['status']}): {wf['detail']}")
        return EmergencyStopResponse(
            emergency_stop_active=True,
            status="ACTIVE",
            activated_at=now_iso,
            activated_by=admin_email,
            reason=req.reason,
            workflows_cancelled_count=cancelled_count,
            workflows_cancel_status=wf["status"],
            workflows_cancel_detail=wf["detail"],
            workflows_already_finished_count=wf["already_finished"],
            workflows_cancel_failed_count=wf["failed"],
            workflow_list_failures=wf["list_failures"],
            workflow_cancel_results=wf["executions"],
            workloads_frozen_count=counts["frozen"],
            stop_id=stop_id,
            workloads_skipped_decommissioned_count=counts["skipped_decommissioned"],
            workloads_snapshot_kept_count=counts["snapshot_kept"],
            workloads_failed_count=counts["failed"],
            failed_workloads=counts["failed_workloads"],
            errors=errors,
        )
    else:
        stop_id = None
        counts = {"restored": 0, "operator_override": 0, "without_snapshot": 0, "skipped_decommissioned": 0,
                  "malformed_snapshot": 0, "failed": 0, "failed_workloads": []}
        reengaged = None
        refreeze = {"frozen": 0, "failed": 0, "failed_workloads": []}
        if db:
            kill_switch_data = {
                "emergency_stop_active": False,
                "resumed_at": now_iso,
                "resumed_by": admin_email,
            }
            try:
                ref = _kill_switch_ref()
                current = ref.get()
                if current.exists:
                    stop_id = (current.to_dict() or {}).get("stop_id")
                    # Precondition on the record read above: an engage landing in between makes this write fail into
                    # the 503 below instead of being silently cleared.
                    ref.update(kill_switch_data, option=db.write_option(last_update_time=current.update_time))
                else:
                    ref.create(kill_switch_data)  # AlreadyExists (an engage created it meanwhile) -> 503 below
            except Exception as e:
                # The switch is still engaged (or changed under us): restore nothing (every workload stays frozen).
                logger.error(f"Error resuming platform operations in Firestore: {e}")
                raise HTTPException(
                    status_code=503,
                    detail=f"Could not clear the emergency stop ({e}). It is still engaged; no workload was changed.",
                )
            # Restores run after the switch is cleared: a failure leaves that workload frozen (the safe side) with its
            # snapshot, is counted and returned, and is retried by the next resume ("Retry restore" on the page).
            counts = _resume_restore_workloads(now_iso, admin_email, stop_id, errors)

            # An engage that landed during the restore loop may have found workloads still holding their old snapshot
            # and the ones already restored: freeze them all again for that stop (idempotent, snapshots kept). This
            # resume has just cleared the switch, so ANY active switch now is a re-engage -- including one that read
            # the old stop_id before the clear and wrote it back after it.
            try:
                after = _kill_switch_ref().get()
                after_data = (after.to_dict() or {}) if after.exists else {}
            except Exception as e:  # noqa: BLE001
                after_data = {}
                errors.append(f"could not re-check the stop after resuming: {e}")
            if after_data.get("emergency_stop_active") is True:
                reengaged = after_data
                new_stop_id = str(after_data.get("stop_id") or uuid.uuid4().hex)
                refreeze = _engage_freeze_workloads(new_stop_id, now_iso, str(after_data.get("activated_by") or ""),
                                                    errors)
                errors.append(f"re-engaged by {after_data.get('activated_by') or 'unknown'} during resume; "
                              f"workloads re-frozen ({refreeze['frozen']} frozen, {refreeze['failed']} failed)")
            _record_emergency_stop_result("last_resume_result", {
                "stop_id": stop_id, "at": now_iso, "by": admin_email, "workloads_restored": counts["restored"],
                "workloads_operator_override": counts["operator_override"],
                "workloads_without_snapshot": counts["without_snapshot"],
                "workloads_skipped_decommissioned": counts["skipped_decommissioned"],
                "workloads_malformed_snapshot": counts["malformed_snapshot"],
                "workloads_failed": counts["failed"], "failed_workloads": counts["failed_workloads"],
                "reengaged_during_resume": bool(reengaged)}, errors)

        log = logger.error if (counts["failed"] or reengaged) else logger.info
        log(f"🔓 Platform Emergency Stop DEACTIVATED by {admin_email} (stop {stop_id}). {counts['restored']} workloads "
            f"restored to their pre-stop freeze/SRE state ({counts['operator_override']} kept an operator change), "
            f"{counts['without_snapshot']} without a snapshot untouched, {counts['skipped_decommissioned']} closed "
            f"skipped, {counts['failed']} failed and stay frozen"
            + (f": {', '.join(counts['failed_workloads'])}" if counts["failed"] else "")
            + (" -- re-engaged during resume, workloads re-frozen" if reengaged else "") + ".")
        if reengaged:
            return EmergencyStopResponse(
                emergency_stop_active=True,
                status="ACTIVE",
                activated_at=reengaged.get("activated_at"),
                activated_by=reengaged.get("activated_by"),
                reason=reengaged.get("reason"),
                stop_id=reengaged.get("stop_id"),
                workloads_restored_count=counts["restored"],
                workloads_frozen_count=refreeze["frozen"],
                workloads_failed_count=counts["failed"] + refreeze["failed"],
                failed_workloads=sorted(set(counts["failed_workloads"]) | set(refreeze["failed_workloads"])),
                errors=errors,
            )
        return EmergencyStopResponse(
            emergency_stop_active=False,
            status="NORMAL",
            activated_at=now_iso,
            activated_by=admin_email,
            stop_id=stop_id,
            workloads_restored_count=counts["restored"],
            workloads_operator_override_count=counts["operator_override"],
            workloads_without_snapshot_count=counts["without_snapshot"],
            workloads_skipped_decommissioned_count=counts["skipped_decommissioned"],
            workloads_malformed_snapshot_count=counts["malformed_snapshot"],
            workloads_failed_count=counts["failed"],
            failed_workloads=counts["failed_workloads"],
            errors=errors,
        )


# ------------------------------------------------------------------------------
# Platform Global Settings Endpoints
# ------------------------------------------------------------------------------
@router.get("/api/settings", response_model=PlatformSettings, dependencies=[require(AUTHENTICATED)])
def get_settings_api(force: bool = False, request: Request = None):
    # FD-4AK: the editor must never be handed compile-time defaults in place of settings it could not read or parse
    # (saving that form would overwrite the real ones): an unreadable / invalid stored document is a typed 503.
    unavailable_t, _ = _settings_error_types()
    try:
        current = _get_current_platform_settings(force_refresh=force, project_id=PROJECT_ID, strict=True)
    except unavailable_t as e:
        raise HTTPException(status_code=503, detail=_settings_error_detail(e))
    # FD-4N (red-team H12): the settings audit log carries administrator emails; ADMIN-only.
    if request is not None and getattr(getattr(request, "state", None), "user_role", None) != UserRole.ADMIN:
        try:
            current = current.model_copy(update={"audit_log": []})
        except Exception:  # noqa: BLE001 - never return the audit log to a non-admin
            current = PlatformSettings(**{**current.model_dump(), "audit_log": []})
    return current


# OPEN-MODEL-SETTINGS (owner 11-10): the live model check of a save (services/model_check.py). Test seam: None = the
# real client the agents build (AI Studio key, else Vertex AI on GEMINI_LOCATION).
model_check_client_factory = None


def _model_check_module():
    try:
        from services import model_check
    except ImportError:  # pragma: no cover - loaded as a package
        from ..services import model_check  # type: ignore
    return model_check


def _parse_settings_body(raw: Any, stored_custom_families: Dict[str, str]) -> Any:
    """OPEN-MODEL-SETTINGS: the PUT body as PlatformSettings. The client's `models.custom_families` is replaced by the
    stored one, and a model id that is neither built in nor stored is admitted with a provisional style so the rest of
    the document is validated first (no paid call for a body that is invalid anyway); the live check then decides its
    style (update_settings_api). A validation error is the 422 FastAPI gives for an invalid body."""
    if not isinstance(raw, dict):
        raise RequestValidationError([{"loc": ("body",), "msg": "the settings document must be a mapping",
                                       "type": "dict_type"}])
    doc = dict(raw)
    models = doc.get("models")
    if isinstance(models, dict):
        mc = _model_check_module()
        families = dict(stored_custom_families or {})
        ids = [models.get(f) for f in mc.FIELD_PURPOSE if f != "fallback_models"]
        ids += list(models.get("fallback_models") or []) if isinstance(models.get("fallback_models"), list) else []
        for mid in ids:
            if isinstance(mid, str) and mid.strip() and mc.known_model_id(mid) is None and mc.is_model_id_syntax(mid):
                families.setdefault(mc.canonical_model_id(mid), mc.PROVISIONAL_STYLE)
        doc["models"] = {**models, "custom_families": families}
    try:
        return PlatformSettings.model_validate(doc)
    except RequestValidationError:
        raise
    except Exception as e:  # noqa: BLE001 - pydantic ValidationError: FastAPI's own 422 shape
        errs = (e.errors(include_url=False) if callable(getattr(e, "errors", None))
                else [{"loc": (), "msg": str(e), "type": "value_error"}])
        raise RequestValidationError([{**er, "loc": ("body",) + tuple(er.get("loc") or ()),
                                       **({"ctx": {k: str(v) for k, v in er["ctx"].items()}}
                                          if isinstance(er.get("ctx"), dict) else {})} for er in errs])


def _check_models_and_set_families(payload: Any, diff_base: Any, current: Any) -> None:
    """OPEN-MODEL-SETTINGS: one live call per changed model (and per level-style model of a role whose thinking level
    changed); refused -> 422 with the typed code and Google's message, nothing stored. Then the server-owned
    `models.custom_families`: the style of every model id in use that is not built in, from this check or the
    stored settings. An id with neither stays out, so the document validation refuses it (UNSUPPORTED_MODEL_CONFIG)."""
    mc = _model_check_module()
    models = payload.models
    stored = dict(getattr(getattr(current, "models", None), "custom_families", None) or {})
    try:
        mc.check_limits(models)                                   # RT F2: before any call
        checks = mc.plan_checks(diff_base.models, models, stored)
        probed = mc.run_checks(checks, thinking_levels=dict(models.thinking_levels or {}),
                               client_factory=model_check_client_factory)
    except mc.ModelCheckError as e:
        logger.warning(f"Settings save refused by the model check: {e}")
        raise HTTPException(status_code=422, detail=e.detail())
    families = {}
    for mid in mc.referenced_custom_ids(models):
        style = probed.get(mid) or stored.get(mid)
        if style:
            families[mid] = style
    models.custom_families = families


@router.put("/api/settings", response_model=PlatformSettings, dependencies=[require(ADMIN)])
def update_settings_api(settings_payload: Dict[str, Any] = Body(...), request: Request = None):
    user_role = getattr(request.state, "user_role", UserRole.APPROVER)
    if user_role != UserRole.ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Admin role required to update platform global settings.",
        )

    admin_email = getattr(request.state, "user_email", "admin-console")
    now_iso = datetime.now(timezone.utc).isoformat()

    current, stored_invalid = _read_current_settings_for_write()
    if current is not None:
        diff_base, prior_audit, prior_version = current, list(current.audit_log or []), current.version
    else:   # FD-4AK repair of an invalid stored document: diff against the defaults, keep the salvageable history
        diff_base = PlatformSettings()
        prior_audit, prior_version = _salvaged_audit_and_version(stored_invalid)
    # OPEN-MODEL-SETTINGS: an HTTP body arrives as a mapping (a model id without built-in rules must reach the live
    # check below); a caller in this process may still pass a PlatformSettings.
    if not isinstance(settings_payload, PlatformSettings):
        settings_payload = _parse_settings_body(
            settings_payload, dict(getattr(getattr(current, "models", None), "custom_families", None) or {}))

    # FD-4CI-b: Config Version is an optimistic lock. A save based on an older version than the stored one (another
    # administrator saved in between) is refused with 409 and nothing is written; the editor reloads and re-applies.
    # A request that sends no version is not checked (API callers that PUT the whole document as before).
    if current is not None and "version" in _fields_set(settings_payload) and settings_payload.version != prior_version:
        raise HTTPException(status_code=409, detail={
            "code": "SETTINGS_VERSION_CONFLICT",
            "message": (f"Settings were changed by someone else (Config Version {prior_version}; your page has "
                        f"{settings_payload.version}). Nothing was saved. Reload the settings and make your change "
                        "again."),
            "errors": [{"loc": ["version"], "msg": f"stale config version (stored {prior_version})",
                        "type": "version_conflict"}],
            "stored_version": prior_version,
        })
    # FD-4CI-b: a Terraform version the Terraform server refuses at run time (1.6 or later) is not saved.
    tf_version = getattr(getattr(settings_payload, "orchestration", None), "terraform_version", None)
    accepted = getattr(_current_settings_module(), "terraform_version_accepted", None)
    if callable(accepted) and not accepted(tf_version):
        empty = not (isinstance(tf_version, str) and tf_version.strip())
        raise HTTPException(status_code=422, detail={
            "code": "TERRAFORM_VERSION_REFUSED",
            "message": ("No Terraform version is selected. Choose 1.5.7." if empty else
                        f"Terraform {tf_version} is refused when a deploy runs (only versions below 1.6, the last "
                        "open-source series, are accepted). Choose 1.5.7."),
            "errors": [{"loc": ["orchestration", "terraform_version"],
                        "msg": "empty" if empty else "refused at run time (>= 1.6)", "type": "value_error"}],
        })
    # OPEN-MODEL-SETTINGS + THINKING-LEVEL-SETTINGS (owner 11-10): changed models are called once before the save
    _check_models_and_set_families(settings_payload, diff_base, current)

    changed_fields = {}
    if stored_invalid is not None:
        changed_fields["repaired_invalid_document"] = {"from": _settings_error_detail(stored_invalid)["errors"],
                                                       "to": "validated settings"}
    for section_name in ["finops", "orchestration", "models", "governance", "runtimes"]:
        curr_dict = getattr(diff_base, section_name).model_dump()
        new_dict = getattr(settings_payload, section_name).model_dump()
        for k, v in new_dict.items():
            if curr_dict.get(k) != v:
                changed_fields[f"{section_name}.{k}"] = {"from": curr_dict.get(k), "to": v}

    audit_entry = SettingsAuditEntry(
        timestamp=now_iso,
        admin_email=admin_email,
        action="UPDATE_SETTINGS",
        changed_fields=changed_fields,
    )

    audit_history = list(prior_audit)
    audit_history.insert(0, audit_entry)
    audit_history = audit_history[:15]

    settings_payload.audit_log = audit_history
    settings_payload.updated_at = now_iso
    settings_payload.updated_by = admin_email
    settings_payload.version = (prior_version or 1) + 1

    # FD-4AK validate-on-write: the whole document as stored, and stored exactly (merge=False): a merge could keep a
    # stale or invalid nested key of the old document that the validated payload no longer has.
    stored_doc = validated_settings_document(settings_payload)
    # FD-7M-a (after the whole-document validation, before the store): a region still used by a workload is never
    # removed; an added region must be a Cloud Run region. No region change: no call.
    check_approved_regions_change(_old_effective_regions(current, stored_invalid), settings_payload.orchestration)
    if db:
        try:
            # FD-4CI-b-R3: transactional with the version check above (Firestore precondition)
            store_settings_document(stored_doc, prior_version)
            logger.info(f"Platform global settings updated in Firestore by {admin_email}")
        except SettingsChangedMeanwhile as e:
            raise HTTPException(status_code=409, detail=_version_conflict_detail(
                "Settings were changed by someone else while you were saving. Nothing was saved. Reload the "
                "settings and make your change again.", e.stored_version))
        except Exception as e:
            logger.error(f"Failed to persist platform settings to Firestore: {e}")
            raise HTTPException(
                status_code=500, detail=f"Failed to persist platform settings: {e}"
            )

    _invalidate_current_settings_cache()
    return settings_payload


@router.post("/api/settings/reset-defaults", response_model=PlatformSettings, dependencies=[require(ADMIN)])
def reset_settings_defaults_api(request: Request):
    user_role = getattr(request.state, "user_role", UserRole.APPROVER)
    if user_role != UserRole.ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Admin role required to reset platform global settings.",
        )

    admin_email = getattr(request.state, "user_email", "admin-console")
    now_iso = datetime.now(timezone.utc).isoformat()

    current, stored_invalid = _read_current_settings_for_write()
    if current is not None:
        prior_audit, prior_version = list(current.audit_log or []), current.version
    else:   # FD-4AK: resetting an invalid stored document is a repair; its salvageable history is kept
        prior_audit, prior_version = _salvaged_audit_and_version(stored_invalid)

    default_settings = PlatformSettings()
    audit_entry = SettingsAuditEntry(
        timestamp=now_iso,
        admin_email=admin_email,
        action="RESET_DEFAULTS",
        changed_fields={"all": "Reset to factory defaults"},
    )
    audit_history = list(prior_audit)
    audit_history.insert(0, audit_entry)
    default_settings.audit_log = audit_history[:15]
    default_settings.updated_at = now_iso
    default_settings.updated_by = admin_email
    default_settings.version = (prior_version or 1) + 1

    stored_doc = validated_settings_document(default_settings)
    # FD-7M-a: a reset never removes a region a workload still deploys in (the default region needs no lookup).
    check_approved_regions_change(_old_effective_regions(current, stored_invalid), default_settings.orchestration,
                                  check_added=False)
    if db:
        try:
            db.collection("system_config").document("platform_settings").set(
                stored_doc, merge=False
            )
            logger.info(f"Platform global settings reset to defaults by {admin_email}")
        except Exception as e:
            logger.error(f"Failed to reset platform settings in Firestore: {e}")
            raise HTTPException(
                status_code=500, detail=f"Failed to reset platform settings: {e}"
            )

    invalidate_settings_cache()
    return default_settings


class SwitchVcsProviderRequest(BaseModel):
    vcs_provider: Literal["GITHUB", "SERVERLESS_GIT"]


@router.put("/api/settings/vcs-provider", response_model=PlatformSettings, dependencies=[require(ADMIN)])
def switch_vcs_provider_api(req: SwitchVcsProviderRequest, request: Request):
    """FD-4CI-b (9-10): the VCS card's *Switch Default* changes ``governance.vcs_provider`` and nothing else. The
    stored settings are read fresh and written back with only that field changed, so unsaved edits in the Parameters
    form (never sent here) are never saved by it. Audited like a Parameters save (UPDATE_SETTINGS, the one changed
    field), version + 1. A stored document that cannot be read (503) or does not validate (409; a full Parameters
    save repairs it) is refused: a one-field switch never rewrites a document it could not read."""
    if getattr(request.state, "user_role", None) != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Forbidden: Admin role required to change the default VCS.")
    admin_email = getattr(request.state, "user_email", "admin-console")
    now_iso = datetime.now(timezone.utc).isoformat()

    current, stored_invalid = _read_current_settings_for_write()
    if current is None:
        detail = _settings_error_detail(stored_invalid)
        detail["message"] = ("The stored platform settings do not validate, so the default VCS was not changed. "
                             "Repair them with Save Changes on the Parameters tab (or Reset Defaults), then retry. "
                             f"({detail['message']})")
        raise HTTPException(status_code=409, detail=detail)

    updated = current.model_copy(deep=True)
    previous = updated.governance.vcs_provider
    updated.governance.vcs_provider = req.vcs_provider
    changed_fields = {} if previous == req.vcs_provider else {
        "governance.vcs_provider": {"from": previous, "to": req.vcs_provider}}
    audit_history = list(current.audit_log or [])
    audit_history.insert(0, SettingsAuditEntry(timestamp=now_iso, admin_email=admin_email, action="UPDATE_SETTINGS",
                                               changed_fields=changed_fields))
    updated.audit_log = audit_history[:15]
    updated.updated_at = now_iso
    updated.updated_by = admin_email
    updated.version = (current.version or 1) + 1

    stored_doc = validated_settings_document(updated)
    if db:
        try:
            # FD-4CI-b-3a: a Settings save landing between the read above and this write is never overwritten
            store_settings_document(stored_doc, current.version or 1)
            logger.info(f"Default VCS provider set to {req.vcs_provider} by {admin_email}")
        except SettingsChangedMeanwhile as e:
            raise HTTPException(status_code=409, detail=_version_conflict_detail(
                "The settings were changed by someone else while the default VCS was being switched. Nothing was "
                "changed. Reload the settings and switch again.", e.stored_version))
        except Exception as e:
            logger.error(f"Failed to persist the default VCS provider: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to persist platform settings: {e}")

    _invalidate_current_settings_cache()
    return updated


# ------------------------------------------------------------------------------
# Google Cloud Billing Status
# ------------------------------------------------------------------------------
# BG-1: core Terraform (infra/platform/billing_iam.tf) grants Billing Account User to these service accounts
# only when the person running scripts/apply.sh is a Billing Account Administrator; otherwise the grant is
# skipped (the install still succeeds). The card reports, per service account, whether the grant exists.
BILLING_USER_ROLE = "roles/billing.user"
BILLING_USER_SERVICE_ACCOUNTS = ("sa-project-provisioner", "sa-castor-developer")
# roles/billing.admin contains every roles/billing.user permission, so a direct admin grant also satisfies it.
_BILLING_USER_SATISFIED_BY = frozenset({"roles/billing.user", "roles/billing.admin"})
BILLING_GRANT_SKIP_REASON = (
    "Terraform skipped this grant (the install itself succeeded): most likely the person who ran the install was "
    "not a Billing Account Administrator, or bind_billing_iam = false is set in the install's tfvars. If access "
    "comes from an organization-level grant, it does not show here."
)


def _billing_authed_session():
    """AuthorizedSession for the Control Center's own runtime identity (ADC)."""
    from google.auth.transport.requests import AuthorizedSession
    import google.auth
    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    return AuthorizedSession(creds)


# Shell safety (billing-card-commands review): an install value goes into a copyable command only when it has the
# exact Google shape (billing account id as `gcloud billing accounts list` prints it; project id rules); anything
# else becomes the placeholder, never text pasted into the operator's shell.
_BILLING_ID = re.compile(r"[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}")
_PROJECT_ID = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")


def _safe_billing(clean_billing: str) -> str:
    return clean_billing if _BILLING_ID.fullmatch(clean_billing or "") else "<billing-account-id>"


def _safe_project(proj: str) -> str:
    return proj if _PROJECT_ID.fullmatch(proj or "") else "<project_id>"


def _billing_user_fix_command(clean_billing: str, name: str, proj: str) -> str:
    return (f"gcloud billing accounts add-iam-policy-binding {_safe_billing(clean_billing)} "
            f"--member=serviceAccount:{name}@{_safe_project(proj)}.iam.gserviceaccount.com --role={BILLING_USER_ROLE}")


# BG-1-b: the Control Center's own runtime identity (infra/platform/destructive_guard.tf persona key; the same name as
# routes/install_status.py CC_SA_ACCOUNT_ID) gets Billing Account Viewer so this card can read the billing account.
BILLING_VIEWER_ROLE = "roles/billing.viewer"
BILLING_VIEWER_SERVICE_ACCOUNT = "sa-stackvend-control-center"


def billing_grant_fix_commands(clean_billing: str, proj: str) -> List[str]:
    """BILLING-CARD-COMMANDS (11-03 limited-user install): the three billing-account grants the platform needs
    (infra/platform/billing_iam.tf; the same commands scripts/bootstrap.sh prints and documentation/quickstart.md
    "Post-install: billing access" lists). Shown when the card cannot verify the grants. Display only; each command
    adds one member and is safe to re-run. Unknown or malformed values stay placeholders (never a made-up id, never
    unchecked text in a shell command)."""
    account = _safe_billing(clean_billing)
    project = _safe_project(proj)
    pairs = [(name, BILLING_USER_ROLE) for name in BILLING_USER_SERVICE_ACCOUNTS]
    pairs.append((BILLING_VIEWER_SERVICE_ACCOUNT, BILLING_VIEWER_ROLE))
    return [f"gcloud billing accounts add-iam-policy-binding {account} "
            f"--member=serviceAccount:{name}@{project}.iam.gserviceaccount.com --role={role}"
            for name, role in pairs]


def _billing_service_account_grants(authed_session, clean_billing: str, proj: str) -> List[Dict[str, Any]]:
    """Per service account: GRANTED / NOT_GRANTED / CANNOT_VERIFY, from billingAccounts.getIamPolicy.

    Read-only. Never raises: any failure becomes CANNOT_VERIFY with the HTTP status (when there is one).
    Only grants on the billing account itself are visible here (an organization-level grant is not).
    """
    if not clean_billing:
        return []
    rows: List[Dict[str, Any]] = []
    for name in BILLING_USER_SERVICE_ACCOUNTS:
        email = f"{name}@{proj}.iam.gserviceaccount.com" if proj else ""
        rows.append({
            "service_account": name,
            "email": email,
            "role": BILLING_USER_ROLE,
            "status": "CANNOT_VERIFY",
            "http_status": None,
            "detail": "",
            "fix_command": _billing_user_fix_command(clean_billing, name, proj) if email else "",
        })
    if not proj:
        for row in rows:
            row["detail"] = "The platform project id is unknown, so the service account emails cannot be built."
        return rows

    bindings = None
    detail = ""
    try:
        session = authed_session if authed_session is not None else _billing_authed_session()
        resp = session.get(
            f"https://cloudbilling.googleapis.com/v1/billingAccounts/{clean_billing}:getIamPolicy",
            params={"options.requestedPolicyVersion": 3},
            timeout=5.0,
        )
        status = getattr(resp, "status_code", None)
        for row in rows:
            row["http_status"] = status
        if status == 200:
            body = resp.json()
            if isinstance(body, dict) and isinstance(body.get("bindings", []), list):
                bindings = body.get("bindings", [])
            else:
                detail = "The billing account IAM policy answer was not readable (HTTP 200)."
        elif status == 403:
            detail = ("The Control Center's own identity may not read this billing account's IAM policy (HTTP 403). "
                      "It needs Billing Account User or Billing Account Viewer on the billing account.")
        else:
            detail = f"Reading the billing account IAM policy returned HTTP {status}."
    except Exception as ex:
        bindings = None
        detail = f"Reading the billing account IAM policy failed ({type(ex).__name__})."

    if bindings is None:
        for row in rows:
            row["detail"] = detail
        return rows

    for row in rows:
        member = f"serviceAccount:{row['email']}"
        unconditional, conditional = False, False
        for b in bindings:
            if not isinstance(b, dict) or b.get("role") not in _BILLING_USER_SATISFIED_BY:
                continue
            if member not in (b.get("members") or []):
                continue
            if b.get("condition"):
                conditional = True
            else:
                unconditional = True
        if unconditional:
            row["status"] = "GRANTED"
            row["detail"] = "Billing Account User is granted on the billing account."
        elif conditional:
            row["detail"] = "Granted only with an IAM condition, which this check does not evaluate."
        else:
            row["status"] = "NOT_GRANTED"
            row["detail"] = (f"{row['service_account']} does NOT have Billing Account User on billing account "
                             f"{clean_billing}. {BILLING_GRANT_SKIP_REASON}")
    return rows


@router.get("/api/settings/billing-status", dependencies=[require(ADMIN)])
def get_billing_status_api(request: Request):
    proj = PROJECT_ID or os.getenv("PROJECT_ID", "") or os.getenv("GOOGLE_CLOUD_PROJECT", "")
    billing_id = os.getenv("BILLING_ACCOUNT_ID", "") or os.getenv("BILLING_ACCOUNT", "") or ""
    clean_billing = billing_id.replace("billingAccounts/", "").strip()
    provisioner_sa = f"sa-project-provisioner@{proj}.iam.gserviceaccount.com" if proj else ""

    has_access = False
    error_message = ""
    authed_session = None

    if clean_billing:
        try:
            authed_session = _billing_authed_session()
            resp = authed_session.get(f"https://cloudbilling.googleapis.com/v1/billingAccounts/{clean_billing}", timeout=5.0)
            if resp.status_code == 200:
                has_access = True
            elif resp.status_code == 403:
                has_access = False
                error_message = f"Billing account access not permitted (HTTP 403): {resp.text}"
            else:
                has_access = False
                error_message = f"Billing account check returned HTTP {resp.status_code}: {resp.text}"
        except Exception as auth_ex:
            try:
                from googleapiclient.discovery import build
                import google.auth
                creds, _ = google.auth.default()
                billing_service = build("cloudbilling", "v1", credentials=creds, cache_discovery=False)
                billing_service.billingAccounts().get(name=f"billingAccounts/{clean_billing}").execute()
                has_access = True
            except Exception:
                error_message = str(auth_ex)
                has_access = False

    try:
        grants = _billing_service_account_grants(authed_session, clean_billing, proj)
    except Exception as ex:  # never fail the Settings page
        logger.warning(f"Billing grant check failed: {type(ex).__name__}")
        grants = []
    missing = [g["service_account"] for g in grants if g["status"] == "NOT_GRANTED"]

    return {
        "project_id": proj,
        "billing_account_id": clean_billing,
        "provisioner_sa": provisioner_sa,
        "has_billing_access": has_access,
        "error_message": error_message,
        "configured": bool(clean_billing),
        # BG-1: Billing Account User status per StackVend service account.
        "billing_user_grants": grants,
        "billing_grants_missing": missing,
        "billing_healthy": bool(clean_billing) and has_access and not missing,
        "grant_skip_reason": BILLING_GRANT_SKIP_REASON if missing else "",
        "grant_fix_apply": f"PROJECT_ID={proj} bash scripts/apply.sh apply" if _PROJECT_ID.fullmatch(proj or "") else "",
        "grant_fix_where": apply_where(proj) if _PROJECT_ID.fullmatch(proj or "") else "",
        # BILLING-CARD-COMMANDS: all three grants, for the card's Cannot verify state.
        "grant_fix_commands": billing_grant_fix_commands(clean_billing, proj) if clean_billing else [],
    }


# ------------------------------------------------------------------------------
# Universal VCS Gateway Health
# ------------------------------------------------------------------------------
@router.get("/api/settings/vcs-status", dependencies=[require(ADMIN)])
def get_vcs_status_api(request: Request):
    proj = PROJECT_ID or os.getenv("PROJECT_ID", "") or os.getenv("GOOGLE_CLOUD_PROJECT", "")

    settings = None
    try:
        settings = get_platform_settings()
    except Exception:
        pass

    raw_provider = getattr(settings, "vcs_provider", None) or os.getenv("VCS_PROVIDER", "GITHUB")
    provider = str(raw_provider).strip().upper()

    ui_icons = {
        "GITHUB": "🐙",
        "SERVERLESS_GIT": "☁️",
        "SECURE_SOURCE_MANAGER": "🛡️",
        "GITLAB": "🦊",
        "BITBUCKET": "🪣",
    }
    display_names = {
        "GITHUB": "GitHub (Commercial / Enterprise)",
        "SERVERLESS_GIT": "Serverless Git (Cloud Run + GCS)",
        "SECURE_SOURCE_MANAGER": "Google Secure Source Manager (FedRAMP High)",
        "GITLAB": "GitLab",
        "BITBUCKET": "Bitbucket",
    }

    result = {
        "provider": provider,
        "provider_display_name": display_names.get(provider, provider),
        "ui_icon": ui_icons.get(provider, "📦"),
        "is_healthy": False,
        "auth_mode": "UNCONFIGURED",
        "target_owner": "",
        "authenticated_as": "",
        "app_id": "",
        "has_credentials": False,
        "credentials_detail": {
            "app_id_configured": False,
            "private_key_configured": False,
            "installation_id_configured": False,
            "pat_configured": False,
        },
        "rate_limit": {
            "limit": 0,
            "remaining": 0,
            "reset_in_minutes": 0,
        },
        "error_message": "",
        "error_code": "",          # GITHUB-ORG-ONLY: GITHUB_OWNER_NOT_ORGANIZATION when the owner is not an org
        "target_owner_type": "",   # GitHub account type of target_owner (Organization / User / NOT_FOUND)
        "project_id": proj,
    }

    if provider == "GITHUB":
        try:
            result["target_owner"] = get_default_github_owner(proj)
        except Exception:
            result["target_owner"] = os.getenv("GITHUB_OWNER", "")

        try:
            main_mod = get_caller_main_module()
            active_get_token_manager = getattr(main_mod, "get_token_manager", get_token_manager)
            active_get_github_token = getattr(main_mod, "get_github_token", get_github_token)

            mgr = None
            if active_get_token_manager is not None:
                mgr = active_get_token_manager(project_id=proj)
            elif GitHubTokenManager is not None:
                mgr = GitHubTokenManager(project_id=proj)
            elif TokenManager is not None:
                mgr = TokenManager(project_id=proj)

            if mgr is not None:
                creds = mgr._get_credentials()
            else:
                creds = {
                    "app_id": os.getenv("GITHUB_APP_ID", ""),
                    "installation_id": os.getenv("GITHUB_INSTALLATION_ID", ""),
                    "private_key": os.getenv("GITHUB_APP_PRIVATE_KEY", ""),
                    "pat": os.getenv("GITHUB_PAT") or os.getenv("GITHUB_TOKEN", ""),
                }

            app_id = creds.get("app_id") or os.getenv("GITHUB_APP_ID", "")
            inst_id = creds.get("installation_id") or os.getenv("GITHUB_INSTALLATION_ID", "")
            pk = creds.get("private_key") or os.getenv("GITHUB_APP_PRIVATE_KEY", "")
            pat = creds.get("pat") or os.getenv("GITHUB_PAT", "") or os.getenv("GITHUB_TOKEN", "")

            result["credentials_detail"]["app_id_configured"] = bool(app_id)
            result["credentials_detail"]["installation_id_configured"] = bool(inst_id)
            result["credentials_detail"]["private_key_configured"] = bool(pk)
            result["credentials_detail"]["pat_configured"] = bool(pat)

            if app_id and inst_id and pk:
                result["auth_mode"] = "GITHUB_APP"
                result["has_credentials"] = True
                result["app_id"] = str(app_id)
            elif pat:
                result["auth_mode"] = "PAT"
                result["has_credentials"] = True
            else:
                result["auth_mode"] = "UNCONFIGURED"
                result["has_credentials"] = False

            token = ""
            if callable(active_get_github_token):
                token = active_get_github_token(project_id=proj)
            elif mgr is not None:
                token = mgr.get_token()
            if not token and pat:
                token = pat

            result["github_configured"] = bool(result["credentials_detail"]["app_id_configured"] or result["credentials_detail"]["pat_configured"])
            result["serverless_git_available"] = True

            if token:
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "ProjectCastor-ControlCenter",
                }
                try:
                    rl_req = urllib.request.Request("https://api.github.com/rate_limit", headers=headers)
                    with urllib.request.urlopen(rl_req, timeout=5.0) as rl_resp:
                        if rl_resp.status == 200:
                            result["is_healthy"] = True
                            rl_data = json.loads(rl_resp.read().decode("utf-8"))
                            core = rl_data.get("resources", {}).get("core", {})
                            result["rate_limit"]["limit"] = core.get("limit", 0)
                            result["rate_limit"]["remaining"] = core.get("remaining", 0)
                            reset_epoch = core.get("reset", 0)
                            now_epoch = int(time.time())
                            result["rate_limit"]["reset_in_minutes"] = max(0, int((reset_epoch - now_epoch) / 60))
                except urllib.error.HTTPError as http_err:
                    result["is_healthy"] = False
                    if http_err.code in (401, 403):
                        result["error_message"] = f"GitHub API rejected credentials (HTTP {http_err.code})."
                    else:
                        result["error_message"] = f"GitHub API returned HTTP {http_err.code}."
                except Exception as net_err:
                    result["is_healthy"] = False
                    result["error_message"] = str(net_err)

                if result["is_healthy"]:
                    try:
                        user_req = urllib.request.Request("https://api.github.com/user", headers=headers)
                        with urllib.request.urlopen(user_req, timeout=5.0) as user_resp:
                            if user_resp.status == 200:
                                udata = json.loads(user_resp.read().decode("utf-8"))
                                result["authenticated_as"] = udata.get("login") or udata.get("name") or ""
                    except Exception:
                        pass

                # GITHUB-ORG-ONLY: the target owner must be an organization (an App installation token cannot create
                # repositories under a personal account). Decided from the account `type` GitHub returns.
                owner = (result.get("target_owner") or "").strip()
                if result["is_healthy"] and owner:
                    owner_type = ""
                    try:
                        owner_req = urllib.request.Request(
                            f"https://api.github.com/users/{urllib.parse.quote(owner, safe='')}", headers=headers)
                        with urllib.request.urlopen(owner_req, timeout=5.0) as owner_resp:
                            if owner_resp.status == 200:
                                owner_type = str(json.loads(owner_resp.read().decode("utf-8")).get("type") or "")
                    except urllib.error.HTTPError as owner_err:
                        if owner_err.code == 404:
                            owner_type = "NOT_FOUND"
                    except Exception:
                        pass   # unknown (network): no verdict, the status stays as measured
                    result["target_owner_type"] = owner_type
                    if owner_type and owner_type != "Organization":
                        found = ("is a personal GitHub account" if owner_type == "User"
                                 else "does not exist on GitHub" if owner_type == "NOT_FOUND"
                                 else f"is a GitHub account of type '{owner_type}'")
                        result["is_healthy"] = False
                        result["error_code"] = "GITHUB_OWNER_NOT_ORGANIZATION"
                        result["error_message"] = (
                            f"GitHub VCS needs an organization: '{owner}' {found}. Install the StackVend GitHub App "
                            f"on an organization and set it as the GitHub owner; personal accounts are not supported.")
            else:
                result["is_healthy"] = False
                if not result["has_credentials"]:
                    result["error_message"] = "No GitHub credentials configured in Secret Manager or environment. Serverless Git (☁️) is available as the standard zero-dependency default."
                else:
                    result["error_message"] = "Unable to generate token from configured credentials."
        except Exception as ex:
            result["is_healthy"] = False
            result["error_message"] = str(ex)

    elif provider == "SERVERLESS_GIT":
        result["auth_mode"] = "GCP_IAM"
        result["has_credentials"] = True
        result["is_healthy"] = True
        result["target_owner"] = proj
        result["serverless_git_available"] = True
        gh_app_id = os.getenv("GITHUB_APP_ID", "")
        gh_pat = os.getenv("GITHUB_PAT") or os.getenv("GITHUB_TOKEN", "")
        result["github_configured"] = bool(gh_app_id or gh_pat)

    return result


# ------------------------------------------------------------------------------
# Multi-Folder GCP Management Endpoints
# ------------------------------------------------------------------------------
_CACHED_VENDING_SERVICE_URL: Optional[str] = None
_CACHED_TERRAFORM_SERVICE_URL: Optional[str] = None


def get_vending_service_url(request: Optional[Request] = None) -> Optional[str]:
    """VENDING_SERVICE_URL only (set by Terraform / deploy-services.sh on both installs).
    FD-4N / FD25-18 + lane-5 red-team: when it is unset this FAILS CLOSED (None). The URL is never derived from
    Host / X-Forwarded-Host or any other request header (ID tokens would follow a client-chosen host).
    `request` is accepted for call-site compatibility and ignored."""
    env_url = os.getenv("VENDING_SERVICE_URL")
    if env_url and env_url.strip():
        return env_url.strip().rstrip("/")
    logger.error("VENDING_SERVICE_URL is not configured; vending calls are refused (fail closed).")
    return None


def _discover_cloud_run_service_url(service: str) -> Optional[str]:
    """Cloud Run Admin API lookup of a peer service in THIS project and THIS instance's region (metadata server).
    No region default (Invariant 3); any failure => None."""
    proj_id = (PROJECT_ID or os.getenv("PROJECT_ID") or "").strip()
    if not proj_id or not os.getenv("K_SERVICE"):
        return None
    try:
        import google.auth
        import requests as _requests
        from google.auth.transport.requests import AuthorizedSession
        region_path = _requests.get(
            "http://metadata.google.internal/computeMetadata/v1/instance/region",
            headers={"Metadata-Flavor": "Google"}, timeout=2,
        ).text.strip()
        region = region_path.rsplit("/", 1)[-1]
        if not region:
            return None
        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        resp = AuthorizedSession(credentials).get(
            f"https://run.googleapis.com/v2/projects/{proj_id}/locations/{region}/services/{service}", timeout=5.0)
        if resp.status_code == 200:
            uri = (resp.json() or {}).get("uri")
            if isinstance(uri, str) and uri.startswith("https://"):
                return uri.rstrip("/")
    except Exception as api_err:  # noqa: BLE001
        logger.warning(f"Cloud Run Admin API discovery of '{service}' failed: {api_err}")
    return None


def get_terraform_service_url(request: Optional[Request] = None) -> Optional[str]:
    """TERRAFORM_SERVICE_URL / TERRAFORM_MCP_URL, else Cloud Run Admin API discovery of mcp-terraform-server.
    Never derived from request headers (FD25-18). `request` is accepted for compatibility and ignored."""
    global _CACHED_TERRAFORM_SERVICE_URL
    env_url = os.getenv("TERRAFORM_SERVICE_URL") or os.getenv("TERRAFORM_MCP_URL")
    if env_url and env_url.strip():
        return env_url.strip().rstrip("/")
    if _CACHED_TERRAFORM_SERVICE_URL:
        return _CACHED_TERRAFORM_SERVICE_URL
    found = _discover_cloud_run_service_url("mcp-terraform-server")
    if found:
        _CACHED_TERRAFORM_SERVICE_URL = found
    return found


GIT_SERVER_SERVICE = "castor-git-server"
GIT_SERVER_URL_UNKNOWN = "GIT_SERVER_URL_UNKNOWN"
_CACHED_GIT_SERVER_URL: Optional[str] = None


def get_git_server_url() -> Optional[str]:
    """FALLBACK-URLS (fail-loudly 1.4): the Serverless Git server's URL from a typed source only -- the
    GIT_SERVER_URL / CASTOR_GIT_SERVER_URL env (the platform Terraform passes the git server's `uri`), else the
    platform setting `governance.git_server_url`, else a Cloud Run Admin API lookup of castor-git-server in this
    project and this instance's region. None when none of them knows it (callers report GIT_SERVER_URL_UNKNOWN);
    never a URL built from the project id and a hardcoded region (invariant 3)."""
    global _CACHED_GIT_SERVER_URL
    env_url = os.getenv("CASTOR_GIT_SERVER_URL") or os.getenv("GIT_SERVER_URL")
    if env_url and env_url.strip():
        return env_url.strip().rstrip("/")
    try:
        ps = get_platform_settings()
        configured = getattr(ps, "git_server_url", None) or getattr(getattr(ps, "governance", None),
                                                                    "git_server_url", None)
    except Exception as ps_err:  # noqa: BLE001 - unreadable settings: the next typed source decides
        logger.warning(f"Platform settings unreadable for the git server URL ({type(ps_err).__name__})")
        configured = None
    if isinstance(configured, str) and configured.strip():
        return configured.strip().rstrip("/")
    if _CACHED_GIT_SERVER_URL:
        return _CACHED_GIT_SERVER_URL
    found = _discover_cloud_run_service_url(GIT_SERVER_SERVICE)
    if found:
        _CACHED_GIT_SERVER_URL = found
    return found


def get_google_id_token(audience: str) -> Optional[str]:
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token
        auth_req = google_requests.Request()
        return id_token.fetch_id_token(auth_req, audience)
    except Exception as e:
        logger.debug(f"Could not fetch Google OIDC ID token for audience '{audience}': {e}")
        return None


def make_vending_request(
    method: str,
    path: str,
    json_body: Optional[Dict[str, Any]] = None,
    timeout: float = 60.0,
    request: Optional[Request] = None,
) -> Optional[Any]:
    main_mod = get_caller_main_module()
    active_get_vending = getattr(main_mod, "get_vending_service_url", get_vending_service_url)
    active_get_token = getattr(main_mod, "get_google_id_token", get_google_id_token)

    vending_url = active_get_vending(request)
    if not vending_url:
        return None

    import httpx
    clean_path = path.lstrip("/")
    target_url = f"{vending_url.rstrip('/')}/{clean_path}"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    token = active_get_token(vending_url)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    with httpx.Client(timeout=timeout) as client:
        return client.request(
            method=method.upper(),
            url=target_url,
            json=json_body,
            headers=headers,
        )


def make_terraform_request(
    method: str,
    path: str,
    json_body: Optional[Dict[str, Any]] = None,
    timeout: float = 120.0,
    request: Optional[Request] = None,
) -> Optional[Any]:
    main_mod = get_caller_main_module()
    active_get_tf = getattr(main_mod, "get_terraform_service_url", get_terraform_service_url)
    active_get_token = getattr(main_mod, "get_google_id_token", get_google_id_token)

    tf_url = active_get_tf(request)
    if not tf_url:
        return None

    import httpx
    clean_path = path.lstrip("/")
    target_url = f"{tf_url.rstrip('/')}/{clean_path}"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    token = active_get_token(tf_url)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    with httpx.Client(timeout=timeout) as client:
        return client.request(
            method=method.upper(),
            url=target_url,
            json=json_body,
            headers=headers,
        )


@router.get("/api/settings/folders", response_model=List[ManagedFolder], dependencies=[require(ADMIN)])
def list_managed_folders_api(request: Request):
    folders: List[ManagedFolder] = []
    if db:
        try:
            docs = list(db.collection("managed_folders").stream())
            for doc in docs:
                data = doc.to_dict() or {}
                if data.get("status") != "DISABLED":
                    folders.append(ManagedFolder(**data))
        except Exception as e:
            logger.warning(f"Could not load managed folders from Firestore: {e}")

    if not folders:
        # FD-4AY: the root comes only from MANAGED_WORKLOADS_FOLDER_ID; no hardcoded default.
        try:
            root_folder = managed_root_folder()
        except FolderConfigError as cfg_err:
            raise HTTPException(status_code=503, detail=str(cfg_err))
        root_num = root_folder.replace("folders/", "")
        folders.append(ManagedFolder(
            folder_id=root_folder,
            folder_number=root_num,
            display_name="Managed workloads root folder",
            description="The managed workloads root folder set at install time",
            parent_folder_id=None,
            is_default=True,
            status="ACTIVE",
            created_at=datetime.now(timezone.utc).isoformat(),
            created_by="system",
        ))

    folders.sort(key=lambda f: (not f.is_default, f.display_name.lower()))
    return folders


@router.post("/api/settings/folders", response_model=ManagedFolder, dependencies=[require(ADMIN)])
def create_managed_folder_api(req: CreateFolderRequest, request: Request):
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin-console")
    now_iso = datetime.now(timezone.utc).isoformat()
    clean_name = req.display_name.strip()
    if not clean_name:
        raise HTTPException(status_code=400, detail="Folder display name cannot be empty.")

    # FD-4N (red-team H9) / FD-4AY: the parent must be the Terraform-configured managed root or a folder below it
    # (CRM v3 parent walk, fail closed). organizations/* and arbitrary folders are refused. No hardcoded root.
    try:
        root_folder = managed_root_folder()
    except FolderConfigError as cfg_err:
        raise HTTPException(status_code=503, detail=str(cfg_err))
    parent_folder = normalize_folder_name(req.parent_folder_id) if req.parent_folder_id else root_folder
    if not parent_folder or not is_descendant_of_root(parent_folder):
        raise HTTPException(
            status_code=400,
            detail=f"Parent folder must be the managed workloads root ({root_folder}) or one of its sub-folders.",
        )

    main_mod = get_caller_main_module()
    active_get_vending = getattr(main_mod, "get_vending_service_url", get_vending_service_url)
    if not active_get_vending(request):
        raise HTTPException(status_code=503, detail="VENDING_SERVICE_URL is not configured; cannot create a GCP folder.")

    active_make_vending_req = getattr(main_mod, "make_vending_request", make_vending_request)
    try:
        resp = active_make_vending_req(
            method="POST",
            path="/folders",
            json_body={"display_name": clean_name, "parent_folder_id": parent_folder},
            timeout=60.0,
            request=request,
        )
    except Exception as v_err:
        logger.error(f"Vending service folder call error: {v_err}")
        raise HTTPException(status_code=502, detail=f"Failed to communicate with Project Vending Service: {v_err}")
    if resp is None or resp.status_code != 200:
        code = getattr(resp, "status_code", None)
        err_msg = f"Vending service folder creation failed (HTTP {code}): {getattr(resp, 'text', '')}"
        logger.error(err_msg)
        raise HTTPException(status_code=code if code in (400, 403, 404, 409) else 502, detail=err_msg)
    v_data = resp.json() or {}
    folder_res_name = normalize_folder_name(str(v_data.get("folder_id") or ""))
    if not folder_res_name:
        raise HTTPException(status_code=502, detail="Vending service returned no folder id; nothing was recorded.")
    folder_num = str(v_data.get("folder_number") or folder_res_name.replace("folders/", ""))
    logger.info(f"Successfully created GCP Resource Manager folder '{clean_name}' -> {folder_res_name}")

    doc_key = folder_res_name.replace("folders/", "folders_")
    folder_record = ManagedFolder(
        folder_id=folder_res_name,
        folder_number=folder_num or folder_res_name.replace("folders/", ""),
        display_name=clean_name,
        description=req.description or "",
        parent_folder_id=parent_folder,
        is_default=req.is_default,
        status="ACTIVE",
        created_at=now_iso,
        created_by=admin_email,
    )

    if db:
        try:
            if req.is_default:
                existing_docs = list(db.collection("managed_folders").where("is_default", "==", True).stream())
                for ed in existing_docs:
                    ed.reference.set({"is_default": False}, merge=True)

            db.collection("managed_folders").document(doc_key).set(folder_record.model_dump())
            logger.info(f"Created managed folder '{folder_res_name}' ({clean_name}) in Firestore by {admin_email}")
        except Exception as fs_err:
            logger.error(f"Failed to record managed folder in Firestore: {fs_err}")
            raise HTTPException(status_code=500, detail=f"Failed to save folder to Firestore: {fs_err}")

    return folder_record


@router.post("/api/settings/folders/{folder_id:path}/set-default", dependencies=[require(ADMIN)])
def set_default_managed_folder_api(folder_id: str, request: Request):
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin-console")
    clean_fid = folder_id.strip()
    if not clean_fid.startswith("folders/"):
        clean_fid = f"folders/{clean_fid}"
    doc_key = clean_fid.replace("folders/", "folders_")

    if db:
        try:
            existing_docs = list(db.collection("managed_folders").stream())
            target_found = False
            for doc in existing_docs:
                if doc.id == doc_key or (doc.to_dict() or {}).get("folder_id") == clean_fid:
                    doc.reference.set({"is_default": True, "updated_at": datetime.now(timezone.utc).isoformat()}, merge=True)
                    target_found = True
                else:
                    if (doc.to_dict() or {}).get("is_default"):
                        doc.reference.set({"is_default": False}, merge=True)
            if not target_found:
                raise HTTPException(status_code=404, detail=f"Folder '{clean_fid}' not found in managed folders.")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to set default folder: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    return {"status": "SUCCESS", "default_folder_id": clean_fid, "updated_by": admin_email}


@router.delete("/api/settings/folders/{folder_id:path}", dependencies=[require(ADMIN)])
def delete_managed_folder_api(folder_id: str, request: Request):
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin-console")
    clean_fid = folder_id.strip()
    if not clean_fid.startswith("folders/"):
        clean_fid = f"folders/{clean_fid}"
    doc_key = clean_fid.replace("folders/", "folders_")

    if db:
        try:
            workloads = list(db.collection("workloads").where("folder_id", "==", clean_fid).stream())
            active_workloads = [w.id for w in workloads if (w.to_dict() or {}).get("status") not in _CLOSED_WORKLOAD_STATUSES]
            if active_workloads:
                raise HTTPException(
                    status_code=400,
                    detail=f"Cannot delete folder '{clean_fid}': {len(active_workloads)} active workload(s) reside in it ({', '.join(active_workloads[:3])}). Decommission them first.",
                )

            doc_ref = db.collection("managed_folders").document(doc_key)
            doc = doc_ref.get()
            if not doc.exists:
                raise HTTPException(status_code=404, detail=f"Folder '{clean_fid}' not found.")

            doc_ref.set({
                "status": "DISABLED",
                "is_default": False,
                "disabled_at": datetime.now(timezone.utc).isoformat(),
                "disabled_by": admin_email,
            }, merge=True)
            logger.info(f"Marked folder '{clean_fid}' as DISABLED by {admin_email}")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to delete/disable folder: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    return {"status": "SUCCESS", "message": f"Folder '{clean_fid}' successfully disabled.", "disabled_by": admin_email}


# ------------------------------------------------------------------------------
# IPAM Allocations
# ------------------------------------------------------------------------------
@router.get("/api/ipam/allocations", dependencies=[require(ADMIN)])
def get_ipam_allocations_endpoint(request: Request):
    verify_admin_access(request)
    try:
        try:
            from shared.ipam import CastorIPAMEngine
        except ImportError:
            from .shared.ipam import CastorIPAMEngine

        supernet = "10.100.0.0/16"
        try:
            settings = get_platform_settings()
            if settings and hasattr(settings, "orchestration"):
                supernet = getattr(settings.orchestration, "ipam_supernet_cidr", "10.100.0.0/16")
        except Exception:
            pass

        engine = CastorIPAMEngine(db=db, supernet_cidr=supernet)
        allocations = engine.list_allocations(include_decommissioned=True)
        stats = engine.get_pool_statistics()
        return {
            "status": "SUCCESS",
            "allocations": [a.model_dump() if hasattr(a, "model_dump") else a.dict() for a in allocations],
            "stats": stats,
        }
    except Exception as e:
        logger.error(f"Error fetching IPAM allocations: {e}")
        return {
            "status": "ERROR",
            "allocations": [],
            "stats": {
                "supernet_cidr": "10.100.0.0/16",
                "total_capacity_slash_28": 4096,
                "allocated_count": 0,
                "reserved_decommissioned_count": 0,
                "available_count": 4096,
                "utilization_pct": 0.0,
                "total_records": 0,
            },
            "error": str(e),
        }


# ------------------------------------------------------------------------------
# Custom Golden Modules Catalog Endpoints
# ------------------------------------------------------------------------------

@router.get("/api/settings/modules", response_model=CustomModulesListResponse, dependencies=[require(ADMIN)])
def list_custom_modules_endpoint(request: Request):
    verify_admin_access(request)
    custom_modules: List[CustomGoldenModuleRecord] = []
    if db:
        try:
            docs = db.collection("custom_modules").stream()
            for doc in docs:
                data = doc.to_dict() or {}
                if "module_id" not in data:
                    data["module_id"] = doc.id
                custom_modules.append(CustomGoldenModuleRecord(**data))
        except Exception as e:
            logger.error(f"Error listing custom modules: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to list custom modules: {e}")

    # Sort custom modules alphabetically by module_id
    custom_modules.sort(key=lambda m: m.module_id)

    # Active overrides mapping: {override_builtin_name: custom_module_name_or_id}
    active_overrides: Dict[str, str] = {}
    for m in custom_modules:
        if m.is_active and m.override_builtin:
            active_overrides[m.override_builtin] = m.name or m.module_id

    # Load built-in native modules dynamically from code/contracts
    builtin_records: List[CustomGoldenModuleRecord] = []
    try:
        builtin_raw = get_builtin_modules()
        for b in builtin_raw:
            b_dict = dict(b)
            if b_dict.get("module_id") in active_overrides:
                b_dict["overridden_by"] = active_overrides[b_dict["module_id"]]
            builtin_records.append(CustomGoldenModuleRecord(**b_dict))
    except Exception as e:
        logger.warning(f"Failed to load built-in modules: {e}")

    # Unified list: built-in modules followed by custom modules
    all_modules = builtin_records + custom_modules

    return CustomModulesListResponse(
        custom_modules=custom_modules,
        modules=all_modules,
        builtin_modules_count=len(builtin_records),
        total_custom=len(custom_modules),
    )


def _module_exposure_check(module_id: str, source_type: Any, hcl_files: Optional[Dict[str, str]],
                           source_url: Optional[str], repo_path: Optional[str], version_tag: Optional[str]) -> None:
    """FD-4CX: raise RegisteredModulePublicExposureError when the module's own files grant public access (parsed,
    shared/module_exposure.py). DIRECT_CODE: the stored / submitted hcl_files. REMOTE_GIT: every .tf / .tf.json file
    of the module directory at the ref the contract was read from (ValueError when it cannot be read completely)."""
    if source_type == CustomModuleSourceType.REMOTE_GIT:
        files = fetch_remote_module_files(source_url or "", repo_path or "", version_tag or "main")
    else:
        files = dict(hcl_files or {})
    check_registered_module(module_id, files)


def _refuse_public_module(module_id: str, source_type: Any, hcl_files: Optional[Dict[str, str]],
                          source_url: Optional[str], repo_path: Optional[str], version_tag: Optional[str]) -> None:
    """FD-4CX (register / update): the exposure check as an HTTP refusal; nothing has been written yet."""
    try:
        _module_exposure_check(module_id, source_type, hcl_files, source_url, repo_path, version_tag)
    except RegisteredModulePublicExposureError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ModuleExposureUnavailable as e:
        raise HTTPException(status_code=503, detail=f"Module public-access check unavailable: {e}")
    except RemoteModuleReadError as e:   # RT F4: a failed read (retry later) vs a repository too large to read whole
        raise HTTPException(status_code=503 if e.transient else 400,
                            detail=f"Module '{module_id}' cannot be checked for public access: {e}")
    except Exception as e:  # REMOTE_GIT: the module directory could not be read, so it cannot be checked
        raise HTTPException(status_code=400, detail=f"Module '{module_id}' cannot be checked for public access: {e}")


@router.post("/api/settings/modules", response_model=CustomGoldenModuleRecord, dependencies=[require(ADMIN)])
@router.post("/api/settings/modules/register", response_model=CustomGoldenModuleRecord, dependencies=[require(ADMIN)])
def register_custom_module_endpoint(payload: Any = None, request: Any = None):
    if hasattr(payload, "state") and not hasattr(request, "state"):
        payload, request = request, payload
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin")
    clean_id = payload.module_id.strip().lower()

    if not clean_id or not re.match(r'^[a-z0-9_-]+$', clean_id):
        raise HTTPException(
            status_code=400,
            detail="Module ID must be alphanumeric with dashes or underscores (e.g. 'acme-secure-vpc')."
        )

    # Check for existing record
    if db:
        existing = db.collection("custom_modules").document(clean_id).get()
        if existing.exists:
            raise HTTPException(status_code=409, detail=f"Custom module '{clean_id}' already exists.")

        # Check if another active custom module already overrides this built-in
        if payload.override_builtin:
            clean_override = payload.override_builtin.strip()
            conflicts = []
            try:
                query = db.collection("custom_modules").where("is_active", "==", True).where("override_builtin", "==", clean_override)
                for doc in query.stream():
                    if doc.id != clean_id:
                        doc_data = doc.to_dict() or {}
                        conflicts.append(doc_data.get("name") or doc.id)
            except Exception as e:
                logger.warning(f"Could not check override conflicts: {e}")

            if conflicts:
                raise HTTPException(
                    status_code=409,
                    detail=f"Built-in module '{clean_override}' is already actively overridden by custom module '{conflicts[0]}'."
                )

    inputs: List[Dict[str, Any]] = []
    outputs: List[Dict[str, Any]] = []

    if payload.source_type == CustomModuleSourceType.DIRECT_CODE:
        if not payload.hcl_files:
            raise HTTPException(
                status_code=400,
                detail="Direct code registration requires at least 'main.tf' or 'variables.tf' in hcl_files."
            )
        vars_hcl = payload.hcl_files.get("variables.tf") or payload.hcl_files.get("main.tf", "")
        outs_hcl = payload.hcl_files.get("outputs.tf", "")
        try:
            inputs, outputs = parse_hcl_variables_and_outputs(vars_hcl, outs_hcl)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse HCL code: {e}")
    else:
        if not payload.source_url:
            raise HTTPException(status_code=400, detail="Remote Git registration requires 'source_url'.")
        try:
            inputs, outputs = fetch_and_inspect_github_module(
                source_url=payload.source_url,
                repo_path=payload.repo_path or "",
                version_tag=payload.version_tag or "main",
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to inspect remote Git module: {e}")

    # FD-4CX: refuse a module that grants public access by itself (nothing is written)
    _refuse_public_module(clean_id, payload.source_type, payload.hcl_files, payload.source_url,
                          payload.repo_path, payload.version_tag)

    now_iso = datetime.now(timezone.utc).isoformat()
    record = CustomGoldenModuleRecord(
        module_id=clean_id,
        name=payload.name.strip() or clean_id,
        source_type=payload.source_type,
        category=payload.category,
        description=payload.description or "",
        source_url=payload.source_url,
        repo_path=payload.repo_path or "",
        version_tag=payload.version_tag or "v1.0.0",
        hcl_files=payload.hcl_files,
        override_builtin=payload.override_builtin,
        is_heavy_stateful=payload.is_heavy_stateful,
        timeout_minutes=payload.timeout_minutes,
        inputs=inputs,
        variables=inputs,
        outputs=outputs,
        is_active=True,
        sync_status="VERIFIED",
        created_by=admin_email,
        created_at=now_iso,
        last_synced_at=now_iso,
    )

    if db:
        try:
            doc_data = record.model_dump() if hasattr(record, "model_dump") else record.dict()
            db.collection("custom_modules").document(clean_id).set(doc_data)
            logger.info(f"Registered custom golden module '{clean_id}' by {admin_email}")
        except Exception as e:
            logger.error(f"Failed to save custom module '{clean_id}' to Firestore: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to save custom module: {e}")

    return record


@router.post("/api/settings/modules/{module_id}/sync", response_model=CustomGoldenModuleRecord, dependencies=[require(ADMIN)])
def sync_custom_module_endpoint(module_id: Any = None, request: Any = None):
    if hasattr(module_id, "state") and not hasattr(request, "state"):
        module_id, request = request, module_id
    verify_admin_access(request)
    clean_id = module_id.strip().lower()

    # If syncing a built-in module, refresh and return in-memory contract (a built-in whose files cannot be read
    # comes back with sync_status ERROR and its error_message, row CC-MI-2)
    builtin_error: Optional[Exception] = None
    try:
        builtin_modules_map = {b["module_id"]: b for b in get_builtin_modules(force_refresh=True)}
        if clean_id in builtin_modules_map:
            return CustomGoldenModuleRecord(**builtin_modules_map[clean_id])
    except Exception as e:
        builtin_error = e
        logger.warning(f"Error checking built-in sync: {e}")

    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    doc_ref = db.collection("custom_modules").document(clean_id)
    doc = doc_ref.get()
    if not doc.exists:
        if builtin_error is not None:  # it may be a built-in: say why it could not be synced, not "not found"
            raise HTTPException(status_code=503, detail=f"Built-in module catalog unavailable, so '{clean_id}' "
                                                        f"could not be synced: {builtin_error}")
        raise HTTPException(status_code=404, detail=f"Custom module '{clean_id}' not found.")

    data = doc.to_dict() or {}
    record = CustomGoldenModuleRecord(**data)
    inputs: List[Dict[str, Any]] = []
    outputs: List[Dict[str, Any]] = []

    try:
        if record.source_type == CustomModuleSourceType.DIRECT_CODE:
            vars_hcl = record.hcl_files.get("variables.tf") or record.hcl_files.get("main.tf", "")
            outs_hcl = record.hcl_files.get("outputs.tf", "")
            inputs, outputs = parse_hcl_variables_and_outputs(vars_hcl, outs_hcl)
        else:
            inputs, outputs = fetch_and_inspect_github_module(
                source_url=record.source_url or "",
                repo_path=record.repo_path or "",
                version_tag=record.version_tag or "main",
            )
        # FD-4CX: a module that grants public access by itself is marked ERROR with the precise reason (below)
        _module_exposure_check(clean_id, record.source_type, record.hcl_files, record.source_url,
                               record.repo_path, record.version_tag)
        now_iso = datetime.now(timezone.utc).isoformat()
        doc_ref.set({
            "inputs": inputs,
            "variables": inputs,
            "outputs": outputs,
            "sync_status": "VERIFIED",
            "error_message": None,
            "last_synced_at": now_iso,
        }, merge=True)
        record.inputs = inputs
        record.variables = inputs
        record.outputs = outputs
        record.sync_status = "VERIFIED"
        record.last_synced_at = now_iso
        record.error_message = None
        return record
    except Exception as e:
        # FD-4CX RT F6 / F4: a platform defect (no HCL parser) or a failed repository read says nothing about the
        # module, so it is a 503 and the stored record is left as it was (never marked ERROR for it)
        if isinstance(e, ModuleExposureUnavailable) or (isinstance(e, RemoteModuleReadError) and e.transient):
            raise HTTPException(status_code=503, detail=f"Module '{clean_id}' could not be checked now: {e}")
        logger.warning(f"Sync error for custom module '{clean_id}': {e}")
        doc_ref.set({
            "sync_status": "ERROR",
            "error_message": str(e),
            "last_synced_at": datetime.now(timezone.utc).isoformat(),
        }, merge=True)
        record.sync_status = "ERROR"
        record.error_message = str(e)
        return record


def _builtin_module_ids_or_refuse(action: str, clean_id: str) -> set:
    """Built-in module ids for the immutability checks (row CC-MI-2). If the built-in catalog itself cannot be built,
    the change is refused with a clear 503: it cannot be shown that `clean_id` is not a built-in (never a bare 500)."""
    try:
        return {b["module_id"] for b in get_builtin_modules()}
    except Exception as e:
        logger.error(f"Built-in module catalog unavailable; refusing to {action} '{clean_id}': {e}")
        raise HTTPException(
            status_code=503,
            detail=f"Built-in module catalog unavailable, so '{clean_id}' cannot be checked before {action}: {e}",
        )


@router.patch("/api/settings/modules/{module_id}", response_model=CustomGoldenModuleRecord, dependencies=[require(ADMIN)])
def update_custom_module_endpoint(module_id: str, payload: UpdateCustomModuleRequest, request: Request):
    verify_admin_access(request)
    clean_id = module_id.strip().lower()

    builtin_ids = _builtin_module_ids_or_refuse("update", clean_id)
    if clean_id in builtin_ids:
        raise HTTPException(status_code=400, detail=f"Cannot modify native platform module '{clean_id}'. Built-in modules are immutable.")

    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    doc_ref = db.collection("custom_modules").document(clean_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Custom module '{clean_id}' not found.")

    data = doc.to_dict() or {}
    record = CustomGoldenModuleRecord(**data)

    updates: Dict[str, Any] = {}
    if payload.name is not None:
        updates["name"] = payload.name.strip()
        record.name = payload.name.strip()
    if payload.description is not None:
        updates["description"] = payload.description.strip()
        record.description = payload.description.strip()
    if payload.category is not None:
        updates["category"] = payload.category.value
        record.category = payload.category
    if payload.is_active is not None:
        updates["is_active"] = payload.is_active
        record.is_active = payload.is_active
    if payload.override_builtin is not None:
        updates["override_builtin"] = payload.override_builtin.strip() if payload.override_builtin else None
        record.override_builtin = updates["override_builtin"]
        if updates["override_builtin"] and db:
            conflicts = []
            try:
                query = db.collection("custom_modules").where("is_active", "==", True).where("override_builtin", "==", updates["override_builtin"])
                for doc in query.stream():
                    if doc.id != clean_id:
                        doc_data = doc.to_dict() or {}
                        conflicts.append(doc_data.get("name") or doc.id)
            except Exception as e:
                logger.warning(f"Could not check override conflicts: {e}")

            if conflicts:
                raise HTTPException(
                    status_code=409,
                    detail=f"Built-in module '{updates['override_builtin']}' is already actively overridden by custom module '{conflicts[0]}'."
                )
    if payload.is_heavy_stateful is not None:
        updates["is_heavy_stateful"] = payload.is_heavy_stateful
        record.is_heavy_stateful = payload.is_heavy_stateful
    if payload.timeout_minutes is not None:
        updates["timeout_minutes"] = payload.timeout_minutes
        record.timeout_minutes = payload.timeout_minutes
    if payload.version_tag is not None:
        updates["version_tag"] = payload.version_tag.strip()
        record.version_tag = payload.version_tag.strip()
        if record.source_type == CustomModuleSourceType.REMOTE_GIT:   # FD-4CX: the new ref's files are checked
            _refuse_public_module(clean_id, record.source_type, None, record.source_url, record.repo_path,
                                  record.version_tag)
    if payload.hcl_files is not None:
        vars_hcl = payload.hcl_files.get("variables.tf") or payload.hcl_files.get("main.tf", "")
        outs_hcl = payload.hcl_files.get("outputs.tf", "")
        try:  # unparseable HCL: reject the update (nothing is written), same as registration
            inputs, outputs = parse_hcl_variables_and_outputs(vars_hcl, outs_hcl)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse HCL code: {e}")
        # FD-4CX: new code that grants public access by itself is refused (nothing is written)
        _refuse_public_module(clean_id, CustomModuleSourceType.DIRECT_CODE, payload.hcl_files, None, None, None)
        updates["hcl_files"] = payload.hcl_files
        record.hcl_files = payload.hcl_files
        updates["inputs"] = inputs
        updates["variables"] = inputs
        updates["outputs"] = outputs
        record.inputs = inputs
        record.variables = inputs
        record.outputs = outputs
        now_iso = datetime.now(timezone.utc).isoformat()
        updates["last_synced_at"] = now_iso
        updates["sync_status"] = "VERIFIED"
        record.last_synced_at = now_iso
        record.sync_status = "VERIFIED"

    if updates:
        doc_ref.set(updates, merge=True)
        logger.info(f"Updated custom module '{clean_id}' fields: {list(updates.keys())}")

    return record


@router.delete("/api/settings/modules/{module_id}", dependencies=[require(ADMIN)])
def delete_custom_module_endpoint(module_id: Any = None, request: Any = None):
    if hasattr(module_id, "state") and not hasattr(request, "state"):
        module_id, request = request, module_id
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin")
    clean_id = module_id.strip().lower()

    builtin_ids = _builtin_module_ids_or_refuse("delete", clean_id)
    if clean_id in builtin_ids:
        raise HTTPException(status_code=400, detail=f"Cannot delete native platform module '{clean_id}'. Built-in modules are immutable.")

    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    doc_ref = db.collection("custom_modules").document(clean_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Custom module '{clean_id}' not found.")

    doc_ref.delete()
    logger.info(f"Deleted custom module '{clean_id}' by {admin_email}")
    return {"status": "SUCCESS", "message": f"Module '{clean_id}' deleted successfully.", "module_id": clean_id, "deleted": True}


# ------------------------------------------------------------------------------
# Agentic Skills Catalog Endpoints
# ------------------------------------------------------------------------------

@router.get("/api/settings/skills", response_model=SkillsListResponse, dependencies=[require(ADMIN)])
def list_skills_endpoint(request: Request):
    verify_admin_access(request)
    custom_skills: List[AgentSkillRecord] = []
    if db:
        try:
            docs = db.collection("custom_skills").stream()
            for doc in docs:
                data = doc.to_dict() or {}
                if "skill_id" not in data:
                    data["skill_id"] = doc.id
                custom_skills.append(AgentSkillRecord(**data))
        except Exception as e:
            logger.error(f"Error listing custom skills: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to list custom skills: {e}")

    # Sort custom skills alphabetically by skill_id
    custom_skills.sort(key=lambda s: s.skill_id)

    # Load built-in native skills
    builtin_records: List[AgentSkillRecord] = []
    try:
        builtin_raw = get_builtin_skills()
        for b in builtin_raw:
            builtin_records.append(AgentSkillRecord(**b))
    except Exception as e:
        logger.warning(f"Failed to load built-in skills: {e}")

    # Unified list: built-in skills followed by custom skills
    all_skills = builtin_records + custom_skills

    return SkillsListResponse(
        skills=all_skills,
        custom_skills=custom_skills,
        builtin_skills_count=len(builtin_records),
        total_custom=len(custom_skills),
    )


@router.post("/api/settings/skills", response_model=AgentSkillRecord, dependencies=[require(ADMIN)])
def create_skill_endpoint(payload: Any = None, request: Any = None):
    if hasattr(payload, "state") and not hasattr(request, "state"):
        payload, request = request, payload
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin")

    clean_id = getattr(payload, "skill_id", "").strip().lower()
    if not clean_id or not re.match(r"^[a-z0-9][a-z0-9-_]{1,63}$", clean_id):
        raise HTTPException(
            status_code=400,
            detail="Skill ID must be 2-64 lowercase alphanumeric characters, dashes, or underscores."
        )

    # Check collision with built-in skills
    try:
        builtin_ids = {b["skill_id"] for b in get_builtin_skills()}
    except Exception as e:
        logger.warning(f"Error fetching built-in skills: {e}")
        builtin_ids = set()

    if clean_id in builtin_ids:
        raise HTTPException(
            status_code=400,
            detail=f"Skill ID '{clean_id}' collides with a native built-in platform skill."
        )

    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    doc_ref = db.collection("custom_skills").document(clean_id)
    if doc_ref.get().exists:
        raise HTTPException(status_code=409, detail=f"Skill '{clean_id}' is already registered.")

    now_iso = datetime.now(timezone.utc).isoformat()
    record = AgentSkillRecord(
        skill_id=clean_id,
        name=payload.name.strip(),
        source_type=SkillSourceType.CUSTOM,
        target_agent=payload.target_agent,
        description=getattr(payload, "description", "").strip(),
        trigger_keywords=payload.trigger_keywords or [],
        always_active=payload.always_active,
        instructions_markdown=payload.instructions_markdown.strip(),
        is_builtin=False,
        is_active=True,
        created_by=admin_email,
        created_at=now_iso,
        updated_at=now_iso,
    )

    doc_ref.set(record.model_dump())
    logger.info(f"Registered custom agent skill '{clean_id}' by {admin_email}")
    return record


@router.get("/api/settings/skills/{skill_id}", response_model=AgentSkillRecord, dependencies=[require(ADMIN)])
def get_skill_endpoint(skill_id: Any = None, request: Any = None):
    if hasattr(skill_id, "state") and not hasattr(request, "state"):
        skill_id, request = request, skill_id
    verify_admin_access(request)
    clean_id = skill_id.strip().lower()

    # Check built-in skills first
    try:
        builtin_map = {b["skill_id"]: b for b in get_builtin_skills()}
        if clean_id in builtin_map:
            return AgentSkillRecord(**builtin_map[clean_id])
    except Exception as e:
        logger.warning(f"Error checking built-in skill: {e}")

    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    doc_ref = db.collection("custom_skills").document(clean_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Skill '{clean_id}' not found.")

    data = doc.to_dict() or {}
    return AgentSkillRecord(**data)


@router.patch("/api/settings/skills/{skill_id}", response_model=AgentSkillRecord, dependencies=[require(ADMIN)])
def update_skill_endpoint(skill_id: str, payload: UpdateSkillRequest, request: Request):
    verify_admin_access(request)
    clean_id = skill_id.strip().lower()

    builtin_ids = {b["skill_id"] for b in get_builtin_skills()}
    if clean_id in builtin_ids:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot modify native platform skill '{clean_id}'. Built-in skills are immutable."
        )

    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    doc_ref = db.collection("custom_skills").document(clean_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Skill '{clean_id}' not found.")

    data = doc.to_dict() or {}
    record = AgentSkillRecord(**data)

    updates: Dict[str, Any] = {}
    if payload.name is not None:
        updates["name"] = payload.name.strip()
        record.name = payload.name.strip()
    if payload.description is not None:
        updates["description"] = payload.description.strip()
        record.description = payload.description.strip()
    if payload.target_agent is not None:
        updates["target_agent"] = payload.target_agent.value
        record.target_agent = payload.target_agent
    if payload.trigger_keywords is not None:
        updates["trigger_keywords"] = payload.trigger_keywords
        record.trigger_keywords = payload.trigger_keywords
    if payload.always_active is not None:
        updates["always_active"] = payload.always_active
        record.always_active = payload.always_active
    if payload.instructions_markdown is not None:
        updates["instructions_markdown"] = payload.instructions_markdown.strip()
        record.instructions_markdown = payload.instructions_markdown.strip()
    if payload.is_active is not None:
        updates["is_active"] = payload.is_active
        record.is_active = payload.is_active

    if updates:
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        doc_ref.set(updates, merge=True)
        record.updated_at = updates["updated_at"]
        logger.info(f"Updated custom skill '{clean_id}' fields: {list(updates.keys())}")

    return record


@router.delete("/api/settings/skills/{skill_id}", dependencies=[require(ADMIN)])
def delete_skill_endpoint(skill_id: Any = None, request: Any = None):
    if hasattr(skill_id, "state") and not hasattr(request, "state"):
        skill_id, request = request, skill_id
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin")
    clean_id = skill_id.strip().lower()

    builtin_ids = {b["skill_id"] for b in get_builtin_skills()}
    if clean_id in builtin_ids:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete native platform skill '{clean_id}'. Built-in skills are immutable."
        )

    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    doc_ref = db.collection("custom_skills").document(clean_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Skill '{clean_id}' not found.")

    doc_ref.delete()
    logger.info(f"Deleted custom skill '{clean_id}' by {admin_email}")
    return {"status": "SUCCESS", "message": f"Skill '{clean_id}' deleted successfully.", "skill_id": clean_id, "deleted": True}


# ------------------------------------------------------------------------------
# Composite Solution Bundles Endpoints
# ------------------------------------------------------------------------------

@router.get("/api/settings/custom-bundles", response_model=CustomBundlesListResponse, dependencies=[require(ADMIN)])
def list_custom_bundles_endpoint(request: Request):
    """List all composite solution bundles (5 built-in enterprise bundles + registered custom bundles)."""
    verify_admin_access(request)
    custom_bundles: List[CompositeBundleRecord] = []
    if db:
        try:
            docs = db.collection("custom_bundles").stream()
            for doc in docs:
                data = doc.to_dict() or {}
                if "bundle_id" not in data:
                    data["bundle_id"] = doc.id
                custom_bundles.append(CompositeBundleRecord(**data))
        except Exception as e:
            logger.error(f"Error listing custom bundles: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to list custom bundles: {e}")

    custom_bundles.sort(key=lambda b: b.bundle_id)

    builtin_bundles: List[CompositeBundleRecord] = []
    try:
        if callable(list_builtin_bundles):
            builtin_bundles = list_builtin_bundles()
    except Exception as e:
        logger.warning(f"Failed to load built-in bundles: {e}")

    all_bundles = builtin_bundles + custom_bundles
    return CustomBundlesListResponse(
        bundles=all_bundles,
        builtin_count=len(builtin_bundles),
        custom_count=len(custom_bundles),
        total_bundles=len(all_bundles),
    )


@router.get("/api/settings/custom-bundles/{bundle_id}", response_model=CompositeBundleRecord, dependencies=[require(ADMIN)])
def get_custom_bundle_endpoint(bundle_id: Any = None, request: Any = None):
    """Retrieve details for a specific composite bundle by ID."""
    if hasattr(bundle_id, "state") and not hasattr(request, "state"):
        bundle_id, request = request, bundle_id
    verify_admin_access(request)
    clean_id = bundle_id.strip().lower()

    # Check built-ins first
    if callable(get_builtin_bundle):
        built = get_builtin_bundle(clean_id)
        if built:
            return built

    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    doc = db.collection("custom_bundles").document(clean_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Bundle '{clean_id}' not found.")

    data = doc.to_dict() or {}
    return CompositeBundleRecord(**data)


def _client_bundle_ref(payload: Any) -> Optional[str]:
    """The request's ``version_tag`` only when the client actually sent one (not the schema default
    "main"), so a ``?ref=`` in the source URL is honoured; ``None`` lets the inspector resolve it."""
    fields_set = getattr(payload, "model_fields_set", None)
    if fields_set is not None and "version_tag" not in fields_set:
        return None
    return (getattr(payload, "version_tag", None) or "").strip() or None


@router.post("/api/settings/custom-bundles", response_model=CompositeBundleRecord, dependencies=[require(ADMIN)])
def register_custom_bundle_endpoint(payload: Any = None, request: Any = None):
    """Register a new Git-native custom bundle from GitHub or StackVend Git."""
    if hasattr(payload, "state") and not hasattr(request, "state"):
        payload, request = request, payload
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin")

    source_url = getattr(payload, "source_url", "").strip()
    if not source_url:
        raise HTTPException(status_code=400, detail="Repository 'source_url' is required.")

    repo_path = (getattr(payload, "repo_path", "") or "").strip().strip("/")

    # Derive bundle_id if not specified
    raw_bundle_id = getattr(payload, "bundle_id", None)
    if raw_bundle_id and raw_bundle_id.strip():
        clean_id = raw_bundle_id.strip().lower()
    else:
        if repo_path:
            clean_id = repo_path.split("/")[-1].lower()
        else:
            clean_id = source_url.rstrip("/").split("/")[-1].replace(".git", "").lower()

    if not clean_id or not re.match(r"^[a-z0-9][a-z0-9-_]{1,63}$", clean_id):
        raise HTTPException(
            status_code=400,
            detail="Bundle ID must be 2-64 lowercase alphanumeric characters, dashes, or underscores."
        )

    # Check collision with built-in bundles
    if callable(get_builtin_bundle) and get_builtin_bundle(clean_id):
        raise HTTPException(
            status_code=400,
            detail=f"Bundle ID '{clean_id}' collides with a native built-in platform bundle."
        )

    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    doc_ref = db.collection("custom_bundles").document(clean_id)
    if doc_ref.get().exists:
        raise HTTPException(status_code=409, detail=f"Custom bundle '{clean_id}' is already registered.")

    # Inspect Git bundle package
    try:
        proj_id = PROJECT_ID or os.getenv("PROJECT_ID", "")
        inspect_res = fetch_and_inspect_git_bundle(
            source_url=source_url,
            repo_path=repo_path,
            version_tag=_client_bundle_ref(payload),
            project_id=proj_id,
        )
    except Exception as e:
        logger.error(f"Failed to inspect remote Git bundle '{clean_id}': {e}")
        raise HTTPException(status_code=400, detail=f"Failed to inspect Git bundle: {e}")

    now_iso = datetime.now(timezone.utc).isoformat()
    record = CompositeBundleRecord(
        bundle_id=clean_id,
        name=payload.name.strip() if getattr(payload, "name", None) else inspect_res.get("name", clean_id),
        category=inspect_res.get("category", "COMPUTE_DATA"),
        description=inspect_res.get("description", ""),
        source_type=CompositeBundleSourceType.REMOTE_GIT,
        source_url=source_url,
        repo_path=repo_path,
        version_tag=inspect_res.get("version_tag") or "main",  # the ref actually read
        commit_sha=inspect_res.get("commit_sha"),
        supported_engines=getattr(payload, "supported_engines", None) or inspect_res.get("supported_engines", ["tofu", "terraform"]),
        default_engine=inspect_res.get("default_engine", "tofu"),
        modules_included=inspect_res.get("modules_included", []),
        resource_footprint=inspect_res.get("resource_footprint", {}),
        default_parameters=inspect_res.get("default_parameters", {}),
        variables=inspect_res.get("variables", []),
        outputs=inspect_res.get("outputs", []),
        hcl_files=inspect_res.get("hcl_files", {}),
        is_active=True,
        is_builtin=False,
        created_at=now_iso,
        updated_at=now_iso,
    )

    doc_ref.set(record.model_dump())
    logger.info(f"Successfully registered custom bundle '{clean_id}' from {source_url} by {admin_email}")
    return record


@router.patch("/api/settings/custom-bundles/{bundle_id}", response_model=CompositeBundleRecord, dependencies=[require(ADMIN)])
def update_custom_bundle_endpoint(bundle_id: str, payload: UpdateBundleRequest, request: Request):
    """Update metadata for a registered custom bundle."""
    verify_admin_access(request)
    clean_id = bundle_id.strip().lower()

    if callable(get_builtin_bundle) and get_builtin_bundle(clean_id):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot modify native platform bundle '{clean_id}'. Built-in bundles are immutable."
        )

    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    doc_ref = db.collection("custom_bundles").document(clean_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Custom bundle '{clean_id}' not found.")

    data = doc.to_dict() or {}
    record = CompositeBundleRecord(**data)

    updates: Dict[str, Any] = {}
    if payload.name is not None:
        updates["name"] = payload.name.strip()
        record.name = payload.name.strip()
    if payload.description is not None:
        updates["description"] = payload.description.strip()
        record.description = payload.description.strip()
    if payload.category is not None:
        updates["category"] = payload.category.strip()
        record.category = payload.category.strip()
    if payload.is_active is not None:
        updates["is_active"] = payload.is_active
        record.is_active = payload.is_active
    if payload.default_parameters is not None:
        updates["default_parameters"] = payload.default_parameters
        record.default_parameters = payload.default_parameters
    if payload.version_tag is not None:
        updates["version_tag"] = payload.version_tag.strip()
        record.version_tag = payload.version_tag.strip()

    if updates:
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        doc_ref.set(updates, merge=True)
        record.updated_at = updates["updated_at"]
        logger.info(f"Updated custom bundle '{clean_id}' fields: {list(updates.keys())}")

    return record


@router.patch("/api/settings/custom-bundles/{bundle_id}/toggle-active", response_model=CompositeBundleRecord, dependencies=[require(ADMIN)])
def toggle_bundle_active_endpoint(bundle_id: str, request: Request):
    """Toggle is_active on/off for a custom bundle."""
    verify_admin_access(request)
    clean_id = bundle_id.strip().lower()

    if callable(get_builtin_bundle) and get_builtin_bundle(clean_id):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot toggle native platform bundle '{clean_id}'. Built-in bundles are immutable."
        )

    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    doc_ref = db.collection("custom_bundles").document(clean_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Custom bundle '{clean_id}' not found.")

    data = doc.to_dict() or {}
    new_state = not data.get("is_active", True)
    now_iso = datetime.now(timezone.utc).isoformat()

    doc_ref.set({"is_active": new_state, "updated_at": now_iso}, merge=True)
    data["is_active"] = new_state
    data["updated_at"] = now_iso
    return CompositeBundleRecord(**data)


@router.delete("/api/settings/custom-bundles/{bundle_id}", dependencies=[require(ADMIN)])
def delete_custom_bundle_endpoint(bundle_id: Any = None, request: Any = None):
    """Delete a registered custom bundle."""
    if hasattr(bundle_id, "state") and not hasattr(request, "state"):
        bundle_id, request = request, bundle_id
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin")
    clean_id = bundle_id.strip().lower()

    if callable(get_builtin_bundle) and get_builtin_bundle(clean_id):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete native platform bundle '{clean_id}'. Built-in bundles are immutable."
        )

    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    doc_ref = db.collection("custom_bundles").document(clean_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Custom bundle '{clean_id}' not found.")

    doc_ref.delete()
    logger.info(f"Deleted custom bundle '{clean_id}' by {admin_email}")
    return {"status": "SUCCESS", "message": f"Bundle '{clean_id}' deleted successfully.", "bundle_id": clean_id, "deleted": True}


@router.post("/api/settings/custom-bundles/scan-repository", response_model=List[DiscoveredBundleSummary], dependencies=[require(ADMIN)])
def scan_repository_bundles_endpoint(payload: Any = None, request: Any = None):
    """Scan a remote Git repository/monorepo for composite bundles (Guardrail 3)."""
    if hasattr(payload, "state") and not hasattr(request, "state"):
        payload, request = request, payload
    verify_admin_access(request)

    source_url = getattr(payload, "source_url", "").strip()
    if not source_url:
        raise HTTPException(status_code=400, detail="Repository 'source_url' is required.")

    parent_path = (getattr(payload, "parent_path", "bundles") or "bundles").strip().strip("/")
    ref = _client_bundle_ref(payload)
    proj_id = PROJECT_ID or os.getenv("PROJECT_ID", "")

    try:
        discovered = scan_repository_git_bundles(
            source_url=source_url,
            parent_path=parent_path,
            version_tag=ref,
            project_id=proj_id,
        )
        return [DiscoveredBundleSummary(**d) for d in discovered]
    except Exception as e:
        logger.error(f"Error scanning repository '{source_url}' for bundles: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to scan repository: {e}")


@router.post("/api/settings/custom-bundles/{bundle_id}/sync", response_model=CompositeBundleRecord, dependencies=[require(ADMIN)])
def sync_custom_bundle_endpoint(bundle_id: Any = None, request: Any = None):
    """Re-sync an existing custom bundle from its Git source."""
    if hasattr(bundle_id, "state") and not hasattr(request, "state"):
        bundle_id, request = request, bundle_id
    verify_admin_access(request)
    clean_id = bundle_id.strip().lower()

    if callable(get_builtin_bundle):
        built = get_builtin_bundle(clean_id)
        if built:
            return built

    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized.")

    doc_ref = db.collection("custom_bundles").document(clean_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail=f"Custom bundle '{clean_id}' not found.")

    data = doc.to_dict() or {}
    record = CompositeBundleRecord(**data)

    if record.source_type != CompositeBundleSourceType.REMOTE_GIT or not record.source_url:
        raise HTTPException(status_code=400, detail=f"Bundle '{clean_id}' does not have a remote Git source.")

    proj_id = PROJECT_ID or os.getenv("PROJECT_ID", "")
    try:
        inspect_res = fetch_and_inspect_git_bundle(
            source_url=record.source_url,
            repo_path=record.repo_path or "",
            version_tag=record.version_tag or None,
            project_id=proj_id,
        )
        now_iso = datetime.now(timezone.utc).isoformat()
        updates = {
            "commit_sha": inspect_res.get("commit_sha"),
            "modules_included": inspect_res.get("modules_included", []),
            "resource_footprint": inspect_res.get("resource_footprint", {}),
            "variables": inspect_res.get("variables", []),
            "outputs": inspect_res.get("outputs", []),
            "hcl_files": inspect_res.get("hcl_files", {}),
            "updated_at": now_iso,
        }
        doc_ref.set(updates, merge=True)
        for k, v in updates.items():
            setattr(record, k, v)
        logger.info(f"Re-synced custom bundle '{clean_id}' from {record.source_url}")
        return record
    except Exception as e:
        logger.error(f"Failed to re-sync custom bundle '{clean_id}': {e}")
        raise HTTPException(status_code=400, detail=f"Failed to re-sync bundle: {e}")



