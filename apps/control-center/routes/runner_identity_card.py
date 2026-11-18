"""
StackVend Control Center: Settings card "Terraform runner identity" (FD-7L Phase 3, plan 3; rows FD-7L-g, FD-7L-n).

GET  /api/settings/runner-identity           (ADMIN) the operative mode ("Shared" / "Per workload"), where it comes from
                                             (the install declaration, or vending's signed Settings record, FD-7L-F4),
                                             the last changes, and vending's per-workload status; on a Shared install
                                             the known-limitation warning.
POST /api/settings/runner-identity/mode      (ADMIN, human principal, sign-in younger than 15 minutes, typed
                                             confirmation = the mode token, expected_version) FD-7L-F4: asks vending to
                                             set the operative mode. Vending signs the record and its never-trimmed
                                             change entry, and refuses on an install that declares Per workload
                                             (RUNNER_IDENTITY_MODE_RETIRED) and Per workload before step A
                                             (RUNNER_IDENTITY_STEP_A_MISSING). Behind IAP the Control Center cannot see
                                             the sign-in time, so the change is refused (RECENT_SIGN_IN_UNAVAILABLE,
                                             the SAT-11 rule for sensitive settings); the install's apply path
                                             (`tf_runner_identity`) stays available there.
POST /api/settings/runner-identity/backfill  (ADMIN) vending's backfill: {"dry_run": true} lists every call and writes
                                             nothing; {"dry_run": false} runs it (idempotent, resumable, audited)
                                             for explicit product_ids only, at most 3 per request (RT F2-2: the
                                             run happens inside this one HTTP request), and writes one Control
                                             Center audit entry per named workload (RT F2-5).
                                             `steps` / `product_ids` pass through (owner actions such as
                                             restore_platform_state and purge_platform_copy are not on the card).

Vending is called with the Control Center's ID token (the only caller its routes accept); the CC never writes a
runner identity record itself.
"""
import json
import logging
import os
import time
from typing import Any, Callable, Dict, List, Literal, Optional

from datetime import datetime, timezone

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field, StrictBool, StrictInt

import authz
import config
import recent_sign_in
from authz import ADMIN, require
import destructive_actions as da
from routes import settings as settings_routes
from shared import runner_identity as ri

logger = logging.getLogger("control-center-runner-identity")

router = APIRouter()

SHARED_WARNING = ("Shared runner identity: every workload's OpenTofu runs as the platform's service account, which "
                  "can read platform secrets and every workload's state (documentation/known-limitations.md). "
                  "Per workload is chosen at install time and is a one-way upgrade (backfill, then the platform "
                  "apply).")

# FD-7L-F4: the sign-in age rule of sensitive Settings writes (recent_sign_in.py, shared with SAT-11's release source).
RECENT_SIGN_IN_SECONDS = recent_sign_in.RECENT_SIGN_IN_SECONDS
clock: Callable[[], float] = time.time   # test seam (sign-in age)

REAL_RUN_MAX = 3   # vending's runner_identity_backfill.REAL_RUN_MAX

# Test seams (None = the real Control Center vending requester / default Firestore database).
vending_requester: Optional[Callable[..., Any]] = None
audit_db_provider: Optional[Callable[[], Any]] = None


def _requester() -> Callable[..., Any]:
    return vending_requester or settings_routes.make_vending_request


class RunnerIdentityBackfillBody(BaseModel):
    dry_run: StrictBool = True
    product_ids: Optional[List[str]] = Field(None, max_length=200)
    max: StrictInt = Field(25, ge=1, le=200)
    steps: Optional[List[str]] = Field(None, max_length=9)


def _audit_db():
    if audit_db_provider is not None:
        return audit_db_provider()
    from db import get_db
    return get_db()


def _audit_real_run(product_ids: List[str], body: "RunnerIdentityBackfillBody", admin_email: Optional[str],
                    outcome: "da.VendingOutcome") -> None:
    """RT F2-5: one workloads/{pid}/audit_logs entry per named workload for a real run (vending audits its own steps
    under RUNNER_IDENTITY_BACKFILL). A failed audit write is logged; vending's answer is returned either way."""
    db = _audit_db()
    rows = (outcome.body or {}).get("results") if outcome.ok else None
    results = {r.get("product_id"): r for r in (rows or []) if isinstance(r, dict)}
    now_iso = datetime.now(timezone.utc).isoformat()
    for pid in product_ids:
        r = results.get(pid) or {}
        entry = {"action": "RUNNER_IDENTITY_BACKFILL_REQUESTED", "timestamp": now_iso, "operator": admin_email,
                 "dry_run": False, "steps": body.steps, "product_ids": product_ids,
                 "vending_status": outcome.http_status, "vending_code": None if outcome.ok else outcome.code,
                 "outcome": r.get("outcome"), "error_class": r.get("error_class")}
        try:
            if db is None:
                raise RuntimeError("Firestore unavailable")
            db.collection("workloads").document(pid).collection("audit_logs").document().set(entry)
        except Exception as e:  # noqa: BLE001
            logger.error(f"RUNNER_IDENTITY_BACKFILL audit entry for {pid} not written: {type(e).__name__}")


def _vending_get(path: str, request: Request) -> da.VendingOutcome:
    """GET with the CC's ID token (same contract as install_status._vending_get)."""
    try:
        resp = _requester()(method="GET", path=path, json_body=None, timeout=60.0, request=request)
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


def _local_mode() -> Dict[str, Any]:
    from services import runner_state   # lazy, as routes/workloads.py
    try:
        mode = runner_state.operative_mode()   # FD-7L-F4: the one shared reader (declaration, then the record)
        return {"mode": mode, "mode_label": ri.MODE_LABELS[mode], "error": None}
    except ri.RunnerIdentityError as e:
        return {"mode": None, "mode_label": None, "error": f"{e.code}: {e.detail}"}


def _mode_setting(request: Request) -> Dict[str, Any]:
    """Vending's view of the operative-mode record (GET /runner-identity/mode). Display only: when vending does not
    answer, the card says so in `mode_setting_error` and offers no change."""
    outcome = _vending_get("/runner-identity/mode", request)
    if not outcome.ok:
        return {"mode_setting": None, "mode_setting_error": f"{outcome.code}: {outcome.detail}"}
    return {"mode_setting": outcome.body, "mode_setting_error": None}


@router.get("/api/settings/runner-identity", dependencies=[require(ADMIN)])
def get_runner_identity_card(request: Request):
    local = _local_mode()
    card: Dict[str, Any] = {"control_center_mode": local["mode"], "control_center_mode_error": local["error"],
                            "mode_source": f"install setting {ri.MODE_ENV} (Terraform-owned; not editable here)",
                            "last_mode_change": None, "warnings": [], "status": None}
    card.update(_mode_setting(request))
    setting = card["mode_setting"]
    if isinstance(setting, dict):
        card["mode_source"] = setting.get("mode_source") or card["mode_source"]
        card["last_mode_change"] = setting.get("last_mode_change")
        # FD-7L-F4 RT H1/M1: a mode record changed outside Settings (missing, replayed, tampered) is a warning
        card["warnings"].extend(w for w in (setting.get("warnings") or []) if isinstance(w, dict) and w.get("code"))
    outcome = _vending_get("/runner-identity/status", request)
    if not outcome.ok:
        card.update(mode=local["mode"], mode_label=local["mode_label"])
        card["warnings"].append({"code": "RUNNER_IDENTITY_STATUS_UNAVAILABLE", "severity": "warning",
                                 "message": f"Project vending did not report the runner identity status "
                                            f"({outcome.code}: {outcome.detail})."})
        return card
    st = outcome.body
    mode = st.get("mode")
    card.update(mode=mode, mode_label=st.get("mode_label"), status=st)
    if mode == ri.MODE_PLATFORM:
        card["warnings"].append({"code": "RUNNER_IDENTITY_SHARED", "severity": "warning", "message": SHARED_WARNING})
    if local["mode"] != mode:
        card["warnings"].append({"code": "RUNNER_IDENTITY_MODE_DIFFERS", "severity": "warning",
                                 "message": f"Vending runs in {mode!r} but the Control Center in {local['mode']!r}: "
                                            "the state views read the platform bucket until both match."})
    return card


@router.post("/api/settings/runner-identity/backfill", dependencies=[require(ADMIN)])
def run_runner_identity_backfill(request: Request, body: Optional[RunnerIdentityBackfillBody] = None):
    body = body or RunnerIdentityBackfillBody()
    admin_email = getattr(request.state, "user_email", None)
    pids = list(dict.fromkeys(p for p in (body.product_ids or []) if isinstance(p, str) and p))
    if not body.dry_run and (not pids or len(pids) > REAL_RUN_MAX or body.max > REAL_RUN_MAX):
        from fastapi.responses import JSONResponse   # lazy, as in destructive_actions
        return JSONResponse(status_code=422, content={
            "code": "BACKFILL.REAL_RUN_TOO_LARGE",
            "detail": (f"BACKFILL.REAL_RUN_TOO_LARGE: a real backfill names its workloads (product_ids), at most "
                       f"{REAL_RUN_MAX} per run, with max <= {REAL_RUN_MAX}; a dry run may cover every workload.")})
    payload = {"dry_run": body.dry_run, "max": body.max, "operator_email": admin_email}
    if body.product_ids:
        payload["product_ids"] = body.product_ids
    if body.steps:
        payload["steps"] = body.steps
    outcome = da.call_vending(_requester(), "/runner-identity/backfill", payload, request=request, timeout=120.0)
    if not body.dry_run:
        _audit_real_run(pids, body, admin_email, outcome)
    if not outcome.ok:
        return da.failure_response(outcome, action="RUNNER_IDENTITY_BACKFILL", product_id="*")
    logger.info(f"RUNNER_IDENTITY_BACKFILL (dry_run={body.dry_run}) requested by {admin_email}: "
                f"{outcome.body.get('counts')}")
    return outcome.body


# ------------------------------------------------------------------------------------------------ FD-7L-F4 mode change
class RunnerIdentityModeBody(BaseModel):
    mode: Literal["PLATFORM", "PER_WORKLOAD"]
    expected_version: StrictInt = Field(..., ge=0)
    confirm: str = ""   # typed confirmation: exactly the mode token


def _refuse(status: int, code: str, message: str):
    from fastapi.responses import JSONResponse   # lazy, as in destructive_actions
    return JSONResponse(status_code=status, content={"code": code, "detail": f"{code}: {message}"})


def _recent_sign_in_refusal(request: Request):
    """None when the administrator signed in less than RECENT_SIGN_IN_SECONDS ago (session cookie: its issue time,
    auth.session_issued_at). Behind IAP the Control Center cannot see the sign-in time: refused, fail closed (the
    SAT-11 rule, register row SAT11-IAP-RELEASE-SOURCE); on such an install the mode is changed through the install
    declaration (tf_runner_identity + apply.sh)."""
    refusal = recent_sign_in.sign_in_refusal(request, clock())
    if refusal is None:
        return None
    if refusal == recent_sign_in.RECENT_SIGN_IN_REQUIRED:
        return _refuse(403, "RECENT_SIGN_IN_REQUIRED",
                       "sign out and sign in again (a sign-in younger than 15 minutes is needed), then retry.")
    return _refuse(403, "RECENT_SIGN_IN_UNAVAILABLE",
                   "this Control Center cannot confirm a recent sign-in (Identity-Aware Proxy does not pass the sign-in "
                   "time), so the runner identity mode cannot be changed from the browser on this install. Use the "
                   "install setting tf_runner_identity with scripts/apply.sh instead. "
                   + config.apply_where(config.PROJECT_ID or os.getenv("PROJECT_ID", "")))


@router.post("/api/settings/runner-identity/mode", dependencies=[require(ADMIN)])
def set_runner_identity_mode(request: Request, body: RunnerIdentityModeBody):
    """FD-7L-F4: vending sets (and signs) the operative mode. ADMIN on the route; a human principal (never a service
    account), a recent sign-in and the typed confirmation here; everything else is vending's decision."""
    if authz.principal_type(request) != authz.PRINCIPAL_USER:
        return _refuse(403, "HUMAN_ADMIN_REQUIRED", "only a signed-in administrator can change the runner identity mode.")
    refusal = _recent_sign_in_refusal(request)
    if refusal is not None:
        return refusal
    if body.confirm != body.mode:
        return _refuse(422, "RUNNER_MODE_CONFIRMATION_MISMATCH", f"type {body.mode} to confirm the change.")
    admin_email = getattr(request.state, "user_email", None)
    payload = {"mode": body.mode, "expected_version": body.expected_version, "operator_email": admin_email}
    outcome = da.call_vending(_requester(), "/runner-identity/mode", payload, request=request, timeout=60.0)
    logger.warning(json.dumps({"event": "stackvend.runner_identity_mode_requested", "by": admin_email,
                               "mode": body.mode, "expected_version": body.expected_version,
                               "vending_status": outcome.http_status, "vending_code": None if outcome.ok
                               else outcome.code}, sort_keys=True))
    if not outcome.ok:
        if outcome.http_status in (409, 422):   # vending's typed refusal (RETIRED, STEP_A_MISSING, CHANGED, ...)
            return _refuse(outcome.http_status, outcome.code, outcome.detail)
        return da.failure_response(outcome, action="RUNNER_IDENTITY_MODE", product_id="*")
    return outcome.body
