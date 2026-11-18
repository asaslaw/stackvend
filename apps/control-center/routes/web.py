"""
Project Castor: Web & Authentication Routes
Renders the Flight Deck Dashboard UI and manages Google Identity Services authentication.
"""

import html
import json
import logging
import os
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
try:
    from fastapi.templating import Jinja2Templates
except Exception:
    try:
        from starlette.templating import Jinja2Templates
    except Exception:
        class Jinja2Templates:
            def __init__(self, directory=None):
                self.directory = directory
            def TemplateResponse(self, *args, **kwargs):
                return HTMLResponse("<html></html>")
from pydantic import BaseModel

import config
import identity
import quick_guide
from auth import (
    create_session_token,
    extract_user_email,
    get_user_access_record,
    render_sign_in_html,
    resolve_access,
)
from authz import AUTHENTICATED, PUBLIC, require
from schemas import GoogleLoginRequest, UserRole

logger = logging.getLogger("control-center-web")

router = APIRouter(tags=["Web"])

templates_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


class ConfigClientIdRequest(BaseModel):
    client_id: str
    credential: str = ""


_CLIENT_ID_SUFFIX = ".apps.googleusercontent.com"


@router.get("/", response_class=HTMLResponse, dependencies=[require(AUTHENTICATED)])
def index_page(request: Request):
    """Renders the main interactive flight deck dashboard for authorized users."""
    user_email = getattr(request.state, "user_email", "admin")
    user_role = getattr(request.state, "user_role", UserRole.APPROVER)
    role_str = user_role.value if hasattr(user_role, "value") else str(user_role)
    safe_email = html.escape(user_email)
    safe_role = html.escape(role_str)

    template_file = templates_dir / "dashboard.html"
    if template_file.exists():
        try:
            with open(template_file, "r", encoding="utf-8") as f:
                content = f.read()
            raw_nonce = getattr(request.state, "csp_nonce", "")
            nonce = html.escape(raw_nonce if isinstance(raw_nonce, str) else "")
            # FD-4AR: JS-context values are JSON-encoded then HTML-escaped (x-data is evaluated after entity decoding).
            return (content.replace("{{ user_email_js }}", html.escape(json.dumps(user_email)))
                    .replace("{{ user_role_js }}", html.escape(json.dumps(role_str)))
                    .replace("{{ csp_nonce }}", nonce)
                    .replace("{{ user_email }}", safe_email).replace("{{ user_role }}", safe_role))
        except Exception as e:
            logger.warning(f"Error reading dashboard template: {e}")

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user_email": safe_email,
            "user_role": safe_role,
        },
    )


@router.get("/api/guide", dependencies=[require(AUTHENTICATED)])
def guide_markdown(request: Request):
    """FD-4CV: the Guide tab's markdown (quick_guide.py). Administrators get the admin-only sections, everyone else
    does not; display only, every action keeps its own authorization. Read-only."""
    role = getattr(request.state, "user_role", None)
    is_admin = role == UserRole.ADMIN
    try:
        markdown = quick_guide.load_for_role(is_admin)
    except (OSError, quick_guide.GuideFormatError) as e:
        logger.error(f"Quick guide unavailable: {e}")
        raise HTTPException(status_code=500, detail="The guide could not be loaded.")
    return {"markdown": markdown, "admin_sections_shown": is_admin}


def _cookie_secure() -> bool:
    """FD-4M F4: always Secure on Cloud Run (*.run.app is HTTPS; TLS ends at Google's front end, the
    attribute is static). CC_INSECURE_LOCAL_COOKIES=true is a local-HTTP-only opt-out (Safari rejects
    Secure on http://localhost); it is ignored whenever K_SERVICE is set. Never derived from
    request.url.scheme (inside the container it is http)."""
    if os.getenv("K_SERVICE"):
        return True
    return os.getenv("CC_INSECURE_LOCAL_COOKIES", "").strip().lower() != "true"


_COOKIE_ATTRS = dict(path="/", httponly=True, samesite="lax")


def _session_response(verified_email: str, role_value: str):
    token = create_session_token(verified_email)
    resp = JSONResponse(content={
        "status": "SUCCESS", "email": verified_email, "role": role_value,
        "message": "Google authentication verified. Redirecting to Control Center...",
    })
    for ckey in ["stackvend_session", "castor_session"]:
        resp.set_cookie(key=ckey, value=token, max_age=86400 * 7, secure=_cookie_secure(), **_COOKIE_ATTRS)
    return resp


def _refuse_gis_session_behind_iap(status_code: int) -> None:
    """Register row 41 (owner, 10-12): when Cloud Run reports iapEnabled, no Google Sign-In credential ever mints a
    session cookie (those cookies would not be honoured anyway, see auth.extract_user_email)."""
    if identity.get_runtime_identity().iap_audience:
        raise HTTPException(status_code=status_code,
                            detail="Not available: this Control Center runs behind Identity-Aware Proxy (IAP sign-in only).")


@router.post("/auth/google-login", dependencies=[require(PUBLIC)])
async def auth_google_login(request: Request):
    """
    Cryptographically verifies a Google ID Token (OIDC JWT) from Google Identity Services (popup mode, JSON body),
    checks the authorization list, and issues a signed session cookie.
    FD-4N (red-team B18): the form-POST redirect branch is removed (no GSI g_csrf_token check => login CSRF);
    the UI only uses popup mode. Red-team H2: platform service accounts can never obtain a session.
    Register row 41: behind Direct IAP this route does not exist (404); the IAP assertion is the only human identity.
    """
    _refuse_gis_session_behind_iap(404)
    credential = ""
    try:
        body = await request.json()
        credential = str(body.get("credential", "")).strip() if isinstance(body, dict) else ""
    except Exception:
        credential = ""
    if not credential:
        raise HTTPException(status_code=400, detail="Missing Google ID token credential.")

    try:
        client_id_to_check = config.get_google_oauth_client_id()
        id_info = identity.verify_google_login_credential(credential, client_id_to_check)
        verified_email = id_info["email"].strip().lower()
    except Exception as verify_err:
        logger.warning(f"Google ID token verification failed: {verify_err}")
        raise HTTPException(
            status_code=401,
            detail=f"Google authentication failed: Cryptographic token verification failed ({verify_err}).",
        )

    user_record = resolve_access(verified_email, "google_login")
    if not user_record:
        logger.warning(f"Verified Google user '{verified_email}' is not on the authorized access list.")
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: Verified Google account '{verified_email}' is not listed in the StackVend authorized users registry.",
        )

    logger.info(f"User '{verified_email}' ({user_record.role.value}) authenticated via Google Sign-In.")
    return _session_response(verified_email, user_record.role.value)


def cc_identity_record() -> dict:
    """Lane 19 L19-0c: which OAuth client this Control Center revision verifies logins against, and where it came
    from. source: env (Terraform pin) | secret_manager | firestore | none; iap_only when Cloud Run reports IAP (row 41:
    no Google Sign-In session at all). tf-applier compares the tenant client against this record (A1) and refuses
    shared mode unless source is env or iap_only. The client id is public; no secret is ever written here."""
    iap_only = bool(identity.get_runtime_identity().iap_audience)
    source = "iap_only" if iap_only else (getattr(config, "GOOGLE_OAUTH_CLIENT_ID_SOURCE", "") or "none")
    return {
        "google_client_id": getattr(config, "GOOGLE_OAUTH_CLIENT_ID", "") or "",
        "source": source,
        "env_pinned": bool(getattr(config, "GOOGLE_OAUTH_CLIENT_ID_ENV_PINNED", False)),
        "revision": os.getenv("K_REVISION", ""),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def publish_cc_identity() -> None:
    """Writes platform_config/cc_identity (startup and after a client-id change). Never raises: a missing or stale
    record makes tf-applier fail closed (AUTH_CONFIG_UNAVAILABLE), it never makes the CC fail to boot."""
    try:
        from db import db
        if db:
            rec = cc_identity_record()
            db.collection("platform_config").document("cc_identity").set(rec)
            logger.info(f"Published platform_config/cc_identity (source={rec['source']}, revision={rec['revision']}).")
    except Exception as e:
        logger.warning(f"Could not publish platform_config/cc_identity: {type(e).__name__}")


# Lane 19 RT F3: a lazy client-id resolution after a failed import-time read republishes the record.
config.CLIENT_ID_RESOLVED_HOOK = publish_cc_identity


def _persist_client_id(clean_id: str) -> None:
    """Unchanged persistence: memory + Firestore platform_config/auth + Secret Manager version."""
    config.GOOGLE_OAUTH_CLIENT_ID = clean_id
    logger.info("Updated in-memory GOOGLE_OAUTH_CLIENT_ID")
    # Lane 19 RT F6: the published source names the store that actually holds the value (SM, else Firestore,
    # else none: memory only).
    fs_ok = sm_ok = False
    try:
        from db import db
        if db:
            db.collection("platform_config").document("auth").set(
                {"google_oauth_client_id": clean_id, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                merge=True,
            )
            logger.info("Persisted GOOGLE_OAUTH_CLIENT_ID to Firestore platform_config/auth")
            fs_ok = True
    except Exception as fs_err:
        logger.warning(f"Could not persist client ID to Firestore: {fs_err}")
    proj = getattr(config, "PROJECT_ID", "") or os.getenv("PROJECT_ID", "")
    if proj:
        try:
            from google.cloud import secretmanager
            secretmanager.SecretManagerServiceClient().add_secret_version(
                request={"parent": f"projects/{proj}/secrets/castor-oauth-client-id",
                         "payload": {"data": clean_id.encode("utf-8")}}
            )
            logger.info("Persisted new version to Secret Manager castor-oauth-client-id")
            sm_ok = True
        except Exception as sm_err:
            logger.debug(f"Secret Manager write-through omitted or failed: {sm_err}")
    config.GOOGLE_OAUTH_CLIENT_ID_SOURCE = "secret_manager" if sm_ok else ("firestore" if fs_ok else "")
    publish_cc_identity()


@router.post("/auth/config-client-id", dependencies=[require(PUBLIC)])
def config_client_id(req: ConfigClientIdRequest, request: Request):
    """
    First run (no client ID configured anywhere): the caller must present a Google ID token minted FOR the
    client ID being registered, for a verified email that is already ADMIN (ADMIN_EMAIL or Firestore).
    Once configured: ADMIN session / IAP identity only. Empty or malformed IDs are always rejected.
    First run requires a definitive "absent" (Secret Manager NotFound AND no Firestore value); if the
    configuration state cannot be read, the request fails closed with 503.
    """
    # Lane 19 L19-0c: a Terraform-pinned client (env GOOGLE_OAUTH_CLIENT_ID from cc_google_oauth_client_id) is never
    # changed here: this route writes Secret Manager castor-oauth-client-id, which tf-applier copies into tenants.
    if getattr(config, "GOOGLE_OAUTH_CLIENT_ID_ENV_PINNED", False):
        proj = getattr(config, "PROJECT_ID", "") or os.getenv("PROJECT_ID", "")
        raise HTTPException(status_code=409, detail=(
            "The Control Center OAuth client is pinned by Terraform (cc_google_oauth_client_id). Change it in "
            f"infra/platform/{proj or '<project_id>'}.tfvars and run scripts/apply.sh apply. "
            + config.apply_where(proj)))
    clean_id = req.client_id.strip()
    if (not clean_id.endswith(_CLIENT_ID_SUFFIX) or len(clean_id) > 255
            or any(c.isspace() for c in clean_id) or clean_id == _CLIENT_ID_SUFFIX):
        raise HTTPException(status_code=400, detail="A Web OAuth client ID ending in .apps.googleusercontent.com is required.")

    state = config.oauth_client_id_state()  # FD-4E F1: a read error must never look like "first run"
    if state == "unknown":
        raise HTTPException(status_code=503, detail="Cannot confirm OAuth configuration state; retry.")
    if state == "configured":
        email = extract_user_email(request)
        rec = resolve_access(email, getattr(request.state, "auth_method", "")) if email else None
        if not rec or rec.role != UserRole.ADMIN:
            raise HTTPException(status_code=403 if email else 401,
                                detail="Platform Administrator sign-in required to change the OAuth client ID.")
        _persist_client_id(clean_id)
        logger.info(f"OAuth client ID rotated by administrator '{email}'.")
        return {"status": "SUCCESS", "configured": True}

    _refuse_gis_session_behind_iap(403)  # row 41: first-run GIS proof would mint a session cookie
    if not req.credential.strip():
        raise HTTPException(status_code=401, detail="First-run setup requires signing in with the new client ID.")
    try:
        info = identity.verify_google_login_credential(req.credential.strip(), clean_id)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"First-run identity proof failed: {e}")
    email = info["email"].strip().lower()
    rec = resolve_access(email, "google_login")
    if not rec or rec.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail=(
            "Only the platform administrator can complete first-run setup. If ADMIN_EMAIL is unset, store the client ID with: "
            "printf %s '<client-id>' | gcloud secrets versions add castor-oauth-client-id --data-file=-"))
    _persist_client_id(clean_id)
    logger.info(f"First-run OAuth client ID configured by administrator '{email}'.")
    return _session_response(email, rec.role.value)


@router.post("/auth/logout", dependencies=[require(PUBLIC)])
@router.get("/auth/logout", dependencies=[require(PUBLIC)])
def auth_logout():
    """Logs out the user by clearing the session cookie."""
    response = JSONResponse(content={"status": "LOGGED_OUT", "message": "Session cleared."})
    for ckey in ["stackvend_session", "castor_session"]:
        response.delete_cookie(key=ckey, secure=_cookie_secure(), **_COOKIE_ATTRS)
    return response


@router.get("/health", dependencies=[require(PUBLIC)])
def health_check():
    return {
        "status": "healthy",
        "service": "product-control-center-ui",
        "auth_mode": "GOOGLE_OAUTH_VERIFIED",
        "has_google_oauth_client_id": bool(config.GOOGLE_OAUTH_CLIENT_ID),
        "environment": os.getenv("ENVIRONMENT", "prod"),
    }
