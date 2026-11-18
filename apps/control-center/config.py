"""
Project Castor: Control Center Configuration
Centralized configuration, environment variable extraction, and platform constants.
"""

import os
import logging

logger = logging.getLogger("control-center-config")

# Project ID resolution
PROJECT_ID = os.getenv("PROJECT_ID", "")
if not PROJECT_ID:
    try:
        import google.auth
        _, _discovered_proj = google.auth.default()
        if _discovered_proj:
            PROJECT_ID = _discovered_proj
    except Exception:
        pass


def apply_where(project_id: str = "") -> str:
    """CC-APPLY-WHERE (owner, 11-03): where to run scripts/apply.sh. Every Control Center fix that tells the operator
    to run apply.sh shows this sentence next to the command (wording only)."""
    proj = project_id or "<project_id>"
    return (f"Run it from the root of the StackVend folder you installed from: it holds infra/platform/{proj}.tfvars "
            "(keep a copy; the installer's last step prints the command to back it up to "
            f"gs://castor-tfstate-{proj}/platform/).")


ENVIRONMENT = os.getenv("ENVIRONMENT", "production")
PORT = int(os.getenv("PORT", "8080"))

# Google Identity Services & Auth
GOOGLE_OAUTH_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
# Lane 19 L19-0c: GOOGLE_OAUTH_CLIENT_ID in the env is the Terraform pin (cc_google_oauth_client_id). Where the
# effective client came from is published as platform_config/cc_identity (tf-applier's A1 rules read it).
GOOGLE_OAUTH_CLIENT_ID_ENV_PINNED = bool(GOOGLE_OAUTH_CLIENT_ID)
GOOGLE_OAUTH_CLIENT_ID_SOURCE = "env" if GOOGLE_OAUTH_CLIENT_ID else ""
# Lane 19 RT F3: set by routes.web to publish_cc_identity. If the import-time read failed (record published with
# source "none"), a later successful lazy resolution republishes platform_config/cc_identity. Unset at import time,
# so the import-time resolution below never publishes (the startup hook does).
CLIENT_ID_RESOLVED_HOOK = None


def _client_id_resolved(previous: str) -> None:
    """Republishes platform_config/cc_identity when a lazy resolution changed the in-memory client. Never raises."""
    if GOOGLE_OAUTH_CLIENT_ID == previous or CLIENT_ID_RESOLVED_HOOK is None:
        return
    try:
        CLIENT_ID_RESOLVED_HOOK()
    except Exception as e:
        logger.warning(f"Could not republish platform_config/cc_identity: {type(e).__name__}")


def get_google_oauth_client_id() -> str:
    """Returns configured Google OAuth Client ID, resolving from Secret Manager or Firestore if unset."""
    global GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_ID_SOURCE
    if GOOGLE_OAUTH_CLIENT_ID:
        return GOOGLE_OAUTH_CLIENT_ID

    proj = PROJECT_ID or os.getenv("PROJECT_ID", "")
    if proj:
        # 1. Attempt lookup from Secret Manager
        try:
            from google.cloud import secretmanager
            client = secretmanager.SecretManagerServiceClient()
            secret_path = f"projects/{proj}/secrets/castor-oauth-client-id/versions/latest"
            resp = client.access_secret_version(request={"name": secret_path})
            secret_val = resp.payload.data.decode("utf-8").strip()
            if secret_val:
                GOOGLE_OAUTH_CLIENT_ID = secret_val
                GOOGLE_OAUTH_CLIENT_ID_SOURCE = "secret_manager"
                logger.info("Resolved GOOGLE_OAUTH_CLIENT_ID from Secret Manager castor-oauth-client-id")
                _client_id_resolved("")
                return GOOGLE_OAUTH_CLIENT_ID
        except Exception:
            pass

        # 2. Attempt lookup from Firestore
        try:
            from google.cloud import firestore
            fs_client = firestore.Client(project=proj)
            doc = fs_client.collection("platform_config").document("auth").get()
            if doc.exists:
                data = doc.to_dict() or {}
                fs_val = str(data.get("google_oauth_client_id", "")).strip()
                if fs_val:
                    GOOGLE_OAUTH_CLIENT_ID = fs_val
                    GOOGLE_OAUTH_CLIENT_ID_SOURCE = "firestore"
                    logger.info("Resolved GOOGLE_OAUTH_CLIENT_ID from Firestore platform_config/auth")
                    _client_id_resolved("")
                    return GOOGLE_OAUTH_CLIENT_ID
        except Exception:
            pass

    return GOOGLE_OAUTH_CLIENT_ID


def _is_definitive_absence(err: Exception) -> bool:
    """True only for Secret Manager errors that prove the client ID was never stored (FD-4E F1)."""
    try:
        from google.api_core import exceptions as gexc
        return isinstance(err, (gexc.NotFound, gexc.FailedPrecondition))
    except Exception:
        return False


def oauth_client_id_state() -> str:
    """
    FD-4E F1: tri-state OAuth client-ID configuration, for gating first-run setup.
    - "configured": in memory, or Secret Manager / Firestore yields a value (cached in memory).
    - "absent":     Secret Manager says NotFound / no enabled version (or holds an empty value) AND the
                    Firestore doc platform_config/auth has no value. Only then may first-run setup proceed.
    - "unknown":    any other read error (transient outage, permission, ...). Callers must fail closed.
    Unlike get_google_oauth_client_id(), errors are never collapsed into "not configured".
    """
    global GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_ID_SOURCE
    if GOOGLE_OAUTH_CLIENT_ID:
        return "configured"
    proj = PROJECT_ID or os.getenv("PROJECT_ID", "")
    if not proj:
        return "absent"  # local dev: nothing persisted anywhere but memory

    try:
        from google.cloud import secretmanager
        client = secretmanager.SecretManagerServiceClient()
        resp = client.access_secret_version(
            request={"name": f"projects/{proj}/secrets/castor-oauth-client-id/versions/latest"}
        )
        secret_val = resp.payload.data.decode("utf-8").strip()
        if secret_val:
            GOOGLE_OAUTH_CLIENT_ID = secret_val
            GOOGLE_OAUTH_CLIENT_ID_SOURCE = "secret_manager"
            _client_id_resolved("")
            return "configured"
    except Exception as e:
        if not _is_definitive_absence(e):
            logger.warning(f"OAuth client ID state unknown: Secret Manager read failed ({type(e).__name__}).")
            return "unknown"

    try:
        from google.cloud import firestore
        doc = firestore.Client(project=proj).collection("platform_config").document("auth").get()
        if doc.exists:
            fs_val = str((doc.to_dict() or {}).get("google_oauth_client_id", "")).strip()
            if fs_val:
                GOOGLE_OAUTH_CLIENT_ID = fs_val
                GOOGLE_OAUTH_CLIENT_ID_SOURCE = "firestore"
                _client_id_resolved("")
                return "configured"
    except Exception as e:
        logger.warning(f"OAuth client ID state unknown: Firestore read failed ({type(e).__name__}).")
        return "unknown"
    return "absent"


# Auto-resolve at startup
GOOGLE_OAUTH_CLIENT_ID = get_google_oauth_client_id()
_PUBLISHED_DEFAULT_SESSION_SECRETS = frozenset({"castor-platform-session-secret-key-2026"})  # FD-4E: never accept


def _resolve_session_secret(env=os.environ) -> str:
    val = (env.get("SESSION_SECRET") or "").strip()
    if val and val not in _PUBLISHED_DEFAULT_SESSION_SECRETS and len(val) >= 32:
        return val
    if env.get("K_SERVICE"):  # running on Cloud Run: refuse to boot (the revision never takes traffic)
        raise RuntimeError(
            "SESSION_SECRET is missing, shorter than 32 chars, or the published default. "
            "Run `bash scripts/apply.sh apply` to mount Secret Manager secret castor-cc-session-secret. "
            + apply_where(PROJECT_ID)
        )
    import secrets as _secrets
    logger.warning("SESSION_SECRET unset outside Cloud Run: using an ephemeral per-process secret (dev/test only).")
    return _secrets.token_urlsafe(48)


SESSION_SECRET = _resolve_session_secret()
# FD-4M F3: no predictable default admin. Empty => administrators come from Firestore only.
DEFAULT_ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
if not DEFAULT_ADMIN_EMAIL:
    logger.warning("ADMIN_EMAIL is empty: Control Center administrators come from Firestore authorized_users only.")
ALLOWED_DOMAINS = os.getenv("ALLOWED_DOMAINS", "")

# VCS & Git
VCS_PROVIDER = os.getenv("VCS_PROVIDER", "GITHUB")
GITHUB_OWNER = os.getenv("GITHUB_OWNER", "")
# FD-4AY: no built-in org (empty when unset; shared.github_identity.get_default_github_owner decides at use time).
GITHUB_ORG = os.getenv("GITHUB_ORG") or os.getenv("GITHUB_DEPLOYMENTS_ORG") or GITHUB_OWNER


def get_caller_main_module():
    """Dynamically finds the active main/cc_main module by inspecting the call stack."""
    import inspect
    import sys
    import types
    try:
        frame = inspect.currentframe()
        while frame:
            for val in list(frame.f_globals.values()):
                if isinstance(val, types.ModuleType) and getattr(val, "__name__", None) in ("main", "cc_main"):
                    if "control-center" in (getattr(val, "__file__", "") or "") or hasattr(val, "app") or hasattr(val, "db"):
                        return val
            for val in list(frame.f_locals.values()):
                if isinstance(val, types.ModuleType) and getattr(val, "__name__", None) in ("main", "cc_main"):
                    if "control-center" in (getattr(val, "__file__", "") or "") or hasattr(val, "app") or hasattr(val, "db"):
                        return val
            frame = frame.f_back
    except Exception:
        pass
    for mod_name in ("cc_main", "main"):
        mod = sys.modules.get(mod_name)
        if mod and (hasattr(mod, "app") or hasattr(mod, "db")):
            return mod
    return None


def _get_http_exception_cls():
    import inspect
    import sys
    try:
        frame = inspect.currentframe()
        while frame:
            if "MockHTTPException" in frame.f_globals:
                return frame.f_globals["MockHTTPException"]
            frame = frame.f_back
    except Exception:
        pass
    fastapi_mod = sys.modules.get("fastapi")
    if fastapi_mod and hasattr(fastapi_mod, "HTTPException"):
        return fastapi_mod.HTTPException
    try:
        from fastapi import HTTPException as RealHTTPException
        return RealHTTPException
    except Exception:
        return Exception


class DynamicHTTPException(Exception):
    def __new__(cls, status_code=400, detail="", *args, **kwargs):
        target = _get_http_exception_cls()
        if target and target is not cls and issubclass(target, Exception):
            return target(status_code=status_code, detail=detail, *args, **kwargs)
        inst = super().__new__(cls, status_code, detail, *args, **kwargs)
        inst.status_code = status_code
        inst.detail = detail
        return inst


# FD-4AY: owner-specific defaults removed. GitHub owner / platform repo come only from configuration.
def github_owner() -> str:
    """GITHUB_OWNER (set by Terraform on both installs), or "" when unset. Never a guessed owner."""
    return (os.getenv("GITHUB_OWNER") or "").strip()


def require_github_owner() -> str:
    owner = github_owner()
    if not owner:
        raise DynamicHTTPException(status_code=503, detail="GITHUB_OWNER is not configured on this Control Center.")
    return owner
