"""
Project Castor: Control Center Authentication & Authorization
Enforces Google Identity Services (OIDC ID Token verification), Identity-Aware Proxy (IAP),
session cookies, and workload-scoped Role-Based Access Control (RBAC).
"""

import hashlib
import hmac
import html
import json
import logging
import os
import time
from typing import Any, Dict, Optional

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import TypeAdapter, ValidationError
from starlette.middleware.base import BaseHTTPMiddleware

import config
import identity
from config import DEFAULT_ADMIN_EMAIL, SESSION_SECRET, DynamicHTTPException as HTTPException
from db import db
from schemas import UserAccessRecord, UserRole

logger = logging.getLogger("control-center-auth")

# In-memory authorized registry fallback (FD-4M: consulted only when Firestore is unavailable;
# empty when ADMIN_EMAIL is unset, so there is no predictable default admin).
def bootstrap_registry_record(email: str) -> UserAccessRecord:
    """The install-time registry entry for the platform owner (ADMIN_EMAIL). FD-4CI-b-3d: also what an emergency
    copy of the owner's address is reset to once a later save makes that copy stale."""
    return UserAccessRecord(
        email=email,
        role=UserRole.ADMIN,
        added_at="2026-08-30T10:00:00Z",
        added_by="system-init",
        is_active=True,
    )


MOCK_AUTHORIZED_USERS: Dict[str, UserAccessRecord] = (
    {DEFAULT_ADMIN_EMAIL: bootstrap_registry_record(DEFAULT_ADMIN_EMAIL)}
    if DEFAULT_ADMIN_EMAIL
    else {}
)

_BOOL = TypeAdapter(bool)


def _record_is_active(email: str, raw) -> bool:
    """Decode is_active exactly like the Users API schema (Pydantic bool). Callers pass
    data.get("is_active", True), so a missing field is active (legacy docs); an explicit null is inactive.
    Invalid => inactive (fail closed). bootstrap.sh historically wrote the STRING "true"."""
    if raw is None:
        return False
    try:
        return _BOOL.validate_python(raw)
    except ValidationError:
        logger.error(f"authorized_users/{email}: unreadable is_active={raw!r}; treating as inactive.")
        return False


def create_session_token(email: str) -> str:
    """Generates a tamper-proof HMAC-SHA256 signed session token for the verified user email."""
    timestamp = int(time.time())
    payload = f"{email}:{timestamp}"
    signature = hmac.new(SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{signature}"


def verify_session_token(token: str, max_age_seconds: int = 86400 * 7) -> Optional[str]:
    """Verifies HMAC signature and expiration on a session token. Returns clean email or None."""
    if not token or ":" not in token:
        return None
    parts = token.split(":")
    if len(parts) != 3:
        return None
    email, timestamp_str, sig = parts
    payload = f"{email}:{timestamp_str}"
    expected_sig = hmac.new(SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        ts = int(timestamp_str)
        if time.time() - ts > max_age_seconds:
            return None
    except ValueError:
        return None
    return email.strip().lower()


def extract_user_email(request: Request) -> Optional[str]:
    """
    Verified identity only, in this order:
    1. IAP signed assertion, only when Cloud Run reports iapEnabled. An invalid assertion is fatal (no downgrade).
       In public mode, the IAP email header and x-goog-iap-jwt-assertion are ignored entirely.
       (C10, owner 11-07: the FINOPS-IAP-ACCESS platform-caller branch is gone; nothing machine-calls the CC.)
    2. HMAC session cookie (stackvend_session / castor_session) -- PUBLIC mode only (register row 41).
    3. OIDC bearer from the exact platform caller SA, audience pinned to this service's URLs. Since C10 the
       allow-list (identity.platform_callers) is empty, so every bearer is refused (fail closed).
    FD-4N: also records HOW the identity was verified on request.state.auth_method ("iap" | "session" | "bearer")
    and, for bearers, the verified audience on request.state.token_audience. Route policies (authz.py) use these.
    """
    _set_method(request, "", "")
    ri = identity.get_runtime_identity()
    if ri.iap_audience:
        # Register row 41 (owner, 10-12): behind Direct IAP the ONLY human identity is the verified IAP assertion.
        # Session cookies are not honoured in this mode (Google Sign-In is disabled too, see routes/web.py); the
        # platform-caller OIDC bearer below stays for service routes.
        assertion = request.headers.get("x-goog-iap-jwt-assertion")
        if assertion:
            try:
                email = identity.verify_iap_assertion(assertion, ri)
            except Exception as e:
                logger.warning(f"IAP assertion rejected: {e}")
                return None
            _set_method(request, "iap", "")
            return email

    session_cookie = None if ri.iap_audience else (request.cookies.get("stackvend_session") or request.cookies.get("castor_session"))
    if session_cookie:
        verified_email = verify_session_token(session_cookie)
        if verified_email:
            _set_method(request, "session", "")
            _set_session_issued_at(request, session_cookie)
            return verified_email

    auth_header = request.headers.get("authorization") or ""
    if auth_header.startswith("Bearer ") and auth_header[7:].strip():
        try:
            email, aud = identity.verify_service_bearer_claims(auth_header[7:].strip(), request.url.path, ri)
        except Exception as e:
            logger.warning(f"Bearer token rejected on {request.url.path}: {e}")
            return None
        _set_method(request, "bearer", aud)
        return email
    return None


def session_issued_at(token: str) -> Optional[int]:
    """When a VALID session token was issued (Google Sign-In time, epoch seconds); None for anything else. FD-7C P3a:
    the "recent sign-in" check of trust-anchor changes (Settings > Upgrades > Release source) reads it."""
    if not verify_session_token(token):
        return None
    try:
        return int(token.split(":")[1])
    except (IndexError, ValueError):
        return None


def _set_session_issued_at(request: Request, token: str) -> None:
    try:
        request.state.session_issued_at = session_issued_at(token)
    except Exception:  # noqa: BLE001 - no state: no sign-in time (the recent sign-in check then refuses)
        pass


def _set_method(request: Request, method: str, audience: str) -> None:
    try:
        request.state.auth_method = method
        request.state.token_audience = audience
    except Exception:  # noqa: BLE001 - a request without state cannot carry a method (fails closed upstream)
        pass


def resolve_access(email: str, auth_method: str) -> Optional[UserAccessRecord]:
    """FD-4N / red-team H2: the access record for a principal AS AUTHENTICATED BY `auth_method`.
    A platform caller (exact allow-list) is ADMIN only when it presented a verified OIDC bearer on this request;
    through Google Sign-In, a session cookie or IAP it gets nothing (no 7-day SA session)."""
    clean = (email or "").strip().lower()
    if not clean:
        return None
    if clean in identity.platform_callers():
        return get_user_access_record(clean) if auth_method == "bearer" else None
    if auth_method == "bearer":
        return None  # only platform callers authenticate with bearers
    return get_user_access_record(clean)


def get_user_access_record(email: str) -> Optional[UserAccessRecord]:
    """
    Retrieves the UserAccessRecord for a given email if authorized and active.
    Resolution order (FD-4M):
    1. Exact platform caller SA -> ADMIN.
    2. Firestore reachable: a doc for the email is AUTHORITATIVE (active record, or None if inactive),
       for every user including ADMIN_EMAIL. No doc -> only the ADMIN_EMAIL bootstrap below.
    3. Firestore unavailable (db None or the lookup raised): in-memory registry, then ADMIN_EMAIL (break-glass).
    """
    clean_email = email.strip().lower()
    if not clean_email:
        return None

    # Platform service callers: EXACT allow-list (FD-4E). No email-pattern grants.
    if clean_email in identity.platform_callers():
        return UserAccessRecord(
            email=clean_email,
            role=UserRole.ADMIN,
            added_at="2026-08-30T10:00:00Z",
            added_by="platform-service-caller",
            is_active=True,
        )

    # FD-4M: when Firestore answers, its doc is AUTHORITATIVE (active record, or None if inactive) for
    # every user including ADMIN_EMAIL. No doc -> only the ADMIN_EMAIL bootstrap below.
    firestore_answered = False
    if db:
        try:
            doc = db.collection("authorized_users").document(clean_email).get()
            firestore_answered = True
            if doc.exists:
                data = doc.to_dict() or {}
                if not _record_is_active(clean_email, data.get("is_active", True)):
                    return None
                role_str = data.get("role", "APPROVER")
                try:
                    role_enum = UserRole(role_str)
                except ValueError:
                    role_enum = UserRole.APPROVER
                # N1: explicit types so a console-typed Timestamp `added_at` or a non-list
                # `assigned_workloads` cannot break the record build.
                aw = data.get("assigned_workloads")
                added_at = data.get("added_at")
                if hasattr(added_at, "isoformat"):
                    added_at = added_at.isoformat()
                return UserAccessRecord(
                    email=clean_email,
                    role=role_enum,
                    assigned_workloads=[str(w) for w in aw] if isinstance(aw, (list, tuple)) else [],
                    added_at=str(added_at or ""),
                    added_by=str(data.get("added_by") or "admin"),
                    is_active=True,
                )
        except Exception as e:
            if firestore_answered:
                # Firestore answered but the doc is unreadable: fail closed (no break-glass, no ADMIN_EMAIL).
                logger.error(f"authorized_users/{clean_email}: unreadable record ({e}); denying.")
                return None
            logger.warning(f"Error querying authorized_users in Firestore ({e}). Using break-glass fallback.")

    # Firestore unavailable (db None or the lookup raised): per-instance in-memory registry.
    # Never consulted when Firestore answered, so a grant deleted on another instance does not linger.
    if not firestore_answered:
        rec = MOCK_AUTHORIZED_USERS.get(clean_email)
        if rec and rec.is_active:
            return rec

    # ADMIN_EMAIL bootstrap / break-glass admin (only when configured).
    if DEFAULT_ADMIN_EMAIL and clean_email == DEFAULT_ADMIN_EMAIL:
        return UserAccessRecord(
            email=DEFAULT_ADMIN_EMAIL,
            role=UserRole.ADMIN,
            added_at="2026-08-30T10:00:00Z",
            added_by="system-init",
            is_active=True,
        )

    return None


def render_forbidden_html(email: str) -> str:
    safe_email = html.escape(email)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 Access Denied — StackVend</title>
    <script src="/static/vendor/tailwind-play-3.4.17.js" integrity="sha384-igm5BeiBt36UU4gqwWS7imYmelpTsZlQ45FZf+XBn9MuJbn4nQr7yx1yFydocC/K" crossorigin="anonymous"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center font-sans p-6">
    <div class="max-w-md w-full bg-slate-900 border border-rose-500/20 rounded-2xl p-8 text-center shadow-2xl space-y-6">
        <div class="w-16 h-16 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-2xl flex items-center justify-center text-2xl mx-auto shadow-lg">
            🚫
        </div>
        <div class="space-y-2">
            <h1 class="text-xl font-bold text-white tracking-tight">Access Denied</h1>
            <p class="text-xs text-slate-400">Your Google Account is not authorized to access StackVend.</p>
        </div>
        <div class="p-3 bg-slate-950 border border-slate-800 rounded-xl">
            <p class="text-xs text-slate-300 font-mono break-all">{safe_email}</p>
        </div>
        <div class="space-y-3 pt-2">
            <p class="text-xs text-slate-500 leading-relaxed">
                Contact your StackVend administrator to add this email to the Approved Users Registry.
            </p>
            <a href="/auth/logout" class="inline-block w-full bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold py-2.5 rounded-xl border border-slate-700 transition">
                Sign in with a different account
            </a>
        </div>
    </div>
</body>
</html>
"""


def render_sign_in_html(nonce: str = "") -> str:
    # FD-103: one pass over the stores gives the client and the state. A read failure ("unknown") shows a
    # "temporarily unavailable" notice, never the one-time setup instructions.
    active_client_id, client_state = config.resolve_google_oauth_client()
    config_unavailable = not active_client_id and client_state == "unknown"
    client_id_escaped = html.escape(active_client_id)
    admin_email_val = getattr(config, "DEFAULT_ADMIN_EMAIL", "") or os.getenv("ADMIN_EMAIL", "")
    admin_email_escaped = html.escape(admin_email_val)
    project_id_val = getattr(config, "PROJECT_ID", "") or os.getenv("PROJECT_ID", "")
    project_id_escaped = html.escape(project_id_val)
    # FD-103: the first-run panel is instructions only (the install's tfvars file and the apply command).
    project_label_escaped = html.escape(project_id_val or "<project_id>")
    apply_where_escaped = html.escape(config.apply_where(project_id_val))

    template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In — StackVend Control Center</title>
    <script src="/static/vendor/tailwind-play-3.4.17.js" integrity="sha384-igm5BeiBt36UU4gqwWS7imYmelpTsZlQ45FZf+XBn9MuJbn4nQr7yx1yFydocC/K" crossorigin="anonymous"></script>
    <script src="https://accounts.google.com/gsi/client" async defer></script>
    <script defer src="/static/vendor/alpinejs-3.14.9.min.js" integrity="sha384-9Ax3MmS9AClxJyd5/zafcXXjxmwFhZCdsT6HJoJjarvCaAkJlk5QDzjLJm+Wdx5F" crossorigin="anonymous"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center font-sans p-6" x-data="googleAuthController(__CLIENT_ID_JS__, __PROJECT_ID_JS__, __CONFIG_UNAVAILABLE_JS__)">
    <div class="max-w-2xl w-full bg-slate-900 border border-slate-800 rounded-2xl p-8 sm:p-10 shadow-2xl space-y-6">
        <div class="flex items-center justify-center">
            <div class="w-14 h-14 rounded-2xl bg-gradient-to-tr from-indigo-500 to-cyan-400 flex items-center justify-center font-bold text-white text-2xl shadow-lg shadow-indigo-500/20">
                ⚙️
            </div>
        </div>

        <div class="text-center space-y-1.5">
            <h1 class="text-xl font-bold text-white tracking-tight">StackVend Control Center</h1>
            <p class="text-xs text-slate-400">Enterprise Autonomous AI Software Engineering Platform</p>
        </div>

        <div x-show="errorMessage" x-cloak class="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-300 text-xs leading-relaxed" x-text="errorMessage"></div>
        <div x-show="successMessage" x-cloak class="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-300 text-xs leading-relaxed" x-text="successMessage"></div>

        <!-- Google Identity Services Button -->
        <div class="space-y-4 pt-2">
            <div class="text-center">
                <p class="text-xs text-slate-300 font-medium mb-3">Sign in with your verified Google / Gmail Account</p>
                
                <div x-show="clientId">
                    <div id="g_id_onload"
                         :data-client_id="clientId"
                         data-context="signin"
                         data-ux_mode="popup"
                         data-login_uri="/auth/google-login"
                         data-callback="handleCredentialResponse"
                         data-auto_prompt="false">
                    </div>
                    <div class="g_id_signin flex justify-center"
                         data-type="standard"
                         data-shape="rectangular"
                         data-theme="filled_blue"
                         data-text="signin_with"
                         data-size="large"
                         data-logo_alignment="left"
                         data-width="320">
                    </div>
                </div>

                <div x-show="configUnavailable" x-cloak style="display:none" class="p-5 bg-slate-950/90 border border-amber-500/30 rounded-xl text-left text-xs text-amber-300 leading-relaxed">
                    Sign-in is temporarily unavailable: the Control Center cannot read its sign-in configuration right now. Reload this page in a minute.
                </div>

                <div x-show="!clientId &amp;&amp; !configUnavailable" class="p-5 bg-slate-950/90 border border-slate-800 rounded-xl space-y-3.5 text-left shadow-inner">
                    <div class="flex items-center justify-between">
                        <p class="text-xs text-amber-400 font-semibold flex items-center gap-1.5">
                            <span>🔑</span> Configure Google Sign-In
                        </p>
                        <span class="text-[10px] text-slate-500 font-mono bg-slate-900 px-2 py-0.5 rounded border border-slate-800">One-Time Setup</span>
                    </div>

                    <p class="text-xs text-slate-400 leading-relaxed">
                        To enable one-click Google Sign-In for your authorized users, generate a free Web OAuth Client ID in Google Cloud:
                    </p>

                    <div class="space-y-2.5 text-xs bg-slate-900/90 p-3.5 rounded-lg border border-slate-800 text-slate-300">
                        <div class="flex items-start gap-2.5">
                            <span class="font-bold text-indigo-400 text-xs">1.</span>
                            <div class="flex-1">
                                <a :href="'https://console.cloud.google.com/apis/credentials?project=' + (projectId || '')"
                                   target="_blank"
                                   rel="noopener noreferrer"
                                   class="text-indigo-400 hover:text-indigo-300 underline font-semibold inline-flex items-center gap-1">
                                    Open GCP Credentials Console ↗
                                </a>
                                <div class="mt-1 space-y-1 text-[11px] text-slate-400 leading-relaxed">
                                    <p>• If prompted to configure <b>Consent Screen</b>: select <b>External</b>, enter App Name (<span class="text-slate-200 font-mono">StackVend</span>), your support/contact email, and save through defaults.</p>
                                    <p>• Click <b>+ CREATE CREDENTIALS</b> &gt; <b>OAuth client ID</b> &gt; Application type: <b>Web application</b></p>
                                </div>
                            </div>
                        </div>

                        <div class="flex items-start gap-2.5 pt-2.5 border-t border-slate-800">
                            <span class="font-bold text-indigo-400 text-xs">2.</span>
                            <div class="flex-1 min-w-0">
                                <p class="text-slate-300">Under <b>Authorized JavaScript origins</b>, click <b>+ ADD URI</b> and paste:</p>
                                <div class="flex items-center justify-between bg-slate-950 px-3 py-2 rounded-lg mt-1.5 border border-slate-800 min-w-0">
                                    <span class="font-mono text-xs text-slate-200 truncate select-all min-w-0 flex-1" x-text="originUrl"></span>
                                    <button @click="copyText(originUrl)"
                                            type="button"
                                            class="ml-3 flex-shrink-0 px-2.5 py-1 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 text-xs rounded font-medium transition flex items-center gap-1">
                                        <span x-text="copiedOrigin ? '✓ Copied' : 'Copy'"></span>
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div class="flex items-start gap-2.5 pt-2.5 border-t border-slate-800">
                            <span class="font-bold text-indigo-400 text-xs">3.</span>
                            <div class="flex-1 min-w-0">
                                <p class="text-slate-300">Put the new <b>Client ID</b> in the install's settings file <span class="font-mono text-slate-200">infra/platform/__PROJECT_LABEL__.tfvars</span>:</p>
                                <pre class="bg-slate-950 px-3 py-2 rounded-lg mt-1.5 border border-slate-800 font-mono text-xs text-slate-200 whitespace-pre-wrap break-all select-all">cc_google_oauth_client_id = "&lt;client-id&gt;"</pre>
                            </div>
                        </div>

                        <div class="flex items-start gap-2.5 pt-2.5 border-t border-slate-800">
                            <span class="font-bold text-indigo-400 text-xs">4.</span>
                            <div class="flex-1 min-w-0">
                                <p class="text-slate-300">Apply it, then reload this page:</p>
                                <pre class="bg-slate-950 px-3 py-2 rounded-lg mt-1.5 border border-slate-800 font-mono text-xs text-slate-200 whitespace-pre-wrap break-all select-all">PROJECT_ID=__PROJECT_LABEL__ bash scripts/apply.sh apply</pre>
                                <p class="mt-1 text-[11px] text-slate-400 leading-relaxed">__APPLY_WHERE__</p>
                            </div>
                        </div>

                        <div class="flex items-start gap-2.5 pt-2.5 border-t border-slate-800">
                            <span class="font-bold text-indigo-400 text-xs">&bull;</span>
                            <div class="flex-1 min-w-0">
                                <p class="text-slate-400 text-[11px] leading-relaxed">Local development: start the Control Center with the environment variable <span class="font-mono text-slate-200 select-all">GOOGLE_OAUTH_CLIENT_ID=&lt;client-id&gt;</span> instead.</p>
                            </div>
                        </div>
                    </div>

                    <p class="text-[11px] text-slate-500 leading-relaxed">For security, the sign-in client cannot be set from this page.</p>
                </div>
            </div>
        </div>

        <div class="pt-2 border-t border-slate-800/80 text-center">
            <p class="text-[10px] text-slate-600">Protected by Google Identity Services & Cryptographic Session Signing</p>
        </div>
    </div>

    <script nonce="__CSP_NONCE__">
        window.handleCredentialResponse = async function(response) {
            try {
                const res = await fetch('/auth/google-login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ credential: response.credential })
                });
                const data = await res.json();
                if (res.ok) {
                    window.location.href = '/';
                } else {
                    alert((data.detail && data.detail.message) || data.detail || 'Authentication failed. Please try again.');
                }
            } catch (err) {
                alert('Network error verifying identity: ' + err);
            }
        };
        function googleAuthController(initialClientId, initialProjectId, initialConfigUnavailable) {
            return {
                clientId: initialClientId || '',
                projectId: initialProjectId || '',
                configUnavailable: !!initialConfigUnavailable,
                originUrl: window.location.origin,
                copiedOrigin: false,
                errorMessage: '',
                successMessage: '',

                copyText(text) {
                    navigator.clipboard.writeText(text);
                    this.copiedOrigin = true;
                    setTimeout(() => { this.copiedOrigin = false; }, 2000);
                },

                init() {
                    this.setupGoogleSignIn();
                },

                setupGoogleSignIn() {
                    if (!this.clientId) return;
                    let attempts = 0;
                    const checkGoogle = () => {
                        attempts++;
                        if (window.google && window.google.accounts && window.google.accounts.id) {
                            try {
                                google.accounts.id.initialize({
                                    client_id: this.clientId,
                                    callback: this.handleCredentialResponse.bind(this)
                                });
                                const btn = document.querySelector('.g_id_signin');
                                if (btn) {
                                    google.accounts.id.renderButton(
                                        btn,
                                        { theme: 'filled_blue', size: 'large', width: 320 }
                                    );
                                }
                            } catch (renderErr) {
                                console.error('Error rendering Google Sign-In button:', renderErr);
                            }
                        } else if (attempts < 50) {
                            setTimeout(checkGoogle, 100);
                        }
                    };
                    checkGoogle();
                },

                async handleCredentialResponse(response) {
                    this.errorMessage = '';
                    this.successMessage = 'Verifying credential with StackVend...';
                    try {
                        const res = await fetch('/auth/google-login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ credential: response.credential })
                        });
                        const data = await res.json();
                        if (res.ok) {
                            this.successMessage = 'Verified successfully! Redirecting to Control Center...';
                            setTimeout(() => { window.location.href = '/'; }, 600);
                        } else {
                            this.successMessage = '';
                            this.errorMessage = (data.detail && data.detail.message) || data.detail || 'Authentication failed. Please try again.';
                        }
                    } catch (err) {
                        this.successMessage = '';
                        this.errorMessage = 'Network error verifying identity: ' + err;
                    }
                }
            }
        }
    </script>
</body>
</html>
"""
    # FD-4AR (red-team B14): values inside the x-data JS expression are JSON-encoded THEN HTML-escaped (the browser
    # decodes entities before Alpine evaluates the expression, so html.escape alone is not enough).
    return (
        template.replace('__CLIENT_ID_JS__', html.escape(json.dumps(active_client_id)))
        .replace('__PROJECT_ID_JS__', html.escape(json.dumps(project_id_val)))
        .replace('__CONFIG_UNAVAILABLE_JS__', html.escape(json.dumps(config_unavailable)))
        .replace('__CSP_NONCE__', html.escape(nonce))
        .replace('__CLIENT_ID__', client_id_escaped)
        .replace('__ADMIN_EMAIL__', admin_email_escaped)
        .replace('__PROJECT_ID__', project_id_escaped)
        .replace('__PROJECT_LABEL__', project_label_escaped)
        .replace('__APPLY_WHERE__', apply_where_escaped)
    )


class AuthorizationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # RT14-11: a state-changing request a browser sent from another site is refused before anything else runs,
        # public routes included (csrf_guard.py). Requests without fetch metadata or Origin are unchanged.
        import csrf_guard
        csrf_reason = csrf_guard.cross_site_refusal(request.method, request.headers)
        if csrf_reason:
            logger.warning(f"Refused cross-site {request.method} {path}: {csrf_reason}")
            return JSONResponse(status_code=403, content=csrf_guard.refusal_body(csrf_reason))

        # Public paths exempt from authentication: EXACT set (FD-4N), equal to the routes whose policy is PUBLIC
        # (pinned by tests/test_cc_authz_inventory.py), plus files under the vendored-scripts mount /static/vendor/
        # (FD-4AR). FD-4M: /docs, /redoc, /openapi.json are NOT exempt; nothing else under /static is.
        from authz import is_public_path
        if is_public_path(path):
            return await call_next(request)

        # FD-4E F2: identity resolution may block (one-time Cloud Run Admin API discovery, cert fetches);
        # run it off the event loop. Imported here: some root-suite tests replace `starlette` with a MagicMock.
        from starlette.concurrency import run_in_threadpool
        email = await run_in_threadpool(extract_user_email, request)

        if not email:
            logger.warning(f"Unauthenticated request to {path}: Missing verified Google session/IAP header")
            if path.startswith("/api/"):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Authentication required: Please sign in with your verified Google/Gmail account."},
                )
            return HTMLResponse(
                status_code=401,
                content=render_sign_in_html(getattr(request.state, "csp_nonce", "")),
            )

        user_record = resolve_access(email, getattr(request.state, "auth_method", ""))
        if not user_record:
            logger.warning(f"Forbidden access attempt to {path} by unapproved Google account: {email}")
            if path.startswith("/api/"):
                return JSONResponse(
                    status_code=403,
                    content={"detail": f"Access denied: Verified Google account '{email}' is not authorized to access StackVend."},
                )
            return HTMLResponse(
                status_code=403,
                content=render_forbidden_html(email),
            )

        # Attach authenticated user identity, role, and assigned workloads to request state
        request.state.user_email = user_record.email
        request.state.user_role = user_record.role
        request.state.assigned_workloads = getattr(user_record, "assigned_workloads", []) or []

        response = await call_next(request)
        return response


AuthMiddleware = AuthorizationMiddleware


def verify_admin_access(request: Request) -> bool:
    """Enforces that caller holds the ADMIN role. Never reads TEST_MODE (FD-4N / FD25-10)."""
    user_role = getattr(request.state, "user_role", UserRole.VIEWER)
    if user_role != UserRole.ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Platform Administrator privileges required.",
        )
    return True


def verify_workload_access(
    product_id: str,
    request: Request,
    require_manager: bool = False,
) -> bool:
    """
    Validates that caller is either an ADMIN or has explicit assignment to product_id.
    If require_manager=True, rejects VIEWER with HTTP 403.
    Never reads TEST_MODE (FD-4N / FD25-10). Platform pseudo-workloads are ADMIN-only (red-team H8).
    """
    if isinstance(request, str):
        # FD25-09: swapped arguments used to surface as an AttributeError (HTTP 500) for every caller.
        raise TypeError("verify_workload_access(product_id: str, request: Request): arguments swapped")
    from authz import PLATFORM_PSEUDO_WORKLOADS
    user_role = getattr(request.state, "user_role", UserRole.VIEWER)
    assigned = getattr(request.state, "assigned_workloads", [])

    if user_role == UserRole.ADMIN:
        return True
    if not isinstance(product_id, str):
        raise HTTPException(status_code=403, detail="Access denied: invalid workload reference.")

    clean_pid = product_id.strip().lower()
    clean_assigned = [p.strip().lower() for p in (assigned or []) if isinstance(p, str) and p.strip()]

    if clean_pid not in clean_assigned or clean_pid in PLATFORM_PSEUDO_WORKLOADS:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: You are not assigned to workload '{clean_pid}'.",
        )

    if require_manager and user_role == UserRole.VIEWER:
        raise HTTPException(
            status_code=403,
            detail=f"Permission denied: Viewer role cannot modify or submit features for '{clean_pid}'.",
        )

    return True


def migrate_legacy_user_roles(firestore_client: Any):
    """One-time startup migration normalizing legacy APPROVER records in Firestore to WORKLOAD_MANAGER."""
    if not firestore_client:
        return
    try:
        docs = firestore_client.collection("authorized_users").stream()
        for d in docs:
            data = d.to_dict() or {}
            if data.get("role") == "APPROVER":
                firestore_client.collection("authorized_users").document(d.id).set(
                    {"role": "WORKLOAD_MANAGER"}, merge=True
                )
                logger.info(f"Migrated legacy user {d.id} from APPROVER to WORKLOAD_MANAGER in Firestore")
    except Exception as e:
        logger.warning(f"Legacy user role normalization check: {e}")
