"""
StackVend Control Center: Content-Security-Policy and security headers (FD-4AR / FD25-13 / FD25-14).

- A fresh nonce per request (request.state.csp_nonce) is substituted into every inline <script nonce="..."> of the
  dashboard, sign-in and forbidden pages. Inline event-handler attributes are not used (and are blocked).
- 'unsafe-eval' is required by Alpine.js' standard build (expressions are compiled with Function()); moving to the
  @alpinejs/csp build would mean rewriting the 12k-line dashboard. 'unsafe-inline' styles are required by the
  Tailwind play runtime and Alpine :style bindings. Both are documented trade-offs, not oversights.
- Third-party libraries (Alpine, marked, mermaid, DOMPurify, Tailwind play) are vendored same-origin under
  /static/vendor/ at exact versions with SRI (VENDOR_MANIFEST.json, FD-4AR Q7). The only remote script is Google
  Identity Services, allowed by its exact path per Google's documented GIS CSP (Google forbids pinning it).
- This middleware must be the OUTERMOST one (added after AuthorizationMiddleware): the 401 sign-in page and the
  403 page are produced inside AuthorizationMiddleware and need the nonce and the header too.
- CC_CSP_REPORT_ONLY=true switches the header to Content-Security-Policy-Report-Only (rollback lever, owner-only).
"""
import os
import secrets

from starlette.middleware.base import BaseHTTPMiddleware

SCRIPT_HOSTS = (
    "https://accounts.google.com/gsi/client",
)


def build_csp(nonce: str) -> str:
    return "; ".join([
        "default-src 'self'",
        f"script-src 'self' 'nonce-{nonce}' 'unsafe-eval' " + " ".join(SCRIPT_HOSTS),
        "style-src 'self' 'unsafe-inline' https://accounts.google.com/gsi/style",
        "img-src 'self' data:",
        "font-src 'self' data:",
        "connect-src 'self' https://accounts.google.com/gsi/",
        "frame-src https://accounts.google.com/gsi/",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ])


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        nonce = secrets.token_urlsafe(18)
        request.state.csp_nonce = nonce
        response = await call_next(request)
        header = "Content-Security-Policy-Report-Only" if (
            os.getenv("CC_CSP_REPORT_ONLY", "").strip().lower() == "true") else "Content-Security-Policy"
        response.headers[header] = build_csp(nonce)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        return response
