"""
StackVend Control Center: cross-site request refusal for every state-changing request (RT14-11).

Behind Direct IAP (and in public mode, with the session cookie) a browser attaches the caller's credential to any
request it sends to this origin, including a form another site auto-submits. Several mutating routes need no body
(retrigger, deploy-infra, unlock, sandbox sweep, abort), so a cross-site `<form method=post>` could start a paid build
or an apply as the signed-in administrator. One check, in `AuthorizationMiddleware`, before anything else runs:

- a request whose method is not GET / HEAD / OPTIONS is refused (403 `CSRF_CROSS_SITE_REFUSED`) when
  - the browser's `Sec-Fetch-Site` header is present and is not `same-origin`, or
  - `Sec-Fetch-Site` is absent and the `Origin` header is present and is not exactly this request's own
    scheme-and-host (`null` is refused).
- When `Sec-Fetch-Site` is present it decides alone: it is set by the browser (a page cannot forge it), and the
  `Origin`/`Host` comparison would wrongly refuse the documented CLI proxy path (`gcloud run services proxy`), where
  the browser's origin is `http://localhost:8080` but the proxy forwards the service's `run.app` name as `Host`
  (RT14-11 review F1). The `Origin` comparison is the fallback for browsers that do not send fetch metadata.
- Requests that carry neither header (non-browser clients: Pub/Sub push, scripts, the test client) are unchanged:
  they carry no ambient browser credential, so there is nothing to forge. Same-origin dashboard fetches send
  `Sec-Fetch-Site: same-origin` and their own origin, so they are unchanged too.

The decision reads typed request headers only (the Fetch Metadata value set and a parsed Origin compared with the
Host header), never a body or a URL pattern. Public routes are covered too (the Google sign-in fetch is same-origin).
"""
from typing import Mapping, Optional
from urllib.parse import urlsplit

CSRF_CROSS_SITE_REFUSED = "CSRF_CROSS_SITE_REFUSED"
CSRF_STAGE = "control_center_request"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
ALLOWED_FETCH_SITES = frozenset({"same-origin"})


def _same_origin(origin: str, host: str) -> bool:
    try:
        parts = urlsplit(origin.strip())
    except ValueError:
        return False
    if parts.scheme not in ("https", "http") or not parts.netloc or parts.path or parts.query or parts.fragment:
        return False
    return bool(host) and parts.netloc.lower() == host.strip().lower()


def cross_site_refusal(method: str, headers: Mapping[str, str]) -> Optional[str]:
    """The reason a state-changing request is refused as cross-site, or None when it is allowed."""
    if (method or "").upper() in SAFE_METHODS:
        return None
    site = headers.get("sec-fetch-site")
    if site is not None:
        if site.strip().lower() not in ALLOWED_FETCH_SITES:
            return f"Sec-Fetch-Site is {site.strip()[:40]!r}; only same-origin requests may change state."
        return None
    origin = headers.get("origin")
    if origin is not None and not _same_origin(origin, headers.get("host") or ""):
        return f"Origin {origin.strip()[:120]!r} is not this Control Center; only same-origin requests may change state."
    return None


def refusal_body(reason: str) -> dict:
    return {"detail": f"Refused: {reason}", "error_class": CSRF_CROSS_SITE_REFUSED, "stage": CSRF_STAGE}
