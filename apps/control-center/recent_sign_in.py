"""
StackVend Control Center: the "recent sign-in" rule of sensitive Settings writes (one rule, two routes).

Used by Settings > Upgrades > Release source (SAT-11, routes/platform_release.py) and by the Terraform runner identity
mode switch (FD-7L-F4, routes/runner_identity_card.py). OQ-12c Q2: a sign-in younger than 15 minutes.

Only the session cookie carries a sign-in time (`auth.session_issued_at`, set on request.state by
`auth.extract_user_email`). Behind Identity-Aware Proxy the Control Center cannot see when the administrator signed in,
so the rule refuses there (fail closed; register row SAT11-IAP-RELEASE-SOURCE). Each route builds its own answer
(message and fallback path) from the code returned here.
"""
from typing import Optional

RECENT_SIGN_IN_SECONDS = 15 * 60
RECENT_SIGN_IN_REQUIRED = "RECENT_SIGN_IN_REQUIRED"
RECENT_SIGN_IN_UNAVAILABLE = "RECENT_SIGN_IN_UNAVAILABLE"


def sign_in_refusal(request, now: float) -> Optional[str]:
    """None when this request's administrator signed in at most RECENT_SIGN_IN_SECONDS before `now` (epoch seconds,
    the caller's clock); else RECENT_SIGN_IN_REQUIRED (a session without a recent sign-in time) or
    RECENT_SIGN_IN_UNAVAILABLE (any other authentication method: IAP, bearer, none)."""
    state = getattr(request, "state", None)
    if getattr(state, "auth_method", "") != "session":
        return RECENT_SIGN_IN_UNAVAILABLE
    issued = getattr(state, "session_issued_at", None)
    if isinstance(issued, int) and not isinstance(issued, bool) and 0 <= now - issued <= RECENT_SIGN_IN_SECONDS:
        return None
    return RECENT_SIGN_IN_REQUIRED
