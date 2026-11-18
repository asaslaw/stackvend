"""
Project Castor: Autonomous Sandbox Workload Detection & Lifecycle Timing Engine
Provides natural language intent detection, 30-day lifecycle expiration calculation,
remaining duration tracking, and anti-abuse extension validation.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

# Third-party false-positive indicators (negative context)
# Excludes references where 'sandbox' belongs to an external vendor, payment gateway, or third-party service
THIRD_PARTY_EXCLUSIONS = re.compile(
    r"\b(?:stripe|paypal|plaid|twilio|salesforce|github|aws|azure|external|third[- ]party|mock|api|vendor|client)\b.*?\bsand\s*box\b",
    re.IGNORECASE,
)

# First-party self-designation directives
# Matches commands or declarations to create the workload itself as an ephemeral sandbox
SANDBOX_DIRECTIVES = re.compile(
    r"\b(?:make|create|deploy|build|run|set\s+up|spin\s+up)\s+(?:this\s+)?(?:as\s+)?(?:a\s+)?sand\s*box(?:\s+(?:enviornment|environment|env|mode|instance))?\b",
    re.IGNORECASE,
)

SANDBOX_ENV_PHRASES = re.compile(
    r"\b(?:this\s+(?:is|workload\s+is)\s+(?:a\s+)?)?sand\s*box\s+(?:enviornment|environment|env|mode)\b",
    re.IGNORECASE,
)

EPHEMERAL_PHRASES = re.compile(
    r"\b(?:ephemeral|temporary|spike|poc)\s+sand\s*box\b",
    re.IGNORECASE,
)

TEMPORARY_TEST_PATTERNS = re.compile(
    r"\b(?:temporary|throwaway|disposable|eval|evaluation)\s+(?:test\s+)?(?:enviornment|environment|env|sandbox)\b",
    re.IGNORECASE,
)

MAX_SANDBOX_CUMULATIVE_DAYS = 90
MAX_SANDBOX_EXTENSIONS = 3
DEFAULT_SANDBOX_TTL_DAYS = 30


def detect_sandbox_intent(text: str) -> Tuple[bool, int]:
    """
    Parses text to determine if the workload self-designates as an ephemeral sandbox.
    Returns (is_sandbox: bool, ttl_days: int).
    Safeguarded against external third-party API sandbox references.
    """
    if not text or not text.strip():
        return False, DEFAULT_SANDBOX_TTL_DAYS

    clean_text = text.strip()

    # Guard against false positives if phrase specifically refers to third-party sandbox
    # and has no explicit self-creation directive
    if THIRD_PARTY_EXCLUSIONS.search(clean_text) and not SANDBOX_DIRECTIVES.search(clean_text):
        return False, DEFAULT_SANDBOX_TTL_DAYS

    # Check for direct self-designation directives or ephemeral/test environment phrases
    has_directive = bool(
        SANDBOX_DIRECTIVES.search(clean_text)
        or SANDBOX_ENV_PHRASES.search(clean_text)
        or EPHEMERAL_PHRASES.search(clean_text)
        or TEMPORARY_TEST_PATTERNS.search(clean_text)
    )

    if not has_directive:
        return False, DEFAULT_SANDBOX_TTL_DAYS

    # Extract optional custom TTL if specified (e.g. 'sandbox with 60 days', 'for 14 days', '(14d ttl)')
    ttl_days = DEFAULT_SANDBOX_TTL_DAYS
    m1 = re.search(r"\b(?:with|for|\()\s*(\d{1,3})\s*(?:day|days|d)\b", clean_text, re.IGNORECASE)
    m2 = re.search(r"\b(\d{1,3})\s*(?:day|days|d)\s*(?:duration|ttl|sandbox|lifecycle)\b", clean_text, re.IGNORECASE)
    m3 = re.search(r"\(?(\d{1,3})d(?:\s*ttl)?\)?", clean_text, re.IGNORECASE)

    for m in (m1, m2, m3):
        if m:
            try:
                parsed_ttl = int(m.group(1))
                if 1 <= parsed_ttl <= MAX_SANDBOX_CUMULATIVE_DAYS:
                    ttl_days = parsed_ttl
                    break
            except (ValueError, TypeError):
                pass

    return True, ttl_days


def compute_sandbox_expiry(ttl_days: int = DEFAULT_SANDBOX_TTL_DAYS) -> str:
    """Returns ISO 8601 UTC timestamp for now + ttl_days."""
    return (datetime.now(timezone.utc) + timedelta(days=ttl_days)).isoformat()


def compute_days_remaining(expires_at_iso: Optional[str]) -> Optional[float]:
    """Calculates float days remaining until expiration (0.0 if expired or None)."""
    if not expires_at_iso:
        return None
    try:
        exp_dt = datetime.fromisoformat(expires_at_iso.replace("Z", "+00:00"))
        now_dt = datetime.now(timezone.utc)
        diff_sec = (exp_dt - now_dt).total_seconds()
        return max(round(diff_sec / 86400.0, 2), 0.0)
    except Exception:
        return None


def validate_extension(
    current_cumulative_days: int,
    current_extensions: int = 0,
    extend_days: int = 30,
    **kwargs,
) -> Tuple[bool, str]:
    """
    Validates whether an operator extension request complies with anti-abuse guardrails:
    - Maximum 3 extensions
    - Maximum 90 cumulative lifespan days
    Returns (is_valid: bool, error_message: str).
    """
    if "current_extension_count" in kwargs:
        current_extensions = kwargs["current_extension_count"]
    if "extension_days" in kwargs:
        extend_days = kwargs["extension_days"]

    if current_extensions >= MAX_SANDBOX_EXTENSIONS:
        return False, f"Maximum extension limit ({MAX_SANDBOX_EXTENSIONS}) reached. Please promote to permanent production."

    new_cumulative = current_cumulative_days + extend_days
    if new_cumulative > MAX_SANDBOX_CUMULATIVE_DAYS:
        return False, f"Cumulative maximum lifespan exceeded ({MAX_SANDBOX_CUMULATIVE_DAYS} days max; requested total {new_cumulative} days). Please promote to permanent production."

    if extend_days < 1 or extend_days > 30:
        return False, "Extension duration must be between 1 and 30 days."

    return True, ""
