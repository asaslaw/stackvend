"""
The explicit compliance-profile selection, gateway side (compliance-profile-explicit, 10-18).

A workload's compliance profile is never inferred from its spec text. It comes from:
  1. the folder's Assured Workloads regime (decided by the compliance server), else
  2. an explicit, typed selection: `compliance_profile` on the intake event / workflow args / audit request, or the
     selection stored on the workload (`workloads/{pid}.requested_compliance_profile`, written by the Control Center
     create form and by every audit that received an explicit value), else
  3. STANDARD, recorded as `profile_source: DEFAULT_STANDARD`.

The vocabulary is exactly the compliance plan gate's (`mcp-servers/compliance/plan_gate.py::KNOWN_PROFILES`); the copy
here exists because the gateway image does not ship the compliance server. tests/test_compliance_profile_explicit.py
checks every copy is equal. Pure functions; exact comparisons only.
"""

from __future__ import annotations

from typing import Any, Optional

COMPLIANCE_PROFILES = (
    "STANDARD", "HIPAA", "FEDRAMP_MODERATE", "FEDRAMP_HIGH", "CJIS", "EU_REGIONS_AND_SUPPORT", "PCI_DSS",
)
KNOWN_PROFILES = frozenset(COMPLIANCE_PROFILES)

# The workload field that keeps the explicit selection across runs (retrigger, SRE, refactor, deploy-only).
REQUESTED_PROFILE_FIELD = "requested_compliance_profile"

# `profile_source` values recorded in `workloads/{pid}.compliance_decision`.
SOURCE_EXPLICIT_REQUEST = "EXPLICIT_REQUEST"        # this run's request carried the value
SOURCE_WORKLOAD_SELECTION = "WORKLOAD_SELECTION"    # read back from workloads/{pid}.requested_compliance_profile
SOURCE_FOLDER = "ASSURED_WORKLOADS_FOLDER"          # the parent folder's Assured Workloads regime
SOURCE_DEFAULT = "DEFAULT_STANDARD"                 # nothing selected
# What the compliance server may answer (contract v3); WORKLOAD_SELECTION is the gateway's own refinement.
SERVER_PROFILE_SOURCES = frozenset({SOURCE_EXPLICIT_REQUEST, SOURCE_FOLDER, SOURCE_DEFAULT})

ERROR_INVALID_PROFILE = "INVALID_COMPLIANCE_PROFILE"


class InvalidComplianceProfile(ValueError):
    """A value that is not exactly one of KNOWN_PROFILES (typed refusal: the route answers 422)."""

    error_class = ERROR_INVALID_PROFILE

    def __init__(self, value: Any, where: str = "compliance_profile"):
        super().__init__(f"{where} {value!r} is not one of {list(COMPLIANCE_PROFILES)}")
        self.value = value
        self.where = where

    def body(self) -> dict:
        return {"error_class": ERROR_INVALID_PROFILE, "detail": str(self), "allowed": list(COMPLIANCE_PROFILES)}


# ------------------------------------------------------------------------------------------------------------------
# Owner decisions 10-18 (register 73507f9, rows CP-8..CP-11). Strictness of the profiles, as a table.
#   rank:   higher = stricter. STANDARD is the least strict.
#   family: the region family. EU_REGIONS_AND_SUPPORT allows only EU regions, every other regulated profile only US
#           regions, so a profile of one family is never "stricter" than one of the other: the pair is incomparable.
# The same table is in mcp-servers/compliance/service.py and apps/control-center/routes/workloads.py
# (tests/test_compliance_profile_explicit.py checks they are equal).
# Note: rank is a total order inside the US family. It does not merge controls: HIPAA outranks PCI_DSS, but PCI_DSS's
# private ingress is not part of HIPAA's requirements.
# ------------------------------------------------------------------------------------------------------------------
PROFILE_STRICTNESS = {
    # profile:                (rank, family)
    "STANDARD":               (0, None),
    "PCI_DSS":                (1, "US"),
    "HIPAA":                  (2, "US"),
    "FEDRAMP_MODERATE":       (3, "US"),
    "CJIS":                   (4, "US"),
    "FEDRAMP_HIGH":           (5, "US"),
    "EU_REGIONS_AND_SUPPORT": (3, "EU"),
}

ERROR_PROFILE_CONFLICT = "COMPLIANCE_PROFILE_CONFLICT"
ERROR_UNMAPPED_REGIME = "UNMAPPED_ASSURED_WORKLOADS_REGIME"
SERVER_REFUSAL_CLASSES = frozenset({ERROR_PROFILE_CONFLICT, ERROR_UNMAPPED_REGIME})
ERROR_EXPRESS_REGULATED = "EXPRESS_REGULATED_PROFILE_UNSUPPORTED"
REASON_DOWNGRADE_APPROVAL = "COMPLIANCE_DOWNGRADE_REQUIRES_APPROVAL"
APPROVAL_TYPE_DOWNGRADE = "COMPLIANCE_PROFILE_DOWNGRADE"


def at_least_as_strict(a: str, b: str) -> bool:
    """True when profile `a` is at least as strict as `b` (exact table lookup; unknown -> KeyError)."""
    if a == b:
        return True
    ra, fa = PROFILE_STRICTNESS[a]
    rb, fb = PROFILE_STRICTNESS[b]
    if fb is None:
        return True  # everything is at least as strict as STANDARD
    if fa is None or fa != fb:
        return False
    return ra >= rb


def is_downgrade(stored: Optional[str], requested: Optional[str]) -> bool:
    """CP-11: replacing a stored REGULATED selection by one that is not at least as strict (lower rank, or the other
    region family) needs an admin approval. No stored selection, STANDARD stored, or an upgrade: no approval."""
    if not stored or not requested or stored == "STANDARD":
        return False
    return not at_least_as_strict(requested, stored)


def downgrade_approval_id(product_id: str, from_profile: str, to_profile: str) -> str:
    """Deterministic approval card id (one card per product and transition)."""
    return f"appr-cpdown-{product_id}-{from_profile}-{to_profile}".lower()


def downgrade_approval_record(product_id: str, from_profile: str, to_profile: str, *, requested_via: str,
                              trace_id: str = "", now_iso: str = "", now: float = 0.0) -> dict:
    return {
        "approval_id": downgrade_approval_id(product_id, from_profile, to_profile),
        "approval_type": APPROVAL_TYPE_DOWNGRADE,
        "product_id": product_id,
        "trace_id": trace_id or "",
        "status": "PENDING",
        "from_profile": from_profile,
        "to_profile": to_profile,
        "requested_via": requested_via,
        "cost_delta_monthly": "$0.00/mo",
        "risk_assessment": (f"Compliance profile downgrade for {product_id}: {from_profile} -> {to_profile}. "
                            "APPROVE (admin only) stores the new profile; the next run uses it. REJECT keeps "
                            f"{from_profile}."),
        "created_at": now,
        "created_at_iso": now_iso,
        "requested_at": now_iso,
    }


class ComplianceProfileRefused(Exception):
    """A typed refusal of the profile decision itself (CP-8 incomparable pair, CP-10 unmapped AW regime)."""

    def __init__(self, error_class: str, detail: str):
        super().__init__(f"{error_class}: {detail}")
        self.error_class = error_class
        self.detail = detail

    def body(self) -> dict:
        return {"error_class": self.error_class, "detail": self.detail}


def parse_profile(value: Any, where: str = "compliance_profile") -> Optional[str]:
    """None / "" -> None (no selection). An exact member of KNOWN_PROFILES -> itself. Anything else raises
    InvalidComplianceProfile (no case folding, no trimming: a typo is refused, never guessed)."""
    if value is None or value == "":
        return None
    if isinstance(value, str) and value in KNOWN_PROFILES:
        return value
    raise InvalidComplianceProfile(value, where)
