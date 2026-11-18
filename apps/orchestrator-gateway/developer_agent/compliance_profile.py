"""Lane 14 PR-0b: the regulated-profile controls the platform renders into a workload's IaC.

Owner decision L14-i (10-18): the PR-0 compliance plan gate stays strict (CMEK on every CMEK-capable resource, Data
Access audit logging, regions), so the platform itself must render what the gate enforces for a regulated profile:
a per-workload Cloud KMS key (golden `security-kms`), the key wired into every platform-rendered CMEK-capable golden
module, the service-agent grants, and `google_project_iam_audit_config` (allServices, DATA_READ + DATA_WRITE).

Source of truth (never inferred from spec text). Integration with FD-4R R-6 (Fable RT
docs/planning/fd-4r-4f-code-red-team-fable.md F3 / §4.2 step 4): ONE decision per run.
  * Pipeline (gateway `_execute_developer_logic`): the persisted v2 compliance record the gateway already resolved
    for the developer's ingress (`workloads/{pid}/compliance_audits/{trace}`, fail closed with 503 when absent) is
    passed in (`controls_from_decision_record`). Its `compliance_profile` decides the render; its
    `is_regulated` / `requires_cmek` / `requires_audit_logging` must agree with that profile's requirements (typed
    refusal otherwise). The plan gate's product-keyed copy is written from the same record in the same batch.
  * Direct callers without a record (the eval harness, unit tests): the stored product-keyed decision, with exactly
    the precedence of the gate's `compliance_gate.load_decision` (lane 14 PR-0 + compliance-profile-explicit F1):
    1. `workloads/{pid}.compliance_decision` with `profile_source`: its profile, if its `requested_profile` equals the
       stored selection (`requested_compliance_profile`), else a typed DECISION_STALE refusal;
       without `profile_source` (recorded before the explicit-profile change): the selection, else STANDARD
       (`LEGACY_DECISION_REBASED`);
    2. `workloads/{pid}.requested_compliance_profile` (the stored selection, e.g. Express before any audit);
    3. `workloads/{pid}.compliance_profile` (legacy, no decision map);
    4. absent -> STANDARD (`DEFAULT_STANDARD`).
So the IaC is rendered for exactly the profile the gate will enforce at apply. A STANDARD (or absent) decision
renders byte-identical IaC to before.

`PROFILE_REQUIREMENTS` mirrors `ComplianceService.get_compliance_requirements` (mcp-servers/compliance/service.py) for
the three fields the render needs; tests/test_lane14_pr0b_regulated.py checks the two tables are equal.

Pure functions; the Firestore read is the caller's (developer handler), passed in as the workload document.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

STANDARD = "STANDARD"

# profile -> (requires_cmek, requires_audit_logging, allowed_regions). Exact copy of the compliance server's table.
PROFILE_REQUIREMENTS: Dict[str, Dict[str, Any]] = {
    "HIPAA": {"requires_cmek": True, "requires_audit_logging": True,
              "allowed_regions": ("us-central1", "us-east1", "us-east4", "us-west1")},
    "FEDRAMP_MODERATE": {"requires_cmek": True, "requires_audit_logging": True,
                         "allowed_regions": ("us-central1", "us-east1", "us-east4")},
    "FEDRAMP_HIGH": {"requires_cmek": True, "requires_audit_logging": True,
                     "allowed_regions": ("us-central1", "us-east1", "us-east4")},
    "CJIS": {"requires_cmek": True, "requires_audit_logging": True,
             "allowed_regions": ("us-central1", "us-east1", "us-east4")},
    "EU_REGIONS_AND_SUPPORT": {"requires_cmek": True, "requires_audit_logging": True,
                               "allowed_regions": ("europe-west1", "europe-west3", "europe-west4", "europe-north1")},
    "PCI_DSS": {"requires_cmek": True, "requires_audit_logging": True,
                "allowed_regions": ("us-central1", "us-east1", "us-east4")},
}
REGULATED_PROFILES = frozenset(PROFILE_REQUIREMENTS)
KNOWN_PROFILES = frozenset({STANDARD}) | REGULATED_PROFILES

# Same vocabulary as the plan gate's evidence (`compliance_gate.PROFILE_SOURCE_*`).
PROFILE_SOURCE_DECISION = "WORKLOAD_DECISION"
PROFILE_SOURCE_PROFILE = "WORKLOAD_PROFILE"
PROFILE_SOURCE_SELECTION = "WORKLOAD_SELECTION"
PROFILE_SOURCE_LEGACY = "LEGACY_DECISION_REBASED"
PROFILE_SOURCE_DEFAULT = "DEFAULT_STANDARD"
# The gateway-resolved v2 compliance record of this run (pipeline path; not a gate vocabulary value).
PROFILE_SOURCE_RECORD = "COMPLIANCE_RECORD"
# Same field as `compliance_gate.REQUESTED_PROFILE_FIELD` / the gateway's stored selection.
REQUESTED_PROFILE_FIELD = "requested_compliance_profile"

# Typed refusals (developer_agent.errors): raised before any LLM call.
COMPLIANCE_PROFILE_UNKNOWN = "COMPLIANCE_PROFILE_UNKNOWN"
COMPLIANCE_REGION_NOT_ALLOWED = "COMPLIANCE_REGION_NOT_ALLOWED"
COMPLIANCE_DECISION_UNAVAILABLE = "COMPLIANCE_DECISION_UNAVAILABLE"   # Q1 unreadable doc; an inconsistent record
COMPLIANCE_DECISION_STALE = "COMPLIANCE_DECISION_STALE"   # the gate's DECISION_STALE (it would refuse the apply)

# ------------------------------------------------------------------------------------------------------------------
# Owner options (PR-0b Fable RT §6). DECIDED by the owner 10-18 (register 73507f9): Q1 yes, Q2 yes, Q3 yes. The tests
# that pin the values are named in docs/handoff/lane14-pr0b-report.md §6.
# ------------------------------------------------------------------------------------------------------------------
# Q1: an unreadable workloads/{pid} document refuses the developer stage (COMPLIANCE_DECISION_UNAVAILABLE) instead of
# rendering STANDARD (the plan gate refuses a regulated workload at apply either way). Owner yes: True.
FAIL_CLOSED_ON_UNREADABLE_DECISION = True   # owner Q1 = yes (10-18)
# Q2: Data Access audit log types of the regulated foundation (the gate requires DATA_READ + DATA_WRITE; a superset
# passes). Owner yes: ("ADMIN_READ", "DATA_READ", "DATA_WRITE").
AUDIT_LOG_TYPES: Tuple[str, ...] = ("ADMIN_READ", "DATA_READ", "DATA_WRITE")   # owner Q2 = yes (10-18)
# Q3: profiles whose workload key is HSM-protected (Cloud KMS protection level is create-only: decide before the first
# regulated apply). Owner yes: frozenset({"FEDRAMP_HIGH", "CJIS"}).
HSM_PROFILES: frozenset = frozenset({"FEDRAMP_HIGH", "CJIS"})   # owner Q3 = yes (10-18)
# The values security-kms / workload-foundation take when the option is off (their variable defaults).
DEFAULT_PROTECTION_LEVEL = "SOFTWARE"
DEFAULT_AUDIT_LOG_TYPES: Tuple[str, ...] = ("DATA_READ", "DATA_WRITE")


class ComplianceRenderRefused(ValueError):
    """The platform cannot render IaC the plan gate would accept for this profile (typed, before generation)."""

    def __init__(self, error_class: str, message: str):
        super().__init__(f"{error_class}: {message}")
        self.error_class = error_class


@dataclass(frozen=True)
class RegulatedControls:
    """What the platform renders for a regulated profile. `None` is used for STANDARD (nothing rendered)."""

    profile: str
    source: str
    cmek: bool
    audit_logging: bool
    region: str
    protection_level: str = DEFAULT_PROTECTION_LEVEL       # owner Q3 (HSM_PROFILES)
    audit_log_types: Tuple[str, ...] = DEFAULT_AUDIT_LOG_TYPES   # owner Q2 (AUDIT_LOG_TYPES)


def profile_from_workload_doc(doc: Optional[Mapping[str, Any]]) -> Tuple[str, str]:
    """(profile, source) from the `workloads/{pid}` document, with the plan gate's precedence (module docstring).
    Raises ComplianceRenderRefused(COMPLIANCE_DECISION_STALE) where the gate raises DecisionStale."""
    data = doc if isinstance(doc, Mapping) else {}
    raw_selection = data.get(REQUESTED_PROFILE_FIELD)
    selection = raw_selection if isinstance(raw_selection, str) and raw_selection else None
    decision = data.get("compliance_decision")
    if isinstance(decision, Mapping) and isinstance(decision.get("profile"), str) and decision.get("profile"):
        if "profile_source" not in decision:
            return (selection or STANDARD), PROFILE_SOURCE_LEGACY
        if decision.get("requested_profile") != selection:
            raise ComplianceRenderRefused(
                COMPLIANCE_DECISION_STALE,
                f"the stored compliance decision was made for profile selection {decision.get('requested_profile')!r}, "
                f"the workload's selection is now {selection!r}; the compliance plan gate refuses the apply until a "
                "full build re-audits, so no IaC is generated")
        return decision["profile"], PROFILE_SOURCE_DECISION
    if selection:
        return selection, PROFILE_SOURCE_SELECTION
    profile = data.get("compliance_profile")
    if isinstance(profile, str) and profile:
        return profile, PROFILE_SOURCE_PROFILE
    return STANDARD, PROFILE_SOURCE_DEFAULT


def resolve_regulated_controls(profile: str, source: str, region: str) -> Optional[RegulatedControls]:
    """None for STANDARD; the controls for a regulated profile. Raises ComplianceRenderRefused for a profile the gate
    does not know (it would refuse UNKNOWN_PROFILE) or a platform region outside the profile's allowed regions (the
    gate would refuse every regional resource with REGION_NOT_ALLOWED)."""
    if profile == STANDARD:
        return None
    if not isinstance(profile, str):
        # Integration RT F2: a non-string profile in a record (list / dict / number) is typed, never a TypeError.
        raise ComplianceRenderRefused(
            COMPLIANCE_PROFILE_UNKNOWN,
            f"compliance profile {profile!r} ({source}) is not a string; the compliance plan gate refuses it at "
            "apply, so no IaC is generated")
    reqs = PROFILE_REQUIREMENTS.get(profile)
    if reqs is None:
        raise ComplianceRenderRefused(
            COMPLIANCE_PROFILE_UNKNOWN,
            f"stored compliance profile {profile!r} ({source}) is not one of {sorted(KNOWN_PROFILES)}; the compliance "
            "plan gate refuses it at apply, so no IaC is generated")
    if region not in reqs["allowed_regions"]:
        raise ComplianceRenderRefused(
            COMPLIANCE_REGION_NOT_ALLOWED,
            f"profile {profile} allows only {list(reqs['allowed_regions'])}; the platform deploys this workload to "
            f"{region!r} (no per-workload region yet: FD-4AL), so the compliance plan gate would refuse every "
            "regional resource. Nothing was generated")
    return RegulatedControls(profile=profile, source=source, cmek=bool(reqs["requires_cmek"]),
                             audit_logging=bool(reqs["requires_audit_logging"]), region=region,
                             protection_level="HSM" if profile in HSM_PROFILES else DEFAULT_PROTECTION_LEVEL,
                             audit_log_types=tuple(sorted(AUDIT_LOG_TYPES)))


def controls_from_decision_record(decision: Mapping[str, Any], region: str) -> Optional[RegulatedControls]:
    """Pipeline path (FD-4R R-6 integration): the controls for the gateway-resolved compliance record of this run.

    The record's `compliance_profile` decides (exact vocabulary; anything else is COMPLIANCE_PROFILE_UNKNOWN, never
    STANDARD). The record's own `is_regulated` / `requires_cmek` / `requires_audit_logging` are checked, when present
    as booleans (a pre-R-6 v1 record has no `requires_*`), against what that profile requires: a disagreement is a
    typed COMPLIANCE_DECISION_UNAVAILABLE refusal (the record contradicts itself; nothing is guessed). `is_regulated`
    may be True for STANDARD (private ingress / domain restriction), so only a regulated profile pins it."""
    if not isinstance(decision, Mapping):
        raise ComplianceRenderRefused(COMPLIANCE_DECISION_UNAVAILABLE,
                                      "the compliance record passed to the developer is not a mapping")
    profile = decision.get("compliance_profile")
    controls = resolve_regulated_controls(profile, PROFILE_SOURCE_RECORD, region)
    want = {"requires_cmek": bool(controls.cmek) if controls else False,
            "requires_audit_logging": bool(controls.audit_logging) if controls else False}
    if controls is not None:
        want["is_regulated"] = True
    bad = sorted(k for k, v in want.items() if isinstance(decision.get(k), bool) and decision[k] != v)
    if bad:
        raise ComplianceRenderRefused(
            COMPLIANCE_DECISION_UNAVAILABLE,
            f"the compliance record for profile {profile!r} disagrees with that profile's requirements on {bad}; "
            "nothing is generated")
    return controls
