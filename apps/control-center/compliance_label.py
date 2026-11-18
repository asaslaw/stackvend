"""COMPLIANCE-BASELINE-LABEL (owner 10-27): the honest display label of a workload's compliance profile.

A regulated profile chosen in an ordinary folder applies that baseline's technical controls (customer-managed
encryption keys, audit logging, allowed regions); it does not make the workload compliant. Only a profile that comes
from the parent folder's Assured Workloads regime is a compliance environment. So:

  * `profile_source == ASSURED_WORKLOADS_FOLDER` -> "Compliance: <regime> (Assured Workloads)";
  * any other non-STANDARD profile             -> "Controls: <regime> baseline (not a compliance environment)";
  * STANDARD                                   -> "Standard".

The compliance server answers `ASSURED_WORKLOADS_FOLDER` exactly when the profile is the folder's regime
(`mcp-servers/compliance/service.py::resolve_profile`), so the typed `profile_source` the gateway records in
`workloads/{pid}.compliance_decision` is the only input that can say "Assured Workloads". A record without it (made
before the explicit-profile change, or before the first compliance step ran) gets the "Controls: ... baseline" form.

The profile shown is the one the apply-time gate enforces, with the same precedence as
`mcp-servers/terraform/compliance_gate.py::load_decision` (that module is not shipped in this image):
  1. a current decision (has `profile_source`) made for the stored selection: its profile and source;
     a decision made for another selection (stale; the gate refuses the apply until the next full build) and a legacy
     decision (no `profile_source`): the stored selection, else STANDARD, with no source;
  2. else the stored selection `requested_compliance_profile`;
  3. else the legacy bare `compliance_profile`;
  4. else STANDARD.

Display only: nothing here changes resolution, enforcement, the API or intake. Pure function; exact comparisons only.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

SOURCE_FOLDER = "ASSURED_WORKLOADS_FOLDER"

KIND_STANDARD = "STANDARD"
KIND_COMPLIANCE_ENVIRONMENT = "COMPLIANCE_ENVIRONMENT"
KIND_CONTROLS_BASELINE = "CONTROLS_BASELINE"

# The names the create form shows (dashboard.html `newWorkloadForm.compliance_profile`; a test checks they match).
PROFILE_DISPLAY_NAMES = {
    "STANDARD": "Standard",
    "HIPAA": "HIPAA",
    "FEDRAMP_MODERATE": "FedRAMP Moderate",
    "FEDRAMP_HIGH": "FedRAMP High",
    "CJIS": "CJIS",
    "EU_REGIONS_AND_SUPPORT": "EU Regions and Support",
    "PCI_DSS": "PCI DSS",
}


def _text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def effective_profile(workload: Dict[str, Any]) -> tuple:
    """(profile, profile_source or None) as the apply-time gate would read it (precedence in the module docstring)."""
    data = workload if isinstance(workload, dict) else {}
    selection = _text(data.get("requested_compliance_profile"))
    decision = data.get("compliance_decision")
    if isinstance(decision, dict) and _text(decision.get("profile")):
        if "profile_source" in decision and decision.get("requested_profile") == selection:
            return decision["profile"], _text(decision.get("profile_source"))
        return selection or "STANDARD", None
    if selection:
        return selection, None
    legacy = _text(data.get("compliance_profile"))
    if legacy:
        return legacy, None
    return "STANDARD", None


def compliance_label(workload: Dict[str, Any]) -> Dict[str, str]:
    """{"compliance_label": text, "compliance_label_kind": STANDARD | COMPLIANCE_ENVIRONMENT | CONTROLS_BASELINE}."""
    profile, source = effective_profile(workload)
    if profile == "STANDARD":
        return {"compliance_label": "Standard", "compliance_label_kind": KIND_STANDARD}
    name = PROFILE_DISPLAY_NAMES.get(profile, profile)
    if source == SOURCE_FOLDER:
        return {"compliance_label": f"Compliance: {name} (Assured Workloads)",
                "compliance_label_kind": KIND_COMPLIANCE_ENVIRONMENT}
    return {"compliance_label": f"Controls: {name} baseline (not a compliance environment)",
            "compliance_label_kind": KIND_CONTROLS_BASELINE}

