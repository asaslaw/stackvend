"""PRIVATE-INGRESS-EARLY-STOP (owner 11-08, register row of the same name): the early, typed stop.

The compliance decision can ask for internal-only ingress (`enforce_private_ingress`: from the specification wording,
the folder's organization policy or the profile). The apply-time gate (mcp-servers/compliance/plan_gate.py) then
requires it on every `google_cloud_run_v2_service`, but this release cannot render a per-service `ingress`: the golden
compute-cloudrun module keeps its default and the typed topology has no ingress field. Such a run always ends in
COMPLIANCE_VIOLATION / PRIVATE_INGRESS_NOT_SET at apply, after a child project, a developer run, QA and a human release
approval. The compliance stage now stops it first. The apply gate is unchanged.

The stop is decided from typed facts only (invariant 2): the existing flag and the architect's typed compute record
(`pipeline_executions/{trace}.architect_compute_intent`, the record the developer resolves). Pure functions; no I/O.
"""

from __future__ import annotations

from typing import Any, List, Mapping, Sequence

from gate_errors import ErrorClass

# Which input asked for private ingress. The compliance server reports them (`private_ingress_sources`, additive; the
# same names are in mcp-servers/compliance/service.py, tests/test_private_ingress_early_stop.py checks they are equal).
SOURCE_SPEC_WORDING = "SPEC_WORDING"
SOURCE_ORG_POLICY = "ORG_POLICY"
SOURCE_PROFILE = "COMPLIANCE_PROFILE"
KNOWN_SOURCES = (SOURCE_SPEC_WORDING, SOURCE_ORG_POLICY, SOURCE_PROFILE)

REASON_UNSUPPORTED = "PRIVATE_INGRESS_UNSUPPORTED"
REASON_COMPUTE_UNKNOWN = "COMPLIANCE_COMPUTE_INTENT_UNAVAILABLE"
STAGE = "compliance"


def cloud_run_services(intent: Any) -> List[str]:
    """The Cloud Run services (`google_cloud_run_v2_service`, the only resource type the apply gate checks) of a
    resolved `developer_agent.compute_intent.ComputeIntent`, in plan order.

    Topology path: every service whose typed kind is `cloudrun`. Legacy records (no topology): the service list
    contract of compute_intent.py, `service_names[1:]` are Cloud Run secondaries and `service_names[0]` is a Cloud Run
    service only when the archetype is `cloudrun`. Cloud Run Jobs (`event-worker`), GKE, VMs and foundation-only plans
    add nothing."""
    if intent.topology is not None:
        return [name for name in intent.service_names if intent.kind_of(name) == "cloudrun"]
    if intent.archetype == "cloudrun":
        return list(intent.service_names)
    return list(intent.secondary_services)


def requested_by(sources: Sequence[str], spec_terms: Sequence[str], profile: str) -> List[str]:
    """One plain sentence fragment per input that asked for private ingress (data from the typed decision only)."""
    parts: List[str] = []
    if SOURCE_SPEC_WORDING in sources:
        wording = ", ".join(repr(t) for t in spec_terms)
        parts.append(f"the specification wording ({wording})" if wording else "the specification wording")
    if SOURCE_ORG_POLICY in sources:
        parts.append("the organization policy on the folder (constraints/run.allowedIngress)")
    if SOURCE_PROFILE in sources:
        parts.append(f"the {profile} compliance profile")
    return parts


def unsupported_message(services: Sequence[str], sources: Sequence[str], spec_terms: Sequence[str],
                        profile: str) -> str:
    """The operator's message: what cannot be done, which input asked for it, and what to do."""
    named = requested_by(sources, spec_terms, profile)
    asked = "; ".join(named) if named else "the compliance decision (the compliance server did not report which input)"
    return (
        f"{ErrorClass.COMPLIANCE_PRIVATE_INGRESS_UNSUPPORTED.value}: This release cannot make Cloud Run services "
        f"internal-only, and the compliance decision requires it, so the run stopped before anything was built or "
        f"changed. Cloud Run services in the plan: {', '.join(services)}. Asked for by: {asked}. What to do: remove "
        f"that requirement (change the wording, the compliance profile or the organization policy), or plan the "
        f"workload without Cloud Run services. With the requirement gone, you can protect the services with IAM only "
        f"(authenticated callers with a verified identity token). Per-service private ingress is planned for a later "
        f"release."
    )


def known_sources(raw: Any) -> List[str]:
    """The source names the compliance server reported, restricted to the exact vocabulary (data, never a guess)."""
    if not isinstance(raw, (list, tuple)):
        return []
    return [s for s in KNOWN_SOURCES if s in raw]


def spec_terms_of(raw: Any) -> List[str]:
    return [t for t in raw if isinstance(t, str)] if isinstance(raw, (list, tuple)) else []


def org_policy_asked(policy_matrix: Any) -> bool:
    return isinstance(policy_matrix, Mapping) and bool(policy_matrix.get("enforce_private_ingress"))
