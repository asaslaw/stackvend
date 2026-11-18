"""ACCESS-INTERNAL-SERVICE-ADVISORY (register row of the same name): the plan-time warning
`ACCESS.INTERNAL_SERVICE_PUBLIC`.

Who may call a Cloud Run service is decided once for the whole workload. In a Public app (`PUBLIC_APP`) every Cloud Run
service accepts requests from anyone on the internet, including a worker that only a Pub/Sub push subscription calls.
The push sends an identity token, but neither Cloud Run nor StackVend checks it; only the service's own code can. The
per-service fix (close such a service with Cloud Run IAM) is planned for a later release. Until then the compliance
stage names each such service so the operator sees it on the plan approval card.

Typed facts only (invariant 2), never the specification text (the phrase "internal ingress" is deliberately not
detected):
- the workload's access mode: `workloads/{pid}.access.mode`, exact enum (`access_mode_of`); an absent record gives no
  advisory, as the developer then takes the mode from the compliance decision and the record is written on create;
- the run's compliance decision: a decision that is not public (`allow_unauthenticated is not True` or Direct IAP)
  makes the workload private or stops the developer (ACCESS_COMPLIANCE_CONFLICT), so no advisory;
- the architect's validated service topology (`pipeline_executions/{trace}.architect_compute_intent`, resolved by
  `developer_agent.compute_intent.resolve_compute_intent`): `http_entrypoint`, `edges` with `protocol == "http"`,
  `pushes`.

A Cloud Run service gets one advisory when it is the target of a topology push edge (Pub/Sub push), is not the
workload's HTTP entrypoint and is not the callee of any `http` edge. Cloud Scheduler and Eventarc targets are not known
at this stage (they live in the developer's typed intent, built later), so this release names push targets only.

It never changes the plan and makes no model call; a non-empty list makes the pre-build gate wait for plan approval
(workflow_gates.REASON_ACCESS_INTERNAL_SERVICE_PUBLIC, owner 11-10). Malformed facts raise `AccessAdvisoryError`
(the caller maps it to a typed gate error); a clean workload never raises. Pure functions; no I/O.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple

CODE = "ACCESS.INTERNAL_SERVICE_PUBLIC"
STAGE = "compliance"
REASON_FACTS_INVALID = "ACCESS_ADVISORY_FACTS_INVALID"
REASON_FACTS_UNAVAILABLE = "ACCESS_ADVISORY_FACTS_UNAVAILABLE"

# shared.access_policy.AccessMode values (exact strings; developer_agent.access_resolution pins the same equality).
PUBLIC_APP = "PUBLIC_APP"
PRIVATE_IAM = "PRIVATE_IAM"
PRIVATE_IAP = "PRIVATE_IAP"
MODES = frozenset({PUBLIC_APP, PRIVATE_IAM, PRIVATE_IAP})

# At most this many advisories travel to the pre-build gate and the card (the gate refuses a longer list as a contract
# break: workflow_gates.MAX_ACCESS_ADVISORIES, a test pins the equality). The rest are counted, never dropped silently.
MAX_ADVISORIES = 50

DELIVERY_PUBSUB_PUSH = "PUBSUB_PUSH"
CLOUD_RUN = "cloudrun"


class AccessAdvisoryError(ValueError):
    """A fact the advisory needs is present but malformed. Never raised for a clean workload."""


def access_mode_of(access: Any, *, where: str = "workloads/{pid}.access") -> Optional[str]:
    """The workload's access mode from its stored access record: None when there is no record; the exact enum value
    otherwise. A record that is not an object, or whose `mode` is not one of the three exact values, raises."""
    if access is None:
        return None
    if not isinstance(access, Mapping):
        raise AccessAdvisoryError(f"{where} is a {type(access).__name__}, not an access record object")
    mode = access.get("mode")
    if not isinstance(mode, str) or mode not in MODES:
        raise AccessAdvisoryError(f"{where}.mode is {mode!r}, not one of {sorted(MODES)}")
    return mode


def workload_is_public(access_mode: Optional[str], *, allow_unauthenticated: Any, enable_direct_iap: Any) -> bool:
    """True only when the stored record says PUBLIC_APP and the run's compliance decision is public too (exact
    booleans). Any other combination deploys private services or stops the developer, so it needs no advisory."""
    return access_mode == PUBLIC_APP and allow_unauthenticated is True and enable_direct_iap is not True


def message(service: str) -> str:
    """The operator's sentence (plain words; the service name is a validated topology name)."""
    return (f"{service} will be reachable from the internet: in the plan only Pub/Sub push calls it, but this "
            f"workload is Public, so every Cloud Run service accepts requests from anyone and the push identity "
            f"token is checked only if the service's own code checks it. Choose Private to make every service "
            f"private (the main service too).")


def capped(advisories: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """(the first MAX_ADVISORIES advisories, how many more there are). The topology does not bound its services, so a
    plan with more push-only services than the card can carry still pauses with a count instead of failing."""
    return list(advisories[:MAX_ADVISORIES]), max(0, len(advisories) - MAX_ADVISORIES)


def internal_service_advisories(topology: Any) -> List[Dict[str, Any]]:
    """One advisory per Cloud Run push target that is neither the HTTP entrypoint nor an `http` callee, in the order of
    the topology's push edges. `topology` is a `shared.service_topology.ValidatedTopology`; None (a record without a
    topology) gives none. Facts that contradict the topology's own invariants raise `AccessAdvisoryError`."""
    if topology is None:
        return []
    try:
        names = tuple(topology.names)
        entrypoint = topology.http_entrypoint
        edges = tuple(topology.intent.edges)
        pushes = tuple(topology.pushes)
    except AttributeError as e:
        raise AccessAdvisoryError(f"the service topology is not a validated topology: {e}") from None
    if entrypoint is not None and entrypoint not in names:
        raise AccessAdvisoryError(f"http_entrypoint {entrypoint!r} is not a service of the topology {list(names)}")
    http_callees = set()
    for e in edges:
        callee, protocol = getattr(e, "callee", None), getattr(e, "protocol", None)
        if not isinstance(callee, str) or callee not in names or not isinstance(protocol, str):
            raise AccessAdvisoryError(f"edge {e!r} names no service of the topology {list(names)}")
        if protocol == "http":
            http_callees.add(callee)
    by_service: Dict[str, Dict[str, Any]] = {}
    for p in pushes:
        service, topic, path = getattr(p, "service", None), getattr(p, "topic", None), getattr(p, "path", None)
        if not isinstance(service, str) or service not in names:
            raise AccessAdvisoryError(f"push edge {p!r} targets no service of the topology {list(names)}")
        if topology.kind(service) != CLOUD_RUN:
            raise AccessAdvisoryError(f"push edge {p!r} targets {service!r} of kind {topology.kind(service)!r}, "
                                      f"not a Cloud Run service")
        if not isinstance(topic, str) or not isinstance(path, str):
            raise AccessAdvisoryError(f"push edge {p!r} has no topic or path")
        if service == entrypoint or service in http_callees:
            continue
        adv = by_service.setdefault(service, {
            "code": CODE, "service": service, "delivered_by": [DELIVERY_PUBSUB_PUSH], "push_topics": [],
            "push_paths": [], "access_mode": PUBLIC_APP, "message": message(service)})
        if topic not in adv["push_topics"]:
            adv["push_topics"].append(topic)
        if path not in adv["push_paths"]:
            adv["push_paths"].append(path)
    return list(by_service.values())
