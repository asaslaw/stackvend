"""VM-EXTERNAL-IP-FALSE-CONFLICT: does the platform compute the plan declares rule out a virtual machine?

`compute.vmExternalIpAccess` concerns VMs only, but its plan check reads the plan's prose, so a plan with no VM could
raise the conflict (a word such as "bastion" next to "external IP"), which forces a plan approval and injects a NAT step
that renders nothing. The check now also asks this typed question (invariant 2: the architect's compute record, the one
the developer resolves; `private_ingress.py` reads the same record). Pure function; no I/O.

The limit of this answer: the record lists the platform's compute services and nothing else. A VM or instance template
the build writes itself in `custom.tf` is not in it, so a Cloud Run plan that also adds one reads as "no VM" here and
loses this one plan conflict. The block on the external IP itself is V2e (`org_constraint_findings`), which reads the
generated HCL, plus the folder policy at Google.
"""

from __future__ import annotations

from typing import Any

# An allow-list on purpose. `gce-bastion` and `gce-worker` are VMs. `gke-autopilot` runs on Google-managed nodes, which
# the prose check has never named, so a GKE plan keeps exactly the answer that check gives it. A kind added later also
# keeps that answer until someone lists it here.
KINDS_WITHOUT_VMS = frozenset({"cloudrun", "event-worker"})
ARCHETYPES_WITHOUT_VMS = KINDS_WITHOUT_VMS | {"foundation-only"}

# `ComputeIntent.archetype_source` values meaning nobody stated the compute (the Cloud Run contract filled it in).
_ARCHETYPE_NOT_STATED = frozenset({"architect.target_compute_services", "platform-default"})


def typed_compute_has_no_vm(intent: Any) -> bool:
    """True only when a resolved `developer_agent.compute_intent.ComputeIntent` states compute that has no VM. Says
    nothing about resources outside the record (see the module docstring).

    Topology path: every service's own kind. Records without a topology: the stated archetype (their secondaries are
    Cloud Run services by the service-list contract of compute_intent.py). A defaulted archetype states nothing."""
    if intent.topology is not None:
        return (intent.archetype in ARCHETYPES_WITHOUT_VMS
                and all(intent.kind_of(name) in KINDS_WITHOUT_VMS for name in intent.service_names))
    return intent.archetype_source not in _ARCHETYPE_NOT_STATED and intent.archetype in ARCHETYPES_WITHOUT_VMS
