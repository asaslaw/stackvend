"""RT14-06 / RT14-16 (full-scope red-team 11-14): the architect's run context, carried as ONE object through every
decomposition path.

Before: only the single-turn path put the folder's organization policies, the operator's REWORK feedback, the quota
snapshot and the workload's current service topology into the model prompt. A large specification (map-reduce path)
never showed a model any of them, so both REWORK cycles re-ran the same plan, and the critic's remediation turn
re-planned from the raw specification without the operator's feedback.

Now `ArchitectAgent.decompose` builds one `ArchitectContext`; the single-turn prompt, every map-reduce map prompt, the
critic and the remediation turn all read it, and the prompt text comes from the one renderer below (the single-turn
prompt is byte-identical to before for the same inputs; tests/test_rt14_architect_context.py pins both).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional

# RT14 architect-context RT F3: the decomposition path that produced a plan (`ArchitectAgent.last_decomposition_path`).
DECOMPOSITION_PATH_MAP_REDUCE = "map_reduce"
DECOMPOSITION_PATH_SINGLE_TURN = "single_turn"


def _policy_constraints(policy_matrix: Any) -> List[str]:
    """The prompt lines for the active folder organization policies (typed flags of the harvested policy matrix)."""
    if not (policy_matrix and isinstance(policy_matrix, dict)):
        return []
    active_constraints: List[str] = []
    if policy_matrix.get("disallow_vm_external_ip"):
        # SAT14-ARCHITECT-VM-LINE (owner 10-31): conditional wording. The prompt is built before the architect
        # chooses the compute, so there is no typed field to gate on yet; a text check of the spec is ruled out
        # (invariant 2). The line therefore scopes itself to designs that have VMs and says explicitly that a
        # design without VMs needs nothing for it (no VPC / NAT / jump host added because of this policy).
        active_constraints.append("- VM External IP Access is PROHIBITED for Compute Engine VMs: if the design uses Compute Engine VMs, they must not have external IPs (no access_config); reach them with Cloud IAP SSH and give them outbound access through Cloud NAT on private subnets. A design without Compute Engine VMs needs no change for this policy: do not add a VPC, NAT or jump host because of it.")
    if policy_matrix.get("disallow_default_network"):
        active_constraints.append("- Default VPC Creation is PROHIBITED: Must provision custom VPC and subnets.")
    if policy_matrix.get("require_os_login"):
        active_constraints.append("- OS Login is MANDATORY: Compute instances must declare metadata = { enable-oslogin = 'TRUE' }.")
    if policy_matrix.get("require_shielded_vm"):
        active_constraints.append("- Shielded VM is MANDATORY: Compute instances must declare shielded_instance_config with secure boot.")
    if policy_matrix.get("enforce_uniform_bucket_level_access"):
        active_constraints.append("- Uniform Bucket-Level Access is ENFORCED: All GCS buckets must declare uniform_bucket_level_access = true.")
    if policy_matrix.get("enforce_public_access_prevention"):
        active_constraints.append("- Public Access Prevention is ENFORCED: All GCS buckets must declare public_access_prevention = 'enforced'.")
    if policy_matrix.get("enforce_private_ingress"):
        active_constraints.append("- Private Ingress is ENFORCED: Cloud Run services must use ingress = 'internal' or 'internal-and-cloud-load-balancing'.")
    if policy_matrix.get("restrict_public_sql"):
        active_constraints.append("- Public IP on Cloud SQL is PROHIBITED: Cloud SQL instances must use private IP peering.")
    if policy_matrix.get("domain_restricted_sharing"):
        allowed_doms = policy_matrix.get("allowed_domains", [])
        active_constraints.append(f"- Domain-Restricted Sharing is ENFORCED: Workload IAM must strictly restrict access to {allowed_doms}.")
    return active_constraints


def render_quota_block(quota_snapshot: Any) -> str:
    """The regional capacity & quota block ("" when there is no usable snapshot). The single-turn path puts it in the
    system prompt (prompt.build_architect_system_prompt); the map-reduce map prompts carry it in their own text."""
    if not (quota_snapshot and isinstance(quota_snapshot, dict)):
        return ""
    try:
        from shared.quota_inspector import sanitize_quota_for_prompt
    except ImportError:
        try:
            from apps.orchestrator_gateway.shared.quota_inspector import sanitize_quota_for_prompt  # type: ignore
        except ImportError:
            from quota_inspector import sanitize_quota_for_prompt  # type: ignore
    quota_block = sanitize_quota_for_prompt(quota_snapshot)
    return f"### REGIONAL CAPACITY & QUOTA CONSTRAINTS:\n{quota_block}\n" if quota_block else ""


@dataclass(frozen=True)
class ArchitectContext:
    """Everything about a run, beyond the specification text, that the architect's models must see.

    - policy_matrix: the folder's harvested organization-policy flags (MANDATORY constraints).
    - human_feedback: the operator's REWORK guidance from the plan-approval gate (verbatim).
    - quota_snapshot: the regional quota headroom snapshot.
    - current_topology: the workload's last committed service topology (brownfield context; never an authority).
    - remediation_brief: the critic's critical faults + the draft plan, set only for the consensus remediation turn
      (rendered after the operator's guidance, never as operator text).
    """
    policy_matrix: Optional[Dict[str, Any]] = None
    human_feedback: Optional[str] = None
    quota_snapshot: Optional[Dict[str, Any]] = None
    current_topology: Optional[Dict[str, Any]] = None
    remediation_brief: Optional[str] = None

    def with_remediation(self, brief: str) -> "ArchitectContext":
        return replace(self, remediation_brief=brief)

    @property
    def operator_feedback(self) -> Optional[str]:
        """The operator's REWORK guidance, stripped; None when there is none."""
        fb = self.human_feedback
        return fb.strip() if isinstance(fb, str) and fb.strip() else None

    def prompt_blocks(self, for_map: bool = False) -> str:
        """The context blocks appended to a decomposition prompt, in a fixed order: organization policies, operator
        REWORK guidance, current deployed topology, then (remediation turn only) the critic's brief. "" when the
        context is empty. `for_map` (RT F6): a map-reduce map prompt, whose answer has a `services` name list and no
        `service_topology`, so the topology instruction names that field instead."""
        out = ""
        constraints = _policy_constraints(self.policy_matrix)
        if constraints:
            out += (
                "\n\n--- MANDATORY FOLDER ORGANIZATION POLICIES ---\n"
                "The target GCP deployment folder strictly enforces the following organizational constraints.\n"
                "You MUST design the architecture and DAG tasks natively complying with these rules:\n"
                + "\n".join(constraints)
                + "\n--- END ORGANIZATION POLICIES ---"
            )
        feedback = self.operator_feedback
        if feedback:
            out += (
                f"\n\n--- OPERATOR REWORK GUIDANCE / FEEDBACK ---\n"
                f"A human Lead Architect reviewed the previous architecture and requested the following modifications:\n"
                f"{feedback}\n"
                f"You MUST adjust the architecture plan and Task DAG to satisfy this feedback.\n"
                f"--- END OPERATOR GUIDANCE ---"
            )
        # Lane 10 (FD-51): an existing workload's last committed service topology (context only; the developer's
        # brownfield guard checks the repository). Absent for new workloads, so their prompt is unchanged.
        if self.current_topology:
            out += (
                "\n\n--- CURRENT DEPLOYED SERVICE TOPOLOGY (last committed build of this product) ---\n"
                f"{json.dumps(self.current_topology, sort_keys=True)}\n"
                + ("Keep every existing service's name in the services you list (removing or renaming a deployed "
                   "service needs a decommission); add services only when the specification asks.\n" if for_map else
                   "Keep every existing service with the same name and kind in service_topology (removing, renaming "
                   "or re-kinding a deployed service needs a decommission); add services only when the specification "
                   "asks.\n")
                + "--- END CURRENT TOPOLOGY ---"
            )
        if self.remediation_brief and self.remediation_brief.strip():
            out += f"\n\n{self.remediation_brief.strip()}"
        return out

    def quota_block(self) -> str:
        return render_quota_block(self.quota_snapshot)

    def critic_blocks(self) -> str:
        """What the red-team critic is told about the run beyond the plan: the operator's REWORK guidance, so a plan
        that follows it (for example, removes what the operator removed) is not flagged as a dropped directive."""
        feedback = self.operator_feedback
        if not feedback:
            return ""
        return (
            "\n### OPERATOR REWORK GUIDANCE (approved by a human reviewer; it amends the specification above):\n"
            f"{feedback}\n"
            "A plan that follows this guidance where it differs from the specification has NOT dropped a directive.\n"
        )
