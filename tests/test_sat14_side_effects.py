"""SAT-14 side effects (owner 10-31): once the harvest reads the managed folder's denyAll "no external VM IPs" policy,
the matrix on an install with that policy has disallow_vm_external_ip = True and has_constraints = True.

SAT14-REGULATED-NARROW: a guardrail-only folder constraint is not regulation. `has_constraints` no longer makes a
workload regulated, on the compliance server (`inspect_folder`) or in the gateway (`audit_and_enrich`). The material
constraints keep their own terms (domain restriction / not public, private ingress, IAP), and the keyword conflict
check still runs before the STANDARD fast path.

SAT14-ARCHITECT-VM-LINE: the architect's policy line is conditional on the design having Compute Engine VMs.

Negatives: an install without the constraint gets a byte-identical architect prompt and the same compliance answer.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from test_compliance_bundle import _handler, _req, _resp, _v2, server  # noqa: E402,F401  (fixtures reused)
from test_architect_topology_gate import BASE, GOOD, _Client, architect  # noqa: E402,F401  (fixture reused)

# The matrix an install with the platform folder policy harvests after SAT-14.
VM_ONLY = {
    "disallow_vm_external_ip": True, "disallow_default_network": False, "require_os_login": False,
    "require_shielded_vm": False, "enforce_private_ingress": False, "enforce_uniform_bucket_level_access": False,
    "enforce_public_access_prevention": False, "domain_restricted_sharing": False, "allowed_domains": [],
    "allow_unauthenticated": True, "disable_sa_key_creation": False, "restrict_public_sql": False,
    "allowed_locations": [], "has_constraints": True,
}
NO_CONSTRAINT = {**VM_ONLY, "disallow_vm_external_ip": False, "has_constraints": False}

VM_LINE = ("- VM External IP Access is PROHIBITED for Compute Engine VMs: if the design uses Compute Engine VMs, they "
           "must not have external IPs (no access_config); reach them with Cloud IAP SSH and give them outbound access "
           "through Cloud NAT on private subnets. A design without Compute Engine VMs needs no change for this policy: "
           "do not add a VPC, NAT or jump host because of it.")


# ============================================================================== SAT14-REGULATED-NARROW: server
@pytest.mark.parametrize("matrix", [
    VM_ONLY,
    {**NO_CONSTRAINT, "require_os_login": True, "has_constraints": True},
    {**NO_CONSTRAINT, "enforce_uniform_bucket_level_access": True, "disallow_default_network": True,
     "has_constraints": True},
    {**NO_CONSTRAINT, "allowed_locations": ["in:us-locations"], "has_constraints": True},
])
def test_server_guardrail_only_constraint_is_not_regulated(server, monkeypatch, matrix):
    monkeypatch.setattr(server.main.service, "inspect_org_policies", lambda folder_id: dict(matrix))
    body = server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": "a simple public todo app"}).json()
    assert body["is_regulated"] is False
    assert body["profile"] == "STANDARD" and body["allow_unauthenticated"] is True and body["mandated_tasks"] == []
    assert body["policy_matrix"] == matrix  # the guardrail itself is still reported
    assert body["disallow_vm_external_ip"] is matrix["disallow_vm_external_ip"]


def test_server_guardrail_answer_equals_no_constraint_answer_except_the_flags(server, monkeypatch):
    bodies = {}
    for name, matrix in (("vm", VM_ONLY), ("none", NO_CONSTRAINT)):
        monkeypatch.setattr(server.main.service, "inspect_org_policies", lambda folder_id, m=matrix: dict(m))
        bodies[name] = server.client.post("/inspect-folder",
                                          json={"folder_id": "", "spec_text": "a simple public todo app"}).json()
    for b in bodies.values():
        b.pop("policy_matrix")
        b.pop("disallow_vm_external_ip")
    assert bodies["vm"] == bodies["none"]


@pytest.mark.parametrize("matrix, field", [
    ({**VM_ONLY, "domain_restricted_sharing": True, "allowed_domains": ["C0abc"], "allow_unauthenticated": False},
     "domain_restricted_sharing"),
    ({**VM_ONLY, "enforce_private_ingress": True}, "enforce_private_ingress"),
    ({**NO_CONSTRAINT, "allow_unauthenticated": False}, "allow_unauthenticated"),
])
def test_server_material_constraints_keep_their_own_terms(server, monkeypatch, matrix, field):
    monkeypatch.setattr(server.main.service, "inspect_org_policies", lambda folder_id: dict(matrix))
    body = server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": "a simple public todo app"}).json()
    assert body["is_regulated"] is True, field


# ============================================================================== SAT14-REGULATED-NARROW: gateway
def _gw(monkeypatch, matrix):
    remote = _v2(policy_matrix=dict(matrix), disallow_vm_external_ip=matrix.get("disallow_vm_external_ip", False))
    return _handler(monkeypatch, lambda *a: _resp(200, remote))


def test_gateway_guardrail_only_matrix_takes_the_standard_fast_path(monkeypatch):
    _, h, _, persisted = _gw(monkeypatch, VM_ONLY)
    res = h.audit_and_enrich(_req(spec="a simple public todo app", policy_matrix=dict(VM_ONLY),
                                  plan_markdown="# Plan\nOne Cloud Run service behind a public URL.",
                                  task_dag=[{"step_id": "STEP-01", "title": "Deploy Cloud Run", "description": "api"}]))
    assert res.status == "PASSED" and res.is_regulated is False and res.compliance_profile == "STANDARD"
    assert res.has_policy_conflicts is False and res.requires_human_approval is False
    assert res.allow_unauthenticated is True and res.injected_tasks == []
    assert persisted


def test_gateway_no_constraint_matrix_unchanged(monkeypatch):
    """Negative: an install without the folder policy gets exactly the answer it got before (fast path)."""
    _, h, _, _ = _gw(monkeypatch, NO_CONSTRAINT)
    res = h.audit_and_enrich(_req(spec="a simple public todo app", policy_matrix=dict(NO_CONSTRAINT),
                                  plan_markdown="# Plan\nOne Cloud Run service behind a public URL."))
    assert res.status == "PASSED" and res.is_regulated is False and res.has_policy_conflicts is False


def test_gateway_vm_conflict_check_still_runs_before_the_fast_path(monkeypatch):
    """The keyword conflict check (unchanged here) still runs with the guardrail: a VM with a public IP is a conflict,
    which leaves the fast path and needs approval."""
    _, h, _, _ = _gw(monkeypatch, VM_ONLY)
    res = h.audit_and_enrich(_req(spec="a batch worker", policy_matrix=dict(VM_ONLY),
                                  plan_markdown="# Plan\nA GCE vm instance with a public ip for the batch worker.",
                                  task_dag=[{"step_id": "STEP-06", "title": "GCE worker", "description": "vm"}]))
    assert res.has_policy_conflicts is True and res.policy_conflicts
    assert res.status == "ENRICHED" and res.is_regulated is True and res.requires_human_approval is True


def test_gateway_vm_without_public_ip_is_no_conflict(monkeypatch):
    _, h, _, _ = _gw(monkeypatch, VM_ONLY)
    res = h.audit_and_enrich(_req(spec="a batch worker", policy_matrix=dict(VM_ONLY),
                                  plan_markdown="# Plan\nA GCE vm instance on a private subnet; egress via Cloud NAT."))
    assert res.has_policy_conflicts is False and res.status == "PASSED" and res.is_regulated is False


@pytest.mark.parametrize("override", [
    {"domain_restricted_sharing": True, "allowed_domains": ["C0abc"], "allow_unauthenticated": False},
    {"enforce_private_ingress": True},
    {"allow_unauthenticated": False},  # a private matrix never takes the (public) fast path
])
def test_gateway_material_constraints_keep_their_own_terms(monkeypatch, override):
    matrix = {**VM_ONLY, **override}
    _, h, _, _ = _gw(monkeypatch, NO_CONSTRAINT)  # the server answer is plain STANDARD; the workflow matrix is not
    res = h.audit_and_enrich(_req(spec="a simple public todo app", policy_matrix=matrix,
                                  plan_markdown="# Plan\nOne Cloud Run service."))
    assert res.is_regulated is True and res.status == "ENRICHED"


# ============================================================================== SAT14-ARCHITECT-VM-LINE
def _prompt(agent, policy_matrix):
    agent.genai_client = _Client({**BASE, "service_topology": GOOD})
    agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="t-14", policy_matrix=policy_matrix)
    return agent.genai_client.calls[0][2]


def test_architect_prompt_without_the_constraint_is_byte_identical(architect):
    """Negative: an install without the folder policy (or no matrix at all) gets the same prompt bytes."""
    _, agent = architect
    base = _prompt(agent, None)
    assert "MANDATORY FOLDER ORGANIZATION POLICIES" not in base
    assert _prompt(agent, {}) == base
    assert _prompt(agent, dict(NO_CONSTRAINT)) == base


def test_architect_prompt_vm_line_is_conditional(architect):
    _, agent = architect
    base = _prompt(agent, None)
    p = _prompt(agent, dict(VM_ONLY))
    assert p.startswith(base)
    block = p[len(base):]
    assert block == ("\n\n--- MANDATORY FOLDER ORGANIZATION POLICIES ---\n"
                     "The target GCP deployment folder strictly enforces the following organizational constraints.\n"
                     "You MUST design the architecture and DAG tasks natively complying with these rules:\n"
                     + VM_LINE + "\n--- END ORGANIZATION POLICIES ---")
    # The old unconditional wording is gone.
    assert "Do NOT assign public IPs (access_config). Use Cloud IAP SSH, Cloud NAT, and private subnets." not in p


def test_architect_prompt_other_policy_lines_unchanged(architect):
    """Negative: only the VM line changed; every other constraint line keeps its exact text."""
    _, agent = architect
    base = _prompt(agent, None)
    p = _prompt(agent, {**NO_CONSTRAINT, "require_os_login": True, "enforce_uniform_bucket_level_access": True,
                        "restrict_public_sql": True, "has_constraints": True})
    assert p[len(base):] == (
        "\n\n--- MANDATORY FOLDER ORGANIZATION POLICIES ---\n"
        "The target GCP deployment folder strictly enforces the following organizational constraints.\n"
        "You MUST design the architecture and DAG tasks natively complying with these rules:\n"
        "- OS Login is MANDATORY: Compute instances must declare metadata = { enable-oslogin = 'TRUE' }.\n"
        "- Uniform Bucket-Level Access is ENFORCED: All GCS buckets must declare uniform_bucket_level_access = true.\n"
        "- Public IP on Cloud SQL is PROHIBITED: Cloud SQL instances must use private IP peering."
        "\n--- END ORGANIZATION POLICIES ---")


def test_architect_vm_line_avoids_the_conflict_check_vm_keywords():
    """If the architect echoes the line into its plan, the compliance keyword check must not read it as a VM with a
    public IP: the line names Cloud NAT (a NAT/private keyword) and none of the check's VM nouns except via 'Compute
    Engine VMs'."""
    lower = VM_LINE.lower()
    assert "cloud nat" in lower
    for vm_word in ("compute instance", "google_compute_instance", "vm instance", "bastion", "gce"):
        assert vm_word not in lower
