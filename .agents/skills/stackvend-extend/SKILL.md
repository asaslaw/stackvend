---
name: stackvend-extend
description: >-
  Architect and implement major core features and capabilities in StackVend, such as
  full brownfield repository ingestion, new multi-agent swarm roles, or new cloud compute archetypes.
  Enforces cross-tier subsystem mapping, zero-drift guarantees, and platform invariant synchronization.
---

# StackVend Core Platform Extensibility Protocol

You are the Principal Systems Architect extending the core StackVend platform. 
Use this runbook when designing or implementing major functional capabilities (e.g. Full Brownfield Ingestion, multi-region support, custom agent swarms).

---

## 1. Five-Tier Subsystem Impact Mapping
Before modifying code, declare which of StackVend's 5 architectural tiers require changes:

1. **Tier 1: Ingestion & Vending** (`apps/spec-ingestion`, `apps/project-vending`):
   - Spec parsing (Markdown, Google Docs, REST payload).
   - Project binding: GCP project creation vs. existing project attachment.
2. **Tier 2: Multi-Agent Orchestration Swarm** (`apps/orchestrator-gateway`):
   - Swarm decomposition (`developer_agent/wbs_decomposer.py`).
   - Wave dispatching and Solo Fast-Path routing (`SOLO_FAST_PATH`).
   - Shared data contract validation (`contract_registry.py`).
3. **Tier 3: IaC Engine & Runtime Services** (`mcp-servers/terraform`, `tf-applier`):
   - Workspace preparation & OpenTofu execution.
   - AST resource auto-wiring (`shared/hcl_utils.py`).
   - State locking and provider pre-caching (`target_providers_map`).
4. **Tier 4: Verification & Autonomous QA** (`apps/qa-runner`, `SynthesisVerifierAgent`):
   - Ephemeral testing sandbox, Bandit security scanning, and regression gates.
5. **Tier 5: Control Center & Flight Deck UI** (`apps/control-center`):
   - Interactive modals, telemetry streams, and feature queue management.

---

## 2. Brownfield Ingestion Reference Architecture

When implementing or extending Brownfield support across existing codebases:

### A. Codebase Ingestion & Solo Fast-Path
- **Detection**: Triggered when `len(existing_files) > 0` in the target repository.
- **Routing**: If the specification is under 1,500 characters and scoped to single-wave additions, bypass the 5-agent swarm and route directly to the `SOLO_FAST_PATH` Lead Developer agent (~35-second synthesis).
- **Directory Isolation**: New services must be placed in a dedicated subdirectory (e.g. `services/<new_service>/`) to prevent accidental modification of existing application entrypoints.

### B. The Zero-Drift Guarantee
The OpenTofu plan must strictly guarantee:
$$\text{Plan: } X \text{ to add, } 0 \text{ to change, } 0 \text{ to destroy}$$
Pre-existing resources must never be tainted, recreated, or destroyed.

### C. 8-Pass Auto-Import Recovery Protocol
If an existing GCP project contains pre-provisioned assets (e.g. existing VPC networks, default service accounts, or buckets), OpenTofu will return `409 Requested entity already exists`.
- Execute the **8-pass auto-import loop** (`_reconcile_import_drift` in `service.py`).
- Parse the address and remote GCP ID from the error message.
- Run `tofu import <resource.address> <gcp_resource_id>` directly into `default.tfstate`.
- Re-run `tofu plan` to verify convergence.

### D. Deterministic Regression Hard Gate
- 100% of pre-existing unit and integration tests must run and pass before any new pull request is merged or deployed.

---

## 3. Non-Negotiable Platform Invariants

### Invariant A: Human Override Preservation (`human.tf`)
- StackVend recognizes human authority.
- Any files named `human.tf`, `human_override.tf`, or located in an `overrides/` directory are **immutable to autonomous agents**.
- Agents must inspect, preserve, and synthesize around human overrides without modifying or deleting them.

### Invariant B: Slim Container Invariant
- `tf-applier` and `mcp-terraform-server` contain no `gcloud` or binary CLI.
- All GCP management must use native Python SDKs or `google.auth.transport.requests.AuthorizedSession` REST calls.

### Invariant C: Single-Source-of-Truth Sync
If modifying foundational HCL utilities or canonical modules, synchronize across all 5 replica locations:
1. `shared/hcl_utils.py`
2. `mcp-servers/terraform/shared/hcl_utils.py`
3. `mcp-servers/terraform/hcl_utils.py`
4. `apps/orchestrator-gateway/shared/hcl_utils.py`
5. `apps/orchestrator-gateway/developer_agent/hcl_utils.py`
*(And similarly for `builtin_modules_payload.py` and `composite_bundles_payload.py`).*
