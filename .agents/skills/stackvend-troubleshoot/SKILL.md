---
name: stackvend-troubleshoot
description: >-
  Diagnose, root-cause, and remediate failed child workload builds, deployment errors,
  OpenTofu crashes, or container boot failures in StackVend. Enforces autonomous self-healing without manual child project edits.
---

# StackVend Workload & Build Troubleshooting Engine

You are the Lead SRE and Autonomous Debugger for StackVend.
Use this runbook to analyze failed child workload deployments, CI/CD pipeline breaks, and OpenTofu rejections.

---

## 1. Diagnostic Decision Tree

```mermaid
flowchart TD
    Error["Build / Deployment Failure"] --> Type{Failure Layer}
    Type -->|Terraform / IaC| IaC["Layer 1: OpenTofu & IaC Syntax"]
    Type -->|Networking & Peering| Net["Layer 2: VPC, PSA Peering & Dead Stubs"]
    Type -->|Container Boot & Buildpacks| Boot["Layer 3: Buildpack & Python Runtime"]
    Type -->|Post-Apply Container Crash| Rollout["Layer 4: Failure-Aware Revision Rollout"]
```

---

## 2. Layer 1: OpenTofu & IaC Syntax

### A. Missing PostgreSQL User Password
* **Error**: `Error 400: Missing user password for PostgreSQL instance., invalidParameter`
* **Root Cause**: Cloud SQL PostgreSQL strictly requires non-empty user passwords upon creation.
* **Remediation**:
  - Auto-wire `password = random_password.db_password.result` into `google_sql_user`.
  - Auto-synthesize `resource "random_password" "db_password"` if not present.
  - Update Secret Manager secret payload (`password = ...`) and connection string (`:${random_password.db_password.result}@`) to maintain 100% cryptographic parity across infrastructure and application runtime.

### B. Uncached / Unresolved Provider
* **Error**: `Failed to query available provider packages`
* **Root Cause**: OpenTofu running inside a zero-network runtime requires providers to be pre-cached.
* **Remediation**:
  - Add the required provider (e.g. `"random": ["3.7.1", "3.6.3"]`) to `target_providers_map` in `mcp-servers/terraform/service.py`.

### C. Self-Referential Resource Cycle
* **Error**: `Error: Self-referential block` or cycle in DAG.
* **Remediation**:
  - The deploy no longer rewrites the block (FD-55 W6c): the error returns to the developer agent's bounded
    regeneration. If it recurs, fix the generation side (prompt, skill or validator) so a resource never reads its
    own attributes (use a literal or a variable); never patch the child repository by hand.

---

## 3. Layer 2: VPC, PSA Peering & Dead Stubs

### A. Private Services Access (PSA) Peering Connection
* **Error**: `Error 400: Failed to create network connection. The project was not found or Service Networking API is not enabled...`
* **Root Cause**: Cloud SQL private IP requires a peered subnet allocated by the Google Service Networking tenant VPC.
* **Remediation**:
  - Ensure `servicenetworking.googleapis.com` is in `GCP_RESOURCE_TO_API_MAP`.
  - Declare `google_compute_global_address` with `purpose = "VPC_PEERING"`, `address_type = "INTERNAL"`, and `prefix_length = 16`.
  - Declare `google_service_networking_connection.private_vpc_connection`.
  - Wire `depends_on = [google_service_networking_connection.private_vpc_connection]` directly onto `google_sql_database_instance`.

### B. Dead Serverless VPC Access Connector (`ERROR` State)
* **Error**: `Error 409: Requested entity already exists` on `google_vpc_access_connector`.
* **Root Cause**: A prior failed run left a connector entity in state `ERROR` in the child project. GCP rejects recreating or importing errored connectors.
* **Remediation**:
  - Purge the dead stub via native REST:
    `DELETE https://vpcaccess.googleapis.com/v1/projects/{child}/locations/us-central1/connectors/{name}`
    using `AuthorizedSession`. **Never use `gcloud` subprocess** (container lacks CLI).

### C. GKE Subnetwork Update Collision
* **Error**: `The subnetwork resource ... is already being used by ... instanceGroups`
* **Root Cause**: GKE Autopilot dynamically allocated pod ranges; subsequent applies attempt to delete them in-place.
* **Remediation**:
  - Inject `lifecycle { ignore_changes = [secondary_ip_range] }` into `google_compute_subnetwork`.

---

## 4. Layer 3: Buildpack & Python Runtime

### A. Python Version Mismatch & Wheel Compilation
* **Error**: `fatal error: Python.h: No such file or directory` or wheel compilation failure.
* **Root Cause**: Google Cloud Buildpacks default to an unexpected Python version (e.g. 3.11 when dependencies require 3.12).
* **Remediation**:
  - Pin the Python runtime in `project.toml`:
    ```toml
    [[build.env]]
    name = "GOOGLE_RUNTIME_VERSION"
    value = "3.12"
    ```
  - Soften rigid dependency pins in `requirements.txt`. Replace C-compiled libraries with binary equivalents (e.g. `psycopg2-binary` instead of `psycopg2`).

### B. Commented Contract Schemas
* **Error**: `ImportError: cannot import name ... from schemas`
* **Root Cause**: Upstream code generator commented out valid Pydantic classes with `#`.
* **Remediation**:
  - Fix the generation contract and let the repair loop / QA regenerate the file. Do not un-comment code after QA: the old build-time `heal_commented_contract_schemas()` was deleted (FD-4AE) because it rewrote valid code that QA had already passed.
  - Ensure `contract_registry.py` strips markdown code fences before validating syntax.

---

## 5. Layer 4: Failure-Aware Revision Rollout

### Retriggering Container Builds Without Swarm Re-Runs
* **Scenario**: OpenTofu successfully provisioned all cloud infrastructure, but the application container crashed on boot due to an environment variable typo or transient start failure.
* **Protocol**:
  - Do NOT re-run the 15-minute 5-agent developer swarm.
  - Patch the container template directly using `_rollout_cloud_run_revision` with `CASTOR_DEPLOY_NONCE` injected into `containers[0].env`.
  - This forces Cloud Run to deploy a fresh revision while preserving all existing environment variables and infrastructure.
