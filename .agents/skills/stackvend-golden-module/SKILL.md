---
name: stackvend-golden-module
description: >-
  Author, validate, and register new OpenTofu/Terraform Golden Modules and Composite Bundles
  in StackVend. Enforces RFC 1123 naming invariants, multi-file payload synchronization, and API governance.
---

# StackVend Golden Module & Composite Bundle Authoring Protocol

You are the Lead Infrastructure Engineer authoring canonical modules and composite bundles for StackVend's Golden Catalog.

---

## 1. Golden Modules vs. Composite Bundles

| Concept | Scope | Where Defined | Purpose |
| :--- | :--- | :--- | :--- |
| **Golden Module** | Single Resource Component (e.g. `cloud-sql-postgres`, `networking-vpc`) | `shared/builtin_modules_payload.py` | Granular, composable building blocks with strict security and RFC 1123 naming defaults. |
| **Composite Bundle** | Multi-Tier Architecture (e.g. Cloud Run + Private Cloud SQL + Secret Manager) | `shared/composite_bundles_payload.py` | Turnkey architectural stacks that the Lead Architect vendors in a single shot. |

---

## 2. Platform Invariants for Golden Modules

### A. RFC 1123 Naming Governance
- Google Cloud resource names must adhere to RFC 1123 (lowercase alphanumeric and hyphens; cannot start or end with a hyphen).
- Always use `coalesce` or ternary fallback to protect against empty or hyphenated variables:
  ```hcl
  name = var.name != "" ? var.name : "${var.project_id}-resource"
  ```

### B. Dynamic Google Cloud API Auto-Enablement
- Register every new GCP resource type in `GCP_RESOURCE_TO_API_MAP` in `mcp-servers/terraform/service.py` so the platform enables the corresponding API before `tofu apply`:
  ```python
  "google_redis_instance": ["redis.googleapis.com"],
  "google_sql_database_instance": ["sqladmin.googleapis.com", "servicenetworking.googleapis.com"],
  ```

### C. Subnetwork Lifecycle Safety
- If declaring `google_compute_subnetwork`, always include:
  ```hcl
  lifecycle {
    ignore_changes = [secondary_ip_range]
  }
  ```
  *(Prevents GKE Autopilot runtime node pool pod allocations from causing in-place update collisions).*

---

## 3. Authoring Composite Bundles

When authoring a Composite Bundle (e.g. `cloudrun-postgres`):
1. **Module Composition**: Declare the participating Golden Modules and their wiring inside `shared/composite_bundles_payload.py`.
2. **Explicit Dependency Chains**:
   - Cloud SQL must depend on Service Networking PSA peering.
   - Cloud Run must depend on Secret Manager database credentials.
3. **Cryptographic Parity**:
   - Ensure database users and Secret Manager connection strings share the exact same `random_password` resource.

---

## 4. Single-Source-of-Truth Payload Synchronization

Whenever you update `builtin_modules_payload.py` or `composite_bundles_payload.py`, synchronize across all 4 engine replicas:
1. `shared/builtin_modules_payload.py`
2. `mcp-servers/terraform/shared/builtin_modules_payload.py`
3. `apps/orchestrator-gateway/shared/builtin_modules_payload.py`
4. `apps/control-center/shared/builtin_modules_payload.py`

---

## 5. Verification Commands
Always verify with the automated test suite before committing:
```bash
pytest tests/test_hcl_utils.py
pytest mcp-servers/terraform/test_service.py
```
