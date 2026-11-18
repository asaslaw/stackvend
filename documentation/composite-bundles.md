# Composite Infrastructure Bundles

A **composite bundle** is a pre-written, parameterized set of OpenTofu/Terraform configuration that wires several golden modules into a complete architecture. Agents are steered toward bundles and golden modules instead of writing every resource from scratch, which reduces (but does not eliminate) invalid or inconsistent HCL.

> **Public preview.** The bundle catalog is small and the bundles are not security-audited for production use. Review the generated infrastructure before applying it.

---

## Golden modules and bundles

| Concept | Where it lives | Purpose |
| :--- | :--- | :--- |
| **Golden module** | `infra/modules/<module-id>/` (`main.tf`, `variables.tf`, `outputs.tf`). Embedded for containers in `shared/builtin_modules_payload.py`; catalog metadata in `shared/builtin_modules_provider.py`. | A single building block (for example `compute-cloudrun`, `database-cloudsql`, `networking-vpc`). |
| **Composite bundle** | Built-in bundles are defined in `shared/builtin_bundles_payload.py`. Custom bundles are stored in the Firestore `custom_bundles` collection. | A multi-module architecture with default parameters. |

Available golden modules (see `infra/modules/`): `ai-vertex-endpoint`, `analytics-bigquery`, `cache-redis`, `compute-cloudrun`, `compute-event-worker`, `compute-gce-bastion`, `compute-gce-worker`, `compute-gke-autopilot`, `database-alloydb`, `database-bigtable`, `database-cloudsql`, `database-spanner`, `dns-record`, `event-trigger`, `messaging-pubsub`, `networking-vpc`, `observability-alerts`, `orchestration-composer`, `scheduling-cron`, `security-kms`, `security-secret`, `storage-bucket`, `tasks-queue`, `workflows-dag`, plus `workload-foundation` and `workload_auth` support modules. `networking-vpc-connector` (the Serverless VPC Access connector, on the workload's IPAM /28) is created by the platform itself: on typed infrastructure, for every Cloud Run service that uses Cloud SQL, Redis, AlloyDB or a Vertex AI endpoint; it is not in the workload module catalog. `infra/modules/` also holds one module that only the StackVend platform itself uses: `workflows` (StackVend's own orchestrator workflows). It is not listed in the workload module catalog, the developer stage never adds it to a workload, and a workload that names it is sent back for repair, with `workflows-dag` suggested instead. The list of platform-only modules is `shared/host_platform_modules.py`.

**Project variables in Cloud Run workloads.** Cloud Run itself sets no Google Cloud project variable, so the two modules that run workload code on Cloud Run set them: `compute-cloudrun` (services) and `compute-event-worker` (the worker job) both set `PROJECT_ID` and `GOOGLE_CLOUD_PROJECT` to the workload's project. `GOOGLE_CLOUD_PROJECT` is the name Google's client libraries read. When the workload's own `env_vars` already sets `GOOGLE_CLOUD_PROJECT`, `compute-cloudrun` uses that value and does not add a second entry. A workload deployed before this change gets the variable after **Upgrade IaC** updates its committed module copy (see [Known Limitations](known-limitations.md)) or after a rebuild.

---

## Built-in bundle catalog

All built-in bundles are version `1.0.0` and declare support for both OpenTofu (`tofu`) and Terraform.

| Bundle ID | Name | Category | Modules included |
| :--- | :--- | :--- | :--- |
| `secure-three-tier-web` | Enterprise Secure 3-Tier Web & DB Stack | `COMPUTE_DATA` | `networking-vpc`, `database-cloudsql`, `compute-cloudrun`, `security-secret`, `security-kms` |
| `event-driven-microservice` | Event-Driven Serverless Microservice | `EVENT_DRIVEN` | `storage-bucket`, `event-trigger`, `messaging-pubsub`, `tasks-queue`, `compute-event-worker` |
| `vertex-ai-rag-stack` | Vertex AI Enterprise RAG Stack | `AI_ML` | `storage-bucket`, `ai-vertex-endpoint`, `compute-cloudrun`, `security-secret` |
| `private-gke-microservices` | Private Multi-Zone GKE Autopilot Stack | `KUBERNETES` | `networking-vpc`, `compute-gke-autopilot`, `security-secret`, `observability-alerts` |
| `serverless-analytics-lakehouse` | Serverless Lakehouse & BigQuery Pipeline | `ANALYTICS` | `storage-bucket`, `scheduling-cron`, `messaging-pubsub`, `compute-event-worker`, `analytics-bigquery` |

Descriptions, default parameters, resource footprints and the full HCL for each bundle are in `shared/builtin_bundles_payload.py`. The record schema (`CompositeBundleRecord`) is in `shared/bundle_schema.py`.

---

## How agents use bundles

1. **Selection.** When the requirements match a pre-approved architecture, the architect sets `bundle_id` in its plan. The plan schema (`architect_agent/schemas.py`) currently restricts this field to the five built-in bundle IDs, so custom bundles are registered and vendorable but are not yet selectable by the architect.
2. **Network planning.** If the plan needs private networking, address ranges are reserved through the IPAM component before code is generated.
3. **Vendoring.** `vendor_composite_bundle` in `developer_agent/terraform_engine.py` writes the bundle's HCL into the workload repository under `infra/bundles/<bundle_id>/`, adds a manifest (`.castor-bundle.json`) and copies the golden modules it includes into `infra/modules/`.
4. **Generation and validation.** The developer agent generates workload IaC in `infra/workload/` that references the vendored bundle and modules; the result then goes through preflight validation.
5. **Apply.** The Terraform MCP server and the `tf-applier` job run `init`, `validate`, `plan` and `apply` against the child project.

---

## Custom bundles

Platform operators can register their own bundles from a Git repository through the Control Center (Settings) or the REST API:

| Endpoint | Purpose |
| :--- | :--- |
| `GET /api/settings/custom-bundles` | List built-in and custom bundles. |
| `POST /api/settings/custom-bundles/scan-repository` | Discover bundles in a repository. |
| `POST /api/settings/custom-bundles` | Register a bundle (`source_url`, `repo_path`, `version_tag`, optional overrides). |
| `POST /api/settings/custom-bundles/{bundle_id}/sync` | Re-sync from the source repository. |
| `PATCH /api/settings/custom-bundles/{bundle_id}/toggle-active` | Enable or disable a custom bundle. |
| `DELETE /api/settings/custom-bundles/{bundle_id}` | Remove a custom bundle. |

Custom golden modules have a parallel set of endpoints under `/api/settings/modules`. These endpoints require an administrator.

To add a new built-in module or bundle to the repository itself, follow [Extensibility Guide](extensibility-guide.md), and remember that the payload files are replicated across services.
