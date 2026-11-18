# StackVend: Reference Workload Specifications

This directory contains nine example specifications you can submit to a running StackVend platform, through the Control Center (**New Workload**, paste the text or upload the file), through `POST /api/workloads` with the text in `spec_content`, or through a Google Drive intake folder if you have enabled Drive polling.

They are intended as test inputs that exercise different parts of the pipeline, from a single Cloud Run service to multi-service meshes, GKE, relational databases and an agent-engine solution. They are **not** guarantees: generated results vary with the models in use and with platform changes, and several of these specs are likely to expose bugs in the preview. Review the generated code and infrastructure, and run them only in a disposable environment.

Estimated costs in the examples are rough, and the examples ask for sandbox workloads that expire automatically.

---

## Catalog

| # | Specification | Target topology | Key technologies |
| :--- | :--- | :--- | :--- |
| **01** | [`01-cloudrun-pubsub-event-router.md`](./01-cloudrun-pubsub-event-router.md) | Cloud Run + Pub/Sub router | Cloud Run v2, Pub/Sub, Firestore, Cloud Storage, buildpacks |
| **02** | [`02-multi-cloudrun-vpc-mesh.md`](./02-multi-cloudrun-vpc-mesh.md) | Multi-service microservice mesh | Two Cloud Run services, Serverless VPC egress, Secret Manager, Cloud Scheduler |
| **03** | [`03-hybrid-cloudrun-gce-batch-worker.md`](./03-hybrid-cloudrun-gce-batch-worker.md) | Hybrid serverless and VM compute | Cloud Run API, Compute Engine batch worker, Cloud Storage, service accounts |
| **04** | [`04-gke-micro-stream-processor.md`](./04-gke-micro-stream-processor.md) | GKE Autopilot stream processor | GKE Autopilot, Pub/Sub, Workload Identity, Artifact Registry |
| **05** | [`05-omni-platform-distributed-fleet.md`](./05-omni-platform-distributed-fleet.md) | Heterogeneous fleet | Cloud Run, GKE Autopilot, Compute Engine Spot VM, Pub/Sub, Firestore, FinOps ceiling |
| **06** | [`06-ecommerce-widget-factory.md`](./06-ecommerce-widget-factory.md) | End-to-end e-commerce application | FastAPI API and web UI, payment webhook processing, Pub/Sub order dispatch |
| **07** | [`07-adk-agent-engine-solution.md`](./07-adk-agent-engine-solution.md) | Google ADK agent on Agent Engine | Google Agent Development Kit, Vertex AI Agent Engine, Discovery Engine datastores |
| **08** | [`08-enterprise-crud-cloudsql-postgres.md`](./08-enterprise-crud-cloudsql-postgres.md) | Enterprise CRUD with Cloud SQL | Cloud Run, Cloud SQL (PostgreSQL), VPC networking, IPAM, Alembic |
| **09** | [`09-internal-admin-direct-iap.md`](./09-internal-admin-direct-iap.md) | Zero-trust admin portal | Cloud Run, Direct IAP, SSO, role-based access |

---

## Running an example

1. **Control Center UI**: Workloads Catalog, then **New Workload**, then paste the "Workload Form Submission Prompt" from an example (or upload the file).
2. **REST API**: `POST /api/workloads` with at least `product_id` and `spec_content`.
3. **Google Drive**: copy the text into a Google Doc in the intake folder (`01_Inbox_Requests`) of an installation with Drive polling enabled, and share the folder with the platform's architect service account (`sa-castor-architect@<your-project-id>.iam.gserviceaccount.com`). The folder must be the one configured for the install (`INBOX_FOLDER_ID`): automatic discovery of every shared inbox folder is off by default until authorized submitters are supported.
