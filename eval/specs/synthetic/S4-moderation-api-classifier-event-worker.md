# Synthetic Workload S4: Image Moderation (public API -> internal classifier, plus a Pub/Sub event worker)

## 1. Executive Summary & Objective
* **Product ID**: `test-s4-moderation-chain`
* **Complexity Level**: Tier 2 (Multi-Service)
* **Lifespan**: 30-Day Sandbox Workload (`is_sandbox: true`, `sandbox_ttl_days: 30`)
* **Primary Objective**: Three compute services of two kinds: a public Cloud Run API, an internal Cloud Run classifier it calls over HTTP, and a Pub/Sub-driven worker job.

### Workload Form Submission Prompt (Copy & Paste)
> Please deploy an image moderation system with three components:
>
> 1. `upload-api` (Cloud Run, public): `POST /api/v1/images` accepts an image, stores it in a Cloud Storage bucket named `pending-images`, calls the internal classifier synchronously over HTTPS (authenticated with an ID token) to get a quick safety score, and then publishes a moderation job `{object_name, quick_score}` to Pub/Sub. `GET /api/v1/images/{id}` returns the stored verdict. `GET /health` reports health.
> 2. `classifier` (Cloud Run, internal ingress only): `POST /classify` returns a deterministic safety score for an image (a simple heuristic is fine; no ML service). Only `upload-api` may invoke it.
> 3. A moderation worker job that consumes the moderation jobs from Pub/Sub, makes the final decision, moves approved images to a bucket named `approved-images`, and writes `{object_name, verdict, decided_at}` to a Firestore collection named `moderation_verdicts`.
>
> Python everywhere, Google Cloud Buildpacks only (no Dockerfiles), scale to zero, and pytest tests for all three components.

---

## 2. Architecture

```mermaid
flowchart LR
    C["Client"] -->|POST /api/v1/images| A["upload-api (public Cloud Run)"]
    A -->|POST /classify (ID token)| K["classifier (internal Cloud Run)"]
    A -->|publish job| T["Pub/Sub"]
    T --> W["moderation worker (Cloud Run Job)"]
    A --> P["GCS: pending-images"]
    W --> AP["GCS: approved-images"]
    W --> F[("Firestore: moderation_verdicts")]
```

## 3. Acceptance
* `classifier` is not reachable from the internet; only `upload-api` can invoke it.
* A posted image ends with a verdict in Firestore and, if approved, an object in `approved-images`.
* `pytest` passes for every component.
