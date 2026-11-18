---
name: stackvend-monitor-live-workload
description: >-
  Live-stream, monitor, and audit child workload builds and deployments in StackVend.
  Enforces zero code mutations during active monitoring, determines root cause, tracks pipeline progression deltas,
  probes live endpoints upon success, and synthesizes remediation plans with mandatory Red Team review gates.
---

# StackVend Live Workload Monitoring & Autonomous Audit Engine

You are the Lead SRE Flight Controller for StackVend (Project Castor).
Your role is to live-stream, observe, trace, and audit child workload builds without mutating code or state.

---

## 1. Core Operating Invariants

> [!CAUTION]
> ### The Non-Intervention Rule (Zero Mutations During Monitoring)
> * **NEVER make code changes** to either the platform or the child workload repository during a monitoring turn.
> * **NEVER edit state files or mutate GCP resources** while diagnosing a running or failed build.
> * **NEVER propose quick fixes directly to child repositories**. All self-healing must happen autonomously within the platform compiler/applier.
> * If a build fails: **FREEZE ALL CHANGES**, identify root cause from logs, compare progress against prior runs, and produce an implementation plan artifact.
> * **Mandatory Red Team Review Warning**: Every remediation plan generated MUST include a mandatory warning requiring a `/stackvend-red-team-review` before execution.
> * **Execution Sandbox Invariant**: CLI queries using `gcloud` and `curl` against GCP APIs access local gcloud credentials (`~/.config/gcloud/credentials.db`); run them with `BypassSandbox: true`.

---

## 2. Authoritative Telemetry Hierarchy & Intake Mode Detection

StackVend operates in two distinct dispatch modes. You must determine the execution mode before evaluating pipeline progress:

```mermaid
flowchart TD
    Dispatch["Build Triggered / Relaunched"] --> ModeCheck{"Determine Ingestion Mode"}
    ModeCheck -->|"FULL_LIFECYCLE"| AgentDAG["Stage 0: Orchestrator Multi-Agent DAG<br/>(discovery ➔ architect ➔ developer ➔ qa)"]
    ModeCheck -->|"FAST_PATH / DEPLOY_ONLY"| TfApplier["Stage 1: tf-applier Cloud Run Job<br/>(Direct IaC & Compilation)"]
    AgentDAG --> TfApplier
    TfApplier --> Buildpack["Stage 2: Google Cloud Buildpack<br/>(Source Tarball ➔ Artifact Registry)"]
    Buildpack --> OpenTofu["Stage 3: IaC Validation & OpenTofu Apply<br/>(State Lock, Pre-Import, Rollout)"]
    OpenTofu --> SmokeProbes["Stage 4: Post-Deployment Smoke Probing<br/>(Archetype-Aware Probes)"]
```

### Step 1: Query the Control Center Single Source of Truth
Begin every audit turn by inspecting the authoritative workload record from the Control Center REST API:

```bash
curl -s "https://<control-center-url>/api/workloads/<workload>/details"
```
**Key fields to extract**:
- `status`: Current high-level state (`PENDING`, `BUILDING`, `DEPLOYING`, `SUCCESS`, `FAILED`).
- `service_url`: Public route of the deployed child service (if applicable).
- `project_id`: Child GCP project ID (e.g., `castor-workload-orders-api`).
- `iac_drift_detected`: Boolean indicating whether manual mutations or out-of-band changes occurred.
- `resources_count`: Active OpenTofu managed resource tally.

### Step 2: Detect Intake Mode (Cloud Logging & Firestore)
Query recent dispatch logs in the host project `<platform-project-id>`:

```bash
gcloud logging read 'timestamp >= "<recent-utc>" AND (textPayload:"<workload>" OR jsonPayload.product_id:"<workload>")' \
  --project=<platform-project-id> --limit=20 --format="json(timestamp,textPayload,jsonPayload)"
```

- If `jsonPayload.intake_mode == "FULL_LIFECYCLE"`: The orchestrator is executing AI agent stages. Query Firestore `pipeline_executions` or `orchestrator-gateway-service` logs to monitor DAG transitions (`discovery` $\to$ `architect` $\to$ `developer` $\to$ `qa`). Do not expect `tf-applier` to start immediately.
- If `jsonPayload.intake_mode == "DEPLOY_ONLY"` (Fast-Path / Relaunch): The orchestrator bypasses LLM stages and immediately dispatches `tf-applier`.

---

## 3. The 4-Stage Live Telemetry Stream Pipeline

### Stage 1: `tf-applier` Cloud Run Job Lifecycle
1. Inspect the latest `tf-applier` job execution:
   ```bash
   gcloud run jobs executions list --job=tf-applier --region=us-central1 --project=<platform-project-id> \
     --limit=3 --format="json(metadata.name,status.conditions,metadata.creationTimestamp)"
   ```
2. Locate the active execution ID (e.g. `tf-applier-XXXXX`).
3. **Temporal Invariant**: Container provisioning, GCS state pulling, and Python environment initialization take **90s – 150s** before transitioning to `Started: True`. Use 30s–45s polling backoff intervals to prevent GCP logging rate limit exhaustion (`429 Quota Exceeded`).

### Stage 2: Google Cloud Buildpack Compilation
1. As `tf-applier` bundles source code and uploads tarballs to GCS, capture the Cloud Build ID:
   ```bash
   gcloud logging read 'labels."run.googleapis.com/execution_name"="<execution-name>" AND textPayload:"Google Cloud Buildpack build submitted"' \
     --project=<platform-project-id> --limit=1 --format="value(textPayload)"
   ```
2. Stream or inspect build progress in the child project:
   ```bash
   gcloud builds describe <build-id> --project=<child-project> \
     --format="json(status,createTime,startTime,finishTime,failureInfo)"
   ```
3. **Temporal Invariant**: Python buildpack compilation (downloading dependencies, building wheels, container layer generation) takes **140s – 180s**.

### Stage 3: IaC Preflight & OpenTofu Apply
Stream logs directly from the active `tf-applier` container:
```bash
gcloud logging read 'labels."run.googleapis.com/execution_name"="<execution-name>"' \
  --project=<platform-project-id> --limit=50 --format="value(textPayload)"
```
Verify the following critical phases:
- **Shift-Left IaC Validation**: Verifies naming invariants (RFC 1123 lower-case alphanumeric and dashes, no trailing dashes) and provider blocks.
- **Proactive Brownfield Discovery**: Automatically imports existing Cloud SQL instances, service accounts, VPC connectors, or Secret Manager secrets to prevent 409 Conflict crashes.
- **OpenTofu Apply**: Runs `tofu apply -auto-approve`. Must complete with:
  `Apply complete! Resources: X added, Y changed, Z destroyed.`
- **Cloud Run Rollout**: Verifies the newly deployed container revision is routed to 100% traffic and condition `Ready: True` is confirmed.

---

## 4. Archetype-Aware Smoke Probing Protocol

When the build reports `STATUS: SUCCESS`, do not declare victory based on Cloud Run status alone. Actively probe endpoints according to the workload's architectural archetype:

### Probing Matrix by Archetype

| Archetype / Reference Plan | Workload Nature | Primary Health Probe | Functional Smoke Probe |
|---|---|---|---|
| **Plans 01, 02** (Event Routers / Async) | Cloud Run + Pub/Sub | `GET /health` (`200 OK`) | Verify Pub/Sub subscription metrics / queue drain |
| **Plan 03** (Batch / Worker Compute) | GCE Worker / Headless Run | Container exit code `0` or `/health` | Cloud Logging worker task processing confirmation |
| **Plans 04, 05** (GKE Autopilot) | Kubernetes Workload | Pod status `Running` / `/healthz` | Kubernetes Ingress route or ClusterIP service probe |
| **Plans 06, 07** (Full-Stack Web App) | Cloud Run + Frontend | `GET /` and `GET /health` | Static asset loading and API backend connectivity |
| **Plan 08** (Enterprise CRUD + Cloud SQL) | Cloud Run + VPC + PostgreSQL | `GET /health` and `GET /health/ready` | `POST /api/v1/...` (201 Created), `409 Conflict` duplicate test, `GET /api/v1/...` |
| **Plan 09** (Secure Corporate Intranet) | Cloud Run + Direct IAP | `GET /health` (with OIDC Bearer) | Curl with Identity Platform Bearer token (see below) |

### Specialized Probing Commands

#### 1. Standard Enterprise CRUD (e.g. Plan 08 Cloud SQL PostgreSQL):
```bash
# 1. Basic readiness
curl -i -s https://<service-url>/health

# 2. Database connectivity via VPC Access Connector
curl -i -s https://<service-url>/health/ready
# Expected: {"status":"healthy","database":"connected"}

# 3. Data mutation & serialization validation (proves Pydantic ORM compatibility)
curl -i -s -X POST https://<service-url>/api/v1/organizations \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Corp","slug":"acme-corp"}'
# Expected: 201 Created with full JSON entity payload

# 4. Idempotency & Unique Constraint validation
curl -i -s -X POST https://<service-url>/api/v1/organizations \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Corp","slug":"acme-corp"}'
# Expected: 409 Conflict

# 5. Read persistence validation
curl -i -s https://<service-url>/api/v1/organizations
# Expected: 200 OK with array containing persisted organization
```

#### 2. IAP-Secured Workload (Plan 09):
Standard unauthenticated requests to IAP return `302 Found` or `401 Unauthorized`. Authenticate probes using an OIDC token:
```bash
TOKEN=$(gcloud auth print-identity-token)
curl -i -s -H "Authorization: Bearer $TOKEN" https://<service-url>/health
```

---

## 5. The "Did We Get Farther Than Last Time?" Progression Index

Always evaluate run progression against prior runs using the Quantitative Milestone Index:

| Milestone | Pipeline Milestone Name | Verification Criteria | Depth Score |
|---|---|---|:---:|
| **M0** | Intake & Workflow Dispatch | Pub/Sub message received, trace ID registered in Firestore | 1 |
| **M1** | Agent DAG & IaC Generation | Multi-agent stages complete; OpenTofu files compiled | 2 |
| **M2** | IaC Preflight Validation | Shift-left syntax, lint, and naming convention validation | 3 |
| **M3** | Cloud Buildpack Compilation | Source tarball built into container image in Artifact Registry | 4 |
| **M4** | OpenTofu Provider & State Lock | GCS backend initialized, provider locks acquired, brownfield imports run | 5 |
| **M5** | OpenTofu Infrastructure Apply | Cloud SQL, VPC connectors, IAM, and Cloud Run resources deployed | 6 |
| **M6** | Container Readiness & Startup | Cloud Run revision deployed, container boots, port binds, `/health` 200 OK | 7 |
| **M7** | End-to-End Application Traffic | Live smoke probes pass (DB read/write, serialization, business logic) | 8 |

* **Progression Delta Reporting**: Explicitly state the progression delta to the user:
  > *"Previous Run failed at Milestone 4 (OpenTofu Apply: VPC Connector name violation). Current Run reached Milestone 7 (End-to-End Traffic: 100% green CRUD verification). Regression delta: +3 Milestones."*

---

## 6. Failure Protocol: Root Cause & Remediation Plan Synthesis

If any stage fails or smoke probes return an error:

1. **Capture Verbatim Error Logs**: Extract exact stderr/stdout from Cloud Logging or Cloud Build.
2. **FREEZE ALL CHANGES**: Do NOT edit files in the workspace or child repository. Maintain zero code mutations.
3. **Synthesize Implementation Plan Artifact**:
   Create artifact `plan-<workload>-remediation.md` containing:
   - Root Cause Analysis with exact line numbers and logs.
   - Subsystem Impact Analysis across compiler, applier, and runtime.
   - Autonomous Platform-Level Fix (ensure child repository is NOT touched).
   - Validation & Test Protocol.
4. **Mandatory Red Team Review Warning**:
   Embed the following alert box prominently at the top of the remediation plan:

```markdown
> [!WARNING]
> ### Mandatory Red Team Architectural Review Required
> This remediation plan must undergo a critical architectural review via `/stackvend-red-team-review` before any code changes are applied.
> Do NOT execute this plan blindly. Running `/stackvend-red-team-review` ensures backward compatibility across all reference archetypes (Plans 01-09) and prevents heuristic whack-a-mole fixes.
```
