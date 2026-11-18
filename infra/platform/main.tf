# ==============================================================================
# PROJECT CASTOR: CORE PLATFORM INFRASTRUCTURE (LAYER 1)
# ==============================================================================

locals {
  # All required Google Cloud APIs for Project Castor & Agent Platform
  services = [
    "compute.googleapis.com",
    "run.googleapis.com",
    "workflows.googleapis.com",
    "pubsub.googleapis.com",
    "firestore.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudscheduler.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "clouderrorreporting.googleapis.com",
    "cloudtrace.googleapis.com",
    "storage.googleapis.com",
    "container.googleapis.com",          # Google Kubernetes Engine (GKE) Core API
    "cloudbilling.googleapis.com",       # Google Cloud Billing API
    "drive.googleapis.com",              # Google Drive API for Spec Ingestion & Auto-Discovery
    "docs.googleapis.com",               # Google Docs API for Living Requirements Docs
    "aiplatform.googleapis.com",         # Vertex AI Core API
    "discoveryengine.googleapis.com",    # Vertex AI Agent Builder & Agent Engine API
    "generativelanguage.googleapis.com", # Gemini Developer API
    "agentregistry.googleapis.com",      # Google Cloud Agent Registry API
    "cloudapiregistry.googleapis.com",   # Cloud API Registry for Remote MCP Servers
    "identitytoolkit.googleapis.com",    # Google Cloud Identity Platform (Firebase Auth)
    "iap.googleapis.com",                # Identity-Aware Proxy (IAP) API for Direct Cloud Run Auth
    "servicenetworking.googleapis.com",  # Google Service Networking API for Private Service Access (Cloud SQL/AlloyDB/Redis)
    "vpcaccess.googleapis.com",          # Serverless VPC Access API for Serverless Egress
    "sqladmin.googleapis.com",           # Google Cloud SQL Admin API for Database Provisioning & Management
    "iamcredentials.googleapis.com",     # Lane 13 Stage A: signBlob for the QA job's short-lived signed URLs
    "orgpolicy.googleapis.com",          # ORGPOLICY-API: vending's child "no external VM IPs" policy + compliance folder harvest bill the host (quota project)
    "modelarmor.googleapis.com",         # PREWIRE-APIS (FD-77): prompt-injection screening; nothing calls it yet and it costs nothing until it is called
    "billingbudgets.googleapis.com",     # PREWIRE-APIS: Cloud Billing Budget API on the host; nothing calls it yet
  ]

  # Agent persona service accounts
  agent_roles = {
    "sa-castor-architect"    = "StackVend Architect Agent"
    "sa-castor-developer"    = "StackVend Developer Agent"
    "sa-castor-gcp-devops"   = "StackVend GCP DevOps Agent"
    "sa-castor-qa"           = "StackVend QA Reviewer Agent"
    "sa-castor-release"      = "StackVend Release Engineer Agent"
    "sa-castor-finops"       = "StackVend FinOps Sentinel Agent"
    "sa-castor-sre"          = "StackVend SRE Observability Sentinel Agent"
    "sa-project-provisioner" = "StackVend Project and Repo Vending Service"
  }

  # Cloud Run microservices to provision with bootstrap placeholder image
  cloud_run_services = {
    "spec-ingestion-service"       = "Ingests Google Docs build specs from Drive folders"
    "orchestrator-gateway-service" = "Cloud Workflows callback and PubSub dispatcher"
    "mcp-terraform-server"         = "Deterministic Terraform MCP tool server"
    "mcp-kubernetes-server"        = "Kubernetes manifest deployment and cluster lifecycle MCP tool server"
    "mcp-gcloud-server"            = "Imperative gcloud CLI and SDK tool server"
    "mcp-github-toolserver"        = "Git and GitHub operations tool server"
    "mcp-workspace-connector"      = "Google Docs and Drive folder lifecycle tool server"
    "mcp-infracost-server"         = "Pre-flight Terraform cost estimation tool server"
    "mcp-compliance-server"        = "Assured Workloads and regulatory compliance MCP tool server"
    "project-repo-vending-service" = "Project creation and JIT token vending machine"
    "log-sre-sentinel-service"     = "Cloud Logging and Error Reporting incident sentinel"
    "mcp-agent-builder-server"     = "Google ADK and Agent Engine vending MCP tool server"
    "product-control-center-ui"    = "Product Control Center web portal"
  }

  # Per-service container limits for google_cloud_run_v2_service.services; unlisted services get 1000m / 1024Mi.
  cloud_run_service_cpu = {
    "mcp-terraform-server"         = "2000m"
    "orchestrator-gateway-service" = "2000m"
  }
  cloud_run_service_memory = {
    # Step 1 follow-up (owner 10-13): the /validate warm-up builds the whole provider mirror at every instance start
    # in Cloud Run's in-memory /tmp (4 providers x 2 versions, unpacked, copied into 2 registries: ~1.15 GB), next
    # to the engine binary, the validate/plan plugin caches, the Python server and tofu + provider processes.
    "mcp-terraform-server"         = "4096Mi"
    "orchestrator-gateway-service" = "2048Mi"
  }

  # Cloud Run Jobs (Ephemeral batch execution workers). The full inventory; qa-sandbox-test-runner (local.qa_job_name)
  # is built by its own resource in qa_sandbox.tf (lane 13 Stage A), not by google_cloud_run_v2_job.jobs, because it
  # runs generated tenant code as the zero-role QA sandbox SA, with no env.
  cloud_run_jobs = {
    "github-refactor-scanner-job"   = "Scans GitHub repositories for AST and Dependabot issues"
    "qa-sandbox-test-runner"        = "Executes test suites and linters in isolated sandboxes"
    "finops-budget-enforcer-job"    = "Auto-kill circuit breaker for hard budget breaches"
    "infra-rollback-job"            = "Reverts Terraform state and cleans up failed deployments"
    "sandbox-garbage-collector-job" = "Sweeps and destroys expired test sandbox resources"
    "sre-telemetry-digest-job"      = "Clusters warning logs and identifies latency drift"
    # C10 (owner 11-07): the Control Center's machine work, off the Control Center (one directory each, the job
    # pattern above; shared bodies in shared/ replicated into each image, parity:
    # tests/test_c10_platform_tf.py::test_c10_copies_are_byte_identical).
    "finops-spend-sync-job"        = "Nightly workload spend sync and run-rate projection (apps/finops-spend-sync)"
    "sandbox-workload-sweeper-job" = "Daily sandbox expiry notices and vending-executed decommission (apps/sandbox-sweeper)"
    "billing-alert-drain-job"      = "Drains billing budget alerts every 30 minutes and enforces breaches (apps/billing-alert-drain)"
  }


  # C10 (owner 11-07, register row C10-MACHINE-CALLERS-OFF-CC): per-job task timeouts (unlisted jobs keep the Cloud Run
  # default, 600 s). The sweeper may wait for 10 vending decommissions (180 s each) plus Workflows cancels; the drain
  # job waits for enforcer executions (apps/billing-alert-drain/main.py ENFORCER_WAIT_S).
  job_timeouts = {
    "finops-spend-sync-job"        = "1800s"
    "sandbox-workload-sweeper-job" = "3600s"
    "billing-alert-drain-job"      = "1800s"
  }

  # C10: the env each new job's code reads (beyond the common job env). Empty values are not set.
  c10_job_env = {
    # RT D1: the enforcer's restore relinks the account recorded at unlink time, else this install's account.
    "finops-budget-enforcer-job" = {
      BILLING_ACCOUNT_ID = var.billing_account_id
    }
    "sandbox-workload-sweeper-job" = {
      # The exact URL vending accepts as its ID-token audience (destructive_guard.tf local.vending_service_url).
      VENDING_SERVICE_URL = local.vending_service_url
      REGION              = var.region # Workflows cascade cancel (workflow_executions.py)
    }
    "billing-alert-drain-job" = {
      REGION                      = var.region
      BILLING_ALERTS_SUBSCRIPTION = "projects/${var.project_id}/subscriptions/billing-alerts-push-subscription"
      FINOPS_ENFORCER_JOB         = "finops-budget-enforcer-job"
      BILLING_ACCOUNT_ID          = var.billing_account_id
      BILLING_BREACH_ENFORCEMENT  = var.billing_breach_enforcement_enabled ? "true" : "false"
    }
  }
}

# ------------------------------------------------------------------------------
# 1. API Enablement
# ------------------------------------------------------------------------------
# Foundational Resource Manager API must be enabled first to allow project service queries
resource "google_project_service" "cloudresourcemanager" {
  project                    = var.project_id
  service                    = "cloudresourcemanager.googleapis.com"
  disable_on_destroy         = false
  disable_dependent_services = false
}

resource "google_project_service" "apis" {
  depends_on                 = [google_project_service.cloudresourcemanager]
  for_each                   = toset(local.services)
  project                    = var.project_id
  service                    = each.key
  disable_on_destroy         = false
  disable_dependent_services = false
}

# ------------------------------------------------------------------------------
# 2. Artifact Registry (Central Container Repository)
# ------------------------------------------------------------------------------
resource "google_artifact_registry_repository" "castor_docker_repo" {
  depends_on    = [google_project_service.apis]
  project       = var.project_id
  location      = var.region
  repository_id = "castor-docker-repo"
  description   = "Docker container repository for StackVend microservices and MCP servers"
  format        = "DOCKER"

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

# ------------------------------------------------------------------------------
# 3. Firestore Native State Database
# ------------------------------------------------------------------------------
resource "google_firestore_database" "castor_state_db" {
  depends_on  = [google_project_service.apis]
  project     = var.project_id
  name        = "(default)"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"

  # Lane 18 S0 / owner Q10 (plan D12): the platform ledger is delete-protected and point-in-time
  # recoverable. Both are in-place updates (no replace); deletion_policy is unchanged.
  delete_protection_state           = "DELETE_PROTECTION_ENABLED"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"
  deletion_policy                   = "DELETE"
}

# ------------------------------------------------------------------------------
# 4. Central GCS Bucket for Workload Terraform Remote State
# ------------------------------------------------------------------------------
# Pre-created by bootstrap.sh to house the platform's own remote state backend.
# Referenced as a data source so Terraform never attempts to recreate it or throw 409 conflicts.
data "google_storage_bucket" "workload_tfstate_bucket" {
  name = "castor-tfstate-${var.project_id}"
}

# FD-0C: installs applied before d3a4fe8 (e.g. the original dev install) still track this bucket in state as a
# managed resource. Without this block a plan proposes DESTROYING the bucket that holds the platform
# state and every workload state. destroy = false only forgets the address; the bucket is untouched.
# No-op on installs whose state never managed it.
removed {
  from = google_storage_bucket.workload_tfstate_bucket

  lifecycle {
    destroy = false
  }
}

# Central Repository Storage Bucket for Serverless Git (Cloud Storage FUSE backend)
resource "google_storage_bucket" "git_repos_bucket" {
  count                       = (var.deploy_git_server || upper(var.vcs_provider) == "SERVERLESS_GIT") ? 1 : 0
  depends_on                  = [google_project_service.apis]
  project                     = var.project_id
  name                        = "castor-git-repos-${var.project_id}"
  location                    = var.region
  force_destroy               = false
  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

resource "google_storage_bucket_iam_member" "git_repos_bucket_admin" {
  count  = (var.deploy_git_server || upper(var.vcs_provider) == "SERVERLESS_GIT") ? 1 : 0
  bucket = google_storage_bucket.git_repos_bucket[0].name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.agents["sa-castor-developer"].email}"
}

# ------------------------------------------------------------------------------
# 5. Cloud Pub/Sub Event Topics
# ------------------------------------------------------------------------------
resource "google_pubsub_topic" "spec_intake_events" {
  depends_on = [google_project_service.apis]
  project    = var.project_id
  name       = "spec-intake-events"
}

resource "google_pubsub_topic" "autonomous_refactor_events" {
  depends_on = [google_project_service.apis]
  project    = var.project_id
  name       = "autonomous-refactor-events"
}

resource "google_pubsub_topic" "runtime_incident_events" {
  depends_on = [google_project_service.apis]
  project    = var.project_id
  name       = "runtime-incident-events"
}

resource "google_pubsub_topic" "workflow_callbacks" {
  depends_on = [google_project_service.apis]
  project    = var.project_id
  name       = "workflow-callbacks"
}

resource "google_pubsub_topic" "castor_dlq" {
  depends_on = [google_project_service.apis]
  project    = var.project_id
  name       = "castor-dlq"
}

resource "google_pubsub_topic" "billing_budget_alerts" {
  depends_on = [google_project_service.apis]
  project    = var.project_id
  name       = "billing-budget-alerts"
}

data "google_project" "platform_project" {
  project_id = var.project_id
}

# Ensure IAP Service Agent is instantiated in the project
# RC B2: the only creator of the IAP / Logging / Workflows service agents (bootstrap.sh no longer calls
# `gcloud beta services identity create`); depends_on the API enablement like logging_sa / workflows_sa (plan-neutral).
resource "google_project_service_identity" "iap_sa" {
  provider   = google-beta
  depends_on = [google_project_service.apis]
  project    = var.project_id
  service    = "iap.googleapis.com"
}

# Ensure Cloud Logging Service Agent is instantiated in the project
resource "google_project_service_identity" "logging_sa" {
  provider   = google-beta
  depends_on = [google_project_service.apis]
  project    = var.project_id
  service    = "logging.googleapis.com"
}

# Ensure Workflows Service Agent is instantiated in the project
resource "google_project_service_identity" "workflows_sa" {
  provider   = google-beta
  depends_on = [google_project_service.apis]
  project    = var.project_id
  service    = "workflows.googleapis.com"
}

# Pull subscription on castor-dlq: allows operators or monitoring tools to inspect dead-letter messages
resource "google_pubsub_subscription" "castor_dlq_sub" {
  depends_on = [google_project_service.apis, google_pubsub_topic.castor_dlq]
  project    = var.project_id
  name       = "castor-dlq-sub"
  topic      = google_pubsub_topic.castor_dlq.name

  # SUB-NO-EXPIRY (10-27): Pub/Sub deletes a subscription after 31 days without activity by default; quiet
  # platform subscriptions (billing alerts, SRE incidents, the DLQ) expired silently on a dev install. Never expire.
  expiration_policy {
    ttl = ""
  }
  ack_deadline_seconds       = 60
  message_retention_duration = "604800s" # 7 days
}

# IAM: Pub/Sub service agent requires publisher role on the dead-letter topic
resource "google_pubsub_topic_iam_member" "pubsub_dlq_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.castor_dlq.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:service-${data.google_project.platform_project.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

# ------------------------------------------------------------------------------
# 6. Dedicated IAM Service Accounts per Agent Persona
# ------------------------------------------------------------------------------
resource "google_service_account" "agents" {
  for_each     = local.agent_roles
  depends_on   = [google_project_service.apis]
  project      = var.project_id
  account_id   = each.key
  display_name = each.value
}

# Lane 19 L19-0b (Fable R3 check F-R3-3): the QA sandbox job's OWN identity with ZERO roles (it executes generated
# tenant code, which must not read any host secret). Deliberately outside local.agent_roles (no shared bindings).
# Attached by lane 13 Stage A (qa_sandbox.tf): the job runs as this SA; it reads and writes only through signed URLs
# the gateway mints, and the gateway (not the job) writes Firestore evidence and drives the workflow.
resource "google_service_account" "qa_sandbox" {
  depends_on   = [google_project_service.apis]
  project      = var.project_id
  account_id   = "sa-castor-qa-sandbox"
  display_name = "StackVend QA sandbox job (zero roles)"
}

# Core IAM bindings for Agent Service Accounts
# Lane 18 S0b: every database EXCEPT stackvend-guard (provenance, approvals, ephemeral ledger), which
# only the Control Center and vending may write (destructive_guard.tf guard_db_writers). Adding the
# condition replaces each binding; create_before_destroy adds the conditioned binding before the old
# unconditioned one is removed, so access to the default database never lapses.
resource "google_project_iam_member" "agent_datastore_users" {
  for_each = local.agent_roles
  project  = var.project_id
  role     = "roles/datastore.user"
  member   = "serviceAccount:${google_service_account.agents[each.key].email}"

  condition {
    title       = "stackvend-not-guard-db"
    description = "Every Firestore database except the stackvend-guard database (lane 18 S0b)"
    expression  = "!(${local.guard_db_condition})"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# FD-4AS-c (owner 10-20): no project-level roles/pubsub.publisher for the agent SAs any more (it let any of them
# publish spec-intake events directly). Each publisher holds it on its own topic only: pubsub_publishers.tf.

# Vertex AI User permission for Agents to invoke Gemini models
resource "google_project_iam_member" "agent_vertex_users" {
  for_each = local.agent_roles
  project  = var.project_id
  role     = "roles/aiplatform.user"
  member   = "serviceAccount:${google_service_account.agents[each.key].email}"
}

# Logging Viewer permission for Agents and Control Center to inspect Cloud Logging
resource "google_project_iam_member" "agent_logging_viewers" {
  for_each = local.agent_roles
  project  = var.project_id
  role     = "roles/logging.viewer"
  member   = "serviceAccount:${google_service_account.agents[each.key].email}"
}

# Logging LogWriter permission for Agents to stream structured logs
resource "google_project_iam_member" "agent_logging_writers" {
  for_each = local.agent_roles
  project  = var.project_id
  role     = "roles/logging.logWriter"
  member   = "serviceAccount:${google_service_account.agents[each.key].email}"
}

# SELFUP-STATE (owner 10-27): the state bucket holds the platform's own state (platform/state/default.tfstate,
# providers.tf) next to every workload's state (backend prefix workloads/<product_id>: <prefix>/default.tfstate and
# the lock <prefix>/default.tflock; vending's archive workloads/<pid>/state_history/...; the rollback service's
# restore of workloads/<pid>/default.tfstate). The bucket-wide writers below may write ONLY objects under
# workloads/. GCS evaluates the condition on `projects/_/buckets/<bucket>/objects/<object>` for object operations
# and on the bucket itself (`storage.googleapis.com/Bucket`) for bucket-level checks such as storage.objects.list,
# so listing keeps working. Reads stay unconditional (agent_state_viewers, cc_state_viewer). apply.sh runs as the
# operator's own identity and is not affected. The bucket is uniform-access (bootstrap.sh), so conditions apply.
locals {
  state_bucket_workload_objects_prefix  = "projects/_/buckets/${data.google_storage_bucket.workload_tfstate_bucket.name}/objects/workloads/"
  state_bucket_workload_write_condition = "resource.type == \"storage.googleapis.com/Bucket\" || resource.name.startsWith(\"${local.state_bucket_workload_objects_prefix}\")"
}

# Grant DevOps, Developer and vending (provisioner) Agents read/write access to WORKLOAD state in the central state
# bucket (SELFUP-STATE: never the platform's own state under platform/).
resource "google_storage_bucket_iam_member" "state_bucket_admins" {
  for_each = toset([
    "sa-castor-gcp-devops",
    "sa-castor-developer",
    "sa-project-provisioner", # lane 18 S0: vending archives state after a decommission (copy, then delete)
  ])
  bucket = data.google_storage_bucket.workload_tfstate_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.agents[each.key].email}"

  condition {
    title       = "stackvend-workload-state-only"
    description = "SELFUP-STATE: write only workload state (objects under workloads/), never the platform state"
    expression  = local.state_bucket_workload_write_condition
  }
  # Opus RT F1 (core-tf-pre-rc): the condition forces a replace; create the conditional member before removing
  # the unconditional one so the runners never lose state write during the apply (lane 18 S0b precedent).
  lifecycle {
    create_before_destroy = true
  }
}

# Grant remaining Agents read access to the central state bucket
resource "google_storage_bucket_iam_member" "agent_state_viewers" {
  for_each = local.agent_roles
  bucket   = data.google_storage_bucket.workload_tfstate_bucket.name
  role     = "roles/storage.objectViewer"
  member   = "serviceAccount:${google_service_account.agents[each.key].email}"
}

# Grant Agent service accounts Cloud Run Invoker & Developer permissions to execute Cloud Run services & jobs
resource "google_project_iam_member" "agent_run_invokers" {
  for_each = local.agent_roles
  project  = var.project_id
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.agents[each.key].email}"
}

resource "google_project_iam_member" "agent_run_developers" {
  for_each = toset([
    "sa-castor-developer",
    "sa-castor-gcp-devops",
    "sa-castor-sre",
    "sa-project-provisioner",
  ])
  project = var.project_id
  role    = "roles/run.developer"
  member  = "serviceAccount:${google_service_account.agents[each.key].email}"
}

# Grant Agent service accounts Cloud Workflows Invoker permissions to launch workflow state machines
resource "google_project_iam_member" "agent_workflow_invokers" {
  for_each = local.agent_roles
  project  = var.project_id
  role     = "roles/workflows.invoker"
  member   = "serviceAccount:${google_service_account.agents[each.key].email}"
}

# Grant Default Compute Engine Service Account permissions to build and push containers in Cloud Build
# RC B3: Google creates this account asynchronously once compute.googleapis.com is enabled; the bindings depend on the
# API enablement, bootstrap.sh / apply.sh pre-enable compute and wait for the account (sv_wait_default_compute_sa).
resource "google_project_iam_member" "cloudbuild_compute_storage" {
  depends_on = [google_project_service.apis] # RC B3: compute API first (it creates the account)
  project    = var.project_id
  role       = "roles/storage.admin"
  member     = "serviceAccount:${data.google_project.platform_project.number}-compute@developer.gserviceaccount.com"
}

resource "google_project_iam_member" "cloudbuild_compute_logging" {
  depends_on = [google_project_service.apis] # RC B3: compute API first (it creates the account)
  project    = var.project_id
  role       = "roles/logging.logWriter"
  member     = "serviceAccount:${data.google_project.platform_project.number}-compute@developer.gserviceaccount.com"
}

resource "google_project_iam_member" "cloudbuild_compute_artifact" {
  depends_on = [google_project_service.apis] # RC B3: compute API first (it creates the account)
  project    = var.project_id
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${data.google_project.platform_project.number}-compute@developer.gserviceaccount.com"
}

# ------------------------------------------------------------------------------
# 7. Secret Manager (Placeholders for JIT Tokens & Webhook Secrets)
# ------------------------------------------------------------------------------
resource "google_secret_manager_secret" "github_app_private_key" {
  depends_on = [google_project_service.apis]
  project    = var.project_id
  secret_id  = "castor-github-app-private-key"

  replication {
    auto {}
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

# FD-7F: castor-webhook-signing-secret was a placeholder no service ever read. Removed from the configuration; an install
# that already has it forgets the address (destroy = false: a state-only action, not a delete in the apply gate) and
# the empty secret stays in the project, unmanaged and free. No-op on a new install, which never creates it.
removed {
  from = google_secret_manager_secret.webhook_signing_secret

  lifecycle {
    destroy = false
  }
}

# Grant Vending and Developer Service Accounts access to read the GitHub App Private Key
resource "google_secret_manager_secret_iam_member" "vending_secret_accessor" {
  for_each  = toset(["sa-project-provisioner", "sa-castor-developer"])
  project   = var.project_id
  secret_id = google_secret_manager_secret.github_app_private_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.agents[each.key].email}"
}

# Master Google OAuth 2.0 Client ID for Identity Platform & Vended Workloads
resource "google_secret_manager_secret" "oauth_client_id" {
  depends_on = [google_project_service.apis]
  project    = var.project_id
  secret_id  = "castor-oauth-client-id"

  replication {
    auto {}
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

# Master Google OAuth 2.0 Client Secret for Identity Platform & Vended Workloads
resource "google_secret_manager_secret" "oauth_client_secret" {
  depends_on = [google_project_service.apis]
  project    = var.project_id
  secret_id  = "castor-oauth-client-secret"

  replication {
    auto {}
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

# Lane 19 L19-0b (plan §2.7.4): only sa-castor-developer reads the castor-oauth-client-* pair. Every host service
# and job runs as sa-castor-developer today (the CC resolves its client id, tf-applier copies the pair into tenants),
# so it keeps access until tf-applier has its own SA (Q24 / L19-10). sa-project-provisioner and sa-castor-gcp-devops
# are no runtime identity of any host service (code read 10-13; RT-6 confirms it read-only from Data Access logs
# before the apply) and lose access. Removing their four members shows as "delete" in the plan gate.
resource "google_secret_manager_secret_iam_member" "oauth_client_id_accessors" {
  for_each = toset([
    "sa-castor-developer",
  ])
  project   = var.project_id
  secret_id = google_secret_manager_secret.oauth_client_id.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.agents[each.key].email}"
}

resource "google_secret_manager_secret_iam_member" "oauth_client_secret_accessors" {
  for_each = toset([
    "sa-castor-developer",
  ])
  project   = var.project_id
  secret_id = google_secret_manager_secret.oauth_client_secret.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.agents[each.key].email}"
}

# Optional Gemini API Key for direct Google AI Studio API access alongside Vertex AI
resource "google_secret_manager_secret" "gemini_api_key" {
  depends_on = [google_project_service.apis]
  project    = var.project_id
  secret_id  = "castor-gemini-api-key"

  replication {
    auto {}
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

resource "google_secret_manager_secret_iam_member" "gemini_api_key_accessors" {
  for_each  = local.agent_roles
  project   = var.project_id
  secret_id = google_secret_manager_secret.gemini_api_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.agents[each.key].email}"
}


# Grant Provisioner & Developer Service Accounts projectCreator role on the Managed Workloads Folder
resource "google_folder_iam_member" "folder_project_creators" {
  depends_on = [google_project_service.apis]
  for_each = var.castor_managed_workloads_folder_id != "" ? toset([
    "sa-project-provisioner",
    "sa-castor-developer",
  ]) : toset([])

  folder = startswith(var.castor_managed_workloads_folder_id, "folders/") ? var.castor_managed_workloads_folder_id : "folders/${var.castor_managed_workloads_folder_id}"
  role   = "roles/resourcemanager.projectCreator"
  member = "serviceAccount:${google_service_account.agents[each.key].email}"
}

# Grant the vending identity (sa-project-provisioner) projectDeleter on the Managed Workloads Folder (decommission executor)
resource "google_folder_iam_member" "folder_project_deleters" {
  depends_on = [google_project_service.apis]
  # Lane 18 S0 (plan F1): only the vending identity may delete projects / administer the folder.
  # sa-castor-developer is dropped (it keeps its reads via destructive_guard.tf guard_folder_readers).
  for_each = var.castor_managed_workloads_folder_id != "" ? local.folder_destructive_holders : toset([])

  folder = startswith(var.castor_managed_workloads_folder_id, "folders/") ? var.castor_managed_workloads_folder_id : "folders/${var.castor_managed_workloads_folder_id}"
  role   = "roles/resourcemanager.projectDeleter"
  member = "serviceAccount:${google_service_account.agents[each.key].email}"
}

# Grant Provisioner & Developer Service Accounts folderCreator role on the Managed Workloads Folder (to create subfolders)
resource "google_folder_iam_member" "folder_creators" {
  depends_on = [google_project_service.apis]
  for_each = var.castor_managed_workloads_folder_id != "" ? toset([
    "sa-project-provisioner",
    "sa-castor-developer",
  ]) : toset([])

  folder = startswith(var.castor_managed_workloads_folder_id, "folders/") ? var.castor_managed_workloads_folder_id : "folders/${var.castor_managed_workloads_folder_id}"
  role   = "roles/resourcemanager.folderCreator"
  member = "serviceAccount:${google_service_account.agents[each.key].email}"
}

# Grant the vending identity (sa-project-provisioner) folderAdmin on the Managed Workloads Folder (to manage/delete subfolders)
resource "google_folder_iam_member" "folder_admins" {
  depends_on = [google_project_service.apis]
  # Lane 18 S0 (plan F1): only the vending identity may delete projects / administer the folder.
  # sa-castor-developer is dropped (it keeps its reads via destructive_guard.tf guard_folder_readers).
  for_each = var.castor_managed_workloads_folder_id != "" ? local.folder_destructive_holders : toset([])

  folder = startswith(var.castor_managed_workloads_folder_id, "folders/") ? var.castor_managed_workloads_folder_id : "folders/${var.castor_managed_workloads_folder_id}"
  role   = "roles/resourcemanager.folderAdmin"
  member = "serviceAccount:${google_service_account.agents[each.key].email}"
}

# FD-49: folder-wide roles/editor for the devops SA is opt-in (default off) pending the owner's
# decision. Neither install's state holds it, so the default creates/destroys nothing.
resource "google_folder_iam_member" "devops_workloads_editor" {
  depends_on = [google_project_service.apis]
  count      = (var.grant_devops_workloads_folder_editor && var.castor_managed_workloads_folder_id != "") ? 1 : 0

  folder = startswith(var.castor_managed_workloads_folder_id, "folders/") ? var.castor_managed_workloads_folder_id : "folders/${var.castor_managed_workloads_folder_id}"
  role   = "roles/editor"
  member = "serviceAccount:${google_service_account.agents["sa-castor-gcp-devops"].email}"
}

# Grant Admin User Read-Only Viewer access across all Managed Workload child projects
# Only applied if an admin email is explicitly provided and is NOT a personal @gmail.com account blocked by Domain-Restricted Sharing
resource "google_folder_iam_member" "admin_workloads_viewer" {
  count  = var.castor_managed_workloads_folder_id != "" && var.admin_user_email != "" && !endswith(var.admin_user_email, "@gmail.com") ? 1 : 0
  folder = startswith(var.castor_managed_workloads_folder_id, "folders/") ? var.castor_managed_workloads_folder_id : "folders/${var.castor_managed_workloads_folder_id}"
  role   = "roles/viewer"
  member = startswith(var.admin_user_email, "user:") || startswith(var.admin_user_email, "group:") ? var.admin_user_email : "user:${var.admin_user_email}"
}

resource "google_folder_iam_member" "admin_workloads_folder_viewer" {
  count  = var.castor_managed_workloads_folder_id != "" && var.admin_user_email != "" && !endswith(var.admin_user_email, "@gmail.com") ? 1 : 0
  folder = startswith(var.castor_managed_workloads_folder_id, "folders/") ? var.castor_managed_workloads_folder_id : "folders/${var.castor_managed_workloads_folder_id}"
  role   = "roles/resourcemanager.folderViewer"
  member = startswith(var.admin_user_email, "user:") || startswith(var.admin_user_email, "group:") ? var.admin_user_email : "user:${var.admin_user_email}"
}

# ORG-POLICY-FOLDER (owner 10-28): "no external VM IPs" (compute.vmExternalIpAccess = deny all) is set ONCE on the
# managed workloads folder, so every project in it inherits it: every vended child, and also any other project
# placed in that folder. No service account gets org-policy rights; only the person running bootstrap.sh /
# apply.sh needs Organization Policy Administrator (roles/orgpolicy.policyAdmin, grantable only on the
# organization). scripts/common/org_policy_preflight.sh checks that read-only (folders.testIamPermissions) and sets
# var.create_folder_vm_external_ip_policy = false when it is missing, with a warning and the fix; the install never
# fails for it. Vending then only reads the effective policy on each child (orgpolicy.policy.get, in its folderAdmin)
# and records VENDING.ORG_POLICY_NOT_ENFORCED with the fix when it is not in effect.
locals {
  folder_vm_external_ip_policy_enabled = local.managed_folder != "" && var.create_folder_vm_external_ip_policy != false
}

resource "google_org_policy_policy" "managed_folder_vm_external_ip" {
  count      = local.folder_vm_external_ip_policy_enabled ? 1 : 0
  provider   = google.host_quota
  depends_on = [google_project_service.apis]
  name       = "${local.managed_folder}/policies/compute.vmExternalIpAccess"
  parent     = local.managed_folder

  spec {
    rules {
      deny_all = "TRUE"
    }
  }
}

# NOTE (BG-1): Billing Account IAM lives in billing_iam.tf. It grants roles/billing.user to
# sa-project-provisioner and sa-castor-developer with additive google_billing_account_iam_member resources,
# only when var.bind_billing_iam is true. Changing billing-account IAM needs billing.accounts.setIamPolicy
# (Billing Account Administrator), which most deployers lack, so scripts/apply.sh decides the value with a
# read-only preflight and skips the grant with a warning instead of failing the apply. The Control Center
# Settings billing card reports per service account whether the grant exists and how to fix it.

# FD-4DA item 10 (platform version stamp; SAT-10 design, docs/planning/self-upgrade-plan.md §3.4.3, rides FD-7L step A):
# two service-level annotations on the Control Center. The release comes from the repository's VERSION file (no
# release-manifest.json exists yet); the commit from var.stackvend_platform_commit, which scripts/apply.sh and
# scripts/bootstrap.sh fill internally (sv_export_platform_stamp). An empty value omits its annotation.
locals {
  platform_release_file = "${path.module}/../../VERSION"
  platform_release      = fileexists(local.platform_release_file) ? trimspace(file(local.platform_release_file)) : ""
  platform_stamp_annotations = merge(
    local.platform_release != "" ? { "stackvend/platform-release" = local.platform_release } : {},
    var.stackvend_platform_commit != "" ? { "stackvend/platform-commit" = var.stackvend_platform_commit } : {},
  )
}

# ------------------------------------------------------------------------------
# 8. Cloud Run Microservices (Single-Pass "Hello World" Bootstrap)
# ------------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "services" {
  provider = google-beta
  for_each = local.cloud_run_services
  depends_on = [
    google_project_service.apis,
    google_artifact_registry_repository.castor_docker_repo,
    google_secret_manager_secret_version.cc_session_secret,
    google_secret_manager_secret_iam_member.cc_session_secret_accessor,
    # Lane 18 S0/S0b: a revision on a new runtime SA starts only after that SA can read its secrets and
    # Firestore, and (vending) archive state and bind the tag.
    google_secret_manager_secret_iam_member.cc_secret_accessors,
    google_project_iam_member.cc_project_roles,
    google_project_iam_member.persona_datastore_users,
    google_project_iam_member.guard_db_writers,
    google_storage_bucket_iam_member.state_bucket_admins,
    google_storage_bucket_iam_member.cc_state_admin,
    google_storage_bucket_iam_member.cc_state_viewer, # SELFUP-STATE: the CC's unconditional read
    google_folder_iam_member.guard_folder_readers,
    google_tags_tag_value_iam_member.stackvend_managed_vending_tag_user,
    # Lane 18 RT fix 2: the staged apply's step A (-target = the Control Center service) must also bring
    # the CC's spec-intake publish and git-server invoker grants (no cycle: neither depends on services).
    # persona_invokers cannot be listed (they reference services): CC -> vending / mcp-terraform-server
    # calls answer 403 between step A and step B (runbook).
    google_pubsub_topic_iam_member.cc_spec_intake_publisher,
    google_cloud_run_v2_service_iam_member.cc_git_server_invoker,
    # FD-7L (tf_runner_identity.tf): the terraform server's step-B revision starts only after its SA holds its
    # roles (none of these reference the services, so no cycle). Vending's self-signBlob rides with its env.
    google_project_iam_member.tf_runner_project_roles,
    google_project_iam_member.tf_runner_datastore_users,
    google_project_iam_member.tf_runner_guard_db_readers,
    google_storage_bucket_iam_member.tf_runner_staging_server_create,
    google_service_account_iam_member.vending_self_sign_blob,
    # SELFUP-B: the Control Center revision that gets STACKVEND_PLATFORM_UPGRADE_TOPIC starts only after the topic,
    # the CC's publisher grant AND the trigger exist (a refused trigger leaves the button hidden). No cycle: neither
    # references the services (platform_upgrader.tf).
    google_pubsub_topic_iam_member.cc_platform_upgrade_publisher,
    google_cloudbuild_trigger.platform_upgrade,
  ]
  project     = var.project_id
  location    = var.region
  name        = each.key
  description = each.value

  # FD-0D: deletion_protection is a Terraform-only latch (not a Cloud Run setting): apply/destroy
  # refuse to delete or replace the service while state holds true. Flip deliberately, reviewed.
  # HOST-INTERNAL-INGRESS (host_network.tf): every service but the Control Center is internal-only when switched on.
  ingress             = each.key == "product-control-center-ui" ? var.control_center_ingress_traffic : local.host_service_ingress
  launch_stage        = (each.key == "product-control-center-ui" && !var.allow_unauthenticated && var.enable_direct_iap) ? "BETA" : null
  iap_enabled         = (each.key == "product-control-center-ui" && !var.allow_unauthenticated && var.enable_direct_iap) ? true : null
  deletion_protection = true

  # FD-4DA item 10 (platform version stamp): SERVICE-level annotations on the Control Center only (no new revision;
  # deploy paths never touch them). Not in ignore_changes: only a successful apply changes the stamp. Every other
  # service keeps no Terraform-managed annotation (null = unchanged).
  annotations = (each.key == "product-control-center-ui" && length(local.platform_stamp_annotations) > 0) ? local.platform_stamp_annotations : null

  template {
    timeout = "1800s"
    # Lane 18 S0 (FD-4T slice): vending -> sa-project-provisioner, Control Center -> its own SA; every
    # other service stays on sa-castor-developer. Deploy paths never pass --service-account, so they keep it.
    # FD-7L step B (tf_runner_dedicated_sa): mcp-terraform-server -> sa-stackvend-tf-server, merged into
    # local.service_runtime_sa (destructive_guard.tf); nothing changes in step A.
    service_account = lookup(local.service_runtime_sa, each.key, google_service_account.agents["sa-castor-developer"].email)

    # HOST-VPC-EGRESS (host_network.tf): all 13 services, the Control Center included (it calls vending, the
    # terraform server and the git server).
    dynamic "vpc_access" {
      for_each = local.host_vpc_access
      content {
        egress = local.host_egress_mode
        network_interfaces {
          network    = vpc_access.value.network
          subnetwork = vpc_access.value.subnetwork
        }
      }
    }

    containers {
      image = var.placeholder_container_image

      resources {
        limits = {
          cpu    = lookup(local.cloud_run_service_cpu, each.key, "1000m")
          memory = lookup(local.cloud_run_service_memory, each.key, "1024Mi")
        }
        cpu_idle = contains(["mcp-terraform-server", "project-repo-vending-service"], each.key) ? false : true
      }

      # STAGE-JOB-RUNNER (owner 11-13): the values of the env every service gets live in ONE place,
      # stage_runner.tf local.platform_service_env (and local.gateway_service_env for the gateway's own), so the
      # stage-runner job, which runs the gateway's image, gets exactly the gateway's env. Same names, same order,
      # same values as before: no plan change for any service.
      env {
        name  = "ENVIRONMENT"
        value = local.platform_service_env["ENVIRONMENT"]
      }
      env {
        name  = "PROJECT_ID"
        value = local.platform_service_env["PROJECT_ID"]
      }
      env {
        name  = "TFSTATE_BUCKET"
        value = local.platform_service_env["TFSTATE_BUCKET"]
      }
      env {
        name  = "INBOX_FOLDER_ID"
        value = local.platform_service_env["INBOX_FOLDER_ID"]
      }
      env {
        name  = "IN_PROGRESS_FOLDER_ID"
        value = local.platform_service_env["IN_PROGRESS_FOLDER_ID"]
      }
      env {
        name  = "COMPLETED_FOLDER_ID"
        value = local.platform_service_env["COMPLETED_FOLDER_ID"]
      }
      env {
        name  = "GEMINI_MODEL"
        value = local.service_gemini_model[each.key]
      }
      env {
        name  = "GEMINI_LOCATION"
        value = local.platform_service_env["GEMINI_LOCATION"]
      }
      env {
        name  = "MANAGED_WORKLOADS_FOLDER_ID"
        value = local.platform_service_env["MANAGED_WORKLOADS_FOLDER_ID"]
      }
      env {
        name  = "FOLDER_ID"
        value = local.platform_service_env["FOLDER_ID"]
      }
      env {
        name  = "BILLING_ACCOUNT_ID"
        value = local.platform_service_env["BILLING_ACCOUNT_ID"]
      }
      env {
        name  = "GITHUB_ORG"
        value = local.platform_service_env["GITHUB_ORG"]
      }
      env {
        name  = "GITHUB_OWNER"
        value = local.platform_service_env["GITHUB_OWNER"]
      }
      env {
        name = "ADMIN_EMAIL"
        # FD-4M F6/H4 (stage_runner.tf local.platform_service_env): the first invoker member only when it is user:.
        value = local.platform_service_env["ADMIN_EMAIL"]
      }
      env {
        name  = "ENABLE_TF_APPLIER_JOB"
        value = local.platform_service_env["ENABLE_TF_APPLIER_JOB"]
      }
      env {
        name  = "VCS_PROVIDER"
        value = local.platform_service_env["VCS_PROVIDER"]
      }
      env {
        name  = "GIT_SERVER_URL"
        value = local.platform_service_env["GIT_SERVER_URL"]
      }
      dynamic "env" {
        for_each = each.key == "product-control-center-ui" ? [1] : []
        content {
          name = "SESSION_SECRET"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.cc_session_secret.secret_id
              version = "latest"
            }
          }
        }
      }
      # FD-4W/R3 + FD28-08: Terraform owns the Control Center's vending endpoint (deploy scripts no
      # longer set it). Cloud Run's documented deterministic URL; a reference to
      # services["project-repo-vending-service"].uri would be a self-cycle inside this for_each.
      # Never apply this service without it: unset, CC derives the URL from request headers.
      dynamic "env" {
        for_each = each.key == "product-control-center-ui" ? [1] : []
        content {
          name  = "VENDING_SERVICE_URL"
          value = "https://project-repo-vending-service-${data.google_project.platform_project.number}.${var.region}.run.app"
        }
      }
      # ORCHESTRATOR §5 item 4 (owner 10-12): the platform repo's full name comes from the per-install
      # tfvars (OSS rule: no owner-specific default here). Unset when empty (CC keeps its fallback).
      dynamic "env" {
        for_each = (each.key == "product-control-center-ui" && var.platform_github_repo != "") ? [1] : []
        content {
          name  = "GITHUB_REPO"
          value = var.platform_github_repo
        }
      }
      # Owner 10-12 (lane 19 Q8/Q17): the Control Center's own OAuth client ID (public, not a secret).
      # Unset when empty: the CC then resolves it from Secret Manager castor-oauth-client-id as before.
      dynamic "env" {
        for_each = (each.key == "product-control-center-ui" && var.cc_google_oauth_client_id != "") ? [1] : []
        content {
          name  = "GOOGLE_OAUTH_CLIENT_ID"
          value = var.cc_google_oauth_client_id
        }
      }
      # Lane 18 S0/S0b guard env (vending + Control Center), from Terraform resources, never literals:
      # destructive_guard.tf local.guard_service_env. Empty values are not set (the guard fails closed).
      dynamic "env" {
        for_each = { for k, v in lookup(local.guard_service_env, each.key, {}) : k => v if v != "" }
        content {
          name  = env.key
          value = env.value
        }
      }
      # FD28-07: optional AI Studio key, as a Secret Manager reference (never a plaintext env var).
      # Enable only once castor-gemini-api-key has an ENABLED version (bootstrap.sh does this).
      dynamic "env" {
        for_each = (each.key == "product-control-center-ui" && var.cc_gemini_api_key_from_secret) ? [1] : []
        content {
          name = "GEMINI_API_KEY"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.gemini_api_key.secret_id
              version = "latest"
            }
          }
        }
      }
      # Lane 14 PR-3 (RT F3-1; I2 slice). POST /incidents/register accepts only a Google ID token whose verified
      # email is in SRE_REGISTRATION_CALLERS (unset -> 503, nothing recorded). The digest job runs as
      # sa-castor-developer until FD-4T gives it its own SA. REGION lets the sentinel resolve its own Run Admin
      # `uri` (the audience the digest mints its token for). Takes effect only after an owner `scripts/apply.sh apply`.
      dynamic "env" {
        for_each = each.key == "log-sre-sentinel-service" ? [1] : []
        content {
          name  = "SRE_REGISTRATION_CALLERS"
          value = google_service_account.agents["sa-castor-developer"].email
        }
      }
      dynamic "env" {
        for_each = each.key == "log-sre-sentinel-service" ? [1] : []
        content {
          name  = "REGION"
          value = var.region
        }
      }
      # Lane 13 Stage A (FD-4F, register row 19 option A): the gateway's QA job client (qa_job_client.py
      # QAJobConfig.REQUIRED_ENV = PROJECT_ID, REGION, QA_JOB_NAME, QA_STAGING_BUCKET, QA_SANDBOX_SA; PROJECT_ID is
      # set for every service above). With any of them unset, GET /agent/qa/readiness answers 503 QA_NOT_CONFIGURED
      # and QA never passes. QA_SANDBOX_SA is compared (exact) with the job's serviceAccount before code is staged.
      dynamic "env" {
        for_each = each.key == "orchestrator-gateway-service" ? [1] : []
        content {
          name  = "REGION"
          value = local.gateway_service_env["REGION"]
        }
      }
      dynamic "env" {
        for_each = each.key == "orchestrator-gateway-service" ? [1] : []
        content {
          name  = "QA_JOB_NAME"
          value = local.gateway_service_env["QA_JOB_NAME"]
        }
      }
      dynamic "env" {
        for_each = each.key == "orchestrator-gateway-service" ? [1] : []
        content {
          name  = "QA_STAGING_BUCKET"
          value = local.gateway_service_env["QA_STAGING_BUCKET"]
        }
      }
      dynamic "env" {
        for_each = each.key == "orchestrator-gateway-service" ? [1] : []
        content {
          name  = "QA_SANDBOX_SA"
          value = local.gateway_service_env["QA_SANDBOX_SA"]
        }
      }
      # FD-7L step A (tf_runner_identity.tf local.tf_runner_service_env): vending, mcp-terraform-server and the Control
      # Center only, appended LAST so an existing install plans pure env additions. Inert until the FD-7L phases read
      # them (STACKVEND_TF_RUNNER_IDENTITY = PLATFORM is the Shared behaviour). Empty values are not set.
      dynamic "env" {
        for_each = { for k, v in lookup(local.tf_runner_service_env, each.key, {}) : k => v if v != "" }
        content {
          name  = env.key
          value = env.value
        }
      }
      # SELFUP-B (platform_upgrader.tf local.platform_upgrader_service_env): STACKVEND_PLATFORM_UPGRADE_TOPIC on the
      # Control Center only, appended LAST (one env addition = the upgrader apply's single in-place change). Unset
      # (enable_platform_upgrader = false) = the Update StackVend button is hidden.
      dynamic "env" {
        for_each = { for k, v in lookup(local.platform_upgrader_service_env, each.key, {}) : k => v if v != "" }
        content {
          name  = env.key
          value = env.value
        }
      }
    }

    scaling {
      # Per-service override (var.cloud_run_min_instances); unlisted services scale to zero.
      min_instance_count = lookup(var.cloud_run_min_instances, each.key, 0)
      max_instance_count = 5
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].containers[0].image,
      client,
      client_version,
      # Written by `gcloud run deploy --source` (deploy path owns it); never set here.
      build_config,
      # SERVICE-level scaling (not template[0].scaling, which stays managed): provider-reported,
      # never set here, otherwise a perpetual "- scaling {...}" diff on every service.
      scaling,
    ]

    # Lane 19 L19-0a (A1, register row 27b): two different OAuth clients per install.
    precondition {
      condition     = var.cc_google_oauth_client_id == "" || var.tenant_google_client_id == "" || var.cc_google_oauth_client_id != var.tenant_google_client_id
      error_message = "A1 (register row 27b): the Control Center OAuth client (cc_google_oauth_client_id) and the tenant sign-in client (tenant_google_client_id) must be two different clients."
    }

    # Step 1 follow-up: a misspelled service name in cloud_run_min_instances would silently keep scale-to-zero.
    # (Kept after the A1 precondition: tests/test_lane19_two_clients_tf.py reads the first one.)
    precondition {
      condition     = alltrue([for k in keys(var.cloud_run_min_instances) : contains(keys(local.cloud_run_services), k)])
      error_message = "cloud_run_min_instances keys must be Cloud Run service names declared in local.cloud_run_services."
    }

    # FD-7L step B needs a Per-workload install and vending on its own identity (the broker, re-RT R9).
    precondition {
      condition     = !var.tf_runner_dedicated_sa || (var.tf_runner_identity == "PER_WORKLOAD" && var.vending_runs_as_provisioner)
      error_message = "tf_runner_dedicated_sa = true (FD-7L step B) needs tf_runner_identity = \"PER_WORKLOAD\" and vending_runs_as_provisioner = true."
    }

    # HOST-INTERNAL-INGRESS: internal-only ingress without the platform network would cut every service-to-service
    # and job-to-service call (Cloud Run answers them 404).
    precondition {
      condition     = !var.host_internal_ingress || var.host_vpc_egress
      error_message = "host_internal_ingress = true needs host_vpc_egress = true (the platform's own services and jobs reach internal-only services through the stackvend-host network)."
    }
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

# ------------------------------------------------------------------------------
# Control Center Ingress IAM (Plan 12: Dual-Mode Public / Enterprise Direct IAP)
# ------------------------------------------------------------------------------

# 1. Public Ingress (used ONLY when allow_unauthenticated is true)
resource "google_cloud_run_v2_service_iam_member" "control_center_public_invoker" {
  count    = var.allow_unauthenticated ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.services["product-control-center-ui"].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# 2. Enterprise Direct IAM Invokers (used for service-to-service / CLI proxy when allow_unauthenticated is false)
resource "google_cloud_run_v2_service_iam_member" "control_center_authenticated_invoker" {
  for_each = var.allow_unauthenticated ? toset([]) : toset(var.authorized_invoker_members)
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.services["product-control-center-ui"].name
  role     = "roles/run.invoker"
  member   = each.key
}

# FD-4M F6/H4: non-blocking warning when enterprise mode has no ADMIN_EMAIL bootstrap admin.
check "control_center_admin_email" {
  assert {
    condition     = var.allow_unauthenticated || var.admin_email != "" || (length(var.authorized_invoker_members) > 0 && startswith(try(var.authorized_invoker_members[0], ""), "user:"))
    error_message = "allow_unauthenticated=false with no admin_email (and no leading user: invoker): the Control Center has no ADMIN_EMAIL bootstrap admin. Admins must already exist in Firestore authorized_users."
  }
}

# Lane 19 L19-0a: non-blocking warning when the Control Center has no Terraform-pinned OAuth client (an IAP-only CC,
# register row 41, needs none). Unpinned, the CC falls back to Secret Manager castor-oauth-client-id, which tf-applier
# copies into every tenant today (the Q8 path).
check "cc_client_pinned" {
  assert {
    condition     = var.cc_google_oauth_client_id != "" || (!var.allow_unauthenticated && var.enable_direct_iap)
    error_message = "The Control Center has no pinned OAuth client (cc_google_oauth_client_id is empty); it would fall back to Secret Manager castor-oauth-client-id."
  }
}

# 3. IAP Service Agent Invoker (allows IAP proxy to invoke the Cloud Run container)
resource "google_cloud_run_v2_service_iam_member" "control_center_iap_agent_invoker" {
  count      = (!var.allow_unauthenticated && var.enable_direct_iap) ? 1 : 0
  depends_on = [google_project_service_identity.iap_sa]
  project    = var.project_id
  location   = var.region
  name       = google_cloud_run_v2_service.services["product-control-center-ui"].name
  role       = "roles/run.invoker"
  member     = "serviceAccount:service-${data.google_project.platform_project.number}@gcp-sa-iap.iam.gserviceaccount.com"
}

# 4. Enterprise IAP Web Accessors (grants corporate browser users access through IAP)
resource "google_iap_web_cloud_run_service_iam_member" "control_center_iap_accessors" {
  for_each               = (!var.allow_unauthenticated && var.enable_direct_iap) ? toset(var.authorized_invoker_members) : toset([])
  project                = var.project_id
  location               = var.region
  cloud_run_service_name = google_cloud_run_v2_service.services["product-control-center-ui"].name
  role                   = "roles/iap.httpsResourceAccessor"
  member                 = each.key
}

# 5. FINOPS-IAP-ACCESS (owner 10-26) is withdrawn by C10 (owner 11-07): the IAP accessor grant for sa-castor-finops on
#    the Control Center is removed. Direct IAP refused that service account's requests anyway (the nightly spend sync,
#    the sandbox sweeper and the billing push all failed 401), and since C10 nothing machine-calls the Control Center:
#    the two schedulers run Cloud Run jobs and the billing subscription is drained by a job (section 9c). Humans are
#    unchanged (accessors above). The Control Center's platform-caller allow-list (identity.py) is empty (fail closed):
#    its ADMIN routes accept humans only and the kept /api/alerts/billing route (PUBSUB_PUSH) refuses every caller.

# ------------------------------------------------------------------------------
# Serverless Git Microservice (Cloud Run Gen2 + Cloud Storage FUSE)
# ------------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "git_server" {
  provider = google-beta
  count    = (var.deploy_git_server || upper(var.vcs_provider) == "SERVERLESS_GIT") ? 1 : 0
  depends_on = [
    google_project_service.apis,
    google_storage_bucket.git_repos_bucket,
    google_storage_bucket_iam_member.git_repos_bucket_admin
  ]
  project     = var.project_id
  location    = var.region
  name        = "castor-git-server"
  description = "Serverless Git microservice backed by Cloud Storage FUSE ($0/mo idle)"

  # FD-0D: Terraform-only latch; see google_cloud_run_v2_service.services.
  deletion_protection = true

  # HOST-INTERNAL-INGRESS (host_network.tf). Its callers (gateway, Control Center, vending, github MCP, tf-applier,
  # refactor scanner) all have Direct VPC egress; child-project builds never read it (they read a GCS tarball).
  ingress = local.host_service_ingress

  template {
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
    timeout               = "900s"
    service_account       = google_service_account.agents["sa-castor-developer"].email

    # HOST-VPC-EGRESS: the git server calls nothing, but every host Cloud Run resource except the QA job is on the
    # network (one rule, tests/test_internal_ingress_tf.py).
    dynamic "vpc_access" {
      for_each = local.host_vpc_access
      content {
        egress = local.host_egress_mode
        network_interfaces {
          network    = vpc_access.value.network
          subnetwork = vpc_access.value.subnetwork
        }
      }
    }

    # max_instance_count = 1 is a GCS FUSE single-writer invariant: keep it managed.
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    # FD-4W / FD28-03: repo storage is ALWAYS declared (it used to depend on the image variable,
    # so an apply with the default image dropped the volume and broke Serverless Git).
    volumes {
      name = "git-storage"
      gcs {
        bucket    = google_storage_bucket.git_repos_bucket[0].name
        read_only = false
      }
    }

    containers {
      # Initial image only: after creation the deploy paths own the image (ignore_changes below).
      image = var.git_server_container_image != "" ? var.git_server_container_image : var.placeholder_container_image

      resources {
        limits = {
          cpu    = "1000m"
          memory = "1024Mi"
        }
        cpu_idle = true
      }

      volume_mounts {
        name       = "git-storage"
        mount_path = "/data/git"
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "GIT_DATA_DIR"
        value = "/data/git"
      }
      # Lane 18 S0: callers no longer share one SA. Unset, git_server_auth.py allows only the server's own
      # runtime SA (sa-castor-developer); vending and the Control Center now run as their own SAs.
      env {
        name  = "GIT_SERVER_ALLOWED_INVOKERS"
        value = join(",", distinct([local.developer_sa_email, local.vending_sa_email, local.cc_sa_email]))
      }
      # FD-7L step B only (tf_runner_identity.tf local.git_server_runner_env): the tf-applier job SA, read-only
      # class. Absent in step A (no change to this service).
      dynamic "env" {
        for_each = local.git_server_runner_env
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].containers[0].image,
      client,
      client_version,
      build_config,
      # SERVICE-level scaling only (provider-reported). template[0].scaling stays managed.
      scaling,
    ]
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

# Grant authorized agent service accounts invoker access to private git server
resource "google_cloud_run_v2_service_iam_member" "git_server_agent_invokers" {
  for_each = (var.deploy_git_server || upper(var.vcs_provider) == "SERVERLESS_GIT") ? google_service_account.agents : {}
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.git_server[0].name
  role     = "roles/run.invoker"
  member   = each.value.member
}

# Push subscription: routes spec-intake-events to orchestrator-gateway-service
resource "google_pubsub_subscription" "spec_intake_push" {
  depends_on = [google_project_service.apis, google_cloud_run_v2_service.services, google_pubsub_topic.castor_dlq]
  project    = var.project_id
  name       = "castor-spec-intake-push"
  topic      = google_pubsub_topic.spec_intake_events.name

  # SUB-NO-EXPIRY (10-27): Pub/Sub deletes a subscription after 31 days without activity by default; quiet
  # platform subscriptions (billing alerts, SRE incidents, the DLQ) expired silently on a dev install. Never expire.
  expiration_policy {
    ttl = ""
  }

  ack_deadline_seconds = 60

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.castor_dlq.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "300s"
  }

  push_config {
    push_endpoint = "${google_cloud_run_v2_service.services["orchestrator-gateway-service"].uri}/events/pubsub-intake"

    oidc_token {
      service_account_email = google_service_account.agents["sa-castor-architect"].email
      audience              = google_cloud_run_v2_service.services["orchestrator-gateway-service"].uri
    }
  }
}

# Push subscription: routes runtime-incident-events to log-sre-sentinel-service
resource "google_pubsub_subscription" "sre_incident_push" {
  depends_on = [google_project_service.apis, google_cloud_run_v2_service.services, google_pubsub_topic.castor_dlq]
  project    = var.project_id
  name       = "castor-sre-incident-push"
  topic      = google_pubsub_topic.runtime_incident_events.name

  # SUB-NO-EXPIRY (10-27): Pub/Sub deletes a subscription after 31 days without activity by default; quiet
  # platform subscriptions (billing alerts, SRE incidents, the DLQ) expired silently on a dev install. Never expire.
  expiration_policy {
    ttl = ""
  }

  ack_deadline_seconds = 60

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.castor_dlq.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "300s"
  }

  push_config {
    push_endpoint = "${google_cloud_run_v2_service.services["log-sre-sentinel-service"].uri}/events/log-sink"

    oidc_token {
      service_account_email = google_service_account.agents["sa-castor-sre"].email
      audience              = google_cloud_run_v2_service.services["log-sre-sentinel-service"].uri
    }
  }
}

# Billing alerts subscription. C10 (owner 11-07): a PULL subscription (no push_config), drained every 30 minutes by
# billing-alert-drain-job (section 9c; stackvend-billing-alert-drain scheduler), which acks a message only after it was
# processed. Until C10 it pushed to the Control Center's /api/alerts/billing as sa-castor-finops, which Direct IAP
# refused. Removing push_config is an in-place update (UpdateSubscription); the name and the resource address are
# kept (renaming would replace the subscription and drop its backlog), and the topic, the retry policy and the
# dead-letter policy are unchanged. Pull-only settings (pre-review F2/F15, in place): exactly-once delivery (the first
# duplicate defence; the drain job also claims each message id), a 600 s ack deadline (the drain extends it while an
# enforcer execution runs and acks only after a verified outcome) and an explicit 7-day retention.
resource "google_pubsub_subscription" "billing_alerts_push" {
  depends_on = [google_project_service.apis, google_pubsub_topic.billing_budget_alerts, google_pubsub_topic.castor_dlq]
  project    = var.project_id
  name       = "billing-alerts-push-subscription"
  topic      = google_pubsub_topic.billing_budget_alerts.name

  # SUB-NO-EXPIRY (10-27): Pub/Sub deletes a subscription after 31 days without activity by default; quiet
  # platform subscriptions (billing alerts, SRE incidents, the DLQ) expired silently on a dev install. Never expire.
  expiration_policy {
    ttl = ""
  }

  ack_deadline_seconds         = 600
  enable_exactly_once_delivery = true
  message_retention_duration   = "604800s"

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.castor_dlq.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "300s"
  }
}

# C10: only the drain job's own SA pulls, acks and extends ack deadlines, on this one subscription (no project-level
# Pub/Sub role; FD-4AS-c).
resource "google_pubsub_subscription_iam_member" "billing_alert_drain_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.billing_alerts_push.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${local.billing_drain_sa_email}"
}

# IAM: Pub/Sub service agent requires subscriber role on subscriptions with dead-letter topic
resource "google_pubsub_subscription_iam_member" "pubsub_dlq_subscribers" {
  for_each = toset([
    "castor-spec-intake-push",
    "castor-sre-incident-push",
    "billing-alerts-push-subscription",
  ])
  project      = var.project_id
  subscription = each.key
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:service-${data.google_project.platform_project.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
  depends_on   = [google_pubsub_subscription.spec_intake_push, google_pubsub_subscription.sre_incident_push, google_pubsub_subscription.billing_alerts_push]
}

# ------------------------------------------------------------------------------
# 9. Cloud Run Jobs (Single-Pass "Hello World" Batch Workers)
# ------------------------------------------------------------------------------
resource "google_cloud_run_v2_job" "jobs" {
  for_each   = { for k, v in local.cloud_run_jobs : k => v if k != local.qa_job_name }
  depends_on = [google_project_service.apis, google_artifact_registry_repository.castor_docker_repo, google_project_iam_member.cleaner_project_roles, google_project_iam_member.persona_datastore_users, google_storage_bucket_iam_member.cleaner_state_viewer, google_project_iam_member.guard_db_readers]
  project    = var.project_id
  location   = var.region
  name       = each.key

  # FD-0D: Terraform-only latch (provider default true; declared to document intent).
  deletion_protection = true

  template {
    template {
      # Lane 18 S0: sandbox-garbage-collector-job -> sa-stackvend-sandbox-cleaner; the others are unchanged.
      service_account = lookup(local.job_runtime_sa, each.key, google_service_account.agents["sa-castor-developer"].email)
      # Lane 14 I9 (row L14-a, owner 10-13): no blind Cloud Run re-runs of a failed execution; the job contract
      # (run record + exit codes) reports a failure once and the scheduler runs the next cadence.
      max_retries = 0
      # C10 (pre-review F7): per-job task timeout; null = the Cloud Run default for the jobs not listed.
      timeout = lookup(local.job_timeouts, each.key, null)

      # HOST-VPC-EGRESS (host_network.tf): the cleaner and refactor scanner call vending / the git server, the digest
      # calls the SRE sentinel. Only new executions pick it up.
      dynamic "vpc_access" {
        for_each = local.host_vpc_access
        content {
          egress = local.host_egress_mode
          network_interfaces {
            network    = vpc_access.value.network
            subnetwork = vpc_access.value.subnetwork
          }
        }
      }

      containers {
        image = var.placeholder_container_image

        resources {
          limits = {
            cpu    = "2000m"
            memory = "2048Mi"
          }
        }

        env {
          name  = "ENVIRONMENT"
          value = var.environment
        }
        env {
          name  = "PROJECT_ID"
          value = var.project_id
        }
        env {
          name  = "TFSTATE_BUCKET"
          value = data.google_storage_bucket.workload_tfstate_bucket.name
        }
        env {
          name  = "INBOX_FOLDER_ID"
          value = var.google_drive_intake_folder_ids
        }
        env {
          name  = "IN_PROGRESS_FOLDER_ID"
          value = var.google_drive_in_progress_folder_ids
        }
        env {
          name  = "COMPLETED_FOLDER_ID"
          value = var.google_drive_completed_folder_ids
        }
        env {
          name  = "GEMINI_MODEL"
          value = lookup(var.gemini_model_overrides, each.key, var.gemini_model)
        }
        env {
          name  = "GEMINI_LOCATION"
          value = "global"
        }
        # Lane 14 PR-3 (I3 slice): the digest resolves the sentinel URL with services.get; without REGION a HIGH
        # regression week ends NOT_CONFIGURED (exit 3). Owner `scripts/apply.sh apply` per install.
        dynamic "env" {
          for_each = each.key == "sre-telemetry-digest-job" ? [1] : []
          content {
            name  = "REGION"
            value = var.region
          }
        }
        # FD-4O (lane 4): the finops enforcer's target guard needs the managed root folder; without it every
        # quarantine is refused. Services already get this env (google_cloud_run_v2_service.services).
        env {
          name  = "MANAGED_WORKLOADS_FOLDER_ID"
          value = var.castor_managed_workloads_folder_id
        }
        # C10: the new jobs' own inputs (local.c10_job_env). Empty values are not set (fail closed in the job:
        # NOT_CONFIGURED, exit 3).
        dynamic "env" {
          for_each = { for k, v in lookup(local.c10_job_env, each.key, {}) : k => v if v != "" }
          content {
            name  = env.key
            value = env.value
          }
        }
        # Lane 14 PR-6 (RT F6-2; I3 slice for the sandbox cleaner). VENDING_SERVICE_URL is the deterministic
        # URL that vending accepts as its ID-token audience (the same value the Control Center gets in the
        # services block); the cleaner calls exactly this URL and mints its token for it. The Run Admin `uri`
        # is the hashed *.a.run.app form, which vending would answer 401. REGION is the cleaner's fallback
        # (services.get) and is required with due work when VENDING_SERVICE_URL is absent.
        # Lane 18 window v2: the value is destructive_guard.tf local.vending_service_url, the one expression
        # vending's own VENDING_SERVICE_URL (its accepted ID-token audience) is built from, so the two cannot drift.
        # Takes effect only after an owner `scripts/apply.sh apply` per install.
        dynamic "env" {
          for_each = each.key == "sandbox-garbage-collector-job" ? [1] : []
          content {
            name  = "REGION"
            value = var.region
          }
        }
        dynamic "env" {
          for_each = each.key == "sandbox-garbage-collector-job" ? [1] : []
          content {
            name  = "VENDING_SERVICE_URL"
            value = local.vending_service_url
          }
        }
        # Lane 18 S0b (closes lane 14 PR-6 SEAM): guard env per job, destructive_guard.tf local.guard_job_env
        # (today: STACKVEND_GUARD_FIRESTORE_DATABASE on the sandbox cleaner). Empty values are not set.
        dynamic "env" {
          for_each = { for k, v in lookup(local.guard_job_env, each.key, {}) : k => v if v != "" }
          content {
            name  = env.key
            value = env.value
          }
        }
        # Lane 14 PR-4 (I3 slice for the refactor scanner): GitHub archives use a vending-issued token (vending's
        # deterministic URL is its ID-token audience, as for the cleaner); StackVend git server archives use an ID
        # token for the git server; without these the nightly run exits 3
        # NOT_CONFIGURED at WARNING. Takes effect only after an owner `scripts/apply.sh apply`.
        dynamic "env" {
          for_each = each.key == "github-refactor-scanner-job" ? [1] : []
          content {
            name  = "VENDING_SERVICE_URL"
            value = "https://project-repo-vending-service-${data.google_project.platform_project.number}.${var.region}.run.app"
          }
        }
        dynamic "env" {
          for_each = (each.key == "github-refactor-scanner-job" && (var.deploy_git_server || upper(var.vcs_provider) == "SERVERLESS_GIT")) ? [1] : []
          content {
            name  = "GIT_SERVER_URL"
            value = try(google_cloud_run_v2_service.git_server[0].uri, "")
          }
        }
        # FD-7L step A (tf_runner_identity.tf local.tf_runner_job_env), appended LAST: pure env additions on the jobs
        # whose code reads the runner identity (today infra-rollback-job). Empty values are not set.
        dynamic "env" {
          for_each = { for k, v in lookup(local.tf_runner_job_env, each.key, {}) : k => v if v != "" }
          content {
            name  = env.key
            value = env.value
          }
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].template[0].containers[0].image,
      client,
      client_version,
    ]
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

# ------------------------------------------------------------------------------
# 9b. Dedicated Terraform Applier Batch Job (24h timeout headroom for stateful applies)
# ------------------------------------------------------------------------------
resource "google_cloud_run_v2_job" "tf_applier" {
  # FD-7L: the step-B template (job SA) is written only after that SA holds its roles.
  depends_on = [google_project_service.apis, google_artifact_registry_repository.castor_docker_repo, google_project_iam_member.tf_runner_project_roles, google_project_iam_member.tf_runner_datastore_users, google_project_iam_member.tf_runner_guard_db_readers, google_storage_bucket_iam_member.tf_runner_staging_job_reader]
  project    = var.project_id
  location   = var.region
  name       = "tf-applier"

  # FD-0D: Terraform-only latch (provider default true; declared to document intent).
  deletion_protection = true

  template {
    template {
      max_retries = 0 # Disable blind container retries; retries are orchestrated by StackVend
      # FD-7L: sa-castor-developer until step B (tf_runner_dedicated_sa), then sa-stackvend-tf-applier
      # (tf_runner_identity.tf local.tf_applier_runtime_sa). Deploy paths never pass --service-account.
      service_account = local.tf_applier_runtime_sa
      timeout         = "86400s" # 24-hour timeout for long-running stateful applies

      # HOST-VPC-EGRESS (host_network.tf): the applier calls vending (broker), the git server and compliance.
      dynamic "vpc_access" {
        for_each = local.host_vpc_access
        content {
          egress = local.host_egress_mode
          network_interfaces {
            network    = vpc_access.value.network
            subnetwork = vpc_access.value.subnetwork
          }
        }
      }

      containers {
        image   = var.placeholder_container_image
        command = ["/cnb/lifecycle/launcher"]
        args    = ["python3", "-m", "applier"]

        resources {
          limits = {
            cpu    = "2000m"
            memory = "2048Mi"
          }
        }

        env {
          name  = "ENVIRONMENT"
          value = var.environment
        }
        env {
          name  = "PROJECT_ID"
          value = var.project_id
        }
        env {
          name  = "TFSTATE_BUCKET"
          value = data.google_storage_bucket.workload_tfstate_bucket.name
        }
        env {
          name  = "VCS_PROVIDER"
          value = upper(var.vcs_provider)
        }
        env {
          name  = "GIT_SERVER_URL"
          value = (var.deploy_git_server || upper(var.vcs_provider) == "SERVERLESS_GIT") ? try(google_cloud_run_v2_service.git_server[0].uri, "") : ""
        }
        # FD-7L step A (tf_runner_identity.tf local.tf_applier_runner_env), appended LAST: pure env additions on
        # an existing install, inert until the FD-7L phases read them. Empty values are not set.
        dynamic "env" {
          for_each = { for k, v in local.tf_applier_runner_env : k => v if v != "" }
          content {
            name  = env.key
            value = env.value
          }
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].template[0].containers[0].image,
      client,
      client_version,
    ]

    # FD-7L step B needs a Per-workload install and vending on its own identity (the broker, re-RT R9).
    precondition {
      condition     = !var.tf_runner_dedicated_sa || (var.tf_runner_identity == "PER_WORKLOAD" && var.vending_runs_as_provisioner)
      error_message = "tf_runner_dedicated_sa = true (FD-7L step B) needs tf_runner_identity = \"PER_WORKLOAD\" and vending_runs_as_provisioner = true."
    }
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

# ------------------------------------------------------------------------------
# 9c. C10 (owner 11-07): IAM on the new jobs (google_cloud_run_v2_job.jobs; identities in destructive_guard.tf)
# ------------------------------------------------------------------------------
locals {
  c10_scheduled_jobs = toset(["finops-spend-sync-job", "sandbox-workload-sweeper-job", "billing-alert-drain-job"])
}

# Each scheduler's oauth identity (sa-castor-finops) may run its job: job-scoped roles/run.invoker (run.jobs.run).
# sa-castor-finops also holds the project-wide invoker of every agent SA (agent_run_invokers); this survives an FD-4T
# trim of that. Never run.developer (runWithOverrides on any job).
resource "google_cloud_run_v2_job_iam_member" "c10_job_schedulers" {
  for_each = local.c10_scheduled_jobs
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.jobs[each.key].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.agents["sa-castor-finops"].email}"
}

# On a budget breach the drain job runs finops-budget-enforcer-job ONCE with its FINOPS_ENFORCE_* env overrides
# (apps/finops-enforcer/main.py run_batch; the enforcer keeps its own identity, policy engine and FD-4O target guard)
# and polls that execution. Exactly these permissions, bound on that one job only, for the drain job's own SA.
resource "google_project_iam_custom_role" "billing_drain_enforcer_runner" {
  depends_on  = [google_project_service.apis]
  project     = var.project_id
  role_id     = "stackvendBillingDrainEnforcerRunner"
  title       = "StackVend billing drain: run the FinOps enforcer job"
  description = "C10: run finops-budget-enforcer-job with env overrides and read its executions. Bound on that one job only, for sa-stackvend-billing-drain."
  permissions = [
    "run.executions.get",
    "run.jobs.run",
    "run.jobs.runWithOverrides",
  ]
}

resource "google_cloud_run_v2_job_iam_member" "billing_drain_enforcer_runner" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.jobs["finops-budget-enforcer-job"].name
  role     = google_project_iam_custom_role.billing_drain_enforcer_runner.name
  member   = "serviceAccount:${local.billing_drain_sa_email}"
}

# C10 (RT residual R3, FD26-07): the Control Center's budget-breach approvals (RESTORE_BUFFER / budget increase) restore
# a quarantined workload by running the same job with FINOPS_ACTION=RESTORE (shared/enforcer_job.py); the engine is not
# in the CC image. The same narrow custom role, on that one job only.
resource "google_cloud_run_v2_job_iam_member" "cc_enforcer_runner" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.jobs["finops-budget-enforcer-job"].name
  role     = google_project_iam_custom_role.billing_drain_enforcer_runner.name
  member   = "serviceAccount:${local.cc_sa_email}"
}

# ------------------------------------------------------------------------------
# 10. Cloud Scheduler Cron Pollers & Timers
# ------------------------------------------------------------------------------
# Ingestion Poller: Scans Google Drive 01_Inbox_Requests folder every 5 minutes (optional, disabled by default)
resource "google_cloud_scheduler_job" "spec_ingestion_poller" {
  count       = var.enable_drive_spec_polling ? 1 : 0
  depends_on  = [google_project_service.apis, google_cloud_run_v2_service.services]
  project     = var.project_id
  region      = var.region
  name        = "castor-spec-ingestion-poller"
  description = "Polls Google Drive 01_Inbox_Requests folder every 5 minutes"
  schedule    = "*/5 * * * *"
  time_zone   = "America/New_York"

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.services["spec-ingestion-service"].uri}/poll"

    oidc_token {
      service_account_email = google_service_account.agents["sa-castor-architect"].email
    }
  }
}

# Nightly Refactor Scanner: Runs repository AST and Dependabot scan at 2:00 AM daily
resource "google_cloud_scheduler_job" "nightly_refactor_scan" {
  depends_on  = [google_project_service.apis, google_cloud_run_v2_job.jobs]
  project     = var.project_id
  region      = var.region
  name        = "castor-nightly-refactor-scan"
  description = "Triggers the repository refactor and Dependabot scanner at 2 AM daily"
  schedule    = "0 2 * * *"
  time_zone   = "America/New_York"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/github-refactor-scanner-job:run"

    oauth_token {
      service_account_email = google_service_account.agents["sa-castor-developer"].email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }
}

# Sandbox TTL Cleaner: Sweeps expired ephemeral test sandboxes every 2 hours
resource "google_cloud_scheduler_job" "sandbox_ttl_cleaner" {
  depends_on  = [google_project_service.apis, google_cloud_run_v2_job.jobs]
  project     = var.project_id
  region      = var.region
  name        = "castor-sandbox-ttl-cleaner"
  description = "Sweeps and destroys expired test sandboxes every 2 hours"
  schedule    = "0 */2 * * *"
  time_zone   = "America/New_York"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/sandbox-garbage-collector-job:run"

    oauth_token {
      service_account_email = google_service_account.agents["sa-castor-gcp-devops"].email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }
}

# SRE Telemetry Digest: Runs weekly system health analysis every Sunday at 3:00 AM
resource "google_cloud_scheduler_job" "sre_telemetry_digest" {
  depends_on  = [google_project_service.apis, google_cloud_run_v2_job.jobs]
  project     = var.project_id
  region      = var.region
  name        = "castor-sre-telemetry-digest"
  description = "Aggregates warning log clusters and latency drift weekly on Sunday at 3 AM"
  schedule    = "0 3 * * 0"
  time_zone   = "America/New_York"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/sre-telemetry-digest-job:run"

    oauth_token {
      service_account_email = google_service_account.agents["sa-castor-sre"].email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }
}

# FinOps Spend Sync: Runs daily spend synchronization and run-rate budget projection at 3:00 AM
# C10 (owner 11-07): runs finops-spend-sync-job (apps/finops-spend-sync) instead of calling the Control Center, which
# Direct IAP refused. Same name, schedule and identity (in-place update of uri and token type only).
resource "google_cloud_scheduler_job" "finops_nightly_spend_sync" {
  depends_on  = [google_project_service.apis, google_cloud_run_v2_job.jobs, google_cloud_run_v2_job_iam_member.c10_job_schedulers]
  project     = var.project_id
  region      = var.region
  name        = "castor-finops-nightly-spend-sync"
  description = "Synchronizes workload spend metrics and calculates run-rate projections daily at 3:00 AM"
  schedule    = "0 3 * * *"
  time_zone   = "America/New_York"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/finops-spend-sync-job:run"

    oauth_token {
      service_account_email = google_service_account.agents["sa-castor-finops"].email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }
}

# Sandbox Workload Sweeper: Runs daily at 4:00 AM to decommission expired 30-day sandboxes and send advance warnings
# C10 (owner 11-07): runs sandbox-workload-sweeper-job (apps/sandbox-sweeper) instead of calling the Control Center. Same name,
# schedule and identity (in-place update of uri and token type only). Vending still executes every delete (lane 18 S2).
resource "google_cloud_scheduler_job" "sandbox_workload_sweeper" {
  depends_on  = [google_project_service.apis, google_cloud_run_v2_job.jobs, google_cloud_run_v2_job_iam_member.c10_job_schedulers]
  project     = var.project_id
  region      = var.region
  name        = "castor-sandbox-workload-sweeper"
  description = "Scans 30-day sandbox lifespans daily, issues advance notifications (T-7 / T-2), and autonomously decommissions expired sandboxes to zero cost"
  schedule    = "0 4 * * *"
  time_zone   = "America/New_York"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/sandbox-workload-sweeper-job:run"

    oauth_token {
      service_account_email = google_service_account.agents["sa-castor-finops"].email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }
}

# Billing Alert Drain (C10, owner 11-07): every 30 minutes, billing-alert-drain-job pulls the billing-alerts
# subscription (apps/billing-alert-drain): budget notifications reach Firestore and, on a breach, the enforcer within
# about 30 minutes (the push used to be immediate but never got through Direct IAP).
resource "google_cloud_scheduler_job" "billing_alert_drain" {
  depends_on  = [google_project_service.apis, google_cloud_run_v2_job.jobs, google_cloud_run_v2_job_iam_member.c10_job_schedulers]
  project     = var.project_id
  region      = var.region
  name        = "stackvend-billing-alert-drain"
  description = "Drains Cloud Billing budget notifications from the billing-alerts pull subscription every 30 minutes"
  schedule    = "*/30 * * * *"
  time_zone   = "America/New_York"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/billing-alert-drain-job:run"

    oauth_token {
      service_account_email = google_service_account.agents["sa-castor-finops"].email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }
}

# ------------------------------------------------------------------------------
# 11. Cloud Logging SRE Error Sink -> Pub/Sub
# ------------------------------------------------------------------------------
resource "google_logging_project_sink" "sre_error_sink" {
  depends_on  = [google_project_service.apis, google_pubsub_topic.runtime_incident_events]
  project     = var.project_id
  name        = "castor-sre-error-sink"
  description = "Routes runtime errors and unhandled crashes to StackVend SRE incident sentinel"

  destination = "pubsub.googleapis.com/projects/${var.project_id}/topics/runtime-incident-events"
  filter      = "severity >= ERROR OR (resource.type=\"cloud_run_revision\" AND jsonPayload.level=\"ERROR\")"

  unique_writer_identity = true
}

# Grant the log sink permission to publish to the Pub/Sub topic
resource "google_pubsub_topic_iam_member" "sre_log_sink_publisher" {
  depends_on = [google_project_service_identity.logging_sa, google_logging_project_sink.sre_error_sink]
  project    = var.project_id
  topic      = google_pubsub_topic.runtime_incident_events.name
  role       = "roles/pubsub.publisher"
  member     = google_logging_project_sink.sre_error_sink.writer_identity
}

# HOST-AUDIT-LOG-SETTING: optional Data Access audit logs on the host project (default {}: nothing is planned). Failed
# calls can be logged at ERROR, which the sink above forwards to the sentinel as record-only UNATTRIBUTED incidents.
# Removing an entry is a delete, which the apply gate refuses without --allow-destroy; audit_log_config needs at least
# one block and an exemption does not switch a log type off, so there is no in-place "off" (configuration.md).
resource "google_project_iam_audit_config" "host_data_access" {
  for_each   = var.host_data_access_audit_logs
  depends_on = [google_project_service.apis]
  project    = var.project_id
  service    = each.key

  audit_log_config {
    log_type = each.value
  }
}

# ------------------------------------------------------------------------------
# 13. Google Cloud Workflows Orchestration Module
# ------------------------------------------------------------------------------
module "workflows" {
  source = "../modules/workflows"

  depends_on                         = [google_project_service.apis, google_project_service_identity.workflows_sa, google_cloud_run_v2_service.services, google_service_account.agents]
  project_id                         = var.project_id
  region                             = var.region
  environment                        = var.environment
  orchestrator_service_account_email = google_service_account.agents["sa-castor-architect"].email
  sre_service_account_email          = google_service_account.agents["sa-castor-sre"].email

  service_urls = {
    for k, v in google_cloud_run_v2_service.services : k => v.uri
  }

  pubsub_topics = {
    spec_intake           = google_pubsub_topic.spec_intake_events.id
    autonomous_refactor   = google_pubsub_topic.autonomous_refactor_events.id
    runtime_incident      = google_pubsub_topic.runtime_incident_events.id
    workflow_callbacks    = google_pubsub_topic.workflow_callbacks.id
    dead_letter_queue     = google_pubsub_topic.castor_dlq.id
    billing_budget_alerts = google_pubsub_topic.billing_budget_alerts.id
  }
}
