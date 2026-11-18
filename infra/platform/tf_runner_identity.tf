# ==============================================================================
# FD-7L Phase 7 (SAT-33) + FD-7L-n (SAT-35): per-workload Terraform runner identities
# ==============================================================================
# Plan: docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3 §2.3, §2.12, §2.13, §4 (owner D1: two runner
# SAs). Red team: docs/handoff/fd-7l-plan-rt.md F3, F9, R1, R3, R4, R9. Report + runbook: docs/handoff/sat-33-report.md.
#
# STEP A (always declared; additive and inert). With the defaults (tf_runner_dedicated_sa = false,
# tf_runner_identity = "PLATFORM") an existing install plans ONLY creates here, plus in-place env ADDITIONS on
# project-repo-vending-service, mcp-terraform-server, product-control-center-ui, the tf-applier job and
# infra-rollback-job (main.tf).
# No runtime identity changes, nothing is removed, and no code reads the new env until the FD-7L phases ship (vending
# treats STACKVEND_TF_RUNNER_IDENTITY = PLATFORM exactly like unset). Both member lists name the developer SA AND the
# new SA, so every broker call keeps working while the runtimes are still sa-castor-developer (re-RT R4).
#
# STEP B (tf_runner_dedicated_sa = true; needs tf_runner_identity = "PER_WORKLOAD" and vending_runs_as_provisioner):
#   mcp-terraform-server runtime -> sa-stackvend-tf-server, tf-applier runtime -> sa-stackvend-tf-applier,
#   STACKVEND_TF_RUNNER_MEMBERS / STACKVEND_TF_SERVER_MEMBERS narrowed to the new SAs,
#   GIT_SERVER_READONLY_INVOKERS (= job SA) on the git server. scripts/apply.sh refuses the runtime switch unless every
#   live workload's vending-signed runner identity record is READY (scripts/common/runner_identity_readiness.py).
#   ROLLBACK: tf_runner_dedicated_sa = false (runtimes back on sa-castor-developer, member lists widened again).
#
# NEW INSTALLS (SAT-35/SAT-46): scripts/bootstrap.sh writes tf_runner_identity = "PER_WORKLOAD" and
# tf_runner_dedicated_sa = true, so a new install creates step A and step B together on its first apply (a create, not
# a switch: no workloads, so the readiness check is not involved). The variables.tf defaults keep existing installs Shared.
#
# NOT granted to either runner SA (plan §4, RT F3): Secret Manager, the platform state bucket, folder roles,
# agent_state_viewers, agent_run_invokers, run.developer, workflows.invoker, billing, any tokenCreator / actAs.
# Nothing is removed from sa-castor-developer (D1; FD-4T owns that).
# ==============================================================================

locals {
  tf_runner_job_account_id    = "sa-stackvend-tf-applier"
  tf_runner_server_account_id = "sa-stackvend-tf-server"
  # The emails as plain strings (a user-managed SA's email is always <account_id>@<project>.iam.gserviceaccount.com),
  # so the env values are KNOWN at plan time and the step-A plan shows them exactly. Every IAM grant and runtime
  # identity below uses the resource attributes instead, so it is ordered after the SA exists.
  tf_runner_job_sa_email    = "${local.tf_runner_job_account_id}@${var.project_id}.iam.gserviceaccount.com"
  tf_runner_server_sa_email = "${local.tf_runner_server_account_id}@${var.project_id}.iam.gserviceaccount.com"
  tf_runner_job_member      = google_service_account.tf_runners[local.tf_runner_job_account_id].member
  tf_runner_server_member   = google_service_account.tf_runners[local.tf_runner_server_account_id].member

  # Runtime identities. Step A keeps both runners on sa-castor-developer; step B moves them (main.tf reads these).
  tf_runner_service_runtime_sa = var.tf_runner_dedicated_sa ? { "mcp-terraform-server" = google_service_account.tf_runners[local.tf_runner_server_account_id].email } : {}
  tf_applier_runtime_sa        = var.tf_runner_dedicated_sa ? google_service_account.tf_runners[local.tf_runner_job_account_id].email : local.developer_sa_email

  # Broker caller lists (vending env, comma-separated emails; apps/project-vending runner_broker.py BrokerConfig).
  # Step A: {developer, new SA} (R4: mints keep working until the runtimes move). Step B: the new SA only.
  tf_runner_job_members    = var.tf_runner_dedicated_sa ? [local.tf_runner_job_sa_email] : distinct([local.developer_sa_email, local.tf_runner_job_sa_email])
  tf_runner_server_members = var.tf_runner_dedicated_sa ? [local.tf_runner_server_sa_email] : distinct([local.developer_sa_email, local.tf_runner_server_sa_email])

  # Plan §2.13: the only identities whose workload Terraform the server's workload routes accept (Phase 5 reads it).
  # Workflow (orchestrator runs as sa-castor-architect, module "workflows"), gateway (sa-castor-developer),
  # Control Center, vending.
  tf_server_workload_callers = distinct([
    google_service_account.agents["sa-castor-architect"].email,
    local.developer_sa_email,
    local.cc_sa_email,
    local.vending_sa_email,
  ])

  tf_runner_git_enabled = var.deploy_git_server || upper(var.vcs_provider) == "SERVERLESS_GIT"

  # Env contract. Empty values are omitted by the dynamic blocks in main.tf (none is empty here). The broker email
  # is the Terraform-owned vending identity (R9): with vending_runs_as_provisioner = false it is sa-castor-developer,
  # which the broker refuses (RUNNER_BROKER_SHARED_IDENTITY); never "whoever runs vending".
  tf_runner_service_env = {
    "project-repo-vending-service" = {
      STACKVEND_TF_RUNNER_IDENTITY    = var.tf_runner_identity
      STACKVEND_BROKER_SA             = local.vending_sa_email
      STACKVEND_TF_RUNNER_MEMBERS     = join(",", local.tf_runner_job_members)
      STACKVEND_TF_SERVER_MEMBERS     = join(",", local.tf_runner_server_members)
      STACKVEND_RUNNER_STAGING_BUCKET = google_storage_bucket.tf_runner_staging.name
    }
    "mcp-terraform-server" = {
      STACKVEND_TF_RUNNER_IDENTITY       = var.tf_runner_identity
      STACKVEND_BROKER_SA                = local.vending_sa_email
      VENDING_SERVICE_URL                = local.vending_service_url
      TF_SERVER_WORKLOAD_CALLERS         = join(",", local.tf_server_workload_callers)
      STACKVEND_RUNNER_STAGING_BUCKET    = google_storage_bucket.tf_runner_staging.name
      STACKVEND_GUARD_FIRESTORE_DATABASE = google_firestore_database.stackvend_guard.name
    }
    "product-control-center-ui" = {
      STACKVEND_TF_RUNNER_IDENTITY = var.tf_runner_identity
      STACKVEND_BROKER_SA          = local.vending_sa_email
    }
  }
  tf_applier_runner_env = {
    STACKVEND_TF_RUNNER_IDENTITY       = var.tf_runner_identity
    STACKVEND_BROKER_SA                = local.vending_sa_email
    VENDING_SERVICE_URL                = local.vending_service_url
    STACKVEND_RUNNER_STAGING_BUCKET    = google_storage_bucket.tf_runner_staging.name
    STACKVEND_GUARD_FIRESTORE_DATABASE = google_firestore_database.stackvend_guard.name
  }
  # The same contract for the other Cloud Run JOBS (main.tf google_cloud_run_v2_job.jobs) whose code reads the runner
  # identity (a shared/runner_identity.py copy). infra-rollback-job (apps/infra-rollback/rollback.py
  # resolve_state_bucket) reads the mode, the expected signer and the guard database; without them a Per-workload
  # install's rollback would read the platform bucket. It runs as sa-castor-developer, which already holds
  # guard_db_readers.developer (destructive_guard.tf): no new IAM.
  tf_runner_job_env = {
    "infra-rollback-job" = {
      STACKVEND_TF_RUNNER_IDENTITY       = var.tf_runner_identity
      STACKVEND_BROKER_SA                = local.vending_sa_email
      STACKVEND_GUARD_FIRESTORE_DATABASE = google_firestore_database.stackvend_guard.name
    }
    # C10: finops-spend-sync-job reads workload state where the Control Center does (services/runner_state.py, a
    # byte copy): the mode, the expected signer and the guard database. Its SA holds guard_db_readers.spend.
    "finops-spend-sync-job" = {
      STACKVEND_TF_RUNNER_IDENTITY       = var.tf_runner_identity
      STACKVEND_BROKER_SA                = local.vending_sa_email
      STACKVEND_GUARD_FIRESTORE_DATABASE = google_firestore_database.stackvend_guard.name
    }
  }
  # Step B only (plan §2.10, RT F3/F9): the job SA reads repositories through the git server's read-only class.
  git_server_runner_env = var.tf_runner_dedicated_sa ? { GIT_SERVER_READONLY_INVOKERS = local.tf_runner_job_sa_email } : {}
}

# ------------------------------------------------------------------------------
# 1. The two runner service accounts (owner D1)
# ------------------------------------------------------------------------------
resource "google_service_account" "tf_runners" {
  for_each = {
    "sa-stackvend-tf-applier" = "StackVend Terraform runner job (tf-applier)"
    "sa-stackvend-tf-server"  = "StackVend Terraform server (validate and dispatch; no deployer access)"
  }
  depends_on   = [google_project_service.apis]
  project      = var.project_id
  account_id   = each.key
  display_name = each.value
}

# ------------------------------------------------------------------------------
# 2. Custom roles (RT F3: no project-wide workflows.invoker, no objectCreator with overwrite). The fallback-design role
#    stackvendTfApplierRun is NOT created: the owner chose the vending broker (plan §2.3, §9).
# ------------------------------------------------------------------------------
resource "google_project_iam_custom_role" "stackvend_workflow_callback" {
  depends_on  = [google_project_service.apis]
  project     = var.project_id
  role_id     = "stackvendWorkflowCallback"
  title       = "StackVend workflow callback sender"
  description = "FD-7L: send a Cloud Workflows callback only (no executions.create). Held by the tf-applier job SA."
  permissions = ["workflows.callbacks.send"]
  stage       = "GA"
}

resource "google_project_iam_custom_role" "stackvend_staging_create" {
  depends_on  = [google_project_service.apis]
  project     = var.project_id
  role_id     = "stackvendStagingCreate"
  title       = "StackVend runner staging object create"
  description = "FD-7L: create objects in the runner staging bucket only (no overwrite, no delete, no read). Held by the terraform server SA on that bucket."
  permissions = ["storage.objects.create"]
  stage       = "GA"
}

# ------------------------------------------------------------------------------
# 3. Staging bucket for caller-supplied payloads (plan §2.12, re-RT R3): the server SA may only create objects, the
#    job SA may only read; the dispatch record carries the payload's sha256.
# ------------------------------------------------------------------------------
resource "google_storage_bucket" "tf_runner_staging" {
  depends_on                  = [google_project_service.apis]
  project                     = var.project_id
  name                        = "stackvend-runner-staging-${var.project_id}"
  location                    = var.region
  force_destroy               = false
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  # Objects are create-only (no overwrite); nothing to version.
  versioning {
    enabled = false
  }

  # A deleted payload is not kept (it can hold caller Terraform).
  soft_delete_policy {
    retention_duration_seconds = 0
  }

  # A payload is read once by the execution that was dispatched for it, within minutes.
  lifecycle_rule {
    condition {
      age = 1
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

resource "google_storage_bucket_iam_member" "tf_runner_staging_job_reader" {
  bucket = google_storage_bucket.tf_runner_staging.name
  role   = "roles/storage.objectViewer"
  member = local.tf_runner_job_member
}

resource "google_storage_bucket_iam_member" "tf_runner_staging_server_create" {
  bucket = google_storage_bucket.tf_runner_staging.name
  role   = google_project_iam_custom_role.stackvend_staging_create.id
  member = local.tf_runner_server_member
}

# ------------------------------------------------------------------------------
# 4. Host project roles of the two runner SAs (exact sets; tests/fixtures/fd7l_tf/fd7l_tf.tftest.hcl)
# ------------------------------------------------------------------------------
# The terraform server SA also holds the callback role (owner 11-01): its watcher (FD-7L Phase 5a) sends the typed
# FAILED callback when a Per-workload tf-applier execution fails before redeeming its nonce. Inert until step B.
resource "google_project_iam_member" "tf_runner_project_roles" {
  for_each = {
    "job-log-writer"           = { role = "roles/logging.logWriter", member = local.tf_runner_job_member }
    "job-workflow-callback"    = { role = google_project_iam_custom_role.stackvend_workflow_callback.id, member = local.tf_runner_job_member }
    "server-log-writer"        = { role = "roles/logging.logWriter", member = local.tf_runner_server_member }
    "server-workflow-callback" = { role = google_project_iam_custom_role.stackvend_workflow_callback.id, member = local.tf_runner_server_member }
  }
  project = var.project_id
  role    = each.value.role
  member  = each.value.member
}

# Default (and any other) Firestore database, never the guard database (D2: records stay platform-side; the server's
# grant covers the whole default database, plan §2.12 R4 correction).
resource "google_project_iam_member" "tf_runner_datastore_users" {
  for_each = {
    job    = local.tf_runner_job_member
    server = local.tf_runner_server_member
  }
  project = var.project_id
  role    = "roles/datastore.user"
  member  = each.value

  condition {
    title       = "stackvend-not-guard-db"
    description = "Every Firestore database except the stackvend-guard database (lane 18 S0b)"
    expression  = "!(${local.guard_db_condition})"
  }
}

# Guard database READ (vending-signed provenance and dispatch records). Read-only, so neither SA can forge a record.
resource "google_project_iam_member" "tf_runner_guard_db_readers" {
  for_each = {
    job    = local.tf_runner_job_member
    server = local.tf_runner_server_member
  }
  project = var.project_id
  role    = "roles/datastore.viewer"
  member  = each.value

  condition {
    title       = "stackvend-guard-db-read"
    description = "stackvend-guard database only, read-only (FD-7L runner provenance)"
    expression  = local.guard_db_condition
  }

  depends_on = [google_firestore_database.stackvend_guard]
}

# ------------------------------------------------------------------------------
# 5. Service invokers: the job calls the compliance server and vending's /runner/* routes; the server calls vending's
#    /runner/dispatch. (Vending checks the caller lists above on top of Cloud Run IAM.)
# ------------------------------------------------------------------------------
resource "google_cloud_run_v2_service_iam_member" "tf_runner_invokers" {
  for_each = {
    "job:mcp-compliance-server"           = { service = "mcp-compliance-server", member = local.tf_runner_job_member }
    "job:project-repo-vending-service"    = { service = "project-repo-vending-service", member = local.tf_runner_job_member }
    "server:project-repo-vending-service" = { service = "project-repo-vending-service", member = local.tf_runner_server_member }
  }
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.services[each.value.service].name
  role     = "roles/run.invoker"
  member   = each.value.member
}

# Serverless Git (when deployed): Cloud Run invoker only. The app-level read-only class is GIT_SERVER_READONLY_INVOKERS
# (step B); the job SA is never in GIT_SERVER_ALLOWED_INVOKERS (read and write).
resource "google_cloud_run_v2_service_iam_member" "tf_runner_git_server_invoker" {
  count    = local.tf_runner_git_enabled ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.git_server[0].name
  role     = "roles/run.invoker"
  member   = local.tf_runner_job_member
}

# ------------------------------------------------------------------------------
# 6. Vending (the broker): signBlob as ITSELF for record signatures (re-RT R1; precedent qa_sandbox.tf
#    gateway_self_sign_blob). Only when vending runs as sa-project-provisioner: with the rollback lever it runs as
#    sa-castor-developer, which already holds this grant on itself (gateway_self_sign_blob) and which the broker
#    refuses as a shared identity (R9).
# ------------------------------------------------------------------------------
resource "google_service_account_iam_member" "vending_self_sign_blob" {
  count              = var.vending_runs_as_provisioner ? 1 : 0
  service_account_id = google_service_account.agents["sa-project-provisioner"].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = google_service_account.agents["sa-project-provisioner"].member
}

# Vending act-as on the job SA, ONLY if Phase 0 shows that running the job with overrides needs it (plan §4). Default
# off; scripts/check-install-iam.sh accepts exactly this one act-as grant on a runner SA.
resource "google_service_account_iam_member" "vending_act_as_tf_applier" {
  count              = var.tf_runner_vending_act_as ? 1 : 0
  service_account_id = google_service_account.tf_runners[local.tf_runner_job_account_id].name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${local.vending_sa_email}"
}
