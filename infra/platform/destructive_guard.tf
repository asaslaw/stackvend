# ==============================================================================
# Lane 18 S0 + S0b: destructive-action guard prerequisites (FD-4Q, FD-4T slice)
# Plan: docs/planning/wave2-lane18-destructive-guards-plan.md §3.0, §2.3 check 6, §2.4, §2.5 (F1-F4);
# lane 14 rev 3 I7 (read-only guard-DB grants). Report: docs/handoff/wave2-lane18-s0-report.md.
#
# S0 and S0b MUST land in one `apply.sh apply` (plan G4): a live tag with provenance still writable by
# every agent SA would let a forged provenance record on a tagged project pass the guard.
#
# Identities after this file (default vending_runs_as_provisioner = true):
#   project-repo-vending-service  -> sa-project-provisioner       (the only destructive executor)
#   product-control-center-ui     -> sa-stackvend-control-center  (new; DESTRUCTIVE_CALLERS / SANDBOX_TTL_CALLERS)
#   sandbox-garbage-collector-job -> sa-stackvend-sandbox-cleaner (new; EPHEMERAL_TTL_CALLERS)
#   everything else               -> sa-castor-developer          (unchanged; FD-4T splits the rest)
# Every grant below ADDS access; the only removals in this change are sa-castor-developer's folder
# projectDeleter/folderAdmin (main.tf) and the guard database carved out of the agents' project-wide
# datastore.user (main.tf agent_datastore_users). No component is removed or disabled.
# ==============================================================================

locals {
  # Per-install values only (AGENTS.md invariant 3): organization and folder come from the tfvars.
  managed_folder = var.castor_managed_workloads_folder_id == "" ? "" : (
    startswith(var.castor_managed_workloads_folder_id, "folders/") ? var.castor_managed_workloads_folder_id : "folders/${var.castor_managed_workloads_folder_id}"
  )
  organization = var.organization_id == "" ? "" : (
    startswith(var.organization_id, "organizations/") ? var.organization_id : "organizations/${var.organization_id}"
  )

  # Lane 18 F2: the tag key must live on the ORGANIZATION. A project-parented tag can only be bound to
  # resources inside that same project, so it could never mark a child project.
  managed_tag_scope_set = local.organization != "" && local.managed_folder != ""
  # Lane 18 v3 (owner 10-18, "install never fails"): creating an org tag key needs an org Tag Administrator.
  # scripts/apply.sh and bootstrap.sh run a read-only preflight (organizations.testIamPermissions) and pass
  # the result in; an explicit create_stackvend_managed_tag in the tfvars wins. null (plain tofu) = true.
  # Without the tag the guard refuses every delete (GUARD_UNCONFIGURED) and Settings warns.
  managed_tag_enabled = local.managed_tag_scope_set && var.create_stackvend_managed_tag != false
  managed_tag_key     = var.managed_tag_key_short_name != "" ? var.managed_tag_key_short_name : "stackvend-managed-${var.project_id}"
  # `.id` is "tagValues/<numeric id>" (google 6.50.0 id template "tagValues/{{name}}"); `.name` is the BARE
  # numeric id, which lane 18 S1 (_env_tag_value) rejects -> every guarded delete GUARD_UNCONFIGURED (RT F1).
  managed_tag_value = local.managed_tag_enabled ? google_tags_tag_value.stackvend_managed_true[0].id : ""

  developer_sa_email = google_service_account.agents["sa-castor-developer"].email
  vending_sa_key     = var.vending_runs_as_provisioner ? "sa-project-provisioner" : "sa-castor-developer"
  vending_sa_email   = google_service_account.agents[local.vending_sa_key].email
  cc_sa_email        = google_service_account.stackvend_personas["sa-stackvend-control-center"].email
  cleaner_sa_email   = google_service_account.stackvend_personas["sa-stackvend-sandbox-cleaner"].email
  # C10 (owner 11-07; pre-review F9/F11): least-privilege personas of the three jobs that took the Control Center's
  # machine work (main.tf local.cloud_run_jobs). None of them holds a secret, a project-wide run role or a child grant.
  sweeper_sa_email       = google_service_account.stackvend_personas["sa-stackvend-sandbox-sweeper"].email
  spend_sync_sa_email    = google_service_account.stackvend_personas["sa-stackvend-finops-sync"].email
  billing_drain_sa_email = google_service_account.stackvend_personas["sa-stackvend-billing-drain"].email

  # Runtime identity per Cloud Run service / job (unlisted = sa-castor-developer, as before).
  # FD-7L step B adds "mcp-terraform-server" = sa-stackvend-tf-server (tf_runner_identity.tf; {} in step A).
  service_runtime_sa = merge({
    "product-control-center-ui"    = local.cc_sa_email
    "project-repo-vending-service" = local.vending_sa_email
  }, local.tf_runner_service_runtime_sa)
  job_runtime_sa = {
    "sandbox-garbage-collector-job" = local.cleaner_sa_email
    "finops-spend-sync-job"         = local.spend_sync_sa_email
    "sandbox-workload-sweeper-job"  = local.sweeper_sa_email
    "billing-alert-drain-job"       = local.billing_drain_sa_email
  }

  # Folder roles that let an identity delete projects / administer the folder: vending only (plan F1).
  folder_destructive_holders = var.vending_runs_as_provisioner ? toset(["sa-project-provisioner"]) : toset(["sa-project-provisioner", "sa-castor-developer"])

  # S0b: the guard database. Exact resource name; the condition also matches document paths under it
  # ("<db>/documents/...") but never another database whose name merely starts with the same text.
  guard_db_id        = "stackvend-guard"
  guard_db_path      = "projects/${var.project_id}/databases/${local.guard_db_id}"
  guard_db_condition = "resource.name == \"${local.guard_db_path}\" || resource.name.startsWith(\"${local.guard_db_path}/\")"

  # Deterministic Cloud Run URL (same form the Control Center already gets in main.tf); a reference to
  # services["project-repo-vending-service"].uri would be a self-cycle inside that for_each.
  vending_service_url = "https://project-repo-vending-service-${data.google_project.platform_project.number}.${var.region}.run.app"

  # Lane 18 S1 env contract (apps/project-vending/destructive_guard.py, vending.py). Empty values are
  # omitted, so an unconfigured install fails closed (GUARD_UNCONFIGURED / CALLERS_UNCONFIGURED).
  # EPHEMERAL_PRODUCERS is deliberately absent: lane 13's producer SA does not exist yet (registration
  # answers 503 PRODUCER_UNCONFIGURED until it does, plan §4.4).
  guard_service_env = {
    # C10 (RT finding 1): the sandbox sweeper job is in SANDBOX_TTL_CALLERS only. Vending's decommission route accepts
    # DESTRUCTIVE_CALLERS + SANDBOX_TTL_CALLERS and lets a TTL-only caller request SANDBOX_TTL and nothing else; every
    # other destructive-class route (runner identity, managed tag, lifecycle) stays DESTRUCTIVE_CALLERS = the CC.
    "project-repo-vending-service" = {
      STACKVEND_MANAGED_TAG_VALUE        = local.managed_tag_value
      DESTRUCTIVE_CALLERS                = local.cc_sa_email
      SANDBOX_TTL_CALLERS                = join(",", [local.cc_sa_email, local.sweeper_sa_email])
      EPHEMERAL_TTL_CALLERS              = local.cleaner_sa_email
      VENDING_SERVICE_URL                = local.vending_service_url
      STACKVEND_GUARD_FIRESTORE_DATABASE = google_firestore_database.stackvend_guard.name
      # Lane 18 v3: informational only (Settings names the organization a Tag Administrator must act on).
      STACKVEND_ORGANIZATION_ID = local.organization
      # S1 delta (report B1): vending grants roles/owner on every project it CREATES to these members,
      # which keeps today's state (sa-castor-developer, the identity of tf-applier / mcp-terraform-server /
      # finops / MCPs, has been the implicit creator-owner of every child). Inert until S1 reads it.
      STACKVEND_CHILD_PROJECT_OWNER_MEMBERS = var.vending_runs_as_provisioner ? "serviceAccount:${local.developer_sa_email}" : ""
      # APPROVAL-CONSUME-VIA-VENDING (owner 11-07): who may consume an MCP action approval
      # (POST /approvals/{id}/consume): the kubernetes and agent-builder MCP servers' runtime SA.
      MCP_APPROVAL_CONSUMERS = local.developer_sa_email
    }
    "product-control-center-ui" = {
      STACKVEND_GUARD_FIRESTORE_DATABASE = google_firestore_database.stackvend_guard.name
    }
    # APPROVAL-CONSUME-VIA-VENDING: the MCP approval pre-check reads approvals where the Control Center mints them
    # (read-only: guard_db_readers.developer below; no new IAM). They already hold project roles/run.invoker
    # (main.tf agent_run_invokers), which covers the call to vending.
    "mcp-kubernetes-server" = {
      STACKVEND_GUARD_FIRESTORE_DATABASE = google_firestore_database.stackvend_guard.name
    }
    "mcp-agent-builder-server" = {
      STACKVEND_GUARD_FIRESTORE_DATABASE = google_firestore_database.stackvend_guard.name
    }
  }

  # Same contract for Cloud Run JOBS (main.tf google_cloud_run_v2_job.jobs). Lane 14 PR-6 SEAM(lane 18 S0b):
  # the sandbox cleaner reads vending's ephemeral ledger from the guard database (read-only grant,
  # guard_db_readers.cleaner). Without it the cleaner reads the default DB, which vending never writes.
  # Its REGION and VENDING_SERVICE_URL stay in main.tf (lane 14 PR-6 hunk); VENDING_SERVICE_URL there is
  # local.vending_service_url, the exact audience vending accepts (guard_service_env above).
  guard_job_env = {
    "sandbox-garbage-collector-job" = {
      STACKVEND_GUARD_FIRESTORE_DATABASE = google_firestore_database.stackvend_guard.name
    }
  }
}

# Non-blocking warning: without an organization and a managed folder, or when the installer is not an
# org Tag Administrator (create_stackvend_managed_tag = false, lane 18 v3), there is no tag, so the vending
# guard refuses every decommission and sandbox TTL delete (fail closed) and Settings shows a warning card.
check "stackvend_managed_tag_configured" {
  assert {
    condition     = local.managed_tag_enabled
    error_message = "No stackvend-managed tag is planned (organization_id or castor_managed_workloads_folder_id is empty, or create_stackvend_managed_tag = false because the installer is not a Tag Administrator on the organization). STACKVEND_MANAGED_TAG_VALUE stays unset, so every guarded delete refuses (GUARD_UNCONFIGURED) until a Tag Administrator re-runs scripts/apply.sh apply."
  }
}

# ------------------------------------------------------------------------------
# 1. Persona service accounts (FD-4T slice: Control Center and sandbox cleaner)
# ------------------------------------------------------------------------------
resource "google_service_account" "stackvend_personas" {
  for_each = {
    "sa-stackvend-control-center"  = "StackVend Control Center"
    "sa-stackvend-sandbox-cleaner" = "StackVend Sandbox Cleaner Job"
    "sa-stackvend-sandbox-sweeper" = "StackVend Sandbox Workload Sweeper Job"
    "sa-stackvend-finops-sync"     = "StackVend FinOps Spend Sync Job"
    "sa-stackvend-billing-drain"   = "StackVend Billing Alert Drain Job"
  }
  depends_on   = [google_project_service.apis]
  project      = var.project_id
  account_id   = each.key
  display_name = each.value
}

# ------------------------------------------------------------------------------
# 2. Control Center SA: exactly what apps/control-center uses today (host project), nothing in children
#    (its only child calls, the decommission fallback and the sandbox sweep, move into vending with S2).
# ------------------------------------------------------------------------------
resource "google_project_iam_member" "cc_project_roles" {
  for_each = toset([
    "roles/aiplatform.user",   # assistant + agent evaluator (Vertex AI)
    "roles/logging.viewer",    # workload / trace log views
    "roles/logging.logWriter", # parity with the agent SAs
    "roles/workflows.invoker", # HITL approval callbacks, execution list/cancel
    "roles/run.viewer",        # identity.py discovers its own service (IAP / bearer auth) + MCP URL lookup
  ])
  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${local.cc_sa_email}"
}

# FD-77 pre-wire (register row PREWIRE-MODEL-ARMOR-GRANT): the identities of the three intake surfaces may call the Model
# Armor sanitize methods on this project. The gateway and spec-ingestion both run as sa-castor-developer (neither is in
# local.service_runtime_sa), hence one entry for the two. Keys are fixed names so for_each is known on a new install.
# roles/modelarmor.user sanitizes with an existing template only: it cannot create or read templates.
resource "google_project_iam_member" "model_armor_users" {
  for_each = {
    "gateway-and-spec-ingestion" = local.developer_sa_email
    "control-center"             = local.cc_sa_email
  }
  project = var.project_id
  role    = "roles/modelarmor.user"
  member  = "serviceAccount:${each.value}"
}

# Default (and any other) database, never the guard database (that grant is below, S0b).
resource "google_project_iam_member" "persona_datastore_users" {
  for_each = {
    cc      = local.cc_sa_email
    cleaner = local.cleaner_sa_email       # sandbox_cleanups audit records
    sweeper = local.sweeper_sa_email       # C10: workloads / audit_logs / feature_requests / pipeline_executions
    spend   = local.spend_sync_sa_email    # C10: workloads spend fields
    drain   = local.billing_drain_sa_email # C10: workloads, billing_alerts, deliveries, enforcer run records
  }
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${each.value}"

  condition {
    title       = "stackvend-not-guard-db"
    description = "Every Firestore database except the stackvend-guard database (lane 18 S0b)"
    expression  = "!(${local.guard_db_condition})"
  }
}

resource "google_pubsub_topic_iam_member" "cc_spec_intake_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.spec_intake_events.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${local.cc_sa_email}"
}

resource "google_secret_manager_secret_iam_member" "cc_secret_accessors" {
  for_each = {
    session_secret = google_secret_manager_secret.cc_session_secret.secret_id # boot-critical SESSION_SECRET mount
    oauth_id       = google_secret_manager_secret.oauth_client_id.secret_id
    github_app_key = google_secret_manager_secret.github_app_private_key.secret_id
    gemini_api_key = google_secret_manager_secret.gemini_api_key.secret_id
  }
  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.cc_sa_email}"
}

# Workload state views + (until S2) the decommission-fallback / sweep state archive.
# SELFUP-STATE (owner 10-27): writes only under workloads/ (same condition as state_bucket_admins, main.tf).
resource "google_storage_bucket_iam_member" "cc_state_admin" {
  bucket = data.google_storage_bucket.workload_tfstate_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${local.cc_sa_email}"

  condition {
    title       = "stackvend-workload-state-only"
    description = "SELFUP-STATE: write only workload state (objects under workloads/), never the platform state"
    expression  = local.state_bucket_workload_write_condition
  }
  # Opus RT F1: create the conditional member before the unconditional one is removed.
  lifecycle {
    create_before_destroy = true
  }
}

# SELFUP-STATE: the Control Center keeps READ of the whole bucket, platform state included (the workload state
# view reads platform/ paths for the platform entry, routes/workloads.py fetch_workload_state_from_gcs).
resource "google_storage_bucket_iam_member" "cc_state_viewer" {
  bucket = data.google_storage_bucket.workload_tfstate_bucket.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${local.cc_sa_email}"
}

# Services the CC calls with an ID token. (vending + cleaner -> vending: S1 DESTRUCTIVE / TTL callers.)
resource "google_cloud_run_v2_service_iam_member" "persona_invokers" {
  for_each = {
    "cc:project-repo-vending-service"      = { service = "project-repo-vending-service", sa = local.cc_sa_email }
    "cc:mcp-terraform-server"              = { service = "mcp-terraform-server", sa = local.cc_sa_email }
    "cleaner:project-repo-vending-service" = { service = "project-repo-vending-service", sa = local.cleaner_sa_email }
    "sweeper:project-repo-vending-service" = { service = "project-repo-vending-service", sa = local.sweeper_sa_email }
  }
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.services[each.value.service].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${each.value.sa}"
}

resource "google_cloud_run_v2_service_iam_member" "cc_git_server_invoker" {
  count    = (var.deploy_git_server || upper(var.vcs_provider) == "SERVERLESS_GIT") ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.git_server[0].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${local.cc_sa_email}"
}

# ------------------------------------------------------------------------------
# 3. Sandbox cleaner SA (lane 14 I7): browser on the managed folder, invoker on vending, guard-DB read.
#    Plus the host READS today's cleaner code does (Cloud Run list, tfstate list). No delete permission:
#    no producer of its name patterns / sandboxes/ prefix exists (inventory), and lane 14 replaces those
#    sweeps with vending's EPHEMERAL_TTL executor (owner F5: no second deleter).
# ------------------------------------------------------------------------------
resource "google_project_iam_member" "cleaner_project_roles" {
  for_each = toset([
    "roles/run.viewer", # services.list (today's sweep) + services.get on vending (lane 14 G14)
    "roles/logging.logWriter",
  ])
  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${local.cleaner_sa_email}"
}

resource "google_storage_bucket_iam_member" "cleaner_state_viewer" {
  bucket = data.google_storage_bucket.workload_tfstate_bucket.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${local.cleaner_sa_email}"
}

# ------------------------------------------------------------------------------
# 3b. C10 (owner 11-07) job personas: exactly what each job's code uses (pre-review F9/F11). Their default-database
#     datastore.user is in persona_datastore_users, the sweeper's vending invoker in persona_invokers, the spend sync's
#     guard-DB read in guard_db_readers; the drain job's subscriber and enforcer-runner grants are job/subscription
#     scoped in main.tf section 9c / the billing subscription.
# ------------------------------------------------------------------------------
resource "google_project_iam_member" "c10_persona_project_roles" {
  for_each = {
    "sweeper:workflows"     = { role = "roles/workflows.invoker", sa = local.sweeper_sa_email } # cascade cancel (SAT-43)
    "sweeper:logging"       = { role = "roles/logging.logWriter", sa = local.sweeper_sa_email }
    "spend_sync:logging"    = { role = "roles/logging.logWriter", sa = local.spend_sync_sa_email }
    "billing_drain:logging" = { role = "roles/logging.logWriter", sa = local.billing_drain_sa_email }
  }
  project = var.project_id
  role    = each.value.role
  member  = "serviceAccount:${each.value.sa}"
}

# The spend sync reads workload state (services/finops_sync.py fetch_workload_state_from_gcs). Read only.
resource "google_storage_bucket_iam_member" "spend_sync_state_viewer" {
  bucket = data.google_storage_bucket.workload_tfstate_bucket.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${local.spend_sync_sa_email}"
}

# ------------------------------------------------------------------------------
# 4. Managed-folder READ grants (no write, no delete)
#    - vending + CC + cleaner: roles/browser (plan §3.0: ancestry, liens, project get)
#    - vending: tagViewer (direct tag bindings on legacy children it did not create)
#    - sa-castor-developer: browser + orgpolicy.policyViewer = the reads it loses with folderAdmin
#      (mcp-compliance-server harvests folder org policies; projects.get on children)
# ------------------------------------------------------------------------------
resource "google_folder_iam_member" "guard_folder_readers" {
  for_each = local.managed_folder == "" ? {} : {
    "vending-browser"       = { role = "roles/browser", member = "serviceAccount:${local.vending_sa_email}" }
    "vending-tagviewer"     = { role = "roles/resourcemanager.tagViewer", member = "serviceAccount:${local.vending_sa_email}" }
    "cc-browser"            = { role = "roles/browser", member = "serviceAccount:${local.cc_sa_email}" }
    "cleaner-browser"       = { role = "roles/browser", member = "serviceAccount:${local.cleaner_sa_email}" }
    "developer-browser"     = { role = "roles/browser", member = "serviceAccount:${local.developer_sa_email}" }
    "developer-orgpolicies" = { role = "roles/orgpolicy.policyViewer", member = "serviceAccount:${local.developer_sa_email}" }
  }
  depends_on = [google_project_service.apis]
  folder     = local.managed_folder
  role       = each.value.role
  member     = each.value.member
}

# Re-vend of a child sa-castor-developer created (status PROVISIONED/ACTIVE: vending.py re-runs billing
# link and API enablement) needs these on projects the provisioner does not own. sa-castor-developer
# had them as creator-owner. Same folder scope as the provisioner's existing projectDeleter.
resource "google_folder_iam_member" "vending_legacy_revend" {
  for_each   = local.managed_folder == "" ? toset([]) : toset(["roles/serviceusage.serviceUsageAdmin", "roles/billing.projectManager"])
  depends_on = [google_project_service.apis]
  folder     = local.managed_folder
  role       = each.key
  member     = "serviceAccount:${local.vending_sa_email}"
}

# ------------------------------------------------------------------------------
# 5. S0: IAM-gated ownership tag (plan F2, §2.3 check 6, §2.4)
# ------------------------------------------------------------------------------
resource "google_tags_tag_key" "stackvend_managed" {
  count       = local.managed_tag_enabled ? 1 : 0
  depends_on  = [google_project_service.cloudresourcemanager]
  parent      = local.organization
  short_name  = local.managed_tag_key
  description = "StackVend (${var.project_id}): projects vended by this install. Only its vending identity may bind the value; the destructive guard requires a DIRECT binding."

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_tags_tag_value" "stackvend_managed_true" {
  count       = local.managed_tag_enabled ? 1 : 0
  parent      = google_tags_tag_key.stackvend_managed[0].id
  short_name  = "true"
  description = "Bound by project-repo-vending-service at project creation (lane 18 S1)."

  lifecycle {
    prevent_destroy = true
  }
}

# tagUser on the VALUE, for the vending identity ONLY. No other principal in this configuration gets
# tagUser/tagAdmin anywhere (static test).
resource "google_tags_tag_value_iam_member" "stackvend_managed_vending_tag_user" {
  count     = local.managed_tag_enabled ? 1 : 0
  tag_value = google_tags_tag_value.stackvend_managed_true[0].name
  role      = "roles/resourcemanager.tagUser"
  member    = "serviceAccount:${local.vending_sa_email}"
}

# ------------------------------------------------------------------------------
# 6. S0b: named Firestore database for provenance, approvals and the ephemeral ledger. Collections are
#    created by code (workload_provenance, destructive_approvals, ephemeral_resources), never here.
# ------------------------------------------------------------------------------
resource "google_firestore_database" "stackvend_guard" {
  depends_on  = [google_project_service.apis]
  project     = var.project_id
  name        = local.guard_db_id
  location_id = var.region
  type        = "FIRESTORE_NATIVE"

  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"
  delete_protection_state           = "DELETE_PROTECTION_ENABLED"
  deletion_policy                   = "ABANDON"

  lifecycle {
    prevent_destroy = true
  }
}

# Writers: the Control Center (mints approvals) and vending (provenance, consumes approvals, ephemeral
# ledger). Every other agent SA's project-wide datastore.user excludes this database (main.tf).
resource "google_project_iam_member" "guard_db_writers" {
  for_each = {
    cc      = local.cc_sa_email
    vending = local.vending_sa_email
  }
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${each.value}"

  condition {
    title       = "stackvend-guard-db-only"
    description = "stackvend-guard database only (lane 18 S0b writers)"
    expression  = local.guard_db_condition
  }

  depends_on = [google_firestore_database.stackvend_guard]
}

# Readers (lane 14 rev 3 I7): read-only, so they cannot forge. The enforcer, digest, sentinel, rollback,
# scanner and gcloud/k8s/agent-builder MCP servers all run as sa-castor-developer until FD-4T; the
# sandbox cleaner has its own SA now.
resource "google_project_iam_member" "guard_db_readers" {
  for_each = {
    developer = local.developer_sa_email
    cleaner   = local.cleaner_sa_email
    spend     = local.spend_sync_sa_email # C10: vending's signed state provenance (services/runner_state.py)
  }
  project = var.project_id
  role    = "roles/datastore.viewer"
  member  = "serviceAccount:${each.value}"

  condition {
    title       = "stackvend-guard-db-read"
    description = "stackvend-guard database only, read-only (lane 14 I7)"
    expression  = local.guard_db_condition
  }

  depends_on = [google_firestore_database.stackvend_guard]
}
