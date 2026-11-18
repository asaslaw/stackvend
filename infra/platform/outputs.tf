output "artifact_registry_docker_repo" {
  description = "The Artifact Registry Docker repository URI for pushing Castor container images."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.castor_docker_repo.name}"
}

output "firestore_database_name" {
  description = "The name of the Firestore database storing Castor state."
  value       = google_firestore_database.castor_state_db.name
}

output "workload_tfstate_bucket_name" {
  description = "The central GCS bucket storing Terraform remote state files for all dynamic Castor workloads."
  value       = data.google_storage_bucket.workload_tfstate_bucket.name
}

output "pubsub_topics" {
  description = "The Pub/Sub topics provisioned for multi-agent event dispatching."
  value = {
    spec_intake         = google_pubsub_topic.spec_intake_events.id
    autonomous_refactor = google_pubsub_topic.autonomous_refactor_events.id
    runtime_incident    = google_pubsub_topic.runtime_incident_events.id
    workflow_callbacks  = google_pubsub_topic.workflow_callbacks.id
    dead_letter_queue   = google_pubsub_topic.castor_dlq.id
  }
}

output "cloud_run_service_urls" {
  description = "The HTTPS URLs for all provisioned Project Castor microservices."
  value = {
    for k, v in google_cloud_run_v2_service.services : k => v.uri
  }
}

output "agent_service_account_emails" {
  description = "The IAM Service Account email addresses for each agent persona."
  value = {
    for k, v in google_service_account.agents : k => v.email
  }
}

output "workflows_main_orchestrator_name" {
  description = "The resource name of the Main Orchestrator Workflow."
  value       = module.workflows.main_orchestrator_name
}

output "workflows_sre_remediation_name" {
  description = "The resource name of the SRE Incident Remediation Workflow."
  value       = module.workflows.sre_remediation_name
}

# ------------------------------------------------------------------------------
# Control Center Access & Authentication Outputs (Plan 12)
# ------------------------------------------------------------------------------
output "control_center_url" {
  description = "URL to access the Project Castor Product Control Center UI."
  value       = google_cloud_run_v2_service.services["product-control-center-ui"].uri
}

output "access_instructions" {
  description = "Authentication guidance for accessing the Control Center UI."
  value = var.allow_unauthenticated ? (
    "Public Access: Open ${google_cloud_run_v2_service.services["product-control-center-ui"].uri} directly in any browser."
  ) : (
    var.enable_direct_iap ? (
      "Enterprise IAP Access: Open ${google_cloud_run_v2_service.services["product-control-center-ui"].uri} in Chrome. Sign in with your authorized corporate Google Workspace account (${join(", ", var.authorized_invoker_members)})."
    ) : (
      "CLI Proxy Access: Run 'gcloud run services proxy product-control-center-ui --port 8080 --project ${var.project_id}' and open http://localhost:8080 in Chrome or Firefox (Safari won't keep Secure cookies over http://localhost, so sign-in loops)."
    )
  )
}

# ------------------------------------------------------------------------------
# Lane 18 S0 / S0b (destructive-action guard prerequisites)
# ------------------------------------------------------------------------------
output "stackvend_managed_tag_value" {
  description = "Resource Manager tag value (tagValues/<id>) that marks projects vended by this install; set on vending as STACKVEND_MANAGED_TAG_VALUE. Empty when organization_id or the managed folder is unset (the guard then refuses every delete)."
  value       = local.managed_tag_value
}

output "stackvend_guard_database" {
  description = "Named Firestore database for provenance, destructive approvals and the ephemeral ledger (STACKVEND_GUARD_FIRESTORE_DATABASE)."
  value       = google_firestore_database.stackvend_guard.name
}

output "stackvend_runtime_service_accounts" {
  description = "Runtime identities after lane 18 S0 (vending = the only destructive executor; Control Center = DESTRUCTIVE_CALLERS / SANDBOX_TTL_CALLERS; cleaner = EPHEMERAL_TTL_CALLERS)."
  value = {
    vending         = local.vending_sa_email
    control_center  = local.cc_sa_email
    sandbox_cleaner = local.cleaner_sa_email
    other_services  = local.developer_sa_email
  }
}

output "stackvend_tf_runner_identity" {
  description = "FD-7L / FD-7L-n: the install's Terraform runner identity setting and the runner identities (tf_runner_identity.tf). dedicated_sa = false: both runners still run as sa-castor-developer (step A); true: step B."
  value = {
    mode                  = var.tf_runner_identity
    dedicated_sa          = var.tf_runner_dedicated_sa
    tf_applier_runtime    = local.tf_applier_runtime_sa
    tf_server_runtime     = lookup(local.service_runtime_sa, "mcp-terraform-server", local.developer_sa_email)
    tf_applier_sa         = local.tf_runner_job_sa_email
    tf_server_sa          = local.tf_runner_server_sa_email
    broker_sa             = local.vending_sa_email
    runner_members        = local.tf_runner_job_members
    server_members        = local.tf_runner_server_members
    runner_staging_bucket = google_storage_bucket.tf_runner_staging.name
  }
}

output "stackvend_platform_stamp" {
  description = "FD-4DA platform version stamp written on product-control-center-ui as service-level annotations (empty map = no stamp)."
  value       = local.platform_stamp_annotations
}

output "serverless_git_repo_bucket" {
  description = "The central GCS bucket storing bare repositories for Serverless Git."
  value       = length(google_storage_bucket.git_repos_bucket) > 0 ? google_storage_bucket.git_repos_bucket[0].name : ""
}

output "serverless_git_server_url" {
  description = "The HTTPS URL for the Serverless Git microservice."
  value       = length(google_cloud_run_v2_service.git_server) > 0 ? google_cloud_run_v2_service.git_server[0].uri : ""
}

