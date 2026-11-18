# ==============================================================================
# STACKVEND: GOOGLE CLOUD WORKFLOWS ORCHESTRATION MODULE
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. Main Multi-Agent Orchestrator Workflow
# ------------------------------------------------------------------------------
resource "google_workflows_workflow" "main_orchestrator" {
  project         = var.project_id
  region          = var.region
  name            = "castor-main-orchestrator"
  description     = "Master multi-agent orchestration state machine coordinating Architect, Developer, DevOps, QA, and Release agents"
  service_account = var.orchestrator_service_account_email

  source_contents = file("${path.module}/../../../workflows/main_orchestrator.yaml")

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

# ------------------------------------------------------------------------------
# 2. SRE Incident Remediation Workflow
# ------------------------------------------------------------------------------
resource "google_workflows_workflow" "sre_remediation" {
  project         = var.project_id
  region          = var.region
  name            = "castor-sre-remediation"
  description     = "Automated incident RCA, ticket creation, and self-healing dispatch workflow"
  service_account = var.sre_service_account_email

  source_contents = file("${path.module}/../../../workflows/sre_remediation.yaml")

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

# ------------------------------------------------------------------------------
# 3. Workflows IAM Permissions to Invoke Cloud Run (Pub/Sub publish: topic-level, infra/platform)
# ------------------------------------------------------------------------------
resource "google_project_iam_member" "orchestrator_run_invoker" {
  project = var.project_id
  role    = "roles/run.invoker"
  member  = "serviceAccount:${var.orchestrator_service_account_email}"
}

# FD-4AS-c (owner 10-20): no project-level roles/pubsub.publisher here any more. The orchestrator workflow publishes
# only to the dead-letter topic and the SRE workflow only to spec-intake-events; both hold topic-level grants in
# infra/platform/pubsub_publishers.tf.

resource "google_project_iam_member" "orchestrator_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${var.orchestrator_service_account_email}"
}

resource "google_project_iam_member" "sre_run_invoker" {
  project = var.project_id
  role    = "roles/run.invoker"
  member  = "serviceAccount:${var.sre_service_account_email}"
}

resource "google_project_iam_member" "sre_workflow_invoker" {
  project = var.project_id
  role    = "roles/workflows.invoker"
  member  = "serviceAccount:${var.sre_service_account_email}"
}
