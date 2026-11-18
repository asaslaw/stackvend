terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_workflows_workflow" "workflow" {
  project         = var.project_id
  region          = var.region
  name            = "${var.project_id}-${var.workflow_name_suffix}"
  description     = "Workload orchestration workflow state machine managed by StackVend"
  service_account = var.service_account_email
  source_contents = var.source_contents
}
