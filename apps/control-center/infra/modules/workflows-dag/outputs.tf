output "workflow_name" {
  description = "Name of the Cloud Workflows state machine"
  value       = google_workflows_workflow.workflow.name
}

output "workflow_id" {
  description = "Resource ID of the Cloud Workflows state machine"
  value       = google_workflows_workflow.workflow.id
}
