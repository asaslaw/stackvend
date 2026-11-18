output "main_orchestrator_id" {
  description = "The unique ID of the Main Orchestrator Workflow."
  value       = google_workflows_workflow.main_orchestrator.id
}

output "main_orchestrator_name" {
  description = "The resource name of the Main Orchestrator Workflow."
  value       = google_workflows_workflow.main_orchestrator.name
}

output "sre_remediation_id" {
  description = "The unique ID of the SRE Incident Remediation Workflow."
  value       = google_workflows_workflow.sre_remediation.id
}

output "sre_remediation_name" {
  description = "The resource name of the SRE Incident Remediation Workflow."
  value       = google_workflows_workflow.sre_remediation.name
}
