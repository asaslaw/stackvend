# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - GCE WORKER OUTPUTS
# ==============================================================================

output "instance_template_self_link" {
  description = "Self-link of the instance template the launcher passes as sourceInstanceTemplate"
  value       = google_compute_instance_template.worker.self_link
}

output "instance_template_name" {
  description = "Name of the current instance template"
  value       = google_compute_instance_template.worker.name
}

output "instance_name_prefix" {
  description = "Launched instance names must start with this prefix (the launch grant is limited to it)"
  value       = local.instance_prefix
}

output "zone" {
  description = "Zone the launcher creates worker VMs in"
  value       = local.zone
}

output "service_account_email" {
  description = "Service account the worker VMs run as"
  value       = google_service_account.worker.email
}
