# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - GCE BASTION OUTPUTS
# ==============================================================================

output "instance_id" {
  description = "Compute Engine instance ID"
  value       = google_compute_instance.bastion.instance_id
}

output "instance_name" {
  description = "Compute Engine instance name"
  value       = google_compute_instance.bastion.name
}

output "instance_self_link" {
  description = "URI of the bastion instance"
  value       = google_compute_instance.bastion.self_link
}

output "bastion_sa_email" {
  description = "Service account email of the bastion instance"
  value       = google_service_account.bastion_sa.email
}
