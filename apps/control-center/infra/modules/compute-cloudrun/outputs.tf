# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - CLOUD RUN OUTPUTS
# ==============================================================================

output "service_name" {
  description = "Name of the Cloud Run v2 service"
  value       = google_cloud_run_v2_service.app.name
}

output "service_uri" {
  description = "HTTPS URI of the deployed Cloud Run service"
  value       = google_cloud_run_v2_service.app.uri
}

output "service_id" {
  description = "Resource ID of the Cloud Run service"
  value       = google_cloud_run_v2_service.app.id
}

output "iap_enabled" {
  description = "Whether Direct IAP is enabled on the Cloud Run service"
  value       = (!var.allow_unauthenticated && var.enable_direct_iap)
}
