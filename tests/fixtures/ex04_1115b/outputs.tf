# ==============================================================================
# STACKVEND: WORKLOAD OUTPUTS
# ==============================================================================

output "workload_sa_email" {
  description = "Workload runtime service account email"
  value       = module.foundation.workload_sa_email
}

output "deployer_sa_email" {
  description = "CI/CD deployer service account email"
  value       = module.foundation.deployer_sa_email
}

output "wif_provider_name" {
  description = "Workload Identity Provider resource name"
  value       = module.foundation.wif_provider_name
}

output "docker_repo_id" {
  description = "Artifact Registry Docker repository ID"
  value       = module.foundation.docker_repo_id
}

output "database_name" {
  description = "Firestore database name"
  value       = module.foundation.database_name
}

output "cluster_name" {
  description = "GKE Autopilot cluster name"
  value       = module.compute.cluster_name
}

output "cluster_endpoint" {
  description = "GKE Autopilot cluster control plane endpoint"
  value       = module.compute.cluster_endpoint
}

