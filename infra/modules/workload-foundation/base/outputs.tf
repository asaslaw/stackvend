# ==============================================================================
# STACKVEND: WORKLOAD FOUNDATION - BASE MODULE OUTPUTS
# ==============================================================================

output "workload_sa_email" {
  description = "Runtime service account email for the workload"
  value       = google_service_account.workload_sa.email
}

output "workload_sa_id" {
  description = "Runtime service account ID"
  value       = google_service_account.workload_sa.id
}

output "deployer_sa_email" {
  description = "CI/CD GitHub Actions deployer service account email (null when enable_github_actions_deploy is false)"
  value       = one(google_service_account.github_deployer[*].email)
}

output "wif_pool_name" {
  description = "Workload Identity Pool name (null when enable_github_actions_deploy is false)"
  value       = one(google_iam_workload_identity_pool.github_pool[*].name)
}

output "wif_provider_name" {
  description = "Workload Identity Provider resource name (null when enable_github_actions_deploy is false)"
  value       = one(google_iam_workload_identity_pool_provider.github_provider[*].name)
}

output "docker_repo_id" {
  description = "Artifact Registry Docker repository ID"
  value       = google_artifact_registry_repository.docker_repo.repository_id
}

output "database_name" {
  description = "Firestore database name"
  value       = google_firestore_database.database.name
}
