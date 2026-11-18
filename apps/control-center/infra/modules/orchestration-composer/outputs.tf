output "environment_id" {
  description = "The ID of the Cloud Composer environment."
  value       = google_composer_environment.environment.id
}

output "environment_name" {
  description = "The name of the Cloud Composer environment."
  value       = google_composer_environment.environment.name
}

output "airflow_uri" {
  description = "The URI of the Apache Airflow Web UI."
  value       = google_composer_environment.environment.config[0].airflow_uri
}

output "gcs_bucket" {
  description = "The Cloud Storage prefix/bucket used by the environment."
  value       = google_composer_environment.environment.config[0].dag_gcs_prefix
}
