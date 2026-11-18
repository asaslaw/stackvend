output "cluster_id" {
  description = "The ID of the AlloyDB cluster."
  value       = google_alloydb_cluster.cluster.cluster_id
}

output "cluster_name" {
  description = "The resource name of the AlloyDB cluster."
  value       = google_alloydb_cluster.cluster.name
}

output "instance_id" {
  description = "The ID of the primary AlloyDB instance."
  value       = google_alloydb_instance.primary.instance_id
}

output "ip_address" {
  description = "The private IP address of the primary AlloyDB instance."
  value       = google_alloydb_instance.primary.ip_address
}

output "secret_id_password" {
  description = "Secret Manager secret_id holding the initial user's (postgres) password (read it at runtime; the password itself is never an output)"
  value       = google_secret_manager_secret.initial_user_password.secret_id
}
