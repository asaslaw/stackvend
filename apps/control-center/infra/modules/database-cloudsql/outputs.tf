output "instance_name" {
  description = "Name of the Cloud SQL instance"
  value       = google_sql_database_instance.instance.name
}

output "instance_connection_name" {
  description = "Connection name for Cloud SQL Auth Proxy socket (PROJECT:REGION:INSTANCE)"
  value       = google_sql_database_instance.instance.connection_name
}

output "private_ip_address" {
  description = "Private IP address of the instance on private_network_id (empty when the instance has no private IP)"
  value       = google_sql_database_instance.instance.private_ip_address
}

output "database_name" {
  description = "Name of the default logical database"
  value       = google_sql_database.database.name
}

output "db_user" {
  description = "Name of the database user"
  value       = google_sql_user.user.name
}

output "secret_id_password" {
  description = "Secret Manager secret_id holding the db_user password (read it at runtime; the password itself is never an output)"
  value       = google_secret_manager_secret.db_password.secret_id
}
