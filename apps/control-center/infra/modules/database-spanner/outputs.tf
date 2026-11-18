output "instance_id" {
  description = "The ID of the created Cloud Spanner instance."
  value       = google_spanner_instance.instance.name
}

output "instance_state" {
  description = "The operational state of the Spanner instance."
  value       = google_spanner_instance.instance.state
}

output "database_id" {
  description = "The name of the database created, if any."
  value       = length(google_spanner_database.database) > 0 ? google_spanner_database.database[0].name : ""
}

output "database_state" {
  description = "The operational state of the Spanner database, if any."
  value       = length(google_spanner_database.database) > 0 ? google_spanner_database.database[0].state : ""
}
