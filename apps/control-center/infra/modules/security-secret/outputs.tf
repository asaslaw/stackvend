output "secret_id" {
  description = "Identifier of the secret"
  value       = google_secret_manager_secret.secret.secret_id
}

output "secret_name" {
  description = "Fully qualified resource name of the secret"
  value       = google_secret_manager_secret.secret.name
}

output "secret_version_id" {
  description = "Resource ID of the created version (if initial data was provided)"
  # FD-4CC: test the version's count, not the sensitive var.secret_data (the same value: count = 1 exactly when
  # secret_data != ""), so the id never takes the input's sensitive mark and the module also validates as a root.
  value = length(google_secret_manager_secret_version.version) > 0 ? google_secret_manager_secret_version.version[0].id : ""
}
