output "identity_platform_config_name" {
  description = "The resource name of the Identity Platform configuration."
  value       = google_identity_platform_config.auth_config.name
}

output "google_idp_name" {
  description = "The resource name of the Google IdP configuration."
  value       = google_identity_platform_default_supported_idp_config.google_idp.name
}

output "authorized_domains" {
  description = "The list of authorized domains for OAuth redirects."
  value       = google_identity_platform_config.auth_config.authorized_domains
}
