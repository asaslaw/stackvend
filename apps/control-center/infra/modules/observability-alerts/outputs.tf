output "alert_policy_id" {
  description = "Resource ID of the Cloud Monitoring alert policy"
  value       = google_monitoring_alert_policy.alert.id
}

output "alert_policy_name" {
  description = "Display name of the alert policy"
  value       = google_monitoring_alert_policy.alert.display_name
}
