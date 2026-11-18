output "trigger_name" {
  description = "Name of the Eventarc trigger"
  value       = google_eventarc_trigger.trigger.name
}

output "trigger_id" {
  description = "Resource ID of the Eventarc trigger"
  value       = google_eventarc_trigger.trigger.id
}
