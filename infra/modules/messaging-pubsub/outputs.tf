output "topic_name" {
  description = "Name of the Pub/Sub topic"
  value       = google_pubsub_topic.topic.name
}

output "topic_id" {
  description = "Resource ID of the Pub/Sub topic"
  value       = google_pubsub_topic.topic.id
}

output "subscription_name" {
  description = "Name of the subscription (if enabled)"
  value       = var.enable_subscription ? google_pubsub_subscription.subscription[0].name : ""
}

output "subscription_id" {
  description = "Resource ID of the subscription (if enabled)"
  value       = var.enable_subscription ? google_pubsub_subscription.subscription[0].id : ""
}

output "dead_letter_topic_id" {
  description = "Resource ID of the Dead Letter topic (if enabled)"
  value       = var.enable_dead_letter ? google_pubsub_topic.dead_letter[0].id : ""
}
