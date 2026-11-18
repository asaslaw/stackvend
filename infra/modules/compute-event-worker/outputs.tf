# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - EVENT WORKER OUTPUTS
# ==============================================================================

output "job_name" {
  description = "Name of the Cloud Run v2 Job"
  value       = google_cloud_run_v2_job.worker.name
}

output "job_id" {
  description = "ID of the Cloud Run v2 Job"
  value       = google_cloud_run_v2_job.worker.id
}

output "topic_name" {
  description = "Pub/Sub Topic name"
  value       = google_pubsub_topic.events.name
}

output "topic_id" {
  description = "Pub/Sub Topic ID"
  value       = google_pubsub_topic.events.id
}

output "subscription_name" {
  description = "Pub/Sub Subscription name"
  value       = google_pubsub_subscription.worker_sub.name
}
