output "queue_name" {
  description = "Name of the Cloud Tasks queue"
  value       = google_cloud_tasks_queue.queue.name
}

output "queue_id" {
  description = "Resource ID of the Cloud Tasks queue"
  value       = google_cloud_tasks_queue.queue.id
}
