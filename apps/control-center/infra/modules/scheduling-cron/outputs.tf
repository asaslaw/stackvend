output "job_name" {
  description = "Name of the Cloud Scheduler job"
  value       = google_cloud_scheduler_job.job.name
}

output "job_id" {
  description = "Resource ID of the Cloud Scheduler job"
  value       = google_cloud_scheduler_job.job.id
}
