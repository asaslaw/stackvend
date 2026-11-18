terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_cloud_tasks_queue" "queue" {
  project  = var.project_id
  location = var.region
  name     = "${var.project_id}-${var.queue_name_suffix}"

  rate_limits {
    max_dispatches_per_second = var.max_dispatches_per_second
    max_concurrent_dispatches = var.max_concurrent_dispatches
  }

  retry_config {
    max_attempts = var.max_attempts
  }
}

resource "google_cloud_tasks_queue_iam_member" "enqueuer" {
  count    = var.workload_sa_email != "" ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_tasks_queue.queue.name
  role     = "roles/cloudtasks.enqueuer"
  member   = "serviceAccount:${var.workload_sa_email}"
}
