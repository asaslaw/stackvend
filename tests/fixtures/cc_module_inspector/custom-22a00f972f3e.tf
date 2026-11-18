locals {
  push_endpoint = var.push_endpoint != "" ? var.push_endpoint : "${var.cloud_run_service_url}/api/v1/tasks/process"
}

resource "google_pubsub_topic" "test_events_inbound" {
  name = "test-events-inbound"

  labels = {
    environment = var.environment
  }
}

resource "google_storage_bucket" "event_payloads" {
  name                        = "${var.project_id}-event-payloads"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = 7
    }
  }

  labels = {
    environment = var.environment
  }
}

resource "google_pubsub_subscription" "test_events_worker_sub" {
  name  = "test-events-worker-sub"
  topic = google_pubsub_topic.test_events_inbound.name

  ack_deadline_seconds = 30

  push_config {
    push_endpoint = local.push_endpoint
  }

  labels = {
    environment = var.environment
  }
}

# stackvend: from infra/workload/variables.tf (IAC_ENGINEER)


variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "prod"
}

variable "cloud_run_service_url" {
  description = "The target Cloud Run service URL for push subscriptions"
  type        = string
  default     = "https://test-01-event-router-placeholder.a.run.app"
}

variable "push_endpoint" {
  description = "Explicit push endpoint URL for worker subscription"
  type        = string
  default     = ""
}

# stackvend: from infra/workload/outputs.tf (IAC_ENGINEER)
output "event_bucket_name" {
  description = "The name of the GCS bucket for event payloads"
  value       = google_storage_bucket.event_payloads.name
}

output "gcs_bucket_name" {
  description = "Canonical GCS bucket name alias for workload binding"
  value       = google_storage_bucket.event_payloads.name
}

output "pubsub_topic_name" {
  description = "The name of the inbound Pub/Sub topic"
  value       = google_pubsub_topic.test_events_inbound.name
}

output "pubsub_topic_id" {
  description = "The ID of the inbound Pub/Sub topic"
  value       = google_pubsub_topic.test_events_inbound.id
}

output "push_subscription_name" {
  description = "The name of the worker push subscription"
  value       = google_pubsub_subscription.test_events_worker_sub.name
}

output "push_subscription_id" {
  description = "The ID of the worker push subscription"
  value       = google_pubsub_subscription.test_events_worker_sub.id
}
