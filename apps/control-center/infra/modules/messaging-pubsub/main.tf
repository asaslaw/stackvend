terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_pubsub_topic" "topic" {
  project      = var.project_id
  name         = "${var.project_id}-${var.topic_name_suffix}"
  kms_key_name = var.kms_key_name # lane 14 PR-0b: CMEK for regulated profiles (null = Google-managed)
}

resource "google_pubsub_topic" "dead_letter" {
  count        = var.enable_dead_letter ? 1 : 0
  project      = var.project_id
  name         = "${var.project_id}-${var.topic_name_suffix}-dlq"
  kms_key_name = var.kms_key_name
}

resource "google_pubsub_subscription" "subscription" {
  count                      = var.enable_subscription ? 1 : 0
  project                    = var.project_id
  name                       = "${google_pubsub_topic.topic.name}-sub"
  topic                      = google_pubsub_topic.topic.name
  ack_deadline_seconds       = var.ack_deadline_seconds
  message_retention_duration = var.message_retention_duration

  # StackVend WORKLOAD-SUB-NO-EXPIRY (owner 10-28): never expire from inactivity. Pub/Sub's default deletes a
  # subscription after 31 days without activity (as SUB-NO-EXPIRY fixed for the platform's own subscriptions).
  expiration_policy {
    ttl = ""
  }

  dynamic "dead_letter_policy" {
    for_each = var.enable_dead_letter ? [1] : []
    content {
      dead_letter_topic     = google_pubsub_topic.dead_letter[0].id
      max_delivery_attempts = 5
    }
  }

  # StackVend PUSH-SUB-RENDER (owner 10-28): with `push` set (platform-rendered from the typed intent, never an AI
  # string) the subscription pushes to the workload's own Cloud Run service with an OIDC token; null = pull, unchanged.
  dynamic "push_config" {
    for_each = var.push == null ? [] : [var.push]
    content {
      push_endpoint = push_config.value.endpoint
      oidc_token {
        service_account_email = push_config.value.service_account_email
        audience              = push_config.value.audience
      }
    }
  }
}

resource "google_pubsub_topic_iam_member" "publisher" {
  count   = var.workload_sa_email != "" ? 1 : 0
  project = var.project_id
  topic   = google_pubsub_topic.topic.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${var.workload_sa_email}"
}

resource "google_pubsub_subscription_iam_member" "subscriber" {
  count        = var.enable_subscription && var.workload_sa_email != "" ? 1 : 0
  project      = var.project_id
  subscription = google_pubsub_subscription.subscription[0].name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${var.workload_sa_email}"
}
