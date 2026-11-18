# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - EVENT WORKER (PUBSUB + CLOUD RUN JOB)
# ==============================================================================
# Provisions an asynchronous event processing worker backed by Google Cloud Pub/Sub
# and a Cloud Run Job execution engine.
# ==============================================================================

locals {
  # EXP-4: name_suffix (optional) tells several event workers of one workload apart. Null or empty keeps the
  # product-only names; a suffix is appended to the job, topic and subscription names as "-<suffix>".
  name_base = replace(var.product_id, "_", "-")
  name_stem = var.name_suffix == null || var.name_suffix == "" ? local.name_base : "${local.name_base}-${var.name_suffix}"
}

resource "google_pubsub_topic" "events" {
  project      = var.project_id
  name         = "events-${local.name_stem}"
  kms_key_name = var.kms_key_name # lane 14 PR-0b: CMEK for regulated profiles (null = Google-managed)
}

resource "google_pubsub_subscription" "worker_sub" {
  project              = var.project_id
  name                 = "worker-sub-${local.name_stem}"
  topic                = google_pubsub_topic.events.name
  ack_deadline_seconds = 60
}

resource "google_cloud_run_v2_job" "worker" {
  project             = var.project_id
  name                = "worker-${local.name_stem}"
  location            = var.region
  deletion_protection = false

  template {
    task_count = 1

    template {
      service_account = var.service_account_email
      encryption_key  = var.kms_key_name

      containers {
        image = var.container_image

        resources {
          limits = {
            cpu    = var.cpu_limit
            memory = var.memory_limit
          }
        }

        env {
          name  = "PROJECT_ID"
          value = var.project_id
        }
        # StackVend CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV (owner 11-10): the project variable Google client libraries and
        # most generated code read (Cloud Run sets none). This module takes no caller env, so the name is never doubled.
        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.project_id
        }
        env {
          name  = "TOPIC_ID"
          value = google_pubsub_topic.events.id
        }
      }
    }
  }
}
