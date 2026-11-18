terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_storage_bucket" "bucket" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.bucket_name_suffix}"
  location                    = var.region
  uniform_bucket_level_access = var.uniform_bucket_level_access
  force_destroy               = !var.prevent_destroy

  versioning {
    enabled = var.versioning_enabled
  }

  # Lane 14 PR-0b: default CMEK for regulated profiles (no block = Google-managed encryption).
  dynamic "encryption" {
    for_each = var.kms_key_name != null ? [1] : []
    content {
      default_kms_key_name = var.kms_key_name
    }
  }

  dynamic "lifecycle_rule" {
    for_each = var.lifecycle_delete_age_days > 0 ? [1] : []
    content {
      action {
        type = "Delete"
      }
      condition {
        age = var.lifecycle_delete_age_days
      }
    }
  }
}

resource "google_storage_bucket_iam_member" "workload_admin" {
  count  = var.workload_sa_email != "" ? 1 : 0
  bucket = google_storage_bucket.bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${var.workload_sa_email}"
}
