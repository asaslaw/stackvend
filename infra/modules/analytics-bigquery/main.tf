terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_bigquery_dataset" "dataset" {
  project                    = var.project_id
  dataset_id                 = var.dataset_id
  location                   = var.region
  delete_contents_on_destroy = var.delete_contents_on_destroy
  description                = "Serverless BigQuery dataset managed by StackVend"

  # Lane 14 PR-0b: default CMEK for the dataset's tables (no block = Google-managed encryption).
  dynamic "default_encryption_configuration" {
    for_each = var.kms_key_name != null ? [1] : []
    content {
      kms_key_name = var.kms_key_name
    }
  }
}

resource "google_bigquery_dataset_access" "workload_editor" {
  count         = var.workload_sa_email != "" ? 1 : 0
  project       = var.project_id
  dataset_id    = google_bigquery_dataset.dataset.dataset_id
  role          = "roles/bigquery.dataEditor"
  user_by_email = var.workload_sa_email
}
