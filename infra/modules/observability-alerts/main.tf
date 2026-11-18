terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_monitoring_alert_policy" "alert" {
  project      = var.project_id
  display_name = "${var.project_id}-${var.alert_name_suffix}"
  combiner     = "OR"

  conditions {
    display_name = "Metric condition for ${var.alert_name_suffix}"
    condition_threshold {
      filter          = var.filter
      duration        = var.duration
      comparison      = "COMPARISON_GT"
      threshold_value = var.threshold_value

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = var.notification_channels
}
