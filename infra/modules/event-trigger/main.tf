terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_eventarc_trigger" "trigger" {
  project  = var.project_id
  location = var.region
  name     = "${var.project_id}-${var.trigger_name_suffix}"

  matching_criteria {
    attribute = "type"
    value     = var.event_type
  }

  destination {
    cloud_run_service {
      service = var.destination_run_service_name
      region  = var.region
    }
  }

  service_account = var.service_account_email
}
