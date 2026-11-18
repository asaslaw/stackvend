terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_cloud_scheduler_job" "job" {
  project     = var.project_id
  region      = var.region
  name        = "${var.project_id}-${var.job_name_suffix}"
  description = "Scheduled cron job managed by StackVend"
  schedule    = var.schedule
  time_zone   = var.time_zone

  http_target {
    http_method = var.http_method
    uri         = var.target_uri

    dynamic "oidc_token" {
      for_each = var.service_account_email != "" ? [1] : []
      content {
        service_account_email = var.service_account_email
        # SCHEDULING-CRON-AUDIENCE: null leaves the attribute unset, so the token's audience stays the target URI.
        audience = var.audience
      }
    }
  }

  lifecycle {
    # SCHEDULING-CRON-AUDIENCE: an audience is carried by the OIDC token only; without a service account there is no
    # token, so a set audience would be dropped silently. Fail the plan instead.
    precondition {
      condition     = var.audience == null || var.service_account_email != ""
      error_message = "scheduling-cron: audience is set but service_account_email is empty; the job sends no OIDC token, so the audience would be ignored. Set service_account_email or leave audience null."
    }
  }
}
