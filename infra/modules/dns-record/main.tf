terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_dns_record_set" "record" {
  project      = var.project_id
  managed_zone = var.managed_zone
  name         = var.record_name
  type         = var.record_type
  ttl          = var.ttl
  rrdatas      = var.rrdatas
}
