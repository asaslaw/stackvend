terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_redis_instance" "cache" {
  project                 = var.project_id
  region                  = var.region
  name                    = "${var.project_id}-${var.instance_name_suffix}"
  tier                    = var.tier
  memory_size_gb          = var.memory_size_gb
  authorized_network      = var.authorized_network
  transit_encryption_mode = var.transit_encryption_mode
  auth_enabled            = var.auth_enabled
  customer_managed_key    = var.kms_key_name # lane 14 PR-0b: CMEK for regulated profiles (null = Google-managed)
}
