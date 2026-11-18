# ==============================================================================
# STACKVEND: PARAMETERIZED MODULE - CLOUD COMPOSER (TIER 2 STATEFUL)
# ==============================================================================
# Provisions a managed Cloud Composer (Apache Airflow) environment with
# parameterized sizing and maintenance policies.
# ==============================================================================

locals {
  environment_name = var.environment_name != "" ? var.environment_name : "composer-${replace(lower(var.product_id), "_", "-")}"

  default_labels = {
    managed_by = "castor-terraform"
    product_id = var.product_id
  }
}

resource "google_composer_environment" "environment" {
  project  = var.project_id
  region   = var.region
  name     = local.environment_name

  config {
    environment_size = var.environment_size

    software_config {
      image_version = var.image_version
    }

    node_config {
      service_account = var.service_account
    }
  }

  labels = merge(local.default_labels, var.labels)
}
