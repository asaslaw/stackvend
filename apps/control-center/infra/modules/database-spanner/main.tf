# ==============================================================================
# STACKVEND: PARAMETERIZED MODULE - CLOUD SPANNER (TIER 2 STATEFUL)
# ==============================================================================
# Provisions an enterprise Cloud Spanner instance and optional database with
# configurable processing units, CMEK support, and deletion protection defaults.
# ==============================================================================

# RT14-36: with `region` (the platform renders region = var.region) the instance configuration is regional-<region>,
# never a literal and never a model's choice. RT14-F2 (owner 11-14, option a): a call without `region` (classic,
# AI-written HCL) keeps its own `config` exactly as written, so an existing instance plans with no diff; the
# compliance plan gate still checks it for regulated profiles. No data source: a read inside a module called with
# depends_on = [module.foundation] is deferred to apply, which made `config` unknown at plan.
locals {
  config       = var.region != null ? "regional-${var.region}" : var.config
  instance_id  = var.instance_id != "" ? var.instance_id : "spanner-${replace(lower(var.product_id), "_", "-")}"
  display_name = var.display_name != "" ? var.display_name : "Spanner Instance for ${var.product_id}"

  default_labels = {
    managed_by = "castor-terraform"
    product_id = var.product_id
  }
}

resource "google_spanner_instance" "instance" {
  project          = var.project_id
  name             = local.instance_id
  config           = local.config
  display_name     = local.display_name
  processing_units = var.processing_units

  labels = merge(local.default_labels, var.labels)

  lifecycle {
    precondition {
      condition     = var.region != null ? (var.config == "" || var.config == local.config) : var.config != ""
      error_message = "database-spanner: pass region = var.region and leave config empty (RT14-36: the configuration is then regional-<region>, so the instance stays in the workload region). With region set, config must be empty or exactly regional-<region>; without region, config must be set."
    }
  }
}

resource "google_spanner_database" "database" {
  count               = var.database_name != "" ? 1 : 0
  project             = var.project_id
  instance            = google_spanner_instance.instance.name
  name                = var.database_name
  deletion_protection = var.deletion_protection
  ddl                 = var.ddl_statements

  # FD-4AZ-b1: only emit encryption_config when a CMEK key is given. An empty block (kms_key_name = null)
  # fails the provider's "one of kms_key_name/kms_key_names" check at plan time.
  dynamic "encryption_config" {
    for_each = var.kms_key_name != null ? [1] : []
    content {
      kms_key_name = var.kms_key_name
    }
  }
}
