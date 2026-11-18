# ==============================================================================
# STACKVEND: PARAMETERIZED MODULE - CLOUD BIGTABLE (TIER 2 STATEFUL)
# ==============================================================================
# Provisions an enterprise Cloud Bigtable instance, cluster, and optional initial
# table with column families.
# ==============================================================================

locals {
  instance_id  = var.instance_id != "" ? var.instance_id : "bigtable-${replace(lower(var.product_id), "_", "-")}"
  display_name = var.display_name != "" ? var.display_name : "Bigtable Instance for ${var.product_id}"
  cluster_id   = var.cluster_id != "" ? var.cluster_id : "${local.instance_id}-c1"

  default_labels = {
    managed_by = "castor-terraform"
    product_id = var.product_id
  }
}

resource "google_bigtable_instance" "instance" {
  project             = var.project_id
  name                = local.instance_id
  display_name        = local.display_name
  deletion_protection = var.deletion_protection

  cluster {
    cluster_id   = local.cluster_id
    zone         = var.zone
    num_nodes    = var.num_nodes
    storage_type = var.storage_type
  }

  labels = merge(local.default_labels, var.labels)
}

resource "google_bigtable_table" "table" {
  count         = var.table_name != "" ? 1 : 0
  project       = var.project_id
  name          = var.table_name
  instance_name = google_bigtable_instance.instance.name

  dynamic "column_family" {
    for_each = toset(var.column_families)
    content {
      family = column_family.value
    }
  }
}
