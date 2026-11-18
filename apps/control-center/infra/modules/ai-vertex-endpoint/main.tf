# ==============================================================================
# STACKVEND: PARAMETERIZED MODULE - VERTEX AI ENDPOINT (TIER 2 STATEFUL)
# ==============================================================================
# Provisions a managed Google Cloud Vertex AI Endpoint for machine learning
# inference and foundation model serving.
# ==============================================================================

locals {
  endpoint_name = var.endpoint_name != "" ? var.endpoint_name : "endpoint-${replace(lower(var.product_id), "_", "-")}"
  display_name  = var.display_name != "" ? var.display_name : (var.product_id != "" ? "Endpoint for ${var.product_id}" : local.endpoint_name)

  default_labels = {
    managed_by = "castor-terraform"
    product_id = var.product_id
  }
}

resource "google_vertex_ai_endpoint" "endpoint" {
  project      = var.project_id
  location     = var.region
  name         = local.endpoint_name
  display_name = local.display_name
  description  = var.description
  network      = var.network

  dynamic "encryption_spec" {
    for_each = var.kms_key_name != null ? [1] : []
    content {
      kms_key_name = var.kms_key_name
    }
  }

  labels = merge(local.default_labels, var.labels)
}
