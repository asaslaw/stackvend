# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - GKE AUTOPILOT (MANAGED KUBERNETES)
# ==============================================================================
# Provisions a Google-managed GKE Autopilot cluster with private nodes and
# deletion_protection = false for automated lifecycle management.
# ==============================================================================

resource "google_container_cluster" "autopilot" {
  project             = var.project_id
  name                = var.cluster_name != "" ? var.cluster_name : "gke-${replace(var.product_id, "_", "-")}"
  location            = var.region
  enable_autopilot    = true
  deletion_protection = false

  network    = var.network
  subnetwork = var.subnetwork != "" ? var.subnetwork : null

  ip_allocation_policy {}

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
  }

  # Lane 14 PR-0b: application-layer secrets encryption with a CMEK for regulated profiles (no block = default).
  dynamic "database_encryption" {
    for_each = var.database_encryption_key != null ? [1] : []
    content {
      state    = "ENCRYPTED"
      key_name = var.database_encryption_key
    }
  }
}
