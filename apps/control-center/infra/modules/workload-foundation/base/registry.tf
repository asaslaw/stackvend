# ==============================================================================
# STACKVEND: WORKLOAD FOUNDATION - ARTIFACT REGISTRY
# ==============================================================================
# Provisions Docker container image repository for workload builds and images.
# ==============================================================================

resource "google_artifact_registry_repository" "docker_repo" {
  project       = var.project_id
  location      = var.region
  repository_id = replace(var.product_id, "_", "-")
  description   = "Docker container image repository for ${var.product_id}"
  format        = "DOCKER"
  kms_key_name  = var.kms_key_name # lane 14 PR-0b: CMEK for regulated profiles (null = Google-managed)
  depends_on    = [google_project_service.apis]
}
