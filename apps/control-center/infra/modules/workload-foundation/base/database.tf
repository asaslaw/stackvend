# ==============================================================================
# STACKVEND: WORKLOAD FOUNDATION - FIRESTORE DATABASE
# ==============================================================================
# Provisions Google Cloud Firestore in Native mode with automated teardown safety.
# ==============================================================================

resource "google_firestore_database" "database" {
  project                  = var.project_id
  name                     = "(default)"
  location_id              = var.region
  type                     = "FIRESTORE_NATIVE"
  delete_protection_state  = var.firestore_delete_protection ? "DELETE_PROTECTION_ENABLED" : "DELETE_PROTECTION_DISABLED"
  deletion_policy          = "DELETE"
  depends_on               = [google_project_service.apis]

  # Lane 14 PR-0b: CMEK for regulated profiles (no block = Google-managed encryption). Set at creation only.
  dynamic "cmek_config" {
    for_each = var.kms_key_name != null ? [1] : []
    content {
      kms_key_name = var.kms_key_name
    }
  }
}
