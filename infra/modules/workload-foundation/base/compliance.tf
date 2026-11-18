# ==============================================================================
# STACKVEND: WORKLOAD FOUNDATION - REGULATED-PROFILE CONTROLS (LANE 14 PR-0b)
# ==============================================================================
# Inputs the platform sets only when the workload's stored compliance profile is
# regulated (HIPAA, FedRAMP, CJIS, PCI-DSS, EU). Their defaults leave a standard
# workload exactly as before: no CMEK, no project audit configuration.
# ==============================================================================

variable "kms_key_name" {
  description = "Cloud KMS CryptoKey resource name for the Artifact Registry repository and the Firestore database (CMEK). null = Google-managed encryption."
  type        = string
  default     = null
}

variable "enable_data_access_audit_logs" {
  description = "Turn on Data Access audit logs (data_access_log_types) for all services of the workload project."
  type        = bool
  default     = false
}

variable "data_access_log_types" {
  description = "Data Access audit log types turned on by enable_data_access_audit_logs (ADMIN_READ, DATA_READ, DATA_WRITE)."
  type        = list(string)
  default     = ["DATA_READ", "DATA_WRITE"]
}

# Authoritative for the allServices audit configuration of this (dedicated child) project.
resource "google_project_iam_audit_config" "data_access" {
  count   = var.enable_data_access_audit_logs ? 1 : 0
  project = var.project_id
  service = "allServices"

  dynamic "audit_log_config" {
    for_each = toset(var.data_access_log_types)
    content {
      log_type = audit_log_config.value
    }
  }
}
