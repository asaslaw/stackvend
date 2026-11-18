variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "bucket_name_suffix" {
  description = "Suffix for the bucket name (e.g. 'uploads', 'assets')"
  type        = string
  default     = "data"
}

variable "versioning_enabled" {
  description = "Enable object versioning"
  type        = bool
  default     = false
}

variable "uniform_bucket_level_access" {
  description = "Enforce uniform bucket-level access (Org Policy compliant)"
  type        = bool
  default     = true
}

variable "lifecycle_delete_age_days" {
  description = "Number of days before objects are automatically deleted (0 to disable)"
  type        = number
  default     = 0
}

variable "prevent_destroy" {
  description = "When true (FD-4AZ default), force_destroy is off: OpenTofu cannot delete the bucket while it still holds objects. Set false explicitly only for an ephemeral bucket."
  type        = bool
  default     = true
}

variable "workload_sa_email" {
  description = "Runtime service account email to grant storage.objectAdmin"
  type        = string
  default     = ""
}

variable "kms_key_name" {
  description = "Cloud KMS CryptoKey resource name for the bucket's default customer-managed encryption (CMEK), in the bucket's location. The Cloud Storage service agent needs roles/cloudkms.cryptoKeyEncrypterDecrypter on it. null = Google-managed encryption."
  type        = string
  default     = null
}
