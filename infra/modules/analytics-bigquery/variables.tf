variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "BigQuery Dataset Region/Location"
  type        = string
  default     = "us-central1"
}

variable "dataset_id" {
  description = "Dataset ID (letters, numbers, underscores)"
  type        = string
  default     = "analytics"
}

variable "delete_contents_on_destroy" {
  description = "Delete all tables when dataset is destroyed"
  type        = bool
  default     = true
}

variable "workload_sa_email" {
  description = "Workload service account email to grant dataEditor role"
  type        = string
  default     = ""
}

variable "kms_key_name" {
  description = "Cloud KMS CryptoKey resource name for the dataset's default table encryption (CMEK), in the dataset's location. The BigQuery encryption service account needs roles/cloudkms.cryptoKeyEncrypterDecrypter on it. null = Google-managed encryption."
  type        = string
  default     = null
}
