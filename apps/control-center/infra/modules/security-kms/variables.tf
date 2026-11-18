variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "location" {
  description = "KMS Keyring Location (e.g. 'us-central1' or 'global')"
  type        = string
  default     = "us-central1"
}

variable "keyring_name" {
  description = "Name suffix for the KMS Keyring"
  type        = string
  default     = "keyring"
}

variable "key_name" {
  description = "Name for the KMS CryptoKey"
  type        = string
  default     = "workload-cmek"
}

variable "rotation_period" {
  description = "Automated key rotation period in seconds (e.g. '7776000s' for 90 days)"
  type        = string
  default     = "7776000s"
}

variable "workload_sa_email" {
  description = "Workload service account email to grant encrypter/decrypter role"
  type        = string
  default     = ""
}

variable "service_agent_services" {
  description = "Google APIs whose service agents are granted roles/cloudkms.cryptoKeyEncrypterDecrypter on the key (e.g. artifactregistry.googleapis.com). Default: none."
  type        = list(string)
  default     = []
  # TI-5-G3b: only agents this module can grant (identity API, or the dedicated table in main.tf); anything else
  # would plan and then fail at apply with an empty member.
  validation {
    condition = alltrue([for s in var.service_agent_services : contains([
      "aiplatform.googleapis.com", "alloydb.googleapis.com", "artifactregistry.googleapis.com",
      "container.googleapis.com", "firestore.googleapis.com", "pubsub.googleapis.com", "redis.googleapis.com",
      "run.googleapis.com", "secretmanager.googleapis.com", "spanner.googleapis.com", "sqladmin.googleapis.com",
      "storage.googleapis.com",
    ], s)])
    error_message = "service_agent_services: the module grants only aiplatform, alloydb, artifactregistry, container, firestore, pubsub, redis, run, secretmanager, spanner, sqladmin and storage (.googleapis.com)."
  }
}

variable "protection_level" {
  description = "Protection level of the key's versions: SOFTWARE (default) or HSM. Create-only: set it before the first apply."
  type        = string
  default     = "SOFTWARE"
  validation {
    condition     = contains(["SOFTWARE", "HSM"], var.protection_level)
    error_message = "protection_level must be SOFTWARE or HSM."
  }
}

variable "enable_apis" {
  description = "Enable cloudkms.googleapis.com and every service_agent_services API from this module (never disabled on destroy)."
  type        = bool
  default     = false
}
