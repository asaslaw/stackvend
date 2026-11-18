# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - EVENT WORKER VARIABLES
# ==============================================================================

variable "project_id" {
  description = "Target GCP Child Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "product_id" {
  description = "Workload Product ID"
  type        = string
}

variable "service_account_email" {
  description = "Runtime service account email"
  type        = string
}

variable "container_image" {
  description = "Container image URL"
  type        = string
  default     = ""
}

variable "cpu_limit" {
  description = "CPU limit for worker task"
  type        = string
  default     = "1000m"
}

variable "memory_limit" {
  description = "Memory limit for worker task"
  type        = string
  default     = "512Mi"
}

variable "kms_key_name" {
  description = "Cloud KMS CryptoKey resource name (CMEK) for the events topic and the worker job, in the worker's region. null = Google-managed encryption."
  type        = string
  default     = null
}

variable "name_suffix" {
  description = "Optional RFC 1123 label appended to the job, topic and subscription names as -<suffix>, so one workload can run several event workers. Null or empty keeps the product-only names."
  type        = string
  default     = null

  validation {
    condition     = var.name_suffix == null || can(regex("^([a-z0-9]([-a-z0-9]*[a-z0-9])?)?$", var.name_suffix))
    error_message = "name_suffix must be empty or an RFC 1123 label: lowercase letters, digits and hyphens, starting and ending with a letter or digit."
  }
}
