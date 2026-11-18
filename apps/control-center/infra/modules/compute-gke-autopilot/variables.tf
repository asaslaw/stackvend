# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - GKE AUTOPILOT VARIABLES
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

variable "network" {
  description = "VPC network name"
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "VPC subnetwork name (optional)"
  type        = string
  default     = ""
}

variable "cluster_name" {
  description = "Optional custom name for the GKE Autopilot cluster. If empty, derived from product_id."
  type        = string
  default     = ""
}

variable "database_encryption_key" {
  description = "Cloud KMS CryptoKey resource name for application-layer secrets encryption (CMEK), in the cluster's region. null = default encryption."
  type        = string
  default     = null
}
