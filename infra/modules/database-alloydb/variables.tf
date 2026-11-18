variable "project_id" {
  description = "The GCP project ID to deploy AlloyDB in."
  type        = string
}

variable "region" {
  description = "The GCP region to host the AlloyDB cluster."
  type        = string
  default     = "us-central1"
}

variable "product_id" {
  description = "StackVend product/workload identifier for labeling and naming defaults."
  type        = string
  default     = ""
}

variable "cluster_id" {
  description = "The unique identifier of the AlloyDB cluster. If empty, derived from product_id."
  type        = string
  default     = ""
}

variable "instance_id" {
  description = "The unique identifier of the primary AlloyDB instance. If empty, derived from cluster_id."
  type        = string
  default     = ""
}

variable "network" {
  description = "VPC network ID (projects/PROJECT/global/networks/NAME, e.g. networking-vpc's network_id) with an active Private Services Access connection; depend on that module. Required: a bare network name is not accepted."
  type        = string
  default     = null

  validation {
    condition     = var.network == null || can(regex("(^|/)projects/[^/]+/global/networks/[^/]+$", var.network))
    error_message = "network must be a VPC network ID (projects/PROJECT/global/networks/NAME), not a bare name."
  }
}

variable "initial_user_password" {
  description = "Initial password for the cluster's initial user (postgres). If null, a random password is generated. Either way it is stored in Secret Manager (output secret_id_password)."
  type        = string
  sensitive   = true
  default     = null
}

variable "cpu_count" {
  description = "Number of vCPUs allocated to the primary instance (2, 4, 8, 16, etc.). Default 2."
  type        = number
  default     = 2
}

variable "kms_key_name" {
  description = "Optional Cloud KMS CryptoKey resource name for CMEK encryption."
  type        = string
  default     = null
}

variable "labels" {
  description = "Key-value labels to attach to the AlloyDB resources."
  type        = map(string)
  default     = {}
}

variable "workload_sa_email" {
  description = "Workload runtime service account email that grant_workload_secret_access gives read access to the password secret"
  type        = string
  default     = ""
}

variable "grant_workload_secret_access" {
  description = "Grant workload_sa_email roles/secretmanager.secretAccessor on the password secret (requires workload_sa_email)"
  type        = bool
  default     = false
}
