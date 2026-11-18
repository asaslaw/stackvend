variable "project_id" {
  description = "The GCP project ID to deploy the Cloud Spanner instance in."
  type        = string
}

variable "product_id" {
  description = "StackVend product/workload identifier for labeling and naming defaults."
  type        = string
  default     = ""
}

variable "instance_id" {
  description = "The unique ID of the Cloud Spanner instance. If empty, derived from product_id."
  type        = string
  default     = ""
}

variable "display_name" {
  description = "The descriptive display name for the Spanner instance."
  type        = string
  default     = ""
}

variable "region" {
  description = "Workload region; the instance configuration is regional-<region> (RT14-36). Pass region = var.region. Null: config is used as written (RT14-F2) and must be set."
  type        = string
  default     = null
}

variable "config" {
  description = "Leave empty and pass region: the configuration is then regional-<region> (RT14-36, data residency); with region set, any other value is refused at plan. Without region it is used as written."
  type        = string
  default     = ""
}

variable "processing_units" {
  description = "Compute capacity allocated in processing units (1000 processing units = 1 node). Default 100 for cost efficiency."
  type        = number
  default     = 100
}

variable "database_name" {
  description = "Optional initial database name to create within the instance."
  type        = string
  default     = ""
}

variable "ddl_statements" {
  description = "Optional DDL statements to execute upon database creation."
  type        = list(string)
  default     = []
}

variable "deletion_protection" {
  description = "Block OpenTofu from deleting the Spanner database (FD-4AZ: on by default). Set false explicitly only for an ephemeral database you intend to destroy."
  type        = bool
  default     = true
}

variable "kms_key_name" {
  description = "Optional Cloud KMS CryptoKey resource name for CMEK encryption."
  type        = string
  default     = null
}

variable "labels" {
  description = "Key-value labels to attach to the Cloud Spanner instance."
  type        = map(string)
  default     = {}
}
