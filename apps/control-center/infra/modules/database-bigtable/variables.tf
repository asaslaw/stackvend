variable "project_id" {
  description = "The GCP project ID to deploy Cloud Bigtable in."
  type        = string
}

variable "product_id" {
  description = "StackVend product/workload identifier for labeling and naming defaults."
  type        = string
  default     = ""
}

variable "instance_id" {
  description = "The unique ID of the Cloud Bigtable instance. If empty, derived from product_id."
  type        = string
  default     = ""
}

variable "display_name" {
  description = "Descriptive display name for the Bigtable instance."
  type        = string
  default     = ""
}

variable "cluster_id" {
  description = "The unique ID of the primary Bigtable cluster. If empty, derived from instance_id."
  type        = string
  default     = ""
}

variable "zone" {
  description = "The GCP zone for the primary Bigtable cluster."
  type        = string
  default     = "us-central1-a"
}

variable "num_nodes" {
  description = "Number of nodes allocated to the Bigtable cluster. Default 1."
  type        = number
  default     = 1
}

variable "storage_type" {
  description = "Storage type for the cluster: 'SSD' (recommended for low latency) or 'HDD'."
  type        = string
  default     = "SSD"
}

variable "deletion_protection" {
  description = "Block OpenTofu from deleting the Bigtable instance (FD-4AZ: on by default). Set false explicitly only for an ephemeral instance you intend to destroy."
  type        = bool
  default     = true
}

variable "table_name" {
  description = "Optional initial Bigtable table to create."
  type        = string
  default     = ""
}

variable "column_families" {
  description = "Optional list of column family names to create in the initial table."
  type        = list(string)
  default     = []
}

variable "labels" {
  description = "Key-value labels to attach to the Bigtable instance."
  type        = map(string)
  default     = {}
}
