variable "project_id" {
  description = "The GCP project ID to deploy the Vertex AI Endpoint in."
  type        = string
}

variable "region" {
  description = "The GCP region to deploy the Vertex AI Endpoint in."
  type        = string
  default     = "us-central1"
}

variable "product_id" {
  description = "StackVend product/workload identifier for labeling and naming defaults."
  type        = string
  default     = ""
}

variable "endpoint_name" {
  description = "The resource name of the Vertex AI Endpoint. If empty, derived from product_id."
  type        = string
  default     = ""
}

variable "display_name" {
  description = "User-facing display name of the Vertex AI Endpoint."
  type        = string
  default     = ""
}

variable "description" {
  description = "The description of the Vertex AI Endpoint."
  type        = string
  default     = "Managed Vertex AI Endpoint provisioned by StackVend"
}

variable "network" {
  description = "Optional VPC network name/self-link for private service connect / direct peering."
  type        = string
  default     = null
}

variable "kms_key_name" {
  description = "Optional Cloud KMS CryptoKey resource name for customer-managed encryption."
  type        = string
  default     = null
}

variable "labels" {
  description = "Key-value labels to attach to the Vertex AI Endpoint."
  type        = map(string)
  default     = {}
}
