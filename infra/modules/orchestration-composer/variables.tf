variable "project_id" {
  description = "The GCP project ID to deploy Cloud Composer in."
  type        = string
}

variable "region" {
  description = "The GCP region to host the Cloud Composer environment."
  type        = string
  default     = "us-central1"
}

variable "product_id" {
  description = "StackVend product/workload identifier for labeling and naming defaults."
  type        = string
  default     = ""
}

variable "environment_name" {
  description = "The name of the Cloud Composer environment. If empty, derived from product_id."
  type        = string
  default     = ""
}

variable "environment_size" {
  description = "The size of the Cloud Composer 2 environment: 'ENVIRONMENT_SIZE_SMALL', 'ENVIRONMENT_SIZE_MEDIUM', or 'ENVIRONMENT_SIZE_LARGE'."
  type        = string
  default     = "ENVIRONMENT_SIZE_SMALL"
}

variable "image_version" {
  description = "The version of the Airflow image to use. Defaults to null (latest Composer 2 image)."
  type        = string
  default     = null
}

variable "service_account" {
  description = "Optional custom service account for Composer workers. If null, uses default compute service account."
  type        = string
  default     = null
}

variable "labels" {
  description = "Key-value labels to attach to the Cloud Composer environment."
  type        = map(string)
  default     = {}
}
