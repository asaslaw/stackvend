variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "queue_name_suffix" {
  description = "Suffix for the Cloud Tasks queue name (e.g. 'webhooks', 'background')"
  type        = string
  default     = "tasks"
}

variable "max_dispatches_per_second" {
  description = "Maximum dispatch rate per second"
  type        = number
  default     = 100
}

variable "max_concurrent_dispatches" {
  description = "Maximum number of concurrent tasks dispatched"
  type        = number
  default     = 50
}

variable "max_attempts" {
  description = "Maximum retry attempts before sending to DLQ"
  type        = number
  default     = 5
}

variable "workload_sa_email" {
  description = "Workload service account email to grant enqueuer role"
  type        = string
  default     = ""
}
