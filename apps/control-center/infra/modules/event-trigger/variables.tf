variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "trigger_name_suffix" {
  description = "Suffix for the Eventarc trigger name"
  type        = string
  default     = "gcs-trigger"
}

variable "event_type" {
  description = "Event type to match (e.g. 'google.cloud.storage.object.v1.finalized')"
  type        = string
  default     = "google.cloud.storage.object.v1.finalized"
}

variable "destination_run_service_name" {
  description = "Target Cloud Run service name"
  type        = string
}

variable "service_account_email" {
  description = "Service account email authorized to invoke the destination Cloud Run service"
  type        = string
}
