variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "workflow_name_suffix" {
  description = "Suffix for the workflow resource name"
  type        = string
  default     = "pipeline"
}

variable "service_account_email" {
  description = "Service account email that executes the workflow steps"
  type        = string
}

variable "source_contents" {
  description = "YAML source definition for the workflow state machine"
  type        = string
  default     = "main:\n  steps:\n    - init:\n        return: 'ok'\n"
}
