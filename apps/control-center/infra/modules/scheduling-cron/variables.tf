variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "job_name_suffix" {
  description = "Suffix for the cron job name (e.g. 'nightly-sync')"
  type        = string
  default     = "sync"
}

variable "schedule" {
  description = "Cron schedule expression (e.g. '0 2 * * *' for 2 AM daily)"
  type        = string
  default     = "0 0 * * *"
}

variable "time_zone" {
  description = "Time zone for cron schedule"
  type        = string
  default     = "UTC"
}

variable "target_uri" {
  description = "Target HTTP URI to invoke (e.g. Cloud Run service URL + '/jobs/sync')"
  type        = string
}

variable "http_method" {
  description = "HTTP method to invoke"
  type        = string
  default     = "POST"
}

variable "service_account_email" {
  description = "Service account email for OIDC token authorization"
  type        = string
  default     = ""
}

variable "audience" {
  description = "OIDC token audience (e.g. the exact audience constant the target service verifies). Null keeps the default: the target URI. Needs service_account_email."
  type        = string
  default     = null
  validation {
    condition     = var.audience == null ? true : (length(var.audience) > 0 && trimspace(var.audience) == var.audience)
    error_message = "audience must be null or a non-empty string without leading or trailing whitespace."
  }
}
