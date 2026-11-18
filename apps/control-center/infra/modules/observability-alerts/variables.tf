variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "alert_name_suffix" {
  description = "Suffix for the alert policy display name (e.g. '5xx-errors', 'high-latency')"
  type        = string
  default     = "high-error-rate"
}

variable "filter" {
  description = "Cloud Monitoring metric filter expression"
  type        = string
  default     = "metric.type=\"run.googleapis.com/request_count\" resource.type=\"cloud_run_revision\" metric.labels.response_code_class=\"5xx\""
}

variable "duration" {
  description = "Duration over which metric violation is measured (e.g. '300s')"
  type        = string
  default     = "300s"
}

variable "threshold_value" {
  description = "Threshold value above which the alert triggers"
  type        = number
  default     = 5
}

variable "notification_channels" {
  description = "List of Cloud Monitoring notification channel IDs"
  type        = list(string)
  default     = []
}
