variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "secret_id" {
  description = "Secret identifier (e.g. 'stripe_api_key', 'db_password')"
  type        = string
}

variable "secret_data" {
  description = "Initial secret payload value (optional, can be populated out-of-band)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "workload_sa_email" {
  description = "Runtime service account email to grant secretAccessor role"
  type        = string
  default     = ""
}

variable "generate_initial_version" {
  description = "Create one random first version (64 letters and digits) for a value the workload itself makes and uses. Set by the platform on typed infrastructure; stable across applies"
  type        = bool
  default     = false
}
