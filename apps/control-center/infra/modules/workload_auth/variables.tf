variable "project_id" {
  description = "The target GCP project ID where Identity Platform will be configured."
  type        = string
}

variable "oauth_client_id" {
  description = "Google OAuth 2.0 Client ID (injected from Central Platform Secret Manager)."
  type        = string
}

variable "oauth_client_secret" {
  description = "Google OAuth 2.0 Client Secret (injected from Central Platform Secret Manager)."
  type        = string
  sensitive   = true
}

variable "enable_email_password_auth" {
  description = "Whether to enable Email and Password sign-in."
  type        = bool
  default     = true
}

variable "enable_anonymous_auth" {
  description = "Whether to enable anonymous guest sign-in."
  type        = bool
  default     = false
}

variable "additional_authorized_domains" {
  description = "List of additional web domains authorized for OAuth redirects (e.g. custom domains, Cloud Run URL)."
  type        = list(string)
  default     = []
}
