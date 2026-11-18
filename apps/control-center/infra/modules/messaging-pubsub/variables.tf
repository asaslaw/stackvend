variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "topic_name_suffix" {
  description = "Suffix for the Pub/Sub topic name (e.g. 'events', 'audit')"
  type        = string
  default     = "events"
}

variable "enable_subscription" {
  description = "Whether to create a pull subscription on this topic"
  type        = bool
  default     = true
}

variable "enable_dead_letter" {
  description = "Whether to create a Dead Letter Queue (DLQ) topic for failed messages"
  type        = bool
  default     = false
}

variable "ack_deadline_seconds" {
  description = "Subscription acknowledge deadline in seconds"
  type        = number
  default     = 20
}

variable "message_retention_duration" {
  description = "Message retention duration (e.g. '604800s' for 7 days)"
  type        = string
  default     = "604800s"
}

variable "workload_sa_email" {
  description = "Workload service account email to grant publisher/subscriber IAM"
  type        = string
  default     = ""
}

variable "kms_key_name" {
  description = "Cloud KMS CryptoKey resource name (CMEK) for the topic and its dead-letter topic. The Pub/Sub service agent needs roles/cloudkms.cryptoKeyEncrypterDecrypter on it. null = Google-managed encryption."
  type        = string
  default     = null
}

variable "push" {
  description = "PUSH-SUB-RENDER: push delivery for the subscription, rendered by the platform from the typed intent: the endpoint (the workload's own Cloud Run service URL plus a path), the service account that signs the OIDC token and the token audience (the service URL). null = pull subscription."
  type = object({
    endpoint              = string
    service_account_email = string
    audience              = string
  })
  default = null

  validation {
    condition     = var.push == null ? true : (startswith(var.push.endpoint, "https:") && var.push.service_account_email != "" && !startswith(var.push.service_account_email, "serviceAccount:"))
    error_message = "push.endpoint must be an https URL and push.service_account_email a bare service account email."
  }
}
