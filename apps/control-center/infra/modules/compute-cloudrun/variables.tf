# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - CLOUD RUN VARIABLES
# ==============================================================================

variable "project_id" {
  description = "Target GCP Child Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "product_id" {
  description = "Workload Product ID"
  type        = string
}

variable "service_name" {
  description = "Override name for Cloud Run service (defaults to product_id)"
  type        = string
  default     = ""
}

variable "service_account_email" {
  description = "Runtime service account email"
  type        = string
}

variable "container_image" {
  description = "Container image URL"
  type        = string
  default     = ""
}

variable "ingress" {
  description = "Ingress traffic configuration"
  type        = string
  default     = "INGRESS_TRAFFIC_ALL"
}

variable "allow_unauthenticated" {
  description = "Allow unauthenticated public access to the Cloud Run service"
  type        = bool
  default     = true
}

variable "enable_direct_iap" {
  description = "Whether to enable native Direct Identity-Aware Proxy (IAP) on Cloud Run when allow_unauthenticated is false"
  type        = bool
  default     = false
}

variable "authorized_invoker_members" {
  description = "List of authorized IAM members when unauthenticated access is disabled (e.g. ['domain:mycompany.com', 'serviceAccount:sa-caller@...'])"
  type        = list(string)
  default     = []

  # StackVend FD-4I (lane 19 L19-5a): exact "<kind>:<value>" members only. allUsers / allAuthenticatedUsers (with or
  # without a prefix), unprefixed strings and other kinds fail at plan; public access is allow_unauthenticated only.
  validation {
    condition = alltrue([
      for m in var.authorized_invoker_members :
      length(split(":", m)) >= 2
      && contains(["user", "group", "serviceAccount", "domain"], split(":", m)[0])
      && length(join(":", slice(split(":", m), 1, length(split(":", m))))) > 0
      && !contains(["allUsers", "allAuthenticatedUsers"], join(":", slice(split(":", m), 1, length(split(":", m)))))
    ])
    error_message = "authorized_invoker_members entries must be user:, group:, serviceAccount: or domain: members; allUsers / allAuthenticatedUsers are never invokers of a private service."
  }
}

variable "cpu_limit" {
  description = "CPU limit for container"
  type        = string
  default     = "1000m"
}

variable "memory_limit" {
  description = "Memory limit for container"
  type        = string
  default     = "512Mi"
}

variable "health_check_path" {
  description = "HTTP path for startup health probe"
  type        = string
  default     = "/health"
}

variable "oauth_client_id" {
  description = "Google OAuth 2.0 Web Client ID"
  type        = string
  default     = ""
}

variable "firebase_api_key" {
  description = "Firebase Browser API Key"
  type        = string
  default     = ""
}

variable "firebase_auth_domain" {
  description = "Firebase Auth Domain"
  type        = string
  default     = ""
}

variable "min_instances" {
  description = "Minimum number of warm instances (0 = scale to zero, 1+ = keep hot/warm)"
  type        = number
  default     = 0
}

variable "max_instances" {
  description = "Maximum number of instances for auto-scaling"
  type        = number
  default     = 10
}

variable "cpu_idle" {
  description = "Whether CPU is throttled when idle (true = request-based billing, false = always allocated)"
  type        = bool
  default     = true
}

variable "env_vars" {
  description = "Custom environment variables to pass to the container"
  type        = map(string)
  default     = {}
}

variable "vpc_access_connector" {
  description = "The ID or name of the Serverless VPC Access connector (e.g. google_vpc_access_connector.<name>.id)"
  type        = string
  default     = ""
}

variable "vpc_egress" {
  description = "VPC egress traffic routing policy: PRIVATE_RANGES_ONLY or ALL_TRAFFIC"
  type        = string
  default     = "PRIVATE_RANGES_ONLY"
}

variable "encryption_key" {
  description = "Cloud KMS CryptoKey resource name for the service's customer-managed encryption (CMEK), in the service's region. null = Google-managed encryption."
  type        = string
  default     = null
}

variable "project_number" {
  description = "IAP-GATE-KNOWN-MEMBER: the workload project's number, set by the platform render for a Direct IAP service so the IAP agent's invoker member is known at plan. Empty = the module reads it with its own data source."
  type        = string
  default     = ""

  validation {
    condition     = var.project_number == "" || can(regex("^[0-9]+$", var.project_number))
    error_message = "project_number must be the numeric project number (or empty)."
  }
}

variable "push_service_accounts" {
  description = "PUSH-TO-PRIVATE: the service accounts this workload's own Pub/Sub push subscriptions to this service sign their OIDC tokens with, keyed by a stable platform label (keys known at plan; values may be computed). A private service admits exactly these: the IAP accessor role with Direct IAP, run.invoker without it. Ignored for a public service. Rendered by the platform from the typed intent."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for e in values(var.push_service_accounts) : can(regex("^[a-z0-9-]+@[a-z0-9.-]+\\.gserviceaccount\\.com$", e))])
    error_message = "push_service_accounts values must be bare service account emails (no member prefix)."
  }
}
