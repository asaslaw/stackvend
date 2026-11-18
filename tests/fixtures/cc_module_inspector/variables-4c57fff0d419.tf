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
  default     = "test-08-cloudsql-postgres"
}

variable "github_repo_full_name" {
  description = "Full GitHub repository name (owner/repo) for WIF authentication"
  type        = string
  default     = "example-org/castor-test-08-cloudsql-postgres"
}

variable "container_image" {
  description = "Container image URL"
  type        = string
  default     = ""
}

variable "oauth_client_id" {
  description = "Google OAuth 2.0 Web Client ID from host platform"
  type        = string
  default     = ""
}

variable "oauth_client_secret" {
  description = "Google OAuth 2.0 Client Secret from host platform"
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
  description = "List of authorized IAM members when unauthenticated access is disabled"
  type        = list(string)
  default     = []
}

variable "additional_apis" {
  description = "Extra GCP APIs requested by custom extensions"
  type        = list(string)
  default     = []
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

variable "env_vars" {
  description = "Custom environment variables to pass to the container"
  type        = map(string)
  default     = {}
}

variable "service_name" {
  description = "Workload primary service name"
  type        = string
  default     = "test-08-cloudsql-postgres"
}

variable "network" {
  description = "VPC network name"
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "VPC subnetwork name"
  type        = string
  default     = ""
}

variable "labels" {
  description = "Common labels to apply to all resources"
  type        = map(string)
  default     = {}
}

# Platform network facts (IPAM). Values are supplied in terraform.tfvars by the platform; reference
# these variables, never a CIDR literal.
variable "subnet_cidr" {
  description = "Workload subnet range allocated by the platform IPAM (platform-owned; never a literal)"
  type        = string
  validation {
    condition     = can(cidrnetmask(var.subnet_cidr))
    error_message = "subnet_cidr must be an IPv4 CIDR allocated by the platform IPAM."
  }
}

variable "connector_cidr" {
  description = "Serverless VPC Access connector range allocated by the platform IPAM (platform-owned; /28)"
  type        = string
  validation {
    condition     = can(cidrnetmask(var.connector_cidr))
    error_message = "connector_cidr must be an IPv4 CIDR allocated by the platform IPAM."
  }
}
