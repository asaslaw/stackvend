variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "instance_name_suffix" {
  description = "Suffix for the Redis instance name (e.g. 'cache', 'session')"
  type        = string
  default     = "cache"
}

variable "tier" {
  description = "Service tier (BASIC or STANDARD_HA)"
  type        = string
  default     = "BASIC"
}

variable "memory_size_gb" {
  description = "Redis memory size in GiB"
  type        = number
  default     = 1
}

variable "authorized_network" {
  description = "VPC Network ID authorized to connect to Redis"
  type        = string
  default     = "default"
}

variable "transit_encryption_mode" {
  description = "In-transit encryption mode (SERVER_AUTHENTICATION or DISABLED)"
  type        = string
  default     = "SERVER_AUTHENTICATION"
}

variable "auth_enabled" {
  description = "Enable Redis AUTH password authentication"
  type        = bool
  default     = true
}

variable "kms_key_name" {
  description = "Cloud KMS CryptoKey resource name (CMEK) for the instance, in the instance's region. The Memorystore service agent needs roles/cloudkms.cryptoKeyEncrypterDecrypter on it. null = Google-managed encryption."
  type        = string
  default     = null
}
