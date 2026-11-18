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
  description = "Suffix for the Cloud SQL instance name (e.g. 'db', 'postgres')"
  type        = string
  default     = "pg-db"
}

variable "database_version" {
  description = "Database engine version (e.g. 'POSTGRES_16', 'MYSQL_8_0')"
  type        = string
  default     = "POSTGRES_16"
}

variable "tier" {
  description = "Machine tier (e.g. 'db-f1-micro', 'db-custom-2-7680')"
  type        = string
  default     = "db-f1-micro"
}

variable "database_name" {
  description = "Name of the initial logical database"
  type        = string
  default     = "app_db"
}

variable "db_user" {
  description = "Master database username"
  type        = string
  default     = "app_user"
}

variable "db_password" {
  description = "Optional caller-supplied password for db_user. If empty, a random 32-character password is generated. Either way it is stored in Secret Manager (output secret_id_password)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "deletion_protection" {
  description = "Block OpenTofu from deleting the Cloud SQL instance (FD-4AZ: on by default). Set false explicitly only for an ephemeral instance you intend to destroy."
  type        = bool
  default     = true
}

variable "private_network_id" {
  description = "VPC network ID or self-link (projects/PROJECT/global/networks/NAME) for the instance's private IP. The network must already have an active Private Services Access connection (networking-vpc creates one; depend on that module). Null = no private IP."
  type        = string
  default     = null

  validation {
    condition     = var.private_network_id == null || can(regex("(^|/)projects/[^/]+/global/networks/[^/]+$", var.private_network_id))
    error_message = "private_network_id must be a VPC network ID or self-link (projects/PROJECT/global/networks/NAME), or null."
  }
}

variable "enable_public_ip" {
  description = "Give the instance a public IPv4 address (off by default). Needed only when private_network_id is not set; connections still require TLS (ssl_mode)."
  type        = bool
  default     = false
}

variable "ssl_mode" {
  description = "Cloud SQL connection encryption: ENCRYPTED_ONLY (default: TLS required, no client certificate), TRUSTED_CLIENT_CERTIFICATE_REQUIRED (TLS plus a client certificate signed by the instance CA), or ALLOW_UNENCRYPTED_AND_ENCRYPTED."
  type        = string
  default     = "ENCRYPTED_ONLY"

  validation {
    condition     = contains(["ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED", "ALLOW_UNENCRYPTED_AND_ENCRYPTED"], var.ssl_mode)
    error_message = "ssl_mode must be ENCRYPTED_ONLY, TRUSTED_CLIENT_CERTIFICATE_REQUIRED or ALLOW_UNENCRYPTED_AND_ENCRYPTED."
  }
}

variable "workload_sa_email" {
  description = "Workload runtime service account email to grant cloudsql.client role"
  type        = string
  default     = ""
}

variable "grant_workload_secret_access" {
  description = "Grant workload_sa_email roles/secretmanager.secretAccessor on the database password secret (requires workload_sa_email)"
  type        = bool
  default     = false
}

variable "kms_key_name" {
  description = "Cloud KMS CryptoKey resource name (CMEK) for the instance, in the instance's region. The Cloud SQL service agent needs roles/cloudkms.cryptoKeyEncrypterDecrypter on it. Set at creation only. null = Google-managed encryption."
  type        = string
  default     = null
}
