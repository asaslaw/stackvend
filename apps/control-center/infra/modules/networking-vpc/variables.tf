# ==============================================================================
# STACKVEND: NETWORKING ARCHETYPE - ENTERPRISE VPC NETWORK VARIABLES
# ==============================================================================

variable "project_id" {
  description = "Target GCP Child Project ID"
  type        = string
}

variable "network_name" {
  description = "Name of the Virtual Private Cloud (VPC) network"
  type        = string
  default     = "main-vpc"
}

variable "region" {
  description = "Primary anchor GCP Region for the core subnetwork"
  type        = string
  default     = "us-central1"
}

variable "primary_subnet_cidr" {
  description = "IPv4 CIDR block for the primary regional subnetwork"
  type        = string
  default     = "10.10.0.0/24"
}

variable "additional_regions" {
  description = "Map of secondary GCP regions to their respective subnet CIDR ranges (e.g., {'us-east4' = '10.20.0.0/24', 'us-west1' = '10.30.0.0/24'})"
  type        = map(string)
  default     = {}
}

variable "enable_private_service_access" {
  description = "Whether to reserve an internal IP range and configure Private Services Access (PSA) peering for managed databases (Cloud SQL, Redis, AlloyDB)"
  type        = bool
  default     = true
}

variable "psa_prefix_length" {
  description = "Prefix length of the IP range reserved for Private Services Access (default /16 supports 65,536 internal IP addresses)"
  type        = number
  default     = 16
}

variable "psa_address" {
  description = "Network address of the Private Services Access range (with psa_prefix_length), from the platform IPAM; null lets Google choose the range"
  type        = string
  default     = null
  validation {
    condition     = var.psa_address == null || can(cidrhost("${var.psa_address}/32", 0))
    error_message = "psa_address must be an IPv4 network address (the platform IPAM range), or null."
  }
}

variable "enable_nat" {
  description = "Whether to provision regional Cloud Routers and Cloud NAT gateways for outbound internet egress ($0 idle cost when false)"
  type        = bool
  default     = false
}

variable "enable_flow_logs" {
  description = "Whether to enable VPC Flow Logs on created subnetworks"
  type        = bool
  default     = false
}
