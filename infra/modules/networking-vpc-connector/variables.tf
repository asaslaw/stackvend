# ==============================================================================
# STACKVEND: NETWORKING ARCHETYPE - SERVERLESS VPC ACCESS CONNECTOR VARIABLES
# ==============================================================================
# region and connector_cidr have no default: the caller passes its var.region and
# the IPAM connector allocation (var.connector_cidr). AGENTS.md invariant 3.

variable "project_id" {
  description = "Target GCP child project ID"
  type        = string
}

variable "region" {
  description = "GCP region of the connector (the caller's var.region). Must be the region of the Cloud Run services that use it."
  type        = string

  validation {
    condition     = length(trimspace(var.region)) > 0
    error_message = "region must be the workload region (var.region of the caller)."
  }
}

variable "network" {
  description = "Name or self link of the VPC network the connector attaches to (for example networking-vpc's network_name output)."
  type        = string

  validation {
    condition     = length(trimspace(var.network)) > 0
    error_message = "network must be a non-empty VPC network name or self link."
  }
}

variable "connector_cidr" {
  description = "Unreserved /28 IPv4 range for the connector: the workload's IPAM connector allocation (var.connector_cidr). Must not overlap a subnet of the network."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.connector_cidr)) && can(cidrhost(var.connector_cidr, 0)) && try(split("/", var.connector_cidr)[1] == "28", false)
    error_message = "connector_cidr must be an IPv4 CIDR with a /28 prefix (the size Serverless VPC Access requires)."
  }

  validation {
    condition     = try(cidrhost(var.connector_cidr, 0) == split("/", var.connector_cidr)[0], false)
    error_message = "connector_cidr must be the network address of its /28 (host bits zero)."
  }
}

variable "name" {
  description = "Connector name: 2 to 25 characters, lowercase letters, digits and hyphens, starting with a letter and not ending with a hyphen. Unique per region in the project."
  type        = string
  default     = "vpc-connector"

  validation {
    condition     = can(regex("^[a-z][-a-z0-9]{0,23}[a-z0-9]$", var.name))
    error_message = "name must match ^[a-z][-a-z0-9]{0,23}[a-z0-9]$ (RFC 1123 label, at most 25 characters)."
  }
}

variable "machine_type" {
  description = "Machine type of the connector instances: f1-micro, e2-micro or e2-standard-4."
  type        = string
  default     = "e2-micro"

  validation {
    condition     = contains(["f1-micro", "e2-micro", "e2-standard-4"], var.machine_type)
    error_message = "machine_type must be one of f1-micro, e2-micro or e2-standard-4."
  }
}

variable "min_instances" {
  description = "Minimum number of connector instances (2 to 9). Must be lower than max_instances."
  type        = number
  default     = 2

  validation {
    condition     = var.min_instances >= 2 && var.min_instances <= 9 && floor(var.min_instances) == var.min_instances
    error_message = "min_instances must be a whole number from 2 to 9."
  }
}

variable "max_instances" {
  description = "Maximum number of connector instances (3 to 10). Must be greater than min_instances."
  type        = number
  default     = 3

  validation {
    condition     = var.max_instances >= 3 && var.max_instances <= 10 && floor(var.max_instances) == var.max_instances
    error_message = "max_instances must be a whole number from 3 to 10."
  }
}
