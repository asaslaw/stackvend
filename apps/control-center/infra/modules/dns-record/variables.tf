variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "managed_zone" {
  description = "Name of the Google Cloud DNS managed zone"
  type        = string
}

variable "record_name" {
  description = "Fully qualified domain name (must end with a period, e.g. 'api.example.com.')"
  type        = string
}

variable "record_type" {
  description = "DNS record type (A, CNAME, TXT, etc.)"
  type        = string
  default     = "CNAME"
}

variable "ttl" {
  description = "Time to live (seconds)"
  type        = number
  default     = 300
}

variable "rrdatas" {
  description = "List of resource record data strings"
  type        = list(string)
}
