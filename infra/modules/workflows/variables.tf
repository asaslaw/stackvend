variable "project_id" {
  description = "The Google Cloud Project ID."
  type        = string
}

variable "region" {
  description = "The Google Cloud region for deploying workflows."
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "The deployment environment tier (e.g. prod, staging, dev)."
  type        = string
  default     = "prod"
}

variable "orchestrator_service_account_email" {
  description = "The IAM Service Account email used by the Main Orchestrator Workflow."
  type        = string
}

variable "sre_service_account_email" {
  description = "The IAM Service Account email used by the SRE Incident Remediation Workflow."
  type        = string
}

variable "service_urls" {
  description = "Map of Cloud Run service names to their live HTTPS URLs."
  type        = map(string)
}

variable "pubsub_topics" {
  description = "Map of provisioned Pub/Sub topic IDs."
  type        = map(string)
}
