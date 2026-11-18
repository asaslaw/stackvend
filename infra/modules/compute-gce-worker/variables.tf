# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - GCE WORKER VARIABLES
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

variable "worker_name" {
  description = "Topology service name of this worker (RFC 1123 label, <= 40 chars)"
  type        = string
}

variable "zone" {
  description = "Zone the launcher creates worker VMs in (empty: the first UP zone of the region)"
  type        = string
  default     = ""
}

variable "subnet_cidr" {
  description = "Own-subnet range: the platform IPAM fact var.subnet_cidr (never a literal); unused with an existing subnetwork"
  type        = string
  default     = ""
}

variable "use_existing_subnetwork" {
  description = "Join the workload's existing subnetwork (subnetwork_id) instead of creating a VPC + subnet"
  type        = bool
  default     = false
}

variable "subnetwork_id" {
  description = "Existing subnetwork id (projects/<p>/regions/<r>/subnetworks/<n>) when use_existing_subnetwork"
  type        = string
  default     = ""
}

variable "machine_type" {
  description = "GCE machine type"
  type        = string
  default     = "e2-micro"
}

variable "spot" {
  description = "Spot provisioning (deleted on preemption or after max_run_duration_seconds)"
  type        = bool
  default     = true
}

variable "max_run_duration_seconds" {
  description = "Spot workers only: seconds after which Compute Engine deletes a worker VM (default 86400 = 24 h; null = no bound; 30 to 10368000). Standard workers (spot = false) are never bounded"
  type        = number
  default     = 86400
  nullable    = true

  validation {
    condition = var.max_run_duration_seconds == null ? true : (
      var.max_run_duration_seconds >= 30 && var.max_run_duration_seconds <= 10368000 &&
      floor(var.max_run_duration_seconds) == var.max_run_duration_seconds
    )
    error_message = "compute-gce-worker: max_run_duration_seconds must be null or a whole number of seconds from 30 to 10368000 (120 days)."
  }
}

variable "boot_image" {
  description = "Boot disk image"
  type        = string
  default     = "debian-cloud/debian-12"
}

variable "disk_type" {
  description = "Boot disk type"
  type        = string
  default     = "pd-standard"
}

variable "disk_size_gb" {
  description = "Boot disk size in GB"
  type        = number
  default     = 10
}

variable "startup_script" {
  description = "Startup script of every VM launched from the template (default: power off at once)"
  type        = string
  default     = "#!/bin/bash\n# StackVend gce-worker: no worker script was provided; power off.\npoweroff\n"
}

variable "env_vars" {
  description = "Settings the worker reads from instance metadata attributes (key -> value)"
  type        = map(string)
  default     = {}
}

variable "launcher_service_account_emails" {
  description = "Runtime service accounts allowed to launch this worker (conditional instanceAdmin + actAs on the worker SA)"
  type        = list(string)
  default     = []
}

variable "storage_buckets" {
  description = "Bucket names the worker SA may read and write objects in (roles/storage.objectUser)"
  type        = list(string)
  default     = []
}

variable "pubsub_topics" {
  description = "Topic names the worker SA may publish to (roles/pubsub.publisher)"
  type        = list(string)
  default     = []
}

variable "pubsub_subscriptions" {
  description = "Subscription names the worker SA may pull from (roles/pubsub.subscriber)"
  type        = list(string)
  default     = []
}

variable "secrets" {
  description = "Secret ids the worker SA may read (roles/secretmanager.secretAccessor)"
  type        = list(string)
  default     = []
}

variable "bigquery_datasets" {
  description = "Dataset ids the worker SA may edit (roles/bigquery.dataEditor)"
  type        = list(string)
  default     = []
}
