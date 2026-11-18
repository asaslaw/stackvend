# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - GCE BASTION VARIABLES
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

variable "zone" {
  description = "Zone of the bastion VM (empty: the first zone of var.region in sorted order, RT14-35)"
  type        = string
  default     = ""
}

variable "machine_type" {
  description = "GCE Machine Type"
  type        = string
  default     = "e2-micro"
}

variable "boot_image" {
  description = "OS Boot Disk Image"
  type        = string
  default     = "debian-cloud/debian-12"
}

variable "network" {
  description = "VPC network name"
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "VPC subnetwork name (optional)"
  type        = string
  default     = ""
}

variable "startup_script" {
  description = "Startup script the VM runs at boot (the platform passes apps/<service>/startup.sh; null: none)"
  type        = string
  default     = null
}

variable "subnet_cidr" {
  description = "Own-subnet range: the platform IPAM fact var.subnet_cidr (never a literal); empty with no existing subnetwork: network / subnetwork as given"
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

variable "settings" {
  description = "Settings the startup script reads from instance metadata attributes (key -> value)"
  type        = map(string)
  default     = {}
}

variable "storage_buckets" {
  description = "Bucket names the bastion SA may read and write objects in (roles/storage.objectUser)"
  type        = list(string)
  default     = []
}

variable "pubsub_topics" {
  description = "Topic names the bastion SA may publish to (roles/pubsub.publisher)"
  type        = list(string)
  default     = []
}

variable "pubsub_subscriptions" {
  description = "Subscription names the bastion SA may pull from (roles/pubsub.subscriber)"
  type        = list(string)
  default     = []
}

variable "secrets" {
  description = "Secret ids the bastion SA may read (roles/secretmanager.secretAccessor)"
  type        = list(string)
  default     = []
}

variable "bigquery_datasets" {
  description = "Dataset ids the bastion SA may edit (roles/bigquery.dataEditor)"
  type        = list(string)
  default     = []
}
