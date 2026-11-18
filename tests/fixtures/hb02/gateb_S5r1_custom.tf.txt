# Custom managed resources for Castor workload

# ------------------------------------------------------------------------------
# 1. Memorystore Redis Cache (Basic tier, 1 GB, VPC authorized network)
# ------------------------------------------------------------------------------
resource "google_redis_instance" "quote_cache" {
  name               = "quote-cache"
  tier               = "BASIC"
  memory_size_gb     = 1
  region             = var.region
  project            = var.project_id
  authorized_network = google_compute_network.vpc.id

  labels = var.labels

  depends_on = [google_project_service.apis]
}

# ------------------------------------------------------------------------------
# 2. BigQuery Analytics Dataset and Day-Partitioned Table
# ------------------------------------------------------------------------------
resource "google_bigquery_dataset" "quotes_analytics" {
  dataset_id                 = "quotes_analytics"
  friendly_name              = "Quotes Analytics"
  description                = "Analytics dataset for quote events and rollups"
  location                   = var.region
  project                    = var.project_id
  delete_contents_on_destroy = true

  labels = var.labels

  depends_on = [google_project_service.apis]
}

resource "google_bigquery_table" "quote_events" {
  dataset_id          = google_bigquery_dataset.quotes_analytics.dataset_id
  table_id            = "quote_events"
  project             = var.project_id
  deletion_protection = false

  time_partitioning {
    type = "DAY"
  }

  schema = jsonencode([
    {
      name = "quote_id"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "origin"
      type = "STRING"
      mode = "NULLABLE"
    },
    {
      name = "destination"
      type = "STRING"
      mode = "NULLABLE"
    },
    {
      name = "weight_kg"
      type = "FLOAT"
      mode = "NULLABLE"
    },
    {
      name = "price_usd"
      type = "FLOAT"
      mode = "NULLABLE"
    },
    {
      name = "created_at"
      type = "TIMESTAMP"
      mode = "NULLABLE"
    },
    {
      name = "event_type"
      type = "STRING"
      mode = "NULLABLE"
    },
    {
      name = "payload"
      type = "STRING"
      mode = "NULLABLE"
    }
  ])

  labels = var.labels
}

# ------------------------------------------------------------------------------
# 3. KMS-Encrypted GCS Bucket for Quote Documents
# ------------------------------------------------------------------------------
resource "google_storage_bucket" "quote_documents" {
  name                        = "quote-documents"
  project                     = var.project_id
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true

  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  labels = var.labels

  depends_on = [
    google_kms_crypto_key_iam_member.gcs_kms_encrypter_decrypter,
    google_project_service.apis
  ]
}

# ------------------------------------------------------------------------------
# 4. Cloud Tasks Queue: carrier-webhooks
# ------------------------------------------------------------------------------
resource "google_cloud_tasks_queue" "carrier_webhooks" {
  name     = "carrier-webhooks"
  location = var.region
  project  = var.project_id

  rate_limits {
    max_dispatches_per_second = 100
    max_concurrent_dispatches = 10
  }

  retry_config {
    max_attempts = 5
    min_backoff  = "1s"
    max_backoff  = "10s"
  }

  depends_on = [google_project_service.apis]
}

# ------------------------------------------------------------------------------
# 5. Cloud Scheduler Hourly Job
# ------------------------------------------------------------------------------
resource "google_cloud_scheduler_job" "hourly_rollup" {
  name             = "quote-hourly-rollup"
  description      = "Hourly scheduled trigger for quotes rollup aggregation"
  schedule         = "0 * * * *"
  time_zone        = "UTC"
  region           = var.region
  project          = var.project_id
  attempt_deadline = "320s"

  http_target {
    http_method = "POST"
    uri         = "https://${var.project_id}.run.app/internal/rollup"
    headers = {
      "Content-Type" = "application/json"
    }
    body = base64encode("{\"date\": null}")
  }

  depends_on = [google_project_service.apis]
}

# ------------------------------------------------------------------------------
# Canonical Outputs for Service Consumption
# ------------------------------------------------------------------------------
output "redis_host" {
  description = "IP address of the Memorystore Redis quote cache instance"
  value       = google_redis_instance.quote_cache.host
}

output "redis_port" {
  description = "Port of the Memorystore Redis quote cache instance"
  value       = google_redis_instance.quote_cache.port
}

output "bigquery_dataset_id" {
  description = "Identifier of the quotes_analytics BigQuery dataset"
  value       = google_bigquery_dataset.quotes_analytics.dataset_id
}

output "bigquery_table_id" {
  description = "Identifier of the quote_events BigQuery table"
  value       = google_bigquery_table.quote_events.table_id
}

output "gcs_bucket_name" {
  description = "Name of the CMEK-encrypted GCS bucket for quote documents"
  value       = google_storage_bucket.quote_documents.name
}

output "cloud_tasks_queue_name" {
  description = "Name of the Cloud Tasks queue for carrier webhooks"
  value       = google_cloud_tasks_queue.carrier_webhooks.name
}

output "cloud_tasks_queue_id" {
  description = "Full resource ID of the Cloud Tasks queue for carrier webhooks"
  value       = google_cloud_tasks_queue.carrier_webhooks.id
}

output "scheduler_job_name" {
  description = "Name of the hourly rollup Cloud Scheduler job"
  value       = google_cloud_scheduler_job.hourly_rollup.name
}

# stackvend: from infra/workload/main.tf (IAC_ENGINEER)

locals {
  required_services = [
    "compute.googleapis.com",
    "vpcaccess.googleapis.com",
    "cloudkms.googleapis.com",
    "storage.googleapis.com",
    "redis.googleapis.com",
    "cloudtasks.googleapis.com",
    "bigquery.googleapis.com",
    "run.googleapis.com",
    "iam.googleapis.com"
  ]
}

resource "google_project_service" "apis" {
  for_each           = toset(local.required_services)
  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

data "google_project" "current" {
  project_id = var.project_id
  depends_on = [google_project_service.apis]
}

resource "google_compute_network" "vpc" {
  name                    = "${var.workload_name}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
  description             = "Private VPC network for Castor workload"
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "workload_subnet" {
  name                     = "${var.workload_name}-subnet"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = "10.0.1.0/24"
  private_ip_google_access = true
  depends_on               = [google_project_service.apis]
}

resource "google_compute_subnetwork" "connector_subnet" {
  name          = "${var.workload_name}-connector-sub"
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.vpc.id
  ip_cidr_range = "10.8.0.0/28"
  depends_on    = [google_project_service.apis]
}

resource "google_vpc_access_connector" "connector" {
  name          = var.vpc_connector_name
  project       = var.project_id
  region        = var.region
  subnet {
    name = google_compute_subnetwork.connector_subnet.name
  }
  min_instances = 2
  max_instances = 3
  machine_type  = "e2-micro"
  depends_on    = [google_project_service.apis]
}

resource "google_kms_key_ring" "keyring" {
  name       = "${var.workload_name}-keyring"
  project    = var.project_id
  location   = var.region
  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key" "key" {
  name            = "${var.workload_name}-crypto-key"
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = "7776000s"
  labels          = var.labels

  lifecycle {
    prevent_destroy = false
  }
}

resource "google_kms_crypto_key_iam_member" "gcs_kms_encrypter_decrypter" {
  crypto_key_id = google_kms_crypto_key.key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@gs-project-accounts.iam.gserviceaccount.com"
}

# stackvend: from infra/workload/variables.tf (IAC_ENGINEER)


variable "workload_name" {
  type        = string
  description = "Base name prefix applied to infrastructure resources."
  default     = "castor-workload"
}

variable "vpc_connector_name" {
  type        = string
  description = "Name of the Serverless VPC Access connector (max 25 characters)."
  default     = "castor-connector"
}

# stackvend: from infra/workload/outputs.tf (IAC_ENGINEER)
output "network_id" {
  description = "The ID of the VPC network."
  value       = google_compute_network.vpc.id
}

output "network_name" {
  description = "The name of the VPC network."
  value       = google_compute_network.vpc.name
}

output "subnet_id" {
  description = "The ID of the primary workload subnet."
  value       = google_compute_subnetwork.workload_subnet.id
}

output "subnet_name" {
  description = "The name of the primary workload subnet."
  value       = google_compute_subnetwork.workload_subnet.name
}

output "connector_id" {
  description = "The ID of the Serverless VPC Access connector."
  value       = google_vpc_access_connector.connector.id
}

output "connector_name" {
  description = "The name of the Serverless VPC Access connector."
  value       = google_vpc_access_connector.connector.name
}

output "kms_key_ring_id" {
  description = "The ID of the Cloud KMS KeyRing."
  value       = google_kms_key_ring.keyring.id
}

output "kms_crypto_key_id" {
  description = "The ID of the Cloud KMS CryptoKey with 90-day rotation."
  value       = google_kms_crypto_key.key.id
}

output "kms_crypto_key_name" {
  description = "The name of the Cloud KMS CryptoKey."
  value       = google_kms_crypto_key.key.name
}
