output "gcs_bucket_name" {
  description = "Name of the CMEK-encrypted Cloud Storage bucket for quote documents."
  value       = google_storage_bucket.quote_documents.name
}

output "redis_host" {
  description = "Host IP address of the Memorystore Redis cache instance."
  value       = google_redis_instance.quote_cache.host
}

output "redis_port" {
  description = "Port of the Memorystore Redis cache instance."
  value       = google_redis_instance.quote_cache.port
}

output "bigquery_dataset_id" {
  description = "Dataset ID for BigQuery analytics."
  value       = google_bigquery_dataset.quotes_analytics.dataset_id
}

output "bigquery_table_id" {
  description = "Table ID for BigQuery partitioned quote events."
  value       = google_bigquery_table.quote_events.table_id
}

output "cloud_tasks_queue_name" {
  description = "Name of the Cloud Tasks queue for carrier webhooks."
  value       = google_cloud_tasks_queue.carrier_webhooks.name
}

output "cloud_tasks_queue_id" {
  description = "Resource identifier of the Cloud Tasks queue for carrier webhooks."
  value       = google_cloud_tasks_queue.carrier_webhooks.id
}

output "kms_key_ring_name" {
  description = "Name of the KMS Key Ring."
  value       = google_kms_key_ring.quote_keyring.name
}

output "kms_crypto_key_id" {
  description = "ID of the KMS CryptoKey used for CMEK storage encryption."
  value       = google_kms_crypto_key.storage_key.id
}

output "scheduler_job_name" {
  description = "Name of the Cloud Scheduler hourly rollup job."
  value       = google_cloud_scheduler_job.hourly_rollup.name
}
