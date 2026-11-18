output "dataset_id" {
  description = "Identifier of the BigQuery dataset"
  value       = google_bigquery_dataset.dataset.dataset_id
}

output "dataset_name" {
  description = "Fully qualified ID of the dataset"
  value       = google_bigquery_dataset.dataset.id
}
