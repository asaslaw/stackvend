output "instance_id" {
  description = "The ID of the Cloud Bigtable instance."
  value       = google_bigtable_instance.instance.name
}

output "cluster_id" {
  description = "The ID of the Bigtable cluster."
  value       = local.cluster_id
}

output "table_id" {
  description = "The ID of the created Bigtable table, if any."
  value       = length(google_bigtable_table.table) > 0 ? google_bigtable_table.table[0].name : ""
}
