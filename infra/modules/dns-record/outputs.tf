output "record_name" {
  description = "Name of the DNS record"
  value       = google_dns_record_set.record.name
}

output "record_type" {
  description = "Type of the DNS record"
  value       = google_dns_record_set.record.type
}
