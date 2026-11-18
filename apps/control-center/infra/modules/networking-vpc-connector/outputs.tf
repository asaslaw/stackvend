# ==============================================================================
# STACKVEND: NETWORKING ARCHETYPE - SERVERLESS VPC ACCESS CONNECTOR OUTPUTS
# ==============================================================================

output "id" {
  description = "Connector ID (projects/PROJECT/locations/REGION/connectors/NAME). Pass it to compute-cloudrun's vpc_access_connector input."
  value       = google_vpc_access_connector.connector.id
}

output "name" {
  description = "Connector name"
  value       = google_vpc_access_connector.connector.name
}

output "self_link" {
  description = "Connector self link"
  value       = google_vpc_access_connector.connector.self_link
}

output "region" {
  description = "Region the connector serves"
  value       = google_vpc_access_connector.connector.region
}

output "ip_cidr_range" {
  description = "The /28 range the connector uses (the IPAM connector allocation)"
  value       = google_vpc_access_connector.connector.ip_cidr_range
}
