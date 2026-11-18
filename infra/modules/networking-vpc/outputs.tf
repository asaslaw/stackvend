# ==============================================================================
# STACKVEND: NETWORKING ARCHETYPE - ENTERPRISE VPC NETWORK OUTPUTS
# ==============================================================================

output "network_id" {
  description = "The unique identifier of the VPC network"
  value       = google_compute_network.vpc.id
}

output "network_name" {
  description = "The name of the VPC network"
  value       = google_compute_network.vpc.name
}

output "network_self_link" {
  description = "The URI of the VPC network"
  value       = google_compute_network.vpc.self_link
}

output "primary_subnetwork_id" {
  description = "The unique identifier of the primary regional subnetwork"
  value       = google_compute_subnetwork.primary.id
}

output "primary_subnetwork_name" {
  description = "The name of the primary regional subnetwork"
  value       = google_compute_subnetwork.primary.name
}

output "primary_subnetwork_cidr" {
  description = "The IPv4 CIDR range of the primary subnetwork"
  value       = google_compute_subnetwork.primary.ip_cidr_range
}

output "additional_subnetwork_ids" {
  description = "Map of secondary region names to their respective subnetwork IDs"
  value       = { for k, v in google_compute_subnetwork.additional : k => v.id }
}

output "psa_connection_id" {
  description = "Identifier of the Private Services Access peering connection (null if disabled)"
  value       = length(google_service_networking_connection.private_vpc_connection) > 0 ? google_service_networking_connection.private_vpc_connection[0].id : null
}
