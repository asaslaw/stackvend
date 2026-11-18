# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - GKE AUTOPILOT OUTPUTS
# ==============================================================================

output "cluster_name" {
  description = "Name of the GKE Autopilot cluster"
  value       = google_container_cluster.autopilot.name
}

output "cluster_endpoint" {
  description = "Cluster Kubernetes control plane endpoint"
  value       = google_container_cluster.autopilot.endpoint
}

output "cluster_id" {
  description = "Resource ID of the GKE cluster"
  value       = google_container_cluster.autopilot.id
}

output "cluster_ca_certificate" {
  description = "Public certificate authority of the cluster control plane"
  value       = google_container_cluster.autopilot.master_auth[0].cluster_ca_certificate
  sensitive   = true
}
