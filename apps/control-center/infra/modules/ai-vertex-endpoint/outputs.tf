output "endpoint_id" {
  description = "The ID of the Vertex AI Endpoint."
  value       = google_vertex_ai_endpoint.endpoint.id
}

output "endpoint_name" {
  description = "The name of the Vertex AI Endpoint."
  value       = google_vertex_ai_endpoint.endpoint.name
}
