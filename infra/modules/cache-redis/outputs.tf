output "instance_id" {
  description = "Identifier of the Redis instance"
  value       = google_redis_instance.cache.id
}

output "host" {
  description = "IP address of the Redis instance"
  value       = google_redis_instance.cache.host
}

output "port" {
  description = "Port number of the Redis instance"
  value       = google_redis_instance.cache.port
}

output "current_location_id" {
  description = "The zone where the instance is currently provisioned"
  value       = google_redis_instance.cache.current_location_id
}
