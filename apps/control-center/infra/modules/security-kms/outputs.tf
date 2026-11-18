output "keyring_id" {
  description = "Resource ID of the KMS Keyring"
  value       = google_kms_key_ring.keyring.id
}

output "crypto_key_id" {
  description = "Resource ID of the KMS CryptoKey"
  value       = google_kms_crypto_key.key.id
}

# Lane 14 PR-0b: the CMEK input of every platform-wired golden module. Known at plan time; a consumer that
# references it waits for the key and every service-agent grant (depends_on), so no resource is created with the
# key before its service agent may use it.
output "crypto_key_name" {
  description = "Cloud KMS resource name of the CryptoKey (known at plan time)"
  value       = local.crypto_key_name
  depends_on = [
    google_kms_crypto_key.key,
    google_kms_crypto_key_iam_member.encrypter_decrypter,
    google_kms_crypto_key_iam_member.service_agents,
  ]
  precondition {
    condition     = google_kms_crypto_key.key.id == local.crypto_key_name
    error_message = "The created CryptoKey id differs from the computed crypto_key_name."
  }
}
