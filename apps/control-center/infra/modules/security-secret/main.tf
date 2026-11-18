terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
    }
    random = {
      source = "hashicorp/random"
    }
  }
}

resource "google_secret_manager_secret" "secret" {
  project   = var.project_id
  secret_id = var.secret_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "version" {
  count       = var.secret_data != "" ? 1 : 0
  secret      = google_secret_manager_secret.secret.id
  secret_data = var.secret_data
}

# SECRET-INITIAL-VERSION (owner 11-10): a random first version for a value the workload itself makes and uses (a
# signing, HMAC or encryption key). Typed infrastructure sets generate_initial_version for a secret the architect's
# plan marks initial_value = "random" only when the workload repository does not hold that secret yet, and keeps it
# set once it was set; it never adds a version to a secret that already existed.
# - No keepers: the value is generated once and never changes on later applies.
# - ignore_changes = [secret_data]: even if random_password were ever replaced (state loss, a future length change),
#   the version is not replaced, so the key the app has used never rotates by accident.
# - deletion_policy = "ABANDON": removing it from the configuration leaves the version (and the key) in Secret
#   Manager instead of destroying it. Deleting the secret itself (or the project) still deletes every version.
# - The value is stored in the OpenTofu state (no write-only attributes on OpenTofu 1.9); it is never a module output.
resource "random_password" "initial" {
  count   = var.generate_initial_version ? 1 : 0
  length  = 64
  special = false
}

resource "google_secret_manager_secret_version" "generated" {
  count           = var.generate_initial_version ? 1 : 0
  secret          = google_secret_manager_secret.secret.id
  secret_data     = random_password.initial[0].result
  deletion_policy = "ABANDON"

  lifecycle {
    ignore_changes = [secret_data]
  }
}

resource "google_secret_manager_secret_iam_member" "accessor" {
  count     = var.workload_sa_email != "" ? 1 : 0
  project   = var.project_id
  secret_id = google_secret_manager_secret.secret.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.workload_sa_email}"
}
