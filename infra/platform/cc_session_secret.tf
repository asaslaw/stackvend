# FD-4E: Control Center session-cookie signing key. Replaces the published default in config.py.
# Rotation: tofu apply -replace=random_password.cc_session_secret  (all users re-login once)
resource "random_password" "cc_session_secret" {
  length  = 64
  special = false
}

resource "google_secret_manager_secret" "cc_session_secret" {
  depends_on = [google_project_service.apis]
  project    = var.project_id
  secret_id  = "castor-cc-session-secret"

  replication {
    auto {}
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

resource "google_secret_manager_secret_version" "cc_session_secret" {
  secret      = google_secret_manager_secret.cc_session_secret.id
  secret_data = random_password.cc_session_secret.result
}

# Runtime SA of the Control Center (all services share it today; FD-4T will split personas).
resource "google_secret_manager_secret_iam_member" "cc_session_secret_accessor" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.cc_session_secret.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.agents["sa-castor-developer"].email}"
}
