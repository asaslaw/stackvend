# ==============================================================================
# STACKVEND: WORKLOAD AUTHENTICATION MODULE (IDENTITY PLATFORM / FIREBASE)
# ==============================================================================
# Automates Google Cloud Identity Platform provisioning and Google IdP configuration
# for vended child projects using centralized or injected OAuth 2.0 credentials.
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

# ------------------------------------------------------------------------------
# 1. API Enablement: Identity Toolkit API
# ------------------------------------------------------------------------------
resource "google_project_service" "identitytoolkit" {
  project                    = var.project_id
  service                    = "identitytoolkit.googleapis.com"
  disable_on_destroy         = false
  disable_dependent_services = false
}

# ------------------------------------------------------------------------------
# 2. Identity Platform Configuration
# ------------------------------------------------------------------------------
resource "google_identity_platform_config" "auth_config" {
  depends_on = [google_project_service.identitytoolkit]
  project    = var.project_id

  sign_in {
    allow_duplicate_emails = false

    email {
      enabled           = var.enable_email_password_auth
      password_required = var.enable_email_password_auth
    }

    anonymous {
      enabled = var.enable_anonymous_auth
    }
  }

  authorized_domains = concat(
    [
      "localhost",
      "${var.project_id}.firebaseapp.com",
      "${var.project_id}.web.app",
    ],
    var.additional_authorized_domains
  )
}

# ------------------------------------------------------------------------------
# 3. Google OAuth 2.0 Identity Provider (IdP) Binding
# ------------------------------------------------------------------------------
resource "google_identity_platform_default_supported_idp_config" "google_idp" {
  depends_on    = [google_identity_platform_config.auth_config]
  project       = var.project_id
  idp_id        = "google.com"
  enabled       = true
  client_id     = var.oauth_client_id
  client_secret = var.oauth_client_secret
}
