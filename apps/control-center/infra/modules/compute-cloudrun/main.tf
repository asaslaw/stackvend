# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - CLOUD RUN (SERVERLESS CONTAINER)
# ==============================================================================
# Enterprise-hardened Cloud Run v2 service module.
# Enforces deletion_protection = false, standard health probes, and IAM invoker.
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source = "hashicorp/google"
    }
    google-beta = {
      source = "hashicorp/google-beta"
    }
  }
}

data "google_project" "workload_project" {
  project_id = var.project_id
}

resource "google_cloud_run_v2_service" "app" {
  provider            = google-beta
  project             = var.project_id
  name                = var.service_name != "" ? var.service_name : var.product_id
  location            = var.region
  ingress             = var.ingress
  deletion_protection = false

  launch_stage = (!var.allow_unauthenticated && var.enable_direct_iap) ? "BETA" : null
  iap_enabled  = (!var.allow_unauthenticated && var.enable_direct_iap)

  # StackVend FD-4I (lane 19 L19-5a): a private service with zero invokers fails at plan, loudly (never widened).
  lifecycle {
    precondition {
      condition     = var.allow_unauthenticated || length(var.authorized_invoker_members) > 0
      error_message = "A private Cloud Run service (allow_unauthenticated = false) needs at least one authorized_invoker_members entry; StackVend never widens it to allAuthenticatedUsers."
    }
  }

  template {
    service_account = var.service_account_email
    timeout         = "300s"
    encryption_key  = var.encryption_key # lane 14 PR-0b: CMEK for regulated profiles (null = Google-managed)

    containers {
      image = var.container_image != "" ? var.container_image : "us-central1-docker.pkg.dev/${var.project_id}/${var.product_id}/${var.service_name != "" ? var.service_name : var.product_id}:latest"
      resources {
        limits = {
          cpu    = var.cpu_limit
          memory = var.memory_limit
        }
        cpu_idle = var.cpu_idle
      }
      env {
        name  = "PROJECT_ID"
        value = var.project_id
      }
      # StackVend CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV (owner 11-10): Cloud Run sets no project variable, and Google client
      # libraries and most generated code read GOOGLE_CLOUD_PROJECT. Emitted only when var.env_vars has no such key, so
      # a caller's own value is the single entry (Cloud Run env names must be unique).
      dynamic "env" {
        for_each = contains(keys(var.env_vars), "GOOGLE_CLOUD_PROJECT") ? [] : [var.project_id]
        content {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = env.value
        }
      }
      env {
        name  = "ENVIRONMENT"
        value = "prod"
      }
      env {
        name  = "GOOGLE_CLIENT_ID"
        value = var.oauth_client_id
      }
      env {
        name  = "FIREBASE_API_KEY"
        value = var.firebase_api_key
      }
      env {
        name  = "FIREBASE_AUTH_DOMAIN"
        value = var.firebase_auth_domain
      }
      dynamic "env" {
        for_each = var.env_vars
        content {
          name  = env.key
          value = env.value
        }
      }
      startup_probe {
        http_get {
          path = var.health_check_path
          port = 8080
        }
        initial_delay_seconds = 2
        timeout_seconds      = 4
        period_seconds       = 5
        failure_threshold    = 20
      }
    }

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    dynamic "vpc_access" {
      for_each = var.vpc_access_connector != "" ? [1] : []
      content {
        connector = var.vpc_access_connector
        egress    = var.vpc_egress
      }
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "public_access" {
  count    = var.allow_unauthenticated ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.app.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "domain_access" {
  for_each = var.allow_unauthenticated ? toset([]) : toset(var.authorized_invoker_members)
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.app.name
  role     = "roles/run.invoker"
  member   = each.key
}

# StackVend FD-4CS-b: the IAP service agent of the workload project. A fresh project has no IAP agent until it is
# created (or read) through the Service Usage API, so the invoker binding below waits for it. Direct IAP only.
resource "google_project_service_identity" "iap_service_agent" {
  provider = google-beta
  count    = (!var.allow_unauthenticated && var.enable_direct_iap) ? 1 : 0
  project  = var.project_id
  service  = "iap.googleapis.com"
}

# IAP Service Agent Invoker (allows IAP proxy to invoke the Cloud Run container)
# IAP-GATE-KNOWN-MEMBER: the agent's project number comes from var.project_number when the platform render sets it, so
# the member is a real value in the plan the compliance gate reads. The data source in this module is read only at
# apply on a first deploy (the platform's module-level depends_on on module.foundation defers it); it stays as the
# fallback for a caller that does not set the input. Same project, same number, so the member string does not change.
resource "google_cloud_run_v2_service_iam_member" "iap_agent_invoker" {
  count      = (!var.allow_unauthenticated && var.enable_direct_iap) ? 1 : 0
  project    = var.project_id
  location   = var.region
  name       = google_cloud_run_v2_service.app.name
  role       = "roles/run.invoker"
  member     = "serviceAccount:service-${var.project_number != "" ? var.project_number : data.google_project.workload_project.number}@gcp-sa-iap.iam.gserviceaccount.com"
  depends_on = [google_project_service_identity.iap_service_agent]
}

# Enterprise IAP Web Accessors (grants corporate browser users access through IAP)
resource "google_iap_web_cloud_run_service_iam_member" "iap_accessors" {
  for_each               = (!var.allow_unauthenticated && var.enable_direct_iap) ? toset(var.authorized_invoker_members) : toset([])
  project                = var.project_id
  location               = var.region
  cloud_run_service_name = google_cloud_run_v2_service.app.name
  role                   = "roles/iap.httpsResourceAccessor"
  member                 = each.key
}

# StackVend PUSH-TO-PRIVATE (owner 10-27): the workload's own Pub/Sub push subscriptions to this service sign with the
# service accounts in push_service_accounts (platform-rendered from the typed intent, never an AI argument). A private
# service lets exactly those identities in, and only the way its access mode needs: Direct IAP checks
# roles/iap.httpsResourceAccessor on this service's IAP resource (Cloud Run then checks run.invoker on the IAP agent,
# granted above); a private IAM-only service checks roles/run.invoker on the caller. Public services and an empty map
# plan nothing.
resource "google_iap_web_cloud_run_service_iam_member" "push_accessors" {
  for_each               = (!var.allow_unauthenticated && var.enable_direct_iap) ? var.push_service_accounts : tomap({})
  project                = var.project_id
  location               = var.region
  cloud_run_service_name = google_cloud_run_v2_service.app.name
  role                   = "roles/iap.httpsResourceAccessor"
  member                 = "serviceAccount:${each.value}"
}

resource "google_cloud_run_v2_service_iam_member" "push_invokers" {
  for_each = (!var.allow_unauthenticated && !var.enable_direct_iap) ? var.push_service_accounts : tomap({})
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.app.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${each.value}"
}
