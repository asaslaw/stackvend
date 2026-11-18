# ==============================================================================
# STACKVEND: WORKLOAD INFRASTRUCTURE (DETERMINISTIC GOLDEN FOUNDATION)
# ==============================================================================
# Instantiates canonical vendored foundation and compute modules.
# Any bespoke additions (Storage, Pub/Sub, Redis) are declared in custom.tf.
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0.0, < 7.0.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 6.0.0, < 7.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20.0"
    }
  }
}

provider "google" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}

provider "google-beta" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}

# ------------------------------------------------------------------------------
# Tier 1: Canonical Base Foundation (APIs, WIF, IAM, Firestore, Registry)
# ------------------------------------------------------------------------------
module "foundation" {
  source                = "../modules/workload-foundation/base"
  project_id            = var.project_id
  region                = var.region
  product_id            = var.product_id
  github_repo_full_name = var.github_repo_full_name
  github_repository_id  = var.github_repository_id
  additional_apis       = var.additional_apis
}

# ------------------------------------------------------------------------------
# Tier 2: Compute Archetype (gke-autopilot)
# ------------------------------------------------------------------------------
module "compute" {
  source     = "../modules/compute-gke-autopilot"
  project_id = var.project_id
  region     = var.region
  product_id = var.product_id
  network    = var.network
  subnetwork = var.subnetwork

  depends_on = [module.foundation]
}

# ------------------------------------------------------------------------------
# Kubernetes Provider Configuration (GKE Autopilot)
# ------------------------------------------------------------------------------
data "google_client_config" "default" {}

provider "kubernetes" {
  host                   = "https://${module.compute.cluster_endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(module.compute.cluster_ca_certificate)
}
