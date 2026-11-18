# ==============================================================================
# STACKVEND: PARAMETERIZED MODULE - ALLOYDB FOR POSTGRESQL (TIER 2 STATEFUL)
# ==============================================================================
# Provisions an enterprise AlloyDB cluster and primary instance with VPC peering,
# automated backups, and CPU sizing controls.
# ==============================================================================
# TI-5-R2 P3 (owner 10-25, as database-cloudsql since FD-4AX): the initial user's
# password (generated unless the caller supplies initial_user_password) is stored
# in Secret Manager (output secret_id_password); it is never a module output.

locals {
  cluster_id  = var.cluster_id != "" ? var.cluster_id : "alloydb-${replace(lower(var.product_id), "_", "-")}"
  instance_id = var.instance_id != "" ? var.instance_id : "${local.cluster_id}-primary"

  initial_user_password = var.initial_user_password != null ? var.initial_user_password : random_password.alloydb_password[0].result

  default_labels = {
    managed_by = "castor-terraform"
    product_id = var.product_id
  }
}

resource "random_password" "alloydb_password" {
  count   = var.initial_user_password == null ? 1 : 0
  length  = 24
  special = false
}

resource "google_alloydb_cluster" "cluster" {
  project    = var.project_id
  location   = var.region
  cluster_id = local.cluster_id

  # FD-4AZ-b1: the top-level `network` argument was removed in google 6.0; it now lives in network_config.
  network_config {
    network = var.network
  }

  initial_user {
    password = local.initial_user_password
  }

  automated_backup_policy {
    enabled = true
    weekly_schedule {
      days_of_week = ["MONDAY", "WEDNESDAY", "FRIDAY"]
      start_times {
        hours   = 2
        minutes = 0
      }
    }
  }

  dynamic "encryption_config" {
    for_each = var.kms_key_name != null ? [1] : []
    content {
      kms_key_name = var.kms_key_name
    }
  }

  labels = merge(local.default_labels, var.labels)

  # FD-CSQL (F6): the old default was the bare name "default", which the API does not accept and which has no
  # Private Services Access in a vended project. Refuse a missing network at plan time with a plain message.
  lifecycle {
    precondition {
      condition     = var.network != null
      error_message = "database-alloydb: set network to a VPC network ID with Private Services Access (e.g. module.network.network_id from networking-vpc)."
    }
  }
}

resource "google_alloydb_instance" "primary" {
  cluster       = google_alloydb_cluster.cluster.name
  instance_id   = local.instance_id
  instance_type = "PRIMARY"

  machine_config {
    cpu_count = var.cpu_count
  }

  labels = merge(local.default_labels, var.labels)
}

# The initial user's password, for the workload to read at runtime (AlloyDB's initial user is `postgres`).
resource "google_secret_manager_secret" "initial_user_password" {
  project   = var.project_id
  secret_id = "${local.cluster_id}-db-password"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "initial_user_password" {
  secret      = google_secret_manager_secret.initial_user_password.id
  secret_data = local.initial_user_password
}

# Opt-in read access for the workload runtime SA. A plain bool keeps count known at plan time even when
# workload_sa_email is computed by another module.
resource "google_secret_manager_secret_iam_member" "workload_accessor" {
  count     = var.grant_workload_secret_access ? 1 : 0
  project   = var.project_id
  secret_id = google_secret_manager_secret.initial_user_password.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.workload_sa_email}"

  lifecycle {
    precondition {
      condition     = var.workload_sa_email != ""
      error_message = "grant_workload_secret_access = true requires workload_sa_email."
    }
  }
}
