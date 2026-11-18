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

# FD-4AX: no default password literal. A per-instance password is generated unless the caller supplies
# var.db_password, and is stored in Secret Manager (output secret_id_password). It is never a module output.
# Created unconditionally so that no count depends on the sensitive variable (portable across OpenTofu and Terraform).
resource "random_password" "db" {
  length  = 32
  special = false
}

locals {
  db_password = var.db_password != "" ? var.db_password : random_password.db.result
}

resource "google_sql_database_instance" "instance" {
  project             = var.project_id
  region              = var.region
  name                = "${var.project_id}-${var.instance_name_suffix}"
  database_version    = var.database_version
  deletion_protection = var.deletion_protection
  encryption_key_name = var.kms_key_name # lane 14 PR-0b: CMEK for regulated profiles (null = Google-managed)

  settings {
    tier              = var.tier
    availability_type = "ZONAL"
    disk_size         = 10
    disk_type         = "PD_SSD"

    backup_configuration {
      enabled    = true
      start_time = "03:00"
    }

    # FD-4AZ-b1: `require_ssl` was removed in google 6.0. ssl_mode defaults to "ENCRYPTED_ONLY": TLS is still
    # required; a client certificate is no longer required (the removed require_ssl = true did require one).
    # FD-CSQL: private IP on var.private_network_id (a VPC with Private Services Access, e.g. networking-vpc's
    # network_id) and a public IPv4 address only when enable_public_ip = true. Cloud SQL refuses an instance with
    # neither; the precondition below says so at plan time instead of an API 400 at create.
    ip_configuration {
      ipv4_enabled    = var.enable_public_ip
      private_network = var.private_network_id
      ssl_mode        = var.ssl_mode
    }
  }

  lifecycle {
    precondition {
      condition     = var.enable_public_ip || var.private_network_id != null
      error_message = "database-cloudsql: set private_network_id (a VPC network with Private Services Access, e.g. module.network.network_id from networking-vpc) or enable_public_ip = true. Cloud SQL refuses an instance with neither."
    }
  }
}

resource "google_sql_database" "database" {
  project  = var.project_id
  instance = google_sql_database_instance.instance.name
  name     = var.database_name
}

resource "google_sql_user" "user" {
  project  = var.project_id
  instance = google_sql_database_instance.instance.name
  name     = var.db_user
  password = local.db_password
}

# Grant workload service account Cloud SQL Client role for Auth Proxy socket access
resource "google_project_iam_member" "cloudsql_client" {
  count   = var.workload_sa_email != "" ? 1 : 0
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${var.workload_sa_email}"
}

resource "google_secret_manager_secret" "db_password" {
  project   = var.project_id
  secret_id = "${var.project_id}-${var.instance_name_suffix}-db-password"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = local.db_password
}

# Opt-in read access for the workload runtime SA. A plain bool keeps count known at plan time even when
# workload_sa_email is computed by another module.
resource "google_secret_manager_secret_iam_member" "workload_accessor" {
  count     = var.grant_workload_secret_access ? 1 : 0
  project   = var.project_id
  secret_id = google_secret_manager_secret.db_password.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.workload_sa_email}"

  lifecycle {
    precondition {
      condition     = var.workload_sa_email != ""
      error_message = "grant_workload_secret_access = true requires workload_sa_email."
    }
  }
}
