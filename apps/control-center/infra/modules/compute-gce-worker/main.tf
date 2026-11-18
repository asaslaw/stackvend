# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - GCE WORKER (ON-DEMAND VM FROM A TEMPLATE)
# ==============================================================================
# An instance template that a Cloud Run launcher starts VMs from at runtime (lane 10, register L10-s/t/u):
# Spot e2-micro by default, deleted after max_run_duration_seconds (default 24 h), startup script, its own service
# account, no VM at rest, no external IP, no inbound firewall rule, no Cloud NAT. Network (L10-u2): the workload's
# existing subnetwork when the platform passes one (use_existing_subnetwork + subnetwork_id), else its own VPC + subnet
# on the IPAM range with Private Google Access.
# The launcher gets roles/compute.instanceAdmin.v1 only under an IAM condition limited to this worker's instances,
# their boot disks, its templates and its subnetwork, plus roles/iam.serviceAccountUser on the worker SA only.
# ==============================================================================

# RT F2: the default zone is a zone of the region that exists and is UP (names are sorted: deterministic per region),
# never a guessed "<region>-a" (us-east1 / europe-west1 have none).
data "google_compute_zones" "available" {
  project = var.project_id
  region  = var.region
  status  = "UP"
}

locals {
  short           = replace(substr(var.worker_name, 0, 25), "/-+$/", "")
  base            = "gcew-${local.short}"
  zone            = var.zone != "" ? var.zone : data.google_compute_zones.available.names[0]
  instance_prefix = "gcew-${var.worker_name}-"
  own_network     = var.use_existing_subnetwork ? 0 : 1
  subnetwork      = var.use_existing_subnetwork ? var.subnetwork_id : one(google_compute_subnetwork.worker[*].id)
}

resource "google_service_account" "worker" {
  project      = var.project_id
  account_id   = local.base
  display_name = "GCE worker ${var.worker_name} of ${var.product_id}"
}

resource "google_project_iam_member" "worker_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_compute_network" "worker" {
  count                   = local.own_network
  project                 = var.project_id
  name                    = "${local.base}-net"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "worker" {
  count                    = local.own_network
  project                  = var.project_id
  name                     = "${local.base}-subnet"
  region                   = var.region
  network                  = google_compute_network.worker[0].id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true

  lifecycle {
    ignore_changes = [secondary_ip_range]
    precondition {
      condition     = var.subnet_cidr != ""
      error_message = "compute-gce-worker: subnet_cidr (the IPAM fact var.subnet_cidr) is required for its own subnet."
    }
  }
}

resource "google_compute_instance_template" "worker" {
  project      = var.project_id
  name_prefix  = "${local.base}-"
  machine_type = var.machine_type
  labels = {
    stackvend-worker = local.short
  }

  scheduling {
    provisioning_model          = var.spot ? "SPOT" : "STANDARD"
    preemptible                 = var.spot
    automatic_restart           = false
    on_host_maintenance         = "TERMINATE"
    instance_termination_action = var.spot ? "DELETE" : null

    # GCE-WORKER-MAX-RUN-DURATION: a Spot worker is deleted after max_run_duration_seconds even when its startup
    # script never powers it off (a runaway batch VM otherwise bills forever). Spot only: a Spot VM can already be
    # deleted at any moment by preemption, so a time bound changes no guarantee the worker had; a standard worker
    # (spot = false) keeps an unbounded run time. null = no bound. VMs that instances.insert creates from this
    # template (sourceInstanceTemplate) inherit the setting.
    dynamic "max_run_duration" {
      for_each = var.spot && var.max_run_duration_seconds != null ? [var.max_run_duration_seconds] : []
      content {
        seconds = max_run_duration.value
      }
    }
  }

  disk {
    source_image = var.boot_image
    disk_type    = var.disk_type
    disk_size_gb = var.disk_size_gb
    auto_delete  = true
    boot         = true
  }

  network_interface {
    subnetwork = local.subnetwork
    # No access_config: no external IP (Google APIs through Private Google Access).
  }

  metadata = merge(var.env_vars, {
    "startup-script" = var.startup_script
    "enable-oslogin" = "TRUE"
  })

  service_account {
    email  = google_service_account.worker.email
    scopes = ["cloud-platform"]
  }

  lifecycle {
    create_before_destroy = true
    precondition {
      condition     = !var.use_existing_subnetwork || var.subnetwork_id != ""
      error_message = "compute-gce-worker: use_existing_subnetwork needs subnetwork_id (projects/<p>/regions/<r>/subnetworks/<n>)."
    }
  }
}

# ------------------------------------------------------------------------------
# Launcher: conditional instanceAdmin (this worker's instances, boot disks, templates, subnetwork) + actAs worker SA
# ------------------------------------------------------------------------------
resource "google_project_iam_member" "launcher_instance_admin" {
  count   = length(var.launcher_service_account_emails)
  project = var.project_id
  role    = "roles/compute.instanceAdmin.v1"
  member  = "serviceAccount:${var.launcher_service_account_emails[count.index]}"

  condition {
    title       = "${local.base}-launch"
    description = "Only GCE worker ${var.worker_name}: its instances, their boot disks, its templates, its subnetwork"
    expression = join(" || ", [
      "resource.name.startsWith(\"projects/${var.project_id}/zones/${local.zone}/instances/${local.instance_prefix}\")",
      "resource.name.startsWith(\"projects/${var.project_id}/zones/${local.zone}/disks/${local.instance_prefix}\")",
      "resource.name.startsWith(\"projects/${var.project_id}/global/instanceTemplates/${local.base}-\")",
      "resource.name == \"${local.subnetwork}\"",
    ])
  }
}

resource "google_service_account_iam_member" "launcher_act_as" {
  count              = length(var.launcher_service_account_emails)
  service_account_id = google_service_account.worker.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${var.launcher_service_account_emails[count.index]}"
}

# ------------------------------------------------------------------------------
# Worker resource access: granted to the worker's own SA, per resource
# ------------------------------------------------------------------------------
resource "google_storage_bucket_iam_member" "worker_bucket" {
  count  = length(var.storage_buckets)
  bucket = var.storage_buckets[count.index]
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_pubsub_topic_iam_member" "worker_topic" {
  count   = length(var.pubsub_topics)
  project = var.project_id
  topic   = var.pubsub_topics[count.index]
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_pubsub_subscription_iam_member" "worker_subscription" {
  count        = length(var.pubsub_subscriptions)
  project      = var.project_id
  subscription = var.pubsub_subscriptions[count.index]
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_secret_manager_secret_iam_member" "worker_secret" {
  count     = length(var.secrets)
  project   = var.project_id
  secret_id = var.secrets[count.index]
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_bigquery_dataset_iam_member" "worker_dataset" {
  count      = length(var.bigquery_datasets)
  project    = var.project_id
  dataset_id = var.bigquery_datasets[count.index]
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.worker.email}"
}
