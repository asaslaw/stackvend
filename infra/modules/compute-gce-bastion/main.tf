# ==============================================================================
# STACKVEND: COMPUTE ARCHETYPE - GCE BASTION (IAP PRIVATE JUMP HOST)
# ==============================================================================
# Provisions an e2-micro Google Compute Engine instance with NO external public IP.
# Enforces OS Login and restricts SSH ingress exclusively to Google Cloud IAP CIDR.
# Network (gce-bastion-network, the compute-gce-worker L10-u2 model): the workload's existing subnetwork when the
# platform passes one (use_existing_subnetwork + subnetwork_id), else its own VPC + subnet on the IPAM fact
# var.subnet_cidr with Private Google Access (Google APIs only: no external IP, no Cloud NAT, no internet). Neither
# set: var.network / var.subnetwork exactly as before.
# ==============================================================================

# RT14-35: the VM's zone is var.zone when set, else the first zone of the workload region in sorted order (deterministic
# per region; us-central1 keeps us-central1-a). Never a guessed "<region>-a": us-east1 and europe-west1 have none. No
# status filter, like the typed-intent zone fact of the developer stage (ZONE_FACT_EXPR): the sorted list changes only
# when Google adds a zone, so the zone of a running bastion stays put (a zone change would replace the VM).
# RT14-F1: the platform render passes var.zone from a root read of the same list (no depends_on, so it is known at
# plan even when the foundation has a pending change); the read below is the fallback for direct callers only.
data "google_compute_zones" "available" {
  project = var.project_id
  region  = var.region
}

locals {
  zone              = var.zone != "" ? var.zone : sort(data.google_compute_zones.available.names)[0]
  net_base          = "bastion-${replace(substr(lower(replace(var.product_id, "_", "-")), 0, 40), "/-+$/", "")}"
  own_network       = !var.use_existing_subnetwork && var.subnet_cidr != "" ? 1 : 0
  own_net_id        = one(google_compute_network.bastion[*].id)
  own_subnet_id     = one(google_compute_subnetwork.bastion[*].id)
  legacy_subnetwork = var.subnetwork != "" ? var.subnetwork : null
  # existing subnetwork: GCE takes the network from it; own: the own VPC; neither: var.network / var.subnetwork as before
  vm_network    = var.use_existing_subnetwork ? null : (local.own_network == 1 ? local.own_net_id : var.network)
  vm_subnetwork = var.use_existing_subnetwork ? var.subnetwork_id : (local.own_network == 1 ? local.own_subnet_id : local.legacy_subnetwork)
}

# SA-ACCOUNT-ID-TRIM: trailing dashes of the 18-character cut are dropped (an account_id cannot end in '-'); a cut
# that does not end in '-' is unchanged.
resource "google_service_account" "bastion_sa" {
  project      = var.project_id
  account_id   = "sa-bastion-${replace(substr(replace(var.product_id, "_", "-"), 0, 18), "/-+$/", "")}"
  display_name = "IAP Bastion Service Account for ${var.product_id}"
}

resource "google_project_iam_member" "bastion_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.bastion_sa.email}"
}

resource "google_project_iam_member" "bastion_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.bastion_sa.email}"
}

resource "google_compute_network" "bastion" {
  count                   = local.own_network
  project                 = var.project_id
  name                    = "${local.net_base}-net"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "bastion" {
  count                    = local.own_network
  project                  = var.project_id
  name                     = "${local.net_base}-subnet"
  region                   = var.region
  network                  = google_compute_network.bastion[0].id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true

  lifecycle {
    ignore_changes = [secondary_ip_range]
  }
}

resource "google_compute_instance" "bastion" {
  project      = var.project_id
  name         = "bastion-${replace(var.product_id, "_", "-")}"
  machine_type = var.machine_type
  zone         = local.zone

  tags = ["bastion", "iap-ssh"]

  boot_disk {
    initialize_params {
      image = var.boot_image
    }
  }

  network_interface {
    network    = local.vm_network
    subnetwork = local.vm_subnetwork
    # Zero public IP: access_config omitted intentionally (Google APIs through Private Google Access)
  }

  # The bastion's code (gce-bastion-startup): the platform passes `apps/<service>/startup.sh` as startup_script, the
  # metadata key compute-gce-worker uses. Settings (gce-bastion-network): its topology resource bindings as instance
  # metadata attributes, platform keys last. Both unset: the metadata is exactly { enable-oslogin = "TRUE" }.
  metadata = merge(
    var.settings,
    var.startup_script == null ? {} : { "startup-script" = var.startup_script },
    { "enable-oslogin" = "TRUE" },
  )

  service_account {
    email  = google_service_account.bastion_sa.email
    scopes = ["cloud-platform"]
  }

  lifecycle {
    precondition {
      condition     = !var.use_existing_subnetwork || var.subnetwork_id != ""
      error_message = "compute-gce-bastion: use_existing_subnetwork needs subnetwork_id (projects/<p>/regions/<r>/subnetworks/<n>)."
    }
  }
}

resource "google_compute_firewall" "iap_ssh" {
  project = var.project_id
  name    = "allow-iap-ssh-${replace(var.product_id, "_", "-")}"
  # The VM's own network: an existing subnetwork's network as the instance reports it, else the own VPC, else as before.
  network = var.use_existing_subnetwork ? google_compute_instance.bastion.network_interface[0].network : (local.own_network == 1 ? local.own_net_id : var.network)

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["iap-ssh"]
}

# ------------------------------------------------------------------------------
# Resource access: granted to the bastion's own SA, per resource (compute-gce-worker WORKER_RESOURCE_ACCESS roles)
# ------------------------------------------------------------------------------
resource "google_storage_bucket_iam_member" "bastion_bucket" {
  count  = length(var.storage_buckets)
  bucket = var.storage_buckets[count.index]
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.bastion_sa.email}"
}

resource "google_pubsub_topic_iam_member" "bastion_topic" {
  count   = length(var.pubsub_topics)
  project = var.project_id
  topic   = var.pubsub_topics[count.index]
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.bastion_sa.email}"
}

resource "google_pubsub_subscription_iam_member" "bastion_subscription" {
  count        = length(var.pubsub_subscriptions)
  project      = var.project_id
  subscription = var.pubsub_subscriptions[count.index]
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.bastion_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "bastion_secret" {
  count     = length(var.secrets)
  project   = var.project_id
  secret_id = var.secrets[count.index]
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.bastion_sa.email}"
}

resource "google_bigquery_dataset_iam_member" "bastion_dataset" {
  count      = length(var.bigquery_datasets)
  project    = var.project_id
  dataset_id = var.bigquery_datasets[count.index]
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.bastion_sa.email}"
}
