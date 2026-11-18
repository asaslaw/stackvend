terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.0.0"
    }
  }
}

# ------------------------------------------------------------------------------
# 1. Core Virtual Private Cloud (VPC) Network
# ------------------------------------------------------------------------------
resource "google_compute_network" "vpc" {
  project                 = var.project_id
  name                    = var.network_name
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  description             = "Enterprise Google Cloud VPC Network managed by StackVend"
}

# ------------------------------------------------------------------------------
# 2. Primary Subnetwork (Anchor Region)
# ------------------------------------------------------------------------------
resource "google_compute_subnetwork" "primary" {
  project                  = var.project_id
  name                     = "${var.network_name}-${var.region}-subnet"
  ip_cidr_range            = var.primary_subnet_cidr
  region                   = var.region
  network                  = google_compute_network.vpc.id
  private_ip_google_access = true
  description              = "Primary subnetwork in ${var.region} with Private Google Access"

  dynamic "log_config" {
    for_each = var.enable_flow_logs ? [1] : []
    content {
      aggregation_interval = "INTERVAL_5_SEC"
      flow_sampling        = 0.5
      metadata             = "INCLUDE_ALL_METADATA"
    }
  }
  lifecycle {
    ignore_changes = [secondary_ip_range]
  }
}

# ------------------------------------------------------------------------------
# 3. Additional Multi-Region Subnetworks (On-Demand Expansion)
# ------------------------------------------------------------------------------
resource "google_compute_subnetwork" "additional" {
  for_each                 = var.additional_regions
  project                  = var.project_id
  name                     = "${var.network_name}-${each.key}-subnet"
  ip_cidr_range            = each.value
  region                   = each.key
  network                  = google_compute_network.vpc.id
  private_ip_google_access = true
  description              = "Multi-region subnetwork in ${each.key} with Private Google Access"

  dynamic "log_config" {
    for_each = var.enable_flow_logs ? [1] : []
    content {
      aggregation_interval = "INTERVAL_5_SEC"
      flow_sampling        = 0.5
      metadata             = "INCLUDE_ALL_METADATA"
    }
  }
  lifecycle {
    ignore_changes = [secondary_ip_range]
  }
}

# ------------------------------------------------------------------------------
# 4. Private Services Access (PSA) Peering for Cloud SQL, Redis & AlloyDB
# ------------------------------------------------------------------------------
resource "google_compute_global_address" "private_service_access" {
  count         = var.enable_private_service_access ? 1 : 0
  project       = var.project_id
  name          = "${var.network_name}-psa-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  address       = var.psa_address # TI-5-F4: the platform IPAM range; null = Google allocates (unchanged)
  prefix_length = var.psa_prefix_length
  network       = google_compute_network.vpc.id
  description   = "Reserved internal IP address block for Google Cloud Private Services Access (Cloud SQL, Redis, AlloyDB)"
}

resource "google_service_networking_connection" "private_vpc_connection" {
  count                   = var.enable_private_service_access ? 1 : 0
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_service_access[0].name]
}

# ------------------------------------------------------------------------------
# 5. Cloud NAT & Cloud Router (Optional Egress Gateway)
# ------------------------------------------------------------------------------
locals {
  nat_regions = var.enable_nat ? distinct(concat([var.region], keys(var.additional_regions))) : []
}

resource "google_compute_router" "nat_router" {
  for_each = toset(local.nat_regions)
  project  = var.project_id
  name     = "${var.network_name}-${each.key}-router"
  region   = each.key
  network  = google_compute_network.vpc.id

  bgp {
    asn = 64514
  }
}

resource "google_compute_router_nat" "nat_gateway" {
  for_each                           = toset(local.nat_regions)
  project                            = var.project_id
  name                               = "${var.network_name}-${each.key}-nat"
  router                             = google_compute_router.nat_router[each.key].name
  region                             = each.key
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# ------------------------------------------------------------------------------
# 6. Hardened Baseline Firewall Rules
# ------------------------------------------------------------------------------
resource "google_compute_firewall" "allow_internal" {
  project     = var.project_id
  name        = "${var.network_name}-allow-internal"
  network     = google_compute_network.vpc.name
  description = "Permit internal east-west traffic between all subnets in the VPC"

  allow {
    protocol = "icmp"
  }
  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }
  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  source_ranges = concat([var.primary_subnet_cidr], values(var.additional_regions))
}

resource "google_compute_firewall" "allow_health_checks" {
  project     = var.project_id
  name        = "${var.network_name}-allow-health-checks"
  network     = google_compute_network.vpc.name
  description = "Permit Google Cloud Load Balancer and Cloud Run health check probes"

  allow {
    protocol = "tcp"
  }

  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"]
}

resource "google_compute_firewall" "allow_iap" {
  project     = var.project_id
  name        = "${var.network_name}-allow-iap"
  network     = google_compute_network.vpc.name
  description = "Permit Google Cloud Identity-Aware Proxy (IAP) management tunneling without public bastion IPs"

  allow {
    protocol = "tcp"
    ports    = ["22", "80", "443", "8080"]
  }

  source_ranges = ["35.235.240.0/20"]
}
