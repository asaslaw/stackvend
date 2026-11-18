# ==============================================================================
# HOST-INTERNAL-INGRESS + HOST-VPC-EGRESS (owner rule 11-07: "nothing public except the Control Center";
# owner decision 11-07: Design B, shipped with the RC; Design A kept as a one-variable fallback)
# ==============================================================================
# Cloud Run treats a call from another Cloud Run service or job as "internal" only when it leaves through a VPC
# network. The host project had none, so internal-only ingress would have cut the platform off from itself. This file
# adds that network and the switches that use it (variables.tf):
#
#   * var.host_vpc_egress (default true): network stackvend-host and one subnet (Private Google Access on). Every host
#     Cloud Run service and job gets Direct VPC egress into it (local.host_vpc_access, used by the dynamic
#     "vpc_access" blocks in main.tf). How traffic leaves depends on var.host_egress_mode:
#       - "PSC_PRIVATE_RANGES" (Design B, default): egress PRIVATE_RANGES_ONLY, a Private Service Connect (PSC)
#         endpoint for Google APIs (bundle all-apis) and a private DNS zone run.app. bound to this network only, whose
#         wildcard *.run.app. A record answers the PSC address. A *.run.app name (the hashed <svc>-<hash>.a.run.app
#         and the deterministic <svc>-<project number>.<region>.run.app forms) resolves to the private PSC address,
#         enters the network and reaches Cloud Run as an internal request. Everything else (GitHub, the OpenTofu
#         registry, infracost, Helm, GKE endpoints, *.googleapis.com) keeps Cloud Run's default path: no Cloud NAT, no
#         new egress IPs. Verified live (2026-11-08): Direct VPC egress in PRIVATE_RANGES_ONLY mode resolves both
#         run.app forms through the network's private zone, and the call counts as internal (outside callers get 404).
#       - "NAT_ALL_TRAFFIC" (Design A, Google's documented pattern): egress ALL_TRAFFIC; run.app and Google APIs are
#         reached over Private Google Access on the subnet, everything else through Cloud NAT (google_compute_router +
#         google_compute_router_nat, automatic addresses, dynamic port allocation). No PSC endpoint, no run.app zone.
#         Non-Google egress then leaves from the NAT addresses (GitHub and allow-lists see new IPs).
#   * var.host_internal_ingress (default false; bootstrap writes true for a new install from one constant, see
#     scripts/bootstrap.sh SV_NEW_INSTALL_HOST_INTERNAL_INGRESS): local.host_service_ingress = INGRESS_TRAFFIC_INTERNAL_ONLY on the 12
#     services other than the Control Center, and on castor-git-server. IAM is unchanged, so a request passes the
#     network check first and IAM second.
#   * var.host_network_deployer_grants (default false): roles/compute.networkUser on the subnet for the identities that
#     re-deploy revisions carrying vpcAccess (the Cloud Build trigger account here; the upgrader in
#     platform_upgrader.tf), in case the live spike shows the Run Admin API requires it.
#
# Never on this network: qa-sandbox-test-runner (qa_sandbox.tf). It runs untrusted generated code; on this network it
# would become an internal source for every host service, protected by IAM alone. tests/test_internal_ingress_tf.py
# fails if qa_sandbox.tf ever names a resource from this file.
#
# Same-project Pub/Sub push, Cloud Scheduler and Workflows count as internal without a network (no workflows/*.yaml
# change). Operators' laptops, Cloud Shell and Cloud Build's default pool never do: `curl` with an ID token or
# `gcloud run services proxy` to a host service other than the Control Center stops working on purpose (break-glass:
# documentation/configuration.md). The network is never peered (no VPN, interconnect or peering), so its ranges cannot
# collide with any workload range; they default to the IPAM platform reservations shared/ipam.py
# PLATFORM_RESERVED_CIDRS (variables.tf; tests pin equality).
#
# Cost (us-central1 list prices, approximate): Design B: PSC endpoint for Google APIs up to about $7.30/month plus
# data processed, private DNS zone $0.20/month plus queries. Design A: Cloud NAT about $0.0014/h per assigned instance
# (capped at about $32/month) plus $0.045/GB processed. The network, subnet and Direct VPC egress have no charge.
# ==============================================================================

locals {
  host_network_name = "stackvend-host"

  # Ingress of every host Cloud Run service except the Control Center (main.tf services + git_server).
  host_service_ingress = var.host_internal_ingress ? "INGRESS_TRAFFIC_INTERNAL_ONLY" : "INGRESS_TRAFFIC_ALL"

  # Design B: only private-range destinations (the PSC address that *.run.app resolves to) enter the network.
  # Design A: everything enters the network (Private Google Access for Google, Cloud NAT for the rest).
  host_egress_mode = var.host_egress_mode == "PSC_PRIVATE_RANGES" ? "PRIVATE_RANGES_ONLY" : "ALL_TRAFFIC"

  # Per-design resource switches (count = 1 / 0).
  host_network_psc = var.host_vpc_egress && var.host_egress_mode == "PSC_PRIVATE_RANGES"
  host_network_nat = var.host_vpc_egress && var.host_egress_mode == "NAT_ALL_TRAFFIC"

  # The one Direct VPC egress attachment, [] when host_vpc_egress is off. main.tf's four dynamic "vpc_access" blocks
  # (services, git_server, jobs, tf_applier) iterate over it; qa_sandbox.tf never does.
  host_vpc_access = var.host_vpc_egress ? [{
    network    = google_compute_network.host[0].id
    subnetwork = google_compute_subnetwork.host_run_egress[0].id
  }] : []
}

# Cloud DNS (the private run.app zone) and Service Directory (Google registers a PSC endpoint for Google APIs there)
# are not in main.tf's API list; enabled here, never disabled on destroy. Unconditional, so another file can reuse
# them (FD-4BR's QA sandbox zones need Cloud DNS too).
resource "google_project_service" "host_network_dns" {
  depends_on         = [google_project_service.apis]
  project            = var.project_id
  service            = "dns.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "host_network_service_directory" {
  depends_on         = [google_project_service.apis]
  project            = var.project_id
  service            = "servicedirectory.googleapis.com"
  disable_on_destroy = false
}

resource "google_compute_network" "host" {
  count                   = var.host_vpc_egress ? 1 : 0
  depends_on              = [google_project_service.apis]
  project                 = var.project_id
  name                    = local.host_network_name
  description             = "StackVend platform network: Direct VPC egress of the host Cloud Run services and jobs (never peered; never the QA sandbox job)."
  auto_create_subnetworks = false
}

# Every vpc_access attachment references this subnet, so it is created only after the way out exists (depends_on:
# the PSC endpoint and the run.app record in Design B, the Cloud NAT in Design A): no revision joins the network
# before its calls can leave it.
resource "google_compute_subnetwork" "host_run_egress" {
  count                    = var.host_vpc_egress ? 1 : 0
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.host[0].id
  name                     = "${local.host_network_name}-${var.region}"
  ip_cidr_range            = var.host_egress_subnet_cidr # IPAM platform reservation (PLATFORM_RESERVED_CIDRS)
  private_ip_google_access = true

  depends_on = [
    google_compute_global_forwarding_rule.psc_google_apis,
    google_dns_record_set.host_run_app_wildcard,
    google_compute_router_nat.host,
  ]

  lifecycle {
    # Design B: a PSC endpoint address must lie outside every subnet of its network.
    precondition {
      condition     = var.host_egress_mode != "PSC_PRIVATE_RANGES" || cidrsubnet("${var.host_psc_endpoint_ip}/${split("/", var.host_egress_subnet_cidr)[1]}", 0, 0) != var.host_egress_subnet_cidr
      error_message = "host_psc_endpoint_ip must lie outside host_egress_subnet_cidr (a Private Service Connect endpoint address cannot be inside a subnet of its network)."
    }
  }
}

# ------------------------------------------------------------------------------
# Design B (host_egress_mode = "PSC_PRIVATE_RANGES")
# ------------------------------------------------------------------------------
resource "google_compute_global_address" "psc_google_apis" {
  count        = local.host_network_psc ? 1 : 0
  depends_on   = [google_project_service.apis]
  project      = var.project_id
  name         = "${local.host_network_name}-psc-googleapis"
  purpose      = "PRIVATE_SERVICE_CONNECT"
  address_type = "INTERNAL"
  address      = var.host_psc_endpoint_ip # IPAM platform reservation (PLATFORM_RESERVED_CIDRS, /32)
  network      = google_compute_network.host[0].id
}

# PSC endpoint for Google APIs: run.app is served by the all-apis bundle. The name must be 1-20 lowercase letters or
# digits, starting with a letter; load_balancing_scheme "" is the documented value for a Google APIs endpoint.
resource "google_compute_global_forwarding_rule" "psc_google_apis" {
  count                 = local.host_network_psc ? 1 : 0
  depends_on            = [google_project_service.host_network_service_directory]
  project               = var.project_id
  name                  = "svgoogleapis"
  target                = "all-apis"
  network               = google_compute_network.host[0].id
  ip_address            = google_compute_global_address.psc_google_apis[0].id
  load_balancing_scheme = ""
}

# Private zone run.app., visible from stackvend-host only. Under RFC 4592 the wildcard also answers names below a.run.app
# (no a.run.app node exists in the zone). No googleapis.com zone: Google APIs keep their default path.
resource "google_dns_managed_zone" "host_run_app" {
  count       = local.host_network_psc ? 1 : 0
  depends_on  = [google_project_service.host_network_dns]
  project     = var.project_id
  name        = "${local.host_network_name}-run-app"
  dns_name    = "run.app."
  description = "StackVend: *.run.app resolves to the platform's Private Service Connect endpoint inside stackvend-host only, so platform-to-platform calls are internal."
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.host[0].id
    }
  }
}

resource "google_dns_record_set" "host_run_app_wildcard" {
  count        = local.host_network_psc ? 1 : 0
  project      = var.project_id
  managed_zone = google_dns_managed_zone.host_run_app[0].name
  name         = "*.run.app."
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.psc_google_apis[0].address]
}

# ------------------------------------------------------------------------------
# Design A (host_egress_mode = "NAT_ALL_TRAFFIC")
# ------------------------------------------------------------------------------
resource "google_compute_router" "host" {
  count   = local.host_network_nat ? 1 : 0
  project = var.project_id
  region  = var.region
  name    = "${local.host_network_name}-${var.region}"
  network = google_compute_network.host[0].id
}

resource "google_compute_router_nat" "host" {
  count                               = local.host_network_nat ? 1 : 0
  project                             = var.project_id
  region                              = var.region
  name                                = "${local.host_network_name}-nat"
  router                              = google_compute_router.host[0].name
  nat_ip_allocate_option              = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat  = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  enable_dynamic_port_allocation      = true
  enable_endpoint_independent_mapping = false # required with dynamic port allocation
  min_ports_per_vm                    = 1024  # parallel provider downloads (terraform server warm-up)

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}
