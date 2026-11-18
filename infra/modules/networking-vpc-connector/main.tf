# ==============================================================================
# STACKVEND: NETWORKING ARCHETYPE - SERVERLESS VPC ACCESS CONNECTOR (FD-4BH)
# ==============================================================================
# One Serverless VPC Access connector, so Cloud Run services reach private IPs in
# the workload VPC (Cloud SQL, Memorystore Redis, AlloyDB over Private Services
# Access; a peered Vertex AI endpoint). Pass the `id` output to compute-cloudrun's
# `vpc_access_connector` input.
#
# A separate module, not a block inside networking-vpc: networking-vpc stays
# unchanged (no plan diff for a workload that uses it), and `region` and
# `connector_cidr` are required here with no default. The /28 range is the
# workload's IPAM allocation (var.connector_cidr of the workload root); the region
# is the workload's var.region. No region or CIDR literal lives in this module.
# On typed infrastructure the platform renders the call itself
# (module.stackvend_connector); the AI never writes it.
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0"
    }
  }
}

resource "google_vpc_access_connector" "connector" {
  project       = var.project_id
  name          = var.name
  region        = var.region
  network       = var.network
  ip_cidr_range = var.connector_cidr
  machine_type  = var.machine_type
  min_instances = var.min_instances
  max_instances = var.max_instances

  lifecycle {
    precondition {
      condition     = var.min_instances < var.max_instances
      error_message = "min_instances must be lower than max_instances."
    }
  }
}
