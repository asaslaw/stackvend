# ==============================================================================
# STACKVEND: WORKLOAD FOUNDATION - BASE MODULE (APIS)
# ==============================================================================
# Declarative enablement of core GCP APIs required by all StackVend workloads.
# Supports dynamic extension via var.additional_apis for custom services.
# ==============================================================================

resource "google_project_service" "apis" {
  project            = var.project_id
  for_each           = toset(concat(var.base_apis, var.additional_apis))
  service            = each.key
  disable_on_destroy = false
}
