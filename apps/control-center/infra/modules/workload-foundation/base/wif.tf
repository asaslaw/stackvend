# ==============================================================================
# STACKVEND: WORKLOAD FOUNDATION - WORKLOAD IDENTITY FEDERATION (WIF)
# ==============================================================================
# Provisions keyless OIDC authentication for GitHub Actions CI/CD workflows.
# Dynamically binds GitHub repository to the deployer service account.
# ==============================================================================

locals {
  wif_repository_id_clause = var.github_repository_id == "" ? "" : " && assertion.repository_id == '${var.github_repository_id}'"
  # GHA-DEPLOY-SWITCH: one instance of every GitHub Actions deploy resource (pool, provider, deployer SA, its WIF
  # binding and roles) while the switch is on (default), none when it is off.
  github_actions_deploy_count = var.enable_github_actions_deploy ? 1 : 0
}

# GHA-DEPLOY-SWITCH: the resources below and the deployer roles in iam.tf gained `count`. These moved blocks keep the
# existing single instance as [0], so a workload with the switch on plans no change.
moved {
  from = google_iam_workload_identity_pool.github_pool
  to   = google_iam_workload_identity_pool.github_pool[0]
}

moved {
  from = google_iam_workload_identity_pool_provider.github_provider
  to   = google_iam_workload_identity_pool_provider.github_provider[0]
}

moved {
  from = google_service_account.github_deployer
  to   = google_service_account.github_deployer[0]
}

moved {
  from = google_service_account_iam_member.github_wif_binding
  to   = google_service_account_iam_member.github_wif_binding[0]
}

resource "google_iam_workload_identity_pool" "github_pool" {
  count                     = local.github_actions_deploy_count
  project                   = var.project_id
  workload_identity_pool_id = "castor-gh-pool"
  display_name              = "StackVend GitHub Pool"
  description               = "Workload Identity Pool for GitHub Actions keyless authentication"
  disabled                  = false
  depends_on                = [google_project_service.apis]
}

resource "google_iam_workload_identity_pool_provider" "github_provider" {
  count                              = local.github_actions_deploy_count
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"
  display_name                       = "GitHub Actions Provider"
  description                        = "OIDC Provider for GitHub Actions"
  disabled                           = false

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.actor"            = "assertion.actor"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
    "attribute.repository_id"    = "assertion.repository_id"
    "attribute.ref"              = "assertion.ref"
  }

  # FD-4AT: only one branch of this workload repository, and only the events the generated workflows use
  # (push to that branch, workflow_dispatch), so a pull_request_target / workflow_run / schedule run is rejected.
  # FD-4AT-c: when the platform supplies the repository's immutable numeric id, the token must also carry that
  # assertion.repository_id, so a deleted-and-re-created repository with the same name is rejected. Without the id
  # the condition is byte-identical to FD-4AT's (no change for workloads vended before FD-4AT-c). Exact equality.
  # FD-4CI-b-R1-WIF: the one branch is the workload's recorded default branch (var.github_default_branch, validated
  # to the platform's branch-name grammar); "main" (the default) renders the FD-4AT ref byte for byte. Still exact.
  attribute_condition = "assertion.repository == '${var.github_repo_full_name}'${local.wif_repository_id_clause} && assertion.ref == 'refs/heads/${var.github_default_branch}' && assertion.event_name in ['push','workflow_dispatch']"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "github_deployer" {
  count        = local.github_actions_deploy_count
  project      = var.project_id
  account_id   = "sa-gh-deployer"
  display_name = "GitHub Actions Workload Deployer"
  depends_on   = [google_project_service.apis]
}

resource "google_service_account_iam_member" "github_wif_binding" {
  count              = local.github_actions_deploy_count
  service_account_id = google_service_account.github_deployer[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool[0].name}/attribute.repository/${var.github_repo_full_name}"
}
