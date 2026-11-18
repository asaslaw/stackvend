# ==============================================================================
# STACKVEND: WORKLOAD FOUNDATION - IAM & SERVICE ACCOUNTS
# ==============================================================================
# IAM for the GitHub Actions deployer (sa-gh-deployer) and the workload's runtime
# execution identity (workload_sa).
#
# FD-4AT: the deployer holds only what the generated CI workflows run
# (.github/workflows/deploy-<svc>.yml): `gcloud run deploy --source` and
# `gcloud run jobs deploy --source` (roles/run.sourceDeveloper: Cloud Run,
# Cloud Build, the gcloud-managed source repository and bucket), and
# `gcloud container clusters get-credentials` + `kubectl apply` for GKE
# Autopilot. No Editor role and no project-wide admin or
# iam.serviceAccountUser: it may act only as the runtime SA and the Cloud Build
# (Compute Engine default) SA (section 3).
# Invoker (public/private) IAM on services stays with Terraform.
#
# Known limits: roles/run.sourceDeveloper also carries Pub/Sub topic and
# subscription create/delete and Eventarc admin (Google's predefined role for
# source deploys). roles/container.developer has no Kubernetes RBAC create
# (Role/RoleBinding/ClusterRole/ClusterRoleBinding), so a k8s/ manifest set
# that carries RBAC objects fails at `kubectl apply`; no generator emits them.
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. CI/CD Deployer Service Account Roles
# ------------------------------------------------------------------------------
# GHA-DEPLOY-SWITCH: every deployer grant exists only while the switch is on (local.github_actions_deploy_count,
# wif.tf); the moved blocks keep the existing single instance as [0] (no change with the switch on).
moved {
  from = google_project_iam_member.deployer_run_source_developer
  to   = google_project_iam_member.deployer_run_source_developer[0]
}

moved {
  from = google_project_iam_member.deployer_logging_viewer
  to   = google_project_iam_member.deployer_logging_viewer[0]
}

moved {
  from = google_project_iam_member.deployer_container_developer
  to   = google_project_iam_member.deployer_container_developer[0]
}

moved {
  from = google_service_account_iam_member.deployer_runtime_sa_user
  to   = google_service_account_iam_member.deployer_runtime_sa_user[0]
}

moved {
  from = google_service_account_iam_member.deployer_build_sa_user
  to   = google_service_account_iam_member.deployer_build_sa_user[0]
}

# Deploy from source: Cloud Run services/jobs, the source build, the
# gcloud-managed `cloud-run-source-deploy` repository and source bucket.
resource "google_project_iam_member" "deployer_run_source_developer" {
  count   = local.github_actions_deploy_count
  project = var.project_id
  role    = "roles/run.sourceDeveloper"
  member  = "serviceAccount:${google_service_account.github_deployer[0].email}"
}

# Read Cloud Build logs while gcloud waits for the source build.
resource "google_project_iam_member" "deployer_logging_viewer" {
  count   = local.github_actions_deploy_count
  project = var.project_id
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${google_service_account.github_deployer[0].email}"
}

# GKE Autopilot archetype: clusters describe / get-credentials + `kubectl apply -f k8s/`.
resource "google_project_iam_member" "deployer_container_developer" {
  count   = local.github_actions_deploy_count
  project = var.project_id
  role    = "roles/container.developer"
  member  = "serviceAccount:${google_service_account.github_deployer[0].email}"
}

# ------------------------------------------------------------------------------
# 2. Workload Runtime Service Account & Scoped Permissions
# ------------------------------------------------------------------------------
# SA-ACCOUNT-ID-TRIM: trailing dashes of the 20-character cut are dropped (an account_id cannot end in '-'); a cut
# that does not end in '-' is unchanged.
resource "google_service_account" "workload_sa" {
  project      = var.project_id
  account_id   = "sa-${replace(substr(replace(var.product_id, "_", "-"), 0, 20), "/-+$/", "")}"
  display_name = "Runtime Service Account for ${var.product_id}"
}

resource "google_project_iam_member" "workload_datastore_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.workload_sa.email}"
}

resource "google_project_iam_member" "workload_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.workload_sa.email}"
}

resource "google_project_iam_member" "workload_pubsub_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.workload_sa.email}"
}

resource "google_project_iam_member" "workload_storage_user" {
  project = var.project_id
  role    = "roles/storage.objectUser"
  member  = "serviceAccount:${google_service_account.workload_sa.email}"
}

# ------------------------------------------------------------------------------
# 3. The deployer may act only as the runtime SA and the Cloud Build SA
# ------------------------------------------------------------------------------
# `--service-account` on `gcloud run deploy` / `gcloud run jobs deploy`.
resource "google_service_account_iam_member" "deployer_runtime_sa_user" {
  count              = local.github_actions_deploy_count
  service_account_id = google_service_account.workload_sa.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.github_deployer[0].email}"
}

# `--source` submits a Cloud Build that runs as the project's default build SA
# (the Compute Engine default SA in child projects). FD-7L 2b (review F1): the project number is read from the
# project itself (a data source, known at plan time), so this grant's service_account_id is a known string that the
# platform's identity content policy checks before the apply. It used to come from the WIF pool's resource name
# (projects/<project_number>/...), which is unknown until the pool exists; the value is the same.
data "google_project" "this" {
  count      = local.github_actions_deploy_count
  project_id = var.project_id
}

resource "google_service_account_iam_member" "deployer_build_sa_user" {
  count              = local.github_actions_deploy_count
  service_account_id = "projects/${var.project_id}/serviceAccounts/${data.google_project.this[0].number}-compute@developer.gserviceaccount.com"
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.github_deployer[0].email}"
}
