# ==============================================================================
# Lane 13 Stage A (FD-4F, register row 19 option A): isolated QA job infrastructure
# ==============================================================================
# Trust model (apps/orchestrator-gateway/qa_job_client.py):
#   * The gateway (orchestrator-gateway-service, runtime SA sa-castor-developer) stages the commit-bound source
#     tarball in the staging bucket, mints short-lived V4 signed URLs (one GET for the source, two create-only PUTs
#     for static.json / report.json), runs ONE execution of qa-sandbox-test-runner with those URLs as env overrides,
#     reads the execution/task result and the two artifacts with its own credentials, and writes the QA evidence to
#     Firestore (qa_test_runs/{trace_id}, the existing (default) database; datastore.user is already granted).
#   * The job runs untrusted generated code as sa-castor-qa-sandbox, which holds NO roles anywhere (lane 19 L19-0b).
#     It writes no Firestore and sends no callback: everything it can touch is the three signed URLs.
#   * Before staging any code the gateway checks the job template (verify_job_identity): serviceAccount ==
#     QA_SANDBOX_SA, maxRetries == 0, exactly one container with no env, task timeout <= 900 s. Any drift answers
#     GATE_UNAVAILABLE QA_JOB_DRIFT, never a pass.
# Existing grants this relies on (unchanged here): sa-castor-developer's project-level roles/run.developer
# (run.jobs.runWithOverrides, executions get/cancel, tasks list) and roles/datastore.user.

locals {
  # The gateway's QA_JOB_NAME. Listed in local.cloud_run_jobs (inventory) but excluded from the generic jobs resource.
  qa_job_name = "qa-sandbox-test-runner"
}

# Staging bucket: tenant source tarballs + job artifacts, ephemeral by design.
resource "google_storage_bucket" "qa_staging" {
  depends_on                  = [google_project_service.apis]
  project                     = var.project_id
  name                        = "castor-qa-staging-${var.project_id}"
  location                    = var.region
  force_destroy               = false
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  # Objects are create-only (ifGenerationMatch=0); no versions to keep.
  versioning {
    enabled = false
  }

  # Deleted objects are not retained (no 7-day soft-delete copy of tenant source).
  soft_delete_policy {
    retention_duration_seconds = 0
  }

  # A QA run reads its artifacts within minutes (signed URLs live <= 25 min; evidence is copied to Firestore).
  lifecycle_rule {
    condition {
      age = 1
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

# The gateway's runtime SA: create (upload + signed create-only PUTs) and read (artifacts + signed GET).
# No delete/overwrite (objectAdmin is not needed: the lifecycle rule deletes). Nothing for the sandbox SA.
resource "google_storage_bucket_iam_member" "qa_staging_gateway" {
  for_each = toset(["roles/storage.objectCreator", "roles/storage.objectViewer"])
  bucket   = google_storage_bucket.qa_staging.name
  role     = each.key
  member   = google_service_account.agents["sa-castor-developer"].member
}

# V4 signed URLs from Cloud Run need IAM signBlob as the runtime SA itself (GcsStore.sign passes
# service_account_email + access_token). Scoped to that one SA, granted to itself: no new identity is reachable.
resource "google_service_account_iam_member" "gateway_self_sign_blob" {
  service_account_id = google_service_account.agents["sa-castor-developer"].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = google_service_account.agents["sa-castor-developer"].member
}

# The QA job, adopted from the generic jobs map (same name, same live job: moved, never replaced).
moved {
  from = google_cloud_run_v2_job.jobs["qa-sandbox-test-runner"]
  to   = google_cloud_run_v2_job.qa_sandbox
}

resource "google_cloud_run_v2_job" "qa_sandbox" {
  depends_on = [google_project_service.apis, google_artifact_registry_repository.castor_docker_repo]
  project    = var.project_id
  location   = var.region
  name       = local.qa_job_name

  # FD-0D: Terraform-only latch (provider default true; declared to document intent).
  deletion_protection = true

  template {
    task_count = 1

    template {
      service_account = google_service_account.qa_sandbox.email
      # FD-09: max_retries belongs on the TASK template. A retried execution is GATE_UNAVAILABLE to the gateway.
      max_retries = 0
      # qa_job_client.JOB_TASK_TIMEOUT_S (the client also sends it as a per-run override).
      timeout = "900s"

      containers {
        # Initial image only: the deploy paths own the image (Cloud Build `run jobs update --image`,
        # deploy-services.sh `run jobs deploy --source`, neither passes SA/retries/timeout/env flags; both also set
        # the stackvend-qa-job-contract label, row L3-PRB-r). If a deploy
        # ever changed them, verify_job_identity refuses to stage code (QA_JOB_DRIFT) and the next apply restores them.
        image   = var.placeholder_container_image
        command = ["/cnb/lifecycle/launcher"]
        args    = ["python3", "-m", "sandbox_job"]

        resources {
          limits = {
            cpu    = "2000m"
            memory = "4096Mi"
          }
        }

        # No env blocks, on purpose: every per-run value arrives as an execution override from the gateway, and
        # verify_job_identity refuses a template that carries env.
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].template[0].containers[0].image,
      client,
      client_version,
      # Row L3-PRB-r: the image deploy paths own this label (they set it in the same call that ships the image:
      # scripts/deploy-services.sh, the upgrader); readiness checks it. Terraform keeps managing every other label.
      labels["stackvend-qa-job-contract"],
      # 10-13: `gcloud run jobs update --update-labels` (deploy-services.sh) also copies the job labels onto
      # the execution template; Terraform never sets template labels, so it must not strip them on every apply.
      template[0].labels,
    ]
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}
