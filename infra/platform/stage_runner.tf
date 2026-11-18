# ------------------------------------------------------------------------------
# STAGE-JOB-RUNNER (G7, owner 11-13 "approved! Lets do G7 into the apply.sh"; same apply.sh as LONG-STAGE-CALLBACK).
# Plan: docs/planning/stage-job-runner-plan.md. Needs core Terraform: yes (owner-approved 11-13 exception to
# POST-RC-NO-CORE-TF, together with workflows/main_orchestrator.yaml).
#
# The architect, developer and QA stages run as ONE execution each of the `stage-runner` Cloud Run Job, which runs the
# orchestrator-gateway image (`python3 -m stage_runner`). The gateway validates a stage request, stores it by
# reference in Firestore and starts the execution with env overrides (references only); the job answers the
# workflow's callback (apps/orchestrator-gateway/stage_jobs.py, stage_runner.py). A job needs no request to stay
# alive (a Cloud Run service instance without one is stopped within about 15 minutes) and is untouched by a gateway
# deploy. Precedent: tf-applier runs the mcp-terraform-server image (main.tf section 9b).
#
# Same identity, env, network and limits as the gateway service, from the same locals (below), so they cannot drift.
# Image: the gateway service's live image at creation (Terraform refreshes it from Cloud Run; the services resource
# only ignores CHANGES to it), then owned by the deploy paths (scripts/deploy-services.sh and the upgrader copy the
# gateway's image after every gateway deploy; the job refuses a gateway / job release mismatch at run time).
# ------------------------------------------------------------------------------
locals {
  stage_runner_job_name = "stage-runner"
  gateway_service_name  = "orchestrator-gateway-service"

  # The env every platform Cloud Run service gets (main.tf section 8 reads its values from here). Values exactly as
  # they were written inline in google_cloud_run_v2_service.services.
  platform_service_env = {
    ENVIRONMENT           = var.environment
    PROJECT_ID            = var.project_id
    TFSTATE_BUCKET        = data.google_storage_bucket.workload_tfstate_bucket.name
    INBOX_FOLDER_ID       = var.google_drive_intake_folder_ids
    IN_PROGRESS_FOLDER_ID = var.google_drive_in_progress_folder_ids
    COMPLETED_FOLDER_ID   = var.google_drive_completed_folder_ids
    GEMINI_LOCATION       = "global"
    # MANAGED_WORKLOADS_FOLDER_ID and FOLDER_ID: the same folder under both names (callers read either).
    MANAGED_WORKLOADS_FOLDER_ID = var.castor_managed_workloads_folder_id
    FOLDER_ID                   = var.castor_managed_workloads_folder_id
    BILLING_ACCOUNT_ID          = var.billing_account_id
    GITHUB_ORG                  = var.workloads_github_owner != "" ? var.workloads_github_owner : var.github_owner
    GITHUB_OWNER                = var.workloads_github_owner != "" ? var.workloads_github_owner : var.github_owner
    # FD-4M F6/H4: derive from the first invoker member ONLY when it is a user: principal
    # (group:/domain: members are not emails and must not become the bootstrap admin).
    ADMIN_EMAIL = var.admin_email != "" ? var.admin_email : (
      length(var.authorized_invoker_members) > 0 && startswith(try(var.authorized_invoker_members[0], ""), "user:")
      ? trimprefix(var.authorized_invoker_members[0], "user:") : ""
    )
    ENABLE_TF_APPLIER_JOB = "true"
    VCS_PROVIDER          = upper(var.vcs_provider)
    GIT_SERVER_URL        = (var.deploy_git_server || upper(var.vcs_provider) == "SERVERLESS_GIT") ? try(google_cloud_run_v2_service.git_server[0].uri, "") : ""
  }

  # GEMINI_MODEL per service (per-service override, else the install's model).
  service_gemini_model = { for k in keys(local.cloud_run_services) : k => lookup(var.gemini_model_overrides, k, var.gemini_model) }

  # The gateway's own env (lane 13 Stage A: the QA job client, qa_job_client.py QAJobConfig.REQUIRED_ENV). REGION also
  # addresses the stage-runner job (stage_jobs.run_api_starter).
  gateway_service_env = {
    REGION            = var.region
    QA_JOB_NAME       = google_cloud_run_v2_job.qa_sandbox.name
    QA_STAGING_BUCKET = google_storage_bucket.qa_staging.name
    QA_SANDBOX_SA     = google_service_account.qa_sandbox.email
  }

  # The stage-runner's env = the gateway service's env: the common map, the gateway's model, the gateway-only map and
  # whatever the per-service maps give the gateway (empty today; listed so a future gateway entry reaches the job).
  stage_runner_env = merge(
    local.platform_service_env,
    { GEMINI_MODEL = local.service_gemini_model[local.gateway_service_name] },
    local.gateway_service_env,
    { for k, v in lookup(local.guard_service_env, local.gateway_service_name, {}) : k => v if v != "" },
    { for k, v in lookup(local.tf_runner_service_env, local.gateway_service_name, {}) : k => v if v != "" },
    { for k, v in lookup(local.platform_upgrader_service_env, local.gateway_service_name, {}) : k => v if v != "" },
  )

  # The gateway's runtime identity (main.tf section 8: lookup(local.service_runtime_sa, ..., sa-castor-developer)).
  stage_runner_sa_email = lookup(local.service_runtime_sa, local.gateway_service_name, google_service_account.agents["sa-castor-developer"].email)
}

resource "google_cloud_run_v2_job" "stage_runner" {
  depends_on = [
    google_project_service.apis,
    google_artifact_registry_repository.castor_docker_repo,
    # the same grants the gateway's revisions rely on (Firestore, guard reads)
    google_project_iam_member.persona_datastore_users,
    google_project_iam_member.guard_db_readers,
  ]
  project  = var.project_id
  location = var.region
  name     = local.stage_runner_job_name

  # FD-0D: Terraform-only latch (provider default true; declared to document intent).
  deletion_protection = true

  template {
    template {
      # One execution = one stage request. No blind re-run: a retry would repeat the LLM spend and could commit twice;
      # the workflow owns retries (dispatch retry is idempotent per callback URL).
      max_retries = 0
      # The longest stage answers at accepted + 3,620 s (developer CALLBACK budget 3,600 s + 20 s grace) and delivers
      # in under 100 s: 3,800 s covers that with margin and stays below the developer's 3,900 s await bound
      # (tests/test_stage_job_runner_tf.py pins this against stage_deadline.STAGE_BUDGETS and the YAML). A task
      # timeout sends SIGTERM: the job answers STAGE_INTERRUPTED before it exits.
      timeout         = "3800s"
      service_account = local.stage_runner_sa_email

      # HOST-VPC-EGRESS (host_network.tf): the job calls what the gateway calls (git server, vending, terraform
      # server, the QA job API).
      dynamic "vpc_access" {
        for_each = local.host_vpc_access
        content {
          egress = local.host_egress_mode
          network_interfaces {
            network    = vpc_access.value.network
            subnetwork = vpc_access.value.subnetwork
          }
        }
      }

      containers {
        # The gateway's image as Cloud Run reports it now (ignored afterwards: the deploy paths own the image).
        image   = google_cloud_run_v2_service.services[local.gateway_service_name].template[0].containers[0].image
        command = ["/cnb/lifecycle/launcher"]
        args    = ["python3", "-m", "stage_runner"]

        resources {
          limits = {
            cpu    = lookup(local.cloud_run_service_cpu, local.gateway_service_name, "1000m")
            memory = lookup(local.cloud_run_service_memory, local.gateway_service_name, "1024Mi")
          }
        }

        dynamic "env" {
          for_each = local.stage_runner_env
          content {
            name  = env.key
            value = env.value
          }
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].template[0].containers[0].image,
      client,
      client_version,
    ]
  }

  labels = {
    environment = var.environment
    managed_by  = "castor-terraform"
  }
}

# The gateway starts stage-runner executions with env overrides and reads their state (the workflow's probe):
# exactly these permissions, bound on this one job only, for the gateway's identity. sa-castor-developer also holds
# project-wide roles/run.developer today (main.tf agent_run_developers); this binding keeps the stage path working
# when that is trimmed (FD-4T) and documents what the path needs. No act-as grant: running a job never needs one
# (the C10 billing-drain precedent runs the enforcer job with overrides on the same three permissions).
resource "google_project_iam_custom_role" "stage_runner_dispatcher" {
  depends_on  = [google_project_service.apis]
  project     = var.project_id
  role_id     = "stackvendStageRunnerDispatcher"
  title       = "StackVend gateway: run the stage-runner job"
  description = "STAGE-JOB-RUNNER: run the stage-runner job with env overrides and read its executions. Bound on that one job only, for the orchestrator gateway's identity."
  permissions = [
    "run.executions.get",
    "run.jobs.run",
    "run.jobs.runWithOverrides",
  ]
}

resource "google_cloud_run_v2_job_iam_member" "gateway_stage_runner_dispatcher" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.stage_runner.name
  role     = google_project_iam_custom_role.stage_runner_dispatcher.name
  member   = "serviceAccount:${local.stage_runner_sa_email}"
}
