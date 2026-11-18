# STAGE-JOB-RUNNER: plan-level contract for infra/platform/stage_runner.tf and the services' env refactor, run by
# tests/test_stage_job_runner_tf.py on a COPY of the repository tree. Every provider is MOCKED (no backend, no
# credentials, no network; providers come only from a local filesystem mirror).

mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      email  = "svcacct@mock-stackvend-project.iam.gserviceaccount.com"
      member = "serviceAccount:svcacct@mock-stackvend-project.iam.gserviceaccount.com"
      name   = "projects/mock-stackvend-project/serviceAccounts/svcacct@mock-stackvend-project.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_project_service_identity" {
    defaults = {
      email  = "agent@gcp-sa-x.iam.gserviceaccount.com"
      member = "serviceAccount:agent@gcp-sa-x.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_logging_project_sink" {
    defaults = {
      writer_identity = "serviceAccount:service-123456789012@gcp-sa-logging.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_project_iam_custom_role" {
    defaults = {
      id = "projects/mock-stackvend-project/roles/mockRole"
    }
  }
  mock_data "google_project" {
    defaults = {
      number = "123456789012"
    }
  }
}
mock_provider "google-beta" {
  mock_resource "google_service_account" {
    defaults = {
      email  = "svcacct@mock-stackvend-project.iam.gserviceaccount.com"
      member = "serviceAccount:svcacct@mock-stackvend-project.iam.gserviceaccount.com"
      name   = "projects/mock-stackvend-project/serviceAccounts/svcacct@mock-stackvend-project.iam.gserviceaccount.com"
    }
  }
}
mock_provider "google" {
  alias = "host_quota"
}
mock_provider "random" {}

variables {
  project_id                         = "mock-stackvend-project"
  allow_unauthenticated              = false
  authorized_invoker_members         = ["user:admin@example.com"]
  vcs_provider                       = "SERVERLESS_GIT"
  deploy_git_server                  = true
  organization_id                    = "organizations/123456789012"
  castor_managed_workloads_folder_id = "folders/4242"
  create_stackvend_managed_tag       = true
  gemini_model_overrides             = { "orchestrator-gateway-service" = "gemini-gw-override", "mcp-gcloud-server" = "gemini-other" }
}


run "stage_runner_job_matches_the_gateway" {
  command = plan
  assert {
    condition     = google_cloud_run_v2_job.stage_runner.name == "stage-runner" && google_cloud_run_v2_job.stage_runner.deletion_protection == true
    error_message = "the stage-runner job is planned, deletion-protected"
  }
  assert {
    condition = (google_cloud_run_v2_job.stage_runner.template[0].template[0].max_retries == 0
    && google_cloud_run_v2_job.stage_runner.template[0].template[0].timeout == "3800s")
    error_message = "no retries; task timeout 3800 s"
  }
  assert {
    condition     = google_cloud_run_v2_job.stage_runner.template[0].template[0].containers[0].args == tolist(["python3", "-m", "stage_runner"])
    error_message = "the job runs the stage_runner entry point"
  }
  assert {
    condition     = google_cloud_run_v2_job.stage_runner.template[0].template[0].service_account == google_cloud_run_v2_service.services["orchestrator-gateway-service"].template[0].service_account
    error_message = "the job runs as the gateway's service account"
  }
  assert {
    condition     = google_cloud_run_v2_job.stage_runner.template[0].template[0].containers[0].resources[0].limits == google_cloud_run_v2_service.services["orchestrator-gateway-service"].template[0].containers[0].resources[0].limits
    error_message = "the job has the gateway's cpu and memory"
  }
  assert {
    condition = (toset([for e in google_cloud_run_v2_job.stage_runner.template[0].template[0].containers[0].env : e.name])
    == toset([for e in google_cloud_run_v2_service.services["orchestrator-gateway-service"].template[0].containers[0].env : e.name]))
    error_message = "the job has exactly the gateway's env names"
  }
  assert {
    condition     = { for e in google_cloud_run_v2_job.stage_runner.template[0].template[0].containers[0].env : e.name => e.value }["GEMINI_MODEL"] == "gemini-gw-override"
    error_message = "the job uses the gateway's model override"
  }
  assert {
    condition = alltrue([for k in ["ENVIRONMENT", "PROJECT_ID", "GEMINI_MODEL", "GEMINI_LOCATION", "REGION", "VCS_PROVIDER", "ENABLE_TF_APPLIER_JOB", "FOLDER_ID", "ADMIN_EMAIL"] :
      { for e in google_cloud_run_v2_job.stage_runner.template[0].template[0].containers[0].env : e.name => e.value }[k]
    == { for e in google_cloud_run_v2_service.services["orchestrator-gateway-service"].template[0].containers[0].env : e.name => e.value }[k]])
    error_message = "the job's known env values equal the gateway's"
  }
  assert {
    condition     = length(google_cloud_run_v2_job.stage_runner.template[0].template[0].vpc_access) == 1
    error_message = "the job is on the host network like the gateway"
  }
  assert {
    condition = (google_cloud_run_v2_job_iam_member.gateway_stage_runner_dispatcher.name == "stage-runner"
    && toset(google_project_iam_custom_role.stage_runner_dispatcher.permissions) == toset(["run.executions.get", "run.jobs.run", "run.jobs.runWithOverrides"]))
    error_message = "the dispatcher role has exactly three permissions and is bound on the stage-runner job only"
  }
  assert {
    condition     = google_cloud_run_v2_job_iam_member.gateway_stage_runner_dispatcher.member == "serviceAccount:${google_cloud_run_v2_service.services["orchestrator-gateway-service"].template[0].service_account}"
    error_message = "the binding is for the gateway's identity"
  }
}

run "services_env_order_and_values_unchanged" {
  command = plan
  assert {
    condition = (toset([for e in google_cloud_run_v2_service.services["orchestrator-gateway-service"].template[0].containers[0].env : e.name])
      == toset(["ENVIRONMENT", "PROJECT_ID", "TFSTATE_BUCKET", "INBOX_FOLDER_ID", "IN_PROGRESS_FOLDER_ID", "COMPLETED_FOLDER_ID", "GEMINI_MODEL",
        "GEMINI_LOCATION", "MANAGED_WORKLOADS_FOLDER_ID", "FOLDER_ID", "BILLING_ACCOUNT_ID", "GITHUB_ORG", "GITHUB_OWNER", "ADMIN_EMAIL",
    "ENABLE_TF_APPLIER_JOB", "VCS_PROVIDER", "GIT_SERVER_URL", "REGION", "QA_JOB_NAME", "QA_STAGING_BUCKET", "QA_SANDBOX_SA"]))
    error_message = "the gateway's env names are those of the inline blocks before the refactor (env is a set on google-beta)"
  }
  assert {
    condition = (toset([for e in google_cloud_run_v2_service.services["mcp-gcloud-server"].template[0].containers[0].env : e.name])
      == toset(["ENVIRONMENT", "PROJECT_ID", "TFSTATE_BUCKET", "INBOX_FOLDER_ID", "IN_PROGRESS_FOLDER_ID", "COMPLETED_FOLDER_ID", "GEMINI_MODEL",
        "GEMINI_LOCATION", "MANAGED_WORKLOADS_FOLDER_ID", "FOLDER_ID", "BILLING_ACCOUNT_ID", "GITHUB_ORG", "GITHUB_OWNER", "ADMIN_EMAIL",
    "ENABLE_TF_APPLIER_JOB", "VCS_PROVIDER", "GIT_SERVER_URL"]))
    error_message = "an ordinary service keeps the common env only"
  }
  assert {
    condition = ({ for e in google_cloud_run_v2_service.services["mcp-gcloud-server"].template[0].containers[0].env : e.name => e.value }["GEMINI_MODEL"] == "gemini-other"
      && { for e in google_cloud_run_v2_service.services["mcp-agent-builder-server"].template[0].containers[0].env : e.name => e.value }["GEMINI_MODEL"] == var.gemini_model
      && { for e in google_cloud_run_v2_service.services["mcp-gcloud-server"].template[0].containers[0].env : e.name => e.value }["PROJECT_ID"] == var.project_id
      && { for e in google_cloud_run_v2_service.services["mcp-gcloud-server"].template[0].containers[0].env : e.name => e.value }["ADMIN_EMAIL"] == "admin@example.com"
    && { for e in google_cloud_run_v2_service.services["orchestrator-gateway-service"].template[0].containers[0].env : e.name => e.value }["REGION"] == var.region)
    error_message = "per-service model, project, derived admin email and the gateway's region are as before"
  }
}
