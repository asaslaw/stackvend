# FD-7L Phase 7 (SAT-33) + FD-7L-n (SAT-35) + FD-4DA stamp: plan-level contract for infra/platform, run by
# tests/test_fd7l_platform_runner_identity.py. Every provider is MOCKED (no backend, no credentials, no network;
# providers come only from a local filesystem mirror). Mock header as tests/fixtures/lane18_s0/lane18_s0.tftest.hcl.

mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      member = "serviceAccount:mock-sa@mock-stackvend-project.iam.gserviceaccount.com"
      name   = "projects/mock-stackvend-project/serviceAccounts/mock-sa@mock-stackvend-project.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_logging_project_sink" {
    defaults = {
      writer_identity = "serviceAccount:mock-sink@mock-stackvend-project.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_project_iam_custom_role" {
    defaults = {
      id = "projects/mock-stackvend-project/roles/mockRole"
    }
  }
}
mock_provider "google-beta" {}
mock_provider "google" {
  alias = "host_quota"
}
mock_provider "random" {}

override_resource {
  target = google_service_account.agents["sa-castor-developer"]
  values = { email = "sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com", name = "projects/mock-stackvend-project/serviceAccounts/sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com" }
}
override_resource {
  target = google_service_account.agents["sa-castor-architect"]
  values = { email = "sa-castor-architect@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-castor-architect@mock-stackvend-project.iam.gserviceaccount.com" }
}
override_resource {
  target = google_service_account.agents["sa-project-provisioner"]
  values = { email = "sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com", name = "projects/mock-stackvend-project/serviceAccounts/sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com" }
}
override_resource {
  target = google_service_account.stackvend_personas["sa-stackvend-control-center"]
  values = { email = "sa-stackvend-control-center@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-stackvend-control-center@mock-stackvend-project.iam.gserviceaccount.com" }
}
override_resource {
  target = google_service_account.tf_runners["sa-stackvend-tf-applier"]
  values = { email = "sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com", name = "projects/mock-stackvend-project/serviceAccounts/sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com" }
}
override_resource {
  target = google_service_account.tf_runners["sa-stackvend-tf-server"]
  values = { email = "sa-stackvend-tf-server@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-stackvend-tf-server@mock-stackvend-project.iam.gserviceaccount.com", name = "projects/mock-stackvend-project/serviceAccounts/sa-stackvend-tf-server@mock-stackvend-project.iam.gserviceaccount.com" }
}
override_resource {
  target = google_project_iam_custom_role.stackvend_workflow_callback
  values = { id = "projects/mock-stackvend-project/roles/stackvendWorkflowCallback" }
}
override_resource {
  target = google_project_iam_custom_role.stackvend_staging_create
  values = { id = "projects/mock-stackvend-project/roles/stackvendStagingCreate" }
}
override_data {
  target = data.google_project.platform_project
  values = { number = "123456789012" }
}
override_resource {
  target = google_tags_tag_value.stackvend_managed_true[0]
  values = { name = "281478392000", id = "tagValues/281478392000" }
}

variables {
  project_id                         = "mock-stackvend-project"
  region                             = "us-central1"
  organization_id                    = "organizations/111111111111"
  castor_managed_workloads_folder_id = "folders/222222222222"
  vcs_provider                       = "SERVERLESS_GIT"
  deploy_git_server                  = true
  cc_google_oauth_client_id          = "123456789012-mockcontrolcenter.apps.googleusercontent.com"
  stackvend_platform_commit          = "0123456789abcdef0123456789abcdef01234567"
}

# STEP A (defaults): the runners keep sa-castor-developer; the new SAs, roles, grants, bucket and env exist.
run "step_a_defaults_are_additive_and_inert" {
  command = apply

  assert {
    condition = (
      google_cloud_run_v2_job.tf_applier.template[0].template[0].service_account == "sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com"
      && google_cloud_run_v2_service.services["mcp-terraform-server"].template[0].service_account == "sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com"
      && google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].service_account == "sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com"
    )
    error_message = "step A must not move any runtime identity"
  }
  assert {
    condition     = keys(google_service_account.tf_runners) == ["sa-stackvend-tf-applier", "sa-stackvend-tf-server"]
    error_message = "exactly the two runner SAs (owner D1)"
  }
  assert {
    condition = (
      google_project_iam_custom_role.stackvend_workflow_callback.permissions == toset(["workflows.callbacks.send"])
      && google_project_iam_custom_role.stackvend_staging_create.permissions == toset(["storage.objects.create"])
    )
    error_message = "custom roles carry exactly one permission each"
  }
  assert {
    condition = (
      { for k, m in google_project_iam_member.tf_runner_project_roles : k => "${m.role} ${m.member}" } == {
        "job-log-writer"           = "roles/logging.logWriter serviceAccount:sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com"
        "job-workflow-callback"    = "projects/mock-stackvend-project/roles/stackvendWorkflowCallback serviceAccount:sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com"
        "server-log-writer"        = "roles/logging.logWriter serviceAccount:sa-stackvend-tf-server@mock-stackvend-project.iam.gserviceaccount.com"
        "server-workflow-callback" = "projects/mock-stackvend-project/roles/stackvendWorkflowCallback serviceAccount:sa-stackvend-tf-server@mock-stackvend-project.iam.gserviceaccount.com"
      }
    )
    error_message = "exact host project roles of the runner SAs"
  }
  assert {
    condition = (
      alltrue([for m in google_project_iam_member.tf_runner_datastore_users : m.role == "roles/datastore.user" && m.condition[0].title == "stackvend-not-guard-db"])
      && alltrue([for m in google_project_iam_member.tf_runner_guard_db_readers : m.role == "roles/datastore.viewer" && m.condition[0].title == "stackvend-guard-db-read"])
      && keys(google_project_iam_member.tf_runner_datastore_users) == ["job", "server"]
      && keys(google_project_iam_member.tf_runner_guard_db_readers) == ["job", "server"]
    )
    error_message = "default DB write (not the guard DB) and guard DB read only, for both runner SAs"
  }
  assert {
    condition = (
      { for k, m in google_cloud_run_v2_service_iam_member.tf_runner_invokers : k => "${m.name} ${m.role} ${m.member}" } == {
        "job:mcp-compliance-server"           = "mcp-compliance-server roles/run.invoker serviceAccount:sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com"
        "job:project-repo-vending-service"    = "project-repo-vending-service roles/run.invoker serviceAccount:sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com"
        "server:project-repo-vending-service" = "project-repo-vending-service roles/run.invoker serviceAccount:sa-stackvend-tf-server@mock-stackvend-project.iam.gserviceaccount.com"
      }
      && google_cloud_run_v2_service_iam_member.tf_runner_git_server_invoker[0].member == "serviceAccount:sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com"
    )
    error_message = "exact Cloud Run invoker grants of the runner SAs"
  }
  assert {
    condition = (
      google_storage_bucket.tf_runner_staging.name == "stackvend-runner-staging-mock-stackvend-project"
      && google_storage_bucket.tf_runner_staging.public_access_prevention == "enforced"
      && google_storage_bucket.tf_runner_staging.uniform_bucket_level_access
      && google_storage_bucket_iam_member.tf_runner_staging_job_reader.role == "roles/storage.objectViewer"
      && google_storage_bucket_iam_member.tf_runner_staging_job_reader.member == "serviceAccount:sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com"
      && google_storage_bucket_iam_member.tf_runner_staging_server_create.role == "projects/mock-stackvend-project/roles/stackvendStagingCreate"
      && google_storage_bucket_iam_member.tf_runner_staging_server_create.member == "serviceAccount:sa-stackvend-tf-server@mock-stackvend-project.iam.gserviceaccount.com"
    )
    error_message = "staging bucket: server create-only, job read-only"
  }
  assert {
    condition = (
      length(google_service_account_iam_member.vending_self_sign_blob) == 1
      && google_service_account_iam_member.vending_self_sign_blob[0].role == "roles/iam.serviceAccountTokenCreator"
      && google_service_account_iam_member.vending_self_sign_blob[0].member == "serviceAccount:sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com"
      && google_service_account_iam_member.vending_self_sign_blob[0].service_account_id == "projects/mock-stackvend-project/serviceAccounts/sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com"
      && length(google_service_account_iam_member.vending_act_as_tf_applier) == 0
    )
    error_message = "vending signs as itself only; no act-as on the job SA by default"
  }
  assert {
    condition = {
      for e in google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].containers[0].env : e.name => e.value
      if contains(["STACKVEND_TF_RUNNER_IDENTITY", "STACKVEND_BROKER_SA", "STACKVEND_TF_RUNNER_MEMBERS", "STACKVEND_TF_SERVER_MEMBERS", "STACKVEND_RUNNER_STAGING_BUCKET"], e.name)
      } == {
      STACKVEND_TF_RUNNER_IDENTITY    = "PLATFORM"
      STACKVEND_BROKER_SA             = "sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com"
      STACKVEND_TF_RUNNER_MEMBERS     = "sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com,sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com"
      STACKVEND_TF_SERVER_MEMBERS     = "sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com,sa-stackvend-tf-server@mock-stackvend-project.iam.gserviceaccount.com"
      STACKVEND_RUNNER_STAGING_BUCKET = "stackvend-runner-staging-mock-stackvend-project"
    }
    error_message = "step A vending env: Shared mode, broker = vending, both lists = {developer, new SA} (re-RT R4)"
  }
  assert {
    condition = {
      for e in google_cloud_run_v2_service.services["mcp-terraform-server"].template[0].containers[0].env : e.name => e.value
      if contains(["STACKVEND_TF_RUNNER_IDENTITY", "STACKVEND_BROKER_SA", "VENDING_SERVICE_URL", "TF_SERVER_WORKLOAD_CALLERS", "STACKVEND_RUNNER_STAGING_BUCKET", "STACKVEND_GUARD_FIRESTORE_DATABASE"], e.name)
      } == {
      STACKVEND_TF_RUNNER_IDENTITY       = "PLATFORM"
      STACKVEND_BROKER_SA                = "sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com"
      VENDING_SERVICE_URL                = "https://project-repo-vending-service-123456789012.us-central1.run.app"
      TF_SERVER_WORKLOAD_CALLERS         = "sa-castor-architect@mock-stackvend-project.iam.gserviceaccount.com,sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com,sa-stackvend-control-center@mock-stackvend-project.iam.gserviceaccount.com,sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com"
      STACKVEND_RUNNER_STAGING_BUCKET    = "stackvend-runner-staging-mock-stackvend-project"
      STACKVEND_GUARD_FIRESTORE_DATABASE = "stackvend-guard"
    }
    error_message = "step A terraform server env"
  }
  assert {
    condition = {
      for e in google_cloud_run_v2_job.tf_applier.template[0].template[0].containers[0].env : e.name => e.value
      if contains(["STACKVEND_TF_RUNNER_IDENTITY", "STACKVEND_BROKER_SA", "VENDING_SERVICE_URL", "STACKVEND_RUNNER_STAGING_BUCKET", "STACKVEND_GUARD_FIRESTORE_DATABASE"], e.name)
      } == {
      STACKVEND_TF_RUNNER_IDENTITY       = "PLATFORM"
      STACKVEND_BROKER_SA                = "sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com"
      VENDING_SERVICE_URL                = "https://project-repo-vending-service-123456789012.us-central1.run.app"
      STACKVEND_RUNNER_STAGING_BUCKET    = "stackvend-runner-staging-mock-stackvend-project"
      STACKVEND_GUARD_FIRESTORE_DATABASE = "stackvend-guard"
    }
    error_message = "step A tf-applier env"
  }
  assert {
    condition = {
      for e in google_cloud_run_v2_job.jobs["infra-rollback-job"].template[0].template[0].containers[0].env : e.name => e.value
      if contains(["STACKVEND_TF_RUNNER_IDENTITY", "STACKVEND_BROKER_SA", "STACKVEND_GUARD_FIRESTORE_DATABASE"], e.name)
      } == {
      STACKVEND_TF_RUNNER_IDENTITY       = "PLATFORM"
      STACKVEND_BROKER_SA                = "sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com"
      STACKVEND_GUARD_FIRESTORE_DATABASE = "stackvend-guard"
    }
    error_message = "step A infra-rollback-job env (rollback.py resolve_state_bucket reads all three)"
  }
  assert {
    condition = alltrue([
      for k, j in google_cloud_run_v2_job.jobs : length([
        for e in j.template[0].template[0].containers[0].env : e if contains(["STACKVEND_TF_RUNNER_IDENTITY", "STACKVEND_BROKER_SA"], e.name)
      ]) == 0 if k != "infra-rollback-job"
    ])
    error_message = "step A gives the runner-identity env to no other platform job"
  }
  assert {
    condition     = length([for e in google_cloud_run_v2_service.git_server[0].template[0].containers[0].env : e if e.name == "GIT_SERVER_READONLY_INVOKERS"]) == 0
    error_message = "step A does not touch the git server env"
  }
  assert {
    condition = (
      google_cloud_run_v2_service.services["product-control-center-ui"].annotations == {
        "stackvend/platform-release" = "0.9.0-preview"
        "stackvend/platform-commit"  = "0123456789abcdef0123456789abcdef01234567"
      }
      && alltrue([for k, s in google_cloud_run_v2_service.services : s.annotations == null if k != "product-control-center-ui"])
    )
    error_message = "the platform stamp is two service-level annotations on the Control Center only"
  }
}

# STEP B: runtimes move, lists narrow, git server read-only class.
run "step_b_moves_the_runners" {
  command = apply

  variables {
    tf_runner_identity     = "PER_WORKLOAD"
    tf_runner_dedicated_sa = true
  }

  assert {
    condition = (
      google_cloud_run_v2_job.tf_applier.template[0].template[0].service_account == "sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com"
      && google_cloud_run_v2_service.services["mcp-terraform-server"].template[0].service_account == "sa-stackvend-tf-server@mock-stackvend-project.iam.gserviceaccount.com"
      && alltrue([for k, s in google_cloud_run_v2_service.services : s.template[0].service_account != "sa-stackvend-tf-server@mock-stackvend-project.iam.gserviceaccount.com" if k != "mcp-terraform-server"])
    )
    error_message = "step B moves only the terraform server and the tf-applier job"
  }
  assert {
    condition = {
      for e in google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].containers[0].env : e.name => e.value
      if contains(["STACKVEND_TF_RUNNER_IDENTITY", "STACKVEND_TF_RUNNER_MEMBERS", "STACKVEND_TF_SERVER_MEMBERS"], e.name)
      } == {
      STACKVEND_TF_RUNNER_IDENTITY = "PER_WORKLOAD"
      STACKVEND_TF_RUNNER_MEMBERS  = "sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com"
      STACKVEND_TF_SERVER_MEMBERS  = "sa-stackvend-tf-server@mock-stackvend-project.iam.gserviceaccount.com"
    }
    error_message = "step B narrows both member lists to the new SAs"
  }
  assert {
    condition     = [for e in google_cloud_run_v2_service.git_server[0].template[0].containers[0].env : e.value if e.name == "GIT_SERVER_READONLY_INVOKERS"] == ["sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com"]
    error_message = "step B lists the job SA as a read-only git invoker"
  }
  assert {
    condition     = [for e in google_cloud_run_v2_service.git_server[0].template[0].containers[0].env : e.value if e.name == "GIT_SERVER_ALLOWED_INVOKERS"] == ["sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com,sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com,sa-stackvend-control-center@mock-stackvend-project.iam.gserviceaccount.com"]
    error_message = "the read-write git invoker list is unchanged (the job SA is never in it)"
  }
}

# ROLLBACK: the lever back to false restores step A exactly.
run "rollback_lever_restores_step_a" {
  command = apply

  variables {
    tf_runner_identity     = "PER_WORKLOAD"
    tf_runner_dedicated_sa = false
  }

  assert {
    condition = (
      google_cloud_run_v2_job.tf_applier.template[0].template[0].service_account == "sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com"
      && google_cloud_run_v2_service.services["mcp-terraform-server"].template[0].service_account == "sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com"
      && length([for e in google_cloud_run_v2_service.git_server[0].template[0].containers[0].env : e if e.name == "GIT_SERVER_READONLY_INVOKERS"]) == 0
    )
    error_message = "tf_runner_dedicated_sa = false puts both runners back on sa-castor-developer"
  }
}

# Step B is refused on a Shared install (FD-7L-n).
run "step_b_refused_on_a_shared_install" {
  command = plan

  variables {
    tf_runner_identity     = "PLATFORM"
    tf_runner_dedicated_sa = true
  }

  expect_failures = [
    google_cloud_run_v2_job.tf_applier,
    google_cloud_run_v2_service.services,
  ]
}

# Phase 0 lever: vending act-as on the job SA, nothing else.
run "vending_act_as_lever" {
  command = apply

  variables {
    tf_runner_vending_act_as = true
  }

  assert {
    condition = (
      length(google_service_account_iam_member.vending_act_as_tf_applier) == 1
      && google_service_account_iam_member.vending_act_as_tf_applier[0].role == "roles/iam.serviceAccountUser"
      && google_service_account_iam_member.vending_act_as_tf_applier[0].member == "serviceAccount:sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com"
      && google_service_account_iam_member.vending_act_as_tf_applier[0].service_account_id == "projects/mock-stackvend-project/serviceAccounts/sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com"
    )
    error_message = "the act-as lever grants exactly vending serviceAccountUser on the job SA"
  }
}
