# SELFUP-B BL-2: run by tests/test_selfup_platform_upgrader.py on a tree whose scripts/release/allowed_signers is
# missing, empty or holds no valid key line. With the upgrader enabled the plan must stop at the trigger's
# precondition: the trigger is never created with an empty trust set.

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

override_data {
  target = data.google_project.platform_project
  values = { number = "123456789012" }
}

variables {
  project_id                         = "mock-stackvend-project"
  region                             = "us-central1"
  organization_id                    = "organizations/111111111111"
  castor_managed_workloads_folder_id = "folders/222222222222"
  vcs_provider                       = "SERVERLESS_GIT"
  deploy_git_server                  = true
  cc_google_oauth_client_id          = "123456789012-mockcontrolcenter.apps.googleusercontent.com"
  enable_platform_upgrader           = true
}

run "no_trust_set_refuses_the_plan" {
  command = plan

  expect_failures = [
    google_cloudbuild_trigger.platform_upgrade,
  ]
}
