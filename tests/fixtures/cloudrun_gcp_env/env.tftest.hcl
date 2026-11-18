# CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV: plan-level check of infra/modules/compute-cloudrun with MOCK providers (no
# credentials, no API calls). Run by tests/test_cloudrun_google_cloud_project_env.py from a copy of the module.

mock_provider "google" {}
mock_provider "google-beta" {
  mock_data "google_project" {
    defaults = { number = "123" }
  }
}

variables {
  project_id            = "p-test"
  product_id            = "prod"
  region                = "us-central1"
  service_account_email = "sa@p-test.iam.gserviceaccount.com"
  allow_unauthenticated = true
}

run "no_caller_key_sets_the_project" {
  command = plan
  assert {
    condition     = length([for e in google_cloud_run_v2_service.app.template[0].containers[0].env : e if e.name == "GOOGLE_CLOUD_PROJECT"]) == 1
    error_message = "expected exactly one GOOGLE_CLOUD_PROJECT entry"
  }
  assert {
    condition     = [for e in google_cloud_run_v2_service.app.template[0].containers[0].env : e.value if e.name == "GOOGLE_CLOUD_PROJECT"][0] == "p-test"
    error_message = "GOOGLE_CLOUD_PROJECT must be var.project_id"
  }
}

run "caller_key_is_the_single_entry" {
  command = plan
  variables {
    env_vars = { GOOGLE_CLOUD_PROJECT = "caller-value", OTHER = "x" }
  }
  assert {
    condition     = length([for e in google_cloud_run_v2_service.app.template[0].containers[0].env : e if e.name == "GOOGLE_CLOUD_PROJECT"]) == 1
    error_message = "a caller GOOGLE_CLOUD_PROJECT must not be doubled by the module"
  }
  assert {
    condition     = [for e in google_cloud_run_v2_service.app.template[0].containers[0].env : e.value if e.name == "GOOGLE_CLOUD_PROJECT"][0] == "caller-value"
    error_message = "the caller's value must be the one entry"
  }
}

run "other_caller_keys_keep_the_project" {
  command = plan
  variables {
    env_vars = { PUBSUB_TOPIC_ID = "events", PROJECT_ID = "p-test" }
  }
  assert {
    condition     = [for e in google_cloud_run_v2_service.app.template[0].containers[0].env : e.value if e.name == "GOOGLE_CLOUD_PROJECT"] == ["p-test"]
    error_message = "GOOGLE_CLOUD_PROJECT must still be set once"
  }
}
