# HOST-AUDIT-LOG-SETTING plan-level contract for infra/platform, run by tests/test_host_audit_log_setting.py.
# Every provider is MOCKED: `tofu test` evaluates the configuration in memory, with no backend, no credentials and no
# network. command = plan only.

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
}

run "default_plans_no_audit_config_and_leaves_the_sink_filter_alone" {
  command = plan

  assert {
    condition     = length(google_project_iam_audit_config.host_data_access) == 0
    error_message = "the default must plan no audit configuration"
  }

  assert {
    condition     = google_logging_project_sink.sre_error_sink.filter == "severity >= ERROR OR (resource.type=\"cloud_run_revision\" AND jsonPayload.level=\"ERROR\")"
    error_message = "the setting must not change the SRE sink filter"
  }
}

run "both_entries_plan_one_config_each" {
  command = plan

  variables {
    host_data_access_audit_logs = {
      "datastore.googleapis.com"     = "DATA_WRITE"
      "secretmanager.googleapis.com" = "DATA_READ"
    }
  }

  assert {
    condition     = length(google_project_iam_audit_config.host_data_access) == 2
    error_message = "expected one audit configuration per entry"
  }

  assert {
    condition     = one(google_project_iam_audit_config.host_data_access["datastore.googleapis.com"].audit_log_config[*].log_type) == "DATA_WRITE"
    error_message = "Firestore must log DATA_WRITE only"
  }

  assert {
    condition     = one(google_project_iam_audit_config.host_data_access["secretmanager.googleapis.com"].audit_log_config[*].log_type) == "DATA_READ"
    error_message = "Secret Manager must log DATA_READ only"
  }

  assert {
    condition     = google_project_iam_audit_config.host_data_access["datastore.googleapis.com"].project == "mock-stackvend-project"
    error_message = "the audit configuration belongs to the host project"
  }
}

run "the_firestore_api_name_is_refused" {
  command = plan

  variables {
    host_data_access_audit_logs = {
      "firestore.googleapis.com" = "DATA_WRITE"
    }
  }

  expect_failures = [var.host_data_access_audit_logs]
}

run "firestore_data_read_is_refused" {
  command = plan

  variables {
    host_data_access_audit_logs = {
      "datastore.googleapis.com" = "DATA_READ"
    }
  }

  expect_failures = [var.host_data_access_audit_logs]
}

run "all_services_is_refused" {
  command = plan

  variables {
    host_data_access_audit_logs = {
      "allServices" = "DATA_READ"
    }
  }

  expect_failures = [var.host_data_access_audit_logs]
}
