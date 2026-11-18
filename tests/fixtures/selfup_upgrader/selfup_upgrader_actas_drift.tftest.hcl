# SELFUP-B M-4: run by tests/test_selfup_platform_upgrader.py on a tree whose platform_upgrader.tf act-as list lost one
# runtime account (the harness removes the sandbox cleaner line). The plan must stop at the trigger precondition:
# a component the upgrader could not redeploy is a loud failure, never a silently broken upgrade.

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
  values = { email = "sa-castor-architect@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-castor-architect@mock-stackvend-project.iam.gserviceaccount.com", name = "projects/mock-stackvend-project/serviceAccounts/sa-castor-architect@mock-stackvend-project.iam.gserviceaccount.com" }
}
override_resource {
  target = google_service_account.agents["sa-project-provisioner"]
  values = { email = "sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com", name = "projects/mock-stackvend-project/serviceAccounts/sa-project-provisioner@mock-stackvend-project.iam.gserviceaccount.com" }
}
override_resource {
  target = google_service_account.stackvend_personas["sa-stackvend-control-center"]
  values = { email = "sa-stackvend-control-center@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-stackvend-control-center@mock-stackvend-project.iam.gserviceaccount.com", name = "projects/mock-stackvend-project/serviceAccounts/sa-stackvend-control-center@mock-stackvend-project.iam.gserviceaccount.com" }
}
override_resource {
  target = google_service_account.stackvend_personas["sa-stackvend-sandbox-cleaner"]
  values = { email = "sa-stackvend-sandbox-cleaner@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-stackvend-sandbox-cleaner@mock-stackvend-project.iam.gserviceaccount.com", name = "projects/mock-stackvend-project/serviceAccounts/sa-stackvend-sandbox-cleaner@mock-stackvend-project.iam.gserviceaccount.com" }
}
override_resource {
  target = google_service_account.qa_sandbox
  values = { email = "sa-castor-qa-sandbox@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-castor-qa-sandbox@mock-stackvend-project.iam.gserviceaccount.com", name = "projects/mock-stackvend-project/serviceAccounts/sa-castor-qa-sandbox@mock-stackvend-project.iam.gserviceaccount.com" }
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
  target = google_service_account.stackvend_upgrader[0]
  values = { email = "sa-stackvend-upgrader@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-stackvend-upgrader@mock-stackvend-project.iam.gserviceaccount.com", name = "projects/mock-stackvend-project/serviceAccounts/sa-stackvend-upgrader@mock-stackvend-project.iam.gserviceaccount.com", id = "projects/mock-stackvend-project/serviceAccounts/sa-stackvend-upgrader@mock-stackvend-project.iam.gserviceaccount.com" }
}
override_resource {
  target = google_project_iam_custom_role.stackvend_upgrader_deploy[0]
  values = { id = "projects/mock-stackvend-project/roles/stackvendPlatformUpgraderDeploy" }
}
override_resource {
  target = google_pubsub_topic.platform_upgrade[0]
  values = { id = "projects/mock-stackvend-project/topics/stackvend-platform-upgrade" }
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
  enable_platform_upgrader           = true
}

run "actas_drift_refuses_the_plan" {
  command = plan

  expect_failures = [
    google_cloudbuild_trigger.platform_upgrade,
  ]
}
