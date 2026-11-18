# FD-4AS-c plan-level contract for infra/platform (topic-level Pub/Sub publishers), run by
# tests/test_fd4as_c_topic_publishers.py. Every provider is MOCKED (no backend, no credentials, no network; providers
# come only from a local filesystem mirror). Same mock header as tests/fixtures/lane18_s0/lane18_s0.tftest.hcl.

mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      member = "serviceAccount:mock-sa@mock-stackvend-project.iam.gserviceaccount.com"
      # FD-7L (SAT-33): google_service_account_iam_member.service_account_id is provider-validated.
      name = "projects/mock-stackvend-project/serviceAccounts/mock-sa@mock-stackvend-project.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_logging_project_sink" {
    defaults = {
      writer_identity = "serviceAccount:mock-sink@mock-stackvend-project.iam.gserviceaccount.com"
    }
  }
}
mock_provider "google-beta" {}
# ORG-POLICY-FOLDER: the host-quota google alias (providers.tf) used only by google_org_policy_policy.managed_folder_vm_external_ip.
mock_provider "google" {
  alias = "host_quota"
}
mock_provider "random" {}

override_resource {
  target = google_service_account.agents["sa-castor-developer"]
  values = { email = "sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com", name = "projects/mock-stackvend-project/serviceAccounts/sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com" }
}
override_resource {
  target = google_service_account.agents["sa-castor-sre"]
  values = { email = "sa-castor-sre@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-castor-sre@mock-stackvend-project.iam.gserviceaccount.com" }
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
  target = google_service_account.stackvend_personas["sa-stackvend-sandbox-cleaner"]
  values = { email = "sa-stackvend-sandbox-cleaner@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-stackvend-sandbox-cleaner@mock-stackvend-project.iam.gserviceaccount.com" }
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
}

# Fresh install: one apply on empty state creates every topic-level grant (no ordering failure) and each grant
# names exactly the identity that runs the publishing code.
run "fresh_install_topic_publishers" {
  command = apply

  assert {
    condition     = google_pubsub_topic_iam_member.spec_ingestion_spec_intake_publisher.member == "serviceAccount:${google_cloud_run_v2_service.services["spec-ingestion-service"].template[0].service_account}"
    error_message = "the spec-intake grant must follow the spec-ingestion service's runtime SA"
  }
  assert {
    condition     = google_pubsub_topic_iam_member.cc_spec_intake_publisher.member == "serviceAccount:${google_cloud_run_v2_service.services["product-control-center-ui"].template[0].service_account}"
    error_message = "the CC spec-intake grant must follow the Control Center's runtime SA"
  }
  assert {
    condition     = google_pubsub_topic_iam_member.sre_remediation_spec_intake_publisher.member == "serviceAccount:sa-castor-sre@mock-stackvend-project.iam.gserviceaccount.com"
    error_message = "the SRE remediation workflow SA publishes remediation requests"
  }
  assert {
    condition = alltrue([
      for r in [google_pubsub_topic_iam_member.spec_ingestion_spec_intake_publisher, google_pubsub_topic_iam_member.cc_spec_intake_publisher, google_pubsub_topic_iam_member.sre_remediation_spec_intake_publisher] :
      r.topic == google_pubsub_topic.spec_intake_events.name && r.role == "roles/pubsub.publisher"
    ])
    error_message = "spec-intake publishers are topic-level on spec-intake-events"
  }
  assert {
    condition     = google_pubsub_topic_iam_member.refactor_scanner_publisher.member == "serviceAccount:${google_cloud_run_v2_job.jobs["github-refactor-scanner-job"].template[0].template[0].service_account}" && google_pubsub_topic_iam_member.refactor_scanner_publisher.topic == google_pubsub_topic.autonomous_refactor_events.name
    error_message = "the refactor scanner job publishes only to autonomous-refactor-events, as its runtime SA"
  }
  assert {
    condition     = google_pubsub_topic_iam_member.orchestrator_dlq_publisher.member == "serviceAccount:sa-castor-architect@mock-stackvend-project.iam.gserviceaccount.com" && google_pubsub_topic_iam_member.orchestrator_dlq_publisher.topic == google_pubsub_topic.castor_dlq.name
    error_message = "the main orchestrator workflow SA publishes only to castor-dlq"
  }
  assert {
    condition     = google_pubsub_topic.spec_intake_events.name == "spec-intake-events" && google_pubsub_topic.autonomous_refactor_events.name == "autonomous-refactor-events" && google_pubsub_topic.castor_dlq.name == "castor-dlq"
    error_message = "topic names are the ones the code publishes to"
  }
}
