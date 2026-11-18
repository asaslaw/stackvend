# SELFUP-B (P3b): plan-level contract for infra/platform/platform_upgrader.tf, run by
# tests/test_selfup_platform_upgrader.py on a COPY of the repository tree in which the harness has (a) written a test
# scripts/release/allowed_signers, (b) replaced the step-0 placeholder with a stand-in script and (c) set a test image
# digest. Every provider is MOCKED (no backend, no credentials, no network; providers come only from a local
# filesystem mirror). Mock header as tests/fixtures/fd7l_tf/fd7l_tf.tftest.hcl.

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
  stackvend_platform_commit          = "0123456789abcdef0123456789abcdef01234567"
}

# DEFAULTS (enable_platform_upgrader = false): nothing of SELFUP-B is planned; the CC gets no new env.
run "defaults_plan_nothing" {
  command = apply

  assert {
    condition = (
      length(google_service_account.stackvend_upgrader) == 0
      && length(google_project_iam_custom_role.stackvend_upgrader_deploy) == 0
      && length(google_project_iam_member.platform_upgrader_project_roles) == 0
      && length(google_artifact_registry_repository_iam_member.platform_upgrader_ar_writer) == 0
      && length(google_service_account_iam_member.platform_upgrader_act_as) == 0
      && length(google_project_iam_member.platform_upgrader_guard_db_reader) == 0
      && length(google_project_iam_member.platform_upgrader_datastore_user) == 0
      && length(google_pubsub_topic.platform_upgrade) == 0
      && length(google_pubsub_topic_iam_member.cc_platform_upgrade_publisher) == 0
      && length(google_service_account_iam_member.cloudbuild_agent_act_as_upgrader) == 0
      && length(google_cloudbuild_trigger.platform_upgrade) == 0
    )
    error_message = "with the default (false) no SELFUP-B resource may be planned (the FD-7L step-B apply stays untouched)"
  }
  assert {
    condition     = length([for e in google_cloud_run_v2_service.services["product-control-center-ui"].template[0].containers[0].env : e.name if e.name == "STACKVEND_PLATFORM_UPGRADE_TOPIC"]) == 0
    error_message = "with the default the Control Center must not get STACKVEND_PLATFORM_UPGRADE_TOPIC (button hidden)"
  }
}

# ENABLED before FD-7L step B: 16 resources, 5 act-as targets.
run "enabled_before_step_b" {
  command = apply

  variables {
    enable_platform_upgrader = true
  }

  assert {
    condition = keys(google_service_account_iam_member.platform_upgrader_act_as) == [
      "sa-castor-developer", "sa-castor-qa-sandbox", "sa-project-provisioner", "sa-stackvend-control-center",
      "sa-stackvend-sandbox-cleaner",
    ]
    error_message = "before step B the upgrader acts as exactly the 5 runtime accounts"
  }
  assert {
    condition = (
      length(google_service_account.stackvend_upgrader) + length(google_project_iam_custom_role.stackvend_upgrader_deploy)
      + length(google_project_iam_member.platform_upgrader_project_roles) + length(google_artifact_registry_repository_iam_member.platform_upgrader_ar_writer)
      + length(google_service_account_iam_member.platform_upgrader_act_as) + length(google_project_iam_member.platform_upgrader_guard_db_reader)
      + length(google_project_iam_member.platform_upgrader_datastore_user) + length(google_pubsub_topic.platform_upgrade)
      + length(google_pubsub_topic_iam_member.cc_platform_upgrade_publisher) + length(google_service_account_iam_member.cloudbuild_agent_act_as_upgrader)
      + length(google_cloudbuild_trigger.platform_upgrade)
    ) == 16
    error_message = "before step B the upgrader footprint is 16 resource instances"
  }
  assert {
    condition = (
      alltrue([for k, m in google_service_account_iam_member.platform_upgrader_act_as :
        m.role == "roles/iam.serviceAccountUser"
        && m.member == "serviceAccount:sa-stackvend-upgrader@mock-stackvend-project.iam.gserviceaccount.com"
        && m.service_account_id == "projects/mock-stackvend-project/serviceAccounts/${k}@mock-stackvend-project.iam.gserviceaccount.com"
      ])
    )
    error_message = "each act-as grant is serviceAccountUser for the upgrader on that one account"
  }
  assert {
    condition = google_project_iam_custom_role.stackvend_upgrader_deploy[0].permissions == toset([
      "run.jobs.get", "run.jobs.list", "run.jobs.update", "run.operations.get", "run.revisions.get",
      "run.revisions.list", "run.services.get", "run.services.list", "run.services.update",
    ])
    error_message = "exact custom-role permission set"
  }
  assert {
    condition = (
      { for k, m in google_project_iam_member.platform_upgrader_project_roles : k => "${m.role} ${m.member}" } == {
        "deploy"     = "projects/mock-stackvend-project/roles/stackvendPlatformUpgraderDeploy serviceAccount:sa-stackvend-upgrader@mock-stackvend-project.iam.gserviceaccount.com"
        "log-writer" = "roles/logging.logWriter serviceAccount:sa-stackvend-upgrader@mock-stackvend-project.iam.gserviceaccount.com"
      }
    )
    error_message = "exact host project roles of the upgrader"
  }
  assert {
    condition = (
      google_artifact_registry_repository_iam_member.platform_upgrader_ar_writer[0].role == "roles/artifactregistry.writer"
      && google_artifact_registry_repository_iam_member.platform_upgrader_ar_writer[0].repository == google_artifact_registry_repository.castor_docker_repo.name
      && google_project_iam_member.platform_upgrader_guard_db_reader[0].role == "roles/datastore.viewer"
      && google_project_iam_member.platform_upgrader_guard_db_reader[0].condition[0].title == "stackvend-guard-db-read"
      && google_project_iam_member.platform_upgrader_datastore_user[0].role == "roles/datastore.user"
      && google_project_iam_member.platform_upgrader_datastore_user[0].condition[0].title == "stackvend-not-guard-db"
    )
    error_message = "AR writer on the platform repo only; guard DB read-only; default DB write (not the guard DB)"
  }
  assert {
    condition = (
      google_pubsub_topic.platform_upgrade[0].name == "stackvend-platform-upgrade"
      && google_pubsub_topic_iam_member.cc_platform_upgrade_publisher[0].role == "roles/pubsub.publisher"
      && google_pubsub_topic_iam_member.cc_platform_upgrade_publisher[0].member == "serviceAccount:sa-stackvend-control-center@mock-stackvend-project.iam.gserviceaccount.com"
    )
    error_message = "the Control Center is the only publisher on stackvend-platform-upgrade"
  }
  assert {
    condition = (
      google_service_account_iam_member.cloudbuild_agent_act_as_upgrader[0].service_account_id == "projects/mock-stackvend-project/serviceAccounts/sa-stackvend-upgrader@mock-stackvend-project.iam.gserviceaccount.com"
      && google_service_account_iam_member.cloudbuild_agent_act_as_upgrader[0].role == "roles/iam.serviceAccountUser"
      && google_service_account_iam_member.cloudbuild_agent_act_as_upgrader[0].member == "serviceAccount:service-123456789012@gcp-sa-cloudbuild.iam.gserviceaccount.com"
    )
    error_message = "M-1: only the Cloud Build service agent acts as the upgrader"
  }
  assert {
    condition = (
      google_cloudbuild_trigger.platform_upgrade[0].service_account == "projects/mock-stackvend-project/serviceAccounts/sa-stackvend-upgrader@mock-stackvend-project.iam.gserviceaccount.com"
      && google_cloudbuild_trigger.platform_upgrade[0].pubsub_config[0].topic == "projects/mock-stackvend-project/topics/stackvend-platform-upgrade"
      && google_cloudbuild_trigger.platform_upgrade[0].pubsub_config[0].service_account_email == null
      && google_cloudbuild_trigger.platform_upgrade[0].approval_config[0].approval_required == true
      && google_cloudbuild_trigger.platform_upgrade[0].disabled == false
      && length(google_cloudbuild_trigger.platform_upgrade[0].source_to_build) == 0
      && google_cloudbuild_trigger.platform_upgrade[0].location == "us-central1"
      && length(google_cloudbuild_trigger.platform_upgrade[0].substitutions) == 1
      && google_cloudbuild_trigger.platform_upgrade[0].substitutions["_REQUEST_ID"] == "$(body.message.attributes.request_id)"
    )
    error_message = "trigger: Pub/Sub on the topic, runs as the upgrader, approval on, enabled, no source_to_build"
  }
  assert {
    condition = (
      google_cloudbuild_trigger.platform_upgrade[0].build[0].timeout == "7200s"
      && google_cloudbuild_trigger.platform_upgrade[0].build[0].options[0].logging == "CLOUD_LOGGING_ONLY"
      && length(google_cloudbuild_trigger.platform_upgrade[0].build[0].step) == 2
      && google_cloudbuild_trigger.platform_upgrade[0].build[0].step[0].id == "step0-unpack"
      && join("\n", google_cloudbuild_trigger.platform_upgrade[0].build[0].step[0].env) == join("\n", [
        "STACKVEND_STEP0_VERIFY_SH_B64=${base64encode(file("${path.module}/upgrade_step0/verify.sh"))}",
        "STACKVEND_STEP0_GUARD_PY_B64=${base64encode(file("${path.module}/upgrade_step0/guard.py"))}",
        "STACKVEND_OFFICIAL_ALLOWED_SIGNERS_B64=${base64encode(file("${path.module}/../../scripts/release/allowed_signers"))}",
      ])
      && !strcontains(google_cloudbuild_trigger.platform_upgrade[0].build[0].step[0].args[1], "$")
      && strcontains(google_cloudbuild_trigger.platform_upgrade[0].build[0].step[0].args[1], sha256(file("${path.module}/upgrade_step0/guard.py")))
      && google_cloudbuild_trigger.platform_upgrade[0].build[0].step[1].id == "step0-verify"
      && join(" ", google_cloudbuild_trigger.platform_upgrade[0].build[0].step[1].args) == join(" ", [
        "/workspace/step0/verify.sh", "run", "--request-id", "$_REQUEST_ID", "--project", "mock-stackvend-project",
        "--region", "us-central1", "--guard-database", "stackvend-guard",
        "--official-signers", "/workspace/step0/allowed_signers", "--workdir", "/workspace/up",
      ])
      && length(google_cloudbuild_trigger.platform_upgrade[0].build[0].step[1].args) == 14
      && try(length(google_cloudbuild_trigger.platform_upgrade[0].build[0].step[1].env), 0) == 0
    )
    error_message = "build: unpack (embedded copies + signers, no $) then verify.sh run with the request id as its own argument, 2 h"
  }
  assert {
    condition = (
      [for e in google_cloud_run_v2_service.services["product-control-center-ui"].template[0].containers[0].env : e.value if e.name == "STACKVEND_PLATFORM_UPGRADE_TOPIC"] == ["projects/mock-stackvend-project/topics/stackvend-platform-upgrade"]
      && alltrue([for k, s in google_cloud_run_v2_service.services : k == "product-control-center-ui" || length([for e in s.template[0].containers[0].env : e.name if e.name == "STACKVEND_PLATFORM_UPGRADE_TOPIC"]) == 0])
    )
    error_message = "STACKVEND_PLATFORM_UPGRADE_TOPIC on the Control Center only"
  }
}

# ENABLED after FD-7L step B: 7 act-as targets (the two runner accounts added, H-1).
run "enabled_after_step_b" {
  command = apply

  variables {
    enable_platform_upgrader = true
    tf_runner_identity       = "PER_WORKLOAD"
    tf_runner_dedicated_sa   = true
  }

  assert {
    condition = keys(google_service_account_iam_member.platform_upgrader_act_as) == [
      "sa-castor-developer", "sa-castor-qa-sandbox", "sa-project-provisioner", "sa-stackvend-control-center",
      "sa-stackvend-sandbox-cleaner", "sa-stackvend-tf-applier", "sa-stackvend-tf-server",
    ]
    error_message = "after step B the upgrader acts as exactly the 7 runtime accounts"
  }
  assert {
    condition = (
      length(google_service_account.stackvend_upgrader) + length(google_project_iam_custom_role.stackvend_upgrader_deploy)
      + length(google_project_iam_member.platform_upgrader_project_roles) + length(google_artifact_registry_repository_iam_member.platform_upgrader_ar_writer)
      + length(google_service_account_iam_member.platform_upgrader_act_as) + length(google_project_iam_member.platform_upgrader_guard_db_reader)
      + length(google_project_iam_member.platform_upgrader_datastore_user) + length(google_pubsub_topic.platform_upgrade)
      + length(google_pubsub_topic_iam_member.cc_platform_upgrade_publisher) + length(google_service_account_iam_member.cloudbuild_agent_act_as_upgrader)
      + length(google_cloudbuild_trigger.platform_upgrade)
    ) == 18
    error_message = "after step B the upgrader footprint is 18 resource instances (Fable plan RT §5)"
  }
  assert {
    condition = (
      google_cloud_run_v2_job.tf_applier.template[0].template[0].service_account == "sa-stackvend-tf-applier@mock-stackvend-project.iam.gserviceaccount.com"
      && google_cloud_run_v2_service.services["mcp-terraform-server"].template[0].service_account == "sa-stackvend-tf-server@mock-stackvend-project.iam.gserviceaccount.com"
    )
    error_message = "step B moves the runners (the act-as set follows)"
  }
}

# Kill switch and approval off pass through exactly; nothing else changes (BL-3: no push identity, no source).
run "switches" {
  command = apply

  variables {
    enable_platform_upgrader           = true
    platform_upgrade_trigger_disabled  = true
    platform_upgrade_approval_required = false
  }

  assert {
    condition = (
      google_cloudbuild_trigger.platform_upgrade[0].disabled == true
      && google_cloudbuild_trigger.platform_upgrade[0].approval_config[0].approval_required == false
      && google_cloudbuild_trigger.platform_upgrade[0].pubsub_config[0].service_account_email == null
      && length(google_cloudbuild_trigger.platform_upgrade[0].source_to_build) == 0
      && google_cloudbuild_trigger.platform_upgrade[0].name == "stackvend-platform-upgrade"
    )
    error_message = "trigger switches"
  }
}
