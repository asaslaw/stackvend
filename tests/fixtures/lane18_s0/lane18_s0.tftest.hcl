# Lane 18 S0/S0b plan-level contract for infra/platform, run by tests/test_lane18_s0_platform_iam.py.
# Every provider is MOCKED: `tofu test` evaluates the configuration in memory, with no backend, no
# credentials and no network (the pytest wrapper also points every proxy at a dead loopback port and
# installs providers only from a local filesystem mirror). Nothing here can reach GCP.

# Generated values are random strings; give the attributes the provider validates as IAM members a
# valid shape (emails stay random and distinct, which the assertions rely on).
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

# Distinct, realistic identities (mock values are otherwise identical per resource type).
override_resource {
  target = google_service_account.agents["sa-castor-developer"]
  # `name` (lane 13 Stage A gateway_self_sign_blob uses it as service_account_id, which the provider validates).
  values = { email = "sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com", member = "serviceAccount:sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com", name = "projects/mock-stackvend-project/serviceAccounts/sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com" }
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
# Realistic tag value attributes (google 6.50.0): `name` is the BARE generated numeric id, `id` is the
# "tagValues/<id>" resource name. Mock providers otherwise return random strings, which could not tell
# the two apart (lane 18 RT F1: S1 accepts only "tagValues/<digits>").
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
  # Lane 19 L19-0a `check "cc_client_pinned"` (merged in lane18-window-v2): a failed check block fails a
  # `tofu test` run, so the fixture pins a (fake, well-formed) Control Center client like a real install.
  cc_google_oauth_client_id = "123456789012-mockcontrolcenter.apps.googleusercontent.com"
}

# Lane 18 RT fix 2 (staged apply, step A): `apply.sh apply -target=<the Control Center service>` must bring
# the CC's identity and every grant it needs (incl. the conditioned default-DB grant = the canary) and must
# NOT touch the 8 agent_datastore_users bindings, the folder role removals, other services or jobs.
# Runs first on empty state, so "not in state after the targeted apply" = "not in the targeted plan".
run "step_a_targeted_control_center_canary" {
  command = apply

  plan_options {
    target = [google_cloud_run_v2_service.services["product-control-center-ui"]]
  }

  assert {
    condition     = keys(google_cloud_run_v2_service.services) == ["product-control-center-ui"] && google_cloud_run_v2_service.services["product-control-center-ui"].template[0].service_account == google_service_account.stackvend_personas["sa-stackvend-control-center"].email
    error_message = "step A changes only the Control Center service, onto its own SA"
  }
  assert {
    condition = (
      length(google_project_iam_member.persona_datastore_users) == 2
      && alltrue([for m in google_project_iam_member.persona_datastore_users : m.condition[0].title == "stackvend-not-guard-db"])
      && length(google_project_iam_member.guard_db_writers) == 2
      && length(google_project_iam_member.cc_project_roles) == 5
      && length(google_secret_manager_secret_iam_member.cc_secret_accessors) == 4
      && google_storage_bucket_iam_member.cc_state_admin.member == "serviceAccount:${google_service_account.stackvend_personas["sa-stackvend-control-center"].email}"
      && google_pubsub_topic_iam_member.cc_spec_intake_publisher.member == "serviceAccount:${google_service_account.stackvend_personas["sa-stackvend-control-center"].email}"
      && google_cloud_run_v2_service_iam_member.cc_git_server_invoker[0].member == "serviceAccount:${google_service_account.stackvend_personas["sa-stackvend-control-center"].email}"
      && google_firestore_database.stackvend_guard.name == "stackvend-guard"
      && length(google_tags_tag_value_iam_member.stackvend_managed_vending_tag_user) == 1
    )
    error_message = "step A must include every Control Center grant (conditioned default DB = the canary), the guard DB and the tag"
  }
  assert {
    condition = (
      length(google_project_iam_member.agent_datastore_users) == 0
      && length(google_folder_iam_member.folder_project_deleters) == 0
      && length(google_folder_iam_member.folder_admins) == 0
      && length(google_cloud_run_v2_job.jobs) == 0
      && length(google_cloud_run_v2_service_iam_member.persona_invokers) == 0
    )
    error_message = "step A must not replace the 8 agent datastore bindings, touch folder delete/admin roles or jobs (no --allow-destroy needed)"
  }
}

run "s0_default_identities_env_and_grants" {
  command = apply

  # Runtime identities.
  assert {
    condition     = google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].service_account == google_service_account.agents["sa-project-provisioner"].email
    error_message = "vending must run as sa-project-provisioner"
  }
  assert {
    condition     = google_cloud_run_v2_service.services["product-control-center-ui"].template[0].service_account == google_service_account.stackvend_personas["sa-stackvend-control-center"].email
    error_message = "the Control Center must run as its own SA"
  }
  assert {
    condition = alltrue([
      for k, s in google_cloud_run_v2_service.services : s.template[0].service_account == google_service_account.agents["sa-castor-developer"].email
      if !contains(["project-repo-vending-service", "product-control-center-ui"], k)
    ])
    error_message = "every other service keeps sa-castor-developer"
  }
  assert {
    condition     = google_cloud_run_v2_job.jobs["sandbox-garbage-collector-job"].template[0].template[0].service_account == google_service_account.stackvend_personas["sa-stackvend-sandbox-cleaner"].email
    error_message = "the sandbox cleaner job must run as its own SA"
  }
  assert {
    condition = alltrue([
      for k, j in google_cloud_run_v2_job.jobs : j.template[0].template[0].service_account == google_service_account.agents["sa-castor-developer"].email
      if k != "sandbox-garbage-collector-job"
    ]) && google_cloud_run_v2_job.tf_applier.template[0].template[0].service_account == google_service_account.agents["sa-castor-developer"].email && google_cloud_run_v2_service.git_server[0].template[0].service_account == google_service_account.agents["sa-castor-developer"].email
    error_message = "other jobs, tf-applier and the git server keep sa-castor-developer"
  }
  assert {
    # Lane 13 Stage A (merged in lane18-window-v2): qa-sandbox-test-runner moved out of the generic jobs block into
    # google_cloud_run_v2_job.qa_sandbox (zero-role QA SA, row L13-SA-a); it is still deployed.
    condition     = length(google_cloud_run_v2_service.services) == 13 && length(google_cloud_run_v2_job.jobs) == 5 && google_cloud_run_v2_job.qa_sandbox.name == "qa-sandbox-test-runner" && google_cloud_run_v2_job.qa_sandbox.template[0].template[0].service_account == google_service_account.qa_sandbox.email
    error_message = "every service and job stays deployed"
  }

  # Folder roles: delete/admin only for the vending identity.
  assert {
    condition     = keys(google_folder_iam_member.folder_project_deleters) == ["sa-project-provisioner"] && keys(google_folder_iam_member.folder_admins) == ["sa-project-provisioner"]
    error_message = "sa-castor-developer must lose projectDeleter and folderAdmin"
  }
  assert {
    condition     = keys(google_folder_iam_member.folder_project_creators) == ["sa-castor-developer", "sa-project-provisioner"] && keys(google_folder_iam_member.folder_creators) == ["sa-castor-developer", "sa-project-provisioner"]
    error_message = "projectCreator / folderCreator are unchanged by S0"
  }
  assert {
    condition     = google_folder_iam_member.folder_admins["sa-project-provisioner"].folder == "folders/222222222222"
    error_message = "folder roles stay on the managed folder"
  }
  assert {
    condition = (
      google_folder_iam_member.guard_folder_readers["vending-browser"].member == "serviceAccount:${google_service_account.agents["sa-project-provisioner"].email}"
      && google_folder_iam_member.guard_folder_readers["vending-tagviewer"].member == "serviceAccount:${google_service_account.agents["sa-project-provisioner"].email}"
      && alltrue([for m in google_folder_iam_member.vending_legacy_revend : m.member == "serviceAccount:${google_service_account.agents["sa-project-provisioner"].email}"])
      && length(google_folder_iam_member.vending_legacy_revend) == 2
    )
    error_message = "lever true: vending browser / tagViewer / legacy re-vend grants are on sa-project-provisioner"
  }

  # Tag: org parent, value 'true', tagUser only for vending.
  assert {
    condition     = google_tags_tag_key.stackvend_managed[0].parent == "organizations/111111111111" && google_tags_tag_key.stackvend_managed[0].short_name == "stackvend-managed-mock-stackvend-project" && google_tags_tag_value.stackvend_managed_true[0].short_name == "true"
    error_message = "tag key under the organization, per-install short name, value 'true'"
  }
  assert {
    condition     = google_tags_tag_value_iam_member.stackvend_managed_vending_tag_user[0].member == "serviceAccount:${google_service_account.agents["sa-project-provisioner"].email}" && google_tags_tag_value_iam_member.stackvend_managed_vending_tag_user[0].role == "roles/resourcemanager.tagUser" && google_tags_tag_value_iam_member.stackvend_managed_vending_tag_user[0].tag_value == google_tags_tag_value.stackvend_managed_true[0].name
    error_message = "tagUser on the value for vending only"
  }

  # Vending env contract (S1).
  assert {
    condition = {
      for e in google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].containers[0].env : e.name => e.value
      if contains(["STACKVEND_MANAGED_TAG_VALUE", "DESTRUCTIVE_CALLERS", "SANDBOX_TTL_CALLERS", "EPHEMERAL_TTL_CALLERS", "VENDING_SERVICE_URL", "STACKVEND_GUARD_FIRESTORE_DATABASE", "STACKVEND_CHILD_PROJECT_OWNER_MEMBERS", "MANAGED_WORKLOADS_FOLDER_ID"], e.name)
      } == {
      STACKVEND_MANAGED_TAG_VALUE           = "tagValues/281478392000"
      DESTRUCTIVE_CALLERS                   = google_service_account.stackvend_personas["sa-stackvend-control-center"].email
      SANDBOX_TTL_CALLERS                   = google_service_account.stackvend_personas["sa-stackvend-control-center"].email
      EPHEMERAL_TTL_CALLERS                 = google_service_account.stackvend_personas["sa-stackvend-sandbox-cleaner"].email
      VENDING_SERVICE_URL                   = "https://project-repo-vending-service-${data.google_project.platform_project.number}.us-central1.run.app"
      STACKVEND_GUARD_FIRESTORE_DATABASE    = "stackvend-guard"
      STACKVEND_CHILD_PROJECT_OWNER_MEMBERS = "serviceAccount:${google_service_account.agents["sa-castor-developer"].email}"
      MANAGED_WORKLOADS_FOLDER_ID           = "folders/222222222222"
    }
    error_message = "vending env must carry the S1 guard contract from Terraform resources"
  }
  # Lane 18 v3: the organization reaches vending (Settings names it in the Tag Administrator warning).
  assert {
    condition     = [for e in google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].containers[0].env : e.value if e.name == "STACKVEND_ORGANIZATION_ID"] == ["organizations/111111111111"]
    error_message = "vending gets STACKVEND_ORGANIZATION_ID from organization_id"
  }
  # Lane 18 v3: default (no preflight decision, plain tofu) keeps the tag planned.
  assert {
    condition     = length(google_tags_tag_key.stackvend_managed) == 1 && length(google_tags_tag_value.stackvend_managed_true) == 1 && length(google_tags_tag_value_iam_member.stackvend_managed_vending_tag_user) == 1
    error_message = "create_stackvend_managed_tag = null (default) plans the tag"
  }
  assert {
    condition     = length([for e in google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].containers[0].env : e if e.name == "EPHEMERAL_PRODUCERS"]) == 0
    error_message = "EPHEMERAL_PRODUCERS stays unset until lane 13's producer SA exists"
  }
  assert {
    condition = (
      [for e in google_cloud_run_v2_service.services["product-control-center-ui"].template[0].containers[0].env : e.value if e.name == "STACKVEND_GUARD_FIRESTORE_DATABASE"] == ["stackvend-guard"]
      && [for e in google_cloud_run_v2_service.services["product-control-center-ui"].template[0].containers[0].env : e.value if e.name == "VENDING_SERVICE_URL"] == ["https://project-repo-vending-service-${data.google_project.platform_project.number}.us-central1.run.app"]
    )
    error_message = "the Control Center gets the guard DB name and keeps VENDING_SERVICE_URL"
  }
  # Lane 18 window v2: lane 14 PR-6 seam. The cleaner reads vending's ledger in the guard DB and calls vending at
  # exactly the URL vending accepts as its ID-token audience; I9 stays on the job.
  assert {
    condition = (
      [for e in google_cloud_run_v2_job.jobs["sandbox-garbage-collector-job"].template[0].template[0].containers[0].env : e.value if e.name == "STACKVEND_GUARD_FIRESTORE_DATABASE"] == ["stackvend-guard"]
      && [for e in google_cloud_run_v2_job.jobs["sandbox-garbage-collector-job"].template[0].template[0].containers[0].env : e.value if e.name == "VENDING_SERVICE_URL"]
      == [for e in google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].containers[0].env : e.value if e.name == "VENDING_SERVICE_URL"]
      && google_cloud_run_v2_job.jobs["sandbox-garbage-collector-job"].template[0].template[0].max_retries == 0
    )
    error_message = "the sandbox cleaner gets the guard DB name and vending's own audience URL"
  }
  assert {
    condition = alltrue([
      for k, j in google_cloud_run_v2_job.jobs : length([for e in j.template[0].template[0].containers[0].env : e if e.name == "STACKVEND_GUARD_FIRESTORE_DATABASE"]) == 0
      if k != "sandbox-garbage-collector-job"
    ])
    error_message = "no other job gets guard env in S0"
  }
  assert {
    condition = alltrue([
      for k, s in google_cloud_run_v2_service.services : length([for e in s.template[0].containers[0].env : e if contains(["DESTRUCTIVE_CALLERS", "STACKVEND_MANAGED_TAG_VALUE", "STACKVEND_GUARD_FIRESTORE_DATABASE"], e.name)]) == 0
      if !contains(["project-repo-vending-service", "product-control-center-ui"], k)
    ])
    error_message = "no other service gets guard env in S0"
  }

  # Git server allow-list follows the split.
  assert {
    condition = (
      [for e in google_cloud_run_v2_service.git_server[0].template[0].containers[0].env : e.value if e.name == "GIT_SERVER_ALLOWED_INVOKERS"]
      == [join(",", [google_service_account.agents["sa-castor-developer"].email, google_service_account.agents["sa-project-provisioner"].email, google_service_account.stackvend_personas["sa-stackvend-control-center"].email])]
    )
    error_message = "git server must allow developer, vending and Control Center callers"
  }

  # S0b: guard DB and Firestore conditions.
  assert {
    condition = (
      google_firestore_database.stackvend_guard.name == "stackvend-guard"
      && google_firestore_database.stackvend_guard.point_in_time_recovery_enablement == "POINT_IN_TIME_RECOVERY_ENABLED"
      && google_firestore_database.stackvend_guard.delete_protection_state == "DELETE_PROTECTION_ENABLED"
      && google_firestore_database.stackvend_guard.type == "FIRESTORE_NATIVE"
    )
    error_message = "guard DB: named, PITR on, delete protection on"
  }
  assert {
    condition     = google_firestore_database.castor_state_db.delete_protection_state == "DELETE_PROTECTION_ENABLED" && google_firestore_database.castor_state_db.point_in_time_recovery_enablement == "POINT_IN_TIME_RECOVERY_ENABLED" && google_firestore_database.castor_state_db.name == "(default)"
    error_message = "host ledger DB: delete protection + PITR (owner Q10)"
  }
  assert {
    condition = alltrue([
      for k, m in google_project_iam_member.agent_datastore_users :
      m.condition[0].expression == "!(resource.name == \"projects/mock-stackvend-project/databases/stackvend-guard\" || resource.name.startsWith(\"projects/mock-stackvend-project/databases/stackvend-guard/\"))"
    ]) && length(google_project_iam_member.agent_datastore_users) == 8
    error_message = "every agent SA keeps datastore.user on all databases except stackvend-guard"
  }
  assert {
    condition = (
      toset([for m in google_project_iam_member.guard_db_writers : m.member]) == toset(["serviceAccount:${google_service_account.stackvend_personas["sa-stackvend-control-center"].email}", "serviceAccount:${google_service_account.agents["sa-project-provisioner"].email}"])
      && alltrue([for m in google_project_iam_member.guard_db_writers : m.role == "roles/datastore.user" && m.condition[0].expression == "resource.name == \"projects/mock-stackvend-project/databases/stackvend-guard\" || resource.name.startsWith(\"projects/mock-stackvend-project/databases/stackvend-guard/\")"])
    )
    error_message = "guard DB writers are exactly the Control Center and vending"
  }
  assert {
    condition = (
      toset([for m in google_project_iam_member.guard_db_readers : m.member]) == toset(["serviceAccount:${google_service_account.agents["sa-castor-developer"].email}", "serviceAccount:${google_service_account.stackvend_personas["sa-stackvend-sandbox-cleaner"].email}"])
      && alltrue([for m in google_project_iam_member.guard_db_readers : m.role == "roles/datastore.viewer"])
    )
    error_message = "lane 14 I7 consumers read the guard DB, read-only"
  }

  assert {
    condition     = output.stackvend_managed_tag_value == "tagValues/281478392000" && output.stackvend_guard_database == "stackvend-guard"
    error_message = "outputs expose the tag value and guard DB"
  }

  # SELFUP-STATE (owner 10-27): the four bucket-wide writers of the state bucket write only workload state.
  assert {
    condition = (
      keys(google_storage_bucket_iam_member.state_bucket_admins) == ["sa-castor-developer", "sa-castor-gcp-devops", "sa-project-provisioner"]
      && alltrue([for k, m in google_storage_bucket_iam_member.state_bucket_admins : (
        m.bucket == "castor-tfstate-mock-stackvend-project" && m.role == "roles/storage.objectAdmin"
        && m.member == "serviceAccount:${google_service_account.agents[k].email}"
        && length(m.condition) == 1
        && m.condition[0].expression == "resource.type == \"storage.googleapis.com/Bucket\" || resource.name.startsWith(\"projects/_/buckets/castor-tfstate-mock-stackvend-project/objects/workloads/\")"
      )])
      && google_storage_bucket_iam_member.cc_state_admin.role == "roles/storage.objectAdmin"
      && length(google_storage_bucket_iam_member.cc_state_admin.condition) == 1
      && google_storage_bucket_iam_member.cc_state_admin.condition[0].expression == google_storage_bucket_iam_member.state_bucket_admins["sa-castor-developer"].condition[0].expression
    )
    error_message = "SELFUP-STATE: DevOps, developer, provisioner and the Control Center write only objects under workloads/ (bucket-level checks allowed)"
  }
  assert {
    condition = (
      google_storage_bucket_iam_member.cc_state_viewer.role == "roles/storage.objectViewer"
      && google_storage_bucket_iam_member.cc_state_viewer.member == "serviceAccount:${google_service_account.stackvend_personas["sa-stackvend-control-center"].email}"
      && length(google_storage_bucket_iam_member.cc_state_viewer.condition) == 0
      && alltrue([for m in google_storage_bucket_iam_member.agent_state_viewers : length(m.condition) == 0 && m.role == "roles/storage.objectViewer"])
    )
    error_message = "SELFUP-STATE: reads of the state bucket (platform state included) stay unconditional"
  }
}

run "rollback_lever_vending_on_developer" {
  command = apply

  variables {
    vending_runs_as_provisioner = false
  }

  assert {
    condition     = google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].service_account == google_service_account.agents["sa-castor-developer"].email
    error_message = "lever false: vending back on sa-castor-developer"
  }
  assert {
    condition     = keys(google_folder_iam_member.folder_project_deleters) == ["sa-castor-developer", "sa-project-provisioner"] && keys(google_folder_iam_member.folder_admins) == ["sa-castor-developer", "sa-project-provisioner"]
    error_message = "lever false: the vending identity keeps its delete/admin folder roles"
  }
  assert {
    condition     = google_tags_tag_value_iam_member.stackvend_managed_vending_tag_user[0].member == "serviceAccount:${google_service_account.agents["sa-castor-developer"].email}"
    error_message = "lever false: tagUser follows the vending identity"
  }
  assert {
    condition = (
      google_folder_iam_member.guard_folder_readers["vending-browser"].member == "serviceAccount:${google_service_account.agents["sa-castor-developer"].email}"
      && google_folder_iam_member.guard_folder_readers["vending-tagviewer"].member == "serviceAccount:${google_service_account.agents["sa-castor-developer"].email}"
      && alltrue([for m in google_folder_iam_member.vending_legacy_revend : m.member == "serviceAccount:${google_service_account.agents["sa-castor-developer"].email}"])
      && length(google_folder_iam_member.vending_legacy_revend) == 2
    )
    error_message = "lever false: every vending folder grant (browser, tagViewer, legacy re-vend) moves to the vending identity (RT fix 5)"
  }
  assert {
    condition = (
      toset([for m in google_project_iam_member.guard_db_writers : m.member]) == toset(["serviceAccount:${google_service_account.stackvend_personas["sa-stackvend-control-center"].email}", "serviceAccount:${google_service_account.agents["sa-castor-developer"].email}"])
      && [for e in google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].containers[0].env : e.value if e.name == "STACKVEND_MANAGED_TAG_VALUE"] == ["tagValues/281478392000"]
    )
    error_message = "lever false: guard-DB write and the tag env follow the vending identity"
  }
  assert {
    condition     = length([for e in google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].containers[0].env : e if e.name == "STACKVEND_CHILD_PROJECT_OWNER_MEMBERS"]) == 0
    error_message = "lever false: no extra child owner (vending is the developer SA itself)"
  }
}

run "no_organization_fails_closed" {
  command = apply

  variables {
    organization_id = ""
  }

  assert {
    condition     = length(google_tags_tag_key.stackvend_managed) == 0 && length(google_tags_tag_value_iam_member.stackvend_managed_vending_tag_user) == 0
    error_message = "no organization: no tag"
  }
  assert {
    condition     = length([for e in google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].containers[0].env : e if e.name == "STACKVEND_MANAGED_TAG_VALUE"]) == 0
    error_message = "no organization: the tag env is not set, so the guard refuses (GUARD_UNCONFIGURED)"
  }

  expect_failures = [check.stackvend_managed_tag_configured]
}

# Lane 18 v3 (owner 10-18, "install never fails"): the installer is not an org Tag Administrator, so the
# apply.sh / bootstrap.sh preflight passes create_stackvend_managed_tag = false. No tag resources are planned
# (no 403 part-way through the apply); everything else, incl. the guard database and the persona SAs, is.
# The guard stays fail closed: no STACKVEND_MANAGED_TAG_VALUE -> GUARD_UNCONFIGURED.
run "installer_not_tag_admin_skips_only_the_tag" {
  command = apply

  variables {
    create_stackvend_managed_tag = false
  }

  assert {
    condition     = length(google_tags_tag_key.stackvend_managed) == 0 && length(google_tags_tag_value.stackvend_managed_true) == 0 && length(google_tags_tag_value_iam_member.stackvend_managed_vending_tag_user) == 0
    error_message = "not a Tag Administrator: no tag key, value or tagUser grant is planned"
  }
  assert {
    condition     = length([for e in google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].containers[0].env : e if e.name == "STACKVEND_MANAGED_TAG_VALUE"]) == 0
    error_message = "no tag: the tag env is not set, so the guard refuses (GUARD_UNCONFIGURED)"
  }
  assert {
    condition = (
      google_firestore_database.stackvend_guard.name == "stackvend-guard"
      && google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].service_account == google_service_account.agents["sa-project-provisioner"].email
      && google_cloud_run_v2_service.services["product-control-center-ui"].template[0].service_account == google_service_account.stackvend_personas["sa-stackvend-control-center"].email
      && length(google_project_iam_member.guard_db_writers) == 2
      && [for e in google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].containers[0].env : e.value if e.name == "STACKVEND_ORGANIZATION_ID"] == ["organizations/111111111111"]
    )
    error_message = "everything except the tag is still planned (identities, guard database, writers, org env)"
  }

  expect_failures = [check.stackvend_managed_tag_configured]
}

# Explicit true plans the tag (in a real install the tfvars value wins over the preflight's TF_VAR_*).
run "explicit_true_plans_the_tag" {
  command = apply

  variables {
    create_stackvend_managed_tag = true
  }

  assert {
    condition     = length(google_tags_tag_key.stackvend_managed) == 1 && [for e in google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].containers[0].env : e.value if e.name == "STACKVEND_MANAGED_TAG_VALUE"] == ["tagValues/281478392000"]
    error_message = "create_stackvend_managed_tag = true plans the tag and sets the env"
  }
}

# ORG-POLICY-FOLDER (owner 10-28): "no external VM IPs" is set once on the managed workloads folder, through the
# host-quota provider alias. null (plain tofu / preflight passed) plans it; false (preflight: the installer is not
# an Organization Policy Administrator) plans nothing and everything else is unchanged.
run "folder_vm_external_ip_policy_default_is_planned" {
  command = apply

  assert {
    condition = (
      length(google_org_policy_policy.managed_folder_vm_external_ip) == 1
      && google_org_policy_policy.managed_folder_vm_external_ip[0].parent == "folders/222222222222"
      && google_org_policy_policy.managed_folder_vm_external_ip[0].name == "folders/222222222222/policies/compute.vmExternalIpAccess"
      && google_org_policy_policy.managed_folder_vm_external_ip[0].spec[0].rules[0].deny_all == "TRUE"
    )
    error_message = "the folder deny-all policy for compute.vmExternalIpAccess is planned on the managed folder"
  }
}

run "folder_vm_external_ip_policy_false_plans_nothing" {
  command = apply

  variables {
    create_folder_vm_external_ip_policy = false
  }

  assert {
    condition     = length(google_org_policy_policy.managed_folder_vm_external_ip) == 0 && google_cloud_run_v2_service.services["project-repo-vending-service"].template[0].service_account == google_service_account.agents["sa-project-provisioner"].email
    error_message = "not an Organization Policy Administrator: no folder policy, the rest is planned"
  }
}
