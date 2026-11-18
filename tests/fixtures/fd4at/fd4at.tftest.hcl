mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      name  = "projects/fd4at-test/serviceAccounts/sa-mock@fd4at-test.iam.gserviceaccount.com"
      email = "sa-mock@fd4at-test.iam.gserviceaccount.com"
    }
  }
  mock_resource "google_iam_workload_identity_pool" {
    defaults = {
      name = "projects/123/locations/global/workloadIdentityPools/castor-gh-pool"
    }
  }
  # FD-7L 2b (review F1): the build-SA grant reads the project number from data.google_project.this
  mock_data "google_project" {
    defaults = {
      number = "123"
    }
  }
}

variables {
  project_id            = "fd4at-test"
  product_id            = "fd4at"
  github_repo_full_name = "acme/fd4at"
}

run "main_branch_of_the_named_repo_only" {
  command = apply

  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider[0].attribute_condition == "assertion.repository == 'acme/fd4at' && assertion.ref == 'refs/heads/main' && assertion.event_name in ['push','workflow_dispatch']"
    error_message = "condition: ${google_iam_workload_identity_pool_provider.github_provider[0].attribute_condition}"
  }
  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider[0].attribute_mapping["attribute.ref"] == "assertion.ref"
    error_message = "attribute.ref mapping missing"
  }
  assert {
    condition     = google_service_account_iam_member.github_wif_binding[0].member == "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/castor-gh-pool/attribute.repository/acme/fd4at"
    error_message = "member: ${google_service_account_iam_member.github_wif_binding[0].member}"
  }
  assert {
    condition     = google_service_account_iam_member.deployer_runtime_sa_user[0].service_account_id == google_service_account.workload_sa.name
    error_message = "serviceAccountUser is not on the runtime SA"
  }
  assert {
    condition     = google_service_account_iam_member.deployer_runtime_sa_user[0].member == "serviceAccount:${google_service_account.github_deployer[0].email}"
    error_message = "runtime SA user member is not the deployer"
  }
  assert {
    condition     = google_service_account_iam_member.deployer_build_sa_user[0].service_account_id == "projects/fd4at-test/serviceAccounts/123-compute@developer.gserviceaccount.com"
    error_message = "build SA: ${google_service_account_iam_member.deployer_build_sa_user[0].service_account_id}"
  }
  assert {
    condition     = google_service_account_iam_member.deployer_build_sa_user[0].role == "roles/iam.serviceAccountUser" && google_service_account_iam_member.deployer_build_sa_user[0].member == "serviceAccount:${google_service_account.github_deployer[0].email}"
    error_message = "build SA user grant is not the deployer's actAs"
  }
}

# FD-4AT RT R1: a Day-2 apply that changes additional_apis (google_project_service.apis gains an instance) must
# leave the build-SA actAs grant known at plan (an unknown ForceNew service_account_id would replace it; an
# unknown value makes this assert fail with "could not be evaluated"). Runs on the state of the run above.
run "day2_additional_apis_change_keeps_build_sa_grant_known" {
  command = plan
  variables {
    additional_apis = ["x.googleapis.com"]
  }

  assert {
    condition     = google_service_account_iam_member.deployer_build_sa_user[0].service_account_id == "projects/fd4at-test/serviceAccounts/123-compute@developer.gserviceaccount.com"
    error_message = "build SA: ${google_service_account_iam_member.deployer_build_sa_user[0].service_account_id}"
  }
  assert {
    condition     = google_service_account_iam_member.deployer_runtime_sa_user[0].service_account_id == google_service_account.workload_sa.name
    error_message = "runtime SA grant changed on a Day-2 plan"
  }
}

# FD-4AT-c: with the vend-time repository id the condition also requires assertion.repository_id (exact equality);
# everything else, including the binding member, is unchanged (no replace of github_wif_binding).
run "fd4at_c_repository_id_pinned" {
  command = plan
  variables {
    github_repository_id = "123456789"
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider[0].attribute_condition == "assertion.repository == 'acme/fd4at' && assertion.repository_id == '123456789' && assertion.ref == 'refs/heads/main' && assertion.event_name in ['push','workflow_dispatch']"
    error_message = "condition: ${google_iam_workload_identity_pool_provider.github_provider[0].attribute_condition}"
  }
  assert {
    condition     = google_service_account_iam_member.github_wif_binding[0].member == "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/castor-gh-pool/attribute.repository/acme/fd4at"
    error_message = "member: ${google_service_account_iam_member.github_wif_binding[0].member}"
  }
}

# FD-4AT-c: anything but GitHub's digits-only id is refused by the module's own validation (no CEL injection).
run "fd4at_c_non_numeric_repository_id_refused" {
  command = plan
  variables {
    github_repository_id = "123' || true || '"
  }
  expect_failures = [var.github_repository_id]
}

# FD-4CI-b-R1-WIF: the recorded default branch replaces main in the one exact ref clause; the repository (and the
# FD-4AT-c id) clauses, the events and the binding member are unchanged.
run "r1_wif_recorded_branch" {
  command = plan
  variables {
    github_default_branch = "release/v1.2_rc-1"
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider[0].attribute_condition == "assertion.repository == 'acme/fd4at' && assertion.ref == 'refs/heads/release/v1.2_rc-1' && assertion.event_name in ['push','workflow_dispatch']"
    error_message = "condition: ${google_iam_workload_identity_pool_provider.github_provider[0].attribute_condition}"
  }
  assert {
    condition     = google_service_account_iam_member.github_wif_binding[0].member == "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/castor-gh-pool/attribute.repository/acme/fd4at"
    error_message = "member: ${google_service_account_iam_member.github_wif_binding[0].member}"
  }
}

run "r1_wif_recorded_branch_with_repository_id" {
  command = plan
  variables {
    github_default_branch = "develop"
    github_repository_id  = "123456789"
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider[0].attribute_condition == "assertion.repository == 'acme/fd4at' && assertion.repository_id == '123456789' && assertion.ref == 'refs/heads/develop' && assertion.event_name in ['push','workflow_dispatch']"
    error_message = "condition: ${google_iam_workload_identity_pool_provider.github_provider[0].attribute_condition}"
  }
}

# FD-4CI-b-R1-WIF: an explicit "main" is the FD-4AT condition byte for byte.
run "r1_wif_explicit_main_is_the_fd4at_condition" {
  command = plan
  variables {
    github_default_branch = "main"
  }

  assert {
    condition     = google_iam_workload_identity_pool_provider.github_provider[0].attribute_condition == "assertion.repository == 'acme/fd4at' && assertion.ref == 'refs/heads/main' && assertion.event_name in ['push','workflow_dispatch']"
    error_message = "condition: ${google_iam_workload_identity_pool_provider.github_provider[0].attribute_condition}"
  }
}

# FD-4CI-b-R1-WIF: anything outside the platform's branch-name grammar is refused by the module's own validation
# (no CEL quote, no wildcard, no git-invalid name), so the condition can never widen.
run "r1_wif_quote_injection_refused" {
  command = plan
  variables {
    github_default_branch = "main' || true || '"
  }
  expect_failures = [var.github_default_branch]
}

run "r1_wif_wildcard_refused" {
  command = plan
  variables {
    github_default_branch = "feature/*"
  }
  expect_failures = [var.github_default_branch]
}

run "r1_wif_empty_refused" {
  command = plan
  variables {
    github_default_branch = ""
  }
  expect_failures = [var.github_default_branch]
}

run "r1_wif_head_refused" {
  command = plan
  variables {
    github_default_branch = "HEAD"
  }
  expect_failures = [var.github_default_branch]
}

run "r1_wif_dotdot_refused" {
  command = plan
  variables {
    github_default_branch = "a..b"
  }
  expect_failures = [var.github_default_branch]
}

run "r1_wif_lock_component_refused" {
  command = plan
  variables {
    github_default_branch = "x.lock/y"
  }
  expect_failures = [var.github_default_branch]
}

run "r1_wif_dot_component_refused" {
  command = plan
  variables {
    github_default_branch = "feature/.hidden"
  }
  expect_failures = [var.github_default_branch]
}

run "r1_wif_empty_component_refused" {
  command = plan
  variables {
    github_default_branch = "a//b"
  }
  expect_failures = [var.github_default_branch]
}

run "r1_wif_too_long_refused" {
  command = plan
  variables {
    github_default_branch = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
  expect_failures = [var.github_default_branch]
}

# GHA-DEPLOY-SWITCH: the switch off creates no GitHub Actions deploy resource (pool, provider, deployer SA, its WIF
# binding, its three project roles and two actAs grants); the runtime SA and its roles stay; the outputs are null.
run "gha_deploy_switch_off_creates_no_deploy_resources" {
  command = apply
  variables {
    enable_github_actions_deploy = false
  }

  assert {
    condition = (length(google_iam_workload_identity_pool.github_pool) + length(google_iam_workload_identity_pool_provider.github_provider)
      + length(google_service_account.github_deployer) + length(google_service_account_iam_member.github_wif_binding)
      + length(google_project_iam_member.deployer_run_source_developer) + length(google_project_iam_member.deployer_logging_viewer)
      + length(google_project_iam_member.deployer_container_developer) + length(google_service_account_iam_member.deployer_runtime_sa_user)
    + length(google_service_account_iam_member.deployer_build_sa_user)) == 0
    error_message = "a GitHub Actions deploy resource exists with the switch off"
  }
  assert {
    condition     = google_service_account.workload_sa.account_id == "sa-fd4at"
    error_message = "the runtime SA changed with the switch off"
  }
  assert {
    condition     = output.deployer_sa_email == null && output.wif_pool_name == null && output.wif_provider_name == null
    error_message = "deployer / WIF outputs are not null with the switch off"
  }
}

# GHA-DEPLOY-SWITCH: on again (explicit true = the default) creates exactly one of each, as before the switch.
run "gha_deploy_switch_on_creates_one_of_each" {
  command = apply
  variables {
    enable_github_actions_deploy = true
  }

  assert {
    condition = (length(google_iam_workload_identity_pool.github_pool) == 1 && length(google_iam_workload_identity_pool_provider.github_provider) == 1
      && length(google_service_account.github_deployer) == 1 && length(google_service_account_iam_member.github_wif_binding) == 1
      && length(google_project_iam_member.deployer_run_source_developer) == 1 && length(google_project_iam_member.deployer_logging_viewer) == 1
      && length(google_project_iam_member.deployer_container_developer) == 1 && length(google_service_account_iam_member.deployer_runtime_sa_user) == 1
    && length(google_service_account_iam_member.deployer_build_sa_user) == 1)
    error_message = "the switch on does not create exactly one of each deploy resource"
  }
  assert {
    condition     = output.deployer_sa_email == google_service_account.github_deployer[0].email
    error_message = "deployer_sa_email output is not the deployer's email"
  }
}
