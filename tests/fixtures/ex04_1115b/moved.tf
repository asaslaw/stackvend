# ==============================================================================
# STACKVEND: DECLARATIVE STATE MIGRATION GUARDS
# ==============================================================================
# Ensures zero-destruction upgrades for existing production workloads.
# Terraform renames resource addresses in remote state without recreating live resources.
# For new workloads with an empty state file, Terraform silently ignores these blocks.
# ==============================================================================

moved {
  from = google_firestore_database.database
  to   = module.foundation.google_firestore_database.database
}

moved {
  from = google_artifact_registry_repository.docker_repo
  to   = module.foundation.google_artifact_registry_repository.docker_repo
}

moved {
  from = google_service_account.workload_sa
  to   = module.foundation.google_service_account.workload_sa
}

moved {
  from = google_project_iam_member.workload_datastore_user
  to   = module.foundation.google_project_iam_member.workload_datastore_user
}

moved {
  from = google_project_iam_member.workload_log_writer
  to   = module.foundation.google_project_iam_member.workload_log_writer
}

moved {
  from = google_iam_workload_identity_pool.github_pool
  to   = module.foundation.google_iam_workload_identity_pool.github_pool
}

moved {
  from = google_iam_workload_identity_pool_provider.github_provider
  to   = module.foundation.google_iam_workload_identity_pool_provider.github_provider
}

moved {
  from = google_service_account.github_deployer
  to   = module.foundation.google_service_account.github_deployer
}

moved {
  from = google_service_account_iam_member.github_wif_binding
  to   = module.foundation.google_service_account_iam_member.github_wif_binding
}

moved {
  from = google_project_iam_member.deployer_run_admin
  to   = module.foundation.google_project_iam_member.deployer_run_admin
}

moved {
  from = google_project_iam_member.deployer_artifact_admin
  to   = module.foundation.google_project_iam_member.deployer_artifact_admin
}

moved {
  from = google_project_iam_member.deployer_sa_user
  to   = module.foundation.google_project_iam_member.deployer_sa_user
}

moved {
  from = google_project_iam_member.deployer_build_editor
  to   = module.foundation.google_project_iam_member.deployer_build_editor
}

moved {
  from = google_project_iam_member.deployer_storage_admin
  to   = module.foundation.google_project_iam_member.deployer_storage_admin
}


