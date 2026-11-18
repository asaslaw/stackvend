"""GHA-DEPLOY-SWITCH test support: the exact edits GHA-DEPLOY-SWITCH makes to infra/modules/workload-foundation/base
(variables.tf, wif.tf, iam.tf, outputs.tf), as (before, after) text pairs.

`without_gha_switch(name, text)` undoes them (each `after` replaced by its `before`, once), so older byte-identity
pins of the vendored foundation files keep proving "nothing else changed"; tests/test_gha_deploy_switch.py pins that
undoing them on today's module gives the base files (tests/fixtures/gha_switch/pre_gha_<name>.txt, main 3dfe3f73)
byte for byte and that every `after` occurs exactly once.
"""

_DEP_OLD = 'member  = "serviceAccount:${google_service_account.github_deployer.email}"'
_DEP_NEW = 'member  = "serviceAccount:${google_service_account.github_deployer[0].email}"'

# FD-7L 2b (review F1; not a GHA-DEPLOY-SWITCH edit): the build-SA grant reads the project number from a data source
# (known at plan time). It is the last iam.tf entry, so it is undone first and the GHA edits apply as before.
_BUILD_SA_FD7L_BEFORE = (
    "# `--source` submits a Cloud Build that runs as the project's default build SA\n"
    "# (the Compute Engine default SA in child projects). The project number comes from the WIF pool's resource\n"
    "# name (projects/<project_number>/locations/global/workloadIdentityPools/<id>), which is in every tenant's state.\n"
    'resource "google_service_account_iam_member" "deployer_build_sa_user" {\n'
    '  count              = local.github_actions_deploy_count\n'
    '  service_account_id = "projects/${var.project_id}/serviceAccounts/${split("/", '
    'google_iam_workload_identity_pool.github_pool[0].name)[1]}-compute@developer.gserviceaccount.com"\n')
_BUILD_SA_FD7L_AFTER = (
    "# `--source` submits a Cloud Build that runs as the project's default build SA\n"
    "# (the Compute Engine default SA in child projects). FD-7L 2b (review F1): the project number is read from the\n"
    "# project itself (a data source, known at plan time), so this grant's service_account_id is a known string that the\n"
    "# platform's identity content policy checks before the apply. It used to come from the WIF pool's resource name\n"
    "# (projects/<project_number>/...), which is unknown until the pool exists; the value is the same.\n"
    'data "google_project" "this" {\n'
    '  count      = local.github_actions_deploy_count\n'
    '  project_id = var.project_id\n'
    '}\n'
    '\n'
    'resource "google_service_account_iam_member" "deployer_build_sa_user" {\n'
    '  count              = local.github_actions_deploy_count\n'
    '  service_account_id = "projects/${var.project_id}/serviceAccounts/${data.google_project.this[0].number}'
    '-compute@developer.gserviceaccount.com"\n')

# SA-ACCOUNT-ID-TRIM (not a GHA-DEPLOY-SWITCH edit; tests/test_sa_account_id_trim.py): the workload SA account_id drops
# the trailing dashes of its 20-character cut. The last iam.tf entry, so it is undone first.
_WORKLOAD_SA_TRIM_BEFORE = (
    'resource "google_service_account" "workload_sa" {\n'
    '  project      = var.project_id\n'
    '  account_id   = "sa-${substr(replace(var.product_id, "_", "-"), 0, 20)}"\n')
_WORKLOAD_SA_TRIM_AFTER = (
    "# SA-ACCOUNT-ID-TRIM: trailing dashes of the 20-character cut are dropped (an account_id cannot end in '-'); a cut\n"
    "# that does not end in '-' is unchanged.\n"
    'resource "google_service_account" "workload_sa" {\n'
    '  project      = var.project_id\n'
    '  account_id   = "sa-${replace(substr(replace(var.product_id, "_", "-"), 0, 20), "/-+$/", "")}"\n')

EDITS = {
    "variables.tf": [(
        'variable "github_default_branch" {',
        'variable "enable_github_actions_deploy" {\n'
        '  description = "GHA-DEPLOY-SWITCH: the workload\'s GitHub Actions deploy path. true (the default, the module '
        'before this input existed) creates the Workload Identity Federation pool and provider, the deployer service '
        'account sa-gh-deployer and its roles, so the generated .github/workflows/deploy-<service>.yml can deploy the '
        'app. false creates none of them: every deploy goes through the platform\'s pipeline. Supplied by the platform '
        'from the workload record."\n'
        '  type        = bool\n'
        '  default     = true\n'
        '  nullable    = false\n'
        '}\n'
        '\n'
        'variable "github_default_branch" {',
    )],
    "wif.tf": [
        ('  wif_repository_id_clause = var.github_repository_id == "" ? "" : " && assertion.repository_id == '
         '\'${var.github_repository_id}\'"\n'
         '}\n'
         '\n'
         'resource "google_iam_workload_identity_pool" "github_pool" {\n'
         '  project                   = var.project_id',
         '  wif_repository_id_clause = var.github_repository_id == "" ? "" : " && assertion.repository_id == '
         '\'${var.github_repository_id}\'"\n'
         '  # GHA-DEPLOY-SWITCH: one instance of every GitHub Actions deploy resource (pool, provider, deployer SA, its WIF\n'
         '  # binding and roles) while the switch is on (default), none when it is off.\n'
         '  github_actions_deploy_count = var.enable_github_actions_deploy ? 1 : 0\n'
         '}\n'
         '\n'
         '# GHA-DEPLOY-SWITCH: the resources below and the deployer roles in iam.tf gained `count`. These moved blocks keep '
         'the\n'
         '# existing single instance as [0], so a workload with the switch on plans no change.\n'
         'moved {\n'
         '  from = google_iam_workload_identity_pool.github_pool\n'
         '  to   = google_iam_workload_identity_pool.github_pool[0]\n'
         '}\n'
         '\n'
         'moved {\n'
         '  from = google_iam_workload_identity_pool_provider.github_provider\n'
         '  to   = google_iam_workload_identity_pool_provider.github_provider[0]\n'
         '}\n'
         '\n'
         'moved {\n'
         '  from = google_service_account.github_deployer\n'
         '  to   = google_service_account.github_deployer[0]\n'
         '}\n'
         '\n'
         'moved {\n'
         '  from = google_service_account_iam_member.github_wif_binding\n'
         '  to   = google_service_account_iam_member.github_wif_binding[0]\n'
         '}\n'
         '\n'
         'resource "google_iam_workload_identity_pool" "github_pool" {\n'
         '  count                     = local.github_actions_deploy_count\n'
         '  project                   = var.project_id'),
        ('resource "google_iam_workload_identity_pool_provider" "github_provider" {\n'
         '  project                            = var.project_id\n'
         '  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id',
         'resource "google_iam_workload_identity_pool_provider" "github_provider" {\n'
         '  count                              = local.github_actions_deploy_count\n'
         '  project                            = var.project_id\n'
         '  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool[0].workload_identity_pool_id'),
        ('resource "google_service_account" "github_deployer" {\n'
         '  project      = var.project_id',
         'resource "google_service_account" "github_deployer" {\n'
         '  count        = local.github_actions_deploy_count\n'
         '  project      = var.project_id'),
        ('resource "google_service_account_iam_member" "github_wif_binding" {\n'
         '  service_account_id = google_service_account.github_deployer.name\n'
         '  role               = "roles/iam.workloadIdentityUser"\n'
         '  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}'
         '/attribute.repository/${var.github_repo_full_name}"\n'
         '}',
         'resource "google_service_account_iam_member" "github_wif_binding" {\n'
         '  count              = local.github_actions_deploy_count\n'
         '  service_account_id = google_service_account.github_deployer[0].name\n'
         '  role               = "roles/iam.workloadIdentityUser"\n'
         '  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool[0].name}'
         '/attribute.repository/${var.github_repo_full_name}"\n'
         '}'),
    ],
    "iam.tf": [
        ('# 1. CI/CD Deployer Service Account Roles\n'
         '# ------------------------------------------------------------------------------\n',
         '# 1. CI/CD Deployer Service Account Roles\n'
         '# ------------------------------------------------------------------------------\n'
         '# GHA-DEPLOY-SWITCH: every deployer grant exists only while the switch is on (local.github_actions_deploy_count,\n'
         '# wif.tf); the moved blocks keep the existing single instance as [0] (no change with the switch on).\n'
         + "".join(f'moved {{\n  from = {a}\n  to   = {a}[0]\n}}\n\n' for a in (
             "google_project_iam_member.deployer_run_source_developer",
             "google_project_iam_member.deployer_logging_viewer",
             "google_project_iam_member.deployer_container_developer",
             "google_service_account_iam_member.deployer_runtime_sa_user",
             "google_service_account_iam_member.deployer_build_sa_user"))),
    ] + [
        (f'resource "google_project_iam_member" "{n}" {{\n  project = var.project_id\n  role    = "{r}"\n  {_DEP_OLD}',
         f'resource "google_project_iam_member" "{n}" {{\n  count   = local.github_actions_deploy_count\n'
         f'  project = var.project_id\n  role    = "{r}"\n  {_DEP_NEW}')
        for n, r in (("deployer_run_source_developer", "roles/run.sourceDeveloper"),
                     ("deployer_logging_viewer", "roles/logging.viewer"),
                     ("deployer_container_developer", "roles/container.developer"))
    ] + [
        ('resource "google_service_account_iam_member" "deployer_runtime_sa_user" {\n'
         '  service_account_id = google_service_account.workload_sa.name\n'
         '  role               = "roles/iam.serviceAccountUser"\n'
         '  member             = "serviceAccount:${google_service_account.github_deployer.email}"\n'
         '}',
         'resource "google_service_account_iam_member" "deployer_runtime_sa_user" {\n'
         '  count              = local.github_actions_deploy_count\n'
         '  service_account_id = google_service_account.workload_sa.name\n'
         '  role               = "roles/iam.serviceAccountUser"\n'
         '  member             = "serviceAccount:${google_service_account.github_deployer[0].email}"\n'
         '}'),
        ('resource "google_service_account_iam_member" "deployer_build_sa_user" {\n'
         '  service_account_id = "projects/${var.project_id}/serviceAccounts/${split("/", '
         'google_iam_workload_identity_pool.github_pool.name)[1]}-compute@developer.gserviceaccount.com"\n'
         '  role               = "roles/iam.serviceAccountUser"\n'
         '  member             = "serviceAccount:${google_service_account.github_deployer.email}"\n'
         '}',
         'resource "google_service_account_iam_member" "deployer_build_sa_user" {\n'
         '  count              = local.github_actions_deploy_count\n'
         '  service_account_id = "projects/${var.project_id}/serviceAccounts/${split("/", '
         'google_iam_workload_identity_pool.github_pool[0].name)[1]}-compute@developer.gserviceaccount.com"\n'
         '  role               = "roles/iam.serviceAccountUser"\n'
         '  member             = "serviceAccount:${google_service_account.github_deployer[0].email}"\n'
         '}'),
        (_BUILD_SA_FD7L_BEFORE, _BUILD_SA_FD7L_AFTER),
        (_WORKLOAD_SA_TRIM_BEFORE, _WORKLOAD_SA_TRIM_AFTER),
    ],
    "outputs.tf": [
        ('  description = "CI/CD GitHub Actions deployer service account email"\n'
         '  value       = google_service_account.github_deployer.email',
         '  description = "CI/CD GitHub Actions deployer service account email (null when enable_github_actions_deploy '
         'is false)"\n'
         '  value       = one(google_service_account.github_deployer[*].email)'),
        ('  description = "Workload Identity Pool name"\n'
         '  value       = google_iam_workload_identity_pool.github_pool.name',
         '  description = "Workload Identity Pool name (null when enable_github_actions_deploy is false)"\n'
         '  value       = one(google_iam_workload_identity_pool.github_pool[*].name)'),
        ('  description = "Workload Identity Provider resource name"\n'
         '  value       = google_iam_workload_identity_pool_provider.github_provider.name',
         '  description = "Workload Identity Provider resource name (null when enable_github_actions_deploy is false)"\n'
         '  value       = one(google_iam_workload_identity_pool_provider.github_provider[*].name)'),
    ],
}


def without_gha_switch(name: str, text: str) -> str:
    """`text` (module file `name`) with the GHA-DEPLOY-SWITCH edits undone, in reverse order (no-op for a file
    without them)."""
    for before, after in reversed(EDITS.get(name, [])):
        text = text.replace(after, before, 1)
    return text
