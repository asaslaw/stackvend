# ==============================================================================
# SELFUP-B (P3b, pre-RC, owner 11-02): the "Update StackVend" button's one-time core Terraform
# ==============================================================================
# Plan: docs/planning/self-upgrade-plan.md §4.2-§4.5, §7.2. Fable plan RT: §5 footprint table, H-1, H-2, M-1, M-2,
# M-4, BL-2, BL-3. Report and apply counts: docs/handoff/selfup-b3-report.md; owner runbook:
# docs/handoff/selfup-apply-runbook.md.
#
# What this file creates when var.enable_platform_upgrader = true (default false: NOTHING here is planned, so the
# FD-7L step-B apply from the same commit is untouched):
#   - sa-stackvend-upgrader: build-and-deploy only. A custom role (get/list/update of the EXISTING Cloud Run services
#     and jobs, revisions and operations; no create, delete, setIamPolicy, run or invoke), Artifact Registry writer on
#     castor-docker-repo only, act-as on each runtime service account of a component it redeploys (never
#     project-wide), log writer, guard-database READ, default-database write (progress ledger + version record).
#   - topic stackvend-platform-upgrade: the Control Center's ONLY new permission is publisher on it.
#   - the Cloud Build service agent may act as the upgrader (M-1); nobody else may.
#   - trigger stackvend-platform-upgrade: Pub/Sub event, runs as the upgrader, step 0 FIXED here (validate request ->
#     fetch -> verify the signed tag against the embedded official signers -> commit pin -> floor -> manifest guard ->
#     checkout -> hand over to the verified target's scripts/upgrade/). Created after every other resource here
#     (depends_on), and the Control Center's env change waits for it (main.tf depends_on), so an org-policy refusal
#     of the trigger leaves only inert grants and the button stays hidden.
#
# The button NEVER runs Terraform: the upgrader holds no state-bucket access, no resourcemanager / iam admin, no
# create/delete of any resource type, no cloudbuild.builds.create, no run.invoker, no run.jobs.run (static tests:
# tests/test_selfup_platform_upgrader.py). Rotating the official signing key, changing step 0 or any grant here is a
# platform release (scripts/apply.sh by a person).
#
# KILL SWITCH: platform_upgrade_trigger_disabled = true (the trigger ignores messages). Do NOT set
# enable_platform_upgrader back to false on an install that applied it: the destroy would delete the custom role,
# whose id stays reserved for up to 37 days (the same as the FD-7L roles).
# ==============================================================================

locals {
  platform_upgrader_account_id = "sa-stackvend-upgrader"
  platform_upgrade_topic_name  = "stackvend-platform-upgrade"
  # Plain string (known at plan time, so the Control Center env shows exactly in the plan; tf_runner_identity.tf does
  # the same for the runner e-mails). The publisher grant below orders the CC revision after the topic exists.
  platform_upgrade_topic_path = "projects/${var.project_id}/topics/${local.platform_upgrade_topic_name}"

  # The CC env switch (main.tf, appended last): unset -> the button is hidden and the start route answers
  # 409 UPGRADER_NOT_INSTALLED. This is the apply's single in-place change (one new CC revision). Empty values are not
  # set (main.tf), so with the default false nothing changes on the Control Center.
  platform_upgrader_service_env = {
    "product-control-center-ui" = {
      STACKVEND_PLATFORM_UPGRADE_TOPIC = var.enable_platform_upgrader ? local.platform_upgrade_topic_path : ""
    }
  }

  # ---- M-4: act-as targets = every runtime service account of a component the upgrader redeploys ----------------
  # Keyed by ACCOUNT ID so the for_each keys are known at plan time on a FRESH install (bootstrap's single apply),
  # where the e-mails of not-yet-created accounts are unknown. Mirrors, one line each:
  #   google_cloud_run_v2_service.services  lookup(local.service_runtime_sa, ..., developer)  (destructive_guard.tf)
  #   google_cloud_run_v2_service.git_server sa-castor-developer                               (main.tf)
  #   google_cloud_run_v2_job.jobs           lookup(local.job_runtime_sa, ..., developer)      (destructive_guard.tf)
  #   google_cloud_run_v2_job.tf_applier     local.tf_applier_runtime_sa                       (tf_runner_identity.tf)
  #   google_cloud_run_v2_job.qa_sandbox     google_service_account.qa_sandbox                 (qa_sandbox.tf)
  # The trigger's precondition compares this set with the runtime accounts the Cloud Run resources ACTUALLY declare,
  # so a new runtime account (FD-4T) without a line here fails the plan loudly instead of breaking one upgrade.
  # 8 accounts before FD-7L step B (developer, CC, vending = provisioner, cleaner, QA sandbox, and the C10 sweeper,
  # spend sync and billing drain personas), 10 after it.
  platform_upgrader_actas_accounts = toset(concat(
    ["sa-castor-developer"],                                                                    # default runtime, git server
    ["sa-stackvend-control-center", local.vending_sa_key],                                      # local.service_runtime_sa
    var.tf_runner_dedicated_sa ? [local.tf_runner_server_account_id] : [],                      # local.tf_runner_service_runtime_sa
    ["sa-stackvend-sandbox-cleaner"],                                                           # local.job_runtime_sa
    ["sa-stackvend-sandbox-sweeper", "sa-stackvend-finops-sync", "sa-stackvend-billing-drain"], # local.job_runtime_sa (C10)
    var.tf_runner_dedicated_sa ? [local.tf_runner_job_account_id] : [],                         # local.tf_applier_runtime_sa
    [google_service_account.qa_sandbox.account_id],                                             # qa_sandbox.tf job
  ))
  # Every user-managed service account of this configuration, by account id (known keys).
  platform_upgrader_sa_by_account = merge(
    google_service_account.agents,
    google_service_account.stackvend_personas,
    google_service_account.tf_runners,
    { (google_service_account.qa_sandbox.account_id) = google_service_account.qa_sandbox },
  )

  # ---- BL-2: the OFFICIAL trust anchor, embedded at apply time --------------------------------------------------
  # Public keys only (the owner's release key, `git tag -s` with gpg.format=ssh). A missing or empty file must never
  # become an empty trust set: the trigger's precondition stops the plan.
  platform_upgrade_allowed_signers_file = "${path.module}/../../scripts/release/allowed_signers"
  platform_upgrade_allowed_signers      = fileexists(local.platform_upgrade_allowed_signers_file) ? file(local.platform_upgrade_allowed_signers_file) : ""
  platform_upgrade_signer_lines = [
    for l in split("\n", local.platform_upgrade_allowed_signers) : trimspace(l)
    if trimspace(l) != "" && !startswith(trimspace(l), "#")
  ]
  # allowed_signers line exactly as step 0 accepts it (upgrade_step0/guard.py parse_official_signers, RT L-B):
  # `<principal> [namespaces="git"] <keytype> <base64-key> [comment]`, key types of plan §3.10.3. Any other option
  # (cert-authority, valid-after=...) refuses the plan instead of refusing every build later.
  platform_upgrade_signer_line_re = "^[^ \\t]+([ \\t]+namespaces=\"git\")?[ \\t]+(ssh-ed25519|sk-ssh-ed25519@openssh\\.com|ecdsa-sha2-nistp256|sk-ecdsa-sha2-nistp256@openssh\\.com)[ \\t]+AAAA[A-Za-z0-9+/]+={0,2}([ \\t].*)?$"
  platform_upgrade_signers_valid = length(local.platform_upgrade_signer_lines) > 0 && alltrue([
    for l in local.platform_upgrade_signer_lines : can(regex(local.platform_upgrade_signer_line_re, l))
  ])

  # ---- Step 0: BYTE COPIES of scripts/upgrade/verify.sh + guard.py (builder B2's frozen reference, tested with
  # fixture repositories). They live under infra/platform/ so any change is a platform change
  # (scripts/sync_upstream_needs_apply.py APPLY_REQUIRED_PREFIXES) and needs apply.sh; tests/test_selfup_platform_upgrader.py
  # pins copy == reference. Embedded base64 (no `$` for Cloud Build's substitution to touch) and checked by SHA-256
  # after decoding in the build.
  platform_upgrade_step0_dir       = "${path.module}/upgrade_step0"
  platform_upgrade_step0_verify_sh = fileexists("${local.platform_upgrade_step0_dir}/verify.sh") ? file("${local.platform_upgrade_step0_dir}/verify.sh") : ""
  platform_upgrade_step0_guard_py  = fileexists("${local.platform_upgrade_step0_dir}/guard.py") ? file("${local.platform_upgrade_step0_dir}/guard.py") : ""

  # The unpack step: no `$` anywhere (Cloud Build substitutes $NAME / ${NAME} in args), so the text below reaches bash
  # exactly as written. Writes /workspace/step0/{verify.sh,guard.py,allowed_signers} and checks each SHA-256.
  platform_upgrade_unpack_script = join("\n", [
    "set -euo pipefail",
    "umask 022",
    "mkdir -p /workspace/step0",
    "printenv STACKVEND_STEP0_VERIFY_SH_B64 | base64 -d > /workspace/step0/verify.sh",
    "printenv STACKVEND_STEP0_GUARD_PY_B64 | base64 -d > /workspace/step0/guard.py",
    "printenv STACKVEND_OFFICIAL_ALLOWED_SIGNERS_B64 | base64 -d > /workspace/step0/allowed_signers",
    "echo '${sha256(local.platform_upgrade_step0_verify_sh)}  /workspace/step0/verify.sh' | sha256sum -c --quiet -",
    "echo '${sha256(local.platform_upgrade_step0_guard_py)}  /workspace/step0/guard.py' | sha256sum -c --quiet -",
    "echo '${sha256(local.platform_upgrade_allowed_signers)}  /workspace/step0/allowed_signers' | sha256sum -c --quiet -",
    "chmod 0555 /workspace/step0/verify.sh /workspace/step0/guard.py",
    "chmod 0444 /workspace/step0/allowed_signers",
    "",
  ])

  # Step-0 image (one image runs step 0 AND the hand-over to the verified target's stages, same step): bash, git >= 2.34,
  # ssh-keygen (OpenSSH >= 8.2, BL-3 c), python3, gcloud, curl, sha256sum, tar; the Cloud Build docker socket is
  # mounted into every step. gcr.io/google.com/cloudsdktool/cloud-sdk:591.0.0-slim (built 2026-10-27), digest resolved
  # read-only with `gcloud container images describe` on 11-03. Frozen here like the scripts.
  platform_upgrade_step0_image = "gcr.io/google.com/cloudsdktool/cloud-sdk@sha256:b38f2881552c3054d140c8eeb4ad88bdc0eb4deeeb38507c5dac1403adc3ee64"
}

# BL-3 (resolved by the live spike on castor, 11-03): a Pub/Sub trigger with an INLINE build needs no source_to_build,
# and Cloud Build creates and deletes its own subscription (projects/<number>/subscriptions/gcb-<trigger name>, pushed to
# an internal Cloud Build endpoint, no OIDC token, no push service account). So: no push identity, no tokenCreator, and
# the subscription is NOT managed here. Keep the trigger name stable (the subscription name derives from it).

# ------------------------------------------------------------------------------
# 1. The upgrader service account (tier 0: build and deploy only)
# ------------------------------------------------------------------------------
resource "google_service_account" "stackvend_upgrader" {
  count        = var.enable_platform_upgrader ? 1 : 0
  depends_on   = [google_project_service.apis]
  project      = var.project_id
  account_id   = local.platform_upgrader_account_id
  display_name = "StackVend platform upgrader (build and deploy only; never Terraform)"
}

# ------------------------------------------------------------------------------
# 2. Custom role: new revisions of EXISTING services and jobs (M-2: no iam.serviceAccounts.get, the per-account
#    serviceAccountUser grants carry get + actAs)
# ------------------------------------------------------------------------------
resource "google_project_iam_custom_role" "stackvend_upgrader_deploy" {
  count       = var.enable_platform_upgrader ? 1 : 0
  depends_on  = [google_project_service.apis]
  project     = var.project_id
  role_id     = "stackvendPlatformUpgraderDeploy"
  title       = "StackVend platform upgrader deploy"
  description = "SELFUP-B: deploy new revisions of the existing StackVend Cloud Run services and jobs. No create, delete, setIamPolicy, run or invoke. Held by sa-stackvend-upgrader only."
  # HOST-VPC-EGRESS (host_network_deployer_grants, default false): the two subnet permissions a revision carrying
  # Direct VPC egress may need, only when the live spike shows the Run Admin API asks the deployer for them.
  permissions = concat([
    "run.jobs.get",
    "run.jobs.list",
    "run.jobs.update",
    "run.operations.get",
    "run.revisions.get",
    "run.revisions.list",
    "run.services.get",
    "run.services.list",
    "run.services.update",
  ], (var.host_vpc_egress && var.host_network_deployer_grants) ? ["compute.subnetworks.get", "compute.subnetworks.use"] : [])
  stage = "GA"
}

# ------------------------------------------------------------------------------
# 3. Host project roles of the upgrader (exact set; the static test pins it)
# ------------------------------------------------------------------------------
resource "google_project_iam_member" "platform_upgrader_project_roles" {
  for_each = var.enable_platform_upgrader ? {
    "deploy"     = google_project_iam_custom_role.stackvend_upgrader_deploy[0].id
    "log-writer" = "roles/logging.logWriter"
  } : {}
  project = var.project_id
  role    = each.value
  member  = google_service_account.stackvend_upgrader[0].member
}

# Push the built images: the platform docker repository only (repo-level writer includes the reads rollback needs).
resource "google_artifact_registry_repository_iam_member" "platform_upgrader_ar_writer" {
  count      = var.enable_platform_upgrader ? 1 : 0
  project    = var.project_id
  location   = google_artifact_registry_repository.castor_docker_repo.location
  repository = google_artifact_registry_repository.castor_docker_repo.name
  role       = "roles/artifactregistry.writer"
  member     = google_service_account.stackvend_upgrader[0].member
}

# M-4: act-as on each runtime account individually (Cloud Run requires actAs on the revision's runtime account for
# every new revision). Never project-wide. H-1 / FD7L-UPGRADER-ACTAS: after step B this includes the two Terraform
# runner accounts; scripts/check-install-iam.sh accepts exactly this grant on them.
resource "google_service_account_iam_member" "platform_upgrader_act_as" {
  for_each           = var.enable_platform_upgrader ? local.platform_upgrader_actas_accounts : toset([])
  service_account_id = local.platform_upgrader_sa_by_account[each.key].name
  role               = "roles/iam.serviceAccountUser"
  member             = google_service_account.stackvend_upgrader[0].member
}

# Inputs (request, lease, release source) in the guard database: READ only, so the upgrader cannot forge them.
resource "google_project_iam_member" "platform_upgrader_guard_db_reader" {
  count   = var.enable_platform_upgrader ? 1 : 0
  project = var.project_id
  role    = "roles/datastore.viewer"
  member  = google_service_account.stackvend_upgrader[0].member

  condition {
    title       = "stackvend-guard-db-read"
    description = "stackvend-guard database only, read-only (SELFUP-B upgrade request, lease, release source)"
    expression  = local.guard_db_condition
  }

  depends_on = [google_firestore_database.stackvend_guard]
}

# Progress ledger and version record in the default database (M-11: like every agent SA; never the guard database).
resource "google_project_iam_member" "platform_upgrader_datastore_user" {
  count   = var.enable_platform_upgrader ? 1 : 0
  project = var.project_id
  role    = "roles/datastore.user"
  member  = google_service_account.stackvend_upgrader[0].member

  condition {
    title       = "stackvend-not-guard-db"
    description = "Every Firestore database except the stackvend-guard database (lane 18 S0b)"
    expression  = "!(${local.guard_db_condition})"
  }
}

# HOST-VPC-EGRESS (host_network_deployer_grants, default false; host_network.tf): use of the stackvend-host subnet,
# on that one subnet only, for the revisions the upgrader deploys with Direct VPC egress. Planned only when the live
# spike shows the Run Admin API requires it of the deployer.
resource "google_compute_subnetwork_iam_member" "platform_upgrader_subnet_user" {
  count      = (var.enable_platform_upgrader && var.host_vpc_egress && var.host_network_deployer_grants) ? 1 : 0
  project    = var.project_id
  region     = var.region
  subnetwork = google_compute_subnetwork.host_run_egress[0].name
  role       = "roles/compute.networkUser"
  member     = google_service_account.stackvend_upgrader[0].member
}

# ------------------------------------------------------------------------------
# 4. Request path: one topic; the Control Center is its ONLY publisher (plan §4.3, §4.5)
# ------------------------------------------------------------------------------
resource "google_pubsub_topic" "platform_upgrade" {
  count      = var.enable_platform_upgrader ? 1 : 0
  depends_on = [google_project_service.apis]
  project    = var.project_id
  name       = local.platform_upgrade_topic_name
}

resource "google_pubsub_topic_iam_member" "cc_platform_upgrade_publisher" {
  count   = var.enable_platform_upgrader ? 1 : 0
  project = var.project_id
  topic   = google_pubsub_topic.platform_upgrade[0].name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${local.cc_sa_email}"
}

# SELFUP-BOOTSTRAP-ON: a new install applies the upgrader in its FIRST apply, when the Cloud Build service agent may
# not exist yet; create it explicitly before binding it, like the IAP / Logging / Workflows agents in main.tf.
resource "google_project_service_identity" "cloudbuild_sa" {
  count      = var.enable_platform_upgrader ? 1 : 0
  provider   = google-beta
  depends_on = [google_project_service.apis]
  project    = var.project_id
  service    = "cloudbuild.googleapis.com"
}

# M-1: the Cloud Build service agent runs the trigger's builds as the upgrader. It is the ONLY principal that may act
# as the upgrader (no serviceAccountUser / token creator on it for people or other accounts).
resource "google_service_account_iam_member" "cloudbuild_agent_act_as_upgrader" {
  count              = var.enable_platform_upgrader ? 1 : 0
  depends_on         = [google_project_service.apis, google_project_service_identity.cloudbuild_sa]
  service_account_id = google_service_account.stackvend_upgrader[0].name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:service-${data.google_project.platform_project.number}@gcp-sa-cloudbuild.iam.gserviceaccount.com"
}

# ------------------------------------------------------------------------------
# 5. The trigger (LAST): fixed step 0, runs as the upgrader, optional console approval (H-2)
# ------------------------------------------------------------------------------
resource "google_cloudbuild_trigger" "platform_upgrade" {
  count    = var.enable_platform_upgrader ? 1 : 0
  project  = var.project_id
  location = var.region
  # STABLE: Cloud Build names its auto-created subscription gcb-<this name> (BL-3 spike); renaming = a new trigger
  # and a new subscription.
  name        = "stackvend-platform-upgrade"
  description = "SELFUP-B: Update StackVend (services and jobs only, never Terraform). Started by the Control Center through ${local.platform_upgrade_topic_name}; step 0 verifies the signed release before anything from it runs."
  disabled    = var.platform_upgrade_trigger_disabled
  tags        = ["stackvend-platform-upgrade"]

  service_account = google_service_account.stackvend_upgrader[0].id

  # No service_account_email and no source_to_build (BL-3 spike): Cloud Build owns the subscription and its push.
  pubsub_config {
    topic = google_pubsub_topic.platform_upgrade[0].id
  }

  # H-2 (SELFUP-APPROVAL): an administrator approves every upgrade build in the Google Cloud console with their own
  # Google account. On by default; the owner may turn it off in the tfvars.
  approval_config {
    approval_required = var.platform_upgrade_approval_required
  }

  # The Control Center publishes the request id as the message ATTRIBUTE request_id (plain text; `data` is base64).
  # Step 0 accepts only 32 lowercase hex before any read and re-reads the request from the guard database. Nothing
  # else in the message is used.
  substitutions = {
    _REQUEST_ID = "$(body.message.attributes.request_id)"
  }

  build {
    timeout = "7200s"

    options {
      logging      = "CLOUD_LOGGING_ONLY"
      machine_type = "E2_HIGHCPU_8"
    }

    # Step 0a: unpack the embedded files (fixed text, no `$`, SHA-256 checked).
    step {
      id         = "step0-unpack"
      name       = local.platform_upgrade_step0_image
      entrypoint = "bash"
      args       = ["-c", local.platform_upgrade_unpack_script]
      env = [
        "STACKVEND_STEP0_VERIFY_SH_B64=${base64encode(local.platform_upgrade_step0_verify_sh)}",
        "STACKVEND_STEP0_GUARD_PY_B64=${base64encode(local.platform_upgrade_step0_guard_py)}",
        "STACKVEND_OFFICIAL_ALLOWED_SIGNERS_B64=${base64encode(local.platform_upgrade_allowed_signers)}",
      ]
    }

    # Step 0b: verify, then hand over to the verified target (same step, same image). No shell parses the request id:
    # Cloud Build substitutes it into its own argv element, and verify.sh rejects anything but 32 lowercase hex.
    step {
      id         = "step0-verify"
      name       = local.platform_upgrade_step0_image
      entrypoint = "bash"
      args = [
        "/workspace/step0/verify.sh", "run",
        "--request-id", "$_REQUEST_ID",
        "--project", var.project_id,
        "--region", var.region,
        "--guard-database", google_firestore_database.stackvend_guard.name,
        "--official-signers", "/workspace/step0/allowed_signers",
        "--workdir", "/workspace/up",
      ]
      wait_for = ["step0-unpack"]
    }
  }

  depends_on = [
    google_project_iam_custom_role.stackvend_upgrader_deploy,
    google_project_iam_member.platform_upgrader_project_roles,
    google_artifact_registry_repository_iam_member.platform_upgrader_ar_writer,
    google_service_account_iam_member.platform_upgrader_act_as,
    google_project_iam_member.platform_upgrader_guard_db_reader,
    google_project_iam_member.platform_upgrader_datastore_user,
    google_pubsub_topic_iam_member.cc_platform_upgrade_publisher,
    google_project_service_identity.cloudbuild_sa,
    google_service_account_iam_member.cloudbuild_agent_act_as_upgrader,
    google_compute_subnetwork_iam_member.platform_upgrader_subnet_user,
  ]

  lifecycle {
    # BL-2: never an empty or malformed trust set.
    precondition {
      condition     = local.platform_upgrade_signers_valid
      error_message = "SELFUP BL-2: scripts/release/allowed_signers is missing, empty or malformed. It must hold the official StackVend release public key (one line per key: '<principal> ssh-ed25519 AAAA...'; created by the owner, private key never in the repository). The upgrade trigger embeds it as the official signer set and is never created with an empty trust set."
    }
    # Step 0 must be the embedded copies of scripts/upgrade/verify.sh + guard.py.
    precondition {
      condition     = local.platform_upgrade_step0_verify_sh != "" && local.platform_upgrade_step0_guard_py != ""
      error_message = "SELFUP: infra/platform/upgrade_step0/verify.sh or guard.py is missing. Copy scripts/upgrade/verify.sh and guard.py byte for byte (tests/test_selfup_platform_upgrader.py checks the copies)."
    }
    precondition {
      condition     = can(regex("^[a-z0-9.-]+(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$", local.platform_upgrade_step0_image))
      error_message = "SELFUP: the step-0 builder image (local.platform_upgrade_step0_image in platform_upgrader.tf) is not pinned by digest."
    }
    # M-4: the act-as set equals the runtime identities the Cloud Run services and jobs are given, read from the same
    # locals they use (services/jobs: lookup(..., developer); git server: developer; tf-applier; QA sandbox job).
    # Locals, not the Cloud Run resources: the Control Center service depends on THIS trigger (main.tf), so the button
    # never appears unless the trigger exists. Checked at apply time on a fresh install (e-mails unknown at plan).
    precondition {
      condition = toset([for acc in local.platform_upgrader_actas_accounts : local.platform_upgrader_sa_by_account[acc].email]) == toset(concat(
        values(local.service_runtime_sa),
        values(local.job_runtime_sa),
        [local.tf_applier_runtime_sa, google_service_account.qa_sandbox.email, local.developer_sa_email],
      ))
      error_message = "SELFUP M-4: the upgrader's act-as accounts (local.platform_upgrader_actas_accounts) differ from the runtime service accounts of the Cloud Run services and jobs it redeploys. Add the new runtime account there (FD-4T) so every component can be upgraded."
    }
  }
}
