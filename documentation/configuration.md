# Platform Configuration Guide

StackVend keeps its runtime configuration in Firestore (document `system_config/platform_settings`), with a 60-second in-memory cache in each service. Administrators change values in the Control Center **Settings** tab; the [Settings Reference](settings-reference.md) describes each control on that page, what reads it, and which stored fields are not used yet. If the document does not exist, built-in defaults are used. The schema and defaults are defined in `shared/settings.py` (copied into several services; see [`CONTRIBUTING.md`](../CONTRIBUTING.md)).

Infrastructure-level choices (project, region, ingress, VCS provider) are set once in `infra/platform/<project_id>.tfvars` (one file per install, written by `scripts/bootstrap.sh`; `scripts/apply.sh` also accepts `terraform.tfvars` when its `project_id` matches, but the installer refuses to run while that file exists); see `infra/platform/terraform.tfvars.example` and [Platform variables](#platform-variables-project_idtfvars) below.

> **Names.** Some keys, variables and secrets still carry the historical `castor` prefix. They are shown exactly as they appear in the code.

---

## 1. Orchestration and IaC settings

| Setting key | Default | Description |
| :--- | :--- | :--- |
| `default_iac_engine` | `OPENTOFU` | Engine for newly created workloads: `OPENTOFU` or `TERRAFORM`. |
| `tofu_version` | `1.9.0` | OpenTofu version the Terraform MCP server / `tf-applier` uses (MPL-2.0 licensed). The release archive is downloaded from the official OpenTofu GitHub releases and runs only after it matches a pinned SHA-256 checksum; a binary already on `PATH` is never used. Only versions with a pinned checksum run (`1.8.8`, `1.9.0` and `1.10.0`, the versions the Settings list offers); any other version fails the deploy with `ENGINE_UNVERIFIABLE`. This setting is for workloads only: installing the host platform (`infra/platform`) needs OpenTofu 1.10 or later on the installer's machine (`required_version`, checked first by `scripts/bootstrap.sh` / `scripts/apply.sh`); platform installs have been verified with OpenTofu 1.13.x. |
| `terraform_version` | `1.5.7` | HashiCorp Terraform version, for workloads that select `TERRAFORM`. **Only the 1.5.x series is accepted:** the service refuses to run Terraform 1.6 or later (BUSL licensed). The release archive runs only after it matches a pinned SHA-256 checksum (`1.5.7` has one); a version without one fails the deploy with `ENGINE_UNVERIFIABLE`. |
| `supported_tofu_versions` | `["1.8.8", "1.9.0", "1.10.0"]` | Versions offered in the Settings UI dropdown. This is a UI list only and may lag behind versions that work. |
| `supported_terraform_versions` | `["1.5.7"]` | Versions offered in the Settings UI dropdown: only versions the service accepts at run time (below 1.6). A stored entry of 1.6 or later is dropped when the settings are read, and a save that selects one is refused (HTTP 422, `TERRAFORM_VERSION_REFUSED`). |
| `default_gcp_region` | `us-central1` | The default workload region: selected first on the New Workload form and used when a create request names no `region`. A workload keeps the region recorded at its creation; a workload created before approved regions has none and follows this setting at its next deploy. Must be one of `approved_deployable_regions`. |
| `approved_deployable_regions` | empty | The regions a new workload may be created in (Settings **Approved Deployable Regions**); empty means `default_gcp_region` only. A region outside the list is refused at creation (`REGION_NOT_APPROVED`); a save that adds a region Cloud Run does not offer (`REGION_UNKNOWN`) or removes one a workload still uses (`REGION_IN_USE`) is refused. |
| `default_folder_id` | empty | Not used at present: the default folder is the one marked default on the Settings **GCP Folders** tab, else the managed workloads root. |
| `default_terraform_timeout_seconds` | `3600` | Not used at present. |
| `terraform_lock_timeout_seconds` | `180` | How long a deploy waits for the workload's state lock (`-lock-timeout` and the Terraform server's pre-flight wait) before it stops with `STATE_LOCKED`. A lock is never broken. The server's `TF_LOCK_TIMEOUT` environment variable, when set, wins; unreadable settings: 180. |
| `stale_lock_threshold_minutes` | `20` | A held state lock older than this is reported as stale (`lock_info.is_stale` in the `STATE_LOCKED` result). Report only: StackVend never clears a state lock automatically. `TF_STALE_LOCK_MAX_AGE_MINUTES`, when set, wins; unreadable settings: 20. |
| `max_concurrent_builds` | `1` (1 to 20) | How many builds that use the AI models run at the same time: new Agent-mode workloads, **Full Swarm Rebuild** and **Resume Developer** relaunches (also an Auto relaunch that resolves to one of them), promotions, and Drive, refactor-scanner and SRE builds. A build over the limit is not started: it is recorded `QUEUED` (the Control Center answers HTTP 202 with `build_queue {position, ahead, limit, running}`) and starts, oldest first, when a running build ends. **Fast-Path Deploy**, Express, redeploy and **Upgrade IaC** never wait. **Abort** on a queued build cancels it. Lowering the value never stops a running build; it only holds new ones until fewer are running. A run waiting for a person (a plan, quota or pull-request approval) gives its slot to the next queued build; when it is approved (or sent back for rework) it takes a slot again, and when none is free it waits at the head of the queue, ahead of new submissions, and goes on when a slot frees. The Flight Deck shows such a run as *waiting for approval — not holding a build slot*, then *approved — waiting for a build slot (#n in line)*. Unreadable settings: 1 (never unlimited). The accounting is the Firestore document `system_config/build_admission`; a run whose workflow never started within 20 minutes of getting its slot is failed `BUILD_DISPATCH_LOST` and its slot freed. A build event that arrives after its workload was decommissioned or archived (`BUILD_QUEUE_WORKLOAD_GONE`), or after its run already ended, for example was aborted (`RUN_ALREADY_ENDED`), starts nothing and frees its slot; decommissioning a workload also cancels its builds that hold a slot but have not started yet. |
| `max_pipeline_retries` | `3` | Not used at present. |
| `ipam_supernet_cidr` | `10.100.0.0/16` | Address pool from which workload network ranges are carved. |
| `ipam_connector_prefix` / `ipam_subnet_prefix` | `28` / `24` | Prefix lengths for Serverless VPC Access connectors and standard subnets. |
| `ipam_psa_prefix` | `20` (16 to 24) | Prefix length of the Private Services Access range a typed workload with AlloyDB, Cloud SQL or a Vertex AI endpoint gets from the pool (new ranges only). |
| `default_container_memory_mb` / `default_container_cpu` | `512` / `1` | Memory (MiB) and vCPU of an Agent-mode Cloud Run service with no heavy packages; a data or compute sizing tier keeps its larger value. A combination Cloud Run cannot run (for example more than 4096 MB with 1 vCPU, or 3 vCPU) is not applied. Read once per developer run; unreadable settings: 512 / 1. |
| `default_branch` | `main` | The branch a new workload gets when its create request (or Drive intake) names none: repository default branch, deploy workflow trigger, release pull request target. Existing workloads keep their recorded branch. Not a plain branch name: `main`. |

How the IaC binary is chosen (`_ensure_binary` in `mcp-servers/terraform/service.py`): the version comes from the call, then the `OPENTOFU_VERSION` / `TERRAFORM_VERSION` environment variables, then the settings above. If a `tofu` / `terraform` binary is already on `PATH` in the container it is used as is; otherwise the requested version is downloaded and cached. Requests for Terraform 1.6 or later raise an error.

Runtime settings (Python version for buildpacks, Cloud Build machine type and timeout) are in the `RuntimeSettings` group of the same schema.

---

## 2. AI model settings

Each agent role has its own configured Gemini model, so the models in use are a deployment choice rather than a fixed part of the design. The `AgentModelSettings` group contains `architect_model`, `developer_model`, `finops_model` and `assistant_model`, plus output-token ceilings (`max_output_tokens` and per-role limits) and `default_thinking_budget`. A new install uses `gemini-4-carbon` for every role and `gemini-4-argon`, then `gemini-3.8-flash`, then `gemini-3.7-flash` as the fallback models (`DEFAULT_PRIMARY_MODEL` / `DEFAULT_FALLBACK_MODELS` in `shared/gemini_model_config.py`); an existing install keeps the models its saved settings name. Carbon costs several times more per pipeline run than `gemini-3.8-flash` (about 4.5 times on simpler examples, 6 to 9 times on harder ones in offline evaluations); administrators can pick any Gemini model id per role in **Settings** (checked with one live call on save). `finops_model` writes a short recommendation on each budget-breach approval card (one call per card, after the enforcement action; it sees only the workload id and the spend numbers). A stored `max_output_tokens` is used as it is, and an empty `architect_max_output_tokens` / `developer_max_output_tokens` means `max_output_tokens`.

Overrides and related environment variables:

* `GEMINI_MODEL`: the model a role uses only when its setting is empty (or the settings cannot be read). It never outranks a role's settings model; the compliance agent uses the architect's model. The platform Terraform sets it from the `gemini_model` variable (default `gemini-3.7-flash`).
* `ARCHITECT_CRITIC_MODEL`: model for the red-team critic (defaults to the architect's model).
* If a model is unavailable or deprecated, the services fall back through a short cascade of alternative models.

Two backends are supported:

1. **Vertex AI** using the services' own service accounts (the default). The installer does not ask for an API key: the build agents and the Control Center assistant use Vertex AI.
2. **Google AI Studio API key.** Kept for existing installs: when the Secret Manager secret `castor-gemini-api-key` already has an enabled version, `scripts/bootstrap.sh` sets `cc_gemini_api_key_from_secret = true` and wires the key into the Control Center as a secret reference, and the assistant uses it.

---

## 3. Version control systems (VCS)

The `vcs_provider` platform variable (and the `governance.vcs_provider` setting) selects the default provider; workloads may override it at creation time. Supported values are `GITHUB` and `SERVERLESS_GIT`.

### GitHub

* Credentials are read from one Secret Manager secret, `castor-github-app-private-key`, containing a JSON document with `app_id` (or `client_id`), `installation_id` and `private_key` for a GitHub App.
* **Organizations only.** The GitHub owner (`github_owner`) must be an organization with the GitHub App installed: StackVend acts through short-lived App installation tokens, which can create repositories only in such an organization. Personal GitHub accounts are not supported; repository vending for an owner that is not an organization stops with `GITHUB_OWNER_NOT_ORGANIZATION`, and the Settings VCS card shows **Owner Not an Organization**. A `pat` key, if present, is still read as a fallback token for organization repositories; it does not enable personal accounts and will be removed in the next release.
* Creates a repository per workload (named after the workload id by default, for example `<organization>/payment-service`), opens pull requests and posts release certificates. A workload created before this release keeps its recorded `castor-<product_id>` repository. Vending never uses an existing repository of that name that it did not record for the workload (for example a staff repository): the vend stops with `GITHUB_REPOSITORY_NAME_TAKEN` and nothing is changed; rename or remove that repository, create the workload with another id, or enter another existing repository in **Target GitHub Repository** on the New Workload form. When GitHub cannot be read the vend stops with `GITHUB_REPOSITORY_UNREADABLE`; run it again.

### Serverless Git

* The `castor-git-server` Cloud Run service (`apps/git-server`) stores bare repositories in a Cloud Storage bucket (`castor-git-repos-<project-id>`).
* Useful for evaluation or restricted-egress environments. Set `vcs_provider = "SERVERLESS_GIT"` and `deploy_git_server = true`.

### Commit author

Commits the platform makes (both providers and the Serverless Git server) use the e-mail in the `STACKVEND_GIT_AUTHOR_EMAIL` environment variable. When it is unset they use `stackvend-agent@noreply.invalid`, a reserved address that no one can own.

The commit that **Upgrade IaC** makes in the Control Center uses the same author e-mail, and names the operator who pressed the button in its author name (`<operator e-mail> (via StackVend IaC Engine)`). That e-mail, the audit record's `triggered_by` and the pull request's "Triggered By" line are always the signed-in caller's verified address; an `author` value in the request body is ignored.

---

## 4. FinOps and budget controls

| Setting key | Default | Description |
| :--- | :--- | :--- |
| `default_monthly_budget_usd` | `40.0` | Budget of a new workload created without one (allowed range 5 to 5000): the create form is pre-filled with it, an API request without `budget_ceiling_monthly_usd` gets it, and project vending gives it to a new record that has none (a Drive intake). Existing workloads keep theirs. |
| `warning_threshold_pct` | `80.0` | A Cloud Billing budget notification at or above this share of a workload's ceiling (or approved buffer ceiling), and below the circuit breaker, records a `BUDGET_WARNING_THRESHOLD` entry (severity `WARNING`; one per workload and billing month, updated with the latest spend) in the `billing_alerts` collection and the Control Center log. Nothing is stopped. |
| `circuit_breaker_threshold_pct` | `100.0` | The breach policy fires when spend reaches this share of the workload's own ceiling. An approved buffer ceiling is used as it is. |
| `enforce_scale_to_zero_default` | `true` | On: an Agent-mode Cloud Run service whose spec or architect plan states no minimum instance count scales to zero. Off: such a service keeps one warm instance (billed while idle). A stated minimum always wins. |
| `default_breach_policy` | `AUTONOMOUS_SCALE_TO_ZERO` | Breach policy for a new workload created without one. One of `AUTONOMOUS_SCALE_TO_ZERO`, `ALERT_ONLY`, `HITL_CONFIRMATION_REQUIRED`, `NUCLEAR_UNLINK_BILLING`. |

A Cloud Scheduler job (`castor-finops-nightly-spend-sync`, daily at 03:00 in the `America/New_York` time zone) runs the `finops-spend-sync-job` Cloud Run job, which refreshes spend and projected month-end run rate in Firestore. Operators can also trigger a sync per workload, or for all workloads (administrators). The breach policy is a default for new workloads and can be changed per workload.

Budget alerts: a Cloud Billing budget connected to the `billing-budget-alerts` Pub/Sub topic is read by the `billing-alert-drain-job` Cloud Run job every 30 minutes (Cloud Scheduler `stackvend-billing-alert-drain`). It acts only on a notification from this install's billing account (`billing_account_id`) whose budget maps exactly to a workload (the workload's recorded budget id, or a budget named `budget-<workload id>`). On a breach it applies the workload's breach policy through `finops-budget-enforcer-job`, once per workload, billing month and threshold. To stop automatic enforcement, set `billing_breach_enforcement_enabled = false` in the platform tfvars and run `scripts/apply.sh apply`; the drain job then records spend and warnings only and leaves breach notifications unacknowledged (they end in the dead-letter topic).

---

## 5. Folders and organization policies

* **Default parent folder.** Child projects are created under a parent folder such as `folders/<FOLDER_ID>`; set it with the `castor_managed_workloads_folder_id` Terraform variable; sub-folders and the default folder for new workloads are managed on the Settings **GCP Folders** tab. Google Cloud only has folders inside an organization, so personal accounts without an organization cannot vend child projects.
* **Per-workload folder.** A different folder can be chosen when creating a workload, or a workload can be moved with the "deploy to folder" action.
* **Organization-policy harvesting.** Before planning, the compliance MCP server (`compliance_mcp_url` in the workflow) reads the effective organization policies for the target and passes the following to the agents as constraints: `domain_restricted_sharing`, `enforce_private_ingress`, `disallow_vm_external_ip`, `disallow_default_network`, `enforce_uniform_bucket_level_access` and `require_os_login`. If the organization policy requires internal-only Cloud Run ingress (`enforce_private_ingress`), a plan with a Cloud Run service stops at the compliance stage: see [Known limitations](known-limitations.md#cloud-run-services-cannot-be-made-internal-only-yet).

---

## 6. Quotas and IPAM

* **Regional quota headroom.** Before the architect runs, the quota inspector checks regional quotas in candidate regions (`us-central1`, `us-east4`, `europe-west1` by default) and a later feasibility gate refuses plans that clearly will not fit. The Control Center's regional quota view shows the approved deployable regions unless regions are named in the request.
* **IPAM.** `shared/ipam.py` allocates non-overlapping ranges from `ipam_supernet_cidr`. Ranges of decommissioned workloads are kept as `RESERVED_DECOMMISSIONED` so they are not reused immediately.

---

## Secrets in the host project

The platform Terraform creates these Secret Manager secrets in the host project. Most start empty and several stay empty for good; a secret is in use only when it has an enabled version (`gcloud secrets versions list <name> --project=<project-id>`). StackVend never prints secret values.

| Secret | Filled by | What uses it |
| :--- | :--- | :--- |
| `castor-cc-session-secret` | The platform Terraform (a random 64-character key) | Signs the Control Center's session cookies. Always filled. Rotate with `tofu apply -replace=random_password.cc_session_secret` (everyone signs in again once). |
| `castor-github-app-private-key` | You, after the install, with the GitHub VCS provider only | A JSON document with the GitHub App's `app_id` (or `client_id`), `installation_id` and `private_key` of a GitHub App installed on an organization (see "GitHub" above). Vending, the developer stage and the release step use it to mint one-hour GitHub installation tokens. Empty with Serverless Git. |
| `castor-oauth-client-id` | Nobody: a new install never writes it. **Leave it empty** | Only a fallback client ID for a Control Center whose install never set `cc_google_oauth_client_id` (the installer pins the Control Center client in the tfvars in public mode). Set the Control Center client with that variable and `scripts/apply.sh apply`, never here; the sign-in screen cannot set a client either. A value stored here may be passed to workload Terraform (see [known limitations](known-limitations.md)). Direct IAP needs no client at all: it uses a Google-managed one. |
| `castor-oauth-client-secret` | Nobody: a new install never writes it. **Leave it empty** | Reserved for a shared Google sign-in for generated apps, which this release does not have; never put the tenant client's secret here (the installer keeps that one only in `stackvend-tenant-google-client-secret`, when that secret exists). |
| `castor-gemini-api-key` | Nobody on a new install: the installer no longer asks for a key | Optional AI Studio access for the Control Center (see "AI model settings" above): an install whose secret already has an enabled version keeps using it. Without it the platform uses Vertex AI through IAM. |

## Platform variables (`<project_id>.tfvars`)

Key variables from `infra/platform/variables.tf`:

| Variable | Meaning |
| :--- | :--- |
| `project_id`, `region`, `zone` | Host project and location. |
| `organization_id` | Optional for the apply. Needed, with the folder, for the deletion-safety tag: without it StackVend refuses every child-project delete (`GUARD_UNCONFIGURED`). The managed-workloads folder must belong to this organization. |
| `billing_account_id` | Optional for the apply, but required to deploy any workload: child projects are linked to this billing account. |
| `castor_managed_workloads_folder_id` | Parent folder for child projects. Optional for the apply, but required to deploy any workload: the vend refuses without it. |
| `bind_billing_iam` | Whether Terraform grants `roles/billing.user` on the billing account to `sa-project-provisioner` and `sa-castor-developer` (additive members; needs Billing Account Administrator). Default unset: `scripts/apply.sh` decides with a read-only permission check and skips the grant with a warning when you lack the role. An explicit `true`/`false` always wins. |
| `github_owner`, `workloads_github_owner` | Where generated workload repositories live: a GitHub organization with the StackVend GitHub App installed (personal accounts are not supported). Services receive `workloads_github_owner` (or `github_owner` when it is empty) as `GITHUB_ORG` / `GITHUB_OWNER`. There is no built-in owner: with `vcs_provider = "GITHUB"`, leaving both empty makes the orchestrator gateway and the vending service refuse to start (`GitHubOwnerNotConfiguredError`); other services return that error on GitHub operations. |
| `vcs_provider`, `deploy_git_server` | VCS selection (see above). |
| `allow_unauthenticated`, `authorized_invoker_members`, `enable_direct_iap`, `control_center_ingress_traffic`, `admin_email` | Ingress posture and access control for the Control Center. |
| `enable_drive_spec_polling`, `google_drive_*_folder_ids` | Optional Google Drive intake. |
| `tf_runner_identity` | Install setting **Terraform runner identity** (FD-7L-n), passed to vending, the Terraform server, the `tf-applier` job, the `infra-rollback-job` and the Control Center as `STACKVEND_TF_RUNNER_IDENTITY`. `PLATFORM` (**Shared**, the variable's default): workload OpenTofu runs with the platform's account, and the [known limitation](known-limitations.md) applies. `PER_WORKLOAD` (**Per workload**): each workload deploys as its own deployer service account in its own project. `scripts/bootstrap.sh` writes `PER_WORKLOAD` (with `tf_runner_dedicated_sa = true`) into a new install's tfvars, so a new install is Per workload from its first apply. An existing install whose tfvars does not set the variable stays Shared until an operator moves it; `scripts/bootstrap.sh --overwrite-tfvars` keeps the existing file's `tf_runner_identity` and `tf_runner_dedicated_sa` (and refuses with `BOOTSTRAP_RUNNER_IDENTITY_UNREADABLE` when it cannot read them), so regenerating the file never switches an install. Bootstrap's apply also runs the same step-B readiness check as `scripts/apply.sh` (an existing install bootstrapped again without its vars file is refused while a live workload is not ready). Moving from Shared to Per workload is a one-way upgrade (runner identity backfill, then `tf_runner_dedicated_sa`; see [Terraform runner identity](#terraform-runner-identity-shared-or-per-workload)). On an install that declares `PLATFORM`, the operative mode can be switched between Shared and Per workload from Control Center Settings without an apply (a vending-signed record in the guard database; see [Settings reference](settings-reference.md#terraform-runner-identity-card)); `PER_WORKLOAD` here is final. |
| `tf_runner_dedicated_sa` | Runs `mcp-terraform-server` as `sa-stackvend-tf-server` and the `tf-applier` job as `sa-stackvend-tf-applier` (neither has Secret Manager, platform state, folder or token-minting access), and narrows vending's runner caller lists to them. Needs `tf_runner_identity = "PER_WORKLOAD"`. `scripts/apply.sh` refuses the switch unless every live workload already has a READY runner identity signed by vending (check first with `scripts/check-runner-identity-readiness.sh`). Default `false`: both runners run as `sa-castor-developer`; setting it back to `false` is the rollback. `scripts/bootstrap.sh` writes `true` for a new install (it has no workloads, so there is nothing to check). The two service accounts, their roles and the runner staging bucket exist on every install whatever the value. |
| `tf_runner_vending_act_as` | Grants vending `roles/iam.serviceAccountUser` on `sa-stackvend-tf-applier`. Leave `false` unless running the `tf-applier` job with overrides is shown to need it. |
| `enable_platform_upgrader` | Installs the upgrader behind Settings ▸ Upgrades ▸ **Update StackVend** (`sa-stackvend-upgrader`, the `stackvend-platform-upgrade` topic and Cloud Build trigger; see [Settings reference](settings-reference.md)). `scripts/bootstrap.sh` writes `true` into a new install's tfvars, so a new install has it from its first apply. Default `false`: an existing install whose tfvars does not set it has no upgrader until an operator sets it to `true` and runs `scripts/apply.sh apply`; `--overwrite-tfvars` keeps the existing file's value. Once applied, do not set it back to `false`; use `platform_upgrade_trigger_disabled = true` to stop upgrades. |
| `stackvend_platform_commit` | Not set in the tfvars. `scripts/apply.sh` and `scripts/bootstrap.sh` fill it with the commit they apply from (`+dirty` when a tracked file in the checkout has changes; untracked files are ignored). Together with the `VERSION` file it becomes the platform version stamp: the service-level annotations `stackvend/platform-release` and `stackvend/platform-commit` on the Control Center service. A plan from a new commit therefore shows one in-place change on that service. |
| `cloud_run_min_instances` | Minimum running instances per platform Cloud Run service, keyed by service name (whole numbers from 0 to 5). Default `{}`: every service scales to zero. See [Keeping the Terraform server warm](#keeping-the-terraform-server-warm). |
| `host_vpc_egress` | Creates the platform network `stackvend-host` and puts every platform Cloud Run service and job except the QA sandbox job on it (Direct VPC egress; what goes through it depends on `host_egress_mode`). Default `true`. Needed by `host_internal_ingress`. See [Platform network](#platform-network-internal-only-host-services). |
| `host_internal_ingress` | Makes every platform service except the Control Center internal-only (`INGRESS_TRAFFIC_INTERNAL_ONLY`). Default `false` (an existing install keeps its ingress until you set it); `scripts/bootstrap.sh` writes `true` for a new install, which is internal-only from its first apply (see [Platform network](#platform-network-internal-only-host-services)); `--overwrite-tfvars` keeps the existing file's values. `true` with `host_vpc_egress = false` is refused at plan time, and `scripts/apply.sh` refuses `true` before the plan (`APPLY_HOST_INGRESS_BEFORE_NETWORK`) while the platform network is not applied yet on an install that already has its services. |
| `host_egress_mode` | `PSC_PRIVATE_RANGES` (default): only `*.run.app` calls go through the network, to a Private Service Connect endpoint for Google APIs that a private `run.app` DNS zone points to; all other traffic leaves as before, with no NAT. `NAT_ALL_TRAFFIC`: all traffic goes through the network; `run.app` and Google APIs over Private Google Access, everything else through Cloud NAT (new egress addresses that GitHub and allow-lists see; NAT charges). Switching is one apply (new revisions). |
| `host_network_deployer_grants` | Grants `roles/compute.networkUser` on the platform subnet to the upgrader (whose custom role also gains `compute.subnetworks.get` and `compute.subnetworks.use`). Default `false`; set it to `true` only if an **Update StackVend** run is refused with `PERMISSION_DENIED` on `compute.subnetworks.*`. |
| `host_egress_subnet_cidr`, `host_psc_endpoint_ip` | The platform network's subnet and its Private Service Connect address (used with `PSC_PRIVATE_RANGES` only). Defaults are IPAM platform reservations outside the workload range; the network is never peered, so leave them unless you peer it. Validated: canonical form, RFC 1918, subnet `/8`..`/26`, the address outside the subnet. |
| `host_data_access_audit_logs` | Optional Data Access audit logs on the host project, as a map of service to log type. Default `{}`: none. See [Data Access audit logs on the host project](#data-access-audit-logs-on-the-host-project). |

### Backup and restore of the vars file

`infra/platform/<project_id>.tfvars` is not committed (it holds IDs, e-mail addresses, public OAuth client IDs and switches; no secret: the tenant sign-in client secret goes only to Secret Manager). StackVend keeps a copy next to the platform state, `gs://castor-tfstate-<project_id>/platform/<project_id>.tfvars`, with your own gcloud login. StackVend's agent and job service accounts can write only workload state (objects under `workloads/`) in that bucket; a principal with a project-level storage role (the project's owners and, for example, the Compute Engine default service account that Cloud Build uses) is not limited by that, which is one reason a restored copy is reviewed before the next run.

* **Backup.** `scripts/bootstrap.sh` writes the copy at the end of a successful install, and `scripts/apply.sh apply` refreshes it after every successful apply (also one with no changes; never for `plan`, and never after a failed or refused apply). It first reads the copy's metadata: when the copy already matches, nothing is written; when it differs (for example it was written from another machine), it is kept as `<project_id>.tfvars.prev-<UTC time>` in the same folder before it is replaced; when it cannot be read, it is not overwritten. These explicit `.prev-` copies do not depend on bucket object versioning, which the installer turns on only for a state bucket it creates. When the copy cannot be written, the install or apply still counts as done and prints `BOOTSTRAP_TFVARS_BACKUP_NOT_WRITTEN` or `APPLY_TFVARS_BACKUP_NOT_WRITTEN` with the reason and the retry, `PROJECT_ID=<project_id> bash scripts/apply.sh apply` (a run with no changes only refreshes the copy).
* **Restore.** When `PROJECT_ID` is set and `infra/platform/<project_id>.tfvars` does not exist (a new machine, a fresh clone), `scripts/apply.sh` shows the copy, its size and when it was updated, and in a terminal asks `Restore infra/platform/<project_id>.tfvars from gs://castor-tfstate-<project_id>/platform/<project_id>.tfvars? [y/N]`. **y** downloads exactly that version, checks it (MD5, and that its `project_id` is this project: otherwise `APPLY_TFVARS_BACKUP_PROJECT_MISMATCH`), creates the file with mode 600 and stops (`APPLY_TFVARS_RESTORED`) so that you review it before the next run: it holds the values of the last install or apply that backed it up. **N**, Enter or no terminal stops with `APPLY_TFVARS_MISSING` and the restore command. With no copy, the stop is `APPLY_TFVARS_MISSING_NO_BACKUP`: run `bash scripts/bootstrap.sh` again, which asks the install questions again; hand edits made since the install (for example extra `authorized_invoker_members`) must then be made again. A copy that cannot be checked stops with `APPLY_TFVARS_BACKUP_UNCHECKED`. A local file that exists is never overwritten, and nothing is offered with `TFVARS_FILE=<path>` or when the project comes from `gcloud config` (their "No vars file" stop names the backup and the `apply.sh plan` command). When `scripts/bootstrap.sh` starts without the local file and a backup exists, it prints a note that `PROJECT_ID=<project_id> bash scripts/apply.sh plan` restores it, and continues.

### Keeping the Terraform server warm

The Terraform server (`mcp-terraform-server`) scales to zero by default. A new instance first fetches the OpenTofu engine and its provider mirror, so a cold start can take a few minutes. The developer stage waits up to 3 minutes for the server to report ready (and waits again when a later check lands on an instance that is still starting) before it stops the run as unavailable. Runs that start after a quiet spell are the ones that wait.

To keep one instance running, set the existing install variable in `<project_id>.tfvars`:

```hcl
cloud_run_min_instances = { "mcp-terraform-server" = 1 }
```

* **Default:** `{}` (0 for every service: cold starts, no idle instance cost; the install's fixed costs are listed under [Platform network](#platform-network-internal-only-host-services)). There is no separate variable for this.
* **Cost:** the server has 2 vCPU and 4 GiB of memory with CPU always allocated, so one warm instance costs approximately $100–120 a month per install (approximately, list prices; check the Google Cloud pricing calculator for your region and any discounts).
* **Applying it:** this is platform Terraform, so a change takes effect only after `scripts/apply.sh` runs; a service deploy does not change it. Set the value back to 0, or remove the key, to return to scale-to-zero.
* A service name that is not a platform Cloud Run service is refused at plan time.
* The architect, developer and QA stages do not run on the gateway service but as executions of the `stage-runner`
  Cloud Run Job (same image, identity and limits as the gateway), so `cloud_run_min_instances` for the gateway does not
  keep a stage alive; a stage job needs no warm instance. The job is not in this map.

### Platform network (internal-only host services)

Only the Control Center is reachable from outside the platform. Every other platform service (the orchestrator
gateway, project vending, the MCP tool servers, the SRE sentinel, spec ingestion and the Serverless Git server)
accepts internal traffic only, and IAM is still checked on every request.

* **Who can still call them:** Pub/Sub push subscriptions, Cloud Scheduler jobs and Cloud Workflows in the host project
  (these count as internal), and the platform's own services and jobs, which send their `*.run.app` calls through the
  platform network `stackvend-host`. With `host_egress_mode = "PSC_PRIVATE_RANGES"` (the default) a private DNS zone on
  that network answers `*.run.app` with a Private Service Connect endpoint for Google APIs, so the call reaches Cloud
  Run from inside the project, and everything else they send (GitHub, the OpenTofu registry, Google APIs) goes out as
  before, with no NAT and no new egress address. With `"NAT_ALL_TRAFFIC"` all their traffic goes through the network:
  Google APIs and `run.app` over Private Google Access, the rest through Cloud NAT.
* **Never on the network:** the QA sandbox job (`qa-sandbox-test-runner`), which runs generated code.
* **New installs** are internal-only from their first apply: `scripts/bootstrap.sh` writes `host_vpc_egress = true`
  and `host_internal_ingress = true`, and the installer's single apply creates the network, then the services on it
  with internal-only ingress. No second apply is needed. (If bootstrap finds platform services already in state but no
  platform network, it writes `host_internal_ingress = false` instead and tells you to turn it on in a later apply, as
  for an existing install.)
* **Existing installs already on the network** (`host_vpc_egress = true` applied) turn it on with one apply: set
  `host_internal_ingress = true` in `infra/platform/<your-project-id>.tfvars` and run
  `PROJECT_ID=<your-project-id> bash scripts/apply.sh apply`. Only the ingress of 12 services and the git server
  changes, without new revisions.
* **Existing installs not yet on the network** turn it on in two applies. First `scripts/apply.sh apply` with the
  defaults: it creates the network and gives every service a new revision on it (jobs pick it up at their next run);
  ingress does not change. After a soak (wait until no job execution started before that apply is still running; a `tf-applier` run can last
  up to 24 hours), set `host_internal_ingress = true` and apply again: only the ingress of 12 services and the git
  server changes, without new revisions. To undo it, set `host_internal_ingress = false` and apply.
* **Switching `host_egress_mode` on an internal-only install** takes three applies: set `host_internal_ingress = false`
  and apply; set the new `host_egress_mode` and apply (it replaces the Private Service Connect endpoint and `run.app`
  zone with Cloud NAT or the other way round, so pass `--allow-destroy=<project-id>`, and rolls every service to a new
  revision); then set `host_internal_ingress = true` and apply. In one step, revisions still draining on the old design
  would lose their way to the other services (transient 404s), so `scripts/apply.sh` refuses it before the plan with
  `APPLY_HOST_EGRESS_MODE_SWITCH_WITH_INGRESS` (it reads the applied design from state).
* **Organization policies:** `scripts/apply.sh` and `scripts/bootstrap.sh` read the host project's effective
  `run.allowedVPCEgress` (must allow `private-ranges-only`, or `all-traffic` with `NAT_ALL_TRAFFIC`) and
  `run.allowedIngress` (must allow `internal`) before the plan and stop with `APPLY_HOST_NETWORK_ORG_POLICY_REFUSED` /
  `BOOTSTRAP_HOST_NETWORK_ORG_POLICY_REFUSED` when one refuses. With `PSC_PRIVATE_RANGES` they also read
  `compute.disablePrivateServiceConnectCreationForConsumers` and warn when it has any rule. A
  policy they cannot read gives a warning; if it does refuse, the apply stops with a 400 that names it.
* **Cost:** with `PSC_PRIVATE_RANGES`, approximately $7 to $8 a month (the always-on Private Service Connect endpoint, about
  $7.30, and the private DNS zones: `run.app.`, and the `p.googleapis.com` zone Google creates for the endpoint); with
  `NAT_ALL_TRAFFIC`, approximately $1 to $35 a month plus about $0.045 per GB through Cloud NAT
  (list prices, check the pricing calculator).
* **First apply:** the network apply enables Cloud DNS and Service Directory and uses them in the same run. If the
  Private Service Connect rule or the DNS zone fails with "API not enabled" or "not yet propagated", run the same
  `scripts/apply.sh apply` again. After an apply that failed part-way, use `scripts/apply.sh apply` again, never a
  new `scripts/bootstrap.sh`.

**Break-glass (operators).** `curl` with an ID token and `gcloud run services proxy` to a platform service other than
the Control Center no longer work from a laptop or Cloud Shell; Cloud Run answers 404 before IAM is checked. Diagnose
through the Control Center and Cloud Logging. If you must call one service directly, an owner opens that one service
for the shortest time possible and records it:

```bash
gcloud run services update <service> --region=<region> --project=<project-id> --ingress=all
# ...diagnose with an ID token as before...
gcloud run services update <service> --region=<region> --project=<project-id> --ingress=internal
```

This is drift from the platform Terraform; the next `scripts/apply.sh apply` restores internal-only ingress in any case.

### Data Access audit logs on the host project

Google Cloud does not record who read or changed data unless Data Access audit logs are on. This Terraform setting turns them on for the two host-project services where that record matters. Add it to `<project_id>.tfvars` and run `scripts/apply.sh apply`:

```hcl
host_data_access_audit_logs = {
  "datastore.googleapis.com"     = "DATA_WRITE"
  "secretmanager.googleapis.com" = "DATA_READ"
}
```

| Entry | What it records | Why you might want it |
| :--- | :--- | :--- |
| `"datastore.googleapis.com" = "DATA_WRITE"` | Firestore writes and deletes, in every database of the host project. Firestore's audit configuration uses this service name; `firestore.googleapis.com` is refused at plan time. | A record of which identity wrote to or deleted from Firestore and when, for example when investigating a change to the signed Terraform runner identity record. |
| `"secretmanager.googleapis.com" = "DATA_READ"` | Every read of a secret value in the host project. | A record of which identity read which platform secret. |

Each entry can be set on its own, and no other service or log type is accepted.

* **Default:** `{}`. Nothing is planned and nothing changes on the install.
* **Cost:** the entries are billed as Cloud Logging volume. Firestore writes are the larger part, because every pipeline run writes to the default database; check your log volume after turning it on.
* **Reading the entries:** they are in the `data_access` log of the host project and stay for the retention of the `_Default` log bucket (30 days unless you changed it). Reading them needs *Private Logs Viewer* (`roles/logging.privateLogViewer`) or Owner.
* **Failed calls and the SRE list:** a call that fails, such as a Firestore write that loses a race or a read of a secret with no version, can be logged at `ERROR` severity. The platform's error log sink forwards those entries to the SRE sentinel, which records each one as an unattributed incident. They never start a remediation, but expect more entries in the incident list.
* **Turning an entry off:** remove it from the map. That deletes the audit setting, so the plan lists `google_project_iam_audit_config.host_data_access["<service>"]` as a delete and the apply stops, as it does for any delete. Check that it is the only delete listed, then run `PROJECT_ID=<project_id> scripts/apply.sh apply --allow-destroy=<project_id>`. Audit logs set on a parent folder or organization stay on.

### Terraform runner identity (Shared or Per workload)

The **Terraform runner identity** decides whose credentials a workload's OpenTofu runs with.

* **Shared** (`PLATFORM`): every workload's OpenTofu runs as the platform's service account `sa-castor-developer`, and
  its state lives in the platform state bucket. Anyone who can push Terraform to a workload repository then has that
  account's reach (see [Known limitations](known-limitations.md#trust-model-who-may-change-a-workloads-terraform)).
* **Per workload** (`PER_WORKLOAD`): each workload has a deployer service account in its own project
  (`stackvend-deployer@<workload project>`, owner of that project only) and its own state bucket there
  (`<workload project>-tfstate-<6 hex>`). Project vending creates both when it vends the project, and keeps a signed
  record of them. Each deploy runs as one `tf-applier` execution, and vending hands that execution one short-lived,
  single-use credential for the workload's deployer.

The platform Terraform has two **runner service accounts** for this: `sa-stackvend-tf-applier` (the `tf-applier` job)
and `sa-stackvend-tf-server` (`mcp-terraform-server`). Neither can read Secret Manager or the platform state, act on
the workloads folder or mint tokens.

**A new install** made with `scripts/bootstrap.sh` is Per workload from its first apply: the installer writes
`tf_runner_identity = "PER_WORKLOAD"` and `tf_runner_dedicated_sa = true`, so the steps below are already done and the
Settings card only shows the mode. **An existing install** stays Shared until an operator moves it.

**Moving an existing install to Per workload** takes two platform applies (step A and step B) with Control Center steps
in between:

1. **Step A.** Run `scripts/apply.sh apply` from a release that has the runner identity code. It adds the two runner
   service accounts, two one-permission roles, a runner staging bucket (`stackvend-runner-staging-<project>`) and
   inert settings. It changes no running identity and destroys nothing. A new install made from such a release
   already has them.
2. **Switch the mode.** In Control Center **Settings**, the **Terraform runner identity** card switches between
   Shared and Per workload without an apply (see [Settings reference](settings-reference.md#terraform-runner-identity-card)).
   Switch when no vend or deploy is running. From now on, vending gives each new workload its own deployer.
3. **Backfill.** On the same card, **Dry run** lists what the backfill would do; **Run** gives one existing workload
   its deployer and bucket and copies its state there. A workload that has not been backfilled cannot deploy
   (`RUNNER_IDENTITY_NOT_READY`).
4. **Check readiness.** `PROJECT_ID=<id> bash scripts/check-runner-identity-readiness.sh` is read-only. It lists every
   live workload that does not yet have a ready, vending-signed runner identity. Exit status: `0` all ready, `1` not
   ready, `2` could not check.
5. **Step B.** Set `tf_runner_identity = "PER_WORKLOAD"` and `tf_runner_dedicated_sa = true` in the tfvars (this
   also needs `vending_runs_as_provisioner = true`) and run `scripts/apply.sh apply`. It moves the job and the server
   onto their runner service accounts. `apply.sh` runs the readiness check on the plan and applies nothing while a
   live workload is not ready (`APPLY_RUNNER_SWITCH_NOT_READY`) or the check cannot run
   (`APPLY_RUNNER_SWITCH_UNCHECKED`).

After step B the install's mode is final: the card no longer switches it. To roll step B back, set
`tf_runner_dedicated_sa = false` and apply again; both runners then run as `sa-castor-developer` again. Before step B,
switching the card back to Shared is the rollback. Step B removes nothing from `sa-castor-developer`: other platform
services still use it.

**What a Per-workload install refuses in this release** (each with a typed error; see
[Known limitations](known-limitations.md#per-workload-terraform-runner-identity-is-new)):

* `terraform plan`, a saved-plan apply and the drift check, also through the agents' plan and drift tools
  (`RUNNER_MODE_UNSUPPORTED`). Normal deploys are not affected.
* Between step A and step B: Express deploys, vending redeploys and force-unlock (`RUNNER_PAYLOAD_STAGING_FAILED`).
* Workload Terraform that sets a provider setting outside the platform's allow-list, declares its own backend or
  state encryption, uses a non-local module or reads another state (`APPLY_CONTENT_POLICY`), and a file the
  platform's parser cannot read (`APPLY.SOURCE_NOT_CHECKABLE`).
* A plan that would manage the deployer account, its keys or grants, or grant `roles/owner`, `roles/editor` or
  `roles/iam.serviceAccountTokenCreator` in the workload's project (`POLICY.PLATFORM_IDENTITY_TOUCHED`).

A Shared install only logs what Per workload would refuse (`POLICY_WOULD_REFUSE`). The full list of error classes is
in [fail-loudly-policy.md](fail-loudly-policy.md).
