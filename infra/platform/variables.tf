variable "project_id" {
  description = "The Google Cloud Project ID where the Project Castor platform engine is deployed."
  type        = string
}

variable "region" {
  description = "The primary Google Cloud region for compute, storage, and serverless runtimes."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "The default zone for regional compute resources."
  type        = string
  default     = "us-central1-a"
}

variable "organization_id" {
  description = "The Google Cloud Organization ID (e.g., organizations/123456789012)."
  type        = string
  default     = ""
}

variable "billing_account_id" {
  description = "The Google Cloud Billing Account ID to bind to projects."
  type        = string
  default     = ""
}

variable "billing_breach_enforcement_enabled" {
  description = "C10 (owner 11-07 \"B\"): billing-alert-drain-job enforces a workload's budget breach policy (finops-budget-enforcer-job: ALERT_ONLY, HITL card, billing unlink or scale to zero) for a Cloud Billing budget notification on the billing-budget-alerts topic that maps to the workload (budget id, or the budget named budget-<workload id>, on this install's billing account). false = the drain job records spend and warnings but leaves a breach unacknowledged (typed BUDGET_BREACH_ENFORCER_NOT_ENABLED; Pub/Sub redelivers, then dead-letters it), which is the behaviour before C10."
  type        = bool
  default     = true
}

variable "bind_billing_iam" {
  description = "BG-1: grant roles/billing.user on the billing account to sa-project-provisioner and sa-castor-developer (billing_iam.tf; additive members only). Needs billing.accounts.setIamPolicy (Billing Account Administrator) for whoever applies. Leave unset (null) for auto: scripts/apply.sh checks that permission read-only before the plan and passes true or false (false = grant skipped with a warning; the install still succeeds and Control Center Settings shows the fix). An explicit true/false here always wins."
  type        = bool
  default     = null
}

variable "castor_managed_workloads_folder_id" {
  description = "The Google Cloud Folder ID for dynamically provisioned workload projects (e.g., folders/123456789012)."
  type        = string
  default     = ""
}

variable "castor_admin_group" {
  description = "The Google Group or Cloud IAM Group email for Castor Platform Administrators (e.g. group:castor-admins@yourdomain.com)."
  type        = string
  default     = ""
}

variable "admin_user_email" {
  description = "The primary administrator email address granted read-only viewer access across all managed workload projects (leave blank if deploying with a personal account or under domain-restricted org policies)."
  type        = string
  default     = ""
}

variable "castor_developer_group" {
  description = "The Google Group or Cloud IAM Group email for Castor Developers (e.g. group:castor-devs@yourdomain.com)."
  type        = string
  default     = ""
}

variable "environment" {
  description = "The deployment environment tier (e.g. prod, staging, dev)."
  type        = string
  default     = "dev"
}

variable "github_owner" {
  description = "The GitHub user or organization where StackVend vends workload repositories (unless workloads_github_owner is set)."
  type        = string
  default     = ""
}

variable "workloads_github_owner" {
  description = "The GitHub Organization or user where Project Castor vends child workload repositories. If empty, defaults to var.github_owner."
  type        = string
  default     = ""
}

variable "platform_github_repo" {
  description = "Full name (\"<owner>/<repo>\") of this install's own StackVend platform repository, exposed to the Control Center as GITHUB_REPO (used when it registers the platform as a workload). Set per install in the gitignored <project_id>.tfvars. Empty = GITHUB_REPO is not set and registering the platform as a workload is refused (HTTP 503) until it is."
  type        = string
  default     = ""

  validation {
    condition     = var.platform_github_repo == "" || can(regex("^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$", var.platform_github_repo))
    error_message = "platform_github_repo must be empty or \"<owner>/<repo>\" (GitHub owner and repository name; not a URL)."
  }
}

variable "cc_google_oauth_client_id" {
  description = "Google OAuth client ID dedicated to this install's Control Center (owner 10-12, lane 19 Q8/Q17 mitigation), exposed to the Control Center ONLY as GOOGLE_OAUTH_CLIENT_ID. A client ID is public, not a secret. Set per install in the gitignored <project_id>.tfvars. Empty = GOOGLE_OAUTH_CLIENT_ID is not set and the Control Center keeps resolving it from Secret Manager castor-oauth-client-id."
  type        = string
  default     = ""

  validation {
    condition     = var.cc_google_oauth_client_id == "" || can(regex("^[0-9]+-[a-z0-9]+\\.apps\\.googleusercontent\\.com$", var.cc_google_oauth_client_id))
    error_message = "cc_google_oauth_client_id must be empty or a Google OAuth client ID (<digits>-<id>.apps.googleusercontent.com)."
  }
}

variable "tenant_google_client_id" {
  description = "Public client ID of this install's SECOND Web OAuth client, used only for tenant-app Google sign-in (lane 19 L19-0a, register rows 27b/44). Must differ from cc_google_oauth_client_id (A1: a tenant app could otherwise sign platform admins into the Control Center). Its secret never enters Terraform: bootstrap.sh stores it in Secret Manager. Empty = no shared tenant Google sign-in client configured."
  type        = string
  default     = ""

  validation {
    condition     = var.tenant_google_client_id == "" || can(regex("^[0-9]+-[a-z0-9]+\\.apps\\.googleusercontent\\.com$", var.tenant_google_client_id))
    error_message = "tenant_google_client_id must be empty or a Google OAuth client ID (<digits>-<id>.apps.googleusercontent.com)."
  }
}

variable "placeholder_container_image" {
  description = "The public bootstrap placeholder container image used for single-pass Cloud Run provisioning."
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "enable_drive_spec_polling" {
  description = "Whether to enable Cloud Scheduler cron poller for Google Drive intake folders. Defaults to false."
  type        = bool
  default     = false
}

variable "google_drive_intake_folder_ids" {
  description = "Google Drive folder ID (or comma-separated IDs) for 01_Inbox_Requests."
  type        = string
  default     = ""
}

variable "google_drive_in_progress_folder_ids" {
  description = "Google Drive folder ID (or comma-separated IDs) for 02_In_Progress."
  type        = string
  default     = ""
}

variable "google_drive_completed_folder_ids" {
  description = "Google Drive folder ID (or comma-separated IDs) for 04_Completed."
  type        = string
  default     = ""
}

# ------------------------------------------------------------------------------
# Enterprise Ingress & Authentication Hardening (Plan 12)
# ------------------------------------------------------------------------------
variable "allow_unauthenticated" {
  description = "Whether to allow allUsers public unauthenticated invocation on the Control Center UI. Set to false in enterprise organizations with Domain-Restricted Sharing (defaults to true for backwards compatibility with existing open installations)."
  type        = bool
  default     = true
}

variable "authorized_invoker_members" {
  description = "List of IAM member principals permitted to access the Control Center UI when allow_unauthenticated is false (e.g. ['domain:company.com', 'group:platform-admins@company.com', 'user:admin@company.com'])."
  type        = list(string)
  default     = []

  validation {
    condition = (
      var.allow_unauthenticated || length(var.authorized_invoker_members) > 0
    )
    error_message = "When allow_unauthenticated is false, at least one principal must be specified in authorized_invoker_members to prevent complete administrative lockout."
  }
}

variable "enable_direct_iap" {
  description = "Whether to enable native Direct Identity-Aware Proxy (IAP) on the Control Center UI when allow_unauthenticated is false, enabling Google Workspace SSO for browser users without an ALB."
  type        = bool
  default     = true
}

variable "control_center_ingress_traffic" {
  description = "Ingress traffic setting for the Control Center UI service. Valid values: INGRESS_TRAFFIC_ALL, INGRESS_TRAFFIC_INTERNAL_ONLY, INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER."
  type        = string
  default     = "INGRESS_TRAFFIC_ALL"
}

variable "admin_email" {
  description = "Primary platform administrator email address (e.g. user@gmail.com or admin@yourdomain.com)"
  type        = string
  default     = ""

  validation {
    condition     = var.admin_email == "" || can(regex("^[^@:[:space:]]+@[^@:[:space:]]+$", var.admin_email))
    error_message = "admin_email must be empty or a bare email address (no user:/group: prefix, no spaces)."
  }
}

# ------------------------------------------------------------------------------
# Universal VCS Gateway & Serverless Git Configuration
# ------------------------------------------------------------------------------
variable "vcs_provider" {
  description = "Primary Version Control System provider for Project Castor ('GITHUB' or 'SERVERLESS_GIT'). Defaults to 'GITHUB' for 100% backwards compatibility."
  type        = string
  default     = "GITHUB"

  validation {
    condition     = contains(["GITHUB", "SERVERLESS_GIT"], upper(var.vcs_provider))
    error_message = "var.vcs_provider must be either 'GITHUB' or 'SERVERLESS_GIT'."
  }
}

variable "deploy_git_server" {
  description = "Whether to provision the Serverless Git microservice (Cloud Run + GCS FUSE) and repository storage bucket ($0/mo idle). Enabled by default as a standard platform capability."
  type        = bool
  default     = true
}

variable "git_server_container_image" {
  description = "INITIAL container image for the Serverless Git microservice (used only when the service is created; afterwards the deploy paths own the image via lifecycle.ignore_changes). Leave empty to use the bootstrap placeholder container image."
  type        = string
  default     = ""
}

variable "gemini_model" {
  description = "Value of the GEMINI_MODEL env var on platform Cloud Run services and jobs (an env fallback: agents check Firestore model settings first). Set per install in <project_id>.tfvars to the live value so an apply does not change the model."
  type        = string
  default     = "gemini-3.7-flash"
}

variable "gemini_model_overrides" {
  description = "Per-service/job GEMINI_MODEL overrides, keyed by Cloud Run service or job name (e.g. { \"orchestrator-gateway-service\" = \"gemini-3.8-flash\" }). Unlisted names use var.gemini_model."
  type        = map(string)
  default     = {}
}

variable "cloud_run_min_instances" {
  description = "Per-service template min_instance_count, keyed by platform Cloud Run service name; unlisted services scale to zero. Default {} (owner 10-13: no standing ~$115/month warm instance); the gateway's bounded readiness wait (180 s, SF-1) covers each mcp-terraform-server cold start. Set mcp-terraform-server = 1 in an install's tfvars to keep one warm."
  type        = map(number)
  default     = {}

  validation {
    condition     = alltrue([for n in values(var.cloud_run_min_instances) : n >= 0 && n <= 5 && floor(n) == n])
    error_message = "cloud_run_min_instances values must be whole numbers from 0 to 5 (the services' max_instance_count)."
  }
}

variable "cc_gemini_api_key_from_secret" {
  description = "Mount GEMINI_API_KEY on the Control Center from Secret Manager (castor-gemini-api-key:latest). Set true ONLY when that secret has an ENABLED version (bootstrap.sh sets it); otherwise the revision fails to start. False = Vertex AI via IAM."
  type        = bool
  default     = false
}

variable "grant_devops_workloads_folder_editor" {
  description = "FD-49: grant roles/editor on the whole managed-workloads folder to sa-castor-gcp-devops. Default false (least privilege); vending grants per-project roles."
  type        = bool
  default     = false
}

# ------------------------------------------------------------------------------
# Lane 18 S0 / S0b: destructive-action guard prerequisites (FD-4Q, FD-4T slice)
# ------------------------------------------------------------------------------
variable "vending_runs_as_provisioner" {
  description = "Lane 18 S0: run project-repo-vending-service as sa-project-provisioner (then the only identity with projectDeleter/folderAdmin on the managed folder, tagUser on the stackvend-managed tag value and write access to the stackvend-guard database besides the Control Center). false = ROLLBACK LEVER: vending runs as sa-castor-developer again and every grant that follows the vending identity moves with it, so nothing stops working, but the guard is anti-accident only again."
  type        = bool
  default     = true
}

variable "create_stackvend_managed_tag" {
  description = "Lane 18 v3: create the organization-level stackvend-managed tag key, its value 'true' and the vending identity's tagUser grant (needs an org Tag Administrator). null (default) = decided by the read-only Tag Administrator preflight in scripts/apply.sh / scripts/bootstrap.sh (a plain tofu run treats null as true). Set true or false in the tfvars to decide explicitly; that wins over the preflight. false = no tag: the install succeeds, Settings warns, and every project delete is refused (GUARD_UNCONFIGURED) until a Tag Administrator re-runs apply."
  type        = bool
  default     = null
  nullable    = true
}

variable "create_folder_vm_external_ip_policy" {
  description = "ORG-POLICY-FOLDER: set the org policy compute.vmExternalIpAccess = deny all ('no external VM IPs') on castor_managed_workloads_folder_id. Every project in that folder inherits it, including projects StackVend did not vend. Needs the person running apply to be an Organization Policy Administrator (roles/orgpolicy.policyAdmin on the organization). null (default) = decided by the read-only preflight in scripts/apply.sh / scripts/bootstrap.sh (scripts/common/org_policy_preflight.sh; a plain tofu run treats null as true). Set true or false in the tfvars to decide explicitly; that wins over the preflight. false = no folder policy: the install succeeds and every vend records VENDING.ORG_POLICY_NOT_ENFORCED with the fix."
  type        = bool
  default     = null
  nullable    = true
}

variable "managed_tag_key_short_name" {
  description = "Lane 18 S0: short name of the organization-level Resource Manager tag key whose value 'true' marks projects vended by StackVend (the value is bindable only by the vending identity). Empty = 'stackvend-managed-<project_id>': tag key short names are unique per organization and two installs can share one organization (e.g. a dev and a second install). The guard compares only the tag VALUE id (STACKVEND_MANAGED_TAG_VALUE), never this name. Changing it later replaces the key (refused by prevent_destroy)."
  type        = string
  default     = ""

  validation {
    condition     = var.managed_tag_key_short_name == "" || can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,61}[A-Za-z0-9]$", var.managed_tag_key_short_name))
    error_message = "managed_tag_key_short_name must be empty or 2-63 characters (letters, digits, '.', '_', '-'), starting and ending with a letter or digit."
  }
}

# ------------------------------------------------------------------------------
# FD-7L (SAT-33) / FD-7L-n (SAT-35): Terraform runner identity (infra/platform/tf_runner_identity.tf)
# ------------------------------------------------------------------------------
variable "tf_runner_identity" {
  description = "FD-7L-n install setting 'Terraform runner identity', exposed as STACKVEND_TF_RUNNER_IDENTITY on vending, mcp-terraform-server, tf-applier, infra-rollback-job and the Control Center. PLATFORM = Shared (workload OpenTofu runs with the platform's account; the known limitation stays). PER_WORKLOAD = Per workload (each workload deploys as its own deployer in its own project). scripts/bootstrap.sh writes PER_WORKLOAD (with tf_runner_dedicated_sa = true) for every new install, so a new install is Per workload from its first apply. The default stays PLATFORM so an existing install whose tfvars does not set it stays Shared until an operator moves it: Settings switch, runner identity backfill, then the step-B apply (one-way upgrade)."
  type        = string
  default     = "PLATFORM"

  validation {
    condition     = contains(["PLATFORM", "PER_WORKLOAD"], var.tf_runner_identity)
    error_message = "tf_runner_identity must be exactly PLATFORM (Shared) or PER_WORKLOAD (Per workload)."
  }
}

variable "tf_runner_dedicated_sa" {
  description = "FD-7L step B: run mcp-terraform-server as sa-stackvend-tf-server and the tf-applier job as sa-stackvend-tf-applier, narrow vending's runner/server caller lists to them and set GIT_SERVER_READONLY_INVOKERS. Needs tf_runner_identity = PER_WORKLOAD and vending_runs_as_provisioner = true; scripts/apply.sh refuses the switch unless every live workload's vending-signed runner identity record is READY. false (default) = both runners stay on sa-castor-developer; this is also the ROLLBACK LEVER after step B. The step-A resources (the two SAs, custom roles, grants, staging bucket, env) exist either way and are inert."
  type        = bool
  default     = false
}

variable "tf_runner_vending_act_as" {
  description = "FD-7L: grant vending roles/iam.serviceAccountUser on sa-stackvend-tf-applier. Set true ONLY if the Phase 0 check shows that running the tf-applier job with overrides needs act-as on the job's service account (plan §4). Default false (no act-as grant on either runner SA)."
  type        = bool
  default     = false
}

# ------------------------------------------------------------------------------
# FD-4DA item 10 (SAT-10 stamp design, rides SAT-33 step A): platform version stamp on the Control Center service
# ------------------------------------------------------------------------------
variable "stackvend_platform_commit" {
  description = "Platform version stamp: the git commit this platform Terraform was applied from (40 hex, '+dirty' when a tracked file had changes; untracked files are ignored), written as the service-level annotation stackvend/platform-commit on product-control-center-ui. Supplied internally by scripts/apply.sh and scripts/bootstrap.sh (sv_export_platform_stamp); never set it in a tfvars. Empty (default: a plain tofu run, or a checkout without git) = the annotation is omitted."
  type        = string
  default     = ""

  validation {
    condition     = can(regex("^([0-9a-f]{40}(\\+dirty)?)?$", var.stackvend_platform_commit))
    error_message = "stackvend_platform_commit must be empty or a 40-hex git commit, optionally followed by +dirty."
  }
}

# ------------------------------------------------------------------------------
# SELFUP-B (P3b, pre-RC, owner 11-02): "Update StackVend" button (infra/platform/platform_upgrader.tf)
# ------------------------------------------------------------------------------
variable "enable_platform_upgrader" {
  description = "SELFUP-B: create the upgrader identity (sa-stackvend-upgrader, build and deploy only), the stackvend-platform-upgrade topic (the Control Center's only new grant: publisher on it) and the Pub/Sub-started Cloud Build trigger behind the Control Center's 'Update StackVend' button, and give the Control Center STACKVEND_PLATFORM_UPGRADE_TOPIC. false (default) = none of it is planned and the button stays hidden (UPGRADER_NOT_INSTALLED). Needs scripts/release/allowed_signers (the official release key) and the synced step 0. Once applied, do not set it back to false (the custom role id stays reserved for up to 37 days after a delete); use platform_upgrade_trigger_disabled to stop upgrades."
  type        = bool
  default     = false
}

variable "platform_upgrade_trigger_disabled" {
  description = "SELFUP-B kill switch: true disables the stackvend-platform-upgrade Cloud Build trigger (messages from the Control Center start nothing). Default false."
  type        = bool
  default     = false
}

variable "platform_upgrade_approval_required" {
  description = "SELFUP-APPROVAL (Fable plan RT H-2): every upgrade build waits for an administrator's approval in the Google Cloud console (Cloud Build approvals, the admin's own Google account), so a compromised Control Center cannot deploy on its own. Default true; the owner decides whether an install may turn it off."
  type        = bool
  default     = true
}

# ------------------------------------------------------------------------------
# HOST-INTERNAL-INGRESS / HOST-VPC-EGRESS (owner 11-07: Design B for the RC; infra/platform/host_network.tf)
# ------------------------------------------------------------------------------
# Two staged switches. An existing install not yet on the network turns on host_vpc_egress first (apply 1: every host
# Cloud Run service and job except the QA sandbox job joins the stackvend-host network), then host_internal_ingress
# (apply 2: every host service except the Control Center accepts internal traffic only); one already on the network
# needs only apply 2. scripts/bootstrap.sh writes host_vpc_egress = true and its SV_NEW_INSTALL_HOST_INTERNAL_INGRESS
# constant (true), so a fresh install (no services in state) is internal from its single first apply;
# --overwrite-tfvars carries an existing file's values.
# These variables live here, not in host_network.tf: the install scripts read them with sv_tfvar, which evaluates
# variables.tf only (scripts/common/platform_target.sh).
variable "host_vpc_egress" {
  description = "HOST-VPC-EGRESS: create the platform network stackvend-host (one subnet, plus a Private Service Connect endpoint for Google APIs and a private run.app DNS zone in Design B, or a Cloud Router + Cloud NAT in Design A) and give every host Cloud Run service and job except qa-sandbox-test-runner Direct VPC egress into it (host_egress_mode: Design B sends only *.run.app calls through the network, Design A all traffic through Cloud NAT). Needed by host_internal_ingress. Default true."
  type        = bool
  default     = true
}

variable "host_internal_ingress" {
  description = "HOST-INTERNAL-INGRESS: the 12 host Cloud Run services other than the Control Center, plus castor-git-server, accept internal traffic only (INGRESS_TRAFFIC_INTERNAL_ONLY): same-project Pub/Sub, Cloud Scheduler and Workflows, and the platform's own services and jobs through the stackvend-host network. The Control Center keeps control_center_ingress_traffic. Needs host_vpc_egress = true (precondition) and, on an existing install, the network already applied (scripts/apply.sh refuses the flip otherwise). Default false, so an existing install never flips both switches in one apply; scripts/bootstrap.sh writes its SV_NEW_INSTALL_HOST_INTERNAL_INGRESS constant (true) for a new install, whose services are created on the network with internal-only ingress in its first apply."
  type        = bool
  default     = false
}

variable "host_egress_mode" {
  description = "How the stackvend-host network sends traffic out (host_network.tf). \"PSC_PRIVATE_RANGES\" (Design B, default): Direct VPC egress PRIVATE_RANGES_ONLY, a Private Service Connect endpoint for Google APIs and a private run.app zone; only *.run.app calls enter the network; other egress unchanged (no NAT). \"NAT_ALL_TRAFFIC\" (Design A, the fallback): Direct VPC egress ALL_TRAFFIC, Private Google Access for run.app and Google APIs, Cloud NAT for everything else (new egress addresses; NAT charges). Switching modes is one apply: the services roll to a new revision."
  type        = string
  default     = "PSC_PRIVATE_RANGES"

  validation {
    condition     = contains(["PSC_PRIVATE_RANGES", "NAT_ALL_TRAFFIC"], var.host_egress_mode)
    error_message = "host_egress_mode must be \"PSC_PRIVATE_RANGES\" (Design B) or \"NAT_ALL_TRAFFIC\" (Design A)."
  }
}

variable "host_network_deployer_grants" {
  description = "Grant roles/compute.networkUser on the stackvend-host subnet to the identity that re-deploys revisions carrying Direct VPC egress: the upgrader (sa-stackvend-upgrader, when enable_platform_upgrader; its custom role also gains compute.subnetworks.get and compute.subnetworks.use). Default false: set it to true only if an Update StackVend run is refused with PERMISSION_DENIED compute.subnetworks.*."
  type        = bool
  default     = false
}

variable "host_egress_subnet_cidr" {
  description = "IPv4 range of the stackvend-host subnet that host Cloud Run services and jobs take their Direct VPC egress addresses from. Defaults to the IPAM platform reservation shared/ipam.py PLATFORM_RESERVED_CIDRS[\"HOST_RUN_EGRESS_SUBNET\"] (tests/test_internal_ingress_tf.py pins equality); the network is never peered, so override only if you later peer it. Canonical network address, prefix /8../26 (Direct VPC egress needs /26 or larger; about 2 addresses per instance, so a /24 fits the platform), inside RFC 1918."
  type        = string
  default     = "10.254.1.0/24" # = shared/ipam.py PLATFORM_RESERVED_CIDRS["HOST_RUN_EGRESS_SUBNET"] (tests pin equality)

  validation {
    condition = can(cidrnetmask(var.host_egress_subnet_cidr)) && try(
      cidrsubnet(var.host_egress_subnet_cidr, 0, 0) == var.host_egress_subnet_cidr &&
      tonumber(split("/", var.host_egress_subnet_cidr)[1]) >= 8 &&
      tonumber(split("/", var.host_egress_subnet_cidr)[1]) <= 26,
    false)
    error_message = "host_egress_subnet_cidr must be an IPv4 CIDR in canonical form (network address) with a prefix length between /8 and /26."
  }

  # RFC 1918 ranges are protocol constants, not allocations.
  validation {
    condition = try(
      (tonumber(split("/", var.host_egress_subnet_cidr)[1]) >= 8 && cidrsubnet("${cidrhost(var.host_egress_subnet_cidr, 0)}/8", 0, 0) == "10.0.0.0/8") ||
      (tonumber(split("/", var.host_egress_subnet_cidr)[1]) >= 12 && cidrsubnet("${cidrhost(var.host_egress_subnet_cidr, 0)}/12", 0, 0) == "172.16.0.0/12") ||
      (tonumber(split("/", var.host_egress_subnet_cidr)[1]) >= 16 && cidrsubnet("${cidrhost(var.host_egress_subnet_cidr, 0)}/16", 0, 0) == "192.168.0.0/16"),
    false)
    error_message = "host_egress_subnet_cidr must lie inside an RFC 1918 range (10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16)."
  }
}

variable "host_psc_endpoint_ip" {
  description = "Internal IPv4 address of the stackvend-host Private Service Connect endpoint for Google APIs (bundle all-apis). The private run.app zone answers *.run.app with it, so platform-to-platform calls reach Cloud Run from inside the network and count as internal. Defaults to the IPAM platform reservation shared/ipam.py PLATFORM_RESERVED_CIDRS[\"HOST_PSC_GOOGLE_APIS\"] (a /32; tests pin equality). Canonical dotted IPv4, inside RFC 1918 (Direct VPC egress in PRIVATE_RANGES_ONLY mode sends only private destinations into the network), outside host_egress_subnet_cidr (precondition in host_network.tf). Used in Design B only."
  type        = string
  default     = "10.254.2.10" # = shared/ipam.py PLATFORM_RESERVED_CIDRS["HOST_PSC_GOOGLE_APIS"] /32 (tests pin equality)

  validation {
    condition     = try(cidrhost("${var.host_psc_endpoint_ip}/32", 0) == var.host_psc_endpoint_ip, false)
    error_message = "host_psc_endpoint_ip must be one IPv4 address in canonical dotted form (a.b.c.d, no prefix length)."
  }

  validation {
    condition = try(
      cidrsubnet("${var.host_psc_endpoint_ip}/8", 0, 0) == "10.0.0.0/8" ||
      cidrsubnet("${var.host_psc_endpoint_ip}/12", 0, 0) == "172.16.0.0/12" ||
      cidrsubnet("${var.host_psc_endpoint_ip}/16", 0, 0) == "192.168.0.0/16",
    false)
    error_message = "host_psc_endpoint_ip must be an RFC 1918 address (10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16)."
  }
}

variable "host_data_access_audit_logs" {
  description = "Optional Data Access audit logs on the host project, as a map of service to log type. Default {}: none (nothing is planned and nothing is billed). Allowed entries: \"datastore.googleapis.com\" = \"DATA_WRITE\" (Firestore writes and deletes; Firestore's audit configuration uses the service name datastore.googleapis.com) and \"secretmanager.googleapis.com\" = \"DATA_READ\" (secret value reads). Removing an entry is a delete, which scripts/apply.sh refuses without --allow-destroy. See documentation/configuration.md."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for service, log_type in var.host_data_access_audit_logs :
      contains(["datastore.googleapis.com=DATA_WRITE", "secretmanager.googleapis.com=DATA_READ"], "${service}=${log_type}")
    ])
    error_message = "host_data_access_audit_logs accepts only \"datastore.googleapis.com\" = \"DATA_WRITE\" and \"secretmanager.googleapis.com\" = \"DATA_READ\" (for Firestore the service name is datastore.googleapis.com, not firestore.googleapis.com)."
  }
}

