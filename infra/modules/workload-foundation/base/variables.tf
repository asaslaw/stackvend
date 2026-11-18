# ==============================================================================
# STACKVEND: WORKLOAD FOUNDATION - BASE MODULE VARIABLES
# ==============================================================================

variable "project_id" {
  description = "Target GCP Child Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region for regional resources"
  type        = string
  default     = "us-central1"
}

variable "product_id" {
  description = "Workload Product ID"
  type        = string
}

variable "github_repo_full_name" {
  description = "Full GitHub repository name in owner/repo form (e.g. example-org/example-workload)"
  type        = string
}

variable "github_repository_id" {
  description = "FD-4AT-c: GitHub's immutable numeric id of github_repo_full_name, resolved by vending and supplied by the platform at apply time (never by generated code). Empty = not pinned; the repository name + main-branch condition still applies."
  type        = string
  default     = ""

  validation {
    condition     = var.github_repository_id == "" || can(regex("^[1-9][0-9]*$", var.github_repository_id))
    error_message = "github_repository_id must be empty or GitHub's numeric repository id (digits only)."
  }
}

variable "enable_github_actions_deploy" {
  description = "GHA-DEPLOY-SWITCH: the workload's GitHub Actions deploy path. true (the default, the module before this input existed) creates the Workload Identity Federation pool and provider, the deployer service account sa-gh-deployer and its roles, so the generated .github/workflows/deploy-<service>.yml can deploy the app. false creates none of them: every deploy goes through the platform's pipeline. Supplied by the platform from the workload record."
  type        = bool
  default     = true
  nullable    = false
}

variable "github_default_branch" {
  description = "FD-4CI-b-R1-WIF: the workload's recorded default branch, the only branch whose GitHub Actions runs the WIF condition accepts (exact refs/heads/<branch>). Supplied by the platform from the workload record; \"main\" = the condition before this input existed."
  type        = string
  default     = "main"
  nullable    = false

  # The platform's branch-name grammar (shared/settings.py is_branch_name): 1..100 of letters, digits, '.', '_', '-',
  # '/'; not "HEAD"; no leading '-', '/' or '.'; no trailing '/' or '.'; no '..'; no empty path component; no
  # component starting with '.' or ending in '.lock'. Nothing else reaches the condition (no quote, no wildcard).
  validation {
    condition     = can(regex("^[A-Za-z0-9._/-]{1,100}$", var.github_default_branch)) && var.github_default_branch != "HEAD"
    error_message = "github_default_branch must be 1 to 100 letters, digits, '.', '_', '-' or '/' and not HEAD."
  }

  validation {
    condition     = !can(regex("^[-/.]", var.github_default_branch)) && !can(regex("[/.]$", var.github_default_branch)) && !can(regex("\\.\\.", var.github_default_branch))
    error_message = "github_default_branch must not start with '-', '/' or '.', end with '/' or '.', or contain '..'."
  }

  validation {
    condition     = !can(regex("//", var.github_default_branch)) && !can(regex("/\\.", var.github_default_branch)) && !can(regex("\\.lock(/|$)", var.github_default_branch))
    error_message = "github_default_branch must not have an empty path component, or one that starts with '.' or ends in '.lock'."
  }
}

variable "base_apis" {
  description = "Foundational GCP APIs required by all StackVend workloads"
  type        = list(string)
  default = [
    "run.googleapis.com",
    "firestore.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "identitytoolkit.googleapis.com",
    "iap.googleapis.com",
    "pubsub.googleapis.com",
    "storage.googleapis.com",
  ]
}

variable "additional_apis" {
  description = "Extra GCP APIs requested by custom extensions in custom.tf"
  type        = list(string)
  default     = []
}

variable "firestore_delete_protection" {
  description = "Enable delete protection on the workload Firestore database (FD-4AZ: on by default). Set false explicitly only for an ephemeral workload."
  type        = bool
  default     = true
}
