terraform {
  # RC B1: OpenTofu >= 1.10.0. The `removed { lifecycle { destroy = false } }` block in main.tf (FD-0C) does not
  # parse on OpenTofu 1.9 ("Unsupported block type"); HashiCorp Terraform needs >= 1.7 for it, so Terraform 1.5.x
  # cannot install the platform. One constraint covers both engines (required_version cannot tell them apart).
  # scripts/bootstrap.sh and scripts/apply.sh check the same minimum first (SV_IAC_MIN_VERSION,
  # scripts/common/platform_target.sh). Workload IaC run by tf-applier has its own engine version (separate).
  required_version = ">= 1.10.0"

  # FD-0A: exact pins. They resolve identically under OpenTofu and HashiCorp Terraform (a committed
  # .terraform.lock.hcl from `tofu providers lock` lists only registry.opentofu.org entries and
  # would break the Terraform fallback). 6.50.0 is the version both installs were last planned
  # and validated with (6.30.0 cannot validate this configuration). Bump deliberately, with a plan.
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "6.50.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "6.50.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.9.1"
    }
  }

  # Remote state backend in Google Cloud Storage
  backend "gcs" {
    prefix = "platform/state"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# ORG-POLICY-FOLDER (owner 10-28): the one resource that calls the Org Policy API
# (google_org_policy_policy.managed_folder_vm_external_ip, main.tf) bills the HOST as quota project
# (X-Goog-User-Project), so the installer's end-user token never depends on a client default quota project. The
# applier already needs serviceusage.services.use on the host (Owner / Editor), and orgpolicy.googleapis.com is
# enabled there by google_project_service.apis. Every other resource keeps the default provider above, unchanged.
provider "google" {
  alias                 = "host_quota"
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}
