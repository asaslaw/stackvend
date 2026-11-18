# ------------------------------------------------------------------------------
# BG-1: billing-account grants for the StackVend service accounts (owner request 10-18; viewer 10-20)
# ------------------------------------------------------------------------------
# The same three grants scripts/bootstrap.sh makes with gcloud after the apply (kept there as the fallback):
#   roles/billing.user   -> sa-project-provisioner      (links vended child projects to billing)
#   roles/billing.user   -> sa-castor-developer         (FinOps / billing reads by the host services)
#   roles/billing.viewer -> sa-stackvend-control-center (BG-1-b: the lane 18 CC persona, local.cc_sa_email in
#                           destructive_guard.tf; the Settings billing card reads the billing account as it)
#
# Changing billing-account IAM needs billing.accounts.setIamPolicy (Billing Account Administrator).
# Most installers are project owners without it, so the grant is OPTIONAL and never fails the apply:
#   - var.bind_billing_iam unset (null): scripts/apply.sh (and bootstrap.sh) run a read-only
#     billingAccounts.testIamPermissions preflight as the person applying and pass
#     -var=bind_billing_iam=true only when they hold billing.accounts.setIamPolicy. Otherwise they pass
#     false and print a WARNING (not an error); the Control Center Settings billing card then shows
#     which service account is missing Billing Account User (or the CC's Billing Account Viewer) and the fix.
#     A non-admin apply after an admin's apply keeps all three declared and -exclude's them (never a delete).
#   - an explicit true/false in the tfvars always wins (no preflight override).
#   - plain `tofu plan` outside the wrapper: null -> no billing resources.
#
# Additive only: google_billing_account_iam_member adds one member to one role and leaves every other
# member and role on the billing account untouched. Never use google_billing_account_iam_policy or
# google_billing_account_iam_binding here: both are authoritative and would remove other members.
# The viewer member (cc_billing_viewer) has exactly the same gate as billing_user: both or neither.
# Existing installs where the grant was already made by hand or by bootstrap: the create is a
# read-modify-write that finds the member already present, so it adds nothing (no import needed).
# Once created, Terraform owns these grants: setting bind_billing_iam = false later plans their REMOVAL
# (refused by the apply.sh destroy gate unless --allow-destroy). To stop managing them, remove the line instead.
locals {
  billing_iam_account_id = trimprefix(var.billing_account_id, "billingAccounts/")
  bind_billing_iam_on    = var.bind_billing_iam == true && local.billing_iam_account_id != ""
  billing_user_service_accounts = (
    local.bind_billing_iam_on
    ? toset(["sa-project-provisioner", "sa-castor-developer"])
    : toset([])
  )
}

resource "google_billing_account_iam_member" "billing_user" {
  for_each           = local.billing_user_service_accounts
  billing_account_id = local.billing_iam_account_id
  role               = "roles/billing.user"
  member             = "serviceAccount:${google_service_account.agents[each.key].email}"
}

resource "google_billing_account_iam_member" "cc_billing_viewer" {
  count              = local.bind_billing_iam_on ? 1 : 0
  billing_account_id = local.billing_iam_account_id
  role               = "roles/billing.viewer"
  member             = "serviceAccount:${local.cc_sa_email}"
}
