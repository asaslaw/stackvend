"""PUSH-TO-PRIVATE (owner 10-27): the exact text the golden compute-cloudrun module gained (appended at the end of
main.tf and variables.tf). Tests that pin older bytes of those files remove exactly this (each once) first."""

ADDED_MAIN = '\n# StackVend PUSH-TO-PRIVATE (owner 10-27): the workload\'s own Pub/Sub push subscriptions to this service sign with the\n# service accounts in push_service_accounts (platform-rendered from the typed intent, never an AI argument). A private\n# service lets exactly those identities in, and only the way its access mode needs: Direct IAP checks\n# roles/iap.httpsResourceAccessor on this service\'s IAP resource (Cloud Run then checks run.invoker on the IAP agent,\n# granted above); a private IAM-only service checks roles/run.invoker on the caller. Public services and an empty map\n# plan nothing.\nresource "google_iap_web_cloud_run_service_iam_member" "push_accessors" {\n  for_each               = (!var.allow_unauthenticated && var.enable_direct_iap) ? var.push_service_accounts : tomap({})\n  project                = var.project_id\n  location               = var.region\n  cloud_run_service_name = google_cloud_run_v2_service.app.name\n  role                   = "roles/iap.httpsResourceAccessor"\n  member                 = "serviceAccount:${each.value}"\n}\n\nresource "google_cloud_run_v2_service_iam_member" "push_invokers" {\n  for_each = (!var.allow_unauthenticated && !var.enable_direct_iap) ? var.push_service_accounts : tomap({})\n  project  = var.project_id\n  location = var.region\n  name     = google_cloud_run_v2_service.app.name\n  role     = "roles/run.invoker"\n  member   = "serviceAccount:${each.value}"\n}\n'
ADDED_VARIABLES = '\nvariable "push_service_accounts" {\n  description = "PUSH-TO-PRIVATE: the service accounts this workload\'s own Pub/Sub push subscriptions to this service sign their OIDC tokens with, keyed by a stable platform label (keys known at plan; values may be computed). A private service admits exactly these: the IAP accessor role with Direct IAP, run.invoker without it. Ignored for a public service. Rendered by the platform from the typed intent."\n  type        = map(string)\n  default     = {}\n\n  validation {\n    condition     = alltrue([for e in values(var.push_service_accounts) : can(regex("^[a-z0-9-]+@[a-z0-9.-]+\\\\.gserviceaccount\\\\.com$", e))])\n    error_message = "push_service_accounts values must be bare service account emails (no member prefix)."\n  }\n}\n'


def pre_push_private(rel: str, text: str) -> str:
    """`text` without the PUSH-TO-PRIVATE addition when `rel` is compute-cloudrun/main.tf or variables.tf (asserted
    present exactly once, at the end); any other file is returned unchanged."""
    if rel.endswith("compute-cloudrun/main.tf"):
        added = ADDED_MAIN
    elif rel.endswith("compute-cloudrun/variables.tf"):
        added = ADDED_VARIABLES
    else:
        return text
    assert text.count(added) == 1 and text.endswith(added), rel
    return text[:-len(added)]
