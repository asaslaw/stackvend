"""FD-4CS-b: the exact text the golden compute-cloudrun main.tf gained (the IAP service agent block and the invoker
binding's depends_on). Tests that pin older bytes of that file remove exactly this (each once) first."""

ADDED_BLOCK = '''# StackVend FD-4CS-b: the IAP service agent of the workload project. A fresh project has no IAP agent until it is
# created (or read) through the Service Usage API, so the invoker binding below waits for it. Direct IAP only.
resource "google_project_service_identity" "iap_service_agent" {
  provider = google-beta
  count    = (!var.allow_unauthenticated && var.enable_direct_iap) ? 1 : 0
  project  = var.project_id
  service  = "iap.googleapis.com"
}

'''
ADDED_DEPENDS_ON = "  depends_on = [google_project_service_identity.iap_service_agent]\n"


def pre_fd4cs_b(rel: str, text: str) -> str:
    """`text` without the FD-4CS-b insertions when `rel` is compute-cloudrun/main.tf (asserted present exactly once);
    any other file is returned unchanged."""
    if not rel.endswith("compute-cloudrun/main.tf"):
        return text
    assert text.count(ADDED_BLOCK) == 1 and text.count(ADDED_DEPENDS_ON) == 1, rel
    return text.replace(ADDED_BLOCK, "").replace(ADDED_DEPENDS_ON, "")
