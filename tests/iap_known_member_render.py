"""IAP-GATE-KNOWN-MEMBER: the exact text the golden compute-cloudrun module gained (project_number input, member
expression and its comment) and the two lines a Direct IAP root render gained. Tests that pin older bytes remove
exactly this first (each once), so a further change to those files still fails them."""

MODULE_VARIABLE = '\nvariable "project_number" {\n  description = "IAP-GATE-KNOWN-MEMBER: the workload project\'s number, set by the platform render for a Direct IAP service so the IAP agent\'s invoker member is known at plan. Empty = the module reads it with its own data source."\n  type        = string\n  default     = ""\n\n  validation {\n    condition     = var.project_number == "" || can(regex("^[0-9]+$", var.project_number))\n    error_message = "project_number must be the numeric project number (or empty)."\n  }\n}\n'
MODULE_COMMENT = "# IAP-GATE-KNOWN-MEMBER: the agent's project number comes from var.project_number when the platform render sets it, so\n# the member is a real value in the plan the compliance gate reads. The data source in this module is read only at\n# apply on a first deploy (the platform's module-level depends_on on module.foundation defers it); it stays as the\n# fallback for a caller that does not set the input. Same project, same number, so the member string does not change.\n"
NEW_MEMBER = 'member     = "serviceAccount:service-${var.project_number != "" ? var.project_number : data.google_project.workload_project.number}@gcp-sa-iap.iam.gserviceaccount.com"'
OLD_MEMBER = 'member     = "serviceAccount:service-${data.google_project.workload_project.number}@gcp-sa-iap.iam.gserviceaccount.com"'
ROOT_DATA_BLOCK = """
# IAP-GATE-KNOWN-MEMBER: read at plan time (no depends_on), so the IAP agent's invoker member is a known value in the
# plan the compliance gate checks.
data "google_project" "stackvend_iap_project" {
  project_id = var.project_id
}
"""
ROOT_NUMBER_INPUT = "  project_number        = data.google_project.stackvend_iap_project.number\n"


def pre_iap_known_member(rel: str, text: str) -> str:
    """`text` without the module's IAP-GATE-KNOWN-MEMBER change (asserted present exactly once); other files unchanged."""
    if rel.endswith("compute-cloudrun/main.tf"):
        assert text.count(MODULE_COMMENT) == 1 and text.count(NEW_MEMBER) == 1, rel
        return text.replace(MODULE_COMMENT, "").replace(NEW_MEMBER, OLD_MEMBER)
    if rel.endswith("compute-cloudrun/variables.tf"):
        assert text.count(MODULE_VARIABLE) == 1, rel
        return text.replace(MODULE_VARIABLE, "")
    return text


def without_iap_known_member(render: str) -> str:
    """A generator render without the Direct IAP lines (when present: other renders pass through untouched)."""
    assert render.count(ROOT_DATA_BLOCK) <= 1
    if ROOT_NUMBER_INPUT not in render and ROOT_DATA_BLOCK not in render:
        return render
    return render.replace(ROOT_NUMBER_INPUT, "").replace(ROOT_DATA_BLOCK, "")
