"""S2-F HB-13 (proposed register row, not approved), generation side of the deletion: with the apply-time
``google_service_account.workload_sa`` -> ``module.foundation.*`` remap gone, an undeclared reference is reported by
the engine, and that report is typed for the repair loop.

The raw diagnostic below is the shape ``tofu validate -json`` (1.9) emits for the reference (range = the reference
bytes; the same summary/detail as the real run recorded in docs/handoff/s2f-hb13-remap-report.md). V1b maps it with
``map_raw_diagnostic`` to ``TF.REFERENCE_TO_UNDECLARED_RESOURCE`` with the referenced address as the symbol, located
in the AI's file and block: the repair loop routes that code back to the AI (``repair_loop.UNDECLARED_REFERENCE_CODE``).
Pure functions, no network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent.repair_loop import UNDECLARED_REFERENCE_CODE  # noqa: E402
from developer_agent.validators.tofu_diagnostics import map_raw_diagnostic  # noqa: E402

PATH = "infra/workload/custom.tf"
UNDECLARED_SA_TF = '''resource "google_project_iam_member" "sa_invoker" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.workload_sa.email}"
}
'''


def _raw(text, ref):
    start = text.index(ref)
    line = text[:start].count("\n") + 1
    col = start - text.rfind("\n", 0, start)
    return {"severity": "error", "summary": "Reference to undeclared resource",
            "detail": 'A managed resource "google_service_account" "workload_sa" has not been declared in the root '
                      'module.',
            "range": {"filename": PATH,
                      "start": {"line": line, "column": col, "byte": start},
                      "end": {"line": line, "column": col + len(ref), "byte": start + len(ref)}}}


def test_undeclared_workload_sa_is_a_typed_repairable_diagnostic():
    diag, target = map_raw_diagnostic(_raw(UNDECLARED_SA_TF, "google_service_account.workload_sa.email"),
                                      {PATH: UNDECLARED_SA_TF})
    assert diag.code == UNDECLARED_REFERENCE_CODE == "TF.REFERENCE_TO_UNDECLARED_RESOURCE"
    assert target == diag.symbol == "google_service_account.workload_sa"
    assert diag.file == PATH and diag.severity == "error"
    assert diag.block_address and "google_project_iam_member" in diag.block_address \
        and "sa_invoker" in diag.block_address
