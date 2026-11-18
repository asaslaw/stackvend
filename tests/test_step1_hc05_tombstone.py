"""Step 1 HS-19a (owner-approved 10-12; code RT F10): HC-05's phantom Cloud Run reference rewrite is deleted from
self_correct_hcl (branch 3b and its unconditional final sweep). A reference to a Cloud Run address the S1-A assembly
recorded as replaced passes self_correct_hcl byte-identical; the detection string stays (report only).
FD-55 W4: the whole HD-15 -> self_correct_hcl chain is now deleted; these tests pin that."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent import preflight_validator as PV  # noqa: E402

W = "infra/workload/"
SRC = os.path.join(GATEWAY, "developer_agent", "preflight_validator.py")


def test_self_correct_chain_is_deleted():
    """FD-55 W4 (FD55-W4): the HD-15 -> self_correct_hcl chain that held the deleted branch 3b is itself deleted, so a
    reference to a recorded Cloud Run replacement reaches V1b as the AI wrote it (the repair hint names the module)."""
    for name in ("run_ast_preflight_check", "self_correct_hcl", "_self_correct_workload_hcl"):
        assert not hasattr(PV, name)


def test_tombstone_no_phantom_cloud_run_rewrite_left():
    src = open(SRC).read()
    assert "Auto-healing phantom reference 'google_cloud_run_v2_service" not in src
    assert "Final preflight sweep auto-healing phantom reference" not in src
    tree = ast.parse(src)
    consts = {c.value for c in ast.walk(tree) if isinstance(c, ast.Constant) and isinstance(c.value, str)}
    assert not any("module.compute.service_name" in c for c in consts)
    assert "{target_mod}.service_name" not in src and "'module.compute.service_uri'" not in src
