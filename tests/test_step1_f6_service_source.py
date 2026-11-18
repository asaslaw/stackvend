"""Step 1 code RT F6: HB-04 decides "this LLM module is a Cloud Run service" by the module's exact `source` (the golden
compute-cloudrun directory), not by "compute" in the label or "cloudrun" anywhere in the block text (AGENTS.md
invariant 2). Only the service-label list changes; every LLM block stays byte-identical (HS-01 append-only)."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (apps/orchestrator-gateway/requirements.txt) not installed")

from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.assembly import CUSTOM_TF  # noqa: E402
from shared.diagnostics import AssemblyRecord  # noqa: E402

W = "infra/workload/"
MAIN = 'module "compute" {\n  source       = "../modules/compute-cloudrun"\n  service_name = var.product_id\n}\n'
SPEC = "Two services: api and worker"


@pytest.fixture()
def no_hb01():
    """FD-55 W5: HB-01 (reconcile_iac_reference_graph) is deleted; HB-04 already runs alone."""
    assert not hasattr(te, "reconcile_iac_reference_graph")
    yield


def _run(custom):
    files = {W + "main.tf": MAIN, CUSTOM_TF: custom, "apps/api/main.py": "x = 1\n", "apps/worker/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text=SPEC, archetype="cloudrun",
                                            assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF])
    return files


@pytest.mark.parametrize("source,expected", [
    ("../modules/compute-cloudrun", True), ("./modules/compute-cloudrun/", True), ("../modules/./compute-cloudrun", True),
    ("../modules/compute-gke-autopilot", False), ("../modules/compute-event-worker", False),
    ("../modules/compute-cloudrun-v2", False), ("git::https://example.invalid/compute-cloudrun", False),
    ("compute-cloudrun", False), ("${var.src}/compute-cloudrun", False), (None, False), (["x"], False),
])
def test_cloud_run_module_source_is_an_exact_path_component(source, expected):
    assert te._is_cloud_run_module_source(source) is expected


@pytest.mark.parametrize("custom,phantom", [
    # "compute" in the label, but a GKE cluster module
    ('module "gke_compute" {\n  source = "../modules/compute-gke-autopilot"\n}\n', "gke-compute"),
    # "cloudrun" only in an attribute value of a networking module
    ('module "edge" {\n  source = "../modules/networking-vpc"\n  note   = "fronts the cloudrun api"\n}\n', "edge"),
])
def test_a_non_cloud_run_module_is_not_a_phantom_service(no_hb01, custom, phantom):
    # mutation checked: the pre-F6 predicate ("compute" in label or "cloudrun" in block text) synthesizes a
    # compute-cloudrun module and an apps/<label>/ stub for it -> this fails (both cases)
    files = _run(custom)
    assert files[CUSTOM_TF].startswith(custom)
    assert f"apps/{phantom}/main.py" not in files
    assert files[CUSTOM_TF].count("../modules/compute-cloudrun") == 1      # only the requested worker is synthesized


def test_negative_a_cloud_run_module_still_counts_and_stays_byte_identical(no_hb01):
    # Do No Harm: an LLM compute-cloudrun module is still a service label (as before) and is never rewritten
    custom = 'module "reports" {\n  source       = "../modules/compute-cloudrun"\n  service_name = "reports"\n}\n'
    files = _run(custom)
    assert files[CUSTOM_TF].startswith(custom)
    assert not any(p.startswith("apps/reports/") for p in files)   # FD-55 W5 (G15): no placeholder app written
