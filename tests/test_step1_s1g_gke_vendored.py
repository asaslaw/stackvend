"""Step 1 S1-G (register HS-58, integration finding I-21) protected the vendored GKE module from HA-06
`sanitize_duplicate_gke_clusters`. FD-55 W4 (register FD55-W4) deleted HA-06 itself: it removed an AI
`google_container_cluster` it took for a duplicate of the platform's compute-gke-autopilot cluster and re-pointed the
references to module.compute (invariant 5 risk: a cross-region cluster). An AI cluster now reaches the validators as
written: on the typed-topology path V-T3 reports it (TOPOLOGY.COMPUTE_DECLARED_BY_LLM, the fix is a deletion by the
AI); the vendored module is the platform's own and restored by restore_platform_files (FD-4AB)."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from developer_agent import preflight_validator as PV  # noqa: E402
from developer_agent.validators.topology import LLM_COMPUTE_RESOURCE_TYPES  # noqa: E402


def test_ha06_is_deleted_and_nothing_calls_it():
    assert not hasattr(PV, "sanitize_duplicate_gke_clusters")
    for rel in ("handler.py", "preflight_validator.py"):
        src = open(os.path.join(GATEWAY, "developer_agent", rel)).read()
        calls = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call)
                 and getattr(n.func, "id", None) == "sanitize_duplicate_gke_clusters"]
        assert calls == [], rel


def test_an_ai_gke_cluster_is_reported_on_the_topology_path_not_stripped():
    assert "google_container_cluster" in LLM_COMPUTE_RESOURCE_TYPES   # V-T3: the AI deletes it in the repair loop
