"""TI-1 code RT F2: a repository holding the platform's infra/workload/services.tf was generated with a service
topology. A request without one (legacy v1 record) would append the secondaries to custom.tf beside that render
(duplicate module declarations), so `resolve_compute_intent` holds it as a typed BROWNFIELD_CONFLICT
(TOPOLOGY.SERVICES_TF_WITHOUT_TOPOLOGY) before any LLM call. v1 without services.tf and v2 with it are unchanged.
Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

from developer_agent import compute_intent as ci  # noqa: E402
from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.assembly import CUSTOM_TF  # noqa: E402
from shared.diagnostics import AssemblyRecord, ErrorClass  # noqa: E402
from shared.service_topology import validate_service_topology  # noqa: E402

W = "infra/workload/"
MAIN_TF = W + "main.tf"
SERVICES_TF = W + "services.tf"
PID = "shop"
MAIN = 'module "compute" {\n  source       = "../modules/compute-cloudrun"\n  service_name = "api"\n}\n'
V1 = {"schema": "architect_compute_intent/v1", "target_compute_services": ["api", "core"], "bundle_id": None,
      "compute_archetype": None}
TOPO = {"services": [{"name": "api", "kind": "cloudrun"}, {"name": "core", "kind": "cloudrun"}],
        "primary_service": "api", "edges": [{"caller": "api", "callee": "core", "protocol": "http"}],
        "resources": []}


def _vt():
    vt, diags = validate_service_topology(TOPO, product_id=PID)
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def _v2():
    vt = _vt()
    return {"schema": "architect_compute_intent/v2", "target_compute_services": list(vt.names), "bundle_id": None,
            "compute_archetype": vt.archetype, "service_topology": vt.as_record()}


def _ti1_render():
    vt = _vt()
    files = {CUSTOM_TF: "", "apps/core/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(files=files, product_id=PID, spec_text="", archetype=vt.archetype,
                                            assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF],
                                            target_services=list(vt.names), topology=vt)
    return files[SERVICES_TF]


def test_v1_request_on_a_repository_with_services_tf_is_held_before_any_llm_call():
    existing = {MAIN_TF: MAIN, SERVICES_TF: _ti1_render()}
    with pytest.raises(ci.TopologyGuardError) as ei:
        ci.resolve_compute_intent(PID, V1, existing, ["api", "core"])
    (d,) = ei.value.diagnostics
    assert (d.code, d.error_class, d.file, d.severity) == ("TOPOLOGY.SERVICES_TF_WITHOUT_TOPOLOGY",
                                                           ErrorClass.BROWNFIELD_CONFLICT, SERVICES_TF, "error")
    assert d.hint and "FD-4Q" in d.hint
    # the developer turns it into a typed StageError with no LLM call (lane 10 handler mapping)
    from developer_agent.handler import DeveloperAgent
    from shared.diagnostics import StageError
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        dev = DeveloperAgent(project_id="")
    dev.genai_client = MagicMock()
    with patch.object(dev, "fetch_existing_repo_files", return_value=existing):
        with pytest.raises(StageError) as se:
            dev.generate_code_files(product_id=PID, spec_text="x", task_dag=[{"task_id": "T"}], trace_id="t-f2",
                                    architect_compute_intent=V1, allow_unauthenticated=True,  # FD-4R R-6
                                    enable_direct_iap=False, domain_restricted_sharing=False)
    assert se.value.report.error_class == ErrorClass.BROWNFIELD_CONFLICT
    assert [x.code for x in se.value.report.diagnostics] == ["TOPOLOGY.SERVICES_TF_WITHOUT_TOPOLOGY"]
    dev.genai_client.models.generate_content.assert_not_called()


def test_negative_v1_without_services_tf_resolves_exactly_as_before():
    """Do No Harm: the guard reads only the exact key; every other v1 input resolves as before."""
    got = ci.resolve_compute_intent(PID, V1, {MAIN_TF: MAIN}, ["api", "core"])
    assert (got.archetype, got.service_names, got.topology, got.source) == ("cloudrun", ("api", "core"), None,
                                                                            "existing-repo")
    custom_only = {MAIN_TF: MAIN, CUSTOM_TF: 'module "compute_core" {\n  source = "../modules/compute-cloudrun"\n'
                                             '  service_name = "core"\n}\n'}
    legacy = ci.resolve_compute_intent(PID, V1, custom_only, ["api", "core"])   # pre-TI-1 layout: no refusal
    assert (legacy.archetype, legacy.service_names, legacy.topology) == ("cloudrun", ("api", "core"), None)
    fresh = ci.resolve_compute_intent(PID, V1, {}, ["api", "core"])
    assert (fresh.archetype, fresh.service_names, fresh.topology) == ("cloudrun", ("api", "core"), None)


def test_negative_v2_with_services_tf_takes_the_topology_path():
    existing = {MAIN_TF: MAIN, SERVICES_TF: _ti1_render()}
    got = ci.resolve_compute_intent(PID, _v2(), existing)
    assert got.topology is not None and got.service_names == ("api", "core")
    assert "module.compute_core" in got.existing_services


@pytest.fixture(autouse=True)
def _fd7m_a_no_record_region(monkeypatch):
    """FD-7M-a (SAT-23 RT F1): these tests build developer agents without a Firestore client while the test env
    configures a project, which the dispatch now refuses (REGION_UNAVAILABLE: the recorded region cannot be read).
    They are not about regions: keep the platform-region answer they always had (the record-region paths are covered
    by tests/test_fd7m_a_regions_gw.py)."""
    from developer_agent import handler as _handler
    from developer_agent import terraform_engine as _engine
    monkeypatch.setattr(_handler, "resolve_workload_region",
                        lambda db=None, product_id=None, **kw: _engine.resolve_workload_region(db, **kw))
