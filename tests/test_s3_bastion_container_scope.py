"""S3-bastion (10-19): V3c (the Buildpacks container contract) judged the VM code of a `gce-bastion` workload.

Gate B (main 6534185) S3 = one Compute Engine bastion VM, "do not run any web server". The swarm wrote the
maintenance script under apps/ops-bastion/ (no Procfile, correctly). V3c listed `ops-bastion` as a container service
(`detect_workload_services`, a directory inventory) and raised CONTAINER.ENTRYPOINT_MISSING; the repair could only
write a uvicorn Procfile for a module that does not exist -> RepairBudgetExhausted (r1, r3). r2 "passed" because the
repairs bolted a Procfile and a PORT read onto the bastion script. A gce-bastion's CI workflow builds nothing (a
logged no-op since FD-4AT-b) and compute-gce-bastion takes no image; a gce-worker gets no workflow and runs apps/<worker>/startup.sh.

Fix: on the topology path V3c / V3c-health-unverified / V3c-migration skip services whose TYPED kind (the validated
service topology, exact name lookup) is in NON_CONTAINER_KINDS. The legacy path (no topology), every other kind and
every directory the topology does not name are judged exactly as before."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators.container import (NON_CONTAINER_KINDS, ContainerContractValidator,  # noqa: E402
                                                  HealthRouteUnverifiedValidator, MigrationInvocationValidator,
                                                  llm_services)
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from shared import service_topology as st  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402

FASTAPI = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/health")\ndef health():\n    return {"ok": True}\n'
WEB = "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"
# The S3-r1 first-draft shape: a maintenance script package, no Procfile, no web app.
BASTION = {
    "apps/ops-bastion/export_maintenance.py": "import json\n\n\ndef main():\n    print(json.dumps({}))\n\n\n"
                                              "if __name__ == '__main__':\n    main()\n",
    "apps/ops-bastion/config.py": "BUCKET = 'ops-reports'\n",
    "apps/ops-bastion/models.py": "class Entry:\n    pass\n",
    "apps/ops-bastion/requirements.txt": "google-cloud-storage\n",
    "apps/ops-bastion/startup.sh": "#!/bin/bash\npython3 /opt/ops/export_maintenance.py\n",
}


def _topo(services, primary, edges=()):
    vt, diags = st.validate_service_topology(
        {"services": [{"name": n, "kind": k, **({"vm": {"machine_type": "e2-micro"}} if k == "gce-worker" else {})}
                      for n, k in services],
         "primary_service": primary, "edges": list(edges), "resources": []}, product_id="test-s3-ops-bastion")
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def _ctx(files):
    return ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED, draft=dict(files))


def _codes(files, topology=None, validator=ContainerContractValidator):
    return sorted((d.code, d.file) for d in validator(topology).validate(_ctx(files)))


BASTION_TOPO = [("ops-bastion", "gce-bastion")]


# ------------------------------------------------------------------------------------------------ the S3 finding
def test_s3_bastion_vm_code_has_no_container_contract_on_the_topology_path():
    vt = _topo(BASTION_TOPO, "ops-bastion")
    assert vt.kind("ops-bastion") == "gce-bastion"
    assert _codes(BASTION, vt) == []
    assert llm_services(_ctx(BASTION), vt) == []


def test_s3_bastion_without_topology_is_judged_as_before():
    """Legacy path unchanged: the same tree still gets ENTRYPOINT_MISSING when no topology is passed."""
    assert _codes(BASTION) == [("CONTAINER.ENTRYPOINT_MISSING", "apps/ops-bastion/Procfile")]


def test_bastion_with_a_procfile_is_not_judged_either():
    """r2's repaired shape (Procfile + main.py without PORT) is not a container finding on a VM."""
    files = dict(BASTION, **{"apps/ops-bastion/main.py": "print('maintenance')\n",
                             "apps/ops-bastion/Procfile": "web: python main.py\n"})
    assert _codes(files, _topo(BASTION_TOPO, "ops-bastion")) == []
    assert _codes(files) == [("CONTAINER.PORT_NOT_BOUND", "apps/ops-bastion/main.py")]   # legacy: as before


def test_report_only_container_validators_skip_the_bastion_too():
    vt = _topo(BASTION_TOPO, "ops-bastion")
    files = dict(BASTION, **{"apps/ops-bastion/alembic.ini": "[alembic]\n"})
    assert _codes(files, vt, MigrationInvocationValidator) == []
    assert _codes(files, None, MigrationInvocationValidator) == [
        ("CONTAINER.MIGRATION_NOT_INVOKED", "apps/ops-bastion/Procfile")]   # HS-40: names the file to repair
    assert _codes(files, vt, HealthRouteUnverifiedValidator) == []


# ------------------------------------------------------------------------------------------------ still fires
def test_cloudrun_topology_service_missing_its_procfile_still_fires():
    vt = _topo([("api", "cloudrun")], "api")
    assert _codes({"apps/api/main.py": FASTAPI}, vt) == [("CONTAINER.ENTRYPOINT_MISSING", "apps/api/Procfile")]


def test_mixed_topology_judges_the_container_service_and_skips_the_gce_worker():
    vt = _topo([("dispatcher", "cloudrun"), ("batch-worker", "gce-worker")], "dispatcher",
               edges=[{"caller": "dispatcher", "callee": "batch-worker", "protocol": "launch"}])
    files = {"apps/dispatcher/main.py": FASTAPI, "apps/batch-worker/main.py": "print(1)\n",
             "apps/batch-worker/startup.sh": "#!/bin/bash\npoweroff\n"}
    assert _codes(files, vt) == [("CONTAINER.ENTRYPOINT_MISSING", "apps/dispatcher/Procfile")]


def test_directory_the_topology_does_not_name_is_judged_as_before():
    """Exact name lookup: an apps/<dir> that is not a topology service gets no exemption (never a name guess)."""
    vt = _topo(BASTION_TOPO, "ops-bastion")
    files = {"apps/test-s3-ops-bastion/main.py": "print(1)\n"}
    assert _codes(files, vt) == _codes(files) == [
        ("CONTAINER.ENTRYPOINT_MISSING", "apps/test-s3-ops-bastion/Procfile")]


# ------------------------------------------------------------------------------------------------ Do No Harm
@pytest.mark.parametrize("kind", ["cloudrun", "event-worker", "gke-autopilot"])
def test_container_kinds_get_the_exact_same_findings_with_and_without_topology(kind):
    vt = _topo([("api", kind)], "api")
    for files in ({"apps/api/main.py": FASTAPI, "apps/api/Procfile": WEB},           # valid -> []
                  {"apps/api/main.py": FASTAPI},                                     # missing Procfile
                  {"apps/api/main.py": FASTAPI, "apps/api/Procfile": "web: uvicorn app:app --port $PORT\n"}):
        assert _codes(files, vt) == _codes(files)
    assert _codes({"apps/api/main.py": FASTAPI, "apps/api/Procfile": WEB}, vt) == []


def test_validators_never_change_the_tree():
    vt = _topo(BASTION_TOPO, "ops-bastion")
    files = dict(BASTION)
    ctx = _ctx(files)
    for v in (ContainerContractValidator(vt), HealthRouteUnverifiedValidator(vt), MigrationInvocationValidator(vt)):
        v.validate(ctx)
    assert dict(ctx.files) == BASTION


# ------------------------------------------------------------------------------------------------ data + wiring
def test_non_container_kinds_are_typed_vm_kinds():
    assert NON_CONTAINER_KINDS <= set(st.COMPUTE_KINDS)
    assert {st.CAPABILITIES[k].module_dir for k in NON_CONTAINER_KINDS} == {"compute-gce-bastion",
                                                                            "compute-gce-worker"}


def test_why_vm_kinds_have_no_container_build():
    """The facts NON_CONTAINER_KINDS rests on: the gce-bastion workflow builds no image from apps/<svc>
    (a logged no-op since FD-4AT-b; tf-applier applies) and a gce-worker gets no workflow at all; a Cloud Run workflow does build one."""
    from developer_agent.handler import generate_service_workflow
    from developer_agent.topology_wiring import workflow_services
    assert "--source" not in generate_service_workflow("ops-bastion", "test-s3-ops-bastion", archetype="gce-bastion")
    assert "--source" in generate_service_workflow("api", "p", archetype="cloudrun")
    vt = _topo([("dispatcher", "cloudrun"), ("batch-worker", "gce-worker")], "dispatcher",
               edges=[{"caller": "dispatcher", "callee": "batch-worker", "protocol": "launch"}])
    assert workflow_services(vt) == ["dispatcher"]


def test_build_step1_stack_passes_the_topology_to_the_container_validators():
    vt = _topo(BASTION_TOPO, "ops-bastion")
    for topology in (vt, None):
        stack = build_step1_stack(validate_client=None, verifier_factory=None, topology=topology)
        regs = {r.validator.id: r.validator for r in stack._regs}
        for vid in ("V3c", "V3c-health-unverified", "V3c-migration"):
            assert regs[vid].topology is topology
