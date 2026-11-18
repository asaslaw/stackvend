"""PWB-3 / PWB-4 (10-19, follow-ups of the Procfile-worker Fable RT F2 / F7, Gate A 05-r2).

PWB-3: V3c's inventory (`detect_workload_services`) applied the "authentic entrypoint" skeleton rule: when a sibling has
a `main.py`, a Procfile-only worker (05-r2 `apps/fleet-gke/`, `worker: python consumer.py`) was not a service, so a
Procfile naming a missing module was never judged; since PWB-1 such a worker is built and would crash at runtime. On
the topology path V3c now judges every container-kind topology service (any kind except NON_CONTAINER_KINDS; the
build's own rule). The legacy path (no topology) and VM kinds are unchanged.

PWB-4: a gke-autopilot topology service runs only if a Kubernetes workload runs its image; compute-gke-autopilot
renders the cluster only and the platform applies exactly the repository-root `k8s/*.yaml`. 05-r2 x3 shipped none.
V3c-k8s reports CONTAINER.K8S_WORKLOAD_MISSING (file `k8s/<svc>.yaml`, a file to create), routed to the persona that
writes the Kubernetes manifests; the topology contract prompt asks for the manifest. Fakes only; no network."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

import pytest
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
pytest.importorskip("yaml", reason="PyYAML (gateway requirement) not installed")

from developer_agent import topology_wiring as tw  # noqa: E402
from developer_agent.repair_loop import (CREATE_FILE_CODES, Assembled, LoopContext, RepairLoop,  # noqa: E402
                                         Router)
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.container import (K8S_MANIFEST_UNPARSEABLE_CODE,  # noqa: E402
                                                  K8S_WORKLOAD_MISSING_CODE, NON_CONTAINER_KINDS,
                                                  ContainerContractValidator, K8sWorkloadValidator,
                                                  is_topology_container_service, k8s_workload_hint, llm_services)
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from developer_agent.workload_inventory import detect_workload_services  # noqa: E402
from shared import service_topology as st  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import AssemblyRecord, Diagnostic, ErrorClass, MemoryLedgerStore  # noqa: E402
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

FASTAPI = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/health")\ndef health():\n    return {"ok": True}\n'
WEB = "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"
CONSUMER = "import json\n\n\ndef handle(msg):\n    return json.loads(msg)\n\n\nif __name__ == '__main__':\n    pass\n"
# The Gate A 05-r2 shape: Cloud Run edge (main.py) + GKE Procfile-only worker + gce-worker the edge launches.
R2 = {
    "apps/fleet-edge/main.py": FASTAPI,
    "apps/fleet-edge/Procfile": WEB,
    "apps/fleet-edge/requirements.txt": "fastapi\nuvicorn\n",
    "apps/fleet-gke/consumer.py": CONSUMER,
    "apps/fleet-gke/Procfile": "worker: python consumer.py\n",
    "apps/fleet-gke/requirements.txt": "google-cloud-pubsub\n",
    "apps/batch-worker/startup.sh": "#!/bin/bash\npoweroff\n",
    "apps/batch-worker/tool.py": "print(1)\n",
}
TYPO = dict(R2, **{"apps/fleet-gke/Procfile": "worker: python consumr.py\n"})
DEPLOYMENT = ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {name}\nspec:\n  template:\n    spec:\n"
              "      containers:\n        - name: {cname}\n          image: ${{ARTIFACT_REGISTRY}}/fleet-gke:latest\n")


def _topo(services, primary, edges=()):
    vt, diags = st.validate_service_topology(
        {"services": [{"name": n, "kind": k, **({"vm": {"machine_type": "e2-micro"}} if k == "gce-worker" else {})}
                      for n, k in services],
         "primary_service": primary, "edges": list(edges), "resources": []}, product_id="test-05-fleet")
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def _r2_topo():
    return _topo([("fleet-gke", "gke-autopilot"), ("fleet-edge", "cloudrun"), ("batch-worker", "gce-worker")],
                 "fleet-gke", edges=[{"caller": "fleet-edge", "callee": "batch-worker", "protocol": "launch"}])


def _ctx(files, llm=None):
    llm = set(files) if llm is None else set(llm)
    return ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED if p in llm
                                   else Ownership.PLATFORM_RENDERED, draft={k: files[k] for k in llm if k in files})


def _v3c(files, topology=None, llm=None):
    return sorted((d.code, d.file, d.symbol) for d in ContainerContractValidator(topology).validate(_ctx(files, llm)))


def _k8s(files, topology):
    return sorted((d.code, d.file) for d in K8sWorkloadValidator(topology).validate(_ctx(files)))


# ================================================================================================ PWB-3
def test_r2_shape_is_the_skeleton_rule_case():
    """The inventory alone leaves the Procfile-only worker out (why V3c never judged it)."""
    assert detect_workload_services(dict(TYPO), "") == ["fleet-edge"]
    assert llm_services(_ctx(TYPO)) == ["fleet-edge"]


def test_r2_typod_procfile_is_entrypoint_missing_on_the_topology_path():
    vt = _r2_topo()
    assert llm_services(_ctx(TYPO), vt) == ["fleet-edge", "fleet-gke"]   # batch-worker: gce-worker, exempt
    assert _v3c(TYPO, vt) == [("CONTAINER.ENTRYPOINT_MISSING", "apps/fleet-gke/Procfile", "worker")]


def test_r2_typod_procfile_without_topology_is_unchanged():
    assert _v3c(TYPO) == []


def test_do_no_harm_valid_r2_worker_has_no_finding():
    assert _v3c(R2, _r2_topo()) == [] == _v3c(R2)


def test_topology_container_service_without_procfile_is_reported():
    files = {k: v for k, v in R2.items() if k != "apps/fleet-gke/Procfile"}
    assert _v3c(files, _r2_topo()) == [("CONTAINER.ENTRYPOINT_MISSING", "apps/fleet-gke/Procfile", None)]
    assert _v3c(files) == []   # legacy: unchanged


@pytest.mark.parametrize("kind", ["cloudrun", "event-worker", "gke-autopilot"])
def test_every_container_kind_is_judged(kind):
    # gke-autopilot can only be the primary (one per workload); the others are judged as secondaries
    vt = _topo([("wrk", kind), ("edge", "cloudrun")], "wrk") if kind == "gke-autopilot" else \
        _topo([("edge", "cloudrun"), ("wrk", kind)], "edge")
    files = {"apps/edge/main.py": FASTAPI, "apps/edge/Procfile": WEB, "apps/wrk/w.py": CONSUMER,
             "apps/wrk/Procfile": "worker: python missing.py\n"}
    assert _v3c(files, vt) == [("CONTAINER.ENTRYPOINT_MISSING", "apps/wrk/Procfile", "worker")]
    assert _v3c(files) == []


def test_vm_kinds_stay_exempt():
    vt = _r2_topo()
    files = dict(TYPO, **{"apps/batch-worker/Procfile": "worker: python nothere.py\n"})
    assert ("CONTAINER.ENTRYPOINT_MISSING", "apps/batch-worker/Procfile", "worker") not in _v3c(files, vt)
    assert not any(is_topology_container_service(vt, n) for n in ("batch-worker",))
    assert NON_CONTAINER_KINDS == frozenset({"gce-bastion", "gce-worker"})


def test_underscore_directory_uses_the_s3b1_normalization():
    vt = _r2_topo()
    files = {k.replace("apps/fleet-gke/", "apps/fleet_gke/"): v for k, v in TYPO.items()}
    assert _v3c(files, vt) == [("CONTAINER.ENTRYPOINT_MISSING", "apps/fleet_gke/Procfile", "worker")]


def test_directory_the_topology_does_not_name_keeps_the_inventory_rule():
    vt = _r2_topo()
    files = dict(R2, **{"apps/helpers/util.py": "X = 1\n", "apps/helpers/Procfile": "worker: python gone.py\n"})
    assert _v3c(files, vt) == []
    assert not is_topology_container_service(vt, "helpers") and not is_topology_container_service(None, "fleet-gke")


def test_platform_only_service_is_not_judged():
    """Only LLM-owned `.py` files make a service (the platform renders its own stubs' Procfiles)."""
    vt = _r2_topo()
    llm = set(TYPO) - {"apps/fleet-gke/consumer.py"}
    assert _v3c(TYPO, vt, llm=llm) == []


def test_v3c_never_changes_the_tree():
    ctx = _ctx(dict(TYPO))
    ContainerContractValidator(_r2_topo()).validate(ctx)
    assert dict(ctx.files) == TYPO


# ================================================================================================ PWB-4 validator
def test_r2_without_any_manifest_is_k8s_workload_missing():
    assert _k8s(R2, _r2_topo()) == [(K8S_WORKLOAD_MISSING_CODE, "k8s/fleet-gke.yaml")]


@pytest.mark.parametrize("name,cname", [("fleet-gke", "consumer"), ("fleet-gke-deployment", "fleet-gke")])
def test_applied_deployment_naming_the_service_passes(name, cname):
    files = dict(R2, **{"k8s/deployment.yaml": DEPLOYMENT.format(name=name, cname=cname)})
    assert _k8s(files, _r2_topo()) == []


@pytest.mark.parametrize("kind", ["StatefulSet", "DaemonSet"])
def test_other_workload_kinds_count(kind):
    files = dict(R2, **{"k8s/fleet-gke.yml": DEPLOYMENT.format(name="fleet-gke", cname="c").replace(
        "kind: Deployment", f"kind: {kind}")})
    assert _k8s(files, _r2_topo()) == []


@pytest.mark.parametrize("path", ["apps/fleet-gke/k8s/deployment.yaml", "k8s/sub/deployment.yaml",
                                  "infra/workload/k8s/deployment.yaml"])
def test_a_manifest_the_platform_does_not_apply_does_not_count(path):
    """Gate A 04-r2 / 05-r1 shape: manifests under apps/<svc>/k8s/ are never applied (kubectl apply -f k8s/)."""
    files = dict(R2, **{path: DEPLOYMENT.format(name="fleet-gke", cname="fleet-gke")})
    assert _k8s(files, _r2_topo()) == [(K8S_WORKLOAD_MISSING_CODE, "k8s/fleet-gke.yaml")]


def test_service_and_hpa_only_is_missing_and_points_at_the_existing_file_name():
    files = dict(R2, **{"k8s/fleet-gke.yaml": "apiVersion: v1\nkind: Service\nmetadata:\n  name: fleet-gke\n---\n"
                                              "apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n"
                                              "metadata:\n  name: fleet-gke\n"})
    assert _k8s(files, _r2_topo()) == [(K8S_WORKLOAD_MISSING_CODE, "k8s/fleet-gke.yaml")]


def test_terraform_kubernetes_workload_is_not_judged():
    """Gate A 04-r1 shape: kubernetes_deployment_v1 in the root module, names are expressions -> no name guess."""
    tf = ('resource "kubernetes_deployment_v1" "stream_processor" {\n  metadata {\n    name = local.app_name\n  }\n'
          '}\n')
    assert _k8s(dict(R2, **{"infra/workload/k8s_manifests.tf": tf}), _r2_topo()) == []
    other = 'resource "kubernetes_service_v1" "svc" {\n  metadata {\n    name = "x"\n  }\n}\n'
    assert _k8s(dict(R2, **{"infra/workload/k8s_manifests.tf": other}), _r2_topo()) == [
        (K8S_WORKLOAD_MISSING_CODE, "k8s/fleet-gke.yaml")]


BAD_YAML = 'a: "unterminated\n---\nb: 1\n'   # the 05-r1 failure shape (quoted scalar cut by a document separator)


def test_unparseable_applied_manifest_is_its_own_finding_and_the_rest_is_still_judged():
    """RT F1: never fail open. A broken applied manifest is reported (file = that manifest, PyYAML's message), and the
    services are judged against the manifests that parsed."""
    vt = _r2_topo()
    files = dict(R2, **{"k8s/bad.yaml": BAD_YAML, "k8s/deployment.yaml": DEPLOYMENT.format(name="fleet-gke",
                                                                                           cname="fleet-gke")})
    got = K8sWorkloadValidator(vt).validate(_ctx(files))
    assert [(d.code, d.file, d.severity) for d in got] == [(K8S_MANIFEST_UNPARSEABLE_CODE, "k8s/bad.yaml", "error")]
    assert "not valid YAML" in got[0].message and "quoted scalar" in got[0].message
    # the broken file alone: both findings (the gate can never be satisfied by emitting invalid YAML)
    assert _k8s(dict(R2, **{"k8s/bad.yaml": BAD_YAML}), vt) == [
        (K8S_MANIFEST_UNPARSEABLE_CODE, "k8s/bad.yaml"), (K8S_WORKLOAD_MISSING_CODE, "k8s/fleet-gke.yaml")]


def test_unparseable_finding_routes_to_the_manifest_author():
    draft = dict(R2, **{"k8s/bad.yaml": BAD_YAML})
    attribution = {p: "BACKEND_ENGINEER" for p in R2} | {"k8s/bad.yaml": "DEVOPS_ENGINEER"}
    d = Diagnostic(tool="container", code=K8S_MANIFEST_UNPARSEABLE_CODE, severity="error", file="k8s/bad.yaml",
                   message="m", source="precommit")
    r = _router(draft, attribution).route(d)
    assert (r.error_class, r.persona, r.draft_path) == (ErrorClass.CODE_DEFECT, "DEVOPS_ENGINEER", "k8s/bad.yaml")
    assert K8S_MANIFEST_UNPARSEABLE_CODE not in CREATE_FILE_CODES


def test_do_no_harm_valid_manifests_give_no_unparseable_finding():
    vt = _r2_topo()
    multi = ("apiVersion: v1\nkind: Service\nmetadata:\n  name: fleet-gke\n---\n"
             "apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\nmetadata:\n  name: fleet-gke-hpa\n---\n"
             + DEPLOYMENT.format(name="fleet-gke", cname="fleet-gke"))
    for files in ({"k8s/deployment.yaml": DEPLOYMENT.format(name="fleet-gke", cname="c")}, {"k8s/all.yaml": multi},
                  {"k8s/fleet-gke.yml": DEPLOYMENT.format(name="x", cname="fleet-gke")}):
        assert _k8s(dict(R2, **files), vt) == [], files
    # an empty manifest is valid YAML: no UNPARSEABLE, only the missing workload
    assert _k8s(dict(R2, **{"k8s/empty.yaml": ""}), vt) == [(K8S_WORKLOAD_MISSING_CODE, "k8s/fleet-gke.yaml")]


def test_unindexable_root_tf_is_not_judged():
    """tofu validate (blocking) reports a broken .tf; the k8s check does not guess around it."""
    assert _k8s(dict(R2, **{"infra/workload/custom.tf": 'resource "x" {\n'}), _r2_topo()) == []


JOB = ("apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: other\nspec:\n  template:\n    spec:\n"
       "      containers:\n        - name: fleet-gke\n          image: ${ARTIFACT_REGISTRY}/fleet-gke:latest\n")
CRONJOB = ("apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: other\nspec:\n  schedule: '*/5 * * * *'\n"
           "  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n"
           "            - name: fleet-gke\n              image: ${ARTIFACT_REGISTRY}/fleet-gke:latest\n")
LIST = ("apiVersion: v1\nkind: List\nitems:\n  - apiVersion: apps/v1\n    kind: Deployment\n    metadata:\n"
        "      name: fleet-gke\n    spec:\n      template:\n        spec:\n          containers:\n"
        "            - name: c\n              image: x\n")


@pytest.mark.parametrize("manifest", [JOB, CRONJOB, LIST], ids=["job", "cronjob", "list"])
def test_job_cronjob_and_list_are_workloads(manifest):
    """RT F2: container names are read at the documented pod-template path of each kind; `kind: List` is unwrapped."""
    assert _k8s(dict(R2, **{"k8s/w.yaml": manifest}), _r2_topo()) == []


def test_cronjob_containers_are_read_only_at_the_job_template_path():
    wrong = CRONJOB.replace("  jobTemplate:\n    spec:\n      template:", "  template:\n    spec:\n      template:")
    assert _k8s(dict(R2, **{"k8s/w.yaml": wrong}), _r2_topo()) == [(K8S_WORKLOAD_MISSING_CODE, "k8s/fleet-gke.yaml")]
    service_list = LIST.replace("kind: Deployment", "kind: Service")
    assert _k8s(dict(R2, **{"k8s/w.yaml": service_list}), _r2_topo()) == [
        (K8S_WORKLOAD_MISSING_CODE, "k8s/fleet-gke.yaml")]


@pytest.mark.parametrize("tf_type", ["kubernetes_job_v1", "kubernetes_job", "kubernetes_cron_job_v1",
                                     "kubernetes_cron_job"])
def test_terraform_jobs_are_terraform_workloads(tf_type):
    tf = f'resource "{tf_type}" "batch" {{\n  metadata {{\n    name = local.n\n  }}\n}}\n'
    assert _k8s(dict(R2, **{"infra/workload/k8s.tf": tf}), _r2_topo()) == []


def test_hint_names_every_workload_kind():
    hint = k8s_workload_hint("fleet-gke")
    assert "Deployment (or StatefulSet / DaemonSet / Job / CronJob)" in hint
    assert "${ARTIFACT_REGISTRY}/fleet-gke:latest" in hint and "k8s/fleet-gke.yaml" in hint


def test_the_gke_service_is_checked_by_exact_name():
    """A workload for another name does not count (gke-autopilot is the single primary of a topology)."""
    files = dict(R2, **{"k8s/a.yaml": DEPLOYMENT.format(name="fleet-edge", cname="fleet-gke-worker")})
    assert _k8s(files, _r2_topo()) == [(K8S_WORKLOAD_MISSING_CODE, "k8s/fleet-gke.yaml")]


def test_no_gke_service_or_no_topology_checks_nothing():
    assert _k8s(R2, None) == []
    assert _k8s(R2, _topo([("api", "cloudrun")], "api")) == []


def test_registered_blocking_only_for_a_topology_with_a_gke_service():
    gke = build_step1_stack(validate_client=None, verifier_factory=None, topology=_r2_topo())
    assert gke.mode_of("V3c-k8s") == "blocking"
    for topology in (None, _topo([("api", "cloudrun")], "api")):
        stack = build_step1_stack(validate_client=None, verifier_factory=None, topology=topology)
        assert "V3c-k8s" not in stack.ids


def test_k8s_validator_never_changes_the_tree():
    ctx = _ctx(dict(R2))
    K8sWorkloadValidator(_r2_topo()).validate(ctx)
    assert dict(ctx.files) == R2


# ================================================================================================ PWB-4 routing
def _diag(path):
    return Diagnostic(tool="container", code=K8S_WORKLOAD_MISSING_CODE, severity="error", file=path, message="m",
                      source="precommit")


def _router(draft, attribution):
    ctx = LoopContext(trace_id="t1", product_id="test-05-fleet", assemble=lambda d: None, stack=ValidatorStack(),
                      ledger_store=MemoryLedgerStore(), settings=HallucinationStackSettings(),
                      attribution=dict(attribution), llm_draft_paths=set(draft), preexisting=set(), model="m")
    return Router(ctx, draft, Assembled(tree=dict(draft), record=AssemblyRecord(), assembled_root={}))


def test_code_is_a_create_code():
    assert K8S_WORKLOAD_MISSING_CODE in CREATE_FILE_CODES


def test_routed_to_the_persona_that_writes_k8s_manifests():
    draft = dict(R2, **{"apps/fleet-gke/k8s/svc.yaml": "kind: Service\n"})
    attribution = {p: "BACKEND_ENGINEER" for p in R2} | {"apps/fleet-gke/k8s/svc.yaml": "DEVOPS_ENGINEER"}
    r = _router(draft, attribution).route(_diag("k8s/fleet-gke.yaml"))
    assert (r.error_class, r.persona, r.draft_path) == (ErrorClass.CODE_DEFECT, "DEVOPS_ENGINEER", "k8s/fleet-gke.yaml")
    # an applied manifest's author is preferred over a non-applied one
    draft["k8s/ns.yaml"] = "kind: Namespace\n"
    attribution["k8s/ns.yaml"] = "IAC_ENGINEER"
    assert _router(draft, attribution).route(_diag("k8s/fleet-gke.yaml")).persona == "IAC_ENGINEER"


def test_no_manifest_author_falls_back_to_the_service_author():
    attribution = {p: ("WORKER_ENGINEER" if p.startswith("apps/fleet-gke/") else "BACKEND_ENGINEER") for p in R2}
    r = _router(dict(R2), attribution).route(_diag("k8s/fleet-gke.yaml"))
    assert (r.error_class, r.persona) == (ErrorClass.CODE_DEFECT, "WORKER_ENGINEER")


def test_nobody_wrote_the_service_or_a_manifest_is_a_platform_defect():
    draft = {"apps/fleet-edge/main.py": FASTAPI}
    r = _router(draft, {"apps/fleet-edge/main.py": "BACKEND_ENGINEER"}).route(_diag("k8s/fleet-gke.yaml"))
    assert r.error_class is ErrorClass.PLATFORM_DEFECT


@pytest.mark.parametrize("path", ["k8s/../x.yaml", "/k8s/a.yaml", "k8s/sub/a.yaml", "apps/fleet-gke/a.yaml",
                                  "k8s/.yaml", "k8s/a.yml", "k8s/.git/a.yaml"])
def test_only_the_exact_applied_manifest_path_is_offered_as_a_create(path):
    attribution = {p: "BACKEND_ENGINEER" for p in R2}
    assert _router(dict(R2), attribution).route(_diag(path)).error_class is ErrorClass.PLATFORM_DEFECT


def test_existing_manifest_file_is_repaired_by_its_author_not_created():
    draft = dict(R2, **{"k8s/fleet-gke.yaml": "kind: Service\nmetadata:\n  name: fleet-gke\n"})
    attribution = {p: "BACKEND_ENGINEER" for p in R2} | {"k8s/fleet-gke.yaml": "DEVOPS_ENGINEER"}
    r = _router(draft, attribution).route(_diag("k8s/fleet-gke.yaml"))
    assert (r.error_class, r.persona, r.draft_path) == (ErrorClass.CODE_DEFECT, "DEVOPS_ENGINEER", "k8s/fleet-gke.yaml")


class _Persona:
    def __init__(self, *responses):
        self.responses, self.tasks = list(responses), []

    def __call__(self, task):
        self.tasks.append(task)
        return {"files": self.responses.pop(0) if self.responses else {}, "envelope_ok": True, "model": "m",
                "tokens_in": 10, "tokens_out": 10, "tokens_thoughts": 0}


def test_repair_loop_creates_the_manifest_end_to_end():
    manifest = DEPLOYMENT.format(name="fleet-gke", cname="fleet-gke")
    persona = _Persona({"k8s/fleet-gke.yaml": manifest})
    stack = ValidatorStack()
    stack.register(K8sWorkloadValidator(_r2_topo()), "blocking")
    ctx = LoopContext(trace_id="t1", product_id="test-05-fleet",
                      assemble=lambda d: Assembled(tree=dict(d), record=AssemblyRecord(), assembled_root={}),
                      stack=stack, ledger_store=MemoryLedgerStore(), settings=HallucinationStackSettings(),
                      attribution={p: "BACKEND_ENGINEER" for p in R2}, llm_draft_paths=set(R2), preexisting=set(),
                      repair_fn=persona, model="m", available_providers=["google"])
    tree, report = RepairLoop(ctx).run(dict(R2))
    assert report.status == "PASS" and tree["k8s/fleet-gke.yaml"] == manifest
    t = persona.tasks[0]
    assert t.creates == ["k8s/fleet-gke.yaml"] and t.files_to_fix == {"k8s/fleet-gke.yaml": ""}
    assert "${ARTIFACT_REGISTRY}/fleet-gke:latest" in t.prompt()   # the hint carries the FD-4AF placeholder
    assert ctx.attribution["k8s/fleet-gke.yaml"] == "BACKEND_ENGINEER"


# ================================================================================================ PWB-4 prompt
def test_contract_asks_gke_services_for_their_manifest_only():
    vt = _r2_topo()
    text = tw.topology_contract_rule(vt)
    clause = tw.gke_manifest_clause("fleet-gke")
    assert text.count(clause) == 1
    gke_line = [ln for ln in text.splitlines() if ln.startswith("- `fleet-gke` (gke-autopilot,")]
    assert len(gke_line) == 1 and clause in gke_line[0]
    assert "`k8s/fleet-gke.yaml`" in clause and "${ARTIFACT_REGISTRY}/fleet-gke:latest" in clause
    for other in ("fleet-edge", "batch-worker"):
        assert tw.gke_manifest_clause(other) not in text


def test_single_gke_service_now_gets_a_contract_and_single_cloudrun_stays_empty():
    assert tw.gke_manifest_clause("solo") in tw.topology_contract_rule(_topo([("solo", "gke-autopilot")], "solo"))
    assert tw.topology_contract_rule(_topo([("shop", "cloudrun")], "shop")) == ""
    assert tw.topology_contract_rule(None) == ""


def test_contract_placeholder_is_an_fd4af_placeholder():
    from developer_agent.preflight_validator import K8S_MANIFEST_PLACEHOLDERS
    assert "ARTIFACT_REGISTRY" in K8S_MANIFEST_PLACEHOLDERS


def test_pwb4b_clause_names_exactly_the_fd4af_placeholder_set():
    """Paid check 27b4623e: the swarm invented `${WORKLOAD_SA_EMAIL}`; the clause lists the exact set it may use."""
    from developer_agent.preflight_validator import K8S_MANIFEST_PLACEHOLDERS
    clause = tw.gke_manifest_clause("stream-processor")
    for t in K8S_MANIFEST_PLACEHOLDERS:
        assert f"`${{{t}}}`" in clause
    assert "iam.gke.io/gcp-service-account" in clause and "@${PROJECT_ID}.iam.gserviceaccount.com" in clause


def test_pwb4b_a_manifest_written_as_the_clause_says_hydrates_and_the_paid_check_shape_does_not():
    from developer_agent.preflight_validator import ManifestHydrationError, hydrate_kubernetes_manifests
    sa = ("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa-stream-worker\n  annotations:\n"
          "    iam.gke.io/gcp-service-account: {gsa}\n---\n")
    dep = DEPLOYMENT.format(name="stream-processor", cname="stream-processor").replace("fleet-gke", "stream-processor")
    good = {"k8s/stream-processor.yaml": sa.format(gsa="stream-worker@${PROJECT_ID}.iam.gserviceaccount.com") + dep}
    out, _ = hydrate_kubernetes_manifests(good, "test-04-gke-stream-processor", project_id="eval-04-project",
                                          region="us-central1")
    assert "$" not in out["k8s/stream-processor.yaml"].split("image:")[1].split("\n")[0]
    assert "stream-worker@eval-04-project.iam.gserviceaccount.com" in out["k8s/stream-processor.yaml"]
    bad = {"k8s/stream-processor.yaml": sa.format(gsa="${WORKLOAD_SA_EMAIL}") + dep}   # the 04-r1 / 04-r3 draft shape
    with pytest.raises(ManifestHydrationError) as e:
        hydrate_kubernetes_manifests(bad, "test-04-gke-stream-processor", project_id="eval-04-project",
                                     region="us-central1")
    assert e.value.code == "K8S.PLACEHOLDER_UNRESOLVED"
