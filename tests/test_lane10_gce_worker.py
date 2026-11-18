"""Lane 10 follow-up (register L10-s/t/u/v): the typed VM worker kind `gce-worker`.

A gce-worker is an instance template (golden module `compute-gce-worker`) that a Cloud Run service launches VMs from
at runtime. Only a `launch` edge from a cloudrun service reaches it; the caller gets the template self-link, zone and
instance-name prefix (never a URL); the worker reads resources through grants on its own SA; it gets no CI deploy
workflow; its subnet uses the IPAM fact. Negatives: single-service topologies hash and render exactly as before; an
http / pubsub edge to a worker, a worker without a launcher, a GKE launcher, a worker primary are rejected. Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import base64
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: put eval/.deps on PYTHONPATH; this file must not skip", pytrace=False)

from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.assembly import CUSTOM_TF  # noqa: E402
from developer_agent.platform_facts import PURPOSE_SUBNET, required_network_purposes  # noqa: E402
from developer_agent.topology_wiring import (  # noqa: E402
    render_event_worker_block,
    render_gce_worker_block,
    render_secondary_worker_block,
    topology_contract_rule,
    topology_env_vars,
    topology_network_purposes,
    workflow_services,
)
from shared import service_topology as st  # noqa: E402
from shared.diagnostics import AssemblyRecord  # noqa: E402


def svc(name, kind="cloudrun", **kw):
    return {"name": name, "kind": kind, **kw}


def topo(services, primary, edges=(), resources=()):
    return {"services": list(services), "primary_service": primary, "edges": list(edges), "resources": list(resources)}


def edge(a, b, protocol):
    return {"caller": a, "callee": b, "protocol": protocol}


W_NET = "infra/workload/network.tf"


def bucket(logical, *consumers):
    return {"type": "google_storage_bucket", "logical_name": logical,
            "consumers": [{"service": s, "env_key": k} for s, k in consumers]}


def validate(raw):
    return st.validate_service_topology(raw, product_id="batch")


def ok(raw):
    vt, diags = validate(raw)
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def errors(raw):
    vt, diags = validate(raw)
    assert vt is None
    return sorted(d.code for d in diags if d.severity == "error")


# Example 03: Cloud Run dispatcher launches an ephemeral Spot e2-micro worker; both use the input / output buckets.
EX03 = topo([svc("dispatcher"), svc("batch-worker", "gce-worker", vm={"machine_type": "e2-micro", "spot": True})],
            "dispatcher", [edge("dispatcher", "batch-worker", "launch")],
            [bucket("inputs", ("dispatcher", "INPUTS_BUCKET"), ("batch-worker", "INPUTS_BUCKET")),
             bucket("outputs", ("batch-worker", "OUTPUTS_BUCKET")),
             {"type": "google_pubsub_topic", "logical_name": "done",
              "consumers": [{"service": "batch-worker", "env_key": "DONE_TOPIC"}]}])
# Example 05: GKE primary, Cloud Run edge launches the worker (owner: 05 launches from the Cloud Run edge).
EX05 = topo([svc("fleet", "gke-autopilot"), svc("edge-api"), svc("gce-worker", "gce-worker")], "fleet",
            [edge("edge-api", "gce-worker", "launch")],
            [bucket("lake", ("gce-worker", "LAKE_BUCKET"), ("edge-api", "LAKE_BUCKET"))])


# ------------------------------------------------------------------------------------------------ model / validator
def test_gce_worker_is_a_secondary_only_kind_and_not_an_archetype():
    assert "gce-worker" in st.COMPUTE_KINDS and "gce-worker" not in st.ARCHETYPES
    cap = st.CAPABILITIES["gce-worker"]
    assert cap.callee_protocol == "launch" and not cap.allowed_as_primary and cap.allowed_as_secondary
    assert [k for k, c in st.CAPABILITIES.items() if c.can_launch] == ["cloudrun"]
    assert st.KIND_FOR_MODULE_DIR["compute-gce-worker"] == "gce-worker"


def test_example_03_launcher_gets_template_zone_prefix_never_a_url():
    vt = ok(EX03)
    assert vt.archetype == "cloudrun" and vt.names == ("dispatcher", "batch-worker")
    assert vt.env_for("dispatcher") == {
        "BATCH_WORKER_INSTANCE_TEMPLATE": "module.compute_batch_worker.instance_template_self_link",
        "BATCH_WORKER_NAME_PREFIX": "module.compute_batch_worker.instance_name_prefix",
        "BATCH_WORKER_ZONE": "module.compute_batch_worker.zone",
        "INPUTS_BUCKET": "google_storage_bucket.inputs.name",
    }
    every_value = [v for n in vt.names for v in vt.env_for(n).values()]
    assert not any("service_uri" in v or "url" in v.lower() for v in every_value)
    assert vt.env_for("batch-worker") == {"DONE_TOPIC": "google_pubsub_topic.done.name",
                                          "INPUTS_BUCKET": "google_storage_bucket.inputs.name",
                                          "OUTPUTS_BUCKET": "google_storage_bucket.outputs.name"}
    assert vt.worker_access("batch-worker") == {
        "pubsub_topics": ["google_pubsub_topic.done.name"],
        "storage_buckets": ["google_storage_bucket.inputs.name", "google_storage_bucket.outputs.name"]}
    assert vt.launchers("batch-worker") == ("dispatcher",)
    assert vt.http_entrypoint == "dispatcher"


def test_example_05_cloud_run_edge_launches_the_worker_of_a_gke_primary():
    vt = ok(EX05)
    assert vt.archetype == "gke-autopilot"
    assert vt.env_for("edge-api")["GCE_WORKER_INSTANCE_TEMPLATE"] == "module.compute_gce_worker.instance_template_self_link"


@pytest.mark.parametrize("protocol", ["http", "pubsub"])
def test_http_or_pubsub_edge_to_a_worker_is_rejected(protocol):
    raw = topo([svc("api"), svc("w", "gce-worker")], "api", [edge("api", "w", protocol)])
    assert errors(raw) == ["TOPOLOGY.EDGE_CALLEE_UNSUPPORTED", "TOPOLOGY.WORKER_NOT_LAUNCHED"]


def test_launch_edge_to_a_cloud_run_service_is_rejected():
    raw = topo([svc("api"), svc("core")], "api", [edge("api", "core", "launch")])
    assert errors(raw) == ["TOPOLOGY.EDGE_CALLEE_UNSUPPORTED"]


def test_worker_without_a_launcher_is_rejected():
    assert errors(topo([svc("api"), svc("w", "gce-worker")], "api")) == ["TOPOLOGY.WORKER_NOT_LAUNCHED"]


def test_gke_cannot_launch_a_worker():
    raw = topo([svc("fleet", "gke-autopilot"), svc("w", "gce-worker")], "fleet", [edge("fleet", "w", "launch")])
    assert errors(raw) == ["TOPOLOGY.LAUNCH_CALLER_UNSUPPORTED", "TOPOLOGY.WORKER_NOT_LAUNCHED"]


def test_worker_cannot_launch_a_worker():
    raw = topo([svc("api"), svc("a", "gce-worker"), svc("b", "gce-worker")], "api",
               [edge("api", "a", "launch"), edge("a", "b", "launch")])
    assert errors(raw) == ["TOPOLOGY.EDGE_CALLER_UNSUPPORTED", "TOPOLOGY.WORKER_NOT_LAUNCHED"]


def test_worker_as_primary_is_rejected():
    codes = errors(topo([svc("w", "gce-worker")], "w"))
    assert "TOPOLOGY.KIND_NOT_ALLOWED_AS_PRIMARY" in codes


def test_vm_shape_only_on_a_worker_and_machine_type_is_a_closed_grammar():
    assert errors(topo([svc("api", vm={"machine_type": "e2-micro"})], "api")) == ["TOPOLOGY.VM_SHAPE_NOT_ALLOWED"]
    bad = topo([svc("api"), svc("w", "gce-worker", vm={"machine_type": 'e2-micro"\n}'})], "api",
               [edge("api", "w", "launch")])
    assert errors(bad) == ["TOPOLOGY.SCHEMA_INVALID"]


def test_worker_consumer_of_a_resource_without_an_own_sa_grant_is_rejected():
    raw = topo([svc("api"), svc("w", "gce-worker")], "api", [edge("api", "w", "launch")],
               [{"type": "google_firestore_database", "logical_name": "db",
                 "consumers": [{"service": "w", "env_key": "DB_NAME"}]}])
    assert errors(raw) == ["TOPOLOGY.WORKER_RESOURCE_UNSUPPORTED"]


@pytest.mark.parametrize("callee_kind,protocol", [("cloudrun", "http"), ("event-worker", "pubsub")])
def test_rt_f1_a_worker_is_never_an_edge_caller(callee_kind, protocol):
    """RT F1: the worker SA holds no invoker / publisher grant, so a call from it could only 403."""
    raw = topo([svc("api"), svc("w", "gce-worker"), svc("svc2", callee_kind)], "api",
               [edge("api", "w", "launch"), edge("w", "svc2", protocol)])
    assert errors(raw) == ["TOPOLOGY.EDGE_CALLER_UNSUPPORTED"]


def test_rt_f1_a_launch_and_back_edge_is_refused_before_any_cycle():
    raw = topo([svc("api"), svc("w", "gce-worker")], "api", [edge("api", "w", "launch"), edge("w", "api", "http")])
    assert errors(raw) == ["TOPOLOGY.EDGE_CALLER_UNSUPPORTED"]


@pytest.mark.parametrize("a,b", [
    ("batch-transformer-worker-a", "batch-transformer-worker-b"),   # same first 25 chars -> same SA / network ids
    ("abcdefghijklmnopqrstuvwx-yz", "abcdefghijklmnopqrstuvwx-q"),   # 25th char '-' stripped: equal ids
    ("w", "w-x"),                                                   # nested launch-grant prefixes
])
def test_rt_f3_worker_name_collisions_are_rejected(a, b):
    raw = topo([svc("api"), svc(a, "gce-worker"), svc(b, "gce-worker")], "api",
               [edge("api", a, "launch"), edge("api", b, "launch")])
    assert errors(raw) == ["TOPOLOGY.WORKER_NAME_COLLISION"]


def test_rt_f3_distinct_worker_names_are_fine():
    raw = topo([svc("api"), svc("ingest", "gce-worker"), svc("render", "gce-worker"), svc("w", "gce-worker"),
                svc("wx", "gce-worker")], "api",
               [edge("api", n, "launch") for n in ("ingest", "render", "w", "wx")])
    ok(raw)
    assert st.worker_short_name("a" * 30) == "a" * 25 and st.worker_short_name("abc-" + "d" * 20 + "-z") == \
        "abc-" + "d" * 20


def test_topologies_without_a_vm_hash_exactly_as_before():
    """Do No Harm: these sha256 values were computed by the code before the gce-worker kind (69fe22d)."""
    t1 = topo([svc("shop")], "shop")
    t2 = topo([svc("api", scaling={"min_instances": 1, "max_instances": 3}), svc("ingest", "event-worker")], "api",
              [edge("api", "ingest", "pubsub")], [bucket("uploads", ("api", "UPLOADS_BUCKET"))])
    for t in (t1, t2):
        for s in t["services"]:
            s.pop("vm", None)
    assert ok(t1).sha256 == "b39950355d7a753bc4806b5c87b71fd9fb8f752c2bb96f433bd9eb63214be4d2"
    assert ok(t2).sha256 == "febbc6bd975a5e5699da8f7058b5f6e6e9b1d2a6de26c4896bf57e675c4db65a"
    assert '"vm"' not in st.canonical_topology_json(ok(t1).intent)
    vt3 = ok(EX03)
    rec = vt3.as_record()
    again, diags = st.topology_from_record(rec, product_id="batch")
    assert again is not None and again.sha256 == vt3.sha256, diags


def test_contract_text_names_the_launch_edge():
    text = st.render_topology_contract()
    assert "`gce-worker`: secondary only" in text and "callee of launch edges" in text
    assert "<BASE>_INSTANCE_TEMPLATE" in text


# ------------------------------------------------------------------------------------------------ developer wiring
def test_rendered_worker_block_parses_and_carries_only_validated_values():
    vt = ok(EX03)
    script = '#!/bin/bash\necho "}\nresource \\"x\\" \\"y\\" {}" ${var.project_id}\npoweroff\n'
    block = render_gce_worker_block(vt, "batch-worker", {"apps/batch-worker/startup.sh": script})
    body = hcl2.loads(block)["module"][0]["compute_batch_worker"]
    assert body["source"] == "../modules/compute-gce-worker"
    assert body["worker_name"] == "batch-worker"
    assert body["subnet_cidr"] == "${var.subnet_cidr}"
    assert body["machine_type"] == "e2-micro" and body["spot"] is True
    assert body["launcher_service_account_emails"] == ["${module.foundation.workload_sa_email}"]
    assert body["storage_buckets"] == ["${google_storage_bucket.inputs.name}", "${google_storage_bucket.outputs.name}"]
    assert body["pubsub_topics"] == ["${google_pubsub_topic.done.name}"]
    assert body["env_vars"] == {"DONE_TOPIC": "${google_pubsub_topic.done.name}",
                                "INPUTS_BUCKET": "${google_storage_bucket.inputs.name}",
                                "OUTPUTS_BUCKET": "${google_storage_bucket.outputs.name}"}
    assert "var.env_vars" not in block          # the services' user env map is not copied into VM metadata
    b64 = body["startup_script"][len('${base64decode("'):-len('")}')]
    assert base64.b64decode(b64).decode() == script            # repository text only as base64 (RT F2)
    assert "resource" not in block.replace("google_storage_bucket", "").replace("google_pubsub_topic", "")
    assert "service_uri" not in block and "_URL" not in block


def test_worker_without_script_or_shape_uses_module_defaults():
    vt = ok(EX05)
    body = hcl2.loads(render_gce_worker_block(vt, "gce-worker", {}))["module"][0]["compute_gce_worker"]
    assert "startup_script" not in body and "machine_type" not in body
    with pytest.raises(ValueError):
        render_gce_worker_block(vt, "edge-api")


def test_event_worker_dispatch_is_unchanged():
    raw = topo([svc("api"), svc("etl", "event-worker")], "api", [edge("api", "etl", "pubsub")])
    vt = ok(raw)
    assert render_secondary_worker_block(vt, "etl", {}) == render_event_worker_block(vt, "etl")


def _reconcile(files, vt):
    te.reconcile_multi_service_declarations(
        files=files, product_id="batch", spec_text="", archetype=vt.archetype, assembly_record=AssemblyRecord(),
        llm_iac_paths=[CUSTOM_TF], target_services=list(vt.names), topology=vt)
    return files


def test_hb04_renders_the_worker_once_and_is_idempotent():
    vt = ok(EX03)
    files = {CUSTOM_TF: 'resource "google_storage_bucket" "inputs" {\n  name = "in"\n  location = "US"\n}\n',
             "apps/dispatcher/main.py": "x = 1\n", "apps/batch-worker/startup.sh": "#!/bin/bash\npoweroff\n"}
    custom = files[CUSTOM_TF]
    _reconcile(files, vt)
    first = files[te.SERVICES_TF]   # TI-1: the topology secondaries are rendered into services.tf
    assert files[CUSTOM_TF] == custom
    mods = {k: v for m in hcl2.loads(first).get("module", []) for k, v in m.items()}
    assert set(mods) == {"compute_batch_worker"}
    assert not any(k.startswith("apps/batch-worker/") and k != "apps/batch-worker/startup.sh" for k in files)
    _reconcile(files, vt)
    assert files[te.SERVICES_TF] == first and files[CUSTOM_TF] == custom


def test_launcher_env_on_a_cloud_run_secondary():
    vt = ok(EX05)
    env = topology_env_vars(vt, "edge-api", "", {}, caller_service="edge-api")
    assert env["GCE_WORKER_ZONE"] == "module.compute_gce_worker.zone"


def test_no_deploy_workflow_for_a_worker_and_single_service_unchanged():
    assert workflow_services(ok(EX03)) == ["dispatcher"]
    assert workflow_services(ok(EX05)) == ["fleet", "edge-api"]
    single = ok(topo([svc("shop")], "shop"))
    assert workflow_services(single) == ["shop"]
    assert topology_contract_rule(single) == ""
    assert topology_network_purposes(single) == frozenset() and topology_network_purposes(None) == frozenset()


def test_worker_needs_the_workload_subnet_fact():
    vt = ok(EX03)
    assert topology_network_purposes(vt) == frozenset({PURPOSE_SUBNET})
    tree = {CUSTOM_TF: render_gce_worker_block(vt, "batch-worker", {})}
    assert required_network_purposes(tree) == frozenset({PURPOSE_SUBNET})


def test_contract_rule_tells_the_launcher_and_the_worker_their_keys():
    rule = topology_contract_rule(ok(EX03))
    assert "apps/batch-worker/startup.sh" in rule and "instances.insert" in rule
    assert "poll `instances.get`" in rule                     # RT F6: operation polling is denied
    assert "BATCH_WORKER_INSTANCE_TEMPLATE" in rule and "OUTPUTS_BUCKET" in rule


# ------------------------------------------------------------------------------------------------ golden module
def _hcl(path):
    with open(os.path.join(REPO_ROOT, path)) as f:
        return hcl2.loads(f.read())


def test_golden_module_has_no_running_vm_no_firewall_no_external_ip_and_a_conditional_launch_grant():
    main = _hcl("infra/modules/compute-gce-worker/main.tf")
    types = {t for r in main["resource"] for t in r}
    assert "google_compute_instance" not in types and "google_compute_firewall" not in types
    assert "google_compute_router_nat" not in types and "google_compute_router" not in types
    tmpl = next(r["google_compute_instance_template"]["worker"] for r in main["resource"]
                if "google_compute_instance_template" in r)
    assert "access_config" not in tmpl["network_interface"][0]
    subnet = next(r["google_compute_subnetwork"]["worker"] for r in main["resource"] if "google_compute_subnetwork" in r)
    assert subnet["private_ip_google_access"] is True and subnet["ip_cidr_range"] == "${var.subnet_cidr}"
    grant = next(r["google_project_iam_member"]["launcher_instance_admin"] for r in main["resource"]
                 if "launcher_instance_admin" in r.get("google_project_iam_member", {}))
    assert grant["role"] == "roles/compute.instanceAdmin.v1" and grant["condition"]
    act_as = next(r["google_service_account_iam_member"]["launcher_act_as"] for r in main["resource"]
                  if "google_service_account_iam_member" in r)
    assert act_as["role"] == "roles/iam.serviceAccountUser"
    assert act_as["service_account_id"] == "${google_service_account.worker.name}"   # the one worker SA


def test_golden_module_is_registered_in_payload_and_metadata():
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
    from shared.builtin_modules_provider import BUILTIN_MODULE_METADATA
    for f in ("main.tf", "outputs.tf", "variables.tf"):
        with open(os.path.join(REPO_ROOT, "infra/modules/compute-gce-worker", f)) as h:
            disk = h.read()
        assert BUILTIN_MODULE_FILES["compute-gce-worker"][f] == disk
        with open(os.path.join(REPO_ROOT, "apps/control-center/infra/modules/compute-gce-worker", f)) as h:
            assert h.read() == disk
    assert BUILTIN_MODULE_METADATA["compute-gce-worker"]["category"] == "COMPUTE"


# ------------------------------------------------------------------------------------------------ RT F2: zone
def test_rt_f2_default_zone_is_an_up_zone_of_the_region_and_the_condition_uses_it():
    with open(os.path.join(REPO_ROOT, "infra/modules/compute-gce-worker/main.tf")) as f:
        text = f.read()
    main = hcl2.loads(text)
    zones = next(d["google_compute_zones"]["available"] for d in main["data"] if "google_compute_zones" in d)
    assert zones["status"] == "UP" and zones["region"] == "${var.region}"
    local_zone = next(lc["zone"] for lc in main["locals"] if "zone" in lc)
    assert "data.google_compute_zones.available.names[0]" in local_zone and "-a" not in local_zone
    assert '"${var.region}-a"' not in text
    assert "zones/${local.zone}/instances/" in text and "zones/${local.zone}/disks/" in text


# ------------------------------------------------------------------------------------------------ L10-u2: network
AI_SUBNET = ('resource "google_compute_subnetwork" "app" {\n  name = "app"\n  region = var.region\n'
             '  network = "x"\n  ip_cidr_range = var.subnet_cidr\n}\n')
AI_VPC_MODULE = ('module "net" {\n  source = "../modules/networking-vpc"\n  project_id = var.project_id\n'
                 '  primary_subnet_cidr = var.subnet_cidr\n}\n')


def test_l10u2_joins_the_workloads_subnet_resource():
    from developer_agent.topology_wiring import workload_subnetwork_ref
    files = {CUSTOM_TF: AI_SUBNET}
    assert workload_subnetwork_ref(files) == "google_compute_subnetwork.app.id"
    body = hcl2.loads(render_gce_worker_block(ok(EX03), "batch-worker", files))["module"][0]["compute_batch_worker"]
    assert body["use_existing_subnetwork"] is True
    assert body["subnetwork_id"] == "${google_compute_subnetwork.app.id}"
    assert "subnet_cidr" not in body


def test_l10u2_joins_the_networking_vpc_module_output():
    from developer_agent.topology_wiring import workload_subnetwork_ref
    assert workload_subnetwork_ref({W_NET: AI_VPC_MODULE}) == "module.net.primary_subnetwork_id"
    # exact var.subnet_cidr wins over a derived range; then file / address order
    derived = AI_SUBNET.replace("var.subnet_cidr", "cidrsubnet(var.subnet_cidr, 1, 0)").replace('"app"', '"aaa"')
    assert workload_subnetwork_ref({CUSTOM_TF: derived, W_NET: AI_VPC_MODULE}) == "module.net.primary_subnetwork_id"
    assert workload_subnetwork_ref({CUSTOM_TF: derived}) == "google_compute_subnetwork.aaa.id"


def test_l10u2_own_vpc_only_without_a_workload_network_and_worker_blocks_never_count():
    from developer_agent.topology_wiring import workload_subnetwork_ref
    vt = ok(EX03)
    assert workload_subnetwork_ref({}) is None
    own = render_gce_worker_block(vt, "batch-worker", {})
    assert workload_subnetwork_ref({CUSTOM_TF: own}) is None      # idempotent: its own block is not a network
    assert workload_subnetwork_ref({"infra/modules/networking-vpc/main.tf": AI_SUBNET}) is None   # not root
    body = hcl2.loads(own)["module"][0]["compute_batch_worker"]
    assert body["subnet_cidr"] == "${var.subnet_cidr}" and "use_existing_subnetwork" not in body


def test_l10u2_module_creates_no_network_when_joining():
    main = _hcl("infra/modules/compute-gce-worker/main.tf")
    for t in ("google_compute_network", "google_compute_subnetwork"):
        blk = next(r[t]["worker"] for r in main["resource"] if t in r)
        assert blk["count"] == "${local.own_network}"
    local = {k: v for lc in main["locals"] for k, v in lc.items()}
    assert local["own_network"] == "${var.use_existing_subnetwork ? 0 : 1}"


# ------------------------------------------------------------------------------------------------ RT F7: script
def _ctx(files):
    from developer_agent.validators import ValidationContext
    return ValidationContext.build(files, ownership=lambda p: None)


def test_rt_f7_missing_or_blank_worker_script_is_a_blocking_typed_finding():
    from developer_agent.repair_loop import CREATE_FILE_CODES
    from developer_agent.validators.topology import WORKER_SCRIPT_CODE, WorkerScriptValidator
    v = WorkerScriptValidator(ok(EX03))
    for files in ({}, {"apps/batch-worker/startup.sh": " \n\t\n"}):
        (d,) = v.validate(_ctx(files))
        assert (d.code, d.file, d.severity) == (WORKER_SCRIPT_CODE, "apps/batch-worker/startup.sh", "error")
    assert v.validate(_ctx({"apps/batch-worker/startup.sh": "#!/bin/bash\npoweroff\n"})) == []
    assert WORKER_SCRIPT_CODE in CREATE_FILE_CODES


def test_rt_f7_registered_only_for_a_topology_with_a_worker():
    from developer_agent.validators.step1 import build_step1_stack
    with_worker = build_step1_stack(validate_client=None, verifier_factory=None, topology=ok(EX03))
    single = build_step1_stack(validate_client=None, verifier_factory=None, topology=ok(topo([svc("shop")], "shop")))
    assert with_worker.mode_of("V-T6") == "blocking"
    assert "V-T6" not in single.ids and with_worker.ids == single.ids + ["V-T6"]
