"""Lane 10 (FD-51) stage 3: the developer renders inter-service wiring from the typed topology.

FD-40 (mutual service_uri cycle), FD-41 (shared-noun misrouting), FD-42 (service_uri on GKE), FD-43 (env key from an
interpolated name), FD-45 (alias substring), FD-4AC (service set from app dirs / LLM labels) on the topology path;
hybrid example 05 (owner Q-B) through per-service kinds; RT F1 existing-compute detection (any label, nested
bundles, Express, .tf.json); the hand-off on the existing compute-intent record (v2) with sha drift and brownfield
guards before any LLM call; the HB-05 seam (`include_siblings`) in both copies (terraform_engine + verifier twin);
V-T3 (compute declared by the LLM). Every legacy path keeps its behavior (negative tests). Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import json
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

try:
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt or put eval/.deps on "
                "PYTHONPATH; this file is acceptance evidence and must not skip", pytrace=False)

from developer_agent import compute_intent as ci  # noqa: E402
from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.assembly import CUSTOM_TF, bespoke_root_text  # noqa: E402
from developer_agent.topology_wiring import render_event_worker_block, topology_env_vars  # noqa: E402
from shared.diagnostics import AssemblyRecord, ErrorClass  # noqa: E402
from shared.service_topology import (  # noqa: E402
    TOPOLOGY_JSON_PATH,
    render_topology_json,
    topology_owned_tree,
    validate_service_topology,
)

W = "infra/workload/"
MAIN_TF = W + "main.tf"
SERVICES_TF = te.SERVICES_TF   # TI-1: topology secondaries are rendered here


def vt_of(raw, pid="shop"):
    vt, diags = validate_service_topology(raw, product_id=pid)
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def record_of(raw, pid="shop"):
    vt = vt_of(raw, pid)
    return {"schema": "architect_compute_intent/v2", "target_compute_services": list(vt.names),
            "bundle_id": None, "compute_archetype": vt.archetype, "service_topology": vt.as_record()}


def topo(services, primary, edges=(), resources=()):
    return {"services": [{"name": n, "kind": k} for n, k in services], "primary_service": primary,
            "edges": [{"caller": a, "callee": b, "protocol": p} for a, b, p in edges], "resources": list(resources)}


def modules_of(text):
    """{label: body} of the module blocks of one HCL file (exact parse)."""
    out = {}
    for m in hcl2.loads(text).get("module", []):
        out.update(m)
    return out


def _main(pid, archetype="cloudrun", **kw):
    return te.generate_golden_main_tf(pid, archetype, "", service_name=kw.pop("service_name", pid), **kw)


# ------------------------------------------------------------------------------------------------ RT F1 detection
def test_f1_existing_compute_found_for_any_label_root_and_tf_json():
    files = {
        MAIN_TF: 'module "compute" {\n  source = "../modules/compute-cloudrun"\n  service_name = var.product_id\n}\n',
        CUSTOM_TF: ('module "compute_admin" {\n  source = "../modules/compute-cloudrun"\n  service_name = "admin"\n}\n'
                    'module "lookalike" {\n  source = "../other/compute-cloudrun"\n}\n'
                    'module "etl_worker" {\n  source = "./../modules/compute-event-worker"\n}\n'),
        W + "extra.tf.json": json.dumps({"module": {"compute_jobs": {"source": "../modules/compute-cloudrun",
                                                                     "service_name": "jobs"}}}),
    }
    entries, unparsed = ci.existing_compute_entries(files)
    got = {(e.address, e.kind, e.root, e.service_name) for e in entries}
    assert got == {("module.compute", "cloudrun", True, "${product_id}"),
                   ("module.compute_admin", "cloudrun", True, "admin"),
                   ("module.etl_worker", "event-worker", True, None),
                   ("module.compute_jobs", "cloudrun", True, "jobs")}
    assert unparsed == []


def test_f1_unparseable_workload_file_is_reported_never_guessed():
    entries, unparsed = ci.existing_compute_entries({MAIN_TF: 'module "compute" {\n  source = \n'})
    assert entries == [] and unparsed == [MAIN_TF]


BUNDLE_IDS = ("secure-three-tier-web", "event-driven-microservice", "vertex-ai-rag-stack",
              "private-gke-microservices", "serverless-analytics-lakehouse")


@pytest.mark.parametrize("bundle_id", BUNDLE_IDS)
def test_t12b_every_builtin_bundle_compute_is_found_nested_and_guarded(bundle_id):
    files = {MAIN_TF: 'module "foundation" {\n  source = "../modules/workload-foundation/base"\n}\n'}
    assert te.vendor_composite_bundle(files, bundle_id)
    label = bundle_id.replace("-", "_")
    files[CUSTOM_TF] = f'module "{label}" {{\n  source = "../bundles/{bundle_id}"\n}}\n'
    expected = set()
    for path, text in files.items():
        if path.startswith(f"infra/bundles/{bundle_id}/") and path.endswith(".tf"):
            for m in hcl2.loads(text).get("module", []):
                for lbl, body in m.items():
                    src = body.get("source", "")
                    if src.split("/")[-1] in ci.MODULE_DIR_ARCHETYPE and src.startswith("../../modules/"):
                        expected.add(f"module.{label}.module.{lbl}")
    entries, unparsed = ci.existing_compute_entries(files)
    assert unparsed == []
    assert {e.address for e in entries} == expected
    assert all(not e.root for e in entries)
    if expected:   # nested compute cannot be pinned by the topology renderer: guarded, never re-addressed
        vt, diags = validate_service_topology(topo([("shop", "cloudrun")], "shop"), product_id="shop",
                                              existing=entries, source="precommit")
        assert vt is None and {d.code for d in diags} == {"TOPOLOGY.LEGACY_SHAPE_UNSUPPORTED"}
        assert all(d.error_class == ErrorClass.BROWNFIELD_CONFLICT for d in diags)


def test_t12b_express_output_is_detected_and_guarded():
    from shared.express_synthesizer import ExpressHCLSynthesizer
    files = ExpressHCLSynthesizer().synthesize_workload(
        product_id="xp", project_id="p-1", module_instances=[
            {"module_id": "compute-cloudrun", "instance_name": "gateway", "parameters": {}},
            {"module_id": "compute-event-worker", "instance_name": "jobs", "parameters": {}}])
    entries, unparsed = ci.existing_compute_entries(files)
    by = {e.label: e for e in entries}
    assert unparsed == [] and set(by) == {"compute_gateway", "worker_jobs"}
    assert by["compute_gateway"].service_name is None and "${var.product_id}-gateway" in by["compute_gateway"].service_name_expr
    vt, diags = validate_service_topology(topo([("gateway", "cloudrun")], "gateway"), product_id="xp",
                                          existing=entries, source="precommit")
    assert vt is None
    assert {d.code for d in diags} >= {"TOPOLOGY.LEGACY_SHAPE_UNSUPPORTED"}


# ------------------------------------------------------------------------------------------------ hand-off (v2 record)
def test_v2_record_decides_archetype_services_and_kinds():
    rec = record_of(topo([("stream-processor", "gke-autopilot"), ("edge-gateway", "cloudrun")], "stream-processor"))
    intent = ci.resolve_compute_intent("test-05-omni-fleet", rec, {})
    assert intent.archetype == "gke-autopilot" and intent.service_names == ("stream-processor", "edge-gateway")
    assert intent.kind_of("edge-gateway") == "cloudrun" and intent.kind_of("stream-processor") == "gke-autopilot"
    assert intent.source == "architect.service_topology" and intent.topology is not None
    assert intent.as_record()["topology_sha256"] == rec["service_topology"]["sha256"]
    assert intent.as_record()["http_entrypoint"] == "edge-gateway"


def test_v2_record_sha_drift_is_a_platform_defect():
    rec = record_of(topo([("shop", "cloudrun")], "shop"))
    rec["service_topology"]["intent"]["services"][0]["name"] = "other"
    rec["service_topology"]["intent"]["primary_service"] = "other"
    with pytest.raises(ci.TopologyGuardError) as ei:
        ci.resolve_compute_intent("shop", rec, {})
    assert [d.code for d in ei.value.diagnostics] == ["TOPOLOGY.RECORD_SHA_MISMATCH"]
    assert ei.value.diagnostics[0].error_class == ErrorClass.PLATFORM_DEFECT


def test_v2_record_brownfield_removal_is_refused_before_any_llm_call():
    existing = {MAIN_TF: 'module "compute" {\n  source = "../modules/compute-cloudrun"\n  service_name = "shop"\n}\n',
                CUSTOM_TF: 'module "compute_admin" {\n  source = "../modules/compute-cloudrun"\n  service_name = "admin"\n}\n'}
    with pytest.raises(ci.TopologyGuardError) as ei:
        ci.resolve_compute_intent("shop", record_of(topo([("shop", "cloudrun")], "shop")), existing)
    codes = [d.code for d in ei.value.diagnostics if d.severity == "error"]
    assert codes == ["TOPOLOGY.COMPUTE_REMOVED"]
    assert "module.compute_admin=cloudrun:admin" in ei.value.diagnostics[0].hint


def test_v2_record_brownfield_same_shape_passes_with_var_product_id():
    existing = {MAIN_TF: 'module "compute" {\n  source = "../modules/compute-cloudrun"\n  service_name = var.product_id\n}\n',
                CUSTOM_TF: 'module "compute_admin" {\n  source = "../modules/compute-cloudrun"\n  service_name = "admin"\n}\n'}
    intent = ci.resolve_compute_intent("shop", record_of(topo([("shop", "cloudrun"), ("admin", "cloudrun")], "shop")),
                                       existing)
    assert intent.service_names == ("shop", "admin")


def test_v2_record_explicit_request_list_conflict_is_typed():
    with pytest.raises(ci.TopologyGuardError) as ei:
        ci.resolve_compute_intent("shop", record_of(topo([("shop", "cloudrun")], "shop")), {}, ["other"])
    assert [d.code for d in ei.value.diagnostics] == ["TOPOLOGY.REQUEST_LIST_CONFLICT"]


def test_do_no_harm_v1_records_resolve_exactly_as_before():
    """Records without a topology (written before lane 10, e.g. a RESUME of an older execution) keep the FH path."""
    rec = {"schema": "architect_compute_intent/v1", "target_compute_services": ["a", "b"],
           "bundle_id": "private-gke-microservices", "compute_archetype": None}
    intent = ci.resolve_compute_intent("p", rec, {})
    assert (intent.archetype, intent.service_names, intent.topology) == ("gke-autopilot", ("a", "b"), None)
    assert "topology_sha256" not in intent.as_record()


def test_developer_turns_a_topology_guard_into_a_typed_stage_error_before_any_llm_call():
    from developer_agent.handler import DeveloperAgent
    from shared.diagnostics import StageError
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        dev = DeveloperAgent(project_id="")
    dev.genai_client = MagicMock()
    existing = {MAIN_TF: 'module "compute" {\n  source = "../modules/compute-cloudrun"\n  service_name = "shop"\n}\n'}
    rec = record_of(topo([("shop", "event-worker")], "shop"))
    with patch.object(dev, "fetch_existing_repo_files", return_value=existing):
        with pytest.raises(StageError) as ei:
            dev.generate_code_files(product_id="shop", spec_text="x", task_dag=[{"task_id": "T"}], trace_id="t-g",
                                    architect_compute_intent=rec, allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)
    assert ei.value.report.error_class == ErrorClass.BROWNFIELD_CONFLICT
    assert [d.code for d in ei.value.report.diagnostics] == ["TOPOLOGY.KIND_CHANGED"]
    dev.genai_client.models.generate_content.assert_not_called()


# ------------------------------------------------------------------------------------------------ HB-04 / HB-05 seam
def _reconcile(files, vt, pid="shop", archetype=None, spec=""):
    te.reconcile_multi_service_declarations(
        files=files, product_id=pid, spec_text=spec, archetype=archetype or vt.archetype,
        assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF], target_services=list(vt.names), topology=vt)
    return files


def _acyclic_module_graph(files):
    """label -> compute labels its parsed body references (`module.<label>.`); raises CycleError on a cycle."""
    import graphlib
    mods = {}
    for path in (MAIN_TF, CUSTOM_TF, SERVICES_TF):
        mods.update(modules_of(files.get(path, "") or "\n"))
    deps = {lbl: {o for o in mods if o != lbl and f"module.{o}." in json.dumps(body)} for lbl, body in mods.items()}
    graphlib.TopologicalSorter(deps).prepare()
    return deps


def test_t1_chain_secondaries_get_only_their_edges_and_the_graph_is_acyclic():
    vt = vt_of(topo([("api", "cloudrun"), ("core", "cloudrun"), ("store", "cloudrun")], "api",
                    [("api", "core", "http"), ("core", "store", "http")]))
    files = {CUSTOM_TF: "", "apps/api/main.py": "x = 1\n", "apps/core/main.py": "x = 1\n",
             "apps/store/main.py": "x = 1\n"}
    _reconcile(files, vt)
    mods = modules_of(files[SERVICES_TF])
    assert set(mods) == {"compute_core", "compute_store"}
    assert "module.compute_store.service_uri" in json.dumps(mods["compute_core"]["env_vars"])
    assert "module.compute" not in json.dumps(mods["compute_store"]["env_vars"])
    from developer_agent.handler import DeveloperAgent
    env, _ = DeveloperAgent._topology_primary_overrides(vt, bespoke_root_text(files), files)
    assert set(k for k in env if k.endswith(("_URL", "_AUDIENCE"))) == {"CORE_URL", "CORE_AUDIENCE"}
    files[MAIN_TF] = _main("shop", service_name="api", env_vars_override=env)
    deps = _acyclic_module_graph(files)
    assert deps["compute"] - {"foundation"} == {"compute_core"}
    assert deps["compute_core"] - {"foundation"} == {"compute_store"}
    assert deps["compute_store"] - {"foundation"} == set()


def test_fd40_mutual_reads_never_produce_a_cycle_on_the_topology_path():
    """Both apps read each other's URL; the topology has one edge: only that edge is wired (no A->B->A)."""
    vt = vt_of(topo([("gateway", "cloudrun"), ("core", "cloudrun"), ("audit", "cloudrun")], "gateway",
                    [("gateway", "core", "http")]))
    code = 'import os\nA = os.environ["GATEWAY_URL"]\nB = os.environ["AUDIT_URL"]\n'
    files = {CUSTOM_TF: "", "apps/gateway/main.py": 'import os\nC = os.environ["CORE_URL"]\n',
             "apps/core/main.py": code, "apps/audit/main.py": code}
    _reconcile(files, vt)
    mods = modules_of(files[SERVICES_TF])
    assert "service_uri" not in json.dumps(mods["compute_core"].get("env_vars", ""))
    assert "service_uri" not in json.dumps(mods["compute_audit"].get("env_vars", ""))
    # contrast: the legacy HB-05 wires every sibling (the FD-40 / FD-45 behavior this path removes)
    legacy = te.extract_custom_resource_env_vars(bespoke_root_text(files), files, caller_service="core")
    assert "AUDIT_URL" in legacy


def test_fd41_fd45_shared_noun_and_alias_keys_are_not_bound():
    vt = vt_of(topo([("web", "cloudrun"), ("order-api", "cloudrun"), ("order-worker", "cloudrun")], "web",
                    [("web", "order-api", "http")]))
    files = {CUSTOM_TF: "", "apps/web/main.py": ('import os\nA = os.getenv("BACKEND_URL")\n'
                                                 'B = os.getenv("ORDER_WORKER_URL")\nC = os.getenv("ORDER_URL")\n'),
             "apps/order-api/main.py": "x = 1\n", "apps/order-worker/main.py": "x = 1\n"}
    _reconcile(files, vt)
    env = topology_env_vars(vt, "web", files[CUSTOM_TF], files, caller_service=None)
    uri_keys = {k for k, v in env.items() if "service_uri" in v}
    assert uri_keys == {"ORDER_API_URL", "ORDER_API_AUDIENCE"}
    assert env["ORDER_API_URL"] == "module.compute_order_api.service_uri"


def test_fd42_gke_primary_hybrid_05_gets_its_cloud_run_edge_and_no_service_uri_on_gke():
    vt = vt_of(topo([("stream-processor", "gke-autopilot"), ("edge-gateway", "cloudrun")], "stream-processor"))
    files = {MAIN_TF: 'module "compute" {\n  source = "../modules/compute-gke-autopilot"\n}\n', CUSTOM_TF: "",
             "apps/stream-processor/main.py": "x = 1\n", "apps/edge-gateway/main.py": "x = 1\n"}
    _reconcile(files, vt, pid="test-05-omni-fleet")
    mods = modules_of(files[SERVICES_TF])
    assert set(mods) == {"compute_edge_gateway"}
    assert "module.compute." not in files[SERVICES_TF] and files[CUSTOM_TF] == ""
    # FD-55 W4: the HB-06 coverage sweep is deleted (no phantom public stream-processor service can be added)
    from developer_agent import preflight_validator as pv
    assert not hasattr(pv, "sanitize_multiservice_compute_coverage")


def test_fd4ac_unplanned_app_dirs_and_llm_labels_add_no_services():
    vt = vt_of(topo([("shop", "cloudrun"), ("admin", "cloudrun")], "shop"))
    llm = ('module "compute_service_must" {\n  source = "../modules/compute-cloudrun"\n  service_name = "service-must"\n}\n')
    files = {CUSTOM_TF: llm, "apps/admin/main.py": "x = 1\n", "apps/stripe/main.py": "x = 1\n"}
    _reconcile(files, vt)
    mods = {**modules_of(files[CUSTOM_TF]), **modules_of(files[SERVICES_TF])}
    assert set(modules_of(files[SERVICES_TF])) == {"compute_admin"}                # TI-1
    assert set(mods) == {"compute_service_must", "compute_admin"}   # the LLM's block stays (V-T3 flags it)
    assert mods["compute_service_must"] == modules_of(llm)["compute_service_must"]   # never re-synthesized
    assert not any(k.startswith(("apps/service-must/", "apps/stripe/Procfile")) for k in files)
    assert "compute_stripe" not in mods
    legacy = {CUSTOM_TF: llm, "apps/admin/main.py": "x = 1\n", "apps/stripe/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(files=legacy, product_id="shop", spec_text="", archetype="cloudrun",
                                            assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF],
                                            target_services=["shop", "admin"])
    assert "compute_stripe" in modules_of(legacy[CUSTOM_TF])                # contrast: today's union


def test_rt_f3_event_worker_secondary_is_rendered_and_wired_by_pubsub_edge():
    vt = vt_of(topo([("api", "cloudrun"), ("etl-worker", "event-worker")], "api", [("api", "etl-worker", "pubsub")]))
    files = {CUSTOM_TF: "", "apps/api/main.py": "x = 1\n", "apps/etl-worker/main.py": "x = 1\n"}
    _reconcile(files, vt)
    mods = modules_of(files[SERVICES_TF])
    assert set(mods) == {"compute_etl_worker"}
    assert mods["compute_etl_worker"]["source"] == "../modules/compute-event-worker"
    assert "service_name" not in mods["compute_etl_worker"] and "env_vars" not in mods["compute_etl_worker"]
    env = topology_env_vars(vt, "api", files[CUSTOM_TF], files, caller_service=None)
    assert env["ETL_WORKER_TOPIC"] == "module.compute_etl_worker.topic_name"
    with pytest.raises(ValueError):
        render_event_worker_block(vt, "api")


def test_topology_scaling_is_used_when_stated():
    raw = topo([("api", "cloudrun"), ("core", "cloudrun")], "api")
    raw["services"][1]["scaling"] = {"min_instances": 2, "max_instances": 7, "cpu_always_allocated": True}
    vt = vt_of(raw)
    files = _reconcile({CUSTOM_TF: "", "apps/core/main.py": "x = 1\n"}, vt)
    core = modules_of(files[SERVICES_TF])["compute_core"]
    assert (core["min_instances"], core["max_instances"], core["cpu_idle"]) == (2, 7, False)


def test_t14_single_service_topology_main_tf_is_byte_identical_to_the_legacy_render():
    """Do No Harm: one Cloud Run service, no edges -> the primary env equals HB-05's (no siblings exist)."""
    vt = vt_of(topo([("shop", "cloudrun")], "shop"))
    custom = 'resource "google_storage_bucket" "uploads" {\n  name = "u"\n}\n'
    files = {CUSTOM_TF: custom, "apps/shop/main.py": 'import os\nB = os.getenv("BUCKET_NAME")\n'}
    from developer_agent.handler import DeveloperAgent
    env, scaling = DeveloperAgent._topology_primary_overrides(vt, custom, files)
    assert scaling is None
    topo_main = _main("shop", custom_tf_content=custom, app_files=files, env_vars_override=env)
    legacy_main = _main("shop", custom_tf_content=custom, app_files=files)
    assert topo_main == legacy_main


def test_hb05_seam_default_is_unchanged_and_false_drops_only_siblings():
    custom = ('resource "google_storage_bucket" "b" {\n  name = "b"\n}\n'
              'module "compute_core" {\n  source = "../modules/compute-cloudrun"\n  service_name = "core"\n}\n')
    files = {"apps/api/main.py": 'import os\nX = os.getenv("CORE_URL")\n'}
    full = te.extract_custom_resource_env_vars(custom, files)
    assert te.extract_custom_resource_env_vars(custom, files, include_siblings=True) == full
    no_sib = te.extract_custom_resource_env_vars(custom, files, include_siblings=False)
    assert {k: v for k, v in full.items() if "service_uri" not in v} == no_sib
    assert any("service_uri" in v for v in full.values())


# ------------------------------------------------------------------------------------------------ verifier twin
def _three_service_tree():
    vt = vt_of(topo([("api", "cloudrun"), ("core", "cloudrun"), ("store", "cloudrun")], "api",
                    [("api", "core", "http")]))
    files = {CUSTOM_TF: "", "apps/api/main.py": "x = 1\n", "apps/core/main.py": "x = 1\n",
             "apps/store/main.py": "x = 1\n"}
    _reconcile(files, vt)
    from developer_agent.handler import DeveloperAgent
    env, _ = DeveloperAgent._topology_primary_overrides(vt, bespoke_root_text(files), files)
    files[MAIN_TF] = _main("shop", service_name="api", custom_tf_content=bespoke_root_text(files), app_files=files,
                           env_vars_override=env)
    return vt, files


def test_verifier_twin_never_re_adds_sibling_urls_on_a_topology_tree():
    from gatekeeper_agent.verifier import SynthesisVerifierAgent
    vt, files = _three_service_tree()
    # lane10-main merge: the primary's code reads STORE_URL exactly (undeclared edge), so S2-D's exact-read twin
    # would bind it on the legacy path; the topology path must still not.
    files["apps/api/main.py"] = 'import os\nX = os.environ["STORE_URL"]\n'
    files[TOPOLOGY_JSON_PATH] = render_topology_json(vt)
    cured = SynthesisVerifierAgent(product_id="shop").reconcile_iac_environment_contracts(dict(files))
    assert cured == files                                         # GK-5: re-curing committed bytes is a no-op
    # contrast: without the topology file the twin injects STORE_URL into main.tf (S2-D exact-read behavior)
    legacy = dict(files)
    legacy.pop(TOPOLOGY_JSON_PATH)
    legacy[CUSTOM_TF] = legacy.pop(SERVICES_TF)   # the legacy path keeps its secondaries in custom.tf (TI-1)
    cured_legacy = SynthesisVerifierAgent(product_id="shop").reconcile_iac_environment_contracts(legacy)
    assert "STORE_URL" in cured_legacy[MAIN_TF] and "STORE_URL" not in files[MAIN_TF]


def test_topology_owned_tree_requires_a_valid_untampered_record():
    vt, files = _three_service_tree()
    assert not topology_owned_tree(files)
    files[TOPOLOGY_JSON_PATH] = render_topology_json(vt)
    assert topology_owned_tree(files)
    rec = json.loads(files[TOPOLOGY_JSON_PATH])
    rec["intent"]["edges"] = []
    assert not topology_owned_tree({**files, TOPOLOGY_JSON_PATH: json.dumps(rec)})
    assert not topology_owned_tree({**files, TOPOLOGY_JSON_PATH: "{not json"})
    assert not topology_owned_tree({**files, TOPOLOGY_JSON_PATH: json.dumps({"schema": "x"})})


# ------------------------------------------------------------------------------------------------ V-T3
def test_vt3_flags_llm_compute_only_on_the_topology_path():
    from developer_agent.validators.base import ValidationContext, ValidatorStack
    from developer_agent.validators.topology import LlmComputeValidator, register
    from shared.artifact_ownership import Ownership
    vt = vt_of(topo([("shop", "cloudrun"), ("core", "cloudrun")], "shop"))
    custom = ('module "compute_core" {\n  source = "../modules/compute-cloudrun"\n}\n'
              'module "compute_service_must" {\n  source = "../modules/compute-cloudrun"\n}\n'
              'module "network" {\n  source = "../modules/networking-vpc"\n}\n'
              'resource "google_container_cluster" "extra" {\n  name = "x"\n}\n'
              'resource "google_storage_bucket" "b" {\n  name = "b"\n}\n')
    ctx = ValidationContext.build({CUSTOM_TF: custom}, ownership=lambda p: Ownership.LLM_AUTHORED,
                                  extras={"platform_addresses": ()})
    found = LlmComputeValidator(vt).validate(ctx)
    assert sorted(d.block_address for d in found) == ["google_container_cluster.extra", "module.compute_service_must"]
    assert all(d.code == "TOPOLOGY.COMPUTE_DECLARED_BY_LLM" and d.error_class == ErrorClass.CODE_DEFECT
               for d in found)
    clean = ValidationContext.build({CUSTOM_TF: 'module "compute_core" {\n  source = "../modules/compute-cloudrun"\n}\n'},
                                    ownership=lambda p: Ownership.LLM_AUTHORED, extras={"platform_addresses": ()})
    assert LlmComputeValidator(vt).validate(clean) == []
    stack = ValidatorStack()
    register(stack, None)
    assert stack.ids == []


# ------------------------------------------------------------------------------------------------ end to end
def test_generate_code_files_end_to_end_two_services_one_edge():
    from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
    from developer_agent.handler import DeveloperAgent
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        dev = DeveloperAgent(project_id="")
    canned = canned_workload_files("public-gateway", extra=canned_workload_files("internal-core"))
    canned["apps/stripe/main.py"] = "x = 1\n"                     # an app dir the architect never planned
    dev.genai_client = FakeGenaiClient(files=canned)
    rec = record_of(topo([("public-gateway", "cloudrun"), ("internal-core", "cloudrun")], "public-gateway",
                         [("public-gateway", "internal-core", "http")]), pid="test-02-multi-cloudrun-mesh")
    no_project = {"PROJECT_ID": "", "GCP_PROJECT": "", "GOOGLE_CLOUD_PROJECT": ""}
    with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false", **no_project}), \
            patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no firestore in tests"))), \
            patch.object(dev, "fetch_existing_repo_files", return_value={}):
        files = dev.generate_code_files(product_id="test-02-multi-cloudrun-mesh", spec_text="Service A and B must",
                                        task_dag=[], architect_compute_intent=rec, allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)
    mods = modules_of(files.get(SERVICES_TF, "") or "\n")
    assert {m for m in mods if m.startswith("compute")} == {"compute_internal_core"}
    assert not any(m.startswith("compute") for m in modules_of(files.get(CUSTOM_TF, "") or "\n"))   # TI-1
    main = files[MAIN_TF]
    assert 'service_name          = "public-gateway"' in main
    assert "module.compute_internal_core.service_uri" in main
    assert "module.compute.service_uri" not in files.get(CUSTOM_TF, "")
    assert topology_owned_tree(files)
    assert json.loads(files[TOPOLOGY_JSON_PATH])["sha256"] == rec["service_topology"]["sha256"]
    assert dev.last_compute_intent["service_kinds"] == {"public-gateway": "cloudrun", "internal-core": "cloudrun"}
    # RT F2: CI deploys exactly the planned services; the unplanned apps/stripe gets no workflow
    workflows = sorted(k for k in files if k.startswith(".github/workflows/deploy-"))
    assert workflows == [".github/workflows/deploy-internal-core.yml", ".github/workflows/deploy-public-gateway.yml"]


def test_gateway_records_the_committed_topology_as_architect_context(monkeypatch):
    from fd4f_support import FakeDB, load_gateway
    gw = load_gateway(monkeypatch)
    db = FakeDB()
    monkeypatch.setattr(gw, "db", db)
    vt = vt_of(topo([("shop", "cloudrun")], "shop"))
    gw._record_topology_context("t-1", "shop", {TOPOLOGY_JSON_PATH: render_topology_json(vt)},
                                {"branch_name": "b", "commit_sha": "c0ffee"})
    st = db.docs["workloads/shop"]["service_topology"]
    assert st["trace_id"] == "t-1" and st["status"] == "PR_OPENED" and st["record"]["sha256"] == vt.sha256
    db2 = FakeDB()
    monkeypatch.setattr(gw, "db", db2)
    bad = json.loads(render_topology_json(vt))
    bad["sha256"] = "0" * 64
    gw._record_topology_context("t-2", "shop", {TOPOLOGY_JSON_PATH: json.dumps(bad)}, {})
    gw._record_topology_context("t-3", "shop", {}, {})                  # legacy run: nothing recorded
    assert db2.writes == []


def test_resume_copy_of_a_v2_record_resolves_identically():
    """FH-7's CC copy (`dict(record, copied_from_trace=prev)`) carries the topology unchanged: same typed intent."""
    rec = record_of(topo([("api", "cloudrun"), ("core", "cloudrun")], "api", [("api", "core", "http")]))
    copied = dict(rec, copied_from_trace="prev-trace")
    a = ci.resolve_compute_intent("shop", rec, {})
    b = ci.resolve_compute_intent("shop", copied, {})
    assert a.as_record() == b.as_record() and b.topology.sha256 == rec["service_topology"]["sha256"]


# ------------------------------------------------------------------------------------------------ prompt contract
def test_topology_contract_lists_services_dirs_and_exact_env_keys():
    from developer_agent.topology_wiring import topology_contract_rule
    assert topology_contract_rule(None) == ""
    assert topology_contract_rule(vt_of(topo([("shop", "cloudrun")], "shop"))) == ""   # single service: unchanged
    vt = vt_of(topo([("public-gateway", "cloudrun"), ("internal-core-service", "cloudrun")], "public-gateway",
                    [("public-gateway", "internal-core-service", "http")],
                    [{"type": "google_storage_bucket", "logical_name": "uploads",
                      "consumers": [{"service": "internal-core-service", "env_key": "UPLOADS_BUCKET"}]}]))
    text = topology_contract_rule(vt)
    assert "`public-gateway` (cloudrun, primary): its code lives in `apps/public-gateway/`" in text
    assert "INTERNAL_CORE_SERVICE_AUDIENCE, INTERNAL_CORE_SERVICE_URL" in text
    assert "`internal-core-service` (cloudrun, secondary)" in text and "UPLOADS_BUCKET" in text
    assert "google_storage_bucket.uploads" in text


def test_contract_reaches_the_developer_and_lead_prompts_only_when_present():
    from developer_agent import prompt as P
    from developer_agent.lead_orchestrator import LeadDeveloperOrchestrator
    from developer_agent.topology_wiring import topology_contract_rule
    vt = vt_of(topo([("api", "cloudrun"), ("core", "cloudrun")], "api", [("api", "core", "http")]))
    contract = topology_contract_rule(vt)
    with patch.object(P, "get_all_active_module_contracts", return_value=""), \
            patch.object(P, "resolve_active_skills", return_value=[]), \
            patch("shared.prompt_resolver.get_agent_system_prompt", return_value="BASE"):
        ref = P.build_developer_system_prompt(service_names=("api", "core"))
        with_c = P.build_developer_system_prompt(service_names=("api", "core"), wiring_contract=contract)
        assert P.build_developer_system_prompt(service_names=("api", "core"), wiring_contract="") == ref
    assert with_c == ref + "\n\n" + contract + "\n"

    def lead_prompt(**kw):
        seen = []

        def gen(model, contents, config):
            seen.append(contents)
            raise ValueError("captured")
        client = MagicMock()
        client.models.generate_content.side_effect = gen
        with patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent", return_value=["m"]):
            LeadDeveloperOrchestrator(genai_client=client, model_name="m").decompose_specification(
                product_id="shop", spec_text="Spec", task_dag=[{"task_id": "s"}], service_names=("api", "core"), **kw)
        return seen[0]
    base = lead_prompt()
    assert lead_prompt(wiring_contract="") == base
    assert lead_prompt(wiring_contract=contract).startswith(base + "\n\n" + contract)


def test_rt_f2_legacy_path_ci_workflows_unchanged():
    """Negative (Do No Harm): a v1 record keeps today's CI set (every app dir with an entrypoint)."""
    from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
    from developer_agent.handler import DeveloperAgent
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        dev = DeveloperAgent(project_id="")
    canned = canned_workload_files("public-gateway", extra=canned_workload_files("internal-core"))
    canned["apps/stripe/main.py"] = "x = 1\n"
    dev.genai_client = FakeGenaiClient(files=canned)
    rec = {"schema": "architect_compute_intent/v1", "target_compute_services": ["public-gateway", "internal-core"],
           "bundle_id": None, "compute_archetype": "cloudrun"}
    no_project = {"PROJECT_ID": "", "GCP_PROJECT": "", "GOOGLE_CLOUD_PROJECT": ""}
    with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false", **no_project}), \
            patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no firestore in tests"))), \
            patch.object(dev, "fetch_existing_repo_files", return_value={}):
        files = dev.generate_code_files(product_id="test-02-multi-cloudrun-mesh", spec_text="x", task_dag=[],
                                        architect_compute_intent=rec, allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)
    assert ".github/workflows/deploy-stripe.yml" in files     # today's behavior on the legacy path
    assert TOPOLOGY_JSON_PATH not in files


@pytest.mark.parametrize("meta", ['for_each = toset(["a", "b"])', "count = 2"])
def test_rt_f5_count_or_for_each_compute_is_held_never_re_addressed(meta):
    existing = {MAIN_TF: 'module "compute" {\n  source = "../modules/compute-cloudrun"\n  service_name = "shop"\n}\n',
                CUSTOM_TF: ('module "compute_w" {\n  source = "../modules/compute-cloudrun"\n'
                            f'  {meta}\n  service_name = "w"\n}}\n')}
    entries, _ = ci.existing_compute_entries(existing)
    assert {e.address: e.indexed for e in entries} == {"module.compute": False, "module.compute_w": True}
    with pytest.raises(ci.TopologyGuardError) as ei:
        ci.resolve_compute_intent("shop", record_of(topo([("shop", "cloudrun"), ("w", "cloudrun")], "shop")), existing)
    assert [d.code for d in ei.value.diagnostics] == ["TOPOLOGY.LEGACY_SHAPE_UNSUPPORTED"]
    assert "count/for_each" in ei.value.diagnostics[0].message


def test_rt_f5_negative_plain_module_unchanged():
    existing = {MAIN_TF: 'module "compute" {\n  source = "../modules/compute-cloudrun"\n  service_name = "shop"\n}\n',
                CUSTOM_TF: 'module "compute_w" {\n  source = "../modules/compute-cloudrun"\n  service_name = "w"\n}\n'}
    intent = ci.resolve_compute_intent("shop", record_of(topo([("shop", "cloudrun"), ("w", "cloudrun")], "shop")),
                                       existing)
    assert intent.service_names == ("shop", "w")


# ------------------------------------------------------------------------------------------------ RT F1 tree completeness
def test_rt_f1_github_provider_reports_tree_completeness():
    from types import SimpleNamespace as NS
    from shared.providers.github_provider import GitHubProvider
    import base64

    def repo_with(n, fail=False):
        repo = MagicMock()
        repo.full_name = "o/r"
        if fail:
            repo.get_git_tree.side_effect = RuntimeError("403 rate limit")
        else:
            repo.get_git_tree.return_value = NS(tree=[NS(type="blob", path=f"f{i}.py", sha=str(i)) for i in range(n)])
        repo.get_git_blob.return_value = NS(content=base64.b64encode(b"x").decode())
        return repo
    prov = GitHubProvider.__new__(GitHubProvider)
    for n, cap, expect in ((3, 5, (True, False)), (5, 5, (True, False)), (6, 5, (False, True))):
        with patch.object(GitHubProvider, "_get_repo", return_value=repo_with(n)):
            files = prov.fetch_file_tree("o/r", max_files=cap)
        assert len(files) == min(n, cap)
        assert (prov.last_tree_status["complete"], prov.last_tree_status["truncated"]) == expect
    with patch.object(GitHubProvider, "_get_repo", return_value=repo_with(0, fail=True)):
        assert prov.fetch_file_tree("o/r") == {}
    assert prov.last_tree_status["complete"] is False and "rate limit" in prov.last_tree_status["error"]


def _dev_with_tree(files, status, workloads_doc=None):
    from developer_agent.handler import DeveloperAgent
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        dev = DeveloperAgent(project_id="")
    dev.genai_client = MagicMock()

    def fetch(product_id):
        dev.last_tree_status = status
        return dict(files)
    dev.fetch_existing_repo_files = fetch
    if workloads_doc is not None:
        doc = MagicMock(exists=True)
        doc.to_dict.return_value = workloads_doc
        dev.db = MagicMock()
        dev.db.collection.return_value.document.return_value.get.return_value = doc
    return dev


@pytest.mark.parametrize("status,files,wdoc", [
    ({"complete": False, "truncated": True, "error": None}, {"apps/a/main.py": "x"}, None),
    ({"complete": False, "truncated": False, "error": "RuntimeError: 500"}, {"README.md": "x"}, None),
    ({"complete": False, "truncated": False, "error": "RuntimeError: 500"}, {}, {"service_topology": {"record": {}}}),
], ids=["truncated", "partial-fetch-failure", "failed-fetch-of-a-built-product"])
def test_rt_f1_topology_run_refuses_an_incomplete_tree_before_any_llm_call(status, files, wdoc):
    from shared.diagnostics import StageError
    dev = _dev_with_tree(files, status, wdoc)
    with pytest.raises(StageError) as ei:
        dev.generate_code_files(product_id="shop", spec_text="x", task_dag=[{"task_id": "T"}], trace_id="t-f1",
                                architect_compute_intent=record_of(topo([("shop", "cloudrun")], "shop")), allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)
    assert [d.code for d in ei.value.report.diagnostics] == ["TOPOLOGY.EXISTING_TREE_UNAVAILABLE"]
    assert ei.value.report.error_class == ErrorClass.PLATFORM_DEFECT
    dev.genai_client.models.generate_content.assert_not_called()


@pytest.mark.parametrize("status,rec", [
    ({"complete": True, "truncated": False, "error": None}, "v2"),
    ({"complete": False, "truncated": False, "error": "RuntimeError: 404"}, "v2"),   # greenfield: nothing built yet
    ({"complete": False, "truncated": True, "error": None}, "v1"),                   # legacy path: unchanged
    (None, "v2"),                                                                    # provider did not report
], ids=["complete", "greenfield-fetch-failure", "legacy-record", "unreported"])
def test_rt_f1_negative_no_refusal(status, rec):
    dev = _dev_with_tree({}, status)
    record = (record_of(topo([("shop", "cloudrun")], "shop")) if rec == "v2" else
              {"schema": "architect_compute_intent/v1", "target_compute_services": ["shop"], "bundle_id": None,
               "compute_archetype": "cloudrun"})
    intent = dev._resolve_compute_intent("shop", "t-f1n", record, {}, None)
    assert intent.service_names == ("shop",)


# ------------------------------------------------------------------------------------------------ S2-D merge seam
_SIB_REF = r'"([A-Z0-9_]+)"\s*=\s*(module\.[a-z0-9_]+\.(?:service_uri|topic_name))'


def _rendered_sibling_env(files):
    """{module label: {env key: module.<x>.service_uri|topic_name}} over main.tf + custom.tf (test-side reader)."""
    import re
    out = {}
    for path in (MAIN_TF, CUSTOM_TF, SERVICES_TF):
        for b in te.extract_hcl_blocks(files.get(path, "") or ""):
            if b.get("block_type") == "module" and b.get("name_label", "").startswith("compute"):
                out[b["name_label"]] = dict(re.findall(_SIB_REF, b.get("raw_text", "")))
    return out


def _s2d_mutual_read_tree(vt):
    """api -> core declared; store undeclared. Apps read CORE_URL / STORE_URL and each other's keys (core <-> store)."""
    files = {CUSTOM_TF: "",
             "apps/api/main.py": 'import os\nA = os.environ["CORE_URL"]\nB = os.getenv("STORE_URL")\n',
             "apps/core/main.py": 'import os\nS = os.environ["STORE_URL"]\n',
             "apps/store/main.py": 'import os\nC = os.environ["CORE_URL"]\n'}
    te.reconcile_multi_service_declarations(
        files=files, product_id="shop", spec_text="", archetype="cloudrun", assembly_record=AssemblyRecord(),
        llm_iac_paths=[CUSTOM_TF], target_services=["api", "core", "store"], topology=vt)
    env = None
    if vt is not None:
        from developer_agent.handler import DeveloperAgent
        env, _ = DeveloperAgent._topology_primary_overrides(vt, bespoke_root_text(files), files)
    files[MAIN_TF] = _main("shop", service_name="api", custom_tf_content=bespoke_root_text(files), app_files=files,
                           env_vars_override=env)
    return files


def test_s2d_merge_sibling_bindings_equal_edges():
    """Lane 10 x S2-D seam (topology report §5 rules 1-4). v2 topology: the sibling env bindings are exactly the
    topology's edges, the verifier twin is a no-op, no V2f validator is registered. v1 (no topology): S2-D's
    exact-read behavior is unchanged (bindings == plan_sibling_wiring, V2f ids registered)."""
    from developer_agent.sibling_wiring import plan_sibling_wiring
    from developer_agent.validators.step1 import build_step1_stack
    from gatekeeper_agent.verifier import SynthesisVerifierAgent
    v2f = {"V2f", "V2f-not-written", "V2f-cycle"}
    vt = vt_of(topo([("api", "cloudrun"), ("core", "cloudrun"), ("store", "cloudrun")], "api",
                    [("api", "core", "http")]))
    files = _s2d_mutual_read_tree(vt)
    files[TOPOLOGY_JSON_PATH] = render_topology_json(vt)
    rendered = _rendered_sibling_env(files)
    labels = {"api": "compute", "core": "compute_core", "store": "compute_store"}
    for svc, label in labels.items():
        assert rendered[label] == vt.edge_env(svc), (svc, rendered[label])
    assert rendered["compute"] and not rendered["compute_core"] and not rendered["compute_store"]
    assert SynthesisVerifierAgent(product_id="shop").reconcile_iac_environment_contracts(dict(files)) == files
    assert not v2f & set(build_step1_stack(validate_client=None, verifier_factory=None, topology=vt).ids)
    # rule 1 directly: include_siblings=False never adds a sibling binding even when the code reads it exactly
    assert not any(v.endswith((".service_uri", ".topic_name")) for v in te.extract_custom_resource_env_vars(
        bespoke_root_text(files), files, caller_service="api", caller_module="compute", main_tf=files[MAIN_TF],
        include_siblings=False).values())

    # v1 record (no topology): S2-D unchanged
    legacy = _s2d_mutual_read_tree(None)
    assert v2f <= set(build_step1_stack(validate_client=None, verifier_factory=None).ids)
    got = _rendered_sibling_env(legacy)
    for svc, label in labels.items():
        kw = {"caller_module": label} if label == "compute" else {}
        plan = plan_sibling_wiring(legacy[CUSTOM_TF], legacy, svc, main_tf=legacy[MAIN_TF], **kw)
        assert got[label] == plan.bindings, (svc, got[label], plan.bindings)
    assert got["compute"] == {"CORE_URL": "module.compute_core.service_uri",
                              "STORE_URL": "module.compute_store.service_uri"}
    assert not got["compute_core"] and not got["compute_store"]     # core <-> store mutual reads: not bound (inv. 6)


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
