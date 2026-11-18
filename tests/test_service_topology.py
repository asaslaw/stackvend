"""Lane 10 (FD-51) stage 1: the typed service topology core (`shared/service_topology.py`).

Plan docs/planning/wave2-lane10-dag-wiring-plan.md R2 §3-§4 tests T-2/T-3/T-6/T-16/T-17/T-23/T-32 plus the RT F2
(closed grammar, no HCL from data) and F10 (single-letter names) checks, and the brownfield guard on typed
`ExistingComputeEntry` facts. Pure: no I/O, no LLM."""
import hermetic_guard  # noqa: F401  (first import)

import graphlib
import itertools
import json
import os
import random
import sys
import typing

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: F401,E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt or put eval/.deps on "
                "PYTHONPATH; this file is acceptance evidence and must not skip", pytrace=False)

from shared import service_topology as st  # noqa: E402
from shared.diagnostics import ErrorClass  # noqa: E402
from shared.service_topology import (  # noqa: E402
    ExistingComputeEntry,
    ServiceTopologyIntent,
    ValidatedTopology,
    strongly_connected_components,
    validate_service_topology,
)


def svc(name, kind="cloudrun", **kw):
    return {"name": name, "kind": kind, **kw}


def topo(services, primary=None, edges=(), resources=()):
    return {"services": list(services), "primary_service": primary, "edges": list(edges),
            "resources": list(resources)}


def edge(a, b, protocol="http", **kw):
    return {"caller": a, "callee": b, "protocol": protocol, **kw}


def codes(diags, severity="error"):
    return sorted(d.code for d in diags if d.severity == severity)


def ok(raw, **kw):
    vt, diags = validate_service_topology(raw, product_id=kw.pop("product_id", "shop"), **kw)
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt, diags


# ------------------------------------------------------------------------------------------------ parity
def test_kinds_equal_architect_enum_and_resolver_archetypes():
    from architect_agent.schemas import COMPUTE_ARCHETYPES
    from developer_agent.compute_intent import ARCHETYPES, MODULE_DIR_ARCHETYPE
    assert st.ARCHETYPES == COMPUTE_ARCHETYPES == ARCHETYPES
    # primary-capable kinds = the resolver's archetype modules; gce-worker (L10-v) is secondary only
    assert {d: k for d, k in st.KIND_FOR_MODULE_DIR.items() if st.CAPABILITIES[k].allowed_as_primary} == \
        MODULE_DIR_ARCHETYPE
    assert set(st.COMPUTE_KINDS) == set(st.CAPABILITIES)


def _module_interface(module_dir):
    base = os.path.join(REPO_ROOT, "infra", "modules", module_dir)
    with open(os.path.join(base, "variables.tf")) as f:
        variables = {list(v)[0] for v in hcl2.loads(f.read()).get("variable", [])}
    with open(os.path.join(base, "outputs.tf")) as f:
        outputs = {list(o)[0] for o in hcl2.loads(f.read()).get("output", [])}
    return variables, outputs


@pytest.mark.parametrize("kind", st.COMPUTE_KINDS)
def test_t17_capability_matrix_matches_the_golden_modules(kind):
    cap = st.CAPABILITIES[kind]
    variables, outputs = _module_interface(cap.module_dir)
    assert set(cap.exports) == outputs
    assert cap.accepts_env_vars == ("env_vars" in variables)
    for _suffix, output in cap.callee_outputs:
        assert output in outputs
    # event-worker names derive from product_id (no service_name input): one per workload
    if kind == "event-worker":
        assert "service_name" not in variables and cap.max_per_workload == 1


def test_t17_reserved_env_keys_cover_the_cloudrun_module_literal_env():
    with open(os.path.join(REPO_ROOT, "infra", "modules", "compute-cloudrun", "main.tf")) as f:
        body = hcl2.loads(f.read())
    literal_env = set()

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "env" and isinstance(v, list):
                    for e in v:
                        if isinstance(e, dict) and isinstance(e.get("name"), str) and "${" not in e["name"]:
                            literal_env.add(e["name"])
                # CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV: a `dynamic "env"` block whose content name is a literal
                # (GOOGLE_CLOUD_PROJECT, emitted unless var.env_vars has the key) counts too.
                if k == "env" and isinstance(v, dict):
                    for e in v.get("content", []):
                        if isinstance(e, dict) and isinstance(e.get("name"), str) and "${" not in e["name"]:
                            literal_env.add(e["name"])
                walk(v)
        elif isinstance(node, list):
            for x in node:
                walk(x)
    walk(body)
    assert "GOOGLE_CLOUD_PROJECT" in literal_env
    assert literal_env and literal_env <= st.RESERVED_ENV_KEYS


# ------------------------------------------------------------------------------------------------ happy paths
def test_t1_chain_each_caller_gets_only_its_callee():
    vt, diags = ok(topo([svc("api"), svc("core"), svc("store")], "api", [edge("api", "core"), edge("core", "store")]))
    assert diags == []
    assert vt.env_for("api") == {"CORE_AUDIENCE": "module.compute_core.service_uri",
                                 "CORE_URL": "module.compute_core.service_uri"}
    assert vt.env_for("core") == {"STORE_AUDIENCE": "module.compute_store.service_uri",
                                  "STORE_URL": "module.compute_store.service_uri"}
    assert vt.env_for("store") == {}
    assert vt.archetype == "cloudrun" and vt.names == ("api", "core", "store")
    assert vt.label("api") == "compute" and vt.label("store") == "compute_store"


def test_secondary_called_by_primary_and_secondary_calling_primary():
    vt, _ = ok(topo([svc("web"), svc("order-api")], "web", [edge("web", "order-api")]))
    assert vt.env_for("web") == {"ORDER_API_AUDIENCE": "module.compute_order_api.service_uri",
                                 "ORDER_API_URL": "module.compute_order_api.service_uri"}
    vt, _ = ok(topo([svc("web"), svc("admin")], "web", [edge("admin", "web", env_key_base="BACKEND")]))
    assert vt.env_for("admin") == {"BACKEND_AUDIENCE": "module.compute.service_uri",
                                   "BACKEND_URL": "module.compute.service_uri"}


def test_t15_event_worker_primary_and_secondary_pubsub_edges():
    vt, _ = ok(topo([svc("ingest", "event-worker"), svc("web")], "ingest", [edge("web", "ingest", "pubsub")]))
    assert vt.archetype == "event-worker"
    assert vt.env_for("web") == {"INGEST_TOPIC": "module.compute.topic_name"}
    assert vt.http_entrypoint == "web"
    vt, _ = ok(topo([svc("api"), svc("etl-worker", "event-worker")], "api", [edge("api", "etl-worker", "pubsub")]))
    assert vt.env_for("api") == {"ETL_WORKER_TOPIC": "module.compute_etl_worker.topic_name"}
    assert vt.secondaries_of_kind("event-worker") == ("etl-worker",)
    assert vt.http_entrypoint == "api"


def test_hybrid_gke_primary_with_cloudrun_edge_owner_q_b():
    """Example 05 shape: GKE stream processor (primary) + Cloud Run edge gateway, each typed."""
    vt, _ = ok(topo([svc("stream-processor", "gke-autopilot"), svc("edge-gateway")], "stream-processor"),
               expected_archetype="gke-autopilot")
    assert vt.archetype == "gke-autopilot"
    assert vt.secondaries_of_kind("cloudrun") == ("edge-gateway",)
    assert vt.kind("stream-processor") == "gke-autopilot" and vt.kind("edge-gateway") == "cloudrun"
    assert vt.http_entrypoint == "edge-gateway"
    assert vt.env_for("edge-gateway") == {}


def test_foundation_only():
    vt, _ = ok(topo([], None), expected_archetype="foundation-only")
    assert vt.archetype == "foundation-only" and vt.names == () and vt.http_entrypoint is None


def test_resource_bindings_render_typed_references():
    vt, _ = ok(topo([svc("api")], "api", resources=[
        {"type": "google_storage_bucket", "logical_name": "uploads",
         "consumers": [{"service": "api", "env_key": "UPLOADS_BUCKET"}]},
        {"type": "google_redis_instance", "logical_name": "cache",
         "consumers": [{"service": "api", "env_key": "REDIS_HOST"},
                       {"service": "api", "env_key": "REDIS_PORT", "attribute": "port"}]}]))
    assert vt.env_for("api") == {"REDIS_HOST": "google_redis_instance.cache.host",
                                 "REDIS_PORT": "tostring(google_redis_instance.cache.port)",
                                 "UPLOADS_BUCKET": "google_storage_bucket.uploads.name"}


def test_f10_single_letter_service_names_are_valid():
    vt, _ = ok(topo([svc("a"), svc("b")], "a", [edge("a", "b")]))
    assert vt.env_for("a") == {"B_AUDIENCE": "module.compute_b.service_uri", "B_URL": "module.compute_b.service_uri"}


# ------------------------------------------------------------------------------------------------ errors
def test_t2_ring_is_one_cycle_with_its_path_and_no_validated_topology():
    vt, diags = validate_service_topology(
        topo([svc("api"), svc("core"), svc("store")], "api",
             [edge("api", "core"), edge("core", "store"), edge("store", "api")]), product_id="p")
    assert vt is None
    cyc = [d for d in diags if d.code == "TOPOLOGY.CYCLE"]
    assert len(cyc) == 1 and json.loads(cyc[0].detail) == ["api", "core", "store", "api"]
    assert cyc[0].error_class == ErrorClass.ARCHITECT_DEFECT


def test_t2_mutual_service_uri_fd40():
    vt, diags = validate_service_topology(topo([svc("gateway"), svc("core")], "gateway",
                                               [edge("gateway", "core"), edge("core", "gateway")]), product_id="p")
    assert vt is None and codes(diags) == ["TOPOLOGY.CYCLE"]
    assert json.loads(diags[0].detail) == ["core", "gateway", "core"]


def test_t3_two_disjoint_rings_two_diagnostics_in_deterministic_order():
    raw = topo([svc("a1"), svc("a2"), svc("b1"), svc("b2")], "a1",
               [edge("b1", "b2"), edge("b2", "b1"), edge("a1", "a2"), edge("a2", "a1")])
    _, d1 = validate_service_topology(raw, product_id="p")
    _, d2 = validate_service_topology(json.loads(json.dumps(raw)), product_id="p")
    assert [json.loads(d.detail) for d in d1] == [["a1", "a2", "a1"], ["b1", "b2", "b1"]]
    assert [d.model_dump() for d in d1] == [d.model_dump() for d in d2]   # T-23 determinism


def test_t6_h4_interpolated_name_and_injection_attempts_are_schema_invalid():
    for bad in ("${var.product_id}-x", "x\"}\nresource", "API", "a_b", "-a", "a-", "9a", "a" * 41, ""):
        vt, diags = validate_service_topology(topo([svc(bad)], bad), product_id="p")
        assert vt is None and "TOPOLOGY.SCHEMA_INVALID" in codes(diags), bad
    for bad_key in ("x_url", "A-B", "${X}", "A" * 70):
        vt, diags = validate_service_topology(
            topo([svc("api"), svc("core")], "api", [edge("api", "core", env_key_base=bad_key)]), product_id="p")
        assert vt is None and "TOPOLOGY.SCHEMA_INVALID" in codes(diags), bad_key
    vt, diags = validate_service_topology(topo([svc("api")], "api", resources=[
        {"type": "google_storage_bucket", "logical_name": "a.b", "consumers": []}]), product_id="p")
    assert vt is None and "TOPOLOGY.SCHEMA_INVALID" in codes(diags)


def test_t16_structural_errors():
    cases = [
        (topo([svc("api")], "api", [edge("api", "api")]), "TOPOLOGY.SELF_EDGE"),
        (topo([svc("api"), svc("api")], "api"), "TOPOLOGY.DUPLICATE_SERVICE"),
        (topo([svc("api")], None), "TOPOLOGY.PRIMARY_MISSING"),
        (topo([svc("api")], "web"), "TOPOLOGY.PRIMARY_UNKNOWN"),
        (topo([], "api"), "TOPOLOGY.PRIMARY_WITHOUT_SERVICES"),
        (topo([svc("w1", "event-worker"), svc("w2", "event-worker"), svc("api")], "api"), "TOPOLOGY.KIND_COUNT_EXCEEDED"),
        (topo([svc("api"), svc("k", "gke-autopilot")], "api"), "TOPOLOGY.KIND_NOT_ALLOWED_AS_SECONDARY"),
        (topo([svc("api"), svc("vm", "gce-bastion")], "api"), "TOPOLOGY.KIND_NOT_ALLOWED_AS_SECONDARY"),
        (topo([svc("api")], "api", [edge("api", "ghost")]), "TOPOLOGY.EDGE_UNKNOWN_SERVICE"),
        (topo([svc("api"), svc("core")], "api", [edge("api", "core"), edge("api", "core")]), "TOPOLOGY.DUPLICATE_EDGE"),
        (topo([svc("api"), svc("w", "event-worker")], "api", [edge("api", "w", "http")]), "TOPOLOGY.EDGE_CALLEE_UNSUPPORTED"),
        (topo([svc("api"), svc("core")], "api", [edge("api", "core", "pubsub")]), "TOPOLOGY.EDGE_CALLEE_UNSUPPORTED"),
        (topo([svc("w", "event-worker"), svc("api")], "w", [edge("w", "api")]), "TOPOLOGY.EDGE_CALLER_NO_ENV_INPUT"),
        (topo([svc("api"), svc("core"), svc("store")], "api",
              [edge("api", "core", env_key_base="X"), edge("api", "store", env_key_base="X")]), "TOPOLOGY.ENV_KEY_COLLISION"),
        (topo([svc("api"), svc("port")], "api", [edge("api", "port", env_key_base="K")]), None),
        (topo([svc("api")], "api", resources=[{"type": "google_storage_bucket", "logical_name": "b",
                                               "consumers": [{"service": "api", "env_key": "PORT"}]}]),
         "TOPOLOGY.ENV_KEY_RESERVED"),
        (topo([svc("api")], "api", resources=[{"type": "google_compute_network", "logical_name": "n"}]),
         "TOPOLOGY.RESOURCE_TYPE_UNKNOWN"),
        (topo([svc("api")], "api", resources=[{"type": "google_storage_bucket", "logical_name": "b",
                                               "consumers": [{"service": "web", "env_key": "B"}]}]),
         "TOPOLOGY.RESOURCE_CONSUMER_UNKNOWN"),
        (topo([svc("api")], "api", resources=[{"type": "google_storage_bucket", "logical_name": "b",
                                               "consumers": [{"service": "api", "env_key": "B", "attribute": "url"}]}]),
         "TOPOLOGY.RESOURCE_ATTRIBUTE_UNSUPPORTED"),
        (topo([svc("api")], "api", resources=[{"type": "google_storage_bucket", "logical_name": "b"},
                                              {"type": "google_storage_bucket", "logical_name": "b"}]),
         "TOPOLOGY.DUPLICATE_RESOURCE"),
        (topo([svc("api"), svc("core")], "api", [edge("api", "core")], resources=[
            {"type": "google_storage_bucket", "logical_name": "b",
             "consumers": [{"service": "api", "env_key": "CORE_URL"}]}]), "TOPOLOGY.ENV_KEY_COLLISION"),
    ]
    for raw, code in cases:
        vt, diags = validate_service_topology(raw, product_id="p")
        if code is None:
            assert vt is not None, [(d.code, d.message) for d in diags]
            continue
        assert vt is None and code in codes(diags), (code, [(d.code, d.message) for d in diags])
        assert all(d.tool == "topology" and d.error_class == ErrorClass.ARCHITECT_DEFECT for d in diags
                   if d.severity == "error")


def test_missing_topology_and_archetype_mismatch():
    vt, diags = validate_service_topology(None, product_id="p")
    assert vt is None and codes(diags) == ["TOPOLOGY.MISSING"]
    vt, diags = validate_service_topology(topo([svc("api")], "api"), product_id="p", expected_archetype="gke-autopilot")
    assert vt is None and codes(diags) == ["TOPOLOGY.ARCHETYPE_MISMATCH"]
    vt, diags = validate_service_topology(topo([], None), product_id="p", expected_archetype="cloudrun")
    assert vt is None and codes(diags) == ["TOPOLOGY.ARCHETYPE_MISMATCH"]


def test_binding_on_kind_without_env_is_a_warning_not_rendered():
    vt, diags = ok(topo([svc("k", "gke-autopilot")], "k", resources=[
        {"type": "google_storage_bucket", "logical_name": "b", "consumers": [{"service": "k", "env_key": "B"}]}]))
    assert codes(diags, "warning") == ["TOPOLOGY.BINDING_NOT_RENDERED"]
    assert vt.env_for("k") == {}


def test_validated_topology_cannot_be_constructed_directly():
    intent = ServiceTopologyIntent.model_validate(topo([svc("api")], "api"))
    with pytest.raises(TypeError):
        ValidatedTopology(intent=intent, product_id="p", sha256="0" * 64)


def test_validator_never_mutates_its_input_and_sha_is_canonical():
    raw = topo([svc("b"), svc("a")], "b", [edge("b", "a")])
    before = json.dumps(raw, sort_keys=True)
    vt1, _ = ok(raw)
    assert json.dumps(raw, sort_keys=True) == before
    vt2, _ = ok(json.loads(before))
    assert vt1.sha256 == vt2.sha256 and len(vt1.sha256) == 64
    assert vt1.names == ("b", "a")                          # architect order kept, never sorted
    rec = vt1.as_record()
    assert rec["schema"] == st.TOPOLOGY_RECORD_SCHEMA and rec["sha256"] == vt1.sha256
    assert ServiceTopologyIntent.model_validate(rec["intent"]) == vt1.intent


def test_f2_rendered_references_contain_only_validated_identifiers():
    vt, _ = ok(topo([svc("api"), svc("core"), svc("w", "event-worker")], "api",
                    [edge("api", "core"), edge("api", "w", "pubsub")],
                    [{"type": "google_pubsub_topic", "logical_name": "events",
                      "consumers": [{"service": "core", "env_key": "EVENTS", "attribute": "id"}]}]))
    import re
    grammar = re.compile(r"^(tostring\()?(module\.[a-z][a-z0-9_]*|[a-z][a-z0-9_]+\.[a-z][a-z0-9_]*)\.[a-z_]+\)?$")
    for name in vt.names:
        for key, ref in vt.env_for(name).items():
            assert re.fullmatch(st.ENV_KEY_PATTERN, key) and grammar.fullmatch(ref) and "${" not in ref, (key, ref)


# ------------------------------------------------------------------------------------------------ Tarjan
def test_t32_tarjan_agrees_with_graphlib_on_random_graphs():
    rng = random.Random(1013)
    for _ in range(400):
        n = rng.randint(1, 7)
        nodes = [f"n{i}" for i in range(n)]
        edges = [(a, b) for a, b in itertools.permutations(nodes, 2) if rng.random() < 0.25]
        sccs = strongly_connected_components(nodes, edges)
        assert sorted(x for c in sccs for x in c) == sorted(nodes)
        has_cycle = any(len(c) > 1 for c in sccs)
        ts = graphlib.TopologicalSorter({v: [a for a, b in edges if b == v] for v in nodes})
        try:
            ts.prepare()
            graphlib_cycle = False
        except graphlib.CycleError:
            graphlib_cycle = True
        assert has_cycle == graphlib_cycle, (nodes, edges, sccs)


def test_tarjan_is_iterative_on_a_long_chain():
    nodes = [f"n{i}" for i in range(3000)]
    edges = [(nodes[i], nodes[i + 1]) for i in range(len(nodes) - 1)] + [(nodes[-1], nodes[0])]
    sccs = strongly_connected_components(nodes, edges)
    assert len(sccs) == 1 and len(sccs[0]) == 3000


# ------------------------------------------------------------------------------------------------ brownfield
def E(address, kind="cloudrun", label=None, file="infra/workload/main.tf", root=True, name=None, expr=None):
    label = label or address.split(".")[-1]
    return ExistingComputeEntry(address=address, label=label, kind=kind, file=file, root=root,
                                service_name=name, service_name_expr=expr)


def bf(raw, existing, **kw):
    return validate_service_topology(raw, product_id="shop", existing=existing, file="infra/workload/topology.json",
                                     source="precommit", **kw)


def test_brownfield_same_shape_passes():
    existing = [E("module.compute", name="shop"),
                E("module.compute_admin", file="infra/workload/custom.tf", name="admin")]
    vt, diags = bf(topo([svc("shop"), svc("admin"), svc("new-svc")], "shop"), existing)
    assert vt is not None and diags == []


@pytest.mark.parametrize("raw,existing,code", [
    (topo([svc("shop")], "shop"), [E("module.compute", name="shop"), E("module.compute_admin", name="admin",
                                                                     file="infra/workload/custom.tf")],
     "TOPOLOGY.COMPUTE_REMOVED"),
    (topo([], None), [E("module.compute", name="shop")], "TOPOLOGY.COMPUTE_REMOVED"),
    (topo([svc("shop", "event-worker")], "shop"), [E("module.compute", name="shop")], "TOPOLOGY.KIND_CHANGED"),
    (topo([svc("admin"), svc("shop")], "admin"), [E("module.compute", name="shop"),
                                                 E("module.compute_admin", name="admin")], "TOPOLOGY.PRIMARY_CHANGED"),
    (topo([svc("web")], "web"), [E("module.compute", name="castor-shop")], "TOPOLOGY.DEPLOYED_NAME_CHANGED"),
    (topo([svc("shop")], "shop"), [E("module.compute", expr="${local.n}")], "TOPOLOGY.LEGACY_NAME_EXPR_UNSUPPORTED"),
    (topo([svc("shop")], "shop"), [E("module.app", label="app")], "TOPOLOGY.LEGACY_SHAPE_UNSUPPORTED"),
    (topo([svc("shop")], "shop"), [E("module.worker_jobs", kind="event-worker", label="worker_jobs")],
     "TOPOLOGY.LEGACY_SHAPE_UNSUPPORTED"),
    (topo([svc("shop")], "shop"), [E("module.bundle.module.app", label="app", root=False,
                                     file="infra/bundles/x/main.tf")], "TOPOLOGY.LEGACY_SHAPE_UNSUPPORTED"),
])
def test_t9_t10_brownfield_conflicts_are_typed_and_never_healed(raw, existing, code):
    before = json.dumps(raw, sort_keys=True)
    vt, diags = bf(raw, existing)
    assert vt is None and code in codes(diags), [(d.code, d.message) for d in diags]
    assert all(d.error_class == ErrorClass.BROWNFIELD_CONFLICT for d in diags if d.code == code)
    assert json.dumps(raw, sort_keys=True) == before


def test_brownfield_approved_removal_is_honoured_only_by_exact_address():
    existing = [E("module.compute", name="shop"), E("module.compute_admin", name="admin")]
    vt, _ = bf(topo([svc("shop")], "shop"), existing, approved_removals=["module.compute_admin"])
    assert vt is not None
    vt, diags = bf(topo([svc("shop")], "shop"), existing, approved_removals=["module.compute_adm"])
    assert vt is None and codes(diags) == ["TOPOLOGY.COMPUTE_REMOVED"]


def test_brownfield_var_product_id_primary_maps_to_the_product_name():
    vt, diags = bf(topo([svc("shop")], "shop"), [E("module.compute", name="shop")])
    assert vt is not None and diags == []
    vt, diags = bf(topo([svc("k", "gke-autopilot"), svc("edge")], "k"),
                   [E("module.compute", kind="gke-autopilot"), E("module.compute_edge", name="edge")])
    assert vt is not None and diags == []
