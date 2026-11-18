"""TI-5-R2 + TI-5-F4 (owner rows 10-21, built 10-24). Hermetic.

TI-5-R2: AlloyDB, Vertex AI endpoints and Bigtable are typed topology resources with consumer edges
(shared/service_topology.BOOTSTRAP_CATALOG + shared/iac_intent.REALIZATION_EXPORTS), so the platform wires the
services that read them: the env binding from the exact intent -> env table (TI-3d) and, for the private-network ones
(AlloyDB, Vertex AI endpoint), the platform VPC connector. Bigtable is not VPC-bound: env only. TI-5c-a is lifted
(shared/iac_intent.NOT_YET_WIRED_MODULES is empty).

TI-5-F4: the Private Services Access range of the platform-rendered network comes from an IPAM purpose
(platform_facts.PURPOSE_PSA -> var.psa_cidr -> networking-vpc `psa_address` / `psa_prefix_length`), so the platform
owns subnet, connector and PSA ranges. A network committed before TI-5-F4 keeps Google's range (no live range move).

Set TI5R2_DUMP_TREE=<dir> to write each end-to-end tree for the offline `tofu validate` / mocked `tofu plan`
(docs/handoff/ti5-evidence/offline_validate_plan.sh)."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from test_typed_iac_ti3_contract import (APP, ART, BUCKET_MODULE, PID, UPLOADS, W, C, II,  # noqa: E402
                                         intent, topo, vt_of)
from test_typed_iac_ti5c_network_facts import (CLOUDSQL, FACTS, SQL_MODULE, _assemble_net,  # noqa: E402
                                               _generate_net, _module_body)
from shared import service_topology as ST  # noqa: E402

import hcl2  # noqa: E402

from developer_agent import platform_facts as PF  # noqa: E402
from developer_agent import topology_wiring as TW  # noqa: E402

ALLOYDB = {"type": "google_alloydb_instance", "logical_name": "ledger", "purpose": "ledger database",
           "consumers": [{"service": "shop", "env_key": "LEDGER_DB_HOST", "attribute": None}]}
VERTEX = {"type": "google_vertex_ai_endpoint", "logical_name": "scorer", "purpose": "own fraud model",
          "consumers": [{"service": "shop", "env_key": "SCORER_ENDPOINT", "attribute": None},
                        {"service": "shop", "env_key": "SCORER_ENDPOINT_ID", "attribute": "name"}]}
BIGTABLE = {"type": "google_bigtable_instance", "logical_name": "events", "purpose": "event history",
            "consumers": [{"service": "shop", "env_key": "BIGTABLE_INSTANCE", "attribute": None}]}
ALLOYDB_MODULE = {"module": "database-alloydb", "name": "ledger", "realizes": "ledger", "args": {}}
VERTEX_MODULE = {"module": "ai-vertex-endpoint", "name": "scorer", "realizes": "scorer", "args": {}}
BIGTABLE_MODULE = {"module": "database-bigtable", "name": "events", "realizes": "events", "args": {}}
PSA_FACTS = PF.NetworkFacts(product_id=PID, region="us-central1", subnet_cidr="10.100.0.0/24",
                            connector_cidr="10.100.1.0/28", psa_cidr="10.100.16.0/20", source="memory")


def _dump(files, name):
    base = os.environ.get("TI5R2_DUMP_TREE")
    if not base:
        return
    for p, t in files.items():
        if isinstance(t, str) and (p.startswith("infra/") or p.startswith("apps/")):
            full = os.path.join(base, name, p)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(t)


def _committed(files):
    return {p: files[p] for p in (C.INTENT_PATH, C.RENDER_PATH, C.FACTS_RENDER_PATH, W + "terraform.tfvars")
            if p in files}


# ------------------------------------------------------------------------------------------------ R2: catalog
def test_r2_the_three_types_are_topology_catalog_types_bound_by_exact_module_outputs():
    # TI-5-R2 P3: + password_secret_id (a module-only attribute)
    assert ST.BOOTSTRAP_CATALOG["google_alloydb_instance"] == (("ip_address", "string"),
                                                               ("password_secret_id", "string"))
    assert ST.BOOTSTRAP_CATALOG["google_vertex_ai_endpoint"] == (("id", "string"), ("name", "string"))
    assert ST.BOOTSTRAP_CATALOG["google_bigtable_instance"] == (("name", "string"),)
    assert II.REALIZATION_EXPORTS[("database-alloydb", "google_alloydb_instance")] == {
        "ip_address": "ip_address", "password_secret_id": "secret_id_password"}
    assert II.REALIZATION_EXPORTS[("ai-vertex-endpoint", "google_vertex_ai_endpoint")] == {
        "id": "endpoint_id", "name": "endpoint_name"}
    assert II.REALIZATION_EXPORTS[("database-bigtable", "google_bigtable_instance")] == {"name": "instance_id"}
    # every exported attribute is a catalog attribute of the type (the TI-3 contract test checks the module outputs)
    for (mid, rtype), row in II.REALIZATION_EXPORTS.items():
        assert set(row) <= {a for a, _ in ST.BOOTSTRAP_CATALOG[rtype]}, (mid, rtype)
    # the private-network types on the intent path; Bigtable is not one; the legacy HCL rule is unchanged
    assert {"google_alloydb_instance", "google_vertex_ai_endpoint"} <= TW.INTENT_PRIVATE_NETWORK_TYPES
    assert "google_bigtable_instance" not in TW.INTENT_PRIVATE_NETWORK_TYPES
    assert set(TW.PRIVATE_NETWORK_RESOURCES) == {"google_sql_database_instance", "google_redis_instance"}


def test_r2_architect_contract_lists_the_types_and_older_types_render_unchanged():
    text = ST.render_topology_contract()
    assert ("`google_alloydb_instance` (ip_address/password_secret_id; password_secret_id is the Secret Manager "
            "secret id of the postgres user's password (typed infrastructure only))") in text
    assert "`google_bigtable_instance` (name)" in text
    assert "`google_vertex_ai_endpoint` (id/name; only for a model the workload deploys" in text
    # Do No Harm: a type without a note renders exactly as before (CLOUDSQL-PASSWORD-BINDING, owner 11-14: Cloud SQL
    # gained password_secret_id and its note, pinned in tests/test_cloudsql_password_binding.py)
    for t in ("`google_redis_instance` (host/port)", "`google_storage_bucket` (name)"):
        assert t in text


def test_r2_topology_validates_consumers_and_refuses_an_unknown_attribute():
    vt = vt_of(topo([ALLOYDB, VERTEX, BIGTABLE]))
    # TI5-ALLOYDB-SECRET-BIND (owner 10-27): a consumer of an AlloyDB instance always reads its password secret id
    assert vt.realization_needs() == {"ledger": ("google_alloydb_instance", ("ip_address", "password_secret_id")),
                                      "scorer": ("google_vertex_ai_endpoint", ("id", "name")),
                                      "events": ("google_bigtable_instance", ("name",))}
    bad = dict(ALLOYDB, consumers=[{"service": "shop", "env_key": "X", "attribute": "connection_name"}])
    vt2, diags = ST.validate_service_topology(topo([bad]), product_id=PID)
    assert vt2 is None and [d.code for d in diags] == ["TOPOLOGY.RESOURCE_ATTRIBUTE_UNSUPPORTED"]
    # a gce-worker cannot be granted these (no resource-level grant in WORKER_RESOURCE_ACCESS)
    worker = topo([dict(BIGTABLE, consumers=[{"service": "w", "env_key": "BT", "attribute": None}])],
                  services=(("shop", "cloudrun"), ("w", "gce-worker")), edges=(("shop", "w", "launch"),))
    vt3, diags3 = ST.validate_service_topology(worker, product_id=PID)
    assert vt3 is None and "TOPOLOGY.WORKER_RESOURCE_UNSUPPORTED" in [d.code for d in diags3]


def test_r2_no_topology_type_stays_legacy_on_the_intent_path():
    from unittest.mock import MagicMock
    from developer_agent.compute_intent import ComputeIntent
    from test_typed_iac_ti3_contract import Client, _agent, _runtime
    assert C.not_wired_slots(vt_of(topo([ALLOYDB, VERTEX, BIGTABLE])), ART) == []
    assert C.network_bound_slots(vt_of(topo([ALLOYDB, VERTEX, BIGTABLE])), ART, C.intent_path_facts()) == []
    agent = _agent(_runtime(None, iac_intent_mode="generate"))
    ci = MagicMock(spec=ComputeIntent)
    ci.topology = vt_of(topo([ALLOYDB, VERTEX, BIGTABLE]))
    run = agent._resolve_intent_run(ci, {}, {"provider_versions": Client().ready()["provider_versions"]})
    assert run is not None
    # the IaC contract names the realizing golden module of each slot
    assert "golden module database-alloydb" in run.run_context
    assert "golden module ai-vertex-endpoint" in run.run_context
    assert "golden module database-bigtable" in run.run_context


# ------------------------------------------------------------------------------------------------ R2: wiring
def test_r2_alloydb_and_vertex_consumers_get_env_and_the_connector_bigtable_env_only():
    vt = vt_of(topo([ALLOYDB, VERTEX, BIGTABLE]))
    asm, bound, files = _assemble_net(vt, {C.INTENT_PATH: intent([ALLOYDB_MODULE, VERTEX_MODULE, BIGTABLE_MODULE])},
                                      PSA_FACTS)
    assert asm.diagnostics == (), [d.code for d in asm.diagnostics]
    assert bound.resource_bindings("shop") == {"BIGTABLE_INSTANCE": "module.events.instance_id",
                                               "LEDGER_DB_HOST": "module.ledger.ip_address",
                                               # TI5-ALLOYDB-SECRET-BIND: implied, platform-bound
                                               "LEDGER_PASSWORD_SECRET_ID": "module.ledger.secret_id_password",
                                               "SCORER_ENDPOINT": "module.scorer.endpoint_id",
                                               "SCORER_ENDPOINT_ID": "module.scorer.endpoint_name"}
    assert json.loads(files[C.RENDER_PATH])["module"]["ledger"]["grant_workload_secret_access"] is True
    assert TW.private_network_consumers(bound) == {"shop"}
    assert TW.topology_vpc_connector(bound, "shop", files) == II.PLATFORM_CONNECTOR_REF
    net = json.loads(files[C.FACTS_RENDER_PATH])
    assert II.PLATFORM_CONNECTOR_MODULE in net["module"] and "resource" not in net   # FD-4BH: the golden module
    assert net["module"][II.PLATFORM_NETWORK_MODULE]["psa_address"] == "${cidrhost(var.psa_cidr, 0)}"


def test_r2_bigtable_alone_is_not_vpc_bound_env_only_no_network_no_ipam():
    vt = vt_of(topo([BIGTABLE]))
    assert TW.private_network_consumers(vt) == frozenset()
    assert C.intent_network_purposes({C.INTENT_PATH: intent([BIGTABLE_MODULE])}, ART, vt) == frozenset()
    asm, bound, files = _assemble_net(vt, {C.INTENT_PATH: intent([BIGTABLE_MODULE])}, None)
    assert asm.diagnostics == (), [d.code for d in asm.diagnostics]
    assert bound.resource_bindings("shop") == {"BIGTABLE_INSTANCE": "module.events.instance_id"}
    data = json.loads(files[C.FACTS_RENDER_PATH])
    assert "module" not in data and "resource" not in data and set(data["data"]) == {"google_compute_zones"}
    assert TW.topology_vpc_connector(bound, "shop", files) is None


def test_r2_the_connector_goes_only_to_cloud_run_consumers_of_the_private_types():
    raw = topo([dict(VERTEX, consumers=[{"service": "core", "env_key": "SCORER", "attribute": None}])],
               services=(("shop", "cloudrun"), ("core", "cloudrun")), edges=(("shop", "core", "http"),))
    vt = vt_of(raw)
    _, bound, files = _assemble_net(vt, {C.INTENT_PATH: intent([VERTEX_MODULE])}, PSA_FACTS)
    assert TW.topology_vpc_connector(bound, "core", files) == II.PLATFORM_CONNECTOR_REF
    assert TW.topology_vpc_connector(bound, "shop", files) is None


# ------------------------------------------------------------------------------------------------ F4: PSA from IPAM
def test_f4_purpose_table_pool_prefix_and_rendered_variable():
    assert PF.PURPOSES == (PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR, PF.PURPOSE_PSA)   # older order unchanged
    assert PF.FACT_VARIABLE[PF.PURPOSE_PSA] == "psa_cidr" and PF.FACT_PURPOSE["psa_cidr"] == PF.PURPOSE_PSA
    pool = PF.IpamPool(supernet="10.100.0.0/16", subnet_prefix=24, connector_prefix=28, region="us-central1")
    assert pool.prefix_for(PF.PURPOSE_PSA) == PF.PSA_PREFIX == 20
    assert pool.prefix_for(PF.PURPOSE_SUBNET) == 24 and pool.prefix_for(PF.PURPOSE_CONNECTOR) == 28
    prov = PF.MemoryFactsProvider()
    f = prov.resolve(PID, PF.PURPOSES, pool=pool)
    assert (f.subnet_cidr, f.connector_cidr, f.psa_cidr) == ("10.100.0.0/24", "10.100.1.0/28", "10.100.16.0/20")
    text = PF.render_fact_variables(f)
    assert 'variable "psa_cidr"' in text and "cidrnetmask(var.psa_cidr)" in text
    assert PF.render_fact_tfvars(f)[-1].startswith("psa_cidr") and '"10.100.16.0/20"' in PF.render_fact_tfvars(f)[-1]
    with pytest.raises(ValueError):
        PF.NetworkFacts(product_id="x", region="r", psa_cidr="10.100.16.5/20")   # host bits: not an allocation


def test_f4_render_passes_the_psa_range_only_with_the_fact():
    vt = vt_of(topo([CLOUDSQL]))
    _, _, with_psa = _assemble_net(vt, {C.INTENT_PATH: intent([SQL_MODULE])}, PSA_FACTS)
    mod = json.loads(with_psa[C.FACTS_RENDER_PATH])["module"][II.PLATFORM_NETWORK_MODULE]
    assert mod["psa_address"] == "${cidrhost(var.psa_cidr, 0)}"
    assert mod["psa_prefix_length"] == '${tonumber(element(split("/", var.psa_cidr), 1))}'
    assert mod["enable_private_service_access"] is True
    assert "10.100." not in with_psa[C.FACTS_RENDER_PATH]          # invariant 3: no CIDR literal
    # Do No Harm: without the PSA fact the network render is byte-identical to TI-5c's (Google allocates the range)
    _, _, without = _assemble_net(vt, {C.INTENT_PATH: intent([SQL_MODULE])}, FACTS)
    mod0 = json.loads(without[C.FACTS_RENDER_PATH])["module"][II.PLATFORM_NETWORK_MODULE]
    assert "psa_address" not in mod0 and "psa_prefix_length" not in mod0
    assert mod0 == {k: v for k, v in mod.items() if k not in ("psa_address", "psa_prefix_length")}
    # the context needs the network facts for a PSA range
    with pytest.raises(ValueError):
        II.IntentContext(psa_range=True)


def test_f4_the_ai_can_never_supply_a_psa_range():
    ctx = C.intent_context(None, network_facts=PSA_FACTS)
    # the network module is platform-only, and so is the PSA address / peering type
    res = II.validate_intent(intent(modules=[{"module": "networking-vpc", "name": "n", "args": {}}]), ART, ctx)
    assert "IAC.MODULE_UNKNOWN" in res.codes and not res.ok
    for rtype in ("google_compute_global_address", "google_service_networking_connection"):
        res = II.validate_intent(intent(resources=[{"type": rtype, "name": "x", "arguments": {}}]), ART, ctx)
        assert "IAC.TYPE_NOT_ALLOWED" in res.codes and not res.ok, rtype
    # psa_cidr is not an intent fact (only the platform render reads var.psa_cidr)
    assert "psa_cidr" not in II.FACTS and "psa_cidr" not in ctx.facts
    res = II.validate_intent(intent(outputs=[{"name": "p", "value": {"$ref": {"kind": "fact", "fact": "psa_cidr"}}}]),
                             ART, ctx)
    assert not res.ok


def test_f4_psa_purpose_new_network_yes_pre_f4_network_no_f4_network_yes():
    vt = vt_of(topo([CLOUDSQL]))
    draft = {C.INTENT_PATH: intent([SQL_MODULE])}
    full = {PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR, PF.PURPOSE_PSA}
    assert C.intent_network_purposes(draft, ART, vt, {}) == full                          # new network
    pre_f4 = {W + "terraform.tfvars": 'subnet_cidr = "10.100.0.0/24"\nconnector_cidr = "10.100.1.0/28"\n'}
    assert C.intent_network_purposes(draft, ART, vt, pre_f4) == full - {PF.PURPOSE_PSA}   # Google's range stays
    f4 = {W + "terraform.tfvars": pre_f4[W + "terraform.tfvars"] + 'psa_cidr = "10.100.16.0/20"\n'}
    assert C.intent_network_purposes(draft, ART, vt, f4) == full                          # reused (reuse-only)
    assert C.psa_range_wanted({W + "terraform.tfvars": "not = [hcl"}) is False             # the stage stops anyway
    # no network module -> no PSA (and no other purpose)
    assert C.intent_network_purposes({C.INTENT_PATH: intent([BUCKET_MODULE])}, ART, vt_of(topo([UPLOADS])), {}) \
        == frozenset()


def test_f4_legacy_path_never_allocates_a_psa_range():
    """Do No Harm: a legacy (.tf) draft with the golden network module asks for its subnet only, exactly as before.
    TI-5-R2 P5 (owner 10-25): `psa_address` is the one AI allocation attribute of the PSA purpose and an optional one,
    so only a call that sets it needs the range (tests/test_ti5_r2_p5_psa_address_ipam.py)."""
    legacy = {W + "custom.tf": 'module "net" {\n  source = "../modules/networking-vpc"\n  project_id = var.project_id\n'
                               '  primary_subnet_cidr = var.subnet_cidr\n}\n'}
    assert PF.required_network_purposes(legacy) == frozenset({PF.PURPOSE_SUBNET})
    assert [(k, a) for k, t in PF.ALLOCATION_ATTRIBUTES.items() for a, p in t.items() if p == PF.PURPOSE_PSA] == [
        (("module", PF.NETWORK_MODULE_DIR), "psa_address")]
    assert "psa_address" in PF.OPTIONAL_ALLOCATION_ATTRIBUTES[("module", PF.NETWORK_MODULE_DIR)]


def test_f4_ipam_engine_records_a_psa_range_without_touching_the_subnet_summary():
    from ipam_fake_firestore import FakeFirestore, fake_transactional
    from shared.ipam import CastorIPAMEngine
    db = FakeFirestore()
    db.collection("workloads").document("shop").set({"network": {}})
    eng = CastorIPAMEngine(db=db, supernet_cidr="10.100.0.0/16", transactional=fake_transactional)
    sub = eng.allocate_next_cidr("shop", purpose="WORKLOAD_SUBNET", prefix_len=24)
    psa = eng.allocate_next_cidr("shop", purpose=PF.PURPOSE_PSA, prefix_len=PF.PSA_PREFIX)
    assert (sub.cidr_block, psa.cidr_block) == ("10.100.0.0/24", "10.100.16.0/20")
    assert psa.subnet_name == "sb-shop-psa"
    meta = db.collection("workloads").document("shop").get().to_dict()["network"]
    assert meta["subnet_cidr"] == "10.100.0.0/24" and meta["psa_cidr"] == "10.100.16.0/20"
    assert eng.reuse_existing_cidr("shop", purpose=PF.PURPOSE_PSA).cidr_block == "10.100.16.0/20"


# ------------------------------------------------------------------------------------------------ end to end
@pytest.mark.parametrize("name,resources,modules,connector", [
    ("alloydb", [ALLOYDB], [ALLOYDB_MODULE], True),
    ("vertex", [VERTEX], [VERTEX_MODULE], True),
    ("bigtable", [BIGTABLE], [BIGTABLE_MODULE], False),
    ("cloudsql-psa", [CLOUDSQL], [SQL_MODULE], True),
])
def test_e2e_each_type_with_its_consumer(name, resources, modules, connector):
    provider = PF.MemoryFactsProvider()
    agent, files = _generate_net(dict(APP, **{C.INTENT_PATH: intent(modules)}), topo(resources), provider)
    assert agent.last_validation_report.status == "PASS", agent.last_validation_report
    compute = _module_body(files[W + "main.tf"], "compute")
    env = compute["env_vars"]
    for r in resources:
        for c in r["consumers"]:
            assert c["env_key"] in str(env), (c["env_key"], env)
    tfvars = hcl2.loads(files[W + "terraform.tfvars"])
    if connector:   # a private-network type: subnet + connector + PSA from IPAM, the consumer on the connector
        assert sorted(p for _pid, p in provider.ledger) == sorted(PF.PURPOSES)
        assert compute["vpc_access_connector"] == "${" + II.PLATFORM_CONNECTOR_REF + "}"
        assert tfvars["psa_cidr"] == provider.ledger[(PID, PF.PURPOSE_PSA)]
        mod = json.loads(files[C.FACTS_RENDER_PATH])["module"][II.PLATFORM_NETWORK_MODULE]
        assert mod["psa_address"] == "${cidrhost(var.psa_cidr, 0)}"
        declared = {n for b in hcl2.loads(files[W + "variables.tf"])["variable"] for n in b}
        assert {"subnet_cidr", "connector_cidr", "psa_cidr"} <= declared
    else:           # Bigtable: env only (zone data source), nothing from IPAM, no connector, no network
        assert provider.ledger == {}
        assert "vpc_access_connector" not in compute and "psa_cidr" not in tfvars
        assert "module" not in json.loads(files[C.FACTS_RENDER_PATH])
    for p in (C.RENDER_PATH, C.FACTS_RENDER_PATH):
        assert "10.100." not in files[p]
    _dump(files, name)


def test_e2e_sticky_pre_f4_network_keeps_googles_psa_range_and_renders_byte_identically():
    """A sticky intent workload whose network was committed before TI-5-F4 (tfvars hold subnet / connector, no
    psa_cidr): no PSA range is allocated and the render is unchanged, so its live PSA range is never replaced."""
    provider = PF.MemoryFactsProvider()
    draft = dict(APP, **{C.INTENT_PATH: intent([SQL_MODULE])})
    _, files = _generate_net(draft, topo([CLOUDSQL]), provider)
    pre = _committed(files)
    ledger = {k: v for k, v in provider.ledger.items() if k[1] != PF.PURPOSE_PSA}
    pre[W + "terraform.tfvars"] = "".join(f'{n} = "{v}"\n' for n, v in (
        ("subnet_cidr", ledger[(PID, PF.PURPOSE_SUBNET)]), ("connector_cidr", ledger[(PID, PF.PURPOSE_CONNECTOR)])))
    net = json.loads(pre[C.FACTS_RENDER_PATH])
    for k in ("psa_address", "psa_prefix_length"):
        net["module"][II.PLATFORM_NETWORK_MODULE].pop(k)
    pre[C.FACTS_RENDER_PATH] = json.dumps(net, indent=2, sort_keys=True, ensure_ascii=True) + "\n"   # TI-5c render
    again = PF.MemoryFactsProvider(ledger=dict(ledger))
    _, files2 = _generate_net(draft, topo([CLOUDSQL]), again, existing=pre)
    assert again.ledger == ledger                                   # nothing allocated
    assert files2[C.FACTS_RENDER_PATH] == pre[C.FACTS_RENDER_PATH]   # byte-identical network render
    assert "psa_cidr" not in hcl2.loads(files2[W + "terraform.tfvars"])


def test_e2e_sticky_f4_network_reuses_its_psa_range_and_a_moved_one_stops_typed():
    from shared.diagnostics import ErrorClass, StageError
    provider = PF.MemoryFactsProvider()
    draft = dict(APP, **{C.INTENT_PATH: intent([SQL_MODULE])})
    _, files = _generate_net(draft, topo([CLOUDSQL]), provider)
    committed = _committed(files)
    again = PF.MemoryFactsProvider(ledger=dict(provider.ledger))
    _, files2 = _generate_net(draft, topo([CLOUDSQL]), again, existing=committed)
    assert again.ledger == provider.ledger and files2[C.FACTS_RENDER_PATH] == files[C.FACTS_RENDER_PATH]
    assert files2[W + "terraform.tfvars"] == files[W + "terraform.tfvars"]
    moved = PF.MemoryFactsProvider(ledger=dict(provider.ledger, **{}))
    moved.ledger[(PID, PF.PURPOSE_PSA)] = "10.100.32.0/20"
    with pytest.raises(StageError) as ei:
        _generate_net(draft, topo([CLOUDSQL]), moved, existing=committed)
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE and "IPAM.LEDGER_MISMATCH" in str(ei.value)
