"""TI-5c (register TI-5c, owner 10-21; replaces TI-3f "until TI-5"): in generate mode Cloud SQL, Redis, AlloyDB,
Vertex AI endpoints and Bigtable are available on the typed-intent path. The platform fills their private network /
zone from the workload's IPAM (lane 11) facts and its own data sources, renders the network (golden networking-vpc on
var.subnet_cidr, Private Services Access) and, for a Cloud Run consumer of Cloud SQL / Redis, one Serverless VPC Access
connector on var.connector_cidr that the consuming services get. The AI never supplies these values. Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from test_typed_iac_ti3_contract import (APP, ART, BUCKET_MODULE, PID, UPLOADS, W, C, II, Client,  # noqa: E402
                                         _NoCallGenai, _agent, _assemble, intent, record_of, run_of, topo, vt_of)
from shared.diagnostics import AssemblyRecord  # noqa: E402

import hcl2  # noqa: E402

from developer_agent import platform_facts as PF  # noqa: E402

CLOUDSQL = {"type": "google_sql_database_instance", "logical_name": "db", "purpose": "app database",
            "consumers": [{"service": "shop", "env_key": "DB_HOST", "attribute": "private_ip_address"}]}
REDIS = {"type": "google_redis_instance", "logical_name": "cache", "purpose": "session cache",
         "consumers": [{"service": "shop", "env_key": "REDIS_HOST", "attribute": "host"}]}
SQL_MODULE = {"module": "database-cloudsql", "name": "db", "realizes": "db", "args": {}}
REDIS_MODULE = {"module": "cache-redis", "name": "cache", "realizes": "cache", "args": {}}
FACTS = PF.NetworkFacts(product_id=PID, region="us-central1", subnet_cidr="10.100.0.0/24",
                        connector_cidr="10.100.1.0/28", source="memory")
SUBNET_ONLY = PF.NetworkFacts(product_id=PID, region="us-central1", subnet_cidr="10.100.0.0/24", source="memory")
NETWORK_MODULES = {"database-cloudsql": ("private_network_id", "network"),
                   "cache-redis": ("authorized_network", "network"),
                   "database-alloydb": ("network", "network"),
                   "ai-vertex-endpoint": ("network", "network_by_project_number")}


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


R2_MODULES = ("ai-vertex-endpoint", "database-alloydb", "database-bigtable")   # held 10-21 (TI-5c-a), wired by R2


def _assemble_net(vt, files, network_facts=FACTS, existing=None):
    rec = AssemblyRecord()
    files = dict(files)
    asm, bound = C.assemble_intent(files, run_of(vt, existing), vt, ("module.foundation", "module.compute"),
                                   existing_files=existing or {}, record=rec, network_facts=network_facts)
    return asm, bound, files


# ------------------------------------------------------------------------------------------------ catalog / facts
def test_every_network_bound_module_now_has_a_platform_fact_and_none_stays_legacy():
    assert C.network_bound_types(ART, C.intent_path_facts()) == frozenset()
    # the mechanism stays: a fact without an expression puts its module's types back on the legacy path
    no_zone = {k: v for k, v in C.intent_path_facts().items() if k != "zone"}
    assert "google_bigtable_instance" in C.network_bound_types(ART, no_zone)
    # the catalog's Vertex endpoint network takes the project-number form (exact per-module override)
    assert ART.module("ai-vertex-endpoint")["variables"]["network"]["fact"] == "network_by_project_number"
    assert ART.module("database-alloydb")["variables"]["network"]["fact"] == "network"
    # the static table and the default context are unchanged: the IaC prompt lists the same facts as before
    assert all(II.FACTS[f]["expr"] is None for f in ("network", "network_by_project_number", "subnetwork", "zone"))
    assert "network" not in II.default_facts() and "zone" not in II.default_facts()


def test_r2_lifts_the_owner_1021_hold_the_three_modules_are_available():
    """TI-5-R2 (owner 10-21; lifts TI-5c-a): AlloyDB, Vertex AI endpoints and Bigtable are no longer held: the set is
    empty, the gate accepts the three modules with the platform facts, and no topology type stays legacy."""
    assert II.NOT_YET_WIRED_MODULES == frozenset()
    assert II.IntentContext().unwired_modules == frozenset()
    assert C.not_wired_types(ART) == frozenset()
    ctx = C.intent_context(None, network_facts=FACTS)
    for mid in R2_MODULES:
        assert II.validate_intent(intent(modules=[{"module": mid, "name": "m", "args": {}}]), ART, ctx).ok, mid


class _StubVt:   # a topology whose realization needs are given directly (exercises the gate's mechanism)
    def __init__(self, needs):
        self._needs = needs

    def realization_needs(self):
        return self._needs


def test_not_wired_mechanism_stays_new_goes_legacy_sticky_stops_typed_before_any_llm_call(monkeypatch):
    """The NOT_YET_WIRED_MODULES mechanism stays for a future module (here: AlloyDB put back by monkeypatch). A new
    workload goes legacy with the logged IAC.TYPE_NOT_WIRED_YET; a sticky workload cannot go legacy, so it stops typed
    (GATE_UNAVAILABLE) before any LLM call instead of a doomed repair loop (Fable 10-22 note)."""
    from developer_agent.compute_intent import ComputeIntent
    from shared.diagnostics import ErrorClass, StageError
    from test_typed_iac_ti3_contract import _runtime
    monkeypatch.setattr(II, "NOT_YET_WIRED_MODULES", frozenset({"database-alloydb"}))
    assert C.not_wired_types(ART) == {"google_alloydb_cluster", "google_alloydb_instance"}
    assert C.not_wired_slots(_StubVt({"x": ("google_alloydb_instance", ())}), ART) == ["x"]
    assert C.not_wired_slots(_StubVt({"db": ("google_sql_database_instance", ())}), ART) == []
    agent = _agent(_runtime(None, iac_intent_mode="generate"))
    agent.genai_client = _NoCallGenai()   # any LLM call would fail the test
    ci = MagicMock(spec=ComputeIntent)
    ci.topology = _StubVt({"x": ("google_alloydb_instance", ())})
    ready = {"provider_versions": Client().ready()["provider_versions"]}
    with patch("developer_agent.handler.logger") as log:
        assert agent._resolve_intent_run(ci, {}, ready) is None
    assert any(C.NOT_WIRED_YET in str(c) for c in log.warning.call_args_list)
    sticky = {C.INTENT_PATH: intent([]), C.RENDER_PATH: "{}\n"}
    with pytest.raises(StageError) as ei:
        agent._resolve_intent_run(ci, sticky, ready)
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE and C.NOT_WIRED_YET in str(ei.value)
    # Do No Harm: without a not-wired slot the sticky workload resolves its run as before
    ci.topology = vt_of(topo([CLOUDSQL]))
    assert agent._resolve_intent_run(ci, sticky, ready) is not None


@pytest.mark.parametrize("mid", sorted(NETWORK_MODULES))
def test_each_network_module_renders_with_the_platform_network(mid):
    var, fact = NETWORK_MODULES[mid]
    ctx = C.intent_context(None, network_facts=FACTS)
    res = II.validate_intent(intent(modules=[{"module": mid, "name": "m", "args": {}}]), ART, ctx)
    assert res.ok, res.codes
    rr = II.render_intent(res.validated)
    body = json.loads(rr.files[C.RENDER_PATH])["module"]["m"]
    assert body[var] == "${" + II.NETWORK_FACT_EXPRS[fact] + "}"
    assert body["depends_on"] == ["module." + II.PLATFORM_NETWORK_MODULE]   # waits for the PSA peering
    net = json.loads(rr.files[C.FACTS_RENDER_PATH])
    mod = net["module"][II.PLATFORM_NETWORK_MODULE]
    assert mod["source"] == "../modules/networking-vpc" and mod["primary_subnet_cidr"] == "${var.subnet_cidr}"
    assert mod["enable_private_service_access"] is True
    assert "resource" not in net            # no connector without a Cloud Run consumer of Cloud SQL / Redis
    assert rr.platform_modules == ("networking-vpc",)
    if fact == "network_by_project_number":
        assert net["data"]["google_project"]["stackvend_intent_project"] == {"project_id": "${var.project_id}"}


def test_bigtable_zone_is_a_platform_data_source_not_a_literal():
    ctx = C.intent_context(None)   # no IPAM facts needed for the zone
    res = II.validate_intent(intent(modules=[{"module": "database-bigtable", "name": "bt", "args": {}}]), ART, ctx)
    assert res.ok, res.codes
    rr = II.render_intent(res.validated)
    body = json.loads(rr.files[C.RENDER_PATH])["module"]["bt"]
    assert body["zone"] == "${element(sort(data.google_compute_zones.stackvend_intent_zones.names), 0)}"
    data = json.loads(rr.files[C.FACTS_RENDER_PATH])
    assert data["data"]["google_compute_zones"]["stackvend_intent_zones"] == {"project": "${var.project_id}",
                                                                              "region": "${var.region}"}
    assert "module" not in data and rr.platform_modules == ()


@pytest.mark.parametrize("mid", sorted(NETWORK_MODULES) + ["database-bigtable"])
def test_an_ai_supplied_network_or_zone_value_is_refused(mid):
    var = NETWORK_MODULES.get(mid, ("zone",))[0]
    ctx = C.intent_context(None, network_facts=FACTS)
    for value in ("projects/p/global/networks/default", {"$ref": {"kind": "fact", "fact": "project_id"}}):
        res = II.validate_intent(intent(modules=[{"module": mid, "name": "m", "args": {var: value}}]), ART, ctx)
        assert "IAC.PLATFORM_OWNED_ARGUMENT" in res.codes, (mid, res.codes)
        assert not res.ok


def test_the_platform_network_module_name_is_reserved():
    ctx = C.intent_context(None, network_facts=FACTS)
    res = II.validate_intent(intent(modules=[dict(BUCKET_MODULE, name=II.PLATFORM_NETWORK_MODULE, realizes=None)]),
                             ART, ctx)
    assert "IAC.DUPLICATE_ADDRESS" in res.codes


def test_without_the_ipam_subnet_fact_a_network_module_stays_a_removable_typed_error():
    ctx = C.intent_context(None)   # no network facts this iteration
    res = II.validate_intent(intent(modules=[SQL_MODULE]), ART, ctx)
    assert "IAC.MODULE_FACT_UNAVAILABLE" in res.codes and not res.ok


def test_ti3g_cloudsql_never_gets_a_public_ip_with_the_network_facts():
    ctx = C.intent_context(None, network_facts=FACTS)
    sql = {"module": "database-cloudsql", "name": "db", "args": {}}
    bad = II.validate_intent(intent(modules=[dict(sql, args={"enable_public_ip": True})]), ART, ctx)
    assert "IAC.INVALID_VALUE" in bad.codes and not bad.ok
    ok = II.validate_intent(intent(modules=[sql]), ART, ctx)
    assert ok.ok, ok.codes
    body = json.loads(II.render_intent(ok.validated).files[C.RENDER_PATH])["module"]["db"]
    assert "enable_public_ip" not in body and body["private_network_id"].startswith("${module.stackvend_network.")


# ------------------------------------------------------------------------------------------------ purposes
def test_ipam_purposes_follow_the_intent_and_the_topology():
    vt = vt_of(topo([CLOUDSQL]))
    assert C.intent_network_purposes({C.INTENT_PATH: intent([SQL_MODULE])}, ART, vt) == {
        PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR, PF.PURPOSE_PSA}
    # AlloyDB that no service consumes: a network (with its PSA range), no connector (no Cloud Run consumer edge)
    alloy = {"module": "database-alloydb", "name": "adb", "args": {}}
    assert C.intent_network_purposes({C.INTENT_PATH: intent([alloy])}, ART, vt_of(topo([UPLOADS]))) == {
        PF.PURPOSE_SUBNET, PF.PURPOSE_PSA}
    # Do No Harm: no network module -> nothing allocated; unparseable / absent -> nothing
    assert C.intent_network_purposes({C.INTENT_PATH: intent([BUCKET_MODULE])}, ART, vt) == frozenset()
    assert C.intent_network_purposes({C.INTENT_PATH: "{not json"}, ART, vt) == frozenset()
    assert C.intent_network_purposes({}, ART, vt) == frozenset()
    # a sticky workload's committed intent counts when the draft wrote none
    assert C.intent_network_purposes({}, ART, vt, {C.INTENT_PATH: intent([SQL_MODULE])}) == {
        PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR, PF.PURPOSE_PSA}


# ------------------------------------------------------------------------------------------------ assembly
def test_cloudsql_and_redis_assemble_with_one_connector_and_vendor_the_network_module():
    vt = vt_of(topo([CLOUDSQL, REDIS]))
    asm, bound, files = _assemble_net(vt, {C.INTENT_PATH: intent([SQL_MODULE, REDIS_MODULE])})
    assert asm.diagnostics == (), [d.code for d in asm.diagnostics]
    assert asm.rendered == (C.RENDER_PATH, C.FACTS_RENDER_PATH)
    assert asm.modules == ("cache-redis", "database-cloudsql", "networking-vpc", "networking-vpc-connector")
    net = json.loads(files[C.FACTS_RENDER_PATH])
    conn = net["module"][II.PLATFORM_CONNECTOR_MODULE]   # FD-4BH: the golden connector module
    assert conn["connector_cidr"] == "${var.connector_cidr}" and conn["region"] == "${var.region}"
    assert conn["network"] == "${module.stackvend_network.network_name}"
    # CLOUDSQL-PASSWORD-BINDING (owner 11-14): a Cloud SQL consumer also reads the password secret id (typed path)
    assert bound.resource_bindings("shop") == {"DB_HOST": "module.db.private_ip_address",
                                               "DB_PASSWORD_SECRET_ID": "module.db.secret_id_password",
                                               "REDIS_HOST": "module.cache.host"}
    # without the connector fact the network is rendered but no connector
    asm2, _, files2 = _assemble_net(vt, {C.INTENT_PATH: intent([SQL_MODULE, REDIS_MODULE])}, SUBNET_ONLY)
    assert asm2.diagnostics == () and "resource" not in json.loads(files2[C.FACTS_RENDER_PATH])


def test_connector_reference_goes_only_to_cloud_run_consumers():
    from developer_agent.topology_wiring import private_network_consumers, topology_vpc_connector
    raw = topo([CLOUDSQL], services=(("shop", "cloudrun"), ("core", "cloudrun")), edges=(("shop", "core", "http"),))
    vt = vt_of(raw)
    _, bound, files = _assemble_net(vt, {C.INTENT_PATH: intent([SQL_MODULE])})
    assert private_network_consumers(bound) == {"shop"}
    assert topology_vpc_connector(bound, "shop", files) == II.PLATFORM_CONNECTOR_REF
    assert topology_vpc_connector(bound, "core", files) is None
    # a connection_name consumer needs the connector too (no public IP on the intent path, TI-3g)
    by_name = dict(CLOUDSQL, consumers=[{"service": "shop", "env_key": "DB_CONN", "attribute": "connection_name"}])
    vt2 = vt_of(topo([by_name]))
    _, bound2, files2 = _assemble_net(vt2, {C.INTENT_PATH: intent([SQL_MODULE])})
    assert topology_vpc_connector(bound2, "shop", files2) == II.PLATFORM_CONNECTOR_REF


def test_dnh_topologies_without_a_network_module_are_unchanged():
    """Do No Harm: an intent with no network-bound module renders exactly what it rendered before TI-5 (no network,
    no connector, no new file), and the legacy connector rule is untouched without the platform render."""
    from developer_agent.topology_wiring import topology_vpc_connector
    vt = vt_of(topo([UPLOADS]))
    asm0, _, files0, _ = _assemble(vt, {C.INTENT_PATH: intent([BUCKET_MODULE])})
    asm1, _, files1 = _assemble_net(vt, {C.INTENT_PATH: intent([BUCKET_MODULE])})
    assert files0 == files1 and asm0.modules == asm1.modules == ("storage-bucket",)
    assert C.FACTS_RENDER_PATH not in files1
    # a data-source fact alone still renders only the data block (the pre-TI-5 layout)
    pn = {"name": "pn", "value": {"$ref": {"kind": "fact", "fact": "project_number"}}}
    res = II.validate_intent(intent(outputs=[pn]), ART, C.intent_context(None, network_facts=FACTS))
    assert res.ok, res.codes
    rr = II.render_intent(res.validated)
    assert sorted(json.loads(rr.files[C.FACTS_RENDER_PATH])) == ["//", "data"] and rr.platform_modules == ()
    # the legacy (.tf) path: no platform render -> topology_vpc_connector keeps its HCL rule (here: nothing)
    assert topology_vpc_connector(vt_of(topo([CLOUDSQL])), "shop", {W + "main.tf": "# x\n"}) is None


# ------------------------------------------------------------------------------------------------ end to end
def _generate_net(draft, raw, provider, existing=None):
    from developer_agent import hallucination_runtime as hr
    from developer_agent import handler as h
    from shared.diagnostics import MemoryLedgerStore, MemoryProvenanceStore
    from shared.hallucination_stack import HallucinationStackSettings
    rt = hr.HallucinationRuntime(ledger_store=MemoryLedgerStore(), provenance_store=MemoryProvenanceStore(),
                                 validate_client=Client(), source="test", facts_provider=provider,
                                 settings=HallucinationStackSettings(iac_intent_mode="generate"))
    agent = _agent(rt)
    agent.genai_client = _NoCallGenai()
    plan = MagicMock()
    plan.execution_mode = [m for m in h.SwarmExecutionMode if m != h.SwarmExecutionMode.SOLO_FAST_PATH][0]
    plan.tasks = [MagicMock()]

    class FakeDispatcher:
        def __init__(self, *a, **k):
            self.last_file_attribution = {p: ("IAC_ENGINEER" if p == C.INTENT_PATH else "BACKEND") for p in draft}
            self.envelope_checks = [{"ok": True, "error": None}]
            self.iac_intent = None

        async def execute_phased_junior_swarm(self, *a, **k):
            return dict(draft)

    with patch.object(h, "LeadDeveloperOrchestrator") as lead, patch.object(h, "SwarmDispatcher", FakeDispatcher), \
            patch.object(agent, "fetch_existing_repo_files", return_value=dict(existing or {})), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")), \
            patch("shared.settings.get_platform_settings",
                  return_value=__import__("shared.settings", fromlist=["x"]).PlatformSettings()):
        lead.return_value.decompose_specification.return_value = plan
        files = agent.generate_code_files(product_id=PID, spec_text="shop with a database", task_dag=[],
                                          trace_id="t-ti5c", architect_compute_intent=record_of(raw),
                                          allow_unauthenticated=True, enable_direct_iap=False,
                                          domain_restricted_sharing=False)
    return agent, files


def _module_body(text, name):
    for m in hcl2.loads(text).get("module") or []:
        if name in m:
            return m[name]
    return None


def test_e2e_cloudsql_and_redis_on_the_intent_path_get_network_connector_and_ipam_facts():
    provider = PF.MemoryFactsProvider()
    draft = dict(APP, **{C.INTENT_PATH: intent([SQL_MODULE, REDIS_MODULE])})
    agent, files = _generate_net(draft, topo([CLOUDSQL, REDIS]), provider)
    assert agent.last_validation_report.status == "PASS", agent.last_validation_report
    assert sorted(provider.ledger) == [(PID, PF.PURPOSE_PSA), (PID, PF.PURPOSE_CONNECTOR), (PID, PF.PURPOSE_SUBNET)]
    compute = _module_body(files[W + "main.tf"], "compute")
    assert compute["vpc_access_connector"] == "${" + II.PLATFORM_CONNECTOR_REF + "}"
    assert compute["env_vars"]  # the consumers' bindings are rendered
    declared = {n for b in hcl2.loads(files[W + "variables.tf"])["variable"] for n in b}
    assert {"subnet_cidr", "connector_cidr"} <= declared
    tfvars = hcl2.loads(files[W + "terraform.tfvars"])
    assert tfvars["subnet_cidr"] == provider.ledger[(PID, PF.PURPOSE_SUBNET)]
    assert tfvars["connector_cidr"] == provider.ledger[(PID, PF.PURPOSE_CONNECTOR)]
    assert tfvars["psa_cidr"] == provider.ledger[(PID, PF.PURPOSE_PSA)]   # TI-5-F4
    net = json.loads(files[C.FACTS_RENDER_PATH])["module"][II.PLATFORM_NETWORK_MODULE]
    assert net["psa_address"] == "${cidrhost(var.psa_cidr, 0)}" and "var.psa_cidr" in net["psa_prefix_length"]
    assert {"vpcaccess.googleapis.com", "servicenetworking.googleapis.com"} <= set(tfvars["additional_apis"])
    assert any(p.startswith("infra/modules/networking-vpc/") for p in files)
    for p in (C.RENDER_PATH, C.FACTS_RENDER_PATH):
        assert "10.100." not in files[p]          # no CIDR literal in the renders (invariant 3)
    dump = os.environ.get("TI5_DUMP_TREE")
    if dump:   # evidence: docs/handoff/ti5-evidence (offline tofu validate / plan of this tree)
        for p, t in files.items():
            if isinstance(t, str) and (p.startswith("infra/") or p.startswith("apps/")):
                full = os.path.join(dump, p)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "w", encoding="utf-8") as fh:
                    fh.write(t)


def test_e2e_cloudsql_topology_is_no_longer_sent_to_the_legacy_path():
    from developer_agent.compute_intent import ComputeIntent
    from test_typed_iac_ti3_contract import _runtime
    agent = _agent(_runtime(None, iac_intent_mode="generate"))
    ci = MagicMock(spec=ComputeIntent)
    ci.topology = vt_of(topo([CLOUDSQL, REDIS]))
    ready = {"provider_versions": Client().ready()["provider_versions"]}
    assert agent._resolve_intent_run(ci, {}, ready) is not None


def test_e2e_bucket_only_intent_allocates_nothing_and_wires_no_connector():
    provider = PF.MemoryFactsProvider()
    draft = dict(APP, **{C.INTENT_PATH: intent([BUCKET_MODULE])})
    agent, files = _generate_net(draft, topo([UPLOADS]), provider)
    assert agent.last_validation_report.status == "PASS"
    assert provider.ledger == {}
    assert "vpc_access_connector" not in _module_body(files[W + "main.tf"], "compute")
    assert C.FACTS_RENDER_PATH not in files


def _dump(files, suffix):
    dump = os.environ.get("TI5_DUMP_TREE")
    if dump:   # evidence only (docs/handoff/ti5-evidence/offline_validate_plan.sh)
        for p, t in files.items():
            if isinstance(t, str) and p.startswith("infra/"):
                full = os.path.join(dump + suffix, p)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "w", encoding="utf-8") as fh:
                    fh.write(t)


def test_e2e_alloydb_vertex_and_bigtable_get_the_network_and_zone_but_no_connector():
    provider = PF.MemoryFactsProvider()
    mods = [{"module": "database-alloydb", "name": "adb", "args": {}},
            {"module": "ai-vertex-endpoint", "name": "vtx", "args": {}},
            {"module": "database-bigtable", "name": "bt", "args": {}}]
    agent, files = _generate_net(dict(APP, **{C.INTENT_PATH: intent(mods)}), topo(), provider)
    assert agent.last_validation_report.status == "PASS", agent.last_validation_report
    assert sorted(provider.ledger) == [(PID, PF.PURPOSE_PSA), (PID, PF.PURPOSE_SUBNET)]   # a network, no connector
    net = json.loads(files[C.FACTS_RENDER_PATH])
    assert "resource" not in net and II.PLATFORM_NETWORK_MODULE in net["module"]
    assert set(net["data"]) == {"google_compute_zones", "google_project"}
    assert "vpc_access_connector" not in _module_body(files[W + "main.tf"], "compute")
    for m in ("networking-vpc", "database-alloydb", "ai-vertex-endpoint", "database-bigtable"):
        assert any(p.startswith(f"infra/modules/{m}/") for p in files), m
    _dump(files, "-other")


def test_e2e_sticky_intent_workload_never_moves_a_committed_ipam_range():
    """A sticky intent workload's network is rendered from its committed IPAM facts: the same ledger value renders
    again; a ledger that returns another range stops the stage (GATE_UNAVAILABLE), never a silent range move."""
    from shared.diagnostics import ErrorClass, StageError
    provider = PF.MemoryFactsProvider()
    draft = dict(APP, **{C.INTENT_PATH: intent([SQL_MODULE])})
    agent, files = _generate_net(draft, topo([CLOUDSQL]), provider)
    committed = {p: files[p] for p in (C.INTENT_PATH, C.RENDER_PATH, C.FACTS_RENDER_PATH, W + "terraform.tfvars")}
    again = PF.MemoryFactsProvider(ledger=dict(provider.ledger))
    _, files2 = _generate_net(draft, topo([CLOUDSQL]), again, existing=committed)
    assert files2[W + "terraform.tfvars"] == files[W + "terraform.tfvars"]
    assert files2[C.FACTS_RENDER_PATH] == files[C.FACTS_RENDER_PATH]
    moved = PF.MemoryFactsProvider(ledger={(PID, PF.PURPOSE_SUBNET): "10.100.9.0/24",
                                           (PID, PF.PURPOSE_CONNECTOR): provider.ledger[(PID, PF.PURPOSE_CONNECTOR)]})
    with pytest.raises(StageError) as ei:
        _generate_net(draft, topo([CLOUDSQL]), moved, existing=committed)
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE


def test_ledger_mismatch_is_checked_reuse_only_before_any_allocation():
    """Fable RT F3: the committed purposes are resolved reuse-only and compared first, so a stage that stops on
    IPAM.LEDGER_MISMATCH never leaves a new allocation behind; a new purpose is allocated only after the check."""
    from shared.diagnostics import ErrorClass, StageError
    provider = PF.MemoryFactsProvider()
    draft = dict(APP, **{C.INTENT_PATH: intent([SQL_MODULE])})
    _, files = _generate_net(draft, topo([CLOUDSQL]), provider)
    subnet = provider.ledger[(PID, PF.PURPOSE_SUBNET)]
    committed = {p: files[p] for p in (C.INTENT_PATH, C.RENDER_PATH, C.FACTS_RENDER_PATH)}
    committed[W + "terraform.tfvars"] = f'subnet_cidr = "{subnet}"\n'   # committed before the connector existed
    # the ledger lost the subnet record: stop, and nothing at all is allocated (not the subnet, not the connector)
    empty = PF.MemoryFactsProvider()
    with pytest.raises(StageError) as ei:
        _generate_net(draft, topo([CLOUDSQL]), empty, existing=committed)
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE and empty.ledger == {}
    # the ledger holds the same subnet: it is reused (not re-allocated) and only the new connector is allocated
    same = PF.MemoryFactsProvider(ledger={(PID, PF.PURPOSE_SUBNET): subnet})
    _, files2 = _generate_net(draft, topo([CLOUDSQL]), same, existing=committed)
    assert same.ledger[(PID, PF.PURPOSE_SUBNET)] == subnet and (PID, PF.PURPOSE_CONNECTOR) in same.ledger
    tfv = hcl2.loads(files2[W + "terraform.tfvars"])
    assert tfv["subnet_cidr"] == subnet and tfv["connector_cidr"] == same.ledger[(PID, PF.PURPOSE_CONNECTOR)]
