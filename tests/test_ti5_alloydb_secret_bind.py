"""TI5-ALLOYDB-SECRET-BIND (owner 10-27). Hermetic.

Generate mode (typed intent): when a service consumes an AlloyDB instance (any attribute), the platform always binds the
instance's password secret id on that service (`<LOGICAL>_PASSWORD_SECRET_ID` = `module.<n>.secret_id_password`,
unless the architect already bound `password_secret_id` under its own key) and renders
`grant_workload_secret_access = true` on the realizing database-alloydb module when the intent leaves it out. Before:
the architect chose whether to bind it and in the 10-25 / 10-26 gates never did (0/3 S8 runs).
Typed tables only (shared/service_topology.TYPED_IMPLIED_ATTRIBUTES, shared/iac_intent.REALIZATION_REQUIRED_ARGS);
the classic path (no realizations) is unchanged."""
import hermetic_guard  # noqa: F401  (first import)
import json
import os
import sys

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from test_typed_iac_ti3_contract import APP, ART, PID, W, C, II, intent, topo, vt_of  # noqa: E402
from test_typed_iac_ti5c_network_facts import (CLOUDSQL, REDIS, REDIS_MODULE, SQL_MODULE,  # noqa: E402
                                               _assemble_net, _generate_net, _module_body)
from test_ti5_r2_typed_topology_psa import (ALLOYDB, ALLOYDB_MODULE, BIGTABLE, BIGTABLE_MODULE,  # noqa: E402
                                            PSA_FACTS, VERTEX, VERTEX_MODULE)
from shared import service_topology as ST  # noqa: E402
from developer_agent import platform_facts as PF  # noqa: E402
from developer_agent import topology_wiring as TW  # noqa: E402

KEY = "LEDGER_PASSWORD_SECRET_ID"
SECRET_REF = "module.ledger.secret_id_password"
# the recorded S8 shape (10-26 gate S8-r1): the architect binds only the AlloyDB address
S8_ALLOYDB = {"type": "google_alloydb_instance", "logical_name": "primary_instance", "purpose": "ledger database",
              "consumers": [{"service": "shop", "env_key": "ALLOYDB_IP", "attribute": "ip_address"}]}
S8_MODULE = {"module": "database-alloydb", "name": "primary_instance", "realizes": "primary_instance",
             "args": {"cpu_count": 2}}


def _render(vt, modules):
    asm, bound, files = _assemble_net(vt, {C.INTENT_PATH: intent(modules)}, PSA_FACTS)
    assert asm.diagnostics == (), [(d.code, d.message) for d in asm.diagnostics]
    return bound, files, json.loads(files[C.RENDER_PATH])


# ------------------------------------------------------------------------------------------------ the binding
def test_s8_shape_binds_the_password_secret_id_and_the_platform_renders_the_grant():
    vt = vt_of(topo([S8_ALLOYDB, VERTEX, BIGTABLE]))
    assert vt.implied_consumers() == (("shop", "google_alloydb_instance", "primary_instance", "password_secret_id",
                                       "PRIMARY_INSTANCE_PASSWORD_SECRET_ID"),)
    bound, files, doc = _render(vt, [S8_MODULE, VERTEX_MODULE, BIGTABLE_MODULE])
    env = bound.resource_bindings("shop")
    assert env["ALLOYDB_IP"] == "module.primary_instance.ip_address"
    assert env["PRIMARY_INSTANCE_PASSWORD_SECRET_ID"] == "module.primary_instance.secret_id_password"
    body = doc["module"]["primary_instance"]
    assert body["grant_workload_secret_access"] is True
    assert body["workload_sa_email"] == "${module.foundation.workload_sa_email}"
    assert body["cpu_count"] == 2                                    # the AI's own args are rendered as written


def test_an_intent_that_sets_the_grant_itself_renders_byte_identically():
    vt = vt_of(topo([ALLOYDB]))
    _, f1, _ = _render(vt, [ALLOYDB_MODULE])
    _, f2, _ = _render(vt, [dict(ALLOYDB_MODULE, args={"grant_workload_secret_access": True})])
    d1, d2 = json.loads(f1[C.RENDER_PATH]), json.loads(f2[C.RENDER_PATH])
    d1.pop("//"), d2.pop("//")                                       # the header carries the intent sha
    assert d1 == d2


def test_the_architects_own_key_wins_and_nothing_is_bound_twice():
    own = dict(ALLOYDB, consumers=ALLOYDB["consumers"] + [{"service": "shop", "env_key": "LEDGER_DB_PASSWORD",
                                                             "attribute": "password_secret_id"}])
    vt = vt_of(topo([own]))
    assert vt.implied_consumers() == ()
    bound, _, _ = _render(vt, [ALLOYDB_MODULE])
    assert bound.resource_bindings("shop") == {"LEDGER_DB_HOST": "module.ledger.ip_address",
                                               "LEDGER_DB_PASSWORD": SECRET_REF}


def test_every_consuming_service_gets_it_and_the_key_is_per_instance():
    two = topo([dict(ALLOYDB, consumers=[{"service": "shop", "env_key": "LEDGER_DB_HOST", "attribute": None},
                                         {"service": "api", "env_key": "DB_HOST", "attribute": None}])],
               services=(("shop", "cloudrun"), ("api", "cloudrun")))
    vt = vt_of(two)
    bound, _, _ = _render(vt, [ALLOYDB_MODULE])
    assert bound.resource_bindings("shop")[KEY] == SECRET_REF
    assert bound.resource_bindings("api")[KEY] == SECRET_REF


# ------------------------------------------------------------------------------------------------ negatives
def test_negative_a_service_that_does_not_consume_alloydb_gets_no_binding():
    raw = topo([ALLOYDB, dict(CLOUDSQL, consumers=[{"service": "api", "env_key": "SQL_HOST",
                                                     "attribute": "private_ip_address"}])],
               services=(("shop", "cloudrun"), ("api", "cloudrun")))
    vt = vt_of(raw)
    bound, _, _ = _render(vt, [ALLOYDB_MODULE, SQL_MODULE])
    assert KEY in bound.resource_bindings("shop")
    # CLOUDSQL-PASSWORD-BINDING (owner 11-14): api reads its own Cloud SQL password secret id, never AlloyDB's
    assert KEY not in bound.resource_bindings("api") and vt.typed_only_env_keys("api") == ("DB_PASSWORD_SECRET_ID",)


def test_negative_an_unconsumed_alloydb_gets_no_binding_and_no_grant():
    vt = vt_of(topo([dict(ALLOYDB, consumers=[])]))
    assert vt.implied_consumers() == () and vt.realization_needs() == {"ledger": ("google_alloydb_instance", ())}
    _, _, doc = _render(vt, [ALLOYDB_MODULE])
    assert "grant_workload_secret_access" not in doc["module"]["ledger"]


def test_negative_a_kind_without_env_vars_gets_no_implied_binding():
    raw = topo([dict(ALLOYDB, consumers=[{"service": "gk", "env_key": "LEDGER_DB_HOST", "attribute": None}])],
               services=(("gk", "gke-autopilot"),), primary="gk")
    vt, _ = ST.validate_service_topology(raw, product_id=PID)
    assert vt is not None and vt.implied_consumers() == () and vt.typed_only_env_keys("gk") == ()


def test_negative_a_derived_key_never_shadows_another_binding():
    """The architect already uses LEDGER_PASSWORD_SECRET_ID on shop for something else: it keeps it (not bound)."""
    secret = {"type": "google_secret_manager_secret", "logical_name": "other", "purpose": "x",
              "consumers": [{"service": "shop", "env_key": KEY, "attribute": None}]}
    vt = vt_of(topo([ALLOYDB, secret]))
    assert vt.implied_consumers() == ()
    # two instances on one service: one key each (the logical names are unique per type, so the keys are too)
    b = dict(ALLOYDB, logical_name="archive", consumers=[{"service": "shop", "env_key": "ARCHIVE_HOST",
                                                          "attribute": None}])
    assert [x[4] for x in vt_of(topo([ALLOYDB, b])).implied_consumers()] == [KEY, "ARCHIVE_PASSWORD_SECRET_ID"]


def test_negative_the_classic_path_binds_nothing_new_and_is_byte_identical(monkeypatch):
    """Mode off: the unbound topology (no realizations) and the classic developer contract are exactly what they were
    with the implied table emptied."""
    raws = [topo([ALLOYDB, VERTEX, BIGTABLE]), topo([S8_ALLOYDB]), topo([CLOUDSQL])]
    now = [(vt_of(r).env_for("shop"), TW.topology_contract_rule(vt_of(r), iac_intent=False)) for r in raws]
    monkeypatch.setattr(ST, "TYPED_IMPLIED_ATTRIBUTES", {})
    before = [(vt_of(r).env_for("shop"), TW.topology_contract_rule(vt_of(r), iac_intent=False)) for r in raws]
    assert now == before
    assert "PASSWORD_SECRET_ID" not in now[0][1] and "Secret Manager" not in now[0][1]


def test_negative_non_alloydb_typed_renders_bindings_and_prompts_unchanged(monkeypatch):
    """Do No Harm: every type outside the table (Redis here; Cloud SQL has its own row since CLOUDSQL-PASSWORD-BINDING,
    owner 11-14) renders, binds and prompts byte-identically with the implied table emptied."""
    vt = vt_of(topo([REDIS]))
    now = (_assemble_net(vt, {C.INTENT_PATH: intent([REDIS_MODULE])}, PSA_FACTS), C.topology_slot_lines(vt),
           TW.topology_contract_rule(vt, iac_intent=True))
    monkeypatch.setattr(ST, "TYPED_IMPLIED_ATTRIBUTES", {})
    before = (_assemble_net(vt, {C.INTENT_PATH: intent([REDIS_MODULE])}, PSA_FACTS), C.topology_slot_lines(vt),
              TW.topology_contract_rule(vt, iac_intent=True))
    (asm1, b1, f1), l1, t1 = now
    (asm0, b0, f0), l0, t0 = before
    assert f1 == f0 and l1 == l0 and t1 == t0 and b1.resource_bindings("shop") == b0.resource_bindings("shop")


def test_negative_a_context_without_topology_attributes_renders_as_before():
    """The renderer adds nothing for a context that carries no topology attributes (every caller before this row)."""
    vt = vt_of(topo([ALLOYDB]))
    raw = intent([ALLOYDB_MODULE])
    ctx = C.intent_context(vt, network_facts=PSA_FACTS)
    bare = II.IntentContext(**{f: getattr(ctx, f) for f in ctx.__dataclass_fields__ if f != "topology_attributes"})
    assert bare.topology_attributes == {}
    doc = json.loads(II.render_intent(II.validate_intent(raw, ART, bare).validated).files[C.RENDER_PATH])
    assert "grant_workload_secret_access" not in doc["module"]["ledger"]
    # and a module that realizes no topology resource never gets a platform argument
    free = dict(ALLOYDB_MODULE, name="spare", realizes=None)
    gate = II.validate_intent(intent([ALLOYDB_MODULE, free]), ART, ctx)
    assert gate.ok, gate.codes
    assert "grant_workload_secret_access" not in json.loads(
        II.render_intent(gate.validated).files[C.RENDER_PATH])["module"]["spare"]


# ------------------------------------------------------------------------------------------------ determinism / contract
def test_render_is_deterministic_from_the_intent_and_its_context():
    vt = vt_of(topo([S8_ALLOYDB, VERTEX, BIGTABLE]))
    ctx = C.intent_context(vt, network_facts=PSA_FACTS)
    assert ctx.topology_attributes == {k: a for k, (_t, a) in vt.realization_needs().items()}
    raw = intent([S8_MODULE, VERTEX_MODULE, BIGTABLE_MODULE])
    r1 = II.render_intent(II.validate_intent(raw, ART, ctx).validated).files
    r2 = II.render_intent(II.validate_intent(raw, ART, C.intent_context(vt, network_facts=PSA_FACTS)).validated).files
    assert r1 == r2


def test_developer_contract_names_the_key_and_what_it_holds_on_the_typed_path_only():
    vt = vt_of(topo([S8_ALLOYDB]))
    typed = TW.topology_contract_rule(vt, iac_intent=True)
    classic = TW.topology_contract_rule(vt, iac_intent=False)
    assert "with exactly these names: ALLOYDB_IP, PRIMARY_INSTANCE_PASSWORD_SECRET_ID;" in typed
    assert ("- `PRIMARY_INSTANCE_PASSWORD_SECRET_ID` on `shop` is " + ST.MODULE_ONLY_ATTRIBUTE_NOTES[
        ("google_alloydb_instance", "password_secret_id")] + ".") in typed
    assert "PRIMARY_INSTANCE_PASSWORD_SECRET_ID" not in classic and "Secret Manager" not in classic
    # the IaC slot line states the grant (the platform also renders it when the intent leaves it out)
    assert ("`primary_instance` (google_alloydb_instance; services read ip_address, password_secret_id; realize it "
            "with golden module database-alloydb with grant_workload_secret_access: true)") in "\n".join(
        C.topology_slot_lines(vt))


def test_tables_are_exact_and_name_only_module_only_attributes():
    for rtype, rows in ST.TYPED_IMPLIED_ATTRIBUTES.items():
        for attr, suffix in rows:
            assert attr in ST.MODULE_ONLY_ATTRIBUTES[rtype] and attr in dict(ST.BOOTSTRAP_CATALOG[rtype])
            assert any(t == rtype and attr in row for (_m, t), row in II.REALIZATION_EXPORTS.items())
            assert (rtype, attr) in ST.MODULE_ONLY_ATTRIBUTE_NOTES
            assert ST._env_key_ok("A_" + suffix)
    for (rtype, attr) in ST.MODULE_ONLY_ATTRIBUTE_NOTES:
        assert attr in ST.MODULE_ONLY_ATTRIBUTES[rtype]


def test_e2e_s8_shape_generate_mode_passes_and_wires_the_secret():
    provider = PF.MemoryFactsProvider()
    agent, files = _generate_net(dict(APP, **{C.INTENT_PATH: intent([ALLOYDB_MODULE])}), topo([ALLOYDB]), provider)
    assert agent.last_validation_report.status == "PASS", agent.last_validation_report
    compute = _module_body(files[W + "main.tf"], "compute")
    env = str(compute["env_vars"])
    assert KEY in env and SECRET_REF in env and "LEDGER_DB_HOST" in env
    assert json.loads(files[C.RENDER_PATH])["module"]["ledger"]["grant_workload_secret_access"] is True
