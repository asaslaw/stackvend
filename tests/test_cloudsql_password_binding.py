"""CLOUDSQL-PASSWORD-BINDING (owner 11-14, P3-b of docs/handoff/ti-5-r2-p13-report.md). Hermetic.

Generate mode (typed intent): when a service consumes a Cloud SQL instance (any attribute; Postgres or MySQL, one golden
module database-cloudsql), the platform binds the instance's password secret id on that service
(`<LOGICAL>_PASSWORD_SECRET_ID` = `module.<n>.secret_id_password`, unless the architect already bound
`password_secret_id` under its own key) and renders `grant_workload_secret_access = true` on the realizing module when
the intent leaves it out, exactly as TI5-ALLOYDB-SECRET-BIND does for AlloyDB. Before: a typed Cloud SQL consumer had no
way to read the generated password (live ex08-1114, docs/handoff/ex08-1114-qa-routing-diagnosis.md). Exact table rows
only (shared/service_topology BOOTSTRAP_CATALOG, MODULE_ONLY_ATTRIBUTES, TYPED_IMPLIED_ATTRIBUTES,
MODULE_ONLY_ATTRIBUTE_NOTES, CATALOG_NOTES; shared/iac_intent REALIZATION_EXPORTS, REALIZATION_REQUIRED_ARGS). The
classic path (no realizations) binds nothing new."""
import hermetic_guard  # noqa: F401  (first import)
import json
import os
import sys

import hcl2
import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from test_typed_iac_ti3_contract import APP, ART, REPO_ROOT, W, C, II, intent, topo, vt_of  # noqa: E402
from test_typed_iac_ti5c_network_facts import _assemble_net, _generate_net, _module_body  # noqa: E402
from test_ti5_r2_typed_topology_psa import PSA_FACTS  # noqa: E402
from shared import service_topology as ST  # noqa: E402
from developer_agent import platform_facts as PF  # noqa: E402
from developer_agent import topology_wiring as TW  # noqa: E402

SQL = "google_sql_database_instance"
KEY = "POSTGRES_PASSWORD_SECRET_ID"
SECRET_REF = "module.postgres.secret_id_password"
# the recorded ex08-1114 shape: the architect binds the address and the connection name, never the password
EX08_DB = {"type": SQL, "logical_name": "postgres", "purpose": "order database",
           "consumers": [{"service": "shop", "env_key": "DB_HOST", "attribute": "private_ip_address"},
                         {"service": "shop", "env_key": "INSTANCE_CONNECTION_NAME", "attribute": "connection_name"}]}
EX08_MODULE = {"module": "database-cloudsql", "name": "postgres", "realizes": "postgres",
               "args": {"grant_workload_secret_access": True}}
BARE_MODULE = dict(EX08_MODULE, args={})
# the tables as they were before this row (the Do No Harm baseline)
PRE_CATALOG = (("connection_name", "string"), ("private_ip_address", "string"))


def _without_rows(monkeypatch):
    """Remove exactly this row's Cloud SQL entries from every table (pre-row behaviour)."""
    monkeypatch.setattr(ST, "BOOTSTRAP_CATALOG", dict(ST.BOOTSTRAP_CATALOG, **{SQL: PRE_CATALOG}))
    only = {k: v for k, v in ST.MODULE_ONLY_ATTRIBUTES.items() if k != SQL}
    for mod in (ST, II, C):
        monkeypatch.setattr(mod, "MODULE_ONLY_ATTRIBUTES", only)
    monkeypatch.setattr(ST, "TYPED_IMPLIED_ATTRIBUTES",
                        {k: v for k, v in ST.TYPED_IMPLIED_ATTRIBUTES.items() if k != SQL})
    monkeypatch.setattr(ST, "MODULE_ONLY_ATTRIBUTE_NOTES",
                        {k: v for k, v in ST.MODULE_ONLY_ATTRIBUTE_NOTES.items() if k[0] != SQL})
    monkeypatch.setattr(ST, "CATALOG_NOTES", {k: v for k, v in ST.CATALOG_NOTES.items() if k != SQL})
    monkeypatch.setattr(II, "REALIZATION_EXPORTS", {**II.REALIZATION_EXPORTS, ("database-cloudsql", SQL): {
        "connection_name": "instance_connection_name", "private_ip_address": "private_ip_address"}})
    monkeypatch.setattr(II, "REALIZATION_REQUIRED_ARGS",
                        {k: v for k, v in II.REALIZATION_REQUIRED_ARGS.items() if k[1] != SQL})


def _render(vt, modules):
    asm, bound, files = _assemble_net(vt, {C.INTENT_PATH: intent(modules)}, PSA_FACTS)
    assert asm.diagnostics == (), [(d.code, d.message) for d in asm.diagnostics]
    return bound, files, json.loads(files[C.RENDER_PATH])


# ------------------------------------------------------------------------------------------------ the binding
def test_ex08_shape_binds_the_password_secret_id():
    vt = vt_of(topo([EX08_DB]))
    assert vt.implied_consumers() == (("shop", SQL, "postgres", "password_secret_id", KEY),)
    assert vt.realization_needs() == {"postgres": (SQL, ("connection_name", "password_secret_id",
                                                         "private_ip_address"))}
    bound, _, doc = _render(vt, [EX08_MODULE])
    assert bound.resource_bindings("shop") == {"DB_HOST": "module.postgres.private_ip_address",
                                               "INSTANCE_CONNECTION_NAME": "module.postgres.instance_connection_name",
                                               KEY: SECRET_REF}
    body = doc["module"]["postgres"]
    assert body["grant_workload_secret_access"] is True
    assert body["workload_sa_email"] == "${module.foundation.workload_sa_email}"


def test_a_left_out_grant_is_rendered_by_the_platform_byte_identically():
    vt = vt_of(topo([EX08_DB]))
    _, f1, d1 = _render(vt, [BARE_MODULE])
    _, f2, d2 = _render(vt, [EX08_MODULE])
    assert d1["module"]["postgres"]["grant_workload_secret_access"] is True
    d1.pop("//"), d2.pop("//")                                       # the header carries the intent sha
    assert d1 == d2


def test_a_stated_false_grant_is_a_typed_finding_never_overridden():
    vt = vt_of(topo([EX08_DB]))
    asm, _, _ = _assemble_net(vt, {C.INTENT_PATH: intent([dict(EX08_MODULE, args={
        "grant_workload_secret_access": False})])}, PSA_FACTS)
    assert [d.code for d in asm.diagnostics] == ["IAC.REALIZATION_ARGUMENT_REQUIRED"]


def test_mysql_uses_the_same_module_and_the_same_binding():
    vt = vt_of(topo([dict(EX08_DB, logical_name="orders_db")]))
    bound, _, doc = _render(vt, [dict(BARE_MODULE, name="orders_db", realizes="orders_db",
                                      args={"database_version": "MYSQL_8_0"})])
    assert bound.resource_bindings("shop")["ORDERS_DB_PASSWORD_SECRET_ID"] == "module.orders_db.secret_id_password"
    assert doc["module"]["orders_db"]["database_version"] == "MYSQL_8_0"
    assert doc["module"]["orders_db"]["grant_workload_secret_access"] is True


def test_the_architects_own_key_wins_and_nothing_is_bound_twice():
    own = dict(EX08_DB, consumers=EX08_DB["consumers"] + [{"service": "shop", "env_key": "DB_PASSWORD_SECRET",
                                                             "attribute": "password_secret_id"}])
    vt = vt_of(topo([own]))
    assert vt.implied_consumers() == ()
    bound, _, _ = _render(vt, [EX08_MODULE])
    assert bound.resource_bindings("shop")["DB_PASSWORD_SECRET"] == SECRET_REF
    assert KEY not in bound.resource_bindings("shop")


def test_every_consuming_service_gets_it():
    two = topo([dict(EX08_DB, consumers=[{"service": "shop", "env_key": "DB_HOST", "attribute": None},
                                         {"service": "api", "env_key": "DB_HOST", "attribute": None}])],
               services=(("shop", "cloudrun"), ("api", "cloudrun")))
    bound, _, _ = _render(vt_of(two), [EX08_MODULE])
    assert bound.resource_bindings("shop")[KEY] == SECRET_REF and bound.resource_bindings("api")[KEY] == SECRET_REF


def test_developer_contract_names_the_key_and_what_it_holds_on_the_typed_path_only():
    vt = vt_of(topo([EX08_DB]))
    typed = TW.topology_contract_rule(vt, iac_intent=True)
    classic = TW.topology_contract_rule(vt, iac_intent=False)
    note = ST.MODULE_ONLY_ATTRIBUTE_NOTES[(SQL, "password_secret_id")]
    assert f"- `{KEY}` on `shop` is {note}." in typed
    assert KEY in typed.split("with exactly these names:")[1].split(";")[0]
    assert "`db_user`" in note and "`app_user`" in note and "Secret Manager API" in note
    assert "`database_name`" in note and "`app_db`" in note
    assert KEY not in classic and "Secret Manager" not in classic
    assert ("`postgres` (google_sql_database_instance; services read connection_name, password_secret_id, "
            "private_ip_address; realize it with golden module database-cloudsql with "
            "grant_workload_secret_access: true)") in "\n".join(C.topology_slot_lines(vt))


def test_e2e_ex08_shape_generate_mode_passes_and_renders_the_secret_binding():
    provider = PF.MemoryFactsProvider()
    agent, files = _generate_net(dict(APP, **{C.INTENT_PATH: intent([BARE_MODULE])}), topo([EX08_DB]), provider)
    assert agent.last_validation_report.status == "PASS", agent.last_validation_report
    env = str(_module_body(files[W + "main.tf"], "compute")["env_vars"])
    assert KEY in env and SECRET_REF in env and "DB_HOST" in env
    assert json.loads(files[C.RENDER_PATH])["module"]["postgres"]["grant_workload_secret_access"] is True


# ------------------------------------------------------------------------------------------------ completeness
def _module_outputs(mid):
    with open(os.path.join(REPO_ROOT, "infra", "modules", mid, "outputs.tf"), encoding="utf-8") as fh:
        return {k: v for o in hcl2.load(fh).get("output", []) for k, v in o.items()}


def test_every_database_password_type_has_a_binding_row():
    """The next database type cannot repeat the ex08 gap: each DATABASE_PASSWORD_TYPES type has an implied
    password_secret_id row, its note, a realizing golden module that exports secret_id_password, and the grant."""
    for rtype in ST.DATABASE_PASSWORD_TYPES:
        assert ("password_secret_id", "PASSWORD_SECRET_ID") in ST.TYPED_IMPLIED_ATTRIBUTES.get(rtype, ()), rtype
        assert "password_secret_id" in ST.MODULE_ONLY_ATTRIBUTES[rtype]
        assert ("password_secret_id", "string") in ST.BOOTSTRAP_CATALOG[rtype]
        assert (rtype, "password_secret_id") in ST.MODULE_ONLY_ATTRIBUTE_NOTES
        mods = [mid for (mid, t), row in II.REALIZATION_EXPORTS.items()
                if t == rtype and row.get("password_secret_id") == "secret_id_password"]
        assert mods, rtype
        for mid in mods:
            assert "secret_id_password" in _module_outputs(mid)
            assert II.REALIZATION_REQUIRED_ARGS[(mid, rtype)]["password_secret_id"] == {
                "grant_workload_secret_access": True}


def test_every_golden_module_that_outputs_a_password_secret_and_realizes_a_type_binds_it():
    """The reverse direction: a realizing golden module with a `secret_id_password` output maps it for its type, and
    that type is a DATABASE_PASSWORD_TYPES type."""
    realizing = {mid for (mid, _t) in II.REALIZATION_EXPORTS}
    found = []
    for mid in sorted(os.listdir(os.path.join(REPO_ROOT, "infra", "modules"))):
        if not os.path.isfile(os.path.join(REPO_ROOT, "infra", "modules", mid, "outputs.tf")):
            continue
        if "secret_id_password" in _module_outputs(mid) and mid in realizing:
            found.append(mid)
            for (m, rtype), row in II.REALIZATION_EXPORTS.items():
                if m == mid:
                    assert row.get("password_secret_id") == "secret_id_password", (mid, rtype)
                    assert rtype in ST.DATABASE_PASSWORD_TYPES, (mid, rtype)
    assert {"database-cloudsql", "database-alloydb"} <= set(found)


# ------------------------------------------------------------------------------------------------ negatives
def test_negative_the_default_attribute_is_unchanged():
    assert ST.BOOTSTRAP_CATALOG[SQL][0] == ("connection_name", "string")
    assert ST.BOOTSTRAP_CATALOG[SQL][:2] == PRE_CATALOG


def test_negative_a_service_that_does_not_consume_cloudsql_gets_no_binding():
    raw = topo([EX08_DB], services=(("shop", "cloudrun"), ("api", "cloudrun")))
    vt = vt_of(raw)
    bound, _, _ = _render(vt, [EX08_MODULE])
    assert KEY in bound.resource_bindings("shop")
    assert KEY not in bound.resource_bindings("api") and vt.typed_only_env_keys("api") == ()


def test_negative_an_unconsumed_cloudsql_gets_no_binding_and_no_grant():
    vt = vt_of(topo([dict(EX08_DB, consumers=[])]))
    assert vt.implied_consumers() == () and vt.realization_needs() == {"postgres": (SQL, ())}
    _, _, doc = _render(vt, [BARE_MODULE])
    assert "grant_workload_secret_access" not in doc["module"]["postgres"]


def test_negative_a_kind_without_env_vars_gets_no_implied_binding():
    raw = topo([dict(EX08_DB, consumers=[{"service": "gk", "env_key": "DB_HOST", "attribute": None}])],
               services=(("gk", "gke-autopilot"),), primary="gk")
    vt, _ = ST.validate_service_topology(raw, product_id="shop")
    assert vt is not None and vt.implied_consumers() == () and vt.typed_only_env_keys("gk") == ()


def test_negative_a_derived_key_never_shadows_another_binding():
    secret = {"type": "google_secret_manager_secret", "logical_name": "other", "purpose": "x",
              "consumers": [{"service": "shop", "env_key": KEY, "attribute": None}]}
    assert vt_of(topo([EX08_DB, secret])).implied_consumers() == ()


def test_negative_the_classic_path_binds_nothing_new_and_is_byte_identical(monkeypatch):
    """Mode off (no realizations): the topology env and the classic developer contract are exactly what they were
    without this row."""
    raws = [topo([EX08_DB]), topo([dict(EX08_DB, consumers=[EX08_DB["consumers"][0]])])]
    now = [(vt_of(r).env_for("shop"), TW.topology_contract_rule(vt_of(r), iac_intent=False)) for r in raws]
    _without_rows(monkeypatch)
    before = [(vt_of(r).env_for("shop"), TW.topology_contract_rule(vt_of(r), iac_intent=False)) for r in raws]
    assert now == before
    assert all(KEY not in env and "Secret Manager" not in text for env, text in now)


def test_negative_other_types_render_bind_and_prompt_byte_identically(monkeypatch):
    """Do No Harm: a typed workload without Cloud SQL (a bucket and Redis) renders, binds and prompts exactly as
    without this row."""
    from test_typed_iac_ti3_contract import BUCKET_MODULE, UPLOADS
    from test_typed_iac_ti5c_network_facts import REDIS, REDIS_MODULE
    vt = vt_of(topo([UPLOADS, REDIS]))
    mods = [BUCKET_MODULE, REDIS_MODULE]

    def snap():
        asm, b, f = _assemble_net(vt, {C.INTENT_PATH: intent(mods)}, PSA_FACTS)
        return asm.diagnostics, f, b.resource_bindings("shop"), C.topology_slot_lines(vt), \
            TW.topology_contract_rule(vt, iac_intent=True)
    now = snap()
    _without_rows(monkeypatch)
    assert snap() == now


def test_negative_the_architect_contract_changes_only_the_cloudsql_entry(monkeypatch):
    now = ST.render_topology_contract()
    _without_rows(monkeypatch)
    before = ST.render_topology_contract()
    new = ("`google_sql_database_instance` (connection_name/private_ip_address/password_secret_id; password_secret_id "
           "is the Secret Manager secret id of the database user's password (typed infrastructure only))")
    assert now != before
    assert now == before.replace("`google_sql_database_instance` (connection_name/private_ip_address)", new)


# ------------------------------------------------------------------------------------------------ the live run (08a)
CORPUS_08A = "08a-cloudsql-password-binding-on-platform-render.json"


def test_corpus_08a_without_this_row_stops_on_the_platform_render_as_live(monkeypatch):
    """The scenario corpus fixture 08a (live ex08-1114) replayed with this row's table entries removed takes the live
    route: the binding is not rendered, the judge's INFRA-04 finding on topology.json stands and QA stops as
    PLATFORM_DEFECT QA_FINDING_ON_PLATFORM_RENDERED_FILE, with no developer seed on a platform render. With the row
    (tests/test_scenario_replay_corpus.py) the binding is rendered, the finding does not arise and the run passes."""
    pytest.importorskip("google.genai")
    import scenario_replay as SR
    sc = SR.load_scenario(os.path.join(SR.CORPUS_DIR, CORPUS_08A))
    _without_rows(monkeypatch)
    replay = SR.run_scenario(sc, monkeypatch)
    pre = {"status_not": "SUCCESS", "error_class": "PLATFORM_DEFECT", "reason": "QA_FINDING_ON_PLATFORM_RENDERED_FILE",
           "qa_attempts": 1}
    assert SR._outcome_matches(replay, pre, sc["trace"]) == [], SR.summarize(replay)
    assert SR.invariant_problems(replay, sc) == [], SR.summarize(replay)
    tested = replay.commits[replay.qa_runs(sc["trace"])[0]["commit_sha"]]
    assert KEY not in tested[W + "main.tf"]
    for d in replay.dispatches(sc["trace"]):
        assert not [s for s in (d.get("qa_plan") or {}).get("seeds") or []
                    if s.get("file") in (W + "topology.json", W + "main.tf")]


def test_corpus_08a_with_the_row_renders_the_binding_into_the_tested_tree(monkeypatch):
    pytest.importorskip("google.genai")
    import scenario_replay as SR
    sc = SR.load_scenario(os.path.join(SR.CORPUS_DIR, CORPUS_08A))
    replay = SR.run_scenario(sc, monkeypatch)
    assert SR.check_expectations(replay, sc) == [], SR.summarize(replay)
    tested = replay.commits[replay.qa_runs(sc["trace"])[0]["commit_sha"]]
    env = str(_module_body(tested[W + "main.tf"], "compute")["env_vars"])
    assert KEY in env and SECRET_REF in env
    assert json.loads(tested[C.RENDER_PATH])["module"]["postgres"]["grant_workload_secret_access"] is True


def test_harness_withdraw_if_tree_reads_only_the_tested_tree():
    """The corpus harness's `withdraw_if_tree` (a judge that reads the code under audit): the item stands unless the
    tested tree meets the condition; an item without the key is never withdrawn (every older fixture unchanged)."""
    pytest.importorskip("google.genai")
    import scenario_replay as SR
    cond = {"file": W + "main.tf", "contains": KEY}
    reply = {"score": 0.6, "score_after_withdrawal": 1.0,
             "missed": [{"text": "no password binding", "file": W + "topology.json", "task_id": "INFRA-04",
                         "withdraw_if_tree": cond}]}
    stands = SR.render_reply("adherence", reply, "", [], {W + "main.tf": "DB_HOST = x"}, {})
    gone = SR.render_reply("adherence", reply, "", [], {W + "main.tf": f"{KEY} = {SECRET_REF}"}, {})
    assert stands["missed_directives"] == ["no password binding"] and stands["instruction_adherence_score"] == 0.6
    assert gone["missed_directives"] == [] and gone["instruction_adherence_score"] == 1.0
    plain = {"score": 0.6, "missed": [{"text": "t", "file": "f", "task_id": "CODE-01"}]}
    assert SR.render_reply("adherence", plain, "", [], {W + "main.tf": KEY}, {}) == \
        SR.render_reply("adherence", plain, "", [])
