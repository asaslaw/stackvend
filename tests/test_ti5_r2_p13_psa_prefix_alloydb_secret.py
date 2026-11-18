"""TI-5-R2 follow-ups P1 + P3 (owner 10-25, register FOLLOWUPS-1025). Hermetic.

P1: the size of the Private Services Access range the platform allocates per typed workload is the platform setting
`orchestration.ipam_psa_prefix` (default /20, allowed /16-/24), read through `platform_facts.load_ipam_pool`, the one
IPAM pool reader of the architect and developer stages (FD-4BZ same-reader rule).

P3: golden `database-alloydb` stores its initial user's password in Secret Manager inside the module and exports the
secret id (`secret_id_password`), as `database-cloudsql` does since FD-4AX. The topology catalog's
`google_alloydb_instance.password_secret_id` (a module-only attribute) binds a consumer's env to it on the typed path,
and the realizing module must then grant the workload service account read access (`grant_workload_secret_access`).

Real-engine tests use the production column (tofu 1.9.0 + google 6.35.0 filesystem mirror, untracked) wherever
`STACKVEND_PROD_TOFU` / `STACKVEND_PROD_MIRROR` point (else `eval/.tools/tofu-1.9.0/tofu` + `eval/.tofu-mirror-prod`
in the checkout); they skip with a reason when it is not on this machine. Everything runs offline."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)
REPO_ROOT = os.path.abspath(os.path.join(TESTS, ".."))
EVAL_DIR = os.path.join(REPO_ROOT, "eval")
if EVAL_DIR not in sys.path:
    sys.path.insert(0, EVAL_DIR)

from test_typed_iac_ti3_contract import APP, ART, PID, W, C, II, intent, topo, vt_of  # noqa: E402
from test_typed_iac_ti5c_network_facts import (CLOUDSQL, SQL_MODULE, _assemble_net,  # noqa: E402
                                               _generate_net, _module_body)
from test_ti5_r2_typed_topology_psa import ALLOYDB, ALLOYDB_MODULE, PSA_FACTS  # noqa: E402
from shared import service_topology as ST  # noqa: E402
from shared import settings as S  # noqa: E402

import hcl2  # noqa: E402

from developer_agent import platform_facts as PF  # noqa: E402
from developer_agent import topology_wiring as TW  # noqa: E402

PROD_TOFU = os.environ.get("STACKVEND_PROD_TOFU") or os.path.join(EVAL_DIR, ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.environ.get("STACKVEND_PROD_MIRROR") or os.path.join(EVAL_DIR, ".tofu-mirror-prod")

SETTINGS_COPIES = ["shared/settings.py", "apps/control-center/shared/settings.py",
                   "apps/orchestrator-gateway/shared/settings.py", "apps/project-vending/shared/settings.py",
                   "apps/spec-ingestion/shared/settings.py", "mcp-servers/terraform/shared/settings.py"]
MOD = "database-alloydb"
MODULE_DIRS = [os.path.join(REPO_ROOT, "infra", "modules", MOD),
               os.path.join(REPO_ROOT, "apps", "control-center", "infra", "modules", MOD)]
PAYLOADS = [os.path.join(REPO_ROOT, p, "builtin_modules_payload.py") for p in (
    "shared", "mcp-servers/terraform/shared", "apps/orchestrator-gateway/shared", "apps/control-center/shared")]
NET_ID = "projects/p13-test/global/networks/stackvend-vpc"

# a consumer that reads the AlloyDB host AND its password secret id
ALLOYDB_AUTH = dict(ALLOYDB, consumers=[{"service": "shop", "env_key": "LEDGER_DB_HOST", "attribute": None},
                                        {"service": "shop", "env_key": "LEDGER_DB_PASSWORD_SECRET",
                                         "attribute": "password_secret_id"}])
ALLOYDB_GRANT = dict(ALLOYDB_MODULE, args={"grant_workload_secret_access": True})


def _settings(**orch):
    s = S.PlatformSettings()
    for k, v in orch.items():
        setattr(s.orchestration, k, v)
    return s


@pytest.fixture
def platform_settings(monkeypatch):
    """Patch the one settings reader load_ipam_pool uses (strict read) with a given settings object. The developer
    stage's own reference to load_ipam_pool builds the pool from the same object through IpamPool.from_settings (the
    end-to-end helper pins every other settings read to the defaults)."""
    from developer_agent import handler as h

    def use(settings_obj):
        monkeypatch.setattr(S, "get_platform_settings", lambda *a, **k: settings_obj)
        monkeypatch.setattr(h, "load_ipam_pool", lambda project_id=None: PF.IpamPool.from_settings(settings_obj))
    return use


# ================================================================================================ P1: the setting
def test_p1_setting_default_and_bounds():
    orch = S.OrchestrationSettings()
    assert orch.ipam_psa_prefix == 20 == PF.PSA_PREFIX
    for ok in (16, 20, 24):
        assert S.OrchestrationSettings(ipam_psa_prefix=ok).ipam_psa_prefix == ok
    from pydantic import ValidationError
    for bad in (15, 25, 28, "big"):
        with pytest.raises(ValidationError):
            S.OrchestrationSettings(ipam_psa_prefix=bad)
    # a stored settings document written before P1 (no key) validates with the default
    doc = S.PlatformSettings().model_dump(mode="json")
    doc["orchestration"].pop("ipam_psa_prefix")
    assert S.PlatformSettings.model_validate(doc).orchestration.ipam_psa_prefix == 20


def test_p1_settings_copies_are_byte_identical():
    digests = {p: hashlib.sha256(open(os.path.join(REPO_ROOT, p), "rb").read()).hexdigest() for p in SETTINGS_COPIES}
    assert len(set(digests.values())) == 1, digests


@pytest.mark.parametrize("prefix", [16, 24])
def test_p1_load_ipam_pool_reads_the_setting_through(platform_settings, prefix):
    platform_settings(_settings(ipam_psa_prefix=prefix, ipam_supernet_cidr="10.100.0.0/14"))
    pool = PF.load_ipam_pool("p13-project")
    assert pool.psa_prefix == prefix and pool.prefix_for(PF.PURPOSE_PSA) == prefix
    # the other purposes are untouched
    assert (pool.prefix_for(PF.PURPOSE_SUBNET), pool.prefix_for(PF.PURPOSE_CONNECTOR)) == (24, 28)


def test_p1_negative_defaults_unchanged_when_the_setting_is_absent(platform_settings):
    """Do No Harm: default settings give exactly the pre-P1 pool (the TI-5-F4 /20 constant)."""
    platform_settings(S.PlatformSettings())
    pool = PF.load_ipam_pool("p13-project")
    assert pool == PF.IpamPool(supernet="10.100.0.0/16", subnet_prefix=24, connector_prefix=28, region="us-central1")
    assert pool.psa_prefix == 20
    f = PF.MemoryFactsProvider().resolve(PID, PF.PURPOSES, pool=pool)
    assert (f.subnet_cidr, f.connector_cidr, f.psa_cidr) == ("10.100.0.0/24", "10.100.1.0/28", "10.100.16.0/20")


def test_p1_both_stages_use_the_one_reader():
    """FD-4BZ same-reader rule: the architect and the developer stage build their pool with load_ipam_pool only."""
    for rel in ("apps/orchestrator-gateway/architect_agent/handler.py",
                "apps/orchestrator-gateway/developer_agent/handler.py"):
        src = open(os.path.join(REPO_ROOT, rel)).read()
        assert "load_ipam_pool(self.project_id)" in src, rel
        assert "IpamPool(" not in src and "ipam_psa_prefix" not in src, rel


@pytest.mark.parametrize("prefix,supernet,want", [
    (16, "10.100.0.0/14", "10.101.0.0/16"),
    (24, "10.100.0.0/16", "10.100.2.0/24"),
])
def test_p1_render_with_a_16_and_a_24(platform_settings, prefix, supernet, want):
    """End to end (developer stage): the PSA range has the configured size; the render stays the fixed platform
    expressions on var.psa_cidr (no CIDR literal), and the subnet / connector ranges are unchanged."""
    platform_settings(_settings(ipam_psa_prefix=prefix, ipam_supernet_cidr=supernet))
    provider = PF.MemoryFactsProvider()
    agent, files = _generate_net(dict(APP, **{C.INTENT_PATH: intent([SQL_MODULE])}), topo([CLOUDSQL]), provider)
    assert agent.last_validation_report.status == "PASS", agent.last_validation_report
    assert provider.ledger[(PID, PF.PURPOSE_PSA)] == want
    assert provider.ledger[(PID, PF.PURPOSE_SUBNET)] == "10.100.0.0/24"
    assert provider.ledger[(PID, PF.PURPOSE_CONNECTOR)] == "10.100.1.0/28"
    assert hcl2.loads(files[W + "terraform.tfvars"])["psa_cidr"] == want
    net = json.loads(files[C.FACTS_RENDER_PATH])["module"][II.PLATFORM_NETWORK_MODULE]
    assert net["psa_address"] == "${cidrhost(var.psa_cidr, 0)}"
    assert net["psa_prefix_length"] == '${tonumber(element(split("/", var.psa_cidr), 1))}'
    assert "10.10" not in files[C.FACTS_RENDER_PATH]


def test_p1_a_16_in_the_default_16_pool_stops_typed_nothing_guessed(platform_settings):
    """A /16 cannot fit next to the subnet in the default /16 pool: the stage stops (IPAM.POOL_EXHAUSTED), never a
    smaller range."""
    from shared.diagnostics import ErrorClass, StageError
    platform_settings(_settings(ipam_psa_prefix=16))
    with pytest.raises(StageError) as ei:
        _generate_net(dict(APP, **{C.INTENT_PATH: intent([SQL_MODULE])}), topo([CLOUDSQL]), PF.MemoryFactsProvider())
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE and "IPAM.POOL_EXHAUSTED" in str(ei.value)


def test_p1_a_changed_setting_never_moves_an_existing_range(platform_settings):
    """A committed PSA range is reused (reuse-only) whatever the setting says now."""
    provider = PF.MemoryFactsProvider()
    draft = dict(APP, **{C.INTENT_PATH: intent([SQL_MODULE])})
    _, files = _generate_net(draft, topo([CLOUDSQL]), provider)          # default /20
    committed = {p: files[p] for p in (C.INTENT_PATH, C.RENDER_PATH, C.FACTS_RENDER_PATH, W + "terraform.tfvars")}
    platform_settings(_settings(ipam_psa_prefix=24))
    again = PF.MemoryFactsProvider(ledger=dict(provider.ledger))
    _, files2 = _generate_net(draft, topo([CLOUDSQL]), again, existing=committed)
    assert again.ledger == provider.ledger
    assert files2[W + "terraform.tfvars"] == files[W + "terraform.tfvars"]


def test_p1_settings_ui_field_matches_the_model_bounds():
    html = open(os.path.join(REPO_ROOT, "apps/control-center/templates/dashboard.html"), encoding="utf-8").read()
    tag = 'type="number" min="16" max="24" x-model.number="platformSettings.orchestration.ipam_psa_prefix"'
    assert html.count(tag) == 1
    f = S.OrchestrationSettings.model_fields["ipam_psa_prefix"]
    bounds = {type(m).__name__: m for m in f.metadata}
    assert bounds["Ge"].ge == 16 and bounds["Le"].le == 24 and f.default == 20


def test_p1_docs_state_the_setting():
    ref = open(os.path.join(REPO_ROOT, "documentation/settings-reference.md"), encoding="utf-8").read()
    assert "`orchestration.ipam_psa_prefix`, 20, 16 to 24" in ref
    assert "a fixed /20 that is not a setting yet" not in ref
    guide = open(os.path.join(REPO_ROOT, "documentation/quick-guide.md"), encoding="utf-8").read()
    # merged into the IaC Engine bullet (the guide stays within its bullet limit)
    assert "**Private Services Access Range Size (prefix)** (20)" in guide


def test_f2_psa_range_wanted_is_exported():
    assert "psa_range_wanted" in C.__all__ and callable(C.psa_range_wanted)


# ================================================================================================ P3: the module
def _disk_module(d=MODULE_DIRS[0]):
    return {fn: open(os.path.join(d, fn)).read() for fn in sorted(os.listdir(d)) if fn.endswith(".tf")}


def _payload(path):
    tree = ast.parse(open(path).read())
    node = next(n for n in tree.body
                if isinstance(n, ast.AnnAssign) and getattr(n.target, "id", None) == "BUILTIN_MODULE_FILES")
    return ast.literal_eval(node.value)


def _blocks(text, kind):
    out = {}
    for b in hcl2.loads(text).get(kind) or []:
        for typ, named in b.items():
            if kind == "resource":
                for name, body in named.items():
                    out[f"{typ}.{name}"] = body
            else:
                out[typ] = named
    return out


def test_p3_module_stores_the_password_in_secret_manager_and_exports_only_the_secret_id():
    files = _disk_module()
    res = _blocks(files["main.tf"], "resource")
    sec = res["google_secret_manager_secret.initial_user_password"]
    assert sec["secret_id"] == "${local.cluster_id}-db-password" and sec["project"] == "${var.project_id}"
    ver = res["google_secret_manager_secret_version.initial_user_password"]
    assert ver["secret"] == "${google_secret_manager_secret.initial_user_password.id}"
    # cryptographic parity: the cluster's initial user and the secret hold the same value (one local)
    assert ver["secret_data"] == "${local.initial_user_password}"
    assert res["google_alloydb_cluster.cluster"]["initial_user"][0]["password"] == "${local.initial_user_password}"
    acc = res["google_secret_manager_secret_iam_member.workload_accessor"]
    assert acc["count"] == "${var.grant_workload_secret_access ? 1 : 0}"
    assert acc["role"] == "roles/secretmanager.secretAccessor"
    assert acc["secret_id"] == "${google_secret_manager_secret.initial_user_password.secret_id}"
    outs = _blocks(files["outputs.tf"], "output")
    assert outs["secret_id_password"]["value"] == "${google_secret_manager_secret.initial_user_password.secret_id}"
    # the password itself is never an output
    assert not [o for o, b in outs.items() if "password" in str(b["value"]) and o != "secret_id_password"]
    assert "random_password" not in files["outputs.tf"] and "local.initial_user_password" not in files["outputs.tf"]
    vars_ = _blocks(files["variables.tf"], "variable")
    assert vars_["grant_workload_secret_access"]["default"] is False
    assert vars_["workload_sa_email"]["default"] == ""


def test_p3_module_copies_and_four_payloads_are_identical():
    disk = _disk_module()
    assert _disk_module(MODULE_DIRS[1]) == disk
    for p in PAYLOADS:
        assert _payload(p)[MOD] == disk, p
    assert len({hashlib.sha256(open(p, "rb").read()).hexdigest() for p in PAYLOADS}) == 1


def test_p3_cloudsql_module_is_untouched_and_mirrored():
    """The AlloyDB variables / accessor rule are the Cloud SQL ones (FD-4AX) and Cloud SQL itself is unchanged."""
    sql = _disk_module(os.path.join(REPO_ROOT, "infra", "modules", "database-cloudsql"))
    alloy = _disk_module()
    sql_vars, alloy_vars = _blocks(sql["variables.tf"], "variable"), _blocks(alloy["variables.tf"], "variable")
    for v in ("workload_sa_email", "grant_workload_secret_access"):
        assert sql_vars[v]["type"] == alloy_vars[v]["type"] and sql_vars[v]["default"] == alloy_vars[v]["default"]
    sql_acc = _blocks(sql["main.tf"], "resource")["google_secret_manager_secret_iam_member.workload_accessor"]
    alloy_acc = _blocks(alloy["main.tf"], "resource")["google_secret_manager_secret_iam_member.workload_accessor"]
    assert {k: v for k, v in sql_acc.items() if k != "secret_id"} == \
        {k: v for k, v in alloy_acc.items() if k != "secret_id"}
    for p in PAYLOADS:
        assert _payload(p)["database-cloudsql"] == sql


def test_p3_catalog_entry_classes():
    m = ART.module(MOD)
    v = m["variables"]
    assert v["workload_sa_email"]["class"] == "FACT" and v["workload_sa_email"]["fact"] == "workload_sa_email"
    assert v["grant_workload_secret_access"]["class"] == "AI" and v["grant_workload_secret_access"]["count_driver"]
    assert v["initial_user_password"]["class"] == "SECRET"
    assert "secret_id_password" in m["outputs"] and not m["outputs"]["secret_id_password"]["sensitive"]
    assert {"google_secret_manager_secret", "google_secret_manager_secret_version",
            "google_secret_manager_secret_iam_member"} <= set(m["declares_types"])


# ------------------------------------------------------------------------------------------------ P3: binding
def test_p3_consumer_gets_the_secret_id_env_and_the_module_grants_access():
    vt = vt_of(topo([ALLOYDB_AUTH]))
    assert vt.realization_needs() == {"ledger": ("google_alloydb_instance", ("ip_address", "password_secret_id"))}
    asm, bound, files = _assemble_net(vt, {C.INTENT_PATH: intent([ALLOYDB_GRANT])}, PSA_FACTS)
    assert asm.diagnostics == (), [(d.code, d.message) for d in asm.diagnostics]
    assert bound.resource_bindings("shop") == {"LEDGER_DB_HOST": "module.ledger.ip_address",
                                               "LEDGER_DB_PASSWORD_SECRET": "module.ledger.secret_id_password"}
    body = json.loads(files[C.RENDER_PATH])["module"]["ledger"]
    assert body["grant_workload_secret_access"] is True
    assert body["workload_sa_email"] == "${module.foundation.workload_sa_email}"     # FACT: the platform renders it
    assert TW.topology_vpc_connector(bound, "shop", files) == II.PLATFORM_CONNECTOR_REF


def test_p3_grant_left_out_is_rendered_by_the_platform():
    """TI5-ALLOYDB-SECRET-BIND (owner 10-27): the grant is the platform's (rendered when the intent leaves it out)."""
    vt = vt_of(topo([ALLOYDB_AUTH]))
    asm, bound, files = _assemble_net(vt, {C.INTENT_PATH: intent([dict(ALLOYDB_MODULE, args={})])}, PSA_FACTS)
    assert asm.diagnostics == (), [(d.code, d.message) for d in asm.diagnostics]
    assert json.loads(files[C.RENDER_PATH])["module"]["ledger"]["grant_workload_secret_access"] is True


@pytest.mark.parametrize("args", [{"grant_workload_secret_access": False}])
def test_p3_reading_the_secret_without_the_grant_is_a_typed_finding(args):
    """An intent that states a different value is still a typed finding (the platform never overrides the AI)."""
    vt = vt_of(topo([ALLOYDB_AUTH]))
    asm, bound, _ = _assemble_net(vt, {C.INTENT_PATH: intent([dict(ALLOYDB_MODULE, args=args)])}, PSA_FACTS)
    codes = [d.code for d in asm.diagnostics]
    assert codes == ["IAC.REALIZATION_ARGUMENT_REQUIRED"], codes
    d = asm.diagnostics[0]
    assert "grant_workload_secret_access" in d.message and '"grant_workload_secret_access": true' in d.hint
    # the fix is to set the argument, never to delete the entry
    assert "IAC.REALIZATION_ARGUMENT_REQUIRED" not in C.INTENT_REMOVAL_CODES


def test_p3_the_required_literal_is_type_exact():
    from shared.service_topology import validate_service_topology  # noqa: F401
    raw = intent([dict(ALLOYDB_MODULE, args={"grant_workload_secret_access": True})])
    parsed = II.validate_intent(raw, ART, C.intent_context(None, network_facts=PSA_FACTS)).intent
    need = {"ledger": ("google_alloydb_instance", ("password_secret_id",))}
    assert II.intent_realizations(parsed, need)[1] == ()
    # a non-bool literal never satisfies it (the gate would refuse 1 / "true" for a bool anyway)
    m = parsed.modules[0].model_copy(update={"args": {"grant_workload_secret_access": 1}})
    bad = parsed.model_copy(update={"modules": [m]})
    assert [d.code for d in II.intent_realizations(bad, need)[1]] == ["IAC.REALIZATION_ARGUMENT_REQUIRED"]


def test_p3_host_only_consumer_gets_the_implied_secret_binding_and_the_grant():
    """TI5-ALLOYDB-SECRET-BIND (owner 10-27; replaces the P3 "host-only consumer binds as before" negative): a
    consumer reading only ip_address (the R2 shape, every recorded S8 run) is gate-clean with no args and the
    platform binds `<LOGICAL>_PASSWORD_SECRET_ID` and renders the grant."""
    vt = vt_of(topo([ALLOYDB]))
    asm, bound, files = _assemble_net(vt, {C.INTENT_PATH: intent([ALLOYDB_MODULE])}, PSA_FACTS)
    assert asm.diagnostics == ()
    assert bound.resource_bindings("shop") == {"LEDGER_DB_HOST": "module.ledger.ip_address",
                                               "LEDGER_PASSWORD_SECRET_ID": "module.ledger.secret_id_password"}
    assert json.loads(files[C.RENDER_PATH])["module"]["ledger"]["grant_workload_secret_access"] is True


def test_p3_an_extra_resource_never_exports_the_module_only_attribute():
    parsed = II.validate_intent(intent(), ART, C.intent_context(None, network_facts=PSA_FACTS)).intent
    res = II.ExtraResource.model_validate({"type": "google_alloydb_instance", "name": "ledger", "realizes": "ledger",
                                           "arguments": {}})
    with_res = parsed.model_copy(update={"resources": [res]})
    out, diags = II.intent_realizations(with_res, {"ledger": ("google_alloydb_instance",
                                                              ("ip_address", "password_secret_id"))})
    assert out == {"ledger": {"ip_address": "google_alloydb_instance.ledger.ip_address"}}
    assert [d.code for d in diags] == ["IAC.REALIZATION_EXPORT_MISSING"]
    assert diags[0].hint == "Realize it with the golden module database-alloydb."


def test_p3_classic_path_binds_nothing_for_it_and_warns():
    vt, diags = ST.validate_service_topology(topo([ALLOYDB_AUTH]), product_id=PID)
    assert vt is not None
    warn = [d for d in diags if d.code == "TOPOLOGY.BINDING_TYPED_ONLY"]
    assert len(warn) == 1 and warn[0].severity == "warning" and "LEDGER_DB_PASSWORD_SECRET" in warn[0].message
    # no realizations (classic path): never a `google_alloydb_instance.<n>.password_secret_id` reference
    assert vt.resource_bindings("shop") == {"LEDGER_DB_HOST": "google_alloydb_instance.ledger.ip_address"}
    # Do No Harm: a topology without the attribute gets no warning
    _, diags0 = ST.validate_service_topology(topo([ALLOYDB]), product_id=PID)
    assert "TOPOLOGY.BINDING_TYPED_ONLY" not in [d.code for d in diags0]


def test_p3_developer_contract_lists_the_secret_env_key_on_the_typed_path_only():
    """The app code must read LEDGER_DB_PASSWORD_SECRET only where the platform binds it (typed path)."""
    vt = vt_of(topo([ALLOYDB_AUTH]))
    assert vt.typed_only_env_keys("shop") == ("LEDGER_DB_PASSWORD_SECRET",)
    typed = TW.topology_contract_rule(vt, iac_intent=True)
    classic = TW.topology_contract_rule(vt, iac_intent=False)
    assert "read these environment variables, with exactly these names: LEDGER_DB_HOST, LEDGER_DB_PASSWORD_SECRET" \
        in typed
    assert "LEDGER_DB_PASSWORD_SECRET" not in classic and "LEDGER_DB_HOST" in classic
    # TI5-ALLOYDB-SECRET-BIND: without the attribute the typed contract lists the implied key; classic unchanged
    vt0 = vt_of(topo([ALLOYDB]))
    assert vt0.typed_only_env_keys("shop") == ("LEDGER_PASSWORD_SECRET_ID",)
    assert "with exactly these names: LEDGER_DB_HOST, LEDGER_PASSWORD_SECRET_ID;" in TW.topology_contract_rule(
        vt0, iac_intent=True)
    assert "with exactly these names: LEDGER_DB_HOST;" in TW.topology_contract_rule(vt0, iac_intent=False)


def test_p3_slot_lines_name_the_required_argument_and_no_resource_option():
    lines = C.topology_slot_lines(vt_of(topo([ALLOYDB_AUTH])))
    assert ("`ledger` (google_alloydb_instance; services read ip_address, password_secret_id; realize it with golden "
            "module database-alloydb with grant_workload_secret_access: true)") in lines[0]
    # TI5-ALLOYDB-SECRET-BIND: the R2 shape (host only) now reads the implied password secret id too
    assert ("`ledger` (google_alloydb_instance; services read ip_address, password_secret_id; realize it with golden "
            "module database-alloydb with grant_workload_secret_access: true)") in C.topology_slot_lines(
        vt_of(topo([ALLOYDB])))[0]


def test_p3_negative_cloudsql_renders_and_binds_unchanged(monkeypatch):
    """Do No Harm: with the P3 AlloyDB rows removed (pre-P3 behaviour for AlloyDB) Cloud SQL's slot line, render and
    bindings are byte-identical. (CLOUDSQL-PASSWORD-BINDING, owner 11-14, gave Cloud SQL rows of its own in the same
    tables; tests/test_cloudsql_password_binding.py pins those.)"""
    alloy = "google_alloydb_instance"
    vt = vt_of(topo([CLOUDSQL]))
    now = (_assemble_net(vt, {C.INTENT_PATH: intent([SQL_MODULE])}, PSA_FACTS), C.topology_slot_lines(vt))
    monkeypatch.setattr(II, "REALIZATION_REQUIRED_ARGS",
                        {k: v for k, v in II.REALIZATION_REQUIRED_ARGS.items() if k[1] != alloy})
    only = {k: v for k, v in ST.MODULE_ONLY_ATTRIBUTES.items() if k != alloy}
    monkeypatch.setattr(II, "MODULE_ONLY_ATTRIBUTES", only)
    monkeypatch.setattr(C, "MODULE_ONLY_ATTRIBUTES", only)
    monkeypatch.setattr(ST, "MODULE_ONLY_ATTRIBUTES", only)
    monkeypatch.setattr(ST, "TYPED_IMPLIED_ATTRIBUTES",
                        {k: v for k, v in ST.TYPED_IMPLIED_ATTRIBUTES.items() if k != alloy})
    before = (_assemble_net(vt, {C.INTENT_PATH: intent([SQL_MODULE])}, PSA_FACTS), C.topology_slot_lines(vt))
    (asm1, b1, f1), l1 = now
    (asm0, b0, f0), l0 = before
    assert asm1.diagnostics == asm0.diagnostics == ()
    assert f1 == f0 and l1 == l0 and b1.resource_bindings("shop") == b0.resource_bindings("shop")


def test_p3_architect_contract_changes_only_the_alloydb_entry(monkeypatch):
    now = ST.render_topology_contract()
    notes = {k: v for k, v in ST.CATALOG_NOTES.items() if k != "google_alloydb_instance"}
    cat = dict(ST.BOOTSTRAP_CATALOG, google_alloydb_instance=(("ip_address", "string"),))
    monkeypatch.setattr(ST, "CATALOG_NOTES", notes)
    monkeypatch.setattr(ST, "BOOTSTRAP_CATALOG", cat)
    before = ST.render_topology_contract()
    new = ("`google_alloydb_instance` (ip_address/password_secret_id; password_secret_id is the Secret Manager secret "
           "id of the postgres user's password (typed infrastructure only))")
    assert now == before.replace("`google_alloydb_instance` (ip_address)", new) and now != before


def test_e2e_alloydb_consumer_reads_host_and_password_secret():
    provider = PF.MemoryFactsProvider()
    agent, files = _generate_net(dict(APP, **{C.INTENT_PATH: intent([ALLOYDB_GRANT])}), topo([ALLOYDB_AUTH]),
                                 provider)
    assert agent.last_validation_report.status == "PASS", agent.last_validation_report
    compute = _module_body(files[W + "main.tf"], "compute")
    env = str(compute["env_vars"])
    assert "LEDGER_DB_PASSWORD_SECRET" in env and "module.ledger.secret_id_password" in env
    assert compute["vpc_access_connector"] == "${" + II.PLATFORM_CONNECTOR_REF + "}"
    _validate_and_plan_if_available(files, "alloydb-auth")


# ------------------------------------------------------------------------------------------------ production engine
def _runner(tmp: Path):
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        return None
    from stackvend_eval.tofu_runner import TofuRunner
    r = TofuRunner(tmp, Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    return r if r.mirror_ready else None


def _validate_and_plan_if_available(files, label):
    """Production `tofu validate` of the whole end-to-end tree when the column is present. The mocked plan of a whole
    tree needs real-format mock values for the foundation (docs/handoff/ti5-evidence/offline_validate_plan.sh); set
    P13_DUMP_TREE=<dir> to write the tree for it."""
    import tempfile
    tree = {p: t for p, t in files.items() if isinstance(t, str) and (p.startswith("infra/") or p.startswith("apps/"))}
    base = os.environ.get("P13_DUMP_TREE")
    if base:
        for p, t in tree.items():
            full = os.path.join(base, label, p)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(t)
    r = _runner(Path(tempfile.mkdtemp(prefix="p13-")))
    if r is None:
        return
    out = r.validate_tree({p: t for p, t in tree.items() if p.startswith("infra/")}, label, plan=False)
    assert out["status"] == "validated" and out["validate_ok"], out


ALLOYDB_TEST = f'''mock_provider "google" {{}}
mock_provider "random" {{}}

variables {{
  project_id = "p13-test"
  product_id = "p13"
  network    = "{NET_ID}"
}}

run "default_plans_the_secret_and_no_grant" {{
  command = plan
  assert {{
    condition     = google_secret_manager_secret.initial_user_password.secret_id == "alloydb-p13-db-password"
    error_message = "the password secret must be planned with the cluster-derived id"
  }}
  assert {{
    condition     = length(google_secret_manager_secret_iam_member.workload_accessor) == 0
    error_message = "no accessor grant by default"
  }}
  assert {{
    condition     = output.secret_id_password == "alloydb-p13-db-password"
    error_message = "the secret id is exported"
  }}
}}

run "grant_gives_the_workload_sa_read_access" {{
  command = plan
  variables {{
    grant_workload_secret_access = true
    workload_sa_email            = "sa-p13@p13-test.iam.gserviceaccount.com"
  }}
  assert {{
    condition     = google_secret_manager_secret_iam_member.workload_accessor[0].member == "serviceAccount:sa-p13@p13-test.iam.gserviceaccount.com"
    error_message = "the workload SA gets the grant"
  }}
  assert {{
    condition     = google_secret_manager_secret_iam_member.workload_accessor[0].role == "roles/secretmanager.secretAccessor"
    error_message = "read access only"
  }}
}}

run "grant_without_an_email_is_refused" {{
  command = plan
  variables {{
    grant_workload_secret_access = true
  }}
  expect_failures = [google_secret_manager_secret_iam_member.workload_accessor]
}}

run "missing_network_is_still_refused" {{
  command = plan
  plan_options {{
    target = [google_alloydb_cluster.cluster]
  }}
  variables {{
    network = null
  }}
  expect_failures = [google_alloydb_cluster.cluster]
}}
'''


def test_p3_module_validates_and_plans_at_the_production_set(tmp_path):
    r = _runner(tmp_path / "r")
    if r is None:
        pytest.skip("production column (tofu 1.9.0 + google 6.35.0 mirror, untracked) not present; set "
                    "STACKVEND_PROD_TOFU / STACKVEND_PROD_MIRROR to run")
    wd = tmp_path / "m"
    shutil.copytree(MODULE_DIRS[0], wd)
    (wd / "p13_tests").mkdir()
    (wd / "p13_tests" / "p13.tftest.hcl").write_text(ALLOYDB_TEST, encoding="utf-8")
    for args in (["init", "-backend=false", "-input=false", "-no-color"], ["validate", "-no-color"]):
        res = r._run(args, cwd=wd)
        assert res.returncode == 0, (res.stdout + res.stderr)[-2000:]
    res = r._run(["test", "-test-directory=p13_tests", "-filter=p13_tests/p13.tftest.hcl", "-no-color"], cwd=wd)
    out = res.stdout + res.stderr
    assert res.returncode == 0 and "4 passed, 0 failed" in out, out[-4000:]
