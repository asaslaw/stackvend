"""RT14 group iac-render-golden, golden-module half (full-scope red-team scan 11-14,
docs/planning/rt14-iac-render-golden-plan.md).

* RT14-35: compute-gce-bastion guessed the zone `<region>-a`; it now takes var.zone or the region's first zone, sorted.
* RT14-36: database-spanner's `config` was AI-chosen with a us-central1 default; the module derives it from the
  workload region, the typed intent refuses it (HELD), and the compliance plan gate reads it as a location.
Every behaviour change has a Do No Harm negative (valid input -> unchanged). Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import shutil
import subprocess
import sys
import importlib.util

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt; this file must not skip",
                pytrace=False)

from shared import iac_intent as ii  # noqa: E402

MODULES = os.path.join(REPO_ROOT, "infra", "modules")
CC_MODULES = os.path.join(REPO_ROOT, "apps", "control-center", "infra", "modules")
PAYLOAD_COPIES = ("shared", os.path.join("mcp-servers", "terraform", "shared"),
                  os.path.join("apps", "orchestrator-gateway", "shared"), os.path.join("apps", "control-center", "shared"))


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()

# ================================================================================================ RT14-35
def _module(name, root=MODULES):
    out = {}
    d = os.path.join(root, name)
    for f in sorted(os.listdir(d)):
        if f.endswith(".tf"):
            out[f] = _read(os.path.join(d, f))
    return out


def _parsed(name):
    return {f: hcl2.loads(t) for f, t in _module(name).items()}


def test_rt14_35_bastion_zone_is_a_zone_of_the_region_never_a_guess():
    main = _parsed("compute-gce-bastion")["main.tf"]
    zones = next(d["google_compute_zones"]["available"] for d in main["data"] if "google_compute_zones" in d)
    assert zones["region"] == "${var.region}" and zones["project"] == "${var.project_id}"
    assert "status" not in zones   # stable: the zone of a running bastion never moves with a zone's status
    local_zone = next(lc["zone"] for lc in main["locals"] if "zone" in lc)
    assert local_zone == '${var.zone != "" ? var.zone : sort(data.google_compute_zones.available.names)[0]}'
    vm = next(r["google_compute_instance"]["bastion"] for r in main["resource"] if "google_compute_instance" in r)
    assert vm["zone"] == "${local.zone}"
    assert '"${var.region}-a"' not in _module("compute-gce-bastion")["main.tf"]
    zone_var = next(v["zone"] for v in _parsed("compute-gce-bastion")["variables.tf"]["variable"] if "zone" in v)
    assert zone_var["default"] == ""


@pytest.mark.skipif(shutil.which("tofu") is None, reason="OpenTofu not installed")
@pytest.mark.parametrize("zones,first", [
    (["us-central1-f", "us-central1-a", "us-central1-c", "us-central1-b"], "us-central1-a"),   # unchanged
    (["us-east1-d", "us-east1-b", "us-east1-c"], "us-east1-b"),                                # no -a zone
    (["europe-west1-d", "europe-west1-c", "europe-west1-b"], "europe-west1-b"),
])
def test_rt14_35_the_expression_picks_the_first_sorted_zone(tmp_path, zones, first):
    expr = 'sort(' + "[" + ", ".join(f'"{z}"' for z in zones) + "])[0]\n"
    out = subprocess.run(["tofu", "console"], input=expr, capture_output=True, text=True, cwd=tmp_path, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == f'"{first}"'


def _zone_attributes(node, path=()):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "zone" and isinstance(v, str):
                yield path + (k,), v
            else:
                yield from _zone_attributes(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _zone_attributes(v, path + (i,))


# A `zone` variable whose default is a zone literal (invariant 3). database-bigtable's default "us-central1-a" is the
# one known instance left (typed intents render the zone fact; follow-up in the RT14 plan), listed so a new one fails.
ZONE_LITERAL_DEFAULT_ALLOWED = {"database-bigtable"}


def test_rt14_35_guard_every_golden_module_zone_is_a_variable_or_a_derived_local():
    """Structural guard over every golden module: a resource's `zone` (at any depth) is exactly var.zone or
    local.zone, and a `zone` variable has no zone literal default (except the listed one)."""
    bad, literal_defaults = [], set()
    for mod in sorted(os.listdir(MODULES)):
        mdir = os.path.join(MODULES, mod)
        for root, _, names in os.walk(mdir):
            for f in names:
                if not f.endswith(".tf"):
                    continue
                doc = hcl2.loads(_read(os.path.join(root, f)))
                for res in doc.get("resource", []):
                    for path, value in _zone_attributes(res):
                        if value not in ("${var.zone}", "${local.zone}"):
                            bad.append((os.path.relpath(os.path.join(root, f), MODULES), path, value))
                for var in doc.get("variable", []):
                    if "zone" in var and var["zone"].get("default") not in (None, ""):
                        literal_defaults.add(mod)
    assert not bad, bad
    assert literal_defaults <= ZONE_LITERAL_DEFAULT_ALLOWED, literal_defaults


# ------------------------------------------------------------------------- RT14-F1: the zone is known at plan
def _te():
    from developer_agent import terraform_engine
    return terraform_engine


def _root(text):
    doc = hcl2.loads(text)
    return doc, next(m["compute"] for m in doc["module"] if "compute" in m)


@pytest.mark.parametrize("kw", [{}, {"app_files": {"apps/ops/startup.sh": "#!/bin/bash\n"}, "service_name": "ops"}])
def test_rt14_f1_bastion_render_reads_the_zone_at_root_without_depends_on(kw):
    """The module's own zones read waits for module.foundation (depends_on) and so is deferred to apply whenever the
    foundation has a pending change; the platform render reads the zones in the root (no depends_on) instead and
    passes the module a `zone` that is known at plan (the IAP-GATE-KNOWN-MEMBER rule)."""
    text = _te().generate_golden_main_tf("shop", "gce-bastion", "", **kw)
    doc, compute = _root(text)
    data = [d["google_compute_zones"] for d in doc.get("data", []) if "google_compute_zones" in d]
    assert len(data) == 1 and list(data[0]) == ["stackvend_bastion_zones"]
    zones = data[0]["stackvend_bastion_zones"]
    assert {k: v for k, v in zones.items() if not k.startswith("__")} == {"project": "${var.project_id}",
                                                                          "region": "${var.region}"}   # no depends_on
    assert compute["zone"] == "${element(sort(data.google_compute_zones.stackvend_bastion_zones.names), 0)}"
    assert compute["depends_on"] == ["${module.foundation}"]
    # same rule as the module fallback and the typed zone fact: first zone of the region in sorted order
    assert ii.ZONE_FACT_EXPR.replace("stackvend_intent_zones", "stackvend_bastion_zones") == compute["zone"][2:-1]
    assert text.count('data "google_compute_zones"') == 1


@pytest.mark.parametrize("arch", ["cloudrun", "gke-autopilot", "event-worker", "foundation-only"])
def test_rt14_f1_other_archetypes_render_no_zone_read(arch):
    """Do No Harm: only a gce-bastion root gains the read and the input."""
    text = _te().generate_golden_main_tf("shop", arch, "", service_name="api", app_files={})
    assert "google_compute_zones" not in text and "stackvend_bastion_zones" not in text


def test_rt14_f1_regulated_bastion_render_keeps_the_known_zone():
    from developer_agent.compliance_profile import RegulatedControls
    regulated = RegulatedControls(profile="HIPAA", source="test", cmek=True, audit_logging=True, region="us-central1")
    _, compute = _root(_te().generate_golden_main_tf("shop", "gce-bastion", "", regulated=regulated))
    assert compute["zone"].startswith("${element(sort(data.google_compute_zones.stackvend_bastion_zones.names)")


# ================================================================================================ RT14-36
def test_rt14_36_spanner_config_follows_the_workload_region():
    parsed = _parsed("database-spanner")
    main, variables = parsed["main.tf"], parsed["variables.tf"]
    local = {k: v for lc in main["locals"] for k, v in lc.items()}
    assert "region" not in local
    assert local["config"] == '${var.region != null ? "regional-${var.region}" : var.config}'
    inst = next(r["google_spanner_instance"]["instance"] for r in main["resource"] if "google_spanner_instance" in r)
    assert inst["config"] == "${local.config}"
    pre = inst["lifecycle"][0]["precondition"][0]
    assert pre["condition"] == ('${var.region != null ? (var.config == "" || var.config == local.config) '
                                ': var.config != ""}')
    # RT14-F2: no data source (a read inside a module called with depends_on = [module.foundation] is deferred to
    # apply, which made `config` unknown at plan)
    assert "data" not in main and "google_client_config" not in _module("database-spanner")["main.tf"]
    var = {k: v for d in variables["variable"] for k, v in d.items()}
    assert var["config"]["default"] == "" and var["region"]["default"] is None
    assert "us-central1" not in _module("database-spanner")["variables.tf"]


def _spanner_exprs():
    """The module's own config / precondition expressions, read from main.tf (so the console test checks the code)."""
    main = _parsed("database-spanner")["main.tf"]
    local = {k: v for lc in main["locals"] for k, v in lc.items()}
    inst = next(r["google_spanner_instance"]["instance"] for r in main["resource"] if "google_spanner_instance" in r)
    return local["config"][2:-1], inst["lifecycle"][0]["precondition"][0]["condition"][2:-1]


@pytest.mark.skipif(shutil.which("tofu") is None, reason="OpenTofu not installed")
@pytest.mark.parametrize("region,config,want_config,want_ok", [
    ("europe-west1", None, "regional-europe-west1", True),                  # typed path / classic with region
    ("europe-west1", "regional-europe-west1", "regional-europe-west1", True),
    ("europe-west1", "regional-us-central1", "regional-europe-west1", False),  # other region refused
    ("europe-west1", "nam3", "regional-europe-west1", False),                  # multi-region refused
    (None, "regional-us-central1", "regional-us-central1", True),   # RT14-F2 (a): classic call kept as written
    (None, "nam3", "nam3", True),                                   # ... (the regulated plan gate checks it)
    (None, None, "", False),                                        # neither: refused, never a guessed region
])
def test_rt14_f2_spanner_config_is_known_without_a_data_source(tmp_path, region, config, want_config, want_ok):
    """RT14-F2: config is a pure function of the call's own inputs (known at plan whatever the foundation does); a
    call without region keeps its config exactly as written (owner option a)."""
    config_expr, condition = _spanner_exprs()
    (tmp_path / "main.tf").write_text(
        'variable "region" {\n  type    = string\n  default = null\n}\n'
        'variable "config" {\n  type    = string\n  default = ""\n}\n'
        f"locals {{\n  config = {config_expr}\n  ok     = {condition}\n}}\n", encoding="utf-8")
    args = ["tofu", "console"]
    if region is not None:
        args += ["-var", f"region={region}"]
    if config is not None:
        args += ["-var", f"config={config}"]
    out = subprocess.run(args, input="jsonencode([local.config, local.ok])\n", capture_output=True, text=True,
                         cwd=tmp_path, timeout=60)
    assert out.returncode == 0, out.stderr
    import json
    assert json.loads(json.loads(out.stdout.strip())) == [want_config, want_ok]


def test_rt14_f2_classic_contract_asks_for_the_region():
    from developer_agent import contract_inspector as ci
    ci._CONTRACT_CACHE.clear()
    try:
        spanner = ci.get_golden_module_contract("database-spanner", force_refresh=True)
        assert "- **Required Wiring**: region = var.region (leave config unset; the instance configuration is then " \
               "regional-<region>)\n" in spanner
        for mod in ("compute-cloudrun", "database-cloudsql", "compute-gce-bastion"):
            assert "Required Wiring" not in ci.get_golden_module_contract(mod, force_refresh=True)
    finally:
        ci._CONTRACT_CACHE.clear()


def test_rt14_36_typed_intent_refuses_config_and_renders_the_region_fact():
    art = ii.load_artifacts()
    cat = art.module("database-spanner")["variables"]
    assert cat["config"]["class"] == "HELD" and cat["config"]["row"] == "RT14-36"
    assert cat["region"]["class"] == "FACT" and cat["region"]["fact"] == "region"

    def gate(args):
        doc = {"schema": "iac_intent/v1", "resources": [], "outputs": [],
               "modules": [{"module": "database-spanner", "name": "spanner", "args": args}]}
        return ii.validate_intent(doc, art, ii.IntentContext())

    held = gate({"database_name": "app", "config": "nam3"})
    assert not held.ok and "IAC.ARGUMENT_HELD" in held.codes
    ok = gate({"database_name": "app"})
    assert ok.ok
    rendered = "".join(ii.render_intent(ok.validated).files.values())
    assert '"region": "${var.region}"' in rendered and '"config"' not in rendered


def _plan_gate():
    path = os.path.join(REPO_ROOT, "mcp-servers", "compliance", "plan_gate.py")
    spec = importlib.util.spec_from_file_location("rt14_plan_gate", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rt14_plan_gate"] = mod
    spec.loader.exec_module(mod)
    return mod


def _spanner_plan(config, *, extra=()):
    rc = [{"address": "module.s.google_spanner_instance.instance", "mode": "managed", "type": "google_spanner_instance",
           "name": "instance", "module_address": "module.s",
           "change": {"actions": ["create"], "after": {"name": "spanner-shop", "config": config}, "after_unknown": {}}}]
    return {"format_version": "1.2", "resource_changes": rc + list(extra), "configuration": {"root_module": {}}}


@pytest.mark.parametrize("config,allowed,ok", [
    ("regional-europe-west1", ["europe-west1"], True),
    ("projects/p/instanceConfigs/regional-europe-west1", ["europe-west1"], True),
    ("regional-us-central1", ["europe-west1"], False),
    ("nam3", ["us-central1", "us-east1"], False),        # multi-region: names no single allowed region
    ("eur3", ["europe-west1"], False),
])
def test_rt14_36_plan_gate_reads_the_spanner_configuration_as_a_location(config, allowed, ok):
    pg = _plan_gate()
    r = pg.evaluate_plan(_spanner_plan(config), profile="HIPAA", requirements={"allowed_regions": allowed})
    codes = sorted(v["code"] for v in r["violations"])
    assert ("REGION_NOT_ALLOWED" not in codes) is ok, (config, codes)


def test_rt14_36_plan_gate_location_attributes_are_otherwise_unchanged():
    """Do No Harm: the generic location attributes and their resolution are as before; only the exact spanner type
    gains `config`, and the terraform server projects exactly that attribute."""
    pg = _plan_gate()
    assert pg.LOCATION_ATTRIBUTES == ("location", "region", "zone")
    assert pg.TYPE_LOCATION_ATTRIBUTES == {"google_spanner_instance": ("config",)}
    bucket = {"address": "google_storage_bucket.b", "mode": "managed", "type": "google_storage_bucket", "name": "b",
              "change": {"actions": ["create"], "after": {"location": "us-central1", "config": "nam3"},
                         "after_unknown": {}}}
    r = pg.evaluate_plan({"format_version": "1.2", "resource_changes": [bucket], "configuration": {"root_module": {}}},
                         profile="HIPAA", requirements={"allowed_regions": ["us-central1"]})
    assert not [v for v in r["violations"] if v["code"] == "REGION_NOT_ALLOWED"]
    cg_path = os.path.join(REPO_ROOT, "mcp-servers", "terraform", "compliance_gate.py")
    tree = ast.parse(_read(cg_path))
    table = next(n.value for n in tree.body if isinstance(n, ast.AnnAssign)
                 and getattr(n.target, "id", "") == "PROJECTED_TYPE_ATTRIBUTES")
    projected = ast.literal_eval(table)
    for rtype, attrs in pg.TYPE_LOCATION_ATTRIBUTES.items():
        assert set(attrs) <= set(projected[rtype])


# ================================================================================================ copies
@pytest.mark.parametrize("module", ["compute-gce-bastion", "database-spanner"])
def test_module_copies_and_payloads_equal_the_golden_module(module):
    disk = _module(module)
    assert _module(module, CC_MODULES) == disk
    for copy in PAYLOAD_COPIES:
        tree = ast.parse(_read(os.path.join(REPO_ROOT, copy, "builtin_modules_payload.py")))
        payload = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.AnnAssign)
                       and getattr(n.target, "id", "") == "BUILTIN_MODULE_FILES")
        assert {f: t for f, t in payload[module].items() if f.endswith(".tf")} == disk, copy


def test_contract_inspector_lists_the_new_inputs():
    from developer_agent.contract_inspector import _EMBEDDED_MODULE_CONTRACTS as C
    assert "zone" in C["compute-gce-bastion"]["inputs"] and "region" in C["database-spanner"]["inputs"]
