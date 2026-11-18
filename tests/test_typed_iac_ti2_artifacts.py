"""Typed IaC intent TI-2: the four artifacts (catalog, allow-list, provider-schema slice, MANIFEST).

Catalog drift (regenerate == committed), every variable classified, the RT F4 static count rule (positive and
negative), the built-in payload matching the catalog modules, slice parity BY VERSION (RT F8) with
eval/config/provider_sets.json "production" and validate_service, the runtime parity check, a missing / malformed /
inconsistent artifact -> GATE_UNAVAILABLE, and the byte-identical gateway copy. Pure (no tofu)."""
import hermetic_guard  # noqa: F401  (first import)

import dataclasses
import functools
import hashlib
import importlib.util
import json
import os
import shutil
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import iac_intent as ii  # noqa: E402

DATA = os.path.join(REPO_ROOT, "shared", "iac_intent")
ART = ii.load_artifacts()


def _load_script(name):
    spec = importlib.util.spec_from_file_location(f"ti2_{name}", os.path.join(REPO_ROOT, "scripts", f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


BUILDER = _load_script("build_iac_catalog")


# ------------------------------------------------------------------------------------------------ catalog
def test_catalog_drift_regenerate_equals_committed():
    catalog, problems = BUILDER.build()
    assert problems == []
    with open(os.path.join(DATA, "module_catalog.json")) as fh:
        assert BUILDER.render(catalog) == fh.read(), "run python3 scripts/build_iac_catalog.py"


def test_manifest_pins_the_catalog_and_the_module_tree():
    man = json.load(open(os.path.join(DATA, "MANIFEST")))
    text = open(os.path.join(DATA, "module_catalog.json")).read()
    assert man["module_catalog"]["sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert man["module_catalog"]["modules_tree_sha256"] == BUILDER.modules_tree_sha256()


def test_check_flags_a_stale_manifest_tree_hash(tmp_path, monkeypatch, capsys):
    """visible-rename-3: `--check` also compares the MANIFEST entry, so a comment-only module edit (catalog text
    unchanged, tree hash moved) is DRIFT, not "up to date". Committed artifacts pass; a stale tree hash fails."""
    assert BUILDER.main(["--check"]) == 0
    man = json.load(open(os.path.join(DATA, "MANIFEST")))
    man["module_catalog"]["modules_tree_sha256"] = "0" * 64
    stale = tmp_path / "MANIFEST"
    stale.write_text(json.dumps(man, indent=1, sort_keys=True) + "\n")
    monkeypatch.setattr(BUILDER, "MANIFEST", stale)
    monkeypatch.setattr(BUILDER, "REPLICA_DIRS", ())
    assert BUILDER.main(["--check"]) == 1
    assert "DRIFT" in capsys.readouterr().out


def test_catalog_covers_every_golden_module_exactly_once():
    on_disk = {d for d in os.listdir(os.path.join(REPO_ROOT, "infra", "modules"))
               if os.path.isdir(os.path.join(REPO_ROOT, "infra", "modules", d))}
    ai, plat = set(BUILDER.AI_INSTANTIABLE), set(BUILDER.PLATFORM_ONLY)
    assert len(ai) == 18 and len(plat) == 10 and not ai & plat and ai | plat == on_disk
    assert tuple(ART.ai_modules) == BUILDER.AI_INSTANTIABLE


def test_every_catalog_variable_has_a_class():
    for mid, entry in ART.catalog["modules"].items():
        for name, v in entry["variables"].items():
            assert v["class"] in ii.ARG_CLASSES, (mid, name)
            if v["class"] == "FACT":
                assert v["fact"] in ii.FACTS, (mid, name)
            if v["class"] == "SECRET":
                assert v["policy"] == "omit", (mid, name)
            ii.parse_type_constraint(v["hcl_type"])


def test_unclassified_variable_fails_the_build(tmp_path):
    mods = tmp_path / "modules"
    shutil.copytree(os.path.join(REPO_ROOT, "infra", "modules"), mods)
    (mods / "storage-bucket" / "extra.tf").write_text('variable "brand_new_knob" {\n  type = string\n}\n')
    _catalog, problems = BUILDER.build(mods)
    assert any("brand_new_knob" in p and "no class" in p for p in problems)


@pytest.mark.parametrize("snippet,ok", [
    # FACT that may be unknown at plan (network) drives a count -> refused
    ('resource "google_pubsub_topic" "t2" {\n  count = var.authorized_network != "" ? 1 : 0\n  name = "x"\n}\n',
     False),
    # REF_ONLY (a reference may be unknown) through a local -> refused
    ('locals {\n  on = var.kms_key_name != null\n}\nresource "google_pubsub_topic" "t2" {\n'
     '  count = local.on ? 1 : 0\n  name = "x"\n}\n', False),
    # plan-known FACT (workload_sa_email: google 6.35.0 plans the SA email) -> allowed
    ('resource "google_pubsub_topic" "t2" {\n  count = var.workload_sa_email != "" ? 1 : 0\n  name = "x"\n}\n',
     True),
    # SECRET with policy omit (the platform never renders it) -> allowed
    ('resource "google_pubsub_topic" "t2" {\n  for_each = var.secret_data == "" ? toset([]) : toset(["a"])\n'
     '  name = "x"\n}\n', True),
    # dynamic-block for_each on a reference is legal when unknown (offline real-provider plan) -> not a meta-argument
    ('resource "google_pubsub_topic" "t2" {\n  name = "x"\n  dynamic "message_storage_policy" {\n'
     '    for_each = var.kms_key_name != null ? [1] : []\n    content {\n'
     '      allowed_persistence_regions = ["us-central1"]\n    }\n  }\n}\n', True),
])
def test_f4_static_count_rule(tmp_path, snippet, ok):
    mods = tmp_path / "modules"
    shutil.copytree(os.path.join(REPO_ROOT, "infra", "modules"), mods)
    var_decls = {"authorized_network": "cache-redis", "kms_key_name": "ai-vertex-endpoint",
                 "workload_sa_email": "storage-bucket", "secret_data": "security-secret"}
    target = next(m for v, m in var_decls.items() if f"var.{v}" in snippet)
    (mods / target / "probe.tf").write_text(snippet)
    _catalog, problems = BUILDER.build(mods)
    count_problems = [p for p in problems if "references" in p]
    assert (count_problems == []) == ok, count_problems


def test_f4_today_every_catalog_count_driver_is_plan_known_or_literal_only():
    for mid, entry in ART.catalog["modules"].items():
        for name, where in entry["count_drivers"].items():
            v = entry["variables"][name]
            # SECRET-INITIAL-VERSION: a TOPOLOGY input is a literal the platform renders (true / the default false)
            assert (v["class"] == "FACT" and v["fact"] in ii.PLAN_KNOWN_FACTS) or \
                (v["class"] == "SECRET" and v["policy"] == "omit") or v["class"] in ("AI", "TOPOLOGY"), \
                (mid, name, where)
            if v["class"] in ("AI", "TOPOLOGY"):
                assert v["count_driver"] is True


@functools.lru_cache(maxsize=None)
def _payload():
    ns = {}
    path = os.path.join(REPO_ROOT, "shared", "builtin_modules_payload.py")
    exec(compile(open(path).read(), path, "exec"), ns)  # noqa: S102 - repo-owned data module
    return ns["BUILTIN_MODULE_FILES"]


@pytest.mark.parametrize("mid", BUILDER.AI_INSTANTIABLE)
def test_builtin_payload_matches_the_catalog_modules(mid):
    payload = _payload()[mid]
    disk = {f: open(os.path.join(REPO_ROOT, "infra", "modules", mid, f)).read()
            for f in os.listdir(os.path.join(REPO_ROOT, "infra", "modules", mid)) if f.endswith(".tf")}
    assert payload == disk


# ------------------------------------------------------------------------------------------------ slice (RT F8)
def test_slice_parity_with_the_production_provider_set_and_validate_service():
    prod = json.load(open(os.path.join(REPO_ROOT, "eval", "config", "provider_sets.json")))["sets"]["production"]
    sl = ART.schema_slice
    assert sl["providers"] == prod["providers"]
    assert sl["engine"] == {"name": prod["engine"], "version": prod["engine_version"]}
    tf_dir = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
    if tf_dir not in sys.path:
        sys.path.append(tf_dir)          # appended: its shared/ copy must not shadow root shared/
    spec = importlib.util.spec_from_file_location("ti2_validate_service",
                                                  os.path.join(REPO_ROOT, "mcp-servers", "terraform",
                                                               "validate_service.py"))
    vs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vs)
    assert {p.split("/", 1)[1] for p in sl["providers"]} == set(vs.VALIDATE_PROVIDERS)
    assert vs.ENGINE_VERSIONS["opentofu"] == sl["engine"]["version"]
    man = ART.manifest["provider_schema"]
    assert man["providers"] == sl["providers"] and man["engine"] == sl["engine"]
    assert "mirror" not in json.dumps(man).lower().replace("filesystem_mirror", "")   # versions, never a mirror sha


def test_slice_holds_exactly_the_allow_listed_types_with_their_shape():
    rs = ART.schema_slice["resource_schemas"]
    assert set(rs) == set(ART.allowed["types"])
    for t, e in rs.items():
        assert e["provider"].split("/")[1] == ART.allowed["types"][t]["provider"]
        for blk in _blocks(e["block"]):
            for a in blk["attributes"].values():
                assert set(a) == {"type", "required", "optional", "computed", "sensitive", "write_only",
                                  "description"}
                assert len(a["description"]) <= 160
            for b in blk["block_types"].values():
                assert b["nesting_mode"] in ("single", "group", "list", "set", "map")
    assert rs["google_storage_bucket"]["block"]["block_types"]["lifecycle_rule"]["block"]["block_types"][
        "action"]["nesting_mode"] == "set"


def _blocks(b):
    yield b
    for bt in b["block_types"].values():
        yield from _blocks(bt["block"])


def test_runtime_parity_is_by_version_and_fails_closed():
    ii.check_ready_parity(ART, {"hashicorp/google": ["6.35.0", "5.44.0"], "hashicorp/google-beta": ["6.35.0"],
                                "hashicorp/kubernetes": ["2.36.0"], "hashicorp/random": "3.7.1"})
    for bad in (None, {}, {"hashicorp/google": ["6.36.0"], "hashicorp/google-beta": ["6.35.0"],
                           "hashicorp/kubernetes": ["2.36.0"], "hashicorp/random": ["3.7.1"]}):
        with pytest.raises(ii.IntentGateUnavailable) as e:
            ii.check_ready_parity(ART, bad)
        assert e.value.code == "GATE.IAC_SCHEMA_PARITY" and e.value.error_class == ii.ErrorClass.GATE_UNAVAILABLE


# ------------------------------------------------------------------------------------------------ GATE_UNAVAILABLE
@pytest.mark.parametrize("missing", ii.ARTIFACT_FILES)
def test_missing_artifact_is_gate_unavailable(tmp_path, missing):
    d = tmp_path / "iac_intent"
    shutil.copytree(DATA, d)
    os.unlink(d / missing)
    with pytest.raises(ii.IntentGateUnavailable) as e:
        ii.load_artifacts(str(d))
    assert e.value.code == "GATE.IAC_INTENT_ARTIFACT_MISSING"
    assert e.value.error_class == ii.ErrorClass.GATE_UNAVAILABLE


def test_malformed_or_inconsistent_artifacts_are_gate_unavailable(tmp_path):
    d = tmp_path / "a"
    shutil.copytree(DATA, d)
    (d / "allowed_types.json").write_text("{not json")
    with pytest.raises(ii.IntentGateUnavailable) as e:
        ii.load_artifacts(str(d))
    assert e.value.code == "GATE.IAC_INTENT_ARTIFACT_MALFORMED"
    d2 = tmp_path / "b"
    shutil.copytree(DATA, d2)
    cat = json.load(open(d2 / "module_catalog.json"))
    cat["modules"]["storage-bucket"]["variables"].pop("region")
    (d2 / "module_catalog.json").write_text(json.dumps(cat))
    with pytest.raises(ii.IntentGateUnavailable) as e:
        ii.load_artifacts(str(d2))
    assert e.value.code == "GATE.IAC_INTENT_ARTIFACT_INCONSISTENT"


def test_gateway_copy_is_byte_identical_and_without_data_it_is_gate_unavailable():
    a = open(os.path.join(REPO_ROOT, "shared", "iac_intent.py"), "rb").read()
    b = open(os.path.join(GATEWAY, "shared", "iac_intent.py"), "rb").read()
    assert a == b
    # TI-2b (RT F5): the gateway image is built from its committed copy, so the four artifacts are committed there
    # too (byte-identical, tests/test_typed_iac_ti2b_hardening.py); test_missing_artifact_* covers the fail-closed path.
