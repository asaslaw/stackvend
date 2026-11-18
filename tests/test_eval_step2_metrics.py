"""S2-0 / G0 metrics (Step 2 plan §2.1 S2-0, §3.3, §3.4 D1(3) + gate): the exact env-read collector
(eval/stackvend_eval/env_reads.py), the google_project_service reference counter and the pure functions of
eval/tools/step2_g0_metrics.py. Offline: in-memory fixtures and a tmp results dir; the product is only read
(AST extraction from source), never imported."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import json
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from stackvend_eval.blobs import BlobStore  # noqa: E402
from stackvend_eval.env_reads import (FORM_BASESETTINGS_FIELD, FORM_ENVIRON_GET, FORM_ENVIRON_SUBSCRIPT,  # noqa: E402
                                      FORM_IMPORTED_ENVIRON_GET, FORM_IMPORTED_ENVIRON_SUBSCRIPT,
                                      FORM_IMPORTED_GETENV, FORM_OS_GETENV, exact_env_reads)
from stackvend_eval.paths import have_hcl2  # noqa: E402

needs_hcl2 = pytest.mark.skipif(not have_hcl2(), reason="python-hcl2 not installed (eval/.deps)")


def _tool():
    spec = importlib.util.spec_from_file_location("step2_g0_metrics_t", ROOT / "eval" / "tools" / "step2_g0_metrics.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def reads(src):
    return exact_env_reads(textwrap.dedent(src))


# ---- exact env reads: positive forms ---------------------------------------------------------------------------

def test_os_environ_subscript_get_getenv():
    r = reads('''
        import os
        a = os.environ["A_URL"]
        b = os.environ.get("B_URL")
        c = os.environ.get("C_URL", "x")
        d = os.getenv("D_URL")
        e = os.getenv("E_URL", "")
    ''')
    assert r.keys == {"A_URL", "B_URL", "C_URL", "D_URL", "E_URL"}
    assert r.forms["A_URL"] == {FORM_ENVIRON_SUBSCRIPT}
    assert r.forms["B_URL"] == {FORM_ENVIRON_GET} and r.forms["C_URL"] == {FORM_ENVIRON_GET}
    assert r.forms["D_URL"] == {FORM_OS_GETENV} and r.forms["E_URL"] == {FORM_OS_GETENV}


def test_import_os_as_alias_positive():
    r = reads('''
        import os as m
        x = m.environ["A"]
        y = m.getenv("B")
        z = os.environ["C"]          # `os` is not bound in this module
    ''')
    assert r.keys == {"A", "B"}


def test_from_os_import_environ_getenv_and_aliases():
    r = reads('''
        from os import environ, getenv
        from os import environ as e, getenv as g
        a = environ["A"]
        b = environ.get("B")
        c = getenv("C")
        d = e["D"]
        f = g("F", "dflt")
    ''')
    assert r.keys == {"A", "B", "C", "D", "F"}
    assert r.forms["A"] == {FORM_IMPORTED_ENVIRON_SUBSCRIPT}
    assert r.forms["B"] == {FORM_IMPORTED_ENVIRON_GET}
    assert r.forms["C"] == {FORM_IMPORTED_GETENV} and r.forms["F"] == {FORM_IMPORTED_GETENV}
    assert r.forms["D"] == {FORM_IMPORTED_ENVIRON_SUBSCRIPT}


def test_import_inside_function_counts():
    r = reads('''
        def f():
            import os
            return os.environ.get("INNER")
    ''')
    assert r.keys == {"INNER"}


# ---- exact env reads: negative forms --------------------------------------------------------------------------

def test_inexact_forms_are_not_counted():
    r = reads('''
        import os
        config = {}
        a = config.get("CONFIG_KEY")
        b = request.headers.get("X_HEADER")
        c = row["ROW_KEY"]
        d = payload["PAYLOAD_KEY"]
        e = settings.getenv("OTHER_GETENV")
        name = "DYN"
        f = os.getenv(name)
    ''')
    assert r.keys == set()
    assert any(u["kind"] == "non_literal_key" for u in r.uncounted)


def test_local_environ_not_from_os_is_not_counted():
    r = reads('''
        import os
        environ = {"A": "1"}
        x = environ["A"]
        y = environ.get("B")
        def getenv(k):
            return k
        z = getenv("C")
    ''')
    assert r.keys == set()


def test_environ_from_other_module_not_counted():
    r = reads('''
        from flask import environ
        from mylib import getenv
        a = environ["A"]
        b = getenv("B")
    ''')
    assert r.keys == set()


def test_environ_write_is_not_a_read():
    r = reads('''
        import os
        os.environ["SET_ME"] = "1"
        del os.environ["DEL_ME"]
    ''')
    assert r.keys == set()
    assert {u["kind"] for u in r.uncounted} == {"environ_subscript_write"}


def test_syntax_error_is_reported_not_raised():
    r = exact_env_reads("def broken(:\n")
    assert r.keys == set() and r.parse_error


# ---- BaseSettings ----------------------------------------------------------------------------------------------

def test_basesettings_field_upper_case():
    r = reads('''
        from pydantic_settings import BaseSettings
        class Settings(BaseSettings):
            core_processor_url: str = ""
            port: int = 8080
            _private: str = "x"
            def method(self):
                return 1
    ''')
    assert r.basesettings_classes == 1
    assert r.keys == {"CORE_PROCESSOR_URL", "PORT"}
    assert r.forms["CORE_PROCESSOR_URL"] == {FORM_BASESETTINGS_FIELD}


def test_basesettings_attribute_base_and_classvar_skipped():
    r = reads('''
        import pydantic_settings
        from typing import ClassVar
        class S(pydantic_settings.BaseSettings):
            a_url: str
            model_config: ClassVar[dict] = {}
            counter: ClassVar[int] = 0
    ''')
    assert r.basesettings_classes == 1 and r.keys == {"A_URL"}


def test_basesettings_field_alias_literal():
    r = reads('''
        from pydantic import Field
        from pydantic_settings import BaseSettings
        class S(BaseSettings):
            core: str = Field(default="", alias="CORE_URL")
            other: str = Field("", validation_alias="Other_Url")
            legacy: str = Field("", env="LEGACY_ENDPOINT")
    ''')
    assert r.keys == {"CORE_URL", "Other_Url", "LEGACY_ENDPOINT"}


def test_basesettings_env_prefix_literal_both_styles():
    r = reads('''
        from pydantic import Field
        from pydantic_settings import BaseSettings, SettingsConfigDict
        class A(BaseSettings):
            model_config = SettingsConfigDict(env_prefix="app_")
            core_url: str = ""
            aliased: str = Field("", alias="EXACT_ALIAS")
        class B(BaseSettings):
            target_uri: str = ""
            class Config:
                env_prefix = "SVC_"
    ''')
    assert r.basesettings_classes == 2
    # env_prefix applies to field names, not to an alias (pydantic-settings semantics)
    assert r.keys == {"APP_CORE_URL", "EXACT_ALIAS", "SVC_TARGET_URI"}


def test_basesettings_case_sensitive_literal_keeps_case():
    r = reads('''
        from pydantic_settings import BaseSettings, SettingsConfigDict
        class A(BaseSettings):
            model_config = SettingsConfigDict(env_prefix="Pre_", case_sensitive=True)
            Core_Url: str = ""
    ''')
    assert r.keys == {"Pre_Core_Url"}


def test_basesettings_non_literal_alias_or_prefix_unresolved():
    r = reads('''
        from pydantic import Field
        from pydantic_settings import BaseSettings, SettingsConfigDict
        PREFIX = "x_"
        NAME = "CORE_URL"
        class A(BaseSettings):
            model_config = SettingsConfigDict(env_prefix=PREFIX)
            a_url: str = ""
        class B(BaseSettings):
            core: str = Field("", alias=NAME)
            plain: str = ""
    ''')
    assert r.basesettings_classes == 2
    assert r.keys == set()   # never guessed
    by_class = {u["class"]: u["reasons"] for u in r.unresolved}
    assert by_class == {"A": ["non_literal_env_prefix"], "B": ["non_literal_alias:core"]}


def test_module_local_subclass_of_basesettings_subclass():
    r = reads('''
        from pydantic_settings import BaseSettings, SettingsConfigDict
        class Base(BaseSettings):
            model_config = SettingsConfigDict(env_prefix="APP_")
            shared_url: str = ""
        class Child(Base):
            child_url: str = ""
        class GrandChild(Child):
            grand_uri: str = ""
        class NotSettings:
            ignored_url: str = ""
    ''')
    assert r.basesettings_classes == 3
    assert r.keys == {"APP_SHARED_URL", "APP_CHILD_URL", "APP_GRAND_URI"}


def test_plain_class_and_pydantic_basemodel_not_settings():
    r = reads('''
        from pydantic import BaseModel
        class Req(BaseModel):
            target_url: str
    ''')
    assert r.basesettings_classes == 0 and r.keys == set()


# ---- google_project_service reference counter (python-hcl2 parse tree) ----------------------------------------

GPS_DRAFT = '''
# google_project_service.run is mentioned in a comment
// google_project_service.run again
/* google_project_service.run block comment */
resource "google_project_service" "run" {
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "apis" {
  for_each = toset(["a", "b"])
  project  = var.project_id
  service  = each.value
}

resource "google_storage_bucket" "b" {
  name       = "google_project_service.run in a string"
  label      = "${google_project_service.run.service}-x"
  other      = google_project_service.apis["a"].id
  ghost      = google_project_service.undeclared.id
  depends_on = [google_project_service.run, google_project_service.apis, module.foundation]
}
'''


@needs_hcl2
def test_gps_reference_counter_exact():
    t = _tool()
    g = t.gps_metrics({"infra/workload/custom.tf": GPS_DRAFT})
    assert g["blocks"] == 2
    assert g["literal_only"] == 1                         # only "run": literal service + disable_on_destroy = false
    assert g["declared"]["run"]["literal_only"] is True and g["declared"]["apis"]["literal_only"] is False
    assert g["depends_on_refs"] == 2                       # .run and .apis in depends_on
    assert g["expression_refs"] == 2                       # template interpolation + index traversal
    assert g["references"] == 4
    assert [r["name"] for r in g["undeclared_refs"]] == ["undeclared"]   # not counted
    assert g["referenced_blocks"] == 2


@needs_hcl2
def test_gps_literal_only_rejects_non_literal_shapes():
    t = _tool()
    src = '''
resource "google_project_service" "a" {
  service = var.api
}
resource "google_project_service" "b" {
  service            = "x.googleapis.com"
  disable_on_destroy = true
}
resource "google_project_service" "c" {
  service                    = "y.googleapis.com"
  disable_dependent_services = false
}
'''
    g = t.gps_metrics({"infra/workload/x.tf": src})
    assert g["blocks"] == 3 and g["literal_only"] == 0 and g["references"] == 0


# ---- tool pure functions on a tiny fixture --------------------------------------------------------------------

CUSTOM_TF = '''
resource "google_kms_key_ring" "kr" {
  name     = "kr"
  location = var.region
}

resource "google_pubsub_topic" "events" {
  name = "events"
}

module "compute_alpha" {
  source       = "../modules/compute-cloudrun"
  service_name = "alpha"
  env_vars = merge(var.env_vars, {
    "BETA_URL"      = module.compute_beta.service_uri
    "BETA_AUDIENCE" = module.compute_beta.service_uri
    "TOPIC"         = google_pubsub_topic.events.name
  })
}

module "compute_beta" {
  source       = "../modules/compute-cloudrun"
  service_name = "beta"
  env_vars = merge(var.env_vars, {
    "ALPHA_URL"      = module.compute_alpha.service_uri
    "ALPHA_AUDIENCE" = module.compute_alpha.service_uri
  })
}
'''

MAIN_TF = '''
module "foundation" {
  source          = "../modules/workload-foundation/base"
  additional_apis = var.additional_apis
}
'''

FIXTURE_TREE = {
    "infra/workload/custom.tf": CUSTOM_TF,
    "infra/workload/main.tf": MAIN_TF,
    "infra/workload/terraform.tfvars": 'additional_apis = ["pubsub.googleapis.com"]\n',
    # alpha reads BETA_URL exactly; beta only has ALPHA_URL in a dict subscript (old collector counts it)
    "apps/alpha/main.py": "import os\nBETA = os.environ.get('BETA_URL')\n",
    "apps/beta/main.py": "cfg = {}\nx = cfg['ALPHA_URL']\n",
}

CYCLE_MSG = ("Cycle: module.compute_alpha.var.env_vars (expand, reference), module.compute_beta.output.service_uri "
             "(expand), module.compute_beta.var.env_vars (expand, input), module.compute_alpha.output.service_uri")


def test_parse_cycle_nodes_and_modules():
    t = _tool()
    nodes = t.parse_cycle_nodes(CYCLE_MSG)
    assert nodes[0] == "module.compute_alpha.var.env_vars" and len(nodes) == 4
    assert t.cycle_modules(nodes) == ["compute_alpha", "compute_beta"]


def test_old_collector_replica_selection_and_forms():
    t = _tool()
    old_beta = t.old_collector(FIXTURE_TREE, "beta")
    assert old_beta["selection"] == "caller_files" and old_beta["keys"] == {"ALPHA_URL"}
    assert old_beta["forms"]["ALPHA_URL"] == {t.OLD_FORM_SUBSCRIPT_OTHER}
    fallback = t.old_collector(FIXTURE_TREE, "gamma")      # no apps/gamma/ -> every .py file (HB-05 fallback)
    assert fallback["selection"] == "all_files_fallback" and fallback["keys"] == {"ALPHA_URL", "BETA_URL"}
    assert t.old_collector(FIXTURE_TREE, None)["selection"] == "all_files_no_caller"


def test_binding_rules_replica():
    t = _tool()
    assert t.binding_rules("BETA_URL", "BETA", set()) == ["unconditional <TOKEN>_URL/_AUDIENCE"]
    assert t.binding_rules("BETA_SVC_ENDPOINT", "BETA", {"BETA_SVC_ENDPOINT"}) == ["shared noun"]
    assert t.binding_rules("BACKEND_URL", "BACKEND", {"BACKEND_URL"}) == [
        "unconditional <TOKEN>_URL/_AUDIENCE", "shared noun", "generic alias"]


@needs_hcl2
def test_cycle_attribution_fixture():
    t = _tool()
    parsed, bad = t.parse_all(t.root_tf(FIXTURE_TREE))
    assert not bad
    mods = t.module_calls(parsed)
    edges = t.sibling_edges(mods)
    assert {(e["caller_module"], e["key"], e["target_module"]) for e in edges} == {
        ("compute_alpha", "BETA_URL", "compute_beta"), ("compute_alpha", "BETA_AUDIENCE", "compute_beta"),
        ("compute_beta", "ALPHA_URL", "compute_alpha"), ("compute_beta", "ALPHA_AUDIENCE", "compute_alpha")}
    result = {"hallucination_stack": {"developer_failed_typed": {"diagnostics": [
        {"code": "TF.CYCLE", "message": CYCLE_MSG, "detail": None}]}}}
    hb05 = t.load_hb05(ROOT)
    (cyc,) = t.cycle_attribution(result, FIXTURE_TREE, mods, hb05)
    by = {(e["caller_module"], e["key"]): e for e in cyc["edges"]}
    assert by[("compute_alpha", "BETA_URL")]["class"] == "read exactly"
    assert by[("compute_alpha", "BETA_URL")]["exact_forms"] == [FORM_ENVIRON_GET]
    assert by[("compute_alpha", "BETA_URL")]["survives_s2d"] is True
    assert by[("compute_alpha", "BETA_AUDIENCE")]["class"] == "unread"
    assert by[("compute_beta", "ALPHA_URL")]["class"] == "guessed (old inexact form only)"
    assert by[("compute_beta", "ALPHA_URL")]["old_forms"] == [t.OLD_FORM_SUBSCRIPT_OTHER]
    # S2-D (HS-65): the product's narrowed HB-05 binds only exact reads (it bound all four before S2-D), and since code
    # RT F1 it also sees the references already written in this (pre-S2-D, cyclic) custom.tf: beta -> alpha is in the
    # HCL, so alpha's exact read of BETA_URL would close the loop and is withheld (IAC.SIBLING_URI_CYCLE).
    assert {k for k, e in by.items() if e["product_binds_on_final_custom_tf"]} == set()
    assert cyc["verdict"].startswith("edge compute_alpha.BETA_URL is read exactly")
    assert cyc["cycle_remains_after_s2d"] is False     # beta -> alpha has no surviving key


@needs_hcl2
def test_required_apis_and_coverage_fixture():
    t = _tool()
    ref = json.loads((ROOT / "eval" / "config" / "api_requirements_ref.json").read_text())
    req = t.required_apis(FIXTURE_TREE, ref)
    assert set(req["apis"]) >= {"cloudkms.googleapis.com", "pubsub.googleapis.com", "run.googleapis.com"}
    assert req["apis"]["cloudkms.googleapis.com"] == {"google_kms_key_ring"}
    assert "module:compute-cloudrun" in req["apis"]["run.googleapis.com"]
    assert "module:base" in req["apis"]["iam.googleapis.com"]
    ref2 = json.loads(json.dumps(ref))
    del ref2["resource_types"]["google_kms_key_ring"]
    assert t.required_apis(FIXTURE_TREE, ref2)["unknown_types"] == ["google_kms_key_ring"]
    cov = t.api_coverage(FIXTURE_TREE, ref, ["run.googleapis.com"], ROOT, lambda tf, yml: ["iam.googleapis.com"])
    assert cov["additional_apis"] == ["pubsub.googleapis.com"]
    assert cov["gaps"]["cloudkms.googleapis.com"] == ["google_kms_key_ring"]
    assert "cloudkms.googleapis.com" in cov["gateway_only_gaps"]
    assert "pubsub.googleapis.com" not in cov["gaps"]


def test_product_sources_extract_without_import():
    t = _tool()
    extract = t.load_extract_apis(ROOT)
    apis = extract({"main.tf": 'resource "google_kms_key_ring" "k" {}'}, None)
    # S2-C C1b: the product's apply scan is the exact table, so the plan's P-1 example (a KMS key ring outside both
    # old substring tables) now gets cloudkms enabled; before S2-C this asserted it was missing.
    assert "serviceusage.googleapis.com" in apis and "cloudkms.googleapis.com" in apis
    assert "cloudkms.googleapis.com" not in extract({"main.tf": '# google_kms_key_ring in a comment\n'}, None)
    vend = t.load_vending_apis(ROOT)
    assert "serviceusage.googleapis.com" in vend and len(vend) == len(set(vend))
    assert "apps.orchestrator-gateway" not in sys.modules and "service" not in sys.modules


@needs_hcl2
def test_reference_table_covers_golden_modules():
    t = _tool()
    ref = json.loads((ROOT / "eval" / "config" / "api_requirements_ref.json").read_text())
    chk = t.module_row_check(ROOT, ref)
    assert chk["unknown_golden_types"] == [] and chk["missing_module_rows"] == [] and chk["rows_incomplete"] == {}
    for table in ("resource_types", "data_types", "modules"):
        for key, apis in ref[table].items():
            assert all(a.endswith(".googleapis.com") for a in apis), key


@needs_hcl2
def test_main_end_to_end_on_tmp_results(tmp_path):
    t = _tool()
    run = tmp_path / "runs" / "01-r1"
    run.mkdir(parents=True)
    bs = BlobStore(run)
    draft = {"infra/workload/custom.tf": GPS_DRAFT}
    result = {"llm": {"per_call": [{"site": "developer_agent/handler.py:DeveloperAgent.generate_code_files"},
                                   {"site": "developer_agent/swarm_dispatcher.py:SwarmDispatcher._call"}]},
              "hallucination_stack": {"developer_failed_typed": {"error_class": "PLATFORM_DEFECT", "diagnostics": [
                  {"code": "TF.CYCLE", "message": CYCLE_MSG}]}},
              "tree_dumps": {"assemble": [{"call": 0, "draft": bs.put_tree(draft),
                                           "assembled": bs.put_tree(FIXTURE_TREE)}]}}
    (run / "result.json").write_text(json.dumps(result))
    assert t.main([str(tmp_path), "--product-root", str(ROOT)]) == 0
    rep = json.loads((tmp_path / "step2_g0_metrics.json").read_text())
    tot = rep["totals"]
    assert tot["single_turn_calls"] == 1 and tot["cycle_runs"] == ["01-r1"]
    assert tot["gps_blocks"] == 2 and tot["gps_references"] == 4 and tot["gps_runs_referencing"] == ["01-r1"]
    assert tot["golden_mutation_runs"] == []
    assert (tmp_path / "step2_g0_metrics.md").read_text().startswith("# S2-0 / G0 metrics")


# ---- code RT F8: exec'd product text must not depend on names outside the extracted namespace -------------------
def test_extract_defs_fails_loudly_on_a_new_module_level_dependency(tmp_path):
    tool = _tool()
    src = tmp_path / "prod.py"
    src.write_text("import json\n\ndef helper(x):\n    return x\n\n"
                   "def target(t):\n    try:\n        return helper(json.loads(t))\n    except Exception:\n"
                   "        return None\n")
    with pytest.raises(RuntimeError, match="helper"):
        tool._extract_defs(src, {"target"}, {})
    ns = tool._extract_defs(src, {"target", "helper"}, {"json": json})     # all globals present -> fine
    assert ns["target"]('"a"') == "a"


def test_extract_defs_of_the_real_product_resolves_every_global():
    tool = _tool()
    assert callable(tool.load_extract_apis(ROOT)) and callable(tool.load_hb05(ROOT))
