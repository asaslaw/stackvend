"""Step 2 S2-D (register HS-65; plan rev 2 §3.4 D1, RT F1, code RT ruling Q1): HB-05's sibling service_uri wiring is
narrowed to the exact env keys the caller's own code reads (`developer_agent/env_reads.py`, python `ast` only), in
both copies (terraform_engine.extract_custom_resource_env_vars and the verifier twin
reconcile_iac_environment_contracts). Unbound siblings are visible (V2f, report-only IAC.SIBLING_URI_UNBOUND); mutual
reads are not bound and block as IAC.SIBLING_URI_CYCLE for the AI to repair (AGENTS invariant 6). Pure fixtures: no
network, no credentials, no tofu."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent import sibling_wiring as sw  # noqa: E402
from developer_agent.assembly import index_blocks  # noqa: E402
from developer_agent.env_reads import env_reads  # noqa: E402
from developer_agent.terraform_engine import (extract_custom_resource_env_vars,  # noqa: E402
                                              generate_golden_main_tf)
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators.sibling import SiblingUriValidator  # noqa: E402
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from gatekeeper_agent.verifier import SynthesisVerifierAgent  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402

MAIN = "infra/workload/main.tf"
CUSTOM = "infra/workload/custom.tf"


def _mod(label, svc, env=None, source="../modules/compute-cloudrun"):
    body = "".join(f'    "{k}" = {v}\n' for k, v in sorted((env or {}).items()))
    env_expr = f"merge(var.env_vars, {{\n{body}  }})" if env else "var.env_vars"
    return (f'module "{label}" {{\n  source       = "{source}"\n  service_name = "{svc}"\n'
            f'  env_vars     = {env_expr}\n  depends_on   = [module.foundation]\n}}\n')


def _primary(svc="gateway", env=None):
    return _mod("compute", svc, env)


def _sibling_refs(text):
    """{(module label, env key, target module)} for env_vars elements that are module.<x>.service_uri (python-hcl2)."""
    out = set()
    for b in index_blocks(text) or []:
        if b.kind != "module":
            continue
        ev = (b.body or {}).get("env_vars")
        if not isinstance(ev, str):
            continue
        for k, v in _merge_object(ev).items():
            if v.startswith("${module.") and v.endswith(".service_uri}"):
                out.add((b.labels[0], k, v[len("${module."):-len(".service_uri}")]))
    return out


def _merge_object(ev):
    """The object argument of `merge(var.env_vars, {...})` as python-hcl2 renders it inside the attribute string."""
    if not ev.startswith("${merge(var.env_vars, ") or not ev.endswith(")}"):
        return {}
    inner = ev[len("${merge(var.env_vars, "):-2]
    return json.loads(inner)


def _cyclic(refs):
    adj = {}
    for a, _k, b in refs:
        adj.setdefault(a, set()).add(b)
    seen, stack = set(), set()

    def dfs(u):
        stack.add(u)
        for v in adj.get(u, ()):
            if v in stack or (v not in seen and dfs(v)):
                return True
        stack.discard(u)
        seen.add(u)
        return False
    return any(dfs(u) for u in list(adj) if u not in seen)


def _ctx(files, llm=None):
    llm = set(files) if llm is None else set(llm)
    return ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED if p in llm
                                   else Ownership.PLATFORM_RENDERED, draft={k: files[k] for k in llm if k in files})


def _v2f(files, cycles=False):
    return SiblingUriValidator(cycles=cycles).validate(_ctx(files))


def _sibling_keys(env):
    return {k: v for k, v in env.items() if v.startswith("module.")}


# ------------------------------------------------------------------------------------------------ env_reads
def test_product_env_reads_is_byte_identical_to_the_harness_copy():
    prod = Path(GATEWAY) / "developer_agent" / "env_reads.py"
    harness = Path(REPO_ROOT) / "eval" / "stackvend_eval" / "env_reads.py"
    assert prod.read_bytes() == harness.read_bytes()


def test_env_reads_exact_forms_only():
    code = (
        "import os\nfrom os import environ as E, getenv\nimport os as m\n"
        "a = os.environ['A_URL']\nb = os.environ.get('B_URL', 'x')\nc = os.getenv('C_URL')\n"
        "d = E['D_URL']\ne = E.get('E_URL')\nf = getenv('F_URL')\ng = m.getenv('G_URL')\n"
        # not reads: dict access, other objects' .get, headers, writes, non-literal keys
        "cfg = {}\nh = cfg['H_URL']\ni = cfg.get('I_URL')\nos.environ['J_URL'] = 'w'\nk = os.getenv(name)\n"
        "def f(request):\n    return request.headers.get('L_URL')\n"
    )
    assert env_reads({"apps/s/main.py": code}) == {"A_URL", "B_URL", "C_URL", "D_URL", "E_URL", "F_URL", "G_URL"}


def test_env_reads_basesettings_fields_alias_and_prefix():
    code = (
        "from pydantic import Field\nfrom pydantic_settings import BaseSettings, SettingsConfigDict\n"
        "class S(BaseSettings):\n    core_processor_url: str\n    core: str = Field(alias='CORE_URL')\n"
        "class P(BaseSettings):\n    model_config = SettingsConfigDict(env_prefix='APP_')\n    beta_url: str = ''\n"
        "class U(BaseSettings):\n    model_config = SettingsConfigDict(env_prefix=PFX)\n    gamma_url: str = ''\n"
    )
    assert env_reads({"apps/s/config.py": code}) == {"CORE_PROCESSOR_URL", "CORE_URL", "APP_BETA_URL"}
    assert env_reads({"apps/s/README.md": "os.getenv('X_URL')", "apps/s/broken.py": "def ("}) == set()


# ------------------------------------------------------------------------------------------------ binding
TWO = _mod("compute_alpha", "alpha") + _mod("compute_beta", "beta")


def test_b_reads_a_url_exactly_binds_it_and_nothing_else():
    files = {"apps/beta/main.py": "import os\nA = os.environ['ALPHA_URL']\n", "apps/alpha/main.py": "x = 1\n"}
    env_b = extract_custom_resource_env_vars(TWO, files, caller_service="beta", caller_module="compute_beta")
    assert _sibling_keys(env_b) == {"ALPHA_URL": "module.compute_alpha.service_uri"}
    env_a = extract_custom_resource_env_vars(TWO, files, caller_service="alpha", caller_module="compute_alpha")
    assert _sibling_keys(env_a) == {}                      # unconditional BETA_URL/BETA_AUDIENCE are gone
    plan = sw.plan_sibling_wiring(TWO, files, "alpha", caller_module="compute_alpha")
    assert [(u["sibling"], u["reason"]) for u in plan.unbound] == [("beta", sw.REASON_NOT_READ)]
    assert plan.withheld == []


def test_basesettings_field_and_alias_are_bound():
    tf = _mod("compute_core_processor", "core-processor") + _mod("compute_core", "core")
    cfg = ("from pydantic import Field\nfrom pydantic_settings import BaseSettings\n"
           "class Settings(BaseSettings):\n    core_processor_url: str\n    core_ep: str = Field(alias='CORE_ENDPOINT')\n")
    env = extract_custom_resource_env_vars(tf, {"apps/gateway/config.py": cfg}, caller_service="gateway",
                                           caller_module="compute")
    assert _sibling_keys(env) == {"CORE_PROCESSOR_URL": "module.compute_core_processor.service_uri",
                                  "CORE_ENDPOINT": "module.compute_core.service_uri"}


def test_field_alias_core_url_is_bound():
    tf = _mod("compute_core", "core")
    cfg = ("from pydantic import Field\nfrom pydantic_settings import BaseSettings\n"
           "class Settings(BaseSettings):\n    core: str = Field(alias='CORE_URL')\n")
    env = extract_custom_resource_env_vars(tf, {"apps/gateway/config.py": cfg}, caller_service="gateway",
                                           caller_module="compute")
    assert _sibling_keys(env) == {"CORE_URL": "module.compute_core.service_uri"}


def test_dict_access_alone_is_not_bound_and_is_reported():
    files = {MAIN: _primary("gateway"), CUSTOM: _mod("compute_alpha", "alpha"),
             "apps/gateway/main.py": "cfg = {}\nu = cfg['ALPHA_URL']\n", "apps/alpha/main.py": "x = 1\n"}
    env = extract_custom_resource_env_vars(files[CUSTOM], files, caller_service="gateway", caller_module="compute")
    assert _sibling_keys(env) == {}
    (d,) = _v2f(files)
    assert d.code == "IAC.SIBLING_URI_UNBOUND" and d.file == MAIN and d.block_address == "module.compute"
    assert d.symbol == "module.compute_alpha"
    assert json.loads(d.detail)["reason"] == sw.REASON_NOT_READ


def test_synthesized_service_without_code_gets_no_sibling_env_and_is_reported():
    files = {CUSTOM: _mod("compute_alpha", "alpha") + _mod("compute_service_2", "service-2"),
             "apps/alpha/main.py": "import os\nS = os.getenv('SERVICE_2_URL')\n"}
    env = extract_custom_resource_env_vars(files[CUSTOM], files, caller_service="service-2",
                                           caller_module="compute_service_2")
    assert _sibling_keys(env) == {}
    diags = [d for d in _v2f(files) if d.block_address == "module.compute_service_2"]
    assert [json.loads(d.detail)["reason"] for d in diags] == [sw.REASON_CALLER_UNRESOLVED]
    # the other direction is a plain exact read: bound
    env_a = extract_custom_resource_env_vars(files[CUSTOM], files, caller_service="alpha",
                                             caller_module="compute_alpha")
    assert _sibling_keys(env_a) == {"SERVICE_2_URL": "module.compute_service_2.service_uri"}


def test_exact_read_that_names_no_sibling_is_reported_not_bound():
    """Code RT ruling Q1 (02-r3): INTERNAL_SERVICE_URL is read exactly, but no sibling has TOKEN INTERNAL_SERVICE."""
    files = {MAIN: _primary("public-gateway"),
             CUSTOM: _mod("compute_internal_core", "internal-core"),
             "apps/public-gateway/main.py": "import os\nU = os.getenv('INTERNAL_SERVICE_URL')\n",
             "apps/internal-core/main.py": "x = 1\n"}
    env = extract_custom_resource_env_vars(files[CUSTOM], files, caller_service="public-gateway",
                                           caller_module="compute")
    assert _sibling_keys(env) == {}
    (d,) = [d for d in _v2f(files) if d.block_address == "module.compute"]
    detail = json.loads(d.detail)
    assert detail["reason"] == sw.REASON_NO_TOKEN_MATCH
    assert detail["unmatched_uri_reads"] == ["INTERNAL_SERVICE_URL"]
    assert "INTERNAL_CORE_URL" in detail["candidate_keys"]


def test_sibling_discovery_is_by_exact_module_source():
    tf = (_mod("compute_gke", "gke", source="../modules/compute-gke-autopilot")     # "compute" label, not Cloud Run
          + _mod("worker", "worker")                                               # no "compute" in the label
          + _mod("compute_x", "x", source="../modules/compute-cloudrun-extra"))      # substring only
    assert [s.label for s in sw.sibling_compute_modules(tf)] == ["worker"]
    files = {"apps/gw/main.py": "import os\na = os.getenv('GKE_URL')\nb = os.getenv('WORKER_URL')\nc = os.getenv('X_URL')\n"}
    env = extract_custom_resource_env_vars(tf, files, caller_service="gw", caller_module="compute")
    assert _sibling_keys(env) == {"WORKER_URL": "module.worker.service_uri"}


def test_caller_files_are_the_exact_service_directory_only():
    files = {"apps/beta/main.py": "x = 1\n", "apps/beta-two/main.py": "import os\na = os.getenv('ALPHA_URL')\n",
             "apps/other/main.py": "import os\na = os.getenv('ALPHA_URL')\n"}
    env = extract_custom_resource_env_vars(TWO, files, caller_service="beta", caller_module="compute_beta")
    assert _sibling_keys(env) == {}                       # no substring match, no all-files fallback
    files["apps/beta_svc/main.py"] = "x = 1\n"
    assert sw.service_py_files({"apps/Beta_Svc/main.py": "", "apps/beta-svc/x.py": ""}, "beta-svc").keys() == {
        "apps/Beta_Svc/main.py", "apps/beta-svc/x.py"}  # the platform's own "_" -> "-" normalisation, exact
    assert sw.service_py_files({"vendor/apps/beta/main.py": "", "lib/beta/apps/util.py": ""}, "beta") == {}  # RT F8
    dup = _mod("compute_one", "same") + _mod("compute_two", "same")
    assert [m.label for m in sw.sibling_compute_modules(dup)] == ["compute_two"]   # later module wins (HB-05)


def test_unresolved_primary_caller_uses_inventory_only_when_one_service_remains():
    files = {"apps/alpha/main.py": "x = 1\n", "apps/gw/main.py": "import os\na = os.getenv('ALPHA_URL')\n"}
    tf = _mod("compute_alpha", "alpha")
    env = extract_custom_resource_env_vars(tf, files, caller_module="compute")
    assert _sibling_keys(env) == {"ALPHA_URL": "module.compute_alpha.service_uri"}
    files["apps/third/main.py"] = "import os\na = os.getenv('ALPHA_URL')\n"
    env2 = extract_custom_resource_env_vars(tf, files, caller_module="compute")
    assert _sibling_keys(env2) == {}                      # two candidates: unresolved, nothing guessed


# ------------------------------------------------------------------------------------------------ invariant 6
def test_mutual_exact_read_is_not_bound_and_blocks_typed():
    files = {MAIN: _primary("gateway"), CUSTOM: TWO, "apps/gateway/main.py": "x = 1\n",
             "apps/alpha/main.py": "import os\nB = os.environ['BETA_URL']\n",
             "apps/beta/main.py": "import os\nA = os.getenv('ALPHA_URL')\n"}
    for svc in ("alpha", "beta"):
        env = extract_custom_resource_env_vars(TWO, files, caller_service=svc, caller_module=f"compute_{svc}")
        assert _sibling_keys(env) == {}
    diags = _v2f(files, cycles=True)
    assert sorted((d.code, d.file, d.symbol) for d in diags) == [
        ("IAC.SIBLING_URI_CYCLE", "apps/alpha/main.py", "BETA_URL"),
        ("IAC.SIBLING_URI_CYCLE", "apps/beta/main.py", "ALPHA_URL")]
    assert all(d.severity == "error" and d.error_class.value == "CODE_DEFECT" for d in diags)
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    assert stack.mode_of("V2f-cycle") == "blocking" and stack.mode_of("V2f") == "report_only"


def test_three_service_ring_is_withheld_and_a_tail_edge_is_bound():
    tf = _mod("compute_a", "a") + _mod("compute_b", "b") + _mod("compute_c", "c") + _mod("compute_d", "d")
    files = {CUSTOM: tf, "apps/a/main.py": "import os\nx = os.getenv('B_URL')\n",
             "apps/b/main.py": "import os\nx = os.getenv('C_URL')\n",
             "apps/c/main.py": "import os\nx = os.getenv('A_URL')\n",
             "apps/d/main.py": "import os\nx = os.getenv('A_URL')\n"}
    for svc in "abc":
        plan = sw.plan_sibling_wiring(tf, files, svc, caller_module=f"compute_{svc}")
        assert plan.bindings == {} and len(plan.withheld) == 1 and plan.withheld[0]["cycle"] == ["a", "b", "c"]
    plan_d = sw.plan_sibling_wiring(tf, files, "d", caller_module="compute_d")
    assert plan_d.bindings == {"A_URL": "module.compute_a.service_uri"} and plan_d.withheld == []
    assert len(_v2f(files, cycles=True)) == 3


def test_ring_through_a_secondary_not_yet_declared_is_detected():
    """HB-04 wires a secondary before its own module is in the text: the caller is still a node of the read graph."""
    tf = _mod("compute_beta", "beta")
    files = {"apps/alpha/main.py": "import os\nB = os.getenv('BETA_URL')\n",
             "apps/beta/main.py": "import os\nA = os.getenv('ALPHA_URL')\n"}
    plan = sw.plan_sibling_wiring(tf, files, "alpha")
    assert plan.bindings == {} and [w["key"] for w in plan.withheld] == ["BETA_URL"]
    # the primary is never a target, so it cannot close a cycle
    plan_p = sw.plan_sibling_wiring(tf, {"apps/gw/main.py": "import os\nB = os.getenv('BETA_URL')\n",
                                         "apps/beta/main.py": "import os\nA = os.getenv('GW_URL')\n"},
                                    "gw", caller_module="compute")
    assert plan_p.bindings == {"BETA_URL": "module.compute_beta.service_uri"}


# ------------------------------------------------------------------------------------------------ 04 / 05 shapes
SA_STUB = ('import os\nfrom fastapi import FastAPI\napp = FastAPI()\n@app.get("/health")\ndef h():\n'
           '    return {"environment": os.getenv("ENVIRONMENT", "prod")}\n')
STREAM = ("import os\nfrom google.cloud import pubsub_v1\nTOPIC = os.getenv('PUBSUB_TOPIC_ID')\n"
          "PROJECT = os.environ.get('GCP_PROJECT_ID')\nrow = {}\nrow['event_id'] = 1\n")
TOPICS = ('resource "google_pubsub_topic" "stream_events" {\n  name = "e"\n}\n'
          'resource "google_pubsub_topic" "stream_events_dlq" {\n  name = "d"\n}\n')


@pytest.mark.parametrize("a_label,a_svc,a_code", [
    ("compute_service_account", "service-account", SA_STUB),       # 04-r1 / 04-r2
    ("compute_service_2", "service-2", None),                       # 05-r1 (synthesized, no code)
    ("compute_edge_gateway", "edge-gateway", STREAM.replace("event_id", "fleet")),   # 05-r2
])
def test_04_05_cycle_shapes_are_acyclic_after_s2d(a_label, a_svc, a_code):
    """The four R2c cycle runs: two HB-04 secondaries, each got the other's <TOKEN>_URL/_AUDIENCE unconditionally
    although neither reads it. Through the verifier twin (main.tf = GKE primary, as in 04/05) and the generator."""
    gke_main = ('module "compute" {\n  source     = "../modules/compute-gke-autopilot"\n'
                '  project_id = var.project_id\n}\n')
    custom = TOPICS + _mod(a_label, a_svc, {"PROJECT_ID": "var.project_id"}) + _mod(
        "compute_stream_processor", "stream-processor", {"PROJECT_ID": "var.project_id"})
    files = {MAIN: gke_main, CUSTOM: custom, "apps/stream-processor/main.py": STREAM}
    if a_code:
        files[f"apps/{a_svc}/main.py"] = a_code
    cured = SynthesisVerifierAgent(product_id="test-04").reconcile_iac_environment_contracts(files)
    refs = _sibling_refs(cured[CUSTOM])
    assert refs == set() and not _cyclic(refs)
    for label, svc in ((a_label, a_svc), ("compute_stream_processor", "stream-processor")):
        env = extract_custom_resource_env_vars(custom, files, caller_service=svc, caller_module=label)
        assert _sibling_keys(env) == {}
        assert env["PUBSUB_TOPIC_ID"] == "google_pubsub_topic.stream_events.name"     # non-sibling env kept
    unbound = {(d.block_address, d.symbol) for d in _v2f(cured)}
    assert unbound == {(f"module.{a_label}", "module.compute_stream_processor"),
                       ("module.compute_stream_processor", f"module.{a_label}")}
    assert _v2f(cured, cycles=True) == []


def test_04_shape_old_wiring_was_cyclic():
    """Pins the defect S2-D removes (R2c 04-r1 custom.tf env, verbatim keys): the two unconditional bindings form
    module.compute_service_account <-> module.compute_stream_processor."""
    old = _mod("compute_service_account", "service-account",
               {"STREAM_PROCESSOR_URL": "module.compute_stream_processor.service_uri",
                "STREAM_PROCESSOR_AUDIENCE": "module.compute_stream_processor.service_uri"}) + _mod(
        "compute_stream_processor", "stream-processor",
        {"SERVICE_ACCOUNT_URL": "module.compute_service_account.service_uri",
         "SERVICE_ACCOUNT_AUDIENCE": "module.compute_service_account.service_uri"})
    assert _cyclic(_sibling_refs(old))


# ------------------------------------------------------------------------------------------------ Do No Harm
SINGLE_CUSTOM = ('resource "google_storage_bucket" "raw_events" {\n  name = "b"\n}\n'
                 'resource "google_pubsub_topic" "inbound_events" {\n  name = "t"\n}\n'
                 'resource "google_redis_instance" "cache" {\n  name = "r"\n}\n'
                 'resource "google_secret_manager_secret" "api_key" {\n  secret_id = "k"\n}\n')
SINGLE_APP = {"apps/api/main.py": "import os\nB = os.getenv('RAW_EVENTS_BUCKET')\nT = os.getenv('TOPIC_NAME')\n"}
# extract_custom_resource_env_vars on step2a @ e17c7b1 (before S2-D) for the fixture above, with and without a caller
# (computed on a clean export of e17c7b1; generate_golden_main_tf output was byte-identical too)
SINGLE_EXPECTED = {
    "GCS_BUCKET_NAME": "google_storage_bucket.raw_events.name",
    "RAW_EVENTS_BUCKET": "google_storage_bucket.raw_events.name",
    "PUBSUB_TOPIC_ID": "google_pubsub_topic.inbound_events.name",
    "EVENTS_TOPIC_ID": "google_pubsub_topic.inbound_events.name",
    "TOPIC_NAME": "google_pubsub_topic.inbound_events.name",
    "SECRET_API_KEY": "google_secret_manager_secret.api_key.secret_id",
    "REDIS_HOST": "google_redis_instance.cache.host",
    "REDIS_PORT": "tostring(google_redis_instance.cache.port)",
    "GCP_PROJECT_ID": "var.project_id",
    "PROJECT_ID": "var.project_id",
}


def test_single_service_env_is_unchanged():
    for kw in ({}, {"caller_service": "api"}, {"caller_service": "api", "caller_module": "compute"}):
        assert extract_custom_resource_env_vars(SINGLE_CUSTOM, SINGLE_APP, **kw) == SINGLE_EXPECTED
    assert extract_custom_resource_env_vars(None, SINGLE_APP) == {}
    assert extract_custom_resource_env_vars("", SINGLE_APP, caller_service="api") == {}


def test_primary_non_sibling_env_keeps_its_file_selection():
    """G-D (06-r2/r3): the primary's callers passed no caller_service before S2-D, so the non-sibling sections read
    every .py file for them; passing the primary's name for the sibling section must not narrow that selection.
    Expected = step2a @ e17c7b1 with no caller."""
    custom = ('resource "google_storage_bucket" "media" {\n  name = "b"\n}\n'
              + _mod("compute_factory_worker", "factory-worker"))
    app = {"apps/storefront/main.py": "import os\nP = os.getenv('PROJECT_ID')\n",
           "apps/factory-worker/main.py": "import os\nB = os.environ['BUCKET_NAME']\nR = os.getenv('RAW_EVENTS_BUCKET')\n"}
    env = extract_custom_resource_env_vars(custom, app, caller_service="storefront", caller_module="compute")
    assert {k: v for k, v in env.items() if not v.startswith("module.")} == {
        "BUCKET_NAME": "google_storage_bucket.media.name", "GCP_PROJECT_ID": "var.project_id",
        "GCS_BUCKET_NAME": "google_storage_bucket.media.name", "PROJECT_ID": "var.project_id",
        "RAW_EVENTS_BUCKET": "google_storage_bucket.media.name"}
    assert _sibling_keys(env) == {}          # the sibling section does use the primary's own files only
    # code RT F3: the same through both call sites (the G-D 06-r2/r3 regression lived in the caller arguments)
    main_tf = generate_golden_main_tf("p", archetype="cloudrun", service_name="storefront", custom_tf_content=custom,
                                      app_files=app)
    for k in ("BUCKET_NAME", "RAW_EVENTS_BUCKET"):
        assert f'"{k}" = google_storage_bucket.media.name' in main_tf
    files = {MAIN: _primary("storefront"), CUSTOM: custom, **app}
    cured = SynthesisVerifierAgent(product_id="p").reconcile_iac_environment_contracts(files)
    for k in ("BUCKET_NAME", "RAW_EVENTS_BUCKET"):
        assert f'"{k}" = google_storage_bucket.media.name' in cured[MAIN]
    # HB-04's secondary call (caller_service, no caller_module): its own directory only, as before S2-D
    env_w = extract_custom_resource_env_vars(custom, {**app, "apps/storefront/x.py": "import os\nS = os.getenv('STORAGE_BUCKET')\n"},
                                             caller_service="factory-worker")
    assert set(env_w) == {"GCS_BUCKET_NAME", "BUCKET_NAME", "RAW_EVENTS_BUCKET", "GCP_PROJECT_ID", "PROJECT_ID"}


def test_single_service_main_tf_and_verifier_are_byte_identical():
    main_tf = generate_golden_main_tf("p", archetype="cloudrun", service_name="api",
                                      custom_tf_content=SINGLE_CUSTOM, app_files=SINGLE_APP)
    for k, v in SINGLE_EXPECTED.items():
        assert f'"{k}" = {v}' in main_tf
    files = {MAIN: main_tf, CUSTOM: SINGLE_CUSTOM, **SINGLE_APP}
    v = SynthesisVerifierAgent(product_id="p")
    assert v.reconcile_iac_environment_contracts(files) == files            # already wired -> unchanged
    assert _v2f(files) == [] and _v2f(files, cycles=True) == []


def test_acyclic_multi_service_wired_tree_is_byte_identical_and_idempotent():
    """A valid two-secondary tree whose one sibling edge is read exactly and already bound: the verifier twin leaves
    every file byte-identical, twice; the generator produces the same binding."""
    nonsib = {k: v for k, v in SINGLE_EXPECTED.items() if k not in ("RAW_EVENTS_BUCKET", "TOPIC_NAME")}
    custom = (SINGLE_CUSTOM + _mod("compute_alpha", "alpha", {**nonsib, "BETA_URL": "module.compute_beta.service_uri"})
              + _mod("compute_beta", "beta", nonsib))
    files = {MAIN: _primary("api", nonsib),
             CUSTOM: custom, "apps/api/main.py": "x = 1\n",
             "apps/alpha/main.py": "import os\nB = os.environ.get('BETA_URL')\n", "apps/beta/main.py": "y = 2\n"}
    v = SynthesisVerifierAgent(product_id="p")
    once = v.reconcile_iac_environment_contracts(files)
    assert once == files and v.reconcile_iac_environment_contracts(once) == files
    env = extract_custom_resource_env_vars(custom, files, caller_service="alpha", caller_module="compute_alpha")
    assert _sibling_keys(env) == {"BETA_URL": "module.compute_beta.service_uri"}
    assert _v2f(files, cycles=True) == []
    assert [d for d in _v2f(files) if json.loads(d.detail)["reason"] == sw.REASON_NOT_WRITTEN] == []   # RT F2


def test_verifier_twin_wires_the_primary_by_its_literal_service_name():
    """main.tf's module "compute" service_name is the caller (two non-sibling services: the inventory alone would
    leave it unresolved)."""
    files = {MAIN: _primary("gateway", {"PROJECT_ID": "var.project_id"}), CUSTOM: _mod("compute_alpha", "alpha"),
             "apps/gateway/main.py": "import os\nA = os.getenv('ALPHA_URL')\n", "apps/alpha/main.py": "x = 1\n",
             "apps/admin/main.py": "import os\nA = os.getenv('ALPHA_AUDIENCE')\n"}
    cured = SynthesisVerifierAgent(product_id="p").reconcile_iac_environment_contracts(files)
    assert _sibling_refs(cured[MAIN]) == {("compute", "ALPHA_URL", "compute_alpha")}
    assert sw.primary_caller_service(files[MAIN]) == "gateway"
    assert sw.primary_caller_service(_mod("compute", "x", source="../modules/compute-gke-autopilot")) is None


def test_verify_and_cure_runs_the_narrowed_twin():
    """The fixtures above also hold through verify_and_cure (the twin runs on every assembly)."""
    gke_main = 'module "compute" {\n  source     = "../modules/compute-gke-autopilot"\n}\n'
    custom = _mod("compute_alpha", "alpha", {"PROJECT_ID": "var.project_id"}) + _mod(
        "compute_beta", "beta", {"PROJECT_ID": "var.project_id"})
    files = {MAIN: gke_main, CUSTOM: custom, "apps/alpha/main.py": "import os\nB = os.environ['BETA_URL']\n",
             "apps/beta/main.py": "import os\nA = os.getenv('ALPHA_URL')\n"}
    # FD-55 W8: verify_and_cure takes no archetype (its module vendoring is archetype-free)
    cured, _ok, _notes = SynthesisVerifierAgent(product_id="p").verify_and_cure(dict(files), product_id="p")
    assert _sibling_refs(cured[CUSTOM]) == set()                      # mutual read: neither edge bound
    files["apps/beta/main.py"] = "y = 2\n"
    cured2, _ok, _notes = SynthesisVerifierAgent(product_id="p").verify_and_cure(dict(files), product_id="p")
    assert _sibling_refs(cured2[CUSTOM]) == {("compute_alpha", "BETA_URL", "compute_beta")}


# ------------------------------------------------------------------------------------------------ tombstones
def test_hb05_substring_discovery_and_guess_rules_are_gone():
    src = (Path(GATEWAY) / "developer_agent" / "terraform_engine.py").read_text()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "extract_custom_resource_env_vars")
    consts = {c.value for c in ast.walk(fn) if isinstance(c, ast.Constant) and isinstance(c.value, str)}
    assert not consts & {"DOWNSTREAM_URL", "BACKEND_URL", "CORE_SERVICE_URL", "compute-cloudrun", "CLOUDRUN"}
    assert "custom_compute_modules" not in {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    vsrc = (Path(GATEWAY) / "gatekeeper_agent" / "verifier.py").read_text()
    twin = next(n for n in ast.walk(ast.parse(vsrc))
                if isinstance(n, ast.FunctionDef) and n.name == "reconcile_iac_environment_contracts")
    tconsts = {c.value for c in ast.walk(twin) if isinstance(c, ast.Constant) and isinstance(c.value, str)}
    assert "compute-cloudrun" not in tconsts and r'service_name\s*=\s*"([^"]+)"' not in tconsts


# ------------------------------------------------------------------------------------------------ code RT fixes
GKE_MAIN = 'module "compute" {\n  source     = "../modules/compute-gke-autopilot"\n}\n'

def test_read_closing_a_loop_with_an_hcl_reference_is_withheld_and_typed():
    """Code RT F1 (`cyc_ring_via_primary_direct_ref`): the AI's worker module already references
    module.compute.service_uri; the primary's code reads WORKER_URL exactly. Binding it would close a Terraform loop
    (an unlocated TF.CYCLE, PLATFORM_DEFECT); instead the read is withheld and the reading file gets a typed CODE
    diagnostic naming the HCL reference."""
    custom = _mod("compute_worker", "worker", {"GW_URL": "module.compute.service_uri"})
    app = {"apps/gw/main.py": "import os\nW = os.environ['WORKER_URL']\n", "apps/worker/main.py": "import os\n"}
    main_tf = generate_golden_main_tf("p", archetype="cloudrun", service_name="gw", custom_tf_content=custom,
                                      app_files=app)
    assert "module.compute_worker.service_uri" not in main_tf
    files = {MAIN: main_tf, CUSTOM: custom, **app}
    cured = SynthesisVerifierAgent(product_id="p").reconcile_iac_environment_contracts(files)
    assert "module.compute_worker.service_uri" not in cured[MAIN]
    assert not _cyclic(_sibling_refs(cured[MAIN]) | _sibling_refs(cured[CUSTOM]))
    (d,) = _v2f(cured, cycles=True)
    assert (d.code, d.file, d.symbol, d.error_class.value) == (
        "IAC.SIBLING_URI_CYCLE", "apps/gw/main.py", "WORKER_URL", "CODE_DEFECT")
    assert "module.compute_worker: GW_URL = module.compute.service_uri" in d.message
    # Do No Harm: without the HCL reference the same read is bound and nothing is reported
    plain = _mod("compute_worker", "worker")
    main_ok = generate_golden_main_tf("p", archetype="cloudrun", service_name="gw", custom_tf_content=plain,
                                      app_files=app)
    assert '"WORKER_URL" = module.compute_worker.service_uri' in main_ok
    assert _v2f({MAIN: main_ok, CUSTOM: plain, **app}, cycles=True) == []


def test_hcl_reference_between_secondaries_joins_the_cycle_graph():
    tf = _mod("compute_alpha", "alpha", {"BETA_URL": "module.compute_beta.service_uri"}) + _mod("compute_beta", "beta")
    files = {CUSTOM: tf, "apps/alpha/main.py": "x = 1\n", "apps/beta/main.py": "import os\nA = os.environ['ALPHA_URL']\n"}
    plan = sw.plan_sibling_wiring(tf, files, "beta", caller_module="compute_beta")
    assert plan.bindings == {} and [w["key"] for w in plan.withheld] == ["ALPHA_URL"]
    assert plan.withheld[0]["hcl_refs"] == ["module.compute_alpha: BETA_URL = module.compute_beta.service_uri"]
    assert sw.module_env_refs(tf)["compute_alpha"] == {"BETA_URL": ("module", "compute_beta", "service_uri")}
    assert sw.module_env_refs("not hcl {{{") == {}


def test_bound_but_not_written_is_reported():
    """Code RT F2: a secondary the twin never visits (declared outside custom.tf) reads a sibling key exactly; the
    plan binds it, the tree lacks it -> IAC.SIBLING_URI_UNBOUND reason not_written (report-only, never silent)."""
    files = {MAIN: GKE_MAIN, CUSTOM: _mod("compute_alpha", "alpha"), "infra/workload/compute.tf": _mod("compute_beta", "beta"),
             "apps/alpha/main.py": "x = 1\n", "apps/beta/main.py": "import os\nA = os.environ['ALPHA_URL']\n"}
    cured = SynthesisVerifierAgent(product_id="p").reconcile_iac_environment_contracts(files)
    nw = [d for d in _v2f(cured) if json.loads(d.detail)["reason"] == sw.REASON_NOT_WRITTEN]
    assert [(d.file, d.block_address, json.loads(d.detail)["key"]) for d in nw] == [
        ("infra/workload/compute.tf", "module.compute_beta", "ALPHA_URL")]


def test_hs65b_not_written_is_blocking_and_the_other_unbound_reasons_stay_report_only():
    """Owner row HS-65b (10-14): IAC.SIBLING_URI_UNBOUND reason=not_written is BLOCKING (its own validator,
    V2f-not-written); not_read / no_token_match / caller_unresolved / not_addressable stay report-only (V2f)."""
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    assert stack.mode_of("V2f-not-written") == "blocking" and stack.mode_of("V2f") == "report_only"
    # beta reads ALPHA_URL from a module the twin never visits (not_written); alpha reads none of beta's keys (not_read)
    files = {MAIN: GKE_MAIN, CUSTOM: _mod("compute_alpha", "alpha"), "infra/workload/compute.tf": _mod("compute_beta", "beta"),
             "apps/alpha/main.py": "x = 1\n", "apps/beta/main.py": "import os\nA = os.environ['ALPHA_URL']\n"}
    ctx = _ctx(files)

    def reasons(diags):
        return sorted(json.loads(d.detail)["reason"] for d in diags if d.code == "IAC.SIBLING_URI_UNBOUND")
    both = reasons(SiblingUriValidator().validate(ctx))
    blocking = reasons(SiblingUriValidator(not_written=True).validate(ctx))
    report_only = reasons(SiblingUriValidator(not_written=False).validate(ctx))
    assert blocking == [sw.REASON_NOT_WRITTEN]
    assert sw.REASON_NOT_WRITTEN not in report_only and report_only != []
    assert sorted(blocking + report_only) == both          # the split loses and duplicates nothing
    nw = [d for d in SiblingUriValidator(not_written=True).validate(ctx)]
    assert all(d.severity == "error" and d.error_class.value == "CODE_DEFECT" for d in nw)
    # a tree with no not_written finding gets nothing from the blocking validator
    quiet = dict(files, **{"apps/beta/main.py": "x = 2\n"})
    assert SiblingUriValidator(not_written=True).validate(_ctx(quiet)) == []


def test_twin_writes_a_read_sibling_url_into_a_plain_var_env_vars_secondary():
    """Code RT F2 Case B: python-hcl2 says `env_vars = var.env_vars` and the code reads a sibling URL exactly -> the
    twin writes the merge body (like the primary's Case B); idempotent; V2f then reports nothing for it."""
    files = {MAIN: GKE_MAIN, CUSTOM: _mod("compute_alpha", "alpha") + _mod("compute_beta", "beta"),
             "apps/alpha/main.py": "x = 1\n", "apps/beta/main.py": "import os\nA = os.environ['ALPHA_URL']\n"}
    v = SynthesisVerifierAgent(product_id="p")
    cured = v.reconcile_iac_environment_contracts(files)
    assert _sibling_refs(cured[CUSTOM]) == {("compute_beta", "ALPHA_URL", "compute_alpha")}
    beta = sw.module_env_refs(cured[CUSTOM])["compute_beta"]
    assert set(beta) == {"ALPHA_URL", "GCP_PROJECT_ID", "PROJECT_ID"}    # every missing key, as Case A writes
    # Do No Harm: a plain var.env_vars secondary that reads no sibling URL is left byte-identical
    quiet = dict(files, **{"apps/beta/main.py": "x = 2\n"})
    assert v.reconcile_iac_environment_contracts(quiet)[CUSTOM] == quiet[CUSTOM]
    assert v.reconcile_iac_environment_contracts(cured) == cured
    assert [d for d in _v2f(cured) if json.loads(d.detail)["reason"] == sw.REASON_NOT_WRITTEN] == []


def _not_written(files):
    """[(caller, key, sibling module)] of V2f's IAC.SIBLING_URI_UNBOUND reason=not_written findings."""
    out = []
    for d in _v2f(files):
        det = json.loads(d.detail)
        if d.code == "IAC.SIBLING_URI_UNBOUND" and det["reason"] == sw.REASON_NOT_WRITTEN:
            out.append((det["caller"], det["key"], det["sibling_module"]))
    return sorted(out)


def test_twin_case_b_never_rewrites_a_heredoc_line_that_looks_like_the_attribute():
    """bcd RT F1 (Do No Harm, probe P3), FD-55 W5: the real attribute carries a trailing comment and a heredoc holds
    the line `env_vars = var.env_vars`. The edit position comes from python-hcl2's parse tree (FD-55 W5 exact parser
    edit), so the heredoc is never touched: only the real attribute's value becomes `merge(var.env_vars, {...})` (its
    comment kept), every other byte of custom.tf is identical, and nothing is left for V2f to report as not_written."""
    heredoc = '  description  = <<-EOT\n    env_vars = var.env_vars\n  EOT\n'
    beta = (_mod("compute_beta", "beta").replace("  depends_on", heredoc + "  depends_on")
            .replace("env_vars     = var.env_vars\n", "env_vars     = var.env_vars # keep\n"))
    custom = _mod("compute_alpha", "alpha") + beta
    files = {MAIN: GKE_MAIN, CUSTOM: custom,
             "apps/alpha/main.py": "x = 1\n", "apps/beta/main.py": "import os\nA = os.environ['ALPHA_URL']\n"}
    cured = SynthesisVerifierAgent(product_id="p").reconcile_iac_environment_contracts(dict(files))
    assert cured[CUSTOM] == custom.replace(
        "env_vars     = var.env_vars # keep\n",
        ('env_vars     = merge(var.env_vars, {\n    "ALPHA_URL" = module.compute_alpha.service_uri\n'
         '    "GCP_PROJECT_ID" = var.project_id\n    "PROJECT_ID" = var.project_id\n  }) # keep\n'))
    assert heredoc in cured[CUSTOM]
    assert _not_written(cured) == []


def test_twin_case_b_trailing_comment_is_kept_and_the_binding_written():
    """bcd RT F3, FD-55 W5: `env_vars = var.env_vars # keep` is exactly `var.env_vars` for the parser, so the sibling
    URL the code reads is written into a merge, the comment stays, the rest is byte-identical and a second pass
    changes nothing."""
    beta = _mod("compute_beta", "beta").replace("env_vars     = var.env_vars\n", "env_vars     = var.env_vars # keep\n")
    custom = _mod("compute_alpha", "alpha") + beta
    files = {MAIN: GKE_MAIN, CUSTOM: custom,
             "apps/alpha/main.py": "x = 1\n", "apps/beta/main.py": "import os\nA = os.environ['ALPHA_URL']\n"}
    cured = SynthesisVerifierAgent(product_id="p").reconcile_iac_environment_contracts(dict(files))
    assert cured[CUSTOM] == custom.replace(
        "env_vars     = var.env_vars # keep\n",
        ('env_vars     = merge(var.env_vars, {\n    "ALPHA_URL" = module.compute_alpha.service_uri\n'
         '    "GCP_PROJECT_ID" = var.project_id\n    "PROJECT_ID" = var.project_id\n  }) # keep\n'))
    assert _not_written(cured) == []
    again = SynthesisVerifierAgent(product_id="p").reconcile_iac_environment_contracts(dict(cured))
    assert again[CUSTOM] == cured[CUSTOM]


def test_twin_other_env_shape_is_unchanged_and_reported_not_silent():
    """FD-55 W5: an `env_vars` that is neither `var.env_vars` nor `merge(var.env_vars, {...})` (here a local) has no
    exact edit: custom.tf is byte-identical and V2f reports the bound sibling URL as not_written."""
    beta = _mod("compute_beta", "beta").replace("env_vars     = var.env_vars\n", "env_vars     = local.beta_env\n")
    custom = _mod("compute_alpha", "alpha") + beta
    files = {MAIN: GKE_MAIN, CUSTOM: custom,
             "apps/alpha/main.py": "x = 1\n", "apps/beta/main.py": "import os\nA = os.environ['ALPHA_URL']\n"}
    cured = SynthesisVerifierAgent(product_id="p").reconcile_iac_environment_contracts(dict(files))
    assert cured[CUSTOM] == custom
    assert _not_written(cured) == [("beta", "ALPHA_URL", "module.compute_alpha")]


def test_for_each_compute_module_is_not_a_target_and_is_reported():
    """Code RT F6: module.<label>.service_uri is not a valid reference to a for_each/count module."""
    fe = _mod("compute_fleet", "fleet").replace('  depends_on', '  for_each     = toset(["a", "b"])\n  depends_on')
    tf = fe + _mod("compute_alpha", "alpha")
    files = {"apps/gw/main.py": "import os\nF = os.getenv('FLEET_URL')\nA = os.getenv('ALPHA_URL')\n"}
    plan = sw.plan_sibling_wiring(tf, files, "gw", caller_module="compute")
    assert plan.bindings == {"ALPHA_URL": "module.compute_alpha.service_uri"}
    assert [(u["sibling_module"], u["reason"]) for u in plan.unbound] == [
        ("module.compute_fleet", sw.REASON_NOT_ADDRESSABLE)]
