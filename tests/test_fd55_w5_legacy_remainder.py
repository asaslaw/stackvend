"""FD-55 W5 (register FD55-W5, owner 10-24): the gateway's legacy generation remainder.

* G15 (HB-04d): a planned Cloud Run service with no code gets no placeholder "Hello World" app; V3c-planned reports
  CONTAINER.ENTRYPOINT_MISSING on apps/<svc>/Procfile and nothing is written.
* G14 (HB-04c) / G16 (HB-01): no regex rewrite of main.tf, no name-matching rewiring of service accounts or Pub/Sub
  endpoints in custom.tf.
* G17 (HB-05) CONVERT: env vars are bound by an exact parser edit (python-hcl2 parse-tree offsets); valid input that
  already binds every key is byte-identical; values unchanged.
* G20 (HD-39) CONVERT: the modules / bundles to vendor come from parsed module `source` values (.tf and .tf.json);
  a commented-out source vendors nothing.
* G21 CONVERT + G22 / G23 / G24 folds: one Dockerfile rule, one runtime-pin rule, `<dir>/.gitkeep` only for a
  literal `StaticFiles(directory="<dir>")` call found by `ast`.
* G26 / G28 folds: the preflight copies of the add-only package / requirements contracts are gone.
Every converted rule has a Do No Harm negative test (valid input -> unchanged). Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import json
import os
import sys

import pytest
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: F401,E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: this file is acceptance evidence and must not skip", pytrace=False)

from developer_agent import handler as h  # noqa: E402
from developer_agent import preflight_validator as pv  # noqa: E402
from developer_agent import sibling_wiring as sw  # noqa: E402
from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.iac_intent_contract import RENDER_PATH, INTENT_PATH, is_intent_tree  # noqa: E402
from developer_agent.validators.base import ValidationContext  # noqa: E402
from developer_agent.validators.container import ENTRYPOINT_CODE, PlannedServiceCodeValidator  # noqa: E402
from gatekeeper_agent.verifier import SynthesisVerifierAgent  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.service_topology import validate_service_topology  # noqa: E402

W = "infra/workload/"
MAIN = W + "main.tf"
CUSTOM = W + "custom.tf"
PID = "shop"


def vt_of(services, primary, edges=()):
    raw = {"services": [{"name": n, "kind": k} for n, k in services], "primary_service": primary,
           "edges": [{"caller": a, "callee": b, "protocol": p} for a, b, p in edges], "resources": []}
    vt, diags = validate_service_topology(raw, product_id=PID)
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def ctx_of(files):
    return ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED)


# ============================================================================================ G15: no placeholder app
TWO = [("api", "cloudrun"), ("worker", "cloudrun")]


def test_planned_service_without_code_gets_no_file_and_a_typed_entrypoint_error():
    vt = vt_of(TWO, "api", [("api", "worker", "http")])
    files = {MAIN: "", "apps/api/main.py": "x = 1\n", "apps/api/Procfile": "web: uvicorn main:app\n"}
    before = dict(files)
    te.reconcile_multi_service_declarations(files=files, product_id=PID, spec_text="", archetype="cloudrun",
                                            target_services=["api", "worker"], topology=vt)
    assert not any(p.startswith("apps/worker/") for p in files)          # nothing written for the missing service
    assert {p: files[p] for p in before if p.startswith("apps/")} == {p: before[p] for p in before
                                                                       if p.startswith("apps/")}
    planned = te.planned_cloud_run_services("cloudrun", PID, ["api", "worker"], vt)
    assert planned == ("api", "worker")
    got = PlannedServiceCodeValidator(planned, vt).validate(ctx_of(files))
    assert [(d.code, d.file) for d in got] == [(ENTRYPOINT_CODE, "apps/worker/Procfile")]
    assert "no code" in got[0].message and "apps/worker/" in got[0].hint


def test_legacy_multi_service_without_code_writes_nothing():
    files = {MAIN: "", CUSTOM: "", "apps/api/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(files=files, product_id=PID, spec_text="", archetype="cloudrun",
                                            target_services=["api", "worker"])
    assert 'module "compute_worker"' in files[CUSTOM]                      # the compute module is still synthesized
    assert sorted(p for p in files if p.startswith("apps/")) == ["apps/api/main.py"]
    planned = te.planned_cloud_run_services("cloudrun", PID, ["api", "worker"])
    got = PlannedServiceCodeValidator(planned).validate(ctx_of(files))
    assert [(d.code, d.file) for d in got] == [(ENTRYPOINT_CODE, "apps/worker/Procfile")]


def test_planned_service_with_code_has_no_finding():
    """Negative: every planned service has an entry file (any spelling of its directory) -> no finding."""
    files = {"apps/api/main.py": "x = 1\n", "apps/my_worker/Procfile": "worker: python run.py\n",
             "apps/web/package.json": "{}\n"}
    got = PlannedServiceCodeValidator(("api", "my-worker", "web")).validate(ctx_of(files))
    assert got == []


def test_service_v3c_already_judges_is_not_reported_twice():
    files = {"apps/worker/consumer.py": "x = 1\n"}   # an LLM .py, no Procfile: V3c's own ENTRYPOINT_MISSING
    assert PlannedServiceCodeValidator(("worker",)).validate(ctx_of(files)) == []


@pytest.mark.parametrize("archetype,names,topology,want", [
    ("cloudrun", ["api"], None, ()),                                   # single service: nothing was ever stubbed
    ("cloudrun", ["shop", "worker"], None, ("worker",)),               # a primary named like the product: skipped
    ("cloudrun", ["api", "worker", "api"], None, ("api", "worker")),
    ("gke-autopilot", ["proc", "edge"], None, ("edge",)),              # non-Cloud Run primary: secondaries only
    ("foundation-only", ["a", "b"], None, ()),
])
def test_planned_set_mirrors_the_deleted_placeholder_scope(archetype, names, topology, want):
    assert te.planned_cloud_run_services(archetype, PID, names, topology) == want


def test_planned_set_on_the_topology_path():
    single = vt_of([("api", "cloudrun")], "api")
    assert te.planned_cloud_run_services("cloudrun", PID, ["api"], single) == ()
    gke = vt_of([("proc", "gke-autopilot"), ("edge", "cloudrun")], "proc")
    assert te.planned_cloud_run_services("gke-autopilot", PID, ["proc", "edge"], gke) == ("edge",)


def test_placeholder_app_source_is_gone():
    src = open(os.path.join(GATEWAY, "developer_agent", "terraform_engine.py")).read()
    assert "Hello World from" not in src and "def health_check" not in src


# ============================================================================================ G14 / G16
def test_hb01_name_matching_rewires_nothing_and_main_tf_is_not_rewritten():
    custom = ('locals {\n  scheduler_sa = var.scheduler_sa_email\n}\n\n'
              'resource "google_cloud_scheduler_job" "j" {\n  name = "j"\n  schedule = "0 2 * * *"\n'
              '  http_target {\n    uri = "https://x"\n    oidc_token {\n'
              '      service_account_email = "not-an-email"\n    }\n  }\n}\n\n'
              'resource "google_pubsub_subscription" "worker_push" {\n  name  = "worker-push"\n  topic = "t"\n'
              '  push_config {\n    push_endpoint = "${module.compute.service_uri}/push"\n  }\n}\n')
    main_tf = 'module "compute" {\n  source       = "../modules/compute-cloudrun"\n  service_name = "old"\n}\n'
    files = {MAIN: main_tf, CUSTOM: custom, "apps/api/main.py": "x = 1\n", "apps/worker/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(files=files, product_id=PID, spec_text="", archetype="cloudrun",
                                            target_services=["api", "worker"], llm_iac_paths=[CUSTOM])
    assert files[MAIN] == main_tf                                    # G14: no service_name / image regex rewrite
    assert files[CUSTOM].startswith(custom)                          # G16: the AI's blocks are byte-identical
    assert not hasattr(te, "reconcile_iac_reference_graph")


# ============================================================================================ G17: HB-05 parser edit
def golden_main(env=None):
    return te.generate_golden_main_tf(PID, "cloudrun", service_name="api", env_vars_override=env or {})


BUCKET = 'resource "google_storage_bucket" "uploads" {\n  name     = "${var.product_id}-uploads"\n  location = "EU"\n}\n'


def test_hb05_valid_main_tf_with_every_key_bound_is_byte_identical():
    """Negative (Do No Harm): main.tf already binds every key HB-05 derives from custom.tf -> both files unchanged."""
    files = {CUSTOM: BUCKET, "apps/api/main.py": "import os\nB = os.getenv('GCS_BUCKET_NAME')\n"}
    env = te.extract_custom_resource_env_vars(BUCKET, files, caller_service="api", caller_module="compute")
    files[MAIN] = golden_main(env)
    before = dict(files)
    cured = SynthesisVerifierAgent(product_id=PID).reconcile_iac_environment_contracts(dict(files))
    assert cured == before


def test_hb05_binds_a_missing_key_by_exact_edit_and_keeps_every_other_byte():
    files = {CUSTOM: BUCKET, "apps/api/main.py": "import os\n"}
    files[MAIN] = golden_main({"EXISTING": "var.project_id"})
    cured = SynthesisVerifierAgent(product_id=PID).reconcile_iac_environment_contracts(dict(files))
    want = files[MAIN].replace(
        '    "EXISTING" = var.project_id\n  })',
        '    "EXISTING" = var.project_id\n    "GCP_PROJECT_ID" = var.project_id\n'
        '    "GCS_BUCKET_NAME" = google_storage_bucket.uploads.name\n    "PROJECT_ID" = var.project_id\n  })')
    assert cured[MAIN] == want                    # the same bytes the old Case A wrote for a platform render
    assert cured[CUSTOM] == BUCKET
    again = SynthesisVerifierAgent(product_id=PID).reconcile_iac_environment_contracts(dict(cured))
    assert again == cured                         # idempotent (GK-5 re-cure is a no-op)


def test_hb05_plain_env_vars_becomes_a_merge_and_keeps_the_alignment():
    files = {CUSTOM: BUCKET, "apps/api/main.py": "import os\n", MAIN: golden_main()}
    assert "env_vars              = var.env_vars\n" in files[MAIN]
    cured = SynthesisVerifierAgent(product_id=PID).reconcile_iac_environment_contracts(dict(files))
    assert ('env_vars              = merge(var.env_vars, {\n    "GCP_PROJECT_ID" = var.project_id\n'
            '    "GCS_BUCKET_NAME" = google_storage_bucket.uploads.name\n    "PROJECT_ID" = var.project_id\n  })\n'
            ) in cured[MAIN]


def test_bind_module_env_object_value_with_braces_is_edited_at_the_real_end():
    """The old Case A regex stopped at the first `})` (here inside jsonencode); the parser edit uses the object's end."""
    text = ('module "compute" {\n  source   = "../modules/compute-cloudrun"\n'
            '  env_vars = merge(var.env_vars, {\n    "CFG" = jsonencode({a = 1})\n  })\n}\n')
    new, written = sw.bind_module_env(text, "compute", {"B": "var.project_id"})
    assert written == ["B"]
    assert new == text.replace('jsonencode({a = 1})\n  })', 'jsonencode({a = 1})\n    "B" = var.project_id\n  })')


@pytest.mark.parametrize("text", [
    'module "compute" {\n  env_vars = local.env\n}\n',                              # another value shape
    'module "compute" {\n  source = "x"\n}\n',                                       # no env_vars
    'module "compute" {\n  env_vars = var.env_vars\n',                               # unparseable
    'module "compute" {\r\n  env_vars = var.env_vars\r\n}\r\n',                      # CRLF: python-hcl2 refuses
    'module "other" {\n  env_vars = var.env_vars\n}\n',                              # no such module
    'module "compute" { env_vars = var.env_vars }\n',                                # not on its own line
])
def test_bind_module_env_writes_nothing_without_an_exact_edit(text):
    assert sw.bind_module_env(text, "compute", {"A": "var.project_id"}) == (text, [])


def test_bind_module_env_never_touches_a_heredoc_or_another_block():
    other = 'resource "x" "y" {\n  description = <<-EOT\n    env_vars = var.env_vars\n  EOT\n}\n'
    text = other + 'module "compute" {\n  env_vars = var.env_vars\n}\n'
    new, written = sw.bind_module_env(text, "compute", {"A": "var.project_id"})
    assert written == ["A"] and new.startswith(other)
    assert sw.module_env_keys(new, "compute") == {"A"}


def test_bind_module_env_plain_needs_permission():
    text = 'module "compute_b" {\n  env_vars = var.env_vars\n}\n'
    assert sw.bind_module_env(text, "compute_b", {"A": "var.project_id"}, allow_plain=False) == (text, [])


def test_hb05_regex_edits_are_gone():
    src = open(os.path.join(GATEWAY, "gatekeeper_agent", "verifier.py")).read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "reconcile_iac_environment_contracts")
    called = {c.func.attr for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)}
    assert not {"search", "finditer", "sub", "replace"} & called, called


# ============================================================================================ G20: HD-39 parser
def test_commented_out_module_source_vendors_nothing():
    files = {CUSTOM: ('# module "q" {\n#   source = "../modules/messaging-pubsub"\n# }\n'
                      '// source = "../bundles/data-platform"\n'
                      '/* module "r" { source = "../modules/data-cloudsql" } */\n')}
    te.vendor_terraform_modules(files, "cloudrun")
    vendored = {p.split("/")[2] for p in files if p.startswith("infra/modules/")}
    assert "messaging-pubsub" not in vendored and "data-cloudsql" not in vendored
    assert not any(p.startswith("infra/bundles/") for p in files)
    assert vendored >= {"workload-foundation", "compute-cloudrun"}       # the archetype's modules, as before


def test_verifier_commented_out_source_is_not_a_reference():
    files = {CUSTOM: '# module "q" {\n#   source = "../modules/messaging-pubsub"\n# }\n'}
    cured, errors = SynthesisVerifierAgent(PID).reconcile_iac_module_vendoring(dict(files))
    assert cured == files and errors == []


def test_parsed_module_sources_are_vendored_tf_and_tf_json():
    tf = 'module "q" {\n  source = "../modules/messaging-pubsub"\n}\n'
    tf_json = json.dumps({"module": {"db": {"source": "../modules/data-cloudsql"}}})
    files = {CUSTOM: tf, W + "custom.tf.json": tf_json}
    assert te.referenced_local_dirs(files, "modules") == {"messaging-pubsub", "data-cloudsql"}


@pytest.mark.parametrize("source,want", [
    ("../modules/workload-foundation/base", "workload-foundation"),
    ("./infra/modules/x", "x"),
    ("../../modules/x", "x"),
    ("../my_modules/x", None),                       # substring of `modules`: not the component
    ("git::https://example.com/r.git//modules/x", None),
    ("${path.module}/../modules/x", None),
    ("../modules", None),
])
def test_local_source_dir_is_exact(source, want):
    assert te.local_source_dir(source, "modules") == want


# ============================================================================================ G21-G24: container rule
@pytest.mark.parametrize("path,banned", [
    ("apps/a/Dockerfile", True), ("Dockerfile.dev", True), ("x/.dockerignore", True), ("apps/a/dockerfile", True),
    ("docs/dockerfile-notes.md", False), ("apps/a/Dockerfiles.md", False), ("apps/a/main.py", False),
])
def test_one_dockerfile_rule(path, banned):
    assert h.is_prohibited_container_file(path) is banned


def test_container_contract_removes_exactly_the_rule_and_the_verifier_no_longer_purges():
    files = {"apps/api/main.py": "x = 1\n", "apps/api/Dockerfile": "FROM x\n", ".dockerignore": "*\n",
             "docs/dockerfile-notes.md": "keep\n"}
    out = dict(files)
    h.enforce_container_contract(out, PID, "cloudrun")
    assert "apps/api/Dockerfile" not in out and ".dockerignore" not in out
    assert out["docs/dockerfile-notes.md"] == "keep\n"            # the old verifier twin deleted this file
    assert not hasattr(SynthesisVerifierAgent, "enforce_container_contracts")
    cured, _, _ = SynthesisVerifierAgent(PID).verify_and_cure(dict(files), product_id=PID)
    assert cured["apps/api/Dockerfile"] == "FROM x\n" and ".python-version" not in cured


def test_runtime_pin_is_the_one_rule_and_other_python_version_files_are_kept():
    files = {"apps/api/main.py": "x = 1\n", "apps/api/.python-version": "3.12\n", "tools/.python-version": "3.11\n"}
    out = dict(files)
    h.enforce_container_contract(out, PID, "cloudrun")
    assert out["apps/api/.python-version"] == "3.13\n" and out[".python-version"] == "3.13\n"
    assert out["tools/.python-version"] == "3.11\n"               # G22 (overwrite of every *.python-version) is gone


STATIC_MAIN = ("from fastapi import FastAPI\nfrom fastapi.staticfiles import StaticFiles\napp = FastAPI()\n"
               "app.mount('/static', StaticFiles(directory='static'), name='static')\n")


@pytest.mark.parametrize("code,want", [
    (STATIC_MAIN, ["static"]),
    ("import fastapi.staticfiles as s\nx = s.StaticFiles(directory='./assets/')\n", ["assets"]),
    ("# app.mount('/static', StaticFiles(directory='static'))\n", []),       # a comment
    ("DOC = \"StaticFiles(directory='static')\"\n", []),                       # a string
    ("from pathlib import Path\nStaticFiles(directory=Path(__file__).parent / 'static')\n", []),   # not a literal
    ("StaticFiles(directory='../outside')\n", []), ("StaticFiles(directory='/abs')\n", []),
    ("StaticFiles(directory='.')\n", []), ("def broken(:\n", []),
])
def test_static_mount_dirs_is_an_ast_rule(code, want):
    assert h.static_mount_dirs(code) == want


def test_gitkeep_only_for_a_mounted_directory_without_files():
    files = {"apps/api/main.py": STATIC_MAIN, "apps/web/main.py": "# StaticFiles static\nx = 1\n"}
    out = dict(files)
    h.enforce_container_contract(out, PID, "cloudrun")
    assert out["apps/api/static/.gitkeep"] == ""
    assert not any(p.startswith("apps/web/static/") for p in out)     # the old substring test added one here
    kept = dict(files, **{"apps/api/static/app.css": "body {}\n"})
    out2 = dict(kept)
    h.enforce_container_contract(out2, PID, "cloudrun")
    assert "apps/api/static/.gitkeep" not in out2                     # add-only: the directory already has a file


# ============================================================================================ G26 / G28 / F4
def test_preflight_twins_are_gone():
    for gone in ("validate_and_heal_python_requirements", "validate_and_heal_python_packages",
                 "validate_zero_dockerfiles"):
        assert not hasattr(pv, gone) and not hasattr(h, gone), gone


def test_intent_tree_is_the_sticky_rule():
    assert is_intent_tree({INTENT_PATH: "{}", RENDER_PATH: "{}"}) is True
    assert is_intent_tree({INTENT_PATH: "{}"}) is False and is_intent_tree({}) is False


# ============================================================================================ Fable RT fixes
FASTAPI = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/health")\ndef health():\n    return {"ok": True}\n'
WEB = "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"


def test_rt_f1_procfile_only_topology_worker_keeps_its_runtime_pin():
    """RT F1 (positive): a Procfile-only event-worker beside a `main.py` sibling is built and deployed (PWB-3), but
    detect_workload_services drops it; with the topology the one container rule pins it like the deleted twin did."""
    vt = vt_of([("api", "cloudrun"), ("worker", "event-worker")], "api")
    files = {"apps/api/main.py": "x = 1\n", "apps/worker/Procfile": "worker: python consumer.py\n",
             "apps/worker/consumer.py": "x = 1\n"}
    out = dict(files)
    h.enforce_container_contract(out, PID, "cloudrun", topology=vt)
    assert out["apps/worker/.python-version"] == "3.13\n" and out["apps/api/.python-version"] == "3.13\n"


def test_rt_f1_negatives_vm_worker_and_legacy_skeleton_get_no_pin():
    """RT F1 (negatives): a gce-worker VM dir (never built) gets no pin with the topology, nor a dir the topology does
    not name; without a topology a skeleton dir beside a `main.py` sibling stays unpinned (unchanged rule)."""
    vt = vt_of([("api", "cloudrun"), ("vmw", "gce-worker")], "api", [("api", "vmw", "launch")])
    files = {"apps/api/main.py": "x = 1\n", "apps/vmw/startup.sh": "#!/bin/sh\n", "apps/vmw/worker.py": "x = 1\n",
             "apps/libs/util.py": "x = 1\n"}
    with_topo = dict(files)
    h.enforce_container_contract(with_topo, PID, "cloudrun", topology=vt)
    assert "apps/vmw/.python-version" not in with_topo and "apps/libs/.python-version" not in with_topo
    legacy = {"apps/api/main.py": "x = 1\n", "apps/worker/Procfile": "worker: python c.py\n", "apps/worker/c.py": "x\n"}
    out = dict(legacy)
    h.enforce_container_contract(out, PID, "cloudrun")
    assert "apps/worker/.python-version" not in out and out["apps/api/.python-version"] == "3.13\n"


def test_rt_f2_legacy_synthesized_secondary_without_code_is_reported():
    """RT F2: on the legacy path an AI-declared `module "compute_reports"` is resynthesized as a secondary; the
    services HB-04 renders reach V3c-planned through `planned_out`, so a missing apps/reports/ is reported."""
    custom = 'module "compute_reports" {\n  source       = "../modules/compute-cloudrun"\n  service_name = "reports"\n}\n'
    files = {MAIN: "", CUSTOM: custom, "apps/api/main.py": "x = 1\n", "apps/worker/main.py": "x = 1\n"}
    rendered = []
    te.reconcile_multi_service_declarations(files=files, product_id=PID, spec_text="", archetype="cloudrun",
                                            target_services=["api", "worker"], llm_iac_paths=[CUSTOM],
                                            planned_out=rendered)
    assert set(rendered) == {"api", "worker", "reports"}
    assert not any(p.startswith("apps/reports/") for p in files)
    got = PlannedServiceCodeValidator(rendered).validate(ctx_of(files))
    assert [(d.code, d.file) for d in got] == [(ENTRYPOINT_CODE, "apps/reports/Procfile")]


def test_rt_f2_single_service_records_nothing_and_a_list_is_read_by_reference():
    rendered = []
    te.reconcile_multi_service_declarations(files={MAIN: "", "apps/api/main.py": "x\n"}, product_id=PID,
                                            spec_text="", target_services=["api"], planned_out=rendered)
    assert rendered == []
    holder = []
    v = PlannedServiceCodeValidator(holder)
    assert v.validate(ctx_of({})) == []
    holder.append("late")
    assert [d.file for d in v.validate(ctx_of({}))] == ["apps/late/Procfile"]


def test_rt_f3_planned_service_stop_names_its_reason_after_the_one_w5c_round():
    """FD55-W5c: the stop now comes after the one whole-service CREATE round (here answered with nothing)."""
    from developer_agent.repair_loop import (PLANNED_SERVICE_STOP_REASON, Assembled, LoopContext, RepairLoop,
                                             Router)
    from developer_agent.validators.base import ValidatorStack
    from shared.diagnostics import AssemblyRecord, Diagnostic, ErrorClass, MemoryLedgerStore, StageError
    from shared.hallucination_stack import HallucinationStackSettings
    calls = []
    st = ValidatorStack()
    st.register(PlannedServiceCodeValidator(("worker",)), "blocking")
    draft = {"apps/api/main.py": FASTAPI, "apps/api/Procfile": WEB}

    def assemble(d):
        return Assembled(tree=dict(d), record=AssemblyRecord(), assembled_root={})
    ctx = LoopContext(trace_id="t1", product_id=PID, assemble=assemble, stack=st, ledger_store=MemoryLedgerStore(),
                      settings=HallucinationStackSettings(), attribution={p: "backend_worker" for p in draft},
                      llm_draft_paths=set(draft), preexisting=set(), repair_fn=lambda t: calls.append(t) or {},
                      model="m", available_providers=["google"])
    with pytest.raises(StageError) as ei:
        RepairLoop(ctx).run(dict(draft))
    assert ei.value.error_class is ErrorClass.PLATFORM_DEFECT and len(calls) == 1
    assert calls[0].creates == ["apps/worker/Procfile", "apps/worker/main.py", "apps/worker/requirements.txt"]
    assert PLANNED_SERVICE_STOP_REASON in str(ei.value) and "apps/worker/" in str(ei.value)
    # a plain V3c create on a platform-only directory keeps the unnamed stop (unchanged)
    plain = Diagnostic(tool="container", code=ENTRYPOINT_CODE, severity="error", file="apps/stub/Procfile",
                       message="m", source="precommit")
    asm = Assembled(tree={"apps/stub/main.py": FASTAPI}, record=AssemblyRecord())
    assert Router(ctx, {}, asm).route(plain).reason is None
