"""TI-3 (docs/planning/typed-iac-intent-plan.md §4 TI-3): the typed IaC intent generation contract.

Mode "generate" (HallucinationStackSettings.iac_intent_mode, sticky per workload): the IaC persona fills
infra/workload/iac_intent.json; the platform gates it, renders custom.tf.json and binds the topology's consumers to the
realizing entries. Mode "off" (default): every prompt and tree is byte-identical to before TI-3 (Do No Harm; the
recorded-run evidence is the $0 replay in docs/handoff/ti3-report.md). Hermetic: fakes for the LLM and /validate."""
import hermetic_guard  # noqa: F401  (first import)

import asyncio
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: put eval/.deps on PYTHONPATH; acceptance evidence must not skip", pytrace=False)

from developer_agent import hallucination_runtime as hr  # noqa: E402
from developer_agent import iac_intent_contract as C  # noqa: E402
from developer_agent.assembly import index_blocks  # noqa: E402
from shared import iac_intent as II  # noqa: E402
from shared.diagnostics import (AssemblyRecord, Diagnostic, ErrorClass, MemoryLedgerStore,  # noqa: E402
                                MemoryProvenanceStore, RepairBudgetExhausted, StageError)
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402
from shared.service_topology import validate_service_topology  # noqa: E402

W = "infra/workload/"
PID = "shop"
ART = II.load_artifacts()


@pytest.fixture(autouse=True)
def _no_firestore():
    """Settings reads (lead / junior model cascade) must never build a real Firestore client here."""
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


# ------------------------------------------------------------------------------------------------ fixtures
def topo(resources=(), services=(("shop", "cloudrun"),), primary="shop", edges=()):
    return {"services": [{"name": n, "kind": k} for n, k in services], "primary_service": primary,
            "edges": [{"caller": a, "callee": b, "protocol": p} for a, b, p in edges],
            "resources": [dict(r) for r in resources]}


UPLOADS = {"type": "google_storage_bucket", "logical_name": "uploads", "purpose": "user uploads",
           "consumers": [{"service": "shop", "env_key": "UPLOADS_BUCKET", "attribute": None}]}
EVENTS = {"type": "google_pubsub_topic", "logical_name": "events", "purpose": "events",
          "consumers": [{"service": "shop", "env_key": "EVENTS_TOPIC", "attribute": "id"}]}
FIRESTORE = {"type": "google_firestore_database", "logical_name": "db", "purpose": "app data",
             "consumers": [{"service": "shop", "env_key": "FIRESTORE_DB", "attribute": None}]}


def vt_of(raw, pid=PID):
    vt, diags = validate_service_topology(raw, product_id=pid)
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def record_of(raw):
    vt = vt_of(raw)
    return {"schema": "architect_compute_intent/v2", "target_compute_services": list(vt.names), "bundle_id": None,
            "compute_archetype": vt.archetype, "service_topology": vt.as_record()}


def intent(modules=(), resources=(), outputs=()):
    return json.dumps({"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources),
                       "outputs": list(outputs)}, indent=2)


BUCKET_MODULE = {"module": "storage-bucket", "name": "uploads", "realizes": "uploads",
                 "args": {"bucket_name_suffix": "uploads"}}
STICKY_REPO = {"infra/workload/iac_intent.json": json.dumps({"schema": "iac_intent/v1"}),
               "infra/workload/custom.tf.json": '{"//": "rendered"}\n'}   # an intent workload's commit (RT F7)
FACT = (lambda f: {"$ref": {"kind": "fact", "fact": f}})


def run_of(vt, existing=None):
    return C.build_intent_run(vt, existing or {}, artifacts=ART)


# ------------------------------------------------------------------------------------------------ mode (TI-3e)
def test_mode_defaults_off_and_is_sticky_per_workload():
    vt = vt_of(topo())
    assert HallucinationStackSettings().iac_intent_mode == "off"
    assert C.resolve_iac_intent_mode("off", {}, vt) == "off"
    assert C.resolve_iac_intent_mode("generate", {}, vt) == "generate"
    # a workload without a typed topology (legacy record path) is never put on the intent path by the setting
    assert C.resolve_iac_intent_mode("generate", {}, None) == "off"
    # sticky (RT F7): the committed intent AND the platform's render keep the workload on the intent path
    assert C.resolve_iac_intent_mode("off", STICKY_REPO, vt) == "generate"
    assert C.iac_intent_mode_decision("off", STICKY_REPO, vt) == ("generate", C.STICKY)
    # a lone intent file (no platform render: not a platform commit) is ignored, whatever the setting
    for setting in ("off", "generate"):
        assert C.iac_intent_mode_decision(setting, {C.INTENT_PATH: intent()}, vt) == ("off", C.INTENT_WITHOUT_RENDER)
    with pytest.raises(Exception):
        HallucinationStackSettings(iac_intent_mode="shadow")   # off / generate only


def _agent(runtime):
    from developer_agent import handler as h
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        agent = h.DeveloperAgent(project_id="")
    agent.attach_stack_runtime(runtime)
    return agent


def _runtime(client, **settings):
    return hr.HallucinationRuntime(ledger_store=MemoryLedgerStore(), provenance_store=MemoryProvenanceStore(),
                                   validate_client=client, settings=HallucinationStackSettings(**settings),
                                   source="test")


def test_mode_off_never_loads_the_intent_artifacts():
    """DNH: with mode off the developer stage does not even read the intent artifacts (no new failure mode)."""
    from developer_agent.compute_intent import ComputeIntent
    agent = _agent(_runtime(None))
    ci = MagicMock(spec=ComputeIntent)
    ci.topology = vt_of(topo([UPLOADS]))
    with patch.object(II, "load_artifacts", side_effect=AssertionError("artifacts read on mode off")):
        assert agent._resolve_intent_run(ci, {}, {"provider_versions": {}}) is None


def test_sticky_workload_without_topology_or_stack_fails_closed_before_any_llm_call():
    from developer_agent.compute_intent import ComputeIntent
    agent = _agent(_runtime(None))
    ci = MagicMock(spec=ComputeIntent)
    ci.topology = None
    with pytest.raises(StageError) as ei:
        agent._resolve_intent_run(ci, STICKY_REPO, {"provider_versions": {}})
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE
    ci.topology = vt_of(topo())
    with pytest.raises(StageError) as ei:   # no hallucination stack -> the gate cannot run
        agent._resolve_intent_run(ci, STICKY_REPO, None)
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE
    with pytest.raises(StageError) as ei:   # provider versions differ from the schema slice
        agent._resolve_intent_run(ci, STICKY_REPO, {"provider_versions": {"hashicorp/google": "5.0.0"}})
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE


# ------------------------------------------------------------------------------------------------ prompts (DNH)
def test_topology_contract_is_byte_identical_off_and_without_resources():
    from developer_agent.topology_wiring import topology_contract_rule
    multi = vt_of(topo([UPLOADS], services=(("shop", "cloudrun"), ("core", "cloudrun")),
                       edges=(("shop", "core", "http"),)))
    off = topology_contract_rule(multi)
    assert topology_contract_rule(multi, iac_intent=False) == off
    gen = topology_contract_rule(multi, iac_intent=True)
    assert "Declare these resources in infra/workload/custom.tf" in off and "custom.tf" not in gen
    assert '"realizes": "<name>"' in gen and "`uploads` (google_storage_bucket" in gen
    assert "golden module storage-bucket" in gen
    # a topology without resources: the intent contract equals today's contract
    bare = vt_of(topo(services=(("shop", "cloudrun"), ("core", "cloudrun")), edges=(("shop", "core", "http"),)))
    assert topology_contract_rule(bare, iac_intent=True) == topology_contract_rule(bare)


def test_developer_system_prompt_is_byte_identical_without_the_intent_rule():
    from developer_agent.prompt import build_developer_system_prompt
    base = build_developer_system_prompt(service_names=["shop"])
    assert build_developer_system_prompt(service_names=["shop"], iac_intent_rule=None) == base
    run = run_of(vt_of(topo([UPLOADS])))
    gen = build_developer_system_prompt(service_names=["shop"], iac_intent_rule=C.developer_intent_rule(run))
    assert gen.startswith(base.split("\n\nDYNAMIC GOLDEN MODULE CONTRACTS")[0])
    assert "infra/workload/iac_intent.json" in gen and run.run_context in gen


def test_intent_worker_prompt_example_passes_the_gate_and_the_hcl_prompt_is_unchanged():
    from developer_agent.juniors import iac_worker
    from developer_agent.juniors.prompt_registry import resolve_junior_prompt
    assert resolve_junior_prompt("IAC_ENGINEER") is iac_worker.IAC_WORKER_PROMPT   # mode off: the HCL prompt
    p = iac_worker.build_iac_intent_worker_prompt(ART)
    assert p == iac_worker.build_iac_intent_worker_prompt(ART)   # deterministic in the artifacts
    for mid in ART.ai_modules:
        assert f"- {mid}: args" in p
    for t in ART.allowed_types:
        assert f"- {t}: required" in p
    example = json.loads(p.split("EXAMPLE", 1)[1].split("\n", 1)[1])["files"][C.INTENT_PATH]
    res = II.validate_intent(example, ART, II.IntentContext(topology_resources={"uploads": "google_storage_bucket"}))
    assert res.ok, res.codes


def test_lead_rule_only_in_intent_mode_and_hcl_assignments_are_reasked():
    from developer_agent.lead_orchestrator import LeadDeveloperOrchestrator

    hcl_plan = {"execution_mode": "STANDARD_SWARM", "tasks": [
        {"task_id": "iac", "persona": "IAC_ENGINEER", "wave": 2, "assigned_files": [W + "main.tf"],
         "task_objective": "iac"}]}
    intent_plan = {"execution_mode": "STANDARD_SWARM", "tasks": [
        {"task_id": "iac", "persona": "IAC_ENGINEER", "wave": 2, "assigned_files": [C.INTENT_PATH],
         "task_objective": "iac"}]}
    prompts = []

    class Models:
        def __init__(self, answers):
            self.answers = list(answers)

        def generate_content(self, model, contents, config):
            prompts.append(contents)
            r = MagicMock()
            r.text = json.dumps(self.answers.pop(0))
            r.candidates = []
            return r

    def decompose(answers, **kw):
        client = MagicMock()
        client.models = Models(answers)
        lead = LeadDeveloperOrchestrator(genai_client=client, model_name="gemini-3.8-flash", db=None, project_id="")
        with patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent",
                   return_value=["gemini-3.8-flash", "gemini-2.5-flash"]):
            return lead.decompose_specification(product_id=PID, spec_text="x" * 2000, task_dag=[{}, {}], **kw)

    plan = decompose([hcl_plan])                      # mode off: the HCL plan is accepted as today
    assert plan.tasks[0].assigned_files == [W + "main.tf"] and C.lead_intent_rule() not in prompts[-1]
    prompts.clear()
    plan = decompose([hcl_plan, intent_plan], iac_intent_rule=C.lead_intent_rule())
    assert plan.tasks[0].assigned_files == [C.INTENT_PATH]
    assert C.lead_intent_rule() in prompts[0] and "IAC.HCL_ASSIGNED" in prompts[1] and W + "main.tf" in prompts[1]
    lead = LeadDeveloperOrchestrator(genai_client=None, model_name="m", db=None, project_id="")
    fb_off = lead._build_deterministic_fallback_plan(product_id=PID, iac_engine="OPENTOFU", vcs_provider="GITHUB")
    fb_gen = lead._build_deterministic_fallback_plan(product_id=PID, iac_engine="OPENTOFU", vcs_provider="GITHUB",
                                                     iac_intent=True)
    iac_off = [t for t in fb_off.tasks if t.persona.value == "IAC_ENGINEER"][0]
    iac_gen = [t for t in fb_gen.tasks if t.persona.value == "IAC_ENGINEER"][0]
    assert iac_off.assigned_files == [W + "main.tf", W + "variables.tf", W + "outputs.tf"]
    assert iac_gen.assigned_files == [C.INTENT_PATH] and not C.iac_hcl_assignments(fb_gen.tasks)


def test_swarm_iac_task_gets_the_intent_prompt_only_in_intent_mode_and_object_intents_are_normalized():
    from developer_agent.juniors.iac_worker import IAC_WORKER_PROMPT
    from developer_agent.swarm_dispatcher import SwarmDispatcher
    from developer_agent.swarm_schemas import (JuniorPersona, JuniorTaskAssignment, LeadDeveloperDecompositionPlan,
                                               SwarmExecutionMode)
    task = JuniorTaskAssignment(task_id="iac", persona=JuniorPersona.IAC_ENGINEER, wave=2,
                                assigned_files=[C.INTENT_PATH], task_objective="intent")
    plan = LeadDeveloperDecompositionPlan(execution_mode=SwarmExecutionMode.STANDARD_SWARM, tasks=[task])
    seen = []

    async def fake_call(self, prompt, system, model, trace_id=None, **kw):
        seen.append((prompt, system, kw))
        return {C.INTENT_PATH: intent()}, 10

    run = run_of(vt_of(topo([UPLOADS])))
    with patch.object(SwarmDispatcher, "_call_gemini_with_backoff", fake_call):
        d = SwarmDispatcher(genai_client=MagicMock(), model_name="m")
        asyncio.run(d.invoke_junior_worker(task, plan, {}, "m"))
        d.iac_intent = run
        asyncio.run(d.invoke_junior_worker(task, plan, {}, "m"))
    (p_off, s_off, kw_off), (p_gen, s_gen, kw_gen) = seen
    assert s_off == IAC_WORKER_PROMPT and kw_off == {} and run.run_context not in p_off
    assert s_gen == run.system_prompt and kw_gen == {"intent_task": True} and p_gen.endswith(run.run_context)
    obj = json.dumps({"files": {C.INTENT_PATH: {"schema": "iac_intent/v1"}, "apps/x.py": "x = 1\n"}})
    norm = json.loads(C.normalize_intent_envelope(obj))
    assert norm["files"][C.INTENT_PATH] == '{\n  "schema": "iac_intent/v1"\n}\n'
    assert norm["files"]["apps/x.py"] == "x = 1\n"
    as_text = json.dumps({"files": {C.INTENT_PATH: "{}"}})
    assert C.normalize_intent_envelope(as_text) == as_text   # a string value is never rewritten (DNH)
    assert C.normalize_intent_envelope("not json") == "not json"


def test_structured_output_schema_is_well_formed_and_off_by_default():
    assert HallucinationStackSettings().iac_intent_structured_output is False
    schema = C.intent_response_json_schema(ART)
    inner = schema["properties"]["files"]["properties"][C.INTENT_PATH]
    assert "$defs" not in inner and "ModuleInstance" in schema["$defs"]
    assert schema["$defs"]["ModuleInstance"]["properties"]["module"]["enum"] == list(ART.ai_modules)


# ------------------------------------------------------------------------------------------------ bindings (TI-3d)
def test_bindings_are_unchanged_without_realizations_and_follow_the_intent_with_them():
    vt = vt_of(topo([UPLOADS, EVENTS, FIRESTORE]))
    assert vt.realizations is None
    assert vt.resource_bindings("shop") == {"EVENTS_TOPIC": "google_pubsub_topic.events.id",
                                            "FIRESTORE_DB": "module.foundation.database_name",
                                            "UPLOADS_BUCKET": "google_storage_bucket.uploads.name"}
    bound = vt.with_realizations({"uploads": {"name": "module.uploads.bucket_name"}})
    # FOUNDATION_PROVIDED still binds module.foundation; an unrealized resource is bound to nothing
    assert bound.resource_bindings("shop") == {"FIRESTORE_DB": "module.foundation.database_name",
                                               "UPLOADS_BUCKET": "module.uploads.bucket_name"}
    assert vt.realization_needs() == {"events": ("google_pubsub_topic", ("id",)),
                                      "uploads": ("google_storage_bucket", ("name",))}
    assert vt.resource_bindings("shop") == vt_of(topo([UPLOADS, EVENTS, FIRESTORE])).resource_bindings("shop")


def test_realization_exports_are_exact_unconditional_module_outputs():
    for (mid, rtype), row in II.REALIZATION_EXPORTS.items():
        cat = ART.module(mid)
        assert cat is not None and rtype in cat["declares_types"], (mid, rtype)
        with open(os.path.join(REPO_ROOT, "infra", "modules", mid, "outputs.tf"), encoding="utf-8") as fh:
            outputs = {k: v for o in hcl2.load(fh).get("output", []) for k, v in o.items()}
        for attr, out in row.items():
            assert out in cat["outputs"], (mid, out)
            value = outputs[out]["value"]
            # TI-5-R2 P3: a module-only attribute (no provider-schema attribute of rtype) is exactly one attribute of
            # another resource the module declares (exact expected table below)
            otype, oattr = MODULE_ONLY_EXPORT_SOURCES.get((rtype, attr), (rtype, attr))
            assert otype in cat["declares_types"], (mid, otype)
            assert isinstance(value, str) and value.startswith("${" + otype + ".") and value.endswith("." + oattr + "}") \
                and value.count(".") == 2, (mid, out, value)
    # every module-only attribute has its exact source here, and nothing else does
    from shared.service_topology import MODULE_ONLY_ATTRIBUTES
    assert set(MODULE_ONLY_EXPORT_SOURCES) == {(t, a) for t, attrs in MODULE_ONLY_ATTRIBUTES.items() for a in attrs}


# TI-5-R2 P3: (topology type, module-only catalog attribute) -> (the realizing module's resource type, its attribute)
MODULE_ONLY_EXPORT_SOURCES = {("google_alloydb_instance", "password_secret_id"): ("google_secret_manager_secret",
                                                                                  "secret_id"),
                              # CLOUDSQL-PASSWORD-BINDING (owner 11-14)
                              ("google_sql_database_instance", "password_secret_id"): ("google_secret_manager_secret",
                                                                                       "secret_id")}


# ------------------------------------------------------------------------------------------------ assembly
def _assemble(vt, files, existing=None, root_keys=("module.foundation", "module.compute", "output.service_url")):
    rec = AssemblyRecord()
    files = dict(files)
    asm, bound = C.assemble_intent(files, run_of(vt, existing), vt, root_keys, existing_files=existing or {},
                                   record=rec)
    return asm, bound, files, rec


def test_gate_clean_intent_renders_custom_tf_json_and_binds_the_consumers():
    vt = vt_of(topo([UPLOADS]))
    asm, bound, files, _ = _assemble(vt, {C.INTENT_PATH: intent([BUCKET_MODULE])})
    assert asm.diagnostics == () and asm.rendered == (C.RENDER_PATH,) and asm.modules == ("storage-bucket",)
    doc = json.loads(files[C.RENDER_PATH])
    assert doc["module"]["uploads"]["source"] == "../modules/storage-bucket"
    assert doc["module"]["uploads"]["workload_sa_email"] == "${module.foundation.workload_sa_email}"
    assert bound.resource_bindings("shop") == {"UPLOADS_BUCKET": "module.uploads.bucket_name"}
    assert asm.provenance["/module/uploads"] == "/modules/0"
    # determinism: the same draft renders the same bytes
    assert _assemble(vt, {C.INTENT_PATH: intent([BUCKET_MODULE])})[2] == files


def test_platform_owned_type_is_a_typed_error_anchored_to_its_entry_and_nothing_is_rendered_or_bound():
    vt = vt_of(topo([UPLOADS]))
    bad = intent([BUCKET_MODULE], [{"type": "google_firestore_database", "name": "db",
                                    "arguments": {"name": "(default)"}}])
    asm, bound, files, _ = _assemble(vt, {C.INTENT_PATH: bad})
    d = [x for x in asm.diagnostics if x.code == "IAC.TYPE_NOT_ALLOWED"][0]
    assert d.file == C.INTENT_PATH and d.block_address == "google_firestore_database.db" and d.attribute_path == "/type"
    assert d.error_class is ErrorClass.CODE_DEFECT
    assert C.RENDER_PATH not in files and asm.rendered == ()
    assert bound.resource_bindings("shop") == {}   # never a reference to an address that does not exist


def test_unrealized_slots_and_missing_intent_are_typed_and_distinct():
    vt = vt_of(topo([UPLOADS, EVENTS]))
    asm, _, _, _ = _assemble(vt, {C.INTENT_PATH: intent()})
    un = [d for d in asm.diagnostics if d.code == "IAC.TOPOLOGY_RESOURCE_UNREALIZED"]
    assert sorted(d.symbol for d in un) == ["events", "uploads"]   # two findings, two fingerprints
    from shared.diagnostics import fingerprint
    assert len({fingerprint(d) for d in un}) == 2
    asm, _, _, _ = _assemble(vt, {"apps/shop/main.py": "x = 1\n"})
    assert [d.code for d in asm.diagnostics] == [C.INTENT_MISSING_CODE]
    asm, _, _, _ = _assemble(vt_of(topo()), {"apps/shop/main.py": "x = 1\n"})
    assert asm.diagnostics == () and asm.present is False   # nothing to realize, no intent needed


def test_module_without_the_consumed_export_is_a_typed_error():
    vt = vt_of(topo([EVENTS]))
    via_module = {"module": "messaging-pubsub", "name": "events", "realizes": "events", "args": {}}
    asm, bound, _, _ = _assemble(vt, {C.INTENT_PATH: intent([via_module])})
    assert asm.diagnostics == ()   # messaging-pubsub exports id as topic_id
    assert bound.resource_bindings("shop") == {"EVENTS_TOPIC": "module.events.topic_id"}
    vt = vt_of(topo([dict(EVENTS, type="google_secret_manager_secret", logical_name="key",
                          consumers=[{"service": "shop", "env_key": "KEY_ID", "attribute": "id"}])]))
    sec = {"module": "security-secret", "name": "key", "realizes": "key", "args": {"secret_id": "key"}}
    asm, _, _, _ = _assemble(vt, {C.INTENT_PATH: intent([sec])})
    assert [d.code for d in asm.diagnostics] == ["IAC.REALIZATION_EXPORT_MISSING"]


def test_ai_render_paths_are_reserved_and_recorded_and_a_sticky_intent_is_the_source():
    vt = vt_of(topo([UPLOADS]))
    asm, _, files, rec = _assemble(vt, {C.INTENT_PATH: intent([BUCKET_MODULE]), C.RENDER_PATH: '{"resource": {}}'})
    assert rec.dropped == {C.RENDER_PATH: "PLATFORM_PATH_RESERVED"} and json.loads(files[C.RENDER_PATH])["module"]
    existing = {C.INTENT_PATH: intent([BUCKET_MODULE])}
    asm, bound, files, _ = _assemble(vt, {"apps/shop/main.py": "x = 1\n"}, existing=existing)
    assert files[C.INTENT_PATH] == existing[C.INTENT_PATH] and asm.diagnostics == ()
    assert bound.resource_bindings("shop") == {"UPLOADS_BUCKET": "module.uploads.bucket_name"}


def test_vendoring_adds_exactly_the_intent_modules_and_is_unchanged_without_them():
    from developer_agent import handler as h
    base, plat = h.vendor_platform_files({}, "cloudrun")
    same, plat2 = h.vendor_platform_files({}, "cloudrun", intent_modules=())
    assert same == base and plat2 == plat
    more, plat3 = h.vendor_platform_files({}, "cloudrun", intent_modules=("storage-bucket",))
    added = sorted(set(plat3) - set(plat))
    assert added and all(p.startswith("infra/modules/storage-bucket/") for p in added)


# ------------------------------------------------------------------------------------------------ validators
def _vctx(files, draft=None, asm=None, iteration=0):
    from developer_agent.validators.base import ValidationContext
    return ValidationContext.build(files, ownership=lambda p: None, draft=dict(draft or {}), iteration=iteration,
                                   extras={"iac_intent": asm})


def test_ai_terraform_under_infra_is_a_typed_path_finding_never_dropped():
    from developer_agent.validators.iac_intent import IacHclPathValidator
    tf = 'resource "google_storage_bucket" "b" {\n  name = "x"\n}\nmodule "m" {\n  source = "../modules/x"\n}\n'
    draft = {W + "custom.tf": tf, W + "extra.tf.json": "{}", "apps/shop/main.tf.txt": "x", W + "empty.tf": "  \n",
             "infra/modules/x/main.tf": "# x\n"}
    out = IacHclPathValidator().validate(_vctx(draft, draft))
    got = sorted((d.file, d.block_address) for d in out)
    assert got == [("infra/modules/x/main.tf", None), (W + "custom.tf", "google_storage_bucket.b"),
                   (W + "custom.tf", "module.m"), (W + "extra.tf.json", None)]
    assert {d.code for d in out} == {C.IAC_HCL_NOT_ALLOWED_CODE} and all(d.error_class is ErrorClass.CODE_DEFECT
                                                                          for d in out)
    # DNH: app code and an emptied file are never findings
    assert IacHclPathValidator().validate(_vctx({"apps/a.py": "x"}, {"apps/a.py": "x", W + "c.tf": ""})) == []


def test_rendered_policy_backstop_is_silent_on_a_real_render_and_flags_a_tampered_one():
    from developer_agent.validators.iac_intent import GATE_GAP_CODE, IntentGateValidator, RenderedIntentPolicyValidator
    vt = vt_of(topo([UPLOADS]))
    asm, _, files, _ = _assemble(vt, {C.INTENT_PATH: intent([BUCKET_MODULE])})
    assert RenderedIntentPolicyValidator().validate(_vctx(files, asm=asm)) == []
    assert IntentGateValidator().validate(_vctx(files, asm=asm)) == []
    tampered = dict(files)
    doc = json.loads(tampered[C.RENDER_PATH])
    doc["resource"] = {"google_billing_budget": {"b": {}},
                       "google_project_iam_member": {"o": {"role": "roles/owner", "member": "allUsers",
                                                           "count": 1}}}
    tampered[C.RENDER_PATH] = json.dumps(doc)
    out = RenderedIntentPolicyValidator().validate(_vctx(tampered, asm=asm))
    assert {d.code for d in out} == {GATE_GAP_CODE} and len(out) == 4
    assert all(d.error_class is ErrorClass.PLATFORM_DEFECT for d in out)
    from developer_agent.validators.base import ValidatorUnavailable
    with pytest.raises(ValidatorUnavailable):   # registered on the intent path only: no gate run is never a pass
        IntentGateValidator().validate(_vctx(files, asm=None))


def test_step1_stack_registers_the_intent_validators_only_in_intent_mode():
    from developer_agent.validators.step1 import build_step1_stack
    off = build_step1_stack(validate_client=None, verifier_factory=None)
    gen = build_step1_stack(validate_client=None, verifier_factory=None, iac_intent=object())
    ids = lambda s: [r.validator.id for r in s._regs]  # noqa: E731
    assert ids(gen) == ids(off) + ["V-IAC", "V-IAC-PATH", "V-IAC-RENDER"]


# ------------------------------------------------------------------------------------------------ routing
def _router(tree, draft, asm_intent, attribution=None, preexisting=()):
    from developer_agent.repair_loop import Assembled, LoopContext, Router
    from developer_agent.validators.base import ValidatorStack
    ctx = LoopContext(trace_id="t", product_id=PID, assemble=lambda d: None, stack=ValidatorStack(),
                      ledger_store=MemoryLedgerStore(), settings=HallucinationStackSettings(),
                      attribution=dict(attribution or {}), llm_draft_paths=set(draft), preexisting=set(preexisting),
                      preexisting_files={p: tree[p] for p in preexisting if p in tree})
    asm = Assembled(tree=dict(tree), record=AssemblyRecord(), iac_intent=asm_intent)
    return Router(ctx, draft, asm)


def _diag(code, file, block=None, tool="tofu", cls=ErrorClass.CODE_DEFECT):
    return Diagnostic(tool=tool, code=code, severity="error", error_class=cls, file=file, block_address=block,
                      message="m", source="precommit")


def test_intent_findings_route_to_the_iac_persona_and_platform_files_stay_platform_defects():
    vt = vt_of(topo([UPLOADS]))
    asm, _, files, _ = _assemble(vt, {C.INTENT_PATH: intent([BUCKET_MODULE])})
    files[W + "services.tf"] = "# platform\n"
    draft = {C.INTENT_PATH: files[C.INTENT_PATH], "apps/shop/main.py": "x = 1\n"}
    r = _router(files, draft, asm, attribution={C.INTENT_PATH: "IAC_ENGINEER", "apps/shop/main.py": "BACKEND"})
    got = r.route(_diag("IAC.UNKNOWN_ARGUMENT", C.INTENT_PATH, "module.uploads", tool="schema"))
    assert (got.error_class, got.persona, got.draft_path) == (ErrorClass.CODE_DEFECT, "IAC_ENGINEER", C.INTENT_PATH)
    assert r.route(_diag("TF.UNSUPPORTED_ARGUMENT", W + "services.tf")).error_class is ErrorClass.PLATFORM_DEFECT
    # TF.* in the render of an intent entry -> the intent's author (exact provenance); no block -> renderer defect
    got = r.route(_diag("TF.UNSUPPORTED_ARGUMENT", C.RENDER_PATH, "module.uploads"))
    assert (got.error_class, got.persona, got.draft_path) == (ErrorClass.CODE_DEFECT, "IAC_ENGINEER", C.INTENT_PATH)
    assert json.loads(got.hint)["rendered_from"] == "/modules/0"
    assert r.route(_diag("TF.UNSUPPORTED_ARGUMENT", C.RENDER_PATH)).error_class is ErrorClass.PLATFORM_DEFECT
    assert r.route(_diag("TF.X", C.RENDER_PATH, "module.other")).error_class is ErrorClass.PLATFORM_DEFECT
    # a missing intent is a create for the IaC persona
    r2 = _router({"apps/shop/main.py": "x"}, {"apps/shop/main.py": "x"}, C.IntentAssembly())
    got = r2.route(_diag(C.INTENT_MISSING_CODE, C.INTENT_PATH, tool="schema"))
    assert (got.error_class, got.persona, got.draft_path) == (ErrorClass.CODE_DEFECT, "IAC_ENGINEER", C.INTENT_PATH)
    # a sticky workload's committed intent (not drafted this run) is repaired in place by the IaC persona
    r3 = _router({C.INTENT_PATH: intent()}, {"apps/shop/main.py": "x"}, C.IntentAssembly(present=True),
                 preexisting=(C.INTENT_PATH,))
    got = r3.route(_diag("IAC.TOPOLOGY_RESOURCE_UNREALIZED", C.INTENT_PATH, tool="schema"))
    assert (got.error_class, got.persona, got.draft_path) == (ErrorClass.CODE_DEFECT, "IAC_ENGINEER", C.INTENT_PATH)


def test_rendered_route_is_inert_off_intent_mode():
    """DNH: without an IntentAssembly a custom.tf.json finding routes exactly as before TI-3."""
    tree = {C.RENDER_PATH: "{}"}
    r = _router(tree, {C.RENDER_PATH: "{}"}, None, attribution={C.RENDER_PATH: "IAC_ENGINEER"})
    got = r.route(_diag("TF.UNSUPPORTED_ARGUMENT", C.RENDER_PATH, "module.uploads"))
    assert (got.error_class, got.draft_path) == (ErrorClass.CODE_DEFECT, C.RENDER_PATH)


# ------------------------------------------------------------------------------------------------ end to end
class Client:
    def __init__(self):
        self.validated = []

    def ready(self, iac_engine="OPENTOFU"):
        return {"ready": True, "providers": ["google", "google-beta", "kubernetes", "random"], "engine": "OPENTOFU",
                "engine_version": "1.9.0", "reason": "",
                "provider_versions": {k: [v] for k, v in ART.manifest["provider_schema"]["providers"].items()}}

    def validate(self, files, *, iac_engine="OPENTOFU", trace_id=""):
        self.validated.append(dict(files))
        return {"status": "PASS", "diagnostics": []}


class _NoCallGenai:
    class models:  # noqa: N801
        @staticmethod
        def generate_content(*a, **k):
            raise AssertionError("unexpected LLM call")


APP = {"apps/shop/main.py": "from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get('/health')\ndef health():\n"
                            "    return {'ok': True}\n",
       "apps/shop/requirements.txt": "fastapi>=0.110.0\nuvicorn>=0.28.0\n",
       "apps/shop/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"}


def _generate(mode, draft, attribution, raw=None, repairs=(), agent_out=None, **settings):
    from developer_agent import handler as h
    client = Client()
    agent = _agent(_runtime(client, iac_intent_mode=mode, **settings))
    if agent_out is not None:
        agent_out.append(agent)
    agent.genai_client = _NoCallGenai()
    plan = MagicMock()
    plan.execution_mode = [m for m in h.SwarmExecutionMode if m != h.SwarmExecutionMode.SOLO_FAST_PATH][0]
    plan.tasks = [MagicMock()]
    seen = {"repair_tasks": []}
    answers = list(repairs)

    class FakeDispatcher:
        def __init__(self, *a, **k):
            self.last_file_attribution = dict(attribution)
            self.envelope_checks = [{"ok": True, "error": None}]
            self.iac_intent = None

        async def execute_phased_junior_swarm(self, *a, **k):
            seen["iac_intent"] = self.iac_intent
            return dict(draft)

        def invoke_repair(self, persona, system_instruction, prompt, model, max_out, **k):
            seen["repair_tasks"].append({"persona": persona, "system": system_instruction, "prompt": prompt,
                                         "iac_intent": self.iac_intent})
            return {"files": answers.pop(0), "envelope_ok": True, "finish_reason": "STOP", "tokens_in": 1,
                    "tokens_out": 1, "tokens_thoughts": 0, "model": model, "persona": persona}

    with patch.object(h, "LeadDeveloperOrchestrator") as lead, patch.object(h, "SwarmDispatcher", FakeDispatcher), \
            patch.object(agent, "fetch_existing_repo_files", return_value={}), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
        lead.return_value.decompose_specification.return_value = plan
        try:
            files = agent.generate_code_files(product_id=PID, spec_text="uploads service", task_dag=[],
                                              trace_id="t-ti3", architect_compute_intent=record_of(raw or topo([UPLOADS])),
                                              allow_unauthenticated=True, enable_direct_iap=False,
                                              domain_restricted_sharing=False)
        finally:
            seen["lead_kwargs"] = dict(lead.return_value.decompose_specification.call_args.kwargs) \
                if lead.return_value.decompose_specification.call_args else {}
    return files, agent, client, seen


def test_end_to_end_intent_mode_renders_binds_vendors_and_validates():
    draft = dict(APP, **{C.INTENT_PATH: intent([BUCKET_MODULE])})
    att = {p: ("IAC_ENGINEER" if p == C.INTENT_PATH else "BACKEND_ENGINEER") for p in draft}
    files, agent, client, seen = _generate("generate", draft, att)
    assert agent.last_validation_report.status == "PASS"
    assert seen["iac_intent"] is not None and seen["lead_kwargs"].get("iac_intent_rule") == C.lead_intent_rule()
    assert "custom.tf" not in [p[len(W):] for p in files if p.startswith(W)]
    assert json.loads(files[C.RENDER_PATH])["module"]["uploads"]["source"] == "../modules/storage-bucket"
    assert any(p.startswith("infra/modules/storage-bucket/") for p in files)
    main = {b.key: b.body for b in index_blocks(files[W + "main.tf"])}
    env = main["module.compute"]["env_vars"]
    assert "module.uploads.bucket_name" in json.dumps(env)
    assert client.validated and C.RENDER_PATH in client.validated[-1]
    # the committed render is exactly render(intent): no healer touched it (zero-tolerance item of plan §6)
    res = II.validate_intent(files[C.INTENT_PATH], ART, C.intent_context(vt_of(topo([UPLOADS]))))
    assert res.ok and files[C.RENDER_PATH] == II.render_intent(res.validated).files[C.RENDER_PATH]


def test_end_to_end_platform_owned_type_is_a_typed_code_defect_routed_to_the_intent():
    bad = intent([BUCKET_MODULE], [{"type": "google_project_service", "name": "run",
                                    "arguments": {"service": "run.googleapis.com"}}])
    draft = dict(APP, **{C.INTENT_PATH: bad})
    att = {p: ("IAC_ENGINEER" if p == C.INTENT_PATH else "BACKEND_ENGINEER") for p in draft}
    with pytest.raises(RepairBudgetExhausted) as ei:
        _generate("generate", draft, att, repair_max_iterations_precommit=0)
    assert ei.value.error_class is ErrorClass.CODE_DEFECT
    codes = {(d.code, d.file) for d in ei.value.report.diagnostics if d.severity == "error"}
    assert ("IAC.TYPE_NOT_ALLOWED", C.INTENT_PATH) in codes


def test_end_to_end_mode_off_is_the_legacy_contract():
    """DNH: mode off passes no intent rule to the lead, no intent to the swarm, and an intent file in the draft is
    just a file (no gate, no render)."""
    draft = dict(APP, **{W + "custom.tf": 'resource "google_storage_bucket" "uploads" {\n  name = "${var.product_id}'
                                          '-u"\n  location = var.region\n  uniform_bucket_level_access = true\n}\n'})
    att = {p: ("IAC_ENGINEER" if p.endswith(".tf") else "BACKEND_ENGINEER") for p in draft}
    files, agent, _client, seen = _generate("off", draft, att)
    assert seen["iac_intent"] is None and "iac_intent_rule" not in seen["lead_kwargs"]
    assert C.RENDER_PATH not in files and "google_storage_bucket.uploads.name" in files[W + "main.tf"]


def test_smoke_strip_keeps_only_the_architect_stage_and_is_unchanged_without_the_flag():
    from eval.tools.strip_repair_calls import strip
    recs = [{"type": "meta", "spec_text": "x"},
            {"type": "call", "site": "architect_agent/handler.py:ArchitectAgent._single_turn_decompose"},
            {"type": "call", "site": "architect_agent/red_team_critic.py:RedTeamCritic._invoke_llm_critic"},
            {"type": "call", "site": "developer_agent/lead_orchestrator.py:LeadDeveloperOrchestrator."
                                     "decompose_specification"},
            {"type": "call", "site": "developer_agent/swarm_dispatcher.py:SwarmDispatcher._call_gemini_with_backoff"}]
    lines = [json.dumps(r) for r in recs]
    assert strip(lines, 99) == lines   # DNH: no flag, nothing dropped
    kept = [json.loads(x) for x in strip(lines, 99, architect_only=True)]
    assert [r.get("site", r["type"]) for r in kept] == ["meta", recs[1]["site"], recs[2]["site"]]


def test_smoke_scorer_counts_the_three_criteria(tmp_path):
    from eval.tools.ti3_smoke_score import score_dir

    def d(code, file):
        return {"code": code, "file": file, "severity": "error"}
    runs = {"01-r1": {"validation_report": {"status": "PASS", "diagnostics": []}},
            "02-r1": {"developer_failed_typed": {"diagnostics": [d("IAC.TYPE_NOT_ALLOWED", C.INTENT_PATH)]}},
            "03-r1": {"developer_failed_typed": {"diagnostics": [d("JSON.OUTPUT_INVALID", C.INTENT_PATH)]}},
            "04-r1": {"developer_failed_typed": {"diagnostics": [d("TF.UNSUPPORTED_ARGUMENT", C.RENDER_PATH),
                                                                 d("CONTAINER.PORT_NOT_BOUND", "apps/a/main.py")]}}}
    for k, hs in runs.items():
        (tmp_path / "runs" / k).mkdir(parents=True)
        (tmp_path / "runs" / k / "result.json").write_text(json.dumps({"valid_run": True, "hallucination_stack": hs}))
    (tmp_path / "manifest.json").write_text(json.dumps({"iac_intent_mode": "generate"}))
    s = score_dir(tmp_path)
    assert (s["valid"], s["intent_parsed"], s["gate_clean"], s["render_validates"]) == (4, 3, 2, 1)
    assert s["pass"]["render_validate_all_gate_clean"] is False and s["pass"]["run_in_generate_mode"] is True


TOPIC = {"type": "google_pubsub_topic", "name": "audit", "arguments": {"name": "audit"}}
API = {"type": "google_project_service", "name": "run", "arguments": {"service": "run.googleapis.com"}}


def test_repair_task_holds_only_the_intent_and_a_justified_entry_removal_is_accepted():
    draft = dict(APP, **{C.INTENT_PATH: intent([BUCKET_MODULE], [TOPIC, API])})
    att = {p: ("IAC_ENGINEER" if p == C.INTENT_PATH else "BACKEND_ENGINEER") for p in draft}
    fixed = {C.INTENT_PATH: intent([BUCKET_MODULE], [TOPIC])}
    files, agent, _c, seen = _generate("generate", draft, att, repairs=[fixed], repair_max_iterations_precommit=1)
    assert agent.last_validation_report.status == "PASS" and files[C.INTENT_PATH] == fixed[C.INTENT_PATH]
    (task,) = seen["repair_tasks"]
    assert task["persona"] == "IAC_ENGINEER" and task["iac_intent"] is not None
    assert task["system"].startswith("You are StackVend's Junior IaC Engineer. You do NOT write Terraform")
    files_to_fix = json.loads(task["prompt"].split("FILES TO FIX:\n\n", 1)[1].split("\n\n", 1)[0])
    assert sorted(files_to_fix) == [C.INTENT_PATH]
    diags = json.loads(task["prompt"].split("DIAGNOSTICS:\n\n", 1)[1].split("\n\nFILES TO FIX", 1)[0])
    assert [(x["code"], x["block"]) for x in diags] == [("IAC.TYPE_NOT_ALLOWED", "google_project_service.run")]


def test_repair_that_drops_an_undiagnosed_intent_entry_is_a_preservation_violation():
    draft = dict(APP, **{C.INTENT_PATH: intent([BUCKET_MODULE], [TOPIC, API])})
    att = {p: ("IAC_ENGINEER" if p == C.INTENT_PATH else "BACKEND_ENGINEER") for p in draft}
    lossy = {C.INTENT_PATH: intent([BUCKET_MODULE])}   # also deletes google_pubsub_topic.audit (no finding on it)
    agents = []
    with pytest.raises(RepairBudgetExhausted):
        _generate("generate", draft, att, repairs=[lossy], repair_max_iterations_precommit=1, agent_out=agents)
    ev = [e for e in agents[0].last_repair_events if e.kind != "junior_reask"]
    assert [(e.accepted, e.reject_reason) for e in ev] == [(False, "PRESERVATION_VIOLATION")]
