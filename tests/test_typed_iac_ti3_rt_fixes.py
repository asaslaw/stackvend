"""TI-3 Fable RT (docs/handoff/rt-ti3-fable.md, rt/ti3-fable @ 23d6b2a9) F1-F8: every RT probe
(docs/handoff/rt-ti3-evidence/rt_probes.py) as a real test, with the safe behaviour it stated. Hermetic; runs on the
tree merged with main (V2j, FD-4AW-a), so F1's end-to-end case is checked against the content-policy validator."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from test_typed_iac_ti3_contract import (API, APP, ART, BUCKET_MODULE, EVENTS, PID, TOPIC, UPLOADS, W, C, II,  # noqa: E402
                                         Client, _NoCallGenai, _agent, _assemble, _generate, _router, _runtime,
                                         intent, record_of, topo, vt_of)
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import ErrorClass, RepairBudgetExhausted  # noqa: E402

NET = dict(II.default_facts(), network="var.network_id", zone="var.zone")   # lane-11 facts, once provided (TI-5)
CLOUDSQL = {"type": "google_sql_database_instance", "logical_name": "db", "purpose": "app database",
            "consumers": [{"service": "shop", "env_key": "DB_CONNECTION", "attribute": None}]}


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


def _committed(vt, doc):
    """An intent workload's repository: the intent and the platform's render of it (what a commit holds)."""
    asm, _, rendered, _ = _assemble(vt, {C.INTENT_PATH: doc})
    assert asm.diagnostics == (), [d.code for d in asm.diagnostics]
    return {C.INTENT_PATH: doc, C.RENDER_PATH: rendered[C.RENDER_PATH]}


def _generate_existing(mode, draft, attribution, existing, repairs=(), **settings):
    from developer_agent import handler as h
    client = Client()
    agent = _agent(_runtime(client, iac_intent_mode=mode, **settings))
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
            seen["repair_tasks"].append({"persona": persona, "system": system_instruction, "prompt": prompt})
            return {"files": answers.pop(0), "envelope_ok": True, "finish_reason": "STOP", "tokens_in": 1,
                    "tokens_out": 1, "tokens_thoughts": 0, "model": model, "persona": persona}

    seen["agent"] = agent
    with patch.object(h, "LeadDeveloperOrchestrator") as lead, patch.object(h, "SwarmDispatcher", FakeDispatcher), \
            patch.object(agent, "fetch_existing_repo_files", return_value=dict(existing)), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
        lead.return_value.decompose_specification.return_value = plan
        files = agent.generate_code_files(product_id=PID, spec_text="uploads service", task_dag=[],
                                          trace_id="t-rt", architect_compute_intent=record_of(topo([UPLOADS])),
                                          allow_unauthenticated=True, enable_direct_iap=False,
                                          domain_restricted_sharing=False)
    return files, agent, seen


# ------------------------------------------------------------------------------------------------ F1
def test_f1_sticky_render_is_platform_rendered_for_the_router():
    vt = vt_of(topo([UPLOADS]))
    asm, _, files, _ = _assemble(vt, {C.INTENT_PATH: intent([BUCKET_MODULE])})
    r = _router(dict(APP, **files), dict(APP), asm, preexisting=(C.INTENT_PATH, C.RENDER_PATH))
    assert C.RENDER_PATH in r.rendered and r.ownership(C.RENDER_PATH) is Ownership.PLATFORM_RENDERED


def test_f1_drafted_render_path_is_platform_rendered_and_the_ai_copy_goes_back_to_its_author():
    vt = vt_of(topo([UPLOADS]))
    draft = dict(APP, **{C.INTENT_PATH: intent([BUCKET_MODULE]), C.RENDER_PATH: '{"resource": {}}'})
    asm, _, files, _ = _assemble(vt, draft)
    r = _router(dict(APP, **files), draft, asm, attribution={C.INTENT_PATH: "IAC_ENGINEER",
                                                              C.RENDER_PATH: "IAC_ENGINEER"})
    assert C.RENDER_PATH in r.rendered and C.RENDER_PATH not in r.authored
    assert r.ownership(C.RENDER_PATH) is Ownership.PLATFORM_RENDERED
    from developer_agent.validators.iac_intent import IacHclPathValidator
    from developer_agent.validators.base import ValidationContext
    (d,) = IacHclPathValidator().validate(ValidationContext.build(files, ownership=lambda p: None, draft=draft))
    got = r.route(d)   # the AI's own draft at the render path is emptied by its author, never PLATFORM_DEFECT
    assert (got.error_class, got.persona, got.draft_path) == (ErrorClass.CODE_DEFECT, "IAC_ENGINEER", C.RENDER_PATH)


def test_f1_rendered_set_is_unchanged_without_an_intent_assembly():
    """DNH: mode off (no IntentAssembly) keeps today's rendered/authored sets."""
    tree = dict(APP, **{C.RENDER_PATH: "{}"})
    r = _router(tree, {C.RENDER_PATH: "{}"}, None, preexisting=())
    assert C.RENDER_PATH in r.authored and C.RENDER_PATH not in r.rendered


def test_f1_sticky_feature_request_with_committed_render_passes_v2j():
    existing = _committed(vt_of(topo([UPLOADS])), intent([BUCKET_MODULE]))
    files, agent, seen = _generate_existing("off", dict(APP), {p: "BACKEND_ENGINEER" for p in APP}, existing)
    assert seen["iac_intent"] is not None
    assert agent.last_validation_report.status == "PASS", [
        (d.code, d.file, d.error_class) for d in agent.last_validation_report.diagnostics]
    assert files[C.RENDER_PATH] == existing[C.RENDER_PATH]


# ------------------------------------------------------------------------------------------------ F2
def test_f2_legacy_workload_hcl_keeps_the_legacy_path_under_generate():
    vt = vt_of(topo([UPLOADS]))
    assert C.iac_intent_mode_decision("generate", {W + "custom.tf": "x"}, vt) == ("off", C.LEGACY_WORKLOAD_STAYS_HCL)
    # platform renders, human files and override files are not legacy workload HCL (exact artifact_ownership rules)
    plat = {W + "main.tf": "", W + "variables.tf": "", W + "outputs.tf": "", W + "moved.tf": "", W + "services.tf": "",
            W + "human.tf": "", W + "human_override.tf": "", W + "x_override.tf": "", "apps/shop/main.py": ""}
    assert C.legacy_workload_hcl(plat) == []
    assert C.resolve_iac_intent_mode("generate", plat, vt) == "generate"
    assert C.legacy_workload_hcl(dict(plat, **{W + "iam.tf": ""})) == [W + "iam.tf"]


def test_f2_legacy_workload_is_not_moved_onto_the_intent_path_by_the_setting():
    legacy = ('resource "google_storage_bucket" "uploads" {\n  name = "${var.product_id}-u"\n  location = var.region\n'
              '  uniform_bucket_level_access = true\n}\n')
    draft = dict(APP, **{C.INTENT_PATH: intent([BUCKET_MODULE])})
    att = {p: ("IAC_ENGINEER" if p == C.INTENT_PATH else "BACKEND_ENGINEER") for p in draft}
    files, agent, seen = _generate_existing("generate", draft, att, {W + "custom.tf": legacy})
    assert seen["iac_intent"] is None and C.RENDER_PATH not in files   # one declaration only: the legacy one
    assert "google_storage_bucket" in files[W + "custom.tf"]


# ------------------------------------------------------------------------------------------------ F3
def test_f3_cloudsql_public_ip_is_not_ai_settable():
    def gate(args):
        return II.validate_intent(intent(modules=[{"module": "database-cloudsql", "name": "db", "args": args}]), ART,
                                  II.IntentContext(facts=NET))
    assert "IAC.INVALID_VALUE" in gate({"enable_public_ip": True}).codes
    assert "IAC.INVALID_VALUE" in gate({"enable_public_ip": 0}).codes          # type-exact: 0 is not false
    assert "IAC.LITERAL_REQUIRED" in gate({"enable_public_ip": {"$fn": "tostring", "$args": [True]}}).codes
    assert gate({"enable_public_ip": False}).ok and gate({}).ok


def test_f3_network_bound_module_is_a_removable_typed_error_without_the_fact():
    for mid, args in (("database-cloudsql", {}), ("cache-redis", {}), ("database-alloydb", {}),
                      ("ai-vertex-endpoint", {}), ("database-bigtable", {})):
        res = II.validate_intent(intent(modules=[{"module": mid, "name": "m", "args": args}]), ART, II.IntentContext())
        assert "IAC.MODULE_FACT_UNAVAILABLE" in res.codes, (mid, res.codes)
        assert not res.ok
    assert "IAC.MODULE_FACT_UNAVAILABLE" in C.INTENT_REMOVAL_CODES
    # with the facts (lane 11, TI-5) the Cloud SQL render carries the private network (the module precondition)
    res = II.validate_intent(intent(modules=[{"module": "database-cloudsql", "name": "db", "args": {}}]), ART,
                             II.IntentContext(facts=NET))
    assert res.ok, res.codes
    body = json.loads(II.render_intent(res.validated).files[C.RENDER_PATH])["module"]["db"]
    assert body["private_network_id"] == "${var.network_id}" and "enable_public_ip" not in body
    # a module without such a fact is unaffected
    assert II.validate_intent(intent([BUCKET_MODULE]), ART, II.IntentContext(
        topology_resources={"uploads": "google_storage_bucket"})).ok


def test_f3_network_bound_types_are_derived_and_ti5_supplies_their_facts():
    bound = C.network_bound_types(ART)                 # the static facts only (no lane-11 facts)
    assert {"google_sql_database_instance", "google_redis_instance"} <= bound
    assert not bound & set(ART.allowed_types)          # derived from the catalog: never an allow-listed type
    assert C.network_bound_slots(vt_of(topo([CLOUDSQL, UPLOADS])), ART) == ["db"]
    assert C.network_bound_slots(vt_of(topo([UPLOADS])), ART) == []
    # TI-5c (owner 10-21, replaces TI-3f): the platform supplies the network / zone facts on the intent path, so no
    # topology is sent back to the legacy path for them (tests/test_typed_iac_ti5c_network_facts.py)
    assert C.network_bound_slots(vt_of(topo([CLOUDSQL, UPLOADS])), ART, facts=C.intent_path_facts()) == []
    from developer_agent.compute_intent import ComputeIntent
    agent = _agent(_runtime(None, iac_intent_mode="generate"))
    ci = MagicMock(spec=ComputeIntent)
    ci.topology = vt_of(topo([CLOUDSQL]))
    ready = {"provider_versions": Client().ready()["provider_versions"]}
    assert agent._resolve_intent_run(ci, {}, ready) is not None
    ci.topology = vt_of(topo([UPLOADS]))
    assert agent._resolve_intent_run(ci, {}, ready) is not None


# ------------------------------------------------------------------------------------------------ F4
def test_f4_render_backstop_has_no_false_positive_on_a_data_key_and_still_catches_body_meta_keys():
    from developer_agent.validators.base import ValidationContext
    from developer_agent.validators.iac_intent import GATE_GAP_CODE, RenderedIntentPolicyValidator
    doc = intent(resources=[{"type": "google_pubsub_topic", "name": "audit",
                             "arguments": {"name": "audit", "labels": {"provider": "stripe", "count": "one"}}}])
    asm, _, files, _ = _assemble(vt_of(topo()), {C.INTENT_PATH: doc})
    assert asm.diagnostics == () and C.RENDER_PATH in files
    ctx = lambda f: ValidationContext.build(f, ownership=lambda p: None, extras={"iac_intent": asm})  # noqa: E731
    assert RenderedIntentPolicyValidator().validate(ctx(files)) == []
    tampered = json.loads(files[C.RENDER_PATH])
    tampered["resource"]["google_pubsub_topic"]["audit"]["provisioner"] = [{"local-exec": {"command": "x"}}]
    tampered["resource"]["google_pubsub_topic"]["audit"]["labels"]["//"] = "x"
    out = RenderedIntentPolicyValidator().validate(ctx(dict(files, **{C.RENDER_PATH: json.dumps(tampered)})))
    assert {d.code for d in out} == {GATE_GAP_CODE} and len(out) == 2


# ------------------------------------------------------------------------------------------------ F5
def test_f5_sticky_intent_entries_are_preserved_across_a_repair():
    existing = _committed(vt_of(topo([UPLOADS])), intent([BUCKET_MODULE], [TOPIC]))
    existing[C.INTENT_PATH] = intent([BUCKET_MODULE], [TOPIC, API])   # the next dispatch finds a finding on API
    lossy = {C.INTENT_PATH: intent([BUCKET_MODULE])}                  # also deletes the undiagnosed topic
    with pytest.raises(RepairBudgetExhausted):
        _generate_existing("off", dict(APP), {p: "BACKEND_ENGINEER" for p in APP}, existing, repairs=[lossy],
                           repair_max_iterations_precommit=1)


def test_f5_sticky_justified_removal_is_accepted():
    existing = _committed(vt_of(topo([UPLOADS])), intent([BUCKET_MODULE], [TOPIC]))
    existing[C.INTENT_PATH] = intent([BUCKET_MODULE], [TOPIC, API])
    fixed = {C.INTENT_PATH: intent([BUCKET_MODULE], [TOPIC])}
    files, agent, seen = _generate_existing("off", dict(APP), {p: "BACKEND_ENGINEER" for p in APP}, existing,
                                            repairs=[fixed], repair_max_iterations_precommit=1)
    assert agent.last_validation_report.status == "PASS" and "google_pubsub_topic" in files[C.INTENT_PATH]
    assert seen["repair_tasks"][0]["persona"] == "IAC_ENGINEER"


# ------------------------------------------------------------------------------------------------ F6
def test_f6_export_missing_repair_by_swapping_module_for_resource_is_accepted():
    key_res = dict(EVENTS, type="google_secret_manager_secret", logical_name="key",
                   consumers=[{"service": "shop", "env_key": "KEY_ID", "attribute": "id"}])
    sec_mod = {"module": "security-secret", "name": "key", "realizes": "key", "args": {"secret_id": "key"}}
    draft = dict(APP, **{C.INTENT_PATH: intent([sec_mod])})
    att = {p: ("IAC_ENGINEER" if p == C.INTENT_PATH else "BACKEND_ENGINEER") for p in draft}
    fixed = {C.INTENT_PATH: intent(resources=[{"type": "google_secret_manager_secret", "name": "key",
                                               "realizes": "key",
                                               "arguments": {"secret_id": "key", "replication": {"auto": {}}}}])}
    files, agent, _c, _seen = _generate("generate", draft, att, raw=topo([key_res]), repairs=[fixed],
                                        repair_max_iterations_precommit=1)
    ev = [(e.accepted, e.reject_reason) for e in agent.last_repair_events if e.kind != "junior_reask"]
    assert ev == [(True, None)] and agent.last_validation_report.status == "PASS"
    assert {"IAC.REALIZATION_EXPORT_MISSING", "IAC.REALIZATION_TYPE_MISMATCH"} <= C.INTENT_REMOVAL_CODES


# ------------------------------------------------------------------------------------------------ F7
def test_f7_a_lone_intent_file_does_not_force_the_intent_path():
    draft = dict(APP)
    files, agent, seen = _generate_existing("off", draft, {p: "BACKEND_ENGINEER" for p in APP},
                                            {C.INTENT_PATH: intent([BUCKET_MODULE])})
    assert seen["iac_intent"] is None and C.RENDER_PATH not in files


# ------------------------------------------------------------------------------------------------ F8
def test_f8_iac_repair_prompt_allows_returning_the_ai_terraform_file_empty():
    run = C.build_intent_run(vt_of(topo([UPLOADS])), {}, artifacts=ART)
    with_tf = C.repair_system_instruction(run, "IAC_ENGINEER", "base", [C.INTENT_PATH, W + "custom.tf"])
    without = C.repair_system_instruction(run, "IAC_ENGINEER", "base", [C.INTENT_PATH])
    assert with_tf == without + "\n" + C.REPAIR_EMPTY_TF_NOTE and C.REPAIR_EMPTY_TF_NOTE not in without
    # end to end: the IaC persona's task holds the intent and its custom.tf; returning custom.tf empty is accepted
    tf = ('resource "google_storage_bucket" "extra" {\n  name = "x"\n  location = var.region\n'
          '  uniform_bucket_level_access = true\n}\n')
    draft = dict(APP, **{C.INTENT_PATH: intent([BUCKET_MODULE]), W + "custom.tf": tf})
    att = {p: ("IAC_ENGINEER" if p.startswith("infra/") else "BACKEND_ENGINEER") for p in draft}
    files, agent, _c, seen = _generate("generate", draft, att, repairs=[{W + "custom.tf": ""}],
                                       repair_max_iterations_precommit=1)
    (task,) = seen["repair_tasks"]
    assert task["system"].endswith(C.REPAIR_EMPTY_TF_NOTE)
    assert agent.last_validation_report.status == "PASS" and "google_storage_bucket" not in files.get(W + "custom.tf",
                                                                                                    "")


# ------------------------------------------------------------------------------------------------ merge gate (10-20)
def test_gate_reserves_the_platform_moved_from_addresses():
    """Merge-gate finding: 10/22 intent runs declared google_project_iam_member.workload_datastore_user, the `from`
    of the platform's moved.tf (module.foundation already grants it): validate passed, an offline `tofu plan` failed
    with "Moved object still exists". The gate now reserves every moved.tf `from` address (exact HCL parse)."""
    from developer_agent.terraform_engine import generate_golden_moved_tf
    vt = vt_of(topo([UPLOADS]))
    reserved = C.platform_moved_from(vt)
    assert reserved == C.moved_from_addresses(generate_golden_moved_tf(vt.product_id, vt.archetype))
    assert {"google_project_iam_member.workload_datastore_user", "google_project_iam_member.workload_log_writer",
            "google_service_account.workload_sa"} <= reserved
    run = C.build_intent_run(vt, {}, artifacts=ART)
    assert run.reserved_addresses == reserved and "google_project_iam_member.workload_datastore_user" in run.run_context
    grant = {"type": "google_project_iam_member", "name": "workload_datastore_user", "arguments": {
        "project": {"$ref": {"kind": "fact", "fact": "project_id"}}, "role": "roles/datastore.user",
        "member": {"$member": {"service_account": {"$ref": {"kind": "fact", "fact": "workload_sa_email"}}}}}}
    asm, _, files, _ = _assemble(vt, {C.INTENT_PATH: intent([BUCKET_MODULE], [grant])})
    d = [x for x in asm.diagnostics if x.code == "IAC.DUPLICATE_ADDRESS"]
    assert d and d[0].block_address == "google_project_iam_member.workload_datastore_user"
    assert C.RENDER_PATH not in files and "IAC.DUPLICATE_ADDRESS" in C.INTENT_REMOVAL_CODES   # removable
    other = dict(grant, name="app_datastore_reader")      # another name: not reserved (DNH)
    other["arguments"] = dict(grant["arguments"], role="roles/datastore.viewer")
    asm, _, files, _ = _assemble(vt, {C.INTENT_PATH: intent([BUCKET_MODULE], [other])})
    assert asm.diagnostics == () and C.RENDER_PATH in files
    # the IaC prompt's own example no longer uses a reserved name
    from developer_agent.juniors.iac_worker import build_iac_intent_worker_prompt
    ex = json.loads(build_iac_intent_worker_prompt(ART).split("EXAMPLE", 1)[1].split("\n", 1)[1])
    names = {f"{r['type']}.{r['name']}" for r in ex["files"][C.INTENT_PATH]["resources"]}
    assert not names & reserved
    assert II.IntentContext().reserved_addresses == frozenset()   # default: nothing reserved (gate unit tests)


# ------------------------------------------------------------------------------------------------ smoke cost (10-20)
def _junior_configs(iac_intent):
    """The GenerateContentConfig each junior call sends (fake client; no network): IaC persona, then a database one."""
    import asyncio
    from developer_agent.swarm_dispatcher import SwarmDispatcher
    from developer_agent.swarm_schemas import (JuniorPersona, JuniorTaskAssignment, LeadDeveloperDecompositionPlan,
                                               SwarmExecutionMode)
    seen = []

    class Models:
        def generate_content(self, model, contents, config):
            seen.append(config)
            r = MagicMock()
            r.text = json.dumps({"files": {C.INTENT_PATH: intent(), "apps/shop/db.py": "x = 1\n"}})
            r.candidates = []
            r.usage_metadata = None
            return r
    client = MagicMock()
    client.models = Models()
    d = SwarmDispatcher(genai_client=client, model_name="gemini-3.8-flash")
    d.iac_intent = iac_intent
    for persona, f in ((JuniorPersona.IAC_ENGINEER, C.INTENT_PATH),
                       (JuniorPersona.DATABASE_ENGINEER, "apps/shop/db.py")):
        task = JuniorTaskAssignment(task_id=persona.value, persona=persona, wave=1, assigned_files=[f],
                                    task_objective="x")
        plan = LeadDeveloperDecompositionPlan(execution_mode=SwarmExecutionMode.STANDARD_SWARM, tasks=[task])
        with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=["gemini-3.8-flash"]):
            asyncio.run(d.invoke_junior_worker(task, plan, {}, "gemini-3.8-flash"))
    return seen


def test_cost_iac_intent_call_has_a_thinking_budget_and_output_bound_other_juniors_unchanged():
    from shared.hallucination_stack import HallucinationStackSettings
    run = C.build_intent_run(vt_of(topo([UPLOADS])), {}, artifacts=ART)
    iac, db = _junior_configs(run)
    assert iac.thinking_config is not None and iac.thinking_config.thinking_budget == 4096
    assert iac.max_output_tokens == 16_384
    assert db.thinking_config is None and db.max_output_tokens == 65_536   # not the IaC persona: unchanged
    off_iac, off_db = _junior_configs(None)                                   # mode off: unchanged
    assert off_iac.thinking_config is None and off_iac.max_output_tokens == 65_536
    s = HallucinationStackSettings()
    assert (s.iac_intent_thinking_budget, s.iac_intent_max_output_tokens) == (4096, 16_384)
    with pytest.raises(Exception):
        HallucinationStackSettings(iac_intent_thinking_budget=16_000, iac_intent_max_output_tokens=16_384)


def test_cost_service_url_prompt_names_the_format_form_the_gate_accepts():
    from developer_agent.juniors.iac_worker import build_iac_intent_worker_prompt
    p = build_iac_intent_worker_prompt(ART)
    assert 'push_config.push_endpoint = a service Ref (output service_uri), or with a path {"$fn": "format"' in p
    svc = {"$ref": {"kind": "service", "service": "shop", "output": "service_uri"}}
    ctx = C.intent_context(vt_of(topo()))

    def sub(ep):
        return intent(modules=[{"module": "messaging-pubsub", "name": "t", "args": {}}], resources=[
            {"type": "google_pubsub_subscription", "name": "s", "arguments": {
                "name": "s", "topic": {"$ref": {"kind": "module_output", "module": "t", "output": "topic_name"}},
                "push_config": {"push_endpoint": ep}}}])
    assert II.validate_intent(sub({"$fn": "format", "$args": ["%s/api/v1/tasks", svc]}), ART, ctx).ok
    assert "IAC.SERVICE_REF_REQUIRED" in II.validate_intent(sub({"$fn": "concat", "$args": [svc, "/x"]}), ART,
                                                            ctx).codes   # the smoke-01 answer


def test_cost_a_429_rejection_is_not_booked_at_the_ceiling():
    sys.path.insert(0, os.path.join(os.path.dirname(TESTS), "eval"))
    from stackvend_eval.budget import Budget, Price, PriceTable
    from stackvend_eval.llm_proxy import LLMProxy
    from stackvend_eval.state import RunState
    prices = PriceTable({"m": Price("m", 1.0, 10.0, 0.5, 5.0, True, 65536)})

    class Rejected(Exception):
        def __init__(self, code):
            super().__init__(f"{code} RESOURCE_EXHAUSTED")
            self.code = code

    def backend(*, model, contents, config):
        raise Rejected(429 if contents == "quota" else 503)
    st = RunState()
    b = Budget(5.0, 10 ** 9, prices, state=st)
    p = LLMProxy(mode="live", budget=b, state=st, gateway_dir=TESTS, example="01", run=1, backend=backend)
    for contents in ("quota", "busy"):
        with pytest.raises(Rejected):
            p.models.generate_content(model="m", contents=contents, config={"max_output_tokens": 65536})
    snap = b.snapshot()
    assert snap["outstanding_usd"] == 0
    rejected = [c for c in p.calls if c.get("settle_basis") == "provider_rejected_429"]
    charged = [c for c in p.calls if c.get("settle_basis") == "full_reservation"]
    assert len(rejected) == 1 and rejected[0]["usd"] == 0.0           # quota rejection: never billed
    assert len(charged) == 1 and charged[0]["usd"] > 0.5               # any other usage-less failure: full charge
    assert snap["settled_usd"] == pytest.approx(charged[0]["usd"])
    with pytest.raises(ValueError):
        b.settle_rejected(b.reserve("m", 10, 10), 503)
