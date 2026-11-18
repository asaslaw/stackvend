"""TI-3i (register, owner 10-21): a typed-intent entry a repair removed as IAC.TYPE_NOT_ALLOWED / IAC.MODULE_UNKNOWN is
a visible workload warning; when the architect's TYPED plan names that service (topology resource / its type, or an
exact API of the model-written build plan's required_cloud_apis) and the shipped build no longer provides it, the
developer stage stops with IAC.REQUESTED_SERVICE_DROPPED instead of shipping without it. Never spec prose
(invariant 2). Negatives: no plan naming -> warning only; platform-owned / forbidden types -> warning only; a
replacement that provides the service -> warning only; the keyword-fallback build plan never feeds the decision."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

import test_typed_iac_ti3_contract as T3  # noqa: E402
from developer_agent import iac_intent_contract as C  # noqa: E402
from shared import iac_intent as ii  # noqa: E402
from shared.diagnostics import ErrorClass, StageError  # noqa: E402

ART = ii.load_artifacts()
W = "infra/workload/"
DOCS = {"type": "google_discovery_engine_data_store", "name": "docs", "arguments": {"data_store_id": "docs"}}
VERTEX = {"type": "google_vertex_ai_endpoint", "name": "ep", "arguments": {"name": "ep"}}
REDIS_RAW = {"type": "google_redis_instance", "name": "cache", "realizes": "cache", "arguments": {"name": "c"}}
NET = {"type": "google_compute_network", "name": "vpc", "arguments": {"name": "vpc"}}
BUDGET = {"type": "google_billing_budget", "name": "b", "arguments": {}}
TOPIC = {"type": "google_pubsub_topic", "name": "audit", "arguments": {"name": "audit"}}


def intent(modules=(), resources=(), api_only=()):
    d = {"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources)}
    if api_only:
        d["api_only"] = [{"service": s} for s in api_only]
    return json.dumps(d, indent=2)


def drops(before, *addresses, code="REMOVAL_CODE:IAC.TYPE_NOT_ALLOWED"):
    return C.dropped_intent_entries(before, {a: code for a in addresses})


def outcome(dropped, final_intent, topology=None, plan_apis=()):
    tree = {C.INTENT_PATH: final_intent, W + "main.tf": "", W + "custom.tf.json": "{}"}
    if final_intent:
        r = ii.validate_intent(final_intent, ART, ii.IntentContext())
        if r.ok:
            tree.update(ii.render_intent(r.validated).files)
    return C.dropped_entry_outcome(dropped, tree, topology, plan_apis, ART)


# ------------------------------------------------------------------------------------------------ identities
def test_dropped_entries_are_read_exactly_from_the_document_they_were_removed_from():
    before = intent([{"module": "vertex-search", "name": "search", "realizes": "kb", "args": {}}], [DOCS, TOPIC])
    got = C.dropped_intent_entries(before, {
        "google_discovery_engine_data_store.docs": "REMOVAL_CODE:IAC.TYPE_NOT_ALLOWED",
        "module.search": "REMOVAL_CODE:IAC.MODULE_UNKNOWN",
        "google_pubsub_topic.audit": "REMOVAL_CODE:IAC.DUPLICATE_ADDRESS",   # other removal reasons: not TI-3i
    })
    assert got == (
        {"address": "google_discovery_engine_data_store.docs", "removed_as": "IAC.TYPE_NOT_ALLOWED",
         "kind": "resource", "type": "google_discovery_engine_data_store", "module": None, "realizes": None,
         "service": None},
        {"address": "module.search", "removed_as": "IAC.MODULE_UNKNOWN", "kind": "module", "type": None,
         "module": "vertex-search", "realizes": "kb", "service": None})
    assert C.dropped_intent_entries(before, {"google_pubsub_topic.audit": "REPLACED:x"}) == ()
    # identity fields keep their closed grammar (they are shown in the Control Center)
    odd = json.dumps({"modules": [{"name": "m", "module": "<script>", "realizes": "A B"}]})
    (e,) = C.dropped_intent_entries(odd, {"module.m": "REMOVAL_CODE:IAC.MODULE_UNKNOWN"})
    assert (e["module"], e["realizes"]) == (None, None)
    (e,) = C.dropped_intent_entries("not json", {"x.y": "REMOVAL_CODE:IAC.TYPE_NOT_ALLOWED"})
    assert e["kind"] is None and e["removed_as"] == "IAC.TYPE_NOT_ALLOWED"


def test_plan_required_apis_reads_only_exact_api_ids():
    rec = {"required_cloud_apis": ["discoveryengine.googleapis.com", "Discovery Engine", "x.googleapis.com.evil",
                                   7, "aiplatform.googleapis.com", "aiplatform.googleapis.com"]}
    assert C.plan_required_apis(rec) == ("aiplatform.googleapis.com", "discoveryengine.googleapis.com")
    assert C.plan_required_apis({}) == () and C.plan_required_apis(None) == ()
    assert C.plan_required_apis({"required_cloud_apis": "aiplatform.googleapis.com"}) == ()


# ------------------------------------------------------------------------------------------------ outcome
def test_a_dropped_entry_the_plan_does_not_name_is_a_warning_only():
    w, stops = outcome(drops(intent(resources=[DOCS]), "google_discovery_engine_data_store.docs"), intent())
    assert stops == [] and len(w) == 1
    assert w[0]["code"] == C.ENTRY_DROPPED_WARNING and w[0]["stops_build"] is False and w[0]["plan_named"] == []
    assert "google_discovery_engine_data_store.docs" in w[0]["message"]


def test_a_plan_named_api_nothing_ships_stops_the_build_typed():
    w, stops = outcome(drops(intent(resources=[DOCS]), "google_discovery_engine_data_store.docs"), intent(),
                       plan_apis=("discoveryengine.googleapis.com", "run.googleapis.com"))
    (d,) = stops
    assert d.code == C.REQUESTED_SERVICE_DROPPED and d.error_class is ErrorClass.PLATFORM_DEFECT
    assert d.block_address == "google_discovery_engine_data_store.docs" and d.file == C.INTENT_PATH
    assert "discoveryengine.googleapis.com" in d.message and w[0]["stops_build"] is True
    assert w[0]["missing"] == ["API discoveryengine.googleapis.com"]


def test_a_shipped_api_only_entry_or_module_providing_the_plan_api_means_no_stop():
    dropped = drops(intent(resources=[VERTEX]), "google_vertex_ai_endpoint.ep")
    w, stops = outcome(dropped, intent(api_only=["aiplatform.googleapis.com"]),
                       plan_apis=("aiplatform.googleapis.com",))
    assert stops == [] and w[0]["plan_named"] == ["plan API aiplatform.googleapis.com"] and w[0]["missing"] == []
    w, stops = outcome(dropped, intent(), plan_apis=("aiplatform.googleapis.com",))
    assert [d.code for d in stops] == [C.REQUESTED_SERVICE_DROPPED]   # negative: nothing provides it


def test_foundation_apis_in_the_plan_never_count():
    pubsub_raw = {"type": "google_pubsub_lite_topic", "name": "lite", "arguments": {}}
    w, stops = outcome(drops(intent(resources=[pubsub_raw]), "google_pubsub_lite_topic.lite"), intent(),
                       plan_apis=("pubsub.googleapis.com", "run.googleapis.com", "firestore.googleapis.com"))
    assert stops == [] and w[0]["plan_named"] == []


@pytest.mark.parametrize("entry,owner", [(NET, "lane11_owned"), (BUDGET, "forbidden")])
def test_platform_owned_or_forbidden_types_are_warnings_never_stops(entry, owner):
    addr = f"{entry['type']}.{entry['name']}"
    w, stops = outcome(drops(intent(resources=[entry]), addr), intent(),
                       plan_apis=("compute.googleapis.com", "billingbudgets.googleapis.com"))
    assert stops == [] and w[0]["owner"] == owner and w[0]["stops_build"] is False


def _topology(resources):
    return T3.vt_of(T3.topo(resources))


REDIS = {"type": "google_redis_instance", "logical_name": "cache", "purpose": "cache",
         "consumers": [{"service": "shop", "env_key": "REDIS_HOST", "attribute": None}]}


def test_topology_named_entry_replaced_by_a_realizing_module_is_a_warning_only():
    vt = _topology([REDIS])
    dropped = drops(intent(resources=[REDIS_RAW]), "google_redis_instance.cache")
    final = intent([{"module": "cache-redis", "name": "cache", "realizes": "cache", "args": {}}])
    tree = {C.INTENT_PATH: final}
    w, stops = C.dropped_entry_outcome(dropped, tree, vt, (), ART)
    assert stops == [] and set(w[0]["plan_named"]) == {"topology resource cache",
                                                       "topology resource type google_redis_instance"}
    # negative: nothing realizes the topology resource any more -> typed stop
    w, stops = C.dropped_entry_outcome(dropped, {C.INTENT_PATH: intent()}, vt, (), ART)
    assert [d.code for d in stops] == [C.REQUESTED_SERVICE_DROPPED] and stops[0].symbol == "cache"


def test_unknown_module_is_judged_only_by_typed_plan_links():
    vt = _topology([REDIS])
    before = intent([{"module": "memorystore", "name": "m", "realizes": "cache", "args": {}},
                     {"module": "vertex-search", "name": "s", "args": {}}])
    dropped = C.dropped_intent_entries(before, {"module.m": "REMOVAL_CODE:IAC.MODULE_UNKNOWN",
                                                "module.s": "REMOVAL_CODE:IAC.MODULE_UNKNOWN"})
    w, stops = C.dropped_entry_outcome(dropped, {C.INTENT_PATH: intent()}, vt,
                                       ("discoveryengine.googleapis.com",), ART)
    assert [d.block_address for d in stops] == ["module.m"]   # realized a topology resource; s: no exact link
    assert {x["address"]: x["stops_build"] for x in w} == {"module.m": True, "module.s": False}
    # a platform module id (compute) is platform-owned: warning only
    dropped = C.dropped_intent_entries(intent([{"module": "compute-cloudrun", "name": "c", "realizes": "cache",
                                                "args": {}}]), {"module.c": "REMOVAL_CODE:IAC.MODULE_UNKNOWN"})
    w, stops = C.dropped_entry_outcome(dropped, {C.INTENT_PATH: intent()}, vt, (), ART)
    assert stops == [] and w[0]["owner"] == "platform_module"


def _api_svc(service):
    return {"type": "google_project_service", "name": "ai", "arguments": {"service": service}}


def test_a_dropped_project_service_whose_plan_named_api_nothing_ships_stops_typed():
    """Fable F1: google_project_service is platform-owned, but its exact `service` is the API the plan may name; the
    owner class does not veto the stop for that exact type."""
    d = drops(intent(resources=[_api_svc("aiplatform.googleapis.com")]), "google_project_service.ai")
    assert d[0]["service"] == "aiplatform.googleapis.com"
    w, stops = outcome(d, intent(), plan_apis=("aiplatform.googleapis.com",))
    assert [s.code for s in stops] == [C.REQUESTED_SERVICE_DROPPED] and stops[0].error_class is ErrorClass.PLATFORM_DEFECT
    assert w[0]["owner"] == "platform_owned" and w[0]["service"] == "aiplatform.googleapis.com"
    assert w[0]["missing"] == ["API aiplatform.googleapis.com"] and w[0]["stops_build"] is True


def test_a_dropped_project_service_replaced_by_an_api_only_entry_is_a_warning_only():
    d = drops(intent(resources=[_api_svc("aiplatform.googleapis.com")]), "google_project_service.ai")
    w, stops = outcome(d, intent(api_only=["aiplatform.googleapis.com"]), plan_apis=("aiplatform.googleapis.com",))
    assert stops == [] and w[0]["missing"] == [] and w[0]["plan_named"] == ["plan API aiplatform.googleapis.com"]


@pytest.mark.parametrize("service", ["${var.api}", "aiplatform", "Aiplatform.googleapis.com", None, 7])
def test_a_dropped_project_service_with_an_off_grammar_service_is_a_warning_only(service):
    d = drops(intent(resources=[_api_svc(service)]), "google_project_service.ai")
    assert d[0]["service"] is None
    w, stops = outcome(d, intent(), plan_apis=("aiplatform.googleapis.com",))
    assert stops == [] and w[0]["owner"] == "platform_owned" and w[0]["stops_build"] is False


def test_a_dropped_project_service_for_a_foundation_api_never_stops():
    d = drops(intent(resources=[_api_svc("run.googleapis.com")]), "google_project_service.ai")
    w, stops = outcome(d, intent(), plan_apis=("run.googleapis.com",))
    assert stops == [] and w[0]["plan_named"] == []


# ------------------------------------------------------------------------------------------------ TI-3i-b
OFF_TABLE = "discoveryengine.googleapis.com"   # an API off the API-only table


def test_ti3i_b_an_api_only_entry_removed_as_not_allowed_is_read_exactly():
    """TI-3i-b (owner 10-25): an api_only entry a repair removed as IAC.API_NOT_ALLOWED is a dropped entry, read from
    the exact document; other removal reasons on an api_only entry (e.g. a duplicate) are not TI-3i drops."""
    before = intent(api_only=[OFF_TABLE, "aiplatform.googleapis.com"])
    got = C.dropped_intent_entries(before, {"api_only." + OFF_TABLE: "REMOVAL_CODE:IAC.API_NOT_ALLOWED",
                                            "api_only.aiplatform.googleapis.com": "REMOVAL_CODE:IAC.DUPLICATE_ADDRESS"})
    assert got == ({"address": "api_only." + OFF_TABLE, "removed_as": "IAC.API_NOT_ALLOWED", "kind": "api_only",
                    "type": None, "module": None, "realizes": None, "service": OFF_TABLE},)
    odd = json.dumps({"api_only": [{"service": "Vision API"}]})   # off-grammar service: kept as None (CC display)
    (e,) = C.dropped_intent_entries(odd, {"api_only.Vision API": "REMOVAL_CODE:IAC.API_NOT_ALLOWED"})
    assert e["kind"] == "api_only" and e["service"] is None


def test_ti3i_b_a_dropped_api_only_entry_is_a_workload_warning():
    d = drops(intent(api_only=[OFF_TABLE]), "api_only." + OFF_TABLE, code="REMOVAL_CODE:IAC.API_NOT_ALLOWED")
    w, stops = outcome(d, intent())
    assert stops == [] and len(w) == 1
    assert (w[0]["code"], w[0]["removed_as"], w[0]["kind"], w[0]["service"], w[0]["stops_build"]) == (
        C.ENTRY_DROPPED_WARNING, "IAC.API_NOT_ALLOWED", "api_only", OFF_TABLE, False)
    assert "api_only." + OFF_TABLE in w[0]["message"] and "API-only entry" in w[0]["message"]
    # held for 0.9.1 with TI-3i-e (review F1): plan-named and not shipped is still reported, but stays a warning
    w, stops = outcome(d, intent(), plan_apis=(OFF_TABLE,))
    assert stops == [] and w[0]["missing"] == ["API " + OFF_TABLE] and w[0]["stops_build"] is False
    (e,) = C.dropped_intent_entries(json.dumps({"api_only": [{"service": "x"}]}),
                                    {"api_only.x": "REMOVAL_CODE:IAC.API_NOT_ALLOWED"})
    w, stops = outcome([e], intent(), plan_apis=(OFF_TABLE,))   # an off-grammar service names no API: warning only
    assert stops == [] and w[0]["plan_named"] == []


def test_ti3i_b_end_to_end_an_off_table_api_only_entry_removed_by_a_repair_ships_with_a_warning():
    files, agent, err = _gen(intent([T3.BUCKET_MODULE], api_only=[OFF_TABLE]), intent([T3.BUCKET_MODULE]))
    assert err is None and agent.last_validation_report.status == "PASS"
    (w,) = agent.stack_run("t-ti3")["iac_intent_warnings"]
    assert (w["address"], w["removed_as"], w["kind"], w["stops_build"]) == (
        "api_only." + OFF_TABLE, "IAC.API_NOT_ALLOWED", "api_only", False)


def test_ti3i_b_held_end_to_end_a_plan_named_api_only_removal_ships_with_a_warning():
    """Review F1 pin (held for 0.9.1 with TI-3i-e, owner decision pending): the plan lists the off-table API the AI
    put in api_only; the repair removes the entry; the build ships with the warning, stops_build False."""
    files, agent, err = _gen(intent([T3.BUCKET_MODULE], api_only=[OFF_TABLE]), intent([T3.BUCKET_MODULE]),
                             plan_apis=[OFF_TABLE])
    assert err is None and agent.last_validation_report.status == "PASS"
    (w,) = agent.stack_run("t-ti3")["iac_intent_warnings"]
    assert (w["address"], w["removed_as"], w["stops_build"], w["missing"]) == (
        "api_only." + OFF_TABLE, "IAC.API_NOT_ALLOWED", False, ["API " + OFF_TABLE])


def test_the_same_dropped_entry_is_reported_once():
    d = drops(intent(resources=[DOCS]), "google_discovery_engine_data_store.docs")
    w, _ = outcome(d + d, intent())
    assert len(w) == 1


# ------------------------------------------------------------------------------------------------ end to end
APP = T3.APP


def _gen(draft_intent, fixed_intent, plan_apis=None):
    draft = dict(APP, **{C.INTENT_PATH: draft_intent})
    att = {p: ("IAC_ENGINEER" if p == C.INTENT_PATH else "BACKEND_ENGINEER") for p in draft}
    orig = T3.record_of
    rec = (lambda raw: {**orig(raw), "required_cloud_apis": list(plan_apis)}) if plan_apis is not None else orig
    agents = []
    with patch.object(T3, "record_of", rec):
        try:
            files, agent, _c, _seen = T3._generate("generate", draft, att, repairs=[{C.INTENT_PATH: fixed_intent}],
                                                   repair_max_iterations_precommit=1, agent_out=agents)
            return files, agent, None
        except StageError as e:
            return None, agents[0], e


def test_end_to_end_a_repair_drop_without_a_plan_link_ships_with_a_visible_warning():
    files, agent, err = _gen(intent([T3.BUCKET_MODULE], [DOCS]), intent([T3.BUCKET_MODULE]))
    assert err is None and agent.last_validation_report.status == "PASS"
    (w,) = agent.stack_run("t-ti3")["iac_intent_warnings"]
    assert (w["address"], w["removed_as"], w["stops_build"]) == (
        "google_discovery_engine_data_store.docs", "IAC.TYPE_NOT_ALLOWED", False)
    ev = [e for e in agent.last_repair_events if e.kind != "junior_reask"]
    assert ev[0].removal_reasons == {"google_discovery_engine_data_store.docs": "REMOVAL_CODE:IAC.TYPE_NOT_ALLOWED"}


def test_end_to_end_a_plan_named_service_dropped_by_a_repair_stops_typed():
    files, agent, err = _gen(intent([T3.BUCKET_MODULE], [DOCS]), intent([T3.BUCKET_MODULE]),
                             plan_apis=["discoveryengine.googleapis.com"])
    assert files is None and err is not None and err.error_class is ErrorClass.PLATFORM_DEFECT
    assert [d.code for d in err.report.diagnostics] == [C.REQUESTED_SERVICE_DROPPED]
    assert agent.stack_run("t-ti3")["iac_intent_warnings"][0]["stops_build"] is True


def test_end_to_end_no_drop_means_no_warning_and_a_provided_plan_list_changes_nothing():
    # TI-3i-e: a plan API nothing provides stops even without a drop (tests/test_ti3i_e_plan_api_stop.py); a plan
    # whose APIs the build provides (vending / foundation / the bucket module's storage) changes nothing
    files, agent, err = _gen(intent([T3.BUCKET_MODULE], [TOPIC]), intent([T3.BUCKET_MODULE], [TOPIC]),
                             plan_apis=["run.googleapis.com", "storage.googleapis.com", "pubsub.googleapis.com"])
    assert err is None and agent.stack_run("t-ti3")["iac_intent_warnings"] == []


def test_warnings_are_stored_on_the_workload_record_and_cleared_by_a_clean_build():
    from developer_agent import handler as h
    db = MagicMock()
    agent = SimpleNamespace(db=db, stack_run=lambda t: {"plan_required_apis": []}, _record_stack=lambda *a, **k: None,
                            _persist_stack_outcome=lambda *a, **k: None)
    inputs = SimpleNamespace(product_id="shop", trace_id="t1", compute_intent=SimpleNamespace(topology=None),
                             iac_intent=SimpleNamespace(artifacts=ART))
    d = drops(intent(resources=[DOCS]), "google_discovery_engine_data_store.docs")
    h.DeveloperAgent._intent_drop_outcome(agent, inputs, list(d), {C.INTENT_PATH: intent()}, [])
    doc = db.collection.return_value.document.return_value
    db.collection.assert_called_with("workloads")
    db.collection.return_value.document.assert_called_with("shop")
    (payload,), kw = doc.set.call_args
    assert kw == {"merge": True} and payload["iac_intent_warnings_trace_id"] == "t1"
    assert [x["address"] for x in payload["iac_intent_warnings"]] == ["google_discovery_engine_data_store.docs"]
    h.DeveloperAgent._intent_drop_outcome(agent, inputs, [], {C.INTENT_PATH: intent()}, [])
    assert doc.set.call_args.args[0]["iac_intent_warnings"] == []


def test_the_workload_page_renders_the_warnings_from_the_details_api():
    with open(os.path.join(REPO_ROOT, "apps/control-center/templates/dashboard.html"), encoding="utf-8") as fh:
        html = fh.read()
    assert 'data-testid="iac-intent-warnings"' in html
    assert 'x-for="w in workloadDetails.iac_intent_warnings"' in html and 'x-text="w.message"' in html
    from importlib import util
    spec = util.spec_from_file_location("cc_schemas_ti3i", os.path.join(REPO_ROOT, "apps/control-center/schemas.py"))
    mod = util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert "iac_intent_warnings" in mod.WorkloadDetailsResponse.model_fields


# ------------------------------------------------------------------------------------------------ architect record
def test_compute_record_carries_the_plan_apis_only_when_given():
    from architect_agent.schemas import ArchitecturePlan, compute_intent_record
    plan = ArchitecturePlan(product_id="p", target_compute_services=["p"])
    assert "required_cloud_apis" not in compute_intent_record(plan)
    rec = compute_intent_record(plan, plan_apis=["run.googleapis.com", "discoveryengine.googleapis.com", "bad api",
                                                 "run.googleapis.com"])
    assert rec["required_cloud_apis"] == ["discoveryengine.googleapis.com", "run.googleapis.com"]


def _architect_record(plan_extra):
    from architect_agent.handler import ArchitectAgent
    plan = {"product_id": "portal", "summary": "s", "architecture_overview": "o", "infra_tasks": [], "code_tasks": [],
            "target_compute_services": ["portal"], "compute_archetype": "cloudrun", "iac_engine": "tofu",
            "service_topology": {"services": [{"name": "portal", "kind": "cloudrun"}], "primary_service": "portal",
                                 "edges": [], "resources": []}, **plan_extra}
    client = MagicMock()
    client.models.generate_content.return_value = SimpleNamespace(text=json.dumps(plan), candidates=[],
                                                                  usage_metadata=None)
    env = {"ENABLE_DUAL_ARCHITECT_CONSENSUS": "false", "PROJECT_ID": "", "GCP_PROJECT": "", "GOOGLE_CLOUD_PROJECT": "",
           "GEMINI_API_KEY": ""}
    with patch.dict(os.environ, env), \
            patch("google.genai.Client", MagicMock(side_effect=RuntimeError("no LLM in tests"))), \
            patch("google.cloud.firestore.Client", MagicMock(return_value=MagicMock())):
        agent = ArchitectAgent(project_id="")
        agent.genai_client = client
        agent.model = None
        result = agent.decompose(spec_text="A portal with a Cloud Storage bucket, Pub/Sub topic and a vpc",
                                 product_id="portal", trace_id="trace-ti3i")
    return result.compute_intent


def test_architect_record_carries_the_model_build_plan_apis_but_never_the_keyword_fallback():
    model_plan = {"sequenced_build_plan": {"required_cloud_apis": ["run.googleapis.com",
                                                                   "discoveryengine.googleapis.com"],
                                           "steps": [{"step_id": "STEP-01", "title": "APIs"}]}}
    assert _architect_record(model_plan)["required_cloud_apis"] == ["discoveryengine.googleapis.com",
                                                                    "run.googleapis.com"]
    # no model build plan: the keyword fallback (spec words "bucket", "pub/sub", "vpc") must not become typed plan data
    assert "required_cloud_apis" not in _architect_record({})
