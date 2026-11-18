"""TI-3i-e (register, owner 10-25): generate mode - an API the architect's typed plan needs (`required_cloud_apis` on
the compute record, the vending / foundation APIs excluded) that nothing in the shipped build provides stops the
developer stage typed (IAC.PLAN_API_NOT_PROVIDED, PLATFORM_DEFECT), even when no intent entry was dropped. "Provides"
is the exact table rule of TI-3i (shared/api_requirements rows of the shipped root Terraform + vending / foundation
APIs + api_only entries). Negatives: no plan list, a provided plan list, and foundation APIs never stop; an API a
dropped-entry stop already names is not stopped twice. Hermetic (no network, no LLM).
HELD for 0.9.1 (owner decision pending): the developer stage does not call plan_api_outcome; the unit tests of the
function stay, and the hold commit's revert re-enables the end-to-end stop."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

import test_ti3i_dropped_entries as D  # noqa: E402
import test_typed_iac_ti3_contract as T3  # noqa: E402
from developer_agent import iac_intent_contract as C  # noqa: E402
from shared.diagnostics import ErrorClass  # noqa: E402

ART = D.ART
OFF = "discoveryengine.googleapis.com"   # nothing in the platform provides it
AI = "aiplatform.googleapis.com"         # api_only table row + ai-vertex-endpoint module


def plan_outcome(final_intent, plan_apis, already=()):
    tree = {C.INTENT_PATH: final_intent, D.W + "main.tf": "", D.W + "custom.tf.json": "{}"}
    if final_intent:
        r = D.ii.validate_intent(final_intent, ART, D.ii.IntentContext())
        if r.ok:
            tree.update(D.ii.render_intent(r.validated).files)
    return C.plan_api_outcome(tree, plan_apis, ART, already=already)


def test_a_plan_api_nothing_provides_stops_typed_without_a_drop():
    w, stops = plan_outcome(D.intent(), (OFF, "run.googleapis.com"))
    (d,) = stops
    assert (d.code, d.error_class, d.file, d.symbol) == (C.PLAN_API_NOT_PROVIDED, ErrorClass.PLATFORM_DEFECT,
                                                         C.INTENT_PATH, OFF)
    assert OFF in d.message and "cannot provide" in d.hint
    (x,) = w
    assert (x["code"], x["address"], x["kind"], x["stops_build"], x["missing_apis"]) == (
        C.PLAN_API_WARNING, OFF, "plan_api", True, [OFF])


def test_the_hint_names_the_typed_ways_from_the_exact_tables():
    _w, (d,) = plan_outcome(D.intent(), (AI,))
    assert '"service": "aiplatform.googleapis.com"' in d.hint and "ai-vertex-endpoint" in d.hint
    assert C.api_providers(AI, ART) == {"api_only": [AI], "modules": ["ai-vertex-endpoint"], "resource_types": []}
    assert C.api_providers(OFF, ART) == {"api_only": [], "modules": [], "resource_types": []}
    sm = C.api_providers("secretmanager.googleapis.com", ART)
    assert "security-secret" in sm["modules"] and "google_secret_manager_secret" in sm["resource_types"]
    # platform-rendered modules (compute, network, foundation) are never offered
    assert not set(C.api_providers("run.googleapis.com", ART)["modules"]) & C._platform_module_ids()


def test_a_provided_plan_api_never_stops():
    assert plan_outcome(D.intent(api_only=[AI]), (AI,)) == ([], [])                     # api_only entry
    assert plan_outcome(D.intent([T3.BUCKET_MODULE]), ("storage.googleapis.com",)) == ([], [])
    tree = {C.INTENT_PATH: D.intent(), D.W + "main.tf":
            'module "kv" {\n  source = "../modules/security-secret"\n}\n'}            # a shipped module's row
    assert C.plan_api_outcome(tree, ("secretmanager.googleapis.com",), ART) == ([], [])


def test_no_plan_list_or_only_foundation_apis_never_stop():
    assert plan_outcome(D.intent(), ()) == ([], [])
    assert plan_outcome(D.intent(), None) == ([], [])
    assert plan_outcome(D.intent(), ("run.googleapis.com", "firestore.googleapis.com", "iam.googleapis.com",
                                     "cloudbuild.googleapis.com", "artifactregistry.googleapis.com")) == ([], [])


def test_an_api_a_dropped_entry_stop_already_names_is_not_stopped_twice():
    assert plan_outcome(D.intent(), (OFF,), already=(OFF,)) == ([], [])
    w, stops = plan_outcome(D.intent(), (OFF, AI), already=(OFF,))
    assert [d.symbol for d in stops] == [AI]
    dropped = D.drops(D.intent(resources=[D.DOCS]), "google_discovery_engine_data_store.docs")
    dw, dstops = D.outcome(dropped, D.intent(), plan_apis=(OFF,))
    assert dw[0]["missing_apis"] == [OFF] and [d.code for d in dstops] == [C.REQUESTED_SERVICE_DROPPED]


def test_held_for_0_9_1_the_developer_stage_does_not_wire_the_plan_api_stop():
    """TI-3i-e is held for 0.9.1 (owner decision pending): plan_api_outcome exists and is unit-tested above, but the
    stage ships a build whose plan lists an API nothing provides. Reverting the hold commit re-enables the stop."""
    files, agent, err = D._gen(D.intent([T3.BUCKET_MODULE], [D.TOPIC]), D.intent([T3.BUCKET_MODULE], [D.TOPIC]),
                               plan_apis=[OFF])
    assert err is None and files is not None and agent.stack_run("t-ti3")["iac_intent_warnings"] == []


def test_end_to_end_a_drop_and_its_plan_api_stop_once_with_the_drop_code():
    files, agent, err = D._gen(D.intent([T3.BUCKET_MODULE], [D.DOCS]), D.intent([T3.BUCKET_MODULE]),
                               plan_apis=[OFF])
    assert err is not None and [d.code for d in err.report.diagnostics] == [C.REQUESTED_SERVICE_DROPPED]
