"""PUSH-PLAN-CHECK (register row PUSH-PLAN-CHECK, owner 10-28): the architect's typed topology records "topic T of this
workload pushes to its cloudrun service S at path P" (`service_topology.PushEdge`, `pushes`), and a blocking
pre-commit validator (V-IAC-PUSH, `validators/push_plan.py`) requires the typed intent to declare that push: a
messaging-pubsub `push` on T's realizing module, or a hand-written google_pubsub_subscription whose typed push_config
targets S's URI + P. A miss is one finding with the exact entry and field to set, repaired by the existing loop; the
platform never rewrites the intent.

- topology: the edge validates (closed grammar; PUSH-SUB-RENDER's push_path_ok, the one definition); refusals typed.
- Do No Harm: a topology without the edge persists, hashes and prompts exactly as main e7cab11b did (pinned digests,
  tests/push_plan_check_cases.py); without an edge (or with mode off) the validator stack is unchanged.
- validator: typed satisfaction (module / raw), precise hints, no finding when the intent does not parse, never a
  mutation.
- loop: end to end through the developer dispatch (generate mode): the miss is routed to the IaC persona and a correct
  repair passes; a finding revealed by making the intent parse is accepted (repair_loop.accept), a caused one is not.
Fakes stand in for the LLM; no network, no credentials.
"""
import hermetic_guard  # noqa: F401  (first import)

import copy
import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from shared import iac_intent as II  # noqa: E402
from shared import service_topology as st  # noqa: E402
from shared.diagnostics import ErrorClass, RepairBudgetExhausted  # noqa: E402
from developer_agent import iac_intent_contract as C  # noqa: E402
from developer_agent.validators import push_plan as PP  # noqa: E402
from developer_agent.validators.base import ValidationContext  # noqa: E402
import push_plan_check_cases as cases  # noqa: E402

PID = "shop"
PATH = "/api/v1/tasks/process"
EVENTS = {"type": "google_pubsub_topic", "logical_name": "events", "purpose": "events",
          "consumers": [{"service": "shop", "env_key": "EVENTS_TOPIC", "attribute": "id"}]}
PUSH_EDGE = {"topic": "events", "service": "shop", "path": PATH}


def topo(pushes=(PUSH_EDGE,), resources=(EVENTS,), services=(("shop", "cloudrun"),), primary="shop", edges=()):
    out = {"services": [{"name": n, "kind": k} for n, k in services], "primary_service": primary,
           "edges": [{"caller": a, "callee": b, "protocol": p} for a, b, p in edges],
           "resources": [copy.deepcopy(r) for r in resources]}
    if pushes is not None:
        out["pushes"] = [dict(e) for e in pushes]
    return out


def vt_of(raw):
    vt, diags = st.validate_service_topology(raw, product_id=PID)
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def errors(raw):
    _vt, diags = st.validate_service_topology(raw, product_id=PID)
    return sorted((d.code, d.block_address) for d in diags if d.severity == "error")


def F(fact="workload_sa_email"):
    return {"$ref": {"kind": "fact", "fact": fact}}


def SVC(svc="shop", output="service_uri"):
    return {"$ref": {"kind": "service", "service": svc, "output": output}}


def push(service="shop", path=PATH):
    return {"service": SVC(service), "path": path, "service_account_email": F()}


def module(p=None, name="events", realizes="events"):
    m = {"module": "messaging-pubsub", "name": name, "args": {"topic_name_suffix": "events"}}
    if p is not None:
        m["args"]["push"] = p
    if realizes:
        m["realizes"] = realizes
    return m


def raw_sub(topic_ref, endpoint, name="events_push", listed=False):
    pc = {"push_endpoint": endpoint, "oidc_token": {"service_account_email": F()}}
    return {"type": "google_pubsub_subscription", "name": name,
            "arguments": {"name": name, "topic": topic_ref, "push_config": [pc] if listed else pc}}


def fmt(path, svc="shop"):
    return {"$fn": "format", "$args": ["%s" + path, SVC(svc)]}


def MOUT(module_name="events", output="topic_id"):
    return {"$ref": {"kind": "module_output", "module": module_name, "output": output}}


def RATTR(name="events", attr="id"):
    return {"$ref": {"kind": "resource_attr", "type": "google_pubsub_topic", "name": name, "attr": attr}}


def intent(modules=(), resources=()):
    return json.dumps({"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources),
                       "outputs": []}, indent=2)


def run_check(text, raw=None):
    files = {} if text is None else {C.INTENT_PATH: text}
    before = dict(files)
    ctx = ValidationContext.build(files, ownership=lambda p: None, iteration=3)
    out = PP.PushPlanValidator(vt_of(raw or topo())).validate(ctx)
    assert dict(ctx.files) == before   # read-only
    return out


# ------------------------------------------------------------------------------------------------ topology
def test_example_01_shape_validates_and_exposes_the_edge():
    vt = vt_of(topo())
    assert [(e.topic, e.service, e.path) for e in vt.pushes] == [("events", "shop", PATH)]
    assert vt.as_record()["intent"]["pushes"] == [PUSH_EDGE]
    # the persisted record round-trips (sha256 is over the canonical form that carries the edge)
    vt2, diags = st.topology_from_record(vt.as_record(), product_id=PID)
    assert vt2 is not None and not diags and vt2.sha256 == vt.sha256 and vt2.pushes == vt.pushes


def test_push_path_rule_is_the_one_push_sub_render_definition():
    assert II.push_path_ok is st.push_path_ok and II.PUSH_PATH_PATTERN == st.PUSH_PATH_PATTERN
    for good in ("/", "/x/", "/tasks", PATH, "/a-b_c.d~e/f", "/.well-known/x"):
        assert not errors(topo(pushes=[dict(PUSH_EDGE, path=good)])), good


@pytest.mark.parametrize("bad", ["/..", "/../../admin", "/.", "/a//b", "//x", "/@x", "/:8080/x", "/x\n", "x/", "",
                                 "/x?y=1", "/x#y", "/${var.x}", "/a b"])
def test_bad_paths_are_a_typed_finding(bad):
    assert errors(topo(pushes=[dict(PUSH_EDGE, path=bad)])) == [("TOPOLOGY.PUSH_PATH_INVALID", "pushes[0].path")]


def test_refusals_are_typed_and_never_healed():
    bucket = {"type": "google_storage_bucket", "logical_name": "raw", "consumers": []}
    assert errors(topo(pushes=[dict(PUSH_EDGE, topic="nope")])) == [("TOPOLOGY.PUSH_TOPIC_UNKNOWN", "pushes[0].topic")]
    assert errors(topo(pushes=[dict(PUSH_EDGE, topic="raw")], resources=(EVENTS, bucket))) == [
        ("TOPOLOGY.PUSH_TOPIC_UNKNOWN", "pushes[0].topic")]
    assert errors(topo(pushes=[PUSH_EDGE, dict(PUSH_EDGE, path="/other")])) == [("TOPOLOGY.DUPLICATE_PUSH", "pushes[1]")]
    assert errors(topo(pushes=[dict(PUSH_EDGE, service="ghost")])) == [
        ("TOPOLOGY.PUSH_UNKNOWN_SERVICE", "pushes[0].service")]
    assert errors(topo(pushes=[dict(PUSH_EDGE, service="jobs")],
                       services=(("shop", "cloudrun"), ("jobs", "event-worker")))) == [
        ("TOPOLOGY.PUSH_TARGET_UNSUPPORTED", "pushes[0].service")]
    worker = topo(pushes=[dict(PUSH_EDGE, service="batch")], services=(("shop", "cloudrun"), ("batch", "gce-worker")),
                  edges=(("shop", "batch", "launch"),))
    assert errors(worker) == [("TOPOLOGY.PUSH_TARGET_UNSUPPORTED", "pushes[0].service")]
    assert errors(topo(pushes=[dict(PUSH_EDGE, path=7)]))[0][0] == "TOPOLOGY.SCHEMA_INVALID"
    assert not errors(topo(pushes=[dict(PUSH_EDGE, path="/" + "x" * 255)]))   # the grammar's 256-char maximum
    assert errors(topo(pushes=[dict(PUSH_EDGE, path="/" + "x" * 256)]))[0][0] == "TOPOLOGY.SCHEMA_INVALID"
    assert errors(topo(pushes=[dict(PUSH_EDGE, service="Bad_Name")]))[0][0] == "TOPOLOGY.SCHEMA_INVALID"
    raw = topo(pushes=[dict(PUSH_EDGE, topic="nope")])
    snapshot = copy.deepcopy(raw)
    st.validate_service_topology(raw, product_id=PID)
    assert raw == snapshot   # the input is never changed


def test_push_to_a_secondary_cloudrun_service():
    raw = topo(pushes=[dict(PUSH_EDGE, service="worker")], services=(("shop", "cloudrun"), ("worker", "cloudrun")))
    assert [e.service for e in vt_of(raw).pushes] == ["worker"]


def test_contract_states_pushes_once_and_the_architect_schema_carries_it():
    from architect_agent.prompt import ARCHITECT_SYSTEM_PROMPT
    from architect_agent.schemas import ArchitecturePlanDAG
    text = st.render_topology_contract()
    assert text.count(st.PUSH_CONTRACT_LINE) == 1 and "`pushes`" in st.PUSH_CONTRACT_LINE
    assert '"pushes": [{"topic": "string", "service": "string", "path": "/string"}]' in ARCHITECT_SYSTEM_PROMPT
    schema = json.dumps(ArchitecturePlanDAG.model_json_schema())
    assert "PushEdge" in schema


# ------------------------------------------------------------------------------------------------ Do No Harm
def test_topology_without_the_edge_is_byte_identical_to_main():
    """Pinned with main e7cab11b: canonical form, sha256, topology.json, the typed / classic developer contract and the
    intent slot lines of three no-push topologies (01, 03 shapes and a multi-service one)."""
    assert cases.digests() == cases.PINNED


def test_explicit_empty_pushes_equals_absent():
    for raw in cases.TOPOLOGIES.values():
        a, b = vt_of(raw), vt_of(dict(raw, pushes=[]))
        assert st.canonical_topology_json(a.intent) == st.canonical_topology_json(b.intent)
        assert "pushes" not in a.as_record()["intent"] and a.pushes == ()


def test_shared_copies_are_byte_identical():
    for rel in ("service_topology.py", "iac_intent.py"):
        assert Path(REPO_ROOT, "shared", rel).read_bytes() == Path(GATEWAY, "shared", rel).read_bytes()


def _stack_ids(topology, iac_intent):
    from developer_agent.validators.step1 import build_step1_stack
    kw = {"iac_intent": iac_intent} if iac_intent is not None else {}
    return build_step1_stack(validate_client=None, verifier_factory=None, topology=topology, **kw)


def test_validator_is_registered_only_with_a_push_edge_on_the_intent_path():
    run = object()   # an IntentRun stand-in: register only checks presence
    with_edge, without = vt_of(topo()), vt_of(topo(pushes=None))
    s = _stack_ids(with_edge, run)
    assert "V-IAC-PUSH" in s.ids and s.mode_of("V-IAC-PUSH") == "blocking"
    assert "V-IAC-PUSH" not in _stack_ids(without, run).ids
    assert "V-IAC-PUSH" not in _stack_ids(with_edge, None).ids   # mode off: classic path unchanged
    assert [i for i in s.ids if i != "V-IAC-PUSH"] == _stack_ids(without, run).ids


def test_developer_contract_line_only_with_the_edge():
    lines = C.topology_slot_lines(vt_of(topo()))
    push_lines = [x for x in lines if "pushes to the service" in x]
    assert push_lines == [C.push_plan_line("events", "shop", PATH)]
    assert json.dumps(C.push_plan_form("shop", PATH), sort_keys=True) in push_lines[0]
    assert C.topology_slot_lines(vt_of(topo(pushes=None))) == [x for x in lines if x not in push_lines]


# ------------------------------------------------------------------------------------------------ validator
def test_module_push_satisfies_the_edge():
    assert run_check(intent([module(push())])) == []


@pytest.mark.parametrize("topic_ref", [MOUT(output="topic_id"), MOUT(output="topic_name")])
@pytest.mark.parametrize("listed", [False, True])
def test_raw_subscription_on_the_module_topic_satisfies_the_edge(topic_ref, listed):
    assert run_check(intent([module()], [raw_sub(topic_ref, fmt(PATH), listed=listed)])) == []


@pytest.mark.parametrize("attr", ["id", "name"])
def test_raw_subscription_on_a_raw_topic_satisfies_the_edge(attr):
    topic = {"type": "google_pubsub_topic", "name": "events", "realizes": "events", "arguments": {"name": "events"}}
    assert run_check(intent([], [topic, raw_sub(RATTR(attr=attr), fmt(PATH))])) == []


def test_root_path_accepts_the_bare_service_url_and_the_slash_form():
    raw = topo(pushes=[dict(PUSH_EDGE, path="/")])
    assert run_check(intent([module()], [raw_sub(MOUT(), SVC())]), raw) == []
    assert run_check(intent([module()], [raw_sub(MOUT(), fmt("/"))]), raw) == []
    assert run_check(intent([module(push(path="/"))]), raw) == []
    # the bare URL is "/" only
    assert [d.code for d in run_check(intent([module()], [raw_sub(MOUT(), SVC())]))] == [PP.CODE]


def test_missing_push_is_one_precise_finding_on_the_intent():
    (d,) = run_check(intent([module()]))
    assert (d.code, d.file, d.severity, d.error_class, d.tool, d.symbol, d.iteration) == (
        PP.CODE, C.INTENT_PATH, "error", ErrorClass.CODE_DEFECT, "schema", "push:events", 3)
    assert "'events' pushes to the service 'shop' at '/api/v1/tasks/process'" in d.message
    assert "module events" in d.hint and json.dumps(C.push_plan_form("shop", PATH), sort_keys=True) in d.hint
    assert "do not also write a google_pubsub_subscription" in d.hint


@pytest.mark.parametrize("p", [push(path="/api/v1/other"), push(service="worker"),
                               {"service": SVC(output="service_name"), "path": PATH, "service_account_email": F()},
                               {"service": SVC(), "path": PATH + "/", "service_account_email": F()}])
def test_push_elsewhere_is_a_finding_that_names_service_and_path(p):
    raw = topo(services=(("shop", "cloudrun"), ("worker", "cloudrun")))
    (d,) = run_check(intent([module(p)]), raw)
    assert "pushes elsewhere" in d.hint and json.dumps(PATH) in d.hint and '"service": "shop"' in d.hint
    assert "keep its service_account_email" in d.hint


def test_raw_subscription_that_does_not_satisfy_is_a_finding():
    other = module(name="audit", realizes=None)
    for bad in (raw_sub(MOUT("audit"), fmt(PATH)),            # another topic
                raw_sub(MOUT(), fmt("/other")),               # another path
                raw_sub(MOUT(), fmt(PATH, svc="worker")),     # another service
                raw_sub(MOUT(), PATH),                        # a literal endpoint (the gate refuses it too)
                raw_sub(MOUT(output="subscription_id"), fmt(PATH))):
        assert [d.code for d in run_check(intent([module(), other], [bad]))] == [PP.CODE], bad
    (d,) = run_check(intent([module()], [raw_sub(MOUT(), fmt("/other"))]))
    assert d.hint.startswith("google_pubsub_subscription.events_push (on the topic 'events') pushes elsewhere")
    assert '"%s/api/v1/tasks/process"' in d.hint and "keep its oidc_token" in d.hint
    no_push = {"type": "google_pubsub_subscription", "name": "pull",
               "arguments": {"name": "pull", "topic": MOUT()}}
    assert [d.code for d in run_check(intent([module()], [no_push]))] == [PP.CODE]


def test_raw_topic_realizer_gets_the_raw_subscription_hint():
    topic = {"type": "google_pubsub_topic", "name": "inbound", "realizes": "events", "arguments": {"name": "events"}}
    (d,) = run_check(intent([], [topic]))
    assert "google_pubsub_topic.inbound" in d.hint and "google_pubsub_subscription" in d.hint
    assert '"%s/api/v1/tasks/process"' in d.hint and '"name": "inbound"' in d.hint


def test_unrealized_topic_gets_the_realize_hint():
    (d,) = run_check(intent([module(realizes=None)]))
    assert d.hint.startswith("Realize the topic 'events' with a messaging-pubsub module instance")


def test_negatives_not_judged_without_a_parseable_intent():
    for text in (None, "", "{", "[]", json.dumps({"schema": "iac_intent/v1", "modules": [], "extra": 1}),
                 json.dumps({"schema": "iac_intent/v2"})):
        assert run_check(text) == [], text
        assert PP.push_plan_judged({} if text is None else {C.INTENT_PATH: text}) is False
    assert PP.push_plan_judged({C.INTENT_PATH: intent()}) is True


def test_no_edge_no_finding():
    assert run_check(intent([module()]), topo(pushes=None)) == []
    assert run_check(intent(), topo(pushes=None)) == []


# ------------------------------------------------------------------------------------------------ the repair loop
def _gen(draft_intent, repairs=(), raw=None, agents=None, **settings):
    from test_typed_iac_ti3_contract import APP, _generate
    draft = dict(APP, **{C.INTENT_PATH: draft_intent})
    att = {p: ("IAC_ENGINEER" if p == C.INTENT_PATH else "BACKEND_ENGINEER") for p in draft}
    agents = [] if agents is None else agents
    out = _generate("generate", draft, att, raw=raw or topo(), repairs=list(repairs), agent_out=agents, **settings)
    return out, agents


def _diag_codes(task):
    return [x["code"] for x in json.loads(task["prompt"].split("DIAGNOSTICS:\n\n", 1)[1].split("\n\nFILES TO FIX", 1)[0])]


def test_end_to_end_missing_push_is_repaired_by_the_iac_persona():
    fixed = {C.INTENT_PATH: intent([module(push())])}
    (files, agent, _c, seen), _a = _gen(intent([module()]), repairs=[fixed], repair_max_iterations_precommit=1)
    assert agent.last_validation_report.status == "PASS" and files[C.INTENT_PATH] == fixed[C.INTENT_PATH]
    (task,) = seen["repair_tasks"]
    assert task["persona"] == "IAC_ENGINEER" and _diag_codes(task) == [PP.CODE]
    files_to_fix = json.loads(task["prompt"].split("FILES TO FIX:\n\n", 1)[1].split("\n\n", 1)[0])
    assert sorted(files_to_fix) == [C.INTENT_PATH]
    assert "set \\\"push\\\" in the args of module events".lower() in task["prompt"].lower()
    custom = json.loads(files[C.RENDER_PATH])
    assert custom["module"]["events"]["push"]["endpoint"] == "${module.compute.service_uri}" + PATH


def test_end_to_end_satisfied_and_no_edge_need_no_repair():
    (files, agent, _c, seen), _a = _gen(intent([module(push())]))
    assert agent.last_validation_report.status == "PASS" and seen["repair_tasks"] == []
    (files2, agent2, _c2, seen2), _a2 = _gen(intent([module()]), raw=topo(pushes=None))
    assert agent2.last_validation_report.status == "PASS" and seen2["repair_tasks"] == []
    assert "push" not in json.loads(files2[C.RENDER_PATH])["module"]["events"]


def test_end_to_end_unfixed_push_blocks_the_commit():
    with pytest.raises(RepairBudgetExhausted) as ei:
        _gen(intent([module()]), repair_max_iterations_precommit=0)
    assert [(d.code, d.file) for d in ei.value.report.diagnostics if d.severity == "error"] == [
        (PP.CODE, C.INTENT_PATH)]


def test_revealed_finding_after_the_intent_parses_is_accepted_then_repaired():
    """The draft's intent is not JSON (V-IAC JSON.OUTPUT_INVALID; V-IAC-PUSH does not judge it). The first repair makes
    it parse without the push: the push finding is revealed, not caused, so the repair is accepted; the second repair
    adds the push and the tree passes."""
    first = {C.INTENT_PATH: intent([module()])}
    second = {C.INTENT_PATH: intent([module(push())])}
    (files, agent, _c, seen), _a = _gen("{not json", repairs=[first, second], repair_max_iterations_precommit=2)
    assert agent.last_validation_report.status == "PASS" and files[C.INTENT_PATH] == second[C.INTENT_PATH]
    assert [_diag_codes(t) for t in seen["repair_tasks"]] == [["JSON.OUTPUT_INVALID"], [PP.CODE]]


def test_without_the_exemption_the_revealing_repair_would_be_rejected(monkeypatch):
    """Guards the exemption itself: when the previous tree counts as judged, the same repair is NEW_FINGERPRINT."""
    from developer_agent import repair_loop
    monkeypatch.setattr(repair_loop, "push_plan_judged", lambda files: True)
    first = {C.INTENT_PATH: intent([module()])}
    agents = []
    with pytest.raises(RepairBudgetExhausted):
        _gen("{not json", repairs=[first], repair_max_iterations_precommit=1, agents=agents)
    ev = [e for e in agents[0].last_repair_events if e.kind != "junior_reask"]
    assert [(e.accepted, e.reject_reason) for e in ev] == [(False, "NEW_FINGERPRINT")]


def test_a_repair_that_drops_a_correct_push_is_rejected():
    """Caused, not revealed: the previous intent parsed (judged) and satisfied the edge; a repair that fixes another
    finding but drops the push is NEW_FINGERPRINT."""
    api = {"type": "google_project_service", "name": "run", "arguments": {"service": "run.googleapis.com"}}
    lossy = {C.INTENT_PATH: intent([module()])}   # removes the refused API entry AND the push
    agents = []
    with pytest.raises(RepairBudgetExhausted):
        _gen(intent([module(push())], [api]), repairs=[lossy], repair_max_iterations_precommit=1, agents=agents)
    ev = [e for e in agents[0].last_repair_events if e.kind != "junior_reask"]
    assert [(e.accepted, e.reject_reason) for e in ev] == [(False, "NEW_FINGERPRINT")]
    # control: the same repair keeping the push is accepted (the API entry's removal is justified)
    keep = {C.INTENT_PATH: intent([module(push())])}
    (_f, agent, _c, _s), _a = _gen(intent([module(push())], [api]), repairs=[keep], repair_max_iterations_precommit=1)
    assert agent.last_validation_report.status == "PASS"


def test_critic_remediation_brief_keeps_the_push_edges():
    """Review F1: the remediation turn is told to keep the draft's push edges with the rest of the topology, so a
    critic round cannot drop the edge the push-plan check is built from."""
    from types import SimpleNamespace
    from architect_agent.consensus_engine import DualArchitectConsensusEngine
    topo = {"services": [{"name": "api", "kind": "cloudrun"}], "primary_service": "api",
            "pushes": [{"topic": "events", "service": "api", "path": "/pubsub/push"}]}
    brief = DualArchitectConsensusEngine._draft_compute_decision(
        SimpleNamespace(_raw_service_topology=topo, compute_archetype="cloudrun"))
    assert "(services, kinds, primary_service, edges, resources, pushes)" in brief
    assert '"/pubsub/push"' in brief
