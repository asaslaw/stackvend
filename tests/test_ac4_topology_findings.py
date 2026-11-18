"""AC-4 (docs/planning/app-code-reliability-plan.md, register row AC-4): the architect's topology gate.

Recorded evidence (cassettes 20261014-FRESH-main-769600e-record, 06-r1; fixture tests/fixtures/ac4/06r1_topology.json
holds the draft, the plan context, the recorded repair prompt and the recorded repair answer): the draft's pubsub edge
storefront -> factory-worker targeted a `cloudrun` service (EDGE_CALLEE_UNSUPPORTED), and that edge was skipped before
the env-key pass, so its ORDERS_TOPIC clash with the topic resource's consumer was invisible. The one repair fixed the
kind, the clash surfaced, and the gate stopped (ARCHITECT_DEFECT).

  1. The validator reports both findings on the first pass (exact key derivation; nothing healed).
  2. The gate gives a second (last) repair turn only when the first fixed every finding it was told about.
  3. Single-finding repair prompts are byte-identical to the pre-AC-4 code (snapshots frozen from main 5b8426b), so
     recorded architect repair calls still match.
Fakes stand in for the LLM; no network, no credentials."""
import hermetic_guard  # noqa: F401  (first import)

import copy
import hashlib
import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from architect_agent.schemas import ArchitecturePlan  # noqa: E402
from architect_agent.topology_gate import (MAX_REPAIR_TURNS, TopologyInvalidError,  # noqa: E402
                                           build_repair_prompt, fixed_every_finding, gate_service_topology)
from shared.diagnostics import fingerprint  # noqa: E402
from shared.service_topology import (CAPABILITIES, PROTOCOL_CALLEE_KIND, ServiceEdge,  # noqa: E402
                                     render_topology_contract, validate_service_topology)

FIXTURE = json.load(open(os.path.join(REPO_ROOT, "tests", "fixtures", "ac4", "06r1_topology.json")))
CTX, DRAFT, ANSWER = FIXTURE["context"], FIXTURE["draft"], FIXTURE["repair_answer"]
PID = CTX["product_id"]
FILE = "architect:service_topology"


def _validate(topo, expected="cloudrun"):
    return validate_service_topology(topo, product_id=PID, expected_archetype=expected, file=FILE, source="architect")


def _errors(diags):
    return [(d.code, d.block_address, d.symbol) for d in diags if d.severity == "error"]


def _without_topic_resource(topo):
    t = copy.deepcopy(topo)
    t["resources"] = [r for r in t["resources"] if r["logical_name"] != "widget_orders_placed"]
    return t


RING = {"services": [{"name": "api", "kind": "cloudrun"}, {"name": "core", "kind": "cloudrun"}],
        "primary_service": "api", "edges": [{"caller": "api", "callee": "core"}, {"caller": "core", "callee": "api"}],
        "resources": []}
GOOD = {**RING, "edges": [{"caller": "api", "callee": "core", "protocol": "http"}]}


# ------------------------------------------------------------------------------------------------ fixture provenance
R2_TYPES = ("google_alloydb_instance", "google_vertex_ai_endpoint", "google_bigtable_instance")


def test_fixture_is_the_recorded_06r1_repair_call(monkeypatch):
    """The recorded system instruction is today's contract without the three catalog types TI-5-R2 added (owner row
    TI-5-R2) and without the `pushes` line PUSH-PLAN-CHECK added (owner 10-28) and the secret `initial_value` line
    SECRET-INITIAL-VERSION added (owner 11-10) and Cloud SQL's password_secret_id attribute and note
    CLOUDSQL-PASSWORD-BINDING added (owner 11-14; the rest of the contract is unchanged), and the recorded draft yields
    today's repair prompt minus the DIAGNOSTICS block (the only part AC-4 changes for this draft)."""
    import shared.service_topology as st
    assert FIXTURE["recorded_system"] != render_topology_contract()   # the R2 types are in today's contract
    # CLOUDSQL-PASSWORD-BINDING (owner 11-14) appended password_secret_id to Cloud SQL's catalog entry
    cat = {t: a for t, a in st.BOOTSTRAP_CATALOG.items() if t not in R2_TYPES}
    cat["google_sql_database_instance"] = (("connection_name", "string"), ("private_ip_address", "string"))
    monkeypatch.setattr(st, "BOOTSTRAP_CATALOG", cat)
    monkeypatch.setattr(st, "CATALOG_NOTES", {})
    now = st.render_topology_contract()
    assert now.count(st.PUSH_CONTRACT_LINE) == 1 and now.count(st.SECRET_CONTRACT_LINE) == 1
    assert FIXTURE["recorded_system"] == now.replace(st.PUSH_CONTRACT_LINE, "").replace(st.SECRET_CONTRACT_LINE, "")
    monkeypatch.undo()
    _, diags = _validate(DRAFT)
    prompt = build_repair_prompt(DRAFT, diags, CTX)
    head = "--- DIAGNOSTICS ---\n"
    assert prompt.split(head)[0] == FIXTURE["recorded_prompt"].split(head)[0]
    recorded = json.loads(FIXTURE["recorded_prompt"].split(head)[1].rsplit("\n--- END ---", 1)[0])
    assert [d["code"] for d in recorded] == ["TOPOLOGY.EDGE_CALLEE_UNSUPPORTED"]    # pre-AC-4: the clash was hidden
    now = json.loads(prompt.split(head)[1].rsplit("\n--- END ---", 1)[0])
    assert now[0] == recorded[0] and len(now) == 2 and now[1]["code"] == "TOPOLOGY.ENV_KEY_COLLISION"


# ------------------------------------------------------------------------------------------------ validator (pass 1)
def test_06r1_draft_reports_both_findings_on_the_first_pass():
    vt, diags = _validate(DRAFT)
    assert vt is None
    assert _errors(diags) == [
        ("TOPOLOGY.EDGE_CALLEE_UNSUPPORTED", "edges[0].callee", None),
        ("TOPOLOGY.ENV_KEY_COLLISION", "edges[0]", "ORDERS_TOPIC"),
    ]
    clash = [d for d in diags if d.code == "TOPOLOGY.ENV_KEY_COLLISION"][0]
    assert clash.message == "'storefront' would receive ORDERS_TOPIC twice (edges[0] and resources[4].consumers[0])"
    assert clash.hint == ("a pubsub edge already gives the caller ORDERS_TOPIC (the platform creates that topic); "
                          "drop the other binding (resources[4].consumers[0]) or set a different env_key_base on "
                          "this edge.")


def test_pass1_clash_is_the_same_finding_the_recorded_repair_then_hit():
    """Same fingerprint as the clash the 10-14 repair answer surfaced: the AI is now told exactly that finding, and a
    repair that keeps it is not progress."""
    _, d1 = _validate(DRAFT)
    vt, d2 = _validate(ANSWER)
    assert vt is None and _errors(d2) == [("TOPOLOGY.ENV_KEY_COLLISION", "edges[0]", "ORDERS_TOPIC")]
    f1 = {fingerprint(d) for d in d1 if d.code == "TOPOLOGY.ENV_KEY_COLLISION"}
    assert f1 == {fingerprint(d) for d in d2 if d.code == "TOPOLOGY.ENV_KEY_COLLISION"}


def test_http_edge_to_a_worker_clashes_on_its_url_key():
    t = copy.deepcopy(_without_topic_resource(DRAFT))
    t["services"][1]["kind"] = "event-worker"
    t["edges"][0]["protocol"] = "http"
    t["resources"].append({"type": "google_storage_bucket", "logical_name": "b",
                           "consumers": [{"service": "storefront", "env_key": "ORDERS_URL"}]})
    _, diags = _validate(t)
    assert ("TOPOLOGY.ENV_KEY_COLLISION", "edges[0]", "ORDERS_URL") in _errors(diags)
    clash = [d for d in diags if d.code == "TOPOLOGY.ENV_KEY_COLLISION"][0]
    assert clash.hint.startswith("an http edge already gives the caller ORDERS_URL (the callee service's URL)")


def test_unbindable_caller_or_other_edge_defect_adds_nothing():
    """Only an edge whose ONLY defect is the callee kind is checked; an event-worker caller (no env vars) or an unknown
    callee keep today's single finding."""
    t = copy.deepcopy(DRAFT)
    t["services"][0]["kind"] = "event-worker"          # caller cannot bind -> no clash finding from this edge
    t["services"][1]["kind"] = "cloudrun"
    _, diags = _validate(t, expected="event-worker")
    assert "TOPOLOGY.ENV_KEY_COLLISION" not in [c for c, _, _ in _errors(diags)]
    t2 = copy.deepcopy(DRAFT)
    t2["edges"][0]["callee"] = "nobody"
    _, diags2 = _validate(t2)
    assert [c for c, _, _ in _errors(diags2)] == ["TOPOLOGY.EDGE_UNKNOWN_SERVICE"]


def test_keys_of_invalid_edges_are_checked_never_registered():
    """Two callee-kind-defective edges with the same base do not clash with each other (no follow-on findings)."""
    t = copy.deepcopy(_without_topic_resource(DRAFT))
    t["services"].append({"name": "billing", "kind": "cloudrun"})
    t["edges"].append({"caller": "storefront", "callee": "billing", "protocol": "pubsub", "env_key_base": "ORDERS"})
    _, diags = _validate(t)
    assert [c for c, _, _ in _errors(diags)] == ["TOPOLOGY.EDGE_CALLEE_UNSUPPORTED"] * 2


def _edge_vs_edge(wrong_first: bool, kind_fixed: bool = False):
    """Opus RT F1 probe: a wrong-kind http edge api -> worker (event-worker) and a valid http edge api -> core, both
    env_key_base X (both bind X_URL / X_AUDIENCE). `kind_fixed` = the repair that only makes worker a cloudrun."""
    wrong = {"caller": "api", "callee": "worker", "protocol": "http", "env_key_base": "X"}
    valid = {"caller": "api", "callee": "core", "protocol": "http", "env_key_base": "X"}
    return {"services": [{"name": "api", "kind": "cloudrun"}, {"name": "core", "kind": "cloudrun"},
                         {"name": "worker", "kind": "cloudrun" if kind_fixed else "event-worker"}],
            "primary_service": "api", "edges": [wrong, valid] if wrong_first else [valid, wrong], "resources": []}


@pytest.mark.parametrize("wrong_first", [True, False], ids=["wrong-edge-first", "wrong-edge-second"])
def test_edge_vs_edge_lookahead_matches_the_post_kind_fix_finding(wrong_first):
    _, d1 = _validate(_edge_vs_edge(wrong_first))
    _, d2 = _validate(_edge_vs_edge(wrong_first, kind_fixed=True))
    c1 = [d for d in d1 if d.code == "TOPOLOGY.ENV_KEY_COLLISION"]
    c2 = [d for d in d2 if d.code == "TOPOLOGY.ENV_KEY_COLLISION"]
    assert len(c1) == 2 and _errors(d2) == [(d.code, d.block_address, d.symbol) for d in c2]
    assert [(d.block_address, d.symbol, d.message) for d in c1] == [(d.block_address, d.symbol, d.message) for d in c2]
    assert {fingerprint(d) for d in c1} == {fingerprint(d) for d in c2}
    assert all(d.block_address == "edges[1]" and "(edges[1] and edges[0])" in d.message for d in c1)


def test_kind_only_fix_keeping_an_edge_clash_gets_no_second_turn():
    rep = _Repairs(_edge_vs_edge(True, kind_fixed=True), _edge_vs_edge(True, kind_fixed=True))
    plan = _plan(_edge_vs_edge(True))
    plan.target_compute_services = ["api", "core", "worker"]
    with pytest.raises(TopologyInvalidError) as ei:
        gate_service_topology(plan, product_id=PID, trace_id="t", repair_fn=rep)
    assert len(rep.prompts) == 1
    body = ei.value.to_body()
    assert body["error_class"] == "ARCHITECT_DEFECT"
    assert body["details"]["repair_event"]["reject_reason"] == "NO_PROGRESS"
    assert {d["code"] for d in body["diagnostics"]} == {"TOPOLOGY.ENV_KEY_COLLISION"}


def test_protocol_callee_kind_is_one_kind_per_protocol():
    protocols = set(ServiceEdge.model_fields["protocol"].annotation.__args__)
    assert set(PROTOCOL_CALLEE_KIND) == protocols
    for proto, kind in PROTOCOL_CALLEE_KIND.items():
        assert [k for k, c in CAPABILITIES.items() if c.callee_protocol == proto] == [kind]


@pytest.mark.parametrize("topo", [GOOD, ANSWER, _without_topic_resource(ANSWER)], ids=["http", "answer", "valid06"])
def test_negative_valid_topologies_have_no_new_findings(topo):
    """Do No Harm: the recorded answer keeps exactly its one (pre-AC-4) finding; valid topologies stay valid with no
    diagnostics at all; nothing is mutated."""
    before = json.dumps(topo, sort_keys=True)
    vt, diags = _validate(topo)
    assert json.dumps(topo, sort_keys=True) == before
    if topo is ANSWER:
        assert len(_errors(diags)) == 1
    elif topo is GOOD:
        assert vt is not None and diags == []
    else:   # the event-worker's resource bindings are warnings (BINDING_NOT_RENDERED), as before AC-4
        assert vt is not None and _errors(diags) == []
        assert {d.code for d in diags} == {"TOPOLOGY.BINDING_NOT_RENDERED"}


# ------------------------------------------------------------------------------------------------ prompt byte-identity
# sha256 of build_repair_prompt(topology, validate(topology), CTX), computed with the pre-AC-4 code (main 5b8426b).
PRE_AC4_PROMPT_SHA256 = {
    "06r1_without_topic_resource": "200406ea4ed363220e80bd3e180fd13ea686d9bdfd39902831385816c2099df2",
    "06r1_repair_answer": "a6b7e94ec67158ba4950f03c41854e6aad1818ac8635b93bc68971b3dd6c214a",
    "ring": "cd3a9ce7a744c2ad7fe538cd67555903c46ac1cb436e559606043654df605aa9",
    "ring_plus_duplicate_service": "92d3d34bd19903f4ebf2604dd0386106e7d6327b63f14d45cdb1141f8f0da403",
    "06r1_http_edge_to_event_worker": "c7512be0946b4ead75e00162a490f72af7033330390442a66e92852802ab5da3",
}


def _snapshot_cases():
    two = copy.deepcopy(RING)
    two["services"].append({"name": "api", "kind": "cloudrun"})
    http_wrong = copy.deepcopy(DRAFT)
    http_wrong["services"][1]["kind"] = "event-worker"
    http_wrong["edges"][0]["protocol"] = "http"
    return {"06r1_without_topic_resource": _without_topic_resource(DRAFT), "06r1_repair_answer": ANSWER,
            "ring": RING, "ring_plus_duplicate_service": two, "06r1_http_edge_to_event_worker": http_wrong}


@pytest.mark.parametrize("name", sorted(PRE_AC4_PROMPT_SHA256))
def test_repair_prompt_is_byte_identical_without_the_new_finding(name):
    """Single-finding repairs (and multi-finding ones without a callee-kind edge clash) keep the exact pre-AC-4 bytes,
    including the existing valid-edge ENV_KEY_COLLISION (no hint added to it)."""
    topo = _snapshot_cases()[name]
    _, diags = _validate(topo)
    prompt = build_repair_prompt(topo, diags, CTX)
    assert hashlib.sha256(prompt.encode()).hexdigest() == PRE_AC4_PROMPT_SHA256[name]


# ------------------------------------------------------------------------------------------------ gate (turns)
def _plan(topo):
    plan = ArchitecturePlan(product_id=PID, summary=CTX["summary"], architecture_overview=CTX["architecture_overview"],
                            infra_tasks=[], code_tasks=[], target_compute_services=CTX["target_compute_services"],
                            compute_archetype="cloudrun", iac_engine="tofu", bundle_id=CTX["bundle_id"])
    plan._raw_service_topology = copy.deepcopy(topo)
    return plan


class _Repairs:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.prompts = []

    def __call__(self, system, prompt):
        self.prompts.append(prompt)
        ans = self.answers.pop(0)
        return (ans if isinstance(ans, str) else json.dumps(ans)), "fake-model", 10, 5


FIXED = _without_topic_resource(ANSWER)    # kind fixed AND the duplicate topic binding dropped: valid


def test_06r1_both_told_and_both_fixed_passes_in_one_turn():
    rep = _Repairs(FIXED)
    res = gate_service_topology(_plan(DRAFT), product_id=PID, trace_id="t", repair_fn=rep)
    assert len(rep.prompts) == 1 and res.repaired is True
    assert "TOPOLOGY.ENV_KEY_COLLISION" in rep.prompts[0] and "TOPOLOGY.EDGE_CALLEE_UNSUPPORTED" in rep.prompts[0]
    assert [e.iteration for e in res.repair_events] == [1] and res.repair_event is res.repair_events[0]


def test_06r1_recorded_answer_kept_a_told_finding_so_no_second_turn():
    """The 10-14 answer fixed the kind but kept the clash it is now told about: not progress -> stop (as today)."""
    rep = _Repairs(ANSWER, FIXED)
    with pytest.raises(TopologyInvalidError) as ei:
        gate_service_topology(_plan(DRAFT), product_id=PID, trace_id="t", repair_fn=rep)
    assert len(rep.prompts) == 1
    body = ei.value.to_body()
    assert body["error_class"] == "ARCHITECT_DEFECT"
    assert [d["code"] for d in body["diagnostics"]] == ["TOPOLOGY.ENV_KEY_COLLISION"]
    assert body["details"]["repair_event"]["reject_reason"] == "NO_PROGRESS"
    assert "repair_events" not in body["details"]
    assert "after one repair" in body["summary"]


def test_second_turn_only_after_the_first_fixed_every_told_finding():
    """Turn 1 fixes the one finding it was told (the kind) and reveals the clash (the pre-AC-4 06-r1 path, here forced
    by a draft whose only told finding is the kind); turn 2 gets the clash and fixes it."""
    draft = _without_topic_resource(DRAFT)                # single finding: EDGE_CALLEE_UNSUPPORTED
    turn1 = ANSWER                                        # kind fixed; reveals ORDERS_TOPIC clash (a NEW finding)
    rep = _Repairs(turn1, FIXED)
    res = gate_service_topology(_plan(draft), product_id=PID, trace_id="t", repair_fn=rep)
    assert len(rep.prompts) == 2 and res.repaired is True
    _, d1 = _validate(turn1)
    assert rep.prompts[1] == build_repair_prompt(turn1, d1, CTX)
    ev = [e.model_dump() for e in res.repair_events]
    assert [(e["iteration"], e["accepted"], e["reject_reason"]) for e in ev] == [(1, True, None), (2, True, None)]
    assert ev[0]["fingerprints_after"] == ev[1]["fingerprints_before"]
    assert not set(ev[0]["fingerprints_before"]) & set(ev[0]["fingerprints_after"])


def test_bound_is_two_turns_even_with_progress_every_time():
    draft = _without_topic_resource(DRAFT)
    turn2 = copy.deepcopy(FIXED)
    turn2["resources"].append({"type": "google_storage_bucket", "logical_name": "media_bucket",   # new finding
                               "consumers": [{"service": "storefront", "env_key": "X_BUCKET"}]})
    rep = _Repairs(ANSWER, turn2, FIXED)
    assert MAX_REPAIR_TURNS == 2
    with pytest.raises(TopologyInvalidError) as ei:
        gate_service_topology(_plan(draft), product_id=PID, trace_id="t", repair_fn=rep)
    assert len(rep.prompts) == 2 and len(rep.answers) == 1          # never a third call
    d = ei.value.to_body()["details"]
    assert [e["iteration"] for e in d["repair_events"]] == [1, 2]
    assert d["repair_event"]["iteration"] == 2 and d["repair_event"]["reject_reason"] == "NO_PROGRESS"
    assert [x["code"] for x in ei.value.diagnostics] == ["TOPOLOGY.DUPLICATE_RESOURCE"]


def test_schema_invalid_or_failed_first_answer_gets_no_second_turn():
    draft = _without_topic_resource(DRAFT)
    bad = copy.deepcopy(ANSWER)
    bad["services"][0]["name"] = "Bad Name"                # schema error hides every other check
    for first in (bad, "null", "not json"):
        rep = _Repairs(first, FIXED)
        with pytest.raises(TopologyInvalidError):
            gate_service_topology(_plan(draft), product_id=PID, trace_id="t", repair_fn=rep)
        assert len(rep.prompts) == 1, first


def test_valid_first_pass_makes_zero_repair_calls():
    rep = _Repairs()
    res = gate_service_topology(_plan(FIXED), product_id=PID, trace_id="t", repair_fn=rep)
    assert rep.prompts == [] and res.repaired is False and res.repair_events == []


def test_fixed_every_finding_unit():
    assert fixed_every_finding(GOOD, ["a"], ["b"]) is True
    assert fixed_every_finding(GOOD, ["a", "b"], ["b"]) is False
    assert fixed_every_finding(None, ["a"], []) is False
    assert fixed_every_finding({"services": "x"}, ["a"], ["b"]) is False


# ------------------------------------------------------------------------------------------------ handler persistence
from test_architect_topology_gate import BASE, _Client, _DB, architect  # noqa: E402,F401  (fixture reused)


def test_handler_persists_one_event_per_turn(architect):
    h, agent = architect
    agent.project_id = "p"
    agent.db = _DB()
    draft = _without_topic_resource(DRAFT)
    plan = {**BASE, "target_compute_services": ["storefront", "factory-worker"], "service_topology": draft}
    agent.genai_client = _Client(plan, repairs=[ANSWER, FIXED])
    res = agent.decompose(spec_text="Build a shop", product_id=PID, trace_id="t-10")
    assert [c[0] for c in agent.genai_client.calls] == ["plan", "repair", "repair"]
    events = [w[2]["stages"]["architect"]["repair_events"] for w in agent.db.writes if "stages" in w[2]
              and "repair_events" in w[2]["stages"].get("architect", {})]
    assert len(events) == 1 and [e["iteration"] for e in events[0]] == [1, 2]
    assert res.compute_intent["topology_provenance"]["repaired"] is True


# ------------------------------------------------------------------------------------------------ eval strip tool
def test_strip_tool_drops_architect_repairs_only_on_request():
    from eval.tools.strip_repair_calls import ARCHITECT_REPAIR_SITE, strip
    recs = [{"type": "meta"},
            {"type": "call", "site": "architect_agent/handler.py:ArchitectAgent._single_turn_decompose"},
            {"type": "call", "site": ARCHITECT_REPAIR_SITE, "site_ordinal": 0}]
    lines = [json.dumps(r) for r in recs]
    assert strip(lines, 1) == lines
    assert strip(lines, 1, drop_architect_repairs=True) == lines[:2]


def test_strip_tool_refuses_keys_that_are_not_run_keys(tmp_path):
    """Opus RT F5: a key is a file stem; a path in --keys could write outside --out (even into the source)."""
    from eval.tools.strip_repair_calls import main, valid_key
    assert valid_key("06-r1") and valid_key("10-r12")
    for k in ("../06-r1", "06-r1/x", "6-r1", "06-r", "06-rx", "06_r1", "a6-r1", "06-r1.jsonl", "/tmp/06-r1", ""):
        assert not valid_key(k), k
    src = tmp_path / "src"
    src.mkdir()
    (src / "06-r1.jsonl").write_text('{"type": "meta"}\n')
    with pytest.raises(SystemExit, match="invalid run key"):
        main([str(src), "--out", str(tmp_path / "out"), "--keys", "06-r1,../src/06-r1", "--force"])
    assert not (tmp_path / "out").exists()
    assert main([str(src), "--out", str(tmp_path / "out"), "--keys", "06-r1"]) == 0
