"""validate-ready-wait (live incident 10-27): the schema-slice parity wait of the typed-intent developer stage.

The terraform server answers /validate/ready `ready: true` as soon as `hashicorp/google` is in its provider mirror,
while its warm-up thread is still fetching google-beta / kubernetes / random. Two workloads failed with
`GATE.IAC_SCHEMA_PARITY: hashicorp/google-beta 6.35.0 not served by validate (has [])` one probe after ready turned
true. The developer stage now keeps polling /validate/ready (typed `ready` + `provider_versions` only, never the
reason text) until every slice provider version is served, inside the one `validate_ready_wait_s` budget. Mode off is
unchanged (ready alone). Virtual clock, no network, no LLM."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys
from unittest.mock import patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

import test_typed_iac_ti3_contract as ti3  # noqa: E402
from developer_agent import hallucination_runtime as hr  # noqa: E402
from shared.diagnostics import ErrorClass, StageError  # noqa: E402
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

SLICE = dict(ti3.ART.manifest["provider_schema"]["providers"])   # {"hashicorp/google": "6.35.0", ...}
LOCAL = ["google", "google-beta", "kubernetes", "random"]


def answer(ready, versions, reason=""):
    return {"ready": ready, "providers": sorted(p.split("/", 1)[1] for p in versions), "engine": "OPENTOFU",
            "engine_version": "1.9.0", "provider_versions": {k: list(v) for k, v in versions.items()},
            "reason": reason}


NOT_READY = answer(False, {}, "provider mirror not populated (google missing)")
# exactly the incident: google mirrored (both pins), google-beta not yet
GOOGLE_ONLY = answer(True, {"hashicorp/google": ["5.44.0", "6.35.0"]})
FULL = answer(True, {k: [v] for k, v in SLICE.items()})


@pytest.fixture()
def clock():
    state = {"now": 0.0, "sleeps": []}

    def sleep(s):
        assert s > 0
        state["sleeps"].append(s)
        state["now"] += s
    with patch.object(hr, "_sleep", sleep), patch.object(hr, "_clock", lambda: state["now"]):
        yield state


def scripted(script):
    """A ti3 end-to-end Client whose ready() answers from `script` (the last entry repeats)."""
    class Scripted(ti3.Client):
        probes = 0

        def ready(self, iac_engine="OPENTOFU"):
            type(self).probes += 1
            item = script[min(type(self).probes - 1, len(script) - 1)]
            if isinstance(item, BaseException):
                raise item
            return item
    return Scripted


def run(mode, script, **settings):
    """generate_code_files end to end (fake lead / swarm, no LLM). Returns (files | StageError, agent, client cls)."""
    cls = scripted(script)
    draft = dict(ti3.APP, **{ti3.C.INTENT_PATH: ti3.intent([ti3.BUCKET_MODULE])})
    att = {p: ("IAC_ENGINEER" if p == ti3.C.INTENT_PATH else "BACKEND_ENGINEER") for p in draft}
    out = []
    with patch.object(ti3, "Client", cls):
        try:
            files, agent, _client, seen = ti3._generate(mode, draft, att, agent_out=out, **settings)
        except StageError as e:
            return e, out[0], cls, None
    return files, agent, cls, seen


# ------------------------------------------------------------------------------------------------ helper (accept)
def test_accept_keeps_polling_a_ready_answer_until_it_holds(clock):
    seq = iter([NOT_READY, GOOGLE_ONLY, GOOGLE_ONLY, FULL])

    class C:
        n = 0

        def ready(self, iac_engine):
            C.n += 1
            return next(seq)
    got, probes, waited = hr.wait_for_validate_ready(C(), "OPENTOFU", 180,
                                                     accept=lambda a: "hashicorp/google-beta" in a["provider_versions"])
    assert got is FULL and probes == C.n == 4 and clock["sleeps"] == [2, 4, 8] and waited == 14


def test_accept_that_raises_is_not_accepted_and_times_out(clock):
    class C:
        def ready(self, iac_engine):
            return FULL

    def boom(a):
        raise KeyError("x")
    got, probes, waited = hr.wait_for_validate_ready(C(), "OPENTOFU", 5, accept=boom)
    assert got is FULL and probes == 3 and waited == 5          # last answer returned; the caller re-checks it
    got, probes, _ = hr.wait_for_validate_ready(C(), "OPENTOFU", 5, accept=lambda a: 1)   # truthy non-True: no
    assert probes == 3


def test_accept_is_never_consulted_on_a_not_ready_answer(clock):
    seen = []

    class C:
        def ready(self, iac_engine):
            return NOT_READY
    hr.wait_for_validate_ready(C(), "OPENTOFU", 0, accept=lambda a: seen.append(a) or True)
    assert seen == []


# ------------------------------------------------------------------------------------------------ intent mode
def test_cold_to_warm_incident_sequence_passes_the_parity_gate(clock):
    """The 10-27 incident: not ready -> ready with google only -> full mirror. The run reaches generation."""
    files, agent, cls, seen = run("generate", [NOT_READY, GOOGLE_ONLY, GOOGLE_ONLY, FULL])
    assert not isinstance(files, StageError), files
    assert cls.probes == 4 and clock["sleeps"] == [2, 2]   # gate: 1 pause; parity wait: probe at once, then 1 pause
    assert seen["iac_intent"] is not None and agent.last_validation_report.status == "PASS"


def test_parity_never_met_is_gate_unavailable_after_the_budget_before_any_llm_call(clock):
    err, _agent, cls, _ = run("generate", [GOOGLE_ONLY])
    assert isinstance(err, StageError) and err.error_class is ErrorClass.GATE_UNAVAILABLE
    assert err.report.tools_unavailable == ["iac_intent_artifacts"]
    msg = str(err)
    assert "GATE.IAC_SCHEMA_PARITY" in msg and "hashicorp/google-beta 6.35.0" in msg
    assert "waited 180s more" in msg and "readiness limit 180s" in msg
    assert sum(clock["sleeps"]) == 180 and cls.probes == 11   # 1 gate probe + 10 parity probes (0..180 s)


def test_one_budget_covers_the_gate_wait_and_the_parity_wait(clock):
    err, _agent, cls, _ = run("generate", [NOT_READY] * 5 + [GOOGLE_ONLY])
    assert isinstance(err, StageError) and err.error_class is ErrorClass.GATE_UNAVAILABLE
    assert sum(clock["sleeps"]) == 180     # 60 s in the gate wait + 120 s parity wait, never more than the limit
    assert cls.probes == 6 + 8   # gate: 0, 2, 6, 14, 30, 60 s; parity: 60, 62, 66, 74, 90, 120, 150, 180 s
    err, _agent, _cls, _ = run("generate", [GOOGLE_ONLY], validate_ready_wait_s=0)
    assert isinstance(err, StageError) and "waited 0s more over 1 probe(s)" in str(err)


def test_server_turning_unready_during_the_parity_wait_names_it(clock):
    err, _agent, _cls, _ = run("generate", [GOOGLE_ONLY, NOT_READY], validate_ready_wait_s=30)
    assert isinstance(err, StageError) and err.error_class is ErrorClass.GATE_UNAVAILABLE
    assert "IAC_SCHEMA_PARITY" in str(err) and "then not ready" in str(err)


def test_warm_server_is_exactly_one_probe_and_no_pause(clock):
    """Do No Harm: parity on the gate's answer costs nothing more (one /validate/ready call, no sleep)."""
    files, _agent, cls, seen = run("generate", [FULL])
    assert not isinstance(files, StageError) and cls.probes == 1 and clock["sleeps"] == []
    assert seen["iac_intent"] is not None


def test_parity_wait_hands_the_fresh_answer_to_the_rest_of_the_run(clock):
    agent = ti3._agent(ti3._runtime(scripted([FULL])()))
    gate = {"providers": ["google"], "provider_versions": GOOGLE_ONLY["provider_versions"], "ready_waited_s": 0.0}
    from shared.iac_intent import IntentGateUnavailable, check_ready_parity
    agent._await_schema_parity(agent.stack_runtime(), ti3.ART, gate, check_ready_parity, IntentGateUnavailable,
                               lambda tool, why: AssertionError(why))
    assert gate["provider_versions"] == FULL["provider_versions"] and gate["providers"] == LOCAL


# ------------------------------------------------------------------------------------------------ mode off
def test_mode_off_needs_ready_only_and_never_waits_for_parity(clock):
    """Pinned: mode off proceeds as soon as /validate/ready is true (google mirrored), with no parity probe. V1b
    validates later, after generation; the mirror finishes seconds after ready turns true (see the report)."""
    files, agent, cls, seen = run("off", [NOT_READY, GOOGLE_ONLY])
    assert not isinstance(files, StageError), files
    assert cls.probes == 2 and clock["sleeps"] == [2] and seen["iac_intent"] is None
    assert agent.last_validation_report.status == "PASS"


def test_mode_off_never_ready_is_still_the_v1b_gate_unavailable(clock):
    err, _agent, cls, _ = run("off", [NOT_READY])
    assert isinstance(err, StageError) and err.error_class is ErrorClass.GATE_UNAVAILABLE
    assert err.report.tools_unavailable == ["V1b"] and sum(clock["sleeps"]) == 180 and cls.probes == 10


def test_default_budget_is_still_180_s():
    assert HallucinationStackSettings().validate_ready_wait_s == 180
