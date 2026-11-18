"""QA-JUDGE-RETRY (owner 10-27): the Stage 2 judge's per-call deadline, the Stage 2 time limit and the typed,
bounded transport retry (the swarm repair call's R3c rule, shared via developer_agent.llm_transport)."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import (SHA_A, SHA_B, FakeBackend, FakeDB, FakeQAClient, backend_factory, judge_reply,
                          passing_outcome, sdk_response, seed_context)
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

pytest.importorskip("google.genai")

import qa_auditor.judge as judge_mod  # noqa: E402
from qa_auditor import DualLensAuditorCoordinator, LensUnavailableError, build_platform_facts  # noqa: E402


class _Status(Exception):
    """An SDK-shaped error: google.genai.errors.APIError carries the HTTP status as the int attribute `code`."""

    def __init__(self, code, message="provider said something"):
        super().__init__(message)
        self.code = code


class _Client:
    def __init__(self, failures, text=None):
        self.failures = list(failures)
        self.calls = 0
        self.models = self
        self.text = text or json.dumps({"passed": True, "critical_vulnerabilities": []})

    def generate_content(self, model, contents, config):
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)
        return sdk_response(self.text)   # JUDGE-LEVEL-FAMILY-CONFIG: typed parts + finish reason


def _call(client, *, deadline=None, now=0.0):
    # QA-JUDGE-FALLBACK (owner 11-13): these tests pin the QA-JUDGE-RETRY rule of a ONE-model chain (no fallback
    # models); the platform chain is covered by tests/test_qa_judge_fallback.py
    slept = []
    out = judge_mod.call("prompt", "m", client=client, deadline=deadline, sleep=slept.append, clock=lambda: now,
                         fallback_models=())
    return out, slept


# ------------------------------------------------------------------ constants
def test_per_call_deadline_is_120s_and_stage_two_fits_a_retry():
    import qa_auditor.coordinator as coord
    assert judge_mod.JUDGE_TIMEOUT_MS == 120_000 and judge_mod.JUDGE_TIMEOUT_S == 120.0
    assert coord.STAGE_TWO_DEADLINE_S == 300.0
    # one full call + the first backoff + a second full call fit in the Stage 2 limit
    assert judge_mod.JUDGE_TIMEOUT_S + judge_mod.RETRY_BACKOFF_S[0] + judge_mod.JUDGE_TIMEOUT_S <= coord.STAGE_TWO_DEADLINE_S


def test_rule_is_the_swarm_repair_rule():
    from developer_agent import llm_transport, swarm_dispatcher
    assert judge_mod.transient_status is llm_transport.transient_status
    assert judge_mod.RETRY_BACKOFF_S is llm_transport.RETRY_BACKOFF_S == (4.0, 16.0)
    assert swarm_dispatcher.REPAIR_TRANSIENT_STATUS is llm_transport.TRANSIENT_PROVIDER_STATUS
    assert swarm_dispatcher.REPAIR_RETRY_BACKOFF_S is llm_transport.RETRY_BACKOFF_S
    assert llm_transport.TRANSIENT_PROVIDER_STATUS == frozenset({429, 500, 503, 504})


def test_gateway_stage_two_budget_constants(monkeypatch):
    gw = fd4f_support.load_gateway(monkeypatch, "qa_retry_gw_consts")
    assert gw.STAGE_TWO_MARGIN_S == 30
    assert gw.STAGE_TWO_MIN_REMAINING_S == 150      # one full judge call + the margin
    assert gw.STAGE_TWO_DEADLINE_S == 300.0
    # the whole QA request stays inside the 1800 s Cloud Run / workflow http.post timeouts
    assert gw.QA_REQUEST_DEADLINE_S < 1800


# ------------------------------------------------------------------ retry (positive)
def test_504_then_success_gives_a_reply():
    c = _Client([_Status(504)])
    out, slept = _call(c)
    assert json.loads(out)["passed"] is True and c.calls == 2 and slept == [4.0]


@pytest.mark.parametrize("code", [429, 500, 503, 504])
def test_each_transient_status_is_retried(code):
    c = _Client([_Status(code), _Status(code)])
    out, slept = _call(c)
    assert c.calls == 3 and slept == [4.0, 16.0]


def test_three_failures_are_unavailable():
    c = _Client([_Status(504), _Status(504), _Status(504)])
    with pytest.raises(judge_mod.JudgeUnavailableError) as ei:
        _call(c)
    assert c.calls == 3 and "transport attempts: 3" in str(ei.value)


def test_three_504s_through_the_coordinator_are_lens_unavailable(monkeypatch):
    c = _Client([_Status(504)] * 10)
    monkeypatch.setattr(judge_mod, "_client", c)
    monkeypatch.setattr(judge_mod.time, "sleep", lambda s: None)
    with pytest.raises(LensUnavailableError):
        DualLensAuditorCoordinator(timeout_seconds=300.0).evaluate_stage_two(
            git_diff="+x", determ_report={"passed": True, "summary": "ok"}, task_dag=[{"task_id": "t"}],
            ingress_policy={}, model_name="m", platform_facts=build_platform_facts(None, "off", []))
    # QA-JUDGE-FALLBACK: per lens, each chain model once + the 2 backoff retries of the first model
    chain = judge_mod._model_chain("m", None)
    assert len(chain) >= 2 and c.calls <= 2 * (len(chain) + len(judge_mod.RETRY_BACKOFF_S))


# ------------------------------------------------------------------ no retry (negative)
@pytest.mark.parametrize("exc", [_Status(400), _Status(404), _Status(True),
                                 RuntimeError("504 DEADLINE_EXCEEDED (no status attribute)"),
                                 _Status("504")])
def test_non_transient_errors_are_not_retried(exc):
    c = _Client([exc])
    with pytest.raises(judge_mod.JudgeUnavailableError):
        _call(c)
    assert c.calls == 1


def test_exhausted_deadline_stops_further_retries():
    """JUDGE-FALLBACK-FLASH-ROOM: a backoff retry starts only when its time box (>= JUDGE_MIN_CALL_S, the deadline
    margin kept free) still fits after the backoff (was: a full 120 s call)."""
    need = judge_mod.RETRY_BACKOFF_S[0] + judge_mod.JUDGE_MIN_CALL_S + judge_mod.JUDGE_DEADLINE_MARGIN_S   # 64 s
    # 63 s left: the 4 s backoff + a 55 s box + the 5 s margin do not fit -> no retry
    c = _Client([_Status(504)])
    with pytest.raises(judge_mod.JudgeUnavailableError) as ei:
        _call(c, deadline=need - 1, now=0.0)
    assert c.calls == 1 and "no room for a backoff retry" in str(ei.value)
    # 64 s left: exactly fits -> one retry, time-boxed to 55 s
    seen = []

    class Boxes(_Client):
        def generate_content(self, model, contents, config):
            seen.append(config.http_options.timeout)
            return super().generate_content(model, contents, config)

    c = Boxes([_Status(504)])
    out, slept = _call(c, deadline=need, now=0.0)
    assert c.calls == 2 and slept == [4.0] and seen == [59_000, 55_000]


def test_no_room_for_the_first_call_asks_no_model():
    """JUDGE-FALLBACK-FLASH-ROOM: below one time box of room no call starts; typed, never a pass."""
    c = _Client([])
    with pytest.raises(judge_mod.JudgeUnavailableError) as ei:
        _call(c, deadline=judge_mod.JUDGE_MIN_CALL_S + judge_mod.JUDGE_DEADLINE_MARGIN_S - 1, now=0.0)
    assert c.calls == 0 and "transport attempts: 0" in str(ei.value) and "'m' not asked" in str(ei.value)


def test_second_retry_needs_its_own_room():
    """Realistic 504s: each failed call uses its whole time box. Stage 2 limit 300 s, one-model chain (no later model:
    every box is the full 120 s): call 1 ends at 120 s, retry 1 (4 s + 120 s) fits; call 2 ends at 244 s, retry 2
    (16 s + a 55 s box + the 5 s margin) does not -> 2 calls, unavailable."""
    t = {"now": 0.0}

    def sleep(s):
        t["now"] += s

    class SlowFail(_Client):
        def generate_content(self, model, contents, config):
            t["now"] += config.http_options.timeout / 1000.0   # the 504 comes at the request's own time box
            return super().generate_content(model, contents, config)

    c = SlowFail([_Status(504), _Status(504), _Status(504)])
    with pytest.raises(judge_mod.JudgeUnavailableError):
        judge_mod.call("p", "m", client=c, deadline=300.0, sleep=sleep, clock=lambda: t["now"], fallback_models=())
    assert c.calls == 2 and t["now"] == 244.0


def test_success_first_time_makes_one_call_and_no_sleep():
    c = _Client([])
    out, slept = _call(c, deadline=1000.0)
    assert c.calls == 1 and slept == []


def test_prompts_are_unchanged_by_the_retry(monkeypatch):
    """The retry is transport only: the request a lens sends is byte-identical with and without a deadline."""
    from qa_auditor.security_lens import evaluate_security_lens

    seen = []
    monkeypatch.setattr(judge_mod, "call", lambda p, m, **k: seen.append((p, k.get("response_schema"))) or
                        judge_reply()(p, m))
    monkeypatch.setattr(judge_mod.secrets, "token_hex", lambda n: "f" * (2 * n))
    evaluate_security_lens("+x", model_name="m")
    evaluate_security_lens("+x", model_name="m", deadline=123.0)
    assert seen[0] == seen[1]


# ------------------------------------------------------------------ run_qa: Stage 2 time limit
def test_run_qa_passes_the_stage_two_limit(monkeypatch):
    gw = fd4f_support.load_gateway(monkeypatch, "qa_retry_gw_limit")
    seen = {}

    class Coord(gw.DualLensAuditorCoordinator):
        def __init__(self, timeout_seconds):
            seen["timeout"] = timeout_seconds
            super().__init__(timeout_seconds)

    monkeypatch.setattr(gw, "DualLensAuditorCoordinator", Coord)
    monkeypatch.setattr(judge_mod, "call", judge_reply())
    db = FakeDB()
    seed_context(db)
    tree = {"apps/app/main.py": b"print('hi')\n"}
    backend = FakeBackend({"castor/app-1": tree, "main": {"README.md": b"x\n"}}, {"castor/app-1": SHA_A, "main": SHA_B})
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name="castor/app-1")
    out = gw.run_qa(req, client=FakeQAClient(passing_outcome()), source_backend_factory=backend_factory(backend),
                    evidence_db=db)
    assert out["passed"] is True
    assert seen["timeout"] == 300.0   # plenty of request budget left: the 300 s cap applies
