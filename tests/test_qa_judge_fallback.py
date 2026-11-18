"""QA-JUDGE-FALLBACK (owner 11-13): the Stage 2 judge degrades down the platform's model fallback chain.

Live defect (11-13, four runs in QA at once, Vertex location global answering 504/429 under load): two runs failed
GATE_UNAVAILABLE "adherence lens: judge call failed (transport attempts: 2): ServerError: 504 DEADLINE_EXCEEDED" while
the architect / developer / swarm agents degrade down Settings > models.fallback_models. Here: on a typed transient
transport error (`transient_status`, never the message) the judge asks the next chain model at once when its time box
can start before the Stage 2 deadline (JUDGE-FALLBACK-FLASH-ROOM, owner 11-16: each attempt is time-boxed so a later
model always keeps room); the chain exhausted, no room left, or a non-transient error is still GATE_UNAVAILABLE,
naming every model tried. The lens result records the model that answered. Do No Harm: a primary that answers first
is the pre-11-13 call exactly (one call, same model, same request content, the same 120 s timeout -- now sent per
request --, same result apart from the new default fields) and reads no settings. Fake clients only: no network, no
LLM, no Firestore."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib
import json
import logging

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import sdk_response
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse)

pytest.importorskip("google.genai")

import qa_auditor.judge as judge_mod  # noqa: E402
from qa_auditor import LensUnavailableError  # noqa: E402
from qa_auditor.adherence_lens import evaluate_adherence_lens  # noqa: E402
from qa_auditor.security_lens import evaluate_security_lens  # noqa: E402
from qa_auditor.platform_facts import build_platform_facts  # noqa: E402

settings_mod = importlib.import_module("shared.settings")   # the module the product's `from shared.settings` gets

CARBON, ARGON, FLASH38, FLASH37 = "gemini-4-carbon", "gemini-4-argon", "gemini-3.8-flash", "gemini-3.7-flash"
CHAIN = (ARGON, FLASH38, FLASH37)
SEC_OK = json.dumps({"passed": True, "critical_vulnerabilities": [], "summary": "ok"})
ADH_OK = json.dumps({"instruction_adherence_score": 1.0, "grounding_score": 1.0, "missed_directives": [],
                     "hallucinated_features": [], "summary": "ok"})


class _Status(Exception):
    """SDK-shaped error: google.genai.errors.APIError carries the HTTP status as the int attribute `code`."""

    def __init__(self, code, message="provider said something"):
        super().__init__(message)
        self.code = code


class _Client:
    """`script` maps a model id to its queued outcomes (an exception to raise, or reply text); a model with nothing
    queued answers `default`. Records (model, config) of every request."""

    def __init__(self, script=None, default=SEC_OK):
        self.script = {m: list(v) for m, v in (script or {}).items()}
        self.default = default
        self.requests = []
        self.models = self

    @property
    def calls(self):
        return len(self.requests)

    @property
    def asked(self):
        return [m for m, _ in self.requests]

    def generate_content(self, model, contents, config):
        self.requests.append((model, config))
        queue = self.script.get(model) or []
        item = queue.pop(0) if queue else self.default
        if isinstance(item, BaseException):
            raise item
        return sdk_response(item)


def _call(client, *, fallback_models=CHAIN, deadline=None, now=0.0, model=CARBON, validate=None):
    slept = []
    out = judge_mod.call("prompt", model, client=client, deadline=deadline, sleep=slept.append, clock=lambda: now,
                         fallback_models=fallback_models, validate=validate)
    return out, slept


@pytest.fixture()
def no_settings_read(monkeypatch):
    """Fails the test if the judge resolves the platform chain."""
    def boom(*a, **k):
        raise AssertionError("the platform fallback chain was resolved")
    monkeypatch.setattr(judge_mod, "platform_fallback_models", boom)


# ------------------------------------------------------------------ Do No Harm (negative)
def test_primary_answers_first_one_call_same_config_no_settings_read(no_settings_read):
    c = _Client()
    slept = []
    out = judge_mod.call("prompt", CARBON, client=c, sleep=slept.append)
    assert out == SEC_OK and c.asked == [CARBON] and slept == []
    # JUDGE-FALLBACK-FLASH-ROOM: the request carries its own time box, the full 120 s the client sent before
    assert c.requests[0][1] == judge_mod.with_time_box(
        judge_mod.judge_config(CARBON, judge_mod.JUDGE_MAX_OUTPUT_TOKENS, None), int(judge_mod.JUDGE_TIMEOUT_S))
    assert isinstance(out, judge_mod.JudgeReply) and out.model == CARBON and out.fallback is False
    assert out.fallback_outcomes == ()
    assert judge_mod.judge_stamp(out, CARBON) == {"eval_judge_model": CARBON}


@pytest.mark.parametrize("lens", ["security", "adherence"])
def test_primary_answer_lens_result_is_the_pre_change_result(monkeypatch, no_settings_read, lens):
    """The real call with the primary answering gives exactly the result a plain-str judge (the pre-11-13 return type)
    gives, and the new fields hold their defaults."""
    monkeypatch.setattr(judge_mod.secrets, "token_hex", lambda n: "f" * (2 * n))
    text = SEC_OK if lens == "security" else ADH_OK

    def run():
        if lens == "security":
            return evaluate_security_lens("+x", model_name=CARBON)
        return evaluate_adherence_lens("+x", task_dag=[{"task_id": "t"}], model_name=CARBON)

    c = _Client(default=text)
    monkeypatch.setattr(judge_mod, "_client", c)
    real = run().model_dump()
    assert c.asked == [CARBON]
    monkeypatch.setattr(judge_mod, "call", lambda p, m, **k: text)
    assert real == run().model_dump()
    assert real["eval_judge_model"] == CARBON and real["eval_judge_fallback"] is False
    assert real["eval_judge_primary_model"] is None and real["eval_judge_fallback_outcomes"] == []


# ------------------------------------------------------------------ fallback (positive)
def test_primary_504_argon_answers_and_is_stamped_as_fallback(caplog):
    c = _Client({CARBON: [_Status(504)]})
    with caplog.at_level(logging.WARNING, logger="castor-qa-judge"):
        out, slept = _call(c)
    assert json.loads(out)["passed"] is True
    assert c.asked == [CARBON, ARGON] and slept == []          # the next model at once, no backoff
    assert out.model == ARGON and out.primary_model == CARBON and out.fallback is True
    assert out.fallback_outcomes == (f"{CARBON}: HTTP 504",)
    assert judge_mod.judge_stamp(out, CARBON) == {
        "eval_judge_model": ARGON, "eval_judge_fallback": True, "eval_judge_primary_model": CARBON,
        "eval_judge_fallback_outcomes": [f"{CARBON}: HTTP 504"]}
    warn = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(f"verdict from '{ARGON}' instead of the evaluation model '{CARBON}'" in m and "HTTP 504" in m
               for m in warn)


def test_429_then_flash_answers():
    c = _Client({CARBON: [_Status(429)], ARGON: [_Status(429)]})
    out, slept = _call(c)
    assert c.asked == [CARBON, ARGON, FLASH38] and slept == [] and out.model == FLASH38
    assert out.fallback_outcomes == (f"{CARBON}: HTTP 429", f"{ARGON}: HTTP 429")


def test_fallback_is_stamped_on_both_lens_results(monkeypatch):
    for lens, text in (("security", SEC_OK), ("adherence", ADH_OK)):
        c = _Client({CARBON: [_Status(504)]}, default=text)
        monkeypatch.setattr(judge_mod, "_client", c)
        monkeypatch.setattr(judge_mod, "platform_fallback_models", lambda model, project_id=None: CHAIN)
        res = (evaluate_security_lens("+x", model_name=CARBON) if lens == "security"
               else evaluate_adherence_lens("+x", task_dag=[{"task_id": "t"}], model_name=CARBON))
        d = res.model_dump()
        assert d["passed"] is True and d["eval_judge_model"] == ARGON and d["eval_judge_fallback"] is True
        assert d["eval_judge_primary_model"] == CARBON and d["eval_judge_fallback_outcomes"] == [f"{CARBON}: HTTP 504"]


def test_whole_chain_transient_is_unavailable_naming_every_model():
    c = _Client({m: [_Status(504)] * 5 for m in (CARBON, *CHAIN)})
    with pytest.raises(judge_mod.JudgeUnavailableError) as ei:
        _call(c)
    # each chain model once, then the two QA-JUDGE-RETRY backoff retries of the first model
    assert c.asked == [CARBON, ARGON, FLASH38, FLASH37, CARBON, CARBON]
    msg = str(ei.value)
    assert "transport attempts: 6" in msg
    for m in (CARBON, ARGON, FLASH38, FLASH37):
        assert f"{m}: HTTP 504" in msg


def test_whole_chain_transient_through_the_lens_is_lens_unavailable(monkeypatch):
    c = _Client({m: [_Status(503)] * 5 for m in (CARBON, *CHAIN)})
    monkeypatch.setattr(judge_mod, "_client", c)
    monkeypatch.setattr(judge_mod.time, "sleep", lambda s: None)
    monkeypatch.setattr(judge_mod, "platform_fallback_models", lambda model, project_id=None: CHAIN)
    with pytest.raises(LensUnavailableError) as ei:
        evaluate_security_lens("+x", model_name=CARBON)
    assert str(ei.value).startswith("security lens: judge call failed") and f"{FLASH37}: HTTP 503" in str(ei.value)


def test_backoff_retry_of_the_first_model_after_the_walk_can_answer():
    c = _Client({CARBON: [_Status(504)], ARGON: [_Status(504)], FLASH38: [_Status(504)], FLASH37: [_Status(504)]})
    out, slept = _call(c)
    assert c.asked == [CARBON, ARGON, FLASH38, FLASH37, CARBON] and slept == [4.0]
    assert out.model == CARBON and out.fallback is False


# ------------------------------------------------------------------ deadline
FLOOR = judge_mod.JUDGE_MIN_CALL_S + judge_mod.JUDGE_DEADLINE_MARGIN_S   # the room one time box needs (60 s)


class _Timed(_Client):
    """A client on a fake clock: a scripted error costs the request's whole time box (a Vertex 504 at the
    X-Server-Timeout the box sends; the live 504s came at 116.8-118.0 s of a 120 s box), or `error_cost` seconds when
    set; an answer costs `answer_s`. Records each request's time box (s) and its end time."""

    def __init__(self, script=None, default=SEC_OK, answer_s=20.0, error_cost=None):
        super().__init__(script, default)
        self.now, self.answer_s, self.error_cost = 0.0, answer_s, error_cost
        self.boxes, self.ends = [], []

    def generate_content(self, model, contents, config):
        box = config.http_options.timeout / 1000.0
        self.boxes.append(box)
        queue = self.script.get(model) or []
        failing = bool(queue) and isinstance(queue[0], BaseException)
        self.now += (box if self.error_cost is None else self.error_cost) if failing else self.answer_s
        self.ends.append(self.now)
        return super().generate_content(model, contents, config)

    def run(self, deadline, **kw):
        kw.setdefault("fallback_models", CHAIN)
        return judge_mod.call("p", CARBON, client=self, deadline=deadline, sleep=lambda s: None,
                              clock=lambda: self.now, **kw)


def test_deadline_too_short_for_the_next_model_stops_and_raises():
    """The primary's 504 after 10 s leaves less than one time box: the next model is not asked (typed, named)."""
    c = _Timed({CARBON: [_Status(504)]}, error_cost=10.0)
    with pytest.raises(judge_mod.JudgeUnavailableError) as ei:
        c.run(10.0 + FLOOR - 1)
    assert c.asked == [CARBON]
    msg = str(ei.value)
    assert f"{CARBON}: HTTP 504" in msg and "not tried (no room for one more call" in msg
    assert ARGON in msg and FLASH37 in msg


def test_deadline_exactly_one_time_box_moves_on():
    c = _Timed({CARBON: [_Status(504)]}, error_cost=10.0)
    out = c.run(10.0 + FLOOR)
    assert c.asked == [CARBON, ARGON] and out.model == ARGON
    assert c.boxes == [10.0 + FLOOR - judge_mod.JUDGE_DEADLINE_MARGIN_S, judge_mod.JUDGE_MIN_CALL_S]


# ------------------------------------------------------------------ JUDGE-FALLBACK-FLASH-ROOM (owner 11-16)
def test_live_1116_both_pro_models_time_out_flash_judges():
    """ex01-1116 (security lens): gemini-4-carbon 504 at its bound, gemini-4-argon 504 at its bound; before the fix the
    two 120 s calls used 240 s of the 300 s Stage 2 budget and the Flash models were 'not tried'. Now, with the real
    Stage 2 limit and the platform chain: carbon keeps its full 120 s, argon is time-boxed to half of the room left
    (87 s), and gemini-3.8-flash gets the rest (88 s) and gives the verdict, stamped as a fallback."""
    import qa_auditor.coordinator as coord

    c = _Timed({CARBON: [_Status(504)], ARGON: [_Status(504)]})
    out = c.run(coord.STAGE_TWO_DEADLINE_S, fallback_models=None)     # the platform chain from the settings defaults
    assert judge_mod._model_chain(CARBON, None) == [CARBON, ARGON, FLASH38, FLASH37]
    assert c.asked == [CARBON, ARGON, FLASH38] and c.boxes == [120.0, 87.0, 88.0]
    assert out.model == FLASH38 and out.fallback is True and json.loads(out)["passed"] is True
    assert out.fallback_outcomes == (f"{CARBON}: HTTP 504", f"{ARGON}: HTTP 504")
    assert judge_mod.judge_stamp(out, CARBON) == {
        "eval_judge_model": FLASH38, "eval_judge_fallback": True, "eval_judge_primary_model": CARBON,
        "eval_judge_fallback_outcomes": [f"{CARBON}: HTTP 504", f"{ARGON}: HTTP 504"]}
    assert max(c.ends) <= coord.STAGE_TWO_DEADLINE_S - judge_mod.JUDGE_DEADLINE_MARGIN_S


def test_primary_answers_fast_under_the_stage_two_deadline_is_unchanged(no_settings_read):
    """Do No Harm: with the full Stage 2 budget the evaluation model is asked once, with the full 120 s box (the same
    X-Server-Timeout as before), and no settings are read; the reply is not a fallback."""
    import qa_auditor.coordinator as coord

    c = _Timed(answer_s=8.0)
    out = c.run(coord.STAGE_TWO_DEADLINE_S, fallback_models=None)
    assert c.asked == [CARBON] and c.boxes == [judge_mod.JUDGE_TIMEOUT_S] and out == SEC_OK
    assert out.fallback is False and judge_mod.judge_stamp(out, CARBON) == {"eval_judge_model": CARBON}
    assert c.requests[0][1].http_options.timeout == judge_mod.JUDGE_TIMEOUT_MS


def test_whole_chain_timed_out_is_unavailable_naming_every_model():
    """Every model 504s at its bound: carbon, argon and gemini-3.8-flash are asked, gemini-3.7-flash has no room left
    (named as not tried), no backoff retry fits; never a pass."""
    import qa_auditor.coordinator as coord

    c = _Timed({m: [_Status(504)] * 3 for m in (CARBON, *CHAIN)})
    with pytest.raises(judge_mod.JudgeUnavailableError) as ei:
        c.run(coord.STAGE_TWO_DEADLINE_S)
    assert c.asked == [CARBON, ARGON, FLASH38] and c.boxes == [120.0, 87.0, 88.0]
    msg = str(ei.value)
    assert "transport attempts: 3" in msg and "not tried (no room for one more call" in msg and FLASH37 in msg
    for m in (CARBON, ARGON, FLASH38):
        assert f"{m}: HTTP 504" in msg
    assert max(c.ends) <= coord.STAGE_TWO_DEADLINE_S - judge_mod.JUDGE_DEADLINE_MARGIN_S


def test_a_client_side_timeout_at_the_time_box_walks_like_a_504():
    """The HTTP client's own typed timeout (httpx.TimeoutException) at the box moves to the next model, recorded as
    "<model>: TIMEOUT"; the evaluation model's other non-transient errors still raise at once (tests below)."""
    httpx = pytest.importorskip("httpx")
    c = _Client({CARBON: [httpx.ReadTimeout("timed out")]})
    out, slept = _call(c)
    assert c.asked == [CARBON, ARGON] and slept == [] and out.model == ARGON
    assert out.fallback_outcomes == (f"{CARBON}: TIMEOUT",)


@pytest.mark.parametrize("budget", range(115, 301))
@pytest.mark.parametrize("chain_len", [1, 2, 3, 4])
def test_time_boxes_keep_room_for_the_next_model(budget, chain_len):
    """Every Stage 2 budget run_qa can start (STAGE_TWO_MIN_REMAINING_S - STAGE_TWO_MARGIN_S = 120 s .. 300 s, from
    115 s for the time spent before the judge starts), worst case (every attempt fails at its whole box): every box is
    55..120 s, every call ends before the deadline margin, a second model is asked when the chain has one for every
    budget >= 115 s (the 5 s margin + two 55 s boxes; below it one model, typed GATE_UNAVAILABLE on failure), and a
    third (with the platform defaults the first Flash model) for every budget >= 225 s, so always at the 300 s
    limit."""
    models = [CARBON, *CHAIN][:chain_len]
    c = _Timed({m: [_Status(504)] * 3 for m in models})
    with pytest.raises(judge_mod.JudgeUnavailableError):
        c.run(float(budget), fallback_models=tuple(models[1:]))
    assert all(judge_mod.JUDGE_MIN_CALL_S <= b <= judge_mod.JUDGE_TIMEOUT_S for b in c.boxes), c.boxes
    assert max(c.ends) <= budget - judge_mod.JUDGE_DEADLINE_MARGIN_S
    assert c.asked[:min(chain_len, 2)] == models[:min(chain_len, 2)]
    if chain_len >= 3 and budget >= 225:
        assert c.asked[:3] == models[:3]
    if chain_len == 1:
        assert c.boxes[0] == min(judge_mod.JUDGE_TIMEOUT_S, budget - judge_mod.JUDGE_DEADLINE_MARGIN_S) // 1


def test_stage_two_minimum_holds_two_time_boxes(monkeypatch):
    """The floor is derived from the smallest Stage 2 budget run_qa starts (120 s before its setup time): it holds two
    boxes and the margin (the owner's 'leave room for one more model')."""
    gw = fd4f_support.load_gateway(monkeypatch, "flash_room_gw_consts")
    smallest = gw.STAGE_TWO_MIN_REMAINING_S - gw.STAGE_TWO_MARGIN_S
    assert smallest == 120
    assert (smallest - judge_mod.JUDGE_DEADLINE_MARGIN_S) / 2 >= judge_mod.JUDGE_MIN_CALL_S


def test_attempt_timeout_rule():
    t = judge_mod.attempt_timeout_s

    def never():
        raise AssertionError("the chain was consulted")

    assert t(None, never) == 120                               # no deadline: the old per-call value
    assert t(300.0, never) == 120 and t(245.0, never) == 120   # half the room >= the cap: the chain is not read
    assert t(180.0, lambda: True) == 87                        # a later model: half of the room (175 / 2)
    assert t(180.0, lambda: False) == 120                      # the last model: the room, capped
    assert t(93.0, lambda: True) == 88                         # too little room for two boxes: this one is the last
    assert t(60.0, lambda: True) == 55 and t(59.9, lambda: True) is None and t(-5.0, lambda: False) is None


def test_a_settings_read_for_the_chain_is_deducted_from_the_box(monkeypatch):
    """RT F3: when the time box needs the chain (room / 2 below the cap) and resolving it reads the settings, the
    room is read again after the read: a 10 s read at 200 s of room gives a 92 s box (185 / 2), not 97 s."""
    c = _Timed()

    def slow_chain(model, project_id=None):
        c.now += 10.0
        return CHAIN

    monkeypatch.setattr(judge_mod, "platform_fallback_models", slow_chain)
    assert c.run(200.0, fallback_models=None) == SEC_OK
    assert c.asked == [CARBON] and c.boxes == [92.0]


@pytest.mark.parametrize("primary_cost_s", [0.5, None])   # a fast 504, and one that uses the whole call deadline
def test_real_stage_two_budget_a_primary_504_reaches_argon(primary_cost_s):
    """The real numbers: Stage 2 limit STAGE_TWO_DEADLINE_S (300 s), per-call deadline JUDGE_TIMEOUT_S (120 s), the
    platform chain from the settings defaults. A 504 from the primary -- even one that took the full 120 s -- leaves
    >= 120 s, so the judge asks gemini-4-argon at once (no same-model backoff in between) and it gives the verdict."""
    import qa_auditor.coordinator as coord

    cost = judge_mod.JUDGE_TIMEOUT_S if primary_cost_s is None else primary_cost_s
    t = {"now": 0.0}

    class Timed(_Client):
        def generate_content(self, model, contents, config):
            t["now"] += cost if model == CARBON else 30.0
            return super().generate_content(model, contents, config)

    assert coord.STAGE_TWO_DEADLINE_S - judge_mod.JUDGE_TIMEOUT_S >= judge_mod.JUDGE_TIMEOUT_S
    c = Timed({CARBON: [_Status(504)]})
    slept = []
    out = judge_mod.call("p", CARBON, client=c, deadline=coord.STAGE_TWO_DEADLINE_S, sleep=slept.append,
                         clock=lambda: t["now"])        # fallback_models=None: the platform chain
    assert judge_mod._model_chain(CARBON, None)[1] == ARGON
    assert c.asked == [CARBON, ARGON] and slept == [] and out.model == ARGON and out.fallback is True
    assert t["now"] <= coord.STAGE_TWO_DEADLINE_S


# ------------------------------------------------------------------ no fallback (negative)
@pytest.mark.parametrize("exc", [_Status(400), _Status(403), _Status(404), _Status(True), _Status("504"),
                                 RuntimeError("504 DEADLINE_EXCEEDED (no status attribute)")])
def test_non_transient_error_raises_without_fallback(no_settings_read, exc):
    c = _Client({CARBON: [exc]})
    with pytest.raises(judge_mod.JudgeUnavailableError) as ei:
        judge_mod.call("p", CARBON, client=c, sleep=lambda s: None)
    assert c.asked == [CARBON] and "transport attempts: 1" in str(ei.value)


def test_a_fallback_with_a_non_transient_error_is_skipped_and_the_next_answers():
    """RT F1: a dead fallback (a retired id's 404) no longer ends the call; it is skipped and recorded (typed)."""
    c = _Client({CARBON: [_Status(504)], ARGON: [_Status(404)]})
    out, slept = _call(c)
    assert c.asked == [CARBON, ARGON, FLASH38] and slept == [] and out.model == FLASH38 and out.fallback is True
    assert out.fallback_outcomes == (f"{CARBON}: HTTP 504", f"{ARGON}: _Status (not transient)")
    stamp = judge_mod.judge_stamp(out, CARBON)
    assert stamp["eval_judge_model"] == FLASH38 and stamp["eval_judge_fallback_outcomes"] == list(out.fallback_outcomes)


def test_every_fallback_dead_then_the_primary_backoff_retry_answers():
    c = _Client({CARBON: [_Status(504)], ARGON: [_Status(404)], FLASH38: [_Status(404)], FLASH37: [_Status(400)]})
    out, slept = _call(c)
    assert c.asked == [CARBON, ARGON, FLASH38, FLASH37, CARBON] and slept == [4.0]
    assert out.model == CARBON and out.fallback is False


def test_every_model_failing_mixed_is_unavailable_naming_each_model():
    c = _Client({CARBON: [_Status(504)] * 3, ARGON: [_Status(404)], FLASH38: [_Status(429)], FLASH37: [_Status(404)]})
    with pytest.raises(judge_mod.JudgeUnavailableError) as ei:
        _call(c)
    assert c.asked == [CARBON, ARGON, FLASH38, FLASH37, CARBON, CARBON]
    msg = str(ei.value)
    for part in (f"{CARBON}: HTTP 504", f"{ARGON}: _Status (not transient)", f"{FLASH38}: HTTP 429",
                 f"{FLASH37}: _Status (not transient)"):
        assert part in msg


def test_primary_non_transient_after_the_walk_still_raises():
    """The backoff retry asks the evaluation model again: its non-transient error raises, never a pass."""
    c = _Client({CARBON: [_Status(504), _Status(403)], ARGON: [_Status(404)], FLASH38: [_Status(404)],
                 FLASH37: [_Status(404)]})
    with pytest.raises(judge_mod.JudgeUnavailableError) as ei:
        _call(c)
    assert c.asked == [CARBON, ARGON, FLASH38, FLASH37, CARBON] and "transport attempts: 5" in str(ei.value)


def test_a_fallback_without_a_request_config_is_skipped(monkeypatch):
    real = judge_mod.judge_config

    def config(model, *a, **k):
        if model == ARGON:
            raise ValueError("no family rules")
        return real(model, *a, **k)

    monkeypatch.setattr(judge_mod, "judge_config", config)
    c = _Client({CARBON: [_Status(503)]})
    out, _ = _call(c)
    assert c.asked == [CARBON, FLASH38] and out.model == FLASH38
    assert out.fallback_outcomes == (f"{CARBON}: HTTP 503", f"{ARGON}: ValueError (request config)")


def test_a_blocked_answer_never_falls_back():
    c = _Client({CARBON: [_Status(504)]})
    c.script[ARGON] = []

    def blocked(model, contents, config):
        c.requests.append((model, config))
        if model == CARBON:
            raise _Status(504)
        return sdk_response(SEC_OK, finish="SAFETY")

    c.generate_content = blocked
    with pytest.raises(judge_mod.JudgeReplyError) as ei:
        _call(c)
    assert ei.value.reason == judge_mod.REPLY_BLOCKED and c.asked == [CARBON, ARGON]


# ------------------------------------------------------------------ re-ask + per-model config
def test_reask_stays_on_the_model_that_answered():
    def validate(text):
        if text == "nope":
            raise LensUnavailableError("security lens: judge reply is not JSON")

    c = _Client({CARBON: [_Status(504)], ARGON: ["nope", SEC_OK]})
    out, _ = _call(c, validate=validate)
    assert c.asked == [CARBON, ARGON, ARGON] and out.model == ARGON


def test_config_is_rebuilt_per_model():
    c = _Client({CARBON: [_Status(504)], ARGON: [_Status(429)]})
    _call(c)
    assert c.asked == [CARBON, ARGON, FLASH38]
    for model, config in c.requests:
        assert config == judge_mod.with_time_box(
            judge_mod.judge_config(model, judge_mod.JUDGE_MAX_OUTPUT_TOKENS, None), int(judge_mod.JUDGE_TIMEOUT_S))
    # the Gemini 4 level family and the 3.x budget family get different requests
    assert c.requests[0][1] != c.requests[2][1]


# ------------------------------------------------------------------ chain resolution
def test_chain_is_deduped_primary_first():
    assert judge_mod._model_chain(CARBON, (ARGON, CARBON, ARGON, "", FLASH38)) == [CARBON, ARGON, FLASH38]
    assert judge_mod._model_chain(CARBON, ()) == [CARBON]


def test_chain_follows_the_stored_fallback_models(monkeypatch):
    s = settings_mod.PlatformSettings()
    s.models.fallback_models = [FLASH37, ARGON, CARBON]
    monkeypatch.setattr(settings_mod, "_SETTINGS_CACHE", s)
    expected = tuple(m for m in settings_mod.get_model_cascade_for_agent("architect")[1:] if m != CARBON)
    assert judge_mod.platform_fallback_models(CARBON) == expected == (FLASH37, ARGON)
    c = _Client({CARBON: [_Status(504)], FLASH37: [_Status(504)]})
    out, _ = _call(c, fallback_models=None)
    assert c.asked == [CARBON, FLASH37, ARGON] and out.model == ARGON


def test_settings_unreadable_uses_the_agents_default_cascade(monkeypatch):
    def unreadable(*a, **k):
        raise settings_mod.PlatformSettingsReadError("settings unreadable")

    monkeypatch.setattr(settings_mod, "get_platform_settings", unreadable)
    agents = settings_mod.get_model_cascade_for_agent("architect")
    assert agents[1:] == [m for m in settings_mod.DEFAULT_FALLBACK_MODELS if m != agents[0]]
    assert judge_mod.platform_fallback_models(CARBON) == tuple(m for m in agents[1:] if m != CARBON)


def test_chain_resolution_error_keeps_the_one_model_rule(monkeypatch):
    def broken(model, project_id=None):
        raise RuntimeError("no settings module")

    monkeypatch.setattr(judge_mod, "platform_fallback_models", broken)
    c = _Client({CARBON: [_Status(504), _Status(504), _Status(504)]})
    with pytest.raises(judge_mod.JudgeUnavailableError):
        _call(c, fallback_models=None)
    assert c.asked == [CARBON, CARBON, CARBON]   # QA-JUDGE-RETRY: 1 call + 2 backoff retries, never a pass


# ------------------------------------------------------------------ RT F2: visible in the composite summary
SEC_MARK = "Security Engineer"   # the security lens prompt's role line


class _LensClient:
    """Answers each lens by its prompt; `fail` = the (lens, model) pairs that answer 504."""

    def __init__(self, fail=()):
        self.fail = set(fail)
        self.models = self

    def generate_content(self, model, contents, config):
        lens = "security" if SEC_MARK in contents else "adherence"
        if (lens, model) in self.fail:
            raise _Status(504)
        return sdk_response(SEC_OK if lens == "security" else ADH_OK)


def _stage_two(monkeypatch, client):
    from qa_auditor import DualLensAuditorCoordinator
    monkeypatch.setattr(judge_mod, "_client", client)
    monkeypatch.setattr(judge_mod, "platform_fallback_models", lambda model, project_id=None: CHAIN)
    monkeypatch.setattr(judge_mod.secrets, "token_hex", lambda n: "f" * (2 * n))
    return DualLensAuditorCoordinator(timeout_seconds=300.0).evaluate_stage_two(
        "+x", determ_report={"passed": True, "summary": "ok"}, task_dag=[{"task_id": "t"}],
        ingress_policy={}, model_name=CARBON, platform_facts=build_platform_facts(None, "off", [{"task_id": "t"}]))


def test_a_fallback_verdict_is_named_in_the_composite_summary(monkeypatch):
    sec, adh, comp = _stage_two(monkeypatch, _LensClient(fail={("security", CARBON)}))
    assert comp.passed is True and sec.eval_judge_fallback is True and adh.eval_judge_fallback is False
    assert comp.summary.endswith(f" Reviewed by a fallback model: security lens by {ARGON} ({CARBON} unavailable: "
                                 f"{CARBON}: HTTP 504).")
    assert comp.model_dump()["summary"] == comp.summary     # the text every consumer of the composite gets


def test_both_lenses_on_fallbacks_are_both_named(monkeypatch):
    fail = {("security", CARBON), ("adherence", CARBON), ("adherence", ARGON)}
    _, _, comp = _stage_two(monkeypatch, _LensClient(fail=fail))
    expected = (f"Reviewed by a fallback model: security lens by {ARGON} ({CARBON} unavailable: {CARBON}: HTTP 504); "
                f"adherence lens by {FLASH38} ({CARBON} unavailable: {CARBON}: HTTP 504, {ARGON}: HTTP 504).")
    assert expected in comp.summary


def test_live_1116_through_the_coordinator_both_lenses_get_a_verdict(monkeypatch):
    """JUDGE-FALLBACK-FLASH-ROOM, the whole Stage 2 (both lenses in parallel under one deadline, the real coordinator,
    one virtual clock per lens thread): the security lens loses carbon and argon to 504s at their bounds, the
    adherence lens loses carbon; both lenses still get a verdict, each stamped, inside the Stage 2 limit."""
    import threading

    import qa_auditor.coordinator as coord

    local = threading.local()

    class Clock:
        """time.monotonic / time.sleep per thread (a lens thread starts at 0); everything else the real module."""
        @staticmethod
        def monotonic():
            return getattr(local, "t", 0.0)

        @staticmethod
        def sleep(s):
            local.t = getattr(local, "t", 0.0) + s

    ends = []

    class Lens(_LensClient):
        def generate_content(self, model, contents, config):
            lens = "security" if SEC_MARK in contents else "adherence"
            local.t = getattr(local, "t", 0.0) + (config.http_options.timeout / 1000.0 if (lens, model) in self.fail
                                                  else 20.0)
            ends.append(local.t)
            return super().generate_content(model, contents, config)

    def fresh(fn):
        """Each lens starts its own clock at 0 (a pool thread can be reused for the second lens)."""
        def run(*a, **k):
            local.t = 0.0
            return fn(*a, **k)
        return run

    monkeypatch.setattr(judge_mod, "time", Clock)
    monkeypatch.setattr(coord, "time", Clock)
    for name in ("evaluate_security_lens", "evaluate_adherence_lens"):
        monkeypatch.setattr(coord, name, fresh(getattr(coord, name)))
    sec, adh, comp = _stage_two(monkeypatch, Lens(fail={("security", CARBON), ("security", ARGON),
                                                        ("adherence", CARBON)}))
    assert comp.passed is True
    assert sec.eval_judge_model == FLASH38 and sec.eval_judge_fallback is True
    assert sec.eval_judge_fallback_outcomes == [f"{CARBON}: HTTP 504", f"{ARGON}: HTTP 504"]
    assert adh.eval_judge_model == ARGON and adh.eval_judge_fallback is True
    assert f"security lens by {FLASH38}" in comp.summary and f"adherence lens by {ARGON}" in comp.summary
    assert max(ends) <= coord.STAGE_TWO_DEADLINE_S - judge_mod.JUDGE_DEADLINE_MARGIN_S


def test_no_fallback_summary_is_unchanged(monkeypatch):
    """Do No Harm: the primary answering both lenses gives the pre-change summary exactly."""
    from qa_auditor import coordinator as coord_mod
    _, _, comp = _stage_two(monkeypatch, _LensClient())
    assert "fallback" not in comp.summary
    assert coord_mod._with_fallback_note("s", object(), object()) == "s"
    monkeypatch.setattr(judge_mod, "call", lambda p, m, **k: SEC_OK if SEC_MARK in p else ADH_OK)
    _, _, plain = _stage_two(monkeypatch, _LensClient())
    assert plain.summary == comp.summary


def test_judge_reply_survives_copy_deepcopy_and_pickle():
    """RT F3: the reply keeps its text and its model fields through copy, deepcopy and pickle."""
    import copy
    import pickle
    r = judge_mod.JudgeReply(SEC_OK, model=ARGON, primary_model=CARBON, fallback_outcomes=[f"{CARBON}: HTTP 504"])
    for dup in (copy.copy(r), copy.deepcopy(r), pickle.loads(pickle.dumps(r))):
        assert isinstance(dup, judge_mod.JudgeReply) and dup == SEC_OK
        assert (dup.model, dup.primary_model, dup.fallback_outcomes) == (ARGON, CARBON, (f"{CARBON}: HTTP 504",))
        assert dup.fallback is True and judge_mod.judge_stamp(dup, CARBON) == judge_mod.judge_stamp(r, CARBON)



# ------------------------------------------------------------------ RT D1: the release certificate names a fallback
def _certificate(monkeypatch, sec, adh, note=None):
    import release_gatekeeper as rg
    from shared.qa_audit_schemas import ReleaseGateDecision
    if note is not None:
        monkeypatch.setattr(rg, "_fallback_judge_note", note)
    decision = ReleaseGateDecision(is_approved=True, requires_human_intervention=False,
                                   recommended_action="AUTO_MERGE", certified_at="2026-11-14T00:00:00Z")
    return rg.generate_release_certificate(decision, product_id="app", branch_name="castor/app-1",
                                           commit_sha="a" * 40, determ_dict={"tests_passed": 3},
                                           sec_dict=sec, adh_dict=adh)


def _records(sec_fallback=False, adh_fallback=False):
    def rec(fallback, **extra):
        r = {"passed": True, "eval_judge_model": CARBON, "eval_judge_fallback": False,
             "eval_judge_primary_model": None, "eval_judge_fallback_outcomes": [], **extra}
        if fallback:
            r.update(eval_judge_model=FLASH38, eval_judge_fallback=True, eval_judge_primary_model=CARBON,
                     eval_judge_fallback_outcomes=[f"{CARBON}: HTTP 504", f"{ARGON}: HTTP 429"])
        return r
    return (rec(sec_fallback, critical_vulnerabilities=[]),
            rec(adh_fallback, missed_directives=[], instruction_adherence_score=1.0, grounding_score=1.0))


def test_certificate_names_a_fallback_judge_on_its_lens_row(monkeypatch):
    cert = _certificate(monkeypatch, *_records(sec_fallback=True))
    sec_row = next(line for line in cert.splitlines() if line.startswith("| **Security & Ingress Lens**"))
    adh_row = next(line for line in cert.splitlines() if line.startswith("| **Task DAG Adherence Lens**"))
    assert f"reviewed by fallback model `{FLASH38}` (`{CARBON}` unavailable)" in sec_row
    assert "fallback" not in adh_row
    cert = _certificate(monkeypatch, *_records(adh_fallback=True))
    adh_row = next(line for line in cert.splitlines() if line.startswith("| **Task DAG Adherence Lens**"))
    assert adh_row.endswith(f"missed directives); reviewed by fallback model `{FLASH38}` (`{CARBON}` unavailable) |")


@pytest.mark.parametrize("records", [_records(), ({}, {}),
                                     ({"eval_judge_fallback": "true"}, {"eval_judge_fallback": 1})])
def test_no_fallback_certificate_is_byte_identical(monkeypatch, records):
    """Do No Harm: without a typed fallback the certificate is the pre-D1 text exactly (the row suffix is the only
    change, so the certificate with the helper stubbed to "" is the old rendering)."""
    sec, adh = records
    new = _certificate(monkeypatch, dict(sec), dict(adh))
    assert "fallback" not in new
    old = _certificate(monkeypatch, dict(sec), dict(adh), note=lambda info: "")
    assert new == old
