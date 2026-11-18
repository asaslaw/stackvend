"""FD-4F DL-1..DL-4 + review H6: Stage 2 has one verdict source (the judge) and a real deadline."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import time

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import judge_reply

import qa_auditor.judge as judge_mod
from qa_auditor import DualLensAuditorCoordinator, LensUnavailableError
from qa_auditor.adherence_lens import evaluate_adherence_lens
from qa_auditor.platform_facts import build_platform_facts
from qa_auditor.security_lens import evaluate_security_lens
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

DETERM = {"passed": True, "summary": "ok"}
# Review E13: a least-privilege diff that the deleted keyword heuristic flagged as 2x CRITICAL.
E13_DIFF = (
    "+# do NOT grant roles/editor here\n"
    "+engine = create_engine(DB_URL)  # cloud sql\n"
    "+resource \"google_compute_firewall\" \"egress\" { direction = \"EGRESS\" destination_ranges = [\"0.0.0.0/0\"] }\n"
)


def _run(**kw):
    return DualLensAuditorCoordinator(timeout_seconds=kw.pop("timeout", 5.0)).evaluate_stage_two(
        git_diff=kw.pop("diff", "+x"), determ_report=kw.pop("determ", DETERM), task_dag=[{"task_id": "t"}],
        ingress_policy={"allow_unauthenticated": True}, model_name="m",
        platform_facts=kw.pop("platform_facts", build_platform_facts(None, "off", [])), **kw)


def test_negative_judge_pass_composes_pass(monkeypatch):
    monkeypatch.setattr(judge_mod, "call", judge_reply())
    _, _, comp = _run()
    assert comp.passed is True and comp.blocking_reasons == []


def test_negative_heuristic_no_longer_vetoes_e13_diff(monkeypatch):
    monkeypatch.setattr(judge_mod, "call", judge_reply())
    sec, _, comp = _run(diff=E13_DIFF)
    assert sec.passed is True and comp.passed is True


def test_judge_unavailable_raises_not_heuristic(monkeypatch):
    def boom(prompt, model, **kw):
        raise judge_mod.JudgeUnavailableError("down")

    monkeypatch.setattr(judge_mod, "call", boom)
    with pytest.raises(LensUnavailableError):
        _run()


def test_slow_lens_bounded_by_deadline(monkeypatch):
    def slow(prompt, model, **kw):
        time.sleep(3)
        return judge_reply()(prompt, model)

    monkeypatch.setattr(judge_mod, "call", slow)
    t0 = time.monotonic()
    with pytest.raises(LensUnavailableError):
        _run(timeout=0.2)
    assert time.monotonic() - t0 < 1.0


@pytest.mark.parametrize("reply", [
    "not json",
    json.dumps({"grounding_score": 1.0, "missed_directives": []}),                 # missing adherence score
    json.dumps({"instruction_adherence_score": 1.0, "missed_directives": []}),     # missing grounding score
    json.dumps({"instruction_adherence_score": 1.5, "grounding_score": 1.0, "missed_directives": []}),
    json.dumps({"instruction_adherence_score": True, "grounding_score": 1.0, "missed_directives": []}),
    json.dumps({"instruction_adherence_score": 1.0, "grounding_score": 1.0}),       # missing missed_directives
])
def test_adherence_incomplete_reply_is_unavailable(monkeypatch, reply):
    monkeypatch.setattr(judge_mod, "call", lambda p, m, **k: reply)
    with pytest.raises(LensUnavailableError):
        evaluate_adherence_lens(git_diff="+x", task_dag=[], model_name="m")


@pytest.mark.parametrize("reply", [
    json.dumps({"critical_vulnerabilities": []}),                 # no passed
    json.dumps({"passed": "yes", "critical_vulnerabilities": []}),
    json.dumps({"passed": True}),                                 # no critical_vulnerabilities
    json.dumps([1, 2]),
])
def test_security_incomplete_reply_is_unavailable(monkeypatch, reply):
    monkeypatch.setattr(judge_mod, "call", lambda p, m, **k: reply)
    with pytest.raises(LensUnavailableError):
        evaluate_security_lens(git_diff="+x", model_name="m")


def test_security_passed_true_with_criticals_fails(monkeypatch):
    monkeypatch.setattr(judge_mod, "call", judge_reply(sec_passed=True, crit=["leak"]))
    assert evaluate_security_lens(git_diff="+x", model_name="m").passed is False


def test_fenced_reply_parses(monkeypatch):
    monkeypatch.setattr(judge_mod, "call", lambda p, m, **k: "```json\n" + judge_reply()(p, m) + "\n```")
    assert evaluate_security_lens(git_diff="+x", model_name="m").passed is True


def test_missing_deterministic_report_raises(monkeypatch):
    monkeypatch.setattr(judge_mod, "call", judge_reply())
    with pytest.raises(LensUnavailableError):
        _run(determ=None)


def test_judge_client_is_vertex_global_with_timeout(monkeypatch):
    seen = {}

    class FakeClient:
        def __init__(self, **kw):
            seen.update(kw)

    import google.genai as genai

    monkeypatch.setattr(genai, "Client", FakeClient)
    monkeypatch.setattr(judge_mod, "_client", None)
    monkeypatch.setenv("PROJECT_ID", "p1")
    monkeypatch.delenv("GEMINI_LOCATION", raising=False)
    judge_mod._get_client()
    assert seen["vertexai"] is True and seen["project"] == "p1" and seen["location"] == "global"
    assert seen["http_options"].timeout == judge_mod.JUDGE_TIMEOUT_MS
    monkeypatch.setattr(judge_mod, "_client", None)


def test_judge_without_project_is_unavailable(monkeypatch):
    monkeypatch.setattr(judge_mod, "_client", None)
    monkeypatch.delenv("PROJECT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    with pytest.raises(judge_mod.JudgeUnavailableError):
        judge_mod.call("p", "m")


def test_judge_empty_response_is_unavailable():
    from fd4f_support import sdk_response

    class C:
        class models:
            @staticmethod
            def generate_content(**kw):
                return sdk_response("  ")

    with pytest.raises(judge_mod.JudgeUnavailableError):
        judge_mod.call("p", "m", client=C())


def test_no_verdict_path_imports_the_heuristics():
    import inspect

    import qa_auditor.adherence_lens as a
    import qa_auditor.coordinator as c
    import qa_auditor.security_lens as s

    for mod, name in ((s, "_deterministic_security_heuristic"), (a, "_deterministic_adherence_heuristic")):
        src = inspect.getsource(mod.evaluate_security_lens if mod is s else mod.evaluate_adherence_lens)
        assert name not in src
    assert "_deterministic_" not in inspect.getsource(c)
