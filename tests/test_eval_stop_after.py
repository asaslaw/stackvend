"""Harness `--stop-after architect` (architect-compute-archetype record run): a run ends right after the architect
stage, so a live record makes only the architect (+ red-team) calls; nothing is generated or scored. Offline: no
child process is launched, the pipeline's stages are stand-ins, no LLM client exists."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

import run_examples  # noqa: E402
from stackvend_eval import stages as st  # noqa: E402
from stackvend_eval.state import RunState  # noqa: E402


def _args(tmp_path, *extra, llm="record"):
    argv = ["--llm", llm, "--model", "gemini-3.8-flash", "--examples", "01", "--runs", "1",
            "--out", str(tmp_path / "res"), "--out-id", "stop", "--accept-unverified-prices"]
    if llm in ("live", "record", "replay-then-live"):
        argv += ["--budget-usd", "5", "--run-cap", "1", "--vertex-project", "eval-test-project"]
    return run_examples.build_parser().parse_args(argv + list(extra))


def test_parser_accepts_only_known_stages(tmp_path):
    assert _args(tmp_path, "--stop-after", "architect").stop_after == "architect"
    assert _args(tmp_path).stop_after is None
    with pytest.raises(SystemExit):
        _args(tmp_path, "--stop-after", "developer")


def test_baseline_refuses_stop_after(tmp_path):
    inv = run_examples.Invocation(_args(tmp_path, "--stop-after", "architect", "--baseline"))
    with pytest.raises(SystemExit, match="stop-after"):
        inv.preflight()


def test_stop_after_skips_scoring(tmp_path, monkeypatch):
    launched = []
    real_run = run_examples.subprocess.run  # read-only repo calls (manifest head_sha / is_dirty) run for real
    monkeypatch.setattr(run_examples.subprocess, "run",
                        lambda cmd, **k: launched.append(cmd) if any(str(c).endswith("score_child.py") for c in cmd)
                        else real_run(cmd, **k))
    inv = run_examples.Invocation(_args(tmp_path, "--stop-after", "architect", llm="synthetic"))
    rd = inv.out / "runs" / "01-r1"
    rd.mkdir(parents=True)
    (rd / "result.json").write_text("{}")
    inv.score([{"key": "01-r1", "run_dir": str(rd), "result": {}}])
    assert launched == []
    assert inv.manifest([])["stop_after"] == "architect"


def _pipeline(stop_after, valid=True):
    state = RunState()
    if not valid:
        state.invalidate("test_non_fatal_reason", "test")  # invalid, but not fatal: the architect stage still runs
    pipe = st.Pipeline(state=state, mods={}, proxy=None, product_id="p", spec_text="spec", trace_id="t",
                       stop_after=stop_after)
    called = []
    pipe._architect = lambda: called.append("architect") or SimpleNamespace()
    pipe._compliance = lambda ares: called.append("compliance")
    pipe._developer = lambda ares, comp: called.append("developer") or {}
    return pipe, called


def test_pipeline_stops_after_the_architect():
    pipe, called = _pipeline("architect")
    pipe.run()
    assert called == ["architect"] and pipe.outcome == "stopped_after_architect"
    assert set(pipe.stages) == {"architect"} and pipe.stages["architect"]["ok"] is True


def test_pipeline_stop_after_keeps_an_invalid_run_invalid():
    pipe, called = _pipeline("architect", valid=False)
    pipe.run()
    assert called == ["architect"] and pipe.outcome == "invalid"


def test_pipeline_without_stop_after_continues_past_the_architect():
    pipe, called = _pipeline(None)
    pipe.run()
    assert called[:3] == ["architect", "compliance", "developer"]


def test_generate_hands_the_architect_compute_record_to_the_developer():
    """RT M12: the harness hands the architect's typed compute record to generate_code_files (production reads the
    same record from pipeline_executions/{trace}); dropping it would make every replay a platform-default run."""
    seen = {}

    class Dev:
        def generate_code_files(self, **kw):
            seen.update(kw)
            return {"infra/workload/main.tf": "", "binary": b"x"}

    record = {"schema": "architect_compute_intent/v1", "target_compute_services": ["stream-processor"],
              "bundle_id": "private-gke-microservices", "compute_archetype": "gke-autopilot"}
    ares = SimpleNamespace(compute_intent=record, plan_markdown="", plan_file_path="")
    comp = SimpleNamespace(plan_markdown=None, plan_file_path=None, domain_restricted_sharing=None,
                           allowed_domains=None, allow_unauthenticated=None, enable_direct_iap=None)
    pipe = SimpleNamespace(product_id="test-04", spec_text="spec", trace_id="eval-04-r1", proxy=SimpleNamespace(),
                           checkpoints={}, stages={"developer": {}})
    files = st.Pipeline._generate(pipe, Dev(), ares, comp, [], lambda v, d: d if v is None else v)
    assert seen["architect_compute_intent"] is record and seen["trace_id"] == "eval-04-r1"
    assert files == {"infra/workload/main.tf": ""}
