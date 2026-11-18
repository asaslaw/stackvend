"""FD-30 harness end to end, OFFLINE: the real pipeline runs in guarded child processes against the synthetic
backend (schema-valid responses built from the product's own fallbacks) and recorded cassettes. No LLM, no
network, no credentials. Each run is a subprocess, so no guard or product import touches the pytest process."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import functools
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "eval"
sys.path.insert(0, str(EVAL))


@functools.lru_cache(maxsize=1)
def _missing_product_deps():
    from stackvend_eval import paths
    rep = paths.probe_child_deps(ROOT, env=hermetic_guard.child_env())
    return paths.missing_deps_message(rep, ROOT) if rep["missing"] else ""


def _require_product_deps():
    """The child cannot run the product without its Step 1 requirements. tests/test_eval_product_deps.py is the one
    test that FAILS for that (by name); the runs here skip instead of failing as unrelated generation_errors."""
    msg = _missing_product_deps()
    if msg:
        pytest.skip(f"see the failing tests/test_eval_product_deps.py: {msg}")


# FD-55 W0 / FD-4CR (row FD55-W0): healers deleted ON PURPOSE are no longer pinned here one by one. Each is listed in
# the reviewed eval/config/healer_deletions.json with the commit that deleted it (history of the old _EXPECTED_ABSENT /
# _EXPECTED_ANCHOR_LOST sets: lane 8, lane 13, lane 17, lane 19, Step 1/2a, S2-B, FD-4R, FD-4P/FD-4BB, FD-4AA, FD-4AD,
# CC-MI; 58 fragments at W0). metrics.coverage takes them out of the denominator (coverage over LIVE fragments), so a
# recorded deletion keeps coverage and needs no edit here. What IS pinned exactly is every live fragment the probe
# cannot measure: an unrecorded deletion (absent or anchor_lost, not listed) joins this set and fails the gate.
_EXPECTED_UNMEASURED = {
    # FD-4AK: the settings floor migrations moved (range starts at `if doc.exists:`, now in the typed read) and gained
    # type guards (RT R3); the code is still there, NOT deleted, so it is not retired (anchor lost, unmeasured)
    "HB-45@apps/orchestrator-gateway/shared/settings.py:PlatformSettings.__init__:420-433",
    "HB-45@apps/orchestrator-gateway/shared/settings.py:get_platform_settings:495-504",
    # unresolved at the inventory SHA (not a function / line range the probe can bind)
    "HD-12@apps/orchestrator-gateway/architect_agent/red_team_critic.py:CANONICAL_GOLDEN_MODULES:53-79",
    "HD-33@apps/orchestrator-gateway/shared/cooldown_manager.py:is_transient_error:43-67",
}
_EXPECTED_ANCHOR_LOST = {k for k in _EXPECTED_UNMEASURED if k.startswith("HB-45@")}
_EXPECTED_FRAGMENTS = 149   # generation-path fragments in eval/config/healer_targets.json (changes only on a rebuild)


def _harness(tmp_path, out_id, *args, expect_rc=0):
    _require_product_deps()
    cmd = [sys.executable, str(EVAL / "run_examples.py"), "--examples", "01", "--runs", "1",
           "--model", "gemini-3.8-flash", "--out", str(tmp_path / "res"), "--out-id", out_id, *args]
    env = hermetic_guard.child_env(
        drop=tuple(k for k in os.environ if k.startswith(("GOOGLE_", "CLOUDSDK")) or k == "STACKVEND_EVAL_VERTEX_PROJECT"),
        extra={"GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/adc-disabled.json"})
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=900)
    assert r.returncode == expect_rc, r.stdout[-3000:] + r.stderr[-3000:]
    return r


def _result(tmp_path, out_id):
    return json.loads((tmp_path / "res" / out_id / "runs" / "01-r1" / "result.json").read_text())


@pytest.fixture(scope="module")
def recorded(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("e2e")
    _harness(tmp, "syn", "--llm", "synthetic", "--cassettes", str(tmp / "cas"), "--skip-score")
    return tmp


def test_synthetic_run_goes_through_every_stage(recorded):
    r = _result(recorded, "syn")
    assert r["valid_run"] is True and r["pipeline_outcome"] == "committed_passed", r.get("invalid_reasons")
    assert r["canary"]["ok"] is True
    assert set(r["checkpoints"]) >= {"C0_raw_swarm", "C2_generated", "C3_committed"}
    assert r["stages"]["precommit"]["capture_point"] == "commit_and_open_pr:fetch_github_token"
    assert r["stages"]["precommit"]["status"] == "MOCK_COMMITTED"
    assert r["stages"]["developer"]["path"] == "swarm"
    assert r["llm"]["calls"] >= 5 and r["llm"]["served"]["backend"] == r["llm"]["calls"]
    assert 0 < r["budget"]["settled_usd"] <= r["budget"]["cap_usd"]
    assert r["model"] == "gemini-3.8-flash" and r["pinned_settings"]["models"]["developer_model"] == "gemini-3.8-flash"
    # only the known, swallowed product paths hit the guard after the canary
    kinds = {(e["kind"], json.dumps(e["detail"], sort_keys=True)) for e in r["state"]["events"]
             if e["stage"] not in ("canary", "guard", "setup")}
    calls = {json.loads(d).get("call") or json.loads(d).get("host") for k, d in kinds if k.endswith("_blocked")}
    assert calls <= {"google.cloud.aiplatform.initializer._Config.init",
                     "google.cloud.firestore_v1.base_client.BaseClient.__init__", "127.0.0.1"}, calls
    tg = r["healers"]["targets"]
    # FD-55 waves delete probed healers on purpose (each listed in eval/config/healer_deletions.json), so the number of
    # bound targets falls with them: W1 deleted 15 never-called bodies and W5 deleted HB-01, the HB-29 verifier twin and
    # the HB-27 / HB-33 preflight copies (~35 bound after both); W6b deleted the gateway-copy bodies of HC-14, HE-01,
    # HB-24 and HA-13 x2 (27 bound), the W6b + W6c merge the HA-17 locals pair x2 (25 bound). The floor stays a sanity check that the probe binds the live healers at all.
    assert sum(1 for t in tg if t.get("bindings")) > 20
    assert sum(1 for t in tg if t.get("reached")) > 3   # 5 after FD-55 W5 (the deleted preflight twins were reached)
    assert (recorded / "cas" / "01-r1.jsonl").exists()


def test_replay_is_deterministic_and_healers_off_gives_c1(recorded):
    _harness(recorded, "rep", "--llm", "replay-strict", "--cassettes", str(recorded / "cas"), "--skip-score")
    _harness(recorded, "off", "--llm", "replay-strict", "--healers-off", "--cassettes", str(recorded / "cas"),
             "--skip-score")
    syn, rep, off = _result(recorded, "syn"), _result(recorded, "rep"), _result(recorded, "off")
    assert rep["llm"]["served"]["replay"] == syn["llm"]["calls"] and rep["llm"]["usd"] == 0.0
    for ck in ("C0_raw_swarm", "C2_generated", "C3_committed"):
        assert rep["checkpoints"][ck]["tree"] == syn["checkpoints"][ck]["tree"], ck
    assert "C1_healers_off" in off["checkpoints"] and "C2_generated" not in off["checkpoints"]
    assert off["checkpoints"]["C0_raw_swarm"]["tree"] == syn["checkpoints"]["C0_raw_swarm"]["tree"]
    assert off["healers"]["events"] == []
    assert any(t.get("healers_off") == "bypassed" for t in off["healers"]["targets"])


def test_no_llm_client_trips_the_fallback_tripwire(tmp_path):
    _harness(tmp_path, "trip", "--llm", "synthetic", "--no-llm-client", "--skip-score")
    r = _result(tmp_path, "trip")
    assert r["valid_run"] is False and "fallback_tripwire" in r["invalid_reasons"]
    assert r["pipeline_outcome"] == "invalid"


def test_run_cap_stops_spend_and_invalidates(tmp_path):
    _harness(tmp_path, "cap", "--llm", "synthetic", "--run-cap", "0.15", "--skip-score")
    r = _result(tmp_path, "cap")
    assert "budget_exceeded" in r["invalid_reasons"] and r["valid_run"] is False
    assert r["budget"]["settled_usd"] <= 0.15 + 1e-9
    assert r["budget"]["calls_refused"] >= 1


def test_scoring_child_writes_scores_and_summary(recorded):
    _harness(recorded, "scored", "--llm", "replay-strict", "--cassettes", str(recorded / "cas"))
    out = recorded / "res" / "scored"
    s = json.loads((out / "runs" / "01-r1" / "score.json").read_text())
    assert "error" not in s, s.get("error")
    assert s["checkpoints"]["C3_committed"]["python"]["py_files"] > 0
    assert not [e for e in s["scoring_guard_events"] if e["kind"] == "egress_blocked"]
    summary = json.loads((out / "summary.json").read_text())
    assert summary["overall"]["valid_runs"] == 1
    cov = summary["coverage"]
    # FD-55 W0 / FD-4CR: coverage_pct is measured / LIVE fragments (inventory minus the retired list). The retired set
    # is exactly the reviewed list (every listed healer is really gone at this product root); no absence is
    # unrecorded; every live fragment is measured except the pinned _EXPECTED_UNMEASURED set.
    # Floor history: 85 -> 80 (compliance integration) -> 75 (EVAL-COV-75, owner 10-19), each forced by deletions on
    # purpose counting as unmeasured; W0: 87 / 91 = 95.6 % over live fragments, floor back above 90.
    from stackvend_eval.targets import load_retired_healers
    retired = load_retired_healers(EVAL / "config" / "healer_deletions.json")
    assert set(cov["retired"]) == set(retired), cov
    assert cov["absent_unrecorded"] == [], cov
    assert set(cov["unmeasured"]) == _EXPECTED_UNMEASURED, cov
    assert set(cov["anchor_lost"]) == _EXPECTED_ANCHOR_LOST, cov
    assert cov["generation_path_fragments"] == _EXPECTED_FRAGMENTS, cov
    assert cov["live_fragments"] == _EXPECTED_FRAGMENTS - len(retired), cov
    assert cov["fragments_measured"] == cov["live_fragments"] - len(_EXPECTED_UNMEASURED), cov
    assert cov["coverage_pct"] > 90, cov
    # health invariant unchanged: > 90 % of what is still there (neither absent nor anchor_lost) is measured
    still_there = cov["generation_path_fragments"] - len(cov["absent"]) - len(cov["anchor_lost"])
    assert still_there > 0 and 100.0 * cov["fragments_measured"] / still_there > 90, cov
    assert (out / "SCOREBOARD.md").read_text().startswith("# StackVend eval scoreboard")
    # python-hcl2 is a product requirement (the _harness gate above); the scoring child (same `python -I`) has it too
    assert "invariants" in s["checkpoints"]["C3_committed"]


@pytest.mark.parametrize("args,msg", [
    (["--llm", "record"], "--budget-usd is required"),
    (["--llm", "record", "--budget-usd", "30"], "exceeds the $25.0 ceiling"),
    (["--llm", "record", "--budget-usd", "2"], "STACKVEND_EVAL_VERTEX_PROJECT"),
    (["--llm", "record", "--budget-usd", "2", "--vertex-project", "p"], "not owner-verified"),
    (["--llm", "synthetic", "--healers-off"], "replayed LLM output only"),
    (["--llm", "synthetic", "--baseline"], "--baseline refuses"),
])
def test_preflight_refuses_unsafe_invocations_before_any_spend(args, msg):
    import run_examples
    with pytest.raises(SystemExit) as e:
        a = run_examples.build_parser().parse_args(["--model", "gemini-3.8-flash", *args])
        a.vertex_project = a.vertex_project if "--vertex-project" in args else None
        run_examples.Invocation(a).preflight()
    assert msg in str(e.value)


def test_preflight_refuses_unknown_model():
    import run_examples
    from stackvend_eval.errors import EvalUnpricedModel
    a = run_examples.build_parser().parse_args(["--model", "gemini-9.9-ultra", "--llm", "synthetic"])
    with pytest.raises(EvalUnpricedModel):
        run_examples.Invocation(a).preflight()
