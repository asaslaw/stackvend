"""F9 replay provenance (wave2 step1 code red-team): replays send the RECORDED spec, not the checkout's docs, and
every run reports how its LLM calls were served. Offline: fake backend / fake Popen only, read-only git; no child
process is launched, no network, no credentials."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

import run_examples  # noqa: E402
from stackvend_eval import gitutil, metrics, scoreboard  # noqa: E402
from stackvend_eval.budget import Budget, Price, PriceTable  # noqa: E402
from stackvend_eval.cassettes import Cassette, normalize_request, request_hash  # noqa: E402
from stackvend_eval.errors import EvalReplayMiss  # noqa: E402
from stackvend_eval.llm_proxy import LLMProxy  # noqa: E402
from stackvend_eval.state import RunState  # noqa: E402

PRICES = PriceTable({"m": Price("m", 1.0, 10.0, 0.5, 5.0, True, 65536)})
HERE = str(Path(__file__).resolve().parent)
PINS = json.loads((ROOT / "eval/config/cassette_spec_pins.json").read_text())["pins"]
PIN = PINS[0]
CATALOG = json.loads((ROOT / "eval/config/examples.json").read_text())["examples"]
_REAL_POPEN = run_examples.subprocess.Popen


def _ex(eid):
    return next(e for e in CATALOG if e["id"] == eid)


# OSS blocker 1a: the legacy pins name a commit of the private history; a fresh single-commit public history (or a
# shallow clone) does not have it, and only pre-F9 private cassettes ever need it.
needs_pin_commit = pytest.mark.skipif(not gitutil.has_commit(ROOT, PIN["examples_sha"]),
                                      reason=f"legacy spec-pin commit {PIN['examples_sha'][:12]} {gitutil.NOT_IN_CLONE}")


class _NoChild:
    launched = []

    def __init__(self, cmd, **kwargs):
        _NoChild.launched.append(cmd)
        self.stdin = self
        self.returncode = -9

    def write(self, s):
        pass

    def close(self):
        pass

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


def _fake_popen(cmd, **kwargs):
    is_child = isinstance(cmd, (list, tuple)) and any(str(c).endswith("run_child.py") for c in cmd)
    return _NoChild(cmd, **kwargs) if is_child else _REAL_POPEN(cmd, **kwargs)


def _replay_inv(tmp_path, meta, *extra, example="04"):
    cas = tmp_path / "cas"
    cas.mkdir()
    (cas / f"{example}-r1.jsonl").write_text(json.dumps({"type": "meta", "example": example, "run": 1, **meta}) + "\n")
    argv = ["--llm", "replay-strict", "--model", "gemini-3.8-flash", "--examples", example, "--runs", "1",
            "--cassettes", str(cas), "--out", str(tmp_path / "res"), "--out-id", "f9", *extra]
    return run_examples.Invocation(run_examples.build_parser().parse_args(argv))


# ------------------------------------------------------------------------------------------------ spec pinning
@needs_pin_commit
def test_legacy_pins_hash_to_the_spec_text_at_their_commit():
    for pin in PINS:
        for eid, want in pin["spec_sha256"].items():
            assert run_examples.sha256_text(run_examples.spec_text(_ex(eid), pin["spec_mode"], pin["examples_sha"])) == want


@needs_pin_commit
def test_replay_of_a_legacy_cassette_sends_the_recorded_spec_not_the_checkout_docs(tmp_path, monkeypatch):
    """Root cause of F9: 04-09 were edited after the 44a2747 recording; the old harness sent the checkout's text."""
    monkeypatch.setattr(run_examples.subprocess, "Popen", _fake_popen)
    inv = _replay_inv(tmp_path, {"frozen_now": PIN["frozen_now"], "model": PIN["model"]})
    rec = inv.run_one(inv.examples[0], 1, [])
    sent = (Path(rec["run_dir"]) / "spec.md").read_text()
    recorded = run_examples.spec_text(_ex("04"), "full", PIN["examples_sha"])
    assert sent == recorded and sent != run_examples.spec_text(_ex("04"), "full", None)
    cfg = json.loads((Path(rec["run_dir"]) / "child_config.json").read_text())
    prov = cfg["spec_provenance"]
    assert prov["source"] == f"legacy_pin:{PIN['examples_sha'][:12]}" and prov["match"] is True
    assert prov["spec_sha256"] == PIN["spec_sha256"]["04"]


def test_replay_strict_fails_closed_when_the_spec_differs_from_the_recording(tmp_path, monkeypatch):
    monkeypatch.setattr(run_examples.subprocess, "Popen", _fake_popen)
    _NoChild.launched.clear()
    # an explicit --examples-sha that is not the recorded text (HEAD's 04 differs from the 44a2747 recording)
    inv = _replay_inv(tmp_path, {"frozen_now": PIN["frozen_now"], "model": PIN["model"]}, "--examples-sha", "HEAD")
    rec = inv.run_one(inv.examples[0], 1, [])
    assert rec["result"]["invalid_reasons"] == ["replay_spec_mismatch"] and rec["result"]["valid_run"] is False
    assert rec["result"]["spec_provenance"]["match"] is False
    assert _NoChild.launched == []


def test_legacy_pin_without_its_commit_refuses_with_a_clear_reason(monkeypatch):
    """Fresh-history behaviour, simulated: git cannot read the pinned commit -> SystemExit that says why (never a
    silent fallback to the checkout's docs)."""
    monkeypatch.setattr(run_examples.gitutil, "show", lambda repo, sha, path: None)
    monkeypatch.setattr(run_examples.gitutil, "has_commit", lambda repo, sha: False)
    with pytest.raises(SystemExit, match="is not in this clone"):
        run_examples.resolve_spec(_ex("04"), "full", None, "replay-strict",
                                  {"frozen_now": PIN["frozen_now"], "model": PIN["model"]})


def test_cassette_meta_spec_text_wins_over_the_checkout_and_is_verified():
    text = "# spec as recorded\n"
    meta = {"spec_text": text, "spec_sha256": run_examples.sha256_text(text), "spec_mode": "full"}
    s = run_examples.resolve_spec(_ex("01"), "full", None, "replay-strict", meta)
    assert s["text"] == text and s["source"] == "cassette_meta" and s["match"] is True
    bad = dict(meta, spec_sha256="0" * 64)
    assert run_examples.resolve_spec(_ex("01"), "full", None, "replay-strict", bad)["match"] is False


def test_unpinned_replay_is_reported_not_guessed(tmp_path):
    s = run_examples.resolve_spec(_ex("01"), "full", None, "replay-strict", {"frozen_now": "1999-01-01T00:00:00+00:00",
                                                                           "model": "m"})
    assert s["source"] == "worktree_unpinned" and s["match"] is None and s["recorded_spec_sha256"] is None


def test_record_writes_the_spec_into_the_cassette_meta(tmp_path, monkeypatch):
    monkeypatch.setattr(run_examples.subprocess, "Popen", _fake_popen)
    argv = ["--llm", "synthetic", "--model", "gemini-3.8-flash", "--examples", "01", "--runs", "1", "--cassettes",
            str(tmp_path / "cas"), "--out", str(tmp_path / "res"), "--out-id", "rec"]
    inv = run_examples.Invocation(run_examples.build_parser().parse_args(argv))
    rec = inv.run_one(inv.examples[0], 1, [])
    extra = json.loads((Path(rec["run_dir"]) / "child_config.json").read_text())["cassette_meta_extra"]
    assert extra["spec_text"] == (Path(rec["run_dir"]) / "spec.md").read_text()
    assert extra["spec_sha256"] == run_examples.sha256_text(extra["spec_text"]) and extra["spec_mode"] == "full"


# ------------------------------------------------------------------------------------------- served accounting
def _resp(text):
    from google.genai import types
    return types.GenerateContentResponse.model_validate({
        "candidates": [{"content": {"role": "model", "parts": [{"text": text}]}, "finish_reason": "STOP"}],
        "usage_metadata": {"prompt_token_count": 10, "candidates_token_count": 5}})


def _proxy(mode, cassette, backend=None, state=None):
    state = state or RunState()
    return LLMProxy(mode=mode, budget=Budget(5.0, 10 ** 9, PRICES, state=state), state=state, gateway_dir=HERE,
                    example="01", run=1, backend=backend, cassette=cassette)


def _record(tmp_path, prompts):
    cas_path = tmp_path / "c.jsonl"
    c = Cassette(cas_path)
    c.open_for_record({})
    p = _proxy("record", c, backend=lambda *, model, contents, config: _resp(f"echo:{contents}"))
    for pr in prompts:
        p.models.generate_content(model="m", contents=pr, config=None)
    c.close()
    return cas_path


def test_recorded_entries_keep_the_hashed_request(tmp_path):
    cas_path = _record(tmp_path, ["alpha"])
    rec = [json.loads(ln) for ln in cas_path.read_text().splitlines()][1]
    assert rec["request"] == normalize_request("m", "alpha", None)
    assert request_hash(rec["request"]) == rec["request_hash"]


def test_summary_counts_exact_fallback_and_miss_per_site(tmp_path):
    cas_path = tmp_path / "c.jsonl"
    c = Cassette(cas_path)
    c.open_for_record({})
    p = _proxy("record", c, backend=lambda *, model, contents, config: _resp(f"echo:{contents}"))
    for pr in ("a", "b"):  # recorded from this function, so the replay below has the same site
        p.models.generate_content(model="m", contents=pr, config=None)
    c.close()
    rp = _proxy("replay-strict", Cassette.load(cas_path))
    rp.models.generate_content(model="m", contents="a", config=None)          # exact
    rp.models.generate_content(model="m", contents="b-changed", config=None)  # same site, ordinal 1 -> fallback
    with pytest.raises(EvalReplayMiss):
        rp.models.generate_content(model="m", contents="c", config=None)      # ordinal 2 not recorded -> miss
    s = rp.summary()
    assert s["served"] == {"replay": 1, "replay_fallback": 1, "replay_miss": 1, "backend": 0}
    (site, by_kind), = s["served_by_site"].items()
    assert site.endswith("test_summary_counts_exact_fallback_and_miss_per_site")
    assert by_kind == {"replay": 1, "replay_fallback": 1, "replay_miss": 1}


def test_summary_and_scoreboard_show_served_for_every_run():
    def rec(key, served, per_call, prov):
        return {"key": key, "run_dir": "/nonexistent", "result": {
            "example": key[:2], "run": 1, "valid_run": True, "pipeline_outcome": "developer_failed_typed",
            "llm": {"calls": len(per_call), "served": served, "per_call": per_call}, "spec_provenance": prov}}
    lead = "developer_agent/lead_orchestrator.py:LeadDeveloperOrchestrator.decompose_specification"
    prov = {"source": "legacy_pin:44a274790b95", "spec_sha256": "ab" * 32, "match": True}
    records = [rec("04-r1", {"replay": 9, "replay_fallback": 0, "replay_miss": 0, "backend": 0},
                   [{"site": "x:J", "served": "replay"}], prov),
               rec("06-r1", {"replay": 10, "replay_fallback": 1, "replay_miss": 0, "backend": 0},
                   [{"site": lead, "served": "replay_fallback"}], prov),
               # a result.json written before F9 (no replay_miss key): the miss is the call left unserved
               rec("07-r1", {"backend": 0, "replay": 2, "replay_fallback": 0},
                   [{"site": "x:A", "served": None}], {})]
    summary = metrics.aggregate(records)
    rows = {r["key"]: r for r in summary["runs"]}
    assert rows["06-r1"]["served"]["replay_fallback"] == 1
    assert rows["06-r1"]["served_not_exact_sites"] == {"LeadDeveloperOrchestrator.decompose_specification": 1}
    assert rows["07-r1"]["served"]["replay_miss"] == 1
    assert summary["overall"]["served"] == {"replay": 21, "replay_fallback": 1, "replay_miss": 1, "backend": 0}
    md = scoreboard.render(dict(summary, manifest={}))
    assert "## Replay provenance (served per run)" in md
    assert "| 06-r1 | 10 | 1 | 0 | 0 | LeadDeveloperOrchestrator.decompose_specification x1 | legacy_pin:44a274790b95" in md
    assert "| 04-r1 | 9 | 0 | 0 | 0 | - |" in md and "| 07-r1 | 2 | 0 | 1 | 0 |" in md
