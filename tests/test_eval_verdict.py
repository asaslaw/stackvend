"""FD-4BN Phase 0: dry-run verdict rules (plan test-workload-dry-run-plan.md §12.2). Pure, offline."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import itertools
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from stackvend_eval import metrics  # noqa: E402
from stackvend_eval.verdict import tally, verdict  # noqa: E402


def _rec(outcome="committed_passed", valid=True, reasons=(), stages=None, validate_ok=True, hs=None, diags=None,
         status="validated", invariants=None, extra_result=None):
    result = {"example": "spec", "run": 1, "valid_run": valid, "invalid_reasons": list(reasons),
              "pipeline_outcome": outcome, "stages": stages if stages is not None else {
                  "architect": {"ok": True}, "compliance": {"ok": True}, "developer": {"ok": True, "path": "swarm"},
                  "precommit": {"ok": True, "status": "MOCK_COMMITTED"}}}
    if hs is not None:
        result["hallucination_stack"] = hs
    result.update(extra_result or {})
    score = None
    if validate_ok is not None or status != "validated":
        tofu = {"status": status, "validate_ok": validate_ok, "diagnostics": diags or []}
        score = {"checkpoints": {"C3_committed": {"tofu": tofu, "invariants": invariants or {}}}}
    return {"key": "spec-r1", "result": result, "score": score}


def _v(rec):
    return verdict(metrics.run_row(rec), rec["result"])


def test_committed_and_validated_would_succeed_through_validation():
    v = _v(_rec())
    assert v["verdict"] == "WOULD_SUCCEED" and v["stage"] is None and v["reason"] == "through validation"
    assert v["gate_false_pass"] is False and v["warnings"] == []


def test_canary_only_is_inconclusive_first():
    v = _v(_rec(outcome="canary_only", validate_ok=None))
    assert v["verdict"] == "INCONCLUSIVE:canary_only"


@pytest.mark.parametrize("reason,shown", [
    ("isolation_guard_ineffective", "isolation"),
    ("replay_miss", "replay_miss"),
    ("unmetered_llm_client", "unmetered_llm_client"),
    ("harness_error", "harness_error"),
    ("timeout", "timeout"),
    ("not_run_budget", "not_run_budget"),
    ("budget_exceeded", "budget_exceeded"),
    ("fallback_tripwire", "llm_fallback"),
    ("replay_spec_mismatch", "replay_spec_mismatch"),
    ("some_future_reason", "some_future_reason"),
])
def test_every_known_invalid_reason(reason, shown):
    v = _v(_rec(outcome="invalid", valid=False, reasons=[reason, "timeout"]))
    assert v["verdict"] == "INCONCLUSIVE:" + shown and v["stage"] is None
    assert reason in v["reason"]


def test_invalid_without_a_recorded_reason():
    assert _v(_rec(outcome=None, valid=False))["verdict"] == "INCONCLUSIVE:invalid_run"


def test_invalid_wins_over_a_committed_pass():
    """A run that committed and validated but tripped e.g. the fallback tripwire is never WOULD_SUCCEED."""
    v = _v(_rec(outcome="committed_passed", valid=False, reasons=["fallback_tripwire"]))
    assert v["verdict"] == "INCONCLUSIVE:llm_fallback"


def test_typed_developer_failure():
    hs = {"developer_failed_typed": {"error_class": "CODE_DEFECT", "codes": ["HCL.SYNTAX", "TF.UNDECLARED_VAR"]}}
    v = _v(_rec(outcome="developer_failed_typed", hs=hs, validate_ok=None))
    assert v["verdict"] == "WOULD_FAIL_AT:developer" and v["stage"] == "developer"
    assert v["reason"] == "CODE_DEFECT: HCL.SYNTAX, TF.UNDECLARED_VAR"


@pytest.mark.parametrize("failed", ["architect", "compliance", "developer"])
def test_generation_error_names_the_first_failed_stage(failed):
    stages = {}
    for name in ("architect", "compliance", "developer"):
        if name == failed:
            stages[name] = {"ok": False, "error": "ValueError: " + "x" * 400}
            break
        stages[name] = {"ok": True}
    v = _v(_rec(outcome="generation_error", stages=stages, validate_ok=None))
    assert v["verdict"] == "WOULD_FAIL_AT:" + failed and v["stage"] == failed
    assert v["reason"].startswith("ValueError: ") and len(v["reason"]) <= 303 and v["reason"].endswith("...")


def test_generation_error_with_a_missing_stage_record():
    v = _v(_rec(outcome="generation_error", stages={"architect": {"ok": True}}, validate_ok=None))
    assert v["verdict"] == "WOULD_FAIL_AT:compliance"


def test_generation_error_after_the_developer_stage_is_precommit():
    stages = {"architect": {"ok": True}, "compliance": {"ok": True}, "developer": {"ok": True},
              "precommit": {"note": "commit_and_open_pr returned without reaching capture"}}
    v = _v(_rec(outcome="generation_error", stages=stages, validate_ok=None))
    assert v["verdict"] == "WOULD_FAIL_AT:precommit" and "without reaching capture" in v["reason"]


def test_precommit_and_gatekeeper_rejections():
    pre = _rec(outcome="precommit_rejected", validate_ok=None)
    pre["result"]["stages"]["precommit"] = {"ok": False, "rejected": True, "error": "RuntimeError: gate says no"}
    assert _v(pre)["verdict"] == "WOULD_FAIL_AT:precommit" and "gate says no" in _v(pre)["reason"]
    gk = _rec(outcome="gatekeeper_rejected", validate_ok=None)
    gk["result"]["stages"]["gatekeeper_4_5"] = {"ok": True, "passed": False, "errors": ["missing provider block"]}
    assert _v(gk) == {"verdict": "WOULD_FAIL_AT:gatekeeper", "stage": "gatekeeper", "reason": "missing provider block",
                      "warnings": [], "gate_false_pass": False}


def test_gate_false_pass_is_a_deploy_failure():
    diags = [{"severity": "error", "summary": "Unsupported argument"}, {"severity": "error", "summary": "Bad ref"}]
    v = _v(_rec(validate_ok=False, diags=diags))
    assert v["verdict"] == "WOULD_FAIL_AT:deploy" and v["stage"] == "deploy" and v["gate_false_pass"] is True
    assert "Bad ref" in v["reason"]  # metrics.run_row sorts the summaries; the first one is reported


@pytest.mark.parametrize("status", ["tofu_unavailable", "init_failed_offline_mirror", "skipped_no_hcl_parser"])
def test_validator_unavailable_is_inconclusive(status):
    v = _v(_rec(validate_ok=None, status=status))
    assert v["verdict"] == "INCONCLUSIVE:validator_unavailable" and status in v["reason"]


def test_unscored_run_is_inconclusive():
    rec = _rec(validate_ok=None)
    rec["score"] = None
    assert _v(rec)["verdict"] == "INCONCLUSIVE:validator_unavailable"


def test_unknown_outcome_passes_through():
    assert _v(_rec(outcome="brand_new_outcome"))["verdict"] == "INCONCLUSIVE:unknown_outcome:brand_new_outcome"


def test_warnings_never_change_the_verdict():
    rec = _rec(invariants={"violations": 2, "I6_service_uri_cycles": [["a", "b"]], "I3_literals": ["x"]})
    rec["result"]["state"] = {"events": [{"stage": "compliance", "kind": "client_blocked",
                                          "detail": {"call": "google.cloud.firestore_v1.base_client.BaseClient.__init__"}}]}
    rec["result"]["llm"] = {"calls": 3, "served": {"replay": 3, "replay_fallback": 0, "replay_miss": 0, "backend": 0}}
    v = _v(rec)
    assert v["verdict"] == "WOULD_SUCCEED"
    joined = " | ".join(v["warnings"])
    assert "invariant violations: 2" in joined and "isolation attempts blocked" in joined


def _diverged(fallback=0, spec_match=None, **kw):
    per_call = ([{"site": "architect_agent.consensus:ConsensusEngine.run", "served": "replay_fallback"}] * fallback
                + [{"site": "x:Lead.plan", "served": "replay"}])
    extra = {"llm": {"calls": fallback + 1, "per_call": per_call,
                     "served": {"replay": 1, "replay_fallback": fallback, "replay_miss": 0, "backend": 0}},
             "spec_provenance": {"source": "spec_file", "match": spec_match}}
    return _rec(extra_result=extra, **kw)


@pytest.mark.parametrize("kw", [{}, {"validate_ok": False, "diags": [{"severity": "error", "summary": "x"}]},
                                {"outcome": "developer_failed_typed", "validate_ok": None},
                                {"outcome": "gatekeeper_rejected", "validate_ok": None}])
def test_a_fallback_served_replay_is_inconclusive_whatever_the_outcome(kw):
    """RT fix 3: a call answered by site/ordinal fallback got another request's recorded response."""
    v = _v(_diverged(fallback=2, **kw))
    assert v["verdict"] == "INCONCLUSIVE:replay_diverged" and v["stage"] is None
    assert "2 call(s) served by site/ordinal fallback" in v["reason"] and "ConsensusEngine.run" in v["reason"]
    assert v["gate_false_pass"] is False


def test_a_spec_mismatch_is_inconclusive_even_with_exact_replays():
    v = _v(_diverged(fallback=0, spec_match=False))
    assert v["verdict"] == "INCONCLUSIVE:replay_diverged" and "spec differs" in v["reason"]


def test_an_exact_replay_keeps_its_verdict():
    assert _v(_diverged(fallback=0, spec_match=True))["verdict"] == "WOULD_SUCCEED"
    assert _v(_diverged(fallback=0, spec_match=None))["verdict"] == "WOULD_SUCCEED"


def test_invalid_and_canary_rules_still_come_first():
    assert _v(_diverged(fallback=1, valid=False, reasons=["replay_miss"]))["verdict"] == "INCONCLUSIVE:replay_miss"
    assert _v(_diverged(fallback=1, outcome="canary_only", validate_ok=None))["verdict"] == "INCONCLUSIVE:canary_only"


def test_never_would_succeed_unless_valid_and_validated():
    """Property: over every combination, WOULD_SUCCEED implies valid, c3_validate_ok is True, no call served by
    replay fallback, and a spec that is not known to differ from the recorded one (RT fix 3)."""
    outcomes = ["committed_passed", "precommit_rejected", "gatekeeper_rejected", "generation_error",
                "developer_failed_typed", "invalid", "canary_only", None, "other"]
    for outcome, valid, ok, reasons, fallback, spec_match in itertools.product(
            outcomes, (True, False), (True, False, None), ([], ["timeout"], ["fallback_tripwire"]), (0, 1, 3),
            (None, True, False)):
        rec = _diverged(fallback=fallback, spec_match=spec_match, outcome=outcome, valid=valid, reasons=reasons,
                        validate_ok=ok)
        row = metrics.run_row(rec)
        v = verdict(row, rec["result"])
        if v["verdict"] == "WOULD_SUCCEED":
            assert row["valid"] is True and row["c3_validate_ok"] is True and outcome == "committed_passed"
            assert row["served"]["replay_fallback"] == 0 and row["spec_match"] is not False
        assert v["verdict"].startswith(("WOULD_SUCCEED", "WOULD_FAIL_AT:", "INCONCLUSIVE:"))


def test_tally_counts_k_of_n():
    vs = [_v(_rec()), _v(_rec(validate_ok=False)), _v(_rec())]
    t = tally(vs)
    assert t["would_succeed"] == 2 and t["runs"] == 3
    assert t["counts"] == {"WOULD_FAIL_AT:deploy": 1, "WOULD_SUCCEED": 2}
