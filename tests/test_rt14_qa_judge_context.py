"""RT14-29 (full-scope red-team 11-14): the adherence judge saw the Task DAG cut at 15 000 characters, mid-JSON (later
tasks' acceptance criteria could never be reported missed), and the HEAD of the QA log tail (pip output, not the
pytest result). Now the DAG is shown whole or Stage 2 stops (GATE_UNAVAILABLE QA_INPUT_BUDGET, the diff-budget rule),
the judge sees the END of the logs, and the platform's own test counts (skipped never counted as passed, RT14-17) are
the last line. A DAG under the old cut and logs under 2 000 characters give exactly the text they gave before.
Plan: docs/planning/rt14-developer-qa-context-plan.md.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import (SHA_A, SHA_B, FakeBackend, FakeDB, FakeQAClient, backend_factory, judge_reply,
                          passing_outcome, seed_context)

import qa_auditor.judge as judge_mod  # noqa: E402
from qa_auditor import judge_input as ji  # noqa: E402
from qa_auditor.adherence_lens import PYTEST_LOGS_CHARS, evaluate_adherence_lens  # noqa: E402
from qa_auditor.lens_common import LensUnavailableError  # noqa: E402

BRANCH = "castor/app-1"


def _dag(n, criteria_len=400):
    return [{"task_id": f"T{i:03d}", "title": f"task {i}", "acceptance_criteria": ["c" * criteria_len]}
            for i in range(n)]


def _capture(monkeypatch):
    seen = []
    monkeypatch.setattr(judge_mod, "call", lambda p, m, **k: seen.append(p) or judge_reply()(p, m))
    monkeypatch.setattr(judge_mod.secrets, "token_hex", lambda n: "f" * (2 * n))
    return seen


def test_large_dag_is_shown_whole_as_valid_json(monkeypatch):
    seen = _capture(monkeypatch)
    dag = _dag(60)                                       # ~30 000 characters: over the old 15 000 cut
    text = ji.task_dag_json(dag)
    assert 15_000 < len(text) <= ji.TASK_DAG_BUDGET_CHARS and json.loads(text) == dag
    evaluate_adherence_lens("+x", task_dag=dag, model_name="m")
    assert text in seen[0] and '"task_id": "T059"' in seen[0]


def test_n_small_dag_text_is_unchanged():
    dag = _dag(3)
    assert ji.task_dag_json(dag) == json.dumps(dag, indent=2)[:15000]
    assert ji.task_dag_json([]) == "[]" and ji.task_dag_json(None) == "[]"


def test_lens_refuses_an_over_budget_dag_instead_of_cutting_it(monkeypatch):
    calls = []
    monkeypatch.setattr(judge_mod, "call", lambda p, m, **k: calls.append(p) or judge_reply()(p, m))
    monkeypatch.setattr("qa_auditor.adherence_lens.TASK_DAG_BUDGET_CHARS", 1_000)
    with pytest.raises(LensUnavailableError):
        evaluate_adherence_lens("+x", task_dag=_dag(5), model_name="m")
    assert calls == []


def test_lens_sees_the_end_of_the_logs(monkeypatch):
    seen = _capture(monkeypatch)
    logs = "Collecting fastapi\n" * 500 + "===== 3 passed, 1 skipped in 0.5s =====\n== QA test counts (platform record)"
    evaluate_adherence_lens("+x", task_dag=[], pytest_logs=logs, model_name="m")
    assert "3 passed, 1 skipped" in seen[0] and logs[-PYTEST_LOGS_CHARS:] in seen[0]


def test_n_short_logs_are_shown_as_before(monkeypatch):
    seen = _capture(monkeypatch)
    evaluate_adherence_lens("+x", task_dag=[], pytest_logs="3 passed", model_name="m")
    assert "3 passed" in seen[0]


def test_counts_line_is_last_and_never_counts_a_skip_as_passed(monkeypatch):
    gw = fd4f_support.load_gateway(monkeypatch, "rt14_ctx_gw1")
    out = gw._qa_pytest_logs({"tests_total": 5, "tests_failed": 1, "tests_skipped": 2, "logs_tail": "tail"})
    assert out == ("tail\n== QA test counts (platform record): 5 test(s), 2 passed, 1 failed, 2 skipped or xfail "
                   "(not passes)")
    assert gw._qa_pytest_logs({"tests_total": 3, "tests_failed": 0}).endswith("3 test(s), 3 passed, 0 failed, "
                                                                              "0 skipped or xfail (not passes)")
    for bad in ({"tests_total": "3"}, {"tests_total": 1, "tests_skipped": 2}, {"tests_total": True}):
        assert gw._qa_pytest_logs(bad) == "== QA test counts (platform record): unavailable"


def test_run_qa_over_budget_dag_fails_closed_before_any_judge(monkeypatch):
    gw = fd4f_support.load_gateway(monkeypatch, "rt14_ctx_gw2")
    calls = []
    monkeypatch.setattr(judge_mod, "call", lambda p, m, **k: calls.append(p) or judge_reply()(p, m))
    monkeypatch.setattr(ji, "TASK_DAG_BUDGET_CHARS", 2_000)
    db = FakeDB()
    seed_context(db)
    db.docs["pipeline_executions/tr-1"]["stages"]["architect"]["details"]["task_dag"] = _dag(10)
    backend = FakeBackend({BRANCH: {"apps/a/main.py": b"x\n"}, "main": {"README.md": b"# a\n"}},
                          {BRANCH: SHA_A, "main": SHA_B})
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name=BRANCH)
    with pytest.raises(gw.GateUnavailableError) as ei:
        gw.run_qa(req, client=FakeQAClient(passing_outcome()), source_backend_factory=backend_factory(backend),
                  evidence_db=db)
    assert ei.value.reason == "QA_INPUT_BUDGET" and calls == []
    details = db.docs["qa_test_runs/tr-1"]["stage2_unavailable_details"]
    assert details["task_dag_budget_chars"] == 2_000 and details["task_dag_chars"] > 2_000


def test_n_run_qa_with_a_normal_dag_passes_and_the_judge_sees_the_counts(monkeypatch):
    gw = fd4f_support.load_gateway(monkeypatch, "rt14_ctx_gw3")
    seen = _capture(monkeypatch)
    db = FakeDB()
    seed_context(db)
    backend = FakeBackend({BRANCH: {"apps/a/main.py": b"x\n"}, "main": {"README.md": b"# a\n"}},
                          {BRANCH: SHA_A, "main": SHA_B})
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name=BRANCH)
    out = gw.run_qa(req, client=FakeQAClient(passing_outcome()), source_backend_factory=backend_factory(backend),
                    evidence_db=db)
    assert out["passed"] is True
    adh = next(p for p in seen if "Security Engineer" not in p)
    assert "3 passed\n== QA test counts (platform record): 3 test(s), 3 passed, 0 failed" in adh
