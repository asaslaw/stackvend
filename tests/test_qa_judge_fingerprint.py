"""QA-JUDGE-FINGERPRINT (owner 10-27), fingerprint rule replaced by JUDGE-GATE-ENUMERATED-FINDINGS (owner 11-13):
judge findings are told apart by their typed fields (code, task_id, file, facet), never the judge's wording, so
NO_PROGRESS fires when the same repair seed comes back reworded; an adherence finding the judge attributes to an exact DAG task_id is routed to
that task's committed target file (so QA-FEEDBACK can repair it); since QA-JUDGE-FILE-MAPPING only when the task has
exactly one committed target (tests/test_qa_judge_file_mapping.py covers the typed path and the multi-target case)."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import json
import warnings

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import (SHA_A, SHA_B, FakeBackend, FakeDB, FakeQAClient, backend_factory, passing_outcome,
                          seed_context)

import qa_auditor.judge as judge_mod  # noqa: E402

BRANCH = "castor/app-1"
DAG = [
    {"task_id": "CODE-01", "category": "CODE", "target_files": ["apps/api/missing.py", "apps/api/main.py"]},
    {"task_id": "CODE-03", "category": "CODE", "target_files": [".github/workflows/deploy-api.yml"]},
]
TREE = {"apps/api/main.py": b"x = 1\n", "tests/test_main.py": b"def test(): pass\n"}


@pytest.fixture()
def gw(monkeypatch):
    mod = fd4f_support.load_gateway(monkeypatch, "qa_fp_gw")
    yield mod
    mod.app.dependency_overrides.clear()


def _judge(missed, task_ids=None, adh=0.5):
    def _call(prompt, model, **kw):
        if "Security Engineer" in prompt:
            return json.dumps({"passed": True, "critical_vulnerabilities": []})
        body = {"instruction_adherence_score": adh, "grounding_score": 1.0, "missed_directives": missed,
                "hallucinated_features": [], "summary": "a"}
        if task_ids is not None:
            body["missed_directive_task_ids"] = task_ids
        return json.dumps(body)
    return _call


def _run(gw, monkeypatch, db, *, missed, task_ids=None, attempt=0, adh=0.5):
    monkeypatch.setattr(judge_mod, "call", _judge(missed, task_ids, adh))
    backend = FakeBackend({BRANCH: TREE, "main": {}}, {BRANCH: SHA_A, "main": SHA_B})
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name=BRANCH, attempt=attempt)
    return gw.run_qa(req, client=FakeQAClient(passing_outcome()), source_backend_factory=backend_factory(backend),
                     evidence_db=db)


def _db():
    db = FakeDB()
    seed_context(db)
    db.docs["pipeline_executions/tr-1"]["stages"]["architect"]["details"]["task_dag"] = DAG
    return db


# ------------------------------------------------------------------ fingerprint
STAMP = "stage2_judge"   # QA-JUDGE-STAMP: developer_agent.qa_repair.JUDGE_FINDING_FIELD (the gateway's judge stamp)


def test_judge_findings_are_told_apart_by_typed_fields_not_wording(gw):
    """JUDGE-GATE-ENUMERATED-FINDINGS (was: distinct messages -> distinct fingerprints)."""
    a = {"tool": "judge", "code": "JUDGE.ADHERENCE", "file": "apps/api/main.py", "line": None,
         "message": "no /health endpoint", "task_id": "CODE-01", STAMP: True}
    assert gw._diagnostic_fingerprint(a) == gw._diagnostic_fingerprint(dict(a, message="the health route is missing"))
    assert gw._diagnostic_fingerprint(a) != gw._diagnostic_fingerprint(dict(a, task_id="CODE-03"))
    assert gw._diagnostic_fingerprint(a) == gw._diagnostic_fingerprint(dict(a))


def test_judge_fingerprint_includes_the_routed_file(gw):
    """JUDGE-GATE-ENUMERATED-FINDINGS (replaces RT F4's "ignores the routed file"): the fingerprint is the repair seed,
    so a finding that gained a task and a file is a different seed."""
    a = {"tool": "judge", "code": "JUDGE.ADHERENCE", "file": None, "line": None, "message": "no /health endpoint",
         STAMP: True}
    routed = dict(a, file="apps/api/main.py", task_id="CODE-01")
    assert gw._diagnostic_fingerprint(a) != gw._diagnostic_fingerprint(routed)
    key = json.dumps(["judge", "JUDGE.ADHERENCE", "CODE-01", "apps/api/main.py", None])
    assert gw._diagnostic_fingerprint(routed) == hashlib.sha256(key.encode()).hexdigest()


def test_attribution_change_on_retry_is_progress(gw, monkeypatch):
    """JUDGE-GATE-ENUMERATED-FINDINGS (was NO_PROGRESS): the next repair round is routed to a file it did not have."""
    db = _db()
    _run(gw, monkeypatch, db, missed=["no /health endpoint"])
    second = _run(gw, monkeypatch, db, missed=["no /health endpoint"], task_ids=["CODE-01"], attempt=1)
    assert second["diagnostics"][0]["file"] == "apps/api/main.py"
    assert second["retryable"] is True and second["reason"] == "STAGE2_FAILED"


def test_non_judge_fingerprints_are_unchanged(gw):
    d = {"tool": "pytest", "code": "PY.TEST_FAILED", "file": "tests/test_a.py", "line": 3, "message": "m1"}
    old = hashlib.sha256(json.dumps(["pytest", "PY.TEST_FAILED", "tests/test_a.py", 3]).encode()).hexdigest()
    assert gw._diagnostic_fingerprint(d) == old
    assert gw._diagnostic_fingerprint(dict(d, message="m2")) == old   # message is not part of it (as before)


def test_different_findings_on_retry_are_progress(gw, monkeypatch):
    """JUDGE-GATE-ENUMERATED-FINDINGS: "different" = a different typed seed (here the task); unattributed findings
    with only new wording share one key per code (test below)."""
    db = _db()
    first = _run(gw, monkeypatch, db, missed=["no /health endpoint", "no seed user"], task_ids=["CODE-01", ""])
    assert first["retryable"] is True and first["reason"] == "STAGE2_FAILED"
    second = _run(gw, monkeypatch, db, missed=["no Firestore index", "no README"], task_ids=["CODE-03", ""],
                  attempt=1)
    assert second["retryable"] is True and second["reason"] == "STAGE2_FAILED"


def test_reworded_unattributed_findings_on_retry_are_no_progress(gw, monkeypatch):
    """JUDGE-GATE-ENUMERATED-FINDINGS (accepted residual): the same number of task-less, file-less findings is the
    same repair seed whatever the wording."""
    db = _db()
    _run(gw, monkeypatch, db, missed=["no /health endpoint", "no seed user"])
    second = _run(gw, monkeypatch, db, missed=["no Firestore index", "no README"], attempt=1)
    assert second["retryable"] is False and second["reason"] == "NO_PROGRESS"


def test_identical_findings_on_retry_are_no_progress(gw, monkeypatch):
    db = _db()
    _run(gw, monkeypatch, db, missed=["no /health endpoint", "no seed user"])
    second = _run(gw, monkeypatch, db, missed=["no seed user", "no /health endpoint"], attempt=1)
    assert second["retryable"] is False and second["reason"] == "NO_PROGRESS"


# ------------------------------------------------------------------ task mapping
def test_attributed_finding_is_routed_to_the_tasks_committed_file(gw, monkeypatch):
    out = _run(gw, monkeypatch, _db(), missed=["no /health endpoint", "no GitHub workflow", "general"],
               task_ids=["CODE-01", "CODE-03", ""])
    diags = [d for d in out["diagnostics"] if d["code"] == "JUDGE.ADHERENCE"]
    assert [d["file"] for d in diags] == ["apps/api/main.py", None, None]   # CODE-03's file is not in the tree
    assert [d.get("task_id") for d in diags] == ["CODE-01", "CODE-03", None]
    assert out["passed"] is False   # attribution never changes the verdict


@pytest.mark.parametrize("task_ids", [None, ["CODE-01"], "CODE-01", [1, 2], ["NOPE", "CODE-99"]])
def test_unusable_attribution_routes_nothing(gw, monkeypatch, task_ids):
    out = _run(gw, monkeypatch, _db(), missed=["a", "b"], task_ids=task_ids)
    diags = [d for d in out["diagnostics"] if d["code"] == "JUDGE.ADHERENCE"]
    assert [d["file"] for d in diags] == [None, None] and all("task_id" not in d for d in diags)


def test_score_only_answer_has_no_finding(gw, monkeypatch):
    """JUDGE-GATE-ENUMERATED-FINDINGS (was: one file-less score finding): a low score (from the 0.80 contradiction
    floor up) with nothing listed passes."""
    out = _run(gw, monkeypatch, _db(), missed=[], task_ids=[], adh=0.85)
    assert out["passed"] is True and [d for d in out["diagnostics"] if d["code"] == "JUDGE.ADHERENCE"] == []


def test_verdict_object_serializes_without_warnings(gw, monkeypatch):
    db = _db()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _run(gw, monkeypatch, db, missed=["a"], task_ids=["CODE-01"])
    doc = db.docs["qa_test_runs/tr-1"]
    assert doc["adherence_lens"]["missed_directive_task_ids"] == ["CODE-01"]
    assert "missed_directive_task_ids" not in doc["composite_audit"]["adherence_lens"]   # shared schema unchanged


def test_prompt_asks_for_task_ids():
    from qa_auditor.adherence_lens import ADHERENCE_AUDITOR_PROMPT_TEMPLATE, ADHERENCE_RESPONSE_SCHEMA
    assert '"missed_directive_task_ids"' in ADHERENCE_AUDITOR_PROMPT_TEMPLATE
    assert "missed_directive_task_ids" in ADHERENCE_RESPONSE_SCHEMA["properties"]
    assert "missed_directive_task_ids" not in ADHERENCE_RESPONSE_SCHEMA["required"]
