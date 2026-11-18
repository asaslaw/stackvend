"""FD-4F QA-1..6 + red-team F1/F3/F6/F8/F9: the QA routes fail closed and persist commit-bound evidence."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

from fastapi.testclient import TestClient

from fd4f_support import (  # noqa: F401  (gw is a fixture)
    SHA_A,
    SHA_B,
    FakeBackend,
    FakeDB,
    FakeQAClient,
    backend_factory,
    code_defect_outcome,
    gw,
    judge_reply,
    passing_outcome,
    seed_context,
)

BRANCH = "castor/app-1"
TREE = {"apps/app/main.py": b"print('hi')\n", "apps/app/tests/test_a.py": b"def test_a():\n    assert True\n"}


def _wire(gw, *, client, db, backend=None, judge=None, monkeypatch=None):
    backend = backend or FakeBackend({BRANCH: TREE, "main": {"README.md": b"x\n"}}, {BRANCH: SHA_A, "main": SHA_B})
    gw.app.dependency_overrides[gw.get_qa_job_client] = lambda: client
    gw.app.dependency_overrides[gw.get_source_backend_factory] = lambda: backend_factory(backend)
    gw.app.dependency_overrides[gw.get_evidence_db] = lambda: db
    if judge is not None:
        import qa_auditor.judge as judge_mod

        monkeypatch.setattr(judge_mod, "call", judge)
    return TestClient(gw.app), backend


def _qa(c, **body):
    payload = {"trace_id": "tr-1", "product_id": "app", "branch_name": BRANCH}
    payload.update(body)
    return c.post("/agent/qa/verify", json=payload)


def test_negative_full_pass_writes_commit_bound_evidence(gw, monkeypatch):
    db = FakeDB()
    seed_context(db)
    client = FakeQAClient(passing_outcome())
    c, _ = _wire(gw, client=client, db=db, judge=judge_reply(), monkeypatch=monkeypatch)
    r = _qa(c, expected_commit_sha=SHA_A)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["passed"] is True and body["error_class"] is None and body["commit_sha"] == SHA_A
    doc = db.docs["qa_test_runs/tr-1"]
    assert doc["commit_sha"] == SHA_A and doc["passed"] is True and doc["nonce"] == "n" * 32
    assert client.calls[0]["commit_sha"] == SHA_A
    # the evidence is a full overwrite, never a merge (no stale keys from an earlier attempt)
    assert [w for w in db.writes if w[0] == "qa_test_runs/tr-1"][-1][2] is False
    # sign-off recorded on the injected client
    assert "qa_test_runs/tr-1" in db.docs


def test_qa_not_configured_sync_is_503(gw):
    c, _ = _wire(gw, client=None, db=FakeDB())
    r = _qa(c)
    assert r.status_code == 503 and r.json()["reason"] == "QA_NOT_CONFIGURED" and r.json()["passed"] is False


def test_f1_async_route_refuses_at_dispatch_when_unconfigured(gw):
    c, _ = _wire(gw, client=None, db=FakeDB())
    r = c.post("/agent/qa/verify-async", json={"trace_id": "tr-1", "product_id": "app", "branch_name": BRANCH,
                                                "callback_url": "http://127.0.0.1:9/cb"})
    assert r.status_code == 503  # not 202: the pre-Stage-A workflow stops here with zero LLM spend
    assert r.json()["error_class"] == "GATE_UNAVAILABLE"


def test_gateway_has_no_in_process_runner(gw):
    assert not hasattr(gw, "QASandboxRunner") and not hasattr(gw, "qa_runner")


def test_trace_id_required(gw):
    c, _ = _wire(gw, client=FakeQAClient(passing_outcome()), db=FakeDB())
    assert c.post("/agent/qa/verify", json={"product_id": "app", "branch_name": BRANCH}).status_code == 422
    assert _qa(c, trace_id="auto qa trace").status_code == 422
    assert _qa(c, expected_commit_sha="abc").status_code == 422


def test_stage2_judge_unavailable_is_gate_unavailable(gw, monkeypatch):
    db = FakeDB()
    seed_context(db)

    def boom(prompt, model, **kw):
        import qa_auditor.judge as j
        raise j.JudgeUnavailableError("vertex down")

    c, _ = _wire(gw, client=FakeQAClient(passing_outcome()), db=db, judge=boom, monkeypatch=monkeypatch)
    r = _qa(c)
    assert r.status_code == 503 and r.json()["reason"] == "STAGE2_UNAVAILABLE"
    assert db.docs["qa_test_runs/tr-1"]["passed"] is False


def test_f9_missing_pipeline_context_is_gate_unavailable(gw, monkeypatch):
    db = FakeDB()  # no workloads / pipeline_executions docs
    c, _ = _wire(gw, client=FakeQAClient(passing_outcome()), db=db, judge=judge_reply(), monkeypatch=monkeypatch)
    r = _qa(c)
    assert r.status_code == 503 and r.json()["reason"] == "QA_CONTEXT"


def test_stage2_judged_fail_is_code_defect_with_diagnostics(gw, monkeypatch):
    db = FakeDB()
    seed_context(db)
    c, _ = _wire(gw, client=FakeQAClient(passing_outcome()), db=db,
                 judge=judge_reply(sec_passed=False, crit=["hardcoded key"]), monkeypatch=monkeypatch)
    r = _qa(c)
    assert r.status_code == 200
    body = r.json()
    assert body["passed"] is False and body["error_class"] == "CODE_DEFECT" and body["retryable"] is True
    assert any(d["code"] == "JUDGE.SECURITY" and d["source"] == "qa" for d in body["diagnostics"])


def test_job_code_defect_returns_diagnostics_and_sign_off_failed(gw):
    db = FakeDB()
    db.docs["workloads/app/implementation_plans/p1"] = {"markdown": "# plan", "created_at": "1"}
    c, _ = _wire(gw, client=FakeQAClient(code_defect_outcome()), db=db)
    r = _qa(c, attempt=0)
    assert r.status_code == 200
    body = r.json()
    assert body["error_class"] == "CODE_DEFECT" and body["diagnostics"][0]["fingerprint"]
    assert db.docs["workloads/app/implementation_plans/p1"]["status"] == "FAILED"


def test_f3_identical_diagnostics_on_retry_stop_retrying(gw):
    db = FakeDB()
    c, _ = _wire(gw, client=FakeQAClient(code_defect_outcome()), db=db)
    assert _qa(c, attempt=0).json()["retryable"] is True
    second = _qa(c, attempt=1).json()
    assert second["retryable"] is False and second["reason"] == "NO_PROGRESS"


def test_f3_different_diagnostics_on_retry_stay_retryable(gw):
    db = FakeDB()
    c, _ = _wire(gw, client=FakeQAClient(code_defect_outcome()), db=db)
    _qa(c, attempt=0)
    gw.app.dependency_overrides[gw.get_qa_job_client] = lambda: FakeQAClient(code_defect_outcome(code="PY.IMPORT_FAILED"))
    assert _qa(c, attempt=1).json()["retryable"] is True


def test_job_unavailable_is_503_and_sign_off_blocked(gw):
    from gate_errors import ErrorClass
    from qa_job_client import QAOutcome

    db = FakeDB()
    db.docs["workloads/app/implementation_plans/p1"] = {"markdown": "# plan", "created_at": "1"}
    out = QAOutcome(passed=False, error_class=ErrorClass.GATE_UNAVAILABLE, summary="runner error", reason="RUNNER_ERROR")
    c, _ = _wire(gw, client=FakeQAClient(out), db=db)
    r = _qa(c)
    assert r.status_code == 503 and r.json()["reason"] == "RUNNER_ERROR"
    assert db.docs["workloads/app/implementation_plans/p1"]["status"] == "BLOCKED"


def test_f6_branch_moved_is_platform_defect(gw):
    c, _ = _wire(gw, client=FakeQAClient(passing_outcome()), db=FakeDB())
    r = _qa(c, expected_commit_sha=SHA_B)  # head is SHA_A
    assert r.status_code == 503
    assert r.json()["error_class"] == "PLATFORM_DEFECT" and r.json()["reason"] == "BRANCH_MOVED"


def test_source_fetch_failure_is_gate_unavailable(gw):
    c, _ = _wire(gw, client=FakeQAClient(passing_outcome()), db=FakeDB(), backend=FakeBackend({}, {}, fail=True))
    r = _qa(c)
    assert r.status_code == 503 and r.json()["reason"] == "SOURCE_FETCH"


def test_evidence_store_missing_or_failing_is_gate_unavailable(gw):
    c, _ = _wire(gw, client=FakeQAClient(code_defect_outcome()), db=None)
    assert _qa(c).json()["reason"] == "EVIDENCE_STORE"
    db = FakeDB()
    db.fail_writes = True
    c, _ = _wire(gw, client=FakeQAClient(code_defect_outcome()), db=db)
    r = _qa(c)
    assert r.status_code == 503 and r.json()["reason"] == "EVIDENCE_STORE"
