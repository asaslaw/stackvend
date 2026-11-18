"""Gateway -> developer request capture for the QA-FEEDBACK byte-identity snapshot (tests/test_qa_feedback.py).

Drives the gateway's `_execute_developer_logic` (hermetic: FakeDB, fake source backend, the developer agent's
generate / commit replaced by recorders) over QA-retry scenarios whose QA evidence does NOT match (and the first
build), and returns, per scenario, the canonical JSON of the keyword arguments the gateway passed to
`developer_agent.generate_code_files`. The snapshot `tests/fixtures/qa_feedback_unchanged_requests.json` was produced
by this module on the code BEFORE QA-FEEDBACK (main 803f4cff); the test re-captures on the current code and requires
every scenario to be byte-identical (an unmatched QA retry is today's blind regeneration, unchanged).
No network, no LLM, no Firestore client."""
import json
import os
import sys

TESTS = os.path.dirname(os.path.abspath(__file__))
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

PID, TRACE = "svc", "t-qa1"
BRANCH = "castor/svc-abc123"
SHA = "a" * 40
OTHER_SHA = "b" * 40
TREE = {
    "apps/svc/main.py": "from schemas import EventAuditRecord\n\napp = None\n",
    "apps/svc/schemas/__init__.py": "class Other:\n    pass\n",
    "apps/svc/requirements.txt": "fastapi>=0.110.0\n",
    "infra/workload/main.tf": "# platform\n",
    ".github/workflows/deploy-svc.yml": "name: x\n",
}
QA_DIAG = {"tool": "python", "code": "PY.IMPORT_FAILED", "severity": "error", "file": "apps/svc/main.py",
           "line": None, "message": "`import main` failed for apps/svc",
           "detail": "ImportError: cannot import name 'EventAuditRecord' from 'schemas'", "source": "qa",
           "iteration": 0, "fingerprint": "f" * 64}


TF_REPORT = {"status": "FAIL", "source": "apply", "artifact_hash": "", "diagnostics": [
    {"tool": "tofu", "code": "TF.UNSUPPORTED_ARGUMENT", "severity": "error", "file": "infra/workload/custom.tf",
     "message": "Unsupported argument", "source": "apply"}]}


def qa_record(**over):
    """The run_qa evidence document of a failed, retryable CODE_DEFECT attempt 0 on BRANCH @ SHA."""
    doc = {"trace_id": TRACE, "product_id": PID, "branch_name": BRANCH, "commit_sha": SHA, "attempt": 0,
           "passed": False, "error_class": "CODE_DEFECT", "reason": None, "retryable": True,
           "summary": "QA failed: 1 diagnostic(s); first: PY.IMPORT_FAILED", "diagnostics": [dict(QA_DIAG)],
           "fingerprints": ["f" * 64]}
    doc.update(over)
    return doc


class _FailingQAReads:
    """A FakeDB whose qa_test_runs reads raise (every other collection is the plain fake)."""

    def __init__(self, db):
        self._db = db

    def collection(self, name):
        if name == "qa_test_runs":
            class _Col:
                def document(self, _id):
                    class _Doc:
                        def get(self):
                            raise RuntimeError("firestore read failed")
                    return _Doc()
            return _Col()
        return self._db.collection(name)


def scenarios():
    """name -> (request overrides, record or None, db mode, backend mode). Every one is today's path."""
    return {
        "first_build_reads_nothing": (dict(retry_count=0), qa_record(), "ok", "ok"),
        "no_record": (dict(retry_count=1), None, "ok", "ok"),
        "read_error": (dict(retry_count=1), qa_record(), "fail_reads", "ok"),
        "trace_mismatch": (dict(retry_count=1), qa_record(trace_id="t-other"), "ok", "ok"),
        "product_mismatch": (dict(retry_count=1), qa_record(product_id="other"), "ok", "ok"),
        "verdict_passed": (dict(retry_count=1), qa_record(passed=True, error_class=None, retryable=False), "ok", "ok"),
        "verdict_not_code_defect": (dict(retry_count=1), qa_record(error_class="GATE_UNAVAILABLE"), "ok", "ok"),
        "verdict_not_retryable": (dict(retry_count=1), qa_record(retryable=False, reason="NO_PROGRESS"), "ok", "ok"),
        "attempt_mismatch": (dict(retry_count=1), qa_record(attempt=1), "ok", "ok"),
        "attempt_not_int": (dict(retry_count=1), qa_record(attempt="0"), "ok", "ok"),
        "commit_moved": (dict(retry_count=1), qa_record(), "ok", "moved"),
        "commit_not_a_sha": (dict(retry_count=1), qa_record(commit_sha="main"), "ok", "ok"),
        "fetch_failed": (dict(retry_count=1), qa_record(), "ok", "fail"),
        "no_diagnostics": (dict(retry_count=1), qa_record(diagnostics=[]), "ok", "ok"),
        "terraform_remediation_dispatch": (dict(retry_count=1, tf_retry_count=1, tf_remediation_context="Error: bad",
                                                tf_validation_report=TF_REPORT), qa_record(), "ok", "ok"),
    }


def committed_draft(sha=SHA, paths=None):
    """SAT-49: the developer's record of the tested commit (pipeline_executions/{trace}.stages.developer)."""
    return {"commit_sha": sha, "llm_draft_paths": sorted(TREE) if paths is None else list(paths)}


def run(gw, monkeypatch, overrides, record=None, db_mode="ok", backend_mode="ok", draft="match", db_out=None):
    """(generate_code_files kwargs, the fake backend's calls) of one gateway developer dispatch.
    SAT-49: `draft` = the committed_draft record of the trace: "match" (of SHA, every TREE path), None (absent) or a
    record dict; `db_out` (a list) receives the FakeDB."""
    from fd4f_support import FakeBackend, FakeDB, backend_factory, make_tar  # noqa: F401
    db = FakeDB()
    db.docs[f"workloads/{PID}/compliance_audits/{TRACE}"] = {
        "product_id": PID, "trace_id": TRACE, "allow_unauthenticated": True, "enable_direct_iap": False,
        "domain_restricted_sharing": False, "allowed_domains": []}
    if record is not None:
        db.docs[f"qa_test_runs/{TRACE}"] = record
    if draft is not None:
        db.docs[f"pipeline_executions/{TRACE}"] = {"stages": {"developer": {
            "committed_draft": committed_draft() if draft == "match" else dict(draft)}}}
    if db_out is not None:
        db_out.append(db)
    monkeypatch.setattr(gw, "db", _FailingQAReads(db) if db_mode == "fail_reads" else db)
    trees = {BRANCH: {p: t.encode() for p, t in TREE.items()}}
    backend = FakeBackend(trees, {BRANCH: OTHER_SHA if backend_mode == "moved" else SHA},
                          fail=backend_mode == "fail")
    monkeypatch.setattr(gw, "get_source_backend_factory", lambda: backend_factory(backend))
    monkeypatch.setattr(gw.developer_agent, "fetch_github_token", lambda *a, **k: None)
    got = {}
    monkeypatch.setattr(gw.developer_agent, "generate_code_files",
                        lambda **kw: got.update(kw) or {"apps/svc/main.py": "x = 1\n"})
    monkeypatch.setattr(gw.developer_agent, "commit_and_open_pr", lambda **kw: {
        "status": "COMMITTED", "branch_name": kw["branch_name"], "commit_sha": "c" * 40,
        "files_committed": ["apps/svc/main.py"], "pull_request_url": "https://example.invalid/pr/2"})
    if hasattr(gw, "_assert_tf_remediation_allowed"):   # its own guard (lane 17) is not under test here
        monkeypatch.setattr(gw, "_assert_tf_remediation_allowed", lambda *a, **k: None)
    req = gw.DeveloperExecuteRequest(product_id=PID, trace_id=TRACE, spec_text="audit service",
                                     task_dag=[{"task_id": "t1", "title": "svc"}], **overrides)
    gw._execute_developer_logic(req)
    return got, backend.calls


def canonical(kwargs):
    return json.dumps(kwargs, sort_keys=True, default=repr)


def capture(monkeypatch_factory):
    """{scenario: canonical kwargs JSON}; `monkeypatch_factory()` -> a context manager yielding a MonkeyPatch."""
    from fd4f_support import load_gateway
    out = {}
    for name, (overrides, record, db_mode, backend_mode) in sorted(scenarios().items()):
        with monkeypatch_factory() as mp:
            gw = load_gateway(mp, name="qa_feedback_capture_gw")
            kwargs, _calls = run(gw, mp, overrides, record, db_mode, backend_mode)
            out[name] = canonical(kwargs)
    return out


if __name__ == "__main__":   # python tests/qa_feedback_capture.py <out.json>  (run on the pre-change code)
    import hermetic_guard  # noqa: F401
    import pytest
    with open(sys.argv[1], "w") as fh:
        json.dump(capture(pytest.MonkeyPatch.context), fh, indent=1, sort_keys=True)
