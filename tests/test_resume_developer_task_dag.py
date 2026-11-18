"""RESUME-DEVELOPER-TASK-DAG: a RESUME_DEVELOPER relaunch used to pass developer and gatekeeper, then always fail at QA
(`QA_CONTEXT`: no Task DAG), because no route kept the DAG for a run that has no architect stage.

The real routes: `/events/pre-build-gate` keeps the DAG on both gate paths, `/agent/resume/outcome` refuses when it is
not kept (before developer spend) and keeps it out of the workflow's data, the developer reads it only on a specification
long enough to rule out the solo path, `/agent/qa/verify` on a resume-shaped trace reads it, and the Control Center's
relaunch stops a resume that cannot succeed. Hermetic: in-memory stores, no cloud clients."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import json
import os
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from fd4f_support import (  # noqa: F401  (gw is a fixture)
    FakeDB,
    FakeQAClient,
    SHA_A,
    gw,
    judge_reply,
    passing_outcome,
    seed_compliance_decision,
    seed_context,
)
from test_fd4f_fail_closed_remainders import _dev_capture
from test_fd4f_qa_endpoints_fail_closed import _wire

if "--harness" not in sys.argv:  # these import the gateway's `shared`; the harness child must get the Control Center's
    from test_compliance_profile_explicit import _intake_with
    from test_l19_11_access_intake import ADMIN_H, _client as _cc_client, cc  # noqa: F401  (cc is a fixture)

HERE = os.path.dirname(os.path.abspath(__file__))
PID, FULL_TRACE, RESUME_TRACE = "app", "t-full", "tr-1"
CB = "https://workflowexecutions.googleapis.com/v1/projects/p/locations/r/workflows/w/executions/e/callbacks/c1"
DAG = [{"step_id": "STEP-42-KEPT", "title": "the approved plan"}, {"step_id": "STEP-43-KEPT", "title": "second task"}]
DAG_PATH = f"workloads/{PID}/prebuild_task_dags/{FULL_TRACE}"
COMPLIANCE = {"requires_human_approval": False, "has_policy_conflicts": False, "allow_unauthenticated": False}
FINOPS = {"requires_human_approval": False, "monthly_cost_delta_usd": 12.5, "risk_assessment": "LOW"}


def _client(gw, db):
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: db
    return TestClient(gw.app, raise_server_exceptions=False)


def _gate(c, *, task_dag=None, trace=FULL_TRACE, rework_cycle=0, operator_requested=False):
    return c.post("/events/pre-build-gate", json={
        "trace_id": trace, "product_id": PID, "callback_url": CB, "rework_cycle": rework_cycle,
        "compliance": COMPLIANCE, "finops": FINOPS, "operator_requested": operator_requested,
        "task_dag": DAG if task_dag is None else task_dag})


def _decide(c, db, approval_id, decision="APPROVED"):
    db.docs[f"approval_requests/{approval_id}"]["status"] = decision
    return c.post("/events/pre-build-gate/decision", json={"trace_id": FULL_TRACE, "product_id": PID,
                                                           "approval_id": approval_id, "decision": decision})


def _resume(c):
    return c.post("/agent/resume/outcome", json={"trace_id": RESUME_TRACE, "product_id": PID})


def _seed_compliance(db, trace=FULL_TRACE):
    seed_compliance_decision(db, PID, trace)


# ======================================================================================= pre-build gate persistence
def test_auto_pass_keeps_the_dag_in_its_own_document(gw):
    db = FakeDB()
    r = _gate(_client(gw, db))
    assert r.status_code == 200 and r.json()["decision"] == "PASS", r.text
    record = db.docs[DAG_PATH]
    assert (record["status"], record["task_count"], record["rework_cycle"]) == ("STORED", 2, 0)
    assert json.loads(record["task_dag_json"]) == DAG
    # never on the gate records, which share the workload document's 1 MiB
    assert "task_dag" not in db.docs[f"workloads/{PID}"]["last_prebuild_gate"]
    assert "task_dag" not in json.dumps(db.docs[f"pipeline_executions/{FULL_TRACE}"]["prebuild_gate"])


def test_await_approval_keeps_the_dag_and_an_approved_gate_can_resume(gw):
    db = FakeDB()
    c = _client(gw, db)
    r = _gate(c, operator_requested=True)
    assert r.status_code == 200 and r.json()["decision"] == "AWAIT_APPROVAL", r.text
    assert json.loads(db.docs[DAG_PATH]["task_dag_json"]) == DAG
    assert _decide(c, db, r.json()["approval_id"]).status_code == 200
    assert db.docs[f"workloads/{PID}"]["last_prebuild_gate"]["status"] == "APPROVED"
    _seed_compliance(db)
    assert _resume(c).status_code == 200


def test_a_later_rework_cycle_replaces_the_dag(gw):
    db = FakeDB()
    c = _client(gw, db)
    first = _gate(c, task_dag=[{"step_id": "OLD"}], operator_requested=True)
    assert _decide(c, db, first.json()["approval_id"], "REWORK").status_code == 200
    second = _gate(c, rework_cycle=1, operator_requested=True)
    assert _decide(c, db, second.json()["approval_id"]).status_code == 200
    assert db.docs[DAG_PATH]["rework_cycle"] == 1 and json.loads(db.docs[DAG_PATH]["task_dag_json"]) == DAG
    _seed_compliance(db)
    assert _resume(c).status_code == 200


def test_dag_write_failure_is_loud_and_no_gate_is_recorded(gw):
    class _Docs(dict):
        def __setitem__(self, key, value):
            if "/prebuild_task_dags/" in key:
                raise RuntimeError("firestore write failed")
            super().__setitem__(key, value)

    db = FakeDB()
    db.docs = _Docs()
    r = _gate(_client(gw, db))
    assert r.status_code == 503 and r.json()["error_class"] == "GATE_UNAVAILABLE"
    assert "last_prebuild_gate" not in db.docs.get(f"workloads/{PID}", {})


def test_store_write_failure_is_loud(gw):
    db = FakeDB()
    db.fail_writes = True
    assert _gate(_client(gw, db)).status_code == 503


# ======================================================================================= size handling
def test_task_dag_record_size_boundary():
    import workflow_gates as g

    def record_of(size):
        dag = [{"x": "y"}]
        overhead = len(json.dumps(dag, separators=(",", ":"))) - 1
        dag = [{"x": "y" * (size - overhead)}]
        return g.task_dag_record(product_id=PID, trace_id="t", rework_cycle=0, task_dag=dag, recorded_at="now")

    at_limit = record_of(g.MAX_PERSISTED_TASK_DAG_BYTES)
    assert (at_limit["status"], at_limit["size_bytes"]) == ("STORED", g.MAX_PERSISTED_TASK_DAG_BYTES)
    assert at_limit["task_dag_json"]
    assert len(json.dumps(at_limit)) < 1_048_576  # one Firestore document
    over = record_of(g.MAX_PERSISTED_TASK_DAG_BYTES + 1)
    assert (over["status"], over["task_dag_json"]) == ("TOO_LARGE", "")


def test_oversized_dag_build_goes_on_and_resume_refuses_with_a_typed_problem(gw, caplog):
    db = FakeDB()
    c = _client(gw, db)
    huge = [{"step_id": "S", "text": "x" * 950_000}]
    r = _gate(c, task_dag=huge)
    assert r.status_code == 200, r.text
    assert db.docs[DAG_PATH]["status"] == "TOO_LARGE" and "task_dag_json" in db.docs[DAG_PATH]
    assert db.docs[DAG_PATH]["task_dag_json"] == ""
    assert "TASK_DAG_TOO_LARGE" in caplog.text
    _seed_compliance(db)
    resumed = _resume(c)
    assert resumed.status_code == 503 and "TASK_DAG_TOO_LARGE" in resumed.json()["details"]["problems"]


# ======================================================================================= /agent/resume/outcome
def test_resume_outcome_passes_and_keeps_the_developer_input_unchanged(gw):
    import workflow_gates as g

    db = FakeDB()
    c = _client(gw, db)
    assert _gate(c).status_code == 200
    _seed_compliance(db)
    r = _resume(c)
    assert r.status_code == 200, r.text
    body = r.json()
    # Exactly the ingress view: a `task_dag` here would reach the developer through the workflow expression
    assert set(body["compliance"]) == set(g.compliance_ingress_view({})) and "task_dag" not in body["compliance"]
    assert body["source_trace_id"] == FULL_TRACE


@pytest.mark.parametrize("mutate, problem", [
    (lambda rec, _db: rec.clear(), "NO_PERSISTED_TASK_DAG"),
    (lambda rec, _db: rec.update(status="EMPTY", task_dag_json="", task_count=0), "NO_PERSISTED_TASK_DAG"),
    (lambda rec, _db: rec.update(task_dag_json="[]"), "NO_PERSISTED_TASK_DAG"),
    (lambda rec, _db: rec.update(task_dag_json="{not json"), "NO_PERSISTED_TASK_DAG"),
    (lambda rec, _db: rec.update(task_dag_json="[1]"), "NO_PERSISTED_TASK_DAG"),
    (lambda rec, _db: rec.update(trace_id="t-other"), "NO_PERSISTED_TASK_DAG"),
    (lambda rec, _db: rec.update(product_id="other"), "NO_PERSISTED_TASK_DAG"),
    (lambda rec, _db: rec.update(rework_cycle=7), "NO_PERSISTED_TASK_DAG"),
])
def test_resume_outcome_refuses_an_unusable_dag(gw, mutate, problem):
    db = FakeDB()
    c = _client(gw, db)
    assert _gate(c).status_code == 200
    _seed_compliance(db)
    mutate(db.docs[DAG_PATH], db)
    if not db.docs[DAG_PATH]:
        del db.docs[DAG_PATH]
    r = _resume(c)
    assert r.status_code == 503 and r.json()["reason"] == "RESUME_GATE_UNAVAILABLE"
    assert r.json()["details"]["problems"] == [problem]


def test_resume_outcome_with_no_prior_build_lists_only_the_gate_problem(gw):
    r = _resume(_client(gw, FakeDB()))
    assert r.status_code == 503 and r.json()["details"]["problems"] == ["NO_PREBUILD_GATE"]


# ======================================================================================= /agent/qa/verify on a resume
def _resume_trace(db):
    seed_context(db, PID, RESUME_TRACE)
    del db.docs[f"workloads/{PID}/compliance_audits/{RESUME_TRACE}"]  # a real resume has none: it reuses the full build's
    db.docs[f"pipeline_executions/{RESUME_TRACE}"] = {
        "product_id": PID, "execution_mode": "RESUME_DEVELOPER",
        "stages": {"architect": {"status": "SKIPPED", "summary": "Bypassed via Fast-Path (Zero-LLM)"},
                   "compliance": {"status": "SKIPPED", "summary": "Bypassed via Fast-Path"}}}


def _full_build_gate(gw, db):
    """The full build's gate and compliance decision, then the resume's own /agent/resume/outcome."""
    c = _client(gw, db)
    assert _gate(c).status_code == 200
    _seed_compliance(db)
    assert _resume(c).status_code == 200
    return c


def test_qa_on_a_resume_trace_judges_against_the_kept_dag(gw, monkeypatch):
    db = FakeDB()
    _resume_trace(db)
    c = _full_build_gate(gw, db)
    outcome = _resume(c)
    assert outcome.status_code == 200, outcome.text
    seen = []
    base = judge_reply()

    def spy(*a, **k):
        seen.append(repr((a, k)))
        return base(*a, **k)

    qa_client, _ = _wire(gw, client=FakeQAClient(passing_outcome()), db=db, judge=spy, monkeypatch=monkeypatch)
    # exactly what the workflow sends on a resume: compliance is the real route's answer, args.task_dag is empty
    workflow_dag = outcome.json()["compliance"].get("task_dag") or []
    assert workflow_dag == []
    r = qa_client.post("/agent/qa/verify", json={"trace_id": RESUME_TRACE, "product_id": PID, "branch_name": "castor/app-1",
                                                 "expected_commit_sha": SHA_A, "task_dag": workflow_dag})
    assert r.status_code == 200, r.text
    assert r.json()["passed"] is True
    assert any("STEP-42-KEPT" in s for s in seen)  # the adherence judge was given the real plan


def test_qa_context_uses_the_gate_trace_dag_only_for_a_resume(gw):
    db = FakeDB()
    _resume_trace(db)
    _full_build_gate(gw, db)
    assert gw._fetch_pipeline_context_for_qa(PID, RESUME_TRACE, db)["task_dag"] == DAG
    # a full build keeps today's lookup: nothing sent and nothing on its trace still stops the stage
    db.docs[f"pipeline_executions/{RESUME_TRACE}"].pop("execution_mode")
    with pytest.raises(gw.GateUnavailableError) as err:
        gw._fetch_pipeline_context_for_qa(PID, RESUME_TRACE, db)
    assert err.value.reason == "QA_CONTEXT"


def test_resume_outcome_records_the_validated_gate_on_the_run(gw):
    db = FakeDB()
    _resume_trace(db)
    _full_build_gate(gw, db)
    recorded = db.docs[f"pipeline_executions/{RESUME_TRACE}"]
    assert recorded["resume_prebuild_gate"]["trace_id"] == FULL_TRACE
    assert recorded["execution_mode"] == "RESUME_DEVELOPER"  # merged, the run's document is kept


def test_resume_outcome_failing_to_record_the_gate_is_loud(gw):
    db = FakeDB()
    c = _client(gw, db)
    assert _gate(c).status_code == 200
    _seed_compliance(db)
    db.fail_writes = True
    r = _resume(c)
    assert r.status_code == 503 and r.json()["error_class"] == "GATE_UNAVAILABLE"


def test_a_refused_resume_records_no_gate(gw):
    db = FakeDB()
    _resume_trace(db)
    c = _client(gw, db)
    assert _gate(c).status_code == 200
    _seed_compliance(db)
    del db.docs[DAG_PATH]
    assert _resume(c).status_code == 503
    assert "resume_prebuild_gate" not in db.docs[f"pipeline_executions/{RESUME_TRACE}"]


def test_a_newer_run_cannot_supply_the_dag_of_a_resume_in_flight(gw):
    db = FakeDB()
    _resume_trace(db)
    c = _full_build_gate(gw, db)
    _seed_compliance(db, "retry-new")  # a real full run's compliance stage writes this before its gate
    newer = _gate(c, task_dag=[{"step_id": "UNAPPROVED"}], trace="retry-new", operator_requested=True)
    assert newer.json()["decision"] == "AWAIT_APPROVAL"
    assert db.docs[f"workloads/{PID}"]["last_prebuild_gate"]["trace_id"] == "retry-new"
    assert gw._fetch_pipeline_context_for_qa(PID, RESUME_TRACE, db)["task_dag"] == DAG


@pytest.mark.parametrize("gate", [None, "not-a-gate", {"status": "REJECTED", "trace_id": FULL_TRACE, "rework_cycle": 0},
                                  {"status": "AWAIT_APPROVAL", "trace_id": FULL_TRACE, "rework_cycle": 0}])
def test_qa_context_needs_a_recorded_passed_gate(gw, gate):
    db = FakeDB()
    _resume_trace(db)
    _full_build_gate(gw, db)
    db.docs[f"pipeline_executions/{RESUME_TRACE}"]["resume_prebuild_gate"] = gate
    with pytest.raises(gw.GateUnavailableError) as err:
        gw._fetch_pipeline_context_for_qa(PID, RESUME_TRACE, db)
    assert err.value.reason == "QA_CONTEXT"


def test_qa_context_ignores_the_workload_gate_when_the_run_recorded_none(gw):
    db = FakeDB()
    _resume_trace(db)
    _full_build_gate(gw, db)
    del db.docs[f"pipeline_executions/{RESUME_TRACE}"]["resume_prebuild_gate"]
    assert db.docs[f"workloads/{PID}"]["last_prebuild_gate"]["status"] == "PASS"
    with pytest.raises(gw.GateUnavailableError):
        gw._fetch_pipeline_context_for_qa(PID, RESUME_TRACE, db)


def test_qa_context_request_dag_still_wins_over_the_kept_one(gw):
    db = FakeDB()
    _resume_trace(db)
    _full_build_gate(gw, db)
    sent = [{"step_id": "SENT"}]
    assert gw._fetch_pipeline_context_for_qa(PID, RESUME_TRACE, db, sent)["task_dag"] == sent


def test_qa_context_refuses_a_resume_without_a_kept_dag(gw):
    db = FakeDB()
    _resume_trace(db)
    _full_build_gate(gw, db)
    del db.docs[DAG_PATH]
    with pytest.raises(gw.GateUnavailableError) as err:
        gw._fetch_pipeline_context_for_qa(PID, RESUME_TRACE, db)
    assert err.value.reason == "QA_CONTEXT" and "no Task DAG" in str(err.value)


def test_a_newer_run_cannot_change_the_ingress_policy_of_a_resume_in_flight(gw):
    db = FakeDB()
    _resume_trace(db)
    _full_build_gate(gw, db)
    db.docs[f"workloads/{PID}"]["last_prebuild_gate"]["trace_id"] = "t-newer"   # has no compliance decision at all
    assert gw._fetch_pipeline_context_for_qa(PID, RESUME_TRACE, db)["task_dag"] == DAG


def test_a_resume_is_never_judged_on_a_newer_runs_ingress_decision(gw):
    db = FakeDB()
    _resume_trace(db)
    _full_build_gate(gw, db)
    _seed_compliance(db, trace="t-newer")
    db.docs[f"workloads/{PID}"]["last_prebuild_gate"]["trace_id"] = "t-newer"
    del db.docs[f"workloads/{PID}/compliance_audits/{FULL_TRACE}"]
    with pytest.raises(gw.GateUnavailableError) as err:
        gw._fetch_pipeline_context_for_qa(PID, RESUME_TRACE, db)
    assert err.value.reason == "QA_ACCESS_POLICY"


def test_qa_context_read_failure_is_unavailable(gw, monkeypatch):
    from fd4f_support import _DocRef

    db = FakeDB()
    _resume_trace(db)
    _full_build_gate(gw, db)
    real_get = _DocRef.get

    def get(self):
        if "/prebuild_task_dags/" in self._path:
            raise RuntimeError("firestore read failed")
        return real_get(self)

    monkeypatch.setattr(_DocRef, "get", get)
    with pytest.raises(gw.GateUnavailableError) as err:
        gw._fetch_pipeline_context_for_qa(PID, RESUME_TRACE, db)
    assert err.value.reason == "QA_CONTEXT" and "read failed" in str(err.value)


# ======================================================================================= Control Center relaunch routing
def _harness():
    import test_faithful_rt_resume_handoff as fh  # same module directory; its fakes, no fixture

    marker = "# ================================================================ public mode"
    src_path = os.path.join(HERE, "cc_identity_harness.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    assert marker in src, "FD-4E harness prefix changed"
    ns = {"__file__": src_path, "__name__": "cc_resume_handoff_harness"}
    exec(compile(src.split(marker, 1)[0], src_path, "exec"), ns)
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch

    from fastapi import HTTPException

    import routes.workloads as wl

    prior = {"trace_id": "trace-prev-1", "product_id": "demo", "status": "FAILED", "current_stage": "DEVELOPER",
             "started_at": "2026-10-13T10:00:00Z", "stages": {"developer": {"status": "FAILED"}}}
    gate = {"status": "PASS", "trace_id": "t-full", "product_id": "demo", "rework_cycle": 0}
    good_dag = {"product_id": "demo", "trace_id": "t-full", "rework_cycle": 0, "status": "STORED", "task_count": 2}

    class _BrokenStore(dict):
        def get(self, key, *a):
            if isinstance(key, tuple) and "prebuild_task_dags" in key:
                raise RuntimeError("firestore down")
            return super().get(key, *a)

    def run(body, *, workload_gate=gate, dag=good_dag, broken_store=False, gate_run=None):
        db, pub = fh.FakeDB(), fh.FakePublisher()
        if broken_store:
            db.store = _BrokenStore()
        fh._seed(db, prior)
        db.store[("workloads", "demo")].pop("last_prebuild_gate", None)
        if workload_gate is not None:
            db.store[("workloads", "demo")]["last_prebuild_gate"] = workload_gate
        dag_key = ("workloads", "demo", "prebuild_task_dags", "t-full")
        dict.pop(db.store, dag_key, None)
        if dag is not None:
            db.store[dag_key] = dag
        if gate_run is not None:
            db.store[("pipeline_executions", "t-full")] = gate_run
        main_mod = SimpleNamespace(project_id="mock-stackvend-project", get_pubsub_publisher=lambda: pub)
        req = MagicMock()
        req.state.user_email = "operator@example.com"
        from build_admission_support import every_build_admitted   # BUILD-ADMISSION-QUEUE: this store holds no slots
        with patch.object(wl, "db", db), patch.object(wl, "verify_workload_access", lambda *a, **k: None), \
                patch.object(wl, "get_caller_main_module", lambda: main_mod), every_build_admitted(wl):
            try:
                res = wl.retrigger_feature_request_build("demo", "fr-1", req, body=body)
            except HTTPException as e:
                return {"http": e.status_code, "detail": e.detail, "published": len(pub.messages)}
        return {"mode": res["execution_mode"], "trace": res["trace_id"], "published": len(pub.messages),
                "reason": res.get("auto_fallback_reason"), "message": res.get("auto_fallback_message"),
                "stored_reason": db.store[("pipeline_executions", res["trace_id"])].get("auto_fallback_reason")}

    explicit = {"execution_mode": "RESUME_DEVELOPER"}
    out = {
        "auto_healthy": run(None),
        "auto_explicit_word_healthy": run({"execution_mode": "AUTO"}),
        "explicit_healthy": run(explicit),
        "auto_no_gate": run(None, workload_gate=None),
        "auto_rejected_gate": run(None, workload_gate=dict(gate, status="REJECTED")),
        "auto_no_dag": run(None, dag=None),
        "auto_empty_dag": run(None, dag=dict(good_dag, status="EMPTY", task_count=0)),
        "auto_too_large": run(None, dag=dict(good_dag, status="TOO_LARGE")),
        "auto_store_broken": run(None, broken_store=True),
        "auto_other_request": run(None, gate_run={"product_id": "demo", "request_id": "fr-2"}),
        "auto_same_request": run(None, gate_run={"product_id": "demo", "request_id": "fr-1"}),
        "auto_request_not_recorded": run(None, gate_run={"product_id": "demo"}),
        "explicit_other_request": run(explicit, gate_run={"product_id": "demo", "request_id": "fr-2"}),
        "explicit_same_request": run(explicit, gate_run={"product_id": "demo", "request_id": "fr-1"}),
        "explicit_no_gate": run(explicit, workload_gate=None),
        "explicit_no_dag": run(explicit, dag=None),
        "explicit_empty_dag": run(explicit, dag=dict(good_dag, status="EMPTY", task_count=0)),
        "explicit_too_large": run(explicit, dag=dict(good_dag, status="TOO_LARGE")),
        "explicit_other_cycle": run(explicit, dag=dict(good_dag, rework_cycle=3)),
        "explicit_store_broken": run(explicit, broken_store=True),
        "full_no_gate_unchanged": run({"execution_mode": "FULL"}, workload_gate=None, dag=None),
        "network_attempts": ns["NETWORK_ATTEMPTS"],
    }
    print(json.dumps(out, default=str))


@pytest.fixture(scope="module")
def relaunch():
    env = hermetic_guard.child_env(drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL"),
                                   extra={"PROJECT_ID": "mock-stackvend-project",
                                          "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project",
                                          "MANAGED_WORKLOADS_FOLDER_ID": "111111111111", "GITHUB_OWNER": "example-org"})
    out = subprocess.run([sys.executable, os.path.abspath(__file__), "--harness"],
                         capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_relaunch_harness_is_hermetic(relaunch):
    assert relaunch["network_attempts"] == []


@pytest.mark.parametrize("case", ["auto_healthy", "auto_explicit_word_healthy", "explicit_healthy", "auto_same_request",
                                  "auto_request_not_recorded", "explicit_same_request"])
def test_relaunch_healthy_resume_is_unchanged(relaunch, case):
    r = relaunch[case]
    assert r["mode"] == "RESUME_DEVELOPER" and r["trace"].startswith("resume-demo-") and r["published"] == 1
    assert r["reason"] is None and r["message"] is None and r["stored_reason"] is None


@pytest.mark.parametrize("case, reason", [
    ("auto_no_gate", "NO_REUSABLE_PREBUILD_GATE"), ("auto_rejected_gate", "NO_REUSABLE_PREBUILD_GATE"),
    ("auto_no_dag", "NO_PERSISTED_TASK_DAG"), ("auto_empty_dag", "NO_PERSISTED_TASK_DAG"),
    ("auto_too_large", "TASK_DAG_TOO_LARGE"), ("auto_other_request", "OTHER_FEATURE_REQUEST"),
])
def test_relaunch_auto_falls_back_to_a_full_build_and_says_why(relaunch, case, reason):
    r = relaunch[case]
    assert r["mode"] == "FULL" and r["trace"].startswith("retry-demo-") and r["published"] == 1
    assert r["reason"] == reason and r["stored_reason"] == reason
    assert "Full Swarm Rebuild" in r["message"]


def test_relaunch_auto_unchecked_store_starts_nothing(relaunch):
    r = relaunch["auto_store_broken"]
    assert r["http"] == 503 and r["published"] == 0
    assert r["detail"]["error_class"] == "RESUME_CHECK_UNAVAILABLE"


@pytest.mark.parametrize("case, reason", [
    ("explicit_no_gate", "NO_REUSABLE_PREBUILD_GATE"), ("explicit_no_dag", "NO_PERSISTED_TASK_DAG"),
    ("explicit_empty_dag", "NO_PERSISTED_TASK_DAG"), ("explicit_too_large", "TASK_DAG_TOO_LARGE"),
    ("explicit_other_cycle", "NO_PERSISTED_TASK_DAG"), ("explicit_other_request", "OTHER_FEATURE_REQUEST"),
])
def test_relaunch_explicit_resume_that_cannot_succeed_is_a_typed_409(relaunch, case, reason):
    r = relaunch[case]
    assert r["http"] == 409 and r["published"] == 0
    assert r["detail"]["error_class"] == "RESUME_NOT_AVAILABLE" and r["detail"]["reason"] == reason
    assert "Full Swarm Rebuild" in r["detail"]["message"]


def test_relaunch_explicit_resume_unchecked_store_is_503_not_a_verdict(relaunch):
    r = relaunch["explicit_store_broken"]
    assert r["http"] == 503 and r["published"] == 0
    assert r["detail"]["error_class"] == "RESUME_CHECK_UNAVAILABLE"


def test_relaunch_full_build_needs_no_check(relaunch):
    r = relaunch["full_no_gate_unchanged"]
    assert r["mode"] == "FULL" and r["published"] == 1


def test_relaunch_toast_shows_the_typed_message():
    with open(os.path.join(HERE, "..", "apps", "control-center", "templates", "dashboard.html"), encoding="utf-8") as f:
        page = f.read()
    start = page.index("async submitRelaunch()")
    body = page[start:page.index("this.isRelaunching = false", start + 2000)]
    assert "this.apiErrorText(err.detail, 'Failed to dispatch relaunch')" in body
    assert "modeNames[data.execution_mode]" in body and "data.auto_fallback_message" in body
    assert "starts a full rebuild and says why" in page  # the Auto card


# ======================================================================================= the developer on a resume (F4 A)
def _limit():
    from developer_agent.lead_orchestrator import SOLO_FAST_PATH_SPEC_CHAR_LIMIT

    return SOLO_FAST_PATH_SPEC_CHAR_LIMIT


def _resume_request(gw, spec_len, **over):
    fields = {"trace_id": RESUME_TRACE, "product_id": PID, "compliance_trace_id": FULL_TRACE, "spec_text": "s" * spec_len,
              "task_dag": []}
    return gw.DeveloperExecuteRequest(**{**fields, **over})


def _resumed_run(gw, monkeypatch):
    """A real full build's gate, then the resume's own /agent/resume/outcome, and a developer that records its input."""
    db = FakeDB()
    _resume_trace(db)
    _full_build_gate(gw, db)
    return db, _dev_capture(gw, monkeypatch, db)


def _selected_mode(spec_len, task_dag):
    """The real swarm-or-solo selection, on a repository that has files (the condition of the fast path)."""
    from developer_agent.lead_orchestrator import LeadDeveloperOrchestrator

    with patch("shared.settings.get_platform_settings", return_value=None):  # no settings store: the defaults
        plan = LeadDeveloperOrchestrator(genai_client=None, model_name="m").decompose_specification(
            product_id=PID, spec_text="s" * spec_len, task_dag=task_dag, existing_files={"apps/app/main.py": "x = 1\n"})
    return plan.execution_mode.value


def test_long_spec_resume_builds_from_the_kept_dag_the_judge_will_use(gw, monkeypatch):
    db, seen = _resumed_run(gw, monkeypatch)
    out = gw._execute_developer_logic(_resume_request(gw, _limit() + 500))
    assert seen["task_dag"] == DAG
    assert out["tasks_executed"] == len(DAG)
    assert gw._fetch_pipeline_context_for_qa(PID, RESUME_TRACE, db)["task_dag"] == seen["task_dag"]


def test_a_qa_repair_dispatch_of_the_resume_keeps_the_dag(gw, monkeypatch):
    _, seen = _resumed_run(gw, monkeypatch)
    gw._execute_developer_logic(_resume_request(gw, _limit(), retry_count=1))
    assert seen["task_dag"] == DAG


def test_compliance_injected_tasks_reach_the_resumed_developer(gw, monkeypatch):
    enriched = DAG + [{"step_id": "COMPLIANCE-INJECTED-CMEK", "title": "added by the compliance stage"}]
    db = FakeDB()
    _resume_trace(db)
    c = _client(gw, db)
    assert _gate(c, task_dag=enriched).status_code == 200  # the workflow sends the compliance stage's enriched DAG here
    _seed_compliance(db)
    assert _resume(c).status_code == 200
    seen = _dev_capture(gw, monkeypatch, db)
    gw._execute_developer_logic(_resume_request(gw, _limit()))
    assert seen["task_dag"] == enriched


def test_short_spec_resume_keeps_the_empty_dag_and_the_solo_path(gw, monkeypatch):
    _, seen = _resumed_run(gw, monkeypatch)
    gw._execute_developer_logic(_resume_request(gw, 200))
    assert seen["task_dag"] == []
    assert _selected_mode(200, seen["task_dag"]) == "SOLO_FAST_PATH"


@pytest.mark.parametrize("offset, dag_given, solo", [(-1, False, True), (0, True, False), (1, True, False)])
def test_the_exact_boundary_of_the_dag_and_of_the_selection(gw, monkeypatch, offset, dag_given, solo):
    _, seen = _resumed_run(gw, monkeypatch)
    gw._execute_developer_logic(_resume_request(gw, _limit() + offset))
    assert seen["task_dag"] == (DAG if dag_given else [])
    assert (_selected_mode(_limit() + offset, seen["task_dag"]) == "SOLO_FAST_PATH") is solo


@pytest.mark.parametrize("task_dag", [[], [{"step_id": "A"}], [{"step_id": str(i)} for i in range(5)]])
def test_no_dag_size_can_make_a_long_spec_take_the_solo_path(gw, task_dag):
    assert _selected_mode(_limit(), task_dag) != "SOLO_FAST_PATH"


def test_the_selection_and_the_resume_share_one_threshold(gw, monkeypatch):
    import developer_agent.lead_orchestrator as lead

    monkeypatch.setattr(lead, "SOLO_FAST_PATH_SPEC_CHAR_LIMIT", 40)
    _, seen = _resumed_run(gw, monkeypatch)
    gw._execute_developer_logic(_resume_request(gw, 40))
    assert seen["task_dag"] == DAG and _selected_mode(40, []) != "SOLO_FAST_PATH"
    assert _selected_mode(39, []) == "SOLO_FAST_PATH"


@pytest.mark.parametrize("break_it", [
    lambda db: db.docs.pop(DAG_PATH),
    lambda db: db.docs[DAG_PATH].update(task_dag_json="{not json"),
    lambda db: db.docs[DAG_PATH].update(status="TOO_LARGE", task_dag_json=""),
    lambda db: db.docs[f"pipeline_executions/{RESUME_TRACE}"].pop("resume_prebuild_gate"),
], ids=["absent", "bad-json", "too-large", "no-gate-on-the-run"])
def test_no_usable_kept_dag_runs_as_before_and_qa_stops_it(gw, monkeypatch, break_it):
    db, seen = _resumed_run(gw, monkeypatch)
    break_it(db)
    gw._execute_developer_logic(_resume_request(gw, _limit() + 1))
    assert seen["task_dag"] == []  # nothing invented
    with pytest.raises(gw.GateUnavailableError) as err:
        gw._fetch_pipeline_context_for_qa(PID, RESUME_TRACE, db)
    assert err.value.reason == "QA_CONTEXT"


@pytest.mark.parametrize("path_part", [f"pipeline_executions/{RESUME_TRACE}", "/prebuild_task_dags/"])
def test_an_unreadable_store_stops_the_long_spec_resume_before_any_developer_spend(gw, monkeypatch, path_part):
    from fd4f_support import _DocRef

    _, seen = _resumed_run(gw, monkeypatch)
    real_get = _DocRef.get

    def get(self):
        if path_part in self._path:
            raise RuntimeError("firestore read failed")
        return real_get(self)

    monkeypatch.setattr(_DocRef, "get", get)
    monkeypatch.setattr(gw, "_resume_validation_report", lambda req: None)
    with pytest.raises(gw.GateUnavailableError) as err:
        gw._execute_developer_logic(_resume_request(gw, _limit()))
    assert err.value.reason == "RESUME_TASK_DAG_UNREADABLE" and err.value.stage == "developer"
    assert "task_dag" not in seen


def test_a_resume_shaped_request_on_a_run_that_is_not_a_resume_is_unchanged(gw, monkeypatch):
    db, seen = _resumed_run(gw, monkeypatch)
    db.docs[f"pipeline_executions/{RESUME_TRACE}"].pop("execution_mode")
    gw._execute_developer_logic(_resume_request(gw, _limit()))
    assert seen["task_dag"] == []


def test_the_kept_dag_is_not_read_for_another_products_run(gw, monkeypatch):
    db, seen = _resumed_run(gw, monkeypatch)
    db.docs[f"pipeline_executions/{RESUME_TRACE}"]["product_id"] = "other-app"
    gw._execute_developer_logic(_resume_request(gw, _limit()))
    assert seen["task_dag"] == []


class _NoStore:
    def collection(self, name):
        raise AssertionError(f"a full build must not read {name} for this")


@pytest.mark.parametrize("over", [
    {"compliance_trace_id": RESUME_TRACE},  # the workflow's value on a full build: its own trace
    {"compliance_trace_id": None},
    {"task_dag": [{"step_id": "SENT"}]},
])
def test_a_full_build_is_untouched_and_never_reads_the_kept_dag(gw, over):
    req = _resume_request(gw, _limit() + 1, **over)
    assert gw._resume_developer_task_dag(req, req.spec_text, _NoStore()) is None


def test_a_full_build_gets_exactly_the_dag_it_was_sent(gw, monkeypatch):
    db, seen = _resumed_run(gw, monkeypatch)  # the worst case: a kept DAG exists and the record says resume
    _seed_compliance(db, RESUME_TRACE)  # a full build's own compliance stage wrote this
    sent = [{"step_id": "FULL-BUILD-PLAN"}]
    out = gw._execute_developer_logic(_resume_request(gw, _limit() + 1, compliance_trace_id=RESUME_TRACE, task_dag=sent))
    assert seen["task_dag"] == sent and out["tasks_executed"] == 1


def test_a_full_build_with_no_dag_still_gets_none(gw, monkeypatch):
    db, seen = _resumed_run(gw, monkeypatch)
    _seed_compliance(db, RESUME_TRACE)
    gw._execute_developer_logic(_resume_request(gw, _limit() + 1, compliance_trace_id=RESUME_TRACE))
    assert seen["task_dag"] == []


# ======================================================================================= the initial build's request
# One in-memory store behind the real routes of both services: POST /api/workloads -> its published event -> the
# gateway's intake -> the run's pre-build gate -> the operator's relaunch of a request picked from the real list.
RESUME_BODY, AUTO_BODY = {"execution_mode": "RESUME_DEVELOPER"}, {"execution_mode": "AUTO"}


def _register(wl, monkeypatch, db):
    """The real create route; returns (response, published event or None, Control Center client)."""
    from routes.settings import PlatformSettings

    client = _cc_client(wl, monkeypatch, db)
    # The real authorization dependency, on this store: its own lookup can resolve a store another test left behind.
    monkeypatch.setitem(wl.require.__globals__, "_db", lambda: db)
    publisher = MagicMock()
    publisher.publish.return_value.result.return_value = "msg-1"
    with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
            patch.object(wl, "get_pubsub_publisher", return_value=publisher), \
            patch.object(wl, "get_platform_settings", return_value=PlatformSettings()):
        r = client.post("/api/workloads", json={"product_id": PID, "spec_content": "a shop"}, headers=ADMIN_H)
    event = json.loads(publisher.publish.call_args[0][1].decode("utf-8")) if publisher.publish.call_args else None
    return r, event, client


def _promote(wl, monkeypatch, db):
    """The real deploy-to-folder route, promoting into workload PID; returns what `_register` returns."""
    import folders
    from routes.settings import PlatformSettings

    db.docs["workloads/src-app"] = {"product_id": "src-app", "status": "ACTIVE", "github_repo": "example-org/src-app"}
    monkeypatch.setattr(folders, "_default_get_folder", lambda name: {"name": name, "parent": "organizations/1"})
    monkeypatch.setattr(wl, "get_caller_main_module", lambda: SimpleNamespace())
    monkeypatch.setattr(wl, "create_or_verify_branch", lambda **k: None)
    client = _cc_client(wl, monkeypatch, db)
    monkeypatch.setitem(wl.require.__globals__, "_db", lambda: db)
    publisher = MagicMock()
    publisher.publish.return_value.result.return_value = "msg-1"
    with patch.dict(os.environ, {"MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
            patch.object(wl, "get_pubsub_publisher", return_value=publisher), \
            patch.object(wl, "get_platform_settings", return_value=PlatformSettings()):
        r = client.post("/api/workloads/src-app/deploy-to-folder", headers=ADMIN_H,
                        json={"destination_folder_id": "folders/111111111111", "new_product_id": PID,
                              "target_branch": "prod"})
    event = json.loads(publisher.publish.call_args[0][1].decode("utf-8")) if publisher.publish.call_args else None
    return r, event, client


def _initial_build(gw, wl, monkeypatch, start=_register):
    """A workload's first build (`start`: the create route or a promotion), up to a passed gate. Returns (store, event,
    Control Center client)."""
    db = FakeDB()
    # BUILD-ADMISSION-QUEUE: a relaunch here starts while the first build is still running; with the default single
    # build slot it would wait in the queue (pinned by test_build_admission_queue.py), so these tests allow two.
    db.docs["system_config/platform_settings"] = {"orchestration": {"max_concurrent_builds": 2}}
    r, event, client = start(wl, monkeypatch, db)
    assert r.status_code == 200, r.text
    intake, created = _intake_with(gw, monkeypatch, db, event)
    assert intake.status_code == 200 and intake.json()["status"] == "DISPATCHED" and len(created) == 1, intake.text
    assert _gate(_client(gw, db), trace=event["trace_id"]).json()["decision"] == "PASS"
    return db, event, client


def _listed_ids(client):
    """What the operator picks from: the workload's real feature request list."""
    r = client.get(f"/api/workloads/{PID}/feature-requests", headers=ADMIN_H)
    assert r.status_code == 200, r.text
    return [fr["request_id"] for fr in r.json()]


def _add_feature_request(client):
    r = client.post(f"/api/workloads/{PID}/feature-requests", headers=ADMIN_H,
                    json={"title": "Second feature", "description": "a different specification"})
    assert r.status_code == 200, r.text
    return r.json()["request_id"]


def _relaunch(wl, client, path, body):
    """The real relaunch route; returns (response, how many events it published)."""
    publisher = MagicMock()
    publisher.publish.return_value.result.return_value = "msg-2"
    main_mod = SimpleNamespace(project_id="mock-stackvend-project", get_pubsub_publisher=lambda: publisher)
    with patch.object(wl, "get_caller_main_module", lambda: main_mod):
        r = client.post(f"/api/workloads/{PID}/{path}", json=body, headers=ADMIN_H)
    return r, publisher.publish.call_count


def _mark_failed_at_developer(db, trace):
    """What sends Auto to a Resume: the last run failed in the developer stage."""
    db.docs[f"pipeline_executions/{trace}"].update({"status": "FAILED", "current_stage": "DEVELOPER"})


def test_initial_build_records_the_feature_request_the_operator_will_relaunch(gw, cc, monkeypatch):
    _, wl = cc
    db, event, client = _initial_build(gw, wl, monkeypatch)
    assert event["request_id"].startswith(f"spec-{PID}-") and f"feature_requests/{event['request_id']}" in db.docs
    assert db.docs[f"pipeline_executions/{event['trace_id']}"]["request_id"] == event["request_id"]
    assert _listed_ids(client) == [event["request_id"]]


@pytest.mark.parametrize("body", [RESUME_BODY, AUTO_BODY])
def test_resume_of_the_initial_feature_request_is_not_refused(gw, cc, monkeypatch, body):
    _, wl = cc
    db, event, client = _initial_build(gw, wl, monkeypatch)
    _mark_failed_at_developer(db, event["trace_id"])
    r, published = _relaunch(wl, client, f"feature-requests/{_listed_ids(client)[0]}/retrigger", body)
    assert r.status_code == 200, r.text
    assert r.json()["execution_mode"] == "RESUME_DEVELOPER" and published == 1 and "auto_fallback_reason" not in r.json()


def test_explicit_resume_of_another_request_after_an_initial_build_is_refused(gw, cc, monkeypatch):
    _, wl = cc
    _, event, client = _initial_build(gw, wl, monkeypatch)
    other = _add_feature_request(client)
    r, published = _relaunch(wl, client, f"feature-requests/{other}/retrigger", RESUME_BODY)
    assert r.status_code == 409 and published == 0, r.text
    assert r.json()["detail"]["error_class"] == "RESUME_NOT_AVAILABLE"
    assert r.json()["detail"]["reason"] == "OTHER_FEATURE_REQUEST"


def test_auto_relaunch_of_another_request_after_an_initial_build_runs_a_full_build(gw, cc, monkeypatch):
    _, wl = cc
    db, event, client = _initial_build(gw, wl, monkeypatch)
    other = _add_feature_request(client)
    _mark_failed_at_developer(db, event["trace_id"])
    r, published = _relaunch(wl, client, f"feature-requests/{other}/retrigger", AUTO_BODY)
    assert r.status_code == 200 and published == 1, r.text
    assert (r.json()["execution_mode"], r.json()["auto_fallback_reason"]) == ("FULL", "OTHER_FEATURE_REQUEST")


def test_a_gate_run_with_no_recorded_request_keeps_resuming_any_request(gw, cc, monkeypatch):
    _, wl = cc
    db, event, client = _initial_build(gw, wl, monkeypatch)
    del db.docs[f"pipeline_executions/{event['trace_id']}"]["request_id"]  # a run from before this field, or Drive
    other = _add_feature_request(client)
    r, published = _relaunch(wl, client, f"feature-requests/{other}/retrigger", RESUME_BODY)
    assert r.status_code == 200 and r.json()["execution_mode"] == "RESUME_DEVELOPER" and published == 1, r.text


def test_relaunch_without_an_id_rebuilds_the_request_of_the_initial_build(gw, cc, monkeypatch):
    """The no-id route takes the newest run that recorded a request; an initial build now is one."""
    _, wl = cc
    _, event, client = _initial_build(gw, wl, monkeypatch)
    _add_feature_request(client)
    r, published = _relaunch(wl, client, "retrigger", {"execution_mode": "FULL"})
    assert r.status_code == 200 and published == 1, r.text
    assert r.json()["request_id"] == event["request_id"]


def test_registration_with_no_store_still_publishes_and_names_no_request(cc, monkeypatch):
    _, wl = cc
    r, event, _ = _register(wl, monkeypatch, None)
    assert r.status_code == 200, r.text
    assert event["source_channel"] == "control_center_form" and "request_id" not in event


def test_registration_that_could_not_save_its_request_publishes_nothing(cc, monkeypatch):
    _, wl = cc
    db = FakeDB()
    db.fail_writes = True
    r, event, _ = _register(wl, monkeypatch, db)
    assert r.status_code == 500 and event is None


@pytest.mark.parametrize("channel", [None, "google_docs", "control_center_form", "control_center_retrigger"])
def test_intake_policy_passes_the_request_id_through(channel):
    import intake_policy

    event = {"product_id": PID, "trace_id": "t", "request_id": "spec-1", **({"source_channel": channel} if channel else {})}
    assert intake_policy.validate_intake(event) == event


@pytest.mark.parametrize("value", [None, "", "   ", 7])
def test_intake_records_no_id_when_the_event_names_none(gw, monkeypatch, value):
    db = FakeDB()
    reads = _spy_request_reads(monkeypatch)
    event = {"product_id": PID, "trace_id": "t-drive", "source_channel": "google_docs"}
    if value is not None:
        event["request_id"] = value
    r, created = _intake_with(gw, monkeypatch, db, event)
    assert r.status_code == 200 and len(created) == 1, r.text
    assert "request_id" not in db.docs["pipeline_executions/t-drive"]
    assert reads == []


def test_intake_keeps_the_request_of_a_record_a_relaunch_seeded(gw, monkeypatch):
    db = FakeDB()
    db.docs["pipeline_executions/t-seeded"] = {"product_id": PID, "request_id": "feat-1"}
    db.docs["feature_requests/feat-2"] = {"product_id": PID}
    r, _ = _intake_with(gw, monkeypatch, db, {"product_id": PID, "trace_id": "t-seeded", "request_id": "feat-2",
                                              "source_channel": "control_center_form"})
    assert r.status_code == 200, r.text
    assert db.docs["pipeline_executions/t-seeded"]["request_id"] == "feat-1"


def test_intake_records_the_request_when_the_workflow_wrote_the_record_first(gw, monkeypatch):
    db = FakeDB()
    db.docs["pipeline_executions/t-first"] = {"product_id": PID, "stages": {}}
    db.docs["feature_requests/spec-1"] = {"product_id": PID}
    r, _ = _intake_with(gw, monkeypatch, db, {"product_id": PID, "trace_id": "t-first", "request_id": "spec-1",
                                              "source_channel": "control_center_form"})
    assert r.status_code == 200, r.text
    assert db.docs["pipeline_executions/t-first"]["request_id"] == "spec-1"


# =========================================================================== a request id must be the event's own
REFUSED, OTHER_PID = "SUPPRESSED:INVALID_REQUEST_ID", "other-app"
FOREIGN_REQUEST = {"product_id": OTHER_PID, "status": "IN_PROGRESS", "title": "not yours"}
AUTONOMOUS_REFACTOR = {"source_channel": "github_refactor_scanner", "scan_id": "s1", "findings_digest": "a" * 64,
                       "execution_mode": "FULL_BUILD"}


def _spy_request_reads(monkeypatch):
    """Every feature request the route reads."""
    from fd4f_support import _DocRef

    reads, real_get = [], _DocRef.get

    def get(self):
        if self._path.startswith("feature_requests/"):
            reads.append(self._path)
        return real_get(self)

    monkeypatch.setattr(_DocRef, "get", get)
    return reads


def _event(request_id, **over):
    return {"product_id": PID, "trace_id": "t-e", "request_id": request_id, "source_channel": "control_center_form", **over}


def _assert_refused_and_nothing_changed(r, created, db, before, status=REFUSED):
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["status"] == status
    assert created == []
    assert db.docs == before   # no run record, no access seed, no claim, no compliance selection, no request touched


@pytest.mark.parametrize("channel", [
    {"source_channel": "control_center_form"}, {"source_channel": "deploy_to_folder"},
    {"source_channel": "google_docs"}, {"source_channel": None}, AUTONOMOUS_REFACTOR])
def test_intake_refuses_the_feature_request_of_another_workload(gw, monkeypatch, channel):
    """The probe: dispatched before, and the run's end then overwrote `other-app`'s request."""
    db = FakeDB()
    db.docs["feature_requests/feat-other"] = dict(FOREIGN_REQUEST)
    db.docs[f"workloads/{PID}"] = {"product_id": PID, "status": "ACTIVE"}
    before = json.loads(json.dumps(db.docs))
    event = {k: v for k, v in {**_event("feat-other"), **channel}.items() if v is not None}
    r, created = _intake_with(gw, monkeypatch, db, event)
    _assert_refused_and_nothing_changed(r, created, db, before)


@pytest.mark.parametrize("record", [None, {}, {"product_id": ""}, {"product_id": None}, {"title": "no owner"}])
def test_intake_refuses_a_request_that_is_missing_or_has_no_owner(gw, monkeypatch, record):
    db = FakeDB()
    if record is not None:
        db.docs["feature_requests/feat-x"] = record
    before = json.loads(json.dumps(db.docs))
    r, created = _intake_with(gw, monkeypatch, db, _event("feat-x"))
    _assert_refused_and_nothing_changed(r, created, db, before)


def test_intake_refuses_an_id_on_an_event_with_no_product(gw, monkeypatch):
    """An ownerless request and a product-less event must not match on two absent values."""
    db = FakeDB()
    db.docs["feature_requests/feat-x"] = {"title": "no owner"}
    before = json.loads(json.dumps(db.docs))
    event = _event("feat-x")
    del event["product_id"]
    r, created = _intake_with(gw, monkeypatch, db, event)
    # RT14-37: a product-less event is now refused before the request id is read (every channel needs a valid id).
    _assert_refused_and_nothing_changed(r, created, db, before, status="SUPPRESSED:INVALID_PRODUCT_ID")


@pytest.mark.parametrize("request_id", ["feat-1/sub/doc", "/feat-1", "feat-1/", "/"])
def test_intake_refuses_a_slash_before_any_read(gw, monkeypatch, request_id):
    db = FakeDB()
    db.docs["feature_requests/feat-1/sub/doc"] = {"product_id": PID}   # a path that would otherwise resolve and match
    before = json.loads(json.dumps(db.docs))
    reads = _spy_request_reads(monkeypatch)
    r, created = _intake_with(gw, monkeypatch, db, _event(request_id))
    _assert_refused_and_nothing_changed(r, created, db, before)
    assert reads == []


def test_intake_unreadable_request_is_a_503_and_starts_nothing(gw, monkeypatch):
    from fd4f_support import _DocRef

    db = FakeDB()
    db.docs["feature_requests/feat-1"] = {"product_id": PID}
    before = json.loads(json.dumps(db.docs))
    real_get = _DocRef.get

    def get(self):
        if self._path.startswith("feature_requests/"):
            raise RuntimeError("firestore read failed")
        return real_get(self)

    monkeypatch.setattr(_DocRef, "get", get)
    r, created = _intake_with(gw, monkeypatch, db, _event("feat-1"))
    assert r.status_code == 503 and created == [] and db.docs == before, r.text
    assert "unreadable" in r.json()["detail"]


def test_intake_with_a_valid_id_dispatches_unchanged(gw, monkeypatch):
    db = FakeDB()
    db.docs["feature_requests/feat-1"] = {"product_id": PID}
    r, created = _intake_with(gw, monkeypatch, db, _event("feat-1"))
    assert r.status_code == 200 and r.json()["status"] == "DISPATCHED" and len(created) == 1, r.text
    assert json.loads(created[0].argument)["request_id"] == "feat-1"
    assert db.docs["pipeline_executions/t-e"]["request_id"] == "feat-1"


def test_a_redelivery_of_a_dispatched_event_still_acks(gw, monkeypatch):
    """After the dedupe: a request deleted after dispatch must not turn a redelivery into a refusal."""
    db = FakeDB()
    db.docs["pipeline_executions/t-e"] = {"workflow_execution_id": "e-1"}
    reads = _spy_request_reads(monkeypatch)
    r, created = _intake_with(gw, monkeypatch, db, _event("feat-gone"))
    assert r.status_code == 200 and r.json()["status"] == "DUPLICATE" and created == [] and reads == [], r.text


# ======================================================================================= a promotion's request
def test_promotion_records_the_feature_request_the_operator_will_relaunch(gw, cc, monkeypatch):
    _, wl = cc
    db, event, client = _initial_build(gw, wl, monkeypatch, start=_promote)
    assert event["source_channel"] == "deploy_to_folder" and event["request_id"].startswith(f"spec-{PID}-")
    assert db.docs[f"feature_requests/{event['request_id']}"]["product_id"] == PID
    assert db.docs[f"pipeline_executions/{event['trace_id']}"]["request_id"] == event["request_id"]
    assert _listed_ids(client) == [event["request_id"]]


def test_resume_of_the_promotions_own_request_is_not_refused(gw, cc, monkeypatch):
    _, wl = cc
    db, event, client = _initial_build(gw, wl, monkeypatch, start=_promote)
    _mark_failed_at_developer(db, event["trace_id"])
    r, published = _relaunch(wl, client, f"feature-requests/{event['request_id']}/retrigger", RESUME_BODY)
    assert r.status_code == 200 and r.json()["execution_mode"] == "RESUME_DEVELOPER" and published == 1, r.text


def test_explicit_resume_of_another_request_after_a_promotion_is_refused(gw, cc, monkeypatch):
    _, wl = cc
    _, _, client = _initial_build(gw, wl, monkeypatch, start=_promote)
    other = _add_feature_request(client)
    r, published = _relaunch(wl, client, f"feature-requests/{other}/retrigger", RESUME_BODY)
    assert r.status_code == 409 and published == 0, r.text
    assert (r.json()["detail"]["error_class"], r.json()["detail"]["reason"]) == ("RESUME_NOT_AVAILABLE",
                                                                                "OTHER_FEATURE_REQUEST")


def test_promotion_that_could_not_save_its_request_publishes_nothing(cc, monkeypatch):
    from fd4f_support import _DocRef

    _, wl = cc
    real_set = _DocRef.set

    def set_(self, data, merge=False):
        if self._path.startswith("feature_requests/"):
            raise RuntimeError("firestore write failed")
        return real_set(self, data, merge=merge)

    monkeypatch.setattr(_DocRef, "set", set_)
    r, event, _ = _promote(wl, monkeypatch, FakeDB())
    assert r.status_code == 500 and event is None


# ======================================================================================= the two copies of the contract
def test_control_center_mirror_equals_the_gateway_contract():
    import workflow_gates as g

    with open(os.path.join(HERE, "..", "apps", "control-center", "routes", "workloads.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    values = {t.id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
              for t in n.targets if isinstance(t, ast.Name) and t.id in
              ("RESUMABLE_GATE_STATUSES", "TASK_DAG_COLLECTION", "TASK_DAG_STORED", "TASK_DAG_TOO_LARGE")}
    assert values == {"RESUMABLE_GATE_STATUSES": tuple(g.RESUMABLE_GATE_STATUSES),
                      "TASK_DAG_COLLECTION": g.TASK_DAG_COLLECTION, "TASK_DAG_STORED": g.TASK_DAG_STORED,
                      "TASK_DAG_TOO_LARGE": g.TASK_DAG_TOO_LARGE}


if __name__ == "__main__" and "--harness" in sys.argv:
    _harness()
