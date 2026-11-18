"""STAGE-DEADLINE (G5, owner 11-13): one stage-deadline mechanism for every gateway agent stage the workflow calls.

Plan: docs/planning/stage-deadline-and-callback-plan.md. Live cause: 11-13 ex08, the developer request hit the
workflow's 1800 s http.post cap (UNHANDLED) and the gateway kept working on an orphaned request.

Hermetic: no network, no cloud clients; fake LLM clients and an in-memory Firestore stand-in.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
import yaml
from fastapi.testclient import TestClient

from fd4f_support import FakeDB, gw  # noqa: F401  (gw is a fixture)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")
WORKFLOW = os.path.join(REPO, "workflows", "main_orchestrator.yaml")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)

import stage_deadline as sdm  # noqa: E402
from gate_errors import StageAbandonedError, StageDeadlineExceededError  # noqa: E402
from stage_deadline import StageMode  # noqa: E402

# Workflow step -> stage for every gateway agent stage the workflow calls (sync http.post or run_stage_job).
SYNC_PATHS = {"/agent/architect/decompose": "architect", "/agent/compliance/audit": "compliance",
              "/agent/developer/execute": "developer", "/agent/gatekeeper/verify": "gatekeeper",
              "/agent/qa/verify": "qa", "/agent/release/promote": "release"}
JOB_PATHS = {"/agent/architect/decompose-job": "architect", "/agent/developer/execute-job": "developer",
             "/agent/qa/verify-job": "qa"}
# Gateway /agent/* calls that are not stages: a 60 s Firestore read (resume) and the readiness GET.
NOT_STAGES = {"/agent/resume/outcome", "/agent/qa/readiness"}


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def _sd(stage="developer", mode=StageMode.SYNC, clock=None, **kw):
    return sdm.StageDeadline(sdm.budget_for(stage, mode), trace_id="tr-1", product_id="app",
                             clock=clock or time.monotonic, **kw)


def _tiny(monkeypatch, stage, mode=StageMode.SYNC, timeout=3, margin=2, grace=0.3):
    """A real (wall-clock) budget of a fraction of a second for runner tests."""
    monkeypatch.setattr(sdm, "ANSWER_GRACE_S", grace)
    monkeypatch.setitem(sdm.STAGE_BUDGETS, (stage, mode), sdm.StageBudget(stage, mode, timeout, margin))
    return sdm.budget_for(stage, mode)


# ===================================================================================== the budget table
def _workflow_agent_steps():
    doc = yaml.safe_load(open(WORKFLOW, encoding="utf-8"))
    found = []

    def walk(x):
        if isinstance(x, dict):
            for name, body in x.items():
                if isinstance(body, dict):
                    tr = body.get("try") if isinstance(body.get("try"), dict) else body
                    if isinstance(tr, dict) and tr.get("call") in ("http.post", "run_stage_job"):
                        found.append((name, tr))
                walk(body)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(doc["run_pipeline"]["steps"])
    return found


def test_budget_table_pins_every_gateway_agent_stage_of_the_workflow():
    """Single source of truth: every /agent/* stage the workflow calls has its row, equal to the YAML bound."""
    seen = set()
    for name, tr in _workflow_agent_steps():
        args = tr.get("args") or {}
        if tr["call"] == "run_stage_job":
            stage = JOB_PATHS[args["path"]]
            assert args["stage"] == stage, name
            row = sdm.budget_for(stage, StageMode.CALLBACK)
            assert row.workflow_timeout_s == args["await_timeout_s"], (name, row)
            seen.add(("job", stage))
            continue
        url = str(args.get("url", ""))
        if "gateway_url" not in url or "/agent/" not in url:
            continue
        path = url.split('"')[1]
        if path in NOT_STAGES:
            continue
        stage = SYNC_PATHS[path]
        timeout = args.get("timeout", 300)   # the Workflows default
        assert sdm.budget_for(stage, StageMode.SYNC).workflow_timeout_s == timeout, (name, timeout)
        seen.add(("sync", stage))
    assert {s for _, s in seen} == set(SYNC_PATHS.values())


def test_every_row_answers_inside_its_workflow_bound():
    for (stage, mode), b in sdm.STAGE_BUDGETS.items():
        assert b.stage == stage and b.mode is mode
        assert b.margin_s >= sdm.ANSWER_GRACE_S + 10, b
        assert b.answer_at_s + 10 <= b.workflow_timeout_s, b
        assert b.budget_s > sdm.SIDE_EFFECT_RESERVE_S, b


def test_qa_keeps_its_1500_s_deadline():
    assert sdm.budget_for("qa", StageMode.SYNC).budget_s == 1500


def test_developer_and_architect_sync_budgets_from_the_diagnosis():
    assert sdm.budget_for("developer", StageMode.SYNC).budget_s == 1650
    assert sdm.budget_for("architect", StageMode.SYNC).budget_s == 540


# ===================================================================================== the runner
def test_negative_in_time_returns_the_body_answer_unchanged():
    sd = _sd()
    sentinel = {"status": "SUCCESS", "files": [1, 2]}
    assert sdm.run_with_deadline(sd, lambda: sentinel) is sentinel
    assert sd.abandoned[0] == "ANSWERED" and not sd.tripped


def test_negative_in_time_exception_is_reraised_unchanged():
    err = ValueError("boom")

    def body():
        raise err
    with pytest.raises(ValueError) as ei:
        sdm.run_with_deadline(_sd(), body)
    assert ei.value is err


def test_negative_no_deadline_everything_is_a_no_op():
    assert sdm.current() is None and sdm.remaining_s() is None and sdm.llm_call_timeout_ms() is None
    sdm.checkpoint("x")
    sdm.mark("x")
    sdm.guard_side_effect("x")
    cfg = object()
    assert sdm.bound_llm_config(cfg, "x", types=None) is cfg


def test_late_stage_answers_typed_and_the_orphan_writes_nothing(monkeypatch):
    _tiny(monkeypatch, "developer")
    done, refused = threading.Event(), []

    def body():
        sdm.mark("developer.junior_done", task_completed="task-a")
        time.sleep(1.6)                      # past budget (1 s) + grace (0.3 s)
        try:
            sdm.guard_side_effect("developer.commit", reserve_s=0)
        except StageAbandonedError as e:
            refused.append(e)
        done.set()
        return {"status": "SUCCESS"}
    sd = _sd()
    t0 = time.monotonic()
    with pytest.raises(StageDeadlineExceededError) as ei:
        sdm.run_with_deadline(sd, body)
    assert time.monotonic() - t0 < 1.6      # answered at the deadline, not when the body ended
    body_ = ei.value.to_body()
    assert body_["error_class"] == "STAGE_DEADLINE_EXCEEDED" and body_["stage"] == "developer"
    assert body_["reason"] == "STAGE_DEADLINE" and ei.value.http_status == 504
    assert body_["details"]["progress"]["tasks_completed"] == ["task-a"]
    assert done.wait(3)
    assert refused and refused[0].reason == "ANSWERED"


def test_checkpoint_after_the_deadline_raises_and_wins_over_a_swallowing_body():
    clock = Clock()
    sd = _sd(clock=clock)
    clock.t += sd.budget.budget_s + 1
    with pytest.raises(StageDeadlineExceededError):
        sd.checkpoint("developer.junior")
    assert sd.tripped

    def body():   # a broad except swallowed the stop and returned a FAILED body
        try:
            sdm.checkpoint("developer.lead_wbs")
        except Exception:
            return {"status": "FAILED"}
    clock2 = Clock()
    sd2 = _sd(clock=clock2)
    clock2.t += sd2.budget.budget_s + 1    # past the deadline, before the hard answer
    with pytest.raises(StageDeadlineExceededError):
        sdm.run_with_deadline(sd2, body)


def test_side_effect_needs_its_reserve():
    clock = Clock()
    sd = _sd(clock=clock)
    clock.t += sd.budget.budget_s - 30      # 30 s left < 60 s reserve
    with pytest.raises(StageDeadlineExceededError):
        sd.guard_side_effect("developer.commit")
    sd2 = _sd()
    sd2.guard_side_effect("developer.commit")   # plenty left: no refusal


def test_abandoned_stage_refuses_new_work_and_logs_orphan(caplog):
    sd = _sd()
    sd.abandon("RUN_ENDED", "run is FAILED")
    with pytest.raises(StageAbandonedError) as ei:
        sd.checkpoint("developer.junior")
    assert ei.value.to_body()["error_class"] == "STAGE_ABANDONED" and ei.value.reason == "RUN_ENDED"
    with caplog.at_level(logging.WARNING, logger="castor.stage_deadline"):
        with pytest.raises(StageAbandonedError):
            sd.guard_side_effect("developer.commit")
    assert "ORPHAN_ABANDONED" in caplog.text


# ===================================================================================== per-call bound
def test_bound_llm_config_sets_the_remaining_budget_as_the_call_timeout():
    """RT F3: only in the last STAGE_CALL_HEADER_CEILING_S of the budget, and never above it."""
    from google.genai import types
    from developer_agent import llm_transport
    clock = Clock()
    sd = _sd(clock=clock)
    token = sdm._CURRENT.set(sd)
    try:
        cfg = types.GenerateContentConfig(temperature=0.2)
        early = sdm.bound_llm_config(cfg, "developer.junior", types=types)
        assert early is cfg and cfg.http_options is None     # plenty of budget: the request is today's, unchanged
        assert sdm.bound_llm_config({"temperature": 0.1}, "architect.red_team", types=types) == {"temperature": 0.1}
        clock.t += sd.budget.budget_s - 90                      # 90 s left
        out = sdm.bound_llm_config(cfg, "developer.junior", types=types)
        assert cfg.http_options is None                       # the caller's config is not mutated
        assert abs(out.http_options.timeout - 90_000) < 2000
        assert out.http_options.timeout <= llm_transport.STAGE_CALL_HEADER_CEILING_S * 1000
        d = sdm.bound_llm_config({"temperature": 0.1}, "architect.red_team", types=types)
        assert d["temperature"] == 0.1 and 0 < d["http_options"].timeout <= 120_000
    finally:
        sdm._CURRENT.reset(token)


def test_transport_seam_signature():
    from developer_agent import llm_transport
    assert llm_transport.STAGE_CALL_HEADER_CEILING_S == 120   # the QA judge's live-proven X-Server-Timeout (RT F3)
    assert llm_transport.call_timeout_ms(3600.0) is None      # no header while the stage has time
    assert llm_transport.call_timeout_ms(120.0) == 120_000
    assert llm_transport.call_timeout_ms(12.5) == 12500
    assert llm_transport.call_timeout_ms(0.0) == llm_transport.STAGE_CALL_MIN_TIMEOUT_MS


def test_bind_context_carries_the_deadline_into_a_thread_pool():
    sd = _sd()
    token = sdm._CURRENT.set(sd)
    try:
        with ThreadPoolExecutor(2) as pool:
            plain = list(pool.map(lambda _: sdm.current(), [1, 2]))
            bound = list(pool.map(sdm.bind_context(lambda _: sdm.current()), [1, 2]))
    finally:
        sdm._CURRENT.reset(token)
    assert plain == [None, None] and bound == [sd, sd]


# ===================================================================================== liveness probe
class _Doc:
    def __init__(self, db, path):
        self.db, self.path = db, path

    def get(self):
        if self.db.fail:
            raise RuntimeError("store down")
        data = self.db.docs.get(self.path)
        return SimpleNamespace(exists=data is not None, to_dict=lambda: dict(data or {}))

    def collection(self, name):
        return _Col(self.db, f"{self.path}/{name}")


class _Col:
    def __init__(self, db, path):
        self.db, self.path = db, path

    def document(self, doc_id):
        return _Doc(self.db, f"{self.path}/{doc_id}")


class _DB:
    def __init__(self, docs=None):
        self.docs, self.fail = dict(docs or {}), False

    def collection(self, name):
        return _Col(self, name)


def test_probe_run_ended_superseded_and_kill_switch():
    db = _DB({"pipeline_executions/tr-1": {"status": "RUNNING", "workflow_execution_id": "exec-1"},
              "pipeline_executions/tr-1/stage_jobs/developer": {"job_id": "job-a"}})
    assert sdm.run_probe(db, "tr-1", execution_id="exec-1", stage_job=("developer", "job-a"))() is None
    assert sdm.run_probe(db, "tr-1", execution_id="exec-2")()[0] == "SUPERSEDED"
    assert sdm.run_probe(db, "tr-1", stage_job=("developer", "job-b"))()[0] == "SUPERSEDED"
    assert sdm.run_probe(db, "tr-1", kill_switch=lambda: True)()[0] == "KILL_SWITCH_ACTIVE"
    db.docs["pipeline_executions/tr-1"]["status"] = "ABORTED"
    assert sdm.run_probe(db, "tr-1")()[0] == "RUN_ENDED"
    # a full execution name compares by its id segment, exactly
    db.docs["pipeline_executions/tr-1"] = {"workflow_execution_name": "projects/1/locations/l/workflows/w/executions/exec-1"}
    assert sdm.run_probe(db, "tr-1", execution_id="exec-1")() is None


def test_probe_read_failure_never_stops_a_stage_and_is_rate_limited():
    db = _DB()
    db.fail = True
    clock = Clock()
    sd = _sd(clock=clock, probe=sdm.run_probe(db, "tr-1"))
    sd.checkpoint("a")                   # logged, not raised
    calls = []
    sd2 = _sd(clock=clock, probe=lambda: calls.append(1))
    sd2.checkpoint("a")
    sd2.checkpoint("b")
    assert len(calls) == 1               # PROBE_INTERVAL_S
    sd2.guard_side_effect("commit")      # a side effect always re-reads
    assert len(calls) == 2


def test_probe_stops_the_stage_at_the_next_checkpoint():
    db = _DB({"pipeline_executions/tr-1": {"status": "RUNNING"}})
    sd = _sd(probe=sdm.run_probe(db, "tr-1"))
    sd.checkpoint("wave_1")
    db.docs["pipeline_executions/tr-1"]["status"] = "FAILED"
    sd._probe_at = None
    with pytest.raises(StageAbandonedError) as ei:
        sd.checkpoint("wave_2")
    assert ei.value.reason == "RUN_ENDED"


# ===================================================================================== cooperative call sites
class _NeverCalledModels:
    def __init__(self):
        self.calls = 0

    def generate_content(self, **kw):
        self.calls += 1
        raise AssertionError("an LLM call started after the stage deadline")


@pytest.fixture()
def no_settings(monkeypatch):
    """Platform settings unreadable (no Firestore in tests): the call sites use their defaults."""
    import shared.settings as settings

    def unreadable(*a, **k):
        raise RuntimeError("no settings store in tests")
    monkeypatch.setattr(settings, "get_platform_settings", unreadable)


def _expired_context():
    clock = Clock()
    sd = _sd(clock=clock)
    clock.t += sd.budget.budget_s + 1
    return sd


def test_repair_call_is_never_started_after_the_deadline(no_settings):
    from developer_agent.swarm_dispatcher import SwarmDispatcher
    models = _NeverCalledModels()
    disp = SwarmDispatcher(genai_client=SimpleNamespace(models=models), model_name="gemini-3.7-flash", db=None)
    token = sdm._CURRENT.set(_expired_context())
    try:
        with pytest.raises(StageDeadlineExceededError):
            disp.invoke_repair("BACKEND_ENGINEER", "sys", "prompt", "gemini-3.7-flash", 4096)
    finally:
        sdm._CURRENT.reset(token)
    assert models.calls == 0


def test_junior_call_is_never_started_after_the_deadline(no_settings):
    import asyncio

    from developer_agent.swarm_dispatcher import SwarmDispatcher
    models = _NeverCalledModels()
    disp = SwarmDispatcher(genai_client=SimpleNamespace(models=models), model_name="gemini-3.7-flash", db=None)
    token = sdm._CURRENT.set(_expired_context())
    try:
        with pytest.raises(StageDeadlineExceededError):
            asyncio.run(disp._call_gemini_with_backoff("p", "sys", "gemini-3.7-flash"))
    finally:
        sdm._CURRENT.reset(token)
    assert models.calls == 0


def test_lead_never_falls_back_to_the_deterministic_plan_after_the_deadline(monkeypatch, no_settings):
    from developer_agent import lead_orchestrator
    from developer_agent.lead_orchestrator import LeadDeveloperOrchestrator
    monkeypatch.setattr(lead_orchestrator, "get_model_cascade_for_agent", lambda *a, **k: ["gemini-3.7-flash"])
    models = _NeverCalledModels()
    lead = LeadDeveloperOrchestrator(genai_client=SimpleNamespace(models=models), model_name="gemini-3.7-flash",
                                     db=None, project_id="")
    token = sdm._CURRENT.set(_expired_context())
    try:
        with pytest.raises(StageDeadlineExceededError):
            lead.decompose_specification(product_id="app", spec_text="a todo app", task_dag=[])
    finally:
        sdm._CURRENT.reset(token)
    assert models.calls == 0


def _calls_in_order(fn_node, first, second):
    """Line of the first call to `first` and of the first call to `second` inside a function."""
    lines = {}
    for node in ast.walk(fn_node):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if name in (first, second) and name not in lines:
                lines[name] = node.lineno
    return lines.get(first), lines.get(second)


def test_commit_and_release_merge_are_guarded_before_any_write():
    src = open(os.path.join(GW_DIR, "developer_agent", "handler.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "commit_and_open_pr")
    guard, token = _calls_in_order(fn, "guard_side_effect", "fetch_github_token")
    assert guard and token and guard < token
    main_src = open(os.path.join(GW_DIR, "main.py"), encoding="utf-8").read()
    merge = next(n for n in ast.walk(ast.parse(main_src))
                 if isinstance(n, ast.FunctionDef) and n.name == "_release_merge")
    assert ast.get_docstring(merge)   # RT S2: the guard sits below the docstring
    first_stmt = merge.body[1]
    assert "guard_side_effect" in ast.unparse(first_stmt)


def test_pr_after_a_slow_commit_and_the_release_approval_are_guarded():
    """RT S1 / S3: the PR is guarded on its own (a commit that outlived the answer opens no PR); the release approval
    record and the certificate comment are guarded before their writes."""
    src = open(os.path.join(GW_DIR, "developer_agent", "handler.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "commit_and_open_pr")
    labels = [ast.literal_eval(c.args[0]) for c in ast.walk(fn) if isinstance(c, ast.Call)
              and getattr(c.func, "attr", None) == "guard_side_effect"]
    assert labels == ["developer.commit", "developer.pr"] or sorted(labels) == ["developer.commit", "developer.pr"]
    pr_guard = next(c.lineno for c in ast.walk(fn) if isinstance(c, ast.Call)
                    and getattr(c.func, "attr", None) == "guard_side_effect" and c.args[0].value == "developer.pr")
    pr_call = next(c.lineno for c in ast.walk(fn) if isinstance(c, ast.Call)
                   and getattr(c.func, "attr", None) == "create_pull_request")
    assert pr_guard < pr_call
    main_src = open(os.path.join(GW_DIR, "main.py"), encoding="utf-8").read()
    i_guard = main_src.index('guard_side_effect("release.approval", reserve_s=0)')
    assert i_guard < main_src.index('db.collection("approval_requests").document(created_approval_id).set(')
    assert main_src.index('guard_side_effect("release.certificate_comment"') < main_src.index(
        "post_release_certificate_to_vcs(\n")


# ===================================================================================== QA (RT F1)
def _qa_fixture(gw, monkeypatch, judge=None):
    from fd4f_support import FakeBackend, FakeQAClient, SHA_A, SHA_B, backend_factory, judge_reply, passing_outcome
    from fd4f_support import seed_context
    import qa_auditor.judge as judge_mod
    db = FakeDB()
    seed_context(db)
    client = FakeQAClient(passing_outcome())
    backend = FakeBackend({"castor/app-1": {"apps/app/main.py": b"x\n"}, "main": {"README.md": b"x\n"}},
                          {"castor/app-1": SHA_A, "main": SHA_B})
    gw.app.dependency_overrides[gw.get_qa_job_client] = lambda: client
    gw.app.dependency_overrides[gw.get_source_backend_factory] = lambda: backend_factory(backend)
    gw.app.dependency_overrides[gw.get_evidence_db] = lambda: db
    monkeypatch.setattr(judge_mod, "call", judge or judge_reply())
    return client, db


def _qa_post(gw):
    return TestClient(gw.app).post("/agent/qa/verify", json={"trace_id": "tr-1", "product_id": "app",
                                                             "branch_name": "castor/app-1"})


def test_negative_qa_in_time_writes_evidence_and_answers_as_before(gw, monkeypatch):
    client, db = _qa_fixture(gw, monkeypatch)
    r = _qa_post(gw)
    assert r.status_code == 200 and r.json()["passed"] is True
    assert len(client.calls) == 1 and db.collection("qa_test_runs").document("tr-1").get().exists


@pytest.mark.parametrize("reason", ["KILL_SWITCH_ACTIVE", "RUN_ENDED", "SUPERSEDED"])
def test_qa_job_is_never_started_after_a_stop(gw, monkeypatch, reason):
    client, db = _qa_fixture(gw, monkeypatch)
    monkeypatch.setattr(gw, "_stage_liveness_probe", lambda *a, **k: (lambda: (reason, f"stop: {reason}")))
    r = _qa_post(gw)
    assert r.status_code == 409, r.text
    assert r.json()["error_class"] == "STAGE_ABANDONED" and r.json()["reason"] == reason
    assert client.calls == [] and not db.collection("qa_test_runs").document("tr-1").get().exists


def test_qa_judge_stops_and_evidence_is_not_written_after_a_stop_mid_stage(gw, monkeypatch):
    """A stop that arrives after the QA job ran: the judge's checkpoint refuses (inside the lens thread: the
    coordinator binds the context) and the evidence write is refused; the answer is typed STAGE_ABANDONED."""
    state = {"stop": False, "judge_calls": 0}
    client, db = _qa_fixture(gw, monkeypatch)
    real_run = client.run

    def run_then_stop(**kw):
        out = real_run(**kw)
        state["stop"] = True
        return out
    monkeypatch.setattr(client, "run", run_then_stop)
    monkeypatch.setattr(sdm, "PROBE_INTERVAL_S", 0.0)
    monkeypatch.setattr(gw, "_stage_liveness_probe",
                        lambda *a, **k: (lambda: ("RUN_ENDED", "run tr-1 is ABORTED") if state["stop"] else None))
    r = _qa_post(gw)
    assert r.status_code == 409, r.text
    assert r.json()["error_class"] == "STAGE_ABANDONED"
    assert not db.collection("qa_test_runs").document("tr-1").get().exists


def test_judge_checkpoint_is_outside_its_transport_retry(no_settings):
    import qa_auditor.judge as judge_mod
    sd = _sd("qa")
    sd.abandon("KILL_SWITCH_ACTIVE", "stop")
    calls = []

    class Models:
        def generate_content(self, **kw):
            calls.append(kw)
            raise AssertionError("never called")
    tok = sdm._CURRENT.set(sd)
    try:
        with pytest.raises(StageAbandonedError):
            judge_mod.call("p", "m", client=SimpleNamespace(models=Models()), validate=lambda t: t)
    finally:
        sdm._CURRENT.reset(tok)
    assert calls == []


def test_every_developer_llm_call_site_is_bounded():
    """Every generate_content of the developer, architect and compliance stages goes through bound_llm_config (or a
    checkpoint right before a legacy model call). SLOW-CALL-FALLBACK RT F3: on the developer path the CallWalk is the
    one writer of http_options (`walk.config(...)`, min(cap, stage time left)), with the checkpoint kept before it."""
    for rel in ("developer_agent/handler.py", "developer_agent/lead_orchestrator.py",
                "developer_agent/swarm_dispatcher.py", "architect_agent/handler.py", "architect_agent/red_team_critic.py",
                "architect_agent/spec_decomposer.py", "compliance_agent/handler.py"):
        tree = ast.parse(open(os.path.join(GW_DIR, rel), encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                    node.func.attr == "generate_content" and isinstance(node.func.value, ast.Attribute) and \
                    node.func.value.attr == "models":
                cfg = next((k.value for k in node.keywords if k.arg == "config"), None)
                assert cfg is not None and ("bound_llm_config" in ast.unparse(cfg) or
                                            "call_config" in ast.unparse(cfg) or
                                            (rel.startswith("developer_agent/") and
                                             "walk.config(" in ast.unparse(cfg))), (rel, node.lineno)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                    node.func.attr == "to_thread":
                cfg = next((k.value for k in node.keywords if k.arg == "config"), None)
                if cfg is not None:
                    assert "bound_llm_config" in ast.unparse(cfg) or (
                        rel.startswith("developer_agent/") and "walk.config(" in ast.unparse(cfg)), (rel, node.lineno)


# ===================================================================================== endpoints
def test_sync_developer_route_answers_504_typed_when_late(gw, monkeypatch):
    _tiny(monkeypatch, "developer")
    after = []

    def slow_body(req):
        time.sleep(1.6)
        try:
            sdm.guard_side_effect("developer.commit", reserve_s=0)
            after.append("COMMITTED")
        except StageAbandonedError:
            after.append("REFUSED")
        return {"status": "SUCCESS"}
    monkeypatch.setattr(gw, "_developer_execute_body", slow_body)
    r = TestClient(gw.app).post("/agent/developer/execute", json={"trace_id": "tr-1", "product_id": "app"})
    assert r.status_code == 504, r.text
    body = r.json()
    assert body["error_class"] == "STAGE_DEADLINE_EXCEEDED" and body["stage"] == "developer"
    assert body["status"] == "FAILED" and body["passed"] is False
    deadline = time.monotonic() + 3
    while not after and time.monotonic() < deadline:
        time.sleep(0.05)
    assert after == ["REFUSED"]


def test_negative_sync_developer_route_in_time_is_unchanged(gw, monkeypatch):
    answer = {"status": "SUCCESS", "branch_name": "castor/app-1", "files_committed": ["a.py"], "commit_sha": "c" * 40}
    monkeypatch.setattr(gw, "_developer_execute_body", lambda req: dict(answer))
    r = TestClient(gw.app).post("/agent/developer/execute", json={"trace_id": "tr-1", "product_id": "app"})
    assert r.status_code == 200 and r.json() == answer


def test_negative_typed_gate_error_keeps_its_status_and_body(gw, monkeypatch):
    from gate_errors import GateUnavailableError

    def body(req):
        raise GateUnavailableError("judge down", reason="JUDGE_UNAVAILABLE", stage="qa")
    monkeypatch.setattr(gw, "_architect_decompose_body", body)
    r = TestClient(gw.app).post("/agent/architect/decompose", json={"trace_id": "tr-1", "product_id": "app"})
    assert r.status_code == 503 and r.json()["reason"] == "JUDGE_UNAVAILABLE"


def test_every_sync_stage_route_runs_under_its_deadline(gw, monkeypatch):
    seen = {}
    real = sdm.run_with_deadline

    def spy(sd, fn):
        seen[sd.stage] = sd.budget.mode
        return real(sd, lambda: {"status": "SUCCESS", "passed": True})
    monkeypatch.setattr(sdm, "run_with_deadline", spy)
    c = TestClient(gw.app)
    c.post("/agent/architect/decompose", json={"trace_id": "tr-1", "product_id": "app"})
    c.post("/agent/compliance/audit", json={"trace_id": "tr-1", "product_id": "app"})
    c.post("/agent/developer/execute", json={"trace_id": "tr-1", "product_id": "app"})
    c.post("/agent/gatekeeper/verify", json={"trace_id": "tr-1", "product_id": "app", "branch_name": "b"})
    c.post("/agent/qa/verify", json={"trace_id": "tr-1", "product_id": "app", "branch_name": "b"})
    c.post("/agent/release/promote", json={"trace_id": "tr-1", "product_id": "app", "branch_name": "b"})
    assert seen == {s: StageMode.SYNC for s in SYNC_PATHS.values()}


def test_qa_uses_the_stage_deadline(gw, monkeypatch):
    from fd4f_support import FakeBackend, FakeQAClient, SHA_A, SHA_B, backend_factory, judge_reply, passing_outcome
    from fd4f_support import seed_context
    import qa_auditor.judge as judge_mod
    db = FakeDB()
    seed_context(db)
    client = FakeQAClient(passing_outcome())
    backend = FakeBackend({"castor/app-1": {"apps/app/main.py": b"x\n"}, "main": {"README.md": b"x\n"}},
                          {"castor/app-1": SHA_A, "main": SHA_B})
    gw.app.dependency_overrides[gw.get_qa_job_client] = lambda: client
    gw.app.dependency_overrides[gw.get_source_backend_factory] = lambda: backend_factory(backend)
    gw.app.dependency_overrides[gw.get_evidence_db] = lambda: db
    monkeypatch.setattr(judge_mod, "call", judge_reply())
    t0 = time.monotonic()
    r = TestClient(gw.app).post("/agent/qa/verify", json={"trace_id": "tr-1", "product_id": "app",
                                                          "branch_name": "castor/app-1"})
    assert r.status_code == 200, r.text
    assert abs(client.calls[0]["deadline"] - (t0 + 1500)) < 5
    assert gw.QA_REQUEST_DEADLINE_S == 1500


# ===================================================================================== workflow routing
def test_workflow_keeps_a_typed_developer_deadline_and_never_retries_it():
    from test_lane17_workflow_sim import Fleet, assert_failed, calls, load_workflow, run
    wf = load_workflow(WORKFLOW)
    body = {"status": "FAILED", "passed": False, "error_class": "STAGE_DEADLINE_EXCEEDED", "stage": "developer",
            "reason": "STAGE_DEADLINE", "summary": "developer stage deadline exceeded",
            "details": {"progress": {"tasks_completed": ["t1"]}}}
    res, _ = run(wf, Fleet(**{"/agent/developer/execute": (504, body)}))
    assert_failed(res, "STAGE_DEADLINE_EXCEEDED", "developer")
    assert res.error["reason"] == "STAGE_DEADLINE" and res.error["remediable"] is False
    assert len(calls(res, "/agent/developer/execute")) == 1 and not calls(res, "/agent/qa/verify")


def test_workflow_keeps_a_typed_qa_deadline_and_never_loops_to_the_developer():
    from test_lane17_workflow_sim import Fleet, assert_failed, calls, load_workflow, run
    wf = load_workflow(WORKFLOW)
    body = {"status": "FAILED", "passed": False, "error_class": "STAGE_DEADLINE_EXCEEDED", "stage": "qa",
            "reason": "STAGE_DEADLINE", "summary": "qa deadline", "retryable": True}
    res, _ = run(wf, Fleet(**{"/agent/qa/verify": (504, body)}))
    assert_failed(res, "STAGE_DEADLINE_EXCEEDED", "qa")
    assert len(calls(res, "/agent/developer/execute")) == 1


def test_workflow_keeps_a_typed_architect_deadline():
    from test_lane17_workflow_sim import VEND, Fleet, assert_failed, calls, load_workflow, run
    wf = load_workflow(WORKFLOW)
    body = {"status": "FAILED", "error_class": "STAGE_DEADLINE_EXCEEDED", "stage": "architect",
            "reason": "STAGE_DEADLINE", "summary": "architect deadline"}
    res, _ = run(wf, Fleet(**{"/agent/architect/decompose": (504, body)}))
    assert_failed(res, "STAGE_DEADLINE_EXCEEDED", "architect")
    assert not calls(res, VEND)
