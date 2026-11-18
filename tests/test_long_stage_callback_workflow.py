"""LONG-STAGE-CALLBACK (owner 11-13): workflows/main_orchestrator.yaml runs the architect, developer and QA stages as
gateway jobs answered by callback (subworkflow run_stage_job), executed offline in tests/workflow_sim.py.

The shared Fleet (tests/test_lane17_workflow_sim.py) answers the job routes and delivers the synchronous route's
answer on the job's callback, so the whole lane 17 scenario suite runs through the callback path unchanged. This file
adds the callback-specific cases: await timeout, malformed callback, dispatch retry, refused dispatch, gateway
contract. Plan: docs/planning/stage-deadline-and-callback-plan.md §4-5.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os

import pytest
import yaml

from test_lane17_workflow_sim import (VEND, Fleet, assert_failed, calls, run, workflow)  # noqa: F401
from workflow_sim import SimTimeout, http_error, validate

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKFLOW = os.path.join(REPO, "workflows", "main_orchestrator.yaml")
JOBS = {"architect": "/agent/architect/decompose-job", "developer": "/agent/developer/execute-job",
        "qa": "/agent/qa/verify-job"}
SYNC = {"architect": "/agent/architect/decompose", "developer": "/agent/developer/execute",
        "qa": "/agent/qa/verify"}


def _urls(res, part):
    return [c["url"] for c in calls(res, part)]


def test_workflow_validates_with_the_subworkflow(workflow):
    validate(workflow)
    doc = yaml.safe_load(open(WORKFLOW, encoding="utf-8"))
    assert doc["run_stage_job"]["params"] == ["gateway_url", "path", "sync_path", "sync_timeout_s", "stage",
                                              "request", "await_timeout_s", "failure_message"]


def test_happy_path_runs_three_stage_jobs_and_no_synchronous_stage_call(workflow):
    res, fleet = run(workflow)
    assert res.state == "SUCCEEDED", res.error
    for stage, path in JOBS.items():
        urls = _urls(res, SYNC[stage])
        assert urls and all(u.endswith(path) for u in urls), (stage, urls)
    assert [k for k, _ in fleet.jobs_started] == [JOBS["architect"], JOBS["developer"], JOBS["qa"]]
    # every await is the stage's own callback, in slices of at most 300 s (STAGE-JOB-RUNNER)
    awaits = {c["url"]: c["timeout"] for c in res.callbacks if c["event"] == "await"}
    assert sorted(awaits[cb] for _, cb in fleet.jobs_started) == [300, 300, 300]
    assert not calls(res, "/agent/stage-job/state")      # answered in the first slice: no probe needed


def test_job_request_is_the_former_synchronous_body_plus_the_callback_url(workflow):
    res, fleet = run(workflow)
    [dev] = calls(res, JOBS["developer"])
    body = dev["body"]
    assert body["callback_url"] == next(cb for k, cb in fleet.jobs_started if k == JOBS["developer"])
    for key in ("trace_id", "product_id", "spec_text", "task_dag", "retry_count", "tf_retry_count",
                "tf_remediation_context", "tf_validation_report", "plan_markdown", "plan_file_path",
                "compliance_trace_id", "allow_unauthenticated", "enable_direct_iap"):
        assert key in body, key
    [qa] = calls(res, JOBS["qa"])
    assert qa["body"]["expected_commit_sha"] == "c" * 40 and qa["body"]["attempt"] == 0
    assert dev["args"]["timeout"] == 60   # the dispatch itself is short; the stage is bounded by the await


AWAIT = {"architect": 2100, "developer": 3900, "qa": 3000}


@pytest.mark.parametrize("stage", ["architect", "developer", "qa"])
def test_await_timeout_is_stage_timeout_never_unhandled(workflow, stage):
    res, _ = run(workflow, Fleet(**{SYNC[stage]: SimTimeout("no callback")}))
    assert_failed(res, "STAGE_TIMEOUT", stage)
    assert res.error["reason"] == "STAGE_CALLBACK_TIMEOUT" and res.error["remediable"] is False
    # the await is sliced (<= 300 s each) and adds up to exactly the budget-table bound; the job is probed between
    slices = [c["timeout"] for c in res.callbacks if c["event"] == "await" and c["timeout"] <= 300][-((AWAIT[stage] + 299) // 300):]
    assert sum(slices) == AWAIT[stage] and max(slices) == 300
    assert len(calls(res, "/agent/stage-job/state")) == len(slices) - 1
    if stage == "qa":
        assert len(calls(res, JOBS["developer"])) == 1   # never a developer retry
    if stage == "architect":
        assert not calls(res, VEND)


def test_typed_failure_by_callback_keeps_class_reason_and_stage(workflow):
    body = {"status": "FAILED", "passed": False, "error_class": "PLATFORM_DEFECT", "reason": "COMMIT_SET_INVALID",
            "stage": "developer", "summary": "commit set invalid"}
    res, _ = run(workflow, Fleet(**{"/agent/developer/execute": (503, body)}))
    assert_failed(res, "PLATFORM_DEFECT", "developer")
    assert res.error["reason"] == "COMMIT_SET_INVALID"
    assert res.error["message"].startswith("Developer implementation failed")
    assert res.error["raw_error"]["code"] == 503 and "HttpError" in res.error["raw_error"]["tags"]


def test_untyped_error_by_callback_is_dependency_failed_as_before(workflow):
    res, _ = run(workflow, Fleet(**{"/agent/developer/execute": (500, {"detail": "Developer execution failed"})}))
    assert_failed(res, "DEPENDENCY_FAILED", "developer")


def test_malformed_callback_is_a_contract_violation(workflow):
    f = Fleet()
    real = f.callback

    def callback(url, timeout):
        if f.callback_owner.get(url) == "stage":
            return {"http_status": "200", "body": {"status": "SUCCESS"}}
        return real(url, timeout)
    f.callback = callback
    res, _ = run(workflow, f)
    assert_failed(res, "CONTRACT_VIOLATION", "architect")
    assert res.error["reason"] == "STAGE_CALLBACK_CONTRACT"


def test_dispatch_is_retried_and_starts_one_job(workflow):
    f = Fleet()
    f.job_dispatch[JOBS["developer"]] = [(503, {"detail": "cold start"})]
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    dispatches = calls(res, JOBS["developer"])
    assert len(dispatches) == 2 and dispatches[0]["body"]["callback_url"] == dispatches[1]["body"]["callback_url"]
    assert [k for k, _ in f.jobs_started].count(JOBS["developer"]) == 1


def test_refused_dispatch_is_typed_and_not_retried(workflow):
    f = Fleet()
    f.job_dispatch[JOBS["developer"]] = [(409, {"status": "FAILED", "error_class": "CONTRACT_VIOLATION",
                                                "reason": "CALLBACK_URL_REJECTED", "stage": "developer",
                                                "summary": "callback URL refused"})]
    res, _ = run(workflow, f)
    assert_failed(res, "CONTRACT_VIOLATION", "developer")
    assert res.error["reason"] == "CALLBACK_URL_REJECTED" and len(calls(res, JOBS["developer"])) == 1
    assert not calls(res, JOBS["qa"])


def test_new_workflow_refuses_an_old_gateway(workflow):
    res, _ = run(workflow, Fleet(**{"/health": (200, {"status": "healthy", "workflow_contract": 2})}))
    assert_failed(res, "GATE_UNAVAILABLE", "gateway_contract")
    assert not calls(res, "/agent/architect")


def test_qa_code_defect_loop_runs_through_callbacks(workflow):
    defect = (200, {"passed": False, "error_class": "CODE_DEFECT", "retryable": True, "summary": "tests failed"})
    passed = (200, {"passed": True, "error_class": None, "summary": "QA passed"})
    res, f = run(workflow, Fleet(**{"/agent/qa/verify": [defect, passed]}))
    assert res.state == "SUCCEEDED", res.error
    assert [k for k, _ in f.jobs_started].count(JOBS["developer"]) == 2
    assert [c["body"]["retry_count"] for c in calls(res, JOBS["developer"])] == [0, 1]
    assert len({cb for _, cb in f.jobs_started}) == len(f.jobs_started)   # a fresh callback per attempt


def test_stage_failure_never_reaches_build_failure_untyped():
    """The subworkflow raises only typed failures (StackVendPipelineError maps or build_failure's result)."""
    doc = yaml.safe_load(open(WORKFLOW, encoding="utf-8"))
    raises = []

    def walk(x):
        if isinstance(x, dict):
            if "raise" in x:
                raises.append(x["raise"])
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(doc["run_stage_job"])
    assert raises and all(r == "${pipeline_failure}" or r.get("tag") == "StackVendPipelineError" for r in raises)


def test_http_error_shape_matches_the_simulator(workflow):
    """The HttpError-shaped map the subworkflow builds has the fields build_failure reads (tags, code, body)."""
    ref = http_error(503, {"error_class": "X"})
    assert {"tags", "code", "body"} <= set(ref)


# ===================================================================================== STAGE-JOB-RUNNER + RT F4
@pytest.mark.parametrize("stage", ["architect", "developer", "qa"])
def test_a_job_that_ended_without_an_answer_is_stage_interrupted_at_the_next_probe(workflow, stage):
    """A hard kill (OOM / SIGKILL): no callback; the probe after the first slice reports DEAD; after one short drain
    the stage ends STAGE_INTERRUPTED (typed), not at the await bound."""
    dead = (200, {"state": "DEAD", "reason": "EXECUTION_ENDED_WITHOUT_ANSWER", "detail": "execution ended"})
    res, _ = run(workflow, Fleet(**{SYNC[stage]: SimTimeout("no callback"), "/agent/stage-job/state": dead}))
    assert_failed(res, "STAGE_INTERRUPTED", stage)
    assert res.error["reason"] == "STAGE_JOB_EXECUTION_ENDED_WITHOUT_ANSWER" and res.error["remediable"] is False
    assert len(calls(res, "/agent/stage-job/state")) == 1
    assert [c["timeout"] for c in res.callbacks if c["event"] == "await"][-2:] == [300, 30]
    if stage == "qa":
        assert len(calls(res, JOBS["developer"])) == 1   # never a developer retry


def test_probe_query_names_the_trace_stage_and_job(workflow):
    f = Fleet(**{SYNC["developer"]: SimTimeout("no callback")})
    res, _ = run(workflow, f)
    q = calls(res, "/agent/stage-job/state")[0]["args"]["query"]
    assert q == {"trace_id": "tr-sim-1", "stage": "developer", "job_id": "job-2"}


def test_unreadable_probe_never_fails_the_stage(workflow):
    f = Fleet(**{"/agent/stage-job/state": (503, {"detail": "store down"})})
    seen = {"n": 0}
    real = f.callback

    def callback(url, timeout):
        if f.callback_owner.get(url) == "stage" and seen["n"] < 2:
            seen["n"] += 1
            raise SimTimeout("not yet")
        return real(url, timeout)
    f.callback = callback
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    assert len(calls(res, "/agent/stage-job/state")) == 2


def test_answer_after_a_few_slices_is_taken(workflow):
    f = Fleet()
    seen = {"n": 0}
    real = f.callback

    def callback(url, timeout):
        if f.callback_owner.get(url) == "stage" and seen["n"] < 4:
            seen["n"] += 1
            raise SimTimeout("still running")
        return real(url, timeout)
    f.callback = callback
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    assert len(calls(res, "/agent/stage-job/state")) == 4


@pytest.mark.parametrize("health", [{"status": "healthy", "workflow_contract": 3, "stage_jobs_enabled": False},
                                    {"status": "healthy", "workflow_contract": 3}])
def test_switch_off_runs_the_synchronous_routes_exactly_as_before(workflow, health):
    """RT F4: rollback = a gateway deploy that reports stage_jobs_enabled false (or a gateway without the field)."""
    res, fleet = run(workflow, Fleet(**{"/health": (200, health)}))
    assert res.state == "SUCCEEDED", res.error
    assert fleet.jobs_started == []
    timeouts = {}
    for stage, path in SYNC.items():
        [c] = [c for c in calls(res, path) if c["url"].endswith(path)]
        assert "callback_url" not in c["body"]
        timeouts[stage] = c["args"]["timeout"]
    assert timeouts == {"architect": 600, "developer": 1800, "qa": 1800}   # the pre-LONG-STAGE-CALLBACK bounds
    assert not [c for c in calls(res, "-job")]


def test_switch_off_keeps_the_synchronous_failure_routing(workflow):
    body = {"status": "FAILED", "passed": False, "error_class": "PLATFORM_DEFECT", "reason": "COMMIT_SET_INVALID",
            "stage": "developer", "summary": "commit set invalid"}
    res, _ = run(workflow, Fleet(**{"/health": (200, {"status": "healthy", "workflow_contract": 3,
                                                      "stage_jobs_enabled": False}),
                                    "/agent/developer/execute": (503, body)}))
    assert_failed(res, "PLATFORM_DEFECT", "developer")
    assert res.error["reason"] == "COMMIT_SET_INVALID"


def test_sync_fallback_timeouts_equal_the_sync_budget_rows():
    """The fallback's http.post timeouts are the SYNC rows' workflow bounds (stage_deadline.STAGE_BUDGETS)."""
    import sys
    gw_dir = os.path.join(REPO, "apps", "orchestrator-gateway")
    if gw_dir not in sys.path:
        sys.path.insert(0, gw_dir)
    import stage_deadline as sdm
    doc = yaml.safe_load(open(WORKFLOW, encoding="utf-8"))
    found = {}

    def walk(x):
        if isinstance(x, dict):
            if x.get("call") == "run_stage_job":
                a = x["args"]
                found[a["stage"]] = (a["sync_path"], a["sync_timeout_s"], a["await_timeout_s"])
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(doc)
    assert set(found) == {"architect", "developer", "qa"}
    for stage, (sync_path, sync_t, await_t) in found.items():
        assert sync_path == SYNC[stage]
        assert sync_t == sdm.budget_for(stage, sdm.StageMode.SYNC).workflow_timeout_s
        assert await_t == sdm.budget_for(stage, sdm.StageMode.CALLBACK).workflow_timeout_s


# ===================================================================================== typed results through the callback
TYPED_QA = [
    {"error_class": "PLATFORM_DEFECT", "reason": "QA_FINDING_ON_PLATFORM_RENDERED_FILE"},
    {"error_class": "OPERATOR_ACTION_REQUIRED", "reason": "QA_FINDING_ON_UNOWNED_FILE"},
]


def _health(jobs):
    return {"/health": (200, {"status": "healthy", "workflow_contract": 3, "stage_jobs_enabled": jobs})}


@pytest.mark.parametrize("jobs", [True, False])
@pytest.mark.parametrize("typed", TYPED_QA)
def test_typed_qa_verdict_keeps_class_reason_and_stage(workflow, jobs, typed):
    """A typed, non-retryable QA verdict (200) keeps class + reason + stage, remediable false, by callback and by the
    synchronous fallback alike; never a developer retry."""
    body = {"passed": False, "retryable": False, "stage": "qa", "summary": "finding on a file the developer does not own",
            **typed}
    res, _ = run(workflow, Fleet(**_health(jobs), **{"/agent/qa/verify": (200, body)}))
    assert_failed(res, typed["error_class"], "qa")
    assert res.error["reason"] == typed["reason"] and res.error["remediable"] is False
    assert len(calls(res, "/agent/developer/execute")) == 1


@pytest.mark.parametrize("jobs", [True, False])
def test_typed_developer_failure_in_a_2xx_keeps_class_reason_and_stage(workflow, jobs):
    body = {"status": "FAILED", "error_class": "OPERATOR_ACTION_REQUIRED", "reason": "QA_FINDING_ON_UNOWNED_FILE",
            "stage": "developer", "summary": "needs an operator", "error": "x"}
    res, _ = run(workflow, Fleet(**_health(jobs), **{"/agent/developer/execute": (200, body)}))
    assert_failed(res, "OPERATOR_ACTION_REQUIRED", "developer")
    assert res.error["reason"] == "QA_FINDING_ON_UNOWNED_FILE" and res.error["remediable"] is False


@pytest.mark.parametrize("jobs", [True, False])
@pytest.mark.parametrize("stage,path", [("developer", "/agent/developer/execute"), ("qa", "/agent/qa/verify")])
def test_typed_non_2xx_stage_result_is_identical_by_callback_and_synchronously(workflow, jobs, stage, path):
    """A typed non-2xx answer: the same class, reason, stage and remediable whether it came back by callback (job
    path) or as the synchronous response (switch off)."""
    body = {"status": "FAILED", "passed": False, "error_class": "PLATFORM_DEFECT",
            "reason": "QA_FINDING_ON_PLATFORM_RENDERED_FILE", "stage": stage, "summary": "platform-rendered file"}
    res, _ = run(workflow, Fleet(**_health(jobs), **{path: (503, body)}))
    assert_failed(res, "PLATFORM_DEFECT", stage)
    assert res.error["reason"] == "QA_FINDING_ON_PLATFORM_RENDERED_FILE" and res.error["remediable"] is False


def test_untyped_developer_2xx_failure_is_unchanged(workflow):
    res, _ = run(workflow, Fleet(**{"/agent/developer/execute": (200, {"status": "FAILED", "error": "boom"})}))
    assert_failed(res, "CONTRACT_VIOLATION", "developer")
    assert res.error["reason"] == ""
