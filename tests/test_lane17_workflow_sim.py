"""Lane 17 PR-2 (FD-4AJ / FD-4R / FD-4AG): workflows/main_orchestrator.yaml executed offline in tests/workflow_sim.py.

Plan §5: static lint rules + simulator scenarios. Every scenario drives the real YAML against a fake gateway / MCP
fleet and asserts what was CALLED (and what was not), the execution state, the DLQ record and the FAILED
notification. The simulator refuses unknown syntax / functions (SimulatorUnsupported), so a scenario cannot pass on
semantics nobody modelled.

Hermetic: no network, no cloud clients; the fake services are Python callables.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os

import pytest
import yaml

from workflow_sim import SimTimeout, Simulator, WorkflowError, http_error, iter_expressions, load_workflow, validate

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKFLOW = os.path.join(REPO, "workflows", "main_orchestrator.yaml")
SHA = "c" * 40
GW, VEND, WS, TF, IC = "https://gw.test", "https://vend.test", "https://ws.test", "https://tf.test", "https://ic.test"


@pytest.fixture(scope="module")
def workflow():
    return load_workflow(WORKFLOW)


# ===================================================================================== fake fleet
# LONG-STAGE-CALLBACK (owner 11-13): the architect, developer and QA stages are gateway jobs answered by callback. The
# fake gateway answers a job route 202 (once per callback URL, like stage_jobs.submit) and delivers on that callback
# exactly what `responses[<synchronous route>]` answers: {"http_status", "body"}. So every scenario written against the
# synchronous route drives the callback path unchanged, and asserts the same routing.
JOB_ROUTES = {"/agent/architect/decompose-job": "/agent/architect/decompose",
              "/agent/developer/execute-job": "/agent/developer/execute",
              "/agent/qa/verify-job": "/agent/qa/verify"}


class Fleet:
    """Fake gateway + MCP servers. `responses[path]` = (status, body) | callable(body) -> (status, body) | list."""

    def __init__(self, **over):
        self.responses = {
            # STAGE-JOB-RUNNER: stage_jobs_enabled true = the stage-runner job path (RT F4 switch)
            "/health": (200, {"status": "healthy", "workflow_contract": 3, "stage_jobs_enabled": True}),
            "/agent/stage-job/state": (200, {"state": "RUNNING", "reason": "EXECUTION_RUNNING"}),
            "/governance/kill-switch": (200, {"active": False, "reason": "", "set_by": ""}),
            "/discovery/quotas": (200, {"regions": {}}),
            "/agent/qa/readiness": (200, {"status": "READY", "ready": True}),
            "/agent/architect/decompose": (200, {"task_dag": [{"step_id": "S1"}], "plan_markdown": "plan",
                                                 "infra_plan": {"services": 1},
                                                 "architecture_plan": {"target_region": "us-central1"}}),
            "/agent/compliance/audit": (200, {"status": "PASSED", "allow_unauthenticated": False,
                                              "enable_direct_iap": False, "task_dag": [{"step_id": "S1"}],
                                              "requires_human_approval": False, "has_policy_conflicts": False}),
            IC + "/evaluate": (200, {"requires_human_approval": False, "monthly_cost_delta_usd": 5.0,
                                     "monthly_cost_estimate": "$5.00/mo", "risk_assessment": "LOW"}),
            "/events/pre-build-gate": (200, {"status": "SUCCESS", "decision": "PASS", "gate_reasons": [],
                                             "approval_id": ""}),
            "/events/pre-build-gate/decision": (200, {"status": "SUCCESS"}),
            "/discovery/validate-headroom": (200, {"is_valid": True}),
            "/events/approval-request": (200, {"status": "SUCCESS", "approval_id": "appr-quota-t-0"}),
            VEND + "/vend-all-async": (202, {"status": "ACCEPTED"}),
            "/agent/developer/execute": (200, {"status": "SUCCESS", "branch_name": "castor/app-1",
                                               "files_committed": ["apps/app/main.py"], "commit_sha": SHA}),
            "/agent/gatekeeper/verify": (200, {"passed": True, "commit_sha": SHA}),
            "/agent/qa/verify": (200, {"passed": True, "error_class": None, "summary": "QA passed"}),
            "/agent/release/promote": (200, {"status": "SUCCESS", "auto_merged": True, "approval_id": "",
                                             "pull_request_url": "https://github.com/o/r/pull/1"}),
            "/events/approval-callback": (200, {"status": "SUCCESS"}),
            WS + "/request-approval": (200, {"status": "APPROVAL_REQUESTED"}),
            TF + "/deploy-async": (202, {"status": "ACCEPTED"}),
            "/agent/resume/outcome": (200, {"status": "SUCCESS", "source_trace_id": "t-old",
                                            "prebuild_gate": {"status": "PASS", "trace_id": "t-old"},
                                            "compliance": {"allow_unauthenticated": False, "enable_direct_iap": True,
                                                           "domain_restricted_sharing": False, "allowed_domains": []}}),
            "/governance/deploy-only-gate": (200, {"status": "ALLOW", "reason": "DEFAULT_BRANCH"}),
            "/events/workflow-status": (200, {"status": "OK"}),
            "/events/quota-claim/release": (200, {"status": "SUCCESS"}),
        }
        self.callbacks = {"vending": [{"status": "SUCCESS", "project_id": "child-1"}],
                          "deploy": [{"status": "SUCCESS", "service_url": "https://app.run.app"}],
                          "plan": [{"decision": "APPROVED"}], "quota": [{"decision": "APPROVED"}],
                          "pr": [{"decision": "APPROVED"}]}
        self.callback_owner = {}
        self.stage_answers = {}    # job callback URL -> (status, body) | exception (LONG-STAGE-CALLBACK)
        self.job_dispatch = {}     # job route -> dispatch answers before the 202 (e.g. [(503, {...})])
        self.jobs_started = []     # (job route, callback URL) per job actually started
        self.responses.update(over)
        self.pubsub_fail = False

    def _key(self, url):
        for base in (IC, VEND, WS, TF):
            if url.startswith(base):
                return url
        return url[len(GW):] if url.startswith(GW) else url

    def _answer(self, resp, body):
        if isinstance(resp, list):
            resp = resp.pop(0) if len(resp) > 1 else resp[0]
        if callable(resp):
            resp = resp(body)
        return resp

    def http(self, method, url, body, args):
        key = self._key(url)
        if key in JOB_ROUTES:
            early = self.job_dispatch.get(key)
            if early:
                resp = early.pop(0)
                if isinstance(resp, BaseException):
                    raise resp
                return resp
            cb = body["callback_url"]
            if cb not in self.stage_answers:   # one job per callback URL (a dispatch retry starts nothing)
                sync_body = {k: v for k, v in body.items() if k != "callback_url"}
                try:
                    self.stage_answers[cb] = self._answer(self.responses[JOB_ROUTES[key]], sync_body)
                except BaseException as e:  # noqa: BLE001 - raised by the job's callback instead
                    self.stage_answers[cb] = e
                self.callback_owner[cb] = "stage"
                self.jobs_started.append((key, cb))
            return (202, {"status": "ACCEPTED", "stage": key.split("/")[2], "job_id": f"job-{len(self.jobs_started)}"})
        if isinstance(body, dict) and isinstance(body.get("callback_url"), str):
            owner = {"/events/pre-build-gate": "plan", "/events/approval-request": "quota",
                     "/events/approval-callback": "pr", VEND + "/vend-all-async": "vending",
                     TF + "/deploy-async": "deploy"}.get(key)
            if owner:
                self.callback_owner[body["callback_url"]] = owner
        resp = self.responses[key]
        if isinstance(resp, list):
            resp = resp.pop(0) if len(resp) > 1 else resp[0]
        if callable(resp):
            resp = resp(body)
        if isinstance(resp, BaseException):
            raise resp
        return resp

    def callback(self, url, timeout):
        owner = self.callback_owner[url]
        if owner == "stage":
            ans = self.stage_answers[url]
            if isinstance(ans, BaseException):
                raise ans
            status, rbody = ans
            return {"stage": "fake", "job_id": "job", "http_status": status, "body": rbody}
        seq = self.callbacks[owner]
        item = seq.pop(0) if len(seq) > 1 else seq[0]
        if isinstance(item, BaseException):
            raise item
        return item

    def pubsub(self, topic, messages):
        if self.pubsub_fail:
            raise WorkflowError(http_error(403, {"error": "denied"}))
        return {"messageIds": ["1"]}


def _args(**kw):
    a = {"trace_id": "tr-sim-1", "product_id": "app", "spec_text": "a todo app", "gateway_url": GW,
         "vending_mcp_url": VEND, "workspace_mcp_url": WS, "terraform_mcp_url": TF, "infracost_mcp_url": IC,
         "github_mcp_url": "https://gh.test", "dlq_topic": "projects/p/topics/castor-dlq"}
    a.update(kw)
    return a


# Bundle RT F6: every scenario runs with map.get(null, k) RAISING (the pessimistic reading of the runtime). A
# scenario that passes here never handed null to map.get, so it behaves the same under the simulator's default
# choice (map.get(null, k) -> null) and under real Cloud Workflows whichever way it resolves that call.
def run(workflow, fleet=None, null_map_get="error", **args):
    fleet = fleet or Fleet()
    sim = Simulator(http_handler=fleet.http, callback_handler=fleet.callback, pubsub_handler=fleet.pubsub,
                    null_map_get=null_map_get)
    res = sim.run(workflow, _args(**args))
    return res, fleet


def calls(res, part):
    return res.calls_to(part)


def dlq(res):
    assert len(res.published) == 1, res.published
    return res.published[0]["data"][0]


def failed_notice(res):
    notes = [c["body"] for c in calls(res, "/events/workflow-status") if (c.get("body") or {}).get("status") == "FAILED"]
    assert len(notes) == 1
    return notes[0]


def assert_failed(res, error_class, stage=None):
    assert res.state == "FAILED", (res.state, res.result)
    assert res.error["error_class"] == error_class, res.error
    rec = dlq(res)
    assert rec["error_class"] == error_class and rec["trace_id"] == "tr-sim-1" and rec["product_id"] == "app"
    note = failed_notice(res)
    assert note["error_class"] == error_class
    if stage:
        assert res.error["stage"] == stage and note["failed_stage"] == stage
    assert calls(res, "/events/quota-claim/release")  # released on every failure path (AJ-5)
    assert not [lv for lv, _ in res.logs if lv in ("ERROR", "CRITICAL", "ALERT", "EMERGENCY")]  # row 24


# ===================================================================================== static (deploy-like) checks
def test_workflow_validates_in_the_simulator(workflow):
    validate(workflow)
    assert sum(1 for _ in iter_expressions(workflow)) > 300


def test_no_error_severity_logs_while_row_24_holds():
    doc = yaml.safe_load(open(WORKFLOW, encoding="utf-8"))
    sev = []

    def walk(x):
        if isinstance(x, dict):
            if x.get("call") == "sys.log":
                sev.append((x.get("args") or {}).get("severity"))
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(doc)
    assert sev and not [s for s in sev if s in ("ERROR", "CRITICAL", "ALERT", "EMERGENCY")]
    # Bundle RT F2(c) / mutant M26: the failure handler logs at ${failure_log_severity}; pin that literal too.
    init = next(iter(doc["main"]["steps"][0].items()))
    assert init[0] == "init_failure_context", init[0]
    [lvl] = [a["failure_log_severity"] for a in init[1]["assign"] if "failure_log_severity" in a]
    assert lvl in ("WARNING", "INFO", "NOTICE", "DEBUG"), lvl


def _ordered_steps(doc):
    """(name, body) in source order for run_pipeline, nested blocks flattened in place."""
    out = []

    def walk(steps):
        for st in steps:
            name, body = next(iter(st.items()))
            out.append((name, body))
            for key in ("try", "except"):
                sub = body.get(key)
                if isinstance(sub, dict) and isinstance(sub.get("steps"), list):
                    walk(sub["steps"])
    walk(doc["run_pipeline"]["steps"])
    return out


def _is_await(body):
    tr = body.get("try") if isinstance(body.get("try"), dict) else body
    return isinstance(tr, dict) and tr.get("call") == "events.await_callback"


def test_every_await_is_preceded_by_a_reaper_exempt_heartbeat():
    """RT F10: the CC reaper exempts stages containing CALLBACK / APPROVAL / QUOTA_PAUSED (telemetry.py)."""
    steps = _ordered_steps(yaml.safe_load(open(WORKFLOW, encoding="utf-8")))
    awaits = [i for i, (_, b) in enumerate(steps) if _is_await(b)]
    assert len(awaits) == 5
    for i in awaits:
        prior = [b for _, b in steps[:i] if isinstance(b.get("try"), dict)
                 and str((b["try"].get("args") or {}).get("url", "")).endswith('"/events/workflow-status"}')]
        stage = prior[-1]["try"]["args"]["body"]["current_stage"]
        assert any(tok in stage for tok in ("CALLBACK", "APPROVAL", "QUOTA_PAUSED")), (steps[i][0], stage)


def test_deploy_await_covers_the_tf_applier_job_timeout():
    """AJ-15: await >= tf-applier job timeout + 10 min (job timeout read from the tf_applier resource block)."""
    tf = open(os.path.join(REPO, "infra", "platform", "main.tf"), encoding="utf-8").read().splitlines()
    start = tf.index(next(line for line in tf if line.startswith('resource "google_cloud_run_v2_job" "tf_applier"')))
    job_line = next(line for line in tf[start:] if line.strip().startswith("timeout"))
    job_s = int(job_line.split("=", 1)[1].split("#", 1)[0].strip().strip('"').rstrip("s"))
    steps = dict(_ordered_steps(yaml.safe_load(open(WORKFLOW, encoding="utf-8"))))
    assert steps["await_deploy_callback"]["try"]["args"]["timeout"] >= job_s + 600


def test_every_raise_is_a_typed_pipeline_failure():
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
    walk(doc)
    assert raises
    for r in raises:
        assert r in ("${failure}", "${pipeline_failure}") or (isinstance(r, dict) and r.get("tag") == "StackVendPipelineError"
                                                              and r.get("error_class")), r


def test_developer_ingress_flags_never_default_public_or_come_from_args():
    doc = yaml.safe_load(open(WORKFLOW, encoding="utf-8"))
    steps = dict(_ordered_steps(doc))
    body = steps["dispatch_developer_implementation"]["try"]["args"]["request"]   # LONG-STAGE-CALLBACK
    for flag in ("allow_unauthenticated", "enable_direct_iap", "domain_restricted_sharing"):
        assert 'map.get(args, "' + flag not in body[flag] and body[flag].endswith("false)}"), body[flag]


# ===================================================================================== scenarios
def test_happy_full_build_succeeds_with_no_dlq(workflow):
    res, _ = run(workflow)
    assert res.state == "SUCCEEDED", res.error
    assert res.result["status"] == "SUCCESS" and res.published == []
    assert len(calls(res, "/agent/developer/execute")) == 1 and calls(res, TF + "/deploy-async")
    assert len(calls(res, "/governance/kill-switch")) == 4  # start, vending, developer, deploy
    assert calls(res, "/events/quota-claim/release")
    assert not [lv for lv, _ in res.logs if lv == "ERROR"]


def test_architect_outage_fails_the_execution_typed(workflow):
    res, _ = run(workflow, Fleet(**{"/agent/architect/decompose": (503, {"detail": "down"})}))
    assert_failed(res, "DEPENDENCY_FAILED", "architect")
    assert not calls(res, VEND) and not calls(res, "/agent/developer/execute")


def test_qa_dispatch_typed_503_keeps_its_class(workflow):
    """RT F4: a typed gateway body is not collapsed into UNHANDLED."""
    res, _ = run(workflow, Fleet(**{"/agent/qa/verify": (503, {"status": "FAILED", "error_class": "GATE_UNAVAILABLE",
                                                               "reason": "QA_NOT_CONFIGURED", "summary": "no QA job"})}))
    assert_failed(res, "GATE_UNAVAILABLE")
    assert res.error["reason"] == "QA_NOT_CONFIGURED" and not calls(res, "/agent/release/promote")


def test_release_409_main_moved_is_typed_and_registers_no_approval(workflow):
    res, _ = run(workflow, Fleet(**{"/agent/release/promote": (409, {"error_class": "MAIN_MOVED", "stage": "release",
                                                                     "summary": "main moved"})}))
    assert_failed(res, "MAIN_MOVED", "release")
    assert not calls(res, "/events/approval-callback") and not calls(res, TF)


def test_pr_approval_merge_failed_raises_its_class(workflow):
    f = Fleet(**{"/agent/release/promote": (200, {"status": "SUCCESS", "auto_merged": False,
                                                  "approval_id": "appr-app-1", "pull_request_url": "u"})})
    f.callbacks["pr"] = [{"decision": "MERGE_FAILED", "error_class": "MAIN_MOVED", "reason": "main advanced"}]
    res, _ = run(workflow, f)
    assert_failed(res, "MAIN_MOVED", "release")
    assert not calls(res, TF)


def test_pr_approval_rejected_never_deploys(workflow):
    """Bundle RT F2(b) / mutant M16: an operator REJECTED on the PR card is POLICY_REJECTED, never a deploy."""
    f = Fleet(**{"/agent/release/promote": (200, {"status": "SUCCESS", "auto_merged": False,
                                                  "approval_id": "appr-app-1", "pull_request_url": "u"})})
    f.callbacks["pr"] = [{"decision": "REJECTED", "decision_reason": "not this sprint"}]
    res, _ = run(workflow, f)
    assert_failed(res, "POLICY_REJECTED", "release")
    assert not calls(res, TF + "/deploy-async") and not calls(res, TF)
    assert "kill_switch_before_deploy" not in res.steps_executed


def test_pr_approval_approved_deploys_and_registers_exactly_that_id(workflow):
    f = Fleet(**{"/agent/release/promote": (200, {"status": "SUCCESS", "auto_merged": False,
                                                  "approval_id": "appr-app-1", "pull_request_url": "u"})})
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    [reg] = calls(res, "/events/approval-callback")
    assert reg["body"]["approval_id"] == "appr-app-1"


def test_release_without_merge_or_approval_id_is_release_failed(workflow):
    res, _ = run(workflow, Fleet(**{"/agent/release/promote": (200, {"status": "FAILED", "auto_merged": False,
                                                                     "approval_id": ""})}))
    assert_failed(res, "RELEASE_FAILED", "release")
    assert not calls(res, "/events/approval-callback")


def test_qa_code_defect_four_times_reruns_the_developer_exactly_three_times(workflow):
    """QA-RETRIES (owner 10-29): up to 3 repair rounds; a run still failing after the last one stops at QA."""
    defect = (200, {"passed": False, "error_class": "CODE_DEFECT", "retryable": True, "summary": "tests failed"})
    res, _ = run(workflow, Fleet(**{"/agent/qa/verify": [defect, defect, defect, defect]}))
    assert_failed(res, "CODE_DEFECT", "qa")
    assert [c["body"]["retry_count"] for c in calls(res, "/agent/developer/execute")] == [0, 1, 2, 3]
    assert [c["body"]["attempt"] for c in calls(res, "/agent/qa/verify")] == [0, 1, 2, 3]


def test_qa_code_defect_passing_on_the_third_round_releases(workflow):
    defect = (200, {"passed": False, "error_class": "CODE_DEFECT", "retryable": True, "summary": "tests failed"})
    passed = (200, {"passed": True, "error_class": None, "summary": "QA passed"})
    res, _ = run(workflow, Fleet(**{"/agent/qa/verify": [defect, defect, defect, passed]}))
    assert res.state == "SUCCEEDED", res.error
    assert len(calls(res, "/agent/developer/execute")) == 4


def test_qa_no_progress_on_the_second_round_stops_without_a_third(workflow):
    """Each round still has to make progress: the gateway's NO_PROGRESS verdict (retryable False) stops the loop."""
    defect = (200, {"passed": False, "error_class": "CODE_DEFECT", "retryable": True, "summary": "tests failed"})
    stuck = (200, {"passed": False, "error_class": "CODE_DEFECT", "retryable": False, "reason": "NO_PROGRESS",
                   "summary": "identical diagnostics"})
    res, _ = run(workflow, Fleet(**{"/agent/qa/verify": [defect, stuck]}))
    assert_failed(res, "CODE_DEFECT", "qa")
    assert len(calls(res, "/agent/developer/execute")) == 2


def test_qa_code_defect_not_retryable_is_not_retried(workflow):
    res, _ = run(workflow, Fleet(**{"/agent/qa/verify": (200, {"passed": False, "error_class": "CODE_DEFECT",
                                                               "retryable": False, "summary": "same diagnostics"})}))
    assert_failed(res, "CODE_DEFECT")
    assert len(calls(res, "/agent/developer/execute")) == 1


def test_qa_not_ready_stops_before_architect_and_vending(workflow):
    res, _ = run(workflow, Fleet(**{"/agent/qa/readiness": (503, {"error_class": "GATE_UNAVAILABLE",
                                                                  "reason": "QA_NOT_CONFIGURED", "summary": "x"})}))
    assert_failed(res, "GATE_UNAVAILABLE")
    assert not calls(res, "/agent/architect/decompose") and not calls(res, VEND)


def test_old_gateway_contract_stops_at_zero_cost(workflow):
    res, _ = run(workflow, Fleet(**{"/health": (200, {"status": "healthy", "workflow_contract": 1})}))
    assert_failed(res, "GATE_UNAVAILABLE", "gateway_contract")
    assert not calls(res, "/agent/architect/decompose") and not calls(res, VEND)


def test_gateway_without_contract_field_stops(workflow):
    res, _ = run(workflow, Fleet(**{"/health": (200, {"status": "healthy"})}))
    assert_failed(res, "GATE_UNAVAILABLE", "gateway_contract")


def test_kill_switch_active_at_start(workflow):
    res, _ = run(workflow, Fleet(**{"/governance/kill-switch": (200, {"active": True, "reason": "incident"})}))
    assert_failed(res, "KILL_SWITCH_ACTIVE", "pipeline_start")
    assert not calls(res, "/agent/architect/decompose")


def test_kill_switch_flipped_mid_run_stops_before_the_developer(workflow):
    clear, active = (200, {"active": False}), (200, {"active": True, "reason": "stop"})
    res, _ = run(workflow, Fleet(**{"/governance/kill-switch": [clear, clear, active]}))
    assert_failed(res, "KILL_SWITCH_ACTIVE", "developer")
    assert calls(res, VEND) and not calls(res, "/agent/developer/execute")


def test_kill_switch_unreadable_fails_closed(workflow):
    res, _ = run(workflow, Fleet(**{"/governance/kill-switch": (503, {"error_class": "GATE_UNAVAILABLE"})}))
    assert_failed(res, "GATE_UNAVAILABLE", "pipeline_start")
    assert res.error["reason"] == "KILL_SWITCH_UNREADABLE"


# ---------------------------------------------------------------------------- pre-build gate (FD-4AG) as a real wait
def _await_gate(**extra):
    body = {"status": "SUCCESS", "decision": "AWAIT_APPROVAL", "gate_reasons": ["FINOPS_THRESHOLD"],
            "approval_id": "appr-plan-tr-sim-1-0"}
    body.update(extra)
    return (200, body)


def test_finops_approval_waits_then_builds_on_approval(workflow):
    res, f = run(workflow, Fleet(**{"/events/pre-build-gate": _await_gate()}))
    assert res.state == "SUCCEEDED", res.error
    assert "plan" in f.callback_owner.values()
    dec = calls(res, "/events/pre-build-gate/decision")
    assert dec and dec[0]["body"]["decision"] == "APPROVED" and dec[0]["body"]["approval_id"] == "appr-plan-tr-sim-1-0"
    order = res.steps_executed
    assert order.index("await_plan_approval_callback") < order.index("dispatch_developer_implementation")
    assert not calls(res, WS + "/request-approval")  # not the Google-Docs channel


def test_finops_approval_rejected_never_vends_or_builds(workflow):
    f = Fleet(**{"/events/pre-build-gate": _await_gate()})
    f.callbacks["plan"] = [{"decision": "REJECTED"}]
    res, _ = run(workflow, f)
    assert_failed(res, "POLICY_REJECTED", "plan_approval")
    assert not calls(res, VEND) and not calls(res, "/agent/developer/execute")


def test_plan_approval_timeout_is_gate_timeout(workflow):
    f = Fleet(**{"/events/pre-build-gate": _await_gate()})
    f.callbacks["plan"] = [SimTimeout("24h")]
    res, _ = run(workflow, f)
    assert_failed(res, "GATE_TIMEOUT", "plan_approval")
    assert not calls(res, VEND)


def test_plan_decision_unverified_stops(workflow):
    f = Fleet(**{"/events/pre-build-gate": _await_gate(),
                 "/events/pre-build-gate/decision": (409, {"error_class": "CONTRACT_VIOLATION",
                                                           "reason": "DECISION_MISMATCH", "summary": "x"})})
    res, _ = run(workflow, f)
    assert_failed(res, "CONTRACT_VIOLATION")
    assert not calls(res, VEND)


def test_plan_decision_pending_is_retried_until_the_cc_write_lands(workflow):
    """Bundle RT F3: the CC writes the decision AFTER delivering the callback, so the decision route may answer 503
    DECISION_PENDING for a while. Six 503s (longer than http.default_retry's 5) then 200: the approved run proceeds."""
    pending = (503, {"error_class": "GATE_UNAVAILABLE", "reason": "DECISION_PENDING", "stage": "plan_approval",
                     "summary": "not yet recorded"})
    f = Fleet(**{"/events/pre-build-gate": _await_gate(),
                 "/events/pre-build-gate/decision": [pending] * 6 + [(200, {"status": "SUCCESS"})]})
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    assert res.attempts["persist_plan_decision"] == 7
    assert [r["delay"] for r in res.retries if r["step"] == "persist_plan_decision"] == [2, 4, 8, 16, 30, 30]
    assert len(calls(res, "/agent/developer/execute")) == 1


def test_plan_decision_pending_retry_is_bounded_and_fails_closed(workflow):
    """Bundle RT F3: the decision retry stays bounded (10 retries, ~4-5 min of backoff), then fails closed."""
    pending = (503, {"error_class": "GATE_UNAVAILABLE", "reason": "DECISION_PENDING", "stage": "plan_approval",
                     "summary": "not yet recorded"})
    f = Fleet(**{"/events/pre-build-gate": _await_gate(), "/events/pre-build-gate/decision": pending})
    res, _ = run(workflow, f)
    assert_failed(res, "GATE_UNAVAILABLE", "plan_approval")
    assert res.attempts["persist_plan_decision"] == 11
    backoff = sum(r["delay"] for r in res.retries if r["step"] == "persist_plan_decision")
    assert 200 <= backoff <= 300, backoff
    assert not calls(res, VEND) and not calls(res, "/agent/developer/execute")


def test_plan_rework_reruns_architect_and_gate(workflow):
    f = Fleet(**{"/events/pre-build-gate": [_await_gate(), (200, {"status": "SUCCESS", "decision": "PASS",
                                                                  "approval_id": ""})]})
    f.callbacks["plan"] = [{"decision": "REWORK", "feedback": "smaller"}]
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    assert len(calls(res, "/agent/architect/decompose")) == 2
    gates = [c for c in calls(res, "/events/pre-build-gate") if c["url"].endswith("/events/pre-build-gate")]
    assert [c["body"]["rework_cycle"] for c in gates] == [0, 1]


def test_docs_channel_posts_the_doc_callout_then_waits(workflow):
    res, _ = run(workflow, Fleet(**{"/events/pre-build-gate": _await_gate()}), spec_doc_id="doc-1")
    assert res.state == "SUCCEEDED", res.error
    [req] = calls(res, WS + "/request-approval")
    assert req["body"]["approval_id"] == "appr-plan-tr-sim-1-0"  # AG-7: the workspace only notifies (one card)
    order = res.steps_executed
    assert order.index("await_human_approval") < order.index("await_plan_approval_callback")


def test_docs_channel_callout_failure_stops_the_run_not_approved(workflow):
    """Register row WS-2: a failed Doc request never continues to the build."""
    res, _ = run(workflow, Fleet(**{"/events/pre-build-gate": _await_gate(),
                                    WS + "/request-approval": (502, {"error_class": "APPROVAL_CALLOUT_FAILED"})}),
                 spec_doc_id="doc-1")
    assert res.state == "FAILED" and res.error["stage"] == "prebuild_gate"
    assert "await_plan_approval_callback" not in res.steps_executed
    assert not calls(res, "/agent/developer/execute")


def test_finops_outage_is_sent_to_the_gate_not_assumed_low(workflow):
    res, _ = run(workflow, Fleet(**{IC + "/evaluate": (503, {"detail": "down"})}))
    [gate] = [c for c in calls(res, "/events/pre-build-gate") if c["url"].endswith("/events/pre-build-gate")]
    assert gate["body"]["finops"] is None and gate["body"]["finops_error"] != ""


def _gate_like_the_gateway(body):
    """Like workflow_gates.evaluate_pre_build_gate: a missing FinOps answer is a reason to wait, never a pass."""
    if body.get("finops") is None:
        return _await_gate(gate_reasons=["FINOPS_UNAVAILABLE"])
    return (200, {"status": "SUCCESS", "decision": "PASS", "gate_reasons": [], "approval_id": ""})


@pytest.mark.parametrize("null_map_get", ["null", "error"])
def test_finops_outage_waits_for_the_operator_whatever_map_get_null_does(workflow, null_map_get):
    """Bundle RT F6: FinOps outage -> finops_output null. The run must reach the plan-approval WAIT (not UNHANDLED)
    under either reading of map.get(null, k); an approval then builds."""
    res, f = run(workflow, Fleet(**{IC + "/evaluate": (503, {"detail": "down"}),
                                    "/events/pre-build-gate": _gate_like_the_gateway}), null_map_get=null_map_get)
    assert res.state == "SUCCEEDED", res.error
    [gate] = [c for c in calls(res, "/events/pre-build-gate") if c["url"].endswith("/events/pre-build-gate")]
    assert gate["body"]["finops"] is None and gate["body"]["finops_error"] != ""
    assert "await_plan_approval_callback" in res.steps_executed and "plan" in f.callback_owner.values()


@pytest.mark.parametrize("null_map_get", ["null", "error"])
def test_finops_outage_docs_channel_callout_says_not_evaluated(workflow, null_map_get):
    """Bundle RT F6: the Doc callout body is built without map.get on null."""
    res, _ = run(workflow, Fleet(**{IC + "/evaluate": (503, {"detail": "down"}),
                                    "/events/pre-build-gate": _gate_like_the_gateway}),
                 null_map_get=null_map_get, spec_doc_id="doc-1")
    assert res.state == "SUCCEEDED", res.error
    [req] = calls(res, WS + "/request-approval")
    assert req["body"]["cost_delta_monthly"] == "not evaluated" and req["body"]["risk_assessment"] == "UNKNOWN"


@pytest.mark.parametrize("null_map_get", ["null", "error"])
def test_quota_unverified_waits_for_the_operator_whatever_map_get_null_does(workflow, null_map_get):
    """Bundle RT F6: inspector error on the first check -> quota_validation_result null. The run must register the
    QUOTA_UNVERIFIED gate and WAIT (not UNHANDLED); an approval re-checks."""
    f = Fleet(**{"/discovery/validate-headroom": [(503, {"detail": "inspector missing"}), (200, {"is_valid": True})]})
    res, _ = run(workflow, f, null_map_get=null_map_get)
    assert res.state == "SUCCEEDED", res.error
    [reg] = calls(res, "/events/approval-request")
    assert reg["body"]["reason"] == "QUOTA_UNVERIFIED"
    assert reg["body"]["violations"] == [] and reg["body"]["target_region"] == "" and reg["body"]["quota_source"] == ""
    assert "await_quota_resolution" in res.steps_executed and len(calls(res, "/discovery/validate-headroom")) == 2


def test_quota_unverified_recheck_never_shows_the_previous_checks_violations(workflow):
    """Bundle RT F6: an unverified re-check is not decorated with an earlier check's answer."""
    f = Fleet(**{"/discovery/validate-headroom": [(200, {"is_valid": False, "violations": ["cpus"]}),
                                                  (503, {"detail": "inspector missing"}), (200, {"is_valid": True})]})
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    regs = calls(res, "/events/approval-request")
    assert [(r["body"]["reason"], r["body"]["violations"]) for r in regs] == [
        ("QUOTA_INSUFFICIENT", ["cpus"]), ("QUOTA_UNVERIFIED", [])]


def test_pre_build_gate_unknown_decision_is_contract_violation(workflow):
    res, _ = run(workflow, Fleet(**{"/events/pre-build-gate": (200, {"status": "SUCCESS", "decision": "MAYBE"})}))
    assert_failed(res, "CONTRACT_VIOLATION", "prebuild_gate")
    assert not calls(res, VEND)


# ---------------------------------------------------------------------------- quota gate
def test_quota_insufficient_waits_and_rechecks_on_approval(workflow):
    f = Fleet(**{"/discovery/validate-headroom": [(200, {"is_valid": False, "violations": ["cpus"]}),
                                                  (200, {"is_valid": True})]})
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    [reg] = calls(res, "/events/approval-request")
    assert reg["body"]["approval_type"] == "QUOTA_GATE" and reg["body"]["reason"] == "QUOTA_INSUFFICIENT"
    assert len(calls(res, "/discovery/validate-headroom")) == 2


def test_quota_rejected_never_vends(workflow):
    f = Fleet(**{"/discovery/validate-headroom": (200, {"is_valid": False})})
    f.callbacks["quota"] = [{"decision": "REJECTED"}]
    res, _ = run(workflow, f)
    assert_failed(res, "POLICY_REJECTED", "quota_gate")
    assert not calls(res, VEND)


def test_quota_unverified_goes_to_the_gate_not_to_vending(workflow):
    f = Fleet(**{"/discovery/validate-headroom": (503, {"detail": "inspector missing"})})
    f.callbacks["quota"] = [{"decision": "REJECTED"}]
    res, _ = run(workflow, f)
    [reg] = calls(res, "/events/approval-request")
    assert reg["body"]["reason"] == "QUOTA_UNVERIFIED"
    assert not calls(res, VEND)


def test_quota_missing_is_valid_is_not_valid(workflow):
    f = Fleet(**{"/discovery/validate-headroom": (200, {})})
    f.callbacks["quota"] = [{"decision": "REJECTED"}]
    res, _ = run(workflow, f)
    assert res.state == "FAILED" and not calls(res, VEND)


def test_quota_recheck_is_bounded(workflow):
    f = Fleet(**{"/discovery/validate-headroom": (200, {"is_valid": False})})
    res, _ = run(workflow, f)
    assert_failed(res, "GATE_UNAVAILABLE", "quota_gate")
    assert len(calls(res, "/discovery/validate-headroom")) == 4  # first check + 3 operator re-checks


# ---------------------------------------------------------------------------- RESUME_DEVELOPER (RT F1)
def test_resume_after_rejected_plan_never_reaches_the_developer(workflow):
    res, _ = run(workflow, Fleet(**{"/agent/resume/outcome": (503, {"error_class": "GATE_UNAVAILABLE",
                                                                    "reason": "RESUME_GATE_UNAVAILABLE",
                                                                    "summary": "run a full build"})}),
                 execution_mode="RESUME_DEVELOPER")
    assert_failed(res, "GATE_UNAVAILABLE", "resume")
    assert not calls(res, "/agent/developer/execute")


def test_resume_with_gate_not_passed_never_reaches_the_developer(workflow):
    res, _ = run(workflow, Fleet(**{"/agent/resume/outcome": (200, {"status": "SUCCESS",
                                                                    "prebuild_gate": {"status": "REJECTED"},
                                                                    "compliance": {}})}),
                 execution_mode="RESUME_DEVELOPER")
    assert_failed(res, "GATE_UNAVAILABLE", "resume")
    assert not calls(res, "/agent/developer/execute")


def test_resume_with_pass_gate_runs_quota_then_developer_with_persisted_ingress(workflow):
    res, _ = run(workflow, execution_mode="RESUME_DEVELOPER")
    assert res.state == "SUCCEEDED", res.error
    assert not calls(res, "/agent/architect/decompose") and not calls(res, VEND)
    order = res.steps_executed
    assert order.index("check_qa_readiness") < order.index("load_resume_outcome") < \
        order.index("check_quota_preflight") < order.index("dispatch_developer_implementation")
    [dev] = calls(res, "/agent/developer/execute")
    assert dev["body"]["allow_unauthenticated"] is False and dev["body"]["enable_direct_iap"] is True


# ---------------------------------------------------------------------------- DEPLOY_ONLY (RT F2)
def test_deploy_only_feature_branch_refused_without_deploy(workflow):
    res, _ = run(workflow, Fleet(**{"/governance/deploy-only-gate": (403, {"error_class": "POLICY_REJECTED",
                                                                           "stage": "deploy_only_gate",
                                                                           "reason": "BRANCH_NOT_REVIEWED",
                                                                           "summary": "no"})}),
                 execution_mode="DEPLOY_ONLY", target_branch="feature/x")
    assert_failed(res, "POLICY_REJECTED", "deploy_only_gate")
    assert not calls(res, TF) and not calls(res, IC)


def test_deploy_only_default_branch_deploys_without_cost_or_llm(workflow):
    res, _ = run(workflow, execution_mode="DEPLOY_ONLY", target_branch="main")
    assert res.state == "SUCCEEDED", res.error
    [gate] = calls(res, "/governance/deploy-only-gate")
    assert gate["body"]["branch"] == "main"
    assert calls(res, TF + "/deploy-async") and not calls(res, IC)
    for gated in ("/agent/architect/decompose", "/agent/developer/execute", "/agent/qa/readiness"):
        assert not calls(res, gated)


# ---------------------------------------------------------------------------- deploy routing (AJ-14 / AJ-15)
def test_state_locked_goes_to_the_operator_not_the_developer(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [{"status": "FAILED", "error_class": "STATE_LOCKED", "error": "STATE_LOCKED: held",
                              "lock_holder": "tf-applier-exec-9"}]
    res, _ = run(workflow, f)
    assert_failed(res, "STATE_LOCKED", "terraform")
    assert len(calls(res, "/agent/developer/execute")) == 1
    assert "tf-applier-exec-9" in res.error["message"]


def test_iac_defect_gets_bounded_developer_remediation(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [{"status": "FAILED", "error_class": "IAC_DEFECT", "error": "bad hcl"},
                             {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    devs = calls(res, "/agent/developer/execute")
    assert len(devs) == 2 and devs[1]["body"]["tf_remediation_context"] == "bad hcl"


def test_iac_defect_budget_spent_is_deploy_failed(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [{"status": "FAILED", "error_class": "IAC_DEFECT", "error": "bad hcl"}]
    res, _ = run(workflow, f)
    assert_failed(res, "DEPLOY_FAILED", "terraform")
    assert len(calls(res, "/agent/developer/execute")) == 3  # first build + max_tf_retries (2)


def test_unknown_deploy_class_is_deploy_failed_not_remediated(workflow):
    """Bundle RT F2(a) / mutant M6 (plan Q9): an error_class nobody knows is not remediable by the developer."""
    f = Fleet()
    f.callbacks["deploy"] = [{"status": "FAILED", "error_class": "SOMETHING_NEW", "error": "new failure kind"},
                             {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert_failed(res, "DEPLOY_FAILED", "terraform")
    assert len(calls(res, "/agent/developer/execute")) == 1  # no developer re-dispatch
    assert len(calls(res, TF + "/deploy-async")) == 1
    assert "increment_tf_retry" not in res.steps_executed


def test_deploy_timeout_is_typed_and_not_retried(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [SimTimeout("no callback")]
    res, _ = run(workflow, f)
    assert_failed(res, "DEPLOY_TIMEOUT", "terraform")
    assert len(calls(res, TF + "/deploy-async")) == 1


# ---------------------------------------------------------------------------- handler robustness
def test_dlq_publish_failure_still_notifies_and_fails(workflow):
    f = Fleet(**{"/agent/architect/decompose": (503, {"detail": "down"})})
    f.pubsub_fail = True
    res, _ = run(workflow, f)
    assert res.state == "FAILED" and res.published == []
    assert failed_notice(res)["error_class"] == "DEPENDENCY_FAILED"


def test_unexpected_contract_error_is_still_handled(workflow):
    """AJ-2: a missing response field outside any try (developer body without branch_name) lands in the handler."""
    res, _ = run(workflow, Fleet(**{"/agent/developer/execute": (200, {"status": "SUCCESS"})}))
    assert res.state == "FAILED"
    assert res.error["error_class"] == "UNHANDLED" and dlq(res)["error_class"] == "UNHANDLED"


def test_missing_product_id_is_contract_violation(workflow):
    res, _ = run(workflow, product_id="")
    assert res.state == "FAILED" and res.error["error_class"] == "CONTRACT_VIOLATION"
    assert not calls(res, "/agent/architect/decompose")


def test_vending_failure_is_typed(workflow):
    f = Fleet()
    f.callbacks["vending"] = [{"status": "FAILED", "error": "billing"}]
    res, _ = run(workflow, f)
    assert_failed(res, "DEPENDENCY_FAILED", "vending")
    assert not calls(res, "/agent/developer/execute")
