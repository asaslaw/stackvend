"""DEPLOY-SYNC-BUDGET (owner 10-25): the synchronous `/deploy` gets one overall time budget for the whole deploy.

The terraform MCP server's `/deploy` passes `time_budget_s=SYNC_DEPLOY_TIME_BUDGET_S` to `deploy_workload`; from the
deploy's start every OpenTofu command of that deploy runs for at most min(its own limit, deadline - now), a command
due to start after the deadline is not started, and at the deadline the AQ-5 behavior applies unchanged (SIGINT, the
grace period, SIGKILL; result and deploy error_class TOFU_TIMEOUT). Fable RT F1: the budget is the 1800 s request
limit minus the SIGINT grace, the pipe drain and a 60 s response margin (1470 s); the 1800 s is pinned to
infra/platform/main.tf and to both sync callers (Control Center Express, vending redeploy).

Negative tests (Do No Harm): a fast deploy with a budget returns the impl's result object unchanged and its commands'
results exactly as before; commands outside a deploy, a deploy without a budget, the in-process /deploy-async path and
the tf-applier job keep the per-command limits only.

Hermetic: short-lived local processes (`sleep`, `echo`) only; no OpenTofu, no network, no cloud clients.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import signal
import subprocess
import time
from unittest.mock import MagicMock, patch

import pytest

from test_fd4g_terraform_workspace import (  # noqa: F401  (pytest fixtures reused by name)
    _isolated_tf_service, _import_service, _no_network, _svc, base, sent_callbacks, tf_main)


def _rc(base):
    rc = os.path.join(base, "test.rc")
    with open(rc, "w", encoding="utf-8") as fh:
        fh.write("provider_installation {}\n")
    return rc


def _runner(base, limits):
    service_mod = _import_service()
    svc = _svc(service_mod, base)
    svc.tofu_time_limits = limits
    svc._ensure_binary = lambda *a, **k: "tofu"
    svc._ensure_provider_mirror = lambda *a, **k: _rc(base)
    return service_mod, svc


def _ok_proc(out="fine"):
    proc = MagicMock(pid=None, returncode=0)
    proc.communicate.return_value = (out, "")
    return proc


class _Clock:
    """A controllable time.monotonic for the service module (everything else is the real `time`)."""

    def __init__(self, now=1000.0):
        self.now = now
        self.module = MagicMock(wraps=time)
        self.module.monotonic = lambda: self.now


# ============================================================================ the budget value
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_budget_leaves_grace_drain_and_margin_inside_the_request_limit():
    tf = _import_service()
    srv = tf.TOFU_TIME_LIMITS_SERVICE
    assert (tf.SYNC_REQUEST_LIMIT_S, tf.TOFU_PIPE_DRAIN_S, tf.SYNC_DEPLOY_RESPONSE_MARGIN_S) == (1800.0, 30.0, 60.0)
    assert tf.SYNC_DEPLOY_TIME_BUDGET_S == (tf.SYNC_REQUEST_LIMIT_S - srv.grace_s - tf.TOFU_PIPE_DRAIN_S
                                           - tf.SYNC_DEPLOY_RESPONSE_MARGIN_S) == 1470.0
    # SIGINT at the deadline, SIGKILL after the grace, the drain: still the margin before the request is cut
    assert tf.SYNC_DEPLOY_TIME_BUDGET_S + srv.grace_s + tf.TOFU_PIPE_DRAIN_S == 1740.0 < tf.SYNC_REQUEST_LIMIT_S
    # the per-command server limit is unchanged; the budget only caps the sum
    assert srv.apply_destroy_s == srv.other_s == 20 * 60


def test_execution_sync_deadline_leaves_room_for_the_result_before_the_last_poll():
    """FD-7L 5b (RT M2): a sync /deploy run as a tf-applier execution gets deadline = start + budget - margin, so a
    budget-killed deploy's own typed result (SIGINT grace + pipe drain after the deadline, then the result write) lands
    before the server's last poll at start + request limit - response margin. Magnitude pinned, not direction."""
    tf = _import_service()
    import importlib.util
    spec = importlib.util.spec_from_file_location("rr_budget", os.path.join(REPO, "mcp-servers", "terraform",
                                                                            "runner_runs.py"))
    rr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rr)
    srv = tf.TOFU_TIME_LIMITS_SERVICE
    deadline_after_start = tf.SYNC_DEPLOY_TIME_BUDGET_S - rr.SYNC_RESULT_MARGIN_S
    # SAT-37: + RESULT_SIGN_ALLOWANCE_S for the signed result fingerprint (vending /runner/result) before the write
    assert rr.SYNC_RESULT_MARGIN_S == 40.0 >= 2 * rr.RESULT_POLL_S + rr.RESULT_SIGN_ALLOWANCE_S
    assert (deadline_after_start + srv.grace_s + tf.TOFU_PIPE_DRAIN_S + rr.SYNC_RESULT_MARGIN_S
            <= tf.SYNC_REQUEST_LIMIT_S - tf.SYNC_DEPLOY_RESPONSE_MARGIN_S)
    # the server code uses exactly this deadline
    src = open(os.path.join(REPO, "mcp-servers", "terraform", "main.py"), encoding="utf-8").read()
    assert '"deadline_epoch": started + SYNC_DEPLOY_TIME_BUDGET_S - rr.SYNC_RESULT_MARGIN_S' in src


def _module_constant(relpath, name):
    import ast
    with open(os.path.join(REPO, relpath), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    values = [n.value.value for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
              and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    assert len(values) == 1, (relpath, name, values)
    return values[0]


def test_request_limit_matches_the_platform_service_timeout_and_both_sync_callers():
    hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (terraform MCP requirement) not installed")
    tf = _import_service()
    with open(os.path.join(REPO, "infra", "platform", "main.tf"), encoding="utf-8") as fh:
        doc = hcl2.load(fh)
    services = [r["google_cloud_run_v2_service"]["services"] for r in doc["resource"]
                if "services" in r.get("google_cloud_run_v2_service", {})]
    assert len(services) == 1
    assert services[0]["for_each"] == "${local.cloud_run_services}"
    names = [n for loc in doc["locals"] for n in (loc.get("cloud_run_services") or {})]
    assert "mcp-terraform-server" in names
    template = services[0]["template"]
    template = template[0] if isinstance(template, list) else template
    assert template["timeout"] == f"{tf.SYNC_REQUEST_LIMIT_S:.0f}s" == "1800s"
    # the two sync /deploy callers wait exactly the same request limit
    assert _module_constant("apps/control-center/routes/workloads.py", "EXPRESS_DEPLOY_TIMEOUT_SECONDS") \
        == tf.SYNC_REQUEST_LIMIT_S
    assert _module_constant("apps/project-vending/vending.py", "REDEPLOY_REQUEST_BUDGET_S") == tf.SYNC_REQUEST_LIMIT_S


# ============================================================================ commands inside a budgeted deploy
def test_each_command_gets_the_smaller_of_its_limit_and_the_time_left(base):
    tf, svc = _runner(base, _import_service().TOFU_TIME_LIMITS_SERVICE)
    clock = _Clock()
    seen = []

    def impl(**kw):
        with patch.object(tf.subprocess, "Popen", return_value=_ok_proc()) as popen:
            svc._run_subprocess(["tofu", "init"], cwd=base)
            seen.append(popen.return_value.communicate.call_args.kwargs["timeout"])
            clock.now += 1000.0                           # 1000 s of the 1470 s budget used
            svc._run_subprocess(["tofu", "apply", "-auto-approve"], cwd=base)
            seen.append(popen.return_value.communicate.call_args.kwargs["timeout"])
        return {"status": "SUCCESS"}

    svc._deploy_workload_impl = impl
    with patch.object(tf, "time", clock.module):
        res = svc.deploy_workload(product_id="app", trace_id="t1", time_budget_s=tf.SYNC_DEPLOY_TIME_BUDGET_S)
    assert res == {"status": "SUCCESS"}
    assert seen == [1200.0, 470.0]                        # min(20 min, 1470 - 0), min(20 min, 1470 - 1000)


def test_a_command_running_at_the_deadline_is_interrupted_and_the_deploy_fails_tofu_timeout(base):
    # the command's own limit (30 s) is far away: only the deploy's 1 s budget stops it
    tf, svc = _runner(base, _import_service().TofuTimeLimits(apply_destroy_s=30.0, other_s=30.0, grace_s=2.0))
    procs, started = [], []
    real_popen = subprocess.Popen

    def popen(cmd, **kw):
        started.append(cmd)
        p = real_popen(cmd, **kw)
        procs.append(p)
        return p

    def impl(**kw):
        first = svc._run_subprocess(["sleep", "30"], cwd=base)
        second = svc._run_subprocess(["tofu", "output"], cwd=base)        # never started
        return {"status": "FAILED", "error": first["stderr"], "second": second}

    svc._deploy_workload_impl = impl
    t0 = time.monotonic()
    with patch.object(tf.subprocess, "Popen", side_effect=popen):
        res = svc.deploy_workload(product_id="app", trace_id="t1", time_budget_s=1.0)
    assert time.monotonic() - t0 < 10
    assert len(started) == 1 and procs[0].poll() is not None              # the process is gone
    assert procs[0].returncode == -signal.SIGINT                         # SIGINT first (sleep dies on it)
    assert res["status"] == "FAILED" and res["error_class"] == "TOFU_TIMEOUT"
    assert res["error"] == ("TOFU_TIMEOUT: this deploy's overall time limit of 1 seconds ran out; the OpenTofu "
                            "command `30` was interrupted. Nothing more is run for this deploy.")
    assert res["second"]["error_class"] == "TOFU_TIMEOUT" and res["second"]["stderr"] == res["error"]


def test_a_command_due_after_the_deadline_is_not_started(base):
    tf, svc = _runner(base, _import_service().TOFU_TIME_LIMITS_SERVICE)
    clock = _Clock()
    out = []

    def impl(**kw):
        out.append(svc._run_subprocess(["tofu", "init"], cwd=base))
        clock.now += 1200.0                                               # the whole budget is used
        out.append(svc._run_subprocess(["tofu", "apply", "-auto-approve"], cwd=base))
        return {"status": "FAILED", "error": "Terraform apply failed"}

    svc._deploy_workload_impl = impl
    with patch.object(tf, "time", clock.module), \
            patch.object(tf.subprocess, "Popen", return_value=_ok_proc()) as popen:
        res = svc.deploy_workload(product_id="app", trace_id="t1", time_budget_s=1200.0)
    assert popen.call_count == 1 and popen.call_args.args[0][:2] == ["tofu", "init"]
    assert out[0]["success"] is True
    assert out[1] == {"exit_code": 124, "stdout": "", "success": False, "timed_out": True,
                      "error_class": "TOFU_TIMEOUT", "stderr": out[1]["stderr"]}
    assert out[1]["stderr"] == ("TOFU_TIMEOUT: this deploy's overall time limit of 1200 seconds ran out; the OpenTofu "
                                "command `apply` was not started. Nothing more is run for this deploy.")
    assert (res["status"], res["error_class"], res["error"]) == ("FAILED", "TOFU_TIMEOUT", out[1]["stderr"])


def test_a_deadline_passing_during_command_setup_still_starts_nothing(base):
    """Fable RT F2: the budget runs out between the check at the top of `_run_subprocess` and `Popen` (here inside
    the provider-mirror setup): `_run_bounded` does not start the command either."""
    tf, svc = _runner(base, _import_service().TOFU_TIME_LIMITS_SERVICE)
    clock = _Clock()
    rc = _rc(base)

    def slow_mirror(*a, **k):
        clock.now += 2000.0                                               # past the 1470 s deadline
        return rc

    svc._ensure_provider_mirror = slow_mirror
    out = []

    def impl(**kw):
        out.append(svc._run_subprocess(["tofu", "init"], cwd=base))
        return {"status": "FAILED", "error": "init failed"}

    svc._deploy_workload_impl = impl
    with patch.object(tf, "time", clock.module), \
            patch.object(tf.subprocess, "Popen", return_value=_ok_proc()) as popen:
        res = svc.deploy_workload(product_id="app", trace_id="t1", time_budget_s=tf.SYNC_DEPLOY_TIME_BUDGET_S)
    popen.assert_not_called()
    assert out[0]["error_class"] == "TOFU_TIMEOUT" and out[0]["exit_code"] == 124
    assert out[0]["stderr"] == ("TOFU_TIMEOUT: this deploy's overall time limit of 1470 seconds ran out; the OpenTofu "
                                "command `init` was not started. Nothing more is run for this deploy.")
    assert (res["status"], res["error_class"], res["error"]) == ("FAILED", "TOFU_TIMEOUT", out[0]["stderr"])


def test_the_command_limit_still_wins_when_it_is_smaller(base):
    """The budget only shortens: a command whose own limit ends first gets the usual AQ-5 message."""
    tf, svc = _runner(base, _import_service().TofuTimeLimits(apply_destroy_s=0.5, other_s=0.5, grace_s=2.0))

    def impl(**kw):
        return {"status": "FAILED", "r": svc._run_subprocess(["sleep", "30"], cwd=base)}

    svc._deploy_workload_impl = impl
    res = svc.deploy_workload(product_id="app", trace_id="t1", time_budget_s=60.0)
    assert res["error_class"] == "TOFU_TIMEOUT"
    assert res["error"].startswith("TOFU_TIMEOUT: the OpenTofu command `30` did not finish within 0 seconds")


# ============================================================================ Do No Harm
def test_a_fast_deploy_with_a_budget_is_unaffected(base):
    tf, svc = _runner(base, _import_service().TOFU_TIME_LIMITS_SERVICE)
    results = []
    expected = {"status": "SUCCESS", "service_url": "https://x"}

    def impl(**kw):
        results.append(svc._run_subprocess(["echo", "hi"], cwd=base))
        results.append(svc._run_subprocess(["/bin/sh", "-c", "echo out; echo err >&2; exit 3"], cwd=base))
        return expected

    svc._deploy_workload_impl = impl
    res = svc.deploy_workload(product_id="app", trace_id="t1", time_budget_s=tf.SYNC_DEPLOY_TIME_BUDGET_S)
    assert res is expected
    assert results == [{"exit_code": 0, "stdout": "hi\n", "stderr": "", "success": True},
                       {"exit_code": 3, "stdout": "out\n", "stderr": "err\n", "success": False}]


def test_no_budget_means_the_per_command_limit_only_and_the_budget_ends_with_its_deploy(base):
    tf, svc = _runner(base, _import_service().TOFU_TIME_LIMITS_SERVICE)
    clock = _Clock()
    timeouts = []

    def impl(**kw):
        with patch.object(tf.subprocess, "Popen", return_value=_ok_proc()) as popen:
            svc._run_subprocess(["tofu", "plan"], cwd=base)
            timeouts.append(popen.return_value.communicate.call_args.kwargs["timeout"])
        return {"status": "SUCCESS"}

    svc._deploy_workload_impl = impl
    with patch.object(tf, "time", clock.module):
        svc.deploy_workload(product_id="app", trace_id="t1", time_budget_s=100.0)   # budgeted deploy first
        clock.now += 5000.0                                                         # its deadline long gone
        svc.deploy_workload(product_id="app", trace_id="t2")                        # same thread, no budget
        with patch.object(tf.subprocess, "Popen", return_value=_ok_proc()) as popen:
            assert svc._run_subprocess(["tofu", "plan"], cwd=base)["success"] is True   # outside a deploy
            timeouts.append(popen.return_value.communicate.call_args.kwargs["timeout"])
    assert timeouts == [100.0, 20 * 60, 20 * 60]


# ============================================================================ who passes the budget
def _client(tf_main):
    from fastapi.testclient import TestClient
    return TestClient(tf_main.app)


def test_sync_deploy_passes_the_budget(tf_main):
    tf_main.service.deploy_workload = MagicMock(return_value={"status": "SUCCESS", "service_url": "https://x"})
    r = _client(tf_main).post("/deploy", json={"product_id": "app", "trace_id": "t-sync"})
    assert r.status_code == 200
    assert tf_main.service.deploy_workload.call_args.kwargs["time_budget_s"] == tf_main.SYNC_DEPLOY_TIME_BUDGET_S
    assert tf_main.SYNC_DEPLOY_TIME_BUDGET_S == 1470.0


def test_in_process_async_deploy_passes_no_budget(tf_main, sent_callbacks):
    tf_main.service.deploy_workload = MagicMock(return_value={"status": "FAILED", "error": "x"})
    req = tf_main.AsyncDeployRequest(product_id="app", trace_id="t-async", callback_url="http://127.0.0.1:9/cb")
    with patch.object(tf_main, "trigger_tf_applier_job", return_value=False):
        tf_main.run_deploy_in_background(req)
    assert "time_budget_s" not in tf_main.service.deploy_workload.call_args.kwargs


def test_the_applier_job_passes_no_budget():
    import ast
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "..", "mcp-servers", "terraform", "applier.py")
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    by_function = {}
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef):
            for n in ast.walk(fn):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "deploy_workload":
                    by_function.setdefault(fn.name, []).append({k.arg for k in n.keywords})
    # The workflow deploy (Shared install and Per-workload callback run) passes no budget (per-command limits only).
    assert by_function.get("_run_deploy") and all("time_budget_s" not in kw for kw in by_function["_run_deploy"])
    # FD-7L 5b: only the synchronous Per-workload run (a sync /deploy dispatched as an execution) carries the
    # request's remaining DEPLOY-SYNC-BUDGET, exactly like the in-process sync /deploy it replaces.
    assert set(by_function) == {"_run_deploy", "_sync_result"}
    assert all("time_budget_s" in kw for kw in by_function["_sync_result"])
