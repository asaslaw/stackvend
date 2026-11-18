"""FD-4AQ W3 (register AQ-5, owner 10-25): workspace lifecycle and OpenTofu time limits in the Terraform MCP server.

1. Every OpenTofu command `_run_subprocess` starts has a time limit: in the tf-applier job apply/destroy 3 h and every
   other command 30 min; in mcp-terraform-server one ~25 min cap (grace included, below the 1800 s request limit).
   At the limit the process group gets SIGINT (OpenTofu releases the state lock), then SIGKILL after the grace period,
   and the result carries error_class TOFU_TIMEOUT. Inside a deploy nothing more runs after a timeout and the deploy
   fails with TOFU_TIMEOUT.
2. A deploy's trace folder is deleted when the deploy ends (success, failure, exception) on /deploy, the in-process
   /deploy-async path and the tf-applier job; plan folders are kept and swept after 24 h unless a running request
   holds them; the sweep never touches `.castor-tooling`, never follows a symlink.

Negative tests (Do No Harm): a command that finishes is returned exactly as before; a deploy without a timeout returns
the impl's result object unchanged; plan folders and young / held / tooling / symlinked folders are kept.

Hermetic: real short-lived local processes (`sleep`, this Python) only; no OpenTofu, no network, no cloud clients.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import signal
import subprocess
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

from test_fd4g_terraform_workspace import (  # noqa: F401  (pytest fixtures reused by name)
    _isolated_tf_service, _import_service, _no_network, _patched_applier, _svc, base, sent_callbacks, tf_main)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO, "mcp-servers", "terraform")


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


class _RecordingPopen:
    """Wraps the real Popen to keep a handle on every process started (so a test can check it is gone)."""

    def __init__(self, real):
        self.real, self.procs = real, []

    def __call__(self, *a, **k):
        p = self.real(*a, **k)
        self.procs.append(p)
        return p


# ============================================================================ limits table
def test_job_and_service_limits_match_the_register_row():
    tf = _import_service()
    job, srv = tf.TOFU_TIME_LIMITS_JOB, tf.TOFU_TIME_LIMITS_SERVICE
    assert job.limit_for(["tofu", "apply", "-auto-approve"]) == 3 * 3600
    assert job.limit_for(["tofu", "destroy"]) == 3 * 3600
    for sub in ("init", "validate", "plan", "show", "import", "state", "output", "force-unlock"):
        assert job.limit_for(["tofu", sub]) == 30 * 60, sub
        assert srv.limit_for(["tofu", sub]) == 20 * 60, sub
    assert srv.limit_for(["tofu", "apply"]) == 20 * 60
    assert job.grace_s == 15 * 60 and srv.grace_s == 4 * 60
    # per command: the server's worst case (limit + grace + the 30 s pipe drain) stays inside the 1800 s request limit
    assert 20 * 60 + 4 * 60 + 30 < 1800
    assert srv.apply_destroy_s + srv.grace_s + 30 < 1800
    assert tf.TOFU_TIMEOUT == "TOFU_TIMEOUT"


def test_new_service_uses_the_server_cap(base):
    tf = _import_service()
    assert _svc(tf, base).tofu_time_limits is tf.TOFU_TIME_LIMITS_SERVICE


def test_applier_uses_the_job_limits_and_removes_its_trace_folder(monkeypatch, base, sent_callbacks):
    seen = {}

    def deploy(**kw):
        # the job's own instance, mid-run: job limits; the workspace exists while the deploy runs
        os.makedirs(os.path.join(base, kw["trace_id"], "app", "infra"), exist_ok=True)
        seen["limits"] = deploy.owner.tofu_time_limits
        return {"status": "SUCCESS", "service_url": "https://x"}

    applier = _patched_applier(monkeypatch, base, "fd4aq_w3_applier", deploy)
    real_factory = applier.TerraformService

    def factory(*a, **k):
        inst = real_factory(*a, **k)
        deploy.owner = inst
        return inst

    monkeypatch.setattr(applier, "TerraformService", factory)
    monkeypatch.setenv("PRODUCT_ID", "app")
    with pytest.raises(SystemExit) as ei:
        applier.run_job()
    assert ei.value.code == 0
    assert seen["limits"] is _import_service().TOFU_TIME_LIMITS_JOB
    assert not os.path.exists(os.path.join(base, "tf-applier-app"))       # deleted when the run ended
    assert os.path.isdir(os.path.join(base, ".castor-tooling"))           # tooling kept
    assert sent_callbacks[-1]["status"] == "SUCCESS"


def test_applier_removes_its_trace_folder_when_the_deploy_raises(monkeypatch, base, sent_callbacks):
    def deploy(**kw):
        os.makedirs(os.path.join(base, kw["trace_id"], "app"), exist_ok=True)
        raise RuntimeError("boom")

    applier = _patched_applier(monkeypatch, base, "fd4aq_w3_applier_raise", deploy)
    monkeypatch.setenv("PRODUCT_ID", "app")
    with pytest.raises((RuntimeError, SystemExit)):
        applier.run_job()
    assert not os.path.exists(os.path.join(base, "tf-applier-app"))
    assert sent_callbacks[-1]["status"] == "FAILED"


# ============================================================================ the bounded runner
def test_a_command_over_its_limit_returns_tofu_timeout_and_is_gone(base):
    tf, svc = _runner(base, _import_service().TofuTimeLimits(apply_destroy_s=0.5, other_s=0.5, grace_s=2.0))
    rec = _RecordingPopen(subprocess.Popen)
    t0 = time.monotonic()
    with patch.object(tf.subprocess, "Popen", rec):
        res = svc._run_subprocess(["sleep", "30"], cwd=base)
    assert time.monotonic() - t0 < 10
    assert res["success"] is False and res["timed_out"] is True
    assert res["error_class"] == "TOFU_TIMEOUT"
    assert res["stderr"].startswith("TOFU_TIMEOUT: the OpenTofu command `30` did not finish within 0 seconds")
    assert len(rec.procs) == 1 and rec.procs[0].poll() is not None    # the process is gone
    assert rec.procs[0].returncode == -signal.SIGINT                  # SIGINT was enough (sleep dies on it)


# Plain shell children (no Python child: tests/test_hermetic_guard.py). $1 / $2 are file paths.
_SIGINT_CLEAN = (       # an engine that stops cleanly on SIGINT (as OpenTofu does, releasing its lock)
    'trap \'kill "$pid" 2>/dev/null; printf "lock released" > "$1"; exit 1\' INT\n'
    'printf ready > "$2"\n'
    'sleep 30 >/dev/null 2>&1 &\n'
    'pid=$!\n'
    'wait "$pid"\n'
)
_SIGINT_IGNORED = (     # an engine that ignores SIGINT
    "trap '' INT\n"
    'printf ready > "$1"\n'
    'sleep 30\n'
)


def _wait_for(path, seconds=10.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end and not os.path.exists(path):
        time.sleep(0.05)
    return os.path.exists(path)


def test_sigint_first_lets_the_engine_stop_cleanly(base):
    tf, svc = _runner(base, _import_service().TofuTimeLimits(apply_destroy_s=3.0, other_s=3.0, grace_s=5.0))
    released, ready = os.path.join(base, "released"), os.path.join(base, "ready")
    rec = _RecordingPopen(subprocess.Popen)
    with patch.object(tf.subprocess, "Popen", rec):
        res = svc._run_subprocess(["/bin/sh", "-c", _SIGINT_CLEAN, "sh", released, ready], cwd=base)
    assert os.path.exists(ready), "the child never started"
    assert res["error_class"] == "TOFU_TIMEOUT"
    assert "was interrupted." in res["stderr"] and "killed" not in res["stderr"]
    with open(released, encoding="utf-8") as fh:
        assert fh.read() == "lock released"                           # its SIGINT handler ran
    assert rec.procs[0].returncode == 1


def test_a_command_ignoring_sigint_is_killed_after_the_grace_period(base):
    tf, svc = _runner(base, _import_service().TofuTimeLimits(apply_destroy_s=3.0, other_s=3.0, grace_s=1.0))
    ready = os.path.join(base, "ready")
    rec = _RecordingPopen(subprocess.Popen)
    with patch.object(tf.subprocess, "Popen", rec):
        res = svc._run_subprocess(["/bin/sh", "-c", _SIGINT_IGNORED, "sh", ready], cwd=base)
    assert os.path.exists(ready), "the child never started"
    assert res["error_class"] == "TOFU_TIMEOUT"
    assert "was interrupted, then killed." in res["stderr"]
    assert "the state lock may still be held and the last resource being created may be missing from state" in res[
        "stderr"]
    assert rec.procs[0].returncode == -signal.SIGKILL


def test_a_command_that_finishes_is_unchanged(base):
    """Do No Harm: the result of a command within its limit is exactly what it was before (no new keys)."""
    tf, svc = _runner(base, _import_service().TofuTimeLimits(apply_destroy_s=30, other_s=30))
    res = svc._run_subprocess(["/bin/sh", "-c", "echo out; echo err >&2; exit 3"], cwd=base)
    assert res == {"exit_code": 3, "stdout": "out\n", "stderr": "err\n", "success": False}
    res = svc._run_subprocess(["echo", "hi"], cwd=base)
    assert res == {"exit_code": 0, "stdout": "hi\n", "stderr": "", "success": True}


def test_engine_starts_in_its_own_process_group_with_the_same_arguments(base):
    tf, svc = _runner(base, _import_service().TOFU_TIME_LIMITS_SERVICE)
    proc = MagicMock(pid=None, returncode=0)
    proc.communicate.return_value = ("ok", "")
    with patch.object(tf.subprocess, "Popen", return_value=proc) as popen:
        svc._run_subprocess(["tofu", "plan", "-input=false"], cwd=base, iac_engine="OPENTOFU")
    kw = popen.call_args.kwargs
    assert popen.call_args.args[0][:2] == ["tofu", "plan"]
    assert kw["cwd"] == base and kw["text"] is True and kw["start_new_session"] is True
    assert kw["stdout"] is subprocess.PIPE and kw["stderr"] is subprocess.PIPE
    assert proc.communicate.call_args.kwargs == {"timeout": 20 * 60}


# ============================================================================ deploy scope
class _TimingOutProc:
    pid = None
    returncode = -2

    def __init__(self):
        self.calls = 0

    def communicate(self, timeout=None):
        self.calls += 1
        if self.calls == 1:
            raise subprocess.TimeoutExpired("tofu", timeout)
        return "partial", "Interrupt received.\nError: operation canceled"


def test_a_timeout_inside_a_deploy_stops_the_deploy_with_tofu_timeout(base):
    tf, svc = _runner(base, _import_service().TOFU_TIME_LIMITS_JOB)
    started, results = [], []

    def popen(cmd, **kw):
        started.append(cmd[1])
        return _TimingOutProc()

    def impl(**kw):
        results.append(svc._run_subprocess(["tofu", "apply", "-auto-approve"], cwd=base))
        results.append(svc._run_subprocess(["tofu", "state", "list"], cwd=base))     # never started
        return {"status": "FAILED", "error": "Terraform apply failed: " + results[0]["stderr"], "stdout": ""}

    svc._deploy_workload_impl = impl
    with patch.object(tf.subprocess, "Popen", side_effect=popen):
        res = svc.deploy_workload(product_id="app", trace_id="t1")
    assert started == ["apply"]
    assert results[1]["error_class"] == "TOFU_TIMEOUT" and results[1]["stderr"] == results[0]["stderr"]
    # the engine's own text never reaches stderr (no healer reads an interrupted run as a defect)
    assert "operation canceled" not in results[0]["stderr"] and results[0]["stdout"] == "partial"
    assert res["status"] == "FAILED" and res["error_class"] == "TOFU_TIMEOUT"
    assert res["error"].startswith("TOFU_TIMEOUT: the OpenTofu command `apply` did not finish within 10800 seconds")
    # the scope ends with the deploy: the next command (outside a deploy) runs normally
    ok = MagicMock(pid=None, returncode=0)
    ok.communicate.return_value = ("fine", "")
    with patch.object(tf.subprocess, "Popen", return_value=ok):
        assert svc._run_subprocess(["tofu", "output"], cwd=base)["success"] is True


def test_a_deploy_without_a_timeout_returns_the_impl_result_unchanged(base):
    tf, svc = _runner(base, _import_service().TOFU_TIME_LIMITS_JOB)
    for result in ({"status": "SUCCESS", "service_url": "https://x"},
                   {"status": "FAILED", "error_class": "STATE_LOCKED", "error": "STATE_LOCKED: held"}):
        svc._deploy_workload_impl = lambda **kw: result
        assert svc.deploy_workload(product_id="app", trace_id="t1") is result


def test_a_timeout_outside_a_deploy_does_not_block_later_commands(base):
    tf, svc = _runner(base, _import_service().TOFU_TIME_LIMITS_SERVICE)
    with patch.object(tf.subprocess, "Popen", side_effect=lambda *a, **k: _TimingOutProc()):
        assert svc._run_subprocess(["tofu", "plan"], cwd=base)["error_class"] == "TOFU_TIMEOUT"
    ok = MagicMock(pid=None, returncode=0)
    ok.communicate.return_value = ("fine", "")
    with patch.object(tf.subprocess, "Popen", return_value=ok) as popen:
        assert svc._run_subprocess(["tofu", "plan"], cwd=base)["success"] is True
    popen.assert_called_once()


# ============================================================================ workspace lifecycle (unit)
def _lifecycle(base, clock=time.time):
    tf = _import_service()
    svc = _svc(tf, base)
    # Loaded per call, like this test's service.py (fd4g_support.load_tf_service), so both use the same
    # shared.path_safety: a module cached by an earlier test may hold an UnsafePathError class from a path_safety
    # that was re-imported since, and `_delete_trace`'s `except UnsafePathError` would then miss the service's error.
    import importlib.util
    spec = importlib.util.spec_from_file_location("workspace_lifecycle", os.path.join(TF_DIR, "workspace_lifecycle.py"))
    wlm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wlm)
    return wlm.WorkspaceLifecycle(svc.workspace_root, svc.workspace_trace_dir, clock=clock), svc


def _mk(base, *parts):
    p = os.path.join(base, *parts)
    os.makedirs(p, exist_ok=True)
    with open(os.path.join(p, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write("# x\n")
    return p


def _age(path, seconds):
    t = time.time() - seconds
    for root, dirs, files in os.walk(path):
        for n in dirs + files:
            os.utime(os.path.join(root, n), (t, t), follow_symlinks=False)
    os.utime(path, (t, t), follow_symlinks=False)


@pytest.mark.parametrize("outcome", ["success", "exception"])
def test_deploy_hold_deletes_the_trace_folder_however_it_ends(base, outcome):
    wl, _ = _lifecycle(base)
    _mk(base, "keep-me", "app")
    with pytest.raises(RuntimeError) if outcome == "exception" else _null():
        with wl.hold("t-deploy", delete_on_release=True):
            _mk(base, "t-deploy", "app", "infra")
            if outcome == "exception":
                raise RuntimeError("deploy blew up")
    assert not os.path.exists(os.path.join(base, "t-deploy"))
    assert os.path.isdir(os.path.join(base, "keep-me", "app"))
    assert os.path.isdir(os.path.join(base, ".castor-tooling"))
    assert wl.active_traces() == []


class _null:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_a_shared_trace_id_is_deleted_only_when_the_last_holder_ends(base):
    wl, _ = _lifecycle(base)
    with wl.hold("auto-deploy", delete_on_release=True):
        with wl.hold("auto-deploy", delete_on_release=True):
            _mk(base, "auto-deploy", "a")
        assert os.path.isdir(os.path.join(base, "auto-deploy", "a"))     # the other deploy still runs
        _mk(base, "auto-deploy", "b")
    assert not os.path.exists(os.path.join(base, "auto-deploy"))


def test_plan_hold_keeps_the_folder(base):
    wl, _ = _lifecycle(base)
    with wl.hold("t-plan", delete_on_release=False):
        _mk(base, "t-plan", "app")
    assert os.path.isdir(os.path.join(base, "t-plan", "app"))


def test_release_never_follows_a_symlinked_trace_folder(base, tmp_path):
    wl, _ = _lifecycle(base)
    target = tmp_path / "outside"
    target.mkdir()
    (target / "precious.txt").write_text("x")
    os.symlink(str(target), os.path.join(base, "t-link"))
    with wl.hold("t-link", delete_on_release=True):
        pass
    assert (target / "precious.txt").exists()
    assert os.path.islink(os.path.join(base, "t-link"))


def test_sweep_deletes_only_old_unheld_trace_folders(base, tmp_path):
    wl, _ = _lifecycle(base)
    day = 24 * 3600
    old = _mk(base, "t-old", "app")
    young = _mk(base, "t-young", "app")
    held = _mk(base, "t-held", "app")
    tooling_file = os.path.join(base, ".castor-tooling", "terraform.rc")
    with open(tooling_file, "w", encoding="utf-8") as fh:
        fh.write("x")
    odd = _mk(base, "_not-a-trace")
    # an old trace folder holding a symlink to something outside: the link goes, its target stays
    outside = tmp_path / "outside2"
    outside.mkdir()
    (outside / "keep.txt").write_text("x")
    linked = _mk(base, "t-old-link", "app")
    os.symlink(str(outside), os.path.join(linked, "modules"))
    # a symlink at the root pointing at an old folder elsewhere: never followed, never removed
    far = tmp_path / "far"
    far.mkdir()
    (far / "keep.txt").write_text("x")
    os.symlink(str(far), os.path.join(base, "t-rootlink"))
    for p in (old, held, os.path.join(base, ".castor-tooling"), odd, linked, str(far)):
        _age(os.path.dirname(p) if p.endswith("app") else p, 2 * day)
    _age(os.path.join(base, "t-young"), 2 * day)
    os.utime(young, None)                                  # a fresh entry inside keeps the folder young
    with wl.hold("t-held", delete_on_release=False):
        deleted = wl.sweep(ttl_seconds=day)
    assert sorted(deleted) == ["t-old", "t-old-link"]
    assert not os.path.exists(os.path.join(base, "t-old"))
    assert not os.path.exists(os.path.join(base, "t-old-link"))
    assert (outside / "keep.txt").exists() and (far / "keep.txt").exists()
    for kept in ("t-young", "t-held", "_not-a-trace", "t-rootlink"):
        assert os.path.lexists(os.path.join(base, kept)), kept
    assert os.path.isfile(tooling_file)


def test_sweep_ttl_comes_from_the_environment(monkeypatch):
    if TF_DIR not in sys.path:
        sys.path.insert(0, TF_DIR)
    import workspace_lifecycle as wlm
    monkeypatch.delenv("TF_WORKSPACE_TTL_HOURS", raising=False)
    assert wlm.workspace_ttl_seconds() == 24 * 3600
    monkeypatch.setenv("TF_WORKSPACE_TTL_HOURS", "6")
    assert wlm.workspace_ttl_seconds() == 6 * 3600
    for bad in ("x", "0", "-3"):
        monkeypatch.setenv("TF_WORKSPACE_TTL_HOURS", bad)
        assert wlm.workspace_ttl_seconds() == 24 * 3600


def test_maybe_sweep_runs_at_most_once_per_interval(base):
    now = [1_000_000.0]
    wl, _ = _lifecycle(base, clock=lambda: now[0])
    with patch.object(wl, "sweep", wraps=wl.sweep) as sweep:
        wl.maybe_sweep()
        wl.maybe_sweep()
        now[0] += 301
        wl.maybe_sweep()
    assert sweep.call_count == 2


# ============================================================================ server endpoints
def _client(tf_main):
    from fastapi.testclient import TestClient
    return TestClient(tf_main.app)


@pytest.mark.parametrize("mode", ["success", "failure", "exception"])
def test_sync_deploy_deletes_its_trace_folder(tf_main, base, mode):
    def deploy(**kw):
        _mk(base, kw["trace_id"], kw["product_id"], "infra")
        if mode == "exception":
            raise RuntimeError("boom")
        return {"status": "SUCCESS" if mode == "success" else "FAILED", "error": "x", "service_url": "https://x"}

    tf_main.service.deploy_workload = deploy
    _mk(base, "t-other", "app")
    r = _client(tf_main).post("/deploy", json={"product_id": "app", "trace_id": "t-sync"})
    assert r.status_code == (200 if mode == "success" else 500)
    assert not os.path.exists(os.path.join(base, "t-sync"))
    assert os.path.isdir(os.path.join(base, "t-other", "app"))
    assert tf_main.workspaces.active_traces() == []


def test_in_process_async_deploy_deletes_its_trace_folder(tf_main, base, sent_callbacks):
    def deploy(**kw):
        _mk(base, kw["trace_id"], kw["product_id"], "infra")
        return {"status": "FAILED", "error": "x"}

    tf_main.service.deploy_workload = deploy
    req = tf_main.AsyncDeployRequest(product_id="app", trace_id="t-async", callback_url="http://127.0.0.1:9/cb")
    with patch.object(tf_main, "trigger_tf_applier_job", return_value=False):
        tf_main.run_deploy_in_background(req)
    assert not os.path.exists(os.path.join(base, "t-async"))
    assert sent_callbacks[-1]["status"] == "FAILED"


def test_job_dispatch_leaves_the_server_folder_alone(tf_main, base):
    _mk(base, "t-job", "app")
    tf_main.service.deploy_workload = MagicMock()
    req = tf_main.AsyncDeployRequest(product_id="app", trace_id="t-job", callback_url="http://127.0.0.1:9/cb")
    with patch.object(tf_main, "trigger_tf_applier_job", return_value=True):
        tf_main.run_deploy_in_background(req)
    tf_main.service.deploy_workload.assert_not_called()
    assert os.path.isdir(os.path.join(base, "t-job", "app"))


def test_plan_apply_and_drift_folders_are_kept_and_held_while_running(tf_main, base):
    held = []

    def plan(product_id, trace_id, hcl_files, iac_engine=None):
        held.append(tf_main.workspaces.active_traces())
        _mk(base, trace_id, product_id)
        return {"status": "PLANNED"}

    tf_main.service.generate_plan = plan
    tf_main.service.apply_plan = MagicMock(side_effect=lambda *a, **k: held.append(
        tf_main.workspaces.active_traces()) or {"status": "SUCCESS"})
    tf_main.service.check_drift = MagicMock(side_effect=lambda *a, **k: held.append(
        tf_main.workspaces.active_traces()) or {"status": "IN_SYNC"})
    c = _client(tf_main)
    assert c.post("/plan", json={"product_id": "app", "trace_id": "t-plan", "hcl_files": {"main.tf": ""}}).status_code == 200
    assert c.post("/apply", json={"product_id": "app", "trace_id": "t-plan"}).status_code == 200
    assert c.post("/drift-check", json={"product_id": "app", "trace_id": "t-plan"}).status_code == 200
    assert held == [["t-plan"], ["t-plan"], ["t-plan"]]
    assert os.path.isdir(os.path.join(base, "t-plan", "app"))
    assert tf_main.workspaces.active_traces() == []


def test_request_sweep_is_off_outside_cloud_run_and_on_when_enabled(tf_main, base, monkeypatch):
    old = _mk(base, "t-stale", "app")
    _age(os.path.dirname(old), 3 * 24 * 3600)
    tf_main.service.check_drift = MagicMock(return_value={"status": "IN_SYNC"})
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("STACKVEND_WORKSPACE_SWEEP", raising=False)
    c = _client(tf_main)
    c.post("/drift-check", json={"product_id": "app", "trace_id": "t1"})
    assert os.path.isdir(os.path.join(base, "t-stale"))
    monkeypatch.setenv("STACKVEND_WORKSPACE_SWEEP", "1")
    c.post("/drift-check", json={"product_id": "app", "trace_id": "t1"})
    assert not os.path.exists(os.path.join(base, "t-stale"))
    assert os.path.isdir(os.path.join(base, ".castor-tooling"))


def test_a_timed_out_init_is_not_retried():
    """Review F4: the deploy's init retry loop (6 attempts, 5..25 s sleeps) stops at a TOFU_TIMEOUT result
    (and, after the merge with FD-4AQ W1b, at any typed result such as PROVIDER_NOT_ALLOWED)."""
    import ast
    src = open(os.path.join(TF_DIR, "service.py"), encoding="utf-8").read()
    loops = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.For)
             and ast.unparse(n.iter) == "range(1, 7)" and "'init'" in ast.unparse(n)]
    assert len(loops) == 1
    breaks = [n for n in ast.walk(loops[0]) if isinstance(n, ast.If) and any(isinstance(b, ast.Break) for b in n.body)]
    assert [ast.unparse(b.test) for b in breaks] == [
        "init_res['success'] or init_res.get('error_class') or init_res.get('timed_out')"]
