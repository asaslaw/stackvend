"""SAT-41 (FD-7L pre-switch red-team review, HIGH-2 (a)): the runner identity mode switch is refused while any
Terraform run may be in flight.

`RunnerIdentityModeSetting.set` (vending) refuses RUNNER_MODE_SWITCH_BUSY (409, nothing written or signed) while a
`pipeline_executions` terraform stage of ANY workload is IN_FLIGHT (younger than the workflow's 87 300 s callback wait)
or ANY tf-applier execution is running. It reuses the backfill's drain check (runner_identity_backfill.runs_in_flight,
install-wide); a read error is busy. The Control Center passes the refusal through and keeps it on the card.

Do No Harm: the backfill's per-workload drain answers exactly as before; a switch to the mode already in force is
still a no-op (no read of in-flight runs, nothing written); an idle install switches as before. Hermetic fakes only.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import json
import os
from datetime import timedelta

import pytest

import destructive_guard_fakes as f
import fd7l_gcs_fakes as g
from test_fd7l_f4_mode_record import (  # noqa: F401  (fixtures and helpers reused by name)
    ADMIN, REPO, VRI, _fresh_cache, _mode_docs, _req, _setting, _vworld, cc)
from test_fd7l_f4_mode_record import rim  # noqa: F401
from test_fd7l_phase3_backfill import W, PID, rib  # noqa: F401
from test_fd7l_phase3_readers import _Resp  # noqa: F401

NOW = f.NOW


def _iso(dt):
    return dt.isoformat()


def _in_flight(world, pid="other-workload", started=None, status="IN_FLIGHT", trace="tr-1"):
    tf = {"status": status, "state": "AWAITING_CALLBACK"}
    if started is not None:
        tf["started_at"] = _iso(started)
    world.db.docs[f"pipeline_executions/{trace}"] = {"product_id": pid, "current_stage": "TERRAFORM",
                                                     "stages": {"terraform": tf}}


def _switch(world, mode="PER_WORKLOAD", version=0):
    return _setting(world).set(f.CC_SA, mode=mode, expected_version=version, operator_email=ADMIN)


def _refused(world, **kw):
    with pytest.raises(VRI.RunnerIdentityError) as e:
        _switch(world, **kw)
    assert e.value.code == "RUNNER_MODE_SWITCH_BUSY" and e.value.http_status == 409
    assert _mode_docs(world) == {} and world.signed == []
    return e.value


# ---------------------------------------------------------------------------------------------- refusals
def test_an_in_flight_deploy_of_any_workload_refuses_the_switch():
    w = _vworld()
    _in_flight(w, started=NOW - timedelta(minutes=5))
    err = _refused(w)
    assert "pipeline_executions/tr-1 terraform IN_FLIGHT" in err.detail and "nothing was changed" in err.detail


def test_a_running_tf_applier_execution_refuses_the_switch_in_both_directions():
    w = _vworld()
    w.google.running = [{"name": g.EXECUTIONS + "/x1"}]          # a vending dispatch: no PRODUCT_ID in its env
    assert "tf-applier execution" in _refused(w).detail
    w.google.running = []
    _switch(w)                                                    # PER_WORKLOAD, version 1
    VRI.clear_mode_cache()
    w.google.running = [{"name": g.EXECUTIONS + "/x2", "template": {"containers": [
        {"env": [{"name": "PRODUCT_ID", "value": "any"}]}]}}]      # a Shared-path start
    signed_before = len(w.signed)
    with pytest.raises(VRI.RunnerIdentityError) as e:
        _switch(w, mode="PLATFORM", version=1)
    assert e.value.code == "RUNNER_MODE_SWITCH_BUSY" and len(w.signed) == signed_before
    assert w.db.doc("install_settings/runner_identity")["mode"] == "PER_WORKLOAD"


def test_an_in_flight_stage_without_a_start_time_is_busy():
    w = _vworld()
    _in_flight(w)
    _refused(w)


@pytest.mark.parametrize("breaker", ["pipeline_executions", "executions", "region"])
def test_what_cannot_be_read_is_busy(breaker):
    w = _vworld()
    if breaker == "pipeline_executions":
        w.db.fail_paths.add("pipeline_executions?query")
    elif breaker == "executions":
        real = w.google.call
        w.google.call = lambda m, url, **kw: (503, {}) if url.endswith("/executions") else real(m, url, **kw)
    else:
        w.deps.region = lambda: None
    _refused(w)


# ---------------------------------------------------------------------------------------------- Do No Harm
def test_an_idle_install_switches_as_before():
    w = _vworld()
    _in_flight(w, status="SUCCESS")
    w.google.running = [{"name": g.EXECUTIONS + "/done", "completionTime": _iso(NOW)}]
    out = _switch(w)
    assert out["changed"] is True and out["version"] == 1


def test_a_stage_older_than_the_workflow_wait_does_not_block():
    w = _vworld()
    _in_flight(w, started=NOW - timedelta(seconds=87300 + 60))   # its workflow stopped waiting long ago
    assert _switch(w)["changed"] is True


def test_the_mode_in_force_is_still_a_no_op_without_the_check():
    w = _vworld()
    _in_flight(w, started=NOW)
    w.db.fail_paths.add("pipeline_executions?query")
    assert _switch(w, mode="PLATFORM") == {"changed": False, "mode": "PLATFORM", "version": 0}
    assert w.db.writes == [] and w.signed == []


def test_the_backfill_drain_is_unchanged_for_one_workload():
    """The per-workload drain ignores other workloads and never skips an old IN_FLIGHT stage of its own."""
    w = W()
    w.db.docs["pipeline_executions/tr-other"] = {"product_id": "other", "stages": {"terraform": {
        "status": "IN_FLIGHT", "started_at": _iso(NOW)}}}
    assert w.backfill()._in_flight(PID) is None
    w.db.docs["pipeline_executions/tr-old"] = {"product_id": PID, "stages": {"terraform": {
        "status": "IN_FLIGHT", "started_at": _iso(NOW - timedelta(days=30))}}}
    assert w.backfill()._in_flight(PID) == "pipeline_executions/tr-old terraform IN_FLIGHT"
    assert rib.runs_in_flight(w.deps, PID) == w.backfill()._in_flight(PID)


def test_one_in_flight_reader():
    src = open(os.path.join(REPO, "apps", "project-vending", "runner_identity_backfill.py")).read()
    assert src.count('collection("pipeline_executions")') == 1
    mode_src = open(os.path.join(REPO, "apps", "project-vending", "runner_identity_mode.py")).read()
    assert "rib.runs_in_flight(" in mode_src and "pipeline_executions\")" not in mode_src


# ---------------------------------------------------------------------------------------------- Control Center
def test_cc_passes_the_busy_refusal_through_and_keeps_it_on_the_card(cc, monkeypatch):
    from routes import runner_identity_card as card

    def requester(method, path, json_body=None, timeout=None, request=None):
        return _Resp(409, {"detail": {"code": "RUNNER_MODE_SWITCH_BUSY", "stage": "runner-identity-mode",
                                      "detail": "a Terraform run may be in flight (x)"}})

    monkeypatch.setattr(card, "vending_requester", requester)
    monkeypatch.setattr(card, "clock", lambda: 10_000.0)
    body = card.RunnerIdentityModeBody(mode="PER_WORKLOAD", expected_version=0, confirm="PER_WORKLOAD")
    resp = card.set_runner_identity_mode(_req(issued=9_999), body)
    assert resp.status_code == 409 and json.loads(resp.body)["code"] == "RUNNER_MODE_SWITCH_BUSY"
    html = open(os.path.join(REPO, "apps", "control-center", "templates", "dashboard.html"), encoding="utf-8").read()
    assert "data-runner-identity-mode-error" in html and "data.code === 'RUNNER_MODE_SWITCH_BUSY'" in html


def test_the_class_is_in_the_fail_loudly_policy():
    doc = open(os.path.join(REPO, "documentation", "fail-loudly-policy.md")).read()
    assert "RUNNER_MODE_SWITCH_BUSY" in doc


# ---------------------------------------------------------------------------------------------- parity (RT LOW-1)
def _find_step(node, name):
    if isinstance(node, dict):
        if name in node:
            return node[name]
        node = list(node.values())
    if isinstance(node, list):
        for item in node:
            hit = _find_step(item, name)
            if hit is not None:
                return hit
    return None


def test_the_stale_cut_equals_the_workflow_wait_and_exceeds_the_job_timeout():
    """Deviation (a) is safe only while: tf-applier job timeout < WORKFLOW_DEPLOY_WAIT == the workflow's wait for the
    deploy callback (a stage IN_FLIGHT longer than that has no waiting workflow and no job still inside its timeout)."""
    import re
    import yaml
    with open(os.path.join(REPO, "workflows", "main_orchestrator.yaml"), encoding="utf-8") as fh:
        wf = yaml.safe_load(fh)
    step = _find_step(wf, "await_deploy_callback")
    assert step is not None, "await_deploy_callback step not found"
    wait = step["try"]["args"]["timeout"]
    assert wait == rib.WORKFLOW_DEPLOY_WAIT.total_seconds()
    tf = open(os.path.join(REPO, "infra", "platform", "main.tf"), encoding="utf-8").read()
    block = tf[tf.index('resource "google_cloud_run_v2_job" "tf_applier"'):]
    block = block[:block.index("\nresource ")] if "\nresource " in block else block
    (job_timeout,) = re.findall(r'^\s*timeout\s*=\s*"(\d+)s"', block, flags=re.M)
    assert int(job_timeout) == 86400 and rib.WORKFLOW_DEPLOY_WAIT.total_seconds() > int(job_timeout)
