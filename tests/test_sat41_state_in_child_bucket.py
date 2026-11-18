"""SAT-41 (FD-7L pre-switch red-team review, HIGH-3, the cheaper RC variant): on a Shared install the terraform
runner refuses (STATE_IN_CHILD_BUCKET, operator_required, nothing initialized) a workload whose READY runner identity
record names a child bucket holding a live `default.tfstate` while the platform bucket holds none for it: a Shared run
would plan from an empty state (a silent lineage split after a switch back to Shared). One existence read each,
platform first; no heuristic.

Do No Harm: before step A (no guard database or broker identity on the process) nothing is read; a workload without a
READY record, or with platform state, runs exactly as before (no child read); the Per-workload path is untouched.
Hermetic: the guard database and the bucket reads are fakes.
"""
import hermetic_guard  # noqa: F401  (first import)

import logging

import pytest

import fd7l_fakes as k
from test_fd7l_2b_runner_state import (  # noqa: F401  (fixtures and helpers reused by name)
    CHILD_BUCKET, PID, PLATFORM_BUCKET, PROJECT, GuardDB, _guard, _per_workload, _svc, forged, provenance,
    signed_record, tf)
from shared import runner_identity as ri


class Buckets:
    """Live state objects per bucket; records every existence read (bucket, client_project)."""

    def __init__(self, live=(), fail=None):
        self.live, self.fail, self.reads = set(live), fail, []

    def __call__(self, bucket, product_id, client_project=None):
        self.reads.append((bucket, client_project))
        if self.fail == bucket:
            raise RuntimeError("403 Forbidden")
        assert product_id == PID
        return bucket in self.live


def _shared(monkeypatch, tf, tmp_path, record=None, live=(), fail=None, guard=None, step_a=True):
    if step_a:
        monkeypatch.setenv(ri.GUARD_DB_ENV, "stackvend-guard")
        monkeypatch.setenv(ri.BROKER_SA_ENV, k.BROKER)
    svc = _svc(tf, tmp_path, guard if guard is not None else _guard(record))
    svc._runner_identity_mode = lambda: ri.MODE_PLATFORM    # the operative mode: Shared (switched back)
    buckets = Buckets(live, fail)
    svc._live_state_exists = buckets
    return svc, buckets


def _refused(tf, svc):
    with pytest.raises(tf.RunnerIdentityRefused) as e:
        svc._runner_state_context(PID, target_project_id=PROJECT)
    return e.value


# ---------------------------------------------------------------------------------------------- the refusal
def test_state_only_in_the_child_bucket_is_refused(tf, tmp_path, monkeypatch):
    svc, buckets = _shared(monkeypatch, tf, tmp_path, signed_record(), live={CHILD_BUCKET})
    err = _refused(tf, svc)
    assert err.error_class == "STATE_IN_CHILD_BUCKET"
    assert f"gs://{CHILD_BUCKET}/workloads/{PID}/default.tfstate" in err.message and "signed by vending" in err.message
    assert buckets.reads == [(PLATFORM_BUCKET, None), (CHILD_BUCKET, PROJECT)]
    res = err.result(PID, "t1")
    assert res["status"] == "FAILED" and res["operator_required"] is True


def test_every_run_kind_stops_before_anything(tf, tmp_path, monkeypatch):
    svc, _ = _shared(monkeypatch, tf, tmp_path, signed_record(), live={CHILD_BUCKET})
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **kw: pytest.fail("tofu must not run"))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **kw: None)
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **kw: "tofu")
    res = svc.generate_plan(PID, "t1", {"main.tf": "# ok\n"}, iac_engine="OPENTOFU")
    assert res["error_class"] == "STATE_IN_CHILD_BUCKET" and res["is_safe_autonomous"] is False
    res = svc.force_unlock(product_id=PID, lock_id="1", trace_id="t2")
    assert res["status"] == "FAILED" and res["error_class"] == "STATE_IN_CHILD_BUCKET"


def test_a_record_whose_signature_no_longer_verifies_still_refuses_and_says_so(tf, tmp_path, monkeypatch):
    """After a switch back to Shared the re-sign sweep is off; the check only refuses, so it still applies."""
    svc, _ = _shared(monkeypatch, tf, tmp_path, forged(), live={CHILD_BUCKET})
    err = _refused(tf, svc)
    assert err.error_class == "STATE_IN_CHILD_BUCKET" and "signature not verified: RUNNER_RECORD_UNSIGNED" in err.message


def test_unreadable_reads_are_typed(tf, tmp_path, monkeypatch):
    svc, _ = _shared(monkeypatch, tf, tmp_path, signed_record(), fail=CHILD_BUCKET)
    assert _refused(tf, svc).error_class == "STATE_LOCATION_UNREADABLE"
    svc, _ = _shared(monkeypatch, tf, tmp_path, signed_record(), fail=PLATFORM_BUCKET)
    assert _refused(tf, svc).error_class == "STATE_LOCATION_UNREADABLE"
    svc, buckets = _shared(monkeypatch, tf, tmp_path, guard=GuardDB(boom=True))
    assert _refused(tf, svc).error_class == "RUNNER_STORE_UNAVAILABLE" and buckets.reads == []


# ---------------------------------------------------------------------------------------------- Do No Harm
def test_platform_state_present_proceeds_without_a_child_read(tf, tmp_path, monkeypatch):
    svc, buckets = _shared(monkeypatch, tf, tmp_path, signed_record(), live={PLATFORM_BUCKET, CHILD_BUCKET})
    ctx = svc._runner_state_context(PID, target_project_id=PROJECT)
    assert (ctx.mode, ctx.bucket, ctx.source) == (ri.MODE_PLATFORM, PLATFORM_BUCKET, "platform")
    assert buckets.reads == [(PLATFORM_BUCKET, None)]


def test_no_state_anywhere_proceeds(tf, tmp_path, monkeypatch):
    svc, buckets = _shared(monkeypatch, tf, tmp_path, signed_record())
    assert svc._runner_state_context(PID).bucket == PLATFORM_BUCKET
    assert len(buckets.reads) == 2


@pytest.mark.parametrize("record", [None, "BUCKET_READY", "MIGRATING", "FAILED"])
def test_no_ready_record_reads_no_bucket(tf, tmp_path, monkeypatch, record):
    rec = signed_record(status=record) if record else None
    svc, buckets = _shared(monkeypatch, tf, tmp_path, rec, live={CHILD_BUCKET})
    assert svc._runner_state_context(PID).bucket == PLATFORM_BUCKET
    assert buckets.reads == [] and svc.guard_db.reads == [f"{ri.PROVENANCE_COLLECTION}/{PID}"]


@pytest.mark.parametrize("env", [(), (ri.GUARD_DB_ENV,), (ri.BROKER_SA_ENV,)])
def test_before_step_a_nothing_is_read(tf, tmp_path, monkeypatch, env):
    for name in (ri.GUARD_DB_ENV, ri.BROKER_SA_ENV):
        monkeypatch.delenv(name, raising=False)
    for name in env:
        monkeypatch.setenv(name, "x")
    svc, buckets = _shared(monkeypatch, tf, tmp_path, guard=GuardDB(boom=True), live={CHILD_BUCKET}, step_a=False)
    ctx = svc._runner_state_context(PID, target_project_id=PROJECT)
    assert ctx.bucket == PLATFORM_BUCKET and svc.guard_db.reads == [] and buckets.reads == []


def test_a_record_naming_another_projects_bucket_is_logged_and_the_run_proceeds(tf, tmp_path, monkeypatch, caplog):
    svc, buckets = _shared(monkeypatch, tf, tmp_path, signed_record(state_bucket="someone-elses-bucket"),
                           live={"someone-elses-bucket"})
    with caplog.at_level(logging.ERROR):
        assert svc._runner_state_context(PID).bucket == PLATFORM_BUCKET
    assert buckets.reads == [] and "STATE_LOCATION_UNCHECKED" in caplog.text


def test_per_workload_path_never_runs_the_check(tf, tmp_path, monkeypatch):
    _per_workload(monkeypatch)
    monkeypatch.setenv(ri.GUARD_DB_ENV, "stackvend-guard")
    svc = _svc(tf, tmp_path, _guard(signed_record()))
    svc._refuse_state_left_in_child_bucket = lambda *a: pytest.fail("Shared-path check on a Per-workload install")
    ctx = svc._runner_state_context(PID, target_project_id=PROJECT)
    assert ctx.per_workload and ctx.bucket == CHILD_BUCKET
