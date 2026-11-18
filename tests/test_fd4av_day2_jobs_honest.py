"""FD-4AV-a: the infra-rollback and FinOps-enforcer services report real outcomes (owner row FD-4AV-a, 10-20).

- rollback: no client/bucket -> ROLLBACK_UNAVAILABLE (no fabricated history); < 2 generations -> NO_PREVIOUS_VERSION
  (never restore the live generation onto itself); a held state lock -> REFUSED_STATE_LOCKED with zero copy calls;
  the Firestore audit status equals the real outcome; HTTP codes match the outcome.
- both Cloud Run jobs (``run_batch``): exit 0 only on a real success, 1 on failure/refusal, 2 on malformed input,
  3 NOT_CONFIGURED (WARNING) when a required env var is missing; the run record is claimed with create().
- behavior kept (negative tests): a real two-generation revert copies exactly the previous generation, once.

Hermetic: GCS/Firestore are in-memory fakes; the enforcer's Google clients are MagicMocks.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import logging
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

HERE = os.path.dirname(os.path.abspath(__file__))
ROLLBACK_DIR = os.path.join(HERE, "..", "apps", "infra-rollback")
FINOPS_DIR = os.path.join(HERE, "..", "apps", "finops-enforcer")
_NO_ADC = {"PROJECT_ID": "", "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/fd4av-adc.json"}


def _load(name, directory, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(directory, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


with patch.dict(os.environ, _NO_ADC):
    rb = _load("fd4av_rollback", ROLLBACK_DIR, "rollback.py")
    with patch.dict(sys.modules, {"rollback": rb}):
        rb_main = _load("fd4av_rollback_main", ROLLBACK_DIR, "main.py")
    enf = _load("fd4av_enforcer", FINOPS_DIR, "enforcer.py")
    with patch.dict(sys.modules, {"enforcer": enf}):
        enf_main = _load("fd4av_enforcer_main", FINOPS_DIR, "main.py")

PID = "auth-service"
STATE = f"workloads/{PID}/default.tfstate"
LOCK = f"workloads/{PID}/default.tflock"


# ------------------------------------------------------------------------------ fakes
class _Blob:
    def __init__(self, name, generation):
        self.name, self.generation = name, generation
        self.updated = datetime(2026, 10, 1, tzinfo=timezone.utc)
        self.size, self.etag = 100, f"etag-{generation}"
        self.time_deleted = None


class PreconditionFailed(Exception):
    code = 412


class FakeBucket:
    def __init__(self, generations=(), locked=False, list_error=None, copy_error=None, versioning=True,
                 live_deleted=False):
        self.blobs = [_Blob(STATE, g) for g in generations]
        if self.blobs:
            # GCS: only the highest generation can be live; every other version is noncurrent (timeDeleted set).
            top = max(b.generation for b in self.blobs)
            for b in self.blobs:
                if b.generation != top or live_deleted:
                    b.time_deleted = datetime(2026, 10, 2, tzinfo=timezone.utc)
        self.locked, self.list_error, self.copy_error = locked, list_error, copy_error
        self.versioning_enabled = None  # unknown until reload(), like a metadata-less google Bucket
        self._versioning = versioning
        self.copy_calls, self.get_blob_calls, self.reloads = [], [], 0
        self.after_copy = None

    def reload(self):
        self.reloads += 1
        self.versioning_enabled = self._versioning

    def list_blobs(self, prefix, versions):
        assert versions is True
        if self.list_error:
            raise self.list_error
        return [b for b in self.blobs if b.name.startswith(prefix)]

    def get_blob(self, name, generation=None):
        self.get_blob_calls.append((name, generation))
        if name == LOCK:
            return _Blob(LOCK, 7) if self.locked else None
        if generation is None:   # GCS: no generation -> the live object (FD-4AV-b post-copy re-check)
            return next((b for b in self.blobs if b.name == name and b.time_deleted is None), None)
        return next((b for b in self.blobs if b.name == name and b.generation == generation), None)

    def _write_live(self, name):
        """GCS: a write creates a new live generation; the previous live version becomes noncurrent."""
        for b in self.blobs:
            if b.name == name and b.time_deleted is None:
                b.time_deleted = datetime(2026, 10, 3, tzinfo=timezone.utc)
        new = _Blob(name, max([b.generation for b in self.blobs] + [0]) + 1)
        self.blobs.append(new)
        return new

    def copy_blob(self, blob, dest_bucket, new_name, **kwargs):
        self.copy_calls.append((blob.generation, new_name, kwargs))
        if self.copy_error:
            raise self.copy_error
        copied = self._write_live(new_name)
        if self.after_copy:   # FD-4AV-b: a concurrent apply acting right after the copy
            self.after_copy(self)
        return copied


class FakeStorage:
    def __init__(self, bucket):
        self._bucket = bucket

    def bucket(self, name):
        return self._bucket


class AlreadyExists(Exception):
    code = 409


class _Snap:
    def __init__(self, data):
        self._d = data
        self.exists = data is not None

    def to_dict(self):
        return dict(self._d) if self._d is not None else None


class _Doc:
    def __init__(self, store, coll, doc_id):
        self.store, self.key = store, (coll, doc_id)

    def set(self, data, merge=False):
        self.store.docs[self.key] = dict(data)
        self.store.ops.append(("set",) + self.key)

    def create(self, data):
        if self.key in self.store.docs:
            raise AlreadyExists("exists")
        self.store.docs[self.key] = dict(data)
        self.store.ops.append(("create",) + self.key)

    def get(self):
        return _Snap(self.store.docs.get(self.key))


class FakeFirestore:
    def __init__(self):
        self.docs, self.ops = {}, []

    def collection(self, name):
        store = self

        class _Coll:
            def document(self, doc_id):
                return _Doc(store, name, doc_id)
        return _Coll()


def _engine(bucket=None, db=None, no_storage=False):
    eng = rb.InfraRollbackEngine(project_id="mock-stackvend-project", state_bucket_name="tfstate-test",
                                 firestore_client=db if db is not None else FakeFirestore(),
                                 storage_client=FakeStorage(bucket or FakeBucket()))
    if no_storage:
        eng.storage = None  # what the constructor leaves when the GCS client cannot be built
    return eng


# ------------------------------------------------------------------------------ rollback outcomes
def test_two_generation_revert_copies_exactly_the_previous_generation_once():
    """Behavior kept: the previous generation (not the live one) is copied once, guarded by the live generation."""
    bucket, db = FakeBucket(generations=(100001, 100002)), FakeFirestore()
    rec = _engine(bucket, db).execute_rollback(PID, "tr-1")
    assert rec["status"] == rb.REVERTED and rec["target_generation"] == "100001"
    assert bucket.copy_calls == [(100001, STATE, {"source_generation": 100001, "if_generation_match": 100002})]
    assert db.docs[("rollback_events", "tr-1")]["status"] == rb.REVERTED
    assert rec["audit_recorded"] is True


def test_explicit_older_target_generation_is_restored():
    bucket = FakeBucket(generations=(1, 2, 3))
    rec = _engine(bucket).execute_rollback(PID, "tr-x", target_generation="1")
    assert rec["status"] == rb.REVERTED
    assert bucket.copy_calls == [(1, STATE, {"source_generation": 1, "if_generation_match": 3})]


def test_no_storage_client_is_unavailable_without_fabricated_history():
    db = FakeFirestore()
    eng = _engine(db=db, no_storage=True)
    with pytest.raises(rb.RollbackUnavailable):
        eng.get_state_history(PID)
    rec = eng.execute_rollback(PID, "tr-2")
    assert rec["status"] == rb.ROLLBACK_UNAVAILABLE and rec["state_history_count"] == 0
    assert rec["target_generation"] is None
    assert db.docs[("rollback_events", "tr-2")]["status"] == rb.ROLLBACK_UNAVAILABLE


def test_no_bucket_name_is_unavailable():
    eng = rb.InfraRollbackEngine(project_id="", state_bucket_name="", firestore_client=FakeFirestore(),
                                 storage_client=FakeStorage(FakeBucket(generations=(1, 2))))
    with patch.dict(os.environ, {"TFSTATE_BUCKET": ""}):
        eng.state_bucket_name = ""
        assert eng.execute_rollback(PID, "tr-3")["status"] == rb.ROLLBACK_UNAVAILABLE


@pytest.mark.parametrize("generations", [(), (100002,)])
def test_fewer_than_two_generations_is_no_previous_version_and_copies_nothing(generations):
    bucket, db = FakeBucket(generations=generations), FakeFirestore()
    rec = _engine(bucket, db).execute_rollback(PID, "tr-4")
    assert rec["status"] == rb.NO_PREVIOUS_VERSION and rec["target_generation"] is None
    assert bucket.copy_calls == []
    assert db.docs[("rollback_events", "tr-4")]["status"] == rb.NO_PREVIOUS_VERSION


def test_held_state_lock_is_refused_with_zero_copy_calls():
    bucket, db = FakeBucket(generations=(1, 2), locked=True), FakeFirestore()
    rec = _engine(bucket, db).execute_rollback(PID, "tr-5")
    assert rec["status"] == rb.REFUSED_STATE_LOCKED
    assert bucket.copy_calls == []
    assert (LOCK, None) in bucket.get_blob_calls
    assert db.docs[("rollback_events", "tr-5")]["status"] == rb.REFUSED_STATE_LOCKED


def test_state_written_after_listing_is_refused_by_the_destination_precondition():
    bucket = FakeBucket(generations=(1, 2), copy_error=PreconditionFailed("412"))
    assert _engine(bucket).execute_rollback(PID, "tr-6")["status"] == rb.REFUSED_STATE_LOCKED


def test_listing_and_copy_errors_are_rollback_failed():
    rec = _engine(FakeBucket(list_error=RuntimeError("boom"))).execute_rollback(PID, "tr-7")
    assert rec["status"] == rb.ROLLBACK_FAILED  # an unreadable history is not "no previous version"
    rec = _engine(FakeBucket(generations=(1, 2), copy_error=RuntimeError("denied"))).execute_rollback(PID, "tr-8")
    assert rec["status"] == rb.ROLLBACK_FAILED


@pytest.mark.parametrize("kwargs", [
    {"product_id": "a/b"}, {"product_id": ""}, {"product_id": ".."},
    {"target_generation": "abc"}, {"target_generation": "0"},
    {"target_generation": "9"},   # not a generation of this state
    {"target_generation": "2"},   # the live generation: never restored onto itself
    {"trace_id": ""},
])
def test_malformed_requests_raise_and_touch_nothing(kwargs):
    bucket, db = FakeBucket(generations=(1, 2)), FakeFirestore()
    args = {"product_id": PID, "trace_id": "tr-9", **kwargs}
    with pytest.raises(rb.InvalidRollbackRequest):
        _engine(bucket, db).execute_rollback(**args)
    assert bucket.copy_calls == [] and db.docs == {}


def test_success_status_never_fabricated_in_product_code():
    src = open(os.path.join(ROLLBACK_DIR, "rollback.py")).read() + open(os.path.join(ROLLBACK_DIR, "main.py")).read()
    for token in ("1234567890", "MOCK_REVERTED", "ROLLBACK_SUCCESS"):
        assert token not in src


# ------------------------------------------------------------------------------ rollback HTTP
@pytest.mark.parametrize("bucket_kwargs,no_storage,expected,code", [
    ({"generations": (1, 2)}, False, rb.REVERTED, 200),
    ({"generations": (1,)}, False, rb.NO_PREVIOUS_VERSION, 409),
    ({"generations": (1, 2), "locked": True}, False, rb.REFUSED_STATE_LOCKED, 409),
    ({}, True, rb.ROLLBACK_UNAVAILABLE, 503),
    ({"list_error": RuntimeError("x")}, False, rb.ROLLBACK_FAILED, 500),
])
def test_rollback_endpoint_maps_outcomes_to_http_status(bucket_kwargs, no_storage, expected, code):
    eng = _engine(FakeBucket(**bucket_kwargs), no_storage=no_storage)
    with patch.object(rb_main, "engine", eng):
        resp = TestClient(rb_main.app).post("/rollback", json={"product_id": PID, "trace_id": "tr-h"})
    assert resp.status_code == code and resp.json()["status"] == expected


def test_rollback_endpoint_malformed_input_is_422():
    with patch.object(rb_main, "engine", _engine(FakeBucket(generations=(1, 2)))):
        resp = TestClient(rb_main.app).post("/rollback", json={"product_id": PID, "target_generation": "nope"})
    assert resp.status_code == 422 and resp.json()["status"] == rb_main.INVALID_REQUEST


def test_history_endpoint_unavailable_is_503_not_fabricated():
    with patch.object(rb_main, "engine", _engine(no_storage=True)):
        resp = TestClient(rb_main.app).get(f"/history/{PID}")
    assert resp.status_code == 503


# ------------------------------------------------------------------------------ rollback job
_RB_ENV = {"PROJECT_ID": "mock-stackvend-project", "ROLLBACK_PRODUCT_ID": PID, "ROLLBACK_TRACE_ID": "tr-job",
           "CLOUD_RUN_EXECUTION": "infra-rollback-job-abc"}


def test_rollback_batch_exit_0_only_on_real_revert_and_run_record_written():
    bucket, db = FakeBucket(generations=(1, 2)), FakeFirestore()
    code, summary = rb_main.run_batch(_RB_ENV, _engine(bucket, db))
    assert code == 0 and summary["outcome"] == rb.REVERTED
    assert ("create", "infra-rollback-job_runs", "infra-rollback-job-abc") in db.ops
    assert db.docs[("infra-rollback-job_runs", "infra-rollback-job-abc")]["outcome"] == rb.REVERTED
    assert len(bucket.copy_calls) == 1


@pytest.mark.parametrize("bucket_kwargs,no_storage", [
    ({"generations": (1,)}, False), ({"generations": (1, 2), "locked": True}, False), ({}, True),
    ({"list_error": RuntimeError("x")}, False),
])
def test_rollback_batch_exit_1_when_nothing_was_reverted(bucket_kwargs, no_storage):
    code, summary = rb_main.run_batch(_RB_ENV, _engine(FakeBucket(**bucket_kwargs), no_storage=no_storage))
    assert code == 1 and summary["outcome"] != rb.REVERTED


def test_rollback_batch_exit_2_on_malformed_generation():
    bucket = FakeBucket(generations=(1, 2))
    code, summary = rb_main.run_batch(dict(_RB_ENV, ROLLBACK_TARGET_GENERATION="latest"), _engine(bucket))
    assert code == 2 and summary["outcome"] == rb_main.INVALID_REQUEST and bucket.copy_calls == []


@pytest.mark.parametrize("drop", ["ROLLBACK_PRODUCT_ID", "ROLLBACK_TRACE_ID", "PROJECT_ID"])
def test_rollback_batch_exit_3_not_configured_at_warning(drop, caplog):
    bucket, db = FakeBucket(generations=(1, 2)), FakeFirestore()
    env = {k: v for k, v in _RB_ENV.items() if k != drop}
    with caplog.at_level(logging.WARNING):
        code, summary = rb_main.run_batch(env, _engine(bucket, db))
    assert code == 3 and summary["outcome"] == "NOT_CONFIGURED" and drop in summary["missing"]
    assert bucket.copy_calls == []
    assert any(r.levelno == logging.WARNING and "NOT_CONFIGURED" in r.getMessage() for r in caplog.records)


def test_rollback_batch_retry_of_same_execution_never_rolls_back_twice():
    bucket, db = FakeBucket(generations=(1, 2, 3)), FakeFirestore()
    eng = _engine(bucket, db)
    assert rb_main.run_batch(_RB_ENV, eng)[0] == 0
    code, prior = rb_main.run_batch(_RB_ENV, eng)
    assert code == 0 and prior["outcome"] == rb.REVERTED and len(bucket.copy_calls) == 1
    db.docs[("infra-rollback-job_runs", "infra-rollback-job-abc")]["outcome"] = "RUNNING"
    assert rb_main.run_batch(_RB_ENV, eng)[0] == 1 and len(bucket.copy_calls) == 1


def test_rollback_batch_without_firestore_refuses():
    bucket = FakeBucket(generations=(1, 2))
    eng = _engine(bucket)
    eng.db = None
    assert rb_main.run_batch(_RB_ENV, eng)[0] == 1 and bucket.copy_calls == []


# ------------------------------------------------------------------------------ FinOps job
_FIN_ENV = {"PROJECT_ID": "mock-stackvend-project", "FINOPS_ENFORCE_PRODUCT_ID": "pay-api",
            "FINOPS_ENFORCE_TARGET_PROJECT_ID": "child-proj-1", "CLOUD_RUN_EXECUTION": "finops-exec-1"}


def _fake_enforcer(result=None, error=None):
    e = MagicMock(name="enforcer")
    e.db = FakeFirestore()
    if error:
        e.quarantine_workload.side_effect = error
    else:
        e.quarantine_workload.return_value = result
    return e


@pytest.mark.parametrize("status", sorted(enf_main.ENFORCED_STATUSES))
def test_finops_batch_exit_0_on_enforced_status_with_same_call_as_http(status):
    e = _fake_enforcer({"status": status})
    code, summary = enf_main.run_batch(dict(_FIN_ENV, FINOPS_ENFORCE_SPEND_AMOUNT="120.5",
                                            FINOPS_ENFORCE_BUDGET_AMOUNT="100"), e)
    assert code == 0 and summary["outcome"] == status
    e.quarantine_workload.assert_called_once_with(product_id="pay-api", target_project_id="child-proj-1",
                                                  trace_id=None, spend_amount=120.5, budget_amount=100.0,
                                                  policy="AUTONOMOUS_SCALE_TO_ZERO")
    assert e.db.docs[("finops-budget-enforcer-job_runs", "finops-exec-1")]["outcome"] == status


def test_http_enforce_uses_the_same_shared_call():
    e = _fake_enforcer({"status": "ALERTED_ONLY"})
    req = enf_main.QuarantineRequest(product_id="pay-api", target_project_id="child-proj-1", policy="ALERT_ONLY")
    with patch.object(enf_main, "enforcer", e):
        assert enf_main.enforce_quarantine(req) == {"status": "ALERTED_ONLY"}
    e.quarantine_workload.assert_called_once_with(product_id="pay-api", target_project_id="child-proj-1",
                                                  trace_id=None, spend_amount=0.0, budget_amount=0.0,
                                                  policy="ALERT_ONLY")


@pytest.mark.parametrize("result,error", [({"status": "REFUSED", "reason": "host"}, None), (None, RuntimeError("x")),
                                          ({"status": "SOMETHING_ELSE"}, None), ({}, None)])
def test_finops_batch_exit_1_on_refusal_or_failure(result, error):
    code, summary = enf_main.run_batch(_FIN_ENV, _fake_enforcer(result, error))
    assert code == 1 and summary["outcome"] not in enf_main.ENFORCED_STATUSES


def test_finops_batch_host_project_refused_by_the_real_fd4o_guard():
    """The batch path goes through the real engine guard: host target -> REFUSED, exit 1, zero compute calls."""
    clients = {k: MagicMock(name=k) for k in ("run_service", "compute_service", "sql_service", "container_service",
                                              "billing_service", "crm_service")}
    real = enf.FinopsBudgetEnforcer(project_id="mock-stackvend-project", firestore_client=FakeFirestore(), **clients)
    code, summary = enf_main.run_batch(dict(_FIN_ENV, FINOPS_ENFORCE_TARGET_PROJECT_ID="mock-stackvend-project"), real)
    assert code == 1 and summary["outcome"] == "REFUSED"
    for name in ("run_service", "compute_service", "sql_service", "container_service", "billing_service"):
        assert clients[name].method_calls == [], name


def test_finops_batch_exit_2_on_malformed_amount():
    e = _fake_enforcer({"status": "QUARANTINED"})
    code, summary = enf_main.run_batch(dict(_FIN_ENV, FINOPS_ENFORCE_SPEND_AMOUNT="lots"), e)
    assert code == 2 and summary["outcome"] == "INVALID_REQUEST"
    e.quarantine_workload.assert_not_called()


@pytest.mark.parametrize("drop", ["FINOPS_ENFORCE_PRODUCT_ID", "FINOPS_ENFORCE_TARGET_PROJECT_ID", "PROJECT_ID"])
def test_finops_batch_exit_3_not_configured_at_warning(drop, caplog):
    e = _fake_enforcer({"status": "QUARANTINED"})
    with caplog.at_level(logging.WARNING):
        code, summary = enf_main.run_batch({k: v for k, v in _FIN_ENV.items() if k != drop}, e)
    assert code == 3 and summary["outcome"] == "NOT_CONFIGURED" and drop in summary["missing"]
    e.quarantine_workload.assert_not_called()
    assert any(r.levelno == logging.WARNING and "NOT_CONFIGURED" in r.getMessage() for r in caplog.records)


def test_finops_batch_empty_env_is_not_configured_not_success():
    """The old batch branch exited 0 without calling the engine; with no inputs the job now exits 3."""
    e = _fake_enforcer({"status": "QUARANTINED"})
    assert enf_main.run_batch({}, e)[0] == 3
    e.quarantine_workload.assert_not_called()


def test_finops_batch_retry_of_same_execution_never_enforces_twice():
    e = _fake_enforcer({"status": "QUARANTINED"})
    assert enf_main.run_batch(_FIN_ENV, e)[0] == 0
    assert enf_main.run_batch(_FIN_ENV, e)[0] == 0
    assert e.quarantine_workload.call_count == 1


def test_finops_batch_without_firestore_refuses():
    e = _fake_enforcer({"status": "QUARANTINED"})
    e.db = None
    assert enf_main.run_batch(_FIN_ENV, e)[0] == 1
    e.quarantine_workload.assert_not_called()


# ------------------------------------------------------------------------------ RT fixes (rt-fd-4av-a-fable)
def test_listing_order_does_not_matter():
    """RT L3: GCS listing order is not relied on; the latest generation is live, the next one is restored."""
    bucket = FakeBucket(generations=(3, 1, 2))
    rec = _engine(bucket).execute_rollback(PID, "tr-order")
    assert rec["status"] == rb.REVERTED and rec["target_generation"] == "2"
    assert bucket.copy_calls == [(2, STATE, {"source_generation": 2, "if_generation_match": 3})]


def test_versioned_bucket_copy_call_is_unchanged():
    """RT F1 negative: versioning True (read from reloaded metadata) -> the same single copy as before."""
    bucket = FakeBucket(generations=(1, 2), versioning=True)
    assert _engine(bucket).execute_rollback(PID, "tr-v1")["status"] == rb.REVERTED
    assert bucket.reloads == 1
    assert bucket.copy_calls == [(1, STATE, {"source_generation": 1, "if_generation_match": 2})]


@pytest.mark.parametrize("versioning", [False, None])
def test_unversioned_bucket_is_unavailable_and_copies_nothing(versioning):
    """RT F1: a restore on an unversioned bucket would destroy the only live copy -> ROLLBACK_UNAVAILABLE."""
    bucket, db = FakeBucket(generations=(1, 2), versioning=versioning), FakeFirestore()
    rec = _engine(bucket, db).execute_rollback(PID, "tr-v2")
    assert rec["status"] == rb.ROLLBACK_UNAVAILABLE and bucket.copy_calls == []
    assert "rolled_back_at" not in rec  # RT L2: refusals are not stamped as rollbacks
    assert db.docs[("rollback_events", "tr-v2")]["status"] == rb.ROLLBACK_UNAVAILABLE


def test_deleted_live_state_is_rollback_failed_not_lock_refusal():
    """RT L1: only noncurrent versions remain -> ROLLBACK_FAILED, nothing copied, never REFUSED_STATE_LOCKED."""
    bucket = FakeBucket(generations=(1, 2), live_deleted=True)
    rec = _engine(bucket).execute_rollback(PID, "tr-del")
    assert rec["status"] == rb.ROLLBACK_FAILED and bucket.copy_calls == []


def test_only_a_revert_is_stamped_rolled_back_at():
    assert "rolled_back_at" in _engine(FakeBucket(generations=(1, 2))).execute_rollback(PID, "tr-s1")
    for kwargs in ({"generations": (1,)}, {"generations": (1, 2), "locked": True}):
        assert "rolled_back_at" not in _engine(FakeBucket(**kwargs)).execute_rollback(PID, "tr-s2")


def test_default_http_trace_id_is_unique_per_call():
    """RT F4: two /rollback calls without trace_id never share (overwrite) an audit document."""
    db = FakeFirestore()
    eng = _engine(FakeBucket(generations=(1,)), db)
    with patch.object(rb_main, "engine", eng):
        client = TestClient(rb_main.app)
        a = client.post("/rollback", json={"product_id": PID}).json()["trace_id"]
        b = client.post("/rollback", json={"product_id": PID}).json()["trace_id"]
    assert a != b and a.startswith(f"rb-tr-{PID}-")
    assert len([k for k in db.docs if k[0] == "rollback_events"]) == 2


@pytest.mark.parametrize("policy", ["ALERT-ONLY", "alert_only!", "SCALE", "none"])
def test_finops_batch_unknown_policy_is_exit_2_before_the_run_claim(policy):
    """RT F3: a policy typo never reaches the engine (whose fallthrough is scale-to-zero)."""
    e = _fake_enforcer({"status": "QUARANTINED"})
    code, summary = enf_main.run_batch(dict(_FIN_ENV, FINOPS_ENFORCE_POLICY=policy), e)
    assert code == 2 and summary["outcome"] == "INVALID_REQUEST"
    e.quarantine_workload.assert_not_called()
    assert ("create", "finops-budget-enforcer-job_runs", "finops-exec-1") not in e.db.ops
    assert e.db.docs[("finops-budget-enforcer-job_runs", "finops-exec-1")]["outcome"] == "INVALID_REQUEST"


@pytest.mark.parametrize("policy", ["ALERT_ONLY", "alert_only", "HITL_CONFIRMATION_REQUIRED"])
def test_finops_batch_known_policy_passes_through_unchanged(policy):
    e = _fake_enforcer({"status": "ALERTED_ONLY"})
    assert enf_main.run_batch(dict(_FIN_ENV, FINOPS_ENFORCE_POLICY=policy), e)[0] == 0
    assert e.quarantine_workload.call_args.kwargs["policy"] == policy


def test_rollback_batch_invalid_request_writes_a_run_record():
    """RT L2: exit-2 runs leave a record, so the sentinel never sees "no record"."""
    db = FakeFirestore()
    code, _ = rb_main.run_batch(dict(_RB_ENV, ROLLBACK_TARGET_GENERATION="latest"), _engine(FakeBucket((1, 2)), db))
    assert code == 2
    assert db.docs[("infra-rollback-job_runs", "infra-rollback-job-abc")]["outcome"] == rb_main.INVALID_REQUEST


def test_finops_batch_malformed_amount_writes_a_run_record():
    e = _fake_enforcer({"status": "QUARANTINED"})
    assert enf_main.run_batch(dict(_FIN_ENV, FINOPS_ENFORCE_BUDGET_AMOUNT="x"), e)[0] == 2
    assert e.db.docs[("finops-budget-enforcer-job_runs", "finops-exec-1")]["outcome"] == "INVALID_REQUEST"


# ------------------------------------------------------------------------------ FD-4AV-b: post-copy re-check
# Register row FD-4AV-b (owner 10-20): after the copy the rollback re-checks the live generation and the lock and
# reports SUPERSEDED instead of REVERTED when a concurrent apply overwrote (or may overwrite) the restore; it never
# creates or deletes a lock.
class _StrictBucket(FakeBucket):
    """Any bucket method other than reads and the one state copy fails the test."""
    _ALLOWED = {"reload", "list_blobs", "get_blob", "copy_blob", "_write_live", "after_copy"}

    def __getattribute__(self, name):
        attr = object.__getattribute__(self, name)
        if callable(attr) and not name.startswith("__") and name not in type(self)._ALLOWED:
            raise AssertionError(f"rollback called bucket.{name}: only reads and the state copy are allowed")
        return attr


def _concurrent_apply(bucket):
    bucket._write_live(STATE)          # an apply wrote a new state right after our copy


def _concurrent_lock(bucket):
    bucket.locked = True               # a tofu run took the lock right after our copy


def test_restore_that_stays_live_is_reverted_after_the_recheck():
    bucket, db = _StrictBucket(generations=(1, 2)), FakeFirestore()
    rec = _engine(bucket, db).execute_rollback(PID, "tr-b1")
    assert rec["status"] == rb.REVERTED and rec["rolled_back_at"]
    assert rec["copied_generation"] == rec["live_generation_after"] == "3"
    assert bucket.get_blob_calls[-2:] == [(STATE, None), (LOCK, None)]     # the re-check: two reads after the copy
    assert db.docs[("rollback_events", "tr-b1")]["status"] == rb.REVERTED


def test_concurrent_overwrite_after_the_copy_is_superseded_not_reverted():
    bucket, db = _StrictBucket(generations=(1, 2)), FakeFirestore()
    bucket.after_copy = _concurrent_apply
    rec = _engine(bucket, db).execute_rollback(PID, "tr-b2")
    assert rec["status"] == rb.SUPERSEDED and "rolled_back_at" not in rec
    assert (rec["copied_generation"], rec["live_generation_after"]) == ("3", "4")
    assert len(bucket.copy_calls) == 1                                     # never retried or "fixed"
    assert db.docs[("rollback_events", "tr-b2")]["status"] == rb.SUPERSEDED


def test_lock_taken_after_the_copy_is_superseded():
    bucket = _StrictBucket(generations=(1, 2))
    bucket.after_copy = _concurrent_lock
    rec = _engine(bucket).execute_rollback(PID, "tr-b3")
    assert rec["status"] == rb.SUPERSEDED and rec["live_generation_after"] == rec["copied_generation"]
    assert len(rec["superseded_reasons"]) == 1 and LOCK in rec["superseded_reasons"][0]


def test_unverifiable_copy_is_rollback_failed_never_reverted():
    bucket = FakeBucket(generations=(1, 2))
    bucket._write_live = lambda name: _Blob(name, None)   # a copy result without a generation
    rec = _engine(bucket).execute_rollback(PID, "tr-b4")
    assert rec["status"] == rb.ROLLBACK_FAILED and rec["restore_unverified"] is True
    assert len(bucket.copy_calls) == 1


def test_recheck_read_error_is_rollback_failed_never_reverted():
    bucket = FakeBucket(generations=(1, 2))
    real_get = bucket.get_blob

    def _get(name, generation=None):
        if bucket.copy_calls:
            raise RuntimeError("read failed after the copy")
        return real_get(name, generation)

    bucket.get_blob = _get
    rec = _engine(bucket).execute_rollback(PID, "tr-b5")
    assert rec["status"] == rb.ROLLBACK_FAILED and rec["restore_unverified"] is True


@pytest.mark.parametrize("after,expected,code,exit_code", [
    (None, rb.REVERTED, 200, 0), (_concurrent_apply, rb.SUPERSEDED, 409, 1), (_concurrent_lock, rb.SUPERSEDED, 409, 1)])
def test_superseded_http_status_and_job_exit_code(after, expected, code, exit_code):
    bucket = FakeBucket(generations=(1, 2))
    bucket.after_copy = after
    with patch.object(rb_main, "engine", _engine(bucket)):
        resp = TestClient(rb_main.app).post("/rollback", json={"product_id": PID, "trace_id": "tr-bh"})
    assert resp.status_code == code and resp.json()["status"] == expected
    bucket = FakeBucket(generations=(1, 2))
    bucket.after_copy = after
    assert rb_main.run_batch(_RB_ENV, _engine(bucket, FakeFirestore()))[0] == exit_code


def test_rollback_path_never_creates_or_deletes_a_lock_or_writes_another_object():
    """Every outcome path (lock held, REVERTED, SUPERSEDED by write or by lock): the only write is the one
    generation-guarded copy onto the state object; the lock object is only ever read (get_blob)."""
    for locked, after, expected in ((True, None, rb.REFUSED_STATE_LOCKED), (False, None, rb.REVERTED),
                                    (False, _concurrent_apply, rb.SUPERSEDED), (False, _concurrent_lock, rb.SUPERSEDED)):
        bucket = _StrictBucket(generations=(1, 2), locked=locked)
        bucket.after_copy = after
        assert _engine(bucket).execute_rollback(PID, "tr-b6")["status"] == expected   # a strict-bucket hit would fail
        assert len(bucket.copy_calls) == (0 if locked else 1)
        assert all(dest == STATE and set(kw) == {"source_generation", "if_generation_match"}
                   for _g, dest, kw in bucket.copy_calls)
        assert any(n == LOCK for n, _g in bucket.get_blob_calls)


def test_rollback_source_has_no_storage_write_or_delete_call():
    """Static check over the engine (ast, exact attribute names): no delete / upload / compose / rewrite / create."""
    import ast
    with open(os.path.join(ROLLBACK_DIR, "rollback.py")) as fh:
        tree = ast.parse(fh.read())
    called = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    forbidden = {"delete", "delete_blob", "delete_blobs", "upload_from_string", "upload_from_file",
                 "upload_from_filename", "compose", "rewrite", "create"}
    assert called & forbidden == set()
    assert "copy_blob" in called
