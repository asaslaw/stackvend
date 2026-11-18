"""WORKLOAD-STATUS-PRE-DEPLOY-FAILURE: a run that ends failed before a deploy leaves workloads/{id}.status = FAILED.

The workflow's single failure handler posts status FAILED to /events/workflow-status. The gateway now records it on the
workload when the record still holds a run-in-progress word (PROVISIONING / PROVISIONED) and the workload's project has
no successful deploy in the terraform_deployments ledger.

Negatives (Do No Harm): every other status is left alone, a re-run of a workload with a good deploy is unchanged (also
after vending rewrote its status to PROVISIONED), nothing but a FAILED event writes, a failure of an older run does not
speak for a newer run still under way, the workload is never named by parsing the trace id, and a status that cannot be
decided is not written. Re-vend and decommission of a FAILED record: tests/test_sat38_vending_recorded_project.py and
tests/test_destructive_guard_vending.py. Hermetic: fake Firestore, no network.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import pytest
from fastapi.testclient import TestClient

from fd4f_support import FakeDB, _ColRef, gw  # noqa: F401  (gw is a fixture)

TRACE, PID, PROJECT = "tr-failed", "shop-app", "shop-app-123abc"
WORKLOAD, RUN = f"workloads/{PID}", f"pipeline_executions/{TRACE}"
VENDING_FAILED = {"trace_id": TRACE, "product_id": PID, "status": "FAILED", "current_stage": "FAILED",
                  "error_class": "BILLING_NOT_LINKED", "failed_stage": "vending",
                  "error_detail": "Project vending failed: billing quota exceeded"}
COMPLIANCE_STOP = dict(VENDING_FAILED, error_class="COMPLIANCE.PRIVATE_INGRESS_UNSUPPORTED", failed_stage="compliance",
                       error_detail="This release cannot make Cloud Run services internal-only")


class _Query(_ColRef):
    """terraform_deployments and pipeline_executions with real filters (the shared FakeDB's where() filters nothing)."""

    def __init__(self, db, path, filters=()):
        super().__init__(db, path)
        self._filters = list(filters)

    def where(self, field, op, value):
        assert op in ("==", "in")
        return _Query(self._db, self._path, self._filters + [(field, op, value)])

    def stream(self):
        if self._path == "terraform_deployments":
            self._db.ledger_reads += 1
            if self._db.fail_ledger:
                raise RuntimeError("ledger unreadable")
            if self._db.on_ledger_read:
                self._db.on_ledger_read()
        elif self._db.fail_runs:
            raise RuntimeError("runs unreadable")
        return [s for s in super().stream() if all(
            s.to_dict().get(k) == v if op == "==" else s.to_dict().get(k) in v for k, op, v in self._filters)]


class DB(FakeDB):
    def __init__(self):
        super().__init__()
        self.ledger_reads, self.fail_ledger, self.on_ledger_read, self.fail_runs = 0, False, None, False

    def collection(self, name):
        return _Query(self, name) if name in ("terraform_deployments", "pipeline_executions") else super().collection(name)

    def workload_writes(self):
        return [w for w in self.writes if w[0] == WORKLOAD]

    def status(self):
        return self.docs[WORKLOAD]["status"]


def _db(status=None, project_id=PROJECT):
    db = DB()
    db.docs[RUN] = {"trace_id": TRACE, "product_id": PID, "started_at": "2026-11-08T10:00:00+00:00"}
    if status:
        db.docs[WORKLOAD] = {"product_id": PID, "project_id": project_id, "status": status}
    return db


def _deployed(db, status="SUCCESS", product_id=PID, project_id=PROJECT, trace="old"):
    db.docs[f"terraform_deployments/deploy-{trace}"] = {"product_id": product_id, "project_id": project_id,
                                                        "status": status, "trace_id": trace}


def _post(gw, monkeypatch, db, body=None):
    import google.cloud.firestore as fs_mod

    monkeypatch.setattr(fs_mod, "Client", lambda *a, **k: db)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    r = TestClient(gw.app).post("/events/workflow-status", json=body or VENDING_FAILED)
    assert r.status_code == 200, r.text
    return r.json()


# ======================================================================== a run that ended before a deploy
def test_vending_failure_of_a_new_workload_sets_failed_with_the_typed_reason(gw, monkeypatch):
    """The live example: BILLING_NOT_LINKED at vending, record still PROVISIONING from the Control Center."""
    db = _db("PROVISIONING")
    assert _post(gw, monkeypatch, db)["status"] == "UPDATED"
    assert db.status() == "FAILED"
    assert db.docs[WORKLOAD]["failure_reason"] == ("BILLING_NOT_LINKED: Project vending failed: billing quota exceeded")
    assert db.docs[WORKLOAD]["project_id"] == PROJECT   # the rest of the record is kept
    assert db.docs[RUN]["status"] == "FAILED" and "workload_status_error" not in db.docs[RUN]


def test_typed_stop_after_vending_sets_failed(gw, monkeypatch):
    """The other live examples: a typed stop on a record vending had already set to PROVISIONED."""
    db = _db("PROVISIONED")
    _post(gw, monkeypatch, db, COMPLIANCE_STOP)
    assert db.status() == "FAILED"
    assert db.docs[WORKLOAD]["failure_reason"].startswith("COMPLIANCE.PRIVATE_INGRESS_UNSUPPORTED: ")


def test_failure_without_a_class_or_detail_names_the_run_and_invents_no_class(gw, monkeypatch):
    db = _db("PROVISIONED")
    _post(gw, monkeypatch, db, {"trace_id": TRACE, "product_id": PID, "status": "FAILED"})
    assert db.status() == "FAILED" and db.docs[WORKLOAD]["failure_reason"] == f"run {TRACE} failed"


def test_product_id_may_come_from_the_run_record(gw, monkeypatch):
    db = _db("PROVISIONING")
    body = {k: v for k, v in VENDING_FAILED.items() if k != "product_id"}
    _post(gw, monkeypatch, db, body)
    assert db.status() == "FAILED"


@pytest.mark.parametrize("seed", [
    dict(status="FAILED"),                           # an earlier deploy attempt failed: no good deploy
    dict(project_id="shop-app-oldproj"),             # decommissioned and vended again: nothing deployed to this project
    dict(product_id="another-app"),                  # another workload's deploy
])
def test_a_ledger_row_that_is_no_good_deploy_of_this_project_does_not_count(gw, monkeypatch, seed):
    db = _db("PROVISIONED")
    _deployed(db, **seed)
    _post(gw, monkeypatch, db)
    assert db.status() == "FAILED"


# ======================================================================== records that stay as they are
@pytest.mark.parametrize("status", ["DEPLOYED", "ACTIVE", "FAILED", "REDEPLOYING", "QUARANTINED", "BILLING_UNLINKED",
                                    "DECOMMISSION_REQUESTED", "DECOMMISSIONED", "ARCHIVED"])
def test_negative_every_other_status_is_left_alone(gw, monkeypatch, status):
    """DEPLOYED is the failed re-run of a deployed workload stopping before vending; a deploy's own FAILED stays too."""
    db = _db(status)
    _post(gw, monkeypatch, db)
    assert db.status() == status and db.workload_writes() == [] and db.ledger_reads == 0


@pytest.mark.parametrize("status", ["PROVISIONED", "PROVISIONING"])
def test_negative_failed_rerun_of_a_deployed_workload_is_unchanged(gw, monkeypatch, status):
    """Vending rewrites DEPLOYED to PROVISIONED on a full re-run; the earlier good deploy is what keeps the record."""
    db = _db(status)
    _deployed(db)
    _deployed(db, status="FAILED", trace="later")
    _post(gw, monkeypatch, db)
    assert db.status() == status and db.workload_writes() == []


def test_negative_workload_without_a_record_gets_none(gw, monkeypatch):
    db = _db()
    _post(gw, monkeypatch, db)
    assert WORKLOAD not in db.docs


@pytest.mark.parametrize("body", [
    {"status": "SUCCEEDED"},
    {"status": "ACTIVE", "current_stage": "ARCHITECT"},
    {"stage_name": "vending", "stage_status": "FAILED", "stage_summary": "a stage event is not the end of the run"},
])
def test_negative_only_the_failed_end_of_a_run_writes(gw, monkeypatch, body):
    db = _db("PROVISIONING")
    _post(gw, monkeypatch, db, {"trace_id": TRACE, "product_id": PID, **body})
    assert db.status() == "PROVISIONING" and db.workload_writes() == []


# ======================================================================== could not decide or write: never a guess
def test_unreadable_ledger_leaves_the_status_and_is_typed_on_the_run(gw, monkeypatch):
    """Without the ledger a good deploy cannot be ruled out. The handler still finishes (it answers UPDATED)."""
    db = _db("PROVISIONED")
    db.fail_ledger = True
    assert _post(gw, monkeypatch, db)["status"] == "UPDATED"
    assert db.status() == "PROVISIONED" and db.workload_writes() == []
    err = db.docs[RUN]["workload_status_error"]
    assert err["code"] == gw.WORKLOAD_STATUS_NOT_RECORDED and "RuntimeError" in err["detail"]


def _concurrent_write(db, data):
    """A writer that lands between the handler's read of the record and its conditional update."""
    db.docs[WORKLOAD].update(data)
    db.__dict__.setdefault("versions", {})[WORKLOAD] = db.__dict__.setdefault("versions", {}).get(WORKLOAD, 0) + 1


def test_a_deploy_recorded_between_read_and_write_is_not_overwritten(gw, monkeypatch):
    db = _db("PROVISIONED")

    def deploy_lands_once():
        db.on_ledger_read = None
        _concurrent_write(db, {"status": "DEPLOYED"})

    db.on_ledger_read = deploy_lands_once
    _post(gw, monkeypatch, db)
    assert db.status() == "DEPLOYED" and db.workload_writes() == []


def test_an_unrelated_write_between_read_and_write_does_not_lose_the_status(gw, monkeypatch):
    db = _db("PROVISIONED")

    def spend_sync_lands_once():
        db.on_ledger_read = None
        _concurrent_write(db, {"current_spend_usd": 1.5})

    db.on_ledger_read = spend_sync_lands_once
    _post(gw, monkeypatch, db)
    assert db.status() == "FAILED" and db.docs[WORKLOAD]["current_spend_usd"] == 1.5


def test_a_record_that_keeps_changing_is_a_typed_error_not_a_blind_write(gw, monkeypatch):
    db = _db("PROVISIONED")
    db.on_ledger_read = lambda: _concurrent_write(db, {"current_spend_usd": 2.0})
    assert _post(gw, monkeypatch, db)["status"] == "UPDATED"
    assert db.status() == "PROVISIONED" and db.ledger_reads == gw._WORKLOAD_STATUS_WRITE_ATTEMPTS
    assert db.docs[RUN]["workload_status_error"]["code"] == gw.WORKLOAD_STATUS_NOT_RECORDED


# ======================================================================== the workload is named, never parsed (RT F3-1)
HYPHENATED, PARSED = "workloads/my-shop", "workloads/my"
INTAKE_TRACE = "intake-my-shop-abc"
HYPHENATED_FAILED = {"trace_id": INTAKE_TRACE, "status": "FAILED", "error_class": "BILLING_NOT_LINKED"}


def _hyphenated_db(run=None):
    """Both the real workload and the one a split of the trace id would name, each exposed to a wrong write."""
    db = DB()
    db.docs[HYPHENATED] = {"product_id": "my-shop", "project_id": PROJECT, "status": "PROVISIONED"}
    db.docs[PARSED] = {"product_id": "my", "project_id": "my-123abc", "status": "PROVISIONED"}
    if run is not None:
        db.docs[f"pipeline_executions/{INTAKE_TRACE}"] = {"trace_id": INTAKE_TRACE, "started_at": "2026-11-08T10:00:00+00:00",
                                                          **run}
    return db


def _workload_writes(db):
    return [w for w in db.writes if w[0].startswith("workloads/")]


@pytest.mark.parametrize("run", [None, {}, {"product_id": ""}, {"product_id": None}])
def test_no_stated_product_id_writes_no_workload_and_is_typed_on_the_run(gw, monkeypatch, run):
    """intake-my-shop-abc must not reach workloads/my."""
    db = _hyphenated_db(run)
    assert _post(gw, monkeypatch, db, HYPHENATED_FAILED)["status"] == "UPDATED"
    assert _workload_writes(db) == [] and db.ledger_reads == 0
    assert db.docs[PARSED]["status"] == "PROVISIONED" and db.docs[HYPHENATED]["status"] == "PROVISIONED"
    err = db.docs[f"pipeline_executions/{INTAKE_TRACE}"]["workload_status_error"]
    assert err["code"] == gw.WORKLOAD_STATUS_NOT_RECORDED and "ValueError" in err["detail"]


def test_event_product_id_names_the_hyphenated_workload(gw, monkeypatch):
    db = _hyphenated_db({})
    _post(gw, monkeypatch, db, dict(HYPHENATED_FAILED, product_id="my-shop"))
    assert db.docs[HYPHENATED]["status"] == "FAILED" and db.docs[PARSED]["status"] == "PROVISIONED"


def test_stored_product_id_names_the_hyphenated_workload(gw, monkeypatch):
    db = _hyphenated_db({"product_id": "my-shop"})
    _post(gw, monkeypatch, db, HYPHENATED_FAILED)
    assert db.docs[HYPHENATED]["status"] == "FAILED" and db.docs[PARSED]["status"] == "PROVISIONED"
    assert "workload_status_error" not in db.docs[f"pipeline_executions/{INTAKE_TRACE}"]


# ======================================================================== overlapping runs (RT F3-2)
EARLIER, LATER = "2026-11-08T09:00:00+00:00", "2026-11-08T11:00:00+00:00"


def _other_run(db, status="ACTIVE", started_at=LATER, product_id=PID, trace="tr-other"):
    db.docs[f"pipeline_executions/{trace}"] = {"trace_id": trace, "product_id": product_id, "status": status,
                                               "started_at": started_at}


@pytest.mark.parametrize("status", ["ACTIVE", "RUNNING", "PAUSED_RATE_LIMIT_COOLDOWN"])
def test_negative_stale_failure_leaves_a_newer_run_under_way_alone(gw, monkeypatch, status):
    """Run A was parked, B was relaunched and vended, then A's callback timed out: the workload is B's."""
    db = _db("PROVISIONED")
    _other_run(db, status)
    assert _post(gw, monkeypatch, db)["status"] == "UPDATED"
    assert db.status() == "PROVISIONED" and db.workload_writes() == [] and db.ledger_reads == 0
    assert "workload_status_error" not in db.docs[RUN]
    assert db.docs[RUN]["status"] == "FAILED"   # the run's own record still says what happened to it


def test_negative_a_newer_run_is_found_when_its_start_time_ends_in_z(gw, monkeypatch):
    db = _db("PROVISIONED")
    _other_run(db, started_at="2026-11-08T11:00:00Z")
    _post(gw, monkeypatch, db)
    assert db.status() == "PROVISIONED"


@pytest.mark.parametrize("seed", [
    dict(started_at=EARLIER),                                     # the failing run is the newest: A parked, B failed
    dict(started_at="2026-11-08T10:00:00+00:00"),                 # same start: not newer
    dict(status="FAILED"), dict(status="SUCCEEDED"), dict(status="ABORTED"),   # newer, but finished
    dict(product_id="another-app"),                               # another workload's run
])
def test_a_run_that_is_not_newer_and_under_way_does_not_keep_the_status(gw, monkeypatch, seed):
    db = _db("PROVISIONED")
    _other_run(db, **seed)
    _post(gw, monkeypatch, db)
    assert db.status() == "FAILED"


def test_a_newer_run_that_appears_during_a_conflict_is_seen_on_the_re_read(gw, monkeypatch):
    db = _db("PROVISIONED")

    def relaunch_lands_once():
        db.on_ledger_read = None
        _other_run(db)
        _concurrent_write(db, {"status": "PROVISIONED"})

    db.on_ledger_read = relaunch_lands_once
    _post(gw, monkeypatch, db)
    assert db.status() == "PROVISIONED" and db.workload_writes() == []


def test_unreadable_run_list_leaves_the_status_and_is_typed_on_the_run(gw, monkeypatch):
    db = _db("PROVISIONED")
    db.fail_runs = True
    assert _post(gw, monkeypatch, db)["status"] == "UPDATED"
    assert db.status() == "PROVISIONED" and db.workload_writes() == []
    assert db.docs[RUN]["workload_status_error"]["code"] == gw.WORKLOAD_STATUS_NOT_RECORDED


@pytest.mark.parametrize("started_at", [None, "not-a-time"])
def test_a_run_whose_start_cannot_be_read_is_typed_not_guessed(gw, monkeypatch, started_at):
    db = _db("PROVISIONED")
    _other_run(db, started_at=started_at)
    assert _post(gw, monkeypatch, db)["status"] == "UPDATED"
    assert db.status() == "PROVISIONED" and db.workload_writes() == []
    assert db.docs[RUN]["workload_status_error"]["code"] == gw.WORKLOAD_STATUS_NOT_RECORDED
