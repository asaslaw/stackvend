"""RT14-05 / RT14-20 (full-scope red-team scan 11-14, owner-approved): the FinOps scale-to-zero and billing unlink.

RT14-05: a second breach on a workload that is already quarantined or unlinked changes nothing (the pre-quarantine
snapshot is never replaced by the zeroed state; no second unlink records "no account"); a missing max is recorded as
None, not 5; the restore reads the live state back and reports RESTORED only when it matches the snapshot (else a typed
RESTORE_PARTIAL with `unverified`), clears its markers in one batch, and falls back to the quarantine record's copy of
the snapshot. RT14-20: nothing is scaled down or detached without a durable record: the snapshot is created (never
overwritten) before any stop, a failed read or write is a typed stop that is not an enforced outcome, and the
quarantine record, status and card land together.

Hermetic: in-memory Firestore (tests/c10_fakes.py), a fake child project behind the engine's resource methods, and the
real engine (apps/finops-enforcer/enforcer.py) with mocked Google clients.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
FINOPS_DIR = os.path.join(REPO, "apps", "finops-enforcer")
for p in (HERE, REPO):
    if p not in sys.path:
        sys.path.insert(0, p)

import c10_fakes as F  # noqa: E402
from shared import enforcer_job as EJ  # noqa: E402


def _load(name, directory, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(directory, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.path.append(directory)
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(directory)
    return mod


with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/rt14-adc.json"}):
    enf = _load("rt14fq_enforcer", FINOPS_DIR, "enforcer.py")
    _prior = sys.modules.get("enforcer")
    sys.modules["enforcer"] = enf
    try:
        enf_main = _load("rt14fq_enforcer_main", FINOPS_DIR, "main.py")
    finally:
        if _prior is None:
            sys.modules.pop("enforcer", None)
        else:
            sys.modules["enforcer"] = _prior

HOST = "mock-stackvend-project"
ROOT = "111111111111"
PID, PROJ = "shop-app", "shop-app-1"
ACCT = "billingAccounts/01ABCD-234567-89EF01"
TYPED_STOPS = ("QUARANTINE_STATE_UNREADABLE", "SNAPSHOT_READ_FAILED", "SNAPSHOT_PERSIST_FAILED",
               "QUARANTINE_RECORD_FAILED")


@pytest.fixture(autouse=True)
def _managed(monkeypatch):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)


def _crm():
    crm = MagicMock(name="crm")
    projects = crm.projects.return_value

    def get_ancestry(projectId, body):
        call = MagicMock()
        call.execute.return_value = {"ancestor": [{"resourceId": {"type": "project", "id": projectId}},
                                                  {"resourceId": {"type": "folder", "id": ROOT}}]}
        return call

    def get(projectId):
        call = MagicMock()
        call.execute.return_value = {"projectNumber": "222" if projectId == PROJ else "999"}
        return call

    projects.getAncestry.side_effect = get_ancestry
    projects.get.side_effect = get
    return crm


class Cloud:
    """The child project as the enforcer sees it through its resource methods (stateful: a stop is visible to the
    next read). `fail_reads` / `fail_ops`: resource types whose read / change fails; `lag`: reads of a VM after its
    start that still show TERMINATED."""

    def __init__(self):
        self.run = {"api": {"max": 7, "min": 1}, "worker": {"max": 3, "min": 0}}
        self.vms = {("us-central1-a", "vm-1"): "RUNNING", ("us-central1-a", "standby"): "TERMINATED"}
        self.sql = {"orders-db": "ALWAYS"}
        self.gke = {("us-central1", "c1", "pool"): 3}
        self.fail_reads, self.fail_ops = set(), set()
        self.lag = 0
        self.ops = []

    def attach(self, eng):
        eng.list_workload_services = self.list_run
        eng.list_running_vms = self.list_vms
        eng.list_cloud_sql_instances = self.list_sql
        eng.list_gke_pools = self.list_gke
        eng.set_service_scaling = self.scale
        eng.stop_vms = self.stop_vms
        eng.start_vms = self.start_vms
        eng.set_cloud_sql_activation = self.set_sql
        eng.scale_gke_pool = self.scale_gke
        return eng

    def _read(self, kind, strict):
        assert strict, f"{kind}: the enforcer read the live state leniently"
        if kind in self.fail_reads:
            raise enf.LiveStateReadError(kind, "boom")

    def list_run(self, proj, region=None, strict=False):
        self._read("cloud_run", strict)
        return [{"name": n, "max_instances": s["max"], "min_instances": s["min"]} for n, s in self.run.items()]

    def list_vms(self, proj, strict=False):
        self._read("compute_vms", strict)
        out = [{"zone": z, "name": n, "status": st} for (z, n), st in self.vms.items()]
        if self.lag:
            self.lag -= 1
            out = [dict(v, status="TERMINATED") if v["name"] == "vm-1" else v for v in out]
        return out

    def list_sql(self, proj, strict=False):
        self._read("cloud_sql", strict)
        return [{"name": n, "activation_policy": p} for n, p in self.sql.items()]

    def list_gke(self, proj, strict=False):
        self._read("gke_pools", strict)
        return [{"location": loc, "cluster_name": c, "pool_name": p, "node_count": n}
                for (loc, c, p), n in self.gke.items()]

    def scale(self, proj, name, max_instances, min_instances=0, region=None):
        self.ops.append(("run", name, max_instances, min_instances))
        if "run" in self.fail_ops:
            return False
        svc = self.run.setdefault(name, {"max": None, "min": 0})
        svc["min"] = min_instances
        if max_instances is not None:
            svc["max"] = None if max_instances == 0 else max_instances   # 0 reads back as absent (proto3)
        return True

    def stop_vms(self, proj, vms):
        self.ops.append(("stop", [v["name"] for v in vms]))
        for v in vms:
            self.vms[(v["zone"], v["name"])] = "TERMINATED"
        return [f"{v['zone']}/{v['name']}" for v in vms]

    def start_vms(self, proj, vms):
        self.ops.append(("start", [v["name"] for v in vms]))
        for v in vms:
            self.vms[(v["zone"], v["name"])] = "STAGING"
        return [f"{v['zone']}/{v['name']}" for v in vms]

    def set_sql(self, proj, name, policy):
        self.ops.append(("sql", name, policy))
        if "sql" in self.fail_ops:
            return False
        self.sql[name] = policy
        return True

    def scale_gke(self, proj, loc, cl, pool, count):
        self.ops.append(("gke", pool, count))
        self.gke[(loc, cl, pool)] = count
        return True

    def mutations(self):
        return [o for o in self.ops if o[0] in ("run", "stop", "start", "sql", "gke")]


def _db(**workload):
    db = F.FakeDB()
    db.put("workloads", PID, dict({"product_id": PID, "project_id": PROJ, "status": "ACTIVE"}, **workload))
    return db


def _engine(db, cloud=None, billing=None):
    eng = enf.FinopsBudgetEnforcer(project_id=HOST, firestore_client=db, run_service=MagicMock(),
                                   compute_service=MagicMock(), sql_service=MagicMock(),
                                   container_service=MagicMock(), billing_service=billing or MagicMock(),
                                   crm_service=_crm(), advisor=SimpleNamespace(available=False))
    eng.resolve_workload_region = lambda pid: "us-central1"
    clock = SimpleNamespace(t=0.0)
    eng._clock = lambda: clock.t
    eng._sleep = lambda s: setattr(clock, "t", clock.t + s)
    return (cloud or Cloud()).attach(eng)


def _quarantine(eng, policy="AUTONOMOUS_SCALE_TO_ZERO", threshold=100.0):
    return eng.quarantine_workload(PID, PROJ, spend_amount=150.0, budget_amount=threshold, policy=policy)


def _cards(db):
    return db.coll("approval_requests")


# ------------------------------------------------------------------------------------------------ RT14-05: idempotent
def test_rt14_05_second_breach_keeps_the_first_snapshot_and_the_restore_brings_everything_back():
    """The live failure: quarantine, then a second breach (a changed ceiling, a redelivery) on the zeroed workload,
    then restore. Before: the second snapshot recorded the zeroed state and the restore started nothing."""
    db, cloud = _db(), Cloud()
    eng = _engine(db, cloud)
    first = _quarantine(eng)
    assert first["status"] == "QUARANTINED"
    snap = db.doc("quarantine_snapshots", PID)
    assert snap["snapshot_version"] == enf.SNAPSHOT_VERSION
    assert {s["name"]: s["max_instances"] for s in snap["cloud_run_services"]} == {"api": 7, "worker": 3}
    assert cloud.vms[("us-central1-a", "vm-1")] == "TERMINATED" and cloud.sql["orders-db"] == "NEVER"
    assert db.doc("quarantined_workloads", PID)["snapshot"] == snap          # RT14-20: the second copy
    cards, ops = dict(_cards(db)), len(cloud.ops)

    second = _quarantine(eng, threshold=120.0)                               # the admin changed the ceiling
    assert second["status"] == "QUARANTINED" and second["already_enforced"] is True
    assert second["status"] in enf_main.ENFORCED_STATUSES                    # the drain latches it
    assert db.doc("quarantine_snapshots", PID) == snap                       # never overwritten
    assert len(cloud.ops) == ops and _cards(db) == cards                     # nothing touched, no second card

    out = eng.restore_workload(PID, PROJ)
    assert out["status"] == "RESTORED", out
    assert cloud.run == {"api": {"max": 7, "min": 1}, "worker": {"max": 3, "min": 0}}
    assert cloud.vms[("us-central1-a", "vm-1")] == "STAGING"                 # started
    assert cloud.vms[("us-central1-a", "standby")] == "TERMINATED"           # was not running: left alone
    assert cloud.sql["orders-db"] == "ALWAYS" and cloud.gke[("us-central1", "c1", "pool")] == 3
    assert db.doc("quarantine_snapshots", PID) is None and db.doc("quarantined_workloads", PID) is None
    assert db.doc("workloads", PID)["status"] == "ACTIVE"


@pytest.mark.parametrize("markers", ["record", "status"])
@pytest.mark.parametrize("policy", ["AUTONOMOUS_SCALE_TO_ZERO", "NUCLEAR_UNLINK_BILLING", "SOMETHING_ELSE"])
def test_rt14_05_an_enforced_workload_is_never_touched_again(markers, policy):
    db = _db(status="QUARANTINED") if markers == "status" else _db()
    if markers == "record":
        db.put("quarantined_workloads", PID, {"status": "QUARANTINED", "approval_id": "appr-1",
                                              "quarantined_resources": ["run/api"]})
    db.put("quarantine_snapshots", PID, {"cloud_run_services": [{"name": "api", "max_instances": 7}]})
    billing = MagicMock(name="billing")
    cloud = Cloud()
    out = _quarantine(_engine(db, cloud, billing), policy=policy)
    assert out["status"] == "QUARANTINED" and out["already_enforced"] is True, out
    assert cloud.ops == [] and not billing.projects.return_value.updateBillingInfo.called
    assert db.doc("quarantine_snapshots", PID) == {"cloud_run_services": [{"name": "api", "max_instances": 7}]}
    assert _cards(db) == {} and "root_billing_account" not in db.doc("workloads", PID)


def test_rt14_05_a_second_unlink_never_records_no_account():
    db = _db(status="BILLING_UNLINKED", root_billing_account=ACCT)
    billing = MagicMock(name="billing")
    billing.projects.return_value.getBillingInfo.return_value.execute.return_value = {}   # detached: no account
    out = _quarantine(_engine(db, billing=billing), policy="NUCLEAR_UNLINK_BILLING")
    assert out["status"] == "BILLING_UNLINKED" and out["already_enforced"] is True
    assert not billing.projects.return_value.updateBillingInfo.called
    assert db.doc("workloads", PID)["root_billing_account"] == ACCT


def test_rt14_05_an_unreadable_account_never_overwrites_the_recorded_one():
    """A redelivery after QUARANTINE_RECORD_FAILED (billing detached, status not recorded): the account recorded
    before the first unlink stays."""
    db = _db(root_billing_account=ACCT)
    billing = MagicMock(name="billing")
    billing.projects.return_value.getBillingInfo.return_value.execute.return_value = {}
    out = _quarantine(_engine(db, billing=billing), policy="NUCLEAR_UNLINK_BILLING")
    assert out["status"] == "BILLING_UNLINKED"
    w = db.doc("workloads", PID)
    assert w["status"] == "BILLING_UNLINKED" and w["root_billing_account"] == ACCT


def test_rt14_05_the_account_is_recorded_before_the_unlink():
    db = _db()
    billing = MagicMock(name="billing")
    billing.projects.return_value.getBillingInfo.return_value.execute.return_value = {"billingAccountName": ACCT}
    db.fail.add(("set", "workloads"))
    out = _quarantine(_engine(db, billing=billing), policy="NUCLEAR_UNLINK_BILLING")
    assert out["status"] == "SNAPSHOT_PERSIST_FAILED" and out["status"] not in enf_main.ENFORCED_STATUSES
    assert not billing.projects.return_value.updateBillingInfo.called         # nothing detached


@pytest.mark.parametrize("unreadable_record", [False, True])
def test_rt14_f2_no_readable_account_and_none_to_relink_detaches_nothing(monkeypatch, unreadable_record):
    """RT14 F2: the account cannot be read, none was recorded and BILLING_ACCOUNT_ID is unset (or the workload record
    cannot be read): a restore could not relink, so nothing is detached and the alert is redelivered."""
    monkeypatch.delenv("BILLING_ACCOUNT_ID", raising=False)
    db = _db()
    billing = MagicMock(name="billing")
    billing.projects.return_value.getBillingInfo.return_value.execute.side_effect = RuntimeError("403")
    eng = _engine(db, billing=billing)
    if unreadable_record:
        real = eng._existing_enforcement
        eng._existing_enforcement = lambda pid, proj: (real(pid, proj), db.fail.add(("get", ("workloads", PID))))[0]
    out = _quarantine(eng, policy="NUCLEAR_UNLINK_BILLING")
    assert out["status"] == "SNAPSHOT_READ_FAILED" and out["stage"] == "finops_quarantine"
    assert out["status"] not in enf_main.ENFORCED_STATUSES and out["status"] not in EJ.ENFORCED_STATUSES
    assert not billing.projects.return_value.updateBillingInfo.called
    assert db.doc("workloads", PID)["status"] == "ACTIVE" and _cards(db) == {}


@pytest.mark.parametrize("fallback", ["recorded", "install"])
def test_rt14_f2_negative_an_unread_account_still_unlinks_when_the_restore_can_relink(monkeypatch, fallback):
    """Do No Harm: with an account recorded earlier, or BILLING_ACCOUNT_ID set (always so in the job), the unlink
    proceeds as before."""
    if fallback == "install":
        monkeypatch.setenv("BILLING_ACCOUNT_ID", "01ABCD-234567-89EF01")
        db = _db()
    else:
        monkeypatch.delenv("BILLING_ACCOUNT_ID", raising=False)
        db = _db(root_billing_account=ACCT)
    billing = MagicMock(name="billing")
    billing.projects.return_value.getBillingInfo.return_value.execute.side_effect = RuntimeError("403")
    out = _quarantine(_engine(db, billing=billing), policy="NUCLEAR_UNLINK_BILLING")
    assert out["status"] == "BILLING_UNLINKED"
    assert billing.projects.return_value.updateBillingInfo.called


def test_rt14_05_unlink_status_and_card_failure_is_typed():
    db = _db()
    billing = MagicMock(name="billing")
    billing.projects.return_value.getBillingInfo.return_value.execute.return_value = {"billingAccountName": ACCT}
    db.fail.add(("commit", None))
    out = _quarantine(_engine(db, billing=billing), policy="NUCLEAR_UNLINK_BILLING")
    assert out["status"] == "QUARANTINE_RECORD_FAILED" and out["stage"] == "finops_quarantine"
    assert db.doc("workloads", PID)["root_billing_account"] == ACCT and db.doc("workloads", PID)["status"] == "ACTIVE"


def test_rt14_05_negative_hitl_and_alert_only_are_unchanged_on_a_quarantined_workload():
    """Do No Harm: the non-destructive policies still write their card / alert (no idempotency short cut)."""
    db = _db(status="QUARANTINED")
    eng = _engine(db)
    assert _quarantine(eng, policy="HITL_CONFIRMATION_REQUIRED")["status"] == "HITL_CONFIRMATION_PENDING"
    assert _quarantine(eng, policy="ALERT_ONLY")["status"] == "ALERTED_ONLY"
    assert len(_cards(db)) == 1 and len(db.coll("billing_alerts")) == 1


def test_rt14_05_markers_unreadable_is_typed_and_changes_nothing():
    db, cloud = _db(), Cloud()
    db.fail.add(("get", ("quarantined_workloads", PID)))
    out = _quarantine(_engine(db, cloud))
    assert out["status"] == "QUARANTINE_STATE_UNREADABLE" and cloud.ops == []
    assert db.doc("quarantine_snapshots", PID) is None


def test_rt14_05_a_missing_max_is_recorded_as_none_not_5():
    run = MagicMock(name="run")
    run.projects.return_value.locations.return_value.services.return_value.list.return_value.execute.return_value = {
        "services": [{"name": "p/services/api", "template": {"scaling": {"minInstanceCount": 1}}},
                     {"name": "p/services/web", "template": {"scaling": {"maxInstanceCount": 9}}}]}
    eng = enf.FinopsBudgetEnforcer(project_id=HOST, firestore_client=F.FakeDB(), run_service=run,
                                   compute_service=MagicMock(), sql_service=MagicMock(), container_service=MagicMock(),
                                   billing_service=MagicMock(), crm_service=_crm(),
                                   advisor=SimpleNamespace(available=False))
    assert eng.list_workload_services(PROJ, region="us-central1", strict=True) == [
        {"name": "api", "max_instances": None, "min_instances": 1},
        {"name": "web", "max_instances": 9, "min_instances": 0}]


def test_rt14_05_strict_cloud_run_read_pages_through_every_result():
    run = MagicMock(name="run")
    services = run.projects.return_value.locations.return_value.services.return_value
    pages = {None: {"services": [{"name": "p/services/a"}], "nextPageToken": "t2"},
             "t2": {"services": [{"name": "p/services/b"}]}}
    services.list.side_effect = lambda parent, pageToken=None: SimpleNamespace(execute=lambda: pages[pageToken])
    eng = enf.FinopsBudgetEnforcer(project_id=HOST, firestore_client=F.FakeDB(), run_service=run,
                                   compute_service=MagicMock(), sql_service=MagicMock(), container_service=MagicMock(),
                                   billing_service=MagicMock(), crm_service=_crm(),
                                   advisor=SimpleNamespace(available=False))
    assert [s["name"] for s in eng.list_workload_services(PROJ, strict=True)] == ["a", "b"]
    assert [s["name"] for s in eng.list_workload_services(PROJ)] == ["a"]   # the lenient read is unchanged


# ------------------------------------------------------------------------------------------------ RT14-05: restore
def _quarantined(cloud=None):
    db, cloud = _db(), cloud or Cloud()
    eng = _engine(db, cloud)
    assert _quarantine(eng)["status"] == "QUARANTINED"
    return db, cloud, eng


def test_rt14_05_restore_not_confirmed_is_partial_and_keeps_everything():
    db, cloud, eng = _quarantined()
    snap = db.doc("quarantine_snapshots", PID)
    cloud.fail_reads.add("cloud_sql")                                       # the read-back cannot see Cloud SQL
    out = eng.restore_workload(PID, PROJ)
    assert out["status"] == "RESTORE_PARTIAL" and out["unverified"] == ["sql/orders-db"] and out["failed"] == []
    assert out["status"] not in EJ.RESTORE_STATUSES
    assert db.doc("quarantine_snapshots", PID) == snap and db.doc("quarantined_workloads", PID)
    assert db.doc("workloads", PID)["status"] == "QUARANTINED"
    cloud.fail_reads.clear()                                                 # deciding again re-applies and confirms
    assert eng.restore_workload(PID, PROJ)["status"] == "RESTORED"


def test_rt14_05_restore_waits_for_a_vm_that_is_still_coming_up():
    db, cloud, eng = _quarantined()
    cloud.lag = 2                                                            # two reads still show TERMINATED
    assert eng.restore_workload(PID, PROJ)["status"] == "RESTORED"
    db2, cloud2, eng2 = _quarantined()
    cloud2.lag = 10**6
    eng2.restore_verify_wait_s = 30
    out = eng2.restore_workload(PID, PROJ)
    assert out["status"] == "RESTORE_PARTIAL" and out["unverified"] == ["gce/us-central1-a/vm-1"]


def test_rt14_05_a_restore_that_leaves_cloud_run_at_zero_is_not_restored():
    db, cloud, eng = _quarantined()
    real_scale = cloud.scale
    cloud.scale = lambda proj, name, max_instances, min_instances=0, region=None: True   # accepted, no effect
    cloud.attach(eng)
    out = eng.restore_workload(PID, PROJ)
    assert out["status"] == "RESTORE_PARTIAL" and set(out["unverified"]) == {"run/api", "run/worker"}
    cloud.scale = real_scale
    cloud.attach(eng)
    assert eng.restore_workload(PID, PROJ)["status"] == "RESTORED"


def test_rt14_05_restore_record_failure_is_typed_and_keeps_the_markers():
    db, cloud, eng = _quarantined()
    db.fail.add(("commit", None))
    out = eng.restore_workload(PID, PROJ)
    assert out["status"] == "RESTORE_RECORD_FAILED" and out["status"] not in EJ.RESTORE_STATUSES
    assert db.doc("quarantine_snapshots", PID) and db.doc("quarantined_workloads", PID)
    assert db.doc("workloads", PID)["status"] == "QUARANTINED"


def test_rt14_05_restore_uses_the_record_copy_and_refuses_a_rewritten_snapshot():
    db, cloud, eng = _quarantined()
    snap = db.doc("quarantine_snapshots", PID)
    db.put("quarantine_snapshots", PID, dict(snap, cloud_run_services=[]))     # rewritten after the quarantine
    ops = len(cloud.ops)
    assert eng.restore_workload(PID, PROJ)["status"] == "SNAPSHOT_MISMATCH" and len(cloud.ops) == ops
    db.docs.pop(("quarantine_snapshots", PID))                                # gone: the record's copy is used
    assert eng.restore_workload(PID, PROJ)["status"] == "RESTORED"
    assert cloud.run["api"] == {"max": 7, "min": 1}


def test_rt14_05_negative_a_legacy_snapshot_restores_as_before():
    """Do No Harm: a quarantine recorded before RT14-05 (no snapshot copy in the record, no version) restores."""
    db, cloud = _db(status="QUARANTINED"), Cloud()
    cloud.run = {"api": {"max": None, "min": 0}}
    cloud.vms, cloud.sql, cloud.gke = {}, {}, {}
    db.put("quarantine_snapshots", PID, {"cloud_run_services": [{"name": "api", "max_instances": 4,
                                                                 "min_instances": 0}]})
    db.put("quarantined_workloads", PID, {"status": "QUARANTINED"})
    out = _engine(db, cloud).restore_workload(PID, PROJ)
    assert out["status"] == "RESTORED" and cloud.run["api"] == {"max": 4, "min": 0}


def test_rt14_05_billing_relink_is_read_back():
    db = _db(status="BILLING_UNLINKED", root_billing_account=ACCT)
    billing = MagicMock(name="billing")
    billing.projects.return_value.getBillingInfo.return_value.execute.return_value = {}   # still detached
    out = _engine(db, billing=billing).restore_workload(PID, PROJ)
    assert out["status"] == "BILLING_RELINK_UNVERIFIED" and out["status"] not in EJ.RESTORE_STATUSES
    assert db.doc("workloads", PID)["status"] == "BILLING_UNLINKED"
    billing.projects.return_value.getBillingInfo.return_value.execute.return_value = {"billingAccountName": ACCT}
    assert _engine(db, billing=billing).restore_workload(PID, PROJ)["status"] == "BILLING_RESTORED"
    assert db.doc("workloads", PID)["status"] == "ACTIVE"


# ------------------------------------------------------------------------------------------------ RT14-20: durable first
def test_rt14_20_a_snapshot_that_cannot_be_written_stops_everything():
    db, cloud = _db(), Cloud()
    db.fail.add(("create", "quarantine_snapshots"))
    out = _quarantine(_engine(db, cloud))
    assert out["status"] == "SNAPSHOT_PERSIST_FAILED" and out["error_class"] == "SNAPSHOT_PERSIST_FAILED"
    assert out["status"] not in enf_main.ENFORCED_STATUSES and out["status"] not in EJ.ENFORCED_STATUSES
    assert cloud.mutations() == [] and db.doc("quarantined_workloads", PID) is None
    assert db.doc("workloads", PID)["status"] == "ACTIVE" and _cards(db) == {}


@pytest.mark.parametrize("kind", ["cloud_run", "compute_vms", "cloud_sql", "gke_pools"])
def test_rt14_20_a_live_read_failure_stops_everything(kind):
    db, cloud = _db(), Cloud()
    cloud.fail_reads.add(kind)
    out = _quarantine(_engine(db, cloud))
    assert out["status"] == "SNAPSHOT_READ_FAILED" and cloud.mutations() == []
    assert db.doc("quarantine_snapshots", PID) is None


def test_rt14_20_without_firestore_nothing_is_scaled():
    db, cloud = _db(), Cloud()
    eng = _engine(db, cloud)
    eng.db = None
    out = _quarantine(eng)
    assert out["status"] == "SNAPSHOT_PERSIST_FAILED" and cloud.mutations() == []


def test_rt14_20_a_failed_record_is_typed_and_the_redelivery_finishes_from_the_kept_snapshot():
    db, cloud = _db(), Cloud()
    eng = _engine(db, cloud)
    db.fail.add(("commit", None))
    out = _quarantine(eng)
    assert out["status"] == "QUARANTINE_RECORD_FAILED" and out["status"] not in enf_main.ENFORCED_STATUSES
    snap = db.doc("quarantine_snapshots", PID)
    assert {s["name"]: s["max_instances"] for s in snap["cloud_run_services"]} == {"api": 7, "worker": 3}
    assert db.doc("quarantined_workloads", PID) is None and _cards(db) == {}
    db.fail.discard(("commit", None))
    out = _quarantine(eng)                                                   # the re-sent alert
    assert out["status"] == "QUARANTINED" and db.doc("quarantine_snapshots", PID) == snap   # kept unchanged
    assert db.doc("quarantined_workloads", PID)["snapshot"] == snap and len(_cards(db)) == 1
    assert eng.restore_workload(PID, PROJ)["status"] == "RESTORED"
    assert cloud.run["api"] == {"max": 7, "min": 1} and cloud.sql["orders-db"] == "ALWAYS"


def test_rt14_20_the_resume_adds_only_resources_created_since():
    db, cloud = _db(), Cloud()
    eng = _engine(db, cloud)
    db.fail.add(("commit", None))
    _quarantine(eng)
    snap = db.doc("quarantine_snapshots", PID)
    db.fail.discard(("commit", None))
    cloud.run["reports"] = {"max": 2, "min": 0}                              # deployed in between
    assert _quarantine(eng)["status"] == "QUARANTINED"
    after = db.doc("quarantine_snapshots", PID)
    assert after["cloud_run_services"][:2] == snap["cloud_run_services"]      # kept entries unchanged
    assert after["cloud_run_services"][2] == {"name": "reports", "max_instances": 2, "min_instances": 0}
    assert cloud.run["reports"] == {"max": None, "min": 0}                   # and it was stopped too


def _interrupted(cloud):
    """A quarantine interrupted after its snapshot and before its record (QUARANTINE_RECORD_FAILED), never finished."""
    db = _db()
    eng = _engine(db, cloud)
    db.fail.add(("commit", None))
    assert _quarantine(eng)["status"] == "QUARANTINE_RECORD_FAILED"
    db.fail.discard(("commit", None))
    return db, eng


def test_rt14_f1_a_resource_serving_now_replaces_its_kept_entry_and_is_restored():
    """RT14 F1: the kept snapshot lists a VM TERMINATED and a Cloud SQL instance NEVER; both serve now (started after
    the interrupted attempt), and a Cloud Run service was redeployed with a new max. The quarantine stops them, so the
    restore must start them again and read them back."""
    cloud = Cloud()
    cloud.sql["archive-db"] = "NEVER"
    db, eng = _interrupted(cloud)
    kept = db.doc("quarantine_snapshots", PID)
    assert {(v["name"], v["status"]) for v in kept["compute_vms"]} >= {("standby", "TERMINATED")}
    cloud.vms[("us-central1-a", "standby")] = "RUNNING"
    cloud.sql["archive-db"] = "ALWAYS"
    cloud.run["worker"] = {"max": 5, "min": 0}
    assert _quarantine(eng)["status"] == "QUARANTINED"
    snap = db.doc("quarantine_snapshots", PID)
    vms = {v["name"]: v["status"] for v in snap["compute_vms"]}
    assert vms == {"vm-1": "RUNNING", "standby": "RUNNING"}               # vm-1 kept (stopped by the first attempt)
    assert {s["name"]: s["activation_policy"] for s in snap["cloud_sql"]} == {"orders-db": "ALWAYS",
                                                                             "archive-db": "ALWAYS"}
    assert {s["name"]: s["max_instances"] for s in snap["cloud_run_services"]} == {"api": 7, "worker": 5}
    assert cloud.vms[("us-central1-a", "standby")] == "TERMINATED" and cloud.sql["archive-db"] == "NEVER"
    assert db.doc("quarantined_workloads", PID)["snapshot"] == snap
    out = eng.restore_workload(PID, PROJ)
    assert out["status"] == "RESTORED", out
    assert cloud.vms[("us-central1-a", "standby")] == "STAGING" and cloud.vms[("us-central1-a", "vm-1")] == "STAGING"
    assert cloud.sql == {"orders-db": "ALWAYS", "archive-db": "ALWAYS"}
    assert cloud.run == {"api": {"max": 7, "min": 1}, "worker": {"max": 5, "min": 0}}


def test_rt14_f1_negative_a_resource_the_interrupted_attempt_stopped_keeps_its_kept_entry():
    """Do No Harm: kept RUNNING / ALWAYS / max 7, live TERMINATED / NEVER / zeroed (the first attempt stopped them):
    the kept entries stay exactly as they were and nothing else is written."""
    cloud = Cloud()
    db, eng = _interrupted(cloud)
    kept = db.doc("quarantine_snapshots", PID)
    assert cloud.vms[("us-central1-a", "vm-1")] == "TERMINATED" and cloud.sql["orders-db"] == "NEVER"
    assert _quarantine(eng)["status"] == "QUARANTINED"
    assert db.doc("quarantine_snapshots", PID) == kept
    assert {v["name"]: v["status"] for v in kept["compute_vms"]}["vm-1"] == "RUNNING"


def test_rt14_f1_running_now_is_exact_per_resource_type():
    rn = enf._running_now
    assert rn("compute_vms", {"status": "RUNNING"}) and not rn("compute_vms", {"status": "TERMINATED"})
    assert rn("cloud_sql", {"activation_policy": "ALWAYS"}) and not rn("cloud_sql", {"activation_policy": "NEVER"})
    assert rn("cloud_run_services", {"max_instances": 3, "min_instances": 0})
    assert rn("cloud_run_services", {"max_instances": None, "min_instances": 1})
    assert not rn("cloud_run_services", {"max_instances": None, "min_instances": 0})
    assert not rn("cloud_run_services", {"max_instances": 0, "min_instances": 0})
    assert not rn("gke_pools", {"node_count": 3})


def test_rt14_20_negative_project_without_the_sql_api_still_quarantines():
    """Do No Harm: a project where an API is not enabled holds none of its resources (structured SERVICE_DISABLED)."""
    from googleapiclient.errors import HttpError
    body = {"error": {"code": 403, "status": "PERMISSION_DENIED", "details": [
        {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "SERVICE_DISABLED"}]}}
    sql = MagicMock(name="sql")
    sql.instances.return_value.list.return_value.execute.side_effect = HttpError(
        SimpleNamespace(status=403, reason="Forbidden"), json.dumps(body).encode())
    eng = enf.FinopsBudgetEnforcer(project_id=HOST, firestore_client=F.FakeDB(), run_service=MagicMock(),
                                   compute_service=MagicMock(), sql_service=sql, container_service=MagicMock(),
                                   billing_service=MagicMock(), crm_service=_crm(),
                                   advisor=SimpleNamespace(available=False))
    assert eng.list_cloud_sql_instances(PROJ, strict=True) == []
    other = dict(body, error=dict(body["error"], details=[]))
    sql.instances.return_value.list.return_value.execute.side_effect = HttpError(
        SimpleNamespace(status=403, reason="Forbidden"), json.dumps(other).encode())
    with pytest.raises(enf.LiveStateReadError):
        eng.list_cloud_sql_instances(PROJ, strict=True)                      # a permission error is not "none"
    assert eng.list_cloud_sql_instances(PROJ) == []                           # the lenient read is unchanged


def test_rt14_20_the_run_record_keeps_a_copy_of_the_snapshot():
    db = _db()
    code, summary = enf_main.run_batch({"PROJECT_ID": HOST, "CLOUD_RUN_EXECUTION": "e1",
                                        "FINOPS_ENFORCE_PRODUCT_ID": PID,
                                        "FINOPS_ENFORCE_TARGET_PROJECT_ID": PROJ}, _engine(db))
    assert code == 0 and summary["outcome"] == "QUARANTINED"
    assert db.doc("finops-budget-enforcer-job_runs", "e1")["snapshot"] == db.doc("quarantine_snapshots", PID)


def test_rt14_20_a_typed_stop_is_a_failed_run_and_a_redelivered_alert():
    db = _db()
    db.fail.add(("create", "quarantine_snapshots"))
    code, summary = enf_main.run_batch({"PROJECT_ID": HOST, "CLOUD_RUN_EXECUTION": "e2",
                                        "FINOPS_ENFORCE_PRODUCT_ID": PID,
                                        "FINOPS_ENFORCE_TARGET_PROJECT_ID": PROJ}, _engine(db))
    assert code == 1 and summary["outcome"] == "SNAPSHOT_PERSIST_FAILED"
    assert summary["error_class"] == "SNAPSHOT_PERSIST_FAILED"
    assert not set(TYPED_STOPS) & (EJ.ENFORCED_STATUSES | EJ.RESTORE_STATUSES)


@pytest.mark.parametrize("outcome", ["RESTORE_PARTIAL", "RESTORE_RECORD_FAILED", "SNAPSHOT_MISMATCH",
                                     "BILLING_RELINK_UNVERIFIED"])
def test_rt14_05_the_control_center_never_reads_a_new_restore_outcome_as_done(outcome):
    """shared/enforcer_job.py (the Control Center's client): any outcome outside RESTORE_STATUSES raises the typed
    EnforcerRunError, so the budget card is EXECUTION_FAILED and stays decidable (routes/approvals.py)."""
    from types import SimpleNamespace as NS
    db = F.FakeDB()
    job = f"projects/{HOST}/locations/us-central1/jobs/finops-budget-enforcer-job"
    rest = F.FakeRest(execution=f"{job}/executions/e9")
    rest.on_run = lambda body: db.put("finops-budget-enforcer-job_runs", "e9", {"outcome": outcome, "reason": "x"})
    clock = NS(t=0.0)
    client = EJ.EnforcerJob(rest, db, HOST, "us-central1", clock=lambda: clock.t,
                            sleep=lambda s: setattr(clock, "t", clock.t + s), wait_s=60)
    with pytest.raises(EJ.EnforcerRunError) as err:
        client.restore_workload(PID, PROJ)
    assert err.value.code == f"ENFORCER_{outcome}"


# ------------------------------------------------------------------------------------------------ structural guards
def _function(name):
    tree = ast.parse(open(os.path.join(FINOPS_DIR, "enforcer.py")).read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(name)


def _calls(node, names):
    return [c for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
            and c.func.attr in names]


MUTATORS = {"set_service_scaling", "stop_vms", "set_cloud_sql_activation", "scale_gke_pool", "unlink_billing_account"}


def test_guard_every_quarantine_mutation_follows_the_idempotency_check_and_the_durable_record():
    """Structural: in quarantine_workload, every statement that stops compute or detaches billing comes after an
    `_existing_enforcement` check in the same block, and every compute stop after `take_pre_quarantine_snapshot`."""
    fn = _function("quarantine_workload")
    blocks = [fn.body] + [s.body for s in fn.body if isinstance(s, ast.If) and _calls(s, MUTATORS)]
    checked = 0
    for block in blocks:
        for i, stmt in enumerate(block):
            if isinstance(stmt, ast.If) and block is fn.body and _calls(stmt, MUTATORS):
                continue                                                     # checked as its own block
            for call in _calls(stmt, MUTATORS):
                before = block[:i]
                assert any(_calls(s, {"_existing_enforcement"}) for s in before), (call.func.attr, call.lineno)
                if call.func.attr != "unlink_billing_account":
                    assert any(_calls(s, {"take_pre_quarantine_snapshot"}) for s in before), call.lineno
                checked += 1
    assert checked >= 5


def test_guard_snapshot_and_restore_checks_read_strictly():
    """Structural: the snapshot and the restore check read the live state with strict=True (a lenient read answers []
    on failure, which would record or confirm nothing)."""
    readers = {"list_workload_services", "list_running_vms", "list_cloud_sql_instances", "list_gke_pools"}
    for name in ("take_pre_quarantine_snapshot", "_unconfirmed_restore"):
        calls = _calls(_function(name), readers)
        assert calls, name
        for c in calls:
            assert any(k.arg == "strict" and isinstance(k.value, ast.Constant) and k.value.value is True
                       for k in c.keywords), (name, c.func.attr, c.lineno)


def test_guard_restored_is_reported_only_after_the_read_back():
    fn = _function("restore_workload")
    status_lines = {}
    for d in ast.walk(fn):
        if isinstance(d, ast.Dict):
            for k, v in zip(d.keys, d.values):
                if isinstance(k, ast.Constant) and k.value == "status" and isinstance(v, ast.Constant):
                    status_lines.setdefault(v.value, []).append(d.lineno)
    confirm = [c.lineno for c in _calls(fn, {"_confirm_restore"})]
    readback = [c.lineno for c in _calls(fn, {"billing_account_of"})]
    assert confirm and all(line > min(confirm) for line in status_lines["RESTORED"])
    assert readback and all(line > min(readback) for line in status_lines["BILLING_RESTORED"])


def test_guard_no_code_overwrites_a_quarantine_snapshot():
    """Structural, repo-wide: `quarantine_snapshots` documents are only created, updated under a precondition, read or
    deleted; never `.set()` (which replaced the pre-quarantine state with the zeroed one)."""
    import subprocess
    files = subprocess.run(["git", "ls-files", "*.py"], cwd=REPO, capture_output=True, text=True).stdout.split()
    offenders = []
    for rel in files:
        if rel.startswith("tests/"):
            continue
        try:
            tree = ast.parse(open(os.path.join(REPO, rel)).read())
        except (SyntaxError, UnicodeDecodeError, FileNotFoundError):
            continue
        for call in ast.walk(tree):
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "set"):
                continue
            targets = [call.func.value] + call.args[:1]                     # db...document(x).set / batch.set(ref)
            chain = [n for t in targets for n in ast.walk(t) if isinstance(n, ast.Constant)]
            if any(n.value == "quarantine_snapshots" for n in chain):
                offenders.append(f"{rel}:{call.lineno}")
    assert offenders == []
