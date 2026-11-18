"""FD-7L Phase 5a (SAT-31) follow-ups, owner 11-01:

* The dispatch watcher (register "FD-7L-TF amendment: callback grant"): a Per-workload tf-applier execution that ends
  or never starts without redeeming its nonce gets ONE typed FAILED callback (TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM,
  operator_required) from the terraform server, decided from vending's SIGNED dispatch record only; a redeemed run is
  never reported; at most once across instances (claim = compare-and-set); bounded in time.
* SAT-27 RT L3: one brokered runner per process (RUNNER_NOT_SINGLE_TENANT).
* SAT-27 RT L1 (CHECKPOINT_DISABLE=1 in the tofu env) is pinned in tests/test_fd7l_2a_runner_service.py.

Do No Harm: on a Shared install nothing is registered, scheduled or swept. Hermetic: fake stores, fake clock,
signatures with tests/fd7l_fakes.py's real RSA key.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import datetime as _dt
import os
import threading
import types
from unittest.mock import MagicMock

import pytest

import fd7l_fakes as fk
from test_fd4g_terraform_workspace import (  # noqa: F401  (pytest fixtures reused by name)
    _isolated_tf_service, _load_tf_module, base, sent_callbacks)
from test_fd7l_5a_dispatch import (  # noqa: F401  (fixtures and fakes reused by name)
    BUCKET, CALLBACK, CHILD, EXECUTION, HOST, MODE, PRODUCT, FakeGuardDb, FakeWatchStore, _post, per_workload,
    tf_main)

DISPATCH_ID = "d" * 64
T0 = 1_793_000_000.0                       # the dispatch's creation time (epoch seconds; test clock)


def _iso(epoch):
    return _dt.datetime.fromtimestamp(epoch, tz=_dt.timezone.utc).isoformat()


def _nonce_record(ri, key=None, signer=None, **over):
    rec = {"schema": ri.NONCE_SCHEMA, "product_id": PRODUCT, "project_id": CHILD, "project_number": "123456789",
           "deployer_email": f"stackvend-deployer@{CHILD}.iam.gserviceaccount.com", "state_bucket": BUCKET,
           "state_prefix": f"workloads/{PRODUCT}", "repository": None, "trace_id": "t1", "branch": "main",
           "mode": "deploy", "callback_url": CALLBACK, "payload_ref": None, "payload_sha256": None,
           "saved_plan_sha256": None, "backfill_product_ids": None, "dispatched_by": fk.DEVELOPER,
           "created_at": _iso(T0), "execution": EXECUTION, "redeemed": False, "redeemed_at": None,
           "redeemed_by": None, "session_key_sha256": None}
    rec.update(over)
    return ri.sign_record(ri.nonce_doc_path(DISPATCH_ID), rec, signer_email=signer or fk.BROKER,
                          signed_at=_iso(T0), sign_blob=(key or fk.BROKER_KEY).sign)


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def kit(tf_main):
    ri, rd = tf_main.ri, tf_main.rd
    guard = FakeGuardDb({(ri.NONCE_COLLECTION, DISPATCH_ID): _nonce_record(ri)})
    store, reports, clock = FakeWatchStore(), [], Clock(T0 + 1)

    def make(store_=None):
        return rd.DispatchWatcher(store_ or store, guard_db=lambda: guard, expected_signer=lambda: fk.BROKER,
                                  certs=fk.certs_for(), report=reports.append, clock=clock)

    w = make()
    w.register(dispatch_id=DISPATCH_ID, execution=EXECUTION, product_id=PRODUCT, trace_id="t1")
    return types.SimpleNamespace(ri=ri, rd=rd, guard=guard, store=store, reports=reports, clock=clock, w=w,
                                 make=make)


def _after_window(k):
    k.clock.t = T0 + k.ri.REDEEM_WINDOW_SECONDS + k.rd.WATCH_MARGIN_S + 1


# ------------------------------------------------------------------------------------------------ the decision
def test_watch_waits_while_vending_may_still_accept_the_redeem(kit):
    assert kit.store.docs[DISPATCH_ID]["state"] == "WATCHING"
    kit.clock.t = T0 + kit.ri.REDEEM_WINDOW_SECONDS + kit.rd.WATCH_MARGIN_S - 1
    assert kit.w.check(DISPATCH_ID) == "WATCHING" and not kit.reports


def test_unredeemed_after_the_window_is_reported_once(kit):
    _after_window(kit)
    assert kit.w.check(DISPATCH_ID) == "SENT"
    assert len(kit.reports) == 1
    r = kit.reports[0]
    assert r["status"] == "FAILED" and r["error_class"] == "TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM"
    assert r["operator_required"] is True and r["callback_url"] == CALLBACK and r["execution"] == EXECUTION
    assert r["product_id"] == PRODUCT and r["trace_id"] == "t1"
    # never twice: the same watcher, another instance on the same store, a sweep
    assert kit.w.check(DISPATCH_ID) == "SENT"
    assert kit.make().check(DISPATCH_ID) == "SENT"
    assert kit.make().sweep() == {}
    assert len(kit.reports) == 1


def test_the_callback_url_comes_from_the_signed_record_only(kit):
    kit.store.docs[DISPATCH_ID]["callback_url"] = "https://attacker.example/cb"   # a forged watch document field
    _after_window(kit)
    kit.w.check(DISPATCH_ID)
    assert kit.reports[0]["callback_url"] == CALLBACK


def test_concurrent_instances_report_at_most_once(kit):
    _after_window(kit)
    barrier = threading.Barrier(8)

    def run():
        barrier.wait()
        kit.make().check(DISPATCH_ID)

    threads = [threading.Thread(target=run) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(kit.reports) == 1


def test_a_redeemed_run_is_never_reported(kit):
    kit.guard.docs[(kit.ri.NONCE_COLLECTION, DISPATCH_ID)] = _nonce_record(kit.ri, redeemed=True,
                                                                            redeemed_at=_iso(T0 + 30))
    _after_window(kit)
    assert kit.w.check(DISPATCH_ID) == "REDEEMED"
    kit.clock.t += 3600
    assert kit.make().check(DISPATCH_ID) == "REDEEMED" and not kit.reports


@pytest.mark.parametrize("case", ["forged", "tampered", "missing", "not_a_dispatch"])
def test_an_untrusted_record_never_triggers_a_callback(kit, case):
    key = (kit.ri.NONCE_COLLECTION, DISPATCH_ID)
    if case == "forged":
        kit.guard.docs[key] = _nonce_record(kit.ri, key=fk.OTHER_KEY, signer=fk.CC)
    elif case == "tampered":   # a redeemed record edited back to "not redeemed"
        rec = _nonce_record(kit.ri, redeemed=True)
        rec["redeemed"] = False
        kit.guard.docs[key] = rec
    elif case == "missing":
        kit.guard.docs.pop(key)
    else:
        kit.guard.docs[key] = _nonce_record(kit.ri, schema="runner_identity/v1")
    _after_window(kit)
    assert kit.w.check(DISPATCH_ID) == "UNVERIFIED" and not kit.reports


def test_an_unreadable_record_is_checked_again_then_given_up(kit):
    kit.guard.raises = RuntimeError("guard db down")
    _after_window(kit)
    assert kit.w.check(DISPATCH_ID) == "WATCHING" and not kit.reports
    kit.clock.t = T0 + 1 + kit.rd.WATCH_GIVE_UP_S + 1
    assert kit.w.check(DISPATCH_ID) == "UNVERIFIED" and not kit.reports


def test_an_old_dispatch_expires_without_a_callback(kit):
    kit.store.docs[DISPATCH_ID].pop("give_up_at_epoch")
    kit.clock.t = T0 + kit.rd.WATCH_GIVE_UP_S + 1
    assert kit.w.check(DISPATCH_ID) == "EXPIRED" and not kit.reports


def test_a_lost_watch_document_is_still_reported_once(kit):
    """register failed (Firestore down): the dispatching instance's check creates the claim itself."""
    store = FakeWatchStore(fail_create=True)
    w = kit.make(store)
    w.register(dispatch_id=DISPATCH_ID, execution=EXECUTION, product_id=PRODUCT, trace_id="t1")
    assert store.docs == {}
    _after_window(kit)
    assert w.check(DISPATCH_ID) == "SENT" and len(kit.reports) == 1
    assert w.check(DISPATCH_ID) == "SENT" and len(kit.reports) == 1


def test_a_report_failure_still_ends_the_watch(kit):
    """At most once: a callback that raised is logged by the sender and never retried by another instance."""
    w = kit.rd.DispatchWatcher(kit.store, guard_db=lambda: kit.guard, expected_signer=lambda: fk.BROKER,
                               certs=fk.certs_for(), report=lambda r: (_ for _ in ()).throw(RuntimeError("down")),
                               clock=kit.clock)
    _after_window(kit)
    with pytest.raises(RuntimeError):
        w.check(DISPATCH_ID)
    assert kit.store.docs[DISPATCH_ID]["state"] == "SENT"
    assert kit.make().check(DISPATCH_ID) == "SENT" and not kit.reports


def test_sweep_decides_only_pending_watches(kit):
    kit.store.docs["e" * 64] = {"state": "SENT"}
    _after_window(kit)
    assert kit.make().sweep() == {DISPATCH_ID: "SENT"} and len(kit.reports) == 1


def test_no_broker_identity_waits(kit):
    w = kit.rd.DispatchWatcher(kit.store, guard_db=lambda: kit.guard, expected_signer=lambda: None,
                               certs=fk.certs_for(), report=kit.reports.append, clock=kit.clock)
    _after_window(kit)
    assert w.check(DISPATCH_ID) == "WATCHING" and not kit.reports


# ------------------------------------------------------------------------------------------------ server wiring
def test_per_workload_dispatch_registers_and_schedules_the_watch(per_workload, sent_callbacks):
    tf_main, vending, guard = per_workload
    ri = tf_main.ri
    clock = Clock(T0 + 1)
    tf_main.WATCH_CLOCK = clock
    guard.docs[(ri.NONCE_COLLECTION, DISPATCH_ID)] = _nonce_record(ri)
    vending.body["dispatch_id"] = DISPATCH_ID
    tf_main.service.db = MagicMock()
    assert _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "trace_id": "t1",
                                            "callback_url": CALLBACK}).status_code == 202
    assert tf_main.watches.docs[DISPATCH_ID]["state"] == "WATCHING"
    assert tf_main.watches.docs[DISPATCH_ID]["execution"] == EXECUTION
    (delay, fn, args), = tf_main.scheduled
    assert delay == ri.REDEEM_WINDOW_SECONDS + tf_main.rd.WATCH_MARGIN_S + 1
    clock.t = T0 + delay + 1
    fn(*args)                                                   # the timer fires: the execution never redeemed
    assert len(sent_callbacks) == 1
    cb = sent_callbacks[0]
    assert cb["status"] == "FAILED" and cb["error_class"] == "TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM"
    assert cb["operator_required"] is True and cb["trace_id"] == "t1" and "callback_url" not in cb
    assert len(tf_main.scheduled) == 1                          # decided: not re-armed
    tf_main._sweep_dispatch_watches()                           # another instance's sweep: nothing more
    assert len(sent_callbacks) == 1


def test_per_workload_redeemed_run_gets_no_server_callback(per_workload, sent_callbacks):
    tf_main, vending, guard = per_workload
    ri = tf_main.ri
    tf_main.WATCH_CLOCK = Clock(T0 + 1)
    guard.docs[(ri.NONCE_COLLECTION, DISPATCH_ID)] = _nonce_record(ri, redeemed=True)
    vending.body["dispatch_id"] = DISPATCH_ID
    assert _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK}).status_code == 202
    (delay, fn, args), = tf_main.scheduled
    tf_main.WATCH_CLOCK = Clock(T0 + delay + 600)
    fn(*args)
    assert not sent_callbacks and tf_main.watches.docs[DISPATCH_ID]["state"] == "REDEEMED"


def test_per_workload_undecided_watch_is_re_armed_until_the_local_limit(per_workload):
    tf_main, _, guard = per_workload
    clock = Clock(T0)
    tf_main.WATCH_CLOCK = clock
    guard.raises = RuntimeError("guard db down")
    limit = T0 + 3 * tf_main.rd.WATCH_RETRY_S
    tf_main._run_watch(DISPATCH_ID, limit)
    assert len(tf_main.scheduled) == 1 and tf_main.scheduled[0][0] == tf_main.rd.WATCH_RETRY_S
    clock.t = limit
    tf_main._run_watch(DISPATCH_ID, limit)
    assert len(tf_main.scheduled) == 1                          # past the local limit: left to the sweep


@pytest.mark.parametrize("mode", [None, "PLATFORM"])
def test_shared_install_registers_schedules_and_sweeps_nothing(monkeypatch, tf_main, mode):
    if mode is not None:
        monkeypatch.setenv(MODE, mode)
    tf_main.WATCH_STORE_FACTORY = lambda: pytest.fail("a Shared install touched the watch store")
    tf_main.WATCH_SCHEDULER = lambda *a: pytest.fail("a Shared install scheduled a watch")
    monkeypatch.setattr(tf_main, "trigger_tf_applier_job", lambda req: True)
    assert _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK},
                 token=None).status_code == 202
    # SAT-41 HIGH-2 (c): the sweep itself is not mode-gated (tests/test_sat41_watch_sweep.py); on a Shared install
    # that never switched no sweeper thread is started, so nothing is swept.
    monkeypatch.setenv("STACKVEND_RUNNER_WATCH_SWEEP", "1")
    tf_main._start_watch_sweeper_on_per_workload_installs()
    assert tf_main._watch_sweeper_started is False


def test_malformed_dispatch_answer_without_a_dispatch_id_is_typed(per_workload):
    tf_main, vending, _ = per_workload
    vending.body.pop("dispatch_id")
    r = _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "callback_url": CALLBACK})
    assert r.status_code == 502 and r.json()["detail"]["cause"] == "MALFORMED_ANSWER"
    assert r.json()["detail"]["outcome_unknown"] is True and tf_main.scheduled == []


def test_the_server_runner_account_holds_the_callback_role_in_step_a():
    """The watcher's callback after step B is sent as sa-stackvend-tf-server: step A grants it the one-permission
    workflow-callback role (register "FD-7L-TF amendment: callback grant")."""
    import hcl2
    with open(os.path.join(os.path.dirname(__file__), "..", "infra", "platform", "tf_runner_identity.tf"),
              encoding="utf-8") as fh:
        doc = hcl2.load(fh)
    roles = [r["google_project_iam_member"]["tf_runner_project_roles"]["for_each"] for r in doc["resource"]
             if "tf_runner_project_roles" in r.get("google_project_iam_member", {})]
    assert roles and roles[0]["server-workflow-callback"] == {
        "role": "${google_project_iam_custom_role.stackvend_workflow_callback.id}",
        "member": "${local.tf_runner_server_member}"}


# ------------------------------------------------------------------------------------------------ SAT-27 RT L3
def test_one_brokered_runner_per_process(monkeypatch, base, tf_main):
    cls = type(tf_main.service)
    monkeypatch.setattr(cls, "_process_runner", None)
    a, b = MagicMock(), MagicMock()
    s1 = tf_main.service
    s2 = cls(project_id=HOST, state_bucket="", workspace_base_dir=base, firestore_client=MagicMock())
    reg = s1._register_workspace_runner(os.path.join(base, "t1"), a)
    reg2 = s1._register_workspace_runner(os.path.join(base, "t1", "x"), a)      # the same runner again: fine
    for svc in (s1, s2):
        with pytest.raises(tf_main.ri.RunnerIdentityError) as ei:
            svc._register_workspace_runner(os.path.join(base, "t2"), b)
        assert ei.value.code == "RUNNER_NOT_SINGLE_TENANT"
    s1._forget_workspace_runner(*reg2)
    assert cls._process_runner is a                                             # still held for t1
    s1._forget_workspace_runner(*reg)
    assert cls._process_runner is None
    s2._register_workspace_runner(os.path.join(base, "t2"), b)                 # free again
    assert cls._process_runner is b


def test_one_instance_forgetting_the_runner_never_frees_it_while_another_holds_it(monkeypatch, base, tf_main):
    """SAT-37 (SAT-27 RT L4): the guard is per process, so its release is too: two instances hold the same runner;
    the first one's forget leaves it held (a different runner is still refused); the last forget frees it."""
    cls = type(tf_main.service)
    monkeypatch.setattr(cls, "_process_runner", None)
    monkeypatch.setattr(cls, "_process_runner_holders", frozenset({(1, "stale")}))   # a stale set is reset
    a, b = MagicMock(), MagicMock()
    s1 = tf_main.service
    s2 = cls(project_id=HOST, state_bucket="", workspace_base_dir=base, firestore_client=MagicMock())
    reg1 = s1._register_workspace_runner(os.path.join(base, "t1"), a)
    reg2 = s2._register_workspace_runner(os.path.join(base, "t1"), a)          # same key, other instance
    s1._forget_workspace_runner(*reg1)
    assert cls._process_runner is a
    with pytest.raises(tf_main.ri.RunnerIdentityError) as ei:
        s1._register_workspace_runner(os.path.join(base, "t2"), b)
    assert ei.value.code == "RUNNER_NOT_SINGLE_TENANT"
    s1._forget_workspace_runner(*reg1)                                         # a repeated forget changes nothing
    assert cls._process_runner is a
    s2._forget_workspace_runner(*reg2)
    assert cls._process_runner is None and cls._process_runner_holders == frozenset()
    s1._register_workspace_runner(os.path.join(base, "t2"), b)
    assert cls._process_runner is b and s1._workspace_runner(os.path.join(base, "t2")) is b


# ------------------------------------------------------------------------------------------------ RT M2: real WatchStore
class _Snap:
    def __init__(self, doc_id, data):
        self.id, self._data = doc_id, data

    @property
    def exists(self):
        return self._data is not None

    def to_dict(self):
        return dict(self._data) if self._data is not None else None


class FakeFirestore:
    """Just enough of google-cloud-firestore for WatchStore: documents, create/set, a transaction whose create of an
    existing document fails at commit with AlreadyExists, and equality-filtered, id-ordered, paged queries."""

    def __init__(self):
        self.docs = {}
        self.before_commit = None
        self.queries = []

    def collection(self, name):
        assert name == "runner_dispatch_watches"
        return _Coll(self)

    def transaction(self):
        return _Txn(self)


class _Ref:
    def __init__(self, db, doc_id):
        self.db, self.id = db, doc_id

    def get(self, transaction=None):
        return _Snap(self.id, self.db.docs.get(self.id))

    def create(self, data):
        from google.api_core.exceptions import AlreadyExists
        if self.id in self.db.docs:
            raise AlreadyExists("exists")
        self.db.docs[self.id] = dict(data)

    def set(self, data, merge=False):
        self.db.docs[self.id] = dict(self.db.docs.get(self.id) or {}, **data) if merge else dict(data)


class _Txn:
    def __init__(self, db):
        self.db, self.ops = db, []

    def create(self, ref, data):
        self.ops.append(("create", ref, data))

    def update(self, ref, data):
        self.ops.append(("update", ref, data))

    def commit(self):
        # Re-check F4: Firestore reports a lost race on a document this transaction read as ABORTED (read-set
        # contention); that is the only error google-cloud-firestore's _Transactional retries.
        from google.api_core.exceptions import Aborted
        if self.db.before_commit is not None:
            hook, self.db.before_commit = self.db.before_commit, None
            hook()
        for op, ref, data in self.ops:
            if (op == "create" and ref.id in self.db.docs) or (op == "update" and ref.id not in self.db.docs):
                raise Aborted("read set changed")
        for op, ref, data in self.ops:
            self.db.docs[ref.id] = dict(self.db.docs.get(ref.id) or {}, **data)
        self.ops = []


class _Coll:
    def __init__(self, db, filt=None, order=None, lim=None, after=None):
        self.db, self.filt, self.order, self.lim, self.after = db, filt, order, lim, after

    def document(self, doc_id):
        return _Ref(self.db, doc_id)

    def where(self, *args, filter=None):
        assert not args and filter is not None, "positional where() is deprecated (RT L7)"
        return _Coll(self.db, filter, self.order, self.lim, self.after)

    def order_by(self, field):
        return _Coll(self.db, self.filt, field, self.lim, self.after)

    def limit(self, n):
        return _Coll(self.db, self.filt, self.order, n, self.after)

    def start_after(self, snap):
        return _Coll(self.db, self.filt, self.order, self.lim, snap.id)

    def stream(self):
        self.db.queries.append((self.filt.field_path, self.filt.op_string, self.filt.value, self.order, self.lim,
                                self.after))
        assert self.order == "__name__"
        ids = sorted(i for i, d in self.db.docs.items() if d.get(self.filt.field_path) == self.filt.value)
        if self.after is not None:
            ids = [i for i in ids if i > self.after]
        return [_Snap(i, self.db.docs[i]) for i in ids[:self.lim]]


@pytest.fixture
def real_store(monkeypatch, tf_main):
    from google.api_core.exceptions import Aborted
    import google.cloud.firestore as gcf

    def transactional(body):
        """Like google-cloud-firestore's _Transactional: re-run the body only on Aborted, at most MAX_ATTEMPTS (5)."""
        def run(txn):
            for attempt in range(5):
                txn.ops = []
                body(txn)
                try:
                    txn.commit()
                    return
                except Aborted:
                    if attempt == 4:
                        raise
        return run

    monkeypatch.setattr(gcf, "transactional", transactional)
    db = FakeFirestore()
    return tf_main.rd.WatchStore(db), db


def test_real_claim_moves_watching_to_sending_once(real_store):
    store, db = real_store
    db.docs[DISPATCH_ID] = {"state": "WATCHING"}
    assert store.claim(DISPATCH_ID, {"state": "SENDING", "claimed_at_epoch": 1.0}) is True
    assert db.docs[DISPATCH_ID]["state"] == "SENDING"
    assert store.claim(DISPATCH_ID, {"state": "SENDING"}) is False
    db.docs[DISPATCH_ID]["state"] = "SENT"
    assert store.claim(DISPATCH_ID, {"state": "SENDING"}) is False


def test_real_claim_creates_a_missing_watch(real_store):
    store, db = real_store
    assert store.claim(DISPATCH_ID, {"state": "SENDING"}) is True and db.docs[DISPATCH_ID] == {"state": "SENDING"}


def test_real_claim_loses_the_create_race_and_rereads(real_store):
    """Another instance creates the document between this read and this commit: the commit is ABORTED, the
    transaction re-runs, sees SENDING and returns False."""
    store, db = real_store
    db.before_commit = lambda: db.docs.__setitem__(DISPATCH_ID, {"state": "SENDING"})
    assert store.claim(DISPATCH_ID, {"state": "SENDING", "by": "me"}) is False
    assert db.docs[DISPATCH_ID] == {"state": "SENDING"}


def test_real_create_set_state_and_get(real_store):
    store, db = real_store
    store.create(DISPATCH_ID, {"state": "WATCHING", "a": 1})
    with pytest.raises(Exception):
        store.create(DISPATCH_ID, {"state": "WATCHING"})
    store.set_state(DISPATCH_ID, {"state": "SENT"})
    assert store.get(DISPATCH_ID) == {"state": "SENT", "a": 1} and store.get("f" * 64) is None


def test_real_pending_pages_by_document_id(real_store):
    """RT L1: every pending watch is returned, page by page in id order (no starvation behind the first page)."""
    store, db = real_store
    ids = [f"{i:064x}" for i in range(7)]
    for i in ids:
        db.docs[i] = {"state": "WATCHING"}
    db.docs["e" * 64] = {"state": "SENT"}
    assert store.pending(page_size=3) == ids
    assert [q[5] for q in db.queries] == [None, ids[2], ids[5]]
    assert all(q[:5] == ("state", "==", "WATCHING", "__name__", 3) for q in db.queries)
    db.queries.clear()
    assert len(store.pending(page_size=3, max_pages=2)) == 6 and len(db.queries) == 2      # bounded


def test_real_store_drives_the_watcher_end_to_end(kit, real_store):
    store, db = real_store
    w = kit.make(store)
    w.register(dispatch_id=DISPATCH_ID, execution=EXECUTION, product_id=PRODUCT, trace_id="t1")
    _after_window(kit)
    assert w.sweep() == {DISPATCH_ID: "SENT"} and len(kit.reports) == 1
    assert w.check(DISPATCH_ID) == "SENT" and kit.make(store).sweep() == {} and len(kit.reports) == 1


# ------------------------------------------------------------------------------------------------ RT L2 / L8 / L5
def test_a_redeem_that_commits_after_the_window_check_is_not_reported(kit):
    """L2: the first read says not redeemed; the redeem commits before the claim; the re-read after the claim sees
    it and nothing is sent."""
    key = (kit.ri.NONCE_COLLECTION, DISPATCH_ID)
    reads = {"n": 0}
    unredeemed, redeemed = _nonce_record(kit.ri), _nonce_record(kit.ri, redeemed=True)

    class Guard:
        def collection(self, name):
            return self

        def document(self, doc_id):
            return self

        def get(self):
            reads["n"] += 1
            snap = MagicMock()
            snap.exists = True
            snap.to_dict.return_value = unredeemed if reads["n"] == 1 else redeemed
            return snap

    kit.guard.docs.pop(key)
    w = kit.rd.DispatchWatcher(kit.store, guard_db=lambda: Guard(), expected_signer=lambda: fk.BROKER,
                               certs=fk.certs_for(), report=kit.reports.append, clock=kit.clock)
    _after_window(kit)
    assert w.check(DISPATCH_ID) == "REDEEMED" and not kit.reports and reads["n"] == 2
    assert kit.store.docs[DISPATCH_ID]["late_redeem"] is True


def test_reread_failure_after_the_claim_keeps_the_first_decision(kit):
    calls = {"n": 0}
    real = kit.guard

    def guard():
        calls["n"] += 1
        if calls["n"] > 1:
            raise RuntimeError("guard db down")
        return real

    w = kit.rd.DispatchWatcher(kit.store, guard_db=guard, expected_signer=lambda: fk.BROKER, certs=fk.certs_for(),
                               report=kit.reports.append, clock=kit.clock)
    _after_window(kit)
    assert w.check(DISPATCH_ID) == "SENT" and len(kit.reports) == 1


def test_a_stuck_sending_watch_is_logged_once_and_never_resent(kit, caplog):
    import logging
    kit.store.docs[DISPATCH_ID] = {"state": "SENDING", "claimed_at_epoch": T0, "claimed_at": _iso(T0),
                                   "product_id": PRODUCT, "trace_id": "t1", "execution": EXECUTION}
    kit.clock.t = T0 + kit.rd.WATCH_STUCK_SENDING_S - 1
    assert kit.w.report_stuck_sending() == []
    kit.clock.t = T0 + kit.rd.WATCH_STUCK_SENDING_S + 1
    with caplog.at_level(logging.ERROR):
        assert kit.w.sweep() == {}
    assert "RUNNER_WATCH_STUCK_SENDING" in caplog.text and kit.store.docs[DISPATCH_ID]["stuck_logged"] is True
    assert kit.w.report_stuck_sending() == [] and not kit.reports
    assert kit.store.docs[DISPATCH_ID]["state"] == "SENDING"


def test_id_token_certificates_are_cached(tf_main):
    """L5: Google's certificates are fetched once per 10 minutes, not per request; failures are not cached."""
    rd = tf_main.rd
    calls = []

    def inner(url, method="GET", headers=None, timeout=None, **kw):
        calls.append(url)
        resp = MagicMock()
        resp.status = 200 if len(calls) != 2 else 500
        return resp

    clock = Clock(0.0)
    req = rd.CachingCertsRequest(inner, clock=clock)
    first = req("https://www.googleapis.com/oauth2/v1/certs")
    assert req("https://www.googleapis.com/oauth2/v1/certs") is first and len(calls) == 1
    clock.t = rd.CERTS_CACHE_SECONDS + 1
    assert req("https://www.googleapis.com/oauth2/v1/certs").status == 500 and len(calls) == 2   # not cached
    assert req("https://www.googleapis.com/oauth2/v1/certs").status == 200 and len(calls) == 3
    req("https://x.example/", method="POST", body=b"{}")
    req("https://x.example/", method="POST", body=b"{}")
    assert calls[-2:] == ["https://x.example/", "https://x.example/"]                           # never cached
    import inspect
    assert "_CERTS_REQUEST" in inspect.getsource(rd.verify_google_id_token)


def test_certs_request_keeps_the_transport_default_timeout(tf_main):
    """Re-check F3: no timeout from the caller -> none is forwarded (google-auth's 120 s default applies); an explicit
    one is forwarded unchanged."""
    seen = []

    def inner(url, **kw):
        seen.append(kw)
        resp = MagicMock()
        resp.status = 500
        return resp

    req = tf_main.rd.CachingCertsRequest(inner)
    req("https://www.googleapis.com/oauth2/v1/certs")
    req("https://www.googleapis.com/oauth2/v1/certs", timeout=7)
    req("https://x.example/", method="POST", body=b"{}")
    assert "timeout" not in seen[0] and seen[1]["timeout"] == 7 and "timeout" not in seen[2]


def test_sweep_survives_a_failed_sending_listing(kit):
    """Re-check F6: decided watches stay decided when listing SENDING watches fails."""
    def boom(*a, **k):
        raise RuntimeError("firestore down")

    kit.store.sending = boom
    _after_window(kit)
    assert kit.w.sweep() == {DISPATCH_ID: "SENT"} and len(kit.reports) == 1
