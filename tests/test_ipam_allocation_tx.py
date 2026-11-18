"""Row IPAM-1 (Fable RT F5, docs/planning/fd-csql-code-red-team-fable.md): IPAM allocation is atomic and fails typed.

- concurrent allocations (two workloads racing) get distinct ranges and neither ledger record is overwritten;
- a ledger read error raises IPAMUnavailable (never treated as an empty ledger), from allocate_next_cidr and
  list_allocations alike, and nothing is written;
- a workload's existing allocation for the same purpose is reused (idempotent, also under a race);
- Do No Harm: a single allocation on the happy path returns the same range as the pre-transaction engine;
- the real google-cloud-firestore `transactional` runner drives the engine (re-runs on Aborted, typed contention);
- the architect caller no longer substitutes a fallback CIDR literal.
All hermetic: an in-memory Firestore fake (tests/ipam_fake_firestore.py), no network, no real client.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import inspect
import os
import threading

import pytest

from ipam_fake_firestore import FakeAborted, FakeFirestore, fake_transactional

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPLICAS = [
    "shared/ipam.py",
    "apps/control-center/shared/ipam.py",
    "apps/orchestrator-gateway/shared/ipam.py",
    "apps/project-vending/shared/ipam.py",
    "mcp-servers/terraform/shared/ipam.py",
]


def _load(rel):
    name = "ipam_tx_" + rel.replace("/", "_").replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO_ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ipam = _load("shared/ipam.py")


def _engine(db, **kw):
    return ipam.CastorIPAMEngine(db=db, supernet_cidr="10.100.0.0/16", transactional=fake_transactional, **kw)


def _ledger(db):
    return db.store.get("cidr_allocations", {})


def test_replicas_are_byte_identical():
    blobs = {rel: open(os.path.join(REPO_ROOT, rel), "rb").read() for rel in REPLICAS}
    assert len(set(blobs.values())) == 1, sorted(blobs)


# ---------------------------------------------------------------- Do No Harm: same answers as before


@pytest.mark.parametrize("rel", REPLICAS)
def test_happy_path_single_allocation_is_unchanged(rel):
    mod = _load(rel)
    db = FakeFirestore()
    rec = mod.CastorIPAMEngine(db=db, supernet_cidr="10.100.0.0/16", transactional=fake_transactional) \
        .allocate_next_cidr("Payment-Service", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28)
    # pre-transaction engine: first free /28 of the supernet, record keyed by the sanitized range
    assert rec.cidr_block == "10.100.0.0/28" and rec.product_id == "payment-service"
    assert list(_ledger(db)) == ["10_100_0_0_28"]
    stored = _ledger(db)["10_100_0_0_28"]
    assert stored["product_id"] == "payment-service" and stored["status"] == "ALLOCATED"
    assert stored["network_name"] == "vpc-payment-service" and stored["subnet_name"] == "sb-payment-service-connector"
    assert db.commits == 1


def test_mixed_prefix_sequence_matches_pre_transaction_engine():
    """Sequence pinned from the pre-transaction engine (origin/main d51bed4) on the same inputs."""
    db = FakeFirestore()
    eng = _engine(db)
    got = [
        eng.allocate_next_cidr("a", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28).cidr_block,
        eng.allocate_next_cidr("a", purpose="WORKLOAD_SUBNET", prefix_len=24).cidr_block,
        eng.allocate_next_cidr("b", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28).cidr_block,
        eng.allocate_next_cidr("c", purpose="WORKLOAD_SUBNET", prefix_len=24).cidr_block,
    ]
    assert got == ["10.100.0.0/28", "10.100.1.0/24", "10.100.0.16/28", "10.100.2.0/24"]


def test_workload_network_metadata_still_updated_after_commit():
    db = FakeFirestore()
    db.store["workloads"] = {"shop": {"name": "shop"}}
    _engine(db).allocate_next_cidr("shop", purpose="WORKLOAD_SUBNET", prefix_len=24)
    net = db.store["workloads"]["shop"]["network"]
    assert net == {"subnet_cidr": "10.100.0.0/24", "subnet_name": "sb-shop-primary", "vpc_name": "vpc-shop",
                   "status": "ALLOCATED"}


# ---------------------------------------------------------------- atomicity under concurrency


def _race(db, calls):
    """Run the allocations in threads; each thread's first ledger read waits until every thread has read once, so
    all of them choose from the same snapshot (the interleaving that double-allocated before)."""
    barrier = threading.Barrier(len(calls), timeout=10)
    seen = set()

    def after_read(coll, txn):
        if coll != "cidr_allocations" or txn is None:
            return
        me = threading.get_ident()
        if me not in seen:
            seen.add(me)
            barrier.wait()

    db.after_read = after_read
    results, errors = [None] * len(calls), []

    def run(i, fn):
        try:
            results[i] = fn()
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=run, args=(i, fn)) for i, fn in enumerate(calls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    db.after_read = None
    assert not errors, errors
    return results


def test_concurrent_allocations_get_distinct_ranges_and_no_record_is_overwritten():
    db = FakeFirestore()
    eng = _engine(db)
    a, b = _race(db, [lambda: eng.allocate_next_cidr("workload-a", purpose="WORKLOAD_SUBNET", prefix_len=24),
                      lambda: eng.allocate_next_cidr("workload-b", purpose="WORKLOAD_SUBNET", prefix_len=24)])
    assert {a.cidr_block, b.cidr_block} == {"10.100.0.0/24", "10.100.1.0/24"}
    ledger = _ledger(db)
    assert len(ledger) == 2
    assert {d["product_id"] for d in ledger.values()} == {"workload-a", "workload-b"}
    assert ledger[a.sanitized_id]["product_id"] == "workload-a"
    assert ledger[b.sanitized_id]["product_id"] == "workload-b"
    assert sum(t.aborts for t in db.transactions) >= 1   # the loser really conflicted and re-ran


def test_many_concurrent_allocations_are_pairwise_disjoint():
    db = FakeFirestore()
    eng = _engine(db)
    n = 4
    recs = _race(db, [lambda i=i: eng.allocate_next_cidr(f"w{i}", prefix_len=28) for i in range(n)])
    blocks = [r.cidr_block for r in recs]
    assert len(set(blocks)) == n and len(_ledger(db)) == n


def test_same_workload_racing_itself_gets_one_record():
    db = FakeFirestore()
    eng = _engine(db)
    x, y = _race(db, [lambda: eng.allocate_next_cidr("shop", purpose="WORKLOAD_SUBNET", prefix_len=24),
                      lambda: eng.allocate_next_cidr("shop", purpose="WORKLOAD_SUBNET", prefix_len=24)])
    assert x.cidr_block == y.cidr_block == "10.100.0.0/24"
    assert list(_ledger(db)) == ["10_100_0_0_24"]


def test_create_never_overwrites_a_record_written_outside_the_transaction():
    """A writer that bypasses the transaction (e.g. a plain create()) takes the chosen block between our read and
    commit: our create() fails AlreadyExists, the allocation re-reads and takes the next block; theirs survives."""
    db = FakeFirestore()
    eng = _engine(db)
    state = {"done": False}

    def intruder(coll, txn):
        if coll == "cidr_allocations" and txn is not None and not state["done"]:
            state["done"] = True
            bucket = db.store.setdefault("cidr_allocations", {})
            bucket["10_100_0_0_28"] = {"cidr_block": "10.100.0.0/28", "sanitized_id": "10_100_0_0_28",
                                       "product_id": "intruder", "purpose": "SERVERLESS_VPC_CONNECTOR",
                                       "status": "ALLOCATED"}   # no version bump: only create()'s precondition catches it

    db.after_read = intruder
    rec = eng.allocate_next_cidr("mine", prefix_len=28)
    assert rec.cidr_block == "10.100.0.16/28"
    assert _ledger(db)["10_100_0_0_28"]["product_id"] == "intruder"
    assert _ledger(db)["10_100_0_16_28"]["product_id"] == "mine"


def test_contention_is_bounded_and_typed():
    db = FakeFirestore()
    db.abort_commits = 10 ** 6   # every commit aborts
    with pytest.raises(ipam.IPAMContention) as ei:
        _engine(db).allocate_next_cidr("w", prefix_len=28)
    assert str(ei.value).startswith("IPAM.CONTENTION")
    assert _ledger(db) == {}
    assert len(db.transactions) == 1 and db.transactions[0].aborts == ipam.CastorIPAMEngine.MAX_TRANSACTION_ATTEMPTS


def test_repeated_create_conflicts_are_bounded_and_typed():
    db = FakeFirestore()

    def always_take_it(coll, txn):
        if coll == "cidr_allocations" and txn is not None:
            # someone keeps creating the next free /28 outside the transaction
            bucket = db.store.setdefault("cidr_allocations", {})
            i = len(bucket)
            cidr = f"10.100.0.{16 * i}/28"
            sid = cidr.replace(".", "_").replace("/", "_")
            bucket[sid] = {"cidr_block": cidr, "sanitized_id": sid, "product_id": f"x{i}", "status": "ALLOCATED"}

    db.after_read = always_take_it
    with pytest.raises(ipam.IPAMContention):
        _engine(db).allocate_next_cidr("w", prefix_len=28)
    assert all(d["product_id"] != "w" for d in _ledger(db).values())
    assert len(db.transactions) == ipam.CastorIPAMEngine.MAX_TRANSACTION_ATTEMPTS


# ---------------------------------------------------------------- read errors are typed, never "empty"


def test_read_error_raises_typed_error_and_writes_nothing():
    db = FakeFirestore()
    _engine(db).allocate_next_cidr("existing", prefix_len=28)          # ledger already holds 10.100.0.0/28
    db.read_error = RuntimeError("firestore unavailable")
    with pytest.raises(ipam.IPAMUnavailable) as ei:
        _engine(db).allocate_next_cidr("newcomer", prefix_len=28)
    assert str(ei.value).startswith("IPAM.UNAVAILABLE") and "firestore unavailable" in str(ei.value)
    assert list(_ledger(db)) == ["10_100_0_0_28"] and _ledger(db)["10_100_0_0_28"]["product_id"] == "existing"


def test_list_allocations_read_error_raises_instead_of_empty():
    db = FakeFirestore()
    db.read_error = RuntimeError("deadline exceeded")
    eng = _engine(db)
    with pytest.raises(ipam.IPAMUnavailable):
        eng.list_allocations()
    with pytest.raises(ipam.IPAMUnavailable):
        eng.get_pool_statistics()
    with pytest.raises(ipam.IPAMUnavailable):
        eng.check_overlap("10.100.0.0/28")


def test_no_client_raises_instead_of_an_unrecorded_range():
    with pytest.raises(ipam.IPAMUnavailable):
        ipam.CastorIPAMEngine(db=None).allocate_next_cidr("w")
    assert ipam.CastorIPAMEngine(db=None).list_allocations() == []   # no ledger configured: nothing to list


def test_client_that_raises_on_collection_fails_typed():
    """The fd-csql Express caller's broken-client case: collection() itself raises -> a typed error, not raw."""
    class BrokenDb:
        def collection(self, name):
            raise RuntimeError("firestore down")

    with pytest.raises(ipam.IPAMUnavailable):
        _engine(BrokenDb()).allocate_next_cidr("w")


def test_client_without_transaction_support_fails_closed():
    class NoTxnDb:
        def collection(self, name):
            return FakeFirestore().collection(name)

    with pytest.raises(ipam.IPAMUnavailable):
        _engine(NoTxnDb()).allocate_next_cidr("w")


def test_unparseable_live_range_is_ledger_corrupt_not_skipped():
    db = FakeFirestore()
    db.store["cidr_allocations"] = {"bad": {"cidr_block": "10.100.0.0/33", "product_id": "x", "status": "ALLOCATED"}}
    with pytest.raises(ipam.IPAMLedgerCorrupt):
        _engine(db).allocate_next_cidr("w", prefix_len=28)
    assert list(_ledger(db)) == ["bad"]


def test_pool_exhausted_is_typed_and_still_a_value_error():
    db = FakeFirestore()
    eng = ipam.CastorIPAMEngine(db=db, supernet_cidr="10.100.0.0/28", transactional=fake_transactional)
    eng.allocate_next_cidr("one", prefix_len=28)
    with pytest.raises(ipam.IPAMPoolExhausted) as ei:
        eng.allocate_next_cidr("two", prefix_len=28)
    assert isinstance(ei.value, ValueError) and isinstance(ei.value, ipam.IPAMError)


# ---------------------------------------------------------------- idempotent reuse


def test_existing_allocation_is_reused_without_a_write():
    db = FakeFirestore()
    eng = _engine(db)
    first = eng.allocate_next_cidr("shop", purpose="WORKLOAD_SUBNET", prefix_len=24)
    before = dict(_ledger(db)[first.sanitized_id])
    again = eng.allocate_next_cidr("SHOP ", purpose="WORKLOAD_SUBNET", prefix_len=24)
    assert again.cidr_block == first.cidr_block and len(_ledger(db)) == 1
    assert _ledger(db)[first.sanitized_id] == before
    other_purpose = eng.allocate_next_cidr("shop", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28)
    assert other_purpose.cidr_block == "10.100.1.0/28" and len(_ledger(db)) == 2


def test_decommissioned_allocation_is_reclaimed_in_the_transaction():
    db = FakeFirestore()
    eng = _engine(db)
    rec = eng.allocate_next_cidr("shop", prefix_len=28)
    assert eng.mark_workload_decommissioned("shop") == 1
    back = eng.allocate_next_cidr("shop", prefix_len=28, project_id="shop-v2")
    assert back.cidr_block == rec.cidr_block
    stored = _ledger(db)[rec.sanitized_id]
    assert stored["status"] == "ALLOCATED" and stored["project_id"] == "shop-v2" and len(_ledger(db)) == 1


def test_released_history_record_does_not_block_its_range():
    """RELEASED records are free (as before); the new allocation replaces the history document it read."""
    db = FakeFirestore()
    db.store["cidr_allocations"] = {"10_100_0_0_28": {"cidr_block": "10.100.0.0/28", "product_id": "old",
                                                      "status": "RELEASED"}}
    rec = _engine(db).allocate_next_cidr("new", prefix_len=28)
    assert rec.cidr_block == "10.100.0.0/28" and _ledger(db)["10_100_0_0_28"]["product_id"] == "new"


# ---------------------------------------------------------------- the real google-cloud-firestore runner


def _real_transactional_or_skip():
    try:
        from google.api_core import exceptions as gexc
        from google.cloud.firestore_v1.transaction import transactional
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"google-cloud-firestore not importable: {e}")
    if not inspect.isfunction(transactional) or not isinstance(gexc.Aborted, type):
        pytest.skip("google-cloud-firestore is replaced by a mock in this process")
    return transactional, gexc


class _RealProtocolTxn:
    """The private surface google.cloud.firestore_v1.transaction._Transactional drives, over the fake's buffering."""

    def __init__(self, fake_txn, aborted_cls, abort_first):
        self._fake, self._aborted, self._abort_left = fake_txn, aborted_cls, abort_first
        self._max_attempts, self._read_only, self._id = fake_txn._max_attempts, False, None
        self.read_versions = fake_txn.read_versions
        self.begun = self.rolled_back = 0

    def set(self, ref, data, merge=False):
        self._fake.set(ref, data, merge)

    def create(self, ref, data):
        self._fake.create(ref, data)

    def _clean_up(self):
        self._fake._reset()
        self.read_versions = self._fake.read_versions
        self._id = None

    def _begin(self, retry_id=None):
        self.begun += 1
        self._id = b"txn-%d" % self.begun

    def _commit(self):
        if self._abort_left:
            self._abort_left -= 1
            raise self._aborted("contention")
        try:
            self._fake._commit()
        except FakeAborted as e:
            raise self._aborted(str(e))

    def _rollback(self):
        self.rolled_back += 1


def _real_db(gexc, abort_first):
    db = FakeFirestore()
    made = []

    def transaction(max_attempts=5):
        t = _RealProtocolTxn(FakeFirestore.transaction(db, max_attempts), gexc.Aborted, abort_first)
        made.append(t)
        return t

    db.transaction = transaction
    return db, made


def test_real_firestore_runner_retries_aborted_then_commits():
    transactional, gexc = _real_transactional_or_skip()
    db, made = _real_db(gexc, abort_first=2)
    rec = ipam.CastorIPAMEngine(db=db, transactional=transactional).allocate_next_cidr("w", prefix_len=28)
    assert rec.cidr_block == "10.100.0.0/28" and list(_ledger(db)) == ["10_100_0_0_28"]
    assert made[0].begun == 3


def test_real_firestore_runner_contention_exhausted_is_typed():
    transactional, gexc = _real_transactional_or_skip()
    db, made = _real_db(gexc, abort_first=10 ** 6)
    with pytest.raises(ipam.IPAMContention):
        ipam.CastorIPAMEngine(db=db, transactional=transactional).allocate_next_cidr("w", prefix_len=28)
    assert _ledger(db) == {} and made[0].begun == ipam.CastorIPAMEngine.MAX_TRANSACTION_ATTEMPTS
    assert made[0].rolled_back == 1


def test_real_firestore_runner_already_exists_rereads_and_takes_the_next_block():
    transactional, gexc = _real_transactional_or_skip()
    db, made = _real_db(gexc, abort_first=0)
    state = {"done": False}

    def intruder(coll, txn):
        if coll == "cidr_allocations" and txn is not None and not state["done"]:
            state["done"] = True
            db.store.setdefault("cidr_allocations", {})["10_100_0_0_28"] = {
                "cidr_block": "10.100.0.0/28", "product_id": "intruder", "status": "ALLOCATED"}

    db.after_read = intruder
    # the fake raises its own AlreadyExists (code 409, like google.api_core.exceptions.AlreadyExists)
    rec = ipam.CastorIPAMEngine(db=db, transactional=transactional).allocate_next_cidr("mine", prefix_len=28)
    assert rec.cidr_block == "10.100.0.16/28" and _ledger(db)["10_100_0_0_28"]["product_id"] == "intruder"
    assert gexc.AlreadyExists.code == gexc.Aborted.code == ipam._CONFLICT_HTTP_STATUS


class _RollbackFails(_RealProtocolTxn):
    """The real runner rolls back on every error; here the rollback RPC itself fails (RT F4), which makes Python
    raise the rollback error with the original error only as __context__."""

    def _rollback(self):
        self.rolled_back += 1
        raise RuntimeError("rollback rejected: transaction already failed")


def _real_db_rollback_fails(gexc, abort_first):
    db = FakeFirestore()
    made = []

    def transaction(max_attempts=5):
        t = _RollbackFails(FakeFirestore.transaction(db, max_attempts), gexc.Aborted, abort_first)
        made.append(t)
        return t

    db.transaction = transaction
    return db, made


def test_failed_rollback_does_not_mask_already_exists_retry():
    transactional, gexc = _real_transactional_or_skip()
    db, made = _real_db_rollback_fails(gexc, abort_first=0)
    state = {"done": False}

    def intruder(coll, txn):
        if coll == "cidr_allocations" and txn is not None and not state["done"]:
            state["done"] = True
            db.store.setdefault("cidr_allocations", {})["10_100_0_0_28"] = {
                "cidr_block": "10.100.0.0/28", "product_id": "intruder", "status": "ALLOCATED"}

    db.after_read = intruder
    rec = ipam.CastorIPAMEngine(db=db, transactional=transactional).allocate_next_cidr("mine", prefix_len=28)
    assert rec.cidr_block == "10.100.0.16/28" and made[0].rolled_back == 1 and len(made) == 2
    assert _ledger(db)["10_100_0_0_28"]["product_id"] == "intruder"


def test_failed_rollback_does_not_mask_contention():
    transactional, gexc = _real_transactional_or_skip()
    db, made = _real_db_rollback_fails(gexc, abort_first=10 ** 6)
    with pytest.raises(ipam.IPAMContention):
        ipam.CastorIPAMEngine(db=db, transactional=transactional).allocate_next_cidr("w", prefix_len=28)
    assert _ledger(db) == {} and len(made) == 1 and made[0].rolled_back == 1


def test_failed_rollback_does_not_mask_a_typed_error_from_the_allocation():
    transactional, gexc = _real_transactional_or_skip()
    db, _made = _real_db_rollback_fails(gexc, abort_first=0)
    db.store["cidr_allocations"] = {"10_100_0_0_28": {"cidr_block": "10.100.0.0/28", "product_id": "x",
                                                      "status": "ALLOCATED"}}
    eng = ipam.CastorIPAMEngine(db=db, supernet_cidr="10.100.0.0/28", transactional=transactional)
    with pytest.raises(ipam.IPAMPoolExhausted):
        eng.allocate_next_cidr("w", prefix_len=28)


def test_failed_rollback_after_an_unrelated_error_is_unavailable(monkeypatch):
    """Negative: a rollback failure over a plain error stays IPAMUnavailable (never a retry or a success)."""
    transactional, gexc = _real_transactional_or_skip()
    db, made = _real_db_rollback_fails(gexc, abort_first=0)

    def boom(self, ref, data):
        raise RuntimeError("serialization failed")

    monkeypatch.setattr(_RollbackFails, "create", boom)
    with pytest.raises(ipam.IPAMUnavailable):
        ipam.CastorIPAMEngine(db=db, transactional=transactional).allocate_next_cidr("w", prefix_len=28)
    assert _ledger(db) == {} and len(made) == 1


def test_default_runner_is_the_real_firestore_decorator():
    transactional, _gexc = _real_transactional_or_skip()
    assert ipam._default_transactional() is transactional


# ---------------------------------------------------------------- callers: typed failure, no fallback literal


ARCHITECT = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "architect_agent", "handler.py")


def test_architect_has_no_fallback_cidr_literal():
    src = open(ARCHITECT).read()
    tree = ast.parse(src)
    literals = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert not [s for s in literals if s.strip() == "10.100.1.0/28"]
    assert "assigned_cidr = None" in src and "plan.assigned_cidr_block = None" in src
