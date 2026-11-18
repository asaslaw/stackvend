"""FD-4BZ: the developer stage's lane 11 facts provider and the architect stage allocate through ONE transactional
allocator (`shared.ipam.CastorIPAMEngine`, row IPAM-1), so their ranges can never overlap.

- the two paths racing (the architect's /28 connector vs. the developer's /24 subnet, the interleaving that could
  overlap before) get disjoint ranges; the loser really aborted and re-ran;
- the same workload and purpose racing across the two paths gets one record;
- the provider retries on contention, and fails typed (IPAM.CONTENTION / IPAM.POOL_EXHAUSTED) with nothing written;
- conflicts are classified by `.code == 409`, never by an exception's class name (Opus RT F6);
- the provider never touches the ledger itself (no stream/create/update/set/delete): only the engine does;
- Do No Harm: the provider's answers on a pinned sequence are the pre-FD-4BZ provider's answers; the engine's
  allocate_next_cidr record is unchanged (notes stays None); reuse_existing_cidr never writes a record.
All hermetic: tests/ipam_fake_firestore.py (in-memory, optimistic transactions), no network, no real client.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import inspect
import ipaddress
import itertools
import os
import sys
import textwrap
import threading

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for _p in (GATEWAY, REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from ipam_fake_firestore import FakeFirestore, fake_transactional  # noqa: E402

from developer_agent import platform_facts as PF  # noqa: E402
from developer_agent import stack_clients  # noqa: E402
from developer_agent.stack_clients import FirestoreFactsProvider  # noqa: E402
from shared.ipam import CastorIPAMEngine  # noqa: E402

POOL = PF.IpamPool(supernet="10.100.0.0/16", subnet_prefix=24, connector_prefix=28, region="us-central1")


def _ledger(db):
    return copy.deepcopy(db.store.get("cidr_allocations", {}))


def _provider(db, transactional=fake_transactional):
    return FirestoreFactsProvider(db, transactional=transactional)


def _architect(db, product, purpose=PF.PURPOSE_CONNECTOR, prefix_len=28):
    """The architect stage's call (architect_agent/handler.py): CastorIPAMEngine().allocate_next_cidr(...)."""
    eng = CastorIPAMEngine(db=db, supernet_cidr=POOL.supernet, transactional=fake_transactional)
    return eng.allocate_next_cidr(product_id=product, purpose=purpose, prefix_len=prefix_len, region=POOL.region)


def _developer(db, product, purposes):
    return _provider(db).resolve(product, set(purposes), pool=POOL, project_id=f"castor-{product}")


def _live_networks(db):
    return [(doc_id, ipaddress.ip_network(d["cidr_block"])) for doc_id, d in _ledger(db).items()
            if d.get("status") != "RELEASED"]


def _assert_pairwise_disjoint(db):
    nets = _live_networks(db)
    for (ia, a), (ib, b) in itertools.combinations(nets, 2):
        assert not a.overlaps(b), (ia, ib)


def _race(db, calls):
    """Each thread's first transactional ledger read waits until every thread has read once, so all of them choose
    from the same snapshot (the interleaving in which two unserialized allocators overlap)."""
    barrier = threading.Barrier(len(calls), timeout=10)
    seen = set()
    lock = threading.Lock()

    def after_read(coll, txn):
        if coll != "cidr_allocations" or txn is None:
            return
        me = threading.get_ident()
        with lock:
            first = me not in seen
            seen.add(me)
        if first:
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
    assert not any(t.is_alive() for t in threads)
    assert not errors, errors
    return results


# ---------------------------------------------------------------- the two paths are serialized


@pytest.mark.parametrize("architect_first", [True, False])
def test_architect_connector_and_developer_subnet_racing_never_overlap(architect_first):
    """Before FD-4BZ: architect -> 10.100.0.0/28 and developer -> 10.100.0.0/24 from the same empty snapshot."""
    db = FakeFirestore()
    calls = [lambda: _architect(db, "shop"), lambda: _developer(db, "shop", {PF.PURPOSE_SUBNET})]
    if not architect_first:
        calls.reverse()
    out = _race(db, calls)
    arch, dev = (out if architect_first else out[::-1])
    conn, sub = ipaddress.ip_network(arch.cidr_block), ipaddress.ip_network(dev.subnet_cidr)
    assert not conn.overlaps(sub)
    assert {conn.prefixlen, sub.prefixlen} == {28, 24}
    assert len(_ledger(db)) == 2
    _assert_pairwise_disjoint(db)
    assert sum(t.aborts for t in db.transactions) >= 1   # the loser conflicted and re-ran on the new ledger


def _interleave(db, first, second):
    """Run `first`; right after its first ledger read, run `second` to completion (it commits in between)."""
    state = {"fired": False}

    def after_read(coll, txn):
        if coll == "cidr_allocations" and not state["fired"]:
            state["fired"] = True
            state["second"] = second()

    db.after_read = after_read
    try:
        out = first()
    finally:
        db.after_read = None
    assert state["fired"]
    return out, state["second"]


def test_architect_commit_between_the_developers_read_and_write_never_overlaps():
    """The exact FD-4BZ interleaving, deterministic: the developer reads the empty ledger, the architect commits
    10.100.0.0/28, then the developer writes. Before FD-4BZ the developer created 10.100.0.0/24 (overlap)."""
    db = FakeFirestore()
    dev, arch = _interleave(db, lambda: _developer(db, "shop", {PF.PURPOSE_SUBNET}), lambda: _architect(db, "shop"))
    assert arch.cidr_block == "10.100.0.0/28" and dev.subnet_cidr == "10.100.1.0/24"
    _assert_pairwise_disjoint(db)
    assert sum(t.aborts for t in db.transactions) == 1   # the developer's first commit aborted, then it re-read


def test_developer_commit_between_the_architects_read_and_write_never_overlaps():
    db = FakeFirestore()
    arch, dev = _interleave(db, lambda: _architect(db, "shop"), lambda: _developer(db, "shop", {PF.PURPOSE_SUBNET}))
    assert dev.subnet_cidr == "10.100.0.0/24" and arch.cidr_block == "10.100.1.0/28"
    _assert_pairwise_disjoint(db)
    assert sum(t.aborts for t in db.transactions) == 1


def test_many_mixed_allocations_from_both_paths_are_pairwise_disjoint():
    db = FakeFirestore()
    calls = [lambda: _architect(db, "a"), lambda: _developer(db, "b", {PF.PURPOSE_SUBNET}),
             lambda: _architect(db, "c"), lambda: _developer(db, "d", {PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR})]
    _race(db, calls)
    assert sorted((d["product_id"], d["purpose"]) for d in _ledger(db).values()) == [
        ("a", PF.PURPOSE_CONNECTOR), ("b", PF.PURPOSE_SUBNET), ("c", PF.PURPOSE_CONNECTOR),
        ("d", PF.PURPOSE_CONNECTOR), ("d", PF.PURPOSE_SUBNET)]
    _assert_pairwise_disjoint(db)


def test_same_workload_and_purpose_across_the_two_paths_gets_one_record():
    db = FakeFirestore()
    arch, dev = _race(db, [lambda: _architect(db, "shop"), lambda: _developer(db, "shop", {PF.PURPOSE_CONNECTOR})])
    assert arch.cidr_block == dev.connector_cidr
    assert len(_ledger(db)) == 1


def test_developer_reuses_the_architects_range_without_a_write():
    db = FakeFirestore()
    arch = _architect(db, "shop")
    before = _ledger(db)
    f = _developer(db, "shop", {PF.PURPOSE_CONNECTOR})
    assert f.connector_cidr == arch.cidr_block and _ledger(db) == before


# ---------------------------------------------------------------- retries and typed errors


def test_provider_retries_on_contention_then_commits():
    db = FakeFirestore()
    db.abort_commits = 2
    f = _developer(db, "shop", {PF.PURPOSE_SUBNET})
    assert f.subnet_cidr == "10.100.0.0/24"
    assert sum(t.aborts for t in db.transactions) == 2 and db.commits == 1


def test_provider_contention_exhausted_is_typed_and_writes_nothing():
    db = FakeFirestore()
    db.abort_commits = 10 ** 6
    with pytest.raises(PF.FactsUnavailable, match=r"^IPAM\.CONTENTION"):
        _developer(db, "shop", {PF.PURPOSE_SUBNET})
    assert _ledger(db) == {} and db.commits == 0


def test_provider_pool_exhausted_is_typed_and_writes_nothing():
    db = FakeFirestore()
    tiny = PF.IpamPool(supernet="10.100.0.0/24", subnet_prefix=24, connector_prefix=28, region="us-central1")
    CastorIPAMEngine(db=db, supernet_cidr=tiny.supernet, transactional=fake_transactional).allocate_next_cidr(
        "other", purpose=PF.PURPOSE_SUBNET, prefix_len=24)
    before = _ledger(db)
    with pytest.raises(PF.FactsUnavailable, match=r"^IPAM\.POOL_EXHAUSTED"):
        _provider(db).resolve("shop", {PF.PURPOSE_SUBNET}, pool=tiny)
    assert _ledger(db) == before


def test_provider_read_error_is_typed_and_writes_nothing():
    db = FakeFirestore()
    db.read_error = RuntimeError("deadline exceeded")
    with pytest.raises(PF.FactsUnavailable, match=r"^IPAM\.UNAVAILABLE"):
        _developer(db, "shop", {PF.PURPOSE_SUBNET})
    assert _ledger(db) == {}


def test_unusable_pool_supernet_fails_closed():
    db = FakeFirestore()
    bad = PF.IpamPool(supernet="not-a-cidr", subnet_prefix=24, connector_prefix=28, region="us-central1")
    with pytest.raises(PF.FactsUnavailable, match=r"^IPAM\.UNAVAILABLE"):
        _provider(db).resolve("shop", {PF.PURPOSE_SUBNET}, pool=bad)
    assert _ledger(db) == {}


def _runner_raising_first(exc):
    """fake_transactional, except the first commit raises `exc` (as a Firestore commit RPC would)."""
    state = {"raised": False}

    def transactional(fn):
        inner = fake_transactional(fn)

        def run(transaction, *a, **k):
            if not state["raised"]:
                state["raised"] = True
                fn(transaction, *a, **k)
                raise exc
            return inner(transaction, *a, **k)
        return run
    return transactional


def test_conflict_is_classified_by_code_not_by_class_name():
    """Opus RT F6: the old provider retried on `type(e).__name__ in ("AlreadyExists", "Conflict")`."""
    class AlreadyExists(Exception):   # the name of a conflict, but no 409 code: not a conflict
        pass

    db = FakeFirestore()
    with pytest.raises(PF.FactsUnavailable, match=r"^IPAM\.UNAVAILABLE"):
        _provider(db, _runner_raising_first(AlreadyExists("x"))).resolve("shop", {PF.PURPOSE_SUBNET}, pool=POOL)
    assert _ledger(db) == {} and len(db.transactions) == 1   # not retried

    class SomethingElse(Exception):   # any name, 409 code: a conflict, re-read and retried
        code = 409

    db2 = FakeFirestore()
    f = _provider(db2, _runner_raising_first(SomethingElse("y"))).resolve("shop", {PF.PURPOSE_SUBNET}, pool=POOL)
    assert f.subnet_cidr == "10.100.0.0/24" and len(db2.transactions) == 2


def test_real_google_already_exists_is_retried():
    gexc = pytest.importorskip("google.api_core.exceptions")
    db = FakeFirestore()
    f = _provider(db, _runner_raising_first(gexc.AlreadyExists("taken"))).resolve(
        "shop", {PF.PURPOSE_SUBNET}, pool=POOL)
    assert f.subnet_cidr == "10.100.0.0/24" and len(db.transactions) == 2


# ---------------------------------------------------------------- structure: one allocator


def test_provider_never_touches_the_ledger_itself():
    """Every read and write of `cidr_allocations` from the developer stage goes through CastorIPAMEngine."""
    src = textwrap.dedent(inspect.getsource(stack_clients.FirestoreFactsProvider))
    tree = ast.parse(src)
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not attrs & {"stream", "create", "update", "set", "delete", "collection", "document", "__name__"}, attrs
    called = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert {"allocate_next_cidr", "reuse_existing_cidr"} <= called


# ---------------------------------------------------------------- Do No Harm


def test_provider_answers_on_a_pinned_sequence_are_unchanged():
    """Pinned from the pre-FD-4BZ provider (main 9e5d595) on the same inputs (no RELEASED records, whose
    semantics FD-4BZ aligns with the engine): same ranges, same record identities."""
    db = FakeFirestore()
    _architect(db, "a")   # the architect's connector, as in a real run
    prov = _provider(db)
    got = [
        prov.resolve("a", {PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR}, pool=POOL).variables(),
        prov.resolve("b", {PF.PURPOSE_CONNECTOR}, pool=POOL).variables(),
        prov.resolve("C", {PF.PURPOSE_SUBNET}, pool=POOL).variables(),
        prov.resolve("b", {PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR}, pool=POOL).variables(),
        prov.resolve("d", {PF.PURPOSE_SUBNET}, pool=POOL, allocate=False).variables(),
    ]
    assert got == [
        {"subnet_cidr": "10.100.1.0/24", "connector_cidr": "10.100.0.0/28"},
        {"connector_cidr": "10.100.0.16/28"},
        {"subnet_cidr": "10.100.2.0/24"},
        {"subnet_cidr": "10.100.3.0/24", "connector_cidr": "10.100.0.16/28"},
        {},
    ]
    assert sorted(_ledger(db)) == ["10_100_0_0_28", "10_100_0_16_28", "10_100_1_0_24", "10_100_2_0_24",
                                   "10_100_3_0_24"]
    _assert_pairwise_disjoint(db)


def test_engine_allocate_record_is_unchanged_without_notes():
    db = FakeFirestore()
    rec = CastorIPAMEngine(db=db, supernet_cidr=POOL.supernet, transactional=fake_transactional) \
        .allocate_next_cidr("shop", purpose=PF.PURPOSE_CONNECTOR, prefix_len=28)
    assert rec.notes is None and _ledger(db)["10_100_0_0_28"]["notes"] is None


def test_engine_reuse_existing_cidr_never_creates():
    db = FakeFirestore()
    eng = CastorIPAMEngine(db=db, supernet_cidr=POOL.supernet, transactional=fake_transactional)
    assert eng.reuse_existing_cidr("shop", purpose=PF.PURPOSE_SUBNET) is None
    assert _ledger(db) == {} and len(db.transactions) == 1   # read in a transaction, nothing written
    eng.allocate_next_cidr("shop", purpose=PF.PURPOSE_SUBNET, prefix_len=24)
    before = _ledger(db)
    assert eng.reuse_existing_cidr("shop", purpose=PF.PURPOSE_SUBNET).cidr_block == "10.100.0.0/24"
    assert _ledger(db) == before
    db.store["cidr_allocations"]["10_100_0_0_24"]["status"] = "RESERVED_DECOMMISSIONED"
    rec = eng.reuse_existing_cidr("shop", purpose=PF.PURPOSE_SUBNET, project_id="castor-shop-2")
    assert rec.cidr_block == "10.100.0.0/24"
    stored = _ledger(db)["10_100_0_0_24"]
    assert (stored["status"], stored["project_id"]) == ("ALLOCATED", "castor-shop-2")
    db.store["cidr_allocations"]["10_100_0_0_24"]["status"] = "RELEASED"
    assert eng.reuse_existing_cidr("shop", purpose=PF.PURPOSE_SUBNET) is None
    assert _ledger(db)["10_100_0_0_24"]["status"] == "RELEASED"
