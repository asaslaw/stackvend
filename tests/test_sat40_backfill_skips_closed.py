"""SAT-40 section 10 (vending `RunnerIdentityBackfill.run`): a backfill run that names no workloads (the Control
Center card's "Dry run") no longer stops with 503 once a decommissioned workload's project is purged.

Before: every provenance record was a target; for a purged project `projects.get` answers 403 -> CRM_UNAVAILABLE ->
RUNNER_STORE_UNAVAILABLE (a configuration error), so the whole run stopped with 503.
After: without product_ids, a record whose ledger status (`workloads/{pid}.status`) is exactly DECOMMISSIONED,
ARCHIVED or DELETED is listed as SKIPPED_CLOSED with no Google call; it does not count against `max`. Named workloads
(product_ids), other statuses and an unreadable / missing ledger record are processed exactly as before.
Hermetic fakes only.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import pytest

from test_fd7l_phase3_backfill import NUMBER, PID, W, rib, ri  # noqa: F401

GONE = "gone-1"
GONE_NUMBER = "987654321"   # not in the fake Resource Manager: projects.get answers 403, as for a purged project


@pytest.fixture
def w():
    return W()


def _add(world, pid, status=..., ledger=True, number=GONE_NUMBER):
    world.db.docs[f"workload_provenance/{pid}"] = {"created_by": "stackvend-vending",
                                                    "project_id": f"{pid}-proj", "project_number": number}
    if ledger:
        doc = {"product_id": pid, "project_id": f"{pid}-proj"}
        if status is not ...:
            doc["status"] = status
        world.db.docs[f"workloads/{pid}"] = doc


def _crm_calls_for(world, number):
    return [c for c in world.crm.calls if number in c[1:]]


def _rows(out):
    return {r["product_id"]: r for r in out["results"]}


def test_a_purged_closed_project_stopped_the_named_run_with_503(w):
    """The defect's mechanism, unchanged for a named workload: the purged project's 403 is a configuration error."""
    _add(w, GONE, "DECOMMISSIONED")
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.backfill().run("cc", dry_run=True, product_ids=[GONE], max_items=1)
    assert e.value.code == "RUNNER_STORE_UNAVAILABLE" and e.value.http_status == 503


@pytest.mark.parametrize("status", sorted(rib.CLOSED_WORKLOAD_STATUSES))
def test_the_full_dry_run_skips_a_closed_workload_without_any_google_call(w, status):
    _add(w, GONE, status)
    out = w.backfill().run("cc")
    rows = _rows(out)
    assert rows[GONE]["outcome"] == rib.SKIPPED_CLOSED == "SKIPPED_CLOSED"
    assert rows[GONE]["workload_status"] == status and rows[GONE]["error_class"] is None
    assert rows[GONE]["calls"] == []
    assert rows[PID]["outcome"] == "DRY_RUN"
    assert out["counts"] == {"DRY_RUN": 1, "SKIPPED_CLOSED": 1}
    assert _crm_calls_for(w, GONE_NUMBER) == []
    assert not [c for c in w.google.calls if f"{GONE}-proj" in str(c)]
    assert w.db.writes == [] and w.google.mutating() == [] and w.crm.mutating_calls() == []


def test_the_live_rows_are_byte_identical_to_a_run_without_the_closed_record():
    base = W()
    expected = base.backfill().run("cc")
    w = W()
    _add(w, GONE, "DECOMMISSIONED")
    out = w.backfill().run("cc")
    assert [r for r in out["results"] if r["product_id"] != GONE] == expected["results"]
    assert out["truncated"] == expected["truncated"] and out["steps"] == expected["steps"]


def test_no_closed_record_gives_todays_result(w):
    """Do No Harm: an install without closed workloads gets the same answer as a run naming every workload."""
    _add(w, "live-2", "DEPLOYED", number=NUMBER)
    swept = w.backfill().run("cc")
    named = W()
    _add(named, "live-2", "DEPLOYED", number=NUMBER)
    every = [pid for pid, _ in named.deps.store.list_provenance()]   # the sweep's own order
    assert sorted(every) == sorted([PID, "live-2"])
    assert swept == named.backfill().run("cc", product_ids=every)
    assert rib.SKIPPED_CLOSED not in swept["counts"]


def test_closed_records_do_not_count_against_max(w):
    for i in range(3):
        _add(w, f"gone-{i}", "ARCHIVED")
    out = w.backfill().run("cc", max_items=1)
    assert [r["product_id"] for r in out["results"] if r["outcome"] != rib.SKIPPED_CLOSED] == [PID]
    assert out["counts"] == {"DRY_RUN": 1, "SKIPPED_CLOSED": 3} and out["truncated"] is False


@pytest.mark.parametrize("status", ["decommissioned", "DECOMMISSION_REQUESTED", "DECOMMISSION_FAILED", "DEPLOYED",
                                    " ARCHIVED", "FAILED", None, "", 7])
def test_any_other_ledger_status_is_processed_as_before(w, status):
    """Exact values only (invariant 2): a purged project whose ledger is not closed still stops the run loudly."""
    _add(w, GONE, status)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.backfill().run("cc")
    assert e.value.code == "RUNNER_STORE_UNAVAILABLE"


def test_a_missing_or_unreadable_ledger_record_is_never_assumed_closed(w):
    _add(w, GONE, ledger=False)   # processed: the identity check refuses it per row (ledger missing), as before
    row = _rows(w.backfill().run("cc"))[GONE]
    assert row["outcome"] == "FAILED" and row["error_class"] == "BACKFILL.IDENTITY_UNVERIFIED"
    w2 = W()
    _add(w2, GONE, "DECOMMISSIONED")
    w2.db.fail_paths.add(f"workloads/{GONE}")
    with pytest.raises(ri.RunnerIdentityError) as e:
        w2.backfill().run("cc")
    assert e.value.code == "RUNNER_STORE_UNAVAILABLE"


def test_a_named_closed_workload_is_still_processed(w):
    """product_ids are unchanged: a closed workload whose project still exists gets its per-row result."""
    _add(w, GONE, "DECOMMISSIONED", number=NUMBER)   # an existing project: projects.get answers
    out = w.backfill().run("cc", product_ids=[GONE], max_items=1)
    (row,) = out["results"]
    assert row["product_id"] == GONE and row["outcome"] != rib.SKIPPED_CLOSED


def test_a_real_run_still_needs_product_ids(w):
    _add(w, GONE, "DECOMMISSIONED")
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.backfill().run("cc", dry_run=False)
    assert e.value.code == "BACKFILL.REAL_RUN_TOO_LARGE"
