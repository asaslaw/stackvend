"""
FD-7L Phase 3, vending side (apps/project-vending/runner_identity_backfill.py, vending.py decommission, main.py routes).
Hermetic fakes only (fd7l_fakes + fd7l_gcs_fakes).

* Shared install (PLATFORM): status answers the mode with zero reads; the backfill refuses before any read or write;
  a decommission is byte-identical to today's.
* Per workload: dry run writes nothing and lists every call; the backfill provisions, then migrates state byte-exactly
  (oldest first, last 20 noncurrent versions + live, chained preconditions, source metadata, crc32c / serial / lineage),
  resumes from the cursor after a crash, refuses busy / locked / racing / conflicting states with typed classes, writes
  a tombstone; restore and purge (owner); decommission archives before the delete and stops when the archive fails.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import destructive_guard_fakes as f
import fd7l_fakes as k
import fd7l_gcs_fakes as g
from test_destructive_guard_vending import VENDING_MAIN, FakeStorage, fake_verifier, TOKENS, AUD as DG_AUD  # noqa: F401
from test_fd7l_vending_runner_identity import World, _config  # noqa: F401

_G = VENDING_MAIN.ProjectRepoVendingEngine.vend_gcp_project.__globals__
rb = _G["rb"]
ri = _G["ri"]
rib = _G["rib"]
VDG = _G["dg"]

PID, PROJECT, NUMBER = f.PID, f.PROJECT, f.NUMBER
PLATFORM_BUCKET = "castor-tfstate-test"
CHILD_BUCKET = f"{PROJECT}-tfstate"
OBJ = f"workloads/{PID}/default.tfstate"
LOCK = f"workloads/{PID}/default.tflock"


REPO_FULL_NAME = "acme/shop-api"
WORKLOAD_REPO = {"github_repo": REPO_FULL_NAME, "vcs_provider": "GITHUB",
                 "github_repository_identity": {"full_name": REPO_FULL_NAME, "repository_id": "4242"}}
PINNED = {"provider": "GITHUB", "full_name": REPO_FULL_NAME, "id": "4242"}


def state(serial, lineage="lin-1"):
    return {"version": 4, "serial": serial, "lineage": lineage, "resources": [{"type": "x", "name": str(serial)}]}


class W(World):
    """SAT-19's world (ledger, provenance, CRM, signing key, certificates) with the GCS object fake."""

    def __init__(self, mode="PER_WORKLOAD", **kw):
        super().__init__(mode=mode, **kw)
        self.google = g.GCSGoogle(self.google.log)
        self.deps.rest = self.google
        # SAT-41 HIGH-1: a vended workload's record names its repository (vend_all writes these three fields)
        self.db.docs[f"workloads/{PID}"].update(WORKLOAD_REPO)

    def backfill(self):
        return rib.RunnerIdentityBackfill(self.deps, platform_bucket=PLATFORM_BUCKET, region_for=lambda _p: k.REGION)

    def platform_state(self, n):
        return [self.google.put(PLATFORM_BUCKET, OBJ, state(i), updated=f"2026-09-{i:02d}T00:00:00Z")
                for i in range(1, n + 1)]

    def record(self):
        return self.runner_record()


@pytest.fixture
def w():
    return W()


def _writes(world):
    return [wr for wr in world.db.writes if not wr[1].startswith(f"workloads/{PID}/audit_logs/")]


# ---------------------------------------------------------------------------------------------- Shared (inert)
def test_platform_status_answers_the_mode_with_zero_reads():
    w = W(mode="PLATFORM")
    out = w.backfill().status()
    assert out == {"mode": "PLATFORM", "mode_label": "Shared", "mode_source": ri.MODE_ENV, "per_workload": False,
                   "workloads": [], "totals": {}, "truncated": False}
    assert w.google.calls == [] and w.db.writes == [] and w.crm.calls == []


def test_platform_backfill_refuses_before_any_read_or_write():
    w = W(mode="PLATFORM")
    w.platform_state(2)
    calls_before = list(w.google.calls)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert e.value.code == "RUNNER_IDENTITY_MODE_PLATFORM"
    assert w.google.calls == calls_before and w.db.writes == [] and w.crm.calls == []


# ---------------------------------------------------------------------------------------------- dry run
def test_dry_run_writes_nothing_and_lists_every_call(w):
    w.platform_state(3)
    before = len(w.google.calls)
    out = w.backfill().run("cc", dry_run=True)
    (res,) = out["results"]
    assert res["outcome"] == "DRY_RUN" and out["dry_run"] is True
    calls = [c["call"] for c in res["calls"]]
    assert any(c.startswith("POST iam projects/") for c in calls)          # deployer create
    assert any(c.startswith("SET projects/") for c in calls)               # owner
    assert any(c.startswith("POST storage b?project=") for c in calls)     # bucket
    assert any(c.startswith("REWRITE") and "3 generation(s)" in x["why"] for x in res["calls"]
               for c in [x["call"]])
    assert w.db.writes == []
    assert w.google.mutating() == [] and w.google.gcs_mutations() == []
    assert len(w.google.calls) > before   # it read (inspection), never wrote
    assert w.iam.sets() == [] and w.crm.mutating_calls() == []


# ---------------------------------------------------------------------------------------------- full backfill
def test_backfill_provisions_then_migrates_byte_exact_with_chained_preconditions_and_tombstone(w):
    src_gens = w.platform_state(3)
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    (res,) = out["results"]
    assert res["outcome"] == "MIGRATED", res
    rec = w.record()
    assert rec["status"] == "READY" and rec["state_bucket"] == CHILD_BUCKET
    mig = rec["migration"]
    assert [c["source_generation"] for c in mig["copied"]] == src_gens
    assert mig["migrated_from"]["generation"] == src_gens[-1] and mig["migrated_at"]
    # bytes equal, oldest first, source metadata stamped
    dst = w.google.versions(CHILD_BUCKET, OBJ)
    src = w.google.versions(PLATFORM_BUCKET, OBJ)
    assert [v["data"] for v in dst] == [v["data"] for v in src]
    assert [v["crc32c"] for v in dst] == [v["crc32c"] for v in src]
    assert [v["metadata"]["stackvend-source-generation"] for v in dst] == src_gens
    assert [v["metadata"]["stackvend-source-updated"] for v in dst] == [v["updated"] for v in src]
    # chained preconditions: 0, then the destination generation just written
    rewrites = [c for c in w.google.calls if "/rewriteTo/" in c[1]]
    pre = [c[3]["ifGenerationMatch"] for c in rewrites]
    assert pre[0] == "0" and pre[1:] == [c["destination_generation"] for c in mig["copied"][:-1]]
    # tombstone replaced the migration lock (generation precondition) and names the new location
    lock = w.google.live(PLATFORM_BUCKET, LOCK)["data"]
    assert ri.is_tombstone(lock) and lock["Info"] == ri.tombstone_info(CHILD_BUCKET, PID)
    assert len(w.google.versions(PLATFORM_BUCKET, LOCK)) == 2
    # the platform copy itself is untouched (kept 30 days)
    assert [v["data"] for v in w.google.versions(PLATFORM_BUCKET, OBJ)] == [state(i) for i in (1, 2, 3)]
    # audited before and after
    actions = [(a["action"], a["status"]) for a in w.db.audit_records() if a.get("action") == "RUNNER_IDENTITY_BACKFILL"]
    assert actions == [("RUNNER_IDENTITY_BACKFILL", "ATTEMPT"), ("RUNNER_IDENTITY_BACKFILL", "MIGRATED")]
    assert w.db.doc(f"workloads/{PID}")["runner_identity_status"] == "READY"


def test_twenty_noncurrent_versions_plus_live_are_copied(w):
    gens = w.platform_state(25)
    w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    copied = [c["source_generation"] for c in w.record()["migration"]["copied"]]
    assert copied == gens[-21:] and len(copied) == 21


def test_second_run_is_idempotent(w):
    w.platform_state(2)
    w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    n_dst = len(w.google.versions(CHILD_BUCKET, OBJ))
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert out["results"][0]["outcome"] == "ALREADY_MIGRATED"
    assert len(w.google.versions(CHILD_BUCKET, OBJ)) == n_dst


def test_no_platform_state_gives_ready_without_a_migration(w):
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert out["results"][0]["outcome"] in ("READY", "NOTHING_TO_MIGRATE")
    assert w.record()["status"] == "READY" and w.record()["migration"] is None
    assert w.google.versions(PLATFORM_BUCKET, LOCK) == []


# ---------------------------------------------------------------------------------------------- resume
def test_resume_from_the_cursor_after_a_crash_between_versions(w):
    gens = w.platform_state(4)
    w.google.rewrite_fail = {3: 503}       # the third copy fails (as a crash would)
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert out["results"][0]["error_class"] == "STATE_COPY_FAILED"
    rec = w.record()
    assert rec["status"] == "MIGRATING" and rec["migration"]["last_source_generation_copied"] == gens[1]
    assert ri.is_migration_lock(w.google.live(PLATFORM_BUCKET, LOCK)["data"])
    w.google.rewrite_fail = {}
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert out["results"][0]["outcome"] == "MIGRATED", out
    dst = w.google.versions(CHILD_BUCKET, OBJ)
    assert [v["metadata"]["stackvend-source-generation"] for v in dst] == gens   # no duplicate, no gap


def test_resume_adopts_a_copy_written_before_the_cursor(w, monkeypatch):
    gens = w.platform_state(3)
    bf = w.backfill()
    real_write = bf._write
    state_ = {"n": 0}

    def crash_after_first_copy(pid, base, broker, **changes):
        mig = changes.get("migration") or {}
        if mig.get("copied") and len(mig["copied"]) == 1 and state_["n"] == 0:
            state_["n"] = 1
            raise ri.RunnerIdentityError("RUNNER_STORE_UNAVAILABLE", "crash", http_status=503)
        return real_write(pid, base, broker, **changes)

    monkeypatch.setattr(bf, "_write", crash_after_first_copy)
    with pytest.raises(ri.RunnerIdentityError):
        bf.run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert len(w.google.versions(CHILD_BUCKET, OBJ)) == 1 and w.record()["migration"]["copied"] == []
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert out["results"][0]["outcome"] == "MIGRATED"
    assert [v["metadata"]["stackvend-source-generation"] for v in w.google.versions(CHILD_BUCKET, OBJ)] == gens


# ---------------------------------------------------------------------------------------------- refusals
def test_drain_timeout_is_state_migration_busy_and_nothing_is_left_behind(w):
    w.platform_state(2)
    w.db.docs["pipeline_executions/tr-9"] = {"product_id": PID, "stages": {"terraform": {"status": "IN_FLIGHT"}}}
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    res = out["results"][0]
    assert res["error_class"] == "STATE_MIGRATION_BUSY"
    assert w.record()["status"] == "BUCKET_READY" and w.record()["error_class"] == "STATE_MIGRATION_BUSY"
    assert w.google.versions(PLATFORM_BUCKET, LOCK) == [] and w.google.versions(CHILD_BUCKET, OBJ) == []
    assert len(w.slept) >= rib.DRAIN_POLLS - 1


def test_a_running_tf_applier_execution_for_the_product_is_busy(w):
    w.platform_state(1)
    w.google.running = [{"name": g.EXECUTIONS + "/x1", "template": {"containers": [
        {"env": [{"name": "PRODUCT_ID", "value": PID}]}]}}]
    assert w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)["results"][0]["error_class"] == "STATE_MIGRATION_BUSY"
    w.google.running = [{"name": g.EXECUTIONS + "/x2", "completionTime": "2026-10-31T00:00:00Z",
                         "template": {"containers": [{"env": [{"name": "PRODUCT_ID", "value": PID}]}]}},
                        {"name": g.EXECUTIONS + "/x3", "template": {"containers": [
                            {"env": [{"name": "PRODUCT_ID", "value": "other"}]}]}}]
    assert w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)["results"][0]["outcome"] == "MIGRATED"


def test_a_lock_held_by_another_run_is_state_locked_and_untouched(w):
    w.platform_state(2)
    w.google.put(PLATFORM_BUCKET, LOCK, {"ID": "tofu-1", "Operation": "OperationTypeApply", "Who": "x"})
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert out["results"][0]["error_class"] == "STATE_LOCKED"
    assert w.google.live(PLATFORM_BUCKET, LOCK)["data"]["ID"] == "tofu-1"
    assert w.record()["status"] == "BUCKET_READY" and w.google.versions(CHILD_BUCKET, OBJ) == []


def test_a_source_change_during_the_copy_is_state_migration_race(w):
    w.platform_state(2)

    def hook(bucket, name, gen):
        if bucket == PLATFORM_BUCKET and len(w.google.versions(CHILD_BUCKET, OBJ)) == 1:
            w.google.put(PLATFORM_BUCKET, OBJ, state(99))   # a write that ignored the lock
            w.google.rewrite_hook = None

    w.google.rewrite_hook = hook
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert out["results"][0]["error_class"] == "STATE_MIGRATION_RACE"
    assert w.record()["status"] == "MIGRATING" and not ri.is_tombstone(w.google.live(PLATFORM_BUCKET, LOCK)["data"])


def test_foreign_generations_in_the_destination_are_a_conflict(w):
    w.platform_state(2)
    w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1, steps=list(rib.ENSURE_STEPS))
    w.google.put(CHILD_BUCKET, OBJ, state(50, "other-lineage"))
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1, steps=["migrate_state"])
    assert out["results"][0]["error_class"] == "STATE_MIGRATION_CONFLICT"
    assert len(w.google.versions(CHILD_BUCKET, OBJ)) == 1


def test_missing_rights_refuse_before_any_write(w):
    w.platform_state(1)
    w.google.perms = ["iam.serviceAccounts.create"]
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert out["results"][0]["error_class"] == "BACKFILL.NO_RIGHTS_ON_PROJECT"
    assert w.google.mutating() == [] and w.iam.sets() == [] and w.record() is None


def test_an_unsigned_record_is_refused_never_replaced(w):
    w.db.docs[f"workload_provenance/{PID}"]["runner_identity"] = {"schema": ri.SCHEMA, "status": "READY"}
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert out["results"][0]["error_class"] == "RUNNER_RECORD_UNSIGNED"
    assert w.record() == {"schema": ri.SCHEMA, "status": "READY"} and w.google.mutating() == []


def test_a_shared_broker_identity_stops_the_whole_run_with_503():
    w = W(runtime=k.DEVELOPER)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert e.value.http_status == 503 and w.db.writes == []


def test_owner_steps_run_alone_and_restore_needs_product_ids(w):
    for steps, pids in ((["migrate_state", "purge_platform_copy"], None), (["restore_platform_state"], None),
                        (["nope"], None), (["ensure_sa", "ensure_sa"], None)):
        with pytest.raises(ri.RunnerIdentityError) as e:
            w.backfill().run("cc", steps=steps, product_ids=pids)
        assert e.value.code == "BACKFILL.STEPS_INVALID"


def test_an_unverified_identity_is_skipped_typed(w):
    w.crm.tag_bindings[NUMBER] = []
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert out["results"][0]["error_class"] == "BACKFILL.IDENTITY_UNVERIFIED" and w.google.mutating() == []


# ---------------------------------------------------------------------------------------------- restore / purge
def test_restore_copies_back_and_removes_the_tombstone(w):
    w.platform_state(2)
    w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    w.google.put(CHILD_BUCKET, OBJ, state(7))      # a deploy after the migration
    out = w.backfill().run("cc", dry_run=False, steps=["restore_platform_state"], product_ids=[PID],
                               max_items=1)
    assert out["results"][0]["outcome"] == "RESTORED"
    assert w.google.live(PLATFORM_BUCKET, OBJ)["data"] == state(7)
    assert w.google.versions(PLATFORM_BUCKET, LOCK) == [v for v in w.google.versions(PLATFORM_BUCKET, LOCK)
                                                         if not ri.is_tombstone(v["data"])]
    assert w.google.live(PLATFORM_BUCKET, LOCK) is None
    assert w.record()["status"] == "BUCKET_READY" and w.record()["migration"]["restored_at"]


def test_purge_waits_30_days_then_keeps_only_the_tombstone(w):
    w.platform_state(3)
    w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1, steps=["purge_platform_copy"])
    assert out["results"][0]["error_class"] == "BACKFILL.PURGE_TOO_EARLY"
    w.clock_now[0] = f.NOW + timedelta(days=31)
    dry = w.backfill().run("cc", dry_run=True, steps=["purge_platform_copy"])
    assert dry["results"][0]["outcome"] == "DRY_RUN" and len(w.google.versions(PLATFORM_BUCKET, OBJ)) == 3
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1, steps=["purge_platform_copy"])
    assert out["results"][0]["outcome"] == "PURGED"
    assert w.google.versions(PLATFORM_BUCKET, OBJ) == []
    assert ri.is_tombstone(w.google.live(PLATFORM_BUCKET, LOCK)["data"])
    assert w.record()["migration"]["purged_at"] and w.record()["status"] == "READY"


# ---------------------------------------------------------------------------------------------- status
def test_status_lists_the_facts_per_workload(w):
    w.platform_state(2)
    st = w.backfill().status()
    (row,) = st["workloads"]
    assert st["per_workload"] is True and row["record"] == "NONE" and row["deployer"] == "ABSENT"
    assert row["platform_state_versions"] == 2 and row["state_location"].startswith(f"gs://{PLATFORM_BUCKET}/")
    assert w.db.writes == [] and w.google.mutating() == []
    w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    (row,) = w.backfill().status()["workloads"]
    assert row["status"] == "READY" and row["platform_lock"] == "TOMBSTONE" and row["owner_grant"] is True \
        and row["broker_grant"] is True and row["state_location"] == f"gs://{CHILD_BUCKET}/workloads/{PID}"


# ---------------------------------------------------------------------------------------------- routes
CC_TOKEN = "good-token"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("DESTRUCTIVE_CALLERS", f.CC_SA)
    monkeypatch.setenv("VENDING_SERVICE_URL", DG_AUD)
    world = W()
    world.db.docs[f"workloads/{PID}"]["region"] = k.REGION   # FD-7M-a field (else a strict platform-settings read)
    eng = VENDING_MAIN.ProjectRepoVendingEngine(platform_project_id=f.HOST, firestore_client=world.db,
                                                crm_service=MagicMock(), storage_client=FakeStorage(),
                                                guard_context=world.ctx, runner_deps=world.deps)
    eng.tfstate_bucket = PLATFORM_BUCKET
    monkeypatch.setattr(VENDING_MAIN, "vending_engine", eng)
    monkeypatch.setattr(VENDING_MAIN, "CALLER_TOKEN_VERIFIER", fake_verifier)
    return world, TestClient(VENDING_MAIN.app)


def test_routes_need_the_destructive_caller(client):
    world, c = client
    assert c.get("/runner-identity/status").status_code == 401
    assert c.post("/runner-identity/backfill", json={}, headers={"Authorization": "Bearer dev-token"}
                  ).status_code == 403
    assert world.db.writes == []


def test_backfill_route_defaults_to_a_dry_run(client):
    world, c = client
    world.platform_state(1)
    r = c.post("/runner-identity/backfill", headers={"Authorization": f"Bearer {CC_TOKEN}"})
    assert r.status_code == 200 and r.json()["dry_run"] is True and world.db.writes == []
    r = c.get("/runner-identity/status", headers={"Authorization": f"Bearer {CC_TOKEN}"})
    assert r.status_code == 200 and r.json()["per_workload"] is True


def test_backfill_route_in_platform_mode_is_409(client):
    world, c = client
    world.deps.config = _config("PLATFORM")
    r = c.post("/runner-identity/backfill", json={"dry_run": False}, headers={"Authorization": f"Bearer {CC_TOKEN}"})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "RUNNER_IDENTITY_MODE_PLATFORM"
    r = c.get("/runner-identity/status", headers={"Authorization": f"Bearer {CC_TOKEN}"})
    assert r.status_code == 200 and r.json()["mode_label"] == "Shared" and world.google.calls == []


# ---------------------------------------------------------------------------------------------- decommission
def _decom_engine(world, storage=None):
    f.add_approval(world.db)
    eng = VENDING_MAIN.ProjectRepoVendingEngine(platform_project_id=f.HOST, firestore_client=world.db,
                                                crm_service=MagicMock(), storage_client=storage or FakeStorage(),
                                                guard_context=world.ctx, runner_deps=world.deps)
    eng.tfstate_bucket = PLATFORM_BUCKET
    return eng


class _Explode:
    def __getattr__(self, name):
        raise AssertionError(f"runner deps touched on a Shared install: {name}")


def _decommission(eng, **kw):
    return eng.decommission_workload(PID, approval_id=f.APPROVAL, caller_email=f.CC_SA, **kw)


@pytest.mark.parametrize("env", [None, "", "PLATFORM"])
def test_shared_install_decommission_is_byte_identical(monkeypatch, env):
    def run(set_env):
        world = W()
        if set_env is None:
            monkeypatch.delenv(ri.MODE_ENV, raising=False)
        else:
            monkeypatch.setenv(ri.MODE_ENV, set_env)
        storage = FakeStorage()
        storage.objects = {OBJ: b"{}"}
        eng = _decom_engine(world, storage)
        eng._runner_deps = _Explode()
        out = _decommission(eng)
        out.pop("decommissioned_at"), out.pop("archive_path")
        ops = [(op[0], op[1]) for op in storage.ops]   # the archive name carries a timestamp
        paths = [w_[1].rsplit("/", 1)[0] if "/audit_logs/" in w_[1] else w_[1] for w_ in world.db.writes]
        return out, ops, world.crm.mutating_calls(), paths, world.google.calls

    baseline = run(None)
    got = run(env)
    assert got[:4] == baseline[:4] and got[4] == [] and baseline[4] == []
    out, ops = got[0], got[1]
    assert out["state_archived"] is True and ops == [("copy", OBJ), ("delete", OBJ)]


def test_per_workload_without_a_record_keeps_todays_decommission(monkeypatch):
    monkeypatch.setenv(ri.MODE_ENV, "PER_WORKLOAD")
    world = W()
    storage = FakeStorage()
    out = _decommission(_decom_engine(world, storage))
    assert out["status"] == "DECOMMISSIONED" and storage.ops[0][0] == "copy" and storage.ops[1] == ("delete", OBJ)
    assert world.google.gcs_mutations() == []


def _migrated_world(monkeypatch):
    monkeypatch.setenv(ri.MODE_ENV, "PER_WORKLOAD")
    world = W()
    world.platform_state(2)
    world.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    world.google.put(CHILD_BUCKET, OBJ, state(9))
    world.google.calls.clear()
    return world


def test_decommission_archives_before_the_delete_and_cleans_the_stale_platform_copy(monkeypatch):
    world = _migrated_world(monkeypatch)
    order = []
    world.google.rewrite_hook = lambda b, n, gen: order.append(("archive", b, n))
    eng = _decom_engine(world)
    real_delete = world.crm.delete_project

    def delete(number):
        order.append(("delete", number))
        return real_delete(number)

    world.crm.delete_project = delete
    out = _decommission(eng)
    assert [o[0] for o in order] == ["archive", "delete"] and order[0][1] == CHILD_BUCKET
    archive = out["archive_path"]
    assert out["state_archived"] is True and archive.startswith(f"workloads/{PID}/state_history/decommission_")
    assert world.google.live(PLATFORM_BUCKET, archive)["data"] == state(9)
    assert world.google.versions(PLATFORM_BUCKET, OBJ) == [] and world.google.versions(PLATFORM_BUCKET, LOCK) == []
    assert eng.storage.ops == []   # the legacy copy-then-delete did not run


def test_a_failed_archive_stops_the_decommission(monkeypatch):
    world = _migrated_world(monkeypatch)
    world.google.rewrite_fail = {world.google.rewrites + 1: 403}
    eng = _decom_engine(world)
    with pytest.raises(VDG.DecommissionFailed) as e:
        _decommission(eng)
    assert e.value.code == "DECOMMISSION_STATE_ARCHIVE_FAILED"
    assert world.crm.count("delete_project") == 0
    assert world.db.doc(f"workloads/{PID}")["status"] == "DECOMMISSION_FAILED"
    assert world.google.versions(PLATFORM_BUCKET, OBJ) != []   # nothing cleaned


def test_delete_without_archive_needs_the_approval_flag(monkeypatch):
    world = _migrated_world(monkeypatch)
    eng = _decom_engine(world)
    with pytest.raises(VDG.DeletionRefused) as e:
        _decommission(eng, delete_without_archive=True)
    assert e.value.code == "DELETE_WITHOUT_ARCHIVE_NOT_APPROVED" and world.crm.count("delete_project") == 0
    assert world.db.doc(f"destructive_approvals/{f.APPROVAL}")["status"] == "APPROVED"   # not consumed
    world.db.docs[f"destructive_approvals/{f.APPROVAL}"]["delete_without_archive"] = True
    world.google.rewrite_fail = {world.google.rewrites + 1: 403}
    out = _decommission(eng, delete_without_archive=True)
    assert out["status"] == "DECOMMISSIONED" and out["state_archived"] is False
    assert any(x.startswith("STATE_ARCHIVE_SKIPPED_BY_APPROVAL") for x in out["warnings"])


def test_decommission_of_a_never_deployed_per_workload_project_archives_nothing(monkeypatch):
    monkeypatch.setenv(ri.MODE_ENV, "PER_WORKLOAD")
    world = W()
    world.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)        # READY, no state anywhere
    out = _decommission(_decom_engine(world))
    assert out["status"] == "DECOMMISSIONED" and out["state_archived"] is False and out["archive_path"] is None


def test_an_unsigned_record_refuses_the_decommission_before_any_change(monkeypatch):
    monkeypatch.setenv(ri.MODE_ENV, "PER_WORKLOAD")
    world = W()
    world.db.docs[f"workload_provenance/{PID}"]["runner_identity"] = {"schema": ri.SCHEMA, "status": "READY"}
    with pytest.raises(VDG.DeletionRefused) as e:
        _decommission(_decom_engine(world))
    assert e.value.code == "DECOMMISSION_STATE_ARCHIVE_FAILED" and world.crm.count("delete_project") == 0
    assert world.db.doc(f"workloads/{PID}")["status"] == "ACTIVE"


# ---------------------------------------------------------------------------------------------- RT fixes (F2-2/3/4)
@pytest.mark.parametrize("kw", [{}, {"product_ids": [PID, "b", "c", "d"], "max_items": 3},
                                {"product_ids": [PID], "max_items": 4}])
def test_a_real_run_names_at_most_three_workloads(w, kw):
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.backfill().run("cc", dry_run=False, **kw)
    assert e.value.code == "BACKFILL.REAL_RUN_TOO_LARGE" and e.value.http_status == 422
    assert w.db.writes == [] and w.google.calls == []


def test_a_dry_run_may_cover_every_workload(w):
    assert w.backfill().run("cc", dry_run=True)["results"][0]["outcome"] == "DRY_RUN"


def test_the_drain_fails_fast_inside_the_request(w):
    w.platform_state(1)
    w.db.docs["pipeline_executions/tr-9"] = {"product_id": PID, "stages": {"terraform": {"status": "IN_FLIGHT"}}}
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert out["results"][0]["error_class"] == "STATE_MIGRATION_BUSY" and w.slept == []


def test_a_bad_copy_written_by_this_run_is_removed_so_the_next_run_succeeds(w):
    gens = w.platform_state(3)
    w.google.rewrite_corrupt = {1}
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    res = out["results"][0]
    assert res["error_class"] == "STATE_MIGRATION_CONFLICT" and "was removed" in res["detail"]
    assert w.google.versions(CHILD_BUCKET, OBJ) == []                     # the bad generation is gone
    assert w.record()["status"] == "BUCKET_READY" and w.google.live(PLATFORM_BUCKET, LOCK) is None
    deletes = [c for c in w.google.calls if c[0] == "DELETE" and c[1].startswith(
        f"https://storage.googleapis.com/storage/v1/b/{CHILD_BUCKET}/")]
    assert len(deletes) == 1 and deletes[0][3]["ifGenerationMatch"] == deletes[0][3]["generation"]
    w.google.rewrite_corrupt = set()
    assert w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)["results"][0]["outcome"] == "MIGRATED"
    assert [v["metadata"]["stackvend-source-generation"] for v in w.google.versions(CHILD_BUCKET, OBJ)] == gens


def test_a_bad_later_copy_keeps_the_cursor_and_resumes(w):
    gens = w.platform_state(3)
    w.google.rewrite_corrupt = {2}
    out = w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)
    assert out["results"][0]["error_class"] == "STATE_MIGRATION_CONFLICT"
    assert len(w.google.versions(CHILD_BUCKET, OBJ)) == 1 and w.record()["status"] == "MIGRATING"
    w.google.rewrite_corrupt = set()
    assert w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)["results"][0]["outcome"] == "MIGRATED"
    assert [v["metadata"]["stackvend-source-generation"] for v in w.google.versions(CHILD_BUCKET, OBJ)] == gens


def test_status_inspects_at_most_limit_records(w):
    for i in range(3):
        w.db.docs[f"workload_provenance/extra-{i}"] = {"created_by": "stackvend-vending",
                                                       "project_id": f"extra-{i}-proj", "project_number": "9"}
    st = w.backfill().status(limit=2)
    assert len(st["workloads"]) == 2 and st["truncated"] is True and st["max_records"] == 2
    assert rib.STATUS_DEFAULT_LIMIT == 50


def test_status_route_takes_a_limit(client):
    world, c = client
    r = c.get("/runner-identity/status?limit=1", headers={"Authorization": f"Bearer {CC_TOKEN}"})
    assert r.status_code == 200 and r.json()["max_records"] == 1
    assert c.get("/runner-identity/status?limit=0", headers={"Authorization": f"Bearer {CC_TOKEN}"}).status_code == 422
