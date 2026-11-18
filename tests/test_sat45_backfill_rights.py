"""SAT-45: the runner identity backfill's rights check (apps/project-vending/runner_identity_backfill.py).

Defect (live, castor 11-02): the project-level check (cloudresourcemanager v3 projects.testIamPermissions) asked for
storage.buckets.setIamPolicy and storage.objects.create, which roles/owner does not grant at project level (an owner
gets them per bucket from Cloud Storage's projectOwner convenience bindings). Every real run on a child that vending
owns failed BACKFILL.NO_RIGHTS_ON_PROJECT, and the dry run only listed a STOP line under an outcome of DRY_RUN.

Fix: the project check asks only for project-level permissions; the bucket permissions are checked on the state bucket
(Cloud Storage buckets.testIamPermissions) once ensure_bucket has found or created it, before its IAM or any object
(typed BACKFILL.NO_RIGHTS_ON_BUCKET, nothing written to the bucket). A dry run that would stop says so in its outcome
(DRY_RUN_STOP + error_class) and lists nothing after the STOP. A child where vending lacks the project rights still
refuses NO_RIGHTS_ON_PROJECT (fallback F-B). Hermetic fakes only.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import pytest

import fd7l_fakes as k
from test_fd7l_phase3_backfill import (  # noqa: F401  (fixtures and constants reused by name)
    CHILD_BUCKET, LOCK, NUMBER, OBJ, PID, PLATFORM_BUCKET, W, ri, rib)

# What roles/owner answers at project level for the old six-permission request (castor testplan01-e2, 11-02): every
# permission but storage.buckets.setIamPolicy and storage.objects.create.
OWNER_PROJECT_PERMS = ["iam.serviceAccounts.create", "iam.serviceAccounts.setIamPolicy",
                       "resourcemanager.projects.setIamPolicy", "storage.buckets.create"]
BUCKET_LEVEL = ("storage.buckets.setIamPolicy", "storage.objects.create")


@pytest.fixture
def w():
    world = W()
    world.google.perms = list(OWNER_PROJECT_PERMS)
    return world


def _run(world, **kw):
    out = world.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1, **kw)
    (res,) = out["results"]
    return res


def _dry(world, **kw):
    out = world.backfill().run("cc", dry_run=True, **kw)
    (res,) = out["results"]
    return out, res


def _project_tests(world):
    return [c for c in world.google.calls if c[1].endswith(":testIamPermissions") and "/v3/projects/" in c[1]]


def _bucket_tests(world):
    return [c for c in world.google.calls if c[1].endswith("/iam/testPermissions")]


def _bucket_iam_puts(world):
    return [c for c in world.google.calls if c[0] == "PUT" and c[1].endswith("/iam")]


def _present_bucket(world):
    world.google.buckets[CHILD_BUCKET] = dict(k.GOOD_BUCKET, name=CHILD_BUCKET, projectNumber=NUMBER)


# ---------------------------------------------------------------------------------------------- the constants
def test_the_project_check_asks_only_project_level_permissions():
    assert set(BUCKET_LEVEL).isdisjoint(rib.REQUIRED_VENDING_PERMISSIONS)
    assert set(rib.REQUIRED_VENDING_PERMISSIONS) == set(OWNER_PROJECT_PERMS)
    assert set(BUCKET_LEVEL) <= set(rib.REQUIRED_BUCKET_PERMISSIONS)


# ---------------------------------------------------------------------------------------------- real runs
def test_an_owner_child_passes_the_project_check_and_migrates(w):
    w.platform_state(2)
    res = _run(w)
    assert res["outcome"] == "MIGRATED", res
    (proj,) = _project_tests(w)
    assert proj[2]["permissions"] == list(rib.REQUIRED_VENDING_PERMISSIONS)
    (bkt,) = _bucket_tests(w)
    assert f"/b/{CHILD_BUCKET}/iam/testPermissions" in bkt[1] and bkt[0] == "GET"
    assert bkt[3]["permissions"] == list(rib.REQUIRED_BUCKET_PERMISSIONS)
    # the bucket check ran before the bucket IAM change and before any object write
    order = [i for i, c in enumerate(w.google.calls)
             if c in _bucket_tests(w) or c in _bucket_iam_puts(w) or "/rewriteTo/" in c[1]]
    assert w.google.calls[order[0]] == bkt
    assert w.record()["status"] == "READY"


@pytest.mark.parametrize("held", [[], ["storage.buckets.getIamPolicy", "storage.objects.list", "storage.objects.get"]])
def test_missing_bucket_rights_refuse_typed_before_bucket_iam_or_any_object(w, held):
    w.platform_state(2)
    w.google.bucket_perms = held
    res = _run(w)
    assert res["outcome"] == "FAILED" and res["error_class"] == "BACKFILL.NO_RIGHTS_ON_BUCKET"
    assert f"gs://{CHILD_BUCKET}" in res["detail"]
    for p in BUCKET_LEVEL:
        assert p in res["detail"]
    assert _bucket_iam_puts(w) == [] and w.google.bucket_iam == {}
    assert w.google.gcs_mutations() == []                        # no lock, no rewrite, no object anywhere
    assert w.google.versions(PLATFORM_BUCKET, LOCK) == [] and w.google.versions(CHILD_BUCKET, OBJ) == []
    assert w.record() is None                                    # no signed record either


def test_a_bucket_rights_answer_other_than_200_fails_closed(w, monkeypatch):
    w.platform_state(1)
    route = w.google._route

    def _route(m, url, json_body, params, bearer):
        if url.endswith("/iam/testPermissions"):
            return 403, {}
        return route(m, url, json_body, params, bearer)

    monkeypatch.setattr(w.google, "_route", _route)
    res = _run(w)
    assert res["error_class"] == "BACKFILL.NO_RIGHTS_ON_BUCKET" and "HTTP 403" in res["detail"]
    assert _bucket_iam_puts(w) == [] and w.google.gcs_mutations() == []


def test_a_migration_without_ensure_bucket_checks_the_recorded_bucket_first(w):
    w.platform_state(2)
    res = _run(w, steps=list(rib.ENSURE_STEPS))
    assert res["outcome"] == "BUCKET_READY", res
    w.google.bucket_perms = ["storage.buckets.getIamPolicy"]
    res = _run(w, steps=[rib.MIGRATE_STEP])
    assert res["error_class"] == "BACKFILL.NO_RIGHTS_ON_BUCKET", res
    assert w.record()["status"] == "BUCKET_READY" and w.record().get("migration") is None
    assert w.google.versions(PLATFORM_BUCKET, LOCK) == [] and w.google.versions(CHILD_BUCKET, OBJ) == []
    w.google.bucket_perms = None
    assert _run(w, steps=[rib.MIGRATE_STEP])["outcome"] == "MIGRATED"


def test_vending_without_project_rights_is_unchanged_fallback_f_b(w):
    w.platform_state(1)
    w.google.perms = ["iam.serviceAccounts.create"]
    res = _run(w)
    assert res["error_class"] == "BACKFILL.NO_RIGHTS_ON_PROJECT" and "fallback F-B" in res["detail"]
    for p in ("iam.serviceAccounts.setIamPolicy", "resourcemanager.projects.setIamPolicy", "storage.buckets.create"):
        assert p in res["detail"]
    assert w.google.mutating() == [] and w.iam.sets() == [] and w.record() is None
    assert _bucket_tests(w) == []


# ---------------------------------------------------------------------------------------------- dry runs
def test_dry_run_owner_child_new_bucket_says_the_check_runs_at_creation(w):
    w.platform_state(3)
    out, res = _dry(w)
    assert res["outcome"] == "DRY_RUN" and res["error_class"] is None and out["counts"] == {"DRY_RUN": 1}
    assert not any(c["call"].startswith("STOP") for c in res["calls"])
    assert any("checked right after the bucket is created" in c["why"] for c in res["calls"])
    assert any(c["call"].startswith("REWRITE") for c in res["calls"])
    assert _bucket_tests(w) == []                                # no bucket yet: nothing to test
    assert w.db.writes == [] and w.google.mutating() == [] and w.google.gcs_mutations() == []


def test_dry_run_existing_bucket_with_rights_lists_the_check(w):
    w.platform_state(1)
    _present_bucket(w)
    _out, res = _dry(w)
    assert res["outcome"] == "DRY_RUN"
    assert any(c["call"] == f"GET storage b/{CHILD_BUCKET}/iam/testPermissions" for c in res["calls"])
    assert len(_bucket_tests(w)) == 1 and w.db.writes == [] and w.google.mutating() == []


def test_dry_run_existing_bucket_without_rights_stops(w):
    w.platform_state(1)
    _present_bucket(w)
    w.google.bucket_perms = []
    out, res = _dry(w)
    assert res["outcome"] == rib.DRY_RUN_STOP and res["error_class"] == "BACKFILL.NO_RIGHTS_ON_BUCKET"
    assert out["counts"] == {rib.DRY_RUN_STOP: 1}
    assert res["calls"][-1]["call"] == f"STOP gs://{CHILD_BUCKET}"
    assert not any(c["call"].startswith(("PUT", "REWRITE")) for c in res["calls"])
    assert w.db.writes == [] and w.google.mutating() == []


def test_dry_run_migrate_only_checks_the_existing_bucket(w):
    w.platform_state(1)
    _present_bucket(w)
    w.google.bucket_perms = []
    _out, res = _dry(w, steps=[rib.MIGRATE_STEP])
    assert res["outcome"] == rib.DRY_RUN_STOP and res["error_class"] == "BACKFILL.NO_RIGHTS_ON_BUCKET"


def test_dry_run_without_project_rights_stops_with_f_b_and_lists_nothing_after(w):
    w.platform_state(1)
    w.google.perms = []
    out, res = _dry(w)
    assert res["outcome"] == rib.DRY_RUN_STOP and res["error_class"] == "BACKFILL.NO_RIGHTS_ON_PROJECT"
    assert "fallback F-B" in res["detail"] and out["counts"] == {rib.DRY_RUN_STOP: 1}
    assert [c["call"].split(" ")[0] for c in res["calls"]] == ["STOP"]
    assert w.db.writes == [] and w.google.mutating() == []


def test_dry_run_and_real_run_agree_for_an_owner_child(w):
    """The 11-02 defect: the dry run said DRY_RUN while the run refused. Now both pass for an owner child."""
    w.platform_state(2)
    _out, dry = _dry(w)
    assert dry["outcome"] == "DRY_RUN"
    assert _run(w)["outcome"] == "MIGRATED"


def test_a_shared_install_still_reads_nothing():
    world = W(mode="PLATFORM")
    with pytest.raises(ri.RunnerIdentityError) as e:
        world.backfill().run("cc", dry_run=True)
    assert e.value.code == "RUNNER_IDENTITY_MODE_PLATFORM" and world.google.calls == []
