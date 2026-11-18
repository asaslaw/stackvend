"""
Lane 18 S1 (plan F7): owner-run provenance backfill. Dry run by default, explicit product ids only, brownfield and
untraced projects skipped, backfilled projects are HITL-decommissionable but never SANDBOX_TTL-eligible.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import io
import json

import destructive_guard_fakes as f
from destructive_guard_fakes import dg

import backfill_provenance as bp

ENV = {"PROJECT_ID": f.HOST, "MANAGED_WORKLOADS_FOLDER_ID": f.ROOT, "STACKVEND_MANAGED_TAG_VALUE": f.TAG}


def _legacy_world():
    """A pre-S1 workload: ledger + project in the managed folder, no labels/tag/provenance."""
    db, crm = f.FakeDB(), f.FakeCRM()
    crm.projects[f.HOST_NUMBER] = {"name": f"projects/{f.HOST_NUMBER}", "projectId": f.HOST, "state": "ACTIVE"}
    f.add_project(crm, f.PROJECT, f.NUMBER, labels={"team": "x"}, tagged=False)
    db.docs[f"workloads/{f.PID}"] = {"product_id": f.PID, "project_id": f.PROJECT, "project_number": f.NUMBER,
                                     "status": "ACTIVE", "trace_id": "vend-tr-shop-api", "is_sandbox": True}
    return db, crm


def _run(args, db, crm, env=ENV):
    out = io.StringIO()
    rc = bp.run(args, store=f.TestStore(db), crm=crm, env=env, now=f.NOW, out=out)
    lines = [json.loads(line) for line in out.getvalue().splitlines() if line.startswith("{")]
    return rc, lines, out.getvalue()


def test_no_project_ids_is_refused():
    db, crm = _legacy_world()
    for args in ([], ["--apply"]):
        rc, lines, text = _run(args, db, crm)
        assert rc == 2 and "explicit --project" in text
    assert db.writes == [] and crm.calls == []


def test_dry_run_writes_nothing_and_prints_facts():
    db, crm = _legacy_world()
    rc, [plan], _ = _run(["--project", f.PID], db, crm)
    assert rc == 0 and plan["decision"] == "PLANNED"
    assert plan["crm_create_time"] == "2026-09-01T00:00:00Z" and plan["trace_id"] == "vend-tr-shop-api"
    assert plan["planned_labels"]["stackvend-workload-type"] == "standard" and plan["planned_labels"]["team"] == "x"
    assert db.writes == [] and crm.mutating_calls() == []


def test_skips_untraced_brownfield_platform_and_already_provenanced():
    db, crm = _legacy_world()
    db.docs["workloads/no-trace"] = {"project_id": "nt-proj", "trace_id": ""}
    db.docs["workloads/byo"] = {"project_id": "byo-proj", "trace_id": "t", "track": "BYO_IAC"}
    db.docs["workloads/brown"] = {"project_id": "brown-proj", "trace_id": "t", "is_brownfield": True}
    db.docs["workloads/project-castor"] = {"project_id": f.HOST, "is_castor": True}
    db.docs["workload_provenance/done"] = {"created_by": "stackvend-vending"}
    db.docs["workloads/done"] = {"project_id": "done-proj", "trace_id": "t"}
    rc, lines, _ = _run(["--project", "no-trace", "--project", "byo", "--project", "brown", "--project",
                         "project-castor", "--project", "done", "--project", "missing", "--apply"], db, crm)
    assert [l["decision"] for l in lines] == ["SKIPPED:NO_VEND_TRACE", "SKIPPED:BROWNFIELD", "SKIPPED:BROWNFIELD",
                                             "SKIPPED:PLATFORM_WORKLOAD", "SKIPPED:ALREADY_PROVENANCED",
                                             "SKIPPED:LEDGER_MISSING"]
    assert db.writes == [] and crm.mutating_calls() == []


def test_outside_managed_folder_or_mismatch_skipped():
    db, crm = _legacy_world()
    crm.ancestry[f.PROJECT][2]["resourceId"]["id"] = "9999"
    assert _run(["--project", f.PID], db, crm)[1][0]["decision"] == "SKIPPED:NOT_IN_MANAGED_FOLDER"
    db, crm = _legacy_world()
    db.docs[f"workloads/{f.PID}"]["project_number"] = "1"
    assert _run(["--project", f.PID], db, crm)[1][0]["decision"] == "SKIPPED:LEDGER_MISMATCH"
    db, crm = _legacy_world()
    crm.fail["get_project"] = 429
    assert _run(["--project", f.PID], db, crm)[1][0]["decision"] == "SKIPPED:CRM_UNAVAILABLE"


def test_apply_needs_the_tag_value():
    db, crm = _legacy_world()
    rc, _, text = _run(["--project", f.PID, "--apply"], db, crm, env={k: v for k, v in ENV.items()
                                                                     if k != "STACKVEND_MANAGED_TAG_VALUE"})
    assert rc == 2 and db.writes == []


def test_apply_backfills_hitl_only_provenance():
    db, crm = _legacy_world()
    rc, [res], _ = _run(["--project", f.PID, "--apply"], db, crm)
    assert rc == 0 and res["decision"] == "APPLIED"
    prov = db.doc(f"workload_provenance/{f.PID}")
    assert prov["created_by"] == "owner-backfill" and prov["project_number"] == f.NUMBER
    assert prov["is_sandbox"] is False and prov["sandbox_expires_at"] is None
    assert [c[0] for c in crm.mutating_calls()] == ["patch_labels", "create_tag_binding"]

    ctx = f.make_ctx(db, crm)
    assert dg.verify_identity(f.PID, ctx=ctx).provenance_created_by == "owner-backfill"
    f.add_approval(db)
    dg.assert_deletable(dg.DeletionTarget(f.PID), action_class="PROJECT_DECOMMISSION", approval_id=f.APPROVAL,
                        caller_email=f.CC_SA, ctx=ctx)
    try:
        dg.assert_deletable(dg.DeletionTarget(f.PID), action_class="SANDBOX_TTL", approval_id=None,
                            caller_email=f.TTL_SA, ctx=ctx)
        raise AssertionError("a backfilled project must never be SANDBOX_TTL-eligible")
    except dg.DeletionRefused as e:
        assert e.code == "SANDBOX_NOT_ELIGIBLE"


def test_apply_failure_is_reported():
    db, crm = _legacy_world()
    crm.fail["patch_labels"] = 403
    rc, [res], _ = _run(["--project", f.PID, "--apply"], db, crm)
    assert rc == 1 and res["decision"] == "FAILED"
    assert db.doc(f"workload_provenance/{f.PID}") is None
