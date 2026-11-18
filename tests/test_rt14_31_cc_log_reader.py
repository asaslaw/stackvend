"""
RT14-31 / owner decision D4 (11-14, Option A): project vending grants the Control Center's runtime service account
roles/logging.viewer on each child project, at vend time and through an idempotent admin backfill. No platform
Terraform change. Hermetic fakes only (tests/destructive_guard_fakes.py).
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import os

import pytest
from fastapi.testclient import TestClient

import destructive_guard_fakes as f
from test_destructive_guard_vending import (  # noqa: F401  (fixtures)
    GOOD, VENDING_MAIN, _vend_crm, _vend_engine, env, fake_verifier, vmain,
    _freeze_setting_without_firestore,
)

# The modules the loaded vending code actually uses (the root conftest's sys.modules sandbox can give this file other
# instances of the same modules).
CCL = VENDING_MAIN.ccl
VDG = CCL.dg
VendingFailure = VENDING_MAIN.VendingFailure
CC_MEMBER = f"serviceAccount:sa-stackvend-control-center@{f.HOST}.iam.gserviceaccount.com"
ROLE = "roles/logging.viewer"
CHILD = "fresh-svc-123abc"


def _iam(**kw):
    return f.FakeChildIAM(err=VDG.CRMUnavailable, **kw)


def _engine(vmain, iam, db=None):
    eng = _vend_engine(vmain, db if db is not None else f.FakeDB(), _vend_crm())
    eng._iam_client = iam
    eng.owner_grant_retry_delay = 0.0
    return eng


def _vend(eng):
    return eng.vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT, force_new_project_id=CHILD)


def _viewers(policy):
    return [b for b in policy["bindings"] if b["role"] == ROLE]


@pytest.fixture(autouse=True)
def _no_owner_members(monkeypatch):
    monkeypatch.delenv("STACKVEND_CHILD_PROJECT_OWNER_MEMBERS", raising=False)
    monkeypatch.delenv("STACKVEND_MANAGED_TAG_VALUE", raising=False)
    monkeypatch.delenv("STACKVEND_GUARD_FIRESTORE_DATABASE", raising=False)


# ---------------------------------------------------------------------------------------------- the member
def test_member_is_the_cc_runtime_sa_of_this_host_never_hardcoded():
    assert CCL.control_center_member(f.HOST) == CC_MEMBER
    assert CCL.control_center_member("other-host") == \
        "serviceAccount:sa-stackvend-control-center@other-host.iam.gserviceaccount.com"
    with pytest.raises(CCL.CCLogReaderGrantError):
        CCL.control_center_member("  ")


def test_cc_account_id_matches_the_platform_terraform_persona():
    tf = open(os.path.join(f.REPO_ROOT, "infra", "platform", "destructive_guard.tf")).read()
    assert '"product-control-center-ui"    = local.cc_sa_email' in tf
    assert f'google_service_account.stackvend_personas["{VENDING_MAIN.rb.CONTROL_CENTER_ACCOUNT_ID}"].email' in tf


# ---------------------------------------------------------------------------------------------- vend time
def test_vend_grants_logging_viewer_to_the_cc_and_changes_nothing_else(vmain):
    iam = _iam(policies={CHILD: {"version": 1, "etag": "BwX1", "bindings": [
        {"role": "roles/viewer", "members": ["user:v@example.com"]},
        {"role": ROLE, "members": ["user:ops@example.com"]}]}})
    res = _vend(_engine(vmain, iam))
    assert res["status"] == "PROJECT_VENDED" and res["cc_log_reader"] == "GRANTED"
    [(_, pid, policy)] = iam.sets()
    assert pid == CHILD and policy["etag"] == "BwX1"
    assert _viewers(policy) == [{"role": ROLE, "members": ["user:ops@example.com", CC_MEMBER]}]
    assert {"role": "roles/viewer", "members": ["user:v@example.com"]} in policy["bindings"]
    assert len(policy["bindings"]) == 2


def test_negative_already_granted_writes_nothing(vmain):
    """Do No Harm: a project that already has the grant (re-vend, adopted, redeploy) gets zero writes."""
    before = {"version": 1, "etag": "e1", "bindings": [{"role": ROLE, "members": [CC_MEMBER]}]}
    iam = _iam(policies={CHILD: before})
    res = _vend(_engine(vmain, iam))
    assert res["cc_log_reader"] == "ALREADY_GRANTED" and iam.sets() == []
    assert iam.policies[CHILD] == before


def test_a_conditional_binding_is_not_the_grant(vmain):
    cond = {"role": ROLE, "members": [CC_MEMBER], "condition": {"title": "t", "expression": "false"}}
    iam = _iam(policies={CHILD: {"bindings": [cond]}})
    assert _vend(_engine(vmain, iam))["cc_log_reader"] == "GRANTED"
    [(_, _, policy)] = iam.sets()
    assert cond in policy["bindings"] and {"role": ROLE, "members": [CC_MEMBER]} in policy["bindings"]


def test_transient_conflict_is_retried(vmain):
    iam = _iam(fail_set=[409, 503])
    assert _vend(_engine(vmain, iam))["cc_log_reader"] == "GRANTED"
    assert len(iam.sets()) == 3


@pytest.mark.parametrize("iam_kw", [{"fail_set": [403]}, {"fail_get": [403]}, {"fail_get": [404, 404, 404]},
                                    {"drop_set": True}])
def test_a_grant_that_cannot_be_made_fails_the_vend_typed(vmain, iam_kw):
    db = f.FakeDB()
    with pytest.raises(VendingFailure) as ei:
        _vend(_engine(vmain, _iam(**iam_kw), db=db))
    assert ei.value.error_class == "VENDING.CC_LOG_READER_GRANT_FAILED"
    assert ei.value.stage == "vending.cc_log_reader"
    # the project is recorded and provenanced first, so a re-run reuses it
    assert db.doc("workloads/fresh-svc")["project_id"] == CHILD


def test_the_host_project_is_never_granted():
    iam = _iam()
    with pytest.raises(CCL.CCLogReaderGrantError):
        CCL.ensure_grant(iam, f.HOST, host_project_ids=frozenset({f.HOST}), member=CC_MEMBER)
    assert iam.calls == []


def test_vend_calls_the_grant_after_the_record_and_before_runner_identity():
    src = open(os.path.join(f.VENDING_DIR, "vending.py")).read()
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "vend_gcp_project")
    body = ast.get_source_segment(src, fn)
    assert body.index('collection("workloads").document(product_id).set(workload_record') \
        < body.index("self._grant_cc_log_reader(target_project_id)") < body.index("self._ensure_runner_identity(")


# ---------------------------------------------------------------------------------------------- backfill
def _world():
    db, crm = f.make_world()
    return db, f.make_ctx(db, crm)


def _run(ctx, iam, **kw):
    return CCL.backfill(ctx, iam, host_project_id=f.HOST, caller_email=f.CC_SA, operator_email=f.ADMIN,
                        retry_delay=0.0, sleep=lambda s: None, **kw)


def test_backfill_grants_a_provenance_proven_workload_and_audits_it():
    db, ctx = _world()
    iam = _iam()
    out = _run(ctx, iam)
    assert out["results"] == [{"product_id": f.PID, "project_id": f.PROJECT, "decision": "GRANTED"}]
    assert out["member"] == CC_MEMBER and out["counts"] == {"GRANTED": 1}
    [(_, pid, policy)] = iam.sets()
    assert pid == f.PROJECT and _viewers(policy) == [{"role": ROLE, "members": [CC_MEMBER]}]
    assert [a["status"] for a in db.audit_records()] == ["ATTEMPT", "GRANTED"]
    assert {a["action"] for a in db.audit_records()} == {"CC_LOG_READER_BACKFILL"}


def test_negative_backfill_is_idempotent():
    db, ctx = _world()
    iam = _iam()
    _run(ctx, iam)
    audits = len(db.audit_records())
    out = _run(ctx, iam)
    assert out["results"][0]["decision"] == "ALREADY_GRANTED"
    assert len(iam.sets()) == 1 and len(db.audit_records()) == audits


def test_backfill_dry_run_writes_nothing():
    db, ctx = _world()
    iam = _iam()
    out = _run(ctx, iam, dry_run=True)
    assert out["results"][0]["decision"] == "WOULD_GRANT" and iam.sets() == [] and db.audit_records() == []


@pytest.mark.parametrize("mutate,code", [
    (lambda db: db.docs[f"workloads/{f.PID}"].update(status="DECOMMISSIONED"), "SKIPPED:CLOSED"),
    (lambda db: db.docs[f"workloads/{f.PID}"].update(project_id="someone-elses-project"), "SKIPPED:LEDGER_MISMATCH"),
    (lambda db: db.docs[f"workloads/{f.PID}"].update(is_castor=True), "SKIPPED:PLATFORM_WORKLOAD"),
    (lambda db: db.docs.pop(f"workloads/{f.PID}"), "SKIPPED:LEDGER_MISSING"),
    (lambda db: db.docs[f"workload_provenance/{f.PID}"].update(created_by="someone"), "SKIPPED:NOT_PROVENANCED"),
    (lambda db: db.docs.__setitem__("workloads/twin", {"product_id": "twin", "project_id": f.PROJECT}),
     "SKIPPED:LEDGER_MISMATCH"),
])
def test_backfill_grants_only_where_provenance_and_ledger_agree(mutate, code):
    db, ctx = _world()
    mutate(db)
    iam = _iam()
    out = _run(ctx, iam)
    assert [r["decision"] for r in out["results"] if r["product_id"] == f.PID] == [code]
    assert iam.calls == []


def test_backfill_never_grants_on_the_host_project():
    db, ctx = _world()
    db.docs[f"workloads/{f.PID}"]["project_id"] = f.HOST
    db.docs[f"workload_provenance/{f.PID}"]["project_id"] = f.HOST
    iam = _iam()
    assert _run(ctx, iam)["results"][0]["decision"] == "SKIPPED:HOST_PROJECT" and iam.calls == []


def test_backfill_failure_is_typed_per_workload_and_audited():
    db, ctx = _world()
    iam = _iam(fail_set=[403])
    [r] = _run(ctx, iam)["results"]
    assert r["decision"] == "FAILED" and r["error_class"] == "VENDING.CC_LOG_READER_GRANT_FAILED"
    assert [a["status"] for a in db.audit_records()] == ["ATTEMPT", "FAILED"]


def test_backfill_unreadable_guard_database_raises():
    db, ctx = _world()
    ctx.store.guard_db = VDG.UnavailableDB("down")
    with pytest.raises(VDG.StoreUnavailable):
        _run(ctx, _iam())


# ---------------------------------------------------------------------------------------------- route
@pytest.fixture
def client(vmain, env, monkeypatch):
    db, ctx = _world()
    iam = _iam()
    eng = _engine(vmain, iam, db=db)
    eng._guard_context = ctx
    monkeypatch.setattr(vmain, "vending_engine", eng)
    monkeypatch.setattr(vmain, "CALLER_TOKEN_VERIFIER", fake_verifier)
    return db, iam, TestClient(vmain.app)


def test_route_runs_the_backfill_for_the_cc(client):
    db, iam, c = client
    r = c.post("/guard/cc-log-reader/backfill", headers={"Authorization": f"Bearer {GOOD}"},
               json={"operator_email": f.ADMIN})
    assert r.status_code == 200, r.text
    assert r.json()["counts"] == {"GRANTED": 1} and len(iam.sets()) == 1


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer forged"}])
def test_route_refuses_unauthenticated_callers_before_any_call(client, headers):
    db, iam, c = client
    r = c.post("/guard/cc-log-reader/backfill", headers=headers, json={})
    assert r.status_code == 401 and iam.calls == [] and db.audit_records() == []
