"""
Lane 18 single window (S1 code RT fixes 1-4 + S0 blocking item B1) on apps/project-vending. Hermetic fakes only.

Fix 1  an approval whose approved_at lies in the future (beyond the clock skew) is APPROVAL_EXPIRED (was: valid for as
       long as approved_at says), on decommission and on CONFIRM_SANDBOX.
Fix 2  (a) StackVend never releases a lien: any lien refuses LIEN_PRESENT 409, even one named in provenance.liens[];
       the REST adapter has no lien delete (register row L18-g).
Fix 3  the F8 re-check right before the delete re-reads ancestry and liens, not only id/state/tag.
Fix 4  the three apps/project-vending/test_vending.py assertions pin the exact refusal code (that file is never run
       here, AGENTS.md); the twins below run the same scenarios hermetically.
B1     a project created in this call gets roles/owner for exactly STACKVEND_CHILD_PROJECT_OWNER_MEMBERS (REST, fails the
       vend loudly, no-op when unset; never for a reused or adopted project).
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import os
from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import destructive_guard_fakes as f
from destructive_guard_fakes import dg
from test_destructive_guard_vending import (  # noqa: F401  (fixtures)
    FakeStorage, VENDING_MAIN, _engine, _post, _vend_crm, _vend_engine, env, fake_verifier, vmain, world,
    _freeze_setting_without_firestore,  # FD-4CU: autouse, the default (on) without a Firestore settings read
)

PD = dg.ActionClass.PROJECT_DECOMMISSION
# The destructive_guard / googleapiclient module objects the loaded vending code actually uses (the root conftest's
# per-module sys.modules sandbox can give this file other instances of the same modules).
_VENDING_GLOBALS = VENDING_MAIN.ProjectRepoVendingEngine.vend_gcp_project.__globals__
VDG = _VENDING_GLOBALS["dg"]


def _ctx_world(**approval):
    db, crm = f.make_world()
    f.add_approval(db, **approval)
    return db, crm, f.make_ctx(db, crm)


# ---------------------------------------------------------------------------------------------- Fix 1
@pytest.mark.parametrize("approved_offset,expires_offset", [
    (timedelta(days=365), timedelta(days=365, minutes=14)),     # probe P1: valid for a year before the fix
    (timedelta(minutes=5), timedelta(minutes=19)),
    (timedelta(seconds=11), timedelta(minutes=14)),              # just beyond the 10 s skew
])
def test_future_approved_at_is_expired(approved_offset, expires_offset):
    db, crm, ctx = _ctx_world(approved_at=f.iso(f.NOW + approved_offset), expires_at=f.iso(f.NOW + expires_offset))
    with pytest.raises(dg.DeletionRefused) as ei:
        dg.assert_deletable(dg.DeletionTarget(f.PID), action_class=PD, approval_id=f.APPROVAL, caller_email=f.CC_SA,
                            ctx=ctx)
    assert ei.value.code == "APPROVAL_EXPIRED"
    assert crm.mutating_calls() == [] and db.audit_records() == []


def test_approved_at_within_clock_skew_is_accepted():
    db, crm, ctx = _ctx_world(approved_at=f.iso(f.NOW + timedelta(seconds=5)),
                              expires_at=f.iso(f.NOW + timedelta(minutes=14)))
    v = dg.assert_deletable(dg.DeletionTarget(f.PID), action_class=PD, approval_id=f.APPROVAL, caller_email=f.CC_SA,
                            ctx=ctx)
    assert v.approved_by == f.ADMIN


def test_expires_before_approved_is_expired():
    db, crm, ctx = _ctx_world(approved_at=f.iso(f.NOW), expires_at=f.iso(f.NOW - timedelta(minutes=1)))
    with pytest.raises(dg.DeletionRefused) as ei:
        dg.assert_deletable(dg.DeletionTarget(f.PID), action_class=PD, approval_id=f.APPROVAL, caller_email=f.CC_SA,
                            ctx=ctx)
    assert ei.value.code == "APPROVAL_EXPIRED"


def test_confirm_sandbox_with_future_approval_is_refused(vmain, env, monkeypatch):
    db, crm = f.make_world(sandbox=False)
    f.add_approval(db, action="CONFIRM_SANDBOX", approved_at=f.iso(f.NOW + timedelta(days=30)),
                   expires_at=f.iso(f.NOW + timedelta(days=30, minutes=10)))
    ctx = f.make_ctx(db, crm)
    monkeypatch.setattr(vmain, "vending_engine", _engine(vmain, db, crm, ctx))
    monkeypatch.setattr(vmain, "CALLER_TOKEN_VERIFIER", fake_verifier)
    r = TestClient(vmain.app).post(f"/projects/{f.PID}/lifecycle", headers={"Authorization": "Bearer good-token"},
                                   json={"action": "CONFIRM_SANDBOX", "ttl_days": 7, "approval_id": f.APPROVAL})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "APPROVAL_EXPIRED"
    assert crm.mutating_calls() == [] and db.doc(f"destructive_approvals/{f.APPROVAL}")["status"] == "APPROVED"


# ---------------------------------------------------------------------------------------------- Fix 2
def test_lien_named_in_provenance_refuses_and_nothing_is_released(world):
    db, crm, ctx, storage, client = world
    db.docs[f"workload_provenance/{f.PID}"]["liens"] = ["liens/owner-placed-do-not-delete"]
    crm.liens[f.NUMBER] = [{"name": "liens/owner-placed-do-not-delete"}]
    r = _post(client)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "LIEN_PRESENT"
    assert crm.count("delete_lien") == 0 and crm.count("delete_project") == 0 and storage.ops == []


def test_rest_adapter_has_no_lien_delete():
    assert not hasattr(dg.RestCRM, "delete_lien")
    assert not hasattr(dg.GuardVerdict, "recorded_liens_present")


# ---------------------------------------------------------------------------------------------- Fix 3
def _flip_on_recheck(crm, method, mutate):
    """Run `mutate(crm)` right after the guard's first call of `method`, i.e. between the check and the delete."""
    orig = getattr(crm, method)
    seen = {"n": 0}

    def wrapped(*args):
        out = orig(*args)
        seen["n"] += 1
        if seen["n"] == 1:
            mutate(crm)
        return out

    setattr(crm, method, wrapped)


def test_project_moved_out_of_managed_folder_before_delete_is_refused(world):
    """Probe P5: re-parented between check 7 and the delete -> 502 NOT_IN_MANAGED_FOLDER, zero deletes."""
    db, crm, ctx, storage, client = world

    def reparent(c):
        c.ancestry[f.PROJECT][2] = {"resourceId": {"type": "folder", "id": "9999"}}

    _flip_on_recheck(crm, "list_liens", reparent)  # check 8 runs after check 7, before the re-check
    r = _post(client)
    assert r.status_code == 502 and r.json()["detail"]["code"] == "NOT_IN_MANAGED_FOLDER"
    assert crm.count("delete_project") == 0 and storage.ops == []
    assert db.doc(f"workloads/{f.PID}")["status"] == "DECOMMISSION_FAILED"
    assert db.doc(f"destructive_approvals/{f.APPROVAL}")["status"] == "EXECUTION_FAILED"


def test_lien_added_before_delete_is_refused(world):
    db, crm, ctx, storage, client = world

    def add_lien(c):
        c.liens[f.NUMBER] = [{"name": "liens/late"}]

    _flip_on_recheck(crm, "list_liens", add_lien)
    r = _post(client)
    assert r.status_code == 502 and r.json()["detail"]["code"] == "LIEN_PRESENT"
    assert crm.count("delete_project") == 0 and crm.count("delete_lien") == 0


def test_recheck_reads_ancestry_and_liens():
    db, crm, ctx = _ctx_world()
    v = dg.assert_deletable(dg.DeletionTarget(f.PID), action_class=PD, approval_id=f.APPROVAL, caller_email=f.CC_SA,
                            ctx=ctx)
    before = len(crm.calls)
    dg.recheck_before_delete(v, ctx)
    assert crm.calls[before:] == [("get_project", f.NUMBER), ("list_tag_bindings", f.NUMBER),
                                  ("get_ancestry", f.PROJECT), ("list_liens", f.NUMBER)]
    assert crm.mutating_calls() == []


# ---------------------------------------------------------------------------------------------- Fix 4
TEST_VENDING = os.path.join(f.VENDING_DIR, "test_vending.py")


def _function_source(name):
    src = open(TEST_VENDING, encoding="utf-8").read()
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node)
    raise AssertionError(f"{name} not found in apps/project-vending/test_vending.py")


@pytest.mark.parametrize("name,code", [
    ("test_decommission_workload_requires_guard", '"LEDGER_UNPROVENANCED"'),
    ("test_decommission_platform_guard_blocked", '"PLATFORM_WORKLOAD"'),
    ("test_rest_decommission_and_redeploy_endpoints", '"CALLERS_UNCONFIGURED"'),
])
def test_vending_unit_tests_pin_exact_codes(name, code):
    """apps/project-vending/test_vending.py is not run by this suite; its three lane 18 assertions must name the exact
    refusal they test (code RT Fix 4), not pass on GUARD_UNCONFIGURED / 'in (401, 503)'."""
    body = _function_source(name)
    assert code in body
    assert "in (401, 503)" not in body


def _mock_engine(vmain, doc):
    db = MagicMock()
    snap = MagicMock(exists=True)
    snap.to_dict.return_value = doc
    db.collection.return_value.document.return_value.get.return_value = snap
    crm = MagicMock()
    eng = vmain.ProjectRepoVendingEngine(platform_project_id="test-platform-proj", firestore_client=db,
                                         crm_service=crm, storage_client=MagicMock())
    return eng, crm


@pytest.fixture
def guard_env(monkeypatch):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", "4242")
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", "tagValues/1")
    monkeypatch.setenv("PROJECT_ID", "test-platform-proj")
    monkeypatch.delenv("PLATFORM_PROJECT_ID", raising=False)
    monkeypatch.delenv("STACKVEND_GUARD_FIRESTORE_DATABASE", raising=False)


def test_twin_unprovenanced_workload_refused(vmain, guard_env):
    eng, crm = _mock_engine(vmain, {"product_id": "auth-service", "project_id": "castor-auth-service-507121",
                                    "status": "ACTIVE", "is_castor": False})
    with pytest.raises(VDG.DeletionRefused) as ei:
        eng.decommission_workload(product_id="auth-service", operator_email="admin@example.com")
    assert ei.value.code == "LEDGER_UNPROVENANCED"
    crm.projects.return_value.delete.assert_not_called()


def test_twin_platform_workload_refused(vmain, guard_env):
    eng, crm = _mock_engine(vmain, {})
    with pytest.raises(VDG.DeletionRefused) as ei:
        eng.decommission_workload(product_id="project-castor", operator_email="admin@example.com")
    assert ei.value.code == "PLATFORM_WORKLOAD"


def test_twin_rest_decommission_unconfigured_callers(vmain, monkeypatch):
    monkeypatch.delenv("DESTRUCTIVE_CALLERS", raising=False)
    r = TestClient(vmain.app).post("/projects/demo-service/decommission", json={"operator_email": "x@example.com"})
    assert r.status_code == 503 and r.json()["detail"]["code"] == "CALLERS_UNCONFIGURED"


# ---------------------------------------------------------------------------------------------- B1
DEV_SA = "serviceAccount:sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com"
OPS = "group:ops@example.com"


class FakeIAM:
    def __init__(self, policy=None, fail_get=None, fail_set=None, drop_members=False):
        self.policy = policy if policy is not None else {
            "version": 1, "etag": "BwX1", "bindings": [{"role": "roles/owner", "members": ["user:creator@example.com"]},
                                                       {"role": "roles/viewer", "members": ["user:v@example.com"]}]}
        self.fail_get, self.fail_set, self.drop_members = list(fail_get or []), list(fail_set or []), drop_members
        self.calls = []

    def get_iam_policy(self, project_id):
        self.calls.append(("get", project_id))
        if self.fail_get:
            raise VDG.CRMUnavailable("getIamPolicy", self.fail_get.pop(0))
        return dict(self.policy, bindings=[dict(b, members=list(b["members"])) for b in self.policy["bindings"]])

    def set_iam_policy(self, project_id, policy):
        self.calls.append(("set", project_id, policy))
        if self.fail_set:
            raise VDG.CRMUnavailable("setIamPolicy", self.fail_set.pop(0))
        if self.drop_members:
            return {"bindings": []}
        self.policy = policy
        return policy


def _b1_engine(vmain, iam, db=None, crm=None):
    eng = _vend_engine(vmain, db or f.FakeDB(), crm or _vend_crm())
    eng._iam_client = iam
    eng.owner_grant_retry_delay = 0.0
    # The RT14-31 Control Center log-reader grant (step 4c, tests/test_rt14_31_cc_log_reader.py) uses the same IAM
    # client; here it is recorded apart so these B1 tests see only the owner grant's calls.
    eng.cc_log_grants = []
    eng._grant_cc_log_reader = lambda project_id: eng.cc_log_grants.append(project_id) or "GRANTED"
    return eng


@pytest.fixture
def b1_env(monkeypatch):
    monkeypatch.delenv("STACKVEND_MANAGED_TAG_VALUE", raising=False)
    monkeypatch.delenv("STACKVEND_GUARD_FIRESTORE_DATABASE", raising=False)
    monkeypatch.setenv("STACKVEND_CHILD_PROJECT_OWNER_MEMBERS", f" {DEV_SA} , {OPS},{DEV_SA}")


def test_owner_granted_to_exact_members_on_created_project(vmain, b1_env):
    iam = FakeIAM()
    res = _b1_engine(vmain, iam).vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT,
                                                  force_new_project_id="fresh-svc-123abc")
    assert res["status"] == "PROJECT_VENDED"
    [(_, pid, policy)] = [c for c in iam.calls if c[0] == "set"]
    assert pid == "fresh-svc-123abc"
    owners = [b for b in policy["bindings"] if b["role"] == "roles/owner"]
    assert owners == [{"role": "roles/owner", "members": ["user:creator@example.com", DEV_SA, OPS]}]
    assert {"role": "roles/viewer", "members": ["user:v@example.com"]} in policy["bindings"]
    assert policy["etag"] == "BwX1"


def test_owner_grant_noop_when_env_unset(vmain, monkeypatch):
    monkeypatch.delenv("STACKVEND_CHILD_PROJECT_OWNER_MEMBERS", raising=False)
    monkeypatch.delenv("STACKVEND_MANAGED_TAG_VALUE", raising=False)
    iam = FakeIAM()
    res = _b1_engine(vmain, iam).vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT,
                                                  force_new_project_id="fresh-svc-123abc")
    assert res["status"] == "PROJECT_VENDED" and iam.calls == []


def test_owner_grant_failure_fails_the_vend_before_billing(vmain, b1_env):
    iam = FakeIAM(fail_set=[403])
    crm = _vend_crm()
    eng = _b1_engine(vmain, iam, crm=crm)
    eng.billing_account_id = "billingAccounts/000000-000000-000000"
    with pytest.raises(RuntimeError, match="CHILD_OWNER_GRANT_FAILED") as ei:
        eng.vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT, force_new_project_id="fresh-svc-123abc")
    eng.billing.projects.return_value.updateBillingInfo.assert_not_called()
    # Window RT fix 1: the only safe recovery is delete-then-retry (a retried vend adopts the project via 409 without
    # B1, provenance or tag), so the message must say exactly that and must not suggest a hand grant.
    msg = str(ei.value)
    assert "delete projects/fresh-svc-123abc by hand, then retry the vend" in msg
    assert "grant roles/owner by hand" not in msg


def test_owner_grant_retries_404_right_after_create(vmain, b1_env):
    """H5: getIamPolicy on a just-created project can answer 404 (CRM eventual consistency): retried, not fatal."""
    iam = FakeIAM(fail_get=[404, 404])
    res = _b1_engine(vmain, iam).vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT,
                                                  force_new_project_id="fresh-svc-123abc")
    assert res["status"] == "PROJECT_VENDED"
    assert [c[0] for c in iam.calls] == ["get", "get", "get", "set"]


def test_owner_grant_persistent_404_still_fails_the_vend(vmain, b1_env):
    """H5 negative: a 404 that survives every attempt still fails the vend loudly (no infinite retry, no skip)."""
    iam = FakeIAM(fail_get=[404, 404, 404])
    with pytest.raises(RuntimeError, match="CHILD_OWNER_GRANT_FAILED"):
        _b1_engine(vmain, iam).vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT,
                                                force_new_project_id="fresh-svc-123abc")
    assert [c[0] for c in iam.calls] == ["get", "get", "get"]


def test_owner_grant_403_is_not_retried(vmain, b1_env):
    """H5 negative: a permission error is final on the first attempt (only the exact transient set is retried)."""
    iam = FakeIAM(fail_get=[403])
    with pytest.raises(RuntimeError, match="CHILD_OWNER_GRANT_FAILED"):
        _b1_engine(vmain, iam).vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT,
                                                force_new_project_id="fresh-svc-123abc")
    assert [c[0] for c in iam.calls] == ["get"]


def test_owner_grant_retries_transient_conflict(vmain, b1_env):
    iam = FakeIAM(fail_set=[409, 503])
    res = _b1_engine(vmain, iam).vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT,
                                                  force_new_project_id="fresh-svc-123abc")
    assert res["status"] == "PROJECT_VENDED" and sum(1 for c in iam.calls if c[0] == "set") == 3


def test_owner_grant_unverified_result_fails(vmain, b1_env):
    with pytest.raises(RuntimeError, match="CHILD_OWNER_GRANT_FAILED"):
        _b1_engine(vmain, FakeIAM(drop_members=True)).vend_gcp_project(
            "fresh-svc", "tr-1", folder_id=f.ROOT, force_new_project_id="fresh-svc-123abc")


@pytest.mark.parametrize("bad", ["sa-castor-developer@p.iam.gserviceaccount.com", "domain:example.com",
                                 "serviceAccount:"])
def test_owner_grant_invalid_member_fails(vmain, monkeypatch, bad):
    monkeypatch.setenv("STACKVEND_CHILD_PROJECT_OWNER_MEMBERS", bad)
    iam = FakeIAM()
    with pytest.raises(RuntimeError, match="CHILD_OWNER_GRANT_FAILED"):
        _b1_engine(vmain, iam).vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT,
                                                force_new_project_id="fresh-svc-123abc")
    assert iam.calls == []


def test_owner_grant_skipped_for_reused_project(vmain, b1_env):
    iam = FakeIAM()
    db = f.FakeDB()
    db.docs["workloads/old-svc"] = {"product_id": "old-svc", "project_id": "existing-proj-1", "status": "ACTIVE"}
    res = _b1_engine(vmain, iam, db=db, crm=_vend_crm(project_id="existing-proj-1")).vend_gcp_project(
        "old-svc", "tr-2", folder_id=f.ROOT)
    assert res["status"] == "PROJECT_VENDED" and iam.calls == []


def test_owner_grant_skipped_for_adopted_409_project(vmain, b1_env):
    HttpError = _VENDING_GLOBALS["HttpError"]
    if not isinstance(HttpError, type):
        pytest.skip("googleapiclient replaced by a stub in this process")
    iam = FakeIAM()
    crm = _vend_crm(create_side_effect=HttpError(MagicMock(status=409, reason="Conflict"), b"already exists"))
    _b1_engine(vmain, iam, crm=crm).vend_gcp_project("adopt-svc", "tr-3", folder_id=f.ROOT,
                                                     force_new_project_id="brownfield-proj")
    assert iam.calls == []


# ---------------------------------------------------------------------------------------------- H7 (window RT)
@pytest.mark.parametrize("raw,clean", [("  Mixed-Svc ", "mixed-svc"), ("fresh-svc", "fresh-svc")])
def test_vend_all_keys_the_project_and_ledger_by_the_normalized_id(vmain, raw, clean):
    """vend_all reads the ledger as the normalized id, so the project, labels, provenance and its own github_repo write
    use that id too (lowercase input, which every caller sends today, is unchanged)."""
    db = f.FakeDB()
    eng = _vend_engine(vmain, db, _vend_crm())
    seen = {}

    def fake_gcp(product_id, trace_id, **kw):
        seen["gcp"] = product_id
        return {"project_id": "p-1", "project_number": f.NUMBER}

    eng.vend_gcp_project = fake_gcp
    eng.vend_github_repo = lambda product_id, **kw: {"full_name": f"acme/castor-{clean}", "repo_name": f"castor-{clean}"}
    res = eng.vend_all(raw, "tr-h7", vcs_provider="GITHUB")
    assert seen["gcp"] == clean and res["status"] == "WORKLOAD_VENDED"
    assert db.doc(f"workloads/{clean}")["github_repo"] == f"acme/castor-{clean}"
