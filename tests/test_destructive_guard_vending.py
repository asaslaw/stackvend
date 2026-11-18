"""
Lane 18 S1 (U1): vending decommission is authenticated and guarded; the executor deletes by project NUMBER after a
re-check; failures are recorded honestly; provenance is written only for projects vending created in that call;
sandbox lifecycle goes through vending; non-delete vending paths are unchanged (Do No Harm). Hermetic fakes only.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import destructive_guard_fakes as f
from destructive_guard_fakes import dg

AUD = "https://project-repo-vending-service-abc-uc.a.run.app"
GOOD = "good-token"
TOKENS = {
    GOOD: {"iss": "https://accounts.google.com", "aud": AUD, "email": f.CC_SA, "email_verified": True},
    "dev-token": {"iss": "https://accounts.google.com", "aud": AUD, "email": f.OTHER_SA, "email_verified": True},
    "unverified": {"iss": "https://accounts.google.com", "aud": AUD, "email": f.CC_SA, "email_verified": False},
    "evil-iss": {"iss": "https://evil.example", "aud": AUD, "email": f.CC_SA, "email_verified": True},
}


def fake_verifier(token, audiences):
    if token not in TOKENS:
        raise ValueError("Token has wrong audience / bad signature")
    return dict(TOKENS[token])


class FakeStorage:
    def __init__(self, has_state=True):
        self.objects = {"workloads/shop-api/default.tfstate": b"{}"} if has_state else {}
        self.ops = []

    def bucket(self, name):
        storage = self

        class _Blob:
            def __init__(self, path):
                self.name = path

            def exists(self):
                return self.name in storage.objects

            def delete(self):
                storage.ops.append(("delete", self.name))
                storage.objects.pop(self.name)

        class _Bucket:
            def blob(self, path):
                return _Blob(path)

            def copy_blob(self, blob, bucket, new_name):
                storage.ops.append(("copy", blob.name, new_name))
                storage.objects[new_name] = storage.objects[blob.name]

        return _Bucket()


# Imported at collection time: the root conftest snapshots each test module's sys.modules view at import (FD-05A).
VENDING_MAIN = f.load_vending_main()


@pytest.fixture
def vmain():
    return VENDING_MAIN


@pytest.fixture(autouse=True)
def _freeze_setting_without_firestore(monkeypatch):
    """FD-4CU / FD-4CU-c: a vend reads platform settings (governance.freeze_new_workloads, and the default code-review
    setting for a record without one), a strict read that would build a real Firestore client here. These tests use
    the defaults without a Firestore read; the settings themselves are covered by
    tests/test_fd4cu_freeze_new_workloads.py."""
    import importlib
    live = importlib.import_module("shared.settings")   # the module the vending engine's lazy imports resolve to
    live.invalidate_settings_cache()
    monkeypatch.setattr(live, "get_platform_settings", lambda *a, **k: live.PlatformSettings())
    yield
    live.invalidate_settings_cache()


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("DESTRUCTIVE_CALLERS", f"{f.CC_SA}, {f.OTHER_SA}")
    monkeypatch.setenv("VENDING_SERVICE_URL", AUD)
    monkeypatch.setenv("TEST_MODE", "true")  # must not bypass anything


def _engine(vmain, db, crm, ctx, storage=None):
    eng = vmain.ProjectRepoVendingEngine(iam_client=f.FakeChildIAM(), platform_project_id=f.HOST, firestore_client=db, crm_service=MagicMock(),
                                         storage_client=storage or FakeStorage(), guard_context=ctx)
    eng.tfstate_bucket = "castor-tfstate-test"
    return eng


@pytest.fixture
def world(vmain, env, monkeypatch):
    db, crm = f.make_world()
    f.add_approval(db)
    ctx = f.make_ctx(db, crm)
    storage = FakeStorage()
    monkeypatch.setattr(vmain, "vending_engine", _engine(vmain, db, crm, ctx, storage))
    monkeypatch.setattr(vmain, "CALLER_TOKEN_VERIFIER", fake_verifier)
    return db, crm, ctx, storage, TestClient(vmain.app)


def _post(client, pid=f.PID, token=GOOD, body=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post(f"/projects/{pid}/decommission", headers=headers,
                       json={"approval_id": f.APPROVAL} if body is None else body)


# ---------------------------------------------------------------------------------------------- authentication
@pytest.mark.parametrize("headers,code", [
    ({}, 401), ({"Authorization": "Basic Zm9v"}, 401), ({"Authorization": "Bearer"}, 401),
    ({"Authorization": "bearer good-token"}, 401), ({"Authorization": "Bearer forged"}, 401),
    ({"Authorization": "Bearer evil-iss"}, 401), ({"Authorization": "Bearer unverified"}, 403)])
def test_unauthenticated_or_bad_token_refused_before_any_read(world, headers, code):
    db, crm, ctx, storage, client = world
    reads_before = len(crm.calls)
    r = client.post(f"/projects/{f.PID}/decommission", headers=headers, json={"approval_id": f.APPROVAL})
    assert r.status_code == code
    assert crm.calls[reads_before:] == [] and db.writes == [] and storage.ops == []


def test_non_allow_listed_caller_refused(world, monkeypatch):
    db, crm, ctx, storage, client = world
    monkeypatch.setenv("DESTRUCTIVE_CALLERS", f.CC_SA)
    r = _post(client, token="dev-token")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "CALLER_NOT_ALLOWED"
    assert crm.calls == []


@pytest.mark.parametrize("var", ["DESTRUCTIVE_CALLERS", "VENDING_SERVICE_URL"])
def test_unconfigured_auth_is_503(world, monkeypatch, var):
    db, crm, ctx, storage, client = world
    monkeypatch.delenv(var)
    assert _post(client).status_code == 503
    assert crm.calls == []


def test_audience_comes_from_vending_service_url(world, monkeypatch, vmain):
    db, crm, ctx, storage, client = world
    seen = {}

    def verifier(token, audiences):
        seen["aud"] = audiences
        return fake_verifier(token, audiences)

    monkeypatch.setattr(vmain, "CALLER_TOKEN_VERIFIER", verifier)
    monkeypatch.setenv("VENDING_SERVICE_URL", AUD + "/")
    _post(client)
    assert seen["aud"] == [AUD]


def test_token_with_other_audience_refused(world, monkeypatch):
    db, crm, ctx, storage, client = world
    monkeypatch.setitem(TOKENS, "other-aud", {"iss": "accounts.google.com", "aud": "https://other.run.app",
                                              "email": f.CC_SA, "email_verified": True})
    assert _post(client, token="other-aud").status_code == 401


# ---------------------------------------------------------------------------------------------- executor
def test_legit_guarded_delete_by_number(world):
    db, crm, ctx, storage, client = world
    r = _post(client)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "DECOMMISSIONED" and body["deleted_project_number"] == f.NUMBER
    assert crm.mutating_calls() == [("delete_project", f.NUMBER)]
    # F8 + S1 code RT Fix 3: a fresh GET by number, tag list, ancestry and lien list immediately precede the delete
    i = crm.calls.index(("delete_project", f.NUMBER))
    assert crm.calls[i - 4:i] == [("get_project", f.NUMBER), ("list_tag_bindings", f.NUMBER),
                                  ("get_ancestry", f.PROJECT), ("list_liens", f.NUMBER)]
    w = db.doc(f"workloads/{f.PID}")
    assert w["status"] == "DECOMMISSIONED" and w["current_spend_usd"] == 0.0
    assert w["decommissioned_by"] == f.ADMIN and w["decommission_crm_operation"] == f"operations/delete-{f.NUMBER}"
    appr = db.doc(f"destructive_approvals/{f.APPROVAL}")
    assert appr["status"] == "EXECUTED" and appr["consumed_by"] == f.CC_SA
    assert ("copy", "workloads/shop-api/default.tfstate") == storage.ops[0][:2]
    audits = [a["action"] for a in db.audit_records()]
    assert audits[0] == "DESTRUCTIVE_GUARD_ALLOW" and "WORKLOAD_DECOMMISSIONED" in audits


def test_approval_cannot_be_reused(world):
    db, crm, ctx, storage, client = world
    assert _post(client).status_code == 200
    crm.projects[f.NUMBER]["state"] = "ACTIVE"
    db.docs[f"workloads/{f.PID}"]["status"] = "ACTIVE"
    r = _post(client)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "APPROVAL_CONSUMED"
    assert crm.count("delete_project") == 1


def test_decommission_without_approval_refused(world):
    db, crm, ctx, storage, client = world
    r = _post(client, body={})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "APPROVAL_MISSING"
    assert crm.mutating_calls() == [] and storage.ops == []


def test_body_product_id_must_match_path(world):
    db, crm, ctx, storage, client = world
    r = _post(client, body={"approval_id": f.APPROVAL, "product_id": "someone-else"})
    assert r.status_code == 400 and crm.calls == []


def test_unknown_action_class_rejected(world):
    db, crm, ctx, storage, client = world
    r = _post(client, body={"approval_id": f.APPROVAL, "action_class": "EPHEMERAL_TTL"})
    assert r.status_code == 422 and crm.calls == []


def test_firestore_503_refuses(world):
    db, crm, ctx, storage, client = world
    db.fail_paths.add(f"workloads/{f.PID}")
    r = _post(client)
    assert r.status_code == 503 and r.json()["detail"]["code"] == "LEDGER_UNAVAILABLE"
    assert crm.mutating_calls() == []


def test_url_pid_without_doc_refused_404(world):
    db, crm, ctx, storage, client = world
    f.add_project(crm, "some-other-teams-project", "555")
    r = _post(client, pid="some-other-teams-project")
    assert r.status_code == 404 and crm.mutating_calls() == []


def test_unlabelled_project_refused(world):
    db, crm, ctx, storage, client = world
    crm.projects[f.NUMBER]["labels"] = {}
    r = _post(client)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "NOT_STACKVEND_OWNED"
    assert crm.mutating_calls() == [] and db.doc(f"workloads/{f.PID}")["status"] == "ACTIVE"


def test_crm_delete_403_is_502_and_recorded(world):
    """FD26-04 inverted: a failed delete never returns DECOMMISSIONED, never archives, never zeroes spend."""
    db, crm, ctx, storage, client = world
    db.docs[f"workloads/{f.PID}"]["current_spend_usd"] = 12.5
    crm.fail["delete_project"] = 403
    r = _post(client)
    assert r.status_code == 502 and r.json()["detail"]["code"] == "DECOMMISSION_FAILED"
    w = db.doc(f"workloads/{f.PID}")
    assert w["status"] == "DECOMMISSION_FAILED" and w["current_spend_usd"] == 12.5
    assert db.doc(f"destructive_approvals/{f.APPROVAL}")["status"] == "EXECUTION_FAILED"
    assert storage.ops == []
    assert "WORKLOAD_DECOMMISSION_FAILED" in [a["action"] for a in db.audit_records()]


def test_tag_removed_between_check_and_delete_is_refused(world):
    db, crm, ctx, storage, client = world
    calls = {"n": 0}
    orig = crm.list_tag_bindings

    def flaky(number):
        calls["n"] += 1
        return orig(number) if calls["n"] == 1 else []

    crm.list_tag_bindings = flaky
    r = _post(client)
    assert r.status_code == 502 and r.json()["detail"]["code"] == "NOT_STACKVEND_OWNED"
    assert crm.count("delete_project") == 0
    assert db.doc(f"destructive_approvals/{f.APPROVAL}")["status"] == "EXECUTION_FAILED"


def test_provenance_listed_lien_is_never_released(world):
    """S1 code RT Fix 2(a) / row L18-g: a lien refuses even when provenance names it; nothing is deleted."""
    db, crm, ctx, storage, client = world
    db.docs[f"workload_provenance/{f.PID}"]["liens"] = ["liens/sv-1"]
    crm.liens[f.NUMBER] = [{"name": "liens/sv-1"}]
    r = _post(client)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "LIEN_PRESENT"
    assert crm.mutating_calls() == [] and storage.ops == []
    assert db.doc(f"destructive_approvals/{f.APPROVAL}")["status"] == "APPROVED"


def test_recorded_dns_deleted_after_the_project(world):
    db, crm, ctx, storage, client = world
    ctx.dns_zone, ctx.dns = "stackvend-zone", crm
    db.docs[f"workload_provenance/{f.PID}"]["dns_records"] = [{"name": "api.example.com.", "type": "A"}]
    assert _post(client).status_code == 200
    assert crm.mutating_calls() == [("delete_project", f.NUMBER),
                                    ("delete_dns_rrset", f.HOST, "stackvend-zone", "api.example.com.", "A")]


def test_recorded_dns_without_zone_is_reported_not_guessed(world):
    db, crm, ctx, storage, client = world
    db.docs[f"workload_provenance/{f.PID}"]["dns_records"] = [{"name": "api.example.com.", "type": "A"}]
    r = _post(client)
    assert r.status_code == 200 and r.json()["warnings"][0].startswith("DNS_RECORDS_NOT_DELETED")
    assert crm.count("delete_dns_rrset") == 0


def test_sandbox_ttl_by_ttl_caller(world):
    db, crm, ctx, storage, client = world
    sdb, scrm = f.make_world(sandbox=True)
    ctx.store, ctx.crm = f.TestStore(sdb), scrm
    ctx.dns = scrm
    r = _post(client, body={"action_class": "SANDBOX_TTL"})
    assert r.status_code == 200, r.text
    assert scrm.mutating_calls() == [("delete_project", f.NUMBER)]
    assert sdb.doc(f"workloads/{f.PID}")["decommission_action_class"] == "SANDBOX_TTL"


def test_decommission_of_a_workload_failed_before_deploy(world):
    """WORKLOAD-STATUS-PRE-DEPLOY-FAILURE: the gateway leaves FAILED on a vended workload whose run stopped early."""
    db, crm, ctx, storage, client = world
    db.docs[f"workloads/{f.PID}"]["status"] = "FAILED"
    r = _post(client)
    assert r.status_code == 200, r.text
    assert crm.mutating_calls() == [("delete_project", f.NUMBER)]
    assert db.doc(f"workloads/{f.PID}")["status"] == "DECOMMISSIONED"


def test_sandbox_ttl_of_a_workload_failed_before_deploy(world):
    db, crm, ctx, storage, client = world
    sdb, scrm = f.make_world(sandbox=True)
    sdb.docs[f"workloads/{f.PID}"]["status"] = "FAILED"
    ctx.store, ctx.crm = f.TestStore(sdb), scrm
    ctx.dns = scrm
    r = _post(client, body={"action_class": "SANDBOX_TTL"})
    assert r.status_code == 200, r.text
    assert scrm.mutating_calls() == [("delete_project", f.NUMBER)]


def test_decommission_of_a_failed_workload_that_never_got_a_project_is_refused_typed(world):
    """A vend that stopped before the project was recorded has no provenance: refused, nothing deleted (as PROVISIONING)."""
    db, crm, ctx, storage, client = world
    db.docs[f"workloads/{f.PID}"]["status"] = "FAILED"
    del db.docs[f"workload_provenance/{f.PID}"]
    r = _post(client)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "LEDGER_UNPROVENANCED"
    assert crm.mutating_calls() == []


def test_sandbox_ttl_from_non_ttl_caller_403(world):
    db, crm, ctx, storage, client = world
    sdb, scrm = f.make_world(sandbox=True)
    ctx.store, ctx.crm = f.TestStore(sdb), scrm
    r = _post(client, token="dev-token", body={"action_class": "SANDBOX_TTL"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "SANDBOX_NOT_ELIGIBLE"
    assert scrm.calls == []


def test_unexpired_sandbox_ttl_refused(world):
    db, crm, ctx, storage, client = world
    sdb, scrm = f.make_world(sandbox=True, expired=False)
    ctx.store, ctx.crm = f.TestStore(sdb), scrm
    r = _post(client, body={"action_class": "SANDBOX_TTL"})
    assert r.status_code == 409 and scrm.mutating_calls() == []


# ---------------------------------------------------------------------------------------------- provenance at vend
def _vend_crm(number=f.NUMBER, project_id="fresh-svc-123abc", create_side_effect=None):
    crm = MagicMock()
    projects = crm.projects.return_value
    if create_side_effect is not None:
        projects.create.return_value.execute.side_effect = create_side_effect
    else:
        projects.create.return_value.execute.return_value = {"name": "operations/cp.42"}
    projects.get.return_value.execute.return_value = {"name": f"projects/{number}", "projectId": project_id,
                                                      "state": "ACTIVE"}
    projects.getIamPolicy.return_value.execute.return_value = {"bindings": []}
    crm.operations.return_value.get.return_value.execute.return_value = {"done": True}
    return crm


def _vend_engine(vmain, db, crm):
    eng = vmain.ProjectRepoVendingEngine(iam_client=f.FakeChildIAM(), platform_project_id=f.HOST, firestore_client=db, crm_service=crm,
                                         billing_service=MagicMock(), storage_client=FakeStorage())
    eng.billing_account_id = ""
    eng.devops_sa_email = ""
    return eng


def test_fresh_vend_writes_labels_tag_and_provenance(vmain, monkeypatch):
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", f.TAG)
    monkeypatch.delenv("STACKVEND_GUARD_FIRESTORE_DATABASE", raising=False)
    db, crm = f.FakeDB(), _vend_crm()
    eng = _vend_engine(vmain, db, crm)
    res = eng.vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT, force_new_project_id="fresh-svc-123abc",
                               is_sandbox=True, sandbox_auto_decommission=True,
                               sandbox_designation_source="OPERATOR_CHECKBOX", sandbox_ttl_days=7)
    assert res["provenance_status"] == "RECORDED"
    body = crm.projects.return_value.create.call_args.kwargs["body"]
    assert body["labels"] == {"stackvend-managed": "true", "stackvend-product-id": "fresh-svc",
                              "stackvend-workload-type": "sandbox"}
    assert (body["projectId"], body["parent"]) == ("fresh-svc-123abc", f"folders/{f.ROOT}")
    crm.tagBindings.return_value.create.assert_called_once_with(body={
        "parent": f"//cloudresourcemanager.googleapis.com/projects/{f.NUMBER}", "tagValue": f.TAG})
    prov = db.doc("workload_provenance/fresh-svc")
    assert prov["created_by"] == "stackvend-vending" and prov["project_number"] == f.NUMBER
    assert prov["crm_create_operation"] == "operations/cp.42" and prov["trace_id"] == "tr-1"
    assert prov["is_sandbox"] is True and prov["sandbox_auto_decommission"] is True
    assert prov["sandbox_designation_source"] == "OPERATOR_CHECKBOX" and prov["sandbox_expires_at"]


def test_vend_without_sandbox_fields_is_standard_and_never_ttl(vmain, monkeypatch):
    monkeypatch.delenv("STACKVEND_MANAGED_TAG_VALUE", raising=False)
    db, crm = f.FakeDB(), _vend_crm()
    res = _vend_engine(vmain, db, crm).vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT,
                                                         force_new_project_id="fresh-svc-123abc")
    assert res["provenance_status"] == "RECORDED_UNTAGGED"  # TAG_UNCONFIGURED: vend succeeds, never deletable
    crm.tagBindings.assert_not_called()
    prov = db.doc("workload_provenance/fresh-svc")
    assert prov["is_sandbox"] is False and prov["sandbox_expires_at"] is None
    assert crm.projects.return_value.create.call_args.kwargs["body"]["labels"]["stackvend-workload-type"] == "standard"


def test_already_created_vend_stamps_nothing(vmain, monkeypatch):
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", f.TAG)
    db, crm = f.FakeDB(), _vend_crm(project_id="existing-proj-1")
    db.docs["workloads/old-svc"] = {"product_id": "old-svc", "project_id": "existing-proj-1", "status": "ACTIVE"}
    res = _vend_engine(vmain, db, crm).vend_gcp_project("old-svc", "tr-2", folder_id=f.ROOT)
    assert res["provenance_status"] == "NOT_CREATED_IN_THIS_CALL"
    crm.projects.return_value.create.assert_not_called()
    crm.tagBindings.assert_not_called()
    assert db.doc("workload_provenance/old-svc") is None


def test_adopted_existing_project_on_409_stamps_nothing(vmain, monkeypatch):
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", f.TAG)
    from googleapiclient.errors import HttpError

    if not isinstance(HttpError, type):
        pytest.skip("googleapiclient replaced by a stub in this process")
    resp = MagicMock(status=409, reason="Conflict")
    db, crm = f.FakeDB(), _vend_crm(create_side_effect=HttpError(resp, b"already exists"))
    res = _vend_engine(vmain, db, crm).vend_gcp_project("adopt-svc", "tr-3", folder_id=f.ROOT,
                                                         force_new_project_id="brownfield-proj")
    assert res["provenance_status"] == "NOT_CREATED_IN_THIS_CALL"
    crm.tagBindings.assert_not_called()
    assert db.doc("workload_provenance/adopt-svc") is None


def test_invalid_label_value_product_gets_no_labels_but_vends(vmain, monkeypatch):
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", f.TAG)
    db, crm = f.FakeDB(), _vend_crm()
    res = _vend_engine(vmain, db, crm).vend_gcp_project("Fresh_Svc", "tr-1", folder_id=f.ROOT,
                                                         force_new_project_id="fresh-svc-123abc")
    assert res["status"] == "PROJECT_VENDED"
    assert "labels" not in crm.projects.return_value.create.call_args.kwargs["body"]
    assert db.doc("workload_provenance/Fresh_Svc")["labels_written"] is False


def test_redeploy_vend_archives_previous_provenance(vmain, monkeypatch):
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", f.TAG)
    db, crm = f.FakeDB(), _vend_crm(number="222333444555")
    db.docs["workload_provenance/fresh-svc"] = {"created_by": "stackvend-vending", "project_number": "111"}
    _vend_engine(vmain, db, crm).vend_gcp_project("fresh-svc", "tr-9", folder_id=f.ROOT,
                                                  force_new_project_id="fresh-svc-999")
    assert db.doc("workload_provenance/fresh-svc/history/111")["project_number"] == "111"
    assert db.doc("workload_provenance/fresh-svc")["project_number"] == "222333444555"


def test_provenance_write_failure_does_not_fail_the_vend(vmain, monkeypatch):
    db, crm = f.FakeDB(), _vend_crm()
    db.fail_write_paths.add("workload_provenance")
    res = _vend_engine(vmain, db, crm).vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT,
                                                         force_new_project_id="fresh-svc-123abc")
    assert res["status"] == "PROJECT_VENDED" and res["provenance_status"] == "PROVENANCE_WRITE_FAILED"


def test_vend_routes_accept_explicit_sandbox_fields_strictly(world, vmain, monkeypatch):
    db, crm, ctx, storage, client = world
    captured = {}
    monkeypatch.setattr(vmain.vending_engine, "vend_gcp_project", lambda **kw: captured.update(kw) or {"ok": 1})
    r = client.post("/vend-project", json={"product_id": "p1", "is_sandbox": True, "sandbox_auto_decommission": True,
                                           "sandbox_designation_source": "API_FIELD", "sandbox_ttl_days": 3})
    assert r.status_code == 200 and captured["is_sandbox"] is True and captured["sandbox_ttl_days"] == 3
    r = client.post("/vend-project", json={"product_id": "p1", "is_sandbox": "true"})
    assert r.status_code == 422
    captured.clear()
    assert client.post("/vend-project", json={"product_id": "p1"}).status_code == 200
    assert captured["is_sandbox"] is False and captured["sandbox_auto_decommission"] is False


# ---------------------------------------------------------------------------------------------- Do No Harm
def test_non_delete_routes_unchanged_and_unauthenticated(world, vmain, monkeypatch):
    db, crm, ctx, storage, client = world
    assert client.get("/health").json()["status"] == "healthy"
    monkeypatch.setattr(vmain.vending_engine, "vend_all", lambda **kw: {"project_id": "p", "status": "WORKLOAD_VENDED"})
    assert client.post("/vend-all", json={"product_id": "p1"}).json()["status"] == "WORKLOAD_VENDED"
    monkeypatch.setattr(vmain.vending_engine, "redeploy_workload", lambda **kw: {"status": "ACTIVE"})
    assert client.post("/projects/p1/redeploy", json={}).json()["status"] == "ACTIVE"
    assert crm.calls == []


# ---------------------------------------------------------------------------------------------- lifecycle
def _life(client, action, token=GOOD, **body):
    return client.post(f"/projects/{f.PID}/lifecycle", headers={"Authorization": f"Bearer {token}"},
                       json={"action": action, **body})


@pytest.fixture
def sandbox_world(vmain, env, monkeypatch):
    db, crm = f.make_world(sandbox=True, expired=False)
    ctx = f.make_ctx(db, crm)
    monkeypatch.setattr(vmain, "vending_engine", _engine(vmain, db, crm, ctx))
    monkeypatch.setattr(vmain, "CALLER_TOKEN_VERIFIER", fake_verifier)
    return db, crm, ctx, TestClient(vmain.app)


def test_lifecycle_requires_auth(sandbox_world):
    db, crm, ctx, client = sandbox_world
    r = client.post(f"/projects/{f.PID}/lifecycle", json={"action": "EXTEND", "ttl_days": 3})
    assert r.status_code == 401 and crm.calls == []


def test_extend_three_times_then_limit(sandbox_world):
    db, crm, ctx, client = sandbox_world
    before = f.dg._parse_ts(db.doc(f"workload_provenance/{f.PID}")["sandbox_expires_at"])
    for i in range(3):
        r = _life(client, "EXTEND", ttl_days=5)
        assert r.status_code == 200, r.text
    prov = db.doc(f"workload_provenance/{f.PID}")
    assert prov["extensions"] == 3
    assert f.dg._parse_ts(prov["sandbox_expires_at"]) == before + timedelta(days=15)
    assert db.doc(f"workloads/{f.PID}")["sandbox_expires_at"] == prov["sandbox_expires_at"]
    r = _life(client, "EXTEND", ttl_days=1)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "EXTENSION_LIMIT"
    assert crm.mutating_calls() == []


def test_extend_beyond_90_days_refused(sandbox_world):
    db, crm, ctx, client = sandbox_world
    db.docs[f"workload_provenance/{f.PID}"]["sandbox_expires_at"] = f.iso(f.NOW + timedelta(days=75))
    r = _life(client, "EXTEND", ttl_days=10)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "EXTENSION_LIMIT"


@pytest.mark.parametrize("days", [0, 31, None])
def test_extend_days_validated(sandbox_world, days):
    db, crm, ctx, client = sandbox_world
    r = _life(client, "EXTEND", ttl_days=days)
    assert r.status_code == 422


def test_extend_refused_on_untagged_project(sandbox_world):
    db, crm, ctx, client = sandbox_world
    crm.tag_bindings[f.NUMBER] = []
    r = _life(client, "EXTEND", ttl_days=3)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "NOT_STACKVEND_OWNED"
    assert db.doc(f"workload_provenance/{f.PID}")["extensions"] == 0


def test_promote_makes_it_ineligible_and_relabels(sandbox_world):
    db, crm, ctx, client = sandbox_world
    r = _life(client, "PROMOTE")
    assert r.status_code == 200, r.text
    prov = db.doc(f"workload_provenance/{f.PID}")
    assert prov["is_sandbox"] is False and prov["sandbox_auto_decommission"] is False
    [(name, number, labels)] = crm.mutating_calls()
    assert (name, number) == ("patch_labels", f.NUMBER)
    assert labels["stackvend-workload-type"] == "standard" and labels["team"] == "x"


def test_confirm_sandbox_needs_human_approval(vmain, env, monkeypatch):
    db, crm = f.make_world(sandbox=False)
    ctx = f.make_ctx(db, crm)
    monkeypatch.setattr(vmain, "vending_engine", _engine(vmain, db, crm, ctx))
    monkeypatch.setattr(vmain, "CALLER_TOKEN_VERIFIER", fake_verifier)
    client = TestClient(vmain.app)
    r = _life(client, "CONFIRM_SANDBOX", ttl_days=7)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "APPROVAL_MISSING"
    f.add_approval(db, action="CONFIRM_SANDBOX", principal_type="SERVICE_ACCOUNT")
    r = _life(client, "CONFIRM_SANDBOX", ttl_days=7, approval_id=f.APPROVAL)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "APPROVAL_NOT_HUMAN"
    assert crm.mutating_calls() == []
    f.add_approval(db, action="CONFIRM_SANDBOX")
    r = _life(client, "CONFIRM_SANDBOX", ttl_days=7, approval_id=f.APPROVAL)
    assert r.status_code == 200, r.text
    prov = db.doc(f"workload_provenance/{f.PID}")
    assert prov["sandbox_designation_source"] == "OPERATOR_CONFIRMED" and prov["sandbox_auto_decommission"] is True
    assert prov["confirmed_by"] == f.ADMIN
    assert crm.projects[f.NUMBER]["labels"]["stackvend-workload-type"] == "sandbox"
    assert db.doc(f"destructive_approvals/{f.APPROVAL}")["status"] == "EXECUTED"


def test_confirm_sandbox_refused_for_backfilled_project(vmain, env, monkeypatch):
    db, crm = f.make_world(sandbox=False)
    db.docs[f"workload_provenance/{f.PID}"]["created_by"] = "owner-backfill"
    f.add_approval(db, action="CONFIRM_SANDBOX")
    ctx = f.make_ctx(db, crm)
    monkeypatch.setattr(vmain, "vending_engine", _engine(vmain, db, crm, ctx))
    monkeypatch.setattr(vmain, "CALLER_TOKEN_VERIFIER", fake_verifier)
    r = _life(TestClient(vmain.app), "CONFIRM_SANDBOX", ttl_days=7, approval_id=f.APPROVAL)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "SANDBOX_NOT_ELIGIBLE"
    assert db.doc(f"destructive_approvals/{f.APPROVAL}")["status"] == "APPROVED"
