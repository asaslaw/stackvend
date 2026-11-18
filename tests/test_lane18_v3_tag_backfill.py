"""
Lane 18 v3 (owner rule 10-18) on the vending side:

(b) without the deletion-safety tag the guard stays fail closed: every delete refuses GUARD_UNCONFIGURED before any
    CRM call, and an untagged project is never deleted;
(c) backfill: once the tag exists, vending binds it to projects whose workload_provenance record vending wrote AT
    BIRTH (plus the guard's ledger / CRM / ancestry identity checks). Never by name or label: a project that only
    looks like a StackVend project (labels and name match, no provenance) is never tagged. Non-destructive (only
    tagBindings.create), idempotent (second run: zero mutating calls, zero writes), audited.
Status + backfill are also exercised through vending's FastAPI routes (authenticated caller). Hermetic fakes only.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

import destructive_guard_fakes as f
from destructive_guard_fakes import dg

import managed_tag_backfill as mtb

VENDING_MAIN = f.load_vending_main()
AUD = "https://project-repo-vending-service-abc-uc.a.run.app"
TOKENS = {"cc": {"iss": "https://accounts.google.com", "aud": AUD, "email": f.CC_SA, "email_verified": True},
          "dev": {"iss": "https://accounts.google.com", "aud": AUD, "email": f.OTHER_SA, "email_verified": True}}


def _verifier(token, audiences):
    if token not in TOKENS:
        raise ValueError("bad token")
    return dict(TOKENS[token])


def _untagged_world():
    """A vending-born project from an install that had no tag: provenance tag_bound False, no binding."""
    db, crm = f.make_world()
    crm.tag_bindings.pop(f.NUMBER)
    db.docs[f"workload_provenance/{f.PID}"]["tag_bound"] = False
    return db, crm


def _add_lookalike(db, crm, pid="look-alike", project="look-alike-x1y2z3", number="555000555000"):
    """Mutant: ledger record + StackVend labels + managed folder, project name like a StackVend one, NO provenance."""
    f.add_project(crm, project, number, tagged=False,
                  labels={"stackvend-managed": "true", "stackvend-product-id": pid, "stackvend-workload-type": "standard"})
    db.docs[f"workloads/{pid}"] = {"product_id": pid, "project_id": project, "project_number": number,
                                   "status": "ACTIVE", "is_castor": False, "trace_id": f"vend-tr-{pid}"}
    return pid, number


def _binds(crm):
    return [c for c in crm.calls if c[0] == "create_tag_binding"]


# ---------------------------------------------------------------------------------------------- (b) fail closed
def test_no_tag_every_delete_refuses_guard_unconfigured_before_any_crm_call():
    db, crm = _untagged_world()
    f.add_approval(db)
    ctx = f.make_ctx(db, crm, managed_tag_value=None)
    for action, approval in ((dg.ActionClass.PROJECT_DECOMMISSION, f.APPROVAL), (dg.ActionClass.SANDBOX_TTL, None)):
        with pytest.raises(dg.DeletionRefused) as e:
            dg.assert_deletable(dg.DeletionTarget(product_id=f.PID), action_class=action, approval_id=approval,
                                caller_email=f.CC_SA, ctx=ctx)
        assert e.value.code == "GUARD_UNCONFIGURED" and e.value.http_status == 503
    assert crm.calls == [] and crm.mutating_calls() == []


def test_tag_configured_but_project_untagged_is_never_deleted():
    db, crm = _untagged_world()
    f.add_approval(db)
    with pytest.raises(dg.DeletionRefused) as e:
        dg.assert_deletable(dg.DeletionTarget(product_id=f.PID), action_class=dg.ActionClass.PROJECT_DECOMMISSION,
                            approval_id=f.APPROVAL, caller_email=f.CC_SA, ctx=f.make_ctx(db, crm))
    assert e.value.code == "NOT_STACKVEND_OWNED"
    assert crm.mutating_calls() == []


def test_backfill_refused_while_the_tag_is_not_set_up():
    db, crm = _untagged_world()
    with pytest.raises(dg.DeletionRefused) as e:
        mtb.backfill_tags(f.make_ctx(db, crm, managed_tag_value=None), caller_email=f.CC_SA)
    assert e.value.code == "GUARD_UNCONFIGURED"
    assert crm.calls == [] and db.writes == []


# ---------------------------------------------------------------------------------------------- status
def test_status_without_tag_lists_vended_projects_and_unprovenanced_workloads():
    db, crm = _untagged_world()
    _add_lookalike(db, crm)
    st = mtb.tag_status(f.make_ctx(db, crm, managed_tag_value=None), organization_raw="organizations/111111111111")
    assert st["tag_configured"] is False and st["organization_id"] == "organizations/111111111111"
    assert st["required_role"] == "roles/resourcemanager.tagAdmin"
    assert [(v["product_id"], v["tag"]) for v in st["untagged_vended"]] == [(f.PID, "NOT_SET_UP")]
    assert st["backfill_candidates"] == []
    assert st["unprovenanced_workloads"] == [{"product_id": "look-alike", "project_id": "look-alike-x1y2z3",
                                              "ledger_status": "ACTIVE"}]
    assert crm.calls == [] and db.writes == []  # read-only, and no CRM call while there is no tag


def test_status_with_tag_checks_the_live_direct_binding():
    db, crm = _untagged_world()
    st = mtb.tag_status(f.make_ctx(db, crm), organization_raw="111111111111")
    assert [(v["product_id"], v["tag"]) for v in st["vended_projects"]] == [(f.PID, "UNTAGGED")]
    assert st["backfill_candidates"] == [f.PID] and st["organization_id"] == "organizations/111111111111"
    assert crm.mutating_calls() == [] and db.writes == []
    # An inherited / foreign binding does not count as the direct tag.
    crm.tag_bindings[f.NUMBER] = [{"parent": "//cloudresourcemanager.googleapis.com/folders/4242", "tagValue": f.TAG},
                                  {"parent": f"//cloudresourcemanager.googleapis.com/projects/{f.NUMBER}",
                                   "tagValue": "tagValues/1"}]
    assert mtb.tag_status(f.make_ctx(db, crm), organization_raw="")["backfill_candidates"] == [f.PID]


@pytest.mark.parametrize("raw,expected", [("organizations/42", "organizations/42"), ("42", "organizations/42"),
                                          ("", ""), (None, ""), ("folders/42", ""), ("organizations/4x", ""),
                                          ("organizations/42/x", "")])
def test_organization_name_is_parsed_positionally(raw, expected):
    assert mtb.organization_name(raw) == expected


# ---------------------------------------------------------------------------------------------- (c) backfill
def test_backfill_tags_only_provenance_proven_projects_and_audits():
    db, crm = _untagged_world()
    look_pid, look_number = _add_lookalike(db, crm)
    out = mtb.backfill_tags(f.make_ctx(db, crm), caller_email=f.CC_SA, operator_email=f.ADMIN, now=f.NOW)
    by_pid = {r["product_id"]: r for r in out["results"]}
    assert by_pid[f.PID]["decision"] == "TAGGED"
    assert look_pid not in by_pid  # never even considered: no provenance record
    assert _binds(crm) == [("create_tag_binding", f.NUMBER, f.TAG)]
    assert crm.mutating_calls() == _binds(crm)  # nothing else changed (no labels, no deletes)
    assert look_number not in crm.tag_bindings
    prov = db.docs[f"workload_provenance/{f.PID}"]
    assert prov["tag_bound"] is True and prov["tag_bound_by"] == "managed-tag-backfill"
    assert prov["created_by"] == "stackvend-vending"  # the birth record itself is unchanged
    audits = db.audit_records()
    assert [a["status"] for a in audits] == ["ATTEMPT", "TAGGED"]
    assert all(a["action"] == "MANAGED_TAG_BACKFILL" and a["caller"] == f.CC_SA and a["operator"] == f.ADMIN
               for a in audits)
    # The project now passes the guard's ownership check (labels + direct tag).
    dg.verify_identity(f.PID, ctx=f.make_ctx(db, crm))


def test_backfill_is_idempotent():
    db, crm = _untagged_world()
    mtb.backfill_tags(f.make_ctx(db, crm), caller_email=f.CC_SA, now=f.NOW)
    writes, mutating = len(db.writes), len(crm.mutating_calls())
    out = mtb.backfill_tags(f.make_ctx(db, crm), caller_email=f.CC_SA, now=f.NOW)
    assert out["counts"] == {"ALREADY_TAGGED": 1}
    assert len(db.writes) == writes and len(crm.mutating_calls()) == mutating


def test_mutant_name_and_label_matched_project_is_never_tagged():
    """No provenance -> never tagged, even with a ledger record, StackVend labels and the managed folder."""
    db, crm = f.FakeDB(), f.FakeCRM()
    crm.projects[f.HOST_NUMBER] = {"name": f"projects/{f.HOST_NUMBER}", "projectId": f.HOST, "state": "ACTIVE"}
    _add_lookalike(db, crm, pid=f.PID, project=f.PROJECT, number=f.NUMBER)
    out = mtb.backfill_tags(f.make_ctx(db, crm), caller_email=f.CC_SA, now=f.NOW)
    assert out["results"] == [] and crm.mutating_calls() == [] and db.writes == []


def _forge_moved_in(db, crm, *, labels):
    """RT F1/F8: a foreign project moved under the managed folder, a ledger record and a forged vending-born
    provenance record (a guard-DB writer could write both)."""
    pid, project, number = "moved-in", "foreign-proj-1", "555000555001"
    f.add_project(crm, project, number, tagged=False, labels=labels)
    db.docs[f"workloads/{pid}"] = {"product_id": pid, "project_id": project, "project_number": number,
                                   "status": "ACTIVE", "is_castor": False, "trace_id": "t"}
    db.docs[f"workload_provenance/{pid}"] = {"created_by": "stackvend-vending", "product_id": pid,
                                             "project_id": project, "project_number": number, "tag_bound": False}
    return pid, number


def test_forged_provenance_on_a_project_without_stackvend_labels_is_not_tagged():
    db, crm = f.FakeDB(), f.FakeCRM()
    crm.projects[f.HOST_NUMBER] = {"name": f"projects/{f.HOST_NUMBER}", "projectId": f.HOST, "state": "ACTIVE"}
    for labels in ({}, {"team": "x"}, {"stackvend-managed": "true", "stackvend-product-id": "other",
                                       "stackvend-workload-type": "standard"},
                   {"stackvend-managed": "true", "stackvend-product-id": "moved-in", "stackvend-workload-type": "x"}):
        pid, number = _forge_moved_in(db, crm, labels=labels)
        out = mtb.backfill_tags(f.make_ctx(db, crm), caller_email=f.CC_SA, now=f.NOW)
        assert out["results"] == [{"product_id": pid, "project_id": "foreign-proj-1", "project_number": number,
                                   "decision": "SKIPPED:NOT_STACKVEND_OWNED",
                                   "detail": "StackVend labels do not name this product"}], labels
        assert crm.mutating_calls() == [] and db.writes == []


def test_guard_label_check_extraction_keeps_guard_behaviour():
    """_crm_identity still refuses unlabelled / mislabelled projects exactly as before the extraction."""
    db, crm = f.make_world()
    crm.projects[f.NUMBER]["labels"] = {"team": "x"}
    with pytest.raises(dg.DeletionRefused) as e:
        dg.verify_identity(f.PID, ctx=f.make_ctx(db, crm))
    assert e.value.code == "NOT_STACKVEND_OWNED"
    assert dg._check_labels({"labels": {"stackvend-managed": "true", "stackvend-product-id": "p",
                                        "stackvend-workload-type": "sandbox"}}, "p", require_sandbox_label=True) == "sandbox"
    with pytest.raises(dg.DeletionRefused) as e:
        dg._check_labels({"labels": {"stackvend-managed": "true", "stackvend-product-id": "p",
                                     "stackvend-workload-type": "standard"}}, "p", require_sandbox_label=True)
    assert e.value.code == "SANDBOX_NOT_ELIGIBLE"


def test_provenance_naming_another_project_is_not_tagged():
    """Mutant: a provenance record whose number resolves to a different project id (CRM_MISMATCH)."""
    db, crm = _untagged_world()
    f.add_project(crm, "someone-else", "777000777000", tagged=False)
    db.docs[f"workload_provenance/{f.PID}"]["project_number"] = "777000777000"
    db.docs[f"workloads/{f.PID}"]["project_number"] = "777000777000"
    out = mtb.backfill_tags(f.make_ctx(db, crm), caller_email=f.CC_SA, now=f.NOW)
    assert out["results"][0]["decision"] == "SKIPPED:CRM_MISMATCH"
    assert crm.mutating_calls() == [] and db.writes == []


@pytest.mark.parametrize("mutate,code", [
    (lambda db, crm: db.docs[f"workload_provenance/{f.PID}"].update(created_by="owner-backfill"),
     "SKIPPED:NOT_VENDING_BIRTH"),
    (lambda db, crm: db.docs[f"workload_provenance/{f.PID}"].update(created_by="sa-castor-developer"),
     "SKIPPED:LEDGER_UNPROVENANCED"),
    (lambda db, crm: db.docs[f"workloads/{f.PID}"].update(project_id="other-project"), "SKIPPED:LEDGER_MISMATCH"),
    (lambda db, crm: db.docs.pop(f"workloads/{f.PID}"), "SKIPPED:LEDGER_MISSING"),
    (lambda db, crm: db.docs.__setitem__("workloads/dup", {"product_id": "dup", "project_id": f.PROJECT}),
     "SKIPPED:LEDGER_MISMATCH"),
    (lambda db, crm: crm.projects[f.NUMBER].update(state="DELETE_REQUESTED"), "SKIPPED:NOT_ACTIVE"),
    (lambda db, crm: crm.ancestry[f.PROJECT].__setitem__(2, {"resourceId": {"type": "folder", "id": "9999"}}),
     "SKIPPED:NOT_IN_MANAGED_FOLDER"),
    (lambda db, crm: crm.fail.__setitem__("get_project", 503), "SKIPPED:CRM_UNAVAILABLE"),
    (lambda db, crm: crm.fail.__setitem__("list_tag_bindings", 429), "SKIPPED:CRM_UNAVAILABLE"),
])
def test_backfill_skips_without_full_proof(mutate, code):
    db, crm = _untagged_world()
    mutate(db, crm)
    out = mtb.backfill_tags(f.make_ctx(db, crm), caller_email=f.CC_SA, now=f.NOW)
    assert {r["product_id"]: r["decision"] for r in out["results"]}[f.PID] == code
    assert crm.mutating_calls() == [] and db.writes == []


def test_status_lists_expired_sandboxes_separately_never_as_candidates():
    """RT F2: what tag_status offers equals what backfill_tags will tag."""
    db, crm = f.make_world(sandbox=True, expired=True)
    crm.tag_bindings.pop(f.NUMBER)
    st = mtb.tag_status(f.make_ctx(db, crm), organization_raw="")
    assert st["backfill_candidates"] == []
    assert [v["product_id"] for v in st["sandbox_expired_untagged"]] == [f.PID]
    assert mtb.backfill_tags(f.make_ctx(db, crm), caller_email=f.CC_SA, now=f.NOW)["counts"] == {
        "SKIPPED:SANDBOX_EXPIRED": 1}
    db, crm = f.make_world(sandbox=True, expired=False)
    crm.tag_bindings.pop(f.NUMBER)
    st = mtb.tag_status(f.make_ctx(db, crm), organization_raw="")
    assert st["backfill_candidates"] == [f.PID] and st["sandbox_expired_untagged"] == []
    # Without the tag nothing is a candidate, but expired sandboxes are still named for the owner.
    db, crm = f.make_world(sandbox=True, expired=True)
    st = mtb.tag_status(f.make_ctx(db, crm, managed_tag_value=None), organization_raw="")
    assert st["backfill_candidates"] == [] and [v["product_id"] for v in st["sandbox_expired_untagged"]] == [f.PID]
    assert st["max_records"] == mtb.MAX_RECORDS


def test_expired_auto_decommission_sandbox_is_not_tagged():
    db, crm = f.make_world(sandbox=True, expired=True)
    crm.tag_bindings.pop(f.NUMBER)
    out = mtb.backfill_tags(f.make_ctx(db, crm), caller_email=f.CC_SA, now=f.NOW)
    assert out["results"][0]["decision"] == "SKIPPED:SANDBOX_EXPIRED"
    assert crm.mutating_calls() == [] and db.writes == []
    # A not-yet-expired sandbox is tagged (its vend-time expiry is what the operator chose).
    db, crm = f.make_world(sandbox=True, expired=False)
    crm.tag_bindings.pop(f.NUMBER)
    assert mtb.backfill_tags(f.make_ctx(db, crm), caller_email=f.CC_SA, now=f.NOW)["counts"] == {"TAGGED": 1}


def test_no_audit_no_binding():
    db, crm = _untagged_world()
    db.fail_write_paths.add("workloads")
    out = mtb.backfill_tags(f.make_ctx(db, crm), caller_email=f.CC_SA, now=f.NOW)
    assert out["results"][0]["decision"] == "SKIPPED:AUDIT_UNAVAILABLE"
    assert crm.mutating_calls() == []


def test_binding_failure_is_reported_and_audited():
    db, crm = _untagged_world()
    crm.fail["create_tag_binding"] = 403
    out = mtb.backfill_tags(f.make_ctx(db, crm), caller_email=f.CC_SA, now=f.NOW)
    assert out["results"][0]["decision"] == "FAILED"
    assert [a["status"] for a in db.audit_records()] == ["ATTEMPT", "FAILED"]
    assert db.docs[f"workload_provenance/{f.PID}"]["tag_bound"] is False


# ---------------------------------------------------------------------------------------------- vending routes
@pytest.fixture
def client(monkeypatch):
    vmain = VENDING_MAIN
    monkeypatch.setenv("DESTRUCTIVE_CALLERS", f.CC_SA)
    monkeypatch.setenv("VENDING_SERVICE_URL", AUD)
    monkeypatch.setenv("STACKVEND_ORGANIZATION_ID", "organizations/111111111111")
    db, crm = _untagged_world()
    ctx = f.make_ctx(db, crm)

    class _Engine:
        def guard_context(self):
            return ctx

    monkeypatch.setattr(vmain, "vending_engine", _Engine())
    monkeypatch.setattr(vmain, "CALLER_TOKEN_VERIFIER", _verifier)
    return db, crm, ctx, TestClient(vmain.app)


def test_routes_require_the_control_center_identity(client):
    db, crm, ctx, c = client
    for method, path in (("get", "/guard/managed-tag"), ("post", "/guard/managed-tag/backfill")):
        assert getattr(c, method)(path).status_code == 401
        r = getattr(c, method)(path, headers={"Authorization": "Bearer dev"})
        assert r.status_code == 403 and r.json()["detail"]["code"] == "CALLER_NOT_ALLOWED"
    assert crm.calls == [] and db.writes == []


def test_routes_status_then_backfill(client):
    db, crm, ctx, c = client
    h = {"Authorization": "Bearer cc"}
    st = c.get("/guard/managed-tag", headers=h).json()
    assert st["tag_configured"] is True and st["backfill_candidates"] == [f.PID]
    assert st["organization_id"] == "organizations/111111111111"
    r = c.post("/guard/managed-tag/backfill", headers=h, json={"operator_email": f.ADMIN})
    assert r.status_code == 200 and r.json()["counts"] == {"TAGGED": 1}
    assert db.audit_records()[0]["operator"] == f.ADMIN
    assert c.get("/guard/managed-tag", headers=h).json()["backfill_candidates"] == []


def test_route_backfill_without_tag_is_503_guard_unconfigured(client, monkeypatch):
    db, crm, ctx, c = client
    monkeypatch.setattr(ctx, "managed_tag_value", None)
    r = c.post("/guard/managed-tag/backfill", headers={"Authorization": "Bearer cc"})
    assert r.status_code == 503 and r.json()["detail"]["code"] == "GUARD_UNCONFIGURED"
    assert crm.calls == [] and db.writes == []


def test_route_status_store_unavailable_is_503(client, monkeypatch):
    db, crm, ctx, c = client
    monkeypatch.setattr(ctx.store, "guard_db", dg.UnavailableDB("guard DB unavailable"))
    r = c.get("/guard/managed-tag", headers={"Authorization": "Bearer cc"})
    assert r.status_code == 503 and r.json()["detail"]["code"] == "LEDGER_UNAVAILABLE"
