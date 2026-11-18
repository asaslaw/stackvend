"""
Lane 18 S1: apps/project-vending/destructive_guard.py — every refusal code of plan section 2.3, with zero mutating
calls on refusal, no retries on CRM 429/5xx, and the happy paths. Hermetic: in-memory Firestore and CRM fakes.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
from datetime import timedelta

import pytest

import destructive_guard_fakes as f
from destructive_guard_fakes import dg

PD = dg.ActionClass.PROJECT_DECOMMISSION
TTL = dg.ActionClass.SANDBOX_TTL


def _assert(db, crm, ctx, code, *, action=PD, approval_id=f.APPROVAL, caller=f.CC_SA, target=None):
    with pytest.raises(dg.DeletionRefused) as ei:
        dg.assert_deletable(target or dg.DeletionTarget(f.PID), action_class=action, approval_id=approval_id,
                            caller_email=caller, ctx=ctx)
    assert ei.value.code == code, ei.value
    assert crm.mutating_calls() == []
    assert db.audit_records() == []
    return ei.value


def _world(sandbox=False, approval=True, **ctx_kw):
    db, crm = f.make_world(sandbox=sandbox)
    if approval:
        f.add_approval(db)
    return db, crm, f.make_ctx(db, crm, **ctx_kw)


# ---------------------------------------------------------------------------------------------- happy paths
def test_project_decommission_allowed_with_human_approval():
    db, crm, ctx = _world()
    v = dg.assert_deletable(dg.DeletionTarget(f.PID), action_class=PD, approval_id=f.APPROVAL,
                            caller_email=f.CC_SA, ctx=ctx)
    assert (v.project_id, v.project_number, v.approved_by) == (f.PROJECT, f.NUMBER, f.ADMIN)
    assert v.checks == ("config", "ledger", "provenance", "not_host", "approval", "crm_identity", "ownership",
                        "ancestry", "liens")
    assert crm.mutating_calls() == []
    [audit] = db.audit_records()
    assert audit["action"] == "DESTRUCTIVE_GUARD_ALLOW" and audit["project_number"] == f.NUMBER


def test_sandbox_ttl_allowed_for_expired_vending_sandbox():
    db, crm, ctx = _world(sandbox=True, approval=False)
    v = dg.assert_deletable(dg.DeletionTarget(f.PID), action_class=TTL, approval_id=None, caller_email=f.TTL_SA,
                            ctx=ctx)
    assert v.approval_id is None and "sandbox_ttl" in v.checks
    assert crm.mutating_calls() == []


def test_verify_identity_returns_managed_target_shape():
    db, crm, ctx = _world(approval=False)
    ident = dg.verify_identity(f.PID, ctx=ctx)
    assert ident == dg.ManagedIdentity(f.PID, f.PROJECT, f.NUMBER, "standard", "stackvend-vending")
    assert db.writes == [] and crm.mutating_calls() == []


def test_lien_named_in_provenance_still_refuses():
    """S1 code RT Fix 2(a) / row L18-g: StackVend never releases a lien; a name in provenance.liens[] proves nothing."""
    db, crm, ctx = _world()
    db.docs[f"workload_provenance/{f.PID}"]["liens"] = ["liens/sv-1"]
    crm.liens[f.NUMBER] = [{"name": "liens/sv-1"}]
    e = _assert(db, crm, ctx, "LIEN_PRESENT")
    assert e.http_status == 409 and crm.count("delete_lien") == 0


# ---------------------------------------------------------------------------------------------- 1 config
@pytest.mark.parametrize("override", [
    {"managed_root_folder_id": None}, {"managed_tag_value": None}, {"host_project_ids": frozenset()},
    {"platform_project_conflict": True}])
def test_guard_unconfigured(override):
    db, crm, ctx = _world(**override)
    e = _assert(db, crm, ctx, "GUARD_UNCONFIGURED")
    assert e.http_status == 503
    assert crm.calls == []


def test_from_env_parses_exact_forms(monkeypatch):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", "folders/4242")
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", "tagValues/777")
    monkeypatch.setenv("SANDBOX_TTL_CALLERS", f" {f.TTL_SA.upper()} , ")
    monkeypatch.delenv("PLATFORM_PROJECT_ID", raising=False)
    ctx = dg.GuardContext.from_env(store=None, crm=None)
    assert ctx.managed_root_folder_id == "4242" and ctx.managed_tag_value == "tagValues/777"
    assert ctx.ttl_callers == frozenset({f.TTL_SA}) and f.HOST in ctx.host_project_ids
    assert ctx.platform_project_conflict is False


@pytest.mark.parametrize("env,value", [
    ("MANAGED_WORKLOADS_FOLDER_ID", ""), ("MANAGED_WORKLOADS_FOLDER_ID", "organizations/1"),
    ("MANAGED_WORKLOADS_FOLDER_ID", "folders/12/extra"), ("STACKVEND_MANAGED_TAG_VALUE", "true"),
    ("STACKVEND_MANAGED_TAG_VALUE", "tagValues/77x"), ("STACKVEND_MANAGED_TAG_VALUE", "tagKeys/1")])
def test_from_env_malformed_config_is_unconfigured(monkeypatch, env, value):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", "4242")
    monkeypatch.setenv("STACKVEND_MANAGED_TAG_VALUE", "tagValues/777")
    monkeypatch.setenv(env, value)
    db, crm = f.make_world()
    ctx = dg.GuardContext.from_env(store=f.TestStore(db), crm=crm)
    _assert(db, crm, ctx, "GUARD_UNCONFIGURED")


def test_platform_project_id_must_equal_project_id(monkeypatch):
    monkeypatch.setenv("PLATFORM_PROJECT_ID", "some-other-host")
    assert dg.GuardContext.from_env(store=None, crm=None).platform_project_conflict is True


# ---------------------------------------------------------------------------------------------- 2 ledger
@pytest.mark.parametrize("pid", ["project-castor", "castor", "platform", ""])
def test_platform_pseudo_workloads_refused(pid):
    db, crm, ctx = _world()
    _assert(db, crm, ctx, "PLATFORM_WORKLOAD", target=dg.DeletionTarget(pid))


def test_is_castor_refused():
    db, crm, ctx = _world()
    db.docs[f"workloads/{f.PID}"]["is_castor"] = True
    _assert(db, crm, ctx, "PLATFORM_WORKLOAD")


def test_url_product_without_ledger_doc_is_missing_no_fallback():
    """FD26-04 inverted: the URL names some other team's project; there is no ledger doc -> 404, never a delete."""
    db, crm, ctx = _world()
    f.add_project(crm, "some-other-teams-project", "555")
    e = _assert(db, crm, ctx, "LEDGER_MISSING", target=dg.DeletionTarget("some-other-teams-project"))
    assert e.http_status == 404 and crm.calls == []


def test_ledger_read_error_refuses():
    db, crm, ctx = _world()
    db.fail_paths.add(f"workloads/{f.PID}")
    e = _assert(db, crm, ctx, "LEDGER_UNAVAILABLE")
    assert e.http_status == 503 and crm.calls == []


def test_ledger_product_id_field_mismatch():
    db, crm, ctx = _world()
    db.docs[f"workloads/{f.PID}"]["product_id"] = "other"
    _assert(db, crm, ctx, "LEDGER_MISMATCH")


# ---------------------------------------------------------------------------------------------- 3 provenance
def test_no_project_id_in_ledger_refuses_without_product_id_fallback():
    db, crm, ctx = _world()
    del db.docs[f"workloads/{f.PID}"]["project_id"]
    f.add_project(crm, f.PID, "777")  # a project literally named like the product must not be picked
    _assert(db, crm, ctx, "LEDGER_UNPROVENANCED")


def test_missing_provenance_refuses():
    db, crm, ctx = _world()
    del db.docs[f"workload_provenance/{f.PID}"]
    _assert(db, crm, ctx, "LEDGER_UNPROVENANCED")


@pytest.mark.parametrize("created_by", [None, "", "control-center", "Stackvend-Vending"])
def test_provenance_creator_must_be_exact(created_by):
    db, crm, ctx = _world()
    db.docs[f"workload_provenance/{f.PID}"]["created_by"] = created_by
    _assert(db, crm, ctx, "LEDGER_UNPROVENANCED")


@pytest.mark.parametrize("number", [None, "", "12ab", True, -5])
def test_provenance_number_must_be_numeric(number):
    db, crm, ctx = _world()
    db.docs[f"workload_provenance/{f.PID}"]["project_number"] = number
    _assert(db, crm, ctx, "LEDGER_UNPROVENANCED")


def test_provenance_project_differs_from_ledger():
    db, crm, ctx = _world()
    db.docs[f"workload_provenance/{f.PID}"]["project_id"] = "another-project"
    _assert(db, crm, ctx, "LEDGER_MISMATCH")


def test_ledger_number_differs_from_provenance():
    db, crm, ctx = _world()
    db.docs[f"workloads/{f.PID}"]["project_number"] = "111"
    _assert(db, crm, ctx, "LEDGER_MISMATCH")


def test_reverse_uniqueness_two_workloads_same_project():
    db, crm, ctx = _world()
    db.docs["workloads/forged"] = {"product_id": "forged", "project_id": f.PROJECT}
    _assert(db, crm, ctx, "LEDGER_MISMATCH")


def test_reverse_lookup_error_refuses():
    db, crm, ctx = _world()
    db.fail_paths.add("workloads?query")
    _assert(db, crm, ctx, "LEDGER_UNAVAILABLE")


# ---------------------------------------------------------------------------------------------- 4/5 host + CRM
def test_host_project_id_refused():
    db, crm, ctx = _world()
    db.docs[f"workloads/{f.PID}"]["project_id"] = f.HOST
    db.docs[f"workload_provenance/{f.PID}"]["project_id"] = f.HOST
    _assert(db, crm, ctx, "HOST_PROJECT")


def test_host_project_number_refused():
    """The number check is independent of the id check (e.g. a second host id resolving to the same number)."""
    db, crm, ctx = _world()
    ctx._host_numbers = frozenset({f.HOST_NUMBER, f.NUMBER})
    _assert(db, crm, ctx, "HOST_PROJECT")


def test_crm_project_id_mismatch():
    db, crm, ctx = _world()
    crm.projects[f.NUMBER]["projectId"] = "renamed-elsewhere"
    _assert(db, crm, ctx, "CRM_MISMATCH")


@pytest.mark.parametrize("state", ["DELETE_REQUESTED", "STATE_UNSPECIFIED", None])
def test_not_active(state):
    db, crm, ctx = _world()
    crm.projects[f.NUMBER]["state"] = state
    e = _assert(db, crm, ctx, "NOT_ACTIVE")
    assert e.http_status == 409


@pytest.mark.parametrize("status", [429, 500, 503, 403])
def test_crm_errors_refuse_with_zero_retries(status):
    db, crm, ctx = _world()
    crm.fail_after["get_project"] = (1, status)  # the host-number read succeeds, the target read fails
    e = _assert(db, crm, ctx, "CRM_UNAVAILABLE")
    assert e.http_status == 503
    assert [c for c in crm.calls if c[0] == "get_project" and c[1] == f.NUMBER] == [("get_project", f.NUMBER)]


def test_host_number_unresolvable_refuses():
    db, crm, ctx = _world()
    crm.fail["get_project"] = 429
    _assert(db, crm, ctx, "CRM_UNAVAILABLE")
    assert crm.count("get_project") == 1


# ---------------------------------------------------------------------------------------------- 6 ownership
def test_tag_missing_but_labels_present_refuses():
    db, crm, ctx = _world()
    crm.tag_bindings[f.NUMBER] = []
    _assert(db, crm, ctx, "NOT_STACKVEND_OWNED")


def test_tag_bound_only_on_parent_folder_refuses():
    db, crm, ctx = _world()
    crm.tag_bindings[f.NUMBER] = [{"parent": f"//cloudresourcemanager.googleapis.com/folders/{f.ROOT}",
                                   "tagValue": f.TAG}]
    _assert(db, crm, ctx, "NOT_STACKVEND_OWNED")


def test_tag_value_differs_from_env_refuses():
    db, crm, ctx = _world()
    crm.tag_bindings[f.NUMBER][0]["tagValue"] = "tagValues/778"
    _assert(db, crm, ctx, "NOT_STACKVEND_OWNED")


def test_tag_list_429_refuses():
    db, crm, ctx = _world()
    crm.fail["list_tag_bindings"] = 429
    _assert(db, crm, ctx, "CRM_UNAVAILABLE")
    assert crm.count("list_tag_bindings") == 1


@pytest.mark.parametrize("labels", [
    {}, {"stackvend-managed": "true", "stackvend-product-id": "shop-api-v2", "stackvend-workload-type": "standard"},
    {"stackvend-managed": "True", "stackvend-product-id": f.PID, "stackvend-workload-type": "standard"},
    {"stackvend-managed": "true", "stackvend-product-id": f.PID},
    {"stackvend-managed": "true", "stackvend-product-id": f.PID, "stackvend-workload-type": "prod"}])
def test_labels_must_match_exactly(labels):
    db, crm, ctx = _world()
    crm.projects[f.NUMBER]["labels"] = labels
    _assert(db, crm, ctx, "NOT_STACKVEND_OWNED")


# ---------------------------------------------------------------------------------------------- 7 ancestry
def test_not_in_managed_folder():
    db, crm, ctx = _world()
    crm.ancestry[f.PROJECT][2]["resourceId"]["id"] = "9999"
    _assert(db, crm, ctx, "NOT_IN_MANAGED_FOLDER")


def test_root_folder_as_the_project_itself_does_not_count():
    db, crm, ctx = _world()
    crm.ancestry[f.PROJECT] = [{"resourceId": {"type": "project", "id": f.PROJECT}},
                               {"resourceId": {"type": "organization", "id": f.ROOT}}]
    _assert(db, crm, ctx, "NOT_IN_MANAGED_FOLDER")


def test_ancestry_error_refuses():
    db, crm, ctx = _world()
    crm.fail["get_ancestry"] = 503
    _assert(db, crm, ctx, "ANCESTRY_UNAVAILABLE")
    assert crm.count("get_ancestry") == 1


def test_ancestry_not_starting_at_project_refuses():
    db, crm, ctx = _world()
    crm.ancestry[f.PROJECT] = crm.ancestry[f.PROJECT][1:]
    _assert(db, crm, ctx, "ANCESTRY_UNAVAILABLE")


# ---------------------------------------------------------------------------------------------- 8 liens
def test_foreign_lien_refuses_and_is_never_deleted():
    db, crm, ctx = _world()
    crm.liens[f.NUMBER] = [{"name": "liens/someone-elses", "restrictions": ["resourcemanager.projects.delete"]}]
    e = _assert(db, crm, ctx, "LIEN_PRESENT")
    assert e.http_status == 409 and crm.count("delete_lien") == 0


def test_lien_list_error_refuses():
    db, crm, ctx = _world()
    crm.fail["list_liens"] = 500
    _assert(db, crm, ctx, "CRM_UNAVAILABLE")


# ---------------------------------------------------------------------------------------------- 9a approvals
def test_hitl_without_approval_id():
    db, crm, ctx = _world()
    _assert(db, crm, ctx, "APPROVAL_MISSING", approval_id=None)
    assert crm.calls == []


def test_approval_doc_missing():
    db, crm, ctx = _world(approval=False)
    _assert(db, crm, ctx, "APPROVAL_MISSING")


def test_approval_store_error():
    db, crm, ctx = _world()
    db.fail_paths.add(f"destructive_approvals/{f.APPROVAL}")
    _assert(db, crm, ctx, "APPROVAL_UNAVAILABLE")


@pytest.mark.parametrize("override,code", [
    ({"status": "PENDING"}, "APPROVAL_NOT_APPROVED"),
    ({"status": "REJECTED"}, "APPROVAL_NOT_APPROVED"),
    ({"consumed_at": "2026-10-12T11:00:00+00:00"}, "APPROVAL_CONSUMED"),
    ({"status": "EXECUTION_FAILED"}, "APPROVAL_CONSUMED"),
    ({"action": "SANDBOX_TTL"}, "APPROVAL_MISMATCH"),
    ({"action": "BILLING_UNLINK"}, "APPROVAL_MISMATCH"),
    ({"product_id": "other"}, "APPROVAL_MISMATCH"),
    ({"project_id": "other"}, "APPROVAL_MISMATCH"),
    ({"project_number": "1"}, "APPROVAL_MISMATCH"),
    ({"resource_name": "projects/x/locations/y/services/z"}, "APPROVAL_MISMATCH"),
    ({"principal_type": "SERVICE_ACCOUNT"}, "APPROVAL_NOT_HUMAN"),
    ({"principal_type": None}, "APPROVAL_NOT_HUMAN"),
    ({"approved_by_role": "MANAGER"}, "APPROVAL_NOT_HUMAN"),
    ({"approved_by": ""}, "APPROVAL_NOT_HUMAN"),
    ({"expires_at": f.iso(f.NOW - timedelta(seconds=1))}, "APPROVAL_EXPIRED"),
    ({"expires_at": f.iso(f.NOW)}, "APPROVAL_EXPIRED"),
    ({"approved_at": f.iso(f.NOW - timedelta(hours=1)), "expires_at": f.iso(f.NOW + timedelta(hours=1))},
     "APPROVAL_EXPIRED"),
    ({"approved_at": None}, "APPROVAL_EXPIRED"),
    ({"expires_at": "tomorrow"}, "APPROVAL_EXPIRED"),
])
def test_approval_rules(override, code):
    db, crm, ctx = _world(approval=False)
    f.add_approval(db, **override)
    _assert(db, crm, ctx, code)
    assert crm.calls == []  # approval is checked before any CRM call


def test_approval_project_number_as_int_is_accepted():
    db, crm, ctx = _world(approval=False)
    f.add_approval(db, project_number=int(f.NUMBER))
    dg.assert_deletable(dg.DeletionTarget(f.PID), action_class=PD, approval_id=f.APPROVAL, caller_email=f.CC_SA,
                        ctx=ctx)


def test_billing_unlink_needs_its_own_approval():
    db, crm, ctx = _world()
    _assert(db, crm, ctx, "APPROVAL_MISMATCH", action=dg.ActionClass.BILLING_UNLINK)


# ---------------------------------------------------------------------------------------------- 9b sandbox TTL
def _ttl(db, crm, ctx, code, caller=f.TTL_SA):
    return _assert(db, crm, ctx, code, action=TTL, approval_id=None, caller=caller)


def test_ttl_from_non_ttl_caller_is_403():
    db, crm, ctx = _world(sandbox=True, approval=False)
    e = _ttl(db, crm, ctx, "SANDBOX_NOT_ELIGIBLE", caller=f.OTHER_SA)
    assert e.http_status == 403 and crm.calls == []


@pytest.mark.parametrize("override", [
    {"created_by": "owner-backfill"}, {"is_sandbox": False}, {"is_sandbox": "true"},
    {"sandbox_auto_decommission": None}, {"sandbox_auto_decommission": "true"}, {"sandbox_auto_decommission": 1},
    {"sandbox_designation_source": "KEYWORD"}, {"sandbox_designation_source": None},
    {"sandbox_expires_at": None}, {"sandbox_expires_at": "soon"},
    {"sandbox_expires_at": f.iso(f.NOW + timedelta(minutes=1))}])
def test_ttl_provenance_rules(override):
    db, crm, ctx = _world(sandbox=True, approval=False)
    db.docs[f"workload_provenance/{f.PID}"].update(override)
    _ttl(db, crm, ctx, "SANDBOX_NOT_ELIGIBLE")


def test_forged_ledger_flags_on_standard_project_cannot_ttl_delete():
    """RT U2: forging is_sandbox/sandbox_expires_at in the shared ledger no longer deletes anything."""
    db, crm, ctx = _world(sandbox=False, approval=False)
    db.docs[f"workloads/{f.PID}"].update({"is_sandbox": True, "sandbox_auto_decommission": True,
                                          "sandbox_designation_source": "OPERATOR_CHECKBOX",
                                          "sandbox_expires_at": f.iso(f.NOW - timedelta(days=3))})
    _ttl(db, crm, ctx, "SANDBOX_NOT_ELIGIBLE")


@pytest.mark.parametrize("status", ["DEPLOYING", "PROVISIONING", "REDEPLOYING", "DECOMMISSIONED",
                                    "DECOMMISSION_REQUESTED"])
def test_ttl_in_flight_status_refused(status):
    db, crm, ctx = _world(sandbox=True, approval=False)
    db.docs[f"workloads/{f.PID}"]["status"] = status
    _ttl(db, crm, ctx, "SANDBOX_NOT_ELIGIBLE")


def test_ttl_ledger_not_sandbox_refused():
    db, crm, ctx = _world(sandbox=True, approval=False)
    db.docs[f"workloads/{f.PID}"]["is_sandbox"] = False
    _ttl(db, crm, ctx, "SANDBOX_NOT_ELIGIBLE")


def test_ttl_project_labelled_standard_refused():
    db, crm, ctx = _world(sandbox=True, approval=False)
    crm.projects[f.NUMBER]["labels"]["stackvend-workload-type"] = "standard"
    _ttl(db, crm, ctx, "SANDBOX_NOT_ELIGIBLE")


def test_ttl_without_tag_refused():
    db, crm, ctx = _world(sandbox=True, approval=False)
    crm.tag_bindings[f.NUMBER] = []
    _ttl(db, crm, ctx, "NOT_STACKVEND_OWNED")


# ---------------------------------------------------------------------------------------------- 10 child resources
class _Facts:
    def __init__(self, region="europe-west1", in_state=True):
        self.region, self.state = region, in_state

    def primary_region(self, product_id):
        return self.region

    def in_state(self, product_id, rest_name):
        return self.state


def _child(name, facts=None, code=None):
    db, crm = f.make_world()
    f.add_approval(db, action="CHILD_RESOURCE_DELETE", resource_name=name)
    ctx = f.make_ctx(db, crm, child_resources=facts)
    target = dg.DeletionTarget(f.PID, name)
    if code:
        return _assert(db, crm, ctx, code, action=dg.ActionClass.CHILD_RESOURCE_DELETE, target=target)
    return dg.assert_deletable(target, action_class=dg.ActionClass.CHILD_RESOURCE_DELETE, approval_id=f.APPROVAL,
                               caller_email=f.CC_SA, ctx=ctx)


R = "europe-west1"


def test_child_resource_allowed_when_in_state_and_primary_region():
    v = _child(f"projects/{f.PROJECT}/locations/{R}/services/api", _Facts(R))
    assert v.resource_name.endswith("/services/api")


@pytest.mark.parametrize("name", [
    f"projects/{f.PROJECT}/locations/{R}/services/api/revisions",   # extra segment
    f"projects/{f.PROJECT}/locations/{R}/services",                  # missing segment
    f"projects/{f.PROJECT}/zones/{R}-b/instances/vm",                # zones not supported
    f"projects/{f.PROJECT}//{R}/services/api",
    f"projects/other-project/locations/{R}/services/api",            # wrong project
    f"projects/{f.HOST}/locations/{R}/services/api"])
def test_child_resource_name_rules(name):
    _child(name, _Facts(R), "RESOURCE_NOT_IN_STATE")


def test_child_resource_without_resolver_or_region_refuses():
    name = f"projects/{f.PROJECT}/locations/{R}/services/api"
    _child(name, None, "RESOURCE_NOT_IN_STATE")
    _child(name, _Facts(None), "RESOURCE_NOT_IN_STATE")


def test_child_resource_not_in_state_refuses():
    _child(f"projects/{f.PROJECT}/locations/{R}/services/api", _Facts(R, in_state=False), "RESOURCE_NOT_IN_STATE")


def test_cross_region_secondary_gke_always_refused():
    _child(f"projects/{f.PROJECT}/locations/us-east4/clusters/dr", _Facts(R), "CROSS_REGION_SECONDARY")


def test_project_level_class_rejects_resource_name():
    db, crm, ctx = _world()
    _assert(db, crm, ctx, "INVALID_REQUEST", target=dg.DeletionTarget(f.PID, "projects/x/locations/y/services/z"))


# ---------------------------------------------------------------------------------------------- 11 audit
def test_audit_failure_refuses():
    db, crm, ctx = _world()
    db.fail_write_paths.add(f"workloads")
    e = _assert(db, crm, ctx, "AUDIT_UNAVAILABLE")
    assert e.http_status == 503


# ---------------------------------------------------------------------------------------------- hygiene
def test_guard_source_has_no_folder_or_region_literals():
    src = open(os.path.join(f.VENDING_DIR, "destructive_guard.py"), encoding="utf-8").read()
    assert "folders/" not in src
    for region in ("us-central1", "us-east1", "us-east4", "us-west1", "europe-west1", "europe-west4",
                   "asia-east1", "asia-northeast1", "australia-southeast1", "northamerica-northeast1"):
        assert region not in src, region


def test_unavailable_guard_db_never_falls_back_to_default_db():
    db, crm = f.make_world()
    f.add_approval(db)
    ctx = f.make_ctx(db, crm, store=f.TestStore(db, dg.UnavailableDB("guard DB down")))
    _assert(db, crm, ctx, "LEDGER_UNAVAILABLE")


def test_consume_approval_is_single_use():
    db, crm, ctx = _world()
    v = dg.assert_deletable(dg.DeletionTarget(f.PID), action_class=PD, approval_id=f.APPROVAL,
                            caller_email=f.CC_SA, ctx=ctx)
    dg.consume_approval(v, ctx=ctx)
    rec = db.doc(f"destructive_approvals/{f.APPROVAL}")
    assert rec["status"] == "CONSUMED" and rec["consumed_by"] == f.CC_SA
    with pytest.raises(dg.DeletionRefused) as ei:
        dg.consume_approval(v, ctx=ctx)
    assert ei.value.code == "APPROVAL_CONSUMED"


def test_mark_execution_failed():
    db, crm, ctx = _world()
    v = dg.assert_deletable(dg.DeletionTarget(f.PID), action_class=PD, approval_id=f.APPROVAL,
                            caller_email=f.CC_SA, ctx=ctx)
    dg.mark_execution_failed(v, error="boom", ctx=ctx)
    assert db.doc(f"destructive_approvals/{f.APPROVAL}")["status"] == "EXECUTION_FAILED"
