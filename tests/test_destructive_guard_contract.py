"""
Lane 18 <-> lane 14 identity contract (plan 2.1, lane 14 rev 3 section 1.0-1.1, G1).

Until lane 18 S5, vending carries its own implementation of guard checks 1-7 (`destructive_guard.verify_identity`);
lane 14 owns `shared/managed_target.py` (`verify_managed_target`) with the SAME refusal codes. This file is the parity
test: one fixture table, both implementations, identical codes (or identical ManagedTarget fields on success).

* `test_vending_identity_contract` always runs: it pins the contract on the vending side.
* `test_managed_target_matches_vending` runs once `shared/managed_target.py` exists (lane 14 PR-M) and is skipped
  before that. It builds lane 14's context with the field names of lane 14 rev 3 section 1.1
  (host_project_ids, host_project_number, managed_root_folder_id, managed_tag_value, crm, db, guard_db, clock) and
  passes the same fake Firestore and CRM (methods get_project, get_ancestry, list_tag_bindings; failures raise
  destructive_guard.CRMUnavailable). If lane 14's adapter needs a different error type, adjust ONLY the fake here.
* At S5 vending imports `verify_managed_target` and this file is retired (plan 7, S5).
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib
import importlib.util

import pytest

import destructive_guard_fakes as f
from destructive_guard_fakes import dg


def _s(path, **fields):
    def apply(db, crm, kw):
        db.docs[path].update(fields)
    return apply


def _del(path, field=None):
    def apply(db, crm, kw):
        if field is None:
            del db.docs[path]
        else:
            del db.docs[path][field]
    return apply


def _crm(fn):
    def apply(db, crm, kw):
        fn(crm)
    return apply


def _ctx(**over):
    def apply(db, crm, kw):
        kw.update(over)
    return apply


W, P = f"workloads/{f.PID}", f"workload_provenance/{f.PID}"

# (case id, mutation, expected code or None for success)
CASES = [
    ("ok", None, None),
    ("ok_backfill", _s(P, created_by="owner-backfill"), None),
    ("ok_int_number", _s(P, project_number=int(f.NUMBER)), None),
    ("cfg_root", _ctx(managed_root_folder_id=None), "GUARD_UNCONFIGURED"),
    ("cfg_tag", _ctx(managed_tag_value=None), "GUARD_UNCONFIGURED"),
    ("cfg_hosts", _ctx(host_project_ids=frozenset()), "GUARD_UNCONFIGURED"),
    ("ledger_missing", _del(W), "LEDGER_MISSING"),
    ("ledger_is_castor", _s(W, is_castor=True), "PLATFORM_WORKLOAD"),
    ("ledger_no_project", _del(W, "project_id"), "LEDGER_UNPROVENANCED"),
    ("prov_missing", _del(P), "LEDGER_UNPROVENANCED"),
    ("prov_creator", _s(P, created_by="control-center"), "LEDGER_UNPROVENANCED"),
    ("prov_number", _s(P, project_number=""), "LEDGER_UNPROVENANCED"),
    ("prov_project", _s(P, project_id="elsewhere"), "LEDGER_MISMATCH"),
    ("reverse_unique", lambda db, crm, kw: db.docs.update({"workloads/twin": {"project_id": f.PROJECT}}),
     "LEDGER_MISMATCH"),
    ("host_id", lambda db, crm, kw: (db.docs[W].update(project_id=f.HOST), db.docs[P].update(project_id=f.HOST)),
     "HOST_PROJECT"),
    ("crm_mismatch", _crm(lambda c: c.projects[f.NUMBER].update(projectId="renamed")), "CRM_MISMATCH"),
    ("crm_not_active", _crm(lambda c: c.projects[f.NUMBER].update(state="DELETE_REQUESTED")), "NOT_ACTIVE"),
    ("crm_429", _crm(lambda c: c.fail.update(get_project=429)), "CRM_UNAVAILABLE"),
    ("crm_503", _crm(lambda c: c.fail.update(get_project=503)), "CRM_UNAVAILABLE"),
    ("no_tag", _crm(lambda c: c.tag_bindings.update({f.NUMBER: []})), "NOT_STACKVEND_OWNED"),
    ("tag_inherited", _crm(lambda c: c.tag_bindings.update({f.NUMBER: [
        {"parent": f"//cloudresourcemanager.googleapis.com/folders/{f.ROOT}", "tagValue": f.TAG}]})),
     "NOT_STACKVEND_OWNED"),
    ("tag_other_value", _crm(lambda c: c.tag_bindings[f.NUMBER][0].update(tagValue="tagValues/1")),
     "NOT_STACKVEND_OWNED"),
    ("tag_429", _crm(lambda c: c.fail.update(list_tag_bindings=429)), "CRM_UNAVAILABLE"),
    ("labels_missing", _crm(lambda c: c.projects[f.NUMBER].update(labels={})), "NOT_STACKVEND_OWNED"),
    ("label_product", _crm(lambda c: c.projects[f.NUMBER]["labels"].update({"stackvend-product-id": "x"})),
     "NOT_STACKVEND_OWNED"),
    ("not_in_folder", _crm(lambda c: c.ancestry[f.PROJECT][2]["resourceId"].update(id="1")),
     "NOT_IN_MANAGED_FOLDER"),
    ("ancestry_503", _crm(lambda c: c.fail.update(get_ancestry=503)), "ANCESTRY_UNAVAILABLE"),
]


def _fixture(mutation):
    db, crm = f.make_world()
    kw = {}
    if mutation:
        mutation(db, crm, kw)
    return db, crm, kw


def _vending_result(db, crm, kw):
    try:
        # host number pre-resolved, as lane 14's context carries it (host_project_number)
        ctx_kw = {"_host_numbers": frozenset({f.HOST_NUMBER})}
        ctx_kw.update(kw)
        ident = dg.verify_identity(f.PID, ctx=f.make_ctx(db, crm, **ctx_kw))
    except dg.DeletionRefused as e:
        return ("REFUSED", e.code)
    return ("OK", ident.project_id, ident.project_number, ident.workload_type, ident.provenance_created_by)


@pytest.mark.parametrize("case,mutation,expected", CASES, ids=[c[0] for c in CASES])
def test_vending_identity_contract(case, mutation, expected):
    db, crm, kw = _fixture(mutation)
    result = _vending_result(db, crm, kw)
    if expected is None:
        assert result[0] == "OK" and result[1:3] == (f.PROJECT, f.NUMBER)
    else:
        assert result == ("REFUSED", expected)
    assert db.writes == [] and crm.mutating_calls() == []  # the identity half never writes


def _managed_target():
    if importlib.util.find_spec("shared") is None:
        return None
    try:
        spec = importlib.util.find_spec("shared.managed_target")
    except (ImportError, ValueError):
        return None
    return importlib.import_module("shared.managed_target") if spec else None


def test_managed_target_matches_vending():
    mt = _managed_target()
    if mt is None:
        pytest.skip("shared/managed_target.py not merged yet (lane 14 PR-M); vending side pinned above")
    mismatches = []
    for case, mutation, _expected in CASES:
        db, crm, kw = _fixture(mutation)
        want = _vending_result(db, crm, kw)
        db, crm, kw = _fixture(mutation)
        ctx_kw = dict(host_project_ids=frozenset({f.HOST}), host_project_number=f.HOST_NUMBER,
                      managed_root_folder_id=f.ROOT, managed_tag_value=f.TAG, crm=crm, db=db, guard_db=db,
                      clock=lambda: f.NOW)
        ctx_kw.update(kw)
        try:
            t = mt.verify_managed_target(f.PID, ctx=mt.ManagedTargetContext(**ctx_kw))
            got = ("OK", t.project_id, str(t.project_number), t.workload_type, t.provenance_created_by)
        except mt.TargetRefused as e:
            got = ("REFUSED", e.code)
        if got != want:
            mismatches.append((case, want, got))
    assert mismatches == []
