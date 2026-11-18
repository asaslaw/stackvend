"""
In-memory fakes for the lane 18 destructive-guard tests (no network, no GCP, no Firestore client).

FakeDB is a small Firestore stand-in (collection/document/get/set/create/update/where/stream/transaction) so the real
`FirestoreGuardStore` code runs in tests, and so lane 14's `shared/managed_target.py` can later run on the same
fixtures (tests/test_destructive_guard_contract.py). FakeCRM records every call; mutating calls are listed in
MUTATING so tests can assert "zero mutating calls" on every refusal.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import copy
import importlib.util
import itertools
import os
import sys
from datetime import datetime, timedelta, timezone

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VENDING_DIR = os.path.join(REPO_ROOT, "apps", "project-vending")
if VENDING_DIR not in sys.path:
    sys.path.insert(0, VENDING_DIR)

import destructive_guard as dg  # noqa: E402

NOW = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
HOST = "mock-stackvend-project"
HOST_NUMBER = "999000999000"
ROOT = "4242"
TAG = "tagValues/777"
PID = "shop-api"
PROJECT = "shop-api-a1b2c3"
NUMBER = "123456789012"
CC_SA = "sa-castor-cc@mock-stackvend-project.iam.gserviceaccount.com"
TTL_SA = CC_SA
OTHER_SA = "sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com"
ADMIN = "owner@example.com"
APPROVAL = "appr-1"


class _Snap:
    def __init__(self, doc_id, data):
        self.id = doc_id
        self.exists = data is not None
        self._data = copy.deepcopy(data)

    def to_dict(self):
        return copy.deepcopy(self._data)


class FakeTxn:
    def __init__(self, db):
        self.db = db

    def update(self, ref, fields):
        ref.update(fields)


class _Doc:
    def __init__(self, db, path):
        self.db, self.path = db, path
        self.id = path.rsplit("/", 1)[-1]

    def get(self, transaction=None):
        self.db._maybe_fail(self.path)
        return _Snap(self.id, self.db.docs.get(self.path))

    def set(self, data, merge=False):
        self.db._maybe_fail_write(self.path)
        self.db.writes.append(("set", self.path, copy.deepcopy(data)))
        if merge and self.path in self.db.docs:
            self.db.docs[self.path].update(copy.deepcopy(data))
        else:
            self.db.docs[self.path] = copy.deepcopy(data)

    def create(self, data):
        self.db._maybe_fail_write(self.path)
        if self.path in self.db.docs:
            raise RuntimeError(f"AlreadyExists: {self.path}")
        self.db.writes.append(("create", self.path, copy.deepcopy(data)))
        self.db.docs[self.path] = copy.deepcopy(data)

    def update(self, fields):
        self.db._maybe_fail_write(self.path)
        if self.path not in self.db.docs:
            raise RuntimeError(f"NotFound: {self.path}")
        self.db.writes.append(("update", self.path, copy.deepcopy(fields)))
        self.db.docs[self.path].update(copy.deepcopy(fields))

    def collection(self, name):
        return _Coll(self.db, f"{self.path}/{name}")


class _Query:
    def __init__(self, coll, field, op, value):
        self.coll, self.field, self.op, self.value = coll, field, op, value

    def stream(self):
        self.coll.db._maybe_fail(self.coll.path + "?query")
        assert self.op == "=="
        prefix = self.coll.path + "/"
        for path, data in sorted(self.coll.db.docs.items()):
            rest = path[len(prefix):] if path.startswith(prefix) else None
            if rest and "/" not in rest and _field_value(data, self.field) == self.value:
                yield _Snap(rest, data)


def _field_value(data, field):
    """A Firestore field path: a dotted name reads a nested map field (SAT-41: `stages.terraform.status`)."""
    value = data
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


class _Coll:
    _ids = itertools.count(1)

    def __init__(self, db, path):
        self.db, self.path = db, path

    def document(self, doc_id=None):
        return _Doc(self.db, f"{self.path}/{doc_id or 'auto' + str(next(self._ids))}")

    def where(self, field, op, value):
        if op == ">=":   # FD-7L-F4: a type-scoped numeric range filter, as Firestore applies it
            return _Ordered(self, None, False, None, (field, value))
        return _Query(self, field, op, value)

    def stream(self):
        self.db._maybe_fail(self.path + "?stream")
        prefix = self.path + "/"
        for path, data in sorted(self.db.docs.items()):
            rest = path[len(prefix):] if path.startswith(prefix) else None
            if rest and "/" not in rest:
                yield _Snap(rest, data)

    # FD-7L-F4: order_by(field, direction=...) / limit(n), enough for the mode change log queries.
    def order_by(self, field, direction="ASCENDING"):
        return _Ordered(self, field, direction == "DESCENDING")

    def limit(self, n):
        return _Ordered(self, None, False, n)


def _numeric(v):
    return not isinstance(v, bool) and isinstance(v, (int, float))


class _Ordered:
    def __init__(self, coll, field, desc, n=None, at_least=None):
        self.coll, self.field, self.desc, self.n, self.at_least = coll, field, desc, n, at_least

    def order_by(self, field, direction="ASCENDING"):
        return _Ordered(self.coll, field, direction == "DESCENDING", self.n, self.at_least)

    def limit(self, n):
        return _Ordered(self.coll, self.field, self.desc, n, self.at_least)

    def stream(self):
        rows = list(self.coll.stream())
        if self.at_least is not None:
            f, low = self.at_least
            rows = [r for r in rows if _numeric((r.to_dict() or {}).get(f)) and (r.to_dict() or {}).get(f) >= low]
        if self.field is not None:
            rows.sort(key=lambda s: (s.to_dict() or {}).get(self.field) or 0, reverse=self.desc)
        return iter(rows if self.n is None else rows[:self.n])


class FakeDB:
    def __init__(self):
        self.docs = {}
        self.writes = []
        self.fail_paths = set()       # read failures (exact path, or "<collection>?query")
        self.fail_write_paths = set()

    def collection(self, name):
        return _Coll(self, name)

    def transaction(self):
        return FakeTxn(self)

    def _maybe_fail(self, path):
        if path in self.fail_paths:
            raise RuntimeError(f"503 Service Unavailable reading {path}")

    def _maybe_fail_write(self, path):
        if path in self.fail_write_paths or path.split("/", 1)[0] in self.fail_write_paths:
            raise RuntimeError(f"503 Service Unavailable writing {path}")

    def doc(self, path):
        return self.docs.get(path)

    def audit_records(self, pid=PID):
        prefix = f"workloads/{pid}/audit_logs/"
        return [d for p, d in sorted(self.docs.items()) if p.startswith(prefix)]


class TestStore(dg.FirestoreGuardStore):
    """The real store, with the Firestore transaction runner replaced by a direct call on the fake."""
    __test__ = False

    def _run_in_transaction(self, body):
        body(FakeTxn(self.guard_db))


class FakeCRM:
    MUTATING = {"delete_project", "delete_lien", "patch_labels", "create_tag_binding", "delete_dns_rrset"}

    def __init__(self):
        self.projects = {}       # number -> project dict (v3 shape)
        self.ancestry = {}       # project id -> ancestor list (v1 shape)
        self.liens = {}          # number -> [lien]
        self.tag_bindings = {}   # number -> [binding]
        self.fail = {}           # method -> status code (raises CRMUnavailable)
        self.fail_after = {}     # method -> (calls allowed before failing, status)
        self.calls = []

    def _hit(self, method, *args):
        self.calls.append((method,) + args)
        if method in self.fail:
            raise dg.CRMUnavailable(method, self.fail[method])
        if method in self.fail_after:
            allowed, status = self.fail_after[method]
            if sum(1 for c in self.calls if c[0] == method) > allowed:
                raise dg.CRMUnavailable(method, status)

    def mutating_calls(self):
        return [c for c in self.calls if c[0] in self.MUTATING]

    def count(self, method):
        return sum(1 for c in self.calls if c[0] == method)

    def _by_number_or_id(self, key):
        if key in self.projects:
            return self.projects[key]
        for p in self.projects.values():
            if p.get("projectId") == key:
                return p
        raise dg.CRMUnavailable(f"projects.get {key}", 403)

    def get_project(self, number_or_id):
        self._hit("get_project", number_or_id)
        return copy.deepcopy(self._by_number_or_id(number_or_id))

    def get_ancestry(self, project_id):
        self._hit("get_ancestry", project_id)
        return copy.deepcopy(self.ancestry.get(project_id, []))

    def list_liens(self, number):
        self._hit("list_liens", number)
        return copy.deepcopy(self.liens.get(number, []))

    def list_tag_bindings(self, number):
        self._hit("list_tag_bindings", number)
        return copy.deepcopy(self.tag_bindings.get(number, []))

    def create_tag_binding(self, number, tag_value):
        self._hit("create_tag_binding", number, tag_value)
        self.tag_bindings.setdefault(number, []).append(
            {"parent": f"//cloudresourcemanager.googleapis.com/projects/{number}", "tagValue": tag_value})
        return {"name": "operations/tb"}

    def patch_labels(self, number, labels):
        self._hit("patch_labels", number, dict(labels))
        self.projects[number]["labels"] = dict(labels)
        return {"name": "operations/patch"}

    def delete_lien(self, name):
        self._hit("delete_lien", name)
        return {}

    def delete_project(self, number):
        self._hit("delete_project", number)
        self.projects[number]["state"] = "DELETE_REQUESTED"
        return {"name": f"operations/delete-{number}"}

    def delete_dns_rrset(self, project, zone, name, rtype):
        self._hit("delete_dns_rrset", project, zone, name, rtype)
        return {}


class FakeChildIAM:
    """Child-project IAM policies (getIamPolicy / setIamPolicy, the dg.RestCRM shape) for the vend-time grants
    (B1 owners, RT14-31 Control Center log reader). `err` is the CRMUnavailable class to raise (the vending module's
    own instance when the root conftest sandbox gives a test file another one)."""

    def __init__(self, policies=None, fail_get=None, fail_set=None, drop_set=False, err=None):
        self.policies = copy.deepcopy(policies or {})   # project id -> policy
        self.fail_get, self.fail_set, self.drop_set = list(fail_get or []), list(fail_set or []), drop_set
        self.err = err or dg.CRMUnavailable
        self.calls = []

    def get_iam_policy(self, project_id):
        self.calls.append(("get", project_id))
        if self.fail_get:
            raise self.err(f"getIamPolicy {project_id}", self.fail_get.pop(0))
        return copy.deepcopy(self.policies.get(project_id, {"version": 1, "etag": "e0", "bindings": []}))

    def set_iam_policy(self, project_id, policy):
        self.calls.append(("set", project_id, copy.deepcopy(policy)))
        if self.fail_set:
            raise self.err(f"setIamPolicy {project_id}", self.fail_set.pop(0))
        if self.drop_set:
            return {"bindings": []}
        self.policies[project_id] = copy.deepcopy(policy)
        return copy.deepcopy(policy)

    def sets(self):
        return [c for c in self.calls if c[0] == "set"]


def iso(dt):
    return dt.isoformat()


def add_project(crm, project_id, number, *, labels=None, state="ACTIVE", root=ROOT, tag=TAG, tagged=True):
    crm.projects[number] = {"name": f"projects/{number}", "projectId": project_id, "state": state,
                            "labels": dict(labels or {}), "createTime": "2026-09-01T00:00:00Z"}
    crm.ancestry[project_id] = [{"resourceId": {"type": "project", "id": project_id}},
                                {"resourceId": {"type": "folder", "id": "5555"}},
                                {"resourceId": {"type": "folder", "id": root}},
                                {"resourceId": {"type": "organization", "id": "1"}}]
    if tagged:
        crm.tag_bindings[number] = [{"parent": f"//cloudresourcemanager.googleapis.com/projects/{number}",
                                     "tagValue": tag}]


def make_world(*, sandbox=False, expired=True):
    """A legit vending-born workload (standard by default) with ledger, provenance, labels, tag and ancestry."""
    db, crm = FakeDB(), FakeCRM()
    crm.projects[HOST_NUMBER] = {"name": f"projects/{HOST_NUMBER}", "projectId": HOST, "state": "ACTIVE"}
    wtype = "sandbox" if sandbox else "standard"
    add_project(crm, PROJECT, NUMBER, labels={"stackvend-managed": "true", "stackvend-product-id": PID,
                                             "stackvend-workload-type": wtype, "team": "x"})
    db.docs[f"workloads/{PID}"] = {"product_id": PID, "project_id": PROJECT, "project_number": NUMBER,
                                   "status": "ACTIVE", "is_castor": False, "is_sandbox": sandbox,
                                   "trace_id": "vend-tr-shop-api"}
    expires = NOW - timedelta(days=1) if expired else NOW + timedelta(days=1)
    db.docs[f"workload_provenance/{PID}"] = {
        "created_by": "stackvend-vending", "crm_create_operation": "operations/cp.1", "product_id": PID,
        "project_id": PROJECT, "project_number": NUMBER, "created_at": iso(NOW - timedelta(days=8)),
        "trace_id": "vend-tr-shop-api", "is_sandbox": sandbox, "sandbox_auto_decommission": sandbox,
        "sandbox_designation_source": "OPERATOR_CHECKBOX" if sandbox else None,
        "sandbox_ttl_days": 7 if sandbox else None, "sandbox_expires_at": iso(expires) if sandbox else None,
        "extensions": 0, "liens": [], "dns_records": []}
    return db, crm


def make_ctx(db, crm, **overrides):
    kw = dict(host_project_ids=frozenset({HOST}), managed_root_folder_id=ROOT, managed_tag_value=TAG,
              ttl_callers=frozenset({TTL_SA}), crm=crm, store=TestStore(db), clock=lambda: NOW)
    kw.update(overrides)
    return dg.GuardContext(**kw)


def add_approval(db, approval_id=APPROVAL, **overrides):
    rec = {"status": "APPROVED", "action": "PROJECT_DECOMMISSION", "product_id": PID, "project_id": PROJECT,
           "project_number": NUMBER, "resource_name": None, "principal_type": "USER", "approved_by": ADMIN,
           "approved_by_role": "ADMIN", "approved_at": iso(NOW - timedelta(minutes=2)),
           "expires_at": iso(NOW + timedelta(minutes=13))}
    rec.update(overrides)
    db.docs[f"destructive_approvals/{approval_id}"] = rec
    return rec


def load_vending_main():
    """Loads apps/project-vending/main.py under a unique module name (other suites own sys.modules['main']).

    Secret Manager (unused by these tests) is stubbed when absent: after some earlier root-suite modules a fresh
    import of google.cloud.secretmanager fails on google.iam. The root conftest rolls the stub back after this
    module (FD-05A sys.modules sandbox), so it never leaks into other files."""
    from unittest.mock import MagicMock
    if "google.cloud.secretmanager" not in sys.modules:
        sys.modules["google.cloud.secretmanager"] = MagicMock()
    spec = importlib.util.spec_from_file_location("stackvend_vending_main_lane18",
                                                  os.path.join(VENDING_DIR, "main.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
