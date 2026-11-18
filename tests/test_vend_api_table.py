"""VEND-API-TABLE (register row, owner 10-27): project vending enables, when it creates the child project, the APIs a
workload deploy needs, from the platform's API table (shared/api_requirements.json: base_apis + foundation_base_apis,
exactly what the workload foundation enables in every first apply: iap, pubsub, storage, ...), next to its unchanged
baseline list, in the same Service Usage call. Failures are typed on the workload record (`api_enablement`) and never
fail vending (the first apply enables the same APIs again).

Negative: the baseline APIs are requested exactly as before (same ids, same order, first); a missing table requests
only the baseline (typed VENDING.API_TABLE_UNAVAILABLE); a refused best-effort API is no VENDING.API_ENABLE_FAILED.
Hermetic: the Service Usage client is a fake."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VENDING_DIR = os.path.join(REPO_ROOT, "apps", "project-vending")
if VENDING_DIR not in sys.path:
    sys.path.insert(0, VENDING_DIR)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

for m in [
    'httpx', 'fastapi', 'google', 'google.auth', 'googleapiclient',
    'googleapiclient.discovery', 'googleapiclient.errors', 'google.cloud',
    'google.cloud.firestore', 'google.cloud.storage', 'google.cloud.secretmanager',
    'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

import vending  # noqa: E402
from vending import ProjectRepoVendingEngine  # noqa: E402

with open(os.path.join(REPO_ROOT, "shared", "api_requirements.json"), encoding="utf-8") as _fh:
    TABLE = json.load(_fh)
REQUIRED = sorted(set(TABLE["base_apis"]) | set(TABLE["foundation_base_apis"]))
# vending's list before VEND-API-TABLE (main 8be6b8e9), in its order
PRE_BASELINE = ["serviceusage.googleapis.com", "run.googleapis.com", "firestore.googleapis.com", "iam.googleapis.com",
                "cloudresourcemanager.googleapis.com", "cloudbuild.googleapis.com", "compute.googleapis.com",
                "secretmanager.googleapis.com", "iamcredentials.googleapis.com", "sts.googleapis.com",
                "identitytoolkit.googleapis.com", "artifactregistry.googleapis.com", "cloudquotas.googleapis.com",
                "cloudscheduler.googleapis.com", "eventarc.googleapis.com"]


class _Call:
    def __init__(self, fn):
        self.fn = fn

    def execute(self):
        return self.fn()


class _ServiceUsage:
    """Fake Service Usage v1: batchEnable -> operation; operations.get -> done (optionally with an error);
    services.enable refuses the ids in `refuse`."""

    def __init__(self, op_error=None, batch_raises=None, refuse=(), never_done=False):
        self.batches, self.enabled = [], []
        self.op_error, self.batch_raises, self.refuse, self.never_done = op_error, batch_raises, set(refuse), never_done

    def services(self):
        return self

    def operations(self):
        su = self

        class _Ops:
            def get(self, name):
                return _Call(lambda: {"name": name, "done": not su.never_done,
                                      **({"error": su.op_error} if su.op_error else {})})
        return _Ops()

    def batchEnable(self, parent, body):
        def run():
            if self.batch_raises:
                raise self.batch_raises
            self.batches.append((parent, list(body["serviceIds"])))
            return {"name": f"operations/op-{len(self.batches)}"}
        return _Call(run)

    def enable(self, name):
        def run():
            api = name.rsplit("/", 1)[1]
            if api in self.refuse:
                raise RuntimeError(f"{api} refused by policy")
            self.enabled.append(name)
            return {}
        return _Call(run)


def _engine():
    e = ProjectRepoVendingEngine(platform_project_id="host-platform", firestore_client=MagicMock(),
                                 secret_client=MagicMock(), crm_service=MagicMock(), billing_service=MagicMock(),
                                 storage_client=MagicMock())
    return e


@pytest.fixture(autouse=True)
def _no_sleep():
    with patch.object(vending.time, "sleep", lambda *_: None):
        yield


# ------------------------------------------------------------------------------------------------ table
def test_required_set_is_the_tables_workload_deploy_set_and_names_the_r3_r4_apis():
    assert list(vending.workload_deploy_apis()) == REQUIRED
    assert {"iap.googleapis.com", "pubsub.googleapis.com", "storage.googleapis.com"} <= set(REQUIRED)


def test_service_copy_of_the_table_is_byte_identical():
    with open(os.path.join(VENDING_DIR, "shared", "api_requirements.json"), "rb") as a, \
            open(os.path.join(REPO_ROOT, "shared", "api_requirements.json"), "rb") as b:
        assert a.read() == b.read()
    assert vending.API_TABLE_PATH == os.path.join(VENDING_DIR, "shared", "api_requirements.json")


def test_negative_baseline_is_unchanged():
    assert list(vending.VENDING_BASELINE_APIS) == PRE_BASELINE


# ------------------------------------------------------------------------------------------------ enablement
def test_one_batch_requests_the_baseline_first_then_the_table_additions():
    su = _ServiceUsage()
    r = _engine().enable_child_apis("child-1", serviceusage=su)
    added = [a for a in REQUIRED if a not in PRE_BASELINE]
    assert su.batches == [("projects/child-1", PRE_BASELINE + added)]
    assert {"iap.googleapis.com", "pubsub.googleapis.com", "storage.googleapis.com"} <= set(added)
    assert len(PRE_BASELINE + added) <= vending.SERVICE_USAGE_BATCH_MAX
    assert r == {"required": REQUIRED, "best_effort": PRE_BASELINE, "requested": PRE_BASELINE + added,
                 "status": "ENABLED", "failed": [], "code": None, "error": None}


def test_more_ids_than_one_call_takes_are_split():
    su = _ServiceUsage()
    extra = [f"x{i}.googleapis.com" for i in range(10)]
    with patch.object(vending, "workload_deploy_apis", lambda: tuple(REQUIRED + extra)):
        r = _engine().enable_child_apis("child-1", serviceusage=su)
    assert [len(b) for _p, b in su.batches] == [20, len(r["requested"]) - 20]
    assert sum((b for _p, b in su.batches), []) == r["requested"] and r["status"] == "ENABLED"


def test_a_refused_required_api_is_typed_and_the_baseline_still_enabled_one_by_one():
    su = _ServiceUsage(op_error={"code": 9, "message": "iap refused"}, refuse={"iap.googleapis.com"})
    r = _engine().enable_child_apis("child-1", serviceusage=su)
    assert r["status"] == "FAILED" and r["failed"] == ["iap.googleapis.com"]
    assert r["code"] == "VENDING.API_ENABLE_FAILED" and "iap refused" in r["error"]
    assert {n.rsplit("/", 1)[1] for n in su.enabled} == set(r["requested"]) - {"iap.googleapis.com"}


def test_negative_a_refused_best_effort_api_is_no_required_failure():
    su = _ServiceUsage(batch_raises=RuntimeError("batch quota"), refuse={"eventarc.googleapis.com"})
    r = _engine().enable_child_apis("child-1", serviceusage=su)
    assert r["failed"] == ["eventarc.googleapis.com"] and r["status"] == "FAILED" and r["code"] is None


def test_operation_still_running_is_pending_not_failed():
    su = _ServiceUsage(never_done=True)
    t = iter(range(0, 10_000, 30))
    with patch.object(vending.time, "time", lambda: next(t)):
        r = _engine().enable_child_apis("child-1", serviceusage=su)
    assert r["status"] == "PENDING" and r["failed"] == [] and r["code"] is None


def test_missing_table_requests_only_the_baseline_typed():
    su = _ServiceUsage()
    with patch.object(vending.workload_deploy_apis, "__defaults__", (os.path.join(REPO_ROOT, "no-such-table.json"),)):
        r = _engine().enable_child_apis("child-1", serviceusage=su)
    assert su.batches == [("projects/child-1", PRE_BASELINE)]
    assert r["code"] == "VENDING.API_TABLE_UNAVAILABLE" and r["required"] == [] and r["status"] == "ENABLED"


def test_client_failure_never_raises():
    class Boom:
        def services(self):
            raise RuntimeError("no credentials")
    r = _engine().enable_child_apis("child-1", serviceusage=Boom())
    assert r["status"] == "FAILED" and set(r["failed"]) == set(r["requested"])
    assert r["code"] == "VENDING.API_ENABLE_FAILED"


def test_malformed_table_is_refused(tmp_path):
    bad = tmp_path / "t.json"
    bad.write_text(json.dumps({"base_apis": ["iam.googleapis.com"], "foundation_base_apis": "iap"}), encoding="utf-8")
    with pytest.raises(ValueError):
        vending.workload_deploy_apis(str(bad))
