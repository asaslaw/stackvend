"""SAT-13: two gateway fixes in apps/orchestrator-gateway/main.py.

(a) Release-stage heartbeat guard. The workflow posts the release stage's PAUSED_FOR_APPROVAL heartbeat after it
    registers the approval callback. A decision stored in between (Control Center SUCCESS / REJECTED, or the gateway's
    own auto-merge SUCCESS) is never overwritten by that late heartbeat. The check and the write run in one Firestore
    transaction (the REAL firestore_v1.transactional retry loop over an in-memory store), so a decision that lands
    after the read aborts the commit and the read is re-run. Every other field of the heartbeat is written as before,
    and every other (stage, status) pair keeps the plain merge-set it had.
(b) Platform-URL cache. resolve_service_url keeps a Cloud Run Admin API `https://` uri for SERVICE_URL_CACHE_TTL_S
    per (project, region, service). Env overrides are never cached, failures are never cached, and the typed
    ServiceUrlUnavailable errors are unchanged (tests/test_fallback_urls_judge_stamp.py). A fake clock drives expiry.

Hermetic: fake Firestore store, fake Cloud Run module, no network.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import os
import sys
import types

import pytest
from fastapi.testclient import TestClient

from fd4f_support import REPO_ROOT, FakeDB, gw  # noqa: F401  (gw is a fixture)

TRACE, PID = "tr-sat13", "shop-app"
PATH = ("pipeline_executions", TRACE)
HEARTBEAT = {"trace_id": TRACE, "product_id": PID, "current_stage": "AWAITING_PR_APPROVAL", "stage_name": "release",
             "stage_status": "PAUSED_FOR_APPROVAL",
             "stage_summary": "Pull Request awaiting human code review (appr-1)"}
PAUSED = {"status": "PAUSED_FOR_APPROVAL", "summary": "Pull Request awaiting human code review (appr-1)"}
CC_APPROVED = {"status": "SUCCESS", "summary": "Approved by admin@example.com; merged into main",
               "decision": "APPROVED",
               "approval_id": "appr-1", "decided_by": "admin@example.com", "decided_at": "2026-10-31T10:00:00+00:00"}
CC_REJECTED = {"status": "REJECTED", "summary": "Rejected by admin@example.com: not this week", "decision": "REJECTED",
               "approval_id": "appr-1", "decided_by": "admin@example.com", "decided_at": "2026-10-31T10:00:00+00:00"}
GW_MERGED = {"status": "SUCCESS", "summary": "Auto-merged into main at https://github.com/o/r/pull/7 "
                                             "(no human review required)"}


# ================================================================================ (a) transactional store fake
def _deep_merge(cur, data):
    out = dict(cur or {})
    for k, v in data.items():
        out[k] = _deep_merge(out.get(k), v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _store(decide_between_read_and_commit=None, always_abort=False):
    """A real firestore_v1 DocumentReference subclass over an in-memory store with Firestore merge semantics (nested
    maps merge field by field). Commits are validated against the versions read in the transaction: a changed read
    set raises Aborted, and the REAL firestore_v1.transactional loop re-runs the function (same technique as
    tests/test_lane17_gateway_gates.py::_transactional_approval_store). `decide_between_read_and_commit` is a release
    stage written by "another writer" right after the first transactional read."""
    from google.api_core import exceptions as gexc
    from google.cloud.firestore_v1.document import DocumentReference

    store = {"docs": {}, "versions": {}, "log": [], "plain_sets": [], "txn_sets": [], "txn_reads": 0}

    def write(key, data, merge):
        store["docs"][key] = _deep_merge(store["docs"].get(key), data) if merge else copy.deepcopy(data)
        store["versions"][key] = store["versions"].get(key, 0) + 1

    class Txn:
        _read_only = False
        _max_attempts = 3

        def __init__(self):
            self._id, self.attempts, self.reads, self.writes = None, 0, {}, []

        def _clean_up(self):
            self.reads, self.writes, self._id = {}, [], None

        def _begin(self, retry_id=None):
            self.attempts += 1
            self._id = f"txn-{self.attempts}".encode()

        def _rollback(self):
            store["log"].append("rolled_back")
            self._clean_up()

        def set(self, ref, data, merge=False):
            store["txn_sets"].append((copy.deepcopy(data), merge))
            self.writes.append((ref._path, copy.deepcopy(data), merge))

        def _commit(self):
            stale = always_abort or any(store["versions"].get(k, 0) != v for k, v in self.reads.items())
            if not stale:
                for key, data, merge in self.writes:
                    write(key, data, merge)
            store["log"].append("aborted" if stale else "committed")
            self._clean_up()
            if stale:
                raise gexc.Aborted("concurrent modification")
            return []

    class Client:
        def transaction(self):
            return Txn()

    client = Client()

    class Snap:
        def __init__(self, data):
            self._d, self.exists = data, data is not None

        def to_dict(self):
            return copy.deepcopy(self._d) if self._d is not None else None

    class Ref(DocumentReference):
        def get(self, field_paths=None, transaction=None, **kw):
            data, ver = copy.deepcopy(store["docs"].get(self._path)), store["versions"].get(self._path, 0)
            if transaction is not None:
                transaction.reads[self._path] = ver
                store["txn_reads"] += 1
                if store["txn_reads"] == 1 and decide_between_read_and_commit is not None:
                    write(self._path, {"stages": {"release": decide_between_read_and_commit}}, True)
            return Snap(data)

        def set(self, data, merge=False):
            store["plain_sets"].append((copy.deepcopy(data), merge))
            write(self._path, data, merge)

    class Coll:
        def __init__(self, name):
            self.name = name

        def document(self, doc_id):
            return Ref(self.name, doc_id, client=client)

        def where(self, *a, **k):
            return self

        def stream(self):
            return iter([])

    class DB:
        def collection(self, name):
            return Coll(name)

        def transaction(self):
            return client.transaction()

    return store, DB()


def _post(gw, monkeypatch, db, body):
    import google.cloud.firestore as fs_mod

    monkeypatch.setattr(fs_mod, "Client", lambda *a, **k: db)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    r = TestClient(gw.app).post("/events/workflow-status", json=body)
    assert r.status_code == 200, r.text
    return r.json()


# ================================================================================ (a) heartbeat after a decision
@pytest.mark.parametrize("decided", [CC_APPROVED, CC_REJECTED, GW_MERGED], ids=["cc-approved", "cc-rejected",
                                                                                 "gateway-auto-merge"])
def test_heartbeat_after_a_decision_keeps_the_release_stage(gw, monkeypatch, decided):
    store, db = _store()
    store["docs"][PATH] = {"trace_id": TRACE, "product_id": PID, "started_at": "2026-10-31T09:00:00+00:00",
                           "stages": {"release": dict(decided), "qa": {"status": "SUCCESS", "summary": "ok"}}}
    assert _post(gw, monkeypatch, db, HEARTBEAT)["status"] == "UPDATED"
    doc = store["docs"][PATH]
    assert doc["stages"]["release"] == decided                         # status, summary and decision fields kept
    assert doc["stages"]["qa"] == {"status": "SUCCESS", "summary": "ok"}
    assert doc["current_stage"] == "AWAITING_PR_APPROVAL"              # the other fields are written as before
    assert (doc["trace_id"], doc["product_id"]) == (TRACE, PID)
    assert store["log"] == ["committed"] and store["plain_sets"] == []


# ================================================================================ (a) heartbeat before a decision
@pytest.mark.parametrize("existing", [
    None,                                                                   # first write of the run record
    {"trace_id": TRACE, "started_at": "2026-10-31T09:00:00+00:00"},         # no stages yet
    {"trace_id": TRACE, "stages": {"release": dict(PAUSED)}},               # a repeated heartbeat
    {"trace_id": TRACE, "stages": {"release": {"status": "IN_FLIGHT"}}},
    {"trace_id": TRACE, "stages": {"release": {"summary": "no status"}}},
    {"trace_id": TRACE, "stages": "not-a-map"},
])
def test_negative_heartbeat_before_a_decision_writes_as_today(gw, monkeypatch, existing):
    store, db = _store()
    if existing is not None:
        store["docs"][PATH] = copy.deepcopy(existing)
    assert _post(gw, monkeypatch, db, HEARTBEAT)["status"] == "UPDATED"
    doc = store["docs"][PATH]
    assert doc["stages"]["release"] == PAUSED
    assert doc["current_stage"] == "AWAITING_PR_APPROVAL" and store["log"] == ["committed"]


def test_negative_undecided_heartbeat_writes_the_exact_payload_of_the_plain_merge_set(gw, monkeypatch):
    """Undecided: the transaction merge-sets exactly the payload the old `doc_ref.set(update_payload, merge=True)`
    wrote for this request, and nothing else."""
    store, db = _store()
    store["docs"][PATH] = {"trace_id": TRACE, "started_at": "2026-10-31T09:00:00+00:00"}
    _post(gw, monkeypatch, db, HEARTBEAT)
    assert store["txn_sets"] == [({"trace_id": TRACE, "product_id": PID, "current_stage": "AWAITING_PR_APPROVAL",
                                   "stages": {"release": PAUSED}}, True)]
    assert store["plain_sets"] == []


# ================================================================================ (a) the read-then-write window
@pytest.mark.parametrize("decided", [CC_APPROVED, CC_REJECTED, GW_MERGED])
def test_decision_landing_after_the_read_aborts_and_the_retry_keeps_it(gw, monkeypatch, decided):
    store, db = _store(decide_between_read_and_commit=dict(decided))
    store["docs"][PATH] = {"trace_id": TRACE, "stages": {"release": {"status": "IN_FLIGHT"}}}
    store["versions"][PATH] = 1
    assert _post(gw, monkeypatch, db, HEARTBEAT)["status"] == "UPDATED"
    assert store["log"] == ["aborted", "committed"]                    # the conflicting commit retried once
    doc = store["docs"][PATH]
    assert doc["stages"]["release"] == decided and doc["current_stage"] == "AWAITING_PR_APPROVAL"


def test_a_transaction_that_never_commits_writes_nothing_and_reports_error(gw, monkeypatch):
    """Same outcome class as a failed plain write today (the handler's existing ERROR answer); never a fake write."""
    store, db = _store(always_abort=True)
    store["docs"][PATH] = {"trace_id": TRACE, "stages": {"release": dict(CC_APPROVED)}}
    before = copy.deepcopy(store["docs"][PATH])
    assert _post(gw, monkeypatch, db, HEARTBEAT)["status"] == "ERROR"
    assert store["docs"][PATH] == before and store["log"][-1] == "rolled_back"
    assert store["log"].count("aborted") == 3


# ================================================================================ (a) every other stage / status
@pytest.mark.parametrize("stage_name, stage_status", [
    ("release", "SUCCESS"), ("release", "FAILED"), ("release", "REJECTED"), ("release", None),
    ("qa", "PAUSED_FOR_APPROVAL"), ("terraform", "IN_FLIGHT"), ("plan_approval", "PAUSED_FOR_APPROVAL"),
    ("Release", "PAUSED_FOR_APPROVAL"), ("release", "paused_for_approval"),
])
def test_negative_other_stage_or_status_keeps_the_plain_merge_set(gw, monkeypatch, stage_name, stage_status):
    """FakeDB has no transaction(): any use of the transactional path would turn the answer into ERROR."""
    db = FakeDB()
    db.docs[f"pipeline_executions/{TRACE}"] = {"trace_id": TRACE, "started_at": "2026-10-31T09:00:00+00:00",
                                               "stages": {"release": dict(CC_APPROVED)}}
    body = {"trace_id": TRACE, "product_id": PID, "stage_name": stage_name, "stage_summary": "s"}
    if stage_status is not None:
        body["stage_status"] = stage_status
    assert _post(gw, monkeypatch, db, body)["status"] == "UPDATED"
    ((path, data, merge),) = db.writes
    assert path == f"pipeline_executions/{TRACE}" and merge is True
    st = {"summary": "s"} if stage_status is None else {"status": stage_status, "summary": "s"}
    assert data["stages"][stage_name] == st                               # written unconditionally, as before


def test_negative_a_run_status_update_without_a_stage_is_unchanged(gw, monkeypatch):
    db = FakeDB()
    db.docs[f"pipeline_executions/{TRACE}"] = {"trace_id": TRACE, "started_at": "x",
                                               "stages": {"release": dict(CC_APPROVED)}}
    assert _post(gw, monkeypatch, db, {"trace_id": TRACE, "current_stage": "AWAITING_PR_APPROVAL"})["status"] \
        == "UPDATED"
    ((_, data, merge),) = db.writes
    assert data == {"trace_id": TRACE, "current_stage": "AWAITING_PR_APPROVAL"} and merge is True


# ================================================================================ (a) the pure decision
@pytest.mark.parametrize("stored", [
    None, {}, {"stages": None}, {"stages": "x"}, {"stages": {}}, {"stages": {"release": None}},
    {"stages": {"release": "SUCCESS"}}, {"stages": {"release": {}}}, {"stages": {"release": dict(PAUSED)}},
    {"stages": {"release": {"status": "FAILED"}}}, {"stages": {"release": {"status": "success"}}},
    {"stages": {"qa": {"status": "SUCCESS"}}},
])
def test_negative_undecided_stored_state_returns_the_same_payload_object(gw, stored):
    payload = {"trace_id": TRACE, "current_stage": "AWAITING_PR_APPROVAL", "stages": {"release": dict(PAUSED)}}
    snapshot = copy.deepcopy(payload)
    assert gw._without_release_over_decision(payload, stored) is payload and payload == snapshot


def test_decided_stored_state_drops_only_the_release_stage(gw):
    payload = {"trace_id": TRACE, "current_stage": "AWAITING_PR_APPROVAL",
               "stages": {"release": dict(PAUSED), "discovery": {"status": "SUCCESS"}}}
    snapshot = copy.deepcopy(payload)
    out = gw._without_release_over_decision(payload, {"stages": {"release": dict(CC_REJECTED)}})
    assert out == {"trace_id": TRACE, "current_stage": "AWAITING_PR_APPROVAL",
                   "stages": {"discovery": {"status": "SUCCESS"}}}
    assert payload == snapshot                                            # the caller's payload is not mutated
    only = gw._without_release_over_decision({"trace_id": TRACE, "stages": {"release": dict(PAUSED)}},
                                             {"stages": {"release": dict(GW_MERGED)}})
    assert only == {"trace_id": TRACE}


def test_decided_statuses_match_both_terminal_writers(gw):
    """The CC mapping is read with Python's own parser (no import of the CC app); the gateway writer is called."""
    src = os.path.join(REPO_ROOT, "apps", "control-center", "routes", "approvals.py")
    tree = ast.parse(open(src, encoding="utf-8").read())
    (mapping,) = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == "RELEASE_STAGE_STATUS_BY_DECISION" for t in n.targets)]
    assert set(mapping.values()) == gw.RELEASE_STAGE_DECIDED_STATUSES
    from unittest.mock import MagicMock

    db = MagicMock()
    gw._record_release_stage_merged(db, TRACE, "Auto-merged")
    (payload,), kw = db.collection.return_value.document.return_value.set.call_args
    assert payload["stages"]["release"]["status"] in gw.RELEASE_STAGE_DECIDED_STATUSES and kw == {"merge": True}
    assert gw.RELEASE_HEARTBEAT_STATUS not in gw.RELEASE_STAGE_DECIDED_STATUSES


def test_the_workflow_heartbeat_uses_the_guarded_stage_and_status():
    import yaml

    wf = yaml.safe_load(open(os.path.join(REPO_ROOT, "workflows", "main_orchestrator.yaml"), encoding="utf-8"))
    found = []

    def walk(node):
        if isinstance(node, dict):
            body = node.get("body")
            if isinstance(body, dict) and body.get("stage_name") == "release" and "stage_status" in body:
                found.append(body["stage_status"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(wf)
    assert "PAUSED_FOR_APPROVAL" in found


# ================================================================================ (b) URL cache
SVC = "mcp-terraform-server"
LIVE = "https://mcp-terraform-server-abc123-uc.a.run.app"


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _fake_run_v2(monkeypatch, answers):
    """Each get_service pops the next answer: a uri string / None, or an exception instance to raise."""
    seen = []

    class _Client:
        def service_path(self, project, region, name):
            return f"projects/{project}/locations/{region}/services/{name}"

        def get_service(self, name=None):
            seen.append(name)
            a = answers.pop(0)
            if isinstance(a, BaseException):
                raise a
            return types.SimpleNamespace(uri=a)

    mod = types.SimpleNamespace(ServicesClient=_Client)
    monkeypatch.setitem(sys.modules, "google.cloud.run_v2", mod)
    import google.cloud as gc
    monkeypatch.setattr(gc, "run_v2", mod, raising=False)
    return seen


@pytest.fixture()
def cache(gw, monkeypatch):
    monkeypatch.delenv("TERRAFORM_MCP_URL", raising=False)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    monkeypatch.setenv("REGION", "europe-west1")
    clock = _Clock()
    monkeypatch.setattr(gw, "_service_url_clock", clock)
    return gw, clock


def test_ttl_is_ten_minutes(gw):
    assert gw.SERVICE_URL_CACHE_TTL_S == 600.0 and gw._SERVICE_URL_CACHE == {}


def test_second_call_within_the_ttl_makes_no_api_call(cache, monkeypatch):
    gw, clock = cache
    seen = _fake_run_v2(monkeypatch, [LIVE + "/"])
    assert gw.resolve_service_url(SVC) == LIVE
    clock.t += gw.SERVICE_URL_CACHE_TTL_S - 1
    assert gw.resolve_service_url(SVC) == LIVE
    assert len(seen) == 1


def test_expiry_refetches(cache, monkeypatch):
    gw, clock = cache
    moved = "https://mcp-terraform-server-def456-uc.a.run.app"
    seen = _fake_run_v2(monkeypatch, [LIVE, moved])
    assert gw.resolve_service_url(SVC) == LIVE
    clock.t += gw.SERVICE_URL_CACHE_TTL_S
    assert gw.resolve_service_url(SVC) == moved
    assert len(seen) == 2
    assert gw.resolve_service_url(SVC) == moved and len(seen) == 2   # the new answer is cached in turn


@pytest.mark.parametrize("failure, lookup", [(PermissionError("403"), "FAILED"), (None, "NO_URI"), ("", "NO_URI"),
                                             ("http://mcp-terraform-server:8080", "NO_URI")])
def test_a_failure_is_never_cached(cache, monkeypatch, failure, lookup):
    gw, clock = cache
    seen = _fake_run_v2(monkeypatch, [failure, failure, LIVE])
    for _ in range(2):
        with pytest.raises(gw.ServiceUrlUnavailable) as ei:
            gw.resolve_service_url(SVC)
        assert (ei.value.reason, ei.value.details["lookup"]) == ("SERVICE_URL_UNKNOWN", lookup)
    assert gw._SERVICE_URL_CACHE == {}
    assert gw.resolve_service_url(SVC) == LIVE and len(seen) == 3


def test_a_failed_refetch_after_expiry_never_returns_the_expired_url(cache, monkeypatch):
    gw, clock = cache
    _fake_run_v2(monkeypatch, [LIVE, PermissionError("403")])
    assert gw.resolve_service_url(SVC) == LIVE
    clock.t += gw.SERVICE_URL_CACHE_TTL_S + 1
    with pytest.raises(gw.ServiceUrlUnavailable):
        gw.resolve_service_url(SVC)


def test_an_env_override_wins_and_is_never_cached(cache, monkeypatch):
    gw, clock = cache
    seen = _fake_run_v2(monkeypatch, [LIVE])
    assert gw.resolve_service_url(SVC) == LIVE                         # cached from the API
    monkeypatch.setenv("TERRAFORM_MCP_URL", "https://override-a.example/")
    assert gw.resolve_service_url(SVC) == "https://override-a.example"
    monkeypatch.setenv("TERRAFORM_MCP_URL", "https://override-b.example")
    assert gw.resolve_service_url(SVC) == "https://override-b.example"  # read on every call
    assert list(gw._SERVICE_URL_CACHE.values()) == [(LIVE, 1000.0 + gw.SERVICE_URL_CACHE_TTL_S)]
    monkeypatch.delenv("TERRAFORM_MCP_URL")
    assert gw.resolve_service_url(SVC) == LIVE and len(seen) == 1


def test_the_key_is_project_region_and_service(cache, monkeypatch):
    gw, clock = cache
    other = "https://mcp-infracost-server-abc123-uc.a.run.app"
    seen = _fake_run_v2(monkeypatch, [LIVE, LIVE.replace("uc", "ew"), "https://p2.example", other])
    monkeypatch.delenv("INFRACOST_MCP_URL", raising=False)
    assert gw.resolve_service_url(SVC) == LIVE
    monkeypatch.setenv("REGION", "us-east1")
    assert gw.resolve_service_url(SVC) == LIVE.replace("uc", "ew")
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project-2")
    assert gw.resolve_service_url(SVC) == "https://p2.example"
    assert gw.resolve_service_url("mcp-infracost-server") == other
    assert seen == [
        f"projects/mock-stackvend-project/locations/europe-west1/services/{SVC}",
        f"projects/mock-stackvend-project/locations/us-east1/services/{SVC}",
        f"projects/mock-stackvend-project-2/locations/us-east1/services/{SVC}",
        "projects/mock-stackvend-project-2/locations/us-east1/services/mcp-infracost-server"]


def test_negative_unconfigured_lookup_is_still_the_typed_error_and_caches_nothing(cache, monkeypatch):
    gw, clock = cache
    seen = _fake_run_v2(monkeypatch, [LIVE])
    assert gw.resolve_service_url(SVC) == LIVE
    monkeypatch.delenv("REGION")
    with pytest.raises(gw.ServiceUrlUnavailable) as ei:
        gw.resolve_service_url(SVC)                                    # never served from another key
    assert ei.value.details["lookup"] == "NOT_CONFIGURED" and len(seen) == 1
