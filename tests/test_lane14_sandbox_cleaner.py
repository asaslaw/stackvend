"""
Wave 2 lane 14 PR-6: sandbox-garbage-collector-job ledger loop (C32, FD-4BC; plan
docs/planning/wave2-lane14-core-services-plan.md sections 1.6, 2.0, 2.2; register row L14-l).

Hermetic: an in-memory Firestore fake (default + guard database), injected Cloud Run URL resolver, ID-token fetcher
and HTTP poster. Nothing here builds a cloud client or reaches the network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import importlib.util
import json
import logging
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from google.api_core.exceptions import AlreadyExists, ServiceUnavailable

REPO = Path(__file__).resolve().parent.parent
APP_DIR = REPO / "apps" / "sandbox-cleaner"
SENTINEL_DIR = REPO / "apps" / "log-sre-sentinel"


def _load_modules():
    sys.path.insert(0, str(APP_DIR))
    try:
        import cleaner as cleaner_mod

        spec = importlib.util.spec_from_file_location("lane14_cleaner_main", APP_DIR / "main.py")
        main_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(main_mod)
    finally:
        sys.path.remove(str(APP_DIR))
    sys.path.insert(0, str(SENTINEL_DIR))
    try:
        import sre_classifier as clf_mod
    finally:
        sys.path.remove(str(SENTINEL_DIR))
    return cleaner_mod, main_mod, clf_mod


cleaner, cleaner_main, clf = _load_modules()

HOST = "mock-stackvend-project"
REGION = "us-central1"
VENDING_URL = "https://project-repo-vending-service-abc123-uc.a.run.app"
NOW = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)
CHILD = "castor-child-123"


# ---------------------------------------------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------------------------------------------
class FakeSnap:
    def __init__(self, doc_id, data):
        self.id = doc_id
        self._data = copy.deepcopy(data)

    @property
    def exists(self):
        return self._data is not None

    def to_dict(self):
        return copy.deepcopy(self._data)


class FakeDocRef:
    def __init__(self, db, coll, doc_id):
        self.db, self.coll, self.id = db, coll, doc_id

    def _store(self):
        return self.db.data.setdefault(self.coll, {})

    def get(self):
        self.db._check("get", self.coll)
        return FakeSnap(self.id, self._store().get(self.id))

    def create(self, data):
        self.db._check("create", self.coll)
        if self.id in self._store():
            raise AlreadyExists(f"{self.coll}/{self.id}")
        self.db.writes.append(("create", self.coll, self.id))
        self._store()[self.id] = copy.deepcopy(data)

    def set(self, data, merge=False):
        self.db._check("set", self.coll)
        self.db.writes.append(("set", self.coll, self.id))
        self._store()[self.id] = copy.deepcopy(data)

    def update(self, data):
        self.db._check("update", self.coll)
        self.db.writes.append(("update", self.coll, self.id))
        self._store()[self.id].update(copy.deepcopy(data))

    def delete(self):
        self.db.writes.append(("delete", self.coll, self.id))
        self._store().pop(self.id, None)


class FakeQuery:
    def __init__(self, db, coll, filters):
        self.db, self.coll, self.filters = db, coll, filters

    def where(self, *args, filter=None):
        assert filter is not None and not args, "the cleaner must use FieldFilter (keyword form)"
        assert filter.op_string == "=="
        return FakeQuery(self.db, self.coll, self.filters + [(filter.field_path, filter.value)])

    def stream(self):
        self.db._check("stream", self.coll)
        self.db.queries.append((self.coll, tuple(self.filters)))
        for doc_id, data in list(self.db.data.get(self.coll, {}).items()):
            if all(isinstance(data, dict) and data.get(k) == v for k, v in self.filters):
                yield FakeSnap(doc_id, data)


class FakeCollection(FakeQuery):
    def __init__(self, db, coll):
        super().__init__(db, coll, [])

    def document(self, doc_id):
        return FakeDocRef(self.db, self.coll, doc_id)


class FakeDB:
    def __init__(self, name="(default)"):
        self.name = name
        self.data = {}
        self.writes = []
        self.queries = []
        self.fail = {}  # (op, collection) -> exception

    def _check(self, op, coll):
        exc = self.fail.get((op, coll))
        if exc is not None:
            raise exc

    def collection(self, name):
        return FakeCollection(self, name)


class FakeVending:
    """Records every :expire call; answers with a programmable (status, body)."""

    def __init__(self, status=404, body=None):
        self.calls = []
        self.status, self.body = status, body if body is not None else {"detail": "Not Found"}
        self.per_eid = {}

    def __call__(self, url, *, headers, json_body, timeout):
        self.calls.append({"url": url, "headers": headers, "json": json_body, "timeout": timeout})
        eid = json_body["eid"]
        return self.per_eid.get(eid, (self.status, self.body))


def ledger_record(eid=None, *, age=timedelta(hours=3), ttl=3600, status="REGISTERED", **over):
    eid = eid or str(uuid.uuid4())
    data = {
        "product_id": "prod-a",
        "project_id": CHILD,
        "project_number": "4455",
        "rest_name": f"projects/{CHILD}/locations/{REGION}/services/qa-tmp-1",
        "kind": "run.service",
        "resource_create_time": NOW - age,
        "ttl_seconds": ttl,
        "registered_by": "sa-qa@x.iam.gserviceaccount.com",
        "registered_at": (NOW - age).isoformat(),
        "status": status,
    }
    data.update(over)
    return eid, data


def make(env=None, *, ledger=None, db=None, vending=None, url=VENDING_URL, url_error=None, token_error=None):
    db = db if db is not None else FakeDB()
    env = {"PROJECT_ID": HOST, "REGION": REGION, "CLOUD_RUN_EXECUTION": "sandbox-garbage-collector-job-abcde"} \
        if env is None else env
    vending = vending if vending is not None else FakeVending()
    resolver_calls, token_calls, factory_calls = [], [], []

    def resolver(project, region, service):
        resolver_calls.append((project, region, service))
        if url_error:
            raise url_error
        return url

    def fetch_token(audience):
        token_calls.append(audience)
        if token_error:
            raise token_error
        return "id-token-xyz"

    def factory(project, database):
        factory_calls.append((project, database))
        if database:
            return ledger
        return db

    # The default DB doubles as the ledger unless STACKVEND_GUARD_FIRESTORE_DATABASE is set (then: `ledger`).
    gc = cleaner.SandboxGarbageCollector(
        env=env, firestore_client=db, service_url_resolver=resolver, id_token_fetcher=fetch_token,
        http_post=vending, clock=lambda: NOW, firestore_factory=factory)
    return gc, db, vending, {"resolver": resolver_calls, "token": token_calls, "factory": factory_calls}


def put(db, eid, data):
    db.data.setdefault(cleaner.LEDGER_COLLECTION, {})[eid] = data


# ---------------------------------------------------------------------------------------------------------------
# The ledger loop
# ---------------------------------------------------------------------------------------------------------------
def test_empty_ledger_makes_zero_calls_and_exits_zero():
    gc, db, vending, calls = make()
    report = gc.execute_cleanup()
    assert report["exit_code"] == 0 and report["status"] == "COMPLETED"
    assert vending.calls == [] and calls["resolver"] == [] and calls["token"] == []
    assert db.queries == [(cleaner.LEDGER_COLLECTION, (("status", "REGISTERED"),))]
    run = db.data[cleaner.RUN_RECORD_COLLECTION]["sandbox-garbage-collector-job-abcde"]
    assert run["outcome"] == "COMPLETED"
    assert db.data[cleaner.SUMMARY_COLLECTION]["sandbox-garbage-collector-job-abcde"]["deleted_count"] == 0


def test_expired_record_makes_exactly_one_call_with_the_exact_eid():
    gc, db, vending, calls = make(vending=FakeVending(200, {"status": "DELETED", "operation": "operations/op-1"}))
    eid, data = ledger_record()
    put(db, eid, data)
    report = gc.execute_cleanup()
    assert len(vending.calls) == 1
    call = vending.calls[0]
    assert call["url"] == f"{VENDING_URL}/ephemeral/{eid}:expire"
    assert call["headers"] == {"Authorization": "Bearer id-token-xyz"}
    assert call["json"]["eid"] == eid and call["json"]["requested_by"] == cleaner.JOB_NAME
    assert calls["resolver"] == [(HOST, REGION, "project-repo-vending-service")]
    assert calls["token"] == [VENDING_URL]  # audience == the URL called
    assert report["exit_code"] == 0 and report["deleted_count"] == 1
    assert report["requests"][0]["operation"] == "operations/op-1"
    audit = db.data[cleaner.AUDIT_COLLECTION][f"sandbox-garbage-collector-job-abcde--{eid}"]
    assert audit["action"] == "EPHEMERAL_TTL_REQUEST" and audit["outcome"] == "DELETED"


def test_unexpired_record_makes_zero_calls():
    gc, db, vending, _ = make()
    eid, data = ledger_record(age=timedelta(minutes=30), ttl=3600)
    put(db, eid, data)
    report = gc.execute_cleanup()
    assert vending.calls == [] and report["exit_code"] == 0 and report["not_yet_due_count"] == 1


def test_record_exactly_at_expiry_is_due():
    gc, db, vending, _ = make()
    eid, data = ledger_record(age=timedelta(seconds=3600), ttl=3600)
    put(db, eid, data)
    gc.execute_cleanup()
    assert len(vending.calls) == 1


def test_non_registered_records_are_never_requested():
    gc, db, vending, _ = make()
    for status in ("DELETED", "REFUSED", "registered", ""):
        eid, data = ledger_record(status=status)
        put(db, eid, data)
    report = gc.execute_cleanup()
    assert vending.calls == [] and report["exit_code"] == 0


def test_dry_run_makes_zero_calls_and_zero_writes():
    gc, db, vending, calls = make()
    eid, data = ledger_record()
    put(db, eid, data)
    report = gc.execute_cleanup(dry_run=True)
    assert vending.calls == [] and calls["token"] == [] and db.writes == []
    assert [r["outcome"] for r in report["requests"]] == ["WOULD_REQUEST"]
    assert report["exit_code"] == 0 and report["dry_run"] is True


def test_vending_404_before_the_executor_exists_is_refused_executor_unavailable_exit_zero():
    gc, db, vending, _ = make(vending=FakeVending(404, {"detail": "Not Found"}))
    eid, data = ledger_record()
    put(db, eid, data)
    report = gc.execute_cleanup()
    assert report["requests"][0]["outcome"] == "REFUSED"
    assert report["requests"][0]["code"] == "EXECUTOR_UNAVAILABLE"
    assert report["outcome_counts"] == {"REFUSED:EXECUTOR_UNAVAILABLE": 1}
    assert report["exit_code"] == 0
    assert db.data[cleaner.AUDIT_COLLECTION][f"sandbox-garbage-collector-job-abcde--{eid}"]["outcome"] == "REFUSED"


def test_vending_403_with_a_typed_code_is_refused_with_that_code():
    gc, db, vending, _ = make(vending=FakeVending(403, {"detail": {"code": "NOT_STACKVEND_OWNED", "detail": "x"}}))
    eid, data = ledger_record()
    put(db, eid, data)
    report = gc.execute_cleanup()
    assert (report["requests"][0]["outcome"], report["requests"][0]["code"]) == ("REFUSED", "NOT_STACKVEND_OWNED")
    assert report["exit_code"] == 0


def test_batch_of_twelve_expired_records_makes_ten_calls_oldest_first():
    gc, db, vending, _ = make()
    eids = []
    for i in range(12):
        eid, data = ledger_record(age=timedelta(hours=2 + i))
        put(db, eid, data)
        eids.append(eid)
    report = gc.execute_cleanup()
    assert len(vending.calls) == 10 and report["deferred_count"] == 2
    called = [c["json"]["eid"] for c in vending.calls]
    assert called == list(reversed(eids))[:10]  # oldest expiry first


def test_cleaner_never_writes_the_ledger():
    gc, db, vending, _ = make(vending=FakeVending(200, {"status": "DELETED"}))
    eid, data = ledger_record()
    put(db, eid, data)
    gc.execute_cleanup()
    assert [w for w in db.writes if w[1] == cleaner.LEDGER_COLLECTION] == []
    assert db.data[cleaner.LEDGER_COLLECTION][eid]["status"] == "REGISTERED"  # vending is the single writer


def test_host_services_named_like_test_runners_are_never_listed_or_deleted():
    """FD-4BC regression: the old sweep deleted HOST Cloud Run services whose names contained -qa-test- etc."""
    gc, db, vending, calls = make()
    report = gc.execute_cleanup()  # a host service "x-qa-test-y" exists only in the platform; nothing lists it
    assert vending.calls == [] and calls["resolver"] == [] and report["exit_code"] == 0
    assert not hasattr(gc, "clean_ephemeral_cloud_run_services")
    assert not hasattr(gc, "clean_gcs_sandbox_artifacts")
    assert not hasattr(gc, "clean_local_workspaces")


def _cleaner_tree():
    return ast.parse((APP_DIR / "cleaner.py").read_text())


def test_cleaner_source_has_no_name_pattern_literals_and_no_listing_or_delete_api():
    tree = _cleaner_tree()
    literals = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    for old in ("-qa-test-", "-qa-sandbox-", "-runner-tmp-", "-ephemeral-", "sandboxes/", "/tmp/castor"):
        assert not any(old in lit for lit in literals), old
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not ({"list_blobs", "services", "rmtree"} & attrs)
    imported = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not ({"googleapiclient.discovery", "shutil", "storage"} & imported)


def test_cleaner_source_uses_no_substring_or_regex_matching():
    tree = _cleaner_tree()
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert "re" not in imported and "fnmatch" not in imported
    calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert not ({"endswith", "find", "match", "search", "fullmatch", "rfind", "index"} & calls)
    # the one startswith is the https scheme check on the Run Admin uri (same as the sentinel's resolver)
    starts = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
              and n.func.attr == "startswith"]
    assert len(starts) == 1 and isinstance(starts[0].args[0], ast.Constant) and starts[0].args[0].value == "https://"
    # no "<literal> in <name>" substring tests
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
            assert not (isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)), ast.unparse(node)


# ---------------------------------------------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------------------------------------------
def test_ledger_read_failure_makes_zero_calls_and_exits_one():
    db = FakeDB()
    db.fail[("stream", cleaner.LEDGER_COLLECTION)] = ServiceUnavailable("firestore down")
    gc, db, vending, _ = make(db=db)
    report = gc.execute_cleanup()
    assert vending.calls == [] and report["exit_code"] == 1 and report["status"] == "FAILED"
    assert db.data[cleaner.RUN_RECORD_COLLECTION]["sandbox-garbage-collector-job-abcde"]["outcome"] == "FAILED"


def test_run_record_failure_makes_zero_calls_and_does_not_read_the_ledger():
    db = FakeDB()
    db.fail[("create", cleaner.RUN_RECORD_COLLECTION)] = ServiceUnavailable("firestore down")
    eid, data = ledger_record()
    put(db, eid, data)
    gc, db, vending, _ = make(db=db)
    report = gc.execute_cleanup()
    assert vending.calls == [] and db.queries == [] and report["exit_code"] == 1


def test_audit_failure_means_no_call_for_that_record():
    db = FakeDB()
    db.fail[("create", cleaner.AUDIT_COLLECTION)] = ServiceUnavailable("firestore down")
    eid, data = ledger_record()
    put(db, eid, data)
    gc, db, vending, _ = make(db=db)
    report = gc.execute_cleanup()
    assert vending.calls == []
    assert (report["requests"][0]["outcome"], report["requests"][0]["code"]) == ("FAILED", "AUDIT_UNAVAILABLE")
    assert report["exit_code"] == 1


def test_vending_url_unresolved_is_an_error_with_no_call():
    gc, db, vending, calls = make(url=None)
    eid, data = ledger_record()
    put(db, eid, data)
    report = gc.execute_cleanup()
    assert vending.calls == [] and calls["token"] == []
    assert report["requests"][0]["code"] == "VENDING_URL_UNRESOLVED" and report["exit_code"] == 1


def test_vending_url_resolver_exception_is_an_error_with_no_call():
    """RT F6-3: a services.get failure is VENDING_URL_UNRESOLVED (no fallback URL, no token, no call)."""
    gc, db, vending, calls = make(url_error=RuntimeError("run admin 403"))
    eid, data = ledger_record()
    put(db, eid, data)
    report = gc.execute_cleanup()
    assert calls["resolver"] == [(HOST, REGION, cleaner.VENDING_SERVICE)]
    assert vending.calls == [] and calls["token"] == []
    assert report["requests"][0]["outcome"] == "FAILED"
    assert report["requests"][0]["code"] == "VENDING_URL_UNRESOLVED" and report["exit_code"] == 1


def test_typed_401_and_caller_not_allowed_fail_the_run():
    """RT F6-1 end to end: a wrong identity/audience is visible (exit 1), never a silent exit-0 refusal."""
    for status, code in ((401, "UNAUTHENTICATED"), (403, "CALLER_NOT_ALLOWED")):
        gc, db, vending, _ = make(vending=FakeVending(status, {"detail": {"code": code, "detail": "x"}}))
        eid, data = ledger_record()
        put(db, eid, data)
        report = gc.execute_cleanup()
        assert len(vending.calls) == 1
        assert (report["requests"][0]["outcome"], report["requests"][0]["code"]) == ("FAILED", code)
        assert report["status"] == "COMPLETED_WITH_ERRORS" and report["exit_code"] == 1


ENV_VENDING_URL = "https://project-repo-vending-service-123456789.us-central1.run.app"


@pytest.mark.parametrize("value", [ENV_VENDING_URL, ENV_VENDING_URL + "/", "  " + ENV_VENDING_URL + "  "])
def test_vending_url_env_is_preferred_and_is_the_token_audience(value):
    """RT F6-2: the install contract (VENDING_SERVICE_URL) wins; no services.get; audience == the URL called."""
    env = {"PROJECT_ID": HOST, "REGION": REGION, "CLOUD_RUN_EXECUTION": "exec-env", "VENDING_SERVICE_URL": value}
    gc, db, vending, calls = make(env=env, vending=FakeVending(200, {"status": "DELETED"}))
    eid, data = ledger_record()
    put(db, eid, data)
    report = gc.execute_cleanup()
    assert calls["resolver"] == []
    assert calls["token"] == [ENV_VENDING_URL]
    assert [c["url"] for c in vending.calls] == [f"{ENV_VENDING_URL}/ephemeral/{eid}:expire"]
    assert report["exit_code"] == 0 and gc.health()["vending_url_source"] == "env"


@pytest.mark.parametrize("value", [
    "", "   ", "http://project-repo-vending-service-1.us-central1.run.app",
    "https://project-repo-vending-service-1.us-central1.run.app/ephemeral",
    "https://a.run.app,https://b.run.app", "https://user@vending.run.app", "https://vending.run.app?x=1",
    "https://vending.run.app#frag", "https://", "project-repo-vending-service",
])
def test_vending_url_env_present_but_invalid_fails_closed_without_a_lookup(value):
    """RT F6-2: present but empty / not one bare https origin -> VENDING_URL_UNRESOLVED; no fallback lookup."""
    env = {"PROJECT_ID": HOST, "REGION": REGION, "CLOUD_RUN_EXECUTION": "exec-bad", "VENDING_SERVICE_URL": value}
    gc, db, vending, calls = make(env=env)
    eid, data = ledger_record()
    put(db, eid, data)
    report = gc.execute_cleanup()
    assert calls["resolver"] == [] and calls["token"] == [] and vending.calls == []
    assert report["requests"][0]["code"] == "VENDING_URL_UNRESOLVED" and report["exit_code"] == 1
    health = gc.health()
    assert health["vending_url_source"] == "unresolved" and "VENDING_SERVICE_URL" in health["missing_configuration"]


def test_vending_url_env_absent_keeps_the_services_get_path():
    gc, db, vending, calls = make(vending=FakeVending(200, {"status": "DELETED"}))
    eid, data = ledger_record()
    put(db, eid, data)
    gc.execute_cleanup()
    assert calls["resolver"] == [(HOST, REGION, cleaner.VENDING_SERVICE)] and calls["token"] == [VENDING_URL]
    assert gc.health()["vending_url_source"] == "services.get"


def test_vending_url_env_set_needs_no_region_for_due_work():
    env = {"PROJECT_ID": HOST, "CLOUD_RUN_EXECUTION": "exec-noregion", "VENDING_SERVICE_URL": ENV_VENDING_URL}
    gc, db, vending, calls = make(env=env, vending=FakeVending(200, {"status": "DELETED"}))
    eid, data = ledger_record()
    put(db, eid, data)
    report = gc.execute_cleanup()
    assert report["exit_code"] == 0 and len(vending.calls) == 1 and calls["resolver"] == []


def test_id_token_failure_is_an_error_with_no_call():
    gc, db, vending, _ = make(token_error=RuntimeError("no metadata server"))
    eid, data = ledger_record()
    put(db, eid, data)
    report = gc.execute_cleanup()
    assert vending.calls == [] and report["requests"][0]["code"] == "ID_TOKEN_UNAVAILABLE"
    assert report["exit_code"] == 1


def test_vending_unreachable_is_an_error_and_not_retried():
    class Boom(FakeVending):
        def __call__(self, url, **kw):
            self.calls.append(url)
            raise ConnectionError("reset")

    gc, db, vending, _ = make(vending=Boom())
    eid, data = ledger_record()
    put(db, eid, data)
    report = gc.execute_cleanup()
    assert len(vending.calls) == 1 and report["requests"][0]["code"] == "VENDING_UNREACHABLE"
    assert report["exit_code"] == 1


@pytest.mark.parametrize("doc_id,over,reason", [
    ("not-a-uuid", {}, "EID_NOT_A_UUID"),
    ("../../projects/x", {}, "EID_NOT_A_UUID"),
    (None, {"ttl_seconds": True}, "TTL_SECONDS_INVALID"),
    (None, {"ttl_seconds": 0}, "TTL_SECONDS_INVALID"),
    (None, {"ttl_seconds": "3600"}, "TTL_SECONDS_INVALID"),
    (None, {"resource_create_time": datetime(2026, 10, 13, 1, 0, 0)}, "RESOURCE_CREATE_TIME_INVALID"),
    (None, {"resource_create_time": "yesterday"}, "RESOURCE_CREATE_TIME_INVALID"),
])
def test_malformed_ledger_records_are_never_sent_and_fail_the_run(doc_id, over, reason):
    gc, db, vending, _ = make()
    eid, data = ledger_record(**over)
    put(db, doc_id or eid, data)
    report = gc.execute_cleanup()
    assert vending.calls == []
    assert report["invalid_records"] == [{"eid": doc_id or eid, "reason": reason}]
    assert report["exit_code"] == 1


def test_uppercase_uuid_eid_is_not_canonical_and_never_sent():
    assert cleaner.canonical_eid(str(uuid.uuid4()).upper()) is None
    good = str(uuid.uuid4())
    assert cleaner.canonical_eid(good) == good


def test_rfc3339_string_create_time_is_accepted():
    gc, db, vending, _ = make()
    eid, data = ledger_record(resource_create_time="2026-10-13T08:00:00Z", ttl=3600)
    put(db, eid, data)
    gc.execute_cleanup()
    assert len(vending.calls) == 1


# ---------------------------------------------------------------------------------------------------------------
# Response classification (exact status codes + typed body fields)
# ---------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("status,body,expected", [
    (200, {"status": "DELETED"}, ("DELETED", "", False)),
    (200, {"status": "deleted"}, ("FAILED", "UNEXPECTED_RESPONSE", True)),
    (200, None, ("FAILED", "UNEXPECTED_RESPONSE", True)),
    (404, {"detail": "Not Found"}, ("REFUSED", "EXECUTOR_UNAVAILABLE", False)),
    (501, None, ("REFUSED", "EXECUTOR_UNAVAILABLE", False)),
    (404, {"detail": {"code": "LEDGER_MISSING", "detail": "x"}}, ("REFUSED", "LEDGER_MISSING", False)),
    (409, {"detail": {"code": "RESOURCE_REPLACED"}}, ("REFUSED", "RESOURCE_REPLACED", False)),
    (503, {"detail": {"code": "CALLERS_UNCONFIGURED"}}, ("REFUSED", "CALLERS_UNCONFIGURED", False)),
    # RT F6-1: lane 18 authenticate_caller answers about THIS job's identity / audience are errors, never refusals
    (401, {"detail": {"code": "UNAUTHENTICATED", "detail": "x"}}, ("FAILED", "UNAUTHENTICATED", True)),
    (403, {"detail": {"code": "CALLER_NOT_ALLOWED", "detail": "x"}}, ("FAILED", "CALLER_NOT_ALLOWED", True)),
    (403, {"code": "CALLER_NOT_ALLOWED"}, ("FAILED", "CALLER_NOT_ALLOWED", True)),
    (401, {"detail": {"code": "TOKEN_EXPIRED"}}, ("FAILED", "TOKEN_EXPIRED", True)),  # any 401 is an error
    (401, None, ("FAILED", "HTTP_401", True)),
    # guard refusals / vending-not-ready keep their REFUSED class
    (403, {"detail": {"code": "NOT_STACKVEND_OWNED"}}, ("REFUSED", "NOT_STACKVEND_OWNED", False)),
    (503, {"detail": {"code": "AUDIENCE_UNCONFIGURED"}}, ("REFUSED", "AUDIENCE_UNCONFIGURED", False)),
    (500, {"detail": {"code": "INTERNAL"}}, ("FAILED", "INTERNAL", True)),
    (502, {"detail": {"code": "EPHEMERAL_DELETE_FAILED"}}, ("FAILED", "EPHEMERAL_DELETE_FAILED", True)),
    (403, None, ("FAILED", "HTTP_403", True)),
    (401, {"detail": "Unauthorized"}, ("FAILED", "HTTP_401", True)),
    (429, None, ("FAILED", "HTTP_429", True)),
    (503, None, ("FAILED", "HTTP_503", True)),
])
def test_classify_vending_response(status, body, expected):
    assert cleaner.classify_vending_response(status, body) == expected


# ---------------------------------------------------------------------------------------------------------------
# Run record idempotency + exit codes (plan 2.0)
# ---------------------------------------------------------------------------------------------------------------
def test_same_execution_twice_makes_one_call():
    gc, db, vending, _ = make(vending=FakeVending(200, {"status": "DELETED"}))
    eid, data = ledger_record()
    put(db, eid, data)
    first = gc.execute_cleanup()
    second = gc.execute_cleanup()
    assert len(vending.calls) == 1
    assert first["exit_code"] == 0
    assert second["status"] == "ALREADY_RECORDED" and second["recorded_outcome"] == "COMPLETED"
    assert second["exit_code"] == 0


def test_interrupted_attempt_is_not_rerun_by_a_retry():
    db = FakeDB()
    db.data[cleaner.RUN_RECORD_COLLECTION] = {"sandbox-garbage-collector-job-abcde": {"outcome": "RUNNING"}}
    eid, data = ledger_record()
    put(db, eid, data)
    gc, db, vending, _ = make(db=db)
    report = gc.execute_cleanup()
    assert vending.calls == [] and report["exit_code"] == 1 and report["recorded_outcome"] == "RUNNING"


def test_missing_project_id_is_not_configured_exit_three_warning(caplog):
    gc, db, vending, _ = make(env={"REGION": REGION})
    gc.project_id = ""
    with caplog.at_level(logging.WARNING, logger="sandbox-garbage-collector-job"):
        report = gc.execute_cleanup()
    assert report["exit_code"] == 3 and report["status"] == "NOT_CONFIGURED" and report["missing"] == ["PROJECT_ID"]
    assert vending.calls == [] and db.writes == []
    warn = [json.loads(r.getMessage()) for r in caplog.records if r.levelno == logging.WARNING]
    assert warn == [{"error_class": "NOT_CONFIGURED", "job": cleaner.JOB_NAME, "missing": ["PROJECT_ID"]}]
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_missing_region_with_due_work_is_not_configured_and_recorded_for_the_sentinel():
    gc, db, vending, calls = make(env={"PROJECT_ID": HOST, "CLOUD_RUN_EXECUTION": "exec-1"})
    eid, data = ledger_record()
    put(db, eid, data)
    report = gc.execute_cleanup()
    assert report["exit_code"] == 3 and report["missing"] == ["REGION"]
    assert vending.calls == [] and calls["resolver"] == []
    assert db.data[cleaner.RUN_RECORD_COLLECTION]["exec-1"]["outcome"] == "NOT_CONFIGURED"
    # the sentinel reads exactly this collection/document for a job incident (plan G11)
    assert cleaner.RUN_RECORD_COLLECTION == clf.run_record_collection(cleaner.JOB_NAME)
    assert cleaner.JOB_NAME in clf.DEFAULT_PLATFORM_JOBS


def test_missing_region_with_an_empty_ledger_still_exits_zero():
    gc, db, vending, _ = make(env={"PROJECT_ID": HOST, "CLOUD_RUN_EXECUTION": "exec-2"})
    report = gc.execute_cleanup()
    assert report["exit_code"] == 0 and vending.calls == []


def test_guard_database_is_used_for_the_ledger_when_configured():
    guard = FakeDB("stackvend-guard")
    eid, data = ledger_record()
    guard.data[cleaner.LEDGER_COLLECTION] = {eid: data}
    default = FakeDB()
    other_eid, other = ledger_record()
    default.data[cleaner.LEDGER_COLLECTION] = {other_eid: other}  # forged default-DB record: never read
    env = {"PROJECT_ID": HOST, "REGION": REGION, "CLOUD_RUN_EXECUTION": "exec-3",
           "STACKVEND_GUARD_FIRESTORE_DATABASE": "stackvend-guard"}
    gc, db, vending, calls = make(env=env, db=default, ledger=guard)
    gc.execute_cleanup()
    assert [c["json"]["eid"] for c in vending.calls] == [eid]
    assert calls["factory"] == [(HOST, "stackvend-guard")]
    assert guard.writes == []  # read-only on the guard database
    assert "exec-3" in default.data[cleaner.RUN_RECORD_COLLECTION]


def test_valid_registered_record_under_ttl_is_untouched_byte_identical():
    """Do-No-Harm negative test: a valid, unexpired ledger record is neither requested nor rewritten."""
    gc, db, vending, _ = make()
    eid, data = ledger_record(age=timedelta(seconds=10), ttl=86400)
    put(db, eid, data)
    before = copy.deepcopy(db.data[cleaner.LEDGER_COLLECTION])
    gc.execute_cleanup()
    assert db.data[cleaner.LEDGER_COLLECTION] == before and vending.calls == []


# ---------------------------------------------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------------------------------------------
def test_main_import_builds_no_client_and_run_batch_propagates_exit_codes(capsys):
    assert cleaner_main._collector is None
    gc, db, vending, _ = make()
    assert cleaner_main.run_batch(["--batch"], collector=gc) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "COMPLETED"
    gc2, _, _, _ = make(env={"REGION": REGION})
    gc2.project_id = ""
    assert cleaner_main.run_batch([], collector=gc2) == 3
    assert cleaner_main.run_batch(["--ttl_minutes", "60"], collector=gc) == 2  # usage


def test_run_batch_dry_run_flag():
    gc, db, vending, _ = make()
    eid, data = ledger_record()
    put(db, eid, data)
    assert cleaner_main.run_batch(["--dry-run"], collector=gc) == 0
    assert vending.calls == [] and db.writes == []


def test_health_endpoint_reports_configuration():
    from fastapi.testclient import TestClient

    gc, _, _, _ = make(env={"PROJECT_ID": HOST})
    cleaner_main._collector = gc
    try:
        body = TestClient(cleaner_main.app).get("/health").json()
    finally:
        cleaner_main._collector = None
    assert body["status"] == "degraded" and body["missing_configuration"] == ["REGION"]
    assert body["batch_cap"] == 10 and body["ledger"] == "ephemeral_resources"
