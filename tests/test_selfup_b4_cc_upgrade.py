"""SELFUP P3b, Control Center side (builder B4): the "Update StackVend" button routes in
apps/control-center/routes/platform_upgrade.py.

FastAPI TestClient on the real routers with in-memory doubles for both Firestore databases (preconditioned batch
commits, create-if-absent), the Pub/Sub publisher seam, the update check, the Workflows executions count and the
maintenance-mode store. No network.

What it proves:
- every refusal: UPGRADER_NOT_INSTALLED (env unset / blank / not a topic name -> button hidden), UPDATE_CHECK_OFF
  (hidden), RELEASE_SOURCE_INVALID, NO_TARGET with each reason, TARGET_CHANGED, SOURCE_SETTING_CHANGED,
  UPGRADE_IN_PROGRESS, WORKLOAD_RUNS_ACTIVE / EXECUTIONS_UNKNOWN, CONFIRMATION_MISMATCH, HUMAN_ADMIN_REQUIRED;
- the request and lease documents pass scripts/upgrade/guard.py's own validate_request / check_lease (B2 contract);
- one message, request id as the `request_id` attribute; idempotent start; the lease race (create-if-absent);
- failures after the commit undo themselves (PUBLISH_FAILED -> NOT_SENT, lease released, maintenance restored);
- progress, finished-lease release and the maintenance restore / keep rules; retry, rollback, clear stale lease,
  maintenance restore; release source changes refused while a lease is held;
- the Control Center never calls Cloud Build or a Cloud Run write API (static + call recording).
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import importlib.util
import json
import os
import sys
import urllib.parse
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI, Request
from google.api_core import exceptions as gexc
from fastapi.testclient import TestClient

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(BASE_DIR, "apps", "control-center")
for _p in (BASE_DIR, CC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_saved_client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "selfup-b4-test.apps.googleusercontent.com"
try:
    import release_source as rsrc  # noqa: E402
    from routes import platform_release as pr  # noqa: E402
    from routes import platform_upgrade as pu  # noqa: E402
    from shared import release_manifest as rm  # noqa: E402
finally:
    if _saved_client_id is None:
        os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
    else:
        os.environ["GOOGLE_OAUTH_CLIENT_ID"] = _saved_client_id

_spec = importlib.util.spec_from_file_location("selfup_b4_guard", os.path.join(BASE_DIR, "scripts", "upgrade",
                                                                              "guard.py"))
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)

PROJ = "mock-stackvend-project"
REGION = "us-central1"
ADMIN_EMAIL = "owner@example.com"
NOW = 2_000_000_000
COMMIT = "c" * 40
TOPIC = f"projects/{PROJ}/topics/stackvend-platform-upgrade"
FP = rsrc.default_source().fingerprint


# ------------------------------------------------------------------------------------------------ Firestore double
class Snap:
    def __init__(self, data, update_time, doc_id=""):
        self._d, self.exists, self.update_time, self.id = data, data is not None, update_time, doc_id

    def to_dict(self):
        return copy.deepcopy(self._d) if self._d is not None else None


class Ref:
    def __init__(self, db, path):
        self.db, self.path, self.id = db, path, path[-1]

    def collection(self, name):
        return Col(self.db, self.path + (name,))

    def get(self):
        if self.db.fail_reads:
            raise RuntimeError("unavailable")
        self.db.reads.append(self.path)
        hook = self.db.after_read.pop(self.path, None)
        snap = Snap(self.db.docs.get(self.path), self.db.times.get(self.path), self.id)
        if hook:
            hook()
        return snap

    def update(self, data, option=None):
        b = Batch(self.db)
        b.update(self, data, option)
        b.commit()


class Col:
    def __init__(self, db, path, order=None, limit=None):
        self.db, self.path, self._order, self._limit = db, path, order, limit

    def document(self, doc_id):
        return Ref(self.db, self.path + (doc_id,))

    def order_by(self, field, direction="ASCENDING"):
        return Col(self.db, self.path, (field, direction), self._limit)

    def limit(self, n):
        return Col(self.db, self.path, self._order, n)

    def stream(self):
        items = [(p, d) for p, d in self.db.docs.items() if p[:-1] == self.path]
        if self._order:
            field, direction = self._order
            items = [x for x in items if field in x[1]]
            items.sort(key=lambda x: x[1][field], reverse=direction == "DESCENDING")
        if self._limit is not None:
            items = items[:self._limit]
        return [Snap(copy.deepcopy(d), self.db.times.get(p), p[-1]) for p, d in items]


class Batch:
    def __init__(self, db):
        self.db, self.ops = db, []

    def set(self, ref, data):
        self.ops.append(("set", ref.path, data, None))

    def create(self, ref, data):
        self.ops.append(("create", ref.path, data, None))

    def update(self, ref, data, option=None):
        self.ops.append(("update", ref.path, data, option))

    def delete(self, ref, option=None):
        self.ops.append(("delete", ref.path, None, option))

    def commit(self):
        if self.db.fail_commit:
            raise RuntimeError("commit refused")
        for op, path, data, option in self.ops:  # all or nothing
            if op == "create" and path in self.db.docs:
                raise gexc.AlreadyExists("already exists")
            if op == "update" and path not in self.db.docs:
                raise RuntimeError("not found")
            if op in ("update", "delete") and option is not None and option != self.db.times.get(path):
                raise RuntimeError("precondition failed")
        for op, path, data, _ in self.ops:
            self.db.commits.append((op, path))
            if op == "delete":
                self.db.docs.pop(path, None)
                self.db.times.pop(path, None)
            elif op == "update":
                self.db._write(path, {**self.db.docs[path], **copy.deepcopy(data)})
            else:
                self.db._write(path, copy.deepcopy(data))


class FakeDb:
    def __init__(self):
        self.docs, self.times, self.tick = {}, {}, 0
        self.fail_commit = self.fail_reads = False
        self.reads, self.commits, self.after_read = [], [], {}

    def _write(self, path, data):
        self.tick += 1
        self.docs[path] = data
        self.times[path] = self.tick

    def put(self, path, data):
        self._write(tuple(path.split("/")), copy.deepcopy(data))

    def doc(self, path):
        return self.docs.get(tuple(path.split("/")))

    def collection(self, name):
        return Col(self, (name,))

    def batch(self):
        return Batch(self)

    def write_option(self, last_update_time=None):
        return last_update_time


# ------------------------------------------------------------------------------------------------ other doubles
class FakePublisher:
    def __init__(self, fail=False):
        self.fail, self.messages = fail, []

    def publish(self, topic, data, **attrs):
        if self.fail:
            raise RuntimeError("PERMISSION_DENIED")
        self.messages.append((topic, data, attrs))

        class F:
            def result(self_inner, timeout=None):
                return f"m-{len(self.messages)}"
        return F()


def ok_updates(tag="v0.9.3", update_available=True, decision="ALLOW", manifest=True, status="OK"):
    out = {"status": status, "update_available": update_available,
           "latest": {"tag": tag, "release": tag[1:], "prerelease": False}}
    if manifest:
        out["manifest"] = {"release": tag[1:], "requires_apply_sh": decision == "NEEDS_APPLY_SH",
                           "min_platform_release": "0.9.0"}
    if decision:
        out["guard"] = {"decision": decision, "platform_release": "0.9.0", "assumed": False, "warnings": []}
    return out


@pytest.fixture
def env(monkeypatch):
    st = {"db": FakeDb(), "guard": FakeDb(), "pub": FakePublisher(), "updates": ok_updates(), "updates_calls": 0,
          "executions": 0, "maintenance": False, "maint_writes": [], "gh": [], "run_calls": [],
          "maint_fail": False}

    def updates(_request):
        st["updates_calls"] += 1
        if isinstance(st["updates"], Exception):
            raise st["updates"]
        return copy.deepcopy(st["updates"])

    def executions():
        if isinstance(st["executions"], Exception):
            raise st["executions"]
        return st["executions"]

    def write_maint(value, by, reason):
        if st["maint_fail"]:
            raise RuntimeError("settings store refused")
        st["maint_writes"].append((value, by, reason))
        st["maintenance"] = value

    def github(method, path, token="", body=None, accept=""):
        st["gh"].append((method, path))
        if path == "/repos/asaslaw/stackvend/commits/refs/tags/v0.9.3":
            return 200, {"sha": COMMIT}
        return 404, None

    def run_get(url):
        st["run_calls"].append(url)
        raise AssertionError("no Cloud Run read expected in these tests: " + url)

    monkeypatch.setattr(pr, "PROJECT_ID", PROJ)
    monkeypatch.setattr(pr, "region_provider", lambda: REGION)
    monkeypatch.setattr(pr, "guard_db_provider", lambda: st["guard"])
    monkeypatch.setattr(pr, "get_db", lambda: st["db"])
    monkeypatch.setattr(pr, "github_request", github)
    monkeypatch.setattr(pr, "cloud_run_get_json", run_get)
    monkeypatch.setattr(pu, "progress_db_provider", lambda: st["db"])
    monkeypatch.setattr(pu, "publisher_provider", lambda: st["pub"])
    monkeypatch.setattr(pu, "updates_provider", updates)
    monkeypatch.setattr(pu, "active_executions_provider", executions)
    monkeypatch.setattr(pu, "maintenance_reader", lambda: st["maintenance"])
    monkeypatch.setattr(pu, "maintenance_writer", write_maint)
    monkeypatch.setattr(pu, "clock", lambda: NOW)
    monkeypatch.setattr(pr, "clock", lambda: NOW)
    st["tf_ready"], st["tf_ready_calls"] = (200, {"ready": True}), 0

    def tf_ready():   # UPGRADER-READY-INGRESS F2: the CC's own /validate/ready probe (never a real request here)
        st["tf_ready_calls"] += 1
        if isinstance(st["tf_ready"], Exception):
            raise st["tf_ready"]
        return st["tf_ready"]
    monkeypatch.setattr(pu, "terraform_ready_probe", tf_ready)
    monkeypatch.setattr(pu, "_cc_ready_cache", {})
    monkeypatch.setenv(pu.TOPIC_ENV, TOPIC)
    monkeypatch.delenv(pu.APPROVAL_ENV, raising=False)
    return st


def client(role="ADMIN", method="session", email=ADMIN_EMAIL):
    app = FastAPI()

    @app.middleware("http")
    async def _auth(request: Request, call_next):
        request.state.user_email, request.state.user_role, request.state.auth_method = email, role, method
        request.state.session_issued_at = NOW - 60
        return await call_next(request)
    app.include_router(pr.router)
    app.include_router(pu.router)
    return TestClient(app)


KEY = "0123456789abcdef0123"


def start(c=None, **kw):
    body = {"target_tag": "v0.9.3", "expected_source_fingerprint": FP, "confirm_project": PROJ,
            "idempotency_key": KEY, **kw}
    return (c or client()).post("/api/settings/platform-upgrade", json=body)


def follow(path, c=None, key="fedcba9876543210fedc", **kw):
    body = {"expected_source_fingerprint": FP, "confirm_project": PROJ, "idempotency_key": key, **kw}
    return (c or client()).post(path, json=body)


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def code(resp):
    d = resp.json().get("detail")
    return d.get("code") if isinstance(d, dict) else d


def no_side_effects(env):
    assert env["pub"].messages == []
    assert not any(p[0] == pu.REQUESTS for p in env["guard"].docs)
    assert env["maint_writes"] == []


# ================================================================================================ topic env (inert)
@pytest.mark.parametrize("value", [None, "", "   ", "projects/x/topics", "a/b", "projects/Bad_Proj/topics/t",
                                   "projects/mock-stackvend-project/topics/goog-x", "1topic"])
def test_unset_or_invalid_topic_hides_button_and_refuses_start(env, monkeypatch, value):
    if value is None:
        monkeypatch.delenv(pu.TOPIC_ENV, raising=False)
    else:
        monkeypatch.setenv(pu.TOPIC_ENV, value)
    body = client().get("/api/settings/platform-upgrade").json()
    assert body["installed"] is False
    assert body["button"]["visible"] is False and body["button"]["enabled"] is False
    assert body["button"]["reason"] == "UPGRADER_NOT_INSTALLED"
    assert env["updates_calls"] == 0  # no update check for a button that is not there
    r = start()
    assert r.status_code == 409 and code(r) == "UPGRADER_NOT_INSTALLED"
    no_side_effects(env)


def test_topic_forms(monkeypatch):
    monkeypatch.setattr(pr, "PROJECT_ID", PROJ)
    monkeypatch.setenv(pu.TOPIC_ENV, "stackvend-platform-upgrade")
    assert pu.upgrade_topic() == (TOPIC, "")
    monkeypatch.setenv(pu.TOPIC_ENV, f" {TOPIC} ")
    assert pu.upgrade_topic() == (TOPIC, "")


def test_runner_identity_mode_does_not_show_the_button(env, monkeypatch):
    """Shared (PLATFORM) or Per-workload runner mode has nothing to do with the upgrader: only the topic env does."""
    monkeypatch.delenv(pu.TOPIC_ENV, raising=False)
    for mode in ("PLATFORM", "PER_WORKLOAD", ""):
        monkeypatch.setenv("STACKVEND_TF_RUNNER_IDENTITY", mode)
        assert client().get("/api/settings/platform-upgrade").json()["button"]["visible"] is False


# ================================================================================================ refusals
def test_update_check_off_hides_button_and_refuses(env):
    src = rsrc.default_source()
    plan = rsrc.plan_change(rsrc.update_check_request(src, False), None, None, 0, ADMIN_EMAIL, "t", "", [],
                            rsrc.VIA_CONTROL_CENTER)
    env["guard"].put("platform_release_source/current", plan.stored)
    body = client().get("/api/settings/platform-upgrade").json()
    assert body["button"]["reason"] == "UPDATE_CHECK_OFF" and body["button"]["visible"] is False
    assert env["updates_calls"] == 0 and env["gh"] == []  # no GitHub call under OFF
    r = start()
    assert r.status_code == 409 and code(r) == "UPDATE_CHECK_OFF"
    no_side_effects(env)


def test_invalid_release_source_refuses(env):
    env["guard"].put("platform_release_source/current", {"repository": "x", "bogus": 1})
    body = client().get("/api/settings/platform-upgrade").json()
    assert body["button"]["reason"] == "RELEASE_SOURCE_INVALID"
    r = start()
    assert r.status_code == 409 and code(r) == "RELEASE_SOURCE_INVALID"
    no_side_effects(env)


@pytest.mark.parametrize("updates,reason", [
    ({"status": "REPOSITORY_NOT_FOUND", "update_available": False}, "REPOSITORY_NOT_FOUND"),
    ({"status": "NO_RELEASES", "update_available": False}, "NO_RELEASES"),
    ({"status": "COULD_NOT_CHECK", "error_code": "GITHUB_RATE_LIMITED"}, "COULD_NOT_CHECK"),
    (ok_updates(update_available=False), "UP_TO_DATE"),
    (ok_updates(decision="NEEDS_APPLY_SH"), "NEEDS_APPLY_SH"),
    (ok_updates(decision="PLATFORM_STAMP_UNKNOWN"), "PLATFORM_STAMP_UNKNOWN"),
    (ok_updates(decision=None), "PLATFORM_STAMP_UNKNOWN"),
    (ok_updates(manifest=False, decision=None), "MANIFEST_UNAVAILABLE"),
])
def test_no_target_reasons(env, updates, reason):
    env["updates"] = updates
    body = client().get("/api/settings/platform-upgrade").json()
    assert body["button"] == {**body["button"], "visible": True, "enabled": False, "reason": reason}
    assert body["button"]["text"] == pu.REASONS[reason]
    # CC-APPLY-WHERE: only the apply.sh reason says where to run it (with this install's project id)
    assert (f"gs://castor-tfstate-{PROJ}/platform/" in body["button"]["apply_where"]) == (reason == "NEEDS_APPLY_SH")
    r = start()
    assert r.status_code == 409 and code(r) == "NO_TARGET" and r.json()["detail"]["reason"] == reason
    no_side_effects(env)


def test_target_changed_and_source_changed_and_confirmation(env):
    r = start(target_tag="v0.9.2")
    assert r.status_code == 409 and code(r) == "TARGET_CHANGED"
    r = start(expected_source_fingerprint="sha256:" + "0" * 64)
    assert r.status_code == 409 and code(r) == "SOURCE_SETTING_CHANGED"
    r = start(confirm_project="wrong-project")
    assert r.status_code == 422 and code(r) == "CONFIRMATION_MISMATCH"
    r = start(idempotency_key="short")
    assert r.status_code == 422 and code(r) == "BAD_IDEMPOTENCY_KEY"
    no_side_effects(env)


@pytest.mark.parametrize("role,method,status,expected", [
    ("ADMIN", "bearer", 403, None),  # require(ADMIN) refuses service credentials before the handler
    ("MANAGER", "session", 403, None),
    ("VIEWER", "session", 403, None),
])
def test_authz_writes_need_a_human_admin(env, role, method, status, expected):
    c = client(role=role, method=method)
    for r in (start(c), follow("/api/settings/platform-upgrade/" + "a" * 32 + "/retry", c),
              follow("/api/settings/platform-upgrade/" + "a" * 32 + "/rollback", c),
              c.post("/api/settings/platform-upgrade/lease/clear",
                     json={"expected_request_id": "a" * 32, "confirm_project": PROJ}),
              c.post("/api/settings/platform-upgrade/" + "a" * 32 + "/maintenance/restore",
                     json={"confirm_project": PROJ})):
        assert r.status_code in (401, status)
        if expected:
            assert code(r) == expected
    if role != "ADMIN":
        assert c.get("/api/settings/platform-upgrade").status_code in (401, 403)
    no_side_effects(env)


def test_active_workload_runs_refuse_unless_upgrade_anyway(env):
    env["executions"] = 2
    r = start()
    assert r.status_code == 409 and code(r) == "WORKLOAD_RUNS_ACTIVE"
    no_side_effects(env)
    env["executions"] = RuntimeError("workflows api down")
    r = start()
    assert r.status_code == 503 and code(r) == "EXECUTIONS_UNKNOWN"
    no_side_effects(env)
    r = start(upgrade_anyway=True)
    assert r.status_code == 202
    assert env["guard"].doc("platform_upgrades/" + r.json()["request_id"])["upgrade_anyway"] is True


# ================================================================================================ start
def test_start_writes_b2_contract_documents_and_publishes_once(env):
    r = start()
    assert r.status_code == 202, r.text
    body = r.json()
    rid = body["request_id"]
    assert rid == pu.request_id_for(ADMIN_EMAIL, KEY) and len(rid) == 32
    req = env["guard"].doc(f"platform_upgrades/{rid}")
    lease = env["guard"].doc("platform_upgrades/_lease")
    # the upgrader's own step 0 accepts both documents (B2 contract, scripts/upgrade/guard.py)
    v = guard.validate_request(rid, req)
    assert v == {"request_id": rid, "kind": "UPGRADE", "target_tag": "v0.9.3", "expected_commit": COMMIT,
                 "source_fingerprint": FP, "requested_by": ADMIN_EMAIL, "rollback_of": ""}
    guard.check_lease(rid, lease, datetime.fromtimestamp(NOW + 60, timezone.utc))
    with pytest.raises(guard.Refusal):  # expires after the build timeout
        guard.check_lease(rid, lease, datetime.fromtimestamp(NOW + pu.LEASE_SECONDS, timezone.utc))
    # exactly one message, the request id as the attribute the trigger maps to a substitution
    assert len(env["pub"].messages) == 1
    topic, data, attrs = env["pub"].messages[0]
    assert topic == TOPIC and attrs == {"request_id": rid}
    assert json.loads(data) == {"request_id": rid, "kind": "UPGRADE"}
    assert req["message_id"] == "m-1"
    # maintenance on, previous value recorded
    assert env["maint_writes"][0][0] is True and env["maintenance"] is True
    assert req["maintenance"] == {"before": False, "set": True, "restored_at": None, "kept_on": False}
    assert body["status"] == "WAITING_FOR_BUILD"
    assert "approve this build in the Google Cloud console (Cloud Build ▸ History)" in body["waiting_text"]
    # the only GitHub call of the start is resolving the tag; no Cloud Run call at all
    assert env["gh"] == [("GET", "/repos/asaslaw/stackvend/commits/refs/tags/v0.9.3")]
    assert env["run_calls"] == []


# ================================================================================================ FD-148 tag resolve
def _github_answer(env, monkeypatch, answer):
    """Replace the GitHub double: every call is recorded, then answered by `answer(path)` (or raises it)."""
    def github(method, path, token="", body=None, accept=""):
        env["gh"].append((method, path))
        if isinstance(answer, Exception):
            raise answer
        return answer(path)
    monkeypatch.setattr(pr, "github_request", github)


def _nothing_started(env):
    """No request document (for this or any id), no lease, no message, maintenance untouched."""
    rid = pu.request_id_for(ADMIN_EMAIL, KEY)
    assert env["guard"].doc(f"platform_upgrades/{rid}") is None
    assert env["guard"].doc("platform_upgrades/_lease") is None
    assert not [p for p in env["guard"].docs if p[0] == pu.REQUESTS]
    no_side_effects(env)


def test_fd148_missing_tag_is_tag_unresolved_and_starts_nothing(env, monkeypatch):
    """GitHub answers 422 "No commit found for SHA: refs/tags/<tag>" for a tag that does not exist (checked live
    2026-11-20). No earlier request is seeded, so nothing can be answered from an idempotent replay."""
    assert not [p for p in env["guard"].docs if p[0] == pu.REQUESTS]
    _github_answer(env, monkeypatch, lambda path: (422, {"message": "No commit found for SHA: refs/tags/v0.9.3"}))
    r = start()
    assert r.status_code == 502 and code(r) == "TAG_UNRESOLVED", r.text
    assert "HTTP 422" in r.json()["detail"]["message"]
    assert env["gh"] == [("GET", "/repos/asaslaw/stackvend/commits/refs/tags/v0.9.3")]
    _nothing_started(env)


@pytest.mark.parametrize("status", [403, 429])
def test_fd148_rate_limit_is_typed_and_starts_nothing(env, monkeypatch, status):
    _github_answer(env, monkeypatch, lambda path: (status, {"message": "API rate limit exceeded"}))
    r = start()
    assert r.status_code == 502 and code(r) == "GITHUB_RATE_LIMITED", r.text
    message = r.json()["detail"]["message"]
    assert f"HTTP {status}" in message
    # 429 is always the rate limit; a 403 cannot be told apart from a refusal without headers, so it says both
    assert ("rate-limited or refused" in message) is (status == 403)
    _nothing_started(env)


@pytest.mark.parametrize("answer", [
    lambda path: (200, {"sha": "not-a-sha"}),
    lambda path: (200, None),
    lambda path: (404, None),
    lambda path: (500, {"message": "x"}),
    OSError("network down"),
])
def test_fd148_negative_other_failures_stay_tag_unresolved(env, monkeypatch, answer):
    """Only 403 / 429 are renamed: every other failure (bad sha, no body, 404, 5xx, no network) is TAG_UNRESOLVED."""
    _github_answer(env, monkeypatch, answer)
    r = start()
    assert r.status_code == 502 and code(r) == "TAG_UNRESOLVED", r.text
    _nothing_started(env)


def test_fd148_tag_is_resolved_only_through_the_qualified_ref(env):
    """Recorded: a start asks GitHub only for `commits/refs/tags/<quoted tag>`. Static: neither CC route module holds
    a GitHub `commits/...` path in any other form (a bare `commits/<tag>`, the 422 `commits/tags/` or a branch's
    `commits/heads/`), so a branch named like the tag can never be resolved instead."""
    assert start().status_code == 202
    gh_paths = [p for _m, p in env["gh"]]
    assert gh_paths == ["/repos/asaslaw/stackvend/commits/refs/tags/v0.9.3"]
    for name in ("platform_upgrade.py", "platform_release.py"):
        tree = ast.parse(open(os.path.join(CC_DIR, "routes", name), encoding="utf-8").read())
        parts = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                 and "/commits/" in n.value]
        for s in parts:
            assert s.endswith("/commits/refs/tags/"), (name, s)
            assert "/commits/tags/" not in s and "/commits/heads/" not in s and "/refs/heads/" not in s, (name, s)
        if name == "platform_upgrade.py":
            assert parts == ["/commits/refs/tags/"]  # the one resolve; a second commits path would be reviewed


def test_fd148_tag_is_quoted_into_one_path_segment(env, monkeypatch):
    """The tag is percent-encoded with safe="" (a `/` or `?` in a tag can never change the path GitHub resolves)."""
    seen = []
    monkeypatch.setattr(pr, "_github", lambda method, path, **kw: (seen.append(path), (200, {"sha": COMMIT}))[1])
    assert pu._resolve_commit("acme/sv", "v1.0.0/../heads?x") == COMMIT
    assert seen == ["/repos/acme/sv/commits/refs/tags/v1.0.0%2F..%2Fheads%3Fx"]


def test_start_is_idempotent(env):
    r1, r2 = start(), start()
    assert r1.status_code == 202 and r2.status_code == 202
    assert r1.json()["request_id"] == r2.json()["request_id"] and r2.json()["idempotent"] is True
    assert len(env["pub"].messages) == 1 and len(env["maint_writes"]) == 1


def test_idempotent_start_republishes_a_request_that_never_reached_pubsub(env):
    r = start()
    rid = r.json()["request_id"]
    env["guard"].docs[("platform_upgrades", rid)].pop("message_id")
    r2 = start()
    assert r2.status_code == 202 and len(env["pub"].messages) == 2


def test_same_key_other_target_is_refused(env):
    start()
    env["updates"] = ok_updates(tag="v0.9.4")
    r = start(target_tag="v0.9.4")
    assert r.status_code == 409 and code(r) == "REQUEST_ID_IN_USE"


def test_second_start_while_lease_held(env):
    assert start().status_code == 202
    r = start(idempotency_key="another-key-0000000001")
    assert r.status_code == 409 and code(r) == "UPGRADE_IN_PROGRESS"
    assert len(env["pub"].messages) == 1
    body = client().get("/api/settings/platform-upgrade").json()
    assert body["button"]["reason"] == "UPGRADE_IN_PROGRESS" and body["lease"]["state"] == "ACTIVE"


def test_lease_race_create_if_absent(env):
    """Another start takes the lease between our check and our commit: our commit fails as a whole (no request, no
    message, maintenance untouched)."""
    def other_start():
        env["guard"].put("platform_upgrades/_lease", {"request_id": "b" * 32, "expires_at": iso(NOW + 7200)})
    env["guard"].after_read[("platform_upgrades", "_lease")] = other_start
    r = start()
    assert r.status_code == 409 and code(r) == "UPGRADE_IN_PROGRESS"
    assert env["guard"].doc("platform_upgrades/_lease")["request_id"] == "b" * 32
    assert env["pub"].messages == [] and env["maint_writes"] == []
    assert not [p for p in env["guard"].docs if p[0] == "platform_upgrades" and p[1] != "_lease"]


def test_publish_failure_undoes_everything(env):
    env["pub"].fail = True
    r = start()
    assert r.status_code == 502 and code(r) == "PUBLISH_FAILED"
    rid = pu.request_id_for(ADMIN_EMAIL, KEY)
    assert env["guard"].doc(f"platform_upgrades/{rid}")["status"] == "NOT_SENT"  # a late message cannot run it
    with pytest.raises(guard.Refusal) as e:
        guard.validate_request(rid, env["guard"].doc(f"platform_upgrades/{rid}"))
    assert e.value.code == "REQUEST_NOT_PENDING"
    assert env["guard"].doc("platform_upgrades/_lease") is None
    assert [w[0] for w in env["maint_writes"]] == [True, False] and env["maintenance"] is False


def test_maintenance_failure_refuses_before_publishing(env):
    env["maint_fail"] = True
    r = start()
    assert r.status_code == 503 and code(r) == "MAINTENANCE_UNAVAILABLE"
    rid = pu.request_id_for(ADMIN_EMAIL, KEY)
    assert env["guard"].doc(f"platform_upgrades/{rid}")["status"] == "CANCELLED"
    assert env["guard"].doc("platform_upgrades/_lease") is None and env["pub"].messages == []


def test_maintenance_already_on_is_left_on(env):
    env["maintenance"] = True
    rid = start().json()["request_id"]
    assert env["maint_writes"] == []
    assert env["guard"].doc(f"platform_upgrades/{rid}")["maintenance"]["before"] is True


# ================================================================================================ progress + finish
def progress(rid, status="RUNNING", stage="BUILDING", **extra):
    return {"schema_version": 1, "request_id": rid, "kind": "UPGRADE", "status": status, "stage": stage, "code": "",
            "message": "", "steps": [], "build_id": "0b1c2d3e-aaaa-bbbb-cccc-0123456789ab", "started_at": iso(NOW),
            "updated_at": iso(NOW), **extra}


ALL = [n for n, _, _ in rm.COMPONENTS]


def started(env):
    rid = start().json()["request_id"]
    env["maint_writes"].clear()
    return rid


def test_progress_view_running(env):
    rid = started(env)
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(
        rid, stage="DEPLOYING", built={n: f"img@sha256:{'1' * 64}" for n in ALL},
        deployed={"mcp-gcloud-server": {"kind": "service", "image": "x"}},
        previous={"mcp-gcloud-server": {"kind": "service", "revision": "mcp-gcloud-server-00007"}}))
    body = client().get("/api/settings/platform-upgrade").json()
    cur = body["current"]
    assert cur["request_id"] == rid and cur["status"] == "RUNNING" and cur["stage"] == "DEPLOYING"
    rows = {c["name"]: c for c in cur["components"]}
    assert rows["mcp-gcloud-server"]["result"] == "DEPLOYED"
    assert rows["mcp-gcloud-server"]["previous_revision"] == "mcp-gcloud-server-00007"
    assert rows["product-control-center-ui"]["result"] == "BUILT"
    assert cur["build_url"].startswith("https://console.cloud.google.com/cloud-build/builds;region=us-central1/")
    assert body["lease"]["state"] == "ACTIVE" and env["maint_writes"] == []


def test_progress_build_id_becomes_the_build_log_link(env):
    # FD-148: step0-verify passes Cloud Build's $BUILD_ID; guard.py records it; the card links that exact build.
    rid = started(env)
    bid = "0b1c2d3e-aaaa-bbbb-cccc-0123456789ab"
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(rid, stage="VERIFYING"))
    cur = client().get("/api/settings/platform-upgrade").json()["current"]
    assert cur["build_id"] == bid
    assert cur["build_url"] == (f"https://console.cloud.google.com/cloud-build/builds;region=us-central1/{bid}"
                                f"?project={PROJ}")
    # no build id (the pre-FD-148 trigger) or a malformed one: no link, never a guessed one
    # (FD-148 attacker review: an exact canonical UUID only; the id itself is never echoed unless it is one)
    for bad in ("", "../x", "ABC", "-" * 36, "0" * 36, bid.upper(), "{" + bid + "}", bid.replace("-", ""),
                bid + "\n", " " + bid[1:], "urn:uuid:" + bid, 12345, None, ["x"]):
        env["db"].put(f"platform_upgrades_progress/{rid}", progress(rid, stage="VERIFYING", build_id=bad))
        cur = client().get("/api/settings/platform-upgrade").json()["current"]
        assert cur["build_url"] == "" and cur["build_id"] == "", bad


def test_malformed_build_id_is_logged_without_its_value(env, caplog):
    rid = started(env)
    planted = "evil-" + "x" * 31
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(rid, stage="VERIFYING", build_id=planted))
    with caplog.at_level("WARNING", logger="control-center-platform-upgrade"):
        assert client().get("/api/settings/platform-upgrade").json()["current"]["build_url"] == ""
    hits = [r.getMessage() for r in caplog.records if "build_id rejected" in r.getMessage()]
    assert hits and "length=36" in hits[0] and planted not in caplog.text
    # an absent id (a pre-FD-148 trigger) and a valid one stay silent
    caplog.clear()
    for quiet in ("", "0b1c2d3e-aaaa-bbbb-cccc-0123456789ab"):
        env["db"].put(f"platform_upgrades_progress/{rid}", progress(rid, stage="VERIFYING", build_id=quiet))
        with caplog.at_level("WARNING", logger="control-center-platform-upgrade"):
            client().get("/api/settings/platform-upgrade")
    assert "build_id rejected" not in caplog.text


def test_succeeded_releases_lease_and_restores_maintenance(env):
    rid = started(env)
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(
        rid, "SUCCEEDED", "DONE", deployed={n: {"kind": "service", "image": "x"} for n in ALL},
        check={n: {"ok": True} for n in ALL}))
    body = client().get("/api/settings/platform-upgrade").json()
    assert body["lease"] is None and env["guard"].doc("platform_upgrades/_lease") is None
    req = env["guard"].doc(f"platform_upgrades/{rid}")
    assert req["status"] == "DONE" and req["result"] == "SUCCEEDED"
    assert env["maint_writes"] == [(False, ADMIN_EMAIL, f"platform upgrade {rid} ended")]
    assert req["maintenance"]["restored_at"]
    assert all(c["result"] == "OK" for c in body["current"]["components"])
    # a second look does not restore again
    client().get("/api/settings/platform-upgrade")
    assert len(env["maint_writes"]) == 1


@pytest.mark.parametrize("status,extra,restored", [
    ("REFUSED_SIGNATURE_INVALID", {}, True),
    ("REFUSED_NEEDS_APPLY_SH", {}, True),
    ("FAILED_BUILDING", {}, True),
    ("FAILED_PREFLIGHT", {}, True),
    ("PARTIAL", {"deployed": {"mcp-gcloud-server": {"kind": "service", "image": "x"}}}, False),
    ("FAILED_CHECKING", {"deployed": {"mcp-gcloud-server": {"kind": "service", "image": "x"}}}, False),
])
def test_maintenance_rules(env, status, extra, restored):
    rid = started(env)
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(rid, status, "DONE", **extra))
    body = client().get("/api/settings/platform-upgrade").json()
    assert body["lease"] is None  # every terminal state releases the lease
    req = env["guard"].doc(f"platform_upgrades/{rid}")
    if restored:
        assert env["maintenance"] is False and req["maintenance"]["restored_at"]
        assert body["maintenance_kept_on"] is None
    else:  # fail closed: stays on, banner + restore button
        assert env["maintenance"] is True and env["maint_writes"] == []
        assert req["maintenance"]["kept_on"] is True
        assert body["maintenance_kept_on"]["request_id"] == rid
    assert body["button"]["enabled"] is True  # the lease is free again


def test_partial_offers_rollback_and_retry(env):
    rid = started(env)
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(
        rid, "PARTIAL", "CHECKING", deployed={"mcp-gcloud-server": {"kind": "service", "image": "x"}},
        previous={"mcp-gcloud-server": {"kind": "service", "revision": "r7"}}))
    cur = client().get("/api/settings/platform-upgrade").json()["current"]
    assert cur["rollback_offered"] is True and cur["retry_offered"] is True


# ================================================================================================ rollback
def finished_partial(env):
    rid = started(env)
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(
        rid, "PARTIAL", "CHECKING", deployed={"mcp-gcloud-server": {"kind": "service", "image": "x"}},
        previous={"mcp-gcloud-server": {"kind": "service", "revision": "r7"}}))
    client().get("/api/settings/platform-upgrade")  # releases the lease, keeps maintenance on
    return rid


def test_rollback_request_through_the_same_trigger(env):
    up = finished_partial(env)
    r = follow(f"/api/settings/platform-upgrade/{up}/rollback")
    assert r.status_code == 202, r.text
    rb = r.json()["request_id"]
    doc = env["guard"].doc(f"platform_upgrades/{rb}")
    v = guard.validate_request(rb, doc)
    assert v["kind"] == "ROLLBACK" and v["rollback_of"] == up and v["target_tag"] == "v0.9.3"
    assert v["expected_commit"] == COMMIT
    assert env["pub"].messages[-1][2] == {"request_id": rb}
    # maintenance: inherited "before" (off), already on -> no write; restored when the rollback succeeds
    assert doc["maintenance"]["before"] is False and env["maint_writes"] == []
    env["db"].put(f"platform_upgrades_progress/{rb}", {**progress(rb, "ROLLED_BACK", "DONE"), "kind": "ROLLBACK",
                                                        "rolled_back": {"mcp-gcloud-server": {"revision": "r7"}}})
    client().get("/api/settings/platform-upgrade")
    assert env["maintenance"] is False


def test_rollback_not_offered(env):
    rid = started(env)
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(rid, "SUCCEEDED", "DONE"))
    r = follow(f"/api/settings/platform-upgrade/{rid}/rollback")
    assert r.status_code == 409 and code(r) == "ROLLBACK_NOT_OFFERED"
    rid2 = pu.request_id_for(ADMIN_EMAIL, "x" * 20)
    env["guard"].put(f"platform_upgrades/{rid2}", {**env["guard"].doc(f"platform_upgrades/{rid}"), "status": "DONE"})
    env["db"].put(f"platform_upgrades_progress/{rid2}", progress(rid2, "PARTIAL", "CHECKING"))  # no previous
    r = follow(f"/api/settings/platform-upgrade/{rid2}/rollback")
    assert r.status_code == 409 and code(r) == "ROLLBACK_NOT_OFFERED"
    r = follow("/api/settings/platform-upgrade/" + "e" * 32 + "/rollback")
    assert r.status_code == 404
    r = follow("/api/settings/platform-upgrade/not-an-id/rollback")
    assert r.status_code == 404


def test_rollback_refused_while_another_lease_is_held(env):
    up = finished_partial(env)
    env["guard"].put("platform_upgrades/_lease", {"request_id": "b" * 32, "expires_at": iso(NOW + 100)})
    env["guard"].put("platform_upgrades/" + "b" * 32, {"status": "REQUESTED", "kind": "UPGRADE"})
    r = follow(f"/api/settings/platform-upgrade/{up}/rollback")
    assert r.status_code == 409 and code(r) == "UPGRADE_IN_PROGRESS"


# ================================================================================================ retry
def test_retry_of_partial_reuses_the_verified_tag(env):
    up = finished_partial(env)
    checks = env["updates_calls"]
    r = follow(f"/api/settings/platform-upgrade/{up}/retry")
    assert r.status_code == 202, r.text
    new = r.json()["request_id"]
    doc = env["guard"].doc(f"platform_upgrades/{new}")
    assert guard.validate_request(new, doc)["kind"] == "UPGRADE"
    assert doc["retry_of"] == up and doc["expected_commit"] == COMMIT and doc["target_tag"] == "v0.9.3"
    assert doc["maintenance"]["before"] is False  # inherited from the failed upgrade
    assert env["updates_calls"] == checks  # the retry makes no new update check (the target is pinned)
    # a retry that is refused again changes nothing, but follows a failure: maintenance stays on
    env["db"].put(f"platform_upgrades_progress/{new}", progress(new, "REFUSED_FETCH_FAILED", "VERIFYING"))
    client().get("/api/settings/platform-upgrade")
    assert env["maintenance"] is True


def test_retry_refusals(env):
    rid = started(env)
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(rid, "SUCCEEDED", "DONE"))
    client().get("/api/settings/platform-upgrade")
    r = follow(f"/api/settings/platform-upgrade/{rid}/retry")
    assert r.status_code == 409 and code(r) == "NOT_RETRYABLE"
    up = pu.request_id_for(ADMIN_EMAIL, "y" * 20)
    env["guard"].put(f"platform_upgrades/{up}", {**env["guard"].doc(f"platform_upgrades/{rid}"),
                                                 "source_fingerprint": "sha256:" + "9" * 64})
    env["db"].put(f"platform_upgrades_progress/{up}", progress(up, "FAILED_BUILDING", "BUILDING"))
    r = follow(f"/api/settings/platform-upgrade/{up}/retry")
    assert r.status_code == 409 and code(r) == "SOURCE_SETTING_CHANGED"


def test_retry_of_a_rollback_keeps_rollback_of(env):
    up = finished_partial(env)
    rb = follow(f"/api/settings/platform-upgrade/{up}/rollback").json()["request_id"]
    env["db"].put(f"platform_upgrades_progress/{rb}", {**progress(rb, "FAILED_ROLLING_BACK", "ROLLING_BACK"),
                                                        "kind": "ROLLBACK"})
    client().get("/api/settings/platform-upgrade")
    r = follow(f"/api/settings/platform-upgrade/{rb}/retry", key="retry-rollback-0000001")
    assert r.status_code == 202, r.text
    doc = env["guard"].doc(f"platform_upgrades/{r.json()['request_id']}")
    assert doc["kind"] == "ROLLBACK" and doc["rollback_of"] == up and doc["retry_of"] == rb


# ================================================================================================ clear lease
def clear(rid, c=None, confirm=PROJ):
    return (c or client()).post("/api/settings/platform-upgrade/lease/clear",
                                json={"expected_request_id": rid, "confirm_project": confirm})


def test_clear_lease_only_when_finished_or_expired(env, monkeypatch):
    rid = started(env)
    r = clear(rid)
    assert r.status_code == 409 and code(r) == "LEASE_ACTIVE"  # waiting for approval: maybe still to run
    r = clear("f" * 32)
    assert r.status_code == 409 and code(r) == "LEASE_CHANGED"
    assert clear(rid, confirm="nope").status_code == 422
    monkeypatch.setattr(pu, "clock", lambda: NOW + pu.LEASE_SECONDS + 1)
    body = client().get("/api/settings/platform-upgrade").json()
    assert body["lease"]["state"] == "STALE" and body["current"]["status"] == "STALE"
    assert body["button"]["reason"] == "UPGRADE_IN_PROGRESS"
    r = clear(rid)
    assert r.status_code == 200 and r.json()["cleared"] is True
    req = env["guard"].doc(f"platform_upgrades/{rid}")
    assert req["status"] == "CANCELLED"  # a build approved later refuses it
    with pytest.raises(guard.Refusal):
        guard.validate_request(rid, req)
    assert env["maintenance"] is False  # never started: nothing changed -> restored


def test_clear_lease_of_a_running_build(env, monkeypatch):
    rid = started(env)
    start_at = NOW + pu.APPROVAL_WINDOW_SECONDS + 400  # approved late, started within the start margin
    env["db"].put(f"platform_upgrades_progress/{rid}", {**progress(rid, stage="DEPLOYING"),
                                                         "started_at": iso(start_at)})
    monkeypatch.setattr(pu, "clock", lambda: NOW + pu.LEASE_SECONDS + 10)  # lease expired, build within its timeout
    r = clear(rid)
    assert r.status_code == 409 and code(r) == "LEASE_ACTIVE"
    monkeypatch.setattr(pu, "clock", lambda: start_at + pu.BUILD_TIMEOUT_SECONDS + pu.RUNNING_SLACK_SECONDS + 1)
    r = clear(rid)
    assert r.status_code == 200 and r.json()["state"] == "STALE"
    assert env["maintenance"] is True  # timed out mid-deploy: unknown state, fail closed
    assert env["guard"].doc(f"platform_upgrades/{rid}")["maintenance"]["kept_on"] is True


def test_clear_without_lease(env):
    r = clear("a" * 32)
    assert r.status_code == 200 and r.json()["cleared"] is False


# ================================================================================================ maintenance restore
def test_restore_maintenance_after_failure(env):
    up = finished_partial(env)
    assert env["maintenance"] is True
    r = client().post(f"/api/settings/platform-upgrade/{up}/maintenance/restore", json={"confirm_project": PROJ})
    assert r.status_code == 200 and r.json() == {"restored": True, "maintenance_mode": False}
    assert env["maintenance"] is False
    r = client().post(f"/api/settings/platform-upgrade/{up}/maintenance/restore", json={"confirm_project": PROJ})
    assert r.json()["restored"] is False
    assert client().get("/api/settings/platform-upgrade").json()["maintenance_kept_on"] is None


def test_restore_maintenance_refused_during_an_upgrade(env):
    up = finished_partial(env)
    follow(f"/api/settings/platform-upgrade/{up}/retry")
    r = client().post(f"/api/settings/platform-upgrade/{up}/maintenance/restore", json={"confirm_project": PROJ})
    assert r.status_code == 409 and code(r) == "UPGRADE_IN_PROGRESS"


def test_default_maintenance_writer_uses_the_one_field_settings_pattern(env, monkeypatch):
    from routes import settings as sr
    from shared.settings import PlatformSettings
    stored = PlatformSettings()
    stored.version = 4
    calls = []
    monkeypatch.setattr(pu, "maintenance_writer", None)
    monkeypatch.setattr(pu, "maintenance_reader", None)
    monkeypatch.setattr(sr, "_read_current_settings_for_write", lambda: (stored, None))
    monkeypatch.setattr(sr, "store_settings_document", lambda doc, version: calls.append((doc, version)))
    monkeypatch.setattr(sr, "_invalidate_current_settings_cache", lambda *a, **k: None)
    monkeypatch.setattr(sr, "db", object())
    assert pu._read_maintenance() is False
    pu._write_maintenance(True, ADMIN_EMAIL, "platform upgrade x")
    doc, version = calls[0]
    assert version == 4 and doc["version"] == 5 and doc["governance"]["maintenance_mode"] is True
    assert doc["audit_log"][0]["action"] == "PLATFORM_UPGRADE_MAINTENANCE"
    assert doc["audit_log"][0]["changed_fields"]["governance.maintenance_mode"] == {"from": False, "to": True}
    stored.governance.maintenance_mode = True
    pu._write_maintenance(True, ADMIN_EMAIL, "again")  # already so: nothing written
    assert len(calls) == 1
    monkeypatch.setattr(sr, "db", None)
    with pytest.raises(Exception) as e:  # never a silent no-op without Firestore
        pu._write_maintenance(False, ADMIN_EMAIL, "x")
    assert e.value.detail["code"] == "MAINTENANCE_UNAVAILABLE"


# ================================================================================================ release source
def test_release_source_change_refused_while_lease_held(env):
    started(env)
    key, _blob = "ssh-ed25519 " + "A" * 4, None
    r = client().put("/api/settings/release-source", json={
        "repository": "acme/fork", "signers": [{"kind": "OFFICIAL"}], "expected_version": 0,
        "confirm_repository": "acme/fork"})
    assert r.status_code == 409 and code(r) == "UPGRADE_IN_PROGRESS"
    assert ("platform_release_source", "current") not in env["guard"].docs


# ================================================================================================ no deploy power
def test_control_center_never_calls_cloud_build_or_cloud_run_writes():
    """Static: the upgrade routes import no Cloud Build / Cloud Run / IAM client, name no such API, and publish in
    exactly one place. (The Control Center's Cloud Run access stays the read-only run.viewer display path in
    platform_release.py, whose seam is GET-only.)"""
    path = os.path.join(CC_DIR, "routes", "platform_upgrade.py")
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    for mod in imported:
        assert "cloudbuild" not in mod and "run_v2" not in mod and "iam" not in mod.split("."), mod
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    for s in strings:
        assert "cloudbuild.googleapis.com" not in s and "run.googleapis.com" not in s, s
        assert "builds:" not in s and "triggers" not in s.lower(), s
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
    assert [c.func.attr for c in calls].count("publish") == 1
    for name in ("AuthorizedSession", "requests", "urlopen"):
        assert name not in {getattr(c.func, "attr", "") for c in calls} | imported


def test_request_ids_are_per_caller(env):
    a, b = pu.request_id_for("a@example.com", KEY), pu.request_id_for("b@example.com", KEY)
    assert a != b and all(len(x) == 32 and set(x) <= set("0123456789abcdef") for x in (a, b))


def test_lease_state_table():
    lease = {"request_id": "a" * 32, "expires_at": iso(NOW + pu.LEASE_SECONDS), "created_at": iso(NOW)}
    req = {"status": "REQUESTED"}
    claim_end = NOW + pu.APPROVAL_WINDOW_SECONDS + pu.BUILD_START_MARGIN_SECONDS
    assert pu.lease_state(lease, req, None, NOW) == "ACTIVE"
    assert pu.lease_state(lease, req, None, claim_end) == "ACTIVE"  # a build may still claim (+ slack)
    assert pu.lease_state(lease, req, None, claim_end + pu.RUNNING_SLACK_SECONDS) == "STALE"
    assert pu.lease_state(lease, None, None, NOW) == "FINISHED"
    assert pu.lease_state(lease, {"status": "NOT_SENT"}, None, NOW) == "FINISHED"
    assert pu.lease_state(lease, {"status": "STARTED"}, None, NOW) == "ACTIVE"
    assert pu.lease_state(lease, req, {"status": "PARTIAL"}, NOW) == "FINISHED"
    assert pu.lease_state({"expires_at": "garbage"}, req, None, NOW) == "STALE"
    short = {"request_id": "a" * 32, "expires_at": iso(NOW + 10), "created_at": iso(NOW)}
    running = {"status": "RUNNING", "started_at": iso(NOW)}
    assert pu.lease_state(short, req, running, NOW + 5000) == "ACTIVE"
    assert pu.lease_state(short, req, running, NOW + 7200 + 901) == "STALE"
    # RT M-1: without created_at nothing from the progress record extends the lease
    no_created = {"request_id": "a" * 32, "expires_at": iso(NOW + 10)}
    assert pu.lease_state(no_created, req, running, NOW + 5000) == "STALE"
    assert pu.renewed_expiry(no_created, running) is None


def test_m1_forged_future_start_cannot_hold_the_lease(env, monkeypatch):
    """RT M-1 (SCN-D): a progress record with started_at years ahead (forgeable default database)."""
    rid = started(env)
    env["db"].put(f"platform_upgrades_progress/{rid}", {**progress(rid, stage="BUILDING"),
                                                         "started_at": iso(NOW + 10 * 365 * 86400)})
    cap = NOW + pu.LEASE_SECONDS + pu.RUNNING_SLACK_SECONDS
    monkeypatch.setattr(pu, "clock", lambda: NOW + 600)
    client().get("/api/settings/platform-upgrade")  # renewal is capped at the lease the CC issued
    assert env["guard"].doc("platform_upgrades/_lease")["expires_at"] == iso(cap)
    monkeypatch.setattr(pu, "clock", lambda: cap - 1)
    assert clear(rid).status_code == 409
    monkeypatch.setattr(pu, "clock", lambda: cap + 1)
    body = client().get("/api/settings/platform-upgrade").json()
    assert body["lease"]["state"] == "STALE"
    r = clear(rid)
    assert r.status_code == 200 and r.json()["cleared"] is True


def test_m1_honest_build_unchanged():
    lease = {"request_id": "a" * 32, "expires_at": iso(NOW + pu.LEASE_SECONDS), "created_at": iso(NOW)}
    latest_start = NOW + pu.APPROVAL_WINDOW_SECONDS + pu.BUILD_START_MARGIN_SECONDS  # the last claim step 0 allows
    running = {"status": "RUNNING", "started_at": iso(latest_start)}
    end = latest_start + pu.BUILD_TIMEOUT_SECONDS + pu.RUNNING_SLACK_SECONDS
    assert pu.lease_cap(lease) == end  # the cap is exactly the honest worst case
    assert pu.renewed_expiry(lease, running) == iso(end)
    assert pu.lease_state(lease, {"status": "STARTED"}, running, end - 1) == "ACTIVE"
    assert pu.lease_state(lease, {"status": "STARTED"}, running, end) == "STALE"


def test_m4_build_timeout_parity():
    """RT M-4: the CC's lease math, step 0's claim rule and the trigger's timeout use one number."""
    assert pu.BUILD_TIMEOUT_SECONDS == guard.BUILD_TIMEOUT_S == 7200
    tf = os.path.join(BASE_DIR, "infra", "platform", "platform_upgrader.tf")
    if os.path.exists(tf):  # B3's trigger (present on the integrated branch)
        text = open(tf, encoding="utf-8").read()
        timeouts = {line.split("=", 1)[1].strip().strip('"') for line in text.splitlines()
                    if line.strip().startswith("timeout") and "=" in line}
        assert timeouts == {f"{pu.BUILD_TIMEOUT_SECONDS}s"}, timeouts
    for copy_path in (os.path.join(BASE_DIR, "infra", "platform", "upgrade_step0", "guard.py"),):
        if os.path.exists(copy_path):  # the frozen copy embedded by Terraform
            assert f"BUILD_TIMEOUT_S = {pu.BUILD_TIMEOUT_SECONDS}\n" in open(copy_path, encoding="utf-8").read()


def m_a_claim_ok(lease, now):
    """Review A M-A, the frozen step 0 rule after the fix: the lease must still cover a whole build at claim."""
    return pu._parse_ts(lease["expires_at"]) >= now + pu.BUILD_TIMEOUT_SECONDS


def test_m_a_lease_covers_approval_window_plus_a_whole_build(env):
    rid = start().json()["request_id"]
    lease = env["guard"].doc("platform_upgrades/_lease")
    margin = pu.BUILD_START_MARGIN_SECONDS  # RT L-1: an approval at minute 60 still has time for the build to start
    assert margin == 600
    assert lease["expires_at"] == iso(NOW + pu.APPROVAL_WINDOW_SECONDS + margin + pu.BUILD_TIMEOUT_SECONDS)
    assert m_a_claim_ok(lease, NOW) and m_a_claim_ok(lease, NOW + pu.APPROVAL_WINDOW_SECONDS + margin)
    assert not m_a_claim_ok(lease, NOW + pu.APPROVAL_WINDOW_SECONDS + margin + 1)  # too late: LEASE_NOT_HELD
    guard.check_lease(rid, lease, datetime.fromtimestamp(NOW + pu.APPROVAL_WINDOW_SECONDS + margin, timezone.utc))
    with pytest.raises(guard.Refusal) as e:  # B2's frozen step 0 (M-A): approved after the window -> refused
        guard.check_lease(rid, lease, datetime.fromtimestamp(NOW + pu.APPROVAL_WINDOW_SECONDS + margin + 1,
                                                             timezone.utc))
    assert e.value.code == "LEASE_NOT_HELD"
    # the admin is told the window
    body = client().get("/api/settings/platform-upgrade").json()
    assert "within 60 minutes of the request" in body["current"]["waiting_text"]
    assert "within 60 minutes" in body["approval_text"]


def test_m_a_lease_renewed_while_the_build_runs(env, monkeypatch):
    rid = started(env)
    late_start = NOW + pu.APPROVAL_WINDOW_SECONDS  # approved at the end of the window
    env["db"].put(f"platform_upgrades_progress/{rid}", {**progress(rid, stage="BUILDING"),
                                                         "started_at": iso(late_start)})
    monkeypatch.setattr(pu, "clock", lambda: late_start + 60)
    client().get("/api/settings/platform-upgrade")
    lease = env["guard"].doc("platform_upgrades/_lease")
    assert lease["expires_at"] == iso(late_start + pu.BUILD_TIMEOUT_SECONDS + pu.RUNNING_SLACK_SECONDS)
    # bounded: a RUNNING record never holds it longer than one build from its start
    monkeypatch.setattr(pu, "clock", lambda: late_start + 5000)
    client().get("/api/settings/platform-upgrade")
    assert env["guard"].doc("platform_upgrades/_lease")["expires_at"] == lease["expires_at"]
    # a second request cannot start while it runs
    r = start(idempotency_key="another-key-0000000002")
    assert r.status_code == 409 and code(r) == "UPGRADE_IN_PROGRESS"


def test_m_b_request_moves_to_started_when_progress_appears(env):
    rid = started(env)
    assert guard.validate_request(rid, env["guard"].doc(f"platform_upgrades/{rid}"))  # still REQUESTED
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(rid, stage="VERIFYING"))
    client().get("/api/settings/platform-upgrade")
    req = env["guard"].doc(f"platform_upgrades/{rid}")
    assert req["status"] == "STARTED"
    # a redelivered Pub/Sub message, even after the progress record was deleted, is refused by step 0
    env["db"].docs.pop(("platform_upgrades_progress", rid))
    with pytest.raises(guard.Refusal) as e:
        guard.validate_request(rid, req)
    assert e.value.code == "REQUEST_NOT_PENDING"
    # the lease is still held by the started request
    assert env["guard"].doc("platform_upgrades/_lease")["request_id"] == rid
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(rid, "SUCCEEDED", "DONE"))
    client().get("/api/settings/platform-upgrade")
    assert env["guard"].doc(f"platform_upgrades/{rid}")["status"] == "DONE"


def test_publish_uses_the_full_topic_path(env, monkeypatch):
    monkeypatch.setenv(pu.TOPIC_ENV, "stackvend-platform-upgrade")  # a bare id becomes this project's full path
    rid = start().json()["request_id"]
    topic, _data, attrs = env["pub"].messages[0]
    assert topic == f"projects/{PROJ}/topics/stackvend-platform-upgrade" and attrs == {"request_id": rid}


# ================================================================================================ dashboard
def test_dashboard_card_wiring():
    with open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8") as f:
        html = f.read()
    assert html.count("async loadPlatformUpgrade()") == 1 and "await this.loadPlatformUpgrade();" in html
    for path in ("'/api/settings/platform-upgrade'", "'/api/settings/platform-upgrade/lease/clear'",
                 "'/maintenance/restore'"):
        assert path in html, path
    # the reason line and the approval text come from the API (one source of truth), never rebuilt in the page
    assert 'x-text="upgrades.upgrade?.button?.text"' in html
    assert 'x-text="upgrades.upgrade.current.waiting_text"' in html
    assert "upgrades.upgrade?.button?.visible && upgrades.upgrade?.button?.enabled" in html
    # a repeated click reuses the same idempotency key; external links go through safeUrl
    assert "idempotency_key: this.upgrades.upgradeKey" in html
    assert 'safeUrl(upgrades.upgrade.current.build_url)' in html
    # polling is a setTimeout chain bound to the Upgrades tab, never a new setInterval
    start = html.index("async loadPlatformUpgrade()")
    body = html[start:html.index("_newIdempotencyKey()", start)]
    assert "setInterval" not in body and "setTimeout" in body and "settingsTab === 'upgrades'" in body
    assert "Roll back services" in html and "Clear the stale lease" in html and "Turn maintenance off" in html


def test_approval_text_is_plain():
    assert pu.APPROVAL_TEXT.startswith("An administrator must approve this build in the Google Cloud console "
                                       "(Cloud Build ▸ History)")


# ================================================================================================ fail-loudly §2 cases
def test_failed_restore_is_typed_shown_and_retried(env):
    rid = started(env)
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(rid, "SUCCEEDED", "DONE"))
    env["maint_fail"] = True
    body = client().get("/api/settings/platform-upgrade").json()
    assert body["lease"] is None and env["maintenance"] is True
    assert env["guard"].doc(f"platform_upgrades/{rid}")["maintenance"]["restore_error"] == "RuntimeError"
    assert body["maintenance_kept_on"]["code"] == "MAINTENANCE_NOT_RESTORED"
    env["maint_fail"] = False
    body = client().get("/api/settings/platform-upgrade").json()  # the next look retries the restore
    assert env["maintenance"] is False and body["maintenance_kept_on"] is None
    assert "restore_error" not in env["guard"].doc(f"platform_upgrades/{rid}")["maintenance"]


def test_a_later_success_supersedes_the_kept_on_banner(env):
    up = finished_partial(env)
    assert client().get("/api/settings/platform-upgrade").json()["maintenance_kept_on"]["code"] == "MAINTENANCE_KEPT_ON"
    pu.clock = lambda: NOW + 100  # the retry is newer (monkeypatch restores the clock afterwards)
    new = follow(f"/api/settings/platform-upgrade/{up}/retry").json()["request_id"]
    assert client().get("/api/settings/platform-upgrade").json()["maintenance_kept_on"] is None  # during the retry
    env["db"].put(f"platform_upgrades_progress/{new}", progress(new, "SUCCEEDED", "DONE"))
    body = client().get("/api/settings/platform-upgrade").json()
    assert env["maintenance"] is False and body["maintenance_kept_on"] is None


def test_publish_failure_says_what_was_not_undone(env):
    env["pub"].fail = True

    def flaky(value, by, reason):
        if value is False:
            raise RuntimeError("settings store refused")
        env["maint_writes"].append((value, by, reason))
        env["maintenance"] = value
    pu.maintenance_writer = flaky
    try:
        r = start()
    finally:
        pu.maintenance_writer = None
    assert r.status_code == 502 and code(r) == "PUBLISH_FAILED"
    assert "Not undone: maintenance mode is still on" in r.json()["detail"]["message"]


def test_default_executions_reader_uses_a_read_only_rest_get(env, monkeypatch):
    """google-cloud-workflows is not in the Control Center image: the count is one authorized GET on the Workflows
    Executions API (the same read-only helper as the Cloud Run display). Any failure raises (-> EXECUTIONS_UNKNOWN)."""
    seen = []

    def get(url):
        seen.append(url)
        return 200, {"executions": [{"name": "e1", "state": "ACTIVE"}]}
    monkeypatch.setattr(pu, "active_executions_provider", None)
    monkeypatch.setattr(pr, "cloud_run_get_json", get)
    assert pu._active_executions() == 1
    assert seen == [f"https://workflowexecutions.googleapis.com/v1/projects/{PROJ}/locations/{REGION}/workflows/"
                    "castor-main-orchestrator/executions?pageSize=100&filter=state%3D%22ACTIVE%22"]
    # the API refuses an unquoted value (HTTP 400 "value must be a string in quotation marks"): pin the exact filter
    assert pu.ACTIVE_FILTER == 'state="ACTIVE"'
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(seen[0]).query)["filter"] == ['state="ACTIVE"']
    monkeypatch.setattr(pr, "cloud_run_get_json", lambda url: (200, {}))
    assert pu._active_executions() == 0
    monkeypatch.setattr(pr, "cloud_run_get_json", lambda url: (403, None))
    with pytest.raises(RuntimeError):
        pu._active_executions()
    r = start()
    assert r.status_code == 503 and code(r) == "EXECUTIONS_UNKNOWN"


# ================================================================================================ final RT (selfup-int)
def test_h1_same_key_after_a_failed_start_is_refused_not_faked(env):
    env["pub"].fail = True
    assert start().status_code == 502
    env["pub"].fail = False
    r = start()  # the same idempotency key: the request exists as NOT_SENT
    assert r.status_code == 409 and code(r) == "REQUEST_NOT_SENT" and r.json()["detail"]["status"] == "NOT_SENT"
    assert env["pub"].messages == []
    r = start(idempotency_key="a-fresh-key-0000000001")  # the dashboard rotates the key after any server answer
    assert r.status_code == 202 and len(env["pub"].messages) == 1


def finished_partial_with_key(env, key):
    rid = start(idempotency_key=key).json()["request_id"]
    env["maint_writes"].clear()
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(
        rid, "PARTIAL", "CHECKING", deployed={"mcp-gcloud-server": {"kind": "service", "image": "x"}},
        previous={"mcp-gcloud-server": {"kind": "service", "revision": "r7"}}))
    client().get("/api/settings/platform-upgrade")
    return rid


def test_h1_same_key_after_maintenance_failure_and_for_follow_ups(env):
    env["maint_fail"] = True
    assert start().status_code == 503
    env["maint_fail"] = False
    r = start()
    assert r.status_code == 409 and code(r) == "REQUEST_NOT_SENT" and r.json()["detail"]["status"] == "CANCELLED"
    up = finished_partial_with_key(env, "partial-upgrade-key-0001")
    for action in ("retry", "rollback"):
        key = f"{action}-follow-key-000001"
        env["pub"].fail = True
        assert follow(f"/api/settings/platform-upgrade/{up}/{action}", key=key).status_code == 502
        env["pub"].fail = False
        r = follow(f"/api/settings/platform-upgrade/{up}/{action}", key=key)
        assert r.status_code == 409 and code(r) == "REQUEST_NOT_SENT", action


def test_m2_fresh_update_after_kept_on_failure_restores_the_original_value(env):
    up = finished_partial(env)
    assert env["maintenance"] is True  # kept on after PARTIAL
    pu.clock = lambda: NOW + 100  # the new request is newer (monkeypatch restores the clock)
    r = start(idempotency_key="next-release-key-000001")
    assert r.status_code == 202, r.text
    new = r.json()["request_id"]
    maint = env["guard"].doc(f"platform_upgrades/{new}")["maintenance"]
    assert maint["before"] is False and maint["inherited_from"] == up
    env["db"].put(f"platform_upgrades_progress/{new}", progress(new, "SUCCEEDED", "DONE"))
    body = client().get("/api/settings/platform-upgrade").json()
    assert env["maintenance"] is False and body["maintenance_kept_on"] is None


def test_m2_no_inheritance_after_a_restored_request(env):
    rid = started(env)
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(rid, "SUCCEEDED", "DONE"))
    client().get("/api/settings/platform-upgrade")
    env["maintenance"] = True  # an admin turned it on deliberately afterwards
    pu.clock = lambda: NOW + 100
    new = start(idempotency_key="later-upgrade-key-00001").json()["request_id"]
    maint = env["guard"].doc(f"platform_upgrades/{new}")["maintenance"]
    assert maint["before"] is True and "inherited_from" not in maint


def test_l3_upgrader_off_reads_nothing(env, monkeypatch):
    monkeypatch.delenv(pu.TOPIC_ENV, raising=False)
    env["guard"].reads.clear()
    env["db"].reads.clear()
    body = client().get("/api/settings/platform-upgrade").json()
    assert body["installed"] is False and body["history"] == [] and body["lease"] is None
    assert env["guard"].reads == [] and env["db"].reads == []
    client().put("/api/settings/update-check", json={"enabled": False, "expected_version": 0})
    assert ("platform_upgrades", "_lease") not in env["guard"].reads


def test_l4_rollback_superseded_by_a_newer_change(env):
    up = finished_partial(env)
    pu.clock = lambda: NOW + 100
    new = start(idempotency_key="next-release-key-000002").json()["request_id"]
    env["db"].put(f"platform_upgrades_progress/{new}", progress(new, "SUCCEEDED", "DONE"))
    client().get("/api/settings/platform-upgrade")
    r = follow(f"/api/settings/platform-upgrade/{up}/rollback")
    assert r.status_code == 409 and code(r) == "ROLLBACK_SUPERSEDED" and r.json()["detail"]["newer"] == new


def test_l4_a_newer_refused_request_does_not_supersede(env):
    up = finished_partial(env)
    pu.clock = lambda: NOW + 100
    new = follow(f"/api/settings/platform-upgrade/{up}/retry").json()["request_id"]
    env["db"].put(f"platform_upgrades_progress/{new}", progress(new, "REFUSED_FETCH_FAILED", "VERIFYING"))
    client().get("/api/settings/platform-upgrade")
    r = follow(f"/api/settings/platform-upgrade/{up}/rollback", key="rollback-after-refused-01")
    assert r.status_code == 202, r.text


def test_l5_update_check_refused_during_an_upgrade(env):
    started(env)
    r = client().put("/api/settings/update-check", json={"enabled": False, "expected_version": 0})
    assert r.status_code == 409 and code(r) == "UPGRADE_IN_PROGRESS"
    assert ("platform_release_source", "current") not in env["guard"].docs


def test_l6_unavailable_guard_database_is_503_not_in_progress(env):
    env["guard"].fail_commit = True
    r = start()
    assert r.status_code == 503 and code(r) == "GUARD_DATABASE_UNAVAILABLE"
    assert env["pub"].messages == [] and env["maint_writes"] == []


def test_dashboard_rotates_the_key_unless_the_answer_was_lost():
    with open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8") as f:
        html = f.read()
    assert "if (result !== 'network') this.upgrades.upgradeKey = '';" in html
    assert "if (result !== 'network') this.upgrades.followKey = '';" in html
    assert "return 'network';" in html and "return 'failed';" in html
    assert 'x-show="upgrades.upgrade?.installed || upgrades.upgradeError"' in html  # L-3: hidden without the upgrader


# ================================================================================================ UPGRADER-READY-INGRESS F2
def _finished(env, ready="NOT_CHECKED: INGRESS_INTERNAL: the terraform server's ingress is INGRESS_TRAFFIC_INTERNAL_ONLY"):
    rid = started(env)
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(
        rid, "SUCCEEDED", "DONE", deployed={n: {"kind": "service", "image": "x"} for n in ALL},
        check={n: {"ok": True} for n in ALL}, terraform_ready=ready))
    return rid


@pytest.mark.parametrize("answer,state,reason", [
    ((200, {"ready": True}), "READY", ""),
    ((200, {"ready": False, "reason": "provider mirror incomplete"}), "NOT_READY",
     "ready=False: provider mirror incomplete"),
    ((200, {}), "NOT_READY", "ready=None"),
    ((200, None), "NOT_READY", "ready=None"),
    ((503, None), "NOT_READY", "HTTP 503"),
    ((403, None), "NOT_CHECKED", "the terraform server refused the Control Center (HTTP 403)"),
    ((404, None), "NOT_CHECKED", "the terraform server was not reachable from the Control Center (HTTP 404: an "
                                 "ingress refusal, or the route is missing)"),
])
def test_cc_checks_validate_ready_when_the_upgrader_could_not(env, answer, state, reason):
    _finished(env)
    env["tf_ready"] = answer
    cur = client().get("/api/settings/platform-upgrade").json()["current"]
    assert cur["terraform_ready"].startswith("NOT_CHECKED")   # the upgrader's own answer is kept as it was
    cc = cur["terraform_ready_cc"]
    assert (cc["state"], cc["reason"]) == (state, reason) and cc["checked_at"]
    assert env["tf_ready_calls"] == 1


@pytest.mark.parametrize("exc,reason", [
    (LookupError("the terraform server's URL is unknown"), "the terraform server's URL is unknown"),
    (ConnectionError("down"), "the terraform server did not answer (ConnectionError)"),
])
def test_cc_check_that_cannot_ask_is_not_checked_never_ready(env, exc, reason):
    _finished(env)
    env["tf_ready"] = exc
    cc = client().get("/api/settings/platform-upgrade").json()["current"]["terraform_ready_cc"]
    assert cc["state"] == "NOT_CHECKED" and cc["reason"] == reason


def test_cc_check_is_cached_for_a_minute(env, monkeypatch):
    _finished(env)
    client().get("/api/settings/platform-upgrade")
    client().get("/api/settings/platform-upgrade")
    assert env["tf_ready_calls"] == 1
    monkeypatch.setattr(pu, "clock", lambda: NOW + pu.CC_READY_CACHE_SECONDS + 1)
    client().get("/api/settings/platform-upgrade")
    assert env["tf_ready_calls"] == 2


@pytest.mark.parametrize("ready", ["READY", ""])
def test_negative_no_cc_check_when_the_upgrader_checked_or_did_not_get_there(env, ready):
    _finished(env, ready=ready)
    cur = client().get("/api/settings/platform-upgrade").json()["current"]
    assert cur["terraform_ready_cc"] is None and env["tf_ready_calls"] == 0


def test_negative_no_cc_check_while_the_upgrade_runs(env):
    rid = started(env)
    env["db"].put(f"platform_upgrades_progress/{rid}", progress(rid, stage="CHECKING", terraform_ready="NOT_CHECKED: x"))
    cur = client().get("/api/settings/platform-upgrade").json()["current"]
    assert cur["terraform_ready_cc"] is None and env["tf_ready_calls"] == 0


def test_dashboard_shows_the_cc_check():
    with open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8") as f:
        html = f.read()
    assert "upgrades.upgrade.current.terraform_ready_cc" in html
    assert "data-upgrade-cc-ready" in html
