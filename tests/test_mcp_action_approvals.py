"""
APPROVAL-CONSUME-VIA-VENDING (owner 11-07; docs/planning/mcp-action-approval-plan.md): MCP action approvals
(HELM_UNINSTALL, AGENT_ENGINE_DEPLOY, DATASTORE_CREATE) are requested by the MCP server (an MCP_ACTION card), approved
by a human ADMIN in the Control Center (a bound single-use destructive_approvals record), and consumed by the MCP
server through project-vending's POST /approvals/{id}/consume (one guard-database transaction), never through the
Control Center.

  * vending consume: success, already consumed, expired, wrong binding / action / target, unapproved, non-MCP
    action, wrong / missing caller, store unavailable, lost race (re-read) and a threaded race (one winner);
  * the seam targets vending (env URL or the Cloud Run metadata URL, ID token for vending's audience) and fails
    closed when vending is unreachable or answers without a typed code;
  * the CC card: ADMIN human only (a manager or a bearer cannot approve; the route policy refuses bearers), approve
    mints with the card's exact binding for the ledger's project, stale / tampered cards are refused, reject mints
    nothing; mint_approval keeps decommission records unchanged;
  * the binding table and digest agree in the seam, the CC and vending;
  * unrelated vending routes keep their caller checks (Do No Harm);
  * Helm request -> CC approve -> vending consume -> uninstall, end to end with fakes; a replay is refused.
Hermetic fakes only.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import copy
import importlib.util
import os
import sys
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import destructive_guard_fakes as f
from destructive_guard_fakes import dg

import mcp_approvals  # noqa: E402  (apps/project-vending on sys.path via destructive_guard_fakes)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO, "apps", "control-center")
for _p in (REPO, CC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_saved_client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "mcp-approvals-test.apps.googleusercontent.com"
try:
    import authz  # noqa: E402
    import destructive_actions as da  # noqa: E402
    from routes import approvals as appr_routes  # noqa: E402
    from schemas import ApprovalDecisionRequest, ApprovalStatus, ApprovalType, UserRole  # noqa: E402
finally:
    if _saved_client_id is None:
        os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
    else:
        os.environ["GOOGLE_OAUTH_CLIENT_ID"] = _saved_client_id


def _load(name, path, extra=None):
    """Loads a module by path under a unique name; `extra` names are visible in sys.modules while it executes."""
    saved = {k: sys.modules.get(k) for k in (extra or {})}
    sys.modules.update(extra or {})
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod   # unique name (dataclasses resolve their module while it executes)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


SEAM_PATHS = {n: os.path.join(REPO, "mcp-servers", n, "managed_target_seam.py")
              for n in ("agent-builder", "kubernetes", "gcloud", "github")}
seam = _load("mcp_approvals_test_seam", SEAM_PATHS["kubernetes"])
helm = _load("mcp_approvals_test_helm", os.path.join(REPO, "mcp-servers", "kubernetes", "helm.py"),
             extra={"managed_target_seam": seam})
VMAIN = f.load_vending_main()

AUD = "https://project-repo-vending-service-abc-uc.a.run.app"
CONSUMER = f.OTHER_SA      # sa-castor-developer@mock-stackvend-project (default MCP_APPROVAL_CONSUMERS)
TOKENS = {
    "dev-token": {"iss": "https://accounts.google.com", "aud": AUD, "email": CONSUMER, "email_verified": True},
    "cc-token": {"iss": "https://accounts.google.com", "aud": AUD, "email": f.CC_SA, "email_verified": True},
}
ADMIN = "owner@example.com"
PID, CHILD, NUMBER = "claims", "claims-child-123", "123456789012"
BINDING = {"cluster": "claims-gke", "location": "us-east4-b", "namespace": "claims", "release": "claims-api"}


def fake_verifier(token, audiences):
    if token not in TOKENS:
        raise ValueError("bad token")
    return dict(TOKENS[token])


# ---------------------------------------------------------------------------------------------- shared fake DB
class _Snap:
    def __init__(self, doc_id, data):
        self.id, self._d, self.exists = doc_id, copy.deepcopy(data), data is not None

    def to_dict(self):
        return copy.deepcopy(self._d)


class _Doc:
    def __init__(self, db, path):
        self.db, self.path, self.id = db, path, path.rsplit("/", 1)[-1]

    def get(self, transaction=None):
        if self.db.down:
            raise RuntimeError("503 Firestore unavailable")
        return _Snap(self.id, self.db.docs.get(self.path))

    def set(self, data, merge=False):
        cur = self.db.docs.get(self.path) if merge else None
        self.db.docs[self.path] = {**(cur or {}), **copy.deepcopy(data)}

    def create(self, data):
        if self.path in self.db.docs:
            raise RuntimeError("409 AlreadyExists")
        self.db.docs[self.path] = copy.deepcopy(data)

    def update(self, fields):
        if self.path not in self.db.docs:
            raise RuntimeError("404 NotFound")
        self.db.docs[self.path] = {**self.db.docs[self.path], **copy.deepcopy(fields)}


class _Coll:
    def __init__(self, db, name, flt=None, n=None):
        self.db, self.name, self.flt, self.n = db, name, flt, n

    def document(self, doc_id):
        return _Doc(self.db, f"{self.name}/{doc_id}")

    def where(self, *args, filter=None):  # noqa: A002 (Firestore API: positional or filter=)
        flt = filter if filter is not None else (args[0], args[2])
        return _Coll(self.db, self.name, (flt[0], flt[-1]), self.n)

    def limit(self, n):
        return _Coll(self.db, self.name, self.flt, n)

    def stream(self):
        if self.db.down:
            raise RuntimeError("503 Firestore unavailable")
        rows = [_Snap(k.split("/", 1)[1], v) for k, v in sorted(self.db.docs.items())
                if k.startswith(self.name + "/") and k.count("/") == 1
                and (self.flt is None or v.get(self.flt[0]) == self.flt[1])]
        return iter(rows[:self.n] if self.n else rows)


class FakeDB:
    def __init__(self):
        self.docs, self.down = {}, False

    def collection(self, name):
        return _Coll(self, name)


class Store(dg.FirestoreGuardStore):
    """The real store; its transaction runner calls the body on the fake (optionally serialized by a lock)."""
    __test__ = False

    def __init__(self, db, guard_db, lock=None):
        super().__init__(db, guard_db)
        self.lock = lock

    def _run_in_transaction(self, body):
        if self.lock is None:
            return body(f.FakeTxn(self.guard_db))
        with self.lock:
            return body(f.FakeTxn(self.guard_db))


def now():
    return datetime.now(timezone.utc)


def approval(**over):
    t = now()
    rec = {"status": "APPROVED", "action": "HELM_UNINSTALL", "product_id": PID, "project_id": CHILD,
           "project_number": NUMBER, "resource_name": None, "principal_type": "USER", "approved_by": ADMIN,
           "approved_by_role": "ADMIN", "approved_at": (t - timedelta(minutes=1)).isoformat(),
           "expires_at": (t + timedelta(minutes=14)).isoformat(), "binding": dict(BINDING),
           "binding_digest": mcp_approvals.binding_digest(BINDING), "request_id": "mcp-req-1"}
    rec.update(over)
    return rec


@pytest.fixture
def world(monkeypatch):
    monkeypatch.setenv("VENDING_SERVICE_URL", AUD)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    monkeypatch.delenv(mcp_approvals.CONSUMERS_ENV, raising=False)
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("CLOUD_RUN_JOB", raising=False)
    monkeypatch.setattr(seam, "_field_filter", lambda field, value: (field, value))
    default_db, guard_db = FakeDB(), FakeDB()
    default_db.docs[f"workloads/{PID}"] = {"product_id": PID, "project_id": CHILD, "project_number": NUMBER,
                                           "status": "ACTIVE", "is_castor": False}
    store = Store(default_db, guard_db)
    ctx = f.make_ctx(default_db, f.FakeCRM(), store=store, clock=now)
    monkeypatch.setattr(VMAIN, "vending_engine", SimpleNamespace(guard_context=lambda: ctx))
    monkeypatch.setattr(VMAIN, "CALLER_TOKEN_VERIFIER", fake_verifier)
    monkeypatch.setattr(appr_routes, "db", default_db)
    monkeypatch.setattr(da, "get_guard_db", lambda: guard_db)
    return SimpleNamespace(db=default_db, guard=guard_db, store=store, ctx=ctx, client=TestClient(VMAIN.app))


def consume(w, approval_id="ap-1", token="dev-token", **over):
    body = {"action": "HELM_UNINSTALL", "product_id": PID, "project_id": CHILD, "binding": dict(BINDING)}
    body.update(over)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return w.client.post(f"/approvals/{approval_id}/consume", json=body, headers=headers)


def code_of(resp):
    return resp.json()["detail"]["code"]


# ============================================================================================ vending consume
def test_consume_success_marks_the_record_consumed_once(world):
    world.guard.docs["destructive_approvals/ap-1"] = approval()
    r = consume(world)
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["status"], body["approval_id"], body["action"], body["consumed_by"], body["approved_by"]) == (
        "CONSUMED", "ap-1", "HELM_UNINSTALL", CONSUMER, ADMIN)
    rec = world.guard.docs["destructive_approvals/ap-1"]
    assert rec["status"] == "CONSUMED" and rec["consumed_by"] == CONSUMER and rec["consumed_at"] == body["consumed_at"]
    assert rec["consumed_via"] == mcp_approvals.CONSUMED_VIA
    assert not [k for k in world.db.docs if k.startswith("destructive_approvals/")]  # only the guard DB


def test_consume_twice_is_refused(world):
    world.guard.docs["destructive_approvals/ap-1"] = approval()
    assert consume(world).status_code == 200
    r = consume(world)
    assert (r.status_code, code_of(r)) == (409, "APPROVAL_CONSUMED")


@pytest.mark.parametrize("over,status,code", [
    ({"expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}, 403, "APPROVAL_EXPIRED"),
    ({"approved_at": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(),
      "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()}, 403, "APPROVAL_EXPIRED"),
    ({"approved_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
      "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()}, 403, "APPROVAL_EXPIRED"),
    ({"status": "PENDING"}, 409, "APPROVAL_NOT_APPROVED"),
    ({"status": "VOID"}, 409, "APPROVAL_NOT_APPROVED"),
    ({"status": "EXECUTED"}, 409, "APPROVAL_CONSUMED"),
    ({"consumed_at": "2026-11-07T10:00:00+00:00"}, 409, "APPROVAL_CONSUMED"),
    ({"principal_type": "SERVICE_ACCOUNT"}, 403, "APPROVAL_NOT_HUMAN"),
    ({"approved_by_role": "WORKLOAD_MANAGER"}, 403, "APPROVAL_NOT_HUMAN"),
    ({"approved_by": "sa-castor-finops@p.iam.gserviceaccount.com"}, 403, "APPROVAL_NOT_HUMAN"),
    ({"project_id": "other-child"}, 403, "APPROVAL_TARGET_MISMATCH"),
    ({"product_id": "other"}, 403, "APPROVAL_TARGET_MISMATCH"),
    ({"action": "DATASTORE_CREATE"}, 403, "APPROVAL_ACTION_MISMATCH"),
    ({"binding_digest": "0" * 64}, 403, "APPROVAL_BINDING_MISMATCH"),
    ({"binding": dict(BINDING, release="other")}, 403, "APPROVAL_BINDING_MISMATCH"),
    ({"binding": None, "binding_digest": None}, 403, "APPROVAL_BINDING_MISMATCH"),
    ({"action": "PROJECT_DECOMMISSION"}, 403, "APPROVAL_ACTION_NOT_CONSUMABLE"),
])
def test_consume_refusals_change_nothing(world, over, status, code):
    world.guard.docs["destructive_approvals/ap-1"] = approval(**over)
    before = copy.deepcopy(world.guard.docs)
    r = consume(world)
    assert (r.status_code, code_of(r)) == (status, code), r.text
    assert world.guard.docs == before


@pytest.mark.parametrize("over,code", [
    ({"binding": dict(BINDING, release="other-api")}, "APPROVAL_BINDING_MISMATCH"),
    ({"binding": dict(BINDING, namespace="kube-system")}, "APPROVAL_BINDING_MISMATCH"),
    ({"project_id": "another-child"}, "APPROVAL_TARGET_MISMATCH"),
    ({"product_id": "other"}, "APPROVAL_TARGET_MISMATCH"),
    ({"action": "AGENT_ENGINE_DEPLOY",
      "binding": {"agent_name": "a", "display_name": "a", "source_digest": "f" * 64}}, "APPROVAL_ACTION_MISMATCH"),
])
def test_consume_request_for_another_action_or_target_is_refused(world, over, code):
    world.guard.docs["destructive_approvals/ap-1"] = approval()
    r = consume(world, **over)
    assert code_of(r) == code and world.guard.docs["destructive_approvals/ap-1"]["status"] == "APPROVED"


@pytest.mark.parametrize("over,status,code", [
    ({"action": "PROJECT_DECOMMISSION"}, 403, "APPROVAL_ACTION_NOT_CONSUMABLE"),
    ({"binding": {"cluster": "claims-gke"}}, 422, "INVALID_REQUEST"),
    ({"binding": dict(BINDING, extra="x")}, 422, "INVALID_REQUEST"),
    ({"binding": dict(BINDING, release="")}, 422, "INVALID_REQUEST"),
    ({"project_id": ""}, 422, "INVALID_REQUEST"),
])
def test_consume_malformed_requests_are_refused_before_any_read(world, over, status, code):
    world.guard.down = True   # never read
    r = consume(world, **over)
    assert (r.status_code, code_of(r)) == (status, code)


def test_consume_missing_record_is_404(world):
    r = consume(world, approval_id="nope")
    assert (r.status_code, code_of(r)) == (404, "APPROVAL_NOT_FOUND")


def test_consume_store_unavailable_is_503(world):
    world.guard.docs["destructive_approvals/ap-1"] = approval()
    world.guard.down = True
    r = consume(world)
    assert (r.status_code, code_of(r)) == (503, "APPROVAL_UNAVAILABLE")


@pytest.mark.parametrize("token,status,code", [
    ("cc-token", 403, "CALLER_NOT_ALLOWED"),   # the Control Center is not a consumer
    ("forged", 401, "UNAUTHENTICATED"),
    (None, 401, "UNAUTHENTICATED"),
])
def test_consume_wrong_caller_is_refused_and_nothing_is_consumed(world, token, status, code):
    world.guard.docs["destructive_approvals/ap-1"] = approval()
    r = consume(world, token=token)
    assert (r.status_code, code_of(r)) == (status, code)
    assert world.guard.docs["destructive_approvals/ap-1"]["status"] == "APPROVED"


def test_consume_caller_list_explicit_env_and_unconfigured(world, monkeypatch):
    world.guard.docs["destructive_approvals/ap-1"] = approval()
    monkeypatch.setenv(mcp_approvals.CONSUMERS_ENV, f.CC_SA)
    assert code_of(consume(world)) == "CALLER_NOT_ALLOWED"
    monkeypatch.delenv(mcp_approvals.CONSUMERS_ENV)
    monkeypatch.delenv("PROJECT_ID")
    r = consume(world)
    assert (r.status_code, code_of(r)) == (503, "CALLERS_UNCONFIGURED")
    assert world.guard.docs["destructive_approvals/ap-1"]["status"] == "APPROVED"


def test_consume_lost_race_after_commit_is_refused(world):
    """Another consumer's stamp is what the re-read finds (a concurrent commit after ours): never a fake success."""
    world.guard.docs["destructive_approvals/ap-1"] = approval()
    real_run = world.store._run_in_transaction

    def run_then_overwrite(body):
        real_run(body)
        world.guard.docs["destructive_approvals/ap-1"]["consumed_by"] = "someone-else@x.iam.gserviceaccount.com"

    world.store._run_in_transaction = run_then_overwrite
    r = consume(world)
    assert (r.status_code, code_of(r)) == (409, "APPROVAL_CONSUMED")


def test_consume_concurrent_callers_have_exactly_one_winner(world):
    world.guard.docs["destructive_approvals/ap-1"] = approval()
    world.store.lock = threading.Lock()
    results, start = [], threading.Barrier(6)

    def worker():
        start.wait()
        try:
            results.append(mcp_approvals.consume(
                world.store, "ap-1", action="HELM_UNINSTALL", product_id=PID, project_id=CHILD,
                binding=dict(BINDING), caller_email=CONSUMER, now=now())["status"])
        except mcp_approvals.ConsumeRefused as e:
            results.append(e.code)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["APPROVAL_CONSUMED"] * 5 + ["CONSUMED"]


def test_unrelated_vending_routes_keep_their_caller_checks(world):
    """Do No Harm: the MCP consumer's identity gains nothing on the destructive / lifecycle / tag / token routes,
    and those routes keep their own dependencies."""
    deps = {r.path: [d.call for d in r.dependant.dependencies] for r in VMAIN.app.routes if hasattr(r, "dependant")}
    # C10: decommission accepts DESTRUCTIVE_CALLERS plus the SANDBOX_TTL-only sweeper (verify_decommission_caller)
    assert VMAIN.verify_decommission_caller in deps["/projects/{product_id}/decommission"]
    assert VMAIN.verify_mcp_approval_consumer not in deps["/projects/{product_id}/decommission"]
    assert VMAIN.verify_destructive_caller in deps["/projects/{product_id}/lifecycle"]
    assert VMAIN.verify_destructive_caller in deps["/guard/managed-tag"]
    assert VMAIN.verify_github_token_caller in deps["/github-token"]
    assert deps["/approvals/{approval_id}/consume"] == [VMAIN.verify_mcp_approval_consumer]
    hdr = {"Authorization": "Bearer dev-token"}
    r = world.client.post(f"/projects/{PID}/decommission", json={"approval_id": "ap-1"}, headers=hdr)
    assert r.status_code in (403, 503) and r.json()["detail"]["code"] in ("CALLER_NOT_ALLOWED", "CALLERS_UNCONFIGURED")


# ============================================================================================ seam -> vending
class Poster:
    def __init__(self, answer=(200, None), exc=None):
        self.answer, self.exc, self.calls = answer, exc, []

    def __call__(self, url, body, headers, timeout):
        self.calls.append((url, copy.deepcopy(body), dict(headers)))
        if self.exc:
            raise self.exc
        status, payload = self.answer
        if status == 200 and payload is None:
            payload = {"status": "CONSUMED", "approval_id": "ap-1"}
        return status, payload


def seam_consume(post, **kw):
    args = dict(action="HELM_UNINSTALL", product_id=PID, project_id=CHILD, binding=dict(BINDING), post=post,
                id_token=lambda aud: f"token-for:{aud}")
    args.update(kw)
    return seam.consume_approval("ap-1", **args)


def test_seam_posts_to_vending_with_an_id_token_for_vendings_audience(monkeypatch):
    monkeypatch.setenv("VENDING_SERVICE_URL", AUD + "/")
    post = Poster()
    assert seam_consume(post)["status"] == "CONSUMED"
    (url, body, headers), = post.calls
    assert url == f"{AUD}/approvals/ap-1/consume"
    assert body == {"action": "HELM_UNINSTALL", "product_id": PID, "project_id": CHILD, "binding": BINDING}
    assert headers == {"Authorization": f"Bearer token-for:{AUD}"}
    assert "control-center" not in url and not hasattr(seam, "CONTROL_CENTER_SERVICE")


def test_seam_derives_the_vending_url_from_cloud_run_metadata(monkeypatch):
    monkeypatch.delenv("VENDING_SERVICE_URL", raising=False)
    monkeypatch.setenv("K_SERVICE", "mcp-kubernetes-server")
    meta = {"project/numeric-project-id": "424242", "instance/region": "projects/424242/regions/europe-west1"}
    post = Poster()
    seam_consume(post, metadata_get=lambda path: meta[path])
    assert post.calls[0][0] == "https://project-repo-vending-service-424242.europe-west1.run.app/approvals/ap-1/consume"
    assert post.calls[0][2]["Authorization"].endswith("https://project-repo-vending-service-424242.europe-west1.run.app")


@pytest.mark.parametrize("post,code", [
    (Poster(exc=ConnectionError("refused")), "APPROVAL_CONSUME_UNAVAILABLE"),
    (Poster((503, {"detail": {"code": "APPROVAL_UNAVAILABLE", "detail": "x"}})), "APPROVAL_CONSUME_UNAVAILABLE"),
    (Poster((502, None)), "APPROVAL_CONSUME_UNAVAILABLE"),
    (Poster((404, {"detail": "Not Found"})), "APPROVAL_CONSUME_UNAVAILABLE"),   # route not deployed yet
    (Poster((404, {"detail": {"code": "APPROVAL_NOT_FOUND", "detail": "ap-1"}})), "APPROVAL_NOT_FOUND"),
    (Poster((409, {"detail": {"code": "APPROVAL_CONSUMED", "detail": "x"}})), "APPROVAL_CONSUMED"),
    (Poster((403, {"detail": {"code": "APPROVAL_BINDING_MISMATCH", "detail": "x"}})), "APPROVAL_BINDING_MISMATCH"),
    (Poster((403, {"detail": {"code": "CALLER_NOT_ALLOWED", "detail": "x"}})), "CALLER_NOT_ALLOWED"),
    (Poster((422, {"detail": [{"msg": "field required"}]})), "APPROVAL_CONSUME_FAILED"),
    (Poster((200, {"status": "OK"})), "APPROVAL_CONSUME_FAILED"),                # never a fake success
    (Poster((200, {"status": "CONSUMED", "approval_id": "other"})), "APPROVAL_CONSUME_FAILED"),
])
def test_seam_fails_closed_with_typed_codes(monkeypatch, post, code):
    monkeypatch.setenv("VENDING_SERVICE_URL", AUD)
    with pytest.raises(seam.ApprovalRefused) as ei:
        seam_consume(post)
    assert ei.value.code == code


def test_seam_fails_closed_without_url_token_or_metadata(monkeypatch):
    monkeypatch.delenv("VENDING_SERVICE_URL", raising=False)
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("CLOUD_RUN_JOB", raising=False)
    post = Poster()
    with pytest.raises(seam.ApprovalRefused) as ei:
        seam_consume(post)
    assert ei.value.code == "APPROVAL_CONSUME_UNAVAILABLE" and post.calls == []
    monkeypatch.setenv("K_SERVICE", "mcp-kubernetes-server")

    def broken(path):
        raise RuntimeError("metadata down")

    with pytest.raises(seam.ApprovalRefused) as ei:
        seam_consume(post, metadata_get=broken)
    assert ei.value.code == "APPROVAL_CONSUME_UNAVAILABLE" and post.calls == []
    monkeypatch.setenv("VENDING_SERVICE_URL", AUD)

    def no_token(aud):
        raise RuntimeError("no ADC")

    with pytest.raises(seam.ApprovalRefused) as ei:
        seam_consume(post, id_token=no_token)
    assert ei.value.code == "APPROVAL_CONSUME_UNAVAILABLE" and post.calls == []


def test_seam_refuses_a_malformed_binding_before_any_call(monkeypatch):
    monkeypatch.setenv("VENDING_SERVICE_URL", AUD)
    post = Poster()
    for binding in ({"cluster": "c"}, dict(BINDING, release=""), dict(BINDING, extra="x"), None):
        with pytest.raises(seam.ApprovalRefused) as ei:
            seam_consume(post, binding=binding)
        assert ei.value.code == "APPROVAL_BINDING_INVALID"
    assert post.calls == []


def test_seam_local_check_without_binding_is_unchanged():
    """Do No Harm: check_approval without a binding applies exactly the earlier rules."""
    db = FakeDB()
    db.docs["destructive_approvals/ap-1"] = approval(binding=None, binding_digest=None)
    assert seam.check_approval(db, "ap-1", action="HELM_UNINSTALL", product_id=PID, project_id=CHILD)["status"] == \
        "APPROVED"
    with pytest.raises(seam.ApprovalRefused) as ei:
        seam.check_approval(db, "ap-1", action="HELM_UNINSTALL", product_id=PID, project_id=CHILD, binding=BINDING)
    assert ei.value.code == "APPROVAL_BINDING_MISMATCH"


def test_record_approval_request_is_idempotent_while_pending_and_new_once_decided():
    db = FakeDB()
    kw = dict(action="HELM_UNINSTALL", product_id=PID, project_id=CHILD, binding=BINDING,
              requested_by="mcp-kubernetes-server", reason="test", new_id=lambda: "abcdef1234")
    first = seam.record_approval_request(db, **kw)
    assert seam.record_approval_request(db, **kw) == first
    db.docs[f"approval_requests/{first}"]["status"] = "APPROVED"
    second = seam.record_approval_request(db, **kw)
    assert second == f"{first}-abcdef12" and db.docs[f"approval_requests/{second}"]["status"] == "PENDING"
    other = seam.record_approval_request(db, **dict(kw, binding=dict(BINDING, release="other")))
    assert other not in (first, second)
    db.down = True
    with pytest.raises(seam.ApprovalRefused) as ei:
        seam.record_approval_request(db, **dict(kw, binding=dict(BINDING, release="third")))
    assert ei.value.code == "APPROVAL_REQUEST_NOT_RECORDED"


# ============================================================================================ parity
def test_binding_table_and_digest_agree_in_seam_cc_and_vending():
    copies = {n: open(p, "rb").read() for n, p in SEAM_PATHS.items()}
    assert len(set(copies.values())) == 1
    assert seam.MCP_ACTION_BINDING_KEYS == da.MCP_ACTION_BINDING_KEYS == mcp_approvals.MCP_ACTION_BINDING_KEYS
    for b in (BINDING, {"datastore_id": "ds-x", "location": "us", "content_type": "WEBSITE"},
              {"agent_name": "a", "display_name": "Ä é", "source_digest": "f" * 64}):
        assert seam.binding_digest(b) == da.binding_digest(b) == mcp_approvals.binding_digest(b)
        assert seam.binding_digest(dict(reversed(list(b.items())))) == seam.binding_digest(b)


# ============================================================================================ Control Center card
def human(role=UserRole.ADMIN, method="session", email=ADMIN):
    return SimpleNamespace(state=SimpleNamespace(user_email=email, user_role=role, auth_method=method,
                                                 token_audience="", assigned_workloads=[PID]),
                           headers={}, path_params={"approval_id": "mcp-req-1"})


def card(w, **over):
    rec = {"approval_id": "mcp-req-1", "approval_type": "MCP_ACTION", "status": "PENDING", "product_id": PID,
           "trace_id": "", "mcp_action": "HELM_UNINSTALL", "mcp_project_id": CHILD, "mcp_binding": dict(BINDING),
           "mcp_binding_digest": seam.binding_digest(BINDING), "mcp_requested_by": "mcp-kubernetes-server",
           "reason": "drift", "requested_at": now().isoformat()}
    rec.update(over)
    w.db.docs["approval_requests/mcp-req-1"] = rec
    return rec


def decide(request, decision=ApprovalStatus.APPROVED, seen=None, card_id="mcp-req-1", db=None):
    """Decides as the dashboard does: echoing the action and fingerprint of the card as displayed (`seen`; default:
    what the CC's view shows for the card as stored now)."""
    if seen is None and db is not None:
        seen = shown(db, card_id)
    with patch.object(appr_routes, "verify_workload_access", return_value=True):
        return appr_routes.decide_approval_request(
            card_id, ApprovalDecisionRequest(decision=decision, **(seen or {})), request)


def shown(db, card_id="mcp-req-1"):
    """What the dashboard echoes: the action and the fingerprint the CC's view computed (absent when malformed)."""
    view = appr_routes._mcp_action_view(db.docs.get(f"approval_requests/{card_id}") or {}, ApprovalType.MCP_ACTION)
    return {"mcp_action": view.get("mcp_action"), "mcp_binding_digest": view.get("mcp_binding_digest")}


def minted(w):
    return {k.split("/", 1)[1]: v for k, v in w.guard.docs.items() if k.startswith("destructive_approvals/")}


def test_admin_approve_mints_a_bound_single_use_approval(world):
    card(world)
    res = decide(human(), db=world.db)
    assert res.status == ApprovalStatus.APPROVED and res.approval_type == ApprovalType.MCP_ACTION
    [(aid, rec)] = minted(world).items()
    assert res.mcp_approval_id == aid and res.mcp_binding == BINDING and res.mcp_action == "HELM_UNINSTALL"
    assert (rec["action"], rec["product_id"], rec["project_id"], rec["project_number"]) == (
        "HELM_UNINSTALL", PID, CHILD, NUMBER)
    assert rec["binding"] == BINDING and rec["binding_digest"] == seam.binding_digest(BINDING)
    assert (rec["principal_type"], rec["approved_by"], rec["approved_by_role"], rec["request_id"]) == (
        "USER", ADMIN, "ADMIN", "mcp-req-1")
    assert datetime.fromisoformat(rec["expires_at"]) - datetime.fromisoformat(rec["approved_at"]) == \
        timedelta(minutes=15)
    stored = world.db.docs["approval_requests/mcp-req-1"]
    assert stored["status"] == "APPROVED" and stored["mcp_approval_expires_at"] == rec["expires_at"]
    # RT F2: the live id is never written to the default-database card (or its decision text)
    assert "mcp_approval_id" not in stored and aid not in str(stored)
    assert not [k for k in world.db.docs if k.startswith("destructive_approvals/")]  # guard DB only


def test_card_swapped_after_display_is_refused_and_mints_nothing(world):
    """RT F1: the card is rewritten (consistently) between the display and the click: 409, nothing minted, still
    decidable; deciding on the reloaded card then works."""
    card(world)
    seen = shown(world.db)
    evil = dict(BINDING, release="prod-ingress")
    world.db.docs["approval_requests/mcp-req-1"].update(mcp_binding=evil, mcp_binding_digest=seam.binding_digest(evil))
    for decision in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED):
        with pytest.raises(HTTPException) as ei:
            decide(human(), decision, seen=seen)
        assert ei.value.status_code == 409 and "APPROVAL_CARD_CHANGED" in str(ei.value.detail)
    assert minted(world) == {} and world.db.docs["approval_requests/mcp-req-1"]["status"] == "PENDING"
    for bad in ({}, {"mcp_action": "HELM_UNINSTALL"}, dict(seen, mcp_action="DATASTORE_CREATE")):
        with pytest.raises(HTTPException) as ei:
            decide(human(), seen=bad)
        assert "APPROVAL_CARD_CHANGED" in str(ei.value.detail)
    res = decide(human(), db=world.db)   # the reloaded card, decided as displayed
    assert minted(world)[res.mcp_approval_id]["binding"] == evil


def test_list_shows_the_minted_id_to_administrators_only(world):
    card(world)
    aid = decide(human(), db=world.db).mcp_approval_id
    [admin_item] = [i for i in appr_routes.list_pending_approvals(human()) if i.approval_id == "mcp-req-1"]
    assert (admin_item.mcp_approval_id, admin_item.mcp_approval_status) == (aid, "APPROVED")
    [mgr_item] = [i for i in appr_routes.list_pending_approvals(human(role=UserRole.WORKLOAD_MANAGER))
                  if i.approval_id == "mcp-req-1"]
    assert mgr_item.mcp_approval_id is None and mgr_item.mcp_binding_digest == seam.binding_digest(BINDING)
    world.guard.down = True   # display only: a guard read failure shows no id, never an error
    [item] = [i for i in appr_routes.list_pending_approvals(human()) if i.approval_id == "mcp-req-1"]
    assert item.mcp_approval_id is None


def test_forged_card_id_field_is_never_shown(world):
    card(world, mcp_approval_id="forged-id", status="APPROVED")
    [item] = [i for i in appr_routes.list_pending_approvals(human()) if i.approval_id == "mcp-req-1"]
    assert item.mcp_approval_id is None


def test_card_details_are_typed(world):
    """RT F3: a forged card's untyped details are dropped, typed ones kept."""
    card(world, mcp_details={"requirements": "x", "source_uri": ["not", "a", "str"], "files": ["agent.py"],
                             "model_name": "gemini"})
    [item] = [i for i in appr_routes.list_pending_approvals(human()) if i.approval_id == "mcp-req-1"]
    assert item.mcp_details == {"model_name": "gemini"}
    card(world, mcp_details={"requirements": ["google-adk==1.0.0", "x" * 300], "source_uri": "gs://b/docs/"})
    [item] = [i for i in appr_routes.list_pending_approvals(human()) if i.approval_id == "mcp-req-1"]
    assert item.mcp_details == {"source_uri": "gs://b/docs/"}
    card(world, mcp_details={"requirements": ["google-adk==1.0.0"]})
    [item] = [i for i in appr_routes.list_pending_approvals(human()) if i.approval_id == "mcp-req-1"]
    assert item.mcp_details == {"requirements": ["google-adk==1.0.0"]}


@pytest.mark.parametrize("setup", ["host", "shared", "unset"])
def test_host_project_or_shared_project_mints_nothing(world, monkeypatch, setup):
    """RT F4: the seam's host-project and reverse-uniqueness rules apply before minting too."""
    if setup == "host":
        world.db.docs[f"workloads/{PID}"]["project_id"] = "mock-stackvend-project"
        card(world, mcp_project_id="mock-stackvend-project")
    else:
        card(world)
    if setup == "shared":
        world.db.docs["workloads/other"] = {"product_id": "other", "project_id": CHILD, "status": "ACTIVE"}
    if setup == "unset":
        monkeypatch.delenv("PROJECT_ID")
    with pytest.raises(HTTPException) as ei:
        decide(human(), db=world.db)
    assert ei.value.status_code == 409 and "APPROVAL_TARGET_UNKNOWN" in str(ei.value.detail)
    assert minted(world) == {} and world.db.docs["approval_requests/mcp-req-1"]["status"] == "PENDING"


def test_inactive_statuses_match_the_seam():
    assert appr_routes.MCP_INACTIVE_STATUSES == seam.INACTIVE_STATUSES


def test_a_failed_card_write_after_minting_is_logged(world, caplog):
    """RT F5: the minted id and the card id reach the ERROR log when the final card write fails."""
    card(world)
    real_set = _Doc.set

    def failing_set(self, data, merge=False):
        if self.path == "approval_requests/mcp-req-1" and data.get("status") == "APPROVED":
            raise RuntimeError("503")
        return real_set(self, data, merge)

    with patch.object(_Doc, "set", failing_set), caplog.at_level("ERROR"):
        with pytest.raises(Exception):
            decide(human(), db=world.db)
    [aid] = minted(world)
    assert any(aid in r.getMessage() and "mcp-req-1" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("request_", [
    human(role=UserRole.WORKLOAD_MANAGER),
    human(role=UserRole.VIEWER),
])
def test_only_an_admin_can_approve_and_the_card_stays_decidable(world, request_):
    card(world)
    with pytest.raises(HTTPException) as ei:
        decide(request_, db=world.db)
    assert ei.value.status_code == 403 and minted(world) == {}
    assert world.db.docs["approval_requests/mcp-req-1"]["status"] == "PENDING"


def test_a_bearer_cannot_approve(world):
    """The route policy APPROVAL refuses service credentials; and even past it, mint_approval needs a human."""
    card(world)
    bearer = human(method="bearer", email="sa-castor-finops@mock-stackvend-project.iam.gserviceaccount.com")
    route = next(r for r in appr_routes.router.routes if getattr(r, "path", "") == "/api/approvals/{approval_id}/decision")
    assert authz.policy_of(route).kind == "APPROVAL"
    with pytest.raises(HTTPException) as ei:
        authz._check(authz.policy_of(route), bearer)
    assert ei.value.status_code in (401, 403)
    with pytest.raises(HTTPException) as ei:
        decide(bearer, db=world.db)
    assert ei.value.status_code == 403 and "APPROVAL_NOT_HUMAN" in str(ei.value.detail)
    assert minted(world) == {} and world.db.docs["approval_requests/mcp-req-1"]["status"] == "PENDING"


@pytest.mark.parametrize("over,needle", [
    ({"mcp_project_id": "another-child"}, "APPROVAL_TARGET_MISMATCH"),
    ({"mcp_binding": dict(BINDING, release="other")}, "APPROVAL_CARD_MALFORMED"),     # digest no longer matches
    ({"mcp_binding": {"cluster": "c"}}, "APPROVAL_CARD_MALFORMED"),
    ({"mcp_action": "PROJECT_DECOMMISSION"}, "APPROVAL_CARD_MALFORMED"),
    ({"product_id": "platform"}, "APPROVAL_CARD_MALFORMED"),
    ({"product_id": "unknown-workload"}, "APPROVAL_TARGET_UNKNOWN"),
])
def test_stale_or_tampered_cards_mint_nothing(world, over, needle):
    card(world, **over)
    with pytest.raises(HTTPException) as ei:
        decide(human(), db=world.db)
    assert ei.value.status_code == 409 and needle in str(ei.value.detail)
    assert minted(world) == {} and world.db.docs["approval_requests/mcp-req-1"]["status"] == "PENDING"


def test_inactive_or_platform_workload_mints_nothing(world):
    card(world)
    world.db.docs[f"workloads/{PID}"]["status"] = "DECOMMISSIONED"
    with pytest.raises(HTTPException) as ei:
        decide(human(), db=world.db)
    assert ei.value.status_code == 409 and minted(world) == {}


def test_reject_records_the_denial_and_mints_nothing(world):
    card(world)
    res = decide(human(), ApprovalStatus.REJECTED, db=world.db)
    assert res.status == ApprovalStatus.REJECTED and minted(world) == {}
    assert world.db.docs["approval_requests/mcp-req-1"]["status"] == "REJECTED"
    with pytest.raises(HTTPException) as ei:
        decide(human(), ApprovalStatus.REWORK, db=world.db)
    assert ei.value.status_code == 409   # decided cards are not decidable again


def test_list_shows_the_card_target(world):
    card(world)
    [item] = [i for i in appr_routes.list_pending_approvals(human()) if i.approval_id == "mcp-req-1"]
    assert (item.approval_type, item.mcp_action, item.mcp_project_id, item.mcp_binding) == (
        ApprovalType.MCP_ACTION, "HELM_UNINSTALL", CHILD, BINDING)


def test_mint_approval_binding_rules_keep_decommission_records_unchanged(world):
    req = human()
    aid = da.mint_approval(req, action=da.PROJECT_DECOMMISSION, product_id=PID, project_id=CHILD,
                           project_number=NUMBER)
    rec = world.guard.docs[f"destructive_approvals/{aid}"]
    assert not {"binding", "binding_digest", "request_id"} & set(rec)
    with pytest.raises(da.MintRefused) as ei:
        da.mint_approval(req, action=da.PROJECT_DECOMMISSION, product_id=PID, project_id=CHILD,
                         project_number=NUMBER, binding=BINDING)
    assert ei.value.code == "APPROVAL_BINDING_INVALID"
    with pytest.raises(da.MintRefused) as ei:
        da.mint_approval(req, action="HELM_UNINSTALL", product_id=PID, project_id=CHILD, project_number=NUMBER)
    assert ei.value.code == "APPROVAL_BINDING_INVALID"


# ============================================================================================ end to end (Helm)
class Runner:
    def __init__(self):
        self.calls = []

    def binary(self):
        return "/usr/local/bin/helm"

    def __call__(self, args, access, values=None, registry_host=None):
        self.calls.append(list(args))
        return 0, "", ""


def test_helm_request_approve_consume_end_to_end(world):
    def post(url, body, headers, timeout):
        assert url.startswith(AUD + "/approvals/")
        r = world.client.post(url[len(AUD):], json=body, headers={"Authorization": headers["Authorization"]})
        return r.status_code, r.json()

    def consumer(approval_id, **kw):
        return seam.consume_approval(approval_id, post=post, id_token=lambda aud: "dev-token", **kw)

    runner = Runner()
    svc = helm.HelmService(
        db_factory=lambda: world.db, guard_db_factory=lambda: world.guard,
        cluster_access=lambda p, c, l: (helm.ClusterAccess("https://10.0.0.1", "tok", "Y2E="), {"location": l}),
        runner=runner, approval_consumer=consumer, env={"PROJECT_ID": "mock-stackvend-project"}, clock=now)
    args = dict(product_id=PID, cluster_name="claims-gke", location="us-east4-b", namespace="claims",
                release="claims-api")

    # 1. no approval -> an MCP_ACTION card, nothing uninstalled
    with pytest.raises(helm.HelmRefused) as ei:
        svc.uninstall(**args, approval_id=None)
    request_id = ei.value.extra["approval_request_id"]
    assert ei.value.code == "REFUSED:APPROVAL_REQUIRED" and runner.calls == []

    # 2. a human administrator approves the card in the Control Center
    decided = decide(human(), card_id=request_id, db=world.db)
    approval_id = decided.mcp_approval_id
    assert approval_id and "mcp_approval_id" not in world.db.docs[f"approval_requests/{request_id}"]
    assert world.guard.docs[f"destructive_approvals/{approval_id}"]["binding"] == BINDING

    # 3. the approval does not fit another release
    with pytest.raises(helm.HelmRefused) as ei:
        svc.uninstall(**dict(args, release="other-api"), approval_id=approval_id)
    assert ei.value.code == "REFUSED:APPROVAL_BINDING_MISMATCH" and runner.calls == []

    # 4. consumed through vending, then the uninstall runs
    res = svc.uninstall(**args, approval_id=approval_id)
    assert res["status"] == "UNINSTALLED" and runner.calls == [["uninstall", "claims-api", "--namespace", "claims",
                                                               "--wait"]]
    rec = world.guard.docs[f"destructive_approvals/{approval_id}"]
    assert rec["status"] == "CONSUMED" and rec["consumed_by"] == CONSUMER

    # 5. replay: refused locally, and vending refuses a direct second consume too
    with pytest.raises(helm.HelmRefused) as ei:
        svc.uninstall(**args, approval_id=approval_id)
    assert ei.value.code == "REFUSED:APPROVAL_CONSUMED" and len(runner.calls) == 1
    with pytest.raises(seam.ApprovalRefused) as ei:
        consumer(approval_id, action="HELM_UNINSTALL", product_id=PID, project_id=CHILD, binding=BINDING)
    assert ei.value.code == "APPROVAL_CONSUMED"


def test_helm_uninstall_fails_closed_when_vending_is_unreachable(world):
    world.guard.docs["destructive_approvals/ap-1"] = approval()

    def unreachable(url, body, headers, timeout):
        raise ConnectionError("connection refused")

    runner = Runner()
    svc = helm.HelmService(
        db_factory=lambda: world.db, guard_db_factory=lambda: world.guard,
        cluster_access=lambda p, c, l: (helm.ClusterAccess("https://10.0.0.1", "tok", "Y2E="), {"location": l}),
        runner=runner, env={"PROJECT_ID": "mock-stackvend-project"}, clock=now,
        approval_consumer=lambda a, **kw: seam.consume_approval(a, post=unreachable, id_token=lambda aud: "t", **kw))
    with pytest.raises(helm.HelmRefused) as ei:
        svc.uninstall(product_id=PID, cluster_name="claims-gke", location="us-east4-b", namespace="claims",
                      release="claims-api", approval_id="ap-1")
    assert (ei.value.code, ei.value.http_status) == ("REFUSED:APPROVAL_CONSUME_UNAVAILABLE", 503)
    assert runner.calls == [] and world.guard.docs["destructive_approvals/ap-1"]["status"] == "APPROVED"


def test_two_step_swap_digest_first_then_binding_is_refused(world):
    """RT N1: the attacker first plants its digest on the card (the admin sees the legitimate arguments), then swaps
    the arguments after display. The echoed fingerprint is the CC's digest of what was shown, so the click is
    refused and nothing is minted."""
    evil = dict(BINDING, release="prod-ingress")
    card(world, mcp_binding_digest=seam.binding_digest(evil))          # step 1: (B_legit, D_evil)
    seen = shown(world.db)
    assert seen["mcp_binding_digest"] == seam.binding_digest(BINDING)   # the fingerprint is of what is displayed
    world.db.docs["approval_requests/mcp-req-1"]["mcp_binding"] = evil  # step 2: arguments swapped after display
    with pytest.raises(HTTPException) as ei:
        decide(human(), seen=seen)
    assert ei.value.status_code == 409 and "APPROVAL_CARD_CHANGED" in str(ei.value.detail)
    assert minted(world) == {} and world.db.docs["approval_requests/mcp-req-1"]["status"] == "PENDING"


def test_planted_digest_without_swap_mints_nothing(world):
    card(world, mcp_binding_digest="0" * 64)   # displayed arguments are fine, the stored digest is not
    with pytest.raises(HTTPException) as ei:
        decide(human(), db=world.db)
    assert "APPROVAL_CARD_MALFORMED" in str(ei.value.detail) and minted(world) == {}


def test_unchanged_card_mints_with_the_echoed_fingerprint(world):
    card(world)
    seen = shown(world.db)
    res = decide(human(), seen=seen)
    assert minted(world)[res.mcp_approval_id]["binding_digest"] == seen["mcp_binding_digest"]


@pytest.mark.parametrize("over", [{"mcp_binding": {"cluster": "c"}}, {"mcp_action": "PROJECT_DECOMMISSION"},
                                  {"mcp_binding": None, "mcp_binding_digest": None}])
def test_malformed_card_is_rejectable_but_not_approvable(world, over):
    card(world, **over)
    view = appr_routes._mcp_action_view(world.db.docs["approval_requests/mcp-req-1"], ApprovalType.MCP_ACTION)
    assert view["mcp_card_malformed"] is True and "mcp_binding_digest" not in view
    with pytest.raises(HTTPException) as ei:
        decide(human(), db=world.db)
    assert "APPROVAL_CARD_MALFORMED" in str(ei.value.detail) and minted(world) == {}
    res = decide(human(), ApprovalStatus.REJECTED, db=world.db)
    assert res.status == ApprovalStatus.REJECTED and minted(world) == {}


def test_card_without_a_stored_digest_can_be_rejected(world):
    """RT N2: a well-formed binding with no stored digest is not approvable, but the admin can clear it."""
    card(world, mcp_binding_digest=None)
    with pytest.raises(HTTPException) as ei:
        decide(human(), db=world.db)
    assert "APPROVAL_CARD_MALFORMED" in str(ei.value.detail)
    assert decide(human(), ApprovalStatus.REJECTED, db=world.db).status == ApprovalStatus.REJECTED
    assert minted(world) == {}
