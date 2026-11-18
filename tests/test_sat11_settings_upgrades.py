"""SAT-11 (FD-7C P3a + FD-4DA item 3) in the Control Center: Settings ▸ Upgrades.

FastAPI TestClient on the real `routes/platform_release.py` router with the authz dependency; Cloud Run, GitHub and
both Firestore databases are in-memory test doubles (no network).

- GET /api/settings/platform-version: record x running digests (RECORDED / NOT_RECORDED / NO_RECORD / NOT_DEPLOYED),
  mixed versions, SELFUP-STAMP-RETIRE (no stamp = unknown, fail closed; never "pending"), "Platform update pending" only
  when a stamp exists and differs, the Control Center's own release.json, history.
- Release source: ADMIN + human + sign-in younger than 15 minutes (behind IAP: refused), typed confirmation, strict
  model (GitHub names, branch rules, SSH keys parsed, RSA refused, at most 8, branch and unsigned sources refused),
  optimistic version, the setting and its never-trimmed change record in one batch, validate-on-read.
- GET /api/settings/platform-updates: releases incl. previews, manifest + guard for display, failures typed and never
  cached, an invalid source switches the check off.
- Upstream-sync switch: default off, ADMIN-only, the exact `gh variable set` command without a token.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(BASE_DIR, "apps", "control-center")
for _p in (BASE_DIR, CC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_saved_client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "sat11-test.apps.googleusercontent.com"
try:
    import auth as cc_auth  # noqa: E402
    import release_source as rsrc  # noqa: E402
    from routes import platform_release as pr  # noqa: E402
    from shared import release_manifest as rm  # noqa: E402
finally:
    if _saved_client_id is None:
        os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
    else:
        os.environ["GOOGLE_OAUTH_CLIENT_ID"] = _saved_client_id

PROJ = "mock-stackvend-project"
REGION = "us-central1"
ADMIN_EMAIL = "owner@example.com"
NOW = 2_000_000_000
D1 = "us-central1-docker.pkg.dev/p/r/a@sha256:" + "1" * 64
D2 = "us-central1-docker.pkg.dev/p/r/a@sha256:" + "2" * 64
C1, C2 = "a" * 40, "b" * 40


# ------------------------------------------------------------------------------------------------ Firestore double
class Snap:
    def __init__(self, data, update_time):
        self._d, self.exists, self.update_time = data, data is not None, update_time

    def to_dict(self):
        return json.loads(json.dumps(self._d)) if self._d is not None else None


class Ref:
    def __init__(self, db, path):
        self.db, self.path = db, path

    def collection(self, name):
        return Col(self.db, self.path + (name,))

    def get(self):
        return Snap(self.db.docs.get(self.path), self.db.times.get(self.path))

    def set(self, data, merge=False):
        self.db._write(self.path, {**(self.db.docs.get(self.path) or {}), **data} if merge else data)


class Col:
    def __init__(self, db, path):
        self.db, self.path = db, path

    def document(self, doc_id):
        return Ref(self.db, self.path + (doc_id,))


class Batch:
    def __init__(self, db):
        self.db, self.ops = db, []

    def set(self, ref, data):
        self.ops.append(("set", ref.path, data, None))

    def update(self, ref, data, option=None):
        self.ops.append(("update", ref.path, data, option))
        self.db.updates.append(dict(data))

    def create(self, ref, data):
        self.ops.append(("create", ref.path, data, None))

    def commit(self):
        if self.db.fail_commit:
            raise RuntimeError("commit refused")
        for op, path, data, option in self.ops:  # check everything first: all or nothing
            if op == "create" and path in self.db.docs:
                raise RuntimeError("already exists")
            if op == "update" and (path not in self.db.docs or (option and option != self.db.times.get(path))):
                raise RuntimeError("precondition failed")
        for op, path, data, _ in self.ops:
            self.db._write(path, _apply_update(self.db.docs.get(path, {}), data, self.db.ignore_delete)
                           if op == "update" else data)


def _apply_update(old, data, ignore_delete=False):
    """Firestore `update` semantics for top-level fields: values replace, DELETE_FIELD removes the named field."""
    from google.cloud.firestore_v1 import DELETE_FIELD
    from google.cloud.firestore_v1.field_path import FieldPath
    out = dict(old)
    for k, v in data.items():
        if v is DELETE_FIELD:
            if not ignore_delete:
                parts = FieldPath.from_api_repr(k).parts
                assert len(parts) == 1, k
                out.pop(parts[0], None)
            continue
        out[k] = v
    return out


class FakeDb:
    def __init__(self):
        self.docs, self.times, self.tick, self.fail_commit = {}, {}, 0, False
        self.ignore_delete = False  # True: behave like a merge that keeps unknown keys (the pre-fix save, review M1)
        self.updates = []  # every `update` payload committed, for the Do No Harm check

    def _write(self, path, data):
        self.tick += 1
        self.docs[path] = json.loads(json.dumps(data))
        self.times[path] = self.tick

    def collection(self, name):
        return Col(self, (name,))

    def batch(self):
        return Batch(self)

    def write_option(self, last_update_time=None):
        return last_update_time

    def under(self, *prefix):
        return {p: d for p, d in self.docs.items() if p[:len(prefix)] == prefix and len(p) == len(prefix) + 1}


# ------------------------------------------------------------------------------------------------ Cloud Run double
def run_v1(path):
    return f"https://{REGION}-run.googleapis.com/apis/{path}"


class FakeRun:
    def __init__(self, digests=None, missing=(), annotations=None, unreadable=()):
        self.digests = digests or {}
        self.missing, self.annotations, self.unreadable = set(missing), annotations or {}, set(unreadable)

    def __call__(self, url):
        for name, kind, _ in rm.COMPONENTS:
            if kind == "service" and url == run_v1(f"serving.knative.dev/v1/namespaces/{PROJ}/services/{name}"):
                if name in self.missing:
                    return 404, None
                if name in self.unreadable:
                    return 403, None
                ann = self.annotations if name == rm.CONTROL_CENTER_SERVICE else {}
                return 200, {"metadata": {"annotations": ann}, "status": {"latestReadyRevisionName": f"{name}-00001"}}
            if kind == "service" and url == run_v1(f"serving.knative.dev/v1/namespaces/{PROJ}/revisions/{name}-00001"):
                return 200, {"status": {"imageDigest": self.digests.get(name, D1)}}
            if kind == "job" and url == run_v1(f"run.googleapis.com/v1/namespaces/{PROJ}/jobs/{name}"):
                if name in self.missing:
                    return 404, None
                return 200, {"spec": {"template": {"spec": {"template": {"spec": {"containers": [
                    {"image": self.digests.get(name, D1)}]}}}}}}
        raise AssertionError(url)


def record(release="0.9.2", commit=C1, digest=D1, overrides=None):
    comps = {}
    for name, kind, _ in rm.COMPONENTS:
        comps[name] = {"kind": kind, "image_digest": digest, "revision": "", "release": release, "commit": commit,
                       "dirty": False, "source_repo": "acme/stackvend", "built_at": "t", "deployed_at": "t"}
    for name, kw in (overrides or {}).items():
        comps[name].update(kw)
    return {"schema_version": 1, "release": release, "commit": commit, "dirty": False, "source_repo": "acme/stackvend",
            "components": comps, "deployed_at": "t", "deployed_by": ADMIN_EMAIL, "deployer": "deploy-services",
            "run_id": "r1", "history": [{"deployed_at": "t", "release": release, "commit": commit,
                                         "components": sorted(comps), "deployed_by": ADMIN_EMAIL}]}


# ------------------------------------------------------------------------------------------------ GitHub double
class FakeGitHub:
    def __init__(self, releases=None, manifests=None, status=200, variables=None, write_status=201, branch_sha=None,
                 unreadable=()):
        self.releases, self.manifests, self.status = releases or [], manifests or {}, status
        self.unreadable = set(unreadable)
        self.variables, self.write_status, self.branch_sha, self.calls = variables, write_status, branch_sha, []

    def __call__(self, method, path, token="", body=None, accept=""):
        self.calls.append((method, path, token, body))
        if "/releases?" in path:
            return (self.status, self.releases) if self.status == 200 else (self.status, {"message": "x"})
        if "/contents/release-manifest.json" in path:
            tag = path.split("ref=")[1]
            return (200, self.manifests[tag].encode()) if tag in self.manifests else (404, None)
        if "/commits/" in path:
            return (200, {"sha": self.branch_sha}) if self.branch_sha else (404, None)
        if "/actions/variables" in path:
            if self.variables is None:
                return 403, None
            if method == "GET":
                name = path.rsplit("/", 1)[1]
                if name in self.unreadable:
                    return 500, None
                return (200, {"name": name, "value": self.variables[name]}) if name in self.variables else (404, None)
            if self.write_status in (200, 201, 204):
                self.variables[body["name"]] = body["value"]
            return self.write_status, None
        raise AssertionError(path)


def rel(tag, prerelease=False, draft=False):
    return {"tag_name": tag, "prerelease": prerelease, "draft": draft, "html_url": f"https://github.com/acme/sv/releases/{tag}",
            "body": "notes for " + tag, "published_at": "2026-11-01T00:00:00Z"}


def manifest(release, requires, minimum):
    return json.dumps({"schema_version": 1, "release": release, "requires_apply_sh": requires,
                       "min_platform_release": minimum})


# ------------------------------------------------------------------------------------------------ SSH keys
def _s(b):
    return struct.pack(">I", len(b)) + b


def ed25519_key(seed=b"k"):
    blob = _s(b"ssh-ed25519") + _s(hashlib.sha256(seed).digest())
    return "ssh-ed25519 " + base64.b64encode(blob).decode(), blob


def fp(blob):
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


# ------------------------------------------------------------------------------------------------ client
@pytest.fixture
def env(monkeypatch):
    state = {"db": FakeDb(), "guard": FakeDb(), "run": FakeRun(), "gh": FakeGitHub(), "token": ""}
    monkeypatch.setattr(pr, "PROJECT_ID", PROJ)
    monkeypatch.setattr(pr, "region_provider", lambda: REGION)
    monkeypatch.setattr(pr, "cloud_run_get_json", lambda url: state["run"](url))
    monkeypatch.setattr(pr, "github_request", lambda *a, **k: state["gh"](*a, **k))
    monkeypatch.setattr(pr, "github_token_provider", lambda: state["token"])
    monkeypatch.setattr(pr, "guard_db_provider", lambda: state["guard"])
    monkeypatch.setattr(pr, "get_db", lambda: state["db"])
    monkeypatch.setattr(pr, "clock", lambda: NOW)
    monkeypatch.setattr(pr.release_info, "current_release",
                        lambda: {"schema_version": 1, "release": "0.9.2", "commit": C1, "dirty": False,
                                 "built_at": "t", "source_repo": "acme/stackvend", "builder": "deploy-services"})
    monkeypatch.setenv("GITHUB_REPO", "acme/platform")
    pr._updates_cache.clear()
    return state


def client(role="ADMIN", method="session", issued=NOW - 60, email=ADMIN_EMAIL):
    app = FastAPI()

    @app.middleware("http")
    async def _auth(request: Request, call_next):
        request.state.user_email, request.state.user_role, request.state.auth_method = email, role, method
        request.state.session_issued_at = issued
        return await call_next(request)
    app.include_router(pr.router)
    return TestClient(app)


# ================================================================================================ platform version
def test_no_record_yet_everything_unknown_and_platform_unknown(env):
    body = client().get("/api/settings/platform-version").json()
    states = {c["name"]: c["state"] for c in body["components"]}
    assert set(states.values()) == {"NO_RECORD"} and body["record"] is None
    # SELFUP-STAMP-RETIRE (review BL-1): every install is stamped since FD-4DA-STAMP, so no stamp = unknown (fail
    # closed), never "the release candidate's release, assumed"
    assert body["platform"]["state"] == "UNKNOWN" and body["platform"]["release"] is None
    assert body["platform"]["text"].startswith("unknown (no platform stamp")
    assert body["platform"]["apply_where"].startswith("Run it from the root of the StackVend folder you installed")
    assert f"infra/platform/{PROJ}.tfvars" in body["platform"]["apply_where"]  # CC-APPLY-WHERE
    assert body["platform_update_pending"] is False  # never "pending" without a stamp
    assert body["control_center_build"]["release"] == "0.9.2"


def test_recorded_components_and_mixed_versions(env):
    env["db"].collection("system_config").document("platform_release").set(record())
    body = client().get("/api/settings/platform-version").json()
    assert {c["state"] for c in body["components"]} == {"RECORDED"}
    assert body["mixed"] is False and body["services_release"] == "0.9.2" and body["unknown"] == []
    assert body["record"]["deployed_by"] == ADMIN_EMAIL and len(body["history"]) == 1
    env["db"].collection("system_config").document("platform_release").set(
        record(overrides={"mcp-gcloud-server": {"release": "0.9.1", "commit": C2}}))
    body = client().get("/api/settings/platform-version").json()
    assert body["mixed"] is True and body["services_release"] is None
    assert {g["release"]: g["components"] for g in body["groups"]}["0.9.1"] == ["mcp-gcloud-server"]


def test_digest_cross_check_and_not_deployed(env):
    """A component whose running image is not the recorded one is never shown with the recorded release."""
    env["db"].collection("system_config").document("platform_release").set(record())
    env["run"] = FakeRun(digests={"mcp-gcloud-server": D2}, missing={"castor-git-server"})
    comps = {c["name"]: c for c in client().get("/api/settings/platform-version").json()["components"]}
    assert comps["mcp-gcloud-server"]["state"] == "NOT_RECORDED" and "release" not in comps["mcp-gcloud-server"]
    assert comps["mcp-gcloud-server"]["text"] == "unknown (not from a recorded deploy)"
    assert comps["castor-git-server"]["state"] == "NOT_DEPLOYED"
    assert comps["infra-rollback-job"]["state"] == "RECORDED"


def test_job_deployed_by_tag_is_its_own_state_never_recorded(env):
    """Review M4 (rework): a job image that is a tag (how the Cloud Build triggers deploy jobs) is IMAGE_BY_TAG, not an
    error and never RECORDED, even when the record holds the same string; digest jobs stay RECORDED (negative)."""
    tag = "us-central1-docker.pkg.dev/p/r/qa-sandbox-test-runner:" + "a" * 40
    env["db"].collection("system_config").document("platform_release").set(
        record(overrides={"infra-rollback-job": {"image_digest": tag}}))
    env["run"] = FakeRun(digests={"infra-rollback-job": tag})
    body = client().get("/api/settings/platform-version").json()
    row = {c["name"]: c for c in body["components"]}["infra-rollback-job"]
    assert row["state"] == "IMAGE_BY_TAG" and "release" not in row and row["image_tag"] == tag
    assert row["text"] == f"deployed by tag — digest not verifiable ({tag})" and "BAD_RESPONSE" not in row["text"]
    assert "infra-rollback-job" in body["unknown"] and body["services_release"] == "0.9.2"
    others = [c for c in body["components"] if c["name"] != "infra-rollback-job"]
    assert {c["state"] for c in others} == {"RECORDED"}


def test_job_with_a_malformed_image_is_unreadable(env):
    env["db"].collection("system_config").document("platform_release").set(record())
    env["run"] = FakeRun(digests={"infra-rollback-job": "img@sha256:short"})
    row = {c["name"]: c for c in client().get("/api/settings/platform-version").json()["components"]}[
        "infra-rollback-job"]
    assert row["state"] == "UNREADABLE" and "BAD_RESPONSE" in row["text"] and "release" not in row


def test_stamp_pending_only_when_a_stamp_exists_and_differs(env):
    env["db"].collection("system_config").document("platform_release").set(record(release="0.9.3"))
    env["run"] = FakeRun(annotations={rm.STAMP_RELEASE_ANNOTATION: "0.9.2", rm.STAMP_COMMIT_ANNOTATION: C2})
    body = client().get("/api/settings/platform-version").json()
    assert body["platform"]["state"] == "STAMPED" and body["platform_update_pending"] is True
    assert body["pending_text"] == "Platform update pending: run upgrade.sh"
    assert body["pending_direction"] == "PLATFORM_BEHIND"
    env["run"] = FakeRun(annotations={rm.STAMP_RELEASE_ANNOTATION: "0.9.3", rm.STAMP_COMMIT_ANNOTATION: C2})
    assert client().get("/api/settings/platform-version").json()["platform_update_pending"] is False
    env["run"] = FakeRun(unreadable={rm.CONTROL_CENTER_SERVICE})
    body = client().get("/api/settings/platform-version").json()
    assert body["platform"]["state"] == "UNKNOWN" and body["platform_update_pending"] is False


def test_platform_ahead_of_the_services_says_redeploy_the_services(env):
    """SAT-10 review: on a trigger install the platform stamp can be newer than the services; the card then says the
    services are behind (redeploy them), never "run upgrade.sh"."""
    env["db"].collection("system_config").document("platform_release").set(record(release="0.9.2"))
    env["run"] = FakeRun(annotations={rm.STAMP_RELEASE_ANNOTATION: "0.9.3", rm.STAMP_COMMIT_ANNOTATION: C2})
    body = client().get("/api/settings/platform-version").json()
    assert body["platform_update_pending"] is True and body["pending_direction"] == "SERVICES_BEHIND"
    assert body["pending_text"] == pr.SERVICES_BEHIND_TEXT and "upgrade.sh" not in body["pending_text"]


def test_pending_direction_never_guesses():
    assert pr.pending_direction("0.9.2", "0.9.3") == ("PLATFORM_BEHIND", pr.PENDING_TEXT)
    assert pr.pending_direction("1.0.0", "0.9.3") == ("SERVICES_BEHIND", pr.SERVICES_BEHIND_TEXT)
    assert pr.pending_direction("1.0.0-preview", "1.0.0")[0] == "PLATFORM_BEHIND"  # pre-release precedence
    for platform, services in (("0.9.2", "not-a-version"), (None, "0.9.2"), ("0.9.2+b1", "0.9.2+b2")):
        direction, text = pr.pending_direction(platform, services)
        assert direction == "DIFFERENT" and "upgrade.sh" not in text and "redeploy" not in text


def test_platform_version_is_admin_only(env):
    assert client(role="VIEWER").get("/api/settings/platform-version").status_code == 403
    assert client(role="WORKLOAD_MANAGER").get("/api/settings/upstream-sync").status_code == 403
    assert client(role="VIEWER").get("/api/settings/release-source").status_code == 403


# ================================================================================================ release source
def body(**kw):
    b = {"repository": "fork/stackvend", "follow": "TAGS", "branch": "", "allow_unsigned": False,
         "include_previews": True, "signers": [{"kind": "OFFICIAL"}], "expected_version": 0,
         "confirm_repository": "fork/stackvend", "confirm_key_suffixes": []}
    b.update(kw)
    return b


def test_default_source_is_official(env):
    s = client().get("/api/settings/release-source").json()
    assert s["valid"] and not s["stored"] and s["is_default"] and s["level"] == "OFFICIAL"
    assert s["line"] == f"Upgrades come from: {rm.OFFICIAL_RELEASE_REPOSITORY} · signed release tags · Official StackVend release key"
    assert s["include_previews"] is True


def test_change_needs_recent_sign_in(env):
    r = client(method="iap").put("/api/settings/release-source", json=body())
    assert r.status_code == 403 and r.json()["detail"]["code"] == "RECENT_SIGN_IN_UNAVAILABLE"
    r = client(issued=NOW - 16 * 60).put("/api/settings/release-source", json=body())
    assert r.status_code == 403 and r.json()["detail"]["code"] == "RECENT_SIGN_IN_REQUIRED"
    r = client(issued=None).put("/api/settings/release-source", json=body())
    assert r.status_code == 403
    r = client(method="bearer").put("/api/settings/release-source", json=body())
    assert r.status_code == 403  # a service principal is never accepted
    assert env["guard"].docs == {}


def test_change_needs_typed_confirmation(env):
    r = client().put("/api/settings/release-source", json=body(confirm_repository="fork/other"))
    assert r.status_code == 422 and r.json()["detail"]["code"] == "CONFIRMATION_REQUIRED"
    key, blob = ed25519_key()
    signers = [{"kind": "SSH_KEY", "principal": "fork release key", "public_key": key}]
    r = client().put("/api/settings/release-source", json=body(signers=signers))
    assert r.status_code == 422 and r.json()["detail"]["field"] == "confirm_key_suffixes"
    r = client().put("/api/settings/release-source", json=body(signers=signers, confirm_key_suffixes=[fp(blob)[-6:]]))
    assert r.status_code == 200, r.text
    assert r.json()["signers"][0]["added_by"] == ADMIN_EMAIL and r.json()["signers"][0]["added_at"]


def test_saved_with_a_never_trimmed_change_record(env):
    r = client().put("/api/settings/release-source", json=body())
    assert r.status_code == 200 and r.json()["changed"] and r.json()["level"] == "NOT_OFFICIAL"
    doc = env["guard"].docs[("platform_release_source", "current")]
    assert doc["repository"] == "fork/stackvend" and doc["version"] == 1 and doc["updated_by"] == ADMIN_EMAIL
    changes = env["guard"].under("platform_release_source", "current", "changes")
    assert len(changes) == 1
    ch = next(iter(changes.values()))
    assert ch["from"]["repository"] == rm.OFFICIAL_RELEASE_REPOSITORY and ch["to"]["repository"] == "fork/stackvend"
    assert ch["changed_by"] == ADMIN_EMAIL and ch["from_default"] is True
    # back to the official source: a second record, the first is kept
    r = client().put("/api/settings/release-source", json=body(repository=rm.OFFICIAL_RELEASE_REPOSITORY,
                                                              confirm_repository=rm.OFFICIAL_RELEASE_REPOSITORY,
                                                              expected_version=1))
    assert r.status_code == 200 and r.json()["is_default"]
    assert len(env["guard"].under("platform_release_source", "current", "changes")) == 2
    # nothing changed: no write, no record
    r = client().put("/api/settings/release-source", json=body(repository=rm.OFFICIAL_RELEASE_REPOSITORY,
                                                              confirm_repository=rm.OFFICIAL_RELEASE_REPOSITORY,
                                                              expected_version=2))
    assert r.status_code == 200 and r.json()["changed"] is False
    assert len(env["guard"].under("platform_release_source", "current", "changes")) == 2


def test_stale_version_and_failed_batch_save_nothing(env):
    r = client().put("/api/settings/release-source", json=body(expected_version=3))
    assert r.status_code == 409 and r.json()["detail"]["code"] == "RELEASE_SOURCE_CHANGED"
    env["guard"].fail_commit = True
    r = client().put("/api/settings/release-source", json=body())
    assert r.status_code == 409 and r.json()["detail"]["code"] == "RELEASE_SOURCE_NOT_SAVED"
    assert env["guard"].docs == {}  # neither the setting nor its record


@pytest.mark.parametrize("kw,code", [
    ({"repository": "not/a/repo", "confirm_repository": "not/a/repo"}, "INVALID_REPOSITORY"),
    ({"follow": "BRANCH", "branch": "main"}, "BRANCH_REQUIRES_DEVELOPER_MODE"),
    ({"allow_unsigned": True}, "UNSIGNED_REQUIRES_BRANCH"),
    ({"signers": []}, "NO_SIGNERS"),
    ({"signers": [{"kind": "OFFICIAL"}, {"kind": "OFFICIAL"}]}, "DUPLICATE_SIGNER"),
    ({"signers": [{"kind": "SSH_KEY", "public_key": "ssh-rsa AAAAB3NzaC1yc2E="}]}, "RSA_REFUSED"),
    ({"signers": [{"kind": "GPG"}]}, "INVALID_SIGNERS"),
    ({"branch": "main"}, "INVALID_BRANCH"),
])
def test_invalid_settings_are_refused(env, kw, code):
    r = client().put("/api/settings/release-source", json=body(**kw))
    assert r.status_code == 422 and r.json()["detail"]["code"] == code, r.text
    assert env["guard"].docs == {}


def test_stored_branch_source_fails_typed_and_is_never_replaced(env):
    """A stored branch source (any older install) reads as RELEASE_SOURCE_INVALID: a typed error, never a fallback to
    the default source, and the update check is off; saving a valid source is the way out."""
    doc = rsrc.stored_document(rsrc.ReleaseSource("acme/sv", "BRANCH", "main", True, (), True), 3, "a", "t")
    with pytest.raises(rsrc.SourceError) as e:
        rsrc.read_stored(doc)
    assert e.value.code == "RELEASE_SOURCE_INVALID" and e.value.field == "follow"
    assert "BRANCH_REQUIRES_DEVELOPER_MODE" in e.value.message and "Developer mode" not in e.value.message
    env["guard"].collection("platform_release_source").document("current").set(doc)
    v = client().get("/api/settings/release-source").json()
    assert v["valid"] is False and v["update_check"] is False and v["error"]["code"] == "RELEASE_SOURCE_INVALID"
    assert env["guard"].collection("platform_release_source").document("current").get().to_dict()["follow"] == "BRANCH"


def test_stored_unsigned_flag_fails_typed(env):
    doc = rsrc.stored_document(rsrc.ReleaseSource("acme/sv", "TAGS", "", True, ({"kind": "OFFICIAL"},), True), 1, "a", "t")
    with pytest.raises(rsrc.SourceError) as e:
        rsrc.read_stored(doc)
    assert e.value.code == "RELEASE_SOURCE_INVALID" and "UNSIGNED_REQUIRES_BRANCH" in e.value.message


def test_nine_keys_refused(env):
    signers = [{"kind": "SSH_KEY", "public_key": ed25519_key(bytes([i]))[0]} for i in range(9)]
    r = client().put("/api/settings/release-source", json=body(signers=signers))
    assert r.json()["detail"]["code"] == "TOO_MANY_SIGNERS"


def test_invalid_stored_source_is_never_replaced_silently(env):
    env["guard"].collection("platform_release_source").document("current").set(
        {"repository": "x/y", "follow": "TAGS", "branch": "", "allow_unsigned": False, "signers": [{"kind": "OFFICIAL"}],
         "include_previews": True, "fingerprint": "sha256:wrong", "version": 4, "updated_by": "", "updated_at": ""})
    s = client().get("/api/settings/release-source").json()
    assert s["valid"] is False and s["level"] == "INVALID" and s["version"] == 4
    u = client().get("/api/settings/platform-updates").json()
    assert u["status"] == "SOURCE_INVALID" and env["gh"].calls == []
    r = client().put("/api/settings/release-source", json=body(expected_version=4))  # an admin repairs it
    assert r.status_code == 200
    ch = next(iter(env["guard"].under("platform_release_source", "current", "changes").values()))
    assert ch["from"] == {"invalid_stored_document": True}


def _valid_then_extra_keys(env, extra):
    r = client().put("/api/settings/release-source", json=body())
    assert r.status_code == 200, r.text
    path = ("platform_release_source", "current")
    env["guard"]._write(path, {**env["guard"].docs[path], **extra})
    s = client().get("/api/settings/release-source").json()
    assert s["valid"] is False and s["level"] == "INVALID" and s["version"] == 1
    return path


@pytest.mark.parametrize("extra", [{"extra": 1}, {"a.b": 2, "`odd`": 3}])
def test_invalid_stored_source_with_extra_keys_is_repaired(env, extra):
    """Review M1: a stored document invalid because of an unknown key is really repaired by a save (the unknown keys
    are deleted in the same write), so the next GET is valid."""
    path = _valid_then_extra_keys(env, extra)
    r = client().put("/api/settings/release-source", json=body(repository="fork/other", confirm_repository="fork/other",
                                                              expected_version=1))
    assert r.status_code == 200 and r.json()["changed"] is True, r.text
    assert set(env["guard"].docs[path]) == rsrc._STORED_FIELDS
    s = client().get("/api/settings/release-source").json()
    assert s["valid"] is True and s["repository"] == "fork/other" and s["version"] == 2
    assert len(env["guard"].under("platform_release_source", "current", "changes")) == 2


def test_save_that_leaves_the_source_invalid_is_refused(env):
    """Review M1: never a 200 `changed: true` while the stored document is still invalid (a store that keeps the
    unknown key answers a typed 500)."""
    _valid_then_extra_keys(env, {"extra": 1})
    env["guard"].ignore_delete = True
    r = client().put("/api/settings/release-source", json=body(repository="fork/other", confirm_repository="fork/other",
                                                              expected_version=1))
    assert r.status_code == 500 and r.json()["detail"]["code"] == "RELEASE_SOURCE_STILL_INVALID"
    assert client().get("/api/settings/release-source").json()["valid"] is False


def test_saving_over_a_valid_source_writes_exactly_the_model(env):
    """Negative (Do No Harm, M1): over a valid stored document the update payload is exactly the stored model (no
    field deletes), as before."""
    client().put("/api/settings/release-source", json=body())
    r = client().put("/api/settings/release-source", json=body(repository="fork/other", confirm_repository="fork/other",
                                                              expected_version=1))
    assert r.status_code == 200 and r.json()["changed"] is True
    assert len(env["guard"].updates) == 1
    payload = env["guard"].updates[0]
    assert set(payload) == rsrc._STORED_FIELDS and payload == env["guard"].docs[("platform_release_source", "current")]
    stored = {"repository": "x/y", "version": 3}
    assert pr._replace_fields(stored, dict(stored)) == stored and pr._replace_fields(stored, None) == stored


# ------------------------------------------------------------------------------------------------ model units
def test_ssh_key_parsing():
    key, blob = ed25519_key()
    assert rsrc.parse_ssh_public_key(key + " me@host")["fingerprint_sha256"] == fp(blob)
    wrong_inner = base64.b64encode(_s(b"ecdsa-sha2-nistp256") + _s(b"x" * 32)).decode()
    with pytest.raises(rsrc.SourceError) as e:
        rsrc.parse_ssh_public_key("ssh-ed25519 " + wrong_inner)
    assert e.value.code == "KEY_TYPE_MISMATCH"
    for bad in ("ssh-ed25519 !!!", "ssh-ed25519 " + base64.b64encode(_s(b"ssh-ed25519") + _s(b"short")).decode(),
                "ssh-ed25519 " + base64.b64encode(blob + b"x").decode(), "ssh-dss AAAA", ""):
        with pytest.raises(rsrc.SourceError):
            rsrc.parse_ssh_public_key(bad)
    point = b"\x04" + b"\x01" * 64
    ec = _s(b"ecdsa-sha2-nistp256") + _s(b"nistp256") + _s(point)
    assert rsrc.parse_ssh_public_key("ecdsa-sha2-nistp256 " + base64.b64encode(ec).decode())["key_type"] == "ecdsa-sha2-nistp256"
    sk = _s(b"sk-ssh-ed25519@openssh.com") + _s(b"k" * 32) + _s(b"ssh:")
    assert rsrc.parse_ssh_public_key("sk-ssh-ed25519@openssh.com " + base64.b64encode(sk).decode())
    with pytest.raises(rsrc.SourceError):  # a security key names its application
        rsrc.parse_ssh_public_key("sk-ssh-ed25519@openssh.com " + base64.b64encode(_s(b"sk-ssh-ed25519@openssh.com") + _s(b"k" * 32)).decode())


@pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="ssh-keygen not installed")
def test_fingerprint_matches_ssh_keygen(tmp_path):
    keyfile = tmp_path / "k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "t", "-f", str(keyfile)], check=True)
    pub = (tmp_path / "k.pub").read_text()
    out = subprocess.run(["ssh-keygen", "-l", "-E", "sha256", "-f", str(tmp_path / "k.pub")], capture_output=True,
                         text=True, check=True).stdout.split()[1]
    assert rsrc.parse_ssh_public_key(pub)["fingerprint_sha256"] == out


def test_fingerprint_is_canonical_and_covers_decision_fields():
    a = rsrc.default_source()
    b = rsrc.ReleaseSource(a.repository, a.follow, a.branch, a.allow_unsigned, a.signers, False)
    assert a.fingerprint == b.fingerprint  # the channel is not a trust decision
    c = rsrc.ReleaseSource("fork/x", a.follow, a.branch, a.allow_unsigned, a.signers, True)
    assert c.fingerprint != a.fingerprint and not c.is_default


def test_session_issued_at_only_for_a_valid_token():
    token = cc_auth.create_session_token("a@example.com")
    assert abs(cc_auth.session_issued_at(token) - int(token.split(":")[1])) == 0
    assert cc_auth.session_issued_at(token[:-1] + ("0" if token[-1] != "0" else "1")) is None
    assert cc_auth.session_issued_at("junk") is None


# ================================================================================================ updates check
def test_updates_lists_newest_release_with_manifest_and_guard(env):
    env["gh"] = FakeGitHub(releases=[rel("v0.9.3-preview", prerelease=True), rel("v0.9.4", draft=True), rel("v0.9.1"),
                                     rel("not-a-tag")],
                           manifests={"v0.9.3-preview": manifest("0.9.3-preview", True, "0.9.3-preview")})
    u = client().get("/api/settings/platform-updates").json()
    assert u["status"] == "OK" and u["latest"]["tag"] == "v0.9.3-preview" and u["latest"]["prerelease"]
    assert u["update_available"] is True and u["installed"] == "0.9.2"
    assert u["manifest"]["requires_apply_sh"] is True
    # no platform stamp: unknown, fail closed (SELFUP-STAMP-RETIRE; it was NEEDS_APPLY_SH "assumed" before)
    assert u["guard"]["decision"] == rm.PLATFORM_STAMP_UNKNOWN and u["guard"]["assumed"] is False
    # review H-5: the terminal path is the shipped upgrade.sh (it verifies the signed tag), one line only
    assert u["steps"] == ["PROJECT_ID=<project> bash scripts/upgrade.sh v0.9.3-preview"] and "services_only" not in u
    assert env["gh"].calls[0][1] == f"/repos/{rm.OFFICIAL_RELEASE_REPOSITORY}/releases?per_page=50"
    env["run"] = FakeRun(annotations={rm.STAMP_RELEASE_ANNOTATION: "0.9.2", rm.STAMP_COMMIT_ANNOTATION: C1})
    u = client().get("/api/settings/platform-updates").json()
    assert u["guard"]["decision"] == rm.NEEDS_APPLY_SH and u["guard"]["assumed"] is False
    assert u["guard"]["platform_release"] == "0.9.2" and len(u["steps"]) == 1


def test_manual_steps_are_only_upgrade_sh_even_when_the_guard_allows(env):
    """Code review M-1: never an unverified services-only `deploy-services.sh` alternative, even when the guard (computed
    from a display-only manifest read from GitHub) says ALLOW; upgrade.sh verifies the signed tag."""
    env["run"] = FakeRun(annotations={rm.STAMP_RELEASE_ANNOTATION: "0.9.2", rm.STAMP_COMMIT_ANNOTATION: C1})
    env["gh"] = FakeGitHub(releases=[rel("v0.9.3")], manifests={"v0.9.3": manifest("0.9.3", False, "0.9.2")})
    u = client().get("/api/settings/platform-updates").json()
    assert u["guard"]["decision"] == rm.ALLOW and "services_only" not in u
    assert u["steps"] == ["PROJECT_ID=<project> bash scripts/upgrade.sh v0.9.3"]
    assert pr.manual_steps("v1.0.0") == ["PROJECT_ID=<project> bash scripts/upgrade.sh v1.0.0"]
    with open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8") as f:
        html = f.read()
    assert "services and jobs only" not in html.lower() and "services_only" not in html


def test_previews_can_be_excluded_and_manifest_errors_are_typed(env):
    env["guard"].collection("platform_release_source").document("current").set(rsrc.stored_document(
        rsrc.ReleaseSource("acme/sv", "TAGS", "", False, ({"kind": "OFFICIAL"},), False), 1, "a", "t"))
    env["gh"] = FakeGitHub(releases=[rel("v0.9.3-preview", prerelease=True), rel("v0.9.2")],
                           manifests={"v0.9.2": '{"schema_version": 9}'})
    u = client().get("/api/settings/platform-updates").json()
    assert u["latest"]["tag"] == "v0.9.2" and u["update_available"] is False
    assert u["manifest_error"]["code"] == "MANIFEST_UNSUPPORTED" and "guard" not in u
    assert env["gh"].calls[0][1].startswith("/repos/acme/sv/releases")  # the fork is what is listed
    env["gh"] = FakeGitHub(releases=[rel("v0.9.5")])
    u = client().get("/api/settings/platform-updates?force=true").json()
    assert u["manifest_error"]["code"] == "MANIFEST_MISSING"


def test_failures_are_typed_and_never_cached_success_is_cached(env):
    env["gh"] = FakeGitHub(status=403)
    u = client().get("/api/settings/platform-updates").json()
    assert u["status"] == "COULD_NOT_CHECK" and u["error_code"] == "GITHUB_RATE_LIMITED"
    env["gh"] = FakeGitHub(releases=[rel("v0.9.2")], manifests={"v0.9.2": manifest("0.9.2", False, "0.9.0-preview")})
    assert client().get("/api/settings/platform-updates").json()["status"] == "OK"  # retried at once
    n = len(env["gh"].calls)
    client().get("/api/settings/platform-updates")
    assert len(env["gh"].calls) == n  # cached
    client().get("/api/settings/platform-updates?force=true")
    assert len(env["gh"].calls) > n
    for status, code in ((429, "GITHUB_RATE_LIMITED"), (500, "GITHUB_ERROR"), (401, "GITHUB_ERROR")):
        env["gh"] = FakeGitHub(status=status)
        pr._updates_cache.clear()
        u = client().get("/api/settings/platform-updates").json()
        assert u["status"] == "COULD_NOT_CHECK" and u["error_code"] == code
        client().get("/api/settings/platform-updates")
        assert len(env["gh"].calls) == 2  # never cached: the next GET asks again


# ================================================================================================ SELFUP-NOTFOUND
def test_repository_not_found_is_a_plain_state_and_cached(env):
    """Owner 11-02 / review §4: the public release repository does not exist before the release; HTTP 404 is the
    typed state REPOSITORY_NOT_FOUND (not "Could not check"), cached for the hour like OK, `force` asks again."""
    env["gh"] = FakeGitHub(status=404)
    u = client().get("/api/settings/platform-updates").json()
    assert u["status"] == "REPOSITORY_NOT_FOUND" and "error_code" not in u and u["update_available"] is False
    assert u["repository"] == rm.OFFICIAL_RELEASE_REPOSITORY
    assert u["message"] == (f"The release repository {rm.OFFICIAL_RELEASE_REPOSITORY} is not published yet, or it is "
                            "private. Updates are manual until it is published; Settings checks again every hour.")
    assert u["steps"] == ["PROJECT_ID=<project> bash scripts/upgrade.sh <tag>"]
    assert len(env["gh"].calls) == 1  # no manifest read for a repository that is not there
    client().get("/api/settings/platform-updates")
    assert len(env["gh"].calls) == 1  # cached
    client().get("/api/settings/platform-updates?force=true")
    assert len(env["gh"].calls) == 2  # force bypasses the cache
    env["gh"] = FakeGitHub(releases=[rel("v0.9.2")])  # published meanwhile: a forced check sees it at once
    assert client().get("/api/settings/platform-updates?force=true").json()["status"] == "OK"


def test_no_releases_is_a_plain_state_and_cached(env):
    env["gh"] = FakeGitHub(releases=[])
    u = client().get("/api/settings/platform-updates").json()
    assert u["status"] == "NO_RELEASES" and u["latest"] is None and u["update_available"] is False
    assert u["message"] == f"{rm.OFFICIAL_RELEASE_REPOSITORY} has no release yet." and u["steps"]
    client().get("/api/settings/platform-updates")
    assert len(env["gh"].calls) == 1
    # releases that are not usable (drafts, non-release tags, previews hidden by the setting) are "no release" too
    _store(env, rsrc.stored_document(rsrc.ReleaseSource("acme/sv", "TAGS", "", False, ({"kind": "OFFICIAL"},), False),
                                     1, "a", "t"))
    env["gh"] = FakeGitHub(releases=[rel("v0.9.3", draft=True), rel("nightly"), rel("v0.9.4-rc.1", prerelease=True)])
    u = client().get("/api/settings/platform-updates?force=true").json()
    assert u["status"] == "NO_RELEASES"
    assert u["message"] == "acme/sv has no release yet. (Preview releases are hidden by the release source setting.)"


@pytest.mark.parametrize("mstatus,cached", [(500, False), (403, False), (404, True)])
def test_ok_with_a_failed_manifest_read_is_not_cached(env, mstatus, cached):
    """Code review L-4: an OK whose manifest read failed transiently (GITHUB_ERROR) is not cached; a missing manifest
    (MANIFEST_MISSING) is a stable answer and is."""
    gh = FakeGitHub(releases=[rel("v0.9.3")])

    def answer(method, path, token="", body=None, accept=""):
        if "/contents/release-manifest.json" in path:
            gh.calls.append((method, path, token, body))
            return mstatus, None
        return gh(method, path, token=token, body=body, accept=accept)
    env["gh"] = answer
    u = client().get("/api/settings/platform-updates").json()
    assert u["status"] == "OK" and u["manifest_error"]["code"] == ("MANIFEST_MISSING" if mstatus == 404 else "GITHUB_ERROR")
    n = len(gh.calls)
    client().get("/api/settings/platform-updates")
    assert (len(gh.calls) == n) is cached


def test_manifest_unreachable_is_not_cached(env):
    gh = FakeGitHub(releases=[rel("v0.9.3")])

    def answer(method, path, token="", body=None, accept=""):
        if "/contents/release-manifest.json" in path:
            gh.calls.append((method, path))
            raise OSError("network down")
        return gh(method, path, token=token, body=body, accept=accept)
    env["gh"] = answer
    assert client().get("/api/settings/platform-updates").json()["manifest_error"]["code"] == "GITHUB_UNREACHABLE"
    n = len(gh.calls)
    client().get("/api/settings/platform-updates")
    assert len(gh.calls) > n


def test_dashboard_copy_and_invalid_source_guard():
    """Code review L-2 / L-3: the switch text claims no GitHub call from this tab only (the VCS integration still
    calls GitHub); the version card's grey line is shown only for a valid source that is off."""
    with open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8") as f:
        html = f.read()
    assert "Off: no GitHub call from this tab" in html and "no GitHub call at all" not in html
    assert ('x-show="upgrades.source && upgrades.source.valid && upgrades.source.update_check === false" '
            'class="text-xs text-slate-400">Update check off</p>') in html


def test_not_found_states_never_render_as_could_not_check():
    """The dashboard shows REPOSITORY_NOT_FOUND / NO_RELEASES / UPDATE_CHECK_OFF in the grey state style; the amber
    "Could not check" line excludes exactly those (and OK)."""
    with open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8") as f:
        html = f.read()
    amber = "upgrades.updates && !['OK', 'UPDATE_CHECK_OFF', 'REPOSITORY_NOT_FOUND', 'NO_RELEASES'].includes(" \
            "upgrades.updates.status)"
    assert amber in html and "'Could not check: '" in html
    assert "['REPOSITORY_NOT_FOUND', 'NO_RELEASES'].includes(upgrades.updates?.status)" in html
    assert "upgrades.updates?.status === 'UPDATE_CHECK_OFF'" in html
    assert set(pr.CACHED_STATUSES) == {"OK", "REPOSITORY_NOT_FOUND", "NO_RELEASES"}


def test_saving_the_source_clears_the_cache(env):
    env["gh"] = FakeGitHub(releases=[rel("v0.9.2")])
    client().get("/api/settings/platform-updates")
    assert pr._updates_cache
    client().put("/api/settings/release-source", json=body())
    assert not pr._updates_cache


# ================================================================================================ upstream sync (FD-4DA 3)
def test_sync_defaults_off_and_shows_the_command_without_a_token(env):
    s = client().get("/api/settings/upstream-sync").json()
    assert s["enabled"] is False and s["state"] == "NO_TOKEN"
    assert s["commands"]["enable"][0] == "gh variable set STACKVEND_UPSTREAM_SYNC --body true --repo acme/platform"
    r = client().put("/api/settings/upstream-sync", json={"enabled": True}).json()
    assert r["applied"] is False and r["code"] == "NO_TOKEN"
    assert r["commands"] == ["gh variable set STACKVEND_UPSTREAM_SYNC --body true --repo acme/platform",
                             f"gh variable set STACKVEND_UPSTREAM_REPO --body {rm.OFFICIAL_RELEASE_REPOSITORY} --repo acme/platform"]
    assert env["db"].docs[("governance", "upstream_sync")]["last_change"]["applied"] is False


def test_sync_sets_the_variable_with_a_token(env):
    env["token"] = "ghs_test"
    env["gh"] = FakeGitHub(variables={})
    assert client().get("/api/settings/upstream-sync").json()["enabled"] is False  # unset = off
    r = client().put("/api/settings/upstream-sync", json={"enabled": True}).json()
    assert r["applied"] is True and env["gh"].variables == {"STACKVEND_UPSTREAM_SYNC": "true"}
    assert ("POST", "/repos/acme/platform/actions/variables", "ghs_test",
            {"name": "STACKVEND_UPSTREAM_SYNC", "value": "true"}) in env["gh"].calls
    assert client().get("/api/settings/upstream-sync").json()["enabled"] is True
    r = client().put("/api/settings/upstream-sync", json={"enabled": False}).json()
    assert r["applied"] and env["gh"].variables["STACKVEND_UPSTREAM_SYNC"] == "false"
    assert any(c[0] == "PATCH" for c in env["gh"].calls)


UPSTREAM_CMD = f"gh variable set STACKVEND_UPSTREAM_REPO --body {rm.OFFICIAL_RELEASE_REPOSITORY} --repo acme/platform"


@pytest.mark.parametrize("variables,unreadable,code", [
    ({}, (), "UPSTREAM_REPO_NOT_SET"),
    ({"STACKVEND_UPSTREAM_REPO": ""}, (), "UPSTREAM_REPO_NOT_SET"),
    ({"STACKVEND_UPSTREAM_REPO": "not-a-slug"}, (), "UPSTREAM_REPO_NOT_SET"),
    ({"STACKVEND_UPSTREAM_REPO": "acme/platform"}, (), "UPSTREAM_REPO_IS_THIS_REPOSITORY"),
    ({}, ("STACKVEND_UPSTREAM_REPO",), "UPSTREAM_REPO_UNREADABLE"),
])
def test_sync_on_without_the_upstream_pointer_is_not_effective(env, variables, unreadable, code):
    """Review M2: the switch is set, but the workflow would skip: `effective: false`, a typed code and only the
    remaining command. The Control Center never writes STACKVEND_UPSTREAM_REPO itself."""
    env["token"] = "ghs_test"
    env["gh"] = FakeGitHub(variables=dict(variables), unreadable=unreadable)
    r = client().put("/api/settings/upstream-sync", json={"enabled": True}).json()
    assert r["applied"] is True and r["enabled"] is True and r["effective"] is False and r["code"] == code
    assert r["commands"] == [UPSTREAM_CMD] and "now on" not in r["message"]
    assert env["gh"].variables.get("STACKVEND_UPSTREAM_REPO") == variables.get("STACKVEND_UPSTREAM_REPO")
    assert not any(c[0] in ("POST", "PATCH") and c[3]["name"] == "STACKVEND_UPSTREAM_REPO" for c in env["gh"].calls)
    assert env["db"].docs[("governance", "upstream_sync")]["last_change"]["effective"] is False


def test_sync_on_with_the_upstream_pointer_is_effective(env):
    """Negative (M2): with a valid upstream pointer the answer is the same success as before, now `effective: true`."""
    env["token"] = "ghs_test"
    env["gh"] = FakeGitHub(variables={"STACKVEND_UPSTREAM_REPO": "example-org/stackvend"})
    r = client().put("/api/settings/upstream-sync", json={"enabled": True}).json()
    assert r["applied"] is True and r["effective"] is True and r["code"] == ""
    assert r["message"] == "Weekly auto-update from upstream is now on."
    assert r["commands"] == pr._sync_commands("acme/platform", True)
    r = client().put("/api/settings/upstream-sync", json={"enabled": False}).json()
    assert r["applied"] is True and r["effective"] is True and r["message"].endswith("now off.")
    assert env["gh"].variables == {"STACKVEND_UPSTREAM_REPO": "example-org/stackvend", "STACKVEND_UPSTREAM_SYNC": "false"}


def test_sync_token_without_the_right_shows_the_command(env):
    env["token"] = "ghs_test"
    env["gh"] = FakeGitHub(variables=None)  # 403 on every variables call
    r = client().put("/api/settings/upstream-sync", json={"enabled": True}).json()
    assert r["applied"] is False and r["code"] == "TOKEN_CANNOT_SET_VARIABLE" and r["commands"]


def test_sync_change_is_admin_and_human_only(env):
    assert client(role="VIEWER").put("/api/settings/upstream-sync", json={"enabled": True}).status_code == 403
    assert client(method="bearer").put("/api/settings/upstream-sync", json={"enabled": True}).status_code == 403
    assert env["db"].docs == {}


def test_sync_without_a_platform_repository(env, monkeypatch):
    monkeypatch.delenv("GITHUB_REPO", raising=False)
    s = client().get("/api/settings/upstream-sync").json()
    assert s["state"] == "REPOSITORY_NOT_CONFIGURED"
    assert s["commands"]["enable"][0].endswith("--repo <owner>/<repo>")


# ================================================================================================ P3a-OFF (SELFUP-OFF)
CURRENT_PATH = ("platform_release_source", "current")


def _raise(*_a, **_k):
    raise AssertionError("no GitHub call (and no GitHub token read) may happen while the update check is off")


def _switch(enabled, version=0, **kw):
    return client(**kw).put("/api/settings/update-check", json={"enabled": enabled, "expected_version": version})


def _store(env, doc):
    env["guard"].collection(CURRENT_PATH[0]).document(CURRENT_PATH[1]).set(doc)


def test_update_check_off_makes_no_github_call_and_does_not_touch_the_cache(env, monkeypatch):
    r = _switch(False)
    assert r.status_code == 200 and r.json()["changed"] is True, r.text
    assert r.json()["update_check"] is False and r.json()["is_default"] is True  # not a trust change
    doc = env["guard"].docs[CURRENT_PATH]
    assert set(doc) == rsrc._STORED_FIELDS and doc["update_check"] is False and doc["version"] == 1
    assert doc["fingerprint"] == rsrc.default_source().fingerprint  # the switch is not in the fingerprint
    ch = next(iter(env["guard"].under(*CURRENT_PATH, "changes").values()))
    assert ch["from"]["update_check"] is True and ch["to"]["update_check"] is False and ch["via"] == "control-center"
    assert ch["changed_by"] == ADMIN_EMAIL and ch["from_default"] is True

    monkeypatch.setattr(pr, "github_request", _raise)
    monkeypatch.setattr(pr, "github_token_provider", _raise)
    sentinel = {("k",): (1.0, {"status": "OK"})}
    pr._updates_cache.clear()
    pr._updates_cache.update(sentinel)
    for force in ("", "?force=true"):
        u = client().get("/api/settings/platform-updates" + force).json()
        assert u["status"] == "UPDATE_CHECK_OFF" and u["update_available"] is False
        assert u["manual_steps"] == ["PROJECT_ID=<project> bash scripts/upgrade.sh <tag>"]  # M-1: one verified path
        assert u["changed_by"] == ADMIN_EMAIL and u["changed_at"] and "platform" in u
        assert u["source"]["update_check"] is False
    assert pr._updates_cache == sentinel  # neither read into nor written

    s = client().get("/api/settings/upstream-sync").json()
    assert s["state"] == "UPDATE_CHECK_OFF" and s["enabled"] is False
    assert s["commands"]["enable"][0] == "gh variable set STACKVEND_UPSTREAM_SYNC --body true --repo acme/platform"
    y = client().put("/api/settings/upstream-sync", json={"enabled": True}).json()
    assert y["applied"] is False and y["code"] == "UPDATE_CHECK_OFF" and y["commands"]
    assert env["db"].docs[("governance", "upstream_sync")]["last_change"]["code"] == "UPDATE_CHECK_OFF"


def test_update_check_back_on_checks_again(env):
    assert _switch(False).status_code == 200
    r = _switch(True, version=1)
    assert r.status_code == 200 and r.json()["update_check"] is True and r.json()["version"] == 2
    env["gh"] = FakeGitHub(releases=[rel("v0.9.2")])
    assert client().get("/api/settings/platform-updates").json()["status"] == "OK" and env["gh"].calls
    changes = list(env["guard"].under(*CURRENT_PATH, "changes").values())
    assert sorted((c["from"]["update_check"], c["to"]["update_check"]) for c in changes) == [(False, True), (True, False)]


def test_update_check_needs_no_recent_sign_in_but_a_human_admin(env):
    # behind Identity-Aware Proxy (no sign-in time) and with an old session: allowed (plan §3.12)
    assert _switch(False, method="iap").status_code == 200
    assert _switch(True, version=1, issued=NOW - 3600).status_code == 200
    assert _switch(False, version=2, method="bearer").status_code == 403  # a service principal is never accepted
    assert _switch(False, version=2, role="VIEWER").status_code == 403
    assert _switch(False, version=2, role="WORKLOAD_MANAGER").status_code == 403
    assert env["guard"].docs[CURRENT_PATH]["update_check"] is True and env["guard"].docs[CURRENT_PATH]["version"] == 2


def test_update_check_stale_version_and_strict_body(env):
    r = _switch(False, version=3)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "RELEASE_SOURCE_CHANGED"
    for bad in ({"enabled": "false", "expected_version": 0}, {"enabled": 0, "expected_version": 0},
                {"enabled": False}, {"enabled": False, "expected_version": "0"}):
        assert client().put("/api/settings/update-check", json=bad).status_code == 422, bad
    env["guard"].fail_commit = True
    r = _switch(False)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "RELEASE_SOURCE_NOT_SAVED"
    assert env["guard"].docs == {}


def test_update_check_unchanged_writes_nothing(env):
    r = _switch(True)  # already on (default, nothing stored)
    assert r.status_code == 200 and r.json()["changed"] is False and env["guard"].docs == {}


def test_update_check_refused_while_the_stored_source_is_invalid(env, monkeypatch):
    _store(env, {**rsrc.stored_document(rsrc.default_source(), 4, "a", "t"), "extra": 1})
    monkeypatch.setattr(pr, "github_request", _raise)
    monkeypatch.setattr(pr, "github_token_provider", _raise)
    r = _switch(True, version=4)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "RELEASE_SOURCE_INVALID"
    assert client().get("/api/settings/platform-updates").json()["status"] == "SOURCE_INVALID"
    assert client().get("/api/settings/upstream-sync").json()["state"] == "SOURCE_INVALID"  # fail closed
    assert client().put("/api/settings/upstream-sync", json={"enabled": False}).json()["code"] == "SOURCE_INVALID"


def test_unreadable_guard_database_is_503_before_any_github_call(env, monkeypatch):
    monkeypatch.setattr(pr, "github_request", _raise)
    monkeypatch.setattr(pr, "github_token_provider", _raise)
    monkeypatch.setattr(pr, "guard_db_provider", lambda: None)
    for method, path, kw in (("get", "/api/settings/platform-updates", {}), ("get", "/api/settings/upstream-sync", {}),
                             ("put", "/api/settings/upstream-sync", {"json": {"enabled": True}}),
                             ("put", "/api/settings/update-check", {"json": {"enabled": False, "expected_version": 0}})):
        r = getattr(client(), method)(path, **kw)
        assert r.status_code == 503 and r.json()["detail"]["code"] == "GUARD_DATABASE_UNAVAILABLE", (path, r.text)

    class Broken:
        def collection(self, _name):
            raise RuntimeError("guard database down")
    monkeypatch.setattr(pr, "guard_db_provider", lambda: Broken())
    assert client().get("/api/settings/platform-updates").status_code == 503


def test_v1_stored_document_reads_on_and_valid(env):
    """Review H-3: a document saved before P3a-OFF (no `update_check` key) stays valid and means "on"."""
    v1 = rsrc.stored_document(rsrc.ReleaseSource("acme/sv", "TAGS", "", False, ({"kind": "OFFICIAL"},), True), 2, "a",
                              "t")
    v1.pop("update_check")
    assert set(v1) == rsrc._STORED_FIELDS_V1
    _store(env, v1)
    s = client().get("/api/settings/release-source").json()
    assert s["valid"] is True and s["update_check"] is True and s["repository"] == "acme/sv" and s["version"] == 2
    env["gh"] = FakeGitHub(releases=[rel("v0.9.2")])
    assert client().get("/api/settings/platform-updates").json()["status"] == "OK"
    r = _switch(False, version=2)  # a save writes v2 and keeps every other field
    assert r.status_code == 200 and r.json()["repository"] == "acme/sv"
    assert set(env["guard"].docs[CURRENT_PATH]) == rsrc._STORED_FIELDS


@pytest.mark.parametrize("value", ["off", "false", 0, 1, None, []])
def test_non_bool_update_check_is_invalid_and_fails_closed(env, monkeypatch, value):
    doc = rsrc.stored_document(rsrc.default_source(), 1, "a", "t")
    doc["update_check"] = value
    _store(env, doc)
    monkeypatch.setattr(pr, "github_request", _raise)
    s = client().get("/api/settings/release-source").json()
    assert s["valid"] is False and s["update_check"] is False
    assert client().get("/api/settings/platform-updates").json()["status"] == "SOURCE_INVALID"


def test_release_source_save_keeps_the_switch(env):
    """The release-source form does not carry the switch: saving it keeps the update check as it is."""
    assert _switch(False).status_code == 200
    r = client().put("/api/settings/release-source", json=body(expected_version=1))
    assert r.status_code == 200 and r.json()["changed"] is True and r.json()["update_check"] is False
    assert env["guard"].docs[CURRENT_PATH]["update_check"] is False


def test_plan_change_update_check_only():
    """Review M-7: a change of only the switch is a change (not None), needs no typed confirmation and keeps every
    other field; the fingerprint does not move. Any other change still needs the typed confirmation."""
    src = rsrc.default_source()
    plan = rsrc.plan_change(rsrc.update_check_request(src, False), None, None, 0, "a@x", "t", "", [], "cli")
    assert plan is not None and plan.new.update_check is False and plan.stored["update_check"] is False
    assert plan.new.fingerprint == src.fingerprint and plan.change["to"]["update_check"] is False
    off = plan.new
    assert rsrc.plan_change(rsrc.update_check_request(off, False), off, None, 1, "a@x", "t", off.repository, [],
                            "cli") is None  # unchanged (the routes answer "already so" before planning)
    with pytest.raises(rsrc.SourceError) as e:  # a new repository is still confirmed, switch or not
        rsrc.plan_change({**rsrc.update_check_request(off, True), "repository": "fork/x"}, off, None, 1, "a@x",
                         "t", "", [], "cli")
    assert e.value.code == "CONFIRMATION_REQUIRED"
    # without `update_check` in the request the value in force is kept
    req = rsrc.update_check_request(off, True)
    req.pop("update_check")
    kept = rsrc.plan_change({**req, "repository": "fork/y"}, off, None, 1, "a@x", "t", "fork/y", [], "cli")
    assert kept.new.update_check is False and kept.change["to"]["update_check"] is False
    with pytest.raises(rsrc.SourceError) as e:
        rsrc.validate_source({**rsrc.update_check_request(src, True), "update_check": "on"})
    assert e.value.code == "INVALID_UPDATE_CHECK"


def test_update_check_is_not_in_the_fingerprint():
    a = rsrc.default_source()
    b = rsrc.ReleaseSource(a.repository, a.follow, a.branch, a.allow_unsigned, a.signers, a.include_previews, False)
    assert a.fingerprint == b.fingerprint and b.is_default and b.level == "OFFICIAL"
    assert a.describe() == b.describe()  # the "Upgrades come from" line is unchanged by the switch
    assert b.describe_update_check().startswith("Update check: off")


# ================================================================================================ SAT-48 record state
def _own(monkeypatch, **doc):
    monkeypatch.setattr(pr.release_info, "current_release", lambda: dict(doc))


def test_sat48_no_record_and_an_unstamped_control_center_explains_why(env, monkeypatch):
    """A Control Center image with no version stamp: a plain, typed explanation instead of a bare "unknown"."""
    _own(monkeypatch, release="unknown", reason="no release.json in this build")
    body = client().get("/api/settings/platform-version").json()
    assert body["record_state"] == "NONE_UNSTAMPED"
    assert "no version stamp" in body["record_note"] and "deploy-services.sh" in body["record_note"]
    assert body["services_text"] == "not recorded yet"
    assert body["control_center_build_text"] == "unknown (no release.json in this build)"
    assert {c["text"] for c in body["components"]} == {"unknown (no recorded deploy yet)"}


def test_sat48_no_record_on_a_script_stamped_build(env):
    body = client().get("/api/settings/platform-version").json()  # env: own builder deploy-services
    assert body["record_state"] == "NONE" and "scripts/deploy-services.sh" in body["record_note"]


def test_sat48_recorded_and_unreadable_records_have_no_note(env, monkeypatch):
    env["db"].collection("system_config").document("platform_release").set(record())
    body = client().get("/api/settings/platform-version").json()
    assert (body["record_state"], body["record_note"], body["services_text"]) == ("RECORDED", "", "0.9.2")
    monkeypatch.setattr(pr, "_read_record", lambda: (None, "could not read the version record: Boom"))
    body = client().get("/api/settings/platform-version").json()
    assert (body["record_state"], body["record_note"]) == ("UNREADABLE", "")
    assert body["record_error"].startswith("could not read")


def test_sat48_same_release_from_several_commits(env):
    """A push-trigger install rebuilds only what a push changed: one release, several commits. Still `mixed` (the
    commits differ), but the line names the release instead of a bare "mixed"."""
    env["db"].collection("system_config").document("platform_release").set(
        record(overrides={"mcp-gcloud-server": {"commit": C2}}))
    body = client().get("/api/settings/platform-version").json()
    assert body["mixed"] is True and body["services_release"] is None
    assert body["services_text"] == "0.9.2 (components from 2 commits)"
    env["db"].collection("system_config").document("platform_release").set(
        record(overrides={"mcp-gcloud-server": {"release": "0.9.1", "commit": C2}}))
    assert client().get("/api/settings/platform-version").json()["services_text"] == "mixed"


def test_sat48_control_center_build_text():
    assert pr.control_center_build_text({"release": "unknown", "reason": "release.json is a symlink"}) == \
        "unknown (release.json is a symlink)"
    assert pr.control_center_build_text({"release": "0.9.2", "commit": "unknown", "dirty": False}) == "0.9.2"
    assert pr.control_center_build_text({"release": "0.9.2", "commit": C1, "dirty": True}) == f"0.9.2 ({C1[:12]}) +dirty"


def test_sat48_dashboard_renders_the_typed_texts():
    with open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8") as f:
        html = f.read()
    assert "upgrades.version.services_text ||" in html
    assert 'x-text="upgrades.version?.control_center_build_text || \'…\'"' in html
    assert 'x-show="upgrades.version?.record_note"' in html and 'x-text="upgrades.version?.record_note"' in html
    assert "deployed before version records" not in html
