"""FD-4AQ W2 (register AQ-3): each PUBLIC_APP workload gets ONE web key with the fixed id `stackvend-web`, limited to
the two Google sign-in APIs (mcp-servers/terraform/service.py `_resolve_workload_web_key`).

Before: the deploy listed the child's keys and used `keys[0]` (any key, e.g. Firebase's auto-created browser key),
else created "Castor <pid> Web Key" with NO restrictions, took the long-running operation's name as the key name
when `response` was absent and never polled the operation.

Now (AuthorizedSession REST, exact resource names): GET .../keys/stackvend-web; present -> compare its apiTargets and
PATCH only when they differ (other restriction kinds kept), polled; absent -> the old StackVend key (displayName
exactly "Castor <pid> Web Key") is restricted once and never used, then POST ?keyId=stackvend-web with the
restrictions, polled to done, the key name from response.name only. No other key is ever read.

Hermetic: a fake AuthorizedSession; httpx is never used here (invariant 7).
"""
import hermetic_guard  # noqa: F401  (first import)

import logging
import sys
import types
from unittest.mock import MagicMock

import pytest

from fd4g_support import load_tf_service

PID = "p-1"
PNUM = "424242"
PARENT = f"projects/{PNUM}/locations/global"
WEB = f"{PARENT}/keys/stackvend-web"
API = "https://apikeys.googleapis.com/v2"
KEY = "AIzaSy-fd4aq-w2-test-only-web-key-00000"         # test value, never a real key
OTHER = "AIzaSy-fd4aq-w2-test-only-foreign-key-000"     # test value: a key StackVend must never read
TARGETS = [{"service": "identitytoolkit.googleapis.com"}, {"service": "securetoken.googleapis.com"}]


@pytest.fixture
def tf(monkeypatch):
    mod = load_tf_service(monkeypatch)
    monkeypatch.setattr(mod, "_APIKEYS_OP_POLL_SECONDS", 0, raising=False)
    return mod


class _Resp:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.text = str(self._body)

    def json(self):
        return self._body


class _Project:
    """A fake child project's API keys behind a fake AuthorizedSession; records every call."""

    def __init__(self, keys=None, op_polls=1, op_response=True, crm_status=200, keystring_status=200):
        self.keys = {k["name"]: dict(k) for k in (keys or [])}
        self.calls = []
        self.op_polls = op_polls
        self.op_response = op_response
        self.crm_status = crm_status
        self.keystring_status = keystring_status
        self._ops = {}

    def _op(self, result_key):
        name = f"operations/akmf.{len(self._ops)}"
        self._ops[name] = {"left": self.op_polls, "key": result_key}
        return {"name": name, "done": self.op_polls == 0, **({"response": result_key} if self.op_polls == 0 else {})}

    def handle(self, method, url, json=None):
        self.calls.append((method, url, json))
        if url.startswith("https://cloudresourcemanager.googleapis.com/v1/projects/"):
            return _Resp(self.crm_status, {"projectNumber": PNUM} if self.crm_status == 200 else {})
        assert url.startswith(API + "/"), url
        path = url[len(API) + 1:]
        if method == "GET" and path.startswith("operations/"):
            op = self._ops[path]
            op["left"] -= 1
            if op["left"] > 0:
                return _Resp(200, {"name": path, "done": False})
            body = {"name": path, "done": True}
            if self.op_response:
                body["response"] = op["key"]
            return _Resp(200, body)
        if method == "GET" and path.endswith("/keyString"):
            name = path[: -len("/keyString")]
            if self.keystring_status != 200:
                return _Resp(self.keystring_status, {"error": "boom"})
            return _Resp(200, {"keyString": self.keys[name]["_string"]})
        if method == "GET" and path.startswith(f"{PARENT}/keys/"):
            key = self.keys.get(path)
            return _Resp(200, {k: v for k, v in key.items() if k != "_string"}) if key else _Resp(404, {})
        if method == "GET" and path.startswith(f"{PARENT}/keys"):
            return _Resp(200, {"keys": [{k: v for k, v in key.items() if k != "_string"}
                                        for key in self.keys.values()]})
        if method == "POST" and path == f"{PARENT}/keys?keyId=stackvend-web":
            key = {"name": WEB, "displayName": json["displayName"], "restrictions": json["restrictions"],
                   "_string": KEY}
            self.keys[WEB] = key
            return _Resp(200, self._op({k: v for k, v in key.items() if k != "_string"}))
        if method == "PATCH" and path.endswith("?updateMask=restrictions"):
            name = path[: -len("?updateMask=restrictions")]
            self.keys[name]["restrictions"] = json["restrictions"]
            return _Resp(200, self._op({"name": name}))
        return _Resp(404, {})

    def writes(self):
        return [c for c in self.calls if c[0] in ("POST", "PATCH", "DELETE")]

    def keystring_reads(self):
        return [c[1] for c in self.calls if c[1].endswith("/keyString")]


def _install(monkeypatch, project):
    import google.auth
    import google.auth.transport.requests as gatr
    import httpx

    class _Session:
        def __init__(self, *a, **k):
            pass

        def get(self, url, **k):
            return project.handle("GET", url)

        def post(self, url, json=None, **k):
            return project.handle("POST", url, json)

        def patch(self, url, json=None, **k):
            return project.handle("PATCH", url, json)

    def _no_httpx(*a, **k):
        raise AssertionError("httpx is not used for API keys (AuthorizedSession only)")

    creds = types.SimpleNamespace(valid=True, token="tok")
    monkeypatch.setattr(sys.modules["google.auth"], "default", lambda *a, **k: (creds, "p"), raising=False)
    monkeypatch.setattr(gatr, "AuthorizedSession", _Session, raising=False)
    monkeypatch.setattr(httpx, "Client", _no_httpx)


_BASE = {}


@pytest.fixture(autouse=True)
def _workspace_base(tmp_path):
    _BASE["dir"] = str(tmp_path)


def _svc(tf):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=_BASE["dir"],
                              firestore_client=MagicMock(name="firestore"))
    svc.db = None
    return svc


def _resolve(tf, monkeypatch, project):
    _install(monkeypatch, project)
    return _svc(tf)._resolve_workload_web_key(PID, "shop")


def _web(restrictions=None, string=KEY):
    return {"name": WEB, "displayName": "StackVend web sign-in key", "_string": string,
            **({"restrictions": restrictions} if restrictions is not None else {})}


FIREBASE_AUTO = {"name": f"{PARENT}/keys/firebase-auto", "displayName": "Browser key (auto created by Firebase)",
                 "restrictions": {"apiTargets": [{"service": f"s{i}.googleapis.com"} for i in range(27)]},
                 "_string": OTHER}
FOREIGN = {"name": f"{PARENT}/keys/k-foreign", "displayName": "team key", "_string": OTHER}
LEGACY = {"name": f"{PARENT}/keys/k-legacy", "displayName": "Castor shop Web Key", "_string": OTHER}


# ------------------------------------------------------------------------------------------------ absent -> create
def test_absent_key_is_created_with_the_fixed_id_and_restrictions_and_the_operation_is_polled(tf, monkeypatch):
    project = _Project(keys=[FIREBASE_AUTO, FOREIGN], op_polls=2)
    assert _resolve(tf, monkeypatch, project) == (KEY, PNUM)
    posts = [c for c in project.writes() if c[0] == "POST"]
    assert len(posts) == 1 and posts[0][1] == f"{API}/{PARENT}/keys?keyId=stackvend-web"
    assert posts[0][2] == {"displayName": "StackVend web sign-in key", "restrictions": {"apiTargets": TARGETS}}
    assert [c for c in project.writes() if c[0] == "PATCH"] == []          # foreign keys never touched
    assert len([c for c in project.calls if "/operations/" in c[1]]) == 2   # polled to done
    assert project.keystring_reads() == [f"{API}/{WEB}/keyString"]          # only the web key is read


def test_operation_without_response_gives_no_key_never_the_operation_name(tf, monkeypatch, caplog):
    caplog.set_level(logging.WARNING, logger="mcp-terraform-server")
    project = _Project(op_polls=1, op_response=False)
    assert _resolve(tf, monkeypatch, project) == ("", PNUM)
    assert project.keystring_reads() == []                                   # not even for the operation name
    assert any("did not finish with the key" in r.getMessage() for r in caplog.records)


def test_operation_that_never_finishes_gives_no_key(tf, monkeypatch):
    project = _Project(op_polls=10_000)
    assert _resolve(tf, monkeypatch, project) == ("", PNUM)
    assert len([c for c in project.calls if "/operations/" in c[1]]) == tf._APIKEYS_OP_POLL_ATTEMPTS


# ------------------------------------------------------------------------------------------------ present
def test_present_and_restricted_key_needs_zero_writes(tf, monkeypatch):
    project = _Project(keys=[_web({"apiTargets": list(reversed(TARGETS))}), FIREBASE_AUTO, FOREIGN])
    assert _resolve(tf, monkeypatch, project) == (KEY, PNUM)
    assert project.writes() == []
    assert not [c for c in project.calls if c[1] == f"{API}/{PARENT}/keys"]   # no listing at all
    assert project.keystring_reads() == [f"{API}/{WEB}/keyString"]


@pytest.mark.parametrize("restrictions", [None, {}, {"apiTargets": [{"service": "identitytoolkit.googleapis.com"}]},
                                          {"apiTargets": [{"service": "identitytoolkit.googleapis.com",
                                                           "methods": ["*"]},
                                                          {"service": "securetoken.googleapis.com"}]}],
                         ids=["no-restrictions", "empty", "one-target", "methods"])
def test_present_key_with_other_targets_gets_one_patch(tf, monkeypatch, restrictions):
    project = _Project(keys=[_web(restrictions)])
    assert _resolve(tf, monkeypatch, project) == (KEY, PNUM)
    patches = [c for c in project.writes() if c[0] == "PATCH"]
    assert len(patches) == 1 and patches[0][1] == f"{API}/{WEB}?updateMask=restrictions"
    assert patches[0][2] == {"restrictions": {"apiTargets": TARGETS}}
    assert [c for c in project.writes() if c[0] == "POST"] == []


def test_patch_keeps_a_browser_restriction(tf, monkeypatch):
    browser = {"allowedReferrers": ["https://shop.example/*"]}
    project = _Project(keys=[_web({"browserKeyRestrictions": browser})])
    assert _resolve(tf, monkeypatch, project) == (KEY, PNUM)
    patch = [c for c in project.writes() if c[0] == "PATCH"][0]
    assert patch[2] == {"restrictions": {"browserKeyRestrictions": browser, "apiTargets": TARGETS}}


# ------------------------------------------------------------------------------------------------ legacy migration
def test_legacy_unrestricted_key_is_restricted_once_and_never_used(tf, monkeypatch, caplog):
    caplog.set_level(logging.WARNING, logger="mcp-terraform-server")
    project = _Project(keys=[LEGACY, FOREIGN])
    assert _resolve(tf, monkeypatch, project) == (KEY, PNUM)
    patches = [c for c in project.writes() if c[0] == "PATCH"]
    assert [p[1] for p in patches] == [f"{API}/{LEGACY['name']}?updateMask=restrictions"]
    assert patches[0][2] == {"restrictions": {"apiTargets": TARGETS}}
    assert [c[1] for c in project.writes() if c[0] == "POST"] == [f"{API}/{PARENT}/keys?keyId=stackvend-web"]
    assert project.keystring_reads() == [f"{API}/{WEB}/keyString"]          # the legacy key's string: never
    assert any("LEGACY_WEB_KEY_RESTRICTED" in r.getMessage() for r in caplog.records)
    # the next deploy finds stackvend-web: no listing, no write
    project.calls.clear()
    assert _resolve(tf, monkeypatch, project) == (KEY, PNUM)
    assert project.writes() == [] and not [c for c in project.calls if c[1] == f"{API}/{PARENT}/keys"]


def test_display_name_match_is_exact(tf, monkeypatch):
    near = dict(LEGACY, displayName="Castor shop Web Key (copy)")
    project = _Project(keys=[near, dict(LEGACY, name=f"{PARENT}/keys/k2", displayName="castor shop web key")])
    assert _resolve(tf, monkeypatch, project) == (KEY, PNUM)
    assert [c for c in project.writes() if c[0] == "PATCH"] == []


# ------------------------------------------------------------------------------------------------ errors
def test_project_number_failure_gives_no_key_and_no_apikeys_call(tf, monkeypatch):
    project = _Project(crm_status=403)
    assert _resolve(tf, monkeypatch, project) == ("", "")
    assert [c for c in project.calls if c[1].startswith(API)] == []


def test_key_string_failure_gives_empty_and_no_value_in_logs(tf, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger="mcp-terraform-server")
    project = _Project(keys=[_web({"apiTargets": TARGETS})], keystring_status=500)
    assert _resolve(tf, monkeypatch, project) == ("", PNUM)
    assert not any(KEY in r.getMessage() or OTHER in r.getMessage() for r in caplog.records)


def test_session_error_gives_empty_and_names_no_value(tf, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger="mcp-terraform-server")
    project = _Project(keys=[_web({"apiTargets": TARGETS})])

    def _boom(method, url, json=None):
        raise RuntimeError(f"transport failed for {KEY}")

    monkeypatch.setattr(project, "handle", _boom)
    assert _resolve(tf, monkeypatch, project) == ("", "")
    assert not any(KEY in r.getMessage() for r in caplog.records)
