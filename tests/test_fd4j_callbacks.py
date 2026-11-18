"""FD-4J: the callback client attaches the platform OAuth token only to this project's Workflows callback endpoint.

Every replica of callbacks.py is loaded by file path and exercised. Hermetic: google.auth.default and requests.post
are stubbed and socket.connect is blocked, so nothing leaves the process.
"""
import hermetic_guard  # noqa: F401  (lane 2: must be the first import)

import hashlib
import importlib.util
import os
import socket
import sys
import types

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPLICAS = [
    "shared/callbacks.py",
    "apps/orchestrator-gateway/shared/callbacks.py",
    "apps/project-vending/shared/callbacks.py",
    "apps/qa-runner/shared/callbacks.py",
    "mcp-servers/terraform/shared/callbacks.py",
    "apps/control-center/shared/callbacks.py",  # lane 4: the CC delivers HITL callbacks with this helper
]
SENTINEL = "ya29.FD4J-SENTINEL"
OWN = "mock-stackvend-project"
GOOD = (f"https://workflowexecutions.googleapis.com/v1/projects/{OWN}/locations/us-central1/workflows/main/"
        "executions/0b1c-22/callbacks/1704219779_abc")


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    def _blocked(self, addr):
        raise OSError(f"network blocked in FD-4J test: {addr}")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setenv("PROJECT_ID", OWN)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("PROJECT_NUMBER", raising=False)
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("CLOUD_RUN_JOB", raising=False)

    class _Creds:
        token = SENTINEL

        def refresh(self, _req):
            return None

    fake_auth = types.ModuleType("google.auth")
    fake_auth.default = lambda scopes=None: (_Creds(), OWN)
    fake_transport = types.ModuleType("google.auth.transport")
    fake_requests = types.ModuleType("google.auth.transport.requests")
    fake_requests.Request = lambda *a, **k: None
    fake_auth.transport = fake_transport
    fake_transport.requests = fake_requests
    google_pkg = sys.modules.get("google")
    if not isinstance(google_pkg, types.ModuleType):
        google_pkg = types.ModuleType("google")
        google_pkg.__path__ = []
        monkeypatch.setitem(sys.modules, "google", google_pkg)
    monkeypatch.setattr(google_pkg, "auth", fake_auth, raising=False)
    monkeypatch.setitem(sys.modules, "google.auth", fake_auth)
    monkeypatch.setitem(sys.modules, "google.auth.transport", fake_transport)
    monkeypatch.setitem(sys.modules, "google.auth.transport.requests", fake_requests)


def _load(rel):
    for name in ("requests", "urllib3", "urllib3.util"):
        if name in sys.modules and not isinstance(sys.modules[name], types.ModuleType):
            sys.modules.pop(name)
    import requests  # noqa: F401  (real module; the tests patch requests.post on it)
    path = os.path.join(REPO_ROOT, rel)
    spec = importlib.util.spec_from_file_location(f"fd4j_cb_{rel.replace('/', '_').replace('-', '_')}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(params=REPLICAS)
def cb(request):
    return _load(request.param)


BAD = [
    "https://evil.com/?x=googleapis.com",
    "https://evil.com/workflowexecutions.googleapis.com/cb",
    "https://googleapis.com.evil.com/",
    "https://workflowexecutions.googleapis.com.evil.com/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c",
    "https://workflowexecutions.googleapis.com@evil.com/",
    "https://evil.com@workflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c",
    "https://user:pw@workflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c",
    "https://evil.com\\@workflowexecutions.googleapis.com/",
    "https://workflowexecutions.googleapis.com\\@evil.com/",
    "https://evil.com\\\\.workflowexecutions.googleapis.com/",
    "https://workflowexecutions.googleapis.com#@evil.com/",
    "https://workflowexecutions.googleapis.com?@evil.com/",
    "https://workflowexecutions.googleapis.com%2eevil.com/",
    "https://workflowexecutions.googleapis.com%40evil.com/",
    "https://workflowexecutions.googleapis.com./v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c",
    "https://workflowexecutions.googleapis.com:443/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c",
    "https://workflowexecutions.googleapis.com:0443/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c",
    "https://workflowexecutions.googleapis.com:8443/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c",
    "https://ｗorkflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c",
    "https://workflowexecutions。googleapis.com/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c",
    "http://workflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c",
    # right host, wrong project / wrong path shape / extras
    "https://workflowexecutions.googleapis.com/v1/projects/attacker-proj/locations/l/workflows/w/executions/e/callbacks/c",
    "https://workflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c/x",
    "https://workflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/",
    "https://workflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions//callbacks/c",
    "https://workflowexecutions.googleapis.com/v2/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c",
    "https://workflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c?x=1",
    "https://workflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c#f",
    "https://workflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/../attacker/locations/l/workflows/w/executions/e/callbacks/c",
    "https://workflowexecutions.googleapis.com/v1/callbacks/123",
    "https://evil.run.app/cb",
    "https://x.a.run.app/cb",
    " https://workflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c",
    "https://workflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c\r\nX: y",
    "file:///etc/passwd",
    "ftp://workflowexecutions.googleapis.com/",
    "gopher://127.0.0.1/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://localhost:9/cb",
    "http://127.1/",
    "http://2130706433/",
    "http://10.0.0.1/cb",
    "//workflowexecutions.googleapis.com/",
    "",
    None,
]


@pytest.mark.parametrize("url", BAD)
def test_rejected_urls_get_no_token_and_no_request(cb, monkeypatch, url):
    posts = []
    monkeypatch.setattr(sys.modules["requests"], "post", lambda *a, **k: posts.append((a, k)))
    with pytest.raises(cb.CallbackURLRejected):
        cb.CallbackDeliveryClient._get_headers(url)
    with pytest.raises(cb.CallbackURLRejected):
        cb.CallbackDeliveryClient.send_callback(url, {"status": "SUCCESS"}, max_attempts=3)
    assert posts == []
    with pytest.raises(ValueError):
        cb.validate_callback_url(url)


@pytest.mark.parametrize("url", [GOOD, GOOD.replace("workflowexecutions.googleapis.com", "WORKFLOWEXECUTIONS.googleapis.com")])
def test_own_workflows_callback_gets_token(cb, url):
    assert cb.classify_callback_url(url) == cb.KIND_WORKFLOWS
    assert cb.CallbackDeliveryClient._get_headers(url)["Authorization"] == f"Bearer {SENTINEL}"
    assert cb.validate_callback_url(url) == url


def test_project_number_accepted_when_configured(cb, monkeypatch):
    monkeypatch.setenv("PROJECT_NUMBER", "123456789012")
    url = GOOD.replace(f"/projects/{OWN}/", "/projects/123456789012/")
    assert cb.classify_callback_url(url) == cb.KIND_WORKFLOWS


def test_metadata_failure_is_not_cached(cb, monkeypatch):
    """Code red-team F1: a failed metadata read of the project number must be retried, not frozen in the cache."""
    monkeypatch.setenv("K_SERVICE", "orchestrator-gateway-service")
    monkeypatch.setattr(cb, "_own_project_cache", None)
    url = GOOD.replace(f"/projects/{OWN}/", "/projects/123456789012/")
    answers = {"project-id": OWN, "numeric-project-id": ""}  # first call: number read fails
    calls = []

    def _md(leaf):
        calls.append(leaf)
        return answers[leaf]

    monkeypatch.setattr(cb, "_metadata_project_value", _md)
    with pytest.raises(cb.CallbackURLRejected):
        cb.classify_callback_url(url)
    assert cb._own_project_cache is None
    answers["numeric-project-id"] = "123456789012"  # metadata recovers
    assert cb.classify_callback_url(url) == cb.KIND_WORKFLOWS
    assert cb._own_project_cache == frozenset({OWN, "123456789012"})
    n = len(calls)
    assert cb.classify_callback_url(url) == cb.KIND_WORKFLOWS
    assert len(calls) == n  # complete answer cached; no further metadata reads


def test_no_own_project_known_refuses_token(cb, monkeypatch):
    monkeypatch.delenv("PROJECT_ID", raising=False)
    with pytest.raises(cb.CallbackURLRejected):
        cb.classify_callback_url(GOOD)


@pytest.mark.parametrize("url", ["http://127.0.0.1:9/cb", "http://[::1]:9/cb", "https://127.0.0.1/cb"])
def test_loopback_delivered_without_token(cb, url):
    assert cb.classify_callback_url(url) == cb.KIND_LOOPBACK
    assert "Authorization" not in cb.CallbackDeliveryClient._get_headers(url)


class _Resp:
    def __init__(self, code, body=None):
        self.status_code, self._body, self.text = code, body or {}, ""

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_redirect_not_followed_and_payload_unchanged(cb, monkeypatch):
    calls = []

    def _post(url, json=None, headers=None, timeout=None, allow_redirects=True):
        calls.append({"url": url, "json": json, "headers": headers, "allow_redirects": allow_redirects})
        return _Resp(307)

    monkeypatch.setattr(sys.modules["requests"], "post", _post)
    monkeypatch.setattr(cb.time, "sleep", lambda s: None)
    payload = {"status": "SUCCESS", "outputs": {"service_url": "https://svc.a.run.app"}}
    with pytest.raises(RuntimeError):
        cb.CallbackDeliveryClient.send_callback(GOOD, dict(payload), max_attempts=2)
    assert len(calls) == 2  # retried at the same URL, never at a Location header
    assert all(c["allow_redirects"] is False and c["url"] == GOOD for c in calls)
    assert calls[0]["json"] == payload
    assert calls[0]["headers"]["Authorization"] == f"Bearer {SENTINEL}"


def test_success_path_returns_body(cb, monkeypatch):
    monkeypatch.setattr(sys.modules["requests"], "post", lambda *a, **k: _Resp(200, {"ok": True}))
    assert cb.CallbackDeliveryClient.send_callback(GOOD, {"status": "SUCCESS"}) == {"ok": True}


def test_rejected_callback_still_writes_firestore_telemetry(cb, monkeypatch):
    posts = []
    monkeypatch.setattr(sys.modules["requests"], "post", lambda *a, **k: posts.append(a))
    writes = []

    class _Doc:
        def set(self, data, merge=False):
            writes.append(data)

    class _Coll:
        def document(self, _id):
            return _Doc()

    class _Db:
        def collection(self, _name):
            return _Coll()

    with cb.guaranteed_callback_scope("https://evil.com/?x=googleapis.com", "trace-1", "deploy", "app", _Db()) as out:
        out["status"] = "SUCCESS"
    assert posts == []
    assert writes and writes[0]["stages"]["deploy"]["state"] == "CALLBACK_FAILED"


def test_callbacks_replica_parity():
    digests = {rel: hashlib.sha256(open(os.path.join(REPO_ROOT, rel), "rb").read()).hexdigest() for rel in REPLICAS}
    assert len(set(digests.values())) == 1, digests
