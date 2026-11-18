"""FD4BD-Q3 (owner OQ-5a: the first commit of FD-7L Phase 2a, SAT-27): the quota project per workspace and per call.

Before: deploy_workload (and tf-applier) wrote GOOGLE_BILLING_PROJECT / GOOGLE_CLOUD_QUOTA_PROJECT /
GOOGLE_USER_PROJECT_OVERRIDE into the PROCESS environment and `_active_target_project_id` onto the service, so in the
multi-tenant terraform server every later tofu process and every later Google client (google-auth reads
GOOGLE_CLOUD_QUOTA_PROJECT in `google.auth.default()`) billed whichever child was deployed last.
After: the quota project is registered per deploy workspace (tofu env only) and passed per call to every child REST
session (`_child_credentials(project)`, `_child_storage_client(project)`); nothing writes the process environment.

Do No Harm: a tofu process of a registered workspace gets exactly the three variables it got before; an explicit `env=`
still wins; a child REST call still carries the child as its quota project (as the env did); the web sign-in key's
host header line is unchanged (OQ-5b).

Hermetic: fake Popen, fake google.auth; no network, no cloud clients.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import os
import subprocess
import sys
import threading
from unittest.mock import MagicMock

import pytest

from tests.tofu_popen_fake import popen_from_run
from test_fd4g_terraform_workspace import (  # noqa: F401  (pytest fixtures reused by name)
    _isolated_tf_service, _import_service, _patched_applier, base, sent_callbacks)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO, "mcp-servers", "terraform")
BILLING_VARS = ("GOOGLE_BILLING_PROJECT", "GOOGLE_CLOUD_QUOTA_PROJECT", "GOOGLE_USER_PROJECT_OVERRIDE")


def _svc(base):
    tf = _import_service()
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=base,
                              firestore_client=MagicMock())
    svc.db = None
    return tf, svc


def _engine(monkeypatch, tf, svc, tmp_path, seen):
    rc = tmp_path / "terraform.rc"
    rc.write_text("provider_installation {}\n", encoding="utf-8")
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **k: "tofu")
    monkeypatch.setattr(svc, "_ensure_provider_mirror", lambda *a, **k: str(rc))
    monkeypatch.setattr(tf.subprocess, "Popen", popen_from_run(
        lambda cmd, **kw: seen.append((kw["cwd"], dict(kw["env"]))) or subprocess.CompletedProcess(cmd, 0, "", "")))


@pytest.fixture
def clean_billing_env(monkeypatch):
    for name in BILLING_VARS:
        monkeypatch.delenv(name, raising=False)


def test_registered_workspace_tofu_gets_its_own_quota_project_only(monkeypatch, base, tmp_path, clean_billing_env):
    tf, svc = _svc(base)
    seen = []
    _engine(monkeypatch, tf, svc, tmp_path, seen)
    ws = os.path.join(base, "t1", "claims")
    other = os.path.join(base, "t1", "claims-2")
    os.makedirs(os.path.join(ws, "infra"))
    os.makedirs(other)
    reg = svc._register_workspace_billing(ws, "child-a")
    svc._run_subprocess(["tofu", "plan"], cwd=ws, iac_engine="OPENTOFU")
    svc._run_subprocess(["tofu", "plan"], cwd=os.path.join(ws, "infra"), iac_engine="OPENTOFU")
    svc._run_subprocess(["tofu", "plan"], cwd=other, iac_engine="OPENTOFU")          # sibling prefix: not inside
    svc._run_subprocess(["tofu", "plan"], cwd=ws, env={"GOOGLE_BILLING_PROJECT": "explicit"}, iac_engine="OPENTOFU")
    envs = [e for _cwd, e in seen]
    for env in envs[:2]:
        assert (env["GOOGLE_BILLING_PROJECT"], env["GOOGLE_CLOUD_QUOTA_PROJECT"],
                env["GOOGLE_USER_PROJECT_OVERRIDE"]) == ("child-a", "child-a", "true")
    assert not any(name in envs[2] for name in BILLING_VARS)
    assert envs[3]["GOOGLE_BILLING_PROJECT"] == "explicit" == envs[3]["GOOGLE_CLOUD_QUOTA_PROJECT"]   # explicit wins
    svc._forget_workspace_billing(*reg)
    svc._run_subprocess(["tofu", "plan"], cwd=ws, iac_engine="OPENTOFU")
    assert not any(name in seen[-1][1] for name in BILLING_VARS)
    assert not hasattr(svc, "_active_target_project_id")


def test_two_concurrent_in_process_deploys_never_share_a_quota_project(monkeypatch, base, tmp_path, clean_billing_env):
    """Q3: two deploys of one server process, interleaved on threads: each tofu process bills its own child."""
    tf, svc = _svc(base)
    seen = []
    _engine(monkeypatch, tf, svc, tmp_path, seen)
    barrier = threading.Barrier(2)
    errors = []

    def deploy(trace, child):
        try:
            ws = os.path.join(base, trace, "app")
            os.makedirs(ws, exist_ok=True)
            reg = svc._register_workspace_billing(ws, child)
            barrier.wait(timeout=10)       # both registered before either runs tofu (the old env: last one wins)
            for _ in range(5):
                svc._run_subprocess(["tofu", "plan"], cwd=ws, iac_engine="OPENTOFU")
            barrier.wait(timeout=10)
            svc._forget_workspace_billing(*reg)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=deploy, args=("trace-a", "child-a")),
               threading.Thread(target=deploy, args=("trace-b", "child-b"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors
    assert len(seen) == 10
    for cwd, env in seen:
        want = "child-a" if "trace-a" in cwd else "child-b"
        assert env["GOOGLE_BILLING_PROJECT"] == want == env["GOOGLE_CLOUD_QUOTA_PROJECT"], cwd
    assert not any(name in os.environ for name in BILLING_VARS)


def test_child_credentials_pass_the_child_as_quota_project_per_call(monkeypatch, base, clean_billing_env):
    import google.auth
    tf, svc = _svc(base)
    calls = []
    monkeypatch.setattr(google.auth, "default", lambda *a, **k: calls.append(k) or (MagicMock(), "p"))
    svc._child_credentials("child-a")
    svc._child_credentials("child-b", scoped=False)
    assert calls == [{"scopes": ["https://www.googleapis.com/auth/cloud-platform"], "quota_project_id": "child-a"},
                     {"quota_project_id": "child-b"}]


def test_child_storage_client_bills_the_child_and_keeps_the_platform_default_project(monkeypatch, base):
    from google.cloud import storage
    tf, svc = _svc(base)
    made = []
    monkeypatch.setattr(storage, "Client", lambda **k: made.append(k) or MagicMock())
    svc._child_storage_client("child-a")
    assert made == [{"project": "mock-stackvend-project", "client_options": {"quota_project_id": "child-a"}}]


def test_web_key_header_line_is_unchanged_and_the_credentials_quota_wins_as_before():
    """OQ-5b is open: the explicit host header stays. AuthorizedSession adds the credentials' lowercase
    x-goog-user-project after it, and requests keeps the last case-variant key, so the call bills the child, exactly
    as it did with the process env (measured with a real AuthorizedSession and a fake transport)."""
    import google.auth.credentials as gc
    import requests
    from google.auth.transport.requests import AuthorizedSession

    class _Creds(gc.CredentialsWithQuotaProject):
        def __init__(self, quota=None):
            super().__init__()
            self.token, self._quota_project_id = "t", quota

        def refresh(self, request):
            pass

        def with_quota_project(self, quota):
            return _Creds(quota)

        @property
        def valid(self):
            return True

    captured = {}

    class _Adapter(requests.adapters.HTTPAdapter):
        def send(self, req, **kw):
            captured.update(req.headers)
            resp = requests.Response()
            resp.status_code, resp._content = 200, b"{}"
            return resp

    sess = AuthorizedSession(_Creds("child-a"))
    sess.mount("https://", _Adapter())
    sess.get("https://apikeys.example.invalid/v2/x", headers={"X-Goog-User-Project": "host-project"})
    assert [v for k, v in captured.items() if k.lower() == "x-goog-user-project"] == ["child-a"]
    src = open(os.path.join(TF_DIR, "service.py"), encoding="utf-8").read()
    assert 'headers = {"X-Goog-User-Project": self.project_id or target_project_id}' in src
    assert "else self.project_id or target_project_id)" in src     # authorized domains (httpx): host on Shared


def test_applier_registers_the_quota_project_for_its_run_and_never_writes_the_process_env(
        monkeypatch, base, sent_callbacks, clean_billing_env):
    seen = {}

    def deploy(**kw):
        svc = deploy.owner
        seen["billing"] = svc._workspace_billing_project(os.path.join(base, kw["trace_id"], "app"))
        seen["env"] = {name: os.environ.get(name) for name in BILLING_VARS}
        return {"status": "SUCCESS", "service_url": "https://x"}

    applier = _patched_applier(monkeypatch, base, "fd4bd_q3_applier", deploy)
    real_factory = applier.TerraformService

    def factory(*a, **k):
        inst = real_factory(*a, **k)
        deploy.owner = inst
        return inst

    monkeypatch.setattr(applier, "TerraformService", factory)
    monkeypatch.setenv("PRODUCT_ID", "app")
    monkeypatch.setenv("TARGET_PROJECT_ID", "child-app")
    before = dict(os.environ)
    with pytest.raises(SystemExit) as ei:
        applier.run_job()
    assert ei.value.code == 0
    assert seen["billing"] == "child-app"
    assert seen["env"] == {name: None for name in BILLING_VARS}
    assert dict(os.environ) == before
    assert sent_callbacks[-1]["status"] == "SUCCESS"


def test_workflow_callback_carries_no_child_quota_project(monkeypatch):
    """The callback (shared/callbacks.py) builds its own headers: only the bearer token, never x-goog-user-project,
    whatever google-auth's credentials carry."""
    import google.auth
    import shared.callbacks as cb

    creds = MagicMock()
    creds.token = "tok"
    creds.quota_project_id = "child-a"
    monkeypatch.setattr(google.auth, "default", lambda *a, **k: (creds, "p"))
    monkeypatch.setattr(cb, "classify_callback_url", lambda url: cb.KIND_WORKFLOWS)
    headers = cb.CallbackDeliveryClient._get_headers("https://workflowexecutions.googleapis.com/v1/x/callbacks/y")
    assert headers.get("Authorization") == "Bearer tok"
    assert not [k for k in headers if k.lower() == "x-goog-user-project"]


def _environ_writes(path):
    """Every `os.environ[...] = ...`, `os.environ.update(...)`, `os.environ.setdefault(...)` and `os.putenv(...)`."""
    tree = ast.parse(open(path, encoding="utf-8").read())
    hits = []

    def _is_environ(node):
        return (isinstance(node, ast.Attribute) and node.attr == "environ" and isinstance(node.value, ast.Name)
                and node.value.id == "os")

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            hits += [node.lineno for t in targets if isinstance(t, ast.Subscript) and _is_environ(t.value)]
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if _is_environ(node.func.value) and node.func.attr in ("update", "setdefault", "pop", "clear"):
                hits.append(node.lineno)
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "putenv":
                hits.append(node.lineno)
    return hits


@pytest.mark.parametrize("name", ["service.py", "applier.py"])
def test_no_process_environment_write_in_the_runner(name):
    assert _environ_writes(os.path.join(TF_DIR, name)) == []
