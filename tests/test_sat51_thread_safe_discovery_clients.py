"""SAT-51: the vending engine's cached discovery clients are safe to share across vend worker threads.

Live failure this covers (second dev install, 11-03): three example-01 workloads submitted together; the two vends that
ran in the same instance within a second both died in `vend_gcp_project` with "OSError: [Errno 9] Bad file descriptor"
while refreshing the metadata-server token. The engine is one module-level object, each vend runs on its own
BackgroundTasks worker thread, and the cached Resource Manager / Cloud Billing clients each held ONE httplib2.Http,
which is not thread-safe.

The fix follows the google-api-python-client thread-safety guidance: the client object stays cached, every request
gets its own authorized httplib2 connection (requestBuilder).

Hermetic: the real-library check runs in a clean subprocess (other tests stub googleapiclient in sys.modules) with
anonymous credentials and the library's bundled discovery documents, so nothing touches the network."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import subprocess
import sys
import textwrap
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

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


def _fake_http_modules():
    """google_auth_httplib2 / googleapiclient.http fakes that record every connection they hand out."""
    made = []

    class AuthorizedHttp:
        def __init__(self, credentials, http=None):
            self.credentials, self.http = credentials, http
            made.append(self)

    class HttpRequest:
        def __init__(self, http, *args, **kwargs):
            self.http, self.args, self.kwargs = http, args, kwargs

    gah = ModuleType("google_auth_httplib2")
    gah.AuthorizedHttp = AuthorizedHttp
    gh = ModuleType("googleapiclient.http")
    gh.HttpRequest = HttpRequest
    gh.build_http = lambda: object()
    return made, {"google_auth_httplib2": gah, "googleapiclient.http": gh}


def test_each_request_gets_its_own_connection():
    made, mods = _fake_http_modules()
    creds = object()
    with patch.dict(sys.modules, mods), \
            patch.object(vending, "google", SimpleNamespace(auth=SimpleNamespace(default=lambda scopes=None: (creds, "p")))), \
            patch.object(vending, "build") as build:
        vending._build_thread_safe("cloudresourcemanager", "v3")
    args, kwargs = build.call_args
    assert args == ("cloudresourcemanager", "v3")
    assert "credentials" not in kwargs and kwargs["cache_discovery"] is False
    builder = kwargs["requestBuilder"]
    with patch.dict(sys.modules, mods):
        r1 = builder(kwargs["http"], "postproc", "uri")
        r2 = builder(kwargs["http"], "postproc", "uri")
    assert r1.http is not r2.http and r1.http is not kwargs["http"]
    assert r1.http.http is not r2.http.http                      # distinct underlying httplib2 connections
    assert all(h.credentials is creds for h in made)
    assert r1.args == ("postproc", "uri")


def test_crm_and_billing_use_the_thread_safe_builder():
    eng = vending.ProjectRepoVendingEngine.__new__(vending.ProjectRepoVendingEngine)
    eng._crm = eng._billing = None
    with patch.object(vending, "_build_thread_safe", side_effect=lambda s, v: (s, v)) as b:
        assert eng.crm == ("cloudresourcemanager", "v3")
        assert eng.billing == ("cloudbilling", "v1")
        assert eng.crm == ("cloudresourcemanager", "v3")          # cached: built once
    assert b.call_count == 2


def test_injected_clients_are_unchanged():
    """Negative: a client passed in (tests, callers) is used as is and nothing is built."""
    eng = vending.ProjectRepoVendingEngine.__new__(vending.ProjectRepoVendingEngine)
    crm, billing = object(), object()
    eng._crm, eng._billing = crm, billing
    with patch.object(vending, "_build_thread_safe") as b:
        assert eng.crm is crm and eng.billing is billing
    b.assert_not_called()


def test_real_library_builds_a_distinct_connection_per_request():
    """The real google-api-python-client accepts http + requestBuilder and the two requests differ in connection."""
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {VENDING_DIR!r})
        import google.auth
        from google.auth.credentials import AnonymousCredentials
        google.auth.default = lambda scopes=None: (AnonymousCredentials(), None)
        import vending
        svc = vending._build_thread_safe("cloudresourcemanager", "v3")
        r1 = svc.projects().get(name="projects/a")
        r2 = svc.projects().get(name="projects/b")
        assert r1.http is not r2.http, "shared connection"
        assert r1.http.http is not r2.http.http, "shared httplib2.Http"
        assert r1.http._request.http is r1.http.http, "token refresh not on the request's own connection"
        bill = vending._build_thread_safe("cloudbilling", "v1")
        b1 = bill.projects().getBillingInfo(name="projects/a")
        assert b1.http is not r1.http
        print("OK")
    """)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120,
                         env=hermetic_guard.child_env(), cwd=VENDING_DIR)
    assert out.returncode == 0 and out.stdout.strip().endswith("OK"), out.stderr[-3000:]


SPEC_DIR = os.path.join(REPO_ROOT, "apps", "spec-ingestion")
WORKSPACE_DIR = os.path.join(REPO_ROOT, "mcp-servers", "workspace")


def _run_isolated(code: str, cwd: str):
    env = hermetic_guard.child_env(drop=("TEST_MODE",))   # the poller skips building its Drive client in TEST_MODE
    return subprocess.run([sys.executable, "-c", textwrap.dedent(_ANON) + textwrap.dedent(code)], capture_output=True,
                          text=True, timeout=120, env=env, cwd=cwd)


_ANON = """
    import sys
    import google.auth
    from google.auth.credentials import AnonymousCredentials
    google.auth.default = lambda scopes=None: (AnonymousCredentials(), None)
"""


def test_spec_ingestion_poller_clients_use_a_connection_per_request():
    """Same hazard in spec-ingestion: the module-global poller's Drive / Docs clients serve the sync endpoints."""
    code = f"""
        sys.path.insert(0, {SPEC_DIR!r})
        import poller
        from unittest.mock import MagicMock
        p = poller.SpecIngestionPoller(publisher_client=MagicMock(), firestore_client=MagicMock())
        d1 = p.drive_service.files().get(fileId="a")
        d2 = p.drive_service.files().get(fileId="b")
        assert d1.http is not d2.http and d1.http.http is not d2.http.http, "shared Drive connection"
        docs = poller._build_thread_safe("docs", "v1", AnonymousCredentials())
        assert docs.documents().get(documentId="a").http is not docs.documents().get(documentId="b").http
        print("OK")
    """
    out = _run_isolated(code, SPEC_DIR)
    assert out.returncode == 0 and out.stdout.strip().endswith("OK"), out.stderr[-3000:]


def test_workspace_service_clients_use_a_connection_per_request():
    """Same hazard in the workspace MCP: the module-global WorkspaceService serves every sync endpoint."""
    code = f"""
        sys.path.insert(0, {WORKSPACE_DIR!r})
        import service
        s = service.WorkspaceService()
        a, b = s.drive_service.files().get(fileId="a"), s.drive_service.files().get(fileId="b")
        assert a.http is not b.http and a.http.http is not b.http.http, "shared Drive connection"
        c, d = s.docs_service.documents().get(documentId="a"), s.docs_service.documents().get(documentId="b")
        assert c.http is not d.http, "shared Docs connection"
        print("OK")
    """
    out = _run_isolated(code, WORKSPACE_DIR)
    assert out.returncode == 0 and out.stdout.strip().endswith("OK"), out.stderr[-3000:]


FINOPS_DIR = os.path.join(REPO_ROOT, "apps", "finops-enforcer")


def test_finops_enforcer_clients_use_a_connection_per_request():
    """Same class in the finops enforcer (a job today; the module-global enforcer would race if it ran as a service)."""
    code = f"""
        sys.path.insert(0, {FINOPS_DIR!r})
        from unittest.mock import MagicMock
        import enforcer
        e = enforcer.FinopsBudgetEnforcer(firestore_client=MagicMock())
        for client, call in ((e.run, lambda c: c.projects().locations().services().get(name="projects/p/locations/l/services/s")),
                             (e.compute, lambda c: c.instances().get(project="p", zone="z", instance="i")),
                             (e.sql, lambda c: c.instances().get(project="p", instance="i")),
                             (e.container, lambda c: c.projects().locations().clusters().get(name="projects/p/locations/l/clusters/c")),
                             (e.billing, lambda c: c.projects().getBillingInfo(name="projects/p")),
                             (e.crm, lambda c: c.projects().getAncestry(projectId="p", body={{}}))):
            a, b = call(client), call(client)
            assert a.http is not b.http and a.http.http is not b.http.http, "shared connection"
        print("OK")
    """
    out = _run_isolated(code, FINOPS_DIR)
    assert out.returncode == 0 and out.stdout.strip().endswith("OK"), out.stderr[-3000:]
