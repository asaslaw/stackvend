"""Compliance bundle (owner 10-12, shipped early, split out of the Stage A hold).

1. Register row 19f, ported from lane 13 (`8c80d53` + the compliance route of `2fdec06`): a compliance-server OUTAGE
   (not just a handler crash) is GATE_UNAVAILABLE / COMPLIANCE_UNAVAILABLE, never PASSED / STANDARD / public.
2. Lane 17 PR-1a (`docs/planning/wave2-lane17-workflow-integrity-plan.md` R-3 + R-4 on lane 17's branch):
   - the gateway calls mcp-compliance-server with a Google ID token (audience = the service's https origin, minted by
     the metadata server); no token for any other URL; on Cloud Run a non-Cloud-Run URL is refused;
   - contract v2: the answer must carry contract_version >= 2, enable_direct_iap, allow_unauthenticated (strict
     types) and be internally consistent; anything else is COMPLIANCE_UNAVAILABLE;
   - the spec ingress intent (IAP / domain restriction / private ingress / no unauthenticated) moved into the server,
     most restrictive wins, so an IAP spec can never come out public;
   - Do No Harm: a valid answer is enriched byte-identically to the pre-bundle remote path
     (tests/fixtures/compliance_bundle_golden.json, captured from main@8f9314a before the change).
3. compliance-profile-explicit (10-18): contract v3. The profile is the folder regime or the explicit
   `compliance_profile`, never spec keywords; the answer adds profile_source / requested_profile /
   profile_suggestions (advisory). The golden checks below compare everything else unchanged.

Hermetic: fake httpx, a fake metadata server (google-auth's real ID-token code path), the compliance server through
FastAPI's TestClient; the gateway is loaded by path with no project. Nothing reads TEST_MODE. No network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import base64
import copy
import importlib.util
import json
import os
import sys
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from fd4f_support import FakeDB as _fd4f_FakeDB

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
COMPLIANCE_DIR = os.path.join(REPO_ROOT, "mcp-servers", "compliance")
GOLDEN = os.path.join(os.path.dirname(__file__), "fixtures", "compliance_bundle_golden.json")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)

CR_URL = "https://mcp-compliance-server-abc123-uc.a.run.app"
SA_EMAIL = "sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com"

IAP_SPECS = [
    "make a new cloud run service but restrict access, do not allow unauthenticated",
    "internal web app with IAP single sign-on for company employees",
    "employee directory portal requiring corporate sso login",
    "Please create two cloud run services. PLease make both of the cloud run services protected with IDP.",
    "an admin console behind Identity-Aware Proxy",
]


# ============================================================================================ fixtures / fakes
@pytest.fixture()
def gw(monkeypatch):
    from fd4g_support import real_modules

    real_modules(monkeypatch)
    for k in ("PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "GEMINI_API_KEY", "GOOGLE_API_KEY", "K_SERVICE",
              "REGION", "COMPLIANCE_MODE"):
        monkeypatch.delenv(k, raising=False)
    spec = importlib.util.spec_from_file_location("compliance_bundle_gw_main", os.path.join(GW_DIR, "main.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    yield mod
    mod.app.dependency_overrides.clear()


@pytest.fixture()
def server(monkeypatch):
    """The REAL mcp-servers/compliance app (main.py + service.py), loaded by path under unique names (RT F12)."""
    from fd4g_support import load_module, real_modules

    real_modules(monkeypatch)
    monkeypatch.delenv("PROJECT_ID", raising=False)
    svc = load_module(monkeypatch, "service", os.path.join(COMPLIANCE_DIR, "service.py"))
    main = load_module(monkeypatch, "compliance_bundle_server_main", os.path.join(COMPLIANCE_DIR, "main.py"))
    return SimpleNamespace(main=main, service=svc, client=TestClient(main.app))


class _FakeHttpx:
    """Stands in for the httpx module inside compliance_agent.handler; `respond(url, json, headers)` answers or raises."""

    def __init__(self, respond):
        self.respond = respond
        self.calls = []

    def Client(self, timeout=None, follow_redirects=None):  # noqa: N802 (mirrors httpx.Client)
        outer = self

        class _C:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def post(self, url, json=None, headers=None):
                outer.calls.append({"url": url, "json": json, "headers": dict(headers or {}), "timeout": timeout,
                                    "follow_redirects": follow_redirects})
                return outer.respond(url, json, headers)

        return _C()


class FakeMetadataServer:
    """A GCE/Cloud Run metadata server, as seen by google-auth's transport interface (request(url, method, ...)).

    google.oauth2.id_token.fetch_id_token runs its real code path against it: ping -> service-account info ->
    identity?audience=... It mints an unsigned JWT whose `aud` is the requested audience.
    """

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    @staticmethod
    def _r(status, data, ctype):
        return SimpleNamespace(status=status, data=data, headers={"metadata-flavor": "Google", "content-type": ctype})

    def __call__(self, url, method="GET", body=None, headers=None, timeout=None, **kw):
        parts = urlsplit(url)
        self.calls.append({"url": url, "path": parts.path, "query": parse_qs(parts.query), "headers": dict(headers or {})})
        if parts.path.endswith("/service-accounts/default/"):
            info = {"email": SA_EMAIL, "aliases": ["default"], "scopes": []}
            return self._r(200, json.dumps(info).encode(), "application/json")
        if parts.path.endswith("/service-accounts/default/identity"):
            if self.fail:
                return self._r(500, b"metadata server error", "text/plain")
            aud = parse_qs(parts.query)["audience"][0]
            b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=")  # noqa: E731
            claims = {"aud": aud, "email": SA_EMAIL, "iss": "https://accounts.google.com", "exp": int(time.time()) + 3600}
            return self._r(200, b64({"alg": "RS256", "typ": "JWT"}) + b"." + b64(claims) + b".c2ln", "text/html")
        return self._r(200, b"", "text/html")  # ping

    def identity_calls(self):
        return [c for c in self.calls if c["path"].endswith("/identity")]


def _jwt_claims(bearer):
    token = bearer.split(" ", 1)[1]
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def _resp(status_code, payload):
    return SimpleNamespace(status_code=status_code, json=lambda: copy.deepcopy(payload))


def _raise(exc):
    def _f(*a, **k):
        raise exc
    return _f


CONTRACT = 3  # compliance-profile-explicit


def _v2(**over):
    """A valid current-contract (v3) STANDARD / public answer (the shape the server emits for a plain spec with no
    explicit profile). Name kept from contract v2."""
    body = {
        "contract_version": CONTRACT, "intent_source": "SPEC_KEYWORDS_LEGACY", "profile": "STANDARD",
        "profile_source": "DEFAULT_STANDARD", "requested_profile": None, "profile_suggestions": [],
        "is_regulated": False,
        "is_assured_workload": False, "compliance_regime": "NONE", "requires_cmek": False,
        "requires_audit_logging": False, "allowed_regions": ["us-central1"], "mandated_tasks": [],
        "description": "Standard Enterprise Baseline", "domain_restricted_sharing": False, "allowed_domains": [],
        "allow_unauthenticated": True, "enable_direct_iap": False, "enforce_private_ingress": False,
        "policy_matrix": {"has_constraints": False},
    }
    body.update(over)
    return body


def _metadata_reachable(monkeypatch):
    """Lane 2's hermetic guard answers "not on GCE" (google.auth.compute_engine._metadata.ping -> False), so
    fetch_id_token would never consult the injected FakeMetadataServer. Restore the probe for THIS test only; the
    guard's socket block still refuses any real metadata call."""
    from google.auth.compute_engine import _metadata

    monkeypatch.setattr(_metadata, "ping", lambda *a, **k: True)


def _handler(monkeypatch, respond, *, url="http://compliance.invalid", cloud_run=False, metadata=None, **kw):
    import compliance_agent.handler as ch

    if metadata is not None:
        _metadata_reachable(monkeypatch)

    for k in ("PROJECT_ID", "GEMINI_API_KEY", "K_SERVICE", "COMPLIANCE_MODE", "PARENT_FOLDER_ID",
              "GOOGLE_APPLICATION_CREDENTIALS"):
        monkeypatch.delenv(k, raising=False)
    if cloud_run:
        monkeypatch.setenv("K_SERVICE", "orchestrator-gateway-service")
    fake = _FakeHttpx(respond)
    monkeypatch.setattr(ch, "httpx", fake)
    h = ch.ComplianceAgentHandler(compliance_server_url=url, auth_request=metadata, **kw)
    h.genai_client = None  # remediation stays deterministic and offline
    h.model = None
    persisted = []
    monkeypatch.setattr(h, "_persist_audit_record", lambda *a, **k: persisted.append({"args": list(a), "kwargs": k}))
    monkeypatch.setattr(h, "_determine_approval_requirement", lambda has_conflicts: has_conflicts)
    return ch, h, fake, persisted


def _req(spec="HIPAA PHI; internal users only", **kw):
    from compliance_agent.schemas import ComplianceAuditRequest

    base = dict(product_id="hipaa-claims", spec_text=spec, task_dag=[{"step_id": "STEP-01"}], trace_id="t1",
                policy_matrix={"has_constraints": False})
    base.update(kw)
    return ComplianceAuditRequest(**base)


def _server_respond(server, seen=None):
    def respond(url, body, headers):
        if seen is not None:
            seen.append({"url": url, "headers": dict(headers or {})})
        r = server.client.post("/inspect-folder", json=body, headers=headers or {})
        return _resp(r.status_code, r.json())
    return respond


# ============================================================================ 1. 19f + contract: every outage shape
_V1_ANSWER = {k: v for k, v in _v2().items() if k not in ("contract_version", "intent_source", "enable_direct_iap")}

OUTAGES = [
    ("connection refused", _raise(ConnectionError("connection refused")), "TRANSPORT"),
    ("timeout", _raise(TimeoutError("read timed out after 60s")), "TRANSPORT"),
    ("HTTP 503", lambda *a: _resp(503, {"detail": "unavailable"}), "HTTP_STATUS"),
    ("HTTP 500", lambda *a: _resp(500, {"detail": "boom"}), "HTTP_STATUS"),
    ("HTTP 401", lambda *a: _resp(401, {"detail": "unauthenticated"}), "AUTH"),
    ("HTTP 403", lambda *a: _resp(403, {"detail": "forbidden"}), "AUTH"),
    ("HTTP 302", lambda *a: _resp(302, {}), "HTTP_STATUS"),
    ("empty object", lambda *a: _resp(200, {}), "CONTRACT"),
    ("JSON list", lambda *a: _resp(200, ["not", "an", "object"]), "CONTRACT"),
    ("JSON null", lambda *a: _resp(200, None), "CONTRACT"),
    ("invalid JSON", lambda *a: SimpleNamespace(status_code=200, json=_raise(ValueError("bad json"))), "INVALID_JSON"),
    ("v1 answer (old server)", lambda *a: _resp(200, _V1_ANSWER), "CONTRACT"),
    ("contract_version 1", lambda *a: _resp(200, _v2(contract_version=1)), "CONTRACT"),
    ("contract_version as string", lambda *a: _resp(200, _v2(contract_version="2")), "CONTRACT"),
    ("missing allow_unauthenticated", lambda *a: _resp(200, {k: v for k, v in _v2().items() if k != "allow_unauthenticated"}), "CONTRACT"),
    ("missing enable_direct_iap", lambda *a: _resp(200, {k: v for k, v in _v2().items() if k != "enable_direct_iap"}), "CONTRACT"),
    ("missing policy_matrix", lambda *a: _resp(200, {k: v for k, v in _v2().items() if k != "policy_matrix"}), "CONTRACT"),
    ("allow_unauthenticated as string", lambda *a: _resp(200, _v2(allow_unauthenticated="false")), "CONTRACT"),
    ("allow_unauthenticated null", lambda *a: _resp(200, _v2(allow_unauthenticated=None)), "CONTRACT"),
    ("IAP but public", lambda *a: _resp(200, _v2(is_regulated=True, enable_direct_iap=True, mandated_tasks=[
        {"step_id": "STEP-03D-DIRECT-IAP", "title": "IAP"}])), "CONTRACT"),
    ("IAP without its task", lambda *a: _resp(200, _v2(is_regulated=True, enable_direct_iap=True,
                                                       allow_unauthenticated=False)), "CONTRACT"),
    ("domain-restricted but public", lambda *a: _resp(200, _v2(is_regulated=True, domain_restricted_sharing=True)), "CONTRACT"),
    ("private but not regulated", lambda *a: _resp(200, _v2(allow_unauthenticated=False)), "CONTRACT"),
    ("private ingress without NEG/LB", lambda *a: _resp(200, _v2(is_regulated=True, enforce_private_ingress=True)), "CONTRACT"),
    ("task without step_id", lambda *a: _resp(200, _v2(is_regulated=True, mandated_tasks=[{"title": "x"}])), "CONTRACT"),
    ("empty profile", lambda *a: _resp(200, _v2(profile="")), "CONTRACT"),
    # compliance-profile-explicit (contract v3)
    ("contract_version 2 (keyword-guessing server)", lambda *a: _resp(200, _v2(contract_version=2)), "CONTRACT"),
    ("missing profile_source", lambda *a: _resp(200, {k: v for k, v in _v2().items() if k != "profile_source"}), "CONTRACT"),
    ("unknown profile_source", lambda *a: _resp(200, _v2(profile_source="SPEC_KEYWORDS")), "CONTRACT"),
    ("unknown profile", lambda *a: _resp(200, _v2(profile="HIPPA", profile_source="ASSURED_WORKLOADS_FOLDER")), "CONTRACT"),
    ("DEFAULT_STANDARD but regulated profile", lambda *a: _resp(200, _v2(profile="HIPAA", is_regulated=True)), "CONTRACT"),
    ("EXPLICIT_REQUEST for another profile", lambda *a: _resp(200, _v2(
        profile="HIPAA", is_regulated=True, profile_source="EXPLICIT_REQUEST", requested_profile="PCI_DSS")), "CONTRACT"),
    ("echoes a selection that was not sent", lambda *a: _resp(200, _v2(
        profile="HIPAA", is_regulated=True, profile_source="EXPLICIT_REQUEST", requested_profile="HIPAA")), "CONTRACT"),
    ("missing profile_suggestions", lambda *a: _resp(200, {k: v for k, v in _v2().items() if k != "profile_suggestions"}), "CONTRACT"),
]


@pytest.mark.parametrize("name, respond, failure", OUTAGES, ids=[o[0] for o in OUTAGES])
def test_every_outage_shape_is_compliance_unavailable_never_passed(monkeypatch, name, respond, failure):
    """Production shape: on Cloud Run, https Cloud Run URL, ID token from the (fake) metadata server."""
    ch, h, fake, persisted = _handler(monkeypatch, respond, url=CR_URL, cloud_run=True, metadata=FakeMetadataServer())
    from gate_errors import ErrorClass, GateUnavailableError

    assert h.require_remote_engine is True
    with pytest.raises(GateUnavailableError) as ei:
        h.audit_and_enrich(_req(spec="a simple public todo app"))
    err = ei.value
    assert err.error_class is ErrorClass.GATE_UNAVAILABLE and err.reason == "COMPLIANCE_UNAVAILABLE"
    assert err.details["failure"] == failure and err.details["product_id"] == "hipaa-claims"
    assert "compliance server unavailable" in str(err)
    body = err.to_body()
    assert body["passed"] is False and body["status"] == "FAILED"
    assert "allow_unauthenticated" not in body and "compliance_profile" not in body
    assert persisted == []  # no audit record for an outage
    assert len(fake.calls) == 1 and fake.calls[0]["timeout"] == ch.COMPLIANCE_SERVER_TIMEOUT_S


@pytest.mark.parametrize("name, respond, failure", OUTAGES[:6], ids=[o[0] for o in OUTAGES[:6]])
def test_outage_off_cloud_run_also_fails_closed_no_local_fallback(monkeypatch, name, respond, failure):
    # 19f + lane 17 R-4: there is no implicit embedded-engine fallback anywhere (the in-process engine is opt-in).
    _, h, _, persisted = _handler(monkeypatch, respond)
    from gate_errors import GateUnavailableError

    assert h.require_remote_engine is False
    with pytest.raises(GateUnavailableError) as ei:
        h.audit_and_enrich(_req(spec="HIPAA PHI patient records"))
    assert ei.value.reason == "COMPLIANCE_UNAVAILABLE" and persisted == []


def test_on_cloud_run_the_remote_engine_is_required_by_default(monkeypatch):
    ch, h, _, _ = _handler(monkeypatch, _raise(ConnectionError("down")))
    assert h.require_remote_engine is False
    monkeypatch.setenv("K_SERVICE", "orchestrator-gateway-service")
    assert ch.ComplianceAgentHandler(compliance_server_url=CR_URL).require_remote_engine is True


@pytest.mark.parametrize("kw, cloud_run", [({"require_remote_engine": True}, False), ({}, True)])
def test_inprocess_mode_is_refused_on_the_gate_and_on_cloud_run(monkeypatch, kw, cloud_run):
    _, h, fake, persisted = _handler(monkeypatch, lambda *a: _resp(200, _v2()), url=CR_URL, cloud_run=cloud_run,
                                     metadata=FakeMetadataServer(), mode="inprocess", **kw)
    from gate_errors import GateUnavailableError

    with pytest.raises(GateUnavailableError) as ei:
        h.audit_and_enrich(_req(spec="a simple public todo app"))
    assert ei.value.details["failure"] == "CONFIG" and "inprocess" in str(ei.value)
    assert fake.calls == [] and persisted == []


@pytest.mark.parametrize("value", ["embedded", "local", "remote ", "", "REMOTE", "inprocess"])
def test_compliance_mode_env_exact_values(monkeypatch, value):
    _, h, fake, _ = _handler(monkeypatch, lambda *a: _resp(200, _v2()))
    monkeypatch.setenv("COMPLIANCE_MODE", value)
    from gate_errors import GateUnavailableError

    if value.strip().lower() in ("remote", ""):
        assert h.audit_and_enrich(_req(spec="a simple public todo app")).status == "PASSED"
        assert len(fake.calls) == 1
    elif value == "inprocess":
        assert h.audit_and_enrich(_req(spec="a simple public todo app")).status == "PASSED"
        assert fake.calls == []  # the same server function, in this process; no HTTP
    else:
        with pytest.raises(GateUnavailableError) as ei:
            h.audit_and_enrich(_req(spec="a simple public todo app"))
        assert ei.value.details["failure"] == "CONFIG" and fake.calls == []


def test_valid_remote_answer_passes_and_is_used(monkeypatch):
    remote = _v2(profile="HIPAA", is_regulated=True, requires_cmek=True, requires_audit_logging=True,
                 allow_unauthenticated=False, allowed_domains=["example.com"], profile_source="EXPLICIT_REQUEST",
                 requested_profile="HIPAA")
    _, h, fake, persisted = _handler(monkeypatch, lambda *a: _resp(200, remote), url=CR_URL, cloud_run=True,
                                     metadata=FakeMetadataServer())
    res = h.audit_and_enrich(_req(compliance_profile="HIPAA"))
    assert res.compliance_profile == "HIPAA" and res.is_regulated is True and res.status == "ENRICHED"
    assert res.compliance_profile_source == "EXPLICIT_REQUEST"
    assert res.allow_unauthenticated is False and res.allowed_domains == ["example.com"]
    assert fake.calls[0]["url"] == f"{CR_URL}/inspect-folder" and fake.calls[0]["follow_redirects"] is False
    assert fake.calls[0]["json"] == {"folder_id": "", "spec_text": "HIPAA PHI; internal users only",
                                     "compliance_profile": "HIPAA"}
    assert persisted  # the audit record is still written on a real answer


# ============================================================================ 2. gateway route (pipeline gate)
def _route_body(spec="a simple public todo app"):
    return {"product_id": "todo", "trace_id": "t1", "spec_text": spec, "task_dag": [{"step_id": "STEP-01-APIS"}],
            "policy_matrix": {"has_constraints": False}}


def test_gateway_route_turns_a_real_outage_into_503_not_public_passed(gw, monkeypatch):
    import compliance_agent.handler as ch

    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://compliance.invalid")
    monkeypatch.setattr(ch, "httpx", _FakeHttpx(_raise(ConnectionError("compliance MCP unreachable"))))
    persisted = []
    monkeypatch.setattr(ch.ComplianceAgentHandler, "_persist_audit_record", lambda self, *a, **k: persisted.append(a))
    r = TestClient(gw.app).post("/agent/compliance/audit", json=_route_body())
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["error_class"] == "GATE_UNAVAILABLE" and body["reason"] == "COMPLIANCE_UNAVAILABLE"
    assert body["passed"] is False and "allow_unauthenticated" not in body and "compliance_profile" not in body
    assert "compliance server unavailable" in body["summary"]  # the handler's typed error, not a crash wrapper
    assert persisted == []


def test_gateway_route_handler_crash_is_503_not_public_passed(gw, monkeypatch):
    # Lane 13 F4 (2fdec06): any other exception in the route is 503, not PASSED/public.
    import compliance_agent.handler as ch

    monkeypatch.setattr(ch.ComplianceAgentHandler, "audit_and_enrich", _raise(KeyError("unexpected")))
    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://compliance.invalid")   # FALLBACK-URLS: reach the handler
    r = TestClient(gw.app).post("/agent/compliance/audit", json={"product_id": "todo", "trace_id": "t1"})
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["error_class"] == "GATE_UNAVAILABLE" and body["reason"] == "COMPLIANCE_UNAVAILABLE"
    assert body["passed"] is False and "allow_unauthenticated" not in body


def test_gateway_route_never_uses_inprocess_even_if_env_asks(gw, monkeypatch):
    import compliance_agent.handler as ch

    monkeypatch.setenv("COMPLIANCE_MODE", "inprocess")
    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://compliance.invalid")
    monkeypatch.setattr(ch, "httpx", _FakeHttpx(lambda *a: _resp(200, _v2())))
    r = TestClient(gw.app).post("/agent/compliance/audit", json=_route_body())
    assert r.status_code == 503 and r.json()["details"]["failure"] == "CONFIG"


def test_gateway_route_on_cloud_run_refuses_an_unknown_compliance_url(gw, monkeypatch):
    # FALLBACK-URLS: with no COMPLIANCE_SERVER_URL and no Cloud Run lookup, resolve_service_url raises a typed
    # SERVICE_URL_UNKNOWN (it no longer guesses http://mcp-compliance-server:8080): refused, nothing sent.
    import compliance_agent.handler as ch

    monkeypatch.setenv("K_SERVICE", "orchestrator-gateway-service")
    monkeypatch.setattr(gw, "db", _fd4f_FakeDB())  # on Cloud Run the route needs a store (RT F3)
    monkeypatch.delenv("COMPLIANCE_SERVER_URL", raising=False)
    monkeypatch.delenv("REGION", raising=False)
    fake = _FakeHttpx(lambda *a: _resp(200, _v2()))
    monkeypatch.setattr(ch, "httpx", fake)
    r = TestClient(gw.app).post("/agent/compliance/audit", json=_route_body())
    body = r.json()
    assert r.status_code == 503 and body["error_class"] == "GATE_UNAVAILABLE"
    assert body["reason"] == "SERVICE_URL_UNKNOWN" and body["details"]["service"] == "mcp-compliance-server"
    assert ":8080" not in r.text and "a.run.app" not in r.text and fake.calls == []


def test_gateway_route_on_cloud_run_refuses_an_http_override_url(gw, monkeypatch):
    # An http:// override (not an https Cloud Run URL) is still refused by the handler, nothing sent.
    import compliance_agent.handler as ch

    monkeypatch.setenv("K_SERVICE", "orchestrator-gateway-service")
    monkeypatch.setattr(gw, "db", _fd4f_FakeDB())
    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://mcp-compliance-server:8080")
    fake = _FakeHttpx(lambda *a: _resp(200, _v2()))
    monkeypatch.setattr(ch, "httpx", fake)
    r = TestClient(gw.app).post("/agent/compliance/audit", json=_route_body())
    assert r.status_code == 503 and r.json()["details"]["failure"] == "CONFIG"
    assert "http://mcp-compliance-server:8080" in r.json()["summary"] and fake.calls == []


def test_gateway_route_end_to_end_with_id_token_and_v2_server(gw, server, monkeypatch):
    """Gateway route -> handler -> (ID token from the fake metadata server) -> real compliance server app."""
    import compliance_agent.handler as ch

    monkeypatch.setenv("K_SERVICE", "orchestrator-gateway-service")
    monkeypatch.setattr(gw, "db", _fd4f_FakeDB())  # on Cloud Run the route needs a store (RT F3)
    monkeypatch.setenv("COMPLIANCE_SERVER_URL", CR_URL)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    md, seen = FakeMetadataServer(), []
    _metadata_reachable(monkeypatch)
    monkeypatch.setattr(ch, "httpx", _FakeHttpx(_server_respond(server, seen)))
    real_init = ch.ComplianceAgentHandler.__init__
    monkeypatch.setattr(ch.ComplianceAgentHandler, "__init__",
                        lambda self, *a, **k: real_init(self, *a, **{**k, "auth_request": md}))
    monkeypatch.setattr(ch.ComplianceAgentHandler, "_persist_audit_record", lambda self, *a, **k: None)
    monkeypatch.setattr(ch.ComplianceAgentHandler, "_determine_approval_requirement", lambda self, c: c)
    c = TestClient(gw.app)

    r = c.post("/agent/compliance/audit", json=_route_body("internal web app with IAP single sign-on"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enable_direct_iap"] is True and body["allow_unauthenticated"] is False
    assert "STEP-03D-DIRECT-IAP" in [t["step_id"] for t in body["injected_tasks"]]
    assert _jwt_claims(seen[-1]["headers"]["Authorization"])["aud"] == CR_URL

    r = c.post("/agent/compliance/audit", json=_route_body("a simple public todo app"))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "PASSED" and r.json()["allow_unauthenticated"] is True


# ============================================================================ 3. ID token (R-4)
def test_id_token_attached_with_the_service_origin_as_audience(monkeypatch):
    md = FakeMetadataServer()
    _, h, fake, _ = _handler(monkeypatch, lambda *a: _resp(200, _v2()), url=CR_URL + "/", cloud_run=True, metadata=md)
    h.audit_and_enrich(_req(spec="a simple public todo app"))
    (ident,) = md.identity_calls()
    assert ident["query"]["audience"] == [CR_URL] and ident["query"]["format"] == ["full"]
    assert ident["headers"].get("metadata-flavor") == "Google"
    auth = fake.calls[0]["headers"]["Authorization"]
    assert auth.startswith("Bearer ") and _jwt_claims(auth)["aud"] == CR_URL
    assert fake.calls[0]["url"] == f"{CR_URL}/inspect-folder"


def test_id_token_mint_failure_fails_closed_without_calling(monkeypatch):
    _, h, fake, persisted = _handler(monkeypatch, lambda *a: _resp(200, _v2()), url=CR_URL, cloud_run=True,
                                     metadata=FakeMetadataServer(fail=True))
    from gate_errors import GateUnavailableError

    with pytest.raises(GateUnavailableError) as ei:
        h.audit_and_enrich(_req(spec="a simple public todo app"))
    assert ei.value.details["failure"] == "AUTH" and fake.calls == [] and persisted == []


def test_run_app_url_off_cloud_run_without_identity_fails_closed(monkeypatch):
    # Off Cloud Run a run.app URL still needs a token; with no usable identity the call fails closed (no tokenless try).
    _, h, fake, _ = _handler(monkeypatch, lambda *a: _resp(200, _v2()), url=CR_URL)
    monkeypatch.setattr(h, "_fetch_id_token", _raise(RuntimeError("no identity")))
    from gate_errors import GateUnavailableError

    with pytest.raises(GateUnavailableError) as ei:
        h.audit_and_enrich(_req(spec="a simple public todo app"))
    assert ei.value.details["failure"] == "AUTH" and fake.calls == []


NOT_ALLOWLISTED = [
    "http://mcp-compliance-server:8080",
    "http://localhost:8080",
    "http://mcp-compliance-server-abc123-uc.a.run.app",
    "https://evil.example.com",
    "https://mcp-compliance-server-abc123-uc.a.run.app.evil.example.com",
    "https://run.app",
    "https://user:pw@mcp-compliance-server-abc123-uc.a.run.app",
    "https://mcp-compliance-server-abc123-uc.a.run.app:8443",
    "ftp://mcp-compliance-server-abc123-uc.a.run.app",
]


@pytest.mark.parametrize("url", NOT_ALLOWLISTED)
def test_no_token_to_non_allowlisted_urls_off_cloud_run(monkeypatch, url):
    md = FakeMetadataServer()
    _, h, fake, _ = _handler(monkeypatch, lambda *a: _resp(200, _v2()), url=url, metadata=md)
    h.audit_and_enrich(_req(spec="a simple public todo app"))
    assert md.calls == []  # the metadata server is never asked for a token
    assert "Authorization" not in fake.calls[0]["headers"]


@pytest.mark.parametrize("url", NOT_ALLOWLISTED)
def test_non_allowlisted_urls_are_refused_on_cloud_run(monkeypatch, url):
    md = FakeMetadataServer()
    _, h, fake, _ = _handler(monkeypatch, lambda *a: _resp(200, _v2()), url=url, cloud_run=True, metadata=md)
    from gate_errors import GateUnavailableError

    with pytest.raises(GateUnavailableError) as ei:
        h.audit_and_enrich(_req(spec="a simple public todo app"))
    assert ei.value.details["failure"] == "CONFIG" and md.calls == [] and fake.calls == []


@pytest.mark.parametrize("url, aud", [
    (CR_URL, CR_URL),
    (CR_URL + "/", CR_URL),
    (CR_URL + ":443", CR_URL),
    ("https://MCP-Compliance-Server-abc123-uc.a.run.app", CR_URL),
    ("https://mcp-compliance-server-123456789012.us-central1.run.app", "https://mcp-compliance-server-123456789012.us-central1.run.app"),
] + [(u, None) for u in NOT_ALLOWLISTED] + [("", None), ("not a url", None), ("https://[::1", None)])
def test_id_token_audience_table(url, aud):
    from compliance_agent.handler import id_token_audience

    assert id_token_audience(url) == aud


# ============================================================================ 4. server contract v2 + moved intent (R-3)
def test_server_health_and_answer_carry_contract_v2(server):
    assert server.client.get("/health").json()["contract_version"] == CONTRACT
    body = server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": "a todo app"}).json()
    assert body["contract_version"] == CONTRACT and body["intent_source"] == "SPEC_KEYWORDS_LEGACY"
    assert body["profile_source"] == "DEFAULT_STANDARD" and body["requested_profile"] is None
    assert body["enable_direct_iap"] is False and body["allow_unauthenticated"] is True
    from compliance_agent.schemas import RemoteInspectResponseV2

    RemoteInspectResponseV2.model_validate(body)


def test_server_do_no_harm_specs_without_ingress_keywords_answer_as_v1(server):
    # Every pre-bundle field of the answer is unchanged; v2 only adds contract_version / intent_source /
    # enable_direct_iap (false). Golden answers captured from main@8f9314a's server.
    # compliance-profile-explicit: the golden regulated answers were keyword-chosen; the same answer now needs the
    # explicit profile, and the same spec without it is STANDARD.
    golden = json.load(open(GOLDEN))
    for name, spec in golden["server_specs"].items():
        want = golden["answers_v1"][name]
        explicit = None if want["profile"] == "STANDARD" else want["profile"]
        body = server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": spec,
                                                           "compliance_profile": explicit}).json()
        new = {k: body.pop(k) for k in ("contract_version", "intent_source", "enable_direct_iap", "profile_source",
                                        "requested_profile")}
        assert new == {"contract_version": CONTRACT, "intent_source": "SPEC_KEYWORDS_LEGACY", "enable_direct_iap": False,
                       "profile_source": "EXPLICIT_REQUEST" if explicit else "DEFAULT_STANDARD",
                       "requested_profile": explicit}
        suggestions = body.pop("profile_suggestions")
        assert want["profile"] not in [s["profile"] for s in suggestions]
        # PRIVATE-INGRESS-EARLY-STOP: additive report of what asked for the flag; the decision fields stay golden.
        assert bool(body.pop("private_ingress_sources")) == want["enforce_private_ingress"], name
        body.pop("private_ingress_spec_terms")
        assert body == want, name
        if explicit:
            implicit = server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": spec}).json()
            assert implicit["profile"] == "STANDARD" and implicit["profile_source"] == "DEFAULT_STANDARD"
            assert explicit in [s["profile"] for s in implicit["profile_suggestions"]]


@pytest.mark.parametrize("spec", IAP_SPECS)
@pytest.mark.parametrize("org_allows", [True, False])
def test_iap_spec_can_never_come_out_public(server, monkeypatch, spec, org_allows):
    monkeypatch.setattr(server.main.service, "inspect_org_policies",
                        lambda folder_id: {"allow_unauthenticated": org_allows, "has_constraints": False})
    body = server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": spec}).json()
    assert body["enable_direct_iap"] is True and body["allow_unauthenticated"] is False
    assert body["is_regulated"] is True
    assert "STEP-03D-DIRECT-IAP" in [t["step_id"] for t in body["mandated_tasks"]]


@pytest.mark.parametrize("spec, expect", [
    ("billing service with domain-restricted sharing", {"domain_restricted_sharing": True, "allow_unauthenticated": False}),
    ("backend worker with no public IP, internal only", {"enforce_private_ingress": True}),
    ("an api; do not allow unauthenticated callers", {"allow_unauthenticated": False, "enable_direct_iap": False}),
    ("a simple public todo app", {"allow_unauthenticated": True, "enable_direct_iap": False,
                                  "domain_restricted_sharing": False, "enforce_private_ingress": False}),
])
def test_server_intent_combines_most_restrictive(server, spec, expect):
    body = server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": spec}).json()
    for k, v in expect.items():
        assert body[k] is v, (k, body[k])
    if body["enforce_private_ingress"]:
        assert {"STEP-06B-SERVERLESS-NEG", "STEP-06C-HTTPS-LOAD-BALANCER"} <= {t["step_id"] for t in body["mandated_tasks"]}
    if not body["allow_unauthenticated"]:
        assert body["is_regulated"] is True  # never the gateway's public STANDARD fast path


def test_org_policy_restriction_still_wins_over_a_plain_spec(server, monkeypatch):
    monkeypatch.setattr(server.main.service, "inspect_org_policies", lambda folder_id: {
        "domain_restricted_sharing": True, "allowed_domains": ["example.com"], "allow_unauthenticated": False,
        "has_constraints": True})
    body = server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": "a simple public todo app"}).json()
    assert body["allow_unauthenticated"] is False and body["domain_restricted_sharing"] is True
    assert body["allowed_domains"] == ["example.com"]


@pytest.mark.parametrize("spec", IAP_SPECS + [
    "a simple public todo app",
    "HIPAA compliant portal storing patient electronic health records (ePHI)",
    "Deploy enterprise billing service with domain-restricted sharing policy",
    "Backend worker with no public IP and private ingress internal only",
    "Deploy a basic internal reporting dashboard",
])
def test_gateway_remote_and_inprocess_answers_are_identical(server, monkeypatch, spec):
    """One implementation: the gateway's explicit in-process mode and the HTTP server give the same decision."""
    _, remote_h, _, remote_p = _handler(monkeypatch, _server_respond(server))
    remote = remote_h.audit_and_enrich(_req(spec=spec, policy_matrix=None)).model_dump(mode="json")
    _, inproc_h, fake, inproc_p = _handler(monkeypatch, _raise(AssertionError("no HTTP in-process")), mode="inprocess")
    inproc = inproc_h.audit_and_enrich(_req(spec=spec, policy_matrix=None)).model_dump(mode="json")

    def _untimed(persisted):  # FD-4R R-6: the v2 record carries its decision time
        return [{"args": [{k: v for k, v in p["args"][0].items() if k not in ("decided_at", "timestamp")}],
                 "kwargs": p["kwargs"]} for p in persisted]

    assert remote == inproc and _untimed(remote_p) == _untimed(inproc_p) and fake.calls == []


def test_inprocess_engine_keeps_the_old_embedded_answers(monkeypatch):
    # The apps/orchestrator-gateway/test_compliance_agent.py cases, through the explicit in-process mode.
    dag = [
        {"step_id": "STEP-01-APIS", "title": "Enable APIs", "depends_on": []},
        {"step_id": "STEP-02-DB-REGISTRY", "title": "Create Database", "depends_on": ["STEP-01-APIS"]},
        {"step_id": "STEP-03-IAM", "title": "Create Service Accounts", "depends_on": ["STEP-01-APIS"]},
        {"step_id": "STEP-04-APP-CODE", "title": "Generate Code", "depends_on": ["STEP-03-IAM"]},
        {"step_id": "STEP-06-COMPUTE", "title": "Deploy Cloud Run", "depends_on": ["STEP-04-APP-CODE"]},
    ]
    _, h, _, _ = _handler(monkeypatch, _raise(AssertionError("no HTTP")), mode="inprocess")
    res = h.audit_and_enrich(_req(spec="Deploy a basic internal reporting dashboard", task_dag=copy.deepcopy(dag),
                                  policy_matrix=None))
    assert res.compliance_profile == "STANDARD" and res.status == "PASSED" and res.allow_unauthenticated is True
    res = h.audit_and_enrich(_req(spec="HIPAA compliant portal storing patient electronic health records (ePHI)",
                                  task_dag=copy.deepcopy(dag), policy_matrix=None))
    assert res.compliance_profile == "STANDARD" and res.status == "PASSED"  # spec words never choose the profile
    assert [a["profile"] for a in res.profile_advisories] == ["HIPAA"]
    res = h.audit_and_enrich(_req(spec="HIPAA compliant portal storing patient electronic health records (ePHI)",
                                  task_dag=copy.deepcopy(dag), policy_matrix=None, compliance_profile="HIPAA"))
    assert res.compliance_profile == "HIPAA" and res.requires_cmek is True
    code_step = next(s for s in res.enriched_dag if s["step_id"] == "STEP-04-APP-CODE")
    assert "STEP-03B-KMS-CMEK" in code_step["depends_on"]
    res = h.audit_and_enrich(_req(spec="Deploy enterprise billing service with domain-restricted sharing policy",
                                  task_dag=copy.deepcopy(dag), policy_matrix=None,
                                  plan_markdown="# Enterprise Plan\n\n## 3. Security, IAM & Governance Assessment"))
    assert res.domain_restricted_sharing is True and res.allow_unauthenticated is False
    assert "Domain-Restricted Sharing" in res.plan_markdown
    res = h.audit_and_enrich(_req(spec="Backend worker with no public IP and private ingress internal only",
                                  task_dag=copy.deepcopy(dag), policy_matrix=None))
    assert res.enforce_private_ingress is True
    assert {"STEP-06B-SERVERLESS-NEG", "STEP-06C-HTTPS-LOAD-BALANCER"} <= {s["step_id"] for s in res.enriched_dag}


# ============================================================================ 5. Do No Harm: byte-identical enrichment
_GOLDEN = json.load(open(GOLDEN))


@pytest.mark.parametrize("case", _GOLDEN["cases"], ids=[c["name"] for c in _GOLDEN["cases"]])
def test_do_no_harm_valid_answer_enriched_byte_identically_to_pre_bundle(monkeypatch, case):
    v1 = _GOLDEN["answers_v1"][case["answer"]]
    # compliance-profile-explicit: a regulated golden answer is served as a folder-regime answer (the request carries
    # no explicit profile); the v3 fields are popped below and everything else must stay byte-identical.
    regulated = v1["profile"] != "STANDARD"
    v2 = dict(copy.deepcopy(v1), contract_version=CONTRACT, intent_source="SPEC_KEYWORDS_LEGACY",
              enable_direct_iap=v1.get("enable_direct_iap", False),
              profile_source="ASSURED_WORKLOADS_FOLDER" if regulated else "DEFAULT_STANDARD",
              requested_profile=None, profile_suggestions=[])
    _, h, _, persisted = _handler(monkeypatch, lambda *a: _resp(200, v2), url=CR_URL, cloud_run=True,
                                  metadata=FakeMetadataServer())
    from compliance_agent.schemas import ComplianceAuditRequest

    # PRIVATE-INGRESS-EARLY-STOP: the pipeline gate needs the architect's record; these golden requests carry none, so
    # they are treated as plans whose compute record has no Cloud Run service.
    monkeypatch.setattr(h, "_planned_cloud_run_services", lambda req: [])
    res = h.audit_and_enrich(ComplianceAuditRequest(**copy.deepcopy(case["request"])))
    dumped = res.model_dump(mode="json")
    assert dumped.pop("compliance_profile_source") == v2["profile_source"]
    assert dumped.pop("profile_advisories") == []
    # ACCESS-INTERNAL-SERVICE-ADVISORY: additive, report-only field; these direct-handler requests pass no access
    # reader, so it is always empty and everything else stays byte-identical.
    assert dumped.pop("access_advisories") == [] and dumped.pop("access_advisories_omitted") == 0
    got = json.dumps(dumped, sort_keys=True, separators=(",", ":"))
    want = json.dumps(case["response"], sort_keys=True, separators=(",", ":"))
    assert got == want
    # FD-4R R-6: the persisted decision is now ONE complete record (schema v2). Do No Harm on what was persisted
    # before: every v1 field keeps its exact value; the added fields are the response's own decision fields.
    [old] = case["persisted"]
    [new] = json.loads(json.dumps(persisted))
    assert new["kwargs"] == {} and len(new["args"]) == 1
    record = new["args"][0]
    pid, trace, profile, is_regulated, summary = old["args"]
    v1 = {"product_id": pid, "trace_id": trace, "compliance_profile": profile, "is_regulated": is_regulated,
          "summary": summary, "enable_direct_iap": False}
    for k, v in old["kwargs"].items():
        v1[k] = (v or {}) if k == "policy_matrix" else ((v or []) if k in ("allowed_domains", "policy_conflicts") else v)
    assert {k: record[k] for k in v1} == v1
    resp = case["response"]
    assert record["schema_version"] == 2 and record["status"] == resp["status"]
    for k in ("enforce_private_ingress", "requires_cmek", "requires_audit_logging", "injected_tasks",
              "allow_unauthenticated", "enable_direct_iap", "domain_restricted_sharing", "allowed_domains"):
        assert record[k] == resp[k], k
    assert record["contract_version"] == CONTRACT and record["intent_source"] == "SPEC_KEYWORDS_LEGACY"
    assert "plan_markdown" not in record and "enriched_dag" not in record
    # compliance-profile-explicit (integration): the 3 additive v2 fields.
    assert record["profile_source"] == v2["profile_source"]
    assert record["requested_profile"] is None
    assert record["profile_advisories"] == []
    assert record["access_advisories"] == [] and record["access_advisories_omitted"] == 0


# ============================================================================ 6. deployed layout (no monorepo)
def test_handler_imports_and_fails_closed_in_the_deployed_image_layout(monkeypatch, tmp_path):
    """The gateway image holds apps/orchestrator-gateway only: the handler must import there (no import-time monorepo
    path), the remote path works, and the explicit in-process mode fails closed instead of crashing."""
    import shutil

    from gate_errors import GateUnavailableError

    app = tmp_path / "workspace"
    shutil.copytree(os.path.join(GW_DIR, "compliance_agent"), app / "deployed_compliance_agent")
    monkeypatch.syspath_prepend(str(app))
    for k in ("PROJECT_ID", "GEMINI_API_KEY", "K_SERVICE", "COMPLIANCE_MODE", "GOOGLE_APPLICATION_CREDENTIALS"):
        monkeypatch.delenv(k, raising=False)
    mod = importlib.import_module("deployed_compliance_agent.handler")
    monkeypatch.setitem(sys.modules, "deployed_compliance_agent.handler", mod)
    monkeypatch.setattr(mod, "httpx", _FakeHttpx(lambda *a: _resp(200, _v2())))
    schemas = importlib.import_module("deployed_compliance_agent.schemas")

    def make(**kw):
        h = mod.ComplianceAgentHandler(compliance_server_url="http://compliance.invalid", **kw)
        h.genai_client, h.model = None, None
        h._persist_audit_record = lambda *a, **k: None
        h._determine_approval_requirement = lambda has_conflicts: has_conflicts
        return h

    req = schemas.ComplianceAuditRequest(product_id="todo", spec_text="a todo app", task_dag=[], trace_id="t1")
    assert make().audit_and_enrich(req).status == "PASSED"
    with pytest.raises(GateUnavailableError) as ei:
        make(mode="inprocess").audit_and_enrich(req)
    assert ei.value.details["failure"] == "INPROCESS"


# ============================================================================ 7. timeout budget (red-team F2)
COLD_START_MARGIN_S = 20.0  # Cloud Run cold start of mcp-compliance-server + one access-token refresh


class _SlowGoogleApis:
    """An AuthorizedSession stand-in where every Google API answers 503 (slow path: v2 empty -> all CRM v3 checks)."""

    def __init__(self):
        self.timeouts = []

    def _r(self, url, timeout):
        self.timeouts.append((urlsplit(url).netloc, timeout))
        return SimpleNamespace(status_code=503, json=lambda: {})

    def get(self, url, timeout=None, **kw):
        return self._r(url, timeout)

    def post(self, url, json=None, timeout=None, **kw):
        return self._r(url, timeout)


@pytest.mark.parametrize("org_env", ["123456789", None])
def test_servers_worst_case_is_the_sum_of_the_timeouts_it_actually_uses(server, monkeypatch, org_env):
    """RT14-33: the Assured Workloads check (organization lookup through the folder ancestry when ORGANIZATION_ID is
    unset, then the workloads list) shares ASSURED_WORKLOADS_TIMEOUT_S, so the worst case is unchanged."""
    if org_env:
        monkeypatch.setenv("ORGANIZATION_ID", org_env)
    else:
        monkeypatch.delenv("ORGANIZATION_ID", raising=False)
    svc = server.service.ComplianceService(project_id="mock-stackvend-project")
    svc._session = _SlowGoogleApis()
    out = svc.inspect_folder("folders/123", "a simple public todo app")
    assert out["contract_version"] == CONTRACT
    assert out["assured_workloads_check"]["status"] == "FAILED"   # every API answers 503 here: typed, not silent
    hosts = [h for h, _ in svc._session.timeouts]
    first = "assuredworkloads.googleapis.com" if org_env else "cloudresourcemanager.googleapis.com"
    assert hosts == ([first, "orgpolicy.googleapis.com"]
                     + ["cloudresourcemanager.googleapis.com"] * len(server.service.CRM_V3_FALLBACK_CONSTRAINTS))
    aw_time = svc._session.timeouts[0][1]
    assert aw_time <= server.service.ASSURED_WORKLOADS_TIMEOUT_S
    assert sum(t for _, t in svc._session.timeouts) <= server.service.INSPECT_FOLDER_WORST_CASE_S == 33.0
    if org_env:   # the list call alone gets the whole Assured Workloads budget: the worst case is reached exactly
        assert sum(t for _, t in svc._session.timeouts) == server.service.INSPECT_FOLDER_WORST_CASE_S


def test_gateway_budget_covers_the_servers_worst_case_plus_a_cold_start(server):
    import compliance_agent.handler as ch

    assert ch.COMPLIANCE_SERVER_TIMEOUT_S >= server.service.INSPECT_FOLDER_WORST_CASE_S + COLD_START_MARGIN_S
    # ...and stays well inside what calls the gateway: Workflows http.post default 300 s; Cloud Run request 1800 s.
    assert ch.COMPLIANCE_SERVER_TIMEOUT_S <= 120.0
