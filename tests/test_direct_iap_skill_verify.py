"""DIRECT-IAP-SKILL-VERIFY (register row): the guidance the code-writing AI receives for a Cloud Run Direct IAP workload.

Live defect: a generated app called ``verify_token`` without IAP's certs URL and with the OAuth secret as audience, so
every signed-in API call was a 401 ("Certificate for key id ... not found"), and it read the email header unverified.
The ``gcp-direct-iap`` skill's rules were also never reaching the code writers: skills are keyword-activated from a
``task_context`` no developer call site passes, and swarm prompts carry no skill block.

Real-verification checks run the real ``google-auth`` in a subprocess: other tests in this suite replace
``google.auth`` in ``sys.modules``, so importing it here could silently test a mock. Hermetic: no network, $0.
"""
import hermetic_guard  # noqa: F401  (first import)

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import textwrap
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared.builtin_skills_provider import DIRECT_IAP_VERIFICATION_RULES, get_builtin_skill_by_id  # noqa: E402
from developer_agent import prompt as P  # noqa: E402
from developer_agent.lead_orchestrator import LeadDeveloperOrchestrator  # noqa: E402
from developer_agent.swarm_dispatcher import SwarmDispatcher  # noqa: E402
from developer_agent.swarm_schemas import (JuniorPersona, JuniorTaskAssignment, LeadDeveloperDecompositionPlan,  # noqa: E402
                                           SwarmExecutionMode)
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse)

IAP_CERTS_URL = "https://www.gstatic.com/iap/verify/public_key"
AUDIENCE = "/projects/123456/locations/us-central1/services/admin"


# ---------------------------------------------------------------------------------------------- the guidance itself
@pytest.mark.parametrize("copy", [
    "apps/control-center/shared/builtin_skills_provider.py",
    "apps/orchestrator-gateway/shared/builtin_skills_provider.py",
    "mcp-servers/terraform/shared/builtin_skills_provider.py",
])
def test_every_copy_of_the_skills_provider_is_byte_identical(copy):
    with open(os.path.join(REPO_ROOT, "shared/builtin_skills_provider.py"), "rb") as source, \
            open(os.path.join(REPO_ROOT, copy), "rb") as replica:
        assert hashlib.sha256(source.read()).digest() == hashlib.sha256(replica.read()).digest()


def test_skill_pattern_a_is_the_verification_rules():
    body = get_builtin_skill_by_id("gcp-direct-iap")["instructions_markdown"]
    assert DIRECT_IAP_VERIFICATION_RULES in body
    assert "routes inspect `X-Goog-Authenticated-User-Email`" not in body


def test_rules_state_the_facts_the_live_defect_got_wrong():
    for fact in (IAP_CERTS_URL, "`X-Goog-IAP-JWT-Assertion`", "ES256", "https://cloud.google.com/iap",
                 "/projects/<project-number>/locations/<region>/services/<service-name>", "`K_SERVICE`",
                 "project/numeric-project-id", "instance/region", "`Metadata-Flavor: Google`", "HTTP 401",
                 "`google-auth`", "`requests`", "`cryptography`"):
        assert fact in DIRECT_IAP_VERIFICATION_RULES
    assert "never an OAuth client id" in DIRECT_IAP_VERIFICATION_RULES
    assert "unverified decode" in DIRECT_IAP_VERIFICATION_RULES
    assert "not even as a fallback" in DIRECT_IAP_VERIFICATION_RULES


def test_rules_tell_generated_tests_how_to_pass_in_the_qa_sandbox():
    # QA's untrusted env strips K_*, its metadata server answers for QA's own project, an unstubbed gstatic fetch
    # outlasts pytest's --timeout=60: following only "fake the certs transport" fails QA
    for fact in ("one named function, `iap_audience()`", "module-level variable", "`monkeypatch.setenv`",
                 "both metadata reads", "resets the app's cached audience"):
        assert fact in DIRECT_IAP_VERIFICATION_RULES


def test_rules_keep_key_and_metadata_calls_cheap_and_off_the_event_loop():
    # google-auth's verify_token re-fetches the keys on every call and takes the transport to cache them
    for fact in ("verify_token(assertion, cached_certs,", "`cached_certs(url, method=\"GET\", **kwargs)`",
                 "for 10 minutes", "only on a miss", "a 2-second `timeout`", "asyncio.to_thread(", "`async def`",
                 "resets the app's cached audience and cached keys"):
        assert fact in DIRECT_IAP_VERIFICATION_RULES


# ----------------------------------------------------------------------------- what google-auth really does (no mock)
_REAL_VERIFY = textwrap.dedent('''
    import json, sys, time
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from google.auth import crypt, jwt
    from google.oauth2 import id_token

    IAP_CERTS_URL, AUDIENCE = sys.argv[1:3]
    pem = lambda key: key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    private = lambda key: key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()).decode()
    key, other = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    keys = {"kid-1": pem(key)}  # the format of IAP's public_key endpoint: {kid: PEM public key}
    asked = []

    def transport(url, method="GET", **_):
        asked.append(url)
        body = keys if url == IAP_CERTS_URL else {"other-kid": "not IAP"}
        return type("R", (), {"status": 200, "data": json.dumps(body).encode()})()

    def token(signing=key, kid="kid-1", aud=AUDIENCE, iss="https://cloud.google.com/iap", email="op@example.com", age=0):
        now = int(time.time()) - age
        signer = crypt.ES256Signer.from_string(private(signing), kid)
        return jwt.encode(signer, {"iss": iss, "aud": aud, "email": email, "sub": "accounts.google.com:1",
                                   "iat": now, "exp": now + 600}).decode()

    def check(tok, certs_url=IAP_CERTS_URL, audience=AUDIENCE):
        try:
            claims = id_token.verify_token(tok, transport, audience=audience, certs_url=certs_url,
                                           clock_skew_in_seconds=30)
        except Exception as exc:  # google-auth raises InvalidValue / MalformedError / ValueError for a bad token
            return {"ok": False, "error": type(exc).__name__, "message": str(exc)}
        return {"ok": True, "email": claims["email"], "iss": claims["iss"]}

    results = {
        "valid": check(token()),
        "wrong_audience": check(token(aud="/projects/123456/apps/oauth-secret")),
        "wrong_issuer": check(token(iss="https://accounts.google.com")),
        "expired": check(token(age=3600)),
        "wrong_key": check(token(signing=other)),
        "unknown_kid": check(token(kid="kid-unknown")),
        "default_oauth_certs": check(token(), certs_url="https://www.googleapis.com/oauth2/v1/certs"),
    }
    print(json.dumps({"results": results, "asked": asked}))
''')


@pytest.fixture(scope="module")
def real_verification(tmp_path_factory):
    script = tmp_path_factory.mktemp("iap") / "verify_real.py"
    script.write_text(_REAL_VERIFY)
    done = subprocess.run([sys.executable, str(script), IAP_CERTS_URL, AUDIENCE], capture_output=True, text=True,
                          timeout=120, cwd=str(script.parent), env=hermetic_guard.child_env())
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_real_google_auth_accepts_a_token_signed_by_an_iap_format_key(real_verification):
    assert real_verification["results"]["valid"] == {"ok": True, "email": "op@example.com",
                                                     "iss": "https://cloud.google.com/iap"}
    assert IAP_CERTS_URL in real_verification["asked"]


@pytest.mark.parametrize("case", ["wrong_audience", "expired", "wrong_key", "unknown_kid"])
def test_real_google_auth_rejects(real_verification, case):
    assert real_verification["results"][case]["ok"] is False


def test_verify_token_does_not_check_the_issuer_so_the_rule_must(real_verification):
    assert real_verification["results"]["wrong_issuer"]["ok"] is True


def test_the_default_certs_url_reproduces_the_live_error(real_verification):
    result = real_verification["results"]["default_oauth_certs"]
    assert result["ok"] is False and "Certificate for key id" in result["message"]


# ---------------------------------------------------- an app and tests that follow the rule, as QA's sandbox runs them
# Real google-auth and real pytest in a child process, no K_* variables, every socket refused. The app and its tests are
# what a code writer following DIRECT_IAP_VERIFICATION_RULES produces (one named audience function, cached keys,
# metadata timeouts, a sync dependency; K_SERVICE set, both metadata reads stubbed, caches reset).
_RULE_APP = """import os, time
import requests
from fastapi import Depends, FastAPI, Header, HTTPException
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

CERTS_URL = "https://www.gstatic.com/iap/verify/public_key"
METADATA = "http://metadata.google.internal/computeMetadata/v1/"
_audience = None
_keys = {}


def iap_audience():
    global _audience
    if _audience:
        return _audience
    service = os.environ["K_SERVICE"]
    h = {"Metadata-Flavor": "Google"}
    number = requests.get(METADATA + "project/numeric-project-id", headers=h, timeout=2)
    region = requests.get(METADATA + "instance/region", headers=h, timeout=2)
    number.raise_for_status(); region.raise_for_status()
    _audience = f"/projects/{number.text}/locations/{region.text.rsplit('/', 1)[-1]}/services/{service}"
    return _audience


def cached_certs(url, method="GET", **kwargs):
    hit = _keys.get(url)
    if hit and time.monotonic() - hit[0] < 600:
        return hit[1]
    response = google_requests.Request()(url, method=method, **kwargs)
    if response.status == 200:
        _keys[url] = (time.monotonic(), response)
    return response


def require_user(x_goog_iap_jwt_assertion: str = Header(default="")):
    if not x_goog_iap_jwt_assertion:
        raise HTTPException(status_code=401)
    try:
        claims = id_token.verify_token(x_goog_iap_jwt_assertion, cached_certs, audience=iap_audience(),
                                       certs_url=CERTS_URL, clock_skew_in_seconds=30)
        if claims["iss"] != "https://cloud.google.com/iap":
            raise ValueError("issuer")
        return claims["email"]
    except Exception:
        raise HTTPException(status_code=401)


app = FastAPI()


@app.get("/api/me")
def me(user: str = Depends(require_user)):
    return {"user": user}
"""
_RULE_APP_TESTS = """import json, time
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from google.auth import crypt, jwt
import main

key, other = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
AUD = "/projects/123/locations/us-central1/services/admin"
fetches, meta = [], {"fail": False}


def transport(url, method="GET", **_):
    fetches.append(url)
    return type("R", (), {"status": 200, "data": json.dumps({"k1": pub}).encode()})()


class Meta:
    def __init__(self, text): self.text = text
    def raise_for_status(self): pass


def fake_get(url, headers=None, timeout=None):
    assert headers == {"Metadata-Flavor": "Google"} and timeout
    if meta["fail"]:
        raise OSError("metadata down")
    return Meta("123" if url.endswith("numeric-project-id") else "projects/123/regions/us-central1")


@pytest.fixture(autouse=True)
def iap_env(monkeypatch):
    monkeypatch.setenv("K_SERVICE", "admin")
    monkeypatch.setattr(main.requests, "get", fake_get)
    monkeypatch.setattr(main.google_requests, "Request", lambda: transport)
    monkeypatch.setattr(main, "_audience", None)
    main._keys.clear(); fetches.clear(); meta["fail"] = False


def token(signing=key, aud=AUD, iss="https://cloud.google.com/iap", age=0):
    now = int(time.time()) - age
    pem = signing.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return jwt.encode(crypt.ES256Signer.from_string(pem, "k1"),
                      {"iss": iss, "aud": aud, "email": "a@b.c", "iat": now, "exp": now + 600}).decode()


def call(tok):
    return TestClient(main.app).get("/api/me", headers={"X-Goog-IAP-JWT-Assertion": tok} if tok else {})


def test_valid():
    r = call(token())
    assert r.status_code == 200 and r.json() == {"user": "a@b.c"}


@pytest.mark.parametrize("kw", [dict(aud="/projects/9/x"), dict(iss="https://accounts.google.com"), dict(age=3600), dict(signing=other)])
def test_rejected(kw):
    assert call(token(**kw)).status_code == 401


def test_missing_header():
    assert call("").status_code == 401


def test_keys_fetched_once_for_two_requests():
    assert call(token()).status_code == call(token()).status_code == 200
    assert fetches == ["https://www.gstatic.com/iap/verify/public_key"]


def test_metadata_failure_is_401_and_not_cached():
    meta["fail"] = True
    assert call(token()).status_code == 401
    meta["fail"] = False
    assert call(token()).status_code == 200
"""
_NO_NETWORK_CONFTEST = """
import socket
def _refuse(*a, **k):
    raise OSError("no network in this test")
socket.getaddrinfo = _refuse
socket.create_connection = _refuse
socket.socket.connect = _refuse
"""


def test_an_app_and_tests_following_the_rule_pass_offline_without_k_variables(tmp_path):
    (tmp_path / "main.py").write_text(_RULE_APP)
    (tmp_path / "test_main.py").write_text(_RULE_APP_TESTS)
    (tmp_path / "conftest.py").write_text(_NO_NETWORK_CONFTEST)
    env = {k: v for k, v in hermetic_guard.child_env().items() if not k.startswith(("K_", "CLOUD_RUN_"))}
    done = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--no-header", "test_main.py"],
                          cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-2000:]


# ----------------------------------------------------------------------------------- the rule reaches the code writers
def _rule(enable_direct_iap=True, allow_unauthenticated=False, cloud_run=("admin",), others=()):
    return P.direct_iap_auth_rule(enable_direct_iap, allow_unauthenticated, cloud_run, others)


def test_rule_needs_direct_iap_in_effect_on_a_cloud_run_service():
    assert DIRECT_IAP_VERIFICATION_RULES in _rule()
    for not_iap in (False, None, "true", 1):
        assert _rule(enable_direct_iap=not_iap) == ""
    for public in (True, None, "false", 0):   # the module's condition is !allow_unauthenticated && enable_direct_iap
        assert _rule(allow_unauthenticated=public) == ""
    assert _rule(cloud_run=()) == "" and _rule(cloud_run=("",), others=("cluster",)) == ""


def test_all_cloud_run_rule_keeps_its_header_and_names_no_service():
    assert _rule(cloud_run=("api", "admin")) == _rule()
    assert "`api`" not in _rule(cloud_run=("api", "admin"))


def test_mixed_rule_names_exactly_the_services_behind_iap():
    rule = _rule(cloud_run=("api", "admin"), others=("cluster", "worker"))
    head = rule.split(":\n", 1)[0]
    assert head.index("`api`, `admin`") < head.index("`cluster`, `worker`")
    assert "only these Cloud Run services" in head and "never apply these rules" in head
    # APP-ADMIN-IAP-CONTRACT: the verification rules, then the app administrator rules (same gate)
    assert rule.endswith(DIRECT_IAP_VERIFICATION_RULES + P.DIRECT_IAP_APP_ADMIN_RULES)


def test_with_app_auth_rule_scopes_by_persona():
    rule = _rule()
    assert P.with_app_auth_rule("base", "", JuniorPersona.BACKEND_ENGINEER) == "base"
    assert P.with_app_auth_rule("base", rule, JuniorPersona.IAC_ENGINEER) == "base"
    assert P.with_app_auth_rule("base", rule, "IAC_ENGINEER") == "base"
    for persona in (JuniorPersona.BACKEND_ENGINEER, JuniorPersona.DATABASE_ENGINEER, JuniorPersona.TEST_ENGINEER,
                    JuniorPersona.DEVOPS_ENGINEER, "developer"):
        assert P.with_app_auth_rule("base", rule, persona) == f"base\n\n{rule}\n"


def test_developer_system_prompt_is_byte_identical_without_the_rule():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no firestore in tests"))):
        base = P.build_developer_system_prompt()
        assert DIRECT_IAP_VERIFICATION_RULES not in base  # a keyword-activated skill needs a task_context
        assert P.build_developer_system_prompt(app_auth_rule="") == base
        assert P.build_developer_system_prompt(app_auth_rule=None) == base
        assert DIRECT_IAP_VERIFICATION_RULES in P.build_developer_system_prompt(app_auth_rule=_rule())


def _lead_prompt(**kw):
    seen = []

    def gen(model, contents, config):
        seen.append(contents)
        raise ValueError("captured")
    client = MagicMock()
    client.models.generate_content.side_effect = gen
    with patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent", return_value=["m"]):
        LeadDeveloperOrchestrator(genai_client=client, model_name="m").decompose_specification(
            product_id="shop", spec_text="Spec", task_dag=[{"task_id": "s"}], service_names=("shop",), **kw)
    return seen[0]


def test_lead_prompt_gains_the_rule_only_when_given():
    base = _lead_prompt()
    rule = _rule()
    assert _lead_prompt(app_auth_rule="") == base and _lead_prompt(app_auth_rule=None) == base
    assert _lead_prompt(app_auth_rule=rule) == f"{base}\n\n{rule}"


def _junior_system_instruction(persona, rule):
    seen = []

    async def fake_model(prompt, system_instruction, model, trace_id=None, **_):
        seen.append(system_instruction)
        return {"a/x.py": "x = 1\n"}, 1
    dispatcher = SwarmDispatcher(model_name="m")
    dispatcher.app_auth_rule = rule
    dispatcher._call_gemini_with_backoff = fake_model
    task = JuniorTaskAssignment(task_id="t", persona=persona, wave=1, task_objective="o", assigned_files=["a/x.py"],
                                iac_engine="opentofu")
    plan = LeadDeveloperDecompositionPlan(execution_mode=SwarmExecutionMode.STANDARD_SWARM, lead_notes="n",
                                          max_swarm_token_envelope=1000, tasks=[task])
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=["m"]):
        asyncio.run(dispatcher.invoke_junior_worker(task, plan, {}, "m"))
    return seen[0]


def test_junior_workers_receive_the_rule_except_the_iac_persona():
    rule = _rule()
    base = _junior_system_instruction(JuniorPersona.BACKEND_ENGINEER, "")
    assert DIRECT_IAP_VERIFICATION_RULES not in base
    assert _junior_system_instruction(JuniorPersona.BACKEND_ENGINEER, rule) == f"{base}\n\n{rule}\n"
    assert DIRECT_IAP_VERIFICATION_RULES in _junior_system_instruction(JuniorPersona.TEST_ENGINEER, rule)
    assert DIRECT_IAP_VERIFICATION_RULES not in _junior_system_instruction(JuniorPersona.IAC_ENGINEER, rule)


class _Stop(BaseException):
    """Ends generate_code_files at the first model call (BaseException: passes the handler's `except Exception`)."""


@pytest.fixture(autouse=True)
def _no_recorded_region(monkeypatch):
    """Agents here have no Firestore client while the test env configures a project (as in test_dag_wiring_topology)."""
    from developer_agent import handler as _handler
    from developer_agent import terraform_engine as _engine
    monkeypatch.setattr(_handler, "resolve_workload_region",
                        lambda db=None, product_id=None, **kw: _engine.resolve_workload_region(db, **kw))


def _developer(enable_direct_iap):
    from developer_agent.handler import DeveloperAgent
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}), \
            patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no firestore in tests"))):
        dev = DeveloperAgent(project_id="")
    dev.genai_client = MagicMock()
    dev.fetch_existing_repo_files = lambda product_id: {}
    dev._plan_qa_repair = lambda *a, **k: None
    access = SimpleNamespace(allow_unauthenticated=not enable_direct_iap, enable_direct_iap=enable_direct_iap,
                             invoker_members=("user:op@example.com",),
                             # APP-ADMIN-DEFAULT: the verified submitter is the one exact user invoker
                             effective_app_admin_emails=("op@example.com",), app_admin_source="submitter")
    dev._resolve_run_access = lambda *a, **k: (access, False, ())
    return dev


def _swarm_plan():
    task = JuniorTaskAssignment(task_id="t", persona=JuniorPersona.BACKEND_ENGINEER, wave=1, task_objective="o",
                                assigned_files=["a/x.py"], iac_engine="opentofu")
    return LeadDeveloperDecompositionPlan(execution_mode=SwarmExecutionMode.STANDARD_SWARM, lead_notes="n",
                                          max_swarm_token_envelope=1000, tasks=[task])


def _v1_intent(archetype, services=("shop",)):
    return {"schema": "architect_compute_intent/v1", "target_compute_services": list(services), "bundle_id": None,
            "compute_archetype": archetype}


def _topology_intent(services, primary):
    from shared.service_topology import validate_service_topology
    raw = {"primary_service": primary, "edges": [], "services": [{"name": n, "kind": k} for n, k in services]}
    vt, diags = validate_service_topology(raw, product_id="shop")
    assert vt is not None, [(d.code, d.message) for d in diags]
    return {"schema": "architect_compute_intent/v2", "target_compute_services": list(vt.names), "bundle_id": None,
            "compute_archetype": vt.archetype, "service_topology": vt.as_record()}


def _generate(dev, lead_plan, dispatcher_cls=None, intent=None):
    lead = MagicMock()
    lead.return_value.decompose_specification.return_value = lead_plan
    access = dev._resolve_run_access()[0]
    intent = intent or _v1_intent("cloudrun")
    with patch("google.cloud.firestore.Client", MagicMock()):
        with patch("developer_agent.handler.LeadDeveloperOrchestrator", lead):
            with patch("developer_agent.handler.SwarmDispatcher", dispatcher_cls or MagicMock()):
                with pytest.raises(_Stop):
                    dev.generate_code_files(product_id="shop", spec_text="x", task_dag=[{"task_id": "T"}], trace_id="t",
                                            allow_unauthenticated=access.allow_unauthenticated,
                                            enable_direct_iap=access.enable_direct_iap,
                                            domain_restricted_sharing=False, architect_compute_intent=intent)
    return lead.return_value.decompose_specification.call_args.kwargs


def _swarm_rules(enable_direct_iap, intent=None):
    """What the lead and the swarm dispatcher receive; the architect intent decides whether a Cloud Run service exists."""
    recorded = {}

    class Dispatcher:
        any_model_answered = False

        def __init__(self, **_):
            self.iac_intent = None

        async def execute_phased_junior_swarm(self, *a, **k):
            recorded["rule"] = self.app_auth_rule
            raise _Stop()
    lead_kwargs = _generate(_developer(enable_direct_iap), _swarm_plan(), Dispatcher, intent=intent)
    return lead_kwargs.get("app_auth_rule", ""), recorded["rule"]


def _single_turn_instruction(enable_direct_iap, intent=None):
    seen = []

    def gen(model, contents, config):
        seen.append(config.system_instruction)
        raise _Stop()
    dev = _developer(enable_direct_iap)
    dev.genai_client.models.generate_content.side_effect = gen
    solo = LeadDeveloperDecompositionPlan(execution_mode=SwarmExecutionMode.SOLO_FAST_PATH, lead_notes="n",
                                          max_swarm_token_envelope=1000, tasks=[])
    with patch("developer_agent.handler.get_model_cascade_for_agent", return_value=["m"]):
        _generate(dev, solo, intent=intent)
    return seen[0]


@pytest.mark.parametrize("enable_direct_iap", [True, False])
def test_handler_passes_the_typed_rule_to_the_lead_and_the_swarm(enable_direct_iap):
    expected = _rule() if enable_direct_iap else ""
    assert _swarm_rules(enable_direct_iap) == (expected, expected)


@pytest.mark.parametrize("enable_direct_iap", [True, False])
def test_handler_passes_the_typed_rule_to_the_single_turn_prompt(enable_direct_iap):
    assert (DIRECT_IAP_VERIFICATION_RULES in _single_turn_instruction(enable_direct_iap)) is enable_direct_iap


# ------------------------------------------------------------------------- only a Cloud Run service sits behind Direct IAP
@pytest.mark.parametrize("archetype", ["gke-autopilot", "event-worker", "gce-bastion", "foundation-only"])
def test_a_private_iap_non_cloud_run_archetype_gets_no_rule_and_byte_identical_prompts(archetype):
    intent = _v1_intent(archetype)
    assert _swarm_rules(True, intent) == ("", "")
    assert _single_turn_instruction(True, intent) == _single_turn_instruction(False, intent)
    assert DIRECT_IAP_VERIFICATION_RULES not in _single_turn_instruction(True, intent)


GKE_MAIN_TF = """module "compute" {
  source       = "../modules/compute-gke-autopilot"
  service_name = "shop"
}
"""
CLOUD_RUN_MAIN_TF = GKE_MAIN_TF.replace("compute-gke-autopilot", "compute-cloudrun")


@pytest.mark.parametrize("pinned_tf, architect, has_rule", [(GKE_MAIN_TF, "cloudrun", False),
                                                            (CLOUD_RUN_MAIN_TF, "gke-autopilot", True)])
def test_the_rule_follows_the_archetype_the_existing_repository_pins(pinned_tf, architect, has_rule):
    dev = _developer(True)
    dev.fetch_existing_repo_files = lambda product_id: {"infra/workload/main.tf": pinned_tf}

    class Dispatcher:
        any_model_answered = False

        def __init__(self, **_):
            self.iac_intent = None

        async def execute_phased_junior_swarm(self, *a, **k):
            raise _Stop()
    lead_kwargs = _generate(dev, _swarm_plan(), Dispatcher, intent=_v1_intent(architect))
    assert (DIRECT_IAP_VERIFICATION_RULES in lead_kwargs.get("app_auth_rule", "")) is has_rule


def test_a_cloud_run_topology_gets_the_whole_workload_rule():
    intent = _topology_intent([("api", "cloudrun"), ("admin", "cloudrun")], "api")
    assert _swarm_rules(True, intent) == (_rule(), _rule())


@pytest.mark.parametrize("services, primary, behind_iap, not_behind_iap", [
    ([("api", "cloudrun"), ("jobs", "event-worker")], "api", ("api",), ("jobs",)),
    ([("cluster", "gke-autopilot"), ("edge", "cloudrun"), ("api", "cloudrun")], "cluster", ("edge", "api"), ("cluster",)),
])
def test_a_mixed_topology_rule_covers_its_cloud_run_services_and_names_the_others(services, primary, behind_iap,
                                                                                  not_behind_iap):
    lead_rule, swarm_rule = _swarm_rules(True, _topology_intent(services, primary))
    assert lead_rule == swarm_rule == _rule(cloud_run=behind_iap, others=not_behind_iap)
    assert lead_rule != _rule(cloud_run=behind_iap)


def test_a_topology_without_cloud_run_gets_no_rule():
    assert _swarm_rules(True, _topology_intent([("cluster", "gke-autopilot")], "cluster")) == ("", "")


def test_a_legacy_non_cloud_run_primary_with_a_cloud_run_secondary_scopes_the_rule_to_the_secondary():
    # compute_intent's contract: service_names[1:] are Cloud Run secondaries (terraform_engine renders compute-cloudrun)
    lead_rule, _ = _swarm_rules(True, _v1_intent("gke-autopilot", ("cluster", "edge")))
    assert lead_rule == _rule(cloud_run=("edge",), others=("cluster",))


def test_an_image_without_the_rules_crashes_at_import():
    code = ("import sys; sys.path[:0] = [%r, %r]; sys.modules['shared.builtin_skills_provider'] = None\n"
            "try:\n    import developer_agent.prompt\nexcept ImportError as e:\n    print('crashed:', e)\n"
            "else:\n    print('imported')\n" % (GATEWAY, REPO_ROOT))
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120,
                          env=hermetic_guard.child_env())
    assert done.returncode == 0, done.stderr[-2000:]
    assert done.stdout.startswith("crashed:") and "builtin_skills_provider" in done.stdout


# ---------------------------------------------------------------------------- the repair call site (_run_hallucination_stack)
def _repair_instruction(rule, persona, *, prompt_registry_fails=False):
    """The `system_instruction` `invoke_repair` receives from the real `repair()` closure for one repair task."""
    from developer_agent import handler as H
    from developer_agent.compute_intent import ComputeIntent
    captured = {}

    class Loop:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self, draft):
            self.ctx.repair_fn(SimpleNamespace(persona=persona, files_to_fix=["a/x.py"], prompt=lambda: "fix it",
                                               max_output_tokens=1, thinking_budget=0))
            raise _Stop()
    dispatcher = MagicMock()
    dispatcher.return_value.invoke_repair.side_effect = lambda _persona, instruction, *a, **k: captured.update(
        instruction=instruction) or {}
    inputs = H.AssemblyInputs(
        product_id="shop", spec_text="x", trace_id="t", task_dag=[], plan_markdown=None, plan_file_path=None,
        domain_restricted_sharing=False, allowed_domains=[], allow_unauthenticated=False, enable_direct_iap=True,
        target_compute_services=["shop"], existing_files={}, prior_llm={}, llm_draft_paths=[], swarm_attribution={},
        target_project_id="p", project_number="1", workload_vcs="GITHUB", stored_repo=None, auth_invokers=[],
        compute_intent=ComputeIntent(archetype="cloudrun", service_names=("shop",), source="architect",
                                     archetype_source="architect.compute_archetype"),
        app_auth_rule=rule)
    runtime = MagicMock()
    runtime.settings.repair_model = "m"
    runtime.settings.validate_ready_wait_s = 0
    gate = {"runtime": runtime, "trace_id": "t", "providers": [], "engine_label": "x"}
    registry = "developer_agent.juniors.prompt_registry.resolve_junior_prompt"
    registry_kwargs = {"side_effect": RuntimeError("no such junior prompt")} if prompt_registry_fails else {
        "return_value": "JUNIOR PROMPT"}
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no firestore in tests"))), \
            patch("developer_agent.repair_loop.RepairLoop", Loop), \
            patch("developer_agent.validators.step1.build_step1_stack", MagicMock()), \
            patch("developer_agent.handler.SwarmDispatcher", dispatcher), \
            patch(registry, **registry_kwargs), \
            patch("developer_agent.handler.has_existing_network", return_value=False), \
            pytest.raises(_Stop):
        _developer(True)._run_hallucination_stack({"a/x.py": "x = 1\n"}, inputs, gate)
    return captured["instruction"]


@pytest.mark.parametrize("fails", [False, True], ids=["junior-prompt", "except-fallback-system-prompt"])
def test_repair_prompts_get_the_dispatch_rule_except_on_the_iac_persona(fails):
    rule = _rule()
    backend, iac = JuniorPersona.BACKEND_ENGINEER, JuniorPersona.IAC_ENGINEER
    base = _repair_instruction("", backend, prompt_registry_fails=fails)
    assert (base == "JUNIOR PROMPT") is not fails
    assert DIRECT_IAP_VERIFICATION_RULES not in base
    assert _repair_instruction(rule, backend, prompt_registry_fails=fails) == f"{base}\n\n{rule}\n"
    assert _repair_instruction("", iac, prompt_registry_fails=fails) == base
    assert _repair_instruction(rule, iac, prompt_registry_fails=fails) == base


def test_repair_reuses_the_dispatch_value_and_ignores_the_access_flags():
    # enable_direct_iap=True stands on the inputs of every call above: with "" a non-Cloud-Run workload gets no rule
    assert _repair_instruction("", JuniorPersona.BACKEND_ENGINEER) == "JUNIOR PROMPT"


# ------------------------------------------------------------------ the adherence judge knows the rule overrides the task
FACT_LEAD = "- Application authentication: this workload's Cloud Run services are served behind Direct IAP"


def test_platform_facts_gain_the_direct_iap_line_only_when_asked():
    from qa_auditor import judge_input as ji
    dag = [{"task_id": "CODE-01", "category": "CODE", "target_files": ["apps/admin/main.py"]}]
    base = ji.platform_facts_text("GITHUB", "off", dag)
    assert ji.platform_facts_text("GITHUB", "off", dag, direct_iap_cloud_run=False) == base
    assert FACT_LEAD not in base
    told = ji.platform_facts_text("GITHUB", "off", dag, direct_iap_cloud_run=True)
    lines = told.split("\n")
    assert lines[:2] == base.split("\n")[:2] and lines[2].startswith(FACT_LEAD)
    assert "\n".join(lines[:2] + lines[3:]) == base
    for phrase in ("`X-Goog-Authenticated-User-Email`", "mock-auth or bypass flag", "missed directive"):
        assert phrase in lines[2]


def _iac_tree(modules):
    """A commit whose infra/workload/main.tf calls the given (label, golden dir) modules."""
    body = "".join(f'module "{label}" {{\n  source = "../modules/{module}"\n}}\n' for label, module in modules)
    return {"infra/workload/main.tf": body, "apps/shop/main.py": "x = 1\n"}


@pytest.fixture()
def gw(monkeypatch):
    import fd4f_support
    mod = fd4f_support.load_gateway(monkeypatch, "direct_iap_skill_gw")
    yield mod
    mod.app.dependency_overrides.clear()


CR, GKE, WORKER = "compute-cloudrun", "compute-gke-autopilot", "compute-event-worker"


@pytest.mark.parametrize("mode, modules, told", [
    ("PRIVATE_IAP", [("compute", CR)], True),
    ("PRIVATE_IAP", [("compute", GKE), ("compute_edge", CR)], True),
    ("PRIVATE_IAP", [("compute", GKE)], False),
    ("PRIVATE_IAP", [("compute", WORKER)], False),
    ("PRIVATE_IAP", [], False),
    ("PRIVATE_IAM", [("compute", CR)], False),
    ("PUBLIC_APP", [("compute", CR)], False),
])
def test_commit_counts_as_direct_iap_cloud_run_only_with_both_facts(gw, mode, modules, told):
    assert gw._direct_iap_cloud_run_commit({"access_mode": mode}, _iac_tree(modules)) is told


def test_a_cloud_run_module_nested_in_a_bundle_is_not_direct_iap(gw):
    bundle = {"infra/workload/main.tf": 'module "stack" {\n  source = "../bundles/three-tier"\n}\n',
              "infra/bundles/three-tier/main.tf": 'module "web" {\n  source = "../../modules/compute-cloudrun"\n}\n'}
    assert gw._direct_iap_cloud_run_commit({"access_mode": "PRIVATE_IAP"}, bundle) is False


@pytest.mark.parametrize("modules, told", [([("compute", CR)], True), ([("compute", GKE)], False)])
def test_the_adherence_prompt_carries_the_fact_only_for_a_direct_iap_cloud_run_commit(gw, monkeypatch, modules, told):
    import json as _json
    import qa_auditor.judge as judge_mod
    from fd4f_support import SHA_A, SHA_B, FakeBackend, FakeDB, FakeQAClient, backend_factory, passing_outcome, seed_context
    prompts = []

    def fake_judge(prompt, model, **kw):
        if "Security Engineer" in prompt:
            return _json.dumps({"passed": True, "critical_vulnerabilities": []})
        prompts.append(prompt)
        return _json.dumps({"instruction_adherence_score": 1.0, "grounding_score": 1.0, "missed_directives": [],
                            "hallucinated_features": [], "summary": "a"})
    monkeypatch.setattr(judge_mod, "call", fake_judge)
    db = FakeDB()
    seed_context(db)   # the seeded workload is PRIVATE_IAP
    head = {p: t.encode() for p, t in _iac_tree(modules).items()}
    backend = FakeBackend({"castor/app-1": head, "main": {}}, {"castor/app-1": SHA_A, "main": SHA_B})
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name="castor/app-1", attempt=0)
    gw.run_qa(req, client=FakeQAClient(passing_outcome()), source_backend_factory=backend_factory(backend), evidence_db=db)
    (prompt,) = prompts
    assert (FACT_LEAD in prompt.split("### PLATFORM FACTS", 1)[1].split("Sections marked UNTRUSTED", 1)[0]) is told
