"""
FD-4AH follow-up (after FD-4BO / FD-4BP): the remaining undefined names in apps/orchestrator-gateway/architect_agent/.

1. handler.py never imported ``httpx``: fetch_spec_text_from_doc always returned the "Specification document ID: ..."
   placeholder and append_task_checklist_to_doc never reached the workspace connector (NameError swallowed).
   AH-1b: both calls now carry an ID token, minted only for an https Cloud Run origin (compliance_agent's
   id_token_audience). AH-5: a Google-Doc run whose Doc cannot be read fails typed (SPEC_FETCH_FAILED, 502) instead
   of designing from the placeholder; the checklist append stays non-blocking.
2. handler.py _single_turn_decompose (FD24-01) passed undefined ``trace_id`` / ``product_id`` to
   wait_for_rate_limit_cooldown: when every candidate model hit a transient error, NameError escaped decompose instead
   of the interruptible 60 s cooldown. AH-2: still rate-limited after the last cooldown -> typed
   ARCHITECT_RATE_LIMITED (503), never the generic deterministic plan.
3. prompt.py build_architect_system_prompt used ``os`` without importing it: with no db_client (the handler never
   passes one) Glass-Pane custom directives were never added to the architect prompt (NameError swallowed).
4. red_team_critic.py _invoke_llm_critic read ``trace_id`` / ``db`` that were never passed to it: critic token usage
   was never recorded (NameError swallowed).

Hermetic: fake httpx module, fake genai client, in-memory Firestore fakes; the cooldown helper is replaced so nothing
sleeps. Nothing here builds a cloud client or touches the network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import logging
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)

from test_fd4bo_4bp_undefined_names import _undefined_globals  # noqa: E402  (same F821-like symtable checker)

ARCH_DIR = os.path.join(GW_DIR, "architect_agent")
WORKSPACE_URL = "https://mcp-workspace-connector-abc123-uc.a.run.app"


# ============================================================================================ static checks
def _undefined_in(filename, scopes):
    found = _undefined_globals(os.path.join(ARCH_DIR, filename))
    return {(s, n) for s, n in found if s in scopes}


def test_handler_doc_calls_and_single_turn_have_no_undefined_names():
    assert _undefined_in("handler.py", {"fetch_spec_text_from_doc", "append_task_checklist_to_doc",
                                        "_single_turn_decompose"}) == set()


def test_prompt_builder_has_no_undefined_names():
    assert _undefined_in("prompt.py", {"build_architect_system_prompt"}) == set()


def test_red_team_critic_llm_call_has_no_undefined_names():
    assert _undefined_in("red_team_critic.py", {"_invoke_llm_critic", "audit_plan"}) == set()


# ============================================================================================ fakes
class _FakeResponse:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._body


class _FakeHttpx:
    """Stands in for the httpx module: records every Client(...) and post(...) call."""

    def __init__(self, response=None, raise_on_post=None):
        self.response = response or _FakeResponse()
        self.raise_on_post = raise_on_post
        self.clients = []
        self.posts = []
        fake = self

        class Client:
            def __init__(self, **kwargs):
                fake.clients.append(kwargs)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def post(self, url, **kwargs):
                fake.posts.append((url, kwargs))
                if fake.raise_on_post:
                    raise fake.raise_on_post
                return fake.response

        self.Client = Client


class _Snap:
    def __init__(self, data=None):
        self.exists = data is not None
        self._data = data or {}

    def to_dict(self):
        return dict(self._data)


class _FakeDoc:
    def __init__(self, store, path, docs):
        self.store, self.path, self.docs = store, path, docs

    def get(self):
        return _Snap(self.docs.get(self.path))

    def set(self, data, merge=False):
        self.store.setdefault(self.path, []).append(data)

    def update(self, data):
        self.store.setdefault(self.path, []).append(data)

    def collection(self, name):
        return _FakeColl(self.store, f"{self.path}/{name}", self.docs)


class _FakeColl:
    def __init__(self, store, path, docs):
        self.store, self.path, self.docs = store, path, docs

    def document(self, doc_id):
        return _FakeDoc(self.store, f"{self.path}/{doc_id}", self.docs)


class _FakeFirestoreClient:
    instances = []

    def __init__(self, store, docs, project=None):
        self.store, self.docs, self.project = store, docs, project
        _FakeFirestoreClient.instances.append(self)

    def collection(self, name):
        return _FakeColl(self.store, name, self.docs)


def _install_fake_firestore(monkeypatch, docs=None):
    store = {}
    docs = docs or {}
    _FakeFirestoreClient.instances = []
    fake_fs = SimpleNamespace(Client=lambda *a, **kw: _FakeFirestoreClient(store, docs, kw.get("project")),
                              Increment=lambda n: ("INC", n))
    import google.cloud  # noqa: F401
    monkeypatch.setattr(sys.modules["google.cloud"], "firestore", fake_fs, raising=False)
    monkeypatch.setitem(sys.modules, "google.cloud.firestore", fake_fs)
    return store


def _valid_plan_client(product_id="p"):
    """Lane 10: a fake genai client whose architect answer is a valid plan with a service topology (the
    deterministic fallback plan no longer passes the topology gate)."""
    plan = {"product_id": product_id, "summary": "s", "architecture_overview": "o", "infra_tasks": [],
            "code_tasks": [], "target_compute_services": [product_id], "compute_archetype": "cloudrun",
            "iac_engine": "tofu",
            "service_topology": {"services": [{"name": product_id, "kind": "cloudrun"}],
                                 "primary_service": product_id, "edges": [], "resources": []}}
    client = MagicMock()
    client.models.generate_content.return_value = SimpleNamespace(text=json.dumps(plan), candidates=[],
                                                                  usage_metadata=None)
    return client


@pytest.fixture()
def architect(monkeypatch):
    for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "PROJECT_ID", "K_SERVICE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ENABLE_DUAL_ARCHITECT_CONSENSUS", "false")
    from architect_agent import handler as h

    store = _install_fake_firestore(monkeypatch)
    monkeypatch.setattr(h.ArchitectAgent, "persist_build_plan_to_firestore", lambda self, *a, **kw: True)
    monkeypatch.setattr(h.ArchitectAgent, "persist_implementation_plan_to_firestore", lambda self, *a, **kw: True)
    monkeypatch.setattr(h, "get_model_cascade_for_agent", lambda *a, **kw: ["fake-model"])
    monkeypatch.setattr(h, "build_architect_system_prompt", lambda **kw: "RENDERED ARCHITECT PROMPT")
    monkeypatch.setitem(sys.modules, "vertexai", None)  # no legacy Vertex SDK init (it would look up ADC)

    agent = h.ArchitectAgent(project_id="")
    agent.model_name = "fake-model"  # single candidate model (the cascade above is ["fake-model"])
    agent.genai_client = _valid_plan_client()  # lane 10: a model answer with a valid service topology
    agent.model = None
    agent.spec_decomposer = None
    agent.minted_audiences = []

    def fake_mint(audience):
        agent.minted_audiences.append(audience)
        return "tok-123"

    agent._fetch_id_token = fake_mint  # the metadata server is never reached
    return h, agent, store


# ============================================================================================ 1. httpx + AH-1b auth
AUTH = {"Authorization": "Bearer tok-123"}


def test_fetch_spec_returns_real_doc_text_with_id_token(architect, monkeypatch):
    h, agent, _ = architect
    fake = _FakeHttpx(_FakeResponse(200, {"full_text": "Build a todo API on Cloud Run."}))
    monkeypatch.setattr(h, "httpx", fake)

    assert agent.fetch_spec_text_from_doc("doc-123", WORKSPACE_URL + "/") == "Build a todo API on Cloud Run."
    assert fake.posts == [(f"{WORKSPACE_URL}/read-doc", {"json": {"document_id": "doc-123"}, "headers": AUTH})]
    assert agent.minted_audiences == [WORKSPACE_URL]  # the origin, via compliance_agent's id_token_audience
    assert fake.clients == [{"timeout": 30.0, "follow_redirects": False}]


@pytest.mark.parametrize("url", ["http://localhost:8080", "http://mcp-workspace-connector:8080",
                                 "https://workspace.example.com", "https://evil.run.app.example.com",
                                 "https://user:pw@x.a.run.app", "https://x.a.run.app:8443"])
def test_no_token_for_non_cloud_run_urls_off_cloud_run(architect, monkeypatch, url):
    """Off Cloud Run (local dev) a non-Cloud-Run URL is called as before, without a token; nothing is minted."""
    h, agent, _ = architect
    fake = _FakeHttpx(_FakeResponse(200, {"full_text": "local spec"}))
    monkeypatch.setattr(h, "httpx", fake)
    assert agent.fetch_spec_text_from_doc("d", url) == "local spec"
    assert fake.posts[0][1]["headers"] == {}
    assert agent.minted_audiences == []


@pytest.mark.parametrize("url", ["http://localhost:8080", "https://workspace.example.com"])
def test_on_cloud_run_non_cloud_run_url_is_refused(architect, monkeypatch, url):
    h, agent, _ = architect
    monkeypatch.setenv("K_SERVICE", "orchestrator-gateway")
    fake = _FakeHttpx(_FakeResponse(200, {"full_text": "x"}))
    monkeypatch.setattr(h, "httpx", fake)
    assert agent.fetch_spec_text_from_doc("d", url) == "Specification document ID: d"
    assert agent.append_task_checklist_to_doc("d", "## plan", url) is False
    assert fake.posts == [] and agent.minted_audiences == []


def test_mint_failure_sends_no_request(architect, monkeypatch, caplog):
    h, agent, _ = architect
    fake = _FakeHttpx(_FakeResponse(200, {"full_text": "x"}))
    monkeypatch.setattr(h, "httpx", fake)

    def boom(audience):
        raise OSError("metadata server unreachable")

    agent._fetch_id_token = boom
    with caplog.at_level(logging.WARNING, logger="castor-architect-agent"):
        assert agent.fetch_spec_text_from_doc("d", WORKSPACE_URL) == "Specification document ID: d"
        assert agent.append_task_checklist_to_doc("d", "## plan", WORKSPACE_URL) is False
    assert fake.posts == []
    assert "tok-" not in caplog.text


@pytest.mark.parametrize("fake", [
    _FakeHttpx(_FakeResponse(403, {"detail": "forbidden"})),
    _FakeHttpx(raise_on_post=ConnectionError("connection refused")),
    _FakeHttpx(_FakeResponse(200, {"full_text": ""})),
    _FakeHttpx(_FakeResponse(200, {"full_text": "   "})),
    _FakeHttpx(_FakeResponse(200, {"other": "x"})),
    _FakeHttpx(_FakeResponse(200, ["not", "a", "dict"])),
    None,  # httpx not installed
], ids=["http-403", "transport-error", "empty-text", "blank-text", "no-text-key", "non-dict-body", "no-httpx"])
def test_fetch_spec_failures_keep_placeholder_and_warn(architect, monkeypatch, caplog, fake):
    """fetch_spec_text_from_doc keeps its placeholder contract for direct callers (decompose no longer uses it)."""
    h, agent, _ = architect
    monkeypatch.setattr(h, "httpx", fake)
    with caplog.at_level(logging.WARNING, logger="castor-architect-agent"):
        assert agent.fetch_spec_text_from_doc("doc-9", WORKSPACE_URL) == "Specification document ID: doc-9"
    assert any(r.levelno == logging.WARNING and "placeholder" in r.getMessage() for r in caplog.records)


def test_append_checklist_posts_to_workspace_with_token(architect, monkeypatch):
    h, agent, _ = architect
    fake = _FakeHttpx(_FakeResponse(200, {"status": "SUCCESS"}))
    monkeypatch.setattr(h, "httpx", fake)

    assert agent.append_task_checklist_to_doc("doc-1", "## plan", WORKSPACE_URL) is True
    assert fake.posts == [(f"{WORKSPACE_URL}/append-status",
                           {"json": {"document_id": "doc-1", "status_text": "## plan"}, "headers": AUTH})]
    assert fake.clients == [{"timeout": 30.0, "follow_redirects": False}]


@pytest.mark.parametrize("fake", [_FakeHttpx(_FakeResponse(500)), _FakeHttpx(raise_on_post=TimeoutError("t")), None],
                         ids=["http-500", "timeout", "no-httpx"])
def test_append_checklist_failure_returns_false_and_warns(architect, monkeypatch, caplog, fake):
    h, agent, _ = architect
    monkeypatch.setattr(h, "httpx", fake)
    with caplog.at_level(logging.WARNING, logger="castor-architect-agent"):
        assert agent.append_task_checklist_to_doc("doc-1", "## plan", WORKSPACE_URL) is False
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def _spy_spec_text(agent, monkeypatch):
    seen = []
    original = agent._single_turn_decompose

    def spy(**kw):
        seen.append(kw["final_spec_text"])
        return original(**kw)

    monkeypatch.setattr(agent, "_single_turn_decompose", spy)
    return seen


def test_decompose_uses_fetched_doc_text_and_appends_checklist(architect, monkeypatch):
    h, agent, _ = architect
    fake = _FakeHttpx(_FakeResponse(200, {"full_text": "Spec from the Google Doc: a todo API."}))
    monkeypatch.setattr(h, "httpx", fake)
    seen = _spy_spec_text(agent, monkeypatch)
    agent.decompose(spec_text="", spec_doc_id="doc-7", product_id="p7", trace_id="t7",
                    workspace_mcp_url=WORKSPACE_URL)

    assert seen == ["Spec from the Google Doc: a todo API."]
    assert [u for u, _ in fake.posts] == [f"{WORKSPACE_URL}/read-doc", f"{WORKSPACE_URL}/append-status"]
    assert all(kw["headers"] == AUTH for _, kw in fake.posts)


def test_decompose_append_failure_is_non_blocking(architect, monkeypatch):
    h, agent, _ = architect

    class _ReadOkAppendFails(_FakeHttpx):
        pass

    fake = _ReadOkAppendFails(_FakeResponse(200, {"full_text": "Real spec"}))
    orig_post = fake.Client.post

    def post(self, url, **kw):
        if url.endswith("/append-status"):
            fake.posts.append((url, kw))
            raise ConnectionError("down")
        return orig_post(self, url, **kw)

    fake.Client.post = post
    monkeypatch.setattr(h, "httpx", fake)
    agent.genai_client = _valid_plan_client("p8")
    result = agent.decompose(spec_text="", spec_doc_id="doc-8", product_id="p8", trace_id="t8",
                             workspace_mcp_url=WORKSPACE_URL)
    assert result.product_id == "p8"


@pytest.mark.parametrize("fake,url", [
    (_FakeHttpx(_FakeResponse(403)), WORKSPACE_URL),
    (_FakeHttpx(raise_on_post=TimeoutError("t")), WORKSPACE_URL),
    (_FakeHttpx(_FakeResponse(200, {"full_text": ""})), WORKSPACE_URL),
    (_FakeHttpx(_FakeResponse(200, ["malformed"])), WORKSPACE_URL),
    (None, WORKSPACE_URL),
    (_FakeHttpx(_FakeResponse(200, {"full_text": "never called"})), ""),  # no connector URL
], ids=["http-403", "timeout", "empty", "malformed", "no-httpx", "no-url"])
def test_doc_run_fetch_failure_fails_closed(architect, monkeypatch, fake, url):
    """AH-5: a Google-Doc run never designs from the placeholder: typed SPEC_FETCH_FAILED (502), no model call."""
    h, agent, store = architect
    monkeypatch.setattr(h, "httpx", fake)
    seen = _spy_spec_text(agent, monkeypatch)
    with pytest.raises(h.SpecFetchFailedError) as ei:
        agent.decompose(spec_text="  ", spec_doc_id="doc-x", product_id="px", trace_id="tx", workspace_mcp_url=url)
    err = ei.value
    assert err.http_status == 502 and err.reason == "SPEC_FETCH_FAILED"
    body = err.to_body()
    assert body["error_class"] == "GATE_UNAVAILABLE" and body["reason"] == "SPEC_FETCH_FAILED"
    assert body["details"] == {"trace_id": "tx", "product_id": "px", "spec_doc_id": "doc-x"}
    assert seen == []  # never reached the design step
    if fake is not None and url:
        assert [u for u, _ in fake.posts] == [f"{WORKSPACE_URL}/read-doc"]  # no checklist append either


def test_decompose_with_inline_spec_does_not_fetch(architect, monkeypatch):
    """Do No Harm: an inline spec_text never calls /read-doc, even if the Doc could not be read."""
    h, agent, _ = architect
    fake = _FakeHttpx(_FakeResponse(403))
    monkeypatch.setattr(h, "httpx", fake)
    seen = _spy_spec_text(agent, monkeypatch)
    agent.decompose(spec_text="Inline spec", spec_doc_id="doc-7", product_id="p7", trace_id="t7b",
                    workspace_mcp_url=WORKSPACE_URL)
    assert seen == ["Inline spec"]
    assert [u for u, _ in fake.posts] == [f"{WORKSPACE_URL}/append-status"]


def test_no_doc_and_no_text_keeps_generic_prompt(architect, monkeypatch):
    """Do No Harm: not a Doc run (no spec_doc_id) -> unchanged generic text, no fetch, no error."""
    h, agent, _ = architect
    fake = _FakeHttpx()
    monkeypatch.setattr(h, "httpx", fake)
    seen = _spy_spec_text(agent, monkeypatch)
    agent.decompose(spec_text="", product_id="p9", trace_id="t9", workspace_mcp_url=WORKSPACE_URL)
    assert seen == ["Build specification for product 'p9'"]
    assert fake.posts == []


# ============================================================================================ 2. FD24-01 / AH-2 cooldown
class _RateLimited(Exception):
    code = 429


def _rate_limited_client(succeed_after=None, raw=None, exc=None):
    calls = {"n": 0}

    def generate_content(**kw):
        calls["n"] += 1
        if succeed_after is not None and calls["n"] > succeed_after:
            return SimpleNamespace(text=raw, candidates=[], usage_metadata=None)
        raise exc or _RateLimited("429 RESOURCE_EXHAUSTED: quota exceeded")

    client = MagicMock()
    client.models.generate_content.side_effect = generate_content
    return client, calls


def _real_cooldown_contract(record):
    """The real helper's return contract without sleeping: True while attempt <= max_attempts, else False."""
    def fake(**kw):
        record.append(kw)
        return kw["attempt"] <= kw["max_attempts"]
    return fake


def test_still_rate_limited_after_last_cooldown_fails_closed(architect, monkeypatch):
    h, agent, _ = architect
    cooldowns = []
    monkeypatch.setattr(h, "wait_for_rate_limit_cooldown", _real_cooldown_contract(cooldowns))
    agent.genai_client, calls = _rate_limited_client()
    seen_fallback = []
    monkeypatch.setattr(agent, "_fallback_plan", lambda *a: seen_fallback.append(a))

    with pytest.raises(h.ArchitectRateLimitedError) as ei:
        agent.decompose(spec_text="Build a todo API", product_id="p-rl", trace_id="t-rl")

    # 3 real cooldowns, one model pass after each, then the helper's own "max attempts" answer (attempt 4).
    assert [c["attempt"] for c in cooldowns] == [1, 2, 3, 4]
    assert all((c["trace_id"], c["product_id"], c["stage"], c["max_attempts"]) ==
               ("t-rl", "p-rl", "architect_decomposition", 3) for c in cooldowns)
    assert calls["n"] == 4
    assert seen_fallback == []  # never the generic deterministic plan
    err = ei.value
    assert err.http_status == 503 and err.reason == "ARCHITECT_RATE_LIMITED"
    assert err.to_body()["error_class"] == "GATE_UNAVAILABLE"
    assert err.to_body()["details"] == {"trace_id": "t-rl", "product_id": "p-rl", "cooldowns": 3}


def test_cooldown_declined_fails_closed(architect, monkeypatch):
    h, agent, _ = architect
    cooldowns = []
    monkeypatch.setattr(h, "wait_for_rate_limit_cooldown", lambda **kw: (cooldowns.append(kw), False)[1])
    agent.genai_client, _ = _rate_limited_client()
    with pytest.raises(h.ArchitectRateLimitedError):
        agent.decompose(spec_text="Build a todo API", product_id="p-rl", trace_id="t-rl")
    assert [c["attempt"] for c in cooldowns] == [1]


def test_cooldown_retry_then_model_succeeds(architect, monkeypatch):
    h, agent, _ = architect
    raw = json.dumps({**json.loads(agent._fallback_plan("p-rl2", "Build a todo API").model_copy(
        update={"summary": "MODEL PLAN AFTER COOLDOWN"}).model_dump_json()),
        "service_topology": {"services": [{"name": "p-rl2", "kind": "cloudrun"}], "primary_service": "p-rl2"}})
    cooldowns = []
    monkeypatch.setattr(h, "wait_for_rate_limit_cooldown", _real_cooldown_contract(cooldowns))
    agent.genai_client, calls = _rate_limited_client(succeed_after=3, raw=raw)

    result = agent.decompose(spec_text="Build a todo API", product_id="p-rl2", trace_id="t-rl2")

    assert [c["attempt"] for c in cooldowns] == [1, 2, 3]  # success on the pass after the last cooldown
    assert calls["n"] == 4
    assert result.architecture_plan.summary == "MODEL PLAN AFTER COOLDOWN"


def test_non_rate_limit_model_failure_keeps_existing_fallback(architect, monkeypatch):
    """Do No Harm: a non-transient model error (not rate limiting) takes the existing fallback path, no cooldown.
    Lane 10 (plan §5.2): the fallback plan then fails the topology gate typed (ARCHITECT_DEFECT, TOPOLOGY.MISSING)
    instead of shipping the generic plan."""
    h, agent, _ = architect
    cooldowns = []
    monkeypatch.setattr(h, "wait_for_rate_limit_cooldown", lambda **kw: (cooldowns.append(kw), True)[1])
    agent.genai_client, _ = _rate_limited_client(exc=ValueError("400 INVALID_ARGUMENT: bad request"))
    built = []
    original = agent._fallback_plan
    monkeypatch.setattr(agent, "_fallback_plan", lambda *a: (built.append(a), original(*a))[1])
    with pytest.raises(h.GateUnavailableError) as ei:
        agent.decompose(spec_text="Build a todo API", product_id="p-nf", trace_id="t-nf")
    assert cooldowns == []
    assert built == [("p-nf", "Build a todo API")]
    # lane 10 RT F7: no model answered -> unavailable (503), never "architect output invalid"
    assert ei.value.to_body()["error_class"] == "GATE_UNAVAILABLE"
    assert ei.value.reason == "ARCHITECT_NO_MODEL_RESPONSE"


def test_cooldown_abort_propagates(architect, monkeypatch):
    """Operator [Abort] during the cooldown raises RuntimeError in the helper: it must still stop the architect."""
    h, agent, _ = architect

    def abort(**kw):
        raise RuntimeError(f"Build {kw['trace_id']} was aborted by operator during rate-limit cooldown.")

    monkeypatch.setattr(h, "wait_for_rate_limit_cooldown", abort)
    agent.genai_client, _ = _rate_limited_client()
    with pytest.raises(RuntimeError, match="t-ab was aborted"):
        agent.decompose(spec_text="Build a todo API", product_id="p-ab", trace_id="t-ab")


# ============================================================================================ endpoint + workflow
@pytest.fixture()
def gw(monkeypatch):
    from fd4g_support import real_modules
    import importlib.util

    real_modules(monkeypatch)
    for k in ("PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "GEMINI_API_KEY", "GOOGLE_API_KEY", "K_SERVICE",
              "REGION", "GITHUB_OWNER"):
        monkeypatch.delenv(k, raising=False)
    spec = importlib.util.spec_from_file_location("fd4ah_gw_main", os.path.join(GW_DIR, "main.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    yield mod
    mod.app.dependency_overrides.clear()


@pytest.mark.parametrize("which,status,reason", [("rate", 503, "ARCHITECT_RATE_LIMITED"),
                                                 ("spec", 502, "SPEC_FETCH_FAILED")])
def test_architect_endpoint_returns_typed_error(gw, monkeypatch, which, status, reason):
    from fastapi.testclient import TestClient
    from architect_agent import handler as h

    err = (h.ArchitectRateLimitedError("still rate-limited", reason="ARCHITECT_RATE_LIMITED") if which == "rate"
           else h.SpecFetchFailedError("could not read Doc", reason="SPEC_FETCH_FAILED"))

    class _FakeAgent:
        def __init__(self, **kw):
            pass

        def decompose(self, **kw):
            raise err

    monkeypatch.setattr(h, "ArchitectAgent", _FakeAgent)
    r = TestClient(gw.app).post("/agent/architect/decompose",
                                json={"product_id": "p1", "trace_id": "t1", "spec_doc_id": "d1"})
    assert r.status_code == status, r.text
    body = r.json()
    assert body["status"] == "FAILED" and body["error_class"] == "GATE_UNAVAILABLE" and body["reason"] == reason


def test_workflow_architect_failure_goes_to_dlq_without_retry_or_loop():
    """The architect step's non-2xx (503/502 above) is caught by its `except` and routed to the pipeline's typed
    failure (prep_dead_letter_payload -> raise), which main's single failure handler turns into DLQ + FAILED
    notification + a FAILED execution (lane 17 PR-2; it used to `return` FAILED, i.e. execution SUCCEEDED). No retry
    policy on the step; the only edge back into the architect is the human REWORK decision."""
    import yaml

    with open(os.path.join(REPO_ROOT, "workflows", "main_orchestrator.yaml"), encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    steps = doc["run_pipeline"]["steps"]
    names = [next(iter(s)) for s in steps]
    by_name = {next(iter(s)): s[next(iter(s))] for s in steps}

    arch = by_name["architect_decomposition"]
    assert "retry" not in arch and "retry" not in arch["try"]
    # LONG-STAGE-CALLBACK (owner 11-13): a callback job (run_stage_job); its dispatch retry is inside the
    # subworkflow and is idempotent (one job per callback URL), so the architect itself still runs at most once
    assert arch["try"]["call"] == "run_stage_job" and arch["try"]["args"]["stage"] == "architect"
    route = arch["except"]["steps"][0]["route_architect_failure"]
    assert route["next"] == "prep_dead_letter_payload"
    # prep builds the typed failure -> raise_pipeline_failure (sequential) raises it to main's handler
    assert by_name["prep_dead_letter_payload"]["call"] == "build_failure"
    assert names[names.index("prep_dead_letter_payload") + 1] == "raise_pipeline_failure"
    assert "raise" in by_name["raise_pipeline_failure"]
    handler = doc["main"]["steps"][1]["run_pipeline_guarded"]["except"]["steps"]
    handler_names = [next(iter(s)) for s in handler]
    assert handler_names[-1] == "fail_execution" and "raise" in handler[-1]["fail_execution"]
    assert {"publish_dead_letter", "notify_failure"} <= set(handler_names)
    for name in ("prep_dead_letter_payload", "raise_pipeline_failure"):
        assert "architect_decomposition" not in yaml.safe_dump(by_name[name])
    assert "architect_decomposition" not in yaml.safe_dump(handler)


# ============================================================================================ 3. prompt directives
@pytest.fixture()
def prompt_mod(monkeypatch):
    from architect_agent import prompt as ap
    import shared.prompt_resolver as resolver

    monkeypatch.setattr(resolver, "get_agent_system_prompt", lambda **kw: "BASE PROMPT")
    monkeypatch.setattr(ap, "resolve_active_skills", lambda **kw: [])
    return ap


# Lane 10: the service_topology contract (rendered from shared data) always follows the resolved base prompt;
# ARCHITECT-PYTHON-PIN: then the one Python runtime fact line (tests/test_architect_python_pin.py).
from shared.service_topology import render_topology_contract  # noqa: E402
from developer_agent.runtime_pin import ARCHITECT_PYTHON_RUNTIME_FACT  # noqa: E402

TOPOLOGY_CONTRACT = render_topology_contract()
# ARCHITECT-REFUSED-ROLES-FACT (ex02-g13) re-pin: then the IAM roles fact line
from architect_agent.prompt import ARCHITECT_REFUSED_ROLES_FACT  # noqa: E402
BASE_WITH_CONTRACT = ("BASE PROMPT\n\n" + TOPOLOGY_CONTRACT + "\n" + ARCHITECT_PYTHON_RUNTIME_FACT + "\n"
                      + ARCHITECT_REFUSED_ROLES_FACT)


def _settings_docs(directives):
    return {"system_config/platform_settings": {"models": {"custom_directives": {"ARCHITECT_AGENT": directives}}}}


def test_prompt_applies_glass_pane_directives_without_db_client(prompt_mod, monkeypatch):
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    _install_fake_firestore(monkeypatch, _settings_docs(["Prefer Cloud Run over GKE", ""]))

    out = prompt_mod.build_architect_system_prompt(task_context="spec")

    assert out == (BASE_WITH_CONTRACT + "\n\n### ACTIVE OPERATIONAL DIRECTIVES (MANAGED VIA GLASS PANE):\n"
                   "- [DIRECTIVE]: Prefer Cloud Run over GKE\n")
    assert [c.project for c in _FakeFirestoreClient.instances] == ["mock-stackvend-project"]


@pytest.mark.parametrize("docs", [{}, _settings_docs([]), _settings_docs("not-a-list")],
                         ids=["no-settings-doc", "empty-list", "not-a-list"])
def test_prompt_without_directives_is_unchanged(prompt_mod, monkeypatch, docs):
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    _install_fake_firestore(monkeypatch, docs)
    assert prompt_mod.build_architect_system_prompt(task_context="spec") == BASE_WITH_CONTRACT


def test_prompt_without_project_builds_no_client(prompt_mod, monkeypatch):
    monkeypatch.delenv("PROJECT_ID", raising=False)
    _install_fake_firestore(monkeypatch, _settings_docs(["X"]))
    assert prompt_mod.build_architect_system_prompt(task_context="spec") == BASE_WITH_CONTRACT
    assert _FakeFirestoreClient.instances == []


def test_prompt_firestore_error_keeps_base_prompt(prompt_mod, monkeypatch):
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    broken = MagicMock()
    broken.collection.side_effect = RuntimeError("firestore down")
    assert prompt_mod.build_architect_system_prompt(task_context="spec", db_client=broken) == BASE_WITH_CONTRACT


# ============================================================================================ 4. critic tokens
_CRITIQUE = {"soundness_score": 0.9, "has_critical_findings": False, "findings": [],
             "gauntlet_checks": [{"invariant_name": "DAG Topology & Cycles", "status": "PASSED", "details": "ok"}],
             "verdict_summary": "Architectural plan verified without critical defects."}


@pytest.fixture()
def critic(monkeypatch, architect):
    from architect_agent import red_team_critic as rtc
    import shared.token_accounting as ta

    h, agent, _ = architect
    recorded = []
    monkeypatch.setattr(ta, "record_agent_tokens", lambda db, trace, stage, usage: recorded.append((db, trace, stage,
                                                                                                    usage)))
    monkeypatch.setattr(rtc, "get_model_cascade_for_agent", lambda *a, **kw: ["fake-critic"])
    client = MagicMock()
    client.models.generate_content.return_value = SimpleNamespace(
        text=json.dumps(_CRITIQUE), candidates=[],
        usage_metadata=SimpleNamespace(prompt_token_count=1200, candidates_token_count=300, total_token_count=1500))
    c = rtc.RedTeamCritic(genai_client=client, model_name="fake-critic")
    plan = agent._fallback_plan("p-c", "Build a todo API")
    return c, plan, recorded


def test_critic_records_tokens_with_callers_db(critic, monkeypatch):
    c, plan, recorded = critic
    monkeypatch.delenv("PROJECT_ID", raising=False)
    db = object()
    out = c.audit_plan(plan=plan, spec_text="Build a todo API", trace_id="t-c", db=db)
    assert out.soundness_score == 0.9
    assert len(recorded) == 1
    rdb, trace, stage, usage = recorded[0]
    assert (rdb, trace, stage) == (db, "t-c", "red_team_critic")
    assert usage.total_tokens == 1500 and usage is c.last_critic_tokens


def test_critic_without_db_uses_project_client(critic, monkeypatch):
    """The consensus engine passes db=getattr(architect, "db", None), which is None in the gateway: same rule as the
    architect's own token accounting -> a client for PROJECT_ID."""
    c, plan, recorded = critic
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    c.audit_plan(plan=plan, spec_text="Build a todo API", trace_id="t-c2", db=None)
    assert len(recorded) == 1
    assert isinstance(recorded[0][0], _FakeFirestoreClient) and recorded[0][0].project == "mock-stackvend-project"


@pytest.mark.parametrize("trace_id,project", [(None, "mock-stackvend-project"), ("t-c3", None)],
                         ids=["no-trace", "no-project-no-db"])
def test_critic_records_nothing_without_trace_or_store(critic, monkeypatch, trace_id, project):
    c, plan, recorded = critic
    if project:
        monkeypatch.setenv("PROJECT_ID", project)
    else:
        monkeypatch.delenv("PROJECT_ID", raising=False)
    out = c.audit_plan(plan=plan, spec_text="Build a todo API", trace_id=trace_id, db=None)
    assert recorded == []
    assert out.soundness_score == 0.9 and c.last_critic_tokens.total_tokens == 1500
    assert _FakeFirestoreClient.instances == []
