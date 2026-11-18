"""JUDGE-FALLBACK-FLASH-ROOM (owner 11-16; red team 11-16 F1/F2): what the judge's per-request time box puts on the
wire, through the real google-genai request path.

The SDK pieces `google.genai.Client` is made of are used as they are: `_api_client.BaseApiClient` (built exactly like
`qa_auditor.judge._build_client`: Vertex, project, location `global`, client default timeout 120 s) and
`models.Models` (what `Client.models` is); only `Client.__init__` itself is left alone, because the hermetic guard
blocks constructing it in tests. Credentials are a fixed fake token (no ADC lookup), the HTTP client is an
`httpx.Client` on an `httpx.MockTransport` (no socket), and the platform settings are the stubbed defaults
(`platform_settings_defaults`), so nothing here can reach Google.

Pinned: a time box of N s sends `X-Server-Timeout: N` and an httpx timeout of N s; the full 120 s box sends exactly
the request the judge sent before (URL, headers, body, timeout byte-identical to the client-default request); and a
stray request without options of its own -- which makes google-genai 2.29 write `X-Server-Timeout: 120` into the
client's shared header dict -- cannot pin later boxes at 120 s."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
from types import SimpleNamespace

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse: no settings read)

pytest.importorskip("google.genai")
httpx = pytest.importorskip("httpx")

from google.genai import _api_client, models, types  # noqa: E402
from google.oauth2.credentials import Credentials  # noqa: E402

import qa_auditor.judge as judge_mod  # noqa: E402
from developer_agent.llm_transport import with_http_timeout  # noqa: E402

CARBON, ARGON = "gemini-4-carbon", "gemini-4-argon"
ANSWER = json.dumps({"passed": True, "critical_vulnerabilities": [], "summary": "ok"})
HEADER = judge_mod.SERVER_TIMEOUT_HEADER


class _Wire:
    """A real SDK client on a mock transport; `sent` holds every outgoing httpx.Request."""

    def __init__(self):
        self.sent = []

        def handler(request):
            self.sent.append(request)
            return httpx.Response(200, json={
                "candidates": [{"content": {"role": "model", "parts": [{"text": ANSWER}]}, "finishReason": "STOP"}],
                "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5}})

        self.api = _api_client.BaseApiClient(
            vertexai=True, project="mock-stackvend-project", location="global",
            credentials=Credentials(token="fake-token"),
            http_options=types.HttpOptions(timeout=judge_mod.JUDGE_TIMEOUT_MS,
                                           httpx_client=httpx.Client(transport=httpx.MockTransport(handler))))
        self.client = SimpleNamespace(models=models.Models(self.api))

    def judge(self, **kw):
        kw.setdefault("fallback_models", ())
        return judge_mod.call("prompt", CARBON, client=self.client, sleep=lambda s: None, clock=lambda: 0.0, **kw)

    def bare(self, config=None):
        """The pre-11-16 judge request: no options of its own (the client default timeout applies)."""
        cfg = config if config is not None else judge_mod.judge_config(CARBON, judge_mod.JUDGE_MAX_OUTPUT_TOKENS, None)
        return self.client.models.generate_content(model=CARBON, contents="prompt", config=cfg)


def _timeout(request):
    t = request.extensions["timeout"]
    assert t["connect"] == t["read"] == t["write"] == t["pool"]
    return t["read"]


@pytest.fixture(autouse=True)
def no_adc(monkeypatch):
    """Any credential lookup fails the test (the fake token must be the only credential used)."""
    def boom(*a, **k):
        raise AssertionError("an ADC lookup was attempted")
    monkeypatch.setattr(_api_client, "load_auth", boom)


@pytest.mark.parametrize("box, deadline, fallback_models", [
    (55, judge_mod.JUDGE_MIN_CALL_S + judge_mod.JUDGE_DEADLINE_MARGIN_S, ()),   # the floor (one-model chain)
    (87, 179.0, (ARGON,)),                       # half of 174 s of room while a later model remains
])
def test_a_time_box_is_the_server_timeout_and_the_http_timeout(box, deadline, fallback_models):
    w = _Wire()
    assert w.judge(deadline=deadline, fallback_models=fallback_models) == ANSWER
    (req,) = w.sent
    assert req.headers[HEADER] == str(box) and _timeout(req) == float(box)
    assert req.url.host == "aiplatform.googleapis.com" and req.url.path.endswith(f"/models/{CARBON}:generateContent")


def test_the_full_box_is_byte_identical_to_the_client_default_request():
    """Do No Harm: the judge's 120 s request (no deadline, or a full Stage 2 budget) is the old request exactly."""
    old, new, full = _Wire(), _Wire(), _Wire()
    old.bare()
    assert new.judge() == ANSWER
    assert full.judge(deadline=300.0) == ANSWER
    (a,), (b,), (c,) = old.sent, new.sent, full.sent
    assert a.headers[HEADER] == "120" and _timeout(a) == 120.0
    for r in (b, c):
        assert r.method == a.method and str(r.url) == str(a.url)
        assert dict(r.headers) == dict(a.headers)
        assert r.content == a.content and _timeout(r) == _timeout(a)


def test_a_stray_bare_request_cannot_pin_later_boxes():
    """RT F2: a request without options of its own writes the client default (120) into the client's shared header
    dict (google-genai 2.29, `populate_server_timeout_header` only sets an absent header). A timeout-only per-request
    option then keeps sending 120 while the HTTP client gives up at the box; the judge's explicit header does not."""
    w = _Wire()
    w.bare()
    assert w.api._http_options.headers.get(HEADER) == "120"            # the SDK behaviour the fix guards against
    cfg = judge_mod.judge_config(CARBON, judge_mod.JUDGE_MAX_OUTPUT_TOKENS, None)
    w.bare(with_http_timeout(cfg, 55))                                  # timeout-only: the header stays pinned
    assert w.sent[-1].headers[HEADER] == "120" and _timeout(w.sent[-1]) == 55.0
    assert w.judge(deadline=judge_mod.JUDGE_MIN_CALL_S + judge_mod.JUDGE_DEADLINE_MARGIN_S) == ANSWER
    assert w.sent[-1].headers[HEADER] == "55" and _timeout(w.sent[-1]) == 55.0
    assert w.judge() == ANSWER                                          # and back to the full box
    assert w.sent[-1].headers[HEADER] == "120" and _timeout(w.sent[-1]) == 120.0
