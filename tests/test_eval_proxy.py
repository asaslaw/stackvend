"""FD-30 LLM proxy + cassettes (red-team H5): offline, fake backend only (no network, no credentials)."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "eval"))

from google.genai import types  # noqa: E402

from stackvend_eval.budget import Budget, Price, PriceTable  # noqa: E402
from stackvend_eval.cassettes import Cassette, normalize_request, request_hash  # noqa: E402
from stackvend_eval.errors import EvalBudgetExceeded, EvalHarnessError, EvalReplayMiss  # noqa: E402
from stackvend_eval.llm_proxy import LLMProxy, derive_seed, with_seed  # noqa: E402
from stackvend_eval.state import RunState  # noqa: E402

PRICES = PriceTable({"m": Price("m", 1.0, 10.0, 0.5, 5.0, True, 65536)})
HERE = str(Path(__file__).resolve().parent)


def _exact_child_env(env):
    """``hermetic_guard.child_env()`` kwargs that give the child exactly ``env`` plus the guard's Layer 0 and inherit
    nothing else from the pytest process (this child must see a minimal, credential-less env)."""
    want = hermetic_guard.hermetic_env(env)
    guarded = set(hermetic_guard.FORCED_ENV) | set(hermetic_guard.SECRET_ENV) | {"PYTHONPATH"}
    return {"drop": tuple(k for k in os.environ if k not in want or k == "PYTHONPATH"),
            "extra": {k: v for k, v in want.items() if k not in guarded}}


def _resp(text, prompt=100, cand=50):
    return types.GenerateContentResponse.model_validate({
        "candidates": [{"content": {"role": "model", "parts": [{"text": text}]}, "finish_reason": "STOP"}],
        "usage_metadata": {"prompt_token_count": prompt, "candidates_token_count": cand, "thoughts_token_count": 0},
        "model_version": "fake-1"})


class FakeBackend:
    def __init__(self):
        self.calls = []

    def __call__(self, *, model, contents, config):
        self.calls.append((model, contents, config))
        if "boom" in str(contents):
            raise RuntimeError("429 RESOURCE_EXHAUSTED fake")
        return _resp(f"echo:{contents}:{len(self.calls)}")


def _proxy(mode, state=None, backend=None, cassette=None, cap=5.0):
    state = state or RunState()
    return LLMProxy(mode=mode, budget=Budget(cap, 10 ** 9, PRICES, state=state), state=state, gateway_dir=HERE,
                    example="01", run=1, backend=backend, cassette=cassette)


def test_proxy_is_truthy_and_rejects_other_sdk_surfaces():
    p = _proxy("live", backend=FakeBackend())
    assert bool(p)
    with pytest.raises(EvalHarnessError):
        p.chats
    with pytest.raises(EvalHarnessError):
        p.models.generate_content_stream
    with pytest.raises(EvalHarnessError):
        p.models.generate_content(model="m", contents="x", config=None, safety_settings=[])


def test_seed_injection_copies_config_and_keeps_product_seed():
    cfg = types.GenerateContentConfig(temperature=0.2, max_output_tokens=100)
    seeded = with_seed(cfg, 42)
    assert seeded.seed == 42 and cfg.seed is None  # product object untouched
    assert with_seed({"temperature": 0.1}, 7) == {"temperature": 0.1, "seed": 7}
    assert with_seed({"seed": 3}, 7) == {"seed": 3}
    assert derive_seed("01", 1, "abc", 0) == derive_seed("01", 1, "abc", 0)
    assert derive_seed("01", 1, "abc", 0) != derive_seed("01", 1, "abc", 1)


def test_request_hash_ignores_nothing_but_is_stable_for_schema_classes():
    from pydantic import BaseModel

    class S(BaseModel):
        x: int = 1
    c1 = {"response_schema": S, "temperature": 0.1}
    c2 = {"temperature": 0.1, "response_schema": S}
    assert request_hash(normalize_request("m", "hi", c1)) == request_hash(normalize_request("m", "hi", c2))
    assert request_hash(normalize_request("m", "hi", c1)) != request_hash(normalize_request("m", "hi!", c1))


def test_record_then_replay_is_identical_and_keys_by_occurrence(tmp_path):
    cas_path = tmp_path / "c.jsonl"
    rec_cas = Cassette(cas_path)
    rec_cas.open_for_record({"frozen_now": "2026-10-12T00:00:00+00:00"})
    be = FakeBackend()
    p = _proxy("record", backend=be, cassette=rec_cas)
    cfg = types.GenerateContentConfig(temperature=0.2, max_output_tokens=100)
    a1 = p.models.generate_content(model="m", contents="same", config=cfg).text
    a2 = p.models.generate_content(model="m", contents="same", config=cfg).text  # identical retry
    b1 = p.models.generate_content(model="m", contents="other", config=cfg).text
    with pytest.raises(RuntimeError):
        p.models.generate_content(model="m", contents="boom", config=cfg)
    rec_cas.close()
    assert a1 != a2  # the two identical requests got distinct recorded answers (occurrence 0 and 1)
    seeds = [c[2].seed for c in be.calls]
    assert len(set(seeds)) == 4

    rp = _proxy("replay-strict", cassette=Cassette.load(cas_path))
    assert rp.models.generate_content(model="m", contents="same", config=cfg).text == a1
    assert rp.models.generate_content(model="m", contents="same", config=cfg).text == a2
    assert rp.models.generate_content(model="m", contents="other", config=cfg).text == b1
    with pytest.raises(RuntimeError, match="429 RESOURCE_EXHAUSTED fake"):  # recorded errors replay as errors
        rp.models.generate_content(model="m", contents="boom", config=cfg)
    s = rp.summary()
    assert s["served"]["replay"] == 4 and s["usd"] == 0.0


def test_replay_strict_miss_invalidates_and_fallback_is_tagged_diverged(tmp_path):
    cas_path = tmp_path / "c.jsonl"
    c = Cassette(cas_path)
    c.open_for_record({})
    p = _proxy("record", backend=FakeBackend(), cassette=c)
    p.models.generate_content(model="m", contents="original", config=None)
    c.close()
    st = RunState()
    rp = _proxy("replay-strict", state=st, cassette=Cassette.load(cas_path))
    # different request text from the same site and ordinal -> served by fallback, run tagged replay_diverged
    out = rp.models.generate_content(model="m", contents="changed prompt", config=None)
    assert out.text.startswith("echo:original")
    assert st.flags.get("replay_diverged") is True
    with pytest.raises(EvalReplayMiss):
        rp.models.generate_content(model="m", contents="third", config=None)
    assert "replay_miss" in st.invalid_reasons


def test_budget_refusal_inside_proxy_is_sticky_and_stops_later_calls():
    st = RunState()
    be = FakeBackend()
    p = _proxy("live", state=st, backend=be, cap=0.0006)  # one call worst-case: (bytes+64)*1e-6 + 100*1e-5
    cfg = {"max_output_tokens": 100}
    with pytest.raises(EvalBudgetExceeded):
        for _ in range(10):
            p.models.generate_content(model="m", contents="x", config=cfg)
    n = len(be.calls)
    with pytest.raises(EvalBudgetExceeded):
        p.models.generate_content(model="m", contents="x", config=cfg)
    assert len(be.calls) == n  # nothing reached the backend after the trip
    assert st.fatal == "budget_exceeded"


def test_token_bearing_client_is_not_reachable_from_the_proxy():
    """RT finding 1b: build the real live backend (fake token, guard installed, no network) and walk every attribute
    reachable from the product-visible proxy. No path may reach the credentials or the token string. A positive
    control re-publishes the client the old way (`call.client`) and proves the walk would have caught it."""
    import subprocess
    code = r"""
import sys, types as _t
sys.path.insert(0, {eval_dir!r})
from stackvend_eval.state import RunState
from stackvend_eval.guard import Guard
from stackvend_eval.budget import Budget, Price, PriceTable
from stackvend_eval.llm_proxy import LLMProxy, make_live_backend, vertex_hosts
FAKE = "ya29.FAKE-eval-test-token-not-real"
st = RunState()
g = Guard(st, allow_hosts=vertex_hosts("global"))
g.install_all()
backend = make_live_backend("eval-test-project", "global", FAKE)
g.seal_genai()
from google.oauth2.credentials import Credentials
prices = PriceTable({{"m": Price("m", 1.0, 10.0, 0.5, 5.0, True, 65536)}})
proxy = LLMProxy(mode="live", budget=Budget(1.0, 10 ** 9, prices, state=st), state=st, gateway_dir="/nonexistent",
                 example="01", run=1, backend=backend)

def leaks(root):
    seen, stack, found = set(), [(root, "proxy")], []
    while stack:
        obj, path = stack.pop()
        if id(obj) in seen or isinstance(obj, (_t.ModuleType, type, int, float, bool, type(None))):
            continue
        seen.add(id(obj))
        if isinstance(obj, Credentials):
            found.append(path); continue
        if isinstance(obj, (str, bytes)):
            if (FAKE if isinstance(obj, str) else FAKE.encode()) in obj:
                found.append(path)
            continue
        if isinstance(obj, dict):
            stack += [(v, f"{{path}}[{{k!r}}]") for k, v in obj.items()] + [(k, f"{{path}}.key") for k in obj]
            continue
        if isinstance(obj, (list, tuple, set, frozenset)):
            stack += [(v, f"{{path}}[{{i}}]") for i, v in enumerate(obj)]
            continue
        if isinstance(obj, _t.MethodType):
            stack += [(obj.__self__, path + ".__self__"), (obj.__func__, path + ".__func__")]
            continue
        d = getattr(obj, "__dict__", None)     # functions: attributes only (closures/globals are hostile-only paths)
        if isinstance(d, dict):
            stack += [(v, f"{{path}}.{{k}}") for k, v in d.items()]
        for cls in type(obj).__mro__:
            for sl in getattr(cls, "__slots__", ()) if not isinstance(obj, _t.FunctionType) else ():
                if isinstance(sl, str) and hasattr(obj, sl):
                    stack.append((getattr(obj, sl), f"{{path}}.{{sl}}"))
    return found

assert not hasattr(backend, "client")
assert "backend" not in vars(proxy) and "budget" not in vars(proxy)
assert leaks(proxy) == [], leaks(proxy)
client = backend.__closure__[0].cell_contents          # positive control only: the old `call.client = client`
backend.client = client
assert leaks(proxy), "walker failed to find a published client"
print("ok")
""".format(eval_dir=str(Path(__file__).resolve().parent.parent / "eval"))
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent-home", "LANG": "C.UTF-8", "PROJECT_ID": "",
           "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/adc-disabled.json"}
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                       env=hermetic_guard.child_env(**_exact_child_env(env)), timeout=120)
    assert r.returncode == 0 and r.stdout.strip().endswith("ok"), r.stdout[-2000:] + r.stderr[-3000:]
