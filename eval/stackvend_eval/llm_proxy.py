"""Metered, recordable stand-in for google.genai.Client (plan §2.1, §7, §8; red-team B5/B6/H5).

The generation path calls exactly one SDK method: `genai_client.models.generate_content` (sync). The proxy
implements that and nothing else: any other attribute raises, so a new SDK surface shows up as a harness error,
never as an unmetered call. The proxy does not override __bool__ (product code does `if not self.genai_client`).

Modes
  live              backend call, budgeted, not recorded
  record            backend call, budgeted, recorded to the cassette
  replay-strict     cassette only; a miss invalidates the run (replay_miss) and raises
  replay-then-live  cassette first; a miss goes live (budgeted) and is recorded  (needed once FD-53 adds calls)
  synthetic         offline schema-valid responses (tests / harness e2e only); budgeted with fake usage
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .budget import Budget
from .cassettes import Cassette, canonical_bytes, normalize_request, request_hash
from .errors import EvalBudgetExceeded, EvalHarnessError, EvalReplayMiss
from .state import RunState

MODES = ("live", "record", "replay-strict", "replay-then-live", "synthetic")
LIVE_MODES = ("live", "record", "replay-then-live")

# Site of an LLM call made from a worker thread (asyncio.to_thread): set by the to_thread shim in stages.py.
SITE_CTX: contextvars.ContextVar = contextvars.ContextVar("stackvend_eval_llm_site", default=None)


def find_product_frame(gateway_dir: str, start_depth: int = 2) -> Tuple[str, Any]:
    try:
        f = sys._getframe(start_depth)
    except ValueError:
        f = None
    while f is not None:
        fn = f.f_code.co_filename
        if fn.startswith(gateway_dir):
            rel = fn[len(gateway_dir):].lstrip("/")
            return f"{rel}:{f.f_code.co_qualname}", f
        f = f.f_back
    ctx = SITE_CTX.get()
    if ctx:
        return ctx, None
    return "unknown", None


def recorded_error(err: Dict[str, Any]) -> BaseException:
    """SLOW-CALL-FALLBACK RT F8: a recorded call error replays with the type the product's walk classifies, so record
    and replay walk the same way: a recorded httpx timeout is that httpx timeout class (exact recorded type name, a
    subclass of httpx.TimeoutException), and a recorded int provider status is a google.genai ClientError /
    ServerError with that code. Anything else (and every cassette recorded before the code was kept) is a
    RuntimeError, as before."""
    message = err.get("message", "recorded error")
    try:
        import httpx
        cls = getattr(httpx, str(err.get("type") or ""), None)
        if isinstance(cls, type) and issubclass(cls, httpx.TimeoutException):
            return cls(message)
    except ImportError:  # pragma: no cover
        pass
    code = err.get("code")
    if isinstance(code, int) and not isinstance(code, bool):
        from google.genai import errors
        body = {"error": {"code": code, "message": message}}
        return (errors.ServerError if code >= 500 else errors.ClientError)(code, body)
    return RuntimeError(message)


def usage_of(response: Any) -> Optional[Dict[str, int]]:
    um = getattr(response, "usage_metadata", None)
    if um is None:
        return None
    return {"prompt": int(getattr(um, "prompt_token_count", 0) or 0),
            "candidates": int(getattr(um, "candidates_token_count", 0) or 0),
            "thoughts": int(getattr(um, "thoughts_token_count", 0) or 0),
            "cached": int(getattr(um, "cached_content_token_count", 0) or 0),
            "total": int(getattr(um, "total_token_count", 0) or 0)}


def response_to_json(response: Any) -> Dict[str, Any]:
    return response.model_dump(mode="json", exclude_none=True)


def response_from_json(data: Dict[str, Any]) -> Any:
    from google.genai import types
    return types.GenerateContentResponse.model_validate(data)


def derive_seed(example: str, run: int, rhash: str, occurrence: int) -> int:
    h = hashlib.sha256(f"{example}|{run}|{rhash}|{occurrence}".encode()).hexdigest()
    return int(h[:8], 16) % (2 ** 31)


def with_seed(config: Any, seed: int) -> Any:
    """Copy the config (never mutate the product's object) and set seed unless the product already set one."""
    if config is None:
        return {"seed": seed}
    if isinstance(config, dict):
        if config.get("seed") is not None:
            return dict(config)
        return {**config, "seed": seed}
    if getattr(config, "seed", None) is not None:
        return config.model_copy()
    return config.model_copy(update={"seed": seed})


def max_output_of(config: Any) -> Optional[int]:
    if config is None:
        return None
    if isinstance(config, dict):
        return config.get("max_output_tokens")
    return getattr(config, "max_output_tokens", None)


class _Models:
    def __init__(self, proxy: "LLMProxy"):
        self._proxy = proxy

    def generate_content(self, *, model: str, contents: Any, config: Any = None, **kwargs: Any) -> Any:
        if kwargs:
            raise EvalHarnessError(f"unsupported generate_content kwargs: {sorted(kwargs)}")
        return self._proxy._call(model, contents, config)

    def __getattr__(self, name: str) -> Any:
        raise EvalHarnessError(f"LLM proxy: unsupported genai surface 'models.{name}'")


class LLMProxy:
    def __init__(self, *, mode: str, budget: Budget, state: RunState, gateway_dir: str, example: str, run: int,
                 backend: Optional[Callable[..., Any]] = None, cassette: Optional[Cassette] = None,
                 inject_seed: bool = True, temperature_override: Optional[float] = None,
                 request_log: Optional[Path] = None):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        if mode in ("live", "record", "replay-then-live", "synthetic") and backend is None:
            raise ValueError(f"mode {mode} needs a backend")
        if mode.startswith("replay") and cassette is None:
            raise ValueError("replay modes need a cassette")
        self.mode = mode
        # RT finding 1b: the backend (which closes over the token-bearing client) and the budget are not part of the
        # proxy's public namespace; the product only ever sees `models.generate_content`.
        self._budget = budget
        self.state = state
        self.gateway_dir = str(gateway_dir).rstrip("/") + "/"
        self.example = example
        self.run = int(run)
        self._backend = backend
        self.cassette = cassette
        self.inject_seed = inject_seed
        self.temperature_override = temperature_override
        self.models = _Models(self)
        self._lock = threading.Lock()
        self._occ: Dict[str, int] = {}
        self._site_ord: Dict[str, int] = {}
        self.calls: List[Dict[str, Any]] = []
        self.raw_responses: Dict[str, List[str]] = {}  # site -> response texts (checkpoint C0 for single-turn)
        # F9: opt-in dump of every normalized request (the exact bytes that are hashed), so a replay divergence can be
        # diffed against another environment's dump. Contains full prompts: written only into the gitignored run dir.
        self.request_log = Path(request_log) if request_log else None

    def __getattr__(self, name: str) -> Any:
        raise EvalHarnessError(f"LLM proxy: unsupported genai surface '{name}'")

    # ---------------------------------------------------------------------------------------------- core
    def _next(self, table: Dict[str, int], key: str) -> int:
        with self._lock:
            n = table.get(key, 0)
            table[key] = n + 1
            return n

    def _call(self, model: str, contents: Any, config: Any) -> Any:
        site, frame = find_product_frame(self.gateway_dir, start_depth=3)
        fatal = self.state.fatal
        if fatal:
            raise EvalBudgetExceeded(f"run already stopped ({fatal}); refusing LLM call from {site}")
        norm = normalize_request(model, contents, config)
        rhash = request_hash(norm)
        occ = self._next(self._occ, rhash)
        ordinal = self._next(self._site_ord, site)
        if self.request_log is not None:
            with self._lock, self.request_log.open("a") as fh:
                fh.write(json.dumps({"site": site, "site_ordinal": ordinal, "request_hash": rhash, "occurrence": occ,
                                     "request": norm}, sort_keys=True, ensure_ascii=False) + "\n")
        seed = derive_seed(self.example, self.run, rhash, occ) if self.inject_seed else None
        send_config = with_seed(config, seed) if seed is not None else config
        if self.temperature_override is not None:
            send_config = (dict(send_config, temperature=self.temperature_override) if isinstance(send_config, dict)
                           else send_config.model_copy(update={"temperature": self.temperature_override}))
        rec: Dict[str, Any] = {"site": site, "site_ordinal": ordinal, "model": model, "request_hash": rhash,
                               "occurrence": occ, "seed": seed, "served": None, "usage": None, "usd": 0.0,
                               "finish_reason": None, "model_version": None, "error": None,
                               "max_output_tokens": max_output_of(config)}
        t0 = time.time()
        try:
            if self.mode.startswith("replay"):
                hit = self.cassette.lookup(rhash, occ)
                served = "replay"
                if hit is None:
                    hit = self.cassette.lookup_fallback(site, ordinal)
                    served = "replay_fallback"
                    if hit is not None:
                        self.state.set_flag("replay_diverged", True)
                        self.state.record("replay_diverged", {"site": site, "ordinal": ordinal, "request_hash": rhash})
                if hit is not None:
                    rec["served"] = served
                    return self._serve_recorded(hit, rec)
                if self.mode == "replay-strict":
                    self.state.invalidate("replay_miss", {"site": site, "request_hash": rhash, "occurrence": occ})
                    raise EvalReplayMiss(f"no cassette entry for {site} {rhash[:12]}#{occ}")
            return self._call_backend(model, contents, send_config, norm, rec, site, frame)
        finally:
            rec["latency_s"] = round(time.time() - t0, 3)
            with self._lock:
                self.calls.append(rec)

    def _serve_recorded(self, hit: Dict[str, Any], rec: Dict[str, Any]) -> Any:
        rec["usage"] = hit.get("usage")
        rec["finish_reason"] = hit.get("finish_reason")
        rec["model_version"] = hit.get("model_version")
        if hit.get("error"):
            rec["error"] = hit["error"]
            raise recorded_error(hit["error"])
        resp = response_from_json(hit["response"])
        self._remember_text(rec["site"], resp)
        return resp

    def _remember_text(self, site: str, resp: Any) -> None:
        try:
            text = resp.text
        except Exception:
            text = None
        if text is not None:
            with self._lock:
                self.raw_responses.setdefault(site, []).append(text)

    def _call_backend(self, model: str, contents: Any, send_config: Any, norm: Dict[str, Any], rec: Dict[str, Any],
                      site: str, frame: Any) -> Any:
        payload_bytes = len(canonical_bytes(norm))
        reservation = self._budget.reserve(model, payload_bytes, max_output_of(send_config))
        rec["reserved_usd"] = round(reservation.usd, 6)
        rec["served"] = "backend"
        response = None
        try:
            if self.mode == "synthetic":
                response = self._backend(site=site, frame=frame, model=model, contents=contents, config=send_config)
            else:
                response = self._backend(model=model, contents=contents, config=send_config)
        except BaseException as e:  # noqa: BLE001
            code = getattr(e, "code", None)   # google.genai APIError.code: the provider's HTTP status (an int)
            if isinstance(code, int) and not isinstance(code, bool) and code == 429:
                settle = self._budget.settle_rejected(reservation, 429)   # quota rejection: never billed
            else:
                settle = self._budget.settle(reservation, None)  # usage unknown -> charge the full reservation
            rec["usd"] = settle["usd"]
            rec["settle_basis"] = settle["basis"]
            rec["error"] = {"type": type(e).__name__, "message": str(e)[:2000]}
            if isinstance(code, int) and not isinstance(code, bool):
                rec["error"]["code"] = code   # SLOW-CALL-FALLBACK RT F8: replayed as the same typed error
            self._record_cassette(rec, None, norm)
            raise
        usage = usage_of(response)
        settle = self._budget.settle(reservation, usage)
        rec["usage"] = usage
        rec["usd"] = round(settle["usd"], 6)
        rec["settle_basis"] = settle["basis"]
        try:
            cand = response.candidates[0] if response.candidates else None
            rec["finish_reason"] = str(getattr(cand, "finish_reason", None)) if cand is not None else None
        except Exception:
            pass
        rec["model_version"] = getattr(response, "model_version", None)
        self._remember_text(site, response)
        self._record_cassette(rec, response, norm)
        return response

    def _record_cassette(self, rec: Dict[str, Any], response: Any, norm: Optional[Dict[str, Any]] = None) -> None:
        if self.mode not in ("record", "replay-then-live", "synthetic") or self.cassette is None:
            return
        entry = {k: rec[k] for k in ("site", "site_ordinal", "model", "request_hash", "occurrence", "seed",
                                     "usage", "finish_reason", "model_version", "error")}
        # F9: keep the hashed request itself, so a later divergence can be diffed instead of only detected
        entry["request"] = norm
        entry["response"] = response_to_json(response) if response is not None else None
        self.cassette.append(entry)

    # ----------------------------------------------------------------------------------------- reporting
    def summary(self) -> Dict[str, Any]:
        with self._lock:
            calls = list(self.calls)
        tok = {"prompt": 0, "candidates": 0, "thoughts": 0, "cached": 0}
        for c in calls:
            for k in tok:
                tok[k] += int((c.get("usage") or {}).get(k) or 0)
        finish: Dict[str, int] = {}
        for c in calls:
            if c.get("finish_reason"):
                finish[c["finish_reason"]] = finish.get(c["finish_reason"], 0) + 1
        return {"mode": self.mode, "calls": len(calls), "tokens": tok,
                "usd": round(sum(float(c.get("usd") or 0) for c in calls), 6),
                "finish_reasons": finish,
                "max_tokens_truncations": sum(v for k, v in finish.items() if "MAX_TOKENS" in k.upper()),
                "served": served_counts(calls),
                "served_by_site": served_by_site(calls),
                "models_requested": sorted({c["model"] for c in calls}),
                "model_versions": sorted({str(c["model_version"]) for c in calls if c.get("model_version")}),
                "per_call": calls}


SERVED_KINDS = ("replay", "replay_fallback", "replay_miss", "backend")


def _served_kind(call: Dict[str, Any]) -> str:
    # A replay miss leaves served unset (the call raised before anything was served).
    return call.get("served") or "replay_miss"


def served_counts(calls: List[Dict[str, Any]]) -> Dict[str, int]:
    """F9 replay provenance: replay = exact request-hash hit, replay_fallback = site/ordinal fallback (diverged
    request), replay_miss = nothing served (replay-strict invalidates the run), backend = live/synthetic call."""
    return {k: sum(1 for c in calls if _served_kind(c) == k) for k in SERVED_KINDS}


def served_by_site(calls: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for c in calls:
        site = out.setdefault(str(c.get("site")), {})
        k = _served_kind(c)
        site[k] = site.get(k, 0) + 1
    return {k: out[k] for k in sorted(out)}


def make_live_backend(project: str, location: str, access_token: str) -> Callable[..., Any]:
    """B1: the harness's own client authenticates with a short-lived access token only (no refresh token, no ADC).

    RT finding 1b: the client lives only in this closure. Nothing publishes it as an attribute (the function carries
    no `client`), so no attribute path from the product-visible proxy reaches the credentials."""
    from google import genai
    from google.oauth2.credentials import Credentials
    client = genai.Client(vertexai=True, project=project, location=location,
                          credentials=Credentials(token=access_token))

    def call(*, model: str, contents: Any, config: Any) -> Any:
        return client.models.generate_content(model=model, contents=contents, config=config)
    return call


def vertex_hosts(location: str) -> List[str]:
    loc = (location or "global").strip().lower()
    hosts = ["aiplatform.googleapis.com"]
    if loc != "global":
        hosts.append(f"{loc}-aiplatform.googleapis.com")
    return hosts
